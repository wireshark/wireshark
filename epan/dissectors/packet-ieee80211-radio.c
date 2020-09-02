/* packet-ieee80211-radio.c
 * Routines for pseudo 802.11 header dissection and radio packet timing calculation
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * Copyright 2012 Parc Inc and Samsung Electronics
 * Copyright 2015, 2016 & 2017 Cisco Inc
 *
 * Copied from README.developer
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"

#include <epan/packet.h>
#include <epan/expert.h>
#include <wiretap/wtap.h>
#include <epan/prefs.h>
#include <epan/proto_data.h>
#include <epan/tap.h>

#include "packet-ieee80211.h"
#include "packet-ieee80211-radio.h"
#include "packet-ieee80211-radiotap-defs.h"
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
static int hf_wlan_radio_signal_db = -1;
static int hf_wlan_radio_signal_dbm = -1;
static int hf_wlan_radio_noise_percent = -1;
static int hf_wlan_radio_noise_db = -1;
static int hf_wlan_radio_noise_dbm = -1;
static int hf_wlan_radio_snr = -1;
static int hf_wlan_radio_timestamp = -1;
static int hf_wlan_last_part_of_a_mpdu = -1;
static int hf_wlan_a_mpdu_delim_crc_error = -1;
static int hf_wlan_a_mpdu_aggregate_id = -1;
static int hf_wlan_radio_duration = -1;
static int hf_wlan_radio_preamble = -1;
static int hf_wlan_radio_aggregate = -1;
static int hf_wlan_radio_aggregate_duration = -1;
static int hf_wlan_radio_ifs = -1;
static int hf_wlan_radio_start_tsf = -1;
static int hf_wlan_radio_end_tsf = -1;
static int hf_wlan_zero_length_psdu_type = -1;

static expert_field ei_wlan_radio_assumed_short_preamble = EI_INIT;
static expert_field ei_wlan_radio_assumed_non_greenfield = EI_INIT;
static expert_field ei_wlan_radio_assumed_no_stbc = EI_INIT;
static expert_field ei_wlan_radio_assumed_no_extension_streams = EI_INIT;
static expert_field ei_wlan_radio_assumed_bcc_fec = EI_INIT;

static int wlan_radio_tap = -1;
static int wlan_radio_timeline_tap = -1;

/* Settings */
static gboolean wlan_radio_always_short_preamble = FALSE;
static gboolean wlan_radio_tsf_at_end = TRUE;
static gboolean wlan_radio_timeline_enabled = FALSE;

static const value_string phy_vals[] = {
    { PHDR_802_11_PHY_11_FHSS,       "802.11 FHSS" },
    { PHDR_802_11_PHY_11_IR,         "802.11 IR" },
    { PHDR_802_11_PHY_11_DSSS,       "802.11 DSSS" },
    { PHDR_802_11_PHY_11B,           "802.11b (HR/DSSS)" },
    { PHDR_802_11_PHY_11A,           "802.11a (OFDM)" },
    { PHDR_802_11_PHY_11G,           "802.11g (ERP)" },
    { PHDR_802_11_PHY_11N,           "802.11n (HT)" },
    { PHDR_802_11_PHY_11AC,          "802.11ac (VHT)" },
    { PHDR_802_11_PHY_11AD,          "802.11ad (DMG)" },
    { PHDR_802_11_PHY_11AH,          "802.11ah (S1G)" },
    { PHDR_802_11_PHY_11AX,          "802.11ax (HE)" },
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

static const value_string zero_length_psdu_vals[] = {
	{ 0, "sounding PPDU" },
	{ 1, "data not captured" },
	{ 255, "vendor-specific" },
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

/*
 * HE SU OFDM MCS rate table converted from http://mcsindex.com/
 * indexed by (NSTS,MCS,BW,GI)
 */
#define HE_MAX_NSTS 8
#define HE_MAX_MCS  12
#define HE_SU_MAX_BW   4
#define HE_MAX_GI   3
static float he_ofdm_tab[HE_MAX_NSTS][HE_MAX_MCS][HE_SU_MAX_BW][HE_MAX_GI] = {
  {
      {{     8.6f,     8.1f,    7.3f},{     17.2f,    16.3f,    14.6f},{     36.0f,    34.0f,    30.6f},{     72.1f,    68.1f,    61.3f}},
      {{    17.2f,    16.3f,   14.6f},{     34.4f,    32.5f,    29.3f},{     72.1f,    68.1f,    61.3f},{    144.1f,   136.1f,   122.5f}},
      {{    25.8f,    24.4f,   21.9f},{     51.6f,    48.8f,    43.9f},{    108.1f,   102.1f,    91.9f},{    216.2f,   204.2f,   183.8f}},
      {{    34.4f,    32.5f,   29.3f},{     68.8f,    65.0f,    58.5f},{    144.1f,   136.1f,   122.5f},{    288.2f,   272.2f,   245.0f}},
      {{    51.6f,    48.8f,   43.9f},{    103.2f,    97.5f,    87.8f},{    216.2f,   204.2f,   183.8f},{    432.4f,   408.3f,   367.5f}},
      {{    68.8f,    65.0f,   58.5f},{    137.6f,   130.0f,   117.0f},{    288.2f,   272.2f,   245.0f},{    576.5f,   544.4f,   490.0f}},
      {{    77.4f,    73.1f,   65.8f},{    154.9f,   146.3f,   131.6f},{    324.3f,   306.3f,   275.6f},{    648.5f,   612.5f,   551.3f}},
      {{    86.0f,    81.3f,   73.1f},{    172.1f,   162.5f,   146.3f},{    360.3f,   340.3f,   306.3f},{    720.6f,   680.6f,   612.5f}},
      {{   103.2f,    97.5f,   87.8f},{    206.5f,   195.0f,   175.5f},{    432.4f,   408.3f,   367.5f},{    864.7f,   816.7f,   735.0f}},
      {{   114.7f,   108.3f,   97.5f},{    229.4f,   216.7f,   195.0f},{    480.4f,   453.7f,   408.3f},{    960.8f,   907.4f,   816.7f}},
      {{   129.0f,   121.9f,  109.7f},{    258.1f,   243.8f,   219.4f},{    540.4f,   510.4f,   459.4f},{   1080.9f,  1020.8f,   918.8f}},
      {{   143.4f,   135.4f,  121.9f},{    286.8f,   270.8f,   243.8f},{    600.5f,   567.1f,   510.4f},{   1201.0f,  1134.3f,  1020.8f}}
  },{
      {{    17.2f,    16.3f,   14.6f},{     34.4f,    32.5f,    29.3f},{     72.1f,    68.1f,    61.3f},{    144.1f,   136.1f,   122.5f}},
      {{    34.4f,    32.5f,   29.3f},{     68.8f,    65.0f,    58.5f},{    144.1f,   136.1f,   122.5f},{    288.2f,   272.2f,   245.0f}},
      {{    51.6f,    48.8f,   43.9f},{    103.2f,    97.5f,    87.8f},{    216.2f,   204.2f,   183.8f},{    432.4f,   408.3f,   367.5f}},
      {{    68.8f,    65.0f,   58.5f},{    137.6f,   130.0f,   117.0f},{    288.2f,   272.2f,   245.0f},{    576.5f,   544.4f,   490.0f}},
      {{   103.2f,    97.5f,   87.8f},{    206.5f,   195.0f,   175.5f},{    432.4f,   408.3f,   367.5f},{    864.7f,   816.7f,   735.0f}},
      {{   137.6f,   130.0f,  117.0f},{    275.3f,   260.0f,   234.0f},{    576.5f,   544.4f,   490.0f},{   1152.9f,  1088.9f,   980.0f}},
      {{   154.9f,   146.3f,  131.6f},{    309.7f,   292.5f,   263.3f},{    648.5f,   612.5f,   551.3f},{   1297.1f,  1225.0f,  1102.5f}},
      {{   172.1f,   162.5f,  146.3f},{    344.1f,   325.0f,   292.5f},{    720.6f,   680.6f,   612.5f},{   1441.2f,  1361.1f,  1225.0f}},
      {{   206.5f,   195.0f,  175.5f},{    412.9f,   390.0f,   351.0f},{    864.7f,   816.7f,   735.0f},{   1729.4f,  1633.3f,  1470.0f}},
      {{   229.4f,   216.7f,  195.0f},{    458.8f,   433.3f,   390.0f},{    960.8f,   907.4f,   816.7f},{   1921.6f,  1814.8f,  1633.3f}},
      {{   258.1f,   243.8f,  219.4f},{    516.2f,   487.5f,   438.8f},{   1080.9f,  1020.8f,   918.8f},{   2161.8f,  2041.7f,  1837.5f}},
      {{   286.8f,   270.8f,  243.8f},{    573.5f,   541.7f,   487.5f},{   1201.0f,  1134.3f,  1020.8f},{   2402.0f,  2268.5f,  2041.7f}}
  },{
      {{    25.8f,    24.4f,   21.9f},{     51.6f,    48.8f,    43.9f},{    108.1f,   102.1f,    91.9f},{    216.2f,   204.2f,   183.8f}},
      {{    51.6f,    48.8f,   43.9f},{    103.2f,    97.5f,    87.8f},{    216.2f,   204.2f,   183.8f},{    432.4f,   408.3f,   367.5f}},
      {{    77.4f,    73.1f,   65.8f},{    154.9f,   146.3f,   131.6f},{    324.3f,   306.3f,   275.6f},{    648.5f,   612.5f,   551.3f}},
      {{   103.2f,    97.5f,   87.8f},{    206.5f,   195.0f,   175.5f},{    432.4f,   408.3f,   367.5f},{    864.7f,   816.7f,   735.0f}},
      {{   154.9f,   146.3f,  131.6f},{    309.7f,   292.5f,   263.3f},{    648.5f,   612.5f,   551.3f},{   1297.1f,  1225.0f,  1102.5f}},
      {{   206.5f,   195.0f,  175.5f},{    412.9f,   390.0f,   351.0f},{    864.7f,   816.7f,   735.0f},{   1729.4f,  1633.3f,  1470.0f}},
      {{   232.3f,   219.4f,  197.4f},{    464.6f,   438.8f,   394.9f},{    972.8f,   918.8f,   826.9f},{   1945.6f,  1837.5f,  1653.8f}},
      {{   258.1f,   243.8f,  219.4f},{    516.2f,   487.5f,   438.8f},{   1080.9f,  1020.8f,   918.8f},{   2161.8f,  2041.7f,  1837.5f}},
      {{   309.7f,   292.5f,  263.3f},{    619.4f,   585.0f,   526.5f},{   1297.1f,  1225.0f,  1102.5f},{   2594.1f,  2450.0f,  2205.0f}},
      {{   344.1f,   325.0f,  292.5f},{    688.2f,   650.0f,   585.0f},{   1441.2f,  1361.1f,  1225.0f},{   2882.4f,  2722.2f,  2450.0f}},
      {{   387.1f,   365.6f,  329.1f},{    774.3f,   731.3f,   658.1f},{   1621.3f,  1531.3f,  1378.1f},{   3242.6f,  3062.5f,  2756.3f}},
      {{   430.1f,   406.3f,  365.6f},{    860.3f,   812.5f,   731.3f},{   1801.5f,  1701.4f,  1531.3f},{   3602.9f,  3402.8f,  3062.5f}}
  },{
      {{    34.4f,    32.5f,   29.3f},{     68.8f,    65.0f,    58.5f},{    144.1f,   136.1f,   122.5f},{    288.2f,   272.2f,   245.0f}},
      {{    68.8f,    65.0f,   58.5f},{    137.6f,   130.0f,   117.0f},{    288.2f,   272.2f,   245.0f},{    576.5f,   544.4f,   490.0f}},
      {{   103.2f,    97.5f,   87.8f},{    206.5f,   195.0f,   175.5f},{    432.4f,   408.3f,   367.5f},{    864.7f,   816.7f,   735.0f}},
      {{   137.6f,   130.0f,  117.0f},{    275.3f,   260.0f,   234.0f},{    576.5f,   544.4f,   490.0f},{   1152.9f,  1088.9f,   980.0f}},
      {{   206.5f,   195.0f,  175.5f},{    412.9f,   390.0f,   351.0f},{    864.7f,   816.7f,   735.0f},{   1729.4f,  1633.3f,  1470.0f}},
      {{   275.3f,   260.0f,  234.0f},{    550.6f,   520.0f,   468.0f},{   1152.9f,  1088.9f,   980.0f},{   2305.9f,  2177.8f,  1960.0f}},
      {{   309.7f,   292.5f,  263.3f},{    619.4f,   585.0f,   526.5f},{   1297.1f,  1225.0f,  1102.5f},{   2594.1f,  2450.0f,  2205.0f}},
      {{   344.1f,   325.0f,  292.5f},{    688.2f,   650.0f,   585.0f},{   1441.2f,  1361.1f,  1225.0f},{   2882.4f,  2722.2f,  2450.0f}},
      {{   412.9f,   390.0f,  351.0f},{    825.9f,   780.0f,   702.0f},{   1729.4f,  1633.3f,  1470.0f},{   3458.8f,  3266.7f,  2940.0f}},
      {{   458.8f,   433.3f,  390.0f},{    917.6f,   866.7f,   780.0f},{   1921.6f,  1814.8f,  1633.3f},{   3843.1f,  3629.6f,  3266.7f}},
      {{   516.2f,   487.5f,  438.8f},{   1032.4f,   975.0f,   877.5f},{   2161.8f,  2041.7f,  1837.5f},{   4323.5f,  4083.3f,  3675.0f}},
      {{   573.5f,   541.7f,  487.5f},{   1147.1f,  1083.3f,   975.0f},{   2402.0f,  2268.5f,  2041.7f},{   4803.9f,  4537.0f,  4083.3f}}
  },{
      {{    43.0f,    40.6f,   36.6f},{     86.0f,    81.3f,    73.1f},{    180.1f,   170.1f,   153.1f},{    360.3f,   340.3f,   306.3f}},
      {{    86.0f,    81.3f,   73.1f},{    172.1f,   162.5f,   146.3f},{    360.3f,   340.3f,   306.3f},{    720.6f,   680.6f,   612.5f}},
      {{   129.0f,   121.9f,  109.7f},{    258.1f,   243.8f,   219.4f},{    540.4f,   510.4f,   459.4f},{   1080.9f,  1020.8f,   918.8f}},
      {{   172.1f,   162.5f,  146.3f},{    344.1f,   325.0f,   292.5f},{    720.6f,   680.6f,   612.5f},{   1441.2f,  1361.1f,  1225.0f}},
      {{   258.1f,   243.8f,  219.4f},{    516.2f,   487.5f,   438.8f},{   1080.9f,  1020.8f,   918.8f},{   2161.8f,  2041.7f,  1837.5f}},
      {{   344.1f,   325.0f,  292.5f},{    688.2f,   650.0f,   585.0f},{   1441.2f,  1361.1f,  1225.0f},{   2882.4f,  2722.2f,  2450.0f}},
      {{   387.1f,   365.6f,  329.1f},{    774.3f,   731.3f,   658.1f},{   1621.3f,  1531.3f,  1378.1f},{   3242.6f,  3062.5f,  2756.3f}},
      {{   430.1f,   406.3f,  365.6f},{    860.3f,   812.5f,   731.3f},{   1801.5f,  1701.4f,  1531.3f},{   3602.9f,  3402.8f,  3062.5f}},
      {{   516.2f,   487.5f,  438.8f},{   1032.4f,   975.0f,   877.5f},{   2161.8f,  2041.7f,  1837.5f},{   4323.5f,  4083.3f,  3675.0f}},
      {{   573.5f,   541.7f,  487.5f},{   1147.1f,  1083.3f,   975.0f},{   2402.0f,  2268.5f,  2041.7f},{   4803.9f,  4537.0f,  4083.3f}},
      {{   645.2f,   609.4f,  548.4f},{   1290.4f,  1218.8f,  1096.9f},{   2702.2f,  2552.1f,  2296.9f},{   5404.4f,  5104.2f,  4593.8f}},
      {{   716.9f,   677.1f,  609.4f},{   1433.8f,  1354.2f,  1218.8f},{   3002.5f,  2835.6f,  2552.1f},{   6004.9f,  5671.3f,  5104.2f}}
  },{
      {{    51.6f,    48.8f,   43.9f},{    103.2f,    97.5f,    87.8f},{    216.2f,   204.2f,   183.8f},{    432.4f,   408.3f,   367.5f}},
      {{   103.2f,    97.5f,   87.8f},{    206.5f,   195.0f,   175.5f},{    432.4f,   408.3f,   367.5f},{    864.7f,   816.7f,   735.0f}},
      {{   154.9f,   146.3f,  131.6f},{    309.7f,   292.5f,   263.3f},{    648.5f,   612.5f,   551.3f},{   1297.1f,  1225.0f,  1102.5f}},
      {{   206.5f,   195.0f,  175.5f},{    412.9f,   390.0f,   351.0f},{    864.7f,   816.7f,   735.0f},{   1729.4f,  1633.3f,  1470.0f}},
      {{   309.7f,   292.5f,  263.3f},{    619.4f,   585.0f,   526.5f},{   1297.1f,  1225.0f,  1102.5f},{   2594.1f,  2450.0f,  2205.0f}},
      {{   412.9f,   390.0f,  351.0f},{    825.9f,   780.0f,   702.0f},{   1729.4f,  1633.3f,  1470.0f},{   3458.8f,  3266.7f,  2940.0f}},
      {{   464.6f,   438.8f,  394.9f},{    929.1f,   877.5f,   789.8f},{   1945.6f,  1837.5f,  1653.8f},{   3891.2f,  3675.0f,  3307.5f}},
      {{   516.2f,   487.5f,  438.8f},{   1032.4f,   975.0f,   877.5f},{   2161.8f,  2041.7f,  1837.5f},{   4323.5f,  4083.3f,  3675.0f}},
      {{   619.4f,   585.0f,  526.5f},{   1238.8f,  1170.0f,  1053.0f},{   2594.1f,  2450.0f,  2205.0f},{   5188.2f,  4900.0f,  4410.0f}},
      {{   688.2f,   650.0f,  585.0f},{   1376.5f,  1300.0f,  1170.0f},{   2882.4f,  2722.2f,  2450.0f},{   5764.7f,  5444.4f,  4900.0f}},
      {{   774.3f,   731.3f,  658.1f},{   1548.5f,  1462.5f,  1316.3f},{   3242.6f,  3062.5f,  2756.3f},{   6485.3f,  6125.0f,  5512.5f}},
      {{   860.3f,   812.5f,  731.3f},{   1720.6f,  1625.0f,  1462.5f},{   3602.9f,  3402.8f,  3062.5f},{   7205.9f,  6805.6f,  6125.0f}}
  },{
      {{    60.2f,    56.9f,   51.2f},{    120.4f,   113.8f,   102.4f},{    252.2f,   238.2f,   214.4f},{    504.4f,   476.4f,   428.8f}},
      {{   120.4f,   113.8f,  102.4f},{    240.9f,   227.5f,   204.8f},{    504.4f,   476.4f,   428.8f},{   1008.8f,   952.8f,   857.5f}},
      {{   180.7f,   170.6f,  153.6f},{    361.3f,   341.3f,   307.1f},{    756.6f,   714.6f,   643.1f},{   1513.2f,  1429.2f,  1286.3f}},
      {{   240.9f,   227.5f,  204.8f},{    481.8f,   455.0f,   409.5f},{   1008.8f,   952.8f,   857.5f},{   2017.6f,  1905.6f,  1715.0f}},
      {{   361.3f,   341.3f,  307.1f},{    722.6f,   682.5f,   614.3f},{   1513.2f,  1429.2f,  1286.3f},{   3026.5f,  2858.3f,  2572.5f}},
      {{   481.8f,   455.0f,  409.5f},{    963.5f,   910.0f,   819.0f},{   2017.6f,  1905.6f,  1715.0f},{   4035.3f,  3811.1f,  3430.0f}},
      {{   542.0f,   511.9f,  460.7f},{   1084.0f,  1023.8f,   921.4f},{   2269.9f,  2143.8f,  1929.4f},{   4539.7f,  4287.5f,  3858.8f}},
      {{   602.2f,   568.8f,  511.9f},{   1204.4f,  1137.5f,  1023.8f},{   2522.1f,  2381.9f,  2143.8f},{   5044.1f,  4763.9f,  4287.5f}},
      {{   722.6f,   682.5f,  614.3f},{   1445.3f,  1365.0f,  1228.5f},{   3026.5f,  2858.3f,  2572.5f},{   6052.9f,  5716.7f,  5145.0f}},
      {{   802.9f,   758.3f,  682.5f},{   1605.9f,  1516.7f,  1365.0f},{   3362.7f,  3175.9f,  2858.3f},{   6725.5f,  6351.9f,  5716.7f}},
      {{   903.3f,   853.1f,  767.8f},{   1806.6f,  1706.3f,  1535.6f},{   3783.1f,  3572.9f,  3215.6f},{   7566.2f,  7145.8f,  6431.3f}},
      {{  1003.7f,   947.9f,  853.1f},{   2007.4f,  1895.8f,  1706.3f},{   4203.4f,  3969.9f,  3572.9f},{   8406.9f,  7939.8f,  7145.8f}}
  },{
      {{    68.8f,    65.0f,   58.5f},{    137.6f,   130.0f,   117.0f},{    288.2f,   272.2f,   245.0f},{    576.5f,   544.4f,   490.0f}},
      {{   137.6f,   130.0f,  117.0f},{    275.3f,   260.0f,   234.0f},{    576.5f,   544.4f,   490.0f},{   1152.9f,  1088.9f,   980.0f}},
      {{   206.5f,   195.0f,  175.5f},{    412.9f,   390.0f,   351.0f},{    864.7f,   816.7f,   735.0f},{   1729.4f,  1633.3f,  1470.0f}},
      {{   275.3f,   260.0f,  234.0f},{    550.6f,   520.0f,   468.0f},{   1152.9f,  1088.9f,   980.0f},{   2305.9f,  2177.8f,  1960.0f}},
      {{   412.9f,   390.0f,  351.0f},{    825.9f,   780.0f,   702.0f},{   1729.4f,  1633.3f,  1470.0f},{   3458.8f,  3266.7f,  2940.0f}},
      {{   550.6f,   520.0f,  468.0f},{   1101.2f,  1040.0f,   936.0f},{   2305.9f,  2177.8f,  1960.0f},{   4611.8f,  4355.6f,  3920.0f}},
      {{   619.4f,   585.0f,  526.5f},{   1238.8f,  1170.0f,  1053.0f},{   2594.1f,  2450.0f,  2205.0f},{   5188.2f,  4900.0f,  4410.0f}},
      {{   688.2f,   650.0f,  585.0f},{   1376.5f,  1300.0f,  1170.0f},{   2882.4f,  2722.2f,  2450.0f},{   5764.7f,  5444.4f,  4900.0f}},
      {{   825.9f,   780.0f,  702.0f},{   1651.8f,  1560.0f,  1404.0f},{   3458.8f,  3266.7f,  2940.0f},{   6917.6f,  6533.3f,  5880.0f}},
      {{   917.6f,   866.7f,  780.0f},{   1835.3f,  1733.3f,  1560.0f},{   3843.1f,  3629.6f,  3266.7f},{   7686.3f,  7259.3f,  6533.3f}},
      {{  1032.4f,   975.0f,  877.5f},{   2064.7f,  1950.0f,  1755.0f},{   4323.5f,  4083.3f,  3675.0f},{   8647.1f,  8166.7f,  7350.0f}},
      {{  1147.1f,  1083.3f,  975.0f},{   2294.1f,  2166.7f,  1950.0f},{   4803.9f,  4537.0f,  4083.3f},{   9607.8f,  9074.1f,  8166.7f}}
  }
};

/*
 * Calculates 802.11ax HE SU data rate corresponding to a given 802.11ax MCS index,
 * bandwidth, and guard interval.
 */
static float ieee80211_he_ofdm_rate(guint nsts, guint mcs, guint bw, guint gi)
{
  float rate=0.0;
  if ( ((nsts-1) < HE_MAX_NSTS) && (mcs < HE_MAX_MCS) && ( bw < HE_SU_MAX_BW) && ( gi < HE_MAX_GI ) ) {
    rate = he_ofdm_tab[nsts-1][mcs][bw][gi];
  }
  return rate;
}

/*
 * HE MU OFDMA MCS rate table converted from http://mcsindex.com/
 * indexed by (NSTS,MCS,RU,GI)
 */
#define HE_MU_MAX_RU 6
static float he_mu_ofdma_tab[HE_MAX_NSTS][HE_MAX_MCS][HE_MU_MAX_RU][HE_MAX_GI] = {
  {
      {{    0.9f,    0.8f,    0.8f},{     1.8f,    1.7f,    1.5f},{     3.8f,    3.5f,    3.2f},{      8.6f,     8.1f,    7.3f},{     17.2f,    16.3f,    14.6f},{     36.0f,    34.0f,    30.6f}},
      {{    1.8f,    1.7f,    1.5f},{     3.5f,    3.3f,    3.0f},{     7.5f,    7.1f,    6.4f},{     17.2f,    16.3f,   14.6f},{     34.4f,    32.5f,    29.3f},{     72.1f,    68.1f,    61.3f}},
      {{    2.6f,    2.5f,    2.3f},{     5.3f,    5.0f,    4.5f},{    11.3f,   10.6f,    9.6f},{     25.8f,    24.4f,   21.9f},{     51.6f,    48.8f,    43.9f},{    108.1f,   102.1f,    91.9f}},
      {{    3.5f,    3.3f,    3.0f},{     7.1f,    6.7f,    6.0f},{    15.0f,   14.2f,   12.8f},{     34.4f,    32.5f,   29.3f},{     68.8f,    65.0f,    58.5f},{    144.1f,   136.1f,   122.5f}},
      {{    5.3f,    5.0f,    4.5f},{    10.6f,   10.0f,    9.0f},{    22.5f,   21.3f,   19.1f},{     51.6f,    48.8f,   43.9f},{    103.2f,    97.5f,    87.8f},{    216.2f,   204.2f,   183.8f}},
      {{    7.1f,    6.7f,    6.0f},{    14.1f,   13.3f,   12.0f},{    30.0f,   28.3f,   25.5f},{     68.8f,    65.0f,   58.5f},{    137.6f,   130.0f,   117.0f},{    288.2f,   272.2f,   245.0f}},
      {{    7.9f,    7.5f,    6.8f},{    15.9f,   15.0f,   13.5f},{    33.8f,   31.9f,   28.7f},{     77.4f,    73.1f,   65.8f},{    154.9f,   146.3f,   131.6f},{    324.3f,   306.3f,   275.6f}},
      {{    8.8f,    8.3f,    7.5f},{    17.6f,   16.7f,   15.0f},{    37.5f,   35.4f,   31.9f},{     86.0f,    81.3f,   73.1f},{    172.1f,   162.5f,   146.3f},{    360.3f,   340.3f,   306.3f}},
      {{   10.6f,   10.0f,    9.0f},{    21.2f,   20.0f,   18.0f},{    45.0f,   42.5f,   38.3f},{    103.2f,    97.5f,   87.8f},{    206.5f,   195.0f,   175.5f},{    432.4f,   408.3f,   367.5f}},
      {{   11.8f,   11.1f,   10.0f},{    23.5f,   22.2f,   20.0f},{    50.0f,   47.2f,   42.5f},{    114.7f,   108.3f,   97.5f},{    229.4f,   216.7f,   195.0f},{    480.4f,   453.7f,   408.3f}},
      {{   13.2f,   12.5f,   11.3f},{    26.5f,   25.0f,   22.5f},{    56.3f,   53.1f,   47.8f},{    129.0f,   121.9f,  109.7f},{    258.1f,   243.8f,   219.4f},{    540.4f,   510.4f,   459.4f}},
      {{   14.7f,   13.9f,   12.5f},{    29.4f,   27.8f,   25.0f},{    62.5f,   59.0f,   53.1f},{    143.4f,   135.4f,  121.9f},{    286.8f,   270.8f,   243.8f},{    600.5f,   567.1f,   510.4f}}
  },{
      {{    1.8f,    1.7f,    1.5f},{     3.5f,    3.3f,    3.0f},{     7.5f,    7.1f,    6.4f},{     17.2f,    16.3f,   14.6f},{     34.4f,    32.5f,    29.3f},{     72.1f,    68.1f,    61.3f}},
      {{    3.5f,    3.3f,    3.0f},{     7.1f,    6.7f,    6.0f},{    15.0f,   14.2f,   12.8f},{     34.4f,    32.5f,   29.3f},{     68.8f,    65.0f,    58.5f},{    144.1f,   136.1f,   122.5f}},
      {{    5.3f,    5.0f,    4.5f},{    10.6f,   10.0f,    9.0f},{    22.5f,   21.3f,   19.1f},{     51.6f,    48.8f,   43.9f},{    103.2f,    97.5f,    87.8f},{    216.2f,   204.2f,   183.8f}},
      {{    7.1f,    6.7f,    6.0f},{    14.1f,   13.3f,   12.0f},{    30.0f,   28.3f,   25.5f},{     68.8f,    65.0f,   58.5f},{    137.6f,   130.0f,   117.0f},{    288.2f,   272.2f,   245.0f}},
      {{   10.6f,   10.0f,    9.0f},{    21.2f,   20.0f,   18.0f},{    45.0f,   42.5f,   38.3f},{    103.2f,    97.5f,   87.8f},{    206.5f,   195.0f,   175.5f},{    432.4f,   408.3f,   367.5f}},
      {{   14.1f,   13.3f,   12.0f},{    28.2f,   26.7f,   24.0f},{    60.0f,   56.7f,   51.0f},{    137.6f,   130.0f,  117.0f},{    275.3f,   260.0f,   234.0f},{    576.5f,   544.4f,   490.0f}},
      {{   15.9f,   15.0f,   13.5f},{    31.8f,   30.0f,   27.0f},{    67.5f,   63.8f,   57.4f},{    154.9f,   146.3f,  131.6f},{    309.7f,   292.5f,   263.3f},{    648.5f,   612.5f,   551.3f}},
      {{   17.6f,   16.7f,   15.0f},{    35.3f,   33.3f,   30.0f},{    75.0f,   70.8f,   63.8f},{    172.1f,   162.5f,  146.3f},{    344.1f,   325.0f,   292.5f},{    720.6f,   680.6f,   612.5f}},
      {{   21.2f,   20.0f,   18.0f},{    42.4f,   40.0f,   36.0f},{    90.0f,   85.0f,   76.5f},{    206.5f,   195.0f,  175.5f},{    412.9f,   390.0f,   351.0f},{    864.7f,   816.7f,   735.0f}},
      {{   23.5f,   22.2f,   20.0f},{    47.1f,   44.4f,   40.0f},{   100.0f,   94.4f,   85.0f},{    229.4f,   216.7f,  195.0f},{    458.8f,   433.3f,   390.0f},{    960.8f,   907.4f,   816.7f}},
      {{   26.5f,   25.0f,   22.5f},{    52.9f,   50.0f,   45.0f},{   112.5f,  106.3f,   95.6f},{    258.1f,   243.8f,  219.4f},{    516.2f,   487.5f,   438.8f},{   1080.9f,  1020.8f,   918.8f}},
      {{   29.4f,   27.8f,   25.0f},{    58.8f,   55.6f,   50.0f},{   125.0f,  118.1f,  106.3f},{    286.8f,   270.8f,  243.8f},{    573.5f,   541.7f,   487.5f},{   1201.0f,  1134.3f,  1020.8f}}
  },{
      {{    2.6f,    2.5f,    2.3f},{     5.3f,    5.0f,    4.5f},{    11.3f,   10.6f,    9.6f},{     25.8f,    24.4f,   21.9f},{     51.6f,    48.8f,    43.9f},{    108.1f,   102.1f,    91.9f}},
      {{    5.3f,    5.0f,    4.5f},{    10.6f,   10.0f,    9.0f},{    22.5f,   21.3f,   19.1f},{     51.6f,    48.8f,   43.9f},{    103.2f,    97.5f,    87.8f},{    216.2f,   204.2f,   183.8f}},
      {{    7.9f,    7.5f,    6.8f},{    15.9f,   15.0f,   13.5f},{    33.8f,   31.9f,   28.7f},{     77.4f,    73.1f,   65.8f},{    154.9f,   146.3f,   131.6f},{    324.3f,   306.3f,   275.6f}},
      {{   10.6f,   10.0f,    9.0f},{    21.2f,   20.0f,   18.0f},{    45.0f,   42.5f,   38.3f},{    103.2f,    97.5f,   87.8f},{    206.5f,   195.0f,   175.5f},{    432.4f,   408.3f,   367.5f}},
      {{   15.9f,   15.0f,   13.5f},{    31.8f,   30.0f,   27.0f},{    67.5f,   63.8f,   57.4f},{    154.9f,   146.3f,  131.6f},{    309.7f,   292.5f,   263.3f},{    648.5f,   612.5f,   551.3f}},
      {{   21.2f,   20.0f,   18.0f},{    42.4f,   40.0f,   36.0f},{    90.0f,   85.0f,   76.5f},{    206.5f,   195.0f,  175.5f},{    412.9f,   390.0f,   351.0f},{    864.7f,   816.7f,   735.0f}},
      {{   23.8f,   22.5f,   20.3f},{    47.6f,   45.0f,   40.5f},{   101.3f,   95.6f,   86.1f},{    232.3f,   219.4f,  197.4f},{    464.6f,   438.8f,   394.9f},{    972.8f,   918.8f,   826.9f}},
      {{   26.5f,   25.0f,   22.5f},{    52.9f,   50.0f,   45.0f},{   112.5f,  106.3f,   95.6f},{    258.1f,   243.8f,  219.4f},{    516.2f,   487.5f,   438.8f},{   1080.9f,  1020.8f,   918.8f}},
      {{   31.8f,   30.0f,   27.0f},{    63.5f,   60.0f,   54.0f},{   135.0f,  127.5f,  114.8f},{    309.7f,   292.5f,  263.3f},{    619.4f,   585.0f,   526.5f},{   1297.1f,  1225.0f,  1102.5f}},
      {{   35.3f,   33.3f,   30.0f},{    70.6f,   66.7f,   60.0f},{   150.0f,  141.7f,  127.5f},{    344.1f,   325.0f,  292.5f},{    688.2f,   650.0f,   585.0f},{   1441.2f,  1361.1f,  1225.0f}},
      {{   39.7f,   37.5f,   33.8f},{    79.4f,   75.0f,   67.5f},{   168.8f,  159.4f,  143.4f},{    387.1f,   365.6f,  329.1f},{    774.3f,   731.3f,   658.1f},{   1621.3f,  1531.3f,  1378.1f}},
      {{   44.1f,   41.7f,   37.5f},{    88.2f,   83.3f,   75.0f},{   187.5f,  177.1f,  159.4f},{    430.1f,   406.3f,  365.6f},{    860.3f,   812.5f,   731.3f},{   1801.5f,  1701.4f,  1531.3f}}
  },{
      {{    3.5f,    3.3f,    3.0f},{     7.1f,    6.7f,    6.0f},{    15.0f,   14.2f,   12.8f},{     34.4f,    32.5f,   29.3f},{     68.8f,    65.0f,    58.5f},{    144.1f,   136.1f,   122.5f}},
      {{    7.1f,    6.7f,    6.0f},{    14.1f,   13.3f,   12.0f},{    30.0f,   28.3f,   25.5f},{     68.8f,    65.0f,   58.5f},{    137.6f,   130.0f,   117.0f},{    288.2f,   272.2f,   245.0f}},
      {{   10.6f,   10.0f,    9.0f},{    21.2f,   20.0f,   18.0f},{    45.0f,   42.5f,   38.3f},{    103.2f,    97.5f,   87.8f},{    206.5f,   195.0f,   175.5f},{    432.4f,   408.3f,   367.5f}},
      {{   14.1f,   13.3f,   12.0f},{    28.2f,   26.7f,   24.0f},{    60.0f,   56.7f,   51.0f},{    137.6f,   130.0f,  117.0f},{    275.3f,   260.0f,   234.0f},{    576.5f,   544.4f,   490.0f}},
      {{   21.2f,   20.0f,   18.0f},{    42.4f,   40.0f,   36.0f},{    90.0f,   85.0f,   76.5f},{    206.5f,   195.0f,  175.5f},{    412.9f,   390.0f,   351.0f},{    864.7f,   816.7f,   735.0f}},
      {{   28.2f,   26.7f,   24.0f},{    56.5f,   53.3f,   48.0f},{   120.0f,  113.3f,  102.0f},{    275.3f,   260.0f,  234.0f},{    550.6f,   520.0f,   468.0f},{   1152.9f,  1088.9f,   980.0f}},
      {{   31.8f,   30.0f,   27.0f},{    63.5f,   60.0f,   54.0f},{   135.0f,  127.5f,  114.8f},{    309.7f,   292.5f,  263.3f},{    619.4f,   585.0f,   526.5f},{   1297.1f,  1225.0f,  1102.5f}},
      {{   35.3f,   33.3f,   30.0f},{    70.6f,   66.7f,   60.0f},{   150.0f,  141.7f,  127.5f},{    344.1f,   325.0f,  292.5f},{    688.2f,   650.0f,   585.0f},{   1441.2f,  1361.1f,  1225.0f}},
      {{   42.4f,   40.0f,   36.0f},{    84.7f,   80.0f,   72.0f},{   180.0f,  170.0f,  153.0f},{    412.9f,   390.0f,  351.0f},{    825.9f,   780.0f,   702.0f},{   1729.4f,  1633.3f,  1470.0f}},
      {{   47.1f,   44.4f,   40.0f},{    94.1f,   88.9f,   80.0f},{   200.0f,  188.9f,  170.0f},{    458.8f,   433.3f,  390.0f},{    917.6f,   866.7f,   780.0f},{   1921.6f,  1814.8f,  1633.3f}},
      {{   52.9f,   50.0f,   45.0f},{   105.9f,  100.0f,   90.0f},{   225.0f,  212.5f,  191.3f},{    516.2f,   487.5f,  438.8f},{   1032.4f,   975.0f,   877.5f},{   2161.8f,  2041.7f,  1837.5f}},
      {{   58.8f,   55.6f,   50.0f},{   117.6f,  111.1f,  100.0f},{   250.0f,  236.1f,  212.5f},{    573.5f,   541.7f,  487.5f},{   1147.1f,  1083.3f,   975.0f},{   2402.0f,  2268.5f,  2041.7f}}
  },{
      {{    4.4f,    4.2f,    3.8f},{     8.8f,    8.3f,    7.5f},{    18.8f,   17.7f,   15.9f},{     43.0f,    40.6f,   36.6f},{     86.0f,    81.3f,    73.1f},{    180.1f,   170.1f,   153.1f}},
      {{    8.8f,    8.3f,    7.5f},{    17.6f,   16.7f,   15.0f},{    37.5f,   35.4f,   31.9f},{     86.0f,    81.3f,   73.1f},{    172.1f,   162.5f,   146.3f},{    360.3f,   340.3f,   306.3f}},
      {{   13.2f,   12.5f,   11.3f},{    26.5f,   25.0f,   22.5f},{    56.3f,   53.1f,   47.8f},{    129.0f,   121.9f,  109.7f},{    258.1f,   243.8f,   219.4f},{    540.4f,   510.4f,   459.4f}},
      {{   17.6f,   16.7f,   15.0f},{    35.3f,   33.3f,   30.0f},{    75.0f,   70.8f,   63.8f},{    172.1f,   162.5f,  146.3f},{    344.1f,   325.0f,   292.5f},{    720.6f,   680.6f,   612.5f}},
      {{   26.5f,   25.0f,   22.5f},{    52.9f,   50.0f,   45.0f},{   112.5f,  106.3f,   95.6f},{    258.1f,   243.8f,  219.4f},{    516.2f,   487.5f,   438.8f},{   1080.9f,  1020.8f,   918.8f}},
      {{   35.3f,   33.3f,   30.0f},{    70.6f,   66.7f,   60.0f},{   150.0f,  141.7f,  127.5f},{    344.1f,   325.0f,  292.5f},{    688.2f,   650.0f,   585.0f},{   1441.2f,  1361.1f,  1225.0f}},
      {{   39.7f,   37.5f,   33.8f},{    79.4f,   75.0f,   67.5f},{   168.8f,  159.4f,  143.4f},{    387.1f,   365.6f,  329.1f},{    774.3f,   731.3f,   658.1f},{   1621.3f,  1531.3f,  1378.1f}},
      {{   44.1f,   41.7f,   37.5f},{    88.2f,   83.3f,   75.0f},{   187.5f,  177.1f,  159.4f},{    430.1f,   406.3f,  365.6f},{    860.3f,   812.5f,   731.3f},{   1801.5f,  1701.4f,  1531.3f}},
      {{   52.9f,   50.0f,   45.0f},{   105.9f,  100.0f,   90.0f},{   225.0f,  212.5f,  191.3f},{    516.2f,   487.5f,  438.8f},{   1032.4f,   975.0f,   877.5f},{   2161.8f,  2041.7f,  1837.5f}},
      {{   58.8f,   55.6f,   50.0f},{   117.6f,  111.1f,  100.0f},{   250.0f,  236.1f,  212.5f},{    573.5f,   541.7f,  487.5f},{   1147.1f,  1083.3f,   975.0f},{   2402.0f,  2268.5f,  2041.7f}},
      {{   66.2f,   62.5f,   56.3f},{   132.4f,  125.0f,  112.5f},{   281.3f,  265.6f,  239.1f},{    645.2f,   609.4f,  548.4f},{   1290.4f,  1218.8f,  1096.9f},{   2702.2f,  2552.1f,  2296.9f}},
      {{   73.5f,   69.4f,   62.5f},{   147.1f,  138.9f,  125.0f},{   312.5f,  295.1f,  265.6f},{    716.9f,   677.1f,  609.4f},{   1433.8f,  1354.2f,  1218.8f},{   3002.5f,  2835.6f,  2552.1f}}
  },{
      {{    5.3f,    5.0f,    4.5f},{    10.6f,   10.0f,    9.0f},{    22.5f,   21.3f,   19.1f},{     51.6f,    48.8f,   43.9f},{    103.2f,    97.5f,    87.8f},{    216.2f,   204.2f,   183.8f}},
      {{   10.6f,   10.0f,    9.0f},{    21.2f,   20.0f,   18.0f},{    45.0f,   42.5f,   38.3f},{    103.2f,    97.5f,   87.8f},{    206.5f,   195.0f,   175.5f},{    432.4f,   408.3f,   367.5f}},
      {{   15.9f,   15.0f,   13.5f},{    31.8f,   30.0f,   27.0f},{    67.5f,   63.8f,   57.4f},{    154.9f,   146.3f,  131.6f},{    309.7f,   292.5f,   263.3f},{    648.5f,   612.5f,   551.3f}},
      {{   21.2f,   20.0f,   18.0f},{    42.4f,   40.0f,   36.0f},{    90.0f,   85.0f,   76.5f},{    206.5f,   195.0f,  175.5f},{    412.9f,   390.0f,   351.0f},{    864.7f,   816.7f,   735.0f}},
      {{   31.8f,   30.0f,   27.0f},{    63.5f,   60.0f,   54.0f},{   135.0f,  127.5f,  114.8f},{    309.7f,   292.5f,  263.3f},{    619.4f,   585.0f,   526.5f},{   1297.1f,  1225.0f,  1102.5f}},
      {{   42.4f,   40.0f,   36.0f},{    84.7f,   80.0f,   72.0f},{   180.0f,  170.0f,  153.0f},{    412.9f,   390.0f,  351.0f},{    825.9f,   780.0f,   702.0f},{   1729.4f,  1633.3f,  1470.0f}},
      {{   47.6f,   45.0f,   40.5f},{    95.3f,   90.0f,   81.0f},{   202.5f,  191.3f,  172.1f},{    464.6f,   438.8f,  394.9f},{    929.1f,   877.5f,   789.8f},{   1945.6f,  1837.5f,  1653.8f}},
      {{   52.9f,   50.0f,   45.0f},{   105.9f,  100.0f,   90.0f},{   225.0f,  212.5f,  191.3f},{    516.2f,   487.5f,  438.8f},{   1032.4f,   975.0f,   877.5f},{   2161.8f,  2041.7f,  1837.5f}},
      {{   63.5f,   60.0f,   54.0f},{   127.1f,  120.0f,  108.0f},{   270.0f,  255.0f,  229.5f},{    619.4f,   585.0f,  526.5f},{   1238.8f,  1170.0f,  1053.0f},{   2594.1f,  2450.0f,  2205.0f}},
      {{   70.6f,   66.7f,   60.0f},{   141.2f,  133.3f,  120.0f},{   300.0f,  283.3f,  255.0f},{    688.2f,   650.0f,  585.0f},{   1376.5f,  1300.0f,  1170.0f},{   2882.4f,  2722.2f,  2450.0f}},
      {{   79.4f,   75.0f,   67.5f},{   158.8f,  150.0f,  135.0f},{   337.5f,  318.8f,  286.9f},{    774.3f,   731.3f,  658.1f},{   1548.5f,  1462.5f,  1316.3f},{   3242.6f,  3062.5f,  2756.3f}},
      {{   88.2f,   83.3f,   75.0f},{   176.5f,  166.7f,  150.0f},{   375.0f,  354.2f,  318.8f},{    860.3f,   812.5f,  731.3f},{   1720.6f,  1625.0f,  1462.5f},{   3602.9f,  3402.8f,  3062.5f}}
  },{
      {{    6.2f,    5.8f,    5.3f},{    12.4f,   11.7f,   10.5f},{    26.3f,   24.8f,   22.3f},{     60.2f,    56.9f,   51.2f},{    120.4f,   113.8f,   102.4f},{    252.2f,   238.2f,   214.4f}},
      {{   12.4f,   11.7f,   10.5f},{    24.7f,   23.3f,   21.0f},{    52.5f,   49.6f,   44.6f},{    120.4f,   113.8f,  102.4f},{    240.9f,   227.5f,   204.8f},{    504.4f,   476.4f,   428.8f}},
      {{   18.5f,   17.5f,   15.8f},{    37.1f,   35.0f,   31.5f},{    78.8f,   74.4f,   66.9f},{    180.7f,   170.6f,  153.6f},{    361.3f,   341.3f,   307.1f},{    756.6f,   714.6f,   643.1f}},
      {{   24.7f,   23.3f,   21.0f},{    49.4f,   46.7f,   42.0f},{   105.0f,   99.2f,   89.3f},{    240.9f,   227.5f,  204.8f},{    481.8f,   455.0f,   409.5f},{   1008.8f,   952.8f,   857.5f}},
      {{   37.1f,   35.0f,   31.5f},{    74.1f,   70.0f,   63.0f},{   157.5f,  148.8f,  133.9f},{    361.3f,   341.3f,  307.1f},{    722.6f,   682.5f,   614.3f},{   1513.2f,  1429.2f,  1286.3f}},
      {{   49.4f,   46.7f,   42.0f},{    98.8f,   93.3f,   84.0f},{   210.0f,  198.3f,  178.5f},{    481.8f,   455.0f,  409.5f},{    963.5f,   910.0f,   819.0f},{   2017.6f,  1905.6f,  1715.0f}},
      {{   55.6f,   52.5f,   47.3f},{   111.2f,  105.0f,   94.5f},{   236.3f,  223.1f,  200.8f},{    542.0f,   511.9f,  460.7f},{   1084.0f,  1023.8f,   921.4f},{   2269.9f,  2143.8f,  1929.4f}},
      {{   61.8f,   58.3f,   52.5f},{   123.5f,  116.7f,  105.0f},{   262.5f,  247.9f,  223.1f},{    602.2f,   568.8f,  511.9f},{   1204.4f,  1137.5f,  1023.8f},{   2522.1f,  2381.9f,  2143.8f}},
      {{   74.1f,   70.0f,   63.0f},{   148.2f,  140.0f,  126.0f},{   315.0f,  297.5f,  267.8f},{    722.6f,   682.5f,  614.3f},{   1445.3f,  1365.0f,  1228.5f},{   3026.5f,  2858.3f,  2572.5f}},
      {{   82.4f,   77.8f,   70.0f},{   164.7f,  155.6f,  140.0f},{   350.0f,  330.6f,  297.5f},{    802.9f,   758.3f,  682.5f},{   1605.9f,  1516.7f,  1365.0f},{   3362.7f,  3175.9f,  2858.3f}},
      {{   92.6f,   87.5f,   78.8f},{   185.3f,  175.0f,  157.5f},{   393.8f,  371.9f,  334.7f},{    903.3f,   853.1f,  767.8f},{   1806.6f,  1706.3f,  1535.6f},{   3783.1f,  3572.9f,  3215.6f}},
      {{  102.9f,   97.2f,   87.5f},{   205.9f,  194.4f,  175.0f},{   437.5f,  413.2f,  371.9f},{   1003.7f,   947.9f,  853.1f},{   2007.4f,  1895.8f,  1706.3f},{   4203.4f,  3969.9f,  3572.9f}}
  },{
      {{    7.1f,    6.7f,    6.0f},{    14.1f,   13.3f,   12.0f},{    30.0f,   28.3f,   25.5f},{     68.8f,    65.0f,   58.5f},{    137.6f,   130.0f,   117.0f},{    288.2f,   272.2f,   245.0f}},
      {{   14.1f,   13.3f,   12.0f},{    28.2f,   26.7f,   24.0f},{    60.0f,   56.7f,   51.0f},{    137.6f,   130.0f,  117.0f},{    275.3f,   260.0f,   234.0f},{    576.5f,   544.4f,   490.0f}},
      {{   21.2f,   20.0f,   18.0f},{    42.4f,   40.0f,   36.0f},{    90.0f,   85.0f,   76.5f},{    206.5f,   195.0f,  175.5f},{    412.9f,   390.0f,   351.0f},{    864.7f,   816.7f,   735.0f}},
      {{   28.2f,   26.7f,   24.0f},{    56.5f,   53.3f,   48.0f},{   120.0f,  113.3f,  102.0f},{    275.3f,   260.0f,  234.0f},{    550.6f,   520.0f,   468.0f},{   1152.9f,  1088.9f,   980.0f}},
      {{   42.4f,   40.0f,   36.0f},{    84.7f,   80.0f,   72.0f},{   180.0f,  170.0f,  153.0f},{    412.9f,   390.0f,  351.0f},{    825.9f,   780.0f,   702.0f},{   1729.4f,  1633.3f,  1470.0f}},
      {{   56.5f,   53.3f,   48.0f},{   112.9f,  106.7f,   96.0f},{   240.0f,  226.7f,  204.0f},{    550.6f,   520.0f,  468.0f},{   1101.2f,  1040.0f,   936.0f},{   2305.9f,  2177.8f,  1960.0f}},
      {{   63.5f,   60.0f,   54.0f},{   127.1f,  120.0f,  108.0f},{   270.0f,  255.0f,  229.5f},{    619.4f,   585.0f,  526.5f},{   1238.8f,  1170.0f,  1053.0f},{   2594.1f,  2450.0f,  2205.0f}},
      {{   70.6f,   66.7f,   60.0f},{   141.2f,  133.3f,  120.0f},{   300.0f,  283.3f,  255.0f},{    688.2f,   650.0f,  585.0f},{   1376.5f,  1300.0f,  1170.0f},{   2882.4f,  2722.2f,  2450.0f}},
      {{   84.7f,   80.0f,   72.0f},{   169.4f,  160.0f,  144.0f},{   360.0f,  340.0f,  306.0f},{    825.9f,   780.0f,  702.0f},{   1651.8f,  1560.0f,  1404.0f},{   3458.8f,  3266.7f,  2940.0f}},
      {{   94.1f,   88.9f,   80.0f},{   188.2f,  177.8f,  160.0f},{   400.0f,  377.8f,  340.0f},{    917.6f,   866.7f,  780.0f},{   1835.3f,  1733.3f,  1560.0f},{   3843.1f,  3629.6f,  3266.7f}},
      {{  105.9f,  100.0f,   90.0f},{   211.8f,  200.0f,  180.0f},{   450.0f,  425.0f,  382.5f},{   1032.4f,   975.0f,  877.5f},{   2064.7f,  1950.0f,  1755.0f},{   4323.5f,  4083.3f,  3675.0f}},
      {{  117.6f,  111.1f,  100.0f},{   235.3f,  222.2f,  200.0f},{   500.0f,  472.2f,  425.0f},{   1147.1f,  1083.3f,  975.0f},{   2294.1f,  2166.7f,  1950.0f},{   4803.9f,  4537.0f,  4083.3f}}
  }

};

/*
 * Calculates 802.11ax HE SU data rate corresponding to a given 802.11ax MCS index,
 * bandwidth, and guard interval.
 */
static float ieee80211_he_mu_ofdma_rate(guint nsts, guint mcs, guint ru, guint gi)
{
  float rate=0.0;
  if ( ((nsts-1) < HE_MAX_NSTS) && (mcs < HE_MAX_MCS) && ( (ru-4) < HE_MU_MAX_RU) && ( gi < HE_MAX_GI ) ) {
    rate = he_mu_ofdma_tab[nsts-1][mcs][ru-4][gi];
  }
  return rate;
}

static gint ett_wlan_radio = -1;
static gint ett_wlan_radio_11ac_user = -1;
static gint ett_wlan_radio_duration = -1;
static gint ett_wlan_radio_aggregate = -1;

/* previous frame details, for aggregate detection */
struct previous_frame_info {
  gboolean has_tsf_timestamp;
  guint64 tsf_timestamp;
  guint phy;
  union ieee_802_11_phy_info phy_info;
  guint prev_length;
  struct wlan_radio *radio_info;
};

static struct previous_frame_info previous_frame;
static struct aggregate *current_aggregate;
static wmem_list_t *agg_tracker_list;

static guint calculate_11n_duration(guint frame_length,
  struct ieee_802_11n* info_n,
  int stbc_streams)
{
  guint bits;
  guint bits_per_symbol;
  guint Mstbc;
  guint symbols;

  /* data field calculation */
  if (1) {
    /* see ieee80211n-2009 20.3.11 (20-32) - for BCC FEC */
    bits = 8 * frame_length + 16 + ieee80211_ht_Nes[info_n->mcs_index] * 6;
    Mstbc = stbc_streams ? 2 : 1;
    bits_per_symbol = ieee80211_ht_Dbps[info_n->mcs_index] *
        (info_n->bandwidth == PHDR_802_11_BANDWIDTH_40_MHZ ? 2 : 1);
    symbols = bits / (bits_per_symbol * Mstbc);
  } else {
    /* TODO: handle LDPC FEC, it changes the rounding */
  }
  /* round up to whole symbols */
  if ((bits % (bits_per_symbol * Mstbc)) > 0)
    symbols++;

  symbols *= Mstbc;
  return (symbols * (info_n->short_gi ? 36 : 40) + 5) / 10;
}

/* TODO: this is a crude quick hack, need proper calculation of bits/symbols/FEC/etc */
static guint calculate_11ac_duration(guint frame_length, float data_rate)
{
  guint bits = 8 * frame_length + 16;
  return (guint) (bits / data_rate);
}

static void adjust_agg_tsf(gpointer data, gpointer user_data)
{
  struct wlan_radio *wlan_radio_info = (struct wlan_radio *)data;
  guint64 *ppdu_start = (guint64 *)user_data;

  wlan_radio_info->start_tsf += (*ppdu_start);
  wlan_radio_info->end_tsf += (*ppdu_start);
  if (wlan_radio_info->prior_aggregate_data == 0)
	  wlan_radio_info->ifs += (*ppdu_start);
}

/*
 * Dissect 802.11 pseudo-header containing radio information.
 */
static void
dissect_wlan_radio_phdr(tvbuff_t * tvb, packet_info * pinfo, proto_tree * tree, struct ieee_802_11_phdr *phdr)
{
  proto_item *ti;
  proto_tree *radio_tree;
  float data_rate = 0.0f;
  gboolean have_data_rate = FALSE;
  gboolean has_short_preamble = FALSE;
  gboolean short_preamble = TRUE;
  guint bandwidth = 0;
  gboolean can_calculate_rate = FALSE;
  proto_item *p_item;

  guint frame_length = tvb_reported_length(tvb); /* length of 802.11 frame data */

  /* durations in microseconds */
  guint preamble = 0, agg_preamble = 0; /* duration of plcp */
  gboolean have_duration = FALSE;
  guint duration = 0; /* duration of whole frame (plcp + mac data + any trailing parts) */
  guint prior_duration = 0; /* duration of previous part of aggregate */

  struct wlan_radio *wlan_radio_info;
  int phy = phdr->phy;
  union ieee_802_11_phy_info *phy_info = &phdr->phy_info;

  col_set_str(pinfo->cinfo, COL_PROTOCOL, "Radio");
  col_clear(pinfo->cinfo, COL_INFO);

  /* Calculate the data rate, if we have the necessary data */
  if (phdr->has_data_rate) {
    data_rate = phdr->data_rate * 0.5f;
    have_data_rate = TRUE;
  }

  /* this is the first time we are looking at this frame during a
   * capture dissection, so we know the dissection is done in
   * frame order (subsequent dissections may be random access) */
  if (!pinfo->fd->visited) {
    wlan_radio_info = wmem_new0(wmem_file_scope(), struct wlan_radio);
    p_add_proto_data(wmem_file_scope(), pinfo, proto_wlan_radio, 0, wlan_radio_info);

    /* A-MPDU / aggregate detection
     * Different generators need different detection algorithms
     * One common pattern is to report all subframes in the aggregate with the same
     * tsf, referenced to the start of the AMPDU (Broadcom). Another pattern is to
     * report the tsf on the first subframe, then tsf=0 for the rest of the subframes
     * (Intel).
     * Another pattern is to report TSF = -1 for all frames but the last, and the
     * last has the tsf referenced to the end of the PPDU. (QCA)
     */
    /* TODO: add code to work around problem with captures from Macbooks where
     * aggregate subframes frames with FCS errors sometimes have incorrect
     * PHY information.
     */
    if (pinfo->fd->num > 1 &&
        (phdr->phy == PHDR_802_11_PHY_11N || phdr->phy == PHDR_802_11_PHY_11AC) &&
        phdr->phy == previous_frame.phy &&
        phdr->has_tsf_timestamp && previous_frame.has_tsf_timestamp &&
        (phdr->tsf_timestamp == previous_frame.tsf_timestamp || /* find matching TSFs */
         (!current_aggregate && previous_frame.tsf_timestamp && phdr->tsf_timestamp == 0) || /* Intel detect second frame */
         (previous_frame.tsf_timestamp == G_MAXUINT64) /* QCA, detect last frame */
        )) {
      /* we're in an aggregate */
      if (!current_aggregate) {
        /* this is the second frame in an aggregate
         * where we first detect the aggregate */
        current_aggregate = wmem_new0(wmem_file_scope(), struct aggregate);
        current_aggregate->phy = previous_frame.phy;
        current_aggregate->phy_info = previous_frame.phy_info;

        /* go back to the first frame in the aggregate,
         * and mark it as part of this aggregate */
        if (previous_frame.radio_info != NULL)
          previous_frame.radio_info->aggregate = current_aggregate;
      }
      wlan_radio_info->aggregate = current_aggregate;

      /* accumulate the length of the prior subframes in the aggregate.
       * Round up previous frame length (padding) */
      if (previous_frame.prev_length % 4 != 0) {
        previous_frame.prev_length = (previous_frame.prev_length | 3) + 1;
      }
      /* Also add the MPDU delimiter length */
      previous_frame.prev_length += 4;
      /* TODO: add padding to meet minimum subframe timing constraint */
      wlan_radio_info->prior_aggregate_data = previous_frame.prev_length;
      previous_frame.prev_length += frame_length;

      /* work around macbook/QCA FCS error frame PHY rate bug here
       * Some Macbook generators and some QCA generators erroneously report
       * low PHY rates for some subframes within an aggregate that have FCS errors.
       * All subframes must have the same PHY rate.
       * Here we take the highest reported rate for the aggregate. */
      switch (phdr->phy) {
      case PHDR_802_11_PHY_11N:
        {
          struct ieee_802_11n *info_n = &phy_info->info_11n;
          struct ieee_802_11n *agg_info_n = &current_aggregate->phy_info.info_11n;

          if (info_n->has_mcs_index && agg_info_n->has_mcs_index &&
              info_n->mcs_index > agg_info_n->mcs_index)
              current_aggregate->phy_info = *phy_info;
        }
        break;

      case PHDR_802_11_PHY_11AC:
        {
          struct ieee_802_11ac *info_ac = &phy_info->info_11ac;
          struct ieee_802_11ac *agg_info_ac = &current_aggregate->phy_info.info_11ac;

          if (info_ac->mcs[0] > agg_info_ac->mcs[0])
              current_aggregate->phy_info = *phy_info;
        }
        break;
      }
      /* TODO record a warning if the PHY rate does not match the aggregate */
      phy = current_aggregate->phy;
      phy_info = &current_aggregate->phy_info;
    } else {
      current_aggregate = NULL;
      previous_frame.prev_length = frame_length;
    }
    previous_frame.has_tsf_timestamp = phdr->has_tsf_timestamp;
    previous_frame.tsf_timestamp = phdr->tsf_timestamp;
    previous_frame.phy = phdr->phy;
    previous_frame.phy_info = phdr->phy_info;
  } else {
    /* this frame has already been seen, so get its info structure */
    wlan_radio_info = (struct wlan_radio *) p_get_proto_data(wmem_file_scope(), pinfo, proto_wlan_radio, 0);

    if (wlan_radio_info->aggregate) {
      phy = wlan_radio_info->aggregate->phy;
      phy_info = &wlan_radio_info->aggregate->phy_info;
    }
  }

  ti = proto_tree_add_item(tree, proto_wlan_radio, tvb, 0, 0, ENC_NA);
  radio_tree = proto_item_add_subtree (ti, ett_wlan_radio);

  if (phy != PHDR_802_11_PHY_UNKNOWN) {
    proto_tree_add_uint(radio_tree, hf_wlan_radio_phy, tvb, 0, 0, phy);

    switch (phy) {

      case PHDR_802_11_PHY_11_FHSS:
      {
        struct ieee_802_11_fhss *info_fhss = &phy_info->info_11_fhss;

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
        struct ieee_802_11b *info_b = &phy_info->info_11b;

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
        struct ieee_802_11a *info_a = &phy_info->info_11a;

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
        struct ieee_802_11g *info_g = &phy_info->info_11g;

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
          struct ieee_802_11n *info_n = &phy_info->info_11n;
          guint bandwidth_40;

          /*
           * If we have all the fields needed to look up the data rate,
           * do so.
           */
          if (info_n->has_mcs_index &&
              info_n->has_bandwidth &&
              info_n->has_short_gi) {
            bandwidth_40 = (info_n->bandwidth == PHDR_802_11_BANDWIDTH_40_MHZ) ? 1 : 0;
            if (info_n->mcs_index < MAX_MCS_INDEX) {
              data_rate = ieee80211_htrate(info_n->mcs_index, bandwidth_40, info_n->short_gi);
              have_data_rate = TRUE;
            }
          }

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
        }
        break;

      case PHDR_802_11_PHY_11AC:
        {
          struct ieee_802_11ac *info_ac = &phy_info->info_11ac;
          guint i;

          if (info_ac->has_short_gi) {
            can_calculate_rate = TRUE;  /* well, if we also have the bandwidth */
            proto_tree_add_boolean(radio_tree, hf_wlan_radio_11ac_short_gi, tvb, 0, 0, info_ac->short_gi);
          } else {
            can_calculate_rate = FALSE; /* unknown GI length */
          }

          if (info_ac->has_bandwidth) {
            proto_tree_add_uint(radio_tree, hf_wlan_radio_11ac_bandwidth, tvb, 0, 0, info_ac->bandwidth);
            if (info_ac->bandwidth < G_N_ELEMENTS(ieee80211_vht_bw2rate_index))
              bandwidth = ieee80211_vht_bw2rate_index[info_ac->bandwidth];
            else
              can_calculate_rate = FALSE; /* unknown bandwidth */
          } else {
            can_calculate_rate = FALSE;   /* no bandwidth */
          }

          if (info_ac->has_stbc) {
            proto_tree_add_boolean(radio_tree, hf_wlan_radio_11ac_stbc, tvb, 0, 0,
                     info_ac->stbc);
          }

          if (info_ac->has_txop_ps_not_allowed) {
            proto_tree_add_boolean(radio_tree, hf_wlan_radio_11ac_txop_ps_not_allowed, tvb, 0, 0,
                     info_ac->txop_ps_not_allowed);
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

              proto_tree_add_uint(user_tree, hf_wlan_radio_11ac_nss, tvb, 0, 0, info_ac->nss[i]);
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
            proto_tree_add_uint(radio_tree, hf_wlan_radio_11ac_gid, tvb, 0, 0, info_ac->group_id);
          }

          if (info_ac->has_partial_aid) {
            proto_tree_add_uint(radio_tree, hf_wlan_radio_11ac_p_aid, tvb, 0, 0, info_ac->partial_aid);
          }
        }
        break;
      case PHDR_802_11_PHY_11AX:
      {
        struct ieee_802_11ax *info_ax = &phy_info->info_11ax;
        if (info_ax->has_gi && info_ax->has_bwru && info_ax->has_mcs_index) {
          if (info_ax->bwru < HE_SU_MAX_BW) {
            data_rate = ieee80211_he_ofdm_rate(info_ax->nsts,info_ax->mcs,info_ax->bwru,info_ax->gi);
          } else {
            data_rate = ieee80211_he_mu_ofdma_rate(info_ax->nsts,info_ax->mcs,info_ax->bwru,info_ax->gi);
          }
          if (data_rate != 0.0f) {
            proto_tree_add_float_format_value(radio_tree, hf_wlan_radio_data_rate, tvb, 0, 0,
                data_rate,
                "%.1f Mb/s",
                data_rate);
          }
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
    proto_tree_add_uint(radio_tree, hf_wlan_radio_channel, tvb, 0, 0, phdr->channel);
  }

  if (phdr->has_frequency) {
    col_add_fstr(pinfo->cinfo, COL_FREQ_CHAN, "%u MHz", phdr->frequency);
    proto_tree_add_uint(radio_tree, hf_wlan_radio_frequency, tvb, 0, 0, phdr->frequency);
  }

  if (phdr->has_signal_percent) {
    col_add_fstr(pinfo->cinfo, COL_RSSI, "%u%%", phdr->signal_percent);
    proto_tree_add_uint(radio_tree, hf_wlan_radio_signal_percent, tvb, 0, 0, phdr->signal_percent);
  }

  if (phdr->has_signal_db) {
    col_add_fstr(pinfo->cinfo, COL_RSSI, "%u dB", phdr->signal_db);
    proto_tree_add_uint(radio_tree, hf_wlan_radio_signal_db, tvb, 0, 0, phdr->signal_db);
  }

  if (phdr->has_signal_dbm) {
    col_add_fstr(pinfo->cinfo, COL_RSSI, "%d dBm", phdr->signal_dbm);
    proto_tree_add_int(radio_tree, hf_wlan_radio_signal_dbm, tvb, 0, 0, phdr->signal_dbm);
  }

  if (phdr->has_noise_percent) {
    proto_tree_add_uint(radio_tree, hf_wlan_radio_noise_percent, tvb, 0, 0, phdr->noise_percent);
  }

  if (phdr->has_noise_db) {
    proto_tree_add_uint(radio_tree, hf_wlan_radio_noise_db, tvb, 0, 0, phdr->noise_db);
  }

  if (phdr->has_noise_dbm) {
    proto_tree_add_int(radio_tree, hf_wlan_radio_noise_dbm, tvb, 0, 0, phdr->noise_dbm);
  }

  if (phdr->has_signal_dbm && phdr->has_noise_dbm) {
    proto_tree_add_int(radio_tree, hf_wlan_radio_snr, tvb, 0, 0, phdr->signal_dbm - phdr->noise_dbm);
  }
  /*
   * XXX - are the signal and noise in dB from a fixed reference point
   * guaranteed to use the *same* fixed reference point?  If so, we could
   * calculate the SNR if they're both present, too.
   */

  if (phdr->has_tsf_timestamp) {
    proto_tree_add_uint64(radio_tree, hf_wlan_radio_timestamp, tvb, 0, 0, phdr->tsf_timestamp);
  }
  if (phdr->has_aggregate_info) {
    proto_tree_add_boolean(radio_tree, hf_wlan_last_part_of_a_mpdu, tvb, 0, 0, phdr->aggregate_flags);
    proto_tree_add_boolean(radio_tree, hf_wlan_a_mpdu_delim_crc_error, tvb, 0, 0, phdr->aggregate_flags);
    proto_tree_add_uint(radio_tree, hf_wlan_a_mpdu_aggregate_id, tvb, 0, 0, phdr->aggregate_id);
  }

  /* make sure frame_length includes the FCS for accurate duration calculation */
  if (pinfo->pseudo_header->ieee_802_11.fcs_len == 0) {
    frame_length += 4;
  }

  if (have_data_rate && data_rate > 0) {
    /* duration calculations */
    gboolean assumed_short_preamble = FALSE;
    gboolean assumed_non_greenfield = FALSE;
    gboolean assumed_no_stbc = FALSE;
    gboolean assumed_no_extension_streams = FALSE;
    gboolean assumed_bcc_fec = FALSE;

    /* some generators report CCK frames as 'dynamic-cck-ofdm', which are converted
     * into the 11g PHY type, so we need to be smart and recognize which ones are
     * DSSS/CCK and which are OFDM. Use the data_rate to do this. */
    if (phy == PHDR_802_11_PHY_11G &&
      (data_rate == 1.0f || data_rate == 2.0f ||
      data_rate == 5.5f || data_rate == 11.0f ||
      data_rate == 22.0f || data_rate == 33.0f)) {
      phy = PHDR_802_11_PHY_11B;
    } else if (phy == PHDR_802_11_PHY_UNKNOWN &&
      (data_rate == 1.0f || data_rate == 2.0f ||
      data_rate == 5.5f || data_rate == 11.0f ||
      data_rate == 22.0f || data_rate == 33.0f)) {
      phy = PHDR_802_11_PHY_11B;
    } else if (phy == PHDR_802_11_PHY_UNKNOWN &&
      (data_rate == 6.0f || data_rate == 9.0f ||
       data_rate == 12.0f || data_rate == 18.0f ||
       data_rate == 24.0f || data_rate == 36.0f ||
       data_rate == 48.0f || data_rate == 54.0f)) {
      phy = PHDR_802_11_PHY_11A;
    }
    switch (phy) {

    case PHDR_802_11_PHY_11_FHSS:
      /* TODO: preamble/duration calc for FHSS */
      break;

    case PHDR_802_11_PHY_11B:
      if (!has_short_preamble || wlan_radio_always_short_preamble) {
          assumed_short_preamble = TRUE;
          short_preamble = TRUE;
      }
      preamble = short_preamble ? 72 + 24 : 144 + 48;

      /* calculation of frame duration
       * Things we need to know to calculate accurate duration
       * 802.11 / 802.11b (DSSS or CCK modulation)
       * - length of preamble
       * - rate
       */
      /* round up to whole microseconds */
      have_duration = TRUE;
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

      /* preamble + signal */
      preamble = 16 + 4;

      /* 16 service bits, data and 6 tail bits */
      guint bits = 16 + 8 * frame_length + 6;
      guint symbols = (guint) ceil(bits / (data_rate * 4));

      have_duration = TRUE;
      duration = preamble + symbols * 4;
      break;
    }

    case PHDR_802_11_PHY_11N:
    {
      struct ieee_802_11n *info_n = &phy_info->info_11n;

      /* We have all the fields required to calculate the duration */
      static const guint Nhtdltf[4] = {1, 2, 4, 4};
      static const guint Nhteltf[4] = {0, 1, 2, 4};
      guint Nsts;
      guint stbc_streams;
      guint ness;

      /*
       * If we don't have necessary fields, or if we have them but
       * they have invalid values, then bail.
       */
      if (!info_n->has_mcs_index ||
        info_n->mcs_index > MAX_MCS_INDEX ||
        !info_n->has_bandwidth ||
        !info_n->has_short_gi)
          break;

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

      if (info_n->has_stbc_streams) {
        stbc_streams = info_n->stbc_streams;
      } else {
        stbc_streams = 0;
        assumed_no_stbc = TRUE;
      }

      if (!info_n->has_ness) {
        assumed_no_extension_streams = TRUE;
      }

      if (!info_n->has_fec) {
        assumed_bcc_fec = TRUE;
      }

      /* data field calculation */
      if (wlan_radio_info->aggregate) {
        agg_preamble = preamble;
        if (wlan_radio_info->prior_aggregate_data != 0) {
          preamble = 0;
        }
        prior_duration = calculate_11n_duration(wlan_radio_info->prior_aggregate_data, info_n, stbc_streams);
        have_duration = TRUE;
        duration = preamble +
          calculate_11n_duration(frame_length + wlan_radio_info->prior_aggregate_data, info_n, stbc_streams)
          - prior_duration;
      } else {
        have_duration = TRUE;
        duration = preamble + calculate_11n_duration(frame_length, info_n, stbc_streams);
      }
      break;
    }

    case PHDR_802_11_PHY_11AC:
    {
      struct ieee_802_11ac *info_ac = &phy_info->info_11ac;

      if (!info_ac->has_stbc) {
        assumed_no_stbc = TRUE;
      }
      preamble = 32 + 4 * info_ac->nss[0] * (info_ac->has_stbc ? info_ac->stbc+1 : 1);

      if (wlan_radio_info->aggregate) {
        agg_preamble = preamble;
        if (wlan_radio_info->prior_aggregate_data != 0) {
          preamble = 0;
        }
        prior_duration = calculate_11ac_duration(wlan_radio_info->prior_aggregate_data, data_rate);
        have_duration = TRUE;
        duration = preamble +
          calculate_11ac_duration(wlan_radio_info->prior_aggregate_data + frame_length, data_rate)
          - prior_duration;
      } else {
        have_duration = TRUE;
        duration = preamble + calculate_11ac_duration(frame_length, data_rate);
      }
      break;
    }
    }

    if (!pinfo->fd->visited && have_duration && phdr->has_tsf_timestamp) {
      if (current_aggregate) {
        current_aggregate->duration = agg_preamble + prior_duration + duration;
        if (previous_frame.radio_info && previous_frame.radio_info->aggregate == current_aggregate)
          previous_frame.radio_info->nav = 0; // don't display NAV except for last frame in an aggregate
      }
      if (phdr->tsf_timestamp == G_MAXUINT64) {
        /* QCA aggregate, we don't know tsf yet */
        wlan_radio_info->start_tsf = prior_duration + (current_aggregate ? agg_preamble : 0);
        wlan_radio_info->end_tsf = prior_duration + duration + (current_aggregate ? agg_preamble : 0);
        if (agg_tracker_list == NULL) {
          agg_tracker_list = wmem_list_new(NULL);
        }
        wmem_list_append(agg_tracker_list, wlan_radio_info);
      } else if (current_aggregate && wlan_radio_tsf_at_end && phdr->tsf_timestamp != G_MAXUINT64) {
        /* QCA aggregate, last frame */
        wlan_radio_info->start_tsf = phdr->tsf_timestamp - duration;
        wlan_radio_info->end_tsf = phdr->tsf_timestamp;
        /* fix up the tsfs for the prior MPDUs */
        if (agg_tracker_list != NULL) {
          guint64 ppdu_start = phdr->tsf_timestamp - (prior_duration + duration + agg_preamble);
          wmem_list_foreach(agg_tracker_list, adjust_agg_tsf, &ppdu_start);
          wmem_destroy_list(agg_tracker_list);
          agg_tracker_list = NULL;
        };
      } else if (wlan_radio_tsf_at_end) {
        wlan_radio_info->start_tsf = phdr->tsf_timestamp - duration;
        wlan_radio_info->end_tsf = phdr->tsf_timestamp;
      } else {
        wlan_radio_info->start_tsf = phdr->tsf_timestamp + prior_duration - preamble;
        wlan_radio_info->end_tsf = phdr->tsf_timestamp + prior_duration + duration - preamble;
      }
      if ((pinfo->fd->num > 1) && (previous_frame.radio_info != NULL)) {
        /* TODO handle intermediate packets without end_tsf correctly */
        wlan_radio_info->ifs = wlan_radio_info->start_tsf - previous_frame.radio_info->end_tsf;
      }
      if (tvb_captured_length(tvb) >= 4) {
        /*
         * Duration/ID field.
         */
        int nav = tvb_get_letohs(tvb, 2);
        if ((nav & 0x8000) == 0) {
          /* Duration */
          wlan_radio_info->nav = nav;
        }
      }
      if (phdr->has_signal_dbm) {
        wlan_radio_info->rssi = phdr->signal_dbm;
        if (current_aggregate)
          current_aggregate->rssi = phdr->signal_dbm;
      }
    }

    if (have_duration) {
      proto_item *item = proto_tree_add_uint(radio_tree, hf_wlan_radio_duration, tvb, 0, 0, duration);
      proto_tree *d_tree = proto_item_add_subtree(item, ett_wlan_radio_duration);
      proto_item_set_generated(item);

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
        p_item = proto_tree_add_uint(d_tree, hf_wlan_radio_preamble, tvb, 0, 0, preamble);
        proto_item_set_generated(p_item);
      }
      if (wlan_radio_info->aggregate) {
        proto_tree *agg_tree;

        p_item = proto_tree_add_none_format(d_tree, hf_wlan_radio_aggregate, tvb, 0, 0,
          "This MPDU is part of an A-MPDU");
        agg_tree = proto_item_add_subtree(item, ett_wlan_radio_aggregate);
        proto_item_set_generated(p_item);
        if (wlan_radio_info->aggregate->duration) {
          proto_item *aitem = proto_tree_add_uint(agg_tree, hf_wlan_radio_aggregate_duration, tvb, 0, 0,
                  wlan_radio_info->aggregate->duration);
          proto_item_set_generated(aitem);
        }
      }
      if (wlan_radio_info->ifs) {
        p_item = proto_tree_add_int64(d_tree, hf_wlan_radio_ifs, tvb, 0, 0, wlan_radio_info->ifs);
        proto_item_set_generated(p_item);
        /* TODO: warnings on unusual IFS values (too small or negative) */
      }
      if (wlan_radio_info->start_tsf) {
        p_item = proto_tree_add_uint64(d_tree, hf_wlan_radio_start_tsf, tvb, 0, 0, wlan_radio_info->start_tsf);
        proto_item_set_generated(p_item);
      }
      if (wlan_radio_info->end_tsf) {
        p_item = proto_tree_add_uint64(d_tree, hf_wlan_radio_end_tsf, tvb, 0, 0, wlan_radio_info->end_tsf);
        proto_item_set_generated(p_item);
      }
    }
  } /* if (have_data_rate) */
  if (phdr->has_zero_length_psdu_type)
    proto_tree_add_uint(radio_tree, hf_wlan_zero_length_psdu_type, tvb, 0, 0, phdr->zero_length_psdu_type);

  tap_queue_packet(wlan_radio_tap, pinfo, phdr);
  if (wlan_radio_timeline_enabled) {
    tap_queue_packet(wlan_radio_timeline_tap, pinfo, wlan_radio_info);
  }

  if (!pinfo->fd->visited) {
    previous_frame.radio_info = wlan_radio_info;
  }
}

/*
 * Dissect 802.11 with a variable-length link-layer header and a pseudo-
 * header containing radio information.
 */
static int
dissect_wlan_radio (tvbuff_t * tvb, packet_info * pinfo, proto_tree * tree, void *data)
{
  struct ieee_802_11_phdr *phdr = (struct ieee_802_11_phdr *)data;

  dissect_wlan_radio_phdr(tvb, pinfo, tree, phdr);

  /* Is there anything there? A 0-length-psdu has no frame data. */
  if (phdr->has_zero_length_psdu_type)
    return tvb_captured_length(tvb);

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
  struct ieee_802_11_phdr *phdr = (struct ieee_802_11_phdr *)data;

  dissect_wlan_radio_phdr(tvb, pinfo, tree, phdr);

  /* Is there anything there? A 0-length-psdu has no frame data. */
  if (phdr->has_zero_length_psdu_type)
    return tvb_captured_length(tvb);

  /* dissect the 802.11 packet next */
  return call_dissector_with_data(ieee80211_noqos_handle, tvb, pinfo, tree, data);
}

static void
setup_ieee80211_radio(void)
{
  /* start of a new dissection, initialize state variables */
  current_aggregate = NULL;
  agg_tracker_list = NULL;
  memset(&previous_frame, 0, sizeof(previous_frame));
}

static void
cleanup_ieee80211_radio(void)
{
  if (agg_tracker_list != NULL) {
    wmem_destroy_list(agg_tracker_list);
    agg_tracker_list = NULL;
  }
}

void proto_register_ieee80211_radio(void)
{
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
     {"Frequency", "wlan_radio.frequency", FT_UINT16, BASE_DEC|BASE_UNIT_STRING, &units_mhz, 0,
      "Center frequency of the 802.11 channel that this frame was sent/received on", HFILL }},

    {&hf_wlan_radio_short_preamble,
     {"Short preamble", "wlan_radio.short_preamble", FT_BOOLEAN, BASE_NONE, NULL, 0,
      NULL, HFILL }},

    {&hf_wlan_radio_signal_percent,
     {"Signal strength (percentage)", "wlan_radio.signal_percentage", FT_UINT32, BASE_DEC|BASE_UNIT_STRING, &units_percent, 0,
      "Signal strength, as percentage of maximum RSSI", HFILL }},

    {&hf_wlan_radio_signal_db,
     {"Signal strength (dB)", "wlan_radio.signal_db", FT_UINT8, BASE_DEC|BASE_UNIT_STRING, &units_decibels, 0,
      NULL, HFILL }},

    {&hf_wlan_radio_signal_dbm,
     {"Signal strength (dBm)", "wlan_radio.signal_dbm", FT_INT8, BASE_DEC|BASE_UNIT_STRING, &units_dbm, 0,
      NULL, HFILL }},

    {&hf_wlan_radio_noise_percent,
     {"Noise level (percentage)", "wlan_radio.noise_percentage", FT_UINT32, BASE_DEC|BASE_UNIT_STRING, &units_percent, 0,
      NULL, HFILL }},

    {&hf_wlan_radio_noise_db,
     {"Noise level (dB)", "wlan_radio.noise_db", FT_UINT8, BASE_DEC|BASE_UNIT_STRING, &units_decibels, 0,
      NULL, HFILL }},

    {&hf_wlan_radio_noise_dbm,
     {"Noise level (dBm)", "wlan_radio.noise_dbm", FT_INT8, BASE_DEC|BASE_UNIT_STRING, &units_dbm, 0,
      NULL, HFILL }},

    {&hf_wlan_radio_snr,
     {"Signal/noise ratio (dB)", "wlan_radio.snr", FT_INT32, BASE_DEC|BASE_UNIT_STRING, &units_decibels, 0,
      NULL, HFILL }},

    {&hf_wlan_radio_timestamp,
     {"TSF timestamp", "wlan_radio.timestamp", FT_UINT64, BASE_DEC, NULL, 0,
      "Timing Synchronization Function timestamp", HFILL }},

    {&hf_wlan_last_part_of_a_mpdu,
     {"Last part of an A-MPDU", "wlan_radio.last_part_of_an_ampdu", FT_BOOLEAN, 32, NULL, PHDR_802_11_LAST_PART_OF_A_MPDU,
      "This is the last part of an A-MPDU", HFILL }},

    {&hf_wlan_a_mpdu_delim_crc_error,
     {"A-MPDU delimiter CRC error", "wlan_radio.a_mpdu_delim_crc_error", FT_BOOLEAN, 32, NULL, PHDR_802_11_A_MPDU_DELIM_CRC_ERROR,
      NULL, HFILL }},

    {&hf_wlan_a_mpdu_aggregate_id,
     {"A-MPDU aggregate ID", "wlan_radio.a_mpdu_aggregate_id", FT_UINT32, BASE_DEC, NULL, 0,
      NULL, HFILL }},

    {&hf_wlan_radio_duration,
     {"Duration", "wlan_radio.duration", FT_UINT32, BASE_DEC|BASE_UNIT_STRING, &units_microseconds, 0,
      "Total duration of the frame in microseconds, including any preamble or plcp header. "
      "Calculated from the frame length, modulation and other phy data.", HFILL }},

    {&hf_wlan_radio_preamble,
     {"Preamble", "wlan_radio.preamble", FT_UINT32, BASE_DEC|BASE_UNIT_STRING, &units_microseconds, 0,
      "Duration of the PLCP or preamble in microseconds, calculated from PHY data", HFILL }},

    {&hf_wlan_radio_aggregate,
     {"A-MPDU", "wlan_radio.aggregate", FT_NONE, BASE_NONE, NULL, 0,
      "MPDU is part of an A-MPDU", HFILL }},

    {&hf_wlan_radio_ifs,
     {"IFS", "wlan_radio.ifs", FT_INT64, BASE_DEC|BASE_UNIT_STRING, &units_microseconds, 0,
      "Inter Frame Space before this frame in microseconds, calculated from PHY data", HFILL }},

    {&hf_wlan_radio_start_tsf,
     {"Start", "wlan_radio.start_tsf", FT_UINT64, BASE_DEC|BASE_UNIT_STRING, &units_microseconds, 0,
      "Calculated start time of the frame", HFILL }},

    {&hf_wlan_radio_end_tsf,
     {"End", "wlan_radio.end_tsf", FT_UINT64, BASE_DEC|BASE_UNIT_STRING, &units_microseconds, 0,
      "Calculated end time of the frame", HFILL }},

    {&hf_wlan_radio_aggregate_duration,
     {"Duration", "wlan_radio.aggregate.duration", FT_UINT32, BASE_DEC|BASE_UNIT_STRING, &units_microseconds, 0,
      "Total duration of the aggregate in microseconds, including any preamble or plcp header. "
      "Calculated from the total subframe lengths, modulation and other phy data.", HFILL }},

    {&hf_wlan_zero_length_psdu_type,
     {"Zero-length PSDU Type", "wlan_radio.zero_len_psdu.type", FT_UINT8, BASE_HEX, VALS(zero_length_psdu_vals), 0x0,
       "Type of zero-length PSDU", HFILL}},
  };

  static gint *ett[] = {
    &ett_wlan_radio,
    &ett_wlan_radio_11ac_user,
    &ett_wlan_radio_duration,
    &ett_wlan_radio_aggregate
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

  module_t *wlan_radio_module;
  expert_module_t* expert_wlan_radio;

  proto_wlan_radio = proto_register_protocol("802.11 radio information", "802.11 Radio", "wlan_radio");
  proto_register_field_array(proto_wlan_radio, hf_wlan_radio, array_length(hf_wlan_radio));
  proto_register_subtree_array(ett, array_length(ett));

  expert_wlan_radio = expert_register_protocol(proto_wlan_radio);
  expert_register_field_array(expert_wlan_radio, ei, array_length(ei));

  wlan_radio_handle = register_dissector("wlan_radio", dissect_wlan_radio, proto_wlan_radio);
  wlan_noqos_radio_handle = register_dissector("wlan_noqos_radio", dissect_wlan_noqos_radio, proto_wlan_radio);

  wlan_radio_module = prefs_register_protocol(proto_wlan_radio, NULL);
  prefs_register_bool_preference(wlan_radio_module, "always_short_preamble",
    "802.11/11b preamble length is always short",
    "Some generators incorrectly indicate long preamble when the preamble was actually"
    "short. Always assume short preamble when calculating duration.",
    &wlan_radio_always_short_preamble);
  prefs_register_bool_preference(wlan_radio_module, "tsf_at_end",
    "TSF indicates the end of the PPDU",
    "Some generators timestamp the end of the PPDU rather than the start of the (A)MPDU.",
    &wlan_radio_tsf_at_end);
  prefs_register_bool_preference(wlan_radio_module, "timeline",
    "Enable Wireless Timeline (experimental)",
    "Enables an additional panel for navigating through packets",
    &wlan_radio_timeline_enabled);

  register_init_routine( setup_ieee80211_radio );
  register_cleanup_routine( cleanup_ieee80211_radio );
}

void proto_reg_handoff_ieee80211_radio(void)
{
  /* Register handoff to radio-header dissectors */
  dissector_add_uint("wtap_encap", WTAP_ENCAP_IEEE_802_11_WITH_RADIO,
                     wlan_radio_handle);
  ieee80211_handle = find_dissector_add_dependency("wlan", proto_wlan_radio);
  ieee80211_noqos_handle = find_dissector_add_dependency("wlan_noqos", proto_wlan_radio);

  wlan_radio_tap = register_tap("wlan_radio");
  wlan_radio_timeline_tap = register_tap("wlan_radio_timeline");
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
