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
 * Data rates corresponding to a given 802.11n MCS index, bandwidth, and
 * guard interval.
 *
 * Indices are:
 *
 *  the MCS index (0-76);
 *
 *  0 for 20 MHz, 1 for 40 MHz;
 *
 *  0 for a long guard interval, 1 for a short guard interval.
 */
WS_DLL_PUBLIC_DEF
const float ieee80211_float_htrates[MAX_MCS_INDEX+1][2][2] = {
  /* MCS  0  */
  { /* 20 Mhz */ {    6.5f,   /* SGI */    7.2f, },
    /* 40 Mhz */ {   13.5f,   /* SGI */   15.0f, },
  },

  /* MCS  1  */
  { /* 20 Mhz */ {   13.0f,   /* SGI */   14.4f, },
    /* 40 Mhz */ {   27.0f,   /* SGI */   30.0f, },
  },

  /* MCS  2  */
  { /* 20 Mhz */ {   19.5f,   /* SGI */   21.7f, },
    /* 40 Mhz */ {   40.5f,   /* SGI */   45.0f, },
  },

  /* MCS  3  */
  { /* 20 Mhz */ {   26.0f,   /* SGI */   28.9f, },
    /* 40 Mhz */ {   54.0f,   /* SGI */   60.0f, },
  },

  /* MCS  4  */
  { /* 20 Mhz */ {   39.0f,   /* SGI */   43.3f, },
    /* 40 Mhz */ {   81.0f,   /* SGI */   90.0f, },
  },

  /* MCS  5  */
  { /* 20 Mhz */ {   52.0f,   /* SGI */   57.8f, },
    /* 40 Mhz */ {  108.0f,   /* SGI */  120.0f, },
  },

  /* MCS  6  */
  { /* 20 Mhz */ {   58.5f,   /* SGI */   65.0f, },
    /* 40 Mhz */ {  121.5f,   /* SGI */  135.0f, },
  },

  /* MCS  7  */
  { /* 20 Mhz */ {   65.0f,   /* SGI */   72.2f, },
    /* 40 Mhz */ {   135.0f,  /* SGI */  150.0f, },
  },

  /* MCS  8  */
  { /* 20 Mhz */ {   13.0f,   /* SGI */   14.4f, },
    /* 40 Mhz */ {   27.0f,   /* SGI */   30.0f, },
  },

  /* MCS  9  */
  { /* 20 Mhz */ {   26.0f,   /* SGI */   28.9f, },
    /* 40 Mhz */ {   54.0f,   /* SGI */   60.0f, },
  },

  /* MCS 10  */
  { /* 20 Mhz */ {   39.0f,   /* SGI */   43.3f, },
    /* 40 Mhz */ {   81.0f,   /* SGI */   90.0f, },
  },

  /* MCS 11  */
  { /* 20 Mhz */ {   52.0f,   /* SGI */   57.8f, },
    /* 40 Mhz */ {  108.0f,   /* SGI */  120.0f, },
  },

  /* MCS 12  */
  { /* 20 Mhz */ {   78.0f,   /* SGI */   86.7f, },
    /* 40 Mhz */ {  162.0f,   /* SGI */  180.0f, },
  },

  /* MCS 13  */
  { /* 20 Mhz */ {  104.0f,   /* SGI */  115.6f, },
    /* 40 Mhz */ {  216.0f,   /* SGI */  240.0f, },
  },

  /* MCS 14  */
  { /* 20 Mhz */ {  117.0f,   /* SGI */  130.0f, },
    /* 40 Mhz */ {  243.0f,   /* SGI */  270.0f, },
  },

  /* MCS 15  */
  { /* 20 Mhz */ {  130.0f,   /* SGI */  144.4f, },
    /* 40 Mhz */ {  270.0f,   /* SGI */  300.0f, },
  },

  /* MCS 16  */
  { /* 20 Mhz */ {   19.5f,   /* SGI */   21.7f, },
    /* 40 Mhz */ {   40.5f,   /* SGI */   45.0f, },
  },

  /* MCS 17  */
  { /* 20 Mhz */ {   39.0f,   /* SGI */   43.3f, },
    /* 40 Mhz */ {   81.0f,   /* SGI */   90.0f, },
  },

  /* MCS 18  */
  { /* 20 Mhz */ {   58.5f,   /* SGI */   65.0f, },
    /* 40 Mhz */ {  121.5f,   /* SGI */  135.0f, },
  },

  /* MCS 19  */
  { /* 20 Mhz */ {   78.0f,   /* SGI */   86.7f, },
    /* 40 Mhz */ {  162.0f,   /* SGI */  180.0f, },
  },

  /* MCS 20  */
  { /* 20 Mhz */ {  117.0f,   /* SGI */  130.0f, },
    /* 40 Mhz */ {  243.0f,   /* SGI */  270.0f, },
  },

  /* MCS 21  */
  { /* 20 Mhz */ {  156.0f,   /* SGI */  173.3f, },
    /* 40 Mhz */ {  324.0f,   /* SGI */  360.0f, },
  },

  /* MCS 22  */
  { /* 20 Mhz */ {  175.5f,   /* SGI */  195.0f, },
    /* 40 Mhz */ {  364.5f,   /* SGI */  405.0f, },
  },

  /* MCS 23  */
  { /* 20 Mhz */ {  195.0f,   /* SGI */  216.7f, },
    /* 40 Mhz */ {  405.0f,   /* SGI */  450.0f, },
  },

  /* MCS 24  */
  { /* 20 Mhz */ {   26.0f,   /* SGI */   28.9f, },
    /* 40 Mhz */ {   54.0f,   /* SGI */   60.0f, },
  },

  /* MCS 25  */
  { /* 20 Mhz */ {   52.0f,   /* SGI */   57.8f, },
    /* 40 Mhz */ {  108.0f,   /* SGI */  120.0f, },
  },

  /* MCS 26  */
  { /* 20 Mhz */ {   78.0f,   /* SGI */   86.7f, },
    /* 40 Mhz */ {  162.0f,   /* SGI */  180.0f, },
  },

  /* MCS 27  */
  { /* 20 Mhz */ {  104.0f,   /* SGI */  115.6f, },
    /* 40 Mhz */ {  216.0f,   /* SGI */  240.0f, },
  },

  /* MCS 28  */
  { /* 20 Mhz */ {  156.0f,   /* SGI */  173.3f, },
    /* 40 Mhz */ {  324.0f,   /* SGI */  360.0f, },
  },

  /* MCS 29  */
  { /* 20 Mhz */ {  208.0f,   /* SGI */  231.1f, },
    /* 40 Mhz */ {  432.0f,   /* SGI */  480.0f, },
  },

  /* MCS 30  */
  { /* 20 Mhz */ {  234.0f,   /* SGI */  260.0f, },
    /* 40 Mhz */ {  486.0f,   /* SGI */  540.0f, },
  },

  /* MCS 31  */
  { /* 20 Mhz */ {  260.0f,   /* SGI */  288.9f, },
    /* 40 Mhz */ {  540.0f,   /* SGI */  600.0f, },
  },

  /* MCS 32  */
  { /* 20 Mhz */ {    0.0f,   /* SGI */    0.0f, }, /* not valid */
    /* 40 Mhz */ {    6.0f,   /* SGI */    6.7f, },
  },

  /* MCS 33  */
  { /* 20 Mhz */ {   39.0f,   /* SGI */   43.3f, },
    /* 40 Mhz */ {   81.0f,   /* SGI */   90.0f, },
  },

  /* MCS 34  */
  { /* 20 Mhz */ {   52.0f,   /* SGI */   57.8f, },
    /* 40 Mhz */ {  108.0f,   /* SGI */  120.0f, },
  },

  /* MCS 35  */
  { /* 20 Mhz */ {   65.0f,   /* SGI */   72.2f, },
    /* 40 Mhz */ {  135.0f,   /* SGI */  150.0f, },
  },

  /* MCS 36  */
  { /* 20 Mhz */ {   58.5f,   /* SGI */   65.0f, },
    /* 40 Mhz */ {  121.5f,   /* SGI */  135.0f, },
  },

  /* MCS 37  */
  { /* 20 Mhz */ {   78.0f,   /* SGI */   86.7f, },
    /* 40 Mhz */ {  162.0f,   /* SGI */  180.0f, },
  },

  /* MCS 38  */
  { /* 20 Mhz */ {   97.5f,   /* SGI */  108.3f, },
    /* 40 Mhz */ {  202.5f,   /* SGI */  225.0f, },
  },

  /* MCS 39  */
  { /* 20 Mhz */ {   52.0f,   /* SGI */   57.8f, },
    /* 40 Mhz */ {  108.0f,   /* SGI */  120.0f, },
  },

  /* MCS 40  */
  { /* 20 Mhz */ {   65.0f,   /* SGI */   72.2f, },
    /* 40 Mhz */ {  135.0f,   /* SGI */  150.0f, },
  },

  /* MCS 41  */
  { /* 20 Mhz */ {   65.0f,   /* SGI */   72.2f, },
    /* 40 Mhz */ {  135.0f,   /* SGI */  150.0f, },
  },

  /* MCS 42  */
  { /* 20 Mhz */ {   78.0f,   /* SGI */   86.7f, },
    /* 40 Mhz */ {  162.0f,   /* SGI */  180.0f, },
  },

  /* MCS 43  */
  { /* 20 Mhz */ {   91.0f,   /* SGI */  101.1f, },
    /* 40 Mhz */ {  189.0f,   /* SGI */  210.0f, },
  },

  /* MCS 44  */
  { /* 20 Mhz */ {   91.0f,   /* SGI */  101.1f, },
    /* 40 Mhz */ {  189.0f,   /* SGI */  210.0f, },
  },

  /* MCS 45  */
  { /* 20 Mhz */ {  104.0f,   /* SGI */  115.6f, },
    /* 40 Mhz */ {  216.0f,   /* SGI */  240.0f, },
  },

  /* MCS 46  */
  { /* 20 Mhz */ {   78.0f,   /* SGI */   86.7f, },
    /* 40 Mhz */ {  162.0f,   /* SGI */  180.0f, },
  },

  /* MCS 47  */
  { /* 20 Mhz */ {   97.5f,   /* SGI */  108.3f, },
    /* 40 Mhz */ {  202.5f,   /* SGI */  225.0f, },
  },

  /* MCS 48  */
  { /* 20 Mhz */ {   97.5f,   /* SGI */  108.3f, },
    /* 40 Mhz */ {  202.5f,   /* SGI */  225.0f, },
  },

  /* MCS 49  */
  { /* 20 Mhz */ {  117.0f,   /* SGI */  130.0f, },
    /* 40 Mhz */ {  243.0f,   /* SGI */  270.0f, },
  },

  /* MCS 50  */
  { /* 20 Mhz */ {  136.5f,   /* SGI */  151.7f, },
    /* 40 Mhz */ {  283.5f,   /* SGI */  315.0f, },
  },

  /* MCS 51  */
  { /* 20 Mhz */ {  136.5f,   /* SGI */  151.7f, },
    /* 40 Mhz */ {  283.5f,   /* SGI */  315.0f, },
  },

  /* MCS 52  */
  { /* 20 Mhz */ {  156.0f,   /* SGI */  173.3f, },
    /* 40 Mhz */ {  324.0f,   /* SGI */  360.0f, },
  },

  /* MCS 53  */
  { /* 20 Mhz */ {   65.0f,   /* SGI */   72.2f, },
    /* 40 Mhz */ {  135.0f,   /* SGI */  150.0f, },
  },

  /* MCS 54  */
  { /* 20 Mhz */ {   78.0f,   /* SGI */   86.7f, },
    /* 40 Mhz */ {  162.0f,   /* SGI */  180.0f, },
  },

  /* MCS 55  */
  { /* 20 Mhz */ {   91.0f,   /* SGI */  101.1f, },
    /* 40 Mhz */ {  189.0f,   /* SGI */  210.0f, },
  },

  /* MCS 56  */
  { /* 20 Mhz */ {   78.0f,   /* SGI */   86.7f, },
    /* 40 Mhz */ {  162.0f,   /* SGI */  180.0f, },
  },

  /* MCS 57  */
  { /* 20 Mhz */ {   91.0f,   /* SGI */  101.1f, },
    /* 40 Mhz */ {  189.0f,   /* SGI */  210.0f, },
  },

  /* MCS 58  */
  { /* 20 Mhz */ {  104.0f,   /* SGI */  115.6f, },
    /* 40 Mhz */ {  216.0f,   /* SGI */  240.0f, },
  },

  /* MCS 59  */
  { /* 20 Mhz */ {  117.0f,   /* SGI */  130.0f, },
    /* 40 Mhz */ {  243.0f,   /* SGI */  270.0f, },
  },

  /* MCS 60  */
  { /* 20 Mhz */ {  104.0f,   /* SGI */  115.6f, },
    /* 40 Mhz */ {  216.0f,   /* SGI */  240.0f, },
  },

  /* MCS 61  */
  { /* 20 Mhz */ {  117.0f,   /* SGI */  130.0f, },
    /* 40 Mhz */ {  243.0f,   /* SGI */  270.0f, },
  },

  /* MCS 62  */
  { /* 20 Mhz */ {  130.0f,   /* SGI */  144.4f, },
    /* 40 Mhz */ {  270.0f,   /* SGI */  300.0f, },
  },

  /* MCS 63  */
  { /* 20 Mhz */ {  130.0f,   /* SGI */  144.4f, },
    /* 40 Mhz */ {  270.0f,   /* SGI */  300.0f, },
  },

  /* MCS 64  */
  { /* 20 Mhz */ {  143.0f,   /* SGI */  158.9f, },
    /* 40 Mhz */ {  297.0f,   /* SGI */  330.0f, },
  },

  /* MCS 65  */
  { /* 20 Mhz */ {   97.5f,   /* SGI */  108.3f, },
    /* 40 Mhz */ {  202.5f,   /* SGI */  225.0f, },
  },

  /* MCS 66  */
  { /* 20 Mhz */ {  117.0f,   /* SGI */  130.0f, },
    /* 40 Mhz */ {  243.0f,   /* SGI */  270.0f, },
  },

  /* MCS 67  */
  { /* 20 Mhz */ {  136.5f,   /* SGI */  151.7f, },
    /* 40 Mhz */ {  283.5f,   /* SGI */  315.0f, },
  },

  /* MCS 68  */
  { /* 20 Mhz */ {  117.0f,   /* SGI */  130.0f, },
    /* 40 Mhz */ {  243.0f,   /* SGI */  270.0f, },
  },

  /* MCS 69  */
  { /* 20 Mhz */ {  136.5f,   /* SGI */  151.7f, },
    /* 40 Mhz */ {  283.5f,   /* SGI */  315.0f, },
  },

  /* MCS 70  */
  { /* 20 Mhz */ {  156.0f,   /* SGI */  173.3f, },
    /* 40 Mhz */ {  324.0f,   /* SGI */  360.0f, },
  },

  /* MCS 71  */
  { /* 20 Mhz */ {  175.5f,   /* SGI */  195.0f, },
    /* 40 Mhz */ {  364.5f,   /* SGI */  405.0f, },
  },

  /* MCS 72  */
  { /* 20 Mhz */ {  156.0f,   /* SGI */  173.3f, },
    /* 40 Mhz */ {  324.0f,   /* SGI */  360.0f, },
  },

  /* MCS 73  */
  { /* 20 Mhz */ {  175.5f,   /* SGI */  195.0f, },
    /* 40 Mhz */ {  364.5f,   /* SGI */  405.0f, },
  },

  /* MCS 74  */
  { /* 20 Mhz */ {  195.0f,   /* SGI */  216.7f, },
    /* 40 Mhz */ {  405.0f,   /* SGI */  450.0f, },
  },

  /* MCS 75  */
  { /* 20 Mhz */ {  195.0f,   /* SGI */  216.7f, },
    /* 40 Mhz */ {  405.0f,   /* SGI */  450.0f, },
  },

  /* MCS 76  */
  { /* 20 Mhz */ {  214.5f,   /* SGI */  238.3f, },
    /* 40 Mhz */ {  445.5f,   /* SGI */  495.0f, },
  },
};

#define MAX_MCS_VHT_INDEX	9

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
  float       rates[4][2];
};

static const struct mcs_vht_info ieee80211_vhtinfo[MAX_MCS_VHT_INDEX+1] = {
  /* MCS  0  */
  { "BPSK",  "1/2",
    { /* 20 Mhz */  {    6.5f,  /* SGI */    7.2f, },
      /* 40 Mhz */  {   13.5f,  /* SGI */   15.0f, },
      /* 80 Mhz */  {   29.3f,  /* SGI */   32.5f, },
      /* 160 Mhz */ {   58.5f,  /* SGI */   65.0f, }
    }
  },
  /* MCS  1  */
  { "QPSK",  "1/2",
    { /* 20 Mhz */  {   13.0f,  /* SGI */   14.4f, },
      /* 40 Mhz */  {   27.0f,  /* SGI */   30.0f, },
      /* 80 Mhz */  {   58.5f,  /* SGI */   65.0f, },
      /* 160 Mhz */ {  117.0f,  /* SGI */  130.0f, }
    }
  },
  /* MCS  2  */
  { "QPSK",  "3/4",
    { /* 20 Mhz */  {   19.5f,  /* SGI */   21.7f, },
      /* 40 Mhz */  {   40.5f,  /* SGI */   45.0f, },
      /* 80 Mhz */  {   87.8f,  /* SGI */   97.5f, },
      /* 160 Mhz */ {  175.5f,  /* SGI */  195.0f, }
    }
  },
  /* MCS  3  */
  { "16-QAM", "1/2",
    { /* 20 Mhz */  {   26.0f,  /* SGI */   28.9f, },
      /* 40 Mhz */  {   54.0f,  /* SGI */   60.0f, },
      /* 80 Mhz */  {  117.0f,  /* SGI */  130.0f, },
      /* 160 Mhz */ {  234.0f,  /* SGI */  260.0f, }
    }
  },
  /* MCS  4  */
  { "16-QAM", "3/4",
    { /* 20 Mhz */  {   39.0f,  /* SGI */   43.3f, },
      /* 40 Mhz */  {   81.0f,  /* SGI */   90.0f, },
      /* 80 Mhz */  {  175.5f,  /* SGI */  195.0f, },
      /* 160 Mhz */ {  351.0f,  /* SGI */  390.0f, }
    }
  },
  /* MCS  5  */
  { "64-QAM", "2/3",
    { /* 20 Mhz */  {   52.0f,  /* SGI */   57.8f, },
      /* 40 Mhz */  {  108.0f,  /* SGI */  120.0f, },
      /* 80 Mhz */  {  234.0f,  /* SGI */  260.0f, },
      /* 160 Mhz */ {  468.0f,  /* SGI */  520.0f, }
    }
  },
  /* MCS  6  */
  { "64-QAM", "3/4",
    { /* 20 Mhz */  {   58.5f,  /* SGI */   65.0f, },
      /* 40 Mhz */  {  121.5f,  /* SGI */  135.0f, },
      /* 80 Mhz */  {  263.3f,  /* SGI */  292.5f, },
      /* 160 Mhz */ {  526.5f,  /* SGI */  585.0f, }
    }
  },
  /* MCS  7  */
  { "64-QAM", "5/6",
    { /* 20 Mhz */  {   65.0f,  /* SGI */   72.2f, },
      /* 40 Mhz */  {  135.0f,  /* SGI */  150.0f, },
      /* 80 Mhz */  {  292.5f,  /* SGI */  325.0f, },
      /* 160 Mhz */ {  585.0f,  /* SGI */  650.0f, }
    }
  },
  /* MCS  8  */
  { "256-QAM", "3/4",
    { /* 20 Mhz */  {   78.0f,  /* SGI */   86.7f, },
      /* 40 Mhz */  {  162.0f,  /* SGI */  180.0f, },
      /* 80 Mhz */  {  351.0f,  /* SGI */  390.0f, },
      /* 160 Mhz */ {  702.0f,  /* SGI */  780.0f, }
    }
  },
  /* MCS  9  */
  { "256-QAM", "5/6",
    { /* 20 Mhz */  {    0.0f,  /* SGI */    0.0f, },
      /* 40 Mhz */  {  180.0f,  /* SGI */  200.0f, },
      /* 80 Mhz */  {  390.0f,  /* SGI */  433.3f, },
      /* 160 Mhz */ {  780.0f,  /* SGI */  866.7f, }
    }
  }
};

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
  if (phdr->presence_flags & PHDR_802_11_HAS_DATA_RATE) {
    data_rate = phdr->data_rate * 0.5f;
    have_data_rate = TRUE;
  }

  if (phdr->presence_flags & PHDR_802_11_HAS_SIGNAL_DBM) {
    col_add_fstr(pinfo->cinfo, COL_RSSI, "%u dBm", phdr->signal_dbm);
  } else if (phdr->presence_flags & PHDR_802_11_HAS_SIGNAL_PERCENT) {
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
        if (phdr->phy_info.info_11_fhss.presence_flags & PHDR_802_11_FHSS_HAS_HOP_SET) {
          proto_tree_add_uint(radio_tree, hf_wlan_radio_11_fhss_hop_set, tvb, 0, 0,
                   phdr->phy_info.info_11_fhss.hop_set);
        }
        if (phdr->phy_info.info_11_fhss.presence_flags & PHDR_802_11_FHSS_HAS_HOP_PATTERN) {
          proto_tree_add_uint(radio_tree, hf_wlan_radio_11_fhss_hop_pattern, tvb, 0, 0,
                   phdr->phy_info.info_11_fhss.hop_pattern);
        }
        if (phdr->phy_info.info_11_fhss.presence_flags & PHDR_802_11_FHSS_HAS_HOP_INDEX) {
          proto_tree_add_uint(radio_tree, hf_wlan_radio_11_fhss_hop_index, tvb, 0, 0,
                   phdr->phy_info.info_11_fhss.hop_index);
        }
        break;

      case PHDR_802_11_PHY_11B:
        if (phdr->phy_info.info_11b.presence_flags & PHDR_802_11B_HAS_SHORT_PREAMBLE) {
          proto_tree_add_boolean(radio_tree, hf_wlan_radio_short_preamble, tvb, 0, 0,
                   phdr->phy_info.info_11b.short_preamble);
        }
        break;

      case PHDR_802_11_PHY_11A:
        if (phdr->phy_info.info_11a.presence_flags & PHDR_802_11A_HAS_CHANNEL_TYPE) {
          proto_tree_add_uint(radio_tree, hf_wlan_radio_11a_channel_type, tvb, 0, 0,
                   phdr->phy_info.info_11a.channel_type);
        }
        if (phdr->phy_info.info_11a.presence_flags & PHDR_802_11A_HAS_TURBO_TYPE) {
          proto_tree_add_uint(radio_tree, hf_wlan_radio_11a_turbo_type, tvb, 0, 0,
                   phdr->phy_info.info_11a.turbo_type);
        }
        break;

      case PHDR_802_11_PHY_11G:
        if (phdr->phy_info.info_11g.presence_flags & PHDR_802_11G_HAS_SHORT_PREAMBLE) {
          proto_tree_add_boolean(radio_tree, hf_wlan_radio_short_preamble, tvb, 0, 0,
                   phdr->phy_info.info_11g.short_preamble);
        }
        if (phdr->phy_info.info_11g.presence_flags & PHDR_802_11G_HAS_MODE) {
          proto_tree_add_uint(radio_tree, hf_wlan_radio_11g_mode, tvb, 0, 0,
                   phdr->phy_info.info_11g.mode);
        }
        break;

      case PHDR_802_11_PHY_11N:
        {
          guint bandwidth_40;

          if (phdr->phy_info.info_11n.presence_flags & PHDR_802_11N_HAS_MCS_INDEX) {
            proto_tree_add_uint(radio_tree, hf_wlan_radio_11n_mcs_index, tvb, 0, 0,
                     phdr->phy_info.info_11n.mcs_index);
          }

          if (phdr->phy_info.info_11n.presence_flags & PHDR_802_11N_HAS_BANDWIDTH) {
            proto_tree_add_uint(radio_tree, hf_wlan_radio_11n_bandwidth, tvb, 0, 0,
                     phdr->phy_info.info_11n.bandwidth);
          }

          if (phdr->phy_info.info_11n.presence_flags & PHDR_802_11N_HAS_SHORT_GI) {
            proto_tree_add_boolean(radio_tree, hf_wlan_radio_11n_short_gi, tvb, 0, 0,
                     phdr->phy_info.info_11n.short_gi);
          }

          if (phdr->phy_info.info_11n.presence_flags & PHDR_802_11N_HAS_GREENFIELD) {
            proto_tree_add_boolean(radio_tree, hf_wlan_radio_11n_greenfield, tvb, 0, 0,
                     phdr->phy_info.info_11n.greenfield);
          }

          if (phdr->phy_info.info_11n.presence_flags & PHDR_802_11N_HAS_FEC) {
            proto_tree_add_uint(radio_tree, hf_wlan_radio_11n_fec, tvb, 0, 0,
                     phdr->phy_info.info_11n.fec);
          }

          if (phdr->phy_info.info_11n.presence_flags & PHDR_802_11N_HAS_STBC_STREAMS) {
            proto_tree_add_uint(radio_tree, hf_wlan_radio_11n_stbc_streams, tvb, 0, 0,
                     phdr->phy_info.info_11n.stbc_streams);
          }

          if (phdr->phy_info.info_11n.presence_flags & PHDR_802_11N_HAS_NESS) {
            proto_tree_add_uint(radio_tree, hf_wlan_radio_11n_ness, tvb, 0, 0,
                     phdr->phy_info.info_11n.ness);
          }

          /*
           * If we have all the fields needed to look up the data rate,
           * do so.
           */
#define PHDR_802_11N_ALL_FIELDS_FOR_DATARATE \
          (PHDR_802_11N_HAS_MCS_INDEX | \
           PHDR_802_11N_HAS_BANDWIDTH | \
           PHDR_802_11N_HAS_SHORT_GI)

          if ((phdr->phy_info.info_11n.presence_flags & PHDR_802_11N_ALL_FIELDS_FOR_DATARATE) == PHDR_802_11N_ALL_FIELDS_FOR_DATARATE) {
            bandwidth_40 =
              (phdr->phy_info.info_11n.bandwidth == PHDR_802_11_BANDWIDTH_40_MHZ) ?
               1 : 0;
            if (phdr->phy_info.info_11n.mcs_index < MAX_MCS_INDEX) {
              data_rate = ieee80211_float_htrates[phdr->phy_info.info_11n.mcs_index][bandwidth_40][phdr->phy_info.info_11n.short_gi];
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

          if (phdr->phy_info.info_11ac.presence_flags & PHDR_802_11AC_HAS_STBC) {
            proto_tree_add_boolean(radio_tree, hf_wlan_radio_11ac_stbc, tvb, 0, 0,
                     phdr->phy_info.info_11ac.stbc);
          }

          if (phdr->phy_info.info_11ac.presence_flags & PHDR_802_11AC_HAS_TXOP_PS_NOT_ALLOWED) {
            proto_tree_add_boolean(radio_tree, hf_wlan_radio_11ac_txop_ps_not_allowed, tvb, 0, 0,
                     phdr->phy_info.info_11ac.txop_ps_not_allowed);
          }

          if (phdr->phy_info.info_11ac.presence_flags & PHDR_802_11AC_HAS_SHORT_GI) {
            can_calculate_rate = TRUE;  /* well, if we also have the bandwidth */
            proto_tree_add_boolean(radio_tree, hf_wlan_radio_11ac_short_gi, tvb, 0, 0,
                     phdr->phy_info.info_11ac.short_gi);
          } else {
            can_calculate_rate = FALSE; /* unknown GI length */
          }

          if (phdr->phy_info.info_11ac.presence_flags & PHDR_802_11AC_HAS_SHORT_GI_NSYM_DISAMBIG) {
            proto_tree_add_boolean(radio_tree, hf_wlan_radio_11ac_short_gi_nsym_disambig, tvb, 0, 0,
                     phdr->phy_info.info_11ac.short_gi_nsym_disambig);
          }

          if (phdr->phy_info.info_11ac.presence_flags & PHDR_802_11AC_HAS_LDPC_EXTRA_OFDM_SYMBOL) {
            proto_tree_add_boolean(radio_tree, hf_wlan_radio_11ac_ldpc_extra_ofdm_symbol, tvb, 0, 0,
                     phdr->phy_info.info_11ac.ldpc_extra_ofdm_symbol);
          }

          if (phdr->phy_info.info_11ac.presence_flags & PHDR_802_11AC_HAS_BEAMFORMED) {
            proto_tree_add_boolean(radio_tree, hf_wlan_radio_11ac_beamformed, tvb, 0, 0,
                     phdr->phy_info.info_11ac.beamformed);
          }

          if (phdr->phy_info.info_11ac.presence_flags & PHDR_802_11AC_HAS_BANDWIDTH) {
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
              if (phdr->phy_info.info_11ac.presence_flags & PHDR_802_11AC_HAS_STBC) {
                guint nsts;

                if (phdr->phy_info.info_11ac.stbc)
                  nsts = 2 * phdr->phy_info.info_11ac.nss[i];
                else
                  nsts = phdr->phy_info.info_11ac.nss[i];
                proto_tree_add_uint(user_tree, hf_wlan_radio_11ac_nsts, tvb, 0, 0,
                       nsts);
              }
              if (phdr->phy_info.info_11ac.presence_flags & PHDR_802_11AC_HAS_FEC) {
                  proto_tree_add_uint(user_tree, hf_wlan_radio_11ac_fec, tvb, 0, 0,
                           (phdr->phy_info.info_11ac.fec >> i) & 0x01);
              }

              /*
               * If we can calculate the data rate for this user, do so.
               */
              if (can_calculate_rate && phdr->phy_info.info_11ac.mcs[i] <= MAX_MCS_VHT_INDEX) {
                data_rate = ieee80211_vhtinfo[phdr->phy_info.info_11ac.mcs[i]].rates[bandwidth][phdr->phy_info.info_11ac.short_gi] * phdr->phy_info.info_11ac.nss[i];
                if (data_rate != 0.0f) {
                  proto_tree_add_float_format_value(user_tree, hf_wlan_radio_data_rate, tvb, 0, 0,
                        data_rate,
                        "%.1f Mb/s",
                       data_rate);
                }
              }
            }
          }

          if (phdr->phy_info.info_11ac.presence_flags & PHDR_802_11AC_HAS_GROUP_ID) {
            proto_tree_add_uint(radio_tree, hf_wlan_radio_11ac_gid, tvb, 0, 0,
                     phdr->phy_info.info_11ac.group_id);
          }

          if (phdr->phy_info.info_11ac.presence_flags & PHDR_802_11AC_HAS_PARTIAL_AID) {
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

    if (phdr->presence_flags & PHDR_802_11_HAS_CHANNEL) {
      col_add_fstr(pinfo->cinfo, COL_FREQ_CHAN, "%u", phdr->channel);
      proto_tree_add_uint(radio_tree, hf_wlan_radio_channel, tvb, 0, 0,
              phdr->channel);
    }

    if (phdr->presence_flags & PHDR_802_11_HAS_FREQUENCY) {
      col_add_fstr(pinfo->cinfo, COL_FREQ_CHAN, "%u MHz", phdr->frequency);
      proto_tree_add_uint_format_value(radio_tree, hf_wlan_radio_frequency, tvb, 0, 0,
              phdr->frequency,
              "%u MHz",
              phdr->frequency);
    }

    if (phdr->presence_flags & PHDR_802_11_HAS_SIGNAL_PERCENT) {
      col_add_fstr(pinfo->cinfo, COL_RSSI, "%u%%", phdr->signal_percent);
      proto_tree_add_uint_format_value(radio_tree, hf_wlan_radio_signal_percent, tvb, 0, 0,
              phdr->signal_percent,
              "%u%%",
              phdr->signal_percent);
    }

    if (phdr->presence_flags & PHDR_802_11_HAS_SIGNAL_DBM) {
      col_add_fstr(pinfo->cinfo, COL_RSSI, "%d dBm", phdr->signal_dbm);
      proto_tree_add_int_format_value(radio_tree, hf_wlan_radio_signal_dbm, tvb, 0, 0,
              phdr->signal_dbm,
              "%d dBm",
              phdr->signal_dbm);
    }

    if (phdr->presence_flags & PHDR_802_11_HAS_NOISE_PERCENT) {
      proto_tree_add_uint_format_value(radio_tree, hf_wlan_radio_noise_percent, tvb, 0, 0,
              phdr->noise_percent,
              "%u%%",
              phdr->noise_percent);
    }

    if (phdr->presence_flags & PHDR_802_11_HAS_NOISE_DBM) {
      proto_tree_add_int_format_value(radio_tree, hf_wlan_radio_noise_dbm, tvb, 0, 0,
              phdr->noise_dbm,
              "%d dBm",
              phdr->noise_dbm);
    }

    if (phdr->presence_flags & PHDR_802_11_HAS_TSF_TIMESTAMP) {
      proto_tree_add_uint64(radio_tree, hf_wlan_radio_timestamp, tvb, 0, 0,
              phdr->tsf_timestamp);
    }
  }

  /* dissect the 802.11 packet next */
  pinfo->current_proto = "IEEE 802.11";
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
     {"Signal strength (percentage)", "wlan_radio.signal_dbm", FT_UINT32, BASE_DEC, NULL, 0,
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

  wlan_radio_handle = new_register_dissector("wlan_radio", dissect_wlan_radio, proto_wlan_radio);
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
