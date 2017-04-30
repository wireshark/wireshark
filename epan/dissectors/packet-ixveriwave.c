/* packet-ixveriwave.c
 * Routines for calling the right protocol for the ethertype.
 *
 * Tom Cook <tcook@ixiacom.com>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 */

#include "config.h"

#include <math.h>

#include <epan/packet.h>
#include <epan/proto_data.h>

#include <wiretap/wtap.h>

void proto_register_ixveriwave(void);
void proto_reg_handoff_ixveriwave(void);

static void ethernettap_dissect(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, proto_tree *tap_tree);
static void wlantap_dissect(tvbuff_t *tvb, packet_info *pinfo,
                            proto_tree *tree, proto_tree *tap_tree,
                            guint16 vw_msdu_length, guint8 cmd_type,
                            int log_mode, gboolean is_octo);

typedef struct {
    guint32 previous_frame_num;
    guint64 previous_end_time;
} frame_end_data;

typedef struct ifg_info {
    guint32 ifg;
    guint64 previous_end_time;
    guint64 current_start_time;
} ifg_info;

static frame_end_data previous_frame_data = {0,0};

/* static int ieee80211_mhz2ieee(int freq, int flags); */

#define COMMON_LENGTH_OFFSET 2
#define ETHERNETTAP_VWF_TXF                 0x01    /* frame was transmitted flag */
#define ETHERNETTAP_VWF_FCSERR              0x02    /* frame has FCS error */

#define VW_RADIOTAPF_TXF                    0x01    /* frame was transmitted */
#define VW_RADIOTAPF_FCSERR                 0x02    /* FCS error detected */
#define VW_RADIOTAPF_RETRERR                0x04    /* excess retry error detected */
#define VW_RADIOTAPF_DCRERR                 0x10    /* decrypt error detected */
#define VW_RADIOTAPF_ENCMSK                 0x60    /* encryption type mask */
                                                    /* 0 = none, 1 = WEP, 2 = TKIP, 3 = CCKM */
#define VW_RADIOTAPF_ENCSHIFT               5       /* shift amount to right-align above field */
#define VW_RADIOTAPF_IS_WEP                 0x20    /* encryption type value = WEP */
#define VW_RADIOTAPF_IS_TKIP                0x40    /* encryption type value = TKIP */
#define VW_RADIOTAPF_IS_CCMP                0x60    /* encryption type value = CCMP */
#define VW_RADIOTAPF_SEQ_ERR                0x80    /* flow sequence error detected */

#define VW_RADIOTAP_FPGA_VER_vVW510021      0x000C  /* vVW510021 version detected */
#define VW_RADIOTAP_FPGA_VER_vVW510021_11n  0x000D

#define CHAN_CCK                            0x00020 /* CCK channel */
#define CHAN_OFDM                           0x00040 /* OFDM channel */

#define FLAGS_SHORTPRE                      0x0002  /* sent/received
                                                     * with short
                                                     * preamble
                                                     */
#define FLAGS_WEP                           0x0004  /* sent/received
                                                     * with WEP encryption
                                                     */
#define FLAGS_CHAN_HT                       0x0040  /* HT mode */
#define FLAGS_CHAN_VHT                      0x0080  /* VHT mode */
#define FLAGS_CHAN_SHORTGI                  0x0100  /* short guard interval */
#define FLAGS_CHAN_40MHZ                    0x0200  /* 40 Mhz channel bandwidth */
#define FLAGS_CHAN_80MHZ                    0x0400  /* 80 Mhz channel bandwidth */
#define FLAGS_CHAN_160MHZ                   0x0800  /* 160 Mhz channel bandwidth */

#define INFO_MPDU_OF_A_MPDU                 0x0400  /* MPDU of A-MPDU */
#define INFO_FIRST_MPDU_OF_A_MPDU           0x0800  /* first MPDU of A-MPDU */
#define INFO_LAST_MPDU_OF_A_MPDU            0x1000  /* last MPDU of A-MPDU */
#define INFO_MSDU_OF_A_MSDU                 0x2000  /* MSDU of A-MSDU */
#define INFO_FIRST_MSDU_OF_A_MSDU           0x4000  /* first MSDU of A-MSDU */
#define INFO_LAST_MSDU_OF_A_MSDU            0x8000  /* last MSDU of A-MSDU */

#define PLCP_TYPE_LEGACY        0x00        /* pre-HT (11 legacy/11b/11a/11g) */
#define PLCP_TYPE_MIXED         0x01        /* HT, mixed (11n) */
#define PLCP_TYPE_GREENFIELD    0x02        /* HT, greenfield (11n) */
#define PLCP_TYPE_VHT_MIXED     0x03        /* VHT (11ac) */

#define ETHERNET_PORT           1
#define WLAN_PORT               0
#define OCTO_TIMESTAMP_FIELDS_LEN           32              /* (4+4+8+8+4+4) */
#define OCTO_MODIFIED_RF_LEN                76              /* Number of RF bytes to be displayed*/
#define VW_INFO_OFF                         48
#define IFG_MAX_VAL                         0xEE6B2800

static int proto_ixveriwave = -1;
static dissector_handle_t ethernet_handle;

/* static int hf_ixveriwave_version = -1; */
static int hf_ixveriwave_frame_length = -1;

/* static int hf_ixveriwave_fcs = -1; */

static int hf_ixveriwave_vw_vcid = -1;
static int hf_ixveriwave_vw_msdu_length = -1;
static int hf_ixveriwave_vw_seqnum = -1;
static int hf_ixveriwave_vw_flowid = -1;

static int hf_ixveriwave_vw_mslatency = -1;
static int hf_ixveriwave_vw_latency = -1;
static int hf_ixveriwave_vw_pktdur = -1;
static int hf_ixveriwave_vw_ifg = -1;
static int hf_ixveriwave_vw_ifg_neg = -1;
static int hf_ixveriwave_vw_sig_ts = -1;
static int hf_ixveriwave_vw_startt = -1;
static int hf_ixveriwave_vw_endt = -1;
static int hf_ixveriwave_vw_delay = -1;

static gint ett_commontap = -1;
static gint ett_commontap_times = -1;
static gint ett_ethernettap_info = -1;
static gint ett_ethernettap_error = -1;
static gint ett_ethernettap_flags = -1;

static gint ett_radiotap_flags = -1;

static dissector_handle_t ieee80211_radio_handle;

/* Ethernet fields */
static int hf_ixveriwave_vw_info = -1;
static int hf_ixveriwave_vw_error = -1;

static int hf_ixveriwave_vwf_txf = -1;
static int hf_ixveriwave_vwf_fcserr = -1;

static int hf_ixveriwave_vw_l4id = -1;

/*veriwave note:  i know the below method seems clunky, but
they didn't have a item_format at the time to dynamically add the appropriate decode text*/
static int hf_ixveriwave_vw_info_retryCount = -1;

static int hf_ixveriwave_vw_info_rx_1_bit8 = -1;
static int hf_ixveriwave_vw_info_rx_1_bit9 = -1;

/*error flags*/
static int hf_ixveriwave_vw_error_tx_bit1 = -1;
static int hf_ixveriwave_vw_error_tx_bit5 = -1;
static int hf_ixveriwave_vw_error_tx_bit9 = -1;
static int hf_ixveriwave_vw_error_tx_bit10 = -1;
static int hf_ixveriwave_vw_error_tx_bit11 = -1;

static int hf_ixveriwave_vw_error_rx_1_bit0 = -1;
static int hf_ixveriwave_vw_error_rx_1_bit1 = -1;
static int hf_ixveriwave_vw_error_rx_1_bit2 = -1;
static int hf_ixveriwave_vw_error_rx_1_bit3 = -1;
static int hf_ixveriwave_vw_error_rx_1_bit4 = -1;
static int hf_ixveriwave_vw_error_rx_1_bit5 = -1;
static int hf_ixveriwave_vw_error_rx_1_bit6 = -1;
static int hf_ixveriwave_vw_error_rx_1_bit7 = -1;
static int hf_ixveriwave_vw_error_rx_1_bit8 = -1;
static int hf_ixveriwave_vw_error_rx_1_bit9 = -1;

static int hf_radiotap_flags = -1;
static int hf_radiotap_datarate = -1;
static int hf_radiotap_mcsindex = -1;
static int hf_radiotap_plcptype = -1;
static int hf_radiotap_nss = -1;
static int hf_radiotap_dbm_anta = -1;
static int hf_radiotap_dbm_antb = -1;
static int hf_radiotap_dbm_antc = -1;
static int hf_radiotap_dbm_antd = -1;
static int hf_radiotap_dbm_tx_anta = -1;
static int hf_radiotap_dbm_tx_antb = -1;
static int hf_radiotap_dbm_tx_antc = -1;
static int hf_radiotap_dbm_tx_antd = -1;

static int hf_radiotap_flags_preamble = -1;
static int hf_radiotap_flags_wep = -1;
static int hf_radiotap_flags_ht = -1;
static int hf_radiotap_flags_vht = -1;
static int hf_radiotap_flags_40mhz = -1;
static int hf_radiotap_flags_80mhz = -1;
static int hf_radiotap_flags_shortgi = -1;

/* start VeriWave specific 6-2007*/
static int hf_radiotap_vw_errors = -1;
static int hf_radiotap_vw_info = -1;
static int hf_radiotap_vw_ht_length = -1;
static int hf_radiotap_vht_grp_id = -1;
static int hf_radiotap_vht_su_nsts = -1;
static int hf_radiotap_vht_su_partial_aid = -1;
static int hf_radiotap_vht_su_coding_type = -1;
static int hf_radiotap_vht_u0_nsts = -1;
static int hf_radiotap_vht_u1_nsts = -1;
static int hf_radiotap_vht_u2_nsts = -1;
static int hf_radiotap_vht_u3_nsts = -1;
static int hf_radiotap_vht_beamformed = -1;
static int hf_radiotap_vht_user_pos = -1;
static int hf_radiotap_vht_mu_mimo_flg = -1;
static int hf_radiotap_vht_su_mimo_flg = -1;
static int hf_radiotap_vht_u0_coding_type = -1;
static int hf_radiotap_vht_u1_coding_type = -1;
static int hf_radiotap_vht_u2_coding_type = -1;
static int hf_radiotap_vht_u3_coding_type = -1;

static int hf_radiotap_vw_info_tx_bit0 = -1;
static int hf_radiotap_vw_info_tx_bit1 = -1;
static int hf_radiotap_vw_info_tx_bit3 = -1;
static int hf_radiotap_vw_info_tx_bit4 = -1;
static int hf_radiotap_vw_info_tx_bit5 = -1;
static int hf_radiotap_vw_info_tx_bit6 = -1;
static int hf_radiotap_vw_info_tx_bit7 = -1;
static int hf_radiotap_vw_info_tx_bit8 = -1;
static int hf_radiotap_vw_info_tx_bit9 = -1;
static int hf_radiotap_vw_info_tx_bit10 = -1;
static int hf_radiotap_vw_info_tx_bit11 = -1;
static int hf_radiotap_vw_info_tx_bit12 = -1;
static int hf_radiotap_vw_info_tx_bit13 = -1;
static int hf_radiotap_vw_info_tx_bit14 = -1;
static int hf_radiotap_vw_info_tx_bit15 = -1;
static const int *radiotap_info_tx_fields[] = {
    &hf_radiotap_vw_info_tx_bit0,
    &hf_radiotap_vw_info_tx_bit1,
    &hf_radiotap_vw_info_tx_bit3,
    &hf_radiotap_vw_info_tx_bit4,
    &hf_radiotap_vw_info_tx_bit5,
    &hf_radiotap_vw_info_tx_bit6,
    &hf_radiotap_vw_info_tx_bit7,
    &hf_radiotap_vw_info_tx_bit8,
    &hf_radiotap_vw_info_tx_bit9,
    &hf_radiotap_vw_info_tx_bit10,
    &hf_radiotap_vw_info_tx_bit11,
    &hf_radiotap_vw_info_tx_bit12,
    &hf_radiotap_vw_info_tx_bit13,
    &hf_radiotap_vw_info_tx_bit14,
    &hf_radiotap_vw_info_tx_bit15,
    NULL,
};

static int hf_radiotap_vw_info_tx = -1;
static int hf_radiotap_vw_info_rx = -1;
static int hf_radiotap_vw_info_rx_bit0 = -1;
static int hf_radiotap_vw_info_rx_bit1 = -1;
static int hf_radiotap_vw_info_rx_bit3 = -1;
static int hf_radiotap_vw_info_rx_bit4 = -1;
static int hf_radiotap_vw_info_rx_bit5 = -1;
static int hf_radiotap_vw_info_rx_bit6 = -1;
static int hf_radiotap_vw_info_rx_bit7 = -1;
static int hf_radiotap_vw_info_rx_bit8 = -1;
static int hf_radiotap_vw_info_rx_bit9 = -1;
static int hf_radiotap_vw_info_rx_bit10 = -1;
static int hf_radiotap_vw_info_rx_bit11 = -1;
static int hf_radiotap_vw_info_rx_bit12 = -1;
static int hf_radiotap_vw_info_rx_bit13 = -1;
static int hf_radiotap_vw_info_rx_bit14 = -1;
static int hf_radiotap_vw_info_rx_bit15 = -1;
static int hf_radiotap_vw_info_rx_bit16 = -1;
static int hf_radiotap_vw_info_rx_bit17 = -1;
static int hf_radiotap_vw_info_rx_bit18 = -1;
static int hf_radiotap_vw_info_rx_bit19 = -1;
static int hf_radiotap_vw_info_rx_bit20 = -1;
static const int *radiotap_info_rx_fields[] = {
    &hf_radiotap_vw_info_rx_bit0,
    &hf_radiotap_vw_info_rx_bit1,
    &hf_radiotap_vw_info_rx_bit3,
    &hf_radiotap_vw_info_rx_bit4,
    &hf_radiotap_vw_info_rx_bit5,
    &hf_radiotap_vw_info_rx_bit6,
    &hf_radiotap_vw_info_rx_bit7,
    &hf_radiotap_vw_info_rx_bit8,
    &hf_radiotap_vw_info_rx_bit9,
    &hf_radiotap_vw_info_rx_bit10,
    &hf_radiotap_vw_info_rx_bit11,
    &hf_radiotap_vw_info_rx_bit12,
    &hf_radiotap_vw_info_rx_bit13,
    &hf_radiotap_vw_info_rx_bit14,
    &hf_radiotap_vw_info_rx_bit15,
    &hf_radiotap_vw_info_rx_bit16,
    &hf_radiotap_vw_info_rx_bit17,
    &hf_radiotap_vw_info_rx_bit18,
    &hf_radiotap_vw_info_rx_bit19,
    &hf_radiotap_vw_info_rx_bit20,
    NULL,
};

static int hf_radiotap_vw_info_tx_2_bit10 = -1;
static int hf_radiotap_vw_info_tx_2_bit11 = -1;
static int hf_radiotap_vw_info_tx_2_bit12 = -1;
static int hf_radiotap_vw_info_tx_2_bit13 = -1;
static int hf_radiotap_vw_info_tx_2_bit14 = -1;
static int hf_radiotap_vw_info_tx_2_bit15 = -1;

static int hf_radiotap_vw_info_rx_2_bit8 = -1;
static int hf_radiotap_vw_info_rx_2_bit9 = -1;
static int hf_radiotap_vw_info_rx_2_bit10 = -1;
static int hf_radiotap_vw_info_rx_2_bit11 = -1;
static int hf_radiotap_vw_info_rx_2_bit12 = -1;
static int hf_radiotap_vw_info_rx_2_bit13 = -1;
static int hf_radiotap_vw_info_rx_2_bit14 = -1;
static int hf_radiotap_vw_info_rx_2_bit15 = -1;

static int hf_radiotap_vw_errors_tx_bit01 = -1;
static int hf_radiotap_vw_errors_tx_bit05 = -1;
static int hf_radiotap_vw_errors_tx_bit8 = -1;
static int hf_radiotap_vw_errors_tx_bit9 = -1;
static int hf_radiotap_vw_errors_tx_bit10 = -1;
static int hf_radiotap_vw_errors_tx_bit31 = -1;
static int hf_radiotap_vw_tx_retrycount = -1;
static int hf_radiotap_vw_tx_factorydebug = -1;

static int hf_radiotap_vw_errors_tx_bit1 = -1;
static int hf_radiotap_vw_errors_tx_bit5 = -1;

static int hf_radiotap_vw_errors_rx_bit0 = -1;
static int hf_radiotap_vw_errors_rx_bit1 = -1;
static int hf_radiotap_vw_errors_rx_bit2 = -1;
static int hf_radiotap_vw_errors_rx_bit3 = -1;
static int hf_radiotap_vw_errors_rx_bit4 = -1;
static int hf_radiotap_vw_errors_rx_bit5 = -1;
static int hf_radiotap_vw_errors_rx_bit6 = -1;
static int hf_radiotap_vw_errors_rx_bit7 = -1;
static int hf_radiotap_vw_errors_rx_bit8 = -1;
static int hf_radiotap_vw_errors_rx_bit9 = -1;
static int hf_radiotap_vw_errors_rx_bit10 = -1;
static int hf_radiotap_vw_errors_rx_bit11 = -1;
static int hf_radiotap_vw_errors_rx_bit12 = -1;
static int hf_radiotap_vw_errors_rx_bit14 = -1;
static int hf_radiotap_vw_errors_rx_bit15 = -1;
static int hf_radiotap_vw_errors_rx_bit16 = -1;
static int hf_radiotap_vw_errors_rx_bit17 = -1;
static int hf_radiotap_vw_errors_rx_bit18 = -1;
static int hf_radiotap_vw_errors_rx_bit19 = -1;
static int hf_radiotap_vw_errors_rx_bit20 = -1;
static int hf_radiotap_vw_errors_rx_bit21 = -1;
static int hf_radiotap_vw_errors_rx_bit22 = -1;
static int hf_radiotap_vw_errors_rx_bit23 = -1;
static int hf_radiotap_vw_errors_rx_bit24 = -1;
static int hf_radiotap_vw_errors_rx_bit31 = -1;

static int hf_radiotap_vw_errors_rx_2_bit0 = -1;
static int hf_radiotap_vw_errors_rx_2_bit1 = -1;
static int hf_radiotap_vw_errors_rx_2_bit2 = -1;
static int hf_radiotap_vw_errors_rx_2_bit4 = -1;
static int hf_radiotap_vw_errors_rx_2_bit5 = -1;
static int hf_radiotap_vw_errors_rx_2_bit6 = -1;
static int hf_radiotap_vw_errors_rx_2_bit7 = -1;
static int hf_radiotap_vw_errors_rx_2_bit8 = -1;
static int hf_radiotap_vw_errors_rx_2_bit10 = -1;
static int hf_radiotap_vw_errors_rx_2_bit11 = -1;

static int hf_radiotap_vwf_txf = -1;
static int hf_radiotap_vwf_fcserr = -1;
static int hf_radiotap_vwf_dcrerr = -1;
static int hf_radiotap_vwf_retrerr = -1;
static int hf_radiotap_vwf_enctype = -1;

static gint ett_radiotap_info = -1;
static gint ett_radiotap_errors = -1;
static gint ett_radiotap_times = -1;
static gint ett_radiotap_layer1 = -1;
static gint ett_radiotap_layer2to4 = -1;
static gint ett_radiotap_rf = -1;
static gint ett_radiotap_plcp = -1;
static gint ett_radiotap_infoc = -1;
static gint ett_radiotap_contextp = -1;
static gint ett_rf_info = -1;

static int hf_radiotap_rf_info = -1;
static int hf_radiotap_rx = -1;
static int hf_radiotap_tx = -1;
static int hf_radiotap_modulation = -1;
static int hf_radiotap_preamble = -1;
static int hf_radiotap_sigbandwidth = -1;
/* static int hf_radiotap_rssi = -1; */
static int hf_radiotap_l1infoc = -1;
static int hf_radiotap_sigbandwidthmask = -1;
static int hf_radiotap_antennaportenergydetect = -1;
static int hf_radiotap_mumask = -1;
static int hf_radiotap_plcp_info = -1;
static int hf_radiotap_l2_l4_info = -1;
/* static int hf_radiotap_rfinfo_tbd = -1; */
static int hf_radiotap_rfinfo_rfid = -1;
static int hf_radiotap_bssid = -1;
static int hf_radiotap_unicastormulticast = -1;
static int hf_radiotap_clientidvalid = -1;
static int hf_radiotap_bssidvalid = -1;
static int hf_radiotap_flowvalid = -1;
static int hf_radiotap_l4idvalid = -1;
static int hf_radiotap_istypeqos = -1;
static int hf_radiotap_containshtfield = -1;
static int hf_radiotap_tid = -1;
/*static int hf_radiotap_wlantype = -1; */
static int hf_radiotap_payloaddecode = -1;
static int hf_radiotap_vht_bw = -1;
static int hf_radiotap_vht_stbc = -1;
static int hf_radiotap_vht_txop_ps_notallowd = -1;
static int hf_radiotap_vht_shortgi = -1;
static int hf_radiotap_vht_shortginsymdisa = -1;
static int hf_radiotap_vht_ldpc_ofdmsymbol = -1;
static int hf_radiotap_vht_su_mcs = -1;
static int hf_radiotap_vht_crc = -1;
static int hf_radiotap_vht_tail = -1;
static int hf_radiotap_vht_length = -1;
static int hf_radiotap_rfid = -1;
static int hf_radiotap_vht_mcs = -1;
static int hf_radiotap_parity = -1;
static int hf_radiotap_rate = -1;
static int hf_radiotap_plcp_length = -1;
static int hf_radiotap_feccoding = -1;
static int hf_radiotap_aggregation = -1;
static int hf_radiotap_notsounding = -1;
static int hf_radiotap_smoothing = -1;
static int hf_radiotap_ness = -1;
static int hf_radiotap_plcp_service = -1;
static int hf_radiotap_plcp_signal = -1;
static int hf_radiotap_plcp_default = -1;
static int hf_radiotap_tx_antennaselect = -1;
static int hf_radiotap_tx_stbcselect = -1;
static int hf_radiotap_ac = -1;
static int hf_radiotap_crc16 = -1;
// RF LOGGING
static int hf_radiotap_rfinfo_pfe = -1;
/*
static int hf_radiotap_rfinfo_noise = -1;
static int hf_radiotap_rfinfo_noise_anta = -1;
static int hf_radiotap_rfinfo_noise_antb = -1;
static int hf_radiotap_rfinfo_noise_antc = -1;
static int hf_radiotap_rfinfo_noise_antd = -1;
*/
static int hf_radiotap_rfinfo_snr = -1;
static int hf_radiotap_rfinfo_snr_anta = -1;
static int hf_radiotap_rfinfo_snr_antb = -1;
static int hf_radiotap_rfinfo_snr_antc = -1;
static int hf_radiotap_rfinfo_snr_antd = -1;
static int hf_radiotap_rfinfo_pfe_anta = -1;
static int hf_radiotap_rfinfo_pfe_antb = -1;
static int hf_radiotap_rfinfo_pfe_antc = -1;
static int hf_radiotap_rfinfo_pfe_antd = -1;
static int hf_radiotap_rfinfo_contextpa = -1;
static int hf_radiotap_rfinfo_contextpb = -1;
static int hf_radiotap_rfinfo_contextpc = -1;
static int hf_radiotap_rfinfo_contextpd = -1;
static int hf_radiotap_rfinfo_contextpA_bit0 = -1;
static int hf_radiotap_rfinfo_contextpA_bit1 = -1;
static int hf_radiotap_rfinfo_contextpA_bit2 = -1;
static int hf_radiotap_rfinfo_contextpA_bit3 = -1;
static int hf_radiotap_rfinfo_contextpA_bit4 = -1;
static int hf_radiotap_rfinfo_contextpA_bit5 = -1;
/* static int hf_radiotap_rfinfo_contextpA_bit8 = -1; */
/* static int hf_radiotap_rfinfo_contextpA_bit10 = -1; */
/* static int hf_radiotap_rfinfo_contextpA_bit11 = -1; */
static int hf_radiotap_rfinfo_contextpA_bit13 = -1;

static int hf_radiotap_rfinfo_contextpB_bit0 = -1;
static int hf_radiotap_rfinfo_contextpB_bit1 = -1;
static int hf_radiotap_rfinfo_contextpB_bit2 = -1;
static int hf_radiotap_rfinfo_contextpB_bit3 = -1;
static int hf_radiotap_rfinfo_contextpB_bit4 = -1;
static int hf_radiotap_rfinfo_contextpB_bit5 = -1;
static int hf_radiotap_rfinfo_contextpB_bit13 = -1;

static int hf_radiotap_rfinfo_contextpC_bit0 = -1;
static int hf_radiotap_rfinfo_contextpC_bit1 = -1;
static int hf_radiotap_rfinfo_contextpC_bit2 = -1;
static int hf_radiotap_rfinfo_contextpC_bit3 = -1;
static int hf_radiotap_rfinfo_contextpC_bit4 = -1;
static int hf_radiotap_rfinfo_contextpC_bit5 = -1;
static int hf_radiotap_rfinfo_contextpC_bit13 = -1;

static int hf_radiotap_rfinfo_contextpD_bit0 = -1;
static int hf_radiotap_rfinfo_contextpD_bit1 = -1;
static int hf_radiotap_rfinfo_contextpD_bit2 = -1;
static int hf_radiotap_rfinfo_contextpD_bit3 = -1;
static int hf_radiotap_rfinfo_contextpD_bit4 = -1;
static int hf_radiotap_rfinfo_contextpD_bit5 = -1;
static int hf_radiotap_rfinfo_contextpD_bit13 = -1;

static int hf_radiotap_rfinfo_avg_evm_sd_siga = -1;
static int hf_radiotap_rfinfo_avg_evm_sd_sigb = -1;
static int hf_radiotap_rfinfo_avg_evm_sd_sigc = -1;
static int hf_radiotap_rfinfo_avg_evm_sd_sigd = -1;
static int hf_radiotap_rfinfo_avg_evm_sp_siga = -1;
static int hf_radiotap_rfinfo_avg_evm_sp_sigb = -1;
static int hf_radiotap_rfinfo_avg_evm_sp_sigc = -1;
static int hf_radiotap_rfinfo_avg_evm_sp_sigd = -1;
static int hf_radiotap_rfinfo_avg_evm_dd_siga = -1;
static int hf_radiotap_rfinfo_avg_evm_dd_sigb = -1;
static int hf_radiotap_rfinfo_avg_evm_dd_sigc = -1;
static int hf_radiotap_rfinfo_avg_evm_dd_sigd = -1;
static int hf_radiotap_rfinfo_avg_evm_dp_siga = -1;
static int hf_radiotap_rfinfo_avg_evm_dp_sigb = -1;
static int hf_radiotap_rfinfo_avg_evm_dp_sigc = -1;
static int hf_radiotap_rfinfo_avg_evm_dp_sigd = -1;
static int hf_radiotap_rfinfo_avg_evm_ws_siga = -1;
static int hf_radiotap_rfinfo_avg_evm_ws_sigb = -1;
static int hf_radiotap_rfinfo_avg_evm_ws_sigc = -1;
static int hf_radiotap_rfinfo_avg_evm_ws_sigd = -1;
/* static int hf_radiotap_rfinfo_contextp_bits3 = -1; */
static int hf_radiotap_rfinfo_frameformatA = -1;
static int hf_radiotap_rfinfo_frameformatB = -1;
static int hf_radiotap_rfinfo_frameformatC = -1;
static int hf_radiotap_rfinfo_frameformatD = -1;
static int hf_radiotap_rfinfo_sigbwevmA = -1;
static int hf_radiotap_rfinfo_sigbwevmB = -1;
static int hf_radiotap_rfinfo_sigbwevmC = -1;
static int hf_radiotap_rfinfo_sigbwevmD = -1;
static int hf_radiotap_rfinfo_legacytypeA = -1;
static int hf_radiotap_rfinfo_legacytypeB = -1;
static int hf_radiotap_rfinfo_legacytypeC = -1;
static int hf_radiotap_rfinfo_legacytypeD = -1;

static int hf_radiotap_rfinfo_avg_ws_symbol = -1;
static int hf_radiotap_rfinfo_sigdata = -1;
static int hf_radiotap_rfinfo_sigpilot = -1;
static int hf_radiotap_rfinfo_datadata = -1;
static int hf_radiotap_rfinfo_datapilot = -1;
static int hf_radiotap_plcp_type = -1;
static int hf_radiotap_vht_ndp_flg = -1;

static dissector_handle_t ixveriwave_handle;

#define ALIGN_OFFSET(offset, width) \
    ( (((offset) + ((width) - 1)) & (~((width) - 1))) - offset )

static int
dissect_ixveriwave(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
    gboolean    is_octo = FALSE;
    int         log_mode;
    proto_tree *common_tree                 = NULL;
    proto_item *ti                          = NULL;
    proto_item *vw_times_ti                 = NULL;
    proto_tree *vw_times_tree               = NULL;
    proto_item *rf_infot                    = NULL;
    proto_tree *rf_info_tree                = NULL;
    int         offset;
    guint16     length;
    guint       length_remaining;
    guint64     vw_startt=0, vw_endt=0;
    guint32     true_length;
    guint32     vw_latency, vw_pktdur;
    guint32     vw_msdu_length=0;
    tvbuff_t   *next_tvb;
    ifg_info   *p_ifg_info;
    guint8      ixport_type,cmd_type, mgmt_byte = 0;
    guint8      frameformat, rfid, legacy_type;
    gint8       noisevalida, noisevalidb, noisevalidc, noisevalidd, pfevalida, pfevalidb, pfevalidc, pfevalidd;
    guint16     vw_info_ifg;
    int         ifg_flag = 0;
    proto_tree  *vwrft, *vw_rfinfo_tree = NULL, *rfinfo_contextp_tree;

    static const int * context_a_flags[] = {
        &hf_radiotap_rfinfo_contextpA_bit0,
        &hf_radiotap_rfinfo_contextpA_bit1,
        &hf_radiotap_rfinfo_contextpA_bit2,
        &hf_radiotap_rfinfo_contextpA_bit3,
        &hf_radiotap_rfinfo_contextpA_bit4,
        &hf_radiotap_rfinfo_contextpA_bit5,
/*
        &hf_radiotap_rfinfo_contextpA_bit8,
        &hf_radiotap_rfinfo_contextpA_bit10,
        &hf_radiotap_rfinfo_contextpA_bit11,
*/
        &hf_radiotap_rfinfo_contextpA_bit13,
        NULL
    };
    static const int * context_b_flags[] = {
        &hf_radiotap_rfinfo_contextpB_bit0,
        &hf_radiotap_rfinfo_contextpB_bit1,
        &hf_radiotap_rfinfo_contextpB_bit2,
        &hf_radiotap_rfinfo_contextpB_bit3,
        &hf_radiotap_rfinfo_contextpB_bit4,
        &hf_radiotap_rfinfo_contextpB_bit5,
/*
        &hf_radiotap_rfinfo_contextpB_bit8,
        &hf_radiotap_rfinfo_contextpB_bit10,
        &hf_radiotap_rfinfo_contextpB_bit11,
*/
        &hf_radiotap_rfinfo_contextpB_bit13,
        NULL
    };
    static const int * context_c_flags[] = {
        &hf_radiotap_rfinfo_contextpC_bit0,
        &hf_radiotap_rfinfo_contextpC_bit1,
        &hf_radiotap_rfinfo_contextpC_bit2,
        &hf_radiotap_rfinfo_contextpC_bit3,
        &hf_radiotap_rfinfo_contextpC_bit4,
        &hf_radiotap_rfinfo_contextpC_bit5,
/*
        &hf_radiotap_rfinfo_contextpC_bit8,
        &hf_radiotap_rfinfo_contextpC_bit10,
        &hf_radiotap_rfinfo_contextpC_bit11,
*/
        &hf_radiotap_rfinfo_contextpC_bit13,
        NULL
    };
    static const int * context_d_flags[] = {
        &hf_radiotap_rfinfo_contextpD_bit0,
        &hf_radiotap_rfinfo_contextpD_bit1,
        &hf_radiotap_rfinfo_contextpD_bit2,
        &hf_radiotap_rfinfo_contextpD_bit3,
        &hf_radiotap_rfinfo_contextpD_bit4,
        &hf_radiotap_rfinfo_contextpD_bit5,
/*
        &hf_radiotap_rfinfo_contextpD_bit8,
        &hf_radiotap_rfinfo_contextpD_bit10,
        &hf_radiotap_rfinfo_contextpD_bit11,
*/
        &hf_radiotap_rfinfo_contextpD_bit13,
        NULL
    };

    offset = 0;
    //mgmt_bytes = tvb_get_letohs(tvb, offset);
    //1st octet are as command type((7..4 bits)which indicates as Tx, Rx or RF frame) & port type((3..0 bits)ethernet or wlantap).
    //Command type Rx = 0, Tx = 1, RF = 3 , RF_RX = 4
    //2nd octet are as Reduce logging(7..4 bits) & fpga version(3..0 bits).
    //log mode = 0 is normal capture and 1 is reduced capture
    //FPGA version = 1 for OCTO versions
    //OCTO version like 48, 61, 83
    ixport_type = tvb_get_guint8(tvb, offset);
    cmd_type = (ixport_type & 0xf0) >> 4;
    ixport_type &= 0x0f;

    /*
     * If the command type is non-zero, this is from an OCTO board.
     */
    if (cmd_type != 0)
    {
        is_octo = TRUE;
        if (cmd_type != 3)
        {
            mgmt_byte = tvb_get_guint8(tvb, offset+1);
            log_mode = (mgmt_byte & 0xf0) >> 4;
        }
        else
        {
            log_mode = 0;
        }
    }
    else
    {
        /*
         * If it's zero, it could *still* be from an octo board, if the
         * command type is Rx.
         */
        mgmt_byte = tvb_get_guint8(tvb, offset+1);
        if ((mgmt_byte & 0x0f) != 0)
            is_octo = TRUE;
        log_mode = (mgmt_byte & 0xf0) >> 4;
    }

    length = tvb_get_letohs(tvb, offset + COMMON_LENGTH_OFFSET);

    col_add_fstr(pinfo->cinfo, COL_PROTOCOL, "%s", ixport_type ? "ETH" : "WLAN");
    col_clear(pinfo->cinfo, COL_INFO);

    true_length = pinfo->fd->pkt_len - length - tvb_get_letohs(tvb, offset + length) + 4;   /* add FCS length into captured length */

    col_add_fstr(pinfo->cinfo, COL_INFO, "%s Capture, Length %u",
                 ixport_type ? "IxVeriWave Ethernet Tap" : "IxVeriWave Radio Tap", length);

    /* Dissect the packet */
    ti = proto_tree_add_protocol_format(tree, proto_ixveriwave,
                                            tvb, 0, length, "%s Header",
                                            ixport_type ? "IxVeriWave Ethernet Tap" : "IxVeriWave Radio Tap");
    common_tree = proto_item_add_subtree(ti, ett_commontap);

    //checked for only RF frames should be skipped from the other logging details.
    if (!is_octo)
    {
        /*
         * Common header.
         */
        /* common header length */
        proto_tree_add_uint(common_tree, hf_ixveriwave_frame_length,
                            tvb, 4, 2, true_length);
        length_remaining = length;

        offset              +=4;
        length_remaining    -=4;

        /* MSDU length */
        if (length_remaining >= 2) {

            proto_tree_add_item_ret_uint(common_tree, hf_ixveriwave_vw_msdu_length, tvb, offset, 2, ENC_LITTLE_ENDIAN, &vw_msdu_length);
            offset              +=2;
            length_remaining    -=2;
        }

        /*extract flow id , 4bytes*/
        if (length_remaining >= 4) {
            proto_tree_add_item(common_tree, hf_ixveriwave_vw_flowid, tvb, offset, 4, ENC_LITTLE_ENDIAN);

            offset              +=4;
            length_remaining    -=4;
        }

        /*extract client id, 2bytes*/
        if (length_remaining >= 2) {
            proto_tree_add_item(common_tree, hf_ixveriwave_vw_vcid, tvb, offset, 2, ENC_LITTLE_ENDIAN);

            offset              +=2;
            length_remaining    -=2;
        }

        /*extract sequence number , 2bytes*/
        if (length_remaining >= 2) {

            proto_tree_add_item(common_tree, hf_ixveriwave_vw_seqnum, tvb, offset, 2, ENC_LITTLE_ENDIAN);

            offset              +=2;
            length_remaining    -=2;
        }

        /*extract latency, 4 bytes*/
        if (length_remaining >= 4) {
            vw_latency = tvb_get_letohl(tvb, offset);

            /* start a tree going for the various packet times */
            if (vw_latency != 0) {
                vw_times_ti = proto_tree_add_float_format(common_tree,
                    hf_ixveriwave_vw_mslatency,
                    tvb, offset, 4, (float)(vw_latency/1000000.0),
                    "Frame timestamp values: (latency %.3f msec)",
                    (float)(vw_latency/1000000.0));
                vw_times_tree = proto_item_add_subtree(vw_times_ti, ett_commontap_times);

                proto_tree_add_uint(vw_times_tree, hf_ixveriwave_vw_latency, tvb, offset, 4, vw_latency);
            }
            else
            {
                vw_times_ti = proto_tree_add_float_format(common_tree,
                    hf_ixveriwave_vw_mslatency,
                    tvb, offset, 4, (float)(vw_latency/1000000.0),
                    "Frame timestamp values:");
                vw_times_tree = proto_item_add_subtree(vw_times_ti, ett_commontap_times);

                proto_tree_add_uint_format_value(vw_times_tree, hf_ixveriwave_vw_latency,
                    tvb, offset, 4, vw_latency, "N/A");
            }

            offset              +=4;
            length_remaining    -=4;
        }

        /*extract signature timestamp, 4 bytes (32 LSBs only, nsec)*/
        if (length_remaining >= 4) {
            /* TODO: what should this fieldname be? */
            proto_tree_add_item(vw_times_tree, hf_ixveriwave_vw_sig_ts,
                            tvb, offset, 4, ENC_BIG_ENDIAN);
            offset              +=4;
            length_remaining    -=4;
        }

        /*extract frame start timestamp, 8 bytes (nsec)*/
        if (length_remaining >= 8) {
            proto_tree_add_item_ret_uint64(vw_times_tree, hf_ixveriwave_vw_startt,
                    tvb, offset, 8, ENC_LITTLE_ENDIAN, &vw_startt);

            offset              +=8;
            length_remaining    -=8;
        }

        /* extract frame end timestamp, 8 bytes (nsec)*/
        if (length_remaining >= 8) {
            proto_tree_add_item_ret_uint64(vw_times_tree, hf_ixveriwave_vw_endt,
                    tvb, offset, 8, ENC_LITTLE_ENDIAN, &vw_endt);

            offset              +=8;
            length_remaining    -=8;
        }

        /*extract frame duration , 4 bytes*/
        if (length_remaining >= 4) {
            vw_pktdur = tvb_get_letohl(tvb, offset);

            if (vw_endt >= vw_startt) {
                /* Add to root summary */
                if (ixport_type == ETHERNET_PORT) {
                    proto_item_append_text(vw_times_ti, " (Frame duration=%u nsecs)", vw_pktdur);
                    proto_tree_add_uint(vw_times_tree, hf_ixveriwave_vw_pktdur,
                                        tvb, offset-16, 16, vw_pktdur);
                }
                else {
                    proto_item_append_text(vw_times_ti, " (Frame duration=%u usecs)", vw_pktdur);
                    proto_tree_add_uint(vw_times_tree, hf_ixveriwave_vw_pktdur,
                                        tvb, offset-16, 16, vw_pktdur);
                }
            }
            else {
                proto_tree_add_uint_format_value(vw_times_tree, hf_ixveriwave_vw_pktdur,
                                            tvb, offset, 0, vw_pktdur, "N/A");

                /* Add to root summary */
                proto_item_append_text(vw_times_ti, " (Frame duration=N/A)");
            }

            offset              +=4;
        }

    } else { //Rather then the legacy it takes care to show the Time Header for RadioTapHeader in new format
        length_remaining = length;

        offset              +=4;
        length_remaining    -=4;
        /* XXX - not if the command is 3 */
        /*extract latency, 4 bytes*/
        if (length_remaining >= 4) {
            vw_latency = tvb_get_letohl(tvb, offset);

            /* start a tree going for the various packet times */
            if (vw_latency != 0) {
                vw_times_ti = proto_tree_add_float_format(common_tree,
                    hf_ixveriwave_vw_mslatency,
                    tvb, offset, 4, (float)(vw_latency/1000000.0),
                    "Time Header(latency %.3f msec)",
                    (float)(vw_latency/1000000.0));
                vw_times_tree = proto_item_add_subtree(vw_times_ti, ett_commontap_times);

                proto_tree_add_uint(vw_times_tree, hf_ixveriwave_vw_latency, tvb, offset, 4, vw_latency);
            }
            else
            {
                vw_times_ti = proto_tree_add_float_format(common_tree,
                    hf_ixveriwave_vw_mslatency,
                    tvb, offset, 4, (float)(vw_latency/1000000.0),
                    "Time Header");
                vw_times_tree = proto_item_add_subtree(vw_times_ti, ett_commontap_times);

                if (cmd_type != 1) {
                    proto_tree_add_uint_format_value(vw_times_tree, hf_ixveriwave_vw_latency,
                        tvb, offset, 4, vw_latency, "N/A");
                }
            }
            offset              +=4;
            length_remaining    -=4;
        }

        /*extract signature timestamp, 4 bytes (32 LSBs only, nsec)*/
        if (length_remaining >= 4) {
            /* TODO: what should this fieldname be? */
                if (cmd_type != 1)
                    proto_tree_add_item(vw_times_tree, hf_ixveriwave_vw_sig_ts,
                        tvb, offset, 4, ENC_BIG_ENDIAN);
                else
                    proto_tree_add_item(vw_times_tree, hf_ixveriwave_vw_delay,
                        tvb, offset, 4, ENC_BIG_ENDIAN);
            offset              +=4;
            length_remaining    -=4;
        }

        /*extract frame start timestamp, 8 bytes (nsec)*/
        if (length_remaining >= 8) {
            proto_tree_add_item_ret_uint64(vw_times_tree, hf_ixveriwave_vw_startt,
                    tvb, offset, 8, ENC_LITTLE_ENDIAN, &vw_startt);

            offset              +=8;
            length_remaining    -=8;
        }

        /* extract frame end timestamp, 8 bytes (nsec)*/
        if (length_remaining >= 8) {
            proto_tree_add_item_ret_uint64(vw_times_tree, hf_ixveriwave_vw_endt,
                tvb, offset, 8, ENC_LITTLE_ENDIAN, &vw_endt);

            offset              +=8;
            length_remaining    -=8;
        }

        /*extract frame duration , 4 bytes*/
        if (length_remaining >= 4) {
            vw_pktdur = tvb_get_letohl(tvb, offset);

            if (vw_endt >= vw_startt) {
                /* Add to root summary */
                if (ixport_type == ETHERNET_PORT) {
                    proto_item_append_text(vw_times_ti, " (Frame duration=%u nsecs)", vw_pktdur);
                        proto_tree_add_uint(vw_times_tree, hf_ixveriwave_vw_pktdur,
                                        tvb, offset-16, 16, vw_pktdur);
                }
                else {
                    proto_item_append_text(vw_times_ti, " (Frame duration=%u usecs)", vw_pktdur);
                    proto_tree_add_uint(vw_times_tree, hf_ixveriwave_vw_pktdur,
                                        tvb, offset, 4, vw_pktdur);
                }
            }
            else {
                proto_tree_add_uint_format_value(vw_times_tree, hf_ixveriwave_vw_pktdur,
                                            tvb, offset, 0, vw_pktdur, "N/A");

                /* Add to root summary */
                proto_item_append_text(vw_times_ti, " (Frame duration=N/A)");
            }

            offset += 4;
        }
    }

    /*
     * Calculate the IFG
     * Check for an existing ifg value associated with the frame
     */
    p_ifg_info = (ifg_info *)p_get_proto_data(wmem_file_scope(), pinfo, proto_ixveriwave, 0);
    if (!p_ifg_info)
    {
        /* allocate the space */
        p_ifg_info = wmem_new0(wmem_file_scope(), struct ifg_info);

        /* Doesn't exist, so we need to calculate the value */
        if (previous_frame_data.previous_frame_num !=0 && (pinfo->num - previous_frame_data.previous_frame_num == 1))
        {
            p_ifg_info->ifg = (guint32)(vw_startt - previous_frame_data.previous_end_time);
            p_ifg_info->previous_end_time = previous_frame_data.previous_end_time;
        }
        else
        {
            p_ifg_info->ifg                 = 0;
            p_ifg_info->previous_end_time   = 0;
        }

        /* Store current data into the static structure */
        previous_frame_data.previous_end_time = vw_endt;
        previous_frame_data.previous_frame_num = pinfo->num;

        /* Record the current start time */
        p_ifg_info->current_start_time = vw_startt;

        /* Add the ifg onto the frame */
        p_add_proto_data(wmem_file_scope(), pinfo, proto_ixveriwave, 0, p_ifg_info);
    }

    if (is_octo) {
        p_ifg_info = (struct ifg_info *) p_get_proto_data(wmem_file_scope(), pinfo, proto_ixveriwave, 0);
        switch (cmd_type) {
        case 0:
            vw_info_ifg = tvb_get_ntohs(tvb, offset+ VW_INFO_OFF );
            if ((vw_info_ifg & 0x0004) && !(vw_info_ifg & 0x0008))  /* If the packet is part of an A-MPDU but not the first MPDU */
                ifg_flag = 1;
            else
                ifg_flag = 0;
            break;
        case 1:
            vw_info_ifg = tvb_get_letohs(tvb, offset+ VW_INFO_OFF);
            if ((vw_info_ifg & 0x0400) && !(vw_info_ifg & 0x0800))  /* If the packet is part of an A-MPDU but not the first MPDU */
                ifg_flag = 1;
            else
                ifg_flag = 0;
            break;

        case 4:
            vw_info_ifg = tvb_get_ntohs(tvb, offset+ VW_INFO_OFF + OCTO_MODIFIED_RF_LEN);
            if ((vw_info_ifg & 0x0004) && !(vw_info_ifg & 0x0008))  /* If the packet is part of an A-MPDU but not the first MPDU */
                ifg_flag = 1;
            else
                ifg_flag = 0;
            break;

        default:
            break;
        }

        if (ifg_flag == 1) /* If the packet is part of an A-MPDU but not the first MPDU */
            ti = proto_tree_add_uint(common_tree, hf_ixveriwave_vw_ifg, tvb, 18, 0, 0);
        else {
            /*** if (p_ifg_info->ifg < IFG_MAX_VAL) ***/
            if ((gint32) p_ifg_info->ifg >= 0)
                ti = proto_tree_add_uint(common_tree, hf_ixveriwave_vw_ifg, tvb, 18, 0, p_ifg_info->ifg);
            else
                ti = proto_tree_add_string(common_tree, hf_ixveriwave_vw_ifg_neg, tvb, 18, 0, "Cannot be determined");
        }

        PROTO_ITEM_SET_GENERATED(ti);
    }

    if(cmd_type ==3 || cmd_type ==4)
    {
        float flttmp;
        frameformat = tvb_get_guint8(tvb, offset+33)& 0x03;
        legacy_type = tvb_get_guint8(tvb, offset+33)& 0x04 >>2;

        if(cmd_type ==3)
            offset += 1;

        // Only RF header implementation
        if (tree) {

            rfid = tvb_get_guint8(tvb, offset);
            vwrft = proto_tree_add_item(common_tree, hf_radiotap_rf_info,
                            tvb, offset, 76, ENC_NA);
            proto_item_append_text(vwrft, " (RFID = %u)",rfid);
            vw_rfinfo_tree = proto_item_add_subtree(vwrft, ett_radiotap_rf);

            proto_tree_add_uint(vw_rfinfo_tree,
                hf_radiotap_rfinfo_rfid, tvb, offset, 1, rfid);
            offset += 4;
            //Section for Noise
            noisevalida = tvb_get_guint8(tvb, offset+65)& 0x01;
            noisevalidb = tvb_get_guint8(tvb, offset+67)& 0x01;
            noisevalidc = tvb_get_guint8(tvb, offset+69)& 0x01;
            noisevalidd = tvb_get_guint8(tvb, offset+71)& 0x01;

            /*
            noisea = (gint16) tvb_get_ntohs(tvb, offset);
            //noisevalida = tvb_get_guint8(tvb, offset+65)& 0x01;
            if (noisevalida == 1)
                rf_infot = proto_tree_add_float_format(vw_rfinfo_tree, hf_radiotap_rfinfo_noise,
                    tvb, offset, 8, (float)(noisea/16.0),"Noise:   A:%.2fdBm, ", (float)(noisea/16.0));
                //These are 16-bit signed numbers with four fraction bits representing NOISE in dBm.  So 0xFFFF represents -1/16 dBm.
            else
                rf_infot = proto_tree_add_float_format(vw_rfinfo_tree, hf_radiotap_rfinfo_noise,
                    tvb, offset, 8, (float)(noisea/16.0),"Noise:   A: N/A, ", (float)(noisea/16.0));
            rf_info_tree = proto_item_add_subtree(rf_infot, ett_rf_info);
            noiseb = tvb_get_ntohs(tvb, offset+2);
            noisevalidb = tvb_get_guint8(tvb, offset+67)& 0x01;
            if (noisevalidb == 1)
                proto_item_append_text(rf_infot, "B:%.2fdBm, ", (float)(noiseb/16.0));
            else
                proto_item_append_text(rf_infot, "B: N/A, ", (float)(noiseb/16.0));
            noisec = tvb_get_ntohs(tvb, offset+4);
            noisevalidc = tvb_get_guint8(tvb, offset+69)& 0x01;
            if (noisevalidc == 1)
                proto_item_append_text(rf_infot, "C:%.2fdBm, ", (float)(noisec/16.0));
            else
                proto_item_append_text(rf_infot, "C: N/A, ", (float)(noisec/16.0));
            noised = tvb_get_ntohs(tvb, offset+6);
            noisevalidd = tvb_get_guint8(tvb, offset+71)& 0x01;
            if (noisevalidd == 1)
                proto_item_append_text(rf_infot, "D:%.2fdBm", (float)(noised/16.0));
            else
                proto_item_append_text(rf_infot, "D: N/A", (float)(noised/16.0));
            */

            offset     += 8;
            //Section for SNR
            //These are 16-bit signed numbers with four fraction bits in units of dB .  So 0xFFFF represents -1/16 dB.
            rf_infot = proto_tree_add_none_format(vw_rfinfo_tree, hf_radiotap_rfinfo_snr, tvb, offset, 8, "SNR:     ");
            rf_info_tree = proto_item_add_subtree(rf_infot, ett_rf_info);

            flttmp = (float)round(tvb_get_ntohs(tvb, offset) / 16.0f);
            if (noisevalida == 1)
            {
                proto_tree_add_float(rf_info_tree, hf_radiotap_rfinfo_snr_anta, tvb, offset, 2, flttmp);
                proto_item_append_text(rf_infot, "A:%.0fdB, ", flttmp);
            }
            else
            {
                proto_tree_add_float_format_value(rf_info_tree, hf_radiotap_rfinfo_snr_anta, tvb, offset, 2, flttmp, "N/A");
                proto_item_append_text(rf_infot, "A:N/A, ");
            }
            offset += 2;
            flttmp = (float)round(tvb_get_ntohs(tvb, offset) / 16.0f);
            if (noisevalidb == 1)
            {
                proto_tree_add_float(rf_info_tree, hf_radiotap_rfinfo_snr_antb, tvb, offset, 2, flttmp);
                proto_item_append_text(rf_infot, "B:%.0fdB, ", flttmp);
            }
            else
            {
                proto_tree_add_float_format_value(rf_info_tree, hf_radiotap_rfinfo_snr_antb, tvb, offset, 2, flttmp, "N/A");
                proto_item_append_text(rf_infot, "B:N/A, ");
            }
            offset += 2;
            flttmp = (float)round(tvb_get_ntohs(tvb, offset) / 16.0f);
            if (noisevalidc == 1)
            {
                proto_tree_add_float(rf_info_tree, hf_radiotap_rfinfo_snr_antc, tvb, offset, 2, flttmp);
                proto_item_append_text(rf_infot, "C:%.0fdB, ", flttmp);
            }
            else
            {
                proto_tree_add_float_format_value(rf_info_tree, hf_radiotap_rfinfo_snr_antc, tvb, offset, 2, flttmp, "N/A");
                proto_item_append_text(rf_infot, "C:N/A, ");
            }
            offset      += 2;
            flttmp = (float)round(tvb_get_ntohs(tvb, offset) / 16.0f);
            if (noisevalidd == 1)
            {
                proto_tree_add_float(rf_info_tree, hf_radiotap_rfinfo_snr_antd, tvb, offset, 2, flttmp);
                proto_item_append_text(rf_infot, "D:%.0fdB", flttmp);
            }
            else
            {
                proto_tree_add_float_format_value(rf_info_tree, hf_radiotap_rfinfo_snr_antd, tvb, offset, 2, flttmp, "N/A");
                proto_item_append_text(rf_infot, "D:N/A");
            }
            offset      += 2;
            //Section for PFE
            pfevalida = (tvb_get_guint8(tvb, offset+49)& 0x02) >>1;
            pfevalidb = (tvb_get_guint8(tvb, offset+51)& 0x02) >>1;
            pfevalidc = (tvb_get_guint8(tvb, offset+53)& 0x02) >>1;
            pfevalidd = (tvb_get_guint8(tvb, offset+55)& 0x02) >>1;
            rf_infot = proto_tree_add_none_format(vw_rfinfo_tree, hf_radiotap_rfinfo_pfe,
                        tvb, offset, 8, "PFE:     ");
            rf_info_tree = proto_item_add_subtree(rf_infot, ett_rf_info);
            if ((frameformat == 0) && (legacy_type == 0))
            {
                //The basic unit of OFDM frequency error measurement is in units of 80 MHz/2^22.
                //This works out to approximately 19.073 Hz per measurement unit.
                flttmp = (float)(tvb_get_ntohs(tvb, offset)*19.073);
            }
            else
            {
                //The basic unit of CCK frequency error measurement is in units of 88 MHz/2^22.
                //This works out to approximately 20.981 Hz.
                flttmp = (float)(tvb_get_ntohs(tvb, offset)*20.981);
            }

            if (pfevalida == 1)
            {
                proto_item_append_text(rf_infot, "SS#1:%.0fHz, ", flttmp);
                proto_tree_add_float(rf_info_tree, hf_radiotap_rfinfo_pfe_anta,
                    tvb, offset, 2, flttmp);
            }
            else
            {
                proto_item_append_text(rf_infot, "SS#1:N/A, ");
                proto_tree_add_float_format_value(rf_info_tree, hf_radiotap_rfinfo_pfe_anta,
                    tvb, offset, 2, flttmp, "N/A");
            }
            offset += 2;

            if ((frameformat == 0) && (legacy_type == 0))
            {
                flttmp = (float)(tvb_get_ntohs(tvb, offset)*19.073);
            }
            else
            {
                flttmp = (float)(tvb_get_ntohs(tvb, offset)*20.981);
            }
            if (pfevalidb == 1)
            {
                proto_item_append_text(rf_infot, "SS#2:%.0fHz, ", flttmp);
                proto_tree_add_float(rf_info_tree, hf_radiotap_rfinfo_pfe_antb,
                    tvb, offset, 2, flttmp);
            }
            else
            {
                proto_item_append_text(rf_infot, "SS#2:N/A, ");
                proto_tree_add_float_format_value(rf_info_tree, hf_radiotap_rfinfo_pfe_antb,
                    tvb, offset, 2, flttmp, "N/A");
            }
            offset += 2;

            if ((frameformat == 0) && (legacy_type == 0))
            {
                flttmp = (float)(tvb_get_ntohs(tvb, offset)*19.073);
            }
            else
            {
                flttmp = (float)(tvb_get_ntohs(tvb, offset)*20.981);
            }
            if (pfevalidc == 1)
            {
                proto_item_append_text(rf_infot, "SS#3:%.0fHz, ", flttmp);
                proto_tree_add_float(rf_info_tree, hf_radiotap_rfinfo_pfe_antc,
                    tvb, offset, 2, flttmp);
            }
            else
            {
                proto_item_append_text(rf_infot, "SS#3:N/A, ");
                proto_tree_add_float_format_value(rf_info_tree, hf_radiotap_rfinfo_pfe_antc,
                    tvb, offset, 2, flttmp, "N/A");
            }
            offset += 2;

            if ((frameformat == 0) && (legacy_type == 0))
            {
                flttmp = (float)(tvb_get_ntohs(tvb, offset)*19.073);
            }
            else
            {
                flttmp = (float)(tvb_get_ntohs(tvb, offset)*20.981);
            }
            if (pfevalidd == 1)
            {
                proto_item_append_text(rf_infot, "SS#4:%.0fHz", flttmp);
                proto_tree_add_float(rf_info_tree, hf_radiotap_rfinfo_pfe_antd,
                    tvb, offset, 2, flttmp);
            }
            else
            {
                proto_item_append_text(rf_infot, "SS#4:N/A");
                proto_tree_add_float_format_value(rf_info_tree, hf_radiotap_rfinfo_pfe_antd,
                    tvb, offset, 2, flttmp, "N/A");
            }
            offset += 2;

            //AVG EVM SIG Data
            rf_infot = proto_tree_add_none_format(vw_rfinfo_tree, hf_radiotap_rfinfo_sigdata, tvb, offset, 8, "AVG EVM SIG Data:    ");
            rf_info_tree = proto_item_add_subtree(rf_infot, ett_rf_info);

            flttmp = (float)(tvb_get_ntohs(tvb, offset)/512.0);
            proto_item_append_text(rf_infot, "SS#1:%.1f%%, ", flttmp);
            proto_tree_add_float_format_value(rf_info_tree, hf_radiotap_rfinfo_avg_evm_sd_siga,
                tvb, offset, 2, flttmp, "%.1f%%", flttmp);
            offset += 2;

            flttmp = (float)(tvb_get_ntohs(tvb, offset)/512.0);
            proto_item_append_text(rf_infot, "SS#2:%.1f%%, ", flttmp);
            proto_tree_add_float_format_value(rf_info_tree, hf_radiotap_rfinfo_avg_evm_sd_sigb,
                tvb, offset, 2, flttmp, "%.1f%%", flttmp);
            offset += 2;

            flttmp = (float)(tvb_get_ntohs(tvb, offset)/512.0);
            proto_item_append_text(rf_infot, "SS#3:%.1f%%, ", flttmp);
            proto_tree_add_float_format_value(rf_info_tree, hf_radiotap_rfinfo_avg_evm_sd_sigc,
                tvb, offset, 2, flttmp, "%.1f%%", flttmp);
            offset += 2;

            flttmp = (float)(tvb_get_ntohs(tvb, offset)/512.0);
            proto_item_append_text(rf_infot, "SS#4:%.1f%%", flttmp);
            proto_tree_add_float_format_value(rf_info_tree, hf_radiotap_rfinfo_avg_evm_sd_sigd,
                tvb, offset, 2, flttmp, "%.1f%%", flttmp);
            offset += 2;

             //AVG EVM SIG Pilot
            rf_infot = proto_tree_add_none_format(vw_rfinfo_tree, hf_radiotap_rfinfo_sigpilot, tvb, offset, 8, "AVG EVM SIG Pilot:   ");
            rf_info_tree = proto_item_add_subtree(rf_infot, ett_rf_info);

            flttmp = (float)(tvb_get_ntohs(tvb, offset)/512.0);
            proto_item_append_text(rf_infot, "SS#1:%.1f%%, ", flttmp);
            proto_tree_add_float_format_value(rf_info_tree, hf_radiotap_rfinfo_avg_evm_sp_siga,
                tvb, offset, 2, flttmp, "%.1f%%", flttmp);
            offset += 2;

            flttmp = (float)(tvb_get_ntohs(tvb, offset)/512.0);
            proto_item_append_text(rf_infot, "SS#2:%.1f%%, ", flttmp);
            proto_tree_add_float_format_value(rf_info_tree, hf_radiotap_rfinfo_avg_evm_sp_sigb,
                tvb, offset, 2, flttmp, "%.1f%%", flttmp);
            offset += 2;

            flttmp = (float)(tvb_get_ntohs(tvb, offset)/512.0);
            proto_item_append_text(rf_infot, "SS#3:%.1f%%, ", flttmp);
            proto_tree_add_float_format_value(rf_info_tree, hf_radiotap_rfinfo_avg_evm_sp_sigc,
                tvb, offset, 2, flttmp, "%.1f%%", flttmp);
            offset += 2;

            flttmp = (float)(tvb_get_ntohs(tvb, offset)/512.0);
            proto_item_append_text(rf_infot, "SS#4:%.1f%%, ", flttmp);
            proto_tree_add_float_format_value(rf_info_tree, hf_radiotap_rfinfo_avg_evm_sp_sigd,
                tvb, offset, 2, flttmp, "%.1f%%", flttmp);
            offset += 2;

            //AVG EVM DATA Data
            rf_infot = proto_tree_add_none_format(vw_rfinfo_tree, hf_radiotap_rfinfo_datadata,
                          tvb, offset, 8, "AVG EVM DATA Data:   ");
            rf_info_tree = proto_item_add_subtree(rf_infot, ett_rf_info);

            flttmp = (float)(tvb_get_ntohs(tvb, offset)/512.0);
            proto_item_append_text(rf_infot, "SS#1:%.1f%%, ", flttmp);
            proto_tree_add_float_format_value(rf_info_tree, hf_radiotap_rfinfo_avg_evm_dd_siga,
                tvb, offset, 2, flttmp, "%.1f%%", flttmp);
            offset += 2;

            flttmp = (float)(tvb_get_ntohs(tvb, offset)/512.0);
            proto_item_append_text(rf_infot, "SS#2:%.1f%%, ", flttmp);
            proto_tree_add_float_format_value(rf_info_tree, hf_radiotap_rfinfo_avg_evm_dd_sigb,
                tvb, offset, 2, flttmp, "%.1f%%", flttmp);
            offset += 2;

            flttmp = (float)(tvb_get_ntohs(tvb, offset)/512.0);
            proto_item_append_text(rf_infot, "SS#3:%.1f%%, ", flttmp);
            proto_tree_add_float_format_value(rf_info_tree, hf_radiotap_rfinfo_avg_evm_dd_sigc,
                tvb, offset, 2, flttmp, "%.1f%%", flttmp);
            offset += 2;

            flttmp = (float)(tvb_get_ntohs(tvb, offset)/512.0);
            proto_item_append_text(rf_infot, "SS#4:%.1f%%, ", flttmp);
            proto_tree_add_float_format_value(rf_info_tree, hf_radiotap_rfinfo_avg_evm_dd_sigd,
                tvb, offset, 2, flttmp, "%.1f%%", flttmp);
            offset += 2;

             //AVG EVM DATA Pilot
            rf_infot = proto_tree_add_none_format(vw_rfinfo_tree, hf_radiotap_rfinfo_datapilot,
                          tvb, offset, 8, "AVG EVM DATA Pilot:  ");
            rf_info_tree = proto_item_add_subtree(rf_infot, ett_rf_info);

            flttmp = (float)(tvb_get_ntohs(tvb, offset)/512.0);
            proto_item_append_text(rf_infot, "SS#1:%.1f%%, ", flttmp);
            proto_tree_add_float_format_value(rf_info_tree, hf_radiotap_rfinfo_avg_evm_dp_siga,
                tvb, offset, 2, flttmp, "%.1f%%", flttmp);
            offset += 2;

            flttmp = (float)(tvb_get_ntohs(tvb, offset)/512.0);
            proto_item_append_text(rf_infot, "SS#2:%.1f%%, ", flttmp);
            proto_tree_add_float_format_value(rf_info_tree, hf_radiotap_rfinfo_avg_evm_dp_sigb,
                tvb, offset, 2, flttmp, "%.1f%%", flttmp);
            offset += 2;

            flttmp = (float)(tvb_get_ntohs(tvb, offset)/512.0);
            proto_item_append_text(rf_infot, "SS#3:%.1f%%, ", flttmp);
            proto_tree_add_float_format_value(rf_info_tree, hf_radiotap_rfinfo_avg_evm_dp_sigc,
                tvb, offset, 2, flttmp, "%.1f%%", flttmp);
            offset += 2;

            flttmp = (float)(tvb_get_ntohs(tvb, offset)/512.0);
            proto_item_append_text(rf_infot, "SS#4:%.1f%%", flttmp);
            proto_tree_add_float_format_value(rf_info_tree, hf_radiotap_rfinfo_avg_evm_dp_sigd,
                tvb, offset, 2, flttmp, "%.1f%%", flttmp);
            offset += 2;

             //EVM Worst Symbol
            rf_infot = proto_tree_add_item(vw_rfinfo_tree, hf_radiotap_rfinfo_avg_ws_symbol,
                          tvb, offset, 8, ENC_NA);
            rf_info_tree = proto_item_add_subtree(rf_infot, ett_rf_info);

            proto_tree_add_item(rf_info_tree, hf_radiotap_rfinfo_avg_evm_ws_siga, tvb, offset, 2, ENC_BIG_ENDIAN);
            proto_item_append_text(rf_infot, ":   SS#1:%u%%, ", tvb_get_ntohs(tvb, offset));
            offset += 2;

            proto_tree_add_item(rf_info_tree, hf_radiotap_rfinfo_avg_evm_ws_sigb, tvb, offset, 2, ENC_BIG_ENDIAN);
            proto_item_append_text(rf_infot, "SS#2:%u%%, ", tvb_get_ntohs(tvb, offset));
            offset += 2;

            proto_tree_add_item(rf_info_tree, hf_radiotap_rfinfo_avg_evm_ws_sigc, tvb, offset, 2, ENC_BIG_ENDIAN);
            proto_item_append_text(rf_infot, "SS#3:%u%%, ", tvb_get_ntohs(tvb, offset));
            offset += 2;

            proto_tree_add_item(rf_info_tree, hf_radiotap_rfinfo_avg_evm_ws_sigd, tvb, offset, 2, ENC_BIG_ENDIAN);
            proto_item_append_text(rf_infot, "SS#4:%u%%", tvb_get_ntohs(tvb, offset));
            offset += 2;

             //ContextA
            ti = proto_tree_add_bitmask(rf_info_tree, tvb, offset, hf_radiotap_rfinfo_contextpa, ett_radiotap_contextp, context_a_flags, ENC_BIG_ENDIAN);
            rfinfo_contextp_tree = proto_item_add_subtree(ti, ett_radiotap_contextp);

            frameformat = tvb_get_guint8(tvb, offset)& 0x03;
            if (frameformat == 0)
            {
                proto_tree_add_item(rfinfo_contextp_tree, hf_radiotap_rfinfo_legacytypeA, tvb, offset, 1, ENC_NA);
            }
            else
            {
                proto_tree_add_item(rfinfo_contextp_tree, hf_radiotap_rfinfo_frameformatA, tvb, offset, 1, ENC_NA);
            }

            proto_tree_add_item(rfinfo_contextp_tree, hf_radiotap_rfinfo_sigbwevmA, tvb, offset, 1, ENC_NA);
            offset      += 2;

             //ContextB
            ti = proto_tree_add_bitmask(rf_info_tree, tvb, offset, hf_radiotap_rfinfo_contextpb, ett_radiotap_contextp, context_b_flags, ENC_BIG_ENDIAN);
            rfinfo_contextp_tree = proto_item_add_subtree(ti, ett_radiotap_contextp);

            frameformat = tvb_get_guint8(tvb, offset)& 0x03;
            if (frameformat == 0)
            {
                proto_tree_add_item(rfinfo_contextp_tree, hf_radiotap_rfinfo_legacytypeB, tvb, offset, 1, ENC_NA);
            }
            else
            {
                proto_tree_add_item(rfinfo_contextp_tree, hf_radiotap_rfinfo_frameformatB, tvb, offset, 1, ENC_NA);
            }

            proto_tree_add_item(rfinfo_contextp_tree, hf_radiotap_rfinfo_sigbwevmB, tvb, offset, 1, ENC_NA);
            offset += 2;

             //ContextC
            ti = proto_tree_add_bitmask(vw_rfinfo_tree, tvb, offset, hf_radiotap_rfinfo_contextpc, ett_radiotap_contextp, context_c_flags, ENC_BIG_ENDIAN);
            rfinfo_contextp_tree = proto_item_add_subtree(ti, ett_radiotap_contextp);

            frameformat = tvb_get_guint8(tvb, offset)& 0x03;
            if (frameformat == 0)
            {
                proto_tree_add_item(rfinfo_contextp_tree, hf_radiotap_rfinfo_legacytypeC, tvb, offset, 1, ENC_NA);
            }
            else
            {
                proto_tree_add_item(rfinfo_contextp_tree, hf_radiotap_rfinfo_frameformatC, tvb, offset, 1, ENC_NA);
            }

            proto_tree_add_item(rfinfo_contextp_tree, hf_radiotap_rfinfo_sigbwevmC, tvb, offset, 1, ENC_NA);
            offset      += 2;

            //ContextD
            ti = proto_tree_add_bitmask(vw_rfinfo_tree, tvb, offset, hf_radiotap_rfinfo_contextpd, ett_radiotap_contextp, context_d_flags, ENC_BIG_ENDIAN);
            rfinfo_contextp_tree = proto_item_add_subtree(ti, ett_radiotap_contextp);

            frameformat = tvb_get_guint8(tvb, offset)& 0x03;
            if (frameformat == 0)
            {
                proto_tree_add_item(rfinfo_contextp_tree, hf_radiotap_rfinfo_legacytypeD, tvb, offset, 1, ENC_NA);
            }
            else
            {
                proto_tree_add_item(rfinfo_contextp_tree, hf_radiotap_rfinfo_frameformatD, tvb, offset, 1, ENC_NA);
            }

            proto_tree_add_item(rfinfo_contextp_tree, hf_radiotap_rfinfo_sigbwevmD, tvb, offset, 1, ENC_NA);
            offset += 2;
        }
    }
    if (cmd_type !=3) //only RF
    {
        proto_item_set_len(vw_times_ti, 28);

        /* Grab the rest of the frame. */
        if(!is_octo)
        {
            next_tvb = tvb_new_subset_remaining(tvb, length);
        }
        else
        {
            if (cmd_type ==4) //RF+Rx
                next_tvb = tvb_new_subset_remaining(tvb, 108);
            else
                next_tvb = tvb_new_subset_remaining(tvb, 32);
        }

     /* dissect the ethernet or wlan header next */
     if (ixport_type == ETHERNET_PORT)
        ethernettap_dissect(next_tvb, pinfo, tree, common_tree);
     else
        wlantap_dissect(next_tvb, pinfo, tree, common_tree,vw_msdu_length,
                        cmd_type, log_mode, is_octo);
    }

    return tvb_captured_length(tvb);
}

/*
 * Returns the amount required to align "offset" with "width"
 */
#define ALIGN_OFFSET(offset, width) \
    ( (((offset) + ((width) - 1)) & (~((width) - 1))) - offset )

static void
ethernettap_dissect(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, proto_tree *tap_tree)
{
    proto_tree *vwift,*vw_infoFlags_tree = NULL;
    int         offset = 0;
    tvbuff_t   *next_tvb;
    guint       length, length_remaining;
    gboolean    vwf_txf = FALSE;
    ifg_info   *p_ifg_info;
    proto_item *ti;

    /* First add the IFG information */
    p_ifg_info = (struct ifg_info *) p_get_proto_data(wmem_file_scope(), pinfo, proto_ixveriwave, 0);
    ti = proto_tree_add_uint(tap_tree, hf_ixveriwave_vw_ifg,
                            tvb, offset, 0, p_ifg_info->ifg);
    PROTO_ITEM_SET_GENERATED(ti);

    length = tvb_get_letohs(tvb, offset);
    length_remaining = length;

    offset += 2;
    length_remaining -= 2;

    /* extract flags (currently use only TX/RX and FCS error flag) */
    if (length >= 2) {
        proto_tree_add_item_ret_boolean(tap_tree, hf_ixveriwave_vwf_txf,
                 tvb, offset, 2, ENC_LITTLE_ENDIAN, &vwf_txf);
        proto_tree_add_item(tap_tree, hf_ixveriwave_vwf_fcserr,
                 tvb, offset, 2, ENC_LITTLE_ENDIAN);

        offset += 2;
        length_remaining -= 2;
    }

    /*extract info flags , 2bytes*/

    if (length_remaining >= 2) {
        vwift = proto_tree_add_item(tap_tree, hf_ixveriwave_vw_info, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        vw_infoFlags_tree = proto_item_add_subtree(vwift, ett_ethernettap_info);

        if (vwf_txf == 0) {
            /* then it's an rx case */
            proto_tree_add_item(vw_infoFlags_tree, hf_ixveriwave_vw_info_rx_1_bit8,
                                tvb, offset, 2, ENC_LITTLE_ENDIAN);
            proto_tree_add_item(vw_infoFlags_tree, hf_ixveriwave_vw_info_rx_1_bit9,
                                tvb, offset, 2, ENC_LITTLE_ENDIAN);
        } else {
            /* it's a tx case */
            proto_tree_add_item(vw_infoFlags_tree, hf_ixveriwave_vw_info_retryCount,
                                    tvb, offset, 2, ENC_LITTLE_ENDIAN);
        }

        offset              +=2;
        length_remaining    -=2;
    }

    /*extract error , 4bytes*/
    if (length_remaining >= 4) {
        if (vwf_txf == 0) {
            /* then it's an rx case */
            static const int * vw_error_rx_flags[] = {
                &hf_ixveriwave_vw_error_rx_1_bit0,
                &hf_ixveriwave_vw_error_rx_1_bit1,
                &hf_ixveriwave_vw_error_rx_1_bit2,
                &hf_ixveriwave_vw_error_rx_1_bit3,
                &hf_ixveriwave_vw_error_rx_1_bit4,
                &hf_ixveriwave_vw_error_rx_1_bit5,
                &hf_ixveriwave_vw_error_rx_1_bit6,
                &hf_ixveriwave_vw_error_rx_1_bit7,
                &hf_ixveriwave_vw_error_rx_1_bit8,
                &hf_ixveriwave_vw_error_rx_1_bit9,
                NULL
            };

            proto_tree_add_bitmask(tap_tree, tvb, offset, hf_ixveriwave_vw_error, ett_ethernettap_error, vw_error_rx_flags, ENC_LITTLE_ENDIAN);
        } else {
            /* it's a tx case */
            static const int * vw_error_tx_flags[] = {
                &hf_ixveriwave_vw_error_tx_bit1,
                &hf_ixveriwave_vw_error_tx_bit5,
                &hf_ixveriwave_vw_error_tx_bit9,
                &hf_ixveriwave_vw_error_tx_bit10,
                &hf_ixveriwave_vw_error_tx_bit11,
                NULL
            };

            proto_tree_add_bitmask(tap_tree, tvb, offset, hf_ixveriwave_vw_error, ett_ethernettap_error, vw_error_tx_flags, ENC_LITTLE_ENDIAN);
        }

        offset              +=4;
        length_remaining    -=4;
    }
    /*extract l4id , 4bytes*/
    if (length_remaining >= 4) {
        proto_tree_add_item(tap_tree, hf_ixveriwave_vw_l4id, tvb, offset, 4, ENC_LITTLE_ENDIAN);

        offset              +=4;
        length_remaining    -=4;
    }

    /*extract pad, 4bytes*/
    if (length_remaining >= 4) {
        /* throw away pad */
    }

    /* Grab the rest of the frame. */
    next_tvb = tvb_new_subset_remaining(tvb, length);

    /* dissect the ethernet header next */
    call_dissector(ethernet_handle, next_tvb, pinfo, tree);
}

static void
wlantap_dissect(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
                proto_tree *tap_tree, guint16 vw_msdu_length, guint8 cmd_type,
                int log_mode, gboolean is_octo)
{
    proto_tree *ft, *flags_tree         = NULL;
    int         align_offset, offset;
    tvbuff_t   *next_tvb;
    guint       length;
    gint8       dbm;
    guint8      mcs_index, vw_plcp_info, vw_bssid;
    guint8      plcp_type, vht_u3_coding_type = 0, vht_reserved_coding_type=1;
    guint8      vht_ndp_flag,vht_mu_mimo_flg,vht_coding_type,vht_u0_coding_type,vht_u1_coding_type,vht_u2_coding_type;
    float       phyRate;
    guint       i;

    proto_tree *vweft, *vw_errorFlags_tree = NULL, *vwict,*vw_infoC_tree = NULL;
    guint16     vw_info, vw_chanflags, vw_flags, vw_ht_length,  vht_su_partial_id,vw_rflags,vw_vcid, vw_seqnum, mpdu_length, vht_length, crc16, vht_plcp_length, plcp_service_ofdm;
    guint32     vw_errors;
    guint8      vht_grp_id, vht_grp_id1, vht_grp_id2, vht_su_nsts,vht_beamformed,vht_user_pos,vht_su_partial_id1,vht_su_partial_id2;
    guint32     vht_u0_nsts,vht_u1_nsts,vht_u2_nsts,vht_u3_nsts;
    guint8      vht_bw, vht_stbc, vht_txop_ps_notallowd, vht_shortgi, vht_shortginsymdisa, vht_ldpc_ofdmsymbol, vht_su_mcs, vht_crc1, vht_crc2, vht_crc, vht_tail, rfid;
    guint8      vht_mcs1, vht_mcs2, vht_mcs, vht_plcp_length1, vht_plcp_length2, vht_plcp_length3, vht_rate, vht_parity;
    guint8      feccoding, aggregation, notsounding, smoothing, ness, plcp_service, signal, plcp_default;

    ifg_info   *p_ifg_info;
    proto_item *ti;
    proto_tree 	*vwl1t,*vw_l1info_tree = NULL, *vwl2l4t,*vw_l2l4info_tree = NULL, *vwplt,*vw_plcpinfo_tree = NULL;
    guint8      preamble, nss, direction, sigbw, cidv, bssidv, flowv, l4idv;

    struct ieee_802_11_phdr phdr;

    /* We don't have any 802.11 metadata yet. */
    memset(&phdr, 0, sizeof(phdr));
    phdr.fcs_len = -1;
    phdr.decrypted = FALSE;
    phdr.datapad = FALSE;
    phdr.phy = PHDR_802_11_PHY_UNKNOWN;

    //cmd_type Rx = 0, Tx = 1, RF = 3 , RF_RX = 4
    //log mode = 0 is normal capture and 1 is reduced capture
    //is_octo is FALSE for non-OCTO versions and TRUE for OCTO versions

    if (!is_octo)
    {
        /* Pre-OCTO. */
        /* First add the IFG information, need to grab the info bit field here */
        vw_info = tvb_get_letohs(tvb, 20);
        p_ifg_info = (struct ifg_info *) p_get_proto_data(wmem_file_scope(), pinfo, proto_ixveriwave, 0);
        if ((vw_info & INFO_MPDU_OF_A_MPDU) && !(vw_info & INFO_FIRST_MPDU_OF_A_MPDU))  /* If the packet is part of an A-MPDU but not the first MPDU */
            ti = proto_tree_add_uint(tap_tree, hf_ixveriwave_vw_ifg, tvb, 18, 0, 0);
        else
            ti = proto_tree_add_uint(tap_tree, hf_ixveriwave_vw_ifg, tvb, 18, 0, p_ifg_info->ifg);
        PROTO_ITEM_SET_GENERATED(ti);

        offset      = 0;
        /* header length */
        length = tvb_get_letohs(tvb, offset);
        offset      += 2;

        /* rflags */
        vw_rflags = tvb_get_letohs(tvb, offset);
        phdr.fcs_len = 0;

        ft = proto_tree_add_item(tap_tree, hf_radiotap_flags, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        flags_tree = proto_item_add_subtree(ft, ett_radiotap_flags);
        proto_tree_add_item(flags_tree, hf_radiotap_flags_preamble, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        proto_tree_add_item(flags_tree, hf_radiotap_flags_wep, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        if ( vw_rflags & FLAGS_CHAN_HT ) {
            proto_tree_add_item(flags_tree, hf_radiotap_flags_ht, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            proto_tree_add_item(flags_tree, hf_radiotap_flags_40mhz, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            proto_tree_add_item(flags_tree, hf_radiotap_flags_shortgi, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        }
        if ( vw_rflags & FLAGS_CHAN_VHT ) {
            proto_tree_add_item(flags_tree, hf_radiotap_flags_vht, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            proto_tree_add_item(flags_tree, hf_radiotap_flags_shortgi, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            proto_tree_add_item(flags_tree, hf_radiotap_flags_40mhz, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            proto_tree_add_item(flags_tree, hf_radiotap_flags_80mhz, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        }
        offset      += 2;

        /* channel flags */
        vw_chanflags = tvb_get_letohs(tvb, offset);
        offset      += 2;

        /* PHY rate */
        phyRate = (float)tvb_get_letohs(tvb, offset) / 10;
        offset      += 2;

        /* PLCP type */
        plcp_type = tvb_get_guint8(tvb,offset) & 0x03;
        vht_ndp_flag = tvb_get_guint8(tvb,offset) & 0x80;
        offset++;

        vw_flags = tvb_get_letohs(tvb, 16); /**extract the transmit/rcvd direction flag**/

        /* MCS index */
        mcs_index = tvb_get_guint8(tvb, offset);
        offset++;

        /* number of spatial streams */
        nss = tvb_get_guint8(tvb, offset);
        offset++;

        if ((vw_rflags & FLAGS_CHAN_HT) || (vw_rflags & FLAGS_CHAN_VHT)) {
            if (vw_rflags & FLAGS_CHAN_VHT) {
                phdr.phy = PHDR_802_11_PHY_11AC;
                phdr.phy_info.info_11ac.has_short_gi = TRUE;
                phdr.phy_info.info_11ac.short_gi = ((vw_rflags & FLAGS_CHAN_SHORTGI) != 0);
                /*
                 * XXX - this probably has only one user, so only one MCS index
                 * and only one NSS.
                 */
                phdr.phy_info.info_11ac.nss[0] = nss;
                phdr.phy_info.info_11ac.mcs[0] = mcs_index;
                for (i = 1; i < 4; i++)
                    phdr.phy_info.info_11ac.nss[i] = 0;
            } else {
                /*
                 * XXX - where's the number of extension spatial streams?
                 * The code in wiretap/vwr.c doesn't seem to provide it.
                 */
                phdr.phy = PHDR_802_11_PHY_11N;
                phdr.phy_info.info_11n.has_mcs_index = TRUE;
                phdr.phy_info.info_11n.mcs_index = mcs_index;

                phdr.phy_info.info_11n.has_short_gi = TRUE;
                phdr.phy_info.info_11n.short_gi = ((vw_rflags & FLAGS_CHAN_SHORTGI) != 0);

                phdr.phy_info.info_11n.has_greenfield = TRUE;
                phdr.phy_info.info_11n.greenfield = (plcp_type == PLCP_TYPE_GREENFIELD);
            }

            proto_tree_add_item(tap_tree, hf_radiotap_mcsindex,
                                tvb, offset - 2, 1, ENC_BIG_ENDIAN);

            proto_tree_add_item(tap_tree, hf_radiotap_nss,
                                tvb, offset - 1, 1, ENC_BIG_ENDIAN);

            proto_tree_add_uint_format_value(tap_tree, hf_radiotap_datarate,
                                        tvb, offset - 5, 2, tvb_get_letohs(tvb, offset-5),
                                        "%.1f (MCS %d)", phyRate, mcs_index);
        } else {
            /*
             * XXX - CHAN_OFDM could be 11a or 11g.  Unfortunately, we don't
             * have the frequency, or anything else, to distinguish between
             * them.
             */
            if (vw_chanflags & CHAN_CCK) {
                phdr.phy = PHDR_802_11_PHY_11B;
            }
            phdr.has_data_rate = TRUE;
            phdr.data_rate = tvb_get_letohs(tvb, offset-5) / 5;

            proto_tree_add_uint_format_value(tap_tree, hf_radiotap_datarate,
                tvb, offset - 5, 2, tvb_get_letohs(tvb, offset-5),
                "%.1f Mb/s", phyRate);
        }
        col_add_fstr(pinfo->cinfo, COL_TX_RATE, "%.1f", phyRate);

        /* RSSI/antenna A RSSI */
        dbm = (gint8) tvb_get_guint8(tvb, offset);
        phdr.has_signal_dbm = TRUE;
        phdr.signal_dbm = dbm;
        col_add_fstr(pinfo->cinfo, COL_RSSI, "%d dBm", dbm);

        proto_tree_add_item(tap_tree, hf_radiotap_dbm_anta, tvb, offset, 1, ENC_NA);
        offset++;

        /* Antenna B RSSI, or 100 if absent */
        dbm = (gint8) tvb_get_guint8(tvb, offset);
        if (dbm != 100) {
            proto_tree_add_item(tap_tree, hf_radiotap_dbm_antb, tvb, offset, 1, ENC_NA);
        }
        offset++;
        /* Antenna C RSSI, or 100 if absent */
        dbm = (gint8) tvb_get_guint8(tvb, offset);
        if (dbm != 100) {
            proto_tree_add_item(tap_tree, hf_radiotap_dbm_antc, tvb, offset, 1, ENC_NA);
        }
        offset++;
        /* Antenna D RSSI, or 100 if absent */
        dbm = (gint8) tvb_get_guint8(tvb, offset);
        if (dbm != 100) {
            proto_tree_add_item(tap_tree, hf_radiotap_dbm_antd, tvb, offset, 1, ENC_NA);
        }
        offset+=2;  /* also skips paddng octet */

        /* VeriWave flags */
        vw_flags = tvb_get_letohs(tvb, offset);

        if ((vw_rflags & FLAGS_CHAN_HT) || (vw_rflags & FLAGS_CHAN_VHT)) {
            if (plcp_type == PLCP_TYPE_VHT_MIXED) {
                if (!(vw_flags & VW_RADIOTAPF_TXF) && (vht_ndp_flag == 0x80)) {
                    /*** VHT-NDP rx frame and ndp_flag is set***/
                    proto_tree_add_uint(tap_tree, hf_radiotap_plcptype,
                                                tvb, offset-3, 1, plcp_type);
                } else {
                    /*** VHT-NDP transmitted frame ***/
                    if (vw_msdu_length == 4) { /*** Transmit frame and msdu_length = 4***/
                        proto_tree_add_uint(tap_tree, hf_radiotap_plcptype,
                                         tvb, offset-3, 1, plcp_type);
                    }
                }
            }
        }

        proto_tree_add_item(tap_tree, hf_radiotap_vwf_txf, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        proto_tree_add_item(tap_tree, hf_radiotap_vwf_fcserr, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        proto_tree_add_item(tap_tree, hf_radiotap_vwf_dcrerr, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        proto_tree_add_item(tap_tree, hf_radiotap_vwf_retrerr, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        proto_tree_add_item(tap_tree, hf_radiotap_vwf_enctype, tvb, offset, 2, ENC_LITTLE_ENDIAN);

        offset      += 2;

        /* XXX - this should do nothing */
        align_offset = ALIGN_OFFSET(offset, 2);
        offset += align_offset;

        /* HT length */
        vw_ht_length = tvb_get_letohs(tvb, offset);
        if ((vw_ht_length != 0)) {
            proto_tree_add_uint_format_value(tap_tree, hf_radiotap_vw_ht_length,
                tvb, offset, 2, vw_ht_length, "%u (includes the sum of the pieces of the aggregate and their respective Start_Spacing + Delimiter + MPDU + Padding)",
                vw_ht_length);
        }
        offset      += 2;

        align_offset = ALIGN_OFFSET(offset, 2);
        offset += align_offset;

        /* info */
        if (!(vw_flags & VW_RADIOTAPF_TXF)) {                   /* then it's an rx case */
            /*FPGA_VER_vVW510021 version decodes */
            static const int * vw_info_rx_2_flags[] = {
                &hf_radiotap_vw_info_rx_2_bit8,
                &hf_radiotap_vw_info_rx_2_bit9,
                &hf_radiotap_vw_info_rx_2_bit10,
                &hf_radiotap_vw_info_rx_2_bit11,
                &hf_radiotap_vw_info_rx_2_bit12,
                &hf_radiotap_vw_info_rx_2_bit13,
                &hf_radiotap_vw_info_rx_2_bit14,
                &hf_radiotap_vw_info_rx_2_bit15,
                NULL
            };

            proto_tree_add_bitmask(tap_tree, tvb, offset, hf_radiotap_vw_info, ett_radiotap_info, vw_info_rx_2_flags, ENC_LITTLE_ENDIAN);

        } else {                                    /* it's a tx case */
            static const int * vw_info_tx_2_flags[] = {
                &hf_radiotap_vw_info_tx_2_bit10,
                &hf_radiotap_vw_info_tx_2_bit11,
                &hf_radiotap_vw_info_tx_2_bit12,
                &hf_radiotap_vw_info_tx_2_bit13,
                &hf_radiotap_vw_info_tx_2_bit14,
                &hf_radiotap_vw_info_tx_2_bit15,
                NULL
            };

            /* FPGA_VER_vVW510021 and VW_FPGA_VER_vVW510006 tx info decodes same*/
            proto_tree_add_bitmask(tap_tree, tvb, offset, hf_radiotap_vw_info, ett_radiotap_info, vw_info_tx_2_flags, ENC_LITTLE_ENDIAN);
        }
        offset += 2;

        /* errors */
        vw_errors = tvb_get_letohl(tvb, offset);

        vweft = proto_tree_add_uint(tap_tree, hf_radiotap_vw_errors,
                                    tvb, offset, 4, vw_errors);
        vw_errorFlags_tree = proto_item_add_subtree(vweft, ett_radiotap_errors);

        /* build the individual subtrees for the various types of error flags */
        /* NOTE: as the upper 16 bits aren't used at the moment, we pretend that */
        /* the error flags field is only 16 bits (instead of 32) to save space */
        if (!(vw_flags & VW_RADIOTAPF_TXF)) {
            /* then it's an rx case */

            /*FPGA_VER_vVW510021 version decodes */
            proto_tree_add_item(vw_errorFlags_tree,
                hf_radiotap_vw_errors_rx_2_bit0, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            proto_tree_add_item(vw_errorFlags_tree,
                hf_radiotap_vw_errors_rx_2_bit1, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            proto_tree_add_item(vw_errorFlags_tree,
                hf_radiotap_vw_errors_rx_2_bit2, tvb, offset, 2, ENC_LITTLE_ENDIAN);

            /* veriwave removed 8-2007, don't display reserved bit*/

            proto_tree_add_item(vw_errorFlags_tree,
                hf_radiotap_vw_errors_rx_2_bit4, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            proto_tree_add_item(vw_errorFlags_tree,
                hf_radiotap_vw_errors_rx_2_bit5, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            proto_tree_add_item(vw_errorFlags_tree,
                hf_radiotap_vw_errors_rx_2_bit6, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            proto_tree_add_item(vw_errorFlags_tree,
                hf_radiotap_vw_errors_rx_2_bit7, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            proto_tree_add_item(vw_errorFlags_tree,
                hf_radiotap_vw_errors_rx_2_bit8, tvb, offset, 2, ENC_LITTLE_ENDIAN);

            proto_tree_add_item(vw_errorFlags_tree,
            hf_radiotap_vw_errors_rx_2_bit10, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            proto_tree_add_item(vw_errorFlags_tree,
            hf_radiotap_vw_errors_rx_2_bit11, tvb, offset, 2, ENC_LITTLE_ENDIAN);

        } else {                                  /* it's a tx case */
            /* FPGA_VER_vVW510021 and VW_FPGA_VER_vVW510006 tx error decodes same*/

            proto_tree_add_item(vw_errorFlags_tree,
                                hf_radiotap_vw_errors_tx_bit1, tvb, offset, 2, ENC_LITTLE_ENDIAN);

            proto_tree_add_item(vw_errorFlags_tree,
                                hf_radiotap_vw_errors_tx_bit5, tvb, offset, 2, ENC_LITTLE_ENDIAN);

        }
        offset += 4;

        /*** POPULATE THE AMSDU VHT MIXED MODE CONTAINER FORMAT ***/
        if ((vw_rflags & FLAGS_CHAN_VHT) && vw_ht_length != 0)
        {
            if (plcp_type == 0x03) //If the frame is VHT type
            {
                offset += 4; /*** 4 bytes of ERROR ***/

                /*** Extract SU/MU MIMO flag from RX L1 Info ***/
                vht_user_pos = tvb_get_guint8(tvb, offset);
                vht_mu_mimo_flg = (vht_user_pos & 0x08) >> 3;

                if (vht_mu_mimo_flg == 1) {
                    proto_tree_add_item(tap_tree, hf_radiotap_vht_mu_mimo_flg, tvb, offset, 1, ENC_NA);

                    /*** extract user Position in case of mu-mimo ***/
                    proto_tree_add_item(tap_tree, hf_radiotap_vht_user_pos, tvb, offset, 1, ENC_NA);

                } else {
                    proto_tree_add_item(tap_tree, hf_radiotap_vht_su_mimo_flg, tvb, offset, 1, ENC_NA);
                }
                offset += 1; /*** skip the RX L1 Info byte ****/

                /*
                 * XXX - no, 3 bytes are for the L-SIG.
                 */
                offset += 3; /** 3 bytes are for HT length ***/

                /*
                 * Beginning of VHT-SIG-A1, 24 bits.
                 * XXX - get STBC from the 0x08 bit of the first byte
                 * and BW from the 0x03 bits?
                 */
                /* vht_grp_id = tvb_get_letohs(tvb, offset); */
                vht_grp_id1 = tvb_get_guint8(tvb, offset);
                vht_grp_id2 = tvb_get_guint8(tvb, offset+1);
                vht_grp_id = ((vht_grp_id1 &0xF0) >> 4) + ((vht_grp_id2 &0x03) << 4);
                phdr.phy_info.info_11ac.has_group_id = TRUE;
                phdr.phy_info.info_11ac.group_id = vht_grp_id;
                proto_tree_add_uint(tap_tree, hf_radiotap_vht_grp_id, tvb, offset, 2, vht_grp_id);

                if ((vht_grp_id == 0) || (vht_grp_id == 63)) /*** SU VHT type*/
                {
                    proto_tree_add_item(tap_tree, hf_radiotap_vht_su_nsts, tvb, offset+1, 1, ENC_NA);

                    /* Skip to second byte of VHT-SIG-A1 */
                    offset += 1; /*** to decode partial id ***/
                    vht_su_partial_id1 = tvb_get_guint8(tvb,offset);
                    vht_su_partial_id2 = tvb_get_guint8(tvb,offset+1);
                    vht_su_partial_id = ((vht_su_partial_id1 &0xE0) >> 5) + ((vht_su_partial_id2 &0x3f) << 3);
                    phdr.phy_info.info_11ac.has_partial_aid = TRUE;
                    phdr.phy_info.info_11ac.partial_aid = vht_su_partial_id;
                    proto_tree_add_item(tap_tree, hf_radiotap_vht_su_partial_aid, tvb, offset, 2, ENC_LITTLE_ENDIAN);
                }
                else {
                    /*** The below is MU VHT type**/
                    proto_tree_add_item_ret_uint(tap_tree, hf_radiotap_vht_u0_nsts, tvb, offset, 2, ENC_LITTLE_ENDIAN, &vht_u0_nsts);
                    proto_tree_add_item_ret_uint(tap_tree, hf_radiotap_vht_u1_nsts, tvb, offset, 2, ENC_LITTLE_ENDIAN, &vht_u1_nsts);
                    proto_tree_add_item_ret_uint(tap_tree, hf_radiotap_vht_u2_nsts, tvb, offset, 2, ENC_LITTLE_ENDIAN, &vht_u2_nsts);
                    proto_tree_add_item_ret_uint(tap_tree, hf_radiotap_vht_u3_nsts, tvb, offset, 2, ENC_LITTLE_ENDIAN, &vht_u3_nsts);
                }

                /*
                 * Skip past the other 2 bytes of VHT-SIG-A1.
                 *
                 * XXX - extract TXOP_PS_NOT_ALLOWED from the third byte of
                 * the VHT-SIG-A1 structure?
                 */
                 offset += 2;

                /*
                 * Beginning of VHT-SIG-A2, 24 bits.
                 *
                 * XXX - extract Short GI NSYM Disambiguation from the first
                 * byte?
                 */

                /*** extract LDPC or BCC coding *****/
                vht_coding_type = tvb_get_guint8(tvb, offset);
                vht_u0_coding_type = ((vht_coding_type & 0x04) >> 2);
                /*vht_su_coding_type = vht_u0_coding_type; */
                if ((vht_grp_id == 0) || (vht_grp_id == 63)) /*** SU VHT type*/
                {
                    if (vht_u0_coding_type == 0) {
                        proto_tree_add_uint_format(tap_tree, hf_radiotap_vht_u0_coding_type,
                                tvb, offset, 1, vht_u0_coding_type, "VHT BCC Coding : %u ",vht_u0_coding_type);
                    }
                    else {
                        proto_tree_add_uint_format(tap_tree, hf_radiotap_vht_u0_coding_type,
                                tvb, offset, 1, vht_u0_coding_type, "VHT LDPC Coding : %u ",vht_u0_coding_type);
                    }
                    /*** extract SU-MIMO VHT MCS ******/
                    /*****
                        vht_su_mcs = tvb_get_guint8(tvb, offset);
                        vht_su_mcs = ((vht_su_mcs & 0xF0) >> 4);
                        proto_tree_add_uint_format(tap_tree, hf_radiotap_vht_su_mcs,
                            tvb, offset, 1, vht_su_mcs, "VHT SU MCS : %u ",vht_su_mcs);
                    *******/
                } else {
                    /*** it is MU MIMO type BCC coding ****/
                    /*** extract U0 Coding ***/
                    if (vht_u0_nsts) {
                        if (vht_u0_coding_type == 0) {
                            proto_tree_add_uint_format(tap_tree, hf_radiotap_vht_u0_coding_type,
                            tvb, offset, 1, vht_u0_coding_type, "VHT U0 BCC Coding : %u ",vht_u0_coding_type);
                        } else {
                            proto_tree_add_uint_format(tap_tree, hf_radiotap_vht_u0_coding_type,
                            tvb, offset, 1, vht_u0_coding_type, "VHT U0 LDPC Coding : %u ",vht_u0_coding_type);
                        }
                    } else {
                        /*** reserved **/
                        proto_tree_add_uint_format(tap_tree, hf_radiotap_vht_u0_coding_type,
                        tvb, offset, 1, vht_u0_coding_type, "VHT U0 Reserved Coding : %u ",vht_u0_coding_type);
                    }
                    /*** extract U1 Coding type***/
                    vht_u1_coding_type = ((vht_coding_type & 0x10) >> 4);
                    if (vht_u1_nsts) {
                        if (vht_u1_coding_type == 0) {
                            proto_tree_add_uint_format(tap_tree, hf_radiotap_vht_u1_coding_type,
                                tvb, offset, 1, vht_u1_coding_type, "VHT U1 BCC Coding : %u ",vht_u1_coding_type);
                        } else {
                            proto_tree_add_uint_format(tap_tree, hf_radiotap_vht_u1_coding_type,
                                tvb, offset, 1, vht_u1_coding_type, "VHT U1 LDPC Coding : %u ",vht_u1_coding_type);
                        }
                    } else {
                        /*** Reserved **/
                        proto_tree_add_uint_format(tap_tree, hf_radiotap_vht_u1_coding_type,
                            tvb, offset, 1, vht_u1_coding_type, "VHT U1 Reserved Coding : %u ",vht_u1_coding_type);
                    }

                    /*** extract U2 Coding type***/
                    vht_u2_coding_type = ((vht_coding_type & 0x20) >> 5);
                    if (vht_u2_nsts) {
                        if (vht_u2_coding_type == 0) {
                            proto_tree_add_uint_format(tap_tree, hf_radiotap_vht_u2_coding_type,
                            tvb, offset, 1, vht_u2_coding_type, "VHT U2 BCC Coding : %u ",vht_u2_coding_type);
                        } else {
                            proto_tree_add_uint_format(tap_tree, hf_radiotap_vht_u2_coding_type,
                            tvb, offset, 1, vht_u2_coding_type, "VHT U2 LDPC Coding : %u ",vht_u2_coding_type);
                        }
                    } else {
                        /**** Reserved *******/
                        proto_tree_add_uint_format(tap_tree, hf_radiotap_vht_u2_coding_type,
                        tvb, offset, 1, vht_u2_coding_type, "VHT U2 Reserved Coding : %u ",vht_u2_coding_type);
                    }

                    /*** extract U3 Coding type***/
                    if (vht_u3_nsts == 1) {
                        //guint vht_u3_coding_type;

                        vht_u3_coding_type = ((vht_coding_type & 0x40) >> 6);
                        if (vht_u3_coding_type == 0) {
                            proto_tree_add_uint_format(tap_tree, hf_radiotap_vht_u3_coding_type,
                            tvb, offset, 1, vht_u3_coding_type, "VHT U3 BCC Coding : %u ",vht_u3_coding_type);
                        } else {
                            proto_tree_add_uint_format(tap_tree, hf_radiotap_vht_u3_coding_type,
                            tvb, offset, 1, vht_u3_coding_type, "VHT U3 LDPC Coding : %u ",vht_u3_coding_type);
                        }
                    }
                }

                /*** decode Beamformed bit ****/
                offset += 1;
                vht_beamformed = tvb_get_guint8(tvb, offset) & 0x01;
                phdr.phy_info.info_11ac.has_beamformed = TRUE;
                phdr.phy_info.info_11ac.beamformed = vht_beamformed;
                proto_tree_add_item(tap_tree, hf_radiotap_vht_beamformed, tvb, offset, 1, ENC_NA);
            }
        }
    }
    else {
        /*
         * FPGA version is non-zero, meaning this is OCTO.
         * The first part is a timestamp header.
         */
        //RadioTapHeader New format for L1Info
        offset      = 0;

        length = tvb_get_letohs(tvb, offset);
        offset      += 2;

        if (tvb_get_guint8(tvb, offset+1) & 0x01)
            vwl1t = proto_tree_add_item(tap_tree, hf_radiotap_tx, tvb, offset, 12, ENC_NA);
        else
            vwl1t = proto_tree_add_item(tap_tree, hf_radiotap_rx, tvb, offset, 12, ENC_NA);
        vw_l1info_tree = proto_item_add_subtree(vwl1t, ett_radiotap_layer1);

        preamble = (tvb_get_guint8(tvb, offset) & 0x40) >> 6;
        plcp_type = tvb_get_guint8(tvb, offset+4) & 0x0f;
        if (plcp_type == 3)
            mcs_index = tvb_get_guint8(tvb, offset) & 0x0f;
        else
            mcs_index = tvb_get_guint8(tvb, offset) & 0x3f;

        proto_tree_add_uint(vw_l1info_tree, hf_radiotap_preamble,
            tvb, offset, 1, preamble);
        proto_tree_add_uint(vw_l1info_tree, hf_radiotap_mcsindex,
                tvb, offset, 1, mcs_index);
        offset++;

        nss = (tvb_get_guint8(tvb, offset) & 0xf0) >> 4;
        direction = tvb_get_guint8(tvb, offset) & 0x01;

        if (plcp_type)
            proto_tree_add_uint(vw_l1info_tree, hf_radiotap_nss, tvb, offset, 1, nss);

        proto_tree_add_boolean(vw_l1info_tree, hf_radiotap_vwf_txf, tvb, offset, 1, direction);
        offset++;

        /* New pieces of lines for
         * #802.11 radio information#
         * Referred from code changes done for old FPGA version
         * **/
        phdr.fcs_len = (log_mode == 3) ? 0 : 4;
        switch (plcp_type) //To check 5 types of PLCP(NULL, CCK, OFDM, HT & VHT)
        {
        case 0:
            /*
                * XXX - CHAN_OFDM could be 11a or 11g.  Unfortunately, we don't
                * have the frequency, or anything else, to distinguish between
                * them.
                */
            if (mcs_index < 4)
            {
                phdr.phy = PHDR_802_11_PHY_11B;
            }
            phdr.has_data_rate = TRUE;
            phdr.data_rate = tvb_get_letohs(tvb, offset) / 5;
            break;

        case 1:
        case 2:         /* PLCP_TYPE =2 Greenfeild (Not supported)*/
            /*
                * XXX - where's the number of extension spatial streams?
                * The code in wiretap/vwr.c doesn't seem to provide it.
                */
            phdr.phy = PHDR_802_11_PHY_11N;
            phdr.phy_info.info_11n.has_mcs_index = TRUE;
            phdr.phy_info.info_11n.mcs_index = mcs_index;
            phdr.phy_info.info_11n.has_short_gi = TRUE;
            phdr.phy_info.info_11n.short_gi = preamble;
            phdr.phy_info.info_11n.has_greenfield = TRUE;
            phdr.phy_info.info_11n.greenfield = (plcp_type == PLCP_TYPE_GREENFIELD);
            break;

        case 3:
            phdr.phy = PHDR_802_11_PHY_11AC;
            phdr.phy_info.info_11ac.has_short_gi = TRUE;
            phdr.phy_info.info_11ac.short_gi = preamble;
            /*
                * XXX - this probably has only one user, so only one MCS index
                * and only one NSS.
                */
            phdr.phy_info.info_11ac.nss[0] = nss;
            phdr.phy_info.info_11ac.mcs[0] = mcs_index;
            for (i = 1; i < 4; i++)
                phdr.phy_info.info_11ac.nss[i] = 0;
            break;
        }

        phyRate = (float)tvb_get_letohs(tvb, offset) / 10;
        proto_tree_add_uint_format_value(vw_l1info_tree, hf_radiotap_datarate,
                    tvb, offset, 2, tvb_get_letohs(tvb, offset),
                    "%.1f Mb/s", phyRate);
        offset = offset + 2;
        col_add_fstr(pinfo->cinfo, COL_TX_RATE, "%.1f", phyRate);

        sigbw = (tvb_get_guint8(tvb, offset) & 0xf0) >> 4;
        plcp_type = tvb_get_guint8(tvb, offset) & 0x0f;
        proto_tree_add_uint(vw_l1info_tree,
                hf_radiotap_sigbandwidth, tvb, offset, 1, sigbw);

        if (plcp_type)
            proto_tree_add_uint(vw_l1info_tree,
                hf_radiotap_modulation, tvb, offset, 1, plcp_type);
        else
        {
            if (mcs_index < 4)
                proto_tree_add_uint_format_value(vw_l1info_tree, hf_radiotap_modulation,
                    tvb, offset, 1, plcp_type, "CCK (%u)", plcp_type);
            else
                proto_tree_add_uint_format_value(vw_l1info_tree, hf_radiotap_modulation,
                    tvb, offset, 1, plcp_type, "OFDM (%u)", plcp_type);
        }
        offset++;

        dbm = (gint8) tvb_get_guint8(tvb, offset);

        phdr.has_signal_dbm = TRUE;
        phdr.signal_dbm = dbm;

        col_add_fstr(pinfo->cinfo, COL_RSSI, "%d dBm", dbm);

        if (cmd_type != 1)
            proto_tree_add_item(vwl1t, hf_radiotap_dbm_anta,
                                    tvb, offset, 1, ENC_NA);
        else
            proto_tree_add_item(vwl1t, hf_radiotap_dbm_tx_anta,
                                    tvb, offset, 1, ENC_NA);
        offset++;

        dbm = (gint8) tvb_get_guint8(tvb, offset);
        if (dbm != 100) {
            if (cmd_type != 1)
                proto_tree_add_item(vwl1t, hf_radiotap_dbm_antb,
                                            tvb, offset, 1, ENC_NA);
            else
                proto_tree_add_item(vwl1t,
                                        hf_radiotap_dbm_tx_antb,
                                        tvb, offset, 1, ENC_NA);
        }
        offset++;

        dbm = (gint8) tvb_get_guint8(tvb, offset);
        if (dbm != 100) {
            if (cmd_type != 1)
                proto_tree_add_item(vwl1t, hf_radiotap_dbm_antc,
                                        tvb, offset, 1, ENC_NA);
            else
                proto_tree_add_item(vwl1t, hf_radiotap_dbm_tx_antc,
                                        tvb, offset, 1, ENC_NA);
        }
        offset++;

        dbm = (gint8) tvb_get_guint8(tvb, offset);
        if (dbm != 100) {
            if (cmd_type != 1)
                proto_tree_add_item(vwl1t, hf_radiotap_dbm_antd,
                                        tvb, offset, 1, ENC_NA);
            else
                proto_tree_add_item(vwl1t,
                                        hf_radiotap_dbm_tx_antd,
                                        tvb, offset, 1, ENC_NA);
        }
        offset++;

        proto_tree_add_item(vw_l1info_tree, hf_radiotap_sigbandwidthmask, tvb, offset, 1, ENC_NA);
        offset++;

        if (cmd_type != 1)
        {
            proto_tree_add_item(vw_l1info_tree, hf_radiotap_antennaportenergydetect, tvb, offset, 1, ENC_NA);
        }
        else
        {
            proto_tree_add_item(vw_l1info_tree, hf_radiotap_tx_antennaselect, tvb, offset, 1, ENC_NA);
            proto_tree_add_item(vw_l1info_tree, hf_radiotap_tx_stbcselect, tvb, offset, 1, ENC_NA);
        }
        if (plcp_type == 3)
        {
            proto_tree_add_item(vw_l1info_tree, hf_radiotap_mumask, tvb, offset, 1, ENC_NA);
        }
        offset++;

        if (plcp_type == 3)
        {
            // Extract SU/MU MIMO flag from RX L1 Info
            vht_user_pos = tvb_get_guint8(tvb, offset);

            vwict = proto_tree_add_item(vw_l1info_tree,
                    hf_radiotap_l1infoc, tvb, offset, 1, vht_user_pos);
            vw_infoC_tree = proto_item_add_subtree(vwict, ett_radiotap_infoc);

            vht_ndp_flag = (vht_user_pos & 0x80) >> 7;
            vht_mu_mimo_flg = (vht_user_pos & 0x08) >> 3;
            proto_tree_add_item(vw_infoC_tree, hf_radiotap_vht_ndp_flg, tvb, offset, 1, ENC_NA);
            if (vht_ndp_flag == 0)
            {
                if (vht_mu_mimo_flg == 1) {
                    proto_tree_add_uint(vw_infoC_tree, hf_radiotap_vht_mu_mimo_flg,
                        tvb, offset, 1, vht_mu_mimo_flg);

                    // extract user Postiion in case of mu-mimo
                    proto_tree_add_item(vw_infoC_tree, hf_radiotap_vht_user_pos, tvb, offset, 1, ENC_NA);

                } else {
                    proto_tree_add_item(vw_infoC_tree, hf_radiotap_vht_su_mimo_flg, tvb, offset, 1, ENC_NA);
                }
            }
        }
        offset++;

        mpdu_length = tvb_get_letohs(tvb, offset);
        if (cmd_type != 1) //Checking for Rx and Tx
        {
            proto_tree_add_item(vw_l1info_tree, hf_ixveriwave_frame_length, tvb, offset, 2, mpdu_length);
        }
        offset      += 2;

        //RadioTapHeader New format for PLCP section
        vw_plcp_info = tvb_get_guint8(tvb, offset);

        vwplt = proto_tree_add_item(tap_tree, hf_radiotap_plcp_info, tvb, offset, 16, vw_plcp_info);
        vw_plcpinfo_tree = proto_item_add_subtree(vwplt, ett_radiotap_plcp);

        switch (plcp_type) //To check 5 types of PLCP(NULL, CCK, OFDM, HT & VHT)
        {
        case 0:
            if (mcs_index < 4)
            {
                proto_tree_add_uint_format(vw_plcpinfo_tree, hf_radiotap_plcp_type,
                    tvb, offset-10, 1, plcp_type, "Format: Legacy CCK ");
                signal = tvb_get_guint8(tvb, offset);
                proto_tree_add_uint(vw_plcpinfo_tree, hf_radiotap_plcp_signal,
                                        tvb, offset, 1, signal);
                offset = offset + 1;
                plcp_service = tvb_get_guint8(tvb, offset);
                proto_tree_add_uint(vw_plcpinfo_tree, hf_radiotap_plcp_service,
                                        tvb, offset, 1, plcp_service);
                offset = offset + 1;
                vht_plcp_length = tvb_get_letohs(tvb, offset);
               // proto_tree_add_item(vw_plcpinfo_tree,
                 //    hf_radiotap_vht_length, tvb, offset, 2, vht_length);
                proto_tree_add_uint_format(vw_plcpinfo_tree, hf_radiotap_plcp_length,
                    tvb, offset, 2, vht_plcp_length, "PLCP Length: %u ",vht_plcp_length);
                offset      += 2;
                crc16 = tvb_get_letohs(tvb, offset);
                proto_tree_add_uint_format(vw_plcpinfo_tree, hf_radiotap_crc16,
                    tvb, offset, 2, crc16, "CRC 16: %u ",crc16);
                offset      += 2;
                offset = offset + 9;
                rfid = tvb_get_guint8(tvb, offset);
                proto_tree_add_uint(vw_plcpinfo_tree, hf_radiotap_rfid,
                                        tvb, offset, 1, rfid);
                offset = offset + 1;
            }
            else
            {
                proto_tree_add_uint_format(vw_plcpinfo_tree, hf_radiotap_plcp_default,
                    tvb, offset, 1, plcp_type, "Format: Legacy OFDM ");
                vht_plcp_length1 = tvb_get_guint8(tvb, offset);
                vht_plcp_length2 = tvb_get_guint8(tvb, offset+1);
                vht_plcp_length3 = tvb_get_guint8(tvb, offset+2);
                vht_plcp_length1 = ((vht_plcp_length1 & 0xe0) >> 5);
                vht_plcp_length3 = ((vht_plcp_length3) & 0x01);
                vht_plcp_length = (vht_plcp_length1 + (vht_plcp_length2 << 3) + (vht_plcp_length3 << 11));
                proto_tree_add_uint(vw_plcpinfo_tree, hf_radiotap_plcp_length,
                                        tvb, offset, 3, vht_plcp_length);
                vht_rate = (tvb_get_guint8(tvb, offset) &0x0f);
                proto_tree_add_uint(vw_plcpinfo_tree, hf_radiotap_rate,
                                        tvb, offset, 1, vht_rate);
                vht_parity = (tvb_get_guint8(tvb, offset+2) &0x02)>>1;
                proto_tree_add_uint(vw_plcpinfo_tree, hf_radiotap_parity,
                                        tvb, offset+2, 1, vht_parity);
                offset = offset + 3;
                plcp_service_ofdm = tvb_get_letohs(tvb, offset);
                proto_tree_add_uint(vw_plcpinfo_tree, hf_radiotap_plcp_service,
                                        tvb, offset, 2, plcp_service_ofdm);

                offset = offset + 2;
                offset = offset + 10;
                rfid = tvb_get_guint8(tvb, offset);
                proto_tree_add_uint(vw_plcpinfo_tree, hf_radiotap_rfid,
                                        tvb, offset, 1, rfid);
                offset = offset + 1;

            }
            break;

        case 1:
            proto_tree_add_uint_format(vw_plcpinfo_tree, hf_radiotap_plcp_default,
                tvb, offset, 1, plcp_type, "Format: HT ");
            vht_plcp_length1 = tvb_get_guint8(tvb, offset);
            vht_plcp_length2 = tvb_get_guint8(tvb, offset+1);
            vht_plcp_length3 = tvb_get_guint8(tvb, offset+2);
            vht_plcp_length1 = ((vht_plcp_length1 & 0xe0) >> 5);
            vht_plcp_length3 = ((vht_plcp_length3) & 0x01);
            vht_plcp_length = (vht_plcp_length1 + (vht_plcp_length2 << 3) + (vht_plcp_length3 << 11));
            proto_tree_add_uint(vw_plcpinfo_tree, hf_radiotap_plcp_length,
                                    tvb, offset, 3, vht_plcp_length);
            vht_rate = (tvb_get_guint8(tvb, offset) &0x0f);
            proto_tree_add_uint(vw_plcpinfo_tree, hf_radiotap_rate,
                                    tvb, offset, 1, vht_rate);
            vht_parity = (tvb_get_guint8(tvb, offset+2) &0x02)>>1;
            proto_tree_add_uint(vw_plcpinfo_tree, hf_radiotap_parity,
                                    tvb, offset+2, 1, vht_parity);
            offset = offset + 3;

            vht_bw = tvb_get_guint8(tvb, offset) &0x80 >>7;
            //proto_tree_add_uint(vw_plcpinfo_tree, hf_radiotap_vht_bw,
              //                      tvb, offset, 1, vht_bw);
            proto_tree_add_uint_format(vw_plcpinfo_tree, hf_radiotap_vht_bw,
                tvb, offset, 1, vht_bw, "CBW 20/40: %u ",vht_bw);
            vht_mcs = (tvb_get_guint8(tvb, offset)&0x7f);
            proto_tree_add_uint(vw_plcpinfo_tree, hf_radiotap_vht_mcs,
                                    tvb, offset, 1, vht_mcs);
            offset = offset + 1;
            vht_length = tvb_get_letohs(tvb, offset);
            //proto_tree_add_item(vw_plcpinfo_tree,
              //   hf_radiotap_vht_length, tvb, offset, 2, vht_length);
            proto_tree_add_uint_format(vw_plcpinfo_tree, hf_radiotap_vht_length,
                tvb, offset, 2, vht_length, "HT Length: %u ", vht_length);
            offset      += 2;
            vht_shortgi = (tvb_get_guint8(tvb, offset) &0x80) >> 7;
            proto_tree_add_uint(vw_plcpinfo_tree, hf_radiotap_vht_shortgi,
                                    tvb, offset, 1, vht_shortgi);
            feccoding = (tvb_get_guint8(tvb, offset) &0x40) >> 6;
            proto_tree_add_uint(vw_plcpinfo_tree, hf_radiotap_feccoding,
                                    tvb, offset, 1, feccoding);
            vht_stbc = (tvb_get_guint8(tvb, offset) &0x30) >> 4;
            proto_tree_add_uint(vw_plcpinfo_tree, hf_radiotap_vht_stbc,
                                    tvb, offset, 1, vht_stbc);
            aggregation = (tvb_get_guint8(tvb, offset) &0x08) >> 3;
            proto_tree_add_uint(vw_plcpinfo_tree, hf_radiotap_aggregation,
                                    tvb, offset, 1, aggregation);
            notsounding = (tvb_get_guint8(tvb, offset) &0x02) >> 1;
            proto_tree_add_uint(vw_plcpinfo_tree, hf_radiotap_notsounding,
                                    tvb, offset, 1, notsounding);
            smoothing = (tvb_get_guint8(tvb, offset) &0x01);
            proto_tree_add_uint(vw_plcpinfo_tree, hf_radiotap_smoothing,
                                    tvb, offset, 1, smoothing);
            offset = offset + 1;

            vht_crc1 = tvb_get_guint8(tvb, offset);
            vht_crc2 = tvb_get_guint8(tvb, offset+1);
            vht_crc = ((vht_crc1 &0xFC) >> 2) + ((vht_crc2 &0x03) << 2);
            proto_tree_add_uint(vw_plcpinfo_tree, hf_radiotap_vht_crc,
                                    tvb, offset, 2, vht_crc);
            ness = (tvb_get_guint8(tvb, offset) &0x03);
            proto_tree_add_uint(vw_plcpinfo_tree, hf_radiotap_ness,
                                    tvb, offset, 1, ness);
            offset = offset + 1;
            vht_tail = (tvb_get_guint8(tvb, offset) &0xFC) >> 2;
            //proto_tree_add_uint(vw_plcpinfo_tree, hf_radiotap_vht_tail,
            //                        tvb, offset, 1, vht_tail);
            proto_tree_add_uint_format(vw_plcpinfo_tree, hf_radiotap_vht_tail,
                tvb, offset, 1, vht_tail, "Signal Tail: %u ", vht_tail);
            offset = offset + 1;
            plcp_service_ofdm = tvb_get_letohs(tvb, offset);
            proto_tree_add_uint(vw_plcpinfo_tree, hf_radiotap_plcp_service,
                                    tvb, offset, 2, plcp_service_ofdm);

            offset = offset + 2;
            offset = offset + 4;
            rfid = tvb_get_guint8(tvb, offset);
            proto_tree_add_uint(vw_plcpinfo_tree, hf_radiotap_rfid,
                                    tvb, offset, 1, rfid);
            offset = offset + 1;
            break;

        case 2:
            //PLCP_TYPE =2 Greenfeild (Not supported)
            break;

        case 3:
            proto_tree_add_uint_format(vw_plcpinfo_tree, hf_radiotap_plcp_default,
                tvb, offset, 1, plcp_type, "Format: VHT ");
            vht_plcp_length1 = tvb_get_guint8(tvb, offset);
            vht_plcp_length2 = tvb_get_guint8(tvb, offset+1);
            vht_plcp_length3 = tvb_get_guint8(tvb, offset+2);
            vht_plcp_length1 = ((vht_plcp_length1 & 0xe0) >> 5);
            vht_plcp_length3 = ((vht_plcp_length3) & 0x01);
            vht_plcp_length = (vht_plcp_length1 + (vht_plcp_length2 << 3) + (vht_plcp_length3 << 11));
            proto_tree_add_uint(vw_plcpinfo_tree, hf_radiotap_plcp_length,
                                    tvb, offset, 3, vht_plcp_length);
            vht_rate = (tvb_get_guint8(tvb, offset) &0x0f);
            proto_tree_add_uint(vw_plcpinfo_tree, hf_radiotap_rate,
                                    tvb, offset, 1, vht_rate);
            vht_parity = (tvb_get_guint8(tvb, offset+2) &0x02) >>1;
            proto_tree_add_uint(vw_plcpinfo_tree, hf_radiotap_parity,
                                    tvb, offset+2, 1, vht_parity);
            offset = offset + 3; // 3 bytes are for HT length
            vht_bw = tvb_get_guint8(tvb, offset) &0x03;
            proto_tree_add_uint(vw_plcpinfo_tree, hf_radiotap_vht_bw,
                                    tvb, offset, 1, vht_bw);
            vht_stbc = (tvb_get_guint8(tvb, offset) &0x08) >> 3;
            proto_tree_add_uint(vw_plcpinfo_tree, hf_radiotap_vht_stbc,
                                    tvb, offset, 1, vht_stbc);
            // vht_grp_id = tvb_get_letohs(tvb, offset);
            vht_grp_id1 = tvb_get_guint8(tvb, offset);
            vht_grp_id2 = tvb_get_guint8(tvb, offset+1);
            vht_grp_id = ((vht_grp_id1 &0xF0) >> 4) + ((vht_grp_id2 &0x03) << 4);

            phdr.phy_info.info_11ac.has_group_id = TRUE;
            phdr.phy_info.info_11ac.group_id = vht_grp_id;

            proto_tree_add_uint(vw_plcpinfo_tree, hf_radiotap_vht_grp_id,
                tvb, offset, 2, vht_grp_id);
            offset = offset + 1;
            if ((vht_grp_id == 0) || (vht_grp_id == 63)) // SU VHT type
            {
                vht_su_nsts = tvb_get_guint8(tvb, offset);
                vht_su_nsts = ((vht_su_nsts & 0x1c) >> 2);
                proto_tree_add_uint(vw_plcpinfo_tree, hf_radiotap_vht_su_nsts,
                    tvb, offset, 2, vht_su_nsts);

                vht_su_partial_id1 = tvb_get_guint8(tvb,offset);
                vht_su_partial_id2 = tvb_get_guint8(tvb,offset+1);
                vht_su_partial_id = ((vht_su_partial_id1 &0xE0) >> 5) + ((vht_su_partial_id2 &0x3f) << 3);

                phdr.phy_info.info_11ac.has_partial_aid = TRUE;
                phdr.phy_info.info_11ac.partial_aid = vht_su_partial_id;

                proto_tree_add_uint_format(vw_plcpinfo_tree, hf_radiotap_vht_su_partial_aid,
                    tvb, offset, 2, vht_su_partial_id, "PARTIAL AID: %u ",vht_su_partial_id);
                offset = offset + 1;
            }
            else {
                // The below is MU VHT type*
                vht_u0_nsts = tvb_get_guint8(tvb, offset);
                vht_u0_nsts = ((vht_u0_nsts & 0x1c) >> 2);
                proto_tree_add_uint_format(vw_plcpinfo_tree, hf_radiotap_vht_u0_nsts,
                    tvb, offset, 2, vht_u0_nsts, "MU[0] NSTS: %u ",vht_u0_nsts);

                vht_u1_nsts = tvb_get_guint8(tvb, offset);
                vht_u1_nsts = ((vht_u1_nsts & 0xe0) >> 5);
                proto_tree_add_uint_format(vw_plcpinfo_tree, hf_radiotap_vht_u1_nsts,
                    tvb, offset, 2, vht_u1_nsts, "MU[1] NSTS: %u ",vht_u1_nsts);

                vht_u2_nsts = tvb_get_guint8(tvb, offset+1);
                vht_u2_nsts = (vht_u2_nsts & 0x07);
                proto_tree_add_uint_format(vw_plcpinfo_tree, hf_radiotap_vht_u2_nsts,
                    tvb, offset, 2, vht_u2_nsts, "MU[2] NSTS: %u ",vht_u2_nsts);

                vht_u3_nsts = tvb_get_guint8(tvb, offset+1);
                vht_u3_nsts = ((vht_u3_nsts & 0x38) >> 3);
                proto_tree_add_uint_format(vw_plcpinfo_tree, hf_radiotap_vht_u3_nsts,
                    tvb, offset, 2, vht_u3_nsts, "MU[3] NSTS: %u ",vht_u3_nsts);
                offset = offset + 1;
            }
            // extract LDPC or BCC coding
            vht_txop_ps_notallowd = (tvb_get_guint8(tvb, offset) &0x40) >> 6;
            proto_tree_add_uint(vw_plcpinfo_tree, hf_radiotap_vht_txop_ps_notallowd,
                                    tvb, offset, 1, vht_txop_ps_notallowd);
            offset = offset + 1;

            vht_shortgi = tvb_get_guint8(tvb, offset) &0x01;
            proto_tree_add_uint(vw_plcpinfo_tree, hf_radiotap_vht_shortgi,
                                    tvb, offset, 1, vht_shortgi);
            vht_shortginsymdisa = (tvb_get_guint8(tvb, offset) &0x02) >> 1;
            proto_tree_add_uint(vw_plcpinfo_tree, hf_radiotap_vht_shortginsymdisa,
                                    tvb, offset, 1, vht_shortginsymdisa);
/*
            vht_coding_type = (tvb_get_guint8(tvb, offset)& 0x04) >> 2;
            proto_tree_add_uint_format(vw_plcpinfo_tree, hf_radiotap_vht_u0_coding_type,
                    tvb, offset, 1, vht_coding_type, "SU/MU[0] Coding : %u ",vht_coding_type);
*/
            vht_ldpc_ofdmsymbol = (tvb_get_guint8(tvb, offset) &0x08) >> 3;
            proto_tree_add_uint(vw_plcpinfo_tree, hf_radiotap_vht_ldpc_ofdmsymbol,
                                    tvb, offset, 1, vht_ldpc_ofdmsymbol);
            vht_coding_type = tvb_get_guint8(tvb, offset);

            //vht_su_coding_type = vht_u0_coding_type;
            if ((vht_grp_id == 0) || (vht_grp_id == 63)) // SU VHT type
            {
                vht_coding_type = (tvb_get_guint8(tvb, offset)& 0x04) >> 2;
                proto_tree_add_uint(vw_plcpinfo_tree, hf_radiotap_vht_su_coding_type,
                        tvb, offset, 1, vht_coding_type);
                vht_su_mcs = (tvb_get_guint8(tvb, offset) &0xf0) >> 4;
                proto_tree_add_uint(vw_plcpinfo_tree, hf_radiotap_vht_su_mcs,
                                            tvb, offset, 1, vht_su_mcs);

            } else {
                // it is MU MIMO type BCC coding
                // extract U0 Coding
                vht_u0_coding_type = ((vht_coding_type & 0x04) >> 2);
                proto_tree_add_uint(vw_plcpinfo_tree, hf_radiotap_vht_u0_coding_type,
                       tvb, offset, 1, vht_u0_coding_type);

                // extract U1 Coding type
                vht_u1_coding_type = ((vht_coding_type & 0x10) >> 4);
                proto_tree_add_uint(vw_plcpinfo_tree, hf_radiotap_vht_u1_coding_type,
                       tvb, offset, 1, vht_u1_coding_type);

                // extract U2 Coding type
                vht_u2_coding_type = ((vht_coding_type & 0x20) >> 5);
                proto_tree_add_uint(vw_plcpinfo_tree, hf_radiotap_vht_u2_coding_type,
                       tvb, offset, 1, vht_u2_coding_type);

                // extract U3 Coding type
                // reserved
                proto_tree_add_uint_format(vw_plcpinfo_tree, hf_radiotap_vht_u3_coding_type,
                    tvb, offset, 1, vht_u3_coding_type, "MU[3] Coding Type: Reserved (%u)",vht_reserved_coding_type);

            }

            // decode Beamformed bit
            offset = offset + 1;
            vht_beamformed = tvb_get_guint8(tvb, offset);
            vht_beamformed = (vht_beamformed & 0x01);

            phdr.phy_info.info_11ac.has_beamformed = TRUE;
            phdr.phy_info.info_11ac.beamformed = vht_beamformed;

            proto_tree_add_item(vw_plcpinfo_tree, hf_radiotap_vht_beamformed, tvb, offset, 1, ENC_NA);
            vht_crc1 = tvb_get_guint8(tvb, offset);
            vht_crc2 = tvb_get_guint8(tvb, offset+1);
            vht_crc = ((vht_crc1 &0xFC) >> 2) + ((vht_crc2 &0x03) << 2);
            proto_tree_add_uint(vw_plcpinfo_tree, hf_radiotap_vht_crc,
                                    tvb, offset, 2, vht_crc);
            offset = offset + 1;
            vht_tail = (tvb_get_guint8(tvb, offset) &0xFC) >> 2;
            proto_tree_add_uint(vw_plcpinfo_tree, hf_radiotap_vht_tail,
                                    tvb, offset, 1, vht_tail);
            offset = offset + 1;
            vht_length = tvb_get_letohs(tvb, offset);
            proto_tree_add_item(vw_plcpinfo_tree,
                 hf_radiotap_vht_length, tvb, offset, 2, vht_length);
            offset      += 2;
            vht_mcs1 = tvb_get_guint8(tvb, offset);
            vht_mcs2 = tvb_get_guint8(tvb, offset+1);
            vht_mcs = ((vht_mcs1 &0xC0) >> 6) + ((vht_mcs2 &0x03) << 2);
            proto_tree_add_uint(vw_plcpinfo_tree, hf_radiotap_vht_mcs,
                                    tvb, offset, 2, vht_mcs);
            offset = offset + 2;

            offset = offset + 2;
            rfid = tvb_get_guint8(tvb, offset);
            proto_tree_add_uint(vw_plcpinfo_tree, hf_radiotap_rfid,
                                    tvb, offset, 1, rfid);
            offset = offset + 1;
            break;

        default:
            proto_tree_add_uint_format(vw_plcpinfo_tree, hf_radiotap_plcp_default,
                tvb, offset, 1, plcp_type, "Format: Null ");
            plcp_default = tvb_get_guint8(tvb, offset);
            proto_tree_add_uint_format(vw_plcpinfo_tree, hf_radiotap_plcp_default,
                tvb, offset, 1, plcp_default, "PLCP0: %u ", plcp_default);
            offset = offset + 1;
            plcp_default = tvb_get_guint8(tvb, offset);
            proto_tree_add_uint_format(vw_plcpinfo_tree, hf_radiotap_plcp_default,
                tvb, offset, 1, plcp_default, "PLCP1: %u ", plcp_default);
            offset = offset + 1;
            plcp_default = tvb_get_guint8(tvb, offset);
            proto_tree_add_uint_format(vw_plcpinfo_tree, hf_radiotap_plcp_default,
                tvb, offset, 1, plcp_default, "PLCP2: %u ", plcp_default);
            offset = offset + 1;
            plcp_default = tvb_get_guint8(tvb, offset);
            proto_tree_add_uint_format(vw_plcpinfo_tree, hf_radiotap_plcp_default,
                tvb, offset, 1, plcp_default, "PLCP3: %u ", plcp_default);
            offset = offset + 1;
            plcp_default = tvb_get_guint8(tvb, offset);
            proto_tree_add_uint_format(vw_plcpinfo_tree, hf_radiotap_plcp_default,
                tvb, offset, 1, plcp_default, "PLCP4: %u ", plcp_default);
            offset = offset + 1;
            plcp_default = tvb_get_guint8(tvb, offset);
            proto_tree_add_uint_format(vw_plcpinfo_tree, hf_radiotap_plcp_default,
                tvb, offset, 1, plcp_default, "PLCP5: %u ", plcp_default);
            offset = offset + 1;
            plcp_default = tvb_get_guint8(tvb, offset);
            proto_tree_add_uint_format(vw_plcpinfo_tree, hf_radiotap_plcp_default,
                tvb, offset, 1, plcp_default, "PLCP6: %u ", plcp_default);
            offset = offset + 1;
            plcp_default = tvb_get_guint8(tvb, offset);
            proto_tree_add_uint_format(vw_plcpinfo_tree, hf_radiotap_plcp_default,
                tvb, offset, 1, plcp_default, "PLCP7: %u ", plcp_default);
            offset = offset + 1;
            plcp_default = tvb_get_guint8(tvb, offset);
            proto_tree_add_uint_format(vw_plcpinfo_tree, hf_radiotap_plcp_default,
                tvb, offset, 1, plcp_default, "PLCP8: %u ", plcp_default);
            offset = offset + 1;
            plcp_default = tvb_get_guint8(tvb, offset);
            proto_tree_add_uint_format(vw_plcpinfo_tree, hf_radiotap_plcp_default,
                tvb, offset, 1, plcp_default, "PLCP9: %u ", plcp_default);
            offset = offset + 1;
            plcp_default = tvb_get_guint8(tvb, offset);
            proto_tree_add_uint_format(vw_plcpinfo_tree, hf_radiotap_plcp_default,
                tvb, offset, 1, plcp_default, "PLCP10: %u ", plcp_default);
            offset = offset + 1;
            plcp_default = tvb_get_guint8(tvb, offset);
            proto_tree_add_uint_format(vw_plcpinfo_tree, hf_radiotap_plcp_default,
                tvb, offset, 1, plcp_default, "PLCP11: %u ", plcp_default);
            offset = offset + 1;
            plcp_default = tvb_get_guint8(tvb, offset);
            proto_tree_add_uint_format(vw_plcpinfo_tree, hf_radiotap_plcp_default,
                tvb, offset, 1, plcp_default, "PLCP12: %u ", plcp_default);
            offset = offset + 1;
            plcp_default = tvb_get_guint8(tvb, offset);
            proto_tree_add_uint_format(vw_plcpinfo_tree, hf_radiotap_plcp_default,
                tvb, offset, 1, plcp_default, "PLCP13: %u ", plcp_default);
            offset = offset + 1;
            plcp_default = tvb_get_guint8(tvb, offset);
            proto_tree_add_uint_format(vw_plcpinfo_tree, hf_radiotap_plcp_default,
                tvb, offset, 1, plcp_default, "PLCP14: %u ", plcp_default);
            offset = offset + 1;
            rfid = tvb_get_guint8(tvb, offset);
            proto_tree_add_uint(vw_plcpinfo_tree, hf_radiotap_rfid,
                                    tvb, offset, 1, rfid);
            offset = offset + 1;
        }

        //RadioTapHeader New format for L2-L4_Info
        vwl2l4t = proto_tree_add_item(tap_tree, hf_radiotap_l2_l4_info,
                            tvb, offset, 23, ENC_NA);
        vw_l2l4info_tree = proto_item_add_subtree(vwl2l4t, ett_radiotap_layer2to4);
        cidv = ((tvb_get_guint8(tvb, offset+3)& 0x20) >> 5);
        bssidv = ((tvb_get_guint8(tvb, offset+3)& 0x40) >> 6);
        if (cmd_type != 1)
        {
            vw_vcid = (tvb_get_letohs(tvb, offset)) &0x0fff;
            if (cidv == 1)
            {
                proto_tree_add_uint(vw_l2l4info_tree, hf_ixveriwave_vw_vcid, tvb, offset, 2, vw_vcid);
            }
            else
            {
                proto_tree_add_uint_format_value(vw_l2l4info_tree, hf_ixveriwave_vw_vcid,
                                    tvb, offset, 2, vw_vcid, "Invalid");
            }

            offset++;
            vw_bssid = ((tvb_get_letohs(tvb, offset)) &0x0ff0)>>4;
            if (bssidv == 1)
            {
                proto_tree_add_uint(vw_l2l4info_tree, hf_radiotap_bssid,
                                    tvb, offset, 2, vw_bssid);
            }
            else
            {
                    proto_tree_add_uint_format_value(vw_l2l4info_tree, hf_radiotap_bssid,
                                        tvb, offset, 2, vw_bssid, "Invalid");
            }
            offset +=2;

            proto_tree_add_item(vw_l2l4info_tree, hf_radiotap_clientidvalid, tvb, offset, 1, ENC_NA);
            bssidv = ((tvb_get_guint8(tvb, offset)& 0x40) >> 6);
            proto_tree_add_item(vw_l2l4info_tree, hf_radiotap_bssidvalid, tvb, offset, 1, ENC_NA);
            proto_tree_add_item(vw_l2l4info_tree, hf_radiotap_unicastormulticast, tvb, offset, 1, ENC_NA);
            offset++;
        }
        else
        {
            if (cidv == 1)
            {
                proto_tree_add_item(vw_l2l4info_tree, hf_ixveriwave_vw_vcid,
                                        tvb, offset, 2, ENC_LITTLE_ENDIAN);
            }
            else
            {
                vw_vcid = tvb_get_letohs(tvb, offset);
                proto_tree_add_uint_format_value(vw_l2l4info_tree, hf_ixveriwave_vw_vcid,
                                        tvb, offset, 2, vw_vcid, "Invalid");
            }
            offset +=3;

            proto_tree_add_item(vw_l2l4info_tree, hf_radiotap_clientidvalid, tvb, offset, 1, ENC_NA);
            offset++;
        }
        /*
        wlantype = tvb_get_guint8(tvb, offset)& 0x3f;
        proto_tree_add_uint(vw_l2l4info_tree, hf_radiotap_wlantype,
                                tvb, offset, 1, wlantype);
        */
        proto_tree_add_item(vw_l2l4info_tree, hf_radiotap_tid, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        offset++;
        if (cmd_type == 1)
        {
            proto_tree_add_item(vw_l2l4info_tree, hf_radiotap_ac, tvb, offset, 1, ENC_NA);
        }
        l4idv = (tvb_get_guint8(tvb, offset)& 0x10) >> 4;
        proto_tree_add_item(vw_l2l4info_tree, hf_radiotap_l4idvalid, tvb, offset, 1, ENC_NA);
        proto_tree_add_item(vw_l2l4info_tree, hf_radiotap_containshtfield, tvb, offset, 1, ENC_NA);
        proto_tree_add_item(vw_l2l4info_tree, hf_radiotap_istypeqos, tvb, offset, 1, ENC_NA);
        flowv = (tvb_get_guint8(tvb, offset)& 0x80) >> 7;
        proto_tree_add_item(vw_l2l4info_tree, hf_radiotap_flowvalid, tvb, offset, 1, ENC_NA);
        offset++;

        vw_seqnum = tvb_get_guint8(tvb, offset);
        proto_tree_add_item(vw_l2l4info_tree, hf_ixveriwave_vw_seqnum,
                                tvb, offset, 1, vw_seqnum);
        offset++;
        if (flowv == 1)
        {
            proto_tree_add_item(vw_l2l4info_tree, hf_ixveriwave_vw_flowid,
                        tvb, offset, 3, ENC_LITTLE_ENDIAN);
        }
        else
        {
            proto_tree_add_uint_format_value(vw_l2l4info_tree, hf_ixveriwave_vw_flowid,
                                    tvb, offset, 2, tvb_get_letohl(tvb, offset) & 0xffffff, "Invalid");
        }
        offset +=3;
        if (l4idv == 1)
        {
            proto_tree_add_item(vw_l2l4info_tree, hf_ixveriwave_vw_l4id,
                        tvb, offset, 2, ENC_LITTLE_ENDIAN);
        }
        else
        {
            proto_tree_add_uint_format_value(vw_l2l4info_tree, hf_ixveriwave_vw_l4id,
                            tvb, offset, 2, tvb_get_letohs(tvb, offset), "Invalid");
        }
        offset +=2;
        proto_tree_add_item(vw_l2l4info_tree, hf_radiotap_payloaddecode, tvb, offset, 4, ENC_LITTLE_ENDIAN);
        offset +=4;

        if (cmd_type != 1) {                   /* then it's an rx case */
            /*FPGA_VER_vVW510021 version decodes */
            proto_tree_add_bitmask(vw_l2l4info_tree, tvb, offset, hf_radiotap_vw_info_rx, ett_radiotap_info, radiotap_info_rx_fields, ENC_LITTLE_ENDIAN);

        } else {                                    /* it's a tx case */
            /* FPGA_VER_vVW510021 and VW_FPGA_VER_vVW510006 tx info decodes same*/
            proto_tree_add_bitmask(vw_l2l4info_tree, tvb, offset, hf_radiotap_vw_info_tx, ett_radiotap_info, radiotap_info_tx_fields, ENC_LITTLE_ENDIAN);
        }

        offset      +=3;
        vw_errors = tvb_get_letohl(tvb, offset);

        /* build the individual subtrees for the various types of error flags */
        /* NOTE: as the upper 16 bits aren't used at the moment, we pretend that */
        /* the error flags field is only 16 bits (instead of 32) to save space */
        if (cmd_type != 1) {
            /* then it's an rx case */
            static const int * vw_errors_rx_flags[] = {
                &hf_radiotap_vw_errors_rx_bit0,
                &hf_radiotap_vw_errors_rx_bit1,
                &hf_radiotap_vw_errors_rx_bit2,
                &hf_radiotap_vw_errors_rx_bit3,
                &hf_radiotap_vw_errors_rx_bit4,
                &hf_radiotap_vw_errors_rx_bit5,
                &hf_radiotap_vw_errors_rx_bit6,
                &hf_radiotap_vw_errors_rx_bit7,
                &hf_radiotap_vw_errors_rx_bit8,
                &hf_radiotap_vw_errors_rx_bit9,
                &hf_radiotap_vw_errors_rx_bit10,
                &hf_radiotap_vw_errors_rx_bit11,
                &hf_radiotap_vw_errors_rx_bit12,
                &hf_radiotap_vw_errors_rx_bit14,
                &hf_radiotap_vw_errors_rx_bit15,
                &hf_radiotap_vw_errors_rx_bit16,
                &hf_radiotap_vw_errors_rx_bit17,
                &hf_radiotap_vw_errors_rx_bit18,
                &hf_radiotap_vw_errors_rx_bit19,
                &hf_radiotap_vw_errors_rx_bit20,
                &hf_radiotap_vw_errors_rx_bit21,
                &hf_radiotap_vw_errors_rx_bit22,
                &hf_radiotap_vw_errors_rx_bit23,
                &hf_radiotap_vw_errors_rx_bit24,
                &hf_radiotap_vw_errors_rx_bit31,
                NULL
            };

            proto_tree_add_bitmask(vw_l2l4info_tree, tvb, offset, hf_radiotap_vw_errors, ett_radiotap_errors, vw_errors_rx_flags, ENC_LITTLE_ENDIAN);

        } else {                                  /* it's a tx case */
            static const int * vw_errors_tx_flags[] = {
                &hf_radiotap_vw_errors_tx_bit01,
                &hf_radiotap_vw_errors_tx_bit05,
                &hf_radiotap_vw_errors_tx_bit8,
                &hf_radiotap_vw_errors_tx_bit9,
                &hf_radiotap_vw_errors_tx_bit10,
                &hf_radiotap_vw_errors_tx_bit31,
                NULL
            };

            /* FPGA_VER_vVW510021 and VW_FPGA_VER_vVW510006 tx error decodes same*/
            proto_tree_add_bitmask(vw_l2l4info_tree, tvb, offset, hf_radiotap_vw_errors, ett_radiotap_errors, vw_errors_tx_flags, ENC_LITTLE_ENDIAN);

            // proto_tree_add_item(vw_l2l4info_tree, hf_ixveriwave_vw_seqnum,
            //                       tvb, offset, 1, vw_seqnum);
            //offset++;
            proto_tree_add_item(vw_l2l4info_tree, hf_radiotap_vw_tx_retrycount, tvb, offset+2, 1, ENC_NA);
            proto_tree_add_item(vw_l2l4info_tree, hf_radiotap_vw_tx_factorydebug, tvb, offset+2, 2, ENC_LITTLE_ENDIAN);
        }
        offset      +=4;

        if (vwl2l4t && log_mode)
            proto_item_append_text(vwl2l4t, " (Reduced)");
    }
/*
        align_offset = ALIGN_OFFSET(offset, 2);
        offset += align_offset;

        vw_ht_length = tvb_get_letohs(tvb, offset);
        if ((tree) && (vw_ht_length != 0))
            if (plcp_type == 3)
            {
                proto_tree_add_uint_format(tap_tree, hf_radiotap_vw_ht_length,
                    tvb, offset, 2, vw_ht_length, "VHT length: %u (includes the sum of the pieces of the aggregate and their respective Start_Spacing + Delimiter + MPDU + Padding)",
                    vw_ht_length);
            }
        else
            {
                proto_tree_add_uint_format(tap_tree, hf_radiotap_vw_ht_length,
                    tvb, offset, 2, vw_ht_length, "HT length: %u (includes the sum of the pieces of the aggregate and their respective Start_Spacing + Delimiter + MPDU + Padding)",
                    vw_ht_length);
            }
        offset      +=2;

        align_offset = ALIGN_OFFSET(offset, 2);
        offset += align_offset;*/

        /* vw_info grabbed in the beginning of the dissector */


        /*** POPULATE THE AMSDU VHT MIXED MODE CONTAINER FORMAT ***/
        /****
        if (vw_ht_length != 0)
        ***/
    /***
    else {
        offset = offset + 17;
     }
    ***/

    if (!is_octo)
    {
        /* Grab the rest of the frame. */
        if (plcp_type == 3) {
            length = length + 17; /*** 16 bytes of PLCP + 1 byte of L1InfoC(UserPos) **/
        }

        next_tvb = tvb_new_subset_remaining(tvb, length);
    }
    else
    {
        if (cmd_type != 4)
            proto_item_set_len(tap_tree, length + OCTO_TIMESTAMP_FIELDS_LEN);
        else
            proto_item_set_len(tap_tree, length + OCTO_TIMESTAMP_FIELDS_LEN + OCTO_MODIFIED_RF_LEN);

        /* Grab the rest of the frame. */
        next_tvb = tvb_new_subset_remaining(tvb, length);
    }

    /* dissect the 802.11 radio informaton and header next */
    if(!is_octo || mpdu_length != 0)
        call_dissector_with_data(ieee80211_radio_handle, next_tvb, pinfo, tree, &phdr);
}

void proto_register_ixveriwave(void)
{
    /* value_strings for TX/RX and FCS error flags */
    static const true_false_string tfs_tx_rx_type = { "Transmitted", "Received" };
    static const true_false_string tfs_fcserr_type = { "Incorrect", "Correct" };
    static const true_false_string tfs_preamble_type = { "Short", "Long", };

    /* Added value_string for decrypt error flag */
    static const true_false_string tfs_decrypterr_type = { "Decrypt Failed", "Decrypt Succeeded" };

    /* Added value_string for excess retry error flag */
    static const true_false_string tfs_retryerr_type = {"Excess retry abort", "Retry limit not reached" };

    static const true_false_string tfs_legacy_type = {"802.11b LEGACY CCK", "LEGACY OFDM"};

    static const value_string vht_coding_vals[] = {
        { 0, "BCC" },
        { 1, "LDPC" },
        { 0, NULL },
    };


    static const value_string l1_preamble_type[] = {
        { 0, "Short" },
        { 1, "Long" },
        { 0, NULL },
    };

   static const value_string modulation_type[] = {
        { 0, "LEGACY" },
        { 1, "HT" },
        { 2, "HT-Greenfield" },
        { 3, "VHT" },
        { 0, NULL },
    };

    static const value_string sbw_type[] = {
        { 0, "5 MHz" },
        { 1, "10 MHz" },
        { 2, "20 MHz" },
        { 3, "40 MHz" },
        { 4, "80 MHz" },
        { 5, "reserved" },
        { 6, "reserved" },
        { 7, "reserved" },
        { 0, NULL },
    };
#if 0
    static const value_string mcs[] = {
        { 0, "DBPSK" },
        { 1, "DQPSK" },
        { 2, "CCK (4bits)" },
        { 3, "CCK (8bits)" },
        { 4, "BPSK (1/2)" },
        { 5, "BPSK (3/4)" },
        { 6, "QPSK (1/2)" },
        { 7, "QPSK (3/4)" },
        { 8, "16-QAM (1/2)" },
        { 9, "16-QAM (3/4)" },
        { 10, "64-QAM (1/2)" },
        { 11, "64-QAM (3/4)" },
        { 0, NULL },
    };
#endif
    /* Added value_string for encryption type field */
    static const value_string encrypt_type[] = {
    { 0, "No encryption" },
    { 1, "WEP encryption" },
    { 2, "TKIP encryption" },
    { 3, "AES-CCMP encryption" },
    { 0, NULL },
    };

   static const value_string bmbit[] = {
    {0, "Unicast"},
    {1, "Multicast"},
    { 0, NULL },
    };

    static const value_string sbw_evm[] = {
        { 0, "20 MHz" },
        { 1, "40 MHz" },
        { 2, "80 MHz" },
        { 3, "160 MHz" },
        { 0, NULL },
    };
    static const value_string frameformat_type[] = {
        { 0x0, "LEGACY" },
        { 0x1, "HT" },
        { 0x3, "VHT" },
        { 0, NULL },
   };

    static const value_string crypto_TKIP_type[] = {
        { 0x0, "False" },
        { 0x1, "TKIP Encapped" },
        { 0x2, "CCMP Encapped" },
        { 0x3, "BIP Encapped" },
        { 0, NULL },
    };

    static hf_register_info hf[] = {
    { &hf_ixveriwave_frame_length,
        { "Actual frame length", "ixveriwave.frame_length",
        FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL } },

    { &hf_ixveriwave_vw_msdu_length,
        { "MSDU length", "ixveriwave.msdu_length",
        FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL } },

    { &hf_ixveriwave_vw_vcid,
        { "Client ID", "ixveriwave.clientid",
        FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL } },

    { &hf_ixveriwave_vw_flowid,
        { "Flow ID", "ixveriwave.flowid",
        FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL } },

    { &hf_ixveriwave_vw_seqnum,
        { "Sequence number", "ixveriwave.seqnum",
        FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL } },

    { &hf_ixveriwave_vw_mslatency,
        { "Msec latency", "ixveriwave.mslatency",
        FT_FLOAT, 0, NULL, 0x0, NULL, HFILL } },

    { &hf_ixveriwave_vw_latency,
        { "Frame latency", "ixveriwave.latency",
        FT_UINT32, BASE_DEC|BASE_UNIT_STRING, &units_nanoseconds, 0x0, NULL, HFILL } },

    { &hf_ixveriwave_vw_sig_ts,
        { "Frame Signature Timestamp(32 LSBs)", "ixveriwave.sig_ts",
        FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL } },

    { &hf_ixveriwave_vw_delay,
        { "Frame Queue Delay (32 LSBs)", "ixveriwave.delay_ts",
        FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL } },

    { &hf_ixveriwave_vw_startt,
        { "Frame start timestamp", "ixveriwave.startt",
        FT_UINT64, BASE_DEC|BASE_UNIT_STRING, &units_microseconds, 0x0, NULL, HFILL } },

    { &hf_ixveriwave_vw_endt,
        { "Frame end timestamp", "ixveriwave.endt",
        FT_UINT64, BASE_DEC|BASE_UNIT_STRING, &units_microseconds, 0x0, NULL, HFILL } },

    { &hf_ixveriwave_vw_pktdur,
        { "Frame duration", "ixveriwave.pktdur",
        FT_UINT32, BASE_DEC|BASE_UNIT_STRING, &units_nanoseconds, 0x0, NULL, HFILL } },

    { &hf_ixveriwave_vw_ifg,
        { "Inter-frame gap (usecs)", "ixveriwave.ifg",
        FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL } },

    { &hf_ixveriwave_vw_ifg_neg,
        { "Inter-frame gap (usecs)", "ixveriwave.ifg",
        FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL } },

    { &hf_ixveriwave_vwf_txf,
        { "Frame direction", "ixveriwave.vwflags.txframe",
        FT_BOOLEAN, 8, TFS(&tfs_tx_rx_type), ETHERNETTAP_VWF_TXF, NULL, HFILL } },

    { &hf_ixveriwave_vwf_fcserr,
        { "MAC FCS check", "ixveriwave.vwflags.fcserr",
        FT_BOOLEAN, 8, TFS(&tfs_fcserr_type), ETHERNETTAP_VWF_FCSERR, NULL, HFILL } },

    { &hf_ixveriwave_vw_info,
        { "Info field", "ixveriwave.info",
        FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL } },

    { &hf_ixveriwave_vw_info_retryCount,
        { "Retry count", "ixveriwave.info.retry_count",
        FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL } },

/* tx info decodes for VW510024 and 510012 */
/* we don't need to enumerate through these, basically for both,
info is the retry count.  for 510024, the 15th bit indicates if
the frame was impressed on the enet tx media with one or more octets having tx_en
framing signal deasserted.  this is caused by software setting the drain all register bit.
*/
    /* rx info decodes for fpga ver VW510024 */
    /*all are reserved*/

    /* rx info decodes for fpga ver VW510012 */
    { &hf_ixveriwave_vw_info_rx_1_bit8,
        { "Go no flow", "ixveriwave.info.bit8",
        FT_BOOLEAN, 16, NULL, 0x0100, NULL, HFILL } },
    { &hf_ixveriwave_vw_info_rx_1_bit9,
        { "Go with flow", "ixveriwave.info.bit9",
        FT_BOOLEAN, 16, NULL, 0x0200, NULL, HFILL } },

    { &hf_ixveriwave_vw_error,
        { "Errors", "ixveriwave.error",
        FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL } },
    /* tx error decodes for VW510024 and previous versions */

    { &hf_ixveriwave_vw_error_tx_bit1,
        { "Packet FCS error", "ixveriwave.error.bit1",
        FT_BOOLEAN, 12, NULL, 0x0002, NULL, HFILL } },
    { &hf_ixveriwave_vw_error_tx_bit5,
        { "IP checksum error", "ixveriwave.error.bit5",
        FT_BOOLEAN, 12, NULL, 0x0020, NULL, HFILL } },
    /*bit 6 is actually reserved in 500012, but i thought it would be okay to leave it here*/
    { &hf_ixveriwave_vw_error_tx_bit9,
        { "Underflow error", "ixveriwave.error.bit9",
        FT_BOOLEAN, 12, NULL, 0x0200, NULL, HFILL } },
    { &hf_ixveriwave_vw_error_tx_bit10,
        { "Late collision error", "ixveriwave.error.bit10",
        FT_BOOLEAN, 12, NULL, 0x0400, NULL, HFILL } },
    { &hf_ixveriwave_vw_error_tx_bit11,
        { "Excessive collisions error", "ixveriwave.error.bit11",
        FT_BOOLEAN, 12, NULL, 0x0800, NULL, HFILL } },
    /*all other bits are reserved */

    /* rx error decodes for fpga ver VW510012 and VW510024 */
    { &hf_ixveriwave_vw_error_rx_1_bit0,
        { "Alignment error", "ixveriwave.error.bit0",
        FT_BOOLEAN, 12, NULL, 0x0001, "error bit 0", HFILL } },
    { &hf_ixveriwave_vw_error_rx_1_bit1,
        { "Packet FCS error", "ixveriwave.error.bit1",
        FT_BOOLEAN, 12, NULL, 0x0002, NULL, HFILL } },
    { &hf_ixveriwave_vw_error_rx_1_bit2,
        { "Bad magic byte signature.", "ixveriwave.error.bit2",
        FT_BOOLEAN, 12, NULL, 0x0004, NULL, HFILL } },
    { &hf_ixveriwave_vw_error_rx_1_bit3,
        { "Bad payload checksum.", "ixveriwave.error.bit3",
        FT_BOOLEAN, 12, NULL, 0x0008, NULL, HFILL } },
    { &hf_ixveriwave_vw_error_rx_1_bit4,
        { "Frame too long error", "ixveriwave.error.bit4",
        FT_BOOLEAN, 12, NULL, 0x0010, NULL, HFILL } },
    { &hf_ixveriwave_vw_error_rx_1_bit5,
        { "IP checksum error", "ixveriwave.error.bit5",
        FT_BOOLEAN, 12, NULL, 0x0020, NULL, HFILL } },
    { &hf_ixveriwave_vw_error_rx_1_bit6,
        { "TCP/ICMP/IGMP/UDP checksum error", "ixveriwave.error.bit6",
        FT_BOOLEAN, 12, NULL, 0x0040, NULL, HFILL } },
    { &hf_ixveriwave_vw_error_rx_1_bit7,
        { "ID mismatch(for fpga510012)", "ixveriwave.error.bit7",
        FT_BOOLEAN, 12, NULL, 0x0080, NULL, HFILL } },
    { &hf_ixveriwave_vw_error_rx_1_bit8,
        { "Length error", "ixveriwave.error.bit8",
        FT_BOOLEAN, 12, NULL, 0x0100, NULL, HFILL } },
    { &hf_ixveriwave_vw_error_rx_1_bit9,
        { "Underflow", "ixveriwave.error.bit9",
        FT_BOOLEAN, 12, NULL, 0x0200, NULL, HFILL } },
    { &hf_radiotap_vw_errors_tx_bit1,
        { "Packet FCS error", "ixveriwave.errors.bit1",
        FT_BOOLEAN, 16, NULL, 0x0002, NULL, HFILL } },
    { &hf_radiotap_vw_errors_tx_bit5,
        { "IP checksum error", "ixveriwave.errors.bit5",
        FT_BOOLEAN, 16, NULL, 0x0020, NULL, HFILL } },

    /* All other enumerations are reserved.*/

    { &hf_ixveriwave_vw_l4id,
        { "Layer 4 ID", "ixveriwave.layer4id",
        FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL } },

    { &hf_radiotap_datarate,
        { "Data rate", "ixveriwave.datarate",
        FT_UINT32, BASE_DEC, NULL, 0x0,
        "Speed this frame was sent/received at", HFILL } },

    { &hf_radiotap_plcptype,
        { "VHT_NDP", "ixveriwave.vhtmixedmode",
        FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },

    { &hf_radiotap_mcsindex,
        { "MCS index", "ixveriwave.mcs",
        FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },

    { &hf_radiotap_nss,
        { "Number of spatial streams", "ixveriwave.nss",
        FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },

    /* Boolean 'present.flags' flags */
    { &hf_radiotap_flags,
        { "Flags", "ixveriwave.flags",
        FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL } },

    { &hf_radiotap_flags_preamble,
        { "Preamble", "ixveriwave.flags.preamble",
        FT_BOOLEAN, 12, TFS(&tfs_preamble_type),  FLAGS_SHORTPRE,
        "Sent/Received with short preamble", HFILL } },

    { &hf_radiotap_flags_wep,
        { "WEP", "ixveriwave.flags.wep",
        FT_BOOLEAN, 12, NULL, FLAGS_WEP,
        "Sent/Received with WEP encryption", HFILL } },

    { &hf_radiotap_flags_ht,
        { "HT frame", "ixveriwave.flags.ht",
        FT_BOOLEAN, 12, NULL, FLAGS_CHAN_HT, NULL, HFILL } },

    { &hf_radiotap_flags_vht,
        { "VHT frame", "ixveriwave.flags.vht",
        FT_BOOLEAN, 12, NULL, FLAGS_CHAN_VHT, NULL, HFILL } },

    { &hf_radiotap_flags_40mhz,
        { "40 MHz channel bandwidth", "ixveriwave.flags.40mhz",
        FT_BOOLEAN, 12, NULL, FLAGS_CHAN_40MHZ, NULL, HFILL } },

    { &hf_radiotap_flags_80mhz,
        { "80 MHz channel bandwidth", "ixveriwave.flags.80mhz",
        FT_BOOLEAN, 12, NULL, FLAGS_CHAN_80MHZ, NULL, HFILL } },

    { &hf_radiotap_flags_shortgi,
        { "Short guard interval", "ixveriwave.flags.shortgi",
        FT_BOOLEAN, 12, NULL, FLAGS_CHAN_SHORTGI, NULL, HFILL } },

    { &hf_radiotap_dbm_anta,
        { "SSI Signal for Antenna A", "ixveriwave.dbm_anta",
        FT_INT32, BASE_DEC|BASE_UNIT_STRING, &units_dbm, 0x0,
        "RF signal power at the antenna from a fixed, arbitrary value in decibels from one milliwatt", HFILL } },

    { &hf_radiotap_dbm_antb,
        { "SSI Signal for Antenna B", "ixveriwave.dbm_antb",
        FT_INT32, BASE_DEC|BASE_UNIT_STRING, &units_dbm, 0x0,
        "RF signal power at the antenna from a fixed, arbitrary value in decibels from one milliwatt", HFILL } },

    { &hf_radiotap_dbm_antc,
        { "SSI Signal for Antenna C", "ixveriwave.dbm_antc",
        FT_INT32, BASE_DEC|BASE_UNIT_STRING, &units_dbm, 0x0,
        "RF signal power at the antenna from a fixed, arbitrary value in decibels from one milliwatt", HFILL } },

    { &hf_radiotap_dbm_antd,
        { "SSI Signal for Antenna D", "ixveriwave.dbm_antd",
        FT_INT32, BASE_DEC|BASE_UNIT_STRING, &units_dbm, 0x0,
        "RF signal power at the antenna from a fixed, arbitrary value in decibels from one milliwatt", HFILL } },

    { &hf_radiotap_dbm_tx_anta,
        { "TX Power for Antenna A", "ixveriwave.dbm_anta",
        FT_INT32, BASE_DEC|BASE_UNIT_STRING, &units_dbm, 0x0,
        "RF signal power at the antenna from a fixed, arbitrary value in decibels from one milliwatt", HFILL } },

    { &hf_radiotap_dbm_tx_antb,
        { "TX Power for Antenna B", "ixveriwave.dbm_antb",
        FT_INT32, BASE_DEC, NULL, 0x0,
        "RF signal power at the antenna from a fixed, arbitrary value in decibels from one milliwatt", HFILL } },

    { &hf_radiotap_dbm_tx_antc,
        { "TX Power for Antenna C", "ixveriwave.dbm_antc",
        FT_INT32, BASE_DEC, NULL, 0x0,
        "RF signal power at the antenna from a fixed, arbitrary value in decibels from one milliwatt", HFILL } },

    { &hf_radiotap_dbm_tx_antd,
        { "TX Power for Antenna D", "ixveriwave.dbm_antd",
        FT_INT32, BASE_DEC, NULL, 0x0,
        "RF signal power at the antenna from a fixed, arbitrary value in decibels from one milliwatt", HFILL } },

    /* Boolean 'present' flags */
    /* VeriWave-specific flags */
    { &hf_radiotap_vwf_txf,
        { "Frame direction", "ixveriwave.vwflags.txframe",
        FT_BOOLEAN, 16, TFS(&tfs_tx_rx_type), VW_RADIOTAPF_TXF, NULL, HFILL } },

    { &hf_radiotap_vwf_fcserr,
        { "MAC FCS check", "ixveriwave.vwflags.fcserr",
        FT_BOOLEAN, 16, TFS(&tfs_fcserr_type), VW_RADIOTAPF_FCSERR, NULL, HFILL } },

    { &hf_radiotap_vwf_dcrerr,
        { "Decryption error", "ixveriwave.vwflags.decrypterr",
        FT_BOOLEAN, 16, TFS(&tfs_decrypterr_type), VW_RADIOTAPF_DCRERR, NULL, HFILL } },

    { &hf_radiotap_vwf_retrerr,
        { "TX retry limit", "ixveriwave.vwflags.retryerr",
        FT_BOOLEAN, 16, TFS(&tfs_retryerr_type), VW_RADIOTAPF_RETRERR, NULL, HFILL } },

    { &hf_radiotap_vwf_enctype,
        { "Encryption type", "ixveriwave.vwflags.encrypt",
        FT_UINT16, BASE_DEC, VALS(encrypt_type), VW_RADIOTAPF_ENCMSK, NULL, HFILL } },

    /* start VeriWave-specific radiotap header elements 6-2007 */
    { &hf_radiotap_vw_ht_length,
        { "HT length", "ixveriwave.ht_length",
        FT_UINT16, BASE_DEC, NULL, 0x0, "Total IP length (incl all pieces of an aggregate)", HFILL } },

    { &hf_radiotap_vht_grp_id,
        { "Group Id", "ixveriwave.GRPID",
        FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL } },

    { &hf_radiotap_vht_su_nsts,
        { "SU NSTS", "ixveriwave.SU_NSTS",
        FT_UINT16, BASE_DEC, NULL, 0x1c, NULL, HFILL } },

    { &hf_radiotap_vht_su_partial_aid,
        { "SU Partial ID", "ixveriwave.VHT_SU_PARTIAL_AID",
            FT_UINT16, BASE_HEX, NULL, 0x3FE0, NULL, HFILL } },

    { &hf_radiotap_vht_su_coding_type,
        { "SU Coding Type", "ixveriwave.vht_su_coding_type",
        FT_UINT16, BASE_DEC, VALS(vht_coding_vals), 0x0, NULL, HFILL } },

    { &hf_radiotap_vht_u0_nsts,
        { "MU[0] NSTS", "ixveriwave.VHT_U0_NSTS",
        FT_UINT16, BASE_DEC, NULL, 0x001c, NULL, HFILL } },

    { &hf_radiotap_vht_u1_nsts,
        { "MU[1] NSTS", "ixveriwave.VHT_U1_NSTS",
        FT_UINT16, BASE_DEC, NULL, 0x000e, NULL, HFILL } },

    { &hf_radiotap_vht_u2_nsts,
        { "MU[2] NSTS", "ixveriwave.VHT_U2_NSTS",
        FT_UINT16, BASE_DEC, NULL, 0x0700, NULL, HFILL } },

    { &hf_radiotap_vht_u3_nsts,
        { "MU[3] NSTS", "ixveriwave.VHT_U3_NSTS",
        FT_UINT16, BASE_DEC, NULL, 0x3800, NULL, HFILL } },

    { &hf_radiotap_vht_beamformed,
        { "Beamformed", "ixveriwave.BEAMFORMED",
        FT_UINT8, BASE_DEC, NULL, 0x01, NULL, HFILL } },

    { &hf_radiotap_vht_user_pos,
        { "VHT User Pos", "ixveriwave.VHT_user_pos",
         FT_UINT8, BASE_DEC, NULL, 0x03, NULL, HFILL } },

    { &hf_radiotap_vht_ndp_flg,
        { "NDP", "ixveriwave.VHT_ndp_flg",
        FT_UINT8, BASE_HEX, NULL, 0x80, NULL, HFILL } },

    { &hf_radiotap_vht_mu_mimo_flg,
        { "VHT MU MIMO", "ixveriwave.VHT_mu_mimo_flg",
        FT_UINT8, BASE_DEC, NULL, 0x08, NULL, HFILL } },

    { &hf_radiotap_vht_su_mimo_flg,
        { "VHT SU MIMO", "ixveriwave.VHT_su_mimo_flg",
        FT_UINT8, BASE_DEC, NULL, 0x04, NULL, HFILL } },

    { &hf_radiotap_vht_u0_coding_type,
        { "MU[0] Coding Type", "ixveriwave.vht_u0_coding_type",
        FT_UINT16, BASE_DEC, VALS(vht_coding_vals), 0x0, NULL, HFILL } },

    { &hf_radiotap_vht_u1_coding_type,
        { "MU[1] Coding Type", "ixveriwave.vht_u1_coding_type",
        FT_UINT16, BASE_DEC, VALS(vht_coding_vals), 0x0, NULL, HFILL } },

    { &hf_radiotap_vht_u2_coding_type,
        { "MU[2] Coding Type", "ixveriwave.vht_u2_coding_type",
        FT_UINT16, BASE_DEC, VALS(vht_coding_vals), 0x0, NULL, HFILL } },

    { &hf_radiotap_vht_u3_coding_type,
        { "MU[3] Coding Type", "ixveriwave.vht_u3_coding_type",
        FT_UINT16, BASE_DEC, VALS(vht_coding_vals), 0x0, NULL, HFILL } },

    { &hf_radiotap_rf_info,
        { "RF Header", "ixveriwave.RFInfo",
        FT_NONE, BASE_NONE, NULL, 0, NULL, HFILL } },

    { &hf_radiotap_tx,
        { "Layer 1 Header (Direction=Transmit)", "ixveriwave.l1info",
        FT_NONE, BASE_NONE, NULL, 0, NULL, HFILL } },
    { &hf_radiotap_rx,
        { "Layer 1 Header (Direction=Receive)", "ixveriwave.l1info",
        FT_NONE, BASE_NONE, NULL, 0, NULL, HFILL } },

    { &hf_radiotap_modulation,
        { "Modulation", "ixveriwave.Modulation",
        FT_UINT8, BASE_DEC, VALS(modulation_type), 0x0, NULL, HFILL } },

    { &hf_radiotap_preamble,
        { "Preamble", "ixveriwave.preamble",
        FT_UINT8, BASE_DEC, VALS(l1_preamble_type), 0x0, NULL, HFILL } },

    { &hf_radiotap_sigbandwidth,
        { "Signaling Band Width", "ixveriwave.sigbandwidth",
        FT_UINT8, BASE_DEC, VALS(sbw_type), 0x0, NULL, HFILL } },
#if 0
    {&hf_radiotap_rssi,
        { "RSSI", "ixveriwave.rssi",
        FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL } },
#endif
    {&hf_radiotap_l1infoc,
        {"L1InfoC", "ixveriwave.l1InfoC",
            FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },

    { &hf_radiotap_sigbandwidthmask,
        { "Signaling Band Width Mask", "ixveriwave.sigbandwidthmask",
        FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL } },

    { &hf_radiotap_antennaportenergydetect,
        { "Antenna Port Energy Detect", "ixveriwave.antennaportenergydetect",
        FT_UINT8, BASE_HEX, NULL, 0x0F, NULL, HFILL } },

    { &hf_radiotap_mumask,
        { "MU_MASK", "ixveriwave.mumask",
        FT_UINT8, BASE_HEX, NULL, 0xF0, NULL, HFILL } },

    { &hf_radiotap_plcp_info,
        {"PLCP Header", "ixveriwave.plcp_info",
            FT_NONE, BASE_NONE, NULL, 0, NULL, HFILL } },
    { &hf_radiotap_l2_l4_info,
        {"Layer 2-4 Header", "ixveriwave.l2_l4info",
            FT_NONE, BASE_NONE, NULL, 0, NULL, HFILL } },
    { &hf_radiotap_bssid,
        {"BSS ID", "ixveriwave.bssid",
            FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },

    { &hf_radiotap_unicastormulticast,
        { "Unicast/Multicast", "ixveriwave.unicastormulticast",
        FT_UINT8, BASE_DEC, VALS(bmbit), 0x80, NULL, HFILL } },

    { &hf_radiotap_clientidvalid,
        { "Client Id Valid", "ixveriwave.clientidvalid",
        FT_BOOLEAN, 8, TFS(&tfs_yes_no), 0x20, NULL, HFILL } },

    { &hf_radiotap_bssidvalid,
        { "BSS ID Valid", "ixveriwave.bssidvalid",
        FT_BOOLEAN, 8, TFS(&tfs_yes_no), 0x40, NULL, HFILL } },

    { &hf_radiotap_flowvalid,
        { "Flow Id Valid", "ixveriwave.flowvalid",
        FT_BOOLEAN, 8, TFS(&tfs_yes_no), 0x80, NULL, HFILL } },

    { &hf_radiotap_l4idvalid,
        { "Layer 4 Id Valid", "ixveriwave.l4idvalid",
        FT_BOOLEAN, 8, TFS(&tfs_yes_no), 0x10, NULL, HFILL } },

    { &hf_radiotap_istypeqos,
        { "Is Type QOS", "ixveriwave.istypeqos",
        FT_BOOLEAN, 8, TFS(&tfs_yes_no), 0x40, NULL, HFILL } },

    { &hf_radiotap_containshtfield,
        { "Contains HT Field", "ixveriwave.containshtfield",
        FT_BOOLEAN, 8, TFS(&tfs_yes_no), 0x20, NULL, HFILL } },

    { &hf_radiotap_tid,
        { "TID", "ixveriwave.tid",
        FT_UINT16, BASE_HEX, NULL, 0x01c0, NULL, HFILL } },
#if 0
    { &hf_radiotap_wlantype,
        { "WLAN Type", "ixveriwave.wlantype",
        FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },
#endif
    { &hf_radiotap_payloaddecode,
        { "Payload Decode", "ixveriwave.payloaddecode",
        FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL } },

    { &hf_radiotap_vht_bw,
        { "BW", "ixveriwave.bw",
        FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL } },

    { &hf_radiotap_vht_stbc,
        { "STBC", "ixveriwave.stbc",
        FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },

    { &hf_radiotap_vht_txop_ps_notallowd,
        { "TXOP_PS_NOT_ALLOWD", "ixveriwave.txop_ps_notallowd",
        FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },

    { &hf_radiotap_vht_shortgi,
        { "Short GI", "ixveriwave.shortgi",
        FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },

    { &hf_radiotap_vht_shortginsymdisa,
        { "Short GI NSYM DISA", "ixveriwave.shortginsymdisa",
        FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },

    { &hf_radiotap_vht_ldpc_ofdmsymbol,
        { "LDPC Extra OFDM Symbol", "ixveriwave.ldpc_ofdmsymbol",
        FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },

    { &hf_radiotap_vht_su_mcs,
        { "SU VHT-MCS", "ixveriwave.su_mcs",
        FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL } },

    { &hf_radiotap_vht_crc,
        { "CRC8", "ixveriwave.crc",
        FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL } },

    { &hf_radiotap_vht_tail,
        { "Tail", "ixveriwave.tail",
        FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL } },

    { &hf_radiotap_vht_length,
        { "VHT Length", "ixveriwave.vht.length",
        FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL } },

    { &hf_radiotap_rfid,
        { "RFID", "ixveriwave.rfid",
        FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL } },

    { &hf_radiotap_vht_mcs,
        { "VHT MCS", "ixveriwave.vhtmcs",
        FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL } },

    { &hf_radiotap_parity,
        { "Parity", "ixveriwave.parity",
        FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },

    { &hf_radiotap_rate,
        { "Rate", "ixveriwave.rate",
        FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL } },

    { &hf_radiotap_plcp_length,
        { "PLCP Length", "ixveriwave.length",
        FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },
    { &hf_radiotap_feccoding,
        { "FEC Coding", "ixveriwave.feccoding",
        FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },
    { &hf_radiotap_aggregation,
        { "Aggregation", "ixveriwave.aggregation",
        FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },
    { &hf_radiotap_notsounding,
        { "Not Sounding", "ixveriwave.notsounding",
        FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },
    { &hf_radiotap_smoothing,
        { "Smoothing", "ixveriwave.smoothing",
        FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },
    { &hf_radiotap_ness,
        { "NUMBER of Extension Spatial Streams", "ixveriwave.ness",
        FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },
    { &hf_radiotap_plcp_service,
        { "Service", "ixveriwave.plcp.service",
        FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL } },
    { &hf_radiotap_plcp_signal,
        { "Signal", "ixveriwave.plcp.signal",
        FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL } },
    { &hf_radiotap_plcp_default,
        { "PLCP", "ixveriwave.plcp",
        FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL } },
    { &hf_radiotap_tx_antennaselect,
        { "Antenna Select", "ixveriwave.tx.antennaselect",
        FT_UINT8, BASE_HEX, NULL, 0x07, NULL, HFILL } },
    { &hf_radiotap_tx_stbcselect,
        { "STBC Select", "ixveriwave.tx.stbcselect",
        FT_UINT8, BASE_HEX, NULL, 0x18, NULL, HFILL } },
    { &hf_radiotap_ac,
        { "AC", "ixveriwave.tx.ac",
        FT_UINT8, BASE_HEX, NULL, 0x0e, NULL, HFILL } },
    { &hf_radiotap_crc16,
        { "CRC16", "ixveriwave.crc16",
        FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL } },
    { &hf_radiotap_plcp_type,
        { "PLCP_TYPE", "ixveriwave.plcp.type",
        FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },

    // RF LOGGING
#if 0
    { &hf_radiotap_rfinfo_noise,
        { "Noise", "ixveriwave.rfinfo.noise",
        FT_FLOAT, 0, NULL, 0x0, NULL, HFILL } },
    { &hf_radiotap_rfinfo_noise_anta,
        { "Noise Antenna A", "ixveriwave.noise_anta",
        FT_INT16, BASE_DEC, NULL, 0x0, NULL, HFILL } },
    { &hf_radiotap_rfinfo_noise_antb,
        { "Noise Antenna B", "ixveriwave.noise_antb",
        FT_INT16, BASE_DEC, NULL, 0x0, NULL, HFILL } },
    { &hf_radiotap_rfinfo_noise_antc,
        { "Noise Antenna C", "ixveriwave.noise_antc",
        FT_INT16, BASE_DEC, NULL, 0x0, NULL, HFILL } },
    { &hf_radiotap_rfinfo_noise_antd,
        { "Noise Antenna D", "ixveriwave.noise_antd",
        FT_INT16, BASE_DEC, NULL, 0x0, NULL, HFILL } },
#endif
    { &hf_radiotap_rfinfo_snr,
        { "SNR", "ixveriwave.snr",
        FT_NONE, BASE_NONE, NULL, 0x0, "Signal-to-noise ratio", HFILL } },
    { &hf_radiotap_rfinfo_snr_anta,
        { "SNR Antenna A", "ixveriwave.snr_anta",
        FT_FLOAT, BASE_NONE|BASE_UNIT_STRING, &units_decibels, 0x0, "Signal-to-noise ratio", HFILL } },
    { &hf_radiotap_rfinfo_snr_antb,
        { "SNR Antenna B", "ixveriwave.snr_antb",
        FT_FLOAT, BASE_NONE|BASE_UNIT_STRING, &units_decibels, 0x0, "Signal-to-noise ratio", HFILL } },
    { &hf_radiotap_rfinfo_snr_antc,
        { "SNR Antenna C", "ixveriwave.snr_antc",
        FT_FLOAT, BASE_NONE|BASE_UNIT_STRING, &units_decibels, 0x0, "Signal-to-noise ratio", HFILL } },
    { &hf_radiotap_rfinfo_snr_antd,
        { "SNR Antenna D", "ixveriwave.snr_antd",
        FT_FLOAT, BASE_NONE|BASE_UNIT_STRING, &units_decibels, 0x0, "Signal-to-noise ratio", HFILL } },

    { &hf_radiotap_rfinfo_pfe,
        { "PFE", "ixveriwave.rfinfo.pfe",
        FT_NONE, BASE_NONE, NULL, 0x0, "Preamble Frequency Error metric", HFILL } },
    { &hf_radiotap_rfinfo_pfe_anta,
        { "PFE SS#1", "ixveriwave.pfe_anta",
        FT_FLOAT, BASE_NONE|BASE_UNIT_STRING, &units_hz, 0x0, "Preamble Frequency Error metric", HFILL } },
    { &hf_radiotap_rfinfo_pfe_antb,
        { "PFE SS#2", "ixveriwave.pfe_antb",
        FT_FLOAT, BASE_NONE|BASE_UNIT_STRING, &units_hz, 0x0, "Preamble Frequency Error metric", HFILL } },
    { &hf_radiotap_rfinfo_pfe_antc,
        { "PFE SS#3", "ixveriwave.pfe_antc",
        FT_FLOAT, BASE_NONE|BASE_UNIT_STRING, &units_hz, 0x0, "Preamble Frequency Error metric", HFILL } },
    { &hf_radiotap_rfinfo_pfe_antd,
        { "PFE SS#4", "ixveriwave.pfe_antd",
        FT_FLOAT, BASE_NONE|BASE_UNIT_STRING, &units_hz, 0x0, "Preamble Frequency Error metric", HFILL } },

    { &hf_radiotap_rfinfo_contextpa,
        { "CONTEXT_A", "ixveriwave.contextpa",
        FT_UINT16, BASE_HEX, NULL, 0, NULL, HFILL } },
    { &hf_radiotap_rfinfo_contextpb,
        { "CONTEXT_B", "ixveriwave.contextpb",
        FT_UINT16, BASE_HEX, NULL, 0, NULL, HFILL } },
    { &hf_radiotap_rfinfo_contextpc,
        { "CONTEXT_C", "ixveriwave.contextpc",
        FT_UINT16, BASE_HEX, NULL, 0, NULL, HFILL } },
    { &hf_radiotap_rfinfo_contextpd,
        { "CONTEXT_D", "ixveriwave.contextpd",
        FT_UINT16, BASE_HEX, NULL, 0, NULL, HFILL } },
    { &hf_radiotap_rfinfo_contextpA_bit0,
        { "SNR_NOISE_valid", "ixveriwave.contextpA.bit0",
        FT_BOOLEAN, 16, NULL, 0x0001, NULL, HFILL } },
    { &hf_radiotap_rfinfo_contextpA_bit1,
        { "PFE_valid", "ixveriwave.contextpA.bit1",
        FT_BOOLEAN, 16, NULL, 0x0002, NULL, HFILL } },
    { &hf_radiotap_rfinfo_contextpA_bit2,
        { "PFE_is_CCK", "ixveriwave.contextpA.bit2",
        FT_BOOLEAN, 16, NULL, 0x0004, NULL, HFILL } },
#if 0
    { &hf_radiotap_rfinfo_contextp_bits3,
        { "AGC", "ixveriwave.contextp.bits3",
        FT_BOOLEAN, 16, NULL, 0x0038, "Automatic Gain Control", HFILL } },
#endif
    { &hf_radiotap_rfinfo_contextpA_bit3,
        { "AGC 3", "ixveriwave.contextpA.bit3",
        FT_BOOLEAN, 16, NULL, 0x0008, "Automatic Gain Control-[3] agc_idle2iqrdy_no_gain_change", HFILL } },
    { &hf_radiotap_rfinfo_contextpA_bit4,
        { "AGC 4", "ixveriwave.contextpA.bit4",
        FT_BOOLEAN, 16, NULL, 0x0010, "Automatic Gain Control-[4] agc_high_pwr_terminated", HFILL } },
    { &hf_radiotap_rfinfo_contextpA_bit5,
        { "AGC 5", "ixveriwave.contextpA.bit5",
        FT_BOOLEAN, 16, NULL, 0x0020, "Automatic Gain Control-[5] agc_high_pwr_terminator", HFILL } },
#if 0
    { &hf_radiotap_rfinfo_contextpA_bit8,
        { "Frame format", "ixveriwave.contextp.bits8",
        FT_UINT16, BASE_DEC, VALS(frameformat_type), 0x0300, "0: LEGACY.   1:HT.   3:-VHT.", HFILL } },
    { &hf_radiotap_rfinfo_contextpA_bit10,
        { "OFDM or CCK", "ixveriwave.contextp.bit10",
        FT_BOOLEAN, 16, TFS(&tfs_legacy_type), 0x0400, "0: LEGACY OFDM      1: 802.11b LEGACY CCK", HFILL } },
    { &hf_radiotap_rfinfo_contextpA_bit11,
        { "SigBandWidth of EVM", "ixveriwave.contextp.bits11",
        FT_UINT16, BASE_DEC, VALS(sbw_evm), 0x1800, "Signal Bandwidth of EVM measurement", HFILL } },
#endif
    { &hf_radiotap_rfinfo_contextpA_bit13,
        { "QAM modulation", "ixveriwave.contextpA.bits13",
        FT_BOOLEAN, 16, NULL, 0xe000, NULL, HFILL } },

    { &hf_radiotap_rfinfo_contextpB_bit0,
        { "SNR_NOISE_valid", "ixveriwave.contextpB.bit0",
        FT_BOOLEAN, 16, NULL, 0x0001, NULL, HFILL } },
    { &hf_radiotap_rfinfo_contextpB_bit1,
        { "PFE_valid", "ixveriwave.contextpB.bit1",
        FT_BOOLEAN, 16, NULL, 0x0002, NULL, HFILL } },
    { &hf_radiotap_rfinfo_contextpB_bit2,
        { "PFE_is_CCK", "ixveriwave.contextpB.bit2",
        FT_BOOLEAN, 16, NULL, 0x0004, NULL, HFILL } },
    { &hf_radiotap_rfinfo_contextpB_bit3,
        { "AGC 3", "ixveriwave.contextpB.bit3",
        FT_BOOLEAN, 16, NULL, 0x0008, "Automatic Gain Control-[3] agc_idle2iqrdy_no_gain_change", HFILL } },
    { &hf_radiotap_rfinfo_contextpB_bit4,
        { "AGC 4", "ixveriwave.contextpB.bit4",
        FT_BOOLEAN, 16, NULL, 0x0010, "Automatic Gain Control-[4] agc_high_pwr_terminated", HFILL } },
    { &hf_radiotap_rfinfo_contextpB_bit5,
        { "AGC 5", "ixveriwave.contextpB.bit5",
        FT_BOOLEAN, 16, NULL, 0x0020, "Automatic Gain Control-[5] agc_high_pwr_terminator", HFILL } },
    { &hf_radiotap_rfinfo_contextpB_bit13,
        { "QAM modulation", "ixveriwave.contextpB.bits13",
        FT_BOOLEAN, 16, NULL, 0xe000, NULL, HFILL } },

    { &hf_radiotap_rfinfo_contextpC_bit0,
        { "SNR_NOISE_valid", "ixveriwave.contextpC.bit0",
        FT_BOOLEAN, 16, NULL, 0x0001, NULL, HFILL } },
    { &hf_radiotap_rfinfo_contextpC_bit1,
        { "PFE_valid", "ixveriwave.contextpC.bit1",
        FT_BOOLEAN, 16, NULL, 0x0002, NULL, HFILL } },
    { &hf_radiotap_rfinfo_contextpC_bit2,
        { "PFE_is_CCK", "ixveriwave.contextpC.bit2",
        FT_BOOLEAN, 16, NULL, 0x0004, NULL, HFILL } },
    { &hf_radiotap_rfinfo_contextpC_bit3,
        { "AGC 3", "ixveriwave.contextpC.bit3",
        FT_BOOLEAN, 16, NULL, 0x0008, "Automatic Gain Control-[3] agc_idle2iqrdy_no_gain_change", HFILL } },
    { &hf_radiotap_rfinfo_contextpC_bit4,
        { "AGC 4", "ixveriwave.contextpC.bit4",
        FT_BOOLEAN, 16, NULL, 0x0010, "Automatic Gain Control-[4] agc_high_pwr_terminated", HFILL } },
    { &hf_radiotap_rfinfo_contextpC_bit5,
        { "AGC 5", "ixveriwave.contextpC.bit5",
        FT_BOOLEAN, 16, NULL, 0x0020, "Automatic Gain Control-[5] agc_high_pwr_terminator", HFILL } },
    { &hf_radiotap_rfinfo_contextpC_bit13,
        { "QAM modulation", "ixveriwave.contextpC.bits13",
        FT_BOOLEAN, 16, NULL, 0xe000, NULL, HFILL } },

    { &hf_radiotap_rfinfo_contextpD_bit0,
        { "SNR_NOISE_valid", "ixveriwave.contextpD.bit0",
        FT_BOOLEAN, 16, NULL, 0x0001, NULL, HFILL } },
    { &hf_radiotap_rfinfo_contextpD_bit1,
        { "PFE_valid", "ixveriwave.contextpD.bit1",
        FT_BOOLEAN, 16, NULL, 0x0002, NULL, HFILL } },
    { &hf_radiotap_rfinfo_contextpD_bit2,
        { "PFE_is_CCK", "ixveriwave.contextpD.bit2",
        FT_BOOLEAN, 16, NULL, 0x0004, NULL, HFILL } },
    { &hf_radiotap_rfinfo_contextpD_bit3,
        { "AGC 3", "ixveriwave.contextpD.bit3",
        FT_BOOLEAN, 16, NULL, 0x0008, "Automatic Gain Control-[3] agc_idle2iqrdy_no_gain_change", HFILL } },
    { &hf_radiotap_rfinfo_contextpD_bit4,
        { "AGC 4", "ixveriwave.contextpD.bit4",
        FT_BOOLEAN, 16, NULL, 0x0010, "Automatic Gain Control-[4] agc_high_pwr_terminated", HFILL } },
    { &hf_radiotap_rfinfo_contextpD_bit5,
        { "AGC 5", "ixveriwave.contextpD.bit5",
        FT_BOOLEAN, 16, NULL, 0x0020, "Automatic Gain Control-[5] agc_high_pwr_terminator", HFILL } },
    { &hf_radiotap_rfinfo_contextpD_bit13,
        { "QAM modulation", "ixveriwave.contextpD.bits13",
        FT_BOOLEAN, 16, NULL, 0xe000, NULL, HFILL } },

    { &hf_radiotap_rfinfo_frameformatA,
        { "Frame format", "ixveriwave.rfinfo.frameformatA",
        FT_UINT8, BASE_DEC, VALS(frameformat_type), 0x03, NULL, HFILL } },
    { &hf_radiotap_rfinfo_frameformatB,
        { "Frame format", "ixveriwave.rfinfo.frameformatB",
        FT_UINT8, BASE_DEC, VALS(frameformat_type), 0x03, NULL, HFILL } },
    { &hf_radiotap_rfinfo_frameformatC,
        { "Frame format", "ixveriwave.rfinfo.frameformatC",
        FT_UINT8, BASE_DEC, VALS(frameformat_type), 0x03, NULL, HFILL } },
    { &hf_radiotap_rfinfo_frameformatD,
        { "Frame format", "ixveriwave.rfinfo.frameformatD",
        FT_UINT8, BASE_DEC, VALS(frameformat_type), 0x03, NULL, HFILL } },
    { &hf_radiotap_rfinfo_legacytypeA,
        { "Frame format", "ixveriwave.rfinfo.legacytypeA",
        FT_BOOLEAN, 8, TFS(&tfs_legacy_type), 0x04, NULL, HFILL } },
    { &hf_radiotap_rfinfo_legacytypeB,
        { "Frame format", "ixveriwave.rfinfo.legacytypeB",
        FT_BOOLEAN, 8, TFS(&tfs_legacy_type), 0x04, NULL, HFILL } },
    { &hf_radiotap_rfinfo_legacytypeC,
        { "Frame format", "ixveriwave.rfinfo.legacytypeC",
        FT_BOOLEAN, 8, TFS(&tfs_legacy_type), 0x04, NULL, HFILL } },
    { &hf_radiotap_rfinfo_legacytypeD,
        { "Frame format", "ixveriwave.rfinfo.legacytypeD",
        FT_BOOLEAN, 8, TFS(&tfs_legacy_type), 0x04, NULL, HFILL } },
    { &hf_radiotap_rfinfo_sigbwevmA,
        { "SigBandWidth of EVM", "ixveriwave.rfinfo.sigbwevmA",
        FT_UINT8, BASE_DEC, VALS(sbw_evm), 0x18, NULL, HFILL } },
    { &hf_radiotap_rfinfo_sigbwevmB,
        { "SigBandWidth of EVM", "ixveriwave.rfinfo.sigbwevmB",
        FT_UINT8, BASE_DEC, VALS(sbw_evm), 0x18, NULL, HFILL } },
    { &hf_radiotap_rfinfo_sigbwevmC,
        { "SigBandWidth of EVM", "ixveriwave.rfinfo.sigbwevmC",
        FT_UINT8, BASE_DEC, VALS(sbw_evm), 0x18, NULL, HFILL } },
    { &hf_radiotap_rfinfo_sigbwevmD,
        { "SigBandWidth of EVM", "ixveriwave.rfinfo.sigbwevmD",
        FT_UINT8, BASE_DEC, VALS(sbw_evm), 0x18, NULL, HFILL } },

    { &hf_radiotap_rfinfo_sigdata,
        { "AVG EVM SIG Data", "ixveriwave.rfinfo.sigdata",
        FT_NONE, BASE_NONE, NULL, 0x0, "Average EVM for DATA SUBCARRIERS for all SIG symbols of the frame", HFILL } },
    { &hf_radiotap_rfinfo_avg_evm_sd_siga,
        { "AVG EVM SIG Data SS#1", "ixveriwave.avg_evm_sda",
        FT_FLOAT, BASE_NONE, NULL, 0x0, NULL, HFILL } },
    { &hf_radiotap_rfinfo_avg_evm_sd_sigb,
        { "AVG EVM SIG Data SS#2", "ixveriwave.avg_evm_sdb",
        FT_FLOAT, BASE_NONE, NULL, 0x0, NULL, HFILL } },
    { &hf_radiotap_rfinfo_avg_evm_sd_sigc,
        { "AVG EVM SIG Data SS#3", "ixveriwave.avg_evm_sdc",
        FT_FLOAT, BASE_NONE, NULL, 0x0, NULL, HFILL } },
    { &hf_radiotap_rfinfo_avg_evm_sd_sigd,
        { "AVG EVM SIG Data SS#4", "ixveriwave.avg_evm_sdd",
        FT_FLOAT, BASE_NONE, NULL, 0x0, NULL, HFILL } },

    { &hf_radiotap_rfinfo_sigpilot,
        { "AVG EVM SIG Pilot", "ixveriwave.rfinfo.sigpilot",
        FT_NONE, BASE_NONE, NULL, 0x0, "Average EVM for  PILOT SUBCARRIERS for all SIG symbols of the frame", HFILL } },
    { &hf_radiotap_rfinfo_avg_evm_sp_siga,
        { "AVG EVM SIG Pilot SS#1", "ixveriwave.avg_evm_spa",
        FT_FLOAT, BASE_NONE, NULL, 0x0, NULL, HFILL } },
    { &hf_radiotap_rfinfo_avg_evm_sp_sigb,
        { "AVG EVM SIG Pilot SS#2", "ixveriwave.avg_evm_spb",
        FT_FLOAT, BASE_NONE, NULL, 0x0, NULL, HFILL } },
    { &hf_radiotap_rfinfo_avg_evm_sp_sigc,
        { "AVG EVM SIG Pilot SS#3", "ixveriwave.avg_evm_spc",
        FT_FLOAT, BASE_NONE, NULL, 0x0, NULL, HFILL } },
    { &hf_radiotap_rfinfo_avg_evm_sp_sigd,
        { "AVG EVM SIG Pilot SS#4", "ixveriwave.avg_evm_spd",
        FT_FLOAT, BASE_NONE, NULL, 0x0, NULL, HFILL } },

    { &hf_radiotap_rfinfo_datadata,
        { "AVG EVM DATA Data", "ixveriwave.rfinfo.datadata",
        FT_NONE, BASE_NONE, NULL, 0x0, "Average EVM for  DATA SUBCARRIERS for all DATA symbols of the frame", HFILL } },
    { &hf_radiotap_rfinfo_avg_evm_dd_siga,
        { "AVG EVM DATA Data SS#1", "ixveriwave.avg_evm_dda",
        FT_FLOAT, BASE_NONE, NULL, 0x0, NULL, HFILL } },
    { &hf_radiotap_rfinfo_avg_evm_dd_sigb,
        { "AVG EVM DATA Data SS#2", "ixveriwave.avg_evm_ddb",
        FT_FLOAT, BASE_NONE, NULL, 0x0, NULL, HFILL } },
    { &hf_radiotap_rfinfo_avg_evm_dd_sigc,
        { "AVG EVM DATA Data SS#3", "ixveriwave.avg_evm_ddc",
        FT_FLOAT, BASE_NONE, NULL, 0x0, NULL, HFILL } },
    { &hf_radiotap_rfinfo_avg_evm_dd_sigd,
        { "AVG EVM DATA Data SS#4", "ixveriwave.avg_evm_ddd",
        FT_FLOAT, BASE_NONE, NULL, 0x0, NULL, HFILL } },

    { &hf_radiotap_rfinfo_datapilot,
        { "AVG EVM DATA Pilot", "ixveriwave.rfinfo.datapilot",
        FT_NONE, BASE_NONE, NULL, 0x0, "Average EVM for  PILOT SUBCARRIERS for all DATA symbols of the frame", HFILL } },
    { &hf_radiotap_rfinfo_avg_evm_dp_siga,
        { "AVG EVM DATA Pilot SSI-1", "ixveriwave.avg_evm_dpa",
        FT_FLOAT, BASE_NONE, NULL, 0x0, NULL, HFILL } },
    { &hf_radiotap_rfinfo_avg_evm_dp_sigb,
        { "AVG EVM DATA Pilot SSI-2", "ixveriwave.avg_evm_dpb",
        FT_FLOAT, BASE_NONE, NULL, 0x0, NULL, HFILL } },
    { &hf_radiotap_rfinfo_avg_evm_dp_sigc,
        { "AVG EVM DATA Pilot SSI-3", "ixveriwave.avg_evm_dpc",
        FT_FLOAT, BASE_NONE, NULL, 0x0, NULL, HFILL } },
    { &hf_radiotap_rfinfo_avg_evm_dp_sigd,
        { "AVG EVM DATA Pilot SSI-4", "ixveriwave.avg_evm_dpd",
        FT_FLOAT, BASE_NONE, NULL, 0x0, NULL, HFILL } },

    { &hf_radiotap_rfinfo_avg_ws_symbol,
        { "EVM Worst Symbol", "ixveriwave.wssymbol",
        FT_NONE, BASE_NONE, NULL, 0, "WORST-CASE SYMBOL", HFILL } },
    { &hf_radiotap_rfinfo_avg_evm_ws_siga,
        { "EVM Worst Symbol SS#1", "ixveriwave.avg_evm_wsa",
        FT_UINT16, BASE_DEC|BASE_UNIT_STRING, &units_percent, 0, NULL, HFILL } },
    { &hf_radiotap_rfinfo_avg_evm_ws_sigb,
        { "EVM Worst Symbol SS#2", "ixveriwave.avg_evm_wsb",
        FT_UINT16, BASE_DEC|BASE_UNIT_STRING, &units_percent, 0, NULL, HFILL } },
    { &hf_radiotap_rfinfo_avg_evm_ws_sigc,
        { "EVM Worst Symbol SS#3", "ixveriwave.avg_evm_wsc",
        FT_UINT16, BASE_DEC|BASE_UNIT_STRING, &units_percent, 0, NULL, HFILL } },
    { &hf_radiotap_rfinfo_avg_evm_ws_sigd,
        { "EVM Worst Symbol SS#4", "ixveriwave.avg_evm_wsd",
        FT_UINT16, BASE_DEC|BASE_UNIT_STRING, &units_percent, 0, NULL, HFILL } },

    { &hf_radiotap_rfinfo_rfid,
        { "RF_ID", "ixveriwave.rfinfo.rfid",
        FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },
#if 0
    { &hf_radiotap_rfinfo_tbd,
        { "RF_TBD", "ixveriwave.rfinfo.tbd",
        FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL } },
#endif
    { &hf_radiotap_vw_errors,
        { "Errors", "ixveriwave.errors",
        FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL } },

    /* rx error decodes for fpga ver VW510021 */
    { &hf_radiotap_vw_errors_rx_2_bit0,
        { "CRC16 or parity error", "ixveriwave.errors.bit0",
        FT_BOOLEAN, 16, NULL, 0x0001, "error bit 0", HFILL } },

    { &hf_radiotap_vw_errors_rx_2_bit1,
        { "Non-supported rate or service field", "ixveriwave.errors.bit1",
        FT_BOOLEAN, 16, NULL, 0x0002, NULL, HFILL } },

    { &hf_radiotap_vw_errors_rx_2_bit2,
        { "Short frame error.  Frame is shorter than length.", "ixveriwave.errors.bit2",
        FT_BOOLEAN, 16, NULL, 0x0004, NULL, HFILL } },

    { &hf_radiotap_vw_errors_rx_2_bit4,
        { "FCS_Error", "ixveriwave.errors.bit4",
        FT_BOOLEAN, 16, NULL, 0x0010, NULL, HFILL } },

    { &hf_radiotap_vw_errors_rx_2_bit5,
        { "L2 de-aggregation error", "ixveriwave.errors.bit5",
        FT_BOOLEAN, 16, NULL, 0x0020, NULL, HFILL } },

    { &hf_radiotap_vw_errors_rx_2_bit6,
        { "Duplicate MPDU", "ixveriwave.errors.bit6",
        FT_BOOLEAN, 16, NULL, 0x0040, NULL, HFILL } },

    { &hf_radiotap_vw_errors_rx_2_bit7,
        { "Bad_Sig:  Bad flow magic number (includes bad flow crc16)", "ixveriwave.errors.bit7",
        FT_BOOLEAN, 16, NULL, 0x0080, NULL, HFILL } },

    { &hf_radiotap_vw_errors_rx_2_bit8,
        { "Bad flow payload checksum", "ixveriwave.errors.bit8",
        FT_BOOLEAN, 16, NULL, 0x0100, NULL, HFILL } },

    { &hf_radiotap_vw_errors_rx_2_bit10,
        { "Bad IP checksum error", "ixveriwave.errors.bit10",
        FT_BOOLEAN, 16, NULL, 0x0400, NULL, HFILL } },

    { &hf_radiotap_vw_errors_rx_2_bit11,
        { "L4(TCP/ICMP/IGMP/UDP) checksum error", "ixveriwave.errors.bit11",
        FT_BOOLEAN, 16, NULL, 0x0800, NULL, HFILL } },

    { &hf_radiotap_vw_errors_tx_bit01,
        { "CRC32 Error", "ixveriwave.errors.bit1",
        FT_BOOLEAN, 32, NULL, 0x00000002, NULL, HFILL } },
    { &hf_radiotap_vw_errors_tx_bit05,
        { "IP Checksum Error", "ixveriwave.errors.bit5",
        FT_BOOLEAN, 32, NULL, 0x00000020, NULL, HFILL } },
    { &hf_radiotap_vw_errors_tx_bit8,
        { "ACK Timeout", "ixveriwave.errors.bit8",
        FT_BOOLEAN, 32, NULL, 0x00000100, NULL, HFILL } },
    { &hf_radiotap_vw_errors_tx_bit9,
        { "CTS Timeout", "ixveriwave.errors.bit9",
        FT_BOOLEAN, 32, NULL, 0x00000200, NULL, HFILL } },
    { &hf_radiotap_vw_errors_tx_bit10,
        { "Last Retry Attempt for this MPDU", "ixveriwave.errors.bit10",
        FT_BOOLEAN, 32, NULL, 0x00000400, NULL, HFILL } },
    { &hf_radiotap_vw_errors_tx_bit31,
        { "Internal Error", "ixveriwave.errors.bit31",
        FT_BOOLEAN, 32, NULL, 0x80000000, NULL, HFILL } },
    { &hf_radiotap_vw_tx_retrycount,
        { "Retry Count", "ixveriwave.tx.retrycount",
        FT_UINT8, BASE_DEC, NULL, 0x1f, NULL, HFILL } },
    { &hf_radiotap_vw_tx_factorydebug,
        { "Factory Debug", "ixveriwave.tx.factorydebug",
        FT_UINT8, BASE_HEX, NULL, 0x7f80, NULL, HFILL } },

    { &hf_radiotap_vw_errors_rx_bit0,
        { "SIG Field CRC/Parity Error", "ixveriwave.errors.bit0",
        FT_BOOLEAN, 32, NULL, 0x00000001, NULL, HFILL } },
    { &hf_radiotap_vw_errors_rx_bit1,
        { "Non-supported service field", "ixveriwave.errors.bit1",
        FT_BOOLEAN, 32, NULL, 0x00000002, NULL, HFILL } },
    { &hf_radiotap_vw_errors_rx_bit2,
        { "Frame Length Error", "ixveriwave.errors.bit2",
        FT_BOOLEAN, 32, NULL, 0x00000004, NULL, HFILL } },
    { &hf_radiotap_vw_errors_rx_bit3,
        { "VHT_SIG_A/B CRC Error", "ixveriwave.errors.bit3",
        FT_BOOLEAN, 32, NULL, 0x00000008, NULL, HFILL } },
    { &hf_radiotap_vw_errors_rx_bit4,
        { "CRC32 Error", "ixveriwave.errors.bit4",
        FT_BOOLEAN, 32, NULL, 0x00000010, NULL, HFILL } },
    { &hf_radiotap_vw_errors_rx_bit5,
        { "L2 de-aggregation error", "ixveriwave.errors.bit5",
        FT_BOOLEAN, 32, NULL, 0x00000020, NULL, HFILL } },
    { &hf_radiotap_vw_errors_rx_bit6,
        { "Duplicate MPDU", "ixveriwave.errors.bit6",
        FT_BOOLEAN, 32, NULL, 0x00000040, NULL, HFILL } },
    { &hf_radiotap_vw_errors_rx_bit7,
        { "Bad Flow Magic Number", "ixveriwave.errors.bit7",
        FT_BOOLEAN, 32, NULL, 0x00000080, NULL, HFILL } },
    { &hf_radiotap_vw_errors_rx_bit8,
        { "Bad flow payload checksum", "ixveriwave.errors.bit8",
        FT_BOOLEAN, 32, NULL, 0x00000100, NULL, HFILL } },
    { &hf_radiotap_vw_errors_rx_bit9,
        { "Illegal VHT_SIG Value", "ixveriwave.errors.bit9",
        FT_BOOLEAN, 32, NULL, 0x00000200, NULL, HFILL } },
    { &hf_radiotap_vw_errors_rx_bit10,
        { "Bad IP checksum error", "ixveriwave.errors.bit10",
        FT_BOOLEAN, 32, NULL, 0x00000400, NULL, HFILL } },
    { &hf_radiotap_vw_errors_rx_bit11,
        { "TCP/ICMP/IGMP/UDP Checksum Error", "ixveriwave.errors.bit11",
        FT_BOOLEAN, 32, NULL, 0x00000800, NULL, HFILL } },
    { &hf_radiotap_vw_errors_rx_bit12,
        { "Layer 1 Unsupported Feature", "ixveriwave.errors.bit12",
        FT_BOOLEAN, 32, NULL, 0x00001000, NULL, HFILL } },
    { &hf_radiotap_vw_errors_rx_bit14,
        { "Layer 1 Packet Termination", "ixveriwave.errors.bit14",
        FT_BOOLEAN, 32, NULL, 0x00004000, NULL, HFILL } },
    { &hf_radiotap_vw_errors_rx_bit15,
        { "Internal Error", "ixveriwave.errors.bit15",
        FT_BOOLEAN, 32, NULL, 0x00008000, NULL, HFILL } },
    { &hf_radiotap_vw_errors_rx_bit16,
        { "WEP IVC/TKIP/CCMP/BIP MIC Miscompare", "ixveriwave.errors.bit16",
        FT_BOOLEAN, 32, NULL, 0x00010000, NULL, HFILL } },
    { &hf_radiotap_vw_errors_rx_bit17,
        { "WEP/TKIP Rate Exceeded", "ixveriwave.errors.bit17",
        FT_BOOLEAN, 32, NULL, 0x00020000, NULL, HFILL } },
    { &hf_radiotap_vw_errors_rx_bit18,
        { "Crypto Short Error", "ixveriwave.errors.bit18",
        FT_BOOLEAN, 32, NULL, 0x00040000, NULL, HFILL } },
    { &hf_radiotap_vw_errors_rx_bit19,
        { "EXTIV Fault A", "ixveriwave.errors.bit19",
        FT_BOOLEAN, 32, NULL, 0x00080000, NULL, HFILL } },
    { &hf_radiotap_vw_errors_rx_bit20,
        { "EXTIV Fault B", "ixveriwave.errors.bit20",
        FT_BOOLEAN, 32, NULL, 0x00100000, NULL, HFILL } },
    { &hf_radiotap_vw_errors_rx_bit21,
        { "Internal Error", "ixveriwave.errors.bit21",
        FT_BOOLEAN, 32, NULL, 0x00200000, NULL, HFILL } },
    { &hf_radiotap_vw_errors_rx_bit22,
        { "Protected Fault A", "ixveriwave.errors.bit22",
        FT_BOOLEAN, 32, NULL, 0x00400000, NULL, HFILL } },
    { &hf_radiotap_vw_errors_rx_bit23,
        { "RX MAC Crypto Incompatibility", "ixveriwave.errors.bit23",
        FT_BOOLEAN, 32, NULL, 0x00800000, NULL, HFILL } },
    { &hf_radiotap_vw_errors_rx_bit24,
        { "Factory Debug", "ixveriwave.errors.bit24",
        FT_BOOLEAN, 32, NULL, 0x7F000000, NULL, HFILL } },
    { &hf_radiotap_vw_errors_rx_bit31,
        { "Internal Error", "ixveriwave.errors.bit31",
        FT_BOOLEAN, 32, NULL, 0x80000000, NULL, HFILL } },

    { &hf_radiotap_vw_info,
        { "Info field", "ixveriwave.info",
        FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL } },
    { &hf_radiotap_vw_info_tx,
        { "Info field", "ixveriwave.info",
        FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL } },
    { &hf_radiotap_vw_info_rx,
            { "Info field", "ixveriwave.info",
            FT_UINT24, BASE_HEX, NULL, 0x0, NULL, HFILL } },

    /* tx info decodes for VW510021 and previous versions */

    /*
    { &hf_radiotap_vw_info_tx_bit0,
        { "Crypto WEP Encoded", "ixveriwave.info.bit0",
        FT_BOOLEAN, 16, NULL, 0x0001, NULL, HFILL } },
    { &hf_radiotap_vw_info_tx_bit1,
        { "Crypto TKIP Encoded", "ixveriwave.info.bit1",
        FT_BOOLEAN, 16, NULL, 0x0006, NULL, HFILL } },
    { &hf_radiotap_vw_info_tx_bit3,
        { "Crypto C bit Error", "ixveriwave.info.bit3",
        FT_BOOLEAN, 16, NULL, 0x0008, NULL, HFILL } },
    { &hf_radiotap_vw_info_tx_bit4,
        { "Crypto TKIP not full MSDU", "ixveriwave.info.bit4",
        FT_BOOLEAN, 16, NULL, 0x0010, NULL, HFILL } },
    { &hf_radiotap_vw_info_tx_bit5,
        { "Crypto Software Error", "ixveriwave.info.bit5",
        FT_BOOLEAN, 16, NULL, 0x0020, NULL, HFILL } },
    { &hf_radiotap_vw_info_tx_bit6,
        { "Crypto Short Fault", "ixveriwave.info.bit6",
        FT_BOOLEAN, 16, NULL, 0x0040, NULL, HFILL } },
    { &hf_radiotap_vw_info_tx_bit7,
        { "Crypto Payload Length Fault", "ixveriwave.info.bit7",
        FT_BOOLEAN, 16, NULL, 0x0080, NULL, HFILL } },
    { &hf_radiotap_vw_info_tx_bit8,
        { "Sent RTS before Data", "ixveriwave.info.bit8",
        FT_BOOLEAN, 16, NULL, 0x0100, NULL, HFILL } },
    { &hf_radiotap_vw_info_tx_bit9,
        { "Sent CTS to Self before Data", "ixveriwave.info.bit9",
        FT_BOOLEAN, 16, NULL, 0x0200, NULL, HFILL } },

    { &hf_radiotap_vw_info_tx_bit10,
        { "MPDU of A-MPDU", "ixveriwave.info.bit10",
        FT_BOOLEAN, 16, NULL, INFO_MPDU_OF_A_MPDU, NULL, HFILL } },

    { &hf_radiotap_vw_info_tx_bit11,
        { "First MPDU of A-MPDU", "ixveriwave.info.bit11",
        FT_BOOLEAN, 16, NULL, INFO_FIRST_MPDU_OF_A_MPDU, NULL, HFILL } },

    { &hf_radiotap_vw_info_tx_bit12,
        { "Last MPDU of A-MPDU", "ixveriwave.info.bit12",
        FT_BOOLEAN, 16, NULL, INFO_LAST_MPDU_OF_A_MPDU, NULL, HFILL } },

    { &hf_radiotap_vw_info_tx_bit13,
        { "MSDU of A-MSDU", "ixveriwave.info.bit13",
        FT_BOOLEAN, 16, NULL, INFO_MSDU_OF_A_MSDU, NULL, HFILL } },

    { &hf_radiotap_vw_info_tx_bit14,
        { "First MSDU of A-MSDU", "ixveriwave.info.bit14",
        FT_BOOLEAN, 16, NULL, INFO_FIRST_MSDU_OF_A_MSDU, NULL, HFILL } },

    { &hf_radiotap_vw_info_tx_bit15,
        { "Last MSDU of A-MSDU", "ixveriwave.info.bit15",
        FT_BOOLEAN, 16, NULL, INFO_LAST_MSDU_OF_A_MSDU, NULL, HFILL } },
    */
    /* tx info decodes for VW510021 and previous versions */
    { &hf_radiotap_vw_info_tx_bit0,
        { "Crypto WEP Encoded", "ixveriwave.info.bit0",
        FT_UINT16, BASE_DEC, NULL, 0x0001, NULL, HFILL } },
    { &hf_radiotap_vw_info_tx_bit1,
        { "Crypto TKIP Encoded", "ixveriwave.info.bit1",
        FT_UINT16, BASE_DEC, VALS(crypto_TKIP_type), 0x0006, NULL, HFILL } },
    { &hf_radiotap_vw_info_tx_bit3,
        { "Crypto C bit Error", "ixveriwave.info.bit3",
        FT_UINT16, BASE_DEC, NULL, 0x0008, NULL, HFILL } },
    { &hf_radiotap_vw_info_tx_bit4,
        { "Crypto TKIP not full MSDU", "ixveriwave.info.bit4",
        FT_UINT16, BASE_DEC, NULL, 0x0010, NULL, HFILL } },
    { &hf_radiotap_vw_info_tx_bit5,
        { "Crypto Software Error", "ixveriwave.info.bit5",
        FT_UINT16, BASE_DEC, NULL, 0x0020, NULL, HFILL } },
    { &hf_radiotap_vw_info_tx_bit6,
        { "Crypto Short Fault", "ixveriwave.info.bit6",
        FT_UINT16, BASE_DEC, NULL, 0x0040, NULL, HFILL } },
    { &hf_radiotap_vw_info_tx_bit7,
        { "Crypto Payload Length Fault", "ixveriwave.info.bit7",
        FT_UINT16, BASE_DEC, NULL, 0x0080, NULL, HFILL } },
    { &hf_radiotap_vw_info_tx_bit8,
        { "Sent RTS before Data", "ixveriwave.info.bit8",
        FT_UINT16, BASE_DEC, NULL, 0x0100, NULL, HFILL } },
    { &hf_radiotap_vw_info_tx_bit9,
        { "Sent CTS to Self before Data", "ixveriwave.info.bit9",
        FT_UINT16, BASE_DEC, NULL, 0x0200, NULL, HFILL } },

    { &hf_radiotap_vw_info_tx_bit10,
        { "MPDU of A-MPDU", "ixveriwave.info.bit10",
        FT_UINT16, BASE_DEC, NULL, INFO_MPDU_OF_A_MPDU, NULL, HFILL } },

    { &hf_radiotap_vw_info_tx_bit11,
        { "First MPDU of A-MPDU", "ixveriwave.info.bit11",
        FT_UINT16, BASE_DEC, NULL, INFO_FIRST_MPDU_OF_A_MPDU, NULL, HFILL } },

    { &hf_radiotap_vw_info_tx_bit12,
        { "Last MPDU of A-MPDU", "ixveriwave.info.bit12",
        FT_UINT16, BASE_DEC, NULL, INFO_LAST_MPDU_OF_A_MPDU, NULL, HFILL } },

    { &hf_radiotap_vw_info_tx_bit13,
        { "MSDU of A-MSDU", "ixveriwave.info.bit13",
        FT_UINT16, BASE_DEC, NULL, INFO_MSDU_OF_A_MSDU, NULL, HFILL } },

    { &hf_radiotap_vw_info_tx_bit14,
        { "First MSDU of A-MSDU", "ixveriwave.info.bit14",
        FT_UINT16, BASE_DEC, NULL, INFO_FIRST_MSDU_OF_A_MSDU, NULL, HFILL } },

    { &hf_radiotap_vw_info_tx_bit15,
        { "Last MSDU of A-MSDU", "ixveriwave.info.bit15",
        FT_UINT16, BASE_DEC, NULL, INFO_LAST_MSDU_OF_A_MSDU, NULL, HFILL } },

    { &hf_radiotap_vw_info_tx_2_bit10,
        { "MPDU of A-MPDU", "ixveriwave.info.bit10",
        FT_BOOLEAN, 16, NULL, INFO_MPDU_OF_A_MPDU, NULL, HFILL } },

    { &hf_radiotap_vw_info_tx_2_bit11,
        { "First MPDU of A-MPDU", "ixveriwave.info.bit11",
        FT_BOOLEAN, 16, NULL, INFO_FIRST_MPDU_OF_A_MPDU, NULL, HFILL } },

    { &hf_radiotap_vw_info_tx_2_bit12,
        { "Last MPDU of A-MPDU", "ixveriwave.info.bit12",
        FT_BOOLEAN, 16, NULL, INFO_LAST_MPDU_OF_A_MPDU, NULL, HFILL } },

    { &hf_radiotap_vw_info_tx_2_bit13,
        { "MSDU of A-MSDU", "ixveriwave.info.bit13",
        FT_BOOLEAN, 16, NULL, INFO_MSDU_OF_A_MSDU, NULL, HFILL } },

    { &hf_radiotap_vw_info_tx_2_bit14,
        { "First MSDU of A-MSDU", "ixveriwave.info.bit14",
        FT_BOOLEAN, 16, NULL, INFO_FIRST_MSDU_OF_A_MSDU, NULL, HFILL } },

    { &hf_radiotap_vw_info_tx_2_bit15,
        { "Last MSDU of A-MSDU", "ixveriwave.info.bit15",
        FT_BOOLEAN, 16, NULL, INFO_LAST_MSDU_OF_A_MSDU, NULL, HFILL } },
    /*v510006 uses bits */

    /* rx info decodes for fpga ver VW510021 */
    { &hf_radiotap_vw_info_rx_bit0,
        { "Crypto WEP Encoded", "ixveriwave.info.bit0",
        FT_UINT24, BASE_DEC, NULL, 0x000001, NULL, HFILL } },
    { &hf_radiotap_vw_info_rx_bit1,
        { "Crypto TKIP Encoded", "ixveriwave.info.bit1",
        FT_UINT24, BASE_DEC, VALS(crypto_TKIP_type), 0x000006, NULL, HFILL } },
    { &hf_radiotap_vw_info_rx_bit3,
        { "Crypto RX TKIP TSC SEQSKIP", "ixveriwave.info.bit3",
        FT_UINT24, BASE_DEC, NULL, 0x000008, NULL, HFILL } },
    { &hf_radiotap_vw_info_rx_bit4,
        { "Crypto RX CCMP PN SEQSKIP", "ixveriwave.info.bit4",
        FT_UINT24, BASE_DEC, NULL, 0x000010, NULL, HFILL } },
    { &hf_radiotap_vw_info_rx_bit5,
        { "TKIP not full MSDU", "ixveriwave.info.bit5",
        FT_UINT24, BASE_DEC, NULL, 0x000020, NULL, HFILL } },
    { &hf_radiotap_vw_info_rx_bit6,
        { "MPDU Length field is greater than MPDU octets", "ixveriwave.info.bit6",
        FT_UINT24, BASE_DEC, NULL, 0x000040, NULL, HFILL } },
    { &hf_radiotap_vw_info_rx_bit7,
        { "RX TKIP / CCMP TSC SEQERR", "ixveriwave.info.bit7",
        FT_UINT24, BASE_DEC, NULL, 0x000080, NULL, HFILL } },
    { &hf_radiotap_vw_info_rx_bit8,
        { "ACK withheld from frame", "ixveriwave.info.bit8",
        FT_UINT24, BASE_DEC, NULL, 0x000100, NULL, HFILL } },
    { &hf_radiotap_vw_info_rx_bit9,
        { "Client BSSID matched", "ixveriwave.info.bit9",
        FT_UINT24, BASE_DEC, NULL, 0x000200, NULL, HFILL } },
    { &hf_radiotap_vw_info_rx_bit10,
        { "MPDU of an A-MPDU", "ixveriwave.info.bit10",
        FT_UINT24, BASE_DEC, NULL, 0x000400, NULL, HFILL } },

    { &hf_radiotap_vw_info_rx_bit11,
        { "First MPDU of A-MPDU", "ixveriwave.info.bit11",
        FT_UINT24, BASE_DEC, NULL, 0x000800, NULL, HFILL } },

    { &hf_radiotap_vw_info_rx_bit12,
        { "Last MPDU of A-MPDU", "ixveriwave.info.bit12",
        FT_UINT24, BASE_DEC, NULL, 0x001000, NULL, HFILL } },

    { &hf_radiotap_vw_info_rx_bit13,
        { "MSDU of A-MSDU", "ixveriwave.info.bit13",
        FT_UINT24, BASE_DEC, NULL, 0x002000, NULL, HFILL } },

    { &hf_radiotap_vw_info_rx_bit14,
        { "First MSDU of A-MSDU", "ixveriwave.info.bit14",
        FT_UINT24, BASE_DEC, NULL, 0x004000, NULL, HFILL } },

    { &hf_radiotap_vw_info_rx_bit15,
        { "Last MSDU of A-MSDU", "ixveriwave.info.bit15",
        FT_UINT24, BASE_DEC, NULL, 0x008000, NULL, HFILL } },
    { &hf_radiotap_vw_info_rx_bit16,
        { "Layer 1 Info[0]", "ixveriwave.info.bit16",
        FT_UINT24, BASE_DEC, NULL, 0x010000, NULL, HFILL } },

    { &hf_radiotap_vw_info_rx_bit17,
        { "Layer 1 Info[1]", "ixveriwave.info.bit17",
        FT_UINT24, BASE_DEC, NULL, 0x020000, NULL, HFILL } },

    { &hf_radiotap_vw_info_rx_bit18,
        { "VHT frame received with the use of the VHT_SIG_B.LENGTH", "ixveriwave.info.bit18",
        FT_UINT24, BASE_DEC, NULL, 0x040000, NULL, HFILL } },

    { &hf_radiotap_vw_info_rx_bit19,
        { "VHT frame received without the use of VHT_SIG_B.LENGTH", "ixveriwave.info.bit19",
        FT_UINT24, BASE_DEC, NULL, 0x080000, NULL, HFILL } },
    { &hf_radiotap_vw_info_rx_bit20,
        { "Factory Internal", "ixveriwave.info.bit20",
        FT_UINT24, BASE_DEC, NULL, 0xf00000, NULL, HFILL } },

    { &hf_radiotap_vw_info_rx_2_bit8,
        { "ACK withheld from frame", "ixveriwave.info.bit8",
        FT_BOOLEAN, 16, NULL, 0x0100, NULL, HFILL } },

    { &hf_radiotap_vw_info_rx_2_bit9,
        { "Sent CTS to self before data", "ixveriwave.info.bit9",
        FT_BOOLEAN, 16, NULL, 0x0200, NULL, HFILL } },

    { &hf_radiotap_vw_info_rx_2_bit10,
        { "MPDU of an A-MPDU", "ixveriwave.info.bit10",
        FT_BOOLEAN, 16, NULL, INFO_MPDU_OF_A_MPDU, NULL, HFILL } },

    { &hf_radiotap_vw_info_rx_2_bit11,
        { "First MPDU of A-MPDU", "ixveriwave.info.bit11",
        FT_BOOLEAN, 16, NULL, INFO_FIRST_MPDU_OF_A_MPDU, NULL, HFILL } },

    { &hf_radiotap_vw_info_rx_2_bit12,
        { "Last MPDU of A-MPDU", "ixveriwave.info.bit12",
        FT_BOOLEAN, 16, NULL, INFO_LAST_MPDU_OF_A_MPDU, NULL, HFILL } },

    { &hf_radiotap_vw_info_rx_2_bit13,
        { "MSDU of A-MSDU", "ixveriwave.info.bit13",
        FT_BOOLEAN, 16, NULL, INFO_MSDU_OF_A_MSDU, NULL, HFILL } },

    { &hf_radiotap_vw_info_rx_2_bit14,
        { "First MSDU of A-MSDU", "ixveriwave.info.bit14",
        FT_BOOLEAN, 16, NULL, INFO_FIRST_MSDU_OF_A_MSDU, NULL, HFILL } },

    { &hf_radiotap_vw_info_rx_2_bit15,
        { "Last MSDU of A-MSDU", "ixveriwave.info.bit15",
        FT_BOOLEAN, 16, NULL, INFO_LAST_MSDU_OF_A_MSDU, NULL, HFILL } },
    };

    static gint *ett[] = {
        &ett_commontap,
        &ett_commontap_times,
        &ett_ethernettap_info,
        &ett_ethernettap_error,
        &ett_ethernettap_flags,
        &ett_radiotap_flags,
        &ett_radiotap_info,
        &ett_radiotap_times,
        &ett_radiotap_errors,
        &ett_radiotap_layer1,
        &ett_radiotap_layer2to4,
        &ett_radiotap_rf,
        &ett_radiotap_plcp,
        &ett_radiotap_infoc,
        &ett_rf_info,
        &ett_radiotap_contextp,
    };

    proto_ixveriwave = proto_register_protocol("ixveriwave", "ixveriwave", "ixveriwave");
    proto_register_field_array(proto_ixveriwave, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

    ixveriwave_handle = register_dissector("ixveriwave", dissect_ixveriwave, proto_ixveriwave);
}

void proto_reg_handoff_ixveriwave(void)
{
    /* handle for ethertype dissector */
    ethernet_handle          = find_dissector_add_dependency("eth_withoutfcs", proto_ixveriwave);
    /* handle for 802.11+radio information dissector */
    ieee80211_radio_handle   = find_dissector_add_dependency("wlan_radio", proto_ixveriwave);

    dissector_add_uint("wtap_encap", WTAP_ENCAP_IXVERIWAVE, ixveriwave_handle);
}

/*
 * Editor modelines  -  http://www.wireshark.org/tools/modelines.html
 *
 * Local variables:
 * c-basic-offset: 4
 * tab-width: 8
 * indent-tabs-mode: nil
 * End:
 *
 * vi: set shiftwidth=4 tabstop=8 expandtab:
 * :indentSize=4:tabSize=8:noTabs=true:
 */
