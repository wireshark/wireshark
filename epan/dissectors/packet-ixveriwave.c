/* packet-ixveriwave.c
 * Routines for calling the right protocol for the ethertype.
 *
 * Tom Cook <tcook@ixiacom.com>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
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
                            uint16_t vw_msdu_length);
static void wlantap_dissect_octo(tvbuff_t *tvb, packet_info *pinfo,
                                 proto_tree *tree, proto_tree *tap_tree,
                                 uint8_t cmd_type, int log_mode);

typedef struct {
    uint32_t previous_frame_num;
    uint64_t previous_end_time;
} frame_end_data;

typedef struct ifg_info {
    uint32_t ifg;
    uint64_t previous_end_time;
    uint64_t current_start_time;
} ifg_info;

static frame_end_data previous_frame_data;

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

/*
 * VHT bandwidth values.
 */
#define VHT_BW_20_MHZ  0
#define VHT_BW_40_MHZ  1
#define VHT_BW_80_MHZ  2
#define VHT_BW_160_MHZ 3

static int proto_ixveriwave;
static dissector_handle_t ethernet_handle;

/* static int hf_ixveriwave_version; */
static int hf_ixveriwave_frame_length;

/* static int hf_ixveriwave_fcs; */

static int hf_ixveriwave_vw_msdu_length;
static int hf_ixveriwave_vw_flowid;
static int hf_ixveriwave_vw_vcid;
static int hf_ixveriwave_vw_seqnum;

static int hf_ixveriwave_vw_mslatency;
static int hf_ixveriwave_vw_latency;
static int hf_ixveriwave_vw_sig_ts;
static int hf_ixveriwave_vw_delay;
static int hf_ixveriwave_vw_startt;
static int hf_ixveriwave_vw_endt;
static int hf_ixveriwave_vw_pktdur;
static int hf_ixveriwave_vw_ifg;

// RF LOGGING
static int hf_radiotap_rf_info;
static int hf_radiotap_rfinfo_rfid;

/*
static int hf_radiotap_rfinfo_noise;
static int hf_radiotap_rfinfo_noise_anta;
static int hf_radiotap_rfinfo_noise_antb;
static int hf_radiotap_rfinfo_noise_antc;
static int hf_radiotap_rfinfo_noise_antd;
*/

static int hf_radiotap_rfinfo_snr;
static int hf_radiotap_rfinfo_snr_anta;
static int hf_radiotap_rfinfo_snr_antb;
static int hf_radiotap_rfinfo_snr_antc;
static int hf_radiotap_rfinfo_snr_antd;

static int hf_radiotap_rfinfo_pfe;
static int hf_radiotap_rfinfo_pfe_anta;
static int hf_radiotap_rfinfo_pfe_antb;
static int hf_radiotap_rfinfo_pfe_antc;
static int hf_radiotap_rfinfo_pfe_antd;

static int hf_radiotap_rfinfo_sigdata;
static int hf_radiotap_rfinfo_avg_evm_sd_siga;
static int hf_radiotap_rfinfo_avg_evm_sd_sigb;
static int hf_radiotap_rfinfo_avg_evm_sd_sigc;
static int hf_radiotap_rfinfo_avg_evm_sd_sigd;

static int hf_radiotap_rfinfo_sigpilot;
static int hf_radiotap_rfinfo_avg_evm_sp_siga;
static int hf_radiotap_rfinfo_avg_evm_sp_sigb;
static int hf_radiotap_rfinfo_avg_evm_sp_sigc;
static int hf_radiotap_rfinfo_avg_evm_sp_sigd;

static int hf_radiotap_rfinfo_datadata;
static int hf_radiotap_rfinfo_avg_evm_dd_siga;
static int hf_radiotap_rfinfo_avg_evm_dd_sigb;
static int hf_radiotap_rfinfo_avg_evm_dd_sigc;
static int hf_radiotap_rfinfo_avg_evm_dd_sigd;

static int hf_radiotap_rfinfo_datapilot;
static int hf_radiotap_rfinfo_avg_evm_dp_siga;
static int hf_radiotap_rfinfo_avg_evm_dp_sigb;
static int hf_radiotap_rfinfo_avg_evm_dp_sigc;
static int hf_radiotap_rfinfo_avg_evm_dp_sigd;

static int hf_radiotap_rfinfo_avg_ws_symbol;
static int hf_radiotap_rfinfo_avg_evm_ws_siga;
static int hf_radiotap_rfinfo_avg_evm_ws_sigb;
static int hf_radiotap_rfinfo_avg_evm_ws_sigc;
static int hf_radiotap_rfinfo_avg_evm_ws_sigd;

static int hf_radiotap_rfinfo_contextpa;
static int hf_radiotap_rfinfo_contextpA_snr_noise_valid;
static int hf_radiotap_rfinfo_contextpA_pfe_valid;
static int hf_radiotap_rfinfo_contextpA_pfe_is_cck;
static int hf_radiotap_rfinfo_contextpA_agc_idle2iqrdy_no_gain_change;
static int hf_radiotap_rfinfo_contextpA_agc_high_pwr_terminated;
static int hf_radiotap_rfinfo_contextpA_agc_high_pwr_terminator;
/* static int hf_radiotap_rfinfo_contextpA_frame_format; */
/* static int hf_radiotap_rfinfo_contextpA_ofdm_or_cck; */
/* static int hf_radiotap_rfinfo_contextpA_sigbandwidth_of_evm; */
static int hf_radiotap_rfinfo_contextpA_qam_modulation;

static int hf_radiotap_rfinfo_frameformatA;
static int hf_radiotap_rfinfo_sigbwevmA;
static int hf_radiotap_rfinfo_legacytypeA;

static int hf_radiotap_rfinfo_contextpb;
static int hf_radiotap_rfinfo_contextpB_snr_noise_valid;
static int hf_radiotap_rfinfo_contextpB_pfe_valid;
static int hf_radiotap_rfinfo_contextpB_pfe_is_cck;
static int hf_radiotap_rfinfo_contextpB_agc_idle2iqrdy_no_gain_change;
static int hf_radiotap_rfinfo_contextpB_agc_high_pwr_terminated;
static int hf_radiotap_rfinfo_contextpB_agc_high_pwr_terminator;
static int hf_radiotap_rfinfo_contextpB_qam_modulation;

static int hf_radiotap_rfinfo_frameformatB;
static int hf_radiotap_rfinfo_sigbwevmB;
static int hf_radiotap_rfinfo_legacytypeB;

static int hf_radiotap_rfinfo_contextpc;
static int hf_radiotap_rfinfo_contextpC_snr_noise_valid;
static int hf_radiotap_rfinfo_contextpC_pfe_valid;
static int hf_radiotap_rfinfo_contextpC_pfe_is_cck;
static int hf_radiotap_rfinfo_contextpC_agc_idle2iqrdy_no_gain_change;
static int hf_radiotap_rfinfo_contextpC_agc_high_pwr_terminated;
static int hf_radiotap_rfinfo_contextpC_agc_high_pwr_terminator;
static int hf_radiotap_rfinfo_contextpC_qam_modulation;

static int hf_radiotap_rfinfo_frameformatC;
static int hf_radiotap_rfinfo_sigbwevmC;
static int hf_radiotap_rfinfo_legacytypeC;

static int hf_radiotap_rfinfo_contextpd;
static int hf_radiotap_rfinfo_contextpD_snr_noise_valid;
static int hf_radiotap_rfinfo_contextpD_pfe_valid;
static int hf_radiotap_rfinfo_contextpD_pfe_is_cck;
static int hf_radiotap_rfinfo_contextpD_agc_idle2iqrdy_no_gain_change;
static int hf_radiotap_rfinfo_contextpD_agc_high_pwr_terminated;
static int hf_radiotap_rfinfo_contextpD_agc_high_pwr_terminator;
static int hf_radiotap_rfinfo_contextpD_qam_modulation;

static int hf_radiotap_rfinfo_frameformatD;
static int hf_radiotap_rfinfo_sigbwevmD;
static int hf_radiotap_rfinfo_legacytypeD;

/* static int hf_radiotap_rfinfo_tbd; */

/* Fields for both Ethernet and WLAN */
static int hf_ixveriwave_vw_l4id;

/* Ethernet fields */
static int hf_ixveriwave_vwf_txf;
static int hf_ixveriwave_vwf_fcserr;

static int hf_ixveriwave_vw_info;
static int hf_ixveriwave_vw_info_go_no_flow;
static int hf_ixveriwave_vw_info_go_with_flow;

/*veriwave note:  i know the below method seems clunky, but
they didn't have a item_format at the time to dynamically add the appropriate decode text*/
static int hf_ixveriwave_vw_info_retry_count;

static int hf_ixveriwave_vw_error;

/*error flags*/
static int hf_ixveriwave_vw_error_1_alignment_error;
static int hf_ixveriwave_vw_error_1_packet_fcs_error;
static int hf_ixveriwave_vw_error_1_bad_magic_byte_signature;
static int hf_ixveriwave_vw_error_1_bad_payload_checksum;
static int hf_ixveriwave_vw_error_1_frame_too_long;
static int hf_ixveriwave_vw_error_1_ip_checksum_error;
static int hf_ixveriwave_vw_error_1_l4_checksum_error;
static int hf_ixveriwave_vw_error_1_id_mismatch;
static int hf_ixveriwave_vw_error_1_length_error;
static int hf_ixveriwave_vw_error_1_underflow;
static int hf_ixveriwave_vw_error_1_late_collision;
static int hf_ixveriwave_vw_error_1_excessive_collisions;

/* WLAN fields */
static int hf_radiotap_flags;
static int hf_radiotap_flags_preamble;
static int hf_radiotap_flags_wep;
static int hf_radiotap_flags_ht;
static int hf_radiotap_flags_vht;
static int hf_radiotap_flags_short_gi;
static int hf_radiotap_flags_40mhz;
static int hf_radiotap_flags_80mhz;

static int hf_radiotap_datarate;
static int hf_radiotap_mcsindex;
static int hf_radiotap_nss;

static int hf_radiotap_dbm_anta;
static int hf_radiotap_dbm_antb;
static int hf_radiotap_dbm_antc;
static int hf_radiotap_dbm_antd;

static int hf_radiotap_plcptype;

static int hf_radiotap_vwf_txf;
static int hf_radiotap_vwf_fcserr;
static int hf_radiotap_vwf_dcrerr;
static int hf_radiotap_vwf_retrerr;
static int hf_radiotap_vwf_enctype;

static int hf_radiotap_vw_ht_length;

static int hf_radiotap_vw_info;

static int hf_radiotap_vw_info_2_ack_withheld_from_frame;
static int hf_radiotap_vw_info_2_sent_cts_to_self_before_data;
static int hf_radiotap_vw_info_2_mpdu_of_a_mpdu;
static int hf_radiotap_vw_info_2_first_mpdu_of_a_mpdu;
static int hf_radiotap_vw_info_2_last_pdu_of_a_mpdu;
static int hf_radiotap_vw_info_2_msdu_of_a_msdu;
static int hf_radiotap_vw_info_2_first_msdu_of_a_msdu;
static int hf_radiotap_vw_info_2_last_msdu_of_a_msdu;

static int hf_radiotap_vw_errors;

static int hf_radiotap_vw_errors_rx_2_crc16_or_parity_error;
static int hf_radiotap_vw_errors_rx_2_non_supported_rate_or_service_field;
static int hf_radiotap_vw_errors_rx_2_short_frame;
static int hf_radiotap_vw_errors_rx_2_fcs_error;
static int hf_radiotap_vw_errors_rx_2_l2_de_aggregation_error;
static int hf_radiotap_vw_errors_rx_2_duplicate_mpdu;
static int hf_radiotap_vw_errors_rx_2_bad_flow_magic_number;
static int hf_radiotap_vw_errors_rx_2_flow_payload_checksum_error;
static int hf_radiotap_vw_errors_rx_2_ip_checksum_error;
static int hf_radiotap_vw_errors_rx_2_l4_checksum_error;

static int hf_radiotap_vw_errors_tx_2_crc32_error;
static int hf_radiotap_vw_errors_tx_2_ip_checksum_error;
static int hf_radiotap_vw_errors_tx_2_ack_timeout;
static int hf_radiotap_vw_errors_tx_2_cts_timeout;
static int hf_radiotap_vw_errors_tx_2_last_retry_attempt;
static int hf_radiotap_vw_errors_tx_2_internal_error;

static int hf_radiotap_vht_mu_mimo_flg;
static int hf_radiotap_vht_user_pos;
static int hf_radiotap_vht_su_mimo_flg;

static int hf_radiotap_l1info;
static int hf_radiotap_l1info_preamble;
static int hf_radiotap_l1info_rateindex;
static int hf_radiotap_l1info_ht_mcsindex;
static int hf_radiotap_l1info_vht_mcsindex;
static int hf_radiotap_l1info_nss;
static int hf_radiotap_l1info_transmitted;

static int hf_radiotap_sigbandwidth;
/* static int hf_radiotap_rssi; */
static int hf_radiotap_modulation;

static int hf_radiotap_dbm_tx_anta;
static int hf_radiotap_dbm_tx_antb;
static int hf_radiotap_dbm_tx_antc;
static int hf_radiotap_dbm_tx_antd;

static int hf_radiotap_sigbandwidthmask;
static int hf_radiotap_antennaportenergydetect;
static int hf_radiotap_tx_antennaselect;
static int hf_radiotap_tx_stbcselect;
static int hf_radiotap_mumask;

static int hf_radiotap_l1infoc;
static int hf_radiotap_vht_ndp_flg;

static int hf_radiotap_plcp_info;
static int hf_radiotap_plcp_type;
static int hf_radiotap_plcp_default;

static int hf_radiotap_plcp_signal;
static int hf_radiotap_plcp_locked_clocks;
static int hf_radiotap_plcp_modulation;
static int hf_radiotap_plcp_length_extension;
static int hf_radiotap_plcp_length;
static int hf_radiotap_plcp_crc16;

static int hf_radiotap_ofdm_service;

static int hf_radiotap_ofdm_rate;
static int hf_radiotap_ofdm_length;
static int hf_radiotap_ofdm_parity;
static int hf_radiotap_ofdm_tail;

/* HT-SIG1 */
static int hf_radiotap_ht_mcsindex;
static int hf_radiotap_ht_bw;
static int hf_radiotap_ht_length;

/* HT-SIG2 */
static int hf_radiotap_ht_smoothing;
static int hf_radiotap_ht_notsounding;
static int hf_radiotap_ht_aggregation;
static int hf_radiotap_ht_stbc;
static int hf_radiotap_ht_feccoding;
static int hf_radiotap_ht_short_gi;
static int hf_radiotap_ht_ness;
static int hf_radiotap_ht_crc;
static int hf_radiotap_ht_tail;

/* VHT-SIG-A1 */
static int hf_radiotap_vht_bw;
static int hf_radiotap_vht_stbc;
static int hf_radiotap_vht_group_id;
static int hf_radiotap_vht_su_nsts;
static int hf_radiotap_vht_su_partial_aid;
static int hf_radiotap_vht_u0_nsts;
static int hf_radiotap_vht_u1_nsts;
static int hf_radiotap_vht_u2_nsts;
static int hf_radiotap_vht_u3_nsts;
static int hf_radiotap_vht_txop_ps_not_allowed;

/* VHT-SIG-A2 */
static int hf_radiotap_vht_short_gi;
static int hf_radiotap_vht_short_gi_nsym_disambig;
static int hf_radiotap_vht_su_coding_type;
static int hf_radiotap_vht_u0_coding_type;
static int hf_radiotap_vht_ldpc_ofdmsymbol;
static int hf_radiotap_vht_su_mcs;
static int hf_radiotap_vht_beamformed;
static int hf_radiotap_vht_u1_coding_type;
static int hf_radiotap_vht_u2_coding_type;
static int hf_radiotap_vht_u3_coding_type;
static int hf_radiotap_vht_crc;
static int hf_radiotap_vht_tail;

/* VHT-SIG-B */
static int hf_radiotap_vht_su_sig_b_length_20_mhz;
static int hf_radiotap_vht_su_sig_b_length_40_mhz;
static int hf_radiotap_vht_su_sig_b_length_80_160_mhz;
static int hf_radiotap_vht_mu_sig_b_length_20_mhz;
static int hf_radiotap_vht_mu_mcs_20_mhz;
static int hf_radiotap_vht_mu_sig_b_length_40_mhz;
static int hf_radiotap_vht_mu_mcs_40_mhz;
static int hf_radiotap_vht_mu_sig_b_length_80_160_mhz;
static int hf_radiotap_vht_mu_mcs_80_160_mhz;

static int hf_radiotap_rfid;

static int hf_radiotap_l2_l4_info;

static int hf_radiotap_bssid;

static int hf_radiotap_clientidvalid;
static int hf_radiotap_bssidvalid;
static int hf_radiotap_unicastormulticast;

/*static int hf_radiotap_wlantype; */

static int hf_radiotap_tid;
static int hf_radiotap_ac;
static int hf_radiotap_l4idvalid;
static int hf_radiotap_containshtfield;
static int hf_radiotap_istypeqos;
static int hf_radiotap_flowvalid;

static int hf_radiotap_payloaddecode;

static int hf_radiotap_vw_info_rx;
static int hf_radiotap_vw_info_rx_crypto_wep_encoded;
static int hf_radiotap_vw_info_rx_crypto_tkip_encoded;
static int hf_radiotap_vw_info_rx_crypto_rx_tkip_tsc_seqskip;
static int hf_radiotap_vw_info_rx_crypto_rx_ccmp_pn_seqskip;
static int hf_radiotap_vw_info_rx_tkip_not_full_msdu;
static int hf_radiotap_vw_info_rx_mpdu_length_gt_mpdu_octets;
static int hf_radiotap_vw_info_rx_tkip_ccmp_tsc_seqerr;
static int hf_radiotap_vw_info_rx_ack_withheld_from_frame;
static int hf_radiotap_vw_info_rx_client_bssid_matched;
static int hf_radiotap_vw_info_rx_mpdu_of_a_mpdu;
static int hf_radiotap_vw_info_rx_first_mpdu_of_a_mpdu;
static int hf_radiotap_vw_info_rx_last_mpdu_of_a_mpdu;
static int hf_radiotap_vw_info_rx_msdu_of_a_msdu;
static int hf_radiotap_vw_info_rx_first_msdu_of_a_msdu;
static int hf_radiotap_vw_info_rx_last_msdu_of_a_msdu;
static int hf_radiotap_vw_info_rx_layer_1_info_0;
static int hf_radiotap_vw_info_rx_layer_1_info_1;
static int hf_radiotap_vw_info_rx_vht_frame_received_with_vht_sig_b_length;
static int hf_radiotap_vw_info_rx_vht_frame_received_without_vht_sig_b_length;
static int hf_radiotap_vw_info_rx_factory_internal;
static int * const radiotap_info_rx_fields[] = {
    &hf_radiotap_vw_info_rx_crypto_wep_encoded,
    &hf_radiotap_vw_info_rx_crypto_tkip_encoded,
    &hf_radiotap_vw_info_rx_crypto_rx_tkip_tsc_seqskip,
    &hf_radiotap_vw_info_rx_crypto_rx_ccmp_pn_seqskip,
    &hf_radiotap_vw_info_rx_tkip_not_full_msdu,
    &hf_radiotap_vw_info_rx_mpdu_length_gt_mpdu_octets,
    &hf_radiotap_vw_info_rx_tkip_ccmp_tsc_seqerr,
    &hf_radiotap_vw_info_rx_ack_withheld_from_frame,
    &hf_radiotap_vw_info_rx_client_bssid_matched,
    &hf_radiotap_vw_info_rx_mpdu_of_a_mpdu,
    &hf_radiotap_vw_info_rx_first_mpdu_of_a_mpdu,
    &hf_radiotap_vw_info_rx_last_mpdu_of_a_mpdu,
    &hf_radiotap_vw_info_rx_msdu_of_a_msdu,
    &hf_radiotap_vw_info_rx_first_msdu_of_a_msdu,
    &hf_radiotap_vw_info_rx_last_msdu_of_a_msdu,
    &hf_radiotap_vw_info_rx_layer_1_info_0,
    &hf_radiotap_vw_info_rx_layer_1_info_1,
    &hf_radiotap_vw_info_rx_vht_frame_received_with_vht_sig_b_length,
    &hf_radiotap_vw_info_rx_vht_frame_received_without_vht_sig_b_length,
    &hf_radiotap_vw_info_rx_factory_internal,
    NULL,
};

static int hf_radiotap_vw_info_tx;
static int hf_radiotap_vw_info_tx_crypto_wep_encoded;
static int hf_radiotap_vw_info_tx_crypto_tkip_encoded;
static int hf_radiotap_vw_info_tx_crypto_c_bit_error;
static int hf_radiotap_vw_info_tx_crypto_tkip_not_full_msdu;
static int hf_radiotap_vw_info_tx_crypto_software_error;
static int hf_radiotap_vw_info_tx_crypto_short_fault;
static int hf_radiotap_vw_info_tx_crypto_payload_length_fault;
static int hf_radiotap_vw_info_tx_sent_rts_before_data;
static int hf_radiotap_vw_info_tx_sent_cts_to_self_before_data;
static int hf_radiotap_vw_info_tx_mpdu_of_a_mpdu;
static int hf_radiotap_vw_info_tx_first_mpdu_of_a_mpdu;
static int hf_radiotap_vw_info_tx_last_mpdu_of_a_mpdu;
static int hf_radiotap_vw_info_tx_msdu_of_a_msdu;
static int hf_radiotap_vw_info_tx_first_msdu_of_a_msdu;
static int hf_radiotap_vw_info_tx_last_msdu_of_a_msdu;
static int * const radiotap_info_tx_fields[] = {
    &hf_radiotap_vw_info_tx_crypto_wep_encoded,
    &hf_radiotap_vw_info_tx_crypto_tkip_encoded,
    &hf_radiotap_vw_info_tx_crypto_c_bit_error,
    &hf_radiotap_vw_info_tx_crypto_tkip_not_full_msdu,
    &hf_radiotap_vw_info_tx_crypto_software_error,
    &hf_radiotap_vw_info_tx_crypto_short_fault,
    &hf_radiotap_vw_info_tx_crypto_payload_length_fault,
    &hf_radiotap_vw_info_tx_sent_rts_before_data,
    &hf_radiotap_vw_info_tx_sent_cts_to_self_before_data,
    &hf_radiotap_vw_info_tx_mpdu_of_a_mpdu,
    &hf_radiotap_vw_info_tx_first_mpdu_of_a_mpdu,
    &hf_radiotap_vw_info_tx_last_mpdu_of_a_mpdu,
    &hf_radiotap_vw_info_tx_msdu_of_a_msdu,
    &hf_radiotap_vw_info_tx_first_msdu_of_a_msdu,
    &hf_radiotap_vw_info_tx_last_msdu_of_a_msdu,
    NULL,
};

static int hf_radiotap_vw_errors_rx_sig_field_crc_parity_error;
static int hf_radiotap_vw_errors_rx_non_supported_service_field;
static int hf_radiotap_vw_errors_rx_frame_length_error;
static int hf_radiotap_vw_errors_rx_vht_sig_ab_crc_error;
static int hf_radiotap_vw_errors_rx_crc32_error;
static int hf_radiotap_vw_errors_rx_l2_de_aggregation_error;
static int hf_radiotap_vw_errors_rx_duplicate_mpdu;
static int hf_radiotap_vw_errors_rx_bad_flow_magic_number;
static int hf_radiotap_vw_errors_rx_bad_flow_payload_checksum;
static int hf_radiotap_vw_errors_rx_illegal_vht_sig_value;
static int hf_radiotap_vw_errors_rx_ip_checksum_error;
static int hf_radiotap_vw_errors_rx_l4_checksum_error;
static int hf_radiotap_vw_errors_rx_l1_unsupported_feature;
static int hf_radiotap_vw_errors_rx_l1_packet_termination;
static int hf_radiotap_vw_errors_rx_internal_error_bit15;
static int hf_radiotap_vw_errors_rx_wep_mic_miscompare;
static int hf_radiotap_vw_errors_rx_wep_tkip_rate_exceeded;
static int hf_radiotap_vw_errors_rx_crypto_short_error;
static int hf_radiotap_vw_errors_rx_extiv_fault_a;
static int hf_radiotap_vw_errors_rx_extiv_fault_b;
static int hf_radiotap_vw_errors_rx_internal_error_bit21;
static int hf_radiotap_vw_errors_rx_protected_fault_a;
static int hf_radiotap_vw_errors_rx_rx_mac_crypto_incompatibility;
static int hf_radiotap_vw_errors_rx_factory_debug;
static int hf_radiotap_vw_errors_rx_internal_error_bit32;

static int hf_radiotap_vw_errors_tx_packet_fcs_error;
static int hf_radiotap_vw_errors_tx_ip_checksum_error;

static int hf_radiotap_vw_tx_retrycount;
static int hf_radiotap_vw_tx_factorydebug;

static int ett_radiotap_info;
static int ett_radiotap_errors;
static int ett_radiotap_times;
static int ett_radiotap_layer1;
static int ett_radiotap_layer2to4;
static int ett_radiotap_rf;
static int ett_radiotap_plcp;
static int ett_radiotap_infoc;
static int ett_radiotap_contextp;
static int ett_rf_info;

static int ett_commontap;
static int ett_commontap_times;
static int ett_ethernettap_info;
static int ett_ethernettap_error;
static int ett_ethernettap_flags;

static int ett_radiotap_flags;

static dissector_handle_t ieee80211_radio_handle;

static dissector_handle_t ixveriwave_handle;

#define ALIGN_OFFSET(offset, width) \
    ( (((offset) + ((width) - 1)) & (~((width) - 1))) - offset )

static int
dissect_ixveriwave(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
    bool        is_octo = false;
    int         log_mode;
    proto_tree *common_tree                 = NULL;
    proto_item *ti                          = NULL;
    proto_item *vw_times_ti                 = NULL;
    proto_tree *vw_times_tree               = NULL;
    proto_item *rf_infot                    = NULL;
    proto_tree *rf_info_tree                = NULL;
    int         offset;
    uint16_t    length;
    unsigned    length_remaining;
    uint64_t    vw_startt=0, vw_endt=0;
    uint32_t    true_length;
    uint32_t    vw_latency, vw_pktdur;
    uint32_t    vw_msdu_length=0;
    tvbuff_t   *next_tvb;
    ifg_info   *p_ifg_info;
    uint8_t     ixport_type,cmd_type, mgmt_byte = 0;
    uint8_t     frameformat, legacy_type;
    unsigned    rfid;
    int8_t      noisevalida, noisevalidb, noisevalidc, noisevalidd, pfevalida, pfevalidb, pfevalidc, pfevalidd;
    uint16_t    vw_info_ifg;
    int         ifg_flag = 0;
    proto_tree  *vwrft, *vw_rfinfo_tree = NULL, *rfinfo_contextp_tree;

    static int * const context_a_flags[] = {
        &hf_radiotap_rfinfo_contextpA_snr_noise_valid,
        &hf_radiotap_rfinfo_contextpA_pfe_valid,
        &hf_radiotap_rfinfo_contextpA_pfe_is_cck,
        &hf_radiotap_rfinfo_contextpA_agc_idle2iqrdy_no_gain_change,
        &hf_radiotap_rfinfo_contextpA_agc_high_pwr_terminated,
        &hf_radiotap_rfinfo_contextpA_agc_high_pwr_terminator,
/*
        &hf_radiotap_rfinfo_contextpA_frame_format,
        &hf_radiotap_rfinfo_contextpA_ofdm_or_cck,
        &hf_radiotap_rfinfo_contextpA_sigbandwidth_of_evm,
*/
        &hf_radiotap_rfinfo_contextpA_qam_modulation,
        NULL
    };
    static int * const context_b_flags[] = {
        &hf_radiotap_rfinfo_contextpB_snr_noise_valid,
        &hf_radiotap_rfinfo_contextpB_pfe_valid,
        &hf_radiotap_rfinfo_contextpB_pfe_is_cck,
        &hf_radiotap_rfinfo_contextpB_agc_idle2iqrdy_no_gain_change,
        &hf_radiotap_rfinfo_contextpB_agc_high_pwr_terminated,
        &hf_radiotap_rfinfo_contextpB_agc_high_pwr_terminator,
/*
        &hf_radiotap_rfinfo_contextpB_bit8,
        &hf_radiotap_rfinfo_contextpB_bit10,
        &hf_radiotap_rfinfo_contextpB_bit11,
*/
        &hf_radiotap_rfinfo_contextpB_qam_modulation,
        NULL
    };
    static int * const context_c_flags[] = {
        &hf_radiotap_rfinfo_contextpC_snr_noise_valid,
        &hf_radiotap_rfinfo_contextpC_pfe_valid,
        &hf_radiotap_rfinfo_contextpC_pfe_is_cck,
        &hf_radiotap_rfinfo_contextpC_agc_idle2iqrdy_no_gain_change,
        &hf_radiotap_rfinfo_contextpC_agc_high_pwr_terminated,
        &hf_radiotap_rfinfo_contextpC_agc_high_pwr_terminator,
/*
        &hf_radiotap_rfinfo_contextpC_bit8,
        &hf_radiotap_rfinfo_contextpC_bit10,
        &hf_radiotap_rfinfo_contextpC_bit11,
*/
        &hf_radiotap_rfinfo_contextpC_qam_modulation,
        NULL
    };
    static int * const context_d_flags[] = {
        &hf_radiotap_rfinfo_contextpD_snr_noise_valid,
        &hf_radiotap_rfinfo_contextpD_pfe_valid,
        &hf_radiotap_rfinfo_contextpD_pfe_is_cck,
        &hf_radiotap_rfinfo_contextpD_agc_idle2iqrdy_no_gain_change,
        &hf_radiotap_rfinfo_contextpD_agc_high_pwr_terminated,
        &hf_radiotap_rfinfo_contextpD_agc_high_pwr_terminator,
/*
        &hf_radiotap_rfinfo_contextpD_bit8,
        &hf_radiotap_rfinfo_contextpD_bit10,
        &hf_radiotap_rfinfo_contextpD_bit11,
*/
        &hf_radiotap_rfinfo_contextpD_qam_modulation,
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
    ixport_type = tvb_get_uint8(tvb, offset);
    cmd_type = (ixport_type & 0xf0) >> 4;
    ixport_type &= 0x0f;

    /*
     * If the command type is non-zero, this is from an OCTO board.
     */
    if (cmd_type != 0)
    {
        is_octo = true;
        if (cmd_type != 3)
        {
            mgmt_byte = tvb_get_uint8(tvb, offset+1);
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
        mgmt_byte = tvb_get_uint8(tvb, offset+1);
        if ((mgmt_byte & 0x0f) != 0)
            is_octo = true;
        log_mode = (mgmt_byte & 0xf0) >> 4;
    }

    length = tvb_get_letohs(tvb, offset + COMMON_LENGTH_OFFSET);

    col_add_str(pinfo->cinfo, COL_PROTOCOL, ixport_type ? "ETH" : "WLAN");
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
         * Pre-OCTO common header.
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
        /*
         * OCTO time header.
         */
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
            p_ifg_info->ifg = (uint32_t)(vw_startt - previous_frame_data.previous_end_time);
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
            if ((int32_t) p_ifg_info->ifg >= 0)
                ti = proto_tree_add_uint(common_tree, hf_ixveriwave_vw_ifg, tvb, 18, 0, p_ifg_info->ifg);
            else
                ti = proto_tree_add_uint_format_value(common_tree, hf_ixveriwave_vw_ifg, tvb, 18, 0, p_ifg_info->ifg, "Cannot be determined");
        }

        proto_item_set_generated(ti);
    }

    if(cmd_type ==3 || cmd_type ==4)
    {
        float flttmp;
        frameformat = tvb_get_uint8(tvb, offset+33)& 0x03;
        legacy_type = tvb_get_uint8(tvb, offset+33)& 0x04 >>2;

        if(cmd_type ==3)
            offset += 1;

        // Only RF header implementation
        if (tree) {
            vwrft = proto_tree_add_item(common_tree, hf_radiotap_rf_info,
                            tvb, offset, 76, ENC_NA);
            vw_rfinfo_tree = proto_item_add_subtree(vwrft, ett_radiotap_rf);

            proto_tree_add_item_ret_uint(vw_rfinfo_tree,
                                         hf_radiotap_rfinfo_rfid, tvb, offset,
                                         1, ENC_LITTLE_ENDIAN, &rfid);
            proto_item_append_text(vwrft, " (RFID = %u)", rfid);
            offset += 4;
            //Section for Noise
            noisevalida = tvb_get_uint8(tvb, offset+65)& 0x01;
            noisevalidb = tvb_get_uint8(tvb, offset+67)& 0x01;
            noisevalidc = tvb_get_uint8(tvb, offset+69)& 0x01;
            noisevalidd = tvb_get_uint8(tvb, offset+71)& 0x01;

            /*
            noisea = tvb_get_ntohis(tvb, offset);
            //noisevalida = tvb_get_uint8(tvb, offset+65)& 0x01;
            if (noisevalida == 1)
                rf_infot = proto_tree_add_float_format(vw_rfinfo_tree, hf_radiotap_rfinfo_noise,
                    tvb, offset, 8, (float)(noisea/16.0),"Noise:   A:%.2fdBm, ", (float)(noisea/16.0));
                //These are 16-bit signed numbers with four fraction bits representing NOISE in dBm.  So 0xFFFF represents -1/16 dBm.
            else
                rf_infot = proto_tree_add_float_format(vw_rfinfo_tree, hf_radiotap_rfinfo_noise,
                    tvb, offset, 8, (float)(noisea/16.0),"Noise:   A: N/A, ", (float)(noisea/16.0));
            rf_info_tree = proto_item_add_subtree(rf_infot, ett_rf_info);
            noiseb = tvb_get_ntohs(tvb, offset+2);
            noisevalidb = tvb_get_uint8(tvb, offset+67)& 0x01;
            if (noisevalidb == 1)
                proto_item_append_text(rf_infot, "B:%.2fdBm, ", (float)(noiseb/16.0));
            else
                proto_item_append_text(rf_infot, "B: N/A, ", (float)(noiseb/16.0));
            noisec = tvb_get_ntohs(tvb, offset+4);
            noisevalidc = tvb_get_uint8(tvb, offset+69)& 0x01;
            if (noisevalidc == 1)
                proto_item_append_text(rf_infot, "C:%.2fdBm, ", (float)(noisec/16.0));
            else
                proto_item_append_text(rf_infot, "C: N/A, ", (float)(noisec/16.0));
            noised = tvb_get_ntohs(tvb, offset+6);
            noisevalidd = tvb_get_uint8(tvb, offset+71)& 0x01;
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
            pfevalida = (tvb_get_uint8(tvb, offset+49)& 0x02) >>1;
            pfevalidb = (tvb_get_uint8(tvb, offset+51)& 0x02) >>1;
            pfevalidc = (tvb_get_uint8(tvb, offset+53)& 0x02) >>1;
            pfevalidd = (tvb_get_uint8(tvb, offset+55)& 0x02) >>1;
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

            frameformat = tvb_get_uint8(tvb, offset)& 0x03;
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

            frameformat = tvb_get_uint8(tvb, offset)& 0x03;
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

            frameformat = tvb_get_uint8(tvb, offset)& 0x03;
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

            frameformat = tvb_get_uint8(tvb, offset)& 0x03;
            if (frameformat == 0)
            {
                proto_tree_add_item(rfinfo_contextp_tree, hf_radiotap_rfinfo_legacytypeD, tvb, offset, 1, ENC_NA);
            }
            else
            {
                proto_tree_add_item(rfinfo_contextp_tree, hf_radiotap_rfinfo_frameformatD, tvb, offset, 1, ENC_NA);
            }

            proto_tree_add_item(rfinfo_contextp_tree, hf_radiotap_rfinfo_sigbwevmD, tvb, offset, 1, ENC_NA);
            /*offset += 2;*/
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
        else {
            if (is_octo)
                wlantap_dissect_octo(next_tvb, pinfo, tree, common_tree,
                                     cmd_type, log_mode);
            else
                wlantap_dissect(next_tvb, pinfo, tree, common_tree,
                                vw_msdu_length);
        }
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
    unsigned    length, length_remaining;
    bool        vwf_txf = false;
    ifg_info   *p_ifg_info;
    proto_item *ti;

    /* First add the IFG information */
    p_ifg_info = (struct ifg_info *) p_get_proto_data(wmem_file_scope(), pinfo, proto_ixveriwave, 0);
    ti = proto_tree_add_uint(tap_tree, hf_ixveriwave_vw_ifg,
                            tvb, offset, 0, p_ifg_info->ifg);
    proto_item_set_generated(ti);

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
            proto_tree_add_item(vw_infoFlags_tree, hf_ixveriwave_vw_info_go_no_flow,
                                tvb, offset, 2, ENC_LITTLE_ENDIAN);
            proto_tree_add_item(vw_infoFlags_tree, hf_ixveriwave_vw_info_go_with_flow,
                                tvb, offset, 2, ENC_LITTLE_ENDIAN);
        } else {
            /* it's a tx case */
            proto_tree_add_item(vw_infoFlags_tree, hf_ixveriwave_vw_info_retry_count,
                                    tvb, offset, 2, ENC_LITTLE_ENDIAN);
        }

        offset              +=2;
        length_remaining    -=2;
    }

    /*extract error , 4bytes*/
    if (length_remaining >= 4) {
        if (vwf_txf == 0) {
            /* then it's an rx case */
            static int * const vw_error_rx_flags[] = {
                &hf_ixveriwave_vw_error_1_alignment_error,
                &hf_ixveriwave_vw_error_1_packet_fcs_error,
                &hf_ixveriwave_vw_error_1_bad_magic_byte_signature,
                &hf_ixveriwave_vw_error_1_bad_payload_checksum,
                &hf_ixveriwave_vw_error_1_frame_too_long,
                &hf_ixveriwave_vw_error_1_ip_checksum_error,
                &hf_ixveriwave_vw_error_1_l4_checksum_error,
                &hf_ixveriwave_vw_error_1_id_mismatch,
                &hf_ixveriwave_vw_error_1_length_error,
                &hf_ixveriwave_vw_error_1_underflow,
                NULL
            };

            proto_tree_add_bitmask(tap_tree, tvb, offset, hf_ixveriwave_vw_error, ett_ethernettap_error, vw_error_rx_flags, ENC_LITTLE_ENDIAN);
        } else {
            /* it's a tx case */
            static int * const vw_error_tx_flags[] = {
                &hf_ixveriwave_vw_error_1_packet_fcs_error,
                &hf_ixveriwave_vw_error_1_ip_checksum_error,
                &hf_ixveriwave_vw_error_1_underflow,
                &hf_ixveriwave_vw_error_1_late_collision,
                &hf_ixveriwave_vw_error_1_excessive_collisions,
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

static int
decode_ofdm_signal(proto_tree *tree, tvbuff_t *tvb, int offset)
{
    proto_tree_add_item(tree, hf_radiotap_ofdm_rate,
                        tvb, offset, 3, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(tree, hf_radiotap_ofdm_length,
                        tvb, offset, 3, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(tree, hf_radiotap_ofdm_parity,
                        tvb, offset, 3, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(tree, hf_radiotap_ofdm_tail,
                        tvb, offset, 3, ENC_LITTLE_ENDIAN);
    return offset + 3;
}

static int
decode_ht_sig(proto_tree *tree, tvbuff_t *tvb, int offset,
              struct ieee_802_11_phdr *phdr)
{
    unsigned bw;
    unsigned stbc_streams;
    unsigned feccoding;
    bool short_gi;
    unsigned ness;

    /* HT-SIG1 */
    proto_tree_add_item(tree, hf_radiotap_ht_mcsindex,
                                tvb, offset, 3, ENC_LITTLE_ENDIAN);
    proto_tree_add_item_ret_uint(tree, hf_radiotap_ht_bw,
                                 tvb, offset, 3, ENC_LITTLE_ENDIAN,
                                 &bw);

    /*
     * XXX - how to distinguish between 20 MHz, 20+20U, and
     * 20+20L if the bit is not set?
     *
     * Or is this something that radiotap only sets for transmitted
     * packets, so you only get the total bandwidth for received
     * packets?
     */
     if (bw != 0)
     {
        phdr->phy_info.info_11n.has_bandwidth = true;
        phdr->phy_info.info_11n.bandwidth = PHDR_802_11_BANDWIDTH_40_MHZ;
    }
    proto_tree_add_item(tree, hf_radiotap_ht_length,
                        tvb, offset, 3, ENC_LITTLE_ENDIAN);
    offset += 3;

    /* HT-SIG2 */
    proto_tree_add_item(tree, hf_radiotap_ht_smoothing,
                        tvb, offset, 1, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(tree, hf_radiotap_ht_notsounding,
                        tvb, offset, 3, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(tree, hf_radiotap_ht_aggregation,
                        tvb, offset, 3, ENC_LITTLE_ENDIAN);
    proto_tree_add_item_ret_uint(tree, hf_radiotap_ht_stbc,
                                 tvb, offset, 3, ENC_LITTLE_ENDIAN,
                                 &stbc_streams);
    phdr->phy_info.info_11n.has_stbc_streams = true;
    phdr->phy_info.info_11n.stbc_streams = stbc_streams;
    proto_tree_add_item_ret_uint(tree, hf_radiotap_ht_feccoding,
                                 tvb, offset, 3, ENC_LITTLE_ENDIAN,
                                 &feccoding);
    phdr->phy_info.info_11n.has_fec = true;
    phdr->phy_info.info_11n.fec = feccoding;
    proto_tree_add_item_ret_boolean(tree, hf_radiotap_ht_short_gi,
                                    tvb, offset, 3, ENC_LITTLE_ENDIAN,
                                    &short_gi);
    phdr->phy_info.info_11n.has_short_gi = true;
    phdr->phy_info.info_11n.short_gi = short_gi;
    proto_tree_add_item_ret_uint(tree, hf_radiotap_ht_ness,
                                 tvb, offset, 3, ENC_LITTLE_ENDIAN,
                                 &ness);
    phdr->phy_info.info_11n.has_ness = true;
    phdr->phy_info.info_11n.ness = ness;
    proto_tree_add_item(tree, hf_radiotap_ht_crc,
                        tvb, offset, 3, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(tree, hf_radiotap_ht_tail,
                        tvb, offset, 3, ENC_LITTLE_ENDIAN);
    offset += 3;

    return offset;
}

static int
decode_vht_sig(proto_tree *tree, tvbuff_t *tvb, int offset,
               struct ieee_802_11_phdr *phdr)
{
    unsigned bw;
    bool stbc;
    unsigned group_id;
    unsigned partial_aid;
    bool txop_ps_not_allowed;
    bool short_gi;
    bool short_gi_nsym_disambig;
    bool ldpc_ofdmsymbol;
    bool beamformed;

    /* VHT-SIG-A1 */
    proto_tree_add_item_ret_uint(tree, hf_radiotap_vht_bw,
                                 tvb, offset, 3, ENC_LITTLE_ENDIAN,
                                 &bw);
    switch (bw)
    {
    case 0:
        phdr->phy_info.info_11ac.has_bandwidth = true;
        phdr->phy_info.info_11ac.bandwidth = PHDR_802_11_BANDWIDTH_20_MHZ;
        break;

    case 1:
        phdr->phy_info.info_11ac.has_bandwidth = true;
        phdr->phy_info.info_11ac.bandwidth = PHDR_802_11_BANDWIDTH_40_MHZ;
        break;

    case 2:
        phdr->phy_info.info_11ac.has_bandwidth = true;
        phdr->phy_info.info_11ac.bandwidth = PHDR_802_11_BANDWIDTH_80_MHZ;
        break;

    case 3:
        /* XXX - how to distinguish between 160 MHz and 80+80 MHz? */
        break;
    }
    proto_tree_add_item_ret_boolean(tree, hf_radiotap_vht_stbc,
                                    tvb, offset, 3, ENC_LITTLE_ENDIAN,
                                    &stbc);
    phdr->phy_info.info_11ac.has_stbc = true;
    phdr->phy_info.info_11ac.stbc = stbc;
    proto_tree_add_item_ret_uint(tree, hf_radiotap_vht_group_id,
                                 tvb, offset, 3, ENC_LITTLE_ENDIAN,
                                 &group_id);
    phdr->phy_info.info_11ac.has_group_id = true;
    phdr->phy_info.info_11ac.group_id = group_id;
    if ((group_id == 0) || (group_id == 63)) // SU VHT type
    {
        proto_tree_add_item(tree, hf_radiotap_vht_su_nsts,
                            tvb, offset, 3, ENC_LITTLE_ENDIAN);
        proto_tree_add_item_ret_uint(tree, hf_radiotap_vht_su_partial_aid,
                                     tvb, offset, 3, ENC_LITTLE_ENDIAN,
                                     &partial_aid);
        phdr->phy_info.info_11ac.has_partial_aid = true;
        phdr->phy_info.info_11ac.partial_aid = partial_aid;
    }
    else
    {
        // The below is MU VHT type*
        proto_tree_add_item(tree, hf_radiotap_vht_u0_nsts,
                            tvb, offset, 3, ENC_LITTLE_ENDIAN);
        proto_tree_add_item(tree, hf_radiotap_vht_u1_nsts,
                            tvb, offset, 3, ENC_LITTLE_ENDIAN);
        proto_tree_add_item(tree, hf_radiotap_vht_u2_nsts,
                            tvb, offset, 3, ENC_LITTLE_ENDIAN);
        proto_tree_add_item(tree, hf_radiotap_vht_u3_nsts,
                            tvb, offset, 3, ENC_LITTLE_ENDIAN);
    }
    proto_tree_add_item_ret_boolean(tree, hf_radiotap_vht_txop_ps_not_allowed,
                                    tvb, offset, 3, ENC_LITTLE_ENDIAN,
                                    &txop_ps_not_allowed);
    phdr->phy_info.info_11ac.has_txop_ps_not_allowed = true;
    phdr->phy_info.info_11ac.txop_ps_not_allowed = txop_ps_not_allowed;
    offset += 3;

    /* VHT-SIG-A2 */
    proto_tree_add_item_ret_boolean(tree, hf_radiotap_vht_short_gi,
                                    tvb, offset, 3, ENC_LITTLE_ENDIAN,
                                    &short_gi);
    phdr->phy_info.info_11ac.has_short_gi = true;
    phdr->phy_info.info_11ac.short_gi = short_gi;
    proto_tree_add_item_ret_boolean(tree, hf_radiotap_vht_short_gi_nsym_disambig,
                                    tvb, offset, 3, ENC_LITTLE_ENDIAN,
                                    &short_gi_nsym_disambig);
    phdr->phy_info.info_11ac.has_short_gi_nsym_disambig = true;
    phdr->phy_info.info_11ac.short_gi_nsym_disambig = short_gi_nsym_disambig;
    if ((group_id == 0) || (group_id == 63)) // SU VHT type
    {
        proto_tree_add_item(tree, hf_radiotap_vht_su_coding_type,
                            tvb, offset, 3, ENC_LITTLE_ENDIAN);
    }
    else
    {
        // it is MU MIMO type BCC coding
        // extract U0 Coding
        proto_tree_add_item(tree, hf_radiotap_vht_u0_coding_type,
                            tvb, offset, 3, ENC_LITTLE_ENDIAN);
    }
    proto_tree_add_item_ret_boolean(tree, hf_radiotap_vht_ldpc_ofdmsymbol,
                                    tvb, offset, 3, ENC_LITTLE_ENDIAN,
                                    &ldpc_ofdmsymbol);
    phdr->phy_info.info_11ac.has_ldpc_extra_ofdm_symbol = true;
    phdr->phy_info.info_11ac.ldpc_extra_ofdm_symbol = ldpc_ofdmsymbol;
    if ((group_id == 0) || (group_id == 63)) // SU VHT type
    {
        proto_tree_add_item(tree, hf_radiotap_vht_su_mcs,
                            tvb, offset, 3, ENC_LITTLE_ENDIAN);
        proto_tree_add_item_ret_boolean(tree, hf_radiotap_vht_beamformed,
                                        tvb, offset, 3, ENC_LITTLE_ENDIAN,
                                        &beamformed);
        phdr->phy_info.info_11ac.has_beamformed = true;
        phdr->phy_info.info_11ac.beamformed = beamformed;
    }
    else
    {
        // extract U1 Coding type
        proto_tree_add_item(tree, hf_radiotap_vht_u1_coding_type,
                            tvb, offset, 3, ENC_LITTLE_ENDIAN);

        // extract U2 Coding type
        proto_tree_add_item(tree, hf_radiotap_vht_u2_coding_type,
                            tvb, offset, 3, ENC_LITTLE_ENDIAN);

        // extract U3 Coding type
        proto_tree_add_item(tree, hf_radiotap_vht_u3_coding_type,
                            tvb, offset, 3, ENC_LITTLE_ENDIAN);
        // reserved
    }
    proto_tree_add_item(tree, hf_radiotap_vht_crc,
                        tvb, offset, 3, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(tree, hf_radiotap_vht_tail,
                        tvb, offset, 3, ENC_LITTLE_ENDIAN);
    offset += 3;

    /* VHT-SIG-B */
    if ((group_id == 0) || (group_id == 63)) // SU VHT type
    {
        switch (bw)
        {
        case VHT_BW_20_MHZ:
            proto_tree_add_item(tree, hf_radiotap_vht_su_sig_b_length_20_mhz,
                                tvb, offset, 4, ENC_LITTLE_ENDIAN);
            break;

        case VHT_BW_40_MHZ:
            proto_tree_add_item(tree, hf_radiotap_vht_su_sig_b_length_40_mhz,
                                tvb, offset, 4, ENC_LITTLE_ENDIAN);
            break;

        case VHT_BW_80_MHZ:
        case VHT_BW_160_MHZ:
            proto_tree_add_item(tree, hf_radiotap_vht_su_sig_b_length_80_160_mhz,
                                tvb, offset, 4, ENC_LITTLE_ENDIAN);
            break;
        }
    }
    else
    {
        switch (bw)
        {
        case VHT_BW_20_MHZ:
            proto_tree_add_item(tree, hf_radiotap_vht_mu_sig_b_length_20_mhz,
                                tvb, offset, 4, ENC_LITTLE_ENDIAN);
            proto_tree_add_item(tree, hf_radiotap_vht_mu_mcs_20_mhz,
                                tvb, offset, 4, ENC_LITTLE_ENDIAN);
            break;

        case VHT_BW_40_MHZ:
            proto_tree_add_item(tree, hf_radiotap_vht_mu_sig_b_length_40_mhz,
                                tvb, offset, 4, ENC_LITTLE_ENDIAN);
            proto_tree_add_item(tree, hf_radiotap_vht_mu_mcs_40_mhz,
                                tvb, offset, 4, ENC_LITTLE_ENDIAN);
            break;

        case VHT_BW_80_MHZ:
        case VHT_BW_160_MHZ:
            proto_tree_add_item(tree, hf_radiotap_vht_mu_sig_b_length_80_160_mhz,
                                tvb, offset, 4, ENC_LITTLE_ENDIAN);
            proto_tree_add_item(tree, hf_radiotap_vht_mu_mcs_80_160_mhz,
                                        tvb, offset, 4, ENC_LITTLE_ENDIAN);
            break;
        }
    }
    offset += 4;

    return offset;
}

static void
wlantap_dissect(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
                proto_tree *tap_tree, uint16_t vw_msdu_length)
{
    proto_tree *ft, *flags_tree         = NULL;
    int         align_offset, offset;
    tvbuff_t   *next_tvb;
    unsigned    length;
    int8_t      dbm;
    uint8_t     rate_mcs_index = 0;
    uint8_t     plcp_type;
    uint8_t     vht_ndp_flag, vht_mu_mimo_flg;
    float       phyRate;

    proto_tree *vweft, *vw_errorFlags_tree = NULL;
    uint16_t    vw_info, vw_chanflags, vw_flags, vw_ht_length, vw_rflags;
    uint32_t    vw_errors;
    uint8_t     vht_user_pos;

    ifg_info   *p_ifg_info;
    proto_item *ti;
    bool        short_preamble;
    uint8_t     nss;

    struct ieee_802_11_phdr phdr;

    /* We don't have any 802.11 metadata yet. */
    memset(&phdr, 0, sizeof(phdr));
    phdr.fcs_len = -1;
    phdr.decrypted = false;
    phdr.datapad = false;
    phdr.phy = PHDR_802_11_PHY_UNKNOWN;

    //Command type Rx = 0, Tx = 1, RF = 3, RF_RX = 4
    //log mode = 0 is normal capture and 1 is reduced capture

    /* Pre-OCTO. */
    /* First add the IFG information, need to grab the info bit field here */
    vw_info = tvb_get_letohs(tvb, 20);
    p_ifg_info = (struct ifg_info *) p_get_proto_data(wmem_file_scope(), pinfo, proto_ixveriwave, 0);
    if ((vw_info & INFO_MPDU_OF_A_MPDU) && !(vw_info & INFO_FIRST_MPDU_OF_A_MPDU))  /* If the packet is part of an A-MPDU but not the first MPDU */
        ti = proto_tree_add_uint(tap_tree, hf_ixveriwave_vw_ifg, tvb, 18, 0, 0);
    else
        ti = proto_tree_add_uint(tap_tree, hf_ixveriwave_vw_ifg, tvb, 18, 0, p_ifg_info->ifg);
    proto_item_set_generated(ti);

    offset      = 0;
    /* header length */
    length = tvb_get_letohs(tvb, offset);
    offset      += 2;

    /* rflags */
    vw_rflags = tvb_get_letohs(tvb, offset);
    phdr.fcs_len = 0;

    ft = proto_tree_add_item(tap_tree, hf_radiotap_flags, tvb, offset, 2, ENC_LITTLE_ENDIAN);
    flags_tree = proto_item_add_subtree(ft, ett_radiotap_flags);
    proto_tree_add_item_ret_boolean(flags_tree, hf_radiotap_flags_preamble, tvb, offset, 2, ENC_LITTLE_ENDIAN, &short_preamble);
    proto_tree_add_item(flags_tree, hf_radiotap_flags_wep, tvb, offset, 2, ENC_LITTLE_ENDIAN);
    if ( vw_rflags & FLAGS_CHAN_HT ) {
        proto_tree_add_item(flags_tree, hf_radiotap_flags_ht, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        proto_tree_add_item(flags_tree, hf_radiotap_flags_40mhz, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        proto_tree_add_item(flags_tree, hf_radiotap_flags_short_gi, tvb, offset, 2, ENC_LITTLE_ENDIAN);
    }
    if ( vw_rflags & FLAGS_CHAN_VHT ) {
        proto_tree_add_item(flags_tree, hf_radiotap_flags_vht, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        proto_tree_add_item(flags_tree, hf_radiotap_flags_short_gi, tvb, offset, 2, ENC_LITTLE_ENDIAN);
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
    plcp_type = tvb_get_uint8(tvb,offset) & 0x03;
    vht_ndp_flag = tvb_get_uint8(tvb,offset) & 0x80;
    offset++;

    /* Rate/MCS index */
    rate_mcs_index = tvb_get_uint8(tvb, offset);
    offset++;

    /* number of spatial streams */
    nss = tvb_get_uint8(tvb, offset);
    offset++;

    if ((vw_rflags & FLAGS_CHAN_HT) || (vw_rflags & FLAGS_CHAN_VHT)) {
        if (vw_rflags & FLAGS_CHAN_VHT) {
            phdr.phy = PHDR_802_11_PHY_11AC;
            phdr.phy_info.info_11ac.has_short_gi = true;
            phdr.phy_info.info_11ac.short_gi = ((vw_rflags & FLAGS_CHAN_SHORTGI) != 0);
            /*
             * XXX - this probably has only one user, so only one MCS index
             * and only one NSS.
             */
            phdr.phy_info.info_11ac.nss[0] = nss;
            phdr.phy_info.info_11ac.mcs[0] = rate_mcs_index;
        } else {
            /*
             * XXX - where's the number of extension spatial streams?
             * The code in wiretap/vwr.c doesn't seem to provide it.
             * It could dig it out of the HT PLCP header in HT-SIG.
             */
            phdr.phy = PHDR_802_11_PHY_11N;
            phdr.phy_info.info_11n.has_mcs_index = true;
            phdr.phy_info.info_11n.mcs_index = rate_mcs_index;

            phdr.phy_info.info_11n.has_short_gi = true;
            phdr.phy_info.info_11n.short_gi = ((vw_rflags & FLAGS_CHAN_SHORTGI) != 0);

            phdr.phy_info.info_11n.has_greenfield = true;
            phdr.phy_info.info_11n.greenfield = (plcp_type == PLCP_TYPE_GREENFIELD);
        }

        proto_tree_add_item(tap_tree, hf_radiotap_mcsindex,
                            tvb, offset - 2, 1, ENC_BIG_ENDIAN);

        proto_tree_add_item(tap_tree, hf_radiotap_nss,
                            tvb, offset - 1, 1, ENC_BIG_ENDIAN);

        proto_tree_add_uint_format_value(tap_tree, hf_radiotap_datarate,
                                    tvb, offset - 5, 2, tvb_get_letohs(tvb, offset-5),
                                    "%.1f (MCS %d)", phyRate, rate_mcs_index);
    } else {
        /*
         * XXX - CHAN_OFDM could be 11a or 11g.  Unfortunately, we don't
         * have the frequency, or anything else, to distinguish between
         * them.
         */
        if (vw_chanflags & CHAN_CCK) {
            phdr.phy = PHDR_802_11_PHY_11B;
            phdr.phy_info.info_11b.has_short_preamble = true;
            phdr.phy_info.info_11b.short_preamble = short_preamble;
        }
        phdr.has_data_rate = true;
        phdr.data_rate = tvb_get_letohs(tvb, offset-5) / 5;

        proto_tree_add_uint_format_value(tap_tree, hf_radiotap_datarate,
            tvb, offset - 5, 2, tvb_get_letohs(tvb, offset-5),
            "%.1f Mb/s", phyRate);
    }
    col_add_fstr(pinfo->cinfo, COL_TX_RATE, "%.1f", phyRate);

    /* RSSI/antenna A RSSI */
    dbm = tvb_get_int8(tvb, offset);
    phdr.has_signal_dbm = true;
    phdr.signal_dbm = dbm;
    col_add_fstr(pinfo->cinfo, COL_RSSI, "%d dBm", dbm);
    proto_tree_add_item(tap_tree, hf_radiotap_dbm_anta, tvb, offset, 1, ENC_NA);
    offset++;

    /* Antenna B RSSI, or 100 if absent */
    dbm = tvb_get_int8(tvb, offset);
    if (dbm != 100) {
        proto_tree_add_item(tap_tree, hf_radiotap_dbm_antb, tvb, offset, 1, ENC_NA);
    }
    offset++;

    /* Antenna C RSSI, or 100 if absent */
    dbm = tvb_get_int8(tvb, offset);
    if (dbm != 100) {
        proto_tree_add_item(tap_tree, hf_radiotap_dbm_antc, tvb, offset, 1, ENC_NA);
    }
    offset++;

    /* Antenna D RSSI, or 100 if absent */
    dbm = tvb_get_int8(tvb, offset);
    if (dbm != 100) {
        proto_tree_add_item(tap_tree, hf_radiotap_dbm_antd, tvb, offset, 1, ENC_NA);
    }
    offset+=2;  /* also skips padding octet */

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
#if 0
        if (plcp_type == PLCP_TYPE_VHT_MIXED)
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
#endif
    }
    offset      += 2;

    align_offset = ALIGN_OFFSET(offset, 2);
    offset += align_offset;

    /* info */
    if (!(vw_flags & VW_RADIOTAPF_TXF)) {                   /* then it's an rx case */
        /*FPGA_VER_vVW510021 version decodes */
        static int * const vw_info_rx_2_flags[] = {
            &hf_radiotap_vw_info_2_ack_withheld_from_frame,
            &hf_radiotap_vw_info_2_sent_cts_to_self_before_data,
            &hf_radiotap_vw_info_2_mpdu_of_a_mpdu,
            &hf_radiotap_vw_info_2_first_mpdu_of_a_mpdu,
            &hf_radiotap_vw_info_2_last_pdu_of_a_mpdu,
            &hf_radiotap_vw_info_2_msdu_of_a_msdu,
            &hf_radiotap_vw_info_2_first_msdu_of_a_msdu,
            &hf_radiotap_vw_info_2_last_msdu_of_a_msdu,
            NULL
        };

        proto_tree_add_bitmask(tap_tree, tvb, offset, hf_radiotap_vw_info, ett_radiotap_info, vw_info_rx_2_flags, ENC_LITTLE_ENDIAN);

    } else {                                    /* it's a tx case */
        static int * const vw_info_tx_2_flags[] = {
            &hf_radiotap_vw_info_2_mpdu_of_a_mpdu,
            &hf_radiotap_vw_info_2_first_mpdu_of_a_mpdu,
            &hf_radiotap_vw_info_2_last_pdu_of_a_mpdu,
            &hf_radiotap_vw_info_2_msdu_of_a_msdu,
            &hf_radiotap_vw_info_2_first_msdu_of_a_msdu,
            &hf_radiotap_vw_info_2_last_msdu_of_a_msdu,
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
            hf_radiotap_vw_errors_rx_2_crc16_or_parity_error, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        proto_tree_add_item(vw_errorFlags_tree,
            hf_radiotap_vw_errors_rx_2_non_supported_rate_or_service_field, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        proto_tree_add_item(vw_errorFlags_tree,
            hf_radiotap_vw_errors_rx_2_short_frame, tvb, offset, 2, ENC_LITTLE_ENDIAN);

        /* veriwave removed 8-2007, don't display reserved bit*/

        proto_tree_add_item(vw_errorFlags_tree,
            hf_radiotap_vw_errors_rx_2_fcs_error, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        proto_tree_add_item(vw_errorFlags_tree,
            hf_radiotap_vw_errors_rx_2_l2_de_aggregation_error, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        proto_tree_add_item(vw_errorFlags_tree,
            hf_radiotap_vw_errors_rx_2_duplicate_mpdu, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        proto_tree_add_item(vw_errorFlags_tree,
            hf_radiotap_vw_errors_rx_2_bad_flow_magic_number, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        proto_tree_add_item(vw_errorFlags_tree,
            hf_radiotap_vw_errors_rx_2_flow_payload_checksum_error, tvb, offset, 2, ENC_LITTLE_ENDIAN);

        proto_tree_add_item(vw_errorFlags_tree,
        hf_radiotap_vw_errors_rx_2_ip_checksum_error, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        proto_tree_add_item(vw_errorFlags_tree,
        hf_radiotap_vw_errors_rx_2_l4_checksum_error, tvb, offset, 2, ENC_LITTLE_ENDIAN);

    } else {                                  /* it's a tx case */
        /* FPGA_VER_vVW510021 and VW_FPGA_VER_vVW510006 tx error decodes same*/

        proto_tree_add_item(vw_errorFlags_tree,
                            hf_radiotap_vw_errors_tx_packet_fcs_error, tvb, offset, 2, ENC_LITTLE_ENDIAN);

        proto_tree_add_item(vw_errorFlags_tree,
                            hf_radiotap_vw_errors_tx_ip_checksum_error, tvb, offset, 2, ENC_LITTLE_ENDIAN);

    }
    offset += 4;

    /*** POPULATE THE AMSDU VHT MIXED MODE CONTAINER FORMAT ***/
    /* XXX - what about other modes?  PLCP here? */
    if ((vw_rflags & FLAGS_CHAN_VHT) && vw_ht_length != 0)
    {
        if (plcp_type == PLCP_TYPE_VHT_MIXED) //If the frame is VHT type
        {
            offset += 4; /*** 4 bytes of ERROR ***/

            /*** Extract SU/MU MIMO flag from RX L1 Info ***/
            vht_user_pos = tvb_get_uint8(tvb, offset);
            vht_mu_mimo_flg = (vht_user_pos & 0x08) >> 3;

            if (vht_mu_mimo_flg == 1) {
                proto_tree_add_item(tap_tree, hf_radiotap_vht_mu_mimo_flg, tvb, offset, 1, ENC_NA);

                /*** extract user Position in case of mu-mimo ***/
                proto_tree_add_item(tap_tree, hf_radiotap_vht_user_pos, tvb, offset, 1, ENC_NA);

            } else {
                proto_tree_add_item(tap_tree, hf_radiotap_vht_su_mimo_flg, tvb, offset, 1, ENC_NA);
            }
            offset += 1; /*** skip the RX L1 Info byte ****/

            /* L-SIG */
            offset = decode_ofdm_signal(tap_tree, tvb, offset);

            /* VHT-SIG */
            /* XXX - does this include VHT-SIG-B? */
            decode_vht_sig(tap_tree, tvb, offset, &phdr);
        }
    }

    /* Grab the rest of the frame. */
    if (plcp_type == PLCP_TYPE_VHT_MIXED) {
        length = length + 17; /*** 16 bytes of PLCP + 1 byte of L1InfoC(UserPos) **/
    }

    next_tvb = tvb_new_subset_remaining(tvb, length);

    /* dissect the 802.11 radio information and header next */
    call_dissector_with_data(ieee80211_radio_handle, next_tvb, pinfo, tree, &phdr);
}


static void
wlantap_dissect_octo(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
                     proto_tree *tap_tree, uint8_t cmd_type, int log_mode)
{
    int         offset;
    tvbuff_t   *next_tvb;
    unsigned    length;
    int8_t      dbm;
    uint8_t     rate_mcs_index = 0, vw_bssid;
    uint8_t     plcp_type;
    uint8_t     vht_ndp_flag, vht_mu_mimo_flg;
    float       phyRate;

    proto_tree *vwict, *vw_infoC_tree = NULL;
    uint16_t    vw_vcid, mpdu_length;
    uint32_t    vw_seqnum;
    uint32_t    vht_user_pos;
    uint8_t     plcp_default;

    proto_item *vwl1i;
    proto_tree *vw_l1info_tree = NULL, *vwl2l4t,*vw_l2l4info_tree = NULL, *vwplt,*vw_plcpinfo_tree = NULL;
    bool        direction, short_preamble;
    uint8_t     nss, sigbw, cidv, bssidv, flowv, l4idv;

    struct ieee_802_11_phdr phdr;

    /* We don't have any 802.11 metadata yet. */
    memset(&phdr, 0, sizeof(phdr));
    phdr.fcs_len = -1;
    phdr.decrypted = false;
    phdr.datapad = false;
    phdr.phy = PHDR_802_11_PHY_UNKNOWN;

    //Command type Rx = 0, Tx = 1, RF = 3, RF_RX = 4
    //log mode = 0 is normal capture and 1 is reduced capture

    /*
     * FPGA version is non-zero, meaning this is OCTO.
     * The first part is a timestamp header.
     */
    //RadioTapHeader New format for L1Info
    offset      = 0;

    length = tvb_get_letohs(tvb, offset);
    offset      += 2;

    vwl1i = proto_tree_add_item(tap_tree, hf_radiotap_l1info, tvb, offset, 12, ENC_NA);
    vw_l1info_tree = proto_item_add_subtree(vwl1i, ett_radiotap_layer1);

    plcp_type = tvb_get_uint8(tvb, offset+4) & 0x0f;

    /* l1p_1 byte */
    switch (plcp_type)
    {
    case PLCP_TYPE_LEGACY:     /* Legacy (pre-HT - 11b/11a/11g) */
        /*
         * XXX - CHAN_OFDM could be 11a or 11g.  Unfortunately, we don't
         * have the frequency, or anything else, to distinguish between
         * them.
         */
        short_preamble = !(tvb_get_uint8(tvb, offset) & 0x40);
        proto_tree_add_boolean(vw_l1info_tree, hf_radiotap_l1info_preamble,
                               tvb, offset, 1, short_preamble);
        rate_mcs_index = tvb_get_uint8(tvb, offset) & 0x3f;
        proto_tree_add_uint(vw_l1info_tree, hf_radiotap_l1info_rateindex,
                            tvb, offset, 1, rate_mcs_index);
        if (rate_mcs_index < 4)
        {
            /* CCK */
            phdr.phy = PHDR_802_11_PHY_11B;
            phdr.phy_info.info_11b.has_short_preamble = true;
            phdr.phy_info.info_11b.short_preamble = short_preamble;
        }
        break;

    case PLCP_TYPE_MIXED:      /* HT Mixed */
    case PLCP_TYPE_GREENFIELD: /* HT Greenfield */
        rate_mcs_index = tvb_get_uint8(tvb, offset) & 0x3f;
        proto_tree_add_uint(vw_l1info_tree, hf_radiotap_l1info_ht_mcsindex,
                            tvb, offset, 1, rate_mcs_index);
        phdr.phy = PHDR_802_11_PHY_11N;
        phdr.phy_info.info_11n.has_mcs_index = true;
        phdr.phy_info.info_11n.mcs_index = rate_mcs_index;
        phdr.phy_info.info_11n.has_greenfield = true;
        phdr.phy_info.info_11n.greenfield = (plcp_type == PLCP_TYPE_GREENFIELD);
        break;

    case PLCP_TYPE_VHT_MIXED:  /* VHT Mixed */
        rate_mcs_index = tvb_get_uint8(tvb, offset) & 0x0f;
        proto_tree_add_uint(vw_l1info_tree, hf_radiotap_l1info_vht_mcsindex,
                            tvb, offset, 1, rate_mcs_index);
        phdr.phy = PHDR_802_11_PHY_11AC;
        /*
         * XXX - this probably has only one user, so only one MCS index.
         */
        phdr.phy_info.info_11ac.mcs[0] = rate_mcs_index;
    }
    offset++;

    /* NSS and direction octet */
    switch (plcp_type)
    {
    case PLCP_TYPE_LEGACY:     /* Legacy (pre-HT - 11b/11a/11g) */
        break;

    case PLCP_TYPE_MIXED:      /* HT Mixed */
    case PLCP_TYPE_GREENFIELD: /* HT Greenfield (Not supported) */
        nss = (tvb_get_uint8(tvb, offset) & 0xf0) >> 4;
        proto_tree_add_uint(vw_l1info_tree, hf_radiotap_l1info_nss,
                            tvb, offset, 1, nss);
        break;

    case PLCP_TYPE_VHT_MIXED:  /* VHT Mixed */
        nss = (tvb_get_uint8(tvb, offset) & 0xf0) >> 4;
        proto_tree_add_uint(vw_l1info_tree, hf_radiotap_l1info_nss,
                            tvb, offset, 1, nss);
        /*
         * XXX - this probably has only one user, so only one NSS.
         */
        phdr.phy_info.info_11ac.nss[0] = nss;
        break;
    }
    direction = ((tvb_get_uint8(tvb, offset) & 0x01) != 0);
    proto_tree_add_boolean(vw_l1info_tree, hf_radiotap_l1info_transmitted,
                           tvb, offset, 1, direction);
    proto_item_append_text(vwl1i, " (Direction=%s)",
                           direction ? "Transmit" : "Receive");
    offset++;

    /* New pieces of lines for
     * #802.11 radio information#
     * Referred from code changes done for old FPGA version
     * **/
    phdr.fcs_len = (log_mode == 3) ? 0 : 4;

    switch (plcp_type)
    {
    case PLCP_TYPE_LEGACY:     /* Legacy (pre-HT - 11b/11a/11g) */
        phdr.has_data_rate = true;
        phdr.data_rate = tvb_get_letohs(tvb, offset) / 5;
        break;

    case PLCP_TYPE_MIXED:      /* HT Mixed */
    case PLCP_TYPE_GREENFIELD: /* HT Greenfield (Not supported) */
    case PLCP_TYPE_VHT_MIXED:  /* VHT Mixed */
        break;
    }

    phyRate = (float)tvb_get_letohs(tvb, offset) / 10;
    proto_tree_add_uint_format_value(vw_l1info_tree, hf_radiotap_datarate,
                tvb, offset, 2, tvb_get_letohs(tvb, offset),
                "%.1f Mb/s", phyRate);
    offset = offset + 2;
    col_add_fstr(pinfo->cinfo, COL_TX_RATE, "%.1f", phyRate);

    sigbw = (tvb_get_uint8(tvb, offset) & 0xf0) >> 4;
    plcp_type = tvb_get_uint8(tvb, offset) & 0x0f;
    proto_tree_add_uint(vw_l1info_tree,
            hf_radiotap_sigbandwidth, tvb, offset, 1, sigbw);

    if (plcp_type != PLCP_TYPE_LEGACY)
    {
        /* HT or VHT */
        proto_tree_add_uint(vw_l1info_tree,
            hf_radiotap_modulation, tvb, offset, 1, plcp_type);
    }
    else
    {
        /* pre-HT */
        if (rate_mcs_index < 4)
            proto_tree_add_uint_format_value(vw_l1info_tree, hf_radiotap_modulation,
                tvb, offset, 1, plcp_type, "CCK (%u)", plcp_type);
        else
            proto_tree_add_uint_format_value(vw_l1info_tree, hf_radiotap_modulation,
                tvb, offset, 1, plcp_type, "OFDM (%u)", plcp_type);
    }
    offset++;

    dbm = tvb_get_int8(tvb, offset);

    phdr.has_signal_dbm = true;
    phdr.signal_dbm = dbm;

    col_add_fstr(pinfo->cinfo, COL_RSSI, "%d dBm", dbm);

    if (cmd_type != 1)
        proto_tree_add_item(vw_l1info_tree, hf_radiotap_dbm_anta,
                                tvb, offset, 1, ENC_NA);
    else
        proto_tree_add_item(vw_l1info_tree, hf_radiotap_dbm_tx_anta,
                                tvb, offset, 1, ENC_NA);
    offset++;

    dbm = tvb_get_int8(tvb, offset);
    if (dbm != 100) {
        if (cmd_type != 1)
            proto_tree_add_item(vw_l1info_tree, hf_radiotap_dbm_antb,
                                        tvb, offset, 1, ENC_NA);
        else
            proto_tree_add_item(vw_l1info_tree,
                                    hf_radiotap_dbm_tx_antb,
                                    tvb, offset, 1, ENC_NA);
    }
    offset++;

    dbm = tvb_get_int8(tvb, offset);
    if (dbm != 100) {
        if (cmd_type != 1)
            proto_tree_add_item(vw_l1info_tree, hf_radiotap_dbm_antc,
                                    tvb, offset, 1, ENC_NA);
        else
            proto_tree_add_item(vw_l1info_tree, hf_radiotap_dbm_tx_antc,
                                    tvb, offset, 1, ENC_NA);
    }
    offset++;

    dbm = tvb_get_int8(tvb, offset);
    if (dbm != 100) {
        if (cmd_type != 1)
            proto_tree_add_item(vw_l1info_tree, hf_radiotap_dbm_antd,
                                    tvb, offset, 1, ENC_NA);
        else
            proto_tree_add_item(vw_l1info_tree,
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
    if (plcp_type == PLCP_TYPE_VHT_MIXED)
    {
        proto_tree_add_item(vw_l1info_tree, hf_radiotap_mumask, tvb, offset, 1, ENC_NA);
    }
    offset++;

    if (plcp_type == PLCP_TYPE_VHT_MIXED)
    {
        // Extract SU/MU MIMO flag from RX L1 Info
        vht_user_pos  = tvb_get_uint8(tvb, offset);
        vwict = proto_tree_add_item(vw_l1info_tree,
                hf_radiotap_l1infoc, tvb, offset, 1, ENC_NA);
        vw_infoC_tree = proto_item_add_subtree(vwict, ett_radiotap_infoc);

        vht_ndp_flag = (vht_user_pos & 0x80) >> 7;
        vht_mu_mimo_flg = (vht_user_pos & 0x08) >> 3;
        proto_tree_add_item(vw_infoC_tree, hf_radiotap_vht_ndp_flg, tvb, offset, 1, ENC_NA);
        if (vht_ndp_flag == 0)
        {
            if (vht_mu_mimo_flg == 1) {
                proto_tree_add_uint(vw_infoC_tree, hf_radiotap_vht_mu_mimo_flg,
                    tvb, offset, 1, vht_mu_mimo_flg);

                // extract user Position in case of mu-mimo
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
        proto_tree_add_item(vw_l1info_tree, hf_ixveriwave_frame_length, tvb, offset, 2, ENC_LITTLE_ENDIAN);
    }
    offset      += 2;

    //RadioTapHeader New format for PLCP section
    //vw_plcp_info = tvb_get_uint8(tvb, offset);

    vwplt = proto_tree_add_item(tap_tree, hf_radiotap_plcp_info, tvb, offset, 16, ENC_NA);
    vw_plcpinfo_tree = proto_item_add_subtree(vwplt, ett_radiotap_plcp);

    switch (plcp_type)
    {
    case PLCP_TYPE_LEGACY:
        if (rate_mcs_index < 4)
        {
            /*
             * From IEEE Std 802.11-2012:
             *
             * According to section 17.2.2 "PPDU format", the PLCP header
             * for the High Rate DSSS PHY (11b) has a SIGNAL field that's
             * 8 bits, followed by a SERVICE field that's 8 bits, followed
             * by a LENGTH field that's 16 bits, followed by a CRC field
             * that's 16 bits.  The PSDU follows it.  Section 17.2.3 "PPDU
             * field definitions" describes those fields.
             *
             * According to section 19.3.2 "PPDU format", the frames for the
             * Extended Rate PHY (11g) either extend the 11b format, using
             * additional bits in the SERVICE field, or extend the 11a
             * format.
             */
            proto_tree_add_uint_format(vw_plcpinfo_tree, hf_radiotap_plcp_type,
                tvb, offset-10, 1, plcp_type, "Format: Legacy CCK ");
            proto_tree_add_item(vw_plcpinfo_tree, hf_radiotap_plcp_signal,
                                tvb, offset, 1, ENC_LITTLE_ENDIAN);
            offset += 1;

            proto_tree_add_item(vw_plcpinfo_tree, hf_radiotap_plcp_locked_clocks,
                                tvb, offset, 1, ENC_LITTLE_ENDIAN);
            proto_tree_add_item(vw_plcpinfo_tree, hf_radiotap_plcp_modulation,
                                tvb, offset, 1, ENC_LITTLE_ENDIAN);
            proto_tree_add_item(vw_plcpinfo_tree, hf_radiotap_plcp_length_extension,
                                tvb, offset, 1, ENC_LITTLE_ENDIAN);
            offset += 1;

            proto_tree_add_item(vw_plcpinfo_tree, hf_radiotap_plcp_length,
                                tvb, offset, 2, ENC_LITTLE_ENDIAN);
            offset += 2;

            proto_tree_add_item(vw_plcpinfo_tree, hf_radiotap_plcp_crc16,
                                tvb, offset, 2, ENC_LITTLE_ENDIAN);
            offset += 2;

            /* Presumably padding */
            offset += 9;
        }
        else
        {
            /*
             * From IEEE Std 802.11-2012:
             *
             * According to sections 18.3.2 "PLCP frame format" and 18.3.4
             * "SIGNAL field", the PLCP for the OFDM PHY (11a) has a SIGNAL
             * field that's 24 bits, followed by a service field that's
             * 16 bits, followed by the PSDU.  Section 18.3.5.2 "SERVICE
             * field" describes the SERVICE field.
             *
             * According to section 19.3.2 "PPDU format", the frames for the
             * Extended Rate PHY (11g) either extend the 11b format, using
             * additional bits in the SERVICE field, or extend the 11a
             * format.
             */
            proto_tree_add_uint_format(vw_plcpinfo_tree, hf_radiotap_plcp_default,
                tvb, offset, 1, plcp_type, "Format: Legacy OFDM ");

            /* SIGNAL */
            offset = decode_ofdm_signal(vw_plcpinfo_tree, tvb, offset);

            /* SERVICE */
            proto_tree_add_item(vw_plcpinfo_tree, hf_radiotap_ofdm_service,
                                tvb, offset, 2, ENC_LITTLE_ENDIAN);
            offset += 2;

            /* Presumably just padding */
            offset += 10;
        }
        break;

    case PLCP_TYPE_MIXED:
        /*
         * From IEEE Std 802.11-2012:
         *
         * According to section 20.3.2 "PPDU format", the HT-mixed
         * PLCP header has a "Non-HT SIGNAL field" (L-SIG), which
         * looks like an 11a SIGNAL field, followed by an HT SIGNAL
         * field (HT-SIG) described in section 20.3.9.4.3 "HT-SIG
         * definition".
         */
        proto_tree_add_uint_format(vw_plcpinfo_tree, hf_radiotap_plcp_default,
            tvb, offset, 1, plcp_type, "Format: HT ");

        /* L-SIG */
        offset = decode_ofdm_signal(vw_plcpinfo_tree, tvb, offset);

        /* HT-SIG */
        offset = decode_ht_sig(vw_plcpinfo_tree, tvb, offset, &phdr);

        proto_tree_add_item(vw_plcpinfo_tree, hf_radiotap_ofdm_service,
                            tvb, offset, 2, ENC_LITTLE_ENDIAN);
        offset += 2;

        /* Are these 4 bytes significant, or are they just padding? */
        offset += 4;
        break;

    case PLCP_TYPE_GREENFIELD:
        /*
         * From IEEE Std 802.11-2012:
         *
         * According to section 20.3.2 "PPDU format", the HT-greenfield
         * PLCP header just has the HT SIGNAL field (HT-SIG) above, with
         * no L-SIG field.
         */
        /* HT-SIG */
        offset = decode_ht_sig(vw_plcpinfo_tree, tvb, offset, &phdr);

        /*
         * XXX - does this follow the PLCP header for HT greenfield?
         * It immediately follows the PLCP header for other PHYs.
         */
        proto_tree_add_item(vw_plcpinfo_tree, hf_radiotap_ofdm_service,
                            tvb, offset, 2, ENC_LITTLE_ENDIAN);
        offset += 2;

        /*
         * XXX - if so, is this padding, or significant?
         */
        offset += 7;
        break;

    case PLCP_TYPE_VHT_MIXED:
        /*
         * According to section 22.3.2 "VHT PPDU format" of IEEE Std
         * 802.11ac-2013, the VHT PLCP header has a "non-HT SIGNAL field"
         * (L-SIG), which looks like an 11a SIGNAL field, followed by
         * a VHT Signal A field (VHT-SIG-A) described in section
         * 22.3.8.3.3 "VHT-SIG-A definition", with training fields
         * between it and a VHT Signal B field (VHT-SIG-B) described
         * in section 22.3.8.3.6 "VHT-SIG-B definition", followed by
         * the PSDU.
         */
        proto_tree_add_uint_format(vw_plcpinfo_tree, hf_radiotap_plcp_default,
            tvb, offset, 1, plcp_type, "Format: VHT ");

        /* L-SIG */
        offset = decode_ofdm_signal(vw_plcpinfo_tree, tvb, offset);

        /* VHT-SIG */
        offset = decode_vht_sig(vw_plcpinfo_tree, tvb, offset, &phdr);
        break;

    default:
        proto_tree_add_uint_format(vw_plcpinfo_tree, hf_radiotap_plcp_default,
            tvb, offset, 1, plcp_type, "Format: Null ");
        plcp_default = tvb_get_uint8(tvb, offset);
        proto_tree_add_uint_format(vw_plcpinfo_tree, hf_radiotap_plcp_default,
            tvb, offset, 1, plcp_default, "PLCP0: %u ", plcp_default);
        offset = offset + 1;
        plcp_default = tvb_get_uint8(tvb, offset);
        proto_tree_add_uint_format(vw_plcpinfo_tree, hf_radiotap_plcp_default,
            tvb, offset, 1, plcp_default, "PLCP1: %u ", plcp_default);
        offset = offset + 1;
        plcp_default = tvb_get_uint8(tvb, offset);
        proto_tree_add_uint_format(vw_plcpinfo_tree, hf_radiotap_plcp_default,
            tvb, offset, 1, plcp_default, "PLCP2: %u ", plcp_default);
        offset = offset + 1;
        plcp_default = tvb_get_uint8(tvb, offset);
        proto_tree_add_uint_format(vw_plcpinfo_tree, hf_radiotap_plcp_default,
            tvb, offset, 1, plcp_default, "PLCP3: %u ", plcp_default);
        offset = offset + 1;
        plcp_default = tvb_get_uint8(tvb, offset);
        proto_tree_add_uint_format(vw_plcpinfo_tree, hf_radiotap_plcp_default,
            tvb, offset, 1, plcp_default, "PLCP4: %u ", plcp_default);
        offset = offset + 1;
        plcp_default = tvb_get_uint8(tvb, offset);
        proto_tree_add_uint_format(vw_plcpinfo_tree, hf_radiotap_plcp_default,
            tvb, offset, 1, plcp_default, "PLCP5: %u ", plcp_default);
        offset = offset + 1;
        plcp_default = tvb_get_uint8(tvb, offset);
        proto_tree_add_uint_format(vw_plcpinfo_tree, hf_radiotap_plcp_default,
            tvb, offset, 1, plcp_default, "PLCP6: %u ", plcp_default);
        offset = offset + 1;
        plcp_default = tvb_get_uint8(tvb, offset);
        proto_tree_add_uint_format(vw_plcpinfo_tree, hf_radiotap_plcp_default,
            tvb, offset, 1, plcp_default, "PLCP7: %u ", plcp_default);
        offset = offset + 1;
        plcp_default = tvb_get_uint8(tvb, offset);
        proto_tree_add_uint_format(vw_plcpinfo_tree, hf_radiotap_plcp_default,
            tvb, offset, 1, plcp_default, "PLCP8: %u ", plcp_default);
        offset = offset + 1;
        plcp_default = tvb_get_uint8(tvb, offset);
        proto_tree_add_uint_format(vw_plcpinfo_tree, hf_radiotap_plcp_default,
            tvb, offset, 1, plcp_default, "PLCP9: %u ", plcp_default);
        offset = offset + 1;
        plcp_default = tvb_get_uint8(tvb, offset);
        proto_tree_add_uint_format(vw_plcpinfo_tree, hf_radiotap_plcp_default,
            tvb, offset, 1, plcp_default, "PLCP10: %u ", plcp_default);
        offset = offset + 1;
        plcp_default = tvb_get_uint8(tvb, offset);
        proto_tree_add_uint_format(vw_plcpinfo_tree, hf_radiotap_plcp_default,
            tvb, offset, 1, plcp_default, "PLCP11: %u ", plcp_default);
        offset = offset + 1;
        plcp_default = tvb_get_uint8(tvb, offset);
        proto_tree_add_uint_format(vw_plcpinfo_tree, hf_radiotap_plcp_default,
            tvb, offset, 1, plcp_default, "PLCP12: %u ", plcp_default);
        offset = offset + 1;
        plcp_default = tvb_get_uint8(tvb, offset);
        proto_tree_add_uint_format(vw_plcpinfo_tree, hf_radiotap_plcp_default,
            tvb, offset, 1, plcp_default, "PLCP13: %u ", plcp_default);
        offset = offset + 1;
        plcp_default = tvb_get_uint8(tvb, offset);
        proto_tree_add_uint_format(vw_plcpinfo_tree, hf_radiotap_plcp_default,
            tvb, offset, 1, plcp_default, "PLCP14: %u ", plcp_default);
        offset = offset + 1;
    }

    proto_tree_add_item(vw_plcpinfo_tree, hf_radiotap_rfid,
                        tvb, offset, 1, ENC_LITTLE_ENDIAN);
    offset += 1;

    //RadioTapHeader New format for L2-L4_Info
    vwl2l4t = proto_tree_add_item(tap_tree, hf_radiotap_l2_l4_info,
                        tvb, offset, 23, ENC_NA);
    vw_l2l4info_tree = proto_item_add_subtree(vwl2l4t, ett_radiotap_layer2to4);
    cidv = ((tvb_get_uint8(tvb, offset+3)& 0x20) >> 5);
    bssidv = ((tvb_get_uint8(tvb, offset+3)& 0x40) >> 6);
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
    wlantype = tvb_get_uint8(tvb, offset)& 0x3f;
    proto_tree_add_uint(vw_l2l4info_tree, hf_radiotap_wlantype,
                            tvb, offset, 1, wlantype);
    */
    proto_tree_add_item(vw_l2l4info_tree, hf_radiotap_tid, tvb, offset, 2, ENC_LITTLE_ENDIAN);
    offset++;
    if (cmd_type == 1)
    {
        proto_tree_add_item(vw_l2l4info_tree, hf_radiotap_ac, tvb, offset, 1, ENC_NA);
    }
    l4idv = (tvb_get_uint8(tvb, offset)& 0x10) >> 4;
    proto_tree_add_item(vw_l2l4info_tree, hf_radiotap_l4idvalid, tvb, offset, 1, ENC_NA);
    proto_tree_add_item(vw_l2l4info_tree, hf_radiotap_containshtfield, tvb, offset, 1, ENC_NA);
    proto_tree_add_item(vw_l2l4info_tree, hf_radiotap_istypeqos, tvb, offset, 1, ENC_NA);
    flowv = (tvb_get_uint8(tvb, offset)& 0x80) >> 7;
    proto_tree_add_item(vw_l2l4info_tree, hf_radiotap_flowvalid, tvb, offset, 1, ENC_NA);
    offset++;

    proto_tree_add_item_ret_uint(vw_l2l4info_tree, hf_ixveriwave_vw_seqnum,
                                 tvb, offset, 1, ENC_NA, &vw_seqnum);
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

    /* build the individual subtrees for the various types of error flags */
    /* NOTE: as the upper 16 bits aren't used at the moment, we pretend that */
    /* the error flags field is only 16 bits (instead of 32) to save space */
    if (cmd_type != 1) {
        /* then it's an rx case */
        static int * const vw_errors_rx_flags[] = {
            &hf_radiotap_vw_errors_rx_sig_field_crc_parity_error,
            &hf_radiotap_vw_errors_rx_non_supported_service_field,
            &hf_radiotap_vw_errors_rx_frame_length_error,
            &hf_radiotap_vw_errors_rx_vht_sig_ab_crc_error,
            &hf_radiotap_vw_errors_rx_crc32_error,
            &hf_radiotap_vw_errors_rx_l2_de_aggregation_error,
            &hf_radiotap_vw_errors_rx_duplicate_mpdu,
            &hf_radiotap_vw_errors_rx_bad_flow_magic_number,
            &hf_radiotap_vw_errors_rx_bad_flow_payload_checksum,
            &hf_radiotap_vw_errors_rx_illegal_vht_sig_value,
            &hf_radiotap_vw_errors_rx_ip_checksum_error,
            &hf_radiotap_vw_errors_rx_l4_checksum_error,
            &hf_radiotap_vw_errors_rx_l1_unsupported_feature,
            &hf_radiotap_vw_errors_rx_l1_packet_termination,
            &hf_radiotap_vw_errors_rx_internal_error_bit15,
            &hf_radiotap_vw_errors_rx_wep_mic_miscompare,
            &hf_radiotap_vw_errors_rx_wep_tkip_rate_exceeded,
            &hf_radiotap_vw_errors_rx_crypto_short_error,
            &hf_radiotap_vw_errors_rx_extiv_fault_a,
            &hf_radiotap_vw_errors_rx_extiv_fault_b,
            &hf_radiotap_vw_errors_rx_internal_error_bit21,
            &hf_radiotap_vw_errors_rx_protected_fault_a,
            &hf_radiotap_vw_errors_rx_rx_mac_crypto_incompatibility,
            &hf_radiotap_vw_errors_rx_factory_debug,
            &hf_radiotap_vw_errors_rx_internal_error_bit32,
            NULL
        };

        proto_tree_add_bitmask(vw_l2l4info_tree, tvb, offset, hf_radiotap_vw_errors, ett_radiotap_errors, vw_errors_rx_flags, ENC_LITTLE_ENDIAN);

    } else {                                  /* it's a tx case */
        static int * const vw_errors_tx_flags[] = {
            &hf_radiotap_vw_errors_tx_2_crc32_error,
            &hf_radiotap_vw_errors_tx_2_ip_checksum_error,
            &hf_radiotap_vw_errors_tx_2_ack_timeout,
            &hf_radiotap_vw_errors_tx_2_cts_timeout,
            &hf_radiotap_vw_errors_tx_2_last_retry_attempt,
            &hf_radiotap_vw_errors_tx_2_internal_error,
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
    /*offset      +=4;*/

    if (vwl2l4t && log_mode)
        proto_item_append_text(vwl2l4t, " (Reduced)");

    if (cmd_type != 4)
        proto_item_set_len(tap_tree, length + OCTO_TIMESTAMP_FIELDS_LEN);
    else
        proto_item_set_len(tap_tree, length + OCTO_TIMESTAMP_FIELDS_LEN + OCTO_MODIFIED_RF_LEN);

    if (mpdu_length != 0) {
        /* There's data to dissect; grab the rest of the frame. */
        next_tvb = tvb_new_subset_remaining(tvb, length);

        /* dissect the 802.11 radio information and header next */
        call_dissector_with_data(ieee80211_radio_handle, next_tvb, pinfo, tree, &phdr);
    }
}

void proto_register_ixveriwave(void)
{
    /* true_false_strings for TX/RX and FCS error flags */
    static const true_false_string tfs_tx_rx_type = { "Transmitted", "Received" };
    static const true_false_string tfs_fcserr_type = { "Incorrect", "Correct" };
    static const true_false_string tfs_preamble_type = { "Short", "Long", };

    /* true_false_string for decrypt error flag */
    static const true_false_string tfs_decrypterr_type = { "Decrypt Failed", "Decrypt Succeeded" };

    /* true_false_string for excess retry error flag */
    static const true_false_string tfs_retryerr_type = {"Excess retry abort", "Retry limit not reached" };

    static const true_false_string tfs_legacy_type = {"802.11b LEGACY CCK", "LEGACY OFDM"};

    static const value_string signal_vals[] = {
        { 0x0a, "1 Mb/s" },
        { 0x14, "2 MB/s" },
        { 0x37, "5.5 Mb/s" },
        { 0x6e, "11 Mb/s" },
        { 0xdc, "22 Mb/s" },
        { 0x1e, "DSSS-OFDM" },
        { 0,    NULL }
    };
    static const value_string modulation_vals[] = {
        { 0, "CCK" },
        { 1, "PBCC" },
        { 0, NULL }
    };
    static const value_string fec_encoding_vals[] = {
        { 0, "BCC" },
        { 1, "LDPC" },
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
        { VHT_BW_20_MHZ,  "20 MHz" },
        { VHT_BW_40_MHZ,  "40 MHz" },
        { VHT_BW_80_MHZ,  "80 MHz" },
        { VHT_BW_160_MHZ, "160 MHz" },
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

    { &hf_ixveriwave_vw_flowid,
        { "Flow ID", "ixveriwave.flowid",
        FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL } },

    { &hf_ixveriwave_vw_vcid,
        { "Client ID", "ixveriwave.clientid",
        FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL } },

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

    // RF LOGGING
    { &hf_radiotap_rf_info,
        { "RF Header", "ixveriwave.RFInfo",
        FT_NONE, BASE_NONE, NULL, 0, NULL, HFILL } },

    { &hf_radiotap_rfinfo_rfid,
        { "RF_ID", "ixveriwave.rfinfo.rfid",
        FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },

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

    { &hf_radiotap_rfinfo_contextpa,
        { "CONTEXT_A", "ixveriwave.contextpa",
        FT_UINT16, BASE_HEX, NULL, 0, NULL, HFILL } },
    { &hf_radiotap_rfinfo_contextpA_snr_noise_valid,
        { "SNR_NOISE_valid", "ixveriwave.contextpA.snr_noise_valid",
        FT_BOOLEAN, 16, NULL, 0x0001, NULL, HFILL } },
    { &hf_radiotap_rfinfo_contextpA_pfe_valid,
        { "PFE_valid", "ixveriwave.contextpA.pfe_valid",
        FT_BOOLEAN, 16, NULL, 0x0002, NULL, HFILL } },
    { &hf_radiotap_rfinfo_contextpA_pfe_is_cck,
        { "PFE_is_CCK", "ixveriwave.contextpA.pfe_is_cck",
        FT_BOOLEAN, 16, NULL, 0x0004, NULL, HFILL } },
    { &hf_radiotap_rfinfo_contextpA_agc_idle2iqrdy_no_gain_change,
        { "AGC 3", "ixveriwave.contextpA.agc_idle2iqrdy_no_gain_change",
        FT_BOOLEAN, 16, NULL, 0x0008, "Automatic Gain Control-[3] agc_idle2iqrdy_no_gain_change", HFILL } },
    { &hf_radiotap_rfinfo_contextpA_agc_high_pwr_terminated,
        { "AGC 4", "ixveriwave.contextpA.agc_high_pwr_terminated",
        FT_BOOLEAN, 16, NULL, 0x0010, "Automatic Gain Control-[4] agc_high_pwr_terminated", HFILL } },
    { &hf_radiotap_rfinfo_contextpA_agc_high_pwr_terminator,
        { "AGC 5", "ixveriwave.contextpA.agc_high_pwr_terminator",
        FT_BOOLEAN, 16, NULL, 0x0020, "Automatic Gain Control-[5] agc_high_pwr_terminator", HFILL } },
#if 0
    { &hf_radiotap_rfinfo_contextpA_frame_format,
        { "Frame format", "ixveriwave.contextp.frame_format",
        FT_UINT16, BASE_DEC, VALS(frameformat_type), 0x0300, "0: LEGACY.   1:HT.   3:-VHT.", HFILL } },
    { &hf_radiotap_rfinfo_contextpA_ofdm_or_cck,
        { "OFDM or CCK", "ixveriwave.contextp.ofdm_or_cck",
        FT_BOOLEAN, 16, TFS(&tfs_legacy_type), 0x0400, "0: LEGACY OFDM      1: 802.11b LEGACY CCK", HFILL } },
    { &hf_radiotap_rfinfo_contextpA_sigbandwidth_of_evm,
        { "SigBandWidth of EVM", "ixveriwave.contextp.sigbandwidth_of_evm",
        FT_UINT16, BASE_DEC, VALS(sbw_evm), 0x1800, "Signal Bandwidth of EVM measurement", HFILL } },
#endif
    { &hf_radiotap_rfinfo_contextpA_qam_modulation,
        { "QAM modulation", "ixveriwave.contextpA.qam_modulation",
        FT_UINT16, BASE_DEC, NULL, 0xe000, NULL, HFILL } },

    { &hf_radiotap_rfinfo_contextpb,
        { "CONTEXT_B", "ixveriwave.contextpb",
        FT_UINT16, BASE_HEX, NULL, 0, NULL, HFILL } },
    { &hf_radiotap_rfinfo_contextpc,
        { "CONTEXT_C", "ixveriwave.contextpc",
        FT_UINT16, BASE_HEX, NULL, 0, NULL, HFILL } },
    { &hf_radiotap_rfinfo_contextpd,
        { "CONTEXT_D", "ixveriwave.contextpd",
        FT_UINT16, BASE_HEX, NULL, 0, NULL, HFILL } },

    { &hf_radiotap_rfinfo_contextpB_snr_noise_valid,
        { "SNR_NOISE_valid", "ixveriwave.contextpB.snr_noise_valid",
        FT_BOOLEAN, 16, NULL, 0x0001, NULL, HFILL } },
    { &hf_radiotap_rfinfo_contextpB_pfe_valid,
        { "PFE_valid", "ixveriwave.contextpB.pfe_valid",
        FT_BOOLEAN, 16, NULL, 0x0002, NULL, HFILL } },
    { &hf_radiotap_rfinfo_contextpB_pfe_is_cck,
        { "PFE_is_CCK", "ixveriwave.contextpB.pfe_is_cck",
        FT_BOOLEAN, 16, NULL, 0x0004, NULL, HFILL } },
    { &hf_radiotap_rfinfo_contextpB_agc_idle2iqrdy_no_gain_change,
        { "AGC 3", "ixveriwave.contextpB.agc_idle2iqrdy_no_gain_change",
        FT_BOOLEAN, 16, NULL, 0x0008, "Automatic Gain Control-[3] agc_idle2iqrdy_no_gain_change", HFILL } },
    { &hf_radiotap_rfinfo_contextpB_agc_high_pwr_terminated,
        { "AGC 4", "ixveriwave.contextpB.agc_high_pwr_terminated",
        FT_BOOLEAN, 16, NULL, 0x0010, "Automatic Gain Control-[4] agc_high_pwr_terminated", HFILL } },
    { &hf_radiotap_rfinfo_contextpB_agc_high_pwr_terminator,
        { "AGC 5", "ixveriwave.contextpB.agc_high_pwr_terminator",
        FT_BOOLEAN, 16, NULL, 0x0020, "Automatic Gain Control-[5] agc_high_pwr_terminator", HFILL } },
    { &hf_radiotap_rfinfo_contextpB_qam_modulation,
        { "QAM modulation", "ixveriwave.contextpB.qam_modulation",
        FT_UINT16, BASE_DEC, NULL, 0xe000, NULL, HFILL } },

    { &hf_radiotap_rfinfo_contextpC_snr_noise_valid,
        { "SNR_NOISE_valid", "ixveriwave.contextpC.snr_noise_valid",
        FT_BOOLEAN, 16, NULL, 0x0001, NULL, HFILL } },
    { &hf_radiotap_rfinfo_contextpC_pfe_valid,
        { "PFE_valid", "ixveriwave.contextpC.pfe_valid",
        FT_BOOLEAN, 16, NULL, 0x0002, NULL, HFILL } },
    { &hf_radiotap_rfinfo_contextpC_pfe_is_cck,
        { "PFE_is_CCK", "ixveriwave.contextpC.pfe_is_cck",
        FT_BOOLEAN, 16, NULL, 0x0004, NULL, HFILL } },
    { &hf_radiotap_rfinfo_contextpC_agc_idle2iqrdy_no_gain_change,
        { "AGC 3", "ixveriwave.contextpC.agc_idle2iqrdy_no_gain_change",
        FT_BOOLEAN, 16, NULL, 0x0008, "Automatic Gain Control-[3] agc_idle2iqrdy_no_gain_change", HFILL } },
    { &hf_radiotap_rfinfo_contextpC_agc_high_pwr_terminated,
        { "AGC 4", "ixveriwave.contextpC.agc_high_pwr_terminated",
        FT_BOOLEAN, 16, NULL, 0x0010, "Automatic Gain Control-[4] agc_high_pwr_terminated", HFILL } },
    { &hf_radiotap_rfinfo_contextpC_agc_high_pwr_terminator,
        { "AGC 5", "ixveriwave.contextpC.agc_high_pwr_terminator",
        FT_BOOLEAN, 16, NULL, 0x0020, "Automatic Gain Control-[5] agc_high_pwr_terminator", HFILL } },
    { &hf_radiotap_rfinfo_contextpC_qam_modulation,
        { "QAM modulation", "ixveriwave.contextpC.qam_modulation",
        FT_UINT16, BASE_DEC, NULL, 0xe000, NULL, HFILL } },

    { &hf_radiotap_rfinfo_contextpD_snr_noise_valid,
        { "SNR_NOISE_valid", "ixveriwave.contextpD.snr_noise_valid",
        FT_BOOLEAN, 16, NULL, 0x0001, NULL, HFILL } },
    { &hf_radiotap_rfinfo_contextpD_pfe_valid,
        { "PFE_valid", "ixveriwave.contextpD.pfe_valid",
        FT_BOOLEAN, 16, NULL, 0x0002, NULL, HFILL } },
    { &hf_radiotap_rfinfo_contextpD_pfe_is_cck,
        { "PFE_is_CCK", "ixveriwave.contextpD.pfe_is_cck",
        FT_BOOLEAN, 16, NULL, 0x0004, NULL, HFILL } },
    { &hf_radiotap_rfinfo_contextpD_agc_idle2iqrdy_no_gain_change,
        { "AGC 3", "ixveriwave.contextpD.agc_idle2iqrdy_no_gain_change",
        FT_BOOLEAN, 16, NULL, 0x0008, "Automatic Gain Control-[3] agc_idle2iqrdy_no_gain_change", HFILL } },
    { &hf_radiotap_rfinfo_contextpD_agc_high_pwr_terminated,
        { "AGC 4", "ixveriwave.contextpD.agc_high_pwr_terminated",
        FT_BOOLEAN, 16, NULL, 0x0010, "Automatic Gain Control-[4] agc_high_pwr_terminated", HFILL } },
    { &hf_radiotap_rfinfo_contextpD_agc_high_pwr_terminator,
        { "AGC 5", "ixveriwave.contextpD.agc_high_pwr_terminator",
        FT_BOOLEAN, 16, NULL, 0x0020, "Automatic Gain Control-[5] agc_high_pwr_terminator", HFILL } },
    { &hf_radiotap_rfinfo_contextpD_qam_modulation,
        { "QAM modulation", "ixveriwave.contextpD.qam_modulation",
        FT_UINT16, BASE_DEC, NULL, 0xe000, NULL, HFILL } },

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
#if 0
    { &hf_radiotap_rfinfo_tbd,
        { "RF_TBD", "ixveriwave.rfinfo.tbd",
        FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL } },
#endif

    /* Fields for both Ethernet and WLAN */

    { &hf_ixveriwave_vw_l4id,
        { "Layer 4 ID", "ixveriwave.layer4id",
        FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL } },

    /* Ethernet fields */

    { &hf_ixveriwave_vwf_txf,
        { "Frame direction", "ixveriwave.vwflags.txframe",
        FT_BOOLEAN, 8, TFS(&tfs_tx_rx_type), ETHERNETTAP_VWF_TXF, NULL, HFILL } },

    { &hf_ixveriwave_vwf_fcserr,
        { "MAC FCS check", "ixveriwave.vwflags.fcserr",
        FT_BOOLEAN, 8, TFS(&tfs_fcserr_type), ETHERNETTAP_VWF_FCSERR, NULL, HFILL } },

    { &hf_ixveriwave_vw_info,
        { "Info field", "ixveriwave.eth_info",
        FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL } },

    /* rx info decodes for fpga ver VW510024 */
    /*all are reserved*/

    /* rx info decodes for fpga ver VW510012 */
    { &hf_ixveriwave_vw_info_go_no_flow,
        { "Go no flow", "ixveriwave.eth_info.go_no_flow",
        FT_BOOLEAN, 16, NULL, 0x0100, NULL, HFILL } },
    { &hf_ixveriwave_vw_info_go_with_flow,
        { "Go with flow", "ixveriwave.eth_info.go_with_flow",
        FT_BOOLEAN, 16, NULL, 0x0200, NULL, HFILL } },

/* tx info decodes for VW510024 and 510012 */
/* we don't need to enumerate through these, basically for both,
info is the retry count.  for 510024, the 15th bit indicates if
the frame was impressed on the enet tx media with one or more octets having tx_en
framing signal deasserted.  this is caused by software setting the drain all register bit.
*/
    { &hf_ixveriwave_vw_info_retry_count,
        { "Retry count", "ixveriwave.eth_info.retry_count",
        FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL } },

    { &hf_ixveriwave_vw_error,
        { "Errors", "ixveriwave.eth_error",
        FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL } },

    /* rx error decodes for fpga ver VW510012 and VW510024 */
    /* tx error decodes for VW510024 and previous versions */
    /* rx-only */
    { &hf_ixveriwave_vw_error_1_alignment_error,
        { "Alignment error", "ixveriwave.eth_error.rx_alignment_error",
        FT_BOOLEAN, 12, NULL, 0x001, NULL, HFILL } },
    /* rx and tx */
    { &hf_ixveriwave_vw_error_1_packet_fcs_error,
        { "Packet FCS error", "ixveriwave.eth_error.rx_packet_fcs_error",
        FT_BOOLEAN, 12, NULL, 0x002, NULL, HFILL } },
    /* rx-only */
    { &hf_ixveriwave_vw_error_1_bad_magic_byte_signature,
        { "Bad magic byte signature", "ixveriwave.eth_error.rx_bad_magic_byte_signature",
        FT_BOOLEAN, 12, NULL, 0x004, NULL, HFILL } },
    /* rx-only */
    { &hf_ixveriwave_vw_error_1_bad_payload_checksum,
        { "Bad payload checksum", "ixveriwave.eth_error.rx_bad_payload_checksum",
        FT_BOOLEAN, 12, NULL, 0x008, NULL, HFILL } },
    /* rx-only */
    { &hf_ixveriwave_vw_error_1_frame_too_long,
        { "Frame too long error", "ixveriwave.eth_error.rx_frame_too_long",
        FT_BOOLEAN, 12, NULL, 0x010, NULL, HFILL } },
    /* rx and tx */
    { &hf_ixveriwave_vw_error_1_ip_checksum_error,
        { "IP checksum error", "ixveriwave.eth_error.rx_ip_checksum_error",
        FT_BOOLEAN, 12, NULL, 0x020, NULL, HFILL } },
    /* rx-only */
    { &hf_ixveriwave_vw_error_1_l4_checksum_error,
        { "L4 (TCP/ICMP/IGMP/UDP) checksum error", "ixveriwave.eth_error.rx_l4_checksum_error",
        FT_BOOLEAN, 12, NULL, 0x040, NULL, HFILL } },
    /* rx-only */
    { &hf_ixveriwave_vw_error_1_id_mismatch,
        { "ID mismatch(for fpga510012)", "ixveriwave.eth_error.rx_id_mismatch",
        FT_BOOLEAN, 12, NULL, 0x080, NULL, HFILL } },
    /* rx-only */
    { &hf_ixveriwave_vw_error_1_length_error,
        { "Length error", "ixveriwave.eth_error.rx_length_error",
        FT_BOOLEAN, 12, NULL, 0x100, NULL, HFILL } },
    /* rx and tx */
    { &hf_ixveriwave_vw_error_1_underflow,
        { "Underflow", "ixveriwave.eth_error.rx_underflow",
        FT_BOOLEAN, 12, NULL, 0x200, NULL, HFILL } },
    /* tx-only */
    { &hf_ixveriwave_vw_error_1_late_collision,
        { "Late collision", "ixveriwave.eth_error.late_collision",
        FT_BOOLEAN, 12, NULL, 0x400, NULL, HFILL } },
    { &hf_ixveriwave_vw_error_1_excessive_collisions,
        { "Excessive collisions", "ixveriwave.eth_error.excessive_collisions",
        FT_BOOLEAN, 12, NULL, 0x800, NULL, HFILL } },
    /*all other bits are reserved */

    /* WLAN fields */
    { &hf_radiotap_flags,
        { "Flags", "ixveriwave.flags",
        FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL } },

    { &hf_radiotap_flags_preamble,
        { "Preamble", "ixveriwave.flags.preamble",
        FT_BOOLEAN, 12, TFS(&tfs_preamble_type), FLAGS_SHORTPRE,
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
    { &hf_radiotap_flags_short_gi,
        { "Short guard interval", "ixveriwave.flags.short_gi",
        FT_BOOLEAN, 12, NULL, FLAGS_CHAN_SHORTGI, NULL, HFILL } },
    { &hf_radiotap_flags_40mhz,
        { "40 MHz channel bandwidth", "ixveriwave.flags.40mhz",
        FT_BOOLEAN, 12, NULL, FLAGS_CHAN_40MHZ, NULL, HFILL } },
    { &hf_radiotap_flags_80mhz,
        { "80 MHz channel bandwidth", "ixveriwave.flags.80mhz",
        FT_BOOLEAN, 12, NULL, FLAGS_CHAN_80MHZ, NULL, HFILL } },

    { &hf_radiotap_datarate,
        { "Data rate", "ixveriwave.datarate",
        FT_UINT32, BASE_DEC, NULL, 0x0,
        "Speed this frame was sent/received at", HFILL } },

    { &hf_radiotap_mcsindex,
        { "MCS index", "ixveriwave.mcs",
        FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },

    { &hf_radiotap_nss,
        { "Number of spatial streams", "ixveriwave.nss",
        FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },

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

    /* All other enumerations are reserved.*/

    { &hf_radiotap_plcptype,
        { "VHT_NDP", "ixveriwave.plcptype",
        FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },

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

    { &hf_radiotap_vw_ht_length,
        { "HT length", "ixveriwave.ht_length",
        FT_UINT16, BASE_DEC, NULL, 0x0, "Total IP length (incl all pieces of an aggregate)", HFILL } },

    { &hf_radiotap_vw_info,
        { "Info field", "ixveriwave.wlan_info",
        FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL } },

    /*v510006 uses bits */

    { &hf_radiotap_vw_info_2_ack_withheld_from_frame,
        { "ACK withheld from frame", "ixveriwave.wlan_info.ack_withheld_from_frame",
        FT_BOOLEAN, 16, NULL, 0x0100, NULL, HFILL } },
    { &hf_radiotap_vw_info_2_sent_cts_to_self_before_data,
        { "Sent CTS to self before data", "ixveriwave.wlan_info.sent_cts_to_self_before_data",
        FT_BOOLEAN, 16, NULL, 0x0200, NULL, HFILL } },
    { &hf_radiotap_vw_info_2_mpdu_of_a_mpdu,
        { "MPDU of A-MPDU", "ixveriwave.wlan_info.mpdu_of_a_mpdu",
        FT_BOOLEAN, 16, NULL, INFO_MPDU_OF_A_MPDU, NULL, HFILL } },
    { &hf_radiotap_vw_info_2_first_mpdu_of_a_mpdu,
        { "First MPDU of A-MPDU", "ixveriwave.wlan_info.first_mpdu_of_a_mpdu",
        FT_BOOLEAN, 16, NULL, INFO_FIRST_MPDU_OF_A_MPDU, NULL, HFILL } },
    { &hf_radiotap_vw_info_2_last_pdu_of_a_mpdu,
        { "Last MPDU of A-MPDU", "ixveriwave.wlan_info.last_pdu_of_a_mpdu",
        FT_BOOLEAN, 16, NULL, INFO_LAST_MPDU_OF_A_MPDU, NULL, HFILL } },
    { &hf_radiotap_vw_info_2_msdu_of_a_msdu,
        { "MSDU of A-MSDU", "ixveriwave.wlan_info.msdu_of_a_msdu",
        FT_BOOLEAN, 16, NULL, INFO_MSDU_OF_A_MSDU, NULL, HFILL } },
    { &hf_radiotap_vw_info_2_first_msdu_of_a_msdu,
        { "First MSDU of A-MSDU", "ixveriwave.wlan_info.first_msdu_of_a_msdu",
        FT_BOOLEAN, 16, NULL, INFO_FIRST_MSDU_OF_A_MSDU, NULL, HFILL } },
    { &hf_radiotap_vw_info_2_last_msdu_of_a_msdu,
        { "Last MSDU of A-MSDU", "ixveriwave.wlan_info.last_msdu_of_a_msdu",
        FT_BOOLEAN, 16, NULL, INFO_LAST_MSDU_OF_A_MSDU, NULL, HFILL } },

    { &hf_radiotap_vw_errors,
        { "Errors", "ixveriwave.errors",
        FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL } },

    /* rx error decodes for fpga ver VW510021 */
    { &hf_radiotap_vw_errors_rx_2_crc16_or_parity_error,
        { "CRC16 or parity error", "ixveriwave.errors.crc16_or_parity_error",
        FT_BOOLEAN, 16, NULL, 0x0001, "error bit 0", HFILL } },
    { &hf_radiotap_vw_errors_rx_2_non_supported_rate_or_service_field,
        { "Non-supported rate or service field", "ixveriwave.errors.supported_rate_or_service_field",
        FT_BOOLEAN, 16, NULL, 0x0002, NULL, HFILL } },
    { &hf_radiotap_vw_errors_rx_2_short_frame,
        { "Short frame error.  Frame is shorter than length.", "ixveriwave.errors.short_frame",
        FT_BOOLEAN, 16, NULL, 0x0004, NULL, HFILL } },
    { &hf_radiotap_vw_errors_rx_2_fcs_error,
        { "FCS error", "ixveriwave.errors.fcs_error",
        FT_BOOLEAN, 16, NULL, 0x0010, NULL, HFILL } },
    { &hf_radiotap_vw_errors_rx_2_l2_de_aggregation_error,
        { "L2 de-aggregation error", "ixveriwave.errors.de_aggregation_error",
        FT_BOOLEAN, 16, NULL, 0x0020, NULL, HFILL } },
    { &hf_radiotap_vw_errors_rx_2_duplicate_mpdu,
        { "Duplicate MPDU", "ixveriwave.errors.duplicate_mpdu",
        FT_BOOLEAN, 16, NULL, 0x0040, NULL, HFILL } },
    { &hf_radiotap_vw_errors_rx_2_bad_flow_magic_number,
        { "Bad_Sig:  Bad flow magic number (includes bad flow crc16)", "ixveriwave.errors.bad_flow_magic_number",
        FT_BOOLEAN, 16, NULL, 0x0080, NULL, HFILL } },
    { &hf_radiotap_vw_errors_rx_2_flow_payload_checksum_error,
        { "Bad flow payload checksum", "ixveriwave.errors.flow_payload_checksum_error",
        FT_BOOLEAN, 16, NULL, 0x0100, NULL, HFILL } },
    { &hf_radiotap_vw_errors_rx_2_ip_checksum_error,
        { "IP checksum error", "ixveriwave.errors.ip_checksum_error",
        FT_BOOLEAN, 16, NULL, 0x0400, NULL, HFILL } },
    { &hf_radiotap_vw_errors_rx_2_l4_checksum_error,
        { "L4 (TCP/ICMP/IGMP/UDP) checksum error", "ixveriwave.errors.l4_checksum_error",
        FT_BOOLEAN, 16, NULL, 0x0800, NULL, HFILL } },

    /* tx error decodes for fpga ver VW510021 */
    { &hf_radiotap_vw_errors_tx_2_crc32_error,
        { "CRC32 Error", "ixveriwave.errors.crc32_error",
        FT_BOOLEAN, 32, NULL, 0x00000002, NULL, HFILL } },
    { &hf_radiotap_vw_errors_tx_2_ip_checksum_error,
        { "IP Checksum Error", "ixveriwave.errors.ip_checksum_error",
        FT_BOOLEAN, 32, NULL, 0x00000020, NULL, HFILL } },
    { &hf_radiotap_vw_errors_tx_2_ack_timeout,
        { "ACK Timeout", "ixveriwave.errors.ack_timeout",
        FT_BOOLEAN, 32, NULL, 0x00000100, NULL, HFILL } },
    { &hf_radiotap_vw_errors_tx_2_cts_timeout,
        { "CTS Timeout", "ixveriwave.errors.cts_timeout",
        FT_BOOLEAN, 32, NULL, 0x00000200, NULL, HFILL } },
    { &hf_radiotap_vw_errors_tx_2_last_retry_attempt,
        { "Last Retry Attempt for this MPDU", "ixveriwave.errors.last_retry_attempt",
        FT_BOOLEAN, 32, NULL, 0x00000400, NULL, HFILL } },
    { &hf_radiotap_vw_errors_tx_2_internal_error,
        { "Internal Error", "ixveriwave.errors.internal_error",
        FT_BOOLEAN, 32, NULL, 0x80000000, NULL, HFILL } },

    { &hf_radiotap_vht_mu_mimo_flg,
        { "VHT MU MIMO", "ixveriwave.VHT_mu_mimo_flg",
        FT_UINT8, BASE_DEC, NULL, 0x08, NULL, HFILL } },
    { &hf_radiotap_vht_user_pos,
        { "VHT User Pos", "ixveriwave.VHT_user_pos",
         FT_UINT8, BASE_DEC, NULL, 0x03, NULL, HFILL } },
    { &hf_radiotap_vht_su_mimo_flg,
        { "VHT SU MIMO", "ixveriwave.VHT_su_mimo_flg",
        FT_UINT8, BASE_DEC, NULL, 0x04, NULL, HFILL } },

    { &hf_radiotap_l1info,
        { "Layer 1 Header", "ixveriwave.l1info",
        FT_NONE, BASE_NONE, NULL, 0, NULL, HFILL } },

    { &hf_radiotap_l1info_preamble,
        { "Preamble", "ixveriwave.l1info.preamble",
        FT_BOOLEAN, BASE_NONE, TFS(&tfs_preamble_type), 0x0,
        "Sent/Received with short preamble", HFILL } },

    { &hf_radiotap_l1info_rateindex,
        { "Rate index", "ixveriwave.l1info.rate",
        FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },

    { &hf_radiotap_l1info_ht_mcsindex,
        { "MCS index", "ixveriwave.mcs",
        FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },

    { &hf_radiotap_l1info_vht_mcsindex,
        { "MCS index", "ixveriwave.mcs",
        FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },

    { &hf_radiotap_l1info_nss,
        { "Number of spatial streams", "ixveriwave.nss",
        FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },

    { &hf_radiotap_l1info_transmitted,
        { "Frame direction", "ixveriwave.txframe",
        FT_BOOLEAN, BASE_NONE, TFS(&tfs_tx_rx_type), 0x0, NULL, HFILL } },

    { &hf_radiotap_sigbandwidth,
        { "Signaling Band Width", "ixveriwave.sigbandwidth",
        FT_UINT8, BASE_DEC, VALS(sbw_type), 0x0, NULL, HFILL } },
#if 0
    {&hf_radiotap_rssi,
        { "RSSI", "ixveriwave.rssi",
        FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL } },
#endif
    { &hf_radiotap_modulation,
        { "Modulation", "ixveriwave.Modulation",
        FT_UINT8, BASE_DEC, VALS(modulation_type), 0x0, NULL, HFILL } },

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

    { &hf_radiotap_sigbandwidthmask,
        { "Signaling Band Width Mask", "ixveriwave.sigbandwidthmask",
        FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL } },
    { &hf_radiotap_antennaportenergydetect,
        { "Antenna Port Energy Detect", "ixveriwave.antennaportenergydetect",
        FT_UINT8, BASE_HEX, NULL, 0x0F, NULL, HFILL } },
    { &hf_radiotap_tx_antennaselect,
        { "Antenna Select", "ixveriwave.tx.antennaselect",
        FT_UINT8, BASE_HEX, NULL, 0x07, NULL, HFILL } },
    { &hf_radiotap_tx_stbcselect,
        { "STBC Select", "ixveriwave.tx.stbcselect",
        FT_UINT8, BASE_HEX, NULL, 0x18, NULL, HFILL } },
    { &hf_radiotap_mumask,
        { "MU_MASK", "ixveriwave.mumask",
        FT_UINT8, BASE_HEX, NULL, 0xF0, NULL, HFILL } },

    {&hf_radiotap_l1infoc,
        {"L1InfoC", "ixveriwave.l1InfoC",
            FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
    { &hf_radiotap_vht_ndp_flg,
        { "NDP", "ixveriwave.VHT_ndp_flg",
        FT_UINT8, BASE_HEX, NULL, 0x80, NULL, HFILL } },

    { &hf_radiotap_plcp_info,
        {"PLCP Header", "ixveriwave.plcp_info",
            FT_NONE, BASE_NONE, NULL, 0, NULL, HFILL } },
    { &hf_radiotap_plcp_type,
        { "PLCP_TYPE", "ixveriwave.plcp.type",
        FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },
    { &hf_radiotap_plcp_default,
        { "PLCP", "ixveriwave.plcp",
        FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL } },

    { &hf_radiotap_plcp_signal,
        { "Signal", "ixveriwave.plcp.signal",
        FT_UINT8, BASE_HEX, VALS(signal_vals), 0x0, NULL, HFILL } },
    { &hf_radiotap_plcp_locked_clocks,
        { "Locked clocks", "ixveriwave.plcp.locked_clocks",
        FT_BOOLEAN, 8, NULL, 0x04, NULL, HFILL } },
    { &hf_radiotap_plcp_modulation,
        { "Modulation", "ixveriwave.plcp.modulation",
        FT_UINT8, BASE_DEC, VALS(modulation_vals), 0x08, NULL, HFILL } },
    { &hf_radiotap_plcp_length_extension,
        { "Length extension", "ixveriwave.plcp.length_extension",
        FT_UINT8, BASE_DEC, NULL, 0xe0, NULL, HFILL } },
    { &hf_radiotap_plcp_length,
        { "PLCP Length", "ixveriwave.plcp.length",
        FT_UINT24, BASE_DEC, NULL, 0x0, NULL, HFILL } },
    { &hf_radiotap_plcp_crc16,
        { "PLCP CRC-16", "ixveriwave.plcp.crc16",
        FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL } },

    { &hf_radiotap_ofdm_service,
        { "Service", "ixveriwave.ofdm.service",
        FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL } },

    /* SIGNAL (11a)/L-SIG (11n, 11ac) */
    { &hf_radiotap_ofdm_rate,
        { "Rate", "ixveriwave.ofdm.rate",
        FT_UINT24, BASE_HEX, NULL, 0x00000f, NULL, HFILL } },
    { &hf_radiotap_ofdm_length,
        { "PLCP Length", "ixveriwave.ofdm.length",
        FT_UINT24, BASE_DEC, NULL, 0x01ffe0, NULL, HFILL } },
    { &hf_radiotap_ofdm_parity,
        { "Parity", "ixveriwave.ofdm.parity",
        FT_UINT24, BASE_DEC, NULL, 0x020000, NULL, HFILL } },
    { &hf_radiotap_ofdm_tail,
        { "Tail", "ixveriwave.ofdm.tail",
        FT_UINT24, BASE_HEX, NULL, 0xfc0000, NULL, HFILL } },

    /* HT-SIG1 */
    { &hf_radiotap_ht_mcsindex,
        { "MCS index", "ixveriwave.ht.mcs",
        FT_UINT24, BASE_DEC, NULL, 0x00007f, NULL, HFILL } },
    { &hf_radiotap_ht_bw,
        { "CBW 20/40", "ixveriwave.ht.bw",
        FT_UINT24, BASE_HEX, NULL, 0x000080, NULL, HFILL } },
    { &hf_radiotap_ht_length,
        { "HT Length", "ixveriwave.ht.length",
        FT_UINT24, BASE_DEC, NULL, 0xffff00, NULL, HFILL } },

    /* HT-SIG2 */
    { &hf_radiotap_ht_smoothing,
        { "Smoothing", "ixveriwave.ht.smoothing",
        FT_BOOLEAN, 24, NULL, 0x000001, NULL, HFILL } },
    { &hf_radiotap_ht_notsounding,
        { "Not Sounding", "ixveriwave.ht.notsounding",
        FT_BOOLEAN, 24, NULL, 0x000002, NULL, HFILL } },
    { &hf_radiotap_ht_aggregation,
        { "Aggregation", "ixveriwave.ht.aggregation",
        FT_BOOLEAN, 24, NULL, 0x000008, NULL, HFILL } },
    { &hf_radiotap_ht_stbc,
        { "STBC", "ixveriwave.ht.stbc",
        FT_UINT24, BASE_DEC, NULL, 0x000030, NULL, HFILL } },
    { &hf_radiotap_ht_feccoding,
        { "FEC Coding", "ixveriwave.ht.feccoding",
        FT_UINT24, BASE_DEC, VALS(fec_encoding_vals), 0x000040, NULL, HFILL } },
    { &hf_radiotap_ht_short_gi,
        { "Short GI", "ixveriwave.ht.short_gi",
        FT_BOOLEAN, 24, NULL, 0x000080, NULL, HFILL } },
    { &hf_radiotap_ht_ness,
        { "Number of Extension Spatial Streams", "ixveriwave.ness",
        FT_UINT24, BASE_DEC, NULL, 0x000300, NULL, HFILL } },
    { &hf_radiotap_ht_crc,
        { "CRC", "ixveriwave.ht.crc",
        FT_UINT24, BASE_HEX, NULL, 0x03fc00, NULL, HFILL } },
    { &hf_radiotap_ht_tail,
        { "Tail Bits", "ixveriwave.ht.tail",
        FT_UINT24, BASE_HEX, NULL, 0xfc0000, NULL, HFILL } },

    /* VHT-SIG-A1 */
    { &hf_radiotap_vht_bw,
        { "BW", "ixveriwave.vht.bw",
        FT_UINT24, BASE_HEX, VALS(sbw_evm), 0x000003, NULL, HFILL } },
    { &hf_radiotap_vht_stbc,
        { "STBC", "ixveriwave.vht.stbc",
        FT_BOOLEAN, 24, NULL, 0x000008, NULL, HFILL } },
    { &hf_radiotap_vht_group_id,
        { "Group Id", "ixveriwave.vht.group_id",
        FT_UINT24, BASE_DEC, NULL, 0x0003f0, NULL, HFILL } },
    { &hf_radiotap_vht_su_nsts,
        { "SU NSTS", "ixveriwave.vht.su_nsts",
        FT_UINT24, BASE_DEC, NULL, 0x001c00, NULL, HFILL } },
    { &hf_radiotap_vht_su_partial_aid,
        { "SU Partial AID", "ixveriwave.vht.su_partial_aid",
        FT_UINT24, BASE_HEX, NULL, 0x3fe000, NULL, HFILL } },
    { &hf_radiotap_vht_u0_nsts,
        { "MU[0] NSTS", "ixveriwave.vht.u0_nsts",
        FT_UINT24, BASE_DEC, NULL, 0x001c00, NULL, HFILL } },
    { &hf_radiotap_vht_u1_nsts,
        { "MU[1] NSTS", "ixveriwave.vht.u1_nsts",
        FT_UINT24, BASE_DEC, NULL, 0x00e000, NULL, HFILL } },
    { &hf_radiotap_vht_u2_nsts,
        { "MU[2] NSTS", "ixveriwave.vht.u2_nsts",
        FT_UINT24, BASE_DEC, NULL, 0x070000, NULL, HFILL } },
    { &hf_radiotap_vht_u3_nsts,
        { "MU[3] NSTS", "ixveriwave.vht.u3_nsts",
        FT_UINT24, BASE_DEC, NULL, 0x380000, NULL, HFILL } },
    { &hf_radiotap_vht_txop_ps_not_allowed,
        { "TXOP_PS_NOT_ALLOWED", "ixveriwave.vht.txop_ps_not_allowed",
        FT_BOOLEAN, 24, NULL, 0x400000, NULL, HFILL } },

    /* VHT-SIG-A2 */
    { &hf_radiotap_vht_short_gi,
        { "Short GI", "ixveriwave.short_gi",
        FT_BOOLEAN, 24, NULL, 0x000001, NULL, HFILL } },
    { &hf_radiotap_vht_short_gi_nsym_disambig,
        { "Short GI NSYM Disambiguation", "ixveriwave.short_gi_nsym_disambig",
        FT_BOOLEAN, 24, NULL, 0x000002, NULL, HFILL } },
    { &hf_radiotap_vht_su_coding_type,
        { "SU Coding Type", "ixveriwave.vht.su_coding_type",
        FT_UINT24, BASE_DEC, VALS(fec_encoding_vals), 0x000004, NULL, HFILL } },
    { &hf_radiotap_vht_u0_coding_type,
        { "MU[0] Coding Type", "ixveriwave.vht.u0_coding_type",
        FT_UINT24, BASE_DEC, VALS(fec_encoding_vals), 0x000004, NULL, HFILL } },
    { &hf_radiotap_vht_ldpc_ofdmsymbol,
        { "LDPC Extra OFDM Symbol", "ixveriwave.vht.ldpc_ofdmsymbol",
        FT_BOOLEAN, 24, NULL, 0x000008, NULL, HFILL } },
    { &hf_radiotap_vht_su_mcs,
        { "VHT MCS", "ixveriwave.vht.su_mcs",
        FT_UINT24, BASE_DEC, NULL, 0x0000f0, NULL, HFILL } },
    { &hf_radiotap_vht_u1_coding_type,
        { "MU[1] Coding Type", "ixveriwave.vht.u1_coding_type",
        FT_UINT24, BASE_DEC, VALS(fec_encoding_vals), 0x000010, NULL, HFILL } },
    { &hf_radiotap_vht_u2_coding_type,
        { "MU[2] Coding Type", "ixveriwave.vht.u2_coding_type",
        FT_UINT24, BASE_DEC, VALS(fec_encoding_vals), 0x000020, NULL, HFILL } },
    { &hf_radiotap_vht_u3_coding_type,
        { "MU[3] Coding Type", "ixveriwave.vht.u3_coding_type",
        FT_UINT24, BASE_DEC, VALS(fec_encoding_vals), 0x000040, NULL, HFILL } },
    { &hf_radiotap_vht_beamformed,
        { "Beamformed", "ixveriwave.vht.beamformed",
        FT_BOOLEAN, 24, NULL, 0x000100, NULL, HFILL } },
    { &hf_radiotap_vht_crc,
        { "CRC8", "ixveriwave.vht.crc",
        FT_UINT24, BASE_HEX, NULL, 0x03fc00, NULL, HFILL } },
    { &hf_radiotap_vht_tail,
        { "Tail", "ixveriwave.vht.tail",
        FT_UINT24, BASE_HEX, NULL, 0xfc0000, NULL, HFILL } },

    /* VHT-SIG-B */
    { &hf_radiotap_vht_su_sig_b_length_20_mhz,
        { "SIG-B Length", "ixveriwave.vht.sig_b_length",
        FT_UINT32, BASE_DEC, NULL, 0x0001ffff, NULL, HFILL } },
    { &hf_radiotap_vht_su_sig_b_length_40_mhz,
        { "SIG-B Length", "ixveriwave.vht.sig_b_length",
        FT_UINT32, BASE_DEC, NULL, 0x0007ffff, NULL, HFILL } },
    { &hf_radiotap_vht_su_sig_b_length_80_160_mhz,
        { "SIG-B Length", "ixveriwave.vht.sig_b_length",
        FT_UINT32, BASE_DEC, NULL, 0x001fffff, NULL, HFILL } },
    { &hf_radiotap_vht_mu_sig_b_length_20_mhz,
        { "SIG-B Length", "ixveriwave.vht.sig_b_length",
        FT_UINT32, BASE_DEC, NULL, 0x0000ffff, NULL, HFILL } },
    { &hf_radiotap_vht_mu_mcs_20_mhz,
        { "MCS index", "ixveriwave.vht.mcs",
        FT_UINT32, BASE_DEC, NULL, 0x000f0000, NULL, HFILL } },
    { &hf_radiotap_vht_mu_sig_b_length_40_mhz,
        { "SIG-B Length", "ixveriwave.vht.sig_b_length",
        FT_UINT32, BASE_DEC, NULL, 0x0001ffff, NULL, HFILL } },
    { &hf_radiotap_vht_mu_mcs_40_mhz,
        { "MCS index", "ixveriwave.vht.mcs",
        FT_UINT32, BASE_DEC, NULL, 0x001e0000, NULL, HFILL } },
    { &hf_radiotap_vht_mu_sig_b_length_80_160_mhz,
        { "SIG-B Length", "ixveriwave.vht.sig_b_length",
        FT_UINT32, BASE_DEC, NULL, 0x0007ffff, NULL, HFILL } },
    { &hf_radiotap_vht_mu_mcs_80_160_mhz,
        { "MCS index", "ixveriwave.vht.mcs",
        FT_UINT32, BASE_DEC, NULL, 0x00780000, NULL, HFILL } },

    { &hf_radiotap_rfid,
        { "RFID", "ixveriwave.rfid",
        FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL } },

    { &hf_radiotap_l2_l4_info,
        {"Layer 2-4 Header", "ixveriwave.l2_l4info",
        FT_NONE, BASE_NONE, NULL, 0, NULL, HFILL } },

    { &hf_radiotap_bssid,
        {"BSS ID", "ixveriwave.bssid",
        FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },

    { &hf_radiotap_clientidvalid,
        { "Client Id Valid", "ixveriwave.clientidvalid",
        FT_BOOLEAN, 8, TFS(&tfs_yes_no), 0x20, NULL, HFILL } },
    { &hf_radiotap_bssidvalid,
        { "BSS ID Valid", "ixveriwave.bssidvalid",
        FT_BOOLEAN, 8, TFS(&tfs_yes_no), 0x40, NULL, HFILL } },
    { &hf_radiotap_unicastormulticast,
        { "Unicast/Multicast", "ixveriwave.unicastormulticast",
        FT_UINT8, BASE_DEC, VALS(bmbit), 0x80, NULL, HFILL } },

#if 0
    { &hf_radiotap_wlantype,
        { "WLAN Type", "ixveriwave.wlantype",
        FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },
#endif

    { &hf_radiotap_tid,
        { "TID", "ixveriwave.tid",
        FT_UINT16, BASE_HEX, NULL, 0x01c0, NULL, HFILL } },
    { &hf_radiotap_ac,
        { "AC", "ixveriwave.tx.ac",
        FT_UINT8, BASE_HEX, NULL, 0x0e, NULL, HFILL } },
    { &hf_radiotap_l4idvalid,
        { "Layer 4 Id Valid", "ixveriwave.l4idvalid",
        FT_BOOLEAN, 8, TFS(&tfs_yes_no), 0x10, NULL, HFILL } },
    { &hf_radiotap_containshtfield,
        { "Contains HT Field", "ixveriwave.containshtfield",
        FT_BOOLEAN, 8, TFS(&tfs_yes_no), 0x20, NULL, HFILL } },
    { &hf_radiotap_istypeqos,
        { "Is Type QOS", "ixveriwave.istypeqos",
        FT_BOOLEAN, 8, TFS(&tfs_yes_no), 0x40, NULL, HFILL } },
    { &hf_radiotap_flowvalid,
        { "Flow Id Valid", "ixveriwave.flowvalid",
        FT_BOOLEAN, 8, TFS(&tfs_yes_no), 0x80, NULL, HFILL } },

    { &hf_radiotap_payloaddecode,
        { "Payload Decode", "ixveriwave.payloaddecode",
        FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL } },

    { &hf_radiotap_vw_info_rx,
        { "Info field", "ixveriwave.info",
        FT_UINT24, BASE_HEX, NULL, 0x0, NULL, HFILL } },

    /* rx info decodes for fpga ver VW510021 */
    { &hf_radiotap_vw_info_rx_crypto_wep_encoded,
        { "Crypto WEP Encoded", "ixveriwave.info.crypto_wep_encoded",
        FT_BOOLEAN, 24, NULL, 0x000001, NULL, HFILL } },
    { &hf_radiotap_vw_info_rx_crypto_tkip_encoded,
        { "Crypto TKIP Encoded", "ixveriwave.info.crypto_tkip_encoded",
        FT_UINT24, BASE_DEC, VALS(crypto_TKIP_type), 0x000006, NULL, HFILL } },
    { &hf_radiotap_vw_info_rx_crypto_rx_tkip_tsc_seqskip,
        { "Crypto RX TKIP TSC SEQSKIP", "ixveriwave.info.crypto_rx_tkip_tsc_seqskip",
        FT_BOOLEAN, 24, NULL, 0x000008, NULL, HFILL } },
    { &hf_radiotap_vw_info_rx_crypto_rx_ccmp_pn_seqskip,
        { "Crypto RX CCMP PN SEQSKIP", "ixveriwave.info.crypto_rx_ccmp_pn_seqskip",
        FT_BOOLEAN, 24, NULL, 0x000010, NULL, HFILL } },
    { &hf_radiotap_vw_info_rx_tkip_not_full_msdu,
        { "TKIP not full MSDU", "ixveriwave.info.tkip_not_full_msdu",
        FT_BOOLEAN, 24, NULL, 0x000020, NULL, HFILL } },
    { &hf_radiotap_vw_info_rx_mpdu_length_gt_mpdu_octets,
        { "MPDU Length field is greater than MPDU octets", "ixveriwave.info.mpdu_length_gt_mpdu_octets",
        FT_BOOLEAN, 24, NULL, 0x000040, NULL, HFILL } },
    { &hf_radiotap_vw_info_rx_tkip_ccmp_tsc_seqerr,
        { "RX TKIP / CCMP TSC SEQERR", "ixveriwave.info.tkip_ccmp_tsc_seqerr",
        FT_BOOLEAN, 24, NULL, 0x000080, NULL, HFILL } },
    { &hf_radiotap_vw_info_rx_ack_withheld_from_frame,
        { "ACK withheld from frame", "ixveriwave.info.ack_withheld_from_frame",
        FT_BOOLEAN, 24, NULL, 0x000100, NULL, HFILL } },
    { &hf_radiotap_vw_info_rx_client_bssid_matched,
        { "Client BSSID matched", "ixveriwave.info.client_bssid_matched",
        FT_BOOLEAN, 24, NULL, 0x000200, NULL, HFILL } },
    { &hf_radiotap_vw_info_rx_mpdu_of_a_mpdu,
        { "MPDU of A-MPDU", "ixveriwave.info.mpdu_of_a_mpdu",
        FT_BOOLEAN, 24, NULL, 0x000400, NULL, HFILL } },
    { &hf_radiotap_vw_info_rx_first_mpdu_of_a_mpdu,
        { "First MPDU of A-MPDU", "ixveriwave.info.first_mpdu_of_a_mpdu",
        FT_BOOLEAN, 24, NULL, 0x000800, NULL, HFILL } },
    { &hf_radiotap_vw_info_rx_last_mpdu_of_a_mpdu,
        { "Last MPDU of A-MPDU", "ixveriwave.info.last_mpdu_of_a_mpdu",
        FT_BOOLEAN, 24, NULL, 0x001000, NULL, HFILL } },
    { &hf_radiotap_vw_info_rx_msdu_of_a_msdu,
        { "MSDU of A-MSDU", "ixveriwave.info.msdu_of_a_msdu",
        FT_BOOLEAN, 24, NULL, 0x002000, NULL, HFILL } },
    { &hf_radiotap_vw_info_rx_first_msdu_of_a_msdu,
        { "First MSDU of A-MSDU", "ixveriwave.info.first_msdu_of_a_msdu",
        FT_BOOLEAN, 24, NULL, 0x004000, NULL, HFILL } },
    { &hf_radiotap_vw_info_rx_last_msdu_of_a_msdu,
        { "Last MSDU of A-MSDU", "ixveriwave.info.last_msdu_of_a_msdu",
        FT_BOOLEAN, 24, NULL, 0x008000, NULL, HFILL } },
    { &hf_radiotap_vw_info_rx_layer_1_info_0,
        { "Layer 1 Info[0]", "ixveriwave.info.layer_1_info_0",
        FT_UINT24, BASE_DEC, NULL, 0x010000, NULL, HFILL } },
    { &hf_radiotap_vw_info_rx_layer_1_info_1,
        { "Layer 1 Info[1]", "ixveriwave.info.layer_1_info_1",
        FT_UINT24, BASE_DEC, NULL, 0x020000, NULL, HFILL } },
    { &hf_radiotap_vw_info_rx_vht_frame_received_with_vht_sig_b_length,
        { "VHT frame received with the use of the VHT_SIG_B.LENGTH", "ixveriwave.info.vht_frame_received_with_vht_sig_b_length",
        FT_BOOLEAN, 24, NULL, 0x040000, NULL, HFILL } },
    { &hf_radiotap_vw_info_rx_vht_frame_received_without_vht_sig_b_length,
        { "VHT frame received without the use of VHT_SIG_B.LENGTH", "ixveriwave.info.vht_frame_received_without_vht_sig_b_length",
        FT_BOOLEAN, 24, NULL, 0x080000, NULL, HFILL } },
    { &hf_radiotap_vw_info_rx_factory_internal,
        { "Factory Internal", "ixveriwave.info.factory_internal",
        FT_UINT24, BASE_DEC, NULL, 0xf00000, NULL, HFILL } },

    { &hf_radiotap_vw_info_tx,
        { "Info field", "ixveriwave.info",
        FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL } },

    /* tx info decodes for VW510021 and previous versions */
    { &hf_radiotap_vw_info_tx_crypto_wep_encoded,
        { "Crypto WEP Encoded", "ixveriwave.info.crypto_wep_encoded",
        FT_BOOLEAN, 16, NULL, 0x0001, NULL, HFILL } },
    { &hf_radiotap_vw_info_tx_crypto_tkip_encoded,
        { "Crypto TKIP Encoded", "ixveriwave.info.crypto_tkip_encoded",
        FT_UINT16, BASE_DEC, VALS(crypto_TKIP_type), 0x0006, NULL, HFILL } },
    { &hf_radiotap_vw_info_tx_crypto_c_bit_error,
        { "Crypto C bit Error", "ixveriwave.info.crypto_c_bit_error",
        FT_BOOLEAN, 16, NULL, 0x0008, NULL, HFILL } },
    { &hf_radiotap_vw_info_tx_crypto_tkip_not_full_msdu,
        { "Crypto TKIP not full MSDU", "ixveriwave.info.crypto_tkip_not_full_msdu",
        FT_BOOLEAN, 16, NULL, 0x0010, NULL, HFILL } },
    { &hf_radiotap_vw_info_tx_crypto_software_error,
        { "Crypto Software Error", "ixveriwave.info.crypto_software_error",
        FT_BOOLEAN, 16, NULL, 0x0020, NULL, HFILL } },
    { &hf_radiotap_vw_info_tx_crypto_short_fault,
        { "Crypto Short Fault", "ixveriwave.info.crypto_short_fault",
        FT_BOOLEAN, 16, NULL, 0x0040, NULL, HFILL } },
    { &hf_radiotap_vw_info_tx_crypto_payload_length_fault,
        { "Crypto Payload Length Fault", "ixveriwave.info.crypto_payload_length_fault",
        FT_BOOLEAN, 16, NULL, 0x0080, NULL, HFILL } },
    { &hf_radiotap_vw_info_tx_sent_rts_before_data,
        { "Sent RTS before Data", "ixveriwave.info.sent_rts_before_data",
        FT_BOOLEAN, 16, NULL, 0x0100, NULL, HFILL } },
    { &hf_radiotap_vw_info_tx_sent_cts_to_self_before_data,
        { "Sent CTS to Self before Data", "ixveriwave.info.sent_cts_to_self_before_data",
        FT_BOOLEAN, 16, NULL, 0x0200, NULL, HFILL } },
    { &hf_radiotap_vw_info_tx_mpdu_of_a_mpdu,
        { "MPDU of A-MPDU", "ixveriwave.info.tx_mpdu_of_a_mpdu",
        FT_BOOLEAN, 16, NULL, INFO_MPDU_OF_A_MPDU, NULL, HFILL } },
    { &hf_radiotap_vw_info_tx_first_mpdu_of_a_mpdu,
        { "First MPDU of A-MPDU", "ixveriwave.info.first_mpdu_of_a_mpdu",
        FT_BOOLEAN, 16, NULL, INFO_FIRST_MPDU_OF_A_MPDU, NULL, HFILL } },
    { &hf_radiotap_vw_info_tx_last_mpdu_of_a_mpdu,
        { "Last MPDU of A-MPDU", "ixveriwave.info.last_mpdu_of_a_mpdu",
        FT_BOOLEAN, 16, NULL, INFO_LAST_MPDU_OF_A_MPDU, NULL, HFILL } },
    { &hf_radiotap_vw_info_tx_msdu_of_a_msdu,
        { "MSDU of A-MSDU", "ixveriwave.info.msdu_of_a_msdu",
        FT_BOOLEAN, 16, NULL, INFO_MSDU_OF_A_MSDU, NULL, HFILL } },
    { &hf_radiotap_vw_info_tx_first_msdu_of_a_msdu,
        { "First MSDU of A-MSDU", "ixveriwave.info.first_msdu_of_a_msdu",
        FT_BOOLEAN, 16, NULL, INFO_FIRST_MSDU_OF_A_MSDU, NULL, HFILL } },
    { &hf_radiotap_vw_info_tx_last_msdu_of_a_msdu,
        { "Last MSDU of A-MSDU", "ixveriwave.info.last_msdu_of_a_msdu",
        FT_BOOLEAN, 16, NULL, INFO_LAST_MSDU_OF_A_MSDU, NULL, HFILL } },

    { &hf_radiotap_vw_errors_rx_sig_field_crc_parity_error,
        { "SIG Field CRC/Parity Error", "ixveriwave.errors.sig_field_crc_parity_error",
        FT_BOOLEAN, 32, NULL, 0x00000001, NULL, HFILL } },
    { &hf_radiotap_vw_errors_rx_non_supported_service_field,
        { "Non-supported service field", "ixveriwave.errors.non_supported_service_field",
        FT_BOOLEAN, 32, NULL, 0x00000002, NULL, HFILL } },
    { &hf_radiotap_vw_errors_rx_frame_length_error,
        { "Frame Length Error", "ixveriwave.errors.frame_length_error",
        FT_BOOLEAN, 32, NULL, 0x00000004, NULL, HFILL } },
    { &hf_radiotap_vw_errors_rx_vht_sig_ab_crc_error,
        { "VHT_SIG_A/B CRC Error", "ixveriwave.errors.vht_sig_ab_crc_error",
        FT_BOOLEAN, 32, NULL, 0x00000008, NULL, HFILL } },
    { &hf_radiotap_vw_errors_rx_crc32_error,
        { "CRC32 Error", "ixveriwave.errors.crc32_error",
        FT_BOOLEAN, 32, NULL, 0x00000010, NULL, HFILL } },
    { &hf_radiotap_vw_errors_rx_l2_de_aggregation_error,
        { "L2 de-aggregation error", "ixveriwave.errors.l2_de_aggregation_error",
        FT_BOOLEAN, 32, NULL, 0x00000020, NULL, HFILL } },
    { &hf_radiotap_vw_errors_rx_duplicate_mpdu,
        { "Duplicate MPDU", "ixveriwave.errors.duplicate_mpdu",
        FT_BOOLEAN, 32, NULL, 0x00000040, NULL, HFILL } },
    { &hf_radiotap_vw_errors_rx_bad_flow_magic_number,
        { "Bad flow magic number", "ixveriwave.errors.bad_flow_magic_number",
        FT_BOOLEAN, 32, NULL, 0x00000080, NULL, HFILL } },
    { &hf_radiotap_vw_errors_rx_bad_flow_payload_checksum,
        { "Bad flow payload checksum", "ixveriwave.errors.bad_flow_payload_checksum",
        FT_BOOLEAN, 32, NULL, 0x00000100, NULL, HFILL } },
    { &hf_radiotap_vw_errors_rx_illegal_vht_sig_value,
        { "Illegal VHT_SIG Value", "ixveriwave.errors.illegal_vht_sig_value",
        FT_BOOLEAN, 32, NULL, 0x00000200, NULL, HFILL } },
    { &hf_radiotap_vw_errors_rx_ip_checksum_error,
        { "IP checksum error", "ixveriwave.errors.ip_checksum_error",
        FT_BOOLEAN, 32, NULL, 0x00000400, NULL, HFILL } },
    { &hf_radiotap_vw_errors_rx_l4_checksum_error,
        { "L4 (TCP/ICMP/IGMP/UDP) checksum error", "ixveriwave.errors.l4_checksum_error",
        FT_BOOLEAN, 32, NULL, 0x00000800, NULL, HFILL } },
    { &hf_radiotap_vw_errors_rx_l1_unsupported_feature,
        { "Layer 1 Unsupported Feature", "ixveriwave.errors.l1_unsupported_feature",
        FT_BOOLEAN, 32, NULL, 0x00001000, NULL, HFILL } },
    { &hf_radiotap_vw_errors_rx_l1_packet_termination,
        { "Layer 1 Packet Termination", "ixveriwave.errors.l1_packet_termination",
        FT_BOOLEAN, 32, NULL, 0x00004000, NULL, HFILL } },
    { &hf_radiotap_vw_errors_rx_internal_error_bit15,
        { "Internal Error", "ixveriwave.errors.internal_error",
        FT_BOOLEAN, 32, NULL, 0x00008000, NULL, HFILL } },
    { &hf_radiotap_vw_errors_rx_wep_mic_miscompare,
        { "WEP IVC/TKIP/CCMP/BIP MIC Miscompare", "ixveriwave.errors.wep_mic_miscompare",
        FT_BOOLEAN, 32, NULL, 0x00010000, NULL, HFILL } },
    { &hf_radiotap_vw_errors_rx_wep_tkip_rate_exceeded,
        { "WEP/TKIP Rate Exceeded", "ixveriwave.errors.wep_tkip_rate_exceeded",
        FT_BOOLEAN, 32, NULL, 0x00020000, NULL, HFILL } },
    { &hf_radiotap_vw_errors_rx_crypto_short_error,
        { "Crypto Short Error", "ixveriwave.errors.crypto_short_error",
        FT_BOOLEAN, 32, NULL, 0x00040000, NULL, HFILL } },
    { &hf_radiotap_vw_errors_rx_extiv_fault_a,
        { "EXTIV Fault A", "ixveriwave.errors.extiv_fault_a",
        FT_BOOLEAN, 32, NULL, 0x00080000, NULL, HFILL } },
    { &hf_radiotap_vw_errors_rx_extiv_fault_b,
        { "EXTIV Fault B", "ixveriwave.errors.extiv_fault_b",
        FT_BOOLEAN, 32, NULL, 0x00100000, NULL, HFILL } },
    { &hf_radiotap_vw_errors_rx_internal_error_bit21,
        { "Internal Error", "ixveriwave.errors.internal_error",
        FT_BOOLEAN, 32, NULL, 0x00200000, NULL, HFILL } },
    { &hf_radiotap_vw_errors_rx_protected_fault_a,
        { "Protected Fault A", "ixveriwave.errors.protected_fault_a",
        FT_BOOLEAN, 32, NULL, 0x00400000, NULL, HFILL } },
    { &hf_radiotap_vw_errors_rx_rx_mac_crypto_incompatibility,
        { "RX MAC Crypto Incompatibility", "ixveriwave.errors.rx_mac_crypto_incompatibility",
        FT_BOOLEAN, 32, NULL, 0x00800000, NULL, HFILL } },
    { &hf_radiotap_vw_errors_rx_factory_debug,
        { "Factory Debug", "ixveriwave.errors.factory_debug",
        FT_UINT32, BASE_HEX, NULL, 0x7F000000, NULL, HFILL } },
    { &hf_radiotap_vw_errors_rx_internal_error_bit32,
        { "Internal Error", "ixveriwave.errors.internal_error",
        FT_BOOLEAN, 32, NULL, 0x80000000, NULL, HFILL } },

    { &hf_radiotap_vw_errors_tx_packet_fcs_error,
        { "Packet FCS error", "ixveriwave.errors.packet_fcs_error",
        FT_BOOLEAN, 16, NULL, 0x0002, NULL, HFILL } },
    { &hf_radiotap_vw_errors_tx_ip_checksum_error,
        { "IP checksum error", "ixveriwave.errors.ip_checksum_error",
        FT_BOOLEAN, 16, NULL, 0x0020, NULL, HFILL } },

    { &hf_radiotap_vw_tx_retrycount,
        { "Retry Count", "ixveriwave.tx.retrycount",
        FT_UINT8, BASE_DEC, NULL, 0x1f, NULL, HFILL } },
    { &hf_radiotap_vw_tx_factorydebug,
        { "Factory Debug", "ixveriwave.tx.factorydebug",
        FT_UINT16, BASE_HEX, NULL, 0x7f80, NULL, HFILL } },
    };

    static int *ett[] = {
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
 * Editor modelines  -  https://www.wireshark.org/tools/modelines.html
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
