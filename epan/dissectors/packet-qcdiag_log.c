/* packet-qcdiag_log.c
 * Dissector routines for Qualcomm DIAG packet handling
 *
 * (C) 2016-2017 by Harald Welte <laforge@gnumonks.org>
 * (C) 2025 by Oliver Smith <osmith@sysmocom.de>
 * (C) 2026 by Tamas Regos <regost@gmail.com>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"

#include <epan/packet.h>

#include <epan/exceptions.h>
#include <epan/show_exception.h>
#include <epan/tfs.h>
#include <epan/to_str.h>
#include <epan/unit_strings.h>
#include <epan/ftypes/ftypes.h>

#include <wsutil/strtoi.h>

#include "packet-e212.h"
#include "packet-gsm_a_common.h"
#include "packet-gsmtap.h"
#include "packet-qcdiag.h"
#include "packet-umts_rlc.h"
#include "expert.h"

#define GSMTAP_HDR_VERSION           0
#define GSMTAP_HDR_HDR_LEN           1
#define GSMTAP_HDR_TYPE              2
#define GSMTAP_HDR_TIMESLOT          3
#define GSMTAP_HDR_ARFCN_4           4
#define GSMTAP_HDR_ARFCN_5           5
#define GSMTAP_HDR_SIGNAL_DBM        6
#define GSMTAP_HDR_SNR_DB            7
#define GSMTAP_HDR_FRAME_NUMBER_8    8
#define GSMTAP_HDR_FRAME_NUMBER_9    9
#define GSMTAP_HDR_FRAME_NUMBER_10  10
#define GSMTAP_HDR_FRAME_NUMBER_11  11
#define GSMTAP_HDR_SUB_TYPE         12
#define GSMTAP_HDR_ANTENNA_NR       13
#define GSMTAP_HDR_SUB_SLOT         14
#define GSMTAP_HDR_RES              15

#define QCDIAG_WCDMA_CID_MASK       0x0FFFFFFF

#define UDP_SRC_PORT                ((uint16_t) 13337)  /* Based on SCAT (assumingly P2P related) */
#define UDP_DST_PORT                ((uint16_t) 47290)  /* User plane UDP port based on GSMTAP port 4729 */

void proto_register_qcdiag_log(void);
void proto_reg_handoff_qcdiag_log(void);

static dissector_handle_t data_handle;
static dissector_handle_t text_lines_handle;
static dissector_handle_t udp_handle;
static dissector_handle_t gsmtap_handle;

static dissector_table_t qcdiag_log_code_dissector_table;

static heur_dtbl_entry_t *hdtbl_entry;

static int proto_qcdiag_log;

static int hf_qcdiag_log_ver;
static int hf_qcdiag_log_ver_4;
static int hf_qcdiag_arfcn;
static int hf_qcdiag_uplink;
static int hf_qcdiag_pcs;
static int hf_qcdiag_psc;
static int hf_qcdiag_subtype_v1;
static int hf_qcdiag_subtype_v2;
static int hf_qcdiag_packet_ver;
static int hf_qcdiag_lte_rrc_rel;
static int hf_qcdiag_nr_rrc_rel;
static int hf_qcdiag_lte_nas_rel;
static int hf_qcdiag_log_len;
static int hf_qcdiag_log_more;
static int hf_qcdiag_log_timestamp;

static int hf_qcdiag_rr_chan_type;
static int hf_qcdiag_rr_direction;
static int hf_qcdiag_rr_msg_type;

static int hf_qcdiag_mac_chan_type;
static int hf_qcdiag_mac_direction;
static int hf_qcdiag_mac_msg_type;

static int hf_qcdiag_wcdma_rrc_state;
static int hf_qcdiag_wcdma_rrc_procedure;
static int hf_qcdiag_wcdma_rrc_failure_cause;
static int hf_qcdiag_wcdma_rrc_prot_err_cause;
static int hf_qcdiag_wcdma_cid_ul_uarfcn;
static int hf_qcdiag_wcdma_cid_dl_uarfcn;
static int hf_qcdiag_wcdma_cid_cell_id;
static int hf_qcdiag_wcdma_cid_ura_id;
static int hf_qcdiag_wcdma_cid_cell_barred;
static int hf_qcdiag_wcdma_cid_cell_reserved;
static int hf_qcdiag_wcdma_cid_cell_solsa;
static int hf_qcdiag_wcdma_cid_ue_camped;
static int hf_qcdiag_wcdma_cid_reserved;
static int hf_qcdiag_wcdma_cid_allowed_call_access;
static int hf_qcdiag_wcdma_cid_psc;
static int hf_qcdiag_wcdma_cid_mcc;
static int hf_qcdiag_wcdma_cid_mnc;
static int hf_qcdiag_wcdma_cid_lac;
static int hf_qcdiag_wcdma_cid_rac;
static int hf_qcdiag_wcdma_freq_scan_type;
static int hf_qcdiag_wcdma_freq_scan_thres;
static int hf_qcdiag_wcdma_freq_scan_num;
static int hf_qcdiag_wcdma_freq_scan_arfcn;
static int hf_qcdiag_wcdma_freq_scan_rssi_raw;
static int hf_qcdiag_wcdma_freq_scan_rssi_dbm;
static int hf_qcdiag_wcdma_crr_ver;
static int hf_qcdiag_wcdma_crr_num_3g;
static int hf_qcdiag_wcdma_crr_reserved;
static int hf_qcdiag_wcdma_crr_num_2g;
static int hf_qcdiag_wcdma_crr_uarfcn_3g;
static int hf_qcdiag_wcdma_crr_psc_3g;
static int hf_qcdiag_wcdma_crr_rscp_3g;
static int hf_qcdiag_wcdma_crr_rscp_rank_3g;
static int hf_qcdiag_wcdma_crr_ecio_3g;
static int hf_qcdiag_wcdma_crr_ecio_rank_3g;
static int hf_qcdiag_wcdma_crr_arfcn_2g;
static int hf_qcdiag_wcdma_crr_rssi_2g;
static int hf_qcdiag_wcdma_crr_rssi_rank_2g;
static int hf_qcdiag_wcdma_crr_bsic_2g;
static int hf_qcdiag_wcdma_crr_bsic_bcc;
static int hf_qcdiag_wcdma_crr_bsic_ncc;
static int hf_qcdiag_wcdma_crr_resel_status;
static int hf_qcdiag_wcdma_crr_hcs_priority;
static int hf_qcdiag_wcdma_crr_h_value;
static int hf_qcdiag_wcdma_crr_hcs_cell_qualify;
static int hf_qcdiag_wcdma_rlc_num_ent;
static int hf_qcdiag_wcdma_rlc_num_pdu;
static int hf_qcdiag_wcdma_rlc_lcid;
static int hf_qcdiag_wcdma_rlc_pdu_size;
static int hf_qcdiag_wcdma_rlc_pdu_size_bits;
static int hf_qcdiag_wcdma_rlc_pdu_count;
static int hf_qcdiag_wcdma_rlc_ciph_key;
static int hf_qcdiag_wcdma_rlc_ciph_alg;
static int hf_qcdiag_wcdma_rlc_ciph_msg;
static int hf_qcdiag_wcdma_rlc_ciph_countc;

static int hf_qcdiag_nas_msg_length;
static int hf_qcdiag_nas_direction;

static int hf_qcdiag_rrc_chan_type;
static int hf_qcdiag_rrc_chan_type_umts_v1;
static int hf_qcdiag_rrc_chan_type_umts_v2;
static int hf_qcdiag_rrc_rb_id;
static int hf_qcdiag_msg_len_1;
static int hf_qcdiag_msg_len_2;

static int hf_qcdiag_lte_rrc_rb_id;
static int hf_qcdiag_lte_rrc_pci;
static int hf_qcdiag_lte_rrc_earfcn_v2;
static int hf_qcdiag_lte_rrc_earfcn_v8;
static int hf_qcdiag_lte_rrc_sfn;
static int hf_qcdiag_lte_rrc_pdu;
static int hf_qcdiag_lte_rrc_sib;

static int ett_qcdiag_log;
static int ett_qcdiag_log_wcdma_crr_wcmda;
static int ett_qcdiag_log_wcdma_crr_gsm;
static int ett_qcdiag_log_wcdma_cid_car;
static int ett_qcdiag_log_wcdma_rlc_dl_am_sig;
static int ett_qcdiag_log_wcdma_rlc_dl_am_ciph;
static int ett_qcdiag_log_wcdma_rlc_ul_am_ciph;
static int ett_qcdiag_log_wcdma_freq_scan;

static expert_field ei_qcdiag_log_mcc_non_decimal;
static expert_field ei_qcdiag_log_mnc_non_decimal;

static bool heur_rlc_udp_enabled;

static const true_false_string tfs_downlink_uplink = { "Downlink", "Uplink" };

/* Active flags indicating "not set" status for restricted states */
static const true_false_string tfs_not_barred_barred = { "Cell Not Barred", "Cell Barred" };
static const true_false_string tfs_not_reserved_reserved = { "Cell Not Reserved", "Cell Reserved" };
static const true_false_string tfs_not_reserved_reserved_solsa = { "Cell Not Reserved", "Cell Reserved for SoLSA" };
static const true_false_string tfs_not_camped_camped = { "UE Not Camped On A Cell", "UE Camped On A Cell" };

/* Subscription Id 1 (Radio Id 0), Subscription Id 2 (Radio Id 1) */
static int gsm_last_uarfcn[]     = { 0, 0 };
static int umts_last_uarfcn_dl[] = { 0, 0 };
static int umts_last_uarfcn_ul[] = { 0, 0 };
//static int umts_last_cell_id[]   = { 0, 0 };

typedef struct _value_number {
    uint32_t value;   /**< Numeric value to match. */
    uint32_t number;  /**< Corresponding number representation. */
} value_number;

static const value_string rr_chan_types[] = {
    { 0, "DCCH" },
    { 1, "BCCH" },
    { 2, "RACH" },
    { 3, "CCCH" },
    { 4, "SACCH" },
    { 5, "SDCCH" },
    { 6, "FACCH/F" },
    { 7, "FACCH/H" },
    { 0, NULL }
};

enum gprs_mac_chan_type {
    PRACH_11BIT_CHANNEL = 0x01,
    PRACH_8BIT_CHANNEL  = 0x02,
    PACCH_RRBP_CHANNEL  = 0x03,
    UL_PACCH_CHANNEL    = 0x04,
    PPCH_CHANNEL        = 0x80,
    PAGCH_CHANNEL       = 0x81,
    PBCCH_CHANNEL       = 0x82,
    DL_PACCH_CHANNEL    = 0x83,
};

static const value_string mac_chan_types[] = {
    { PRACH_11BIT_CHANNEL, "PRACH (11 bit)" },
    { PRACH_8BIT_CHANNEL,  "PRACH (8 bit)" },
    { PACCH_RRBP_CHANNEL,  "PACCH (RRBP)" },
    { UL_PACCH_CHANNEL,    "UL-PACCH" },
    { PPCH_CHANNEL,        "PPCH" },
    { PAGCH_CHANNEL,       "PAGCH" },
    { PBCCH_CHANNEL,       "PBCCH" },
    { DL_PACCH_CHANNEL,    "DL-PACCH" },
    { 0, NULL }
};

static const value_number gsm_gmac_channel_type_map[] = {
    { PRACH_11BIT_CHANNEL, GSMTAP_CHANNEL_PACCH },
    { PRACH_8BIT_CHANNEL,  GSMTAP_CHANNEL_PACCH },
    { PACCH_RRBP_CHANNEL,  GSMTAP_CHANNEL_PACCH },
    { UL_PACCH_CHANNEL,    GSMTAP_CHANNEL_PACCH },
    { PPCH_CHANNEL,        GSMTAP_CHANNEL_PACCH },
    { PAGCH_CHANNEL,       GSMTAP_CHANNEL_PACCH },
    { PBCCH_CHANNEL,       GSMTAP_CHANNEL_PACCH },
    { DL_PACCH_CHANNEL,    GSMTAP_CHANNEL_PACCH },
    { 0, UINT32_MAX }
};

static const value_number gsm_rr_channel_type_map[] = {
    {  0, GSMTAP_CHANNEL_SDCCH8 },                        /* DCCH */
    {  1, GSMTAP_CHANNEL_BCCH },                          /* BCCH */
    {  2, GSMTAP_CHANNEL_RACH },                          /* RACH */
    {  3, GSMTAP_CHANNEL_CCCH },                          /* CCCH */
    {  4, GSMTAP_CHANNEL_ACCH | GSMTAP_CHANNEL_SDCCH8 },  /* SACCH */
    {  5, GSMTAP_CHANNEL_SDCCH },                         /* SDCCH */
    {  6, GSMTAP_CHANNEL_TCH_F },                         /* FACCH */
    {  7, GSMTAP_CHANNEL_TCH_F },                         /* TCH/F */
    {  8, GSMTAP_CHANNEL_TCH_F },                         /* TCH/F9.6 */
    {  9, GSMTAP_CHANNEL_TCH_F },                         /* TCH/F14.4 */
    { 10, GSMTAP_CHANNEL_TCH_H },                         /* TCH/H */
    { 11, GSMTAP_CHANNEL_VOICE_F },                       /* TCH/AFS */
    { 12, GSMTAP_CHANNEL_VOICE_H },                       /* TCH/AHS */
    { 13, GSMTAP_CHANNEL_VOICE_F },                       /* RATSCCH/AFS */
    { 14, GSMTAP_CHANNEL_VOICE_H },                       /* RATSCCH/AHS */
    { 15, GSMTAP_CHANNEL_VOICE_F },                       /* SID_FIRST/AFS */
    { 16, GSMTAP_CHANNEL_VOICE_F },                       /* SID_UPDATE/AFS */
    { 17, GSMTAP_CHANNEL_VOICE_H },                       /* SID_FIRST/AHS */
    { 18, GSMTAP_CHANNEL_VOICE_H },                       /* SID_UPDATE/AHS */
    { 19, GSMTAP_CHANNEL_TCH_H },                         /* FACCH/H */
    { 20, GSMTAP_CHANNEL_VOICE_F },                       /* FACCH_AFS */
    { 21, GSMTAP_CHANNEL_VOICE_H },                       /* FACCH_AHS */
    { 22, GSMTAP_CHANNEL_VOICE_H },                       /* SID_FIRST_INH */
    { 23, GSMTAP_CHANNEL_VOICE_H },                       /* SID_UPDATE_INH */
    { 24, GSMTAP_CHANNEL_VOICE_F },                       /* RATSCCH_MARKER */
    { 25, GSMTAP_CHANNEL_CBCH51 },                        /* CBCH */
    { 26, GSMTAP_CHANNEL_VOICE_F },                       /* ONSET */
    { 27, GSMTAP_CHANNEL_VOICE_F },                       /* TCH_WFS */
    { 28, GSMTAP_CHANNEL_VOICE_F },                       /* FACCH_WFS */
    { 29, GSMTAP_CHANNEL_VOICE_F },                       /* RATSCCH_WFS */
    { 0, UINT32_MAX }
};

static const value_number umts_channel_type_map_v1[] = {
    {    0, GSMTAP_RRC_SUB_UL_CCCH_Message },
    {    1, GSMTAP_RRC_SUB_UL_DCCH_Message },
    {    2, GSMTAP_RRC_SUB_DL_CCCH_Message },
    {    3, GSMTAP_RRC_SUB_DL_DCCH_Message },
    {    4, GSMTAP_RRC_SUB_BCCH_BCH_Message },
    {    5, GSMTAP_RRC_SUB_BCCH_FACH_Message },
    {    6, GSMTAP_RRC_SUB_PCCH_Message },
    {    7, GSMTAP_RRC_SUB_MCCH_Message },
    {    8, GSMTAP_RRC_SUB_MSCH_Message },
    {   10, GSMTAP_RRC_SUB_System_Information_Container },
    { 0, UINT32_MAX }
};

static const value_number umts_channel_type_map_ext_v1[] = {
    { 0x09, GSMTAP_RRC_SUB_BCCH_BCH_Message },
    { 0xFE, GSMTAP_RRC_SUB_BCCH_BCH_Message },
    { 0xFF, GSMTAP_RRC_SUB_BCCH_FACH_Message },
    { 0, UINT32_MAX }
};

static const value_string umts_v1_sub_types[] = {
    {    0, "RRC UL-CCCH" },
    {    1, "RRC UL-DCCH" },
    {    2, "RRC DL-CCCH" },
    {    3, "RRC DL-DCCH" },
    {    4, "RRC BCCH-BCH" },
    {    5, "RRC BCCH-FACH" },
    {    6, "RRC PCCH" },
    {    7, "RRC MCCH" },
    {    8, "RRC MSCH" },
    {    9, "RRC BCCH-BCH" },
    {   10, "RRC System Information Container" },
    { 0xFE, "RRC BCCH-BCH" },
    { 0xFF, "RRC BCCH-FACH" },
    { 0, NULL }
};

static const value_number umts_channel_type_map_v2[] = {
    { 0x80, GSMTAP_RRC_SUB_UL_CCCH_Message },
    { 0x81, GSMTAP_RRC_SUB_UL_DCCH_Message },
    { 0x82, GSMTAP_RRC_SUB_DL_CCCH_Message },
    { 0x83, GSMTAP_RRC_SUB_DL_DCCH_Message },
    { 0x84, GSMTAP_RRC_SUB_BCCH_BCH_Message },
    { 0x85, GSMTAP_RRC_SUB_BCCH_FACH_Message },
    { 0x86, GSMTAP_RRC_SUB_PCCH_Message },
    { 0x87, GSMTAP_RRC_SUB_MCCH_Message },
    { 0x88, GSMTAP_RRC_SUB_MSCH_Message },
    { 0, UINT32_MAX }
};

static const value_number umts_channel_type_map_ext_v2[] = {
    { 0x89, GSMTAP_RRC_SUB_BCCH_BCH_Message },
    { 0xF0, GSMTAP_RRC_SUB_BCCH_BCH_Message },
    { 0, UINT32_MAX }
};

static const value_string umts_v2_sub_types[] = {
    { 0x80, "RRC UL-CCCH" },
    { 0x81, "RRC UL-DCCH" },
    { 0x82, "RRC DL-CCCH" },
    { 0x83, "RRC DL-DCCH" },
    { 0x84, "RRC BCCH-BCH" },
    { 0x85, "RRC BCCH-FACH" },
    { 0x86, "RRC PCCH" },
    { 0x87, "RRC MCCH" },
    { 0x88, "RRC MSCH" },
    { 0x89, "RRC BCCH-BCH" },
    { 0xF0, "RRC BCCH-BCH" },
    { 0, NULL }
};

static const value_number umts_sib_type_map_v1[] = {
    {    0, GSMTAP_RRC_SUB_MasterInformationBlock },
    {    1, GSMTAP_RRC_SUB_SysInfoType1 },
    {    2, GSMTAP_RRC_SUB_SysInfoType2 },
    {    3, GSMTAP_RRC_SUB_SysInfoType3 },
    {    4, GSMTAP_RRC_SUB_SysInfoType4 },
    {    5, GSMTAP_RRC_SUB_SysInfoType5 },
    {    6, GSMTAP_RRC_SUB_SysInfoType6 },
    {    7, GSMTAP_RRC_SUB_SysInfoType7 },
    {    8, GSMTAP_RRC_SUB_SysInfoType8 },
    {    9, GSMTAP_RRC_SUB_SysInfoType9 },
    {   10, GSMTAP_RRC_SUB_SysInfoType10 },
    {   11, GSMTAP_RRC_SUB_SysInfoType11 },
    {   12, GSMTAP_RRC_SUB_SysInfoType12 },
    {   13, GSMTAP_RRC_SUB_SysInfoType13 },
    {   14, GSMTAP_RRC_SUB_SysInfoType13_1 },
    {   15, GSMTAP_RRC_SUB_SysInfoType13_2 },
    {   16, GSMTAP_RRC_SUB_SysInfoType13_3 },
    {   17, GSMTAP_RRC_SUB_SysInfoType13_4 },
    {   18, GSMTAP_RRC_SUB_SysInfoType14 },
    {   19, GSMTAP_RRC_SUB_SysInfoType15 },
    {   20, GSMTAP_RRC_SUB_SysInfoType15_1 },
    {   21, GSMTAP_RRC_SUB_SysInfoType15_2 },
    {   22, GSMTAP_RRC_SUB_SysInfoType15_3 },
    {   23, GSMTAP_RRC_SUB_SysInfoType16 },
    {   24, GSMTAP_RRC_SUB_SysInfoType17 },
    {   25, GSMTAP_RRC_SUB_SysInfoType15_4 },
    {   26, GSMTAP_RRC_SUB_SysInfoType18 },
    {   27, GSMTAP_RRC_SUB_SysInfoTypeSB1 },
    {   28, GSMTAP_RRC_SUB_SysInfoTypeSB2 },
    {   29, GSMTAP_RRC_SUB_SysInfoType15_5 },
    {   30, GSMTAP_RRC_SUB_SysInfoType5bis },
    {   31, GSMTAP_RRC_SUB_SysInfoType11bis },
    {   66, GSMTAP_RRC_SUB_SysInfoType11bis },
    {   67, GSMTAP_RRC_SUB_SysInfoType1 },
    { 0, UINT32_MAX }
};

static const value_string umts_sib_types_v1[] = {
    {    0, "RRC Master Information Block" },
    {    1, "RRC System Information Type 1" },
    {    2, "RRC System Information Type 2" },
    {    3, "RRC System Information Type 3" },
    {    4, "RRC System Information Type 4" },
    {    5, "RRC System Information Type 5" },
    {    6, "RRC System Information Type 6" },
    {    7, "RRC System Information Type 7" },
    {    8, "RRC System Information Type 8" },
    {    9, "RRC System Information Type 9" },
    {   10, "RRC System Information Type 10" },
    {   11, "RRC System Information Type 11" },
    {   12, "RRC System Information Type 12" },
    {   13, "RRC System Information Type 13" },
    {   14, "RRC System Information Type 13.1" },
    {   15, "RRC System Information Type 13.2" },
    {   16, "RRC System Information Type 13.3" },
    {   17, "RRC System Information Type 13.4" },
    {   18, "RRC System Information Type 14" },
    {   19, "RRC System Information Type 15" },
    {   20, "RRC System Information Type 15.1" },
    {   21, "RRC System Information Type 15.1" },
    {   22, "RRC System Information Type 15.3" },
    {   23, "RRC System Information Type 16" },
    {   24, "RRC System Information Type 17" },
    {   25, "RRC System Information Type 15.4" },
    {   26, "RRC System Information Type 18" },
    {   27, "RRC System Information Type SB 1" },
    {   28, "RRC System Information Type SB 2" },
    {   29, "RRC System Information Type 15.5" },
    {   30, "RRC System Information Type 5bis" },
    {   31, "RRC System Information Type 11bis" },
    {   66, "RRC System Information Type 11bis" },
    {   67, "RRC System Information Type 1" },
    { 0, NULL }
};

static const value_number umts_sib_type_map_v2[] = {
    {    0, GSMTAP_RRC_SUB_MasterInformationBlock },
    {    1, GSMTAP_RRC_SUB_SysInfoType1 },
    {    2, GSMTAP_RRC_SUB_SysInfoType2 },
    {    3, GSMTAP_RRC_SUB_SysInfoType3 },
    {    4, GSMTAP_RRC_SUB_SysInfoType4 },
    {    5, GSMTAP_RRC_SUB_SysInfoType5 },
    {    6, GSMTAP_RRC_SUB_SysInfoType6 },
    {    7, GSMTAP_RRC_SUB_SysInfoType7 },
    {    8, GSMTAP_RRC_SUB_SysInfoType8 },
    {    9, GSMTAP_RRC_SUB_SysInfoType9 },
    {   10, GSMTAP_RRC_SUB_SysInfoType10 },
    {   11, GSMTAP_RRC_SUB_SysInfoType11 },
    {   12, GSMTAP_RRC_SUB_SysInfoType12 },
    {   13, GSMTAP_RRC_SUB_SysInfoType13 },
    {   14, GSMTAP_RRC_SUB_SysInfoType13_1 },
    {   15, GSMTAP_RRC_SUB_SysInfoType13_2 },
    {   16, GSMTAP_RRC_SUB_SysInfoType13_3 },
    {   17, GSMTAP_RRC_SUB_SysInfoType13_4 },
    {   18, GSMTAP_RRC_SUB_SysInfoType14 },
    {   19, GSMTAP_RRC_SUB_SysInfoType15 },
    {   20, GSMTAP_RRC_SUB_SysInfoType15_1 },
    {   21, GSMTAP_RRC_SUB_SysInfoType15_2 },
    {   22, GSMTAP_RRC_SUB_SysInfoType15_3 },
    {   23, GSMTAP_RRC_SUB_SysInfoType16 },
    {   24, GSMTAP_RRC_SUB_SysInfoType17 },
    {   25, GSMTAP_RRC_SUB_SysInfoType15_4 },
    {   26, GSMTAP_RRC_SUB_SysInfoType18 },
    {   27, GSMTAP_RRC_SUB_SysInfoTypeSB1 },
    {   28, GSMTAP_RRC_SUB_SysInfoTypeSB2 },
    {   29, GSMTAP_RRC_SUB_SysInfoType15_5 },
    {   30, GSMTAP_RRC_SUB_SysInfoType5bis },
    {   31, GSMTAP_RRC_SUB_SysInfoType19 },
    {   66, GSMTAP_RRC_SUB_SysInfoType11bis },
    {   67, GSMTAP_RRC_SUB_SysInfoType19 },
    { 0, UINT32_MAX }
};

static const value_string umts_sib_types_v2[] = {
    {    0, "RRC Master Information Block" },
    {    1, "RRC System Information Type 1" },
    {    2, "RRC System Information Type 2" },
    {    3, "RRC System Information Type 3" },
    {    4, "RRC System Information Type 4" },
    {    5, "RRC System Information Type 5" },
    {    6, "RRC System Information Type 6" },
    {    7, "RRC System Information Type 7" },
    {    8, "RRC System Information Type 8" },
    {    9, "RRC System Information Type 9" },
    {   10, "RRC System Information Type 10" },
    {   11, "RRC System Information Type 11" },
    {   12, "RRC System Information Type 12" },
    {   13, "RRC System Information Type 13" },
    {   14, "RRC System Information Type 13.1" },
    {   15, "RRC System Information Type 13.2" },
    {   16, "RRC System Information Type 13.3" },
    {   17, "RRC System Information Type 13.4" },
    {   18, "RRC System Information Type 14" },
    {   19, "RRC System Information Type 15" },
    {   20, "RRC System Information Type 15.1" },
    {   21, "RRC System Information Type 15.1" },
    {   22, "RRC System Information Type 15.3" },
    {   23, "RRC System Information Type 16" },
    {   24, "RRC System Information Type 17" },
    {   25, "RRC System Information Type 15.4" },
    {   26, "RRC System Information Type 18" },
    {   27, "RRC System Information Type SB 1" },
    {   28, "RRC System Information Type SB 2" },
    {   29, "RRC System Information Type 15.5" },
    {   30, "RRC System Information Type 5bis" },
    {   31, "RRC System Information Type 19" },
    {   66, "RRC System Information Type 11bis" },
    {   67, "RRC System Information Type 19" },
    { 0, NULL }
};

enum {
    DL_CCCH          =  0,
    DL_DCCH          =  1,
    UL_CCCH          =  2,
    UL_DCCH          =  3,
    BCCH_BCH         =  4,
    BCCH_DL_SCH      =  5,
    PCCH             =  6,
    MCCH             =  7,
    BCCH_BCH_MBMS    =  8,
    BCCH_DL_SCH_BR   =  9,
    BCCH_DL_SCH_MBMS = 10,
    SC_MCCH          = 11,
    SBCCH_SL_BCH     = 12,
    SBCCH_SL_BCH_V2X = 13,
    DL_CCCH_NB       = 14,
    DL_DCCH_NB       = 15,
    UL_CCCH_NB       = 16,
    UL_DCCH_NB       = 17,
    BCCH_BCH_NB      = 18,
    BCCH_BCH_TDD_NB  = 19,
    BCCH_DL_SCH_NB   = 20,
    PCCH_NB          = 21,
    SC_MCCH_NB       = 22
};

static const value_number lte_rrc_sm_v1[] = {
    {  1, BCCH_BCH },
    {  2, BCCH_DL_SCH },
    {  3, MCCH },
    {  4, PCCH },
    {  5, DL_CCCH },
    {  6, DL_DCCH },
    {  7, UL_CCCH },
    {  8, UL_DCCH },
    { 0, UINT32_MAX }
};

static const value_number lte_rrc_sm_v2[] = {
    {  8, BCCH_BCH },
    {  9, BCCH_DL_SCH },
    { 10, MCCH },
    { 11, PCCH },
    { 12, DL_CCCH },
    { 13, DL_DCCH },
    { 14, UL_CCCH },
    { 15, UL_DCCH },
    { 0, UINT32_MAX }
};

static const value_number lte_rrc_sm_v3[] = {
    {  1, BCCH_BCH },
    {  2, BCCH_DL_SCH },
    {  4, MCCH },
    {  5, PCCH },
    {  6, DL_CCCH },
    {  7, DL_DCCH },
    {  8, UL_CCCH },
    {  9, UL_DCCH },
    { 0, UINT32_MAX }
};

static const value_number lte_rrc_sm_v4[] = {
    {  1, BCCH_BCH },
    {  2, BCCH_DL_SCH },
    {  4, MCCH },
    {  5, PCCH },
    {  6, DL_CCCH },
    {  7, DL_DCCH },
    {  8, UL_CCCH },
    {  9, UL_DCCH },
    { 0, UINT32_MAX }
};

static const value_number lte_rrc_sm_v5[] = {
    {  1, BCCH_BCH },
    {  3, BCCH_DL_SCH },
    {  6, MCCH },
    {  7, PCCH },
    {  8, DL_CCCH },
    {  9, DL_DCCH },
    { 10, UL_CCCH },
    { 11, UL_DCCH },
    { 45, BCCH_BCH_NB },
    { 46, BCCH_DL_SCH_NB },
    { 47, PCCH_NB },
    { 48, DL_CCCH_NB },
    { 49, DL_DCCH_NB },
    { 50, UL_CCCH_NB },
    { 52, UL_DCCH_NB },
    { 0, UINT32_MAX }
};

static const value_number lte_rrc_sm_v6[] = {
    {  1, BCCH_BCH },
    {  2, BCCH_DL_SCH },
    {  4, MCCH },
    {  5, PCCH },
    {  6, DL_CCCH },
    {  7, DL_DCCH },
    {  8, UL_CCCH },
    {  9, UL_DCCH },
    { 54, BCCH_BCH_NB },
    { 55, BCCH_DL_SCH_NB },
    { 56, PCCH_NB },
    { 57, DL_CCCH_NB },
    { 58, DL_DCCH_NB },
    { 59, UL_CCCH_NB },
    { 61, UL_DCCH_NB },
    { 0, UINT32_MAX }
};

static const value_string wcdma_rrc_states_vals[] = {
    {  0, "Disconnected" },
    {  1, "Connecting" },
    {  2, "CELL_FACH" },
    {  3, "CELL_DCH" },
    {  4, "CELL_PCH" },
    {  5, "URA_PCH" },
    { 0, NULL }
};

static const value_string umts_rrc_procedure_vals[] = {
    {  0, "Cell Selection" },
    {  1, "SIB Processing" },
    {  2, "Paging Type 2" },
    {  3, "Measurement Control Reporting" },
    {  4, "RRC Connection Establishment" },
    {  5, "RRC Connection Release" },
    {  6, "UE Capability Information" },
    {  7, "UE Capability Enquiry" },
    {  8, "Initial Direct Transfer" },
    {  9, "Uplink Direct Transfer" },
    { 10, "Downlink Direct Transfer" },
    { 11, "Signaling Connection Release" },
    { 12, "Signalling connection Release Request" },
    { 13, "Counter Check" },
    { 14, "Radio Bearer Establishment" },
    { 15, "Radio Bearer Re-configuration" },
    { 16, "Radio Bearer Release" },
    { 17, "Transport Channel Re-configuration" },
    { 18, "Physical Channel Re-configuration" },
    { 19, "Transport Format Combination Control" },
    { 20, "Cell Update" },
    { 21, "URA Update" },
    { 22, "UTRAN Mobility Information" },
    { 23, "Active Set Update" },
    { 24, "Inter-System Handover from UTRAN" },
    { 25, "Inter-System Handover to UTRAN" },
    { 26, "Inter-System Cell Reselection from UTRAN" },
    { 27, "Inter-System Cell Reselection to UTRAN" },
    { 28, "Paging Type 1" },
    { 29, "Security Mode Command" },
    { 0, NULL }
};

static const value_string umts_rrc_fail_cause_vals[] = {
    {  0, "Configuration Unsupported" },
    {  1, "Physical Channel Failure" },
    {  2, "Incompatible Simultaneous Reconfig" },
    {  3, "Protocol Error" },
    {  4, "Compressed Mode Runtime Error" },
    {  5, "Cell Reselection" },
    {  6, "Invalid Configuration" },
    {  7, "Configuration Incomplete" },
    {  8, "Unsupported Measurement" },
    { 0, NULL }
};

static const value_string umts_rrc_prot_err_vals[] = {
    {  0, "ASN.1 Violation / Encoding Error" },
    {  1, "Not Existing or Not Implemented Message Type" },
    {  2, "Message Incompatible With Rx State" },
    {  3, "IE Value Not Understood" },
    {  4, "Conditional IE Error" },
    {  5, "Message Extension Not Understood" },
    { 0, NULL }
};

static const value_string wcdma_cid_allowed_call_access_vals[] = {
    { 0, "All Calls" },
    { 1, "Emergency Calls Only" },
    { 0, NULL }
};

static const value_string wcdma_rlc_ciph_level_vals[] = {
    {   0, "UEA0 (No ciphering)" },
    {   1, "UEA1" },
    {   2, "UEA2" },
    {   3, "UEA3" },
    { 255, "Not set" },
    { 0, NULL }
};

static const value_string wcdma_freq_scan_type_vals[] = {
    {   0, "Raw Scan" },
    {   1, "Fine Scan" },
    {   2, "Additional Channel Scan" },
    {   3, "List Scan" },
    { 0, NULL }
};

static uint32_t
try_val_to_int(const uint32_t val, const value_number *cm)
{
    int i = 0;

    if (cm) {
        while (cm[i].number != UINT32_MAX) {
            if (cm[i].value == val) {
                return(cm[i].number);
            }
            i++;
        }
    }

    return UINT32_MAX;
}

static void
try_call_dissector(dissector_handle_t handle, tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
  TRY {
    call_dissector(handle, tvb, pinfo, tree);
  }
  CATCH_BOUNDS_ERRORS {
    show_exception(tvb, pinfo, tree, EXCEPT_CODE, GET_MESSAGE);
  }
  ENDTRY;
}

static void
qcdiag_format_ver(char *s, uint32_t ver)
{
    uint8_t low, high;

    high = ver >> 16;
    low  = ver & 0xffff;

    if (high)
        snprintf(s, ITEM_LABEL_LENGTH, "%u (%u.%u)", ver, high, low);
    else
        snprintf(s, ITEM_LABEL_LENGTH, "%u (%u)", ver, low);
}

static void
dissect_qcdiag_log_set_col(packet_info *pinfo, uint32_t gsmtap_type)
{
    const char *str;

    str = val_to_str(pinfo->pool, gsmtap_type, gsmtap_types, "Unknown GSMTAP type (%d)");

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "GSMTAP");
    col_set_str(pinfo->cinfo, COL_INFO, str);
}

static void
dissect_qcdiag_log_append_text(proto_tree *log_tree, proto_tree *tree, bool direction)
{
    proto_item *ti;

    ti = proto_tree_get_parent(log_tree);
    proto_item_append_text(ti, " (%s)", tfs_get_string(direction, &tfs_uplink_downlink));

    ti = proto_tree_get_parent(tree);
    proto_item_append_text(ti, " (%s)", tfs_get_string(direction, &tfs_uplink_downlink));
}

static void
store_uint16(uint8_t **array_ptr, uint16_t value) {
    uint16_t network_value = g_htons(value);

    memcpy(*array_ptr, &network_value, sizeof(uint16_t));

    *array_ptr += sizeof(uint16_t);
}

static tvbuff_t*
get_udp_hdr_tvb(packet_info *pinfo _U_, uint16_t pdu_size, const char *string)
{
    tvbuff_t *udp_hdr_tvb;
    uint8_t *udp_bytes, *arr_ptr;
    uint16_t str_len, rlc_hdr_len, udp_hdr_len, udp_len;

    str_len = (uint16_t)strlen(string);
    rlc_hdr_len = str_len + 5;

    udp_hdr_len = 8;
    udp_len = udp_hdr_len + rlc_hdr_len + pdu_size;

    udp_bytes = (uint8_t*)wmem_alloc0(pinfo->pool, udp_hdr_len);

    arr_ptr = udp_bytes;
    store_uint16(&arr_ptr, UDP_SRC_PORT);  /* Source Port */
    store_uint16(&arr_ptr, UDP_DST_PORT);  /* Destination Port */
    store_uint16(&arr_ptr, udp_len);       /* Length */
    store_uint16(&arr_ptr, 0xffff);        /* Checksum */

    udp_hdr_tvb = tvb_new_real_data(udp_bytes, udp_hdr_len, udp_hdr_len);

    return udp_hdr_tvb;
}

static tvbuff_t*
get_rlc_hdr_tvb(packet_info *pinfo, uint8_t direction)
{
    tvbuff_t *rlc_hdr_tvb;
    uint8_t *rlc_bytes;
    uint16_t str_len, rlc_hdr_len;

    str_len = (uint16_t)strlen(RLC_START_STRING);
    rlc_hdr_len = str_len + 5;

    rlc_bytes = (uint8_t*)wmem_alloc0(pinfo->pool, rlc_hdr_len);

    memcpy(rlc_bytes, RLC_START_STRING, str_len);
    rlc_bytes[str_len++] = RLC_MODE_TAG;
    rlc_bytes[str_len++] = RLC_AM;
    rlc_bytes[str_len++] = RLC_DIRECTION_TAG;
    rlc_bytes[str_len++] = direction;
    rlc_bytes[str_len++] = RLC_PAYLOAD_TAG;

    rlc_hdr_tvb = tvb_new_real_data(rlc_bytes, rlc_hdr_len, rlc_hdr_len);

    return rlc_hdr_tvb;
}

static tvbuff_t*
get_gsmtap_hdr_tvb(packet_info *pinfo, uint8_t type, uint16_t arfcn, uint32_t frame_nr, uint8_t subtype, uint8_t subslot)
{
    tvbuff_t *gsmtap_hdr_tvb;
    uint8_t *gsmtap_bytes;

    gsmtap_bytes = (uint8_t*)wmem_alloc0(pinfo->pool, 16);

    gsmtap_bytes[GSMTAP_HDR_VERSION]         = 0x02;
    gsmtap_bytes[GSMTAP_HDR_HDR_LEN]         = 0x04;
    gsmtap_bytes[GSMTAP_HDR_TYPE]            = type;
    gsmtap_bytes[GSMTAP_HDR_ARFCN_4]         = arfcn >> 8;
    gsmtap_bytes[GSMTAP_HDR_ARFCN_5]         = arfcn & 0xff;
    gsmtap_bytes[GSMTAP_HDR_FRAME_NUMBER_8]  = (frame_nr >> 24) & 0xff;
    gsmtap_bytes[GSMTAP_HDR_FRAME_NUMBER_9]  = (frame_nr >> 16) & 0xff;
    gsmtap_bytes[GSMTAP_HDR_FRAME_NUMBER_10] = (frame_nr >>  8) & 0xff;
    gsmtap_bytes[GSMTAP_HDR_FRAME_NUMBER_11] = frame_nr & 0xff;
    gsmtap_bytes[GSMTAP_HDR_SUB_TYPE]        = subtype;
    gsmtap_bytes[GSMTAP_HDR_SUB_SLOT]        = subslot;

    gsmtap_hdr_tvb = tvb_new_real_data(gsmtap_bytes, 16, 16);

    return gsmtap_hdr_tvb;
}

static uint32_t
get_lte_rrc_subtype(uint32_t pkt_ver, uint32_t pdu)
{
    const value_number* selected_map = NULL;

    switch (pkt_ver) {
        case 0x02:
        case 0x03:
        case 0x04:
        case 0x06:
        case 0x07:
        case 0x08:
        case 0x0d:
        case 0x16:
            selected_map = lte_rrc_sm_v1;
            break;
        case 0x09:
        case 0x0c:
            selected_map = lte_rrc_sm_v2;
            break;
        case 0x0e:
            selected_map = lte_rrc_sm_v3;
            break;
        case 0x0f:
        case 0x10:
            selected_map = lte_rrc_sm_v4;
            break;
        case 0x13:
            selected_map = lte_rrc_sm_v5;
            break;
        case 0x14:
        case 0x18:
        case 0x19:
            selected_map = lte_rrc_sm_v6;
            break;
        case 0x1a:
        case 0x1b:
        case 0x1e:
            selected_map = lte_rrc_sm_v5;
            break;
        default:
            return UINT32_MAX;
    }

    return try_val_to_int(pdu, selected_map);
}

static void
dissect_qcdiag_log_wcdma_search_cell_resel_rank(tvbuff_t *tvb, uint32_t offset, packet_info *pinfo _U_, proto_tree *log_tree, proto_tree *tree _U_)
{
    proto_tree *subtree;
    uint8_t i, len, version, num_wcdma, num_gsm;
    int8_t rscp, rssi;
    int16_t rscp_rank, ecio_rank, rssi_rank, h_val;
    float ecio;

    /* Version */
    proto_tree_add_item_ret_uint8(log_tree, hf_qcdiag_wcdma_crr_ver, tvb, offset, 1, ENC_NA, &version);

    /* Number of WCDMA Cells */
    proto_tree_add_item_ret_uint8(log_tree, hf_qcdiag_wcdma_crr_num_3g, tvb, offset, 1, ENC_NA, &num_wcdma);
    offset += 1;

    /* Reserved */
    proto_tree_add_item(log_tree, hf_qcdiag_wcdma_crr_reserved, tvb, offset, 1, ENC_NA);

    /* Number of GSM Cells */
    proto_tree_add_item_ret_uint8(log_tree, hf_qcdiag_wcdma_crr_num_2g, tvb, offset, 1, ENC_NA, &num_gsm);
    offset += 1;

    if (!(version == 0 || version == 1 || version == 2))
        return;

    /* From Version 2 there are 5 more bytes (so far unknown) */
    if (version == 2)
        offset += 5;

    for (i = 0; i < num_wcdma; i++) {
        len = 10;
        if (version == 1) len = 11;
        if (version == 2) len = 16;

        subtree = proto_tree_add_subtree_format(log_tree, tvb, offset, len,
                   ett_qcdiag_log_wcdma_crr_wcmda, NULL, "WCDMA Cell %d", i);

        /* RF Channel Frequency */
        proto_tree_add_item(subtree, hf_qcdiag_wcdma_crr_uarfcn_3g, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        offset += 2;

        /* Primary Scrambling Code */
        proto_tree_add_item(subtree, hf_qcdiag_wcdma_crr_psc_3g, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        offset += 2;

        rscp = tvb_get_int8(tvb, offset) - 21;

        /* Received Signal Code Power */
        proto_tree_add_int(subtree, hf_qcdiag_wcdma_crr_rscp_3g, tvb, offset, 1, rscp);
        offset += 1;

        rscp_rank = tvb_get_int16(tvb, offset, ENC_LITTLE_ENDIAN);

        /* Cell Ranking RSCP */
        proto_tree_add_int(subtree, hf_qcdiag_wcdma_crr_rscp_rank_3g, tvb, offset, 2, rscp_rank);
        offset += 2;

        ecio = (tvb_get_uint8(tvb, offset)-256) / 2.f;

        /* Energy Per Chip Over Interference */
        proto_tree_add_float(subtree, hf_qcdiag_wcdma_crr_ecio_3g, tvb, offset, 1, ecio);
        offset += 1;

        ecio_rank = tvb_get_int16(tvb, offset, ENC_LITTLE_ENDIAN);

        /* Cell Ranking Ec/Io */
        proto_tree_add_int(subtree, hf_qcdiag_wcdma_crr_ecio_rank_3g, tvb, offset, 2, ecio_rank);
        offset += 2;

        // TODO: identify the reselection status values
        if (version > 0) {
            /* Reselection Status */
            proto_tree_add_item(subtree, hf_qcdiag_wcdma_crr_resel_status, tvb, offset, 1, ENC_NA);
            offset += 1;
        }

        if (version > 1) {
            /* Hierarchical Cell Structure (HCS) Priority */
            proto_tree_add_item(subtree, hf_qcdiag_wcdma_crr_hcs_priority, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            offset += 2;

            h_val = tvb_get_int16(tvb, offset, ENC_LITTLE_ENDIAN);

            /* H Value */
            proto_tree_add_int(subtree, hf_qcdiag_wcdma_crr_h_value, tvb, offset, 2, h_val);
            offset += 2;

            /* Hierarchical Cell Structure (HCS) Cell Qualify */
            proto_tree_add_item(subtree, hf_qcdiag_wcdma_crr_hcs_cell_qualify, tvb, offset, 1, ENC_NA);
            offset += 1;
        }
    }

    for (i = 0; i < num_gsm; i++) {
        len = 7;
        if (version == 1) len = 8;
        if (version == 2) len = 13;

        subtree = proto_tree_add_subtree_format(log_tree, tvb, offset, len,
                   ett_qcdiag_log_wcdma_crr_gsm, NULL, "GSM Cell %d", i);

        /* RF Channel Frequency */
        proto_tree_add_item(subtree, hf_qcdiag_wcdma_crr_arfcn_2g, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        offset += 2;

        // TODO: interpret BSIC: NCC/BCC (1 byte each or 3-3 bits?)
        /* Base Station Identity Code */
        proto_tree_add_item(subtree, hf_qcdiag_wcdma_crr_bsic_2g, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        offset += 2;

        rssi = tvb_get_int8(tvb, offset);

        /* Received Signal Strength Indicator */
        proto_tree_add_int(subtree, hf_qcdiag_wcdma_crr_rssi_2g, tvb, offset, 1, rssi);
        offset += 1;

        rssi_rank = tvb_get_int16(tvb, offset, ENC_LITTLE_ENDIAN);

        /* Cell Ranking RSSI */
        proto_tree_add_int(subtree, hf_qcdiag_wcdma_crr_rssi_rank_2g, tvb, offset, 2, rssi_rank);
        offset += 2;

        // TODO: is there a Band here? E.g.: Band = 0 (900/1800)

        // TODO: identify the reselection status values
        if (version > 0) {
            /* Reselection Status */
            proto_tree_add_item(subtree, hf_qcdiag_wcdma_crr_resel_status, tvb, offset, 1, ENC_NA);
            offset += 1;
        }

        if (version > 1) {
            /* Hierarchical Cell Structure (HCS) Priority */
            proto_tree_add_item(subtree, hf_qcdiag_wcdma_crr_hcs_priority, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            offset += 2;

            h_val = tvb_get_int16(tvb, offset, ENC_LITTLE_ENDIAN);

            /* H Value */
            proto_tree_add_int(subtree, hf_qcdiag_wcdma_crr_h_value, tvb, offset, 2, h_val);
            offset += 2;

            /* Hierarchical Cell Structure (HCS) Cell Qualify */
            proto_tree_add_item(subtree, hf_qcdiag_wcdma_crr_hcs_cell_qualify, tvb, offset, 1, ENC_NA);
            offset += 1;
        }
    }
}

static void
dissect_qcdiag_log_wcdma_rrc(tvbuff_t *tvb, uint32_t offset, packet_info *pinfo, proto_tree *log_tree, proto_tree *tree)
{
    tvbuff_t *payload_tvb, *gsmtap_hdr_tvb, *gsmtap_tvb;
    uint32_t ct_offset, chan_type, subtype, uplink;
    uint32_t arfcn_val;
    int hf_rrc_ct, hf_qcdiag_subtype;

    uint32_t arfcn[] = { 0, 0 };

    ct_offset = offset;
    chan_type = (uint32_t)tvb_get_uint8(tvb, offset);

    offset += 4;

    arfcn[0] = umts_last_uarfcn_dl[0];
    arfcn[1] = umts_last_uarfcn_dl[1];

    /* Set the Channel Type header field */
    hf_rrc_ct = hf_qcdiag_rrc_chan_type;

    /* Unset the Subtype header field */
    hf_qcdiag_subtype = -1;

    if (chan_type == 0 || chan_type == 1) {
        arfcn[0] = umts_last_uarfcn_ul[0];
        arfcn[1] = umts_last_uarfcn_ul[1];
    }

    if ((subtype = try_val_to_int(chan_type, umts_channel_type_map_v1) != UINT32_MAX)) {
        /* subtype is from umts_channel_type_map_v1 */

        /* Set the Channel Type header field */
        hf_rrc_ct = hf_qcdiag_rrc_chan_type_umts_v1;

    } else if (try_val_to_int(chan_type, umts_channel_type_map_ext_v1) != UINT32_MAX) {
        /* subtype is from umts_channel_type_map_ext_v1 */
        arfcn[0] = umts_last_uarfcn_dl[0];
        arfcn[1] = umts_last_uarfcn_dl[1];

        /* Set the Subtype */
        subtype = try_val_to_int(chan_type, umts_sib_type_map_v1);

        /* Set the Channel Type header field */
        hf_rrc_ct = hf_qcdiag_rrc_chan_type_umts_v1;

        /* Set the Subtype header field */
        hf_qcdiag_subtype = hf_qcdiag_subtype_v1;

        offset += 1;

    } else if ((subtype = try_val_to_int(chan_type, umts_channel_type_map_v2)) != UINT32_MAX) {
        /* subtype is from umts_channel_type_map_v2 */
        arfcn_val = (uint32_t)tvb_get_uint16(tvb, offset, ENC_LITTLE_ENDIAN);

        arfcn[0] = arfcn_val;
        arfcn[1] = arfcn_val;

        /* Set the Channel Type header field */
        hf_rrc_ct = hf_qcdiag_rrc_chan_type_umts_v2;

        offset += 4;

    } else if (try_val_to_int(chan_type, umts_channel_type_map_ext_v2) != UINT32_MAX) {
        /* subtype is from umts_channel_type_map_ext_v2 */
        arfcn_val = (uint32_t)tvb_get_uint16(tvb, offset, ENC_LITTLE_ENDIAN);

        arfcn[0] = arfcn_val;
        arfcn[1] = arfcn_val;

        /* Set the Subtype */
        subtype = (uint32_t)tvb_get_uint8(tvb, offset+4);
        subtype = try_val_to_int(subtype, umts_sib_type_map_v2);

        /* Set the Channel Type header field */
        hf_rrc_ct = hf_qcdiag_rrc_chan_type_umts_v2;

        /* Set the Subtype header field */
        hf_qcdiag_subtype = hf_qcdiag_subtype_v2;

        offset += 5;
    }

    /* Channel Type */
    proto_tree_add_uint(log_tree, hf_rrc_ct, tvb, ct_offset++, 1, chan_type);

    /* Radio Bearer Id */
    proto_tree_add_item(log_tree, hf_qcdiag_rrc_rb_id, tvb, ct_offset++, 1, ENC_NA);

    /* Message Length */
    proto_tree_add_item(log_tree, hf_qcdiag_msg_len_2, tvb, ct_offset, 2, ENC_LITTLE_ENDIAN);

    /* Absolute Radio Frequency Channel Number */
    proto_tree_add_item(log_tree, hf_qcdiag_arfcn, tvb, ct_offset+2, 2, ENC_LITTLE_ENDIAN);

    /* NOTE: the ARFCN value is not always set correctly with regards to direction.
     * For example, WCDMA MIB with ARFCN 0x2975 but MIB is an uplink packet.
     * ..10 1001 0111 0101 = ARFCN: 10613
     * .0.. .... .... .... = Uplink: 0
     * 0... .... .... .... = PCS band indicator: 0
     *
     * ARFCN 0x6975 would mean uplink.
     */

    /* Uplink */
    proto_tree_add_item_ret_uint(log_tree, hf_qcdiag_uplink, tvb, ct_offset+2, 2, ENC_LITTLE_ENDIAN, &uplink);

    /* PCS band indicator */
    proto_tree_add_item(log_tree, hf_qcdiag_pcs, tvb, ct_offset+2, 2, ENC_LITTLE_ENDIAN);

    /* Primary Scrambling Code */
    proto_tree_add_item(log_tree, hf_qcdiag_psc, tvb, ct_offset+4, 2, ENC_LITTLE_ENDIAN);

    /* Subtype */
    if (hf_qcdiag_subtype != -1) {
        proto_tree_add_item(log_tree, hf_qcdiag_subtype, tvb, offset-1, 1, ENC_NA);
    }

    gsmtap_hdr_tvb = get_gsmtap_hdr_tvb(pinfo, GSMTAP_TYPE_UMTS_RRC, arfcn[0], 0, subtype, 0);
    payload_tvb = tvb_new_subset_remaining(tvb, offset);

    gsmtap_tvb = tvb_new_composite();
    tvb_composite_append(gsmtap_tvb, gsmtap_hdr_tvb);
    tvb_composite_append(gsmtap_tvb, payload_tvb);
    tvb_composite_finalize(gsmtap_tvb);

    dissect_qcdiag_log_set_col(pinfo, GSMTAP_TYPE_UMTS_RRC);
    dissect_qcdiag_log_append_text(log_tree, tree, (bool)uplink);

    add_new_data_source(pinfo, gsmtap_tvb, "UMTS RRC");
    try_call_dissector(gsmtap_handle, gsmtap_tvb, pinfo, proto_tree_get_parent_tree(tree));
}

static void
dissect_qcdiag_log_wcdma_rrc_states(tvbuff_t *tvb, uint32_t offset, packet_info *pinfo _U_, proto_tree *log_tree, proto_tree *tree _U_)
{
    uint32_t state;
    const char *state_str;

    /* RRC State */
    proto_tree_add_item_ret_uint(log_tree, hf_qcdiag_wcdma_rrc_state, tvb, offset, 1, ENC_NA, &state);

    state_str = val_to_str(pinfo->pool, state, wcdma_rrc_states_vals, "Unknown State (%d)");
    col_append_fstr(pinfo->cinfo, COL_INFO, ", %s", state_str);
}

static void
dissect_qcdiag_log_wcdma_rrc_prot_errors(tvbuff_t *tvb, uint32_t offset, packet_info *pinfo _U_, proto_tree *log_tree, proto_tree *tree _U_)
{
    /* RRC State */
    proto_tree_add_item(log_tree, hf_qcdiag_wcdma_rrc_state, tvb, offset, 1, ENC_NA);
    offset += 1;

    /* RRC Procedure */
    proto_tree_add_item(log_tree, hf_qcdiag_wcdma_rrc_procedure, tvb, offset, 1, ENC_NA);
    offset += 1;

    /* RRC Failure Cause */
    proto_tree_add_item(log_tree, hf_qcdiag_wcdma_rrc_failure_cause, tvb, offset, 1, ENC_NA);
    offset += 1;

    /* RRC Protocol Error Cause */
    proto_tree_add_item(log_tree, hf_qcdiag_wcdma_rrc_prot_err_cause, tvb, offset, 1, ENC_NA);
}

static void
dissect_qcdiag_log_wcdma_cell_id(tvbuff_t *tvb, uint32_t offset, packet_info *pinfo _U_, proto_tree *log_tree, proto_tree *tree _U_)
{
    proto_tree *subtree;
    proto_item *item;
    uint64_t mcc_mnc;
    uint32_t mcc, mnc;
    uint8_t mcc1, mcc2, mcc3;
    uint8_t mnc1, mnc2, mnc3;
    char *mcc_str, *mnc_str;

    /* UL UTRA ARFCN */
    proto_tree_add_item(log_tree, hf_qcdiag_wcdma_cid_ul_uarfcn, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;

    /* DL UTRA ARFCN  */
    proto_tree_add_item(log_tree, hf_qcdiag_wcdma_cid_dl_uarfcn, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;

    /* Cell Id */
    proto_tree_add_item(log_tree, hf_qcdiag_wcdma_cid_cell_id, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;

    /* UTRAN Registration Area */
    proto_tree_add_item(log_tree, hf_qcdiag_wcdma_cid_ura_id, tvb, offset, 2, ENC_LITTLE_ENDIAN);
    offset += 2;

    /* Cell Access Restrictions */
    subtree = proto_tree_add_subtree_format(log_tree, tvb, offset, 1,
                   ett_qcdiag_log_wcdma_cid_car, NULL, "Cell Access Restrictions");

    /* Cell Barred */
    proto_tree_add_item(subtree, hf_qcdiag_wcdma_cid_cell_barred, tvb, offset, 1, ENC_NA);

    /* Cell Reserved */
    proto_tree_add_item(subtree, hf_qcdiag_wcdma_cid_cell_reserved, tvb, offset, 1, ENC_NA);

    /* Cell Reserved for SoLSA */
    proto_tree_add_item(subtree, hf_qcdiag_wcdma_cid_cell_solsa, tvb, offset, 1, ENC_NA);

    /* UE Camped on Cell */
    proto_tree_add_item(subtree, hf_qcdiag_wcdma_cid_ue_camped, tvb, offset, 1, ENC_NA);

    /* Reserved */
    proto_tree_add_item(subtree, hf_qcdiag_wcdma_cid_reserved, tvb, offset, 1, ENC_NA);
    offset += 1;

    /* Allowed Call Access */
    proto_tree_add_item(log_tree, hf_qcdiag_wcdma_cid_allowed_call_access, tvb, offset, 1, ENC_NA);
    offset += 1;

    /* Primary Scrambling Code */
    proto_tree_add_item(log_tree, hf_qcdiag_wcdma_cid_psc, tvb, offset, 2, ENC_LITTLE_ENDIAN);
    offset += 2;

    mcc_mnc = tvb_get_ntoh48(tvb, offset);

    mcc1 = tvb_get_uint8(tvb, offset);
    mcc2 = tvb_get_uint8(tvb, offset+1);
    mcc3 = tvb_get_uint8(tvb, offset+2);
    mcc = 100*mcc1 + 10*mcc2 + mcc3;
    mcc_str = wmem_strdup_printf(pinfo->pool, "%03u", mcc);

    /* MCC */
    item = proto_tree_add_string_format_value(log_tree, hf_qcdiag_wcdma_cid_mcc, tvb,
               offset, 3, mcc_str, "%s (%s)",
               val_to_str_ext_const(mcc, &E212_codes_ext, "Unknown"),
               mcc_str);

    if (((mcc1 > 9) || (mcc2 > 9) || (mcc3 > 9)) && (mcc_mnc != 0xffffffffffff))
        expert_add_info(pinfo, item, &ei_qcdiag_log_mcc_non_decimal);

    offset += 3;

    mnc1 = tvb_get_uint8(tvb, offset);
    mnc2 = tvb_get_uint8(tvb, offset+1);
    mnc3 = tvb_get_uint8(tvb, offset+2);
    if (mnc3 != 0xf) {
        mnc = 100 * mnc1 + 10 * mnc2 + mnc3;
        mnc_str = wmem_strdup_printf(pinfo->pool, "%03u", mnc);
    } else {
        mnc = 10 * mnc1 + mnc2;
        mnc_str = wmem_strdup_printf(pinfo->pool, "%02u", mnc);
    }

    /* MNC */
    if (mnc3 != 0xf) {
        item = proto_tree_add_string_format_value(log_tree, hf_qcdiag_wcdma_cid_mnc, tvb,
                   offset, 3, mnc_str, "%s (%s)",
                   val_to_str_ext_const(mcc * 1000 + mnc, &mcc_mnc_3digits_codes_ext, "Unknown"),
                   mnc_str);
    } else {
        item = proto_tree_add_string_format_value(log_tree, hf_qcdiag_wcdma_cid_mnc, tvb,
                   offset, 3, mnc_str, "%s (%s)",
                   val_to_str_ext_const(mcc * 100 + mnc, &mcc_mnc_2digits_codes_ext, "Unknown"),
                   mnc_str);
    }

    if (((mnc1 > 9) || (mnc2 > 9) || ((mnc3 > 9) && (mnc3 != 0x0f))) && (mcc_mnc != 0xffffffffffff))
        expert_add_info(pinfo, item, &ei_qcdiag_log_mnc_non_decimal);

    offset += 3;

    /* LAC */
    proto_tree_add_item(log_tree, hf_qcdiag_wcdma_cid_lac, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;

    /* RAC */
    proto_tree_add_item(log_tree, hf_qcdiag_wcdma_cid_rac, tvb, offset, 4, ENC_LITTLE_ENDIAN);

    //umts_last_uarfcn_ul[radio_id] = ul_uarfcn
    //umts_last_uarfcn_dl[radio_id] = dl_uarfcn
    //umts_last_cell_id[radio_id]   = psc
}

static void
dissect_qcdiag_log_wcdma_rlc_dl_am_signaling_pdu(tvbuff_t *tvb, uint32_t offset, packet_info *pinfo, proto_tree *log_tree, proto_tree *tree _U_)
{
    tvbuff_t *payload_tvb, *udp_hdr_tvb, *rlc_tvb, *rlc_hdr_tvb;
    proto_tree *subtree;
    uint8_t i, num;
    uint16_t pdu_count, pdu_size;

    /* Number of Entities */
    proto_tree_add_item_ret_uint8(log_tree, hf_qcdiag_wcdma_rlc_num_ent, tvb, offset, 1, ENC_NA, &num);
    offset += 1;

    for (i = 0; i < num; i++) {
        pdu_size = tvb_get_uint16(tvb, offset+3, ENC_LITTLE_ENDIAN);

        /* Entity # */
        subtree = proto_tree_add_subtree_format(log_tree, tvb, offset, 5+pdu_size,
                   ett_qcdiag_log_wcdma_rlc_dl_am_sig, NULL, "Entity %d", i);

        /* Logical Channel Id */
        proto_tree_add_item(subtree, hf_qcdiag_wcdma_rlc_lcid, tvb, offset, 1, ENC_NA);
        offset += 1;

        /* PDU Count */
        proto_tree_add_item_ret_uint16(subtree, hf_qcdiag_wcdma_rlc_pdu_count, tvb, offset, 2, ENC_LITTLE_ENDIAN, &pdu_count);
        offset += 2;

        /* PDU Size in Bits */
        proto_tree_add_uint(subtree, hf_qcdiag_wcdma_rlc_pdu_size_bits, tvb, offset, 2, pdu_size);
        offset += 2;

        udp_hdr_tvb = get_udp_hdr_tvb(pinfo, pdu_size, RLC_START_STRING);
        rlc_hdr_tvb = get_rlc_hdr_tvb(pinfo, DIRECTION_DOWNLINK);
        payload_tvb = tvb_new_subset_length(tvb, offset, pdu_size);

        offset += pdu_size;

        /* To be able to call "RLC over UDP", an UDP header is also required */
        rlc_tvb = tvb_new_composite();
        tvb_composite_append(rlc_tvb, udp_hdr_tvb);
        tvb_composite_append(rlc_tvb, rlc_hdr_tvb);
        tvb_composite_append(rlc_tvb, payload_tvb);
        tvb_composite_finalize(rlc_tvb);

        /* "RLC over UDP" heuristic UDP dissector is disabled by default */
        if (hdtbl_entry && !heur_rlc_udp_enabled)
            hdtbl_entry->enabled = HEURISTIC_ENABLE;

        add_new_data_source(pinfo, rlc_tvb, "WCDMA RLC");
        try_call_dissector(udp_handle, rlc_tvb, pinfo, proto_tree_get_parent_tree(tree));

        if (hdtbl_entry && !heur_rlc_udp_enabled)
            hdtbl_entry->enabled = HEURISTIC_DISABLE;
    }
}

static void
dissect_qcdiag_log_wcdma_rlc_ul_am_signaling_pdu(tvbuff_t *tvb, uint32_t offset, packet_info *pinfo, proto_tree *log_tree, proto_tree *tree _U_)
{
    tvbuff_t *payload_tvb, *udp_hdr_tvb, *rlc_tvb, *rlc_hdr_tvb;
    proto_tree *subtree;
    uint8_t i, num;
    uint16_t pdu_count, pdu_size;

    /* Number of Entities */
    proto_tree_add_item_ret_uint8(log_tree, hf_qcdiag_wcdma_rlc_num_ent, tvb, offset, 1, ENC_NA, &num);
    offset += 1;

    for (i = 0; i < num; i++) {
        pdu_size = tvb_get_uint16(tvb, offset+3, ENC_LITTLE_ENDIAN);

        /* Entity # */
        subtree = proto_tree_add_subtree_format(log_tree, tvb, offset, 5+pdu_size,
                   ett_qcdiag_log_wcdma_rlc_dl_am_sig, NULL, "Entity %d", i);

        /* Logical Channel Id */
        proto_tree_add_item(subtree, hf_qcdiag_wcdma_rlc_lcid, tvb, offset, 1, ENC_NA);
        offset += 1;

        /* PDU Count */
        proto_tree_add_item_ret_uint16(subtree, hf_qcdiag_wcdma_rlc_pdu_count, tvb, offset, 2, ENC_LITTLE_ENDIAN, &pdu_count);
        offset += 2;

        /* PDU Size in Bits */
        proto_tree_add_uint(subtree, hf_qcdiag_wcdma_rlc_pdu_size_bits, tvb, offset, 2, pdu_size);
        offset += 2;

        udp_hdr_tvb = get_udp_hdr_tvb(pinfo, pdu_size, RLC_START_STRING);
        rlc_hdr_tvb = get_rlc_hdr_tvb(pinfo, DIRECTION_UPLINK);
        payload_tvb = tvb_new_subset_length(tvb, offset, pdu_size);

        offset += pdu_size;

        /* To be able to call "RLC over UDP", an UDP header is also required */
        rlc_tvb = tvb_new_composite();
        tvb_composite_append(rlc_tvb, udp_hdr_tvb);
        tvb_composite_append(rlc_tvb, rlc_hdr_tvb);
        tvb_composite_append(rlc_tvb, payload_tvb);
        tvb_composite_finalize(rlc_tvb);

        /* "RLC over UDP" heuristic UDP dissector is disabled by default */
        if (hdtbl_entry && !heur_rlc_udp_enabled)
            hdtbl_entry->enabled = HEURISTIC_ENABLE;

        add_new_data_source(pinfo, rlc_tvb, "WCDMA RLC");
        try_call_dissector(udp_handle, rlc_tvb, pinfo, proto_tree_get_parent_tree(tree));

        if (hdtbl_entry && !heur_rlc_udp_enabled)
            hdtbl_entry->enabled = HEURISTIC_DISABLE;
    }
}

static void
dissect_qcdiag_log_wcdma_rlc_ul_am_control_pdu(tvbuff_t *tvb, uint32_t offset, packet_info *pinfo, proto_tree *log_tree, proto_tree *tree _U_)
{
    tvbuff_t *payload_tvb, *udp_hdr_tvb, *rlc_tvb, *rlc_hdr_tvb;
    uint16_t pdu_size;

    /* Logical Channel Id */
    proto_tree_add_item(log_tree, hf_qcdiag_wcdma_rlc_lcid, tvb, offset, 1, ENC_NA);
    offset += 1;

    /* PDU Size */
    proto_tree_add_item_ret_uint16(log_tree, hf_qcdiag_wcdma_rlc_pdu_size, tvb, offset, 2, ENC_LITTLE_ENDIAN, &pdu_size);
    offset += 2;

    udp_hdr_tvb = get_udp_hdr_tvb(pinfo, pdu_size, RLC_START_STRING);
    rlc_hdr_tvb = get_rlc_hdr_tvb(pinfo, DIRECTION_UPLINK);
    payload_tvb = tvb_new_subset_length(tvb, offset, pdu_size);

    /* To be able to call "RLC over UDP", an UDP header is also required */
    rlc_tvb = tvb_new_composite();
    tvb_composite_append(rlc_tvb, udp_hdr_tvb);
    tvb_composite_append(rlc_tvb, rlc_hdr_tvb);
    tvb_composite_append(rlc_tvb, payload_tvb);
    tvb_composite_finalize(rlc_tvb);

    /* "RLC over UDP" heuristic UDP dissector is disabled by default */
    if (hdtbl_entry && !heur_rlc_udp_enabled)
        hdtbl_entry->enabled = HEURISTIC_ENABLE;

    add_new_data_source(pinfo, rlc_tvb, "WCDMA RLC");
    try_call_dissector(udp_handle, rlc_tvb, pinfo, proto_tree_get_parent_tree(tree));

    if (hdtbl_entry && !heur_rlc_udp_enabled)
        hdtbl_entry->enabled = HEURISTIC_DISABLE;
}

static void
dissect_qcdiag_log_wcdma_rlc_dl_am_control_pdu(tvbuff_t *tvb, uint32_t offset, packet_info *pinfo, proto_tree *log_tree, proto_tree *tree _U_)
{
    tvbuff_t *payload_tvb, *udp_hdr_tvb, *rlc_tvb, *rlc_hdr_tvb;
    uint16_t pdu_size;

    /* Logical Channel Id */
    proto_tree_add_item(log_tree, hf_qcdiag_wcdma_rlc_lcid, tvb, offset, 1, ENC_NA);
    offset += 1;

    /* PDU Size */
    proto_tree_add_item_ret_uint16(log_tree, hf_qcdiag_wcdma_rlc_pdu_size, tvb, offset, 2, ENC_LITTLE_ENDIAN, &pdu_size);
    offset += 2;

    udp_hdr_tvb = get_udp_hdr_tvb(pinfo, pdu_size, RLC_START_STRING);
    rlc_hdr_tvb = get_rlc_hdr_tvb(pinfo, DIRECTION_DOWNLINK);
    payload_tvb = tvb_new_subset_length(tvb, offset, pdu_size);

    /* To be able to call "RLC over UDP", an UDP header is also required */
    rlc_tvb = tvb_new_composite();
    tvb_composite_append(rlc_tvb, udp_hdr_tvb);
    tvb_composite_append(rlc_tvb, rlc_hdr_tvb);
    tvb_composite_append(rlc_tvb, payload_tvb);
    tvb_composite_finalize(rlc_tvb);

    /* "RLC over UDP" heuristic UDP dissector is disabled by default */
    if (hdtbl_entry && !heur_rlc_udp_enabled)
        hdtbl_entry->enabled = HEURISTIC_ENABLE;

    add_new_data_source(pinfo, rlc_tvb, "WCDMA RLC");
    try_call_dissector(udp_handle, rlc_tvb, pinfo, proto_tree_get_parent_tree(tree));

    if (hdtbl_entry && !heur_rlc_udp_enabled)
        hdtbl_entry->enabled = HEURISTIC_DISABLE;
}

static void
dissect_qcdiag_log_wcdma_rlc_dl_am_cipher_pdu(tvbuff_t *tvb, uint32_t offset, packet_info *pinfo _U_, proto_tree *log_tree, proto_tree *tree _U_)
{
    proto_tree *subtree;
    uint16_t i, num;

    /* Number of PDUs */
    proto_tree_add_item_ret_uint16(log_tree, hf_qcdiag_wcdma_rlc_num_pdu, tvb, offset, 2, ENC_LITTLE_ENDIAN, &num);
    offset += 2;

    for (i = 0; i < num; i++) {
        /* PDU # */
        subtree = proto_tree_add_subtree_format(log_tree, tvb, offset, 14,
                   ett_qcdiag_log_wcdma_rlc_dl_am_ciph, NULL, "PDU %d", i);

        /* Logical Channel Id */
        proto_tree_add_item(subtree, hf_qcdiag_wcdma_rlc_lcid, tvb, offset, 1, ENC_NA);
        offset += 1;

        /* Ciphering Key */
        proto_tree_add_item(subtree, hf_qcdiag_wcdma_rlc_ciph_key, tvb, offset, 4, ENC_LITTLE_ENDIAN);
        offset += 4;

        /* Ciphering Algorithm */
        proto_tree_add_item(subtree, hf_qcdiag_wcdma_rlc_ciph_alg, tvb, offset, 1, ENC_NA);
        offset += 1;

        /* Ciphered Message */
        proto_tree_add_item(subtree, hf_qcdiag_wcdma_rlc_ciph_msg, tvb, offset, 4, ENC_LITTLE_ENDIAN);
        offset += 4;

        /* Count C */
        proto_tree_add_item(subtree, hf_qcdiag_wcdma_rlc_ciph_countc, tvb, offset, 4, ENC_LITTLE_ENDIAN);
        offset += 4;
    }
}

static void
dissect_qcdiag_log_wcdma_rlc_ul_am_cipher_pdu(tvbuff_t *tvb, uint32_t offset, packet_info *pinfo _U_, proto_tree *log_tree, proto_tree *tree _U_)
{
    proto_tree *subtree;
    uint16_t i, num;

    /* Number of PDUs */
    proto_tree_add_item_ret_uint16(log_tree, hf_qcdiag_wcdma_rlc_num_pdu, tvb, offset, 2, ENC_LITTLE_ENDIAN, &num);
    offset += 2;

    for (i = 0; i < num; i++) {
        /* PDU # */
        subtree = proto_tree_add_subtree_format(log_tree, tvb, offset, 10,
                   ett_qcdiag_log_wcdma_rlc_ul_am_ciph, NULL, "PDU %d", i);

        /* Logical Channel Id */
        proto_tree_add_item(subtree, hf_qcdiag_wcdma_rlc_lcid, tvb, offset, 1, ENC_NA);
        offset += 1;

        /* Ciphering Key */
        proto_tree_add_item(subtree, hf_qcdiag_wcdma_rlc_ciph_key, tvb, offset, 4, ENC_LITTLE_ENDIAN);
        offset += 4;

        /* Ciphering Algorithm */
        proto_tree_add_item(subtree, hf_qcdiag_wcdma_rlc_ciph_alg, tvb, offset, 1, ENC_NA);
        offset += 1;

        /* Count C */
        proto_tree_add_item(subtree, hf_qcdiag_wcdma_rlc_ciph_countc, tvb, offset, 4, ENC_LITTLE_ENDIAN);
        offset += 4;
    }
}

/* Decoded Example
 *
 * [0x41B0] WCDMA Freq Scan
 * Version          = 1
 * Freq Scan Type   = List scan (3)
 * Freq Scan Thresh = -482
 * Number of ARFCN  = 1
 * -----------------------
 * |   |     |RSSI |RSSI |
 * |#  |ARFCN|(raw)|(dBm)|
 * -----------------------
 * |  0|10663|     |  -72|
 * -----------------------
 *
 * Source: https://bchobby.github.io/posts/e3323df4cade84fa0b850a2b85ef1d14/
 */

static void
dissect_qcdiag_log_wcdma_freq_scan(tvbuff_t *tvb, uint32_t offset, packet_info *pinfo _U_, proto_tree *log_tree, proto_tree *tree _U_)
{
    proto_tree *subtree;
    proto_item *generated_item;
    uint8_t i, num, type;
    int16_t val;

    /* Version */
    proto_tree_add_item(log_tree, hf_qcdiag_log_ver, tvb, offset, 1, ENC_NA);
    offset += 1;

    /* Frequency Scan Type */
    proto_tree_add_item_ret_uint8(log_tree, hf_qcdiag_wcdma_freq_scan_type, tvb, offset, 1, ENC_NA, &type);
    offset += 1;

    val = tvb_get_int16(tvb, offset, ENC_LITTLE_ENDIAN);

    /* Frequency Scan Threshold */
    proto_tree_add_int(log_tree, hf_qcdiag_wcdma_freq_scan_thres, tvb, offset, 2, val);
    offset += 2;

    /* Number of ARFCN */
    proto_tree_add_item_ret_uint8(log_tree, hf_qcdiag_wcdma_freq_scan_num, tvb, offset, 1, ENC_NA, &num);
    offset += 1;

    for (i = 0; i < num; i++) {
        /* Frequency # */
        subtree = proto_tree_add_subtree_format(log_tree, tvb, offset, 4,
                   ett_qcdiag_log_wcdma_freq_scan, NULL, "Frequency %d", i);

        /* ARFCN */
        proto_tree_add_item(subtree, hf_qcdiag_wcdma_freq_scan_arfcn, tvb, offset+2, 2, ENC_LITTLE_ENDIAN);

        val = tvb_get_int16(tvb, offset, ENC_LITTLE_ENDIAN);

        if (type == 2) {
            /* RSSI (raw) */
            proto_tree_add_int(subtree, hf_qcdiag_wcdma_freq_scan_rssi_raw, tvb, offset, 2, val);

            /* Convert raw to dBm
             *
             * RSSI (dBm) = (0.474 * raw) – 112
             * The 0.474 value is the RSSI step size, in dB/LSB.
             * -112 dBm will be the minimum read out value.
             */
            val = (int16_t)(0.474 * val) - 112;

            /* RSSI (dBm) */
            generated_item = proto_tree_add_int(subtree, hf_qcdiag_wcdma_freq_scan_rssi_dbm, tvb, offset, 0, val);
            proto_item_set_generated(generated_item);
        } else if (type == 3) {
            /* RSSI (dBm) */
            proto_tree_add_int(subtree, hf_qcdiag_wcdma_freq_scan_rssi_dbm, tvb, offset, 2, val);
        }

        offset += 4;
    }
}

static void
dissect_qcdiag_log_rr(tvbuff_t *tvb, uint32_t offset, packet_info *pinfo, proto_tree *log_tree, proto_tree *tree)
{
    tvbuff_t *payload_tvb, *gsmtap_hdr_tvb, *gsmtap_tvb, *lapdm_tvb;
    uint32_t channel_type_dir, channel_type, length;
    uint8_t *lapdm_bytes;
    bool direction;

    uint16_t arfcn[] = { 0, 0 };

    channel_type_dir = (uint32_t)tvb_get_uint8(tvb, offset);

    /* Channel Type */
    proto_tree_add_item(log_tree, hf_qcdiag_rr_chan_type, tvb, offset, 1, ENC_NA);

    /* Direction */
    proto_tree_add_item(log_tree, hf_qcdiag_rr_direction, tvb, offset, 1, ENC_NA);
    offset += 1;

    /* Message Type */
    proto_tree_add_item(log_tree, hf_qcdiag_rr_msg_type, tvb, offset, 1, ENC_NA);
    offset += 1;

    /* Message Length */
    proto_tree_add_item_ret_uint(log_tree, hf_qcdiag_msg_len_1, tvb, offset, 1, ENC_NA, &length);
    offset += 1;

    arfcn[0] = gsm_last_uarfcn[0];
    arfcn[1] = gsm_last_uarfcn[1];

    /* 0x00: uplink, 0x80: downlink */
    direction = ((channel_type_dir & 0x80) == 0x00);

    if (direction)
        arfcn[0] = arfcn[0] | GSMTAP_ARFCN_F_UPLINK;

    channel_type = try_val_to_int(channel_type_dir & 0x7f, gsm_rr_channel_type_map);

    lapdm_tvb = NULL;

    /* DCCH, SACCH requires pseudo length */
    if (channel_type == 0) {
        /* SDCCH/8 expects LAPDm header */
        lapdm_bytes = (uint8_t*)wmem_alloc0(pinfo->pool, 3);

        lapdm_bytes[0] = 0x01;           /* Address field */
        lapdm_bytes[1] = 0x03;           /* Control field */
        lapdm_bytes[2] = length | 0x01;  /* length field */

        lapdm_tvb = tvb_new_real_data(lapdm_bytes, 3, 3);
    } else if (channel_type == 4) {
        /* SACCH/8 expects SACCH L1/LAPDm header */
        lapdm_bytes = (uint8_t*)wmem_alloc0(pinfo->pool, 5);

        lapdm_bytes[0] = 0x00;           /* SACCH L1 header */
        lapdm_bytes[1] = 0x00;           /* SACCH L1 header */
        lapdm_bytes[2] = 0x01;           /* Address field */
        lapdm_bytes[3] = 0x03;           /* Control field */
        lapdm_bytes[4] = length | 0x01;  /* length field */

        lapdm_tvb = tvb_new_real_data(lapdm_bytes, 5, 5);
    }

    gsmtap_hdr_tvb = get_gsmtap_hdr_tvb(pinfo, GSMTAP_TYPE_UM, arfcn[0], 0, channel_type, 0);
    payload_tvb = tvb_new_subset_remaining(tvb, offset);

    gsmtap_tvb = tvb_new_composite();
    tvb_composite_append(gsmtap_tvb, gsmtap_hdr_tvb);
    tvb_composite_append(gsmtap_tvb, lapdm_tvb);
    tvb_composite_append(gsmtap_tvb, payload_tvb);
    tvb_composite_finalize(gsmtap_tvb);

    dissect_qcdiag_log_set_col(pinfo, GSMTAP_TYPE_UM);
    dissect_qcdiag_log_append_text(log_tree, tree, direction);

    add_new_data_source(pinfo, gsmtap_tvb, "GSM RR");
    try_call_dissector(gsmtap_handle, gsmtap_tvb, pinfo, proto_tree_get_parent_tree(tree));
}

static void
dissect_qcdiag_log_gprs_mac(tvbuff_t *tvb, uint32_t offset, packet_info *pinfo, proto_tree *log_tree, proto_tree *tree)
{
    tvbuff_t *payload_tvb, *gsmtap_hdr_tvb, *gsmtap_tvb, *mac_hdr_tvb;
    uint32_t channel_type_dir, channel_type, length;
    uint8_t *mac_hdr_bytes;
    uint8_t mac_hdr_dl_payload_type, mac_hdr_dl_rrbp, mac_hdr_dl_sp, mac_hdr_dl_usf;
    uint8_t mac_hdr_ul_payload_type, mac_hdr_ul_retry;
    bool direction;

    uint32_t arfcn[] = { 0, 0 };

    channel_type_dir = (uint32_t)tvb_get_uint8(tvb, offset);

    /* Channel Type */
    proto_tree_add_item(log_tree, hf_qcdiag_mac_chan_type, tvb, offset, 1, ENC_NA);

    /* Direction */
    proto_tree_add_item(log_tree, hf_qcdiag_mac_direction, tvb, offset, 1, ENC_NA);
    offset += 1;

    /* Message Type */
    proto_tree_add_item(log_tree, hf_qcdiag_mac_msg_type, tvb, offset, 1, ENC_NA);
    offset += 1;

    /* Message Length */
    proto_tree_add_item_ret_uint(log_tree, hf_qcdiag_msg_len_1, tvb, offset, 1, ENC_NA, &length);
    offset += 1;

    arfcn[0] = gsm_last_uarfcn[0];
    arfcn[1] = gsm_last_uarfcn[1];

    /* 0x00: uplink, 0x80: downlink */
    direction = ((channel_type_dir & 0x80) == 0x00);

    if (direction)
        arfcn[0] = arfcn[0] | GSMTAP_ARFCN_F_UPLINK;

    channel_type = try_val_to_int(channel_type_dir, gsm_gmac_channel_type_map);

    /* 'GPRS MAC Signaling Message' does not have the 'GSM RLC/MAC' header byte

       [0x5226] GPRS MAC Signaling Message  (Downlink)
       Channel Type (1 byte)
       Message Type (1 byte)
       Length       (1 byte)

       MESSAGE_TYPE_xxxxxx (6 bits)
       Packet Downlink <message type name> content
         PAGE_MODE (2 bits)


       [0x5226] GPRS MAC Signaling Message  (Uplink)
       Channel Type (1 byte)
       Message Type (1 byte)
       Length       (1 byte)

       MESSAGE_TYPE_xxxxxx (6 bits)
       Packet Uplink <message type name> content
         TLLI/G-RNTI (32 bits)
         CTRL_ACK    (2 bits)


       GSM RLC/MAC: <message type name> (Downlink)
         xx.. .... = Payload Type
         ..xx .... = RRBP
         .... x... = S/P
         .... .xxx = USF
         MESSAGE_TYPE (DL): <message type name>
           xxxx xx.. = MESSAGE_TYPE (DL)
           .... ..xx = PAGE_MODE


       GSM RLC/MAC: <message type name> (Uplink)
         xx.. .... = Payload Type (UL)
         ..00 000. = spare: 0
         .... ...x = R
         xxxx xx.. = MESSAGE_TYPE (UL)
         .... ..xx  xxxx xxxx  xxxx xxxx  xxxx xxxx  xxxx xx.. = TLLI
         .... ..xx = CTRL_ACK
    */

    mac_hdr_bytes = (uint8_t*)wmem_alloc0(pinfo->pool, 1);

    if (direction) {
        mac_hdr_ul_payload_type = 0x01;  /* packet-gsm_rlcmac.c, dl_payload_type_vals */
        mac_hdr_ul_retry = 0x00;         /* packet-gsm_rlcmac.c, retry_vals */

        mac_hdr_bytes[0]  = mac_hdr_ul_payload_type << 6;
        mac_hdr_bytes[0] += mac_hdr_ul_retry;
    } else {
        mac_hdr_dl_payload_type = 0x01;  /* packet-gsm_rlcmac.c, dl_payload_type_vals */
        mac_hdr_dl_rrbp = 0x00;          /* packet-gsm_rlcmac.c, rrbp_vals */
        mac_hdr_dl_sp = 0x00;            /* packet-gsm_rlcmac.c, s_p_vals */
        mac_hdr_dl_usf = 0x00;

        mac_hdr_bytes[0]  = mac_hdr_dl_payload_type << 6;
        mac_hdr_bytes[0] += mac_hdr_dl_rrbp << 4;
        mac_hdr_bytes[0] += mac_hdr_dl_sp << 3;
        mac_hdr_bytes[0] += mac_hdr_dl_usf;
    }

    gsmtap_hdr_tvb = get_gsmtap_hdr_tvb(pinfo, GSMTAP_TYPE_UM, arfcn[0], 0, channel_type, 0);
    mac_hdr_tvb = tvb_new_real_data(mac_hdr_bytes, 1, 1);
    payload_tvb = tvb_new_subset_remaining(tvb, offset);

    gsmtap_tvb = tvb_new_composite();
    tvb_composite_append(gsmtap_tvb, gsmtap_hdr_tvb);
    tvb_composite_append(gsmtap_tvb, mac_hdr_tvb);
    tvb_composite_append(gsmtap_tvb, payload_tvb);
    tvb_composite_finalize(gsmtap_tvb);

    dissect_qcdiag_log_set_col(pinfo, GSMTAP_TYPE_UM);
    dissect_qcdiag_log_append_text(log_tree, tree, direction);

    add_new_data_source(pinfo, gsmtap_tvb, "GPRS MAC");
    try_call_dissector(gsmtap_handle, gsmtap_tvb, pinfo, proto_tree_get_parent_tree(tree));
}

static void
dissect_qcdiag_log_umts_nas(tvbuff_t *tvb, uint32_t offset, packet_info *pinfo, proto_tree *log_tree, proto_tree *tree)
{
    tvbuff_t *payload_tvb, *gsmtap_hdr_tvb, *gsmtap_tvb;
    uint16_t arfcn;
    bool direction;

    /* Direction */
    proto_tree_add_item_ret_boolean(log_tree, hf_qcdiag_nas_direction, tvb, offset, 1, ENC_NA, &direction);
    offset += 1;

    /* Length */
    proto_tree_add_item(log_tree, hf_qcdiag_nas_msg_length, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;

    arfcn = (uint16_t)(direction) << 14;

    gsmtap_hdr_tvb = get_gsmtap_hdr_tvb(pinfo, GSMTAP_TYPE_ABIS, arfcn, 0, 0, 0);
    payload_tvb = tvb_new_subset_remaining(tvb, offset);

    gsmtap_tvb = tvb_new_composite();
    tvb_composite_append(gsmtap_tvb, gsmtap_hdr_tvb);
    tvb_composite_append(gsmtap_tvb, payload_tvb);
    tvb_composite_finalize(gsmtap_tvb);

    dissect_qcdiag_log_set_col(pinfo, GSMTAP_TYPE_ABIS);
    dissect_qcdiag_log_append_text(log_tree, tree, direction);

    add_new_data_source(pinfo, gsmtap_tvb, "UMTS NAS");
    try_call_dissector(gsmtap_handle, gsmtap_tvb, pinfo, proto_tree_get_parent_tree(tree));
}

static void
dissect_qcdiag_log_lte_rrc(tvbuff_t *tvb, uint32_t offset, packet_info *pinfo, proto_tree *log_tree, proto_tree *tree)
{
    tvbuff_t *payload_tvb, *gsmtap_hdr_tvb, *gsmtap_tvb;
    uint32_t version, sfn, pdu, subtype, subslot, arfcn, earfcn, frame_nr;
    uint8_t lte_rnum, lte_rmajmin, nr_rnum, nr_rmajmin;
    wmem_strbuf_t *buf;
    const char *lte_buf, *nr_buf;
    bool direction;

    /* Packet Version */
    proto_tree_add_item_ret_uint(log_tree, hf_qcdiag_packet_ver, tvb, offset, 1, ENC_NA, &version);
    offset += 1;

    lte_rnum    = tvb_get_uint8(tvb, offset);
    lte_rmajmin = tvb_get_uint8(tvb, offset+1);

    buf = wmem_strbuf_new(pinfo->pool, "");
    wmem_strbuf_append_printf(buf, "%u.%u.%u", lte_rnum, lte_rmajmin / 16, lte_rmajmin % 16);
    lte_buf = wmem_strbuf_finalize(buf);

    /* LTE Release Number */
    proto_tree_add_string(log_tree, hf_qcdiag_lte_rrc_rel, tvb, offset, 2, lte_buf);
    offset += 2;

    if (version > 24) {
        nr_rnum    = tvb_get_uint8(tvb, offset);
        nr_rmajmin = tvb_get_uint8(tvb, offset+1);

        buf = wmem_strbuf_new(pinfo->pool, "");
        wmem_strbuf_append_printf(buf, "%u.%u.%u", nr_rnum, nr_rmajmin / 16, nr_rmajmin % 16);
        nr_buf = wmem_strbuf_finalize(buf);

        /* NR Release Number */
        proto_tree_add_string(log_tree, hf_qcdiag_nr_rrc_rel, tvb, offset, 2, nr_buf);
        offset += 2;
    }

    /* Radio Bearer Id */
    proto_tree_add_item(log_tree, hf_qcdiag_lte_rrc_rb_id, tvb, offset, 1, ENC_NA);
    offset += 1;

    /* Physical Cell Id */
    proto_tree_add_item(log_tree, hf_qcdiag_lte_rrc_pci, tvb, offset, 2, ENC_LITTLE_ENDIAN);
    offset += 2;

    /* Frequency */
    if (version < 8) {
        proto_tree_add_item_ret_uint(log_tree, hf_qcdiag_lte_rrc_earfcn_v2, tvb, offset, 2, ENC_LITTLE_ENDIAN, &earfcn);
        offset += 2;
    } else {
       proto_tree_add_item_ret_uint(log_tree, hf_qcdiag_lte_rrc_earfcn_v8, tvb, offset, 4, ENC_LITTLE_ENDIAN, &earfcn);
        offset += 4;
    }

    /* System Frame Number */
    proto_tree_add_item_ret_uint(log_tree, hf_qcdiag_lte_rrc_sfn, tvb, offset, 2, ENC_LITTLE_ENDIAN, &sfn);
    offset += 2;

    /* PDU */
    proto_tree_add_item_ret_uint(log_tree, hf_qcdiag_lte_rrc_pdu, tvb, offset, 1, ENC_NA, &pdu);
    offset += 1;

    /* SIB */
    if (version > 4) {
       proto_tree_add_item(log_tree, hf_qcdiag_lte_rrc_sib, tvb, offset, 4, ENC_LITTLE_ENDIAN);
        offset += 4;
    }

    /* Message Length */
    proto_tree_add_item(log_tree, hf_qcdiag_msg_len_2, tvb, offset, 2, ENC_LITTLE_ENDIAN);
    offset += 2;

    /* From Version 30 there are 3 more bytes (so far unknown) */
    if (version > 29)
        offset += 3;

    subtype = get_lte_rrc_subtype(version, pdu);

    /* Uplink */
    direction = (subtype == UL_CCCH ||
                 subtype == UL_DCCH ||
                 subtype == UL_CCCH_NB ||
                 subtype == UL_DCCH_NB);

    arfcn = (earfcn >= GSMTAP_ARFCN_F_UPLINK) ? 0 : earfcn;

    if (direction)
        arfcn = arfcn | GSMTAP_ARFCN_F_UPLINK;

    frame_nr = (sfn & 0xfff0) >> 4;
    subslot = sfn & 0x000f;

    gsmtap_hdr_tvb = get_gsmtap_hdr_tvb(pinfo, GSMTAP_TYPE_LTE_RRC, arfcn, frame_nr, subtype, subslot);
    payload_tvb = tvb_new_subset_remaining(tvb, offset);

    gsmtap_tvb = tvb_new_composite();
    tvb_composite_append(gsmtap_tvb, gsmtap_hdr_tvb);
    tvb_composite_append(gsmtap_tvb, payload_tvb);
    tvb_composite_finalize(gsmtap_tvb);

    dissect_qcdiag_log_set_col(pinfo, GSMTAP_TYPE_LTE_RRC);
    dissect_qcdiag_log_append_text(log_tree, tree, direction);

    add_new_data_source(pinfo, gsmtap_tvb, "LTE RRC");
    try_call_dissector(gsmtap_handle, gsmtap_tvb, pinfo, proto_tree_get_parent_tree(tree));
}

static void
dissect_qcdiag_log_lte_nas(tvbuff_t *tvb, uint32_t offset, packet_info *pinfo, proto_tree *log_tree, proto_tree *tree, bool plain)
{
    tvbuff_t *payload_tvb, *gsmtap_hdr_tvb, *gsmtap_tvb;
    uint16_t arfcn;
    uint8_t msgtype, lte_maj, lte_min, lte_patch;
    wmem_strbuf_t *buf;
    const char *str_buf;
    bool direction;

    /* Version */
    proto_tree_add_item(log_tree, hf_qcdiag_log_ver, tvb, offset, 1, ENC_NA);
    offset += 1;

    lte_maj   = tvb_get_uint8(tvb, offset);
    lte_min   = tvb_get_uint8(tvb, offset+1);
    lte_patch = tvb_get_uint8(tvb, offset+2);

    buf = wmem_strbuf_new(pinfo->pool, "");
    wmem_strbuf_append_printf(buf, "%u.%u.%u", lte_maj, lte_min, lte_patch);
    str_buf = wmem_strbuf_finalize(buf);

    /* Release Version */
    proto_tree_add_string(log_tree, hf_qcdiag_lte_nas_rel, tvb, offset, 3, str_buf);
    offset += 3;

    /* Message Type */
    msgtype = tvb_get_uint8(tvb, offset+1);

    /* Uplink */
    direction = (msgtype == 0x41 ||  /* Attach request */
                 msgtype == 0x45 ||  /* Detach request */
                 msgtype == 0x48 ||  /* Tracking area update request */
                 msgtype == 0x4c ||  /* Extended service request */
                 msgtype == 0x4d ||  /* Control plane service request */
                 msgtype == 0x52 ||  /* Authentication request */
                 msgtype == 0x55 ||  /* Identity request */
                 msgtype == 0x63 ||  /* Uplink NAS transport */
                 msgtype == 0x69);   /* Uplink generic NAS transport */

    arfcn = (direction) ? GSMTAP_ARFCN_F_UPLINK : 0;

    gsmtap_hdr_tvb = get_gsmtap_hdr_tvb(pinfo, GSMTAP_TYPE_LTE_NAS, arfcn, 0, !plain, 0);
    payload_tvb = tvb_new_subset_remaining(tvb, offset);

    gsmtap_tvb = tvb_new_composite();
    tvb_composite_append(gsmtap_tvb, gsmtap_hdr_tvb);
    tvb_composite_append(gsmtap_tvb, payload_tvb);
    tvb_composite_finalize(gsmtap_tvb);

    dissect_qcdiag_log_set_col(pinfo, GSMTAP_TYPE_LTE_NAS);
    dissect_qcdiag_log_append_text(log_tree, tree, direction);

    add_new_data_source(pinfo, gsmtap_tvb, "LTE NAS");
    try_call_dissector(gsmtap_handle, gsmtap_tvb, pinfo, proto_tree_get_parent_tree(tree));
}


/* Get Log Request
 * +-----------------------+----------------+-----------------------------------------+
 * | Field                 | Length (bytes) | Description                             |
 * +=======================+================+=========================================+
 * | CMD_CODE ( 16 / 0x10) |       1        | Message ID: The CMD_CODE is set to 16   |
 * |                       |                | for this message                        |
 * +-----------------------+----------------+-----------------------------------------+
 *
 * Get Log Response
 * +-----------------------+----------------+-----------------------------------------+
 * | Field                 | Length (bytes) | Description                             |
 * +=======================+================+=========================================+
 * | CMD_CODE ( 16 / 0x10) |       1        | Message ID: The CMD_CODE is set to 16   |
 * |                       |                | for this message                        |
 * +-----------------------+----------------+-----------------------------------------+
 * | MORE                  |       1        | More log data available indicator;      |
 * |                       |                | indicates how many log entries (not     |
 * |                       |                | including the one returned with this    |
 * |                       |                | message) are queued                     |
 * +-----------------------+----------------+-----------------------------------------+
 * | LENGTH                |       2        | Length of the included LOG_ITEM,        |
 * |                       |                | in bytes                                |
 * +-----------------------+----------------+-----------------------------------------+
 * | LOG_ITEM              |     LENGTH     | Log data;                               |
 * |                       |                | Log Record Structure                    |
 * +-----------------------+----------------+-----------------------------------------+
 *
 * Log Record Structure
 * +-----------------------+----------------+-----------------------------------------+
 * | Field                 | Length (bytes) | Description                             |
 * +=======================+================+=========================================+
 * | LENGTH                |       2        | Length of the log record; this is the   |
 * |                       |                | record including LENGTH, LOG_CODE, and  |
 * |                       |                | TIMESTAMP                               |
 * +-----------------------+----------------+-----------------------------------------+
 * | LOG_CODE              |       2        | Specifies the log item.                 |
 * |                       |                | LOG_CODE is the 16-bit logging code and |
 * |                       |                | consists of the following fields:       |
 * |                       |                | - Equipment identifier: Most significant|
 * |                       |                |   4 bits of the log code specify the    |
 * |                       |                |   equipment ID                          |
 * |                       |                | - Item identifier: Least significant    |
 * |                       |                |   12 bits of the log code specify the   |
 * |                       |                |   log item ID within the equipment ID   |
 * +-----------------------+----------------+-----------------------------------------+
 * | TIMESTAMP             |       8        | QC timestamp; this the same format as   |
 * |                       |                | in the Time Stamp (29 / 0x1D)           |
 * +-----------------------+----------------+-----------------------------------------+
 * | DATA                  |   LENGTH+12    | Data specific to that log type          |
 * +-----------------------+----------------+-----------------------------------------+
 */

static int
dissect_qcdiag_log(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data)
{
    proto_item *ti;
    proto_tree *diag_log_tree;
    tvbuff_t *payload_tvb;
    qcdiag_data_t *qcdata;
    uint32_t offset = 0;
    uint32_t length, code;
    nstime_t abs_time;
    const char *timestamp;
    const char *str;

    qcdata = (qcdiag_data_t*)data;

    length = tvb_reported_length(tvb);

    if (qcdata && qcdata->custom) {
        /* DIAG_MAX_F */
        offset++;
        length--;
    }

    /* Request */
    if (length == 2) {
        return tvb_captured_length(tvb);
    }

    /* Log Code */
    code = tvb_get_uint16(tvb, offset+6, ENC_LITTLE_ENDIAN);

    /* More */
    proto_tree_add_item(tree, hf_qcdiag_log_more, tvb, offset+1, 1, ENC_NA);

    /* Length of the log record */
    proto_tree_add_item(tree, hf_qcdiag_log_len, tvb, offset+4, 2, ENC_LITTLE_ENDIAN);

    offset += 8;

    abs_time = qcdiag_parse_timestamp(tvb, offset);
    pinfo->abs_ts = abs_time;
    pinfo->fd->abs_ts = abs_time;

    /* local time in our time zone, with month and day */
    timestamp = abs_time_to_str(pinfo->pool, &abs_time, ABSOLUTE_TIME_LOCAL, true);

    /* Timestamp */
    proto_tree_add_string(tree, hf_qcdiag_log_timestamp, tvb, offset, 8, timestamp);
    offset += 8;

    str = val_to_str_ext(pinfo->pool, code, qcdiag_logcodes_ext, "Unknown Log Code (0x%04x)");

    ti = proto_tree_get_parent(tree);
    col_set_str(pinfo->cinfo, COL_INFO, str);
    proto_item_append_text(ti, ", %s", str);

    ti = proto_tree_add_item(tree, proto_qcdiag_log, tvb, offset, -1, ENC_NA);
    proto_item_set_text(ti, "%s", str);

    diag_log_tree = proto_item_add_subtree(ti, ett_qcdiag_log);

    if (qcdata && qcdata->custom) {
        payload_tvb = tvb_new_subset_remaining(tvb, offset);
        call_dissector(text_lines_handle, payload_tvb, pinfo, diag_log_tree);

        return tvb_captured_length(tvb);
    }

    switch (code) {
    /* 1X - 0x1000 log code base */

    /* WCDMA - 0x4000 log code base */
    case 0x4005:
        dissect_qcdiag_log_wcdma_search_cell_resel_rank(tvb, offset, pinfo, diag_log_tree, tree);
        break;
    case 0x412f:
        dissect_qcdiag_log_wcdma_rrc(tvb, offset, pinfo, diag_log_tree, tree);
        break;
    case 0x4125:
        dissect_qcdiag_log_wcdma_rrc_states(tvb, offset, pinfo, diag_log_tree, tree);
        break;
    case 0x4126:
        dissect_qcdiag_log_wcdma_rrc_prot_errors(tvb, offset, pinfo, diag_log_tree, tree);
        break;
    case 0x4127:
        dissect_qcdiag_log_wcdma_cell_id(tvb, offset, pinfo, diag_log_tree, tree);
        break;
    case 0x4135:
        dissect_qcdiag_log_wcdma_rlc_dl_am_signaling_pdu(tvb, offset, pinfo, diag_log_tree, tree);
        break;
    case 0x413c:
        dissect_qcdiag_log_wcdma_rlc_ul_am_signaling_pdu(tvb, offset, pinfo, diag_log_tree, tree);
        break;
    case 0x4145:
        dissect_qcdiag_log_wcdma_rlc_ul_am_control_pdu(tvb, offset, pinfo, diag_log_tree, tree);
        break;
    case 0x4146:
        dissect_qcdiag_log_wcdma_rlc_dl_am_control_pdu(tvb, offset, pinfo, diag_log_tree, tree);
        break;
    case 0x4168:
        dissect_qcdiag_log_wcdma_rlc_dl_am_cipher_pdu(tvb, offset, pinfo, diag_log_tree, tree);
        break;
    case 0x4169:
        dissect_qcdiag_log_wcdma_rlc_ul_am_cipher_pdu(tvb, offset, pinfo, diag_log_tree, tree);
        break;
    case 0x41b0:
        dissect_qcdiag_log_wcdma_freq_scan(tvb, offset, pinfo, diag_log_tree, tree);
        break;

    /* GSM - 0x5000 log code base */
    case 0x512f:
        dissect_qcdiag_log_rr(tvb, offset, pinfo, diag_log_tree, tree);
        break;
    case 0x5226:
        dissect_qcdiag_log_gprs_mac(tvb, offset, pinfo, diag_log_tree, tree);
        break;

    /* UMTS - 0x7000 log code base */
    case 0x713a:
        dissect_qcdiag_log_umts_nas(tvb, offset, pinfo, diag_log_tree, tree);
        break;

    /* LTE - 0xB000 log code base (0xB010 - 0xB1FF ) */
    case 0xb0c0:
        dissect_qcdiag_log_lte_rrc(tvb, offset, pinfo, diag_log_tree, tree);
        break;
    case 0xb0e0:
    case 0xb0e1:
        dissect_qcdiag_log_lte_nas(tvb, offset, pinfo, diag_log_tree, tree, false);
        break;
    case 0xb0e2:
    case 0xb0e3:
        dissect_qcdiag_log_lte_nas(tvb, offset, pinfo, diag_log_tree, tree, true);
        break;
    case 0xb0ea:
    case 0xb0eb:
        dissect_qcdiag_log_lte_nas(tvb, offset, pinfo, diag_log_tree, tree, false);
        break;
    case 0xb0ec:
    case 0xb0ed:
        dissect_qcdiag_log_lte_nas(tvb, offset, pinfo, diag_log_tree, tree, true);
        break;

    /* NR - 0xB800 log code base (0xB800 - 0xB9FF ) */

    default:
        payload_tvb = tvb_new_subset_remaining(tvb, offset);
        dissector_try_uint(qcdiag_log_code_dissector_table, code, payload_tvb, pinfo, diag_log_tree);
        break;
    }

    return tvb_captured_length(tvb);
}

void
proto_register_qcdiag_log(void)
{
    static hf_register_info hf[] = {
        { &hf_qcdiag_log_ver,
          { "Version", "qcdiag_log.ver",
            FT_UINT8, BASE_CUSTOM, CF_FUNC(qcdiag_format_ver), 0, "Log Code Version", HFILL }},
        { &hf_qcdiag_log_ver_4,
          { "Version", "qcdiag_log.ver",
            FT_UINT32, BASE_CUSTOM, CF_FUNC(qcdiag_format_ver), 0, "Log Code Version", HFILL }},
        { &hf_qcdiag_log_len,
          { "Log Message Length", "qcdiag_log.length",
            FT_UINT16, BASE_DEC|BASE_UNIT_STRING, UNS(&units_byte_bytes), 0, NULL, HFILL } },
        { &hf_qcdiag_log_more,
          { "More log data available indicator", "qcdiag_log.more",
            FT_UINT8, BASE_DEC, NULL, 0, "Indicates how many log entries (not including the one returned with this message) are queued", HFILL } },
        { &hf_qcdiag_log_timestamp,
          { "Timestamp", "qcdiag_log.ts",
            FT_STRING, BASE_NONE, NULL, 0, "System Time Clock", HFILL }},
        { &hf_qcdiag_arfcn,
          { "ARFCN", "qcdiag_log.arfcn",
            FT_UINT16, BASE_DEC, NULL, GSMTAP_ARFCN_MASK, NULL, HFILL } },
        { &hf_qcdiag_uplink,
          { "Uplink", "qcdiag_log.uplink",
            FT_UINT16, BASE_DEC, NULL, GSMTAP_ARFCN_F_UPLINK, NULL, HFILL } },
        { &hf_qcdiag_pcs,
          { "PCS band indicator", "qcdiag_log.pcs_band",
            FT_UINT16, BASE_DEC, NULL, GSMTAP_ARFCN_F_PCS, NULL, HFILL } },
        { &hf_qcdiag_psc,
          { "Primary Scrambling Code (PSC)", "qcdiag_log.psc",
            FT_UINT16, BASE_DEC, NULL, 0, NULL, HFILL } },
        { &hf_qcdiag_subtype_v1,
          { "Subtype", "qcdiag_log.subtype",
            FT_UINT16, BASE_DEC, VALS(umts_sib_types_v1), 0, NULL, HFILL } },
        { &hf_qcdiag_subtype_v2,
          { "Subtype", "qcdiag_log.subtype",
            FT_UINT16, BASE_DEC, VALS(umts_sib_types_v2), 0, NULL, HFILL } },
        { &hf_qcdiag_packet_ver,
          { "Packet Version", "qcdiag_log.pkt_ver",
            FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL } },
        { &hf_qcdiag_msg_len_1,
          { "Message Length", "qcdiag_log.msg_len",
            FT_UINT8, BASE_DEC|BASE_UNIT_STRING, UNS(&units_byte_bytes), 0, NULL, HFILL } },
        { &hf_qcdiag_msg_len_2,
          {"Message Length", "qcdiag_log.msg_len",
            FT_UINT16, BASE_DEC|BASE_UNIT_STRING, UNS(&units_byte_bytes), 0, NULL, HFILL } },

        /* GSM RR */
        { &hf_qcdiag_rr_chan_type,
          { "Channel Type", "qcdiag_log.rr.chan_type",
            FT_UINT8, BASE_HEX, VALS(rr_chan_types), 0x7f, NULL, HFILL } },
        { &hf_qcdiag_rr_direction,
          { "Direction", "qcdiag_log.rr.direction",
            FT_BOOLEAN, 8, TFS(&tfs_downlink_uplink), 0x80, NULL, HFILL } },
        { &hf_qcdiag_rr_msg_type,
          { "Message Type", "qcdiag_log.rr.msg_type",
            FT_UINT8, BASE_HEX, VALS(gsm_a_dtap_msg_rr_strings), 0, NULL, HFILL } },

        /* GPRS MAC */
        { &hf_qcdiag_mac_chan_type,
          { "Channel Type", "qcdiag_log.gmac.chan_type",
            FT_UINT8, BASE_HEX, VALS(mac_chan_types), 0, NULL, HFILL } },
        { &hf_qcdiag_mac_direction,
          { "Direction", "qcdiag_log.gmac.direction",
            FT_BOOLEAN, 8, TFS(&tfs_downlink_uplink), 0x80, NULL, HFILL } },
        { &hf_qcdiag_mac_msg_type,
          { "Message Type", "qcdiag_log.gmac.msg_type",
            FT_UINT8, BASE_HEX, NULL, 0, NULL, HFILL } },

        /* NAS (3G) */
        { &hf_qcdiag_nas_direction,
          { "Direction", "qcdiag_log.nas.direction",
            FT_BOOLEAN, 8, TFS(&tfs_uplink_downlink), 0x01, NULL, HFILL } },
        { &hf_qcdiag_nas_msg_length,
          { "NAS Message Length", "qcdiag_log.nas.msg_len",
            FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL } },

        /* RRC (3G) */
        { &hf_qcdiag_rrc_chan_type,
          { "Channel Type", "qcdiag_log.rrc.chan_type",
            FT_UINT8, BASE_DEC, VALS(rrc_sub_types), 0, NULL, HFILL } },
        { &hf_qcdiag_rrc_chan_type_umts_v1,
          { "Channel Type", "qcdiag_log.rrc.chan_type",
            FT_UINT8, BASE_DEC, VALS(umts_v1_sub_types), 0, NULL, HFILL } },
        { &hf_qcdiag_rrc_chan_type_umts_v2,
          { "Channel Type", "qcdiag_log.rrc.chan_type",
            FT_UINT8, BASE_DEC, VALS(umts_v2_sub_types), 0, NULL, HFILL } },
        { &hf_qcdiag_rrc_rb_id,
          {"Radio Bearer Id", "qcdiag_log.rrc.rb_id",
            FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL } },

        /* WCDMA */
        { &hf_qcdiag_wcdma_cid_ul_uarfcn,
          { "UL UTRA ARFCN", "qcdiag_log.wcdma_cid.ul_uarfcn",
            FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL } },
        { &hf_qcdiag_wcdma_cid_dl_uarfcn,
          { "DL UTRA ARFCN", "qcdiag_log.wcdma_cid.dl_uarfcn",
            FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL } },
        { &hf_qcdiag_wcdma_cid_cell_id,
          { "Cell Id", "qcdiag_log.wcdma_cid.cell_id",
            FT_UINT32, BASE_DEC, NULL, QCDIAG_WCDMA_CID_MASK, NULL, HFILL } },
        { &hf_qcdiag_wcdma_cid_ura_id,
          { "UTRAN Registration Area (URA) Id", "qcdiag_log.wcdma_cid.ura_id",
            FT_UINT16, BASE_DEC, NULL, 0, "URA to use in case of overlapping URAs", HFILL } },
        { &hf_qcdiag_wcdma_cid_cell_barred,
          { "Cell Barred", "qcdiag_log.wcdma_cid.cell_barred",
            FT_BOOLEAN, 8, TFS(&tfs_not_barred_barred), 0x01, NULL, HFILL } },
        { &hf_qcdiag_wcdma_cid_cell_reserved,
          { "Cell Reserved", "qcdiag_log.wcdma_cid.cell_reserved",
            FT_BOOLEAN, 8, TFS(&tfs_not_reserved_reserved), 0x02, NULL, HFILL } },
        { &hf_qcdiag_wcdma_cid_cell_solsa,
          { "Cell Reserved for SoLSA", "qcdiag_log.wcdma_cid.cell_solsa",
            FT_BOOLEAN, 8, TFS(&tfs_not_reserved_reserved_solsa), 0x04, "Cell Reserved for Support of Localised Service Area (SoLSA)", HFILL } },
        { &hf_qcdiag_wcdma_cid_ue_camped,
          { "UE Camped on Cell", "qcdiag_log.wcdma_cid.ue_camped",
            FT_BOOLEAN, 8, TFS(&tfs_not_camped_camped), 0x08, NULL, HFILL } },
        { &hf_qcdiag_wcdma_cid_reserved,
          { "Reserved", "qcdiag_log.wcdma_cid.res",
            FT_UINT8, BASE_DEC, NULL, 0xf0, NULL, HFILL }},
        { &hf_qcdiag_wcdma_cid_allowed_call_access,
          { "Allowed Call Access", "qcdiag_log.wcdma_cid.allowed_call_access",
            FT_UINT8, BASE_DEC, VALS(wcdma_cid_allowed_call_access_vals), 0, NULL, HFILL } },
        { &hf_qcdiag_wcdma_cid_psc,
          { "Primary Scrambling Code (PSC)", "qcdiag_log.wcdma_cid.psc",
            FT_UINT16, BASE_DEC, NULL, 0, NULL, HFILL } },
        { &hf_qcdiag_wcdma_cid_mcc,
          { "Mobile Country Code (MCC)", "qcdiag_log.wcdma_cid.mcc",
            FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL } },
        { &hf_qcdiag_wcdma_cid_mnc,
          { "Mobile Network Code (MNC)", "qcdiag_log.wcdma_cid.mnc",
            FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL } },
        { &hf_qcdiag_wcdma_cid_lac,
          { "Location Area Code (LAC) Id", "qcdiag_log.wcdma_cid.lac",
            FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL } },
        { &hf_qcdiag_wcdma_cid_rac,
          { "Routing Area Code (RAC) Id", "qcdiag_log.wcdma_cid.rac",
            FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL } },
        { &hf_qcdiag_wcdma_freq_scan_type,
          { "Frequency Scan Type", "qcdiag_log.wcdma_freq_scan.type",
            FT_UINT8, BASE_DEC, VALS(wcdma_freq_scan_type_vals), 0, NULL, HFILL } },
        { &hf_qcdiag_wcdma_freq_scan_thres,
          { "Frequency Scan Threshold", "qcdiag_log.wcdma_freq_scan.thres",
            FT_INT16, BASE_DEC, NULL, 0, NULL, HFILL } },
        { &hf_qcdiag_wcdma_freq_scan_num,
          { "Number of ARFCN", "qcdiag_log.wcdma_freq_scan.num_freq",
            FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL } },
        { &hf_qcdiag_wcdma_freq_scan_arfcn,
          { "ARFCN", "qcdiag_log.wcdma_freq_scan.arfcn",
            FT_UINT16, BASE_DEC, NULL, 0, NULL, HFILL } },
        { &hf_qcdiag_wcdma_freq_scan_rssi_raw,
          { "RSSI (raw)", "qcdiag_log.wcdma_freq_scan.rssi_raw",
            FT_INT16, BASE_DEC, NULL, 0, "Received Signal Strength Indicator (raw)", HFILL } },
        { &hf_qcdiag_wcdma_freq_scan_rssi_dbm,
          { "RSSI (dBm)", "qcdiag_log.wcdma_freq_scan.rssi_dbm",
            FT_INT16, BASE_DEC|BASE_UNIT_STRING, UNS(&units_dbm), 0, "Received Signal Strength Indicator (dBm)", HFILL } },
        { &hf_qcdiag_wcdma_crr_ver,
          { "Version", "qcdiag_log.ver",
            FT_UINT8, BASE_CUSTOM, CF_FUNC(qcdiag_format_ver), 0xc0, "Log Code Version", HFILL }},
        { &hf_qcdiag_wcdma_crr_num_3g,
          { "Number of WCDMA Cells Searched", "qcdiag_log.wcdma_crr.num_3g",
            FT_UINT8, BASE_DEC, NULL, 0x3f, NULL, HFILL }},
        { &hf_qcdiag_wcdma_crr_reserved,
          { "Reserved", "qcdiag_log.wcdma_crr.res",
            FT_UINT8, BASE_DEC, NULL, 0xc0, NULL, HFILL }},
        { &hf_qcdiag_wcdma_crr_num_2g,
          { "Number of GSM Cells Searched", "qcdiag_log.wcdma_crr.num_2g",
            FT_UINT8, BASE_DEC, NULL, 0x3f, NULL, HFILL }},
        { &hf_qcdiag_wcdma_crr_uarfcn_3g,
          { "RF Channel Frequency", "qcdiag_log.wcdma_crr.uarfcn_3g",
            FT_UINT16, BASE_DEC, NULL, 0, NULL, HFILL }},
        { &hf_qcdiag_wcdma_crr_psc_3g,
          { "Primary Scrambling Code (PSC)", "qcdiag_log.wcdma_crr.psc_3g",
            FT_UINT16, BASE_DEC, NULL, 0, NULL, HFILL } },
        { &hf_qcdiag_wcdma_crr_rscp_3g,
          { "Received Signal Code Power (RSCP)", "qcdiag_log.wcdma_crr.rscp_3g",
            FT_INT8, BASE_DEC, NULL, 0, NULL, HFILL } },
        { &hf_qcdiag_wcdma_crr_rscp_rank_3g,
          { "Cell Ranking RSCP", "qcdiag_log.wcdma_crr.rscp_rank_3g",
            FT_INT16, BASE_DEC, NULL, 0, NULL, HFILL } },
        { &hf_qcdiag_wcdma_crr_ecio_3g,
          { "Energy Per Chip Over Interference (Ec/Io)", "qcdiag_log.wcdma_crr.ecio_3g",
            FT_FLOAT, BASE_NONE, NULL, 0, NULL, HFILL } },
        { &hf_qcdiag_wcdma_crr_ecio_rank_3g,
          { "Cell Ranking Ec/Io", "qcdiag_log.wcdma_crr.ecio_rank_3g",
            FT_INT16, BASE_DEC, NULL, 0, NULL, HFILL } },
        { &hf_qcdiag_wcdma_crr_arfcn_2g,
          { "RF Channel Frequency", "qcdiag_log.wcdma_crr.arfcn_2g",
            FT_UINT16, BASE_DEC, NULL, 0, NULL, HFILL }},
        { &hf_qcdiag_wcdma_crr_rssi_2g,
          { "Received Signal Strength Indicator (RSSI)", "qcdiag_log.wcdma_crr.rssi_2g",
            FT_INT8, BASE_DEC, NULL, 0, NULL, HFILL } },
        { &hf_qcdiag_wcdma_crr_rssi_rank_2g,
          { "Cell Ranking RSSI", "qcdiag_log.wcdma_crr.rssi_rank_2g",
            FT_INT16, BASE_DEC, NULL, 0, NULL, HFILL } },
        { &hf_qcdiag_wcdma_crr_bsic_2g,
          { "Base Station Identity Code (BSIC)", "qcdiag_log.wcdma_crr.bsic_2g",
            FT_UINT16, BASE_DEC, NULL, 0, NULL, HFILL } },
        { &hf_qcdiag_wcdma_crr_bsic_bcc,
          { "Base Station Color Code (BCC)", "qcdiag_log.wcdma_crr.bsic_bcc",
            FT_UINT8, BASE_DEC, NULL, 0x07, NULL, HFILL } },
        { &hf_qcdiag_wcdma_crr_bsic_ncc,
          { "Network Color Code (NCC)", "qcdiag_log.wcdma_crr.bsic_ncc",
            FT_UINT8, BASE_DEC, NULL, 0x38, NULL, HFILL } },
        { &hf_qcdiag_wcdma_crr_resel_status,
          { "Reselection Status", "qcdiag_log.wcdma_crr.resel_status",
            FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL }},
        { &hf_qcdiag_wcdma_crr_hcs_priority,
          { "Hierarchical Cell Structure (HCS) Priority", "qcdiag_log.wcdma_crr.hcs_priority",
            FT_UINT16, BASE_DEC, NULL, 0, NULL, HFILL }},
        { &hf_qcdiag_wcdma_crr_h_value,
          { "H Value", "qcdiag_log.wcdma_crr.h_value",
            FT_INT16, BASE_DEC, NULL, 0, NULL, HFILL }},
        { &hf_qcdiag_wcdma_crr_hcs_cell_qualify,
          { "Hierarchical Cell Structure (HCS) Cell Qualify", "qcdiag_log.wcdma_crr.hcs_cell_qualify",
            FT_BOOLEAN, 8, TFS(&tfs_yes_no), 0x01, NULL, HFILL }},

        /* WCDMA RLC */
        { &hf_qcdiag_wcdma_rlc_num_ent,
          { "Number of Entities", "qcdiag_log.wcdma_rlc.num_ent",
            FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL }},
        { &hf_qcdiag_wcdma_rlc_num_pdu,
          { "Number of PDUs", "qcdiag_log.wcdma_rlc.num_pdu",
            FT_UINT16, BASE_DEC, NULL, 0, NULL, HFILL }},
        { &hf_qcdiag_wcdma_rlc_lcid,
          { "Logical Channel Id", "qcdiag_log.wcdma_rlc.lcid",
            FT_UINT8, BASE_DEC, NULL, 0, "RLC Logical channel Id (range 0 to 18)", HFILL }},
        { &hf_qcdiag_wcdma_rlc_pdu_size,
          { "PDU Size", "qcdiag_log.wcdma_rlc.pdu_size",
            FT_UINT16, BASE_DEC|BASE_UNIT_STRING, UNS(&units_byte_bytes), 0, NULL, HFILL }},
        { &hf_qcdiag_wcdma_rlc_pdu_size_bits,
          { "PDU Size", "qcdiag_log.wcdma_rlc.pdu_size",
            FT_UINT16, BASE_DEC|BASE_UNIT_STRING, UNS(&units_bit_bits), 0, "PDU Size in Bits", HFILL }},
        { &hf_qcdiag_wcdma_rlc_pdu_count,
          { "PDU Count", "qcdiag_log.wcdma_rlc.pdu_count",
            FT_UINT16, BASE_DEC, NULL, 0, NULL, HFILL }},
        { &hf_qcdiag_wcdma_rlc_ciph_key,
          { "Ciphering Key", "qcdiag_log.wcdma_rlc.ciph_key",
            FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
        { &hf_qcdiag_wcdma_rlc_ciph_alg,
          { "Ciphering Algorithm", "qcdiag_log.wcdma_rlc.ciph_alg",
            FT_UINT8, BASE_DEC, VALS(wcdma_rlc_ciph_level_vals), 0, "Ultra Encryption Algorithm (UEA)", HFILL }},
        { &hf_qcdiag_wcdma_rlc_ciph_msg,
          { "Ciphered Message", "qcdiag_log.wcdma_rlc.ciph_msg",
            FT_UINT32, BASE_HEX, NULL, 0, NULL, HFILL }},
        { &hf_qcdiag_wcdma_rlc_ciph_countc,
          { "Count C", "qcdiag_log.wcdma_rlc.ciph_countc",
            FT_UINT32, BASE_HEX, NULL, 0, NULL, HFILL }},

        /* WCDMA RRC */
        { &hf_qcdiag_wcdma_rrc_state,
          { "RRC State", "qcdiag_log.wcdma_rrc.state",
            FT_UINT8, BASE_DEC, VALS(wcdma_rrc_states_vals), 0, NULL, HFILL } },
        { &hf_qcdiag_wcdma_rrc_procedure,
          { "RRC Procedure", "qcdiag_log.wcdma_rrc.procedure",
            FT_UINT8, BASE_DEC, VALS(umts_rrc_procedure_vals), 0, NULL, HFILL } },
        { &hf_qcdiag_wcdma_rrc_failure_cause,
          { "RRC Failure Cause", "qcdiag_log.wcdma_rrc.failure_cause",
            FT_UINT8, BASE_DEC, VALS(umts_rrc_fail_cause_vals), 0, NULL, HFILL } },
        { &hf_qcdiag_wcdma_rrc_prot_err_cause,
          { "RRC Protocol Error Cause", "qcdiag_log.wcdma_rrc.prot_err_cause",
            FT_UINT8, BASE_DEC, VALS(umts_rrc_prot_err_vals), 0, NULL, HFILL } },

        /* LTE RRC */
        { &hf_qcdiag_lte_rrc_rel,
          { "LTE RRC Release", "qcdiag_log.lte_rrc_rel",
            FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL } },
        { &hf_qcdiag_nr_rrc_rel,
          { "NR RRC Release", "qcdiag_log.nr_rrc_rel",
            FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL } },
        { &hf_qcdiag_lte_rrc_rb_id,
          {"Radio Bearer Id", "qcdiag_log.lte_rrc.rb_id",
            FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL } },
        { &hf_qcdiag_lte_rrc_pci,
          {"Physical Cell Id", "qcdiag_log.lte_rrc.pci",
            FT_UINT16, BASE_DEC, NULL, 0, "PCI", HFILL } },
        { &hf_qcdiag_lte_rrc_earfcn_v2,
          { "Frequency", "qcdiag_log.lte_rrc.earfcn",
            FT_UINT16, BASE_DEC, NULL, 0, "EARFCN", HFILL } },
        { &hf_qcdiag_lte_rrc_earfcn_v8,
          { "Frequency", "qcdiag_log.lte_rrc.earfcn",
            FT_UINT32, BASE_DEC, NULL, 0, "EARFCN", HFILL } },
        { &hf_qcdiag_lte_rrc_sfn,
          { "System Frame Number", "qcdiag_log.lte_rrc.sfn",
            FT_UINT16, BASE_DEC, NULL, 0, "SFN", HFILL } },
        { &hf_qcdiag_lte_rrc_pdu,
          { "PDU Number", "qcdiag_log.lte_rrc.pdu",
            FT_UINT8, BASE_DEC, NULL, 0, "SFN", HFILL } },
        { &hf_qcdiag_lte_rrc_sib,
          { "SIB Mask in SI", "qcdiag_log.lte_rrc.sib",
            FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL } },

        /* LTE NAS */
        { &hf_qcdiag_lte_nas_rel,
          { "Release Version", "qcdiag_log.lte_nas_rel",
            FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL } },
    };

    int *ett[] = {
        &ett_qcdiag_log,
        &ett_qcdiag_log_wcdma_crr_wcmda,
        &ett_qcdiag_log_wcdma_crr_gsm,
        &ett_qcdiag_log_wcdma_cid_car,
        &ett_qcdiag_log_wcdma_rlc_dl_am_sig,
        &ett_qcdiag_log_wcdma_rlc_dl_am_ciph,
        &ett_qcdiag_log_wcdma_rlc_ul_am_ciph,
        &ett_qcdiag_log_wcdma_freq_scan
    };

    static ei_register_info ei[] = {
        { &ei_qcdiag_log_mcc_non_decimal, { "qcdiag_log.wcdma_cid.mcc.non_decimal", PI_MALFORMED, PI_WARN, "MCC contains non-decimal digits", EXPFILL }},
        { &ei_qcdiag_log_mnc_non_decimal, { "qcdiag_log.wcdma_cid.mnc.non_decimal", PI_MALFORMED, PI_WARN, "MNC contains non-decimal digits", EXPFILL }},
    };

    expert_module_t* expert_qcdiag_log;

    proto_qcdiag_log = proto_register_protocol("Qualcomm Diagnostic Log", "QCDIAG LOG", "qcdiag_log");
    proto_register_field_array(proto_qcdiag_log, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));
    expert_qcdiag_log = expert_register_protocol(proto_qcdiag_log);
    expert_register_field_array(expert_qcdiag_log, ei, array_length(ei));

    /* Register dissector table(s) to do sub dissection of Log Codes */
    qcdiag_log_code_dissector_table = register_dissector_table("qcdiag_log.code", "QCDIAG LOG code", proto_qcdiag_log, FT_UINT16, BASE_HEX);
}

void
proto_reg_handoff_qcdiag_log(void)
{
    dissector_handle_t qcdiag_log_handle;

    qcdiag_log_handle = create_dissector_handle(dissect_qcdiag_log, proto_qcdiag_log);
    dissector_add_uint("qcdiag.cmd", DIAG_LOG_F, qcdiag_log_handle);

    data_handle = find_dissector("data");
    text_lines_handle = find_dissector("data-text-lines");
    udp_handle = find_dissector("udp");
    gsmtap_handle = find_dissector("gsmtap");

    hdtbl_entry = find_heur_dissector_by_unique_short_name("rlc_udp");

    heur_rlc_udp_enabled = true; /* Set to TRUE by default */
    if (hdtbl_entry)
        heur_rlc_udp_enabled = hdtbl_entry->enabled;
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
