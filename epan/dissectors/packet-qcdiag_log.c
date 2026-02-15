/* packet-qcdiag_log.c
 * Dissector routines for Qualcomm DIAG packet handling
 *
 * Credits/Sources:
 * - Osmocom Wireshark qcdiag branch
 *   https://gitea.osmocom.org/osmocom/wireshark/src/branch/osmocom/qcdiag
 *
 * - SCAT: Signaling Collection and Analysis Tool
 *   https://github.com/fgsect/scat/
 *
 * - Android Tools MSM8996
 *   https://github.com/bcyj/android_tools_leeco_msm8996
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

#include "packet-gsm_a_common.h"
#include "packet-gsmtap.h"
#include "packet-qcdiag.h"

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

void proto_register_qcdiag_log(void);
void proto_reg_handoff_qcdiag_log(void);

static dissector_handle_t data_handle;
static dissector_handle_t gsmtap_handle;

static dissector_table_t qcdiag_log_code_dissector_table;

static int proto_qcdiag_log;

static proto_item *ti_qcdiag_ver;

static int hf_qcdiag_ver;
static int hf_qcdiag_ver_4;
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

static const true_false_string tfs_downlink_uplink = { "Downlink", "Uplink" };

/* Subscription Id 1 (Radio Id 0), Subscription Id 2 (Radio Id 1) */
static int gsm_last_uarfcn[]     = { 0, 0 };
static int umts_last_uarfcn_dl[] = { 0, 0 };
static int umts_last_uarfcn_ul[] = { 0, 0 };

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
qcdiag_log_update_version(uint32_t offset, uint32_t version)
{
    field_info *fi;

    if (!ti_qcdiag_ver) return;

    /* Set the item visible before updating it */
    proto_item_set_visible(ti_qcdiag_ver);

    fi = PNODE_FINFO(ti_qcdiag_ver);
    if (!fi) return;

    if (version <= 0xFF) {
        fi->length = 1;
    } else if (version > 0xFF) {
        fi->hfinfo = proto_registrar_get_nth(hf_qcdiag_ver_4);
        fi->length = 4;
    }

    /* Set the actual offset */
    fi->start = offset;

    /* Set the actual version */
    fvalue_set_uinteger(fi->value, version);
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
dissect_qcdiag_log_wcdma(tvbuff_t *tvb, guint offset, packet_info *pinfo, proto_tree *log_tree, proto_tree *tree)
{
    tvbuff_t *payload_tvb, *gsmtap_hdr_tvb, *gsmtap_tvb;
    uint32_t ct_offset, chan_type, subtype, uplink;
    uint32_t arfcn_val;
    int hf_rrc_ct, hf_qcdiag_subtype;
    uint8_t *gsmtap_hdr_bytes;

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

    payload_tvb = tvb_new_subset_remaining(tvb, offset);

    gsmtap_hdr_bytes = (uint8_t*)wmem_alloc0(pinfo->pool, 16);

    gsmtap_hdr_bytes[GSMTAP_HDR_VERSION]  = 0x02;
    gsmtap_hdr_bytes[GSMTAP_HDR_HDR_LEN]  = 0x04;
    gsmtap_hdr_bytes[GSMTAP_HDR_TYPE]     = GSMTAP_TYPE_UMTS_RRC;
    gsmtap_hdr_bytes[GSMTAP_HDR_ARFCN_4]  = arfcn[0] >> 8;
    gsmtap_hdr_bytes[GSMTAP_HDR_ARFCN_5]  = arfcn[0] & 0xff;
    gsmtap_hdr_bytes[GSMTAP_HDR_SUB_TYPE] = subtype;

    gsmtap_hdr_tvb = tvb_new_real_data(gsmtap_hdr_bytes, 16, 16);

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
dissect_qcdiag_log_rr(tvbuff_t *tvb, guint offset, packet_info *pinfo, proto_tree *log_tree, proto_tree *tree)
{
    tvbuff_t *payload_tvb, *gsmtap_hdr_tvb, *gsmtap_tvb, *lapdm_tvb;
    uint32_t channel_type_dir, channel_type, length;
    uint8_t *gsmtap_hdr_bytes, *lapdm_bytes;
    bool direction;

    uint32_t arfcn[] = { 0, 0 };

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

    lapdm_bytes = NULL;

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

    payload_tvb = tvb_new_subset_remaining(tvb, offset);

    gsmtap_hdr_bytes = (uint8_t*)wmem_alloc0(pinfo->pool, 16);

    gsmtap_hdr_bytes[GSMTAP_HDR_VERSION]  = 0x02;
    gsmtap_hdr_bytes[GSMTAP_HDR_HDR_LEN]  = 0x04;
    gsmtap_hdr_bytes[GSMTAP_HDR_TYPE]     = GSMTAP_TYPE_UM;
    gsmtap_hdr_bytes[GSMTAP_HDR_ARFCN_4]  = arfcn[0] >> 8;
    gsmtap_hdr_bytes[GSMTAP_HDR_ARFCN_5]  = arfcn[0] & 0xff;
    gsmtap_hdr_bytes[GSMTAP_HDR_SUB_TYPE] = channel_type;

    gsmtap_hdr_tvb = tvb_new_real_data(gsmtap_hdr_bytes, 16, 16);

    gsmtap_tvb = tvb_new_composite();
    tvb_composite_append(gsmtap_tvb, gsmtap_hdr_tvb);
    if (lapdm_bytes)
        tvb_composite_append(gsmtap_tvb, lapdm_tvb);
    tvb_composite_append(gsmtap_tvb, payload_tvb);
    tvb_composite_finalize(gsmtap_tvb);

    dissect_qcdiag_log_set_col(pinfo, GSMTAP_TYPE_UM);
    dissect_qcdiag_log_append_text(log_tree, tree, direction);

    add_new_data_source(pinfo, gsmtap_tvb, "GSM RR");
    try_call_dissector(gsmtap_handle, gsmtap_tvb, pinfo, proto_tree_get_parent_tree(tree));
}

static void
dissect_qcdiag_log_gprs_mac(tvbuff_t *tvb, guint offset, packet_info *pinfo, proto_tree *log_tree, proto_tree *tree)
{
    tvbuff_t *payload_tvb, *gsmtap_hdr_tvb, *gsmtap_tvb, *mac_hdr_tvb;
    uint32_t channel_type_dir, channel_type, length;
    uint8_t *gsmtap_hdr_bytes, *mac_hdr_bytes;
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

    mac_hdr_bytes = (uint8_t*)wmem_alloc0(pinfo->pool, 1);

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

    mac_hdr_tvb = tvb_new_real_data(mac_hdr_bytes, 1, 1);

    payload_tvb = tvb_new_subset_remaining(tvb, offset);

    gsmtap_hdr_bytes = (uint8_t*)wmem_alloc0(pinfo->pool, 16);

    gsmtap_hdr_bytes[GSMTAP_HDR_VERSION]  = 0x02;
    gsmtap_hdr_bytes[GSMTAP_HDR_HDR_LEN]  = 0x04;
    gsmtap_hdr_bytes[GSMTAP_HDR_TYPE]     = GSMTAP_TYPE_UM;
    gsmtap_hdr_bytes[GSMTAP_HDR_ARFCN_4]  = arfcn[0] >> 8;
    gsmtap_hdr_bytes[GSMTAP_HDR_ARFCN_5]  = arfcn[0] & 0xff;
    gsmtap_hdr_bytes[GSMTAP_HDR_SUB_TYPE] = channel_type;

    gsmtap_hdr_tvb = tvb_new_real_data(gsmtap_hdr_bytes, 16, 16);

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
dissect_qcdiag_log_umts_nas(tvbuff_t *tvb, guint offset, packet_info *pinfo, proto_tree *log_tree, proto_tree *tree)
{
    tvbuff_t *payload_tvb, *gsmtap_hdr_tvb, *gsmtap_tvb;
    bool direction;
    uint8_t *gsmtap_hdr_bytes;

    /* Direction */
    proto_tree_add_item_ret_boolean(log_tree, hf_qcdiag_nas_direction, tvb, offset, 1, ENC_NA, &direction);
    offset += 1;

    /* Length */
    proto_tree_add_item(log_tree, hf_qcdiag_nas_msg_length, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;

    payload_tvb = tvb_new_subset_remaining(tvb, offset);

    gsmtap_hdr_bytes = (uint8_t*)wmem_alloc0(pinfo->pool, 16);

    gsmtap_hdr_bytes[GSMTAP_HDR_VERSION] = 0x02;
    gsmtap_hdr_bytes[GSMTAP_HDR_HDR_LEN] = 0x04;
    gsmtap_hdr_bytes[GSMTAP_HDR_TYPE]    = GSMTAP_TYPE_ABIS;
    gsmtap_hdr_bytes[GSMTAP_HDR_ARFCN_4] = (uint8_t)(direction) << 6;

    gsmtap_hdr_tvb = tvb_new_real_data(gsmtap_hdr_bytes, 16, 16);

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
dissect_qcdiag_log_lte_rrc(tvbuff_t *tvb, guint offset, packet_info *pinfo, proto_tree *log_tree, proto_tree *tree)
{
    tvbuff_t *payload_tvb, *gsmtap_hdr_tvb, *gsmtap_tvb;
    uint8_t *gsmtap_hdr_bytes;
    uint32_t version, sfn, pdu, subtype, arfcn, earfcn, frame_nr;
    uint8_t lte_rnum, lte_rmajmin, nr_rnum, nr_rmajmin;
    bool direction;

    /* Packet Version */
    proto_tree_add_item_ret_uint(log_tree, hf_qcdiag_packet_ver, tvb, offset, 1, ENC_NA, &version);
    offset += 1;

    lte_rnum    = tvb_get_uint8(tvb, offset);
    lte_rmajmin = tvb_get_uint8(tvb, offset+1);

    /* LTE Release Number */
    proto_tree_add_string_format_value(log_tree, hf_qcdiag_lte_rrc_rel, tvb, offset, 2,
        "LTE RRC Release", "%u.%u.%u", lte_rnum, lte_rmajmin / 16, lte_rmajmin % 16);
    offset += 2;


    if (version > 24) {
        nr_rnum    = tvb_get_uint8(tvb, offset);
        nr_rmajmin = tvb_get_uint8(tvb, offset+1);

        /* NR Release Number */
        proto_tree_add_string_format_value(log_tree, hf_qcdiag_nr_rrc_rel, tvb, offset, 2,
            "NR RRC Release", "%u.%u.%u", nr_rnum, nr_rmajmin / 16, nr_rmajmin % 16);
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

    payload_tvb = tvb_new_subset_remaining(tvb, offset);

    gsmtap_hdr_bytes = (uint8_t*)wmem_alloc0(pinfo->pool, 16);

    gsmtap_hdr_bytes[GSMTAP_HDR_VERSION]         = 0x02;
    gsmtap_hdr_bytes[GSMTAP_HDR_HDR_LEN]         = 0x04;
    gsmtap_hdr_bytes[GSMTAP_HDR_TYPE]            = GSMTAP_TYPE_LTE_RRC;
    gsmtap_hdr_bytes[GSMTAP_HDR_ARFCN_4]         = arfcn >> 8;
    gsmtap_hdr_bytes[GSMTAP_HDR_ARFCN_5]         = arfcn & 0xff;
    gsmtap_hdr_bytes[GSMTAP_HDR_FRAME_NUMBER_8]  = (frame_nr >> 24) & 0xff;
    gsmtap_hdr_bytes[GSMTAP_HDR_FRAME_NUMBER_9]  = (frame_nr >> 16) & 0xff;
    gsmtap_hdr_bytes[GSMTAP_HDR_FRAME_NUMBER_10] = (frame_nr >>  8) & 0xff;
    gsmtap_hdr_bytes[GSMTAP_HDR_FRAME_NUMBER_11] = frame_nr & 0xff;
    gsmtap_hdr_bytes[GSMTAP_HDR_SUB_TYPE]        = subtype;
    gsmtap_hdr_bytes[GSMTAP_HDR_SUB_SLOT]        = sfn & 0x000f;

    gsmtap_hdr_tvb = tvb_new_real_data(gsmtap_hdr_bytes, 16, 16);

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
dissect_qcdiag_log_lte_nas(tvbuff_t *tvb, guint offset, packet_info *pinfo, proto_tree *log_tree, proto_tree *tree, bool plain)
{
    tvbuff_t *payload_tvb, *gsmtap_hdr_tvb, *gsmtap_tvb;
    uint32_t version, arfcn;
    uint8_t *gsmtap_hdr_bytes;
    uint8_t msgtype, lte_maj, lte_min, lte_patch;
    bool direction;

    /* Version */
    version = tvb_get_uint8(tvb, offset);
    qcdiag_log_update_version(offset, version);
    offset += 1;

    lte_maj   = tvb_get_uint8(tvb, offset);
    lte_min   = tvb_get_uint8(tvb, offset+1);
    lte_patch = tvb_get_uint8(tvb, offset+2);

    /* Release Version */
    proto_tree_add_string_format_value(log_tree, hf_qcdiag_lte_nas_rel, tvb, offset, 3,
        "Release Version", "%u.%u.%u", lte_maj, lte_min, lte_patch);
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

    payload_tvb = tvb_new_subset_remaining(tvb, offset);

    gsmtap_hdr_bytes = (uint8_t*)wmem_alloc0(pinfo->pool, 16);

    gsmtap_hdr_bytes[GSMTAP_HDR_VERSION]  = 0x02;
    gsmtap_hdr_bytes[GSMTAP_HDR_HDR_LEN]  = 0x04;
    gsmtap_hdr_bytes[GSMTAP_HDR_TYPE]     = GSMTAP_TYPE_LTE_NAS;
    gsmtap_hdr_bytes[GSMTAP_HDR_ARFCN_4]  = arfcn >> 8;
    gsmtap_hdr_bytes[GSMTAP_HDR_SUB_TYPE] = !plain;

    gsmtap_hdr_tvb = tvb_new_real_data(gsmtap_hdr_bytes, 16, 16);

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
dissect_qcdiag_log(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void * data _U_)
{
    proto_item *ti;
    proto_tree *diag_log_tree;
    tvbuff_t *payload_tvb;
    int hf_id;
    uint32_t offset = 0;
    uint32_t code = 0;
    nstime_t abs_time;
    char *timestamp;
    const char *str;

    hf_id = proto_registrar_get_id_byname("qcdiag.logcode");

    /* Log Code */
    if (hf_id > -1)
        proto_tree_add_item_ret_uint(tree, hf_id, tvb, offset+6, 2, ENC_LITTLE_ENDIAN, &code);

    hf_id = proto_registrar_get_id_byname("qcdiag.len");

    /* Length of the included LOG_ITEM */
    if (hf_id > -1)
        proto_tree_add_item(tree, hf_id, tvb, offset+2, 2, ENC_LITTLE_ENDIAN);

    /* Version */
    ti_qcdiag_ver = proto_tree_add_uint(tree, hf_qcdiag_ver, tvb, offset, 0, 0);
    proto_item_set_hidden(ti_qcdiag_ver);

    hf_id = proto_registrar_get_id_byname("qcdiag.cmd");

    /* Command Code */
    if (hf_id > -1)
        proto_tree_add_uint(tree, hf_id, tvb, offset, 1, DIAG_LOG_F);

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

    str = val_to_str_ext(pinfo->pool, code, &qcdiag_logcodes_ext, "Unknown Log Code (0x%02x)");

    ti = proto_tree_get_parent(tree);
    col_set_str(pinfo->cinfo, COL_INFO, str);
    proto_item_append_text(ti, ", %s", str);

    diag_log_tree = proto_tree_add_subtree(tree, tvb, offset, -1, ett_qcdiag_log, NULL, str);

    switch (code) {
    case 0x512f:
        dissect_qcdiag_log_rr(tvb, offset, pinfo, diag_log_tree, tree);
        break;
    case 0x412f:
        dissect_qcdiag_log_wcdma(tvb, offset, pinfo, diag_log_tree, tree);
        break;
    case 0x5226:
        dissect_qcdiag_log_gprs_mac(tvb, offset, pinfo, diag_log_tree, tree);
        break;
    case 0x713a:
        dissect_qcdiag_log_umts_nas(tvb, offset, pinfo, diag_log_tree, tree);
        break;
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
        { &hf_qcdiag_ver,
          { "Version", "qcdiag_log.ver",
            FT_UINT8, BASE_CUSTOM, CF_FUNC(qcdiag_format_ver), 0, "Log Code Version", HFILL }},
        { &hf_qcdiag_ver_4,
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
          { "Primary Scrambling Code", "qcdiag_log.psc",
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
        &ett_qcdiag_log
    };

    proto_qcdiag_log = proto_register_protocol("Qualcomm Diagnostic Log", "QCDIAG LOG", "qcdiag_log");
    proto_register_field_array(proto_qcdiag_log, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

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
    gsmtap_handle = find_dissector("gsmtap");
}

/*
 * Editor modelines  -  http://www.wireshark.org/tools/modelines.html
 *
 * Local variables:
 * c-basic-offset: 8
 * tab-width: 8
 * indent-tabs-mode: t
 * End:
 *
 * vi: set shiftwidth=8 tabstop=8 noexpandtab:
 * :indentSize=8:tabSize=8:noTabs=false:
 */
