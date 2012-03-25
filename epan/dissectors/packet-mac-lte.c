/* Routines for LTE MAC disassembly
 *
 * Martin Mathieson
 *
 * $Id$
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

 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 */

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <string.h>

#include <epan/packet.h>
#include <epan/expert.h>
#include <epan/prefs.h>
#include <epan/tap.h>
#include <epan/uat.h>

#include "packet-mac-lte.h"
#include "packet-rlc-lte.h"


/* Described in:
 * 3GPP TS 36.321 Evolved Universal Terrestrial Radio Access (E-UTRA)
 *                Medium Access Control (MAC) protocol specification (Release 8)
 */


/* Initialize the protocol and registered fields. */
int proto_mac_lte = -1;

static int mac_lte_tap = -1;

/* Decoding context */
static int hf_mac_lte_context = -1;
static int hf_mac_lte_context_radio_type = -1;
static int hf_mac_lte_context_direction = -1;
static int hf_mac_lte_context_rnti = -1;
static int hf_mac_lte_context_rnti_type = -1;
static int hf_mac_lte_context_ueid = -1;
static int hf_mac_lte_context_sysframe_number = -1;
static int hf_mac_lte_context_subframe_number = -1;
static int hf_mac_lte_context_grant_subframe_number = -1;
static int hf_mac_lte_context_predefined_frame = -1;
static int hf_mac_lte_context_length = -1;
static int hf_mac_lte_context_ul_grant_size = -1;
static int hf_mac_lte_context_bch_transport_channel = -1;
static int hf_mac_lte_context_retx_count = -1;
static int hf_mac_lte_context_retx_reason = -1;
static int hf_mac_lte_context_crc_status = -1;
static int hf_mac_lte_context_rapid = -1;
static int hf_mac_lte_context_rach_attempt_number = -1;

/* Inferred context */
static int hf_mac_lte_ues_ul_per_tti = -1;
static int hf_mac_lte_ues_dl_per_tti = -1;


/* Extra PHY context */
static int hf_mac_lte_context_phy_ul = -1;
static int hf_mac_lte_context_phy_ul_modulation_type = -1;
static int hf_mac_lte_context_phy_ul_tbs_index = -1;
static int hf_mac_lte_context_phy_ul_resource_block_length = -1;
static int hf_mac_lte_context_phy_ul_resource_block_start = -1;
static int hf_mac_lte_context_phy_ul_harq_id = -1;
static int hf_mac_lte_context_phy_ul_ndi = -1;

static int hf_mac_lte_context_phy_dl = -1;
static int hf_mac_lte_context_phy_dl_dci_format = -1;
static int hf_mac_lte_context_phy_dl_resource_allocation_type = -1;
static int hf_mac_lte_context_phy_dl_aggregation_level = -1;
static int hf_mac_lte_context_phy_dl_mcs_index = -1;
static int hf_mac_lte_context_phy_dl_redundancy_version_index = -1;
static int hf_mac_lte_context_phy_dl_retx = -1;
static int hf_mac_lte_context_phy_dl_resource_block_length = -1;
static int hf_mac_lte_context_phy_dl_crc_status = -1;
static int hf_mac_lte_context_phy_dl_harq_id = -1;
static int hf_mac_lte_context_phy_dl_ndi = -1;
static int hf_mac_lte_context_phy_dl_tb = -1;


/* Out-of-band events */
static int hf_mac_lte_oob_send_preamble = -1;
static int hf_mac_lte_oob_send_sr = -1;
static int hf_mac_lte_number_of_srs = -1;
static int hf_mac_lte_oob_sr_failure = -1;

/* MAC SCH/MCH header fields */
static int hf_mac_lte_ulsch = -1;
static int hf_mac_lte_ulsch_header = -1;
static int hf_mac_lte_dlsch = -1;
static int hf_mac_lte_dlsch_header = -1;
static int hf_mac_lte_sch_subheader = -1;
static int hf_mac_lte_mch = -1;
static int hf_mac_lte_mch_header = -1;
static int hf_mac_lte_mch_subheader = -1;

static int hf_mac_lte_sch_reserved = -1;
static int hf_mac_lte_dlsch_lcid = -1;
static int hf_mac_lte_ulsch_lcid = -1;
static int hf_mac_lte_sch_extended = -1;
static int hf_mac_lte_sch_format = -1;
static int hf_mac_lte_sch_length = -1;
static int hf_mac_lte_mch_reserved = -1;
static int hf_mac_lte_mch_lcid = -1;
static int hf_mac_lte_mch_extended = -1;
static int hf_mac_lte_mch_format = -1;
static int hf_mac_lte_mch_length = -1;

static int hf_mac_lte_sch_header_only = -1;
static int hf_mac_lte_mch_header_only = -1;

/* Data */
static int hf_mac_lte_sch_sdu = -1;
static int hf_mac_lte_mch_sdu = -1;
static int hf_mac_lte_bch_pdu = -1;
static int hf_mac_lte_pch_pdu = -1;
static int hf_mac_lte_predefined_pdu = -1;
static int hf_mac_lte_raw_pdu = -1;
static int hf_mac_lte_padding_data = -1;
static int hf_mac_lte_padding_length = -1;


/* RAR fields */
static int hf_mac_lte_rar = -1;
static int hf_mac_lte_rar_headers = -1;
static int hf_mac_lte_rar_header = -1;
static int hf_mac_lte_rar_extension = -1;
static int hf_mac_lte_rar_t = -1;
static int hf_mac_lte_rar_bi = -1;
static int hf_mac_lte_rar_rapid = -1;
static int hf_mac_lte_rar_reserved = -1;
static int hf_mac_lte_rar_body = -1;
static int hf_mac_lte_rar_reserved2 = -1;
static int hf_mac_lte_rar_ta = -1;
static int hf_mac_lte_rar_ul_grant = -1;
static int hf_mac_lte_rar_ul_grant_hopping = -1;
static int hf_mac_lte_rar_ul_grant_fsrba = -1;
static int hf_mac_lte_rar_ul_grant_tmcs = -1;
static int hf_mac_lte_rar_ul_grant_tcsp = -1;
static int hf_mac_lte_rar_ul_grant_ul_delay = -1;
static int hf_mac_lte_rar_ul_grant_cqi_request = -1;
static int hf_mac_lte_rar_temporary_crnti = -1;

/* Common channel control values */
static int hf_mac_lte_control_bsr = -1;
static int hf_mac_lte_control_bsr_lcg_id = -1;
static int hf_mac_lte_control_short_bsr_buffer_size = -1;
static int hf_mac_lte_control_long_bsr_buffer_size_0 = -1;
static int hf_mac_lte_control_long_bsr_buffer_size_1 = -1;
static int hf_mac_lte_control_long_bsr_buffer_size_2 = -1;
static int hf_mac_lte_control_long_bsr_buffer_size_3 = -1;
static int hf_mac_lte_control_crnti = -1;
static int hf_mac_lte_control_timing_advance = -1;
static int hf_mac_lte_control_timing_advance_reserved = -1;
static int hf_mac_lte_control_ue_contention_resolution = -1;
static int hf_mac_lte_control_ue_contention_resolution_identity = -1;
static int hf_mac_lte_control_ue_contention_resolution_msg3 = -1;
static int hf_mac_lte_control_ue_contention_resolution_msg3_matched = -1;
static int hf_mac_lte_control_ue_contention_resolution_time_since_msg3 = -1;
static int hf_mac_lte_control_power_headroom = -1;
static int hf_mac_lte_control_power_headroom_reserved = -1;
static int hf_mac_lte_control_power_headroom_level = -1;
static int hf_mac_lte_control_padding = -1;
static int hf_mac_lte_control_mch_scheduling_info = -1;
static int hf_mac_lte_control_mch_scheduling_info_lcid = -1;
static int hf_mac_lte_control_mch_scheduling_info_stop_mtch = -1;

static int hf_mac_lte_dl_harq_resend_original_frame = -1;
static int hf_mac_lte_dl_harq_resend_time_since_previous_frame = -1;
static int hf_mac_lte_dl_harq_resend_next_frame = -1;
static int hf_mac_lte_dl_harq_resend_time_until_next_frame = -1;

static int hf_mac_lte_ul_harq_resend_original_frame = -1;
static int hf_mac_lte_ul_harq_resend_time_since_previous_frame = -1;
static int hf_mac_lte_ul_harq_resend_next_frame = -1;
static int hf_mac_lte_ul_harq_resend_time_until_next_frame = -1;


static int hf_mac_lte_grant_answering_sr = -1;
static int hf_mac_lte_failure_answering_sr = -1;
static int hf_mac_lte_sr_leading_to_failure = -1;
static int hf_mac_lte_sr_leading_to_grant = -1;
static int hf_mac_lte_sr_invalid_event = -1;
static int hf_mac_lte_sr_time_since_request = -1;
static int hf_mac_lte_sr_time_until_answer = -1;


/* Subtrees. */
static int ett_mac_lte = -1;
static int ett_mac_lte_context = -1;
static int ett_mac_lte_phy_context = -1;
static int ett_mac_lte_ulsch_header = -1;
static int ett_mac_lte_dlsch_header = -1;
static int ett_mac_lte_mch_header = -1;
static int ett_mac_lte_sch_subheader = -1;
static int ett_mac_lte_mch_subheader = -1;
static int ett_mac_lte_rar_headers = -1;
static int ett_mac_lte_rar_header = -1;
static int ett_mac_lte_rar_body = -1;
static int ett_mac_lte_rar_ul_grant = -1;
static int ett_mac_lte_bsr = -1;
static int ett_mac_lte_bch = -1;
static int ett_mac_lte_pch = -1;
static int ett_mac_lte_contention_resolution = -1;
static int ett_mac_lte_power_headroom = -1;
static int ett_mac_lte_mch_scheduling_info = -1;
static int ett_mac_lte_oob = -1;



/* Constants and value strings */

static const value_string radio_type_vals[] =
{
    { FDD_RADIO,      "FDD"},
    { TDD_RADIO,      "TDD"},
    { 0, NULL }
};


static const value_string direction_vals[] =
{
    { DIRECTION_UPLINK,      "Uplink"},
    { DIRECTION_DOWNLINK,    "Downlink"},
    { 0, NULL }
};


static const value_string rnti_type_vals[] =
{
    { NO_RNTI,     "NO-RNTI"},
    { P_RNTI,      "P-RNTI"},
    { RA_RNTI,     "RA-RNTI"},
    { C_RNTI,      "C-RNTI"},
    { SI_RNTI,     "SI-RNTI"},
    { SPS_RNTI,    "SPS-RNTI"},
    { M_RNTI,      "M-RNTI"},
    { 0, NULL }
};

static const value_string bch_transport_channel_vals[] =
{
    { SI_RNTI,      "DL-SCH"},
    { NO_RNTI,      "BCH"},
    { 0, NULL }
};

static const value_string crc_status_vals[] =
{
    { crc_success,                "OK"},
    { crc_fail,                   "Failed"},
    { crc_high_code_rate,         "High Code Rate"},
    { crc_pdsch_lost,             "PDSCH Lost"},
    { crc_duplicate_nonzero_rv,   "Duplicate_nonzero_rv"},
    { 0, NULL }
};


static const value_string dci_format_vals[] =
{
    { 0, "0"},
    { 1, "1"},
    { 2, "1A"},
    { 3, "1B"},
    { 4, "1C"},
    { 5, "1D"},
    { 6, "2"},
    { 7, "2A"},
    { 8, "3/3A"},
    { 0, NULL }
};

static const value_string aggregation_level_vals[] =
{
    { 0, "1"},
    { 1, "2"},
    { 2, "4"},
    { 3, "8"},
    { 0, NULL }
};

static const value_string modulation_type_vals[] =
{
    { 2, "QPSK"},
    { 4, "QAM16"},
    { 6, "QAM64"},
    { 0, NULL }
};


#define UE_CONTENTION_RESOLUTION_IDENTITY_LCID 0x1c
#define TIMING_ADVANCE_LCID                    0x1d
#define DRX_COMMAND_LCID                       0x1e
#define PADDING_LCID                           0x1f

static const value_string dlsch_lcid_vals[] =
{
    { 0,                                        "CCCH"},
    { 1,                                        "1"},
    { 2,                                        "2"},
    { 3,                                        "3"},
    { 4,                                        "4"},
    { 5,                                        "5"},
    { 6,                                        "6"},
    { 7,                                        "7"},
    { 8,                                        "8"},
    { 9,                                        "9"},
    { 10,                                       "10"},
    { UE_CONTENTION_RESOLUTION_IDENTITY_LCID,   "UE Contention Resolution Identity"},
    { TIMING_ADVANCE_LCID                   ,   "Timing Advance"},
    { DRX_COMMAND_LCID                      ,   "DRX Command"},
    { PADDING_LCID                          ,   "Padding" },
    { 0, NULL }
};

#define POWER_HEADROOM_REPORT_LCID    0x1a
#define CRNTI_LCID                    0x1b
#define TRUNCATED_BSR_LCID            0x1c
#define SHORT_BSR_LCID                0x1d
#define LONG_BSR_LCID                 0x1e

static const value_string ulsch_lcid_vals[] =
{
    { 0,                            "CCCH"},
    { 1,                            "1"},
    { 2,                            "2"},
    { 3,                            "3"},
    { 4,                            "4"},
    { 5,                            "5"},
    { 6,                            "6"},
    { 7,                            "7"},
    { 8,                            "8"},
    { 9,                            "9"},
    { 10,                           "10"},
    { POWER_HEADROOM_REPORT_LCID,   "Power Headroom Report"},
    { CRNTI_LCID,                   "C-RNTI"},
    { TRUNCATED_BSR_LCID,           "Truncated BSR"},
    { SHORT_BSR_LCID,               "Short BSR"},
    { LONG_BSR_LCID,                "Long BSR"},
    { PADDING_LCID,                 "Padding" },
    { 0, NULL }
};

#define MCH_SCHEDULING_INFO_LCID 0x1e

static const value_string mch_lcid_vals[] =
{
    { 0,                            "MCCH"},
    { 1,                            "1"},
    { 2,                            "2"},
    { 3,                            "3"},
    { 4,                            "4"},
    { 5,                            "5"},
    { 6,                            "6"},
    { 7,                            "7"},
    { 8,                            "8"},
    { 9,                            "9"},
    { 10,                           "10"},
    { 11,                           "11"},
    { 12,                           "12"},
    { 13,                           "13"},
    { 14,                           "14"},
    { 15,                           "15"},
    { 16,                           "16"},
    { 17,                           "17"},
    { 18,                           "18"},
    { 19,                           "19"},
    { 20,                           "20"},
    { 21,                           "21"},
    { 22,                           "22"},
    { 23,                           "23"},
    { 24,                           "24"},
    { 25,                           "25"},
    { 26,                           "26"},
    { 27,                           "27"},
    { 28,                           "28"},
    { MCH_SCHEDULING_INFO_LCID,     "MCH Scheduling Information"},
    { PADDING_LCID,                 "Padding" },
    { 0, NULL }
};

static const value_string format_vals[] =
{
    { 0,      "Data length is < 128 bytes"},
    { 1,      "Data length is >= 128 bytes"},
    { 0, NULL }
};


static const value_string rar_type_vals[] =
{
    { 0,      "Backoff Indicator present"},
    { 1,      "RAPID present"},
    { 0, NULL }
};


static const value_string rar_bi_vals[] =
{
    { 0,      "0"},
    { 1,      "10"},
    { 2,      "20"},
    { 3,      "30"},
    { 4,      "40"},
    { 5,      "60"},
    { 6,      "80"},
    { 7,      "120"},
    { 8,      "160"},
    { 9,      "240"},
    { 10,     "320"},
    { 11,     "480"},
    { 12,     "960"},
    { 0, NULL }
};


static const value_string buffer_size_vals[] =
{
    { 0,      "BS = 0"},
    { 1,      "0   < BS <= 10"},
    { 2,      "10  < BS <= 12"},
    { 3,      "12  < BS <= 14"},
    { 4,      "14  < BS <= 17"},
    { 5,      "17  < BS <= 19"},
    { 6,      "19  < BS <= 22"},
    { 7,      "22  < BS <= 26"},
    { 8,      "26  < BS <= 31"},
    { 9,      "31  < BS <= 36"},
    { 10,     "36  < BS <= 42"},
    { 11,     "42  < BS <= 49"},
    { 12,     "49  < BS <= 57"},
    { 13,     "47  < BS <= 67"},
    { 14,     "67  < BS <= 78"},
    { 15,     "78  < BS <= 91"},
    { 16,     "91  < BS <= 107"},
    { 17,     "107 < BS <= 125"},
    { 18,     "125 < BS <= 146"},
    { 19,     "146 < BS <= 171"},
    { 20,     "171 < BS <= 200"},
    { 21,     "200 < BS <= 234"},
    { 22,     "234 < BS <= 274"},
    { 23,     "274 < BS <= 321"},
    { 24,     "321 < BS <= 376"},
    { 25,     "376 < BS <= 440"},
    { 26,     "440 < BS <= 515"},
    { 27,     "515 < BS <= 603"},
    { 28,     "603 < BS <= 706"},
    { 29,     "706 < BS <= 826"},
    { 30,     "826 < BS <= 967"},
    { 31,     "967  < BS <= 1132"},
    { 32,     "1132 < BS <= 1326"},
    { 33,     "1326 < BS <= 1552"},
    { 34,     "1552 < BS <= 1817"},
    { 35,     "1817 < BS <= 2127"},
    { 36,     "2127 < BS <= 2490"},
    { 37,     "2490 < BS <= 2915"},
    { 38,     "2915 < BS <= 3413"},
    { 39,     "3413 < BS <= 3995"},
    { 40,     "3995 < BS <= 4677"},
    { 41,     "4677 < BS <= 5476"},
    { 42,     "5476 < BS <= 6411"},
    { 43,     "6411 < BS <= 7505"},
    { 44,     "7505 < BS <= 8787"},
    { 45,     "8787 < BS <= 10276"},
    { 46,     "10287 < BS <= 12043"},
    { 47,     "12043 < BS <= 14099"},
    { 48,     "14099 < BS <= 16507"},
    { 49,     "16507 < BS <= 19325"},
    { 50,     "19325 < BS <= 22624"},
    { 51,     "22624 < BS <= 26487"},
    { 52,     "26487 < BS <= 31009"},
    { 53,     "31009 < BS <= 36304"},
    { 54,     "36304 < BS <= 42502"},
    { 55,     "42502 < BS <= 49759"},
    { 56,     "49759 < BS <= 58255"},
    { 57,     "58255 < BS <= 68201"},
    { 58,     "68201 < BS <= 79846"},
    { 59,     "79846 < BS <= 93479"},
    { 60,     "93479 < BS <= 109439"},
    { 61,     "109439 < BS <= 128125"},
    { 62,     "128125 < BS <= 150000"},
    { 63,     "BS > 150000"},
    { 0, NULL }
};

static const value_string power_headroom_size_vals[] =
{
    { 0,      "-23 <= PH < -22"},
    { 1,      "-22 <= PH < -21"},
    { 2,      "-21 <= PH < -20"},
    { 3,      "-20 <= PH < -19"},
    { 4,      "-19 <= PH < -18"},
    { 5,      "-18 <= PH < -17"},
    { 6,      "-17 <= PH < -16"},
    { 7,      "-16 <= PH < -15"},
    { 8,      "-15 <= PH < -14"},
    { 9,      "-14 <= PH < -13"},
    { 10,     "-13 <= PH < -12"},
    { 11,     "-12 <= PH < -11"},
    { 12,     "-11 <= PH < -10"},
    { 13,     "-10 <= PH < -9"},
    { 14,     "-9 <= PH < -8"},
    { 15,     "-8 <= PH < -7"},
    { 16,     "-7 <= PH < -6"},
    { 17,     "-6 <= PH < -5"},
    { 18,     "-5 <= PH < -4"},
    { 19,     "-4 <= PH < -3"},
    { 20,     "-3 <= PH < -2"},
    { 21,     "-2 <= PH < -1"},
    { 22,     "-1 <= PH < 0"},
    { 23,     "0 <= PH < 1"},
    { 24,     "1 <= PH < 2"},
    { 25,     "2 <= PH < 3"},
    { 26,     "3 <= PH < 4"},
    { 27,     "4 <= PH < 5"},
    { 28,     "5 <= PH < 6"},
    { 29,     "6 <= PH < 7"},
    { 30,     "7 <= PH < 8"},
    { 31,     "8 <= PH < 9"},
    { 32,     "9 <= PH < 10"},
    { 33,     "10 <= PH < 11"},
    { 34,     "11 <= PH < 12"},
    { 35,     "12 <= PH < 13"},
    { 36,     "13 <= PH < 14"},
    { 37,     "14 <= PH < 15"},
    { 38,     "15 <= PH < 16"},
    { 39,     "16 <= PH < 17"},
    { 40,     "17 <= PH < 18"},
    { 41,     "18 <= PH < 19"},
    { 42,     "19 <= PH < 20"},
    { 43,     "20 <= PH < 21"},
    { 44,     "21 <= PH < 22"},
    { 45,     "22 <= PH < 23"},
    { 46,     "23 <= PH < 24"},
    { 47,     "24 <= PH < 25"},
    { 48,     "25 <= PH < 26"},
    { 49,     "26 <= PH < 27"},
    { 50,     "27 <= PH < 28"},
    { 51,     "28 <= PH < 29"},
    { 52,     "29 <= PH < 30"},
    { 53,     "30 <= PH < 31"},
    { 54,     "31 <= PH < 32"},
    { 55,     "32 <= PH < 33"},
    { 56,     "33 <= PH < 34"},
    { 57,     "34 <= PH < 35"},
    { 58,     "34 <= PH < 36"},
    { 59,     "36 <= PH < 37"},
    { 60,     "37 <= PH < 38"},
    { 61,     "38 <= PH < 39"},
    { 62,     "39 <= PH < 40"},
    { 63,     "PH >= 40"},
    { 0, NULL }
};

static const value_string header_only_vals[] =
{
    { 0,      "MAC PDU Headers and body present"},
    { 1,      "MAC PDU Headers only"},
    { 0, NULL }
};

static const value_string predefined_frame_vals[] =
{
    { 0,      "Real MAC PDU present - will dissect"},
    { 1,      "Predefined frame present - will not dissect"},
    { 0, NULL }
};

static const value_string ul_retx_grant_vals[] =
{
    { 0,      "PDCCH ReTx"},
    { 1,      "PHICH NACK"},
    { 0, NULL }
};

/**************************************************************************/
/* Preferences state                                                      */
/**************************************************************************/

/* If this PDU has been NACK'd (by HARQ) more than a certain number of times,
   we trigger an expert warning. */
static gint global_mac_lte_retx_counter_trigger = 3;

/* By default try to decode transparent data (BCH, PCH and CCCH) data using LTE RRC dissector */
static gboolean global_mac_lte_attempt_rrc_decode = TRUE;

/* Whether should attempt to dissect frames failing CRC check */
static gboolean global_mac_lte_dissect_crc_failures = FALSE;

/* Whether should attempt to decode lcid 1&2 SDUs as srb1/2 (i.e. AM RLC) */
static gboolean global_mac_lte_attempt_srb_decode = TRUE;

/* Where to take LCID -> DRB mappings from */
enum lcid_drb_source {
    FromStaticTable, FromConfigurationProtocol
};
static gint global_mac_lte_lcid_drb_source = (gint)FromStaticTable;

/* Threshold for warning in expert info about high BSR values */
static gint global_mac_lte_bsr_warn_threshold = 50; /* default is 19325 -> 22624 */

/* Whether or not to track SRs and related frames */
static gboolean global_mac_lte_track_sr = TRUE;

/* Which layer info to show in the info column */
enum layer_to_show {
    ShowPHYLayer, ShowMACLayer, ShowRLCLayer
};

/* Which layer's details to show in Info column */
static gint     global_mac_lte_layer_to_show = (gint)ShowRLCLayer;

/* When showing RLC info, count PDUs so can append info column properly */
static guint8   s_number_of_rlc_pdus_shown = 0;

/***********************************************************************/
/* How to dissect lcid 3-10 (presume drb logical channels)             */

static const value_string drb_lcid_vals[] = {
    { 3,  "LCID 3"},
    { 4,  "LCID 4"},
    { 5,  "LCID 5"},
    { 6,  "LCID 6"},
    { 7,  "LCID 7"},
    { 8,  "LCID 8"},
    { 9,  "LCID 9"},
    { 10, "LCID 10"},
    { 0, NULL }
};

typedef enum rlc_channel_type_t {
    rlcRaw,
    rlcTM,
    rlcUM5,
    rlcUM10,
    rlcAM
} rlc_channel_type_t;

static const value_string rlc_channel_type_vals[] = {
    { rlcTM,    "TM"},
    { rlcUM5 ,  "UM, SN Len=5"},
    { rlcUM10,  "UM, SN Len=10"},
    { rlcAM  ,  "AM"},
    { 0, NULL }
};


/* Mapping type */
typedef struct lcid_drb_mapping_t {
    guint16 lcid;
    gint    drbid;
    rlc_channel_type_t channel_type;
} lcid_drb_mapping_t;

/* Mapping entity */
static lcid_drb_mapping_t *lcid_drb_mappings = NULL;
static guint num_lcid_drb_mappings = 0;

UAT_VS_DEF(lcid_drb_mappings, lcid, lcid_drb_mapping_t, 3, "LCID 3")
UAT_DEC_CB_DEF(lcid_drb_mappings, drbid, lcid_drb_mapping_t)
UAT_VS_DEF(lcid_drb_mappings, channel_type, lcid_drb_mapping_t, 2, "AM")

/* UAT object */
static uat_t* lcid_drb_mappings_uat;

/* Dynamic mappings (set by configuration protocol)
   LCID is the index into the array of these */
typedef struct dynamic_lcid_drb_mapping_t {
    gboolean valid;
    gint     drbid;
    rlc_channel_type_t channel_type;
    guint8   ul_priority;
} dynamic_lcid_drb_mapping_t;

static dynamic_lcid_drb_mapping_t dynamic_lcid_drb_mapping[11];


extern int proto_rlc_lte;

/***************************************************************/



/***************************************************************/
/* Keeping track of Msg3 bodies so they can be compared with   */
/* Contention Resolution bodies.                               */

typedef struct Msg3Data {
    guint8   data[6];
    nstime_t msg3Time;
    guint32  framenum;
} Msg3Data;


/* This table stores (RNTI -> Msg3Data*).  Will be populated when
   Msg3 frames are first read.  */
static GHashTable *mac_lte_msg3_hash = NULL;

/* Hash table functions for mac_lte_msg3_hash.  Hash is just the (RNTI) key */
static gint mac_lte_rnti_hash_equal(gconstpointer v, gconstpointer v2)
{
    return (v == v2);
}

static guint mac_lte_rnti_hash_func(gconstpointer v)
{
    return GPOINTER_TO_UINT(v);
}


typedef enum ContentionResolutionStatus {
    NoMsg3,
    Msg3Match,
    Msg3NoMatch
} ContentionResolutionStatus;

typedef struct ContentionResolutionResult {
    ContentionResolutionStatus status;
    guint                      msg3FrameNum;
    guint                      msSinceMsg3;
} ContentionResolutionResult;


/* This table stores (CRFrameNum -> CRResult).  It is assigned during the first
   pass and used thereafter */
static GHashTable *mac_lte_cr_result_hash = NULL;

/* Hash table functions for mac_lte_cr_result_hash.  Hash is just the (framenum) key */
static gint mac_lte_framenum_hash_equal(gconstpointer v, gconstpointer v2)
{
    return (v == v2);
}

static guint mac_lte_framenum_hash_func(gconstpointer v)
{
    return GPOINTER_TO_UINT(v);
}

/**************************************************************************/



/****************************************************************/
/* Keeping track of last DL frames per C-RNTI so can guess when */
/* there has been a HARQ retransmission                         */
/* TODO: this should be simplified now that harq-id & ndi are   */
/* being logged!                                                */

/* Could be bigger, but more than enough to flag suspected resends */
#define MAX_EXPECTED_PDU_LENGTH 2048

typedef struct LastFrameData {
    gboolean inUse;
    guint32  framenum;
    gboolean ndi;
    nstime_t received_time;
    gint     length;
    guint8   data[MAX_EXPECTED_PDU_LENGTH];
} LastFrameData;

typedef struct DLHarqBuffers {
    LastFrameData harqid[2][15];  /* 2 blocks (1 for each antenna) needed for DL */
} DLHarqBuffers;


/* This table stores (RNTI -> DLHARQBuffers*).  Will be populated when
   DL frames are first read.  */
static GHashTable *mac_lte_dl_harq_hash = NULL;

typedef struct DLHARQResult {
    gboolean    previousSet, nextSet;
    guint       previousFrameNum;
    guint       timeSincePreviousFrame;
    guint       nextFrameNum;
    guint       timeToNextFrame;
} DLHARQResult;


/* This table stores (FrameNumber -> *DLHARQResult).  It is assigned during the first
   pass and used thereafter */
static GHashTable *mac_lte_dl_harq_result_hash = NULL;

/**************************************************************************/


/*****************************************************************/
/* Keeping track of last UL frames per C-RNTI so can verify when */
/* told that a frame is a retx                                   */

typedef struct ULHarqBuffers {
    LastFrameData harqid[8];
} ULHarqBuffers;


/* This table stores (RNTI -> ULHarqBuffers*).  Will be populated when
   UL frames are first read.  */
static GHashTable *mac_lte_ul_harq_hash = NULL;

typedef struct ULHARQResult {
    gboolean    previousSet, nextSet;
    guint       previousFrameNum;
    guint       timeSincePreviousFrame;
    guint       nextFrameNum;
    guint       timeToNextFrame;
} ULHARQResult;


/* This table stores (FrameNum -> ULHARQResult).  It is assigned during the first
   pass and used thereafter */
static GHashTable *mac_lte_ul_harq_result_hash = NULL;

/**************************************************************************/


/**************************************************************************/
/* Tracking of Scheduling Requests (SRs).                                 */
/* Keep track of:                                                         */
/* - last grant before SR                                                 */
/* - SR failures following request                                        */
/* - grant following SR                                                   */

typedef enum SREvent {
    SR_Grant,
    SR_Request,
    SR_Failure
} SREvent;

static const value_string sr_event_vals[] =
{
    { SR_Grant,        "Grant"},
    { SR_Request,      "SR Request"},
    { SR_Failure,      "SR Failure"},
    { 0,               NULL}
};

typedef enum SRStatus {
    None,
    SR_Outstanding,
    SR_Failed
} SRStatus;

static const value_string sr_status_vals[] =
{
    { None,                "Receiving grants"},
    { SR_Outstanding,      "SR Request outstanding"},
    { SR_Failed,           "SR has Failed"},
    { 0,                   NULL}
};


typedef struct SRState {
    SRStatus status;
    guint32  lastSRFramenum;
    guint32  lastGrantFramenum;
    nstime_t requestTime;
} SRState;


/* This table keeps track of the SR state for each UE.
   (RNTI -> SRState) */
static GHashTable *mac_lte_ue_sr_state = NULL;


typedef enum SRResultType {
    GrantAnsweringSR,
    FailureAnsweringSR,
    SRLeadingToGrant,
    SRLeadingToFailure,
    InvalidSREvent
} SRResultType;


typedef struct SRResult {
    SRResultType type;
    guint32      frameNum;
    guint32      timeDifference;

    /* These 2 are only used with InvalidSREvent */
    SRStatus     status;
    SREvent      event;
} SRResult;

/* Entries in this table are created during the first pass
   It maps (SRFrameNum -> SRResult) */
static GHashTable *mac_lte_sr_request_hash = NULL;


/**************************************************************************/



/* Forward declarations */
void proto_reg_handoff_mac_lte(void);
void dissect_mac_lte(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);

static guint8 get_mac_lte_channel_priority(guint16 ueid _U_, guint8 lcid,
                                           guint8 direction);


/* Heuristic dissection */
static gboolean global_mac_lte_heur = FALSE;

static void call_with_catch_all(dissector_handle_t handle, tvbuff_t* tvb, packet_info *pinfo, proto_tree *tree)
{
    /* Call it (catch exceptions so that stats will be updated) */
    TRY {
        call_dissector_only(handle, tvb, pinfo, tree);
    }
    CATCH_ALL {
    }
    ENDTRY
}

/* Dissect context fields in the format described in packet-mac-lte.h.
   Return TRUE if the necessary information was successfully found */
gboolean dissect_mac_lte_context_fields(struct mac_lte_info  *p_mac_lte_info, tvbuff_t *tvb,
                                        gint *p_offset)
{
    gint    offset = *p_offset;
    guint8  tag = 0;

    /* Read fixed fields */
    p_mac_lte_info->radioType = tvb_get_guint8(tvb, offset++);
    p_mac_lte_info->direction = tvb_get_guint8(tvb, offset++);

    /* TODO: currently no support for detailed PHY info... */
    if (p_mac_lte_info->direction == DIRECTION_UPLINK) {
        p_mac_lte_info->detailed_phy_info.ul_info.present = FALSE;
    }
    else {
        p_mac_lte_info->detailed_phy_info.dl_info.present = FALSE;
    }

    p_mac_lte_info->rntiType = tvb_get_guint8(tvb, offset++);

    /* Initialize RNTI with a default value in case optional field is not present */
    switch (p_mac_lte_info->rntiType) {
        case M_RNTI:
            p_mac_lte_info->rnti = 0xFFFD;
            break;
        case P_RNTI:
            p_mac_lte_info->rnti = 0xFFFE;
            break;
        case SI_RNTI:
            p_mac_lte_info->rnti = 0xFFFF;
            break;
        case RA_RNTI:
        case C_RNTI:
        case SPS_RNTI:
            p_mac_lte_info->rnti = 0x0001;
            break;
        default:
            break;
    }

    /* Read optional fields */
    while (tag != MAC_LTE_PAYLOAD_TAG) {
        /* Process next tag */
        tag = tvb_get_guint8(tvb, offset++);
        switch (tag) {
            case MAC_LTE_RNTI_TAG:
                p_mac_lte_info->rnti = tvb_get_ntohs(tvb, offset);
                offset += 2;
                break;
            case MAC_LTE_UEID_TAG:
                p_mac_lte_info->ueid = tvb_get_ntohs(tvb, offset);
                offset += 2;
                break;
            case MAC_LTE_SUBFRAME_TAG:
                p_mac_lte_info->subframeNumber = tvb_get_ntohs(tvb, offset);
                offset += 2;
                break;
            case MAC_LTE_PREDFINED_DATA_TAG:
                p_mac_lte_info->isPredefinedData = tvb_get_guint8(tvb, offset);
                offset++;
                break;
            case MAC_LTE_RETX_TAG:
                p_mac_lte_info->reTxCount = tvb_get_guint8(tvb, offset);
                offset++;
                break;
            case MAC_LTE_CRC_STATUS_TAG:
                p_mac_lte_info->crcStatusValid = TRUE;
                p_mac_lte_info->detailed_phy_info.dl_info.crc_status = tvb_get_guint8(tvb, offset);
                offset++;
                break;

            case MAC_LTE_PAYLOAD_TAG:
                /* Have reached data, so set payload length and get out of loop */
                p_mac_lte_info->length= tvb_length_remaining(tvb, offset);
                continue;

            default:
                /* It must be a recognised tag */
                return FALSE;
        }
    }

    /* Pass out where offset is now */
    *p_offset = offset;

    return TRUE;
}

/* Heuristic dissector looks for supported framing protocol (see wiki page)  */
static gboolean dissect_mac_lte_heur(tvbuff_t *tvb, packet_info *pinfo,
                                     proto_tree *tree)
{
    gint                 offset = 0;
    struct mac_lte_info  *p_mac_lte_info;
    tvbuff_t             *mac_tvb;
    gboolean             infoAlreadySet = FALSE;

    /* This is a heuristic dissector, which means we get all the UDP
     * traffic not sent to a known dissector and not claimed by
     * a heuristic dissector called before us!
     */

    if (!global_mac_lte_heur) {
        return FALSE;
    }

    /* Do this again on re-dissection to re-discover offset of actual PDU */

    /* Needs to be at least as long as:
       - the signature string
       - fixed header bytes
       - tag for data
       - at least one byte of MAC PDU payload */
    if ((size_t)tvb_length_remaining(tvb, offset) < (strlen(MAC_LTE_START_STRING)+3+2)) {
        return FALSE;
    }

    /* OK, compare with signature string */
    if (tvb_strneql(tvb, offset, MAC_LTE_START_STRING, strlen(MAC_LTE_START_STRING)) != 0) {
        return FALSE;
    }
    offset += (gint)strlen(MAC_LTE_START_STRING);

    /* If redissecting, use previous info struct (if available) */
    p_mac_lte_info = p_get_proto_data(pinfo->fd, proto_mac_lte);
    if (p_mac_lte_info == NULL) {
        /* Allocate new info struct for this frame */
        p_mac_lte_info = se_alloc0(sizeof(struct mac_lte_info));
        infoAlreadySet = FALSE;
    }
    else {
        infoAlreadySet = TRUE;
    }

    /* Dissect the fields to populate p_mac_lte */
    if (!dissect_mac_lte_context_fields(p_mac_lte_info, tvb, &offset)) {
        return FALSE;
    }


    if (!infoAlreadySet) {
        /* Store info in packet */
        p_add_proto_data(pinfo->fd, proto_mac_lte, p_mac_lte_info);
    }

    /**************************************/
    /* OK, now dissect as MAC LTE         */

    /* Create tvb that starts at actual MAC PDU */
    mac_tvb = tvb_new_subset(tvb, offset, -1, tvb_reported_length(tvb)-offset);
    dissect_mac_lte(mac_tvb, pinfo, tree);

    return TRUE;
}


/* Write the given formatted text to:
   - the info column (if pinfo != NULL)
   - 1 or 2 other labels (optional)
*/
static void write_pdu_label_and_info(proto_item *ti1, proto_item *ti2,
                                     packet_info *pinfo, const char *format, ...)
{
    #define MAX_INFO_BUFFER 256
    static char info_buffer[MAX_INFO_BUFFER];

    va_list ap;

    va_start(ap, format);
    g_vsnprintf(info_buffer, MAX_INFO_BUFFER, format, ap);
    va_end(ap);

    /* Add to indicated places */
    if (pinfo != NULL) {
        col_append_str(pinfo->cinfo, COL_INFO, info_buffer);
    }
    if (ti1 != NULL) {
        proto_item_append_text(ti1, "%s", info_buffer);
    }
    if (ti2 != NULL) {
        proto_item_append_text(ti2, "%s", info_buffer);
    }
}

/* Show extra PHY parameters (if present) */
static void show_extra_phy_parameters(packet_info *pinfo, tvbuff_t *tvb, proto_tree *tree,
                                      struct mac_lte_info *p_mac_lte_info)
{
    proto_item *phy_ti;
    proto_tree *phy_tree;
    proto_item *ti;

    if (global_mac_lte_layer_to_show == ShowPHYLayer) {
        /* Clear the info column */
        col_clear(pinfo->cinfo, COL_INFO);
    }

    if (p_mac_lte_info->direction == DIRECTION_UPLINK) {
        if (p_mac_lte_info->detailed_phy_info.ul_info.present) {

            /* Create root */
            phy_ti = proto_tree_add_string_format(tree, hf_mac_lte_context_phy_ul,
                                                  tvb, 0, 0, "", "UL PHY Context");
            phy_tree = proto_item_add_subtree(phy_ti, ett_mac_lte_phy_context);
            PROTO_ITEM_SET_GENERATED(phy_ti);

            /* Add items */
            ti = proto_tree_add_uint(phy_tree, hf_mac_lte_context_phy_ul_modulation_type,
                                     tvb, 0, 0,
                                     p_mac_lte_info->detailed_phy_info.ul_info.modulation_type);
            PROTO_ITEM_SET_GENERATED(ti);

            ti = proto_tree_add_uint(phy_tree, hf_mac_lte_context_phy_ul_tbs_index,
                                     tvb, 0, 0,
                                     p_mac_lte_info->detailed_phy_info.ul_info.tbs_index);
            PROTO_ITEM_SET_GENERATED(ti);

            ti = proto_tree_add_uint(phy_tree, hf_mac_lte_context_phy_ul_resource_block_length,
                                     tvb, 0, 0,
                                     p_mac_lte_info->detailed_phy_info.ul_info.resource_block_length);
            PROTO_ITEM_SET_GENERATED(ti);

            ti = proto_tree_add_uint(phy_tree, hf_mac_lte_context_phy_ul_resource_block_start,
                                     tvb, 0, 0,
                                     p_mac_lte_info->detailed_phy_info.ul_info.resource_block_start);
            PROTO_ITEM_SET_GENERATED(ti);

            ti = proto_tree_add_uint(phy_tree, hf_mac_lte_context_phy_ul_harq_id,
                                     tvb, 0, 0,
                                     p_mac_lte_info->detailed_phy_info.ul_info.harq_id);
            PROTO_ITEM_SET_GENERATED(ti);

            ti = proto_tree_add_uint(phy_tree, hf_mac_lte_context_phy_ul_ndi,
                                     tvb, 0, 0,
                                     p_mac_lte_info->detailed_phy_info.ul_info.ndi);
            PROTO_ITEM_SET_GENERATED(ti);


            proto_item_append_text(phy_ti, " (");

            write_pdu_label_and_info(phy_ti, NULL,
                                     (global_mac_lte_layer_to_show == ShowPHYLayer) ? pinfo : NULL,
                                     "UL: UEId=%u RNTI=%u %s Tbs_Index=%u RB_len=%u RB_start=%u",
                                     p_mac_lte_info->ueid,
                                     p_mac_lte_info->rnti,
                                     val_to_str_const(p_mac_lte_info->detailed_phy_info.ul_info.modulation_type,
                                                      modulation_type_vals, "Unknown"),
                                     p_mac_lte_info->detailed_phy_info.ul_info.tbs_index,
                                     p_mac_lte_info->detailed_phy_info.ul_info.resource_block_length,
                                     p_mac_lte_info->detailed_phy_info.ul_info.resource_block_start);

            proto_item_append_text(phy_ti, ")");

            /* Don't want columns to be replaced now */
            if (global_mac_lte_layer_to_show == ShowPHYLayer) {
                col_set_writable(pinfo->cinfo, FALSE);
            }
        }
    }
    else {
        if (p_mac_lte_info->detailed_phy_info.dl_info.present) {

            /* Create root */
            phy_ti = proto_tree_add_string_format(tree, hf_mac_lte_context_phy_dl,
                                                  tvb, 0, 0, "", "DL PHY Context");
            phy_tree = proto_item_add_subtree(phy_ti, ett_mac_lte_phy_context);
            PROTO_ITEM_SET_GENERATED(phy_ti);

            /* Add items */
            ti = proto_tree_add_uint(phy_tree, hf_mac_lte_context_phy_dl_dci_format,
                                     tvb, 0, 0,
                                     p_mac_lte_info->detailed_phy_info.dl_info.dci_format);
            PROTO_ITEM_SET_GENERATED(ti);

            ti = proto_tree_add_uint(phy_tree, hf_mac_lte_context_phy_dl_resource_allocation_type,
                                     tvb, 0, 0,
                                     p_mac_lte_info->detailed_phy_info.dl_info.resource_allocation_type);
            PROTO_ITEM_SET_GENERATED(ti);

            ti = proto_tree_add_uint(phy_tree, hf_mac_lte_context_phy_dl_aggregation_level,
                                     tvb, 0, 0,
                                     p_mac_lte_info->detailed_phy_info.dl_info.aggregation_level);
            PROTO_ITEM_SET_GENERATED(ti);

            ti = proto_tree_add_uint(phy_tree, hf_mac_lte_context_phy_dl_mcs_index,
                                     tvb, 0, 0,
                                     p_mac_lte_info->detailed_phy_info.dl_info.mcs_index);
            PROTO_ITEM_SET_GENERATED(ti);

            ti = proto_tree_add_uint(phy_tree, hf_mac_lte_context_phy_dl_redundancy_version_index,
                                     tvb, 0, 0,
                                     p_mac_lte_info->detailed_phy_info.dl_info.redundancy_version_index);
            PROTO_ITEM_SET_GENERATED(ti);

            ti = proto_tree_add_boolean(phy_tree, hf_mac_lte_context_phy_dl_retx,
                                        tvb, 0, 0,
                                        p_mac_lte_info->dl_retx);
            PROTO_ITEM_SET_GENERATED(ti);

            ti = proto_tree_add_uint(phy_tree, hf_mac_lte_context_phy_dl_resource_block_length,
                                     tvb, 0, 0,
                                     p_mac_lte_info->detailed_phy_info.dl_info.resource_block_length);
            PROTO_ITEM_SET_GENERATED(ti);

            ti = proto_tree_add_uint(phy_tree, hf_mac_lte_context_phy_dl_crc_status,
                                     tvb, 0, 0,
                                     p_mac_lte_info->detailed_phy_info.dl_info.crc_status);
            PROTO_ITEM_SET_GENERATED(ti);

            ti = proto_tree_add_uint(phy_tree, hf_mac_lte_context_phy_dl_harq_id,
                                     tvb, 0, 0,
                                     p_mac_lte_info->detailed_phy_info.dl_info.harq_id);
            PROTO_ITEM_SET_GENERATED(ti);

            ti = proto_tree_add_uint(phy_tree, hf_mac_lte_context_phy_dl_ndi,
                                     tvb, 0, 0,
                                     p_mac_lte_info->detailed_phy_info.dl_info.ndi);
            PROTO_ITEM_SET_GENERATED(ti);

            ti = proto_tree_add_uint(phy_tree, hf_mac_lte_context_phy_dl_tb,
                                     tvb, 0, 0,
                                     p_mac_lte_info->detailed_phy_info.dl_info.transport_block);
            PROTO_ITEM_SET_GENERATED(ti);


            proto_item_append_text(phy_ti, " (");

            write_pdu_label_and_info(phy_ti, NULL,
                                     (global_mac_lte_layer_to_show == ShowPHYLayer) ? pinfo : NULL,
                                     "DL: UEId=%u RNTI=%u DCI_Format=%s Res_Alloc=%u Aggr_Level=%s MCS=%u RV=%u "
                                     "Res_Block_len=%u CRC_status=%s HARQ_id=%u NDI=%u",
                                     p_mac_lte_info->ueid,
                                     p_mac_lte_info->rnti,
                                     val_to_str_const(p_mac_lte_info->detailed_phy_info.dl_info.dci_format,
                                                      dci_format_vals, "Unknown"),
                                     p_mac_lte_info->detailed_phy_info.dl_info.resource_allocation_type,
                                     val_to_str_const(p_mac_lte_info->detailed_phy_info.dl_info.aggregation_level,
                                                      aggregation_level_vals, "Unknown"),
                                     p_mac_lte_info->detailed_phy_info.dl_info.mcs_index,
                                     p_mac_lte_info->detailed_phy_info.dl_info.redundancy_version_index,
                                     p_mac_lte_info->detailed_phy_info.dl_info.resource_block_length,
                                     val_to_str_const(p_mac_lte_info->detailed_phy_info.dl_info.crc_status,
                                                      crc_status_vals, "Unknown"),
                                     p_mac_lte_info->detailed_phy_info.dl_info.harq_id,
                                     p_mac_lte_info->detailed_phy_info.dl_info.ndi);
            proto_item_append_text(phy_ti, ")");

            /* Don't want columns to be replaced now */
            if (global_mac_lte_layer_to_show == ShowPHYLayer) {
                col_set_writable(pinfo->cinfo, FALSE);
            }
        }
    }
}


/* Dissect a single Random Access Reponse body */
static gint dissect_rar_entry(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
                              proto_item *pdu_ti,
                              gint offset, guint8 rapid)
{
    guint8      reserved;
    guint       start_body_offset = offset;
    proto_item *ti;
    proto_item *rar_body_ti;
    proto_tree *rar_body_tree;
    proto_tree *ul_grant_tree;
    proto_item *ul_grant_ti;
    guint16     timing_advance;
    guint32     ul_grant;
    guint16     temp_crnti;

    /* Create tree for this Body */
    rar_body_ti = proto_tree_add_item(tree,
                                      hf_mac_lte_rar_body,
                                      tvb, offset, 0, ENC_ASCII|ENC_NA);
    rar_body_tree = proto_item_add_subtree(rar_body_ti, ett_mac_lte_rar_body);

    /* Dissect an RAR entry */

    /* Check reserved bit */
    reserved = (tvb_get_guint8(tvb, offset) & 0x80) >> 7;
    ti = proto_tree_add_item(rar_body_tree, hf_mac_lte_rar_reserved2, tvb, offset, 1, ENC_BIG_ENDIAN);
    if (reserved != 0) {
            expert_add_info_format(pinfo, ti, PI_MALFORMED, PI_ERROR,
                      "RAR body Reserved bit not zero (found 0x%x)", reserved);
    }

    /* Timing Advance */
    timing_advance = (tvb_get_ntohs(tvb, offset) & 0x7ff0) >> 4;
    ti = proto_tree_add_item(rar_body_tree, hf_mac_lte_rar_ta, tvb, offset, 2, ENC_BIG_ENDIAN);
    if (timing_advance != 0) {
        expert_add_info_format(pinfo, ti, PI_SEQUENCE, (timing_advance <= 31) ? PI_NOTE : PI_WARN,
                               "RAR Timing advance not zero (%u)", timing_advance);
    }
    offset++;

    /* UL Grant */
    ul_grant = (tvb_get_ntohl(tvb, offset) & 0x0fffff00) >> 8;
    ul_grant_ti = proto_tree_add_item(rar_body_tree, hf_mac_lte_rar_ul_grant, tvb, offset, 3, ENC_BIG_ENDIAN);

    /* Break these 20 bits down as described in 36.213, section 6.2 */
    /* Create subtree for UL grant break-down */
    ul_grant_tree = proto_item_add_subtree(ul_grant_ti, ett_mac_lte_rar_ul_grant);

    /* Hopping flag (1 bit) */
    proto_tree_add_item(ul_grant_tree, hf_mac_lte_rar_ul_grant_hopping,
                        tvb, offset, 1, ENC_BIG_ENDIAN);

    /* Fixed sized resource block assignment (10 bits) */
    proto_tree_add_item(ul_grant_tree, hf_mac_lte_rar_ul_grant_fsrba,
                        tvb, offset, 2, ENC_BIG_ENDIAN);

    /* Truncated Modulation and coding scheme (4 bits) */
    proto_tree_add_item(ul_grant_tree, hf_mac_lte_rar_ul_grant_tmcs,
                        tvb, offset+1, 2, ENC_BIG_ENDIAN);

    /* TPC command for scheduled PUSCH (3 bits) */
    proto_tree_add_item(ul_grant_tree, hf_mac_lte_rar_ul_grant_tcsp,
                        tvb, offset+2, 1, ENC_BIG_ENDIAN);

    /* UL delay (1 bit) */
    proto_tree_add_item(ul_grant_tree, hf_mac_lte_rar_ul_grant_ul_delay,
                        tvb, offset+2, 1, ENC_BIG_ENDIAN);

    /* CQI request (1 bit) */
    proto_tree_add_item(ul_grant_tree, hf_mac_lte_rar_ul_grant_cqi_request,
                        tvb, offset+2, 1, ENC_BIG_ENDIAN);

    offset += 3;

    /* Temporary C-RNTI */
    temp_crnti = tvb_get_ntohs(tvb, offset);
    proto_tree_add_item(rar_body_tree, hf_mac_lte_rar_temporary_crnti, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;

    write_pdu_label_and_info(pdu_ti, rar_body_ti, pinfo,
                             "(RAPID=%u: TA=%u, UL-Grant=%u, Temp C-RNTI=%u) ",
                             rapid, timing_advance, ul_grant, temp_crnti);

    proto_item_set_len(rar_body_ti, offset-start_body_offset);

    return offset;
}


#define MAX_RAR_PDUS 64
/* Dissect Random Access Reponse (RAR) PDU */
static void dissect_rar(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, proto_item *pdu_ti,
                        gint offset, mac_lte_info *p_mac_lte_info, mac_lte_tap_info *tap_info)
{
    gint        number_of_rars         = 0; /* No of RAR bodies expected following headers */
    guint8     *rapids                 = ep_alloc(MAX_RAR_PDUS * sizeof(guint8));
    gboolean    backoff_indicator_seen = FALSE;
    guint8      backoff_indicator      = 0;
    guint8      extension;
    gint        n;
    proto_tree *rar_headers_tree;
    proto_item *ti;
    proto_item *rar_headers_ti;
    proto_item *padding_length_ti;
    int         start_headers_offset   = offset;

    write_pdu_label_and_info(pdu_ti, NULL, pinfo,
                             "RAR (RA-RNTI=%u, SF=%u) ",
                             p_mac_lte_info->rnti, p_mac_lte_info->subframeNumber);

    /* Create hidden 'virtual root' so can filter on mac-lte.rar */
    ti = proto_tree_add_item(tree, hf_mac_lte_rar, tvb, offset, -1, ENC_NA);
    PROTO_ITEM_SET_HIDDEN(ti);

    /* Create headers tree */
    rar_headers_ti = proto_tree_add_item(tree,
                                         hf_mac_lte_rar_headers,
                                         tvb, offset, 0, ENC_ASCII|ENC_NA);
    rar_headers_tree = proto_item_add_subtree(rar_headers_ti, ett_mac_lte_rar_headers);


    /***************************/
    /* Read the header entries */
    do {
        int start_header_offset = offset;
        proto_tree *rar_header_tree;
        proto_item *rar_header_ti;
        guint8 type_value;
        guint8 first_byte = tvb_get_guint8(tvb, offset);

        /* Create tree for this header */
        rar_header_ti = proto_tree_add_item(rar_headers_tree,
                                            hf_mac_lte_rar_header,
                                            tvb, offset, 0, ENC_ASCII|ENC_NA);
        rar_header_tree = proto_item_add_subtree(rar_header_ti, ett_mac_lte_rar_header);

        /* Extension */
        extension = (first_byte & 0x80) >> 7;
        proto_tree_add_item(rar_header_tree, hf_mac_lte_rar_extension, tvb, offset, 1, ENC_BIG_ENDIAN);

        /* Type */
        type_value = (first_byte & 0x40) >> 6;
        proto_tree_add_item(rar_header_tree, hf_mac_lte_rar_t, tvb, offset, 1, ENC_BIG_ENDIAN);

        if (type_value == 0) {
            /* Backoff Indicator (BI) case */

            guint8 reserved;
            proto_item *tii;
            proto_item *bi_ti;

            /* 2 Reserved bits */
            reserved = (tvb_get_guint8(tvb, offset) & 0x30) >> 4;
            tii = proto_tree_add_item(rar_header_tree, hf_mac_lte_rar_reserved, tvb, offset, 1, ENC_BIG_ENDIAN);
            if (reserved != 0) {
                expert_add_info_format(pinfo, tii, PI_MALFORMED, PI_ERROR,
                                       "RAR header Reserved bits not zero (found 0x%x)", reserved);
            }

            /* Backoff Indicator */
            backoff_indicator = tvb_get_guint8(tvb, offset) & 0x0f;
            bi_ti = proto_tree_add_item(rar_header_tree, hf_mac_lte_rar_bi, tvb, offset, 1, ENC_BIG_ENDIAN);

            /* As of March 2009 spec, it must be first, and may only appear once */
            if (backoff_indicator_seen) {
                expert_add_info_format(pinfo, bi_ti, PI_MALFORMED, PI_ERROR,
                                       "MAC RAR PDU has > 1 Backoff Indicator subheader present");
            }
            backoff_indicator_seen = TRUE;

            write_pdu_label_and_info(pdu_ti, rar_header_ti, pinfo,
                                     "(Backoff Indicator=%sms)",
                                     val_to_str_const(backoff_indicator, rar_bi_vals, "Illegal-value "));

            /* If present, it must be the first subheader */
            if (number_of_rars > 0) {
                expert_add_info_format(pinfo, bi_ti, PI_MALFORMED, PI_WARN,
                                       "Backoff Indicator must appear as first subheader");
            }

        }
        else {
            /* RAPID case */
            /* TODO: complain if the same RAPID appears twice in same frame? */
            rapids[number_of_rars] = tvb_get_guint8(tvb, offset) & 0x3f;
            proto_tree_add_item(rar_header_tree, hf_mac_lte_rar_rapid, tvb, offset, 1, ENC_BIG_ENDIAN);

            proto_item_append_text(rar_header_ti, "(RAPID=%u)", rapids[number_of_rars]);

            number_of_rars++;
        }

        offset++;

        /* Finalise length of header tree selection */
        proto_item_set_len(rar_header_ti, offset - start_header_offset);

    } while (extension && number_of_rars < MAX_RAR_PDUS);

    /* Append summary to headers root */
    proto_item_append_text(rar_headers_ti, " (%u RARs", number_of_rars);
    if (backoff_indicator_seen) {
        proto_item_append_text(rar_headers_ti, ", BI=%sms)",
                               val_to_str_const(backoff_indicator, rar_bi_vals, "Illegal-value "));
    }
    else {
        proto_item_append_text(rar_headers_ti, ")");
    }

    /* Set length for headers root */
    proto_item_set_len(rar_headers_ti, offset-start_headers_offset);


    /***************************/
    /* Read any indicated RARs */
    for (n=0; n < number_of_rars; n++) {
        offset = dissect_rar_entry(tvb, pinfo, tree, pdu_ti, offset, rapids[n]);
    }

    /* Update TAP info */
    tap_info->number_of_rars += number_of_rars;

    /* Padding may follow */
    if (tvb_length_remaining(tvb, offset) > 0) {
        proto_tree_add_item(tree, hf_mac_lte_padding_data,
                            tvb, offset, -1, ENC_NA);
    }
    padding_length_ti = proto_tree_add_int(tree, hf_mac_lte_padding_length,
                                           tvb, offset, 0,
                                           p_mac_lte_info->length - offset);
    PROTO_ITEM_SET_GENERATED(padding_length_ti);

    /* Update padding bytes in stats */
    tap_info->padding_bytes += (p_mac_lte_info->length - offset);
}


/* Dissect BCH PDU */
static void dissect_bch(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
                        proto_item *pdu_ti,
                        int offset, mac_lte_info *p_mac_lte_info)
{
    proto_item *ti;

    write_pdu_label_and_info(pdu_ti, NULL, pinfo,
                             "BCH PDU (%u bytes, on %s transport)  ",
                             tvb_length_remaining(tvb, offset),
                             val_to_str_const(p_mac_lte_info->rntiType,
                                              bch_transport_channel_vals,
                                              "Unknown"));

    /* Show which transport layer it came in on (inferred from RNTI type) */
    ti = proto_tree_add_uint(tree, hf_mac_lte_context_bch_transport_channel,
                             tvb, offset, 0, p_mac_lte_info->rntiType);
    PROTO_ITEM_SET_GENERATED(ti);

    /****************************************/
    /* Whole frame is BCH data              */

    /* Raw data */
    ti = proto_tree_add_item(tree, hf_mac_lte_bch_pdu,
                             tvb, offset, -1, ENC_NA);

    if (global_mac_lte_attempt_rrc_decode) {
        /* Attempt to decode payload using LTE RRC dissector */
        tvbuff_t *rrc_tvb = tvb_new_subset(tvb, offset, -1, tvb_length_remaining(tvb, offset));

        /* Get appropriate dissector handle */
        dissector_handle_t protocol_handle = 0;
        if (p_mac_lte_info->rntiType == SI_RNTI) {
            protocol_handle = find_dissector("lte_rrc.bcch_dl_sch");
        }
        else {
            protocol_handle = find_dissector("lte_rrc.bcch_bch");
        }

        /* Hide raw view of bytes */
        PROTO_ITEM_SET_HIDDEN(ti);

        call_with_catch_all(protocol_handle, rrc_tvb, pinfo, tree);
    }

    /* Check that this *is* downlink! */
    if (p_mac_lte_info->direction == DIRECTION_UPLINK) {
        expert_add_info_format(pinfo, ti, PI_MALFORMED, PI_ERROR,
                               "BCH data should not be received in Uplink!");
    }
}


/* Dissect PCH PDU */
static void dissect_pch(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
                        proto_item *pdu_ti, int offset, guint8 direction)
{
    proto_item *ti;

    write_pdu_label_and_info(pdu_ti, NULL, pinfo,
                             "PCH PDU (%u bytes)  ",
                             tvb_length_remaining(tvb, offset));

    /****************************************/
    /* Whole frame is PCH data              */

    /* Always show as raw data */
    ti = proto_tree_add_item(tree, hf_mac_lte_pch_pdu,
                             tvb, offset, -1, ENC_NA);

    if (global_mac_lte_attempt_rrc_decode) {

        /* Attempt to decode payload using LTE RRC dissector */
        tvbuff_t *rrc_tvb = tvb_new_subset(tvb, offset, -1, tvb_length_remaining(tvb, offset));

        /* Get appropriate dissector handle */
        dissector_handle_t protocol_handle = find_dissector("lte-rrc.pcch");

        /* Hide raw view of bytes */
        PROTO_ITEM_SET_HIDDEN(ti);

        /* Call it (catch exceptions so that stats will be updated) */
        TRY {
            call_dissector_only(protocol_handle, rrc_tvb, pinfo, tree);
        }
        CATCH_ALL {
        }
        ENDTRY
    }

    /* Check that this *is* downlink! */
    if (direction == DIRECTION_UPLINK) {
        expert_add_info_format(pinfo, ti, PI_MALFORMED, PI_ERROR,
                               "PCH data should not be received in Uplink!");
    }
}


/* Does this header entry correspond to a fixed-sized control element? */
static int is_fixed_sized_control_element(guint8 lcid, guint8 direction)
{
    if (direction == DIRECTION_UPLINK) {
        /* Uplink */
        switch (lcid) {
            case POWER_HEADROOM_REPORT_LCID:
            case CRNTI_LCID:
            case TRUNCATED_BSR_LCID:
            case SHORT_BSR_LCID:
            case LONG_BSR_LCID:
                return TRUE;

            default:
                return FALSE;
        }
    }
    else {
        /* Assume Downlink */
        switch (lcid) {
            case UE_CONTENTION_RESOLUTION_IDENTITY_LCID:
            case TIMING_ADVANCE_LCID:
            case DRX_COMMAND_LCID:
                return TRUE;

            default:
                return FALSE;
        }
    }
}


/* Is this a BSR report header? */
static int is_bsr_lcid(guint8 lcid)
{
    return ((lcid == TRUNCATED_BSR_LCID) ||
            (lcid == SHORT_BSR_LCID) ||
            (lcid == LONG_BSR_LCID));
}


/* Helper function to call RLC dissector for SDUs (where channel params are known) */
static void call_rlc_dissector(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
                               proto_item *pdu_ti,
                               int offset, guint16 data_length,
                               guint8 mode, guint8 direction, guint16 ueid,
                               guint16 channelType, guint16 channelId,
                               guint8 UMSequenceNumberLength,
                               guint8 priority)
{
    tvbuff_t            *srb_tvb = tvb_new_subset(tvb, offset, data_length, data_length);
    struct rlc_lte_info *p_rlc_lte_info;

    /* Get RLC dissector handle */
    volatile dissector_handle_t protocol_handle = find_dissector("rlc-lte");

    /* Resuse or create RLC info */
    p_rlc_lte_info = p_get_proto_data(pinfo->fd, proto_rlc_lte);
    if (p_rlc_lte_info == NULL) {
        p_rlc_lte_info = se_alloc0(sizeof(struct rlc_lte_info));
    }

    /* Fill in struct details for srb channels */
    p_rlc_lte_info->rlcMode = mode;
    p_rlc_lte_info->direction = direction;
    p_rlc_lte_info->priority = priority;
    p_rlc_lte_info->ueid = ueid;
    p_rlc_lte_info->channelType = channelType;
    p_rlc_lte_info->channelId = channelId;
    p_rlc_lte_info->pduLength = data_length;
    p_rlc_lte_info->UMSequenceNumberLength = UMSequenceNumberLength;

    /* Store info in packet */
    p_add_proto_data(pinfo->fd, proto_rlc_lte, p_rlc_lte_info);

    if (global_mac_lte_layer_to_show != ShowRLCLayer) {
        /* Don't want these columns replaced */
        col_set_writable(pinfo->cinfo, FALSE);
    }
    else {
        /* Clear info column before first RLC PDU */
        if (s_number_of_rlc_pdus_shown == 0) {
            col_clear(pinfo->cinfo, COL_INFO);
        }
        else {
            /* Add a separator and protect column contents here */
            write_pdu_label_and_info(pdu_ti, NULL, pinfo, "   ||   ");
            col_set_fence(pinfo->cinfo, COL_INFO);
        }
    }
    s_number_of_rlc_pdus_shown++;

    /* Call it (catch exceptions so that stats will be updated) */
    TRY {
        call_dissector_only(protocol_handle, srb_tvb, pinfo, tree);
    }
    CATCH_ALL {
    }
    ENDTRY

    /* Let columns be written to again */
    col_set_writable(pinfo->cinfo, TRUE);
}


/* For DL frames, look for previous Tx. Add link back if found */
static void TrackReportedDLHARQResend(packet_info *pinfo, tvbuff_t *tvb, volatile int length,
                                      proto_tree *tree, mac_lte_info *p_mac_lte_info)
{
    DLHARQResult *result = NULL;
    DLHARQResult *original_result = NULL;

    /* If don't have detailed DL PHy info, just give up */
    if (!p_mac_lte_info->detailed_phy_info.dl_info.present) {
        return;
    }

    /* TDD may not work... */

    if (!pinfo->fd->flags.visited) {
        /* First time, so set result and update DL harq table */
        LastFrameData *lastData = NULL;
        LastFrameData *thisData = NULL;

        DLHarqBuffers *ueData;

        /* Read these for convenience */
        guint8 harq_id = p_mac_lte_info->detailed_phy_info.dl_info.harq_id;
        guint8 transport_block = p_mac_lte_info->detailed_phy_info.dl_info.transport_block;

        /* Check harq-id bounds, give up if invalid */
        if ((harq_id >= 15) || (transport_block+1 > 2)) {
            return;
        }

        /* Look up entry for this UE/RNTI */
        ueData = g_hash_table_lookup(mac_lte_dl_harq_hash, GUINT_TO_POINTER((guint)p_mac_lte_info->rnti));

        if (ueData != NULL) {
            /* Get previous info for this harq-id */
            lastData = &(ueData->harqid[transport_block][harq_id]);
            if (lastData->inUse) {
                /* Compare time difference, ndi, data to see if this looks like a retx */
                if ((length == lastData->length) &&
                    (p_mac_lte_info->detailed_phy_info.dl_info.ndi == lastData->ndi) &&
                    tvb_memeql(tvb, 0, lastData->data, MIN(lastData->length, MAX_EXPECTED_PDU_LENGTH)) == 0) {

                    /* Work out gap between frames */
                    gint seconds_between_packets = (gint)
                          (pinfo->fd->abs_ts.secs - lastData->received_time.secs);
                    gint nseconds_between_packets =
                          pinfo->fd->abs_ts.nsecs - lastData->received_time.nsecs;

                    /* Round difference to nearest millisecond */
                    gint total_gap = (seconds_between_packets*1000) +
                                     ((nseconds_between_packets+500000) / 1000000);

                    /* Expect to be within (say) 8-13 subframes since previous */
                    if ((total_gap >= 8) && (total_gap <= 13)) {

                        /* Resend detected! Store result pointing back. */
                        result = se_alloc0(sizeof(DLHARQResult));
                        result->previousSet = TRUE;
                        result->previousFrameNum = lastData->framenum;
                        result->timeSincePreviousFrame = total_gap;
                        g_hash_table_insert(mac_lte_dl_harq_result_hash, GUINT_TO_POINTER(pinfo->fd->num), result);

                        /* Now make previous frame point forward to here */
                        original_result = g_hash_table_lookup(mac_lte_dl_harq_result_hash, GUINT_TO_POINTER(lastData->framenum));
                        if (original_result == NULL) {
                            original_result = se_alloc0(sizeof(ULHARQResult));
                            g_hash_table_insert(mac_lte_dl_harq_result_hash, GUINT_TO_POINTER(lastData->framenum), original_result);
                        }
                        original_result->nextSet = TRUE;
                        original_result->nextFrameNum = pinfo->fd->num;
                        original_result->timeToNextFrame = total_gap;
                    }
                }
            }
        }
        else {
            /* Allocate entry in table for this UE/RNTI */
            ueData = se_alloc0(sizeof(DLHarqBuffers));
            g_hash_table_insert(mac_lte_dl_harq_hash, GUINT_TO_POINTER((guint)p_mac_lte_info->rnti), ueData);
        }

        /* Store this frame's details in table */
        thisData = &(ueData->harqid[transport_block][harq_id]);
        thisData->inUse = TRUE;
        thisData->length = length;
        tvb_memcpy(tvb, thisData->data, 0, MIN(thisData->length, MAX_EXPECTED_PDU_LENGTH));
        thisData->ndi = p_mac_lte_info->detailed_phy_info.dl_info.ndi;
        thisData->framenum = pinfo->fd->num;
        thisData->received_time = pinfo->fd->abs_ts;
    }
    else {
        /* Not first time, so just set whats already stored in result */
        result = g_hash_table_lookup(mac_lte_dl_harq_result_hash, GUINT_TO_POINTER(pinfo->fd->num));
    }


    /***************************************************/
    /* Show link back to original frame (if available) */
    if (result != NULL) {
        if (result->previousSet) {
            proto_item *gap_ti;
            proto_item *original_ti = proto_tree_add_uint(tree, hf_mac_lte_dl_harq_resend_original_frame,
                                                          tvb, 0, 0, result->previousFrameNum);
            PROTO_ITEM_SET_GENERATED(original_ti);

            gap_ti = proto_tree_add_uint(tree, hf_mac_lte_dl_harq_resend_time_since_previous_frame,
                                         tvb, 0, 0, result->timeSincePreviousFrame);
            PROTO_ITEM_SET_GENERATED(gap_ti);
        }

        if (result->nextSet) {
            proto_item *gap_ti;
            proto_item *next_ti = proto_tree_add_uint(tree, hf_mac_lte_dl_harq_resend_next_frame,
                                                      tvb, 0, 0, result->nextFrameNum);
            PROTO_ITEM_SET_GENERATED(next_ti);

            gap_ti = proto_tree_add_uint(tree, hf_mac_lte_dl_harq_resend_time_until_next_frame,
                                         tvb, 0, 0, result->timeToNextFrame);
            PROTO_ITEM_SET_GENERATED(gap_ti);
        }

    }
}


/* Return TRUE if the given packet is thought to be a retx */
int is_mac_lte_frame_retx(packet_info *pinfo, guint8 direction)
{
    struct mac_lte_info *p_mac_lte_info = p_get_proto_data(pinfo->fd, proto_mac_lte);

    if (direction == DIRECTION_UPLINK) {
        /* For UL, retx count is stored in per-packet struct */
        return ((p_mac_lte_info != NULL) && (p_mac_lte_info->reTxCount > 0));
    }
    else {
        /* Use answer if told directly */
        if (p_mac_lte_info->dl_retx == dl_retx_yes) {
            return TRUE;
        }
        else {
            /* Otherwise look up in table */
            DLHARQResult *result = g_hash_table_lookup(mac_lte_dl_harq_result_hash, GUINT_TO_POINTER(pinfo->fd->num));
            return ((result != NULL) && result->previousSet);
        }
    }
}


/* Track UL frames, so that when a retx is indicated, we can search for
   the original tx.  We will either find it, and provide a link back to it,
   or flag that we couldn't find as an expert error */
static void TrackReportedULHARQResend(packet_info *pinfo, tvbuff_t *tvb, volatile int offset,
                                      proto_tree *tree, mac_lte_info *p_mac_lte_info,
                                      proto_item *retx_ti)
{
    ULHARQResult *result = NULL;

    /* If don't have detailed DL PHY info, just give up */
    if (!p_mac_lte_info->detailed_phy_info.ul_info.present) {
        return;
    }

    /* Give up if harqid is out of range */
    if (p_mac_lte_info->detailed_phy_info.ul_info.harq_id >= 8) {
        return;
    }

    if (!pinfo->fd->flags.visited) {
        /* First time, so set result and update UL harq table */
        LastFrameData *lastData = NULL;
        LastFrameData *thisData = NULL;

        /* Look up entry for this UE/RNTI */
        ULHarqBuffers *ueData =
            g_hash_table_lookup(mac_lte_ul_harq_hash, GUINT_TO_POINTER((guint)p_mac_lte_info->rnti));
        if (ueData != NULL) {
            if (p_mac_lte_info->reTxCount >= 1) {
                /* Looking for frame previously on this harq-id */
                lastData = &(ueData->harqid[p_mac_lte_info->detailed_phy_info.ul_info.harq_id]);
                if (lastData->inUse) {
                    /* Compare time, sf, data to see if this looks like a retx */
                    if ((tvb_length_remaining(tvb, offset) == lastData->length) &&
                        (p_mac_lte_info->detailed_phy_info.ul_info.ndi == lastData->ndi) &&
                        tvb_memeql(tvb, offset, lastData->data, MIN(lastData->length, MAX_EXPECTED_PDU_LENGTH)) == 0) {

                        /* Work out gap between frames */
                        gint seconds_between_packets = (gint)
                              (pinfo->fd->abs_ts.secs - lastData->received_time.secs);
                        gint nseconds_between_packets =
                              pinfo->fd->abs_ts.nsecs - lastData->received_time.nsecs;

                        /* Round to nearest ms */
                        gint total_gap = (seconds_between_packets*1000) +
                                         ((nseconds_between_packets+500000) / 1000000);

                        /* Could be as many as max-tx (which we don't know) * 8ms ago.
                           32 is the most I've seen... */
                        if (total_gap <= 33) {
                            ULHARQResult *original_result = NULL;

                            /* Original detected!!! Store result pointing back */
                            result = se_alloc0(sizeof(ULHARQResult));
                            result->previousSet = TRUE;
                            result->previousFrameNum = lastData->framenum;
                            result->timeSincePreviousFrame = total_gap;
                            g_hash_table_insert(mac_lte_ul_harq_result_hash, GUINT_TO_POINTER(pinfo->fd->num), result);

                            /* Now make previous frame point forward to here */
                            original_result = g_hash_table_lookup(mac_lte_ul_harq_result_hash, GUINT_TO_POINTER(lastData->framenum));
                            if (original_result == NULL) {
                                original_result = se_alloc0(sizeof(ULHARQResult));
                                g_hash_table_insert(mac_lte_ul_harq_result_hash, GUINT_TO_POINTER(lastData->framenum), original_result);
                            }
                            original_result->nextSet = TRUE;
                            original_result->nextFrameNum = pinfo->fd->num;
                            original_result->timeToNextFrame = total_gap;
                        }
                    }
                }
            }
        }
        else {
            /* Allocate entry in table for this UE/RNTI */
            ueData = se_alloc0(sizeof(ULHarqBuffers));
            g_hash_table_insert(mac_lte_ul_harq_hash, GUINT_TO_POINTER((guint)p_mac_lte_info->rnti), ueData);
        }

        /* Store this frame's details in table */
        thisData = &(ueData->harqid[p_mac_lte_info->detailed_phy_info.ul_info.harq_id]);
        thisData->inUse = TRUE;
        thisData->length = tvb_length_remaining(tvb, offset);
        tvb_memcpy(tvb, thisData->data, offset, MIN(thisData->length, MAX_EXPECTED_PDU_LENGTH));
        thisData->ndi = p_mac_lte_info->detailed_phy_info.ul_info.ndi;
        thisData->framenum = pinfo->fd->num;
        thisData->received_time = pinfo->fd->abs_ts;
    }
    else {
        /* Not first time, so just get whats already stored in result */
        result = g_hash_table_lookup(mac_lte_ul_harq_result_hash, GUINT_TO_POINTER(pinfo->fd->num));
    }

    /* Show any link back to previous Tx */
    if (retx_ti != NULL) {
        if (result != NULL) {
            if (result->previousSet) {
                proto_item *original_ti, *gap_ti;

                original_ti = proto_tree_add_uint(tree, hf_mac_lte_ul_harq_resend_original_frame,
                                                  tvb, 0, 0, result->previousFrameNum);
                PROTO_ITEM_SET_GENERATED(original_ti);

                gap_ti = proto_tree_add_uint(tree, hf_mac_lte_ul_harq_resend_time_since_previous_frame,
                                             tvb, 0, 0, result->timeSincePreviousFrame);
                PROTO_ITEM_SET_GENERATED(gap_ti);
            }
        }
        else {
            expert_add_info_format(pinfo, retx_ti, PI_SEQUENCE, PI_ERROR,
                                   "Original Tx of UL frame not found (UE %u) !!", p_mac_lte_info->ueid);
        }
    }

    /* Show link forward to any known next Tx */
    if ((result != NULL) && result->nextSet) {
        proto_item *next_ti, *gap_ti;

        next_ti = proto_tree_add_uint(tree, hf_mac_lte_ul_harq_resend_next_frame,
                                          tvb, 0, 0, result->nextFrameNum);
        expert_add_info_format(pinfo, next_ti, PI_SEQUENCE, PI_WARN,
                               "UL MAC PDU (UE %u) needed to be retransmitted", p_mac_lte_info->ueid);

        PROTO_ITEM_SET_GENERATED(next_ti);

        gap_ti = proto_tree_add_uint(tree, hf_mac_lte_ul_harq_resend_time_until_next_frame,
                                     tvb, 0, 0, result->timeToNextFrame);
        PROTO_ITEM_SET_GENERATED(gap_ti);
    }
}


/* Look up SRResult associated with a given frame. Will create one if necessary
   if can_create is set */
static SRResult *GetSRResult(guint32 frameNum, gboolean can_create)
{
    SRResult *result;
    result = g_hash_table_lookup(mac_lte_sr_request_hash, GUINT_TO_POINTER(frameNum));

    if ((result == NULL) && can_create) {
        result = se_alloc0(sizeof(SRResult));
        g_hash_table_insert(mac_lte_sr_request_hash, GUINT_TO_POINTER((guint)frameNum), result);
    }
    return result;
}


/* Keep track of SR requests, failures and related grants, in order to show them
   as generated fields in these frames */
static void TrackSRInfo(SREvent event, packet_info *pinfo, proto_tree *tree,
                        tvbuff_t *tvb, mac_lte_info *p_mac_lte_info, gint idx, proto_item *event_ti)
{
    SRResult   *result           = NULL;
    SRState    *state;
    SRResult   *resultForSRFrame = NULL;

    guint16     rnti;
    guint16     ueid;
    proto_item *ti;

    /* Get appropriate identifiers */
    if (event == SR_Request) {
        rnti = p_mac_lte_info->oob_rnti[idx];
        ueid = p_mac_lte_info->oob_ueid[idx];
    }
    else {
        rnti = p_mac_lte_info->rnti;
        ueid = p_mac_lte_info->ueid;
    }

    /* Create state for this RNTI if necessary */
    state = g_hash_table_lookup(mac_lte_ue_sr_state, GUINT_TO_POINTER((guint)rnti));
    if (state == NULL) {
        /* Allocate status for this RNTI */
        state = se_alloc(sizeof(SRState));
        state->status = None;
        g_hash_table_insert(mac_lte_ue_sr_state, GUINT_TO_POINTER((guint)rnti), state);
    }

    /* First time through - update state with new info */
    if (!pinfo->fd->flags.visited) {
        guint32 timeSinceRequest;

        /* Store time of request */
        if (event == SR_Request) {
            state->requestTime = pinfo->fd->abs_ts;
        }

        switch (state->status) {
            case None:
                switch (event) {
                    case SR_Grant:
                        /* Got another grant - fine */

                        /* update state */
                        state->lastGrantFramenum = pinfo->fd->num;
                        break;

                    case SR_Request:
                        /* Sent an SR - fine */

                        /* Update state */
                        state->status = SR_Outstanding;
                        state->lastSRFramenum = pinfo->fd->num;
                        break;

                    case SR_Failure:
                        /* This is an error, since we hadn't send an SR... */
                        result = GetSRResult(pinfo->fd->num, TRUE);
                        result->type = InvalidSREvent;
                        result->status = None;
                        result->event = SR_Failure;
                        break;
                }
                break;

            case SR_Outstanding:
                timeSinceRequest = (guint32)(((pinfo->fd->abs_ts.secs - state->requestTime.secs) * 1000) +
                                             ((pinfo->fd->abs_ts.nsecs - state->requestTime.nsecs) / 1000000));

                switch (event) {
                    case SR_Grant:
                        /* Got grant we were waiting for, so state goes to None */

                        /* Update state */
                        state->status = None;

                        /* Set result info */
                        result = GetSRResult(pinfo->fd->num, TRUE);
                        result->type = GrantAnsweringSR;
                        result->frameNum = state->lastSRFramenum;
                        result->timeDifference = timeSinceRequest;

                        /* Also set forward link for SR */
                        resultForSRFrame = GetSRResult(state->lastSRFramenum, TRUE);
                        resultForSRFrame->type = SRLeadingToGrant;
                        resultForSRFrame->frameNum = pinfo->fd->num;
                        resultForSRFrame->timeDifference = timeSinceRequest;
                        break;

                    case SR_Request:
                        /* Another request when already have one pending */
                        result = GetSRResult(pinfo->fd->num, TRUE);
                        result->type = InvalidSREvent;
                        result->status = SR_Outstanding;
                        result->event = SR_Request;
                        break;

                    case SR_Failure:
                        /* We sent an SR but it failed */

                        /* Update state */
                        state->status = SR_Failed;

                        /* Set result info for failure frame */
                        result = GetSRResult(pinfo->fd->num, TRUE);
                        result->type = FailureAnsweringSR;
                        result->frameNum = state->lastSRFramenum;
                        result->timeDifference = timeSinceRequest;

                        /* Also set forward link for SR */
                        resultForSRFrame = GetSRResult(state->lastSRFramenum, TRUE);
                        resultForSRFrame->type = SRLeadingToFailure;
                        resultForSRFrame->frameNum = pinfo->fd->num;
                        resultForSRFrame->timeDifference = timeSinceRequest;
                        break;
                }
                break;

            case SR_Failed:
                switch (event) {
                    case SR_Grant:
                        /* Got a grant, presumably after a subsequent RACH - fine */

                        /* Update state */
                        state->status = None;
                        break;

                    case SR_Request:
                        /* Tried another SR after previous one failed.
                           Presumably a subsequent RACH was tried in-between... */

                        state->status = SR_Outstanding;

                        result = GetSRResult(pinfo->fd->num, TRUE);
                        result->status = SR_Outstanding;
                        result->event = SR_Request;
                        break;

                    case SR_Failure:
                        /* 2 failures in a row.... */
                        result = GetSRResult(pinfo->fd->num, TRUE);
                        result->type = InvalidSREvent;
                        result->status = SR_Failed;
                        result->event = SR_Failure;
                        break;
                }
                break;
        }
    }

    /* Get stored result for this frame */
    result = GetSRResult(pinfo->fd->num, FALSE);
    if (result == NULL) {
        /* For an SR frame, there should always be either a PDCCH grant or indication
           that the SR has failed */
        if (event == SR_Request) {
            expert_add_info_format(pinfo, event_ti, PI_SEQUENCE, PI_ERROR,
                                   "UE %u: SR results in neither a grant nor a failure indication",
                                   ueid);
        }
        return;
    }


    /* Show result info */
    switch (result->type) {
        case GrantAnsweringSR:
            ti = proto_tree_add_uint(tree, hf_mac_lte_grant_answering_sr,
                                     tvb, 0, 0, result->frameNum);
            PROTO_ITEM_SET_GENERATED(ti);
            ti = proto_tree_add_uint(tree, hf_mac_lte_sr_time_since_request,
                                     tvb, 0, 0, result->timeDifference);
            PROTO_ITEM_SET_GENERATED(ti);
            break;

        case FailureAnsweringSR:
            ti = proto_tree_add_uint(tree, hf_mac_lte_failure_answering_sr,
                                     tvb, 0, 0, result->frameNum);
            PROTO_ITEM_SET_GENERATED(ti);
            ti = proto_tree_add_uint(tree, hf_mac_lte_sr_time_since_request,
                                     tvb, 0, 0, result->timeDifference);
            PROTO_ITEM_SET_GENERATED(ti);
            break;

        case SRLeadingToGrant:
            ti = proto_tree_add_uint(tree, hf_mac_lte_sr_leading_to_grant,
                                     tvb, 0, 0, result->frameNum);
            PROTO_ITEM_SET_GENERATED(ti);
            ti = proto_tree_add_uint(tree, hf_mac_lte_sr_time_until_answer,
                                     tvb, 0, 0, result->timeDifference);
            PROTO_ITEM_SET_GENERATED(ti);

            break;

        case SRLeadingToFailure:
            ti = proto_tree_add_uint(tree, hf_mac_lte_sr_leading_to_failure,
                                     tvb, 0, 0, result->frameNum);
            PROTO_ITEM_SET_GENERATED(ti);
            ti = proto_tree_add_uint(tree, hf_mac_lte_sr_time_until_answer,
                                     tvb, 0, 0, result->timeDifference);
            PROTO_ITEM_SET_GENERATED(ti);
            break;

        case InvalidSREvent:
            ti = proto_tree_add_none_format(tree, hf_mac_lte_sr_invalid_event,
                                            tvb, 0, 0, "UE %u: Invalid SR event - state=%s, event=%s",
                                            ueid,
                                            val_to_str_const(result->status, sr_status_vals, "Unknown"),
                                            val_to_str_const(result->event,  sr_event_vals,  "Unknown"));
            PROTO_ITEM_SET_GENERATED(ti);
            expert_add_info_format(pinfo, ti, PI_SEQUENCE, PI_ERROR,
                                   "Invalid SR event for UE %u (C-RNTI %u) - state=%s, event=%s",
                                   ueid, rnti,
                                   val_to_str_const(result->status, sr_status_vals, "Unknown"),
                                   val_to_str_const(result->event,  sr_event_vals,  "Unknown"));
            break;
    }
}


/********************************************************/
/* Count number of UEs/TTI (in both directions)         */
/********************************************************/

/* For keeping track during first pass */
typedef struct tti_info_t {
    guint16 subframe;
    nstime_t ttiStartTime;
    guint ues_in_tti;
} tti_info_t;

static tti_info_t UL_tti_info;
static tti_info_t DL_tti_info;

/* For associating with frame and displaying */
typedef struct TTIInfoResult_t {
    guint ues_in_tti;
} TTIInfoResult_t;

/* This table stores (FrameNumber -> *TTIInfoResult_t).  It is assigned during the first
   pass and used thereafter */
static GHashTable *mac_lte_tti_info_result_hash = NULL;


/* Work out which UE this is within TTI (within direction). Return answer */
static guint16 count_ues_tti(mac_lte_info *p_mac_lte_info, packet_info *pinfo)
{
    gboolean same_tti = FALSE;
    tti_info_t *tti_info;

    /* Just return any previous result */
    TTIInfoResult_t *result = g_hash_table_lookup(mac_lte_tti_info_result_hash, GUINT_TO_POINTER(pinfo->fd->num));
    if (result != NULL) {
        return result->ues_in_tti;
    }

    /* Set tti_info based upon direction */
    if (p_mac_lte_info->direction == DIRECTION_UPLINK) {
        tti_info = &UL_tti_info;
    }
    else {
        tti_info = &DL_tti_info;
    }

    /* Work out if we are still in the same tti as before */
    if (tti_info->subframe == p_mac_lte_info->subframeNumber) {
        gint seconds_between_packets = (gint)
              (pinfo->fd->abs_ts.secs - tti_info->ttiStartTime.secs);
        gint nseconds_between_packets =
              pinfo->fd->abs_ts.nsecs -  tti_info->ttiStartTime.nsecs;

        /* Round difference to nearest microsecond */
        gint total_us_gap = (seconds_between_packets*1000000) +
                           ((nseconds_between_packets+500) / 1000);

        if (total_us_gap < 1000) {
            same_tti = TRUE;
        }
    }

    /* Update global state */
    if (!same_tti) {
        tti_info->subframe = p_mac_lte_info->subframeNumber;
        tti_info->ttiStartTime = pinfo->fd->abs_ts;
        tti_info->ues_in_tti = 1;
    }
    else {
        tti_info->ues_in_tti++;
    }

    /* Set result state for this frame */
    result = se_alloc(sizeof(TTIInfoResult_t));
    result->ues_in_tti = tti_info->ues_in_tti;
    g_hash_table_insert(mac_lte_tti_info_result_hash,
                        GUINT_TO_POINTER(pinfo->fd->num), result);

    return tti_info->ues_in_tti;
}


/* Show which UE this is (within direction) for this TTI */
static void show_ues_tti(packet_info *pinfo, mac_lte_info *p_mac_lte_info, tvbuff_t *tvb, proto_tree *context_tree)
{
    /* Look up result */
    TTIInfoResult_t *result = g_hash_table_lookup(mac_lte_tti_info_result_hash, GUINT_TO_POINTER(pinfo->fd->num));
    if (result != NULL) {
        proto_item *ti =  proto_tree_add_uint(context_tree,
                                              (p_mac_lte_info->direction == DIRECTION_UPLINK) ?
                                                  hf_mac_lte_ues_ul_per_tti :
                                                  hf_mac_lte_ues_dl_per_tti,
                                              tvb, 0, 0, result->ues_in_tti);
        PROTO_ITEM_SET_GENERATED(ti);
    }
}



/* Lookup channel details for lcid */
static void lookup_rlc_channel_from_lcid(guint8 lcid,
                                         rlc_channel_type_t *rlc_channel_type,
                                         guint8 *UM_seqnum_length,
                                         gint *drb_id)
{
    /* Zero params (in case no match is found) */
    *rlc_channel_type = rlcRaw;
    *UM_seqnum_length = 0;
    *drb_id           = 0;

    if (global_mac_lte_lcid_drb_source == (int)FromStaticTable) {

        /* Look up in static (UAT) table */
        guint m;
        for (m=0; m < num_lcid_drb_mappings; m++) {
            if (lcid == lcid_drb_mappings[m].lcid) {

                *rlc_channel_type = lcid_drb_mappings[m].channel_type;

                /* Set UM_seqnum_length */
                switch (*rlc_channel_type) {
                    case rlcUM5:
                        *UM_seqnum_length = 5;
                        break;
                    case rlcUM10:
                        *UM_seqnum_length = 10;
                        break;
                    default:
                        break;
                }

                /* Set drb_id */
                *drb_id = lcid_drb_mappings[m].drbid;
                break;
            }
        }
    }
    else {
        /* Look up setting gleaned from configuration protocol */
        if (!dynamic_lcid_drb_mapping[lcid].valid) {
            return;
        }

        *rlc_channel_type = dynamic_lcid_drb_mapping[lcid].channel_type;

        /* Set UM_seqnum_length */
        switch (*rlc_channel_type) {
            case rlcUM5:
                *UM_seqnum_length = 5;
                break;
            case rlcUM10:
                *UM_seqnum_length = 10;
                break;
            default:
                break;
        }

        /* Set drb_id */
        *drb_id = dynamic_lcid_drb_mapping[lcid].drbid;
    }
}



#define MAX_HEADERS_IN_PDU 1024

/* UL-SCH and DL-SCH formats have much in common, so handle them in a common
   function */
static void dissect_ulsch_or_dlsch(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
                                   proto_item *pdu_ti,
                                   volatile guint32 offset, guint8 direction,
                                   mac_lte_info *p_mac_lte_info, mac_lte_tap_info *tap_info,
                                   proto_item *retx_ti,
                                   proto_tree *context_tree)
{
    guint8            extension;
    volatile guint16  n;
    proto_item       *truncated_ti;
    proto_item       *padding_length_ti;
    proto_item       *hidden_root_ti;

    /* Keep track of LCIDs and lengths as we dissect the header */
    volatile guint16 number_of_headers = 0;
    guint8           lcids[MAX_HEADERS_IN_PDU];
    gint16           pdu_lengths[MAX_HEADERS_IN_PDU];

    proto_item *pdu_header_ti;
    proto_tree *pdu_header_tree;

    gboolean   have_seen_data_header = FALSE;
    guint8     number_of_padding_subheaders = 0;
    gboolean   have_seen_non_padding_control = FALSE;
    gboolean   have_seen_bsr = FALSE;
    gboolean   expecting_body_data = FALSE;
    volatile   guint32    is_truncated = FALSE;

    /* Maintain/show UEs/TTI count */
    tap_info->ueInTTI = count_ues_tti(p_mac_lte_info, pinfo);
    show_ues_tti(pinfo, p_mac_lte_info, tvb, context_tree);

    write_pdu_label_and_info(pdu_ti, NULL, pinfo,
                             "%s: (SF=%u) UEId=%-3u ",
                             (direction == DIRECTION_UPLINK) ? "UL-SCH" : "DL-SCH",
                             p_mac_lte_info->subframeNumber,
                             p_mac_lte_info->ueid);

    tap_info->raw_length = p_mac_lte_info->length;

    /* For uplink frames, if this is logged as a resend, look for original tx */
    if (direction == DIRECTION_UPLINK) {
        TrackReportedULHARQResend(pinfo, tvb, offset, tree, p_mac_lte_info, retx_ti);
    }

    /* For uplink grants, update SR status.  N.B. only newTx grant should stop SR */
    if ((direction == DIRECTION_UPLINK) && (p_mac_lte_info->reTxCount == 0) &&
        global_mac_lte_track_sr) {

        TrackSRInfo(SR_Grant, pinfo, tree, tvb, p_mac_lte_info, 0, NULL);
    }

    /* Add hidden item to filter on */
    hidden_root_ti = proto_tree_add_string_format(tree,
                                                 (direction == DIRECTION_UPLINK) ?
                                                    hf_mac_lte_ulsch :
                                                    hf_mac_lte_dlsch,
                                                 tvb, offset, 0,
                                                 "",
                                                 "Hidden header");
    PROTO_ITEM_SET_HIDDEN(hidden_root_ti);

    /* Add PDU block header subtree */
    pdu_header_ti = proto_tree_add_string_format(tree,
                                                 (direction == DIRECTION_UPLINK) ?
                                                    hf_mac_lte_ulsch_header :
                                                    hf_mac_lte_dlsch_header,
                                                 tvb, offset, 0,
                                                 "",
                                                 "MAC PDU Header");
    pdu_header_tree = proto_item_add_subtree(pdu_header_ti,
                                             (direction == DIRECTION_UPLINK) ?
                                                    ett_mac_lte_ulsch_header :
                                                    ett_mac_lte_dlsch_header);


    /************************************************************************/
    /* Dissect each sub-header.                                             */
    do {
        guint8 reserved;
        guint64 length = 0;
        proto_item *pdu_subheader_ti;
        proto_tree *pdu_subheader_tree;
        proto_item *lcid_ti;
        proto_item *ti;
        gint       offset_start_subheader = offset;
        guint8 first_byte = tvb_get_guint8(tvb, offset);

        /* Add PDU block header subtree.
           Default with length of 1 byte. */
        pdu_subheader_ti = proto_tree_add_string_format(pdu_header_tree,
                                                        hf_mac_lte_sch_subheader,
                                                        tvb, offset, 1,
                                                        "",
                                                        "Sub-header");
        pdu_subheader_tree = proto_item_add_subtree(pdu_subheader_ti,
                                                    ett_mac_lte_sch_subheader);

        /* Check 1st 2 reserved bits */
        reserved = (first_byte & 0xc0) >> 6;
        ti = proto_tree_add_item(pdu_subheader_tree, hf_mac_lte_sch_reserved,
                                 tvb, offset, 1, ENC_BIG_ENDIAN);
        if (reserved != 0) {
            expert_add_info_format(pinfo, ti, PI_MALFORMED, PI_ERROR,
                                   "%cL-SCH header Reserved bits not zero",
                                   (p_mac_lte_info->direction == DIRECTION_UPLINK) ? 'U' : 'D');
        }

        /* Extended bit */
        extension = (first_byte & 0x20) >> 5;
        proto_tree_add_item(pdu_subheader_tree, hf_mac_lte_sch_extended,
                            tvb, offset, 1, ENC_BIG_ENDIAN);

        /* LCID.  Has different meaning depending upon direction. */
        lcids[number_of_headers] = first_byte & 0x1f;
        if (direction == DIRECTION_UPLINK) {

            lcid_ti = proto_tree_add_item(pdu_subheader_tree, hf_mac_lte_ulsch_lcid,
                                          tvb, offset, 1, ENC_BIG_ENDIAN);
            write_pdu_label_and_info(pdu_ti, NULL, pinfo,
                                     "(%s",
                                     val_to_str_const(lcids[number_of_headers],
                                                      ulsch_lcid_vals, "(Unknown LCID)"));
        }
        else {
            /* Downlink */
            lcid_ti = proto_tree_add_item(pdu_subheader_tree, hf_mac_lte_dlsch_lcid,
                                          tvb, offset, 1, ENC_BIG_ENDIAN);
            write_pdu_label_and_info(pdu_ti, NULL, pinfo,
                                     "(%s",
                                     val_to_str_const(lcids[number_of_headers],
                                                      dlsch_lcid_vals, "(Unknown LCID)"));

            if (lcids[number_of_headers] == DRX_COMMAND_LCID) {
                expert_add_info_format(pinfo, lcid_ti, PI_SEQUENCE, PI_NOTE,
                                       "DRX command received for UE %u (RNTI %u)",
                                       p_mac_lte_info->ueid, p_mac_lte_info->rnti);
            }
        }
        offset++;

        /* Remember if we've seen a data subheader */
        if (lcids[number_of_headers] <= 10) {
            have_seen_data_header = TRUE;
            expecting_body_data = TRUE;
        }

        /* Show an expert item if a contol subheader (except Padding) appears
           *after* a data PDU */
        if (have_seen_data_header &&
            (lcids[number_of_headers] > 10) && (lcids[number_of_headers] != PADDING_LCID)) {
            expert_add_info_format(pinfo, lcid_ti, PI_MALFORMED, PI_ERROR,
                                   "%cL-SCH Control subheaders should not appear after data subheaders",
                                   (p_mac_lte_info->direction == DIRECTION_UPLINK) ? 'U' : 'D');
            return;
        }

        /* Show an expert item if we're seeing more then one BSR in a frame */
        if ((direction == DIRECTION_UPLINK) && is_bsr_lcid(lcids[number_of_headers])) {
            if (have_seen_bsr) {
                expert_add_info_format(pinfo, lcid_ti, PI_MALFORMED, PI_ERROR,
                                       "There shouldn't be > 1 BSR in a frame");
                return;
            }
            have_seen_bsr = TRUE;
        }

        /* Should not see padding after non-padding control... */
        if ((lcids[number_of_headers] > 10) &&
            (lcids[number_of_headers] == PADDING_LCID) &&
            extension)
        {
            number_of_padding_subheaders++;
            if (number_of_padding_subheaders > 2) {
                expert_add_info_format(pinfo, lcid_ti, PI_MALFORMED, PI_WARN,
                                       "Should not see more than 2 padding subheaders in one frame");
            }

            if (have_seen_non_padding_control) {
                expert_add_info_format(pinfo, lcid_ti, PI_MALFORMED, PI_ERROR,
                                       "Padding should come before other control subheaders!");
            }
        }

        /* Remember that we've seen non-padding control */
        if ((lcids[number_of_headers] > 10) &&
            (lcids[number_of_headers] != PADDING_LCID)) {
            have_seen_non_padding_control = TRUE;
        }



        /********************************************************************/
        /* Length field follows if not the last header or for a fixed-sized
           control element */
        if (!extension) {
            /* Last one... */
            if (is_fixed_sized_control_element(lcids[number_of_headers], direction)) {
                pdu_lengths[number_of_headers] = 0;
            }
            else {
                pdu_lengths[number_of_headers] = -1;
            }
        }
        else {
            /* Not the last one */
            if (!is_fixed_sized_control_element(lcids[number_of_headers], direction) &&
                (lcids[number_of_headers] != PADDING_LCID)) {

                guint8  format;

                /* F(ormat) bit tells us how long the length field is */
                format = (tvb_get_guint8(tvb, offset) & 0x80) >> 7;
                proto_tree_add_item(pdu_subheader_tree, hf_mac_lte_sch_format,
                                    tvb, offset, 1, ENC_BIG_ENDIAN);

                /* Now read length field itself */
                if (format) {
                    /* >= 128 - use 15 bits */
                    proto_tree_add_bits_ret_val(pdu_subheader_tree, hf_mac_lte_sch_length,
                                                tvb, offset*8 + 1, 15, &length, ENC_BIG_ENDIAN);

                    offset += 2;
                }
                else {
                    /* Less than 128 - only 7 bits */
                    proto_tree_add_bits_ret_val(pdu_subheader_tree, hf_mac_lte_sch_length,
                                                tvb, offset*8 + 1, 7, &length, ENC_BIG_ENDIAN);
                    offset++;
                }
                pdu_lengths[number_of_headers] = (gint16)length;
            }
            else {
                pdu_lengths[number_of_headers] = 0;
            }
        }


        /* Close off description in info column */
        switch (pdu_lengths[number_of_headers]) {
            case 0:
                write_pdu_label_and_info(pdu_ti, NULL, pinfo, ") ");
                break;
            case -1:
                write_pdu_label_and_info(pdu_ti, NULL, pinfo, ":remainder) ");
                break;
            default:
                write_pdu_label_and_info(pdu_ti, NULL, pinfo, ":%u bytes) ",
                                         pdu_lengths[number_of_headers]);
                break;
        }

        /* Append summary to subheader root */
        proto_item_append_text(pdu_subheader_ti, " (lcid=%s",
                               val_to_str_const(lcids[number_of_headers],
                                                (direction == DIRECTION_UPLINK) ?
                                                    ulsch_lcid_vals :
                                                        dlsch_lcid_vals,
                                                "Unknown"));

        switch (pdu_lengths[number_of_headers]) {
            case -1:
                proto_item_append_text(pdu_subheader_ti, ", length is remainder)");
                proto_item_append_text(pdu_header_ti, " (%s:remainder)",
                                       val_to_str_const(lcids[number_of_headers],
                                                        (direction == DIRECTION_UPLINK) ? ulsch_lcid_vals : dlsch_lcid_vals,
                                                        "Unknown"));
                break;
            case 0:
                proto_item_append_text(pdu_subheader_ti, ")");
                proto_item_append_text(pdu_header_ti, " (%s)",
                                       val_to_str_const(lcids[number_of_headers],
                                                        (direction == DIRECTION_UPLINK) ? ulsch_lcid_vals : dlsch_lcid_vals,
                                                        "Unknown"));
                break;
            default:
                proto_item_append_text(pdu_subheader_ti, ", length=%u)",
                                       pdu_lengths[number_of_headers]);
                proto_item_append_text(pdu_header_ti, " (%s:%u)",
                                       val_to_str_const(lcids[number_of_headers],
                                                        (direction == DIRECTION_UPLINK) ? ulsch_lcid_vals : dlsch_lcid_vals,
                                                        "Unknown"),
                                       pdu_lengths[number_of_headers]);
                break;
        }


        /* Flag unknown lcid values in expert info */
        if (match_strval(lcids[number_of_headers],
                         (direction == DIRECTION_UPLINK) ? ulsch_lcid_vals : dlsch_lcid_vals) == NULL) {
            expert_add_info_format(pinfo, pdu_subheader_ti, PI_MALFORMED, PI_ERROR,
                                   "%cL-SCH: Unexpected LCID received (%u)",
                                   (p_mac_lte_info->direction == DIRECTION_UPLINK) ? 'U' : 'D',
                                   lcids[number_of_headers]);
        }

        /* Set length of this subheader */
        proto_item_set_len(pdu_subheader_ti, offset - offset_start_subheader);

        number_of_headers++;
    } while ((number_of_headers < MAX_HEADERS_IN_PDU) && extension);

    /* Check that we didn't reach the end of the subheader array... */
    if (number_of_headers >= MAX_HEADERS_IN_PDU) {
        proto_item *ti = proto_tree_add_text(tree, tvb, offset, 1,
                                             "Reached %u subheaders - frame obviously malformed",
                                             MAX_HEADERS_IN_PDU);
        expert_add_info_format(pinfo, ti, PI_MALFORMED, PI_ERROR,
                               "Reached %u subheaders - frame obviously malformed",
                               MAX_HEADERS_IN_PDU);
        return;
    }


    /* Append summary to overall PDU header root */
    proto_item_append_text(pdu_header_ti, "  [%u subheaders]",
                           number_of_headers);

    /* And set its length to offset */
    proto_item_set_len(pdu_header_ti, offset);


    /* For DL, see if this is a retx.  Use whole PDU present (i.e. ignore padding if not logged) */
    if (direction == DIRECTION_DOWNLINK) {
        /* Result will be added to context tree */
        TrackReportedDLHARQResend(pinfo, tvb, tvb_length_remaining(tvb, 0), context_tree, p_mac_lte_info);

        tap_info->isPHYRetx = (p_mac_lte_info->dl_retx == dl_retx_yes);
    }


    /************************************************************************/
    /* Dissect SDUs / control elements / padding.                           */
    /************************************************************************/

    /* Dissect control element bodies first */

    for (n=0; n < number_of_headers; n++) {
        /* Get out of loop once see any data SDU subheaders */
        if (lcids[n] <= 10) {
            break;
        }

        /* Process what should be a valid control PDU type */
        if (direction == DIRECTION_DOWNLINK) {

            /****************************/
            /* DL-SCH Control PDUs      */
            switch (lcids[n]) {
                case UE_CONTENTION_RESOLUTION_IDENTITY_LCID:
                    {
                        proto_item *cr_ti;
                        proto_tree *cr_tree;
                        proto_item *ti;
                        ContentionResolutionResult *crResult;

                        /* Create CR root */
                        cr_ti = proto_tree_add_string_format(tree,
                                                             hf_mac_lte_control_ue_contention_resolution,
                                                             tvb, offset, 6,
                                                             "",
                                                             "Contention Resolution");
                        cr_tree = proto_item_add_subtree(cr_ti, ett_mac_lte_contention_resolution);


                        proto_tree_add_item(cr_tree, hf_mac_lte_control_ue_contention_resolution_identity,
                                            tvb, offset, 6, ENC_NA);

                        /* Get pointer to result struct for this frame */
                        crResult =  g_hash_table_lookup(mac_lte_cr_result_hash, GUINT_TO_POINTER(pinfo->fd->num));
                        if (crResult == NULL) {

                            /* Need to set result by looking for and comparing with Msg3 */
                            Msg3Data *msg3Data;
                            guint msg3Key = p_mac_lte_info->rnti;

                            /* Allocate result and add it to the table */
                            crResult = se_alloc(sizeof(ContentionResolutionResult));
                            g_hash_table_insert(mac_lte_cr_result_hash, GUINT_TO_POINTER(pinfo->fd->num), crResult);

                            /* Look for Msg3 */
                            msg3Data = g_hash_table_lookup(mac_lte_msg3_hash, GUINT_TO_POINTER(msg3Key));

                            /* Compare CCCH bytes */
                            if (msg3Data != NULL) {
                                crResult->msSinceMsg3 = (guint32)(((pinfo->fd->abs_ts.secs - msg3Data->msg3Time.secs) * 1000) +
                                                                  ((pinfo->fd->abs_ts.nsecs - msg3Data->msg3Time.nsecs) / 1000000));
                                crResult->msg3FrameNum = msg3Data->framenum;

                                /* Compare the 6 bytes */
                                if (tvb_memeql(tvb, offset, msg3Data->data, 6) == 0) {
                                    crResult->status = Msg3Match;
                                }
                                else {
                                    crResult->status = Msg3NoMatch;
                                }
                            }
                            else {
                                crResult->status = NoMsg3;
                            }
                        }

                        /* Now show CR result in tree */
                        switch (crResult->status) {
                            case NoMsg3:
                                proto_item_append_text(cr_ti, " (no corresponding Msg3 found!)");
                                break;

                            case Msg3Match:
                                ti = proto_tree_add_uint(cr_tree, hf_mac_lte_control_ue_contention_resolution_msg3,
                                                         tvb, 0, 0, crResult->msg3FrameNum);
                                PROTO_ITEM_SET_GENERATED(ti);
                                ti = proto_tree_add_uint(cr_tree, hf_mac_lte_control_ue_contention_resolution_time_since_msg3,
                                                         tvb, 0, 0, crResult->msSinceMsg3);
                                PROTO_ITEM_SET_GENERATED(ti);

                                ti = proto_tree_add_boolean(cr_tree, hf_mac_lte_control_ue_contention_resolution_msg3_matched,
                                                            tvb, 0, 0, TRUE);
                                PROTO_ITEM_SET_GENERATED(ti);
                                proto_item_append_text(cr_ti, " (matches Msg3 from frame %u, %ums ago)",
                                                       crResult->msg3FrameNum, crResult->msSinceMsg3);
                                break;

                            case Msg3NoMatch:
                                ti = proto_tree_add_uint(cr_tree, hf_mac_lte_control_ue_contention_resolution_msg3,
                                                         tvb, 0, 0, crResult->msg3FrameNum);
                                PROTO_ITEM_SET_GENERATED(ti);
                                ti = proto_tree_add_uint(cr_tree, hf_mac_lte_control_ue_contention_resolution_time_since_msg3,
                                                         tvb, 0, 0, crResult->msSinceMsg3);
                                PROTO_ITEM_SET_GENERATED(ti);

                                ti = proto_tree_add_boolean(cr_tree, hf_mac_lte_control_ue_contention_resolution_msg3_matched,
                                                             tvb, 0, 0, FALSE);
                                expert_add_info_format(pinfo, ti, PI_SEQUENCE, PI_WARN,
                                                       "CR body in Msg4 doesn't match Msg3 CCCH in frame %u",
                                                       crResult->msg3FrameNum);
                                PROTO_ITEM_SET_GENERATED(ti);
                                proto_item_append_text(cr_ti, " (doesn't match Msg3 from frame %u, %u ago)",
                                                       crResult->msg3FrameNum, crResult->msSinceMsg3);
                                break;
                        };

                        offset += 6;
                    }
                    break;
                case TIMING_ADVANCE_LCID:
                    {
                        proto_item *ta_ti;
                        proto_item *reserved_ti;
                        guint8      reserved;
                        guint8      ta_value;

                        /* Check 2 reserved bits */
                        reserved = (tvb_get_guint8(tvb, offset) & 0xc0) >> 6;
                        reserved_ti = proto_tree_add_item(tree, hf_mac_lte_control_timing_advance_reserved, tvb, offset, 1, ENC_BIG_ENDIAN);
                        if (reserved != 0) {
                            expert_add_info_format(pinfo, reserved_ti, PI_MALFORMED, PI_ERROR,
                                                   "Timing Advance Reserved bits not zero (found 0x%x)", reserved);
                        }

                        /* TA value */
                        ta_value = tvb_get_guint8(tvb, offset) & 0x3f;
                        ta_ti = proto_tree_add_item(tree, hf_mac_lte_control_timing_advance,
                                                    tvb, offset, 1, ENC_BIG_ENDIAN);

                        if (ta_value == 31) {
                            expert_add_info_format(pinfo, ta_ti, PI_SEQUENCE,
                                                   PI_NOTE,
                                                   "Timing Advance control element received (no correction needed)");
                        }
                        else {
                            expert_add_info_format(pinfo, ta_ti, PI_SEQUENCE,
                                                   PI_WARN,
                                                   "Timing Advance control element received (%u) %s correction needed",
                                                   ta_value,
                                                   (ta_value < 31) ? "-ve" : "+ve");
                        }
                        offset++;
                    }
                    break;
                case DRX_COMMAND_LCID:
                    /* No payload */
                    break;
                case PADDING_LCID:
                    /* No payload (in this position) */
                    tap_info->padding_bytes++;
                    break;

                default:
                    break;
            }
        }
        else {

            /**********************************/
            /* UL-SCH Control PDUs            */
            switch (lcids[n]) {
                case POWER_HEADROOM_REPORT_LCID:
                    {
                        proto_item *phr_ti;
                        proto_tree *phr_tree;
                        proto_item *ti;
                        guint8 reserved;
                        guint8 level;

                        /* Create PHR root */
                        phr_ti = proto_tree_add_string_format(tree,
                                                              hf_mac_lte_control_power_headroom,
                                                              tvb, offset, 1,
                                                              "",
                                                              "Power Headroom");
                        phr_tree = proto_item_add_subtree(phr_ti, ett_mac_lte_power_headroom);

                        /* Check 2 Reserved bits */
                        reserved = (tvb_get_guint8(tvb, offset) & 0xc0) >> 6;
                        ti = proto_tree_add_item(phr_tree, hf_mac_lte_control_power_headroom_reserved,
                                                 tvb, offset, 1, ENC_BIG_ENDIAN);
                        if (reserved != 0) {
                            expert_add_info_format(pinfo, ti, PI_MALFORMED, PI_ERROR,
                                                   "Power Headroom Reserved bits not zero (found 0x%x)", reserved);
                        }

                        /* Level */
                        level = tvb_get_guint8(tvb, offset) & 0x3f;
                        proto_tree_add_item(phr_tree, hf_mac_lte_control_power_headroom_level,
                                            tvb, offset, 1, ENC_BIG_ENDIAN);

                        /* Show value in root label */
                        proto_item_append_text(phr_ti, " (%s)",
                                               val_to_str_const(level, power_headroom_size_vals, "Unknown"));
                        offset++;
                    }


                    break;
                case CRNTI_LCID:
                    proto_tree_add_item(tree, hf_mac_lte_control_crnti,
                                        tvb, offset, 2, ENC_BIG_ENDIAN);
                    offset += 2;
                    break;
                case TRUNCATED_BSR_LCID:
                case SHORT_BSR_LCID:
                    {
                        proto_tree *bsr_tree;
                        proto_item *bsr_ti;
                        proto_item *buffer_size_ti;
                        guint8 lcgid;
                        guint8 buffer_size;

                        bsr_ti = proto_tree_add_string_format(tree,
                                                              hf_mac_lte_control_bsr,
                                                              tvb, offset, 1,
                                                              "",
                                                              "Short BSR");
                        bsr_tree = proto_item_add_subtree(bsr_ti, ett_mac_lte_bsr);

                        /* LCG ID */
                        lcgid = (tvb_get_guint8(tvb, offset) & 0xc0) >> 6;
                        proto_tree_add_item(bsr_tree, hf_mac_lte_control_bsr_lcg_id,
                                                    tvb, offset, 1, ENC_BIG_ENDIAN);
                        /* Buffer Size */
                        buffer_size = tvb_get_guint8(tvb, offset) & 0x3f;
                        buffer_size_ti = proto_tree_add_item(bsr_tree, hf_mac_lte_control_short_bsr_buffer_size,
                                                             tvb, offset, 1, ENC_BIG_ENDIAN);
                        offset++;
                        if (buffer_size >= global_mac_lte_bsr_warn_threshold) {
                            expert_add_info_format(pinfo, buffer_size_ti, PI_SEQUENCE, PI_WARN,
                                                   "UE %u - BSR for LCG %u exceeds threshold: %u (%s)",
                                                   p_mac_lte_info->ueid,
                                                   lcgid,
                                                   buffer_size, val_to_str_const(buffer_size, buffer_size_vals, "Unknown"));
                        }


                        proto_item_append_text(bsr_ti, " (lcgid=%u  %s)",
                                               lcgid,
                                               val_to_str_const(buffer_size, buffer_size_vals, "Unknown"));
                    }
                    break;
                case LONG_BSR_LCID:
                    {
                        proto_tree *bsr_tree;
                        proto_item *bsr_ti;
                        proto_item *buffer_size_ti;
                        guint8     buffer_size[4];
                        bsr_ti = proto_tree_add_string_format(tree,
                                                              hf_mac_lte_control_bsr,
                                                              tvb, offset, 3,
                                                              "",
                                                              "Long BSR");
                        bsr_tree = proto_item_add_subtree(bsr_ti, ett_mac_lte_bsr);

                        /* LCID Group 0 */
                        buffer_size_ti = proto_tree_add_item(bsr_tree, hf_mac_lte_control_long_bsr_buffer_size_0,
                                                             tvb, offset, 1, ENC_BIG_ENDIAN);
                        buffer_size[0] = (tvb_get_guint8(tvb, offset) & 0xfc) >> 2;
                        if (buffer_size[0] >= global_mac_lte_bsr_warn_threshold) {
                            expert_add_info_format(pinfo, buffer_size_ti, PI_SEQUENCE, PI_WARN,
                                                   "UE %u - BSR for LCG 0 exceeds threshold: %u (%s)",
                                                   p_mac_lte_info->ueid,
                                                   buffer_size[0], val_to_str_const(buffer_size[0], buffer_size_vals, "Unknown"));
                        }

                        /* LCID Group 1 */
                        buffer_size_ti = proto_tree_add_item(bsr_tree, hf_mac_lte_control_long_bsr_buffer_size_1,
                                                             tvb, offset, 2, ENC_BIG_ENDIAN);
                        buffer_size[1] = ((tvb_get_guint8(tvb, offset) & 0x03) << 4) | ((tvb_get_guint8(tvb, offset+1) & 0xf0) >> 4);
                        offset++;
                        if (buffer_size[1] >= global_mac_lte_bsr_warn_threshold) {
                            expert_add_info_format(pinfo, buffer_size_ti, PI_SEQUENCE, PI_WARN,
                                                   "UE %u - BSR for LCG 1 exceeds threshold: %u (%s)",
                                                   p_mac_lte_info->ueid,
                                                   buffer_size[1], val_to_str_const(buffer_size[1], buffer_size_vals, "Unknown"));
                        }

                        /* LCID Group 2 */
                        buffer_size_ti = proto_tree_add_item(bsr_tree, hf_mac_lte_control_long_bsr_buffer_size_2,
                                                             tvb, offset, 2, ENC_BIG_ENDIAN);

                        buffer_size[2] = ((tvb_get_guint8(tvb, offset) & 0x0f) << 2) | ((tvb_get_guint8(tvb, offset+1) & 0xc0) >> 6);
                        offset++;
                        if (buffer_size[2] >= global_mac_lte_bsr_warn_threshold) {
                            expert_add_info_format(pinfo, buffer_size_ti, PI_SEQUENCE, PI_WARN,
                                                   "UE %u - BSR for LCG 2 exceeds threshold: %u (%s)",
                                                   p_mac_lte_info->ueid,
                                                   buffer_size[2], val_to_str_const(buffer_size[2], buffer_size_vals, "Unknown"));
                        }

                        /* LCID Group 3 */
                        buffer_size_ti = proto_tree_add_item(bsr_tree, hf_mac_lte_control_long_bsr_buffer_size_3,
                                                             tvb, offset, 1, ENC_BIG_ENDIAN);
                        buffer_size[3] = tvb_get_guint8(tvb, offset) & 0x3f;
                        offset++;
                        if (buffer_size[3] >= global_mac_lte_bsr_warn_threshold) {
                            expert_add_info_format(pinfo, buffer_size_ti, PI_SEQUENCE, PI_WARN,
                                                   "UE %u - BSR for LCG 3 exceeds threshold: %u (%s)",
                                                   p_mac_lte_info->ueid,
                                                   buffer_size[3], val_to_str_const(buffer_size[3], buffer_size_vals, "Unknown"));
                        }

                        /* Append summary to parent */
                        proto_item_append_text(bsr_ti, "   0:(%s)  1:(%s)  2:(%s)  3:(%s)",
                                               val_to_str_const(buffer_size[0], buffer_size_vals, "Unknown"),
                                               val_to_str_const(buffer_size[1], buffer_size_vals, "Unknown"),
                                               val_to_str_const(buffer_size[2], buffer_size_vals, "Unknown"),
                                               val_to_str_const(buffer_size[3], buffer_size_vals, "Unknown"));
                    }
                    break;
                case PADDING_LCID:
                    /* No payload, in this position */
                    tap_info->padding_bytes++;
                    break;

                default:
                    break;
            }
        }
    }

    /* There might not be any data, if only headers (plus control data) were logged */
    is_truncated = ((tvb_length_remaining(tvb, offset) == 0) && expecting_body_data);
    truncated_ti = proto_tree_add_uint(tree, hf_mac_lte_sch_header_only, tvb, 0, 0,
                                       is_truncated);
    if (is_truncated) {
        PROTO_ITEM_SET_GENERATED(truncated_ti);
        expert_add_info_format(pinfo, truncated_ti, PI_SEQUENCE, PI_NOTE,
                               "MAC PDU SDUs have been omitted");
        return;
    }
    else {
        PROTO_ITEM_SET_HIDDEN(truncated_ti);
    }


    /* Now process remaining bodies, which should all be data */
    for (; n < number_of_headers; n++) {

        /* Data SDUs treated identically for Uplink or downlink channels */
        proto_item *sdu_ti;
        const guint8 *pdu_data;
        volatile guint16 data_length;
        int i;
        char buff[64];

        /* Break out if meet padding */
        if (lcids[n] == PADDING_LCID) {
            break;
        }

        /* Work out length */
        data_length = (pdu_lengths[n] == -1) ?
                            tvb_length_remaining(tvb, offset) :
                            pdu_lengths[n];

        /* Dissect SDU as raw bytes */
        sdu_ti = proto_tree_add_bytes_format(tree, hf_mac_lte_sch_sdu, tvb, offset, pdu_lengths[n],
                                             NULL, "SDU (%s, length=%u bytes): ",
                                             val_to_str_const(lcids[n],
                                                              (direction == DIRECTION_UPLINK) ?
                                                                  ulsch_lcid_vals :
                                                                  dlsch_lcid_vals,
                                                             "Unknown"),
                                             data_length);
        /* Show bytes too.  There must be a nicer way of doing this! */
        pdu_data = tvb_get_ptr(tvb, offset, pdu_lengths[n]);
        for (i=0; i < data_length; i++) {
            g_snprintf(buff+(i*2), 3, "%02x",  pdu_data[i]);
            if (i >= 30) {
                g_snprintf(buff+(i*2), 4, "...");
                break;
            }
        }
        proto_item_append_text(sdu_ti, "%s", buff);


        /* Look for Msg3 data so that it may be compared with later
           Contention Resolution body */
        if ((lcids[n] == 0) && (direction == DIRECTION_UPLINK) && (data_length == 6)) {
            if (!pinfo->fd->flags.visited) {
                guint key = p_mac_lte_info->rnti;
                Msg3Data *data = g_hash_table_lookup(mac_lte_msg3_hash, GUINT_TO_POINTER(key));

                /* Look for previous entry for this UE */
                if (data == NULL) {
                    /* Allocate space for data and add to table */
                    data = se_alloc(sizeof(Msg3Data));
                    g_hash_table_insert(mac_lte_msg3_hash, GUINT_TO_POINTER(key), data);
                }

                /* Fill in data details */
                data->framenum = pinfo->fd->num;
                tvb_memcpy(tvb, data->data, offset, data_length);
                data->msg3Time = pinfo->fd->abs_ts;
            }
        }

        /* CCCH frames can be dissected directly by LTE RRC... */
        if ((lcids[n] == 0) && global_mac_lte_attempt_rrc_decode) {
            tvbuff_t *rrc_tvb = tvb_new_subset(tvb, offset, data_length, data_length);

            /* Get appropriate dissector handle */
            volatile dissector_handle_t protocol_handle = 0;
            if (p_mac_lte_info->direction == DIRECTION_UPLINK) {
                protocol_handle = find_dissector("lte_rrc.ul_ccch");
            }
            else {
                protocol_handle = find_dissector("lte_rrc.dl_ccch");
            }

            /* Hide raw view of bytes */
            PROTO_ITEM_SET_HIDDEN(sdu_ti);

            call_with_catch_all(protocol_handle, rrc_tvb, pinfo, tree);
        }

        /* LCID 1 and 2 can be assumed to be srb1&2, so can dissect as RLC AM */
        else if ((lcids[n] == 1) || (lcids[n] == 2)) {
            if (global_mac_lte_attempt_srb_decode) {
                /* Call RLC dissector */
                call_rlc_dissector(tvb, pinfo, tree, pdu_ti, offset, data_length,
                                   RLC_AM_MODE, direction, p_mac_lte_info->ueid,
                                   CHANNEL_TYPE_SRB, lcids[n], 0,
                                   get_mac_lte_channel_priority(p_mac_lte_info->ueid,
                                                                lcids[n], direction));

                /* Hide raw view of bytes */
                PROTO_ITEM_SET_HIDDEN(sdu_ti);
            }
        }

        else if ((lcids[n] >= 2) && (lcids[n] <= 10)) {

            /* Look for mapping for this LCID to drb channel set by UAT table */
            rlc_channel_type_t rlc_channel_type;
            guint8 UM_seqnum_length;
            gint drb_id;
            guint8 priority = get_mac_lte_channel_priority(p_mac_lte_info->ueid,
                                                           lcids[n], direction);

            lookup_rlc_channel_from_lcid(lcids[n],
                                         &rlc_channel_type,
                                         &UM_seqnum_length,
                                         &drb_id);

            /* Dissect according to channel type */
            switch (rlc_channel_type) {
                case rlcUM5:
                    call_rlc_dissector(tvb, pinfo, tree, pdu_ti, offset, data_length,
                                       RLC_UM_MODE, direction, p_mac_lte_info->ueid,
                                       CHANNEL_TYPE_DRB, (guint16)drb_id, UM_seqnum_length,
                                       priority);
                    break;
                case rlcUM10:
                    call_rlc_dissector(tvb, pinfo, tree, pdu_ti, offset, data_length,
                                       RLC_UM_MODE, direction, p_mac_lte_info->ueid,
                                       CHANNEL_TYPE_DRB, (guint16)drb_id, UM_seqnum_length,
                                       priority);
                    break;
                case rlcAM:
                    call_rlc_dissector(tvb, pinfo, tree, pdu_ti, offset, data_length,
                                       RLC_AM_MODE, direction, p_mac_lte_info->ueid,
                                       CHANNEL_TYPE_DRB, (guint16)drb_id, 0,
                                       priority);
                    break;
                case rlcTM:
                    call_rlc_dissector(tvb, pinfo, tree, pdu_ti, offset, data_length,
                                       RLC_TM_MODE, direction, p_mac_lte_info->ueid,
                                       CHANNEL_TYPE_DRB, (guint16)drb_id, 0,
                                       priority);
                    break;
                case rlcRaw:
                    /* Nothing to do! */
                    break;
            }

            if (rlc_channel_type != rlcRaw) {
                /* Hide raw view of bytes */
                PROTO_ITEM_SET_HIDDEN(sdu_ti);
            }

        }

        offset += data_length;

        /* Update tap byte count for this channel */
        tap_info->bytes_for_lcid[lcids[n]] += data_length;
        tap_info->sdus_for_lcid[lcids[n]]++;
    }


    /* Now padding, if present, extends to the end of the PDU */
    if (lcids[number_of_headers-1] == PADDING_LCID) {
        if (tvb_length_remaining(tvb, offset) > 0) {
            proto_tree_add_item(tree, hf_mac_lte_padding_data,
                                tvb, offset, -1, ENC_NA);
        }
        padding_length_ti = proto_tree_add_int(tree, hf_mac_lte_padding_length,
                                               tvb, offset, 0,
                                               p_mac_lte_info->length - offset);
        PROTO_ITEM_SET_GENERATED(padding_length_ti);

        /* Update padding bytes in stats */
        tap_info->padding_bytes += (p_mac_lte_info->length - offset);

        /* Make sure the PDU isn't bigger than reported! */
        if (offset > p_mac_lte_info->length) {
            expert_add_info_format(pinfo, padding_length_ti, PI_MALFORMED, PI_ERROR,
                                   "%s MAC PDU is longer than reported length (reported=%u, actual=%u)",
                                   (direction == DIRECTION_UPLINK) ? "UL-SCH" : "DL-SCH",
                                   p_mac_lte_info->length, offset);
        }
    }
    else {
        /* There is no padding at the end of the frame */
        if (!is_truncated && (offset < p_mac_lte_info->length)) {
            /* There is a problem if we haven't used all of the PDU */
            expert_add_info_format(pinfo, pdu_ti, PI_MALFORMED, PI_ERROR,
                                   "%s PDU for UE %u is shorter than reported length (reported=%u, actual=%u)",
                                   (direction == DIRECTION_UPLINK) ? "UL-SCH" : "DL-SCH",
                                   p_mac_lte_info->ueid, p_mac_lte_info->length, offset);
        }

        if (!is_truncated && (offset > p_mac_lte_info->length)) {
            /* There is a problem if the PDU is longer than rpeported */
            expert_add_info_format(pinfo, pdu_ti, PI_MALFORMED, PI_ERROR,
                                   "%s PDU for UE %u is longer than reported length (reported=%u, actual=%u)",
                                   (direction == DIRECTION_UPLINK) ? "UL-SCH" : "DL-SCH",
                                   p_mac_lte_info->ueid, p_mac_lte_info->length, offset);
        }
    }
}

static void dissect_mch(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, proto_item *pdu_ti,
                        volatile guint32 offset, mac_lte_info *p_mac_lte_info)
{
    guint8            extension;
    volatile guint16  n;
    proto_item       *truncated_ti;
    proto_item       *padding_length_ti;
    proto_item       *hidden_root_ti;

    /* Keep track of LCIDs and lengths as we dissect the header */
    volatile guint16 number_of_headers = 0;
    guint8  lcids[MAX_HEADERS_IN_PDU];
    gint16  pdu_lengths[MAX_HEADERS_IN_PDU];

    proto_item *pdu_header_ti;
    proto_tree *pdu_header_tree;

    gboolean   have_seen_data_header = FALSE;
    guint8     number_of_padding_subheaders = 0;
    gboolean   have_seen_non_padding_control = FALSE;
    gboolean   expecting_body_data = FALSE;
    volatile   guint32    is_truncated = FALSE;

    write_pdu_label_and_info(pdu_ti, NULL, pinfo,
                             "MCH: ",
                             p_mac_lte_info->subframeNumber);

    /* Add hidden item to filter on */
    hidden_root_ti = proto_tree_add_string_format(tree, hf_mac_lte_mch, tvb,
                                                  offset, 0, "", "Hidden header");
    PROTO_ITEM_SET_HIDDEN(hidden_root_ti);

    /* Add PDU block header subtree */
    pdu_header_ti = proto_tree_add_string_format(tree, hf_mac_lte_mch_header,
                                                 tvb, offset, 0,
                                                 "",
                                                 "MAC PDU Header");
    pdu_header_tree = proto_item_add_subtree(pdu_header_ti, ett_mac_lte_mch_header);


    /************************************************************************/
    /* Dissect each sub-header.                                             */
    do {
        guint8 reserved;
        guint64 length = 0;
        proto_item *pdu_subheader_ti;
        proto_tree *pdu_subheader_tree;
        proto_item *lcid_ti;
        proto_item *ti;
        gint       offset_start_subheader = offset;
        guint8 first_byte = tvb_get_guint8(tvb, offset);

        /* Add PDU block header subtree.
           Default with length of 1 byte. */
        pdu_subheader_ti = proto_tree_add_string_format(pdu_header_tree,
                                                        hf_mac_lte_mch_subheader,
                                                        tvb, offset, 1,
                                                        "",
                                                        "Sub-header");
        pdu_subheader_tree = proto_item_add_subtree(pdu_subheader_ti,
                                                    ett_mac_lte_mch_subheader);

        /* Check 1st 2 reserved bits */
        reserved = (first_byte & 0xc0) >> 6;
        ti = proto_tree_add_item(pdu_subheader_tree, hf_mac_lte_mch_reserved,
                                 tvb, offset, 1, ENC_BIG_ENDIAN);
        if (reserved != 0) {
            expert_add_info_format(pinfo, ti, PI_MALFORMED, PI_ERROR,
                                   "MCH header Reserved bits not zero");
        }

        /* Extended bit */
        extension = (first_byte & 0x20) >> 5;
        proto_tree_add_item(pdu_subheader_tree, hf_mac_lte_mch_extended,
                            tvb, offset, 1, ENC_BIG_ENDIAN);

        /* LCID */
        lcids[number_of_headers] = first_byte & 0x1f;
        lcid_ti = proto_tree_add_item(pdu_subheader_tree, hf_mac_lte_mch_lcid,
                                      tvb, offset, 1, ENC_BIG_ENDIAN);
        write_pdu_label_and_info(pdu_ti, NULL, pinfo,
                                 "(%s",
                                 val_to_str_const(lcids[number_of_headers],
                                                  mch_lcid_vals, "(Unknown LCID)"));
        offset++;

        /* Remember if we've seen a data subheader */
        if (lcids[number_of_headers] <= 28) {
            have_seen_data_header = TRUE;
            expecting_body_data = TRUE;
        }

        /* Show an expert item if a contol subheader (except Padding) appears
           *after* a data PDU */
        if (have_seen_data_header &&
            (lcids[number_of_headers] > 28) && (lcids[number_of_headers] != PADDING_LCID)) {
            expert_add_info_format(pinfo, lcid_ti, PI_MALFORMED, PI_ERROR,
                                   "MCH Control subheaders should not appear after data subheaders");
            return;
        }

        /* Should not see padding after non-padding control... */
        if ((lcids[number_of_headers] > 28) &&
            (lcids[number_of_headers] == PADDING_LCID) &&
            extension)
        {
            number_of_padding_subheaders++;
            if (number_of_padding_subheaders > 2) {
                expert_add_info_format(pinfo, lcid_ti, PI_MALFORMED, PI_WARN,
                                       "Should not see more than 2 padding subheaders in one frame");
            }

            if (have_seen_non_padding_control) {
                expert_add_info_format(pinfo, lcid_ti, PI_MALFORMED, PI_ERROR,
                                       "Padding should come before other control subheaders!");
            }
        }

        /* Remember that we've seen non-padding control */
        if ((lcids[number_of_headers] > 28) &&
            (lcids[number_of_headers] != PADDING_LCID)) {
            have_seen_non_padding_control = TRUE;
        }



        /********************************************************************/
        /* Length field follows if not the last header or for a fixed-sized
           control element */
        if (!extension) {
            /* Last one... */
            pdu_lengths[number_of_headers] = -1;
        }
        else {
            /* Not the last one */
            if (lcids[number_of_headers] != PADDING_LCID) {

                guint8  format;

                /* F(ormat) bit tells us how long the length field is */
                format = (tvb_get_guint8(tvb, offset) & 0x80) >> 7;
                proto_tree_add_item(pdu_subheader_tree, hf_mac_lte_mch_format,
                                    tvb, offset, 1, ENC_BIG_ENDIAN);

                /* Now read length field itself */
                if (format) {
                    /* >= 128 - use 15 bits */
                    proto_tree_add_bits_ret_val(pdu_subheader_tree, hf_mac_lte_mch_length,
                                                tvb, offset*8 + 1, 15, &length, ENC_BIG_ENDIAN);

                    offset += 2;
                }
                else {
                    /* Less than 128 - only 7 bits */
                    proto_tree_add_bits_ret_val(pdu_subheader_tree, hf_mac_lte_mch_length,
                                                tvb, offset*8 + 1, 7, &length, ENC_BIG_ENDIAN);
                    offset++;
                }
                if ((lcids[number_of_headers] == MCH_SCHEDULING_INFO_LCID) && (length & 0x01)) {
                    expert_add_info_format(pinfo, lcid_ti, PI_MALFORMED, PI_WARN,
                                           "MCH Scheduling Information MAC Control Element should have an even size");
                }
                pdu_lengths[number_of_headers] = (gint16)length;
            }
            else {
                pdu_lengths[number_of_headers] = 0;
            }
        }


        /* Close off description in info column */
        switch (pdu_lengths[number_of_headers]) {
            case 0:
                write_pdu_label_and_info(pdu_ti, NULL, pinfo, ") ");
                break;
            case -1:
                write_pdu_label_and_info(pdu_ti, NULL, pinfo, ":remainder) ");
                break;
            default:
                write_pdu_label_and_info(pdu_ti, NULL, pinfo, ":%u bytes) ",
                                         pdu_lengths[number_of_headers]);
                break;
        }

        /* Append summary to subheader root */
        proto_item_append_text(pdu_subheader_ti, " (lcid=%s",
                               val_to_str_const(lcids[number_of_headers],
                                                mch_lcid_vals, "Unknown"));

        switch (pdu_lengths[number_of_headers]) {
            case -1:
                proto_item_append_text(pdu_subheader_ti, ", length is remainder)");
                proto_item_append_text(pdu_header_ti, " (%s:remainder)",
                                       val_to_str_const(lcids[number_of_headers],
                                                        mch_lcid_vals,
                                                        "Unknown"));
                break;
            case 0:
                proto_item_append_text(pdu_subheader_ti, ")");
                proto_item_append_text(pdu_header_ti, " (%s)",
                                       val_to_str_const(lcids[number_of_headers],
                                                        mch_lcid_vals,
                                                        "Unknown"));
                break;
            default:
                proto_item_append_text(pdu_subheader_ti, ", length=%u)",
                                       pdu_lengths[number_of_headers]);
                proto_item_append_text(pdu_header_ti, " (%s:%u)",
                                       val_to_str_const(lcids[number_of_headers],
                                                        mch_lcid_vals,
                                                        "Unknown"),
                                       pdu_lengths[number_of_headers]);
                break;
        }


        /* Flag unknown lcid values in expert info */
        if (match_strval(lcids[number_of_headers],mch_lcid_vals) == NULL) {
            expert_add_info_format(pinfo, pdu_subheader_ti, PI_MALFORMED, PI_ERROR,
                                   "MCH: Unexpected LCID received (%u)",
                                   lcids[number_of_headers]);
        }

        /* Set length of this subheader */
        proto_item_set_len(pdu_subheader_ti, offset - offset_start_subheader);

        number_of_headers++;
    } while ((number_of_headers < MAX_HEADERS_IN_PDU) && extension);

    /* Check that we didn't reach the end of the subheader array... */
    if (number_of_headers >= MAX_HEADERS_IN_PDU) {
        proto_item *ti = proto_tree_add_text(tree, tvb, offset, 1,
                                             "Reached %u subheaders - frame obviously malformed",
                                             MAX_HEADERS_IN_PDU);
        expert_add_info_format(pinfo, ti, PI_MALFORMED, PI_ERROR,
                               "Reached %u subheaders - frame obviously malformed",
                               MAX_HEADERS_IN_PDU);
        return;
    }


    /* Append summary to overall PDU header root */
    proto_item_append_text(pdu_header_ti, " (%u subheaders)",
                           number_of_headers);

    /* And set its length to offset */
    proto_item_set_len(pdu_header_ti, offset);


    /************************************************************************/
    /* Dissect SDUs / control elements / padding.                           */
    /************************************************************************/

    /* Dissect control element bodies first */

    for (n=0; n < number_of_headers; n++) {
        /* Get out of loop once see any data SDU subheaders */
        if (lcids[n] <= 28) {
            break;
        }

        /* Process what should be a valid control PDU type */
        switch (lcids[n]) {
            case MCH_SCHEDULING_INFO_LCID:
                {
                    guint32 curr_offset = offset;
                    gint16 i;
                    guint16 stop_mtch_val;
                    proto_item *mch_sched_info_ti, *ti;
                    proto_tree *mch_sched_info_tree;

                    mch_sched_info_ti = proto_tree_add_string_format(tree,
                                                                     hf_mac_lte_control_mch_scheduling_info,
                                                                     tvb, curr_offset, pdu_lengths[n],
                                                                     "",
                                                                     "MCH Scheduling Information");
                    mch_sched_info_tree = proto_item_add_subtree(mch_sched_info_ti, ett_mac_lte_mch_scheduling_info);

                    for (i=0; i<(pdu_lengths[n]/2); i++) {
                        proto_tree_add_item(mch_sched_info_tree, hf_mac_lte_control_mch_scheduling_info_lcid,
                                            tvb, curr_offset, 1, ENC_BIG_ENDIAN);
                        stop_mtch_val = tvb_get_ntohs(tvb, curr_offset) & 0x7ff;
                        ti = proto_tree_add_item(mch_sched_info_tree, hf_mac_lte_control_mch_scheduling_info_stop_mtch,
                                                 tvb, curr_offset, 2, ENC_BIG_ENDIAN);
                        if ((stop_mtch_val >= 2043) && (stop_mtch_val <= 2046)) {
                            proto_item_append_text(ti, " (reserved)");
                        }
                        else if (stop_mtch_val == 2047) {
                            proto_item_append_text(ti, " (MTCH is not scheduled)");
                        }
                        curr_offset += 2;
                    }

                    offset += pdu_lengths[n];
                }
                break;
            case PADDING_LCID:
                /* No payload (in this position) */
                break;

            default:
                break;
        }
    }


    /* There might not be any data, if only headers (plus control data) were logged */
    is_truncated = ((tvb_length_remaining(tvb, offset) == 0) && expecting_body_data);
    truncated_ti = proto_tree_add_uint(tree, hf_mac_lte_mch_header_only, tvb, 0, 0,
                                       is_truncated);
    if (is_truncated) {
        PROTO_ITEM_SET_GENERATED(truncated_ti);
        expert_add_info_format(pinfo, truncated_ti, PI_SEQUENCE, PI_NOTE,
                               "MAC PDU SDUs have been omitted");
        return;
    }
    else {
        PROTO_ITEM_SET_HIDDEN(truncated_ti);
    }


    /* Now process remaining bodies, which should all be data */
    for (; n < number_of_headers; n++) {

        proto_item *sdu_ti;
        const guint8 *pdu_data;
        volatile guint16 data_length;
        int i;
        char buff[64];

        /* Break out if meet padding */
        if (lcids[n] == PADDING_LCID) {
            break;
        }

        /* Work out length */
        data_length = (pdu_lengths[n] == -1) ?
                            tvb_length_remaining(tvb, offset) :
                            pdu_lengths[n];

        /* Dissect SDU as raw bytes */
        sdu_ti = proto_tree_add_bytes_format(tree, hf_mac_lte_mch_sdu, tvb, offset, pdu_lengths[n],
                                             NULL, "SDU (%s, length=%u bytes): ",
                                             val_to_str_const(lcids[n], mch_lcid_vals, "Unknown"),
                                             data_length);
        /* Show bytes too.  There must be a nicer way of doing this! */
        pdu_data = tvb_get_ptr(tvb, offset, pdu_lengths[n]);
        for (i=0; i < data_length; i++) {
            g_snprintf(buff+(i*2), 3, "%02x",  pdu_data[i]);
            if (i >= 30) {
                g_snprintf(buff+(i*2), 4, "...");
                break;
            }
        }
        proto_item_append_text(sdu_ti, "%s", buff);

        offset += data_length;
    }

    /* Now padding, if present, extends to the end of the PDU */
    if (lcids[number_of_headers-1] == PADDING_LCID) {
        if (tvb_length_remaining(tvb, offset) > 0) {
            proto_tree_add_item(tree, hf_mac_lte_padding_data,
                                tvb, offset, -1, ENC_NA);
        }
        padding_length_ti = proto_tree_add_int(tree, hf_mac_lte_padding_length,
                                               tvb, offset, 0,
                                               p_mac_lte_info->length - offset);
        PROTO_ITEM_SET_GENERATED(padding_length_ti);

        /* Make sure the PDU isn't bigger than reported! */
        if (offset > p_mac_lte_info->length) {
            expert_add_info_format(pinfo, padding_length_ti, PI_MALFORMED, PI_ERROR,
                                   "MAC PDU is longer than reported length (reported=%u, actual=%u)",
                                   p_mac_lte_info->length, offset);
        }
    }
    else {
        /* There is no padding at the end of the frame */
        if (!is_truncated && (offset < p_mac_lte_info->length)) {
            /* There is a problem if we haven't used all of the PDU */
            expert_add_info_format(pinfo, pdu_ti, PI_MALFORMED, PI_ERROR,
                                   "PDU is shorter than reported length (reported=%u, actual=%u)",
                                   p_mac_lte_info->length, offset);
        }

        if (!is_truncated && (offset > p_mac_lte_info->length)) {
            /* There is a problem if the PDU is longer than rpeported */
            expert_add_info_format(pinfo, pdu_ti, PI_MALFORMED, PI_ERROR,
                                   "PDU is longer than reported length (reported=%u, actual=%u)",
                                   p_mac_lte_info->length, offset);
        }
    }
}


/*****************************/
/* Main dissection function. */
void dissect_mac_lte(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    proto_tree          *mac_lte_tree;
    proto_item          *pdu_ti;
    proto_tree          *context_tree;
    proto_item          *context_ti;
    proto_item          *retx_ti        = NULL;
    proto_item          *ti;
    gint                 offset         = 0;
    struct mac_lte_info *p_mac_lte_info = NULL;
    gint                 n;

    /* Allocate and zero tap struct */
    mac_lte_tap_info *tap_info = ep_alloc0(sizeof(mac_lte_tap_info));

    /* Set protocol name */
    col_set_str(pinfo->cinfo, COL_PROTOCOL, "MAC-LTE");

    /* Create protocol tree. */
    pdu_ti = proto_tree_add_item(tree, proto_mac_lte, tvb, offset, -1, ENC_NA);
    proto_item_append_text(pdu_ti, " ");
    mac_lte_tree = proto_item_add_subtree(pdu_ti, ett_mac_lte);


    /* Look for packet info! */
    p_mac_lte_info = p_get_proto_data(pinfo->fd, proto_mac_lte);

    /* Can't dissect anything without it... */
    if (p_mac_lte_info == NULL) {
        proto_item *tii =
            proto_tree_add_text(mac_lte_tree, tvb, offset, -1,
                                "Can't dissect LTE MAC frame because no per-frame info was attached!");
        PROTO_ITEM_SET_GENERATED(tii);
        return;
    }

    /* Clear info column */
    col_clear(pinfo->cinfo, COL_INFO);


    /*****************************************/
    /* Show context information              */

    /* Create context root */
    context_ti = proto_tree_add_string_format(mac_lte_tree, hf_mac_lte_context,
                                              tvb, offset, 0, "", "Context");
    context_tree = proto_item_add_subtree(context_ti, ett_mac_lte_context);
    PROTO_ITEM_SET_GENERATED(context_ti);

    ti = proto_tree_add_uint(context_tree, hf_mac_lte_context_radio_type,
                             tvb, 0, 0, p_mac_lte_info->radioType);
    PROTO_ITEM_SET_GENERATED(ti);

    ti = proto_tree_add_uint(context_tree, hf_mac_lte_context_direction,
                             tvb, 0, 0, p_mac_lte_info->direction);
    PROTO_ITEM_SET_GENERATED(ti);

    if (p_mac_lte_info->ueid != 0) {
        ti = proto_tree_add_uint(context_tree, hf_mac_lte_context_ueid,
                                 tvb, 0, 0, p_mac_lte_info->ueid);
        PROTO_ITEM_SET_GENERATED(ti);
    }

    /* There are several out-of-band MAC events that may be indicated in the context info. */
    /* Handle them here */
    if (p_mac_lte_info->length == 0) {
        proto_item *preamble_ti;
        proto_tree *preamble_tree;

        switch (p_mac_lte_info->oob_event) {
            case ltemac_send_preamble:
                preamble_ti = proto_tree_add_item(mac_lte_tree, hf_mac_lte_oob_send_preamble,
                                                  tvb, 0, 0, ENC_ASCII|ENC_NA);
                preamble_tree = proto_item_add_subtree(preamble_ti, ett_mac_lte_oob);
                PROTO_ITEM_SET_GENERATED(ti);

                ti = proto_tree_add_uint(preamble_tree, hf_mac_lte_context_rapid,
                                         tvb, 0, 0, p_mac_lte_info->rapid);
                PROTO_ITEM_SET_GENERATED(ti);

                ti = proto_tree_add_uint(preamble_tree, hf_mac_lte_context_rach_attempt_number,
                                         tvb, 0, 0, p_mac_lte_info->rach_attempt_number);
                PROTO_ITEM_SET_GENERATED(ti);

                /* Info column */
                write_pdu_label_and_info(pdu_ti, preamble_ti, pinfo,
                                         "RACH Preamble sent for UE %u (RAPID=%u, attempt=%u)",
                                         p_mac_lte_info->ueid, p_mac_lte_info->rapid, p_mac_lte_info->rach_attempt_number);

                /* Add expert info (a note, unless attempt > 1) */
                expert_add_info_format(pinfo, ti, PI_SEQUENCE,
                                       (p_mac_lte_info->rach_attempt_number > 1) ? PI_WARN : PI_NOTE,
                                       "RACH Preamble sent for UE %u (RAPID=%u, attempt=%u)",
                                       p_mac_lte_info->ueid, p_mac_lte_info->rapid,
                                       p_mac_lte_info->rach_attempt_number);
                break;
            case ltemac_send_sr:
                    /* Count of SRs */
                    ti = proto_tree_add_uint(mac_lte_tree, hf_mac_lte_number_of_srs,
                                             tvb, 0, 0, p_mac_lte_info->number_of_srs);
                    PROTO_ITEM_SET_GENERATED(ti);


                for (n=0; n < p_mac_lte_info->number_of_srs; n++) {
                    proto_item *sr_ti;
                    proto_tree *sr_tree;

                    /* SR event is subtree */
                    sr_ti = proto_tree_add_item(mac_lte_tree, hf_mac_lte_oob_send_sr,
                                                tvb, 0, 0, ENC_NA);
                    sr_tree = proto_item_add_subtree(sr_ti, ett_mac_lte_oob);
                    PROTO_ITEM_SET_GENERATED(sr_ti);


                    /* RNTI */
                    ti = proto_tree_add_uint(sr_tree, hf_mac_lte_context_rnti,
                                             tvb, 0, 0, p_mac_lte_info->oob_rnti[n]);
                    PROTO_ITEM_SET_GENERATED(ti);

                    /* UEID */
                    ti = proto_tree_add_uint(sr_tree, hf_mac_lte_context_ueid,
                                             tvb, 0, 0, p_mac_lte_info->oob_ueid[n]);
                    PROTO_ITEM_SET_GENERATED(ti);

                    /* Add summary to root. */
                    proto_item_append_text(sr_ti, " (UE=%u C-RNTI=%u)",
                                           p_mac_lte_info->oob_ueid[n],
                                           p_mac_lte_info->oob_rnti[n]);

                    /* Info column */
                    if (n == 0) {
                        write_pdu_label_and_info(pdu_ti, NULL, pinfo,
                                                "Scheduling Requests (%u) sent: (UE=%u C-RNTI=%u)",
                                                p_mac_lte_info->number_of_srs,
                                                p_mac_lte_info->oob_ueid[n],
                                                p_mac_lte_info->oob_rnti[n]);
                    }
                    else {
                        write_pdu_label_and_info(pdu_ti, NULL, pinfo,
                                                " (UE=%u C-RNTI=%u)",
                                                p_mac_lte_info->oob_ueid[n],
                                                p_mac_lte_info->oob_rnti[n]);
                    }

                    /* Add expert info (a note) */
                    expert_add_info_format(pinfo, sr_ti, PI_SEQUENCE, PI_NOTE,
                                           "Scheduling Request sent for UE %u (RNTI %u)",
                                           p_mac_lte_info->oob_ueid[n],
                                           p_mac_lte_info->oob_rnti[n]);

                    /* Update SR status for this UE */
                    if (global_mac_lte_track_sr) {
                        TrackSRInfo(SR_Request, pinfo, mac_lte_tree, tvb, p_mac_lte_info, n, sr_ti);
                    }
                }
                break;
            case ltemac_sr_failure:
                ti = proto_tree_add_uint(context_tree, hf_mac_lte_context_rnti,
                                         tvb, 0, 0, p_mac_lte_info->rnti);
                PROTO_ITEM_SET_GENERATED(ti);

                ti = proto_tree_add_item(mac_lte_tree, hf_mac_lte_oob_sr_failure,
                                         tvb, 0, 0, ENC_NA);
                PROTO_ITEM_SET_GENERATED(ti);

                /* Info column */
                write_pdu_label_and_info(pdu_ti, NULL, pinfo,
                                         "Scheduling Request FAILED for UE %u (C-RNTI=%u)",
                                         p_mac_lte_info->ueid,
                                         p_mac_lte_info->rnti);

                /* Add expert info (an error) */
                expert_add_info_format(pinfo, ti, PI_SEQUENCE, PI_ERROR,
                                       "Scheduling Request failed for UE %u (RNTI %u)",
                                       p_mac_lte_info->ueid,
                                       p_mac_lte_info->rnti);

                /* Update SR status */
                if (global_mac_lte_track_sr) {
                    TrackSRInfo(SR_Failure, pinfo, mac_lte_tree, tvb, p_mac_lte_info, 0, ti);
                }

                break;
        }

        /* Our work here is done */
        return;
    }

    ti = proto_tree_add_uint(context_tree, hf_mac_lte_context_sysframe_number,
                             tvb, 0, 0, p_mac_lte_info->sysframeNumber);
    PROTO_ITEM_SET_GENERATED(ti);

    ti = proto_tree_add_uint(context_tree, hf_mac_lte_context_subframe_number,
                             tvb, 0, 0, p_mac_lte_info->subframeNumber);
    PROTO_ITEM_SET_GENERATED(ti);
    if (p_mac_lte_info->subframeNumber > 9) {
        /* N.B. if we set it to valid value, it won't trigger when we rescan
           (at least with DCT2000 files where the context struct isn't re-read). */
        expert_add_info_format(pinfo, ti, PI_MALFORMED, PI_ERROR,
                               "Subframe number (%u) was out of range - valid range is 0-9",
                               p_mac_lte_info->subframeNumber);
    }

    if (p_mac_lte_info->subframeNumberOfGrantPresent) {
        ti = proto_tree_add_uint(context_tree, hf_mac_lte_context_grant_subframe_number,
                                 tvb, 0, 0, p_mac_lte_info->subframeNumberOfGrant);
        PROTO_ITEM_SET_GENERATED(ti);
    }

    if (p_mac_lte_info->rntiType != NO_RNTI) {
        ti = proto_tree_add_uint(context_tree, hf_mac_lte_context_rnti,
                                 tvb, 0, 0, p_mac_lte_info->rnti);
        PROTO_ITEM_SET_GENERATED(ti);
    }

    ti = proto_tree_add_uint(context_tree, hf_mac_lte_context_rnti_type,
                             tvb, 0, 0, p_mac_lte_info->rntiType);
    PROTO_ITEM_SET_GENERATED(ti);

    /* Check that RNTI value is consistent with given RNTI type */
    switch (p_mac_lte_info->rntiType) {
        case M_RNTI:
            if (p_mac_lte_info->rnti != 0xFFFD) {
                expert_add_info_format(pinfo, ti, PI_MALFORMED, PI_ERROR,
                      "M-RNTI indicated, but value is %u (0x%x) (must be 0x%x)",
                      p_mac_lte_info->rnti, p_mac_lte_info->rnti, 0xFFFD);
                return;
            }
            break;
        case P_RNTI:
            if (p_mac_lte_info->rnti != 0xFFFE) {
                expert_add_info_format(pinfo, ti, PI_MALFORMED, PI_ERROR,
                      "P-RNTI indicated, but value is %u (0x%x) (must be 0x%x)",
                      p_mac_lte_info->rnti, p_mac_lte_info->rnti, 0xFFFE);
                return;
            }
            break;
        case SI_RNTI:
            if (p_mac_lte_info->rnti != 0xFFFF) {
                expert_add_info_format(pinfo, ti, PI_MALFORMED, PI_ERROR,
                      "SI-RNTI indicated, but value is %u (0x%x) (must be 0x%x)",
                      p_mac_lte_info->rnti, p_mac_lte_info->rnti, 0xFFFE);
                return;
            }
            break;
        case RA_RNTI:
            if ((p_mac_lte_info->rnti < 0x0001) || (p_mac_lte_info->rnti > 0x003C)) {
                expert_add_info_format(pinfo, ti, PI_MALFORMED, PI_ERROR,
                      "RA_RNTI indicated, but given value %u (0x%x)is out of range",
                      p_mac_lte_info->rnti, p_mac_lte_info->rnti);
                return;
            }
            break;
        case C_RNTI:
        case SPS_RNTI:
            if ((p_mac_lte_info->rnti < 0x0001) || (p_mac_lte_info->rnti > 0xFFF3)) {
                expert_add_info_format(pinfo, ti, PI_MALFORMED, PI_ERROR,
                      "%s indicated, but given value %u (0x%x)is out of range",
                      val_to_str_const(p_mac_lte_info->rntiType,  rnti_type_vals, "Unknown"),
                      p_mac_lte_info->rnti, p_mac_lte_info->rnti);
                return;
            }
            break;

        default:
            break;
    }

    ti = proto_tree_add_uint(context_tree, hf_mac_lte_context_predefined_frame,
                             tvb, 0, 0, p_mac_lte_info->isPredefinedData);
    if (p_mac_lte_info->isPredefinedData) {
        PROTO_ITEM_SET_GENERATED(ti);
    }
    else {
        PROTO_ITEM_SET_HIDDEN(ti);
    }

    ti = proto_tree_add_uint(context_tree, hf_mac_lte_context_length,
                             tvb, 0, 0, p_mac_lte_info->length);
    PROTO_ITEM_SET_GENERATED(ti);
    /* Infer uplink grant size */
    if (p_mac_lte_info->direction == DIRECTION_UPLINK) {
        ti = proto_tree_add_uint(context_tree, hf_mac_lte_context_ul_grant_size,
                                 tvb, 0, 0, p_mac_lte_info->length);
        PROTO_ITEM_SET_GENERATED(ti);
    }

    /* Retx count goes in top-level tree to make it more visible */
    if (p_mac_lte_info->reTxCount) {
        proto_item *retx_reason_ti;
        retx_ti = proto_tree_add_uint(mac_lte_tree, hf_mac_lte_context_retx_count,
                                 tvb, 0, 0, p_mac_lte_info->reTxCount);
        PROTO_ITEM_SET_GENERATED(retx_ti);

        if (p_mac_lte_info->reTxCount >= global_mac_lte_retx_counter_trigger) {
            expert_add_info_format(pinfo, retx_ti, PI_SEQUENCE, PI_WARN,
                                   "UE %u: UL MAC frame ReTX no. %u",
                                   p_mac_lte_info->ueid, p_mac_lte_info->reTxCount);
        }

        retx_reason_ti = proto_tree_add_uint(mac_lte_tree, hf_mac_lte_context_retx_reason,
                                             tvb, 0, 0, p_mac_lte_info->isPHICHNACK);
        PROTO_ITEM_SET_GENERATED(retx_reason_ti);
    }

    if (p_mac_lte_info->crcStatusValid) {
        /* Set status */
        ti = proto_tree_add_uint(context_tree, hf_mac_lte_context_crc_status,
                                 tvb, 0, 0, p_mac_lte_info->detailed_phy_info.dl_info.crc_status);
        PROTO_ITEM_SET_GENERATED(ti);

        /* Report non-success */
        if (p_mac_lte_info->detailed_phy_info.dl_info.crc_status != crc_success) {
            expert_add_info_format(pinfo, ti, PI_MALFORMED, PI_ERROR,
                                   "%s Frame has CRC error problem (%s)",
                                   (p_mac_lte_info->direction == DIRECTION_UPLINK) ? "UL" : "DL",
                                   val_to_str_const(p_mac_lte_info->detailed_phy_info.dl_info.crc_status,
                                                    crc_status_vals,
                                                    "Unknown"));
            write_pdu_label_and_info(pdu_ti, NULL, pinfo,
                                     "%s: <CRC %s> UEId=%u %s=%u ",
                                     (p_mac_lte_info->direction == DIRECTION_UPLINK) ? "UL" : "DL",
                                     val_to_str_const(p_mac_lte_info->detailed_phy_info.dl_info.crc_status,
                                                    crc_status_vals,
                                                    "Unknown"),
                                     p_mac_lte_info->ueid,
                                     val_to_str_const(p_mac_lte_info->rntiType, rnti_type_vals,
                                                      "Unknown RNTI type"),
                                     p_mac_lte_info->rnti);
        }
    }

    /* May also have extra Physical layer attributes set for this frame */
    show_extra_phy_parameters(pinfo, tvb, mac_lte_tree, p_mac_lte_info);

    /* Set context-info parts of tap struct */
    tap_info->rnti = p_mac_lte_info->rnti;
    tap_info->ueid = p_mac_lte_info->ueid;
    tap_info->rntiType = p_mac_lte_info->rntiType;
    tap_info->isPredefinedData = p_mac_lte_info->isPredefinedData;
    tap_info->isPHYRetx = (p_mac_lte_info->reTxCount >= 1);
    tap_info->crcStatusValid = p_mac_lte_info->crcStatusValid;
    tap_info->crcStatus = p_mac_lte_info->detailed_phy_info.dl_info.crc_status;
    tap_info->direction = p_mac_lte_info->direction;

    tap_info->time = pinfo->fd->abs_ts;

    /* Also set total number of bytes (won't be used for UL/DL-SCH) */
    tap_info->single_number_of_bytes = tvb_length_remaining(tvb, offset);

    /* If we know its predefined data, don't try to decode any further */
    if (p_mac_lte_info->isPredefinedData) {
        proto_tree_add_item(mac_lte_tree, hf_mac_lte_predefined_pdu, tvb, offset, -1, ENC_NA);
        write_pdu_label_and_info(pdu_ti, NULL, pinfo,
                                 "Predefined data (%u bytes%s)",
                                 p_mac_lte_info->length,
                                 (p_mac_lte_info->length > tvb_length_remaining(tvb, offset) ?
                                     " - truncated" :
                                     ""));

        /* Queue tap info */
        if (!pinfo->flags.in_error_pkt) {
            tap_queue_packet(mac_lte_tap, pinfo, tap_info);
        }

        return;
    }

    /* IF CRC status failed, just do decode as raw bytes */
    if (!global_mac_lte_dissect_crc_failures &&
        (p_mac_lte_info->crcStatusValid &&
         (p_mac_lte_info->detailed_phy_info.dl_info.crc_status != crc_success))) {

        proto_tree_add_item(mac_lte_tree, hf_mac_lte_raw_pdu, tvb, offset, -1, ENC_NA);
        write_pdu_label_and_info(pdu_ti, NULL, pinfo, "Raw data (%u bytes)", tvb_length_remaining(tvb, offset));

        /* Queue tap info.
           TODO: unfortunately DL retx detection won't get done if we return here... */
        if (!pinfo->flags.in_error_pkt) {
            tap_queue_packet(mac_lte_tap, pinfo, tap_info);
        }

        return;
    }

    /* Reset this counter */
    s_number_of_rlc_pdus_shown = 0;

    /* Dissect the MAC PDU itself. Format depends upon RNTI type. */
    switch (p_mac_lte_info->rntiType) {

        case P_RNTI:
            /* PCH PDU */
            dissect_pch(tvb, pinfo, mac_lte_tree, pdu_ti, offset, p_mac_lte_info->direction);
            break;

        case RA_RNTI:
            /* RAR PDU */
            dissect_rar(tvb, pinfo, mac_lte_tree, pdu_ti, offset, p_mac_lte_info, tap_info);
            break;

        case C_RNTI:
        case SPS_RNTI:
            /* Can be UL-SCH or DL-SCH */
            dissect_ulsch_or_dlsch(tvb, pinfo, mac_lte_tree, pdu_ti, offset,
                                   p_mac_lte_info->direction, p_mac_lte_info, tap_info,
                                   retx_ti, context_tree);
            break;

        case SI_RNTI:
            /* BCH over DL-SCH */
            dissect_bch(tvb, pinfo, mac_lte_tree, pdu_ti, offset, p_mac_lte_info);
            break;

        case M_RNTI:
            /* MCH PDU */
            dissect_mch(tvb, pinfo, mac_lte_tree, pdu_ti, offset, p_mac_lte_info);
            break;

        case NO_RNTI:
            /* Must be BCH over BCH... */
            dissect_bch(tvb, pinfo, mac_lte_tree, pdu_ti, offset, p_mac_lte_info);
            break;


        default:
            break;
    }

    /* Queue tap info */
    tap_queue_packet(mac_lte_tap, pinfo, tap_info);
}




/* Initializes the hash tables each time a new
 * file is loaded or re-loaded in wireshark */
static void mac_lte_init_protocol(void)
{
    /* Destroy any existing tables. */
    if (mac_lte_msg3_hash) {
        g_hash_table_destroy(mac_lte_msg3_hash);
    }
    if (mac_lte_cr_result_hash) {
        g_hash_table_destroy(mac_lte_cr_result_hash);
    }

    if (mac_lte_dl_harq_hash) {
        g_hash_table_destroy(mac_lte_dl_harq_hash);
    }
    if (mac_lte_dl_harq_result_hash) {
        g_hash_table_destroy(mac_lte_dl_harq_result_hash);
    }
    if (mac_lte_ul_harq_hash) {
        g_hash_table_destroy(mac_lte_ul_harq_hash);
    }
    if (mac_lte_ul_harq_result_hash) {
        g_hash_table_destroy(mac_lte_ul_harq_result_hash);
    }
    if (mac_lte_ue_sr_state) {
        g_hash_table_destroy(mac_lte_ue_sr_state);
    }
    if (mac_lte_sr_request_hash) {
        g_hash_table_destroy(mac_lte_sr_request_hash);
    }
    if (mac_lte_tti_info_result_hash) {
        g_hash_table_destroy(mac_lte_tti_info_result_hash);
    }

    /* Reset structs */
    memset(&UL_tti_info, 0, sizeof(UL_tti_info));
    UL_tti_info.subframe = 0xff;  /* Invalid value */
    memset(&DL_tti_info, 0, sizeof(DL_tti_info));
    DL_tti_info.subframe = 0xff;  /* Invalid value */

    /* Now create them over */
    mac_lte_msg3_hash = g_hash_table_new(mac_lte_rnti_hash_func, mac_lte_rnti_hash_equal);
    mac_lte_cr_result_hash = g_hash_table_new(mac_lte_framenum_hash_func, mac_lte_framenum_hash_equal);

    mac_lte_dl_harq_hash = g_hash_table_new(mac_lte_rnti_hash_func, mac_lte_rnti_hash_equal);
    mac_lte_dl_harq_result_hash = g_hash_table_new(mac_lte_framenum_hash_func, mac_lte_framenum_hash_equal);

    mac_lte_ul_harq_hash = g_hash_table_new(mac_lte_rnti_hash_func, mac_lte_rnti_hash_equal);
    mac_lte_ul_harq_result_hash = g_hash_table_new(mac_lte_framenum_hash_func, mac_lte_framenum_hash_equal);

    mac_lte_ue_sr_state = g_hash_table_new(mac_lte_rnti_hash_func, mac_lte_rnti_hash_equal);
    mac_lte_sr_request_hash = g_hash_table_new(mac_lte_framenum_hash_func, mac_lte_framenum_hash_equal);

    mac_lte_tti_info_result_hash = g_hash_table_new(mac_lte_framenum_hash_func, mac_lte_framenum_hash_equal);
}


static void* lcid_drb_mapping_copy_cb(void* dest, const void* orig, size_t len _U_)
{
    const lcid_drb_mapping_t *o = orig;
    lcid_drb_mapping_t       *d = dest;

    /* Copy all items over */
    d->lcid = o->lcid;
    d->drbid = o->drbid;
    d->channel_type = o->channel_type;

    return d;
}



void proto_register_mac_lte(void)
{
    static hf_register_info hf[] =
    {
        /**********************************/
        /* Items for decoding context     */
        { &hf_mac_lte_context,
            { "Context",
              "mac-lte.context", FT_STRING, BASE_NONE, NULL, 0x0,
              NULL, HFILL
            }
        },
        { &hf_mac_lte_context_radio_type,
            { "Radio Type",
              "mac-lte.radio-type", FT_UINT8, BASE_DEC, VALS(radio_type_vals), 0x0,
              NULL, HFILL
            }
        },
        { &hf_mac_lte_context_direction,
            { "Direction",
              "mac-lte.direction", FT_UINT8, BASE_DEC, VALS(direction_vals), 0x0,
              "Direction of message", HFILL
            }
        },
        { &hf_mac_lte_context_rnti,
            { "RNTI",
              "mac-lte.rnti", FT_UINT16, BASE_DEC, 0, 0x0,
              "RNTI associated with message", HFILL
            }
        },
        { &hf_mac_lte_context_rnti_type,
            { "RNTI Type",
              "mac-lte.rnti-type", FT_UINT8, BASE_DEC, VALS(rnti_type_vals), 0x0,
              "Type of RNTI associated with message", HFILL
            }
        },
        { &hf_mac_lte_context_ueid,
            { "UEId",
              "mac-lte.ueid", FT_UINT16, BASE_DEC, 0, 0x0,
              "User Equipment Identifier associated with message", HFILL
            }
        },
        { &hf_mac_lte_context_sysframe_number,
            { "System Frame Number",
              "mac-lte.sfn", FT_UINT16, BASE_DEC, 0, 0x0,
              "System Frame Number associated with message", HFILL
            }
        },
        { &hf_mac_lte_context_subframe_number,
            { "Subframe",
              "mac-lte.subframe", FT_UINT16, BASE_DEC, 0, 0x0,
              "Subframe number associated with message", HFILL
            }
        },
        { &hf_mac_lte_context_grant_subframe_number,
            { "Grant Subframe",
              "mac-lte.grant-subframe", FT_UINT16, BASE_DEC, 0, 0x0,
              "Subframe when grant for this PDU was received", HFILL
            }
        },
        { &hf_mac_lte_context_predefined_frame,
            { "Predefined frame",
              "mac-lte.is-predefined-frame", FT_UINT8, BASE_DEC, VALS(predefined_frame_vals), 0x0,
              "Predefined test frame (or real MAC PDU)", HFILL
            }
        },
        { &hf_mac_lte_context_length,
            { "Length of frame",
              "mac-lte.length", FT_UINT8, BASE_DEC, 0, 0x0,
              "Original length of frame (including SDUs and padding)", HFILL
            }
        },
        { &hf_mac_lte_context_ul_grant_size,
            { "Uplink grant size",
              "mac-lte.ul-grant-size", FT_UINT8, BASE_DEC, 0, 0x0,
              "Uplink grant size (in bytes)", HFILL
            }
        },
        { &hf_mac_lte_context_bch_transport_channel,
            { "Transport channel",
              "mac-lte.bch-transport-channel", FT_UINT8, BASE_DEC, VALS(bch_transport_channel_vals), 0x0,
              "Transport channel BCH data was carried on", HFILL
            }
        },
        { &hf_mac_lte_context_retx_count,
            { "ReTX count",
              "mac-lte.retx-count", FT_UINT8, BASE_DEC, 0, 0x0,
              "Number of times this PDU has been retransmitted", HFILL
            }
        },
        { &hf_mac_lte_context_retx_reason,
            { "ReTX reason",
              "mac-lte.retx-reason", FT_UINT8, BASE_DEC, VALS(ul_retx_grant_vals), 0x0,
              "Type of UL ReTx grant", HFILL
            }
        },
        { &hf_mac_lte_context_crc_status,
            { "CRC Status",
              "mac-lte.crc-status", FT_UINT8, BASE_DEC, VALS(crc_status_vals), 0x0,
              "CRC Status as reported by PHY", HFILL
            }
        },
        { &hf_mac_lte_context_rapid,
            { "RAPID",
              "mac-lte.preamble-sent.rapid", FT_UINT8, BASE_DEC, 0, 0x0,
              "RAPID sent in RACH preamble", HFILL
            }
        },
        { &hf_mac_lte_context_rach_attempt_number,
            { "RACH Attempt Number",
              "mac-lte.preamble-sent.attempt", FT_UINT8, BASE_DEC, 0, 0x0,
              NULL, HFILL
            }
        },

        { &hf_mac_lte_ues_ul_per_tti,
            { "UL UE in TTI",
              "mac-lte.ul-tti-count", FT_UINT8, BASE_DEC, 0, 0x0,
              "In this TTI, this is the nth UL grant", HFILL
            }
        },
        { &hf_mac_lte_ues_dl_per_tti,
            { "DL UE in TTI",
              "mac-lte.dl-tti-count", FT_UINT8, BASE_DEC, 0, 0x0,
              "In this TTI, this is the nth DL PDU", HFILL
            }
        },


        /* Extra PHY context */
        { &hf_mac_lte_context_phy_ul,
            { "UL PHY attributes",
              "mac-lte.ul-phy", FT_STRING, BASE_NONE, 0, 0x0,
              NULL, HFILL
            }
        },
        { &hf_mac_lte_context_phy_ul_modulation_type,
            { "Modulation type",
              "mac-lte.ul-phy.modulation-type", FT_UINT8, BASE_DEC, VALS(modulation_type_vals), 0x0,
              NULL, HFILL
            }
        },
        { &hf_mac_lte_context_phy_ul_tbs_index,
            { "TBs Index",
              "mac-lte.ul-phy.tbs-index", FT_UINT8, BASE_DEC, 0, 0x0,
              NULL, HFILL
            }
        },
        { &hf_mac_lte_context_phy_ul_resource_block_length,
            { "Resource Block Length",
              "mac-lte.ul-phy.resource-block-length", FT_UINT8, BASE_DEC, 0, 0x0,
              NULL, HFILL
            }
        },
        { &hf_mac_lte_context_phy_ul_resource_block_start,
            { "Resource Block Start",
              "mac-lte.ul-phy.resource-block-start", FT_UINT8, BASE_DEC, 0, 0x0,
              NULL, HFILL
            }
        },
        { &hf_mac_lte_context_phy_ul_harq_id,
            { "HARQ Id",
              "mac-lte.ul-phy.harq-id", FT_UINT8, BASE_DEC, 0, 0x0,
              NULL, HFILL
            }
        },
        { &hf_mac_lte_context_phy_ul_ndi,
            { "NDI",
              "mac-lte.ul-phy.ndi", FT_UINT8, BASE_DEC, 0, 0x0,
              "UL New Data Indicator", HFILL
            }
        },

        { &hf_mac_lte_context_phy_dl,
            { "DL PHY attributes",
              "mac-lte.dl-phy", FT_STRING, BASE_NONE, 0, 0x0,
              NULL, HFILL
            }
        },
        { &hf_mac_lte_context_phy_dl_dci_format,
            { "DCI format",
              "mac-lte.dl-phy.dci-format", FT_UINT8, BASE_DEC, VALS(dci_format_vals), 0x0,
              NULL, HFILL
            }
        },
        { &hf_mac_lte_context_phy_dl_resource_allocation_type,
            { "Resource Allocation Type",
              "mac-lte.dl-phy.resource-allocation-type", FT_UINT8, BASE_DEC, 0, 0x0,
              NULL, HFILL
            }
        },
        { &hf_mac_lte_context_phy_dl_aggregation_level,
            { "Aggregation Level",
              "mac-lte.dl-phy.aggregation-level", FT_UINT8, BASE_DEC, VALS(aggregation_level_vals), 0x0,
              NULL, HFILL
            }
        },
        { &hf_mac_lte_context_phy_dl_mcs_index,
            { "MCS Index",
              "mac-lte.dl-phy.mcs-index", FT_UINT8, BASE_DEC, 0, 0x0,
              NULL, HFILL
            }
        },
        { &hf_mac_lte_context_phy_dl_redundancy_version_index,
            { "RV Index",
              "mac-lte.dl-phy.rv-index", FT_UINT8, BASE_DEC, 0, 0x0,
              NULL, HFILL
            }
        },
        { &hf_mac_lte_context_phy_dl_retx,
            { "DL Retx",
              "mac-lte.dl-phy.dl-retx", FT_BOOLEAN, BASE_NONE, NULL, 0x0,
              NULL, HFILL
            }
        },
        { &hf_mac_lte_context_phy_dl_resource_block_length,
            { "RB Length",
              "mac-lte.dl-phy.rb-length", FT_UINT8, BASE_DEC, 0, 0x0,
              NULL, HFILL
            }
        },
        { &hf_mac_lte_context_phy_dl_crc_status,
            { "CRC Status",
              "mac-lte.dl-phy.crc-status", FT_UINT8, BASE_DEC, VALS(crc_status_vals), 0x0,
              NULL, HFILL
            }
        },
        { &hf_mac_lte_context_phy_dl_harq_id,
            { "HARQ Id",
              "mac-lte.dl-phy.harq-id", FT_UINT8, BASE_DEC, 0, 0x0,
              NULL, HFILL
            }
        },
        { &hf_mac_lte_context_phy_dl_ndi,
            { "NDI",
              "mac-lte.dl-phy.ndi", FT_UINT8, BASE_DEC, 0, 0x0,
              "New Data Indicator", HFILL
            }
        },
        { &hf_mac_lte_context_phy_dl_tb,
            { "TB",
              "mac-lte.dl-phy.tb", FT_UINT8, BASE_DEC, 0, 0x0,
              "Transport Block (antenna #)", HFILL
            }
        },

        /* Out-of-band events */
        { &hf_mac_lte_oob_send_preamble,
            { "PRACH",
              "mac-lte.preamble-sent", FT_STRING, BASE_NONE, NULL, 0x0,
              NULL, HFILL
            }
        },
        { &hf_mac_lte_oob_send_sr,
            { "Scheduling Request sent",
              "mac-lte.sr-req", FT_NONE, BASE_NONE, NULL, 0x0,
              NULL, HFILL
            }
        },
        { &hf_mac_lte_number_of_srs,
            { "Number of SRs",
              "mac-lte.sr-req.count", FT_UINT32, BASE_DEC, 0, 0x0,
              "Number of UEs doing SR in this frame", HFILL
            }
        },
        { &hf_mac_lte_oob_sr_failure,
            { "Scheduling Request failure",
              "mac-lte.sr-failure", FT_NONE, BASE_NONE, NULL, 0x0,
              NULL, HFILL
            }
        },

        /*******************************************/
        /* MAC shared channel header fields        */
        { &hf_mac_lte_ulsch,
            { "UL-SCH",
              "mac-lte.ulsch", FT_STRING, BASE_NONE, NULL, 0x0,
              NULL, HFILL
            }
        },
        { &hf_mac_lte_ulsch_header,
            { "UL-SCH Header",
              "mac-lte.ulsch.header", FT_STRING, BASE_NONE, NULL, 0x0,
              NULL, HFILL
            }
        },
        { &hf_mac_lte_dlsch_header,
            { "DL-SCH Header",
              "mac-lte.dlsch.header", FT_STRING, BASE_NONE, NULL, 0x0,
              NULL, HFILL
            }
        },
        { &hf_mac_lte_dlsch,
            { "DL-SCH",
              "mac-lte.dlsch", FT_STRING, BASE_NONE, NULL, 0x0,
              NULL, HFILL
            }
        },
        { &hf_mac_lte_sch_subheader,
            { "SCH sub-header",
              "mac-lte.sch.subheader", FT_STRING, BASE_NONE, NULL, 0x0,
              NULL, HFILL
            }
        },
        { &hf_mac_lte_mch,
            { "MCH",
              "mac-lte.mch", FT_STRING, BASE_NONE, NULL, 0x0,
              NULL, HFILL
            }
        },
        { &hf_mac_lte_mch_header,
            { "MCH Header",
              "mac-lte.mch.header", FT_STRING, BASE_NONE, NULL, 0x0,
              NULL, HFILL
            }
        },
        { &hf_mac_lte_mch_subheader,
            { "MCH sub-header",
              "mac-lte.mch.subheader", FT_STRING, BASE_NONE, NULL, 0x0,
              NULL, HFILL
            }
        },
        { &hf_mac_lte_sch_reserved,
            { "SCH reserved bits",
              "mac-lte.sch.reserved", FT_UINT8, BASE_HEX, NULL, 0xc0,
              NULL, HFILL
            }
        },
        { &hf_mac_lte_sch_extended,
            { "Extension",
              "mac-lte.sch.extended", FT_UINT8, BASE_HEX, 0, 0x20,
              "Extension - i.e. further headers after this one", HFILL
            }
        },
        { &hf_mac_lte_dlsch_lcid,
            { "LCID",
              "mac-lte.dlsch.lcid", FT_UINT8, BASE_HEX, VALS(dlsch_lcid_vals), 0x1f,
              "DL-SCH Logical Channel Identifier", HFILL
            }
        },
        { &hf_mac_lte_ulsch_lcid,
            { "LCID",
              "mac-lte.ulsch.lcid", FT_UINT8, BASE_HEX, VALS(ulsch_lcid_vals), 0x1f,
              "UL-SCH Logical Channel Identifier", HFILL
            }
        },
        { &hf_mac_lte_sch_format,
            { "Format",
              "mac-lte.sch.format", FT_UINT8, BASE_HEX, VALS(format_vals), 0x80,
              NULL, HFILL
            }
        },
        { &hf_mac_lte_sch_length,
            { "Length",
              "mac-lte.sch.length", FT_UINT16, BASE_DEC, 0, 0x0,
              "Length of MAC SDU or MAC control element", HFILL
            }
        },
        { &hf_mac_lte_mch_reserved,
            { "MCH reserved bits",
              "mac-lte.mch.reserved", FT_UINT8, BASE_HEX, NULL, 0xc0,
              NULL, HFILL
            }
        },
        { &hf_mac_lte_mch_extended,
            { "Extension",
              "mac-lte.mch.extended", FT_UINT8, BASE_HEX, 0, 0x20,
              "Extension - i.e. further headers after this one", HFILL
            }
        },
        { &hf_mac_lte_mch_lcid,
            { "LCID",
              "mac-lte.mch.lcid", FT_UINT8, BASE_HEX, VALS(mch_lcid_vals), 0x1f,
              "MCH Logical Channel Identifier", HFILL
            }
        },
        { &hf_mac_lte_mch_format,
            { "Format",
              "mac-lte.mch.format", FT_UINT8, BASE_HEX, VALS(format_vals), 0x80,
              NULL, HFILL
            }
        },
        { &hf_mac_lte_mch_length,
            { "Length",
              "mac-lte.mch.length", FT_UINT16, BASE_DEC, 0, 0x0,
              "Length of MAC SDU or MAC control element", HFILL
            }
        },
        { &hf_mac_lte_sch_header_only,
            { "MAC PDU Header only",
              "mac-lte.sch.header-only", FT_UINT8, BASE_DEC, VALS(header_only_vals), 0x0,
              NULL, HFILL
            }
        },
        { &hf_mac_lte_mch_header_only,
            { "MAC PDU Header only",
              "mac-lte.mch.header-only", FT_UINT8, BASE_DEC, VALS(header_only_vals), 0x0,
              NULL, HFILL
            }
        },

        /********************************/
        /* Data                         */
        { &hf_mac_lte_sch_sdu,
            { "SDU",
              "mac-lte.sch.sdu", FT_BYTES, BASE_NONE, 0, 0x0,
              "Shared channel SDU", HFILL
            }
        },
        { &hf_mac_lte_mch_sdu,
            { "SDU",
              "mac-lte.mch.sdu", FT_BYTES, BASE_NONE, 0, 0x0,
              "Multicast channel SDU", HFILL
            }
        },
        { &hf_mac_lte_bch_pdu,
            { "BCH PDU",
              "mac-lte.bch.pdu", FT_BYTES, BASE_NONE, 0, 0x0,
              NULL, HFILL
            }
        },
        { &hf_mac_lte_pch_pdu,
            { "PCH PDU",
              "mac-lte.pch.pdu", FT_BYTES, BASE_NONE, 0, 0x0,
              NULL, HFILL
            }
        },
        { &hf_mac_lte_predefined_pdu,
            { "Predefined data",
              "mac-lte.predefined-data", FT_BYTES, BASE_NONE, 0, 0x0,
              "Predefined test data", HFILL
            }
        },
        { &hf_mac_lte_raw_pdu,
            { "Raw data",
              "mac-lte.raw-data", FT_BYTES, BASE_NONE, 0, 0x0,
              "Raw bytes of PDU (e.g. if CRC error)", HFILL
            }
        },
        { &hf_mac_lte_padding_data,
            { "Padding data",
              "mac-lte.padding-data", FT_BYTES, BASE_NONE, 0, 0x0,
              NULL, HFILL
            }
        },
        { &hf_mac_lte_padding_length,
            { "Padding length",
              "mac-lte.padding-length", FT_INT32, BASE_DEC, 0, 0x0,
              "Length of padding data not included at end of frame", HFILL
            }
        },



        /*********************************/
        /* RAR fields                    */
        { &hf_mac_lte_rar,
            { "RAR",
              "mac-lte.rar", FT_NONE, BASE_NONE, NULL, 0x0,
              NULL, HFILL
            }
        },
        { &hf_mac_lte_rar_headers,
            { "RAR Headers",
              "mac-lte.rar.headers", FT_STRING, BASE_NONE, NULL, 0x0,
              NULL, HFILL
            }
        },
        { &hf_mac_lte_rar_header,
            { "RAR Header",
              "mac-lte.rar.header", FT_STRING, BASE_NONE, NULL, 0x0,
              NULL, HFILL
            }
        },
        { &hf_mac_lte_rar_extension,
            { "Extension",
              "mac-lte.rar.e", FT_UINT8, BASE_HEX, 0, 0x80,
              "Extension - i.e. further RAR headers after this one", HFILL
            }
        },
        { &hf_mac_lte_rar_t,
            { "Type",
              "mac-lte.rar.t", FT_UINT8, BASE_HEX, VALS(rar_type_vals), 0x40,
              "Type field indicating whether the payload is RAPID or BI", HFILL
            }
        },
        { &hf_mac_lte_rar_bi,
            { "BI",
              "mac-lte.rar.bi", FT_UINT8, BASE_HEX, VALS(rar_bi_vals), 0x0f,
              "Backoff Indicator (ms)", HFILL
            }
        },
        { &hf_mac_lte_rar_rapid,
            { "RAPID",
              "mac-lte.rar.rapid", FT_UINT8, BASE_HEX_DEC, 0, 0x3f,
              "Random Access Preamble IDentifier", HFILL
            }
        },
        { &hf_mac_lte_rar_reserved,
            { "Reserved",
              "mac-lte.rar.reserved", FT_UINT8, BASE_HEX, 0, 0x30,
              "Reserved bits in RAR header - should be 0", HFILL
            }
        },

        { &hf_mac_lte_rar_body,
            { "RAR Body",
              "mac-lte.rar.body", FT_STRING, BASE_NONE, NULL, 0x0,
              NULL, HFILL
            }
        },
        { &hf_mac_lte_rar_reserved2,
            { "Reserved",
              "mac-lte.rar.reserved2", FT_UINT8, BASE_HEX, 0, 0x80,
              "Reserved bit in RAR body - should be 0", HFILL
            }
        },
        { &hf_mac_lte_rar_ta,
            { "Timing Advance",
              "mac-lte.rar.ta", FT_UINT16, BASE_DEC, 0, 0x7ff0,
              "Required adjustment to uplink transmission timing", HFILL
            }
        },
        { &hf_mac_lte_rar_ul_grant,
            { "UL Grant",
              "mac-lte.rar.ul-grant", FT_UINT24, BASE_DEC, 0, 0x0fffff,
              "Size of UL Grant", HFILL
            }
        },
        { &hf_mac_lte_rar_ul_grant_hopping,
            { "Hopping Flag",
              "mac-lte.rar.ul-grant.hopping", FT_UINT8, BASE_DEC, 0, 0x08,
              NULL, HFILL
            }
        },
        { &hf_mac_lte_rar_ul_grant_fsrba,
            { "Fixed sized resource block assignment",
              "mac-lte.rar.ul-grant.fsrba", FT_UINT16, BASE_DEC, 0, 0x07fe,
              NULL, HFILL
            }
        },
        { &hf_mac_lte_rar_ul_grant_tmcs,
            { "Truncated Modulation and coding scheme",
              "mac-lte.rar.ul-grant.tmcs", FT_UINT16, BASE_DEC, 0, 0x01e0,
              NULL, HFILL
            }
        },
        { &hf_mac_lte_rar_ul_grant_tcsp,
            { "TPC command for scheduled PUSCH",
              "mac-lte.rar.ul-grant.tcsp", FT_UINT8, BASE_DEC, 0, 0x01c,
              NULL, HFILL
            }
        },
        { &hf_mac_lte_rar_ul_grant_ul_delay,
            { "UL Delay",
              "mac-lte.rar.ul-grant.ul-delay", FT_UINT8, BASE_DEC, 0, 0x02,
              NULL, HFILL
            }
        },
        { &hf_mac_lte_rar_ul_grant_cqi_request,
            { "CQI Request",
              "mac-lte.rar.ul-grant.cqi-request", FT_UINT8, BASE_DEC, 0, 0x01,
              NULL, HFILL
            }
        },
        { &hf_mac_lte_rar_temporary_crnti,
            { "Temporary C-RNTI",
              "mac-lte.rar.temporary-crnti", FT_UINT16, BASE_DEC, 0, 0x0,
              NULL, HFILL
            }
        },

        /**********************/
        /* Control PDU fields */
        { &hf_mac_lte_control_bsr,
            { "BSR",
              "mac-lte.control.bsr", FT_STRING, BASE_NONE, 0, 0x0,
              "Buffer Status Report", HFILL
            }
        },
        { &hf_mac_lte_control_bsr_lcg_id,
            { "Logical Channel Group ID",
              "mac-lte.control.bsr.lcg-id", FT_UINT8, BASE_DEC, 0, 0xc0,
              NULL, HFILL
            }
        },
        { &hf_mac_lte_control_short_bsr_buffer_size,
            { "Buffer Size",
              "mac-lte.control.bsr.buffer-size", FT_UINT8, BASE_DEC, VALS(buffer_size_vals), 0x3f,
              "Buffer Size available in all channels in group", HFILL
            }
        },
        { &hf_mac_lte_control_long_bsr_buffer_size_0,
            { "Buffer Size 0",
              "mac-lte.control.bsr.buffer-size-0", FT_UINT8, BASE_DEC, VALS(buffer_size_vals), 0xfc,
              "Buffer Size available in logical channel group 0", HFILL
            }
        },
        { &hf_mac_lte_control_long_bsr_buffer_size_1,
            { "Buffer Size 1",
              "mac-lte.control.bsr.buffer-size-1", FT_UINT16, BASE_DEC, VALS(buffer_size_vals), 0x03f0,
              "Buffer Size available in logical channel group 1", HFILL
            }
        },
        { &hf_mac_lte_control_long_bsr_buffer_size_2,
            { "Buffer Size 2",
              "mac-lte.control.bsr.buffer-size-2", FT_UINT16, BASE_DEC, VALS(buffer_size_vals), 0x0fc0,
              "Buffer Size available in logical channel group 2", HFILL
            }
        },
        { &hf_mac_lte_control_long_bsr_buffer_size_3,
            { "Buffer Size 3",
              "mac-lte.control.bsr.buffer-size-3", FT_UINT8, BASE_DEC, VALS(buffer_size_vals), 0x3f,
              "Buffer Size available in logical channel group 3", HFILL
            }
        },
        { &hf_mac_lte_control_crnti,
            { "C-RNTI",
              "mac-lte.control.crnti", FT_UINT16, BASE_DEC, 0, 0x0,
              "C-RNTI for the UE", HFILL
            }
        },
        { &hf_mac_lte_control_timing_advance,
            { "Timing Advance",
              "mac-lte.control.timing-advance", FT_UINT8, BASE_DEC, 0, 0x3f,
              "Timing Advance (0-1282 - see 36.213, 4.2.3)", HFILL
            }
        },
        { &hf_mac_lte_control_timing_advance_reserved,
            { "Reserved",
              "mac-lte.control.timing-advance.reserved", FT_UINT8, BASE_HEX, 0, 0xc0,
              "Reserved bits", HFILL
            }
        },
        { &hf_mac_lte_control_ue_contention_resolution,
            { "UE Contention Resolution",
              "mac-lte.control.ue-contention-resolution", FT_STRING, BASE_NONE, 0, 0x0,
              NULL, HFILL
            }
        },
        { &hf_mac_lte_control_ue_contention_resolution_identity,
            { "UE Contention Resolution Identity",
              "mac-lte.control.ue-contention-resolution.identity", FT_BYTES, BASE_NONE, 0, 0x0,
              NULL, HFILL
            }
        },
        { &hf_mac_lte_control_ue_contention_resolution_msg3,
            { "Msg3",
              "mac-lte.control.ue-contention-resolution.msg3", FT_FRAMENUM, BASE_NONE, 0, 0x0,
              NULL, HFILL
            }
        },
        { &hf_mac_lte_control_ue_contention_resolution_msg3_matched,
            { "UE Contention Resolution Matches Msg3",
              "mac-lte.control.ue-contention-resolution.matches-msg3", FT_BOOLEAN, BASE_NONE, 0, 0x0,
              NULL, HFILL
            }
        },
        { &hf_mac_lte_control_ue_contention_resolution_time_since_msg3,
            { "Time since Msg3",
              "mac-lte.control.ue-contention-resolution.time-since-msg3", FT_UINT32, BASE_DEC, 0, 0x0,
              "Time in ms since corresponding Msg3", HFILL
            }
        },

        { &hf_mac_lte_control_power_headroom,
            { "Power Headroom",
              "mac-lte.control.power-headroom", FT_STRING, BASE_NONE, 0, 0x0,
              NULL, HFILL
            }
        },
        { &hf_mac_lte_control_power_headroom_reserved,
            { "Reserved",
              "mac-lte.control.power-headroom.reserved", FT_UINT8, BASE_DEC, 0, 0xc0,
              "Reserved bits, should be 0", HFILL
            }
        },
        { &hf_mac_lte_control_power_headroom_level,
            { "Power Headroom Level",
              "mac-lte.control.power-headroom.level", FT_UINT8, BASE_DEC,
               VALS(power_headroom_size_vals), 0x3f, "Power Headroom Level in dB", HFILL
            }
        },

        { &hf_mac_lte_control_padding,
            { "Padding",
              "mac-lte.control.padding", FT_NONE, BASE_NONE, 0, 0x0,
              NULL, HFILL
            }
        },

        { &hf_mac_lte_control_mch_scheduling_info,
            { "MCH Scheduling Information",
              "mac-lte.control.mch_scheduling_info", FT_STRING, BASE_NONE, 0, 0x0,
              NULL, HFILL
            }
        },
        { &hf_mac_lte_control_mch_scheduling_info_lcid,
            { "LCID",
              "mac-lte.control.mch_scheduling_info.lcid", FT_UINT8, BASE_HEX, VALS(mch_lcid_vals), 0xf8,
              "Logical Channel ID of the MTCH", HFILL
            }
        },
        { &hf_mac_lte_control_mch_scheduling_info_stop_mtch,
            { "Stop MTCH",
              "mac-lte.control.mch_scheduling_info.stop_mtch", FT_UINT16, BASE_DEC, 0, 0x07ff,
              "Ordinal number of the subframe where the corresponding MTCH stops", HFILL
            }
        },

        /* Generated fields */
        { &hf_mac_lte_dl_harq_resend_original_frame,
            { "Frame with previous tx",
              "mac-lte.dlsch.retx.original-frame", FT_FRAMENUM, BASE_NONE, 0, 0x0,
              NULL, HFILL
            }
        },
        { &hf_mac_lte_dl_harq_resend_time_since_previous_frame,
            { "Time since previous tx (ms)",
              "mac-lte.dlsch.retx.time-since-previous", FT_UINT16, BASE_DEC, 0, 0x0,
              NULL, HFILL
            }
        },
        { &hf_mac_lte_dl_harq_resend_next_frame,
            { "Frame with next tx",
              "mac-lte.dlsch.retx.next-frame", FT_FRAMENUM, BASE_NONE, 0, 0x0,
              NULL, HFILL
            }
        },
        { &hf_mac_lte_dl_harq_resend_time_until_next_frame,
            { "Time until next tx (ms)",
              "mac-lte.dlsch.retx.time-until-next", FT_UINT16, BASE_DEC, 0, 0x0,
              NULL, HFILL
            }
        },

        { &hf_mac_lte_ul_harq_resend_original_frame,
            { "Frame with previous tx",
              "mac-lte.ulsch.retx.original-frame", FT_FRAMENUM, BASE_NONE, 0, 0x0,
              NULL, HFILL
            }
        },
        { &hf_mac_lte_ul_harq_resend_time_since_previous_frame,
            { "Time since previous tx (ms)",
              "mac-lte.ulsch.retx.time-since-previous", FT_UINT16, BASE_DEC, 0, 0x0,
              NULL, HFILL
            }
        },
        { &hf_mac_lte_ul_harq_resend_next_frame,
            { "Frame with next tx",
              "mac-lte.ulsch.retx.next-frame", FT_FRAMENUM, BASE_NONE, 0, 0x0,
              NULL, HFILL
            }
        },
        { &hf_mac_lte_ul_harq_resend_time_until_next_frame,
            { "Time until next tx (ms)",
              "mac-lte.ulsch.retx.time-until-next", FT_UINT16, BASE_DEC, 0, 0x0,
              NULL, HFILL
            }
        },

        { &hf_mac_lte_grant_answering_sr,
            { "First Grant Following SR from",
              "mac-lte.ulsch.grant-answering-sr", FT_FRAMENUM, BASE_NONE, 0, 0x0,
              NULL, HFILL
            }
        },
        { &hf_mac_lte_failure_answering_sr,
            { "SR which failed",
              "mac-lte.ulsch.failure-answering-sr", FT_FRAMENUM, BASE_NONE, 0, 0x0,
              NULL, HFILL
            }
        },
        { &hf_mac_lte_sr_leading_to_failure,
            { "This SR fails",
              "mac-lte.ulsch.failure-answering-sr-frame", FT_FRAMENUM, BASE_NONE, 0, 0x0,
              NULL, HFILL
            }
        },
        { &hf_mac_lte_sr_leading_to_grant,
            { "This SR results in a grant here",
              "mac-lte.ulsch.grant-answering-sr-frame", FT_FRAMENUM, BASE_NONE, 0, 0x0,
              NULL, HFILL
            }
        },
        { &hf_mac_lte_sr_invalid_event,
            { "Invalid event",
              "mac-lte.ulsch.sr-invalid-event", FT_NONE, BASE_NONE, 0, 0x0,
              NULL, HFILL
            }
        },
        { &hf_mac_lte_sr_time_since_request,
            { "Time since SR (ms)",
              "mac-lte.ulsch.time-since-sr", FT_UINT32, BASE_DEC, 0, 0x0,
              NULL, HFILL
            }
        },
        { &hf_mac_lte_sr_time_until_answer,
            { "Time until answer (ms)",
              "mac-lte.ulsch.time-until-sr-answer", FT_UINT32, BASE_DEC, 0, 0x0,
              NULL, HFILL
            }
        },

    };

    static gint *ett[] =
    {
        &ett_mac_lte,
        &ett_mac_lte_context,
        &ett_mac_lte_phy_context,
        &ett_mac_lte_rar_headers,
        &ett_mac_lte_rar_header,
        &ett_mac_lte_rar_body,
        &ett_mac_lte_rar_ul_grant,
        &ett_mac_lte_ulsch_header,
        &ett_mac_lte_dlsch_header,
        &ett_mac_lte_mch_header,
        &ett_mac_lte_sch_subheader,
        &ett_mac_lte_mch_subheader,
        &ett_mac_lte_bch,
        &ett_mac_lte_bsr,
        &ett_mac_lte_pch,
        &ett_mac_lte_contention_resolution,
        &ett_mac_lte_power_headroom,
        &ett_mac_lte_mch_scheduling_info,
        &ett_mac_lte_oob
    };

    static enum_val_t show_info_col_vals[] = {
        {"show-phy", "PHY Info", ShowPHYLayer},
        {"show-mac", "MAC Info", ShowMACLayer},
        {"show-rlc", "RLC Info", ShowRLCLayer},
        {NULL, NULL, -1}
    };

    static enum_val_t lcid_drb_source_vals[] = {
        {"from-static-stable",          "From static table",           FromStaticTable},
        {"from-configuration-protocol", "From configuration protocol", FromConfigurationProtocol},
        {NULL, NULL, -1}
    };


    module_t *mac_lte_module;

    static uat_field_t lcid_drb_mapping_flds[] = {
        UAT_FLD_VS(lcid_drb_mappings, lcid, "lcid", drb_lcid_vals, "The MAC LCID"),
        UAT_FLD_DEC(lcid_drb_mappings, drbid,"drb id (1-32)", "Identifier of logical data channel"),
        UAT_FLD_VS(lcid_drb_mappings, channel_type, "RLC Channel Type", rlc_channel_type_vals, "The MAC LCID"),
        UAT_END_FIELDS
    };

    /* Register protocol. */
    proto_mac_lte = proto_register_protocol("MAC-LTE", "MAC-LTE", "mac-lte");
    proto_register_field_array(proto_mac_lte, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

    /* Allow other dissectors to find this one by name. */
    register_dissector("mac-lte", dissect_mac_lte, proto_mac_lte);

    /* Register the tap name */
    mac_lte_tap = register_tap("mac-lte");

    /* Preferences */
    mac_lte_module = prefs_register_protocol(proto_mac_lte, NULL);

    /* Obsolete preferences */
    prefs_register_obsolete_preference(mac_lte_module, "single_rar");
    prefs_register_obsolete_preference(mac_lte_module, "check_reserved_bits");
    prefs_register_obsolete_preference(mac_lte_module, "decode_rar_ul_grant");
    prefs_register_obsolete_preference(mac_lte_module, "show_rlc_info_column");
    prefs_register_obsolete_preference(mac_lte_module, "attempt_to_detect_dl_harq_resend");
    prefs_register_obsolete_preference(mac_lte_module, "attempt_to_track_ul_harq_resend");

    prefs_register_uint_preference(mac_lte_module, "retx_count_warn",
        "Number of Re-Transmits before expert warning triggered",
        "Number of Re-Transmits before expert warning triggered",
        10, &global_mac_lte_retx_counter_trigger);

    prefs_register_bool_preference(mac_lte_module, "attempt_rrc_decode",
        "Attempt to decode BCH, PCH and CCCH data using LTE RRC dissector",
        "Attempt to decode BCH, PCH and CCCH data using LTE RRC dissector",
        &global_mac_lte_attempt_rrc_decode);

    prefs_register_bool_preference(mac_lte_module, "attempt_to_dissect_crc_failures",
        "Dissect frames that have failed CRC check",
        "Attempt to dissect frames that have failed CRC check",
        &global_mac_lte_dissect_crc_failures);

    prefs_register_bool_preference(mac_lte_module, "heuristic_mac_lte_over_udp",
        "Try Heuristic LTE-MAC over UDP framing",
        "When enabled, use heuristic dissector to find MAC-LTE frames sent with "
        "UDP framing",
        &global_mac_lte_heur);

    prefs_register_bool_preference(mac_lte_module, "attempt_to_dissect_srb_sdus",
        "Attempt to dissect LCID 1&2 as srb1&2",
        "Will call LTE RLC dissector with standard settings as per RRC spec",
        &global_mac_lte_attempt_srb_decode);

    prefs_register_enum_preference(mac_lte_module, "lcid_to_drb_mapping_source",
        "Source of LCID -> drb channel settings",
        "Set whether LCID -> drb Table is taken from static table (below) or from "
        "info learned from control protocol (e.g. RRC)",
        &global_mac_lte_lcid_drb_source, lcid_drb_source_vals, FALSE);

    lcid_drb_mappings_uat = uat_new("Static LCID -> drb Table",
                                    sizeof(lcid_drb_mapping_t),
                                    "drb_logchans",
                                    TRUE,
                                    (void*) &lcid_drb_mappings,
                                    &num_lcid_drb_mappings,
                                    UAT_CAT_FFMT,
                                    "",  /* TODO: is this ref to help manual? */
                                    lcid_drb_mapping_copy_cb,
                                    NULL,
                                    NULL,
                                    NULL,
                                    lcid_drb_mapping_flds );

    prefs_register_uat_preference(mac_lte_module,
                                  "drb_table",
                                  "LCID -> DRB Mappings Table",
                                  "A table that maps from configurable lcids -> RLC logical channels",
                                  lcid_drb_mappings_uat);

    prefs_register_uint_preference(mac_lte_module, "bsr_warn_threshold",
        "BSR size when warning should be issued (0 - 63)",
        "If any BSR report is >= this number, an expert warning will be added",
        10, &global_mac_lte_bsr_warn_threshold);

    prefs_register_bool_preference(mac_lte_module, "track_sr",
        "Track status of SRs within UEs",
        "Track status of SRs, providing links between requests, failure indications and grants",
        &global_mac_lte_track_sr);

    prefs_register_enum_preference(mac_lte_module, "layer_to_show",
        "Which layer info to show in Info column",
        "Can show PHY, MAC or RLC layer info in Info column",
        &global_mac_lte_layer_to_show, show_info_col_vals, FALSE);

    register_init_routine(&mac_lte_init_protocol);
}


/* Set LCID -> RLC channel mappings from signalling protocol (i.e. RRC or similar).
   TODO: not using UEID yet - assume all UEs configured identically... */
void set_mac_lte_channel_mapping(guint16 ueid _U_, guint8 lcid,
                                 guint8  srbid, guint8 drbid,
                                 guint8  rlcMode, guint8 um_sn_length,
                                 guint8  ul_priority)
{
    /* Don't bother setting srb details - we just assume AM */
    if (srbid != 0) {
        return;
    }

    /* Ignore if LCID is out of range */
    if ((lcid < 3) || (lcid > 10)) {
        return;
    }

    /* Set array entry */
    dynamic_lcid_drb_mapping[lcid].valid = TRUE;
    dynamic_lcid_drb_mapping[lcid].drbid = drbid;
    dynamic_lcid_drb_mapping[lcid].ul_priority = ul_priority;

    switch (rlcMode) {
        case RLC_AM_MODE:
            dynamic_lcid_drb_mapping[lcid].channel_type = rlcAM;
            break;
        case RLC_UM_MODE:
            if (um_sn_length == 5) {
                dynamic_lcid_drb_mapping[lcid].channel_type = rlcUM5;
            }
            else {
                dynamic_lcid_drb_mapping[lcid].channel_type = rlcUM10;
            }
            break;

        default:
            break;
    }
}

/* Return the configured UL priority for the channel */
static guint8 get_mac_lte_channel_priority(guint16 ueid _U_, guint8 lcid,
                                           guint8 direction)
{
    /* Priority only affects UL */
    if (direction == DIRECTION_DOWNLINK) {
        return 0;
    }

    /* Won't report value if channel not configured */
    if (!dynamic_lcid_drb_mapping[lcid].valid) {
        return 0;
    }
    else {
        return dynamic_lcid_drb_mapping[lcid].ul_priority;
    }
}

/* Function to be called from outside this module (e.g. in a plugin) to get per-packet data */
mac_lte_info *get_mac_lte_proto_data(packet_info *pinfo)
{
    return p_get_proto_data(pinfo->fd, proto_mac_lte);
}

/* Function to be called from outside this module (e.g. in a plugin) to set per-packet data */
void set_mac_lte_proto_data(packet_info *pinfo, mac_lte_info *p_mac_lte_info)
{
    p_add_proto_data(pinfo->fd, proto_mac_lte, p_mac_lte_info);
}

void proto_reg_handoff_mac_lte(void)
{
    static dissector_handle_t mac_lte_handle;
    if (!mac_lte_handle) {
        mac_lte_handle = find_dissector("mac-lte");

        /* Add as a heuristic UDP dissector */
        heur_dissector_add("udp", dissect_mac_lte_heur, proto_mac_lte);
    }
}

