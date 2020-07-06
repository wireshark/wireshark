/* packet-nfapi.c
 * Routines for Network Function Application Platform Interface (nFAPI) dissection
 * Copyright 2017 Cisco Systems, Inc.
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * References:
 * SCF082.09.04  http://scf.io/en/documents/082_-_nFAPI_and_FAPI_specifications.php
 *
 */

#include "config.h"

#include <epan/packet.h>
#include <epan/exceptions.h>
#include <epan/expert.h>
#include <epan/reassemble.h>
#include <epan/wmem/wmem.h>

#include <ptvcursor.h>

void proto_register_nfapi(void);
void proto_reg_handoff_nfapi(void);

#define NFAPI_HEADER_LENGTH 8
#define NFAPI_P7_HEADER_LENGTH 16

static const unit_name_string khz_100_units_db = { " (100)khz", NULL };

typedef enum{
	NFAPI_DL_CONFIG_REQUEST_MSG_ID = 0x0080,
	NFAPI_UL_CONFIG_REQUEST_MSG_ID,
	NFAPI_SUBFRAME_INDICATION_MSG_ID,
	NFAPI_HI_DCI0_REQUEST_MSG_ID,
	NFAPI_TX_REQUEST_MSG_ID,
	NFAPI_HARQ_INDICATION_MSG_ID,
	NFAPI_CRC_INDICATION_MSG_ID,
	NFAPI_RX_ULSCH_INDICATION_MSG_ID,
	NFAPI_RACH_INDICATION_MSG_ID,
	NFAPI_SRS_INDICATION_MSG_ID,
	NFAPI_RX_SR_INDICATION_MSG_ID,
	NFAPI_RX_CQI_INDICATION_MSG_ID,
	NFAPI_LBT_DL_CONFIG_REQUEST_MSG_ID,
	NFAPI_LBT_DL_INDICATION_MSG_ID,

	NFAPI_PNF_PARAM_REQUEST_MSG_ID = 0x0100,
	NFAPI_PNF_PARAM_RESPONSE_MSG_ID,
	NFAPI_PNF_CONFIG_REQUEST_MSG_ID,
	NFAPI_PNF_CONFIG_RESPONSE_MSG_ID,
	NFAPI_PNF_START_REQUEST_MSG_ID,
	NFAPI_PNF_START_RESPONSE_MSG_ID,
	NFAPI_PNF_STOP_REQUEST_MSG_ID,
	NFAPI_PNF_STOP_RESPONSE_MSG_ID,
	NFAPI_PARAM_REQUEST_MSG_ID,
	NFAPI_PARAM_RESPONSE_MSG_ID,
	NFAPI_CONFIG_REQUEST_MSG_ID,
	NFAPI_CONFIG_RESPONSE_MSG_ID,
	NFAPI_START_REQUEST_MSG_ID,
	NFAPI_START_RESPONSE_MSG_ID,
	NFAPI_STOP_REQUEST_MSG_ID,
	NFAPI_STOP_RESPONSE_MSG_ID,
	NFAPI_MEASUREMENT_REQUEST_MSG_ID,
	NFAPI_MEASUREMENT_RESPONSE_MSG_ID,

	NFAPI_DL_NODE_SYNC_MSG_ID = 0x0180,
	NFAPI_UL_NODE_SYNC_MSG_ID,
	NFAPI_TIMING_INFO_MSG_ID,

	NFAPI_RSSI_REQUEST_MSG_ID = 0x0200,
	NFAPI_RSSI_RESPONSE_MSG_ID,
	NFAPI_RSSI_INDICATION_MSG_ID,
	NFAPI_CELL_SEARCH_REQUEST_MSG_ID,
	NFAPI_CELL_SEARCH_RESPONSE_MSG_ID,
	NFAPI_CELL_SEARCH_INDICATION_MSG_ID,
	NFAPI_BROADCAST_DETECT_REQUEST_MSG_ID,
	NFAPI_BROADCAST_DETECT_RESPONSE_MSG_ID,
	NFAPI_BROADCAST_DETECT_INDICATION_MSG_ID,
	NFAPI_SYSTEM_INFORMATION_SCHEDULE_REQUEST_MSG_ID,
	NFAPI_SYSTEM_INFORMATION_SCHEDULE_RESPONSE_MSG_ID,
	NFAPI_SYSTEM_INFORMATION_SCHEDULE_INDICATION_MSG_ID,
	NFAPI_SYSTEM_INFORMATION_REQUEST_MSG_ID,
	NFAPI_SYSTEM_INFORMATION_RESPONSE_MSG_ID,
	NFAPI_SYSTEM_INFORMATION_INDICATION_MSG_ID,
	NFAPI_NMM_STOP_REQUEST_MSG_ID,
	NFAPI_NMM_STOP_RESPONSE_MSG_ID,
} nfapi_message_id_e;

static const value_string nfapi_error_vals[] = {
	{ 0x0, "MSG_OK" },
	{ 0x1, "MSG_INVALID_STATE" },
	{ 0x2, "MSG_INVALID_CONFIG" },
	{ 0x3, "SFN_OUT_OF_SYNC" },
	{ 0x4, "MSG_SUBFRAME_ERR" },
	{ 0x5, "MSG_BCH_MISSING" },
	{ 0x6, "MSG_BCH_MISSING" },
	{ 0x7, "MSG_HI_ERR" },
	{ 0x8, "MSG_TX_ERR" },
	{ 0, NULL },
};

static const value_string nfapi_p4_error_vals[] = {
	{ 100, "MSG_OK" },
	{ 101, "MSG_INVALID_STATE" },
	{ 102, "MSG_INVALID_CONFIG" },
	{ 103, "MSG_RAT_NOT_SUPPORTED" },
	{ 200, "MSG_NMM_STOP_OK" },
	{ 201, "MSG_NMM_STOP_IGNORED" },
	{ 202, "MSG_NMM_STOP_INVALID_STATE" },
	{ 300, "MSG_PROCEDURE_COMPLETE" },
	{ 301, "MSG_PROCEDURE_STOPPED" },
	{ 302, "MSG_PARTIAL_RESULTS" },
	{ 303, "MSG_TIMEOUT" },
	{ 0, NULL },
};

static const value_string nfapi_rat_type_vals[] = {
	{ 0, "LTE" },
	{ 1, "UTRAN" },
	{ 2, "GERAN" },
	{ 0, NULL },
};

typedef enum{
	UN_ALIGNED_SYNCHRONIZATION = 0,
	INTERNAL_PNF_FRAME_ALIGNMENT,
	ABSOLUTE_TIME_ALIGNED_SYNCHRONIZATION
} nfapi_sync_mode_e;

static const value_string nfapi_sync_mode_vals[] = {
	{ UN_ALIGNED_SYNCHRONIZATION, "UN-ALIGNED SYNCHRONIZATION" },
	{ INTERNAL_PNF_FRAME_ALIGNMENT, "INTERNAL PNF FRAME ALIGNMENT" },
	{ ABSOLUTE_TIME_ALIGNED_SYNCHRONIZATION, "ABSOLUTE TIME ALIGNED SYNCHRONIZATION" },
	{ 0, NULL },
};

typedef enum {
	NONE = 0,
	GPS,
	GLONASS,
	BEIDOU
} location_mode_e;

static const value_string location_mode_vals[] = {
	{ NONE, "NONE" },
	{ GPS, "GPS" },
	{ GLONASS, "GLONASS" },
	{ BEIDOU, "BeiDou" },
	{ 0, NULL }
};

static const value_string nfapi_uplink_rs_hopping_vals[] = {
	{ 0, "RS_NO_HOPPING" },
	{ 1, "RS_GROUP_HOPPING" },
	{ 2, "RS_SEQUENCE_HOPPING" },
	{ 0, NULL }
};

static const value_string nfapi_laa_carrier_type_vals[] = {
	{ 0, "No multi carrier support" },
	{ 1, "Mode A1" },
	{ 2, "Mode A12" },
	{ 3, "Mode B1" },
	{ 4, "Mode B2" },
	{ 0, NULL }
};

static const value_string nfapi_mutli_carrier_lbt_support_vals[] = {
	{ 0, "Multi carrier Mode A1" },
	{ 1, "Multi carrier Mode A2" },
	{ 2, "Multi carrier Mode B1" },
	{ 3, "Multi carrier Mode B2" },
	{ 0, NULL }
};

static const value_string nfapi_lbt_dl_req_pdu_type[] = {
	{ 0, "LBT_PDSCH_REQ PDU" },
	{ 1, "LBT_DRS_REQ PDU" },
	{ 0, NULL }
};


static const value_string nfapi_lbt_dl_ind_pdu_type[] = {
	{ 0, "LBT_PDSCH_RSP PDU" },
	{ 1, "LBT_DRS_RSP PDU" },
	{ 0, NULL }
};

static const value_string nfapi_phy_state_vals[] = {
	{ 0, "IDLE" },
	{ 1, "CONFIGURED" },
	{ 2, "RUNNING" },
	{ 0, NULL },
};


/* These are definitions where data 0 & 1 represent/provide a string name*/
static const true_false_string nfapi_csi_report_type_strname = {
	"Periodic",
	"Aperiodic",
};

static const true_false_string nfapi_control_type_string_name = {
	"CQI/PMI",
	"RI",
};

static const true_false_string cyclic_prefix_type_strname = {
	"CP_NORMAL",
	"CP_EXTENDED"
};

static const true_false_string support_strname = {
	"No Support",
	"Support"
};

static const true_false_string partial_sf_support_strname =
{
	"Start partial SF support",
	"End partial SF support"
};

static const true_false_string phich_duration_strname = {
	"PHICH_D_NORMAL",
	"PHICH_D_EXTENDED"
};

static const true_false_string high_speed_flag_strname = {
	"HS_UNRESTRICTED_SET",
	"HS_RESTRICTED_SET"
};

static const true_false_string hopping_mode_strname = {
	"HM_INTER_SF",
	"HM_INTRA_INTER_SF"
};

static const true_false_string srs_simult_tx_strname = {
	"No Simultaneous Transmission",
	"Simultaneous Transmission"
};

static const true_false_string crc_flag_strname = {
	"CRC_CORRECT",
	"CRC_ERROR"
};

static const true_false_string hi_value_strname = {
	"HI_NACK",
	"HI_ACK"
};

static const true_false_string flag_tb2_strname = {
	"HI_NOT_PRESENT",
	"HI_PRESENT"
};

static const true_false_string nfapi_multi_carrier_tx_strname = {
	"Mutual transmission (self-deferral support for current carrier)",
	"Transmit on channel access win (no self-deferral)"
};

static const true_false_string nfapi_multi_carrier_freeze_strname = {
	"Absence of other technology is not guaranteed",
	"Absence of other technology is guaranteed"
};

static const true_false_string initial_partial_sf_strname = {
	"Full SF",
	"Partial SF"
};

static const true_false_string lbt_mode_strname = {
	"Full LBT",
	"Partial LBT"
};

static const true_false_string data_report_mode_vals = {
	"Crc reported in CRC.indication",
	"Crc reported in RX.indication"
};

static const true_false_string mcch_flag_string_name = {
	"MCCH or SC-MCCH change notification field is not valid",
	"MCCH or SC-MCCH change notification field is valid"
};

static const true_false_string cross_carrier_scheduling_flag_strname = {
	"Carrier indicator field is not valid",
	"Carrier indicator field is valid"
};

static const true_false_string srs_flag_strname = {
	"SRS request field is not valid",
	"SRS request field is valid"
};
static const true_false_string srs_request_strname = {
	"SRS not requested",
	"SRS requested"
};

static const true_false_string ul_dl_configuration_flag_strname = {
	"UL/DL configuration field is not valid",
	"UL/DL configuration field is valid"
};

static const true_false_string prs_cyclic_prefix_type_strname = {
	"normal cyclic prefix",
	"extended cyclic prefix"
};

static const true_false_string prs_muting_strname = {
	"no muting",
	"muting"
};


static const value_string nfapi_dl_config_pdu_type_vals[] = {
	{ 0, "DL_CONFIG_DCI_DL_PDU" },
	{ 1, "DL_CONFIG_BCH_PDU" },
	{ 2, "DL_CONFIG_MCH_PDU" },
	{ 3, "DL_CONFIG_DLSCH_PDU" },
	{ 4, "DL_CONFIG_PCH_PDU" },
	{ 5, "DL_CONFIG_PRS_PDU" },
	{ 6, "DL_CONFIG_CSI_RS_PDU" },
	{ 7, "DL_CONFIG_EPDCCH_DL_PDU" },
	{ 8, "DL_CONFIG_EPDCCH_DL_PDU" },
	{ 0, NULL }
};

static const value_string nfapi_duplex_mode_vals[] = {
	{ 0, "TDD" },
	{ 1, "FDD" },
	{ 2, "HD-FDD" },
	{ 0, NULL }
};

static const value_string modulation_vals[] = {
	{ 2, "QPSK" },
	{ 4, "16QAM" },
	{ 6, "64QAM" },
	{ 8, "256QAM" },
	{ 0, NULL }
};

static const value_string pch_modulation_vals[] = {
	{ 0, "QPSK" },
	{ 0, NULL }
};

static const value_string ue_mode_vals[] = {
	{ 0, "non LC/CE UE" },
	{ 1, "LC/CE UE" },
	{ 0, NULL }
};

static const value_string csi_rs_class_vals[] = {
	{ 0, "not used" },
	{ 1, "Class A" },
	{ 2, "Class B" },
	{ 0, NULL }
};

static const value_string csi_rs_cdm_type_vals[] = {
	{ 0, "cdm 2" },
	{ 1, "cdm 4" },
	{ 0, NULL }
};

static const value_string antenna_ports_vals[] = {
	{ 0, "1 antenna ports" },
	{ 1, "2 antenna ports" },
	{ 2, "4 antenna ports" },
	{ 0, NULL }
};

static const value_string combs_vals[] = {
	{ 0, "2 TC" },
	{ 1, "4 TC" },
	{ 0, NULL }
};

static const value_string resource_allocation_type_vals[] = {
	{ 0, "type 0" },
	{ 1, "type 1" },
	{ 2, "type 2 1A/1B/1D" },
	{ 3, "type 2 1C" },
	{ 4, "type 2 6-1A" },
	{ 5, "type UEModeB" },
	{ 6, "NB Index" },
	{ 0, NULL }
};

static const value_string transmission_scheme_vals[] = {
	{ 0, "SINGLE_ANTENNA_PORT_0" },
	{ 1, "TX_DIVERSITY" },
	{ 2, "LARGE_DELAY_CDD" },
	{ 3, "CLOSED_LOOP_SPATIAL_MULTIPLEXING" },
	{ 4, "MULTI_USER_MIMO" },
	{ 5, "CLOSED_LOOP_RANK_1_PRECODING" },
	{ 6, "SINGLE_ANTENNA_PORT_5" },
	{ 7, "SINGLE_ANTENNA_PORT_7" },
	{ 8, "SINGLE_ANTENNA_PORT_8" },
	{ 9, "DUAL_LAYER_TX_PORT_7_AND_8" },
	{ 10, "UP_TO_8_LAYER_TX" },
	{ 11, "SINGLE_ANTENNA_PORT_11" },
	{ 12, "SINGLE_ANTENNA_PORT_13" },
	{ 13, "DUAL_LAYER_TX_PORT_11_13" },
	{ 0, NULL }
};

static const value_string ul_transmission_scheme_vals[] = {
	{ 0, "SINGLE_ANTENNA_PORT_10" },
	{ 1, "CLOSED_LOOP_SPATIAL_MULTIPLEXING" },
	{ 0, NULL },
};

static const value_string dl_dci_format_vals[] = {
	{ 0, "1" },
	{ 1, "1A" },
	{ 2, "1B" },
	{ 3, "1C" },
	{ 4, "1D" },
	{ 5, "2" },
	{ 6, "2A" },
	{ 7, "2B" },
	{ 8, "2C" },
	{ 9, "2D" },
	{ 10, "6-1A" },
	{ 11, "6-1B" },
	{ 12, "6-2" },
	{ 0, NULL }
};

static const value_string ul_dci_format_vals[] = {
	{ 0, "0" },
	{ 1, "3" },
	{ 2, "3A" },
	{ 3, "4" },
	{ 4, "5" },
	{ 0, NULL }
};

static const value_string mpdcch_ul_dci_format_vals[] = {
	{ 1, "3" },
	{ 2, "3A" },
	{ 4, "6-0A" },
	{ 5, "6-0B" },
	{ 0, NULL }
};


static const value_string pa_vals[] = {
	{ 0, "-6dB" },
	{ 1, "-4.77dB" },
	{ 2, "-3dB" },
	{ 3, "-1.77dB" },
	{ 4, "0dB" },
	{ 5, "1dB" },
	{ 6, "2dB" },
	{ 7, "3dB" },
	{ 0, NULL }
};

static const value_string transmission_mode_vals[] = {
	{ 1, "Mode 1" },
	{ 2, "Mode 2" },
	{ 3, "Mode 3" },
	{ 4, "Mode 4" },
	{ 5, "Mode 5" },
	{ 6, "Mode 6" },
	{ 7, "Mode 7" },
	{ 8, "Mode 8" },
	{ 9, "Mode 9" },
	{ 10, "Mode 10" },
	{ 0, NULL }
};

static const value_string nfapi_ul_config_pdu_type_vals[] = {
	{ 0, "ULSCH" },
	{ 1, "ULSCH_CQI_RI" },
	{ 2, "ULSCH_HARQ" },
	{ 3, "ULSCH_CQI_HARQ_RI" },
	{ 4, "UCI_CQI" },
	{ 5, "UCI_SR" },
	{ 6, "UCI_HARQ" },
	{ 7, "UCI_SR_HARQ" },
	{ 8, "UCI_CQI_HARQ" },
	{ 9, "UCI_CQI_SR" },
	{ 10, "UCI_CQI_SR_HARQ" },
	{ 11, "SRS" },
	{ 12, "HARQ_BUFFER" },
	{ 13, "ULSCH_UCI_CSI" },
	{ 14, "ULSCH_UCI_HARQ" },
	{ 15, "ULSCH_CSI_UCI_HARQ" },
	{ 0, NULL }
};

static const value_string nfapi_tdd_ack_nack_mode_vals[] = {
	{ 0, "Bundling" },
	{ 1, "Multiplexing" },
	{ 2, "Format 1b with channel selection" },
	{ 3, "Format 3" },
	{ 4, "Format 4" },
	{ 5, "Format 5" },
	{ 0, NULL }
};
static const value_string nfapi_fdd_ack_nack_mode_vals[] = {
	{ 0, "Format 1a/1b" },
	{ 1, "Channel selection" },
	{ 2, "Format 3" },
	{ 3, "Format 4" },
	{ 4, "Format 5" },
	{ 0, NULL }
};

static const value_string nfapi_phich_resource_vals[] = {
	{ 0, "PHICH_R_ONE_SIXTH " },
	{ 1, "PHICH_R_HALF" },
	{ 2, "PHICH_R_ONE" },
	{ 3, "PHICH_R_TWO" },
	{ 0, NULL }
};

static const value_string local_distributed_vals[] = {
	{ 0, "localized" },
	{ 1, "distributed" },
	{ 0, NULL }
};

static const value_string transport_block_to_codeword_swap_flag_vals[] = {
	{ 0, "no swapping" },
	{ 1, "swapped" },
	{ 0, NULL }
};

static const value_string ngap_vals[] = {
	{ 0, "Ngap1" },
	{ 1, "Ngap2" },
	{ 0, NULL }
};

static const value_string pmi_vals[] = {
	{ 0, "Use precoding indicated in TPMI field" },
	{ 1, "Use precoding indicated in last PMI report on PUSCH" },
	{ 2, "use precoding indicated in TPM field" },
	{ 0, NULL }
};

static const value_string true_false_vals[] = {
	{ 0, "false" },
	{ 1, "true" },
	{ 0, NULL }
};

static const value_string exhustive_search_vals[] = {
	{ 0, "non-exhaustive search" },
	{ 1, "exhaustive search" },
	{ 0, NULL }
};

static const value_string not_used_enabled_vals[] = {
	{ 0, "not used" },
	{ 1, "enabled" },
	{ 0, NULL }
};

static const value_string hopping_vals[] = {
	{ 0, "no hopping" },
	{ 1, "hopping enabled" },
	{ 0, NULL }
};


static const value_string mpdcch_rnti_type_vals[] = {
	{ 1, "Temporary C-RNTI" },
	{ 2, "RA-RNTI" },
	{ 3, "P-RNTI" },
	{ 4, "other" },
	{ 0, NULL }
};

static const value_string rnti_type_vals[] = {
	{ 1, "C-RNTI" },
	{ 2, "RA-RNTI, P-RNTI, SI-RNTI, SC-RNTI, G-RNTI" },
	{ 3, "SPS-CRNTI" },
	{ 0, NULL }
};

static const value_string primary_cells_type_vals[] = {
	{ 1, "TDD" },
	{ 2, "FDD" },
	{ 3, "HD_FDD" },
	{ 0, NULL }
};

static const value_string ul_rssi_supported_vals[] = {
	{ 0, "Uplink RSSI not supported" },
	{ 1, "Uplink RSSI supported" },
	{ 0, NULL }
};

static const value_string nprb_vals[] = {
	{ 0, "2" },
	{ 1, "3" },
	{ 0, NULL }
};

static const value_string nmm_modes_supported_vals[] =
{
	{ 0, "NONE" },
	{ 1, "NMM_ONLY" },
	{ 2, "NMM_IN_CONFIGURED_STATE" },
	{ 3, "NMM_IN_RUNNING_STATE" },
	{ 4, "NMM_IN_CONFIGURED_AND_RUNNING_STATE" },
	{ 0, NULL }
};

static const value_string dlsch_re13_ue_type_vals[] = {
	{ 0, "non LC/CE UE" },
	{ 1, "LC/CE CEModeA UE" },
	{ 2, "LC/CE CEModeB UE" },
	{ 0, NULL }
};

static const value_string dlsch_re13_pdsch_payload_type_vals[] = {
	{ 0, "PDSCH carrying SIB1-BR " },
	{ 1, "PDSCH carrying SI message (except for SIB1-BR or PCH)" },
	{ 2, "PDSCH carrying other" },
	{ 0, NULL }
};


static const value_string paging_direct_indication_differtiation_flag_vals[] = {
	{ 0, "Direct Information" },
	{ 1, "Paging" },
	{ 0, NULL }
};

static const value_string ul_tx_mode_vals[] = {
	{ 0, "SISO/MIMO" },
	{ 1, "MIMO" },
	{ 0, NULL }
};

static const value_string n_srs_vals[] = {
	{ 0, "No overlap" },
	{ 1, "Overlap" },
	{ 0, NULL }
};

static const value_string n_srs_initial_vals[] = {
	{ 0, "Last OFDM symbol is not punctured" },
	{ 1, "Last OFDM symbol is punctured." },
	{ 0, NULL }
};


static const value_string csi_mode_vals[] = {
	{ 0, "PUCCH format 2/2a/2b/3" },
	{ 1, "PUCCH format 4" },
	{ 2, "PUCCH format 5" },
	{ 0, NULL }
};

static const value_string hi_dci0_pdu_type_vals[] = {
	{ 0, "HI" },
	{ 1, "DCI UL" },
	{ 2, "EDPCCH DCI UL" },
	{ 3, "MDPCCH DCI UL" },
	{ 0, NULL }
};

static const value_string ue_tx_antenna_selection_vals[] = {
	{ 0, "Not Configured" },
	{ 1, "Configured and using UE port 0" },
	{ 2, "Configured and using UE port 1" },
	{ 0, NULL }
};

static const value_string size_of_cqi_csi_feild_vals[] = {
	{ 0, "1 bit" },
	{ 1, "2 bits" },
	{ 2, "3 bits" },
	{ 0, NULL }
};

static const value_string number_of_antenna_port_vals[] = {
	{ 0, "1 antenna port" },
	{ 1, "2 antenna ports" },
	{ 2, "4 antenna ports" },
	{ 0, NULL }
};

static const value_string ce_mode_vals[] = {
	{ 1, "CEModeA" },
	{ 2, "CEModeB" },
	{ 0, NULL }
};


static const value_string csi_request_vals[] = {
	{ 0, "Aperiodic CSI not requested" },
	{ 1, "Aperiodic CSI requested" },
	{ 0, NULL }
};

static const value_string tdd_harq_mode_vals[] = {
	{ 0, "Format 1a/1b BUNDLING" },
	{ 1, "Format 1a/1b MULTIPLEXING" },
	{ 2, "Format 1a/1b SPECIAL BUNDLING" },
	{ 3, "Channel Selection" },
	{ 4, "Format 3" },
	{ 5, "Format 4" },
	{ 6, "Format 5" },
	{ 0, NULL }
};

static const value_string fdd_harq_mode_vals[] = {
	{ 0, "Format 1a/1b" },
	{ 1, "Channel Selection" },
	{ 2, "Format 3" },
	{ 3, "Format 4" },
	{ 4, "Format 5" },
	{ 0, NULL }
};

static const value_string harq_value_vals[] = {
	{ 1, "ACK" },
	{ 2, "NACK" },
	{ 3, "ACK or NACK" },
	{ 4, "DTX" },
	{ 5, "ACK or DTX" },
	{ 6, "NACK or DTX" },
	{ 7, "ACK or NACK or DTX" },
	{ 0, NULL }
};


static const value_string harq_special_value_vals[] = {
	{ 0, "0 or None" },
	{ 1, "1 or 4 or 7 ACKs reported" },
	{ 2, "2 or 5 or 8 ACKs reported" },
	{ 3, "3 or 6 or 9 ACKs reported" },
	{ 4, "DTX (UE did not transmit anything)" },
	{ 0, NULL }
};

static const value_string channel_vals[] = {
	{ 0, "PUCCH" },
	{ 1, "PUSCH" },
	{ 0, NULL }
};

static const value_string rach_resource_type_vals[] = {
	{ 0, "Non LC / CE RACH" },
	{ 1, "LC / CE RACH CE level 0" },
	{ 2, "LC / CE RACH CE level 1" },
	{ 3, "LC / CE RACH CE level 2" },
	{ 4, "LC / CE RACH CE level 3" },
	{ 0, NULL }
};

static const value_string up_pts_symbol_vals[] = {
	{ 0, "Symbol 0" },
	{ 1, "Symbol 1" },
	{ 0, NULL }
};

static const value_string arfcn_direction_vals[] = {
	{ 0, "DL" },
	{ 1, "UL" },
	{ 0, NULL }
};

static int proto_nfapi = -1;

/* These are for the subtrees */
static gint ett_nfapi = -1;
static gint ett_nfapi_p4_p5_message_header = -1;
static gint ett_nfapi_p7_message_header = -1;
static gint ett_nfapi_tlv_tree = -1;
static gint ett_nfapi_tl = -1;
static gint ett_nfapi_pnf_phy = -1;
static gint ett_nfapi_pnf_phy_rel10 = -1;
static gint ett_nfapi_pnf_phy_rel11 = -1;
static gint ett_nfapi_pnf_phy_rel12 = -1;
static gint ett_nfapi_pnf_phy_rel13 = -1;
static gint ett_nfapi_pnf_phy_rf_config = -1;
static gint ett_nfapi_rf_bands = -1;
static gint ett_nfapi_tx_antenna_ports = -1;
static gint ett_nfapi_harq_ack_nack_data = -1;
static gint ett_nfapi_harq_data = -1;
static gint ett_nfapi_cc = -1;
static gint ett_nfapi_rbs = -1;
static gint ett_nfapi_antennas = -1;
static gint ett_nfapi_dl_config_request_pdu_list = -1;
static gint ett_nfapi_ul_config_request_pdu_list = -1;
static gint ett_nfapi_hi_dci0_request_pdu_list = -1;
static gint ett_nfapi_tx_request_pdu_list = -1;
static gint ett_nfapi_rx_indication_pdu_list = -1;
static gint ett_nfapi_harq_indication_pdu_list = -1;
static gint ett_nfapi_crc_indication_pdu_list = -1;
static gint ett_nfapi_sr_indication_pdu_list = -1;
static gint ett_nfapi_cqi_indication_pdu_list = -1;
static gint ett_nfapi_preamble_indication_pdu_list = -1;
static gint ett_nfapi_srs_indication_pdu_list = -1;
static gint ett_nfapi_lbt_dl_config_pdu_list = -1;
static gint ett_nfapi_lbt_dl_indication_pdu_list = -1;
static gint ett_nfapi_subbands = -1;
static gint ett_nfapi_bf_vector_antennas = -1;
static gint ett_nfapi_bf_vectors = -1;
static gint ett_nfapi_csi_rs_resource_configs = -1;
static gint ett_nfapi_csi_rs_bf_vector = -1;
static gint ett_nfapi_epdcch_prbs = -1;
static gint ett_nfapi_precoding = -1;
static gint ett_nfapi_earfcn_list = -1;
static gint ett_nfapi_uarfcn_list = -1;
static gint ett_nfapi_arfcn_list = -1;
static gint ett_nfapi_rssi_list = -1;
static gint ett_nfapi_pci_list = -1;
static gint ett_nfapi_psc_list = -1;
static gint ett_nfapi_lte_cells_found_list = -1;
static gint ett_nfapi_utran_cells_found_list = -1;
static gint ett_nfapi_geran_cells_found_list = -1;
static gint ett_nfapi_si_periodicity_list = -1;
static gint ett_nfapi_downlink_bandwidth_support = -1;
static gint ett_nfapi_uplink_bandwidth_support = -1;
static gint ett_nfapi_downlink_modulation_support = -1;
static gint ett_nfapi_uplink_modulation_support = -1;
static gint ett_nfapi_received_interference_power_mesurement_results = -1;
static gint ett_nfapi_release_support = -1;
static expert_field ei_invalid_range = EI_INIT;
static expert_field ei_invalid_tlv_length = EI_INIT;

static int hf_nfapi_p4_p5_message_header_phy_id = -1;
static int hf_nfapi_p4_p5_message_header_message_id = -1;
static int hf_nfapi_p4_p5_message_header_message_length = -1;
static int hf_nfapi_p4_p5_message_header_spare = -1;
static int hf_nfapi_p7_message_header_phy_id = -1;
static int hf_nfapi_p7_message_header_message_id = -1;
static int hf_nfapi_p7_message_header_message_length = -1;
static int hf_nfapi_p7_message_header_m = -1;
static int hf_nfapi_p7_message_header_segment = -1;
static int hf_nfapi_p7_message_header_sequence_number = -1;
static int hf_nfapi_p7_message_header_checksum = -1;
static int hf_nfapi_p7_message_header_transmit_timestamp = -1;
static int hf_nfapi_tl_tag = -1;
static int hf_nfapi_tl_length = -1;
static int hf_nfapi_sync_mode = -1;
static int hf_nfapi_location_mode = -1;
static int hf_nfapi_location_coordinates = -1;
static int hf_nfapi_dl_config_timing = -1;
static int hf_nfapi_tx_timing = -1;
static int hf_nfapi_ul_config_timing = -1;
static int hf_nfapi_hi_dci0_timing = -1;
static int hf_nfapi_maximum_number_phys = -1;
static int hf_nfapi_maximum_total_bandwidth = -1;
static int hf_nfapi_maximum_total_number_dl_layers = -1;
static int hf_nfapi_maximum_total_number_ul_layers = -1;
static int hf_nfapi_shared_bands = -1;
static int hf_nfapi_shared_pa = -1;
static int hf_nfapi_maximum_total_power = -1;
static int hf_nfapi_oui = -1;
static int hf_nfapi_pdu = -1;
static int hf_nfapi_pnf_phy_number_phy = -1;
static int hf_nfapi_pnf_phy_config_index = -1;
static int hf_nfapi_number_of_rf_exclusions = -1;
static int hf_nfapi_dl_bandwidth_support = -1;
static int hf_nfapi_dl_bandwidth_support_6 = -1;
static int hf_nfapi_dl_bandwidth_support_15 = -1;
static int hf_nfapi_dl_bandwidth_support_25 = -1;
static int hf_nfapi_dl_bandwidth_support_50 = -1;
static int hf_nfapi_dl_bandwidth_support_75 = -1;
static int hf_nfapi_dl_bandwidth_support_100 = -1;
static int hf_nfapi_ul_bandwidth_support = -1;
static int hf_nfapi_ul_bandwidth_support_6 = -1;
static int hf_nfapi_ul_bandwidth_support_15= -1;
static int hf_nfapi_ul_bandwidth_support_25 = -1;
static int hf_nfapi_ul_bandwidth_support_50 = -1;
static int hf_nfapi_ul_bandwidth_support_75 = -1;
static int hf_nfapi_ul_bandwidth_support_100 = -1;
static int hf_nfapi_downlink_channel_bandwidth_supported = -1;
static int hf_nfapi_uplink_channel_bandwidth_supported = -1;
static int hf_nfapi_number_of_dl_layers_supported = -1;
static int hf_nfapi_number_of_ul_layers_supported = -1;
static int hf_nfapi_maximum_3gpp_release_supported = -1;
static int hf_nfapi_maximum_3gpp_release_supported_rel8 = -1;
static int hf_nfapi_maximum_3gpp_release_supported_rel9 = -1;
static int hf_nfapi_maximum_3gpp_release_supported_rel10 = -1;
static int hf_nfapi_maximum_3gpp_release_supported_rel11 = -1;
static int hf_nfapi_maximum_3gpp_release_supported_rel12 = -1;
static int hf_nfapi_maximum_3gpp_release_supported_rel13 = -1;
static int hf_nfapi_nmm_modes_supported = -1;
static int hf_nfapi_number_of_rfs = -1;
static int hf_nfapi_rf_config_index = -1;
static int hf_nfapi_band = -1;
static int hf_nfapi_maximum_transmit_power = -1;
static int hf_nfapi_maximum_transmit_power_2 = -1;
static int hf_nfapi_earfcn = -1;
static int hf_nfapi_minimum_transmit_power = -1;
static int hf_nfapi_number_of_antennas_suppported = -1;
static int hf_nfapi_minimum_downlink_frequency = -1;
static int hf_nfapi_maximum_downlink_frequency = -1;
static int hf_nfapi_minimum_uplink_frequency = -1;
static int hf_nfapi_maximum_uplink_frequency = -1;
static int hf_nfapi_number_of_rf_bands = -1;
static int hf_nfapi_nmm_uplink_rssi_supported = -1;
static int hf_nfapi_phy_rf_config_info_phy_id = -1;
static int hf_nfapi_transmission_mode7_supported = -1;
static int hi_nfapi_transmission_mode8_supported = -1;
static int hi_nfapi_two_antennas_ports_for_pucch = -1;
static int hi_nfapi_transmission_mode_9_supported = -1;
static int hi_nfapi_simultaneous_pucch_pusch = -1;
static int hi_nfapi_four_layer_tx_with_tm3_and_tm4 = -1;
static int hf_nfapi_epdcch_supported = -1;
static int hi_nfapi_multi_ack_csi_reporting = -1;
static int hi_nfapi_pucch_tx_diversity_with_channel_selection = -1;
static int hi_nfapi_ul_comp_supported = -1;
static int hi_nfapi_transmission_mode_5_supported = -1;
static int hf_nfapi_csi_subframe_set = -1;
static int hi_nfapi_enhanced_4tx_codebook = -1;
static int hi_nfapi_drs_supported = -1;
static int hi_nfapi_ul_64qam_supported = -1;
static int hi_nfapi_transmission_mode_10_supported = -1;
static int hi_nfapi_alternative_tbs_indices = -1;
static int hf_nfapi_pucch_format_4_supported = -1;
static int hf_nfapi_pucch_format_5_supported = -1;
static int hf_nfapi_more_than_5_ca_supported = -1;
static int hf_nfapi_laa_supported = -1;
static int hf_nfapi_laa_ending_in_dwpts_supported = -1;
static int hf_nfapi_laa_starting_in_second_slot_supported = -1;
static int hf_nfapi_beamforming_supported = -1;
static int hf_nfapi_csi_rs_enhancements_supported = -1;
static int hf_nfapi_drms_enhancements_supported = -1;
static int hf_nfapi_srs_enhancements_supported = -1;
static int hf_nfapi_dl_rs_tx_power = -1;
static int hf_nfapi_received_interference_power = -1;
static int hf_nfapi_thermal_noise_power = -1;
static int hf_nfapi_dl_rs_tx_power_measurement = -1;
static int hf_nfapi_received_interference_power_measurement = -1;
static int hf_nfapi_thermal_noise_power_measurement = -1;

// P5 Message Structures
static int hf_nfapi_error_code = -1;
static int hf_nfapi_p4_error_code = -1;
static int hf_nfapi_rat_type = -1;
static int hf_nfapi_num_tlv = -1;
static int hf_nfapi_phy_state = -1;
static int hf_nfapi_phy_antenna_capability = -1;
static int hf_nfapi_release_capability = -1;
static int hf_nfapi_mbsfn_capability = -1;
static int hf_nfapi_laa_capability = -1;
static int hf_nfapi_pd_sensing_lbt_support = -1;
static int hf_nfapi_multi_carrier_lbt_support = -1;
static int hf_nfapi_partial_sf_support = -1;

static int hf_nfapi_pnf_address_ipv4 = -1;
static int hf_nfapi_pnf_address_ipv6 = -1;
static int hf_nfapi_vnf_address_ipv4 = -1;
static int hf_nfapi_vnf_address_ipv6 = -1;
static int hf_nfapi_pnf_port = -1;
static int hf_nfapi_vnf_port = -1;
static int hf_nfapi_dl_ue_per_sf = -1;
static int hf_nfapi_ul_ue_per_sf = -1;
static int hf_nfapi_timing_window = -1;
static int hf_nfapi_timing_info_mode = -1;
static int hf_nfapi_timing_info_period = -1;
static int hf_nfapi_duplex_mode = -1;
static int hf_nfapi_pcfich_power_offset = -1;
static int hf_nfapi_pb = -1;
static int hf_nfapi_dl_cyclic_prefix_type = -1;
static int hf_nfapi_ul_cyclic_prefix_type = -1;
static int hf_nfapi_tx_antenna_ports = -1;
static int hf_nfapi_rx_antenna_ports = -1;
static int hf_nfapi_downlink_channel_bandwidth = -1;
static int hf_nfapi_uplink_channel_bandwidth = -1;
static int hf_nfapi_reference_signal_power = -1;
static int hf_nfapi_phich_resource = -1;
static int hf_nfapi_phich_duration = -1;
static int hf_nfapi_phich_power_offset = -1;
static int hf_nfapi_primary_synchronization_signal_epre_eprers = -1;
static int hf_nfapi_secondary_synchronization_signal_epre_eprers = -1;
static int hf_nfapi_physical_cell_id = -1;
static int hf_nfapi_configuration_index = -1;
static int hf_nfapi_root_sequence_index = -1;
static int hf_nfapi_zero_correlation_zone_configuration = -1;
static int hf_nfapi_high_speed_flag = -1;
static int hf_nfapi_frequency_offset = -1;
static int hf_nfapi_hopping_mode = -1;
static int hf_nfapi_hopping_offset = -1;
static int hf_nfapi_delta_pucch_shift = -1;
static int hf_nfapi_n_cqi_rb = -1;
static int hf_nfapi_n_an_cs = -1;
static int hf_nfapi_n1_pucch_an = -1;
static int hf_nfapi_bandwidth_configuration = -1;
static int hf_nfapi_max_up_pts = -1;
static int hf_nfapi_srs_subframe_configuration = -1;
static int hf_nfapi_srs_acknack_srs_simultaneous_transmission = -1;
static int hf_nfapi_uplink_rs_hopping = -1;
static int hf_nfapi_group_assignment = -1;
static int hf_nfapi_cyclic_shift_1_for_drms = -1;
static int hf_nfapi_subframe_assignment = -1;
static int hf_nfapi_special_subframe_patterns = -1;
static int hf_nfapi_ed_threshold_for_lbt_for_pdsch = -1;
static int hf_nfapi_ed_threshold_for_lbt_for_drs = -1;
static int hf_nfapi_pd_threshold = -1;
static int hf_nfapi_multi_carrier_type = -1;
static int hf_nfapi_multi_carrier_tx = -1;
static int hf_nfapi_multi_carrier_freeze = -1;
static int hf_nfapi_tx_antenna_ports_for_drs = -1;
static int hf_nfapi_transmission_power_for_drs = -1;
static int hf_nfapi_pbch_repetitions_enabled_r13 = -1;
static int hf_nfapi_prach_cat_m_root_sequence_index = -1;
static int hf_nfapi_prach_cat_m_zero_correlation_zone_configuration = -1;
static int hf_nfapi_prach_cat_m_high_speed_flag = -1;
static int hf_nfapi_prach_ce_level_0_enable = -1;
static int hf_nfapi_prach_ce_level_0_configuration_index = -1;
static int hf_nfapi_prach_ce_level_0_frequency_offset = -1;
static int hf_nfapi_prach_ce_level_0_number_of_repetitions_per_attempt = -1;
static int hf_nfapi_prach_ce_level_0_starting_subframe_periodicity = -1;
static int hf_nfapi_prach_ce_level_0_hopping_enabled = -1;
static int hf_nfapi_prach_ce_level_0_hopping_offset = -1;
static int hf_nfapi_prach_ce_level_1_enable = -1;
static int hf_nfapi_prach_ce_level_1_configuration_index = -1;
static int hf_nfapi_prach_ce_level_1_frequency_offset = -1;
static int hf_nfapi_prach_ce_level_1_number_of_repetitions_per_attempt = -1;
static int hf_nfapi_prach_ce_level_1_starting_subframe_periodicity = -1;
static int hf_nfapi_prach_ce_level_1_hopping_enabled = -1;
static int hf_nfapi_prach_ce_level_1_hopping_offset = -1;
static int hf_nfapi_prach_ce_level_2_enable = -1;
static int hf_nfapi_prach_ce_level_2_configuration_index = -1;
static int hf_nfapi_prach_ce_level_2_frequency_offset = -1;
static int hf_nfapi_prach_ce_level_2_number_of_repetitions_per_attempt = -1;
static int hf_nfapi_prach_ce_level_2_starting_subframe_periodicity = -1;
static int hf_nfapi_prach_ce_level_2_hopping_enabled = -1;
static int hf_nfapi_prach_ce_level_2_hopping_offset = -1;
static int hf_nfapi_prach_ce_level_3_enable = -1;
static int hf_nfapi_prach_ce_level_3_configuration_index = -1;
static int hf_nfapi_prach_ce_level_3_frequency_offset = -1;
static int hf_nfapi_prach_ce_level_3_number_of_repetitions_per_attempt = -1;
static int hf_nfapi_prach_ce_level_3_starting_subframe_periodicity = -1;
static int hf_nfapi_prach_ce_level_3_hopping_enabled = -1;
static int hf_nfapi_prach_ce_level_3_hopping_offset = -1;
static int hf_nfapi_pucch_internal_ul_hopping_config_common_mode_b = -1;
static int hf_nfapi_pucch_internal_ul_hopping_config_common_mode_a = -1;
static int hf_nfapi_dl_modulation_support = -1;
static int hf_nfapi_dl_modulation_support_qpsk = -1;
static int hf_nfapi_dl_modulation_support_16qam = -1;
static int hf_nfapi_dl_modulation_support_64qam = -1;
static int hf_nfapi_dl_modulation_support_256qam = -1;
static int hf_nfapi_ul_modulation_support = -1;
static int hf_nfapi_ul_modulation_support_qpsk = -1;
static int hf_nfapi_ul_modulation_support_16qam = -1;
static int hf_nfapi_ul_modulation_support_64qam = -1;
static int hf_nfapi_data_report_mode = -1;
static int hf_nfapi_sfnsf = -1;

// P7 Sub Structures
static int hf_nfapi_dl_dci_format = -1;
static int hf_nfapi_ul_dci_format = -1;
static int hf_nfapi_mpdcch_ul_dci_format = -1;
static int hf_nfapi_cce_idx = -1;
static int hf_nfapi_aggregation_level = -1;
static int hf_nfapi_mcs_1 = -1;
static int hf_nfapi_redundancy_version_1 = -1;
static int hf_nfapi_new_data_indicator_1 = -1;
static int hf_nfapi_mcs_2 = -1;
static int hf_nfapi_redundancy_version_2 = -1;
static int hf_nfapi_new_data_indicator_2 = -1;
static int hf_nfapi_harq_process = -1;
static int hf_nfapi_tpmi = -1;
static int hf_nfapi_pmi = -1;
static int hf_nfapi_precoding_information = -1;
static int hf_nfapi_tpc = -1;
static int hf_nfapi_downlink_assignment_index = -1;
static int hf_nfapi_transport_block_size_index = -1;
static int hf_nfapi_downlink_power_offset = -1;
static int hf_nfapi_allocate_prach_flag = -1;
static int hf_nfapi_preamble_index = -1;
static int hf_nfapi_prach_mask_index = -1;
static int hf_nfapi_rnti_type = -1;
static int hf_nfapi_mpdcch_rnti_type = -1;
static int hf_nfapi_mcch_flag = -1;
static int hf_nfapi_mcch_change_notification = -1;
static int hf_nfapi_scrambling_identity = -1;
static int hf_nfapi_cross_carrier_scheduling_flag = -1;
static int hf_nfapi_carrier_indicator = -1;
static int hf_nfapi_srs_flag = -1;
static int hf_nfapi_srs_request = -1;
static int hf_nfapi_antenna_ports_scrambling_and_layers = -1;
static int hf_nfapi_total_dci_length_including_padding = -1;
static int hf_nfapi_harq_ack_resource_offset = -1;
static int hf_nfapi_pdsch_re_mapping_and_quasi_co_location_indicator = -1;
static int hf_nfapi_primary_cell_type = -1;
static int hf_nfapi_ul_dl_configuration_flag = -1;
static int hf_nfapi_number_of_ul_dl_configurations = -1;
static int hf_nfapi_ul_dl_configuration_index = -1;
static int hf_nfapi_laa_end_partial_sf_flag = -1;
static int hf_nfapi_laa_end_partial_sf_configuration = -1;
static int hf_nfapi_initial_lbt_sf = -1;
static int hf_nfapi_codebooksize_determination_r13 = -1;
static int hf_nfapi_rel13_drms_table_flag = -1;
static int hf_nfapi_csi_rs_resource_config = -1;
static int hf_nfapi_csi_rs_number_of_nzp_configurations = -1;
static int hf_nfapi_pdsch_start = -1;
static int hf_nfapi_drms_config_flag = -1;
static int hf_nfapi_drms_scrambling = -1;
static int hf_nfapi_csi_config_flag = -1;
static int hf_nfapi_csi_scrambling = -1;
static int hf_nfapi_pdsch_re_mapping_flag = -1;
static int hf_nfapi_pdsch_re_mapping_antenna_ports = -1;
static int hf_nfapi_pdsch_re_mapping_freq_shift = -1;
static int hf_nfapi_alt_cqi_table_r12 = -1;
static int hf_nfapi_max_layers = -1;
static int hf_nfapi_n_dl_harq = -1;
static int hf_nfapi_dwpts_symbols = -1;
static int hf_nfapi_ue_type = -1;
static int hf_nfapi_pdsch_payload_type = -1;
static int hf_nfapi_initial_transmission_sf = -1;
static int hf_nfapi_req13_drms_table_flag = -1;
static int hf_nfapi_prnti = -1;
static int hf_nfapi_mcs = -1;
static int hf_nfapi_number_of_transport_blocks = -1;
static int hf_nfapi_ue_mode = -1;
static int hf_prs_bandwidth = -1;
static int hf_prs_cyclic_prefix_type = -1;
static int hf_prs_muting = -1;
static int hf_nfapi_csi_rs_resource_index = -1;
static int hf_nfapi_csi_rs_class = -1;
static int hf_nfapi_cdm_type = -1;
static int hf_nfapi_edpcch_prb_index = -1;
static int hf_nfapi_epdcch_resource_assignment_flag = -1;
static int hf_nfapi_epdcch_id = -1;
static int hf_nfapi_epdcch_start_symbol = -1;
static int hf_nfapi_epdcch_num_prb = -1;
static int hf_nfapi_precoding_value = -1;
static int hf_nfapi_mpdcch_narrowband = -1;
static int hf_nfapi_number_of_prb_pairs = -1;
static int hf_nfapi_resource_block_assignment = -1;
static int hf_nfapi_start_symbol = -1;
static int hf_nfapi_ecce_index = -1;
static int hf_nfapi_ce_mode = -1;
static int hf_nfapi_drms_scrabmling_init = -1;
static int hf_nfapi_pdsch_reception_levels = -1;
static int hf_nfapi_new_data_indicator = -1;
static int hf_nfapi_tpmi_length = -1;
static int hf_nfapi_pmi_flag = -1;
static int hf_nfapi_harq_resource_offset = -1;
static int hf_nfapi_dci_subframe_repetition_number = -1;
static int hf_nfapi_downlink_assignment_index_length = -1;
static int hf_nfapi_starting_ce_level = -1;
static int hf_nfapi_antenna_ports_and_scrambling_identity_flag = -1;
static int hf_nfapi_antenna_ports_and_scrambling_identity = -1;
static int hf_nfapi_paging_direct_indication_differentiation_flag = -1;
static int hf_nfapi_direct_indication = -1;
static int hf_nfapi_number_of_tx_antenna_ports = -1;

// P7 Message Structures
static int hf_nfapi_dl_node_sync_t1 = -1;
static int hf_nfapi_dl_node_sync_delta_sfn_sf = -1;
static int hf_nfapi_ul_node_sync_t1 = -1;
static int hf_nfapi_ul_node_sync_t2 = -1;
static int hf_nfapi_ul_node_sync_t3 = -1;
static int hf_nfapi_timing_info_last_sfn_sf = -1;
static int hf_nfapi_timing_info_time_since_last_timing_info = -1;
static int hf_nfapi_timing_info_dl_config_jitter = -1;
static int hf_nfapi_timing_info_tx_request_jitter = -1;
static int hf_nfapi_timing_info_ul_config_jitter = -1;
static int hf_nfapi_timing_info_hi_dci0_jitter = -1;
static int hf_nfapi_timing_info_dl_config_latest_delay = -1;
static int hf_nfapi_timing_info_tx_request_latest_delay = -1;
static int hf_nfapi_timing_info_ul_config_latest_delay = -1;
static int hf_nfapi_timing_info_hi_dci0_latest_delay = -1;
static int hf_nfapi_timing_info_dl_config_earliest_arrival = -1;
static int hf_nfapi_timing_info_tx_request_earliest_arrival = -1;
static int hf_nfapi_timing_info_ul_config_earliest_arrival = -1;
static int hf_nfapi_timing_info_hi_dci0_earliest_arrival = -1;
static int hf_nfapi_sfn_sf = -1;
static int hf_nfapi_number_pdcch_ofdm_symbols = -1;
static int hf_nfapi_number_dci = -1;
static int hf_nfapi_number_pdus = -1;
static int hf_nfapi_number_pdsch_rnti = -1;
static int hf_nfapi_transmission_power_pcfich = -1;
static int hf_nfapi_number_of_harqs = -1;
static int hf_nfapi_number_of_crcs = -1;
static int hf_nfapi_number_of_srs = -1;
static int hf_nfapi_number_of_cqi = -1;
static int hf_nfapi_number_of_preambles = -1;
static int hf_nfapi_number_of_srss = -1;
static int hf_nfapi_lbt_dl_req_pdu_type = -1;
static int hf_nfapi_lbt_dl_ind_pdu_type = -1;
static int hf_nfapi_dl_config_pdu_type = -1;
static int hf_nfapi_pdu_size = -1;
static int hf_nfapi_instance_length = -1;
static int hf_nfapi_length;
static int hf_nfapi_pdu_index = -1;
static int hf_nfapi_rnti = -1;
static int hf_nfapi_resource_allocation_type = -1;
static int hf_nfapi_virtual_resource_block_assignment_flag = -1;
static int hf_nfapi_resource_block_coding = -1;
static int hf_nfapi_modulation = -1;
static int hf_nfapi_redundancy_version = -1;
static int hf_nfapi_transport_blocks = -1;
static int hf_nfapi_transport_block_to_codeword_swap_flag = -1;
static int hf_nfapi_transmission_scheme = -1;
static int hf_nfapi_ul_transmission_scheme = -1;
static int hf_nfapi_number_of_layers = -1;
static int hf_nfapi_number_of_subbands = -1;
static int hf_nfapi_codebook_index = -1;
static int hf_nfapi_ue_category_capacity = -1;
static int hf_nfapi_pa = -1;
static int hf_nfapi_delta_power_offset_index = -1;
static int hf_nfapi_ngap = -1;
static int hf_nfapi_nprb = -1;
static int hf_nfapi_transmission_mode = -1;
static int hf_nfapi_num_bf_prb_per_subband = -1;
static int hf_nfapi_num_bf_vector = -1;
static int hf_nfapi_bf_vector_subband_index = -1;
static int hf_nfapi_bf_vector_num_antennas = -1;
static int hf_nfapi_bf_vector_bf_value = -1;
static int hf_nfapi_nscid = -1;
static int hf_nfapi_csi_rs_flag = -1;
static int hf_nfapi_csi_rs_resource_config_r10 = -1;
static int hf_nfapi_csi_rs_zero_tx_power_resource_config_bitmap_r10 = -1;
static int hf_nfapi_transmission_power = -1;
static int hf_nfapi_mbsfn_area_id = -1;
static int hf_nfapi_csi_rs_antenna_port_count_r10 = -1;
static int hf_nfapi_ul_config_pdu_type = -1;
static int hf_nfapi_rach_prach_frequency_resources = -1;
static int hf_nfapi_srs_present = -1;
static int hf_nfapi_handle = -1;
static int hf_nfapi_pucch_index = -1;
static int hf_nfapi_size = -1;
static int hf_nfapi_resource_block_start = -1;
static int hf_nfapi_number_of_resource_blocks = -1;
static int hf_nfapi_cyclic_shift_2_for_drms = -1;
static int hf_nfapi_frequency_hopping_enabled_flag = -1;
static int hf_nfapi_frequency_hopping_bits = -1;
static int hf_nfapi_new_data_indication = -1;
static int hf_nfapi_harq_process_number = -1;
static int hf_nfapi_ul_tx_mode = -1;
static int hf_nfapi_current_tx_nb = -1;
static int hf_nfapi_n_srs = -1;
static int hf_nfapi_disable_sequence_hopping_flag = -1;
static int hf_nfapi_dl_cqi_pmi_size_rank_1 = -1;
static int hf_nfapi_dl_cqi_pmi_size_rank_greater_1 = -1;
static int hf_nfapi_ri_size = -1;
static int hf_nfapi_delta_offset_cqi = -1;
static int hf_nfapi_delta_offset_ri = -1;
static int hf_nfapi_harq_size = -1;
static int hf_nfapi_delta_offset_harq = -1;
static int hf_nfapi_tdd_ack_nack_mode = -1;
static int hf_nfapi_fdd_ack_nack_mode = -1;
static int hf_nfapi_n_srs_initial = -1;
static int hf_nfapi_initial_number_of_resource_blocks = -1;
static int hf_nfapi_dl_cqi_pmi_size = -1;
static int hf_nfapi_report_type = -1;
static int hf_nfapi_dl_cqi_ri_pmi_size = -1;
static int hf_nfapi_control_type = -1;
static int hf_nfapi_number_of_cc = -1;
static int hf_nfapi_virtual_cell_id_enabled_flag = -1;
static int hf_nfapi_npusch_identity = -1;
static int hf_nfapi_ndrms_csh_identity = -1;
static int hf_nfapi_total_number_of_repetitions = -1;
static int hf_nfapi_repetition_number = -1;
static int hf_nfapi_initial_sf_io = -1;
static int hf_nfapi_empty_symbols_due_to_retunning = -1;
static int hf_nfapi_dl_cqi_ri_pmi_size_2 = -1;
static int hf_nfapi_npucch_identity = -1;
static int hf_nfapi_harq_size_2 = -1;
static int hf_nfapi_delta_offset_harq_2 = -1;
static int hf_nfapi_empty_symbols = -1;
static int hf_nfapi_csi_mode = -1;
static int hf_nfapi_dl_cqi_pmi_size_2 = -1;
static int hf_nfapi_statring_prb = -1;
static int hf_nfapi_cdm_index = -1;
static int hf_nfapi_nsrs = -1;
static int hf_nfapi_num_ant_ports = -1;
static int hf_nfapi_n_pucch_2_0 = -1;
static int hf_nfapi_n_pucch_2_1 = -1;
static int hf_nfapi_n_pucch_2_2 = -1;
static int hf_nfapi_n_pucch_2_3 = -1;
static int hf_nfapi_starting_prb = -1;
static int hf_nfapi_antenna_port = -1;
static int hf_nfapi_number_of_combs = -1;
static int hf_nfapi_number_of_pucch_resource = -1;
static int hf_nfapi_pucch_index_p1 = -1;
static int hf_nfapi_n_pucch_1_0 = -1;
static int hf_nfapi_n_pucch_1_1 = -1;
static int hf_nfapi_n_pucch_1_2 = -1;
static int hf_nfapi_n_pucch_1_3 = -1;
static int hf_nfapi_srs_bandwidth = -1;
static int hf_nfapi_frequency_domain_position = -1;
static int hf_nfapi_srs_hopping_bandwidth = -1;
static int hf_nfapi_transmission_comb = -1;
static int hf_nfapi_i_srs = -1;
static int hf_nfapi_sounding_reference_cyclic_shift = -1;
static int hf_nfapi_pdu_length = -1;
static int hf_nfapi_crc_flag = -1;
static int hf_nfapi_number_of_hi_pdus = -1;
static int hf_nfapi_number_of_dci_pdus = -1;
static int hf_nfapi_hi_dci0_pdu_type = -1;
static int hf_nfapi_hi_value = -1;
static int hf_nfapi_i_phich = -1;
static int hf_nfapi_flag_tb2 = -1;
static int hf_nfapi_hi_value_2 = -1;
static int hf_nfapi_ue_tx_antenna_selection = -1;
static int hf_nfapi_cqi_csi_request = -1;
static int hf_nfapi_ul_index = -1;
static int hf_nfapi_dl_assignment_index = -1;
static int hf_nfapi_tpc_bitmap = -1;
static int hf_nfapi_new_data_indication_two = -1;
static int hf_nfapi_size_of_cqi_csi_feild = -1;
static int hf_nfapi_resource_allocation_flag = -1;
static int hf_nfapi_number_of_antenna_ports = -1;
static int hf_nfapi_n_ul_rb = -1;
static int hf_nfapi_pscch_resource = -1;
static int hf_nfapi_time_resource_pattern = -1;
static int hf_nfapi_mpdcch_transmission_type = -1;
static int hf_nfapi_drms_scrambling_init = -1;
static int hf_nfapi_pusch_repetition_levels = -1;
static int hf_nfapi_frequency_hopping_flag = -1;
static int hf_nfapi_csi_request = -1;
static int hf_nfapi_dai_presence_flag = -1;
static int hf_nfapi_total_dci_length_include_padding = -1;
static int hf_nfapi_data_offset = -1;
static int hf_nfapi_ul_cqi = -1;
static int hf_nfapi_timing_advance_r9 = -1;
static int hf_nfapi_timing_advance = -1;
static int hf_nfapi_harq_data_value_0 = -1;
static int hf_nfapi_harq_data_value_0_special = -1;
static int hf_nfapi_harq_data_value_1 = -1;
static int hf_nfapi_harq_data_value_2 = -1;
static int hf_nfapi_harq_data_value_3 = -1;
static int hf_nfapi_tdd_harq_mode = -1;
static int hf_nfapi_fdd_harq_mode = -1;
static int hf_nfapi_number_of_ack_nack = -1;
static int hf_nfapi_harq_tb_1 = -1;
static int hf_nfapi_harq_tb_2 = -1;
static int hf_nfapi_harq_tb_n = -1;
static int hf_nfapi_channel = -1;
static int hf_nfapi_ri = -1;
static int hf_nfapi_number_of_cc_reported = -1;
static int hf_nfapi_preamble = -1;
static int hf_nfapi_rach_resource_type = -1;
static int hf_nfapi_snr = -1;
static int hf_nfapi_doppler_estimation = -1;
static int hf_nfapi_rb_start = -1;
static int hf_nfapi_up_pts_symbol = -1;
static int hf_nfapi_number_prb_per_subband = -1;
static int hf_nfapi_number_antennas = -1;
static int hf_nfapi_subband_index = -1;
static int hf_nfapi_channel_coefficient = -1;
static int hf_nfapi_ul_rtoa = -1;
static int hf_nfapi_mp_cca = -1;
static int hf_nfapi_n_cca = -1;
static int hf_nfapi_offset = -1;
static int hf_nfapi_lte_txop_sf = -1;
static int hf_nfapi_txop_sfn_sf_end = -1;
static int hf_nfapi_lbt_mode = -1;
static int hf_nfapi_sfn_sf_end = -1;
static int hf_nfapi_result = -1;
static int hf_nfapi_txop_symbols = -1;
static int hf_nfapi_initial_partial_sf = -1;
static int hf_nfapi_frequency_band_indicator = -1;
static int hf_nfapi_measurement_period = -1;
static int hf_nfapi_bandwidth = -1;
static int hf_nfapi_timeout = -1;
static int hf_nfapi_number_of_earfcns = -1;
static int hf_nfapi_uarfcn = -1;
static int hf_nfapi_number_of_uarfcns = -1;
static int hf_nfapi_arfcn = -1;
static int hf_nfapi_arfcn_direction = -1;
static int hf_nfapi_number_of_arfcns = -1;
static int hf_nfapi_rssi = -1;
static int hf_nfapi_number_of_rssi = -1;
static int hf_nfapi_pci = -1;
static int hf_nfapi_measurement_bandwidth = -1;
static int hf_nfapi_exhaustive_search = -1;
static int hf_nfapi_number_of_pci = -1;
static int hf_nfapi_psc = -1;
static int hf_nfapi_number_of_psc = -1;
static int hf_nfapi_rsrp = -1;
static int hf_nfapi_rsrq = -1;
static int hf_nfapi_number_of_lte_cells_found = -1;
static int hf_nfapi_rscp = -1;
static int hf_nfapi_enco = -1;
static int hf_nfapi_number_of_utran_cells_found = -1;
static int hf_nfapi_bsic = -1;
static int hf_nfapi_rxlev = -1;
static int hf_nfapi_rxqual = -1;
static int hf_nfapi_sfn_offset = -1;
static int hf_nfapi_number_of_geran_cells_found = -1;
static int hf_nfapi_number_of_tx_antenna = -1;
static int hf_nfapi_mib = -1;
static int hf_nfapi_phich_configuration = -1;
static int hf_nfapi_retry_count = -1;
static int hf_nfapi_sib1 = -1;
static int hf_nfapi_si_periodicity = -1;
static int hf_nfapi_si_index = -1;
static int hf_nfapi_number_of_si_periodicity = -1;
static int hf_nfapi_si_window_length = -1;
static int hf_nfapi_sib_type = -1;
static int hf_nfapi_sib = -1;
static int hf_nfapi_si = -1;
static int hf_nfapi_pnf_search_state = -1;
static int hf_nfapi_pnf_broadcast_state = -1;

static const value_string message_id_vals[] =
{
	{ NFAPI_DL_CONFIG_REQUEST_MSG_ID, "DL_CONFIG.request" },
	{ NFAPI_UL_CONFIG_REQUEST_MSG_ID, "UL_CONFIG.request" },
	{ NFAPI_SUBFRAME_INDICATION_MSG_ID, "SUBFRAME_INDICATION" },
	{ NFAPI_HI_DCI0_REQUEST_MSG_ID, "HI_DCI0.request" },
	{ NFAPI_TX_REQUEST_MSG_ID, "TX.request" },
	{ NFAPI_HARQ_INDICATION_MSG_ID, "HARQ.indication" },
	{ NFAPI_CRC_INDICATION_MSG_ID, "CRC.indication" },
	{ NFAPI_RX_ULSCH_INDICATION_MSG_ID, "RX_ULSCH.indication" },
	{ NFAPI_RACH_INDICATION_MSG_ID, "RACH.indication" },
	{ NFAPI_SRS_INDICATION_MSG_ID, "SRS.indication" },
	{ NFAPI_RX_SR_INDICATION_MSG_ID, "RX_SR.indication" },
	{ NFAPI_RX_CQI_INDICATION_MSG_ID, "RX_CQI.indication" },
	{ NFAPI_LBT_DL_CONFIG_REQUEST_MSG_ID, "LBT_DL_CONFIG.request" },
	{ NFAPI_LBT_DL_INDICATION_MSG_ID, "LBT_DL.indication" },

	{ NFAPI_PNF_PARAM_REQUEST_MSG_ID, "PNF_PARAM.request" },
	{ NFAPI_PNF_PARAM_RESPONSE_MSG_ID, "PNF_PARAM.response" },
	{ NFAPI_PNF_CONFIG_REQUEST_MSG_ID, "PNF_CONFIG.request" },
	{ NFAPI_PNF_CONFIG_RESPONSE_MSG_ID, "PNF_CONFIG.response" },
	{ NFAPI_PNF_START_REQUEST_MSG_ID, "PNF_START.request" },
	{ NFAPI_PNF_START_RESPONSE_MSG_ID, "PNF_START.response" },
	{ NFAPI_PNF_STOP_REQUEST_MSG_ID, "PNF_STOP.request" },
	{ NFAPI_PNF_STOP_RESPONSE_MSG_ID, "PNF_STOP.response" },
	{ NFAPI_PARAM_REQUEST_MSG_ID, "PARAM.request" },
	{ NFAPI_PARAM_RESPONSE_MSG_ID, "PARAM.response" },
	{ NFAPI_CONFIG_REQUEST_MSG_ID, "CONFIG.request" },
	{ NFAPI_CONFIG_RESPONSE_MSG_ID, "CONFIG.response" },
	{ NFAPI_START_REQUEST_MSG_ID, "START.request" },
	{ NFAPI_START_RESPONSE_MSG_ID, "START.response" },
	{ NFAPI_STOP_REQUEST_MSG_ID, "STOP.request" },
	{ NFAPI_STOP_RESPONSE_MSG_ID, "STOP.response" },
	{ NFAPI_MEASUREMENT_REQUEST_MSG_ID, "MEASUREMENT.request" },
	{ NFAPI_MEASUREMENT_RESPONSE_MSG_ID, "MEASUREMENT.response" },

	{ NFAPI_DL_NODE_SYNC_MSG_ID, "UL_NODE_SYNC" },
	{ NFAPI_UL_NODE_SYNC_MSG_ID, "DL_NODE_SYNC" },
	{ NFAPI_TIMING_INFO_MSG_ID, "TIMING_INFO" },

	{ NFAPI_RSSI_REQUEST_MSG_ID, "RSSI.request" },
	{ NFAPI_RSSI_RESPONSE_MSG_ID, "RSSI.response" },
	{ NFAPI_RSSI_INDICATION_MSG_ID, "RSSI.indication" },
	{ NFAPI_CELL_SEARCH_REQUEST_MSG_ID, "CELL_SEARCH.request" },
	{ NFAPI_CELL_SEARCH_RESPONSE_MSG_ID, "CELL_SEARCH.response" },
	{ NFAPI_CELL_SEARCH_INDICATION_MSG_ID, "CELL_SEARCH.indication" },
	{ NFAPI_BROADCAST_DETECT_REQUEST_MSG_ID, "BROADCAST_DETECT.request" },
	{ NFAPI_BROADCAST_DETECT_RESPONSE_MSG_ID, "BROADCAST_DETECT.response" },
	{ NFAPI_BROADCAST_DETECT_INDICATION_MSG_ID, "BROADCAST_DETECT.indication" },
	{ NFAPI_SYSTEM_INFORMATION_SCHEDULE_REQUEST_MSG_ID, "SYSTEM_INFORMATION_SCHEDULE.request" },
	{ NFAPI_SYSTEM_INFORMATION_SCHEDULE_RESPONSE_MSG_ID, "SYSTEM_INFORMATION_SCHEDULE.response" },
	{ NFAPI_SYSTEM_INFORMATION_SCHEDULE_INDICATION_MSG_ID, "SYSTEM_INFORMATION_SCHEDULE.indication" },
	{ NFAPI_SYSTEM_INFORMATION_REQUEST_MSG_ID, "SYSTEM_INFORMATION.request" },
	{ NFAPI_SYSTEM_INFORMATION_RESPONSE_MSG_ID, "SYSTEM_INFORMATION.response" },
	{ NFAPI_SYSTEM_INFORMATION_INDICATION_MSG_ID, "SYSTEM_INFORMATION.indication" },
	{ NFAPI_NMM_STOP_REQUEST_MSG_ID, "NMM_STOP.request" },
	{ NFAPI_NMM_STOP_RESPONSE_MSG_ID, "NMM_STOP.response" },

	{ 0, NULL },
};

static dissector_handle_t nfapi_handle;
static dissector_table_t message_table;

static int * const dl_bandwidth_support_fields[] = {
	&hf_nfapi_dl_bandwidth_support_6,
	&hf_nfapi_dl_bandwidth_support_15,
	&hf_nfapi_dl_bandwidth_support_25,
	&hf_nfapi_dl_bandwidth_support_50,
	&hf_nfapi_dl_bandwidth_support_75,
	&hf_nfapi_dl_bandwidth_support_100,
	NULL
};

static int * const ul_bandwidth_support_fields[] = {
	&hf_nfapi_ul_bandwidth_support_6,
	&hf_nfapi_ul_bandwidth_support_15,
	&hf_nfapi_ul_bandwidth_support_25,
	&hf_nfapi_ul_bandwidth_support_50,
	&hf_nfapi_ul_bandwidth_support_75,
	&hf_nfapi_ul_bandwidth_support_100,
	NULL
};

static int * const maximum_3gpp_release_supported_fields[] = {
	&hf_nfapi_maximum_3gpp_release_supported_rel8,
	&hf_nfapi_maximum_3gpp_release_supported_rel9,
	&hf_nfapi_maximum_3gpp_release_supported_rel10,
	&hf_nfapi_maximum_3gpp_release_supported_rel11,
	&hf_nfapi_maximum_3gpp_release_supported_rel12,
	&hf_nfapi_maximum_3gpp_release_supported_rel13,
	&hf_nfapi_dl_bandwidth_support_100,
	NULL
};

typedef void(*tlv_decode)(ptvcursor_t * ptvc, packet_info* pinfo);

typedef struct
{
	guint16 tag_id;
	char* name;
	tlv_decode decode;
} tlv_t;

static void dissect_tlv_list(ptvcursor_t * ptvc, packet_info* pinfo, gint len);

static void dissect_array_value(ptvcursor_t * ptvc, packet_info* pinfo, const char* name, guint32 ett_idx, guint32 count, tlv_decode decode)
{
	guint16 i = 0;

	if (count > 0)
	{
		ptvcursor_add_text_with_subtree(ptvc, SUBTREE_UNDEFINED_LENGTH, ett_idx, "%s", name);

		for (i = 0; i < count; ++i)
		{
			ptvcursor_add_text_with_subtree(ptvc, SUBTREE_UNDEFINED_LENGTH, ett_idx, "[%d]", i);
			decode(ptvc, pinfo);
			ptvcursor_pop_subtree(ptvc);
		}

		ptvcursor_pop_subtree(ptvc);
	}
}

static void dissect_pnf_param_general_value(ptvcursor_t * ptvc, packet_info* pinfo)
{
	proto_item* item;
	gint32 test_value;

	// nFAPI Sync Mode
	item = ptvcursor_add_ret_uint(ptvc, hf_nfapi_sync_mode, 1, ENC_BIG_ENDIAN, &test_value);
	if (test_value > 2)
	{
		expert_add_info_format(pinfo, item, &ei_invalid_range, "Invalid nfapi sync mode value [0..2]");
	}

	// Location Mode
	item = ptvcursor_add_ret_uint(ptvc, hf_nfapi_location_mode, 1, ENC_BIG_ENDIAN, &test_value);
	if (test_value > 3)
	{
		expert_add_info_format(pinfo, item, &ei_invalid_range, "Invalid location mode value [0..3]");
	}

	ptvcursor_add(ptvc, hf_nfapi_location_coordinates, 2, ENC_BIG_ENDIAN|ENC_NA);
	ptvcursor_add(ptvc, hf_nfapi_dl_config_timing, 4, ENC_BIG_ENDIAN);
	ptvcursor_add(ptvc, hf_nfapi_tx_timing, 4, ENC_BIG_ENDIAN);
	ptvcursor_add(ptvc, hf_nfapi_ul_config_timing, 4, ENC_BIG_ENDIAN);
	ptvcursor_add(ptvc, hf_nfapi_hi_dci0_timing, 4, ENC_BIG_ENDIAN);
	ptvcursor_add(ptvc, hf_nfapi_maximum_number_phys, 2, ENC_BIG_ENDIAN);
	ptvcursor_add(ptvc, hf_nfapi_maximum_total_bandwidth, 2, ENC_BIG_ENDIAN);
	ptvcursor_add(ptvc, hf_nfapi_maximum_total_number_dl_layers, 1, ENC_BIG_ENDIAN);
	ptvcursor_add(ptvc, hf_nfapi_maximum_total_number_ul_layers, 1, ENC_BIG_ENDIAN);

	// Shared Bands
	item = ptvcursor_add_ret_boolean(ptvc, hf_nfapi_shared_bands, 1, ENC_BIG_ENDIAN, &test_value);
	if (test_value > 1)
	{
		expert_add_info_format(pinfo, item, &ei_invalid_range, "Invalid shared bands value [0..1]");
	}

	// Shared PA
	item = ptvcursor_add_ret_boolean(ptvc, hf_nfapi_shared_pa, 1, ENC_BIG_ENDIAN, &test_value);
	if (test_value > 1)
	{
		expert_add_info_format(pinfo, item, &ei_invalid_range, "Invalid shared pa value [0..1]");
	}

	ptvcursor_add(ptvc, hf_nfapi_maximum_total_power, 2, ENC_BIG_ENDIAN);
	ptvcursor_add(ptvc, hf_nfapi_oui, 3, ENC_HOST_ENDIAN);
}
static void dissect_pnf_rf_config_instance_value(ptvcursor_t * ptvc, packet_info* pinfo _U_)
{
	ptvcursor_add(ptvc, hf_nfapi_rf_config_index, 2, ENC_BIG_ENDIAN);
}

static void dissect_pnf_phy_instance_value(ptvcursor_t * ptvc, packet_info* pinfo)
{
	proto_item* item;
	guint32 array_size, test_value;
	guint64 test_value64;

	ptvcursor_add(ptvc, hf_nfapi_pnf_phy_config_index, 2, ENC_BIG_ENDIAN);

	ptvcursor_add_ret_uint(ptvc, hf_nfapi_number_of_rfs, 2, ENC_BIG_ENDIAN, &array_size);
	dissect_array_value(ptvc, pinfo, "RF Config List", ett_nfapi_pnf_phy, array_size, dissect_pnf_rf_config_instance_value);

	ptvcursor_add_ret_uint(ptvc, hf_nfapi_number_of_rf_exclusions, 2, ENC_BIG_ENDIAN, &array_size);
	dissect_array_value(ptvc, pinfo, "RF Exclustion List", ett_nfapi_pnf_phy, array_size, dissect_pnf_rf_config_instance_value);

	// Downlink Channel Bandwidth Supported
	item = proto_tree_add_bitmask_ret_uint64(ptvcursor_tree(ptvc), ptvcursor_tvbuff(ptvc), ptvcursor_current_offset(ptvc),
											hf_nfapi_downlink_channel_bandwidth_supported, ett_nfapi_downlink_bandwidth_support, dl_bandwidth_support_fields, ENC_BIG_ENDIAN, &test_value64);
	if (test_value64 > 0x3F)
	{
		expert_add_info_format(pinfo, item, &ei_invalid_range, "Invalid downlink channel bandwidth supported bits [0..0x3F]");
	}
	ptvcursor_advance(ptvc, 2);

	// Uplink Channel Bandwidth Supported
	item = proto_tree_add_bitmask_ret_uint64(ptvcursor_tree(ptvc), ptvcursor_tvbuff(ptvc), ptvcursor_current_offset(ptvc),
											hf_nfapi_uplink_channel_bandwidth_supported, ett_nfapi_uplink_bandwidth_support, ul_bandwidth_support_fields, ENC_BIG_ENDIAN, &test_value64);
	if (test_value64 > 0x3F)
	{
		expert_add_info_format(pinfo, item, &ei_invalid_range, "Invalid uplink channel bandwidth supported bits [0..0x3F]");
	}
	ptvcursor_advance(ptvc, 2);

	// Number of DL layers supported
	item = ptvcursor_add_ret_uint(ptvc, hf_nfapi_number_of_dl_layers_supported, 1, ENC_BIG_ENDIAN, &test_value);
	switch (test_value)
	{
	case 1:
	case 2:
	case 4:
	case 8:
		break;
	default:
		expert_add_info_format(pinfo, item, &ei_invalid_range, "Invalid number of dl layers supported value [1, 2, 4, 8]");
		break;
	}

	// Number of DL layers supported
	item = ptvcursor_add_ret_uint(ptvc, hf_nfapi_number_of_ul_layers_supported, 1, ENC_BIG_ENDIAN, &test_value);
	switch (test_value)
	{
	case 1:
	case 2:
	case 4:
	case 8:
		break;
	default:
		expert_add_info_format(pinfo, item, &ei_invalid_range, "Invalid number of ul layers supported value [1, 2, 4, 8]");
		break;
	}

	// Maximum 3GPP Release Supported
	item = proto_tree_add_bitmask_ret_uint64(ptvcursor_tree(ptvc), ptvcursor_tvbuff(ptvc), ptvcursor_current_offset(ptvc),
											hf_nfapi_maximum_3gpp_release_supported, ett_nfapi_release_support, maximum_3gpp_release_supported_fields, ENC_BIG_ENDIAN, &test_value64);
	if (test_value64 > 0x3F)
	{
		expert_add_info_format(pinfo, item, &ei_invalid_range, "Invalid maximum 3GPP release supported value [0..0x3F]");
	}
	ptvcursor_advance(ptvc, 2);

	// NMM Modes Supported
	item = ptvcursor_add_ret_uint(ptvc, hf_nfapi_nmm_modes_supported, 1, ENC_BIG_ENDIAN, &test_value);
	if (test_value > 3)
	{
		expert_add_info_format(pinfo, item, &ei_invalid_range, "Invalid nmm modes supported value [0..3]");
	}
}

static void dissect_pnf_phy_value(ptvcursor_t * ptvc, packet_info* pinfo)
{
	guint32 num_phy;
	ptvcursor_add_ret_uint(ptvc, hf_nfapi_pnf_phy_number_phy, 2, ENC_BIG_ENDIAN, &num_phy);
	dissect_array_value(ptvc, pinfo, "PHY List", ett_nfapi_pnf_phy, num_phy, dissect_pnf_phy_instance_value);
}

static void dissect_pnf_rf_config_value(ptvcursor_t * ptvc, packet_info* pinfo)
{
	proto_item* item;
	guint32 test_value;

	ptvcursor_add(ptvc, hf_nfapi_rf_config_index, 2, ENC_BIG_ENDIAN);
	ptvcursor_add(ptvc, hf_nfapi_band, 2, ENC_BIG_ENDIAN);
	ptvcursor_add(ptvc, hf_nfapi_maximum_transmit_power, 2, ENC_BIG_ENDIAN);
	ptvcursor_add(ptvc, hf_nfapi_minimum_transmit_power, 2, ENC_BIG_ENDIAN);

	item = ptvcursor_add_ret_uint(ptvc, hf_nfapi_number_of_antennas_suppported, 1, ENC_BIG_ENDIAN, &test_value);
	switch (test_value)
	{
	case 1:
	case 2:
	case 4:
	case 8:
		break;
	default:
		expert_add_info_format(pinfo, item, &ei_invalid_range, "Invalid number of supported antennas [1, 2, 4, 8]");
		break;
	}

	ptvcursor_add(ptvc, hf_nfapi_minimum_downlink_frequency, 4, ENC_BIG_ENDIAN);
	ptvcursor_add(ptvc, hf_nfapi_maximum_downlink_frequency, 4, ENC_BIG_ENDIAN);
	ptvcursor_add(ptvc, hf_nfapi_minimum_uplink_frequency, 4, ENC_BIG_ENDIAN);
	ptvcursor_add(ptvc, hf_nfapi_maximum_uplink_frequency, 4, ENC_BIG_ENDIAN);
}


static void dissect_pnf_rf_value(ptvcursor_t * ptvc, packet_info* pinfo)
{
	guint32 num_rf;
	ptvcursor_add_ret_uint(ptvc, hf_nfapi_number_of_rfs, 2, ENC_BIG_ENDIAN, &num_rf);
	dissect_array_value(ptvc, pinfo, "RF List", ett_nfapi_pnf_phy_rf_config, num_rf, dissect_pnf_rf_config_value);
}

static void dissect_pnf_phy_rel10_instance_value(ptvcursor_t * ptvc, packet_info* pinfo)
{
	proto_item* item;
	guint32 test_value;

	// PHY Config Index
	ptvcursor_add(ptvc, hf_nfapi_pnf_phy_config_index, 2, ENC_BIG_ENDIAN);

	// Transmission mode 7 supported
	item = ptvcursor_add_ret_uint(ptvc, hf_nfapi_transmission_mode7_supported, 2, ENC_BIG_ENDIAN, &test_value);
	if (test_value > 1)
	{
		expert_add_info_format(pinfo, item, &ei_invalid_range, "Invalid transmission mode 7 supported value [0..1]");
	}

	// Two antennas ports for PUCCH
	item = ptvcursor_add_ret_uint(ptvc, hi_nfapi_transmission_mode8_supported, 2, ENC_BIG_ENDIAN, &test_value);
	if (test_value > 1)
	{
		expert_add_info_format(pinfo, item, &ei_invalid_range, "Invalid transmission mode 8 supported value [0..1]");
	}

	// Transmission mode 8 supported
	item = ptvcursor_add_ret_uint(ptvc, hi_nfapi_two_antennas_ports_for_pucch, 2, ENC_BIG_ENDIAN, &test_value);
	if (test_value > 1)
	{
		expert_add_info_format(pinfo, item, &ei_invalid_range, "Invalid two antennas ports for pucch value [0..1]");
	}

	// Transmission mode 9 supported
	item = ptvcursor_add_ret_uint(ptvc, hi_nfapi_transmission_mode_9_supported, 2, ENC_BIG_ENDIAN, &test_value);
	if (test_value > 1)
	{
		expert_add_info_format(pinfo, item, &ei_invalid_range, "Invalid transmission mode 9 supported value [0..1]");
	}

	// Simultaneous PUCCH PUSCH
	item = ptvcursor_add_ret_uint(ptvc, hi_nfapi_simultaneous_pucch_pusch, 2, ENC_BIG_ENDIAN, &test_value);
	if (test_value > 1)
	{
		expert_add_info_format(pinfo, item, &ei_invalid_range, "Invalid simultaneous pucch pusch supported value [0..1]");
	}

	// Four layer Tx with TM3 and TM4
	item = ptvcursor_add_ret_uint(ptvc, hi_nfapi_four_layer_tx_with_tm3_and_tm4, 2, ENC_BIG_ENDIAN, &test_value);
	if (test_value > 1)
	{
		expert_add_info_format(pinfo, item, &ei_invalid_range, "Invalid four layer tx with tm3 and tm4 value [0..1]");
	}
}

static void dissect_pnf_phy_rel10_value(ptvcursor_t * ptvc, packet_info* pinfo)
{
	guint32 num_phy;
	ptvcursor_add_ret_uint(ptvc, hf_nfapi_pnf_phy_number_phy, 2, ENC_BIG_ENDIAN, &num_phy);
	dissect_array_value(ptvc, pinfo, "PHY Rel 10 List", ett_nfapi_pnf_phy_rel10, num_phy, dissect_pnf_phy_rel10_instance_value);
}

static void dissect_pnf_phy_rel11_instance_value(ptvcursor_t * ptvc, packet_info* pinfo)
{
	proto_item* item;
	guint32 test_value;

	// PHY Config Index
	ptvcursor_add(ptvc, hf_nfapi_pnf_phy_config_index, 2, ENC_BIG_ENDIAN);

	// ePDCCH supported
	item = ptvcursor_add_ret_uint(ptvc, hf_nfapi_epdcch_supported, 2, ENC_BIG_ENDIAN, &test_value);
	if (test_value > 1)
	{
		expert_add_info_format(pinfo, item, &ei_invalid_range, "Invalid edpcch supported value [0..1]");
	}

	// Multi ACK CSI reporting
	item = ptvcursor_add_ret_uint(ptvc, hi_nfapi_multi_ack_csi_reporting, 2, ENC_BIG_ENDIAN, &test_value);
	if (test_value > 1)
	{
		expert_add_info_format(pinfo, item, &ei_invalid_range, "Invalid multi ack csi reporting value [0..1]");
	}

	// PUCCH Tx diversity with channel selection
	item = ptvcursor_add_ret_uint(ptvc, hi_nfapi_pucch_tx_diversity_with_channel_selection, 2, ENC_BIG_ENDIAN, &test_value);
	if (test_value > 1)
	{
		expert_add_info_format(pinfo, item, &ei_invalid_range, "Invalid pucch tx diversity with channel selection value [0..1]");
	}

	// UL CoMP supported
	item = ptvcursor_add_ret_uint(ptvc, hi_nfapi_ul_comp_supported, 2, ENC_BIG_ENDIAN, &test_value);
	if (test_value > 1)
	{
		expert_add_info_format(pinfo, item, &ei_invalid_range, "Invalid ul comp supported value [0..1]");
	}

	// Transmission mode 5 supported
	item = ptvcursor_add_ret_uint(ptvc, hi_nfapi_transmission_mode_5_supported, 2, ENC_BIG_ENDIAN, &test_value);
	if (test_value > 1)
	{
		expert_add_info_format(pinfo, item, &ei_invalid_range, "Invalid transmission mode 5 supported value [0..1]");
	}
}

static void dissect_pnf_phy_rel11_value(ptvcursor_t * ptvc, packet_info* pinfo)
{
	guint32 num_phy;
	ptvcursor_add_ret_uint(ptvc, hf_nfapi_pnf_phy_number_phy, 2, ENC_BIG_ENDIAN, &num_phy);
	dissect_array_value(ptvc, pinfo, "PHY Rel 11 List", ett_nfapi_pnf_phy_rel11, num_phy, dissect_pnf_phy_rel11_instance_value);
}

static void dissect_pnf_phy_rel12_instance_value(ptvcursor_t * ptvc, packet_info* pinfo)
{
	proto_item* item;
	guint32 test_value;

	// PHY Config Index
	ptvcursor_add(ptvc, hf_nfapi_pnf_phy_config_index, 2, ENC_BIG_ENDIAN);

	// CSI subframe set
	item = ptvcursor_add_ret_uint(ptvc, hf_nfapi_csi_subframe_set, 2, ENC_BIG_ENDIAN, &test_value);
	if (test_value > 1)
	{
		expert_add_info_format(pinfo, item, &ei_invalid_range, "Invalid csi subframe set value [0..1]");
	}

	// Enhanced 4TX codebook
	item = ptvcursor_add_ret_uint(ptvc, hi_nfapi_enhanced_4tx_codebook, 2, ENC_BIG_ENDIAN, &test_value);
	if (test_value > 1)
	{
		expert_add_info_format(pinfo, item, &ei_invalid_range, "Invalid enhanced 4TX codebook value [0..1]");
	}

	// DRS supported
	item = ptvcursor_add_ret_uint(ptvc, hi_nfapi_drs_supported, 2, ENC_BIG_ENDIAN, &test_value);
	if (test_value > 1)
	{
		expert_add_info_format(pinfo, item, &ei_invalid_range, "Invalid drs supported value [0..1]");
	}

	// UL 64QAM supported
	item = ptvcursor_add_ret_uint(ptvc, hi_nfapi_ul_64qam_supported, 2, ENC_BIG_ENDIAN, &test_value);
	if (test_value > 1)
	{
		expert_add_info_format(pinfo, item, &ei_invalid_range, "Invalid ul 64 QAM supported value [0..1]");
	}

	// Transmission mode 10 supported
	item = ptvcursor_add_ret_uint(ptvc, hi_nfapi_transmission_mode_10_supported, 2, ENC_BIG_ENDIAN, &test_value);
	if (test_value > 1)
	{
		expert_add_info_format(pinfo, item, &ei_invalid_range, "Invalid transmission mode 10 supported value [0..1]");
	}

	// Alternative TBS indices
	item = ptvcursor_add_ret_uint(ptvc, hi_nfapi_alternative_tbs_indices, 2, ENC_BIG_ENDIAN, &test_value);
	if (test_value > 1)
	{
		expert_add_info_format(pinfo, item, &ei_invalid_range, "Invalid alternative tbs indicies supported value [0..1]");
	}
}

static void dissect_pnf_phy_rel12_value(ptvcursor_t * ptvc, packet_info* pinfo)
{
	guint32 num_phy;
	ptvcursor_add_ret_uint(ptvc, hf_nfapi_pnf_phy_number_phy, 2, ENC_BIG_ENDIAN, &num_phy);
	dissect_array_value(ptvc, pinfo, "PHY Rel 12 List", ett_nfapi_pnf_phy_rel12, num_phy, dissect_pnf_phy_rel12_instance_value);
}

static void dissect_pnf_phy_rel13_instance_value(ptvcursor_t * ptvc, packet_info* pinfo)
{
	proto_item* item;
	guint32 test_value;

	// PHY Config Index
	ptvcursor_add(ptvc, hf_nfapi_pnf_phy_config_index, 2, ENC_BIG_ENDIAN);

	// PUCCH format 4 supported
	item = ptvcursor_add_ret_uint(ptvc, hf_nfapi_pucch_format_4_supported, 2, ENC_BIG_ENDIAN, &test_value);
	if (test_value > 1)
	{
		expert_add_info_format(pinfo, item, &ei_invalid_range, "Invalid pucch format 4 supported value [0..1]");
	}

	// PUCCH format 5 supported
	item = ptvcursor_add_ret_uint(ptvc, hf_nfapi_pucch_format_5_supported, 2, ENC_BIG_ENDIAN, &test_value);
	if (test_value > 1)
	{
		expert_add_info_format(pinfo, item, &ei_invalid_range, "Invalid pucch format 5 supported value [0..1]");
	}

	// More than 5 CA support
	item = ptvcursor_add_ret_uint(ptvc, hf_nfapi_more_than_5_ca_supported, 2, ENC_BIG_ENDIAN, &test_value);
	if (test_value > 1)
	{
		expert_add_info_format(pinfo, item, &ei_invalid_range, "Invalid more than 5 ca supported value [0..1]");
	}

	// LAA supported
	item = ptvcursor_add_ret_uint(ptvc, hf_nfapi_laa_supported, 2, ENC_BIG_ENDIAN, &test_value);
	if (test_value > 1)
	{
		expert_add_info_format(pinfo, item, &ei_invalid_range, "Invalid laa supported value [0..1]");
	}

	// LAA ending in DwPTS supported
	item = ptvcursor_add_ret_uint(ptvc, hf_nfapi_laa_ending_in_dwpts_supported, 2, ENC_BIG_ENDIAN, &test_value);
	if (test_value > 1)
	{
		expert_add_info_format(pinfo, item, &ei_invalid_range, "Invalid laa ending in dwpts supported value [0..1]");
	}

	// LAA starting in second slot Supported
	item = ptvcursor_add_ret_uint(ptvc, hf_nfapi_laa_starting_in_second_slot_supported, 2, ENC_BIG_ENDIAN, &test_value);
	if (test_value > 1)
	{
		expert_add_info_format(pinfo, item, &ei_invalid_range, "Invalid laa starting in second slot supported value [0..1]");
	}

	// Beamforming Supported
	item = ptvcursor_add_ret_uint(ptvc, hf_nfapi_beamforming_supported, 2, ENC_BIG_ENDIAN, &test_value);
	if (test_value > 1)
	{
		expert_add_info_format(pinfo, item, &ei_invalid_range, "Invalid beamforming supported value [0..1]");
	}

	// CSI-RS enhancements supported
	item = ptvcursor_add_ret_uint(ptvc, hf_nfapi_csi_rs_enhancements_supported, 2, ENC_BIG_ENDIAN, &test_value);
	if (test_value > 1)
	{
		expert_add_info_format(pinfo, item, &ei_invalid_range, "Invalid csi rs enhancements supported value [0..1]");
	}

	// DMRS enhancements supported
	item = ptvcursor_add_ret_uint(ptvc, hf_nfapi_drms_enhancements_supported, 2, ENC_BIG_ENDIAN, &test_value);
	if (test_value > 1)
	{
		expert_add_info_format(pinfo, item, &ei_invalid_range, "Invalid drms enhancements supported value [0..1]");
	}

	// SRS enhancements supported
	item = ptvcursor_add_ret_uint(ptvc, hf_nfapi_srs_enhancements_supported, 2, ENC_BIG_ENDIAN, &test_value);
	if (test_value > 1)
	{
		expert_add_info_format(pinfo, item, &ei_invalid_range, "Invalid srs enhancements supported value [0..1]");
	}

}

static void dissect_pnf_phy_rel13_value(ptvcursor_t * ptvc, packet_info* pinfo)
{
	guint32 num_phy;
	ptvcursor_add_ret_uint(ptvc, hf_nfapi_pnf_phy_number_phy, 2, ENC_BIG_ENDIAN, &num_phy);
	dissect_array_value(ptvc, pinfo, "PHY Rel 13 List", ett_nfapi_pnf_phy_rel13, num_phy, dissect_pnf_phy_rel13_instance_value);
}

static void dissect_pnf_phy_rf_config_instance_value(ptvcursor_t * ptvc, packet_info* pinfo _U_)
{
	ptvcursor_add(ptvc, hf_nfapi_phy_rf_config_info_phy_id, 2, ENC_BIG_ENDIAN);
	ptvcursor_add(ptvc, hf_nfapi_pnf_phy_config_index, 2, ENC_BIG_ENDIAN);
	ptvcursor_add(ptvc, hf_nfapi_rf_config_index, 2, ENC_BIG_ENDIAN);
}
static void dissect_pnf_phy_rf_config_value(ptvcursor_t * ptvc, packet_info* pinfo)
{
	guint32 num_configs;
	ptvcursor_add_ret_uint(ptvc, hf_nfapi_pnf_phy_number_phy, 2, ENC_BIG_ENDIAN, &num_configs);
	dissect_array_value(ptvc, pinfo, "PHY RF Config List", ett_nfapi_pnf_phy_rf_config, num_configs, dissect_pnf_phy_rf_config_instance_value);
}

static void dissect_dl_rs_tx_power_value(ptvcursor_t * ptvc, packet_info* pinfo)
{
	guint32 test_value;
	proto_item* item = ptvcursor_add_ret_uint(ptvc, hf_nfapi_dl_rs_tx_power, 2, ENC_BIG_ENDIAN, &test_value);

	if (!(test_value >= 1 && test_value <= 255))
	{
		expert_add_info_format(pinfo, item, &ei_invalid_range, "Invalid value [1..255]");
	}
}
static void dissect_received_interference_power_value(ptvcursor_t * ptvc, packet_info* pinfo)
{
	guint32 test_value;
	proto_item* item = ptvcursor_add_ret_uint(ptvc, hf_nfapi_received_interference_power, 2, ENC_BIG_ENDIAN, &test_value);

	if (!(test_value >= 1 && test_value <= 255))
	{
		expert_add_info_format(pinfo, item, &ei_invalid_range, "Invalid value [1..255]");
	}
}
static void dissect_thermal_noise_power_value(ptvcursor_t * ptvc, packet_info* pinfo _U_)
{
	ptvcursor_add(ptvc, hf_nfapi_thermal_noise_power, 2, ENC_BIG_ENDIAN);
}
static void dissect_dl_rs_tx_power_measurement_value(ptvcursor_t * ptvc, packet_info* pinfo _U_)
{
	ptvcursor_add(ptvc, hf_nfapi_dl_rs_tx_power_measurement, 2, ENC_BIG_ENDIAN);
}

static void dissect_received_interference_power_result_value(ptvcursor_t * ptvc, packet_info* pinfo _U_)
{
	ptvcursor_add(ptvc, hf_nfapi_received_interference_power_measurement, 2, ENC_BIG_ENDIAN);
}
static void dissect_received_interference_power_measurement_value(ptvcursor_t * ptvc, packet_info* pinfo)
{
	guint32 num_resource_block;
	ptvcursor_add_ret_uint(ptvc, hf_nfapi_number_of_resource_blocks, 2, ENC_BIG_ENDIAN, &num_resource_block);
	dissect_array_value(ptvc, pinfo, "Results", ett_nfapi_received_interference_power_mesurement_results, num_resource_block, dissect_received_interference_power_result_value);
}
static void dissect_thermal_noise_power_measurement_value(ptvcursor_t * ptvc, packet_info* pinfo _U_)
{
	ptvcursor_add(ptvc, hf_nfapi_thermal_noise_power_measurement, 2, ENC_BIG_ENDIAN);
}
static void dissect_duplex_mode_value(ptvcursor_t * ptvc, packet_info* pinfo)
{
	guint32 test_value;
	proto_item* item = ptvcursor_add_ret_uint(ptvc, hf_nfapi_duplex_mode, 2, ENC_BIG_ENDIAN, &test_value);

	if (test_value > 2)
	{
		expert_add_info_format(pinfo, item, &ei_invalid_range, "Invalid duplex mode [0..2]");
	}
}
static void dissect_pcfich_power_offset_value(ptvcursor_t* ptvc, packet_info *pinfo)
{
	guint32 test_value;
	proto_item* item = ptvcursor_add_ret_uint(ptvc, hf_nfapi_pcfich_power_offset, 2, ENC_BIG_ENDIAN, &test_value);

	if (test_value > 10000)
	{
		expert_add_info_format(pinfo, item, &ei_invalid_range, "Invalid power level [0..10000]");
	}
}
static void dissect_pb_value(ptvcursor_t * ptvc, packet_info* pinfo)
{
	guint32 test_value;
	proto_item* item = ptvcursor_add_ret_uint(ptvc, hf_nfapi_pb, 2, ENC_BIG_ENDIAN, &test_value);

	if (test_value > 3)
	{
		expert_add_info_format(pinfo, item, &ei_invalid_range, "Invalid downlink power allocation Index [0..3]");
	}
}

static void dissect_dl_cyclic_prefix_value(ptvcursor_t * ptvc, packet_info* pinfo)
{
	gint32 test_value;
	proto_item* item = ptvcursor_add_ret_boolean(ptvc, hf_nfapi_dl_cyclic_prefix_type, 2, ENC_BIG_ENDIAN, &test_value);

	if (test_value > 1)
	{
		expert_add_info_format(pinfo, item, &ei_invalid_range, "Invalid dl cyclic prefix type [0..1]");
	}
}
static void dissect_ul_cyclic_prefix_value(ptvcursor_t * ptvc, packet_info* pinfo)
{
	gint32 test_value;
	proto_item* item = ptvcursor_add_ret_boolean(ptvc, hf_nfapi_ul_cyclic_prefix_type, 2, ENC_BIG_ENDIAN, &test_value);

	if (test_value > 1)
	{
		expert_add_info_format(pinfo, item, &ei_invalid_range, "Invalid ul cyclic prefix type [0..1]");
	}
}
static void dissect_dl_channel_bandwidth_value(ptvcursor_t * ptvc, packet_info* pinfo)
{
	guint32 test_value;
	proto_item* item = ptvcursor_add_ret_uint(ptvc, hf_nfapi_downlink_channel_bandwidth, 2, ENC_BIG_ENDIAN, &test_value);

	if (!(test_value == 6 || test_value == 15 || test_value == 25 || test_value == 50 || test_value == 75 || test_value == 100))
	{
		expert_add_info_format(pinfo, item, &ei_invalid_range, "Invalid downlink bandwidth value [6, 15, 25, 50, 75, 100]");
	}
}
static void dissect_ul_channel_bandwidth_value(ptvcursor_t * ptvc, packet_info* pinfo)
{
	guint32 test_value;
	proto_item* item = ptvcursor_add_ret_uint(ptvc, hf_nfapi_uplink_channel_bandwidth, 2, ENC_BIG_ENDIAN, &test_value);

	if (!(test_value == 6 || test_value == 15 || test_value == 25 || test_value == 50 || test_value == 75 || test_value == 100))
	{
		expert_add_info_format(pinfo, item, &ei_invalid_range, "Invalid uplink bandwidth value [6, 15, 25, 50, 75, 100]");
	}
}
static void dissect_reference_signal_power_value(ptvcursor_t * ptvc, packet_info* pinfo)
{
	guint32 test_value;
	proto_item* item = ptvcursor_add_ret_uint(ptvc, hf_nfapi_reference_signal_power, 2, ENC_BIG_ENDIAN, &test_value);

	if (test_value > 255)
	{
		expert_add_info_format(pinfo, item, &ei_invalid_range, "Invalid reference signal power [0..255]");
	}

}
static void dissect_tx_antenna_ports_value(ptvcursor_t * ptvc, packet_info* pinfo)
{
	guint32 test_value;
	proto_item* item = ptvcursor_add_ret_uint(ptvc, hf_nfapi_tx_antenna_ports, 2, ENC_BIG_ENDIAN, &test_value);

	if (!(test_value == 1 || test_value == 2 || test_value == 4 || test_value == 8 || test_value == 16))
	{
		expert_add_info_format(pinfo, item, &ei_invalid_range, "Invalid tx antenna ports value [1, 2, 4, 8, 16]");
	}
}
static void dissect_rx_antenna_ports_value(ptvcursor_t * ptvc, packet_info* pinfo)
{
	guint32 test_value;
	proto_item* item = ptvcursor_add_ret_uint(ptvc, hf_nfapi_rx_antenna_ports, 2, ENC_BIG_ENDIAN, &test_value);

	if (!(test_value == 1 || test_value == 2 || test_value == 4 || test_value == 8 || test_value == 16))
	{
		expert_add_info_format(pinfo, item, &ei_invalid_range, "Invalid rx antenna ports value [1, 2, 4, 8, 16]");
	}
}
static void dissect_phich_resource_value(ptvcursor_t * ptvc, packet_info* pinfo)
{
	guint32 test_value;
	proto_item* item = ptvcursor_add_ret_uint(ptvc, hf_nfapi_phich_resource, 2, ENC_BIG_ENDIAN, &test_value);

	if (test_value > 3)
	{
		expert_add_info_format(pinfo, item, &ei_invalid_range, "Invalid phich resource value [0..3]");
	}
}
static void dissect_phich_duration_value(ptvcursor_t * ptvc, packet_info* pinfo)
{
	gint32 test_value;
	proto_item* item = ptvcursor_add_ret_boolean(ptvc, hf_nfapi_phich_duration, 2, ENC_BIG_ENDIAN, &test_value);

	if (test_value > 1)
	{
		expert_add_info_format(pinfo, item, &ei_invalid_range, "Invalid phich duration value [0..1]");
	}
}
static void dissect_phich_power_offset_value(ptvcursor_t * ptvc, packet_info* pinfo)
{
	guint32 test_value;
	proto_item* item = ptvcursor_add_ret_uint(ptvc, hf_nfapi_phich_power_offset, 2, ENC_BIG_ENDIAN, &test_value);

	if (test_value > 10000)
	{
		expert_add_info_format(pinfo, item, &ei_invalid_range, "Invalid phich power offset value [0..10000]");
	}
}
static void dissect_psch_synch_signal_epre_eprers_value(ptvcursor_t * ptvc, packet_info* pinfo)
{
	guint32 test_value;
	proto_item* item = ptvcursor_add_ret_uint(ptvc, hf_nfapi_primary_synchronization_signal_epre_eprers, 2, ENC_BIG_ENDIAN, &test_value);

	if (test_value > 10000)
	{
		expert_add_info_format(pinfo, item, &ei_invalid_range, "Invalid primary synchronization signal epre/eprers value [0..10000]");
	}
}
static void dissect_physical_cell_id_value(ptvcursor_t * ptvc, packet_info* pinfo)
{
	guint32 test_value;
	proto_item* item = ptvcursor_add_ret_uint(ptvc, hf_nfapi_physical_cell_id, 2, ENC_BIG_ENDIAN, &test_value);

	if (test_value > 503)
	{
		expert_add_info_format(pinfo, item, &ei_invalid_range, "Invalid physical cell id [0..503]");
	}
}
static void dissect_ssch_synch_signal_epre_eprers_value(ptvcursor_t * ptvc, packet_info* pinfo)
{
	guint32 test_value;
	proto_item* item = ptvcursor_add_ret_uint(ptvc, hf_nfapi_secondary_synchronization_signal_epre_eprers, 2, ENC_BIG_ENDIAN, &test_value);

	if (test_value > 10000)
	{
		expert_add_info_format(pinfo, item, &ei_invalid_range, "Invalid secondary synchronization signal epre/eprers value [0..10000]");
	}
}
static void dissect_prach_configuration_index_value(ptvcursor_t * ptvc, packet_info* pinfo)
{
	guint32 test_value;
	proto_item* item = ptvcursor_add_ret_uint(ptvc, hf_nfapi_configuration_index, 2, ENC_BIG_ENDIAN, &test_value);

	if (test_value > 63)
	{
		expert_add_info_format(pinfo, item, &ei_invalid_range, "Invalid prach configuration Index [0..63]");
	}
}
static void dissect_prach_root_sequence_index_value(ptvcursor_t * ptvc, packet_info* pinfo)
{
	guint32 test_value;
	proto_item* item = ptvcursor_add_ret_uint(ptvc, hf_nfapi_root_sequence_index, 2, ENC_BIG_ENDIAN, &test_value);

	if (test_value > 837)
	{
		expert_add_info_format(pinfo, item, &ei_invalid_range, "Invalid prach root sequency Index [0..837]");
	}
}
static void dissect_prach_zero_correlation_zone_configuration_value(ptvcursor_t * ptvc, packet_info* pinfo)
{
	guint32 test_value;
	proto_item* item = ptvcursor_add_ret_uint(ptvc, hf_nfapi_zero_correlation_zone_configuration, 2, ENC_BIG_ENDIAN, &test_value);

	// How do differentiate between fdd 0..6 and tdd 0..15 ranges?
	if (test_value > 15)
	{
		expert_add_info_format(pinfo, item, &ei_invalid_range, "Invalid zero correlation zone configuration [0..15]");
	}
}
static void dissect_prach_high_speed_flag_value(ptvcursor_t * ptvc, packet_info* pinfo)
{
	gint32 test_value;
	proto_item* item = ptvcursor_add_ret_boolean(ptvc, hf_nfapi_high_speed_flag, 2, ENC_BIG_ENDIAN, &test_value);

	if (test_value > 1)
	{
		expert_add_info_format(pinfo, item, &ei_invalid_range, "Invalid high speed flag value [0..1]");
	}
}
static void dissect_prach_frequency_offset_value(ptvcursor_t * ptvc, packet_info* pinfo)
{
	guint32 test_value;
	proto_item* item = ptvcursor_add_ret_uint(ptvc, hf_nfapi_frequency_offset, 2, ENC_BIG_ENDIAN, &test_value);

	// How to determine the ul channel bandwidth?
	if (test_value > (100 -6))
	{
		expert_add_info_format(pinfo, item, &ei_invalid_range, "Invalid prach frequency offset value [0..94]");
	}
}
static void dissect_pusch_hopping_mode_value(ptvcursor_t * ptvc, packet_info* pinfo)
{
	gint32 test_value;
	proto_item* item = ptvcursor_add_ret_boolean(ptvc, hf_nfapi_hopping_mode, 2, ENC_BIG_ENDIAN, &test_value);

	if (test_value > 1)
	{
		expert_add_info_format(pinfo, item, &ei_invalid_range, "Invalid pusch hopping mode value [0..1]");
	}
}
static void dissect_pusch_hopping_offset_value(ptvcursor_t * ptvc, packet_info* pinfo)
{
	guint32 test_value;
	proto_item* item = ptvcursor_add_ret_uint(ptvc, hf_nfapi_hopping_offset, 2, ENC_BIG_ENDIAN, &test_value);

	if (test_value > 98)
	{
		expert_add_info_format(pinfo, item, &ei_invalid_range, "Invalid pusch hopping offset value [0..98]");
	}
}
static void dissect_pusch_number_of_subbands_value(ptvcursor_t * ptvc, packet_info* pinfo)
{
	guint32 test_value;
	proto_item* item = ptvcursor_add_ret_uint(ptvc, hf_nfapi_number_of_subbands, 2, ENC_BIG_ENDIAN, &test_value);

	if (!(test_value >= 1 && test_value <= 4))
	{
		expert_add_info_format(pinfo, item, &ei_invalid_range, "Invalid number of sub-bands [1..4]");
	}
}
static void dissect_pucch_delta_pucch_shift_value(ptvcursor_t * ptvc, packet_info* pinfo)
{
	guint32 test_value;
	proto_item* item = ptvcursor_add_ret_uint(ptvc, hf_nfapi_delta_pucch_shift, 2, ENC_BIG_ENDIAN, &test_value);

	if (!(test_value >= 1 && test_value <= 3))
	{
		expert_add_info_format(pinfo, item, &ei_invalid_range, "Invalid delta pucch shift [1..3]");
	}
}
static void dissect_pucch_n_cqi_rb_value(ptvcursor_t * ptvc, packet_info* pinfo)
{
	guint32 test_value;
	proto_item* item = ptvcursor_add_ret_uint(ptvc, hf_nfapi_n_cqi_rb, 2, ENC_BIG_ENDIAN, &test_value);

	if (test_value > 98)
	{
		expert_add_info_format(pinfo, item, &ei_invalid_range, "Invalid n cqi rb value [0..98]");
	}
}
static void dissect_pucch_n_an_cs_value(ptvcursor_t * ptvc, packet_info* pinfo)
{
	guint32 test_value;
	proto_item* item = ptvcursor_add_ret_uint(ptvc, hf_nfapi_n_an_cs, 2, ENC_BIG_ENDIAN, &test_value);

	if (test_value > 7)
	{
		expert_add_info_format(pinfo, item, &ei_invalid_range, "Invalid n an cs value [0..7]");
	}
}
static void dissect_pucch_n1_pucch_an_value(ptvcursor_t * ptvc, packet_info* pinfo)
{
	guint32 test_value;
	proto_item* item = ptvcursor_add_ret_uint(ptvc, hf_nfapi_n1_pucch_an, 2, ENC_BIG_ENDIAN, &test_value);

	if (test_value > 2047)
	{
		expert_add_info_format(pinfo, item, &ei_invalid_range, "Invalid n1pucch an value [0..2047]");
	}
}
static void dissect_srs_bandwidth_configuration_value(ptvcursor_t * ptvc, packet_info* pinfo)
{
	guint32 test_value;
	proto_item* item = ptvcursor_add_ret_uint(ptvc, hf_nfapi_bandwidth_configuration, 2, ENC_BIG_ENDIAN, &test_value);

	if (test_value > 7)
	{
		expert_add_info_format(pinfo, item, &ei_invalid_range, "Invalid srs bandwidth configuration value [0..7]");
	}
}
static void dissect_srs_max_uppts_value(ptvcursor_t * ptvc, packet_info* pinfo)
{
	gint32 test_value;
	proto_item* item = ptvcursor_add_ret_boolean(ptvc, hf_nfapi_max_up_pts, 2, ENC_BIG_ENDIAN, &test_value);

	if (test_value > 1)
	{
		expert_add_info_format(pinfo, item, &ei_invalid_range, "Invalid max up pts value [0..1]");
	}
}
static void dissect_srs_subframe_configuration_value(ptvcursor_t * ptvc, packet_info* pinfo)
{
	guint32 test_value;
	proto_item* item = ptvcursor_add_ret_uint(ptvc, hf_nfapi_srs_subframe_configuration, 2, ENC_BIG_ENDIAN, &test_value);

	if (test_value > 15)
	{
		expert_add_info_format(pinfo, item, &ei_invalid_range, "Invalid srs subframe configuration value [0..15]");
	}
}
static void dissect_srs_acknack_srs_sim_tx_value(ptvcursor_t * ptvc, packet_info* pinfo)
{
	gint32 test_value;
	proto_item* item = ptvcursor_add_ret_boolean(ptvc, hf_nfapi_srs_acknack_srs_simultaneous_transmission, 2, ENC_BIG_ENDIAN, &test_value);

	if (test_value > 1)
	{
		expert_add_info_format(pinfo, item, &ei_invalid_range, "Invalid srs ack nack srs simultaneous transmission value [0..1]");
	}
}
static void dissect_uplink_rs_hopping_value(ptvcursor_t * ptvc, packet_info* pinfo)
{
	guint32 test_value;
	proto_item* item = ptvcursor_add_ret_uint(ptvc, hf_nfapi_uplink_rs_hopping, 2, ENC_BIG_ENDIAN, &test_value);

	if (test_value > 2)
	{
		expert_add_info_format(pinfo, item, &ei_invalid_range, "Invalid uplink rs hopping value [0..2]");
	}
}
static void dissect_group_assignment_value(ptvcursor_t * ptvc, packet_info* pinfo)
{
	guint32 test_value;
	proto_item* item = ptvcursor_add_ret_uint(ptvc, hf_nfapi_group_assignment, 2, ENC_BIG_ENDIAN, &test_value);

	if (test_value > 29)
	{
		expert_add_info_format(pinfo, item, &ei_invalid_range, "Invalid group assignment value [0..29]");
	}
}
static void dissect_cyclic_shift_1_for_drms_value(ptvcursor_t * ptvc, packet_info* pinfo)
{
	guint32 test_value;
	proto_item* item = ptvcursor_add_ret_uint(ptvc, hf_nfapi_cyclic_shift_1_for_drms, 2, ENC_BIG_ENDIAN, &test_value);

	if (test_value > 7)
	{
		expert_add_info_format(pinfo, item, &ei_invalid_range, "Invalid cyclic shift 1 for drms value [0..7]");
	}
}
static void dissect_tdd_subframe_assignement_value(ptvcursor_t * ptvc, packet_info* pinfo)
{
	guint32 test_value;
	proto_item* item = ptvcursor_add_ret_uint(ptvc, hf_nfapi_subframe_assignment, 2, ENC_BIG_ENDIAN, &test_value);

	if (test_value > 6)
	{
		expert_add_info_format(pinfo, item, &ei_invalid_range, "Invalid tdd subframe assignment value [0..6]");
	}
}
static void dissect_tdd_subframe_patterns_value(ptvcursor_t * ptvc, packet_info* pinfo)
{
	guint32 test_value;
	proto_item* item = ptvcursor_add_ret_uint(ptvc, hf_nfapi_special_subframe_patterns, 2, ENC_BIG_ENDIAN, &test_value);

	if (test_value > 9)
	{
		expert_add_info_format(pinfo, item, &ei_invalid_range, "Invalid special subframe pattern value [0..9]");
	}
}
static void dissect_laa_ed_threashold_for_lbt_for_pdsch_value(ptvcursor_t * ptvc, packet_info* pinfo)
{
	guint32 test_value;
	proto_item* item = ptvcursor_add_ret_uint(ptvc, hf_nfapi_ed_threshold_for_lbt_for_pdsch, 2, ENC_BIG_ENDIAN, &test_value);

	if (test_value > 70)
	{
		expert_add_info_format(pinfo, item, &ei_invalid_range, "Invalid ed threshold for ltb for pdsch value [0..70]");
	}
}
static void dissect_laa_ed_threashold_for_lbt_for_drs_value(ptvcursor_t * ptvc, packet_info* pinfo)
{
	guint32 test_value;
	proto_item* item = ptvcursor_add_ret_uint(ptvc, hf_nfapi_ed_threshold_for_lbt_for_drs, 2, ENC_BIG_ENDIAN, &test_value);

	if (test_value > 70)
	{
		expert_add_info_format(pinfo, item, &ei_invalid_range, "Invalid ed threshold for ltb for drs value [0..70]");
	}
}
static void dissect_laa_pd_threshold_value(ptvcursor_t * ptvc, packet_info* pinfo)
{
	guint32 test_value;
	proto_item* item = ptvcursor_add_ret_uint(ptvc, hf_nfapi_pd_threshold, 2, ENC_BIG_ENDIAN, &test_value);

	if (test_value > 70 && test_value != 65535)
	{
		expert_add_info_format(pinfo, item, &ei_invalid_range, "Invalid pd threshold value [0..70, 65536]");
	}
}
static void dissect_laa_multi_carrier_type_value(ptvcursor_t * ptvc, packet_info* pinfo)
{
	guint32 test_value;
	proto_item* item = ptvcursor_add_ret_uint(ptvc, hf_nfapi_multi_carrier_type, 2, ENC_BIG_ENDIAN, &test_value);

	if (test_value > 4)
	{
		expert_add_info_format(pinfo, item, &ei_invalid_range, "Invalid mutli carrier type [0..4]");
	}
}
static void dissect_laa_multi_carrier_tx_value(ptvcursor_t * ptvc, packet_info* pinfo)
{
	gint32 test_value;
	proto_item* item = ptvcursor_add_ret_boolean(ptvc, hf_nfapi_multi_carrier_tx, 2, ENC_BIG_ENDIAN, &test_value);

	if (test_value > 1)
	{
		expert_add_info_format(pinfo, item, &ei_invalid_range, "Invalid mutli carrier tx value [0..1]");
	}
}
static void dissect_laa_multi_carrier_freeze_value(ptvcursor_t * ptvc, packet_info* pinfo)
{
	gint32 test_value;
	proto_item* item = ptvcursor_add_ret_boolean(ptvc, hf_nfapi_multi_carrier_freeze, 2, ENC_BIG_ENDIAN, &test_value);

	if (test_value > 1)
	{
		expert_add_info_format(pinfo, item, &ei_invalid_range, "Invalid mutli carrier freeze value [0..1]");
	}
}
static void dissect_laa_tx_antenna_port_for_drs_value(ptvcursor_t * ptvc, packet_info* pinfo)
{
	guint32 test_value;
	proto_item* item = ptvcursor_add_ret_uint(ptvc, hf_nfapi_tx_antenna_ports_for_drs, 2, ENC_BIG_ENDIAN, &test_value);

	if (!(test_value == 1 || test_value == 2 || test_value == 4))
	{
		expert_add_info_format(pinfo, item, &ei_invalid_range, "Invalid tx antenna ports for drs value [1, 2, 4]");
	}
}
static void dissect_laa_transmission_power_for_drs_value(ptvcursor_t * ptvc, packet_info* pinfo)
{
	guint32 test_value;
	proto_item* item = ptvcursor_add_ret_uint(ptvc, hf_nfapi_transmission_power_for_drs, 2, ENC_BIG_ENDIAN, &test_value);

	if (test_value > 10000)
	{
		expert_add_info_format(pinfo, item, &ei_invalid_range, "Invalid transmission power for drs [0..10000]");
	}
}
static void dissect_emtc_pbch_repeitions_enabled_r13_value(ptvcursor_t * ptvc, packet_info* pinfo)
{
	gint32 test_value;
	proto_item* item = ptvcursor_add_ret_boolean(ptvc, hf_nfapi_pbch_repetitions_enabled_r13, 2, ENC_BIG_ENDIAN, &test_value);

	if (test_value > 1)
	{
		expert_add_info_format(pinfo, item, &ei_invalid_range, "Invalid pbch repetitions enabled r13 value [0..1]");
	}
}
static void dissect_emtc_prach_cat_m_root_sequence_index_value(ptvcursor_t * ptvc, packet_info* pinfo)
{
	guint32 test_value;
	proto_item* item = ptvcursor_add_ret_uint(ptvc, hf_nfapi_prach_cat_m_root_sequence_index, 2, ENC_BIG_ENDIAN, &test_value);

	if (test_value > 837)
	{
		expert_add_info_format(pinfo, item, &ei_invalid_range, "Invalid prach cat-m root sequence Index value [0..837]");
	}
}
static void dissect_emtc_prach_cat_m_zero_correlation_zone_configuration_value(ptvcursor_t * ptvc, packet_info* pinfo)
{
	guint32 test_value;
	proto_item* item = ptvcursor_add_ret_uint(ptvc, hf_nfapi_prach_cat_m_zero_correlation_zone_configuration, 2, ENC_BIG_ENDIAN, &test_value);

	if (test_value > 15)
	{
		expert_add_info_format(pinfo, item, &ei_invalid_range, "Invalid prach cat-m zero correlation zone configuration value [0..15]");
	}
}
static void dissect_emtc_prach_cat_m_high_speed_flag_value(ptvcursor_t * ptvc, packet_info* pinfo)
{
	gint32 test_value;
	proto_item* item = ptvcursor_add_ret_boolean(ptvc, hf_nfapi_prach_cat_m_high_speed_flag, 2, ENC_BIG_ENDIAN, &test_value);

	if (test_value > 1)
	{
		expert_add_info_format(pinfo, item, &ei_invalid_range, "Invalid prach cat-m high speed flag value [0..1]");
	}
}
static void dissect_emtc_prach_ce_level_0_enabled_value(ptvcursor_t * ptvc, packet_info* pinfo)
{
	gint32 test_value;
	proto_item* item = ptvcursor_add_ret_boolean(ptvc, hf_nfapi_prach_ce_level_0_enable, 2, ENC_BIG_ENDIAN, &test_value);

	if (test_value > 1)
	{
		expert_add_info_format(pinfo, item, &ei_invalid_range, "Invalid prach ce level #0 enable value [0..1]");
	}
}
static void dissect_emtc_prach_ce_level_0_configuration_offset_value(ptvcursor_t * ptvc, packet_info* pinfo)
{
	guint32 test_value;
	proto_item* item = ptvcursor_add_ret_uint(ptvc, hf_nfapi_prach_ce_level_0_configuration_index, 2, ENC_BIG_ENDIAN, &test_value);

	if (test_value > 63)
	{
		expert_add_info_format(pinfo, item, &ei_invalid_range, "Invalid prach ce level #0 configuration Index value [0..63]");
	}
}
static void dissect_emtc_prach_ce_level_0_frequency_offset_value(ptvcursor_t * ptvc, packet_info* pinfo)
{
	guint32 test_value;
	proto_item* item = ptvcursor_add_ret_uint(ptvc, hf_nfapi_prach_ce_level_0_frequency_offset, 2, ENC_BIG_ENDIAN, &test_value);

	if (test_value > (100 - 6))
	{
		expert_add_info_format(pinfo, item, &ei_invalid_range, "Invalid prach ce level #0 frequency offset value [0..94]");
	}
}
static void dissect_emtc_preach_ce_level_0_num_of_repeitions_per_attempt_value(ptvcursor_t * ptvc, packet_info* pinfo)
{
	guint32 test_value;
	proto_item* item = ptvcursor_add_ret_uint(ptvc, hf_nfapi_prach_ce_level_0_number_of_repetitions_per_attempt, 2, ENC_BIG_ENDIAN, &test_value);

	if (!( test_value == 1 || test_value == 2 || test_value == 4 || test_value == 8 || test_value == 16 || test_value == 32 ||
		   test_value == 64 || test_value == 128))
	{
		expert_add_info_format(pinfo, item, &ei_invalid_range, "Invalid prach ce level #0 number of repetitions per attempt value [1, 2, 4, 8, 16, 32, 64, 128]");
	}
}
static void dissect_emtc_ce_level_0_starting_subframe_periodicity_value(ptvcursor_t * ptvc, packet_info* pinfo)
{
	guint32 test_value;
	proto_item* item = ptvcursor_add_ret_uint(ptvc, hf_nfapi_prach_ce_level_0_starting_subframe_periodicity, 2, ENC_BIG_ENDIAN, &test_value);

	if (!(test_value == 0xFFF || test_value == 2 || test_value == 4 || test_value == 8 || test_value == 16 || test_value == 32 ||
		  test_value == 64 || test_value == 128 || test_value == 256))
	{
		expert_add_info_format(pinfo, item, &ei_invalid_range, "Invalid prach ce level #0 starting subframe periodicity value [2, 4, 8, 16, 32, 64, 128, 256, 0xFFFF]");
	}
}
static void dissect_emtc_preach_ce_level_0_hopping_enabled_value(ptvcursor_t * ptvc, packet_info* pinfo)
{
	gint32 test_value;
	proto_item* item = ptvcursor_add_ret_boolean(ptvc, hf_nfapi_prach_ce_level_0_hopping_enabled, 2, ENC_BIG_ENDIAN, &test_value);

	if (test_value > 1)
	{
		expert_add_info_format(pinfo, item, &ei_invalid_range, "Invalid prach ce level #0 hopping enabled value [0..1]");
	}
}
static void dissect_emtc_preach_ce_level_0_hopping_offset_value(ptvcursor_t * ptvc, packet_info* pinfo)
{
	guint32 test_value;
	proto_item* item = ptvcursor_add_ret_uint(ptvc, hf_nfapi_prach_ce_level_0_hopping_offset, 2, ENC_BIG_ENDIAN, &test_value);

	if (test_value > 94)
	{
		expert_add_info_format(pinfo, item, &ei_invalid_range, "Invalid prach ce level #0 hopping offset value [0..94]");
	}
}
static void dissect_emtc_prach_ce_level_1_enabled_value(ptvcursor_t * ptvc, packet_info* pinfo)
{
	gint32 test_value;
	proto_item* item = ptvcursor_add_ret_boolean(ptvc, hf_nfapi_prach_ce_level_1_enable, 2, ENC_BIG_ENDIAN, &test_value);

	if (test_value > 1)
	{
		expert_add_info_format(pinfo, item, &ei_invalid_range, "Invalid prach ce level #1 enable value [0..1]");
	}
}
static void dissect_emtc_prach_ce_level_1_configuration_offset_value(ptvcursor_t * ptvc, packet_info* pinfo)
{
	guint32 test_value;
	proto_item* item = ptvcursor_add_ret_uint(ptvc, hf_nfapi_prach_ce_level_1_configuration_index, 2, ENC_BIG_ENDIAN, &test_value);

	if (test_value > 63)
	{
		expert_add_info_format(pinfo, item, &ei_invalid_range, "Invalid prach ce level #1 configuration Index value [0..63]");
	}
}
static void dissect_emtc_prach_ce_level_1_frequency_offset_value(ptvcursor_t * ptvc, packet_info* pinfo)
{
	guint32 test_value;
	proto_item* item = ptvcursor_add_ret_uint(ptvc, hf_nfapi_prach_ce_level_1_frequency_offset, 2, ENC_BIG_ENDIAN, &test_value);

	if (test_value > (100 - 6))
	{
		expert_add_info_format(pinfo, item, &ei_invalid_range, "Invalid prach ce level #1 frequency offset value [0..94]");
	}
}
static void dissect_emtc_preach_ce_level_1_num_of_repeitions_per_attempt_value(ptvcursor_t * ptvc, packet_info* pinfo)
{
	guint32 test_value;
	proto_item* item = ptvcursor_add_ret_uint(ptvc, hf_nfapi_prach_ce_level_1_number_of_repetitions_per_attempt, 2, ENC_BIG_ENDIAN, &test_value);

	if (!(test_value == 1 || test_value == 2 || test_value == 4 || test_value == 8 || test_value == 16 || test_value == 32 ||
		test_value == 64 || test_value == 128))
	{
		expert_add_info_format(pinfo, item, &ei_invalid_range, "Invalid prach ce level #1 number of repetitions per attempt value [1, 2, 4, 8, 16, 32, 64, 128]");
	}
}
static void dissect_emtc_ce_level_1_starting_subframe_periodicity_value(ptvcursor_t * ptvc, packet_info* pinfo)
{
	guint32 test_value;
	proto_item* item = ptvcursor_add_ret_uint(ptvc, hf_nfapi_prach_ce_level_1_starting_subframe_periodicity, 2, ENC_BIG_ENDIAN, &test_value);

	if (!(test_value == 0xFFF || test_value == 2 || test_value == 4 || test_value == 8 || test_value == 16 || test_value == 32 ||
		test_value == 64 || test_value == 128 || test_value == 256))
	{
		expert_add_info_format(pinfo, item, &ei_invalid_range, "Invalid prach ce level #1 starting subframe periodicity value [2, 4, 8, 16, 32, 64, 128, 256, 0xFFFF]");
	}
}
static void dissect_emtc_preach_ce_level_1_hopping_enabled_value(ptvcursor_t * ptvc, packet_info* pinfo)
{
	gint32 test_value;
	proto_item* item = ptvcursor_add_ret_boolean(ptvc, hf_nfapi_prach_ce_level_1_hopping_enabled, 2, ENC_BIG_ENDIAN, &test_value);

	if (test_value > 1)
	{
		expert_add_info_format(pinfo, item, &ei_invalid_range, "Invalid prach ce level #1 hopping enabled value [0..1]");
	}
}
static void dissect_emtc_preach_ce_level_1_hopping_offset_value(ptvcursor_t * ptvc, packet_info* pinfo)
{
	guint32 test_value;
	proto_item* item = ptvcursor_add_ret_uint(ptvc, hf_nfapi_prach_ce_level_1_hopping_offset, 2, ENC_BIG_ENDIAN, &test_value);

	if (test_value > 94)
	{
		expert_add_info_format(pinfo, item, &ei_invalid_range, "Invalid prach ce level #1 hopping offset value [0..94]");
	}
}
static void dissect_emtc_prach_ce_level_2_enabled_value(ptvcursor_t * ptvc, packet_info* pinfo)
{
	gint32 test_value;
	proto_item* item = ptvcursor_add_ret_boolean(ptvc, hf_nfapi_prach_ce_level_2_enable, 2, ENC_BIG_ENDIAN, &test_value);

	if (test_value > 1)
	{
		expert_add_info_format(pinfo, item, &ei_invalid_range, "Invalid prach ce level #2 enable value [0..1]");
	}
}
static void dissect_emtc_prach_ce_level_2_configuration_offset_value(ptvcursor_t * ptvc, packet_info* pinfo)
{
	guint32 test_value;
	proto_item* item = ptvcursor_add_ret_uint(ptvc, hf_nfapi_prach_ce_level_2_configuration_index, 2, ENC_BIG_ENDIAN, &test_value);

	if (test_value > 63)
	{
		expert_add_info_format(pinfo, item, &ei_invalid_range, "Invalid prach ce level #2 configuration Index value [0..63]");
	}
}
static void dissect_emtc_prach_ce_level_2_frequency_offset_value(ptvcursor_t * ptvc, packet_info* pinfo)
{
	guint32 test_value;
	proto_item* item = ptvcursor_add_ret_uint(ptvc, hf_nfapi_prach_ce_level_2_frequency_offset, 2, ENC_BIG_ENDIAN, &test_value);

	if (test_value > (100 - 6))
	{
		expert_add_info_format(pinfo, item, &ei_invalid_range, "Invalid prach ce level #2 frequency offset value [0..94]");
	}
}
static void dissect_emtc_preach_ce_level_2_num_of_repeitions_per_attempt_value(ptvcursor_t * ptvc, packet_info* pinfo)
{
	guint32 test_value;
	proto_item* item = ptvcursor_add_ret_uint(ptvc, hf_nfapi_prach_ce_level_2_number_of_repetitions_per_attempt, 2, ENC_BIG_ENDIAN, &test_value);

	if (!(test_value == 1 || test_value == 2 || test_value == 4 || test_value == 8 || test_value == 16 || test_value == 32 ||
		test_value == 64 || test_value == 128))
	{
		expert_add_info_format(pinfo, item, &ei_invalid_range, "Invalid prach ce level #2 number of repetitions per attempt value [1, 2, 4, 8, 16, 32, 64, 128]");
	}
}
static void dissect_emtc_ce_level_2_starting_subframe_periodicity_value(ptvcursor_t * ptvc, packet_info* pinfo)
{
	guint32 test_value;
	proto_item* item = ptvcursor_add_ret_uint(ptvc, hf_nfapi_prach_ce_level_2_starting_subframe_periodicity, 2, ENC_BIG_ENDIAN, &test_value);

	if (!(test_value == 0xFFF || test_value == 2 || test_value == 4 || test_value == 8 || test_value == 16 || test_value == 32 ||
		test_value == 64 || test_value == 128 || test_value == 256))
	{
		expert_add_info_format(pinfo, item, &ei_invalid_range, "Invalid prach ce level #2 starting subframe periodicity value [2, 4, 8, 16, 32, 64, 128, 256, 0xFFFF]");
	}
}
static void dissect_emtc_preach_ce_level_2_hopping_enabled_value(ptvcursor_t * ptvc, packet_info* pinfo)
{
	gint32 test_value;
	proto_item* item = ptvcursor_add_ret_boolean(ptvc, hf_nfapi_prach_ce_level_2_hopping_enabled, 2, ENC_BIG_ENDIAN, &test_value);

	if (test_value > 1)
	{
		expert_add_info_format(pinfo, item, &ei_invalid_range, "Invalid prach ce level #2 hopping enabled value [0..1]");
	}
}
static void dissect_emtc_preach_ce_level_2_hopping_offset_value(ptvcursor_t * ptvc, packet_info* pinfo)
{
	guint32 test_value;
	proto_item* item = ptvcursor_add_ret_uint(ptvc, hf_nfapi_prach_ce_level_2_hopping_offset, 2, ENC_BIG_ENDIAN, &test_value);

	if (test_value > 94)
	{
		expert_add_info_format(pinfo, item, &ei_invalid_range, "Invalid prach ce level #2 hopping offset value [0..94]");
	}
}
static void dissect_emtc_prach_ce_level_3_enabled_value(ptvcursor_t * ptvc, packet_info* pinfo)
{
	gint32 test_value;
	proto_item* item = ptvcursor_add_ret_boolean(ptvc, hf_nfapi_prach_ce_level_3_enable, 2, ENC_BIG_ENDIAN, &test_value);

	if (test_value > 1)
	{
		expert_add_info_format(pinfo, item, &ei_invalid_range, "Invalid prach ce level #3 enable value [0..1]");
	}
}
static void dissect_emtc_prach_ce_level_3_configuration_offset_value(ptvcursor_t * ptvc, packet_info* pinfo)
{
	guint32 test_value;
	proto_item* item = ptvcursor_add_ret_uint(ptvc, hf_nfapi_prach_ce_level_3_configuration_index, 2, ENC_BIG_ENDIAN, &test_value);

	if (test_value > 63)
	{
		expert_add_info_format(pinfo, item, &ei_invalid_range, "Invalid prach ce level #2 configuration Index value [0..63]");
	}
}
static void dissect_emtc_prach_ce_level_3_frequency_offset_value(ptvcursor_t * ptvc, packet_info* pinfo)
{
	guint32 test_value;
	proto_item* item = ptvcursor_add_ret_uint(ptvc, hf_nfapi_prach_ce_level_3_frequency_offset, 2, ENC_BIG_ENDIAN, &test_value);

	if (test_value > (100 - 6))
	{
		expert_add_info_format(pinfo, item, &ei_invalid_range, "Invalid prach ce level #3 frequency offset value [0..94]");
	}
}
static void dissect_emtc_preach_ce_level_3_num_of_repeitions_per_attempt_value(ptvcursor_t * ptvc, packet_info* pinfo)
{
	guint32 test_value;
	proto_item* item = ptvcursor_add_ret_uint(ptvc, hf_nfapi_prach_ce_level_3_number_of_repetitions_per_attempt, 2, ENC_BIG_ENDIAN, &test_value);

	if (!(test_value == 1 || test_value == 2 || test_value == 4 || test_value == 8 || test_value == 16 || test_value == 32 ||
		test_value == 64 || test_value == 128))
	{
		expert_add_info_format(pinfo, item, &ei_invalid_range, "Invalid prach ce level #3 number of repetitions per attempt value [1, 2, 4, 8, 16, 32, 64, 128]");
	}
}
static void dissect_emtc_ce_level_3_starting_subframe_periodicity_value(ptvcursor_t * ptvc, packet_info* pinfo)
{
	guint32 test_value;
	proto_item* item = ptvcursor_add_ret_uint(ptvc, hf_nfapi_prach_ce_level_3_starting_subframe_periodicity, 2, ENC_BIG_ENDIAN, &test_value);

	if (!(test_value == 0xFFF || test_value == 2 || test_value == 4 || test_value == 8 || test_value == 16 || test_value == 32 ||
		test_value == 64 || test_value == 128 || test_value == 256))
	{
		expert_add_info_format(pinfo, item, &ei_invalid_range, "Invalid prach ce level #3 starting subframe periodicity value [2, 4, 8, 16, 32, 64, 128, 256, 0xFFFF]");
	}
}
static void dissect_emtc_preach_ce_level_3_hopping_enabled_value(ptvcursor_t * ptvc, packet_info* pinfo)
{
	gint32 test_value;
	proto_item* item = ptvcursor_add_ret_boolean(ptvc, hf_nfapi_prach_ce_level_3_hopping_enabled, 2, ENC_BIG_ENDIAN, &test_value);

	if (test_value > 1)
	{
		expert_add_info_format(pinfo, item, &ei_invalid_range, "Invalid prach ce level #3 hopping enabled value [0..1]");
	}
}
static void dissect_emtc_preach_ce_level_3_hopping_offset_value(ptvcursor_t * ptvc, packet_info* pinfo)
{
	guint32 test_value;
	proto_item* item = ptvcursor_add_ret_uint(ptvc, hf_nfapi_prach_ce_level_3_hopping_offset, 2, ENC_BIG_ENDIAN, &test_value);

	if (test_value > 94)
	{
		expert_add_info_format(pinfo, item, &ei_invalid_range, "Invalid prach ce level #3 hopping offset value [0..94]");
	}
}
static void dissect_emtc_pucch_interval_ul_hopping_config_common_mode_a_value(ptvcursor_t * ptvc, packet_info* pinfo)
{
	guint32 test_value;
	proto_item* item = ptvcursor_add_ret_uint(ptvc, hf_nfapi_pucch_internal_ul_hopping_config_common_mode_a, 2, ENC_BIG_ENDIAN, &test_value);

	if (!(test_value == 1 || test_value == 2 || test_value == 4 || test_value == 8 || test_value == 5 || test_value == 10 || test_value == 20))
	{
		expert_add_info_format(pinfo, item, &ei_invalid_range, "Invalid pucch internal ul hopping config common mode a value [1, 2, 4, 8] or [1, 5, 10, 20]");
	}
}
static void dissect_emtc_pucch_interval_ul_hopping_config_common_mode_b_value(ptvcursor_t * ptvc, packet_info* pinfo)
{
	guint32 test_value;
	proto_item* item = ptvcursor_add_ret_uint(ptvc, hf_nfapi_pucch_internal_ul_hopping_config_common_mode_b, 2, ENC_BIG_ENDIAN, &test_value);

	if (!(test_value == 2 || test_value == 4 || test_value == 8 || test_value == 16 || test_value == 5 || test_value == 10 || test_value == 20 || test_value == 40))
	{
		expert_add_info_format(pinfo, item, &ei_invalid_range, "Invalid pucch internal ul hopping config common mode a value [2, 4, 8, 16] or [5, 10, 20, 40]");
	}
}
static void dissect_dl_bandwidth_support_value(ptvcursor_t * ptvc, packet_info* pinfo)
{
	guint64 test_value64;
	proto_item* item = proto_tree_add_bitmask_ret_uint64(ptvcursor_tree(ptvc), ptvcursor_tvbuff(ptvc), ptvcursor_current_offset(ptvc),
					hf_nfapi_dl_bandwidth_support, ett_nfapi_downlink_bandwidth_support, dl_bandwidth_support_fields, ENC_BIG_ENDIAN, &test_value64);
	if (test_value64 > 0x3F)
	{
		expert_add_info_format(pinfo, item, &ei_invalid_range, "Invalid downlink bandwidth supported bits [0..0x3F]");
	}

	ptvcursor_advance(ptvc, 2);
}
static void dissect_ul_bandwidth_support_value(ptvcursor_t * ptvc, packet_info* pinfo)
{
	guint64 test_value64;
	proto_item* item = proto_tree_add_bitmask_ret_uint64(ptvcursor_tree(ptvc), ptvcursor_tvbuff(ptvc), ptvcursor_current_offset(ptvc),
					hf_nfapi_ul_bandwidth_support, ett_nfapi_uplink_bandwidth_support, ul_bandwidth_support_fields, ENC_BIG_ENDIAN, &test_value64);
	if (test_value64 > 0x3F)
	{
		expert_add_info_format(pinfo, item, &ei_invalid_range, "Invalid uplink bandwidth supported bits [0..0x3F]");
	}

	ptvcursor_advance(ptvc, 2);

}
static void dissect_dl_modulation_value(ptvcursor_t * ptvc, packet_info* pinfo)
{
	static int * const dl_modulation_support_fields[] = {
		&hf_nfapi_dl_modulation_support_qpsk,
		&hf_nfapi_dl_modulation_support_16qam,
		&hf_nfapi_dl_modulation_support_64qam,
		&hf_nfapi_dl_modulation_support_256qam,
		NULL
	};

	guint64 test_value64;
	proto_item* item = proto_tree_add_bitmask_ret_uint64(ptvcursor_tree(ptvc), ptvcursor_tvbuff(ptvc), ptvcursor_current_offset(ptvc),
					hf_nfapi_dl_modulation_support, ett_nfapi_downlink_modulation_support, dl_modulation_support_fields, ENC_BIG_ENDIAN, &test_value64);

	if (test_value64 > 0xF)
	{
		expert_add_info_format(pinfo, item, &ei_invalid_range, "Invalid downlink modulation support bit [0..0xF]");
	}

	ptvcursor_advance(ptvc, 2);
}
static void dissect_ul_modulation_value(ptvcursor_t * ptvc, packet_info* pinfo)
{
	static int * const ul_modulation_support_fields[] = {
		&hf_nfapi_ul_modulation_support_qpsk,
		&hf_nfapi_ul_modulation_support_16qam,
		&hf_nfapi_ul_modulation_support_64qam,
		NULL
	};

	guint64 test_value64;
	proto_item* item = proto_tree_add_bitmask_ret_uint64(ptvcursor_tree(ptvc), ptvcursor_tvbuff(ptvc), ptvcursor_current_offset(ptvc),
					hf_nfapi_ul_modulation_support, ett_nfapi_uplink_modulation_support, ul_modulation_support_fields, ENC_BIG_ENDIAN, &test_value64);

	if (test_value64 > 0x7)
	{
		expert_add_info_format(pinfo, item, &ei_invalid_range, "Invalid uplink modulation support bit [0..0x7]");
	}

	ptvcursor_advance(ptvc, 2);
}
static void dissect_phy_antenna_capability_value(ptvcursor_t * ptvc, packet_info* pinfo)
{
	guint32 test_value;
	proto_item* item = ptvcursor_add_ret_uint(ptvc, hf_nfapi_phy_antenna_capability, 2, ENC_BIG_ENDIAN, &test_value);

	if (!(test_value == 1 || test_value == 2 || test_value == 4 || test_value == 8 || test_value == 16))
	{
		expert_add_info_format(pinfo, item, &ei_invalid_range, "Invalid phy antenna capability [1, 2, 4, 8, 16]");
	}
}
static void dissect_release_capability_value(ptvcursor_t * ptvc, packet_info* pinfo)
{
	guint64 test_value64;
	proto_item* item = proto_tree_add_bitmask_ret_uint64(ptvcursor_tree(ptvc), ptvcursor_tvbuff(ptvc), ptvcursor_current_offset(ptvc),
											hf_nfapi_release_capability, ett_nfapi_release_support, maximum_3gpp_release_supported_fields, ENC_BIG_ENDIAN, &test_value64);
	if (test_value64 > 0x3F)
	{
		expert_add_info_format(pinfo, item, &ei_invalid_range, "Invalid release capability value [0..0x3F]");
	}

	ptvcursor_advance(ptvc, 2);
}
static void dissect_mbsfn_value(ptvcursor_t * ptvc, packet_info* pinfo)
{
	gint32 test_value;
	proto_item* item = ptvcursor_add_ret_boolean(ptvc, hf_nfapi_mbsfn_capability, 2, ENC_BIG_ENDIAN, &test_value);

	if (test_value > 1)
	{
		expert_add_info_format(pinfo, item, &ei_invalid_range, "Invalid mbsfn capability bit [0..0x1]");
	}
}
static void dissect_laa_support_value(ptvcursor_t * ptvc, packet_info* pinfo)
{
	gint32 test_value;
	proto_item* item = ptvcursor_add_ret_boolean(ptvc, hf_nfapi_laa_capability, 2, ENC_BIG_ENDIAN, &test_value);

	if (test_value > 1)
	{
		expert_add_info_format(pinfo, item, &ei_invalid_range, "Invalid laa support bit [0..0x1]");
	}
}
static void dissect_laa_pd_sensing_lbt_support_value(ptvcursor_t * ptvc, packet_info* pinfo)
{
	gint32 test_value;
	proto_item* item = ptvcursor_add_ret_boolean(ptvc, hf_nfapi_pd_sensing_lbt_support, 2, ENC_BIG_ENDIAN, &test_value);

	if (test_value > 1)
	{
		expert_add_info_format(pinfo, item, &ei_invalid_range, "Invalid pd sensing lbt support bit [0..0x1]");
	}
}
static void dissect_laa_multi_carrier_lbt_support_value(ptvcursor_t * ptvc, packet_info* pinfo)
{
	guint32 test_value;
	proto_item* item = ptvcursor_add_ret_uint(ptvc, hf_nfapi_multi_carrier_lbt_support, 2, ENC_BIG_ENDIAN, &test_value);

	if (test_value > 0xF)
	{
		expert_add_info_format(pinfo, item, &ei_invalid_range, "Invalid multi carrier LBT support bit [0..0xF]");
	}
}
static void dissect_laa_partial_sf_support_value(ptvcursor_t * ptvc, packet_info* pinfo)
{
	gint32 test_value;
	proto_item* item = ptvcursor_add_ret_boolean(ptvc, hf_nfapi_partial_sf_support, 2, ENC_BIG_ENDIAN, &test_value);

	if (test_value > 0x1)
	{
		expert_add_info_format(pinfo, item, &ei_invalid_range, "Invalid partial SF support bit [0..0x1]");
	}
}
static void dissect_data_report_mode_value(ptvcursor_t * ptvc, packet_info* pinfo)
{
	gboolean test_value;
	proto_item* item = ptvcursor_add_ret_boolean(ptvc, hf_nfapi_data_report_mode, 2, ENC_BIG_ENDIAN, &test_value);

	if (test_value > 1)
	{
		expert_add_info_format(pinfo, item, &ei_invalid_range, "Invalid data report mode value [0..1]");
	}
}
static void dissect_sfn_sf_value(ptvcursor_t * ptvc, packet_info* pinfo)
{
	guint32 test_value;
	proto_item* item = ptvcursor_add_ret_uint(ptvc, hf_nfapi_sfnsf, 2, ENC_BIG_ENDIAN, &test_value);

	guint32 sfn = test_value >> 0x4;
	guint32 sf = test_value & 0x000F;
	if (sfn > 1023 || sf > 9)
	{
		expert_add_info_format(pinfo, item, &ei_invalid_range, "Invalid sfn/sf value sfn:%u [0..1023] sf:%u [0..9]", sfn, sf);
	}
}
static void dissect_phy_state_value(ptvcursor_t * ptvc, packet_info* pinfo)
{
	guint32 test_value;
	proto_item* item = ptvcursor_add_ret_uint(ptvc, hf_nfapi_phy_state, 2, ENC_BIG_ENDIAN, &test_value);

	if (test_value > 2)
	{
		expert_add_info_format(pinfo, item, &ei_invalid_range, "Invalid phy state [0..2]");
	}
}
static void dissect_p7_vnf_address_ipv4_value(ptvcursor_t * ptvc, packet_info* pinfo _U_)
{
	ptvcursor_add(ptvc, hf_nfapi_vnf_address_ipv4, 4, ENC_NA);
}
static void dissect_p7_vnf_address_ipv6_value(ptvcursor_t * ptvc, packet_info* pinfo _U_)
{
	ptvcursor_add(ptvc, hf_nfapi_vnf_address_ipv6, 16, ENC_NA);
}
static void dissect_p7_vnf_port_value(ptvcursor_t * ptvc, packet_info* pinfo _U_)
{
	ptvcursor_add(ptvc, hf_nfapi_vnf_port, 2, ENC_BIG_ENDIAN);
}
static void dissect_p7_pnf_address_ipv4_value(ptvcursor_t * ptvc, packet_info* pinfo _U_)
{
	ptvcursor_add(ptvc, hf_nfapi_pnf_address_ipv4, 4, ENC_NA);
}
static void dissect_p7_pnf_address_ipv6_value(ptvcursor_t * ptvc, packet_info* pinfo _U_)
{
	ptvcursor_add(ptvc, hf_nfapi_pnf_address_ipv6, 16, ENC_NA);
}
static void dissect_p7_pnf_port_value(ptvcursor_t * ptvc, packet_info* pinfo _U_)
{
	ptvcursor_add(ptvc, hf_nfapi_pnf_port, 2, ENC_BIG_ENDIAN);
}
static void dissect_downlink_ues_per_subframe_value(ptvcursor_t * ptvc, packet_info* pinfo _U_)
{
	ptvcursor_add(ptvc, hf_nfapi_dl_ue_per_sf, 1, ENC_BIG_ENDIAN);
}
static void dissect_uplink_ues_per_subframe_value(ptvcursor_t * ptvc, packet_info* pinfo _U_)
{
	ptvcursor_add(ptvc, hf_nfapi_ul_ue_per_sf, 1, ENC_BIG_ENDIAN);
}
static void dissect_rf_band_value(ptvcursor_t * ptvc, packet_info* pinfo _U_)
{
	ptvcursor_add(ptvc, hf_nfapi_band, 2, ENC_BIG_ENDIAN);
}
static void dissect_rf_bands_value(ptvcursor_t * ptvc, packet_info* pinfo)
{
	guint32 count;
	ptvcursor_add_ret_uint(ptvc, hf_nfapi_number_of_rf_bands, 2, ENC_BIG_ENDIAN, &count);
	dissect_array_value(ptvc, pinfo, "RF Band List", ett_nfapi_rf_bands, count, dissect_rf_band_value);
}
static void dissect_timing_window_value(ptvcursor_t * ptvc, packet_info* pinfo)
{
	guint32 test_value;
	proto_item* item = ptvcursor_add_ret_uint(ptvc, hf_nfapi_timing_window, 1, ENC_BIG_ENDIAN, &test_value);

	if (test_value > 30)
	{
		expert_add_info_format(pinfo, item, &ei_invalid_range, "Invalid timing window value [0..30]");
	}
}
static void dissect_timing_info_mode_value(ptvcursor_t * ptvc, packet_info* pinfo)
{
	guint32 test_value;
	proto_item* item = ptvcursor_add_ret_uint(ptvc, hf_nfapi_timing_info_mode, 1, ENC_BIG_ENDIAN, &test_value);

	if (test_value > 0x3)
	{
		expert_add_info_format(pinfo, item, &ei_invalid_range, "Invalid timing info mode [0..0x3]");
	}
}
static void dissect_timing_info_period_value(ptvcursor_t * ptvc, packet_info* pinfo)
{
	guint32 test_value;
	proto_item* item = ptvcursor_add_ret_uint(ptvc, hf_nfapi_timing_info_period, 1, ENC_BIG_ENDIAN, &test_value);

	if (!(test_value >= 1 && test_value <= 255))
	{
		expert_add_info_format(pinfo, item, &ei_invalid_range, "Invalid timing info period [1..255]");
	}
}
static void dissect_maximum_transmit_power_value(ptvcursor_t * ptvc, packet_info* pinfo)
{
	guint32 test_value;
	proto_item* item = ptvcursor_add_ret_uint(ptvc, hf_nfapi_maximum_transmit_power_2, 2, ENC_BIG_ENDIAN, &test_value);

	if (test_value > 700)
	{
		expert_add_info_format(pinfo, item, &ei_invalid_range, "Invalid maxiumum transmit power [0..700]");
	}
}
static void dissect_earfcn_value(ptvcursor_t * ptvc, packet_info* pinfo _U_)
{
	ptvcursor_add(ptvc, hf_nfapi_earfcn, 2, ENC_BIG_ENDIAN);
}
static void dissect_nmm_gsm_frequency_bands_value(ptvcursor_t * ptvc, packet_info* pinfo)
{
	guint32 count;
	ptvcursor_add_ret_uint(ptvc, hf_nfapi_number_of_rf_bands, 2, ENC_BIG_ENDIAN, &count);
	dissect_array_value(ptvc, pinfo, "RF Band List", ett_nfapi_rf_bands, count, dissect_rf_band_value);
}
static void dissect_nmm_umts_frequency_bands_value(ptvcursor_t * ptvc, packet_info* pinfo)
{
	guint32 count;
	ptvcursor_add_ret_uint(ptvc, hf_nfapi_number_of_rf_bands, 2, ENC_BIG_ENDIAN, &count);
	dissect_array_value(ptvc, pinfo, "RF Band List", ett_nfapi_rf_bands, count, dissect_rf_band_value);
}
static void dissect_nmm_lte_frequency_bands_value(ptvcursor_t * ptvc, packet_info* pinfo)
{
	guint32 count;
	ptvcursor_add_ret_uint(ptvc, hf_nfapi_number_of_rf_bands, 2, ENC_BIG_ENDIAN, &count);
	dissect_array_value(ptvc, pinfo, "RF Band List", ett_nfapi_rf_bands, count, dissect_rf_band_value);
}
static void dissect_nmm_uplink_rssi_supported_value(ptvcursor_t * ptvc, packet_info* pinfo)
{
	guint32 test_value;
	proto_item* item = ptvcursor_add_ret_uint(ptvc, hf_nfapi_nmm_uplink_rssi_supported, 1, ENC_BIG_ENDIAN, &test_value);

	if (test_value > 1)
	{
		expert_add_info_format(pinfo, item, &ei_invalid_range, "Invalid nmm uplink rssi supported value [0..1]");
	}
}
static void dissect_dl_config_pdu(ptvcursor_t * ptvc, packet_info* pinfo)
{
	guint32 size;
	ptvcursor_add(ptvc, hf_nfapi_dl_config_pdu_type, 1, ENC_BIG_ENDIAN);
	ptvcursor_add_ret_uint(ptvc, hf_nfapi_pdu_size, 1, ENC_BIG_ENDIAN, &size);

	guint pdu_end = (ptvcursor_current_offset(ptvc) + size - 2);
	dissect_tlv_list(ptvc, pinfo, pdu_end);
}
static void dissect_dl_config_request_body_value(ptvcursor_t * ptvc, packet_info* pinfo)
{
	proto_item* item;
	guint32 test_value, number_of_dcis_value, number_of_pdus_value;

	// Number of PDCCH OFDM symbols
	item = ptvcursor_add_ret_uint(ptvc, hf_nfapi_number_pdcch_ofdm_symbols, 1, ENC_BIG_ENDIAN, &test_value);
	if (test_value > 4)
	{
		expert_add_info_format(pinfo, item, &ei_invalid_range, "Invalid number of pdcch ofdm symbols value [0..4]");
	}

	// Number of DCIs
	ptvcursor_add_ret_uint(ptvc, hf_nfapi_number_dci, 1, ENC_BIG_ENDIAN, &number_of_dcis_value);

	// Number of PDUs
	item = ptvcursor_add_ret_uint(ptvc, hf_nfapi_number_pdus, 2, ENC_BIG_ENDIAN, &number_of_pdus_value);
	if (number_of_pdus_value > 514)
	{
		expert_add_info_format(pinfo, item, &ei_invalid_range, "Invalid number of pdus value [0..514]");
	}

	// Number of PDSCH RNTIs
	ptvcursor_add(ptvc, hf_nfapi_number_pdsch_rnti, 1, ENC_BIG_ENDIAN);

	// Transmission power for PCFICH
	item = ptvcursor_add_ret_uint(ptvc, hf_nfapi_transmission_power_pcfich, 2, ENC_BIG_ENDIAN, &test_value);
	if (test_value > 10000)
	{
		expert_add_info_format(pinfo, item, &ei_invalid_range, "Invalid transmission power for pcfich value [0..10000]");
	}

	dissect_array_value(ptvc, pinfo, "DL Config PDU List", ett_nfapi_dl_config_request_pdu_list, number_of_dcis_value + number_of_pdus_value, dissect_dl_config_pdu);
}
static void dissect_dl_config_request_bch_pdu_rel8_value(ptvcursor_t * ptvc, packet_info* pinfo)
{
	proto_item* item;
	guint32 test_value;

	// Length
	ptvcursor_add(ptvc, hf_nfapi_length, 2, ENC_BIG_ENDIAN);

	// PDU index
	ptvcursor_add(ptvc, hf_nfapi_pdu_index, 2, ENC_BIG_ENDIAN);

	// Transmission power
	item = ptvcursor_add_ret_uint(ptvc, hf_nfapi_transmission_power, 2, ENC_BIG_ENDIAN, &test_value);
	if (test_value > 10000)
	{
		expert_add_info_format(pinfo, item, &ei_invalid_range, "Invalid transmission power value [0..10000]");
	}

}
static void dissect_dl_config_request_dl_dci_pdu_rel8_value(ptvcursor_t * ptvc, packet_info* pinfo)
{
	proto_item* item;
	guint32 test_value;

	// DCI format
	item = ptvcursor_add_ret_uint(ptvc, hf_nfapi_dl_dci_format, 1, ENC_BIG_ENDIAN, &test_value);
	if (test_value > 9)
	{
		expert_add_info_format(pinfo, item, &ei_invalid_range, "Invalid dci format value [0..9]");
	}

	// CCE index
	item = ptvcursor_add_ret_uint(ptvc, hf_nfapi_cce_idx, 1, ENC_BIG_ENDIAN, &test_value);
	if (test_value > 88)
	{
		expert_add_info_format(pinfo, item, &ei_invalid_range, "Invalid cce Index value [0..88]");
	}

	// Aggregation level
	item = ptvcursor_add_ret_uint(ptvc, hf_nfapi_aggregation_level, 1, ENC_BIG_ENDIAN, &test_value);
	if (!(test_value == 1 || test_value == 2 || test_value == 4 ||
		  test_value == 8 || test_value == 16 || test_value == 32))
	{
		expert_add_info_format(pinfo, item, &ei_invalid_range, "Invalid aggregation level value [1, 2, 4, 8, 16, 32]");
	}

	// RNTI
	item = ptvcursor_add_ret_uint(ptvc, hf_nfapi_rnti, 2, ENC_BIG_ENDIAN, &test_value);
	if (test_value < 1)
	{
		expert_add_info_format(pinfo, item, &ei_invalid_range, "Invalid rnti value [1..65535]");
	}

	// Resource allocation type
	item = ptvcursor_add_ret_uint(ptvc, hf_nfapi_resource_allocation_type, 1, ENC_BIG_ENDIAN, &test_value);
	if (test_value > 1)
	{
		expert_add_info_format(pinfo, item, &ei_invalid_range, "Invalid resource allocation type value [0..1]");
	}

	// Virtual resource block assignment flag
	item = ptvcursor_add_ret_uint(ptvc, hf_nfapi_virtual_resource_block_assignment_flag, 1, ENC_BIG_ENDIAN, &test_value);
	if (test_value > 1)
	{
		expert_add_info_format(pinfo, item, &ei_invalid_range, "Invalid virtual resource block assignment flag value [0..1]");
	}

	// Resource block coding
	ptvcursor_add(ptvc, hf_nfapi_resource_block_coding, 4, ENC_BIG_ENDIAN);

	// MCS_1
	item = ptvcursor_add_ret_uint(ptvc, hf_nfapi_mcs_1, 1, ENC_BIG_ENDIAN, &test_value);
	if (test_value > 31)
	{
		expert_add_info_format(pinfo, item, &ei_invalid_range, "Invalid mcs 1 value [0..31]");
	}

	// Redundancy version_1
	item = ptvcursor_add_ret_uint(ptvc, hf_nfapi_redundancy_version_1, 1, ENC_BIG_ENDIAN, &test_value);
	if (test_value > 3)
	{
		expert_add_info_format(pinfo, item, &ei_invalid_range, "Invalid redundancy version 1 value [0..3]");
	}

	// New data indicator_1
	item = ptvcursor_add_ret_uint(ptvc, hf_nfapi_new_data_indicator_1, 1, ENC_BIG_ENDIAN, &test_value);
	if (test_value > 3)
	{
		expert_add_info_format(pinfo, item, &ei_invalid_range, "Invalid new data indicator 1 value [0..1]");
	}

	// Transport block to codeword swap flag
	item = ptvcursor_add_ret_uint(ptvc, hf_nfapi_transport_block_to_codeword_swap_flag, 1, ENC_BIG_ENDIAN, &test_value);
	if (test_value > 3)
	{
		expert_add_info_format(pinfo, item, &ei_invalid_range, "Invalid transport block to codeword swap flag value [0..1]");
	}

	// MCS_2
	item = ptvcursor_add_ret_uint(ptvc, hf_nfapi_mcs_2, 1, ENC_BIG_ENDIAN, &test_value);
	if (test_value > 31)
	{
		expert_add_info_format(pinfo, item, &ei_invalid_range, "Invalid mcs 2 value [0..31]");
	}

	// Redundancy version_2
	item = ptvcursor_add_ret_uint(ptvc, hf_nfapi_redundancy_version_2, 1, ENC_BIG_ENDIAN, &test_value);
	if (test_value > 3)
	{
		expert_add_info_format(pinfo, item, &ei_invalid_range, "Invalid redundancy version 2 value [0..3]");
	}

	// New Data indicator_2
	item = ptvcursor_add_ret_uint(ptvc, hf_nfapi_new_data_indicator_2, 1, ENC_BIG_ENDIAN, &test_value);
	if (test_value > 3)
	{
		expert_add_info_format(pinfo, item, &ei_invalid_range, "Invalid new data indicator 2 value [0..1]");
	}

	// HARQ process
	item = ptvcursor_add_ret_uint(ptvc, hf_nfapi_harq_process, 1, ENC_BIG_ENDIAN, &test_value);
	if (test_value > 3)
	{
		expert_add_info_format(pinfo, item, &ei_invalid_range, "Invalid harq process value [0..15]");
	}

	// TPMI
	item = ptvcursor_add_ret_uint(ptvc, hf_nfapi_tpmi, 1, ENC_BIG_ENDIAN, &test_value);
	if (test_value > 3)
	{
		expert_add_info_format(pinfo, item, &ei_invalid_range, "Invalid tpmi value [0..3]");
	}

	// PMI
	item = ptvcursor_add_ret_uint(ptvc, hf_nfapi_pmi, 1, ENC_BIG_ENDIAN, &test_value);
	if (test_value > 2)
	{
		expert_add_info_format(pinfo, item, &ei_invalid_range, "Invalid tpmi value [0..2]");
	}

	// Precoding information
	item = ptvcursor_add_ret_uint(ptvc, hf_nfapi_precoding_information, 1, ENC_BIG_ENDIAN, &test_value);
	if (test_value > 2)
	{
		expert_add_info_format(pinfo, item, &ei_invalid_range, "Invalid precoding information value [0..15]");
	}

	// TPC
	item = ptvcursor_add_ret_uint(ptvc, hf_nfapi_tpc, 1, ENC_BIG_ENDIAN, &test_value);
	if (test_value > 3)
	{
		expert_add_info_format(pinfo, item, &ei_invalid_range, "Invalid tpc value [0..3]");
	}

	// Downlink assignment index
	item = ptvcursor_add_ret_uint(ptvc, hf_nfapi_downlink_assignment_index, 1, ENC_BIG_ENDIAN, &test_value);
	if (test_value > 15)
	{
		expert_add_info_format(pinfo, item, &ei_invalid_range, "Invalid downlink assignment value [0..15]");
	}

	// NGAP
	item = ptvcursor_add_ret_uint(ptvc, hf_nfapi_ngap, 1, ENC_BIG_ENDIAN, &test_value);
	if (test_value > 1)
	{
		expert_add_info_format(pinfo, item, &ei_invalid_range, "Invalid ngap value [0..1]");
	}

	// Transport block size index
	item = ptvcursor_add_ret_uint(ptvc, hf_nfapi_transport_block_size_index, 1, ENC_BIG_ENDIAN, &test_value);
	if (test_value > 31)
	{
		expert_add_info_format(pinfo, item, &ei_invalid_range, "Invalid transport block size Index value [0..31]");
	}

	// Downlink power offset
	item = ptvcursor_add_ret_uint(ptvc, hf_nfapi_downlink_power_offset, 1, ENC_BIG_ENDIAN, &test_value);
	if (test_value > 1)
	{
		expert_add_info_format(pinfo, item, &ei_invalid_range, "Invalid downlink power offset value [0..1]");
	}

	// Allocate PRACH flag
	item = ptvcursor_add_ret_uint(ptvc, hf_nfapi_allocate_prach_flag, 1, ENC_BIG_ENDIAN, &test_value);
	if (test_value > 1)
	{
		expert_add_info_format(pinfo, item, &ei_invalid_range, "Invalid allocate prach flag value [0..1]");
	}

	// Preamble index
	item = ptvcursor_add_ret_uint(ptvc, hf_nfapi_preamble_index, 1, ENC_BIG_ENDIAN, &test_value);
	if (test_value > 63)
	{
		expert_add_info_format(pinfo, item, &ei_invalid_range, "Invalid preamble Index value [0..63]");
	}

	// PRACH mask index
	item = ptvcursor_add_ret_uint(ptvc, hf_nfapi_prach_mask_index, 1, ENC_BIG_ENDIAN, &test_value);
	if (test_value > 15)
	{
		expert_add_info_format(pinfo, item, &ei_invalid_range, "Invalid prach mask Index value [0..15]");
	}

	// RNTI type
	item = ptvcursor_add_ret_uint(ptvc, hf_nfapi_rnti_type, 1, ENC_BIG_ENDIAN, &test_value);
	if (!(test_value >= 1 && test_value <= 3))
	{
		expert_add_info_format(pinfo, item, &ei_invalid_range, "Invalid rnti type value [1..3]");
	}

	// Transmission power
	item = ptvcursor_add_ret_uint(ptvc, hf_nfapi_transmission_power, 2, ENC_BIG_ENDIAN, &test_value);
	if (test_value > 10000)
	{
		expert_add_info_format(pinfo, item, &ei_invalid_range, "Invalid transmission power value value [0..10000]");
	}

}
static void dissect_dl_config_request_dl_dci_pdu_rel9_value(ptvcursor_t * ptvc, packet_info* pinfo)
{
	proto_item* item;
	guint32 test_value;
	gboolean test_boolean;

	// MCCH flag
	item = ptvcursor_add_ret_boolean(ptvc, hf_nfapi_mcch_flag, 1, ENC_BIG_ENDIAN, &test_boolean);
	if (test_boolean > 1)
	{
		expert_add_info_format(pinfo, item, &ei_invalid_range, "Invalid mcch flag value [0..1]");
	}

	// MCCH change notification
	ptvcursor_add(ptvc, hf_nfapi_mcch_change_notification, 1, ENC_BIG_ENDIAN);

	// Scrambling identity
	item = ptvcursor_add_ret_uint(ptvc, hf_nfapi_scrambling_identity, 1, ENC_BIG_ENDIAN, &test_value);
	if (test_value > 1)
	{
		expert_add_info_format(pinfo, item, &ei_invalid_range, "Invalid scrambling identity value [0..1]");
	}

}
static void dissect_dl_config_request_dl_dci_pdu_rel10_value(ptvcursor_t * ptvc, packet_info* pinfo)
{
	proto_item* item;
	guint32 test_value;
	gboolean test_boolean;

	// Cross carrier scheduling flag
	item = ptvcursor_add_ret_boolean(ptvc, hf_nfapi_cross_carrier_scheduling_flag, 1, ENC_BIG_ENDIAN, &test_boolean);
	if (test_boolean > 1)
	{
		expert_add_info_format(pinfo, item, &ei_invalid_range, "Invalid cross carrier scheduling flag value [0..1]");
	}

	// Carrier indicator
	item = ptvcursor_add_ret_uint(ptvc, hf_nfapi_carrier_indicator, 1, ENC_BIG_ENDIAN, &test_value);
	if (test_value > 7)
	{
		expert_add_info_format(pinfo, item, &ei_invalid_range, "Invalid carrier indicator value [0..7]");
	}

	// SRS flag
	item = ptvcursor_add_ret_boolean(ptvc, hf_nfapi_srs_flag, 1, ENC_BIG_ENDIAN, &test_boolean);
	if (test_boolean > 1)
	{
		expert_add_info_format(pinfo, item, &ei_invalid_range, "Invalid srs flag value [0..1]");
	}

	// SRS request
	item = ptvcursor_add_ret_boolean(ptvc, hf_nfapi_srs_request, 1, ENC_BIG_ENDIAN, &test_boolean);
	if (test_boolean > 1)
	{
		expert_add_info_format(pinfo, item, &ei_invalid_range, "Invalid srs request value [0..1]");
	}

	// Antenna ports, scrambling and layers
	item = ptvcursor_add_ret_uint(ptvc, hf_nfapi_antenna_ports_scrambling_and_layers, 1, ENC_BIG_ENDIAN, &test_value);
	if (test_value > 15)
	{
		expert_add_info_format(pinfo, item, &ei_invalid_range, "Invalid antenna ports scrambling and layers value [0..15]");
	}

	// Total DCI length including padding
	ptvcursor_add(ptvc, hf_nfapi_total_dci_length_including_padding, 1, ENC_BIG_ENDIAN);

	// N_DL_RB
	// TODO : This is missing from the encoder....
	//ptvcursor_add(ptvc, hf_nfapi_n_dl_rb, 1, ENC_BIG_ENDIAN);
}
static void dissect_dl_config_request_dl_dci_pdu_rel11_value(ptvcursor_t * ptvc, packet_info* pinfo)
{
	proto_item* item;
	guint32 test_value;

	// HARQ-ACK resource offset
	item = ptvcursor_add_ret_uint(ptvc, hf_nfapi_harq_ack_resource_offset, 1, ENC_BIG_ENDIAN, &test_value);
	if (test_value > 3)
	{
		expert_add_info_format(pinfo, item, &ei_invalid_range, "Invalid hack ack resource offset value [0..3]");
	}

	// PDSCH RE Mapping and Quasi-Co-Location Indicator
	item = ptvcursor_add_ret_uint(ptvc, hf_nfapi_pdsch_re_mapping_and_quasi_co_location_indicator, 1, ENC_BIG_ENDIAN, &test_value);
	if (test_value > 3)
	{
		expert_add_info_format(pinfo, item, &ei_invalid_range, "Invalid pdsch re mapping value [0..3]");
	}

}
static void dissect_ul_dl_configuration_index_value(ptvcursor_t * ptvc, packet_info* pinfo)
{
	guint32 test_value;

	// UL/DL configuration indication
	proto_item* item = ptvcursor_add_ret_uint(ptvc, hf_nfapi_ul_dl_configuration_index, 1, ENC_BIG_ENDIAN, &test_value);
	if (!(test_value >= 1 && test_value <= 5))
	{
		expert_add_info_format(pinfo, item, &ei_invalid_range, "Invalid ul/dl configuration indication value [1..5]");
	}
}
static void dissect_dl_config_request_dl_dci_pdu_rel12_value(ptvcursor_t * ptvc, packet_info* pinfo)
{
	proto_item* item;
	guint32 test_value, count;
	gboolean test_boolean;

	// Primary cell type
	item = ptvcursor_add_ret_uint(ptvc, hf_nfapi_primary_cell_type, 1, ENC_BIG_ENDIAN, &test_value);
	if (test_value > 2)
	{
		expert_add_info_format(pinfo, item, &ei_invalid_range, "Invalid primary cell type value [0..2]");
	}

	// UL/DL configuration flag
	item = ptvcursor_add_ret_boolean(ptvc, hf_nfapi_ul_dl_configuration_flag, 1, ENC_BIG_ENDIAN, &test_boolean);
	if (test_boolean > 1)
	{
		expert_add_info_format(pinfo, item, &ei_invalid_range, "Invalid ul/dl configuration flag value [0..1]");
	}

	// Number of UL / DL configurations
	ptvcursor_add_ret_uint(ptvc, hf_nfapi_number_of_ul_dl_configurations, 1, ENC_BIG_ENDIAN, &count);

	dissect_array_value(ptvc, pinfo, "UL/DL Configurations", ett_nfapi_pnf_phy, count, dissect_ul_dl_configuration_index_value);
}
static void dissect_dl_config_request_dl_dci_pdu_rel13_value(ptvcursor_t * ptvc, packet_info* pinfo _U_)
{
	ptvcursor_add(ptvc, hf_nfapi_laa_end_partial_sf_flag, 1, ENC_BIG_ENDIAN);
	ptvcursor_add(ptvc, hf_nfapi_laa_end_partial_sf_configuration, 1, ENC_BIG_ENDIAN);
	ptvcursor_add(ptvc, hf_nfapi_initial_lbt_sf, 1, ENC_BIG_ENDIAN);
	ptvcursor_add(ptvc, hf_nfapi_codebooksize_determination_r13, 1, ENC_BIG_ENDIAN);
	ptvcursor_add(ptvc, hf_nfapi_rel13_drms_table_flag, 1, ENC_BIG_ENDIAN);
}
static void dissect_dl_config_request_mch_pdu_rel8_value(ptvcursor_t * ptvc, packet_info* pinfo _U_)
{
	ptvcursor_add(ptvc, hf_nfapi_length, 2, ENC_BIG_ENDIAN);
	ptvcursor_add(ptvc, hf_nfapi_pdu_index, 2, ENC_BIG_ENDIAN);
	ptvcursor_add(ptvc, hf_nfapi_rnti, 2, ENC_BIG_ENDIAN);
	ptvcursor_add(ptvc, hf_nfapi_resource_allocation_type, 1, ENC_BIG_ENDIAN);
	ptvcursor_add(ptvc, hf_nfapi_resource_block_coding, 4, ENC_BIG_ENDIAN);
	ptvcursor_add(ptvc, hf_nfapi_modulation, 1, ENC_BIG_ENDIAN);
	ptvcursor_add(ptvc, hf_nfapi_transmission_power, 2, ENC_BIG_ENDIAN);
	ptvcursor_add(ptvc, hf_nfapi_mbsfn_area_id, 2, ENC_BIG_ENDIAN);
}
static void dissect_codebook_index_value(ptvcursor_t * ptvc, packet_info* pinfo)
{
	guint32 test_value;

	proto_item* item = ptvcursor_add_ret_uint(ptvc, hf_nfapi_codebook_index, 1, ENC_BIG_ENDIAN, &test_value);
	if (test_value > 15)
	{
		expert_add_info_format(pinfo, item, &ei_invalid_range, "Invalid codebook Index value [0..15]");
	}
}
static void dissect_bf_vector_value(ptvcursor_t * ptvc, packet_info* pinfo _U_)
{
	ptvcursor_add(ptvc, hf_nfapi_bf_vector_bf_value, 2, ENC_BIG_ENDIAN);
}
static void dissect_bf_vector_type_value(ptvcursor_t * ptvc, packet_info* pinfo)
{
	guint32 count;

	ptvcursor_add(ptvc, hf_nfapi_bf_vector_subband_index, 1, ENC_BIG_ENDIAN);
	ptvcursor_add_ret_uint(ptvc, hf_nfapi_bf_vector_num_antennas, 1, ENC_BIG_ENDIAN, &count);
	dissect_array_value(ptvc, pinfo, "Antennas", ett_nfapi_bf_vector_antennas, count, dissect_bf_vector_value);
}
static void dissect_dl_config_request_dlsch_pdu_rel8_value(ptvcursor_t * ptvc, packet_info* pinfo)
{
	proto_item* item;
	guint32 test_value, num_subbands, num_vectors;

	// Length
	ptvcursor_add(ptvc, hf_nfapi_length, 2, ENC_BIG_ENDIAN);

	// PDU index
	ptvcursor_add(ptvc, hf_nfapi_pdu_index, 2, ENC_BIG_ENDIAN);

	// RNTI
	item = ptvcursor_add_ret_uint(ptvc, hf_nfapi_rnti, 2, ENC_BIG_ENDIAN, &test_value);
	if (!(test_value >= 1 /* && rnti_value <= 65535)*/))
	{
		expert_add_info_format(pinfo, item, &ei_invalid_range, "Invalid codebook Index value [1..65535]");
	}

	// Resource allocation type
	item = ptvcursor_add_ret_uint(ptvc, hf_nfapi_resource_allocation_type, 1, ENC_BIG_ENDIAN, &test_value);
	if (test_value > 5)
	{
		expert_add_info_format(pinfo, item, &ei_invalid_range, "Invalid resource allocation type value [0..5]");
	}

	// Virtual resource block assignment flag
	item = ptvcursor_add_ret_uint(ptvc, hf_nfapi_virtual_resource_block_assignment_flag, 1, ENC_BIG_ENDIAN, &test_value);
	if (test_value > 1)
	{
		expert_add_info_format(pinfo, item, &ei_invalid_range, "Invalid virtual resource block allocation assignment value [0..1]");
	}

	// Resource block coding
	ptvcursor_add(ptvc, hf_nfapi_resource_block_coding, 4, ENC_BIG_ENDIAN);

	// Modulation
	item = ptvcursor_add_ret_uint(ptvc, hf_nfapi_modulation, 1, ENC_BIG_ENDIAN, &test_value);
	if (!(test_value == 2 || test_value == 4 || test_value == 6 || test_value == 8))
	{
		expert_add_info_format(pinfo, item, &ei_invalid_range, "Invalid modulation value [2, 4, 6, 8]");
	}

	// Redundancy version
	item = ptvcursor_add_ret_uint(ptvc, hf_nfapi_redundancy_version, 1, ENC_BIG_ENDIAN, &test_value);
	if (test_value > 3)
	{
		expert_add_info_format(pinfo, item, &ei_invalid_range, "Invalid redundancy value [0..3]");
	}

	// Transport blocks
	item = ptvcursor_add_ret_uint(ptvc, hf_nfapi_transport_blocks, 1, ENC_BIG_ENDIAN, &test_value);
	if (!(test_value >= 1 && test_value <= 2))
	{
		expert_add_info_format(pinfo, item, &ei_invalid_range, "Invalid transport blocks value [1..2]");
	}

	// Transport block to codeword swap flag
	item = ptvcursor_add_ret_uint(ptvc, hf_nfapi_transport_block_to_codeword_swap_flag, 1, ENC_BIG_ENDIAN, &test_value);
	if (test_value > 1)
	{
		expert_add_info_format(pinfo, item, &ei_invalid_range, "Invalid transport block to codeword swap flag value [0..1]");
	}

	// Transmission scheme
	item = ptvcursor_add_ret_uint(ptvc, hf_nfapi_transmission_scheme, 1, ENC_BIG_ENDIAN, &test_value);
	if (test_value > 13)
	{
		expert_add_info_format(pinfo, item, &ei_invalid_range, "Invalid transmission scheme value [0..13]");
	}

	// Number of layers
	item = ptvcursor_add_ret_uint(ptvc, hf_nfapi_number_of_layers, 1, ENC_BIG_ENDIAN, &test_value);
	if (!(test_value >= 1 && test_value <= 8))
	{
		expert_add_info_format(pinfo, item, &ei_invalid_range, "Invalid number of layers value [1..8]");
	}

	// Number of subbands
	item = ptvcursor_add_ret_uint(ptvc, hf_nfapi_number_of_subbands, 1, ENC_BIG_ENDIAN, &num_subbands);
	if (num_subbands > 13)
	{
		expert_add_info_format(pinfo, item, &ei_invalid_range, "Invalid number of subbands value [0..13]");
	}

	dissect_array_value(ptvc, pinfo, "Subbands", ett_nfapi_subbands, num_subbands, dissect_codebook_index_value);

	// UE category capacity
	item = ptvcursor_add_ret_uint(ptvc, hf_nfapi_ue_category_capacity, 1, ENC_BIG_ENDIAN, &test_value);
	if (test_value > 14)
	{
		expert_add_info_format(pinfo, item, &ei_invalid_range, "Invalid ue category capacity value [0..14]");
	}

	// P-A
	item = ptvcursor_add_ret_uint(ptvc, hf_nfapi_pa, 1, ENC_BIG_ENDIAN, &test_value);
	if (test_value > 7)
	{
		expert_add_info_format(pinfo, item, &ei_invalid_range, "Invalid p-a value [0..7]");
	}

	// Delta power offset index
	item = ptvcursor_add_ret_uint(ptvc, hf_nfapi_delta_power_offset_index, 1, ENC_BIG_ENDIAN, &test_value);
	if (test_value > 1)
	{
		expert_add_info_format(pinfo, item, &ei_invalid_range, "Invalid delta power offset value [0..1]");
	}

	// NGAP
	item = ptvcursor_add_ret_uint(ptvc, hf_nfapi_ngap, 1, ENC_BIG_ENDIAN, &test_value);
	if (test_value > 1)
	{
		expert_add_info_format(pinfo, item, &ei_invalid_range, "Invalid ngap value [0..1]");
	}

	// NPRB
	item = ptvcursor_add_ret_uint(ptvc, hf_nfapi_nprb, 1, ENC_BIG_ENDIAN, &test_value);
	if (test_value > 1)
	{
		expert_add_info_format(pinfo, item, &ei_invalid_range, "Invalid nprb value [0..1]");
	}

	// Transmission mode
	item = ptvcursor_add_ret_uint(ptvc, hf_nfapi_transmission_mode, 1, ENC_BIG_ENDIAN, &test_value);
	if (!(test_value >= 1 && test_value <= 10))
	{
		expert_add_info_format(pinfo, item, &ei_invalid_range, "Invalid transmission mode value [1..10]");
	}

	// numBfPRBperSubband
	ptvcursor_add(ptvc, hf_nfapi_num_bf_prb_per_subband, 1, ENC_BIG_ENDIAN);

	// numBfVector
	ptvcursor_add_ret_uint(ptvc, hf_nfapi_num_bf_vector, 1, ENC_BIG_ENDIAN, &num_vectors);

	dissect_array_value(ptvc, pinfo, "Beamforming Vectors", ett_nfapi_bf_vectors, num_vectors, dissect_bf_vector_type_value);
}
static void dissect_csi_rs_resource_config_value(ptvcursor_t * ptvc, packet_info* pinfo)
{
	guint32 test_value;

	proto_item* item = ptvcursor_add_ret_uint(ptvc, hf_nfapi_csi_rs_resource_config, 1, ENC_BIG_ENDIAN, &test_value);
	if (test_value > 31)
	{
		expert_add_info_format(pinfo, item, &ei_invalid_range, "Invalid csi-rs resource config value [0..31]");
	}
}
static void dissect_dl_config_request_dlsch_pdu_rel9_value(ptvcursor_t * ptvc, packet_info* pinfo)
{
	guint32 test_value;

	proto_item* item = ptvcursor_add_ret_uint(ptvc, hf_nfapi_nscid, 1, ENC_BIG_ENDIAN, &test_value);
	if (test_value > 1)
	{
		expert_add_info_format(pinfo, item, &ei_invalid_range, "Invalid nscid value [0..1]");
	}
}
static void dissect_dl_config_request_dlsch_pdu_rel10_value(ptvcursor_t * ptvc, packet_info* pinfo)
{
	proto_item* item;
	guint32 test_value, count;
	gboolean test_boolean;

	// CSI-RS flag
	item = ptvcursor_add_ret_boolean(ptvc, hf_nfapi_csi_rs_flag, 1, ENC_BIG_ENDIAN, &test_boolean);
	if (test_boolean > 1)
	{
		expert_add_info_format(pinfo, item, &ei_invalid_range, "Invalid csi-rs flag value [0..1]");
	}

	// CSI-RS resource config R10
	ptvcursor_add(ptvc, hf_nfapi_csi_rs_resource_config_r10, 1, ENC_BIG_ENDIAN);

	// CSI-RS zero Tx power resource config bitmap R10
	ptvcursor_add(ptvc, hf_nfapi_csi_rs_zero_tx_power_resource_config_bitmap_r10, 2, ENC_BIG_ENDIAN);

	// CSI-RS Number of NZP configuration
	item = ptvcursor_add_ret_uint(ptvc, hf_nfapi_csi_rs_number_of_nzp_configurations, 1, ENC_BIG_ENDIAN, &count);
	if (count > 3)
	{
		expert_add_info_format(pinfo, item, &ei_invalid_range, "Invalid csi-rs number of nzp configuration value [0..3]");
	}

	// CSI-RS configuration
	dissect_array_value(ptvc, pinfo, "CSI-RS Resource Configs", ett_nfapi_csi_rs_resource_configs, count, dissect_csi_rs_resource_config_value);

	// PDSCH start
	ptvcursor_add_ret_uint(ptvc, hf_nfapi_pdsch_start, 1, ENC_BIG_ENDIAN, &test_value);
	if (test_value > 4)
	{
		expert_add_info_format(pinfo, item, &ei_invalid_range, "Invalid pdsch start value [0..4]");
	}

}
static void dissect_dl_config_request_dlsch_pdu_rel11_value(ptvcursor_t * ptvc, packet_info* pinfo)
{
	proto_item* item;
	guint32 test_value;

	// DMRS Config flag
	item = ptvcursor_add_ret_uint(ptvc, hf_nfapi_drms_config_flag, 1, ENC_BIG_ENDIAN, &test_value);
	if (test_value > 1)
	{
		expert_add_info_format(pinfo, item, &ei_invalid_range, "Invalid drms config flag value [0..1]");
	}

	// DMRS-Scrambling
	item = ptvcursor_add_ret_uint(ptvc, hf_nfapi_drms_scrambling, 2, ENC_BIG_ENDIAN, &test_value);
	if (test_value > 503)
	{
		expert_add_info_format(pinfo, item, &ei_invalid_range, "Invalid drms scrambling value [0..503]");
	}

	// CSI Config flag
	item = ptvcursor_add_ret_uint(ptvc, hf_nfapi_csi_config_flag, 1, ENC_BIG_ENDIAN, &test_value);
	if (test_value > 1)
	{
		expert_add_info_format(pinfo, item, &ei_invalid_range, "Invalid csi config flag value [0..1]");
	}

	// CSI- Scrambling
	item = ptvcursor_add_ret_uint(ptvc, hf_nfapi_csi_scrambling, 2, ENC_BIG_ENDIAN, &test_value);
	if (test_value > 503)
	{
		expert_add_info_format(pinfo, item, &ei_invalid_range, "Invalid csi scrambling value [0..503]");
	}

	// PDSCH RE mapping flag
	item = ptvcursor_add_ret_uint(ptvc, hf_nfapi_pdsch_re_mapping_flag, 1, ENC_BIG_ENDIAN, &test_value);
	if (test_value > 1)
	{
		expert_add_info_format(pinfo, item, &ei_invalid_range, "Invalid pdsch re mapping flag value [0..1]");
	}

	// PDSCH RE mapping antenna ports
	item = ptvcursor_add_ret_uint(ptvc, hf_nfapi_pdsch_re_mapping_antenna_ports, 1, ENC_BIG_ENDIAN, &test_value);
	if (!(test_value == 1 || test_value == 2 || test_value == 4))
	{
		expert_add_info_format(pinfo, item, &ei_invalid_range, "Invalid pdsch re mapping antenna ports value [1, 2, 4]");
	}

	// PDSCH RE mapping freq shift
	item = ptvcursor_add_ret_uint(ptvc, hf_nfapi_pdsch_re_mapping_freq_shift, 1, ENC_BIG_ENDIAN, &test_value);
	if (test_value > 5)
	{
		expert_add_info_format(pinfo, item, &ei_invalid_range, "Invalid pdsch re mapping freq shift value [0..5]");
	}
}
static void dissect_dl_config_request_dlsch_pdu_rel12_value(ptvcursor_t * ptvc, packet_info* pinfo)
{
	proto_item* item;
	guint32 test_value;

	// altCQI-Table-r12
	item = ptvcursor_add_ret_uint(ptvc, hf_nfapi_alt_cqi_table_r12, 1, ENC_BIG_ENDIAN, &test_value);
	if (test_value > 1)
	{
		expert_add_info_format(pinfo, item, &ei_invalid_range, "Invalid alt cqi table r12 value [0..1]");
	}

	// MaxLayers
	item = ptvcursor_add_ret_uint(ptvc, hf_nfapi_max_layers, 1, ENC_BIG_ENDIAN, &test_value);
	if (!(test_value >= 1 && test_value <= 8))
	{
		expert_add_info_format(pinfo, item, &ei_invalid_range, "Invalid max layers value [1..8]");
	}

	ptvcursor_add(ptvc, hf_nfapi_n_dl_harq, 1, ENC_BIG_ENDIAN);
}
static void dissect_dl_config_request_dlsch_pdu_rel13_value(ptvcursor_t * ptvc, packet_info* pinfo)
{
	proto_item* item;
	guint32 test_value;

	// DwPTS Symbols
	item = ptvcursor_add_ret_uint(ptvc, hf_nfapi_dwpts_symbols, 1, ENC_BIG_ENDIAN, &test_value);
	if (!(test_value == 3 || test_value == 6 || test_value == 9 ||
		test_value == 10 || test_value == 11 || test_value == 12 ||
		test_value == 14))
	{
		expert_add_info_format(pinfo, item, &ei_invalid_range, "Invalid dwpts symbols value [3, 6, 9, 10, 11, 12, 14]");
	}

	// Initial LBT SF
	item = ptvcursor_add_ret_uint(ptvc, hf_nfapi_initial_lbt_sf, 1, ENC_BIG_ENDIAN, &test_value);
	if (test_value > 1)
	{
		expert_add_info_format(pinfo, item, &ei_invalid_range, "Invalid initial lbt sf value [0..1]");
	}

	// UE Type
	item = ptvcursor_add_ret_uint(ptvc, hf_nfapi_ue_type, 1, ENC_BIG_ENDIAN, &test_value);
	if (test_value > 2)
	{
		expert_add_info_format(pinfo, item, &ei_invalid_range, "Invalid ue type value [0..2]");
	}

	// PDSCH Payload Type
	item = ptvcursor_add_ret_uint(ptvc, hf_nfapi_pdsch_payload_type, 1, ENC_BIG_ENDIAN, &test_value);
	if (test_value > 2)
	{
		expert_add_info_format(pinfo, item, &ei_invalid_range, "Invalid pdsch payload type value [0..2]");
	}

	// Initial transmission SF (io)
	item = ptvcursor_add_ret_uint(ptvc, hf_nfapi_initial_transmission_sf, 2, ENC_BIG_ENDIAN, &test_value);
	if (!(test_value <= 10239 || test_value == 0xFFFF))
	{
		expert_add_info_format(pinfo, item, &ei_invalid_range, "Invalid initial transmission sf io value [0..10239, 0xFFFF]");
	}

	// Rel-13-DMRS-tabe flag
	item = ptvcursor_add_ret_uint(ptvc, hf_nfapi_req13_drms_table_flag, 1, ENC_BIG_ENDIAN, &test_value);
	if (test_value > 1)
	{
		expert_add_info_format(pinfo, item, &ei_invalid_range, "Invalid rel13 drms table flag value [0..1]");
	}
}
static void dissect_dl_config_request_pch_pdu_rel8_value(ptvcursor_t * ptvc, packet_info* pinfo)
{
	proto_item* item;
	guint32 test_value;

	// Length
	ptvcursor_add(ptvc, hf_nfapi_length, 2, ENC_BIG_ENDIAN);

	// PDU index
	ptvcursor_add(ptvc, hf_nfapi_pdu_index, 2, ENC_BIG_ENDIAN);

	// P-RNTI
	item = ptvcursor_add_ret_uint(ptvc, hf_nfapi_prnti, 2, ENC_BIG_ENDIAN, &test_value);
	if (test_value != 0xFFFE)
	{
		expert_add_info_format(pinfo, item, &ei_invalid_range, "Invalid prnti value [0xFFFE]");
	}

	// Resource allocation type
	item = ptvcursor_add_ret_uint(ptvc, hf_nfapi_resource_allocation_type, 1, ENC_BIG_ENDIAN, &test_value);
	if (!(test_value == 2 || test_value == 3 || test_value == 6))
	{
		expert_add_info_format(pinfo, item, &ei_invalid_range, "Invalid resource allocate type value [2, 3, 6]");
	}

	// Virtual resource block assignment flag
	item = ptvcursor_add_ret_uint(ptvc, hf_nfapi_virtual_resource_block_assignment_flag, 1, ENC_BIG_ENDIAN, &test_value);
	if (test_value > 1)
	{
		expert_add_info_format(pinfo, item, &ei_invalid_range, "Invalid virtual resource block assignment flag value [0..1]");
	}

	// Resource block coding
	ptvcursor_add(ptvc, hf_nfapi_resource_block_coding, 4, ENC_BIG_ENDIAN);

	// MCS
	item = ptvcursor_add_ret_uint(ptvc, hf_nfapi_mcs, 1, ENC_BIG_ENDIAN, &test_value);
	if (test_value != 0)
	{
		expert_add_info_format(pinfo, item, &ei_invalid_range, "Invalid mcs value [0]");
	}

	// Redundancy version
	item = ptvcursor_add_ret_uint(ptvc, hf_nfapi_redundancy_version, 1, ENC_BIG_ENDIAN, &test_value);
	if (test_value != 0)
	{
		expert_add_info_format(pinfo, item, &ei_invalid_range, "Invalid redundancy value [0]");
	}

	// Number of transport blocks
	item = ptvcursor_add_ret_uint(ptvc, hf_nfapi_number_of_transport_blocks, 1, ENC_BIG_ENDIAN, &test_value);
	if (test_value != 1)
	{
		expert_add_info_format(pinfo, item, &ei_invalid_range, "Invalid transport blocks value [1]");
	}

	// Transport block to codeword swap flag
	ptvcursor_add(ptvc, hf_nfapi_transport_block_to_codeword_swap_flag, 1, ENC_BIG_ENDIAN);

	// Transmission scheme
	item = ptvcursor_add_ret_uint(ptvc, hf_nfapi_transmission_scheme, 1, ENC_BIG_ENDIAN, &test_value);
	if (!(test_value == 0 || test_value == 1 || test_value == 6))
	{
		expert_add_info_format(pinfo, item, &ei_invalid_range, "Invalid transmission schemes value [0, 1, 6]");
	}

	// Number of layers
	item = ptvcursor_add_ret_uint(ptvc, hf_nfapi_number_of_layers, 1, ENC_BIG_ENDIAN, &test_value);
	if (!(test_value >= 1 && test_value <= 4))
	{
		expert_add_info_format(pinfo, item, &ei_invalid_range, "Invalid number of layers value [1..4]");
	}

	// Codebook index
	ptvcursor_add(ptvc, hf_nfapi_codebook_index, 1, ENC_BIG_ENDIAN);

	// UE category capacity
	item = ptvcursor_add_ret_uint(ptvc, hf_nfapi_ue_category_capacity, 1, ENC_BIG_ENDIAN, &test_value);
	if (test_value > 14)
	{
		expert_add_info_format(pinfo, item, &ei_invalid_range, "Invalid ue category capacity value [0..14]");
	}

	// P-A
	item = ptvcursor_add_ret_uint(ptvc, hf_nfapi_pa, 1, ENC_BIG_ENDIAN, &test_value);
	if (test_value > 7)
	{
		expert_add_info_format(pinfo, item, &ei_invalid_range, "Invalid p-a value value [0..7]");
	}

	// Transmission power
	item = ptvcursor_add_ret_uint(ptvc, hf_nfapi_transmission_power, 2, ENC_BIG_ENDIAN, &test_value);
	if (test_value > 10000)
	{
		expert_add_info_format(pinfo, item, &ei_invalid_range, "Invalid transmission power value [0..10000]");
	}

	// NPRB
	item = ptvcursor_add_ret_uint(ptvc, hf_nfapi_nprb, 1, ENC_BIG_ENDIAN, &test_value);
	if (test_value > 1)
	{
		expert_add_info_format(pinfo, item, &ei_invalid_range, "Invalid nprb value [0..1]");
	}

	// NGAP
	item = ptvcursor_add_ret_uint(ptvc, hf_nfapi_ngap, 1, ENC_BIG_ENDIAN, &test_value);
	if (test_value > 1)
	{
		expert_add_info_format(pinfo, item, &ei_invalid_range, "Invalid ngap value [0..1]");
	}

}
static void dissect_dl_config_request_pch_pdu_rel13_value(ptvcursor_t * ptvc, packet_info* pinfo)
{
	proto_item* item;
	guint32 test_value;

	// UE mode
	item = ptvcursor_add_ret_uint(ptvc, hf_nfapi_ue_mode, 1, ENC_BIG_ENDIAN, &test_value);
	if (test_value > 1)
	{
		expert_add_info_format(pinfo, item, &ei_invalid_range, "Invalid ue mode value [0..1]");
	}

	// Initial transmission SF (io)
	item = ptvcursor_add_ret_uint(ptvc, hf_nfapi_initial_transmission_sf, 2, ENC_BIG_ENDIAN, &test_value);
	if (!(test_value <= 10239 || test_value == 0xFFFF))
	{
		expert_add_info_format(pinfo, item, &ei_invalid_range, "Invalid initial transmission sf io value [0..10239, 0xFFFF]");
	}
}
static void dissect_dl_config_request_prs_pdu_rel9_value(ptvcursor_t * ptvc, packet_info* pinfo)
{
	proto_item* item;
	guint32 test_value;
	gboolean test_boolean;

	// Transmission power
	item = ptvcursor_add_ret_uint(ptvc, hf_nfapi_transmission_power, 2, ENC_BIG_ENDIAN, &test_value);
	if (test_value > 10000)
	{
		expert_add_info_format(pinfo, item, &ei_invalid_range, "Invalid transmission power value [0..10000]");
	}

	// PRS bandwidth
	item = ptvcursor_add_ret_uint(ptvc, hf_prs_bandwidth, 1, ENC_BIG_ENDIAN, &test_value);
	if (!(test_value == 6 || test_value == 15 || test_value == 25 ||
		  test_value == 50 || test_value == 75 || test_value == 100))
	{
		expert_add_info_format(pinfo, item, &ei_invalid_range, "Invalid prs bandwidth value [6, 15, 25, 50, 75, 100]");
	}

	// PRS cyclic prefix type
	item = ptvcursor_add_ret_boolean(ptvc, hf_prs_cyclic_prefix_type, 1, ENC_BIG_ENDIAN, &test_boolean);
	if (test_boolean > 1)
	{
		expert_add_info_format(pinfo, item, &ei_invalid_range, "Invalid prs cyclic prefix value [0..1]");
	}

	// PRS muting
	item = ptvcursor_add_ret_boolean(ptvc, hf_prs_muting, 1, ENC_BIG_ENDIAN, &test_boolean);
	if (test_boolean > 1)
	{
		expert_add_info_format(pinfo, item, &ei_invalid_range, "Invalid prs muting value [0..1]");
	}
}
static void dissect_dl_config_request_csi_rs_pdu_rel10_value(ptvcursor_t * ptvc, packet_info* pinfo)
{
	proto_item* item;
	guint32 test_value, count;

	// CSI-RS antenna port count R10
	item = ptvcursor_add_ret_uint(ptvc, hf_nfapi_csi_rs_antenna_port_count_r10, 1, ENC_BIG_ENDIAN, &test_value);
	if (!(test_value == 1 || test_value == 2 ||
		  test_value == 4 || test_value == 8 ||
		  test_value == 12 || test_value == 16))
	{
		expert_add_info_format(pinfo, item, &ei_invalid_range, "Invalid csi rs antenna port count r10 value [1, 2, 4, 6, 8, 10]");
	}

	// CSI-RS resource config R10
	ptvcursor_add(ptvc, hf_nfapi_csi_rs_resource_config_r10, 1, ENC_BIG_ENDIAN);

	// Transmission power
	item = ptvcursor_add_ret_uint(ptvc, hf_nfapi_transmission_power, 2, ENC_BIG_ENDIAN, &test_value);
	if (test_value > 10000)
	{
		expert_add_info_format(pinfo, item, &ei_invalid_range, "Invalid transmission power value [0..10000]");
	}

	// CSI-RS zero Tx power resource config bitmap R10
	ptvcursor_add(ptvc, hf_nfapi_csi_rs_zero_tx_power_resource_config_bitmap_r10, 2, ENC_BIG_ENDIAN);

	// CSI-RS Number of NZP configuration
	item = ptvcursor_add_ret_uint(ptvc, hf_nfapi_csi_rs_number_of_nzp_configurations, 1, ENC_BIG_ENDIAN, &count);
	if (count > 8)
	{
		expert_add_info_format(pinfo, item, &ei_invalid_range, "Invalid csi-rs number of nzp configuration value [0..8]");
	}

	// CSI-RS configuration
	dissect_array_value(ptvc, pinfo, "CSI-RS Resource Configs", ett_nfapi_csi_rs_resource_configs, count, dissect_csi_rs_resource_config_value);
}
static void dissect_csi_rs_bf_vector_value(ptvcursor_t * ptvc, packet_info* pinfo)
{
	guint32 count;
	proto_item* item = ptvcursor_add_ret_uint(ptvc, hf_nfapi_csi_rs_resource_index, 1, ENC_BIG_ENDIAN, &count);
	if (count > 7)
	{
		expert_add_info_format(pinfo, item, &ei_invalid_range, "Invalid csi-rs resource Index value [0..7]");
	}

	// todo : how to work out the antenna port count for the bfValue
}
static void dissect_dl_config_request_csi_rs_pdu_rel13_value(ptvcursor_t * ptvc, packet_info* pinfo)
{
	proto_item* item;
	guint32 test_value, class_value, count;

	// Class
	item = ptvcursor_add_ret_uint(ptvc, hf_nfapi_csi_rs_class, 1, ENC_BIG_ENDIAN, &class_value);
	if (class_value > 2)
	{
		expert_add_info_format(pinfo, item, &ei_invalid_range, "Invalid class value [0..2]");
	}

	// cdmType
	item = ptvcursor_add_ret_uint(ptvc, hf_nfapi_cdm_type, 1, ENC_BIG_ENDIAN, &test_value);
	if (test_value > 1)
	{
		expert_add_info_format(pinfo, item, &ei_invalid_range, "Invalid cdm type value [0..1]");
	}

	// numBfVector
	item = ptvcursor_add_ret_uint(ptvc, hf_nfapi_num_bf_vector, 1, ENC_BIG_ENDIAN, &count);
	if (!((class_value == 1 && count == 0) || (class_value == 2 && count <= 8)))
	{
		expert_add_info_format(pinfo, item, &ei_invalid_range, "Invalid num bf vector value [0] or [0..8]");
	}

	dissect_array_value(ptvc, pinfo, "Beamforming Vector", ett_nfapi_csi_rs_bf_vector, count, dissect_csi_rs_bf_vector_value);
}
static void dissect_epdcch_prb_index_value(ptvcursor_t * ptvc, packet_info* pinfo)
{
	guint32 test_value;

	// EPDCCH PRB index
	proto_item* item = ptvcursor_add_ret_uint(ptvc, hf_nfapi_edpcch_prb_index, 1, ENC_BIG_ENDIAN, &test_value);
	if (test_value > 99)
	{
		expert_add_info_format(pinfo, item, &ei_invalid_range, "Invalid epdcch prb_index value [0..99]");
	}
}
static void dissect_dl_config_request_edpcch_params_rel11_value(ptvcursor_t * ptvc, packet_info* pinfo)
{
	proto_item* item;
	guint32 test_value, count;

	// EPDCCH Resource assignment flag
	item = ptvcursor_add_ret_uint(ptvc, hf_nfapi_epdcch_resource_assignment_flag, 1, ENC_BIG_ENDIAN, &test_value);
	if (test_value > 1)
	{
		expert_add_info_format(pinfo, item, &ei_invalid_range, "Invalid epdcch resource assignment flag value [0..1]");
	}

	// EPDCCH ID
	item = ptvcursor_add_ret_uint(ptvc, hf_nfapi_epdcch_id, 2, ENC_BIG_ENDIAN, &test_value);
	if (test_value > 503)
	{
		expert_add_info_format(pinfo, item, &ei_invalid_range, "Invalid epdcch id value [0..503]");
	}

	// EPDCCH Start Symbol
	item = ptvcursor_add_ret_uint(ptvc, hf_nfapi_epdcch_start_symbol, 1, ENC_BIG_ENDIAN, &test_value);
	if (!(test_value >= 1 && test_value <= 4))
	{
		expert_add_info_format(pinfo, item, &ei_invalid_range, "Invalid epdcch start symbol value [1..4]");
	}

	// EPDCCH NumPRB
	item = ptvcursor_add_ret_uint(ptvc, hf_nfapi_epdcch_num_prb, 1, ENC_BIG_ENDIAN, &count);
	if (!(count == 2 || count == 4 || count == 8))
	{
		expert_add_info_format(pinfo, item, &ei_invalid_range, "Invalid epdcch num prb value [2, 4, 8]");
	}

	dissect_array_value(ptvc, pinfo, "PRBs", ett_nfapi_epdcch_prbs, count, dissect_epdcch_prb_index_value);

	dissect_bf_vector_type_value(ptvc, pinfo);
}
static void dissect_dl_config_request_edpcch_params_rel13_value(ptvcursor_t * ptvc, packet_info* pinfo)
{
	proto_item* item;
	guint32 test_value;

	// DwPTS Symbols
	item = ptvcursor_add_ret_uint(ptvc, hf_nfapi_initial_lbt_sf, 1, ENC_BIG_ENDIAN, &test_value);
	if (!(test_value == 3 || test_value == 6 || test_value == 9 ||
		test_value == 10 || test_value == 11 || test_value == 12 ||
		test_value == 14))
	{
		expert_add_info_format(pinfo, item, &ei_invalid_range, "Invalid dwpts symbols value [3, 6, 9, 10, 11, 12, 14]");
	}

	// Initial LBT SF
	item = ptvcursor_add_ret_uint(ptvc, hf_nfapi_dwpts_symbols, 1, ENC_BIG_ENDIAN, &test_value);
	if (test_value > 1)
	{
		expert_add_info_format(pinfo, item, &ei_invalid_range, "Invalid initial lbt sf value [0..1]");
	}

}
static void dissect_precoding_value(ptvcursor_t * ptvc, packet_info* pinfo _U_)
{
	ptvcursor_add(ptvc, hf_nfapi_precoding_value, 2, ENC_BIG_ENDIAN);
}
static void dissect_dl_config_request_mpdpcch_pdu_rel13_value(ptvcursor_t * ptvc, packet_info* pinfo)
{
	proto_item* item;
	guint32 test_value, count;
	gboolean test_boolean;

	// MPDCCH Narrowband
	item = ptvcursor_add_ret_uint(ptvc, hf_nfapi_mpdcch_narrowband, 1, ENC_BIG_ENDIAN, &test_value);
	if (test_value > 15)
	{
		expert_add_info_format(pinfo, item, &ei_invalid_range, "Invalid mpdcch narrowband value [0..15]");
	}

	// Number of PRB pairs
	item = ptvcursor_add_ret_uint(ptvc, hf_nfapi_number_of_prb_pairs, 1, ENC_BIG_ENDIAN, &test_value);
	if (!(test_value == 2 || test_value == 4 || test_value == 6))
	{
		expert_add_info_format(pinfo, item, &ei_invalid_range, "Invalid number of prb pair value [2, 4, 6]");
	}

	// Resource Block Assignment
	item = ptvcursor_add_ret_uint(ptvc, hf_nfapi_resource_block_assignment, 1, ENC_BIG_ENDIAN, &test_value);
	if (test_value > 14)
	{
		expert_add_info_format(pinfo, item, &ei_invalid_range, "Invalid resource block assignment value [0..14]");
	}

	// MPDCCH transmission type
	item = ptvcursor_add_ret_uint(ptvc, hf_nfapi_mpdcch_transmission_type, 1, ENC_BIG_ENDIAN, &test_value);
	if (test_value > 1)
	{
		expert_add_info_format(pinfo, item, &ei_invalid_range, "Invalid mpdcch transmission type value [0..1]");
	}

	// Start symbol
	item = ptvcursor_add_ret_uint(ptvc, hf_nfapi_start_symbol, 1, ENC_BIG_ENDIAN, &test_value);
	if (!(test_value >= 1 && test_value <=4))
	{
		expert_add_info_format(pinfo, item, &ei_invalid_range, "Invalid start symbol value [1..4]");
	}

	// ECCE index
	item = ptvcursor_add_ret_uint(ptvc, hf_nfapi_ecce_index, 1, ENC_BIG_ENDIAN, &test_value);
	if (test_value > 22)
	{
		expert_add_info_format(pinfo, item, &ei_invalid_range, "Invalid ecce Index value [0..22]");
	}

	// Aggregation level
	item = ptvcursor_add_ret_uint(ptvc, hf_nfapi_aggregation_level, 1, ENC_BIG_ENDIAN, &test_value);
	if (!(test_value == 2 || test_value == 4 || test_value == 8 ||
		test_value == 16 || test_value == 24))
	{
		expert_add_info_format(pinfo, item, &ei_invalid_range, "Invalid aggregation level value [2, 4, 8, 16, 24]");
	}

	// RNTI type
	item = ptvcursor_add_ret_uint(ptvc, hf_nfapi_mpdcch_rnti_type, 1, ENC_BIG_ENDIAN, &test_value);
	if (test_value > 4)
	{
		expert_add_info_format(pinfo, item, &ei_invalid_range, "Invalid rnti type value [0..4]");
	}

	// RNTI
	item = ptvcursor_add_ret_uint(ptvc, hf_nfapi_rnti, 2, ENC_BIG_ENDIAN, &test_value);
	if (!(test_value >= 1))
	{
		expert_add_info_format(pinfo, item, &ei_invalid_range, "Invalid rnti value [1..65535]");
	}

	// CEMode
	item = ptvcursor_add_ret_uint(ptvc, hf_nfapi_ce_mode, 1, ENC_BIG_ENDIAN, &test_value);
	if (!(test_value >= 1 && test_value <= 2))
	{
		expert_add_info_format(pinfo, item, &ei_invalid_range, "Invalid cemode value [1..2]");
	}

	// DMRS scrambling init
	item = ptvcursor_add_ret_uint(ptvc, hf_nfapi_drms_scrabmling_init, 2, ENC_BIG_ENDIAN, &test_value);
	if (test_value > 503)
	{
		expert_add_info_format(pinfo, item, &ei_invalid_range, "Invalid drms scrambling init value [0..503]");
	}

	// Initial transmission SF (io)
	item = ptvcursor_add_ret_uint(ptvc, hf_nfapi_initial_transmission_sf, 2, ENC_BIG_ENDIAN, &test_value);
	if (!(test_value <= 10239 || test_value == 0xFFFF))
	{
		expert_add_info_format(pinfo, item, &ei_invalid_range, "Invalid initial transmission sf io value [0..10239, 0xFFFF]");
	}

	// Transmission power
	item = ptvcursor_add_ret_uint(ptvc, hf_nfapi_transmission_power, 2, ENC_BIG_ENDIAN, &test_value);
	if (test_value > 10000)
	{
		expert_add_info_format(pinfo, item, &ei_invalid_range, "Invalid transmission power value [0..10000]");
	}

	// DCI format
	item = ptvcursor_add_ret_uint(ptvc, hf_nfapi_dl_dci_format, 1, ENC_BIG_ENDIAN, &test_value);
	if (!(test_value == 10 || test_value == 11 || test_value == 12))
	{
		expert_add_info_format(pinfo, item, &ei_invalid_range, "Invalid dci format value [10, 11, 12]");
	}

	// Resource block coding
	ptvcursor_add(ptvc, hf_nfapi_resource_block_coding, 2, ENC_BIG_ENDIAN);

	// MCS
	item = ptvcursor_add_ret_uint(ptvc, hf_nfapi_mcs, 1, ENC_BIG_ENDIAN, &test_value);
	if (test_value > 15)
	{
		expert_add_info_format(pinfo, item, &ei_invalid_range, "Invalid transmission power value [0..15]");
	}

	// PDSCH repetition levels
	item = ptvcursor_add_ret_uint(ptvc, hf_nfapi_pdsch_reception_levels, 1, ENC_BIG_ENDIAN, &test_value);
	if (!(test_value >= 1 && test_value <= 8))
	{
		expert_add_info_format(pinfo, item, &ei_invalid_range, "Invalid pdsch repetition levels value [1..8]");
	}

	// Redundancy version
	item = ptvcursor_add_ret_uint(ptvc, hf_nfapi_redundancy_version, 1, ENC_BIG_ENDIAN, &test_value);
	if (test_value > 3)
	{
		expert_add_info_format(pinfo, item, &ei_invalid_range, "Invalid redundancy version value [0..3]");
	}

	// New data indicator
	item = ptvcursor_add_ret_uint(ptvc, hf_nfapi_new_data_indicator, 1, ENC_BIG_ENDIAN, &test_value);
	if (test_value > 1)
	{
		expert_add_info_format(pinfo, item, &ei_invalid_range, "Invalid new data indicator value [0..1]");
	}

	// HARQ process
	item = ptvcursor_add_ret_uint(ptvc, hf_nfapi_harq_process, 1, ENC_BIG_ENDIAN, &test_value);
	if (test_value > 15)
	{
		expert_add_info_format(pinfo, item, &ei_invalid_range, "Invalid harq process value [0..15]");
	}

	// TPMI length
	item = ptvcursor_add_ret_uint(ptvc, hf_nfapi_tpmi_length, 1, ENC_BIG_ENDIAN, &test_value);
	if (!(test_value == 0 || test_value == 2 || test_value == 4))
	{
		expert_add_info_format(pinfo, item, &ei_invalid_range, "Invalid tpmi length value [0, 2, 4]");
	}

	// TPMI
	item = ptvcursor_add_ret_uint(ptvc, hf_nfapi_tpmi, 1, ENC_BIG_ENDIAN, &test_value);
	if (test_value > 15)
	{
		expert_add_info_format(pinfo, item, &ei_invalid_range, "Invalid tpmi value [0..15]");
	}

	// PMI flag
	item = ptvcursor_add_ret_boolean(ptvc, hf_nfapi_pmi_flag, 1, ENC_BIG_ENDIAN, &test_boolean);
	if (test_boolean > 1)
	{
		expert_add_info_format(pinfo, item, &ei_invalid_range, "Invalid pmi flag value [0..1]");
	}

	// PMI
	item = ptvcursor_add_ret_uint(ptvc, hf_nfapi_pmi, 1, ENC_BIG_ENDIAN, &test_value);
	if (test_value > 1)
	{
		expert_add_info_format(pinfo, item, &ei_invalid_range, "Invalid pmi value [0..1]");
	}

	// HARQ resource offset
	item = ptvcursor_add_ret_uint(ptvc, hf_nfapi_harq_resource_offset, 1, ENC_BIG_ENDIAN, &test_value);
	if (test_value > 3)
	{
		expert_add_info_format(pinfo, item, &ei_invalid_range, "Invalid harq resource offset value [0..3]");
	}

	// DCI subframe repetition number
	item = ptvcursor_add_ret_uint(ptvc, hf_nfapi_dci_subframe_repetition_number, 1, ENC_BIG_ENDIAN, &test_value);
	if (!(test_value >= 1 && test_value <= 4))
	{
		expert_add_info_format(pinfo, item, &ei_invalid_range, "Invalid dci subframe repetition number value [1..4]");
	}

	// TPC
	item = ptvcursor_add_ret_uint(ptvc, hf_nfapi_tpc, 1, ENC_BIG_ENDIAN, &test_value);
	if (test_value > 3)
	{
		expert_add_info_format(pinfo, item, &ei_invalid_range, "Invalid tpc value [0..3]");
	}

	// Downlink assignment Index Length
	item = ptvcursor_add_ret_uint(ptvc, hf_nfapi_downlink_assignment_index_length, 1, ENC_BIG_ENDIAN, &test_value);
	if (!(test_value == 0 || test_value == 2 || test_value == 4))
	{
		expert_add_info_format(pinfo, item, &ei_invalid_range, "Invalid downlink assignment Index length value [0, 2, 4]");
	}

	// Downlink assignment index
	item = ptvcursor_add_ret_uint(ptvc, hf_nfapi_downlink_assignment_index, 1, ENC_BIG_ENDIAN, &test_value);
	if (test_value > 15)
	{
		expert_add_info_format(pinfo, item, &ei_invalid_range, "Invalid downlink assignment Index value [0..15]");
	}

	// Allocate PRACH flag
	item = ptvcursor_add_ret_uint(ptvc, hf_nfapi_allocate_prach_flag, 1, ENC_BIG_ENDIAN, &test_value);
	if (test_value > 1)
	{
		expert_add_info_format(pinfo, item, &ei_invalid_range, "Invalid allocate prach flag value [0..1]");
	}

	// Preamble index
	item = ptvcursor_add_ret_uint(ptvc, hf_nfapi_preamble_index, 1, ENC_BIG_ENDIAN, &test_value);
	if (test_value > 63)
	{
		expert_add_info_format(pinfo, item, &ei_invalid_range, "Invalid preamble Index value [0..63]");
	}

	// PRACH mask index
	item = ptvcursor_add_ret_uint(ptvc, hf_nfapi_prach_mask_index, 1, ENC_BIG_ENDIAN, &test_value);
	if (test_value > 15)
	{
		expert_add_info_format(pinfo, item, &ei_invalid_range, "Invalid prach mask Index value [0..15]");
	}

	// Starting CE Level
	item = ptvcursor_add_ret_uint(ptvc, hf_nfapi_starting_ce_level, 1, ENC_BIG_ENDIAN, &test_value);
	if (test_value > 3)
	{
		expert_add_info_format(pinfo, item, &ei_invalid_range, "Invalid starting ce level value [0..3]");
	}

	// SRS request
	item = ptvcursor_add_ret_boolean(ptvc, hf_nfapi_srs_request, 1, ENC_BIG_ENDIAN, &test_boolean);
	if (test_boolean > 1)
	{
		expert_add_info_format(pinfo, item, &ei_invalid_range, "Invalid srs request value [0..1]");
	}

	// Antenna ports and scrambling identity flag
	item = ptvcursor_add_ret_boolean(ptvc, hf_nfapi_antenna_ports_and_scrambling_identity_flag, 1, ENC_BIG_ENDIAN, &test_boolean);
	if (test_boolean > 1)
	{
		expert_add_info_format(pinfo, item, &ei_invalid_range, "Invalid antenna ports and scrambling identity flag value [0..1]");
	}

	// Antenna ports and scrambling identity
	item = ptvcursor_add_ret_uint(ptvc, hf_nfapi_antenna_ports_and_scrambling_identity, 1, ENC_BIG_ENDIAN, &test_value);
	if (test_value > 3)
	{
		expert_add_info_format(pinfo, item, &ei_invalid_range, "Invalid antenna ports and scrambling identity value [0..3]");
	}

	// Frequency hopping enabled flag
	item = ptvcursor_add_ret_uint(ptvc, hf_nfapi_frequency_hopping_enabled_flag, 1, ENC_BIG_ENDIAN, &test_value);
	if (test_value > 1)
	{
		expert_add_info_format(pinfo, item, &ei_invalid_range, "Invalid frequency hopping enabled flag value [0..1]");
	}

	// Paging/Direct indication differentiation flag
	item = ptvcursor_add_ret_uint(ptvc, hf_nfapi_paging_direct_indication_differentiation_flag, 1, ENC_BIG_ENDIAN, &test_value);
	if (test_value > 1)
	{
		expert_add_info_format(pinfo, item, &ei_invalid_range, "Invalid paging/direct indication differentiation flag value [0..1]");
	}

	// Direct indication
	ptvcursor_add(ptvc, hf_nfapi_direct_indication, 1, ENC_BIG_ENDIAN);

	// Total DCI length including padding
	ptvcursor_add(ptvc, hf_nfapi_total_dci_length_including_padding, 1, ENC_BIG_ENDIAN);

	// Number of TX Antenna ports
	ptvcursor_add_ret_uint(ptvc, hf_nfapi_number_of_tx_antenna_ports, 1, ENC_BIG_ENDIAN, &count);

	dissect_array_value(ptvc, pinfo, "Precoding", ett_nfapi_precoding, count, dissect_precoding_value);
}
static void dissect_ul_config_pdu(ptvcursor_t * ptvc, packet_info* pinfo)
{
	proto_item* item;
	guint32 test_value, size;

	// PDU Type
	item = ptvcursor_add_ret_uint(ptvc, hf_nfapi_ul_config_pdu_type, 1, ENC_BIG_ENDIAN, &test_value);
	if (test_value > 15)
	{
		expert_add_info_format(pinfo, item, &ei_invalid_range, "Invalid ul pdu type value [0..15]");
	}

	ptvcursor_add_ret_uint(ptvc, hf_nfapi_pdu_size, 1, ENC_BIG_ENDIAN, &size);

	guint pdu_end = (ptvcursor_current_offset(ptvc) + size - 2);
	dissect_tlv_list(ptvc, pinfo, pdu_end);
}
static void dissect_ul_config_request_body_value(ptvcursor_t * ptvc, packet_info* pinfo)
{
	proto_item* item;
	guint32 test_value, num_pdu;
	gboolean test_boolean;

	// Number of PDUs
	ptvcursor_add_ret_uint(ptvc, hf_nfapi_number_pdus, 1, ENC_BIG_ENDIAN, &num_pdu);

	// RACH/PRACH frequency resources
	item = ptvcursor_add_ret_uint(ptvc, hf_nfapi_rach_prach_frequency_resources, 1, ENC_BIG_ENDIAN, &test_value);
	if (test_value > 1)
	{
		expert_add_info_format(pinfo, item, &ei_invalid_range, "Invalid rach prach frequency resources value [0..1]");
	}

	// SRS present
	item = ptvcursor_add_ret_boolean(ptvc, hf_nfapi_srs_present, 1, ENC_BIG_ENDIAN, &test_boolean);
	if (test_boolean > 1)
	{
		expert_add_info_format(pinfo, item, &ei_invalid_range, "Invalid srs present value [0..1]");
	}

	dissect_array_value(ptvc, pinfo, "UL Config PDU List", ett_nfapi_ul_config_request_pdu_list, num_pdu, dissect_ul_config_pdu);
}
static void dissect_ul_config_ulsch_pdu_rel8_value(ptvcursor_t * ptvc, packet_info* pinfo)
{
	proto_item* item;
	guint32 test_value;

	// Handle
	ptvcursor_add(ptvc, hf_nfapi_handle, 4, ENC_BIG_ENDIAN);

	// Size
	ptvcursor_add(ptvc, hf_nfapi_size, 2, ENC_BIG_ENDIAN);

	// RNTI
	item = ptvcursor_add_ret_uint(ptvc, hf_nfapi_rnti, 2, ENC_BIG_ENDIAN, &test_value);
	if (!(test_value >= 1))
	{
		expert_add_info_format(pinfo, item, &ei_invalid_range, "Invalid rnti value [1..65535]");
	}

	// Resource block start
	item = ptvcursor_add_ret_uint(ptvc, hf_nfapi_resource_block_start, 1, ENC_BIG_ENDIAN, &test_value);
	if (test_value > 99)
	{
		expert_add_info_format(pinfo, item, &ei_invalid_range, "Invalid resource block start value [0..99]");
	}

	// Number of resource blocks
	item = ptvcursor_add_ret_uint(ptvc, hf_nfapi_number_of_resource_blocks, 1, ENC_BIG_ENDIAN, &test_value);
	if (!(test_value >= 1 && test_value <= 100))
	{
		expert_add_info_format(pinfo, item, &ei_invalid_range, "Invalid number of resource blocks value [1..100]");
	}

	// Modulation type
	item = ptvcursor_add_ret_uint(ptvc, hf_nfapi_modulation, 1, ENC_BIG_ENDIAN, &test_value);
	if (!(test_value == 2 || test_value == 4 || test_value == 6))
	{
		expert_add_info_format(pinfo, item, &ei_invalid_range, "Invalid modulation type value [2, 4, 6]");
	}

	// Cyclic Shift 2 for DMRS
	item = ptvcursor_add_ret_uint(ptvc, hf_nfapi_cyclic_shift_2_for_drms, 1, ENC_BIG_ENDIAN, &test_value);
	if (test_value > 99)
	{
		expert_add_info_format(pinfo, item, &ei_invalid_range, "Invalid cyclic shift 2 for drms value [0..7]");
	}

	// Frequency hopping enabled flag
	item = ptvcursor_add_ret_uint(ptvc, hf_nfapi_frequency_hopping_enabled_flag, 1, ENC_BIG_ENDIAN, &test_value);
	if (test_value > 1)
	{
		expert_add_info_format(pinfo, item, &ei_invalid_range, "Invalid frequency hopping enabled flag value [0..1]");
	}

	// Frequency hopping bits
	item = ptvcursor_add_ret_uint(ptvc, hf_nfapi_frequency_hopping_bits, 1, ENC_BIG_ENDIAN, &test_value);
	if (test_value > 3)
	{
		expert_add_info_format(pinfo, item, &ei_invalid_range, "Invalid frequency hopping bits value [0..3]");
	}

	// New data indication
	item = ptvcursor_add_ret_uint(ptvc, hf_nfapi_new_data_indication, 1, ENC_BIG_ENDIAN, &test_value);
	if (test_value > 1)
	{
		expert_add_info_format(pinfo, item, &ei_invalid_range, "Invalid new data indicator value [0..1]");
	}

	// Redundancy version
	item = ptvcursor_add_ret_uint(ptvc, hf_nfapi_redundancy_version, 1, ENC_BIG_ENDIAN, &test_value);
	if (test_value > 3)
	{
		expert_add_info_format(pinfo, item, &ei_invalid_range, "Invalid redundancy version value [0..3]");
	}

	// HARQ process number
	item = ptvcursor_add_ret_uint(ptvc, hf_nfapi_harq_process_number, 1, ENC_BIG_ENDIAN, &test_value);
	if (test_value > 15)
	{
		expert_add_info_format(pinfo, item, &ei_invalid_range, "Invalid harq process number value [0..15]");
	}

	// UL Tx mode
	item = ptvcursor_add_ret_uint(ptvc, hf_nfapi_ul_tx_mode, 1, ENC_BIG_ENDIAN, &test_value);
	if (test_value > 1)
	{
		expert_add_info_format(pinfo, item, &ei_invalid_range, "Invalid ul tx mode value [0..1]");
	}

	// Current TX NB
	ptvcursor_add(ptvc, hf_nfapi_current_tx_nb, 1, ENC_BIG_ENDIAN);

	// N srs
	item = ptvcursor_add_ret_uint(ptvc, hf_nfapi_n_srs, 1, ENC_BIG_ENDIAN, &test_value);
	if (test_value > 1)
	{
		expert_add_info_format(pinfo, item, &ei_invalid_range, "Invalid n_srs value [0..1]");
	}
}
static void dissect_ul_config_ulsch_pdu_rel10_value(ptvcursor_t * ptvc, packet_info* pinfo)
{
	proto_item* item;
	guint32 test_value;

	// Resource allocation type
	item = ptvcursor_add_ret_uint(ptvc, hf_nfapi_resource_allocation_type, 1, ENC_BIG_ENDIAN, &test_value);
	if (test_value > 1)
	{
		expert_add_info_format(pinfo, item, &ei_invalid_range, "Invalid resource allocation type value [0..1]");
	}

	// Resource block coding
	ptvcursor_add(ptvc, hf_nfapi_resource_block_coding, 4, ENC_BIG_ENDIAN);

	// Transport blocks
	item = ptvcursor_add_ret_uint(ptvc, hf_nfapi_transport_blocks, 1, ENC_BIG_ENDIAN, &test_value);
	if (!(test_value >= 1 && test_value <= 2))
	{
		expert_add_info_format(pinfo, item, &ei_invalid_range, "Invalid transport blocks value [1..2]");
	}

	// Transmission scheme
	item = ptvcursor_add_ret_uint(ptvc, hf_nfapi_ul_transmission_scheme, 1, ENC_BIG_ENDIAN, &test_value);
	if (test_value > 1)
	{
		expert_add_info_format(pinfo, item, &ei_invalid_range, "Invalid transmission scheme value [0..1]");
	}

	// Number Of layers
	item = ptvcursor_add_ret_uint(ptvc, hf_nfapi_number_of_layers, 1, ENC_BIG_ENDIAN, &test_value);
	if (!(test_value >= 1 && test_value <=4 ))
	{
		expert_add_info_format(pinfo, item, &ei_invalid_range, "Invalid number of layers value [1..4]");
	}

	// Codebook Index
	item = ptvcursor_add_ret_uint(ptvc, hf_nfapi_codebook_index, 1, ENC_BIG_ENDIAN, &test_value);
	if (test_value > 23)
	{
		expert_add_info_format(pinfo, item, &ei_invalid_range, "Invalid codebook Index value [0..23]");
	}

	// Disable sequence hopping flag
	item = ptvcursor_add_ret_uint(ptvc, hf_nfapi_disable_sequence_hopping_flag, 1, ENC_BIG_ENDIAN, &test_value);
	if (test_value > 1)
	{
		expert_add_info_format(pinfo, item, &ei_invalid_range, "Invalid disable sequence hopping flag value [0..1]");
	}
}
static void dissect_ul_config_ulsch_pdu_rel11_value(ptvcursor_t * ptvc, packet_info* pinfo)
{
	proto_item* item;
	guint32 test_value;

	// Virtual cell ID enabled flag
	item = ptvcursor_add_ret_uint(ptvc, hf_nfapi_virtual_cell_id_enabled_flag, 1, ENC_BIG_ENDIAN, &test_value);
	if (test_value > 1)
	{
		expert_add_info_format(pinfo, item, &ei_invalid_range, "Invalid virtual cell id enabled flag value [0..1]");
	}

	// nPUSCH Identity
	item = ptvcursor_add_ret_uint(ptvc, hf_nfapi_npusch_identity, 2, ENC_BIG_ENDIAN, &test_value);
	if (test_value > 509)
	{
		expert_add_info_format(pinfo, item, &ei_invalid_range, "Invalid npusch identity value [0..509]");
	}

	// DMRS Config flag
	item = ptvcursor_add_ret_uint(ptvc, hf_nfapi_drms_config_flag, 1, ENC_BIG_ENDIAN, &test_value);
	if (test_value > 1)
	{
		expert_add_info_format(pinfo, item, &ei_invalid_range, "Invalid drms config flag value [0..1]");
	}

	// nDMRS-CSH Identity
	item = ptvcursor_add_ret_uint(ptvc, hf_nfapi_ndrms_csh_identity, 2, ENC_BIG_ENDIAN, &test_value);
	if (test_value > 509)
	{
		expert_add_info_format(pinfo, item, &ei_invalid_range, "Invalid ndrms-csh identity value [0..509]");
	}

}
static void dissect_ul_config_ulsch_pdu_rel13_value(ptvcursor_t * ptvc, packet_info* pinfo)
{
	proto_item* item;
	guint32 test_value;

	// UE Type
	item = ptvcursor_add_ret_uint(ptvc, hf_nfapi_ue_type, 1, ENC_BIG_ENDIAN, &test_value);
	if (test_value > 2)
	{
		expert_add_info_format(pinfo, item, &ei_invalid_range, "Invalid ue type value [0..2]");
	}

	// Total Number of repetitions
	item = ptvcursor_add_ret_uint(ptvc, hf_nfapi_total_number_of_repetitions, 2, ENC_BIG_ENDIAN, &test_value);
	if (!(test_value >= 1 && test_value <= 2048))
	{
		expert_add_info_format(pinfo, item, &ei_invalid_range, "Invalid total number of repetitions value [1..2048]");
	}

	// Repetition Number
	item = ptvcursor_add_ret_uint(ptvc, hf_nfapi_repetition_number, 2, ENC_BIG_ENDIAN, &test_value);
	if (!(test_value >= 1 && test_value <= 2048))
	{
		expert_add_info_format(pinfo, item, &ei_invalid_range, "Invalid repetition number value [1..2048]");
	}

	// Initial transmission SF (io)
	item = ptvcursor_add_ret_uint(ptvc, hf_nfapi_initial_sf_io, 2, ENC_BIG_ENDIAN, &test_value);
	if (!(test_value <= 10239 || test_value == 0xFFFF))
	{
		expert_add_info_format(pinfo, item, &ei_invalid_range, "Invalid repetition number value [0..10239, 0xFFFF]");
	}

	// Empy symbols due to re-tunning
	// todo : decode as a bitmap
	ptvcursor_add(ptvc, hf_nfapi_empty_symbols_due_to_retunning, 1, ENC_BIG_ENDIAN);
}
static void dissect_ul_config_init_tx_params_rel8_value(ptvcursor_t * ptvc, packet_info* pinfo)
{
	proto_item* item;
	guint32 test_value;

	// N srs initial
	item = ptvcursor_add_ret_uint(ptvc, hf_nfapi_n_srs_initial, 1, ENC_BIG_ENDIAN, &test_value);
	if (test_value > 1)
	{
		expert_add_info_format(pinfo, item, &ei_invalid_range, "Invalid n srs initial value [0..1]");
	}

	// Initial number of resource blocks
	item = ptvcursor_add_ret_uint(ptvc, hf_nfapi_initial_number_of_resource_blocks, 1, ENC_BIG_ENDIAN, &test_value);
	if (!(test_value >= 1 && test_value <= 100))
	{
		expert_add_info_format(pinfo, item, &ei_invalid_range, "Invalid initial number of resource blocks value [1..100]");
	}

}
static void dissect_ul_config_cqi_ri_info_rel8_value(ptvcursor_t * ptvc, packet_info* pinfo)
{
	proto_item* item;
	guint32 test_value;

	// DL CQI/PMI Size Rank = 1
	ptvcursor_add(ptvc, hf_nfapi_dl_cqi_pmi_size_rank_1, 1, ENC_BIG_ENDIAN);

	// DL CQI/PMI Size Rank>1
	ptvcursor_add(ptvc, hf_nfapi_dl_cqi_pmi_size_rank_greater_1, 1, ENC_BIG_ENDIAN);

	// RI Size
	item = ptvcursor_add_ret_uint(ptvc, hf_nfapi_ri_size, 1, ENC_BIG_ENDIAN, &test_value);
	if (test_value > 3)
	{
		expert_add_info_format(pinfo, item, &ei_invalid_range, "Invalid ri size value [0..3]");
	}

	// Delta Offset CQI
	item = ptvcursor_add_ret_uint(ptvc, hf_nfapi_delta_offset_cqi, 1, ENC_BIG_ENDIAN, &test_value);
	if (test_value > 15)
	{
		expert_add_info_format(pinfo, item, &ei_invalid_range, "Invalid delta offset cqi value [0..15]");
	}

	// Delta Offset RI
	item = ptvcursor_add_ret_uint(ptvc, hf_nfapi_delta_offset_ri, 1, ENC_BIG_ENDIAN, &test_value);
	if (test_value > 15)
	{
		expert_add_info_format(pinfo, item, &ei_invalid_range, "Invalid delta offset ri value [0..15]");
	}

}
static void dissect_ul_config_cqi_ri_info_rel9_later_value(ptvcursor_t * ptvc, packet_info* pinfo)
{
	proto_item* item;
	guint32 test_value;
	gboolean type, test_boolean;

	// Report type
	item = ptvcursor_add_ret_boolean(ptvc, hf_nfapi_report_type, 1, ENC_BIG_ENDIAN, &type);
	if (type > 1)
	{
		expert_add_info_format(pinfo, item, &ei_invalid_range, "Invalid report type value [0..1]");
	}

	// Delta offset CQI
	item = ptvcursor_add_ret_uint(ptvc, hf_nfapi_delta_offset_cqi, 1, ENC_BIG_ENDIAN, &test_value);
	if (test_value > 15)
	{
		expert_add_info_format(pinfo, item, &ei_invalid_range, "Invalid delta offset cqi value [0..15]");
	}

	// Delta offset RI
	item = ptvcursor_add_ret_uint(ptvc, hf_nfapi_delta_offset_ri, 1, ENC_BIG_ENDIAN, &test_value);
	if (test_value > 15)
	{
		expert_add_info_format(pinfo, item, &ei_invalid_range, "Invalid delta offset ri value [0..15]");
	}

	switch (type)
	{
		case 0:
		{
			// DL CQI/PMI/RI size
			ptvcursor_add(ptvc, hf_nfapi_dl_cqi_ri_pmi_size, 1, ENC_BIG_ENDIAN);

			// Control Type
			ptvcursor_add_ret_boolean(ptvc, hf_nfapi_control_type, 1, ENC_BIG_ENDIAN, &test_boolean);
			if (test_boolean > 1)
			{
				expert_add_info_format(pinfo, item, &ei_invalid_range, "Invalid control type value [0..1]");
			}
			break;
		}
		case 1:
		{
			// todo : encoder not right for this case.
			ptvcursor_add_ret_uint(ptvc, hf_nfapi_number_of_cc, 1, ENC_BIG_ENDIAN, &test_value);

			if (!(test_value >= 1 && test_value <= 32))
			{
				expert_add_info_format(pinfo, item, &ei_invalid_range, "Invalid number of cc value [1..32]");
			}

			/*
			ptvcursor_add_text_with_subtree(ptvc, SUBTREE_UNDEFINED_LENGTH, ett_nfapi_tlv_tree, "CCs");

			for (int i = 0; i < num_cc; ++i)
			{
				ptvcursor_add_text_with_subtree(ptvc, SUBTREE_UNDEFINED_LENGTH, ett_nfapi_tlv_tree, "[%d]", i);

				guint8 ri_size = tvb_get_guint8(ptvcursor_tvbuff(ptvc), ptvcursor_current_offset(ptvc));
				ptvcursor_add(ptvc, hf_nfapi_ri_size, 1, ENC_BIG_ENDIAN);

				ptvcursor_add_text_with_subtree(ptvc, SUBTREE_UNDEFINED_LENGTH, ett_nfapi_tlv_tree, "Rank");

				for (int j = 0; j < ri_size; ++j)
				{
					ptvcursor_add_text_with_subtree(ptvc, SUBTREE_UNDEFINED_LENGTH, ett_nfapi_tlv_tree, "[%d]", j);
					ptvcursor_add(ptvc, hf_nfapi_dl_cqi_pmi_size, 1, ENC_BIG_ENDIAN);
					ptvcursor_pop_subtree(ptvc);
				}

				ptvcursor_pop_subtree(ptvc);

				ptvcursor_pop_subtree(ptvc);
			}

			ptvcursor_pop_subtree(ptvc);
			*/

			break;
		}
	}
}
static void dissect_ul_config_cqi_ri_info_rel13_value(ptvcursor_t * ptvc, packet_info* pinfo)
{
	guint32 test_value;

	// DL CQI/PMI/RI size 2
	proto_item* item = ptvcursor_add_ret_uint(ptvc, hf_nfapi_dl_cqi_ri_pmi_size_2, 2, ENC_BIG_ENDIAN, &test_value);
	if (test_value < 255)
	{
		expert_add_info_format(pinfo, item, &ei_invalid_range, "Invalid dl cqi ri pmi size 2 value [>= 255]");
	}
}
static void dissect_ul_config_harq_info_ulsch_rel10_value(ptvcursor_t * ptvc, packet_info* pinfo)
{
	proto_item* item;
	guint32 test_value;

	// HARQ Size
	item = ptvcursor_add_ret_uint(ptvc, hf_nfapi_harq_size, 1, ENC_BIG_ENDIAN, &test_value);
	if (test_value > 21)
	{
		expert_add_info_format(pinfo, item, &ei_invalid_range, "Invalid harq size value [0..21]");
	}

	// Delta Offset HARQ
	item = ptvcursor_add_ret_uint(ptvc, hf_nfapi_delta_offset_harq, 1, ENC_BIG_ENDIAN, &test_value);
	if (test_value > 15)
	{
		expert_add_info_format(pinfo, item, &ei_invalid_range, "Invalid delta offset harq value [0..15]");
	}

	// ACK_NACK mode
	item = ptvcursor_add_ret_uint(ptvc, hf_nfapi_tdd_ack_nack_mode, 1, ENC_BIG_ENDIAN, &test_value);
	if (test_value > 5)
	{
		expert_add_info_format(pinfo, item, &ei_invalid_range, "Invalid ack nack mode value [0..5]");
	}
}
static void dissect_ul_config_harq_info_ulsch_rel13_value(ptvcursor_t * ptvc, packet_info* pinfo)
{
	proto_item* item;
	guint32 test_value;

	// HARQ Size 2
	ptvcursor_add(ptvc, hf_nfapi_harq_size_2, 2, ENC_BIG_ENDIAN);

	// Delta Offset HARQ 2
	item = ptvcursor_add_ret_uint(ptvc, hf_nfapi_delta_offset_harq_2, 1, ENC_BIG_ENDIAN, &test_value);
	if (test_value > 15)
	{
		expert_add_info_format(pinfo, item, &ei_invalid_range, "Invalid delta offset harq 2 value [0..15]");
	}
}
static void dissect_ul_config_ue_info_rel8_value(ptvcursor_t * ptvc, packet_info* pinfo)
{
	proto_item* item;
	guint32 test_value;

	// Handle
	ptvcursor_add(ptvc, hf_nfapi_handle, 4, ENC_BIG_ENDIAN);

	// RNTI
	item = ptvcursor_add_ret_uint(ptvc, hf_nfapi_rnti, 2, ENC_BIG_ENDIAN, &test_value);
	if (test_value < 1)
	{
		expert_add_info_format(pinfo, item, &ei_invalid_range, "Invalid rnti value [1..65535]");
	}
}
static void dissect_ul_config_ue_info_rel11_value(ptvcursor_t * ptvc, packet_info* pinfo)
{
	proto_item* item;
	guint32 test_value;

	// Virtual cell ID enabled flag
	item = ptvcursor_add_ret_uint(ptvc, hf_nfapi_virtual_cell_id_enabled_flag, 1, ENC_BIG_ENDIAN, &test_value);
	if (test_value > 1)
	{
		expert_add_info_format(pinfo, item, &ei_invalid_range, "Invalid virtual cell id enabled flag value [0..1]");
	}

	// nPUCCH Identity
	item = ptvcursor_add_ret_uint(ptvc, hf_nfapi_npucch_identity, 2, ENC_BIG_ENDIAN, &test_value);
	if (test_value > 503)
	{
		expert_add_info_format(pinfo, item, &ei_invalid_range, "Invalid npucch identity value [0..503]");
	}

}
static void dissect_ul_config_ue_info_rel13_value(ptvcursor_t * ptvc, packet_info* pinfo)
{
	proto_item* item;
	guint32 test_value;

	// UE Type
	item = ptvcursor_add_ret_uint(ptvc, hf_nfapi_ue_type, 1, ENC_BIG_ENDIAN, &test_value);
	if (test_value > 2)
	{
		expert_add_info_format(pinfo, item, &ei_invalid_range, "Invalid ue type value [0..2]");
	}

	// Empty symbols
	// todo : use bit map decoding
	ptvcursor_add(ptvc, hf_nfapi_empty_symbols, 1, ENC_BIG_ENDIAN);

	// Total Number of repetitions
	item = ptvcursor_add_ret_uint(ptvc, hf_nfapi_total_number_of_repetitions, 2, ENC_BIG_ENDIAN, &test_value);
	if (!(test_value >= 1 && test_value <= 32))
	{
		expert_add_info_format(pinfo, item, &ei_invalid_range, "Invalid total number of repetitions value [1..32]");
	}

	// Repetition Number
	item = ptvcursor_add_ret_uint(ptvc, hf_nfapi_repetition_number, 2, ENC_BIG_ENDIAN, &test_value);
	if (!(test_value >= 1 && test_value <= 32))
	{
		expert_add_info_format(pinfo, item, &ei_invalid_range, "Invalid repetition number value [1..32]");
	}

}
static void dissect_ul_config_cqi_info_rel8_value(ptvcursor_t * ptvc, packet_info* pinfo)
{
	proto_item* item;
	guint32 test_value;

	// PUCCH index
	item = ptvcursor_add_ret_uint(ptvc, hf_nfapi_pucch_index, 2, ENC_BIG_ENDIAN, &test_value);
	if (test_value > 1184)
	{
		expert_add_info_format(pinfo, item, &ei_invalid_range, "Invalid pucch Index value [0..1184]");
	}

	// DL CQI/PMI Size
	ptvcursor_add(ptvc, hf_nfapi_dl_cqi_pmi_size, 1, ENC_BIG_ENDIAN);
}
static void dissect_ul_config_cqi_info_rel10_value(ptvcursor_t * ptvc, packet_info* pinfo)
{
	proto_item* item;
	guint32 test_value;

	// Number of PUCCH Resources
	item = ptvcursor_add_ret_uint(ptvc, hf_nfapi_number_of_pucch_resource, 1, ENC_BIG_ENDIAN, &test_value);
	if (!(test_value >= 1 && test_value <= 2))
	{
		expert_add_info_format(pinfo, item, &ei_invalid_range, "Invalid number of pucch resources value [1..2]");
	}

	//PUCCH Index P1
	item = ptvcursor_add_ret_uint(ptvc, hf_nfapi_pucch_index_p1, 2, ENC_BIG_ENDIAN, &test_value);
	if (test_value > 1184)
	{
		expert_add_info_format(pinfo, item, &ei_invalid_range, "Invalid pucch Index p1 value [0..1184]");
	}
}
static void dissect_ul_config_cqi_info_rel13_value(ptvcursor_t * ptvc, packet_info* pinfo)
{
	proto_item* item;
	guint32 test_value;

	// CSI_mode
	item = ptvcursor_add_ret_uint(ptvc, hf_nfapi_csi_mode, 1, ENC_BIG_ENDIAN, &test_value);
	if (test_value > 2)
	{
		expert_add_info_format(pinfo, item, &ei_invalid_range, "Invalid csi mode value [0..2]");
	}

	// DL CQI/PMI Size 2
	ptvcursor_add(ptvc, hf_nfapi_dl_cqi_pmi_size_2, 2, ENC_BIG_ENDIAN);

	// Starting PRB
	item = ptvcursor_add_ret_uint(ptvc, hf_nfapi_statring_prb, 1, ENC_BIG_ENDIAN, &test_value);
	if (test_value > 109)
	{
		expert_add_info_format(pinfo, item, &ei_invalid_range, "Invalid starting prb value [0..109]");
	}

	// n_PRB
	item = ptvcursor_add_ret_uint(ptvc, hf_nfapi_nprb, 1, ENC_BIG_ENDIAN, &test_value);
	if (test_value > 7)
	{
		expert_add_info_format(pinfo, item, &ei_invalid_range, "Invalid n prb value [0..7]");
	}

	// cdm_Index
	item = ptvcursor_add_ret_uint(ptvc, hf_nfapi_cdm_index, 1, ENC_BIG_ENDIAN, &test_value);
	if (test_value > 1)
	{
		expert_add_info_format(pinfo, item, &ei_invalid_range, "Invalid cdm Index value [0..1]");
	}

	// N srs
	item = ptvcursor_add_ret_uint(ptvc, hf_nfapi_nsrs, 1, ENC_BIG_ENDIAN, &test_value);
	if (test_value > 1)
	{
		expert_add_info_format(pinfo, item, &ei_invalid_range, "Invalid n srs value [0..1]");
	}

}
static void dissect_ul_config_sr_info_rel8_value(ptvcursor_t * ptvc, packet_info* pinfo)
{
	guint32 test_value;
	proto_item* item = ptvcursor_add_ret_uint(ptvc, hf_nfapi_pucch_index, 1, ENC_BIG_ENDIAN, &test_value);
	if (test_value > 2047)
	{
		expert_add_info_format(pinfo, item, &ei_invalid_range, "Invalid pucch Index value [0..2047]");
	}
}
static void dissect_ul_config_sr_info_rel10_value(ptvcursor_t * ptvc, packet_info* pinfo)
{
	proto_item* item;
	guint32 test_value;

	// Number of PUCCH Resources
	item = ptvcursor_add_ret_uint(ptvc, hf_nfapi_number_of_pucch_resource, 1, ENC_BIG_ENDIAN, &test_value);
	if (!(test_value >= 1 && test_value <= 2))
	{
		expert_add_info_format(pinfo, item, &ei_invalid_range, "Invalid number of pucch resources value [1..2]");
	}

	// PUCCH Index P1
	item = ptvcursor_add_ret_uint(ptvc, hf_nfapi_pucch_index_p1, 2, ENC_BIG_ENDIAN, &test_value);
	if (test_value > 2047)
	{
		expert_add_info_format(pinfo, item, &ei_invalid_range, "Invalid pucch Index p1 value [0..2047]");
	}
}
static void dissect_ul_config_harq_info_uci_rel10_tdd_value(ptvcursor_t * ptvc, packet_info* pinfo)
{
	proto_item* item;
	guint32 test_value, ack_nack_mode_value;

	// HARQ size
	item = ptvcursor_add_ret_uint(ptvc, hf_nfapi_harq_size, 1, ENC_BIG_ENDIAN, &test_value);
	if (test_value > 21)
	{
		expert_add_info_format(pinfo, item, &ei_invalid_range, "Invalid harq size value [0..21]");
	}

	// ACK_NACK mode
	item = ptvcursor_add_ret_uint(ptvc, hf_nfapi_tdd_ack_nack_mode, 1, ENC_BIG_ENDIAN, &ack_nack_mode_value);
	if (ack_nack_mode_value > 5)
	{
		expert_add_info_format(pinfo, item, &ei_invalid_range, "Invalid ack nack mode value [0..5]");
	}

	// Number of PUCCH resources
	item = ptvcursor_add_ret_uint(ptvc, hf_nfapi_number_of_pucch_resource, 1, ENC_BIG_ENDIAN, &test_value);
	if (test_value > 4)
	{
		expert_add_info_format(pinfo, item, &ei_invalid_range, "Invalid number of pucch resources value [0..4]");
	}

	// n_PUCCH_1_0
	item = ptvcursor_add_ret_uint(ptvc, hf_nfapi_n_pucch_1_0, 2, ENC_BIG_ENDIAN, &test_value);
	if (ack_nack_mode_value == 0 || ack_nack_mode_value == 1 || ack_nack_mode_value == 2)
	{
		if (test_value > 2047)
		{
			expert_add_info_format(pinfo, item, &ei_invalid_range, "Invalid n pucch 1 0 value [0..2047] (All Format 1a/1b)");
		}
	}
	else if (ack_nack_mode_value == 3)
	{
		if (test_value > 549)
		{
			expert_add_info_format(pinfo, item, &ei_invalid_range, "Invalid n pucch 1 0 value [0..549] (Format 3)");
		}
	}

	// n_PUCCH_1_1
	item = ptvcursor_add_ret_uint(ptvc, hf_nfapi_n_pucch_1_1, 2, ENC_BIG_ENDIAN, &test_value);
	if (ack_nack_mode_value == 0 || ack_nack_mode_value == 1 || ack_nack_mode_value == 2)
	{
		if (test_value > 2047)
		{
			expert_add_info_format(pinfo, item, &ei_invalid_range, "Invalid n pucch 1 1 value [0..2047] (All Format 1a/1b)");
		}
	}

	// n_PUCCH_1_2
	item = ptvcursor_add_ret_uint(ptvc, hf_nfapi_n_pucch_1_2, 2, ENC_BIG_ENDIAN, &test_value);
	if (ack_nack_mode_value == 2)
	{
		if (test_value > 2047)
		{
			expert_add_info_format(pinfo, item, &ei_invalid_range, "Invalid n pucch 1 2 value [0..2047] (All Format 1a/1b)");
		}
	}

	// n_PUCCH_1_3
	item = ptvcursor_add_ret_uint(ptvc, hf_nfapi_n_pucch_1_3, 2, ENC_BIG_ENDIAN, &test_value);
	if (ack_nack_mode_value == 2)
	{
		if (test_value > 2047)
		{
			expert_add_info_format(pinfo, item, &ei_invalid_range, "Invalid n pucch 1 3 value [0..2047] (All Format 1a/1b)");
		}
	}
}
static void dissect_ul_config_harq_info_uci_rel8_fdd_value(ptvcursor_t * ptvc, packet_info* pinfo)
{
	proto_item* item;
	guint32 test_value;

	// n_PUCCH_1_0
	// todo : how to work out the ack_nack mode?
	item = ptvcursor_add_ret_uint(ptvc, hf_nfapi_n_pucch_1_0, 2, ENC_BIG_ENDIAN, &test_value);
	if (test_value > 2047)
	{
		expert_add_info_format(pinfo, item, &ei_invalid_range, "Invalid n pucch 1 0 value [0..2047]");
	}

	// HARQ Size
	item = ptvcursor_add_ret_uint(ptvc, hf_nfapi_harq_size, 1, ENC_BIG_ENDIAN, &test_value);
	if (!(test_value >= 1 && test_value <= 2))
	{
		expert_add_info_format(pinfo, item, &ei_invalid_range, "Invalid harq size value [1..2]");
	}
}
static void dissect_ul_config_harq_info_uci_rel9_later_fdd_value(ptvcursor_t * ptvc, packet_info* pinfo)
{
	proto_item *item, *harq_size_item;
	guint32 test_value, harq_size_value, ack_nack_mode_value;

	// HARQ Size
	harq_size_item = ptvcursor_add_ret_uint(ptvc, hf_nfapi_harq_size, 1, ENC_BIG_ENDIAN, &harq_size_value);

	// ACK_NAK mode
	item = ptvcursor_add_ret_uint(ptvc, hf_nfapi_fdd_ack_nack_mode, 1, ENC_BIG_ENDIAN, &ack_nack_mode_value);
	if (ack_nack_mode_value > 4)
	{
		expert_add_info_format(pinfo, item, &ei_invalid_range, "Invalid ack nack mode value [0..4]");
	}

	if (ack_nack_mode_value == 0 || ack_nack_mode_value == 2)
	{
		if (!(harq_size_value >= 1 && harq_size_value <= 10))
		{
			expert_add_info_format(pinfo, harq_size_item, &ei_invalid_range, "Invalid harq size value [1..10] (Format 1a/1b/3)");
		}
	}
	else if (ack_nack_mode_value == 3 || ack_nack_mode_value == 4)
	{
		if (harq_size_value != 0)
		{
			expert_add_info_format(pinfo, harq_size_item, &ei_invalid_range, "Invalid harq size value [0] (Format 4/5)");
		}
	}

	// Number of PUCCH Resources
	item = ptvcursor_add_ret_uint(ptvc, hf_nfapi_number_of_pucch_resource, 1, ENC_BIG_ENDIAN, &test_value);
	if (test_value == 0 || test_value == 2)
	{
		if (!(harq_size_value >= 1 && harq_size_value <= 4))
		{
			expert_add_info_format(pinfo, item, &ei_invalid_range, "Invalid harq size value [1..4] (Format 1a/1b/3)");
		}
	}
	else if (test_value == 3 || test_value == 4)
	{
		if (harq_size_value != 0)
		{
			expert_add_info_format(pinfo, item, &ei_invalid_range, "Invalid harq size value [0] (Format 4/5)");
		}
	}

	// n_PUCCH_1_0
	item = ptvcursor_add_ret_uint(ptvc, hf_nfapi_n_pucch_1_0, 2, ENC_BIG_ENDIAN, &test_value);
	if (ack_nack_mode_value == 0 || ack_nack_mode_value == 1)
	{
		if (test_value > 2047)
		{
			expert_add_info_format(pinfo, item, &ei_invalid_range, "Invalid npucch 1 0 value [0..2047] (Format 1a/1b/channel selection)");
		}
	}
	else if (ack_nack_mode_value == 2)
	{
		if (test_value > 549)
		{
			expert_add_info_format(pinfo, item, &ei_invalid_range, "Invalid npucch 1 0 value [0..549] (Format 3)");
		}
	}

	// n_PUCCH_1_1
	item = ptvcursor_add_ret_uint(ptvc, hf_nfapi_n_pucch_1_1, 2, ENC_BIG_ENDIAN, &test_value);
	if (ack_nack_mode_value == 0 || ack_nack_mode_value == 1)
	{
		if (test_value > 2047)
		{
			expert_add_info_format(pinfo, item, &ei_invalid_range, "Invalid npucch 1 1 value [0..2047] (Format 1a/1b/channel selection)");
		}
	}

	// n_PUCCH_1_2
	item = ptvcursor_add_ret_uint(ptvc, hf_nfapi_n_pucch_1_2, 2, ENC_BIG_ENDIAN, &test_value);
	if (ack_nack_mode_value == 0 || ack_nack_mode_value == 1)
	{
		if (test_value > 2047)
		{
			expert_add_info_format(pinfo, item, &ei_invalid_range, "Invalid npucch 1 2 value [0..2047] (Format 1a/1b/channel selection)");
		}
	}

	// n_PUCCH_1_3
	item = ptvcursor_add_ret_uint(ptvc, hf_nfapi_n_pucch_1_3, 2, ENC_BIG_ENDIAN, &test_value);
	if (ack_nack_mode_value == 0 || ack_nack_mode_value == 1)
	{
		if (test_value > 2047)
		{
			expert_add_info_format(pinfo, item, &ei_invalid_range, "Invalid npucch 1 3 value [0..2047] (Format 1a/1b/channel selection)");
		}
	}
}
static void dissect_ul_config_harq_info_uci_rel11_fdd_tdd_value(ptvcursor_t * ptvc, packet_info* pinfo)
{
	proto_item* item;
	guint32 test_value;

	// Num_ant_ports
	item = ptvcursor_add_ret_uint(ptvc, hf_nfapi_num_ant_ports, 1, ENC_BIG_ENDIAN, &test_value);
	if (!(test_value >= 1 && test_value <= 2))
	{
		expert_add_info_format(pinfo, item, &ei_invalid_range, "Invalid num ant ports value [1..2]");
	}

	// n_PUCCH_2_0
	// todo : how to work out the ack nack mode
	item = ptvcursor_add_ret_uint(ptvc, hf_nfapi_n_pucch_2_0, 2, ENC_BIG_ENDIAN, &test_value);
	if (test_value > 2047)
	{
		expert_add_info_format(pinfo, item, &ei_invalid_range, "Invalid npucch 2 0 value [0..2047]");
	}

	// n_PUCCH_2_1
	item = ptvcursor_add_ret_uint(ptvc, hf_nfapi_n_pucch_2_1, 2, ENC_BIG_ENDIAN, &test_value);
	if (test_value > 2047)
	{
		expert_add_info_format(pinfo, item, &ei_invalid_range, "Invalid npucch 2 1 value [0..2047]");
	}

	// n_PUCCH_2_2
	item = ptvcursor_add_ret_uint(ptvc, hf_nfapi_n_pucch_2_2, 2, ENC_BIG_ENDIAN, &test_value);
	if (test_value > 2047)
	{
		expert_add_info_format(pinfo, item, &ei_invalid_range, "Invalid npucch 2 2 value [0..2047]");
	}

	// n_PUCCH_2_3
	item = ptvcursor_add_ret_uint(ptvc, hf_nfapi_n_pucch_2_3, 2, ENC_BIG_ENDIAN, &test_value);
	if (test_value > 2047)
	{
		expert_add_info_format(pinfo, item, &ei_invalid_range, "Invalid npucch 2 3 value [0..2047]");
	}

}
static void dissect_ul_config_harq_info_uci_rel13_fdd_tdd_value(ptvcursor_t * ptvc, packet_info* pinfo)
{
	proto_item* item;
	guint32 test_value;

	// HARQ Size 2
	ptvcursor_add(ptvc, hf_nfapi_harq_size_2, 2, ENC_BIG_ENDIAN);

	// Starting PRB
	item = ptvcursor_add_ret_uint(ptvc, hf_nfapi_starting_prb, 1, ENC_BIG_ENDIAN, &test_value);
	if (test_value > 109)
	{
		expert_add_info_format(pinfo, item, &ei_invalid_range, "Invalid starting prb value [0..109]");
	}

	// n_PRB
	item = ptvcursor_add_ret_uint(ptvc, hf_nfapi_nprb, 1, ENC_BIG_ENDIAN, &test_value);
	if (test_value > 109)
	{
		expert_add_info_format(pinfo, item, &ei_invalid_range, "Invalid n prb value [0..7]");
	}

	// cdm_Index
	item = ptvcursor_add_ret_uint(ptvc, hf_nfapi_cdm_index, 1, ENC_BIG_ENDIAN, &test_value);
	if (test_value > 1)
	{
		expert_add_info_format(pinfo, item, &ei_invalid_range, "Invalid cdm Index value [0..1]");
	}

	// N srs
	item = ptvcursor_add_ret_uint(ptvc, hf_nfapi_nsrs, 1, ENC_BIG_ENDIAN, &test_value);
	if (test_value > 1)
	{
		expert_add_info_format(pinfo, item, &ei_invalid_range, "Invalid n srs value [0..1]");
	}
}
static void dissect_ul_config_srs_info_rel8_value(ptvcursor_t * ptvc, packet_info* pinfo)
{
	proto_item* item;
	guint32 test_value;

	// Handle
	ptvcursor_add(ptvc, hf_nfapi_handle, 4, ENC_BIG_ENDIAN);

	// Size
	ptvcursor_add(ptvc, hf_nfapi_size, 2, ENC_BIG_ENDIAN);

	// RNTI
	item = ptvcursor_add_ret_uint(ptvc, hf_nfapi_rnti, 2, ENC_BIG_ENDIAN, &test_value);
	if (test_value < 1)
	{
		expert_add_info_format(pinfo, item, &ei_invalid_range, "Invalid rnti value [1..65535]");
	}

	// SRS Bandwidth
	item = ptvcursor_add_ret_uint(ptvc, hf_nfapi_srs_bandwidth, 1, ENC_BIG_ENDIAN, &test_value);
	if (test_value > 3)
	{
		expert_add_info_format(pinfo, item, &ei_invalid_range, "Invalid srs bandwidth value [0..3]");
	}

	// Frequency Domain Position
	item = ptvcursor_add_ret_uint(ptvc, hf_nfapi_frequency_domain_position, 1, ENC_BIG_ENDIAN, &test_value);
	if (test_value > 23)
	{
		expert_add_info_format(pinfo, item, &ei_invalid_range, "Invalid frequency domain bandwidth value [0..23]");
	}

	// SRS Hopping Bandwidth
	item = ptvcursor_add_ret_uint(ptvc, hf_nfapi_srs_hopping_bandwidth, 1, ENC_BIG_ENDIAN, &test_value);
	if (test_value > 3)
	{
		expert_add_info_format(pinfo, item, &ei_invalid_range, "Invalid srs hopping bandwidth value [0..3]");
	}

	// Transmission Comb
	item = ptvcursor_add_ret_uint(ptvc, hf_nfapi_transmission_comb, 1, ENC_BIG_ENDIAN, &test_value);
	if (test_value > 3)
	{
		expert_add_info_format(pinfo, item, &ei_invalid_range, "Invalid transmission comb value [0..3]");
	}

	// ISRS / SRS-ConfigIndex
	item = ptvcursor_add_ret_uint(ptvc, hf_nfapi_i_srs, 2, ENC_BIG_ENDIAN, &test_value);
	if (test_value > 1023)
	{
		expert_add_info_format(pinfo, item, &ei_invalid_range, "Invalid isrs/srs-configindex value [0..1023]");
	}

	// Sounding Reference Cyclic Shift
	item = ptvcursor_add_ret_uint(ptvc, hf_nfapi_sounding_reference_cyclic_shift, 1, ENC_BIG_ENDIAN, &test_value);
	if (test_value > 11)
	{
		expert_add_info_format(pinfo, item, &ei_invalid_range, "Invalid sounding reference cyclic shift value [0..11]");
	}
}
static void dissect_ul_config_srs_info_rel10_value(ptvcursor_t * ptvc, packet_info* pinfo)
{
	guint32 test_value;

	proto_item* item = ptvcursor_add_ret_uint(ptvc, hf_nfapi_antenna_port, 1, ENC_BIG_ENDIAN, &test_value);
	if (test_value > 2)
	{
		expert_add_info_format(pinfo, item, &ei_invalid_range, "Invalid antenna port value [0..2]");
	}
}
static void dissect_ul_config_srs_info_rel13_value(ptvcursor_t * ptvc, packet_info* pinfo)
{
	guint32 test_value;

	proto_item* item = ptvcursor_add_ret_uint(ptvc, hf_nfapi_number_of_combs, 1, ENC_BIG_ENDIAN, &test_value);
	if (test_value > 1)
	{
		expert_add_info_format(pinfo, item, &ei_invalid_range, "Invalid number of combs value [0..1]");
	}
}
static void dissect_hi_dci0_pdu(ptvcursor_t * ptvc, packet_info* pinfo)
{
	guint32 test_value, size;

	// PDU Type
	proto_item* item = ptvcursor_add_ret_uint(ptvc, hf_nfapi_hi_dci0_pdu_type, 1, ENC_BIG_ENDIAN, &test_value);
	if (test_value > 3)
	{
		expert_add_info_format(pinfo, item, &ei_invalid_range, "Invalid pdu type value [0..3]");
	}

	// PDU Size
	ptvcursor_add_ret_uint(ptvc, hf_nfapi_pdu_size, 1, ENC_BIG_ENDIAN, &size);

	guint pdu_end = (ptvcursor_current_offset(ptvc) + size - 2);
	dissect_tlv_list(ptvc, pinfo, pdu_end);
}
static void dissect_hi_dci0_request_body_value(ptvcursor_t * ptvc, packet_info* pinfo)
{
	guint32 test_value, num_pdu;

	// SFN/SF
	ptvcursor_add(ptvc, hf_nfapi_sfn_sf, 2, ENC_BIG_ENDIAN);

	// Number of DCI
	ptvcursor_add_ret_uint(ptvc, hf_nfapi_number_of_dci_pdus, 1, ENC_BIG_ENDIAN, &num_pdu);

	// Number of HI
	ptvcursor_add_ret_uint(ptvc, hf_nfapi_number_of_hi_pdus, 1, ENC_BIG_ENDIAN, &test_value);
	num_pdu += test_value;

	dissect_array_value(ptvc, pinfo, "HI DCI0 PDU List", ett_nfapi_hi_dci0_request_pdu_list, num_pdu, dissect_hi_dci0_pdu);
}
static void dissect_hi_dci0_hi_rel8_value(ptvcursor_t * ptvc, packet_info* pinfo)
{
	proto_item* item;
	guint32 test_value;
	gboolean test_boolean;

	// Resource block start
	item = ptvcursor_add_ret_uint(ptvc, hf_nfapi_resource_block_start, 1, ENC_BIG_ENDIAN, &test_value);
	if (test_value > 100)
	{
		expert_add_info_format(pinfo, item, &ei_invalid_range, "Invalid resource block start value [0..100]");
	}

	// Cyclic Shift 2 for DMRS
	item = ptvcursor_add_ret_uint(ptvc, hf_nfapi_cyclic_shift_2_for_drms, 1, ENC_BIG_ENDIAN, &test_value);
	if (test_value > 7)
	{
		expert_add_info_format(pinfo, item, &ei_invalid_range, "Invalid cyclic shift 2 for drms value [0..7]");
	}

	// HI value
	item = ptvcursor_add_ret_boolean(ptvc, hf_nfapi_hi_value, 1, ENC_BIG_ENDIAN, &test_boolean);
	if (test_boolean > 1)
	{
		expert_add_info_format(pinfo, item, &ei_invalid_range, "Invalid hi value [0..1]");
	}

	// I_PHICH
	item = ptvcursor_add_ret_uint(ptvc, hf_nfapi_i_phich, 1, ENC_BIG_ENDIAN, &test_value);
	if (test_value > 1)
	{
		expert_add_info_format(pinfo, item, &ei_invalid_range, "Invalid i phich value [0..1]");
	}

	// Transmission power
	item = ptvcursor_add_ret_uint(ptvc, hf_nfapi_transmission_power, 2, ENC_BIG_ENDIAN, &test_value);
	if (test_value > 10000)
	{
		expert_add_info_format(pinfo, item, &ei_invalid_range, "Invalid transmission power value [0..10000]");
	}

}
static void dissect_hi_dci0_hi_rel10_value(ptvcursor_t * ptvc, packet_info* pinfo)
{
	proto_item* item;
	gboolean test_boolean;

	// Flag TB2
	item = ptvcursor_add_ret_boolean(ptvc, hf_nfapi_flag_tb2, 1, ENC_BIG_ENDIAN, &test_boolean);
	if (test_boolean > 1)
	{
		expert_add_info_format(pinfo, item, &ei_invalid_range, "Invalid flag tb2 value [0..1]");
	}

	// HI Value 2
	item = ptvcursor_add_ret_boolean(ptvc, hf_nfapi_hi_value_2, 1, ENC_BIG_ENDIAN, &test_boolean);
	if (test_boolean > 1)
	{
		expert_add_info_format(pinfo, item, &ei_invalid_range, "Invalid hi2 value [0..1]");
	}

}
static void dissect_hi_dci0_dci_ul_rel8_value(ptvcursor_t * ptvc, packet_info* pinfo)
{
	proto_item* item;
	guint32 test_value;

	// DCI format
	item = ptvcursor_add_ret_uint(ptvc, hf_nfapi_ul_dci_format, 1, ENC_BIG_ENDIAN, &test_value);
	if (test_value > 4)
	{
		expert_add_info_format(pinfo, item, &ei_invalid_range, "Invalid dci format value [0..4]");
	}

	// CCE index
	item = ptvcursor_add_ret_uint(ptvc, hf_nfapi_cce_idx, 1, ENC_BIG_ENDIAN, &test_value);
	if (test_value > 88)
	{
		expert_add_info_format(pinfo, item, &ei_invalid_range, "Invalid cce Index value [0..88]");
	}

	// Aggregation level
	item = ptvcursor_add_ret_uint(ptvc, hf_nfapi_aggregation_level, 1, ENC_BIG_ENDIAN, &test_value);
	if (!(test_value == 1 || test_value == 2 || test_value == 4 ||
		  test_value == 8))
	{
		expert_add_info_format(pinfo, item, &ei_invalid_range, "Invalid aggregation level value [1, 2, 4, 8]");
	}

	// RNTI
	item = ptvcursor_add_ret_uint(ptvc, hf_nfapi_rnti, 2, ENC_BIG_ENDIAN, &test_value);
	if (test_value < 1)
	{
		expert_add_info_format(pinfo, item, &ei_invalid_range, "Invalid rnti value [1..65535]");
	}

	// Resource block start
	item = ptvcursor_add_ret_uint(ptvc, hf_nfapi_resource_block_start, 1, ENC_BIG_ENDIAN, &test_value);
	if (test_value > 100)
	{
		expert_add_info_format(pinfo, item, &ei_invalid_range, "Invalid resource block start value [0..100]");
	}

	// Number of resource blocks
	item = ptvcursor_add_ret_uint(ptvc, hf_nfapi_number_of_resource_blocks, 1, ENC_BIG_ENDIAN, &test_value);
	if (test_value > 100)
	{
		expert_add_info_format(pinfo, item, &ei_invalid_range, "Invalid number of resource blocks value [0..100]");
	}

	// MCS_1
	item = ptvcursor_add_ret_uint(ptvc, hf_nfapi_mcs_1, 1, ENC_BIG_ENDIAN, &test_value);
	if (test_value > 31)
	{
		expert_add_info_format(pinfo, item, &ei_invalid_range, "Invalid mcs 1 value [0..31]");
	}

	// Cyclic Shift 2 for DMRS
	item = ptvcursor_add_ret_uint(ptvc, hf_nfapi_cyclic_shift_2_for_drms, 1, ENC_BIG_ENDIAN, &test_value);
	if (test_value > 7)
	{
		expert_add_info_format(pinfo, item, &ei_invalid_range, "Invalid cyclic shift 2 for drms value [0..7]");
	}

	// Frequency hopping enabled flag
	item = ptvcursor_add_ret_uint(ptvc, hf_nfapi_frequency_hopping_enabled_flag, 1, ENC_BIG_ENDIAN, &test_value);
	if (test_value > 1)
	{
		expert_add_info_format(pinfo, item, &ei_invalid_range, "Invalid frequency hopping enabled flag value [0..1]");
	}

	// Frequency hopping bits
	item = ptvcursor_add_ret_uint(ptvc, hf_nfapi_frequency_hopping_bits, 1, ENC_BIG_ENDIAN, &test_value);
	if (test_value > 3)
	{
		expert_add_info_format(pinfo, item, &ei_invalid_range, "Invalid frequency hopping bits value [0..3]");
	}

	// New Data indication_1
	item = ptvcursor_add_ret_uint(ptvc, hf_nfapi_new_data_indication, 1, ENC_BIG_ENDIAN, &test_value);
	if (test_value > 1)
	{
		expert_add_info_format(pinfo, item, &ei_invalid_range, "Invalid new data indication value [0..1]");
	}

	// UE TX antenna selection
	item = ptvcursor_add_ret_uint(ptvc, hf_nfapi_ue_tx_antenna_selection, 1, ENC_BIG_ENDIAN, &test_value);
	if (test_value > 2)
	{
		expert_add_info_format(pinfo, item, &ei_invalid_range, "Invalid ue tx antenna selection value [0..2]");
	}

	// TPC
	item = ptvcursor_add_ret_uint(ptvc, hf_nfapi_tpc, 1, ENC_BIG_ENDIAN, &test_value);
	if (test_value > 3)
	{
		expert_add_info_format(pinfo, item, &ei_invalid_range, "Invalid tpc value value [0..3]");
	}

	// CQI/CSI request
	item = ptvcursor_add_ret_uint(ptvc, hf_nfapi_cqi_csi_request, 1, ENC_BIG_ENDIAN, &test_value);
	if (test_value > 7)
	{
		expert_add_info_format(pinfo, item, &ei_invalid_range, "Invalid cqi csi value [0..7]");
	}

	// UL index
	item = ptvcursor_add_ret_uint(ptvc, hf_nfapi_ul_index, 1, ENC_BIG_ENDIAN, &test_value);
	if (test_value > 3)
	{
		expert_add_info_format(pinfo, item, &ei_invalid_range, "Invalid ul Index value [0..3]");
	}

	// DL assignment index
	item = ptvcursor_add_ret_uint(ptvc, hf_nfapi_dl_assignment_index, 1, ENC_BIG_ENDIAN, &test_value);
	if (!(test_value >= 1 && test_value <= 4))
	{
		expert_add_info_format(pinfo, item, &ei_invalid_range, "Invalid dl assignment Index value [1..4]");
	}

	// TPC bitmap
	ptvcursor_add(ptvc, hf_nfapi_tpc_bitmap, 4, ENC_BIG_ENDIAN);

	// Transmission power
	item = ptvcursor_add_ret_uint(ptvc, hf_nfapi_transmission_power, 2, ENC_BIG_ENDIAN, &test_value);
	if (test_value > 10000)
	{
		expert_add_info_format(pinfo, item, &ei_invalid_range, "Invalid transmission power value [0..10000]");
	}
}

static void dissect_hi_dci0_dci_ul_rel10_value(ptvcursor_t * ptvc, packet_info* pinfo)
{
	proto_item* item;
	guint32 test_value, number_of_antenna_ports_value;
	gboolean test_boolean;

	// Cross carrier scheduling flag
	item = ptvcursor_add_ret_boolean(ptvc, hf_nfapi_cross_carrier_scheduling_flag, 1, ENC_BIG_ENDIAN, &test_boolean);
	if (test_boolean > 1)
	{
		expert_add_info_format(pinfo, item, &ei_invalid_range, "Invalid cross carrier scheduling flag value [0..1]");
	}

	// Carrier indicator
	item = ptvcursor_add_ret_uint(ptvc, hf_nfapi_carrier_indicator, 1, ENC_BIG_ENDIAN, &test_value);
	if (test_value > 7)
	{
		expert_add_info_format(pinfo, item, &ei_invalid_range, "Invalid carrier indicator value [0..7]");
	}

	// Size of CQI/CSI field
	item = ptvcursor_add_ret_uint(ptvc, hf_nfapi_size_of_cqi_csi_feild, 1, ENC_BIG_ENDIAN, &test_value);
	if (test_value > 2)
	{
		expert_add_info_format(pinfo, item, &ei_invalid_range, "Invalid size of cqi/csi field value [0..2]");
	}

	// SRS flag
	item = ptvcursor_add_ret_boolean(ptvc, hf_nfapi_srs_flag, 1, ENC_BIG_ENDIAN, &test_boolean);
	if (test_boolean > 1)
	{
		expert_add_info_format(pinfo, item, &ei_invalid_range, "Invalid srs field value [0..1]");
	}

	// SRS request
	ptvcursor_add(ptvc, hf_nfapi_srs_request, 1, ENC_BIG_ENDIAN);

	// Resource allocation flag
	item = ptvcursor_add_ret_uint(ptvc, hf_nfapi_resource_allocation_flag, 1, ENC_BIG_ENDIAN, &test_value);
	if (test_value > 1)
	{
		expert_add_info_format(pinfo, item, &ei_invalid_range, "Invalid resource allocation flag value [0..1]");
	}

	// Resource allocation type
	item = ptvcursor_add_ret_uint(ptvc, hf_nfapi_resource_allocation_type, 1, ENC_BIG_ENDIAN, &test_value);
	if (test_value > 1)
	{
		expert_add_info_format(pinfo, item, &ei_invalid_range, "Invalid resource allocation type value [0..1]");
	}

	// Resource block coding
	ptvcursor_add(ptvc, hf_nfapi_resource_block_coding, 4, ENC_BIG_ENDIAN);

	// MCS_2
	item = ptvcursor_add_ret_uint(ptvc, hf_nfapi_mcs_2, 1, ENC_BIG_ENDIAN, &test_value);
	if (test_value > 31)
	{
		expert_add_info_format(pinfo, item, &ei_invalid_range, "Invalid mcs 2 value [0..31]");
	}

	// New data indication_2
	item = ptvcursor_add_ret_uint(ptvc, hf_nfapi_new_data_indication_two, 1, ENC_BIG_ENDIAN, &test_value);
	if (test_value > 1)
	{
		expert_add_info_format(pinfo, item, &ei_invalid_range, "Invalid new data indication 2 value [0..1]");
	}

	// Number of antenna ports
	item = ptvcursor_add_ret_uint(ptvc, hf_nfapi_number_of_antenna_ports, 1, ENC_BIG_ENDIAN, &number_of_antenna_ports_value);
	if (number_of_antenna_ports_value > 2)
	{
		expert_add_info_format(pinfo, item, &ei_invalid_range, "Invalid number of antenna ports value [0..2]");
	}

	// TPMI
	item = ptvcursor_add_ret_uint(ptvc, hf_nfapi_tpmi, 1, ENC_BIG_ENDIAN, &test_value);
	if (number_of_antenna_ports_value == 2)
	{
		if (test_value > 7)
		{
			expert_add_info_format(pinfo, item, &ei_invalid_range, "Invalid tpmi value [0..7]");
		}
	}
	else if (number_of_antenna_ports_value == 4)
	{
		if (test_value > 63)
		{
			expert_add_info_format(pinfo, item, &ei_invalid_range, "Invalid tpmi value [0..63]");
		}
	}

	// Total DCI length including padding
	ptvcursor_add(ptvc, hf_nfapi_total_dci_length_including_padding, 1, ENC_BIG_ENDIAN);

	// N_UL_RB
	item = ptvcursor_add_ret_uint(ptvc, hf_nfapi_n_ul_rb, 1, ENC_BIG_ENDIAN, &test_value);
	if (!(test_value == 6 || test_value == 15 || test_value == 25 || test_value == 50 ||
		test_value == 75 || test_value == 100))
	{
		expert_add_info_format(pinfo, item, &ei_invalid_range, "Invalid n ul rb value [6, 15, 25, 50, 75, 100]");
	}
}
static void dissect_hi_dci0_dci_ul_rel12_value(ptvcursor_t * ptvc, packet_info* pinfo)
{
	proto_item* item;
	guint32 test_value;

	// PSCCH Resource
	item = ptvcursor_add_ret_uint(ptvc, hf_nfapi_pscch_resource, 1, ENC_BIG_ENDIAN, &test_value);
	if (test_value > 0x3F)
	{
		expert_add_info_format(pinfo, item, &ei_invalid_range, "Invalid pscch resource value [0..0x3F]");
	}

	// Time resource pattern
	item = ptvcursor_add_ret_uint(ptvc, hf_nfapi_time_resource_pattern, 1, ENC_BIG_ENDIAN, &test_value);
	if (test_value > 0x7F)
	{
		expert_add_info_format(pinfo, item, &ei_invalid_range, "Invalid time resource pattern value [0..0x7F]");
	}

}
static void dissect_hi_dci0_mdpcch_dci_ul_rel13_value(ptvcursor_t * ptvc, packet_info* pinfo)
{
	proto_item* item;
	guint32 test_value, dci_format_value, count;
	gboolean test_boolean;

	// MPDCCH Narrowband
	item = ptvcursor_add_ret_uint(ptvc, hf_nfapi_mpdcch_narrowband, 1, ENC_BIG_ENDIAN, &test_value);
	if (test_value > 15)
	{
		expert_add_info_format(pinfo, item, &ei_invalid_range, "Invalid mpdcch narrowband value [0..15]");
	}

	// Number of PRB pairs
	item = ptvcursor_add_ret_uint(ptvc, hf_nfapi_number_of_prb_pairs, 1, ENC_BIG_ENDIAN, &test_value);
	if (!(test_value == 2 || test_value == 4 || test_value == 6))
	{
		expert_add_info_format(pinfo, item, &ei_invalid_range, "Invalid number of prb pairs value [2, 4, 6]");
	}

	// Resource Block Assignment
	item = ptvcursor_add_ret_uint(ptvc, hf_nfapi_resource_block_assignment, 1, ENC_BIG_ENDIAN, &test_value);
	if (test_value > 14)
	{
		expert_add_info_format(pinfo, item, &ei_invalid_range, "Invalid resource block assignment value [0..14]");
	}

	// MPDCCH transmission type
	item = ptvcursor_add_ret_uint(ptvc, hf_nfapi_mpdcch_transmission_type, 1, ENC_BIG_ENDIAN, &test_value);
	if (test_value > 1)
	{
		expert_add_info_format(pinfo, item, &ei_invalid_range, "Invalid mpdcch transmission type value [0..1]");
	}

	// Start symbol
	item = ptvcursor_add_ret_uint(ptvc, hf_nfapi_start_symbol, 1, ENC_BIG_ENDIAN, &test_value);
	if (!(test_value >= 1 && test_value <=4))
	{
		expert_add_info_format(pinfo, item, &ei_invalid_range, "Invalid start symbol value [0..1]");
	}

	// ECCE index
	item = ptvcursor_add_ret_uint(ptvc, hf_nfapi_ecce_index, 1, ENC_BIG_ENDIAN, &test_value);
	if (test_value > 22)
	{
		expert_add_info_format(pinfo, item, &ei_invalid_range, "Invalid ecce Index value [0..22]");
	}

	// Aggregation level
	item = ptvcursor_add_ret_uint(ptvc, hf_nfapi_aggregation_level, 1, ENC_BIG_ENDIAN, &test_value);
	if (!(test_value == 2 || test_value == 4 || test_value == 8 ||
		test_value == 16 || test_value == 24))
	{
		expert_add_info_format(pinfo, item, &ei_invalid_range, "Invalid aggregation level value [2, 4, 8, 16, 24]");
	}

	// RNTI type
	item = ptvcursor_add_ret_uint(ptvc, hf_nfapi_mpdcch_rnti_type, 1, ENC_BIG_ENDIAN, &test_value);
	if (!(test_value == 0 || test_value == 4))
	{
		expert_add_info_format(pinfo, item, &ei_invalid_range, "Invalid rnti type value [0, 4]");
	}

	// RNTI
	item = ptvcursor_add_ret_uint(ptvc, hf_nfapi_rnti, 2, ENC_BIG_ENDIAN, &test_value);
	if (test_value < 1)
	{
		expert_add_info_format(pinfo, item, &ei_invalid_range, "Invalid rnti value [1..65535]");
	}

	// CEMode
	item = ptvcursor_add_ret_uint(ptvc, hf_nfapi_ce_mode, 1, ENC_BIG_ENDIAN, &test_value);
	if (!(test_value == 1 || test_value == 2))
	{
		expert_add_info_format(pinfo, item, &ei_invalid_range, "Invalid cemode value [1,2]");
	}

	// DMRS scrambling init
	item = ptvcursor_add_ret_uint(ptvc, hf_nfapi_drms_scrambling_init, 2, ENC_BIG_ENDIAN, &test_value);
	if (test_value < 503)
	{
		expert_add_info_format(pinfo, item, &ei_invalid_range, "Invalid drms scrambling init value [0..503]");
	}

	// Initial transmission SF (io)
	item = ptvcursor_add_ret_uint(ptvc, hf_nfapi_initial_transmission_sf, 2, ENC_BIG_ENDIAN, &test_value);
	if (!(test_value <= 10239 || test_value == 0xFFFF))
	{
		expert_add_info_format(pinfo, item, &ei_invalid_range, "Invalid initial transmission sf io value [0..10239, 0xFFFF]");
	}

	// Transmission power
	item = ptvcursor_add_ret_uint(ptvc, hf_nfapi_transmission_power, 2, ENC_BIG_ENDIAN, &test_value);
	if (test_value > 10000)
	{
		expert_add_info_format(pinfo, item, &ei_invalid_range, "Invalid transmission power value [0..10000]");
	}

	// DCI format
	item = ptvcursor_add_ret_uint(ptvc, hf_nfapi_mpdcch_ul_dci_format, 1, ENC_BIG_ENDIAN, &dci_format_value);
	if (!(dci_format_value == 1 || dci_format_value == 2 || dci_format_value == 4 || dci_format_value == 5))
	{
		expert_add_info_format(pinfo, item, &ei_invalid_range, "Invalid dci format value [1, 2, 4, 5]");
	}

	// Resource block start
	item = ptvcursor_add_ret_uint(ptvc, hf_nfapi_resource_block_start, 1, ENC_BIG_ENDIAN, &test_value);
	if (test_value > 99)
	{
		expert_add_info_format(pinfo, item, &ei_invalid_range, "Invalid resource block start value [0..99]");
	}

	// Number of resource blocks
	item = ptvcursor_add_ret_uint(ptvc, hf_nfapi_number_of_resource_blocks, 1, ENC_BIG_ENDIAN, &test_value);
	if (!(test_value >= 1 && test_value <= 6))
	{
		expert_add_info_format(pinfo, item, &ei_invalid_range, "Invalid number of resource blocks value [1..6]");
	}

	// MCS
	item = ptvcursor_add_ret_uint(ptvc, hf_nfapi_mcs, 1, ENC_BIG_ENDIAN, &test_value);
	if (test_value > 15)
	{
		expert_add_info_format(pinfo, item, &ei_invalid_range, "Invalid mcs value [0..15]");
	}

	// PUSCH repetition levels
	item = ptvcursor_add_ret_uint(ptvc, hf_nfapi_pusch_repetition_levels, 1, ENC_BIG_ENDIAN, &test_value);
	if (dci_format_value == 4)
	{
		if (!(test_value >= 1 && test_value <= 4))
		{
			expert_add_info_format(pinfo, item, &ei_invalid_range, "Invalid pusch repetition levels value [1..4]");
		}
	}
	else if (dci_format_value == 5)
	{
		if (!(test_value >= 1 && test_value <= 8))
		{
			expert_add_info_format(pinfo, item, &ei_invalid_range, "Invalid pusch repetition levels value [1..8]");
		}
	}

	// Frequency hopping flag
	item = ptvcursor_add_ret_uint(ptvc, hf_nfapi_frequency_hopping_flag, 1, ENC_BIG_ENDIAN, &test_value);
	if (test_value > 1)
	{
		expert_add_info_format(pinfo, item, &ei_invalid_range, "Invalid frequency hopping flag value [0..1]");
	}

	// New Data indication
	item = ptvcursor_add_ret_uint(ptvc, hf_nfapi_new_data_indication, 1, ENC_BIG_ENDIAN, &test_value);
	if (test_value > 1)
	{
		expert_add_info_format(pinfo, item, &ei_invalid_range, "Invalid new data indication value [0..1]");
	}

	// HARQ process
	item = ptvcursor_add_ret_uint(ptvc, hf_nfapi_harq_process, 1, ENC_BIG_ENDIAN, &test_value);
	if (test_value > 7)
	{
		expert_add_info_format(pinfo, item, &ei_invalid_range, "Invalid harq process value [0..7]");
	}

	// Redundancy version
	item = ptvcursor_add_ret_uint(ptvc, hf_nfapi_redundancy_version, 1, ENC_BIG_ENDIAN, &test_value);
	if (test_value > 3)
	{
		expert_add_info_format(pinfo, item, &ei_invalid_range, "Invalid redundancy version value [0..3]");
	}

	// TPC
	item = ptvcursor_add_ret_uint(ptvc, hf_nfapi_tpc, 1, ENC_BIG_ENDIAN, &test_value);
	if (test_value > 3)
	{
		expert_add_info_format(pinfo, item, &ei_invalid_range, "Invalid tpc value [0..3]");
	}

	// CSI request
	item = ptvcursor_add_ret_uint(ptvc, hf_nfapi_csi_request, 1, ENC_BIG_ENDIAN, &test_value);
	if (test_value > 1)
	{
		expert_add_info_format(pinfo, item, &ei_invalid_range, "Invalid csi request value [0..1]");
	}

	// UL index
	item = ptvcursor_add_ret_uint(ptvc, hf_nfapi_ul_index, 1, ENC_BIG_ENDIAN, &test_value);
	if (test_value > 3)
	{
		expert_add_info_format(pinfo, item, &ei_invalid_range, "Invalid ul Index value [0..3]");
	}

	// DAI presence flag
	item = ptvcursor_add_ret_boolean(ptvc, hf_nfapi_dai_presence_flag, 1, ENC_BIG_ENDIAN, &test_boolean);
	if (test_boolean > 1)
	{
		expert_add_info_format(pinfo, item, &ei_invalid_range, "Invalid dai presence value [0..1]");
	}

	// DL assignment index
	item = ptvcursor_add_ret_uint(ptvc, hf_nfapi_dl_assignment_index, 1, ENC_BIG_ENDIAN, &test_value);
	if (!(test_value >=1 && test_value <= 4))
	{
		expert_add_info_format(pinfo, item, &ei_invalid_range, "Invalid dl assignment value [1, 2, 3, 4]");
	}

	// SRS request
	item = ptvcursor_add_ret_boolean(ptvc, hf_nfapi_srs_request, 1, ENC_BIG_ENDIAN, &test_boolean);
	if (test_boolean > 1)
	{
		expert_add_info_format(pinfo, item, &ei_invalid_range, "Invalid srs request value [0..1]");
	}

	// DCI subframe repetition number
	item = ptvcursor_add_ret_uint(ptvc, hf_nfapi_dci_subframe_repetition_number, 1, ENC_BIG_ENDIAN, &test_value);
	if (!(test_value >= 1 && test_value <= 4))
	{
		expert_add_info_format(pinfo, item, &ei_invalid_range, "Invalid dci subframe repetition number value [1..4]");
	}

	//TPC bitmap
	ptvcursor_add(ptvc, hf_nfapi_tpc_bitmap, 4, ENC_BIG_ENDIAN);

	// Total DCI length including padding
	ptvcursor_add(ptvc, hf_nfapi_total_dci_length_include_padding, 1, ENC_BIG_ENDIAN);

	// Number of TX Antenna ports
	ptvcursor_add_ret_uint(ptvc, hf_nfapi_number_of_tx_antenna_ports, 1, ENC_BIG_ENDIAN, &count);

	dissect_array_value(ptvc, pinfo, "TX Antenna Ports", ett_nfapi_tx_antenna_ports, count, dissect_precoding_value);
}
static void dissect_rx_ue_info_value(ptvcursor_t * ptvc, packet_info* pinfo)
{
	guint32 test_value;

	// Handle
	ptvcursor_add(ptvc, hf_nfapi_handle, 4, ENC_BIG_ENDIAN);

	// RNTI
	proto_item* item = ptvcursor_add_ret_uint(ptvc, hf_nfapi_rnti, 2, ENC_BIG_ENDIAN, &test_value);
	if (test_value < 1)
	{
		expert_add_info_format(pinfo, item, &ei_invalid_range, "Invalid rnti value [1..65535]");
	}
}
static void dissect_rx_indication_rel8_value(ptvcursor_t * ptvc, packet_info* pinfo)
{
	proto_item* item;
	guint32 test_value;

	// Length
	ptvcursor_add(ptvc, hf_nfapi_length, 2, ENC_BIG_ENDIAN);

	// Data offset
	ptvcursor_add(ptvc, hf_nfapi_data_offset, 2, ENC_BIG_ENDIAN);

	// UL_CQI
	ptvcursor_add(ptvc, hf_nfapi_ul_cqi, 1, ENC_BIG_ENDIAN);

	// Timing advance
	item = ptvcursor_add_ret_uint(ptvc, hf_nfapi_timing_advance, 2, ENC_BIG_ENDIAN, &test_value);
	if (test_value > 63)
	{
		expert_add_info_format(pinfo, item, &ei_invalid_range, "Invalid timing advance value [0..63]");
	}
}
static void dissect_rx_indication_rel9_value(ptvcursor_t * ptvc, packet_info* pinfo)
{
	guint32 test_value;

	// Timing advance R9
	proto_item* item = ptvcursor_add_ret_uint(ptvc, hf_nfapi_timing_advance_r9, 2, ENC_BIG_ENDIAN, &test_value);
	if (test_value > 7690)
	{
		expert_add_info_format(pinfo, item, &ei_invalid_range, "Invalid timing advance r9 value [0..7690]");
	}

}
static void dissect_harq_indication_data_bundling_value(ptvcursor_t * ptvc, packet_info* pinfo)
{
	proto_item* item;
	guint32 test_value;

	item = ptvcursor_add_ret_uint(ptvc, hf_nfapi_harq_data_value_0, 1, ENC_BIG_ENDIAN, &test_value);
	if (!(test_value >= 1 && test_value <= 7))
	{
		expert_add_info_format(pinfo, item, &ei_invalid_range, "Invalid value 0 [1..7]");
	}

	item = ptvcursor_add_ret_uint(ptvc, hf_nfapi_harq_data_value_1, 1, ENC_BIG_ENDIAN, &test_value);
	if (!(test_value >= 1 && test_value <= 7))
	{
		expert_add_info_format(pinfo, item, &ei_invalid_range, "Invalid value 1 [1..7]");
	}
}
static void dissect_harq_indication_data_format_1a_1b_bundling_value(ptvcursor_t * ptvc, packet_info* pinfo)
{
	guint32 test_value;

	proto_item* item = ptvcursor_add_ret_uint(ptvc, hf_nfapi_harq_data_value_0, 1, ENC_BIG_ENDIAN, &test_value);
	if (!(test_value >= 1 && test_value <= 7))
	{
		expert_add_info_format(pinfo, item, &ei_invalid_range, "Invalid value 0 [1..7]");
	}
}
static void dissect_harq_indication_data_multplexing_value(ptvcursor_t * ptvc, packet_info* pinfo)
{
	proto_item* item;
	guint32 test_value;

	item = ptvcursor_add_ret_uint(ptvc, hf_nfapi_harq_data_value_0, 1, ENC_BIG_ENDIAN, &test_value);
	if (!(test_value >= 1 && test_value <= 7))
	{
		expert_add_info_format(pinfo, item, &ei_invalid_range, "Invalid value 0 [1..7]");
	}

	item = ptvcursor_add_ret_uint(ptvc, hf_nfapi_harq_data_value_1, 1, ENC_BIG_ENDIAN, &test_value);
	if (!(test_value >= 1 && test_value <= 7))
	{
		expert_add_info_format(pinfo, item, &ei_invalid_range, "Invalid value 1 [1..7]");
	}

	item = ptvcursor_add_ret_uint(ptvc, hf_nfapi_harq_data_value_2, 1, ENC_BIG_ENDIAN, &test_value);
	if (!(test_value >= 1 && test_value <= 7))
	{
		expert_add_info_format(pinfo, item, &ei_invalid_range, "Invalid value 2 [1..7]");
	}

	item = ptvcursor_add_ret_uint(ptvc, hf_nfapi_harq_data_value_3, 1, ENC_BIG_ENDIAN, &test_value);
	if (!(test_value >= 1 && test_value <= 7))
	{
		expert_add_info_format(pinfo, item, &ei_invalid_range, "Invalid value 3 [1..7]");
	}

}
static void dissect_harq_indication_data_format_1a_1b_multplexing_value(ptvcursor_t * ptvc, packet_info* pinfo)
{
	guint32 test_value;
	proto_item* item = ptvcursor_add_ret_uint(ptvc, hf_nfapi_harq_data_value_0, 1, ENC_BIG_ENDIAN, &test_value);
	if (!(test_value >= 1 && test_value <= 7))
	{
		expert_add_info_format(pinfo, item, &ei_invalid_range, "Invalid value 0 [1..7]");
	}
}
static void dissect_harq_indication_data_special_bundling_value(ptvcursor_t * ptvc, packet_info* pinfo)
{
	guint32 test_value;
	proto_item* item = ptvcursor_add_ret_uint(ptvc, hf_nfapi_harq_data_value_0_special, 1, ENC_BIG_ENDIAN, &test_value);

	if (test_value > 4)
	{
		expert_add_info_format(pinfo, item, &ei_invalid_range, "Invalid value 0 [0..4]");
	}
}
static void dissect_harq_indication_data_format_1a_1b_special_bundling_value(ptvcursor_t * ptvc, packet_info* pinfo)
{
	guint32 test_value;
	proto_item* item = ptvcursor_add_ret_uint(ptvc, hf_nfapi_harq_data_value_0_special, 1, ENC_BIG_ENDIAN, &test_value);
	if (test_value > 4)
	{
		expert_add_info_format(pinfo, item, &ei_invalid_range, "Invalid value 0 [0..4]");
	}
}
static void dissect_harq_indication_data_channel_selection_value(ptvcursor_t * ptvc, packet_info* pinfo)
{
	guint32 test_value;
	proto_item* item = ptvcursor_add_ret_uint(ptvc, hf_nfapi_harq_data_value_0, 1, ENC_BIG_ENDIAN, &test_value);
	if (!(test_value >= 1 && test_value <= 7))
	{
		expert_add_info_format(pinfo, item, &ei_invalid_range, "Invalid value 0 [1..7]");
	}
}
static void dissect_harq_indication_data_format_3_value(ptvcursor_t * ptvc, packet_info* pinfo)
{
	guint32 test_value;
	proto_item* item = ptvcursor_add_ret_uint(ptvc, hf_nfapi_harq_data_value_0, 1, ENC_BIG_ENDIAN, &test_value);
	if (!(test_value >= 1 && test_value <= 7))
	{
		expert_add_info_format(pinfo, item, &ei_invalid_range, "Invalid value 0 [1..7]");
	}
}
static void dissect_harq_indication_data_format_4_value(ptvcursor_t * ptvc, packet_info* pinfo)
{
	guint32 test_value;
	proto_item* item = ptvcursor_add_ret_uint(ptvc, hf_nfapi_harq_data_value_0, 1, ENC_BIG_ENDIAN, &test_value);
	if (!(test_value >= 1 && test_value <= 7))
	{
		expert_add_info_format(pinfo, item, &ei_invalid_range, "Invalid value 0 [1..7]");
	}
}
static void dissect_harq_indication_data_format_5_value(ptvcursor_t * ptvc, packet_info* pinfo)
{
	guint32 test_value;
	proto_item* item = ptvcursor_add_ret_uint(ptvc, hf_nfapi_harq_data_value_0, 1, ENC_BIG_ENDIAN, &test_value);
	if (!(test_value >= 1 && test_value <= 7))
	{
		expert_add_info_format(pinfo, item, &ei_invalid_range, "Invalid value 0 [1..7]");
	}
}
static void dissect_harq_indication_rel8_tdd_value(ptvcursor_t * ptvc, packet_info* pinfo)
{
	proto_item* item;
	guint32 test_value, mode;

	item = ptvcursor_add_ret_uint(ptvc, hf_nfapi_tdd_harq_mode, 1, ENC_BIG_ENDIAN, &mode);
	if (mode > 4)
	{
		expert_add_info_format(pinfo, item, &ei_invalid_range, "Invalid mode value [0..4]");
	}

	item = ptvcursor_add_ret_uint(ptvc, hf_nfapi_number_of_ack_nack, 1, ENC_BIG_ENDIAN, &test_value);
	if (!(test_value >= 1 && test_value <= 4))
	{
		expert_add_info_format(pinfo, item, &ei_invalid_range, "Invalid number of ack nack value [1..4]");
	}

	switch (mode)
	{
		case 0:
		{
			dissect_harq_indication_data_bundling_value(ptvc, pinfo);
			break;
		}
		case 1:
		{
			dissect_harq_indication_data_multplexing_value(ptvc, pinfo);
			break;
		}
		case 2:
		{
			dissect_harq_indication_data_special_bundling_value(ptvc, pinfo);
			break;
		}
	};
}
static void dissect_harq_indication_rel9_later_tdd_value(ptvcursor_t * ptvc, packet_info* pinfo)
{
	proto_item* item;
	guint32 mode, i, count;

	item = ptvcursor_add_ret_uint(ptvc, hf_nfapi_tdd_harq_mode, 1, ENC_BIG_ENDIAN, &mode);
	if (mode > 4)
	{
		expert_add_info_format(pinfo, item, &ei_invalid_range, "Invalid mode value [0..4]");
	}

	item = ptvcursor_add_ret_uint(ptvc, hf_nfapi_number_of_ack_nack, 1, ENC_BIG_ENDIAN, &count);
	if (mode == 0 || mode == 1)
	{
		if (!(count >= 1 && count <= 4))
		{
			expert_add_info_format(pinfo, item, &ei_invalid_range, "Invalid number of ack nack value [1..4]");
		}
	}
	else if (mode == 3)
	{
		if (!(count >= 1 && count <= 8))
		{
			expert_add_info_format(pinfo, item, &ei_invalid_range, "Invalid number of ack nack value [1..8]");
		}
	}
	else if (mode == 4)
	{
		if (!(count >= 1 && count <= 21))
		{
			expert_add_info_format(pinfo, item, &ei_invalid_range, "Invalid number of ack nack value [1..21]");
		}
	}


	ptvcursor_add_text_with_subtree(ptvc, SUBTREE_UNDEFINED_LENGTH, ett_nfapi_harq_ack_nack_data, "ACK/NACK Data");

	for (i = 0; i < count; ++i)
	{
		ptvcursor_add_text_with_subtree(ptvc, SUBTREE_UNDEFINED_LENGTH, ett_nfapi_harq_ack_nack_data, "[%u]", i);

		switch (mode)
		{
			case 0:
			{
				dissect_harq_indication_data_format_1a_1b_bundling_value(ptvc, pinfo);
				break;
			}
			case 1:
			{
				dissect_harq_indication_data_format_1a_1b_multplexing_value(ptvc, pinfo);
				break;
			}
			case 2:
			{
				dissect_harq_indication_data_format_1a_1b_special_bundling_value(ptvc, pinfo);
				break;
			}
			case 3:
			{
				dissect_harq_indication_data_channel_selection_value(ptvc, pinfo);
				break;
			}
			case 4:
			{
				dissect_harq_indication_data_format_3_value(ptvc, pinfo);
				break;
			}
		};

		ptvcursor_pop_subtree(ptvc);
	}

	ptvcursor_pop_subtree(ptvc);
}
static void dissect_harq_indication_rel13_later_tdd_value(ptvcursor_t * ptvc, packet_info* pinfo)
{
	proto_item* item;
	guint32 mode, i, count;

	item = ptvcursor_add_ret_uint(ptvc, hf_nfapi_tdd_harq_mode, 1, ENC_BIG_ENDIAN, &mode);
	if (mode > 6)
	{
		expert_add_info_format(pinfo, item, &ei_invalid_range, "Invalid mode value [0..6]");
	}

	ptvcursor_add_ret_uint(ptvc, hf_nfapi_number_of_ack_nack, 2, ENC_BIG_ENDIAN, &count);
	if (mode == 0 || mode == 1)
	{
		if (!(count >= 1 && count <= 4))
		{
			expert_add_info_format(pinfo, item, &ei_invalid_range, "Invalid number of ack nack value [1..4]");
		}
	}
	else if (mode == 3)
	{
		if (!(count >= 1 && count <= 8))
		{
			expert_add_info_format(pinfo, item, &ei_invalid_range, "Invalid number of ack nack value [1..8]");
		}
	}
	else if (mode == 4)
	{
		if (!(count >= 1 && count <= 21))
		{
			expert_add_info_format(pinfo, item, &ei_invalid_range, "Invalid number of ack nack value [1..21]");
		}
	}
	else if (mode == 5 || mode == 6)
	{
		if (count < 22)
		{
			expert_add_info_format(pinfo, item, &ei_invalid_range, "Invalid number of ack nack value [>= 22]");
		}

	}

	ptvcursor_add_text_with_subtree(ptvc, SUBTREE_UNDEFINED_LENGTH, ett_nfapi_harq_ack_nack_data, "ACK/NACK Data");

	for (i = 0; i < count; ++i)
	{
		ptvcursor_add_text_with_subtree(ptvc, SUBTREE_UNDEFINED_LENGTH, ett_nfapi_harq_ack_nack_data, "[%u]", i);

		switch (mode)
		{
			case 0:
			{
				dissect_harq_indication_data_format_1a_1b_bundling_value(ptvc, pinfo);
				break;
			}
			case 1:
			{
				dissect_harq_indication_data_format_1a_1b_multplexing_value(ptvc, pinfo);
				break;
			}
			case 2:
			{
				dissect_harq_indication_data_special_bundling_value(ptvc, pinfo);
				break;
			}
			case 3:
			{
				dissect_harq_indication_data_channel_selection_value(ptvc, pinfo);
				break;
			}
			case 4:
			{
				dissect_harq_indication_data_format_3_value(ptvc, pinfo);
				break;
			}
			case 5:
			{
				dissect_harq_indication_data_format_4_value(ptvc, pinfo);
				break;
			}
			case 6:
			{
				dissect_harq_indication_data_format_5_value(ptvc, pinfo);
				break;
			}
		};

		ptvcursor_pop_subtree(ptvc);
	}

	ptvcursor_pop_subtree(ptvc);
}
static void dissect_harq_indication_rel8_fdd_value(ptvcursor_t * ptvc, packet_info* pinfo)
{
	proto_item* item;
	guint32 test_value;

	item = ptvcursor_add_ret_uint(ptvc, hf_nfapi_harq_tb_1, 1, ENC_BIG_ENDIAN, &test_value);
	if (!(test_value >= 1 && test_value <= 7))
	{
		expert_add_info_format(pinfo, item, &ei_invalid_range, "Invalid harq tb 1 [1..7]");
	}

	item = ptvcursor_add_ret_uint(ptvc, hf_nfapi_harq_tb_2, 1, ENC_BIG_ENDIAN, &test_value);
	if (!(test_value >= 1 && test_value <= 7))
	{
		expert_add_info_format(pinfo, item, &ei_invalid_range, "Invalid harq tb 2 [1..7]");
	}

}
static void dissect_harq_tb_value(ptvcursor_t * ptvc, packet_info* pinfo)
{
	guint32 test_value;
	proto_item* item = ptvcursor_add_ret_uint(ptvc, hf_nfapi_harq_tb_n, 1, ENC_BIG_ENDIAN, &test_value);

	if (!(test_value >= 1 && test_value <= 7))
	{
		expert_add_info_format(pinfo, item, &ei_invalid_range, "Invalid harq tb n [1..7]");
	}
}
static void dissect_harq_indication_rel9_later_fdd_value(ptvcursor_t * ptvc, packet_info* pinfo)
{
	guint32 harq_mode_value, count;

	// Mode
	proto_item* item = ptvcursor_add_ret_uint(ptvc, hf_nfapi_fdd_harq_mode, 1, ENC_BIG_ENDIAN, &harq_mode_value);
	if (harq_mode_value > 2)
	{
		expert_add_info_format(pinfo, item, &ei_invalid_range, "Invalid harq mode value [0..2]");
	}

	// Number of ACK/NACK
	item = ptvcursor_add_ret_uint(ptvc, hf_nfapi_number_of_ack_nack, 1, ENC_BIG_ENDIAN, &count);

	if (harq_mode_value == 0)
	{
		if (!(count >=1 && count <= 2))
		{
			expert_add_info_format(pinfo, item, &ei_invalid_range, "Invalid number of ack/nack value [1..2]");
		}
	}
	else if (harq_mode_value == 1)
	{
		if (!(count >= 1 && count <= 4))
		{
			expert_add_info_format(pinfo, item, &ei_invalid_range, "Invalid number of ack/nack value [1..4]");
		}

	}
	else if (harq_mode_value == 2)
	{
		if (!(count >= 1 && count <= 10))
		{
			expert_add_info_format(pinfo, item, &ei_invalid_range, "Invalid number of ack/nack value [1..10]");
		}

	}

	dissect_array_value(ptvc, pinfo, "HARQ TB List", ett_nfapi_harq_data, count, dissect_harq_tb_value);
}
static void dissect_harq_indication_rel13_later_fdd_value(ptvcursor_t * ptvc, packet_info* pinfo)
{
	guint32 harq_mode_value, count;

	// Mode
	proto_item* item = ptvcursor_add_ret_uint(ptvc, hf_nfapi_fdd_harq_mode, 1, ENC_BIG_ENDIAN, &harq_mode_value);
	if (harq_mode_value > 4)
	{
		expert_add_info_format(pinfo, item, &ei_invalid_range, "Invalid harq mode value [0..4]");
	}

	// Number of ACK/NACK
	item = ptvcursor_add_ret_uint(ptvc, hf_nfapi_number_of_ack_nack, 2, ENC_BIG_ENDIAN, &count);

	if (harq_mode_value == 0)
	{
		if (!(count >= 1 && count <= 2))
		{
			expert_add_info_format(pinfo, item, &ei_invalid_range, "Invalid number of ack/nack value [1..2]");
		}
	}
	else if (harq_mode_value == 1)
	{
		if (!(count >= 1 && count <= 4))
		{
			expert_add_info_format(pinfo, item, &ei_invalid_range, "Invalid number of ack/nack value [1..4]");
		}

	}
	else if (harq_mode_value == 2)
	{
		if (!(count >= 1 && count <= 10))
		{
			expert_add_info_format(pinfo, item, &ei_invalid_range, "Invalid number of ack/nack value [1..10]");
		}
	}
	else if (harq_mode_value == 3 || harq_mode_value == 4)
	{
		if (count < 22)
		{
			expert_add_info_format(pinfo, item, &ei_invalid_range, "Invalid number of ack/nack value [>= 22]");
		}
	}

	dissect_array_value(ptvc, pinfo, "HARQ TB List", ett_nfapi_harq_data, count, dissect_harq_tb_value);
}
static void dissect_ul_cqi_information_value(ptvcursor_t * ptvc, packet_info* pinfo)
{
	proto_item* item;
	guint32 test_value;

	// UL_CQI
	ptvcursor_add(ptvc, hf_nfapi_ul_cqi, 1, ENC_BIG_ENDIAN);

	// Channel
	item = ptvcursor_add_ret_uint(ptvc, hf_nfapi_channel, 1, ENC_BIG_ENDIAN, &test_value);
	if (test_value > 1)
	{
		expert_add_info_format(pinfo, item, &ei_invalid_range, "Invalid channel value [0..1]");
	}
}
static void dissect_crc_indication_rel8_value(ptvcursor_t * ptvc, packet_info* pinfo)
{
	gboolean test_boolean;

	// CRC Flag
	proto_item* item = ptvcursor_add_ret_boolean(ptvc, hf_nfapi_crc_flag, 1, ENC_BIG_ENDIAN, &test_boolean);
	if (test_boolean > 1)
	{
		expert_add_info_format(pinfo, item, &ei_invalid_range, "Invalid crc flag value [0..1]");
	}
}
static void dissect_rx_cqi_indication_rel8_value(ptvcursor_t * ptvc, packet_info* pinfo)
{
	proto_item* item;
	guint32 test_value;

	//Length
	ptvcursor_add(ptvc, hf_nfapi_length, 2, ENC_BIG_ENDIAN);

	// Data Offset
	ptvcursor_add(ptvc, hf_nfapi_data_offset, 2, ENC_BIG_ENDIAN);

	// UL_CQI
	ptvcursor_add(ptvc, hf_nfapi_ul_cqi, 1, ENC_BIG_ENDIAN);

	// RI
	item = ptvcursor_add_ret_uint(ptvc, hf_nfapi_ri, 1, ENC_BIG_ENDIAN, &test_value);
	if (test_value > 8)
	{
		expert_add_info_format(pinfo, item, &ei_invalid_range, "Invalid ri value [0..8]");
	}

	// Timing Advance
	item = ptvcursor_add_ret_uint(ptvc, hf_nfapi_timing_advance, 2, ENC_BIG_ENDIAN, &test_value);
	if (test_value > 63)
	{
		expert_add_info_format(pinfo, item, &ei_invalid_range, "Invalid timing advance value [0..63]");
	}
}
static void dissect_ri_value(ptvcursor_t * ptvc, packet_info* pinfo)
{
	guint32 test_value;

	// RI
	proto_item* item = ptvcursor_add_ret_uint(ptvc, hf_nfapi_ri, 1, ENC_BIG_ENDIAN, &test_value);
	if (test_value > 8)
	{
		expert_add_info_format(pinfo, item, &ei_invalid_range, "Invalid ri value [0..8]");
	}
}
static void dissect_rx_cqi_indication_rel9_value(ptvcursor_t * ptvc, packet_info* pinfo)
{
	proto_item* item;
	guint32 test_value, count;

	// Length
	ptvcursor_add(ptvc, hf_nfapi_length, 2, ENC_BIG_ENDIAN);

	// Data Offset
	ptvcursor_add(ptvc, hf_nfapi_data_offset, 2, ENC_BIG_ENDIAN);

	// UL_CQI
	ptvcursor_add(ptvc, hf_nfapi_ul_cqi, 1, ENC_BIG_ENDIAN);

	// Number of CC reported
	item = ptvcursor_add_ret_uint(ptvc, hf_nfapi_number_of_cc_reported, 1, ENC_BIG_ENDIAN, &count);
	if (!(count >= 1 && count <= 5))
	{
		expert_add_info_format(pinfo, item, &ei_invalid_range, "Invalid number of CC reported value [1..5]");
	}

	dissect_array_value(ptvc, pinfo, "CC List", ett_nfapi_cc, count, dissect_ri_value);

	// Timing Advance
	item = ptvcursor_add_ret_uint(ptvc, hf_nfapi_timing_advance, 2, ENC_BIG_ENDIAN, &test_value);
	if (test_value > 63)
	{
		expert_add_info_format(pinfo, item, &ei_invalid_range, "Invalid timing advance value [0..63]");
	}

	// Timing Advance R9
	item = ptvcursor_add_ret_uint(ptvc, hf_nfapi_timing_advance_r9, 2, ENC_BIG_ENDIAN, &test_value);
	if (test_value > 7690)
	{
		expert_add_info_format(pinfo, item, &ei_invalid_range, "Invalid timing advance value [0..7690]");
	}
}
static void dissect_rach_indication_rel8_value(ptvcursor_t * ptvc, packet_info* pinfo)
{
	proto_item* item;
	guint32 test_value;

	// RNTI
	item = ptvcursor_add_ret_uint(ptvc, hf_nfapi_rnti, 2, ENC_BIG_ENDIAN, &test_value);
	if (test_value < 1)
	{
		expert_add_info_format(pinfo, item, &ei_invalid_range, "Invalid rnti value [1..65535]");
	}

	// Preamble
	item = ptvcursor_add_ret_uint(ptvc, hf_nfapi_preamble, 1, ENC_BIG_ENDIAN, &test_value);
	if (test_value > 63)
	{
		expert_add_info_format(pinfo, item, &ei_invalid_range, "Invalid preamble value [0..63]");
	}

	// Timing Advance
	item = ptvcursor_add_ret_uint(ptvc, hf_nfapi_timing_advance, 2, ENC_BIG_ENDIAN, &test_value);
	if (test_value > 1282)
	{
		expert_add_info_format(pinfo, item, &ei_invalid_range, "Invalid timing advance value [0..1282]");
	}

}
static void dissect_rach_indication_rel9_value(ptvcursor_t * ptvc, packet_info* pinfo)
{
	guint32 test_value;

	// Timing Advance R9
	proto_item* item = ptvcursor_add_ret_uint(ptvc, hf_nfapi_timing_advance_r9, 2, ENC_BIG_ENDIAN, &test_value);
	if (test_value > 7690)
	{
		expert_add_info_format(pinfo, item, &ei_invalid_range, "Invalid timing advance value [0..7690]");
	}
}
static void dissect_rach_indication_rel13_value(ptvcursor_t * ptvc, packet_info* pinfo)
{
	guint32 test_value;

	// RACH resource type
	proto_item* item = ptvcursor_add_ret_uint(ptvc, hf_nfapi_rach_resource_type, 1, ENC_BIG_ENDIAN, &test_value);
	if (test_value > 4)
	{
		expert_add_info_format(pinfo, item, &ei_invalid_range, "Invalid rach resource type value [0..4]");
	}
}
static void dissect_snr_value(ptvcursor_t * ptvc, packet_info* pinfo _U_)
{
	// SNR
	ptvcursor_add(ptvc, hf_nfapi_snr, 1, ENC_BIG_ENDIAN);
}
static void dissect_srs_indication_rel8_value(ptvcursor_t * ptvc, packet_info* pinfo)
{
	proto_item* item;
	guint32 test_value, count;

	// Doppler estimation
	ptvcursor_add(ptvc, hf_nfapi_doppler_estimation, 2, ENC_BIG_ENDIAN);

	// Timing Advance
	item = ptvcursor_add_ret_uint(ptvc, hf_nfapi_timing_advance, 2, ENC_BIG_ENDIAN, &test_value);
	if (test_value > 1282)
	{
		expert_add_info_format(pinfo, item, &ei_invalid_range, "Invalid timing advance value [0..1282]");
	}

	// Number of resource blocks
	ptvcursor_add_ret_uint(ptvc, hf_nfapi_number_of_resource_blocks, 1, ENC_BIG_ENDIAN, &count);

	// RB start
	ptvcursor_add(ptvc, hf_nfapi_rb_start, 1, ENC_BIG_ENDIAN);


	dissect_array_value(ptvc, pinfo, "RB List", ett_nfapi_rbs, count, dissect_snr_value);
}
static void dissect_srs_indication_rel9_value(ptvcursor_t * ptvc, packet_info* pinfo)
{
	guint32 test_value;

	// Timing Advance R9
	proto_item* item = ptvcursor_add_ret_uint(ptvc, hf_nfapi_timing_advance_r9, 2, ENC_BIG_ENDIAN, &test_value);
	if (test_value > 7690)
	{
		expert_add_info_format(pinfo, item, &ei_invalid_range, "Invalid timing advance value [0..7690]");
	}
}
static void dissect_srs_indication_rel10_tdd_value(ptvcursor_t * ptvc, packet_info* pinfo)
{
	guint32 test_value;

	// UpPTS Symbol
	proto_item* item = ptvcursor_add_ret_uint(ptvc, hf_nfapi_up_pts_symbol, 1, ENC_BIG_ENDIAN, &test_value);
	if (test_value > 1)
	{
		expert_add_info_format(pinfo, item, &ei_invalid_range, "Invalid up pts symbol value [0..1]");
	}

}
static void dissect_tdd_channel_measurement_value(ptvcursor_t * ptvc, packet_info* pinfo _U_)
{
	guint32 i, j, num_subbands, num_phy_ant;

	// numPRBperSubband
	ptvcursor_add(ptvc, hf_nfapi_number_prb_per_subband, 1, ENC_BIG_ENDIAN);

	// Number of subbands
	ptvcursor_add_ret_uint(ptvc, hf_nfapi_number_of_subbands, 1, ENC_BIG_ENDIAN, &num_subbands);

	// numAntennas
	ptvcursor_add_ret_uint(ptvc, hf_nfapi_number_antennas, 1, ENC_BIG_ENDIAN, &num_phy_ant);

	ptvcursor_add_text_with_subtree(ptvc, SUBTREE_UNDEFINED_LENGTH, ett_nfapi_subbands, "Subbands");

	for (i = 0; i < num_subbands; ++i)
	{
		ptvcursor_add_text_with_subtree(ptvc, SUBTREE_UNDEFINED_LENGTH, ett_nfapi_subbands, "[%u]", i);

		// subbandIndex
		ptvcursor_add(ptvc, hf_nfapi_subband_index, 1, ENC_BIG_ENDIAN);

		ptvcursor_add_text_with_subtree(ptvc, SUBTREE_UNDEFINED_LENGTH, ett_nfapi_antennas, "Physical Antennas");

		for (j = 0; j < num_phy_ant; ++j)
		{
			ptvcursor_add_text_with_subtree(ptvc, SUBTREE_UNDEFINED_LENGTH, ett_nfapi_antennas, "[%u]", j);

			// Channel
			ptvcursor_add(ptvc, hf_nfapi_channel_coefficient, 2, ENC_BIG_ENDIAN);

			ptvcursor_pop_subtree(ptvc);
		}

		ptvcursor_pop_subtree(ptvc);

		ptvcursor_pop_subtree(ptvc);
	}

	ptvcursor_pop_subtree(ptvc);
}
static void dissect_srs_indication_rel11_value(ptvcursor_t * ptvc, packet_info* pinfo)
{
	guint32 test_value;

	//UL_RTOA
	proto_item* item = ptvcursor_add_ret_uint(ptvc, hf_nfapi_ul_rtoa, 2, ENC_BIG_ENDIAN, &test_value);
	if (test_value > 4800)
	{
		expert_add_info_format(pinfo, item, &ei_invalid_range, "Invalid ul rtoa value [0..4800]");
	}
}
static void dissect_lbt_dl_config_request_pdsch_req_rel13_value(ptvcursor_t * ptvc, packet_info* pinfo)
{
	proto_item* item;
	guint32 test_value;
	gint32 test_boolean;

	// Handle
	ptvcursor_add(ptvc, hf_nfapi_handle, 4, ENC_BIG_ENDIAN);

	// nCCA
	ptvcursor_add(ptvc, hf_nfapi_mp_cca, 4, ENC_BIG_ENDIAN);

	// NCCA
	ptvcursor_add(ptvc, hf_nfapi_n_cca, 4, ENC_BIG_ENDIAN);

	// Offset
	item = ptvcursor_add_ret_uint(ptvc, hf_nfapi_offset, 4, ENC_BIG_ENDIAN, &test_value);
	if (test_value > 999)
	{
		expert_add_info_format(pinfo, item, &ei_invalid_range, "Invalid offset value [0..999]");
	}

	// LTE TXOP SF
	ptvcursor_add(ptvc, hf_nfapi_lte_txop_sf, 4, ENC_BIG_ENDIAN);

	// TXOP SFN/SF End
	ptvcursor_add(ptvc, hf_nfapi_txop_sfn_sf_end, 2, ENC_BIG_ENDIAN);

	// LBT mode
	item = ptvcursor_add_ret_boolean(ptvc, hf_nfapi_lbt_mode, 4, ENC_BIG_ENDIAN, &test_boolean);
	if (test_boolean > 1)
	{
		expert_add_info_format(pinfo, item, &ei_invalid_range, "Invalid offset value [0..1]");
	}
}
static void dissect_lbt_dl_config_request_drs_req_rel13_value(ptvcursor_t * ptvc, packet_info* pinfo)
{
	proto_item* item;
	guint32 test_value;
	gint32 test_boolean;

	// Handle
	ptvcursor_add(ptvc, hf_nfapi_handle, 4, ENC_BIG_ENDIAN);

	// Offset
	item = ptvcursor_add_ret_uint(ptvc, hf_nfapi_offset, 4, ENC_BIG_ENDIAN, &test_value);
	if (test_value > 999)
	{
		expert_add_info_format(pinfo, item, &ei_invalid_range, "Invalid offset value [0..999]");
	}

	// SFN/SF End
	ptvcursor_add(ptvc, hf_nfapi_sfn_sf_end, 2, ENC_BIG_ENDIAN);

	// LBT mode
	item = ptvcursor_add_ret_boolean(ptvc, hf_nfapi_lbt_mode, 4, ENC_BIG_ENDIAN, &test_boolean);
	if (test_boolean > 1)
	{
		expert_add_info_format(pinfo, item, &ei_invalid_range, "Invalid offset value [0..1]");
	}
}
static void dissect_lbt_dl_config_request_pdsch_resp_rel13_value(ptvcursor_t * ptvc, packet_info* pinfo)
{
	proto_item* item;
	gint32 test_boolean;

	// Handle
	ptvcursor_add(ptvc, hf_nfapi_handle, 4, ENC_BIG_ENDIAN);

	// result
	item = ptvcursor_add_ret_boolean(ptvc, hf_nfapi_result, 4, ENC_BIG_ENDIAN, &test_boolean);
	if (test_boolean > 1)
	{
		expert_add_info_format(pinfo, item, &ei_invalid_range, "Invalid result value [0..1]");
	}

	// LTE TXOP symbols
	ptvcursor_add(ptvc, hf_nfapi_txop_symbols, 4, ENC_BIG_ENDIAN);

	// Initial Partial SF
	item = ptvcursor_add_ret_boolean(ptvc, hf_nfapi_initial_partial_sf, 4, ENC_BIG_ENDIAN, &test_boolean);
	if (test_boolean > 1)
	{
		expert_add_info_format(pinfo, item, &ei_invalid_range, "Invalid initial partial sf value [0..1]");
	}
}
static void dissect_lbt_dl_config_request_drs_resp_rel13_value(ptvcursor_t * ptvc, packet_info* pinfo)
{
	proto_item* item;
	gint32 test_boolean;

	// Handle
	ptvcursor_add(ptvc, hf_nfapi_handle, 4, ENC_BIG_ENDIAN);

	// result
	item = ptvcursor_add_ret_boolean(ptvc, hf_nfapi_result, 4, ENC_BIG_ENDIAN, &test_boolean);
	if (test_boolean > 1)
	{
		expert_add_info_format(pinfo, item, &ei_invalid_range, "Invalid result value [0..1]");
	}
}
static void dissect_tx_pdu(ptvcursor_t * ptvc, packet_info* pinfo _U_)
{
	guint32 len;

	// PDU length
	ptvcursor_add_ret_uint(ptvc, hf_nfapi_pdu_length, 2, ENC_BIG_ENDIAN, &len);

	// PDU index
	ptvcursor_add(ptvc, hf_nfapi_pdu_index, 2, ENC_BIG_ENDIAN);

	// PDU#N
	ptvcursor_add(ptvc, hf_nfapi_pdu, len, ENC_NA);
}
static void dissect_tx_request_body_value(ptvcursor_t * ptvc, packet_info* pinfo)
{
	guint32 num_pdu;

	// Number of PDUs
	ptvcursor_add_ret_uint(ptvc, hf_nfapi_number_pdus, 2, ENC_BIG_ENDIAN, &num_pdu);

	dissect_array_value(ptvc, pinfo, "TX PDU List", ett_nfapi_tx_request_pdu_list, num_pdu, dissect_tx_pdu);
}
static void dissect_harq_indication_pdu(ptvcursor_t * ptvc, packet_info* pinfo)
{
	guint32 instance_len;

	// Instance Length
	ptvcursor_add_ret_uint(ptvc, hf_nfapi_instance_length, 2, ENC_BIG_ENDIAN, &instance_len);

	guint32 instance_end = (ptvcursor_current_offset(ptvc) + instance_len - 2);
	dissect_tlv_list(ptvc, pinfo, instance_end);
}
static void dissect_harq_indication_body_value(ptvcursor_t * ptvc, packet_info* pinfo)
{
	guint32 num_pdu;

	// Number of HARQs
	ptvcursor_add_ret_uint(ptvc, hf_nfapi_number_of_harqs, 2, ENC_BIG_ENDIAN, &num_pdu);

	dissect_array_value(ptvc, pinfo, "HARQ PDU List", ett_nfapi_harq_indication_pdu_list, num_pdu, dissect_harq_indication_pdu);
}
static void dissect_crc_indication_pdu(ptvcursor_t * ptvc, packet_info* pinfo)
{
	guint32 instance_len;

	// Instance Length
	ptvcursor_add_ret_uint(ptvc, hf_nfapi_instance_length, 2, ENC_BIG_ENDIAN, &instance_len);

	guint32 instance_end = (ptvcursor_current_offset(ptvc) + instance_len - 2);
	dissect_tlv_list(ptvc, pinfo, instance_end);
}
static void dissect_crc_indication_body_value(ptvcursor_t * ptvc, packet_info* pinfo)
{
	guint32 num_pdu;

	// Number of CRCs
	ptvcursor_add_ret_uint(ptvc, hf_nfapi_number_of_crcs, 2, ENC_BIG_ENDIAN, &num_pdu);
	dissect_array_value(ptvc, pinfo, "CRC PDU List", ett_nfapi_crc_indication_pdu_list, num_pdu, dissect_crc_indication_pdu);
}
static void dissect_sr_indication_pdu(ptvcursor_t * ptvc, packet_info* pinfo)
{
	guint32 instance_len;

	// Instance Length
	ptvcursor_add_ret_uint(ptvc, hf_nfapi_instance_length, 2, ENC_BIG_ENDIAN, &instance_len);

	guint32 instance_end = (ptvcursor_current_offset(ptvc) + instance_len - 2);
	dissect_tlv_list(ptvc, pinfo, instance_end);
}
static void dissect_rx_sr_indication_body_value(ptvcursor_t * ptvc, packet_info* pinfo)
{
	guint32 num_pdu;

	// Number of SRs
	ptvcursor_add_ret_uint(ptvc, hf_nfapi_number_of_srs, 2, ENC_BIG_ENDIAN, &num_pdu);

	dissect_array_value(ptvc, pinfo, "SR PDU List", ett_nfapi_sr_indication_pdu_list, num_pdu, dissect_sr_indication_pdu);
}
static void dissect_cqi_indication_pdu(ptvcursor_t * ptvc, packet_info* pinfo)
{
	guint32 instance_len;

	// Instance Length
	ptvcursor_add_ret_uint(ptvc, hf_nfapi_instance_length, 2, ENC_BIG_ENDIAN, &instance_len);

	guint32 instance_end = (ptvcursor_current_offset(ptvc) + instance_len - 2);
	dissect_tlv_list(ptvc, pinfo, instance_end);
}
static void dissect_rx_cqi_indication_body_value(ptvcursor_t * ptvc, packet_info* pinfo)
{
	guint32 i, num_pdu;
	guint16* lengths = NULL;

	// Number of PDUs
	ptvcursor_add_ret_uint(ptvc, hf_nfapi_number_of_cqi, 2, ENC_BIG_ENDIAN, &num_pdu);


	tvbuff_t* tvb = ptvcursor_tvbuff(ptvc);
	guint32 tmp_offset = ptvcursor_current_offset(ptvc);

	if (num_pdu > 0)
	{
		lengths = (guint16*)wmem_alloc0(wmem_packet_scope(), num_pdu * 2);
	}

	for (i = 0; i < num_pdu; ++i)
	{
		guint32 instance_len = tvb_get_ntohs(tvb, tmp_offset);
		tmp_offset += 2;
		guint32 pdu_end = tmp_offset + instance_len;

		while (tmp_offset < pdu_end)
		{
			guint16 tlv_id = tvb_get_ntohs(tvb, tmp_offset);
			tmp_offset += 2;
			guint16 tlv_len = tvb_get_ntohs(tvb, tmp_offset);
			tmp_offset += 2;

			if (tlv_id == 0x202F)
			{
				lengths[i] = tvb_get_ntohs(tvb, tmp_offset);
			}
			else if (tlv_id == 0x2030)
			{
				lengths[i] = tvb_get_ntohs(tvb, tmp_offset);
			}

			tmp_offset += tlv_len;
		}
	}

	dissect_array_value(ptvc, pinfo, "CQI PDU List", ett_nfapi_cqi_indication_pdu_list, num_pdu, dissect_cqi_indication_pdu);

	for (i = 0; i < num_pdu; ++i)
	{
		ptvcursor_add(ptvc, hf_nfapi_pdu, lengths[i], ENC_NA);
	}
}
static void dissect_preamble_indication_pdu(ptvcursor_t * ptvc, packet_info* pinfo)
{
	guint32 instance_len;

	// Instance Length
	ptvcursor_add_ret_uint(ptvc, hf_nfapi_instance_length, 2, ENC_BIG_ENDIAN, &instance_len);

	guint32 instance_end = (ptvcursor_current_offset(ptvc) + instance_len - 2);
	dissect_tlv_list(ptvc, pinfo, instance_end);
}
static void dissect_rach_indication_body_value(ptvcursor_t * ptvc, packet_info* pinfo)
{
	guint32 num_pdu;

	// Number of Preambles
	ptvcursor_add_ret_uint(ptvc, hf_nfapi_number_of_preambles, 2, ENC_BIG_ENDIAN, &num_pdu);
	dissect_array_value(ptvc, pinfo, "Preamble PDU List", ett_nfapi_preamble_indication_pdu_list, num_pdu, dissect_preamble_indication_pdu);
}
static void dissect_srs_indication_pdu(ptvcursor_t * ptvc, packet_info* pinfo)
{
	guint32 instance_len;

	// Instance Length
	ptvcursor_add_ret_uint(ptvc, hf_nfapi_instance_length, 2, ENC_BIG_ENDIAN, &instance_len);
	guint32 instance_end = (ptvcursor_current_offset(ptvc) + instance_len - 2);
	dissect_tlv_list(ptvc, pinfo, instance_end);
}
static void dissect_srs_indication_body_value(ptvcursor_t * ptvc, packet_info* pinfo)
{
	guint32 num_pdu;

	// Number of UEs
	ptvcursor_add_ret_uint(ptvc, hf_nfapi_number_of_srss, 1, ENC_BIG_ENDIAN, &num_pdu);
	dissect_array_value(ptvc, pinfo, "SRS PDU List", ett_nfapi_srs_indication_pdu_list, num_pdu, dissect_srs_indication_pdu);
}
static void dissect_lbt_dl_config_pdu(ptvcursor_t * ptvc, packet_info* pinfo)
{
	guint32 test_value, size;

	// PDU Type
	proto_item* item = ptvcursor_add_ret_uint(ptvc, hf_nfapi_lbt_dl_req_pdu_type, 1, ENC_BIG_ENDIAN, &test_value);
	if (test_value > 1)
	{
		expert_add_info_format(pinfo, item, &ei_invalid_range, "Invalid pdu type value [0..1]");
	}

	ptvcursor_add_ret_uint(ptvc, hf_nfapi_pdu_size, 1, ENC_BIG_ENDIAN, &size);
	guint pdu_end = (ptvcursor_current_offset(ptvc) + size - 2);

	dissect_tlv_list(ptvc, pinfo, pdu_end);
}
static void dissect_lbt_dl_config_request_body_value(ptvcursor_t * ptvc, packet_info* pinfo)
{
	guint32 num_pdu;

	// Number of PDUs
	proto_item* item = ptvcursor_add_ret_uint(ptvc, hf_nfapi_number_pdus, 2, ENC_BIG_ENDIAN, &num_pdu);
	if (!(num_pdu >= 1 && num_pdu <= 2))
	{
		expert_add_info_format(pinfo, item, &ei_invalid_range, "Invalid number of pdus value [1..2]");
	}

	dissect_array_value(ptvc, pinfo, "LBT DL PDU List", ett_nfapi_lbt_dl_config_pdu_list, num_pdu, dissect_lbt_dl_config_pdu);
}
static void dissect_lbt_dl_indication_pdu(ptvcursor_t * ptvc, packet_info* pinfo)
{
	guint32 test_value, size;

	// PDU Type
	proto_item* item = ptvcursor_add_ret_uint(ptvc, hf_nfapi_lbt_dl_ind_pdu_type, 1, ENC_BIG_ENDIAN, &test_value);
	if (test_value > 1)
	{
		expert_add_info_format(pinfo, item, &ei_invalid_range, "Invalid pdu type value [0..1]");
	}

	// PDU Size
	ptvcursor_add_ret_uint(ptvc, hf_nfapi_pdu_size, 1, ENC_BIG_ENDIAN, &size);
	guint32 pdu_end = (ptvcursor_current_offset(ptvc) + size - 2);
	dissect_tlv_list(ptvc, pinfo, pdu_end);
}
static void dissect_lbt_indication_message_body_value(ptvcursor_t * ptvc, packet_info* pinfo)
{
	guint32 num_pdu;

	// Number of PDUs
	proto_item* item = ptvcursor_add_ret_uint(ptvc, hf_nfapi_number_pdus, 2, ENC_BIG_ENDIAN, &num_pdu);
	if (!(num_pdu >= 1 && num_pdu <= 2))
	{
		expert_add_info_format(pinfo, item, &ei_invalid_range, "Invalid number of pdus value [1..2]");
	}

	dissect_array_value(ptvc, pinfo, "LBT DL PDU List", ett_nfapi_lbt_dl_indication_pdu_list, num_pdu, dissect_lbt_dl_indication_pdu);
}
static void dissect_lte_rssi_request_value(ptvcursor_t * ptvc, packet_info* pinfo)
{
	guint32 test_value, num_earfcns;

	// Frequency Band Indicator
	ptvcursor_add(ptvc, hf_nfapi_frequency_band_indicator, 1, ENC_BIG_ENDIAN);

	// Measurement Period
	ptvcursor_add(ptvc, hf_nfapi_measurement_period, 2, ENC_BIG_ENDIAN);

	// Bandwidth
	proto_item* item = ptvcursor_add_ret_uint(ptvc, hf_nfapi_bandwidth, 1, ENC_BIG_ENDIAN, &test_value);
	if (!(test_value == 6 || test_value == 15 || test_value == 25 ||
		test_value == 50 || test_value == 75 || test_value == 100))
	{
		expert_add_info_format(pinfo, item, &ei_invalid_range, "Invalid bandwidth value [6, 15, 25, 50, 75, 100]");
	}

	// Timeout
	ptvcursor_add(ptvc, hf_nfapi_timeout, 4, ENC_BIG_ENDIAN);

	// Number of EARFCNs
	ptvcursor_add_ret_uint(ptvc, hf_nfapi_number_of_earfcns, 1, ENC_BIG_ENDIAN, &num_earfcns);

	dissect_array_value(ptvc, pinfo, "EARFCNs", ett_nfapi_earfcn_list, num_earfcns, dissect_earfcn_value);
}
static void dissect_uarfcn_value(ptvcursor_t * ptvc, packet_info* pinfo _U_)
{
	// UARFCN
	ptvcursor_add(ptvc, hf_nfapi_uarfcn, 2, ENC_BIG_ENDIAN);
}
static void dissect_utran_rssi_request_value(ptvcursor_t * ptvc, packet_info* pinfo)
{
	guint32 num_uarfcns;

	// Frequency Band Indicator
	ptvcursor_add(ptvc, hf_nfapi_frequency_band_indicator, 1, ENC_BIG_ENDIAN);

	// Measurement Period
	ptvcursor_add(ptvc, hf_nfapi_measurement_period, 2, ENC_BIG_ENDIAN);

	// Timeout
	ptvcursor_add(ptvc, hf_nfapi_timeout, 4, ENC_BIG_ENDIAN);

	// Number of UARFCNs
	ptvcursor_add_ret_uint(ptvc, hf_nfapi_number_of_uarfcns, 1, ENC_BIG_ENDIAN, &num_uarfcns);

	dissect_array_value(ptvc, pinfo, "UARFCNs", ett_nfapi_uarfcn_list, num_uarfcns, dissect_uarfcn_value);
}
static void dissect_arfcn_dir_value(ptvcursor_t * ptvc, packet_info* pinfo)
{
	guint32 test_value;

	// ARFCN
	ptvcursor_add(ptvc, hf_nfapi_arfcn, 2, ENC_BIG_ENDIAN);

	// Direction
	proto_item* item = ptvcursor_add_ret_uint(ptvc, hf_nfapi_arfcn_direction, 1, ENC_BIG_ENDIAN, &test_value);
	if (test_value > 1)
	{
		expert_add_info_format(pinfo, item, &ei_invalid_range, "Invalid direction value [0..1]");
	}

}
static void dissect_geran_rssi_request_value(ptvcursor_t * ptvc, packet_info* pinfo)
{
	guint32 num_arfcns;

	// Frequency Band Indicator
	ptvcursor_add(ptvc, hf_nfapi_frequency_band_indicator, 1, ENC_BIG_ENDIAN);

	// Measurement Period
	ptvcursor_add(ptvc, hf_nfapi_measurement_period, 2, ENC_BIG_ENDIAN);

	// Timeout
	ptvcursor_add(ptvc, hf_nfapi_timeout, 4, ENC_BIG_ENDIAN);

	// Number of ARFCNs
	ptvcursor_add_ret_uint(ptvc, hf_nfapi_number_of_arfcns, 1, ENC_BIG_ENDIAN, &num_arfcns);

	dissect_array_value(ptvc, pinfo, "ARFCNs", ett_nfapi_arfcn_list, num_arfcns, dissect_arfcn_dir_value);
}
static void dissect_rssi_value(ptvcursor_t * ptvc, packet_info* pinfo _U_)
{
	// RSSI
	ptvcursor_add(ptvc, hf_nfapi_rssi, 2, ENC_BIG_ENDIAN);
}
static void dissect_rssi_indication_value(ptvcursor_t * ptvc, packet_info* pinfo)
{
	guint32 num_rssi;

	// Number of RSSI
	ptvcursor_add_ret_uint(ptvc, hf_nfapi_number_of_rssi, 2, ENC_BIG_ENDIAN, &num_rssi);

	dissect_array_value(ptvc, pinfo, "ARFCNs", ett_nfapi_rssi_list, num_rssi, dissect_rssi_value);
}
static void dissect_pci_value(ptvcursor_t * ptvc, packet_info* pinfo _U_)
{
	// PCI
	ptvcursor_add(ptvc, hf_nfapi_pci, 2, ENC_BIG_ENDIAN);
}
static void dissect_lte_cell_search_value(ptvcursor_t * ptvc, packet_info* pinfo)
{
	guint32 num_pci;

	// EARFCN
	ptvcursor_add(ptvc, hf_nfapi_earfcn, 2, ENC_BIG_ENDIAN);

	// Measurement Bandwidth
	ptvcursor_add(ptvc, hf_nfapi_measurement_bandwidth, 1, ENC_BIG_ENDIAN);

	// Exhaustive Search
	ptvcursor_add(ptvc, hf_nfapi_exhaustive_search, 1, ENC_BIG_ENDIAN);

	// Timeout
	ptvcursor_add(ptvc, hf_nfapi_timeout, 4, ENC_BIG_ENDIAN);

	// Number of PCI
	ptvcursor_add_ret_uint(ptvc, hf_nfapi_number_of_pci, 1, ENC_BIG_ENDIAN, &num_pci);

	dissect_array_value(ptvc, pinfo, "PCIs", ett_nfapi_pci_list, num_pci, dissect_pci_value);
}
static void dissect_psc_value(ptvcursor_t * ptvc, packet_info* pinfo _U_)
{
	// PSC
	ptvcursor_add(ptvc, hf_nfapi_psc, 2, ENC_BIG_ENDIAN);
}
static void dissect_utran_cell_search_value(ptvcursor_t * ptvc, packet_info* pinfo)
{
	guint32 num_psc;

	// UARFCN
	ptvcursor_add(ptvc, hf_nfapi_uarfcn, 2, ENC_BIG_ENDIAN);

	// Exhaustive Search
	ptvcursor_add(ptvc, hf_nfapi_exhaustive_search, 1, ENC_BIG_ENDIAN);

	// Timeout
	ptvcursor_add(ptvc, hf_nfapi_timeout, 4, ENC_BIG_ENDIAN);

	// Number of PSC
	ptvcursor_add_ret_uint(ptvc, hf_nfapi_number_of_psc, 1, ENC_BIG_ENDIAN, &num_psc);

	dissect_array_value(ptvc, pinfo, "PSCs", ett_nfapi_psc_list, num_psc, dissect_psc_value);
}
static void dissect_arfcn_value(ptvcursor_t * ptvc, packet_info* pinfo _U_)
{
	// ARFCN
	ptvcursor_add(ptvc, hf_nfapi_arfcn, 2, ENC_BIG_ENDIAN);
}
static void dissect_geran_cell_search_value(ptvcursor_t * ptvc, packet_info* pinfo)
{
	guint32 num_arfcn;

	// Timeout
	ptvcursor_add(ptvc, hf_nfapi_timeout, 4, ENC_BIG_ENDIAN);

	// Number of ARFCN
	ptvcursor_add_ret_uint(ptvc, hf_nfapi_number_of_arfcns, 1, ENC_BIG_ENDIAN, &num_arfcn);

	dissect_array_value(ptvc, pinfo, "ARFCNs", ett_nfapi_arfcn_list, num_arfcn, dissect_arfcn_value);
}

static void dissect_lte_cell_found_value(ptvcursor_t * ptvc, packet_info* pinfo _U_)
{
	// PCI
	ptvcursor_add(ptvc, hf_nfapi_pci, 2, ENC_BIG_ENDIAN);

	// RSRP
	ptvcursor_add(ptvc, hf_nfapi_rsrp, 1, ENC_BIG_ENDIAN);

	// RSRQ
	ptvcursor_add(ptvc, hf_nfapi_rsrq, 1, ENC_BIG_ENDIAN);

	// Frequency Offset
	ptvcursor_add(ptvc, hf_nfapi_frequency_offset, 2, ENC_BIG_ENDIAN);
}
static void dissect_lte_cell_search_indication_value(ptvcursor_t * ptvc, packet_info* pinfo)
{
	guint32 num_lte_cells;

	// Number of LTE Cells Found
	ptvcursor_add_ret_uint(ptvc, hf_nfapi_number_of_lte_cells_found, 2, ENC_BIG_ENDIAN, &num_lte_cells);
	dissect_array_value(ptvc, pinfo, "LTE Cells Found", ett_nfapi_lte_cells_found_list, num_lte_cells, dissect_lte_cell_found_value);
}
static void dissect_utran_cell_found_value(ptvcursor_t * ptvc, packet_info* pinfo _U_)
{
	// PSC
	ptvcursor_add(ptvc, hf_nfapi_psc, 2, ENC_BIG_ENDIAN);

	// RSCP
	ptvcursor_add(ptvc, hf_nfapi_rscp, 1, ENC_BIG_ENDIAN);

	// EcN0
	ptvcursor_add(ptvc, hf_nfapi_enco, 1, ENC_BIG_ENDIAN);

	// Frequency Offset
	ptvcursor_add(ptvc, hf_nfapi_frequency_offset, 2, ENC_BIG_ENDIAN);
}
static void dissect_utran_cell_search_indication_value(ptvcursor_t * ptvc, packet_info* pinfo)
{
	guint32 num_utran_cells;

	// Number of UTRAN Cells Found
	ptvcursor_add_ret_uint(ptvc, hf_nfapi_number_of_utran_cells_found, 2, ENC_BIG_ENDIAN, &num_utran_cells);
	dissect_array_value(ptvc, pinfo, "UTRAN Cells Found", ett_nfapi_utran_cells_found_list, num_utran_cells, dissect_utran_cell_found_value);
}
static void dissect_geran_cell_found_value(ptvcursor_t * ptvc, packet_info* pinfo _U_)
{
	// ARFCN
	ptvcursor_add(ptvc, hf_nfapi_arfcn, 2, ENC_BIG_ENDIAN);

	// BSIC
	ptvcursor_add(ptvc, hf_nfapi_bsic, 1, ENC_BIG_ENDIAN);

	// RxLev
	ptvcursor_add(ptvc, hf_nfapi_rxlev, 1, ENC_BIG_ENDIAN);

	// RxQual
	ptvcursor_add(ptvc, hf_nfapi_rxqual, 1, ENC_BIG_ENDIAN);

	// Frequency Offset
	ptvcursor_add(ptvc, hf_nfapi_frequency_offset, 2, ENC_BIG_ENDIAN);

	// SFN Offset
	ptvcursor_add(ptvc, hf_nfapi_sfn_offset, 4, ENC_BIG_ENDIAN);
}
static void dissect_geran_cell_search_indication_value(ptvcursor_t * ptvc, packet_info* pinfo)
{
	guint32 num_geran_cells;

	// Number of GSM Cells Found
	ptvcursor_add_ret_uint(ptvc, hf_nfapi_number_of_geran_cells_found, 2, ENC_BIG_ENDIAN, &num_geran_cells);
	dissect_array_value(ptvc, pinfo, "GERAN Cells Found", ett_nfapi_geran_cells_found_list, num_geran_cells, dissect_geran_cell_found_value);
}
static void dissect_pnf_cell_search_state_value(ptvcursor_t * ptvc, packet_info* pinfo _U_)
{
	guint len = tvb_reported_length_remaining(ptvcursor_tvbuff(ptvc), ptvcursor_current_offset(ptvc));
	ptvcursor_add(ptvc, hf_nfapi_pnf_search_state, len, ENC_NA);
}
static void dissect_pnf_cell_broadcast_state_value(ptvcursor_t * ptvc, packet_info* pinfo _U_)
{
	guint len = tvb_reported_length_remaining(ptvcursor_tvbuff(ptvc), ptvcursor_current_offset(ptvc));
	ptvcursor_add(ptvc, hf_nfapi_pnf_broadcast_state, len, ENC_NA);
}
static void dissect_lte_broadcast_detect_request_value(ptvcursor_t * ptvc, packet_info* pinfo _U_)
{
	// EARFCN
	ptvcursor_add(ptvc, hf_nfapi_earfcn, 2, ENC_BIG_ENDIAN);

	// PCI
	ptvcursor_add(ptvc, hf_nfapi_pci, 2, ENC_BIG_ENDIAN);

	// Timeout
	ptvcursor_add(ptvc, hf_nfapi_timeout, 4, ENC_BIG_ENDIAN);
}
static void dissect_utran_broadcast_detect_request_value(ptvcursor_t * ptvc, packet_info* pinfo _U_)
{
	// UARFCN
	ptvcursor_add(ptvc, hf_nfapi_uarfcn, 2, ENC_BIG_ENDIAN);

	// PSC
	ptvcursor_add(ptvc, hf_nfapi_psc, 2, ENC_BIG_ENDIAN);

	// Timeout
	ptvcursor_add(ptvc, hf_nfapi_timeout, 4, ENC_BIG_ENDIAN);
}
static void dissect_lte_broadcast_detect_indication_value(ptvcursor_t * ptvc, packet_info* pinfo)
{
	guint32 test_value;

	// Number of Tx Antenna
	proto_item* item = ptvcursor_add_ret_uint(ptvc, hf_nfapi_number_of_tx_antenna, 1, ENC_BIG_ENDIAN, &test_value);
	if (!(test_value == 1 || test_value == 2 || test_value == 4))
	{
		expert_add_info_format(pinfo, item, &ei_invalid_range, "Invalid number of tx antenna value [1, 2, 4]");
	}

	// MIB[MIB Length]
	ptvcursor_add(ptvc, hf_nfapi_mib, 2, ENC_BIG_ENDIAN|ENC_NA);

	// SFN Offset
	ptvcursor_add(ptvc, hf_nfapi_sfn_offset, 4, ENC_BIG_ENDIAN);
}
static void dissect_utran_broadcast_detect_indication_value(ptvcursor_t * ptvc, packet_info* pinfo _U_)
{
	// MIB[MIB Length]
	ptvcursor_add(ptvc, hf_nfapi_mib, 2, ENC_BIG_ENDIAN|ENC_NA);

	// SFN Offset
	ptvcursor_add(ptvc, hf_nfapi_sfn_offset, 4, ENC_BIG_ENDIAN);
}
static void dissect_lte_system_information_schedule_request_value(ptvcursor_t * ptvc, packet_info* pinfo)
{
	proto_item* item;
	guint32 test_value;

	// EARFCN
	ptvcursor_add(ptvc, hf_nfapi_earfcn, 2, ENC_BIG_ENDIAN);

	// PCI
	ptvcursor_add(ptvc, hf_nfapi_pci, 2, ENC_BIG_ENDIAN);

	// Bandwidth
	item = ptvcursor_add_ret_uint(ptvc, hf_nfapi_bandwidth, 2, ENC_BIG_ENDIAN, &test_value);
	if (!(test_value == 6 || test_value == 15 || test_value == 25 ||
		test_value == 50 || test_value == 75 || test_value == 100))
	{
		expert_add_info_format(pinfo, item, &ei_invalid_range, "Invalid bandwidth value [6, 15, 25, 50, 75, 100]");
	}

	// PHICH Configuration
	// todo : phich bit decode
	ptvcursor_add(ptvc, hf_nfapi_phich_configuration, 1, ENC_BIG_ENDIAN);

	// Number of Tx Antenna
	item = ptvcursor_add_ret_uint(ptvc, hf_nfapi_number_of_tx_antenna, 1, ENC_BIG_ENDIAN, &test_value);
	if (!(test_value == 1 || test_value == 2 || test_value == 4))
	{
		expert_add_info_format(pinfo, item, &ei_invalid_range, "Invalid number of tx antenna value [1, 2, 4]");
	}

	// retryCount
	ptvcursor_add(ptvc, hf_nfapi_retry_count, 1, ENC_BIG_ENDIAN);

	// Timeout
	ptvcursor_add(ptvc, hf_nfapi_timeout, 4, ENC_BIG_ENDIAN);
}
static void dissect_lte_system_information_schedule_indication_value(ptvcursor_t * ptvc, packet_info* pinfo _U_)
{
	// this needs to be SIB 1
	guint len = tvb_reported_length_remaining(ptvcursor_tvbuff(ptvc), ptvcursor_current_offset(ptvc));
	ptvcursor_add(ptvc, hf_nfapi_sib1, len, ENC_NA);
}
static void dissect_si_periodicity_value(ptvcursor_t * ptvc, packet_info* pinfo)
{
	proto_item* item;
	guint32 test_value;

	// SI Periodicity
	item = ptvcursor_add_ret_uint(ptvc, hf_nfapi_si_periodicity, 1, ENC_BIG_ENDIAN, &test_value);
	if (test_value > 7)
	{
		expert_add_info_format(pinfo, item, &ei_invalid_range, "Invalid si periodicity value [0..7]");
	}

	// SI Index
	item = ptvcursor_add_ret_uint(ptvc, hf_nfapi_si_index, 1, ENC_BIG_ENDIAN, &test_value);
	if (test_value > 32)
	{
		expert_add_info_format(pinfo, item, &ei_invalid_range, "Invalid si Index value [0..32]");
	}
}

static void dissect_lte_system_information_request_value(ptvcursor_t * ptvc, packet_info* pinfo)
{
	proto_item* item;
	guint32 test_value, si_priodicity;

	// EARFCN
	ptvcursor_add(ptvc, hf_nfapi_earfcn, 2, ENC_BIG_ENDIAN);

	// PCI
	ptvcursor_add(ptvc, hf_nfapi_pci, 2, ENC_BIG_ENDIAN);

	// Downlink channel bandwidth
	item = ptvcursor_add_ret_uint(ptvc, hf_nfapi_downlink_channel_bandwidth, 2, ENC_BIG_ENDIAN, &test_value);
	if (!(test_value == 6 || test_value == 15 || test_value == 25 ||
		test_value == 50 || test_value == 75 || test_value == 100))
	{
		expert_add_info_format(pinfo, item, &ei_invalid_range, "Invalid bandwidth value [6, 15, 25, 50, 75, 100]");
	}

	// PHICH Configuration
	ptvcursor_add(ptvc, hf_nfapi_phich_configuration, 1, ENC_BIG_ENDIAN);

	// Number of Tx Antenna
	item = ptvcursor_add_ret_uint(ptvc, hf_nfapi_number_of_tx_antenna, 1, ENC_BIG_ENDIAN, &test_value);
	if (!(test_value == 1 || test_value == 2 || test_value == 4))
	{
		expert_add_info_format(pinfo, item, &ei_invalid_range, "Invalid number of tx antenna value [1, 2, 4]");
	}

	// Number of SI Periodicity
	ptvcursor_add_ret_uint(ptvc, hf_nfapi_number_of_si_periodicity, 1, ENC_BIG_ENDIAN, &si_priodicity);

	dissect_array_value(ptvc, pinfo, "Number SI Periodicity", ett_nfapi_si_periodicity_list, si_priodicity, dissect_si_periodicity_value);

	// SI Window Length
	item = ptvcursor_add_ret_uint(ptvc, hf_nfapi_si_window_length, 1, ENC_BIG_ENDIAN, &test_value);
	if (!(test_value == 1 || test_value == 2 || test_value == 5 || test_value == 10 ||
		  test_value == 15 || test_value == 20 || test_value == 40))
	{
		expert_add_info_format(pinfo, item, &ei_invalid_range, "Invalid si window length value [1, 2, 5, 10, 15, 20, 40]");
	}

	// Timeout
	ptvcursor_add(ptvc, hf_nfapi_timeout, 4, ENC_BIG_ENDIAN);
}
static void dissect_utran_system_information_request_value(ptvcursor_t * ptvc, packet_info* pinfo _U_)
{
	// UARFCN
	ptvcursor_add(ptvc, hf_nfapi_uarfcn, 2, ENC_BIG_ENDIAN);

	// PSC
	ptvcursor_add(ptvc, hf_nfapi_psc, 2, ENC_BIG_ENDIAN);

	// Timeout
	ptvcursor_add(ptvc, hf_nfapi_timeout, 4, ENC_BIG_ENDIAN);
}
static void dissect_geran_system_information_request_value(ptvcursor_t * ptvc, packet_info* pinfo _U_)
{
	// ARFCN
	ptvcursor_add(ptvc, hf_nfapi_arfcn, 2, ENC_BIG_ENDIAN);

	// BSIC
	ptvcursor_add(ptvc, hf_nfapi_bsic, 1, ENC_BIG_ENDIAN);

	// Timeout
	ptvcursor_add(ptvc, hf_nfapi_timeout, 4, ENC_BIG_ENDIAN);
}
static void dissect_lte_system_information_indication_value(ptvcursor_t * ptvc, packet_info* pinfo _U_)
{
	// SIB Type
	ptvcursor_add(ptvc, hf_nfapi_sib_type, 1, ENC_BIG_ENDIAN);

	// SIB[SIB Length]
	ptvcursor_add(ptvc, hf_nfapi_sib, 2, ENC_BIG_ENDIAN|ENC_NA);
}
static void dissect_utran_system_information_indication_value(ptvcursor_t * ptvc, packet_info* pinfo _U_)
{
	// SIB[SIB Length]
	ptvcursor_add(ptvc, hf_nfapi_sib, 2, ENC_BIG_ENDIAN|ENC_NA);
}
static void dissect_geran_system_information_indication_value(ptvcursor_t * ptvc, packet_info* pinfo _U_)
{
	// SI[SI Length]
	ptvcursor_add(ptvc, hf_nfapi_si, 2, ENC_BIG_ENDIAN|ENC_NA);
}

static void dissect_rx_indication_body_value(ptvcursor_t * ptvc, packet_info* pinfo _U_);

// Important the tags must be in numerical order so that they can be indexed correctly
static const tlv_t nfapi_tags[] =
{
	{ 0x1000, "PNF Param General", dissect_pnf_param_general_value },
	{ 0x1001, "PNF PHY", dissect_pnf_phy_value },
	{ 0x1002, "PNF RF", dissect_pnf_rf_value },
	{ 0x1003, "PNF PHY RF Config", dissect_pnf_phy_rf_config_value },
	{ 0x1004, "DL RS Tx power", dissect_dl_rs_tx_power_value },
	{ 0x1005, "Received interference power", dissect_received_interference_power_value },
	{ 0x1006, "Thermal noise power", dissect_thermal_noise_power_value },
	{ 0x1007, "DL RS TX Power measurement", dissect_dl_rs_tx_power_measurement_value },
	{ 0x1008, "Received Interference power measurement", dissect_received_interference_power_measurement_value },
	{ 0x1009, "Thermal noise power measurement", dissect_thermal_noise_power_measurement_value },
	{ 0x100A, "PNF PHY Rel 10", dissect_pnf_phy_rel10_value },
	{ 0x100B, "PNF PHY Rel 11", dissect_pnf_phy_rel11_value },
	{ 0x100C, "PNF PHY Rel 12", dissect_pnf_phy_rel12_value },
	{ 0x100D, "PNF PHY Rel 13", dissect_pnf_phy_rel13_value },
};

static const tlv_t configuration_tags[] =
{
	{ 0x0000, NULL, NULL },
	{ 0x0001, "Subframe config - Duplex Mode", dissect_duplex_mode_value },
	{ 0x0002, "Subframe config - PCFICH power offset TLV", dissect_pcfich_power_offset_value },
	{ 0x0003, "Subframe config - P-B", dissect_pb_value },
	{ 0x0004, "Subframe config - DL cyclic prefix type", dissect_dl_cyclic_prefix_value },
	{ 0x0005, "Subframe config - UL cyclic prefix type", dissect_ul_cyclic_prefix_value },
	{ 0x0006, NULL, NULL },
	{ 0x0007, NULL, NULL },
	{ 0x0008, NULL, NULL },
	{ 0x0009, NULL, NULL },
	{ 0x000A, "RF config - Downlink channel bandwidth", dissect_dl_channel_bandwidth_value },
	{ 0x000B, "RF config - Uplink channel bandwidth", dissect_ul_channel_bandwidth_value },
	{ 0x000C, "RF config - Reference signal power", dissect_reference_signal_power_value },
	{ 0x000D, "RF config - Tx antenna ports", dissect_tx_antenna_ports_value },
	{ 0x000E, "RF config - Rx Antenna ports", dissect_rx_antenna_ports_value },
	{ 0x000F, NULL, NULL },
	{ 0x0010, NULL, NULL },
	{ 0x0011, NULL, NULL },
	{ 0x0012, NULL, NULL },
	{ 0x0013, NULL, NULL },
	{ 0x0014, "PHICH config - PHICH resource", dissect_phich_resource_value },
	{ 0x0015, "PHICH config - PHICH duration", dissect_phich_duration_value },
	{ 0x0016, "PHICH config - PHICH power offset", dissect_phich_power_offset_value },
	{ 0x0017, NULL, NULL },
	{ 0x0018, NULL, NULL },
	{ 0x0019, NULL, NULL },
	{ 0x001A, NULL, NULL },
	{ 0x001B, NULL, NULL },
	{ 0x001C, NULL, NULL },
	{ 0x001D, NULL, NULL },
	{ 0x001E, "SCH config - Primary synchronization signal EPRE/EPRERS", dissect_psch_synch_signal_epre_eprers_value },
	{ 0x001F, "SCH config - Secondary synchronization signal EPRE/EPRERS", dissect_ssch_synch_signal_epre_eprers_value },
	{ 0x0020, "SCH config - Physical Cell Id", dissect_physical_cell_id_value },
	{ 0x0021, NULL, NULL },
	{ 0x0022, NULL, NULL },
	{ 0x0023, NULL, NULL },
	{ 0x0024, NULL, NULL },
	{ 0x0025, NULL, NULL },
	{ 0x0026, NULL, NULL },
	{ 0x0027, NULL, NULL },
	{ 0x0028, "PRACH config - Configuration Index", dissect_prach_configuration_index_value },
	{ 0x0029, "PRACH config - Root sequence Index", dissect_prach_root_sequence_index_value },
	{ 0x002A, "PRACH config - Zero correlation zone configuration", dissect_prach_zero_correlation_zone_configuration_value },
	{ 0x002B, "PRACH config - High speed flag", dissect_prach_high_speed_flag_value },
	{ 0x002C, "PRACH config - Frequency offset", dissect_prach_frequency_offset_value },
	{ 0x002D, NULL, NULL },
	{ 0x002E, NULL, NULL },
	{ 0x002F, NULL, NULL },
	{ 0x0030, NULL, NULL },
	{ 0x0031, NULL, NULL },
	{ 0x0032, "PUSCH config - Hopping mode", dissect_pusch_hopping_mode_value },
	{ 0x0033, "PUSCH config - Hopping offset", dissect_pusch_hopping_offset_value },
	{ 0x0034, "PUSCH config - Number of sub-bands", dissect_pusch_number_of_subbands_value },
	{ 0x0035, NULL, NULL },
	{ 0x0036, NULL, NULL },
	{ 0x0037, NULL, NULL },
	{ 0x0038, NULL, NULL },
	{ 0x0039, NULL, NULL },
	{ 0x003A, NULL, NULL },
	{ 0x003B, NULL, NULL },
	{ 0x003C, "PUCCH config - Delta PUCCH Shift", dissect_pucch_delta_pucch_shift_value },
	{ 0x003D, "PUCCH config - N_CQI RB", dissect_pucch_n_cqi_rb_value },
	{ 0x003E, "PUCCH config - N_AN CS", dissect_pucch_n_an_cs_value },
	{ 0x003F, "PUCCH config - N1Pucch-AN", dissect_pucch_n1_pucch_an_value },
	{ 0x0040, NULL, NULL },
	{ 0x0041, NULL, NULL },
	{ 0x0042, NULL, NULL },
	{ 0x0043, NULL, NULL },
	{ 0x0044, NULL, NULL },
	{ 0x0045, NULL, NULL },
	{ 0x0046, "SRS config - Bandwidth configuration", dissect_srs_bandwidth_configuration_value },
	{ 0x0047, "SRS config - MaxUpPTS", dissect_srs_max_uppts_value },
	{ 0x0048, "SRS config - SRS subframe configuration", dissect_srs_subframe_configuration_value },
	{ 0x0049, "SRS config - SRS AckNack SRS simultaneous transmission", dissect_srs_acknack_srs_sim_tx_value },
	{ 0x004A, NULL, NULL },
	{ 0x004B, NULL, NULL },
	{ 0x004C, NULL, NULL },
	{ 0x004D, NULL, NULL },
	{ 0x004E, NULL, NULL },
	{ 0x004F, NULL, NULL },
	{ 0x0050, "Uplink reference signal config - Uplink RS hopping", dissect_uplink_rs_hopping_value },
	{ 0x0051, "Uplink reference signal config - Group assignment (delta sequence-shift pattern)", dissect_group_assignment_value },
	{ 0x0052, "Uplink reference signal config - Cyclic Shift 1 for DMRS", dissect_cyclic_shift_1_for_drms_value },
	{ 0x0053, NULL, NULL },
	{ 0x0054, NULL, NULL },
	{ 0x0055, NULL, NULL },
	{ 0x0056, NULL, NULL },
	{ 0x0057, NULL, NULL },
	{ 0x0058, NULL, NULL },
	{ 0x0059, NULL, NULL },
	{ 0x005A, "TDD frame structure config - Subframe assignment", dissect_tdd_subframe_assignement_value },
	{ 0x005B, "TDD frame structure config - Special sub-frame patterns", dissect_tdd_subframe_patterns_value },
	{ 0x005C, NULL, NULL },
	{ 0x005D, NULL, NULL },
	{ 0x005E, NULL, NULL },
	{ 0x005F, NULL, NULL },
	{ 0x0060, NULL, NULL },
	{ 0x0061, NULL, NULL },
	{ 0x0062, NULL, NULL },
	{ 0x0063, NULL, NULL },
	{ 0x0064, "LAA config - ED Threshold for LBT for PDSCH", dissect_laa_ed_threashold_for_lbt_for_pdsch_value },
	{ 0x0065, "LAA config - ED Threshold for LBT for DRS", dissect_laa_ed_threashold_for_lbt_for_drs_value },
	{ 0x0066, "LAA config - PD Threshold", dissect_laa_pd_threshold_value },
	{ 0x0067, "LAA config - Multi carrier type", dissect_laa_multi_carrier_type_value },
	{ 0x0068, "LAA config - Multi carrier TX", dissect_laa_multi_carrier_tx_value },
	{ 0x0069, "LAA config - Multi carrier freeze", dissect_laa_multi_carrier_freeze_value },
	{ 0x006A, "LAA config - Tx antenna ports for DRS", dissect_laa_tx_antenna_port_for_drs_value },
	{ 0x006B, "LAA config - Transmission power for DRS", dissect_laa_transmission_power_for_drs_value },
	{ 0x006C, NULL, NULL },
	{ 0x006D, NULL, NULL },
	{ 0x006E, NULL, NULL },
	{ 0x006F, NULL, NULL },
	{ 0x0070, NULL, NULL },
	{ 0x0071, NULL, NULL },
	{ 0x0072, NULL, NULL },
	{ 0x0073, NULL, NULL },
	{ 0x0074, NULL, NULL },
	{ 0x0075, NULL, NULL },
	{ 0x0076, NULL, NULL },
	{ 0x0077, NULL, NULL },
	{ 0x0078, "eMTC config - PBCH Repetitions enable R13", dissect_emtc_pbch_repeitions_enabled_r13_value },
	{ 0x0079, "eMTC config - PRACH CAT-M Root sequence Index", dissect_emtc_prach_cat_m_root_sequence_index_value },
	{ 0x007A, "eMTC config - PRACH CAT-M Zero correlation zone configuration", dissect_emtc_prach_cat_m_zero_correlation_zone_configuration_value },
	{ 0x007B, "eMTC config - PRACH CAT-M High speed flag", dissect_emtc_prach_cat_m_high_speed_flag_value },
	{ 0x007C, "eMTC config - PRACH CE level #0 Enable", dissect_emtc_prach_ce_level_0_enabled_value },
	{ 0x007D, "eMTC config - PRACH CE level #0 Configuration Index", dissect_emtc_prach_ce_level_0_configuration_offset_value },
	{ 0x007E, "eMTC config - PRACH CE level #0 Frequency offset", dissect_emtc_prach_ce_level_0_frequency_offset_value },
	{ 0x007F, "eMTC config - PRACH CE level #0 Number of repetitions per attempt", dissect_emtc_preach_ce_level_0_num_of_repeitions_per_attempt_value },
	{ 0x0080, "eMTC config - CE level #0 Starting subframe periodicity", dissect_emtc_ce_level_0_starting_subframe_periodicity_value },
	{ 0x0081, "eMTC config - PRACH CE level #0 Hopping Enable", dissect_emtc_preach_ce_level_0_hopping_enabled_value },
	{ 0x0082, "eMTC config - PRACH CE level #0 Hopping Offset", dissect_emtc_preach_ce_level_0_hopping_offset_value },
	{ 0x0083, "eMTC config - PRACH CE level #1 Enable", dissect_emtc_prach_ce_level_1_enabled_value },
	{ 0x0084, "eMTC config - PRACH CE level #1 Configuration Index", dissect_emtc_prach_ce_level_1_configuration_offset_value },
	{ 0x0085, "eMTC config - PRACH CE level #1 Frequency offset", dissect_emtc_prach_ce_level_1_frequency_offset_value },
	{ 0x0086, "eMTC config - PRACH CE level #1 Number of repetitions per attempt", dissect_emtc_preach_ce_level_1_num_of_repeitions_per_attempt_value },
	{ 0x0087, "eMTC config - CE level #1 Starting subframe periodicity", dissect_emtc_ce_level_1_starting_subframe_periodicity_value },
	{ 0x0088, "eMTC config - PRACH CE level #1 Hopping Enable", dissect_emtc_preach_ce_level_1_hopping_enabled_value },
	{ 0x0089, "eMTC config - PRACH CE level #1 Hopping Offset", dissect_emtc_preach_ce_level_1_hopping_offset_value },
	{ 0x008A, "eMTC config - PRACH CE level #2 Enable", dissect_emtc_prach_ce_level_2_enabled_value },
	{ 0x008B, "eMTC config - PRACH CE level #2 Configuration Index", dissect_emtc_prach_ce_level_2_configuration_offset_value },
	{ 0x008C, "eMTC config - PRACH CE level #2 Frequency offset", dissect_emtc_prach_ce_level_2_frequency_offset_value },
	{ 0x008D, "eMTC config - PRACH CE level #2 Number of repetitions per attempt", dissect_emtc_preach_ce_level_2_num_of_repeitions_per_attempt_value },
	{ 0x008E, "eMTC config - CE level #2 Starting subframe periodicity", dissect_emtc_ce_level_2_starting_subframe_periodicity_value },
	{ 0x008F, "eMTC config - PRACH CE level #2 Hopping Enable", dissect_emtc_preach_ce_level_2_hopping_enabled_value },
	{ 0x0090, "eMTC config - PRACH CE level #2 Hopping Offset", dissect_emtc_preach_ce_level_2_hopping_offset_value },
	{ 0x0091, "eMTC config - PRACH CE level #3 Enable", dissect_emtc_prach_ce_level_3_enabled_value },
	{ 0x0092, "eMTC config - PRACH CE level #3 Configuration Index", dissect_emtc_prach_ce_level_3_configuration_offset_value },
	{ 0x0093, "eMTC config - PRACH CE level #3 Frequency offset", dissect_emtc_prach_ce_level_3_frequency_offset_value },
	{ 0x0094, "eMTC config - PRACH CE level #3 Number of repetitions per attempt", dissect_emtc_preach_ce_level_3_num_of_repeitions_per_attempt_value },
	{ 0x0095, "eMTC config - CE level #3 Starting subframe periodicity", dissect_emtc_ce_level_3_starting_subframe_periodicity_value },
	{ 0x0096, "eMTC config - PRACH CE level #3 Hopping Enable", dissect_emtc_preach_ce_level_3_hopping_enabled_value },
	{ 0x0097, "eMTC config - PRACH CE level #3 Hopping Offset", dissect_emtc_preach_ce_level_3_hopping_offset_value },
	{ 0x0098, "eMTC config - PUCCH Interval - ULHoppingConfigCommonModeA", dissect_emtc_pucch_interval_ul_hopping_config_common_mode_a_value },
	{ 0x0099, "eMTC config - PUCCH Interval - ULHoppingConfigCommonModeB", dissect_emtc_pucch_interval_ul_hopping_config_common_mode_b_value },
	{ 0x009A, NULL, NULL },
	{ 0x009B, NULL, NULL },
	{ 0x009C, NULL, NULL },
	{ 0x009D, NULL, NULL },
	{ 0x009E, NULL, NULL },
	{ 0x009F, NULL, NULL },
	{ 0x00A0, NULL, NULL },
	{ 0x00A1, NULL, NULL },
	{ 0x00A2, NULL, NULL },
	{ 0x00A3, NULL, NULL },
	{ 0x00A4, NULL, NULL },
	{ 0x00A5, NULL, NULL },
	{ 0x00A6, NULL, NULL },
	{ 0x00A7, NULL, NULL },
	{ 0x00A8, NULL, NULL },
	{ 0x00A9, NULL, NULL },
	{ 0x00AA, NULL, NULL },
	{ 0x00AB, NULL, NULL },
	{ 0x00AC, NULL, NULL },
	{ 0x00AD, NULL, NULL },
	{ 0x00AE, NULL, NULL },
	{ 0x00AF, NULL, NULL },
	{ 0x00B0, NULL, NULL },
	{ 0x00B1, NULL, NULL },
	{ 0x00B2, NULL, NULL },
	{ 0x00B3, NULL, NULL },
	{ 0x00B4, NULL, NULL },
	{ 0x00B5, NULL, NULL },
	{ 0x00B6, NULL, NULL },
	{ 0x00B7, NULL, NULL },
	{ 0x00B8, NULL, NULL },
	{ 0x00B9, NULL, NULL },
	{ 0x00BA, NULL, NULL },
	{ 0x00BB, NULL, NULL },
	{ 0x00BC, NULL, NULL },
	{ 0x00BD, NULL, NULL },
	{ 0x00BE, NULL, NULL },
	{ 0x00BF, NULL, NULL },
	{ 0x00C0, NULL, NULL },
	{ 0x00C1, NULL, NULL },
	{ 0x00C2, NULL, NULL },
	{ 0x00C3, NULL, NULL },
	{ 0x00C4, NULL, NULL },
	{ 0x00C5, NULL, NULL },
	{ 0x00C6, NULL, NULL },
	{ 0x00C7, NULL, NULL },
	{ 0x00C8, "Layer 2/3 - Downlink Bandwidth Support", dissect_dl_bandwidth_support_value },
	{ 0x00C9, "Layer 2/3 - Uplink Bandwidth Support", dissect_ul_bandwidth_support_value },
	{ 0x00CA, "Layer 2/3 - Downlink modulation support", dissect_dl_modulation_value },
	{ 0x00CB, "Layer 2/3 - Uplink modulation support", dissect_ul_modulation_value },
	{ 0x00CC, "Layer 2/3 - PHY antenna capability", dissect_phy_antenna_capability_value },
	{ 0x00CD, "Layer 2/3 - Release capability", dissect_release_capability_value },
	{ 0x00CE, "Layer 2/3 - MBSFN capability", dissect_mbsfn_value },
	{ 0x00CF, NULL, NULL },
	{ 0x00D0, NULL, NULL },
	{ 0x00D1, "LAA Capability - LAA support", dissect_laa_support_value },
	{ 0x00D2, "LAA Capability - PD sensing LBT support", dissect_laa_pd_sensing_lbt_support_value },
	{ 0x00D3, "LAA Capability - Multi carrier LBT support", dissect_laa_multi_carrier_lbt_support_value },
	{ 0x00D4, "LAA Capability - Partial SF support", dissect_laa_partial_sf_support_value },
	{ 0x00D5, NULL, NULL },
	{ 0x00D6, NULL, NULL },
	{ 0x00D7, NULL, NULL },
	{ 0x00D8, NULL, NULL },
	{ 0x00D9, NULL, NULL },
	{ 0x00DA, NULL, NULL },
	{ 0x00DB, NULL, NULL },
	{ 0x00DC, NULL, NULL },
	{ 0x00DD, NULL, NULL },
	{ 0x00DE, NULL, NULL },
	{ 0x00DF, NULL, NULL },
	{ 0x00E0, NULL, NULL },
	{ 0x00E1, NULL, NULL },
	{ 0x00E2, NULL, NULL },
	{ 0x00E3, NULL, NULL },
	{ 0x00E4, NULL, NULL },
	{ 0x00E5, NULL, NULL },
	{ 0x00E6, NULL, NULL },
	{ 0x00E7, NULL, NULL },
	{ 0x00E8, NULL, NULL },
	{ 0x00E9, NULL, NULL },
	{ 0x00EA, NULL, NULL },
	{ 0x00EB, NULL, NULL },
	{ 0x00EC, NULL, NULL },
	{ 0x00ED, NULL, NULL },
	{ 0x00EE, NULL, NULL },
	{ 0x00EF, NULL, NULL },
	{ 0x00F0, "Layer 2/3 - Data report mode", dissect_data_report_mode_value },
	{ 0x00F1, "Layer 2/3 - SFN/SF", dissect_sfn_sf_value },
	{ 0x00F2, NULL, NULL },
	{ 0x00F3, NULL, NULL },
	{ 0x00F4, NULL, NULL },
	{ 0x00F5, NULL, NULL },
	{ 0x00F6, NULL, NULL },
	{ 0x00F7, NULL, NULL },
	{ 0x00F8, NULL, NULL },
	{ 0x00F9, NULL, NULL },
	{ 0x00FA, "Layer 1 - PHY state", dissect_phy_state_value },
	{ 0x00FB, NULL, NULL },
	{ 0x00FC, NULL, NULL },
	{ 0x00FD, NULL, NULL },
	{ 0x00FE, NULL, NULL },
	{ 0x00FF, NULL, NULL },
	{ 0x0100, "NFAPI - P7 VNF Address IPv4", dissect_p7_vnf_address_ipv4_value },
	{ 0x0101, "NFAPI - P7 VNF Address IPv4", dissect_p7_vnf_address_ipv6_value },
	{ 0x0102, "NFAPI - P7 Port", dissect_p7_vnf_port_value },
	{ 0x0103, "NFAPI - P7 PNF Address IPv4", dissect_p7_pnf_address_ipv4_value },
	{ 0x0104, "NFAPI - P7 PNF Address IPv4", dissect_p7_pnf_address_ipv6_value },
	{ 0x0105, "NFAPI - P7 Port", dissect_p7_pnf_port_value },
	{ 0x0106, NULL, NULL },
	{ 0x0107, NULL, NULL },
	{ 0x0108, NULL, NULL },
	{ 0x0109, NULL, NULL },
	{ 0x010A, "NFAPI - Downlink UEs per Subframe", dissect_downlink_ues_per_subframe_value },
	{ 0x010B, "NFAPI - Uplink UEs per Subframe", dissect_uplink_ues_per_subframe_value },
	{ 0x010C, NULL, NULL },
	{ 0x010D, NULL, NULL },
	{ 0x010E, NULL, NULL },
	{ 0x010F, NULL, NULL },
	{ 0x0110, NULL, NULL },
	{ 0x0111, NULL, NULL },
	{ 0x0112, NULL, NULL },
	{ 0x0113, NULL, NULL },
	{ 0x0114, "NFAPI - nFAPI RF Bands", dissect_rf_bands_value },
	{ 0x0115, NULL, NULL },
	{ 0x0116, NULL, NULL },
	{ 0x0117, NULL, NULL },
	{ 0x0118, NULL, NULL },
	{ 0x0119, NULL, NULL },
	{ 0x011A, NULL, NULL },
	{ 0x011B, NULL, NULL },
	{ 0x011C, NULL, NULL },
	{ 0x011D, NULL, NULL },
	{ 0x011E, "NFAPI - Timing window", dissect_timing_window_value },
	{ 0x011F, "NFAPI - Timing info mode", dissect_timing_info_mode_value },
	{ 0x0120, "NFAPI - Timing info period", dissect_timing_info_period_value },
	{ 0x0121, NULL, NULL },
	{ 0x0122, NULL, NULL },
	{ 0x0123, NULL, NULL },
	{ 0x0124, NULL, NULL },
	{ 0x0125, NULL, NULL },
	{ 0x0126, NULL, NULL },
	{ 0x0127, NULL, NULL },
	{ 0x0128, "NFAPI - Maximum Transmit Power", dissect_maximum_transmit_power_value },
	{ 0x0129, "NFAPI - EARFCN", dissect_earfcn_value },
	{ 0x012A, NULL, NULL },
	{ 0x012B, NULL, NULL },
	{ 0x012C, NULL, NULL },
	{ 0x012D, NULL, NULL },
	{ 0x012E, NULL, NULL },
	{ 0x012F, NULL, NULL },
	{ 0x0130, "NFAPI - NMM GSM Frequency Bands", dissect_nmm_gsm_frequency_bands_value },
	{ 0x0131, "NFAPI - NMM UMTS Frequency Bands", dissect_nmm_umts_frequency_bands_value },
	{ 0x0132, "NFAPI - NMM LTE Frequency Bands", dissect_nmm_lte_frequency_bands_value },
	{ 0x0133, "NFAPI - NMM Uplink RSSI supported", dissect_nmm_uplink_rssi_supported_value },
};

static const tlv_t p7_tags[] =
{
	{ 0x2000, "DL Config Request Body", dissect_dl_config_request_body_value },
	{ 0x2001, "DL DCI PDU Release 8", dissect_dl_config_request_dl_dci_pdu_rel8_value },
	{ 0x2002, "DL DCI PDU Release 9", dissect_dl_config_request_dl_dci_pdu_rel9_value },
	{ 0x2003, "DL DCI PDU Release 10", dissect_dl_config_request_dl_dci_pdu_rel10_value },
	{ 0x2004, "BCH PDU Release 8", dissect_dl_config_request_bch_pdu_rel8_value },
	{ 0x2005, "MCH PDU Release 8", dissect_dl_config_request_mch_pdu_rel8_value },
	{ 0x2006, "DLSCH PDU Release 8", dissect_dl_config_request_dlsch_pdu_rel8_value },
	{ 0x2007, "DLSCH PDU Release 9", dissect_dl_config_request_dlsch_pdu_rel9_value },
	{ 0x2008, "DLSCH PDU Release 10", dissect_dl_config_request_dlsch_pdu_rel10_value },
	{ 0x2009, "PCH PDU Release 8", dissect_dl_config_request_pch_pdu_rel8_value },
	{ 0x200A, "PRS PDU Release 9", dissect_dl_config_request_prs_pdu_rel9_value },
	{ 0x200B, "CSI-RS PDU Release 10", dissect_dl_config_request_csi_rs_pdu_rel10_value },
	{ 0x200C, "UL Config Request Body", dissect_ul_config_request_body_value },
	{ 0x200D, "ULSCH PDU Release 8", dissect_ul_config_ulsch_pdu_rel8_value },
	{ 0x200E, "ULSCH PDU Release 10", dissect_ul_config_ulsch_pdu_rel10_value },
	{ 0x200F, "Initial Transmission Parameters Release 8", dissect_ul_config_init_tx_params_rel8_value },
	{ 0x2010, "CQI RI Information Release 8", dissect_ul_config_cqi_ri_info_rel8_value },
	{ 0x2011, "CQI RI Information Release 9 or later", dissect_ul_config_cqi_ri_info_rel9_later_value },
	{ 0x2012, "HARQ Information (ULSCH) Release 10", dissect_ul_config_harq_info_ulsch_rel10_value },
	{ 0x2013, "UE Information Release 8", dissect_ul_config_ue_info_rel8_value },
	{ 0x2014, "CQI Information Release 8", dissect_ul_config_cqi_info_rel8_value },
	{ 0x2015, "CQI Information Release 10", dissect_ul_config_cqi_info_rel10_value },
	{ 0x2016, "SR Information Release 8", dissect_ul_config_sr_info_rel8_value },
	{ 0x2017, "SR Information Release 10", dissect_ul_config_sr_info_rel10_value },
	{ 0x2018, "HARQ Information (UCI) Release 10 TDD", dissect_ul_config_harq_info_uci_rel10_tdd_value },
	{ 0x2019, "HARQ Information (UCI) Release 8 FDD", dissect_ul_config_harq_info_uci_rel8_fdd_value },
	{ 0x201A, "HARQ Information (UCI) Release 9 or later FDD", dissect_ul_config_harq_info_uci_rel9_later_fdd_value },
	{ 0x201B, "SRS Information Release 8", dissect_ul_config_srs_info_rel8_value },
	{ 0x201C, "SRS Information Release 10", dissect_ul_config_srs_info_rel10_value },
	{ 0x201D, "HI DCI0 Request Body", dissect_hi_dci0_request_body_value },
	{ 0x201E, "HI PDU Release 8", dissect_hi_dci0_hi_rel8_value },
	{ 0x201F, "HI PDU Release 10", dissect_hi_dci0_hi_rel10_value },
	{ 0x2020, "DCI UL PDU Release 8", dissect_hi_dci0_dci_ul_rel8_value },
	{ 0x2021, "DCI UL PDU Release 10", dissect_hi_dci0_dci_ul_rel10_value },
	{ 0x2022, "Tx Request Body", dissect_tx_request_body_value },
	{ 0x2023, "RX Indication Body", dissect_rx_indication_body_value },
	{ 0x2024, "RX PDU Release 8", dissect_rx_indication_rel8_value },
	{ 0x2025, "RX PDU Release 9", dissect_rx_indication_rel9_value },
	{ 0x2026, "HARQ Indication Body", dissect_harq_indication_body_value },
	{ 0x2027, "HARQ PDU Release 8 TDD", dissect_harq_indication_rel8_tdd_value },
	{ 0x2028, "HARQ PDU Release 9 or later TDD", dissect_harq_indication_rel9_later_tdd_value },
	{ 0x2029, "HARQ PDU Release 8 FDD", dissect_harq_indication_rel8_fdd_value },
	{ 0x202A, "HARQ PDU Release 9 or later FDD", dissect_harq_indication_rel9_later_fdd_value },
	{ 0x202B, "CRC Indication Body", dissect_crc_indication_body_value },
	{ 0x202C, "CRC PDU Release 8", dissect_crc_indication_rel8_value },
	{ 0x202D, "RX SR Indication Body", dissect_rx_sr_indication_body_value },
	{ 0x202E, "RX CQI Indication Body", dissect_rx_cqi_indication_body_value },
	{ 0x202F, "CQI PDU Release 8", dissect_rx_cqi_indication_rel8_value },
	{ 0x2030, "CQI PDU Release 9", dissect_rx_cqi_indication_rel9_value },
	{ 0x2031, "RACH Indication Body", dissect_rach_indication_body_value },
	{ 0x2032, "Preamable PDU Release 8", dissect_rach_indication_rel8_value },
	{ 0x2033, "Preamable PDU Release 9", dissect_rach_indication_rel9_value },
	{ 0x2034, "SRS Indication Body", dissect_srs_indication_body_value },
	{ 0x2035, "SRS PDU Release 8", dissect_srs_indication_rel8_value },
	{ 0x2036, "SRS PDU Release 9", dissect_srs_indication_rel9_value },
	{ 0x2037, "SRS PDU Release 10 TDD", dissect_srs_indication_rel10_tdd_value },
	{ 0x2038, "RX UE Information", dissect_rx_ue_info_value },
	{ 0x2039, "DL DCI PDU Release 11", dissect_dl_config_request_dl_dci_pdu_rel11_value },
	{ 0x203A, "DL DCI PDU Release 12", dissect_dl_config_request_dl_dci_pdu_rel12_value },
	{ 0x203B, "DL DCI PDU Release 13", dissect_dl_config_request_dl_dci_pdu_rel13_value },
	{ 0x203C, "DLSCH PDU Release 11", dissect_dl_config_request_dlsch_pdu_rel11_value },
	{ 0x203D, "DLSCH PDU Release 12", dissect_dl_config_request_dlsch_pdu_rel12_value },
	{ 0x203E, "DLSCH PDU Release 13", dissect_dl_config_request_dlsch_pdu_rel13_value },
	{ 0x203F, "PCH PDU Release 13", dissect_dl_config_request_pch_pdu_rel13_value },
	{ 0x2040, "CSI-RS PDU Release 13", dissect_dl_config_request_csi_rs_pdu_rel13_value },
	{ 0x2041, "EDPCCH PDU Release 11 Parameters", dissect_dl_config_request_edpcch_params_rel11_value },
	{ 0x2042, "EDPCCH PDU Release 13 Parameters", dissect_dl_config_request_edpcch_params_rel13_value },
	{ 0x2043, "ULSCH PDU Release 11", dissect_ul_config_ulsch_pdu_rel11_value },
	{ 0x2044, "ULSCH PDU Release 13", dissect_ul_config_ulsch_pdu_rel13_value },
	{ 0x2045, "CQI RI Information Release 13", dissect_ul_config_cqi_ri_info_rel13_value },
	{ 0x2046, "HARQ Information (ULSCH) Release 13", dissect_ul_config_harq_info_ulsch_rel13_value },
	{ 0x2047, "UE Information Release 11", dissect_ul_config_ue_info_rel11_value },
	{ 0x2048, "UE Information Release 13", dissect_ul_config_ue_info_rel13_value },
	{ 0x2049, "CQI Information Release 13", dissect_ul_config_cqi_info_rel13_value },
	{ 0x204A, "HARQ Information (UCI) Release 11 FDD/TDD", dissect_ul_config_harq_info_uci_rel11_fdd_tdd_value },
	{ 0x204B, "HARQ Information (UCI) Release 13 FDD/TDD", dissect_ul_config_harq_info_uci_rel13_fdd_tdd_value },
	{ 0x204C, "SRS Information Release 13", dissect_ul_config_srs_info_rel13_value },
	{ 0x204D, "DCI UL PDU Release 12", dissect_hi_dci0_dci_ul_rel12_value },
	{ 0x204E, "MDPCCH DCI UL PDU Release 13", dissect_hi_dci0_mdpcch_dci_ul_rel13_value },
	{ 0x204F, "HARQ PDU Release 13 or later TDD", dissect_harq_indication_rel13_later_tdd_value },
	{ 0x2050, "HARQ PDU Release 13 or later FDD", dissect_harq_indication_rel13_later_fdd_value },
	{ 0x2051, "Preamable PDU Release 13", dissect_rach_indication_rel13_value },
	{ 0x2052, "UL CQI Information", dissect_ul_cqi_information_value },
	{ 0x2053, "SRS PDU Release 11", dissect_srs_indication_rel11_value },
	{ 0x2054, "TDD Channel Measurement", dissect_tdd_channel_measurement_value },
	{ 0x2055, "LBT DL Config Request Body", dissect_lbt_dl_config_request_body_value },
	{ 0x2056, "LBT PDSCH Req PDU Release 13", dissect_lbt_dl_config_request_pdsch_req_rel13_value },
	{ 0x2057, "LBT DRS req PDU Release 13", dissect_lbt_dl_config_request_drs_req_rel13_value },
	{ 0x2058, "LBT DL Indication Message Body", dissect_lbt_indication_message_body_value },
	{ 0x2059, "LBT PDSCH Resp PDU Release 13", dissect_lbt_dl_config_request_pdsch_resp_rel13_value },
	{ 0x205A, "LBT DRS Resp PDU Release 13", dissect_lbt_dl_config_request_drs_resp_rel13_value },
	{ 0x205B, "MPDCCH PDU Release 13", dissect_dl_config_request_mpdpcch_pdu_rel13_value },
};

static const tlv_t p4_tags[] =
{
	{ 0x3000, "LTE RSSI Request", dissect_lte_rssi_request_value },
	{ 0x3001, "UTRAN RSSI Request", dissect_utran_rssi_request_value },
	{ 0x3002, "GERAN RSSI Request", dissect_geran_rssi_request_value },
	{ 0x3003, "RSSI Indication", dissect_rssi_indication_value },
	{ 0x3004, "LTE CELL SEARCH Request", dissect_lte_cell_search_value },
	{ 0x3005, "UTRAN CELL SEARCH Request", dissect_utran_cell_search_value },
	{ 0x3006, "GERAN CELL SEARCH Request", dissect_geran_cell_search_value },
	{ 0x3007, "LTE CELL SEARCH Indication", dissect_lte_cell_search_indication_value },
	{ 0x3008, "UTRAN CELL SEARCH Indication", dissect_utran_cell_search_indication_value },
	{ 0x3009, "GERAN CELL SEARCH Indication", dissect_geran_cell_search_indication_value },
	{ 0x300A, "PNF CELL SEARCH STATE", dissect_pnf_cell_search_state_value },
	{ 0x300B, "LTE BROADCAST DETECT Request", dissect_lte_broadcast_detect_request_value },
	{ 0x300C, "UTRAN BROADCAST DETECT Request", dissect_utran_broadcast_detect_request_value },
	{ 0x300D, "PNF CELL SEARCH STATE", dissect_pnf_cell_search_state_value },
	{ 0x300E, "LTE BROADCAST DETECT Indication", dissect_lte_broadcast_detect_indication_value },
	{ 0x300F, "UTRAN BROADCAST DETECT Indication", dissect_utran_broadcast_detect_indication_value },
	{ 0x3010, "PNF CELL BROADCAST STATE", dissect_pnf_cell_broadcast_state_value },
	{ 0x3011, "LTE SYSTEM INFORMATION SCHEDULE Request", dissect_lte_system_information_schedule_request_value },
	{ 0x3012, "PNF CELL BROADCAST STATE", dissect_pnf_cell_broadcast_state_value },
	{ 0x3013, "LTE SYSTEM INFORMATION SCHEDULE Indication", dissect_lte_system_information_schedule_indication_value },
	{ 0x3014, "LTE SYSTEM INFORMATION Request", dissect_lte_system_information_request_value },
	{ 0x3015, "UTRAN SYSTEM INFORMATION Request", dissect_utran_system_information_request_value },
	{ 0x3016, "GERAN SYSTEM INFORMATION Request", dissect_geran_system_information_request_value },
	{ 0x3017, "PNF CELL BROADCAST STATE", dissect_pnf_cell_broadcast_state_value },
	{ 0x3018, "LTE SYSTEM INFORMATION Indication", dissect_lte_system_information_indication_value },
	{ 0x3019, "UTRAN SYSTEM INFORMATION Indication", dissect_utran_system_information_indication_value },
	{ 0x301A, "GERAN SYSTEM INFORMATION Indication", dissect_geran_system_information_indication_value },
};


static const tlv_t* look_up_tlv(int tag_id)
{
	const tlv_t* tlv = NULL;

	static const gint num_configuration_tags = sizeof(configuration_tags) / sizeof(tlv_t);
	static const gint num_nfapi_tags = sizeof(nfapi_tags) / sizeof(tlv_t);
	static const gint num_p7_tags = sizeof(p7_tags) / sizeof(tlv_t);
	static const gint num_p4_tags = sizeof(p4_tags) / sizeof(tlv_t);

	if (tag_id >= 0x0000 && tag_id <= (0x0000 + num_configuration_tags - 1)) // 0x0133)
	{
		tlv = &configuration_tags[tag_id];
	}
	else if (tag_id >= 0x1000 && tag_id <= (0x1000 + num_nfapi_tags - 1)) // 0x100D)
	{
		tlv = &nfapi_tags[tag_id - 0x1000];
	}
	else if (tag_id >= 0x2000 && tag_id <= (0x2000 + num_p7_tags - 1)) //0x205B)
	{
		tlv = &p7_tags[tag_id - 0x2000];
	}
	else if (tag_id >= 0x3000 && tag_id <= (0x3000 + num_p4_tags - 1)) // 0x301A)
	{
		tlv = &p4_tags[tag_id - 0x3000];
	}
	return tlv;
}


static proto_item* dissect_tl_header(ptvcursor_t * ptvc, packet_info* pinfo _U_)
{
	ptvcursor_add_text_with_subtree(ptvc, SUBTREE_UNDEFINED_LENGTH, ett_nfapi_tl, "TL");
	ptvcursor_add(ptvc, hf_nfapi_tl_tag, 2, ENC_BIG_ENDIAN);
	proto_item* item = ptvcursor_add(ptvc, hf_nfapi_tl_length, 2, ENC_BIG_ENDIAN);
	ptvcursor_pop_subtree(ptvc);

	return item;
}

static void dissect_tlv_list(ptvcursor_t* ptvc, packet_info* pinfo, gint len)
{
	while (ptvcursor_current_offset(ptvc) < len)
	{
		guint16 tlv_id = tvb_get_ntohs(ptvcursor_tvbuff(ptvc), ptvcursor_current_offset(ptvc));
		guint16 tlv_len = tvb_get_ntohs(ptvcursor_tvbuff(ptvc), ptvcursor_current_offset(ptvc) + 2);

		const tlv_t* tlv = look_up_tlv(tlv_id);

		if (tlv != NULL && tlv->name != NULL && tlv->tag_id == tlv_id)
		{
			ptvcursor_add_text_with_subtree(ptvc, SUBTREE_UNDEFINED_LENGTH, ett_nfapi_tlv_tree, "%s", tlv->name);
			proto_item* tlv_length_item = dissect_tl_header(ptvc, pinfo);

			// There are rare cases where the len of the tlv is 0.
			if (tlv_len > 0)
			{

				if (tlv->decode != NULL)
				{
					// Create a sub buff with the correct length, so we can detect reading off the end
					tvbuff_t* sub_tvbuff = tvb_new_subset_length(ptvcursor_tvbuff(ptvc), ptvcursor_current_offset(ptvc), tlv_len);
					ptvcursor_t* sub_ptvc = ptvcursor_new(ptvcursor_tree(ptvc), sub_tvbuff, 0);

					tlv->decode(sub_ptvc, pinfo);

					if (ptvcursor_current_offset(sub_ptvc) != tlv_len)
					{
						// error in the tlv length
						expert_add_info_format(pinfo, tlv_length_item, &ei_invalid_tlv_length, "TLV length does not match decoded length");
					}

					ptvcursor_free(sub_ptvc);
				}

				ptvcursor_advance(ptvc, tlv_len);
			}

			ptvcursor_pop_subtree(ptvc);
		}
		else
		{
			if (tlv_id >= 0xF000 /* && tlv_id <= 0xFFFF*/)
			{
				ptvcursor_add_text_with_subtree(ptvc, SUBTREE_UNDEFINED_LENGTH, ett_nfapi_tlv_tree, "Unknown Vendor Extension Tag");
			}
			else
			{
				ptvcursor_add_text_with_subtree(ptvc, SUBTREE_UNDEFINED_LENGTH, ett_nfapi_tlv_tree, "Unknown");
			}

			dissect_tl_header(ptvc, pinfo);
			ptvcursor_advance(ptvc, tlv_len);
			ptvcursor_pop_subtree(ptvc);
		}
	}
}


static void dissect_rx_indication_body_value(ptvcursor_t * ptvc, packet_info* pinfo)
{
	guint32 i = 0, count;
	guint number_of_pdu_addr = ptvcursor_current_offset(ptvc); // *offset;
	wmem_array_t *lengths = wmem_array_new(wmem_packet_scope(), sizeof(guint16));

	ptvcursor_add_ret_uint(ptvc, hf_nfapi_number_pdus, 2, ENC_BIG_ENDIAN, &count);

	if (count > 0)
	{
		ptvcursor_add_text_with_subtree(ptvc, SUBTREE_UNDEFINED_LENGTH, ett_nfapi_rx_indication_pdu_list, "RX PDU List");
		gint pdu_end = tvb_reported_length_remaining(ptvcursor_tvbuff(ptvc), ptvcursor_current_offset(ptvc)) + ptvcursor_current_offset(ptvc);

		while (tvb_reported_length_remaining(ptvcursor_tvbuff(ptvc), ptvcursor_current_offset(ptvc)) > 0 &&
			   ptvcursor_current_offset(ptvc) < pdu_end )
		{
			guint16 tlv_id = tvb_get_ntohs(ptvcursor_tvbuff(ptvc), ptvcursor_current_offset(ptvc));
			//guint16 tlv_len = tvb_get_ntohs(ptvcursor_tvbuff(ptvc), ptvcursor_current_offset(ptvc) + 2);

			if (tlv_id == 0x2038)
			{
				if (i != 0)
					ptvcursor_pop_subtree(ptvc);

				ptvcursor_add_text_with_subtree(ptvc, SUBTREE_UNDEFINED_LENGTH, ett_nfapi_rx_indication_pdu_list, "[%u]", i);

				i++;
			}

			char* tlv_name = "Unknown";
			const tlv_t* tlv = look_up_tlv(tlv_id);

			if (tlv != NULL && tlv->name != NULL && tlv->tag_id == tlv_id)
			{
				tlv_name = tlv->name;
			}

			ptvcursor_add_text_with_subtree(ptvc, SUBTREE_UNDEFINED_LENGTH, ett_nfapi_rx_indication_pdu_list, "%s", tlv_name);

			dissect_tl_header(ptvc, pinfo);


			if (tlv_id == 0x2038)
			{
				dissect_rx_ue_info_value(ptvc, pinfo);
			}
			else if ((tlv_id == 0x2024) && (i > 0))
			{
				guint16 val = tvb_get_ntohs(ptvcursor_tvbuff(ptvc), ptvcursor_current_offset(ptvc));
				wmem_array_append_one(lengths, val);
				ptvcursor_add(ptvc, hf_nfapi_length, 2, ENC_BIG_ENDIAN);
				int data_offset = tvb_get_ntohs(ptvcursor_tvbuff(ptvc), ptvcursor_current_offset(ptvc));
				ptvcursor_add(ptvc, hf_nfapi_data_offset, 2, ENC_BIG_ENDIAN);
				ptvcursor_add(ptvc, hf_nfapi_ul_cqi, 1, ENC_BIG_ENDIAN);
				ptvcursor_add(ptvc, hf_nfapi_timing_advance, 2, ENC_BIG_ENDIAN);

				if ((data_offset > 0) && (pdu_end == (tvb_reported_length_remaining(ptvcursor_tvbuff(ptvc), ptvcursor_current_offset(ptvc)) + ptvcursor_current_offset(ptvc))))
				{
					pdu_end = number_of_pdu_addr + data_offset;
				}

			}
			else if (tlv_id == 0x2025)
			{
				dissect_rx_indication_rel9_value(ptvc, pinfo);
			}

			ptvcursor_pop_subtree(ptvc);

		}

		// pop the last pdu index
		ptvcursor_pop_subtree(ptvc);

		ptvcursor_pop_subtree(ptvc);
	}

	for (i = 0; i < wmem_array_get_count(lengths); ++i)
	{
		ptvcursor_add(ptvc, hf_nfapi_pdu, *((guint16 *)wmem_array_index(lengths, i)), ENC_NA);
	}
}


// ----------------------------------------------------------------------------|

static int dissect_p45_header(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, void* data _U_)
{
	proto_tree* p45_tree;

	p45_tree = proto_tree_add_subtree(tree, tvb, 0, 8, ett_nfapi_p4_p5_message_header, NULL, "P4 P5 Header");

	proto_tree_add_item(p45_tree, hf_nfapi_p4_p5_message_header_phy_id, tvb, 0, 2, ENC_BIG_ENDIAN);
	proto_tree_add_item(p45_tree, hf_nfapi_p4_p5_message_header_message_id, tvb, 2, 2, ENC_BIG_ENDIAN);
	proto_tree_add_item(p45_tree, hf_nfapi_p4_p5_message_header_message_length, tvb, 4, 2, ENC_BIG_ENDIAN);
	proto_tree_add_item(p45_tree, hf_nfapi_p4_p5_message_header_spare, tvb, 6, 2, ENC_BIG_ENDIAN);

	return 8;
}

static int dissect_p45_header_with_list(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data)
{
	int offset = dissect_p45_header(tvb, pinfo, tree, data);
	ptvcursor_t *ptvc = ptvcursor_new(tree, tvb, offset);

	dissect_tlv_list(ptvc, pinfo, tvb_reported_length(tvb));
	ptvcursor_free(ptvc);
	return tvb_captured_length(tvb);
}

static int dissect_p45_header_with_error(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data)
{
	int offset = dissect_p45_header(tvb, pinfo, tree, data);

	proto_tree_add_item(tree, hf_nfapi_error_code, tvb, offset, 4, ENC_BIG_ENDIAN);

	return offset+4;
}

static int dissect_p45_header_with_error_and_list(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data)
{
	int offset = dissect_p45_header(tvb, pinfo, tree, data);
	ptvcursor_t *ptvc;

	proto_tree_add_item(tree, hf_nfapi_error_code, tvb, offset, 4, ENC_BIG_ENDIAN);
	offset += 4;

	ptvc = ptvcursor_new(tree, tvb, offset);
	dissect_tlv_list(ptvc, pinfo, tvb_reported_length(tvb));
	ptvcursor_free(ptvc);

	return tvb_captured_length(tvb);
}

static int dissect_p45_header_with_p4_error(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data)
{
	int offset = dissect_p45_header(tvb, pinfo, tree, data);

	proto_tree_add_item(tree, hf_nfapi_p4_error_code, tvb, offset, 4, ENC_BIG_ENDIAN);

	return offset+4;
}

static int dissect_p45_header_with_p4_error_and_list(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data)
{
	int offset = dissect_p45_header(tvb, pinfo, tree, data);
	ptvcursor_t *ptvc;

	proto_tree_add_item(tree, hf_nfapi_p4_error_code, tvb, offset, 4, ENC_BIG_ENDIAN);
	offset += 4;

	ptvc = ptvcursor_new(tree, tvb, offset);
	dissect_tlv_list(ptvc, pinfo, tvb_reported_length(tvb));
	ptvcursor_free(ptvc);

	return tvb_captured_length(tvb);
}

static int dissect_p45_header_with_rat_type_list(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data)
{
	int offset = dissect_p45_header(tvb, pinfo, tree, data);
	ptvcursor_t *ptvc;

	proto_tree_add_item(tree, hf_nfapi_rat_type, tvb, offset, 1, ENC_BIG_ENDIAN);
	offset += 1;

	ptvc = ptvcursor_new(tree, tvb, offset);
	dissect_tlv_list(ptvc, pinfo, tvb_reported_length(tvb));
	ptvcursor_free(ptvc);

	return tvb_captured_length(tvb);
}

static int dissect_p45_param_response_msg_id(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data)
{
	int offset = dissect_p45_header(tvb, pinfo, tree, data);
	ptvcursor_t *ptvc;

	proto_tree_add_item(tree, hf_nfapi_error_code, tvb, offset, 1, ENC_BIG_ENDIAN);
	offset += 1;
	proto_tree_add_item(tree, hf_nfapi_num_tlv, tvb, offset, 1, ENC_BIG_ENDIAN);
	offset += 1;

	ptvc = ptvcursor_new(tree, tvb, offset);
	dissect_tlv_list(ptvc, pinfo, tvb_reported_length(tvb));
	ptvcursor_free(ptvc);

	return tvb_captured_length(tvb);
}

static int dissect_p45_config_request_msg_id(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data)
{
	int offset = dissect_p45_header(tvb, pinfo, tree, data);
	ptvcursor_t *ptvc;

	proto_tree_add_item(tree, hf_nfapi_num_tlv, tvb, offset, 1, ENC_BIG_ENDIAN);
	offset += 1;

	ptvc = ptvcursor_new(tree, tvb, offset);
	dissect_tlv_list(ptvc, pinfo, tvb_reported_length(tvb));
	ptvcursor_free(ptvc);

	return tvb_captured_length(tvb);
}

static int dissect_p7_header(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, guint8* m, guint8* seg, guint8* seq)
{
	proto_tree *header_tree;
	int offset = 0;
	guint8 m_seg;
	static int * const fields[] = {
		&hf_nfapi_p7_message_header_m,
		&hf_nfapi_p7_message_header_segment,
		NULL
	};

	header_tree = proto_tree_add_subtree(tree, tvb, offset, 16, ett_nfapi_p7_message_header, NULL, "P7 Header");
	proto_tree_add_item(header_tree, hf_nfapi_p7_message_header_phy_id, tvb, offset, 2, ENC_BIG_ENDIAN);
	offset += 2;
	proto_tree_add_item(header_tree, hf_nfapi_p7_message_header_message_id, tvb, offset, 2, ENC_BIG_ENDIAN);
	offset += 2;
	proto_tree_add_item(header_tree, hf_nfapi_p7_message_header_message_length, tvb, offset, 2, ENC_BIG_ENDIAN);
	offset += 2;

	if ((m != NULL) && (seg != NULL))
	{
		m_seg = tvb_get_guint8(tvb, offset);
		*m = (m_seg & 0x80) >> 7;
		*seg = m_seg & 0x7F;
	}
	proto_tree_add_bitmask_list(header_tree, tvb, offset, 1, fields, ENC_BIG_ENDIAN);
	offset += 1;

	if (seq != NULL)
	{
		*seq = tvb_get_guint8(tvb, offset);
	}
	proto_tree_add_item(header_tree, hf_nfapi_p7_message_header_sequence_number, tvb, offset, 1, ENC_BIG_ENDIAN);
	offset += 1;
	proto_tree_add_item(header_tree, hf_nfapi_p7_message_header_checksum, tvb, offset, 4, ENC_BIG_ENDIAN);
	offset += 4;
	proto_tree_add_item(header_tree, hf_nfapi_p7_message_header_transmit_timestamp, tvb, offset, 4, ENC_BIG_ENDIAN);
	offset += 4;

	return offset;
}

static int dissect_p7_dl_node_sync_msg_id(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
	int offset = dissect_p7_header(tvb, pinfo, tree, NULL, NULL, NULL);

	proto_tree_add_item(tree, hf_nfapi_ul_node_sync_t1, tvb, offset, 4, ENC_BIG_ENDIAN);
	offset += 4;
	proto_tree_add_item(tree, hf_nfapi_ul_node_sync_t2, tvb, offset, 4, ENC_BIG_ENDIAN);
	offset += 4;
	proto_tree_add_item(tree, hf_nfapi_ul_node_sync_t3, tvb, offset, 4, ENC_BIG_ENDIAN);
	offset += 4;

	return offset;
}

static int dissect_p7_ul_node_sync_msg_id(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
	int offset = dissect_p7_header(tvb, pinfo, tree, NULL, NULL, NULL);

	proto_tree_add_item(tree, hf_nfapi_dl_node_sync_t1, tvb, offset, 4, ENC_BIG_ENDIAN);
	offset += 4;
	proto_tree_add_item(tree, hf_nfapi_dl_node_sync_delta_sfn_sf, tvb, offset, 4, ENC_BIG_ENDIAN);
	offset += 4;

	return offset;
}

static int dissect_p7_timing_info_msg_id(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
	int offset = dissect_p7_header(tvb, pinfo, tree, NULL, NULL, NULL);
	proto_tree_add_item(tree, hf_nfapi_timing_info_last_sfn_sf, tvb, offset, 4, ENC_BIG_ENDIAN);
	offset += 4;
	proto_tree_add_item(tree, hf_nfapi_timing_info_time_since_last_timing_info, tvb, offset, 4, ENC_BIG_ENDIAN);
	offset += 4;
	proto_tree_add_item(tree, hf_nfapi_timing_info_dl_config_jitter, tvb, offset, 4, ENC_BIG_ENDIAN);
	offset += 4;
	proto_tree_add_item(tree, hf_nfapi_timing_info_tx_request_jitter, tvb, offset, 4, ENC_BIG_ENDIAN);
	offset += 4;
	proto_tree_add_item(tree, hf_nfapi_timing_info_ul_config_jitter, tvb, offset, 4, ENC_BIG_ENDIAN);
	offset += 4;
	proto_tree_add_item(tree, hf_nfapi_timing_info_hi_dci0_jitter, tvb, offset, 4, ENC_BIG_ENDIAN);
	offset += 4;
	proto_tree_add_item(tree, hf_nfapi_timing_info_dl_config_latest_delay, tvb, offset, 4, ENC_BIG_ENDIAN);
	offset += 4;
	proto_tree_add_item(tree, hf_nfapi_timing_info_tx_request_latest_delay, tvb, offset, 4, ENC_BIG_ENDIAN);
	offset += 4;
	proto_tree_add_item(tree, hf_nfapi_timing_info_ul_config_latest_delay, tvb, offset, 4, ENC_BIG_ENDIAN);
	offset += 4;
	proto_tree_add_item(tree, hf_nfapi_timing_info_hi_dci0_latest_delay, tvb, offset, 4, ENC_BIG_ENDIAN);
	offset += 4;
	proto_tree_add_item(tree, hf_nfapi_timing_info_dl_config_earliest_arrival, tvb, offset, 4, ENC_BIG_ENDIAN);
	offset += 4;
	proto_tree_add_item(tree, hf_nfapi_timing_info_tx_request_earliest_arrival, tvb, offset, 4, ENC_BIG_ENDIAN);
	offset += 4;
	proto_tree_add_item(tree, hf_nfapi_timing_info_ul_config_earliest_arrival, tvb, offset, 4, ENC_BIG_ENDIAN);
	offset += 4;
	proto_tree_add_item(tree, hf_nfapi_timing_info_hi_dci0_earliest_arrival, tvb, offset, 4, ENC_BIG_ENDIAN);
	offset += 4;

	return offset;
}

static reassembly_table ul_p7_reassemble_table;
static reassembly_table dl_p7_reassemble_table;

static int hf_msg_fragments = -1;
static int hf_msg_fragment = -1;
static int hf_msg_fragment_overlap = -1;
static int hf_msg_fragment_overlap_conflicts = -1;
static int hf_msg_fragment_multiple_tails = -1;
static int hf_msg_fragment_too_long_fragment = -1;
static int hf_msg_fragment_error = -1;
static int hf_msg_fragment_count = -1;
static int hf_msg_reassembled_in = -1;
static int hf_msg_reassembled_length = -1;
static gint ett_msg_fragment = -1;
static gint ett_msg_fragments = -1;

static const fragment_items msg_frag_items = {
	/* Fragment subtrees */
	&ett_msg_fragment,
	&ett_msg_fragments,
	/* Fragment fields */
	&hf_msg_fragments,
	&hf_msg_fragment,
	&hf_msg_fragment_overlap,
	&hf_msg_fragment_overlap_conflicts,
	&hf_msg_fragment_multiple_tails,
	&hf_msg_fragment_too_long_fragment,
	&hf_msg_fragment_error,
	&hf_msg_fragment_count,
	/* Reassembled in field */
	&hf_msg_reassembled_in,
	/* Reassembled length field */
	&hf_msg_reassembled_length,
	NULL,
	/* Tag */
	"Message fragments"
};

static int dissect_nfapi_ul_p7(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
	guint8 m, seg, seq;
	int offset;

	guint8 save_fragmented;

	guint16 msg_id = tvb_get_ntohs(tvb, 2);
	guint16 msg_len = tvb_get_ntohs(tvb, 4);

	offset = dissect_p7_header(tvb, pinfo, tree, &m, &seg, &seq);
	save_fragmented = pinfo->fragmented;

	if (m == 1 || (m == 0 && seg > 0))
	{
		fragment_head *fd_head;
		tvbuff_t *save_tvb = tvb;

		if (offset >= msg_len) {
			return tvb_captured_length(tvb);
		}

		pinfo->fragmented = TRUE;

		fd_head = fragment_add_seq_check(&ul_p7_reassemble_table, tvb, offset, pinfo, seq, NULL, seg, msg_len - offset, (m == 1));

		if (fd_head == NULL)
		{
			return tvb_captured_length(tvb);
		}

		tvb = process_reassembled_data(tvb, offset, pinfo, "Reassembled UL P7", fd_head, &msg_frag_items, NULL, tree);
		if (tvb)
		{
			offset = 0;
			col_append_fstr(pinfo->cinfo, COL_INFO, "[NFAPI P7 Reassembled %d]", seg);
		}
		else
		{
			col_append_fstr(pinfo->cinfo, COL_INFO, "[NFAPI P7 Segment %d]", seg);
			return tvb_captured_length(save_tvb);
		}
	}

	pinfo->fragmented = save_fragmented;

	switch (msg_id)
	{
		case NFAPI_HARQ_INDICATION_MSG_ID:
		case NFAPI_CRC_INDICATION_MSG_ID:
		case NFAPI_RX_ULSCH_INDICATION_MSG_ID:
		case NFAPI_RACH_INDICATION_MSG_ID:
		case NFAPI_SRS_INDICATION_MSG_ID:
		case NFAPI_RX_SR_INDICATION_MSG_ID:
		case NFAPI_RX_CQI_INDICATION_MSG_ID:
		{
			ptvcursor_t *ptvc = ptvcursor_new(tree, tvb, offset);
			ptvcursor_add(ptvc, hf_nfapi_sfn_sf, 2, ENC_BIG_ENDIAN);
			dissect_tlv_list(ptvc, pinfo, msg_len);
			ptvcursor_free(ptvc);
		}
		break;

	};


	return tvb_captured_length(tvb);
}

static int dissect_nfapi_dl_p7(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
	guint8 m, seg, seq;
	int offset;

	guint8 save_fragmented;

	guint16 msg_id = tvb_get_ntohs(tvb, 2);
	guint16 msg_len = tvb_get_ntohs(tvb, 4);

	offset = dissect_p7_header(tvb, pinfo, tree, &m, &seg, &seq);
	save_fragmented = pinfo->fragmented;

	if (m == 1 || (m == 0 && seg > 0))
	{
		fragment_head *fd_head;
		tvbuff_t *save_tvb = tvb;

		if (offset >= msg_len) {
			return tvb_captured_length(tvb);
		}

		pinfo->fragmented = TRUE;

		fd_head = fragment_add_seq_check(&dl_p7_reassemble_table, tvb, offset, pinfo, seq, NULL, seg, msg_len - offset, (m == 1));

		if (fd_head == NULL)
		{
			return tvb_captured_length(tvb);
		}

		tvb = process_reassembled_data(tvb, offset, pinfo, "Reassembled DL P7", fd_head, &msg_frag_items, NULL, tree);
		if (tvb)
		{
			offset = 0;
			col_append_fstr(pinfo->cinfo, COL_INFO, "[NFAPI P7 Reassembled %d]", seg);
		}
		else
		{
			col_append_fstr(pinfo->cinfo, COL_INFO, "[NFAPI P7 Segment %d]", seg);
			return tvb_captured_length(save_tvb);
		}
	}

	pinfo->fragmented = save_fragmented;

	switch (msg_id)
	{
		case NFAPI_DL_CONFIG_REQUEST_MSG_ID:
		case NFAPI_UL_CONFIG_REQUEST_MSG_ID:
		case NFAPI_HI_DCI0_REQUEST_MSG_ID:
		case NFAPI_TX_REQUEST_MSG_ID:
		case NFAPI_LBT_DL_CONFIG_REQUEST_MSG_ID:
		case NFAPI_LBT_DL_INDICATION_MSG_ID:
		{
			ptvcursor_t *ptvc = ptvcursor_new(tree, tvb, offset);
			ptvcursor_add(ptvc, hf_nfapi_sfn_sf, 2, ENC_BIG_ENDIAN);
			dissect_tlv_list(ptvc, pinfo, msg_len);
			ptvcursor_free(ptvc);
			break;
		}
	}

	return tvb_captured_length(tvb);
}


static int dissect_nfapi(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
	proto_tree* nfapi_tree;
	proto_item* nfapi_item;
	guint16 msg_id;
	const gchar* message_str;

	if (tvb_reported_length(tvb) < 4)
		return 0;

	col_set_str(pinfo->cinfo, COL_PROTOCOL, "NFAPI");
	col_clear(pinfo->cinfo, COL_INFO);

	nfapi_item = proto_tree_add_item(tree, proto_nfapi, tvb, 0, -1, ENC_NA);
	nfapi_tree = proto_item_add_subtree(nfapi_item, ett_nfapi);

	msg_id = tvb_get_ntohs(tvb, 2);
	message_str = val_to_str_const(msg_id, message_id_vals, "Unknown");

	// Flag if this is a vendor extention message, could do it for P4, 5, 7
	if (msg_id >= 0x0300 && msg_id <= 0x03FF)
	{
		col_append_fstr(pinfo->cinfo, COL_INFO, "Vendor Extension");
		proto_item_append_text(nfapi_item, ", Vendor Extension");
	}
	else
	{
		proto_item_append_text(nfapi_item, ", %s", message_str);
		col_append_fstr(pinfo->cinfo, COL_INFO, " %s ", message_str);
	}

	if (!dissector_try_uint_new(message_table, msg_id, tvb, pinfo, nfapi_tree, FALSE, NULL))
	{
		call_data_dissector(tvb, pinfo, nfapi_tree);
	}

	return tvb_captured_length(tvb);
}

static void nfapi_tag_vals_fn(gchar* s, guint32 v)
{
	const tlv_t* tlv = look_up_tlv(v);
	if (tlv != 0)
	{
		g_snprintf(s, ITEM_LABEL_LENGTH, "%s (0x%x)", tlv->name, v);
	}
	else
	{
		g_snprintf(s, ITEM_LABEL_LENGTH, "%s (0x%x)", "Unknown", v);
	}
}
static void neg_pow_conversion_fn(gchar* s, guint8 v)
{
	g_snprintf(s, ITEM_LABEL_LENGTH, "%d dB (%d)", ((gint16)v * (-1)), v);
}
static void power_offset_conversion_fn(gchar* s, guint16 v)
{
	g_snprintf(s, ITEM_LABEL_LENGTH, "%.2f dB (%d)", (((float)v * 0.001) - 6.0), v);
}
static void reference_signal_power_conversion_fn(gchar* s, guint16 v)
{
	g_snprintf(s, ITEM_LABEL_LENGTH, "%.2f dB (%d)", (((float)v * 0.25) - 63.75), v);
}
static void laa_threshold_conversion_fn(gchar* s, guint16 v)
{
	g_snprintf(s, ITEM_LABEL_LENGTH, "%.2f dB (%d)", (float)(v * -100.00), v);
}
static void max_transmit_power_2_conversion_fn(gchar* s, guint16 v)
{
	g_snprintf(s, ITEM_LABEL_LENGTH, "%.2f dB (%d)", ((float)v * 0.1) - 10.0, v);
}
static void max_transmit_power_conversion_fn(gchar* s, guint16 v)
{
	g_snprintf(s, ITEM_LABEL_LENGTH, "%.2f dB (%d)", ((float)v * 0.1), v);
}
static void sfn_sf_conversion_fn(gchar* s, guint16 v)
{
	g_snprintf(s, ITEM_LABEL_LENGTH, "%d/%d (%d)", v >> 0x4, v & 0x000F, v);
}
static void rssi_conversion_fn(gchar* s, guint16 v)
{
	g_snprintf(s, ITEM_LABEL_LENGTH, "%.2f dB (%d)", ((float)v * 0.1), v);
}
static void dl_rs_tx_pow_measment_conversion_fn(gchar* s, guint16 v)
{
	g_snprintf(s, ITEM_LABEL_LENGTH, "%.2f dB (%d)", ((float)v * 0.1), v);
}

static void ul_cqi_conversion_fn(gchar* s, guint16 v)
{
	g_snprintf(s, ITEM_LABEL_LENGTH, "%.2f dB (%d)", (((float)v / 2 ) - 64.0), v);
}

// ----------------------------------------------------------------------------|

void proto_register_nfapi(void)
{
	static hf_register_info hf[] =
	{
		{ &hf_msg_fragments,
			{ "Message fragments", "nfapi.fragments",
			FT_NONE, BASE_NONE, NULL, 0x00,
			NULL, HFILL }
		},
		{ &hf_msg_fragment,
			{ "Message fragment", "nfapi.fragment",
			FT_FRAMENUM, BASE_NONE, NULL, 0x00,
			NULL, HFILL }
		},
		{ &hf_msg_fragment_overlap,
			{ "Message fragment overlap", "nfapi.fragment.overlap",
			FT_BOOLEAN, 0, NULL, 0x00,
			NULL, HFILL }
		},
		{ &hf_msg_fragment_overlap_conflicts,
			{ "Message fragment overlapping with conflicting data", "nfapi.fragment.overlap.conflicts",
			FT_BOOLEAN, 0, NULL, 0x00,
			NULL, HFILL }
		},
		{ &hf_msg_fragment_multiple_tails,
			{ "Message has multiple tail fragments", "nfapi.fragment.multiple_tails",
			FT_BOOLEAN, 0, NULL, 0x00,
			NULL, HFILL }
		},
		{ &hf_msg_fragment_too_long_fragment,
			{ "Message fragment too long", "nfapi.fragment.too_long_fragment",
			FT_BOOLEAN, 0, NULL, 0x00,
			NULL, HFILL }
		},
		{ &hf_msg_fragment_error,
			{ "Message defragmentation error", "nfapi.fragment.error",
			FT_FRAMENUM, BASE_NONE, NULL, 0x00,
			NULL, HFILL }
		},
		{ &hf_msg_fragment_count,
			{ "Message fragment count", "nfapi.fragment.count",
			FT_UINT32, BASE_DEC, NULL, 0x00,
			NULL, HFILL }
		},
		{ &hf_msg_reassembled_in,
			{ "Reassembled in", "nfapi.reassembled.in",
			FT_FRAMENUM, BASE_NONE, NULL, 0x00,
			NULL, HFILL }
		},
		{ &hf_msg_reassembled_length,
			{ "Reassembled length", "nfapi.reassembled.length",
			FT_UINT32, BASE_DEC, NULL, 0x00,
			NULL, HFILL }
		},
		{ &hf_nfapi_p4_p5_message_header_phy_id,
			{ "PHY ID", "nfapi.p4_p5_message_header.phy_id",
			FT_UINT16, BASE_DEC, NULL, 0x0,
			"Within the PNF Device, the unique identity of the PHY instance as assigned through the PNF_CONFIG.request", HFILL }
		},
		{ &hf_nfapi_p4_p5_message_header_message_id,
			{ "Message ID", "nfapi.p4_p5_message_header.message_id",
			FT_UINT16, BASE_HEX_DEC, VALS(message_id_vals), 0x0,
			"The nFAPI message identity", HFILL }
		},
		{ &hf_nfapi_p4_p5_message_header_message_length,
			{ "Message Length", "nfapi.p4_p5_message_header.message_length",
			FT_UINT16, BASE_DEC, NULL, 0x0,
			"The length in bytes of the message including the header", HFILL }
		},
		{ &hf_nfapi_p4_p5_message_header_spare,
			{ "Spare", "nfapi.p4_p5_message_header.spare",
			FT_UINT16, BASE_DEC, NULL, 0x0,
			"Reserved field to be populated with zeros on transmission and ignored on reception", HFILL }
		},
		{ &hf_nfapi_p7_message_header_phy_id,
			{ "Phy ID", "nfapi.p7_message_header.phy_id",
			FT_UINT16, BASE_DEC, NULL, 0x0,
			"Within the PNF Device, the unique identity of the PHY instance as assigned through the PNF_CONFIG.request", HFILL }
		},
		{ &hf_nfapi_p7_message_header_message_id,
			{ "Message ID", "nfapi.p7.message_header.message_id",
			FT_UINT16, BASE_HEX_DEC, VALS(message_id_vals), 0x0,
			"The nFAPI message identity", HFILL }
		},
		{ &hf_nfapi_p7_message_header_message_length,
			{ "Message Length", "nfapi.p7_message_header.message_length",
			FT_UINT16, BASE_DEC | BASE_UNIT_STRING, &units_byte_bytes, 0x0,
			"The length in bytes of the message segment including the header", HFILL }
		},
		{ &hf_nfapi_p7_message_header_m,
			{ "More segments", "nfapi.p7_message_header.more_segments",
			FT_BOOLEAN, 8, TFS(&tfs_yes_no), 0x80,
			"A More flag indicating there are more segments to follow to complete the entire message", HFILL }
		},
		{ &hf_nfapi_p7_message_header_segment,
			{ "Segment Number", "nfapi.p7_message_header.segment_number",
			FT_UINT8, BASE_DEC, NULL, 0x7F,
			"The segment number starting at zero and incrementing by one between each segment", HFILL }
		},
		{ &hf_nfapi_p7_message_header_sequence_number,
			{ "Sequence Number", "nfapi.p7_message_header.m_segment_sequence",
			FT_UINT8, BASE_DEC, NULL, 0x0,
			"The incrementing sequence number for all complete messages over the P7 nFAPI interface per PHY instance", HFILL }
		},
		{ &hf_nfapi_p7_message_header_checksum,
			{ "Checksum", "nfapi.p7_message_header.checksum",
			FT_UINT32, BASE_HEX_DEC, NULL, 0x0,
			"The checksum of the whole message segment (including header) as calculated using "
			"the CRC32c algorithm following the same method as the SCTP protocol defined in IETF RFC 4960 "
			"The Checksum is optional to populate and must be filled with zero's when not used", HFILL }
		},
		{ &hf_nfapi_p7_message_header_transmit_timestamp,
			{ "Transmit Timestamp", "nfapi.p7_message_header.timestamp",
			FT_UINT32, BASE_DEC | BASE_UNIT_STRING, &units_milliseconds, 0x0,
			"The offset from VNF SFN/SF 0/0 time reference of the message transmission at the transport layer, in microseconds, with a range of 0 to 10239999", HFILL }
		},
		{ &hf_nfapi_tl_tag,
			{ "TLV Tag", "nfapi.tl_tag",
			FT_UINT16, BASE_CUSTOM, CF_FUNC(nfapi_tag_vals_fn), 0x0,
			NULL, HFILL }
		},
		{ &hf_nfapi_tl_length,
			{ "TLV Length", "nfapi.tl_length",
			FT_UINT16, BASE_DEC | BASE_UNIT_STRING, &units_byte_bytes, 0x0,
			NULL, HFILL }
		},
		{ &hf_nfapi_error_code,
			{ "Error Code", "nfapi.error.code",
			FT_UINT8, BASE_DEC, VALS(nfapi_error_vals), 0x0,
			NULL, HFILL }
		},
		{ &hf_nfapi_p4_error_code,
			{ "Error Code", "nfapi.p4_error.code",
			FT_UINT8, BASE_DEC, VALS(nfapi_p4_error_vals), 0x0,
			NULL, HFILL }
		},
		{ &hf_nfapi_rat_type,
			{ "RAT Type", "nfapi.rat_type",
			FT_UINT8, BASE_DEC, VALS(nfapi_rat_type_vals), 0x0,
			NULL, HFILL }
		},
		{ &hf_nfapi_num_tlv,
			{ "Number of TLV", "nfapi.param.response.num_tlv",
			FT_UINT8, BASE_DEC, NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_nfapi_phy_state,
			{ "Phy state value", "nfapi.phy.state",
			FT_UINT16, BASE_DEC, VALS(nfapi_phy_state_vals), 0x0,
			"Indicates the current operational state of the PHY", HFILL }
		},
		{ &hf_nfapi_dl_ue_per_sf,
			{ "Downlink UEs per Subframe", "nfapi.dl.ue.per.sf",
			FT_UINT8, BASE_DEC, NULL, 0x0,
			"The maximum number of downlink UEs per subframe supported."
			"This is the maximum number of downlink UEs that can be scheduled per "
			"subframe, non-inclusive of broadcast, paging and common channels.", HFILL }
		},
		{ &hf_nfapi_ul_ue_per_sf,
			{ "Uplink UEs per Subframe", "nfapi.ul.ue.per.sf",
			FT_UINT8, BASE_DEC, NULL, 0x0,
			"The maximum number of uplink UEs per subframe supported."
			"This is the maximum number of uplink UEs that can be scheduled per "
			"subframe, non-inclusive of common channels.", HFILL }
		},
		{ &hf_nfapi_duplex_mode,
			{ "Duplex Mode", "nfapi.duplex.mode",
			FT_UINT16, BASE_DEC, VALS(nfapi_duplex_mode_vals), 0x0,
			NULL, HFILL }
		},
		{ &hf_nfapi_dl_bandwidth_support,
			{ "Downlink bandwidth support", "nfapi.dl.bandwidth.support",
			FT_UINT16, BASE_HEX, NULL, 0x0,
			"The PHY downlink channel bandwidth capability (in resource blocks)", HFILL }
		},
		{ &hf_nfapi_dl_bandwidth_support_6,
			{ "6Mhz", "nfapi.dl.bandwidth.support.6",
			FT_BOOLEAN, 16, TFS(&tfs_supported_not_supported), 0x0001,
			NULL, HFILL }
		},
		{ &hf_nfapi_dl_bandwidth_support_15,
			{ "15Mhz", "nfapi.dl.bandwidth.support.15",
			FT_BOOLEAN, 16, TFS(&tfs_supported_not_supported), 0x0002,
			NULL, HFILL }
		},
		{ &hf_nfapi_dl_bandwidth_support_25,
			{ "25Mhz", "nfapi.dl.bandwidth.support.25",
			FT_BOOLEAN, 16, TFS(&tfs_supported_not_supported), 0x0004,
			NULL, HFILL }
		},
		{ &hf_nfapi_dl_bandwidth_support_50,
			{ "50Mhz", "nfapi.dl.bandwidth.support.50",
			FT_BOOLEAN, 16, TFS(&tfs_supported_not_supported), 0x0008,
			NULL, HFILL }
		},
		{ &hf_nfapi_dl_bandwidth_support_75,
			{ "75Mhz", "nfapi.dl.bandwidth.support.75",
			FT_BOOLEAN, 16, TFS(&tfs_supported_not_supported), 0x0010,
			NULL, HFILL }
		},
		{ &hf_nfapi_dl_bandwidth_support_100,
			{ "100Mhz", "nfapi.dl.bandwidth.support.100",
			FT_BOOLEAN, 16, TFS(&tfs_supported_not_supported), 0x0020,
			NULL, HFILL }
		},
		{ &hf_nfapi_ul_bandwidth_support,
			{ "Uplink bandwidth support", "nfapi.ul.bandwidth.support",
			FT_UINT16, BASE_HEX, NULL, 0x0,
			"The PHY uplink channel bandwidth capability (in resource blocks)", HFILL }
		},
		{ &hf_nfapi_ul_bandwidth_support_6,
			{ "6Mhz", "nfapi.ul.bandwidth.support.6",
			FT_BOOLEAN, 16, TFS(&tfs_supported_not_supported), 0x0001,
			NULL, HFILL }
		},
		{ &hf_nfapi_ul_bandwidth_support_15,
			{ "15Mhz", "nfapi.ul.bandwidth.support.15",
			FT_BOOLEAN, 16, TFS(&tfs_supported_not_supported), 0x0002,
			NULL, HFILL }
		},
		{ &hf_nfapi_ul_bandwidth_support_25,
			{ "25Mhz", "nfapi.ul.bandwidth.support.25",
			FT_BOOLEAN, 16, TFS(&tfs_supported_not_supported), 0x0004,
			NULL, HFILL }
		},
		{ &hf_nfapi_ul_bandwidth_support_50,
			{ "50Mhz", "nfapi.ul.bandwidth.support.50",
			FT_BOOLEAN, 16, TFS(&tfs_supported_not_supported), 0x0008,
			NULL, HFILL }
		},
		{ &hf_nfapi_ul_bandwidth_support_75,
			{ "75Mhz", "nfapi.ul.bandwidth.support.75",
			FT_BOOLEAN, 16, TFS(&tfs_supported_not_supported), 0x0010,
			NULL, HFILL }
		},
		{ &hf_nfapi_ul_bandwidth_support_100,
			{ "100Mhz", "nfapi.ul.bandwidth.support.100",
			FT_BOOLEAN, 16, TFS(&tfs_supported_not_supported), 0x0020,
			NULL, HFILL }
		},
		{ &hf_nfapi_dl_modulation_support,
			{ "Downlink modulation support", "nfapi.dl.modulation.support",
			FT_UINT16, BASE_HEX, NULL, 0x0,
			"The PHY downlink modulation capability", HFILL }
		},
		{ &hf_nfapi_dl_modulation_support_qpsk,
			{ "QPSK", "nfapi.dl.modulation.support.qpsk",
			FT_BOOLEAN, 16, TFS(&tfs_supported_not_supported), 0x0001,
			NULL, HFILL }
		},
		{ &hf_nfapi_dl_modulation_support_16qam,
			{ "16QAM", "nfapi.dl.modulation.support.16qam",
			FT_BOOLEAN, 16, TFS(&tfs_supported_not_supported), 0x0002,
			NULL, HFILL }
		},
		{ &hf_nfapi_dl_modulation_support_64qam,
			{ "64QAM", "nfapi.dl.modulation.support.64qam",
			FT_BOOLEAN, 16, TFS(&tfs_supported_not_supported), 0x0004,
			NULL, HFILL }
		},
		{ &hf_nfapi_dl_modulation_support_256qam,
			{ "256QAM", "nfapi.dl.modulation.support.256qam",
			FT_BOOLEAN, 16, TFS(&tfs_supported_not_supported), 0x0008,
			NULL, HFILL }
		},
		{ &hf_nfapi_ul_modulation_support,
			{ "Uplink modulation support", "nfapi.ul.modulation.support",
			FT_UINT16, BASE_HEX, NULL, 0x0,
			"The PHY uplink modulation capability", HFILL }
		},
		{ &hf_nfapi_ul_modulation_support_qpsk,
			{ "QPSK", "nfapi.ul.modulation.support.qpsk",
			FT_BOOLEAN, 16, NULL, 0x0001,
			NULL, HFILL }
		},
		{ &hf_nfapi_ul_modulation_support_16qam,
			{ "16QAM", "nfapi.ul.modulation.support.16qam",
			FT_BOOLEAN, 16, NULL, 0x0002,
			NULL, HFILL }
		},
		{ &hf_nfapi_ul_modulation_support_64qam,
			{ "64QAM", "nfapi.ul.modulation.support.64qam",
			FT_BOOLEAN, 16, NULL, 0x0004,
			NULL, HFILL }
		},
		{ &hf_nfapi_phy_antenna_capability,
			{ "Phy Antenna capability", "nfapi.phy.antenna.capability",
			FT_UINT16, BASE_DEC, NULL, 0x0,
			"Number of antennas supported", HFILL }
		},
		{ &hf_nfapi_release_capability,
			{ "Release capability", "nfapi.release.capability",
			FT_UINT16, BASE_DEC, NULL, 0x0,
			"Indicates which release the PHY supports", HFILL }
		},
		{ &hf_nfapi_mbsfn_capability,
			{ "MBSFN capability", "nfapi.mbsfn.capability",
			FT_BOOLEAN, 16, TFS(&support_strname), 0x0,
			"Indicates support for MBSFN features", HFILL }
		},
		{ &hf_nfapi_laa_capability,
			{ "LAA Support", "nfapi.laa.support",
			FT_BOOLEAN, 16, TFS(&support_strname), 0x0,
			"Indicates support for LAA features", HFILL }
		},
		{ &hf_nfapi_pd_sensing_lbt_support,
			{ "PD sensing LBT support", "nfapi.pd.sensing.lbt.support",
			FT_BOOLEAN, 16, TFS(&support_strname), 0x0,
			"Indicates support for PD sensing in L1", HFILL }
		},
		{ &hf_nfapi_multi_carrier_lbt_support,
			{ "Multi carrier LBT support", "nfapi.multi.carrier.lbt.support",
			FT_UINT16, BASE_DEC, VALS(nfapi_mutli_carrier_lbt_support_vals), 0x0,
			NULL, HFILL }
		},
		{ &hf_nfapi_partial_sf_support,
			{ "Partial SF support", "nfapi.partial.sf.support",
			FT_BOOLEAN, 8, TFS(&partial_sf_support_strname), 0x0,
			"Indicates support for Partial SF in L1", HFILL }
		},
		{ &hf_nfapi_reference_signal_power,
			{ "Reference signal power", "nfapi.ref_sig_power",
			FT_UINT16, BASE_CUSTOM, CF_FUNC(reference_signal_power_conversion_fn), 0x0,
			"Normalized value levels (relative) to accommodate different absolute Tx Power used by eNb", HFILL }
		},
		{ &hf_nfapi_primary_synchronization_signal_epre_eprers,
			{ "Primary synchronization signal EPRE/EPRERS", "nfapi.primary.sync.signal",
			FT_UINT16, BASE_CUSTOM, CF_FUNC(power_offset_conversion_fn), 0x0,
			"The power of synchronization signal with respect to the reference signal, (PSS for LTE cell, NPSS for NB-IOT cell)", HFILL }
		},
		{ &hf_nfapi_secondary_synchronization_signal_epre_eprers,
			{ "Secondary synchronization signal EPRE/EPRERS", "nfapi.secondary.sync.signal",
			FT_UINT16, BASE_CUSTOM, CF_FUNC(power_offset_conversion_fn), 0x0,
			"The power of synchronization signal with respect to the reference signal, (SSS for LTE cell, NSSS for NB-IOT cell)", HFILL }
		},
		{ &hf_nfapi_physical_cell_id,
			{ "Physical Cell ID", "nfapi.physical.cell.id",
			FT_UINT16, BASE_DEC, NULL, 0x0,
			"The Cell ID sent with the synchronization signal", HFILL }
		},
		{ &hf_nfapi_phich_resource,
			{ "PHICH Resource", "nfapi.phich.resource",
			FT_UINT16, BASE_DEC, VALS(nfapi_phich_resource_vals), 0x0,
			"The number of resource element groups used for PHICH", HFILL }
		},
		{ &hf_nfapi_phich_duration,
			{ "PHICH Duration", "nfapi.phich.duration",
			FT_BOOLEAN, 8, TFS(&phich_duration_strname), 0x0,
			"The PHICH duration for MBSFN and non-MBSFN sub-frames", HFILL }
		},
		{ &hf_nfapi_phich_power_offset,
			{ "PHICH Power Offset", "nfapi.phich.power.offset",
			FT_UINT16, BASE_CUSTOM, CF_FUNC(power_offset_conversion_fn), 0x0,
			"The power per antenna of the PHICH with respect to the reference signal", HFILL }
		},
		{ &hf_nfapi_configuration_index,
			{ "Configuration Index", "nfapi.configuration.index",
			FT_UINT16, BASE_DEC, NULL, 0x0,
			"Provides information about the location and format of the PRACH.", HFILL }
		},
		{ &hf_nfapi_root_sequence_index,
			{ "Root sequence Index", "nfapi.root.sequence.index",
			FT_UINT16, BASE_DEC, NULL, 0x0,
			"PRACH Root sequence Index", HFILL }
		},
		{ &hf_nfapi_zero_correlation_zone_configuration,
			{ "Zero correlation zone configuration", "nfapi.zero.correlation.zone.configuration",
			FT_UINT16, BASE_DEC, NULL, 0x0,
			"Equivalent to Ncs", HFILL }
		},
		{ &hf_nfapi_high_speed_flag,
			{ "High Speed Flag", "nfapi.high.speed.flag",
			FT_BOOLEAN, 8, TFS(&high_speed_flag_strname), 0x0,
			"Indicates if unrestricted, or restricted, set of preambles is used", HFILL }
		},
		{ &hf_nfapi_frequency_offset,
			{ "Frequency offset", "nfapi.frequency.offset",
			FT_UINT16, BASE_DEC, NULL, 0x0,
			"The first physical resource block available for PRACH", HFILL }
		},
		{ &hf_nfapi_hopping_mode,
			{ "Hopping Mode", "nfapi.hopping.mode",
			FT_BOOLEAN, 8, TFS(&hopping_mode_strname), 0x0,
			"If hopping is enabled indicates the type of hopping used", HFILL }
		},
		{ &hf_nfapi_hopping_offset,
			{ "Hopping offset", "nfapi.hopping.offset",
			FT_UINT16, BASE_DEC, NULL, 0x0,
			"The offset used if hopping is enabled", HFILL }
		},
		{ &hf_nfapi_delta_pucch_shift,
			{ "Delta PUCCH Shift", "nfapi.delta.pucch.shift",
			FT_UINT16, BASE_DEC, NULL, 0x0,
			"The cyclic shift difference", HFILL }
		},
		{ &hf_nfapi_n_cqi_rb,
			{ "N CQI RB", "nfapi.n.cqi.rb",
			FT_UINT16, BASE_DEC, NULL, 0x0,
			"The bandwidth, in units of resource blocks, that is available for use by PUCCH formats 2/2a/2b transmission in each slot", HFILL }
		},
		{ &hf_nfapi_n_an_cs,
			{ "N AN CS", "nfapi.n.an.cs",
			FT_UINT16, BASE_DEC, NULL, 0x0,
			"The number of cyclic shifts used for PUCCH formats 1/1a/1b in a resource block with a mix of formats 1/a/1/ab and 2/2a/2b.", HFILL }
		},
		{ &hf_nfapi_n1_pucch_an,
			{ "N1 PUCCH AN", "nfapi.n1.pucch.an",
			FT_UINT16, BASE_DEC, NULL, 0x0,
			"N1 PUCCH", HFILL }
		},
		{ &hf_nfapi_bandwidth_configuration,
			{ "Bandwidth configuration", "nfapi.bw.configuration",
			FT_UINT16, BASE_DEC, NULL, 0x0,
			"The available SRS bandwidth of the cell", HFILL }
		},
		{ &hf_nfapi_srs_subframe_configuration,
			{ "SRS subframe configuration", "nfapi.srs.subframe.configuration",
			FT_UINT16, BASE_DEC, NULL, 0x0,
			"The subframe configuration. Needed if semi-static configuration is held in PHY", HFILL }
		},
		{ &hf_nfapi_uplink_rs_hopping,
			{ "Uplink RS hopping", "nfapi.uplink.rs.hopping",
			FT_UINT16, BASE_DEC, VALS(nfapi_uplink_rs_hopping_vals), 0x0,
			"Indicates the type of hopping to use", HFILL }
		},
		{ &hf_nfapi_group_assignment,
			{ "Group assignment", "nfapi.group.assignment",
			FT_UINT16, BASE_DEC, NULL, 0x0,
			"The sequence shift pattern used if group hopping is enabled", HFILL }
		},
		{ &hf_nfapi_cyclic_shift_1_for_drms,
			{ "Cyclic Shift 1 for DRMS", "nfapi.cyclic.shift.1.for.drms",
			FT_UINT16, BASE_DEC, NULL, 0x0,
			"Specifies the cyclic shift for the reference signal used in the cell.", HFILL }
		},
		{ &hf_nfapi_subframe_assignment,
			{ "Subframe_assignment", "nfapi.subframe.assignment",
			FT_UINT16, BASE_DEC, NULL, 0x0,
			"For TDD mode only, indicates the DL/UL subframe structure", HFILL }
		},
		{ &hf_nfapi_special_subframe_patterns,
			{ "Special Subframe patterns", "nfapi.special.subframe.patterns",
			FT_UINT16, BASE_DEC, NULL, 0x0,
			"For TDD mode only. Length of fields DwPTS, GP and UpPTS", HFILL }
		},
		{ &hf_nfapi_ed_threshold_for_lbt_for_pdsch,
			{ "ED Threshold for LBT for PDSCH", "nfapi.ed.threshold.for.lbt.pdsch",
			FT_UINT16, BASE_CUSTOM, CF_FUNC(laa_threshold_conversion_fn), 0x0,
			"Indicates the energy detection threshold in dBm for LBT for PDSCH", HFILL }
		},
		{ &hf_nfapi_ed_threshold_for_lbt_for_drs,
			{ "ED Threshold for LBT for DRS", "nfapi.ed.threshold.for.lbt.for.drs",
			FT_UINT16, BASE_CUSTOM, CF_FUNC(laa_threshold_conversion_fn), 0x0,
			"Indicates the energy detection threshold in dBm for LBT for DRS", HFILL }
		},
		{ &hf_nfapi_pd_threshold,
			{ "PD Threshold", "nfapi.pd.threshold",
			FT_UINT16, BASE_CUSTOM, CF_FUNC(laa_threshold_conversion_fn), 0x0,
			"Indicates the preamble detection threshold in dBm, if the L1 capabilities support PD", HFILL }
		},
		{ &hf_nfapi_multi_carrier_type,
			{ "Multi carrier type", "nfapi.multi.carrier.type",
			FT_UINT16, BASE_DEC, VALS(nfapi_laa_carrier_type_vals), 0x0,
			"Indicates multi carrier type configuration of L1 (according to L1 capabilities and L2 scheduler requirements", HFILL }
		},
		{ &hf_nfapi_multi_carrier_tx,
			{ "Multi carrier TX", "nfapi.multi.carrier.tx",
			FT_BOOLEAN, 8, TFS(&nfapi_multi_carrier_tx_strname), 0x0,
			"Indicates multi carrier transmission configuration of L1 (according to type if supporting multi carrier)", HFILL }
		},
		{ &hf_nfapi_multi_carrier_freeze,
			{ "Multi carrier freeze", "nfapi.multi.carrier.freeze",
			FT_BOOLEAN, 8, TFS(&nfapi_multi_carrier_freeze_strname), 0x0,
			"Indicates multi carrier freeze, configuration of L1 (applicable only to type A type if supporting multi carrier)", HFILL }
		},
		{ &hf_nfapi_tx_antenna_ports_for_drs,
			{ "Tx antenna ports for DRS", "nfapi.tx.antenna.ports.for.drs",
			FT_UINT16, BASE_DEC, NULL, 0x0,
			"The number of cell specific transmit antenna ports within the DRS occasions", HFILL }
		},
		{ &hf_nfapi_transmission_power_for_drs,
			{ "Transmission power for DRS", "nfapi.transmission.power.for.drs",
			FT_UINT16, BASE_CUSTOM, CF_FUNC(power_offset_conversion_fn), 0x0,
			"Offset of cell specific Reference signals power within DRS occasions to the reference signal power", HFILL }
		},
		{ &hf_nfapi_pbch_repetitions_enabled_r13,
			{ "PBCH Repetitions enable R13", "nfapi.pbch.repetitions.enabled_r13",
			FT_BOOLEAN, 8, TFS(&tfs_enabled_disabled), 0x0,
			"Enable / Disable PBCH repetitions", HFILL }
		},
		{ &hf_nfapi_prach_cat_m_root_sequence_index,
			{ "PRACH CAT-M Root sequence Index", "nfapi.prach.cat_m.root.squence.index",
			FT_UINT16, BASE_DEC, NULL, 0x0,
			"PRACH Root sequence Index", HFILL }
		},
		{ &hf_nfapi_prach_cat_m_zero_correlation_zone_configuration,
			{ "PRACH CAT-M Zero correlation zone configuration", "nfapi.prach.cat_m.zero.correlation.zone.configuration",
			FT_UINT16, BASE_DEC, NULL, 0x0,
			"Equivalent to Ncs", HFILL }
		},
		{ &hf_nfapi_prach_cat_m_high_speed_flag,
			{ "PRACH CAT-M High speed flag", "nfapi.prach.cat_m.high.speed.flag",
			FT_BOOLEAN, 8, TFS(&high_speed_flag_strname), 0x0,
			"Indicates if unrestricted, or restricted, set of preambles is used", HFILL }
		},
		{ &hf_nfapi_prach_ce_level_0_enable,
			{ "PRACH CE level #0 Enable", "nfapi.prach.ce.level.0.enable",
			FT_BOOLEAN, 8, TFS(&tfs_enabled_disabled), 0x0,
			"Enable \\ Disable CE level #0.", HFILL }
		},
		{ &hf_nfapi_prach_ce_level_0_configuration_index,
			{ "PRACH CE level #0 Configuration Index", "nfapi.prach.ce.level.0.configuration.index",
			FT_UINT16, BASE_DEC, NULL, 0x0,
			"Provides information about the location and format of the PRACH", HFILL }
		},
		{ &hf_nfapi_prach_ce_level_0_frequency_offset,
			{ "PRACH CE level #0 Frequency offset", "nfapi.prach.ce.level.0.frequency_offset",
			FT_UINT16, BASE_DEC, NULL, 0x0,
			"The first physical resource block available for PRACH for each CE", HFILL }
		},
		{ &hf_nfapi_prach_ce_level_0_number_of_repetitions_per_attempt,
			{ "PRACH CE level #0 Number of repetitions per attempt", "nfapi.prach.ce.level.0.number.of.repetitions.per_attempt",
			FT_UINT16, BASE_DEC, NULL, 0x0,
			"Number of PRACH repetitions per attempt for each CE level", HFILL }
		},
		{ &hf_nfapi_prach_ce_level_0_starting_subframe_periodicity,
			{ "CE level #0 Starting subframe periodicity", "nfapi.prach.ce.level.0.starting.subframe_periodicity",
			FT_UINT16, BASE_DEC, NULL, 0x0,
			"Optional. PRACH starting subframe periodicity, expressed in number of slots available for preamble transmission(PRACH opportunities)", HFILL }
		},
		{ &hf_nfapi_prach_ce_level_0_hopping_enabled,
			{ "PRACH CE level #0 Hopping Enable", "nfapi.prach.ce.level.0.hopping_enable",
			FT_BOOLEAN, 8, TFS(&tfs_enabled_disabled), 0x0,
			"Enable \\ Disable PRACH frequency hopping for each CE level", HFILL }
		},
		{ &hf_nfapi_prach_ce_level_0_hopping_offset,
			{ "PRACH CE level #0 Hopping Offset", "nfapi.prach.ce.level.0.hopping.offset",
			FT_UINT16, BASE_DEC, NULL, 0x0,
			"Valid in case 'PRACH Hopping Enable' is enabled", HFILL }
		},
		{ &hf_nfapi_prach_ce_level_1_enable,
			{ "PRACH CE level #1 Enable", "nfapi.prach.ce.level.0.enable",
			FT_BOOLEAN, 8, TFS(&tfs_enabled_disabled), 0x0,
			"Enable \\ Disable CE level #1", HFILL }
		},
		{ &hf_nfapi_prach_ce_level_1_configuration_index,
			{ "PRACH CE level #1 Configuration Index", "nfapi.prach.ce.level.1.configuration.index",
			FT_UINT16, BASE_DEC, NULL, 0x0,
			"Provides information about the location and format of the PRACH", HFILL }
		},
		{ &hf_nfapi_prach_ce_level_1_frequency_offset,
			{ "PRACH CE level #1 Frequency offset", "nfapi.prach.ce.level.1.frequency_offset",
			FT_UINT16, BASE_DEC, NULL, 0x0,
			"The first physical resource block available for PRACH for each CE", HFILL }
		},
		{ &hf_nfapi_prach_ce_level_1_number_of_repetitions_per_attempt,
			{ "PRACH CE level #1 Number of repetitions per attempt", "nfapi.prach.ce.level.1.number.of.repetitions.per_attempt",
			FT_UINT16, BASE_DEC, NULL, 0x0,
			"Number of PRACH repetitions per attempt for each CE level", HFILL }
		},
		{ &hf_nfapi_prach_ce_level_1_starting_subframe_periodicity,
			{ "CE level #1 Starting subframe periodicity", "nfapi.prach.ce.level.1.starting.subframe_periodicity",
			FT_UINT16, BASE_DEC, NULL, 0x0,
			"Optional.PRACH starting subframe periodicity, expressed in number of slots available for preamble transmission(PRACH opportunities),", HFILL }
		},
		{ &hf_nfapi_prach_ce_level_1_hopping_enabled,
			{ "PRACH CE level #1 Hopping Enable", "nfapi.prach.ce.level.1.hopping_enable",
			FT_BOOLEAN, 8, TFS(&tfs_enabled_disabled), 0x0,
			"Enable \\ Disable PRACH frequency hopping for each CE level.", HFILL }
		},
		{ &hf_nfapi_prach_ce_level_1_hopping_offset,
			{ "PRACH CE level #1 Hopping Offset", "nfapi.prach.ce.level.1.hopping.offset",
			FT_UINT16, BASE_DEC, NULL, 0x0,
			"Valid in case 'PRACH Hopping Enable' is enabled.", HFILL }
		},
		{ &hf_nfapi_prach_ce_level_2_enable,
			{ "PRACH CE level #2 Enable", "nfapi.prach.ce.level.2.enable",
			FT_BOOLEAN, 8, TFS(&tfs_enabled_disabled), 0x0,
			"Enable \\ Disable CE level #2", HFILL }
		},
		{ &hf_nfapi_prach_ce_level_2_configuration_index,
			{ "PRACH CE level #2 Configuration Index", "nfapi.prach.ce.level.2.configuration.index",
			FT_UINT16, BASE_DEC, NULL, 0x0,
			"Provides information about the location and format of the PRACH", HFILL }
		},
		{ &hf_nfapi_prach_ce_level_2_frequency_offset,
			{ "PRACH CE level #2 Frequency offset", "nfapi.prach.ce.level.2.frequency_offset",
			FT_UINT16, BASE_DEC, NULL, 0x0,
			"The first physical resource block available for PRACH for each CE", HFILL }
		},
		{ &hf_nfapi_prach_ce_level_2_number_of_repetitions_per_attempt,
			{ "PRACH CE level #2 Number of repetitions per attempt", "nfapi.prach.ce.level.2.number.of.repetitions.per_attempt",
			FT_UINT16, BASE_DEC, NULL, 0x0,
			"Number of PRACH repetitions per attempt for each CE level", HFILL }
		},
		{ &hf_nfapi_prach_ce_level_2_starting_subframe_periodicity,
			{ "CE level #2 Starting subframe periodicity", "nfapi.prach.ce.level.2.starting.subframe_periodicity",
			FT_UINT16, BASE_DEC, NULL, 0x0,
			"Optional. PRACH starting subframe periodicity, expressed in number of slots available for preamble transmission(PRACH opportunities)", HFILL }
		},
		{ &hf_nfapi_prach_ce_level_2_hopping_enabled,
			{ "PRACH CE level #2 Hopping Enable", "nfapi.prach.ce.level.2.hopping_enable",
			FT_BOOLEAN, 8, TFS(&tfs_enabled_disabled), 0x0,
			"Enable \\ Disable PRACH frequency hopping for each CE level", HFILL }
		},
		{ &hf_nfapi_prach_ce_level_2_hopping_offset,
			{ "PRACH CE level #2 Hopping Offset", "nfapi.prach.ce.level.2.hopping.offset",
			FT_UINT16, BASE_DEC, NULL, 0x0,
			"Valid in case 'PRACH Hopping Enable' is enabled.", HFILL }
		},
		{ &hf_nfapi_prach_ce_level_3_enable,
			{ "PRACH CE level #3 Enable", "nfapi.prach.ce.level.3.enable",
			FT_BOOLEAN, 8, TFS(&tfs_enabled_disabled), 0x0,
			"Enable \\ Disable CE level #3.", HFILL }
		},
		{ &hf_nfapi_prach_ce_level_3_configuration_index,
			{ "PRACH CE level #3 Configuration Index", "nfapi.prach.ce.level.3.configuration.index",
			FT_UINT16, BASE_DEC, NULL, 0x0,
			"Provides information about the location and format of the PRACH.", HFILL }
		},
		{ &hf_nfapi_prach_ce_level_3_frequency_offset,
			{ "PRACH CE level #3 Frequency offset", "nfapi.prach.ce.level.3.frequency_offset",
			FT_UINT16, BASE_DEC, NULL, 0x0,
			"The first physical resource block available for PRACH for each CE", HFILL }
		},
		{ &hf_nfapi_prach_ce_level_3_number_of_repetitions_per_attempt,
			{ "PRACH CE level #3 Number of repetitions per attempt", "nfapi.prach.ce.level.3.number.of.repetitions.per_attempt",
			FT_UINT16, BASE_DEC, NULL, 0x0,
			"Number of PRACH repetitions per attempt for each CE level", HFILL }
		},
		{ &hf_nfapi_prach_ce_level_3_starting_subframe_periodicity,
			{ "CE level #3 Starting subframe periodicity", "nfapi.prach.ce.level.3.starting.subframe_periodicity",
			FT_UINT16, BASE_DEC, NULL, 0x0,
			"Optional. PRACH starting subframe periodicity, expressed in number of slots available for preamble transmission(PRACH opportunities)", HFILL }
		},
		{ &hf_nfapi_prach_ce_level_3_hopping_enabled,
			{ "PRACH CE level #3 Hopping Enable", "nfapi.prach.ce.level.3.hopping_enable",
			FT_BOOLEAN, 8, TFS(&tfs_enabled_disabled), 0x0,
			"Enable \\ Disable PRACH frequency hopping for each CE level.", HFILL }
		},
		{ &hf_nfapi_prach_ce_level_3_hopping_offset,
			{ "PRACH CE level #3 Hopping Offset", "nfapi.prach.ce.level.3.hopping.offset",
			FT_UINT16, BASE_DEC, NULL, 0x0,
			"Valid in case 'PRACH Hopping Enable' is enabled.", HFILL }
		},
		{ &hf_nfapi_pucch_internal_ul_hopping_config_common_mode_a,
			{ "PUCCH Interval-ULHoppingConfigCommonModeA", "nfapi.pucch.interval.ulhopping.config.common.mode.a",
			FT_UINT16, BASE_DEC, NULL, 0x0,
			"NthULNB for UEModeA", HFILL }
		},
		{ &hf_nfapi_pucch_internal_ul_hopping_config_common_mode_b,
			{ "PUCCH Interval-ULHoppingConfigCommonModeB", "nfapi.pucch.interval.ulhopping.config.common.mode.b",
			FT_UINT16, BASE_DEC, NULL, 0x0,
			"NthULNB for UEModeB", HFILL }
		},
		{ &hf_nfapi_data_report_mode,
			{ "Data Report Mode", "nfapi.data.report.mode",
			FT_BOOLEAN, 8, TFS(&data_report_mode_vals), 0x0,
			"The data report mode for the uplink data", HFILL }
		},
		{ &hf_nfapi_sfnsf,
			{ "SFN/SF", "nfapi.sfn.sf",
			FT_UINT16, BASE_CUSTOM, CF_FUNC(sfn_sf_conversion_fn), 0x0,
			"The future SFN/SF subframe where the TLVs included in the message should be applied", HFILL }
		},
		{ &hf_nfapi_max_up_pts,
			{ "Max UpPTS frames", "nfapi.max.uppts.frame",
			FT_BOOLEAN, 8, TFS(&tfs_enabled_disabled), 0x0,
			"Used for TDD only and indicates how SRS operates in UpPTS subframes", HFILL }
		},
		{ &hf_nfapi_srs_acknack_srs_simultaneous_transmission,
			{ "SRS AckNack Simultaneous transmission", "nfapi.srs.acknack.simult.tx",
			FT_BOOLEAN, 8, TFS(&srs_simult_tx_strname), 0x0,
			"Indicates if SRS and ACK/NACK can be received in the same subframe. Needed if semi-static configuration is held in PHY.", HFILL }
		},
		{ &hf_nfapi_pnf_address_ipv4,
			{ "PNF IPV4", "nfapi.pnf.address.ipv4",
			FT_IPv4, BASE_NONE, NULL, 0x0,
			"The IPv4 address of the PNF PHY instance to be used by the VNF for this PNF PHY instance", HFILL }
		},
		{ &hf_nfapi_pnf_address_ipv6,
			{ "PNF IPV6", "nfapi.pnf.address.ipv6",
			FT_IPv6, BASE_NONE, NULL, 0x0,
			"The IPv6 address of the PNF PHY instance to be used by the VNF for this PNF PHY instance", HFILL }
		},
		{ &hf_nfapi_vnf_address_ipv4,
			{ "VNF IPV4 Address", "nfapi.vnf.address.ipv4",
			FT_IPv4, BASE_NONE, NULL, 0x0,
			"The IPv4 address of the VNF to be used by the PNF for this P7 PHY instance", HFILL }
		},
		{ &hf_nfapi_vnf_address_ipv6,
			{ "VNF IPV6 Address", "nfapi.vnf.address.ipv6",
			FT_IPv6, BASE_NONE, NULL, 0x0,
			"The IPv6 address of the VNF to be used by the PNF for this P7 PHY instance", HFILL }
		},
		{ &hf_nfapi_pnf_port,
			{ "PNF PORT value", "nfapi.config.pnf.port.value",
			FT_UINT16, BASE_DEC, NULL, 0x0,
			"The port of the PNF PHY instance to be used by the VNF for this PNF PHY instance", HFILL }
		},
		{ &hf_nfapi_vnf_port,
			{ "VNF PORT value", "nfapi.config.vnf.port.value",
			FT_UINT16, BASE_DEC, NULL, 0x0,
			"The port of the VNF to be used by the PNF for this P7 PHY instance", HFILL } },
		{ &hf_nfapi_sync_mode,
			{ "Sync Mode", "nfapi.sync.mode",
			FT_UINT8, BASE_DEC, VALS(nfapi_sync_mode_vals), 0x0,
			"The method of nFAPI Synchronization supported by the PNF", HFILL }
		},
		{ &hf_nfapi_location_mode,
			{ "Location Mode", "nfapi.location.mode",
			FT_UINT8, BASE_DEC, VALS(location_mode_vals), 0x0,
			"The method of location derivation supported by the PNF", HFILL }
		},
		{ &hf_nfapi_location_coordinates,
			{ "Location Coordinates", "nfapi.location.coordinates",
			FT_UINT_BYTES, BASE_NONE, NULL, 0x0,
			"The Location of the PNF. The value is formatted as the LocationCoordinates IE using BASIC-PER encoding as defined in "
			"TS36.355 section 6.4.2. The first bit of the LocationCoordinates IE is in the LSB of the first byte of the array."
			"The MSBs of the last element of the array may be padded with zeros if the ASN.1 element is not an integer number of bytes", HFILL }
		},
		{ &hf_nfapi_pdu,
			{ "PDU", "nfapi.pdu",
			FT_BYTES, BASE_NONE, NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_nfapi_dl_config_timing,
			{ "DL config Timing", "nfapi.dl.config.timing",
			FT_UINT32, BASE_DEC | BASE_UNIT_STRING, &units_milliseconds, 0x0,
			"The timing offset before the air interface subframe start that the DL_Config.request must be received at the PNF.", HFILL }
		},
		{ &hf_nfapi_tx_timing,
			{ "Tx Timing", "nfapi.general.tx.timing",
			FT_UINT32, BASE_DEC | BASE_UNIT_STRING, &units_milliseconds, 0x0,
			"The timing offset before the air interface subframe start that the TX.request must be received at the PNF.", HFILL }
		},
		{ &hf_nfapi_ul_config_timing,
			{ "UL Config Timing", "nfapi.ul.config.timing",
			FT_UINT32, BASE_DEC | BASE_UNIT_STRING, &units_milliseconds, 0x0,
			"The timing offset before the air interface subframe start that the UL_CONFIG.request must be received at the PNF.", HFILL }
		},
		{ &hf_nfapi_hi_dci0_timing,
			{ "HI DCi0 Timing", "nfapi.hi.dci0.timing",
			FT_UINT32, BASE_DEC | BASE_UNIT_STRING, &units_milliseconds, 0x0,
			"The timing offset before the air interface subframe start that the HI_DCI0.request must be received at the PNF.", HFILL }
		},
		{ &hf_nfapi_maximum_number_phys,
			{ "Maximum number of Phys", "nfapi.maximum.number.phys",
			FT_UINT16, BASE_DEC, NULL, 0x0,
			"The maximum number of operational PHYs supported by the PNF device.", HFILL }
		},
		{ &hf_nfapi_maximum_total_bandwidth,
			{ "Maximum Total Bandwidth", "nfapi.maximum.total.bandwidth",
			FT_UINT16, BASE_DEC | BASE_UNIT_STRING, &khz_100_units_db, 0x0,
			"The total maximum bandwidth (in units of 100kHz) supported by the PNF device.", HFILL }
		},
		{ &hf_nfapi_maximum_total_number_dl_layers,
			{ "Maximum Total Number DL Layers", "nfapi.maximum.total.number.dl.layers",
			FT_UINT16, BASE_DEC, NULL, 0x0,
			"The maximum total number of downlink layers supported.", HFILL }
		},
		{ &hf_nfapi_maximum_total_number_ul_layers,
			{ "Maximum Total Number UL Layers", "nfapi.maximum.total.number.ul.layers",
			FT_UINT16, BASE_DEC, NULL, 0x0,
			"The maximum total number of uplink layers supported across all available PHYs.", HFILL }
		},
		{ &hf_nfapi_shared_bands,
			{ "Shared bands", "nfapi.shared.bands",
			FT_BOOLEAN, 8, TFS(&tfs_true_false), 0x0,
			"Indication that the PNF device shares the list of RF band options available across all available PHYs, so each may only be used with a single PHY.", HFILL }
		},
		{ &hf_nfapi_shared_pa,
			{ "Shared pa", "nfapi.shared.pa",
			FT_BOOLEAN, 8, TFS(&tfs_true_false), 0x0,
			"Indication that the PNF device shares a single RF PA across all available PHYs, so that the maximum Total Power is shared across all available PHYs.", HFILL }
		},
		{ &hf_nfapi_maximum_total_power,
			{ "Maximum total power", "nfapi.maximum.total.power",
			FT_UINT16, BASE_CUSTOM, CF_FUNC(dl_rs_tx_pow_measment_conversion_fn), 0x0,
			"The maximum transmit power of the PNF device summed across all PHYs.", HFILL }
		},
		{ &hf_nfapi_oui,
			{ "OUI", "nfapi.oui",
			FT_STRING, BASE_NONE, NULL, 0x0,
			"The PNF OUI in the format as specified by IEEE", HFILL }
		},
		{ &hf_nfapi_pnf_phy_number_phy,
			{ "PNF Phy Number of Phy", "nfapi.pnf.phy.number.phy",
			FT_UINT16, BASE_DEC, NULL, 0x0,
			"The number of PHY instances", HFILL }
		},
		{ &hf_nfapi_pnf_phy_config_index,
			{ "PNF Phy Config Index", "nfapi.pnf.phy.config.index",
			FT_UINT16, BASE_DEC, NULL, 0x0,
			"The unique Index number of the PHY to permit the PNF to identify the PHY in the PNF_CONFIG.Request", HFILL }
		},
		{ &hf_nfapi_number_of_rfs,
			{ "Number of RFs", "nfapi.pnf.rf.number.rf",
			FT_UINT16, BASE_DEC, NULL, 0x0,
			"The number of RF configurations", HFILL }
		},
		{ &hf_nfapi_phy_rf_config_info_phy_id,
			{ "Phy ID", "nfapi.pnf.phy.rf.config.phy.id",
			FT_UINT16, BASE_DEC, NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_nfapi_rf_config_index,
			{ "RF Config Index", "nfapi.rf_config_index",
			FT_UINT16, BASE_DEC, NULL, 0x0,
			"The Index number defined in the PNF RF struct that the PHY can support",
			HFILL }
		},
		{ &hf_nfapi_number_of_rf_exclusions,
			{ "Number of RF exclusions", "nfapi.hf_nfapi_number_of_rf_exclusions",
			FT_UINT16, BASE_DEC, NULL, 0x0,
			"The number of RF configurations excluded from use by this PHY", HFILL }
		},
		{ &hf_nfapi_maximum_3gpp_release_supported,
			{ "Maximum 3gpp Release Supported", "nfapi.maximum_3gpp_release_supported",
			FT_UINT16, BASE_HEX, NULL, 0x0,
			"The major 3GPP releases supported", HFILL }
		},
		{ &hf_nfapi_maximum_3gpp_release_supported_rel8,
			{ "Release 8", "nfapi.maximum_3gpp_release_supported.rel8",
			FT_BOOLEAN, 16, NULL, 0x0001,
			NULL, HFILL }
		},
		{ &hf_nfapi_maximum_3gpp_release_supported_rel9,
			{ "Release 9", "nfapi.maximum_3gpp_release_supported.rel9",
			FT_BOOLEAN, 16, NULL, 0x0002,
			NULL, HFILL }
		},
		{ &hf_nfapi_maximum_3gpp_release_supported_rel10,
			{ "Release 10", "nfapi.maximum_3gpp_release_supported.rel10",
			FT_BOOLEAN, 16, NULL, 0x0004,
			NULL, HFILL }
		},
		{ &hf_nfapi_maximum_3gpp_release_supported_rel11,
			{ "Release 11", "nfapi.maximum_3gpp_release_supported.rel11",
			FT_BOOLEAN, 16, NULL, 0x0008,
			NULL, HFILL }
		},
		{ &hf_nfapi_maximum_3gpp_release_supported_rel12,
			{ "Release 12", "nfapi.maximum_3gpp_release_supported.rel12",
			FT_BOOLEAN, 16, NULL, 0x0010,
			NULL, HFILL }
		},
		{ &hf_nfapi_maximum_3gpp_release_supported_rel13,
			{ "Release 13", "nfapi.maximum_3gpp_release_supported.rel13",
			FT_BOOLEAN, 16, NULL, 0x0020,
			NULL, HFILL }
		},
		{ &hf_nfapi_downlink_channel_bandwidth_supported,
			{ "Maximum Channel Downlink Bandwidth Supported", "nfapi.downlink_channel_bandwidth_supported",
			FT_UINT16, BASE_DEC, NULL, 0x0,
			"The downlink channel bandwidth supported in resource blocks as specified in 3GPP TS 36.104", HFILL }
		},
		{ &hf_nfapi_uplink_channel_bandwidth_supported,
			{ "Maximum Channel Uplink Bandwidth Supported", "nfapi.uplink_channel_bandwidth_supported",
			FT_UINT16, BASE_DEC, NULL, 0x0,
			"The uplink channel bandwidth supported in resource blocks as specified in 3GPP TS 36.104.", HFILL }
		},
		{ &hf_nfapi_number_of_dl_layers_supported,
			{ "Number of DL Layers Supported", "nfapi.number_of_dl_layer_supported",
			FT_UINT16, BASE_DEC, NULL, 0x0,
			"The maximum number of downlink layers supported", HFILL }
		},
		{ &hf_nfapi_number_of_ul_layers_supported,
			{ "Number of UL Layers Supported", "nfapi.number_of_ul_layer_supported",
			FT_UINT16, BASE_DEC, NULL, 0x0,
			"The maximum number of uplink layers supported", HFILL }
		},
		{ &hf_nfapi_nmm_modes_supported,
			{ "NMM modes supported", "nfapi.nmm_modes_supported",
			FT_UINT8, BASE_DEC, VALS(nmm_modes_supported_vals), 0x0,
			"Network Monitor Modes Supported.", HFILL }
		},
		{ &hf_nfapi_band,
			{ "Band", "nfapi.band",
			FT_UINT16, BASE_DEC, NULL, 0x0,
			"Band number as specified in 3GPP TS36.101", HFILL }
		},
		{ &hf_nfapi_maximum_transmit_power_2,
			{ "Maximum transmit power", "nfapi.maximum_transmit_power",
			FT_UINT16, BASE_CUSTOM, CF_FUNC(max_transmit_power_2_conversion_fn), 0x0,
			"The maximum transmit power for the PHY and RF operating at the configured bandwidth as defined in 3GPP TS 36.104.", HFILL }
		},
		{ &hf_nfapi_maximum_transmit_power,
			{ "Maximum transmit power", "nfapi.maximum_transmit_power",
			FT_UINT16, BASE_CUSTOM, CF_FUNC(max_transmit_power_conversion_fn), 0x0,
			"The maximum transmit power for the RF chain operating at the maximum supported bandwidth as defined in 3GPP TS 36.104.", HFILL }
		},
		{ &hf_nfapi_earfcn,
			{ "EARFCN", "nfapi.earfcn",
			FT_UINT16, BASE_DEC, NULL, 0x0,
			"The EARFCN to be measured.", HFILL }
		},
		{ &hf_nfapi_number_of_rf_bands,
			{ "Number of RF Bands", "nfapi.num.rf_bands",
			FT_UINT16, BASE_DEC, NULL, 0x0,
			"The number of RF Band instances", HFILL }
		},
		{ &hf_nfapi_nmm_uplink_rssi_supported,
			{ "NMM Uplink RSSI supported", "nfapi.nmm.uplink.rssi.supported",
			FT_UINT8, BASE_DEC, VALS(ul_rssi_supported_vals), 0x0,
			"Indicates if the uplink RSSI meausremnts are supported by NMM.", HFILL }
		},
		{ &hf_nfapi_minimum_transmit_power,
			{ "Minimum transmit power", "nfapi.minimum_transmit_power",
			FT_UINT16, BASE_CUSTOM, CF_FUNC(max_transmit_power_conversion_fn), 0x0,
			"The minimum transmit power for the RF chain operating at the maximum supported bandwidth as defined in 3GPP TS 36.104.", HFILL }
		},
		{ &hf_nfapi_number_of_antennas_suppported,
			{ "Number of Supported Antennas", "nfapi.number_of_antennas_suppported",
			FT_UINT8, BASE_DEC, NULL, 0x0,
			"The maximum number of antennas supported.", HFILL }
		},
		{ &hf_nfapi_minimum_downlink_frequency,
			{ "Minimum downlink frequency", "nfapi.minimum_downlink_frequency",
			FT_UINT32, BASE_DEC | BASE_UNIT_STRING, &khz_100_units_db, 0x0,
			"The minimum supported downlink frequency in 100kHz units", HFILL }
		},
		{ &hf_nfapi_maximum_downlink_frequency,
			{ "Maximum downlink frequency", "nfapi.maximum_downlink_frequency",
			FT_UINT32, BASE_DEC | BASE_UNIT_STRING, &khz_100_units_db, 0x0,
			"The maximum supported downlink frequency in 100kHz units", HFILL }
		},
		{ &hf_nfapi_minimum_uplink_frequency,
			{ "Minimum uplink frequency", "nfapi.minimum_downlink_frequency",
			FT_UINT32, BASE_DEC | BASE_UNIT_STRING, &khz_100_units_db, 0x0,
			"The minimum supported uplink frequency in 100kHz units", HFILL }
		},
		{ &hf_nfapi_maximum_uplink_frequency,
			{ "Maximum uplink frequency", "nfapi.maximum_downlink_frequency",
			FT_UINT32, BASE_DEC | BASE_UNIT_STRING, &khz_100_units_db, 0x0,
			"The maximum supported uplink frequency in 100kHz units", HFILL }
		},
		{ &hf_nfapi_transmission_mode7_supported,
			{ "Transmission Mode 7 Supported", "nfapi.pnf.phy_rel10.tx_mode7_supported",
			FT_UINT16, BASE_DEC, NULL, 0x0,
			"Indicates if PHY supports TM7 for PDSCH", HFILL }
		},
		{ &hi_nfapi_transmission_mode8_supported,
			{ "Transmission Mode 8 Supported", "nfapi.pnf.phy_rel10.tx_mode8_supported",
			FT_UINT16, BASE_DEC, NULL, 0x0,
			"Indicates if PHY supports TM8 for PDSCH", HFILL }
		},
		{ &hi_nfapi_two_antennas_ports_for_pucch,
			{ "Two antennas ports for PUCCH", "nfapi.pnf.phy_rel10.two_antennas_ports_for_pucch",
			FT_UINT16, BASE_DEC, NULL, 0x0,
			"Indicates if PHY supports PUCCH transmit diversity introduced in Release 10. Equivalent to two-AntennaPortsForPUCCH-r10 in TS36.306", HFILL }
		},
		{ &hi_nfapi_transmission_mode_9_supported,
			{ "Transmission Mode 9 Supported", "nfapi.pnf.phy_rel10.tx_mode9_supported",
			FT_UINT16, BASE_DEC, NULL, 0x0,
			"Indicates if PHY supports TM9 for PDSCH with 8 antennas and 8 CSI. Equivalent to tm9-With-8Tx-FDD-r10 in TS36.306", HFILL }
		},
		{ &hi_nfapi_simultaneous_pucch_pusch,
			{ "Simultaneous PUCCH PUSCH", "nfapi.pnf.simultaneous_pucch_pusch",
			FT_UINT16, BASE_DEC, NULL, 0x0,
			"Indicates if PHY supports UE sending simultaneous PUCCH and PUSCH introduced in Release 10. Equivalent to simultaneousPUCCH-PUSCH-r10 in TS36.306", HFILL }
		},
		{ &hi_nfapi_four_layer_tx_with_tm3_and_tm4,
			{ "Four layer Tx with TM3 and TM4", "nfapi.pnf.phy_rel10.layer_tx_with_tm3_and_tm4",
			FT_UINT16, BASE_DEC, NULL, 0x0,
			"Indicates if PHY supports four layer transmission for TM3 and TM4. Equivalent to fourLayerTM3-TM4-r10 in TS36.306", HFILL }
		},
		{ &hf_nfapi_epdcch_supported,
			{ "ePDCCH supported", "nfapi.pnf.phy_rel11.epdcch_supported",
			FT_UINT16, BASE_DEC, NULL, 0x0,
			"Indicates if PHY supports Enhanced PDCCH", HFILL }
		},
		{ &hi_nfapi_multi_ack_csi_reporting,
			{ "Multi ACK CSI reporting", "nfapi.pnf.phy_rel11.mutli_ack_csi_reporting",
			FT_UINT16, BASE_DEC, NULL, 0x0,
			"Indicates if PHY supports the multi ACK and CSI reporting required with CA and mixed FDD/TDD carriers. Equivalent to multiACK-CSI-Reporting-r11 in TS36.306", HFILL }
		},
		{ &hi_nfapi_pucch_tx_diversity_with_channel_selection,
			{ "PUCCH Tx diversity with channel selection", "nfapi.pnf.phy_rel11.tx_div_with_channel_selection",
			FT_UINT16, BASE_DEC, NULL, 0x0,
			"Indicates if PHY supports transmit diversity for PUCCH format 1b with channel selection. Equivalent to txDiv-PUCCH1b-ChSelect in TS36.306", HFILL }
		},
		{ &hi_nfapi_ul_comp_supported,
			{ "UL CoMP supported", "nfapi.pnf.phy_rel11.ul_comp_supported",
			FT_UINT16, BASE_DEC, NULL, 0x0,
			"Indicates if PHY supports UL CoMP", HFILL }
		},
		{ &hi_nfapi_transmission_mode_5_supported,
			{ "Transmission mode 5 supported", "nfapi.pnf.phy_rel11.tx_mode5_supported",
			FT_UINT16, BASE_DEC, NULL, 0x0,
			"Indicates if PHY supports TM5 for PDSCH", HFILL }
		},
		{ &hf_nfapi_csi_subframe_set,
			{ "CSI subframe set", "nfapi.pnf.phy_rel12.csi_subframe_set",
			FT_UINT16, BASE_DEC, NULL, 0x0,
			"Equivalent to csi-SubframeSet-r12 in TS36.306", HFILL }
		},
		{ &hi_nfapi_enhanced_4tx_codebook,
			{ "Enhanced 4TX codebook", "nfapi.pnf.phy_rel12.exhanced_t4x_codebook",
			FT_UINT16, BASE_DEC, NULL, 0x0,
			"Indicates if PHY supports the enhanced 4TX codebook. Equivalent to enhanced-4TxCodebook-r12 in TS36.306", HFILL }
		},
		{ &hi_nfapi_drs_supported,
			{ "DRS supported", "nfapi.pnf.phy_rel12.drs_supported",
			FT_UINT16, BASE_DEC, NULL, 0x0,
			"Indicates if PHY supports the Discovery Reference Signal", HFILL }
		},
		{ &hi_nfapi_ul_64qam_supported,
			{ "UL 64QAM supported", "nfapi.pnf.phy_rel12.ul_64qam_supported",
			FT_UINT16, BASE_DEC, NULL, 0x0,
			"Indicates if PHY support 64 QAM in the uplink", HFILL }
		},
		{ &hi_nfapi_transmission_mode_10_supported,
			{ "Transmission mode 10 supported", "nfapi.pnf.phy_rel12.tx_mode10_supported",
			FT_UINT16, BASE_DEC, NULL, 0x0,
			"Indicates if PHY supports TM10 for PDSCH (DL CoMP)", HFILL }
		},
		{ &hi_nfapi_alternative_tbs_indices,
			{ "Alternative TBS indices", "nfapi.pnf.phy_rel12.alternative_tbs_indices",
			FT_UINT16, BASE_DEC, NULL, 0x0,
			"Indicates if PHY supports the alternate TBS indices (256 QAM).  Equivalent to alternativeTBS-Indices-r12 in TS36.306", HFILL }
		},
		{ &hf_nfapi_pucch_format_4_supported,
			{ "PUCCH format 4 supported", "nfapi.pnf.phy_rel13.pucch_format4_supported",
			FT_UINT16, BASE_DEC, NULL, 0x0,
			"Indicates if PHY supports PUCCH format 4", HFILL }
		},
		{ &hf_nfapi_pucch_format_5_supported,
			{ "PUCCH format 5 supported", "nfapi.pnf.phy_rel13.pucch_format5_supported",
			FT_UINT16, BASE_DEC, NULL, 0x0,
			"Indicates if PHY supports PUCCH format 5", HFILL }
		},
		{ &hf_nfapi_more_than_5_ca_supported,
			{ "More than 5 CA support", "nfapi.pnf.phy_rel13.mode_than_5_ca_supported",
			FT_UINT16, BASE_DEC, NULL, 0x0,
			"Indicates if PHY supports features required for more than 5 CA support on PUSCH. Equivalent to uci-PUSCH-Ext-r13 in TS36.306", HFILL }
		},
		{ &hf_nfapi_laa_supported,
			{ "LAA supported", "nfapi.pnf.phy_rel13.laa_supported",
			FT_UINT16, BASE_DEC, NULL, 0x0,
			"Indicates if PHY supports DL LAA (subframe format 3)", HFILL }
		},
		{ &hf_nfapi_laa_ending_in_dwpts_supported,
			{ "LAA ending in DwPTS supported", "nfapi.pnf.phy_rel13.laa_ending_in_dwpts_supported",
			FT_UINT16, BASE_DEC, NULL, 0x0,
			"Indicates if PHY supports DL LAA ending in a DwPTS subframe. Equivalent to endingDwPTS-r13i n TS36.306", HFILL }
		},
		{ &hf_nfapi_laa_starting_in_second_slot_supported,
			{ "LAA starting in second slot Supported", "nfapi.pnf.phy_rel13.laa_starting_in_second_slot_supported",
			FT_UINT16, BASE_DEC, NULL, 0x0,
			"Indicates if PHY supports DL LAA starting in the second slot in a subframe. Equivalent to secondSlotStartingPosition-r13 in TS36.306", HFILL }
		},
		{ &hf_nfapi_beamforming_supported,
			{ "Beamforming Supported", "nfapi.pnf.phy_rel13.beamingforming_supported",
			FT_UINT16, BASE_DEC, NULL, 0x0,
			"Indicates if PHY supports beamforming (FD-MIMO Class B). Equivalent to beamformed-r13 in TS36.306", HFILL }
		},
		{ &hf_nfapi_csi_rs_enhancements_supported,
			{ "CSI-RS enhancements supported", "nfapi.pnf.phy_rel13.csi_rs_enchancements_supported",
			FT_UINT16, BASE_DEC, NULL, 0x0,
			"Indicates if PHY supports CSI-RS enhancements (FD-MIMO Class A). Equivalent to csi-RS-EnhancementsTDD-r13 in TS36.306", HFILL }
		},
		{ &hf_nfapi_drms_enhancements_supported,
			{ "DMRS enhancements supported", "nfapi.pnf.phy_rel13.drms_enhancements_supported",
			FT_UINT16, BASE_DEC, NULL, 0x0,
			"Indicates if PHY supports DMRS enhancements added in Release 13. Equivalent to dmrs-Enhancements-r13 in TS36.306", HFILL }
		},
		{ &hf_nfapi_srs_enhancements_supported,
			{ "SRS enhancements supported", "nfapi.pnf.phy_rel13.srs_enhancements_supported",
			FT_UINT16, BASE_DEC, NULL, 0x0,
			"Indicates if PHY supports SRS enhancements added in Release 13. Equivalent to srs-Enhancements-r13in TS36.306", HFILL }
		},
		{ &hf_nfapi_sfn_sf,
			{ "SFN_SF", "nfapi.sfn_sf",
			FT_UINT16, BASE_CUSTOM, CF_FUNC(sfn_sf_conversion_fn), 0x0,
			NULL, HFILL }
		},
		{ &hf_nfapi_number_pdcch_ofdm_symbols,
			{ "Number of PDCCH OFDM Symbols", "nfapi.number_pdcch_ofdm_symbols",
			FT_UINT8, BASE_DEC, NULL, 0x0,
			"The number of OFDM symbols for the PDCCH", HFILL }
		},
		{ &hf_nfapi_number_dci,
			{ "Number of DCI", "nfapi.number_dci",
			FT_UINT8, BASE_DEC, NULL, 0x0,
			"The number of DCI PDUs included in this message", HFILL }
		},
		{ &hf_nfapi_number_pdus,
			{ "Number of PDUs", "nfapi.number_pdu",
			FT_UINT16, BASE_DEC, NULL, 0x0,
			"Number of PDUs that are included in this message", HFILL }
		},
		{ &hf_nfapi_number_of_harqs,
			{ "Number of HARQs", "nfapi.number_harqs",
			FT_UINT16, BASE_DEC, NULL, 0x0,
			"Number of HARQs included in this message", HFILL }
		},
		{ &hf_nfapi_number_of_crcs,
			{ "Number of CRCs", "nfapi.number_crcs",
			FT_UINT16, BASE_DEC, NULL, 0x0,
			"Number of CRCs included in this message", HFILL }
		},
		{ &hf_nfapi_number_of_srs,
			{ "Number of SRs", "nfapi.number_srs",
			FT_UINT16, BASE_DEC, NULL, 0x0,
			"Number of SRs included in this message", HFILL }
		},
		{ &hf_nfapi_number_of_cqi,
			{ "Number of CQIs", "nfapi.number_cqi",
			FT_UINT16, BASE_DEC, NULL, 0x0,
			"Number of CQIs included in this message", HFILL }
		},
		{ &hf_nfapi_number_of_preambles,
			{ "Number of Preambles", "nfapi.number_preambles",
			FT_UINT16, BASE_DEC, NULL, 0x0,
			"Number of RACH preambles", HFILL }
		},
		{ &hf_nfapi_number_of_srss,
			{ "Number of SRSs", "nfapi.number_srss",
			FT_UINT16, BASE_DEC, NULL, 0x0,
			"Number of UEs contributing to the uplink SRS", HFILL }
		},
		{ &hf_nfapi_lbt_dl_req_pdu_type,
			{ "LBT DL Request PDU Type", "nfapi.number_srss",
			FT_UINT16, BASE_DEC, VALS(nfapi_lbt_dl_req_pdu_type), 0x0,
			NULL, HFILL }
		},
		{ &hf_nfapi_lbt_dl_ind_pdu_type,
			{ "LBT DL Indication PDU Type", "nfapi.number_srss",
			FT_UINT16, BASE_DEC, VALS(nfapi_lbt_dl_ind_pdu_type), 0x0,
			NULL, HFILL }
		},
		{ &hf_nfapi_number_pdsch_rnti,
			{ "Number of PDSCH RNTI", "nfapi.number_pdsch_rnti",
			FT_UINT8, BASE_DEC, NULL, 0x0,
			"Number of unique RNTIs sent on the PDSCH", HFILL }
		},
		{ &hf_nfapi_transmission_power_pcfich,
			{ "Transmission Power PCFICH", "nfapi.transmission_power_pcfich",
			FT_UINT16, BASE_CUSTOM, CF_FUNC(power_offset_conversion_fn), 0x0,
			"Offset to the reference signal power.", HFILL }
		},
		{ &hf_nfapi_dl_config_pdu_type,
			{ "PDU Type", "nfapi.pdu.type",
			FT_UINT8, BASE_DEC, VALS(nfapi_dl_config_pdu_type_vals), 0x0,
			"DL_CONFIG.request PDU Type", HFILL }
		},
		{ &hf_nfapi_pdu_size,
			{ "PDU size", "nfapi.pdu.size",
			FT_UINT8, BASE_DEC, NULL, 0x0,
			"Size of the PDU control information (in bytes). This length value includes the 2 bytes required for the PDU type and PDU size parameters", HFILL }
		},
		{ &hf_nfapi_instance_length,
			{ "Instance length", "nfapi.instance.length",
			FT_UINT16, BASE_DEC, NULL, 0x0,
			"The Length in bytes of all TLVs within this instance", HFILL }
		},
		{ &hf_nfapi_length,
			{ "PDU length", "nfapi.pdu.length",
			FT_UINT16, BASE_DEC, NULL, 0x0,
			"Length of PDU in bytes.", HFILL }
		},
		{ &hf_nfapi_pdu_index,
			{ "PDU Index", "nfapi.pdu.index",
			FT_UINT16, BASE_DEC, NULL, 0x0,
			"The PDU Index parameter specified for each PDU", HFILL }
		},
		{ &hf_nfapi_rnti,
			{ "RNTI", "nfapi.rnti",
			FT_UINT16, BASE_DEC, NULL, 0x0,
			"The RNTI used for identifying the UE when receiving the PDU", HFILL }
		},
		{ &hf_nfapi_resource_allocation_type,
			{ "Resource Allocation Type", "nfapi.resource.allocation.type",
			FT_UINT8, BASE_DEC, VALS(resource_allocation_type_vals), 0x0,
			"Resource allocation type/header Valid for DCI formats : 1, 2, 2A, 2B, 2C, 2D", HFILL }
		},
		{ &hf_nfapi_virtual_resource_block_assignment_flag,
			{ "Virtual resource block assignment flag", "nfapi.resource.block.assignment.flag",
			FT_UINT8, BASE_DEC, VALS(local_distributed_vals), 0x0,
			"Type of virtual resource block used Valid for DCI formats : 1A, 1B, 1D", HFILL }
		},
		{ &hf_nfapi_resource_block_coding,
			{ "Resource block coding", "nfapi.resource.block.coding",
			FT_UINT32, BASE_DEC, NULL, 0x0,
			"The encoding for the resource blocks. The coding is dependent on whether resource allocation type 0, 1, 2 is in use", HFILL }
		},
		{ &hf_nfapi_modulation,
			{ "Modulation", "nfapi.modulation",
			FT_UINT8, BASE_DEC, VALS(modulation_vals), 0x0,
			NULL, HFILL }
		},
		{ &hf_nfapi_redundancy_version,
			{ "Redundancy version", "nfapi.redundancy.version",
			FT_UINT8, BASE_DEC, NULL, 0x0,
			"HARQ redundancy version", HFILL }
		},
		{ &hf_nfapi_transport_blocks,
			{ "Transport blocks", "nfapi.transport.blocks",
			FT_UINT8, BASE_DEC, NULL, 0x0,
			"The transport block transmitted to this RNTI", HFILL }
		},
		{ &hf_nfapi_transport_block_to_codeword_swap_flag,
			{ "Transport block to codeword swap flag", "nfapi.transport.block.to.codeword.swap.flag",
			FT_UINT8, BASE_DEC, VALS(transport_block_to_codeword_swap_flag_vals), 0x0,
			"Indicates the mapping of transport block to codewords.", HFILL }
		},
		{ &hf_nfapi_transmission_scheme,
			{ "Transmission scheme", "nfapi.transmission.scheme",
			FT_UINT8, BASE_DEC, VALS(transmission_scheme_vals), 0x0,
			"The MIMO mode used in the PDU", HFILL }
		},
		{ &hf_nfapi_ul_transmission_scheme,
			{ "Transmission scheme", "nfapi.transmission.scheme",
			FT_UINT8, BASE_DEC, VALS(ul_transmission_scheme_vals), 0x0,
			"The MIMO mode used in the PDU", HFILL }
		},
		{ &hf_nfapi_number_of_layers,
			{ "Number of layers", "nfapi.number.of.layers",
			FT_UINT8, BASE_DEC, NULL, 0x0,
			"The number of layers used in transmission", HFILL }
		},
		{ &hf_nfapi_number_of_subbands,
			{ "Number of subbands", "nfapi.number.of.subbands",
			FT_UINT8, BASE_DEC, NULL, 0x0,
			"Only valid when transmission scheme = 3, 4, 5. Defines the number of subbands and "
			"codebooks used for PMI.If value = 1 then a single PMI value is supplied which should be used over all RB", HFILL }
		},
		{ &hf_nfapi_codebook_index,
			{ "Codebook Index", "nfapi.number.of.codebook.index",
			FT_UINT8, BASE_DEC, NULL, 0x0,
			"Only valid when transmission scheme = 3, 4, 5. Defines the codebook used.", HFILL }
		},
		{ &hf_nfapi_ue_category_capacity,
			{ "UE category capacity", "nfapi.ue.category.capacity",
			FT_UINT8, BASE_DEC, NULL, 0x0,
			"The UE capabilities category", HFILL }
		},
		{ &hf_nfapi_pa,
			{ "P-A", "nfapi.pa",
			FT_UINT8, BASE_DEC, VALS(pa_vals), 0x0,
			"The ratio of PDSCH EPRE to cell-specific RS EPRE among PDSCH REs in all the OFDM symbols not containing cell-specific RS in dB.", HFILL }
		},
		{ &hf_nfapi_delta_power_offset_index,
			{ "Delta Power offset Index", "nfapi.delta.power.offset.index",
			FT_UINT8, BASE_DEC, NULL, 0x0,
			"Delta power offset, value: 0..1", HFILL }
		},
		{ &hf_nfapi_nprb,
			{ "Nprb", "nfapi.nprb",
			FT_UINT8, BASE_DEC, VALS(nprb_vals), 0x0,
			"Used with DCI format 1A and RNTI=SI-RNTI or RA-RNTI. This should match the value sent in the TPC field of the DCI 1A PDU which allocated this grant.", HFILL }
		},
		{ &hf_nfapi_transmission_mode,
			{ "Transmission Mode", "nfapi.transmission_nprb",
			FT_UINT8, BASE_DEC, VALS(transmission_mode_vals), 0x0,
			"Transmission mode associated with the UE", HFILL }
		},
		{ &hf_nfapi_prnti,
			{ "P-RNTI", "nfapi.prnti",
			FT_UINT16, BASE_DEC, NULL, 0x0,
			"The P-RNTI associated with the paging", HFILL }
		},
		{ &hf_nfapi_mcs,
			{ "MCS", "nfapi.mcs",
			FT_UINT8, BASE_DEC, VALS(pch_modulation_vals), 0x0,
			"The modulation and coding scheme for the transport block", HFILL }
		},
		{ &hf_nfapi_number_of_transport_blocks,
			{ "Number of transport blocks", "nfapi.number_of_transport_blocks",
			FT_UINT8, BASE_DEC, NULL, 0x0,
			"The number of transport blocks transmitted to this RNTI", HFILL }
		},
		{ &hf_nfapi_ue_mode,
			{ "UE Mode", "nfapi.ue.mode",
			FT_UINT8, BASE_DEC, VALS(ue_mode_vals), 0x0,
			NULL, HFILL }
		},
		{ &hf_prs_bandwidth,
			{ "PRS bandwidth", "nfapi.prs.bandwidth",
			FT_UINT8, BASE_DEC, NULL, 0x0,
			"PRS bandwidth in resource blocks.", HFILL }
		},
		{ &hf_prs_cyclic_prefix_type,
			{ "PRS cyclic prefix type", "nfapi.prs.cyclic.prefix.type",
			FT_BOOLEAN, 8, TFS(&prs_cyclic_prefix_type_strname), 0x0,
			"The cyclic prefix used for PRS transmission", HFILL }
		},
		{ &hf_prs_muting,
			{ "PRS muting", "nfapi.prs.muting",
			FT_BOOLEAN, 8, TFS(&prs_muting_strname), 0x0,
			"PRS muting dictates if PRS REs are vacant (prsMutingInfo-r9 indicates the SF occasions)", HFILL }
		},
		{ &hf_nfapi_num_bf_prb_per_subband,
			{ "Num of BF PRB per Subband", "nfapi.num.bf.prb.per.subband",
			FT_UINT8, BASE_DEC, NULL, 0x0,
			"Number of PRBs that are treated as one subband", HFILL }
		},
		{ &hf_nfapi_num_bf_vector,
			{ "Num of BF Vector", "nfapi.num.bf.vector",
			FT_UINT8, BASE_DEC, NULL, 0x0,
			"Number of beam forming vectors. One beam forming vector is specified for each subband", HFILL }
		},
		{ &hf_nfapi_csi_rs_resource_config,
			{ "CSI-RS resource config", "nfapi.csi.rs.resource.config",
			FT_UINT8, BASE_DEC, NULL, 0x0,
			"Indicates reference signal configuration for CSI-RS", HFILL }
		},
		{ &hf_nfapi_bf_vector_subband_index,
			{ "BF Subband Index", "nfapi.num.bf.vector.subband.index",
			FT_UINT8, BASE_DEC, NULL, 0x0,
			"Index of subband for which the following beam forming vector is applied", HFILL }
		},
		{ &hf_nfapi_bf_vector_num_antennas,
			{ "BF Num of Antennas", "nfapi.num.bf.vector.bf.value",
			FT_UINT8, BASE_DEC, NULL, 0x0,
			"Number of physical antennas", HFILL }
		},
		{ &hf_nfapi_bf_vector_bf_value,
			{ "BF Value per Antenna", "nfapi.num.bf.vector.bf.value",
			FT_UINT16, BASE_DEC, NULL, 0x0,
			"Beam forming vector element for physical antenna #i real 8 bits followed by imaginary 8 bits", HFILL }
		},
		{ &hf_nfapi_nscid,
			{ "NSC id", "nfapi.nscid",
			FT_UINT8, BASE_DEC, NULL, 0x0,
			"Used with DCI format 2B and 2C.", HFILL }
		},
		{ &hf_nfapi_csi_rs_flag,
			{ "CSI RS Flag", "nfapi.csi.rs.flag",
			FT_BOOLEAN, 8, TFS(&tfs_valid_not_valid), 0x0,
			"Indicates if parameters related to CSI-RS are valid or not.", HFILL }
		},
		{ &hf_nfapi_csi_rs_resource_config_r10,
			{ "CSI RS resource config R10", "nfapi.csi.rs.resource_config_r10",
			FT_UINT8, BASE_DEC, NULL, 0x0,
			"This value is deprecated", HFILL }
		},
		{ &hf_nfapi_csi_rs_zero_tx_power_resource_config_bitmap_r10,
			{ "CSI-RS Number of NZP configuration", "nfapi.csi.rs.num.of.nzp.configurations",
			FT_UINT8, BASE_DEC, NULL, 0x0,
			"Bitmap of 16 bits. Encoding format of bitmap follows section 6.10.5.2 of 36.211", HFILL }
		},
		{ &hf_nfapi_csi_rs_number_of_nzp_configurations,
			{ "CSI RS zero Tx Power Resource config bitmap R10", "nfapi.csi.rs.zero.tx.power.resource.config.bitmap.r10",
			FT_UINT16, BASE_DEC, NULL, 0x0,
			"Indicates the number of Non-Zero power CSI-RS configurations.", HFILL }
		},
		{ &hf_nfapi_pdsch_start,
			{ "PDSCH_start", "nfapi.pdsch.start",
			FT_UINT8, BASE_DEC, NULL, 0x0,
			"Per UE starting OFDM symbol for the PDSCH, impacts the mapping of PDSCH to REs", HFILL }
		},
		{ &hf_nfapi_drms_config_flag,
			{ "DMRS Config flag", "nfapi.drms.config.flag",
			FT_UINT8, BASE_DEC, VALS(not_used_enabled_vals), 0x0,
			"Indicates if the DMRS Config parameter is valid", HFILL }
		},
		{ &hf_nfapi_drms_scrambling,
			{ "DMRS Scrambling", "nfapi.drms.scrambling",
			FT_UINT16, BASE_DEC, NULL, 0x0,
			"The scrambling identity for UE specific reference signals.", HFILL }
		},
		{ &hf_nfapi_csi_config_flag,
			{ "CSI Config flag", "nfapi.csi.config.flag",
			FT_UINT8, BASE_DEC, VALS(not_used_enabled_vals), 0x0,
			"Indicates if the CSI Config parameter is valid", HFILL }
		},
		{ &hf_nfapi_csi_scrambling,
			{ "CSI Scrambling", "nfapi.csi.scrambling",
			FT_UINT16, BASE_DEC, NULL, 0x0,
			"The scrambling identity for CSI.", HFILL }
		},
		{ &hf_nfapi_pdsch_re_mapping_flag,
			{ "PDSCH RE mapping flag", "nfapi.pdsch.remapping.flag",
			FT_UINT8, BASE_DEC, VALS(not_used_enabled_vals), 0x0,
			"Indicates if the PDSCH RE parameters are valid.", HFILL }
		},
		{ &hf_nfapi_pdsch_re_mapping_antenna_ports,
			{ "PDSCH RE mapping antenna ports", "nfapi.pdsch.remapping.antenna.ports",
			FT_UINT8, BASE_DEC, NULL, 0x0,
			"Indicates number of antennas used for PDSCH RE mapping", HFILL }
		},
		{ &hf_nfapi_pdsch_re_mapping_freq_shift,
			{ "PDSCH RE mapping freq shift", "nfapi.pdsch.remapping.freq.shift",
			FT_UINT8, BASE_DEC, NULL, 0x0,
			"Indicates the frequency shift used for PDSCH RE mapping.", HFILL }
		},
		{ &hf_nfapi_alt_cqi_table_r12,
			{ "altCQI-Table-r12", "nfapi.alt.cqi.table.r12",
			FT_UINT8, BASE_DEC, NULL, 0x0,
			"altCQI-Table-r12 is indicative of using an alternative MCS table for UEs supporting 256QAM."
			"This is taken into account for calculation of soft buffer size for the transport block", HFILL }
		},
		{ &hf_nfapi_max_layers,
			{ "MaxLayers", "nfapi.max.layers",
			FT_UINT16, BASE_DEC, NULL, 0x0,
			"Maximal number of negotiated / configured layers for a UE, used for the calculation of soft buffer size for the transport block", HFILL }
		},
		{ &hf_nfapi_n_dl_harq,
			{ "N_DL_HARQ", "nfapi.n.dl.harq",
			FT_UINT8, BASE_DEC, NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_nfapi_dwpts_symbols,
			{ "DwPTS Symbols", "nfapi.dwpts.symbols",
			FT_UINT8, BASE_DEC, NULL, 0x0,
			"Valid if DCI format 1C is being used to signal LAA end partial SF. Indicates the number of starting symbols according to 36.213 Table 13-A-1", HFILL }
		},
		{ &hf_nfapi_initial_lbt_sf,
			{ "Initial LBT SF", "nfapi.initial.lbt.sf",
			FT_UINT8, BASE_DEC, NULL, 0x0,
			"Indicates if the DCI PDU is prepared for full SF (regular) or for initial partial SF (2nd slot) according to [11] section 6.2.4 (if PDCCH) or 6.2.4A (if ePDCCH)", HFILL }
		},
		{ &hf_nfapi_ue_type,
			{ "UE Type", "nfapi.ue.type",
			FT_UINT8, BASE_DEC, VALS(dlsch_re13_ue_type_vals), 0x0,
			NULL, HFILL }
		},
		{ &hf_nfapi_pdsch_payload_type,
			{ "PDSCH Payload Type", "nfapi.pdsch.payload.type",
			FT_UINT8, BASE_DEC, VALS(dlsch_re13_pdsch_payload_type_vals), 0x0,
			NULL, HFILL }
		},
		{ &hf_nfapi_initial_transmission_sf,
			{ "Initial transmission SF (io)", "nfapi.init.tx.sf.io",
			FT_UINT16, BASE_DEC, NULL, 0x0,
			"Absolute Sub-Frame of the initial transmission", HFILL }
		},
		{ &hf_nfapi_req13_drms_table_flag,
			{ "Rel-13-DMRS-tabe flag", "nfapi.r13.drms.table.flag",
			FT_UINT8, BASE_DEC, NULL, 0x0,
			"Indicates if Release 13 DMRS table is used.", HFILL }
		},
		{ &hf_nfapi_csi_rs_resource_index,
			{ "CSI-RS resource Index", "nfapi.csi.rs.resource.index",
			FT_UINT8, BASE_DEC, NULL, 0x0,
			"Index of the CSI-RS resource. This is included to link bfValues to CSI-RS resources included in Release 10 parameters.", HFILL }
		},
		{ &hf_nfapi_csi_rs_class,
			{ "Class", "nfapi.csi.rs.class",
			FT_UINT8, BASE_DEC, VALS(csi_rs_class_vals), 0x0,
			"Indicates CSI-RS class", HFILL }
		},
		{ &hf_nfapi_cdm_type,
			{ "CDM Type", "nfapi.cdm.type",
			FT_UINT8, BASE_DEC, VALS(csi_rs_cdm_type_vals), 0x0,
			"Indicates CDM type for CSI-RS. See [36.211] section 6.10.5.2. Valid for Class A", HFILL }
		},
		{ &hf_nfapi_edpcch_prb_index,
			{ "EPDCCH PRB Index", "nfapi.edpcch.prb.index",
			FT_UINT8, BASE_DEC, NULL, 0x0,
			"PRB Index", HFILL }
		},
		{ &hf_nfapi_epdcch_resource_assignment_flag,
			{ "EPDCCH Resource assignment flag", "nfapi.epdcch.resource.assignment.flag",
			FT_UINT8, BASE_DEC, VALS(local_distributed_vals), 0x0,
			"Type of virtual resource block used", HFILL }
		},
		{ &hf_nfapi_epdcch_id,
			{ "EPDCCH ID", "nfapi.epdcch.id",
			FT_UINT8, BASE_DEC, NULL, 0x0,
			"EPDCCH Index- used for the scrambler initiation The DMRS scrambling sequence initialization parameter defined in[11] section 6.10.3A.1", HFILL }
		},
		{ &hf_nfapi_epdcch_start_symbol,
			{ "EPDCCH Start Symbol", "nfapi.epdcch.start.symbol",
			FT_UINT8, BASE_DEC, NULL, 0x0,
			"Indicates the OFDM starting symbol for any EPDCCH and PDSCH", HFILL }
		},
		{ &hf_nfapi_epdcch_num_prb,
			{ "EPDCCH NumPRB", "nfapi.epdcch.num.prb",
			FT_UINT8, BASE_DEC, NULL, 0x0,
			"Number of PRBs allocated for EPDCCH", HFILL }
		},
		{ &hf_nfapi_precoding_value,
			{ "Precoding value", "nfapi.precoding.value",
			FT_UINT16, BASE_DEC, NULL, 0x0,
			"Precoding element for physical antenna #i real 8 bits followed by imaginary 8 bits", HFILL }
		},
		{ &hf_nfapi_mpdcch_narrowband,
			{ "MPDCCH Narrowband", "nfapi.mpdcch.narrowband",
			FT_UINT8, BASE_DEC, NULL, 0x0,
			"Narrowband for MPDCCH", HFILL }
		},
		{ &hf_nfapi_number_of_prb_pairs,
			{ "Number of PRB pairs", "nfapi.number.prb.pairs",
			FT_UINT8, BASE_DEC, NULL, 0x0,
			"Number of PRB-pairs constituting the MPDCCH-PRB-pair set", HFILL }
		},
		{ &hf_nfapi_resource_block_assignment,
			{ "Resource Block Assignment", "nfapi.resource.block.assignement",
			FT_UINT8, BASE_DEC, NULL, 0x0,
			"Combinational Index r", HFILL }
		},
		{ &hf_nfapi_start_symbol,
			{ "Start symbol", "nfapi.start.symbol",
			FT_UINT8, BASE_DEC, NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_nfapi_ecce_index,
			{ "ECCE Index", "nfapi.ecce.index",
			FT_UINT8, BASE_DEC, NULL, 0x0,
			"ECCE Index used to send the DCI", HFILL }
		},
		{ &hf_nfapi_ce_mode,
			{ "CE Mode", "nfapi.ce.mode",
			FT_UINT8, BASE_DEC, VALS(ce_mode_vals), 0x0,
			NULL, HFILL }
		},
		{ &hf_nfapi_drms_scrabmling_init,
			{ "DMRS scrambling init", "nfapi.drms.scrambling.init",
			FT_UINT16, BASE_DEC, NULL, 0x0,
			"The DMRS scrambling sequence initialization parameter defined in [11] section 6.10.3A.1", HFILL }
		},
		{ &hf_nfapi_pdsch_reception_levels,
			{ "PDSCH repetition levels", "nfapi.pdsch.repetition.levels",
			FT_UINT8, BASE_DEC, NULL, 0x0,
			"Valid for DCI formats: 6-0A, 6-0B", HFILL }
		},
		{ &hf_nfapi_new_data_indicator,
			{ "New data indicator", "nfapi.new.data.indicator",
			FT_UINT8, BASE_DEC, NULL, 0x0,
			"The new data indicator for the transport block", HFILL }
		},
		{ &hf_nfapi_tpmi_length,
			{ "TPMI length", "nfapi.tpmi.length",
			FT_UINT8, BASE_DEC, NULL, 0x0,
			"Length of 'TPMI' field in units of bits", HFILL }
		},
		{ &hf_nfapi_pmi_flag,
			{ "PMI flag", "nfapi.pmi.flag",
			FT_BOOLEAN, 8, TFS(&tfs_present_not_present), 0x0,
			"Indicates if 'PMI' field is present", HFILL }
		},
		{ &hf_nfapi_harq_resource_offset,
			{ "HARQ resource offset", "nfapi.harq.resource.offset",
			FT_UINT8, BASE_DEC, NULL, 0x0,
			"HARQ-ACK resource offset used", HFILL }
		},
		{ &hf_nfapi_dci_subframe_repetition_number,
			{ "DCI subframe repetition number", "nfapi.dci.subframe.repetition.number",
			FT_UINT8, BASE_DEC, NULL, 0x0,
			"Indicates the number of MPDCCH repetitions", HFILL }
		},
		{ &hf_nfapi_downlink_assignment_index_length,
			{ "Downlink assignment Index Length", "nfapi.dl.assignement.index.length",
			FT_UINT8, BASE_DEC, NULL, 0x0,
			"Length of Downlink assignment Index field in units of bits.", HFILL }
		},
		{ &hf_nfapi_starting_ce_level,
			{ "Starting CE Level", "nfapi.starting.ce.level",
			FT_UINT8, BASE_DEC, NULL, 0x0,
			"2 bits provide the PRACH starting CE level", HFILL }
		},
		{ &hf_nfapi_antenna_ports_and_scrambling_identity_flag,
			{ "Antenna ports and scrambling identity flag", "nfapi.antenna.ports.and.scrambling.identity.flag",
			FT_BOOLEAN, 8, TFS(&tfs_present_not_present), 0x0,
			"Indicates if 'Antenna ports and scrambling identity' field is present.", HFILL }
		},
		{ &hf_nfapi_antenna_ports_and_scrambling_identity,
			{ "Antenna ports and scrambling identity", "nfapi.antenna.ports.and.scrambling.identit",
			FT_UINT8, BASE_DEC, NULL, 0x0,
			"Indicates the Antenna port and, scrambling identity value", HFILL }
		},
		{ &hf_nfapi_paging_direct_indication_differentiation_flag,
			{ "Paging/Direct indication differentiation flag", "nfapi.paging.direct.indictation.differentiation.flag",
			FT_UINT8, BASE_DEC, VALS(paging_direct_indication_differtiation_flag_vals), 0x0,
			"Valid for DCI format 6-2", HFILL }
		},
		{ &hf_nfapi_direct_indication,
			{ "Direct indication", "nfapi.direct.indication",
			FT_UINT8, BASE_DEC, NULL, 0x0,
			"Valid for DCI format 6-2", HFILL }
		},
		{ &hf_nfapi_number_of_tx_antenna_ports,
			{ "Number of TX Antenna ports", "nfapi.num.of.tx.antenna.ports",
			FT_UINT8, BASE_DEC, NULL, 0x0,
			"Number of TX physical antenna ports", HFILL }
		},
		{ &hf_nfapi_transmission_power,
			{ "Transmission Power", "nfapi.transmission_power",
			FT_UINT16, BASE_CUSTOM, CF_FUNC(power_offset_conversion_fn), 0x0,
			"Offset to the reference signal power.", HFILL }
		},
		{ &hf_nfapi_mbsfn_area_id,
			{ "MBSFN Area id", "nfapi.mbsfn.area.id",
			FT_UINT16, BASE_DEC, NULL, 0x0,
			"Indicates MBSFN area ID", HFILL }
		},
		{ &hf_nfapi_dl_dci_format,
			{ "DL DCI format", "nfapi.dl.dci.format",
			FT_UINT8, BASE_DEC, VALS(dl_dci_format_vals), 0x0,
			"Format of the DL DCI", HFILL }
		},
		{ &hf_nfapi_ul_dci_format,
			{ "UL DCI format", "nfapi.ul_dci.format",
			FT_UINT8, BASE_DEC, VALS(ul_dci_format_vals), 0x0,
			"Format of the UL DCI", HFILL }
		},
		{ &hf_nfapi_mpdcch_ul_dci_format,
			{ "UL DCI format", "nfapi.mpdcch.ul_dci.format",
			FT_UINT8, BASE_DEC, VALS(mpdcch_ul_dci_format_vals), 0x0,
			"Format of the UL DCI", HFILL }
		},
		{ &hf_nfapi_cce_idx,
			{ "CCE Index", "nfapi.cce.index",
			FT_UINT8, BASE_DEC, NULL, 0x0,
			"CCE Index used to send the DCI", HFILL }
		},
		{ &hf_nfapi_aggregation_level,
			{ "Aggregation level", "nfapi.aggregation.level",
			FT_UINT8, BASE_DEC, NULL, 0x0,
			"The aggregation level used", HFILL }
		},
		{ &hf_nfapi_mcs_1,
			{ "MCS_1", "nfapi.mcs_1",
			FT_UINT8, BASE_DEC, NULL, 0x0,
			"The modulation and coding scheme for 1st transport block", HFILL }
		},
		{ &hf_nfapi_mcs_2,
			{ "MCS_2", "nfapi.mcs_2",
			FT_UINT8, BASE_DEC, NULL, 0x0,
			"The modulation and coding scheme for 2nd transport block", HFILL }
		},
		{ &hf_nfapi_redundancy_version_1,
			{ "Redundancy version_1", "nfapi.redundancy.version.1",
			FT_UINT8, BASE_DEC, NULL, 0x0,
			"The redundancy version for 1st transport block.", HFILL }
		},
		{ &hf_nfapi_redundancy_version_2,
			{ "Redundancy version_2", "nfapi.redundancy.version.2",
			FT_UINT8, BASE_DEC, NULL, 0x0,
			"The redundancy version for 2nd transport block", HFILL }
		},
		{ &hf_nfapi_new_data_indicator_1,
			{ "New data indicator_1", "nfapi.new.data.indicator.1",
			FT_UINT8, BASE_DEC, NULL, 0x0,
			"The new data indicator for 1st transport block.", HFILL }
		},
		{ &hf_nfapi_new_data_indicator_2,
			{ "New data indicator_2", "nfapi.new.data.indicator.2",
			FT_UINT8, BASE_DEC, NULL, 0x0,
			"The new data indicator for 2nd transport block.", HFILL }
		},
		{ &hf_nfapi_harq_process,
			{ "HARQ process", "nfapi.harq.process",
			FT_UINT8, BASE_DEC, NULL, 0x0,
			"HARQ process number", HFILL }
		},
		{ &hf_nfapi_tpmi,
			{ "TPMI", "nfapi.tpmi",
			FT_UINT8, BASE_DEC, NULL, 0x0,
			"The codebook Index to be used for precoding", HFILL }
		},
		{ &hf_nfapi_pmi,
			{ "PMI", "nfapi.pmi",
			FT_UINT8, BASE_DEC, VALS(pmi_vals), 0x0,
			"Confirmation for precoding", HFILL }
		},
		{ &hf_nfapi_precoding_information,
			{ "Precoding information", "nfapi.precoding.information",
			FT_UINT8, BASE_DEC, NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_nfapi_tpc,
			{ "TPC", "nfapi.tpc",
			FT_UINT8, BASE_DEC, NULL, 0x0,
			"Tx power control command for PUCCH", HFILL }
		},
		{ &hf_nfapi_downlink_assignment_index,
			{ "Downlink assignment Index", "nfapi.downlink.assignment.index",
			FT_UINT8, BASE_DEC, NULL, 0x0,
			"The downlink assignment Index. In release 8-11 this is only used in TDD mode, "
			"value ignored for FDD. In release 12 or later a field indicating the structure "
			"type of the primary cell is used to determine if this is valid with size 2 bits."
			"In release 13 or later a field indicating codebooksizeDetermination - r13 = 0 is "
			"used to determine is this field is valid with size 4 bits", HFILL }
		},
		{ &hf_nfapi_ngap,
			{ "Ngap", "nfapi.ngap",
			FT_UINT8, BASE_DEC, VALS(ngap_vals), 0x0,
			"Used in virtual resource block distribution", HFILL }
		},
		{ &hf_nfapi_transport_block_size_index,
			{ "Transport block size Index", "nfapi.transport.block.size.index",
			FT_UINT8, BASE_DEC, NULL, 0x0,
			"The transport block size", HFILL }
		},
		{ &hf_nfapi_downlink_power_offset,
			{ "Downlink power offset", "nfapi.downlink.power.offset",
			FT_UINT8, BASE_DEC, NULL, 0x0,
			"Indicates the DL power offset type for multi-user MIMO transmission", HFILL }
		},
		{ &hf_nfapi_allocate_prach_flag,
			{ "Allocation PRACH flag", "nfapi.allocation.prach.flag",
			FT_UINT8, BASE_DEC, VALS(true_false_vals), 0x0,
			"Indicates that PRACH procedure is initiated", HFILL }
		},
		{ &hf_nfapi_preamble_index,
			{ "Preamble Index", "nfapi.preamable.index",
			FT_UINT8, BASE_DEC, NULL, 0x0,
			"The preamble Index to be used on the PRACH", HFILL }
		},
		{ &hf_nfapi_prach_mask_index,
			{ "PRACH mask Index", "nfapi.prach.mask.index",
			FT_UINT8, BASE_DEC, NULL, 0x0,
			"The mask Index to be used on the PRACH", HFILL }
		},
		{ &hf_nfapi_rnti_type,
			{ "RNTI type", "nfapi.rnti.type",
			FT_UINT8, BASE_DEC, VALS(rnti_type_vals), 0x0,
			NULL, HFILL }
		},
		{ &hf_nfapi_mpdcch_rnti_type,
			{ "RNTI type", "nfapi.mpdcch.rnti.type",
			FT_UINT8, BASE_DEC, VALS(mpdcch_rnti_type_vals), 0x0,
			NULL, HFILL }
		},
		{ &hf_nfapi_mcch_flag,
			{ "MCCH flag", "nfapi.mcch.flag",
			FT_BOOLEAN, BASE_NONE, TFS(&mcch_flag_string_name), 0x0,
			"Indicates if format 1C is being used to signal a MCCH or SC-MCCH change notification", HFILL }
		},
		{ &hf_nfapi_mcch_change_notification,
			{ "MCCH change notification", "nfapi.mcch.change.notification",
			FT_UINT8, BASE_DEC, NULL, 0x0,
			"MCCH or SC-MCCH Change Notification", HFILL }
		},
		{ &hf_nfapi_scrambling_identity,
			{ "Scrambling identity", "nfapi.scrambling.identity",
			FT_UINT8, BASE_DEC, NULL, 0x0,
			"Indicates the scrambling identity value NSCID", HFILL }
		},
		{ &hf_nfapi_cross_carrier_scheduling_flag,
			{ "Cross Carrier scheduling flag", "nfapi.cross.carrier.scheduling.flag",
			FT_BOOLEAN, 8, TFS(&cross_carrier_scheduling_flag_strname), 0x0,
			"Indicates if cross carrier scheduling has been enabled for the UE receiving this DCI", HFILL }
		},
		{ &hf_nfapi_carrier_indicator,
			{ "Carrier Indicator", "nfapi.carrier.indicator",
			FT_UINT8, BASE_DEC, NULL, 0x0,
			"Serving Cell Index", HFILL }
		},
		{ &hf_nfapi_srs_flag,
			{ "SRS flag", "nfapi.srs.flag",
			FT_BOOLEAN, 8, TFS(&srs_flag_strname), 0x0,
			"Indicates if the SRS request parameter is valid", HFILL }
		},
		{ &hf_nfapi_srs_request,
			{ "SRS request", "nfapi.srs.request",
			FT_BOOLEAN, 8, TFS(&srs_request_strname), 0x0,
			"SRS request flag", HFILL }
		},
		{ &hf_nfapi_antenna_ports_scrambling_and_layers,
			{ "Antenna ports scrambling and layers", "nfapi.antenna.ports.scrambling.and.layers",
			FT_UINT8, BASE_DEC, NULL, 0x0,
			"Indicates the Antenna port, scrambling identity value NSCID and number of layers", HFILL }
		},
		{ &hf_nfapi_total_dci_length_including_padding,
			{ "Total DCI length including padding", "nfapi.total.dci.length.including.padding",
			FT_UINT8, BASE_DEC, NULL, 0x0,
			"The total DCI length including padding bits", HFILL }
		},
		{ &hf_nfapi_n_ul_rb,
			{ "N_UL_RB", "nfapi.n.dl.rb",
			FT_UINT8, BASE_DEC, NULL, 0x0,
			"BW of serving cell for which the DCI was scheduled for.  This is valid for "
			"the case of cross carrier scheduling, for the case of a self - "
			"scheduling(cross carrier scheduling is not valid or Carrier indicator has value '0', "
			"the BW is the 'DL BW support' as configured in configuration phase(params) "
			"Uplink channel bandwidth in resource blocks", HFILL }
		},
		{ &hf_nfapi_harq_ack_resource_offset,
			{ "HARQ-ACK resource offset", "nfapi.harq.ack.resource.offset",
			FT_UINT8, BASE_DEC, NULL, 0x0,
			"HARQ-ACK resource offset field is present only when this format is carried by EPDCCH.", HFILL }
		},
		{ &hf_nfapi_pdsch_re_mapping_and_quasi_co_location_indicator,
			{ "PDSCH RE Mapping and Quasi-Co-Location Indicator", "nfapi.pdsch.re.mapping",
			FT_UINT8, BASE_DEC, NULL, 0x0,
			"Indicates the parameter set configured by the higher layers which the UE should use.", HFILL }
		},
		{ &hf_nfapi_primary_cell_type,
			{ "Primary cell type", "nfapi.primary.cell.type",
			FT_UINT8, BASE_DEC, VALS(primary_cells_type_vals), 0x0,
			"Indicates the type of the primary cell.", HFILL }
		},
		{ &hf_nfapi_ul_dl_configuration_flag,
			{ "UL/DL configuration flag", "nfapi.ul.dl.configuration.flag",
			FT_BOOLEAN, 8, TFS(&ul_dl_configuration_flag_strname), 0x0,
			"Indicates if format 1C is being used to signal UL/DL configuration", HFILL }
		},
		{ &hf_nfapi_number_of_ul_dl_configurations,
			{ "Number of UL/DL configurations", "nfapi.number.ul.dl.configurations",
			FT_UINT8, BASE_DEC, NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_nfapi_ul_dl_configuration_index,
			{ "UL/DL configuration indication", "nfapi.ul.dl.configuration.indication",
			FT_UINT8, BASE_DEC, NULL, 0x0,
			"UL/DL configuration Index", HFILL }
		},
		{ &hf_nfapi_laa_end_partial_sf_flag,
			{ "LAA end partial SF flag", "nfapi.laa.end.partial.sf.flag",
			FT_UINT8, BASE_DEC, NULL, 0x0,
			"Indicates if DCI format 1C is being used to signal LAA end partial SF (valid if end partial SF support configuration is set)", HFILL }
		},
		{ &hf_nfapi_laa_end_partial_sf_configuration,
			{ "LAA end partial SF configuration", "nfapi.laa.end.partial.sf.configuration",
			FT_UINT8, BASE_DEC, NULL, 0x0,
			"If DCI format 1C scrambled by CC - RNTI is used to signal end partial SF, this field "
			"contains LAA common information (4 bits used in [9] Table 13A-1 for configuration of "
			"occupied OFDM symbols for current and next SF)", HFILL }
		},
		{ &hf_nfapi_codebooksize_determination_r13,
			{ "Codebook Size Determination R13", "nfapi.codebook.size.determination.r13",
			FT_UINT8, BASE_DEC, NULL, 0x0,
			"Indicates if the downlink assignment Index parameter (DAI) is 4 bits", HFILL }
		},
		{ &hf_nfapi_rel13_drms_table_flag,
			{ "Rel-13-DMRS-tabe flag", "nfapi.drms.table.flag.r13",
			FT_UINT8, BASE_DEC, NULL, 0x0,
			"Indicates if Release 13 DMRS table for be used", HFILL }
		},
		{ &hf_nfapi_pscch_resource,
			{ "PSCCH Resource", "nfapi.pscch.resource",
			FT_UINT8, BASE_DEC, NULL, 0x0,
			"6-bits describing the resource blocks for transmitting PSCCH", HFILL }
		},
		{ &hf_nfapi_time_resource_pattern,
			{ "Time resource pattern", "nfapi.time.resource.pattern",
			FT_UINT8, BASE_DEC, NULL, 0x0,
			"7-bits describing the time resource pattern Index", HFILL }
		},
		{ &hf_nfapi_mpdcch_transmission_type,
			{ "MPDCCH transmission type", "nfapi.mpdcch.transmission.type",
			FT_UINT8, BASE_DEC, VALS(local_distributed_vals), 0x0,
			NULL, HFILL }
		},
		{ &hf_nfapi_drms_scrambling_init,
			{ "DMRS scrambling init", "nfapi.drms.scrambling.init",
			FT_UINT8, BASE_DEC, NULL, 0x0,
			"The DMRS scrambling sequence initialization", HFILL }
		},
		{ &hf_nfapi_pusch_repetition_levels,
			{ "PUSCH repetition levels", "nfapi.pusch.repetition.levels",
			FT_UINT8, BASE_DEC, NULL, 0x0,
			"Valid for DCI formats: 6-0A, 6-0B", HFILL }
		},
		{ &hf_nfapi_frequency_hopping_flag,
			{ "Frequency hopping flag", "nfapi.frequency.hopping.flag",
			FT_UINT8, BASE_DEC, NULL, 0x0,
			"Indicates if hopping is being used.", HFILL }
		},
		{ &hf_nfapi_csi_request,
			{ "CSI request", "nfapi.csi.request",
			FT_UINT8, BASE_DEC, VALS(csi_request_vals), 0x0,
			"Aperiodic CSI request flag", HFILL }
		},
		{ &hf_nfapi_dai_presence_flag,
			{ "DAI presence flag", "nfapi.dia.presence.flag",
			FT_BOOLEAN, 8, TFS(&tfs_present_not_present), 0x0,
			"Indicates if DL assignment Index field is present in the DCI", HFILL }
		},
		{ &hf_nfapi_total_dci_length_include_padding,
			{ "Total DCI length including padding", "nfapi.total.dci.length.including.padding",
			FT_UINT8, BASE_DEC, NULL, 0x0,
			"The total DCI length including padding bits", HFILL }
		},
		{ &hf_nfapi_csi_rs_antenna_port_count_r10,
			{ "CSI-RS antenna port count r10", "nfapi.csi.rs.antenna.port.count.r10",
			FT_UINT8, BASE_DEC, NULL, 0x0,
			"Indicates number of antennas used for transmission of CSI reference signal.", HFILL }
		},
		{ &hf_nfapi_ul_config_pdu_type,
			{ "UL Config PDU Type", "nfapi.ul.config.pdu.type",
			FT_UINT8, BASE_DEC, VALS(nfapi_ul_config_pdu_type_vals), 0x0,
			NULL, HFILL }
		},
		{ &hf_nfapi_rach_prach_frequency_resources,
			{ "RACH PRACH Frequency resources", "nfapi.rach.prach.frequency.resources",
			FT_UINT8, BASE_DEC, NULL, 0x0,
			"If semi-static information is held in the MAC", HFILL }
		},
		{ &hf_nfapi_srs_present,
			{ "SRS present", "nfapi.srs.present",
			FT_BOOLEAN, 8, TFS(&tfs_present_not_present), 0x01,
			"If semi-static information is held in the MAC", HFILL }
		},
		{ &hf_nfapi_handle,
			{ "Handle", "nfapi.handle",
			FT_UINT32, BASE_DEC, NULL, 0x0,
			"An opaque handle", HFILL }
		},
		{ &hf_nfapi_pucch_index,
			{ "PUCCH Index", "nfapi.pucch.index",
			FT_UINT16, BASE_DEC, NULL, 0x0,
			"The PUCCH Index value", HFILL }
		},
		{ &hf_nfapi_size,
			{ "Size", "nfapi.size",
			FT_UINT16, BASE_DEC, NULL, 0x0,
			"The size of the ULSCH PDU in bytes as defined by the relevant UL grant", HFILL }
		},
		{ &hf_nfapi_resource_block_start,
			{ "Resource block start", "nfapi.resource.block.start",
			FT_UINT8, BASE_DEC, NULL, 0x0,
			"The starting resource block for this ULSCH allocation", HFILL }
		},
		{ &hf_nfapi_number_of_resource_blocks,
			{ "Number of resource blocks", "nfapi.resource.blocks",
			FT_UINT8, BASE_DEC, NULL, 0x0,
			"The number of resource blocks allocated to this ULSCH grant", HFILL }
		},
		{ &hf_nfapi_cyclic_shift_2_for_drms,
			{ "Cyclic Shift 2 for DRMS", "nfapi.cyclic.shift.2.for.drms",
			FT_UINT8, BASE_DEC, NULL, 0x0,
			"The 2nd cyclic shift for DMRS assigned to the UE in the ULSCH grant", HFILL }
		},
		{ &hf_nfapi_frequency_hopping_enabled_flag,
			{ "Frequency hopping enabled flag", "nfapi.frequency.hopping.enabled.flag",
			FT_UINT8, BASE_DEC, VALS(hopping_vals), 0x0,
			"Indicates if hopping is being used", HFILL }
		},
		{ &hf_nfapi_frequency_hopping_bits,
			{ "Frequency hopping bits", "nfapi.frequency.hopping.bits",
			FT_UINT8, BASE_DEC, NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_nfapi_new_data_indication,
			{ "New Data inidication", "nfapi.new.data.indication",
			FT_UINT8, BASE_DEC, NULL, 0x0,
			"Specify whether this received transport block is a new transmission from UE", HFILL }
		},
		{ &hf_nfapi_harq_process_number,
			{ "HARQ Process number", "nfapi.harq.process.number",
			FT_UINT8, BASE_DEC, NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_nfapi_ul_tx_mode,
			{ "UL Tx Mode", "nfapi.ul.tx.mode",
			FT_UINT8, BASE_DEC, VALS(ul_tx_mode_vals), 0x0,
			NULL, HFILL }
		},
		{ &hf_nfapi_current_tx_nb,
			{ "Current Tx nb", "nfapi.current.tx.nb",
			FT_UINT8, BASE_DEC, NULL, 0x0,
			"The current HARQ transmission count of this transport block. Valid if frequency hopping enabled.", HFILL }
		},
		{ &hf_nfapi_n_srs,
			{ "N SRS", "nfapi.n.srs",
			FT_UINT8, BASE_DEC, VALS(n_srs_vals), 0x0,
			"Indicates if the resource blocks allocated for this grant overlap with the SRS configuration.", HFILL }
		},
		{ &hf_nfapi_disable_sequence_hopping_flag,
			{ "Disable seqeunce hopping flag", "nfapi.disable.sequence.hopping.flag",
			FT_UINT8, BASE_DEC, NULL, 0x0,
			"Indicates if any configured group hopping should be disabled for this UE.", HFILL }
		},
		{ &hf_nfapi_virtual_cell_id_enabled_flag,
			{ "Virtual cell ID enabled flag", "nfapi.virtual.cell.id.enabled.flag",
			FT_UINT8, BASE_DEC, VALS(not_used_enabled_vals), 0x0,
			"Indicates if virtual cell is being used and nPUSCH identity is valid.", HFILL }
		},
		{ &hf_nfapi_npusch_identity,
			{ "nPUSCH Identity", "nfapi.npusch.identity",
			FT_UINT16, BASE_DEC, NULL, 0x0,
			"Virtual cell ID for initialization of group hopping, sequence hopping and sequence shift pattern of PUSCH DMRS.", HFILL }
		},
		{ &hf_nfapi_ndrms_csh_identity,
			{ "nDMRS-CSH Identity", "nfapi.ndrms.csh.identity",
			FT_UINT16, BASE_DEC, NULL, 0x0,
			"Virtual cell ID for initialization of cyclic shift hopping of PUSCH DMRS.", HFILL }
		},
		{ &hf_nfapi_total_number_of_repetitions,
			{ "Total Number of repetitions", "nfapi.total.number.of.repetitions",
			FT_UINT16, BASE_DEC, NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_nfapi_repetition_number,
			{ "Repetition Number", "nfapi.repetition.number",
			FT_UINT16, BASE_DEC, NULL, 0x0,
			"Current transmission number", HFILL }
		},
		{ &hf_nfapi_initial_sf_io,
			{ "Initial transmission SF (io)", "nfapi.initial.sf.io",
			FT_UINT16, BASE_DEC, NULL, 0x0,
			"Absolute Sub-Frame of the initial transmission", HFILL }
		},
		{ &hf_nfapi_empty_symbols_due_to_retunning,
			{ "Empy symbols due to re-tunning", "nfapi.empty.symbols.due.to.retunning",
			FT_UINT8, BASE_DEC, NULL, 0x0,
			"Indicates the symbols that are left empty due to eMTC retuning.", HFILL }
		},
		{ &hf_nfapi_dl_cqi_ri_pmi_size_2,
			{ "DL CQI/PMI/RI size 2", "nfapi.dl.cqi.ri.pmi.size.2",
			FT_UINT16, BASE_DEC, NULL, 0x0,
			"The size of the DL CQI/PMI/RI in bits. If the CQI/PMI/RI size exceeds 255 (8-bits) then the Release 9 size value = 0, and this field is used instead.", HFILL }
		},
		{ &hf_nfapi_harq_size_2,
			{ "HARQ Size 2", "nfapi.harq.size2",
			FT_UINT8, BASE_DEC, NULL, 0x0,
			"The size of the ACK/NACK in bits.", HFILL }
		},
		{ &hf_nfapi_delta_offset_harq_2,
			{ "Delta Offset HARQ 2", "nfapi.delta.offset.harq.2",
			FT_UINT8, BASE_DEC, NULL, 0x0,
			"Delta offset 2 for HARQ. This value is fixed for a UE, allocated in RRC connection setup and used for ACK_NACK mode = 4 or 5", HFILL }
		},
		{ &hf_nfapi_starting_prb,
			{ "Starting PRB", "nfapi.starting.prb",
			FT_UINT8, BASE_DEC, NULL, 0x0,
			"The starting PRB for the PUCCH", HFILL }
		},
		{ &hf_nfapi_antenna_port,
			{ "Antenna Port", "nfapi.antenna.port",
			FT_UINT8, BASE_DEC, VALS(antenna_ports_vals), 0x0,
			"Defines the number of antenna ports used by the UE for the SRS. This value is fixed for a UE and allocated in RRC connection setup.", HFILL }
		},
		{ &hf_nfapi_number_of_combs,
			{ "Number of Combs", "nfapi.num.of.combs",
			FT_UINT8, BASE_DEC, VALS(combs_vals), 0x0,
			"Defines the maximum number of transmission combs (TC).", HFILL }
		},
		{ &hf_nfapi_npucch_identity,
			{ "nPUCCH Identity", "nfapi.npucch.identity",
			FT_UINT16, BASE_DEC, NULL, 0x0,
			"Virtual cell ID for initialization of base sequence and cyclic shift hopping of PUCCH.", HFILL }
		},
		{ &hf_nfapi_empty_symbols,
			{ "Empty symbols", "nfapi.empty.symbols",
			FT_UINT8, BASE_DEC, NULL, 0x0,
			"Indicates the symbols that are left empty due to eMTC retuning.", HFILL }
		},
		{ &hf_nfapi_csi_mode,
			{ "CSI_mode", "nfapi.csi.mode",
			FT_UINT8, BASE_DEC, VALS(csi_mode_vals), 0x0,
			NULL, HFILL }
		},
		{ &hf_nfapi_dl_cqi_pmi_size_2,
			{ "DL CQI/PMI Size 2", "nfapi.dl.cqi.pmi.size.2",
			FT_UINT16, BASE_DEC, NULL, 0x0,
			"The size of the DL CQI/PMI in bits", HFILL }
		},
		{ &hf_nfapi_statring_prb,
			{ "Starting PRB", "nfapi.starting.prb",
			FT_UINT8, BASE_DEC, NULL, 0x0,
			"The starting PRB for the PUCCH", HFILL }
		},
		{ &hf_nfapi_cdm_index,
			{ "cdm_Index", "nfapi.cdm.index",
			FT_UINT8, BASE_DEC, NULL, 0x0,
			"Selected CDM option", HFILL }
		},
		{ &hf_nfapi_nsrs,
			{ "N srs", "nfapi.n.srs",
			FT_UINT8, BASE_DEC, NULL, 0x0,
			"Indicates if the resource blocks allocated for this grant overlap with the SRS configuration.", HFILL }
		},
		{ &hf_nfapi_num_ant_ports,
			{ "Num_ant_ports", "nfapi.num.ant.port",
			FT_UINT8, BASE_DEC, NULL, 0x0,
			"The number of antenna ports used by the UE transmit", HFILL }
		},
		{ &hf_nfapi_n_pucch_2_0,
			{ "n_PUCCH_2_0", "nfapi.n.pucch.2.0",
			FT_UINT16, BASE_DEC, NULL, 0x0,
			"The PUCCH Index value for ACK/NACK HARQ resource 4 on antenna port", HFILL }
		},
		{ &hf_nfapi_n_pucch_2_1,
			{ "n_PUCCH_2_1", "nfapi.n.pucch.2.1",
			FT_UINT16, BASE_DEC, NULL, 0x0,
			"HARQ resource 5", HFILL }
		},
		{ &hf_nfapi_n_pucch_2_2,
			{ "n_PUCCH_2_2", "nfapi.n.pucch.2.2",
			FT_UINT16, BASE_DEC, NULL, 0x0,
			"HARQ resource 6", HFILL }
		},
		{ &hf_nfapi_n_pucch_2_3,
			{ "n_PUCCH_2_3", "nfapi.n.pucch.2.3",
			FT_UINT16, BASE_DEC, NULL, 0x0,
			"HARQ resource 7", HFILL }
		},
		{ &hf_nfapi_dl_cqi_pmi_size_rank_1,
			{ "DL CQI PMI size rank 1", "nfapi.dl.cqi.pmi.size.rank.1",
			FT_UINT8, BASE_DEC, NULL, 0x0,
			"The size of the DL CQI/PMI in bits in case of rank 1 report.", HFILL }
		},
		{ &hf_nfapi_dl_cqi_pmi_size_rank_greater_1,
			{ "DL CQI PMI size rank greater 1", "nfapi.dl.cqi.pmi.size.rank.1",
			FT_UINT8, BASE_DEC, NULL, 0x0,
			"The size of the DL CQI/PMI in bits in case of rank>1 report.", HFILL }
		},
		{ &hf_nfapi_ri_size,
			{ "RI size", "nfapi.ri.size",
			FT_UINT8, BASE_DEC, NULL, 0x0,
			"The size of RI in bits", HFILL }
		},
		{ &hf_nfapi_delta_offset_cqi,
			{ "Delta offset cqi", "nfapi.delta.offset.cqi",
			FT_UINT8, BASE_DEC, NULL, 0x0,
			"Delta offset for CQI. This value is fixed for a UE and allocated in RRC connection setup.", HFILL }
		},
		{ &hf_nfapi_delta_offset_ri,
			{ "Delta offset ri", "nfapi.delta.offset.ri",
			FT_UINT8, BASE_DEC, NULL, 0x0,
			"Delta offset for RI. This value is fixed for a UE and allocated in RRC connection setup.", HFILL }
		},
		{ &hf_nfapi_harq_size,
			{ "HARQ size", "nfapi.harq_size",
			FT_UINT8, BASE_DEC, NULL, 0x0,
			"The size of the ACK/NACK in bits", HFILL }
		},
		{ &hf_nfapi_delta_offset_harq,
			{ "Delta offset HARQ", "nfapi.delta.offset.harq",
			FT_UINT8, BASE_DEC, NULL, 0x0,
			"Delta offset for HARQ. This value is fixed for a UE and allocated in RRC connection setup.", HFILL }
		},
		{ &hf_nfapi_tdd_ack_nack_mode,
			{ "ACK NACK mode", "nfapi.tdd.ack.nack.mode",
			FT_UINT8, BASE_DEC, VALS(nfapi_tdd_ack_nack_mode_vals), 0x0,
			"The format of the ACK/NACK response expected. For TDD only.", HFILL }
		},
		{ &hf_nfapi_fdd_ack_nack_mode,
			{ "ACK NACK mode", "nfapi.fdd.ack.nack.mode",
			FT_UINT8, BASE_DEC, VALS(nfapi_fdd_ack_nack_mode_vals), 0x0,
			"The format of the ACK/NACK response expected. For TDD only.", HFILL }
		},
		{ &hf_nfapi_n_srs_initial,
			{ "N srs initial", "nfapi.n.srs.initial",
			FT_UINT8, BASE_DEC, VALS(n_srs_initial_vals), 0x0,
			NULL, HFILL }
		},
		{ &hf_nfapi_initial_number_of_resource_blocks,
			{ "Initial number of resource blocks", "nfapi.initial.number.of.resource.blocks",
			FT_UINT8, BASE_DEC, NULL, 0x0,
			"The number of resource blocks used in the initial transmission of this transport block.", HFILL }
		},
		{ &hf_nfapi_dl_cqi_pmi_size,
			{ "DL cqi pmi size", "nfapi.dl.cqi.pmi.size",
			FT_UINT8, BASE_DEC, NULL, 0x0,
			"The size of the DL CQI/PMI in bits in case of this RI value. The size of the DL CQI / PMI / RI in bits in case of this CRI value", HFILL }
		},
		{ &hf_nfapi_report_type,
			{ "Report type", "nfapi.report.type",
			FT_BOOLEAN, 8, TFS(&nfapi_csi_report_type_strname), 0x0,
			"Type of CSI report", HFILL }
		},
		{ &hf_nfapi_dl_cqi_ri_pmi_size,
			{ "DL CQI/PMI/RI size", "nfapi.dl.cqi.ri.pmi.size",
			FT_UINT8, BASE_DEC, NULL, 0x0,
			"The size of the DL CQI/PMI/RI/CRI in bits", HFILL }
		},
		{ &hf_nfapi_control_type,
			{ "Control type", "nfapi.control.type",
			FT_BOOLEAN, 8, TFS(&nfapi_control_type_string_name), 0x0,
			NULL, HFILL }
		},
		{ &hf_nfapi_number_of_cc,
			{ "Number of cc", "nfapi.number.of.cc",
			FT_UINT8, BASE_DEC, NULL, 0x0,
			"The number of CC in the aperiodic report", HFILL }
		},
		{ &hf_nfapi_number_of_pucch_resource,
			{ "Number of PUCCH Resource", "nfapi.number.of.pucch.resource",
			FT_UINT8, BASE_DEC, NULL, 0x0,
			"A value of 2 indicates that the UE is configured to transmit on two antenna ports", HFILL }
		},
		{ &hf_nfapi_pucch_index_p1,
			{ "PUCCH Index P1", "nfapi.pucch.index.p1",
			FT_UINT16, BASE_DEC, NULL, 0x0,
			"The PUCCH Index value for antenna port P1", HFILL }
		},
		{ &hf_nfapi_n_pucch_1_0,
			{ "N PUCCH 1 0", "nfapi.n.pucch.1.0",
			FT_UINT8, BASE_DEC, NULL, 0x0,
			"HARQ resource 0", HFILL }
		},
		{ &hf_nfapi_n_pucch_1_1,
			{ "N PUCCH 1 1", "nfapi.n.pucch.1.1",
			FT_UINT8, BASE_DEC, NULL, 0x0,
			"HARQ resource 1", HFILL }
		},
		{ &hf_nfapi_n_pucch_1_2,
			{ "N PUCCH 1 2", "nfapi.n.pucch.1.2",
			FT_UINT8, BASE_DEC, NULL, 0x0,
			"HARQ resource 2", HFILL }
		},
		{ &hf_nfapi_n_pucch_1_3,
			{ "N PUCCH 1 3", "nfapi.n.pucch.1.3",
			FT_UINT8, BASE_DEC, NULL, 0x0,
			"HARQ resource 3", HFILL }
		},
		{ &hf_nfapi_srs_bandwidth,
			{ "SRS Bandwidth", "nfapi.srs.bandwidth",
			FT_UINT8, BASE_DEC, NULL, 0x0,
			"SRS Bandwidth. This value is fixed for a UE and allocated in RRC connection setup.", HFILL }
		},
		{ &hf_nfapi_frequency_domain_position,
			{ "Frequency Domain position", "nfapi.frequency.domain.position",
			FT_UINT8, BASE_DEC, NULL, 0x0,
			"Frequency-domain position, NRRC This value is fixed for a UE and allocated in RRC connection setup.", HFILL }
		},
		{ &hf_nfapi_srs_hopping_bandwidth,
			{ "SRS hopping bandwidth", "nfapi.srs.hopping.bandwidth",
			FT_UINT8, BASE_DEC, NULL, 0x0,
			"Configures the frequency hopping on the SRS. This value is fixed for a UE and allocated in RRC connection setup.", HFILL }
		},
		{ &hf_nfapi_transmission_comb,
			{ "Transmission comb", "nfapi.transmission.comb",
			FT_UINT8, BASE_DEC, NULL, 0x0,
			"Configures the frequency location of the SRS. This value is fixed for a UE and allocated in RRC connection setup.", HFILL }
		},
		{ &hf_nfapi_i_srs,
			{ "I SRS", "nfapi.i.srs",
			FT_UINT8, BASE_DEC, NULL, 0x0,
			"Defines the periodicity and subframe location of the SRS. SRS Configuration Index. This value is fixed for a UE and allocated in RRC connection setup.", HFILL }
		},
		{ &hf_nfapi_sounding_reference_cyclic_shift,
			{ "Sounding reference cyclic shift", "nfapi.sounding.reference.cyclic.shift",
			FT_UINT8, BASE_DEC, NULL, 0x0,
			"Configures the SRS sequence generation. This value is fixed for a UE and allocated in RRC connection setup.", HFILL }
		},
		{ &hf_nfapi_pdu_length,
			{ "PDU length", "nfapi.pdu.length",
			FT_UINT16, BASE_DEC, NULL, 0x0,
			"The total length (in bytes) of the PDU description and PDU data, without the padding bytes", HFILL }
		},
		{ &hf_nfapi_crc_flag,
			{ "CRC flag", "nfapi.crc.flag",
			FT_BOOLEAN, 8, TFS(&crc_flag_strname), 0x0,
			"A flag indicating if a CRC error was detected", HFILL }
		},
		{ &hf_nfapi_number_of_hi_pdus,
			{ "Number of HI Pdu's", "nfapi.number_of_hi_pdus",
			FT_UINT8, BASE_DEC, NULL, 0x0,
			"Number of HI PDUs included in this message", HFILL }
		},
		{ &hf_nfapi_number_of_dci_pdus,
			{ "Number of DCI Pdu's", "nfapi.number_of_dci_pdus",
			FT_UINT8, BASE_DEC, NULL, 0x0,
			"Number of DCI PDUs included in this message", HFILL }
		},
		{ &hf_nfapi_hi_dci0_pdu_type,
			{ "PDU Type", "nfapi.pdu_type",
			FT_UINT8, BASE_DEC, VALS(hi_dci0_pdu_type_vals), 0x0,
			NULL, HFILL }
		},
		{ &hf_nfapi_hi_value,
			{ "HI Value", "nfapi.hi_value",
			FT_BOOLEAN, 8, TFS(&hi_value_strname), 0x0,
			"The PHICH value which is sent on the resource", HFILL }
		},
		{ &hf_nfapi_i_phich,
			{ "i phich", "nfapi.i_phich",
			FT_UINT8, BASE_DEC, NULL, 0x0,
			"Is used in the calculation of the PHICH location. For TDD only", HFILL }
		},
		{ &hf_nfapi_flag_tb2,
			{ "Flag TB2", "nfapi.flag_tb2",
			FT_BOOLEAN, BASE_NONE, TFS(&flag_tb2_strname), 0x0,
			"Indicates is HI is present for a second transport block", HFILL }
		},
		{ &hf_nfapi_hi_value_2,
			{ "HI Value 2", "nfapi.hi_value_2",
			FT_BOOLEAN, BASE_NONE, TFS(&hi_value_strname), 0x0,
			"The PHICH value for a second transport block.", HFILL }
		},
		{ &hf_nfapi_ue_tx_antenna_selection,
			{ "UE Tx Antenna selection", "nfapi.ue_tx_antenna_selection",
			FT_UINT8, BASE_DEC, VALS(ue_tx_antenna_selection_vals), 0x0,
			"Indicates how the CRC is calculated on the PDCCH.", HFILL }
		},
		{ &hf_nfapi_cqi_csi_request,
			{ "cqi csi request", "nfapi.cqi_csi_request",
			FT_UINT8, BASE_DEC, NULL, 0x0,
			"Aperiodic CQI request flag", HFILL }
		},
		{ &hf_nfapi_ul_index,
			{ "UL Index", "nfapi.ul_index",
			FT_UINT8, BASE_DEC, NULL, 0x0,
			"Valid for TDD mode only", HFILL }
		},
		{ &hf_nfapi_dl_assignment_index,
			{ "DL Assignment Index", "nfapi.dl_assignment_index",
			FT_UINT8, BASE_DEC, NULL, 0x0,
			"Valid for TDD mode only.", HFILL }
		},
		{ &hf_nfapi_tpc_bitmap,
			{ "TPC bitmap", "nfapi.tpc_bitmap",
			FT_UINT8, BASE_DEC, NULL, 0x0,
			"TPC commands for PUCCH and PUSCH", HFILL }
		},
		{ &hf_nfapi_number_of_antenna_ports,
			{ "Number of antenna ports", "nfapi.number.of.antenna.ports",
			FT_UINT8, BASE_DEC, VALS(number_of_antenna_port_vals), 0x0,
			"Defines number of antenna ports for this ULSCH allocation", HFILL }
		},
		{ &hf_nfapi_size_of_cqi_csi_feild,
			{ "Size of cqi csi feild", "nfapi.size.of.cqi.csi.feild",
			FT_UINT8, BASE_DEC, VALS(size_of_cqi_csi_feild_vals), 0x0,
			"Indicates the size of the CQI/CSI request field", HFILL }
		},
		{ &hf_nfapi_new_data_indication_two,
			{ "New data indication 2", "nfapi.new.data.indication.two",
			FT_UINT8, BASE_DEC, NULL, 0x0,
			"The new data indicator for the second transport block", HFILL }
		},
		{ &hf_nfapi_resource_allocation_flag,
			{ "Resource allocation flag", "nfapi.resource.allocation.flag",
			FT_UINT8, BASE_DEC, NULL, 0x0,
			"Indicates if the Resource Allocation Type parameter is valid.", HFILL }
		},
		{ &hf_nfapi_dl_node_sync_t1,
			{ "DL Node Sync t1", "nfapi.dl.node.sync.t1",
			FT_UINT32, BASE_DEC | BASE_UNIT_STRING, &units_milliseconds, 0x0,
			"Offset from VNF SFN/SF 0/0 time reference of the DL Node Sync message transmission at the transport layer, in microseconds.", HFILL }
		},
		{ &hf_nfapi_dl_node_sync_delta_sfn_sf,
			{ "DL Node Sync Delta SFN SF", "nfapi.dl.node.sync.delta_sfn_sf",
			FT_INT32, BASE_DEC, NULL, 0x0,
			"The delta shift in subframes that the PNF PHY instance must update to on the next subframe boundary", HFILL }
		},
		{ &hf_nfapi_dl_cyclic_prefix_type,
			{ "DL Cyclic Prefix type", "nfapi.dl.cyclic.prefix.type",
			FT_BOOLEAN, 8, TFS(&cyclic_prefix_type_strname), 0x0,
			"Cyclic prefix type, used for DL", HFILL }
		},
		{ &hf_nfapi_ul_cyclic_prefix_type,
			{ "UL Cyclic Prefix type", "nfapi.ul.cyclic.prefix.type",
			FT_BOOLEAN, 8, TFS(&cyclic_prefix_type_strname), 0x0,
			"Cyclic prefix type, used for UL", HFILL }
		},
		{ &hf_nfapi_downlink_channel_bandwidth,
			{ "Downlink Channel Bandwidth", "nfapi.dl.channel.bandwidth",
			FT_UINT16, BASE_DEC, NULL, 0x0,
			"Downlink channel bandwidth in resource blocks.", HFILL }
		},
		{ &hf_nfapi_uplink_channel_bandwidth,
			{ "Uplink Channel Bandwidth", "nfapi.ul.channel_bandwidth",
			FT_UINT16, BASE_DEC, NULL, 0x0,
			"Uplink channel bandwidth in resource blocks.", HFILL }
		},
		{ &hf_nfapi_tx_antenna_ports,
			{ "Tx Antenna Ports", "nfapi.tx.antenna.ports",
			FT_UINT16, BASE_DEC, NULL, 0x0,
			"The number of cell specific or NB transmit antenna ports.", HFILL }
		},
		{ &hf_nfapi_rx_antenna_ports,
			{ "Tx Antenna Ports", "nfapi.rx.antenna.ports",
			FT_UINT16, BASE_DEC, NULL, 0x0,
			"The number of cell specific or NB receive antenna ports.", HFILL }
		},
		{ &hf_nfapi_ul_node_sync_t1,
			{ "UL Node Sync t1", "nfapi.ul.node.sync.t1",
			FT_UINT32, BASE_DEC | BASE_UNIT_STRING, &units_milliseconds, 0x0,
			"The supplied t1 field in the DL Node Sync", HFILL }
		},
		{ &hf_nfapi_ul_node_sync_t2,
			{ "UL Node Sync t2", "nfapi.ul.node.sync.t2",
			FT_UINT32, BASE_DEC | BASE_UNIT_STRING, &units_milliseconds, 0x0,
			"Offset from PNF SFN/SF 0/0 time reference of the DL Node Sync message reception at the transport layer, in microseconds.", HFILL }
		},
		{ &hf_nfapi_ul_node_sync_t3,
			{ "UL Node Sync t3", "nfapi.ul.node.sync.t3",
			FT_UINT32, BASE_DEC | BASE_UNIT_STRING, &units_milliseconds, 0x0,
			"Offset from PNF SFN/SF 0/0 time reference of the UL Node Sync message transmission at the transport layer, in microseconds.", HFILL }
		},
		{ &hf_nfapi_pb,
			{ "P-B", "nfapi.pb.allocation",
			FT_UINT16, BASE_DEC, NULL, 0x0,
			"Refers to downlink power allocation. Value is an Index into the referenced table.", HFILL }
		},
		{ &hf_nfapi_timing_info_last_sfn_sf,
			{ "Last SFN/SF", "nfapi.timing.info.last.sfn.sf",
			FT_UINT32, BASE_DEC, NULL, 0x0,
			"The completed SFN/SF at the PNF PHY instance that triggered the Timing Info message", HFILL }
		},
		{ &hf_nfapi_timing_info_time_since_last_timing_info,
			{ "Time since last Timing Info", "nfapi.timing.info.time.since.last.timing.info",
			FT_UINT32, BASE_DEC, NULL, 0x0,
			"The number of ms since the last Timing Info was sent from this PNF PHY instance.", HFILL }
		},
		{ &hf_nfapi_timing_info_dl_config_jitter,
			{ "DL Config Jitter", "nfapi.timing.info.dl.config.jitter",
			FT_UINT32, BASE_DEC, NULL, 0x0,
			"The inter message jitter of the DL Config message reception in microseconds", HFILL }
		},
		{ &hf_nfapi_timing_info_tx_request_jitter,
			{ "Tx Request Jitter", "nfapi.timing.info.tx.req.jitter",
			FT_UINT32, BASE_DEC, NULL, 0x0,
			"The inter message jitter of the Tx Request message reception in microseconds", HFILL }
		},
		{ &hf_nfapi_timing_info_ul_config_jitter,
			{ "UL Config Jitter", "nfapi.timing.info.ul.config.jitter",
			FT_UINT32, BASE_DEC, NULL, 0x0,
			"The inter message jitter of the UL Config message reception in microseconds", HFILL }
		},
		{ &hf_nfapi_timing_info_hi_dci0_jitter,
			{ "HI_DCI0 Jitter", "nfapi.timing.info.hi.dci0.jitter",
			FT_UINT32, BASE_DEC, NULL, 0x0,
			"The inter message jitter of the HI_DCI0 message reception in microseconds", HFILL }
		},
		{ &hf_nfapi_timing_info_dl_config_latest_delay,
			{ "DL Config Latest Delay", "nfapi.timing.info.dl.config.latest.delay",
			FT_INT32, BASE_DEC, NULL, 0x0,
			"The latest delay offset in microseconds from the latest acceptable time for the DL Config as defined in the DL Config Timing in the PNF_PARAM.Response since the last transmission of the Timing Info Message.", HFILL }
		},
		{ &hf_nfapi_timing_info_tx_request_latest_delay,
			{ "Tx Request Latest Delay", "nfapi.timing.info.tx.request.latest.delay",
			FT_INT32, BASE_DEC, NULL, 0x0,
			"The latest delay offset in microseconds from the latest acceptable time for the Tx Request as defined in the Tx Config Timing in the PNF_PARAM.Response since the last transmission of the Timing Info Message.", HFILL }
		},
		{ &hf_nfapi_timing_info_ul_config_latest_delay,
			{ "UL Config Latest Delay", "nfapi.timing.info.ul.config.latest.delay",
			FT_INT32, BASE_DEC, NULL, 0x0,
			"The latest delay offset in microseconds from the latest acceptable time for the UL Config as defined in the UL Config Timing in the PNF_PARAM.Response since the last transmission of the Timing Info Message.", HFILL }
		},
		{ &hf_nfapi_timing_info_hi_dci0_latest_delay,
			{ "HI_DCI0 Latest Delay", "nfapi.timing.info.hi.dci0.latest.delay",
			FT_INT32, BASE_DEC, NULL, 0x0,
			"The latest delay offset in microseconds from the latest acceptable time for the HI_DCI0 as defined in the HI_DCI0 Timing in the PNF_PARAM.Response since the last transmission of the Timing Info Message.", HFILL }
		},
		{ &hf_nfapi_timing_info_dl_config_earliest_arrival,
			{ "DL Config Earliest Arrival", "nfapi.timing.info.dl.config.earliest.arrival",
			FT_INT32, BASE_DEC, NULL, 0x0,
			"The earlierst arrival offset in microseconds from the latest time acceptable for the DL Config as defined in the Timing Window in the PARAM.Response since the last transmission of the Timing Info Message.", HFILL }
		},
		{ &hf_nfapi_timing_info_tx_request_earliest_arrival,
			{ "Tx Request Earliest Arrival", "nfapi.timing.info.tx.request.earliest.arrival",
			FT_INT32, BASE_DEC, NULL, 0x0,
			"The earlierst arrival offset in microseconds from the latest time acceptable for the Tx Request as defined in the Timing Window in the PARAM.Response since the last transmission of the Timing Info Message.", HFILL }
		},
		{ &hf_nfapi_timing_info_ul_config_earliest_arrival,
			{ "UL Config Earliest Arrival", "nfapi.timing.info.ul.config.earliest.arrival",
			FT_INT32, BASE_DEC, NULL, 0x0,
			"The earlierst arrival offset in microseconds from the latest time acceptable for the UL Config as defined in the Timing Window in the PARAM.Response since the last transmission of the Timing Info Message.", HFILL }
		},
		{ &hf_nfapi_timing_info_hi_dci0_earliest_arrival,
			{ "HI_DCI0 Earliest Arrival", "nfapi.timing.info.hi.dci0.earliest.arrival",
			FT_INT32, BASE_DEC, NULL, 0x0,
			"The earlierst arrival offset in microseconds from the latest time acceptable for the HI_DCI0 as defined in the Timing Window in the PARAM.Response since the last transmission of the Timing Info Message.", HFILL }
		},
		{ &hf_nfapi_pcfich_power_offset,
			{ "PCFICH Power Offset", "nfapi.pcfich.power.offset",
			FT_UINT16, BASE_CUSTOM, CF_FUNC(power_offset_conversion_fn), 0x0,
			"The power per antenna of the PCFICH with respect to the reference signal.", HFILL }
		},
		{ &hf_nfapi_timing_window,
			{ "NFAPI Timing window", "nfapi.timing.window",
			FT_UINT8, BASE_DEC, NULL, 0x0,
			"The window in milliseconds that the PHY must receive and queue the P7 messages.", HFILL }
		},
		{ &hf_nfapi_timing_info_mode,
			{ "Timing Info mode", "nfapi.timing.info.mode",
			FT_UINT8, BASE_DEC, NULL, 0x0,
			"The configured mode of operation for the timing info message to be sent to the VNF from the PHY", HFILL }
		},
		{ &hf_nfapi_timing_info_period,
			{ "Timing info period", "nfapi.timing.info.period",
			FT_UINT8, BASE_DEC, NULL, 0x0,
			"If Periodic timing mode is enabled, this defines the periodicity in subframes. This field is ignored if periodic timing mode is disabled.", HFILL }
		},
		{ &hf_nfapi_tdd_harq_mode,
			{ "Mode", "nfapi.tdd.harq.mode",
			FT_UINT8, BASE_DEC, VALS(tdd_harq_mode_vals), 0x0,
			"The format of the ACK/NACK response expected", HFILL }
		},
		{ &hf_nfapi_fdd_harq_mode,
			{ "Mode", "nfapi.fdd.harq.mode",
			FT_UINT8, BASE_DEC, VALS(fdd_harq_mode_vals), 0x0,
			"The format of the ACK/NACK response expected", HFILL }
		},
		{ &hf_nfapi_number_of_ack_nack,
			{ "Number of ACK/NACK", "nfapi.uint16.tag",
			FT_UINT16, BASE_DEC, NULL, 0x0,
			"The number of ACK/NACK results reported for this UE", HFILL }
		},
		{ &hf_nfapi_harq_data_value_0,
			{ "Value 0", "nfapi.harq.value.0",
			FT_UINT8, BASE_DEC, VALS(harq_value_vals), 0x0,
			"Indicates HARQ results", HFILL }
		},
		{ &hf_nfapi_harq_data_value_0_special,
			{ "Value 0", "nfapi.harq.value.0.special",
			FT_UINT8, BASE_DEC, VALS(harq_special_value_vals), 0x0,
			"Indicates HARQ results", HFILL }
		},
		{ &hf_nfapi_harq_data_value_1,
			{ "Value 1", "nfapi.harq.value.1",
			FT_UINT8, BASE_DEC, VALS(harq_value_vals), 0x0,
			"Indicates HARQ results", HFILL }
		},
		{ &hf_nfapi_harq_data_value_2,
			{ "Value 2", "nfapi.harq.value.2",
			FT_UINT8, BASE_DEC, VALS(harq_value_vals), 0x0,
			"Indicates HARQ results", HFILL }
		},
		{ &hf_nfapi_harq_data_value_3,
			{ "Value 3", "nfapi.harq.value.3",
			FT_UINT8, BASE_DEC, VALS(harq_value_vals), 0x0,
			"Indicates HARQ results", HFILL }
		},
		{ &hf_nfapi_harq_tb_1,
			{ "HARQ TB1", "nfapi.harq.tb.1",
			FT_UINT8, BASE_DEC, VALS(harq_value_vals), 0x0,
			"HARQ feedback of 1st TB.", HFILL }
		},
		{ &hf_nfapi_harq_tb_2,
			{ "HARQ TB2", "nfapi.harq.tb.2",
			FT_UINT8, BASE_DEC, VALS(harq_value_vals), 0x0,
			"HARQ feedback of 2nd TB.", HFILL }
		},
		{ &hf_nfapi_harq_tb_n,
			{ "HARQ TB_N", "nfapi.harq.tb.n",
			FT_UINT8, BASE_DEC, VALS(harq_value_vals), 0x0,
			"HARQ feedback of Nth TB.", HFILL }
		},
		{ &hf_nfapi_ul_cqi,
			{ "UL_CQI", "nfapi.ul.cqi",
			FT_UINT8, BASE_CUSTOM, CF_FUNC(ul_cqi_conversion_fn), 0x0,
			"SNR", HFILL }
		},
		{ &hf_nfapi_channel,
			{ "Channel", "nfapi.channel",
			FT_UINT8, BASE_DEC, VALS(channel_vals), 0x0,
			"The channel to which this measurement refers", HFILL }
		},
		{ &hf_nfapi_data_offset,
			{ "Data Offset", "nfapi.data.offset",
			FT_UINT16, BASE_DEC, NULL, 0x0,
			"Gives the PDU#i data address offset from the beginning of the 'Number of PDUs' field. An offset of 0 indicates a CRC or decoding error", HFILL }
		},
		{ &hf_nfapi_ri,
			{ "RI", "nfapi.ri",
			FT_UINT8, BASE_DEC, NULL, 0x0,
			"The rank indication reported by the UE on PUSCH for aperiodic CSI.", HFILL }
		},
		{ &hf_nfapi_timing_advance,
			{ "Timing Advance", "nfapi.timing.advance",
			FT_UINT16, BASE_DEC, NULL, 0x0,
			"The timing advance measured for this PDU and UE.", HFILL }
		},
		{ &hf_nfapi_timing_advance_r9,
			{ "Timing Advance R9", "nfapi.timing.advance.r9",
			FT_UINT16, BASE_DEC, NULL, 0x0,
			"Timing advance used for positioning", HFILL }
		},
		{ &hf_nfapi_number_of_cc_reported,
			{ "Number of CC reported", "nfapi.number.of.cc.reported",
			FT_UINT8, BASE_DEC, NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_nfapi_preamble,
			{ "Preamble", "nfapi.preamble",
			FT_UINT8, BASE_DEC, NULL, 0x0,
			"The detected preamble", HFILL }
		},
		{ &hf_nfapi_rach_resource_type,
			{ "RACH resource type", "nfapi.rach.resource.type",
			FT_UINT8, BASE_DEC, VALS(rach_resource_type_vals), 0x0,
			"Indicates if this indication is related to Cat-M UE and in which CE level", HFILL }
		},
		{ &hf_nfapi_doppler_estimation,
			{ "Doppler estimation", "nfapi.doppler.estimation",
			FT_UINT16, BASE_DEC, NULL, 0x0,
			"FFS", HFILL }
		},
		{ &hf_nfapi_rb_start,
			{ "RB Start", "nfapi.rb.start",
			FT_UINT8, BASE_DEC, NULL, 0x0,
			"The starting point of the RBs to be reported", HFILL }
		},
		{ &hf_nfapi_snr,
			{ "SNR", "nfapi.snr",
			FT_UINT8, BASE_CUSTOM, CF_FUNC(ul_cqi_conversion_fn), 0x0,
			"Field size dependent on configured bandwidth SNR for RBs, each RBs report one SNR.", HFILL }
		},
		{ &hf_nfapi_up_pts_symbol,
			{ "UpPTS Symbol", "nfapi.uppts.symbol",
			FT_UINT8, BASE_DEC, VALS(up_pts_symbol_vals), 0x0,
			"Indicates symbol where SRS was received. Only valid if the SRS was received in subframe 1 or 6.", HFILL }
		},
		{ &hf_nfapi_number_prb_per_subband,
			{ "numPRBperSubband", "nfapi.num.prb.per.subband",
			FT_UINT8, BASE_DEC, NULL, 0x0,
			"Number of PRBs that are treated as one subband", HFILL }
		},
		{ &hf_nfapi_number_antennas,
			{ "numAntennas", "nfapi.num.antennas",
			FT_UINT8, BASE_DEC, NULL, 0x0,
			"Number of physical antennas", HFILL }
		},
		{ &hf_nfapi_subband_index,
			{ "subbandIndex", "nfapi.subband.index",
			FT_UINT8, BASE_DEC, NULL, 0x0,
			"Index of subband for which the following channel coefficient is applied", HFILL }
		},
		{ &hf_nfapi_channel_coefficient,
			{ "Channel", "nfapi.channel.coefficient",
			FT_UINT16, BASE_DEC, NULL, 0x0,
			"Averaged channel coefficient in a subband for physical antenna #i, real 8 bits followed by imaginary 8 bits", HFILL }
		},
		{ &hf_nfapi_ul_rtoa,
			{ "UL_RTOA", "nfapi.ul.rtoa",
			FT_UINT16, BASE_DEC, NULL, 0x0,
			"UL relative time of arrival used for network based positioning", HFILL }
		},
		{ &hf_nfapi_frequency_band_indicator,
			{ "Frequency Band Indicator", "nfapi.frequency.band.indicator",
			FT_UINT16, BASE_DEC, NULL, 0x0,
			"The E-UTRA band for which the carrierList applies.", HFILL }
		},
		{ &hf_nfapi_measurement_period,
			{ "Measurement Period", "nfapi.measurement.period",
			FT_UINT16, BASE_DEC | BASE_UNIT_STRING, &units_milliseconds, 0x0,
			"The length of time to measure RSSI over, in units of 1ms.", HFILL }
		},
		{ &hf_nfapi_bandwidth,
			{ "Bandwidth", "nfapi.bandwidth",
			FT_UINT8, BASE_DEC, NULL, 0x0,
			"The bandwidth (in resource blocks) over which the RSSI is measured.", HFILL }
		},
		{ &hf_nfapi_timeout,
			{ "Timeout", "nfapi.timeout",
			FT_UINT32, BASE_DEC | BASE_UNIT_STRING, &units_milliseconds, 0x0,
			"The timeout value after which the PNF should abort the procedure in units of 1ms. The value of 0 indicates that the PNF should attempt to complete the procedure without any VNF-imposed timeout.", HFILL }
		},
		{ &hf_nfapi_number_of_earfcns,
			{ "Number of EARFCNs", "nfapi.number.of.earfcns",
			FT_UINT8, BASE_DEC, NULL, 0x0,
			"The number of EARFCNs which should be measured. In the case that no EARFCN (value 0) is specified, all valid EARFCNs for the specified bandwidth in the band shall be measured, in order of ascending EARCFN.", HFILL }
		},
		{ &hf_nfapi_uarfcn,
			{ "UARFCN", "nfapi.uarfcn",
			FT_UINT16, BASE_DEC, NULL, 0x0,
			"UARFCN to be measured.", HFILL }
		},
		{ &hf_nfapi_number_of_uarfcns,
			{ "Number of UARFCNs", "nfapi.number.of.uarfcn",
			FT_UINT8, BASE_DEC, NULL, 0x0,
			"The number of UARFCNs which should be measured. In the case that no UARFCN (value 0) is specified, all UARFCNs in the band shall be measured, in order of ascending UARCFN.", HFILL }
		},
		{ &hf_nfapi_arfcn,
			{ "ARFCN", "nfapi.arfcn",
			FT_UINT16, BASE_DEC, NULL, 0x0,
			"The ARFCN to be measured", HFILL }
		},
		{ &hf_nfapi_arfcn_direction,
			{ "Direction", "nfapi.arfcn.direction",
			FT_UINT8, BASE_DEC, VALS(arfcn_direction_vals), 0x0,
			"The link direction to be measured", HFILL }
		},
		{ &hf_nfapi_number_of_arfcns,
			{ "Number of ARFCNs", "nfapi.number.of.arfcn",
			FT_UINT8, BASE_DEC, NULL, 0x0,
			"The number of ARFCNs which should be measured. In the case that no ARFCN (value 0) is specified, all ARFCNs in the band shall be measured, in order of ascending ARCFN.", HFILL }
		},
		{ &hf_nfapi_rssi,
			{ "RSSI", "nfapi.rssi",
			FT_INT16, BASE_CUSTOM, CF_FUNC(rssi_conversion_fn), 0x0,
			"The list of RSSI values of the carriers measured, in the order of the list of the original request.", HFILL }
		},
		{ &hf_nfapi_number_of_rssi,
			{ "Number of RSSI", "nfapi.number.of.rssi",
			FT_UINT16, BASE_DEC, NULL, 0x0,
			"The number of RSSI results returned in the following array.", HFILL }
		},
		{ &hf_nfapi_pci,
			{ "PCI", "nfapi.pci",
			FT_UINT16, BASE_DEC, NULL, 0x0,
			"The PCI for cell which should be searched", HFILL }
		},
		{ &hf_nfapi_measurement_bandwidth,
			{ "Measurement Bandwidth", "nfapi.measurement.bandwidth",
			FT_UINT8, BASE_DEC, NULL, 0x0,
			"The number of resource blocks which should be used for measuring RSRP", HFILL }
		},
		{ &hf_nfapi_exhaustive_search,
			{ "Exhaustive Search", "nfapi.exhaustive.search",
			FT_UINT8, BASE_DEC, VALS(exhustive_search_vals), 0x0,
			"NMM should try to find all cells on the carrier", HFILL }
		},
		{ &hf_nfapi_number_of_pci,
			{ "Number of PCI", "nfapi.number.of.pci",
			FT_UINT8, BASE_DEC, NULL, 0x0,
			"The number of cells in the PCI list. If 0 all cells on the carrier should be found. Otherwise, depending on exhaustiveSearch flag, only the given pciList is searched or the pciList is used for indicating a priority list. Range: 0 to MAX_PCI_LIST.", HFILL }
		},
		{ &hf_nfapi_psc,
			{ "PSC", "nfapi.psc",
			FT_UINT16, BASE_DEC, NULL, 0x0,
			"The PSC for cells which should be searched.", HFILL }
		},
		{ &hf_nfapi_number_of_psc,
			{ "Number of PSC", "nfapi.number.of.psc",
			FT_UINT8, BASE_DEC, NULL, 0x0,
			"The number of cells in the PSC list. If 0 all cells on the carrier should be found. Otherwise, depending on Exhaustive Search flag, only the given PSC list is searched or the PSC list is used for indicating a priority list. Range: 0 to MAX_PSC_LIST.", HFILL }
		},
		{ &hf_nfapi_rsrp,
			{ "RSRP", "nfapi.rsrp",
			FT_UINT8, BASE_CUSTOM, CF_FUNC(neg_pow_conversion_fn), 0x0,
			"The measured RSRP value in units of -1dB", HFILL }
		},
		{ &hf_nfapi_rsrq,
			{ "RSRQ", "nfapi.rsrq",
			FT_UINT8, BASE_CUSTOM, CF_FUNC(neg_pow_conversion_fn), 0x0,
			"The measured RSRQ value in units of -1dB", HFILL }
		},
		{ &hf_nfapi_number_of_lte_cells_found,
			{ "Number of LTE Cells Found", "nfapi.number.of.lte.cells.found",
			FT_UINT16, BASE_DEC, NULL, 0x0,
			"The number of LTE cells indicated in this message.", HFILL }
		},
		{ &hf_nfapi_rscp,
			{ "RSCP", "nfapi.rscp",
			FT_UINT8, BASE_CUSTOM, CF_FUNC(neg_pow_conversion_fn), 0x0,
			"The measured RSCP value in units of -1dB", HFILL }
		},
		{ &hf_nfapi_enco,
			{ "EcNo", "nfapi.ecno",
			FT_UINT8, BASE_CUSTOM, CF_FUNC(neg_pow_conversion_fn), 0x0,
			"The measured RSCP value in units of -1dB", HFILL }
		},
		{ &hf_nfapi_number_of_utran_cells_found,
			{ "Number of UTRAN Cells Found", "nfapi.number.of.utran.cells.found",
			FT_UINT16, BASE_DEC, NULL, 0x0,
			"The number of LTE cells indicated in this message", HFILL }
		},
		{ &hf_nfapi_bsic,
			{ "BSIC", "nfapi.bsic",
			FT_UINT8, BASE_DEC, NULL, 0x0,
			"The BSIC of the cell which the NMM synchronized to", HFILL }
		},
		{ &hf_nfapi_rxlev,
			{ "RxLev", "nfapi.rxlev",
			FT_UINT8, BASE_DEC, NULL, 0x0,
			"The measured RxLev value", HFILL }
		},
		{ &hf_nfapi_rxqual,
			{ "RxQual", "nfapi.rxqual",
			FT_UINT8, BASE_DEC, NULL, 0x0,
			"The measured RxQual value", HFILL }
		},
		{ &hf_nfapi_sfn_offset,
			{ "SFN Offset", "nfapi.sfn.offset",
			FT_UINT32, BASE_DEC, NULL, 0x0,
			"The offset in us of the start of the current GSM Radio HyperFrame (i.e. FN=0) from the start of the preceding LTE Radio Frame of the PNF for SFN=0", HFILL }
		},
		{ &hf_nfapi_number_of_geran_cells_found,
			{ "Number of GSM Cells Found", "nfapi.number.of.geran.cells.found",
			FT_UINT16, BASE_DEC, NULL, 0x0,
			"The number of GSM cells indicated in this message", HFILL }
		},
		{ &hf_nfapi_number_of_tx_antenna,
			{ "Number of Tx Antenna", "nfapi.number.of.tx.antenna",
			FT_UINT8, BASE_DEC, NULL, 0x0,
			"The number of Tx Antenna detected for the cell", HFILL }
		},
		{ &hf_nfapi_mib,
			{ "MIB", "nfapi.mib",
			FT_UINT_BYTES, BASE_NONE, NULL, 0x0,
			"The MIB read from the specified cell.", HFILL }
		},
		{ &hf_nfapi_phich_configuration,
			{ "PHICH Configuration", "nfapi.phich.configuration",
			FT_UINT8, BASE_DEC, NULL, 0x0,
			"The PHICH-Config of the cell", HFILL }
		},
		{ &hf_nfapi_retry_count,
			{ "retryCount", "nfapi.retry.count",
			FT_UINT8, BASE_DEC, NULL, 0x0,
			"The number of SIB1 repetition periods for which decoding of SIB1 should be retried.", HFILL }
		},
		{ &hf_nfapi_sib1,
			{ "SIB1", "nfapi.sib1",
			FT_BYTES, BASE_NONE, NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_nfapi_si_periodicity,
			{ "SI Periodicity", "nfapi.si.periodicity",
			FT_UINT8, BASE_DEC, NULL, 0x0,
			"The SI Periodicity of the requested SIBs, with the first element being for SIB2, the next for SIB3, etc, encoded as follows", HFILL }
		},
		{ &hf_nfapi_si_index,
			{ "SI Index", "nfapi.si.index",
			FT_UINT8, BASE_DEC, NULL, 0x0,
			"The Index of this SIB in the SIB1 SchedulingInfoList:", HFILL }
		},
		{ &hf_nfapi_number_of_si_periodicity,
			{ "Number of SI Periodicity", "nfapi.number.of.si.periodicity",
			FT_UINT8, BASE_DEC, NULL, 0x0,
			"The number of System Information periodicity values in the following array", HFILL }
		},
		{ &hf_nfapi_si_window_length,
			{ "SI Window Length", "nfapi.si.window.length",
			FT_UINT8, BASE_DEC, NULL, 0x0,
			"The SI window in units of 1ms", HFILL }
		},
		{ &hf_nfapi_sib_type,
			{ "SIB Type", "nfapi.sib.type",
			FT_UINT8, BASE_DEC, NULL, 0x0,
			"The SIB type", HFILL }
		},
		{ &hf_nfapi_sib,
			{ "SIB", "nfapi.sib",
			FT_UINT_BYTES, BASE_NONE, NULL, 0x0,
			"The SIB element read from the specified cell.", HFILL }
		},
		{ &hf_nfapi_si,
			{ "SI", "nfapi.si",
			FT_UINT_BYTES, BASE_NONE, NULL, 0x0,
			"The SI element read from the specified cell.", HFILL }
		},
		{ &hf_nfapi_pnf_search_state,
			{ "State", "nfapi.state",
			FT_BYTES, BASE_NONE, NULL, 0x0,
			"A structure of opaque data optionally sent by the PNF to the VNF", HFILL }
		},
		{ &hf_nfapi_pnf_broadcast_state,
			{ "State", "nfapi.state",
			FT_BYTES, BASE_NONE, NULL, 0x0,
			"A structure of opaque data optionally sent by the PNF to the VNF", HFILL }
		},
		{ &hf_nfapi_dl_rs_tx_power,
			{ "DL RS Tx power", "nfapi.dl.rs.tx.power",
			FT_UINT16, BASE_DEC, NULL, 0x0,
			"The DL RS Tx power measurement", HFILL }
		},
		{ &hf_nfapi_received_interference_power,
			{ "Received interference power", "nfapi.received.interference.power",
			FT_UINT16, BASE_DEC | BASE_UNIT_STRING, &units_milliseconds, 0x0,
			"The Received interference power measurement", HFILL }
		},
		{ &hf_nfapi_thermal_noise_power,
			{ "Thermal noise power", "nfapi.thermal.noise.power",
			FT_UINT16, BASE_DEC | BASE_UNIT_STRING, &units_milliseconds, 0x0,
			"The Thermal noise power measurement", HFILL }
		},
		{ &hf_nfapi_dl_rs_tx_power_measurement,
			{ "DL RS TX Power measurement", "nfapi.dl.rs.tx.power.measurement",
			FT_INT16, BASE_CUSTOM, CF_FUNC(dl_rs_tx_pow_measment_conversion_fn), 0x0,
			"The DL RS Tx power measurement defined", HFILL }
		},
		{ &hf_nfapi_received_interference_power_measurement,
			{ "Received interference power measurement", "nfapi.received.interference.power.measurement",
			FT_INT16, BASE_CUSTOM, CF_FUNC(dl_rs_tx_pow_measment_conversion_fn), 0x0,
			NULL, HFILL }
		},
		{ &hf_nfapi_thermal_noise_power_measurement,
			{ "Thermal noise power measurement", "nfapi.thermal.noise.power.measurement",
			FT_INT16, BASE_CUSTOM, CF_FUNC(dl_rs_tx_pow_measment_conversion_fn), 0x0,
			"The Thermal noise power measurement", HFILL }
		},
		{ &hf_nfapi_initial_partial_sf,
			{ "Initial Partial SF", "nfapi.initial.partial.sf",
			FT_BOOLEAN, 32, TFS(&initial_partial_sf_strname), 0x0,
			"Indicates whether the initial SF in the LBT process is full or partial", HFILL }
		},
		{ &hf_nfapi_lbt_mode,
			{ "LBT Mode", "nfapi.lbt.mode",
			FT_BOOLEAN, 32, TFS(&lbt_mode_strname), 0x0,
			"Part of multi-carrier support. Indicates whether full LBT process is carried or partial LBT process is carried (multi carrier mode B according to [9] section 15.1.5.2)", HFILL }
		},
		{ &hf_nfapi_lte_txop_sf,
			{ "LTE TXOP SF", "nfapi.txop.sf",
			FT_UINT32, BASE_DEC, NULL, 0x0,
			"Indicates the LTE TXOP (TMCOT,P in [9] section 15.1.1) duration in subframes.", HFILL }
		},
		{ &hf_nfapi_mp_cca,
			{ "mp cca", "nfapi.mp.cca",
			FT_UINT32, BASE_DEC, NULL, 0x0,
			"Indicates the value of the defer factor", HFILL }
		},
		{ &hf_nfapi_n_cca,
			{ "n cca", "nfapi.n.cca",
			FT_UINT32, BASE_DEC, NULL, 0x0,
			"Indicates the value of LBT backoff counter", HFILL }
		},
		{ &hf_nfapi_offset,
			{ "offset", "nfapi.offset",
			FT_UINT32, BASE_DEC, NULL, 0x0,
			"Indicates the LBT start time in microseconds from the beginning of the subframe scheduled by this message.", HFILL }
		},
		{ &hf_nfapi_result,
			{ "result", "nfapi.result",
			FT_BOOLEAN, 32, TFS(&tfs_fail_success), 0x0,
			"Indicates the LBT procedure result of SFN/SF:", HFILL }
		},
		{ &hf_nfapi_sfn_sf_end,
			{ "SFN/SF End", "nfapi.sfn.sf.end",
			FT_UINT16, BASE_DEC, NULL, 0x0,
			"Indicates the SFN/SF by which the DRS window (Discovery signal occasion as described in [9] section 6.11A) must end. In worst case, this would be the last TXOP subframe.", HFILL }
		},
		{ &hf_nfapi_txop_sfn_sf_end,
			{ "TXOP SFN/SF End", "nfapi.txop.sfn.sf.end",
			FT_UINT16, BASE_DEC, NULL, 0x0,
			"Indicates the SFN/SF by which the TXOP must end. In worst case, this would be the last TXOP subframe.", HFILL }
		},
		{ &hf_nfapi_txop_symbols,
			{ "LTE TXOP symbols", "nfapi.lte.txop.symbols",
			FT_UINT32, BASE_DEC, NULL, 0x0,
			"Actual LTE TXOP in symbols", HFILL }
		},
	};

	/* Setup protocol subtree array */
	static gint *ett[] =
	{
		&ett_nfapi,
		&ett_nfapi_p4_p5_message_header,
		&ett_nfapi_p7_message_header,
		&ett_nfapi_tlv_tree,
		&ett_nfapi_tl,
		&ett_nfapi_pnf_phy_rf_config,
		&ett_nfapi_pnf_phy,
		&ett_nfapi_pnf_phy_rel10,
		&ett_nfapi_pnf_phy_rel11,
		&ett_nfapi_pnf_phy_rel12,
		&ett_nfapi_pnf_phy_rel13,
		&ett_nfapi_rf_bands,
		&ett_nfapi_bf_vectors,
		&ett_nfapi_csi_rs_bf_vector,
		&ett_nfapi_csi_rs_resource_configs,
		&ett_nfapi_tx_antenna_ports,
		&ett_nfapi_harq_ack_nack_data,
		&ett_nfapi_harq_data,
		&ett_nfapi_cc,
		&ett_nfapi_rbs,
		&ett_nfapi_antennas,
		&ett_nfapi_epdcch_prbs,
		&ett_nfapi_dl_config_request_pdu_list,
		&ett_nfapi_ul_config_request_pdu_list,
		&ett_nfapi_hi_dci0_request_pdu_list,
		&ett_nfapi_tx_request_pdu_list,
		&ett_nfapi_rx_indication_pdu_list,
		&ett_nfapi_harq_indication_pdu_list,
		&ett_nfapi_crc_indication_pdu_list,
		&ett_nfapi_sr_indication_pdu_list,
		&ett_nfapi_cqi_indication_pdu_list,
		&ett_nfapi_preamble_indication_pdu_list,
		&ett_nfapi_srs_indication_pdu_list,
		&ett_nfapi_lbt_dl_config_pdu_list,
		&ett_nfapi_lbt_dl_indication_pdu_list,
		&ett_nfapi_subbands,
		&ett_nfapi_precoding,
		&ett_nfapi_bf_vector_antennas,
		&ett_nfapi_received_interference_power_mesurement_results,
		&ett_nfapi_downlink_bandwidth_support,
		&ett_nfapi_uplink_bandwidth_support,
		&ett_nfapi_release_support,
		&ett_nfapi_downlink_modulation_support,
		&ett_nfapi_uplink_modulation_support,

		&ett_nfapi_earfcn_list,
		&ett_nfapi_uarfcn_list,
		&ett_nfapi_arfcn_list,
		&ett_nfapi_rssi_list,
		&ett_nfapi_pci_list,
		&ett_nfapi_psc_list,
		&ett_nfapi_lte_cells_found_list,
		&ett_nfapi_utran_cells_found_list,
		&ett_nfapi_geran_cells_found_list,
		&ett_nfapi_si_periodicity_list,

		/* for fragmentation support*/
		&ett_msg_fragment,
		&ett_msg_fragments
	};

	static ei_register_info ei[] =
	{
		{ &ei_invalid_range, { "nfapi.invalid.range", PI_PROTOCOL, PI_WARN, "Invalid range", EXPFILL } },
		{ &ei_invalid_tlv_length, { "nfapi.invalid.tlv.length", PI_PROTOCOL, PI_ERROR, "Invalid TLV length", EXPFILL } },
	};

	expert_module_t* expert_nfapi;
	/* Register protocol */
	proto_nfapi = proto_register_protocol("Nfapi", "NFAPI", "nfapi");

	expert_nfapi = expert_register_protocol(proto_nfapi);
	expert_register_field_array(expert_nfapi, ei, array_length(ei));


	proto_register_field_array(proto_nfapi, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));

	message_table = register_dissector_table("nfapi.msg_id", "NFAPI Message ID", proto_nfapi, FT_UINT16, BASE_DEC);

	reassembly_table_register(&ul_p7_reassemble_table, &addresses_ports_reassembly_table_functions);
	reassembly_table_register(&dl_p7_reassemble_table, &addresses_ports_reassembly_table_functions);

	nfapi_handle = register_dissector("nfapi", dissect_nfapi, proto_nfapi);

}

// ----------------------------------------------------------------------------|

void proto_reg_handoff_nfapi(void)
{
	dissector_handle_t handle;

	handle = create_dissector_handle( dissect_nfapi_ul_p7, -1 );
	dissector_add_uint("nfapi.msg_id", NFAPI_HARQ_INDICATION_MSG_ID, handle);
	dissector_add_uint("nfapi.msg_id", NFAPI_CRC_INDICATION_MSG_ID, handle);
	dissector_add_uint("nfapi.msg_id", NFAPI_RX_ULSCH_INDICATION_MSG_ID, handle);
	dissector_add_uint("nfapi.msg_id", NFAPI_RACH_INDICATION_MSG_ID, handle);
	dissector_add_uint("nfapi.msg_id", NFAPI_SRS_INDICATION_MSG_ID, handle);
	dissector_add_uint("nfapi.msg_id", NFAPI_RX_SR_INDICATION_MSG_ID, handle);
	dissector_add_uint("nfapi.msg_id", NFAPI_RX_CQI_INDICATION_MSG_ID, handle);

	handle = create_dissector_handle( dissect_nfapi_dl_p7, -1 );
	dissector_add_uint("nfapi.msg_id", NFAPI_DL_CONFIG_REQUEST_MSG_ID, handle);
	dissector_add_uint("nfapi.msg_id", NFAPI_UL_CONFIG_REQUEST_MSG_ID, handle);
	dissector_add_uint("nfapi.msg_id", NFAPI_HI_DCI0_REQUEST_MSG_ID, handle);
	dissector_add_uint("nfapi.msg_id", NFAPI_TX_REQUEST_MSG_ID, handle);
	dissector_add_uint("nfapi.msg_id", NFAPI_LBT_DL_CONFIG_REQUEST_MSG_ID, handle);
	dissector_add_uint("nfapi.msg_id", NFAPI_LBT_DL_INDICATION_MSG_ID, handle);

	handle = create_dissector_handle( dissect_p45_header, -1 );
	dissector_add_uint("nfapi.msg_id", NFAPI_PNF_START_REQUEST_MSG_ID, handle);
	dissector_add_uint("nfapi.msg_id", NFAPI_PNF_STOP_REQUEST_MSG_ID, handle);
	dissector_add_uint("nfapi.msg_id", NFAPI_PARAM_REQUEST_MSG_ID, handle);
	dissector_add_uint("nfapi.msg_id", NFAPI_START_REQUEST_MSG_ID, handle);
	dissector_add_uint("nfapi.msg_id", NFAPI_STOP_REQUEST_MSG_ID, handle);
	dissector_add_uint("nfapi.msg_id", NFAPI_NMM_STOP_REQUEST_MSG_ID, handle);

	handle = create_dissector_handle( dissect_p45_header_with_list, -1 );
	dissector_add_uint("nfapi.msg_id", NFAPI_PNF_PARAM_REQUEST_MSG_ID, handle);
	dissector_add_uint("nfapi.msg_id", NFAPI_PNF_CONFIG_REQUEST_MSG_ID, handle);
	dissector_add_uint("nfapi.msg_id", NFAPI_MEASUREMENT_REQUEST_MSG_ID, handle);

	handle = create_dissector_handle( dissect_p45_header_with_error, -1 );
	dissector_add_uint("nfapi.msg_id", NFAPI_PNF_CONFIG_RESPONSE_MSG_ID, handle);
	dissector_add_uint("nfapi.msg_id", NFAPI_PNF_START_RESPONSE_MSG_ID, handle);
	dissector_add_uint("nfapi.msg_id", NFAPI_PNF_STOP_RESPONSE_MSG_ID, handle);
	dissector_add_uint("nfapi.msg_id", NFAPI_CONFIG_RESPONSE_MSG_ID, handle);
	dissector_add_uint("nfapi.msg_id", NFAPI_START_RESPONSE_MSG_ID, handle);
	dissector_add_uint("nfapi.msg_id", NFAPI_STOP_RESPONSE_MSG_ID, handle);

	handle = create_dissector_handle( dissect_p45_header_with_p4_error, -1 );
	dissector_add_uint("nfapi.msg_id", NFAPI_RSSI_RESPONSE_MSG_ID, handle);
	dissector_add_uint("nfapi.msg_id", NFAPI_CELL_SEARCH_RESPONSE_MSG_ID, handle);
	dissector_add_uint("nfapi.msg_id", NFAPI_BROADCAST_DETECT_RESPONSE_MSG_ID, handle);
	dissector_add_uint("nfapi.msg_id", NFAPI_SYSTEM_INFORMATION_SCHEDULE_RESPONSE_MSG_ID, handle);
	dissector_add_uint("nfapi.msg_id", NFAPI_SYSTEM_INFORMATION_RESPONSE_MSG_ID, handle);
	dissector_add_uint("nfapi.msg_id", NFAPI_NMM_STOP_RESPONSE_MSG_ID, handle);

	handle = create_dissector_handle( dissect_p45_header_with_error_and_list, -1 );
	dissector_add_uint("nfapi.msg_id", NFAPI_PNF_PARAM_RESPONSE_MSG_ID, handle);
	dissector_add_uint("nfapi.msg_id", NFAPI_MEASUREMENT_RESPONSE_MSG_ID, handle);

	handle = create_dissector_handle( dissect_p45_header_with_p4_error_and_list, -1 );
	dissector_add_uint("nfapi.msg_id", NFAPI_RSSI_INDICATION_MSG_ID, handle);
	dissector_add_uint("nfapi.msg_id", NFAPI_CELL_SEARCH_INDICATION_MSG_ID, handle);
	dissector_add_uint("nfapi.msg_id", NFAPI_BROADCAST_DETECT_INDICATION_MSG_ID, handle);
	dissector_add_uint("nfapi.msg_id", NFAPI_SYSTEM_INFORMATION_SCHEDULE_INDICATION_MSG_ID, handle);
	dissector_add_uint("nfapi.msg_id", NFAPI_SYSTEM_INFORMATION_INDICATION_MSG_ID, handle);

	handle = create_dissector_handle( dissect_p45_header_with_rat_type_list, -1 );
	dissector_add_uint("nfapi.msg_id", NFAPI_RSSI_REQUEST_MSG_ID, handle);
	dissector_add_uint("nfapi.msg_id", NFAPI_CELL_SEARCH_REQUEST_MSG_ID, handle);
	dissector_add_uint("nfapi.msg_id", NFAPI_BROADCAST_DETECT_REQUEST_MSG_ID, handle);
	dissector_add_uint("nfapi.msg_id", NFAPI_SYSTEM_INFORMATION_SCHEDULE_REQUEST_MSG_ID, handle);
	dissector_add_uint("nfapi.msg_id", NFAPI_SYSTEM_INFORMATION_REQUEST_MSG_ID, handle);

	dissector_add_uint("nfapi.msg_id", NFAPI_CONFIG_REQUEST_MSG_ID, create_dissector_handle( dissect_p45_config_request_msg_id, -1 ));
	dissector_add_uint("nfapi.msg_id", NFAPI_PARAM_RESPONSE_MSG_ID, create_dissector_handle( dissect_p45_param_response_msg_id, -1 ));
	dissector_add_uint("nfapi.msg_id", NFAPI_DL_NODE_SYNC_MSG_ID, create_dissector_handle( dissect_p7_dl_node_sync_msg_id, -1 ));
	dissector_add_uint("nfapi.msg_id", NFAPI_UL_NODE_SYNC_MSG_ID, create_dissector_handle( dissect_p7_ul_node_sync_msg_id, -1 ));
	dissector_add_uint("nfapi.msg_id", NFAPI_TIMING_INFO_MSG_ID, create_dissector_handle( dissect_p7_timing_info_msg_id, -1 ));

	dissector_add_for_decode_as("sctp.port", nfapi_handle);
	dissector_add_for_decode_as("udp.port", nfapi_handle);
}


/*
* Editor modelines  -  https://www.wireshark.org/tools/modelines.html
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
