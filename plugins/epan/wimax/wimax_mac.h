/* wimax_mac.h
 * WiMax MAC Definitions
 *
 * Copyright (c) 2007 by Intel Corporation.
 *
 * Author: Lu Pan <lu.pan@intel.com>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1999 Gerald Combs
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

#ifndef WIMAX_MAC_H
#define WIMAX_MAC_H

#define		IP_HEADER_BYTE			0x45

/* WiMax MAC Header/Subheader Sizes */
#define		WIMAX_MAC_HEADER_SIZE                   6
#define		WIMAX_MAC_SUBHEADER_MESH_SIZE           2
#define		WIMAX_MAC_SUBHEADER_FAST_FEEDBACK_SIZE  1
#define		WIMAX_MAC_SUBHEADER_GRANT_MGMT_SIZE     2

#define		WIMAX_MAC_SUBHEADER_FRAG_SIZE(x)	(((x) & (WIMAX_MAC_TYPE_EXTENDED | WIMAX_MAC_TYPE_ARQ)) ? 3 : 2)
#define		WIMAX_MAC_SUBHEADER_PACK_SIZE(x)	(((x) & (WIMAX_MAC_TYPE_EXTENDED | WIMAX_MAC_TYPE_ARQ)) ? 3 : 2)

#define		WIMAX_MAC_HEADER_GENERIC	0
#define		WIMAX_MAC_CID_PADDING           0xFFFE

/* wimax mac arq */
#define		ARQ_CUMULATIVE_ACK_ENTRY	1
#define		ARQ_CUMULATIVE_ACK_BLOCK_SEQ	3
#define		ARQ_ACK_MAP_SIZE		2

/* WiMax MAC Header Sub-types (Table 6) */
#define		WIMAX_MAC_TYPE_MESH		(1 << 5)
#define		WIMAX_MAC_TYPE_ARQ		(1 << 4)
#define		WIMAX_MAC_TYPE_EXTENDED		(1 << 3)
#define		WIMAX_MAC_TYPE_FRAGMENTATION	(1 << 2)
#define		WIMAX_MAC_TYPE_PACKING		(1 << 1)
#define		WIMAX_MAC_TYPE_FAST_FEEDBACK	(1 << 0)
#define		WIMAX_MAC_TYPE_GRANT_MGMT	(1 << 0)

/* wimax mac management messages (Table 14) */
#define		MAC_MGMT_MSG_UCD		0
#define		MAC_MGMT_MSG_DCD		1
#define		MAC_MGMT_MSG_DL_MAP		2
#define		MAC_MGMT_MSG_UL_MAP		3
#define		MAC_MGMT_MSG_RNG_REQ		4
#define		MAC_MGMT_MSG_RNG_RSP		5
#define		MAC_MGMT_MSG_REG_REQ		6
#define		MAC_MGMT_MSG_REG_RSP		7

#define		MAC_MGMT_MSG_PKM_REQ		9
#define		MAC_MGMT_MSG_PKM_RSP		10
#define		MAC_MGMT_MSG_DSA_REQ		11
#define		MAC_MGMT_MSG_DSA_RSP		12
#define		MAC_MGMT_MSG_DSA_ACK		13
#define		MAC_MGMT_MSG_DSC_REQ		14
#define		MAC_MGMT_MSG_DSC_RSP		15
#define		MAC_MGMT_MSG_DSC_ACK		16
#define		MAC_MGMT_MSG_DSD_REQ		17
#define		MAC_MGMT_MSG_DSD_RSP		18

#define		MAC_MGMT_MSG_MCA_REQ		21
#define		MAC_MGMT_MSG_MCA_RSP		22
#define		MAC_MGMT_MSG_DBPC_REQ		23
#define		MAC_MGMT_MSG_DBPC_RSP		24
#define		MAC_MGMT_MSG_RES_CMD		25
#define		MAC_MGMT_MSG_SBC_REQ		26
#define		MAC_MGMT_MSG_SBC_RSP		27
#define		MAC_MGMT_MSG_CLK_CMP		28
#define		MAC_MGMT_MSG_DREG_CMD		29
#define		MAC_MGMT_MSG_DSX_RVD		30
#define		MAC_MGMT_MSG_TFTP_CPLT		31
#define		MAC_MGMT_MSG_TFTP_RSP		32
#define		MAC_MGMT_MSG_ARQ_FEEDBACK	33
#define		MAC_MGMT_MSG_ARQ_DISCARD	34
#define		MAC_MGMT_MSG_ARQ_RESET		35
#define		MAC_MGMT_MSG_REP_REQ		36
#define		MAC_MGMT_MSG_REP_RSP		37
#define		MAC_MGMT_MSG_FPC		38
#define		MAC_MGMT_MSG_MSH_NCFG		39
#define		MAC_MGMT_MSG_MSH_NENT		40
#define		MAC_MGMT_MSG_MSH_DSCH		41
#define		MAC_MGMT_MSG_MSH_CSCH		42
#define		MAC_MGMT_MSG_MSH_CSCF		43
#define		MAC_MGMT_MSG_AAS_FBCK_REQ	44
#define		MAC_MGMT_MSG_AAS_FBCK_RSP	45
#define		MAC_MGMT_MSG_AAS_BEAM_SELECT	46
#define		MAC_MGMT_MSG_AAS_BEAM_REQ	47
#define		MAC_MGMT_MSG_AAS_BEAM_RSP	48
#define		MAC_MGMT_MSG_DREG_REQ		49

#define		MAC_MGMT_MSG_MOB_SLP_REQ	50
#define		MAC_MGMT_MSG_MOB_SLP_RSP	51
#define		MAC_MGMT_MSG_MOB_TRF_IND	52
#define		MAC_MGMT_MSG_MOB_NBR_ADV	53
#define		MAC_MGMT_MSG_MOB_SCN_REQ	54
#define		MAC_MGMT_MSG_MOB_SCN_RSP	55
#define		MAC_MGMT_MSG_MOB_BSHO_REQ	56
#define		MAC_MGMT_MSG_MOB_MSHO_REQ	57
#define		MAC_MGMT_MSG_MOB_BSHO_RSP	58
#define		MAC_MGMT_MSG_MOB_HO_IND		59
#define		MAC_MGMT_MSG_MOB_SCN_REP	60
#define		MAC_MGMT_MSG_MOB_PAG_ADV	61
#define		MAC_MGMT_MSG_MBS_MAP		62
#define		MAC_MGMT_MSG_PMC_REQ		63
#define		MAC_MGMT_MSG_PMC_RSP		64
#define		MAC_MGMT_MSG_PRC_LT_CTRL	65
#define		MAC_MGMT_MSG_MOB_ASC_REP	66
#define		MAC_MGMT_MSG_TYPE_MAX		67

/* DL-MAP types (Table 276) */
#define		DL_MAP_EXTENDED_2_DIUC          14
#define		DL_MAP_EXTENDED_IE              15
/* DL-MAP Extended UIUC Code (table 277a) */
#define		DL_MAP_AAS_IE                   2
#define		DL_MAP_EXTENDED_CID_SWITCH_IE   4
#define		DL_MAP_HARQ_IE                  7
/* DL-MAP Extended-2 UIUC Code (table 277c) */
#define		DL_MAP_EXTENDED_2_HARQ          7

/* UL-MAP types (Table 288) */
#define		UL_MAP_FAST_FEEDBACK_CHANNEL    0
#define		UL_MAP_CDMA_BR_RANGING_IE       12
#define		UL_MAP_PAPR_RECUCTION_ALLOC_SAFETY_ZONE 13
#define		UL_MAP_CDMA_ALLOCATION_IE       14
#define		UL_MAP_EXTENDED_IE              15
/* UL-MAP Extended UIUC Code (table 290a) */
#define		UL_MAP_CQICH_ALLOCATION_IE      3

/* DCD types (Table 358)*/
#define		DCD_DOWNLINK_BURST_PROFILE	1
#define		DCD_BS_EIRP			2
#define		DCD_FRAME_DURATION		3
#define		DCD_PHY_TYPE			4
#define		DCD_POWER_ADJUSTMENT		5
#define		DCD_CHANNEL_NR			6
#define		DCD_TTG				7
#define		DCD_RTG				8
#define		DCD_RSS				9
#define		DCD_EIRXP			9
#define		DCD_CHANNEL_SWITCH_FRAME_NR	10
#define		DCD_FREQUENCY			12
#define		DCD_BS_ID			13
#define		DCD_FRAME_DURATION_CODE		14
#define		DCD_FRAME_NR			15
#define		DCD_SIZE_CQICH_ID		16
#define		DCD_H_ARQ_ACK_DELAY		17
#define		DCD_MAC_VERSION			148

#define		DCD_RESTART_COUNT               154

#define		DCD_BURST_FREQUENCY		1
#define		DCD_BURST_FEC_CODE_TYPE		150
#define		DCD_BURST_DIUC_EXIT_THRESHOLD	151
#define		DCD_BURST_DIUC_ENTRY_THRESHOLD	152
#define		DCD_BURST_TCS_ENABLE		153
/*#define		DCD_MAXIMUM_RETRANSMISSION      20*/
/* TLV types */
#define		DCD_TLV_T_19_PERMUTATION_TYPE_FOR_BROADCAST_REGION_IN_HARQ_ZONE 19
#define		DCD_TLV_T_20_MAXIMUM_RETRANSMISSION    20
#define		DCD_TLV_T_21_DEFAULT_RSSI_AND_CINR_AVERAGING_PARAMETER   21
#define		DCD_TLV_T_22_DL_AMC_ALLOCATED_PHYSICAL_BANDS_BITMAP      22
#define		DCD_TLV_T_34_DL_REGION_DEFINITION 34
#define		DCD_TLV_T_50_HO_TYPE_SUPPORT      50
#define		DCD_TLV_T_31_H_ADD_THRESHOLD      31
#define		DCD_TLV_T_32_H_DELETE_THRESHOLD   32
#define		DCD_TLV_T_33_ASR                  33
#define		DCD_TLV_T_34_DL_REGION_DEFINITION 34
#define		DCD_TLV_T_35_PAGING_GROUP_ID      35
#define		DCD_TLV_T_36_TUSC1_PERMUTATION_ACTIVE_SUBCHANNELS_BITMAP 36
#define		DCD_TLV_T_37_TUSC2_PERMUTATION_ACTIVE_SUBCHANNELS_BITMAP 37
#define		DCD_TLV_T_51_HYSTERSIS_MARGIN     51
#define		DCD_TLV_T_52_TIME_TO_TRIGGER_DURATION 52
#define		DCD_TLV_T_54_TRIGGER                  54
#define		DCD_TLV_T_60_NOISE_AND_INTERFERENCE   60
#define		DCD_TLV_T_153_DOWNLINK_BURST_PROFILE_FOR_MULTIPLE_FEC_TYPES 153
#define		DCD_TLV_T_22_DL_AMC_ALLOCATED_PHYSICAL_BANDS_BITMAP  22
#define		DCD_TLV_T_541_TYPE_FUNCTION_ACTION 1
#define		DCD_TLV_T542_TRIGGER_VALUE  2
#define		DCD_TLV_T_543_TRIGGER_AVERAGING_DURATION 3
#define		DCD_TLV_T_45_PAGING_INTERVAL_LENGTH   45

/* UCD types (Table 353) */
#define		UCD_UPLINK_BURST_PROFILE   	    1
#define		UCD_RESERVATION_TIMEOUT	   	    2
#define		UCD_BW_REQ_SIZE			    3
#define		UCD_RANGING_REQ_SIZE		    4
#define		UCD_FREQUENCY			    5

#define		UCD_TLV_T_7_HO_RANGING_START        7
#define		UCD_TLV_T_8_RANGING_HO_END          8
#define		UCD_INITIAL_RANGING_CODES	    150
#define		UCD_PERIODIC_RANGING_CODES	    151
#define		UCD_BANDWIDTH_REQUEST_CODES         152
#define		UCD_PERIODIC_RANGING_BACKOFF_START  153
#define		UCD_PERIODIC_RANGING_BACKOFF_END    154
#define		UCD_START_OF_RANGING_CODES_GROUP    155
#define		UCD_PERMUTATION_BASE                156
#define		UCD_UL_ALLOCATED_SUBCHANNELS_BITMAP 157
#define		UCD_TLV_T_158_OPTIONAL_PERMUTATION_UL_ALLOCATED_SUBCHANNELS_BITMAP 158
#define		UCD_TLV_T_159_BAND_AMC_ALLOCATION_THRESHHOLD 159
#define		UCD_TLV_T_160_BAND_AMC_RELEASE_THRESHOLD     160
#define		UCD_TLV_T_161_BAND_AMC_ALLOCATION_TIMER      161
#define		UCD_TLV_T_162_BAND_AMC_RELEASE_TIMER         162
#define		UCD_TLV_T_163_BAND_STATUS_REPORT_MAX_PERIOD  163
#define		UCD_TLV_T_164_BAND_AMC_RETRY_TIMER           164
#define		UCD_TLV_T_170_SAFETY_CHANNEL_RETRY_TIMER     170
#define		UCD_TLV_T_171_HARQ_ACK_DELAY_FOR_DL_BURST    171

#define		UCD_TLV_T_172_CQICH_BAND_AMC_TRANSITION_DELAY 172
#define		UCD_TLV_T_174_MAXIMUM_RETRANSMISSION         174
#define		UCD_TLV_T_176_SIZE_OF_CQICH_ID_FIELD         176
#define		UCD_TLV_T_177_NORMALIZED_CN_OVERRIDE_2       177
#define		UCD_TLV_T_186_UPPER_BOUND__AAS_PREAMBLE      186
#define		UCD_TLV_T_187_LOWER_BOUND_AAS_PREAMBLE       187
#define		UCD_TLV_T_188_ALLOW_AAS_BEAM_SELECT_MESSAGE  188
#define		UCD_TLV_T_189_USE_CQICH_INDICATION_FLAG      189
#define		UCD_TLV_T_190_MS_SPECIFIC_UP_POWER_OFFSET_ADJUSTMENT_STEP    190
#define		UCD_TLV_T_191_MS_SPECIFIC_DOWN_POWER_OFSET_ADJUSTMENT_STEP   191
#define		UCD_TLV_T_192_MIN_LEVEL_POWER_OFFSET_ADJUSTMENT              192
#define		UCD_TLV_T_193_MAX_LEVEL_POWER_OFFSETR_ADJUSTMENT             193
#define		UCD_TLV_T_194_HANDOVER_RANGING_CODES                         194
#define		UCD_TLV_T_195_INITIAL_RANGING_INTERVAL                       195
#define		UCD_TLV_T_196_TX_POWER_REPORT                                196
#define		UCD_TLV_T_197_NORMALIZED_CN_FOR_CHANNEL_SOUNDING             197
#define		UCD_TLV_T_198_INTIAL_RANGING_BACKOFF_START                   198
#define		UCD_TLV_T_199_INITIAL_RANGING_BACKOFF_END                    199
#define		UCD_TLV_T_200_BANDWIDTH_REQUESET_BACKOFF_START               200
#define		UCD_TLV_T_201_BANDWIDTH_REQUEST_BACKOFF_END                  201
#define		UCD_TLV_T_202_UPLINK_BURST_PROFILE_FOR_MULTIPLE_FEC_TYPES    202
#define		UCD_TLV_T_203_UL_PUSC_SUBCHANNEL_ROTATION		     203
#define		UCD_TLV_T_205_RELATIVE_POWER_OFFSET_UL_HARQ_BURST	     205
#define		UCD_TLV_T_206_RELATIVE_POWER_OFFSET_UL_BURST_CONTAINING_MAC_MGMT_MSG	 206
#define		UCD_TLV_T_207_UL_INITIAL_TRANSMIT_TIMING		     207
#define		UCD_TLV_T_210_FAST_FEEDBACK_REGION			     210
#define		UCD_TLV_T_211_HARQ_ACK_REGION				     211
#define		UCD_TLV_T_212_RANGING_REGION				     212
#define		UCD_TLV_T_213_SOUNDING_REGION				     213

/* Table 357 */
#define		UCD_BURST_FEC				150
#define		UCD_BURST_RANGING_DATA_RATIO		151
/*#define		UCD_BURST_POWER_BOOST		151*/
/*#define		UCD_BURST_TCS_ENABLE		152*/

/* RNG-REQ types (Table 364) */
/* Sorted these values */
#define		RNG_REQ_DL_BURST_PROFILE                1
#define		RNG_REQ_SS_MAC_ADDRESS                  2
#define		RNG_REQ_RANGING_ANOMALIES               3
#define		RNG_REQ_AAS_BROADCAST                   4
#define		RNG_REQ_SERVING_BS_ID                   5
#define		RNG_REQ_RANGING_PURPOSE_INDICATION      6
#define		RNG_REQ_HO_ID                           7
#define		RNG_REQ_POWER_DOWN_INDICATOR            8
#define		RNG_REQ_PAGING_CONTROLLER_ID            9
#define		RNG_REQ_MAC_HASH_SKIP_THRESHOLD         10
#define		RNG_REQ_ENABLED_ACTION_TRIGGERED        11
#define		RNG_REQ_REQUESTED_DNLK_REP_CODING_LEVEL 12
#define		RNG_REQ_CMAC_KEY_COUNT			13
#define		RNG_REQ_POWER_SAVING_CLASS_PARAMETERS   21

/* RNG-REQ/RSP Power Saving Class Parameter TLV's (Table 364a) */
#define		RNG_POWER_SAVING_CLASS_FLAGS            1
#define		RNG_POWER_SAVING_CLASS_ID               2
#define		RNG_POWER_SAVING_CLASS_TYPE             3
#define		RNG_START_FRAME_NUMBER                  4
#define		RNG_INITIAL_SLEEP_WINDOW                5
#define		RNG_LISTENING_WINDOW                    6
#define		RNG_FINAL_SLEEP_WINDOW_BASE             7
#define		RNG_FINAL_SLEEP_WINDOW_EXPONENT         8
#define		RNG_SLPID                               9
#define		RNG_CID                                 10
#define		RNG_DIRECTION                           11

/* RNG-RSP types (Table 367) */
#define		RNG_RSP_TIMING_ADJUST                   1
#define		RNG_RSP_POWER_LEVEL_ADJUST              2
#define		RNG_RSP_OFFSET_FREQ_ADJUST              3
#define		RNG_RSP_RANGING_STATUS                  4
#define		RNG_RSP_DL_FREQ_OVERRIDE                5
#define		RNG_RSP_UL_CHANNEL_ID_OVERRIDE          6
#define		RNG_RSP_DL_OPERATIONAL_BURST_PROFILE    7
#define		RNG_RSP_SS_MAC_ADDRESS                  8
#define		RNG_RSP_BASIC_CID                       9
#define		RNG_RSP_PRIMARY_MGMT_CID                10
#define		RNG_RSP_AAS_BROADCAST_PERMISSION        11
#define		RNG_RSP_FRAME_NUMBER                    12
#define		RNG_RSP_OPPORTUNITY_NUMBER              13
#define		RNG_RSP_SERVICE_LEVEL_PREDICTION        17
#define		RNG_RSP_GLOBAL_SERVICE_CLASS_NAME       18
#define		RNG_RSP_RESOURCE_RETAIN_FLAG            20
#define		RNG_RSP_HO_PROCESS_OPTIMIZATION         21
/* Sorted the following values (for readability) */
#define		RNG_RSP_HO_ID                           22
#define		RNG_RSP_LOCATION_UPDATE_RESPONSE        23
#define		RNG_RSP_PAGING_INFORMATION              24
#define		RNG_RSP_PAGING_CONTROLLER_ID            25
#define		RNG_RSP_NEXT_PERIODIC_RANGING           26
#define		RNG_RSP_POWER_SAVING_CLASS_PARAMETERS   27
#define		RNG_RSP_MAC_HASH_SKIP_THRESHOLD         28
#define		RNG_RSP_SBC_RSP_ENCODINGS               29
#define		RNG_RSP_REG_RSP_ENCODINGS               30
#define		RNG_RSP_SA_CHALLENGE_TUPLE              31
#define		RNG_RSP_ENABLED_ACTION_TRIGGERED        32
#define		RNG_RSP_DL_OP_BURST_PROFILE_OFDMA       33
#define		RNG_RSP_RANGING_CODE_ATTRIBUTES         150
#define		RNG_RSP_SA_CHALLENGE_BS_RANDOM          1
#define		RNG_RSP_SA_CHALLENGE_AKID               2

/* SBC types (section 11.8) */
#define		SBC_BW_ALLOC_SUPPORT                    1
#define		SBC_TRANSITION_GAPS                     2
#define		SBC_REQ_MAX_TRANSMIT_POWER              3
#define		SBC_MAC_PDU                             4
#define		SBC_PKM_FLOW_CONTROL                    15
#define		SBC_AUTH_POLICY_SUPPORT                 16
#define		SBC_MAX_SECURITY_ASSOCIATIONS           17
#define		SBC_REQ_CURR_TRANSMITTED_POWER          147
#define		SBC_SS_FFT_SIZES                        150
#define		SBC_SS_DEMODULATOR                      151
#define		SBC_SS_MODULATOR                        152
#define		SBC_SS_NUM_UL_ARQ_ACK_CHANNEL           153
#define		SBC_SS_PERMUTATION_SUPPORT              154
#define		SBC_SS_DEMODULATOR_MIMO_SUPPORT		156
#define		SBC_SS_MIMO_UPLINK_SUPPORT		157
#define		SBC_SS_OFDMA_AAS_PRIVATE_MAP_SUPPORT    158
#define		SBC_SS_OFDMA_AAS_CAPABILITIES           159
#define		SBC_SS_CINR_MEASUREMENT_CAPABILITY      160
#define		SBC_SS_NUM_DL_ARQ_ACK_CHANNEL           161

#define		SBC_TLV_T_26_POWER_SAVE_CLASS_TYPES_CAPABILITY  26
#define		SBC_TLV_T_28_HO_TRIGGER_METRIC_SUPPORT  28
#define		SBC_TLV_T_27_EXTENSION_CAPABILITY       27

#define		SBC_TLV_T_162_HARQ_INCREMENTAL_REDUNDANCY_BUFFER_CAPABILITY 162
#define		SBC_TLV_T_163_HARQ_CHASE_COMBINING_AND_CC_IR_BUFFER_CAPABILITY 163
#define		SBC_TLV_T_167_ASSOCIATION_SUPPORT       167
#define		SBC_TLV_T_170_UPLINK_POWER_CONTROL_SUPPORT 170
#define		SBC_TLV_T_171_MINIMUM_NUM_OF_FRAMES     171
#define		SBC_TLV_T_172                           172
#define		SBC_TLV_T_173_UL_CONTROL_CHANNEL_SUPPORT   173
#define		SBC_TLV_T_174_OFDMA_MS_CSIT_CAPABILITY  174
#define		SBC_TLV_T_175_MAX_NUM_BST_PER_FRM_CAPABILITY_HARQ 175
#define		SBC_TLV_T_176                           176
#define		SBC_TLV_T_177_OFDMA_SS_MODULATOR_FOR_MIMO_SUPPORT  177
#define		SBC_TLV_T_178_SDMA_PILOT_CAPABILITY     178
#define		SBC_TLV_T_179_OFDMA_MULTIPLE_DL_BURST_PROFILE_CAPABILITY 179
#define		SBC_TLV_T_204_OFDMA_PARAMETERS_SETS	204

/* DREG-REQ DREG-CMD types (Sections 6.3.2.3.42 and  6.3.2.3.26) */
#define		DREG_PAGING_INFO			1
#define		DREG_REQ_DURATION			2
#define		DREG_PAGING_CONTROLLER_ID		3
#define		DREG_IDLE_MODE_RETAIN_INFO		4
#define		DREG_MAC_HASH_SKIP_THRESHOLD		5
#define		DREG_PAGING_CYCLE_REQUEST		52

/* REP-REQ types (Sections 11.11) */
#define		REP_REQ_REPORT_REQUEST			1
/* REP-REQ report request subtypes */
#define		REP_REQ_REPORT_TYPE			1
#define		REP_REQ_CHANNEL_NUMBER			2
#define		REP_REQ_CHANNEL_TYPE			3
#define		REP_REQ_ZONE_SPEC_PHY_CINR_REQ		4
#define		REP_REQ_PREAMBLE_PHY_CINR_REQ		5
#define		REP_REQ_ZONE_SPEC_EFF_CINR_REQ		6
#define		REP_REQ_PREAMBLE_EFF_CINR_REQ		7
#define		REP_REQ_CHANNEL_SELECTIVITY_REPORT	8

/* REP-RSP types (Sections 11.12) */
#define		REP_RSP_REPORT_TYPE			1
#define		REP_RSP_CHANNEL_TYPE			2
#define		REP_RSP_ZONE_SPECIFIC_PHY_CINR		3
#define		REP_RSP_PREAMBLE_PHY_CINR		4
#define		REP_RSP_ZONE_SPECIFIC_EFFECTIVE_CINR	5
#define		REP_RSP_PREAMBLE_EFFECTIVE_CINR		6
/* REP-RSP report subtypes */
#define		REP_RSP_REPORT_CHANNEL_NUMBER		1
#define		REP_RSP_REPORT_START_FRAME		2
#define		REP_RSP_REPORT_DURATION			3
#define		REP_RSP_REPORT_BASIC_REPORT		4
#define		REP_RSP_REPORT_CINR_REPORT		5
#define		REP_RSP_REPORT_RSSI_REPORT		6
/* REP-RSP channel type report subtypes */
#define		REP_RSP_CHANNEL_TYPE_SUBCHANNEL		1
#define		REP_RSP_CHANNEL_TYPE_BAND_AMC		2
#define		REP_RSP_CHANNEL_TYPE_SAFETY_CHANNEL	3
#define		REP_RSP_CHANNEL_TYPE_ENHANCED_BAND_AMC	4
#define		REP_RSP_CHANNEL_TYPE_SOUNDING		5
/* REP-RSP zone-specific physical CINR report subtypes */
#define		REP_RSP_ZONE_SPECIFIC_PHY_CINR_PUSC_SC0		1
#define		REP_RSP_ZONE_SPECIFIC_PHY_CINR_PUSC_SC1		2
#define		REP_RSP_ZONE_SPECIFIC_PHY_CINR_FUSC		3
#define		REP_RSP_ZONE_SPECIFIC_PHY_CINR_OPTIONAL_FUSC	4
#define		REP_RSP_ZONE_SPECIFIC_PHY_CINR_SAFETY_CHANNEL	5
#define		REP_RSP_ZONE_SPECIFIC_PHY_CINR_AMC		6
/* REP-RSP preamble physical CINR report subtypes */
#define		REP_RSP_PREAMBLE_PHY_CINR_CONFIGURATION1	1
#define		REP_RSP_PREAMBLE_PHY_CINR_CONFIGURATION3	2
#define		REP_RSP_PREAMBLE_PHY_CINR_BAND_AMC		3
/* REP-RSP zone-specific effective CINR report subtypes */
#define		REP_RSP_ZONE_SPECIFIC_EFFECTIVE_CINR_PUSC_SC0	1
#define		REP_RSP_ZONE_SPECIFIC_EFFECTIVE_CINR_PUSC_SC1	2
#define		REP_RSP_ZONE_SPECIFIC_EFFECTIVE_CINR_FUSC	3
#define		REP_RSP_ZONE_SPECIFIC_EFFECTIVE_CINR_OPTIONAL_FUSC	4
#define		REP_RSP_ZONE_SPECIFIC_EFFECTIVE_CINR_AMC_AAS	5
/* REP-RSP preamble effective CINR report subtypes */
#define		REP_RSP_PREAMBLE_EFFECTIVE_CINR_CONFIGURATION1	1
#define		REP_RSP_PREAMBLE_EFFECTIVE_CINR_CONFIGURATION3	2
#define		REP_RSP_CHANNEL_SELECTIVITY			3
/* REP-RSP channel selectivity report subtypes */
#define		FREQUENCY_SELECTIVITY_REPORT			1

/* REG types (Section 11.7) */
#define		REG_ARQ_PARAMETERS                      1
#define		REG_SS_MGMT_SUPPORT                     2
#define		REG_IP_MGMT_MODE                        3
#define		REG_IP_VERSION                          4
#define		REG_REQ_SECONDARY_MGMT_CID              5
#define		REG_RSP_SECONDARY_MGMT_CID		5
#define		REG_UL_TRANSPORT_CIDS_SUPPORTED         6
#define		REG_IP_PHS_SDU_ENCAP                    7
#define		REG_MAX_CLASSIFIERS_SUPPORTED           8
#define		REG_PHS_SUPPORT                         9
#define		REG_ARQ_SUPPORT                         10
#define		REG_DSX_FLOW_CONTROL                    11
#define		REG_MAC_CRC_SUPPORT                     12
#define		REG_MCA_FLOW_CONTROL                    13
#define		REG_MCAST_POLLING_CIDS                  14
#define         REG_NUM_DL_TRANS_CID                    15
#if 0 /* WIMAX_16E_2005 changes this to SBC scope */
#define         REG_PKM_FLOW_CONTROL                    15
#define         REG_AUTH_POLICY_SUPPORT                 16
#define         REG_MAX_SECURITY_ASSOCIATIONS           17
#endif
#if 0 /* TODO: scope has been changed to SBC scope */
#define		REG_DL_TRANSPORT_CIDS_SUPPORTED         15
#endif
#define		REG_MAC_ADDRESS                         18

#define		REG_TLV_T_20_MAX_MAC_DATA_PER_FRAME_SUPPORT 20
#define		REG_TLV_T_20_1_MAX_MAC_LEVEL_DATA_PER_DL_FRAME 1
#define		REG_TLV_T_20_2_MAX_MAC_LEVEL_DATA_PER_UL_FRAME 2
#define		REG_TLV_T_21_PACKING_SUPPORT            21
#define		REG_TLV_T_22_MAC_EXTENDED_RTPS_SUPPORT	22
#define		REG_TLV_T_23_MAX_NUM_BURSTS_TRANSMITTED_CONCURRENTLY_TO_THE_MS 23
#define		REG_RSP_TLV_T_24_CID_UPDATE_ENCODINGS	24
#define		REG_RSP_TLV_T_24_1_CID_UPDATE_ENCODINGS_NEW_CID	1
#define		REG_RSP_TLV_T_24_2_CID_UPDATE_ENCODINGS_SFID	2
#define		REG_RSP_TLV_T_24_3_CID_UPDATE_ENCODINGS_CONNECTION_INFO 3
#define		REG_RSP_TLV_T_25_COMPRESSED_CID_UPDATE_ENCODINGS	25
#define		REG_TLV_T_26_METHOD_FOR_ALLOCATING_IP_ADDR_SECONDARY_MGMNT_CONNECTION 26
#define		REG_TLV_T_27_HANDOVER_SUPPORTED		27
#define		REG_RSP_TLV_T_28_HO_SYSTEM_RESOURCE_RETAIN_TIME 28
#define		REG_TLV_T_29_HO_PROCESS_OPTIMIZATION_MS_TIMER   29
#define		REG_RSP_TLV_T_30_MS_HANDOVER_RETRANSMISSION_TIMER 30
#define		REG_TLV_T_31_MOBILITY_FEATURES_SUPPORTED 31
#define		REG_REQ_TLV_T_32_SLEEP_MODE_RECOVERY_TIME 32
#define		REG_REQ_TLV_T_33_MS_PREV_IP_ADDR	33
#define		REG_RSP_TLV_T_34_SKIP_ADDR_ACQUISITION	34
#define		REG_RSP_TLV_T_35_SAID_UPDATE_ENCODINGS	35
#define		REG_RSP_TLV_T_35_1_NEW_SAID		1
#define		REG_RSP_TLV_T_35_2_OLD_SAID		2
#define		REG_RSP_TLV_T_36_TOTAL_PROVISIONED_SERVICE_FLOW_DSAs 36
#define		REG_TLV_T_37_IDLE_MODE_TIMEOUT		37
#define		REG_RSP_TLV_T_38_SA_TEK_UPDATE		38
#define		REG_RSP_TLV_T_38_1_SA_TEK_UPDATE_TYPE	1
#define		REG_RSP_TLV_T_38_2_NEW_SAID		2
#define		REG_RSP_TLV_T_38_3_OLD_SAID		3
#define		REG_RSP_TLV_T_38_4_OLD_TEK_PARAMETERS	4
#define		REG_RSP_TLV_T_38_5_NEW_TEK_GTEK_PARAMETERS 5
#define		REG_RSP_TLV_T_38_6_GKEK_PARAMETERS	6
#define		REG_RSP_TLV_T_39_GKEK_PARAMETERS	39
#define		REG_TLV_T_40_ARQ_ACK_TYPE               40
#define		REG_TLV_T_41_MS_HO_CONNECTIONS_PARAM_PROCESSING_TIME 41
#define		REG_TLV_T_42_MS_HO_TEK_PROCESSING_TIME               42
#define		REG_TLV_T_43_MAC_HEADER_AND_EXTENDED_SUBHEADER_SUPPORT 43
#define		REG_RSP_TLV_T_44_SN_REPORTING_BASE		44
#define		REG_REQ_TLV_T_45_MS_PERIODIC_RANGING_TIMER_INFO 45
#define		REG_HANDOVER_INDICATION_READINESS_TIMER		46
#define		REG_REQ_BS_SWITCHING_TIMER			47
#define		REG_POWER_SAVING_CLASS_CAPABILITY			48



/* PKM types (Table 370) */
#define		PKM_ATTR_DISPLAY_STRING                  6
#define		PKM_ATTR_AUTH_KEY                        7
#define		PKM_ATTR_TEK                             8
#define		PKM_ATTR_KEY_LIFE_TIME                   9
#define		PKM_ATTR_KEY_SEQ_NUM                    10
#define		PKM_ATTR_HMAC_DIGEST                    11
#define		PKM_ATTR_SAID                           12
#define		PKM_ATTR_TEK_PARAM                      13
#define		PKM_ATTR_CBC_IV                         15
#define		PKM_ATTR_ERROR_CODE                     16
#define		PKM_ATTR_CA_CERTIFICATE                 17
#define		PKM_ATTR_SS_CERTIFICATE                 18
#define		PKM_ATTR_SECURITY_CAPABILITIES          19
#define		PKM_ATTR_CRYPTO_SUITE                   20
#define		PKM_ATTR_CRYPTO_LIST                    21
#define		PKM_ATTR_VERSION                        22
#define		PKM_ATTR_SA_DESCRIPTOR                  23
#define		PKM_ATTR_SA_TYPE                        24
#define		PKM_ATTR_SECURITY_NEGOTIATION_PARAMETERS 25
#define		PKM_ATTR_PKM_CONFIG_SETTINGS            27
#define		PKM_ATTR_PKM_EAP_PAYLOAD                28
#define		PKM_ATTR_PKM_NONCE                      29
#define		PKM_ATTR_AUTH_RESULT_CODE               30
#define		PKM_ATTR_SA_SERVICE_TYPE                31
#define		PKM_ATTR_FRAME_NUMBER                   32
#define		PKM_ATTR_SS_RANDOM                      33
#define		PKM_ATTR_BS_RANDOM                      34
#define		PKM_ATTR_PRE_PAK                        35
#define		PKM_ATTR_PAK_AK_SEQ_NUMBER              36
#define		PKM_ATTR_BS_CERTIFICATE                 37
#define		PKM_ATTR_SIG_BS                         38
#define		PKM_ATTR_MS_MAC_ADDRESS                 39
#define		PKM_ATTR_CMAC_DIGEST                    40
#define		PKM_ATTR_KEY_PUSH_MODES                 41
#define		PKM_ATTR_KEY_PUSH_COUNTER               42
#define		PKM_ATTR_GKEK                           43
#define		PKM_ATTR_SIG_SS                         44
#define		PKM_ATTR_AKID                           45
#define		PKM_ATTR_ASSOCIATED_GKEK_SEQ_NUM        46
#define		PKM_ATTR_GKEK_PARAMETERS                47

#define		PKM_ATTR_PKM_CONFIG_SETTINGS_AUTHORIZE_WAIT_TIMEOUT 1
#define		PKM_ATTR_PKM_CONFIG_SETTINGS_REAUTHORIZE_WAIT_TIMEOUT 2
#define		PKM_ATTR_PKM_CONFIG_SETTINGS_AUTHORIZATION_GRACE_TIME 3
#define		PKM_ATTR_PKM_CONFIG_SETTINGS_OPERATIONAL_WAIT_TIMEOUT 4
#define		PKM_ATTR_PKM_CONFIG_SETTINGS_REKEY_WAIT_TIMEOUT 5
#define		PKM_ATTR_PKM_CONFIG_SETTINGS_TEK_GRACE_TIME 6
#define		PKM_ATTR_PKM_CONFIG_SETTINGS_AUTHORIZE_REJECT_WAIT_TIMEOUT 7

#define		PKM_ATTR_SECURITY_NEGOTIATION_PARAMETER_SUB_PKM_VERSION_SUPPORT 1
#define		PKM_ATTR_SECURITY_NEGOTIATION_PARAMETER_SUB_AUTHORIZATION_POLICY_SUPPORT 2
#define		PKM_ATTR_SECURITY_NEGOTIATION_PARAMETER_SUB_MESSAGE_AUTHENTICATION_CODE  3
#define		PKM_ATTR_SECURITY_NEGOTIATION_PARAMETER_SUB_PN_WINDOW_SIZE               4
#define		PKM_ATTR_SECURITY_NEGOTIATION_PARAMETER_SUB_PKM_FLOW_CONTROL		 5
#define		PKM_ATTR_SECURITY_NEGOTIATION_PARAMETER_SUB_MAX_SUPPT_SECURITY_ASSNS	 6

/* Common TLV Encoding types (Table 346) */
#define		SHORT_HMAC_TUPLE_COR2                   140
#define		CMAC_TUPLE                              141
#define		VENDOR_SPECIFIC_INFO                    143
#define		VENDOR_ID_ENCODING                      144
#define		DSx_UPLINK_FLOW                         145
#define		DSx_DOWNLINK_FLOW                       146
#define		CURRENT_TX_POWER                        147
#define		MAC_VERSION_ENCODING                    148
#define		HMAC_TUPLE                              149
#define		SHORT_HMAC_TUPLE                        150

/* Section 11.13.18 */
#define		ARQ_ENABLE                              18
#define		ARQ_WINDOW_SIZE                         19
#define		ARQ_TRANSMITTER_DELAY                   20
#define		ARQ_RECEIVER_DELAY                      21
#define		ARQ_BLOCK_LIFETIME                      22
#define		ARQ_SYNC_LOSS_TIMEOUT                   23
#define		ARQ_DELIVER_IN_ORDER                    24
#define		ARQ_RX_PURGE_TIMEOUT                    25
#define		ARQ_BLOCK_SIZE                          26

/* Section 6.2.3.2.26 */

/* Service Flow Encodings (SFE) (Table 383) */
#define		SFE_SF_ID                               1
#define		SFE_CID                                 2
#define		SFE_SERVICE_CLASS_NAME                  3
#define		SFE_MBS_SERVICE                         4
#define		SFE_QOS_PARAMS_SET                      5
#define		SFE_TRAFFIC_PRIORITY                    6
#define		SFE_MAX_STR                             7
#define		SFE_MAX_TRAFFIC_BURST                   8
#define		SFE_MIN_RTR                             9
#define		SFE_RESERVED_10                         10
#define		SFE_UL_SCHEDULING                       11
#define		SFE_TX_POLICY                           12
#define		SFE_TOLERATED_JITTER                    13
#define		SFE_MAX_LATENCY                         14
#define		SFE_FIXED_LEN_SDU                       15
#define		SFE_SDU_SIZE                            16
#define		SFE_TARGET_SAID                         17
#define		SFE_ARQ_ENABLE                          18
#define		SFE_ARQ_WINDOW_SIZE                     19
#define		SFE_ARQ_TRANSMITTER_DELAY               20
#define		SFE_ARQ_RECEIVER_DELAY                  21
#define		SFE_ARQ_BLOCK_LIFETIME                  22
#define		SFE_ARQ_SYNC_LOSS_TIMEOUT               23
#define		SFE_ARQ_DELIVER_IN_ORDER                24
#define		SFE_ARQ_RX_PURGE_TIMEOUT                25
#define		SFE_ARQ_BLOCK_SIZE                      26
#define		SFE_RESERVED_27                         27
#define		SFE_CS_SPECIFICATION                    28
#define		SFE_TYPE_OF_DATA_DELIVERY_SERVICES      29
#define		SFE_SDU_INTER_ARRIVAL_INTERVAL          30
#define		SFE_TIME_BASE                           31
#define		SFE_PAGING_PREFERENCE                   32
#define		SFE_MBS_ZONE_IDENTIFIER_ASSIGNMENT      33
#define		SFE_RESERVED_34				34
#define		SFE_GLOBAL_SERVICE_CLASS_NAME           35
#define		SFE_RESERVED_36                         36
#define		SFE_SN_FEEDBACK_ENABLED                 37
#define		SFE_FSN_SIZE                            38
#define		SFE_CID_ALLOCATION_FOR_ACTIVE_BS        39
#define		SFE_UNSOLICITED_GRANT_INTERVAL          40
#define		SFE_UNSOLOCITED_POLLING_INTERVAL        41
#define		SFE_PDU_SN_EXT_SUBHEADER_HARQ_REORDER   42
#define		SFE_MBS_CONTENTS_ID                     43
#define		SFE_HARQ_SERVICE_FLOWS                  44
#define		SFE_AUTHORIZATION_TOKEN                 45
#define		SFE_HARQ_CHANNEL_MAPPING                46

/* Convergence Servicerameter Encoding Rules (Section 11.13.19.2) */
#define		SFE_CSPER_ATM                                 99
#define		SFE_CSPER_PACKET_IPV4                         100
#define		SFE_CSPER_PACKET_IPV6                         101
#define		SFE_CSPER_PACKET_802_3                        102
#define		SFE_CSPER_PACKET_802_1Q                       103
#define		SFE_CSPER_PACKET_IPV4_802_3                   104
#define		SFE_CSPER_PACKET_IPV6_802_3                   105
#define		SFE_CSPER_PACKET_IPV4_802_1Q                  106
#define		SFE_CSPER_PACKET_IPV6_802_1Q                  107
#define		SFE_CSPER_PACKET_IP_ROCH_COMPRESSION          108
#define		SFE_CSPER_PACKET_IP_ECRTP_COMPRESSION         109
#define		SFE_CSPER_PACKET_IP_802_3_ROCH_COMPRESSION    110
#define		SFE_CSPER_PACKET_IP_802_3_ECRTP_COMPRESSION   111

/* Section 11.13.19.3 */
#define		CST_CLASSIFIER_ACTION                   1
#define		CST_CLASSIFIER_ERROR_PARAM_SET          2
#define		CST_PACKET_CLASSIFICATION_RULE          3
#define		CST_PHS_DSC_ACTION                      4
#define		CST_PHS_ERROR_PARAM_SET                 5
#define		CST_PHS_RULE                            6

/* Section 11.13.19.3.3 */
#define		CST_ERROR_SET_ERRORED_PARAM             1
#define		CST_ERROR_SET_ERROR_CODE                2
#define		CST_ERROR_SET_ERROR_MSG                 3

/* Section 11.13.19.4 */
#define		CST_ATM_SWITCHING                       1
#define		CST_ATM_CLASSIFIER                      2
#define		CST_ATM_CLASSIFIER_DSC_ACTION           3
#define		CST_ATM_CLASSIFIER_ERROR_PARAMETER_SET  4

#define		ATM_VPI_CLASSIFIER                      1
#define		ATM_VCI_CLASSIFIER                      2
#define		ATM_CLASSIFIER_ID                       3

/* Section 11.13.19.3.4 */
#define		CST_PKT_CLASS_RULE_PRIORITY             1
#define		CST_PKT_CLASS_RULE_RANGE_MASK           2
#define		CST_PKT_CLASS_RULE_PROTOCOL             3
#define		CST_PKT_CLASS_RULE_SRC_IP               4
#define		CST_PKT_CLASS_RULE_DST_IP               5
#define		CST_PKT_CLASS_RULE_SRCPORT_RANGE        6
#define		CST_PKT_CLASS_RULE_DSTPORT_RANGE        7
#define		CST_PKT_CLASS_RULE_DST_MAC              8
#define		CST_PKT_CLASS_RULE_SRC_MAC              9
#define		CST_PKT_CLASS_RULE_ETHERTYPE            10
#define		CST_PKT_CLASS_RULE_USER_PRIORITY        11
#define		CST_PKT_CLASS_RULE_VLAN_ID              12
#define		CST_PKT_CLASS_RULE_PHSI                 13
#define		CST_PKT_CLASS_RULE_INDEX                14
#define		CST_PKT_CLASS_RULE_IPv6_FLOW_LABEL      15
#define		CST_PKT_CLASS_RULE_LARGE_CONTEXT_ID     16
#define		CST_PKT_CLASS_RULE_SHORT_FORMAT_CONTEXT_ID 18
#define		CST_CLASSIFIER_ACTION_RULE              19
#define		CST_PKT_CLASS_RULE_VENDOR_SPEC          143

/* Section 11.13.19.3.7 */
#define		CST_PHS_PHSI                            1
#define		CST_PHS_PHSF                            2
#define		CST_PHS_PHSM                            3
#define		CST_PHS_PHSS                            4
#define		CST_PHS_PHSV                            5
#define		CST_PHS_VENDOR_SPEC                     143

#endif /* WIMAX_MAC_H */
