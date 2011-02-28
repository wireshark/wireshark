/* packet-gsm_rlcmac.c
 * Routines for GSM RLC MAC control plane message dissection in wireshark.
 * TS 44.060 and 24.008
 * By Vincent Helfre
 * Copyright (c) 2011 ST-Ericsson
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
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 */

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <glib.h>
#include <epan/packet.h>

#include "packet-csn1.h"
#include "packet-gsm_rlcmac.h"

/* Initialize the protocol and registered fields
*/
static int proto_gsm_rlcmac = -1;
static int ett_gsm_rlcmac  = -1;

/* RLC/MAC Downlink control block header */
static int hf_dl_ctrl_payload_type = -1;
static int hf_dl_ctrl_rrbp = -1;
static int hf_dl_ctrl_s_p = -1;
static int hf_dl_ctrl_usf = -1;
static int hf_dl_ctrl_rbsn = -1;
static int hf_dl_ctrl_rti = -1;
static int hf_dl_ctrl_fs = -1;
static int hf_dl_ctrl_ac = -1;
static int hf_dl_ctrl_pr = -1;
static int hf_dl_ctrl_tfi = -1;
static int hf_dl_ctrl_d = -1;
static int hf_dl_ctrl_rbsn_e = -1;
static int hf_dl_ctrl_fs_e = -1;
static int hf_dl_ctrl_spare = -1;

/* Payload type as defined in TS 44.060 / 10.4.7 */
#define PAYLOAD_TYPE_DATA              0
#define PAYLOAD_TYPE_CTRL_NO_OPT_OCTET 1
#define PAYLOAD_TYPE_CTRL_OPT_OCTET    2
#define PAYLOAD_TYPE_RESERVED          3


/* CSN1 structures */
/*(not all parts of CSN_DESCR structure are always initialized.)*/
static const
CSN_DESCR_BEGIN(StartingTime_t)
  M_UINT       (StartingTime_t, N32, 5),  /* 04.08 refers to T1' := (FN div 1326) mod 32 */
  M_UINT       (StartingTime_t, N51, 6),  /* 04.08 refers to T3 := FN mod 51  */
  M_UINT       (StartingTime_t, N26, 5),  /* 04.08 refers to T2 := FN mod 26 */
CSN_DESCR_END  (StartingTime_t)

/*< Global TFI IE >*/
static const
CSN_DESCR_BEGIN(Global_TFI_t)
  M_UNION      (Global_TFI_t, 2),
  M_UINT       (Global_TFI_t, u.UPLINK_TFI_v, 5),
  M_UINT       (Global_TFI_t, u.DOWNLINK_TFI_v, 5),
CSN_DESCR_END  (Global_TFI_t)

/*< Starting Frame Number Description IE >*/
static const
CSN_DESCR_BEGIN(Starting_Frame_Number_t)
  M_UNION      (Starting_Frame_Number_t, 2),
  M_TYPE       (Starting_Frame_Number_t, u.StartingTime, StartingTime_t),
  M_UINT       (Starting_Frame_Number_t, u.k, 13),
CSN_DESCR_END(Starting_Frame_Number_t)

/*< Ack/Nack Description IE >*/
static const
CSN_DESCR_BEGIN(Ack_Nack_Description_t)
  M_BIT        (Ack_Nack_Description_t, FINAL_ACK_INDICATION_v),
  M_UINT       (Ack_Nack_Description_t, STARTING_SEQUENCE_NUMBER_v, 7),
  M_BITMAP     (Ack_Nack_Description_t, RECEIVED_BLOCK_BITMAP_v, 64),
CSN_DESCR_END  (Ack_Nack_Description_t)

/*< Packet Timing Advance IE >*/
static const
CSN_DESCR_BEGIN(Packet_Timing_Advance_t)
  M_NEXT_EXIST (Packet_Timing_Advance_t, Exist_TIMING_ADVANCE_VALUE_v, 1),
  M_UINT       (Packet_Timing_Advance_t, TIMING_ADVANCE_VALUE_v, 6),

  M_NEXT_EXIST (Packet_Timing_Advance_t, Exist_IndexAndtimeSlot, 2),
  M_UINT       (Packet_Timing_Advance_t, TIMING_ADVANCE_INDEX_v, 4),
  M_UINT       (Packet_Timing_Advance_t, TIMING_ADVANCE_TIMESLOT_NUMBER_v, 3),
CSN_DESCR_END  (Packet_Timing_Advance_t)

/*< Power Control Parameters IE >*/
static const
CSN_DESCR_BEGIN(GPRS_Power_Control_Parameters_t)
  M_UINT       (GPRS_Power_Control_Parameters_t, ALPHA_v, 4),
  M_UINT       (GPRS_Power_Control_Parameters_t, T_AVG_W_v, 5),
  M_UINT       (GPRS_Power_Control_Parameters_t, T_AVG_T_v, 5),
  M_BIT        (GPRS_Power_Control_Parameters_t, PC_MEAS_CHAN_v),
  M_UINT       (GPRS_Power_Control_Parameters_t, N_AVG_I_v, 4),
CSN_DESCR_END  (GPRS_Power_Control_Parameters_t)

/*< Global Power Control Parameters IE >*/
static const
CSN_DESCR_BEGIN(Global_Power_Control_Parameters_t)
  M_UINT       (Global_Power_Control_Parameters_t, ALPHA_v, 4),
  M_UINT       (Global_Power_Control_Parameters_t, T_AVG_W_v, 5),
  M_UINT       (Global_Power_Control_Parameters_t, T_AVG_T_v, 5),
  M_UINT       (Global_Power_Control_Parameters_t, Pb, 4),
  M_UINT       (Global_Power_Control_Parameters_t, PC_MEAS_CHAN_v, 1),
  M_UINT       (Global_Power_Control_Parameters_t, INT_MEAS_CHANNEL_LIST_AVAIL_v, 1),
  M_UINT       (Global_Power_Control_Parameters_t, N_AVG_I_v, 4),
CSN_DESCR_END  (Global_Power_Control_Parameters_t)

/*< Global Packet Timing Advance IE >*/
static const
CSN_DESCR_BEGIN(Global_Packet_Timing_Advance_t)
  M_NEXT_EXIST (Global_Packet_Timing_Advance_t, Exist_TIMING_ADVANCE_VALUE_v, 1),
  M_UINT       (Global_Packet_Timing_Advance_t, TIMING_ADVANCE_VALUE_v, 6),

  M_NEXT_EXIST (Global_Packet_Timing_Advance_t, Exist_UPLINK_TIMING_ADVANCE, 2),
  M_UINT       (Global_Packet_Timing_Advance_t, UPLINK_TIMING_ADVANCE_INDEX_v, 4),
  M_UINT       (Global_Packet_Timing_Advance_t, UPLINK_TIMING_ADVANCE_TIMESLOT_NUMBER_v, 3),

  M_NEXT_EXIST (Global_Packet_Timing_Advance_t, Exist_DOWNLINK_TIMING_ADVANCE, 2),
  M_UINT       (Global_Packet_Timing_Advance_t, DOWNLINK_TIMING_ADVANCE_INDEX_v, 4),
  M_UINT       (Global_Packet_Timing_Advance_t, DOWNLINK_TIMING_ADVANCE_TIMESLOT_NUMBER_v, 3),
CSN_DESCR_END  (Global_Packet_Timing_Advance_t)

/*< Channel Quality Report struct >*/
static const
CSN_DESCR_BEGIN(Channel_Quality_Report_t)
  M_UINT       (Channel_Quality_Report_t, C_VALUE_v, 6),
  M_UINT       (Channel_Quality_Report_t, RXQUAL_v, 3),
  M_UINT       (Channel_Quality_Report_t, SIGN_VAR_v, 6),

  M_NEXT_EXIST (Channel_Quality_Report_t, Slot[0].Exist, 1),
  M_UINT       (Channel_Quality_Report_t, Slot[0].I_LEVEL_TN_v, 4),

  M_NEXT_EXIST (Channel_Quality_Report_t, Slot[1].Exist, 1),
  M_UINT       (Channel_Quality_Report_t, Slot[1].I_LEVEL_TN_v, 4),

  M_NEXT_EXIST (Channel_Quality_Report_t, Slot[2].Exist, 1),
  M_UINT       (Channel_Quality_Report_t, Slot[2].I_LEVEL_TN_v, 4),

  M_NEXT_EXIST (Channel_Quality_Report_t, Slot[3].Exist, 1),
  M_UINT       (Channel_Quality_Report_t, Slot[3].I_LEVEL_TN_v, 4),

  M_NEXT_EXIST (Channel_Quality_Report_t, Slot[4].Exist, 1),
  M_UINT       (Channel_Quality_Report_t, Slot[4].I_LEVEL_TN_v, 4),

  M_NEXT_EXIST (Channel_Quality_Report_t, Slot[5].Exist, 1),
  M_UINT       (Channel_Quality_Report_t, Slot[5].I_LEVEL_TN_v, 4),

  M_NEXT_EXIST (Channel_Quality_Report_t, Slot[6].Exist, 1),
  M_UINT       (Channel_Quality_Report_t, Slot[6].I_LEVEL_TN_v, 4),

  M_NEXT_EXIST (Channel_Quality_Report_t, Slot[7].Exist, 1),
  M_UINT       (Channel_Quality_Report_t, Slot[7].I_LEVEL_TN_v, 4),
CSN_DESCR_END  (Channel_Quality_Report_t)

/*< EGPRS Ack/Nack Description >*/
static const
CSN_DESCR_BEGIN   (EGPRS_AckNack_t)
  M_NEXT_EXIST    (EGPRS_AckNack_t, Exist_LENGTH_v, 1),
  M_UINT          (EGPRS_AckNack_t, LENGTH_v, 8),

  M_UINT          (EGPRS_AckNack_t, FINAL_ACK_INDICATION_v, 1),
  M_UINT          (EGPRS_AckNack_t, BEGINNING_OF_WINDOW_v, 1),
  M_UINT          (EGPRS_AckNack_t, END_OF_WINDOW_v, 1),
  M_UINT          (EGPRS_AckNack_t, STARTING_SEQUENCE_NUMBER_v, 11),

  M_NEXT_EXIST    (EGPRS_AckNack_t, Exist_CRBB, 3),
  M_UINT          (EGPRS_AckNack_t, CRBB_LENGTH_v, 7),
  M_UINT          (EGPRS_AckNack_t, CRBB_STARTING_COLOR_CODE_v, 1),
  M_LEFT_VAR_BMP  (EGPRS_AckNack_t, CRBB_v, CRBB_LENGTH_v, 0),
CSN_DESCR_END     (EGPRS_AckNack_t)

/*<P1 Rest Octets>*/
/*<P2 Rest Octets>*/
static const
CSN_DESCR_BEGIN(MobileAllocationIE_t)
  M_UINT       (MobileAllocationIE_t, Length, 8),
  M_VAR_ARRAY  (MobileAllocationIE_t, MA_v, Length, 0),
CSN_DESCR_END  (MobileAllocationIE_t)

static const
CSN_DESCR_BEGIN(SingleRFChannel_t)
  M_UINT       (SingleRFChannel_t, spare, 2),
  M_UINT       (SingleRFChannel_t, ARFCN_v, 10),
CSN_DESCR_END  (SingleRFChannel_t)

static const
CSN_DESCR_BEGIN(RFHoppingChannel_t)
  M_UINT       (RFHoppingChannel_t, MAIO_v, 6),
  M_UINT       (RFHoppingChannel_t, HSN_v, 6),
CSN_DESCR_END  (RFHoppingChannel_t)

static const
CSN_DESCR_BEGIN(MobileAllocation_or_Frequency_Short_List_t)
  M_UNION      (MobileAllocation_or_Frequency_Short_List_t, 2),
  M_BITMAP     (MobileAllocation_or_Frequency_Short_List_t, u.Frequency_Short_List, 64),
  M_TYPE       (MobileAllocation_or_Frequency_Short_List_t, u.MA_v, MobileAllocationIE_t),
CSN_DESCR_END  (MobileAllocation_or_Frequency_Short_List_t)

static const
CSN_DESCR_BEGIN(Channel_Description_t)
  M_UINT       (Channel_Description_t, Channel_type_and_TDMA_offset, 5),
  M_UINT       (Channel_Description_t, TN_v, 3),
  M_UINT       (Channel_Description_t, TSC_v, 3),

  M_UNION      (Channel_Description_t, 2),
  M_TYPE       (Channel_Description_t, u.SingleRFChannel, SingleRFChannel_t),
  M_TYPE       (Channel_Description_t, u.RFHoppingChannel, RFHoppingChannel_t),
CSN_DESCR_END(Channel_Description_t)

static const
CSN_DESCR_BEGIN(Group_Channel_Description_t)
  M_TYPE       (Group_Channel_Description_t, Channel_Description, Channel_Description_t),

  M_NEXT_EXIST (Group_Channel_Description_t, Exist_Hopping, 1),
  M_TYPE       (Group_Channel_Description_t, MA_or_Frequency_Short_List, MobileAllocation_or_Frequency_Short_List_t),
CSN_DESCR_END  (Group_Channel_Description_t)

static const
CSN_DESCR_BEGIN(Group_Call_Reference_t)
  M_UINT       (Group_Call_Reference_t, value, 27),
  M_BIT        (Group_Call_Reference_t, SF),
  M_BIT        (Group_Call_Reference_t, AF),
  M_UINT       (Group_Call_Reference_t, call_priority, 3),
  M_UINT       (Group_Call_Reference_t, Ciphering_information, 4),
CSN_DESCR_END  (Group_Call_Reference_t)

static const
CSN_DESCR_BEGIN(Group_Call_information_t)
  M_TYPE       (Group_Call_information_t, Group_Call_Reference, Group_Call_Reference_t),

  M_NEXT_EXIST (Group_Call_information_t, Exist_Group_Channel_Description, 1),
  M_TYPE       (Group_Call_information_t, Group_Channel_Description, Group_Channel_Description_t),
CSN_DESCR_END (Group_Call_information_t)

static const
CSN_DESCR_BEGIN  (P1_Rest_Octets_t)
  M_NEXT_EXIST_LH(P1_Rest_Octets_t, Exist_NLN_PCH_and_NLN_status, 2),
  M_UINT         (P1_Rest_Octets_t, NLN_PCH_v, 2),
  M_UINT         (P1_Rest_Octets_t, NLN_status, 1),

  M_NEXT_EXIST_LH(P1_Rest_Octets_t, Exist_Priority1, 1),
  M_UINT         (P1_Rest_Octets_t, Priority1, 3),

  M_NEXT_EXIST_LH(P1_Rest_Octets_t, Exist_Priority2, 1),
  M_UINT         (P1_Rest_Octets_t, Priority2, 3),

  M_NEXT_EXIST_LH(P1_Rest_Octets_t, Exist_Group_Call_information, 1),
  M_TYPE         (P1_Rest_Octets_t, Group_Call_information, Group_Call_information_t),

  M_UINT_LH      (P1_Rest_Octets_t, Packet_Page_Indication_1, 1),
  M_UINT_LH      (P1_Rest_Octets_t, Packet_Page_Indication_2, 1),
CSN_DESCR_END    (P1_Rest_Octets_t)

static const
CSN_DESCR_BEGIN  (P2_Rest_Octets_t)
  M_NEXT_EXIST_LH(P2_Rest_Octets_t, Exist_CN3_v, 1),
  M_UINT         (P2_Rest_Octets_t, CN3_v, 2),

  M_NEXT_EXIST_LH(P2_Rest_Octets_t, Exist_NLN_and_status, 2),
  M_UINT         (P2_Rest_Octets_t, NLN_v, 2),
  M_UINT         (P2_Rest_Octets_t, NLN_status, 1),

  M_NEXT_EXIST_LH(P2_Rest_Octets_t, Exist_Priority1, 1),
  M_UINT         (P2_Rest_Octets_t, Priority1, 3),

  M_NEXT_EXIST_LH(P2_Rest_Octets_t, Exist_Priority2, 1),
  M_UINT         (P2_Rest_Octets_t, Priority2, 3),

  M_NEXT_EXIST_LH(P2_Rest_Octets_t, Exist_Priority3, 1),
  M_UINT         (P2_Rest_Octets_t, Priority3, 3),

  M_UINT_LH      (P2_Rest_Octets_t, Packet_Page_Indication_3, 1),
CSN_DESCR_END    (P2_Rest_Octets_t)


/* <IA Rest Octets>
 * Note!!
 * - first two bits skipped and frequencyparameters skipped
 * - additions for R99 and EGPRS added
 */
static const
CSN_DESCR_BEGIN(DynamicAllocation_t)
  M_UINT       (DynamicAllocation_t, USF_v, 3),
  M_UINT       (DynamicAllocation_t, USF_GRANULARITY_v, 1),

  M_NEXT_EXIST (DynamicAllocation_t, Exist_P0_PR_MODE, 2),
  M_UINT       (DynamicAllocation_t, P0_v, 4),
  M_UINT       (DynamicAllocation_t, PR_MODE_v, 1),
CSN_DESCR_END  (DynamicAllocation_t)

static const
CSN_DESCR_BEGIN(EGPRS_TwoPhaseAccess_t)
  M_NEXT_EXIST (EGPRS_TwoPhaseAccess_t, Exist_ALPHA_v, 1),
  M_UINT       (EGPRS_TwoPhaseAccess_t, ALPHA_v, 4),

  M_UINT       (EGPRS_TwoPhaseAccess_t, GAMMA_v, 5),
  M_TYPE       (EGPRS_TwoPhaseAccess_t, TBF_STARTING_TIME_v, StartingTime_t),
  M_UINT       (EGPRS_TwoPhaseAccess_t, NR_OF_RADIO_BLOCKS_ALLOCATED_v, 2),

  M_NEXT_EXIST (EGPRS_TwoPhaseAccess_t, Exist_P0_BTS_PWR_CTRL_PR_MODE, 3),
  M_UINT       (EGPRS_TwoPhaseAccess_t, P0_v, 4),
  M_UINT       (EGPRS_TwoPhaseAccess_t, BTS_PWR_CTRL_MODE_v, 1),
  M_UINT       (EGPRS_TwoPhaseAccess_t, PR_MODE_v, 1),
CSN_DESCR_END  (EGPRS_TwoPhaseAccess_t)

static const
CSN_DESCR_BEGIN(EGPRS_OnePhaseAccess_t)
  M_UINT       (EGPRS_OnePhaseAccess_t, TFI_ASSIGNMENT_v, 5),
  M_UINT       (EGPRS_OnePhaseAccess_t, POLLING_v, 1),

  M_UNION      (EGPRS_OnePhaseAccess_t, 2),
  M_TYPE       (EGPRS_OnePhaseAccess_t, Allocation.DynamicAllocation, DynamicAllocation_t),
  CSN_ERROR    (EGPRS_OnePhaseAccess_t, "1 <Fixed Allocation>", CSN_ERROR_STREAM_NOT_SUPPORTED),

  M_UINT       (EGPRS_OnePhaseAccess_t, EGPRS_CHANNEL_CODING_COMMAND_v, 4),
  M_UINT       (EGPRS_OnePhaseAccess_t, TLLI_BLOCK_CHANNEL_CODING_v, 1),

  M_NEXT_EXIST (EGPRS_OnePhaseAccess_t, Exist_BEP_PERIOD2_v, 1),
  M_UINT       (EGPRS_OnePhaseAccess_t, BEP_PERIOD2_v, 4),

  M_UINT       (EGPRS_OnePhaseAccess_t, RESEGMENT_v, 1),
  M_UINT       (EGPRS_OnePhaseAccess_t, EGPRS_WindowSize, 5),

  M_NEXT_EXIST (EGPRS_OnePhaseAccess_t, Exist_ALPHA_v, 1),
  M_UINT       (EGPRS_OnePhaseAccess_t, ALPHA_v, 4),

  M_UINT       (EGPRS_OnePhaseAccess_t, GAMMA_v, 5),

  M_NEXT_EXIST (EGPRS_OnePhaseAccess_t, Exist_TIMING_ADVANCE_INDEX_v, 1),
  M_UINT       (EGPRS_OnePhaseAccess_t, TIMING_ADVANCE_INDEX_v, 4),

  M_NEXT_EXIST (EGPRS_OnePhaseAccess_t, Exist_TBF_STARTING_TIME_v, 1),
  M_TYPE       (EGPRS_OnePhaseAccess_t, TBF_STARTING_TIME_v, StartingTime_t),
CSN_DESCR_END  (EGPRS_OnePhaseAccess_t)

static const
CSN_DESCR_BEGIN(IA_EGPRS_00_t)
  M_UINT       (IA_EGPRS_00_t, ExtendedRA, 5),

  M_REC_ARRAY  (IA_EGPRS_00_t, AccessTechnologyType, NrOfAccessTechnologies, 4),

  M_UNION      (IA_EGPRS_00_t, 2),
  M_TYPE       (IA_EGPRS_00_t, Access.TwoPhaseAccess, EGPRS_TwoPhaseAccess_t),
  M_TYPE       (IA_EGPRS_00_t, Access.OnePhaseAccess, EGPRS_OnePhaseAccess_t),
CSN_DESCR_END  (IA_EGPRS_00_t)

static const
CSN_ChoiceElement_t IA_EGPRS_Choice[] =
{
  {2, 0x00, M_TYPE   (IA_EGPRS_t, u.IA_EGPRS_PUA, IA_EGPRS_00_t)},
  {2, 0x01, CSN_ERROR(IA_EGPRS_t, "01 <IA_EGPRS>", CSN_ERROR_STREAM_NOT_SUPPORTED)},
  {1, 0x01, CSN_ERROR(IA_EGPRS_t, "1 <IA_EGPRS>", CSN_ERROR_STREAM_NOT_SUPPORTED)}
};

/* Please observe the double usage of UnionType element.
 * First, it is used to store the second bit of LL/LH identification of EGPRS contents.
 * Thereafter, UnionType will be used to store the index to detected choice.
 */
static const
CSN_DESCR_BEGIN(IA_EGPRS_t)
  M_UINT       (IA_EGPRS_t, UnionType , 1),
  M_CHOICE     (IA_EGPRS_t, UnionType, IA_EGPRS_Choice, ElementsOf(IA_EGPRS_Choice)),
CSN_DESCR_END  (IA_EGPRS_t)

static const
CSN_DESCR_BEGIN(IA_FreqParamsBeforeTime_t)
  M_UINT       (IA_FreqParamsBeforeTime_t, Length, 6),
  M_UINT       (IA_FreqParamsBeforeTime_t, MAIO_v, 6),
  M_VAR_ARRAY  (IA_FreqParamsBeforeTime_t, MobileAllocation, Length, 8),
CSN_DESCR_END  (IA_FreqParamsBeforeTime_t)

static const
CSN_DESCR_BEGIN  (GPRS_SingleBlockAllocation_t)
  M_NEXT_EXIST   (GPRS_SingleBlockAllocation_t, Exist_ALPHA_v, 1),
  M_UINT         (GPRS_SingleBlockAllocation_t, ALPHA_v, 4),

  M_UINT         (GPRS_SingleBlockAllocation_t, GAMMA_v, 5),
  M_FIXED        (GPRS_SingleBlockAllocation_t, 2, 0x01),
  M_TYPE         (GPRS_SingleBlockAllocation_t, TBF_STARTING_TIME_v, StartingTime_t), /*bit(16)*/

  M_NEXT_EXIST_LH(GPRS_SingleBlockAllocation_t, Exist_P0_BTS_PWR_CTRL_PR_MODE, 3),
  M_UINT         (GPRS_SingleBlockAllocation_t, P0_v, 4),
  M_UINT         (GPRS_SingleBlockAllocation_t, BTS_PWR_CTRL_MODE_v, 1),
  M_UINT         (GPRS_SingleBlockAllocation_t, PR_MODE_v, 1),
CSN_DESCR_END    (GPRS_SingleBlockAllocation_t)

static const
CSN_DESCR_BEGIN  (GPRS_DynamicOrFixedAllocation_t)
  M_UINT         (GPRS_DynamicOrFixedAllocation_t, TFI_ASSIGNMENT_v, 5),
  M_UINT         (GPRS_DynamicOrFixedAllocation_t, POLLING_v, 1),

  M_UNION        (GPRS_DynamicOrFixedAllocation_t, 2),
  M_TYPE         (GPRS_DynamicOrFixedAllocation_t, Allocation.DynamicAllocation, DynamicAllocation_t),
  CSN_ERROR      (GPRS_DynamicOrFixedAllocation_t, "1 <Fixed Allocation>", CSN_ERROR_STREAM_NOT_SUPPORTED),

  M_UINT         (GPRS_DynamicOrFixedAllocation_t, CHANNEL_CODING_COMMAND_v, 2),
  M_UINT         (GPRS_DynamicOrFixedAllocation_t, TLLI_BLOCK_CHANNEL_CODING_v, 1),

  M_NEXT_EXIST   (GPRS_DynamicOrFixedAllocation_t, Exist_ALPHA_v, 1),
  M_UINT         (GPRS_DynamicOrFixedAllocation_t, ALPHA_v, 4),

  M_UINT         (GPRS_DynamicOrFixedAllocation_t, GAMMA_v, 5),

  M_NEXT_EXIST   (GPRS_DynamicOrFixedAllocation_t, Exist_TIMING_ADVANCE_INDEX_v, 1),
  M_UINT         (GPRS_DynamicOrFixedAllocation_t, TIMING_ADVANCE_INDEX_v, 4),

  M_NEXT_EXIST   (GPRS_DynamicOrFixedAllocation_t, Exist_TBF_STARTING_TIME_v, 1),
  M_TYPE         (GPRS_DynamicOrFixedAllocation_t, TBF_STARTING_TIME_v, StartingTime_t),
CSN_DESCR_END    (GPRS_DynamicOrFixedAllocation_t)

static const
CSN_DESCR_BEGIN(PU_IA_AdditionsR99_t)
  M_NEXT_EXIST (PU_IA_AdditionsR99_t, Exist_ExtendedRA, 1),
  M_UINT       (PU_IA_AdditionsR99_t, ExtendedRA, 5),
CSN_DESCR_END  (PU_IA_AdditionsR99_t)

static const
CSN_DESCR_BEGIN          (Packet_Uplink_ImmAssignment_t)
  M_UNION                (Packet_Uplink_ImmAssignment_t, 2),
  M_TYPE                 (Packet_Uplink_ImmAssignment_t, Access.SingleBlockAllocation, GPRS_SingleBlockAllocation_t),
  M_TYPE                 (Packet_Uplink_ImmAssignment_t, Access.DynamicOrFixedAllocation, GPRS_DynamicOrFixedAllocation_t),

  M_NEXT_EXIST_OR_NULL_LH(Packet_Uplink_ImmAssignment_t, Exist_AdditionsR99, 1),
  M_TYPE                 (Packet_Uplink_ImmAssignment_t, AdditionsR99, PU_IA_AdditionsR99_t),
CSN_DESCR_END            (Packet_Uplink_ImmAssignment_t)

static const
CSN_DESCR_BEGIN(PD_IA_AdditionsR99_t)
  M_UINT       (PD_IA_AdditionsR99_t, EGPRS_WindowSize, 5),
  M_UINT       (PD_IA_AdditionsR99_t, LINK_QUALITY_MEASUREMENT_MODE_v, 2),

  M_NEXT_EXIST (PD_IA_AdditionsR99_t, Exist_BEP_PERIOD2_v, 1),
  M_UINT       (PD_IA_AdditionsR99_t, BEP_PERIOD2_v, 4),
CSN_DESCR_END  (PD_IA_AdditionsR99_t)

static const
CSN_DESCR_BEGIN(Packet_Downlink_ImmAssignment_t)
  M_UINT       (Packet_Downlink_ImmAssignment_t, TLLI_v, 32),

  M_NEXT_EXIST (Packet_Downlink_ImmAssignment_t, Exist_TFI_to_TA_VALID_v, 6 + 1),
  M_UINT       (Packet_Downlink_ImmAssignment_t, TFI_ASSIGNMENT_v, 5),
  M_UINT       (Packet_Downlink_ImmAssignment_t, RLC_MODE_v, 1),
  M_NEXT_EXIST (Packet_Downlink_ImmAssignment_t, Exist_ALPHA_v, 1),
  M_UINT       (Packet_Downlink_ImmAssignment_t, ALPHA_v, 4),
  M_UINT       (Packet_Downlink_ImmAssignment_t, GAMMA_v, 5),
  M_UINT       (Packet_Downlink_ImmAssignment_t, POLLING_v, 1),
  M_UINT       (Packet_Downlink_ImmAssignment_t, TA_VALID_v, 1),

  M_NEXT_EXIST (Packet_Downlink_ImmAssignment_t, Exist_TIMING_ADVANCE_INDEX_v, 1),
  M_UINT       (Packet_Downlink_ImmAssignment_t, TIMING_ADVANCE_INDEX_v, 4),

  M_NEXT_EXIST (Packet_Downlink_ImmAssignment_t, Exist_TBF_STARTING_TIME_v, 1),
  M_TYPE       (Packet_Downlink_ImmAssignment_t, TBF_STARTING_TIME_v, StartingTime_t),

  M_NEXT_EXIST (Packet_Downlink_ImmAssignment_t, Exist_P0_PR_MODE, 3),
  M_UINT       (Packet_Downlink_ImmAssignment_t, P0_v, 4),
  M_UINT       (Packet_Downlink_ImmAssignment_t, BTS_PWR_CTRL_MODE_v, 1),
  M_UINT       (Packet_Downlink_ImmAssignment_t, PR_MODE_v, 1),

  M_NEXT_EXIST_OR_NULL_LH(Packet_Downlink_ImmAssignment_t, Exist_AdditionsR99, 1),
  M_TYPE       (Packet_Downlink_ImmAssignment_t, AdditionsR99, PD_IA_AdditionsR99_t),
CSN_DESCR_END  (Packet_Downlink_ImmAssignment_t)

static const
CSN_DESCR_BEGIN          (Second_Part_Packet_Assignment_t)
  M_NEXT_EXIST_OR_NULL_LH(Second_Part_Packet_Assignment_t, Exist_SecondPart, 2),
  M_NEXT_EXIST           (Second_Part_Packet_Assignment_t, Exist_ExtendedRA, 1),
  M_UINT                 (Second_Part_Packet_Assignment_t, ExtendedRA, 5),
CSN_DESCR_END            (Second_Part_Packet_Assignment_t)

static const
CSN_DESCR_BEGIN(IA_PacketAssignment_UL_DL_t)
  M_UNION      (IA_PacketAssignment_UL_DL_t, 2),
  M_TYPE       (IA_PacketAssignment_UL_DL_t, ul_dl.Packet_Uplink_ImmAssignment, Packet_Uplink_ImmAssignment_t),
  M_TYPE       (IA_PacketAssignment_UL_DL_t, ul_dl.Packet_Downlink_ImmAssignment, Packet_Downlink_ImmAssignment_t),
CSN_DESCR_END  (IA_PacketAssignment_UL_DL_t)

static const
CSN_DESCR_BEGIN(IA_PacketAssignment_t)
  M_UNION      (IA_PacketAssignment_t, 2),
  M_TYPE       (IA_PacketAssignment_t, u.UplinkDownlinkAssignment, IA_PacketAssignment_UL_DL_t),
  M_TYPE       (IA_PacketAssignment_t, u.UplinkDownlinkAssignment, Second_Part_Packet_Assignment_t),
CSN_DESCR_END  (IA_PacketAssignment_t)

/* Packet Polling Request */
static const
CSN_ChoiceElement_t PacketPollingID[] =
{
  {1, 0,    M_TYPE(PacketPollingID_t, u.Global_TFI, Global_TFI_t)},
  {2, 0x02, M_UINT(PacketPollingID_t, u.TLLI_v, 32)},
  {3, 0x06, M_UINT(PacketPollingID_t, u.TQI_v, 16)},
/*{3, 0x07 , M_TYPE(PacketUplinkID_t, u.Packet_Request_Reference, Packet_Request_Reference_t)},*/
};

static const
CSN_DESCR_BEGIN(PacketPollingID_t)
  M_CHOICE     (PacketPollingID_t, UnionType, PacketPollingID, ElementsOf(PacketPollingID)),
CSN_DESCR_END  (PacketPollingID_t)

static const
CSN_DESCR_BEGIN(Packet_Polling_Request_t)
  M_UINT       (Packet_Polling_Request_t, MESSAGE_TYPE_v, 6),
  M_UINT       (Packet_Polling_Request_t, PAGE_MODE_v, 2),
  M_TYPE       (Packet_Polling_Request_t, ID, PacketPollingID_t),
  M_BIT        (Packet_Polling_Request_t, TYPE_OF_ACK_v),
CSN_DESCR_END  (Packet_Polling_Request_t)

static const
CSN_DESCR_BEGIN(MobileAllocation_t)
  M_UINT_OFFSET(MobileAllocation_t, MA_BitLength, 6, 1),
  M_VAR_BITMAP (MobileAllocation_t, MA_BITMAP_v, MA_BitLength, 0),
CSN_DESCR_END  (MobileAllocation_t)

static const
CSN_DESCR_BEGIN(ARFCN_index_list_t)
  M_REC_ARRAY  (ARFCN_index_list_t, ARFCN_INDEX_v, ElementsOf_ARFCN_INDEX_v, 6),
CSN_DESCR_END  (ARFCN_index_list_t)

static const
CSN_DESCR_BEGIN(GPRS_Mobile_Allocation_t)
  M_UINT       (GPRS_Mobile_Allocation_t, HSN_v, 6),
  M_REC_ARRAY  (GPRS_Mobile_Allocation_t, RFL_NUMBER_v, ElementsOf_RFL_NUMBER_v, 4),
  M_UNION      (GPRS_Mobile_Allocation_t, 2),
  M_TYPE       (GPRS_Mobile_Allocation_t, u.MA_v, MobileAllocation_t),
  M_TYPE       (GPRS_Mobile_Allocation_t, u.ARFCN_index_list, ARFCN_index_list_t),
CSN_DESCR_END  (GPRS_Mobile_Allocation_t)

/*< SI 13 Rest Octets >*/
static const
CSN_DESCR_BEGIN (Extension_Bits_t)
  M_UINT_OFFSET (Extension_Bits_t, extension_length, 6, 1),
  M_LEFT_VAR_BMP(Extension_Bits_t, Extension_Info, extension_length, 0),
CSN_DESCR_END   (Extension_Bits_t)

static const
CSN_DESCR_BEGIN(GPRS_Cell_Options_t)
  M_UINT       (GPRS_Cell_Options_t, NMO_v, 2),
  M_UINT_OFFSET(GPRS_Cell_Options_t, T3168_v, 3, 1),
  M_UINT_OFFSET(GPRS_Cell_Options_t, T3192_v, 3, 1),
  M_UINT       (GPRS_Cell_Options_t, DRX_TIMER_MAX_v, 3),
  M_BIT        (GPRS_Cell_Options_t, ACCESS_BURST_TYPE_v),
  M_BIT        (GPRS_Cell_Options_t, CONTROL_ACK_TYPE_v),
  M_UINT       (GPRS_Cell_Options_t, BS_CV_MAX_v, 4),

  M_NEXT_EXIST (GPRS_Cell_Options_t, Exist_PAN, 3),
  M_UINT       (GPRS_Cell_Options_t, PAN_DEC_v, 3),
  M_UINT       (GPRS_Cell_Options_t, PAN_INC_v, 3),
  M_UINT       (GPRS_Cell_Options_t, PAN_MAX_v, 3),

  M_NEXT_EXIST (GPRS_Cell_Options_t, Exist_Extension_Bits, 1),
  M_TYPE       (GPRS_Cell_Options_t, Extension_Bits, Extension_Bits_t),
CSN_DESCR_END  (GPRS_Cell_Options_t)

static const
CSN_DESCR_BEGIN(PBCCH_Not_present_t)
  M_UINT       (PBCCH_Not_present_t, RAC_v, 8),
  M_BIT        (PBCCH_Not_present_t, SPGC_CCCH_SUP_v),
  M_UINT       (PBCCH_Not_present_t, PRIORITY_ACCESS_THR_v, 3),
  M_UINT       (PBCCH_Not_present_t, NETWORK_CONTROL_ORDER_v, 2),
  M_TYPE       (PBCCH_Not_present_t, GPRS_Cell_Options, GPRS_Cell_Options_t),
  M_TYPE       (PBCCH_Not_present_t, GPRS_Power_Control_Parameters, GPRS_Power_Control_Parameters_t),
CSN_DESCR_END  (PBCCH_Not_present_t)

static const
CSN_ChoiceElement_t SI13_PBCCH_Description_Channel[] =
{/* this one is used in SI13*/
  {2, 0x00 , M_NULL(PBCCH_Description_t, u.dummy)},/*Default to BCCH carrier*/
  {2, 0x01 , M_UINT(PBCCH_Description_t, u.ARFCN_v, 10)},
  {1, 0x01 , M_UINT(PBCCH_Description_t, u.MAIO_v, 6)},
};

static const
CSN_DESCR_BEGIN(PBCCH_Description_t)/*SI13*/
  M_UINT       (PBCCH_Description_t, Pb, 4),
  M_UINT       (PBCCH_Description_t, TSC_v, 3),
  M_UINT       (PBCCH_Description_t, TN_v, 3),

  M_CHOICE     (PBCCH_Description_t, UnionType, SI13_PBCCH_Description_Channel, ElementsOf(SI13_PBCCH_Description_Channel)),
CSN_DESCR_END  (PBCCH_Description_t)

static const
CSN_DESCR_BEGIN(PBCCH_present_t)
  M_UINT       (PBCCH_present_t, PSI1_REPEAT_PERIOD_v, 4),
  M_TYPE       (PBCCH_present_t, PBCCH_Description, PBCCH_Description_t),
CSN_DESCR_END  (PBCCH_present_t)

static const
CSN_DESCR_BEGIN          (SI_13_t)
  M_THIS_EXIST_LH        (SI_13_t),

  M_UINT                 (SI_13_t, BCCH_CHANGE_MARK_v, 3),
  M_UINT                 (SI_13_t, SI_CHANGE_FIELD_v, 4),

  M_NEXT_EXIST           (SI_13_t, Exist_MA, 2),
  M_UINT                 (SI_13_t, SI13_CHANGE_MARK_v, 2),
  M_TYPE                 (SI_13_t, GPRS_Mobile_Allocation, GPRS_Mobile_Allocation_t),

  M_UNION                (SI_13_t, 2),
  M_TYPE                 (SI_13_t, u.PBCCH_Not_present, PBCCH_Not_present_t),
  M_TYPE                 (SI_13_t, u.PBCCH_present, PBCCH_present_t),

  M_NEXT_EXIST_OR_NULL_LH(SI_13_t, Exist_AdditionsR99, 1),
  M_UINT                 (SI_13_t, SGSNR_v, 1),
  M_NEXT_EXIST_OR_NULL_LH(SI_13_t, Exist_AdditionsR4, 1),
  M_UINT                 (SI_13_t, SI_STATUS_IND_v, 1),
CSN_DESCR_END            (SI_13_t)

/************************************************************/
/*                         TS 44.060 messages               */
/************************************************************/

/*< Packet TBF Release message content >*/
static const
CSN_DESCR_BEGIN(Packet_TBF_Release_t)
  M_UINT       (Packet_TBF_Release_t, MESSAGE_TYPE_v, 6),
  M_UINT       (Packet_TBF_Release_t, PAGE_MODE_v, 2),
  M_FIXED      (Packet_TBF_Release_t, 1, 0x00),
  M_TYPE       (Packet_TBF_Release_t, Global_TFI, Global_TFI_t),
  M_BIT        (Packet_TBF_Release_t, UPLINK_RELEASE_v),
  M_BIT        (Packet_TBF_Release_t, DOWNLINK_RELEASE_v),
  M_UINT       (Packet_TBF_Release_t, TBF_RELEASE_CAUSE_v, 4),
CSN_DESCR_END  (Packet_TBF_Release_t)

/*< Packet Control Acknowledgement message content >*/

static const
CSN_DESCR_BEGIN        (Packet_Control_Acknowledgement_AdditionsR6_t)
  M_NEXT_EXIST         (Packet_Control_Acknowledgement_AdditionsR6_t, Exist_CTRL_ACK_Extension, 1),
  M_UINT               (Packet_Control_Acknowledgement_AdditionsR6_t, CTRL_ACK_Extension_v, 9),
CSN_DESCR_END          (Packet_Control_Acknowledgement_AdditionsR6_t)

static const
CSN_DESCR_BEGIN        (Packet_Control_Acknowledgement_AdditionsR5_t)
  M_NEXT_EXIST         (Packet_Control_Acknowledgement_AdditionsR5_t, Exist_TN_RRBP, 1),
  M_UINT               (Packet_Control_Acknowledgement_AdditionsR5_t, TN_RRBP_v, 3),
  M_NEXT_EXIST         (Packet_Control_Acknowledgement_AdditionsR5_t, Exist_G_RNTI_Extension, 1),
  M_UINT               (Packet_Control_Acknowledgement_AdditionsR5_t, G_RNTI_Extension_v, 4),

  M_NEXT_EXIST_OR_NULL (Packet_Control_Acknowledgement_AdditionsR5_t, Exist_AdditionsR6, 1),
  M_TYPE               (Packet_Control_Acknowledgement_AdditionsR5_t, AdditionsR6, Packet_Control_Acknowledgement_AdditionsR6_t),
CSN_DESCR_END          (Packet_Control_Acknowledgement_AdditionsR5_t)

static const
CSN_DESCR_BEGIN        (Packet_Control_Acknowledgement_t)
  M_UINT               (Packet_Control_Acknowledgement_t, PayloadType, 2),
  M_UINT               (Packet_Control_Acknowledgement_t, spare, 5),
  M_BIT                (Packet_Control_Acknowledgement_t, R),

  M_UINT               (Packet_Control_Acknowledgement_t, MESSAGE_TYPE_v, 6),
  M_UINT               (Packet_Control_Acknowledgement_t, TLLI_v, 32),
  M_UINT               (Packet_Control_Acknowledgement_t, CTRL_ACK_v, 2),
  M_NEXT_EXIST_OR_NULL (Packet_Control_Acknowledgement_t, Exist_AdditionsR5, 1),
  M_TYPE               (Packet_Control_Acknowledgement_t, AdditionsR5, Packet_Control_Acknowledgement_AdditionsR5_t),
CSN_DESCR_END  (Packet_Control_Acknowledgement_t)

/*< Packet Downlink Dummy Control Block message content >*/
static const
CSN_DESCR_BEGIN(Packet_Downlink_Dummy_Control_Block_t)
  M_UINT       (Packet_Downlink_Dummy_Control_Block_t, MESSAGE_TYPE_v, 6),
  M_UINT       (Packet_Downlink_Dummy_Control_Block_t, PAGE_MODE_v, 2),

  M_NEXT_EXIST (Packet_Downlink_Dummy_Control_Block_t, Exist_PERSISTENCE_LEVEL_v, 1),
  M_UINT_ARRAY (Packet_Downlink_Dummy_Control_Block_t, PERSISTENCE_LEVEL_v, 4, 4),
CSN_DESCR_END  (Packet_Downlink_Dummy_Control_Block_t)

/*< Packet Uplink Dummy Control Block message content >*/
static const
CSN_DESCR_BEGIN(Packet_Uplink_Dummy_Control_Block_t)
  M_UINT       (Packet_Uplink_Dummy_Control_Block_t, PayloadType, 2),
  M_UINT       (Packet_Uplink_Dummy_Control_Block_t, spare, 5),
  M_BIT        (Packet_Uplink_Dummy_Control_Block_t, R),

  M_UINT       (Packet_Uplink_Dummy_Control_Block_t, MESSAGE_TYPE_v, 6),
  M_UINT       (Packet_Uplink_Dummy_Control_Block_t, TLLI_v, 32),
/*M_FIXED      (Packet_Uplink_Dummy_Control_Block_t, 1, 0),*/
CSN_DESCR_END  (Packet_Uplink_Dummy_Control_Block_t)

static const
CSN_DESCR_BEGIN(Receive_N_PDU_Number_t)
  M_UINT       (Receive_N_PDU_Number_t, nsapi, 4),
  M_UINT       (Receive_N_PDU_Number_t, value, 8),
CSN_DESCR_END  (Receive_N_PDU_Number_t)

gint16 Receive_N_PDU_Number_list_Dissector(proto_tree *tree, csnStream_t* ar, tvbuff_t *tvb, void* data, int ett_csn1 _U_)
{
  return csnStreamDissector(tree, ar, CSNDESCR(Receive_N_PDU_Number_t), tvb, data, ett_gsm_rlcmac);
}

static const
CSN_DESCR_BEGIN(Receive_N_PDU_Number_list_t)
  M_SERIALIZE  (Receive_N_PDU_Number_list_t, IEI, Receive_N_PDU_Number_list_Dissector),
  M_VAR_TARRAY (Receive_N_PDU_Number_list_t, Receive_N_PDU_Number, Receive_N_PDU_Number_t, Count_Receive_N_PDU_Number),
CSN_DESCR_END  (Receive_N_PDU_Number_list_t)

/*< MS Radio Access capability IE >*/
static const
CSN_DESCR_BEGIN       (DTM_EGPRS_t)
  M_NEXT_EXIST        (DTM_EGPRS_t, Exist_DTM_EGPRS_multislot_class, 1),
  M_UINT              (DTM_EGPRS_t, DTM_EGPRS_multislot_class, 2),
CSN_DESCR_END         (DTM_EGPRS_t)

static const
CSN_DESCR_BEGIN       (DTM_EGPRS_HighMultislotClass_t)
  M_NEXT_EXIST        (DTM_EGPRS_HighMultislotClass_t, Exist_DTM_EGPRS_HighMultislotClass, 1),
  M_UINT              (DTM_EGPRS_HighMultislotClass_t, DTM_EGPRS_HighMultislotClass, 3),
CSN_DESCR_END         (DTM_EGPRS_HighMultislotClass_t)

static const
CSN_DESCR_BEGIN       (Multislot_capability_t)
  M_NEXT_EXIST        (Multislot_capability_t, Exist_HSCSD_multislot_class, 1),
  M_UINT              (Multislot_capability_t, HSCSD_multislot_class, 5),

  M_NEXT_EXIST        (Multislot_capability_t, Exist_GPRS_multislot_class, 2),
  M_UINT              (Multislot_capability_t, GPRS_multislot_class, 5),
  M_UINT              (Multislot_capability_t, GPRS_Extended_Dynamic_Allocation_Capability, 1),

  M_NEXT_EXIST        (Multislot_capability_t, Exist_SM, 2),
  M_UINT              (Multislot_capability_t, SMS_VALUE_v, 4),
  M_UINT              (Multislot_capability_t, SM_VALUE_v, 4),

  M_NEXT_EXIST        (Multislot_capability_t, Exist_ECSD_multislot_class, 1),
  M_UINT              (Multislot_capability_t, ECSD_multislot_class, 5),

  M_NEXT_EXIST        (Multislot_capability_t, Exist_EGPRS_multislot_class, 2),
  M_UINT              (Multislot_capability_t, EGPRS_multislot_class, 5),
  M_UINT              (Multislot_capability_t, EGPRS_Extended_Dynamic_Allocation_Capability, 1),

  M_NEXT_EXIST        (Multislot_capability_t, Exist_DTM_GPRS_multislot_class, 3),
  M_UINT              (Multislot_capability_t, DTM_GPRS_multislot_class, 2),
  M_UINT              (Multislot_capability_t, Single_Slot_DTM, 1),
  M_TYPE              (Multislot_capability_t, DTM_EGPRS_Params, DTM_EGPRS_t),
CSN_DESCR_END         (Multislot_capability_t)

static const
CSN_DESCR_BEGIN       (Content_t)
  M_UINT              (Content_t, RF_Power_Capability, 3),

  M_NEXT_EXIST        (Content_t, Exist_A5_bits, 1),
  M_UINT              (Content_t, A5_bits, 7),

  M_UINT              (Content_t, ES_IND_v, 1),
  M_UINT              (Content_t, PS_v, 1),
  M_UINT              (Content_t, VGCS_v, 1),
  M_UINT              (Content_t, VBS_v, 1),

  M_NEXT_EXIST_OR_NULL(Content_t, Exist_Multislot_capability, 1),
  M_TYPE              (Content_t, Multislot_capability, Multislot_capability_t),

  M_NEXT_EXIST        (Content_t, Exist_Eight_PSK_Power_Capability, 1),
  M_UINT              (Content_t, Eight_PSK_Power_Capability, 2),

  M_UINT              (Content_t, COMPACT_Interference_Measurement_Capability, 1),
  M_UINT              (Content_t, Revision_Level_Indicator, 1),
  M_UINT              (Content_t, UMTS_FDD_Radio_Access_Technology_Capability, 1),
  M_UINT              (Content_t, UMTS_384_TDD_Radio_Access_Technology_Capability, 1),
  M_UINT              (Content_t, CDMA2000_Radio_Access_Technology_Capability, 1),

  M_UINT              (Content_t, UMTS_128_TDD_Radio_Access_Technology_Capability, 1),
  M_UINT              (Content_t, GERAN_Feature_Package_1, 1),

  M_NEXT_EXIST        (Content_t, Exist_Extended_DTM_multislot_class, 2),
  M_UINT              (Content_t, Extended_DTM_GPRS_multislot_class, 2),
  M_UINT              (Content_t, Extended_DTM_EGPRS_multislot_class, 2),

  M_UINT              (Content_t, Modulation_based_multislot_class_support, 1),

  M_NEXT_EXIST        (Content_t, Exist_HighMultislotCapability, 1),
  M_UINT              (Content_t, HighMultislotCapability, 2),

  M_NEXT_EXIST        (Content_t, Exist_GERAN_lu_ModeCapability, 1),
  M_UINT              (Content_t, GERAN_lu_ModeCapability, 4),

  M_UINT              (Content_t, GMSK_MultislotPowerProfile, 2),
  M_UINT              (Content_t, EightPSK_MultislotProfile, 2),

  M_UINT              (Content_t, MultipleTBF_Capability, 1),
  M_UINT              (Content_t, DownlinkAdvancedReceiverPerformance, 2),
  M_UINT              (Content_t, ExtendedRLC_MAC_ControlMessageSegmentionsCapability, 1),
  M_UINT              (Content_t, DTM_EnhancementsCapability, 1),

  M_NEXT_EXIST        (Content_t, Exist_DTM_GPRS_HighMultislotClass, 2),
  M_UINT              (Content_t, DTM_GPRS_HighMultislotClass, 3),
  M_TYPE              (Content_t, DTM_EGPRS_HighMultislotClass, DTM_EGPRS_HighMultislotClass_t),

  M_UINT              (Content_t, PS_HandoverCapability, 1),
CSN_DESCR_END         (Content_t)

gint16 Content_Dissector(proto_tree *tree, csnStream_t* ar, tvbuff_t *tvb, void* data, int ett_csn1 _U_)
{
  return csnStreamDissector(tree, ar, CSNDESCR(Content_t), tvb, data, ett_gsm_rlcmac);
}

static const
CSN_DESCR_BEGIN       (Additional_access_technologies_struct_t)
  M_UINT              (Additional_access_technologies_struct_t, Access_Technology_Type, 4),
  M_UINT              (Additional_access_technologies_struct_t, GMSK_Power_class, 3),
  M_UINT              (Additional_access_technologies_struct_t, Eight_PSK_Power_class, 2),
CSN_DESCR_END         (Additional_access_technologies_struct_t)

static const
CSN_DESCR_BEGIN       (Additional_access_technologies_t)
  M_REC_TARRAY        (Additional_access_technologies_t, Additional_access_technologies[0], Additional_access_technologies_struct_t, Count_additional_access_technologies),
CSN_DESCR_END         (Additional_access_technologies_t)

gint16 Additional_access_technologies_Dissector(proto_tree *tree, csnStream_t* ar, tvbuff_t *tvb, void* data, int ett_csn1 _U_)
{
  return csnStreamDissector(tree, ar, CSNDESCR(Additional_access_technologies_t), tvb, data, ett_gsm_rlcmac);
}

static const
CSN_ChoiceElement_t MS_RA_capability_value_Choice[] =
{
  {4, AccTech_GSMP,     M_SERIALIZE (MS_RA_capability_value_t, u.Content, Content_Dissector)}, /* Long Form */
  {4, AccTech_GSME,     M_SERIALIZE (MS_RA_capability_value_t, u.Content, Content_Dissector)}, /* Long Form */
  {4, AccTech_GSM1800,  M_SERIALIZE (MS_RA_capability_value_t, u.Content, Content_Dissector)}, /* Long Form */
  {4, AccTech_GSM1900,  M_SERIALIZE (MS_RA_capability_value_t, u.Content, Content_Dissector)}, /* Long Form */
  {4, AccTech_GSM850,   M_SERIALIZE (MS_RA_capability_value_t, u.Content, Content_Dissector)}, /* Long Form */
  {4, AccTech_GSMOther, M_SERIALIZE (MS_RA_capability_value_t, u.Additional_access_technologies, Additional_access_technologies_Dissector)}, /* Short Form */
};

static const
CSN_DESCR_BEGIN(MS_RA_capability_value_t)
  M_CHOICE     (MS_RA_capability_value_t, IndexOfAccTech, MS_RA_capability_value_Choice, ElementsOf(MS_RA_capability_value_Choice)),
CSN_DESCR_END  (MS_RA_capability_value_t)

static const
CSN_DESCR_BEGIN (MS_Radio_Access_capability_t)
/*Will be done in the main routines:*/
/*M_UINT        (MS_Radio_Access_capability_t, IEI, 8), 00100100 */
/*M_UINT        (MS_Radio_Access_capability_t, Length, 8),*/

  M_REC_TARRAY_1(MS_Radio_Access_capability_t, MS_RA_capability_value[0], MS_RA_capability_value_t, Count_MS_RA_capability_value),
CSN_DESCR_END   (MS_Radio_Access_capability_t)

/*< MS Classmark 3 IE > R99 ecsttsv*/
static const
CSN_DESCR_BEGIN(ARC_t)
  M_UINT       (ARC_t, A5_Bits, 4),
  M_UINT       (ARC_t, Arc2_Spare, 4),
  M_UINT       (ARC_t, Arc1, 4),
CSN_DESCR_END  (ARC_t)

static const
CSN_ChoiceElement_t MultibandChoice[] =
{
  {3, 0x00, M_UINT(Multiband_t, u.A5_Bits, 4)},
  {3, 0x05, M_TYPE(Multiband_t, u.ARC, ARC_t)},
  {3, 0x06, M_TYPE(Multiband_t, u.ARC, ARC_t)},
  {3, 0x01, M_TYPE(Multiband_t, u.ARC, ARC_t)},
  {3, 0x02, M_TYPE(Multiband_t, u.ARC, ARC_t)},
  {3, 0x04, M_TYPE(Multiband_t, u.ARC, ARC_t)},
};

static const
CSN_DESCR_BEGIN(Multiband_t)
  M_CHOICE     (Multiband_t, Multiband_v, MultibandChoice, ElementsOf(MultibandChoice)),
CSN_DESCR_END  (Multiband_t)

static const
CSN_DESCR_BEGIN(EDGE_RF_Pwr_t)
  M_NEXT_EXIST (EDGE_RF_Pwr_t, ExistEDGE_RF_PwrCap1, 1),
  M_UINT       (EDGE_RF_Pwr_t, EDGE_RF_PwrCap1, 2),

  M_NEXT_EXIST (EDGE_RF_Pwr_t, ExistEDGE_RF_PwrCap2, 1),
  M_UINT       (EDGE_RF_Pwr_t, EDGE_RF_PwrCap2, 2),
CSN_DESCR_END  (EDGE_RF_Pwr_t)

static const
CSN_DESCR_BEGIN(MS_Class3_Unpacked_t)
  M_UINT       (MS_Class3_Unpacked_t, Spare1, 1),
  M_TYPE       (MS_Class3_Unpacked_t, Multiband, Multiband_t),

  M_NEXT_EXIST (MS_Class3_Unpacked_t, Exist_R_Support, 1),
  M_UINT       (MS_Class3_Unpacked_t, R_GSM_Arc, 3),

  M_NEXT_EXIST (MS_Class3_Unpacked_t, Exist_MultiSlotCapability, 1),
  M_UINT       (MS_Class3_Unpacked_t, MultiSlotClass, 5),

  M_UINT       (MS_Class3_Unpacked_t, UCS2, 1),
  M_UINT       (MS_Class3_Unpacked_t, ExtendedMeasurementCapability, 1),

  M_NEXT_EXIST (MS_Class3_Unpacked_t, Exist_MS_MeasurementCapability, 2),
  M_UINT       (MS_Class3_Unpacked_t, SMS_VALUE_v, 4),
  M_UINT       (MS_Class3_Unpacked_t, SM_VALUE_v, 4),

  M_NEXT_EXIST (MS_Class3_Unpacked_t, Exist_MS_PositioningMethodCapability, 1),
  M_UINT       (MS_Class3_Unpacked_t, MS_PositioningMethod, 5),

  M_NEXT_EXIST (MS_Class3_Unpacked_t, Exist_EDGE_MultiSlotCapability, 1),
  M_UINT       (MS_Class3_Unpacked_t, EDGE_MultiSlotClass, 5),

  M_NEXT_EXIST (MS_Class3_Unpacked_t, Exist_EDGE_Struct, 2),
  M_UINT       (MS_Class3_Unpacked_t, ModulationCapability, 1),
  M_TYPE       (MS_Class3_Unpacked_t, EDGE_RF_PwrCaps, EDGE_RF_Pwr_t),

  M_NEXT_EXIST (MS_Class3_Unpacked_t, Exist_GSM400_Info, 2),
  M_UINT       (MS_Class3_Unpacked_t, GSM400_Bands, 2),
  M_UINT       (MS_Class3_Unpacked_t, GSM400_Arc, 4),

  M_NEXT_EXIST (MS_Class3_Unpacked_t, Exist_GSM850_Arc, 1),
  M_UINT       (MS_Class3_Unpacked_t, GSM850_Arc, 4),

  M_NEXT_EXIST (MS_Class3_Unpacked_t, Exist_PCS1900_Arc, 1),
  M_UINT       (MS_Class3_Unpacked_t, PCS1900_Arc, 4),

  M_UINT       (MS_Class3_Unpacked_t, UMTS_FDD_Radio_Access_Technology_Capability, 1),
  M_UINT       (MS_Class3_Unpacked_t, UMTS_384_TDD_Radio_Access_Technology_Capability, 1),
  M_UINT       (MS_Class3_Unpacked_t, CDMA2000_Radio_Access_Technology_Capability, 1),

  M_NEXT_EXIST (MS_Class3_Unpacked_t, Exist_DTM_GPRS_multislot_class, 3),
  M_UINT       (MS_Class3_Unpacked_t, DTM_GPRS_multislot_class, 2),
  M_UINT       (MS_Class3_Unpacked_t, Single_Slot_DTM, 1),
  M_TYPE       (MS_Class3_Unpacked_t, DTM_EGPRS_Params, DTM_EGPRS_t),

  M_NEXT_EXIST (MS_Class3_Unpacked_t, Exist_SingleBandSupport, 1),
  M_UINT       (MS_Class3_Unpacked_t, GSM_Band, 4),

  M_NEXT_EXIST (MS_Class3_Unpacked_t, Exist_GSM_700_Associated_Radio_Capability, 1),
  M_UINT       (MS_Class3_Unpacked_t, GSM_700_Associated_Radio_Capability, 4),

  M_UINT       (MS_Class3_Unpacked_t, UMTS_128_TDD_Radio_Access_Technology_Capability, 1),
  M_UINT       (MS_Class3_Unpacked_t, GERAN_Feature_Package_1, 1),

  M_NEXT_EXIST (MS_Class3_Unpacked_t, Exist_Extended_DTM_multislot_class, 2),
  M_UINT       (MS_Class3_Unpacked_t, Extended_DTM_GPRS_multislot_class, 2),
  M_UINT       (MS_Class3_Unpacked_t, Extended_DTM_EGPRS_multislot_class, 2),

  M_NEXT_EXIST (MS_Class3_Unpacked_t, Exist_HighMultislotCapability, 1),
  M_UINT       (MS_Class3_Unpacked_t, HighMultislotCapability, 2),

  M_NEXT_EXIST (MS_Class3_Unpacked_t, Exist_GERAN_lu_ModeCapability, 1),
  M_UINT       (MS_Class3_Unpacked_t, GERAN_lu_ModeCapability, 4),

  M_UINT       (MS_Class3_Unpacked_t, GERAN_FeaturePackage_2, 1),

  M_UINT       (MS_Class3_Unpacked_t, GMSK_MultislotPowerProfile, 2),
  M_UINT       (MS_Class3_Unpacked_t, EightPSK_MultislotProfile, 2),

  M_NEXT_EXIST (MS_Class3_Unpacked_t, Exist_TGSM_400_Bands, 2),
  M_UINT       (MS_Class3_Unpacked_t, TGSM_400_BandsSupported, 2),
  M_UINT       (MS_Class3_Unpacked_t, TGSM_400_AssociatedRadioCapability, 4),

  M_NEXT_EXIST (MS_Class3_Unpacked_t, Exist_TGSM_900_AssociatedRadioCapability, 1),
  M_UINT       (MS_Class3_Unpacked_t, TGSM_900_AssociatedRadioCapability, 4),

  M_UINT       (MS_Class3_Unpacked_t, DownlinkAdvancedReceiverPerformance, 2),
  M_UINT       (MS_Class3_Unpacked_t, DTM_EnhancementsCapability, 1),

  M_NEXT_EXIST (MS_Class3_Unpacked_t, Exist_DTM_GPRS_HighMultislotClass, 3),
  M_UINT       (MS_Class3_Unpacked_t, DTM_GPRS_HighMultislotClass, 3),
  M_UINT       (MS_Class3_Unpacked_t, OffsetRequired, 1),
  M_TYPE       (MS_Class3_Unpacked_t, DTM_EGPRS_HighMultislotClass, DTM_EGPRS_HighMultislotClass_t),

  M_UINT       (MS_Class3_Unpacked_t, RepeatedSACCH_Capability, 1),
  M_UINT       (MS_Class3_Unpacked_t, Spare2, 1),
CSN_DESCR_END  (MS_Class3_Unpacked_t)

static const
CSN_DESCR_BEGIN(Channel_Request_Description_t)
  M_UINT       (Channel_Request_Description_t, PEAK_THROUGHPUT_CLASS_v, 4),
  M_UINT       (Channel_Request_Description_t, RADIO_PRIORITY_v, 2),
  M_BIT        (Channel_Request_Description_t, RLC_MODE_v),
  M_BIT        (Channel_Request_Description_t, LLC_PDU_TYPE_v),
  M_UINT       (Channel_Request_Description_t, RLC_OCTET_COUNT_v, 16),
CSN_DESCR_END  (Channel_Request_Description_t)

/* < Packet Resource Request message content > */
static const
CSN_ChoiceElement_t PacketResourceRequestID[] =
{
  {1, 0,    M_TYPE(PacketResourceRequestID_t, u.Global_TFI, Global_TFI_t)},
  {1, 0x01, M_UINT(PacketResourceRequestID_t, u.TLLI_v, 32)},
};

static const
CSN_DESCR_BEGIN(PacketResourceRequestID_t)
  M_CHOICE     (PacketResourceRequestID_t, UnionType, PacketResourceRequestID, ElementsOf(PacketResourceRequestID)),
CSN_DESCR_END  (PacketResourceRequestID_t)

static const
CSN_DESCR_BEGIN(BEP_MeasurementReport_t)
  M_NEXT_EXIST (BEP_MeasurementReport_t, Exist, 3),
  M_UNION      (BEP_MeasurementReport_t, 2),
  M_UINT       (BEP_MeasurementReport_t, u.MEAN_BEP_GMSK_v, 4),
  M_UINT       (BEP_MeasurementReport_t, u.MEAN_BEP_8PSK_v, 4),
CSN_DESCR_END  (BEP_MeasurementReport_t)

static const
CSN_DESCR_BEGIN(InterferenceMeasurementReport_t)
  M_NEXT_EXIST (InterferenceMeasurementReport_t, Exist, 1),
  M_UINT       (InterferenceMeasurementReport_t, I_LEVEL_v, 4),
CSN_DESCR_END  (InterferenceMeasurementReport_t)

static const
CSN_DESCR_BEGIN(EGPRS_TimeslotLinkQualityMeasurements_t)
  M_NEXT_EXIST (EGPRS_TimeslotLinkQualityMeasurements_t, Exist_BEP_MEASUREMENTS, 1),
  M_TYPE_ARRAY (EGPRS_TimeslotLinkQualityMeasurements_t, BEP_MEASUREMENTS_v, BEP_MeasurementReport_t, 8),

  M_NEXT_EXIST (EGPRS_TimeslotLinkQualityMeasurements_t, Exist_INTERFERENCE_MEASUREMENTS, 1),
  M_TYPE_ARRAY (EGPRS_TimeslotLinkQualityMeasurements_t, INTERFERENCE_MEASUREMENTS_v, InterferenceMeasurementReport_t, 8),
CSN_DESCR_END  (EGPRS_TimeslotLinkQualityMeasurements_t)

static const
CSN_DESCR_BEGIN(EGPRS_BEP_LinkQualityMeasurements_t)
  M_NEXT_EXIST (EGPRS_BEP_LinkQualityMeasurements_t, Exist_MEAN_CV_BEP_GMSK, 2),
  M_UINT       (EGPRS_BEP_LinkQualityMeasurements_t, MEAN_BEP_GMSK_v, 5),
  M_UINT       (EGPRS_BEP_LinkQualityMeasurements_t, CV_BEP_GMSK_v, 3),

  M_NEXT_EXIST (EGPRS_BEP_LinkQualityMeasurements_t, Exist_MEAN_CV_BEP_8PSK, 2),
  M_UINT       (EGPRS_BEP_LinkQualityMeasurements_t, MEAN_BEP_8PSK_v, 5),
  M_UINT       (EGPRS_BEP_LinkQualityMeasurements_t, CV_BEP_8PSK_v, 3),
CSN_DESCR_END  (EGPRS_BEP_LinkQualityMeasurements_t)

static const
CSN_DESCR_BEGIN(PRR_AdditionsR99_t)
  M_NEXT_EXIST (PRR_AdditionsR99_t, Exist_EGPRS_BEP_LinkQualityMeasurements, 1),
  M_TYPE       (PRR_AdditionsR99_t, EGPRS_BEP_LinkQualityMeasurements, EGPRS_BEP_LinkQualityMeasurements_t),

  M_NEXT_EXIST (PRR_AdditionsR99_t, Exist_EGPRS_TimeslotLinkQualityMeasurements, 1),
  M_TYPE       (PRR_AdditionsR99_t, EGPRS_TimeslotLinkQualityMeasurements, EGPRS_TimeslotLinkQualityMeasurements_t),

  M_NEXT_EXIST (PRR_AdditionsR99_t, Exist_PFI_v, 1),
  M_UINT       (PRR_AdditionsR99_t, PFI_v, 7),

  M_UINT       (PRR_AdditionsR99_t, MS_RAC_AdditionalInformationAvailable, 1),
  M_UINT       (PRR_AdditionsR99_t, RetransmissionOfPRR, 1),
CSN_DESCR_END  (PRR_AdditionsR99_t)

static const
CSN_DESCR_BEGIN       (Packet_Resource_Request_t)
  /* Mac header */
  M_UINT              (Packet_Resource_Request_t, PayloadType, 2),
  M_UINT              (Packet_Resource_Request_t, spare, 5),
  M_UINT              (Packet_Resource_Request_t, R, 1),
  M_UINT              (Packet_Resource_Request_t, MESSAGE_TYPE_v, 6),
  /* Mac header */

  M_NEXT_EXIST        (Packet_Resource_Request_t, Exist_ACCESS_TYPE_v, 1),
  M_UINT              (Packet_Resource_Request_t, ACCESS_TYPE_v, 2),

  M_TYPE              (Packet_Resource_Request_t, ID, PacketResourceRequestID_t),

  M_NEXT_EXIST        (Packet_Resource_Request_t, Exist_MS_Radio_Access_capability, 1),
  M_TYPE              (Packet_Resource_Request_t, MS_Radio_Access_capability, MS_Radio_Access_capability_t),

  M_TYPE              (Packet_Resource_Request_t, Channel_Request_Description, Channel_Request_Description_t),

  M_NEXT_EXIST        (Packet_Resource_Request_t, Exist_CHANGE_MARK_v, 1),
  M_UINT              (Packet_Resource_Request_t, CHANGE_MARK_v, 2),

  M_UINT              (Packet_Resource_Request_t, C_VALUE_v, 6),

  M_NEXT_EXIST        (Packet_Resource_Request_t, Exist_SIGN_VAR_v, 1),
  M_UINT              (Packet_Resource_Request_t, SIGN_VAR_v, 6),

  M_TYPE_ARRAY        (Packet_Resource_Request_t, Slot, InterferenceMeasurementReport_t, 8),

  M_NEXT_EXIST_OR_NULL(Packet_Resource_Request_t, Exist_AdditionsR99, 1),
  M_TYPE              (Packet_Resource_Request_t, AdditionsR99, PRR_AdditionsR99_t),
CSN_DESCR_END         (Packet_Resource_Request_t)

/*< Packet Mobile TBF Status message content > */
static const
CSN_DESCR_BEGIN(Packet_Mobile_TBF_Status_t)
  /* Mac header */
  M_UINT       (Packet_Mobile_TBF_Status_t, PayloadType, 2),
  M_UINT       (Packet_Mobile_TBF_Status_t, spare, 5),
  M_UINT       (Packet_Mobile_TBF_Status_t, R, 1),
  M_UINT       (Packet_Mobile_TBF_Status_t, MESSAGE_TYPE_v, 6),
  /* Mac header */

  M_TYPE       (Packet_Mobile_TBF_Status_t, Global_TFI, Global_TFI_t),
  M_UINT       (Packet_Mobile_TBF_Status_t, TBF_CAUSE_v, 3),

  M_NEXT_EXIST (Packet_Mobile_TBF_Status_t, Exist_STATUS_MESSAGE_TYPE_v, 1),
  M_UINT       (Packet_Mobile_TBF_Status_t, STATUS_MESSAGE_TYPE_v, 6),
CSN_DESCR_END  (Packet_Mobile_TBF_Status_t)

/*< Packet PSI Status message content > */
static const
CSN_DESCR_BEGIN(PSI_Message_t)
  M_UINT       (PSI_Message_t, PSI_MESSAGE_TYPE_v, 6),
  M_UINT       (PSI_Message_t, PSIX_CHANGE_MARK_v, 2),
  M_NEXT_EXIST (PSI_Message_t, Exist_PSIX_COUNT_and_Instance_Bitmap, 2),
  M_FIXED      (PSI_Message_t, 4, 0),   /* Placeholder for PSIX_COUNT (4 bits) */
  M_FIXED      (PSI_Message_t, 1, 0),   /* Placeholder for Instance bitmap (1 bit) */
CSN_DESCR_END  (PSI_Message_t)

static const
CSN_DESCR_BEGIN(PSI_Message_List_t)
  M_REC_TARRAY (PSI_Message_List_t, PSI_Message[0], PSI_Message_t, Count_PSI_Message),
  M_FIXED      (PSI_Message_List_t, 1, 0x00),
  M_UINT       (PSI_Message_List_t, ADDITIONAL_MSG_TYPE_v, 1),
CSN_DESCR_END  (PSI_Message_List_t)

static const
CSN_DESCR_BEGIN(Unknown_PSI_Message_List_t)
  M_FIXED      (Unknown_PSI_Message_List_t, 1, 0x00),
  M_UINT       (Unknown_PSI_Message_List_t, ADDITIONAL_MSG_TYPE_v, 1),
CSN_DESCR_END  (Unknown_PSI_Message_List_t)

static const
CSN_DESCR_BEGIN(Packet_PSI_Status_t)
  /* Mac header */
  M_UINT       (Packet_PSI_Status_t, PayloadType, 2),
  M_UINT       (Packet_PSI_Status_t, spare, 5),
  M_UINT       (Packet_PSI_Status_t, R, 1),
  M_UINT       (Packet_PSI_Status_t, MESSAGE_TYPE_v, 6),
  /* Mac header */

  M_TYPE       (Packet_PSI_Status_t, Global_TFI, Global_TFI_t),
  M_UINT       (Packet_PSI_Status_t, PBCCH_CHANGE_MARK_v, 3),
  M_TYPE       (Packet_PSI_Status_t, PSI_Message_List, PSI_Message_List_t),
  M_TYPE       (Packet_PSI_Status_t, Unknown_PSI_Message_List, Unknown_PSI_Message_List_t),
CSN_DESCR_END  (Packet_PSI_Status_t)

/* < Packet SI Status message content > */

static const
CSN_DESCR_BEGIN(SI_Message_t)
  M_UINT       (SI_Message_t, SI_MESSAGE_TYPE_v, 8),
  M_UINT       (SI_Message_t, MESS_REC, 2),
CSN_DESCR_END  (SI_Message_t)

static const
CSN_DESCR_BEGIN(SI_Message_List_t)
  M_REC_TARRAY (SI_Message_List_t, SI_Message[0], SI_Message_t, Count_SI_Message),
  M_FIXED      (SI_Message_List_t, 1, 0x00),
  M_UINT       (SI_Message_List_t, ADDITIONAL_MSG_TYPE_v, 1),
CSN_DESCR_END  (SI_Message_List_t)

static const
CSN_DESCR_BEGIN(Unknown_SI_Message_List_t)
  M_FIXED      (Unknown_SI_Message_List_t, 1, 0x00),
  M_UINT       (Unknown_SI_Message_List_t, ADDITIONAL_MSG_TYPE_v, 1),
CSN_DESCR_END  (Unknown_SI_Message_List_t)

static const
CSN_DESCR_BEGIN(Packet_SI_Status_t)
  /* Mac header */
  M_UINT       (Packet_SI_Status_t, PayloadType, 2),
  M_UINT       (Packet_SI_Status_t, spare, 5),
  M_UINT       (Packet_SI_Status_t, R, 1),
  M_UINT       (Packet_SI_Status_t, MESSAGE_TYPE_v, 6),
  /* Mac header */

  M_TYPE       (Packet_SI_Status_t, Global_TFI, Global_TFI_t),
  M_UINT       (Packet_SI_Status_t, BCCH_CHANGE_MARK_v, 3),
  M_TYPE       (Packet_SI_Status_t, SI_Message_List, SI_Message_List_t),
  M_TYPE       (Packet_SI_Status_t, Unknown_SI_Message_List, Unknown_SI_Message_List_t),
CSN_DESCR_END  (Packet_SI_Status_t)

/* < Packet Downlink Ack/Nack message content > */
static const
CSN_DESCR_BEGIN(PD_AckNack_AdditionsR99_t)
  M_NEXT_EXIST (PD_AckNack_AdditionsR99_t, Exist_PFI_v, 1),
  M_UINT       (PD_AckNack_AdditionsR99_t, PFI_v, 7),
CSN_DESCR_END  (PD_AckNack_AdditionsR99_t)

static const
CSN_DESCR_BEGIN       (Packet_Downlink_Ack_Nack_t)
  M_UINT              (Packet_Downlink_Ack_Nack_t, PayloadType, 2),
  M_UINT              (Packet_Downlink_Ack_Nack_t, spare, 5),
  M_BIT               (Packet_Downlink_Ack_Nack_t, R),
  M_UINT              (Packet_Downlink_Ack_Nack_t, MESSAGE_TYPE_v, 6),
  M_UINT              (Packet_Downlink_Ack_Nack_t, DOWNLINK_TFI_v, 5),
  M_TYPE              (Packet_Downlink_Ack_Nack_t, Ack_Nack_Description, Ack_Nack_Description_t),

  M_NEXT_EXIST        (Packet_Downlink_Ack_Nack_t, Exist_Channel_Request_Description, 1),
  M_TYPE              (Packet_Downlink_Ack_Nack_t, Channel_Request_Description, Channel_Request_Description_t),

  M_TYPE              (Packet_Downlink_Ack_Nack_t, Channel_Quality_Report, Channel_Quality_Report_t),

  M_NEXT_EXIST_OR_NULL(Packet_Downlink_Ack_Nack_t, Exist_AdditionsR99, 1),
  M_TYPE              (Packet_Downlink_Ack_Nack_t, AdditionsR99, PD_AckNack_AdditionsR99_t),
CSN_DESCR_END         (Packet_Downlink_Ack_Nack_t)


/*< EGPRS Packet Downlink Ack/Nack message content > */
static const
CSN_DESCR_BEGIN(EGPRS_ChannelQualityReport_t)
  M_TYPE       (EGPRS_ChannelQualityReport_t, EGPRS_BEP_LinkQualityMeasurements, EGPRS_BEP_LinkQualityMeasurements_t),
  M_UINT       (EGPRS_ChannelQualityReport_t, C_VALUE_v, 6),
  M_TYPE       (EGPRS_ChannelQualityReport_t, EGPRS_TimeslotLinkQualityMeasurements, EGPRS_TimeslotLinkQualityMeasurements_t),
CSN_DESCR_END  (EGPRS_ChannelQualityReport_t)

static const
CSN_DESCR_BEGIN(EGPRS_PD_AckNack_t)
/*  M_CALLBACK   (EGPRS_PD_AckNack_t, (void*)21, IsSupported, IsSupported), */
  M_UINT       (EGPRS_PD_AckNack_t, PayloadType, 2),
  M_UINT       (EGPRS_PD_AckNack_t, spare, 5),
  M_BIT        (EGPRS_PD_AckNack_t, R),

  M_UINT       (EGPRS_PD_AckNack_t, MESSAGE_TYPE_v, 6),
  M_UINT       (EGPRS_PD_AckNack_t, DOWNLINK_TFI_v, 5),
  M_UINT       (EGPRS_PD_AckNack_t, MS_OUT_OF_MEMORY_v, 1),

  M_NEXT_EXIST (EGPRS_PD_AckNack_t, Exist_EGPRS_ChannelQualityReport, 1),
  M_TYPE       (EGPRS_PD_AckNack_t, EGPRS_ChannelQualityReport, EGPRS_ChannelQualityReport_t),

  M_NEXT_EXIST (EGPRS_PD_AckNack_t, Exist_ChannelRequestDescription, 1),
  M_TYPE       (EGPRS_PD_AckNack_t, ChannelRequestDescription, Channel_Request_Description_t),

  M_NEXT_EXIST (EGPRS_PD_AckNack_t, Exist_PFI_v, 1),
  M_UINT       (EGPRS_PD_AckNack_t, PFI_v, 7),

  M_NEXT_EXIST (EGPRS_PD_AckNack_t, Exist_ExtensionBits, 1),
  M_TYPE       (EGPRS_PD_AckNack_t, ExtensionBits, Extension_Bits_t),

  M_TYPE       (EGPRS_PD_AckNack_t, EGPRS_AckNack, EGPRS_AckNack_t),
/*  M_CALLBACK   (EGPRS_PD_AckNack_t, (void*)24, EGPRS_AckNack, EGPRS_AckNack),  */
  M_LEFT_VAR_BMP (EGPRS_PD_AckNack_t, EGPRS_AckNack.URBB_v, EGPRS_AckNack.URBB_LENGTH_v, 0),

CSN_DESCR_END  (EGPRS_PD_AckNack_t)

static const
CSN_DESCR_BEGIN(FDD_Target_Cell_t)
  M_UINT       (FDD_Target_Cell_t, FDD_ARFCN_v, 14),
  M_UINT       (FDD_Target_Cell_t, DIVERSITY_v, 1),
  M_NEXT_EXIST (FDD_Target_Cell_t, Exist_Bandwith_FDD, 1),
  M_UINT       (FDD_Target_Cell_t, BANDWITH_FDD_v, 3),
  M_UINT       (FDD_Target_Cell_t, SCRAMBLING_CODE_v, 9),
CSN_DESCR_END  (FDD_Target_Cell_t)

/* TDD cell not implemented */
static const
CSN_DESCR_BEGIN(TDD_Target_Cell_t)
  M_UINT       (TDD_Target_Cell_t, Complete_This, 1),
  CSN_ERROR    (TDD_Target_Cell_t, "Not Implemented", CSN_ERROR_STREAM_NOT_SUPPORTED),
CSN_DESCR_END  (TDD_Target_Cell_t)

static const
CSN_DESCR_BEGIN(PCCF_AdditionsR99_t)
  M_NEXT_EXIST (PCCF_AdditionsR99_t, Exist_FDD_Description, 1),
  M_TYPE       (PCCF_AdditionsR99_t, FDD_Target_Cell, FDD_Target_Cell_t),
  M_NEXT_EXIST (PCCF_AdditionsR99_t, Exist_TDD_Description, 1),
  M_TYPE       (PCCF_AdditionsR99_t, TDD_Target_Cell, TDD_Target_Cell_t),  /* not implemented */
CSN_DESCR_END  (PCCF_AdditionsR99_t)

/*< Packet Cell Change Failure message content > */
static const
CSN_DESCR_BEGIN(Packet_Cell_Change_Failure_t)
  /* Mac header */
  M_UINT               (Packet_Cell_Change_Failure_t, PayloadType, 2),
  M_UINT               (Packet_Cell_Change_Failure_t, spare, 5),
  M_UINT               (Packet_Cell_Change_Failure_t, R, 1),
  M_UINT               (Packet_Cell_Change_Failure_t, MESSAGE_TYPE_v, 6),
  /* Mac header */

  M_UINT               (Packet_Cell_Change_Failure_t, TLLI_v, 32),
  M_UINT               (Packet_Cell_Change_Failure_t, ARFCN_v, 10),
  M_UINT               (Packet_Cell_Change_Failure_t, BSIC_v, 6),
  M_UINT               (Packet_Cell_Change_Failure_t, CAUSE_v, 4),

  M_NEXT_EXIST_OR_NULL (Packet_Cell_Change_Failure_t, Exist_AdditionsR99, 1),
  M_TYPE               (Packet_Cell_Change_Failure_t, AdditionsR99, PCCF_AdditionsR99_t),
CSN_DESCR_END          (Packet_Cell_Change_Failure_t)

/*< Packet Uplink Ack/Nack message content > */
static const
CSN_DESCR_BEGIN(Power_Control_Parameters_t)
  M_UINT       (Power_Control_Parameters_t, ALPHA_v, 4),

  M_NEXT_EXIST (Power_Control_Parameters_t, Slot[0].Exist, 1),
  M_UINT       (Power_Control_Parameters_t, Slot[0].GAMMA_TN_v, 5),

  M_NEXT_EXIST (Power_Control_Parameters_t, Slot[1].Exist, 1),
  M_UINT       (Power_Control_Parameters_t, Slot[1].GAMMA_TN_v, 5),

  M_NEXT_EXIST (Power_Control_Parameters_t, Slot[2].Exist, 1),
  M_UINT       (Power_Control_Parameters_t, Slot[2].GAMMA_TN_v, 5),

  M_NEXT_EXIST (Power_Control_Parameters_t, Slot[3].Exist, 1),
  M_UINT       (Power_Control_Parameters_t, Slot[3].GAMMA_TN_v, 5),

  M_NEXT_EXIST (Power_Control_Parameters_t, Slot[4].Exist, 1),
  M_UINT       (Power_Control_Parameters_t, Slot[4].GAMMA_TN_v, 5),

  M_NEXT_EXIST (Power_Control_Parameters_t, Slot[5].Exist, 1),
  M_UINT       (Power_Control_Parameters_t, Slot[5].GAMMA_TN_v, 5),

  M_NEXT_EXIST (Power_Control_Parameters_t, Slot[6].Exist, 1),
  M_UINT       (Power_Control_Parameters_t, Slot[6].GAMMA_TN_v, 5),

  M_NEXT_EXIST (Power_Control_Parameters_t, Slot[7].Exist, 1),
  M_UINT       (Power_Control_Parameters_t, Slot[7].GAMMA_TN_v, 5),
CSN_DESCR_END  (Power_Control_Parameters_t)

static const
CSN_DESCR_BEGIN(PU_AckNack_GPRS_AdditionsR99_t)
  M_NEXT_EXIST (PU_AckNack_GPRS_AdditionsR99_t, Exist_PacketExtendedTimingAdvance, 1),
  M_UINT       (PU_AckNack_GPRS_AdditionsR99_t, PacketExtendedTimingAdvance, 2),

  M_UINT       (PU_AckNack_GPRS_AdditionsR99_t, TBF_EST_v, 1),
CSN_DESCR_END  (PU_AckNack_GPRS_AdditionsR99_t)

static const
CSN_DESCR_BEGIN       (PU_AckNack_GPRS_t)
  M_UINT              (PU_AckNack_GPRS_t, CHANNEL_CODING_COMMAND_v, 2),
  M_TYPE              (PU_AckNack_GPRS_t, Ack_Nack_Description, Ack_Nack_Description_t),

  M_NEXT_EXIST        (PU_AckNack_GPRS_t, Common_Uplink_Ack_Nack_Data.Exist_CONTENTION_RESOLUTION_TLLI_v, 1),
  M_UINT              (PU_AckNack_GPRS_t, Common_Uplink_Ack_Nack_Data.CONTENTION_RESOLUTION_TLLI_v, 32),

  M_NEXT_EXIST        (PU_AckNack_GPRS_t, Common_Uplink_Ack_Nack_Data.Exist_Packet_Timing_Advance, 1),
  M_TYPE              (PU_AckNack_GPRS_t, Common_Uplink_Ack_Nack_Data.Packet_Timing_Advance, Packet_Timing_Advance_t),

  M_NEXT_EXIST        (PU_AckNack_GPRS_t, Common_Uplink_Ack_Nack_Data.Exist_Power_Control_Parameters, 1),
  M_TYPE              (PU_AckNack_GPRS_t, Common_Uplink_Ack_Nack_Data.Power_Control_Parameters, Power_Control_Parameters_t),

  M_NEXT_EXIST        (PU_AckNack_GPRS_t, Common_Uplink_Ack_Nack_Data.Exist_Extension_Bits, 1),
  M_TYPE              (PU_AckNack_GPRS_t, Common_Uplink_Ack_Nack_Data.Extension_Bits, Extension_Bits_t),

  M_UNION             (PU_AckNack_GPRS_t, 2), /* Fixed Allocation was removed */
  M_UINT              (PU_AckNack_GPRS_t, u.FixedAllocationDummy, 1),
  CSN_ERROR           (PU_AckNack_GPRS_t, "01 <Fixed Allocation>", CSN_ERROR_STREAM_NOT_SUPPORTED),

  M_NEXT_EXIST_OR_NULL(PU_AckNack_GPRS_t, Exist_AdditionsR99, 1),
  M_TYPE              (PU_AckNack_GPRS_t, AdditionsR99, PU_AckNack_GPRS_AdditionsR99_t),
CSN_DESCR_END         (PU_AckNack_GPRS_t)

static const
CSN_DESCR_BEGIN(PU_AckNack_EGPRS_00_t)
  M_UINT       (PU_AckNack_EGPRS_00_t, EGPRS_ChannelCodingCommand, 4),
  M_UINT       (PU_AckNack_EGPRS_00_t, RESEGMENT_v, 1),
  M_UINT       (PU_AckNack_EGPRS_00_t, PRE_EMPTIVE_TRANSMISSION_v, 1),
  M_UINT       (PU_AckNack_EGPRS_00_t, PRR_RETRANSMISSION_REQUEST_v, 1),
  M_UINT       (PU_AckNack_EGPRS_00_t, ARAC_RETRANSMISSION_REQUEST_v, 1),

  M_NEXT_EXIST (PU_AckNack_EGPRS_00_t, Common_Uplink_Ack_Nack_Data.Exist_CONTENTION_RESOLUTION_TLLI_v, 1),
  M_UINT       (PU_AckNack_EGPRS_00_t, Common_Uplink_Ack_Nack_Data.CONTENTION_RESOLUTION_TLLI_v, 32),

  M_UINT       (PU_AckNack_EGPRS_00_t, TBF_EST_v, 1),

  M_NEXT_EXIST (PU_AckNack_EGPRS_00_t, Common_Uplink_Ack_Nack_Data.Exist_Packet_Timing_Advance, 1),
  M_TYPE       (PU_AckNack_EGPRS_00_t, Common_Uplink_Ack_Nack_Data.Packet_Timing_Advance, Packet_Timing_Advance_t),

  M_NEXT_EXIST (PU_AckNack_EGPRS_00_t, Exist_Packet_Extended_Timing_Advance, 1),
  M_UINT       (PU_AckNack_EGPRS_00_t, Packet_Extended_Timing_Advance, 2),

  M_NEXT_EXIST (PU_AckNack_EGPRS_00_t, Common_Uplink_Ack_Nack_Data.Exist_Power_Control_Parameters, 1),
  M_TYPE       (PU_AckNack_EGPRS_00_t, Common_Uplink_Ack_Nack_Data.Power_Control_Parameters, Power_Control_Parameters_t),

  M_NEXT_EXIST (PU_AckNack_EGPRS_00_t, Common_Uplink_Ack_Nack_Data.Exist_Extension_Bits, 1),
  M_TYPE       (PU_AckNack_EGPRS_00_t, Common_Uplink_Ack_Nack_Data.Extension_Bits, Extension_Bits_t),

  M_TYPE       (PU_AckNack_EGPRS_00_t, EGPRS_AckNack, EGPRS_AckNack_t),
/*  M_CALLBACK   (PU_AckNack_EGPRS_00_t, (void*)24, EGPRS_AckNack, EGPRS_AckNack),  */
  M_LEFT_VAR_BMP (PU_AckNack_EGPRS_00_t, EGPRS_AckNack.URBB_v, EGPRS_AckNack.URBB_LENGTH_v, 0),
CSN_DESCR_END  (PU_AckNack_EGPRS_00_t)

static const
CSN_DESCR_BEGIN(PU_AckNack_EGPRS_t)
/*  M_CALLBACK   (PU_AckNack_EGPRS_t, (void*)21, IsSupported, IsSupported), */
  M_UNION      (PU_AckNack_EGPRS_t, 4),
  M_TYPE       (PU_AckNack_EGPRS_t, u.PU_AckNack_EGPRS_00, PU_AckNack_EGPRS_00_t),
  CSN_ERROR    (PU_AckNack_EGPRS_t, "01 <PU_AckNack_EGPRS>", CSN_ERROR_STREAM_NOT_SUPPORTED),
  CSN_ERROR    (PU_AckNack_EGPRS_t, "10 <PU_AckNack_EGPRS>", CSN_ERROR_STREAM_NOT_SUPPORTED),
  CSN_ERROR    (PU_AckNack_EGPRS_t, "11 <PU_AckNack_EGPRS>", CSN_ERROR_STREAM_NOT_SUPPORTED),
CSN_DESCR_END  (PU_AckNack_EGPRS_t)

static const
CSN_DESCR_BEGIN(Packet_Uplink_Ack_Nack_t)
  M_UINT       (Packet_Uplink_Ack_Nack_t, MESSAGE_TYPE_v, 6),
  M_UINT       (Packet_Uplink_Ack_Nack_t, PAGE_MODE_v, 2),
  M_FIXED      (Packet_Uplink_Ack_Nack_t, 2, 0x00),
  M_UINT       (Packet_Uplink_Ack_Nack_t, UPLINK_TFI_v, 5),

  M_UNION      (Packet_Uplink_Ack_Nack_t, 2),
  M_TYPE       (Packet_Uplink_Ack_Nack_t, u.PU_AckNack_GPRS_Struct, PU_AckNack_GPRS_t),
  M_TYPE       (Packet_Uplink_Ack_Nack_t, u.PU_AckNack_EGPRS_Struct, PU_AckNack_EGPRS_t),
CSN_DESCR_END  (Packet_Uplink_Ack_Nack_t)

/*< Packet Uplink Assignment message content > */
static const
CSN_DESCR_BEGIN(CHANGE_MARK_t)
  M_UINT       (CHANGE_MARK_t, CHANGE_MARK_1, 2),

  M_NEXT_EXIST (CHANGE_MARK_t, Exist_CHANGE_MARK_2, 1),
  M_UINT       (CHANGE_MARK_t, CHANGE_MARK_2, 2),
CSN_DESCR_END  (CHANGE_MARK_t)

static const
CSN_DESCR_BEGIN(Indirect_encoding_t)
  M_UINT       (Indirect_encoding_t, MAIO_v, 6),
  M_UINT       (Indirect_encoding_t, MA_NUMBER_v, 4),

  M_NEXT_EXIST (Indirect_encoding_t, Exist_CHANGE_MARK, 1),
  M_TYPE       (Indirect_encoding_t, CHANGE_MARK, CHANGE_MARK_t),
CSN_DESCR_END  (Indirect_encoding_t)

static const
CSN_DESCR_BEGIN(Direct_encoding_1_t)
  M_UINT       (Direct_encoding_1_t, MAIO_v, 6),
  M_TYPE       (Direct_encoding_1_t, GPRS_Mobile_Allocation, GPRS_Mobile_Allocation_t),
CSN_DESCR_END  (Direct_encoding_1_t)

static const
CSN_DESCR_BEGIN(Direct_encoding_2_t)
  M_UINT       (Direct_encoding_2_t, MAIO_v, 6),
  M_UINT       (Direct_encoding_2_t, HSN_v, 6),
  M_UINT_OFFSET(Direct_encoding_2_t, Length_of_MA_Frequency_List, 4, 3),
  M_VAR_ARRAY  (Direct_encoding_2_t, MA_Frequency_List, Length_of_MA_Frequency_List, 0),
CSN_DESCR_END  (Direct_encoding_2_t)

static const
CSN_DESCR_BEGIN(Frequency_Parameters_t)
  M_UINT       (Frequency_Parameters_t, TSC_v, 3),

  M_UNION      (Frequency_Parameters_t, 4),
  M_UINT       (Frequency_Parameters_t, u.ARFCN_v, 10),
  M_TYPE       (Frequency_Parameters_t, u.Indirect_encoding, Indirect_encoding_t),
  M_TYPE       (Frequency_Parameters_t, u.Direct_encoding_1, Direct_encoding_1_t),
  M_TYPE       (Frequency_Parameters_t, u.Direct_encoding_2, Direct_encoding_2_t),
CSN_DESCR_END  (Frequency_Parameters_t)

static const
CSN_DESCR_BEGIN(Packet_Request_Reference_t)
  M_UINT       (Packet_Request_Reference_t, RANDOM_ACCESS_INFORMATION_v, 11),
  M_UINT_ARRAY (Packet_Request_Reference_t, FRAME_NUMBER_v, 8, 2),
CSN_DESCR_END  (Packet_Request_Reference_t)

static const
CSN_DESCR_BEGIN(Timeslot_Allocation_t)
  M_NEXT_EXIST (Timeslot_Allocation_t, Exist, 1),
  M_UINT       (Timeslot_Allocation_t, USF_TN_v, 3),
CSN_DESCR_END  (Timeslot_Allocation_t)

static const
CSN_DESCR_BEGIN(Timeslot_Allocation_Power_Ctrl_Param_t)
  M_UINT       (Timeslot_Allocation_Power_Ctrl_Param_t, ALPHA_v, 4),

  M_NEXT_EXIST (Timeslot_Allocation_Power_Ctrl_Param_t, Slot[0].Exist, 2),
  M_UINT       (Timeslot_Allocation_Power_Ctrl_Param_t, Slot[0].USF_TN_v, 3),
  M_UINT       (Timeslot_Allocation_Power_Ctrl_Param_t, Slot[0].GAMMA_TN_v, 5),

  M_NEXT_EXIST (Timeslot_Allocation_Power_Ctrl_Param_t, Slot[1].Exist, 2),
  M_UINT       (Timeslot_Allocation_Power_Ctrl_Param_t, Slot[1].USF_TN_v, 3),
  M_UINT       (Timeslot_Allocation_Power_Ctrl_Param_t, Slot[1].GAMMA_TN_v, 5),

  M_NEXT_EXIST (Timeslot_Allocation_Power_Ctrl_Param_t, Slot[2].Exist, 2),
  M_UINT       (Timeslot_Allocation_Power_Ctrl_Param_t, Slot[2].USF_TN_v, 3),
  M_UINT       (Timeslot_Allocation_Power_Ctrl_Param_t, Slot[2].GAMMA_TN_v, 5),

  M_NEXT_EXIST (Timeslot_Allocation_Power_Ctrl_Param_t, Slot[3].Exist, 2),
  M_UINT       (Timeslot_Allocation_Power_Ctrl_Param_t, Slot[3].USF_TN_v, 3),
  M_UINT       (Timeslot_Allocation_Power_Ctrl_Param_t, Slot[3].GAMMA_TN_v, 5),

  M_NEXT_EXIST (Timeslot_Allocation_Power_Ctrl_Param_t, Slot[4].Exist, 2),
  M_UINT       (Timeslot_Allocation_Power_Ctrl_Param_t, Slot[4].USF_TN_v, 3),
  M_UINT       (Timeslot_Allocation_Power_Ctrl_Param_t, Slot[4].GAMMA_TN_v, 5),

  M_NEXT_EXIST (Timeslot_Allocation_Power_Ctrl_Param_t, Slot[5].Exist, 2),
  M_UINT       (Timeslot_Allocation_Power_Ctrl_Param_t, Slot[5].USF_TN_v, 3),
  M_UINT       (Timeslot_Allocation_Power_Ctrl_Param_t, Slot[5].GAMMA_TN_v, 5),

  M_NEXT_EXIST (Timeslot_Allocation_Power_Ctrl_Param_t, Slot[6].Exist, 2),
  M_UINT       (Timeslot_Allocation_Power_Ctrl_Param_t, Slot[6].USF_TN_v, 3),
  M_UINT       (Timeslot_Allocation_Power_Ctrl_Param_t, Slot[6].GAMMA_TN_v, 5),

  M_NEXT_EXIST (Timeslot_Allocation_Power_Ctrl_Param_t, Slot[7].Exist, 2),
  M_UINT       (Timeslot_Allocation_Power_Ctrl_Param_t, Slot[7].USF_TN_v, 3),
  M_UINT       (Timeslot_Allocation_Power_Ctrl_Param_t, Slot[7].GAMMA_TN_v, 5),
CSN_DESCR_END  (Timeslot_Allocation_Power_Ctrl_Param_t)

/* USED in <Packet Uplink Assignment message content> */
static const
CSN_DESCR_BEGIN(Dynamic_Allocation_t)
  M_UINT       (Dynamic_Allocation_t, Extended_Dynamic_Allocation, 1),

  M_NEXT_EXIST (Dynamic_Allocation_t, Exist_P0, 2),
  M_UINT       (Dynamic_Allocation_t, P0, 4),
  M_UINT       (Dynamic_Allocation_t, PR_MODE, 1),

  M_UINT       (Dynamic_Allocation_t, USF_GRANULARITY_v, 1),

  M_NEXT_EXIST (Dynamic_Allocation_t, Exist_UPLINK_TFI_ASSIGNMENT_v, 1),
  M_UINT       (Dynamic_Allocation_t, UPLINK_TFI_ASSIGNMENT_v, 5),

  M_NEXT_EXIST (Dynamic_Allocation_t, Exist_RLC_DATA_BLOCKS_GRANTED_v, 1),
  M_UINT       (Dynamic_Allocation_t, RLC_DATA_BLOCKS_GRANTED_v, 8),

  M_NEXT_EXIST (Dynamic_Allocation_t, Exist_TBF_Starting_Time, 1),
  M_TYPE       (Dynamic_Allocation_t, TBF_Starting_Time, Starting_Frame_Number_t),

  M_UNION      (Dynamic_Allocation_t, 2),
  M_TYPE_ARRAY (Dynamic_Allocation_t, u.Timeslot_Allocation, Timeslot_Allocation_t, 8),
  M_TYPE       (Dynamic_Allocation_t, u.Timeslot_Allocation_Power_Ctrl_Param, Timeslot_Allocation_Power_Ctrl_Param_t),
CSN_DESCR_END  (Dynamic_Allocation_t)

static const
CSN_DESCR_BEGIN(Single_Block_Allocation_t)
  M_UINT       (Single_Block_Allocation_t, TIMESLOT_NUMBER_v, 3),

  M_NEXT_EXIST (Single_Block_Allocation_t, Exist_ALPHA_and_GAMMA_TN, 2),
  M_UINT       (Single_Block_Allocation_t, ALPHA_v, 4),
  M_UINT       (Single_Block_Allocation_t, GAMMA_TN_v, 5),

  M_NEXT_EXIST (Single_Block_Allocation_t, Exist_P0, 3),
  M_UINT       (Single_Block_Allocation_t, P0, 4),
  M_UINT       (Single_Block_Allocation_t, BTS_PWR_CTRL_MODE, 1),
  M_UINT       (Single_Block_Allocation_t, PR_MODE, 1),

  M_TYPE       (Single_Block_Allocation_t, TBF_Starting_Time, Starting_Frame_Number_t),
CSN_DESCR_END  (Single_Block_Allocation_t)

static const
CSN_DESCR_BEGIN(DTM_Dynamic_Allocation_t)
  M_UINT       (DTM_Dynamic_Allocation_t, Extended_Dynamic_Allocation, 1),

  M_NEXT_EXIST (DTM_Dynamic_Allocation_t, Exist_P0, 2),
  M_UINT       (DTM_Dynamic_Allocation_t, P0, 4),
  M_UINT       (DTM_Dynamic_Allocation_t, PR_MODE, 1),

  M_UINT       (DTM_Dynamic_Allocation_t, USF_GRANULARITY_v, 1),

  M_NEXT_EXIST (DTM_Dynamic_Allocation_t, Exist_UPLINK_TFI_ASSIGNMENT_v, 1),
  M_UINT       (DTM_Dynamic_Allocation_t, UPLINK_TFI_ASSIGNMENT_v, 5),

  M_NEXT_EXIST (DTM_Dynamic_Allocation_t, Exist_RLC_DATA_BLOCKS_GRANTED_v, 1),
  M_UINT       (DTM_Dynamic_Allocation_t, RLC_DATA_BLOCKS_GRANTED_v, 8),

  M_UNION      (DTM_Dynamic_Allocation_t, 2),
  M_TYPE_ARRAY (DTM_Dynamic_Allocation_t, u.Timeslot_Allocation, Timeslot_Allocation_t, 8),
  M_TYPE       (DTM_Dynamic_Allocation_t, u.Timeslot_Allocation_Power_Ctrl_Param, Timeslot_Allocation_Power_Ctrl_Param_t),
CSN_DESCR_END  (DTM_Dynamic_Allocation_t)

static const
CSN_DESCR_BEGIN(DTM_Single_Block_Allocation_t)
  M_UINT       (DTM_Single_Block_Allocation_t, TIMESLOT_NUMBER_v, 3),

  M_NEXT_EXIST (DTM_Single_Block_Allocation_t, Exist_ALPHA_and_GAMMA_TN, 2),
  M_UINT       (DTM_Single_Block_Allocation_t, ALPHA_v, 4),
  M_UINT       (DTM_Single_Block_Allocation_t, GAMMA_TN_v, 5),

  M_NEXT_EXIST (DTM_Single_Block_Allocation_t, Exist_P0, 3),
  M_UINT       (DTM_Single_Block_Allocation_t, P0, 4),
  M_UINT       (DTM_Single_Block_Allocation_t, BTS_PWR_CTRL_MODE, 1),
  M_UINT       (DTM_Single_Block_Allocation_t, PR_MODE, 1),
CSN_DESCR_END  (DTM_Single_Block_Allocation_t)


/* Help structures */
typedef struct
{
  Global_TFI_t Global_TFI;  /* 0  < Global TFI : < Global TFI IE > > */
} h0_Global_TFI_t;

static const
CSN_DESCR_BEGIN(h0_Global_TFI_t)
  M_FIXED      (h0_Global_TFI_t, 1, 0x00),
  M_TYPE       (h0_Global_TFI_t, Global_TFI, Global_TFI_t),
CSN_DESCR_END  (h0_Global_TFI_t)

typedef struct
{
  guint32 TLLI_v;/* | 10  < TLLI : bit (32) >*/
} h10_TLLI_t;

static const
CSN_DESCR_BEGIN(h10_TLLI_t)
  M_FIXED      (h10_TLLI_t, 2, 0x02),
  M_UINT       (h10_TLLI_t, TLLI_v, 32),
CSN_DESCR_END (h10_TLLI_t)

typedef struct
{
  guint16 TQI_v;/*| 110  < TQI : bit (16) > */
} h110_TQI_t;

static const
CSN_DESCR_BEGIN(h110_TQI_t)
  M_FIXED      (h110_TQI_t, 3, 0x06),
  M_UINT       (h110_TQI_t, TQI_v, 16),
CSN_DESCR_END  (h110_TQI_t)

typedef struct
{
  Packet_Request_Reference_t Packet_Request_Reference;/*| 111  < Packet Request Reference : < Packet Request Reference IE > > }*/
} h111_Packet_Request_Reference_t;

static const
CSN_DESCR_BEGIN(h111_Packet_Request_Reference_t)
  M_FIXED      (h111_Packet_Request_Reference_t, 3, 0x07),
  M_TYPE       (h111_Packet_Request_Reference_t, Packet_Request_Reference, Packet_Request_Reference_t),
CSN_DESCR_END  (h111_Packet_Request_Reference_t)

static const
CSN_ChoiceElement_t PacketUplinkID[] =
{
  {1, 0 ,    M_TYPE(PacketUplinkID_t, u.Global_TFI, Global_TFI_t)},
  {2, 0x02 , M_UINT(PacketUplinkID_t, u.TLLI_v, 32)},
  {3, 0x06 , M_UINT(PacketUplinkID_t, u.TQI_v, 16)},
  {3, 0x07 , M_TYPE(PacketUplinkID_t, u.Packet_Request_Reference, Packet_Request_Reference_t)},
};

static const
CSN_DESCR_BEGIN(PacketUplinkID_t)
  M_CHOICE     (PacketUplinkID_t, UnionType, PacketUplinkID, ElementsOf(PacketUplinkID)),
CSN_DESCR_END  (PacketUplinkID_t)

static const
CSN_DESCR_BEGIN(PUA_GPRS_AdditionsR99_t)
  M_NEXT_EXIST (PUA_GPRS_AdditionsR99_t, Exist_Packet_Extended_Timing_Advance, 1),
  M_UINT       (PUA_GPRS_AdditionsR99_t, Packet_Extended_Timing_Advance, 2),
CSN_DESCR_END  (PUA_GPRS_AdditionsR99_t)

static const
CSN_DESCR_BEGIN       (PUA_GPRS_t)
  M_UINT              (PUA_GPRS_t, CHANNEL_CODING_COMMAND_v, 2),
  M_BIT               (PUA_GPRS_t, TLLI_BLOCK_CHANNEL_CODING_v),
  M_TYPE              (PUA_GPRS_t, Packet_Timing_Advance, Packet_Timing_Advance_t),

  M_NEXT_EXIST        (PUA_GPRS_t, Exist_Frequency_Parameters, 1),
  M_TYPE              (PUA_GPRS_t, Frequency_Parameters, Frequency_Parameters_t),

  M_UNION             (PUA_GPRS_t, 4),
  CSN_ERROR           (PUA_GPRS_t, "00 <extension> not implemented", CSN_ERROR_STREAM_NOT_SUPPORTED),
  M_TYPE              (PUA_GPRS_t, u.Dynamic_Allocation, Dynamic_Allocation_t),
  M_TYPE              (PUA_GPRS_t, u.Single_Block_Allocation, Single_Block_Allocation_t),
  CSN_ERROR           (PUA_GPRS_t, "11 <Fixed Allocation> not supported", CSN_ERROR_STREAM_NOT_SUPPORTED),

  M_NEXT_EXIST_OR_NULL(PUA_GPRS_t, Exist_AdditionsR99, 1),
  M_TYPE              (PUA_GPRS_t, AdditionsR99, PUA_GPRS_AdditionsR99_t),
CSN_DESCR_END         (PUA_GPRS_t)

static const
CSN_DESCR_BEGIN(COMPACT_ReducedMA_t)
  M_UINT       (COMPACT_ReducedMA_t, BitmapLength, 7),
  M_VAR_BITMAP (COMPACT_ReducedMA_t, ReducedMA_Bitmap, BitmapLength, 0),

  M_NEXT_EXIST (COMPACT_ReducedMA_t, Exist_MAIO_2_v, 1),
  M_UINT       (COMPACT_ReducedMA_t, MAIO_2_v, 6),
CSN_DESCR_END  (COMPACT_TeducedMA_t)

static const
CSN_DESCR_BEGIN(MultiBlock_Allocation_t)
  M_UINT       (MultiBlock_Allocation_t, TIMESLOT_NUMBER_v, 3),

  M_NEXT_EXIST (MultiBlock_Allocation_t, Exist_ALPHA_GAMMA_TN_v, 2),
  M_UINT       (MultiBlock_Allocation_t, ALPHA_v, 4),
  M_UINT       (MultiBlock_Allocation_t, GAMMA_TN_v, 5),

  M_NEXT_EXIST (MultiBlock_Allocation_t, Exist_P0_BTS_PWR_CTRL_PR_MODE, 3),
  M_UINT       (MultiBlock_Allocation_t, P0_v, 4),
  M_UINT       (MultiBlock_Allocation_t, BTS_PWR_CTRL_MODE_v, 1),
  M_UINT       (MultiBlock_Allocation_t, PR_MODE_v, 1),

  M_TYPE       (MultiBlock_Allocation_t, TBF_Starting_Time, Starting_Frame_Number_t),
  M_UINT       (MultiBlock_Allocation_t, NUMBER_OF_RADIO_BLOCKS_ALLOCATED_v, 2),
CSN_DESCR_END  (MultiBlock_Allocation_t)

static const
CSN_DESCR_BEGIN (PUA_EGPRS_00_t)
  M_NEXT_EXIST  (PUA_EGPRS_00_t, Exist_CONTENTION_RESOLUTION_TLLI_v, 1),
  M_UINT        (PUA_EGPRS_00_t, CONTENTION_RESOLUTION_TLLI_v, 32),

  M_NEXT_EXIST  (PUA_EGPRS_00_t, Exist_COMPACT_ReducedMA, 1),
  M_TYPE        (PUA_EGPRS_00_t, COMPACT_ReducedMA, COMPACT_ReducedMA_t),

  M_UINT        (PUA_EGPRS_00_t, EGPRS_CHANNEL_CODING_COMMAND_v, 4),
  M_UINT        (PUA_EGPRS_00_t, RESEGMENT_v, 1),
  M_UINT        (PUA_EGPRS_00_t, EGPRS_WindowSize, 5),

  M_REC_ARRAY   (PUA_EGPRS_00_t, AccessTechnologyType, NrOfAccessTechnologies, 4),

  M_UINT        (PUA_EGPRS_00_t, ARAC_RETRANSMISSION_REQUEST_v, 1),
  M_UINT        (PUA_EGPRS_00_t, TLLI_BLOCK_CHANNEL_CODING_v, 1),

  M_NEXT_EXIST  (PUA_EGPRS_00_t, Exist_BEP_PERIOD2_v, 1),
  M_UINT        (PUA_EGPRS_00_t, BEP_PERIOD2_v, 4),

  M_TYPE        (PUA_EGPRS_00_t, PacketTimingAdvance, Packet_Timing_Advance_t),

  M_NEXT_EXIST  (PUA_EGPRS_00_t, Exist_Packet_Extended_Timing_Advance, 1),
  M_UINT        (PUA_EGPRS_00_t, Packet_Extended_Timing_Advance, 2),

  M_NEXT_EXIST  (PUA_EGPRS_00_t, Exist_Frequency_Parameters, 1),
  M_TYPE        (PUA_EGPRS_00_t, Frequency_Parameters, Frequency_Parameters_t),

  M_UNION       (PUA_EGPRS_00_t, 4),
  CSN_ERROR     (PUA_EGPRS_00_t, "00 <extension>", CSN_ERROR_STREAM_NOT_SUPPORTED),
  M_TYPE        (PUA_EGPRS_00_t, u.Dynamic_Allocation, Dynamic_Allocation_t),
  M_TYPE        (PUA_EGPRS_00_t, u.MultiBlock_Allocation, MultiBlock_Allocation_t),
  CSN_ERROR     (PUA_EGPRS_00_t, "11 <Fixed Allocation>", CSN_ERROR_STREAM_NOT_SUPPORTED),
CSN_DESCR_END   (PUA_EGPRS_00_t)

static const
CSN_DESCR_BEGIN(PUA_EGPRS_t)
  M_UNION      (PUA_EGPRS_t, 4),
  M_TYPE       (PUA_EGPRS_t, u.PUA_EGPRS_00, PUA_EGPRS_00_t),
  CSN_ERROR    (PUA_EGPRS_t, "01 <PUA EGPRS>", CSN_ERROR_STREAM_NOT_SUPPORTED),
  CSN_ERROR    (PUA_EGPRS_t, "10 <PUA EGPRS>", CSN_ERROR_STREAM_NOT_SUPPORTED),
  CSN_ERROR    (PUA_EGPRS_t, "11 <PUA EGPRS>", CSN_ERROR_STREAM_NOT_SUPPORTED),
CSN_DESCR_END  (PUA_EGPRS_t)

static const
CSN_DESCR_BEGIN(Packet_Uplink_Assignment_t)
  M_UINT       (Packet_Uplink_Assignment_t, MESSAGE_TYPE_v, 6),
  M_UINT       (Packet_Uplink_Assignment_t, PAGE_MODE_v, 2),

  M_NEXT_EXIST (Packet_Uplink_Assignment_t, Exist_PERSISTENCE_LEVEL_v, 1),
  M_UINT_ARRAY (Packet_Uplink_Assignment_t, PERSISTENCE_LEVEL_v, 4, 4),

  M_TYPE       (Packet_Uplink_Assignment_t, ID, PacketUplinkID_t),

  M_UNION      (Packet_Uplink_Assignment_t, 2),
  M_TYPE       (Packet_Uplink_Assignment_t, u.PUA_GPRS_Struct, PUA_GPRS_t),
  M_TYPE       (Packet_Uplink_Assignment_t, u.PUA_EGPRS_Struct, PUA_EGPRS_t),
CSN_DESCR_END  (Packet_Uplink_Assignment_t)

typedef Packet_Uplink_Assignment_t pulassCheck_t;

static const
CSN_DESCR_BEGIN(pulassCheck_t)
  M_UINT       (pulassCheck_t, MESSAGE_TYPE_v, 6),
  M_UINT       (pulassCheck_t, PAGE_MODE_v, 2),

  M_NEXT_EXIST (pulassCheck_t, Exist_PERSISTENCE_LEVEL_v, 1),
  M_UINT_ARRAY (pulassCheck_t, PERSISTENCE_LEVEL_v, 4, 4),

  M_TYPE       (pulassCheck_t, ID, PacketUplinkID_t),
CSN_DESCR_END  (pulassCheck_t)

/*< Packet Downlink Assignment message content > */
static const
CSN_DESCR_BEGIN(Measurement_Mapping_struct_t)
  M_TYPE       (Measurement_Mapping_struct_t, Measurement_Starting_Time, Starting_Frame_Number_t),
  M_UINT       (Measurement_Mapping_struct_t, MEASUREMENT_INTERVAL_v, 5),
  M_UINT       (Measurement_Mapping_struct_t, MEASUREMENT_BITMAP_v, 8),
CSN_DESCR_END  (Measurement_Mapping_struct_t)

static const
CSN_ChoiceElement_t PacketDownlinkID[] =
{
  {1,    0, M_TYPE(PacketDownlinkID_t, u.Global_TFI, Global_TFI_t)},
  {2, 0x02, M_UINT(PacketDownlinkID_t, u.TLLI_v, 32)},
};

static const
CSN_DESCR_BEGIN(PacketDownlinkID_t)
  M_CHOICE     (PacketDownlinkID_t, UnionType, PacketDownlinkID, ElementsOf(PacketDownlinkID)),
CSN_DESCR_END  (PacketDownlinkID_t)

static const
CSN_DESCR_BEGIN(PDA_AdditionsR99_t)
  M_NEXT_EXIST (PDA_AdditionsR99_t, Exist_EGPRS_Params, 4), /*if Exist_EGPRS_Params == FALSE then none of the following 4 vars exist */
  M_UINT       (PDA_AdditionsR99_t, EGPRS_WindowSize, 5),
  M_UINT       (PDA_AdditionsR99_t, LINK_QUALITY_MEASUREMENT_MODE_v, 2),
  M_NEXT_EXIST (PDA_AdditionsR99_t, Exist_BEP_PERIOD2_v, 1),
  M_UINT       (PDA_AdditionsR99_t, BEP_PERIOD2_v, 4),

  M_NEXT_EXIST (PDA_AdditionsR99_t, Exist_Packet_Extended_Timing_Advance, 1),
  M_UINT       (PDA_AdditionsR99_t, Packet_Extended_Timing_Advance, 2),

  M_NEXT_EXIST (PDA_AdditionsR99_t, Exist_COMPACT_ReducedMA, 1),
  M_TYPE       (PDA_AdditionsR99_t, COMPACT_ReducedMA, COMPACT_ReducedMA_t),
CSN_DESCR_END  (PDA_AdditionsR99_t)

static const
CSN_DESCR_BEGIN       (Packet_Downlink_Assignment_t)
  M_UINT              (Packet_Downlink_Assignment_t, MESSAGE_TYPE_v, 6),
  M_UINT              (Packet_Downlink_Assignment_t, PAGE_MODE_v, 2),

  M_NEXT_EXIST        (Packet_Downlink_Assignment_t, Exist_PERSISTENCE_LEVEL_v, 1),
  M_UINT_ARRAY        (Packet_Downlink_Assignment_t, PERSISTENCE_LEVEL_v, 4, 4),

  M_TYPE              (Packet_Downlink_Assignment_t, ID, PacketDownlinkID_t),

  M_FIXED             (Packet_Downlink_Assignment_t, 1, 0x00),/*-- Message escape */

  M_UINT              (Packet_Downlink_Assignment_t, MAC_MODE_v, 2),
  M_BIT               (Packet_Downlink_Assignment_t, RLC_MODE_v),
  M_BIT               (Packet_Downlink_Assignment_t, CONTROL_ACK_v),
  M_UINT              (Packet_Downlink_Assignment_t, TIMESLOT_ALLOCATION_v, 8),
  M_TYPE              (Packet_Downlink_Assignment_t, Packet_Timing_Advance, Packet_Timing_Advance_t),

  M_NEXT_EXIST        (Packet_Downlink_Assignment_t, Exist_P0_and_BTS_PWR_CTRL_MODE_v, 3),
  M_UINT              (Packet_Downlink_Assignment_t, P0_v, 4),
  M_BIT               (Packet_Downlink_Assignment_t, BTS_PWR_CTRL_MODE_v),
  M_UINT              (Packet_Downlink_Assignment_t, PR_MODE, 1),

  M_NEXT_EXIST        (Packet_Downlink_Assignment_t, Exist_Frequency_Parameters, 1),
  M_TYPE              (Packet_Downlink_Assignment_t, Frequency_Parameters, Frequency_Parameters_t),

  M_NEXT_EXIST        (Packet_Downlink_Assignment_t, Exist_DOWNLINK_TFI_ASSIGNMENT_v, 1),
  M_UINT              (Packet_Downlink_Assignment_t, DOWNLINK_TFI_ASSIGNMENT_v, 5),

  M_NEXT_EXIST        (Packet_Downlink_Assignment_t, Exist_Power_Control_Parameters, 1),
  M_TYPE              (Packet_Downlink_Assignment_t, Power_Control_Parameters, Power_Control_Parameters_t),

  M_NEXT_EXIST        (Packet_Downlink_Assignment_t, Exist_TBF_Starting_Time, 1),
  M_TYPE              (Packet_Downlink_Assignment_t, TBF_Starting_Time, Starting_Frame_Number_t),

  M_NEXT_EXIST        (Packet_Downlink_Assignment_t, Exist_Measurement_Mapping, 1),
  M_TYPE              (Packet_Downlink_Assignment_t, Measurement_Mapping, Measurement_Mapping_struct_t),

  M_NEXT_EXIST_OR_NULL(Packet_Downlink_Assignment_t, Exist_AdditionsR99, 1),
  M_TYPE              (Packet_Downlink_Assignment_t, AdditionsR99, PDA_AdditionsR99_t),
CSN_DESCR_END         (Packet_Downlink_Assignment_t)

typedef Packet_Downlink_Assignment_t pdlaCheck_t;

static const
CSN_DESCR_BEGIN(pdlaCheck_t)
  M_UINT       (pdlaCheck_t, MESSAGE_TYPE_v, 6),
  M_UINT       (pdlaCheck_t, PAGE_MODE_v, 2),

  M_NEXT_EXIST (pdlaCheck_t, Exist_PERSISTENCE_LEVEL_v, 1),
  M_UINT_ARRAY (pdlaCheck_t, PERSISTENCE_LEVEL_v, 4, 4),

  M_TYPE       (pdlaCheck_t, ID, PacketDownlinkID_t),
CSN_DESCR_END  (pdlaCheck_t)

/* DTM Packet UL Assignment */
static const
CSN_DESCR_BEGIN(DTM_Packet_Uplink_Assignment_t)
  M_UINT       (DTM_Packet_Uplink_Assignment_t, CHANNEL_CODING_COMMAND_v, 2),
  M_BIT        (DTM_Packet_Uplink_Assignment_t, TLLI_BLOCK_CHANNEL_CODING_v),
  M_TYPE       (DTM_Packet_Uplink_Assignment_t, Packet_Timing_Advance, Packet_Timing_Advance_t),

  M_UNION      (DTM_Packet_Uplink_Assignment_t, 3),
  CSN_ERROR    (DTM_Packet_Uplink_Assignment_t, "Not Implemented", CSN_ERROR_STREAM_NOT_SUPPORTED),
  M_TYPE       (DTM_Packet_Uplink_Assignment_t, u.DTM_Dynamic_Allocation, DTM_Dynamic_Allocation_t),
  M_TYPE       (DTM_Packet_Uplink_Assignment_t, u.DTM_Single_Block_Allocation, DTM_Single_Block_Allocation_t),
  M_NEXT_EXIST_OR_NULL  (DTM_Packet_Uplink_Assignment_t, Exist_EGPRS_Parameters, 3),
  M_UINT       (DTM_Packet_Uplink_Assignment_t, EGPRS_CHANNEL_CODING_COMMAND_v, 4),
  M_UINT       (DTM_Packet_Uplink_Assignment_t, RESEGMENT_v, 1),
  M_UINT       (DTM_Packet_Uplink_Assignment_t, EGPRS_WindowSize, 5),
  M_NEXT_EXIST (DTM_Packet_Uplink_Assignment_t, Exist_Packet_Extended_Timing_Advance, 1),
  M_UINT       (DTM_Packet_Uplink_Assignment_t, Packet_Extended_Timing_Advance, 2),
CSN_DESCR_END(DTM_Packet_Uplink_Assignment_t)

static const
CSN_DESCR_BEGIN(DTM_UL_t)
  M_TYPE       (DTM_UL_t, DTM_Packet_Uplink_Assignment, DTM_Packet_Uplink_Assignment_t),
CSN_DESCR_END(DTM_UL_t)

/* DTM Packet DL Assignment */
static const
CSN_DESCR_BEGIN(DTM_Packet_Downlink_Assignment_t)
  M_UINT       (DTM_Packet_Downlink_Assignment_t, MAC_MODE_v, 2),
  M_BIT        (DTM_Packet_Downlink_Assignment_t, RLC_MODE_v),
  M_UINT       (DTM_Packet_Downlink_Assignment_t, TIMESLOT_ALLOCATION_v, 8),
  M_TYPE       (DTM_Packet_Downlink_Assignment_t, Packet_Timing_Advance, Packet_Timing_Advance_t),

  M_NEXT_EXIST (DTM_Packet_Downlink_Assignment_t, Exist_P0_and_BTS_PWR_CTRL_MODE_v, 3),
  M_UINT       (DTM_Packet_Downlink_Assignment_t, P0_v, 4),
  M_BIT        (DTM_Packet_Downlink_Assignment_t, BTS_PWR_CTRL_MODE_v),
  M_UINT       (DTM_Packet_Downlink_Assignment_t, PR_MODE, 1),

  M_NEXT_EXIST (DTM_Packet_Downlink_Assignment_t, Exist_Power_Control_Parameters, 1),
  M_TYPE       (DTM_Packet_Downlink_Assignment_t, Power_Control_Parameters, Power_Control_Parameters_t),

  M_NEXT_EXIST (DTM_Packet_Downlink_Assignment_t, Exist_DOWNLINK_TFI_ASSIGNMENT_v, 1),
  M_UINT       (DTM_Packet_Downlink_Assignment_t, DOWNLINK_TFI_ASSIGNMENT_v, 5),

  M_NEXT_EXIST (DTM_Packet_Downlink_Assignment_t, Exist_Measurement_Mapping, 1),
  M_TYPE       (DTM_Packet_Downlink_Assignment_t, Measurement_Mapping, Measurement_Mapping_struct_t),
  M_NEXT_EXIST_OR_NULL  (DTM_Packet_Downlink_Assignment_t, EGPRS_Mode, 2),
  M_UINT       (DTM_Packet_Downlink_Assignment_t, EGPRS_WindowSize, 5),
  M_UINT       (DTM_Packet_Downlink_Assignment_t, LINK_QUALITY_MEASUREMENT_MODE_v, 2),
  M_NEXT_EXIST (DTM_Packet_Downlink_Assignment_t, Exist_Packet_Extended_Timing_Advance, 1),
  M_UINT       (DTM_Packet_Downlink_Assignment_t, Packet_Extended_Timing_Advance, 2),
CSN_DESCR_END(DTM_Packet_Downlink_Assignment_t)

static const
CSN_DESCR_BEGIN(DTM_DL_t)
  M_TYPE       (DTM_DL_t, DTM_Packet_Downlink_Assignment, DTM_Packet_Downlink_Assignment_t),
CSN_DESCR_END(DTM_DL_t)

/* GPRS Broadcast Information */
static const
CSN_DESCR_BEGIN(DTM_GPRS_Broadcast_Information_t)
  M_TYPE       (DTM_GPRS_Broadcast_Information_t, GPRS_Cell_Options, GPRS_Cell_Options_t),
  M_TYPE       (DTM_GPRS_Broadcast_Information_t, GPRS_Power_Control_Parameters, GPRS_Power_Control_Parameters_t),
CSN_DESCR_END(DTM_GPRS_Broadcast_Information_t)

static const
CSN_DESCR_BEGIN(DTM_GPRS_B_t)
  M_TYPE       (DTM_GPRS_B_t, DTM_GPRS_Broadcast_Information, DTM_GPRS_Broadcast_Information_t),
CSN_DESCR_END(DTM_GPRS_B_t)

static const
CSN_DESCR_BEGIN(DTM_Channel_Request_Description_t)
  M_UINT       (DTM_Channel_Request_Description_t, DTM_Pkt_Est_Cause, 2),
  M_TYPE       (DTM_Channel_Request_Description_t, Channel_Request_Description, Channel_Request_Description_t),
  M_NEXT_EXIST (DTM_Channel_Request_Description_t, Exist_PFI_v, 1),
  M_UINT       (DTM_Channel_Request_Description_t, PFI_v, 7),
CSN_DESCR_END(DTM_Channel_Request_Description_t)
/* DTM  */

/*< Packet Paging Request message content > */
typedef struct
{
  guint8 Length_of_Mobile_Identity_contents;/* bit (4) */
  guint8 Mobile_Identity[8];/* octet (val (Length of Mobile Identity contents)) */
} Mobile_Identity_t; /* helper */

static const
CSN_DESCR_BEGIN(Mobile_Identity_t)
  M_UINT       (Mobile_Identity_t, Length_of_Mobile_Identity_contents, 4),
  M_VAR_ARRAY  (Mobile_Identity_t, Mobile_Identity, Length_of_Mobile_Identity_contents, 0),
CSN_DESCR_END  (Mobile_Identity_t)

static const
CSN_DESCR_BEGIN(Page_request_for_TBF_establishment_t)
  M_UNION      (Page_request_for_TBF_establishment_t, 2),
  M_UINT_ARRAY (Page_request_for_TBF_establishment_t, u.PTMSI_v, 8, 4),/* bit (32) == 8*4 */
  M_TYPE       (Page_request_for_TBF_establishment_t, u.Mobile_Identity, Mobile_Identity_t),
CSN_DESCR_END  (Page_request_for_TBF_establishment_t)

static const
CSN_DESCR_BEGIN(Page_request_for_RR_conn_t)
  M_UNION      (Page_request_for_RR_conn_t, 2),
  M_UINT_ARRAY (Page_request_for_RR_conn_t, u.TMSI_v, 8, 4),/* bit (32) == 8*4 */
  M_TYPE       (Page_request_for_RR_conn_t, u.Mobile_Identity, Mobile_Identity_t),

  M_UINT       (Page_request_for_RR_conn_t, CHANNEL_NEEDED_v, 2),

  M_NEXT_EXIST (Page_request_for_RR_conn_t, Exist_eMLPP_PRIORITY, 1),
  M_UINT       (Page_request_for_RR_conn_t, eMLPP_PRIORITY, 3),
CSN_DESCR_END  (Page_request_for_RR_conn_t)

static const
CSN_DESCR_BEGIN(Repeated_Page_info_t)
  M_UNION      (Repeated_Page_info_t, 2),
  M_TYPE       (Repeated_Page_info_t, u.Page_req_TBF, Page_request_for_TBF_establishment_t),
  M_TYPE       (Repeated_Page_info_t, u.Page_req_RR, Page_request_for_RR_conn_t),
CSN_DESCR_END  (Repeated_Page_info_t)

static const
CSN_DESCR_BEGIN(Packet_Paging_Request_t)
  M_UINT       (Packet_Paging_Request_t, MESSAGE_TYPE_v, 6),
  M_UINT       (Packet_Paging_Request_t, PAGE_MODE_v, 2),

  M_NEXT_EXIST (Packet_Paging_Request_t, Exist_PERSISTENCE_LEVEL_v, 1),
  M_UINT_ARRAY (Packet_Paging_Request_t, PERSISTENCE_LEVEL_v, 4, 4), /* 4bit*4 */

  M_NEXT_EXIST (Packet_Paging_Request_t, Exist_NLN_v, 1),
  M_UINT       (Packet_Paging_Request_t, NLN_v, 2),

  M_REC_TARRAY (Packet_Paging_Request_t, Repeated_Page_info, Repeated_Page_info_t, Count_Repeated_Page_info),
CSN_DESCR_END  (Packet_Paging_Request_t)

static const
CSN_DESCR_BEGIN(Packet_PDCH_Release_t)
  M_UINT       (Packet_PDCH_Release_t, MESSAGE_TYPE_v, 6),
  M_UINT       (Packet_PDCH_Release_t, PAGE_MODE_v, 2),

  M_FIXED      (Packet_PDCH_Release_t, 1, 0x01),
  M_UINT       (Packet_PDCH_Release_t, TIMESLOTS_AVAILABLE_v, 8),
CSN_DESCR_END  (Packet_PDCH_Release_t)

/*< Packet Power Control/Timing Advance message content >*/
static const
CSN_DESCR_BEGIN(GlobalTimingAndPower_t)
  M_TYPE       (GlobalTimingAndPower_t, Global_Packet_Timing_Advance, Global_Packet_Timing_Advance_t),
  M_TYPE       (GlobalTimingAndPower_t, Power_Control_Parameters, Power_Control_Parameters_t),
CSN_DESCR_END  (GlobalTimingAndPower_t)

static const
CSN_DESCR_BEGIN(GlobalTimingOrPower_t)
  M_UNION      (GlobalTimingOrPower_t, 2),
  M_TYPE       (GlobalTimingOrPower_t, u.Global_Packet_Timing_Advance, Global_Packet_Timing_Advance_t),
  M_TYPE       (GlobalTimingOrPower_t, u.Power_Control_Parameters, Power_Control_Parameters_t),
CSN_DESCR_END  (GlobalTimingOrPower_t)

static const
CSN_ChoiceElement_t PacketPowerControlTimingAdvanceID[] =
{
  {1, 0,    M_TYPE(PacketPowerControlTimingAdvanceID_t, u.Global_TFI, Global_TFI_t)},
  {3, 0x06, M_UINT(PacketPowerControlTimingAdvanceID_t, u.TQI_v, 16)},
  {3, 0x07, M_TYPE(PacketPowerControlTimingAdvanceID_t, u.Packet_Request_Reference, Packet_Request_Reference_t)},
};

static const
CSN_DESCR_BEGIN(PacketPowerControlTimingAdvanceID_t)
  M_CHOICE     (PacketPowerControlTimingAdvanceID_t, UnionType, PacketPowerControlTimingAdvanceID, ElementsOf(PacketPowerControlTimingAdvanceID)),
CSN_DESCR_END  (PacketPowerControlTimingAdvanceID_t)

static const
CSN_DESCR_BEGIN(Packet_Power_Control_Timing_Advance_t)
  M_UINT       (Packet_Power_Control_Timing_Advance_t, MESSAGE_TYPE_v, 6),
  M_UINT       (Packet_Power_Control_Timing_Advance_t, PAGE_MODE_v, 2),

  M_TYPE       (Packet_Power_Control_Timing_Advance_t, ID, PacketPowerControlTimingAdvanceID_t),

  /*-- Message escape*/
  M_FIXED      (Packet_Power_Control_Timing_Advance_t, 1, 0x00),

  M_NEXT_EXIST (Packet_Power_Control_Timing_Advance_t, Exist_Global_Power_Control_Parameters, 1),
  M_TYPE       (Packet_Power_Control_Timing_Advance_t, Global_Power_Control_Parameters, Global_Power_Control_Parameters_t),

  M_UNION      (Packet_Power_Control_Timing_Advance_t, 2),
  M_TYPE       (Packet_Power_Control_Timing_Advance_t, u.GlobalTimingAndPower, GlobalTimingAndPower_t),
  M_TYPE       (Packet_Power_Control_Timing_Advance_t, u.GlobalTimingOrPower, GlobalTimingOrPower_t),
CSN_DESCR_END  (Packet_Power_Control_Timing_Advance_t)

/*< Packet Queueing Notification message content > */
static const
CSN_DESCR_BEGIN(Packet_Queueing_Notification_t)
  M_UINT       (Packet_Queueing_Notification_t, MESSAGE_TYPE_v, 6),
  M_UINT       (Packet_Queueing_Notification_t, PAGE_MODE_v, 2),

  M_FIXED      (Packet_Queueing_Notification_t, 3, 0x07),/* 111 Fixed */
  M_TYPE       (Packet_Queueing_Notification_t, Packet_Request_Reference, Packet_Request_Reference_t),

  M_UINT       (Packet_Queueing_Notification_t, TQI_v, 16),/* This is where we get our TQI, So do not call TQI_IsOur.*/
CSN_DESCR_END  (Packet_Queueing_Notification_t)

/* USED in Packet Timeslot Reconfigure message content
 * This is almost the same structure as used in
 * <Packet Uplink Assignment message content> but UPLINK_TFI_ASSIGNMENT_v is removed.
 */
static const
CSN_DESCR_BEGIN(TRDynamic_Allocation_t)
  M_UINT       (TRDynamic_Allocation_t, Extended_Dynamic_Allocation, 1),

  M_NEXT_EXIST (TRDynamic_Allocation_t, Exist_P0, 2),
  M_UINT       (TRDynamic_Allocation_t, P0, 4),
  M_UINT       (TRDynamic_Allocation_t, PR_MODE, 1),

  M_UINT       (TRDynamic_Allocation_t, USF_GRANULARITY_v, 1),

  M_NEXT_EXIST (TRDynamic_Allocation_t, Exist_RLC_DATA_BLOCKS_GRANTED_v, 1),
  M_UINT       (TRDynamic_Allocation_t, RLC_DATA_BLOCKS_GRANTED_v, 8),

  M_NEXT_EXIST (TRDynamic_Allocation_t, Exist_TBF_Starting_Time, 1),
  M_TYPE       (TRDynamic_Allocation_t, TBF_Starting_Time, Starting_Frame_Number_t),

  M_UNION      (TRDynamic_Allocation_t, 2),
  M_TYPE_ARRAY (TRDynamic_Allocation_t, u.Timeslot_Allocation, Timeslot_Allocation_t, 8),
  M_TYPE       (TRDynamic_Allocation_t, u.Timeslot_Allocation_Power_Ctrl_Param, Timeslot_Allocation_Power_Ctrl_Param_t),
CSN_DESCR_END  (TRDynamic_Allocation_t)

/*< Packet Timeslot Reconfigure message content > */
static const
CSN_DESCR_BEGIN(PTR_GPRS_AdditionsR99_t)
  M_NEXT_EXIST (PTR_GPRS_AdditionsR99_t, Exist_Packet_Extended_Timing_Advance, 1),
  M_UINT       (PTR_GPRS_AdditionsR99_t, Packet_Extended_Timing_Advance, 2),
CSN_DESCR_END  (PTR_GPRS_AdditionsR99_t)

static const
CSN_DESCR_BEGIN       (PTR_GPRS_t)
  M_UINT              (PTR_GPRS_t, CHANNEL_CODING_COMMAND_v, 2),
  M_TYPE              (PTR_GPRS_t, Common_Timeslot_Reconfigure_Data.Global_Packet_Timing_Advance, Global_Packet_Timing_Advance_t),
  M_UINT              (PTR_GPRS_t, Common_Timeslot_Reconfigure_Data.DOWNLINK_RLC_MODE_v, 1),
  M_UINT              (PTR_GPRS_t, Common_Timeslot_Reconfigure_Data.CONTROL_ACK_v, 1),

  M_NEXT_EXIST        (PTR_GPRS_t, Common_Timeslot_Reconfigure_Data.Exist_DOWNLINK_TFI_ASSIGNMENT_v, 1),
  M_UINT              (PTR_GPRS_t, Common_Timeslot_Reconfigure_Data.DOWNLINK_TFI_ASSIGNMENT_v, 5),

  M_NEXT_EXIST        (PTR_GPRS_t, Common_Timeslot_Reconfigure_Data.Exist_UPLINK_TFI_ASSIGNMENT_v, 1),
  M_UINT              (PTR_GPRS_t, Common_Timeslot_Reconfigure_Data.UPLINK_TFI_ASSIGNMENT_v, 5),

  M_UINT              (PTR_GPRS_t, Common_Timeslot_Reconfigure_Data.DOWNLINK_TIMESLOT_ALLOCATION_v, 8),

  M_NEXT_EXIST        (PTR_GPRS_t, Common_Timeslot_Reconfigure_Data.Exist_Frequency_Parameters, 1),
  M_TYPE              (PTR_GPRS_t, Common_Timeslot_Reconfigure_Data.Frequency_Parameters, Frequency_Parameters_t),

  M_UNION             (PTR_GPRS_t, 2),
  M_TYPE              (PTR_GPRS_t, u.Dynamic_Allocation, TRDynamic_Allocation_t),
  CSN_ERROR           (PTR_GPRS_t, "1 - Fixed Allocation was removed", CSN_ERROR_STREAM_NOT_SUPPORTED),

  M_NEXT_EXIST_OR_NULL(PTR_GPRS_t, Exist_AdditionsR99, 1),
  M_TYPE              (PTR_GPRS_t, AdditionsR99, PTR_GPRS_AdditionsR99_t),
CSN_DESCR_END         (PTR_GPRS_t)

static const
CSN_DESCR_BEGIN(PTR_EGPRS_00_t)
  M_NEXT_EXIST (PTR_EGPRS_00_t, Exist_COMPACT_ReducedMA, 1),
  M_TYPE       (PTR_EGPRS_00_t, COMPACT_ReducedMA, COMPACT_ReducedMA_t),

  M_UINT       (PTR_EGPRS_00_t, EGPRS_ChannelCodingCommand, 4),
  M_UINT       (PTR_EGPRS_00_t, RESEGMENT_v, 1),

  M_NEXT_EXIST (PTR_EGPRS_00_t, Exist_DOWNLINK_EGPRS_WindowSize, 1),
  M_UINT       (PTR_EGPRS_00_t, DOWNLINK_EGPRS_WindowSize, 5),

  M_NEXT_EXIST (PTR_EGPRS_00_t, Exist_UPLINK_EGPRS_WindowSize, 1),
  M_UINT       (PTR_EGPRS_00_t, UPLINK_EGPRS_WindowSize, 5),

  M_UINT       (PTR_EGPRS_00_t, LINK_QUALITY_MEASUREMENT_MODE_v, 2),

  M_TYPE       (PTR_EGPRS_00_t, Common_Timeslot_Reconfigure_Data.Global_Packet_Timing_Advance, Global_Packet_Timing_Advance_t),

  M_NEXT_EXIST (PTR_EGPRS_00_t, Exist_Packet_Extended_Timing_Advance, 1),
  M_UINT       (PTR_EGPRS_00_t, Packet_Extended_Timing_Advance, 2),

  M_UINT       (PTR_EGPRS_00_t, Common_Timeslot_Reconfigure_Data.DOWNLINK_RLC_MODE_v, 1),
  M_UINT       (PTR_EGPRS_00_t, Common_Timeslot_Reconfigure_Data.CONTROL_ACK_v, 1),

  M_NEXT_EXIST (PTR_EGPRS_00_t, Common_Timeslot_Reconfigure_Data.Exist_DOWNLINK_TFI_ASSIGNMENT_v, 1),
  M_UINT       (PTR_EGPRS_00_t, Common_Timeslot_Reconfigure_Data.DOWNLINK_TFI_ASSIGNMENT_v, 5),

  M_NEXT_EXIST (PTR_EGPRS_00_t, Common_Timeslot_Reconfigure_Data.Exist_UPLINK_TFI_ASSIGNMENT_v, 1),
  M_UINT       (PTR_EGPRS_00_t, Common_Timeslot_Reconfigure_Data.UPLINK_TFI_ASSIGNMENT_v, 5),

  M_UINT       (PTR_EGPRS_00_t, Common_Timeslot_Reconfigure_Data.DOWNLINK_TIMESLOT_ALLOCATION_v, 8),

  M_NEXT_EXIST (PTR_EGPRS_00_t, Common_Timeslot_Reconfigure_Data.Exist_Frequency_Parameters, 1),
  M_TYPE       (PTR_EGPRS_00_t, Common_Timeslot_Reconfigure_Data.Frequency_Parameters, Frequency_Parameters_t),

  M_UNION      (PTR_EGPRS_00_t, 2),
  M_TYPE       (PTR_EGPRS_00_t, u.Dynamic_Allocation, TRDynamic_Allocation_t),
  CSN_ERROR    (PTR_EGPRS_00_t, "1 <Fixed Allocation>", CSN_ERROR_STREAM_NOT_SUPPORTED),
CSN_DESCR_END  (PTR_EGPRS_00_t)

static const
CSN_DESCR_BEGIN(PTR_EGPRS_t)
  M_UNION      (PTR_EGPRS_t, 4),
  M_TYPE       (PTR_EGPRS_t, u.PTR_EGPRS_00, PTR_EGPRS_00_t),
  CSN_ERROR    (PTR_EGPRS_t, "01 <PTR_EGPRS>", CSN_ERROR_STREAM_NOT_SUPPORTED),
  CSN_ERROR    (PTR_EGPRS_t, "10 <PTR_EGPRS>", CSN_ERROR_STREAM_NOT_SUPPORTED),
  CSN_ERROR    (PTR_EGPRS_t, "11 <PTR_EGPRS>", CSN_ERROR_STREAM_NOT_SUPPORTED),
CSN_DESCR_END  (PTR_EGPRS_t)

static const
CSN_DESCR_BEGIN(Packet_Timeslot_Reconfigure_t)
  M_UINT       (Packet_Timeslot_Reconfigure_t, MESSAGE_TYPE_v, 6),
  M_UINT       (Packet_Timeslot_Reconfigure_t, PAGE_MODE_v, 2),

  M_FIXED      (Packet_Timeslot_Reconfigure_t, 1, 0x00),
  M_TYPE       (Packet_Timeslot_Reconfigure_t, Global_TFI, Global_TFI_t),

  M_UNION      (Packet_Timeslot_Reconfigure_t, 2),
  M_TYPE       (Packet_Timeslot_Reconfigure_t, u.PTR_GPRS_Struct, PTR_GPRS_t),
  M_TYPE       (Packet_Timeslot_Reconfigure_t, u.PTR_EGPRS_Struct, PTR_EGPRS_t),
CSN_DESCR_END  (Packet_Timeslot_Reconfigure_t)

typedef Packet_Timeslot_Reconfigure_t PTRCheck_t;

static const
CSN_DESCR_BEGIN(PTRCheck_t)
  M_UINT       (PTRCheck_t, MESSAGE_TYPE_v, 6),
  M_UINT       (PTRCheck_t, PAGE_MODE_v, 2),
  M_FIXED      (PTRCheck_t, 1, 0x00),/* 0 fixed */
  M_TYPE       (PTRCheck_t, Global_TFI, Global_TFI_t),
CSN_DESCR_END  (PTRCheck_t)

/*< Packet PRACH Parameters message content > */
static const
CSN_DESCR_BEGIN(PRACH_Control_t)
  M_UINT_ARRAY (PRACH_Control_t, ACC_CONTR_CLASS_v, 8, 2), /* bit (16) == 8bit*2 */
  M_UINT_ARRAY (PRACH_Control_t, MAX_RETRANS_v, 2, 4), /* bit (2) * 4 */
  M_UINT       (PRACH_Control_t, S_v, 4),
  M_UINT       (PRACH_Control_t, TX_INT_v, 4),
  M_NEXT_EXIST (PRACH_Control_t, Exist_PERSISTENCE_LEVEL_v, 1),
  M_UINT_ARRAY (PRACH_Control_t, PERSISTENCE_LEVEL_v, 4, 4),
CSN_DESCR_END  (PRACH_Control_t)

static const
CSN_DESCR_BEGIN(Cell_Allocation_t)
  M_REC_ARRAY  (Cell_Allocation_t, RFL_Number, NoOfRFLs, 4),
CSN_DESCR_END  (Cell_Allocation_t)

static const
CSN_DESCR_BEGIN(HCS_t)
  M_UINT       (HCS_t, PRIORITY_CLASS, 3),
  M_UINT       (HCS_t, HCS_THR, 5),
CSN_DESCR_END  (HCS_t)

static const
CSN_DESCR_BEGIN(Location_Repeat_t)
  M_UINT       (Location_Repeat_t, PBCCH_LOCATION_v, 2),
  M_UINT       (Location_Repeat_t, PSI1_REPEAT_PERIOD_v, 4),
CSN_DESCR_END  (Location_Repeat_t)

static const
CSN_DESCR_BEGIN(SI13_PBCCH_Location_t)
  M_UNION      (SI13_PBCCH_Location_t, 2),
  M_UINT       (SI13_PBCCH_Location_t, u.SI13_LOCATION_v, 1),
  M_TYPE       (SI13_PBCCH_Location_t, u.lr, Location_Repeat_t),
CSN_DESCR_END  (SI13_PBCCH_Location_t)

static const
CSN_DESCR_BEGIN(Cell_Selection_t)
  M_UINT       (Cell_Selection_t, BSIC_v, 6),
  M_UINT       (Cell_Selection_t, CELL_BAR_ACCESS_2_v, 1),
  M_UINT       (Cell_Selection_t, EXC_ACC_v, 1),
  M_UINT       (Cell_Selection_t, SAME_RA_AS_SERVING_CELL_v, 1),
  M_NEXT_EXIST (Cell_Selection_t, Exist_RXLEV_and_TXPWR, 2),
  M_UINT       (Cell_Selection_t, GPRS_RXLEV_ACCESS_MIN_v, 6),
  M_UINT       (Cell_Selection_t, GPRS_MS_TXPWR_MAX_CCH_v, 5),
  M_NEXT_EXIST (Cell_Selection_t, Exist_OFFSET_and_TIME, 2),
  M_UINT       (Cell_Selection_t, GPRS_TEMPORARY_OFFSET_v, 3),
  M_UINT       (Cell_Selection_t, GPRS_PENALTY_TIME_v, 5),
  M_NEXT_EXIST (Cell_Selection_t, Exist_GPRS_RESELECT_OFFSET_v, 1),
  M_UINT       (Cell_Selection_t, GPRS_RESELECT_OFFSET_v, 5),
  M_NEXT_EXIST (Cell_Selection_t, Exist_HCS, 1),
  M_TYPE       (Cell_Selection_t, HCS, HCS_t),
  M_NEXT_EXIST (Cell_Selection_t, Exist_SI13_PBCCH_Location, 1),
  M_TYPE       (Cell_Selection_t, SI13_PBCCH_Location, SI13_PBCCH_Location_t),
CSN_DESCR_END  (Cell_Selection_t)

static const
CSN_DESCR_BEGIN(Cell_Selection_Params_With_FreqDiff_t)
  M_VAR_BITMAP (Cell_Selection_Params_With_FreqDiff_t, FREQUENCY_DIFF_v, FREQ_DIFF_LENGTH_v, 0),
  M_TYPE       (Cell_Selection_Params_With_FreqDiff_t, Cell_SelectionParams, Cell_Selection_t),
CSN_DESCR_END  (Cell_Selection_Params_With_FreqDiff_t)

static const
CSN_DESCR_BEGIN(NeighbourCellParameters_t)
  M_UINT       (NeighbourCellParameters_t, START_FREQUENCY_v, 10),
  M_TYPE       (NeighbourCellParameters_t, Cell_Selection, Cell_Selection_t),
  M_UINT       (NeighbourCellParameters_t, NR_OF_REMAINING_CELLS_v, 4),
  M_UINT_OFFSET(NeighbourCellParameters_t, FREQ_DIFF_LENGTH_v, 3, 1),/* offset 1 */
  M_VAR_TARRAY (NeighbourCellParameters_t, Cell_Selection_Params_With_FreqDiff, Cell_Selection_Params_With_FreqDiff_t, NR_OF_REMAINING_CELLS_v),
CSN_DESCR_END  (NeighbourCellParameters_t)

static const
CSN_DESCR_BEGIN(NeighbourCellList_t)
  M_REC_TARRAY (NeighbourCellList_t, Parameters, NeighbourCellParameters_t, Count),
CSN_DESCR_END  (NeighbourCellList_t)

static const
CSN_DESCR_BEGIN(Cell_Selection_2_t)
  M_UINT       (Cell_Selection_2_t, CELL_BAR_ACCESS_2_v, 1),
  M_UINT       (Cell_Selection_2_t, EXC_ACC_v, 1),
  M_UINT       (Cell_Selection_2_t, SAME_RA_AS_SERVING_CELL_v, 1),
  M_NEXT_EXIST (Cell_Selection_2_t, Exist_RXLEV_and_TXPWR, 2),
  M_UINT       (Cell_Selection_2_t, GPRS_RXLEV_ACCESS_MIN_v, 6),
  M_UINT       (Cell_Selection_2_t, GPRS_MS_TXPWR_MAX_CCH_v, 5),
  M_NEXT_EXIST (Cell_Selection_2_t, Exist_OFFSET_and_TIME, 2),
  M_UINT       (Cell_Selection_2_t, GPRS_TEMPORARY_OFFSET_v, 3),
  M_UINT       (Cell_Selection_2_t, GPRS_PENALTY_TIME_v, 5),
  M_NEXT_EXIST (Cell_Selection_2_t, Exist_GPRS_RESELECT_OFFSET_v, 1),
  M_UINT       (Cell_Selection_2_t, GPRS_RESELECT_OFFSET_v, 5),
  M_NEXT_EXIST (Cell_Selection_2_t, Exist_HCS, 1),
  M_TYPE       (Cell_Selection_2_t, HCS, HCS_t),
  M_NEXT_EXIST (Cell_Selection_2_t, Exist_SI13_PBCCH_Location, 1),
  M_TYPE       (Cell_Selection_2_t, SI13_PBCCH_Location, SI13_PBCCH_Location_t),
CSN_DESCR_END  (Cell_Selection_2_t)

static const
CSN_DESCR_BEGIN(Packet_PRACH_Parameters_t)
  M_UINT       (Packet_PRACH_Parameters_t, MESSAGE_TYPE_v, 6),
  M_UINT       (Packet_PRACH_Parameters_t, PAGE_MODE_v, 2),

  M_TYPE       (Packet_PRACH_Parameters_t, PRACH_Control, PRACH_Control_t),
CSN_DESCR_END  (Packet_PRACH_Parameters_t)

/* < Packet Access Reject message content > */
static const
CSN_ChoiceElement_t RejectID[] =
{
  {1, 0x00, M_UINT(RejectID_t, u.TLLI_v, 32)},
  {2, 0x02, M_TYPE(RejectID_t, u.Packet_Request_Reference, Packet_Request_Reference_t)},
  {2, 0x03, M_TYPE(RejectID_t, u.Global_TFI, Global_TFI_t)},
};

static const
CSN_DESCR_BEGIN(RejectID_t)
  M_CHOICE     (RejectID_t, UnionType, RejectID, ElementsOf(RejectID)),
CSN_DESCR_END  (RejectID_t)

static const
CSN_DESCR_BEGIN(Reject_t)
  M_TYPE       (Reject_t, ID, RejectID_t),

  M_NEXT_EXIST (Reject_t, Exist_Wait, 2),
  M_UINT       (Reject_t, WAIT_INDICATION_v, 8),
  M_UINT       (Reject_t, WAIT_INDICATION_SIZE_v, 1),
CSN_DESCR_END  (Reject_t)

static const
CSN_DESCR_BEGIN(Packet_Access_Reject_t)
  M_UINT       (Packet_Access_Reject_t, MESSAGE_TYPE_v, 6),
  M_UINT       (Packet_Access_Reject_t, PAGE_MODE_v, 2),

  M_TYPE       (Packet_Access_Reject_t, Reject, Reject_t),
  M_REC_TARRAY (Packet_Access_Reject_t, Reject[1], Reject_t, Count_Reject),
CSN_DESCR_END  (Packet_Access_Reject_t)

/* < Packet Cell Change Order message content > */
static const
CSN_ChoiceElement_t PacketCellChangeOrderID[] =
{
  {1, 0,    M_TYPE(PacketCellChangeOrderID_t, u.Global_TFI, Global_TFI_t)},
  {2, 0x02, M_UINT(PacketCellChangeOrderID_t, u.TLLI_v, 32)},
};
/* PacketCellChangeOrderID_t; */

static const
CSN_DESCR_BEGIN(PacketCellChangeOrderID_t)
  M_CHOICE     (PacketCellChangeOrderID_t, UnionType, PacketCellChangeOrderID, ElementsOf(PacketCellChangeOrderID)),
CSN_DESCR_END  (PacketCellChangeOrderID_t)

static const
CSN_DESCR_BEGIN(h_FreqBsicCell_t)
  M_UINT       (h_FreqBsicCell_t, BSIC_v, 6),
  M_TYPE       (h_FreqBsicCell_t, Cell_Selection, Cell_Selection_t),
CSN_DESCR_END  (h_FreqBsicCell_t)

static const CSN_DESCR_BEGIN(CellSelectionParamsWithFreqDiff_t)
  /*FREQUENCY_DIFF_v is really an integer but the number of bits to decode it are stored in FREQ_DIFF_LENGTH_v*/
  M_VAR_BITMAP (CellSelectionParamsWithFreqDiff_t, FREQUENCY_DIFF_v, FREQ_DIFF_LENGTH_v, 0),
  M_UINT       (CellSelectionParamsWithFreqDiff_t, BSIC_v, 6), /*bit(6)*/
  M_NEXT_EXIST (CellSelectionParamsWithFreqDiff_t, Exist_CellSelectionParams, 1),
  M_TYPE       (CellSelectionParamsWithFreqDiff_t, CellSelectionParams, Cell_Selection_2_t),
CSN_DESCR_END  (CellSelectionParamsWithFreqDiff_t)

static const
CSN_DESCR_BEGIN(Add_Frequency_list_t)
  M_UINT       (Add_Frequency_list_t, START_FREQUENCY_v, 10),
  M_UINT       (Add_Frequency_list_t, BSIC_v, 6),

  M_NEXT_EXIST (Add_Frequency_list_t, Exist_Cell_Selection, 1),
  M_TYPE       (Add_Frequency_list_t, Cell_Selection, Cell_Selection_2_t),

  M_UINT       (Add_Frequency_list_t, NR_OF_FREQUENCIES_v, 5),
  M_UINT_OFFSET(Add_Frequency_list_t, FREQ_DIFF_LENGTH_v, 3, 1),/*offset 1*/

  M_VAR_TARRAY (Add_Frequency_list_t, CellSelectionParamsWithFreqDiff, CellSelectionParamsWithFreqDiff_t, NR_OF_FREQUENCIES_v),
CSN_DESCR_END  (Add_Frequency_list_t)

static const CSN_DESCR_BEGIN(Removed_Freq_Index_t)
  M_UINT(Removed_Freq_Index_t, REMOVED_FREQ_INDEX_v, 6),
CSN_DESCR_END(Removed_Freq_Index_t)

static const
CSN_DESCR_BEGIN(NC_Frequency_list_t)
  M_NEXT_EXIST (NC_Frequency_list_t, Exist_REMOVED_FREQ, 2),
  M_UINT_OFFSET(NC_Frequency_list_t, NR_OF_REMOVED_FREQ, 5, 1),/*offset 1*/
  M_VAR_TARRAY (NC_Frequency_list_t, Removed_Freq_Index, Removed_Freq_Index_t, NR_OF_REMOVED_FREQ),
  M_REC_TARRAY (NC_Frequency_list_t, Add_Frequency, Add_Frequency_list_t, Count_Add_Frequency),
CSN_DESCR_END  (NC_Frequency_list_t)

static const
CSN_DESCR_BEGIN(NC_Measurement_Parameters_t)
  M_UINT       (NC_Measurement_Parameters_t, NETWORK_CONTROL_ORDER_v, 2),

  M_NEXT_EXIST (NC_Measurement_Parameters_t, Exist_NC, 3),
  M_UINT       (NC_Measurement_Parameters_t, NC_NON_DRX_PERIOD_v, 3),
  M_UINT       (NC_Measurement_Parameters_t, NC_REPORTING_PERIOD_I_v, 3),
  M_UINT       (NC_Measurement_Parameters_t, NC_REPORTING_PERIOD_T_v, 3),
CSN_DESCR_END  (NC_Measurement_Parameters_t)

static const
CSN_DESCR_BEGIN(NC_Measurement_Parameters_with_Frequency_List_t)
  M_UINT       (NC_Measurement_Parameters_with_Frequency_List_t, NETWORK_CONTROL_ORDER_v, 2),

  M_NEXT_EXIST (NC_Measurement_Parameters_with_Frequency_List_t, Exist_NC, 3),
  M_UINT       (NC_Measurement_Parameters_with_Frequency_List_t, NC_NON_DRX_PERIOD_v, 3),
  M_UINT       (NC_Measurement_Parameters_with_Frequency_List_t, NC_REPORTING_PERIOD_I_v, 3),
  M_UINT       (NC_Measurement_Parameters_with_Frequency_List_t, NC_REPORTING_PERIOD_T_v, 3),

  M_NEXT_EXIST (NC_Measurement_Parameters_with_Frequency_List_t, Exist_NC_FREQUENCY_LIST, 1),
  M_TYPE       (NC_Measurement_Parameters_with_Frequency_List_t, NC_Frequency_list, NC_Frequency_list_t),
CSN_DESCR_END  (NC_Measurement_Parameters_with_Frequency_List_t)

/*< Packet Cell Change Order message contents >*/
static const
CSN_DESCR_BEGIN(BA_IND_t)
  M_UINT       (BA_IND_t, BA_IND_v, 1),
  M_UINT       (BA_IND_t, BA_IND_3G_v, 1),
CSN_DESCR_END  (BA_IND_t)

static const
CSN_DESCR_BEGIN(GPRSReportPriority_t)
  M_UINT       (GPRSReportPriority_t, NUMBER_CELLS_v, 7),
  M_VAR_BITMAP (GPRSReportPriority_t, REPORT_PRIORITY, NUMBER_CELLS_v, 0),
CSN_DESCR_END  (GPRSReportPriority_t)

static const
CSN_DESCR_BEGIN(OffsetThreshold_t)
  M_UINT       (OffsetThreshold_t, REPORTING_OFFSET_v, 3),
  M_UINT       (OffsetThreshold_t, REPORTING_THRESHOLD_v, 3),
CSN_DESCR_END  (OffsetThreshold_t)

static const
CSN_DESCR_BEGIN(GPRSMeasurementParams_PMO_PCCO_t)
  M_NEXT_EXIST (GPRSMeasurementParams_PMO_PCCO_t, Exist_MULTI_BAND_REPORTING, 1),
  M_UINT       (GPRSMeasurementParams_PMO_PCCO_t, MULTI_BAND_REPORTING_v, 2),

  M_NEXT_EXIST (GPRSMeasurementParams_PMO_PCCO_t, Exist_SERVING_BAND_REPORTING, 1),
  M_UINT       (GPRSMeasurementParams_PMO_PCCO_t, SERVING_BAND_REPORTING_v, 2),

  M_UINT       (GPRSMeasurementParams_PMO_PCCO_t, SCALE_ORD_v, 2),

  M_NEXT_EXIST (GPRSMeasurementParams_PMO_PCCO_t, Exist_OffsetThreshold900, 1),
  M_TYPE       (GPRSMeasurementParams_PMO_PCCO_t, OffsetThreshold900, OffsetThreshold_t),

  M_NEXT_EXIST (GPRSMeasurementParams_PMO_PCCO_t, Exist_OffsetThreshold1800, 1),
  M_TYPE       (GPRSMeasurementParams_PMO_PCCO_t, OffsetThreshold1800, OffsetThreshold_t),

  M_NEXT_EXIST (GPRSMeasurementParams_PMO_PCCO_t, Exist_OffsetThreshold400, 1),
  M_TYPE       (GPRSMeasurementParams_PMO_PCCO_t, OffsetThreshold400, OffsetThreshold_t),

  M_NEXT_EXIST (GPRSMeasurementParams_PMO_PCCO_t, Exist_OffsetThreshold1900, 1),
  M_TYPE       (GPRSMeasurementParams_PMO_PCCO_t, OffsetThreshold1900, OffsetThreshold_t),

  M_NEXT_EXIST (GPRSMeasurementParams_PMO_PCCO_t, Exist_OffsetThreshold850, 1),
  M_TYPE       (GPRSMeasurementParams_PMO_PCCO_t, OffsetThreshold850, OffsetThreshold_t),
CSN_DESCR_END  (GPRSMeasurementParams_PMO_PCCO_t)

static const
CSN_DESCR_BEGIN(GPRSMeasurementParams3G_t)
  M_UINT       (GPRSMeasurementParams3G_t, Qsearch_p, 4),
  M_UINT       (GPRSMeasurementParams3G_t, SearchPrio3G, 1),

  M_NEXT_EXIST (GPRSMeasurementParams3G_t, existRepParamsFDD, 2),
  M_UINT       (GPRSMeasurementParams3G_t, RepQuantFDD, 1),
  M_UINT       (GPRSMeasurementParams3G_t, MultiratReportingFDD, 2),

  M_NEXT_EXIST (GPRSMeasurementParams3G_t, existReportingParamsFDD, 2),
  M_UINT       (GPRSMeasurementParams3G_t, ReportingOffsetFDD, 3),
  M_UINT       (GPRSMeasurementParams3G_t, ReportingThresholdFDD, 3),

  M_NEXT_EXIST (GPRSMeasurementParams3G_t, existMultiratReportingTDD, 1),
  M_UINT       (GPRSMeasurementParams3G_t, MultiratReportingTDD, 2),

  M_NEXT_EXIST (GPRSMeasurementParams3G_t, existOffsetThresholdTDD, 2),
  M_UINT       (GPRSMeasurementParams3G_t, ReportingOffsetTDD, 3),
  M_UINT       (GPRSMeasurementParams3G_t, ReportingThresholdTDD, 3),
CSN_DESCR_END  (GPRSMeasurementParams3G_t)

static const
CSN_DESCR_BEGIN(MultiratParams3G_t)
  M_NEXT_EXIST (MultiratParams3G_t, existMultiratReporting, 1),
  M_UINT       (MultiratParams3G_t, MultiratReporting, 2),

  M_NEXT_EXIST (MultiratParams3G_t, existOffsetThreshold, 1),
  M_TYPE       (MultiratParams3G_t, OffsetThreshold, OffsetThreshold_t),
CSN_DESCR_END  (MultiratParams3G_t)

static const
CSN_DESCR_BEGIN(ENH_GPRSMeasurementParams3G_PMO_t)
  M_UINT       (ENH_GPRSMeasurementParams3G_PMO_t, Qsearch_P, 4),
  M_UINT       (ENH_GPRSMeasurementParams3G_PMO_t, SearchPrio3G, 1),

  M_NEXT_EXIST (ENH_GPRSMeasurementParams3G_PMO_t, existRepParamsFDD, 2),
  M_UINT       (ENH_GPRSMeasurementParams3G_PMO_t, RepQuantFDD, 1),
  M_UINT       (ENH_GPRSMeasurementParams3G_PMO_t, MultiratReportingFDD, 2),

  M_NEXT_EXIST (ENH_GPRSMeasurementParams3G_PMO_t, existOffsetThreshold, 1),
  M_TYPE       (ENH_GPRSMeasurementParams3G_PMO_t, OffsetThreshold, OffsetThreshold_t),

  M_TYPE       (ENH_GPRSMeasurementParams3G_PMO_t, ParamsTDD, MultiratParams3G_t),
  M_TYPE       (ENH_GPRSMeasurementParams3G_PMO_t, ParamsCDMA2000, MultiratParams3G_t),
CSN_DESCR_END  (ENH_GPRSMeasurementParams3G_PMO_t)

static const
CSN_DESCR_BEGIN(ENH_GPRSMeasurementParams3G_PCCO_t)
  M_UINT       (ENH_GPRSMeasurementParams3G_PCCO_t, Qsearch_P, 4),
  M_UINT       (ENH_GPRSMeasurementParams3G_PCCO_t, SearchPrio3G, 1),

  M_NEXT_EXIST (ENH_GPRSMeasurementParams3G_PCCO_t, existRepParamsFDD, 2),
  M_UINT       (ENH_GPRSMeasurementParams3G_PCCO_t, RepQuantFDD, 1),
  M_UINT       (ENH_GPRSMeasurementParams3G_PCCO_t, MultiratReportingFDD, 2),

  M_NEXT_EXIST (ENH_GPRSMeasurementParams3G_PCCO_t, existOffsetThreshold, 1),
  M_TYPE       (ENH_GPRSMeasurementParams3G_PCCO_t, OffsetThreshold, OffsetThreshold_t),

  M_TYPE       (ENH_GPRSMeasurementParams3G_PCCO_t, ParamsTDD, MultiratParams3G_t),
CSN_DESCR_END  (ENH_GPRSMeasurementParams3G_PCCO_t)

static const
CSN_DESCR_BEGIN(N2_t)
  M_UINT       (N2_t, REMOVED_3GCELL_INDEX_v, 7),
  M_UINT       (N2_t, CELL_DIFF_LENGTH_3G_v, 3),
  M_VAR_BITMAP (N2_t, CELL_DIFF_3G_v, CELL_DIFF_LENGTH_3G_v, 0),
CSN_DESCR_END  (N2_t)

static const
CSN_DESCR_BEGIN (N1_t)
  M_UINT_OFFSET (N1_t, N2_Count, 5, 1), /*offset 1*/
  M_VAR_TARRAY  (N1_t, N2s, N2_t, N2_Count),
CSN_DESCR_END   (N1_t)

static const
CSN_DESCR_BEGIN (Removed3GCellDescription_t)
  M_UINT_OFFSET (Removed3GCellDescription_t, N1_Count, 2, 1),  /* offset 1 */
  M_VAR_TARRAY  (Removed3GCellDescription_t, N1s, N1_t, N1_Count),
CSN_DESCR_END   (Removed3GCellDescription_t)

static const
CSN_DESCR_BEGIN(CDMA2000_Description_t)
  M_UINT       (CDMA2000_Description_t, Complete_This, 1), /* ISSUE: This implementation must be completed for PMO, PCCO! */
  CSN_ERROR    (CDMA2000_Description_t, "Not Implemented", CSN_ERROR_STREAM_NOT_SUPPORTED),
CSN_DESCR_END  (CDMA2000_Description_t)

static const
CSN_DESCR_BEGIN(UTRAN_FDD_NeighbourCells_t)
  M_UINT       (UTRAN_FDD_NeighbourCells_t, ZERO_v,     1),
  M_UINT       (UTRAN_FDD_NeighbourCells_t, UARFCN_v,  14),
  M_UINT       (UTRAN_FDD_NeighbourCells_t, Indic0,     1),
  M_UINT       (UTRAN_FDD_NeighbourCells_t, NrOfCells,  5),
/*  M_CALLBACK   (UTRAN_FDD_NeighbourCells_t, (void*) 14, NrOfCells, BitsInCellInfo), */
  M_VAR_BITMAP (UTRAN_FDD_NeighbourCells_t, CellInfo,  BitsInCellInfo, 0),
CSN_DESCR_END  (UTRAN_FDD_NeighbourCells_t)

static const
CSN_DESCR_BEGIN(UTRAN_FDD_Description_t)
  M_NEXT_EXIST (UTRAN_FDD_Description_t, existBandwidth, 1),
  M_UINT       (UTRAN_FDD_Description_t, Bandwidth,      3),
  M_REC_TARRAY (UTRAN_FDD_Description_t, CellParams, UTRAN_FDD_NeighbourCells_t, NrOfFrequencies),
CSN_DESCR_END  (UTRAN_FDD_Description_t)

static const
CSN_DESCR_BEGIN(UTRAN_TDD_NeighbourCells_t)
  M_UINT       (UTRAN_TDD_NeighbourCells_t, ZERO_v,     1),
  M_UINT       (UTRAN_TDD_NeighbourCells_t, UARFCN_v,  14),
  M_UINT       (UTRAN_TDD_NeighbourCells_t, Indic0,     1),
  M_UINT       (UTRAN_TDD_NeighbourCells_t, NrOfCells,  5),
/*  M_CALLBACK   (UTRAN_TDD_NeighbourCells_t, (void*) 23, NrOfCells, BitsInCellInfo), */
  M_VAR_BITMAP (UTRAN_TDD_NeighbourCells_t, CellInfo,  BitsInCellInfo, 0),
CSN_DESCR_END  (UTRAN_TDD_NeighbourCells_t)

static const
CSN_DESCR_BEGIN(UTRAN_TDD_Description_t)
  M_NEXT_EXIST (UTRAN_TDD_Description_t, existBandwidth, 1),
  M_UINT       (UTRAN_TDD_Description_t, Bandwidth,      3),
  M_REC_TARRAY (UTRAN_TDD_Description_t, CellParams, UTRAN_TDD_NeighbourCells_t, NrOfFrequencies),
CSN_DESCR_END  (UTRAN_TDD_Description_t)

static const
CSN_DESCR_BEGIN(NeighbourCellDescription3G_PMO_t)
  M_NEXT_EXIST (NeighbourCellDescription3G_PMO_t, Exist_Index_Start_3G_v, 1),
  M_UINT       (NeighbourCellDescription3G_PMO_t, Index_Start_3G_v, 7),
  M_NEXT_EXIST (NeighbourCellDescription3G_PMO_t, Exist_Absolute_Index_Start_EMR_v, 1),
  M_UINT       (NeighbourCellDescription3G_PMO_t, Absolute_Index_Start_EMR_v, 7),
  M_NEXT_EXIST (NeighbourCellDescription3G_PMO_t, Exist_UTRAN_FDD_Description, 1),
  M_TYPE       (NeighbourCellDescription3G_PMO_t, UTRAN_FDD_Description, UTRAN_FDD_Description_t),
  M_NEXT_EXIST (NeighbourCellDescription3G_PMO_t, Exist_UTRAN_TDD_Description, 1),
  M_TYPE       (NeighbourCellDescription3G_PMO_t, UTRAN_TDD_Description, UTRAN_TDD_Description_t),
  M_NEXT_EXIST (NeighbourCellDescription3G_PMO_t, Exist_CDMA2000_Description, 1),
  M_TYPE       (NeighbourCellDescription3G_PMO_t, CDMA2000_Description, CDMA2000_Description_t),
  M_NEXT_EXIST (NeighbourCellDescription3G_PMO_t, Exist_Removed3GCellDescription, 1),
  M_TYPE       (NeighbourCellDescription3G_PMO_t, Removed3GCellDescription, Removed3GCellDescription_t),
CSN_DESCR_END  (NeighbourCellDescription3G_PMO_t)

static const
CSN_DESCR_BEGIN(NeighbourCellDescription3G_PCCO_t)
  M_NEXT_EXIST (NeighbourCellDescription3G_PCCO_t, Exist_Index_Start_3G_v, 1),
  M_UINT       (NeighbourCellDescription3G_PCCO_t, Index_Start_3G_v, 7),
  M_NEXT_EXIST (NeighbourCellDescription3G_PCCO_t, Exist_Absolute_Index_Start_EMR_v, 1),
  M_UINT       (NeighbourCellDescription3G_PCCO_t, Absolute_Index_Start_EMR_v, 7),
  M_NEXT_EXIST (NeighbourCellDescription3G_PCCO_t, Exist_UTRAN_FDD_Description, 1),
  M_TYPE       (NeighbourCellDescription3G_PCCO_t, UTRAN_FDD_Description, UTRAN_FDD_Description_t),
  M_NEXT_EXIST (NeighbourCellDescription3G_PCCO_t, Exist_UTRAN_TDD_Description, 1),
  M_TYPE       (NeighbourCellDescription3G_PCCO_t, UTRAN_TDD_Description, UTRAN_TDD_Description_t),
  M_NEXT_EXIST (NeighbourCellDescription3G_PCCO_t, Exist_Removed3GCellDescription, 1),
  M_TYPE       (NeighbourCellDescription3G_PCCO_t, Removed3GCellDescription, Removed3GCellDescription_t),
CSN_DESCR_END  (NeighbourCellDescription3G_PCCO_t)

static const
CSN_DESCR_BEGIN(ENH_Measurement_Parameters_PMO_t)
  M_UNION      (ENH_Measurement_Parameters_PMO_t, 2),
  M_TYPE       (ENH_Measurement_Parameters_PMO_t, u.BA_IND, BA_IND_t),
  M_UINT       (ENH_Measurement_Parameters_PMO_t, u.PSI3_CHANGE_MARK_v, 2),
  M_UINT       (ENH_Measurement_Parameters_PMO_t, PMO_IND_v, 1),

  M_UINT       (ENH_Measurement_Parameters_PMO_t, REPORT_TYPE_v, 1),
  M_UINT       (ENH_Measurement_Parameters_PMO_t, REPORTING_RATE_v, 1),
  M_UINT       (ENH_Measurement_Parameters_PMO_t, INVALID_BSIC_REPORTING_v, 1),

  M_NEXT_EXIST (ENH_Measurement_Parameters_PMO_t, Exist_NeighbourCellDescription3G, 1),
  M_TYPE       (ENH_Measurement_Parameters_PMO_t, NeighbourCellDescription3G, NeighbourCellDescription3G_PMO_t),

  M_NEXT_EXIST (ENH_Measurement_Parameters_PMO_t, Exist_GPRSReportPriority, 1),
  M_TYPE       (ENH_Measurement_Parameters_PMO_t, GPRSReportPriority, GPRSReportPriority_t),

  M_NEXT_EXIST (ENH_Measurement_Parameters_PMO_t, Exist_GPRSMeasurementParams, 1),
  M_TYPE       (ENH_Measurement_Parameters_PMO_t, GPRSMeasurementParams, GPRSMeasurementParams_PMO_PCCO_t),

  M_NEXT_EXIST (ENH_Measurement_Parameters_PMO_t, Exist_GPRSMeasurementParams3G, 1),
  M_TYPE       (ENH_Measurement_Parameters_PMO_t, GPRSMeasurementParams3G, ENH_GPRSMeasurementParams3G_PMO_t),
CSN_DESCR_END  (ENH_Measurement_Parameters_PMO_t)

static const
CSN_DESCR_BEGIN(ENH_Measurement_Parameters_PCCO_t)
  M_UNION      (ENH_Measurement_Parameters_PCCO_t, 2),
  M_TYPE       (ENH_Measurement_Parameters_PCCO_t, u.BA_IND, BA_IND_t),
  M_UINT       (ENH_Measurement_Parameters_PCCO_t, u.PSI3_CHANGE_MARK_v, 2),
  M_UINT       (ENH_Measurement_Parameters_PCCO_t, PMO_IND_v, 1),

  M_UINT       (ENH_Measurement_Parameters_PCCO_t, REPORT_TYPE_v, 1),
  M_UINT       (ENH_Measurement_Parameters_PCCO_t, REPORTING_RATE_v, 1),
  M_UINT       (ENH_Measurement_Parameters_PCCO_t, INVALID_BSIC_REPORTING_v, 1),

  M_NEXT_EXIST (ENH_Measurement_Parameters_PCCO_t, Exist_NeighbourCellDescription3G, 1),
  M_TYPE       (ENH_Measurement_Parameters_PCCO_t, NeighbourCellDescription3G, NeighbourCellDescription3G_PCCO_t),

  M_NEXT_EXIST (ENH_Measurement_Parameters_PCCO_t, Exist_GPRSReportPriority, 1),
  M_TYPE       (ENH_Measurement_Parameters_PCCO_t, GPRSReportPriority, GPRSReportPriority_t),

  M_NEXT_EXIST (ENH_Measurement_Parameters_PCCO_t, Exist_GPRSMeasurementParams, 1),
  M_TYPE       (ENH_Measurement_Parameters_PCCO_t, GPRSMeasurementParams, GPRSMeasurementParams_PMO_PCCO_t),

  M_NEXT_EXIST (ENH_Measurement_Parameters_PCCO_t, Exist_GPRSMeasurementParams3G, 1),
  M_TYPE       (ENH_Measurement_Parameters_PCCO_t, GPRSMeasurementParams3G, ENH_GPRSMeasurementParams3G_PCCO_t),
CSN_DESCR_END  (ENH_Measurement_Parameters_PCCO_t)

static const
CSN_DESCR_BEGIN(CCN_Support_Description_t)
  M_UINT       (CCN_Support_Description_t, NUMBER_CELLS_v, 7),
  M_VAR_BITMAP (CCN_Support_Description_t, CCN_SUPPORTED, NUMBER_CELLS_v, 0),
CSN_DESCR_END  (CCN_Support_Description_t)

static const
CSN_DESCR_BEGIN(lu_ModeCellSelectionParameters_t)
  M_UINT       (lu_ModeCellSelectionParameters_t, CELL_BAR_QUALIFY_3_v, 2),
  M_NEXT_EXIST (lu_ModeCellSelectionParameters_t, Exist_SI13_Alt_PBCCH_Location, 1),
  M_TYPE       (lu_ModeCellSelectionParameters_t, SI13_Alt_PBCCH_Location, SI13_PBCCH_Location_t),
CSN_DESCR_END  (lu_ModeCellSelectionParameters_t)

static const
CSN_DESCR_BEGIN(lu_ModeCellSelectionParams_t)
  M_NEXT_EXIST (lu_ModeCellSelectionParams_t, Exist_lu_ModeCellSelectionParams, 1),
  M_TYPE       (lu_ModeCellSelectionParams_t, lu_ModeCellSelectionParameters, lu_ModeCellSelectionParameters_t),
CSN_DESCR_END  (lu_ModeCellSelectionParams_t)

static const
CSN_DESCR_BEGIN(lu_ModeNeighbourCellParams_t)
  M_TYPE       (lu_ModeNeighbourCellParams_t, lu_ModeCellSelectionParameters, lu_ModeCellSelectionParams_t),
  M_UINT       (lu_ModeNeighbourCellParams_t, NR_OF_FREQUENCIES_v, 5),
  M_VAR_TARRAY (lu_ModeNeighbourCellParams_t, lu_ModeCellSelectionParams, lu_ModeCellSelectionParams_t, NR_OF_FREQUENCIES_v),
CSN_DESCR_END  (lu_ModeNeighbourCellParams_t)

static const
CSN_DESCR_BEGIN(lu_ModeOnlyCellSelection_t)
  M_UINT       (lu_ModeOnlyCellSelection_t, CELL_BAR_QUALIFY_3_v, 2),
  M_UINT       (lu_ModeOnlyCellSelection_t, SAME_RA_AS_SERVING_CELL_v, 1),

  M_NEXT_EXIST (lu_ModeOnlyCellSelection_t, Exist_RXLEV_and_TXPWR, 2),
  M_UINT       (lu_ModeOnlyCellSelection_t, GPRS_RXLEV_ACCESS_MIN_v, 6),
  M_UINT       (lu_ModeOnlyCellSelection_t, GPRS_MS_TXPWR_MAX_CCH_v, 5),

  M_NEXT_EXIST (lu_ModeOnlyCellSelection_t, Exist_OFFSET_and_TIME, 2),
  M_UINT       (lu_ModeOnlyCellSelection_t, GPRS_TEMPORARY_OFFSET_v, 3),
  M_UINT       (lu_ModeOnlyCellSelection_t, GPRS_PENALTY_TIME_v, 5),

  M_NEXT_EXIST (lu_ModeOnlyCellSelection_t, Exist_GPRS_RESELECT_OFFSET_v, 1),
  M_UINT       (lu_ModeOnlyCellSelection_t, GPRS_RESELECT_OFFSET_v, 5),

  M_NEXT_EXIST (lu_ModeOnlyCellSelection_t, Exist_HCS, 1),
  M_TYPE       (lu_ModeOnlyCellSelection_t, HCS, HCS_t),

  M_NEXT_EXIST (lu_ModeOnlyCellSelection_t, Exist_SI13_Alt_PBCCH_Location, 1),
  M_TYPE       (lu_ModeOnlyCellSelection_t, SI13_Alt_PBCCH_Location, SI13_PBCCH_Location_t),
CSN_DESCR_END  (lu_ModeOnlyCellSelection_t)

static const
CSN_DESCR_BEGIN(lu_ModeOnlyCellSelectionParamsWithFreqDiff_t)
  /*FREQUENCY_DIFF_v is really an integer but the number of bits to decode it are stored in FREQ_DIFF_LENGTH_v*/
  M_VAR_BITMAP (lu_ModeOnlyCellSelectionParamsWithFreqDiff_t, FREQUENCY_DIFF_v, FREQ_DIFF_LENGTH_v, 0),
  M_UINT       (lu_ModeOnlyCellSelectionParamsWithFreqDiff_t, BSIC_v, 6), /*bit(6)*/
  M_NEXT_EXIST (lu_ModeOnlyCellSelectionParamsWithFreqDiff_t, Exist_lu_ModeOnlyCellSelectionParams, 1),
  M_TYPE       (lu_ModeOnlyCellSelectionParamsWithFreqDiff_t, lu_ModeOnlyCellSelectionParams, lu_ModeOnlyCellSelection_t),
CSN_DESCR_END  (lu_ModeOnlyCellSelectionParamsWithFreqDiff_t)

static const
CSN_DESCR_BEGIN(Add_lu_ModeOnlyFrequencyList_t)
  M_UINT       (Add_lu_ModeOnlyFrequencyList_t, START_FREQUENCY_v, 10),
  M_UINT       (Add_lu_ModeOnlyFrequencyList_t, BSIC_v, 6),

  M_NEXT_EXIST (Add_lu_ModeOnlyFrequencyList_t, Exist_lu_ModeCellSelection, 1),
  M_TYPE       (Add_lu_ModeOnlyFrequencyList_t, lu_ModeOnlyCellSelection, lu_ModeOnlyCellSelection_t),

  M_UINT       (Add_lu_ModeOnlyFrequencyList_t, NR_OF_FREQUENCIES_v, 5),
  M_UINT       (Add_lu_ModeOnlyFrequencyList_t, FREQ_DIFF_LENGTH_v, 3),

  M_VAR_TARRAY (Add_lu_ModeOnlyFrequencyList_t, lu_ModeOnlyCellSelectionParamsWithFreqDiff, lu_ModeOnlyCellSelectionParamsWithFreqDiff_t, NR_OF_FREQUENCIES_v),
CSN_DESCR_END  (Add_lu_ModeOnlyFrequencyList_t)

static const
CSN_DESCR_BEGIN(NC_lu_ModeOnlyCapableCellList_t)
  M_REC_TARRAY (NC_lu_ModeOnlyCapableCellList_t, Add_lu_ModeOnlyFrequencyList, Add_lu_ModeOnlyFrequencyList_t, Count_Add_lu_ModeOnlyFrequencyList),
CSN_DESCR_END  (NC_lu_ModeOnlyCapableCellList_t)

static const
CSN_DESCR_BEGIN(GPRS_AdditionalMeasurementParams3G_t)
  M_NEXT_EXIST (GPRS_AdditionalMeasurementParams3G_t, Exist_FDD_REPORTING_THRESHOLD_2, 1),
  M_UINT       (GPRS_AdditionalMeasurementParams3G_t, FDD_REPORTING_THRESHOLD_2, 6),
CSN_DESCR_END  (GPRS_AdditionalMeasurementParams3G_t)

static const
CSN_DESCR_BEGIN(ServingCellPriorityParametersDescription_t)
  M_UINT       (ServingCellPriorityParametersDescription_t, GERAN_PRIORITY, 3),
  M_UINT       (ServingCellPriorityParametersDescription_t, THRESH_Priority_Search, 4),
  M_UINT       (ServingCellPriorityParametersDescription_t, THRESH_GSM_low, 4),
  M_UINT       (ServingCellPriorityParametersDescription_t, H_PRIO, 2),
  M_UINT       (ServingCellPriorityParametersDescription_t, T_Reselection, 2),
CSN_DESCR_END  (ServingCellPriorityParametersDescription_t)

static const
CSN_DESCR_BEGIN(RepeatedUTRAN_PriorityParameters_t)
  M_REC_ARRAY  (RepeatedUTRAN_PriorityParameters_t, UTRAN_FREQUENCY_INDEX_a, NumberOfFrequencyIndexes, 5),

  M_NEXT_EXIST (RepeatedUTRAN_PriorityParameters_t, existUTRAN_PRIORITY, 1),
  M_UINT       (RepeatedUTRAN_PriorityParameters_t, UTRAN_PRIORITY, 3),

  M_UINT       (RepeatedUTRAN_PriorityParameters_t, THRESH_UTRAN_high, 5),

  M_NEXT_EXIST (RepeatedUTRAN_PriorityParameters_t, existTHRESH_UTRAN_low, 1),
  M_UINT       (RepeatedUTRAN_PriorityParameters_t, THRESH_UTRAN_low, 5),

  M_NEXT_EXIST (RepeatedUTRAN_PriorityParameters_t, existUTRAN_QRXLEVMIN, 1),
  M_UINT       (RepeatedUTRAN_PriorityParameters_t, UTRAN_QRXLEVMIN, 5),
CSN_DESCR_END  (RepeatedUTRAN_PriorityParameters_t)

static const
CSN_DESCR_BEGIN(PriorityParametersDescription3G_PMO_t)

  M_NEXT_EXIST (PriorityParametersDescription3G_PMO_t, existDEFAULT_UTRAN_Parameters, 3),
  M_UINT       (PriorityParametersDescription3G_PMO_t, DEFAULT_UTRAN_PRIORITY, 3),
  M_UINT       (PriorityParametersDescription3G_PMO_t, DEFAULT_THRESH_UTRAN, 5),
  M_UINT       (PriorityParametersDescription3G_PMO_t, DEFAULT_UTRAN_QRXLEVMIN, 5),

  M_REC_TARRAY (PriorityParametersDescription3G_PMO_t, RepeatedUTRAN_PriorityParameters_a, RepeatedUTRAN_PriorityParameters_t, NumberOfPriorityParameters),
CSN_DESCR_END  (PriorityParametersDescription3G_PMO_t)

static const
CSN_DESCR_BEGIN(EUTRAN_REPORTING_THRESHOLD_OFFSET_t)
  M_NEXT_EXIST (EUTRAN_REPORTING_THRESHOLD_OFFSET_t, existEUTRAN_FDD_REPORTING_THRESHOLD_OFFSET, 5),
  M_UINT       (EUTRAN_REPORTING_THRESHOLD_OFFSET_t, EUTRAN_FDD_REPORTING_THRESHOLD, 3),
  M_NEXT_EXIST (EUTRAN_REPORTING_THRESHOLD_OFFSET_t, existEUTRAN_FDD_REPORTING_THRESHOLD_2, 1),
  M_UINT       (EUTRAN_REPORTING_THRESHOLD_OFFSET_t, EUTRAN_FDD_REPORTING_THRESHOLD_2, 6),
  M_NEXT_EXIST (EUTRAN_REPORTING_THRESHOLD_OFFSET_t, existEUTRAN_FDD_REPORTING_OFFSET, 1),
  M_UINT       (EUTRAN_REPORTING_THRESHOLD_OFFSET_t, EUTRAN_FDD_REPORTING_OFFSET, 3),

  M_NEXT_EXIST (EUTRAN_REPORTING_THRESHOLD_OFFSET_t, existEUTRAN_TDD_REPORTING_THRESHOLD_OFFSET, 5),
  M_UINT       (EUTRAN_REPORTING_THRESHOLD_OFFSET_t, EUTRAN_TDD_REPORTING_THRESHOLD, 3),
  M_NEXT_EXIST (EUTRAN_REPORTING_THRESHOLD_OFFSET_t, existEUTRAN_TDD_REPORTING_THRESHOLD_2, 1),
  M_UINT       (EUTRAN_REPORTING_THRESHOLD_OFFSET_t, EUTRAN_TDD_REPORTING_THRESHOLD_2, 6),
  M_NEXT_EXIST (EUTRAN_REPORTING_THRESHOLD_OFFSET_t, existEUTRAN_TDD_REPORTING_OFFSET, 1),
  M_UINT       (EUTRAN_REPORTING_THRESHOLD_OFFSET_t, EUTRAN_TDD_REPORTING_OFFSET, 3),
CSN_DESCR_END  (EUTRAN_REPORTING_THRESHOLD_OFFSET_t)

static const
CSN_DESCR_BEGIN(GPRS_EUTRAN_MeasurementParametersDescription_t)
  M_UINT       (GPRS_EUTRAN_MeasurementParametersDescription_t, Qsearch_P_EUTRAN, 4),
  M_BIT        (GPRS_EUTRAN_MeasurementParametersDescription_t, EUTRAN_REP_QUANT),
  M_UINT       (GPRS_EUTRAN_MeasurementParametersDescription_t, EUTRAN_MULTIRAT_REPORTING, 2),
  M_TYPE       (GPRS_EUTRAN_MeasurementParametersDescription_t, EUTRAN_REPORTING_THRESHOLD_OFFSET, EUTRAN_REPORTING_THRESHOLD_OFFSET_t),
CSN_DESCR_END  (GPRS_EUTRAN_MeasurementParametersDescription_t)

static const
CSN_DESCR_BEGIN(RepeatedEUTRAN_Cells_t)
  M_UINT       (RepeatedEUTRAN_Cells_t, EARFCN, 16),
  M_NEXT_EXIST (RepeatedEUTRAN_Cells_t, existMeasurementBandwidth, 1),
  M_UINT       (RepeatedEUTRAN_Cells_t, MeasurementBandwidth, 3),
CSN_DESCR_END  (RepeatedEUTRAN_Cells_t)

static const
CSN_DESCR_BEGIN(RepeatedEUTRAN_NeighbourCells_t)
  M_REC_TARRAY (RepeatedEUTRAN_NeighbourCells_t, EUTRAN_Cells_a, RepeatedEUTRAN_Cells_t, nbrOfEUTRAN_Cells),

  M_NEXT_EXIST (RepeatedEUTRAN_NeighbourCells_t, existEUTRAN_PRIORITY, 1),
  M_UINT       (RepeatedEUTRAN_NeighbourCells_t, EUTRAN_PRIORITY, 3),

  M_UINT       (RepeatedEUTRAN_NeighbourCells_t, THRESH_EUTRAN_high, 5),

  M_NEXT_EXIST (RepeatedEUTRAN_NeighbourCells_t, existTHRESH_EUTRAN_low, 1),
  M_UINT       (RepeatedEUTRAN_NeighbourCells_t, THRESH_EUTRAN_low, 5),

  M_NEXT_EXIST (RepeatedEUTRAN_NeighbourCells_t, existEUTRAN_QRXLEVMIN, 1),
  M_UINT       (RepeatedEUTRAN_NeighbourCells_t, EUTRAN_QRXLEVMIN, 5),
CSN_DESCR_END  (RepeatedEUTRAN_NeighbourCells_t)

static const
CSN_DESCR_BEGIN(PCID_Pattern_t)
  M_UINT       (PCID_Pattern_t, PCID_Pattern_length, 3),
  M_VAR_BITMAP (PCID_Pattern_t, PCID_Pattern, PCID_Pattern_length, 1), /* offset 1, 44.060 12.57 */
  M_UINT       (PCID_Pattern_t, PCID_Pattern_sense, 1),
CSN_DESCR_END  (PCID_Pattern_t)

static const
CSN_DESCR_BEGIN(PCID_Group_IE_t)

  M_REC_ARRAY  (PCID_Group_IE_t, PCID_a, NumberOfPCIDs, 9),

  M_NEXT_EXIST (PCID_Group_IE_t, existPCID_BITMAP_GROUP, 1),
  M_UINT       (PCID_Group_IE_t, PCID_BITMAP_GROUP, 6),

  M_REC_TARRAY (PCID_Group_IE_t, PCID_Pattern_a, PCID_Pattern_t, NumberOfPCID_Patterns),
CSN_DESCR_END  (PCID_Group_IE_t)

static const
CSN_DESCR_BEGIN(EUTRAN_FREQUENCY_INDEX_t)
  M_UINT       (EUTRAN_FREQUENCY_INDEX_t, EUTRAN_FREQUENCY_INDEX, 3),
CSN_DESCR_END  (EUTRAN_FREQUENCY_INDEX_t)

static const
CSN_DESCR_BEGIN(RepeatedEUTRAN_NotAllowedCells_t)
  M_TYPE       (RepeatedEUTRAN_NotAllowedCells_t, NotAllowedCells, PCID_Group_IE_t),

  M_REC_TARRAY (RepeatedEUTRAN_NotAllowedCells_t, EUTRAN_FREQUENCY_INDEX_a, EUTRAN_FREQUENCY_INDEX_t, NumberOfFrequencyIndexes),
CSN_DESCR_END  (RepeatedEUTRAN_NotAllowedCells_t)

static const
CSN_DESCR_BEGIN(RepeatedEUTRAN_PCID_to_TA_mapping_t)
  M_REC_TARRAY (RepeatedEUTRAN_PCID_to_TA_mapping_t, PCID_ToTA_Mapping_a, PCID_Group_IE_t, NumberOfMappings),
  M_REC_TARRAY (RepeatedEUTRAN_PCID_to_TA_mapping_t, EUTRAN_FREQUENCY_INDEX_a, EUTRAN_FREQUENCY_INDEX_t, NumberOfFrequencyIndexes),
CSN_DESCR_END  (RepeatedEUTRAN_PCID_to_TA_mapping_t)

static const
CSN_DESCR_BEGIN(EUTRAN_ParametersDescription_PMO_t)
  M_BIT        (EUTRAN_ParametersDescription_PMO_t, EUTRAN_CCN_ACTIVE),

  M_NEXT_EXIST (EUTRAN_ParametersDescription_PMO_t, existGPRS_EUTRAN_MeasurementParametersDescription, 1),
  M_TYPE       (EUTRAN_ParametersDescription_PMO_t, GPRS_EUTRAN_MeasurementParametersDescription, GPRS_EUTRAN_MeasurementParametersDescription_t),

  M_REC_TARRAY (EUTRAN_ParametersDescription_PMO_t, RepeatedEUTRAN_NeighbourCells_a, RepeatedEUTRAN_NeighbourCells_t, nbrOfRepeatedEUTRAN_NeighbourCellsStructs),
  M_REC_TARRAY (EUTRAN_ParametersDescription_PMO_t, RepeatedEUTRAN_NotAllowedCells_a, RepeatedEUTRAN_NotAllowedCells_t, NumberOfNotAllowedCells),
  M_REC_TARRAY (EUTRAN_ParametersDescription_PMO_t, RepeatedEUTRAN_PCID_to_TA_mapping_a, RepeatedEUTRAN_PCID_to_TA_mapping_t, NumberOfMappings),
CSN_DESCR_END  (EUTRAN_ParametersDescription_PMO_t)

static const
CSN_DESCR_BEGIN        (PriorityAndEUTRAN_ParametersDescription_PMO_t)
  M_NEXT_EXIST         (PriorityAndEUTRAN_ParametersDescription_PMO_t, existServingCellPriorityParametersDescription, 1),
  M_TYPE               (PriorityAndEUTRAN_ParametersDescription_PMO_t, ServingCellPriorityParametersDescription, ServingCellPriorityParametersDescription_t),
  M_NEXT_EXIST         (PriorityAndEUTRAN_ParametersDescription_PMO_t, existPriorityParametersDescription3G_PMO, 1),
  M_TYPE               (PriorityAndEUTRAN_ParametersDescription_PMO_t, PriorityParametersDescription3G_PMO, PriorityParametersDescription3G_PMO_t),
  M_NEXT_EXIST         (PriorityAndEUTRAN_ParametersDescription_PMO_t, existEUTRAN_ParametersDescription_PMO, 1),
  M_TYPE               (PriorityAndEUTRAN_ParametersDescription_PMO_t, EUTRAN_ParametersDescription_PMO, EUTRAN_ParametersDescription_PMO_t),
CSN_DESCR_END          (PriorityAndEUTRAN_ParametersDescription_PMO_t)

static const
CSN_DESCR_BEGIN        (PMO_AdditionsR8_t)
  M_NEXT_EXIST         (PMO_AdditionsR8_t, existBA_IND_3G_PMO_IND, 2),
  M_BIT                (PMO_AdditionsR8_t, BA_IND_3G),
  M_BIT                (PMO_AdditionsR8_t, PMO_IND),
  M_NEXT_EXIST         (PMO_AdditionsR8_t, existPriorityAndEUTRAN_ParametersDescription_PMO, 1),
  M_TYPE               (PMO_AdditionsR8_t, PriorityAndEUTRAN_ParametersDescription_PMO, PriorityAndEUTRAN_ParametersDescription_PMO_t),
  /* TBD: IndividualPriorities_PMO */
CSN_DESCR_END          (PMO_AdditionsR8_t)

static const
CSN_DESCR_BEGIN        (PMO_AdditionsR7_t)
  M_NEXT_EXIST         (PMO_AdditionsR7_t, existREPORTING_OFFSET_THRESHOLD_700, 2),
  M_UINT               (PMO_AdditionsR7_t, REPORTING_OFFSET_700, 3),
  M_UINT               (PMO_AdditionsR7_t, REPORTING_THRESHOLD_700, 3),

  M_NEXT_EXIST         (PMO_AdditionsR7_t, existREPORTING_OFFSET_THRESHOLD_810, 2),
  M_UINT               (PMO_AdditionsR7_t, REPORTING_OFFSET_810, 3),
  M_UINT               (PMO_AdditionsR7_t, REPORTING_THRESHOLD_810, 3),

  M_NEXT_EXIST_OR_NULL (PMO_AdditionsR7_t, existAdditionsR8, 1),
  M_TYPE               (PMO_AdditionsR7_t, additionsR8, PMO_AdditionsR8_t),
CSN_DESCR_END          (PMO_AdditionsR7_t)

static const
CSN_DESCR_BEGIN        (PMO_AdditionsR6_t)
  M_UINT               (PMO_AdditionsR6_t, CCN_ACTIVE_3G, 1),
  M_NEXT_EXIST_OR_NULL (PMO_AdditionsR6_t, existAdditionsR7, 1),
  M_TYPE               (PMO_AdditionsR6_t, additionsR7, PMO_AdditionsR7_t),
CSN_DESCR_END          (PMO_AdditionsR6_t)

static const
CSN_DESCR_BEGIN(PCCO_AdditionsR6_t)
  M_UINT       (PCCO_AdditionsR6_t, CCN_ACTIVE_3G, 1),
CSN_DESCR_END  (PCCO_AdditionsR6_t)

static const
CSN_DESCR_BEGIN        (PMO_AdditionsR5_t)
  M_NEXT_EXIST         (PMO_AdditionsR5_t, existGRNTI_Extension, 1),
  M_UINT               (PMO_AdditionsR5_t, GRNTI, 4),
  M_NEXT_EXIST         (PMO_AdditionsR5_t, exist_lu_ModeNeighbourCellParams, 1),
  M_REC_TARRAY         (PMO_AdditionsR5_t, lu_ModeNeighbourCellParams, lu_ModeNeighbourCellParams_t, count_lu_ModeNeighbourCellParams),
  M_NEXT_EXIST         (PMO_AdditionsR5_t, existNC_lu_ModeOnlyCapableCellList, 1),
  M_TYPE               (PMO_AdditionsR5_t, NC_lu_ModeOnlyCapableCellList, NC_lu_ModeOnlyCapableCellList_t),
  M_NEXT_EXIST         (PMO_AdditionsR5_t, existGPRS_AdditionalMeasurementParams3G, 1),
  M_TYPE               (PMO_AdditionsR5_t, GPRS_AdditionalMeasurementParams3G, GPRS_AdditionalMeasurementParams3G_t),
  M_NEXT_EXIST_OR_NULL (PMO_AdditionsR5_t, existAdditionsR6, 1),
  M_TYPE               (PMO_AdditionsR5_t, additionsR6, PMO_AdditionsR6_t),
CSN_DESCR_END  (PMO_AdditionsR5_t)

static const
CSN_DESCR_BEGIN        (PCCO_AdditionsR5_t)
  M_NEXT_EXIST         (PCCO_AdditionsR5_t, existGRNTI_Extension, 1),
  M_UINT               (PCCO_AdditionsR5_t, GRNTI, 4),
  M_NEXT_EXIST         (PCCO_AdditionsR5_t, exist_lu_ModeNeighbourCellParams, 1),
  M_REC_TARRAY         (PCCO_AdditionsR5_t, lu_ModeNeighbourCellParams, lu_ModeNeighbourCellParams_t, count_lu_ModeNeighbourCellParams),
  M_NEXT_EXIST         (PCCO_AdditionsR5_t, existNC_lu_ModeOnlyCapableCellList, 1),
  M_TYPE               (PCCO_AdditionsR5_t, NC_lu_ModeOnlyCapableCellList, NC_lu_ModeOnlyCapableCellList_t),
  M_NEXT_EXIST         (PCCO_AdditionsR5_t, existGPRS_AdditionalMeasurementParams3G, 1),
  M_TYPE               (PCCO_AdditionsR5_t, GPRS_AdditionalMeasurementParams3G, GPRS_AdditionalMeasurementParams3G_t),
  M_NEXT_EXIST_OR_NULL (PCCO_AdditionsR5_t, existAdditionsR6, 1),
  M_TYPE               (PCCO_AdditionsR5_t, additionsR6, PCCO_AdditionsR6_t),
CSN_DESCR_END  (PCCO_AdditionsR5_t)

static const
CSN_DESCR_BEGIN        (PMO_AdditionsR4_t)
  M_UINT               (PMO_AdditionsR4_t, CCN_ACTIVE, 1),
  M_NEXT_EXIST         (PMO_AdditionsR4_t, Exist_CCN_Support_Description_ID, 1),
  M_TYPE               (PMO_AdditionsR4_t, CCN_Support_Description, CCN_Support_Description_t),
  M_NEXT_EXIST_OR_NULL (PMO_AdditionsR4_t, Exist_AdditionsR5, 1),
  M_TYPE               (PMO_AdditionsR4_t, AdditionsR5, PMO_AdditionsR5_t),
CSN_DESCR_END          (PMO_AdditionsR4_t)

static const
CSN_DESCR_BEGIN        (PMO_AdditionsR99_t)
  M_NEXT_EXIST         (PMO_AdditionsR99_t, Exist_ENH_Measurement_Parameters, 1),
  M_TYPE               (PMO_AdditionsR99_t, ENH_Measurement_Parameters, ENH_Measurement_Parameters_PMO_t),
  M_NEXT_EXIST_OR_NULL (PMO_AdditionsR99_t, Exist_AdditionsR4, 1),
  M_TYPE               (PMO_AdditionsR99_t, AdditionsR4, PMO_AdditionsR4_t),
CSN_DESCR_END          (PMO_AdditionsR99_t)

static const
CSN_DESCR_BEGIN        (PCCO_AdditionsR4_t)
  M_UINT               (PCCO_AdditionsR4_t, CCN_ACTIVE, 1),
  M_NEXT_EXIST         (PCCO_AdditionsR4_t, Exist_Container_ID, 1),
  M_UINT               (PCCO_AdditionsR4_t, CONTAINER_ID_v, 2),
  M_NEXT_EXIST         (PCCO_AdditionsR4_t, Exist_CCN_Support_Description_ID, 1),
  M_TYPE               (PCCO_AdditionsR4_t, CCN_Support_Description, CCN_Support_Description_t),
  M_NEXT_EXIST_OR_NULL (PCCO_AdditionsR4_t, Exist_AdditionsR5, 1),
  M_TYPE               (PCCO_AdditionsR4_t, AdditionsR5, PCCO_AdditionsR5_t),
CSN_DESCR_END  (PCCO_AdditionsR4_t)

static const
CSN_DESCR_BEGIN        (PCCO_AdditionsR99_t)
  M_TYPE               (PCCO_AdditionsR99_t, ENH_Measurement_Parameters, ENH_Measurement_Parameters_PCCO_t),
  M_NEXT_EXIST_OR_NULL (PCCO_AdditionsR99_t, Exist_AdditionsR4, 1),
  M_TYPE               (PCCO_AdditionsR99_t, AdditionsR4, PCCO_AdditionsR4_t),
CSN_DESCR_END          (PCCO_AdditionsR99_t)

static const
CSN_DESCR_BEGIN(LSA_ID_Info_Element_t)
  /* 1 -- Message escape*/
  M_FIXED      (LSA_ID_Info_Element_t, 1, 0x1),
  M_UNION      (LSA_ID_Info_Element_t, 2),
  M_UINT       (LSA_ID_Info_Element_t, u.LSA_ID_v, 24),
  M_UINT       (LSA_ID_Info_Element_t, u.ShortLSA_ID_v, 10),
CSN_DESCR_END  (LSA_ID_Info_Element_t)

static const
CSN_DESCR_BEGIN(LSA_ID_Info_t)
  M_REC_TARRAY (LSA_ID_Info_t, LSA_ID_Info_Elements, LSA_ID_Info_Element_t, Count_LSA_ID_Info_Element),
CSN_DESCR_END  (LSA_ID_Info_t)

static const
CSN_DESCR_BEGIN(LSA_Parameters_t)
  M_UINT       (LSA_Parameters_t, NR_OF_FREQ_OR_CELLS_v, 5),
  M_VAR_TARRAY (LSA_Parameters_t, LSA_ID_Info, LSA_ID_Info_t, NR_OF_FREQ_OR_CELLS_v),
CSN_DESCR_END  (LSA_Parameters_t)

static const
CSN_DESCR_BEGIN        (PMO_AdditionsR98_t)
  M_NEXT_EXIST         (PMO_AdditionsR98_t, Exist_LSA_Parameters, 1),
  M_TYPE               (PMO_AdditionsR98_t, LSA_Parameters, LSA_Parameters_t),

  M_NEXT_EXIST_OR_NULL (PMO_AdditionsR98_t, Exist_AdditionsR99, 1),
  M_TYPE               (PMO_AdditionsR98_t, AdditionsR99, PMO_AdditionsR99_t),
CSN_DESCR_END          (PMO_AdditionsR98_t)

static const
CSN_DESCR_BEGIN        (PCCO_AdditionsR98_t)
  M_NEXT_EXIST         (PCCO_AdditionsR98_t, Exist_LSA_Parameters, 1),
  M_TYPE               (PCCO_AdditionsR98_t, LSA_Parameters, LSA_Parameters_t),

  M_NEXT_EXIST_OR_NULL (PCCO_AdditionsR98_t, Exist_AdditionsR99, 1),
  M_TYPE               (PCCO_AdditionsR98_t, AdditionsR99, PCCO_AdditionsR99_t),
CSN_DESCR_END          (PCCO_AdditionsR98_t)

static const
CSN_DESCR_BEGIN        (Target_Cell_GSM_t)
  M_UINT               (Target_Cell_GSM_t, IMMEDIATE_REL_v, 1),
  M_UINT               (Target_Cell_GSM_t, ARFCN_v, 10),
  M_UINT               (Target_Cell_GSM_t, BSIC_v, 6),
  M_TYPE               (Target_Cell_GSM_t, NC_Measurement_Parameters, NC_Measurement_Parameters_with_Frequency_List_t),
  M_NEXT_EXIST_OR_NULL (Target_Cell_GSM_t, Exist_AdditionsR98, 1),
  M_TYPE               (Target_Cell_GSM_t, AdditionsR98, PCCO_AdditionsR98_t),
CSN_DESCR_END          (Target_Cell_GSM_t)

static const
CSN_DESCR_BEGIN(Target_Cell_3G_t)
  /* 00 -- Message escape */
  M_FIXED      (Target_Cell_3G_t, 2, 0x00),
  M_UINT       (Target_Cell_3G_t, IMMEDIATE_REL_v, 1),
  M_NEXT_EXIST (Target_Cell_3G_t, Exist_FDD_Description, 1),
  M_TYPE       (Target_Cell_3G_t, FDD_Target_Cell, FDD_Target_Cell_t),
  M_NEXT_EXIST (Target_Cell_3G_t, Exist_TDD_Description, 1),
  M_TYPE       (Target_Cell_3G_t, TDD_Target_Cell, TDD_Target_Cell_t),  /* not implemented */
CSN_DESCR_END  (Target_Cell_3G_t)

static const
CSN_DESCR_BEGIN(Packet_Cell_Change_Order_t)
  M_UINT       (Packet_Cell_Change_Order_t, MESSAGE_TYPE_v, 6),
  M_UINT       (Packet_Cell_Change_Order_t, PAGE_MODE_v, 2),

  M_TYPE       (Packet_Cell_Change_Order_t, ID, PacketCellChangeOrderID_t),

  M_UNION      (Packet_Cell_Change_Order_t, 2),
  M_TYPE       (Packet_Cell_Change_Order_t, u.Target_Cell_GSM, Target_Cell_GSM_t),
  M_TYPE       (Packet_Cell_Change_Order_t, u.Target_Cell_3G, Target_Cell_3G_t),
CSN_DESCR_END  (Packet_Cell_Change_Order_t)

/*< Packet (Enhanced) Measurement Report message contents > */
static const
CSN_DESCR_BEGIN(BA_USED_t)
  M_UINT       (BA_USED_t, BA_USED_v, 1),
  M_UINT       (BA_USED_t, BA_USED_3G_v, 1),
CSN_DESCR_END  (BA_USED_t)

static const
CSN_DESCR_BEGIN(Serving_Cell_Data_t)
  M_UINT       (Serving_Cell_Data_t, RXLEV_SERVING_CELL_v, 6),
  M_FIXED      (Serving_Cell_Data_t, 1, 0),
CSN_DESCR_END  (Serving_Cell_Data_t)

static const
CSN_DESCR_BEGIN(NC_Measurements_t)
  M_UINT       (NC_Measurements_t, FREQUENCY_N_v, 6),

  M_NEXT_EXIST (NC_Measurements_t, Exist_BSIC_N, 1),
  M_UINT       (NC_Measurements_t, BSIC_N_v, 6),
  M_UINT       (NC_Measurements_t, RXLEV_N_v, 6),
CSN_DESCR_END  (NC_Measurements_t)

static const
CSN_DESCR_BEGIN(RepeatedInvalid_BSIC_Info_t)
  M_UINT       (RepeatedInvalid_BSIC_Info_t, BCCH_FREQ_N_v, 5),
  M_UINT       (RepeatedInvalid_BSIC_Info_t, BSIC_N_v, 6),
  M_UINT       (RepeatedInvalid_BSIC_Info_t, RXLEV_N_v, 6),
CSN_DESCR_END  (RepeatedInvalid_BSIC_Info_t)

static const
CSN_DESCR_BEGIN(REPORTING_QUANTITY_Instance_t)
  M_NEXT_EXIST (REPORTING_QUANTITY_Instance_t, Exist_REPORTING_QUANTITY, 1),
  M_UINT       (REPORTING_QUANTITY_Instance_t, REPORTING_QUANTITY_v, 6),
CSN_DESCR_END  (REPORTING_QUANTITY_Instance_t)

static const
CSN_DESCR_BEGIN(NC_Measurement_Report_t)
  M_UINT       (NC_Measurement_Report_t, NC_MODE_v, 1),
  M_TYPE       (NC_Measurement_Report_t, Serving_Cell_Data, Serving_Cell_Data_t),
  M_UINT       (NC_Measurement_Report_t, NUMBER_OF_NC_MEASUREMENTS_v, 3),
  M_VAR_TARRAY (NC_Measurement_Report_t, NC_Measurements, NC_Measurements_t, NUMBER_OF_NC_MEASUREMENTS_v),
CSN_DESCR_END  (NC_Measurement_Report_t)

static const
CSN_DESCR_BEGIN(ENH_NC_Measurement_Report_t)
  M_UINT       (ENH_NC_Measurement_Report_t, NC_MODE_v, 1),
  M_UNION      (ENH_NC_Measurement_Report_t, 2),
  M_TYPE       (ENH_NC_Measurement_Report_t, u.BA_USED, BA_USED_t),
  M_UINT       (ENH_NC_Measurement_Report_t, u.PSI3_CHANGE_MARK_v, 2),
  M_UINT       (ENH_NC_Measurement_Report_t, PMO_USED_v, 1),
  M_UINT       (ENH_NC_Measurement_Report_t, BSIC_Seen, 1),
  M_UINT       (ENH_NC_Measurement_Report_t, SCALE_v, 1),
  M_NEXT_EXIST (ENH_NC_Measurement_Report_t, Exist_Serving_Cell_Data, 1),
  M_TYPE       (ENH_NC_Measurement_Report_t, Serving_Cell_Data, Serving_Cell_Data_t),
  M_REC_TARRAY (ENH_NC_Measurement_Report_t, RepeatedInvalid_BSIC_Info[0], RepeatedInvalid_BSIC_Info_t, Count_RepeatedInvalid_BSIC_Info),
  M_NEXT_EXIST (ENH_NC_Measurement_Report_t, Exist_ReportBitmap, 1),
  M_VAR_TARRAY (ENH_NC_Measurement_Report_t, REPORTING_QUANTITY_Instances, REPORTING_QUANTITY_Instance_t, Count_REPORTING_QUANTITY_Instances),
CSN_DESCR_END  (ENH_NC_Measurement_Report_t)


static const
CSN_DESCR_BEGIN(EXT_Measurement_Report_t)
  M_UINT       (EXT_Measurement_Report_t, EXT_REPORTING_TYPE, 2),  /* either 00, 01 or 10 */

  M_NEXT_EXIST (EXT_Measurement_Report_t, Exist_I_LEVEL, 1),

  M_NEXT_EXIST (EXT_Measurement_Report_t, Slot[0].Exist, 1),
  M_UINT       (EXT_Measurement_Report_t, Slot[0].I_LEVEL, 6),

  M_NEXT_EXIST (EXT_Measurement_Report_t, Slot[1].Exist, 1),
  M_UINT       (EXT_Measurement_Report_t, Slot[1].I_LEVEL, 6),

  M_NEXT_EXIST (EXT_Measurement_Report_t, Slot[2].Exist, 1),
  M_UINT       (EXT_Measurement_Report_t, Slot[2].I_LEVEL, 6),

  M_NEXT_EXIST (EXT_Measurement_Report_t, Slot[3].Exist, 1),
  M_UINT       (EXT_Measurement_Report_t, Slot[3].I_LEVEL, 6),

  M_NEXT_EXIST (EXT_Measurement_Report_t, Slot[4].Exist, 1),
  M_UINT       (EXT_Measurement_Report_t, Slot[4].I_LEVEL, 6),

  M_NEXT_EXIST (EXT_Measurement_Report_t, Slot[5].Exist, 1),
  M_UINT       (EXT_Measurement_Report_t, Slot[5].I_LEVEL, 6),

  M_NEXT_EXIST (EXT_Measurement_Report_t, Slot[6].Exist, 1),
  M_UINT       (EXT_Measurement_Report_t, Slot[6].I_LEVEL, 6),

  M_NEXT_EXIST (EXT_Measurement_Report_t, Slot[7].Exist, 1),
  M_UINT       (EXT_Measurement_Report_t, Slot[7].I_LEVEL, 6),

  M_UINT       (EXT_Measurement_Report_t, NUMBER_OF_EXT_MEASUREMENTS_v, 5),
  M_VAR_TARRAY (EXT_Measurement_Report_t, EXT_Measurements, NC_Measurements_t, NUMBER_OF_EXT_MEASUREMENTS_v),
CSN_DESCR_END  (EXT_Measurement_Report_t)

static const
CSN_DESCR_BEGIN (Measurements_3G_t)
  M_UINT          (Measurements_3G_t, CELL_LIST_INDEX_3G_v, 7),
  M_UINT          (Measurements_3G_t, REPORTING_QUANTITY_v, 6),
CSN_DESCR_END   (Measurements_3G_t)

static const
CSN_DESCR_BEGIN (PMR_AdditionsR99_t)
  M_NEXT_EXIST  (PMR_AdditionsR99_t, Exist_Info3G, 4),
  M_UNION       (PMR_AdditionsR99_t, 2),
  M_TYPE        (PMR_AdditionsR99_t, u.BA_USED, BA_USED_t),
  M_UINT        (PMR_AdditionsR99_t, u.PSI3_CHANGE_MARK_v, 2),
  M_UINT        (PMR_AdditionsR99_t, PMO_USED_v, 1),

  M_NEXT_EXIST  (PMR_AdditionsR99_t, Exist_MeasurementReport3G, 2),
  M_UINT_OFFSET (PMR_AdditionsR99_t, N_3G_v, 3, 1),   /* offset 1 */
  M_VAR_TARRAY_OFFSET  (PMR_AdditionsR99_t, Measurements_3G, Measurements_3G_t, N_3G_v),
CSN_DESCR_END   (PMR_AdditionsR99_t)

static const
CSN_DESCR_BEGIN(EMR_ServingCell_t)
  /*CSN_MEMBER_BIT (EMR_ServingCell_t, DTX_USED),*/
  M_BIT          (EMR_ServingCell_t, DTX_USED),
  M_UINT         (EMR_ServingCell_t, RXLEV_VAL,       6),
  M_UINT         (EMR_ServingCell_t, RX_QUAL_FULL,    3),
  M_UINT         (EMR_ServingCell_t, MEAN_BEP,        5),
  M_UINT         (EMR_ServingCell_t, CV_BEP,          3),
  M_UINT         (EMR_ServingCell_t, NBR_RCVD_BLOCKS, 5),
CSN_DESCR_END(EMR_ServingCell_t)

static const
CSN_DESCR_BEGIN   (EnhancedMeasurementReport_t)
  M_UINT          (EnhancedMeasurementReport_t, RR_Short_PD, 1),
  M_UINT          (EnhancedMeasurementReport_t, MESSAGE_TYPE_v, 5),             /* struct, variable, length of bits to be encode  */
  M_UINT          (EnhancedMeasurementReport_t, ShortLayer2_Header, 2),
  M_TYPE          (EnhancedMeasurementReport_t, BA_USED, BA_USED_t),
  M_UINT          (EnhancedMeasurementReport_t, BSIC_Seen, 1),
  M_UINT          (EnhancedMeasurementReport_t, SCALE, 1),
  M_NEXT_EXIST    (EnhancedMeasurementReport_t, Exist_ServingCellData, 1),
  M_TYPE          (EnhancedMeasurementReport_t, ServingCellData, EMR_ServingCell_t),
  M_REC_TARRAY    (EnhancedMeasurementReport_t, RepeatedInvalid_BSIC_Info[0], RepeatedInvalid_BSIC_Info_t,
                    Count_RepeatedInvalid_BSIC_Info),
  M_NEXT_EXIST    (EnhancedMeasurementReport_t, Exist_ReportBitmap, 1),
  M_VAR_TARRAY    (EnhancedMeasurementReport_t, REPORTING_QUANTITY_Instances, REPORTING_QUANTITY_Instance_t, Count_REPORTING_QUANTITY_Instances),
CSN_DESCR_END     (EnhancedMeasurementReport_t)

static const
CSN_DESCR_BEGIN       (Packet_Measurement_Report_t)
  /* Mac header */
  M_UINT              (Packet_Measurement_Report_t, PayloadType, 2),
  M_UINT              (Packet_Measurement_Report_t, spare, 5),
  M_UINT              (Packet_Measurement_Report_t, R, 1),
  M_UINT              (Packet_Measurement_Report_t, MESSAGE_TYPE_v, 6),
  /* Mac header */

  M_UINT              (Packet_Measurement_Report_t, TLLI_v, 32),

  M_NEXT_EXIST        (Packet_Measurement_Report_t, Exist_PSI5_CHANGE_MARK_v, 1),
  M_UINT              (Packet_Measurement_Report_t, PSI5_CHANGE_MARK_v, 2),

  M_UNION             (Packet_Measurement_Report_t, 2),
  M_TYPE              (Packet_Measurement_Report_t, u.NC_Measurement_Report, NC_Measurement_Report_t),
  M_TYPE              (Packet_Measurement_Report_t, u.EXT_Measurement_Report, EXT_Measurement_Report_t),

  M_NEXT_EXIST_OR_NULL(Packet_Measurement_Report_t, Exist_AdditionsR99, 1),
  M_TYPE              (Packet_Measurement_Report_t, AdditionsR99, PMR_AdditionsR99_t),
CSN_DESCR_END         (Packet_Measurement_Report_t)

static const
CSN_DESCR_BEGIN       (Packet_Enh_Measurement_Report_t)
  /* Mac header */
  M_UINT              (Packet_Enh_Measurement_Report_t, PayloadType, 2),
  M_UINT              (Packet_Enh_Measurement_Report_t, spare, 5),
  M_UINT              (Packet_Enh_Measurement_Report_t, R, 1),
  M_UINT              (Packet_Enh_Measurement_Report_t, MESSAGE_TYPE_v, 6),
  /* Mac header */

  M_UINT              (Packet_Enh_Measurement_Report_t, TLLI_v, 32),

  M_TYPE              (Packet_Enh_Measurement_Report_t, Measurements, ENH_NC_Measurement_Report_t),
CSN_DESCR_END         (Packet_Enh_Measurement_Report_t)

/*< Packet Measurement Order message contents >*/
static const
CSN_DESCR_BEGIN(EXT_Frequency_List_t)
  M_UINT       (EXT_Frequency_List_t, START_FREQUENCY_v, 10),
  M_UINT       (EXT_Frequency_List_t, NR_OF_FREQUENCIES_v, 5),
  M_UINT       (EXT_Frequency_List_t, FREQ_DIFF_LENGTH_v, 3),

/* TBD: Count_FREQUENCY_DIFF
 * guint8 FREQUENCY_DIFF[31];
 * bit (FREQ_DIFF_LENGTH) * NR_OF_FREQUENCIES --> MAX is bit(7) * 31
 */
CSN_DESCR_END  (EXT_Frequency_List_t)

static const
CSN_DESCR_BEGIN        (Packet_Measurement_Order_t)
  M_UINT               (Packet_Measurement_Order_t, MESSAGE_TYPE_v, 6),
  M_UINT               (Packet_Measurement_Order_t, PAGE_MODE_v, 2),

  M_TYPE               (Packet_Measurement_Order_t, ID, PacketDownlinkID_t), /* reuse the PDA ID type */

  M_UINT               (Packet_Measurement_Order_t, PMO_INDEX_v, 3),
  M_UINT               (Packet_Measurement_Order_t, PMO_COUNT_v, 3),

  M_NEXT_EXIST         (Packet_Measurement_Order_t, Exist_NC_Measurement_Parameters, 1),
  M_TYPE               (Packet_Measurement_Order_t, NC_Measurement_Parameters, NC_Measurement_Parameters_with_Frequency_List_t),

  M_NEXT_EXIST         (Packet_Measurement_Order_t, Exist_EXT_Measurement_Parameters, 1),
  M_FIXED              (Packet_Measurement_Order_t, 2, 0x0),    /* EXT_Measurement_Parameters not handled */

  M_NEXT_EXIST_OR_NULL (Packet_Measurement_Order_t, Exist_AdditionsR98, 1),
  M_TYPE               (Packet_Measurement_Order_t, AdditionsR98, PMO_AdditionsR98_t),
CSN_DESCR_END          (Packet_Measurement_Order_t)

static const
CSN_DESCR_BEGIN(Packet_Measurement_Order_Reduced_t)
  M_UINT       (Packet_Measurement_Order_Reduced_t, MESSAGE_TYPE_v, 6),
  M_UINT       (Packet_Measurement_Order_Reduced_t, PAGE_MODE_v, 2),

  M_TYPE       (Packet_Measurement_Order_Reduced_t, ID, PacketDownlinkID_t), /* reuse the PDA ID type */

CSN_DESCR_END  (Packet_Measurement_Order_Reduced_t)

static const
CSN_DESCR_BEGIN(CCN_Measurement_Report_t)
  M_UINT       (CCN_Measurement_Report_t, RXLEV_SERVING_CELL_v, 6),
  M_FIXED      (CCN_Measurement_Report_t, 1, 0),
  M_UINT       (CCN_Measurement_Report_t, NUMBER_OF_NC_MEASUREMENTS_v, 3),
  M_VAR_TARRAY (CCN_Measurement_Report_t, NC_Measurements, NC_Measurements_t, NUMBER_OF_NC_MEASUREMENTS_v),
CSN_DESCR_END  (CCN_Measurement_Report_t)

static const
CSN_DESCR_BEGIN(Target_Cell_GSM_Notif_t)
  M_UINT       (Target_Cell_GSM_Notif_t, ARFCN_v, 10),
  M_UINT       (Target_Cell_GSM_Notif_t, BSIC_v, 6),
CSN_DESCR_END  (Target_Cell_GSM_Notif_t)

static const
CSN_DESCR_BEGIN(FDD_Target_Cell_Notif_t)
  M_UINT       (FDD_Target_Cell_Notif_t, FDD_ARFCN_v, 14),
  M_NEXT_EXIST (FDD_Target_Cell_Notif_t, Exist_Bandwith_FDD, 1),
  M_UINT       (FDD_Target_Cell_Notif_t, BANDWITH_FDD_v, 3),
  M_UINT       (FDD_Target_Cell_Notif_t, SCRAMBLING_CODE_v, 9),
CSN_DESCR_END  (FDD_Target_Cell_Notif_t)

static const
CSN_DESCR_BEGIN(Target_Cell_3G_Notif_t)
  /* 0 -- escape bit */
  M_FIXED      (Target_Cell_3G_Notif_t, 1, 0),
  M_NEXT_EXIST (Target_Cell_3G_Notif_t, Exist_FDD_Description, 1),
  M_TYPE       (Target_Cell_3G_Notif_t, FDD_Target_Cell_Notif, FDD_Target_Cell_Notif_t),
  M_NEXT_EXIST (Target_Cell_3G_Notif_t, Exist_TDD_Description, 1),
  M_TYPE       (Target_Cell_3G_Notif_t, TDD_Target_Cell, TDD_Target_Cell_t),  /* not implemented */
  M_UINT       (Target_Cell_3G_Notif_t, REPORTING_QUANTITY_v, 6),
CSN_DESCR_END  (Target_Cell_3G_Notif_t)

static const
CSN_DESCR_BEGIN(Target_Cell_t)
  M_UNION      (Target_Cell_t, 2),
  M_TYPE       (Target_Cell_t, u.Target_Cell_GSM_Notif, Target_Cell_GSM_Notif_t),
  M_TYPE       (Target_Cell_t, u.Target_Cell_3G_Notif, Target_Cell_3G_Notif_t),
CSN_DESCR_END  (Target_Cell_t)

static const
CSN_DESCR_BEGIN (PCCN_AdditionsR6_t)
  M_NEXT_EXIST  (PCCN_AdditionsR6_t, Exist_BA_USED_3G, 1),
  M_UINT        (PCCN_AdditionsR6_t, BA_USED_3G_v, 1),

  M_UINT_OFFSET (PCCN_AdditionsR6_t, N_3G_v, 3, 1),   /* offset 1 */
  M_VAR_TARRAY_OFFSET (PCCN_AdditionsR6_t, Measurements_3G, Measurements_3G_t, N_3G_v),
CSN_DESCR_END   (PCCN_AdditionsR6_t)

/*< Packet Cell Change Notification message contents > */
static const
CSN_DESCR_BEGIN(Packet_Cell_Change_Notification_t)
  /* Mac header */
  M_UINT              (Packet_Cell_Change_Notification_t, PayloadType, 2),
  M_UINT              (Packet_Cell_Change_Notification_t, spare, 5),
  M_UINT              (Packet_Cell_Change_Notification_t, R, 1),
  M_UINT              (Packet_Cell_Change_Notification_t, MESSAGE_TYPE_v, 6),
  /* Mac header */

  M_TYPE              (Packet_Cell_Change_Notification_t, Global_TFI, Global_TFI_t),
  M_TYPE              (Packet_Cell_Change_Notification_t, Target_Cell, Target_Cell_t),

  M_UNION             (Packet_Cell_Change_Notification_t, 2),
  M_UINT              (Packet_Cell_Change_Notification_t, u.BA_IND_v, 1),
  M_UINT              (Packet_Cell_Change_Notification_t, u.PSI3_CHANGE_MARK_v, 2),

  M_UINT              (Packet_Cell_Change_Notification_t, PMO_USED_v, 1),
  M_UINT              (Packet_Cell_Change_Notification_t, PCCN_SENDING, 1),
  M_TYPE              (Packet_Cell_Change_Notification_t, CCN_Measurement_Report, CCN_Measurement_Report_t),

  M_NEXT_EXIST_OR_NULL(Packet_Cell_Change_Notification_t, Exist_AdditionsR6, 1),
  M_TYPE              (Packet_Cell_Change_Notification_t, AdditionsR6, PCCN_AdditionsR6_t),
CSN_DESCR_END  (Packet_Cell_Change_Notification_t)

/*< Packet Cell Change Continue message contents > */
static const
CSN_DESCR_BEGIN(Packet_Cell_Change_Continue_t)
  M_UINT       (Packet_Cell_Change_Continue_t, MESSAGE_TYPE_v, 6),
  M_UINT       (Packet_Cell_Change_Continue_t, PAGE_MODE_v, 2),
  M_FIXED      (Packet_Cell_Change_Continue_t, 1, 0x00),
  M_TYPE       (Packet_Cell_Change_Continue_t, Global_TFI, Global_TFI_t),

  M_NEXT_EXIST (Packet_Cell_Change_Continue_t, Exist_ID, 3),
  M_UINT       (Packet_Cell_Change_Continue_t, ARFCN_v,10),
  M_UINT       (Packet_Cell_Change_Continue_t, BSIC_v, 6),
  M_UINT       (Packet_Cell_Change_Continue_t, CONTAINER_ID_v, 2),
CSN_DESCR_END  (Packet_Cell_Change_Continue_t)

/*< Packet Neighbour Cell Data message contents > */
static const
CSN_DESCR_BEGIN(PNCD_Container_With_ID_t)
  M_UINT       (PNCD_Container_With_ID_t, ARFCN_v,10),
  M_UINT       (PNCD_Container_With_ID_t, BSIC_v, 6),
  M_UINT_ARRAY (PNCD_Container_With_ID_t, CONTAINER, 8, 17),/* 8*17 bits */
CSN_DESCR_END  (PNCD_Container_With_ID_t)

static const
CSN_DESCR_BEGIN(PNCD_Container_Without_ID_t)
  M_UINT_ARRAY (PNCD_Container_Without_ID_t, CONTAINER, 8, 19),/* 8*19 bits */
CSN_DESCR_END  (PNCD_Container_Without_ID_t)

static const
CSN_ChoiceElement_t PNCDContainer[] =
{
  {1, 0x0, M_TYPE(PNCDContainer_t, u.PNCD_Container_Without_ID, PNCD_Container_Without_ID_t)},
  {1, 0x1, M_TYPE(PNCDContainer_t, u.PNCD_Container_With_ID, PNCD_Container_With_ID_t)},
};

static const
CSN_DESCR_BEGIN(PNCDContainer_t)
  M_CHOICE     (PNCDContainer_t, UnionType, PNCDContainer, ElementsOf(PNCDContainer)),
CSN_DESCR_END  (PNCDContainer_t)

static const
CSN_DESCR_BEGIN(Packet_Neighbour_Cell_Data_t)
  M_UINT       (Packet_Neighbour_Cell_Data_t, MESSAGE_TYPE_v, 6),
  M_UINT       (Packet_Neighbour_Cell_Data_t, PAGE_MODE_v, 2),
  M_FIXED      (Packet_Neighbour_Cell_Data_t, 1, 0x00),
  M_TYPE       (Packet_Neighbour_Cell_Data_t, Global_TFI, Global_TFI_t),

  M_UINT       (Packet_Neighbour_Cell_Data_t, CONTAINER_ID_v, 2),
  M_UINT       (Packet_Neighbour_Cell_Data_t, spare, 1),
  M_UINT       (Packet_Neighbour_Cell_Data_t, CONTAINER_INDEX_v, 5),

  M_TYPE       (Packet_Neighbour_Cell_Data_t, Container, PNCDContainer_t),
CSN_DESCR_END  (Packet_Neighbour_Cell_Data_t)

/*< Packet Serving Cell Data message contents > */
static const
CSN_DESCR_BEGIN(Packet_Serving_Cell_Data_t)
  M_UINT       (Packet_Serving_Cell_Data_t, MESSAGE_TYPE_v, 6),
  M_UINT       (Packet_Serving_Cell_Data_t, PAGE_MODE_v, 2),
  M_FIXED      (Packet_Serving_Cell_Data_t, 1, 0x00),
  M_TYPE       (Packet_Serving_Cell_Data_t, Global_TFI, Global_TFI_t),

  M_UINT       (Packet_Serving_Cell_Data_t, spare, 4),
  M_UINT       (Packet_Serving_Cell_Data_t, CONTAINER_INDEX_v, 5),
  M_UINT_ARRAY (Packet_Serving_Cell_Data_t, CONTAINER, 8, 19),/* 8*19 bits */
CSN_DESCR_END  (Packet_Serving_Cell_Data_t)


/* Enhanced Measurement Report */
static const
CSN_DESCR_BEGIN (ServingCellData_t)
  M_UINT        (ServingCellData_t, RXLEV_SERVING_CELL, 6),
  M_FIXED       (ServingCellData_t, 1, 0),
CSN_DESCR_END   (ServingCellData_t)

static const
CSN_DESCR_BEGIN (Repeated_Invalid_BSIC_Info_t)
  M_UINT        (Repeated_Invalid_BSIC_Info_t, BCCH_FREQ_NCELL, 5),
  M_UINT        (Repeated_Invalid_BSIC_Info_t, BSIC, 6),
  M_UINT        (Repeated_Invalid_BSIC_Info_t, RXLEV_NCELL, 5),
CSN_DESCR_END   (Repeated_Invalid_BSIC_Info_t)

static const
CSN_DESCR_BEGIN (REPORTING_QUANTITY_t)
  M_NEXT_EXIST  (REPORTING_QUANTITY_t, Exist_REPORTING_QUANTITY, 1),
  M_UINT        (REPORTING_QUANTITY_t, REPORTING_QUANTITY, 6),
CSN_DESCR_END   (REPORTING_QUANTITY_t)


static const
CSN_DESCR_BEGIN (NC_MeasurementReport_t)
  M_BIT         (NC_MeasurementReport_t, NC_MODE),
  M_UNION       (NC_MeasurementReport_t, 2),
  M_TYPE        (NC_MeasurementReport_t, u.BA_USED, BA_USED_t),
  M_UINT        (NC_MeasurementReport_t, u.PSI3_CHANGE_MARK, 2),
  M_BIT         (NC_MeasurementReport_t, PMO_USED),
  M_BIT         (NC_MeasurementReport_t, SCALE),

  M_NEXT_EXIST  (NC_MeasurementReport_t, Exist_ServingCellData, 1),
  M_TYPE        (NC_MeasurementReport_t, ServingCellData, ServingCellData_t),

  M_REC_TARRAY  (NC_MeasurementReport_t, Repeated_Invalid_BSIC_Info, Repeated_Invalid_BSIC_Info_t, Count_Repeated_Invalid_BSIC_Info),

  M_NEXT_EXIST  (NC_MeasurementReport_t, Exist_Repeated_REPORTING_QUANTITY, 1),
  M_VAR_TARRAY  (NC_MeasurementReport_t, Repeated_REPORTING_QUANTITY, REPORTING_QUANTITY_t, Count_Repeated_Reporting_Quantity),
CSN_DESCR_END   (NC_MeasurementReport_t)



/*< Packet Handover Command message content > */
static const
CSN_DESCR_BEGIN (GlobalTimeslotDescription_t)
  M_UNION       (GlobalTimeslotDescription_t, 2),
  M_UINT        (GlobalTimeslotDescription_t, u.MS_TimeslotAllocation, 8),
  M_TYPE        (GlobalTimeslotDescription_t, u.Power_Control_Parameters, Power_Control_Parameters_t),
CSN_DESCR_END   (GlobalTimeslotDescription_t)

static const
CSN_DESCR_BEGIN (PHO_DownlinkAssignment_t)
  M_UINT        (PHO_DownlinkAssignment_t, TimeslotAllocation, 8),
  M_UINT        (PHO_DownlinkAssignment_t, PFI, 7),
  M_BIT         (PHO_DownlinkAssignment_t, RLC_Mode),
  M_UINT        (PHO_DownlinkAssignment_t, TFI_Assignment, 5),
  M_BIT         (PHO_DownlinkAssignment_t, ControlACK),

  M_NEXT_EXIST  (PHO_DownlinkAssignment_t, Exist_EGPRS_WindowSize, 1),
  M_UINT        (PHO_DownlinkAssignment_t, EGPRS_WindowSize, 5),
CSN_DESCR_END   (PHO_DownlinkAssignment_t)

static const
CSN_DESCR_BEGIN (PHO_USF_1_7_t)
  M_NEXT_EXIST  (PHO_USF_1_7_t, Exist_USF, 1),
  M_UINT        (PHO_USF_1_7_t, USF, 3),
CSN_DESCR_END   (PHO_USF_1_7_t)

static const
CSN_DESCR_BEGIN       (USF_AllocationArray_t)
  M_UINT              (USF_AllocationArray_t, USF_0, 3),
  M_VAR_TARRAY_OFFSET (USF_AllocationArray_t, USF_1_7, PHO_USF_1_7_t, NBR_OfAllocatedTimeslots),
CSN_DESCR_END         (USF_AllocationArray_t)

static const
CSN_DESCR_BEGIN  (PHO_UplinkAssignment_t)
  M_UINT         (PHO_UplinkAssignment_t, PFI, 7),
  M_BIT          (PHO_UplinkAssignment_t, RLC_Mode),
  M_UINT         (PHO_UplinkAssignment_t, TFI_Assignment, 5),

  M_NEXT_EXIST   (PHO_UplinkAssignment_t, Exist_ChannelCodingCommand, 1),
  M_UINT         (PHO_UplinkAssignment_t, ChannelCodingCommand, 2),

  M_NEXT_EXIST   (PHO_UplinkAssignment_t, Exist_EGPRS_ChannelCodingCommand, 1),
  M_UINT         (PHO_UplinkAssignment_t, EGPRS_ChannelCodingCommand, 4),

  M_NEXT_EXIST   (PHO_UplinkAssignment_t, Exist_EGPRS_WindowSize, 1),
  M_UINT         (PHO_UplinkAssignment_t, EGPRS_WindowSize, 5),

  M_BIT          (PHO_UplinkAssignment_t, USF_Granularity),

  M_NEXT_EXIST   (PHO_UplinkAssignment_t, Exist_TBF_TimeslotAllocation, 1),
  M_LEFT_VAR_BMP (PHO_UplinkAssignment_t, TBF_TimeslotAllocation, u.USF_AllocationArray.NBR_OfAllocatedTimeslots, 0),

  M_UNION        (PHO_UplinkAssignment_t, 2),
  M_UINT         (PHO_UplinkAssignment_t, u.USF_SingleAllocation, 3),
  M_TYPE         (PHO_UplinkAssignment_t, u.USF_AllocationArray, USF_AllocationArray_t),
CSN_DESCR_END    (PHO_UplinkAssignment_t)

static const
CSN_DESCR_BEGIN (GlobalTimeslotDescription_UA_t)
  M_TYPE        (GlobalTimeslotDescription_UA_t, GlobalTimeslotDescription, GlobalTimeslotDescription_t),
  M_NEXT_EXIST  (GlobalTimeslotDescription_UA_t, Exist_PHO_UA, 3),  /* Don't use M_REC_TARRAY as we don't support multiple TBFs */

  M_TYPE        (GlobalTimeslotDescription_UA_t, PHO_UA, PHO_UplinkAssignment_t),
  M_FIXED       (GlobalTimeslotDescription_UA_t, 1, 0x0), /* Escape recursive */
CSN_DESCR_END   (GlobalTimeslotDescription_UA_t)

static const
CSN_DESCR_BEGIN (PHO_GPRS_t)
  M_NEXT_EXIST  (PHO_GPRS_t, Exist_ChannelCodingCommand, 1),
  M_UINT        (PHO_GPRS_t, ChannelCodingCommand, 2),

  M_NEXT_EXIST  (PHO_GPRS_t, Exist_GlobalTimeslotDescription_UA, 1),
  M_TYPE        (PHO_GPRS_t, GTD_UA, GlobalTimeslotDescription_UA_t),

  M_NEXT_EXIST  (PHO_GPRS_t, Exist_DownlinkAssignment, 2),  /* Don't use M_REC_TARRAY as we don't support multiple TBFs */
  M_TYPE        (PHO_GPRS_t, DownlinkAssignment, PHO_DownlinkAssignment_t),
  M_FIXED       (PHO_GPRS_t, 1, 0x0), /* Escape recursive */
CSN_DESCR_END   (PHO_GPRS_t)

static const
CSN_DESCR_BEGIN (EGPRS_Description_t)
  M_NEXT_EXIST  (EGPRS_Description_t, Exist_EGPRS_WindowSize, 1),
  M_UINT        (EGPRS_Description_t, EGPRS_WindowSize, 5),

  M_UINT        (EGPRS_Description_t, LinkQualityMeasurementMode, 2),
  M_NEXT_EXIST  (EGPRS_Description_t, Exist_BEP_Period2, 1),
  M_UINT        (EGPRS_Description_t, BEP_Period2, 4),
CSN_DESCR_END   (EGPRS_Description_t)

static const
CSN_DESCR_BEGIN (DownlinkTBF_t)
  M_NEXT_EXIST  (DownlinkTBF_t, Exist_EGPRS_Description, 1),
  M_TYPE        (DownlinkTBF_t, EGPRS_Description, EGPRS_Description_t),

  M_NEXT_EXIST  (DownlinkTBF_t, Exist_DownlinkAssignment, 2),  /* Don't use M_REC_TARRAY as we don't support multiple TBFs */
  M_TYPE        (DownlinkTBF_t, DownlinkAssignment, PHO_DownlinkAssignment_t),
  M_FIXED       (DownlinkTBF_t, 1, 0x0), /* Escape recursive */
CSN_DESCR_END   (DownlinkTBF_t)

static const
CSN_DESCR_BEGIN (PHO_EGPRS_t)
  M_NEXT_EXIST  (PHO_EGPRS_t, Exist_EGPRS_WindowSize, 1),
  M_UINT        (PHO_EGPRS_t, EGPRS_WindowSize, 5),

  M_NEXT_EXIST  (PHO_EGPRS_t, Exist_EGPRS_ChannelCodingCommand, 1),
  M_UINT        (PHO_EGPRS_t, EGPRS_ChannelCodingCommand, 4),

  M_NEXT_EXIST  (PHO_EGPRS_t, Exist_BEP_Period2, 1),
  M_UINT        (PHO_EGPRS_t, BEP_Period2, 4),

  M_NEXT_EXIST  (PHO_EGPRS_t, Exist_GlobalTimeslotDescription_UA, 1),
  M_TYPE        (PHO_EGPRS_t, GTD_UA, GlobalTimeslotDescription_UA_t),

  M_NEXT_EXIST  (PHO_EGPRS_t, Exist_DownlinkTBF, 2),
  M_TYPE        (PHO_EGPRS_t, DownlinkTBF, DownlinkTBF_t),
CSN_DESCR_END   (PHO_EGPRS_t)

static const
CSN_DESCR_BEGIN(PHO_TimingAdvance_t)
  M_TYPE       (PHO_TimingAdvance_t, GlobalPacketTimingAdvance, Global_Packet_Timing_Advance_t),
  M_NEXT_EXIST (PHO_TimingAdvance_t, Exist_PacketExtendedTimingAdvance, 1),
  M_UINT       (PHO_TimingAdvance_t, PacketExtendedTimingAdvance, 2),
CSN_DESCR_END  (PHO_TimingAdvance_t)

static const
CSN_DESCR_BEGIN(NAS_Container_t)
  M_UINT       (NAS_Container_t, NAS_ContainerLength, 7),
  M_VAR_ARRAY  (NAS_Container_t, NAS_Container, NAS_ContainerLength, 0),
CSN_DESCR_END  (NAS_Container_t)

static const
CSN_DESCR_BEGIN(PS_HandoverTo_UTRAN_Payload_t)
  M_UINT       (PS_HandoverTo_UTRAN_Payload_t, RRC_ContainerLength, 8),
  M_VAR_ARRAY  (PS_HandoverTo_UTRAN_Payload_t, RRC_Container, RRC_ContainerLength, 0),
CSN_DESCR_END  (PS_HandoverTo_UTRAN_Payload_t)


static const
CSN_DESCR_BEGIN(PHO_RadioResources_t)
  M_NEXT_EXIST (PHO_RadioResources_t, Exist_HandoverReference, 1),
  M_UINT       (PHO_RadioResources_t, HandoverReference, 8),

  M_UINT       (PHO_RadioResources_t, ARFCN, 10),
  M_UINT       (PHO_RadioResources_t, SI, 2),
  M_BIT        (PHO_RadioResources_t, NCI),
  M_UINT       (PHO_RadioResources_t, BSIC, 6),
  M_NEXT_EXIST (PHO_RadioResources_t, Exist_CCN_Active, 1),
  M_BIT        (PHO_RadioResources_t, CCN_Active),

  M_NEXT_EXIST (PHO_RadioResources_t, Exist_CCN_Active_3G, 1),
  M_BIT        (PHO_RadioResources_t, CCN_Active_3G),

  M_NEXT_EXIST (PHO_RadioResources_t, Exist_CCN_Support_Description, 1),
  M_TYPE       (PHO_RadioResources_t, CCN_Support_Description, CCN_Support_Description_t),

  M_TYPE       (PHO_RadioResources_t, Frequency_Parameters, Frequency_Parameters_t),
  M_UINT       (PHO_RadioResources_t, NetworkControlOrder, 2),
  M_NEXT_EXIST (PHO_RadioResources_t, Exist_PHO_TimingAdvance, 1),
  M_TYPE       (PHO_RadioResources_t, PHO_TimingAdvance, PHO_TimingAdvance_t),

  M_BIT        (PHO_RadioResources_t, Extended_Dynamic_Allocation),
  M_BIT        (PHO_RadioResources_t, RLC_Reset),
  M_NEXT_EXIST (PHO_RadioResources_t, Exist_PO_PR, 2),
  M_UINT       (PHO_RadioResources_t, PO, 4),
  M_BIT        (PHO_RadioResources_t, PR_Mode),


  M_NEXT_EXIST (PHO_RadioResources_t, Exist_UplinkControlTimeslot, 1),
  M_UINT       (PHO_RadioResources_t, UplinkControlTimeslot, 3),

  M_UNION      (PHO_RadioResources_t, 2),
  M_TYPE       (PHO_RadioResources_t, u.PHO_GPRS_Mode, PHO_GPRS_t),
  M_TYPE       (PHO_RadioResources_t, u.PHO_EGPRS_Mode, PHO_EGPRS_t),
CSN_DESCR_END  (PHO_RadioResources_t)

static const
CSN_DESCR_BEGIN(PS_HandoverTo_A_GB_ModePayload_t)
  M_FIXED      (PS_HandoverTo_A_GB_ModePayload_t, 2, 0x00), /* For future extension to enum. */
  M_TYPE       (PS_HandoverTo_A_GB_ModePayload_t, PHO_RadioResources, PHO_RadioResources_t),

  M_NEXT_EXIST (PS_HandoverTo_A_GB_ModePayload_t, Exist_NAS_Container, 1),
  M_TYPE       (PS_HandoverTo_A_GB_ModePayload_t, NAS_Container, NAS_Container_t),
CSN_DESCR_END  (PS_HandoverTo_A_GB_ModePayload_t)

static const
CSN_DESCR_BEGIN(Packet_Handover_Command_t)
  M_UINT       (Packet_Handover_Command_t, MessageType, 6),
  M_UINT       (Packet_Handover_Command_t, PageMode, 2),

  M_FIXED      (Packet_Handover_Command_t, 1, 0x00), /* 0 fixed */
  M_TYPE       (Packet_Handover_Command_t, Global_TFI, Global_TFI_t),

  M_UINT       (Packet_Handover_Command_t, ContainerID, 2),

  M_UNION      (Packet_Handover_Command_t, 4),
  M_TYPE       (Packet_Handover_Command_t, u.PS_HandoverTo_A_GB_ModePayload, PS_HandoverTo_A_GB_ModePayload_t),
  M_TYPE       (Packet_Handover_Command_t, u.PS_HandoverTo_UTRAN_Payload, PS_HandoverTo_UTRAN_Payload_t),
  CSN_ERROR    (Packet_Handover_Command_t, "10 <extension> not implemented", CSN_ERROR_STREAM_NOT_SUPPORTED),
  CSN_ERROR    (Packet_Handover_Command_t, "11 <extension> not implemented", CSN_ERROR_STREAM_NOT_SUPPORTED),
CSN_DESCR_END  (Packet_Handover_Command_t)

typedef Packet_Handover_Command_t PHOCheck_t;

static const
CSN_DESCR_BEGIN(PHOCheck_t)
  M_UINT       (PHOCheck_t, MessageType, 6),
  M_UINT       (PHOCheck_t, PageMode, 2),
  M_FIXED      (PHOCheck_t, 1, 0x00), /* 0 fixed */
  M_TYPE       (PHOCheck_t, Global_TFI, Global_TFI_t),
CSN_DESCR_END  (PHOCheck_t)

/*< End Packet Handover Command >*/

/*< Packet Physical Information message content > */

static const
CSN_DESCR_BEGIN(Packet_PhysicalInformation_t)
  M_UINT       (Packet_PhysicalInformation_t, MessageType, 6),
  M_UINT       (Packet_PhysicalInformation_t, PageMode, 2),

  M_TYPE       (Packet_PhysicalInformation_t, Global_TFI, Global_TFI_t),

  M_UINT       (Packet_PhysicalInformation_t, TimingAdvance, 8),
CSN_DESCR_END  (Packet_PhysicalInformation_t)

/*< End Packet Physical Information > */


typedef char* MT_Strings_t;

static const MT_Strings_t szMT_Downlink[] = {
  "Invalid Message Type",                /* 0x00 */
  "PACKET_CELL_CHANGE_ORDER",            /* 0x01 */
  "PACKET_DOWNLINK_ASSIGNMENT",          /* 0x02 */
  "PACKET_MEASUREMENT_ORDER",            /* 0x03 */
  "PACKET_POLLING_REQUEST",              /* 0x04 */
  "PACKET_POWER_CONTROL_TIMING_ADVANCE", /* 0x05 */
  "PACKET_QUEUEING_NOTIFICATION",        /* 0x06 */
  "PACKET_TIMESLOT_RECONFIGURE",         /* 0x07 */
  "PACKET_TBF_RELEASE",                  /* 0x08 */
  "PACKET_UPLINK_ACK_NACK",              /* 0x09 */
  "PACKET_UPLINK_ASSIGNMENT",            /* 0x0A */
  "PACKET_CELL_CHANGE_CONTINUE",         /* 0x0B */
  "PACKET_NEIGHBOUR_CELL_DATA",          /* 0x0C */
  "PACKET_SERVING_CELL_DATA",            /* 0x0D */
  "Invalid Message Type",                /* 0x0E */
  "Invalid Message Type",                /* 0x0F */
  "Invalid Message Type",                /* 0x10 */
  "Invalid Message Type",                /* 0x11 */
  "Invalid Message Type",                /* 0x12 */
  "Invalid Message Type",                /* 0x13 */
  "Invalid Message Type",                /* 0x14 */
  "PACKET_HANDOVER_COMMAND",             /* 0x15 */
  "PACKET_PHYSICAL_INFORMATION",         /* 0x16 */
  "Invalid Message Type",                /* 0x17 */
  "Invalid Message Type",                /* 0x18 */
  "Invalid Message Type",                /* 0x19 */
  "Invalid Message Type",                /* 0x1A */
  "Invalid Message Type",                /* 0x1B */
  "Invalid Message Type",                /* 0x1C */
  "Invalid Message Type",                /* 0x1D */
  "Invalid Message Type",                /* 0x1E */
  "Invalid Message Type",                /* 0x1F */
  "Invalid Message Type",                /* 0x20 */
  "PACKET_ACCESS_REJECT",                /* 0x21 */
  "PACKET_PAGING_REQUEST",               /* 0x22 */
  "PACKET_PDCH_RELEASE",                 /* 0x23 */
  "PACKET_PRACH_PARAMETERS",             /* 0x24 */
  "PACKET_DOWNLINK_DUMMY_CONTROL_BLOCK", /* 0x25 */
  "Invalid Message Type",                /* 0x26 */
  "Invalid Message Type",                /* 0x27 */
  "Invalid Message Type",                /* 0x28 */
  "Invalid Message Type",                /* 0x29 */
  "Invalid Message Type",                /* 0x2A */
  "Invalid Message Type",                /* 0x2B */
  "Invalid Message Type",                /* 0x2C */
  "Invalid Message Type",                /* 0x2D */
  "Invalid Message Type",                /* 0x2E */
  "Invalid Message Type",                /* 0x2F */
  "PACKET_SYSTEM_INFO_6",                /* 0x30 */
  "PACKET_SYSTEM_INFO_1",                /* 0x31 */
  "PACKET_SYSTEM_INFO_2",                /* 0x32 */
  "PACKET_SYSTEM_INFO_3",                /* 0x33 */
  "PACKET_SYSTEM_INFO_3_BIS",            /* 0x34 */
  "PACKET_SYSTEM_INFO_4",                /* 0x35 */
  "PACKET_SYSTEM_INFO_5",                /* 0x36 */
  "PACKET_SYSTEM_INFO_13",               /* 0x37 */
  "PACKET_SYSTEM_INFO_7",                /* 0x38 */
  "PACKET_SYSTEM_INFO_8",                /* 0x39 */
  "PACKET_SYSTEM_INFO_14",               /* 0x3A */
  "Invalid Message Type",                /* 0x3B */
  "PACKET_SYSTEM_INFO_3_TER",            /* 0x3C */
  "PACKET_SYSTEM_INFO_3_QUATER",         /* 0x3D */
  "PACKET_SYSTEM_INFO_15"                /* 0x3E */
};

static const MT_Strings_t szMT_Uplink[] = {
  "PACKET_CELL_CHANGE_FAILURE",          /* 0x00 */
  "PACKET_CONTROL_ACKNOWLEDGEMENT",      /* 0x01 */
  "PACKET_DOWNLINK_ACK_NACK",            /* 0x02 */
  "PACKET_UPLINK_DUMMY_CONTROL_BLOCK",   /* 0x03 */
  "PACKET_MEASUREMENT_REPORT",           /* 0x04 */
  "PACKET_RESOURCE_REQUEST",             /* 0x05 */
  "PACKET_MOBILE_TBF_STATUS",            /* 0x06 */
  "PACKET_PSI_STATUS",                   /* 0x07 */
  "EGPRS_PACKET_DOWNLINK_ACK_NACK",      /* 0x08 */
  "PACKET_PAUSE",                        /* 0x09 */
  "PACKET_ENHANCED_MEASUREMENT_REPORT",  /* 0x0A */
  "ADDITIONAL_MS_RAC",                   /* 0x0B */
  "PACKET_CELL_CHANGE_NOTIFICATION",     /* 0x0C */
  "PACKET_SI_STATUS",                    /* 0x0D */
};

static char*
MT_DL_TextGet(guint8 mt)
{
  if (mt < ElementsOf(szMT_Downlink))
  {
    return(szMT_Downlink[mt]);
  }
  else
  {
    return("Unknown message type");
  }
}

static char*
MT_UL_TextGet(guint8 mt)
{
  if (mt < ElementsOf(szMT_Uplink))
  {
    return(szMT_Uplink[mt]);
  }
  else
  {
    return("Unknown message type");
  }
}


/* SI1_RestOctet_t */

static const
CSN_DESCR_BEGIN  (SI1_RestOctet_t)
  M_NEXT_EXIST_LH(SI1_RestOctet_t, Exist_NCH_Position, 1),
  M_UINT         (SI1_RestOctet_t, NCH_Position, 5),

  M_UINT_LH      (SI1_RestOctet_t, BandIndicator, 1),
CSN_DESCR_END    (SI1_RestOctet_t)

/* SI3_Rest_Octet_t */
static const
CSN_DESCR_BEGIN(Selection_Parameters_t)
  M_UINT       (Selection_Parameters_t, CBQ_v, 1),
  M_UINT       (Selection_Parameters_t, CELL_RESELECT_OFFSET_v, 6),
  M_UINT       (Selection_Parameters_t, TEMPORARY_OFFSET_v, 3),
  M_UINT       (Selection_Parameters_t, PENALTY_TIME_v, 5),
CSN_DESCR_END  (Selection_Parameters_t)

static const
CSN_DESCR_BEGIN  (SI3_Rest_Octet_t)
  M_NEXT_EXIST_LH(SI3_Rest_Octet_t, Exist_Selection_Parameters, 1),
  M_TYPE         (SI3_Rest_Octet_t, Selection_Parameters, Selection_Parameters_t),

  M_NEXT_EXIST_LH(SI3_Rest_Octet_t, Exist_Power_Offset, 1),
  M_UINT         (SI3_Rest_Octet_t, Power_Offset, 2),

  M_UINT_LH      (SI3_Rest_Octet_t, System_Information_2ter_Indicator, 1),
  M_UINT_LH      (SI3_Rest_Octet_t, Early_Classmark_Sending_Control, 1),

  M_NEXT_EXIST_LH(SI3_Rest_Octet_t, Exist_WHERE_v, 1),
  M_UINT         (SI3_Rest_Octet_t, WHERE_v, 3),

  M_NEXT_EXIST_LH(SI3_Rest_Octet_t, Exist_GPRS_Indicator, 2),
  M_UINT         (SI3_Rest_Octet_t, RA_COLOUR_v, 3),
  M_UINT         (SI3_Rest_Octet_t, SI13_POSITION_v, 1),

  M_UINT_LH      (SI3_Rest_Octet_t, ECS_Restriction3G, 1),

  M_NEXT_EXIST_LH(SI3_Rest_Octet_t, ExistSI2quaterIndicator, 1),
  M_UINT         (SI3_Rest_Octet_t, SI2quaterIndicator, 1),
CSN_DESCR_END    (SI3_Rest_Octet_t)

static const
CSN_DESCR_BEGIN  (SI4_Rest_Octet_t)
  M_NEXT_EXIST_LH(SI4_Rest_Octet_t, Exist_Selection_Parameters, 1),
  M_TYPE         (SI4_Rest_Octet_t, Selection_Parameters, Selection_Parameters_t),

  M_NEXT_EXIST_LH(SI4_Rest_Octet_t, Exist_Power_Offset, 1),
  M_UINT         (SI4_Rest_Octet_t, Power_Offset, 2),

  M_NEXT_EXIST_LH(SI4_Rest_Octet_t, Exist_GPRS_Indicator, 2),
  M_UINT         (SI4_Rest_Octet_t, RA_COLOUR_v, 3),
  M_UINT         (SI4_Rest_Octet_t, SI13_POSITION_v, 1),
CSN_DESCR_END    (SI4_Rest_Octet_t)

/* SI6_RestOctet_t */

static const
CSN_DESCR_BEGIN(PCH_and_NCH_Info_t)
  M_UINT       (PCH_and_NCH_Info_t, PagingChannelRestructuring, 1),
  M_UINT       (PCH_and_NCH_Info_t, NLN_SACCH_v, 2),

  M_NEXT_EXIST (PCH_and_NCH_Info_t, Exist_CallPriority, 1),
  M_UINT       (PCH_and_NCH_Info_t, CallPriority, 3),

  M_UINT       (PCH_and_NCH_Info_t, NLN_Status, 1),
CSN_DESCR_END  (PCH_and_NCH_Info_t)

static const
CSN_DESCR_BEGIN  (SI6_RestOctet_t)
  M_NEXT_EXIST_LH(SI6_RestOctet_t, Exist_PCH_and_NCH_Info, 1),
  M_TYPE         (SI6_RestOctet_t, PCH_and_NCH_Info, PCH_and_NCH_Info_t),

  M_NEXT_EXIST_LH(SI6_RestOctet_t, Exist_VBS_VGCS_Options, 1),
  M_UINT         (SI6_RestOctet_t, VBS_VGCS_Options, 2),

  M_NEXT_EXIST_LH(SI6_RestOctet_t, Exist_DTM_Support, 2),
  M_UINT         (SI6_RestOctet_t, RAC_v, 8),
  M_UINT         (SI6_RestOctet_t, MAX_LAPDm_v, 3),

  M_UINT_LH      (SI6_RestOctet_t, BandIndicator, 1),
CSN_DESCR_END    (SI6_RestOctet_t)

static void
dissect_gsm_rlcmac_uplink(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree)
{
  MSGGPRS_Status_t ret;
  csnStream_t      ar;
  proto_item   *ti;
  proto_tree *rlcmac_tree = NULL;
  guint8 payload_type = tvb_get_bits8(tvb, 0, 2);
  RlcMacUplink_t * data = (RlcMacUplink_t *)ep_alloc(sizeof(RlcMacUplink_t));

  if (payload_type == PAYLOAD_TYPE_DATA)
  {
    ti = proto_tree_add_text(tree, tvb, 0, 1, "Payload Type: DATA (0), not implemented");
    return;
  }
  else if (payload_type == PAYLOAD_TYPE_RESERVED)
  {
    ti = proto_tree_add_text(tree, tvb, 0, 1, "Payload Type: RESERVED (3)");
    return;
  }

  data->NrOfBits = (tvb_length(tvb) - 1) * 8;
  csnStreamInit(&ar, 0, data->NrOfBits);
  data->u.MESSAGE_TYPE_v = tvb_get_bits8(tvb, 8, 6);

  ti = proto_tree_add_text(tree, tvb, 0, 1, "%s (Uplink)", MT_UL_TextGet(data->u.MESSAGE_TYPE_v));
  rlcmac_tree = proto_item_add_subtree(ti, ett_gsm_rlcmac);

  if (check_col(pinfo->cinfo, COL_INFO))
  {
    col_add_str(pinfo->cinfo, COL_INFO,  MT_UL_TextGet(data->u.MESSAGE_TYPE_v));
  }

  switch (data->u.MESSAGE_TYPE_v)
  {
    case MT_PACKET_CELL_CHANGE_FAILURE:
    {
      /*
       * data is the pointer to the unpack struct that hold the unpack value
       * CSNDESCR is an array that holds the different element types
       * ar is the csn context holding the bitcount, offset and output
       */
      ret = csnStreamDissector(rlcmac_tree, &ar, CSNDESCR(Packet_Cell_Change_Failure_t), tvb, &data->u.Packet_Cell_Change_Failure, ett_gsm_rlcmac);
      break;
    }
    case MT_PACKET_CONTROL_ACK:
    {
      ret = csnStreamDissector(rlcmac_tree, &ar, CSNDESCR(Packet_Control_Acknowledgement_t), tvb, &data->u.Packet_Control_Acknowledgement, ett_gsm_rlcmac);
      break;
    }
    case MT_PACKET_DOWNLINK_ACK_NACK:
    {
      ret = csnStreamDissector(rlcmac_tree, &ar, CSNDESCR(Packet_Downlink_Ack_Nack_t), tvb, &data->u.Packet_Downlink_Ack_Nack, ett_gsm_rlcmac);
      break;
    }
    case MT_PACKET_UPLINK_DUMMY_CONTROL_BLOCK:
    {
      ret = csnStreamDissector(rlcmac_tree, &ar, CSNDESCR(Packet_Uplink_Dummy_Control_Block_t), tvb, &data->u.Packet_Uplink_Dummy_Control_Block, ett_gsm_rlcmac);
      break;
    }
    case MT_PACKET_MEASUREMENT_REPORT:
    {
      ret = csnStreamDissector(rlcmac_tree, &ar, CSNDESCR(Packet_Measurement_Report_t), tvb, &data->u.Packet_Measurement_Report, ett_gsm_rlcmac);
      break;
    }
    case MT_PACKET_RESOURCE_REQUEST:
    {
      ret = csnStreamDissector(rlcmac_tree, &ar, CSNDESCR(Packet_Resource_Request_t), tvb, &data->u.Packet_Resource_Request, ett_gsm_rlcmac);
      break;
    }

    case MT_PACKET_MOBILE_TBF_STATUS:
    {
      ret = csnStreamDissector(rlcmac_tree, &ar, CSNDESCR(Packet_Mobile_TBF_Status_t), tvb, &data->u.Packet_Mobile_TBF_Status, ett_gsm_rlcmac);
      break;
    }
    case MT_PACKET_PSI_STATUS:
    {
      ret = csnStreamDissector(rlcmac_tree, &ar, CSNDESCR(Packet_PSI_Status_t), tvb, &data->u.Packet_PSI_Status, ett_gsm_rlcmac);
      break;
    }
    case MT_EGPRS_PACKET_DOWNLINK_ACK_NACK:
    {
      ret = csnStreamDissector(rlcmac_tree, &ar, CSNDESCR(Packet_Downlink_Ack_Nack_t), tvb, &data->u.Packet_Downlink_Ack_Nack, ett_gsm_rlcmac);
      break;
    }
    case MT_PACKET_PAUSE:
    {
      ret = -1;
      break;
    }
    case MT_PACKET_ENHANCED_MEASUREMENT_REPORT:
    {
      ret = csnStreamDissector(rlcmac_tree, &ar, CSNDESCR(Packet_Enh_Measurement_Report_t), tvb, &data->u.Packet_Enh_Measurement_Report, ett_gsm_rlcmac);
      break;
    }
    case MT_ADDITIONAL_MS_RAC:
    {
      ret = -1;
      break;
    }
    case MT_PACKET_CELL_CHANGE_NOTIFICATION:
    {
      ret = csnStreamDissector(rlcmac_tree, &ar, CSNDESCR(Packet_Cell_Change_Notification_t), tvb, &data->u.Packet_Cell_Change_Notification, ett_gsm_rlcmac);
      break;
    }
    case MT_PACKET_SI_STATUS:
    {
      ret = csnStreamDissector(rlcmac_tree, &ar, CSNDESCR(Packet_SI_Status_t), tvb, &data->u.Packet_SI_Status, ett_gsm_rlcmac);
      break;
    }
    default:
      ret = -1;
      break;
  }
}

static void
dissect_gsm_rlcmac_downlink(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree)
{
  csnStream_t  ar;
  proto_item   *ti;
  proto_tree   *rlcmac_tree = NULL;
  RlcMacDownlink_t * data =(RlcMacDownlink_t *) ep_alloc(sizeof(RlcMacDownlink_t));
  MSGGPRS_Status_t ret;

  /* See RLC/MAC downlink control block structure in TS 44.060 / 10.3.1 */
  gint bit_offset = 0;
  gint bit_length;
  guint8 payload_type = tvb_get_bits8(tvb, 0, 2);
  guint8 rbsn = tvb_get_bits8(tvb, 8, 1);
  guint8 fs   = tvb_get_bits8(tvb, 14, 1);
  guint8 ac   = tvb_get_bits8(tvb, 15, 1);

  if (payload_type == PAYLOAD_TYPE_DATA)
  {
    ti = proto_tree_add_text(tree, tvb, 0, 1, "Payload Type: DATA (0), not implemented");
    return;
  }
  else if (payload_type == PAYLOAD_TYPE_RESERVED)
  {
    ti = proto_tree_add_text(tree, tvb, 0, 1, "Payload Type: RESERVED (3)");
    return;
  }
  /* We can decode the message */
  else
  {
    /* First print the message type and create a tree item */
    bit_offset = 8;
    if (payload_type == PAYLOAD_TYPE_CTRL_OPT_OCTET)
    {
      bit_offset += 8;
      if (ac == 1)
      {
        bit_offset += 8;
      }
      if ((rbsn == 1) && (fs == 0))
      {
        bit_offset += 8;
      }
    }
    data->u.MESSAGE_TYPE_v = tvb_get_bits8(tvb, bit_offset, 6);
    ti = proto_tree_add_text(tree, tvb, 0, 1, "%s (downlink)", MT_DL_TextGet(data->u.MESSAGE_TYPE_v));
    rlcmac_tree = proto_item_add_subtree(ti, ett_gsm_rlcmac);

    if (check_col(pinfo->cinfo, COL_INFO))
    {
      col_add_str(pinfo->cinfo, COL_INFO,  MT_DL_TextGet(data->u.MESSAGE_TYPE_v));
    }

    /* Dissect the MAC header */
    proto_tree_add_bits_item(rlcmac_tree, hf_dl_ctrl_payload_type, tvb, 0, 2, FALSE);
    proto_tree_add_bits_item(rlcmac_tree, hf_dl_ctrl_rrbp, tvb, 2, 2, FALSE);
    proto_tree_add_bits_item(rlcmac_tree, hf_dl_ctrl_s_p, tvb, 4, 1, FALSE);
    proto_tree_add_bits_item(rlcmac_tree, hf_dl_ctrl_usf, tvb, 5, 3, FALSE);

    if (payload_type == PAYLOAD_TYPE_CTRL_OPT_OCTET)
    {
      proto_tree_add_bits_item(rlcmac_tree, hf_dl_ctrl_rbsn, tvb, 8, 1, FALSE);
      proto_tree_add_bits_item(rlcmac_tree, hf_dl_ctrl_rti, tvb, 9, 5, FALSE);
      proto_tree_add_bits_item(rlcmac_tree, hf_dl_ctrl_fs, tvb, 14, 1, FALSE);
      proto_tree_add_bits_item(rlcmac_tree, hf_dl_ctrl_ac, tvb, 15, 1, FALSE);

      if (ac == 1) /* Indicates presence of TFI optional octet*/
      {
        proto_tree_add_bits_item(rlcmac_tree, hf_dl_ctrl_pr, tvb, 16, 2, FALSE);
        proto_tree_add_bits_item(rlcmac_tree, hf_dl_ctrl_tfi, tvb, 18, 5, FALSE);
        proto_tree_add_bits_item(rlcmac_tree, hf_dl_ctrl_d, tvb, 23, 1, FALSE);
      }
      if ((rbsn == 1) && (fs == 0)) /* Indicates the presence of optional octet 2/3 */
      {
        proto_tree_add_bits_item(rlcmac_tree, hf_dl_ctrl_rbsn_e, tvb, 16, 2, FALSE);
        proto_tree_add_bits_item(rlcmac_tree, hf_dl_ctrl_tfi, tvb, 18, 5, FALSE);
        proto_tree_add_bits_item(rlcmac_tree, hf_dl_ctrl_d, tvb, 23, 1, FALSE);
      }
    }
  }

  /* Initialize the contexts */
  bit_length = tvb_length(tvb)*8 - bit_offset;

  data->NrOfBits = bit_length;

  csnStreamInit(&ar, bit_offset, bit_length);

  switch (data->u.MESSAGE_TYPE_v)
  {
    case MT_PACKET_ACCESS_REJECT:
    {
      ret = csnStreamDissector(rlcmac_tree, &ar, CSNDESCR(Packet_Access_Reject_t), tvb, &data->u.Packet_Access_Reject, ett_gsm_rlcmac);
      break;
    }
    case MT_PACKET_CELL_CHANGE_ORDER:
    {
      ret = csnStreamDissector(rlcmac_tree, &ar, CSNDESCR(Packet_Cell_Change_Order_t), tvb, &data->u.Packet_Cell_Change_Order, ett_gsm_rlcmac);
      break;
    }
    case MT_PACKET_CELL_CHANGE_CONTINUE:
    {
      ret = csnStreamDissector(rlcmac_tree, &ar, CSNDESCR(Packet_Cell_Change_Continue_t), tvb, &data->u.Packet_Cell_Change_Continue, ett_gsm_rlcmac);
      break;
    }
    case MT_PACKET_DOWNLINK_ASSIGNMENT:
    {
      ret = csnStreamDissector(rlcmac_tree, &ar, CSNDESCR(Packet_Downlink_Assignment_t), tvb, &data->u.Packet_Downlink_Assignment, ett_gsm_rlcmac);
      break;
    }
    case MT_PACKET_MEASUREMENT_ORDER:
    {
      ret = csnStreamDissector(rlcmac_tree, &ar, CSNDESCR(Packet_Measurement_Order_t), tvb, &data->u.Packet_Measurement_Order, ett_gsm_rlcmac);
      break;
    }
    case MT_PACKET_NEIGHBOUR_CELL_DATA:
    {
      ret = csnStreamDissector(rlcmac_tree, &ar, CSNDESCR(Packet_Neighbour_Cell_Data_t), tvb, &data->u.Packet_Neighbour_Cell_Data, ett_gsm_rlcmac);
      break;
    }
    case MT_PACKET_SERVING_CELL_DATA:
    {
      ret = csnStreamDissector(rlcmac_tree, &ar, CSNDESCR(Packet_Serving_Cell_Data_t), tvb, &data->u.Packet_Serving_Cell_Data, ett_gsm_rlcmac);
      break;
    }
    case MT_PACKET_PAGING_REQUEST:
    {
      ret = csnStreamDissector(rlcmac_tree, &ar, CSNDESCR(Packet_Paging_Request_t), tvb, &data->u.Packet_Paging_Request, ett_gsm_rlcmac);
      break;
    }
    case MT_PACKET_PDCH_RELEASE:
    {
      ret = csnStreamDissector(rlcmac_tree, &ar, CSNDESCR(Packet_PDCH_Release_t), tvb, &data->u.Packet_PDCH_Release, ett_gsm_rlcmac);
      break;
    }
    case MT_PACKET_POLLING_REQ:
    {
      ret = csnStreamDissector(rlcmac_tree, &ar, CSNDESCR(Packet_Polling_Request_t), tvb, &data->u.Packet_Polling_Request, ett_gsm_rlcmac);
      break;
    }
    case MT_PACKET_POWER_CONTROL_TIMING_ADVANCE:
    {
      ret = csnStreamDissector(rlcmac_tree, &ar, CSNDESCR(Packet_Power_Control_Timing_Advance_t), tvb, &data->u.Packet_Power_Control_Timing_Advance, ett_gsm_rlcmac);
      break;
    }
    case MT_PACKET_PRACH_PARAMETERS:
    {
      ret = csnStreamDissector(rlcmac_tree, &ar, CSNDESCR(Packet_PRACH_Parameters_t), tvb, &data->u.Packet_PRACH_Parameters, ett_gsm_rlcmac);
      break;
    }
    case MT_PACKET_QUEUEING_NOTIFICATION:
    {
      ret = csnStreamDissector(rlcmac_tree, &ar, CSNDESCR(Packet_Queueing_Notification_t), tvb, &data->u.Packet_Queueing_Notification, ett_gsm_rlcmac);
      break;
    }
    case MT_PACKET_TIMESLOT_RECONFIGURE:
    {
      ret = csnStreamDissector(rlcmac_tree, &ar, CSNDESCR(Packet_Timeslot_Reconfigure_t), tvb, &data->u.Packet_Timeslot_Reconfigure, ett_gsm_rlcmac);
      break;
    }
    case MT_PACKET_TBF_RELEASE:
    {
      ret = csnStreamDissector(rlcmac_tree, &ar, CSNDESCR(Packet_TBF_Release_t), tvb, &data->u.Packet_TBF_Release, ett_gsm_rlcmac);
      break;
    }
    case MT_PACKET_UPLINK_ACK_NACK:
    {
      ret = csnStreamDissector(rlcmac_tree, &ar, CSNDESCR(Packet_Uplink_Ack_Nack_t), tvb, &data->u.Packet_Uplink_Ack_Nack, ett_gsm_rlcmac);
      break;
    }
    case MT_PACKET_UPLINK_ASSIGNMENT:
    {
      ret = csnStreamDissector(rlcmac_tree, &ar, CSNDESCR(Packet_Uplink_Assignment_t), tvb, &data->u.Packet_Uplink_Assignment, ett_gsm_rlcmac);
      break;
    }
    case MT_PACKET_HANDOVER_COMMAND:
    {
      ret = csnStreamDissector(rlcmac_tree, &ar, CSNDESCR(Packet_Handover_Command_t), tvb, &data->u.Packet_Handover_Command, ett_gsm_rlcmac);
      break;
    }
    case MT_PACKET_PHYSICAL_INFORMATION:
    {
      ret = csnStreamDissector(rlcmac_tree, &ar, CSNDESCR(Packet_PhysicalInformation_t), tvb, &data->u.Packet_Handover_Command, ett_gsm_rlcmac);
      break;
    }
    case MT_PACKET_DOWNLINK_DUMMY_CONTROL_BLOCK:
    {
      ret = csnStreamDissector(rlcmac_tree, &ar, CSNDESCR(Packet_Downlink_Dummy_Control_Block_t), tvb, &data->u.Packet_Downlink_Dummy_Control_Block, ett_gsm_rlcmac);
      break;
    }
    default: ret = -1;
      break;
  }
}



void
proto_register_gsm_rlcmac(void)
{
  /* Setup protocol subtree array */
  static gint *ett[] = {
    &ett_gsm_rlcmac,
  };
  static hf_register_info hf[] = {
    { &hf_dl_ctrl_payload_type,
      { "Payload Type",
        "gsm_rlcmac_dl.ctrl_payload_type",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL
      }
    },
    { &hf_dl_ctrl_rrbp,
      { "RRBP",
        "gsm_rlcmac_dl.rrbp",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL
      }
    },
    { &hf_dl_ctrl_s_p,
      { "S/P",
        "gsm_rlcmac_dl.s_p",
        FT_BOOLEAN, BASE_NONE, NULL, 0x0,
        NULL, HFILL
      }
    },
    { &hf_dl_ctrl_usf,
      { "USF",
        "gsm_rlcmac_dl.usf",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL
      }
    },
    { &hf_dl_ctrl_rbsn,
      { "RBSN",
        "gsm_rlcmac_dl.rbsn",
        FT_BOOLEAN,BASE_NONE, NULL, 0x0,
        NULL, HFILL
      }
    },
    { &hf_dl_ctrl_rti,
      { "RTI",
        "gsm_rlcmac_dl.rti",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL
      }
    },
    { &hf_dl_ctrl_fs,
      { "FS",
        "gsm_rlcmac_dl.fs",
        FT_BOOLEAN,BASE_NONE, NULL, 0x0,
        NULL, HFILL
      }
    },
    { &hf_dl_ctrl_ac,
      { "AC",
        "gsm_rlcmac_dl.ac",
        FT_BOOLEAN,BASE_NONE, NULL, 0x0,
        NULL, HFILL
      }
    },
    { &hf_dl_ctrl_pr,
      { "PR",
        "gsm_rlcmac_dl.pr",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL
      }
    },
    { &hf_dl_ctrl_tfi,
      { "TFI",
        "gsm_rlcmac_dl.tfi",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL
      }
    },
    { &hf_dl_ctrl_d,
      { "D",
        "gsm_rlcmac_dl.d",
        FT_BOOLEAN,BASE_NONE, NULL, 0x0,
        NULL, HFILL
      }
    },
    { &hf_dl_ctrl_rbsn_e,
      { "RBSNe",
        "gsm_rlcmac_dl.rbsn_e",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL
      }
    },
    { &hf_dl_ctrl_fs_e,
      { "FSe",
        "gsm_rlcmac_dl.fs_e",
        FT_BOOLEAN,BASE_NONE, NULL, 0x0,
        NULL, HFILL
      }
    },
    { &hf_dl_ctrl_spare,
      { "spare",
        "gsm_rlcmac_dl.spare",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL
      }
    },
  };


  /* Register the protocol name and description */
  proto_gsm_rlcmac = proto_register_protocol("Radio Link Control, Medium Access Control, 3GPP TS44.060",
                                             "GSM RLC MAC", "gsm_rlcmac");

  /* Required function calls to register the header fields and subtrees used */
  proto_register_field_array(proto_gsm_rlcmac, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));
  register_dissector("gsm_rlcmac_ul", dissect_gsm_rlcmac_uplink, proto_gsm_rlcmac);
  register_dissector("gsm_rlcmac_dl", dissect_gsm_rlcmac_downlink, proto_gsm_rlcmac);
}

