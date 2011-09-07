/* packet-gsm_rlcmac.h
 * Definitions for GSM RLC MAC control plane message dissection in wireshark.
 * TS 44.060 and 24.008
 * By Vincent Helfre, based on original code by Jari Sassi
 * with the gracious authorization of STE
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

#ifndef __PACKET_GSM_RLCMAC_H__
#define __PACKET_GSM_RLCMAC_H__

#ifndef PRE_PACKED
#define PRE_PACKED
#endif

#ifndef POST_PACKED
#define POST_PACKED
#endif

typedef guint8 TFI_t;

typedef guint8 N32_t;
typedef guint8 N51_t;
typedef guint8 N26_t;

/*  Starting Time IE as specified in 04.08 */
typedef struct
{
  N32_t N32;  /* 04.08 refers to T1' := (FN div 1326) mod 32 */
  N51_t N51;  /* 04.08 refers to T3 := FN mod 51 */
  N26_t N26;  /* 04.08 refers to T2 := FN mod 26 */
} StartingTime_t;

typedef struct
{
  guint8 UnionType;/* UnionType is index */
  union
  {
    guint8 UPLINK_TFI;
    guint8 DOWNLINK_TFI;
  } u;
} Global_TFI_t;

typedef struct
{
  guint8 UnionType;
  union
  {
    StartingTime_t StartingTime;
    guint16 k;
  } u;
} Starting_Frame_Number_t;

typedef struct
{
  guint8 FINAL_ACK_INDICATION;
  guint8 STARTING_SEQUENCE_NUMBER;
  guint8 RECEIVED_BLOCK_BITMAP[64/8];
} Ack_Nack_Description_t;


typedef struct
{
  guint8 Exist_TIMING_ADVANCE_VALUE;
  guint8 TIMING_ADVANCE_VALUE;

  guint8 Exist_IndexAndtimeSlot;
  guint8 TIMING_ADVANCE_INDEX;
  guint8 TIMING_ADVANCE_TIMESLOT_NUMBER;
} Packet_Timing_Advance_t;

typedef struct
{
  guint8 ALPHA;

  struct
  {
    guint8 Exist;
    guint8 GAMMA_TN;
  } Slot[8];
} Power_Control_Parameters_t;

typedef struct
{
  guint8 ALPHA;
  guint8 T_AVG_W;
  guint8 T_AVG_T;
  guint8 Pb;
  guint8 PC_MEAS_CHAN;
  guint8 INT_MEAS_CHANNEL_LIST_AVAIL;
  guint8 N_AVG_I;
} Global_Power_Control_Parameters_t;

typedef struct
{
  guint8 Exist_TIMING_ADVANCE_VALUE;
  guint8 TIMING_ADVANCE_VALUE;

  guint8 Exist_UPLINK_TIMING_ADVANCE;
  guint8 UPLINK_TIMING_ADVANCE_INDEX;
  guint8 UPLINK_TIMING_ADVANCE_TIMESLOT_NUMBER;

  guint8 Exist_DOWNLINK_TIMING_ADVANCE;
  guint8 DOWNLINK_TIMING_ADVANCE_INDEX;
  guint8 DOWNLINK_TIMING_ADVANCE_TIMESLOT_NUMBER;
} Global_Packet_Timing_Advance_t;


typedef struct
{
  guint8 C_VALUE;
  guint8 RXQUAL;
  guint8 SIGN_VAR;

  struct
  {
    guint8 Exist;
    guint8 I_LEVEL_TN;
  } Slot[8];
} Channel_Quality_Report_t;

typedef enum
{
  RLC_MODE_ACKNOWLEDGED = 0,
  RLC_MODE_UNACKNOWLEDGED = 1
} RLC_MODE_t;

typedef struct
{
  guint8 PEAK_THROUGHPUT_CLASS;
  guint8 RADIO_PRIORITY;
  RLC_MODE_t RLC_MODE;
  guint8 LLC_PDU_TYPE;
  guint16 RLC_OCTET_COUNT;
} Channel_Request_Description_t;

typedef struct
{
  guint16 RANDOM_ACCESS_INFORMATION;
  guint8 FRAME_NUMBER[2];
} Packet_Request_Reference_t;

typedef PRE_PACKED struct
{
  guint8 nsapi;
  guint8 value;
} Receive_N_PDU_Number_t POST_PACKED;

typedef PRE_PACKED struct
{
  guint8 IEI;
  guint8 Length;

  guint8 Count_Receive_N_PDU_Number;
  Receive_N_PDU_Number_t Receive_N_PDU_Number[11];
} Receive_N_PDU_Number_list_t POST_PACKED;

/** IMSI length */
#define IMSI_LEN  9

/** TMSI length */
#define TMSI_LEN  4

typedef  struct
{
  guint8 MCC1;
  guint8 MCC2;
  guint8 MCC3;
  guint8 MNC3;
  guint8 MNC1;
  guint8 MNC2;
} PLMN_t;


/** This type is used to describe LAI codes */
typedef PRE_PACKED struct
{
  PLMN_t  PLMN;
  guint16  LAC;
} LAI_t POST_PACKED;


/** Length of LAI */
#define LAI_LEN  (sizeof(LAI_t))

typedef struct
{
  guint8       TMSI[TMSI_LEN];
}TMSI_t;

typedef guint16 CellId_t;


#define CKSN_NOT_VALID                7

#define IMEI_LEN                      9

#define IMEISV_LEN                    10

#define MAX_ELEMENTS_IN_EQPLMN_LIST   16


typedef struct
{
  guint8 NUMBER_CELLS;
  guint8 CCN_SUPPORTED[16];  /* bit (1), max size: 16 x 8 => 128 bits */
} CCN_Support_Description_t;

typedef struct
{
  guint8 UnionType;
  union
  {
    guint8 LSA_ID;
    guint8 ShortLSA_ID;
  } u;
} LSA_ID_Info_Element_t;

#define LSA_ID_INFO_ELEMENTS_MAX (16)

typedef struct
{
  guint8 Count_LSA_ID_Info_Element;
  LSA_ID_Info_Element_t LSA_ID_Info_Elements[LSA_ID_INFO_ELEMENTS_MAX];
} LSA_ID_Info_t;

#define NR_OF_FREQ_OR_CELLS_MAX (32)

typedef struct
{
  guint8 NR_OF_FREQ_OR_CELLS;
  LSA_ID_Info_t LSA_ID_Info[NR_OF_FREQ_OR_CELLS_MAX];
} LSA_Parameters_t;

#define MAX_REPORT_PRIORITY_CELLS (16)

typedef struct
{
  guint8 NUMBER_CELLS;
  guint8 REPORT_PRIORITY[MAX_REPORT_PRIORITY_CELLS];
} ReportPriority_t;

typedef ReportPriority_t GPRSReportPriority_t;

typedef struct
{
  guint8 REPORTING_OFFSET;
  guint8 REPORTING_THRESHOLD;
} OffsetThreshold_t;


typedef struct
{
  guint8             Exist_MULTI_BAND_REPORTING;
  guint8             MULTI_BAND_REPORTING;

  guint8             Exist_SERVING_BAND_REPORTING;
  guint8             SERVING_BAND_REPORTING;

  /* Warning:
   *
   * SI2quater, MI, PMO, and PCCO always specify Scale Ord.  There is no
   * "exist SCALE_ORD" bit in the CSN.1 descriptions for these messages.
   * However, this struct is shared with the PSI5 message which may or may
   * not specify SCALE_ORD, thus necessitating the inclusion of member
   * Exist_SCALE_ORD in the struct.  This member is never set for SI2quater, MI,
   * PMO, and PCCO so to check it (in these cases) would be erroneous.
   */
  guint8             Exist_SCALE_ORD;
  guint8             SCALE_ORD;

  guint8             Exist_OffsetThreshold900;
  OffsetThreshold_t OffsetThreshold900;

  guint8             Exist_OffsetThreshold1800;
  OffsetThreshold_t OffsetThreshold1800;

  guint8             Exist_OffsetThreshold400;
  OffsetThreshold_t OffsetThreshold400;

  guint8             Exist_OffsetThreshold1900;
  OffsetThreshold_t OffsetThreshold1900;

  guint8             Exist_OffsetThreshold850;
  OffsetThreshold_t OffsetThreshold850;

} MeasurementParams_t;

typedef struct
{
  guint8 Exist_FDD_REPORTING_THRESHOLD_2;
  guint8 FDD_REPORTING_THRESHOLD_2;
} GPRS_AdditionalMeasurementParams3G_t;


typedef struct
{
  guint8 NETWORK_CONTROL_ORDER;

  guint8 Exist_NC;
  guint8 NC_NON_DRX_PERIOD;
  guint8 NC_REPORTING_PERIOD_I;
  guint8 NC_REPORTING_PERIOD_T;
} NC_Measurement_Parameters_t;


/*
**========================================================================
**  Global types
**========================================================================
*/

struct MobileId     /* Mobile id, -> TMSI, IMEI or IMSI */
{
  guint8 Length:8;
  guint8 IdType:3;
  guint8 OddEven:1;
  guint8 Dig1:4;
  union
  {
    unsigned char TMSI[TMSI_LEN];
    unsigned char IMEI[IMEI_LEN - 2];
    unsigned char IMSI[IMEI_LEN - 2];
    unsigned char IMEISV[IMEISV_LEN - 2];
  } Id;
};

struct OV_MobileId    /* Struct for optional mobile identity */
{
  unsigned char   IEI;
  struct MobileId MV;
};

#define LAC_INVALID 0xFEFF

typedef enum
{
  LAI_PRIORITY_AVAILABLE,
  LAI_PRIORITY_FORBIDDEN,
  LAI_PRIORITY_FORCED
}LAI_Priority_t;

typedef enum
{
  NOM_I,
  NOM_II,
  NOM_III,
  NOM_GSM,
  NOM_PS_ONLY,
  NOM_UNKNOWN
}NMO_t;

typedef enum
{
  COMBINED,
  NOT_COMBINED,
  SAME_AS_BEFORE
}ProcedureMode_t;

typedef struct
{
  guint8               Cause;
  LAI_t               LAI;
  struct OV_MobileId  MobileId;
}CombinedResult_t;

typedef enum
{
  R97,
  R99
}MSCR_t, SGSNR_t;

typedef struct
{
  guint8    NbrOfElements;
  PLMN_t   Element[MAX_ELEMENTS_IN_EQPLMN_LIST];
}EqPLMN_List_t;

#define MAX_PCCCH                       16
#define MAX_RFL_LENGTH                  16 /* length of RFL in PSI2 */
#define MAX_RFLS                         4 /* Max number of RFLs */
#define MAX_MA_LISTS_IN_PSI2             8 /* MAX MA lists = 8 */
#define MAX_ALLOCATION_BITMAP_LENGTH   128 /* max length of Fixed Allocation bitmap in BITS (2^7) */
#define MAX_VAR_LENGTH_BITMAP_LENGTH   176 /* max length ever possible for variable length fixed allocation bitmap */
#define MAX_RRC_CONTAINER_LENGTH       255
#define MAX_NAS_CONTAINER_LENGTH       127


typedef struct
{
  guint8 MA_LENGTH;/* =(MA_BitLength +7) MA_BitLength_ converted to bytes */
  guint8 MA_BITMAP[(63+1)/8];/* : bit (val (MA_LENGTH) + 1) > */
  /* The above should not change order! */
  guint8 MA_BitLength;
} MobileAllocation_t;

typedef struct
{
  guint8 ElementsOf_ARFCN_INDEX;
  guint8 ARFCN_INDEX[16];
} ARFCN_index_list_t;

typedef struct
{
  guint8 HSN;

  guint8 ElementsOf_RFL_NUMBER;
  guint8 RFL_NUMBER[4];

  guint8 UnionType;
  union
  {
    MobileAllocation_t MA;
    ARFCN_index_list_t ARFCN_index_list;
  } u;
} GPRS_Mobile_Allocation_t;

/* < EGPRS Ack/Nack Description >
 * CRBB - Compressed Received Blocks Bitmap
 * URBB - Uncompressed Received Blocks Bitmap
 */
#define EGPRS_ACK_NACK_MAX_BITS 0x0FF /* 255 bits/32 bytes */
#define CRBB_MAX_BITS           0x07F /* 127 bits/16 bytes */
#define URBB_MAX_BITS           0x150 /* 336 bits/42 bytes */

typedef struct
{
  gboolean Exist_LENGTH;
  guint8   LENGTH;

  guint8   FINAL_ACK_INDICATION;
  guint8   BEGINNING_OF_WINDOW;
  guint8   END_OF_WINDOW;
  guint16  STARTING_SEQUENCE_NUMBER;

  gboolean Exist_CRBB;
  guint8   CRBB_LENGTH;
  guint8   CRBB_STARTING_COLOR_CODE;
  guint8   CRBB[CRBB_MAX_BITS/8 + 1];

  guint16  URBB_LENGTH;
  guint8   URBB[URBB_MAX_BITS/8];
} EGPRS_AckNack_t;


/* <P1 Rest Octets>
 * <P2 Rest Octets>
 */
#define  SF_VBS  0   /* VBS (broadcast call reference) */
#define  SF_VGCS  1  /* VGCS (group call reference) */

#define  AF_AckIsNotRequired  0  /* acknowledgement is not required */
#define  AF_AckIsRequired    1  /* acknowledgement is required */

typedef struct
{
  guint32 value;
  guint8 SF;
  guint8 AF;
  guint8 call_priority;
  guint8 Ciphering_information;
} Group_Call_Reference_t;

/* Mobile allocation is coded differently but uses the same type! */
typedef struct
{
  guint8 Length;
  guint8 MA[8];
} MobileAllocationIE_t;

typedef struct
{
  guint8 UnionType;
  union
  {
    MobileAllocationIE_t MA;
    guint8 Frequency_Short_List[64/8];
  } u;
} MobileAllocation_or_Frequency_Short_List_t;

typedef struct
{
  guint8 spare;
  guint16 ARFCN;
} SingleRFChannel_t;

typedef struct
{
  guint8 MAIO;
  guint8 HSN;
} RFHoppingChannel_t;

typedef struct
{
  guint8 Channel_type_and_TDMA_offset;
  guint8 TN;
  guint8 TSC;

  guint8 UnionType;
  union
  {
    SingleRFChannel_t SingleRFChannel;
    RFHoppingChannel_t RFHoppingChannel;
  } u;
} Channel_Description_t;

typedef struct
{
  Channel_Description_t Channel_Description;

  guint8 Exist_Hopping;
  MobileAllocation_or_Frequency_Short_List_t MA_or_Frequency_Short_List;

} Group_Channel_Description_t;

typedef struct
{
  Group_Call_Reference_t Group_Call_Reference;

  guint8 Exist_Group_Channel_Description;
  Group_Channel_Description_t Group_Channel_Description;
} Group_Call_information_t;

typedef struct
{
  guint8 Exist_NLN_PCH_and_NLN_status;
  guint8 NLN_PCH;
  guint8 NLN_status;

  guint8 Exist_Priority1;
  guint8 Priority1;

  guint8 Exist_Priority2;
  guint8 Priority2;

  guint8 Exist_Group_Call_information;
  Group_Call_information_t Group_Call_information;

  guint8 Packet_Page_Indication_1;
  guint8 Packet_Page_Indication_2;
} P1_Rest_Octets_t;

typedef struct
{
  guint8 Exist_CN3;
  guint8 CN3;

  guint8 Exist_NLN_and_status;
  guint8 NLN;
  guint8 NLN_status;

  guint8 Exist_Priority1;
  guint8 Priority1;

  guint8 Exist_Priority2;
  guint8 Priority2;

  guint8 Exist_Priority3;
  guint8 Priority3;

  guint8 Packet_Page_Indication_3;
} P2_Rest_Octets_t;

/* <IA Rest Octets> incl additions for R99 and EGPRS */

typedef struct
{
  guint8 USF;
  guint8 USF_GRANULARITY;

  guint8 Exist_P0_PR_MODE;
  guint8 P0;
  guint8 PR_MODE;
} DynamicAllocation_t;

typedef struct
{
  gboolean Exist_ALPHA;
  guint8   ALPHA;

  guint8   GAMMA;
  StartingTime_t TBF_STARTING_TIME;
  guint8   NR_OF_RADIO_BLOCKS_ALLOCATED;

  gboolean Exist_P0_BTS_PWR_CTRL_PR_MODE;
  guint8   P0;
  guint8   BTS_PWR_CTRL_MODE;
  guint8   PR_MODE;
} EGPRS_TwoPhaseAccess_t;

typedef struct
{
  guint8 TFI_ASSIGNMENT;
  guint8 POLLING;

  guint8 UnionType;
  union
  {
    DynamicAllocation_t DynamicAllocation;
    guint8               FixedAllocationDummy;   /* Fixed Allocation was removed */
  } Allocation;

  guint8   EGPRS_CHANNEL_CODING_COMMAND;
  guint8   TLLI_BLOCK_CHANNEL_CODING;

  gboolean Exist_BEP_PERIOD2;
  guint8   BEP_PERIOD2;

  guint8   RESEGMENT;
  guint8   EGPRS_WindowSize;

  gboolean Exist_ALPHA;
  guint8   ALPHA;

  guint8   GAMMA;

  gboolean Exist_TIMING_ADVANCE_INDEX;
  guint8   TIMING_ADVANCE_INDEX;

  gboolean            Exist_TBF_STARTING_TIME;
  StartingTime_t TBF_STARTING_TIME;
} EGPRS_OnePhaseAccess_t;

#define MAX_ACCESS_TECHOLOGY_TYPES 12

typedef struct
{
  guint8 ExtendedRA;

  guint8 NrOfAccessTechnologies;
  guint8 AccessTechnologyType[MAX_ACCESS_TECHOLOGY_TYPES];

  guint8 UnionType;
  union
  {
    EGPRS_TwoPhaseAccess_t TwoPhaseAccess; /* 04.18/10.5.2.16 Multiblock allocation */
    EGPRS_OnePhaseAccess_t OnePhaseAccess; /* 04.60/10.5.2.16 TFI using Dynamic or Fixed Allocation */
  } Access;
} IA_EGPRS_00_t;

typedef struct
{
  guint8           UnionType;
  union
  {
    IA_EGPRS_00_t IA_EGPRS_PUA; /* 00 < EGPRS Packet Uplink Assignment >*/
    guint8         IA_EGPRS_01;  /* 01 reserved for future use */
    guint8         IA_EGPRS_1;   /* 1  reserved for future use */
  } u;
} IA_EGPRS_t;

typedef struct
{
  guint8 Length;
  guint8 MAIO;
  guint8 MobileAllocation[62];
} IA_FreqParamsBeforeTime_t;

typedef struct
{
  gboolean Exist_ALPHA;
  guint8   ALPHA;

  guint8   GAMMA;
  guint8   R97_CompatibilityBits;
  StartingTime_t TBF_STARTING_TIME;

  gboolean Exist_P0_BTS_PWR_CTRL_PR_MODE;
  guint8   P0;
  guint8   BTS_PWR_CTRL_MODE;
  guint8   PR_MODE;
} GPRS_SingleBlockAllocation_t;

typedef struct
{
  guint8 TFI_ASSIGNMENT;
  guint8 POLLING;

  guint8 UnionType;
  union
  {
    DynamicAllocation_t DynamicAllocation;
    guint8               FixedAllocationDummy;
  } Allocation;

  guint8              CHANNEL_CODING_COMMAND;
  guint8              TLLI_BLOCK_CHANNEL_CODING;

  guint8              Exist_ALPHA;
  guint8              ALPHA;

  guint8              GAMMA;

  guint8              Exist_TIMING_ADVANCE_INDEX;
  guint8              TIMING_ADVANCE_INDEX;

  guint8              Exist_TBF_STARTING_TIME;
  StartingTime_t TBF_STARTING_TIME;
} GPRS_DynamicOrFixedAllocation_t;

typedef struct
{
  gboolean Exist_ExtendedRA;
  guint8   ExtendedRA;
} PU_IA_AdditionsR99_t;

typedef struct
{
  guint8 UnionType;
  union
  {
    GPRS_SingleBlockAllocation_t    SingleBlockAllocation;
    GPRS_DynamicOrFixedAllocation_t DynamicOrFixedAllocation;
  } Access;

  gboolean               Exist_AdditionsR99;
  PU_IA_AdditionsR99_t  AdditionsR99;
} Packet_Uplink_ImmAssignment_t;

typedef struct
{
  guint8   EGPRS_WindowSize;
  guint8   LINK_QUALITY_MEASUREMENT_MODE;

  gboolean Exist_BEP_PERIOD2;
  guint8   BEP_PERIOD2;
} PD_IA_AdditionsR99_t;

typedef struct
{
  guint32               TLLI;

  guint8                Exist_TFI_to_TA_VALID;
  guint8                TFI_ASSIGNMENT;
  guint8                RLC_MODE;
  guint8                Exist_ALPHA;
  guint8                ALPHA;
  guint8                GAMMA;
  guint8                POLLING;
  guint8                TA_VALID;

  guint8                Exist_TIMING_ADVANCE_INDEX;
  guint8                TIMING_ADVANCE_INDEX;

  guint8                Exist_TBF_STARTING_TIME;
  StartingTime_t       TBF_STARTING_TIME;

  guint8                Exist_P0_PR_MODE;
  guint8                P0;
  guint8                BTS_PWR_CTRL_MODE;
  guint8                PR_MODE;

  gboolean              Exist_AdditionsR99;
  PD_IA_AdditionsR99_t AdditionsR99;
} Packet_Downlink_ImmAssignment_t;

typedef struct
{
  gboolean Exist_SecondPart;

  gboolean Exist_ExtendedRA;
  guint8   ExtendedRA;
} Second_Part_Packet_Assignment_t;

typedef struct
{
  guint8 UnionType;
  union
  {
    Packet_Uplink_ImmAssignment_t   Packet_Uplink_ImmAssignment;
    Packet_Downlink_ImmAssignment_t Packet_Downlink_ImmAssignment;
  } ul_dl;
} IA_PacketAssignment_UL_DL_t;

typedef struct
{
  guint8 UnionType;
  union
  {
    IA_PacketAssignment_UL_DL_t     UplinkDownlinkAssignment;
    Second_Part_Packet_Assignment_t Second_Part_Packet_Assignment;
  } u;
} IA_PacketAssignment_t;

typedef struct
{
  guint8 UnionType;
  union
  {
    IA_FreqParamsBeforeTime_t IA_FrequencyParams;
    IA_PacketAssignment_t     IA_PacketAssignment;
  } u;
} IA_GPRS_t;

typedef struct
{
  guint8 UnionType;
  union
  {
    IA_EGPRS_t IA_EGPRS_Struct;
    IA_GPRS_t  IA_GPRS_Struct;
  } u;
} IA_t;


/* <IAR Rest Octets> ref: 04.18/10.5.2.17 */
typedef struct
{
  guint8 Exist_ExtendedRA;
  guint8 ExtendedRA;
} ExtendedRA_Info_t;

typedef ExtendedRA_Info_t ExtendedRA_Info_Array_t[4];

typedef struct
{
  ExtendedRA_Info_Array_t ExtendedRA_Info;
} IAR_t;


/* Packet Polling Request */
typedef struct
{
  guint8 UnionType;
  union
  {
    Global_TFI_t Global_TFI;
    guint32 TLLI;
    guint16 TQI;
  } u;
} PacketPollingID_t;

typedef struct
{
  guint8 MESSAGE_TYPE;
  guint8 PAGE_MODE;
  PacketPollingID_t ID;
  guint8 TYPE_OF_ACK;
} Packet_Polling_Request_t;

/* < SI 13 Rest Octets > */
#define MAX_EXTENSION_LENGTH_IN_BYTES (8) /* max value = 64 (coded on 6 bits) */

typedef struct
{
  guint8 extension_length;
  guint8 Extension_Info[MAX_EXTENSION_LENGTH_IN_BYTES];/* ( val (extension length)+1 ) 04.60/12.26 */
} Extension_Bits_t;

typedef struct
{
  guint8 DTM_SUPPORT                  : 1;
  guint8 PFC_FEATURE_MODE             : 1;
  guint8 BEP_PERIOD                   : 4;
  guint8 EGPRS_PACKET_CHANNEL_REQUEST : 1;
  guint8 EGPRS_Support                  : 1;

  guint8 NotUsed                        : 3;
  guint8 EXT_UTBF_NODATA              : 1;
  guint8 MULTIPLE_TBF_CAPABILITY      : 1;
  guint8 NW_EXT_UTBF                  : 1;
  guint8 CCN_ACTIVE                   : 1;
  guint8 BSS_PAGING_COORDINATION      : 1;
} GPRS_ExtensionInfoWithEGPRS_t;

typedef struct
{
  guint8 EXT_UTBF_NODATA         : 1;
  guint8 MULTIPLE_TBF_CAPABILITY : 1;
  guint8 NW_EXT_UTBF             : 1;
  guint8 CCN_ACTIVE              : 1;
  guint8 BSS_PAGING_COORDINATION : 1;
  guint8 DTM_SUPPORT             : 1;
  guint8 PFC_FEATURE_MODE        : 1;
  guint8 EGPRS_Support             : 1;
} GPRS_ExtensionInfoWithoutEGPRS_t;

typedef struct
{
  guint8 NotUsed                   : 7;
  guint8 EGPRS_Support             : 1;
} EGPRS_Support_t;

typedef struct
{
  guint8 ECSC    : 1;
  guint8 ECSR_3G : 1;
} NonGPRS_ExtensionInfo_t;

typedef struct
{
  guint8 Extension_Length;
  union
  {
    EGPRS_Support_t                  EGPRS_Support;
    GPRS_ExtensionInfoWithEGPRS_t    GPRS_ExtensionInfoWithEGPRS;
    GPRS_ExtensionInfoWithoutEGPRS_t GPRS_ExtensionInfoWithoutEGPRS;
    NonGPRS_ExtensionInfo_t          NonGPRS_ExtensionInfo;
    guint8                            Extension_Information[MAX_EXTENSION_LENGTH_IN_BYTES];
  } u;
} Optional_Extension_Information_t;

typedef struct
{
  gboolean EGPRS_Support;
  guint8   BEP_PERIOD;
  gboolean EGPRS_PACKET_CHANNEL_REQUEST;
} EGPRS_OptionalExtensionInformation_t;


typedef struct
{
  guint8 NMO;
  guint8 T3168;
  guint8 T3192;
  guint8 DRX_TIMER_MAX;
  guint8 ACCESS_BURST_TYPE;
  guint8 CONTROL_ACK_TYPE;
  guint8 BS_CV_MAX;

  guint8 Exist_PAN;
  guint8 PAN_DEC;
  guint8 PAN_INC;
  guint8 PAN_MAX;

  guint8 Exist_Extension_Bits;
  Extension_Bits_t Extension_Bits;
} GPRS_Cell_Options_t;

typedef struct
{
  guint8 ALPHA;
  guint8 T_AVG_W;
  guint8 T_AVG_T;
  guint8 PC_MEAS_CHAN;
  guint8 N_AVG_I;
} GPRS_Power_Control_Parameters_t;

typedef struct
{
  guint8 RAC;
  guint8 SPGC_CCCH_SUP;
  guint8 PRIORITY_ACCESS_THR;
  guint8 NETWORK_CONTROL_ORDER;
  GPRS_Cell_Options_t GPRS_Cell_Options;
  GPRS_Power_Control_Parameters_t GPRS_Power_Control_Parameters;
} PBCCH_Not_present_t;

typedef struct
{
  guint8 Pb;
  guint8 TSC;
  guint8 TN;

  guint8 UnionType;
  union
  {
    guint8 dummy;
    guint16 ARFCN;
    guint8 MAIO;
  } u;
} PBCCH_Description_t;

typedef struct
{
  guint8 PSI1_REPEAT_PERIOD;
  PBCCH_Description_t PBCCH_Description;
} PBCCH_present_t;



/* < Packet TBF Release message content > */
typedef guint8 TBF_RELEASE_CAUSE_t;
#define  TBF_RELEASE_CAUSE_NORMAL (0x00)
#define  TBF_RELEASE_CAUSE_ABNORMAL (0x02)

typedef struct
{
  guint8               MESSAGE_TYPE;
  guint8               PAGE_MODE;
  Global_TFI_t        Global_TFI;
  guint8               UPLINK_RELEASE;
  guint8               DOWNLINK_RELEASE;
  TBF_RELEASE_CAUSE_t TBF_RELEASE_CAUSE;
} Packet_TBF_Release_t;

/* < Packet Control Acknowledgement message content > */
typedef struct
{
  guint8  Exist_CTRL_ACK_Extension;
  guint16 CTRL_ACK_Extension;
} Packet_Control_Acknowledgement_AdditionsR6_t;

typedef struct
{
  guint8 Exist_TN_RRBP;
  guint8 TN_RRBP;
  guint8 Exist_G_RNTI_Extension;
  guint8 G_RNTI_Extension;
  gboolean Exist_AdditionsR6;
  Packet_Control_Acknowledgement_AdditionsR6_t AdditionsR6;
} Packet_Control_Acknowledgement_AdditionsR5_t;

typedef struct
{  /* Mac header */
  guint8 MESSAGE_TYPE;
  guint8 PayloadType;
  guint8 spare;
  guint8 R;

  guint32 TLLI;
  guint8 CTRL_ACK;
  gboolean Exist_AdditionsR5;
  Packet_Control_Acknowledgement_AdditionsR5_t AdditionsR5;
} Packet_Control_Acknowledgement_t;

typedef Packet_Control_Acknowledgement_t Packet_Ctrl_Ack_t;

typedef struct
{
  guint8 CTRL_ACK;
} Packet_Control_Acknowledgement_11_bit_t, Packet_Control_Acknowledgement_8_bit_t;

/* < Packet Downlink Dummy Control Block message content > */
typedef struct
{
  guint8 MESSAGE_TYPE;
  guint8 PAGE_MODE;

  guint8 Exist_PERSISTENCE_LEVEL;
  guint8 PERSISTENCE_LEVEL[4];
} Packet_Downlink_Dummy_Control_Block_t;

/* < Packet Uplink Dummy Control Block message content > */
typedef struct
{ /* Mac header */
  guint8 MESSAGE_TYPE;
  guint8 PayloadType;
  guint8 spare;
  guint8 R;

  guint32 TLLI;
} Packet_Uplink_Dummy_Control_Block_t;

/*< MS Radio Access capability IE >
 * 24.008 (10.5.5.12a)
 */
typedef guint8 A5_bits_t;/*<A5 bits> ::= < A5/1 : bit> <A5/2 : bit> <A5/3 : bit> <A5/4 : bit> <A5/5 : bit> <A5/6 : bit> <A5/7 : bit>; -- bits for circuit mode ciphering algorithms */

typedef struct
{
  guint8 Exist_DTM_EGPRS_multislot_class;
  guint8 DTM_EGPRS_multislot_class;
} DTM_EGPRS_t;

typedef struct
{
  guint8 Exist_DTM_EGPRS_HighMultislotClass;
  guint8 DTM_EGPRS_HighMultislotClass;
} DTM_EGPRS_HighMultislotClass_t;

typedef struct
{
  guint8 Exist_HSCSD_multislot_class;
  guint8 HSCSD_multislot_class;

  guint8 Exist_GPRS_multislot_class;
  guint8 GPRS_multislot_class;
  guint8 GPRS_Extended_Dynamic_Allocation_Capability;

  guint8 Exist_SM;
  guint8 SMS_VALUE;
  guint8 SM_VALUE;

/*-------- Rel 99 additions */
  guint8 Exist_ECSD_multislot_class;
  guint8 ECSD_multislot_class;

  guint8 Exist_EGPRS_multislot_class;
  guint8 EGPRS_multislot_class;
  guint8 EGPRS_Extended_Dynamic_Allocation_Capability;

  guint8 Exist_DTM_GPRS_multislot_class;
  guint8 DTM_GPRS_multislot_class;
  guint8 Single_Slot_DTM;
  DTM_EGPRS_t DTM_EGPRS_Params;
} Multislot_capability_t;

typedef struct
{
  guint8 RF_Power_Capability;

  guint8 Exist_A5_bits;
  A5_bits_t A5_bits;
  /*-- zero means that the same values apply for parameters as in the immediately preceeding Access capabilities field within this IE
  *-- The presence of the A5 bits is mandatory in the 1st Access capabilies struct within this IE.
  */

  guint8 ES_IND;
  guint8 PS;
  guint8 VGCS;
  guint8 VBS;

  guint8 Exist_Multislot_capability;
  Multislot_capability_t Multislot_capability;
  /* -- zero means that the same values apply for multislot parameters as in the immediately preceeding Access capabilities field within this IE.
   * -- The presence of the Multislot capability struct is mandatory in the 1st Access capabilites struct within this IE.
   */
  /* -------- Rel 99 additions */
  guint8 Exist_Eight_PSK_Power_Capability;
  guint8 Eight_PSK_Power_Capability;

  guint8 COMPACT_Interference_Measurement_Capability;
  guint8 Revision_Level_Indicator;
  guint8 UMTS_FDD_Radio_Access_Technology_Capability;
  guint8 UMTS_384_TDD_Radio_Access_Technology_Capability;
  guint8 CDMA2000_Radio_Access_Technology_Capability;

  /* -------- R4 additions */
  guint8 UMTS_128_TDD_Radio_Access_Technology_Capability;
  guint8 GERAN_Feature_Package_1;

  guint8 Exist_Extended_DTM_multislot_class;
  guint8 Extended_DTM_GPRS_multislot_class;
  guint8 Extended_DTM_EGPRS_multislot_class;

  guint8 Modulation_based_multislot_class_support;

  /* -------- R5 additions */
  guint8 Exist_HighMultislotCapability;
  guint8 HighMultislotCapability;

  guint8 Exist_GERAN_lu_ModeCapability;
  guint8 GERAN_lu_ModeCapability;

  guint8 GMSK_MultislotPowerProfile;
  guint8 EightPSK_MultislotProfile;

  /* -------- R6 additions */
  guint8 MultipleTBF_Capability;
  guint8 DownlinkAdvancedReceiverPerformance;
  guint8 ExtendedRLC_MAC_ControlMessageSegmentionsCapability;
  guint8 DTM_EnhancementsCapability;

  guint8 Exist_DTM_GPRS_HighMultislotClass;
  guint8 DTM_GPRS_HighMultislotClass;
  DTM_EGPRS_HighMultislotClass_t DTM_EGPRS_HighMultislotClass;
  guint8 PS_HandoverCapability;
} Content_t;

#define ABSOLUTE_MAX_BANDS            2 /*  New fields for R4 extend the length of the capabilities message so we can only send 2 */

#define MAX_ACCESS_TECHNOLOGIES_COUNT 16 /* No more than 16 instances */

typedef enum
{/* See TS 24.008 table 10.5.146, GSM R and GSM 450/480 excluded */
  AccTech_GSMP     = 0x0,
  AccTech_GSME     = 0x1,
  AccTech_GSM1800  = 0x3,
  AccTech_GSM1900  = 0x4,
  AccTech_GSM850   = 0x7,
  AccTech_GSMOther = 0xf
} AccessTechnology_t;

typedef struct
{
  guint8              CountAccessTechnologies;
  AccessTechnology_t AccessTechnologies[MAX_ACCESS_TECHNOLOGIES_COUNT];
} AccessTechnologiesRequest_t;

typedef struct
{
  AccessTechnology_t Access_Technology_Type;
  guint8              GMSK_Power_class;
  guint8              Eight_PSK_Power_class;
} Additional_access_technologies_struct_t;

typedef struct
{
  guint8 Count_additional_access_technologies;
  /* The value 0xf cannot be set for the first ATT, therefore we can only have
     ABSOLUTE_MAX_BANDS-1 additional access technologies. */
  Additional_access_technologies_struct_t Additional_access_technologies[ABSOLUTE_MAX_BANDS-1];
} Additional_access_technologies_t;

typedef struct
{
  guint8 IndexOfAccTech; /* Position in AccessTechnology_t */
  union
  {
    /* Long Form */
    Content_t                        Content;
    /* Short Form */
    Additional_access_technologies_t Additional_access_technologies;
  } u;
} MS_RA_capability_value_t;

typedef struct
{
  guint8 Count_MS_RA_capability_value; /* Recursive */
  MS_RA_capability_value_t MS_RA_capability_value[ABSOLUTE_MAX_BANDS];
} MS_Radio_Access_capability_t;


typedef struct
{
  guint8   ExistEDGE_RF_PwrCap1;
  guint8   EDGE_RF_PwrCap1;
  guint8   ExistEDGE_RF_PwrCap2;
  guint8   EDGE_RF_PwrCap2;
} EDGE_RF_Pwr_t;

typedef struct
{
  guint8 A5_Bits;
  guint8 Arc2_Spare;
  guint8 Arc1;
} ARC_t;

typedef struct
{
  guint8   Multiband;
  union
  {
    guint8 A5_Bits;
    ARC_t ARC;
  } u;
} Multiband_t;

typedef struct              /* MS classmark 3 R99 */
{
  guint8         Spare1;
  Multiband_t   Multiband;

  guint8         Exist_R_Support;
  guint8         R_GSM_Arc;

  guint8         Exist_MultiSlotCapability;
  guint8         MultiSlotClass;

  guint8         UCS2;
  guint8         ExtendedMeasurementCapability;

  guint8         Exist_MS_MeasurementCapability;
  guint8         SMS_VALUE;
  guint8         SM_VALUE;

  guint8         Exist_MS_PositioningMethodCapability;
  guint8         MS_PositioningMethod;

  guint8         Exist_EDGE_MultiSlotCapability;
  guint8         EDGE_MultiSlotClass;

  guint8         Exist_EDGE_Struct;
  guint8         ModulationCapability;
  EDGE_RF_Pwr_t EDGE_RF_PwrCaps;

  guint8         Exist_GSM400_Info;
  guint8         GSM400_Bands;
  guint8         GSM400_Arc;

  guint8         Exist_GSM850_Arc;
  guint8         GSM850_Arc;

  guint8         Exist_PCS1900_Arc;
  guint8         PCS1900_Arc;

  guint8         UMTS_FDD_Radio_Access_Technology_Capability;
  guint8         UMTS_384_TDD_Radio_Access_Technology_Capability;
  guint8         CDMA2000_Radio_Access_Technology_Capability;

  guint8         Exist_DTM_GPRS_multislot_class;
  guint8         DTM_GPRS_multislot_class;
  guint8         Single_Slot_DTM;
  DTM_EGPRS_t   DTM_EGPRS_Params;

  /* -------- R4 additions */
  guint8         Exist_SingleBandSupport;
  guint8         GSM_Band;

  guint8         Exist_GSM_700_Associated_Radio_Capability;
  guint8         GSM_700_Associated_Radio_Capability;

  guint8         UMTS_128_TDD_Radio_Access_Technology_Capability;
  guint8         GERAN_Feature_Package_1;

  guint8         Exist_Extended_DTM_multislot_class;
  guint8         Extended_DTM_GPRS_multislot_class;
  guint8         Extended_DTM_EGPRS_multislot_class;

  /* -------- R5 additions */
  guint8         Exist_HighMultislotCapability;
  guint8         HighMultislotCapability;

  guint8         Exist_GERAN_lu_ModeCapability;
  guint8         GERAN_lu_ModeCapability;

  guint8         GERAN_FeaturePackage_2;

  guint8         GMSK_MultislotPowerProfile;
  guint8         EightPSK_MultislotProfile;

  /* -------- R6 additions */
  guint8         Exist_TGSM_400_Bands;
  guint8         TGSM_400_BandsSupported;
  guint8         TGSM_400_AssociatedRadioCapability;

  guint8         Exist_TGSM_900_AssociatedRadioCapability;
  guint8         TGSM_900_AssociatedRadioCapability;

  guint8         DownlinkAdvancedReceiverPerformance;
  guint8         DTM_EnhancementsCapability;

  guint8         Exist_DTM_GPRS_HighMultislotClass;
  guint8         DTM_GPRS_HighMultislotClass;
  guint8         OffsetRequired;
  DTM_EGPRS_HighMultislotClass_t   DTM_EGPRS_HighMultislotClass;
  guint8         RepeatedSACCH_Capability;

  guint8         Spare2;
} MS_Class3_Unpacked_t;


/* < Packet Resource Request message content > */
typedef struct
{
  gboolean Exist;
  guint8   UnionType;
  union
  {
    guint8 MEAN_BEP_GMSK;
    guint8 MEAN_BEP_8PSK;
  } u;
} BEP_MeasurementReport_t;

typedef struct
{
  gboolean Exist;
  guint8   I_LEVEL;
} InterferenceMeasurementReport_t;

typedef struct
{
  gboolean                 Exist_BEP_MEASUREMENTS;
  BEP_MeasurementReport_t BEP_MEASUREMENTS[8];

  gboolean                         Exist_INTERFERENCE_MEASUREMENTS;
  InterferenceMeasurementReport_t INTERFERENCE_MEASUREMENTS[8];
} EGPRS_TimeslotLinkQualityMeasurements_t;

typedef struct
{
  gboolean Exist_MEAN_CV_BEP_GMSK;
  guint8   MEAN_BEP_GMSK;
  guint8   CV_BEP_GMSK;

  gboolean Exist_MEAN_CV_BEP_8PSK;
  guint8   MEAN_BEP_8PSK;
  guint8   CV_BEP_8PSK;
} EGPRS_BEP_LinkQualityMeasurements_t;

typedef struct
{
  gboolean                                 Exist_EGPRS_BEP_LinkQualityMeasurements;
  EGPRS_BEP_LinkQualityMeasurements_t     EGPRS_BEP_LinkQualityMeasurements;

  gboolean                                 Exist_EGPRS_TimeslotLinkQualityMeasurements;
  EGPRS_TimeslotLinkQualityMeasurements_t EGPRS_TimeslotLinkQualityMeasurements;

  gboolean                                 Exist_PFI;
  guint8                                   PFI;

  guint8                                   MS_RAC_AdditionalInformationAvailable;
  guint8                                   RetransmissionOfPRR;
} PRR_AdditionsR99_t;

typedef struct
{
  guint8 UnionType;
  union
  {
    Global_TFI_t Global_TFI;
    guint32 TLLI;
  } u;
} PacketResourceRequestID_t;

typedef struct
{
  guint8 MESSAGE_TYPE;
  guint8 PayloadType;
  guint8 spare;
  guint8 R;

  guint8 Exist_ACCESS_TYPE;
  guint8 ACCESS_TYPE;

  PacketResourceRequestID_t ID;

  guint8 Exist_MS_Radio_Access_capability;
  MS_Radio_Access_capability_t MS_Radio_Access_capability;

  Channel_Request_Description_t Channel_Request_Description;

  guint8 Exist_CHANGE_MARK;
  guint8 CHANGE_MARK;

  guint8 C_VALUE;

  guint8 Exist_SIGN_VAR;
  guint8 SIGN_VAR;

  InterferenceMeasurementReport_t  Slot[8];

  guint8                            Exist_AdditionsR99;
  PRR_AdditionsR99_t               AdditionsR99;
} Packet_Resource_Request_t;

/* < Packet Mobile TBF Status message content >*/
typedef struct
{
  guint8 MESSAGE_TYPE;
  guint8 PayloadType;
  guint8 spare;
  guint8 R;

  Global_TFI_t Global_TFI;
  guint8 TBF_CAUSE;

  guint8 Exist_STATUS_MESSAGE_TYPE;
  guint8 STATUS_MESSAGE_TYPE;
} Packet_Mobile_TBF_Status_t;

/* < Packet PSI Status message content >*/
typedef struct
{
  guint8 PSI_MESSAGE_TYPE;
  guint8 PSIX_CHANGE_MARK;
  guint8 Exist_PSIX_COUNT_and_Instance_Bitmap;
} PSI_Message_t;

typedef struct
{
  guint8 Count_PSI_Message;
  PSI_Message_t PSI_Message[10];

  guint8 ADDITIONAL_MSG_TYPE;
} PSI_Message_List_t;

typedef struct
{
  guint8 ADDITIONAL_MSG_TYPE;
} Unknown_PSI_Message_List_t;

typedef struct
{
  guint8 MESSAGE_TYPE;
  guint8 PayloadType;
  guint8 spare;
  guint8 R;

  Global_TFI_t Global_TFI;
  guint8 PBCCH_CHANGE_MARK;

  PSI_Message_List_t PSI_Message_List;
  Unknown_PSI_Message_List_t Unknown_PSI_Message_List;
} Packet_PSI_Status_t;

/* < Packet SI Status message content > */
typedef struct
{
  guint8 SI_MESSAGE_TYPE;
  guint8 MESS_REC;
  guint8 SIX_CHANGE_MARK;

  guint8 SIX_COUNT;
  guint8 Instance_bitmap[2];
} SI_Message_t;

typedef struct
{
  guint8 Count_SI_Message;
  SI_Message_t SI_Message[10];

  guint8 ADDITIONAL_MSG_TYPE;
} SI_Message_List_t;

typedef struct
{
  guint8 ADDITIONAL_MSG_TYPE;
} Unknown_SI_Message_List_t;

typedef struct
{
  guint8 MESSAGE_TYPE;
  guint8 PayloadType;
  guint8 spare;
  guint8 R;

  Global_TFI_t Global_TFI;
  guint8 BCCH_CHANGE_MARK;

  SI_Message_List_t SI_Message_List;
  Unknown_SI_Message_List_t Unknown_SI_Message_List;
} Packet_SI_Status_t;

typedef struct
{
  guint16 FDD_ARFCN;
  guint8 DIVERSITY;
  guint8 Exist_Bandwith_FDD;
  guint8 BANDWITH_FDD;
  guint16 SCRAMBLING_CODE;
} FDD_Target_Cell_t;

typedef struct
{
  guint16 TDD_ARFCN;
  guint8  DIVERSITY_TDD;
  guint8 Exist_Bandwith_TDD;
  guint8  BANDWITH_TDD;
  guint16 CELL_PARAMETER;
  guint8  Sync_Case_TSTD;
} TDD_Target_Cell_t;

typedef struct
{
  guint16 EARFCN;
  guint8 Exist_Measurement_Bandwidth;
  guint8 Measurement_Bandwidth;
  guint16 Physical_Layer_Cell_Identity;
}EUTRAN_Target_Cell_t;

typedef struct
{
  guint32 UTRAN_CI;
  guint8 Exist_PLMN_ID;
  PLMN_t  PLMN_ID;
}UTRAN_CSG_Target_Cell_t;

typedef struct
{
  guint32 EUTRAN_CI;
  guint16 Tracking_Area_Code;
  guint8 Exist_PLMN_ID;
  PLMN_t  PLMN_ID;
}EUTRAN_CSG_Target_Cell_t;

typedef struct
{
  guint8 Exist_UTRAN_CSG_Target_Cell;
  UTRAN_CSG_Target_Cell_t UTRAN_CSG_Target_Cell;
  guint8 Exist_EUTRAN_CSG_Target_Cell;
  EUTRAN_CSG_Target_Cell_t EUTRAN_CSG_Target_Cell;
}PCCF_AdditionsR9_t;

typedef struct
{
  guint8 Exist_EUTRAN_Target_Cell;
  EUTRAN_Target_Cell_t EUTRAN_Target_Cell;
  guint8 Exist_AdditionsR9;
  PCCF_AdditionsR9_t AdditionsR9;
}PCCF_AdditionsR8_t;

typedef struct
{
  guint8 Exist_G_RNTI_extention;
  guint8  G_RNTI_extention;
  guint8 Exist_AdditionsR8;
  PCCF_AdditionsR8_t AdditionsR8;
} PCCF_AdditionsR5_t;

typedef struct
{
  guint8 Exist_FDD_Description;
  FDD_Target_Cell_t FDD_Target_Cell;
  guint8 Exist_TDD_Description;
  TDD_Target_Cell_t TDD_Target_Cell;
  guint8 Exist_AdditionsR5;
  PCCF_AdditionsR5_t AdditionsR5;
} PCCF_AdditionsR99_t;

/* < Packet Cell Change Failure message content > */
typedef struct
{
  guint8 MESSAGE_TYPE;
  guint8 PayloadType;
  guint8 spare;
  guint8 R;

  guint32 TLLI;
  guint16 ARFCN;
  guint8 BSIC;
  guint8 CAUSE;
  gboolean Exist_AdditionsR99;
  PCCF_AdditionsR99_t AdditionsR99;
} Packet_Cell_Change_Failure_t;

/* < Packet Downlink Ack/Nack message content > */
typedef struct
{
  gboolean Exist_PFI;
  guint8   PFI;
} PD_AckNack_AdditionsR99_t;

typedef struct
{
  guint8 MESSAGE_TYPE;
  guint8 PayloadType;
  guint8 spare;
  guint8 R;

  guint8 DOWNLINK_TFI;
  Ack_Nack_Description_t Ack_Nack_Description;

  guint8 Exist_Channel_Request_Description;
  Channel_Request_Description_t Channel_Request_Description;

  Channel_Quality_Report_t Channel_Quality_Report;

  gboolean                       Exist_AdditionsR99;
  PD_AckNack_AdditionsR99_t     AdditionsR99;
} Packet_Downlink_Ack_Nack_t;

/* < EGPRS Packet Downlink Ack/Nack message content > */
typedef struct
{
  EGPRS_BEP_LinkQualityMeasurements_t     EGPRS_BEP_LinkQualityMeasurements;
  guint8                                   C_VALUE;
  EGPRS_TimeslotLinkQualityMeasurements_t EGPRS_TimeslotLinkQualityMeasurements;
} EGPRS_ChannelQualityReport_t;

typedef struct
{
  guint8   MESSAGE_TYPE;
  guint8   PayloadType;
  guint8   spare;
  guint8   R;

  guint8   DOWNLINK_TFI;
  guint8   MS_OUT_OF_MEMORY;

  gboolean                       Exist_EGPRS_ChannelQualityReport;
  EGPRS_ChannelQualityReport_t  EGPRS_ChannelQualityReport;

  gboolean                       Exist_ChannelRequestDescription;
  Channel_Request_Description_t ChannelRequestDescription;

  gboolean Exist_PFI;
  guint8   PFI;

  gboolean          Exist_ExtensionBits;
  Extension_Bits_t ExtensionBits;

  EGPRS_AckNack_t  EGPRS_AckNack;
} EGPRS_PD_AckNack_t;

/* < Packet Uplink Ack/Nack message content  04.60 sec.11.2.28 > */

typedef struct
{
  guint8                      Exist_CONTENTION_RESOLUTION_TLLI;
  guint32                     CONTENTION_RESOLUTION_TLLI;

  guint8                      Exist_Packet_Timing_Advance;
  Packet_Timing_Advance_t    Packet_Timing_Advance;

  guint8                      Exist_Extension_Bits;
  Extension_Bits_t           Extension_Bits;

  guint8                      Exist_Power_Control_Parameters;
  Power_Control_Parameters_t Power_Control_Parameters;
} Common_Uplink_Ack_Nack_Data_t;

typedef struct
{
  gboolean Exist_PacketExtendedTimingAdvance;
  guint8   PacketExtendedTimingAdvance;
  guint8   TBF_EST;
} PU_AckNack_GPRS_AdditionsR99_t;

typedef struct
{
  guint8                  CHANNEL_CODING_COMMAND;
  Ack_Nack_Description_t Ack_Nack_Description;

  guint8 UnionType;
  union
  {
    guint8 FixedAllocationDummy;
    guint8 Error;
  } u;

  gboolean                        Exist_AdditionsR99;
  PU_AckNack_GPRS_AdditionsR99_t AdditionsR99;


  Common_Uplink_Ack_Nack_Data_t Common_Uplink_Ack_Nack_Data;
} PU_AckNack_GPRS_t;

typedef struct
{
  guint8   EGPRS_ChannelCodingCommand;
  guint8   RESEGMENT;
  guint8   PRE_EMPTIVE_TRANSMISSION;
  guint8   PRR_RETRANSMISSION_REQUEST;
  guint8   ARAC_RETRANSMISSION_REQUEST;

  guint8   TBF_EST;

  gboolean Exist_Packet_Extended_Timing_Advance;
  guint8   Packet_Extended_Timing_Advance;

  EGPRS_AckNack_t  EGPRS_AckNack;


  Common_Uplink_Ack_Nack_Data_t Common_Uplink_Ack_Nack_Data;
} PU_AckNack_EGPRS_00_t;

typedef struct
{
  guint8   UnionType;
  union
  {
    PU_AckNack_EGPRS_00_t PU_AckNack_EGPRS_00;
    guint8                 extension_01;
    guint8                 extension_10;
    guint8                 extension_11;
  } u;
} PU_AckNack_EGPRS_t;

enum PUAN_Type
{
  PUAN_GPRS,
  PUAN_EGPRS
};

typedef struct
{
  guint8 MESSAGE_TYPE;
  guint8 PAGE_MODE;
  guint8 UPLINK_TFI;

  guint8 UnionType;
  union
  {
    PU_AckNack_GPRS_t  PU_AckNack_GPRS_Struct;
    PU_AckNack_EGPRS_t PU_AckNack_EGPRS_Struct;
  } u;
} Packet_Uplink_Ack_Nack_t;

/* < Packet Uplink Assignment message content > */
typedef struct
{
  guint8 CHANGE_MARK_1;
  guint8 Exist_CHANGE_MARK_2;
  guint8 CHANGE_MARK_2;
} CHANGE_MARK_t;

typedef struct
{
  guint8 MAIO;
  guint8 MA_NUMBER;

  guint8 Exist_CHANGE_MARK;
  CHANGE_MARK_t CHANGE_MARK;
} Indirect_encoding_t;

typedef struct
{
  guint8 MAIO;
  GPRS_Mobile_Allocation_t GPRS_Mobile_Allocation;
} Direct_encoding_1_t;

typedef struct
{
  guint8 MAIO;
  guint8 HSN;
  guint8 Length_of_MA_Frequency_List;
  guint8 MA_Frequency_List[15+3];
} Direct_encoding_2_t;

typedef struct
{
  guint8 TSC;
  guint8 UnionType;
  union
  {
    guint16 ARFCN;
    Indirect_encoding_t Indirect_encoding;
    Direct_encoding_1_t Direct_encoding_1;
    Direct_encoding_2_t Direct_encoding_2;
  } u;
} Frequency_Parameters_t;

typedef struct
{
  guint8 Exist;
  guint8 USF_TN;
} Timeslot_Allocation_t;

typedef struct
{
  guint8 ALPHA;

  struct
  {
    guint8 Exist;
    guint8 USF_TN;
    guint8 GAMMA_TN;
  } Slot[8];
} Timeslot_Allocation_Power_Ctrl_Param_t;

typedef struct
{
  guint8 Extended_Dynamic_Allocation;

  guint8 Exist_P0;
  guint8 P0;
  guint8 PR_MODE;

  guint8 USF_GRANULARITY;

  guint8 Exist_UPLINK_TFI_ASSIGNMENT;
  guint8 UPLINK_TFI_ASSIGNMENT;

  guint8 Exist_RLC_DATA_BLOCKS_GRANTED;
  guint8 RLC_DATA_BLOCKS_GRANTED;

  guint8 Exist_TBF_Starting_Time;
  Starting_Frame_Number_t TBF_Starting_Time;

  guint8 UnionType;
  union
  {
    Timeslot_Allocation_t                  Timeslot_Allocation[8];
    Timeslot_Allocation_Power_Ctrl_Param_t Timeslot_Allocation_Power_Ctrl_Param;
  } u;
} Dynamic_Allocation_t;

typedef struct
{
  guint8 Extended_Dynamic_Allocation;

  guint8 Exist_P0;
  guint8 P0;
  guint8 PR_MODE;

  guint8 USF_GRANULARITY;

  guint8 Exist_UPLINK_TFI_ASSIGNMENT;
  guint8 UPLINK_TFI_ASSIGNMENT;

  guint8 Exist_RLC_DATA_BLOCKS_GRANTED;
  guint8 RLC_DATA_BLOCKS_GRANTED;

  guint8 UnionType;
  union
  {
    Timeslot_Allocation_t Timeslot_Allocation[8];
    Timeslot_Allocation_Power_Ctrl_Param_t Timeslot_Allocation_Power_Ctrl_Param;
  } u;
} DTM_Dynamic_Allocation_t;

typedef struct
{
  guint8 TIMESLOT_NUMBER;

  guint8 Exist_ALPHA_and_GAMMA_TN;
  guint8 ALPHA;
  guint8 GAMMA_TN;

  guint8 Exist_P0;
  guint8 P0;
  guint8 BTS_PWR_CTRL_MODE;
  guint8 PR_MODE;

  Starting_Frame_Number_t TBF_Starting_Time;
} Single_Block_Allocation_t;

typedef struct
{
  guint8 TIMESLOT_NUMBER;

  guint8 Exist_ALPHA_and_GAMMA_TN;
  guint8 ALPHA;
  guint8 GAMMA_TN;

  guint8 Exist_P0;
  guint8 P0;
  guint8 BTS_PWR_CTRL_MODE;
  guint8 PR_MODE;

} DTM_Single_Block_Allocation_t;

typedef struct
{
  guint8 UnionType;
  union
  {
    Global_TFI_t Global_TFI;
    guint32 TLLI;
    guint16 TQI;
    Packet_Request_Reference_t Packet_Request_Reference;
  } u;
} PacketUplinkID_t;

typedef struct
{
  gboolean Exist_Packet_Extended_Timing_Advance;
  guint8   Packet_Extended_Timing_Advance;
} PUA_GPRS_AdditionsR99_t;

typedef struct
{
  guint8                       CHANNEL_CODING_COMMAND;
  guint8                       TLLI_BLOCK_CHANNEL_CODING;
  Packet_Timing_Advance_t     Packet_Timing_Advance;

  guint8                       Exist_Frequency_Parameters;
  Frequency_Parameters_t      Frequency_Parameters;

  guint8                       UnionType;
  union
  {
    guint8                     extension;
    Dynamic_Allocation_t      Dynamic_Allocation;
    Single_Block_Allocation_t Single_Block_Allocation;
    guint8                     FixedAllocationDummy;
  } u;

  gboolean                     Exist_AdditionsR99;
  PUA_GPRS_AdditionsR99_t     AdditionsR99;
} PUA_GPRS_t;

typedef struct
{
  guint8   BitmapLength;
  guint8   ReducedMA_Bitmap[127 / 8 + 1];

  gboolean Exist_MAIO_2;
  guint8   MAIO_2;
} COMPACT_ReducedMA_t;

typedef struct
{
  guint8                   TIMESLOT_NUMBER;

  gboolean                 Exist_ALPHA_GAMMA_TN;
  guint8                   ALPHA;
  guint8                   GAMMA_TN;

  gboolean                 Exist_P0_BTS_PWR_CTRL_PR_MODE;
  guint8                   P0;
  guint8                   BTS_PWR_CTRL_MODE;
  guint8                   PR_MODE;

  Starting_Frame_Number_t TBF_Starting_Time;
  guint8                   NUMBER_OF_RADIO_BLOCKS_ALLOCATED;
} MultiBlock_Allocation_t;

typedef struct
{
  gboolean                     Exist_CONTENTION_RESOLUTION_TLLI;
  guint32                      CONTENTION_RESOLUTION_TLLI;

  gboolean                     Exist_COMPACT_ReducedMA;
  COMPACT_ReducedMA_t         COMPACT_ReducedMA;

  guint8                       EGPRS_CHANNEL_CODING_COMMAND;
  guint8                       RESEGMENT;
  guint8                       EGPRS_WindowSize;

  guint8                       NrOfAccessTechnologies;  /* will hold the number of list elements */
  guint8                       AccessTechnologyType[MAX_ACCESS_TECHOLOGY_TYPES]; /* for max size of array see 24.008/Table 10.5.146 */

  guint8                       ARAC_RETRANSMISSION_REQUEST;
  guint8                       TLLI_BLOCK_CHANNEL_CODING;

  gboolean                     Exist_BEP_PERIOD2;
  guint8                       BEP_PERIOD2;

  Packet_Timing_Advance_t     PacketTimingAdvance;

  gboolean                     Exist_Packet_Extended_Timing_Advance;
  guint8                       Packet_Extended_Timing_Advance;

  gboolean                     Exist_Frequency_Parameters;
  Frequency_Parameters_t      Frequency_Parameters;

  guint8                       UnionType;
  union
  {
    guint8                     extension;
    Dynamic_Allocation_t      Dynamic_Allocation;
    MultiBlock_Allocation_t   MultiBlock_Allocation;
    guint8                     FixedAllocationDummy;/* Fixed Allocation is not used */
  } u;
} PUA_EGPRS_00_t;

typedef struct
{
  guint8            UnionType;
  union
  {
    PUA_EGPRS_00_t PUA_EGPRS_00;
    guint8          PUA_EGPRS_01;
    guint8          PUA_EGPRS_10;
    guint8          PUA_EGPRS_11;
  } u;
} PUA_EGPRS_t;

enum PUA_Type
{
  PUA_GPRS,
  PUA_EGPRS
};

typedef struct
{
  guint8 MESSAGE_TYPE;
  guint8 PAGE_MODE;

  guint8 Exist_PERSISTENCE_LEVEL;
  guint8 PERSISTENCE_LEVEL[4];

  PacketUplinkID_t ID;

  guint8 UnionType;
  union
  {
    PUA_GPRS_t  PUA_GPRS_Struct;
    PUA_EGPRS_t PUA_EGPRS_Struct;
  } u;
} Packet_Uplink_Assignment_t;


/* < DTM Packet Uplink Assignment message content > */
typedef struct
{
  guint8 CHANNEL_CODING_COMMAND;
  guint8 TLLI_BLOCK_CHANNEL_CODING;
  Packet_Timing_Advance_t Packet_Timing_Advance;

  guint8 UnionType;
  union
  {
    guint8 extension;
    DTM_Dynamic_Allocation_t DTM_Dynamic_Allocation;
    DTM_Single_Block_Allocation_t DTM_Single_Block_Allocation;
  } u;
  gboolean Exist_EGPRS_Parameters;
  guint8 EGPRS_CHANNEL_CODING_COMMAND;
  guint8 RESEGMENT;
  guint8 EGPRS_WindowSize;
  gboolean Exist_Packet_Extended_Timing_Advance;
  guint8 Packet_Extended_Timing_Advance;
} DTM_Packet_Uplink_Assignment_t;

typedef struct
{
  DTM_Packet_Uplink_Assignment_t DTM_Packet_Uplink_Assignment;
}DTM_UL_t;

/* < DTM Packet Channel Request message content > */
typedef struct
{
  guint8 DTM_Pkt_Est_Cause;
  Channel_Request_Description_t Channel_Request_Description;
  gboolean                                 Exist_PFI;
  guint8                                   PFI;
}DTM_Channel_Request_Description_t;

/* < Packet Downlink Assignment message content > */
typedef struct
{
  Starting_Frame_Number_t Measurement_Starting_Time;
  guint8 MEASUREMENT_INTERVAL;
  guint8 MEASUREMENT_BITMAP;
} Measurement_Mapping_struct_t;

typedef struct
{
  guint8 UnionType;
  union
  {
    Global_TFI_t Global_TFI;
    guint32 TLLI;
  } u;
} PacketDownlinkID_t;

typedef struct
{
  gboolean Exist_EGPRS_Params; /* if Exist_EGPRS_Params == FALSE then none of the following 4 vars exist */
  guint8   EGPRS_WindowSize;
  guint8   LINK_QUALITY_MEASUREMENT_MODE;
  gboolean Exist_BEP_PERIOD2;
  guint8   BEP_PERIOD2;

  gboolean Exist_Packet_Extended_Timing_Advance;
  guint8   Packet_Extended_Timing_Advance;

  gboolean             Exist_COMPACT_ReducedMA;
  COMPACT_ReducedMA_t COMPACT_ReducedMA;
} PDA_AdditionsR99_t;

typedef struct
{
  guint8                        MESSAGE_TYPE;
  guint8                        PAGE_MODE;

  gboolean                      Exist_PERSISTENCE_LEVEL;
  guint8                        PERSISTENCE_LEVEL[4];

  PacketDownlinkID_t           ID;

  guint8                        MAC_MODE;
  guint8                        RLC_MODE;
  guint8                        CONTROL_ACK;
  guint8                        TIMESLOT_ALLOCATION;
  Packet_Timing_Advance_t      Packet_Timing_Advance;

  gboolean                      Exist_P0_and_BTS_PWR_CTRL_MODE;
  guint8                        P0;
  guint8                        BTS_PWR_CTRL_MODE;
  guint8                        PR_MODE;

  gboolean                      Exist_Frequency_Parameters;
  Frequency_Parameters_t       Frequency_Parameters;

  gboolean                      Exist_DOWNLINK_TFI_ASSIGNMENT;
  guint8                        DOWNLINK_TFI_ASSIGNMENT;

  gboolean                      Exist_Power_Control_Parameters;
  Power_Control_Parameters_t   Power_Control_Parameters;

  gboolean                      Exist_TBF_Starting_Time;
  Starting_Frame_Number_t      TBF_Starting_Time;

  guint8                        Exist_Measurement_Mapping;
  Measurement_Mapping_struct_t Measurement_Mapping;

  gboolean                      Exist_AdditionsR99;
  PDA_AdditionsR99_t           AdditionsR99;
} Packet_Downlink_Assignment_t;

/* < DTM Packet Downlink Assignment message content > */
typedef struct
{
  guint8 MAC_MODE;
  guint8 RLC_MODE;
  guint8 TIMESLOT_ALLOCATION;
  Packet_Timing_Advance_t Packet_Timing_Advance;

  guint8 Exist_P0_and_BTS_PWR_CTRL_MODE;
  guint8 P0;
  guint8 BTS_PWR_CTRL_MODE;
  guint8 PR_MODE;

  guint8 Exist_Power_Control_Parameters;
  Power_Control_Parameters_t Power_Control_Parameters;

  guint8 Exist_DOWNLINK_TFI_ASSIGNMENT;
  guint8 DOWNLINK_TFI_ASSIGNMENT;

  guint8 Exist_Measurement_Mapping;
  Measurement_Mapping_struct_t Measurement_Mapping;
  gboolean EGPRS_Mode;
  guint8 EGPRS_WindowSize;
  guint8 LINK_QUALITY_MEASUREMENT_MODE;
  gboolean Exist_Packet_Extended_Timing_Advance;
  guint8   Packet_Extended_Timing_Advance;
} DTM_Packet_Downlink_Assignment_t;

typedef struct
{
  DTM_Packet_Downlink_Assignment_t DTM_Packet_Downlink_Assignment;
}DTM_DL_t;

typedef struct
{
  GPRS_Cell_Options_t GPRS_Cell_Options;
  GPRS_Power_Control_Parameters_t GPRS_Power_Control_Parameters;
}DTM_GPRS_Broadcast_Information_t;

typedef struct
{
  DTM_GPRS_Broadcast_Information_t DTM_GPRS_Broadcast_Information;
}DTM_GPRS_B_t;

/* < Packet Paging Request message content > */
typedef struct
{
  guint8 UnionType;
  union
  {
    TMSI_t PTMSI;
    struct MobileId Mobile_Identity;
  } u;
} Page_request_for_TBF_establishment_t;

typedef struct
{
  guint8 UnionType;
  union
  {
    TMSI_t TMSI;
    struct MobileId Mobile_Identity;
  } u;

  guint8 CHANNEL_NEEDED;

  guint8 Exist_eMLPP_PRIORITY;
  guint8 eMLPP_PRIORITY;
} Page_request_for_RR_conn_t;

typedef struct
{
  guint8 UnionType;
  union
  {
    Page_request_for_TBF_establishment_t Page_req_TBF;
    Page_request_for_RR_conn_t Page_req_RR;
  } u;
} Repeated_Page_info_t;

typedef struct
{
  guint8 MESSAGE_TYPE;
  guint8 PAGE_MODE;

  guint8 Exist_PERSISTENCE_LEVEL;
  guint8 PERSISTENCE_LEVEL[4];

  guint8 Exist_NLN;
  guint8 NLN;

  guint8 Count_Repeated_Page_info;
  Repeated_Page_info_t Repeated_Page_info[5];
}  Packet_Paging_Request_t;

typedef struct
{
  guint8 MESSAGE_TYPE;
  guint8 PAGE_MODE;

  guint8 TIMESLOTS_AVAILABLE;
} Packet_PDCH_Release_t;

/* < Packet Power Control/Timing Advance message content > */
typedef struct
{
  guint8 UnionType;
  union
  {
    Global_TFI_t Global_TFI;
    guint16 TQI;
    Packet_Request_Reference_t Packet_Request_Reference;
  } u;
} PacketPowerControlTimingAdvanceID_t;

typedef struct
{
  Global_Packet_Timing_Advance_t Global_Packet_Timing_Advance;
  Power_Control_Parameters_t Power_Control_Parameters;
} GlobalTimingAndPower_t;

typedef struct
{
  guint8 UnionType;
  union
  {
    Global_Packet_Timing_Advance_t Global_Packet_Timing_Advance;
    Power_Control_Parameters_t Power_Control_Parameters;
  } u;
} GlobalTimingOrPower_t;

typedef struct
{
  guint8 MESSAGE_TYPE;
  guint8 PAGE_MODE;

  PacketPowerControlTimingAdvanceID_t ID;

  /* -- Message escape */
  guint8 Exist_Global_Power_Control_Parameters;
  Global_Power_Control_Parameters_t Global_Power_Control_Parameters;

  guint8 UnionType;
  union
  {
    GlobalTimingAndPower_t GlobalTimingAndPower;
    GlobalTimingOrPower_t GlobalTimingOrPower;
  } u;
} Packet_Power_Control_Timing_Advance_t;

/* < Packet Queueing Notification message content > */
typedef struct
{
  guint8 MESSAGE_TYPE;
  guint8 PAGE_MODE;

  /* 111 Fixed */
  Packet_Request_Reference_t Packet_Request_Reference;
  guint16 TQI;
} Packet_Queueing_Notification_t;

/* < Packet Timeslot Reconfigure message content 04.60 sec. 11.2.31> */

typedef Dynamic_Allocation_t TRDynamic_Allocation_t;

typedef struct
{
  Global_Packet_Timing_Advance_t Global_Packet_Timing_Advance;

  guint8                          DOWNLINK_RLC_MODE;
  guint8                          CONTROL_ACK;

  guint8                          Exist_DOWNLINK_TFI_ASSIGNMENT;
  guint8                          DOWNLINK_TFI_ASSIGNMENT;

  guint8                          Exist_UPLINK_TFI_ASSIGNMENT;
  guint8                          UPLINK_TFI_ASSIGNMENT;

  guint8                          DOWNLINK_TIMESLOT_ALLOCATION;

  guint8                          Exist_Frequency_Parameters;
  Frequency_Parameters_t         Frequency_Parameters;
} Common_Timeslot_Reconfigure_t;

typedef struct
{
  gboolean Exist_Packet_Extended_Timing_Advance;
  guint8   Packet_Extended_Timing_Advance;
} PTR_GPRS_AdditionsR99_t;

typedef struct
{
  guint8                          CHANNEL_CODING_COMMAND;

  Common_Timeslot_Reconfigure_t  Common_Timeslot_Reconfigure_Data;

  guint8 UnionType;
  union
  {
    TRDynamic_Allocation_t       Dynamic_Allocation;
    guint8                        Fixed_AllocationDummy;
  } u;

   gboolean                       Exist_AdditionsR99;
   PTR_GPRS_AdditionsR99_t       AdditionsR99;
} PTR_GPRS_t;

typedef struct
{
  gboolean                        Exist_COMPACT_ReducedMA;
  COMPACT_ReducedMA_t            COMPACT_ReducedMA;

  guint8                          EGPRS_ChannelCodingCommand;
  guint8                          RESEGMENT;

  gboolean                        Exist_DOWNLINK_EGPRS_WindowSize;
  guint8                          DOWNLINK_EGPRS_WindowSize;

  gboolean                        Exist_UPLINK_EGPRS_WindowSize;
  guint8                          UPLINK_EGPRS_WindowSize;

  guint8                          LINK_QUALITY_MEASUREMENT_MODE;

  gboolean                        Exist_Packet_Extended_Timing_Advance;
  guint8                          Packet_Extended_Timing_Advance;

  Common_Timeslot_Reconfigure_t  Common_Timeslot_Reconfigure_Data;

  guint8                          UnionType;
  union
  {
    TRDynamic_Allocation_t       Dynamic_Allocation;
    guint8                        FixedAllocationDummy;
  } u;
} PTR_EGPRS_00_t;

typedef struct
{
  guint8            UnionType;
  union
  {
    PTR_EGPRS_00_t PTR_EGPRS_00;
    guint8          extension_01;
    guint8          extension_10;
    guint8          extension_11;
  } u;
} PTR_EGPRS_t;

enum PTR_Type
{
  PTR_GPRS,
  PTR_EGPRS
};

typedef struct
{
  guint8          MESSAGE_TYPE;
  guint8          PAGE_MODE;

  Global_TFI_t   Global_TFI;

   guint8         UnionType;
   union
   {
     PTR_GPRS_t  PTR_GPRS_Struct;
     PTR_EGPRS_t PTR_EGPRS_Struct;
   } u;
} Packet_Timeslot_Reconfigure_t;


/* < PSI1 message content > */
typedef struct
{
  guint8 ACC_CONTR_CLASS[2];
  guint8 MAX_RETRANS[4];
  guint8 S;
  guint8 TX_INT;

  guint8 Exist_PERSISTENCE_LEVEL;
  guint8 PERSISTENCE_LEVEL[4];
} PRACH_Control_t;

typedef struct
{
  guint8 BS_PCC_REL;
  guint8 BS_PBCCH_BLKS;
  guint8 BS_PAG_BLKS_RES;
  guint8 BS_PRACH_BLKS;
} PCCCH_Organization_t;

typedef struct
{
  guint8 MSCR;
  guint8 SGSNR;
  guint8 BandIndicator;
} PSI1_AdditionsR99_t;

typedef struct
{
  guint8                             MESSAGE_TYPE;

  guint8                             PAGE_MODE;
  guint8                             PBCCH_CHANGE_MARK;
  guint8                             PSI_CHANGE_FIELD;
  guint8                             PSI1_REPEAT_PERIOD;
  guint8                             PSI_COUNT_LR;

  guint8                             Exist_PSI_COUNT_HR;
  guint8                             PSI_COUNT_HR;

  guint8                             MEASUREMENT_ORDER;
  GPRS_Cell_Options_t               GPRS_Cell_Options;
  PRACH_Control_t                   PRACH_Control;
  PCCCH_Organization_t              PCCCH_Organization;
  Global_Power_Control_Parameters_t Global_Power_Control_Parameters;
  guint8                             PSI_STATUS_IND;

  gboolean                           Exist_AdditionsR99;
  PSI1_AdditionsR99_t               AdditionsR99;
} PSI1_t;

/* < PSI2 message content > */
typedef struct
{
  guint8 NUMBER;

  guint8 Length;
  guint8 Contents[15 + 3];/* octet (val(Length of RFL contents) + 3) */
} Reference_Frequency_t;

typedef struct
{
  guint8 NoOfRFLs;
  guint8 RFL_Number[MAX_RFLS];
} Cell_Allocation_t;

typedef struct
{
  guint8 NUMBER;
  GPRS_Mobile_Allocation_t Mobile_Allocation;
} PSI2_MA_t;

typedef struct
{
  guint16 ARFCN;
  guint8 TIMESLOT_ALLOCATION;
} Non_Hopping_PCCCH_Carriers_t;

typedef struct
{
  guint8 Count_Carriers;
  Non_Hopping_PCCCH_Carriers_t Carriers[7];
} NonHoppingPCCCH_t;

typedef struct
{
  guint8 MAIO;
  guint8 TIMESLOT_ALLOCATION;
} Hopping_PCCCH_Carriers_t;

typedef struct
{
  guint8 MA_NUMBER;

  guint8 Count_Carriers;
  Hopping_PCCCH_Carriers_t Carriers[10];/* MAX_PCCCH but 10 is theoretical max. */
} HoppingPCCCH_t;

typedef struct
{
  guint8 TSC;

  guint8 UnionType;
  union
  {
    NonHoppingPCCCH_t NonHopping;
    HoppingPCCCH_t Hopping;
  } u;
} PCCCH_Description_t;

typedef struct
{
  LAI_t LAI;
  guint8 RAC;
  CellId_t Cell_Identity;
} Cell_Identification_t;

typedef struct
{
  guint8 ATT;

  guint8 Exist_T3212;
  guint8 T3212;

  guint8 NECI;
  guint8 PWRC;
  guint8 DTX;
  guint8 RADIO_LINK_TIMEOUT;
  guint8 BS_AG_BLKS_RES;
  guint8 CCCH_CONF;
  guint8 BS_PA_MFRMS;
  guint8 MAX_RETRANS;
  guint8 TX_INTEGER;
  guint8 EC;
  guint8 MS_TXPWR_MAX_CCCH;

  guint8 Exist_Extension_Bits;
  Extension_Bits_t Extension_Bits;
} Non_GPRS_Cell_Options_t;

typedef struct
{
  guint8 MESSAGE_TYPE;
  guint8 PAGE_MODE;
  guint8 CHANGE_MARK;
  guint8 INDEX;
  guint8 COUNT;

  guint8 Exist_Cell_Identification;
  Cell_Identification_t Cell_Identification;

  guint8 Exist_Non_GPRS_Cell_Options;
  Non_GPRS_Cell_Options_t Non_GPRS_Cell_Options;

  guint8 Count_Reference_Frequency;
  Reference_Frequency_t Reference_Frequency[MAX_RFLS];

  Cell_Allocation_t Cell_Allocation;

  guint8 Count_GPRS_MA;
  PSI2_MA_t GPRS_MA[MAX_MA_LISTS_IN_PSI2];

  guint8 Count_PCCCH_Description;
  PCCCH_Description_t PCCCH_Description[7];/* MAX_PCCCH but it is impossible that more than 7 can be decoded */
} PSI2_t;

/* < PSI3 message content > */
typedef struct
{
  guint8 PRIORITY_CLASS;
  guint8 HCS_THR;
} HCS_t;

typedef struct
{
  guint8 CELL_BAR_ACCESS_2;
  guint8 EXC_ACC;
  guint8 GPRS_RXLEV_ACCESS_MIN;
  guint8 GPRS_MS_TXPWR_MAX_CCH;

  guint8 Exist_HCS;
  HCS_t HCS;
  guint8 MULTIBAND_REPORTING;
} Serving_Cell_params_t;

typedef struct
{
  guint8 GPRS_CELL_RESELECT_HYSTERESIS;
  guint8 C31_HYST;
  guint8 C32_QUAL;
  guint8 RANDOM_ACCESS_RETRY;

  guint8 Exist_T_RESEL;
  guint8 T_RESEL;

  guint8 Exist_RA_RESELECT_HYSTERESIS;
  guint8 RA_RESELECT_HYSTERESIS;
} Gen_Cell_Sel_t;

typedef struct
{
  guint8 PBCCH_LOCATION;
  guint8 PSI1_REPEAT_PERIOD;
} Location_Repeat_t;

typedef struct
{
  guint8 UnionType;
  union
  {
    guint8 SI13_LOCATION;
    Location_Repeat_t lr;
  } u;
} SI13_PBCCH_Location_t;

typedef struct
{
  guint8 BSIC;
  guint8 CELL_BAR_ACCESS_2;
  guint8 EXC_ACC;
  guint8 SAME_RA_AS_SERVING_CELL;

  guint8 Exist_RXLEV_and_TXPWR;
  guint8 GPRS_RXLEV_ACCESS_MIN;
  guint8 GPRS_MS_TXPWR_MAX_CCH;

  guint8 Exist_OFFSET_and_TIME;
  guint8 GPRS_TEMPORARY_OFFSET;
  guint8 GPRS_PENALTY_TIME;

  guint8 Exist_GPRS_RESELECT_OFFSET;
  guint8 GPRS_RESELECT_OFFSET;

  guint8 Exist_HCS;
  HCS_t HCS;

  guint8 Exist_SI13_PBCCH_Location;
  SI13_PBCCH_Location_t SI13_PBCCH_Location;
} Cell_Selection_t;

/* Neigbour cell list as used in PSI3 and PSI3bis */
typedef struct
{
  guint8 FREQ_DIFF_LENGTH;
  guint8 FREQUENCY_DIFF;

  Cell_Selection_t Cell_SelectionParams;
} Cell_Selection_Params_With_FreqDiff_t;

typedef struct
{
  guint16 START_FREQUENCY;
  Cell_Selection_t Cell_Selection;
  guint8 NR_OF_REMAINING_CELLS;
  guint8 FREQ_DIFF_LENGTH;

  Cell_Selection_Params_With_FreqDiff_t Cell_Selection_Params_With_FreqDiff[16];
} NeighbourCellParameters_t;

typedef struct
{
  guint8 Count;
  NeighbourCellParameters_t Parameters[32];
} NeighbourCellList_t;

/* < PSI3 message content > */

typedef struct
{
  guint8  bsic;
  guint8  CELL_BAR_ACCESS_2;
  guint8  EXC_ACC;
  guint8  SAME_RA_AS_SERVING_CELL;
  guint8 Exist_GPRS_RXLEV_ACCESS_MIN;
  guint8  GPRS_RXLEV_ACCESS_MIN;
  guint8  GPRS_MS_TXPWR_MAX_CCH;
  guint8 Exist_GPRS_TEMPORARY_OFFSET;
  guint8  GPRS_TEMPORARY_OFFSET;
  guint8  GPRS_PENALTY_TIME;
  guint8 Exist_GPRS_RESELECT_OFFSET;
  guint8  GPRS_RESELECT_OFFSET;
  guint8 Exist_Hcs_Parm;
  HCS_t   HCS_Param;
  guint8 Exist_TIME_GROUP;
  guint8  TIME_GROUP;
  guint8 Exist_GUAR_CONSTANT_PWR_BLKS;
  guint8  GUAR_CONSTANT_PWR_BLKS;
}COMPACT_Cell_Sel_t;

typedef struct
{
  guint8  FREQ_DIFF_LENGTH;
  guint16 FREQUENCY_DIFF;
  COMPACT_Cell_Sel_t  COMPACT_Cell_Sel_Remain_Cells;
}COMPACT_Neighbour_Cell_Param_Remaining_t;

typedef struct
{
  guint16 START_FREQUENCY;
  COMPACT_Cell_Sel_t COMPACT_Cell_Sel;
  guint8  NR_OF_REMAINING_CELLS;
  guint8  FREQ_DIFF_LENGTH;
  COMPACT_Neighbour_Cell_Param_Remaining_t  COMPACT_Neighbour_Cell_Param_Remaining[16];
}COMPACT_Neighbour_Cell_Param_t;

typedef struct
{
  Cell_Identification_t Cell_Identification;
  guint8  COMPACT_Neighbour_Cell_Param_Count;
  COMPACT_Neighbour_Cell_Param_t COMPACT_Neighbour_Cell_Param[8];
}COMPACT_Info_t;

typedef struct
{
  guint8  Exist_CCN_Support_Desc;
  CCN_Support_Description_t CCN_Support_Desc;
}PSI3_AdditionR4_t;

typedef struct
{
  guint8 Exist_COMPACT_Info;
  COMPACT_Info_t COMPACT_Info;
  guint8 Exist_AdditionR4;
  PSI3_AdditionR4_t AdditionR4;
}PSI3_AdditionR99_t;

typedef struct
{
  LSA_ID_Info_t Scell_LSA_ID_Info;
  guint8 Exist_LSA_Parameters;
  LSA_Parameters_t LSA_Parameters;
  guint8 Exist_AdditionR99;
  PSI3_AdditionR99_t AdditionR99;
}PSI3_AdditionR98_t;

typedef struct
{
  guint8 MESSAGE_TYPE;
  guint8 PAGE_MODE;
  guint8 CHANGE_MARK;
  guint8 BIS_COUNT;

  Serving_Cell_params_t Serving_Cell_params;

  Gen_Cell_Sel_t General_Cell_Selection;
  NeighbourCellList_t NeighbourCellList;

  guint8 Exist_AdditionR98;
  PSI3_AdditionR98_t AdditionR98;
} PSI3_t;

/* < PSI3_BIS message content > */
typedef struct
{
  guint8 MESSAGE_TYPE;
  guint8 PAGE_MODE;
  guint8 CHANGE_MARK;
  guint8 BIS_INDEX;
  guint8 BIS_COUNT;

  NeighbourCellList_t NeighbourCellList;
} PSI3_BIS_t;

/* < PSI4 message content > */
typedef struct
{
  guint8 MA_NUMBER;
  guint8 MAIO;
} h_CG_t;

typedef struct
{
  guint8 UnionType;
  union
  {
    guint16 ARFCN;
    h_CG_t h_CG;
  } u;

  guint8 TIMESLOT_ALLOCATION;
} Channel_Group_t;

typedef struct
{
  /* Channel_Group_t Channel_Group
   * At least one
   * the first one is unpacked in the index
   */
  guint8 Count_Channel_Group;
  Channel_Group_t Channel_Group[8];
} Channel_List_t;

typedef struct
{
  guint8 MESSAGE_TYPE;

  guint8 PAGE_MODE;
  guint8 CHANGE_MARK;
  guint8 INDEX;
  guint8 COUNT;

  Channel_List_t Channel_List;

} PSI4_t;


/* < PSI5 message content > */
typedef struct
{
  guint8 existRepParamsFDD;
  guint8 RepQuantFDD;
  guint8 MultiratReportingFDD;

  guint8 existReportingParamsFDD;
  guint8 ReportingOffsetFDD;
  guint8 ReportingThresholdFDD;

  guint8 existMultiratReportingTDD;
  guint8 MultiratReportingTDD;

  guint8 existOffsetThresholdTDD;
  guint8 ReportingOffsetTDD;
  guint8 ReportingThresholdTDD;
} GPRSMeasurementParams3G_PSI5_t;

typedef struct
{
  guint8   REPORT_TYPE;
  guint8   REPORTING_RATE;
  guint8   INVALID_BSIC_REPORTING;
  guint8  Exist_NCC_PERMITTED;
  guint8   NCC_PERMITTED;
  
  gboolean Exist_GPRSMeasurementParams;
  MeasurementParams_t   GPRSMeasurementParams;
  gboolean Exist_GPRSMeasurementParams3G;
  GPRSMeasurementParams3G_PSI5_t  GPRSMeasurementParams3G;
} ENH_Reporting_Parameters_t;

typedef struct
{
  guint8 Exist_OffsetThreshold_700;
  OffsetThreshold_t OffsetThreshold_700;
  guint8 Exist_OffsetThreshold_810;
  OffsetThreshold_t OffsetThreshold_810;
}PSI5_AdditionsR7;

typedef struct
{
  guint8 Exist_GPRS_AdditionalMeasurementParams3G;
  GPRS_AdditionalMeasurementParams3G_t GPRS_AdditionalMeasurementParams3G;
  guint8 Exist_AdditionsR7;
  PSI5_AdditionsR7 AdditionsR7;
}PSI5_AdditionsR5;

typedef struct
{
  guint8 Exist_ENH_Reporting_Param;
  ENH_Reporting_Parameters_t ENH_Reporting_Param;
  guint8 Exist_AdditionsR5;
  PSI5_AdditionsR5 AdditionisR5;
}PSI5_AdditionsR99;

typedef struct
{
  guint8 MESSAGE_TYPE;

  guint8 PAGE_MODE;
  guint8 CHANGE_MARK;
  guint8 INDEX;
  guint8 COUNT;

  guint8 Eixst_NC_Meas_Param;
  NC_Measurement_Parameters_t NC_Meas_Param;
  guint8 Exist_AdditionsR99;
  PSI5_AdditionsR99 AdditionsR99;
} PSI5_t;




/* < PSI13 message content >
 * Combined with SI13
 */
typedef struct
{
  guint8 Exist_LB_MS_TXPWR_MAX_CCH;
  guint8 LB_MS_TXPWR_MAX_CCH;
  guint8 SI2n_SUPPORT;
}PSI13_AdditionsR6;

typedef PSI13_AdditionsR6 SI13_AdditionsR6;

typedef struct
{
  guint8                SI_STATUS_IND;
  guint8                Exist_AdditionsR6;
  PSI13_AdditionsR6     AdditionsR6;
}PSI13_AdditionsR4;

typedef PSI13_AdditionsR4 SI13_AdditionsR4;

typedef struct
{
  guint8                SGSNR;
  gboolean              Exist_AdditionsR4;
  PSI13_AdditionsR4     AdditionsR4;
}PSI13_AdditionR99;

typedef PSI13_AdditionR99 SI13_AdditionR99;

typedef struct
{
  guint8 Exist;
  guint8 MESSAGE_TYPE;

  guint8 PAGE_MODE;
  guint8 BCCH_CHANGE_MARK;
  guint8 SI_CHANGE_FIELD;

  guint8 Exist_MA;
  guint8 SI13_CHANGE_MARK;
  GPRS_Mobile_Allocation_t GPRS_Mobile_Allocation;

  guint8 UnionType;
  union
  {
    PBCCH_Not_present_t PBCCH_Not_present;
    PBCCH_present_t PBCCH_present;
  } u;

  gboolean              Exist_AdditionsR99;
  PSI13_AdditionR99     AdditionsR99;
} PSI13_t;

/* SI_13_t is combined in the PSI13 structure */
typedef PSI13_t SI_13_t;

/* < Packet PRACH Parameters message content > */
typedef struct
{
  guint8 MESSAGE_TYPE;
  guint8 PAGE_MODE;


  PRACH_Control_t PRACH_Control;
} Packet_PRACH_Parameters_t;

/* < Packet Access Reject message content > */
typedef struct
{
  guint8 UnionType;
  union
  {
    guint32 TLLI;
    Packet_Request_Reference_t Packet_Request_Reference;
    Global_TFI_t Global_TFI;
  } u;
} RejectID_t;

typedef struct
{
  RejectID_t ID;

  guint8 Exist_Wait;
  guint8 WAIT_INDICATION;
  guint8 WAIT_INDICATION_SIZE;
} Reject_t;

typedef struct
{
  guint8 MESSAGE_TYPE;
  guint8 PAGE_MODE;

  guint8 IndexToOur;
  guint8 Count_Reject;
  Reject_t Reject[5];
} Packet_Access_Reject_t;

/* < Packet Cell Change Order message content > */
typedef struct
{
  guint8 CELL_BAR_ACCESS_2;
  guint8 EXC_ACC;
  guint8 SAME_RA_AS_SERVING_CELL;

  guint8 Exist_RXLEV_and_TXPWR;
  guint8 GPRS_RXLEV_ACCESS_MIN;
  guint8 GPRS_MS_TXPWR_MAX_CCH;

  guint8 Exist_OFFSET_and_TIME;
  guint8 GPRS_TEMPORARY_OFFSET;
  guint8 GPRS_PENALTY_TIME;

  guint8 Exist_GPRS_RESELECT_OFFSET;
  guint8 GPRS_RESELECT_OFFSET;

  guint8 Exist_HCS;
  HCS_t HCS;

  guint8 Exist_SI13_PBCCH_Location;
  SI13_PBCCH_Location_t SI13_PBCCH_Location;
} Cell_Selection_2_t;

typedef struct
{
  guint8 FREQUENCY_DIFF;
  guint8 BSIC;
  Cell_Selection_t Cell_Selection;
} h_FreqBsicCell_t;

typedef struct
{
  guint8 FREQ_DIFF_LENGTH;
  guint8 FREQUENCY_DIFF;
  guint8 BSIC;

  gboolean Exist_CellSelectionParams;
  Cell_Selection_2_t CellSelectionParams;
} CellSelectionParamsWithFreqDiff_t;

typedef struct
{
  guint16 START_FREQUENCY;
  guint8 BSIC;

  guint8 Exist_Cell_Selection;
  Cell_Selection_2_t Cell_Selection;

  guint8 NR_OF_FREQUENCIES;
  guint8 FREQ_DIFF_LENGTH;


  CellSelectionParamsWithFreqDiff_t CellSelectionParamsWithFreqDiff[32];
} Add_Frequency_list_t;

typedef struct
{
  guint8 REMOVED_FREQ_INDEX;
} Removed_Freq_Index_t;

typedef struct
{
  guint8 Exist_REMOVED_FREQ;
  guint8 NR_OF_REMOVED_FREQ;
  Removed_Freq_Index_t Removed_Freq_Index[32];

  guint8 Count_Add_Frequency;
  Add_Frequency_list_t Add_Frequency[32];
} NC_Frequency_list_t;


typedef struct
{
  guint8 NETWORK_CONTROL_ORDER;

  guint8 Exist_NC;
  guint8 NC_NON_DRX_PERIOD;
  guint8 NC_REPORTING_PERIOD_I;
  guint8 NC_REPORTING_PERIOD_T;

  guint8 Exist_NC_FREQUENCY_LIST;
  NC_Frequency_list_t NC_Frequency_list;
} NC_Measurement_Parameters_with_Frequency_List_t;


typedef struct
{
  guint8 BA_IND;
  guint8 BA_IND_3G;
} BA_IND_t;

typedef struct
{
  guint8 BA_USED;
  guint8 BA_USED_3G;
} BA_USED_t;

typedef struct
{
  guint8 RXLEV_SERVING_CELL;
} Serving_Cell_Data_t;

typedef struct
{
  guint8 FREQUENCY_N;
  guint8 Exist_BSIC_N;
  guint8 BSIC_N;
  guint8 RXLEV_N;
} NC_Measurements_t;

typedef struct
{
  guint8 BCCH_FREQ_N;
  guint8 BSIC_N;
  guint8 RXLEV_N;
} RepeatedInvalid_BSIC_Info_t;

typedef struct
{
  guint8 Exist_REPORTING_QUANTITY;
  guint8 REPORTING_QUANTITY;
} REPORTING_QUANTITY_Instance_t;

typedef struct
{
  guint8 NC_MODE;
  Serving_Cell_Data_t Serving_Cell_Data;

  guint8 NUMBER_OF_NC_MEASUREMENTS;
  NC_Measurements_t NC_Measurements[6];  /* NC_Measurements * (val(NUMBER_OF_NC_MEASUREMENTS))
                                           Max 7 NC Measurements in one PACKET MEASUREMENT REPORT,
                                           but only 6 cells are updated in PACKET IDLE. */
} NC_Measurement_Report_t;

typedef struct
{
  guint8 EXT_REPORTING_TYPE;

  guint8 Exist_I_LEVEL;
  struct
  {
    guint8 Exist;
    guint8 I_LEVEL;
  } Slot[8];

  guint8 NUMBER_OF_EXT_MEASUREMENTS;
  NC_Measurements_t EXT_Measurements[9];  /* EXT_Measurements * (val(NUMBER_OF_NC_MEASUREMENTS))
                                            Max 9 Ext Measurements in one PACKET MEASUREMENT REPORT */
} EXT_Measurement_Report_t;

typedef struct
{
  guint8 CELL_LIST_INDEX_3G;
  guint8 REPORTING_QUANTITY;
} Measurements_3G_t;

typedef struct
{
  guint32  UTRAN_CGI;
  guint8 Exist_PLMN_ID;
  PLMN_t   Plmn_ID;
  guint32  CSG_ID;
  gboolean Access_Mode;
  guint8   REPORTING_QUANTITY;
}UTRAN_CSG_Measurement_Report_t;

typedef struct
{
  guint32  EUTRAN_CGI;
  guint16  Tracking_Area_Code;
  guint8 Exist_PLMN_ID;
  PLMN_t   Plmn_ID;
  guint32  CSG_ID;
  gboolean Access_Mode;
  guint8   REPORTING_QUANTITY;
}EUTRAN_CSG_Measurement_Report_t;

typedef struct
{
  gboolean  Exist_UTRAN_CSG_Meas_Rpt;
  UTRAN_CSG_Measurement_Report_t  UTRAN_CSG_Meas_Rpt;
  gboolean  Exist_EUTRAN_CSG_Meas_Rpt;
  EUTRAN_CSG_Measurement_Report_t  EUTRAN_CSG_Meas_Rpt;
}PMR_AdditionsR9_t;

typedef struct
{
  guint8  EUTRAN_FREQUENCY_INDEX;
  guint16 CELL_IDENTITY;
  guint8  REPORTING_QUANTITY;
}EUTRAN_Measurement_Report_Body_t;

typedef struct
{
  guint8 N_EUTRAN;
  EUTRAN_Measurement_Report_Body_t Report[4];
}EUTRAN_Measurement_Report_t;

typedef struct
{
  gboolean   Exist_EUTRAN_Meas_Rpt;
  EUTRAN_Measurement_Report_t  EUTRAN_Meas_Rpt;
  gboolean   Exist_AdditionsR9;
  PMR_AdditionsR9_t  AdditionsR9;
}PMR_AdditionsR8_t;

typedef struct
{
  gboolean     Exist_GRNTI;
  guint8        GRNTI;
  gboolean     Exist_AdditionsR8;
  PMR_AdditionsR8_t  AdditionsR8;
}PMR_AdditionsR5_t;

typedef struct
{
  gboolean     Exist_Info3G;
  guint8       UnionType;
  union
  {
    BA_USED_t BA_USED;
    guint8     PSI3_CHANGE_MARK;
  } u;
  guint8       PMO_USED;

  /* N_3G        bit(3): max value 7
   * Report part  (csn): {<3G_CELL_LIST_INDEX:bit(7)><REPORTING_QUANTITY:bit(6)>}*(val(N_3G + 1))
   * Max 6 3G measurement structs in one PMR
   */
  gboolean     Exist_MeasurementReport3G;
  guint8       N_3G;
  Measurements_3G_t Measurements_3G[6];

  gboolean     Exist_AdditionsR5;
  PMR_AdditionsR5_t  AdditionsR5;
} PMR_AdditionsR99_t;

typedef struct
{
  guint8 MESSAGE_TYPE;
  guint8 PayloadType;
  guint8 spare;
  guint8 R;

  guint32 TLLI;
  guint8 Exist_PSI5_CHANGE_MARK;
  guint8 PSI5_CHANGE_MARK;

  guint8 UnionType;
  union
  {
    NC_Measurement_Report_t NC_Measurement_Report;
    EXT_Measurement_Report_t EXT_Measurement_Report;
  } u;

  gboolean Exist_AdditionsR99;
  PMR_AdditionsR99_t AdditionsR99;
} Packet_Measurement_Report_t;

#define INV_BSIC_LIST_LEN (16)

#define REPORT_QUANTITY_LIST_LEN (96) /* Specification specified up to 96 */

typedef struct
{
  guint8 NC_MODE;
  guint8 UnionType;
  union
  {
    BA_USED_t BA_USED;
    guint8 PSI3_CHANGE_MARK;
  } u;

  guint8 PMO_USED;
  guint8 BSIC_Seen;
  guint8 SCALE;

  guint8 Exist_Serving_Cell_Data;
  Serving_Cell_Data_t Serving_Cell_Data;

  guint8 Count_RepeatedInvalid_BSIC_Info;
  RepeatedInvalid_BSIC_Info_t RepeatedInvalid_BSIC_Info[INV_BSIC_LIST_LEN];

  guint8 Exist_ReportBitmap;
  guint8 Count_REPORTING_QUANTITY_Instances;
  REPORTING_QUANTITY_Instance_t REPORTING_QUANTITY_Instances[REPORT_QUANTITY_LIST_LEN];

} ENH_NC_Measurement_Report_t;

typedef struct
{
  guint8 Exist_UTRAN_CSG_Target_Cell;
  UTRAN_CSG_Target_Cell_t UTRAN_CSG_Target_Cell;
  guint8 Exist_EUTRAN_CSG_Target_Cell;
  EUTRAN_CSG_Target_Cell_t EUTRAN_CSG_Target_Cell;  
}PEMR_AdditionsR9_t;

typedef struct
{
  gboolean  Exist_REPORTING_QUANTITY;
  guint8     REPORTING_QUANTITY;
}Bitmap_Report_Quantity_t;

typedef struct
{
  guint8 BITMAP_LENGTH;
  Bitmap_Report_Quantity_t  Bitmap_Report_Quantity[128];
  gboolean  Exist_EUTRAN_Meas_Rpt;
  EUTRAN_Measurement_Report_t EUTRAN_Meas_Rpt;
  gboolean   Exist_AdditionsR9;
  PEMR_AdditionsR9_t AdditionsR9;
}PEMR_AdditionsR8_t;

typedef struct
{
  gboolean  Exist_GRNTI_Ext;
  guint8     GRNTI_Ext;
  gboolean  Exist_AdditionsR8;
  PEMR_AdditionsR8_t  AdditionsR8;
}PEMR_AdditionsR5_t;

typedef struct
{
  guint8 MESSAGE_TYPE;
  guint8 PayloadType;
  guint8 spare;
  guint8 R;

  guint32 TLLI;

  ENH_NC_Measurement_Report_t Measurements;

  gboolean  Exist_AdditionsR5;
  PEMR_AdditionsR5_t  AdditionsR5;
} Packet_Enh_Measurement_Report_t;

typedef struct
{
  guint8 RXLEV_SERVING_CELL;

  guint8 NUMBER_OF_NC_MEASUREMENTS;
  NC_Measurements_t NC_Measurements[6];  /* NC_Measurements * (val(NUMBER_OF_NC_MEASUREMENTS))
                                           Max 7 NC Measurements in one PACKET MEASUREMENT REPORT,
                                           but only 6 cells are updated in PACKET IDLE. */
} CCN_Measurement_Report_t;

typedef struct
{
  guint16 ARFCN;
  guint8 BSIC;
} Target_Cell_GSM_Notif_t;

typedef struct
{
  guint16 FDD_ARFCN;
  guint8 Exist_Bandwith_FDD;
  guint8 BANDWITH_FDD;
  guint16 SCRAMBLING_CODE;
} FDD_Target_Cell_Notif_t;

typedef struct
{
  guint16 TDD_ARFCN;
  guint8 Exist_Bandwith_TDD;
  guint8  BANDWITH_TDD;
  guint8  CELL_PARAMETER;
  guint8  Sync_Case_TSTD;
}TDD_Target_Cell_Notif_t;

typedef struct
{
  guint8 Exist_FDD_Description;
  FDD_Target_Cell_Notif_t FDD_Target_Cell_Notif;
  guint8 Exist_TDD_Description;
  TDD_Target_Cell_Notif_t TDD_Target_Cell;
  guint8 REPORTING_QUANTITY;
} Target_Cell_3G_Notif_t;

typedef struct
{
  guint16 EARFCN;
  guint8 Exist_Measurement_Bandwidth;
  guint8 Measurement_Bandwidth;
  guint16 Physical_Layer_Cell_Identity;
  guint8 Reporting_Quantity;
}Target_EUTRAN_Cell_Notif_t;

typedef struct
{
  guint8  EUTRAN_FREQUENCY_INDEX;
  guint16 CELL_IDENTITY;
  guint8  REPORTING_QUANTITY;
}Eutran_Ccn_Measurement_Report_Cell_t;

typedef struct
{
  gboolean  ThreeG_BA_USED;
  guint8    N_EUTRAN;
  Eutran_Ccn_Measurement_Report_Cell_t Eutran_Ccn_Measurement_Report_Cell[4];
}Eutran_Ccn_Measurement_Report_t;

typedef struct
{
  guint8 Exist_Arfcn;
  guint16 Arfcn;
  guint8  bsic;
  guint8 Exist_3G_Target_Cell;
  Target_Cell_3G_Notif_t Target_Cell_3G_Notif;
  guint8 Exist_Eutran_Target_Cell;
  Target_EUTRAN_Cell_Notif_t Target_EUTRAN_Cell;
  guint8 Exist_Eutran_Ccn_Measurement_Report;
  Eutran_Ccn_Measurement_Report_t Eutran_Ccn_Measurement_Report;
}Target_Cell_4G_Notif_t;

typedef struct
{
  guint8 UnionType;
  union
  {
    UTRAN_CSG_Measurement_Report_t UTRAN_CSG_Measurement_Report;
    EUTRAN_CSG_Measurement_Report_t EUTRAN_CSG_Measurement_Report;
  } u;
  guint8 Exist_Eutran_Ccn_Measurement_Report;
  Eutran_Ccn_Measurement_Report_t Eutran_Ccn_Measurement_Report;
}Target_Cell_CSG_Notif_t;

typedef struct
{
  guint8 UnionType;
  union
  {
    Target_Cell_4G_Notif_t Target_Cell_4G_Notif;
    Target_Cell_CSG_Notif_t Target_Cell_CSG_Notif;
  } u;
}Target_Other_RAT_2_Notif_t;

typedef struct
{
  guint8 UnionType;
  union
  {
    Target_Cell_3G_Notif_t Target_Cell_3G_Notif;
    Target_Other_RAT_2_Notif_t Target_Other_RAT_2_Notif;
  } u;
  
}Target_Other_RAT_Notif_t;

typedef struct
{
  guint8 UnionType;
  union
  {
    Target_Cell_GSM_Notif_t Target_Cell_GSM_Notif;
    Target_Other_RAT_Notif_t Target_Other_RAT_Notif;
  } u;
} Target_Cell_t;

typedef struct
{
  guint8 Exist_BA_USED_3G;
  guint8 BA_USED_3G;

  guint8 N_3G;
  Measurements_3G_t Measurements_3G[6];
} PCCN_AdditionsR6_t;

/* < Packet Cell Change Notification message contents > */
typedef struct
{
  guint8 MESSAGE_TYPE;
  guint8 PayloadType;
  guint8 spare;
  guint8 R;

  Global_TFI_t Global_TFI;

  Target_Cell_t Target_Cell;

  guint8 UnionType;
  union
  {
    guint8 BA_IND;
    guint8 PSI3_CHANGE_MARK;
  } u;
  guint8 PMO_USED;
  guint8 PCCN_SENDING;
  CCN_Measurement_Report_t CCN_Measurement_Report;

  gboolean Exist_AdditionsR6;
  PCCN_AdditionsR6_t AdditionsR6;
} Packet_Cell_Change_Notification_t;

/* < Packet Cell Change Order message contents > */


typedef struct
{
  guint8   FrequencyScrolling;
  guint8   BSIC;
} BSICDesc_t;


#define MAX_BSIC_DESCS (19) /* Due to message size (23 bytes) and header etc,
                             * there cannot be more than 19 DESCS.
                             */

typedef struct
{
  gboolean     Exist_IndexStartBA;
  guint8       IndexStartBA;
  guint8       BSIC;
  guint8       NumRemainingBSICs;
  BSICDesc_t  BSICDesc[MAX_BSIC_DESCS];
} BSICList_t;

typedef BSICList_t GPRSBSICList_t;

#define MAX_RTD_VALUES (6)

typedef struct
{
  guint8  NumRTDValues;
  guint16 RTD[MAX_RTD_VALUES];
} RTDValues_t;

typedef struct
{
  gboolean Exist_StartValue;
  guint8   StartValue;
} BAIndexStartRTD_t;

#define MAX_RTD_FREQS (32)

typedef struct
{
  BAIndexStartRTD_t BAIndexStart;
  guint8 NumFreqs;
  RTDValues_t RTD_s[MAX_RTD_FREQS];
} RTDList_t;

typedef struct
{
  gboolean   Exist_ListRTD6;
  RTDList_t ListRTD6;

  gboolean   Exist_ListRTD12;
  RTDList_t ListRTD12;
} RealTimeDiffs_t;


typedef MeasurementParams_t GPRSMeasurementParams_PMO_PCCO_t;

typedef struct {
  gboolean           existMultiratReporting;
  guint8             MultiratReporting;

  gboolean           existOffsetThreshold;
  OffsetThreshold_t OffsetThreshold;
} MultiratParams3G_t;

typedef struct
{
  guint8              Qsearch_P;
  guint8              SearchPrio3G;

  gboolean            existRepParamsFDD;
  guint8              RepQuantFDD;
  guint8              MultiratReportingFDD;

  gboolean            existOffsetThreshold;
  OffsetThreshold_t  OffsetThreshold;

  MultiratParams3G_t ParamsTDD;
  MultiratParams3G_t ParamsCDMA2000;
} ENH_GPRSMeasurementParams3G_PMO_t;


typedef struct
{
  guint8              Qsearch_P;
  guint8              SearchPrio3G;

  gboolean            existRepParamsFDD;
  guint8              RepQuantFDD;
  guint8              MultiratReportingFDD;

  gboolean            existOffsetThreshold;
  OffsetThreshold_t  OffsetThreshold;

  MultiratParams3G_t ParamsTDD;
} ENH_GPRSMeasurementParams3G_PCCO_t;


typedef struct
{
  guint8 Qsearch_p;
  guint8 SearchPrio3G;

  guint8 existRepParamsFDD;
  guint8 RepQuantFDD;
  guint8 MultiratReportingFDD;

  guint8 existReportingParamsFDD;
  guint8 ReportingOffsetFDD;
  guint8 ReportingThresholdFDD;

  guint8 existMultiratReportingTDD;
  guint8 MultiratReportingTDD;

  guint8 existOffsetThresholdTDD;
  guint8 ReportingOffsetTDD;
  guint8 ReportingThresholdTDD;
} GPRSMeasurementParams3G_t;

typedef struct
{
  guint8 REMOVED_3GCELL_INDEX;
  guint8 CELL_DIFF_LENGTH_3G;
  guint8 CELL_DIFF_3G;
} N2_t;

typedef struct
{
  guint8 N2_Count;
  N2_t N2s[32];
} N1_t;

typedef struct
{
  guint8 N1_Count;
  N1_t N1s[4];
} Removed3GCellDescription_t;

typedef struct
{
  guint8 Complete_This;
} CDMA2000_Description_t;

typedef struct {
  guint8  ZERO;
  guint16 UARFCN;
  guint8  Indic0;
  guint8  NrOfCells;
  guint8  BitsInCellInfo;
  guint8  CellInfo[16]; /* bitmap compressed according to "Range 1024" algorithm (04.18/9.1.54) */
} UTRAN_FDD_NeighbourCells_t;

typedef struct {
  gboolean                        existBandwidth;
  guint8                          Bandwidth;
  guint8                          NrOfFrequencies;
  UTRAN_FDD_NeighbourCells_t     CellParams[8];
} UTRAN_FDD_Description_t;

typedef struct {
  guint8  ZERO;
  guint16 UARFCN;
  guint8  Indic0;
  guint8  NrOfCells;
  guint8  BitsInCellInfo;
  guint8  CellInfo[16]; /* bitmap compressed according to "Range 512" algorithm */
} UTRAN_TDD_NeighbourCells_t;

typedef struct {
  gboolean                        existBandwidth;
  guint8                          Bandwidth;
  guint8                          NrOfFrequencies;
  UTRAN_TDD_NeighbourCells_t    CellParams[8];
} UTRAN_TDD_Description_t;

typedef struct
{
  guint8 Exist_Index_Start_3G;
  guint8 Index_Start_3G;
  guint8 Exist_Absolute_Index_Start_EMR;
  guint8 Absolute_Index_Start_EMR;
  guint8 Exist_UTRAN_FDD_Description;
  UTRAN_FDD_Description_t UTRAN_FDD_Description;
  guint8 Exist_UTRAN_TDD_Description;
  UTRAN_TDD_Description_t UTRAN_TDD_Description;
  guint8 Exist_CDMA2000_Description;
  CDMA2000_Description_t CDMA2000_Description;
  guint8 Exist_Removed3GCellDescription;
  Removed3GCellDescription_t Removed3GCellDescription;
} NeighbourCellDescription3G_PMO_t;

typedef struct
{
  guint8 Exist_Index_Start_3G;
  guint8 Index_Start_3G;
  guint8 Exist_Absolute_Index_Start_EMR;
  guint8 Absolute_Index_Start_EMR;
  guint8 Exist_UTRAN_FDD_Description;
  UTRAN_FDD_Description_t UTRAN_FDD_Description;
  guint8 Exist_UTRAN_TDD_Description;
  UTRAN_TDD_Description_t UTRAN_TDD_Description;
  guint8 Exist_Removed3GCellDescription;
  Removed3GCellDescription_t Removed3GCellDescription;
} NeighbourCellDescription3G_PCCO_t;

typedef struct
{
  guint8 UnionType;
  union
  {
    BA_IND_t BA_IND;
    guint8 PSI3_CHANGE_MARK;
  } u;

  guint8   PMO_IND;

  guint8   REPORT_TYPE;
  guint8   REPORTING_RATE;
  guint8   INVALID_BSIC_REPORTING;

  gboolean Exist_NeighbourCellDescription3G;
  NeighbourCellDescription3G_PMO_t NeighbourCellDescription3G;

  gboolean Exist_GPRSReportPriority;
  GPRSReportPriority_t GPRSReportPriority;

  gboolean Exist_GPRSMeasurementParams;
  GPRSMeasurementParams_PMO_PCCO_t GPRSMeasurementParams;
  gboolean Exist_GPRSMeasurementParams3G;
  ENH_GPRSMeasurementParams3G_PMO_t GPRSMeasurementParams3G;
} ENH_Measurement_Parameters_PMO_t;

typedef struct
{
  guint8 UnionType;
  union
  {
    BA_IND_t BA_IND;
    guint8 PSI3_CHANGE_MARK;
  } u;

  guint8   PMO_IND;

  guint8   REPORT_TYPE;
  guint8   REPORTING_RATE;
  guint8   INVALID_BSIC_REPORTING;

  gboolean Exist_NeighbourCellDescription3G;
  NeighbourCellDescription3G_PCCO_t NeighbourCellDescription3G;

  gboolean Exist_GPRSReportPriority;
  GPRSReportPriority_t GPRSReportPriority;

  gboolean Exist_GPRSMeasurementParams;
  GPRSMeasurementParams_PMO_PCCO_t GPRSMeasurementParams;
  gboolean Exist_GPRSMeasurementParams3G;
  ENH_GPRSMeasurementParams3G_PCCO_t GPRSMeasurementParams3G;
} ENH_Measurement_Parameters_PCCO_t;

typedef struct
{
  guint8 UnionType;
  union
  {
    Global_TFI_t Global_TFI;
    guint32 TLLI;
  } u;
} PacketCellChangeOrderID_t;

typedef struct
{
  guint8 CELL_BAR_QUALIFY_3;
  guint8 Exist_SI13_Alt_PBCCH_Location;
  SI13_PBCCH_Location_t SI13_Alt_PBCCH_Location;
} lu_ModeCellSelectionParameters_t;

typedef struct
{
  guint8 Exist_lu_ModeCellSelectionParams;
  lu_ModeCellSelectionParameters_t lu_ModeCellSelectionParameters;
} lu_ModeCellSelectionParams_t;

typedef struct
{
  lu_ModeCellSelectionParams_t lu_ModeCellSelectionParameters;
  guint8 NR_OF_FREQUENCIES;
  lu_ModeCellSelectionParams_t lu_ModeCellSelectionParams[32];
} lu_ModeNeighbourCellParams_t;

typedef struct
{
  guint8 CELL_BAR_QUALIFY_3;
  guint8 SAME_RA_AS_SERVING_CELL;

  guint8 Exist_RXLEV_and_TXPWR;
  guint8 GPRS_RXLEV_ACCESS_MIN;
  guint8 GPRS_MS_TXPWR_MAX_CCH;

  guint8 Exist_OFFSET_and_TIME;
  guint8 GPRS_TEMPORARY_OFFSET;
  guint8 GPRS_PENALTY_TIME;

  guint8 Exist_GPRS_RESELECT_OFFSET;
  guint8 GPRS_RESELECT_OFFSET;

  guint8 Exist_HCS;
  HCS_t HCS;

  guint8 Exist_SI13_Alt_PBCCH_Location;
  SI13_PBCCH_Location_t SI13_Alt_PBCCH_Location;
} lu_ModeOnlyCellSelection_t;

typedef struct
{
  guint8 FREQ_DIFF_LENGTH;
  guint8 FREQUENCY_DIFF;
  guint8 BSIC;

  gboolean Exist_lu_ModeOnlyCellSelectionParams;
  lu_ModeOnlyCellSelection_t lu_ModeOnlyCellSelectionParams;
} lu_ModeOnlyCellSelectionParamsWithFreqDiff_t;

typedef struct
{
  guint16 START_FREQUENCY;
  guint8 BSIC;

  guint8 Exist_lu_ModeCellSelection;
  lu_ModeOnlyCellSelection_t lu_ModeOnlyCellSelection;

  guint8 NR_OF_FREQUENCIES;
  guint8 FREQ_DIFF_LENGTH;

  lu_ModeOnlyCellSelectionParamsWithFreqDiff_t lu_ModeOnlyCellSelectionParamsWithFreqDiff[32];
} Add_lu_ModeOnlyFrequencyList_t;

typedef struct
{
  guint8 Count_Add_lu_ModeOnlyFrequencyList;
  Add_lu_ModeOnlyFrequencyList_t Add_lu_ModeOnlyFrequencyList[32];
} NC_lu_ModeOnlyCapableCellList_t;


typedef struct
{
  guint8                   NumberOfFrequencyIndexes;
  guint8                   UTRAN_FREQUENCY_INDEX_a[18];

  gboolean                 existUTRAN_PRIORITY;
  guint8                   UTRAN_PRIORITY;

  guint8                   THRESH_UTRAN_high;

  gboolean                 existTHRESH_UTRAN_low;
  guint8                   THRESH_UTRAN_low;

  gboolean                 existUTRAN_QRXLEVMIN;
  guint8                   UTRAN_QRXLEVMIN;
} RepeatedUTRAN_PriorityParameters_t;

typedef struct
{
  gboolean                            existDEFAULT_UTRAN_Parameters;
  guint8                              DEFAULT_UTRAN_PRIORITY;
  guint8                              DEFAULT_THRESH_UTRAN;
  guint8                              DEFAULT_UTRAN_QRXLEVMIN;

  guint8                              NumberOfPriorityParameters;
  RepeatedUTRAN_PriorityParameters_t  RepeatedUTRAN_PriorityParameters_a[8];
} PriorityParametersDescription3G_PMO_t;

typedef struct
{
  gboolean existEUTRAN_FDD_REPORTING_THRESHOLD_OFFSET;
  guint8   EUTRAN_FDD_REPORTING_THRESHOLD;
  gboolean existEUTRAN_FDD_REPORTING_THRESHOLD_2;
  guint8   EUTRAN_FDD_REPORTING_THRESHOLD_2;
  gboolean existEUTRAN_FDD_REPORTING_OFFSET;
  guint8   EUTRAN_FDD_REPORTING_OFFSET;

  gboolean existEUTRAN_TDD_REPORTING_THRESHOLD_OFFSET;
  guint8   EUTRAN_TDD_REPORTING_THRESHOLD;
  gboolean existEUTRAN_TDD_REPORTING_THRESHOLD_2;
  guint8   EUTRAN_TDD_REPORTING_THRESHOLD_2;
  gboolean existEUTRAN_TDD_REPORTING_OFFSET;
  guint8   EUTRAN_TDD_REPORTING_OFFSET;
} EUTRAN_REPORTING_THRESHOLD_OFFSET_t;

typedef struct
{
  guint8                               Qsearch_P_EUTRAN;
  guint8                               EUTRAN_REP_QUANT;
  guint8                               EUTRAN_MULTIRAT_REPORTING;
  EUTRAN_REPORTING_THRESHOLD_OFFSET_t EUTRAN_REPORTING_THRESHOLD_OFFSET;
} GPRS_EUTRAN_MeasurementParametersDescription_t;

typedef struct
{
  guint16  EARFCN;
  gboolean existMeasurementBandwidth;
  guint8   MeasurementBandwidth;
} RepeatedEUTRAN_Cells_t;

typedef struct
{
  guint8                   nbrOfEUTRAN_Cells;
  RepeatedEUTRAN_Cells_t  EUTRAN_Cells_a[6];

  gboolean                 existEUTRAN_PRIORITY;
  guint8                   EUTRAN_PRIORITY;

  guint8                   THRESH_EUTRAN_high;

  gboolean                 existTHRESH_EUTRAN_low;
  guint8                   THRESH_EUTRAN_low;

  gboolean                 existEUTRAN_QRXLEVMIN;
  guint8                   EUTRAN_QRXLEVMIN;
} RepeatedEUTRAN_NeighbourCells_t;

typedef struct
{
  guint16 PCID;
} PCID_t;

typedef struct
{
  guint8 PCID_Pattern_length;
  guint8 PCID_Pattern;
  guint8 PCID_Pattern_sense;
} PCID_Pattern_t;

typedef struct
{
  guint8          NumberOfPCIDs;
  guint16         PCID_a[11];

  gboolean        existPCID_BITMAP_GROUP;
  guint8          PCID_BITMAP_GROUP;

  guint8          NumberOfPCID_Patterns;
  PCID_Pattern_t PCID_Pattern_a[19];
} PCID_Group_IE_t;

typedef struct
{
  guint8 EUTRAN_FREQUENCY_INDEX;
} EUTRAN_FREQUENCY_INDEX_t;

typedef struct
{
  PCID_Group_IE_t          NotAllowedCells;
  guint8                    NumberOfFrequencyIndexes;
  EUTRAN_FREQUENCY_INDEX_t EUTRAN_FREQUENCY_INDEX_a[28];
} RepeatedEUTRAN_NotAllowedCells_t;

typedef struct
{
  guint8                    NumberOfMappings;
  PCID_Group_IE_t          PCID_ToTA_Mapping_a[14];

  guint8                    NumberOfFrequencyIndexes;
  EUTRAN_FREQUENCY_INDEX_t EUTRAN_FREQUENCY_INDEX_a[28];
} RepeatedEUTRAN_PCID_to_TA_mapping_t;

typedef struct
{
  guint8 EUTRAN_CCN_ACTIVE;

  gboolean                                       existGPRS_EUTRAN_MeasurementParametersDescription;
  GPRS_EUTRAN_MeasurementParametersDescription_t GPRS_EUTRAN_MeasurementParametersDescription;

  guint8                                         nbrOfRepeatedEUTRAN_NeighbourCellsStructs;
  RepeatedEUTRAN_NeighbourCells_t                RepeatedEUTRAN_NeighbourCells_a[4];

  guint8                                         NumberOfNotAllowedCells;
  RepeatedEUTRAN_NotAllowedCells_t               RepeatedEUTRAN_NotAllowedCells_a[14];

  guint8                                         NumberOfMappings;
  RepeatedEUTRAN_PCID_to_TA_mapping_t            RepeatedEUTRAN_PCID_to_TA_mapping_a[19];
} EUTRAN_ParametersDescription_PMO_t;

typedef struct
{
  guint8 GERAN_PRIORITY;
  guint8 THRESH_Priority_Search;
  guint8 THRESH_GSM_low;
  guint8 H_PRIO;
  guint8 T_Reselection;
} ServingCellPriorityParametersDescription_t;

typedef struct
{
  gboolean                                   existServingCellPriorityParametersDescription;
  ServingCellPriorityParametersDescription_t ServingCellPriorityParametersDescription;

  gboolean                                   existPriorityParametersDescription3G_PMO;
  PriorityParametersDescription3G_PMO_t      PriorityParametersDescription3G_PMO;

  gboolean                                   existEUTRAN_ParametersDescription_PMO;
  EUTRAN_ParametersDescription_PMO_t         EUTRAN_ParametersDescription_PMO;
} PriorityAndEUTRAN_ParametersDescription_PMO_t;

typedef struct
{
  guint8  PSC_Pattern_length;
  guint8  PSC_Pattern;
  gboolean PSC_Pattern_sense;
}PSC_Pattern_t;

typedef struct
{
  guint8  PSC_Count;
  guint16 PSC[32];
  guint8  PSC_Pattern_Count;
  PSC_Pattern_t PSC_Pattern[32];
}PSC_Group_t;

typedef struct
{
  PSC_Group_t CSG_PSC_SPLIT;
  guint8      Count;
  guint8      UTRAN_FREQUENCY_INDEX[32];
}ThreeG_CSG_Description_Body_t;

typedef struct
{
  guint8  Count;
  ThreeG_CSG_Description_Body_t  ThreeG_CSG_Description_Body[32];
}ThreeG_CSG_Description_t;

typedef struct
{
  PSC_Group_t CSG_PCI_SPLIT;
  guint8  Count;
  guint8  EUTRAN_FREQUENCY_INDEX[32];
}EUTRAN_CSG_Description_Body_t;

typedef struct
{
  guint8  Count;
  EUTRAN_CSG_Description_Body_t EUTRAN_CSG_Description_Body[32];
}EUTRAN_CSG_Description_t;

typedef struct
{
  gboolean  existMeasurement_Control_EUTRAN;
  gboolean  Measurement_Control_EUTRAN;
  guint8    EUTRAN_FREQUENCY_INDEX_top;
  guint8    Count_EUTRAN_FREQUENCY_INDEX;
  guint8    EUTRAN_FREQUENCY_INDEX[32];
  
  gboolean  existMeasurement_Control_UTRAN;
  gboolean  Measurement_Control_UTRAN;
  guint8    UTRAN_FREQUENCY_INDEX_top;
  guint8    Count_UTRAN_FREQUENCY_INDEX;
  guint8    UTRAN_FREQUENCY_INDEX[32];
}Meas_Ctrl_Param_Desp_t;

typedef struct
{
  guint8    THRESH_EUTRAN_high_Q;
  gboolean existTHRESH_EUTRAN_low_Q;
  guint8    THRESH_EUTRAN_low_Q;
  gboolean existEUTRAN_QQUALMIN;
  guint8    EUTRAN_QQUALMIN;
  gboolean existEUTRAN_RSRPmin;
  guint8    EUTRAN_RSRPmin;
}Reselection_Based_On_RSRQ_t;

typedef struct
{
  guint8  Count_EUTRAN_FREQUENCY_INDEX;
  guint8  EUTRAN_FREQUENCY_INDEX[32];
  guint8 UnionType;
  union
  {
    guint8           EUTRAN_Qmin;
    Reselection_Based_On_RSRQ_t Reselection_Based_On_RSRQ;
  } u;
}Rept_EUTRAN_Enh_Cell_Resel_Param_t;

typedef struct
{
  guint8 Count;
  Rept_EUTRAN_Enh_Cell_Resel_Param_t Repeated_EUTRAN_Enhanced_Cell_Reselection_Parameters[32];
}Enh_Cell_Reselect_Param_Desp_t;

typedef struct
{
  gboolean  existUTRAN_CSG_FDD_REPORTING_THRESHOLD;
  guint8     UTRAN_CSG_FDD_REPORTING_THRESHOLD;
  guint8     UTRAN_CSG_FDD_REPORTING_THRESHOLD_2;
  gboolean  existUTRAN_CSG_TDD_REPORTING_THRESHOLD;
  guint8     UTRAN_CSG_TDD_REPORTING_THRESHOLD;
}UTRAN_CSG_Cells_Reporting_Desp_t;

typedef struct
{
  gboolean  existEUTRAN_CSG_FDD_REPORTING_THRESHOLD;
  guint8     EUTRAN_CSG_FDD_REPORTING_THRESHOLD;
  guint8     EUTRAN_CSG_FDD_REPORTING_THRESHOLD_2;
  gboolean  existEUTRAN_CSG_TDD_REPORTING_THRESHOLD;
  guint8     EUTRAN_CSG_TDD_REPORTING_THRESHOLD;
  guint8     EUTRAN_CSG_TDD_REPORTING_THRESHOLD_2;
}EUTRAN_CSG_Cells_Reporting_Desp_t;

typedef struct
{
  gboolean  existUTRAN_CSG_Cells_Reporting_Description;
  UTRAN_CSG_Cells_Reporting_Desp_t UTRAN_CSG_Cells_Reporting_Description;
  gboolean  existEUTRAN_CSG_Cells_Reporting_Description;
  EUTRAN_CSG_Cells_Reporting_Desp_t EUTRAN_CSG_Cells_Reporting_Description;
}CSG_Cells_Reporting_Desp_t;

typedef struct
{
  gboolean                       existEnhanced_Cell_Reselection_Parameters_Description;
  Enh_Cell_Reselect_Param_Desp_t  Enhanced_Cell_Reselection_Parameters_Description;
  
  gboolean                       existCSG_Cells_Reporting_Description;
  CSG_Cells_Reporting_Desp_t      CSG_Cells_Reporting_Description;
}PMO_AdditionsR9_t;

typedef struct
{
  guint8 dummy;
}Delete_All_Stored_Individual_Priorities_t;

typedef struct
{
  guint8  Count;
  guint16 FDD_ARFCN[32];
}Individual_UTRAN_Priority_FDD_t;

typedef struct
{
  guint8  Count;
  guint16 TDD_ARFCN[32];
}Individual_UTRAN_Priority_TDD_t;

typedef struct
{
  guint8 UnionType;
  union
  {
    Individual_UTRAN_Priority_FDD_t Individual_UTRAN_Priority_FDD;
    Individual_UTRAN_Priority_TDD_t Individual_UTRAN_Priority_TDD;
  } u;
  guint8 UTRAN_PRIORITY;
}Repeated_Individual_UTRAN_Priority_Parameters_t;

typedef struct
{
  guint8 Exist_DEFAULT_UTRAN_PRIORITY;
  guint8 DEFAULT_UTRAN_PRIORITY;
  guint8 Repeated_Individual_UTRAN_Priority_Parameters_Count;
  Repeated_Individual_UTRAN_Priority_Parameters_t Repeated_Individual_UTRAN_Priority_Parameters[32];
}ThreeG_Individual_Priority_Parameters_Description_t;

typedef struct
{
  guint8 Count;
  guint16 EARFCN[32];
  guint8 EUTRAN_PRIORITY;
}Repeated_Individual_EUTRAN_Priority_Parameters_t;

typedef struct
{
  guint8 Exist_DEFAULT_EUTRAN_PRIORITY;
  guint8 DEFAULT_EUTRAN_PRIORITY;
  guint8 Count;
  Repeated_Individual_EUTRAN_Priority_Parameters_t Repeated_Individual_EUTRAN_Priority_Parameters[32];
}EUTRAN_Individual_Priority_Parameters_Description_t;

typedef struct
{
  guint8 GERAN_PRIORITY;
  guint8 Exist_3G_Individual_Priority_Parameters_Description;
  ThreeG_Individual_Priority_Parameters_Description_t ThreeG_Individual_Priority_Parameters_Description;
  guint8 Exist_EUTRAN_Individual_Priority_Parameters_Description;
  EUTRAN_Individual_Priority_Parameters_Description_t EUTRAN_Individual_Priority_Parameters_Description;
  guint8 Exist_T3230_timeout_value;
  guint8 T3230_timeout_value;
}Provide_Individual_Priorities_t;

typedef struct
{
  guint8 UnionType;
  union
  {
    Delete_All_Stored_Individual_Priorities_t Delete_All_Stored_Individual_Priorities;
    Provide_Individual_Priorities_t Provide_Individual_Priorities;
  } u;
}Individual_Priorities_t;

typedef struct
{
  gboolean          existBA_IND_3G_PMO_IND;
  guint8            BA_IND_3G;
  guint8            PMO_IND;

  gboolean          existPriorityAndEUTRAN_ParametersDescription_PMO;
  PriorityAndEUTRAN_ParametersDescription_PMO_t PriorityAndEUTRAN_ParametersDescription_PMO;

  gboolean          existIndividualPriorities_PMO;
  Individual_Priorities_t  IndividualPriorities_PMO;

  gboolean          existThreeG_CSG_Description;
  ThreeG_CSG_Description_t  ThreeG_CSG_Description_PMO;

  gboolean          existEUTRAN_CSG_Description;
  EUTRAN_CSG_Description_t  EUTRAN_CSG_Description_PMO;

  gboolean          existMeasurement_Control_Parameters_Description;
  Meas_Ctrl_Param_Desp_t Measurement_Control_Parameters_Description_PMO;

  gboolean          existAdditionsR9;
  PMO_AdditionsR9_t AdditionsR9;
} PMO_AdditionsR8_t;

typedef struct
{
  gboolean          existREPORTING_OFFSET_THRESHOLD_700;
  guint8            REPORTING_OFFSET_700;
  guint8            REPORTING_THRESHOLD_700;

  gboolean          existREPORTING_OFFSET_THRESHOLD_810;
  guint8            REPORTING_OFFSET_810;
  guint8            REPORTING_THRESHOLD_810;

  guint8 existAdditionsR8;
  PMO_AdditionsR8_t additionsR8;
} PMO_AdditionsR7_t;

typedef struct
{
  guint8 CCN_ACTIVE_3G;
  guint8 existAdditionsR7;
  PMO_AdditionsR7_t additionsR7;
} PMO_AdditionsR6_t;

typedef struct
{
  guint8 CCN_ACTIVE_3G;
} PCCO_AdditionsR6_t;

typedef struct
{
  guint8 existGRNTI_Extension;
  guint8 GRNTI;
  guint8 exist_lu_ModeNeighbourCellParams;
  guint8 count_lu_ModeNeighbourCellParams;
  lu_ModeNeighbourCellParams_t lu_ModeNeighbourCellParams[32];
  guint8 existNC_lu_ModeOnlyCapableCellList;
  NC_lu_ModeOnlyCapableCellList_t NC_lu_ModeOnlyCapableCellList;
  guint8 existGPRS_AdditionalMeasurementParams3G;
  GPRS_AdditionalMeasurementParams3G_t GPRS_AdditionalMeasurementParams3G;
  guint8 existAdditionsR6;
  PMO_AdditionsR6_t additionsR6;
} PMO_AdditionsR5_t;

typedef struct
{
  guint8 existGRNTI_Extension;
  guint8 GRNTI;
  guint8 exist_lu_ModeNeighbourCellParams;
  guint8 count_lu_ModeNeighbourCellParams;
  lu_ModeNeighbourCellParams_t lu_ModeNeighbourCellParams[32];
  guint8 existNC_lu_ModeOnlyCapableCellList;
  NC_lu_ModeOnlyCapableCellList_t NC_lu_ModeOnlyCapableCellList;
  guint8 existGPRS_AdditionalMeasurementParams3G;
  GPRS_AdditionalMeasurementParams3G_t GPRS_AdditionalMeasurementParams3G;
  guint8 existAdditionsR6;
  PCCO_AdditionsR6_t additionsR6;
} PCCO_AdditionsR5_t;

typedef struct
{
  guint8 CCN_ACTIVE;
  guint8 Exist_CCN_Support_Description_ID;
  CCN_Support_Description_t CCN_Support_Description;
  guint8 Exist_AdditionsR5;
  PMO_AdditionsR5_t AdditionsR5;
} PMO_AdditionsR4_t;

typedef struct
{
  guint8 CCN_ACTIVE;
  guint8 Exist_Container_ID;
  guint8 CONTAINER_ID;
  guint8 Exist_CCN_Support_Description_ID;
  CCN_Support_Description_t CCN_Support_Description;
  guint8 Exist_AdditionsR5;
  PCCO_AdditionsR5_t AdditionsR5;
} PCCO_AdditionsR4_t;

typedef struct
{
  ENH_Measurement_Parameters_PCCO_t ENH_Measurement_Parameters;
  guint8 Exist_AdditionsR4;
  PCCO_AdditionsR4_t AdditionsR4;
} PCCO_AdditionsR99_t;

typedef struct
{
  guint8 Exist_ENH_Measurement_Parameters;
  ENH_Measurement_Parameters_PMO_t ENH_Measurement_Parameters;
  guint8 Exist_AdditionsR4;
  PMO_AdditionsR4_t AdditionsR4;
} PMO_AdditionsR99_t;

typedef struct
{
  guint8 Exist_LSA_Parameters;
  LSA_Parameters_t LSA_Parameters;

  guint8 Exist_AdditionsR99;
  PMO_AdditionsR99_t AdditionsR99;
} PMO_AdditionsR98_t;

typedef struct
{
  guint8 Exist_LSA_Parameters;
  LSA_Parameters_t LSA_Parameters;

  guint8 Exist_AdditionsR99;
  PCCO_AdditionsR99_t AdditionsR99;
} PCCO_AdditionsR98_t;

typedef struct
{
  guint8 IMMEDIATE_REL;
  guint16 ARFCN;
  guint8 BSIC;
  NC_Measurement_Parameters_with_Frequency_List_t NC_Measurement_Parameters;

  guint8 Exist_AdditionsR98;
  PCCO_AdditionsR98_t AdditionsR98;
} Target_Cell_GSM_t;

typedef struct
{
  guint8 Exist_EUTRAN_Target_Cell;
  EUTRAN_Target_Cell_t EUTRAN_Target_Cell;
  guint8 Exist_Individual_Priorities;
  Individual_Priorities_t Individual_Priorities;
}Target_Cell_3G_AdditionsR8_t;

typedef struct
{
  guint8 Exist_G_RNTI_Extention;
  guint8 G_RNTI_Extention;
  guint8 Exist_AdditionsR8;
  Target_Cell_3G_AdditionsR8_t AdditionsR8;
}Target_Cell_3G_AdditionsR5_t;

typedef struct
{
  /* 00 -- Message escape */
  guint8 IMMEDIATE_REL;
  guint8 Exist_FDD_Description;
  FDD_Target_Cell_t FDD_Target_Cell;
  guint8 Exist_TDD_Description;
  TDD_Target_Cell_t TDD_Target_Cell;
  guint8 Exist_AdditionsR5;
  Target_Cell_3G_AdditionsR5_t AdditionsR5;
} Target_Cell_3G_t;

#define TARGET_CELL_GSM 0
#define TARGET_CELL_3G 1

typedef struct
{
  guint8 MESSAGE_TYPE;
  guint8 PAGE_MODE;

  PacketCellChangeOrderID_t ID;

  guint8 UnionType;
  union
  {
    Target_Cell_GSM_t Target_Cell_GSM;
    Target_Cell_3G_t Target_Cell_3G;
  } u;

} Packet_Cell_Change_Order_t;

/* < Packet Cell Change Continue message contents > */
typedef struct
{
  guint8 MESSAGE_TYPE;
  guint8 PAGE_MODE;

  Global_TFI_t Global_TFI;
  guint8 Exist_ID;
  guint16 ARFCN;
  guint8 BSIC;
  guint8 CONTAINER_ID;
} Packet_Cell_Change_Continue_t;


/* < Packet Neighbour Cell Data message contents > */
typedef struct
{
  guint16 ARFCN;
  guint8 BSIC;
  guint8 CONTAINER[17];     /* PD (3 bits) + CD_LENGTH (5 bits) + 16 bytes of CONTAINER_DATA (max!) */
} PNCD_Container_With_ID_t;

typedef struct
{
  guint8 CONTAINER[19];     /* PD (3 bits) + CD_LENGTH (5 bits) + 18 bytes of CONTAINER_DATA (max!) */
} PNCD_Container_Without_ID_t;

typedef struct
{
  guint8 UnionType;
  union
  {
    PNCD_Container_Without_ID_t PNCD_Container_Without_ID;
    PNCD_Container_With_ID_t PNCD_Container_With_ID;
  } u;
} PNCDContainer_t;

typedef struct
{
  guint8 MESSAGE_TYPE;
  guint8 PAGE_MODE;
  /* Fixed 0 */
  Global_TFI_t Global_TFI;
  guint8 CONTAINER_ID;
  guint8 spare;
  guint8 CONTAINER_INDEX;

  PNCDContainer_t Container;
} Packet_Neighbour_Cell_Data_t;

/* < Packet Serving Cell Data message contents > */
typedef struct
{
  guint8 MESSAGE_TYPE;
  guint8 PAGE_MODE;
  /* Fixed 0 */
  Global_TFI_t Global_TFI;
  guint8 spare;
  guint8 CONTAINER_INDEX;
  guint8 CONTAINER[19];     /* PD (3 bits) + CD_LENGTH (5 bits) + 18 bytes of CONTAINER_DATA (max!) */
} Packet_Serving_Cell_Data_t;

/* < Packet Measurement Order message contents > */
typedef struct
{
  guint16 START_FREQUENCY;
  guint8 NR_OF_FREQUENCIES;
  guint8 FREQ_DIFF_LENGTH;

  guint8 Count_FREQUENCY_DIFF;
  guint8 FREQUENCY_DIFF[31];/* bit (FREQ_DIFF_LENGTH) * NR_OF_FREQUENCIES --> MAX is bit(7) * 31 */
} EXT_Frequency_List_t;

typedef struct
{
  guint8 MESSAGE_TYPE;
  guint8 PAGE_MODE;

  PacketDownlinkID_t ID; /* use the PDA ID as it is the same as as the PMO */

  guint8 PMO_INDEX;
  guint8 PMO_COUNT;

  guint8 Exist_NC_Measurement_Parameters;
  NC_Measurement_Parameters_with_Frequency_List_t NC_Measurement_Parameters;

  guint8 Exist_EXT_Measurement_Parameters;

  guint8 Exist_AdditionsR98;
  PMO_AdditionsR98_t AdditionsR98;
} Packet_Measurement_Order_t;

typedef struct
{
  guint8 MESSAGE_TYPE;
  guint8 PAGE_MODE;
  PacketDownlinkID_t ID;
} Packet_Measurement_Order_Reduced_t;

/* Enhanced measurement report */

typedef struct
{
  guint8   RXLEV_SERVING_CELL;
} ServingCellData_t;

typedef struct
{
  guint8   BCCH_FREQ_NCELL;
  guint8   BSIC;
  guint8   RXLEV_NCELL;
} Repeated_Invalid_BSIC_Info_t;

typedef struct
{
  gboolean Exist_REPORTING_QUANTITY;
  guint8   REPORTING_QUANTITY;
} REPORTING_QUANTITY_t;

typedef struct
{
  guint8                NC_MODE;
  guint8 UnionType;
  union
  {
    BA_USED_t           BA_USED;
    guint8              PSI3_CHANGE_MARK;
  } u;
  guint8 PMO_USED;
  guint8 SCALE;
  guint8 Exist_ServingCellData;
  ServingCellData_t   ServingCellData;
  guint8   Count_Repeated_Invalid_BSIC_Info;
  Repeated_Invalid_BSIC_Info_t Repeated_Invalid_BSIC_Info[32];

  gboolean Exist_Repeated_REPORTING_QUANTITY;
  guint8   Count_Repeated_Reporting_Quantity;
  REPORTING_QUANTITY_t   Repeated_REPORTING_QUANTITY[96];
} NC_MeasurementReport_t;

/* Packet Handover  PHO ----------------- */

typedef struct
{
  guint8 UnionType;
  union
  {
    guint8 MS_TimeslotAllocation;
    Power_Control_Parameters_t Power_Control_Parameters;
  } u;
} GlobalTimeslotDescription_t;

typedef struct
{
  guint8 TimeslotAllocation;
  guint8 PFI;
  guint8 RLC_Mode;
  guint8 TFI_Assignment;
  guint8 ControlACK;
  guint8 Exist_EGPRS_WindowSize;
  guint8 EGPRS_WindowSize;
} PHO_DownlinkAssignment_t;

typedef struct
{
  gboolean Exist_USF;
  guint8 USF;
} PHO_USF_1_7_t;

typedef struct
{
  guint8 USF_0;
  PHO_USF_1_7_t USF_1_7[7];
  guint8 NBR_OfAllocatedTimeslots;
} USF_AllocationArray_t;

typedef struct
{
  guint8 PFI;
  guint8 RLC_Mode;
  guint8 TFI_Assignment;
  guint8 Exist_ChannelCodingCommand;
  guint8 ChannelCodingCommand;
  guint8 Exist_EGPRS_ChannelCodingCommand;
  guint8 EGPRS_ChannelCodingCommand;
  guint8 Exist_EGPRS_WindowSize;
  guint8 EGPRS_WindowSize;
  guint8 USF_Granularity;
  guint8 Exist_TBF_TimeslotAllocation;
  guint8 TBF_TimeslotAllocation;
  guint8 UnionType;
  union
  {
    guint8 USF_SingleAllocation;
    USF_AllocationArray_t USF_AllocationArray;
  } u;
} PHO_UplinkAssignment_t;

typedef struct
{
  GlobalTimeslotDescription_t GlobalTimeslotDescription;
  guint8 Exist_PHO_UA;
  PHO_UplinkAssignment_t PHO_UA;
} GlobalTimeslotDescription_UA_t;

typedef struct
{
  guint8 Exist_ChannelCodingCommand;
  guint8 ChannelCodingCommand;
  guint8 Exist_GlobalTimeslotDescription_UA;
  GlobalTimeslotDescription_UA_t GTD_UA;
  guint8 Exist_DownlinkAssignment;
  PHO_DownlinkAssignment_t DownlinkAssignment;
} PHO_GPRS_t;


typedef struct
{
  guint8 Exist_EGPRS_WindowSize;
  guint8 EGPRS_WindowSize;
  guint8 LinkQualityMeasurementMode;
  guint8 Exist_BEP_Period2;
  guint8 BEP_Period2;
} EGPRS_Description_t;

typedef struct
{
  guint8 Exist_EGPRS_Description;
  EGPRS_Description_t EGPRS_Description;
  guint8 Exist_DownlinkAssignment;
  PHO_DownlinkAssignment_t DownlinkAssignment;
} DownlinkTBF_t;

typedef struct
{
  guint8 Exist_EGPRS_WindowSize;
  guint8 EGPRS_WindowSize;
  guint8 Exist_EGPRS_ChannelCodingCommand;
  guint8 EGPRS_ChannelCodingCommand;
  guint8 Exist_BEP_Period2;
  guint8 BEP_Period2;
  guint8 Exist_GlobalTimeslotDescription_UA;
  GlobalTimeslotDescription_UA_t GTD_UA;
  guint8 Exist_DownlinkTBF;
  DownlinkTBF_t DownlinkTBF;
}PHO_EGPRS_t;

typedef struct
{
  Global_Packet_Timing_Advance_t    GlobalPacketTimingAdvance;
  guint8 Exist_PacketExtendedTimingAdvance;
  guint8 PacketExtendedTimingAdvance;
} PHO_TimingAdvance_t;

typedef struct
{
  guint8 NAS_ContainerLength;
  guint8 NAS_Container[MAX_NAS_CONTAINER_LENGTH];
} NAS_Container_t;

typedef struct
{
  guint8 RRC_ContainerLength;
  guint8 RRC_Container[MAX_RRC_CONTAINER_LENGTH];
} PS_HandoverTo_UTRAN_Payload_t;


typedef struct
{
  guint8 Exist_HandoverReference;
  guint8 HandoverReference;
  guint8 ARFCN;
  guint8 SI;
  guint8 NCI;
  guint8 BSIC;
  guint8 Exist_CCN_Active;
  guint8 CCN_Active;
  guint8 Exist_CCN_Active_3G;
  guint8 CCN_Active_3G;
  guint8 Exist_CCN_Support_Description;
  CCN_Support_Description_t CCN_Support_Description;
  Frequency_Parameters_t    Frequency_Parameters;
  guint8 NetworkControlOrder;
  guint8 Exist_PHO_TimingAdvance;
  PHO_TimingAdvance_t PHO_TimingAdvance;
  guint8 Extended_Dynamic_Allocation;
  guint8 RLC_Reset;
  guint8 Exist_PO_PR;
  guint8 PO;
  guint8 PR_Mode;
  guint8 Exist_UplinkControlTimeslot;
  guint8 UplinkControlTimeslot;
  guint8 UnionType;
  union
  {
    PHO_GPRS_t  PHO_GPRS_Mode;
    PHO_EGPRS_t PHO_EGPRS_Mode;
  } u;
} PHO_RadioResources_t;

typedef struct
{
  PHO_RadioResources_t PHO_RadioResources;
  guint8 Exist_NAS_Container;
  NAS_Container_t NAS_Container;
} PS_HandoverTo_A_GB_ModePayload_t;

typedef struct
{
  guint8 MessageType;
  guint8 PageMode;
  Global_TFI_t Global_TFI;
  guint8 ContainerID;
  guint8 UnionType;
  union
  {
    PS_HandoverTo_A_GB_ModePayload_t PS_HandoverTo_A_GB_ModePayload;
    PS_HandoverTo_UTRAN_Payload_t    PS_HandoverTo_UTRAN_Payload;
  } u;
} Packet_Handover_Command_t;

/* End Packet Handover */

/* Packet Physical Information ----------------- */

typedef struct
{
  guint8 MessageType;
  guint8 PageMode;
  Global_TFI_t Global_TFI;
  guint8 TimingAdvance;
} Packet_PhysicalInformation_t;

/* End Packet Physical Information */



/*  ADDITIONAL MS RADIO ACCESS CAPABILITIES -----------------*/
typedef struct
{
  guint8 UnionType;
  union
  {
    Global_TFI_t Global_TFI;
    guint32 TLLI;
  } u;
} AdditionalMsRadAccessCapID_t;


typedef struct
{
  guint8 MESSAGE_TYPE;
  guint8 PayloadType;
  guint8 spare;
  guint8 R;

  AdditionalMsRadAccessCapID_t ID;
  MS_Radio_Access_capability_t MS_Radio_Access_capability;
} Additional_MS_Rad_Access_Cap_t;

/* End ADDITIONAL MS RADIO ACCESS CAPABILITIES */


/* Packet Pause -----------------*/

typedef struct
{
  guint8 MESSAGE_TYPE;

  guint32 TLLI;
  guint8  RAI[48/8];
} Packet_Pause_t;

/* End Packet Pause */


/*
< NC Measurement Parameters struct > ::=
                                        < NETWORK_CONTROL_ORDER : bit (2) >
                                        { 0 | 1 < NC_ NON_DRX_PERIOD : bit (3) >
                                        < NC_REPORTING_PERIOD_I : bit (3) >
                                        < NC_REPORTING_PERIOD_T : bit (3) > } ;
< Cell Selection struct > ::=
                             < EXC_ACC : bit >
                             < CELL_BAR_ACCESS_2 : bit (1) >
                             < SAME_RA_AS_SERVING_CELL : bit (1) >
                             { 0 | 1  < GPRS_RXLEV_ACCESS_MIN : bit (6) >
                             < GPRS_MS_TXPWR_MAX_CCH : bit (5) > }
{ 0 | 1 < GPRS_TEMPORARY_OFFSET : bit (3) >
   < GPRS_PENALTY_TIME : bit (5) > }
Table 25 (concluded): PACKET CELL CHANGE ORDER message content
   { 0 | 1  < GPRS_RESELECT_OFFSET : bit (5) > }
{ 0 | 1  < HCS params : < HCS struct > > }
{ 0 | 1 < SI13_PBCCH_LOCATION : < SI13_PBCCH_LOCATION struct > > } ;

< SI13_PBCCH_LOCATION struct > ::=
                                  { 0  < SI13_LOCATION : bit (1) >
                                  | 1  < PBCCH_LOCATION : bit (2) >
                                  < PSI1_REPEAT_PERIOD : bit (4) > } ;

< HCS struct > ::=
                  < GPRS_PRIORITY_CLASS : bit (3) >
                  < GPRS_HCS_THR : bit (5) > ;
*/

/* < Downlink RLC/MAC control message > */
#define MT_PACKET_CELL_CHANGE_ORDER            0x01
#define MT_PACKET_DOWNLINK_ASSIGNMENT          0x02
#define MT_PACKET_MEASUREMENT_ORDER            0x03
#define MT_PACKET_POLLING_REQ                  0x04
#define MT_PACKET_POWER_CONTROL_TIMING_ADVANCE 0x05
#define MT_PACKET_QUEUEING_NOTIFICATION        0x06
#define MT_PACKET_TIMESLOT_RECONFIGURE         0x07
#define MT_PACKET_TBF_RELEASE                  0x08
#define MT_PACKET_UPLINK_ACK_NACK              0x09
#define MT_PACKET_UPLINK_ASSIGNMENT            0x0A
#define MT_PACKET_CELL_CHANGE_CONTINUE         0x0B
#define MT_PACKET_NEIGHBOUR_CELL_DATA          0x0C
#define MT_PACKET_SERVING_CELL_DATA            0x0D
#define MT_PACKET_HANDOVER_COMMAND             0x15
#define MT_PACKET_PHYSICAL_INFORMATION         0x16
#define MT_PACKET_ACCESS_REJECT                0x21
#define MT_PACKET_PAGING_REQUEST               0x22
#define MT_PACKET_PDCH_RELEASE                 0x23
#define MT_PACKET_PRACH_PARAMETERS             0x24
#define MT_PACKET_DOWNLINK_DUMMY_CONTROL_BLOCK 0x25
#define MT_PACKET_SYSTEM_INFO_6                0x30
#define MT_PACKET_SYSTEM_INFO_1                0x31
#define MT_PACKET_SYSTEM_INFO_2                0x32
#define MT_PACKET_SYSTEM_INFO_3                0x33
#define MT_PACKET_SYSTEM_INFO_3_BIS            0x34
#define MT_PACKET_SYSTEM_INFO_4                0x35
#define MT_PACKET_SYSTEM_INFO_5                0x36
#define MT_PACKET_SYSTEM_INFO_13               0x37
#define MT_PACKET_SYSTEM_INFO_7                0x38
#define MT_PACKET_SYSTEM_INFO_8                0x39
#define MT_PACKET_SYSTEM_INFO_14               0x3A
#define MT_PACKET_SYSTEM_INFO_3_TER            0x3C
#define MT_PACKET_SYSTEM_INFO_3_QUATER         0x3D
#define MT_PACKET_SYSTEM_INFO_15               0x3E

/* < Uplink RLC/MAC control message > */
#define MT_PACKET_CELL_CHANGE_FAILURE          0x00
#define MT_PACKET_CONTROL_ACK                  0x01
#define MT_PACKET_DOWNLINK_ACK_NACK            0x02
#define MT_PACKET_UPLINK_DUMMY_CONTROL_BLOCK   0x03
#define MT_PACKET_MEASUREMENT_REPORT           0x04
#define MT_PACKET_RESOURCE_REQUEST             0x05
#define MT_PACKET_MOBILE_TBF_STATUS            0x06
#define MT_PACKET_PSI_STATUS                   0x07
#define MT_EGPRS_PACKET_DOWNLINK_ACK_NACK      0x08
#define MT_PACKET_PAUSE                        0x09
#define MT_PACKET_ENHANCED_MEASUREMENT_REPORT  0x0A
#define MT_ADDITIONAL_MS_RAC                   0x0B
#define MT_PACKET_CELL_CHANGE_NOTIFICATION     0x0C
#define MT_PACKET_SI_STATUS                    0x0D
#define MT_ENHANCED_MEASUREMENT_REPORT         0x04

/* < Downlink RLC/MAC control message > */
typedef struct
{
  union
  {
    guint8                                MESSAGE_TYPE;
    Packet_Access_Reject_t                Packet_Access_Reject;
    Packet_Cell_Change_Order_t            Packet_Cell_Change_Order;
    Packet_Downlink_Assignment_t          Packet_Downlink_Assignment;
    Packet_Measurement_Order_Reduced_t    Packet_Measurement_Order;
    Packet_Neighbour_Cell_Data_t          Packet_Neighbour_Cell_Data;
    Packet_Serving_Cell_Data_t            Packet_Serving_Cell_Data;
    Packet_Paging_Request_t               Packet_Paging_Request;
    Packet_PDCH_Release_t                 Packet_PDCH_Release;
    Packet_Polling_Request_t              Packet_Polling_Request;
    Packet_Power_Control_Timing_Advance_t Packet_Power_Control_Timing_Advance;
    Packet_PRACH_Parameters_t             Packet_PRACH_Parameters;
    Packet_Queueing_Notification_t        Packet_Queueing_Notification;
    Packet_Timeslot_Reconfigure_t         Packet_Timeslot_Reconfigure;
    Packet_TBF_Release_t                  Packet_TBF_Release;
    Packet_Uplink_Ack_Nack_t              Packet_Uplink_Ack_Nack;
    Packet_Uplink_Assignment_t            Packet_Uplink_Assignment;
    Packet_Cell_Change_Continue_t         Packet_Cell_Change_Continue;
    Packet_Handover_Command_t             Packet_Handover_Command;
    Packet_PhysicalInformation_t          Packet_PhysicalInformation;
    Packet_Downlink_Dummy_Control_Block_t Packet_Downlink_Dummy_Control_Block;

    PSI1_t                                PSI1;
    PSI2_t                                PSI2;
    PSI3_t                                PSI3;
    PSI3_BIS_t                            PSI3_BIS;
    PSI4_t                                PSI4;
    PSI13_t                               PSI13;
    PSI5_t                                PSI5;
  } u;

  /* NrOfBits is placed after union to avoid unnecessary code changes when addressing the union members
   * NrOfBits serves dual purpose:
   * 1. before unpacking it will hold the max number of bits for the CSN.1 unpacking function
   * 2. after successful unpacking it will hold the number of bits unpacked from a message.
   *   This will be needed for some EGPRS messages to compute the length of included variable bitmap
   */
  gint16 NrOfBits;
} RlcMacDownlink_t;

typedef gint16 MSGGPRS_Status_t;
/* < Uplink RLC/MAC control message > */
typedef struct
{
  union
  {
    guint8 MESSAGE_TYPE;
    Packet_Cell_Change_Failure_t          Packet_Cell_Change_Failure;
    Packet_Control_Acknowledgement_t      Packet_Control_Acknowledgement;
    Packet_Downlink_Ack_Nack_t            Packet_Downlink_Ack_Nack;
    EGPRS_PD_AckNack_t							Egprs_Packet_Downlink_Ack_Nack;
    Packet_Uplink_Dummy_Control_Block_t   Packet_Uplink_Dummy_Control_Block;
    Packet_Measurement_Report_t           Packet_Measurement_Report;
    Packet_Resource_Request_t             Packet_Resource_Request;
    Packet_Mobile_TBF_Status_t            Packet_Mobile_TBF_Status;
    Packet_PSI_Status_t                   Packet_PSI_Status;
    Packet_Enh_Measurement_Report_t       Packet_Enh_Measurement_Report;
    Packet_Cell_Change_Notification_t     Packet_Cell_Change_Notification;
    Packet_SI_Status_t                    Packet_SI_Status;
	Additional_MS_Rad_Access_Cap_t        Additional_MS_Rad_Access_Cap;
	Packet_Pause_t                        Packet_Pause;
  } u;
  gint16 NrOfBits;
} RlcMacUplink_t;


void GPRSMSG_Profile(gint16 i);

/* SI1_RestOctet_t */

typedef struct
{
  gboolean            Exist_NCH_Position;
  guint8              NCH_Position;

  guint8              BandIndicator;
} SI1_RestOctet_t;

/* SI3_Rest_Octet_t */
typedef struct
{
  guint8 CBQ;
  guint8 CELL_RESELECT_OFFSET;
  guint8 TEMPORARY_OFFSET;
  guint8 PENALTY_TIME;
} Selection_Parameters_t;

typedef struct
{
  guint8 Exist_Selection_Parameters;
  Selection_Parameters_t Selection_Parameters;

  guint8 Exist_Power_Offset;
  guint8 Power_Offset;

  guint8 System_Information_2ter_Indicator;
  guint8 Early_Classmark_Sending_Control;

  guint8 Exist_WHERE;
  guint8 WHERE;

  guint8 Exist_GPRS_Indicator;
  guint8 RA_COLOUR;
  guint8 SI13_POSITION;
  guint8 ECS_Restriction3G;
  guint8 ExistSI2quaterIndicator;
  guint8 SI2quaterIndicator;
} SI3_Rest_Octet_t;

typedef struct
{
  guint8 Exist_Selection_Parameters;
  Selection_Parameters_t Selection_Parameters;

  guint8 Exist_Power_Offset;
  guint8 Power_Offset;

  guint8 Exist_GPRS_Indicator;
  guint8 RA_COLOUR;
  guint8 SI13_POSITION;
} SI4_Rest_Octet_t;

typedef SI4_Rest_Octet_t SI7_Rest_Octet_t;
typedef SI4_Rest_Octet_t SI8_Rest_Octet_t;


/* SI6_RestOctet_t */

typedef struct
{
  guint8   PagingChannelRestructuring;
  guint8   NLN_SACCH;

  gboolean Exist_CallPriority;
  guint8   CallPriority;

  guint8   NLN_Status;
} PCH_and_NCH_Info_t;

typedef struct
{
  gboolean            Exist_PCH_and_NCH_Info;
  PCH_and_NCH_Info_t PCH_and_NCH_Info;

  gboolean            Exist_VBS_VGCS_Options;
  guint8              VBS_VGCS_Options;

  /* The meaning of Exist_DTM_Support is as follows:
   * FALSE => DTM is not supported in the serving cell, RAC and MAX_LAPDm are absent in bitstream
   * TRUE  => DTM is supported in the serving cell, RAC and MAX_LAPDm are present in bitstream
   */
  gboolean            Exist_DTM_Support;
  guint8              RAC;
  guint8              MAX_LAPDm;

  guint8              BandIndicator; /* bit(1) L/H, L => ARFCN in 1800 band H => ARFCN in 1900 band */
} SI6_RestOctet_t;

/*************************************************
 * Enhanced Measurement Report. TS 04.18 9.1.55. *
 *************************************************/

typedef struct
{
  guint8        DTX_USED;
  guint8        RXLEV_VAL;
  guint8        RX_QUAL_FULL;
  guint8        MEAN_BEP;
  guint8        CV_BEP;
  guint8        NBR_RCVD_BLOCKS;
} EMR_ServingCell_t;

typedef struct
{
  guint8 RR_Short_PD;
  guint8 MESSAGE_TYPE;
  guint8 ShortLayer2_Header;

  BA_USED_t BA_USED;
  guint8 BSIC_Seen;

  guint8 SCALE;

  guint8 Exist_ServingCellData;
  EMR_ServingCell_t ServingCellData;

  guint8 Count_RepeatedInvalid_BSIC_Info; /* Number of instances */
  RepeatedInvalid_BSIC_Info_t RepeatedInvalid_BSIC_Info[INV_BSIC_LIST_LEN];

  guint8 Exist_ReportBitmap;
  guint8 Count_REPORTING_QUANTITY_Instances; /* Number of instances */
  REPORTING_QUANTITY_Instance_t REPORTING_QUANTITY_Instances[REPORT_QUANTITY_LIST_LEN];

} EnhancedMeasurementReport_t;

#endif /* __PACKET_GSM_RLCMAC_H__ */
