/* packet-gsm_rlcmac.h
 * Definitions for GSM RLC MAC control plane message dissection in wireshark.
 * TS 44.060 and 24.008
 * By Vincent Helfre, based on original code by Jari Sassi
 * with the gracious authorization of STE
 * Copyright (c) 2011 ST-Ericsson
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef __PACKET_GSM_RLCMAC_H__
#define __PACKET_GSM_RLCMAC_H__

#ifndef PRE_PACKED
#define PRE_PACKED
#endif

#ifndef POST_PACKED
#define POST_PACKED
#endif

#define GSM_RLC_MAC_MAGIC_NUMBER  0x67707273

typedef uint8_t TFI_t;

typedef uint8_t N32_t;
typedef uint8_t N51_t;
typedef uint8_t N26_t;

/*  Starting Time IE as specified in 04.08 */
typedef struct
{
  N32_t N32;  /* 04.08 refers to T1' := (FN div 1326) mod 32 */
  N51_t N51;  /* 04.08 refers to T3 := FN mod 51 */
  N26_t N26;  /* 04.08 refers to T2 := FN mod 26 */
} StartingTime_t;

typedef struct
{
  uint8_t UnionType;/* UnionType is index */
  union
  {
    uint8_t UPLINK_TFI;
    uint8_t DOWNLINK_TFI;
  } u;
} Global_TFI_t;

typedef struct
{
  uint8_t UnionType;
  union
  {
    StartingTime_t StartingTime;
    uint16_t k;
  } u;
} Starting_Frame_Number_t;

typedef struct
{
  uint8_t FINAL_ACK_INDICATION;
  uint8_t STARTING_SEQUENCE_NUMBER;
  uint8_t RECEIVED_BLOCK_BITMAP[64/8];
} Ack_Nack_Description_t;


typedef struct
{
  uint8_t Exist_TIMING_ADVANCE_VALUE;
  uint8_t TIMING_ADVANCE_VALUE;

  uint8_t Exist_IndexAndtimeSlot;
  uint8_t TIMING_ADVANCE_INDEX;
  uint8_t TIMING_ADVANCE_TIMESLOT_NUMBER;
} Packet_Timing_Advance_t;

typedef struct
{
  uint8_t ALPHA;

  struct
  {
    uint8_t Exist;
    uint8_t GAMMA_TN;
  } Slot[8];
} Power_Control_Parameters_t;

typedef struct
{
  uint8_t ALPHA;
  uint8_t T_AVG_W;
  uint8_t T_AVG_T;
  uint8_t Pb;
  uint8_t PC_MEAS_CHAN;
  uint8_t INT_MEAS_CHANNEL_LIST_AVAIL;
  uint8_t N_AVG_I;
} Global_Power_Control_Parameters_t;

typedef struct
{
  uint8_t Exist_TIMING_ADVANCE_VALUE;
  uint8_t TIMING_ADVANCE_VALUE;

  uint8_t Exist_UPLINK_TIMING_ADVANCE;
  uint8_t UPLINK_TIMING_ADVANCE_INDEX;
  uint8_t UPLINK_TIMING_ADVANCE_TIMESLOT_NUMBER;

  uint8_t Exist_DOWNLINK_TIMING_ADVANCE;
  uint8_t DOWNLINK_TIMING_ADVANCE_INDEX;
  uint8_t DOWNLINK_TIMING_ADVANCE_TIMESLOT_NUMBER;
} Global_Packet_Timing_Advance_t;


typedef struct
{
  uint8_t C_VALUE;
  uint8_t RXQUAL;
  uint8_t SIGN_VAR;

  struct
  {
    uint8_t Exist;
    uint8_t I_LEVEL_TN;
  } Slot[8];
} Channel_Quality_Report_t;

typedef enum
{
  RLC_MODE_ACKNOWLEDGED = 0,
  RLC_MODE_UNACKNOWLEDGED = 1
} RLC_MODE_t;

typedef struct
{
  uint8_t PEAK_THROUGHPUT_CLASS;
  uint8_t RADIO_PRIORITY;
  RLC_MODE_t RLC_MODE;
  uint8_t LLC_PDU_TYPE;
  uint16_t RLC_OCTET_COUNT;
} Channel_Request_Description_t;

typedef struct
{
  uint16_t RANDOM_ACCESS_INFORMATION;
  uint8_t FRAME_NUMBER[2];
} Packet_Request_Reference_t;

typedef PRE_PACKED struct
{
  uint8_t nsapi;
  uint8_t value;
} Receive_N_PDU_Number_t POST_PACKED;

typedef PRE_PACKED struct
{
  uint8_t IEI;
  uint8_t Length;

  uint8_t Count_Receive_N_PDU_Number;
  Receive_N_PDU_Number_t Receive_N_PDU_Number[11];
} Receive_N_PDU_Number_list_t POST_PACKED;

/** IMSI length */
#define IMSI_LEN  9

/** TMSI length */
#define TMSI_LEN  4

typedef  struct
{
  uint8_t MCC1;
  uint8_t MCC2;
  uint8_t MCC3;
  uint8_t MNC3;
  uint8_t MNC1;
  uint8_t MNC2;
} PLMN_t;


/** This type is used to describe LAI codes */
typedef PRE_PACKED struct
{
  PLMN_t  PLMN;
  uint16_t LAC;
} LAI_t POST_PACKED;


/** Length of LAI */
#define LAI_LEN  (sizeof(LAI_t))

typedef struct
{
  uint8_t      TMSI[TMSI_LEN];
} TMSI_t;

typedef uint16_t CellId_t;


#define CKSN_NOT_VALID                7

#define IMEI_LEN                      9

#define IMEISV_LEN                    10

#define MAX_ELEMENTS_IN_EQPLMN_LIST   16


typedef struct
{
  uint8_t NUMBER_CELLS;
  uint8_t CCN_SUPPORTED[16];  /* bit (1), max size: 16 x 8 => 128 bits */
} CCN_Support_Description_t;

typedef struct
{
  uint8_t UnionType;
  union
  {
    uint8_t LSA_ID;
    uint8_t ShortLSA_ID;
  } u;
} LSA_ID_Info_Element_t;

#define LSA_ID_INFO_ELEMENTS_MAX (16)

typedef struct
{
  uint8_t Count_LSA_ID_Info_Element;
  LSA_ID_Info_Element_t LSA_ID_Info_Elements[LSA_ID_INFO_ELEMENTS_MAX];
} LSA_ID_Info_t;

#define NR_OF_FREQ_OR_CELLS_MAX (32)

typedef struct
{
  uint8_t NR_OF_FREQ_OR_CELLS;
  LSA_ID_Info_t LSA_ID_Info[NR_OF_FREQ_OR_CELLS_MAX];
} LSA_Parameters_t;

#define MAX_REPORT_PRIORITY_CELLS (16)

typedef struct
{
  uint8_t NUMBER_CELLS;
  uint8_t REPORT_PRIORITY[MAX_REPORT_PRIORITY_CELLS];
} ReportPriority_t;

typedef ReportPriority_t GPRSReportPriority_t;

typedef struct
{
  uint8_t REPORTING_OFFSET;
  uint8_t REPORTING_THRESHOLD;
} OffsetThreshold_t;


typedef struct
{
  uint8_t            Exist_MULTI_BAND_REPORTING;
  uint8_t            MULTI_BAND_REPORTING;

  uint8_t            Exist_SERVING_BAND_REPORTING;
  uint8_t            SERVING_BAND_REPORTING;

  /* Warning:
   *
   * SI2quater, MI, PMO, and PCCO always specify Scale Ord.  There is no
   * "exist SCALE_ORD" bit in the CSN.1 descriptions for these messages.
   * However, this struct is shared with the PSI5 message which may or may
   * not specify SCALE_ORD, thus necessitating the inclusion of member
   * Exist_SCALE_ORD in the struct.  This member is never set for SI2quater, MI,
   * PMO, and PCCO so to check it (in these cases) would be erroneous.
   */
  uint8_t            Exist_SCALE_ORD;
  uint8_t            SCALE_ORD;

  uint8_t            Exist_OffsetThreshold900;
  OffsetThreshold_t OffsetThreshold900;

  uint8_t            Exist_OffsetThreshold1800;
  OffsetThreshold_t OffsetThreshold1800;

  uint8_t            Exist_OffsetThreshold400;
  OffsetThreshold_t OffsetThreshold400;

  uint8_t            Exist_OffsetThreshold1900;
  OffsetThreshold_t OffsetThreshold1900;

  uint8_t            Exist_OffsetThreshold850;
  OffsetThreshold_t OffsetThreshold850;

} MeasurementParams_t;

typedef struct
{
  uint8_t Exist_FDD_REPORTING_THRESHOLD_2;
  uint8_t FDD_REPORTING_THRESHOLD_2;
} GPRS_AdditionalMeasurementParams3G_t;


typedef struct
{
  uint8_t NETWORK_CONTROL_ORDER;

  uint8_t Exist_NC;
  uint8_t NC_NON_DRX_PERIOD;
  uint8_t NC_REPORTING_PERIOD_I;
  uint8_t NC_REPORTING_PERIOD_T;
} NC_Measurement_Parameters_t;


/*
**========================================================================
**  Global types
**========================================================================
*/

struct MobileId     /* Mobile id, -> TMSI, IMEI or IMSI */
{
  uint8_t Length;
  uint8_t IdType;
  uint8_t OddEven;
  uint8_t Dig1;
  union
  {
    unsigned char TMSI[TMSI_LEN];
    unsigned char IMEI[IMEI_LEN - 2];
    unsigned char IMSI[IMEI_LEN - 2];
    unsigned char IMEISV[IMEISV_LEN - 2];
  } Id;
};

#if 0
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
} LAI_Priority_t;

typedef enum
{
  NOM_I,
  NOM_II,
  NOM_III,
  NOM_GSM,
  NOM_PS_ONLY,
  NOM_UNKNOWN
} NMO_t;

typedef enum
{
  COMBINED,
  NOT_COMBINED,
  SAME_AS_BEFORE
} ProcedureMode_t;

typedef struct
{
  uint8_t              Cause;
  LAI_t               LAI;
  struct OV_MobileId  MobileId;
} CombinedResult_t;

typedef enum
{
  R97,
  R99
} MSCR_t, SGSNR_t;

typedef struct
{
  uint8_t   NbrOfElements;
  PLMN_t   Element[MAX_ELEMENTS_IN_EQPLMN_LIST];
} EqPLMN_List_t;
#endif

#define MAX_PCCCH                       16
#define MAX_RFL_LENGTH                  16 /* length of RFL in PSI2 */
#define MAX_RFLS                         4 /* Max number of RFLs */
#define MAX_MA_LISTS_IN_PSI2             8 /* MAX MA lists = 8 */
#define MAX_ALLOCATION_BITMAP_LENGTH   128 /* max length of Fixed Allocation bitmap in BITS (2^7) */
#define MAX_VAR_LENGTH_BITMAP_LENGTH   176 /* max length ever possible for variable length fixed allocation bitmap */


typedef struct
{
  uint8_t MA_LENGTH;/* =(MA_BitLength +7) MA_BitLength_ converted to bytes */
  uint8_t MA_BITMAP[(63+1)/8];/* : bit (val (MA_LENGTH) + 1) > */
  /* The above should not change order! */
  uint8_t MA_BitLength;
} MobileAllocation_t;

typedef struct
{
  uint8_t ElementsOf_ARFCN_INDEX;
  uint8_t ARFCN_INDEX[16];
} ARFCN_index_list_t;

typedef struct
{
  uint8_t HSN;

  uint8_t ElementsOf_RFL_NUMBER;
  uint8_t RFL_NUMBER[4];

  uint8_t UnionType;
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
  uint8_t  FINAL_ACK_INDICATION;
  uint8_t  BEGINNING_OF_WINDOW;
  uint8_t  END_OF_WINDOW;
  uint16_t STARTING_SEQUENCE_NUMBER;

  bool Exist_CRBB;
  uint8_t  CRBB_LENGTH;
  uint8_t  CRBB_STARTING_COLOR_CODE;
  uint8_t  CRBB[CRBB_MAX_BITS/8 + 1];

  uint16_t URBB_LENGTH;
  uint8_t  URBB[URBB_MAX_BITS/8];
} EGPRS_AckNack_Desc_t;

typedef struct
{
  uint8_t  UnionType;
  EGPRS_AckNack_Desc_t Desc;
} EGPRS_AckNack_t;

typedef struct
{
  uint8_t  LENGTH;
  EGPRS_AckNack_Desc_t Desc;
} EGPRS_AckNack_w_len_t;


/* <P1 Rest Octets>
 * <P2 Rest Octets>
 */
#if 0
#define  SF_VBS  0   /* VBS (broadcast call reference) */
#define  SF_VGCS  1  /* VGCS (group call reference) */

#define  AF_AckIsNotRequired  0  /* acknowledgement is not required */
#define  AF_AckIsRequired     1  /* acknowledgement is required */
#endif

typedef struct
{
  uint32_t value;
  uint8_t SF;
  uint8_t AF;
  uint8_t call_priority;
  uint8_t Ciphering_information;
} Group_Call_Reference_t;

/* Mobile allocation is coded differently but uses the same type! */
typedef struct
{
  uint8_t Length;
  uint8_t MA[8];
} MobileAllocationIE_t;

typedef struct
{
  uint8_t UnionType;
  union
  {
    MobileAllocationIE_t MA;
    uint8_t Frequency_Short_List[64/8];
  } u;
} MobileAllocation_or_Frequency_Short_List_t;

typedef struct
{
  uint8_t spare;
  uint16_t ARFCN;
} SingleRFChannel_t;

typedef struct
{
  uint8_t MAIO;
  uint8_t HSN;
} RFHoppingChannel_t;

typedef struct
{
  uint8_t Channel_type_and_TDMA_offset;
  uint8_t TN;
  uint8_t TSC;

  uint8_t UnionType;
  union
  {
    SingleRFChannel_t SingleRFChannel;
    RFHoppingChannel_t RFHoppingChannel;
  } u;
} Channel_Description_t;

typedef struct
{
  Channel_Description_t Channel_Description;

  uint8_t Exist_Hopping;
  MobileAllocation_or_Frequency_Short_List_t MA_or_Frequency_Short_List;

} Group_Channel_Description_t;

typedef struct
{
  Group_Call_Reference_t Group_Call_Reference;

  uint8_t Exist_Group_Channel_Description;
  Group_Channel_Description_t Group_Channel_Description;
} Group_Call_information_t;

typedef struct
{
  uint8_t Exist_NLN_PCH_and_NLN_status;
  uint8_t NLN_PCH;
  uint8_t NLN_status;

  uint8_t Exist_Priority1;
  uint8_t Priority1;

  uint8_t Exist_Priority2;
  uint8_t Priority2;

  uint8_t Exist_Group_Call_information;
  Group_Call_information_t Group_Call_information;

  uint8_t Packet_Page_Indication_1;
  uint8_t Packet_Page_Indication_2;
} P1_Rest_Octets_t;

typedef struct
{
  uint8_t Exist_CN3;
  uint8_t CN3;

  uint8_t Exist_NLN_and_status;
  uint8_t NLN;
  uint8_t NLN_status;

  uint8_t Exist_Priority1;
  uint8_t Priority1;

  uint8_t Exist_Priority2;
  uint8_t Priority2;

  uint8_t Exist_Priority3;
  uint8_t Priority3;

  uint8_t Packet_Page_Indication_3;
} P2_Rest_Octets_t;

/* <IA Rest Octets> incl additions for R99 and EGPRS */

typedef struct
{
  uint8_t USF;
  uint8_t USF_GRANULARITY;

  uint8_t Exist_P0_PR_MODE;
  uint8_t P0;
  uint8_t PR_MODE;
} DynamicAllocation_t;

typedef struct
{
  bool Exist_ALPHA;
  uint8_t  ALPHA;

  uint8_t  GAMMA;
  StartingTime_t TBF_STARTING_TIME;
  uint8_t  NR_OF_RADIO_BLOCKS_ALLOCATED;

  bool Exist_P0_BTS_PWR_CTRL_PR_MODE;
  uint8_t  P0;
  uint8_t  BTS_PWR_CTRL_MODE;
  uint8_t  PR_MODE;
} EGPRS_TwoPhaseAccess_t;

typedef struct
{
  uint8_t TFI_ASSIGNMENT;
  uint8_t POLLING;

  uint8_t UnionType;
  union
  {
    DynamicAllocation_t DynamicAllocation;
    uint8_t              FixedAllocationDummy;   /* Fixed Allocation was removed */
  } Allocation;

  uint8_t  EGPRS_CHANNEL_CODING_COMMAND;
  uint8_t  TLLI_BLOCK_CHANNEL_CODING;

  bool Exist_BEP_PERIOD2;
  uint8_t  BEP_PERIOD2;

  uint8_t  RESEGMENT;
  uint8_t  EGPRS_WindowSize;

  bool Exist_ALPHA;
  uint8_t  ALPHA;

  uint8_t  GAMMA;

  bool Exist_TIMING_ADVANCE_INDEX;
  uint8_t  TIMING_ADVANCE_INDEX;

  bool                Exist_TBF_STARTING_TIME;
  StartingTime_t TBF_STARTING_TIME;
} EGPRS_OnePhaseAccess_t;

#define MAX_ACCESS_TECHOLOGY_TYPES 12

typedef struct
{
  uint8_t ExtendedRA;

  uint8_t NrOfAccessTechnologies;
  uint8_t AccessTechnologyType[MAX_ACCESS_TECHOLOGY_TYPES];

  uint8_t UnionType;
  union
  {
    EGPRS_TwoPhaseAccess_t TwoPhaseAccess; /* 04.18/10.5.2.16 Multiblock allocation */
    EGPRS_OnePhaseAccess_t OnePhaseAccess; /* 04.60/10.5.2.16 TFI using Dynamic or Fixed Allocation */
  } Access;
} IA_EGPRS_00_t;

typedef struct
{
  uint8_t          UnionType;
  union
  {
    IA_EGPRS_00_t IA_EGPRS_PUA; /* 00 < EGPRS Packet Uplink Assignment >*/
    uint8_t        IA_EGPRS_01;  /* 01 reserved for future use */
    uint8_t        IA_EGPRS_1;   /* 1  reserved for future use */
  } u;
} IA_EGPRS_t;

typedef struct
{
  uint8_t Length;
  uint8_t MAIO;
  uint8_t MobileAllocation[62];
} IA_FreqParamsBeforeTime_t;

typedef struct
{
  bool Exist_ALPHA;
  uint8_t  ALPHA;

  uint8_t  GAMMA;
  uint8_t  R97_CompatibilityBits;
  StartingTime_t TBF_STARTING_TIME;

  bool Exist_P0_BTS_PWR_CTRL_PR_MODE;
  uint8_t  P0;
  uint8_t  BTS_PWR_CTRL_MODE;
  uint8_t  PR_MODE;
} GPRS_SingleBlockAllocation_t;

typedef struct
{
  uint8_t TFI_ASSIGNMENT;
  uint8_t POLLING;

  uint8_t UnionType;
  union
  {
    DynamicAllocation_t DynamicAllocation;
    uint8_t              FixedAllocationDummy;
  } Allocation;

  uint8_t             CHANNEL_CODING_COMMAND;
  uint8_t             TLLI_BLOCK_CHANNEL_CODING;

  uint8_t             Exist_ALPHA;
  uint8_t             ALPHA;

  uint8_t             GAMMA;

  uint8_t             Exist_TIMING_ADVANCE_INDEX;
  uint8_t             TIMING_ADVANCE_INDEX;

  uint8_t             Exist_TBF_STARTING_TIME;
  StartingTime_t TBF_STARTING_TIME;
} GPRS_DynamicOrFixedAllocation_t;

typedef struct
{
  bool Exist_ExtendedRA;
  uint8_t  ExtendedRA;
} PU_IA_AdditionsR99_t;

typedef struct
{
  uint8_t UnionType;
  union
  {
    GPRS_SingleBlockAllocation_t    SingleBlockAllocation;
    GPRS_DynamicOrFixedAllocation_t DynamicOrFixedAllocation;
  } Access;

  bool                   Exist_AdditionsR99;
  PU_IA_AdditionsR99_t  AdditionsR99;
} Packet_Uplink_ImmAssignment_t;

typedef struct
{
  uint8_t  EGPRS_WindowSize;
  uint8_t  LINK_QUALITY_MEASUREMENT_MODE;

  bool Exist_BEP_PERIOD2;
  uint8_t  BEP_PERIOD2;
} PD_IA_AdditionsR99_t;

typedef struct
{
  uint32_t              TLLI;

  uint8_t               Exist_TFI_to_TA_VALID;
  uint8_t               TFI_ASSIGNMENT;
  uint8_t               RLC_MODE;
  uint8_t               Exist_ALPHA;
  uint8_t               ALPHA;
  uint8_t               GAMMA;
  uint8_t               POLLING;
  uint8_t               TA_VALID;

  uint8_t               Exist_TIMING_ADVANCE_INDEX;
  uint8_t               TIMING_ADVANCE_INDEX;

  uint8_t               Exist_TBF_STARTING_TIME;
  StartingTime_t       TBF_STARTING_TIME;

  uint8_t               Exist_P0_PR_MODE;
  uint8_t               P0;
  uint8_t               BTS_PWR_CTRL_MODE;
  uint8_t               PR_MODE;

  bool                  Exist_AdditionsR99;
  PD_IA_AdditionsR99_t AdditionsR99;
} Packet_Downlink_ImmAssignment_t;

typedef struct
{
  bool Exist_SecondPart;

  bool Exist_ExtendedRA;
  uint8_t  ExtendedRA;
} Second_Part_Packet_Assignment_t;

typedef struct
{
  uint8_t UnionType;
  union
  {
    Packet_Uplink_ImmAssignment_t   Packet_Uplink_ImmAssignment;
    Packet_Downlink_ImmAssignment_t Packet_Downlink_ImmAssignment;
  } ul_dl;
} IA_PacketAssignment_UL_DL_t;

typedef struct
{
  uint8_t UnionType;
  union
  {
    IA_PacketAssignment_UL_DL_t     UplinkDownlinkAssignment;
    Second_Part_Packet_Assignment_t Second_Part_Packet_Assignment;
  } u;
} IA_PacketAssignment_t;

#if 0
typedef struct
{
  uint8_t UnionType;
  union
  {
    IA_FreqParamsBeforeTime_t IA_FrequencyParams;
    IA_PacketAssignment_t     IA_PacketAssignment;
  } u;
} IA_GPRS_t;

typedef struct
{
  uint8_t UnionType;
  union
  {
    IA_EGPRS_t IA_EGPRS_Struct;
    IA_GPRS_t  IA_GPRS_Struct;
  } u;
} IA_t;


/* <IAR Rest Octets> ref: 04.18/10.5.2.17 */
typedef struct
{
  uint8_t Exist_ExtendedRA;
  uint8_t ExtendedRA;
} ExtendedRA_Info_t;

typedef ExtendedRA_Info_t ExtendedRA_Info_Array_t[4];

typedef struct
{
  ExtendedRA_Info_Array_t ExtendedRA_Info;
} IAR_t;
#endif

/* Packet Polling Request */
typedef struct
{
  uint8_t UnionType;
  union
  {
    Global_TFI_t Global_TFI;
    uint32_t TLLI;
    uint16_t TQI;
  } u;
} PacketPollingID_t;

typedef struct
{
  uint8_t MESSAGE_TYPE;
  uint8_t PAGE_MODE;
  PacketPollingID_t ID;
  uint8_t TYPE_OF_ACK;
} Packet_Polling_Request_t;

/* < SI 13 Rest Octets > */
#define MAX_EXTENSION_LENGTH_IN_BYTES (8) /* max value = 64 (coded on 6 bits) */

typedef struct
{
  uint8_t extension_length;
  uint8_t Extension_Info[MAX_EXTENSION_LENGTH_IN_BYTES];/* ( val (extension length)+1 ) 04.60/12.26 */
} Extension_Bits_t;

#if 0
typedef struct
{
  uint8_t DTM_SUPPORT                  : 1;
  uint8_t PFC_FEATURE_MODE             : 1;
  uint8_t BEP_PERIOD                   : 4;
  uint8_t EGPRS_PACKET_CHANNEL_REQUEST : 1;
  uint8_t EGPRS_Support                  : 1;

  uint8_t NotUsed                        : 3;
  uint8_t EXT_UTBF_NODATA              : 1;
  uint8_t MULTIPLE_TBF_CAPABILITY      : 1;
  uint8_t NW_EXT_UTBF                  : 1;
  uint8_t CCN_ACTIVE                   : 1;
  uint8_t BSS_PAGING_COORDINATION      : 1;
} GPRS_ExtensionInfoWithEGPRS_t;

typedef struct
{
  uint8_t EXT_UTBF_NODATA         : 1;
  uint8_t MULTIPLE_TBF_CAPABILITY : 1;
  uint8_t NW_EXT_UTBF             : 1;
  uint8_t CCN_ACTIVE              : 1;
  uint8_t BSS_PAGING_COORDINATION : 1;
  uint8_t DTM_SUPPORT             : 1;
  uint8_t PFC_FEATURE_MODE        : 1;
  uint8_t EGPRS_Support             : 1;
} GPRS_ExtensionInfoWithoutEGPRS_t;

typedef struct
{
  uint8_t NotUsed                   : 7;
  uint8_t EGPRS_Support             : 1;
} EGPRS_Support_t;

typedef struct
{
  uint8_t ECSC    : 1;
  uint8_t ECSR_3G : 1;
} NonGPRS_ExtensionInfo_t;

typedef struct
{
  uint8_t Extension_Length;
  union
  {
    EGPRS_Support_t                  EGPRS_Support;
    GPRS_ExtensionInfoWithEGPRS_t    GPRS_ExtensionInfoWithEGPRS;
    GPRS_ExtensionInfoWithoutEGPRS_t GPRS_ExtensionInfoWithoutEGPRS;
    NonGPRS_ExtensionInfo_t          NonGPRS_ExtensionInfo;
    uint8_t                          Extension_Information[MAX_EXTENSION_LENGTH_IN_BYTES];
  } u;
} Optional_Extension_Information_t;

typedef struct
{
  bool EGPRS_Support;
  uint8_t  BEP_PERIOD;
  bool EGPRS_PACKET_CHANNEL_REQUEST;
} EGPRS_OptionalExtensionInformation_t;
#endif

typedef struct
{
  uint8_t NMO;
  uint8_t T3168;
  uint8_t T3192;
  uint8_t DRX_TIMER_MAX;
  uint8_t ACCESS_BURST_TYPE;
  uint8_t CONTROL_ACK_TYPE;
  uint8_t BS_CV_MAX;

  uint8_t Exist_PAN;
  uint8_t PAN_DEC;
  uint8_t PAN_INC;
  uint8_t PAN_MAX;

  uint8_t Exist_Extension_Bits;
  Extension_Bits_t Extension_Bits;
} GPRS_Cell_Options_t;

typedef struct
{
  uint8_t ALPHA;
  uint8_t T_AVG_W;
  uint8_t T_AVG_T;
  uint8_t PC_MEAS_CHAN;
  uint8_t N_AVG_I;
} GPRS_Power_Control_Parameters_t;

typedef struct
{
  uint8_t RAC;
  uint8_t SPGC_CCCH_SUP;
  uint8_t PRIORITY_ACCESS_THR;
  uint8_t NETWORK_CONTROL_ORDER;
  GPRS_Cell_Options_t GPRS_Cell_Options;
  GPRS_Power_Control_Parameters_t GPRS_Power_Control_Parameters;
} PBCCH_Not_present_t;

typedef struct
{
  uint8_t Pb;
  uint8_t TSC;
  uint8_t TN;

  uint8_t UnionType;
  union
  {
    uint8_t dummy;
    uint16_t ARFCN;
    uint8_t MAIO;
  } u;
} PBCCH_Description_t;

typedef struct
{
  uint8_t PSI1_REPEAT_PERIOD;
  PBCCH_Description_t PBCCH_Description;
} PBCCH_present_t;



/* < Packet TBF Release message content > */
typedef uint8_t TBF_RELEASE_CAUSE_t;
#if 0
#define  TBF_RELEASE_CAUSE_NORMAL (0x00)
#define  TBF_RELEASE_CAUSE_ABNORMAL (0x02)
#endif

typedef struct
{
  uint8_t              MESSAGE_TYPE;
  uint8_t              PAGE_MODE;
  Global_TFI_t         Global_TFI;
  uint8_t              UPLINK_RELEASE;
  uint8_t              DOWNLINK_RELEASE;
  TBF_RELEASE_CAUSE_t TBF_RELEASE_CAUSE;
} Packet_TBF_Release_t;

/* < Packet Control Acknowledgement message content > */
typedef struct
{
  uint8_t Exist_CTRL_ACK_Extension;
  uint16_t CTRL_ACK_Extension;
} Packet_Control_Acknowledgement_AdditionsR6_t;

typedef struct
{
  uint8_t Exist_TN_RRBP;
  uint8_t TN_RRBP;
  uint8_t Exist_G_RNTI_Extension;
  uint8_t G_RNTI_Extension;
  bool Exist_AdditionsR6;
  Packet_Control_Acknowledgement_AdditionsR6_t AdditionsR6;
} Packet_Control_Acknowledgement_AdditionsR5_t;

typedef struct
{  /* Mac header */
  uint8_t MESSAGE_TYPE;
  uint8_t PayloadType;
  uint8_t spare;
  uint8_t R;

  uint32_t TLLI;
  uint8_t CTRL_ACK;
  bool Exist_AdditionsR5;
  Packet_Control_Acknowledgement_AdditionsR5_t AdditionsR5;
} Packet_Control_Acknowledgement_t;

typedef Packet_Control_Acknowledgement_t Packet_Ctrl_Ack_t;

#if 0
typedef struct
{
  uint8_t CTRL_ACK;
} Packet_Control_Acknowledgement_11_bit_t, Packet_Control_Acknowledgement_8_bit_t;
#endif

/* < Packet Downlink Dummy Control Block message content > */
typedef struct
{
  uint8_t MESSAGE_TYPE;
  uint8_t PAGE_MODE;

  uint8_t Exist_PERSISTENCE_LEVEL;
  uint8_t PERSISTENCE_LEVEL[4];
} Packet_Downlink_Dummy_Control_Block_t;

/* < Packet Uplink Dummy Control Block message content > */
typedef struct
{ /* Mac header */
  uint8_t MESSAGE_TYPE;
  uint8_t PayloadType;
  uint8_t spare;
  uint8_t R;

  uint32_t TLLI;
} Packet_Uplink_Dummy_Control_Block_t;

/* MS Radio Access capability IE >
 * 24.008 (10.5.5.12a)
 */
typedef uint8_t A5_bits_t;/* <A5 bits> ::= < A5/1 : bit> <A5/2 : bit> <A5/3 : bit> <A5/4 : bit> <A5/5 : bit> <A5/6 : bit> <A5/7 : bit>; -- bits for circuit mode ciphering algorithms */

typedef struct
{
  uint8_t Exist_DTM_EGPRS_multislot_class;
  uint8_t DTM_EGPRS_multislot_class;
} DTM_EGPRS_t;

typedef struct
{
  uint8_t Exist_DTM_EGPRS_HighMultislotClass;
  uint8_t DTM_EGPRS_HighMultislotClass;
} DTM_EGPRS_HighMultislotClass_t;

typedef struct
{
  uint8_t MultislotCapabilityReductionForDL_DualCarrier;
  uint8_t DL_DualCarrierForDTM;
} DownlinkDualCarrierCapability_r7_t;

typedef struct
{
  uint8_t Exist_HSCSD_multislot_class;
  uint8_t HSCSD_multislot_class;

  uint8_t Exist_GPRS_multislot_class;
  uint8_t GPRS_multislot_class;
  uint8_t GPRS_Extended_Dynamic_Allocation_Capability;

  uint8_t Exist_SM;
  uint8_t SMS_VALUE;
  uint8_t SM_VALUE;

/*-------- Rel 99 additions */
  uint8_t Exist_ECSD_multislot_class;
  uint8_t ECSD_multislot_class;

  uint8_t Exist_EGPRS_multislot_class;
  uint8_t EGPRS_multislot_class;
  uint8_t EGPRS_Extended_Dynamic_Allocation_Capability;

  uint8_t Exist_DTM_GPRS_multislot_class;
  uint8_t DTM_GPRS_multislot_class;
  uint8_t Single_Slot_DTM;
  DTM_EGPRS_t DTM_EGPRS_Params;
} Multislot_capability_t;

typedef struct
{
  uint8_t RF_Power_Capability;

  uint8_t Exist_A5_bits;
  A5_bits_t A5_bits;
  /*-- zero means that the same values apply for parameters as in the immediately preceding Access capabilities field within this IE
  *-- The presence of the A5 bits is mandatory in the 1st Access capabilies struct within this IE.
  */

  uint8_t ES_IND;
  uint8_t PS;
  uint8_t VGCS;
  uint8_t VBS;

  uint8_t Exist_Multislot_capability;
  Multislot_capability_t Multislot_capability;
  /* -- zero means that the same values apply for multislot parameters as in the immediately preceding Access capabilities field within this IE.
   * -- The presence of the Multislot capability struct is mandatory in the 1st Access capabilites struct within this IE.
   */
  /* -------- Rel 99 additions */
  uint8_t Exist_Eight_PSK_Power_Capability;
  uint8_t Eight_PSK_Power_Capability;

  uint8_t COMPACT_Interference_Measurement_Capability;
  uint8_t Revision_Level_Indicator;
  uint8_t UMTS_FDD_Radio_Access_Technology_Capability;
  uint8_t UMTS_384_TDD_Radio_Access_Technology_Capability;
  uint8_t CDMA2000_Radio_Access_Technology_Capability;

  /* -------- R4 additions */
  uint8_t UMTS_128_TDD_Radio_Access_Technology_Capability;
  uint8_t GERAN_Feature_Package_1;

  uint8_t Exist_Extended_DTM_multislot_class;
  uint8_t Extended_DTM_GPRS_multislot_class;
  uint8_t Extended_DTM_EGPRS_multislot_class;

  uint8_t Modulation_based_multislot_class_support;

  /* -------- R5 additions */
  uint8_t Exist_HighMultislotCapability;
  uint8_t HighMultislotCapability;

  uint8_t Exist_GERAN_lu_ModeCapability;
  uint8_t GERAN_lu_ModeCapability;

  uint8_t GMSK_MultislotPowerProfile;
  uint8_t EightPSK_MultislotProfile;

  /* -------- R6 additions */
  uint8_t MultipleTBF_Capability;
  uint8_t DownlinkAdvancedReceiverPerformance;
  uint8_t ExtendedRLC_MAC_ControlMessageSegmentionsCapability;
  uint8_t DTM_EnhancementsCapability;

  uint8_t Exist_DTM_GPRS_HighMultislotClass;
  uint8_t DTM_GPRS_HighMultislotClass;
  DTM_EGPRS_HighMultislotClass_t DTM_EGPRS_HighMultislotClass;
  uint8_t PS_HandoverCapability;

  /* -------- R7 additions */
  uint8_t DTM_Handover_Capability;
  uint8_t Exist_DownlinkDualCarrierCapability_r7;
  DownlinkDualCarrierCapability_r7_t DownlinkDualCarrierCapability_r7;

  uint8_t FlexibleTimeslotAssignment;
  uint8_t GAN_PS_HandoverCapability;
  uint8_t RLC_Non_persistentMode;
  uint8_t ReducedLatencyCapability;
  uint8_t UplinkEGPRS2;
  uint8_t DownlinkEGPRS2;

  /* -------- R8 additions */
  uint8_t EUTRA_FDD_Support;
  uint8_t EUTRA_TDD_Support;
  uint8_t GERAN_To_EUTRAN_supportInGERAN_PTM;
  uint8_t PriorityBasedReselectionSupport;

} Content_t;

typedef enum
{/* See TS 24.008 table 10.5.146 */
  AccTech_GSMP     = 0x0,
  AccTech_GSME     = 0x1,
  AccTech_GSMR     = 0x2,
  AccTech_GSM1800  = 0x3,
  AccTech_GSM1900  = 0x4,
  AccTech_GSM450   = 0x5,
  AccTech_GSM480   = 0x6,
  AccTech_GSM850   = 0x7,
  AccTech_GSM750   = 0x8,
  AccTech_GSMT830  = 0x9,
  AccTech_GSMT410  = 0xa,
  AccTech_GSMT900  = 0xb,
  AccTech_GSM710   = 0xc,
  AccTech_GSMT810  = 0xd,
  AccTech_GSMOther = 0xf
} AccessTechnology_t;

/* Maximum entries in one message, Enum above, applying restrictions from section
   12.30 "MS Radio Access Capability 2": */
#define MAX_ACCESS_TECHNOLOGIES_COUNT 11

typedef struct
{
  AccessTechnology_t Access_Technology_Type;
  uint8_t             GMSK_Power_class;
  uint8_t             Eight_PSK_Power_class;
} Additional_access_technologies_struct_t;

typedef struct
{
  uint8_t Count_additional_access_technologies;
  /* The value 0xf cannot be set for the first ATT, therefore we can only have
     ABSOLUTE_MAX_BANDS-1 additional access technologies. */
  Additional_access_technologies_struct_t Additional_access_technologies[MAX_ACCESS_TECHNOLOGIES_COUNT-1];
} Additional_access_technologies_t;

typedef struct
{
  uint8_t IndexOfAccTech; /* Position in AccessTechnology_t */
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
  uint8_t Count_MS_RA_capability_value; /* Recursive */
  MS_RA_capability_value_t MS_RA_capability_value[MAX_ACCESS_TECHNOLOGIES_COUNT];
} MS_Radio_Access_capability_t;


typedef struct
{
  uint8_t  ExistEDGE_RF_PwrCap1;
  uint8_t  EDGE_RF_PwrCap1;
  uint8_t  ExistEDGE_RF_PwrCap2;
  uint8_t  EDGE_RF_PwrCap2;
} EDGE_RF_Pwr_t;

typedef struct
{
  uint8_t A5_Bits;
  uint8_t Arc2_Spare;
  uint8_t Arc1;
} ARC_t;

typedef struct
{
  uint8_t  Multiband;
  union
  {
    uint8_t A5_Bits;
    ARC_t ARC;
  } u;
} Multiband_t;

typedef struct              /* MS classmark 3 R99 */
{
  uint8_t        Spare1;
  Multiband_t   Multiband;

  uint8_t        Exist_R_Support;
  uint8_t        R_GSM_Arc;

  uint8_t        Exist_MultiSlotCapability;
  uint8_t        MultiSlotClass;

  uint8_t        UCS2;
  uint8_t        ExtendedMeasurementCapability;

  uint8_t        Exist_MS_MeasurementCapability;
  uint8_t        SMS_VALUE;
  uint8_t        SM_VALUE;

  uint8_t        Exist_MS_PositioningMethodCapability;
  uint8_t        MS_PositioningMethod;

  uint8_t        Exist_EDGE_MultiSlotCapability;
  uint8_t        EDGE_MultiSlotClass;

  uint8_t        Exist_EDGE_Struct;
  uint8_t        ModulationCapability;
  EDGE_RF_Pwr_t EDGE_RF_PwrCaps;

  uint8_t        Exist_GSM400_Info;
  uint8_t        GSM400_Bands;
  uint8_t        GSM400_Arc;

  uint8_t        Exist_GSM850_Arc;
  uint8_t        GSM850_Arc;

  uint8_t        Exist_PCS1900_Arc;
  uint8_t        PCS1900_Arc;

  uint8_t        UMTS_FDD_Radio_Access_Technology_Capability;
  uint8_t        UMTS_384_TDD_Radio_Access_Technology_Capability;
  uint8_t        CDMA2000_Radio_Access_Technology_Capability;

  uint8_t        Exist_DTM_GPRS_multislot_class;
  uint8_t        DTM_GPRS_multislot_class;
  uint8_t        Single_Slot_DTM;
  DTM_EGPRS_t   DTM_EGPRS_Params;

  /* -------- R4 additions */
  uint8_t        Exist_SingleBandSupport;
  uint8_t        GSM_Band;

  uint8_t        Exist_GSM_700_Associated_Radio_Capability;
  uint8_t        GSM_700_Associated_Radio_Capability;

  uint8_t        UMTS_128_TDD_Radio_Access_Technology_Capability;
  uint8_t        GERAN_Feature_Package_1;

  uint8_t        Exist_Extended_DTM_multislot_class;
  uint8_t        Extended_DTM_GPRS_multislot_class;
  uint8_t        Extended_DTM_EGPRS_multislot_class;

  /* -------- R5 additions */
  uint8_t        Exist_HighMultislotCapability;
  uint8_t        HighMultislotCapability;

  uint8_t        Exist_GERAN_lu_ModeCapability;
  uint8_t        GERAN_lu_ModeCapability;

  uint8_t        GERAN_FeaturePackage_2;

  uint8_t        GMSK_MultislotPowerProfile;
  uint8_t        EightPSK_MultislotProfile;

  /* -------- R6 additions */
  uint8_t        Exist_TGSM_400_Bands;
  uint8_t        TGSM_400_BandsSupported;
  uint8_t        TGSM_400_AssociatedRadioCapability;

  uint8_t        Exist_TGSM_900_AssociatedRadioCapability;
  uint8_t        TGSM_900_AssociatedRadioCapability;

  uint8_t        DownlinkAdvancedReceiverPerformance;
  uint8_t        DTM_EnhancementsCapability;

  uint8_t        Exist_DTM_GPRS_HighMultislotClass;
  uint8_t        DTM_GPRS_HighMultislotClass;
  uint8_t        OffsetRequired;
  DTM_EGPRS_HighMultislotClass_t   DTM_EGPRS_HighMultislotClass;
  uint8_t        RepeatedSACCH_Capability;

  uint8_t        Spare2;
} MS_Class3_Unpacked_t;


/* < Packet Resource Request message content > */
typedef struct
{
  bool Exist;
  uint8_t  UnionType;
  union
  {
    uint8_t MEAN_BEP_GMSK;
    uint8_t MEAN_BEP_8PSK;
  } u;
} BEP_MeasurementReport_t;

typedef struct
{
  bool Exist;
  uint8_t  I_LEVEL;
} InterferenceMeasurementReport_t;

typedef struct
{
  bool                     Exist_BEP_MEASUREMENTS;
  BEP_MeasurementReport_t BEP_MEASUREMENTS[8];

  bool                             Exist_INTERFERENCE_MEASUREMENTS;
  InterferenceMeasurementReport_t INTERFERENCE_MEASUREMENTS[8];
} EGPRS_TimeslotLinkQualityMeasurements_t;

typedef struct
{
  bool Exist_MEAN_CV_BEP_GMSK;
  uint8_t  MEAN_BEP_GMSK;
  uint8_t  CV_BEP_GMSK;

  bool Exist_MEAN_CV_BEP_8PSK;
  uint8_t  MEAN_BEP_8PSK;
  uint8_t  CV_BEP_8PSK;
} EGPRS_BEP_LinkQualityMeasurements_t;

typedef struct{
uint8_t RB_ID;
uint8_t RADIO_PRIORITY;

bool      Exist_RLC_BLOCK_COUNT;
uint8_t  RLC_BLOCK_COUNT;

bool      Exist_Iu_Mode_ChRequestDesk;
//IU_Mode_Channel_Request_Desk_t IU_Mode_Channel_Request_Desk1;

}IU_Mode_Channel_Request_Desk_t;

typedef struct{
    bool       Exist_G_RNTI_Extension;
    uint8_t   G_RNTI_Extension;
    IU_Mode_Channel_Request_Desk_t  IU_Mode_Channel_Request_Desk;

}IU_Mode_Channel_Request_Desk_RNTI_t;

typedef struct{
    uint8_t PFI;
    uint8_t RADIO_PRIORITY;
    uint8_t RLC_Mode;

    bool      Exist_LCC_PDU;
    uint8_t LCC_PDU;

    bool Exist_Ext_Channel_Request_desc;

}Ext_Channel_Request_desc_t;


typedef struct{
    bool Exist_GMSK_MEAN_BEP;
    uint8_t GMSK_MEAN_BEP;
    uint8_t GMSK_CV_BEP;

    bool Exist_8PSK_MEAN_BEP;
    uint8_t p8PSK_MEAN_BEP;
    uint8_t p8PSK_CV_BEP;

    bool Exist_QPSK_MEAN_BEP;
    uint8_t QPSK_MEAN_BEP;
    uint8_t QPSK_CV_BEP;

    bool Exist_16QAM_NSR_MEAN_BEP;
    uint8_t p16QAM_NSR_MEAN_BEP;
    uint8_t p16QAM_NSR_CV_BEP;

    bool Exist_32QAM_NSR_MEAN_BEP;
    uint8_t p32QAM_NSR_MEAN_BEP;
    uint8_t p32QAM_NSR_CV_BEP;

    bool Exist_16QAM_HSR_MEAN_BEP;
    uint8_t p16QAM_HSR_MEAN_BEP;
    uint8_t p16QAM_HSR_CV_BEP;

    bool Exist_32QAM_HSR_MEAN_BEP;
    uint8_t p32QAM_HSR_MEAN_BEP;
    uint8_t p32QAM_HSR_CV_BEP;

    }EGPRS_BEP_LinkQualityMeasurements_type2_t;

typedef struct
{
    bool Exist;
    uint8_t REPORTED_MODULATION;
    uint8_t MEAN_BEP_TN;

}BEP_MeasurementReport_type2_t;

typedef struct
{
    bool Exist;
    uint8_t I_LEVEL;
}InterferenceMeasurementReport_type2_t;

typedef struct
{
    bool Exist_BEP_MEASUREMENTS;
    BEP_MeasurementReport_type2_t BEP_MEASUREMENTS[8];

    bool Exist_INTERFERENCE_MEASUREMENTS;
    InterferenceMeasurementReport_type2_t INTERFERENCE_MEASUREMENTS[8];

}EGPRS_TimeslotLinkQualityMeasurements_type2_t;


typedef struct
{
    bool Exist_Downlink_eTFI;
    uint8_t DOWNLINK_ETFI;

}PRR_AdditionsR12_t;

typedef struct
{
    uint8_t LOW_ACCESS_PRIORITY_SIGNALLING;

    bool Exist_AdditionsR12;
    PRR_AdditionsR12_t  AdditionsR12;

}PRR_AdditionsR10_t;

typedef struct
{
    uint8_t EARLY_TBF_ESTABLISHMENT;

    bool Exist_EGPRS_BEP_LinkQualityMeasurements_type2;
    EGPRS_BEP_LinkQualityMeasurements_type2_t EGPRS_BEP_LinkQualityMeasurements_type2;

    bool Exist_EGPRS_TimeslotLinkQualityMeasurements_type2;
    EGPRS_TimeslotLinkQualityMeasurements_type2_t EGPRS_TimeslotLinkQualityMeasurements_type2;

    bool Exist_AdditionsR10;
    PRR_AdditionsR10_t AdditionsR10;

}PRR_AdditionsR7_t;

typedef struct
{
    bool Exist_Ext_Channel_Request_desc;
    Ext_Channel_Request_desc_t  Ext_Channel_Request_desc;

    uint8_t Exist_AdditionsR7;
    PRR_AdditionsR7_t  AdditionsR7;

} PRR_AdditionsR6_t;

typedef struct
{
    uint8_t Exist_Iu_Mode_ChRequestDesk;
    IU_Mode_Channel_Request_Desk_RNTI_t  IU_Mode_Channel_Request_Desk_RNTI;

    uint8_t Exist_HFN_LSB;
    uint8_t   HFN_LSb;

    uint8_t Exist_AdditionsR6;
    PRR_AdditionsR6_t AdditionsR6;

}PRR_AdditionsR5_t;

typedef struct
{
  bool                                     Exist_EGPRS_BEP_LinkQualityMeasurements;
  EGPRS_BEP_LinkQualityMeasurements_t     EGPRS_BEP_LinkQualityMeasurements;

  bool                                     Exist_EGPRS_TimeslotLinkQualityMeasurements;
  EGPRS_TimeslotLinkQualityMeasurements_t EGPRS_TimeslotLinkQualityMeasurements;

  bool                                     Exist_PFI;
  uint8_t                                  PFI;

  uint8_t                                  MS_RAC_AdditionalInformationAvailable;
  uint8_t                                  RetransmissionOfPRR;

  uint8_t                                  Exist_AdditionsR5;
  PRR_AdditionsR5_t                        AdditionsR5;
} PRR_AdditionsR99_t;

typedef struct
{
  uint8_t UnionType;
  union
  {
    Global_TFI_t Global_TFI;
    uint32_t TLLI;
  } u;
} PacketResourceRequestID_t;

typedef struct
{
  uint8_t MESSAGE_TYPE;
  uint8_t PayloadType;
  uint8_t spare;
  uint8_t R;

  uint8_t Exist_ACCESS_TYPE;
  uint8_t ACCESS_TYPE;

  PacketResourceRequestID_t ID;

  uint8_t Exist_MS_Radio_Access_capability2;
  MS_Radio_Access_capability_t MS_Radio_Access_capability2;

  Channel_Request_Description_t Channel_Request_Description;

  uint8_t Exist_CHANGE_MARK;
  uint8_t CHANGE_MARK;

  uint8_t C_VALUE;

  uint8_t Exist_SIGN_VAR;
  uint8_t SIGN_VAR;

  InterferenceMeasurementReport_t  I_LEVEL_TN[8];

  uint8_t                           Exist_AdditionsR99;
  PRR_AdditionsR99_t               AdditionsR99;
} Packet_Resource_Request_t;

/* < Packet Mobile TBF Status message content >*/
typedef struct
{
  uint8_t MESSAGE_TYPE;
  uint8_t PayloadType;
  uint8_t spare;
  uint8_t R;

  Global_TFI_t Global_TFI;
  uint8_t TBF_CAUSE;

  uint8_t Exist_STATUS_MESSAGE_TYPE;
  uint8_t STATUS_MESSAGE_TYPE;
} Packet_Mobile_TBF_Status_t;

/* < Packet PSI Status message content >*/
typedef struct
{
  uint8_t PSI_MESSAGE_TYPE;
  uint8_t PSIX_CHANGE_MARK;
  uint8_t Exist_PSIX_COUNT_and_Instance_Bitmap;
} PSI_Message_t;

typedef struct
{
  uint8_t Count_PSI_Message;
  PSI_Message_t PSI_Message[10];

  uint8_t ADDITIONAL_MSG_TYPE;
} PSI_Message_List_t;

typedef struct
{
  uint8_t ADDITIONAL_MSG_TYPE;
} Unknown_PSI_Message_List_t;

typedef struct
{
  uint8_t MESSAGE_TYPE;
  uint8_t PayloadType;
  uint8_t spare;
  uint8_t R;

  Global_TFI_t Global_TFI;
  uint8_t PBCCH_CHANGE_MARK;

  PSI_Message_List_t PSI_Message_List;
  Unknown_PSI_Message_List_t Unknown_PSI_Message_List;
} Packet_PSI_Status_t;

/* < Packet SI Status message content > */
typedef struct
{
  uint8_t SI_MESSAGE_TYPE;
  uint8_t MESS_REC;
  uint8_t SIX_CHANGE_MARK;

  uint8_t SIX_COUNT;
  uint8_t Instance_bitmap[2];
} SI_Message_t;

typedef struct
{
  uint8_t Count_SI_Message;
  SI_Message_t SI_Message[10];

  uint8_t ADDITIONAL_MSG_TYPE;
} SI_Message_List_t;

typedef struct
{
  uint8_t ADDITIONAL_MSG_TYPE;
} Unknown_SI_Message_List_t;

typedef struct
{
  uint8_t MESSAGE_TYPE;
  uint8_t PayloadType;
  uint8_t spare;
  uint8_t R;

  Global_TFI_t Global_TFI;
  uint8_t BCCH_CHANGE_MARK;

  SI_Message_List_t SI_Message_List;
  Unknown_SI_Message_List_t Unknown_SI_Message_List;
} Packet_SI_Status_t;

typedef struct
{
  uint16_t FDD_ARFCN;
  uint8_t DIVERSITY;
  uint8_t Exist_Bandwith_FDD;
  uint8_t BANDWITH_FDD;
  uint16_t SCRAMBLING_CODE;
} FDD_Target_Cell_t;

typedef struct
{
  uint16_t TDD_ARFCN;
  uint8_t DIVERSITY_TDD;
  uint8_t Exist_Bandwith_TDD;
  uint8_t BANDWITH_TDD;
  uint16_t CELL_PARAMETER;
  uint8_t Sync_Case_TSTD;
} TDD_Target_Cell_t;

typedef struct
{
  uint16_t EARFCN;
  uint8_t Exist_Measurement_Bandwidth;
  uint8_t Measurement_Bandwidth;
  uint16_t Physical_Layer_Cell_Identity;
} EUTRAN_Target_Cell_t;

typedef struct
{
  uint32_t UTRAN_CI;
  uint8_t Exist_PLMN_ID;
  PLMN_t  PLMN_ID;
} UTRAN_CSG_Target_Cell_t;

typedef struct
{
  uint32_t EUTRAN_CI;
  uint16_t Tracking_Area_Code;
  uint8_t Exist_PLMN_ID;
  PLMN_t  PLMN_ID;
} EUTRAN_CSG_Target_Cell_t;

typedef struct
{
  uint8_t Exist_UTRAN_CSG_Target_Cell;
  UTRAN_CSG_Target_Cell_t UTRAN_CSG_Target_Cell;
  uint8_t Exist_EUTRAN_CSG_Target_Cell;
  EUTRAN_CSG_Target_Cell_t EUTRAN_CSG_Target_Cell;
} PCCF_AdditionsR9_t;

typedef struct
{
  uint8_t Exist_EUTRAN_Target_Cell;
  EUTRAN_Target_Cell_t EUTRAN_Target_Cell;
  uint8_t Exist_AdditionsR9;
  PCCF_AdditionsR9_t AdditionsR9;
} PCCF_AdditionsR8_t;

typedef struct
{
  uint8_t Exist_G_RNTI_extention;
  uint8_t G_RNTI_extention;
  uint8_t Exist_AdditionsR8;
  PCCF_AdditionsR8_t AdditionsR8;
} PCCF_AdditionsR5_t;

typedef struct
{
  uint8_t Exist_FDD_Description;
  FDD_Target_Cell_t FDD_Target_Cell;
  uint8_t Exist_TDD_Description;
  TDD_Target_Cell_t TDD_Target_Cell;
  uint8_t Exist_AdditionsR5;
  PCCF_AdditionsR5_t AdditionsR5;
} PCCF_AdditionsR99_t;

/* < Packet Cell Change Failure message content > */
typedef struct
{
  uint8_t MESSAGE_TYPE;
  uint8_t PayloadType;
  uint8_t spare;
  uint8_t R;

  uint32_t TLLI;
  uint16_t ARFCN;
  uint8_t BSIC;
  uint8_t CAUSE;
  bool Exist_AdditionsR99;
  PCCF_AdditionsR99_t AdditionsR99;
} Packet_Cell_Change_Failure_t;

/* < Packet Downlink Ack/Nack message content > */
typedef struct
{
  bool Exist_PFI;
  uint8_t  PFI;
} PD_AckNack_AdditionsR99_t;

typedef struct
{
  uint8_t MESSAGE_TYPE;
  uint8_t PayloadType;
  uint8_t spare;
  uint8_t R;

  uint8_t DOWNLINK_TFI;
  Ack_Nack_Description_t Ack_Nack_Description;

  uint8_t Exist_Channel_Request_Description;
  Channel_Request_Description_t Channel_Request_Description;

  Channel_Quality_Report_t Channel_Quality_Report;

  bool                           Exist_AdditionsR99;
  PD_AckNack_AdditionsR99_t     AdditionsR99;
} Packet_Downlink_Ack_Nack_t;

/* < EGPRS Packet Downlink Ack/Nack message content > */
typedef struct
{
  EGPRS_BEP_LinkQualityMeasurements_t     EGPRS_BEP_LinkQualityMeasurements;
  uint8_t                                  C_VALUE;
  EGPRS_TimeslotLinkQualityMeasurements_t EGPRS_TimeslotLinkQualityMeasurements;
} EGPRS_ChannelQualityReport_t;

typedef struct
{
  uint8_t  MESSAGE_TYPE;
  uint8_t  PayloadType;
  uint8_t  spare;
  uint8_t  R;

  uint8_t  DOWNLINK_TFI;
  uint8_t  MS_OUT_OF_MEMORY;

  bool                           Exist_EGPRS_ChannelQualityReport;
  EGPRS_ChannelQualityReport_t  EGPRS_ChannelQualityReport;

  bool                           Exist_ChannelRequestDescription;
  Channel_Request_Description_t ChannelRequestDescription;

  bool Exist_PFI;
  uint8_t  PFI;

  bool              Exist_ExtensionBits;
  Extension_Bits_t ExtensionBits;

  EGPRS_AckNack_t  EGPRS_AckNack;
} EGPRS_PD_AckNack_t;

/* < Packet Uplink Ack/Nack message content  04.60 sec.11.2.28 > */

typedef struct
{
  uint8_t                     Exist_CONTENTION_RESOLUTION_TLLI;
  uint32_t                    CONTENTION_RESOLUTION_TLLI;

  uint8_t                     Exist_Packet_Timing_Advance;
  Packet_Timing_Advance_t    Packet_Timing_Advance;

  uint8_t                     Exist_Extension_Bits;
  Extension_Bits_t           Extension_Bits;

  uint8_t                     Exist_Power_Control_Parameters;
  Power_Control_Parameters_t Power_Control_Parameters;
} Common_Uplink_Ack_Nack_Data_t;

typedef struct
{
  bool Exist_PacketExtendedTimingAdvance;
  uint8_t  PacketExtendedTimingAdvance;
  uint8_t  TBF_EST;
} PU_AckNack_GPRS_AdditionsR99_t;

/* Table 11.2.28.1: PACKET UPLINK ACK/NACK information elements */
typedef struct
{
    uint8_t Error;
    /* Fixed Allocation Parameters was removed from specs.
     * TODO: implement for old versions of spec.
     */
} Fixed_Allocation_Parameters_t;

typedef struct
{
  uint8_t                 CHANNEL_CODING_COMMAND;
  Ack_Nack_Description_t Ack_Nack_Description;

  bool                            Exist_Fixed_Allocation_Parameters;
  Fixed_Allocation_Parameters_t   Fixed_Allocation_Parameters;

  bool                            Exist_AdditionsR99;
  PU_AckNack_GPRS_AdditionsR99_t AdditionsR99;

  Common_Uplink_Ack_Nack_Data_t Common_Uplink_Ack_Nack_Data;
} PU_AckNack_GPRS_t;

typedef struct
{
  uint8_t  EGPRS_ChannelCodingCommand;
  uint8_t  RESEGMENT;
  uint8_t  PRE_EMPTIVE_TRANSMISSION;
  uint8_t  PRR_RETRANSMISSION_REQUEST;
  uint8_t  ARAC_RETRANSMISSION_REQUEST;

  uint8_t  TBF_EST;

  bool Exist_Packet_Extended_Timing_Advance;
  uint8_t  Packet_Extended_Timing_Advance;

  EGPRS_AckNack_t  EGPRS_AckNack;


  Common_Uplink_Ack_Nack_Data_t Common_Uplink_Ack_Nack_Data;
} PU_AckNack_EGPRS_00_t;

typedef struct
{
  uint8_t  UnionType;
  union
  {
    PU_AckNack_EGPRS_00_t PU_AckNack_EGPRS_00;
    uint8_t                extension_01;
    uint8_t                extension_10;
    uint8_t                extension_11;
  } u;
} PU_AckNack_EGPRS_t;

#if 0
enum PUAN_Type
{
  PUAN_GPRS,
  PUAN_EGPRS
};
#endif

typedef struct
{
  uint8_t MESSAGE_TYPE;
  uint8_t PAGE_MODE;
  uint8_t UPLINK_TFI;

  uint8_t UnionType;
  union
  {
    PU_AckNack_GPRS_t  PU_AckNack_GPRS_Struct;
    PU_AckNack_EGPRS_t PU_AckNack_EGPRS_Struct;
  } u;
} Packet_Uplink_Ack_Nack_t;

/* < Packet Uplink Assignment message content > */
typedef struct
{
  uint8_t CHANGE_MARK_1;
  uint8_t Exist_CHANGE_MARK_2;
  uint8_t CHANGE_MARK_2;
} CHANGE_MARK_t;

typedef struct
{
  uint8_t MAIO;
  uint8_t MA_NUMBER;

  uint8_t Exist_CHANGE_MARK;
  CHANGE_MARK_t CHANGE_MARK;
} Indirect_encoding_t;

typedef struct
{
  uint8_t MAIO;
  GPRS_Mobile_Allocation_t GPRS_Mobile_Allocation;
} Direct_encoding_1_t;

typedef struct
{
  uint8_t MAIO;
  uint8_t HSN;
  uint8_t Length_of_MA_Frequency_List;
  uint8_t MA_Frequency_List[15+3];
} Direct_encoding_2_t;

typedef struct
{
  uint8_t TSC;
  uint8_t UnionType;
  union
  {
    uint16_t ARFCN;
    Indirect_encoding_t Indirect_encoding;
    Direct_encoding_1_t Direct_encoding_1;
    Direct_encoding_2_t Direct_encoding_2;
  } u;
} Frequency_Parameters_t;

typedef struct
{
  uint8_t Exist;
  uint8_t USF_TN;
} Timeslot_Allocation_t;

typedef struct
{
  uint8_t ALPHA;

  struct
  {
    uint8_t Exist;
    uint8_t USF_TN;
    uint8_t GAMMA_TN;
  } Slot[8];
} Timeslot_Allocation_Power_Ctrl_Param_t;

typedef struct
{
  uint8_t Extended_Dynamic_Allocation;

  uint8_t Exist_P0;
  uint8_t P0;
  uint8_t PR_MODE;

  uint8_t USF_GRANULARITY;

  uint8_t Exist_UPLINK_TFI_ASSIGNMENT;
  uint8_t UPLINK_TFI_ASSIGNMENT;

  uint8_t Exist_RLC_DATA_BLOCKS_GRANTED;
  uint8_t RLC_DATA_BLOCKS_GRANTED;

  uint8_t Exist_TBF_Starting_Time;
  Starting_Frame_Number_t TBF_Starting_Time;

  uint8_t UnionType;
  union
  {
    Timeslot_Allocation_t                  Timeslot_Allocation[8];
    Timeslot_Allocation_Power_Ctrl_Param_t Timeslot_Allocation_Power_Ctrl_Param;
  } u;
} Dynamic_Allocation_t;

typedef struct
{
  uint8_t Extended_Dynamic_Allocation;

  uint8_t Exist_P0;
  uint8_t P0;
  uint8_t PR_MODE;

  uint8_t USF_GRANULARITY;

  uint8_t Exist_UPLINK_TFI_ASSIGNMENT;
  uint8_t UPLINK_TFI_ASSIGNMENT;

  uint8_t Exist_RLC_DATA_BLOCKS_GRANTED;
  uint8_t RLC_DATA_BLOCKS_GRANTED;

  uint8_t UnionType;
  union
  {
    Timeslot_Allocation_t Timeslot_Allocation[8];
    Timeslot_Allocation_Power_Ctrl_Param_t Timeslot_Allocation_Power_Ctrl_Param;
  } u;
} DTM_Dynamic_Allocation_t;

typedef struct
{
  uint8_t TIMESLOT_NUMBER;

  uint8_t Exist_ALPHA_and_GAMMA_TN;
  uint8_t ALPHA;
  uint8_t GAMMA_TN;

  uint8_t Exist_P0;
  uint8_t P0;
  uint8_t BTS_PWR_CTRL_MODE;
  uint8_t PR_MODE;

  Starting_Frame_Number_t TBF_Starting_Time;
} Single_Block_Allocation_t;

typedef struct
{
  uint8_t TIMESLOT_NUMBER;

  uint8_t Exist_ALPHA_and_GAMMA_TN;
  uint8_t ALPHA;
  uint8_t GAMMA_TN;

  uint8_t Exist_P0;
  uint8_t P0;
  uint8_t BTS_PWR_CTRL_MODE;
  uint8_t PR_MODE;

} DTM_Single_Block_Allocation_t;

typedef struct
{
  uint8_t UnionType;
  union
  {
    Global_TFI_t Global_TFI;
    uint32_t TLLI;
    uint16_t TQI;
    Packet_Request_Reference_t Packet_Request_Reference;
  } u;
} PacketUplinkID_t;

typedef struct
{
  bool Exist_Packet_Extended_Timing_Advance;
  uint8_t  Packet_Extended_Timing_Advance;
} PUA_GPRS_AdditionsR99_t;

typedef struct
{
  uint8_t                      CHANNEL_CODING_COMMAND;
  uint8_t                      TLLI_BLOCK_CHANNEL_CODING;
  Packet_Timing_Advance_t     Packet_Timing_Advance;

  uint8_t                      Exist_Frequency_Parameters;
  Frequency_Parameters_t      Frequency_Parameters;

  uint8_t                      UnionType;
  union
  {
    uint8_t                    extension;
    Dynamic_Allocation_t      Dynamic_Allocation;
    Single_Block_Allocation_t Single_Block_Allocation;
    uint8_t                    FixedAllocationDummy;
  } u;

  bool                         Exist_AdditionsR99;
  PUA_GPRS_AdditionsR99_t     AdditionsR99;
} PUA_GPRS_t;

typedef struct
{
  uint8_t  BitmapLength;
  uint8_t  ReducedMA_Bitmap[127 / 8 + 1];

  bool Exist_MAIO_2;
  uint8_t  MAIO_2;
} COMPACT_ReducedMA_t;

typedef struct
{
  uint8_t                  TIMESLOT_NUMBER;

  bool                     Exist_ALPHA_GAMMA_TN;
  uint8_t                  ALPHA;
  uint8_t                  GAMMA_TN;

  bool                     Exist_P0_BTS_PWR_CTRL_PR_MODE;
  uint8_t                  P0;
  uint8_t                  BTS_PWR_CTRL_MODE;
  uint8_t                  PR_MODE;

  Starting_Frame_Number_t TBF_Starting_Time;
  uint8_t                  NUMBER_OF_RADIO_BLOCKS_ALLOCATED;
} MultiBlock_Allocation_t;

typedef struct
{
  bool                         Exist_CONTENTION_RESOLUTION_TLLI;
  uint32_t                     CONTENTION_RESOLUTION_TLLI;

  bool                         Exist_COMPACT_ReducedMA;
  COMPACT_ReducedMA_t         COMPACT_ReducedMA;

  uint8_t                      EGPRS_CHANNEL_CODING_COMMAND;
  uint8_t                      RESEGMENT;
  uint8_t                      EGPRS_WindowSize;

  uint8_t                      NrOfAccessTechnologies;  /* will hold the number of list elements */
  uint8_t                      AccessTechnologyType[MAX_ACCESS_TECHOLOGY_TYPES]; /* for max size of array see 24.008/Table 10.5.146 */

  uint8_t                      ARAC_RETRANSMISSION_REQUEST;
  uint8_t                      TLLI_BLOCK_CHANNEL_CODING;

  bool                         Exist_BEP_PERIOD2;
  uint8_t                      BEP_PERIOD2;

  Packet_Timing_Advance_t     PacketTimingAdvance;

  bool                         Exist_Packet_Extended_Timing_Advance;
  uint8_t                      Packet_Extended_Timing_Advance;

  bool                         Exist_Frequency_Parameters;
  Frequency_Parameters_t      Frequency_Parameters;

  uint8_t                      UnionType;
  union
  {
    uint8_t                    extension;
    Dynamic_Allocation_t      Dynamic_Allocation;
    MultiBlock_Allocation_t   MultiBlock_Allocation;
    uint8_t                    FixedAllocationDummy;/* Fixed Allocation is not used */
  } u;
} PUA_EGPRS_00_t;

typedef struct
{
  uint8_t           UnionType;
  union
  {
    PUA_EGPRS_00_t PUA_EGPRS_00;
    uint8_t         PUA_EGPRS_01;
    uint8_t         PUA_EGPRS_10;
    uint8_t         PUA_EGPRS_11;
  } u;
} PUA_EGPRS_t;

#if 0
enum PUA_Type
{
  PUA_GPRS,
  PUA_EGPRS
};
#endif

typedef struct
{
  uint8_t MESSAGE_TYPE;
  uint8_t PAGE_MODE;

  uint8_t Exist_PERSISTENCE_LEVEL;
  uint8_t PERSISTENCE_LEVEL[4];

  PacketUplinkID_t ID;

  uint8_t UnionType;
  union
  {
    PUA_GPRS_t  PUA_GPRS_Struct;
    PUA_EGPRS_t PUA_EGPRS_Struct;
  } u;
} Packet_Uplink_Assignment_t;


/* < DTM Packet Uplink Assignment message content > */
typedef struct
{
  uint8_t CHANNEL_CODING_COMMAND;
  uint8_t TLLI_BLOCK_CHANNEL_CODING;
  Packet_Timing_Advance_t Packet_Timing_Advance;

  uint8_t UnionType;
  union
  {
    uint8_t extension;
    DTM_Dynamic_Allocation_t DTM_Dynamic_Allocation;
    DTM_Single_Block_Allocation_t DTM_Single_Block_Allocation;
  } u;
  bool Exist_EGPRS_Parameters;
  uint8_t EGPRS_CHANNEL_CODING_COMMAND;
  uint8_t RESEGMENT;
  uint8_t EGPRS_WindowSize;
  bool Exist_Packet_Extended_Timing_Advance;
  uint8_t Packet_Extended_Timing_Advance;
} DTM_Packet_Uplink_Assignment_t;

typedef struct
{
  DTM_Packet_Uplink_Assignment_t DTM_Packet_Uplink_Assignment;
} DTM_UL_t;

/* < DTM Packet Channel Request message content > */
typedef struct
{
  uint8_t DTM_Pkt_Est_Cause;
  Channel_Request_Description_t Channel_Request_Description;
  bool                                     Exist_PFI;
  uint8_t                                  PFI;
} DTM_Channel_Request_Description_t;

/* < Packet Downlink Assignment message content > */
typedef struct
{
  Starting_Frame_Number_t Measurement_Starting_Time;
  uint8_t MEASUREMENT_INTERVAL;
  uint8_t MEASUREMENT_BITMAP;
} Measurement_Mapping_struct_t;

typedef struct
{
  uint8_t UnionType;
  union
  {
    Global_TFI_t Global_TFI;
    uint32_t TLLI;
  } u;
} PacketDownlinkID_t;

typedef struct
{
  bool Exist_EGPRS_Params; /* if Exist_EGPRS_Params == false then none of the following 4 vars exist */
  uint8_t  EGPRS_WindowSize;
  uint8_t  LINK_QUALITY_MEASUREMENT_MODE;
  bool Exist_BEP_PERIOD2;
  uint8_t  BEP_PERIOD2;

  bool Exist_Packet_Extended_Timing_Advance;
  uint8_t  Packet_Extended_Timing_Advance;

  bool                 Exist_COMPACT_ReducedMA;
  COMPACT_ReducedMA_t COMPACT_ReducedMA;
} PDA_AdditionsR99_t;

typedef struct
{
  uint8_t                       MESSAGE_TYPE;
  uint8_t                       PAGE_MODE;

  bool                          Exist_PERSISTENCE_LEVEL;
  uint8_t                       PERSISTENCE_LEVEL[4];

  PacketDownlinkID_t           ID;

  uint8_t                       MAC_MODE;
  uint8_t                       RLC_MODE;
  uint8_t                       CONTROL_ACK;
  uint8_t                       TIMESLOT_ALLOCATION;
  Packet_Timing_Advance_t      Packet_Timing_Advance;

  bool                          Exist_P0_and_BTS_PWR_CTRL_MODE;
  uint8_t                       P0;
  uint8_t                       BTS_PWR_CTRL_MODE;
  uint8_t                       PR_MODE;

  bool                          Exist_Frequency_Parameters;
  Frequency_Parameters_t       Frequency_Parameters;

  bool                          Exist_DOWNLINK_TFI_ASSIGNMENT;
  uint8_t                       DOWNLINK_TFI_ASSIGNMENT;

  bool                          Exist_Power_Control_Parameters;
  Power_Control_Parameters_t   Power_Control_Parameters;

  bool                          Exist_TBF_Starting_Time;
  Starting_Frame_Number_t      TBF_Starting_Time;

  uint8_t                       Exist_Measurement_Mapping;
  Measurement_Mapping_struct_t Measurement_Mapping;

  bool                          Exist_AdditionsR99;
  PDA_AdditionsR99_t           AdditionsR99;
} Packet_Downlink_Assignment_t;

/* < DTM Packet Downlink Assignment message content > */
typedef struct
{
  uint8_t MAC_MODE;
  uint8_t RLC_MODE;
  uint8_t TIMESLOT_ALLOCATION;
  Packet_Timing_Advance_t Packet_Timing_Advance;

  uint8_t Exist_P0_and_BTS_PWR_CTRL_MODE;
  uint8_t P0;
  uint8_t BTS_PWR_CTRL_MODE;
  uint8_t PR_MODE;

  uint8_t Exist_Power_Control_Parameters;
  Power_Control_Parameters_t Power_Control_Parameters;

  uint8_t Exist_DOWNLINK_TFI_ASSIGNMENT;
  uint8_t DOWNLINK_TFI_ASSIGNMENT;

  uint8_t Exist_Measurement_Mapping;
  Measurement_Mapping_struct_t Measurement_Mapping;
  bool EGPRS_Mode;
  uint8_t EGPRS_WindowSize;
  uint8_t LINK_QUALITY_MEASUREMENT_MODE;
  bool Exist_Packet_Extended_Timing_Advance;
  uint8_t  Packet_Extended_Timing_Advance;
} DTM_Packet_Downlink_Assignment_t;

typedef struct
{
  DTM_Packet_Downlink_Assignment_t DTM_Packet_Downlink_Assignment;
} DTM_DL_t;

typedef struct
{
  GPRS_Cell_Options_t GPRS_Cell_Options;
  GPRS_Power_Control_Parameters_t GPRS_Power_Control_Parameters;
} DTM_GPRS_Broadcast_Information_t;

typedef struct
{
  DTM_GPRS_Broadcast_Information_t DTM_GPRS_Broadcast_Information;
} DTM_GPRS_B_t;

/* < Packet Paging Request message content > */
typedef struct
{
  uint8_t UnionType;
  union
  {
    TMSI_t PTMSI;
    struct MobileId Mobile_Identity;
  } u;
} Page_request_for_TBF_establishment_t;

typedef struct
{
  uint8_t UnionType;
  union
  {
    TMSI_t TMSI;
    struct MobileId Mobile_Identity;
  } u;

  uint8_t CHANNEL_NEEDED;

  uint8_t Exist_eMLPP_PRIORITY;
  uint8_t eMLPP_PRIORITY;
} Page_request_for_RR_conn_t;

typedef struct
{
  uint8_t UnionType;
  union
  {
    Page_request_for_TBF_establishment_t Page_req_TBF;
    Page_request_for_RR_conn_t Page_req_RR;
  } u;
} Repeated_Page_info_t;

typedef struct
{
  uint8_t MESSAGE_TYPE;
  uint8_t PAGE_MODE;

  uint8_t Exist_PERSISTENCE_LEVEL;
  uint8_t PERSISTENCE_LEVEL[4];

  uint8_t Exist_NLN;
  uint8_t NLN;

  uint8_t Count_Repeated_Page_info;
  Repeated_Page_info_t Repeated_Page_info[5];
} Packet_Paging_Request_t;

typedef struct
{
  uint8_t MESSAGE_TYPE;
  uint8_t PAGE_MODE;

  uint8_t TIMESLOTS_AVAILABLE;
} Packet_PDCH_Release_t;

/* < Packet Power Control/Timing Advance message content > */
typedef struct
{
  uint8_t UnionType;
  union
  {
    Global_TFI_t Global_TFI;
    uint16_t TQI;
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
  uint8_t UnionType;
  union
  {
    Global_Packet_Timing_Advance_t Global_Packet_Timing_Advance;
    Power_Control_Parameters_t Power_Control_Parameters;
  } u;
} GlobalTimingOrPower_t;

typedef struct
{
  uint8_t MESSAGE_TYPE;
  uint8_t PAGE_MODE;

  PacketPowerControlTimingAdvanceID_t ID;

  /* -- Message escape */
  uint8_t Exist_Global_Power_Control_Parameters;
  Global_Power_Control_Parameters_t Global_Power_Control_Parameters;

  uint8_t UnionType;
  union
  {
    GlobalTimingAndPower_t GlobalTimingAndPower;
    GlobalTimingOrPower_t GlobalTimingOrPower;
  } u;
} Packet_Power_Control_Timing_Advance_t;

/* < Packet Queueing Notification message content > */
typedef struct
{
  uint8_t MESSAGE_TYPE;
  uint8_t PAGE_MODE;

  /* 111 Fixed */
  Packet_Request_Reference_t Packet_Request_Reference;
  uint16_t TQI;
} Packet_Queueing_Notification_t;

/* < Packet Timeslot Reconfigure message content 04.60 sec. 11.2.31> */

typedef Dynamic_Allocation_t TRDynamic_Allocation_t;

typedef struct
{
  Global_Packet_Timing_Advance_t Global_Packet_Timing_Advance;

  uint8_t                         DOWNLINK_RLC_MODE;
  uint8_t                         CONTROL_ACK;

  uint8_t                         Exist_DOWNLINK_TFI_ASSIGNMENT;
  uint8_t                         DOWNLINK_TFI_ASSIGNMENT;

  uint8_t                         Exist_UPLINK_TFI_ASSIGNMENT;
  uint8_t                         UPLINK_TFI_ASSIGNMENT;

  uint8_t                         DOWNLINK_TIMESLOT_ALLOCATION;

  uint8_t                         Exist_Frequency_Parameters;
  Frequency_Parameters_t         Frequency_Parameters;
} Common_Timeslot_Reconfigure_t;

typedef struct
{
  bool Exist_Packet_Extended_Timing_Advance;
  uint8_t  Packet_Extended_Timing_Advance;
} PTR_GPRS_AdditionsR99_t;

typedef struct
{
  uint8_t                         CHANNEL_CODING_COMMAND;

  Common_Timeslot_Reconfigure_t  Common_Timeslot_Reconfigure_Data;

  uint8_t UnionType;
  union
  {
    TRDynamic_Allocation_t       Dynamic_Allocation;
    uint8_t                       Fixed_AllocationDummy;
  } u;

   bool                           Exist_AdditionsR99;
   PTR_GPRS_AdditionsR99_t       AdditionsR99;
} PTR_GPRS_t;

typedef struct
{
  bool                            Exist_COMPACT_ReducedMA;
  COMPACT_ReducedMA_t            COMPACT_ReducedMA;

  uint8_t                         EGPRS_ChannelCodingCommand;
  uint8_t                         RESEGMENT;

  bool                            Exist_DOWNLINK_EGPRS_WindowSize;
  uint8_t                         DOWNLINK_EGPRS_WindowSize;

  bool                            Exist_UPLINK_EGPRS_WindowSize;
  uint8_t                         UPLINK_EGPRS_WindowSize;

  uint8_t                         LINK_QUALITY_MEASUREMENT_MODE;

  bool                            Exist_Packet_Extended_Timing_Advance;
  uint8_t                         Packet_Extended_Timing_Advance;

  Common_Timeslot_Reconfigure_t  Common_Timeslot_Reconfigure_Data;

  uint8_t                         UnionType;
  union
  {
    TRDynamic_Allocation_t       Dynamic_Allocation;
    uint8_t                       FixedAllocationDummy;
  } u;
} PTR_EGPRS_00_t;

typedef struct
{
  uint8_t           UnionType;
  union
  {
    PTR_EGPRS_00_t PTR_EGPRS_00;
    uint8_t         extension_01;
    uint8_t         extension_10;
    uint8_t         extension_11;
  } u;
} PTR_EGPRS_t;

#if 0
enum PTR_Type
{
  PTR_GPRS,
  PTR_EGPRS
};
#endif

typedef struct
{
  uint8_t         MESSAGE_TYPE;
  uint8_t         PAGE_MODE;

  Global_TFI_t   Global_TFI;

   uint8_t        UnionType;
   union
   {
     PTR_GPRS_t  PTR_GPRS_Struct;
     PTR_EGPRS_t PTR_EGPRS_Struct;
   } u;
} Packet_Timeslot_Reconfigure_t;


/* < PSI1 message content > */
typedef struct
{
  uint8_t ACC_CONTR_CLASS[2];
  uint8_t MAX_RETRANS[4];
  uint8_t S;
  uint8_t TX_INT;

  uint8_t Exist_PERSISTENCE_LEVEL;
  uint8_t PERSISTENCE_LEVEL[4];
} PRACH_Control_t;

typedef struct
{
  uint8_t BS_PCC_REL;
  uint8_t BS_PBCCH_BLKS;
  uint8_t BS_PAG_BLKS_RES;
  uint8_t BS_PRACH_BLKS;
} PCCCH_Organization_t;

typedef struct
{
  uint8_t LB_MS_TXPWR_MAX_CCH;
} PSI1_AdditionsR6_t;

typedef struct
{
  uint8_t            MSCR;
  uint8_t            SGSNR;
  uint8_t            BandIndicator;
  bool               Exist_AdditionsR6;
  PSI1_AdditionsR6_t AdditionsR6;
} PSI1_AdditionsR99_t;

typedef struct
{
  uint8_t                           MESSAGE_TYPE;

  uint8_t                           PAGE_MODE;
  uint8_t                           PBCCH_CHANGE_MARK;
  uint8_t                           PSI_CHANGE_FIELD;
  uint8_t                           PSI1_REPEAT_PERIOD;
  uint8_t                           PSI_COUNT_LR;

  uint8_t                           Exist_PSI_COUNT_HR;
  uint8_t                           PSI_COUNT_HR;

  uint8_t                           MEASUREMENT_ORDER;
  GPRS_Cell_Options_t               GPRS_Cell_Options;
  PRACH_Control_t                   PRACH_Control;
  PCCCH_Organization_t              PCCCH_Organization;
  Global_Power_Control_Parameters_t Global_Power_Control_Parameters;
  uint8_t                           PSI_STATUS_IND;

  bool                              Exist_AdditionsR99;
  PSI1_AdditionsR99_t               AdditionsR99;
} PSI1_t;

/* < PSI2 message content > */
typedef struct
{
  uint8_t NUMBER;

  uint8_t Length;
  uint8_t Contents[15 + 3];/* octet (val(Length of RFL contents) + 3) */
} Reference_Frequency_t;

typedef struct
{
  uint8_t NoOfRFLs;
  uint8_t RFL_Number[MAX_RFLS];
} Cell_Allocation_t;

typedef struct
{
  uint8_t NUMBER;
  GPRS_Mobile_Allocation_t Mobile_Allocation;
} PSI2_MA_t;

typedef struct
{
  uint16_t ARFCN;
  uint8_t TIMESLOT_ALLOCATION;
} Non_Hopping_PCCCH_Carriers_t;

typedef struct
{
  uint8_t Count_Carriers;
  Non_Hopping_PCCCH_Carriers_t Carriers[7];
} NonHoppingPCCCH_t;

typedef struct
{
  uint8_t MAIO;
  uint8_t TIMESLOT_ALLOCATION;
} Hopping_PCCCH_Carriers_t;

typedef struct
{
  uint8_t MA_NUMBER;

  uint8_t Count_Carriers;
  Hopping_PCCCH_Carriers_t Carriers[10];/* MAX_PCCCH but 10 is theoretical max. */
} HoppingPCCCH_t;

typedef struct
{
  uint8_t TSC;

  uint8_t UnionType;
  union
  {
    NonHoppingPCCCH_t NonHopping;
    HoppingPCCCH_t Hopping;
  } u;
} PCCCH_Description_t;

typedef struct
{
  LAI_t LAI;
  uint8_t RAC;
  CellId_t Cell_Identity;
} Cell_Identification_t;

typedef struct
{
  uint8_t ATT;

  uint8_t Exist_T3212;
  uint8_t T3212;

  uint8_t NECI;
  uint8_t PWRC;
  uint8_t DTX;
  uint8_t RADIO_LINK_TIMEOUT;
  uint8_t BS_AG_BLKS_RES;
  uint8_t CCCH_CONF;
  uint8_t BS_PA_MFRMS;
  uint8_t MAX_RETRANS;
  uint8_t TX_INTEGER;
  uint8_t EC;
  uint8_t MS_TXPWR_MAX_CCCH;

  uint8_t Exist_Extension_Bits;
  Extension_Bits_t Extension_Bits;
} Non_GPRS_Cell_Options_t;

typedef struct
{
  uint8_t MESSAGE_TYPE;
  uint8_t PAGE_MODE;
  uint8_t CHANGE_MARK;
  uint8_t INDEX;
  uint8_t COUNT;

  uint8_t Exist_Cell_Identification;
  Cell_Identification_t Cell_Identification;

  uint8_t Exist_Non_GPRS_Cell_Options;
  Non_GPRS_Cell_Options_t Non_GPRS_Cell_Options;

  uint8_t Count_Reference_Frequency;
  Reference_Frequency_t Reference_Frequency[MAX_RFLS];

  Cell_Allocation_t Cell_Allocation;

  uint8_t Count_GPRS_MA;
  PSI2_MA_t GPRS_MA[MAX_MA_LISTS_IN_PSI2];

  uint8_t Count_PCCCH_Description;
  PCCCH_Description_t PCCCH_Description[7];/* MAX_PCCCH but it is impossible that more than 7 can be decoded */
} PSI2_t;

/* < PSI3 message content > */
typedef struct
{
  uint8_t PRIORITY_CLASS;
  uint8_t HCS_THR;
} HCS_t;

typedef struct
{
  uint8_t CELL_BAR_ACCESS_2;
  uint8_t EXC_ACC;
  uint8_t GPRS_RXLEV_ACCESS_MIN;
  uint8_t GPRS_MS_TXPWR_MAX_CCH;

  uint8_t Exist_HCS;
  HCS_t HCS;
  uint8_t MULTIBAND_REPORTING;
} Serving_Cell_params_t;

typedef struct
{
  uint8_t GPRS_CELL_RESELECT_HYSTERESIS;
  uint8_t C31_HYST;
  uint8_t C32_QUAL;
  uint8_t RANDOM_ACCESS_RETRY;

  uint8_t Exist_T_RESEL;
  uint8_t T_RESEL;

  uint8_t Exist_RA_RESELECT_HYSTERESIS;
  uint8_t RA_RESELECT_HYSTERESIS;
} Gen_Cell_Sel_t;

typedef struct
{
  uint8_t PBCCH_LOCATION;
  uint8_t PSI1_REPEAT_PERIOD;
} Location_Repeat_t;

typedef struct
{
  uint8_t UnionType;
  union
  {
    uint8_t SI13_LOCATION;
    Location_Repeat_t lr;
  } u;
} SI13_PBCCH_Location_t;

typedef struct
{
  uint8_t BSIC;
  uint8_t CELL_BAR_ACCESS_2;
  uint8_t EXC_ACC;
  uint8_t SAME_RA_AS_SERVING_CELL;

  uint8_t Exist_RXLEV_and_TXPWR;
  uint8_t GPRS_RXLEV_ACCESS_MIN;
  uint8_t GPRS_MS_TXPWR_MAX_CCH;

  uint8_t Exist_OFFSET_and_TIME;
  uint8_t GPRS_TEMPORARY_OFFSET;
  uint8_t GPRS_PENALTY_TIME;

  uint8_t Exist_GPRS_RESELECT_OFFSET;
  uint8_t GPRS_RESELECT_OFFSET;

  uint8_t Exist_HCS;
  HCS_t HCS;

  uint8_t Exist_SI13_PBCCH_Location;
  SI13_PBCCH_Location_t SI13_PBCCH_Location;
} Cell_Selection_t;

/* Neighbour cell list as used in PSI3 and PSI3bis */
typedef struct
{
  uint8_t FREQ_DIFF_LENGTH;
  uint8_t FREQUENCY_DIFF;

  Cell_Selection_t Cell_SelectionParams;
} Cell_Selection_Params_With_FreqDiff_t;

typedef struct
{
  uint16_t START_FREQUENCY;
  Cell_Selection_t Cell_Selection;
  uint8_t NR_OF_REMAINING_CELLS;
  uint8_t FREQ_DIFF_LENGTH;

  Cell_Selection_Params_With_FreqDiff_t Cell_Selection_Params_With_FreqDiff[16];
} NeighbourCellParameters_t;

typedef struct
{
  uint8_t Count;
  NeighbourCellParameters_t Parameters[32];
} NeighbourCellList_t;

/* < PSI3 message content > */

typedef struct
{
  uint8_t bsic;
  uint8_t CELL_BAR_ACCESS_2;
  uint8_t EXC_ACC;
  uint8_t SAME_RA_AS_SERVING_CELL;
  uint8_t Exist_GPRS_RXLEV_ACCESS_MIN;
  uint8_t GPRS_RXLEV_ACCESS_MIN;
  uint8_t GPRS_MS_TXPWR_MAX_CCH;
  uint8_t Exist_GPRS_TEMPORARY_OFFSET;
  uint8_t GPRS_TEMPORARY_OFFSET;
  uint8_t GPRS_PENALTY_TIME;
  uint8_t Exist_GPRS_RESELECT_OFFSET;
  uint8_t GPRS_RESELECT_OFFSET;
  uint8_t Exist_Hcs_Parm;
  HCS_t   HCS_Param;
  uint8_t Exist_TIME_GROUP;
  uint8_t TIME_GROUP;
  uint8_t Exist_GUAR_CONSTANT_PWR_BLKS;
  uint8_t GUAR_CONSTANT_PWR_BLKS;
} COMPACT_Cell_Sel_t;

typedef struct
{
  uint8_t FREQ_DIFF_LENGTH;
  uint16_t FREQUENCY_DIFF;
  COMPACT_Cell_Sel_t  COMPACT_Cell_Sel_Remain_Cells;
} COMPACT_Neighbour_Cell_Param_Remaining_t;

typedef struct
{
  uint16_t START_FREQUENCY;
  COMPACT_Cell_Sel_t COMPACT_Cell_Sel;
  uint8_t NR_OF_REMAINING_CELLS;
  uint8_t FREQ_DIFF_LENGTH;
  COMPACT_Neighbour_Cell_Param_Remaining_t  COMPACT_Neighbour_Cell_Param_Remaining[16];
} COMPACT_Neighbour_Cell_Param_t;

typedef struct
{
  Cell_Identification_t Cell_Identification;
  uint8_t COMPACT_Neighbour_Cell_Param_Count;
  COMPACT_Neighbour_Cell_Param_t COMPACT_Neighbour_Cell_Param[8];
} COMPACT_Info_t;

typedef struct
{
  uint8_t Exist_CCN_Support_Desc;
  CCN_Support_Description_t CCN_Support_Desc;
} PSI3_AdditionR4_t;

typedef struct
{
  uint8_t Exist_COMPACT_Info;
  COMPACT_Info_t COMPACT_Info;
  uint8_t Exist_AdditionR4;
  PSI3_AdditionR4_t AdditionR4;
} PSI3_AdditionR99_t;

typedef struct
{
  LSA_ID_Info_t Scell_LSA_ID_Info;
  uint8_t Exist_LSA_Parameters;
  LSA_Parameters_t LSA_Parameters;
  uint8_t Exist_AdditionR99;
  PSI3_AdditionR99_t AdditionR99;
} PSI3_AdditionR98_t;

typedef struct
{
  uint8_t MESSAGE_TYPE;
  uint8_t PAGE_MODE;
  uint8_t CHANGE_MARK;
  uint8_t BIS_COUNT;

  Serving_Cell_params_t Serving_Cell_params;

  Gen_Cell_Sel_t General_Cell_Selection;
  NeighbourCellList_t NeighbourCellList;

  uint8_t Exist_AdditionR98;
  PSI3_AdditionR98_t AdditionR98;
} PSI3_t;

/* < PSI3_BIS message content > */
typedef struct
{
  uint8_t MESSAGE_TYPE;
  uint8_t PAGE_MODE;
  uint8_t CHANGE_MARK;
  uint8_t BIS_INDEX;
  uint8_t BIS_COUNT;

  NeighbourCellList_t NeighbourCellList;
} PSI3_BIS_t;

/* < PSI4 message content > */
typedef struct
{
  uint8_t MA_NUMBER;
  uint8_t MAIO;
} h_CG_t;

typedef struct
{
  uint8_t UnionType;
  union
  {
    uint16_t ARFCN;
    h_CG_t h_CG;
  } u;

  uint8_t TIMESLOT_ALLOCATION;
} Channel_Group_t;

typedef struct
{
  /* Channel_Group_t Channel_Group
   * At least one
   * the first one is unpacked in the index
   */
  uint8_t Count_Channel_Group;
  Channel_Group_t Channel_Group[8];
} Channel_List_t;

typedef struct
{
  uint8_t MESSAGE_TYPE;

  uint8_t PAGE_MODE;
  uint8_t CHANGE_MARK;
  uint8_t INDEX;
  uint8_t COUNT;

  Channel_List_t Channel_List;

} PSI4_t;


/* < PSI5 message content > */
typedef struct
{
  uint8_t existRepParamsFDD;
  uint8_t RepQuantFDD;
  uint8_t MultiratReportingFDD;

  uint8_t existReportingParamsFDD;
  uint8_t ReportingOffsetFDD;
  uint8_t ReportingThresholdFDD;

  uint8_t existMultiratReportingTDD;
  uint8_t MultiratReportingTDD;

  uint8_t existOffsetThresholdTDD;
  uint8_t ReportingOffsetTDD;
  uint8_t ReportingThresholdTDD;
} GPRSMeasurementParams3G_PSI5_t;

typedef struct
{
  uint8_t  REPORT_TYPE;
  uint8_t  REPORTING_RATE;
  uint8_t  INVALID_BSIC_REPORTING;
  uint8_t Exist_NCC_PERMITTED;
  uint8_t  NCC_PERMITTED;

  bool Exist_GPRSMeasurementParams;
  MeasurementParams_t   GPRSMeasurementParams;
  bool Exist_GPRSMeasurementParams3G;
  GPRSMeasurementParams3G_PSI5_t  GPRSMeasurementParams3G;
} ENH_Reporting_Parameters_t;

typedef struct
{
  uint8_t Exist_OffsetThreshold_700;
  OffsetThreshold_t OffsetThreshold_700;
  uint8_t Exist_OffsetThreshold_810;
  OffsetThreshold_t OffsetThreshold_810;
} PSI5_AdditionsR7;

typedef struct
{
  uint8_t Exist_GPRS_AdditionalMeasurementParams3G;
  GPRS_AdditionalMeasurementParams3G_t GPRS_AdditionalMeasurementParams3G;
  uint8_t Exist_AdditionsR7;
  PSI5_AdditionsR7 AdditionsR7;
} PSI5_AdditionsR5;

typedef struct
{
  uint8_t Exist_ENH_Reporting_Param;
  ENH_Reporting_Parameters_t ENH_Reporting_Param;
  uint8_t Exist_AdditionsR5;
  PSI5_AdditionsR5 AdditionisR5;
} PSI5_AdditionsR99;

typedef struct
{
  uint8_t MESSAGE_TYPE;

  uint8_t PAGE_MODE;
  uint8_t CHANGE_MARK;
  uint8_t INDEX;
  uint8_t COUNT;

  uint8_t Eixst_NC_Meas_Param;
  NC_Measurement_Parameters_t NC_Meas_Param;
  uint8_t Exist_AdditionsR99;
  PSI5_AdditionsR99 AdditionsR99;
} PSI5_t;




/* < PSI13 message content >
 * Combined with SI13
 */
typedef struct
{
  uint8_t Exist_LB_MS_TXPWR_MAX_CCH;
  uint8_t LB_MS_TXPWR_MAX_CCH;
  uint8_t SI2n_SUPPORT;
}PSI13_AdditionsR6;

typedef PSI13_AdditionsR6 SI13_AdditionsR6;

typedef struct
{
  uint8_t               SI_STATUS_IND;
  uint8_t               Exist_AdditionsR6;
  PSI13_AdditionsR6     AdditionsR6;
}PSI13_AdditionsR4;

typedef PSI13_AdditionsR4 SI13_AdditionsR4;

typedef struct
{
  uint8_t               SGSNR;
  bool                  Exist_AdditionsR4;
  PSI13_AdditionsR4     AdditionsR4;
}PSI13_AdditionR99;

typedef PSI13_AdditionR99 SI13_AdditionR99;

typedef struct
{
  uint8_t Exist;
  uint8_t MESSAGE_TYPE;

  uint8_t PAGE_MODE;
  uint8_t BCCH_CHANGE_MARK;
  uint8_t SI_CHANGE_FIELD;

  uint8_t Exist_MA;
  uint8_t SI13_CHANGE_MARK;
  GPRS_Mobile_Allocation_t GPRS_Mobile_Allocation;

  uint8_t UnionType;
  union
  {
    PBCCH_Not_present_t PBCCH_Not_present;
    PBCCH_present_t PBCCH_present;
  } u;

  bool                  Exist_AdditionsR99;
  PSI13_AdditionR99     AdditionsR99;
} PSI13_t;

/* SI_13_t is combined in the PSI13 structure */
typedef PSI13_t SI_13_t;

/* < Packet PRACH Parameters message content > */
typedef struct
{
  uint8_t MESSAGE_TYPE;
  uint8_t PAGE_MODE;


  PRACH_Control_t PRACH_Control;
} Packet_PRACH_Parameters_t;

/* < Packet Access Reject message content > */
typedef struct
{
  uint8_t UnionType;
  union
  {
    uint32_t TLLI;
    Packet_Request_Reference_t Packet_Request_Reference;
    Global_TFI_t Global_TFI;
  } u;
} RejectID_t;

typedef struct
{
  RejectID_t ID;

  uint8_t Exist_Wait;
  uint8_t WAIT_INDICATION;
  uint8_t WAIT_INDICATION_SIZE;
} Reject_t;

typedef struct
{
  uint8_t MESSAGE_TYPE;
  uint8_t PAGE_MODE;

  uint8_t IndexToOur;
  uint8_t Count_Reject;
  Reject_t Reject[5];
} Packet_Access_Reject_t;

/* < Packet Cell Change Order message content > */
typedef struct
{
  uint8_t CELL_BAR_ACCESS_2;
  uint8_t EXC_ACC;
  uint8_t SAME_RA_AS_SERVING_CELL;

  uint8_t Exist_RXLEV_and_TXPWR;
  uint8_t GPRS_RXLEV_ACCESS_MIN;
  uint8_t GPRS_MS_TXPWR_MAX_CCH;

  uint8_t Exist_OFFSET_and_TIME;
  uint8_t GPRS_TEMPORARY_OFFSET;
  uint8_t GPRS_PENALTY_TIME;

  uint8_t Exist_GPRS_RESELECT_OFFSET;
  uint8_t GPRS_RESELECT_OFFSET;

  uint8_t Exist_HCS;
  HCS_t HCS;

  uint8_t Exist_SI13_PBCCH_Location;
  SI13_PBCCH_Location_t SI13_PBCCH_Location;
} Cell_Selection_2_t;

typedef struct
{
  uint8_t FREQUENCY_DIFF;
  uint8_t BSIC;
  Cell_Selection_t Cell_Selection;
} h_FreqBsicCell_t;

typedef struct
{
  uint8_t FREQ_DIFF_LENGTH;
  uint8_t FREQUENCY_DIFF;
  uint8_t BSIC;

  bool Exist_CellSelectionParams;
  Cell_Selection_2_t CellSelectionParams;
} CellSelectionParamsWithFreqDiff_t;

typedef struct
{
  uint16_t START_FREQUENCY;
  uint8_t BSIC;

  uint8_t Exist_Cell_Selection;
  Cell_Selection_2_t Cell_Selection;

  uint8_t NR_OF_FREQUENCIES;
  uint8_t FREQ_DIFF_LENGTH;


  CellSelectionParamsWithFreqDiff_t CellSelectionParamsWithFreqDiff[32];
} Add_Frequency_list_t;

typedef struct
{
  uint8_t REMOVED_FREQ_INDEX;
} Removed_Freq_Index_t;

typedef struct
{
  uint8_t Exist_REMOVED_FREQ;
  uint8_t NR_OF_REMOVED_FREQ;
  Removed_Freq_Index_t Removed_Freq_Index[32];

  uint8_t Count_Add_Frequency;
  Add_Frequency_list_t Add_Frequency[32];
} NC_Frequency_list_t;


typedef struct
{
  uint8_t NETWORK_CONTROL_ORDER;

  uint8_t Exist_NC;
  uint8_t NC_NON_DRX_PERIOD;
  uint8_t NC_REPORTING_PERIOD_I;
  uint8_t NC_REPORTING_PERIOD_T;

  uint8_t Exist_NC_FREQUENCY_LIST;
  NC_Frequency_list_t NC_Frequency_list;
} NC_Measurement_Parameters_with_Frequency_List_t;


typedef struct
{
  uint8_t BA_IND;
  uint8_t BA_IND_3G;
} BA_IND_t;

typedef struct
{
  uint8_t BA_USED;
  uint8_t BA_USED_3G;
} BA_USED_t;

typedef struct
{
  uint8_t RXLEV_SERVING_CELL;
} Serving_Cell_Data_t;

typedef struct
{
  uint8_t FREQUENCY_N;
  uint8_t Exist_BSIC_N;
  uint8_t BSIC_N;
  uint8_t RXLEV_N;
} NC_Measurements_t;

typedef struct
{
  uint8_t BCCH_FREQ_N;
  uint8_t BSIC_N;
  uint8_t RXLEV_N;
} RepeatedInvalid_BSIC_Info_t;

typedef struct
{
  uint8_t Exist_REPORTING_QUANTITY;
  uint8_t REPORTING_QUANTITY;
} REPORTING_QUANTITY_Instance_t;

typedef struct
{
  uint8_t NC_MODE;
  Serving_Cell_Data_t Serving_Cell_Data;

  uint8_t NUMBER_OF_NC_MEASUREMENTS;
  NC_Measurements_t NC_Measurements[6];  /* NC_Measurements * (val(NUMBER_OF_NC_MEASUREMENTS))
                                           Max 7 NC Measurements in one PACKET MEASUREMENT REPORT,
                                           but only 6 cells are updated in PACKET IDLE. */
} NC_Measurement_Report_t;

typedef struct
{
  uint8_t EXT_REPORTING_TYPE;

  uint8_t Exist_I_LEVEL;
  struct
  {
    uint8_t Exist;
    uint8_t I_LEVEL;
  } Slot[8];

  uint8_t NUMBER_OF_EXT_MEASUREMENTS;
  NC_Measurements_t EXT_Measurements[9];  /* EXT_Measurements * (val(NUMBER_OF_NC_MEASUREMENTS))
                                            Max 9 Ext Measurements in one PACKET MEASUREMENT REPORT */
} EXT_Measurement_Report_t;

typedef struct
{
  uint8_t CELL_LIST_INDEX_3G;
  uint8_t REPORTING_QUANTITY;
} Measurements_3G_t;

typedef struct
{
  uint32_t UTRAN_CGI;
  uint8_t Exist_PLMN_ID;
  PLMN_t   Plmn_ID;
  uint32_t CSG_ID;
  bool Access_Mode;
  uint8_t  REPORTING_QUANTITY;
} UTRAN_CSG_Measurement_Report_t;

typedef struct
{
  uint32_t EUTRAN_CGI;
  uint16_t Tracking_Area_Code;
  uint8_t Exist_PLMN_ID;
  PLMN_t   Plmn_ID;
  uint32_t CSG_ID;
  bool Access_Mode;
  uint8_t  REPORTING_QUANTITY;
} EUTRAN_CSG_Measurement_Report_t;

typedef struct
{
  bool      Exist_UTRAN_CSG_Meas_Rpt;
  UTRAN_CSG_Measurement_Report_t  UTRAN_CSG_Meas_Rpt;
  bool      Exist_EUTRAN_CSG_Meas_Rpt;
  EUTRAN_CSG_Measurement_Report_t  EUTRAN_CSG_Meas_Rpt;
} PMR_AdditionsR9_t;

typedef struct
{
  uint8_t EUTRAN_FREQUENCY_INDEX;
  uint16_t CELL_IDENTITY;
  uint8_t REPORTING_QUANTITY;
} EUTRAN_Measurement_Report_Body_t;

typedef struct
{
  uint8_t N_EUTRAN;
  EUTRAN_Measurement_Report_Body_t Report[4];
} EUTRAN_Measurement_Report_t;

typedef struct
{
  bool       Exist_EUTRAN_Meas_Rpt;
  EUTRAN_Measurement_Report_t  EUTRAN_Meas_Rpt;
  bool       Exist_AdditionsR9;
  PMR_AdditionsR9_t  AdditionsR9;
} PMR_AdditionsR8_t;

typedef struct
{
  bool         Exist_GRNTI;
  uint8_t       GRNTI;
  bool         Exist_AdditionsR8;
  PMR_AdditionsR8_t  AdditionsR8;
} PMR_AdditionsR5_t;

typedef struct
{
  bool         Exist_Info3G;
  uint8_t      UnionType;
  union
  {
    BA_USED_t BA_USED;
    uint8_t    PSI3_CHANGE_MARK;
  } u;
  uint8_t      PMO_USED;

  /* N_3G        bit(3): max value 7
   * Report part  (csn): {<3G_CELL_LIST_INDEX:bit(7)><REPORTING_QUANTITY:bit(6)>}*(val(N_3G + 1))
   * Max 6 3G measurement structs in one PMR
   */
  bool         Exist_MeasurementReport3G;
  uint8_t      N_3G;
  Measurements_3G_t Measurements_3G[6];

  bool         Exist_AdditionsR5;
  PMR_AdditionsR5_t  AdditionsR5;
} PMR_AdditionsR99_t;

typedef struct
{
  uint8_t MESSAGE_TYPE;
  uint8_t PayloadType;
  uint8_t spare;
  uint8_t R;

  uint32_t TLLI;
  uint8_t Exist_PSI5_CHANGE_MARK;
  uint8_t PSI5_CHANGE_MARK;

  uint8_t UnionType;
  union
  {
    NC_Measurement_Report_t NC_Measurement_Report;
    EXT_Measurement_Report_t EXT_Measurement_Report;
  } u;

  bool Exist_AdditionsR99;
  PMR_AdditionsR99_t AdditionsR99;
} Packet_Measurement_Report_t;

#define INV_BSIC_LIST_LEN (16)

#define REPORT_QUANTITY_LIST_LEN (96) /* Specification specified up to 96 */

typedef struct
{
  uint8_t NC_MODE;
  uint8_t UnionType;
  union
  {
    BA_USED_t BA_USED;
    uint8_t PSI3_CHANGE_MARK;
  } u;

  uint8_t PMO_USED;
  uint8_t BSIC_Seen;
  uint8_t SCALE;

  uint8_t Exist_Serving_Cell_Data;
  Serving_Cell_Data_t Serving_Cell_Data;

  uint8_t Count_RepeatedInvalid_BSIC_Info;
  RepeatedInvalid_BSIC_Info_t RepeatedInvalid_BSIC_Info[INV_BSIC_LIST_LEN];

  uint8_t Exist_ReportBitmap;
  uint8_t Count_REPORTING_QUANTITY_Instances;
  REPORTING_QUANTITY_Instance_t REPORTING_QUANTITY_Instances[REPORT_QUANTITY_LIST_LEN];

} ENH_NC_Measurement_Report_t;

typedef struct
{
  uint8_t Exist_UTRAN_CSG_Target_Cell;
  UTRAN_CSG_Target_Cell_t UTRAN_CSG_Target_Cell;
  uint8_t Exist_EUTRAN_CSG_Target_Cell;
  EUTRAN_CSG_Target_Cell_t EUTRAN_CSG_Target_Cell;
} PEMR_AdditionsR9_t;

typedef struct
{
  bool      Exist_REPORTING_QUANTITY;
  uint8_t    REPORTING_QUANTITY;
} Bitmap_Report_Quantity_t;

typedef struct
{
  uint8_t BITMAP_LENGTH;
  Bitmap_Report_Quantity_t  Bitmap_Report_Quantity[128];
  bool      Exist_EUTRAN_Meas_Rpt;
  EUTRAN_Measurement_Report_t EUTRAN_Meas_Rpt;
  bool       Exist_AdditionsR9;
  PEMR_AdditionsR9_t AdditionsR9;
} PEMR_AdditionsR8_t;

typedef struct
{
  bool      Exist_GRNTI_Ext;
  uint8_t    GRNTI_Ext;
  bool      Exist_AdditionsR8;
  PEMR_AdditionsR8_t  AdditionsR8;
} PEMR_AdditionsR5_t;

typedef struct
{
  uint8_t MESSAGE_TYPE;
  uint8_t PayloadType;
  uint8_t spare;
  uint8_t R;

  uint32_t TLLI;

  ENH_NC_Measurement_Report_t Measurements;

  bool      Exist_AdditionsR5;
  PEMR_AdditionsR5_t  AdditionsR5;
} Packet_Enh_Measurement_Report_t;

typedef struct
{
  uint8_t RXLEV_SERVING_CELL;

  uint8_t NUMBER_OF_NC_MEASUREMENTS;
  NC_Measurements_t NC_Measurements[6];  /* NC_Measurements * (val(NUMBER_OF_NC_MEASUREMENTS))
                                           Max 7 NC Measurements in one PACKET MEASUREMENT REPORT,
                                           but only 6 cells are updated in PACKET IDLE. */
} CCN_Measurement_Report_t;

typedef struct
{
  uint16_t ARFCN;
  uint8_t BSIC;
} Target_Cell_GSM_Notif_t;

typedef struct
{
  uint16_t FDD_ARFCN;
  uint8_t Exist_Bandwith_FDD;
  uint8_t BANDWITH_FDD;
  uint16_t SCRAMBLING_CODE;
} FDD_Target_Cell_Notif_t;

typedef struct
{
  uint16_t TDD_ARFCN;
  uint8_t Exist_Bandwith_TDD;
  uint8_t BANDWITH_TDD;
  uint8_t CELL_PARAMETER;
  uint8_t Sync_Case_TSTD;
} TDD_Target_Cell_Notif_t;

typedef struct
{
  uint8_t Exist_FDD_Description;
  FDD_Target_Cell_Notif_t FDD_Target_Cell_Notif;
  uint8_t Exist_TDD_Description;
  TDD_Target_Cell_Notif_t TDD_Target_Cell;
  uint8_t REPORTING_QUANTITY;
} Target_Cell_3G_Notif_t;

typedef struct
{
  uint16_t EARFCN;
  uint8_t Exist_Measurement_Bandwidth;
  uint8_t Measurement_Bandwidth;
  uint16_t Physical_Layer_Cell_Identity;
  uint8_t Reporting_Quantity;
} Target_EUTRAN_Cell_Notif_t;

typedef struct
{
  uint8_t EUTRAN_FREQUENCY_INDEX;
  uint16_t CELL_IDENTITY;
  uint8_t REPORTING_QUANTITY;
} Eutran_Ccn_Measurement_Report_Cell_t;

typedef struct
{
  bool      ThreeG_BA_USED;
  uint8_t   N_EUTRAN;
  Eutran_Ccn_Measurement_Report_Cell_t Eutran_Ccn_Measurement_Report_Cell[4];
} Eutran_Ccn_Measurement_Report_t;

typedef struct
{
  uint8_t Exist_Arfcn;
  uint16_t Arfcn;
  uint8_t bsic;
  uint8_t Exist_3G_Target_Cell;
  Target_Cell_3G_Notif_t Target_Cell_3G_Notif;
  uint8_t Exist_Eutran_Target_Cell;
  Target_EUTRAN_Cell_Notif_t Target_EUTRAN_Cell;
  uint8_t Exist_Eutran_Ccn_Measurement_Report;
  Eutran_Ccn_Measurement_Report_t Eutran_Ccn_Measurement_Report;
} Target_Cell_4G_Notif_t;

typedef struct
{
  uint8_t UnionType;
  union
  {
    UTRAN_CSG_Measurement_Report_t UTRAN_CSG_Measurement_Report;
    EUTRAN_CSG_Measurement_Report_t EUTRAN_CSG_Measurement_Report;
  } u;
  uint8_t Exist_Eutran_Ccn_Measurement_Report;
  Eutran_Ccn_Measurement_Report_t Eutran_Ccn_Measurement_Report;
} Target_Cell_CSG_Notif_t;

typedef struct
{
  uint8_t UnionType;
  union
  {
    Target_Cell_4G_Notif_t Target_Cell_4G_Notif;
    Target_Cell_CSG_Notif_t Target_Cell_CSG_Notif;
  } u;
} Target_Other_RAT_2_Notif_t;

typedef struct
{
  uint8_t UnionType;
  union
  {
    Target_Cell_3G_Notif_t Target_Cell_3G_Notif;
    Target_Other_RAT_2_Notif_t Target_Other_RAT_2_Notif;
  } u;
} Target_Other_RAT_Notif_t;

typedef struct
{
  uint8_t UnionType;
  union
  {
    Target_Cell_GSM_Notif_t Target_Cell_GSM_Notif;
    Target_Other_RAT_Notif_t Target_Other_RAT_Notif;
  } u;
} Target_Cell_t;

typedef struct
{
  uint8_t Exist_BA_USED_3G;
  uint8_t BA_USED_3G;

  uint8_t N_3G;
  Measurements_3G_t Measurements_3G[6];
} PCCN_AdditionsR6_t;

/* < Packet Cell Change Notification message contents > */
typedef struct
{
  uint8_t MESSAGE_TYPE;
  uint8_t PayloadType;
  uint8_t spare;
  uint8_t R;

  Global_TFI_t Global_TFI;

  Target_Cell_t Target_Cell;

  uint8_t UnionType;
  union
  {
    uint8_t BA_IND;
    uint8_t PSI3_CHANGE_MARK;
  } u;
  uint8_t PMO_USED;
  uint8_t PCCN_SENDING;
  CCN_Measurement_Report_t CCN_Measurement_Report;

  bool Exist_AdditionsR6;
  PCCN_AdditionsR6_t AdditionsR6;
} Packet_Cell_Change_Notification_t;

/* < Packet Cell Change Order message contents > */


typedef struct
{
  uint8_t  FrequencyScrolling;
  uint8_t  BSIC;
} BSICDesc_t;


#define MAX_BSIC_DESCS (19) /* Due to message size (23 bytes) and header etc,
                             * there cannot be more than 19 DESCS.
                             */

typedef struct
{
  bool         Exist_IndexStartBA;
  uint8_t      IndexStartBA;
  uint8_t      BSIC;
  uint8_t      NumRemainingBSICs;
  BSICDesc_t  BSICDesc[MAX_BSIC_DESCS];
} BSICList_t;

typedef BSICList_t GPRSBSICList_t;

#define MAX_RTD_VALUES (6)

typedef struct
{
  uint8_t NumRTDValues;
  uint16_t RTD[MAX_RTD_VALUES];
} RTDValues_t;

typedef struct
{
  bool Exist_StartValue;
  uint8_t  StartValue;
} BAIndexStartRTD_t;

#define MAX_RTD_FREQS (32)

typedef struct
{
  BAIndexStartRTD_t BAIndexStart;
  uint8_t NumFreqs;
  RTDValues_t RTD_s[MAX_RTD_FREQS];
} RTDList_t;

typedef struct
{
  bool       Exist_ListRTD6;
  RTDList_t ListRTD6;

  bool       Exist_ListRTD12;
  RTDList_t ListRTD12;
} RealTimeDiffs_t;


typedef MeasurementParams_t GPRSMeasurementParams_PMO_PCCO_t;

typedef struct {
  bool               existMultiratReporting;
  uint8_t            MultiratReporting;

  bool               existOffsetThreshold;
  OffsetThreshold_t OffsetThreshold;
} MultiratParams3G_t;

typedef struct
{
  uint8_t             Qsearch_P;
  uint8_t             SearchPrio3G;

  bool                existRepParamsFDD;
  uint8_t             RepQuantFDD;
  uint8_t             MultiratReportingFDD;

  bool                existOffsetThreshold;
  OffsetThreshold_t  OffsetThreshold;

  MultiratParams3G_t ParamsTDD;
  MultiratParams3G_t ParamsCDMA2000;
} ENH_GPRSMeasurementParams3G_PMO_t;


typedef struct
{
  uint8_t             Qsearch_P;
  uint8_t             SearchPrio3G;

  bool                existRepParamsFDD;
  uint8_t             RepQuantFDD;
  uint8_t             MultiratReportingFDD;

  bool                existOffsetThreshold;
  OffsetThreshold_t  OffsetThreshold;

  MultiratParams3G_t ParamsTDD;
} ENH_GPRSMeasurementParams3G_PCCO_t;


typedef struct
{
  uint8_t Qsearch_p;
  uint8_t SearchPrio3G;

  uint8_t existRepParamsFDD;
  uint8_t RepQuantFDD;
  uint8_t MultiratReportingFDD;

  uint8_t existReportingParamsFDD;
  uint8_t ReportingOffsetFDD;
  uint8_t ReportingThresholdFDD;

  uint8_t existMultiratReportingTDD;
  uint8_t MultiratReportingTDD;

  uint8_t existOffsetThresholdTDD;
  uint8_t ReportingOffsetTDD;
  uint8_t ReportingThresholdTDD;
} GPRSMeasurementParams3G_t;

typedef struct
{
  uint8_t REMOVED_3GCELL_INDEX;
  uint8_t CELL_DIFF_LENGTH_3G;
  uint8_t CELL_DIFF_3G;
} N2_t;

typedef struct
{
  uint8_t N2_Count;
  N2_t N2s[32];
} N1_t;

typedef struct
{
  uint8_t N1_Count;
  N1_t N1s[4];
} Removed3GCellDescription_t;

typedef struct
{
  uint8_t Complete_This;
} CDMA2000_Description_t;

typedef struct {
  uint8_t ZERO;
  uint16_t UARFCN;
  uint8_t Indic0;
  uint8_t NrOfCells;
  uint8_t BitsInCellInfo;
  uint8_t CellInfo[16]; /* bitmap compressed according to "Range 1024" algorithm (04.18/9.1.54) */
} UTRAN_FDD_NeighbourCells_t;

typedef struct {
  bool                            existBandwidth;
  uint8_t                         Bandwidth;
  uint8_t                         NrOfFrequencies;
  UTRAN_FDD_NeighbourCells_t     CellParams[8];
} UTRAN_FDD_Description_t;

typedef struct {
  uint8_t ZERO;
  uint16_t UARFCN;
  uint8_t Indic0;
  uint8_t NrOfCells;
  uint8_t BitsInCellInfo;
  uint8_t CellInfo[16]; /* bitmap compressed according to "Range 512" algorithm */
} UTRAN_TDD_NeighbourCells_t;

typedef struct {
  bool                            existBandwidth;
  uint8_t                         Bandwidth;
  uint8_t                         NrOfFrequencies;
  UTRAN_TDD_NeighbourCells_t    CellParams[8];
} UTRAN_TDD_Description_t;

typedef struct
{
  uint8_t Exist_Index_Start_3G;
  uint8_t Index_Start_3G;
  uint8_t Exist_Absolute_Index_Start_EMR;
  uint8_t Absolute_Index_Start_EMR;
  uint8_t Exist_UTRAN_FDD_Description;
  UTRAN_FDD_Description_t UTRAN_FDD_Description;
  uint8_t Exist_UTRAN_TDD_Description;
  UTRAN_TDD_Description_t UTRAN_TDD_Description;
  uint8_t Exist_CDMA2000_Description;
  CDMA2000_Description_t CDMA2000_Description;
  uint8_t Exist_Removed3GCellDescription;
  Removed3GCellDescription_t Removed3GCellDescription;
} NeighbourCellDescription3G_PMO_t;

typedef struct
{
  uint8_t Exist_Index_Start_3G;
  uint8_t Index_Start_3G;
  uint8_t Exist_Absolute_Index_Start_EMR;
  uint8_t Absolute_Index_Start_EMR;
  uint8_t Exist_UTRAN_FDD_Description;
  UTRAN_FDD_Description_t UTRAN_FDD_Description;
  uint8_t Exist_UTRAN_TDD_Description;
  UTRAN_TDD_Description_t UTRAN_TDD_Description;
  uint8_t Exist_Removed3GCellDescription;
  Removed3GCellDescription_t Removed3GCellDescription;
} NeighbourCellDescription3G_PCCO_t;

typedef struct
{
  uint8_t UnionType;
  union
  {
    BA_IND_t BA_IND;
    uint8_t PSI3_CHANGE_MARK;
  } u;

  uint8_t  PMO_IND;

  uint8_t  REPORT_TYPE;
  uint8_t  REPORTING_RATE;
  uint8_t  INVALID_BSIC_REPORTING;

  bool Exist_NeighbourCellDescription3G;
  NeighbourCellDescription3G_PMO_t NeighbourCellDescription3G;

  bool Exist_GPRSReportPriority;
  GPRSReportPriority_t GPRSReportPriority;

  bool Exist_GPRSMeasurementParams;
  GPRSMeasurementParams_PMO_PCCO_t GPRSMeasurementParams;
  bool Exist_GPRSMeasurementParams3G;
  ENH_GPRSMeasurementParams3G_PMO_t GPRSMeasurementParams3G;
} ENH_Measurement_Parameters_PMO_t;

typedef struct
{
  uint8_t UnionType;
  union
  {
    BA_IND_t BA_IND;
    uint8_t PSI3_CHANGE_MARK;
  } u;

  uint8_t  PMO_IND;

  uint8_t  REPORT_TYPE;
  uint8_t  REPORTING_RATE;
  uint8_t  INVALID_BSIC_REPORTING;

  bool Exist_NeighbourCellDescription3G;
  NeighbourCellDescription3G_PCCO_t NeighbourCellDescription3G;

  bool Exist_GPRSReportPriority;
  GPRSReportPriority_t GPRSReportPriority;

  bool Exist_GPRSMeasurementParams;
  GPRSMeasurementParams_PMO_PCCO_t GPRSMeasurementParams;
  bool Exist_GPRSMeasurementParams3G;
  ENH_GPRSMeasurementParams3G_PCCO_t GPRSMeasurementParams3G;
} ENH_Measurement_Parameters_PCCO_t;

typedef struct
{
  uint8_t UnionType;
  union
  {
    Global_TFI_t Global_TFI;
    uint32_t TLLI;
  } u;
} PacketCellChangeOrderID_t;

typedef struct
{
  uint8_t CELL_BAR_QUALIFY_3;
  uint8_t Exist_SI13_Alt_PBCCH_Location;
  SI13_PBCCH_Location_t SI13_Alt_PBCCH_Location;
} lu_ModeCellSelectionParameters_t;

typedef struct
{
  uint8_t Exist_lu_ModeCellSelectionParams;
  lu_ModeCellSelectionParameters_t lu_ModeCellSelectionParameters;
} lu_ModeCellSelectionParams_t;

typedef struct
{
  lu_ModeCellSelectionParams_t lu_ModeCellSelectionParameters;
  uint8_t NR_OF_FREQUENCIES;
  lu_ModeCellSelectionParams_t lu_ModeCellSelectionParams[32];
} lu_ModeNeighbourCellParams_t;

typedef struct
{
  uint8_t CELL_BAR_QUALIFY_3;
  uint8_t SAME_RA_AS_SERVING_CELL;

  uint8_t Exist_RXLEV_and_TXPWR;
  uint8_t GPRS_RXLEV_ACCESS_MIN;
  uint8_t GPRS_MS_TXPWR_MAX_CCH;

  uint8_t Exist_OFFSET_and_TIME;
  uint8_t GPRS_TEMPORARY_OFFSET;
  uint8_t GPRS_PENALTY_TIME;

  uint8_t Exist_GPRS_RESELECT_OFFSET;
  uint8_t GPRS_RESELECT_OFFSET;

  uint8_t Exist_HCS;
  HCS_t HCS;

  uint8_t Exist_SI13_Alt_PBCCH_Location;
  SI13_PBCCH_Location_t SI13_Alt_PBCCH_Location;
} lu_ModeOnlyCellSelection_t;

typedef struct
{
  uint8_t FREQ_DIFF_LENGTH;
  uint8_t FREQUENCY_DIFF;
  uint8_t BSIC;

  bool Exist_lu_ModeOnlyCellSelectionParams;
  lu_ModeOnlyCellSelection_t lu_ModeOnlyCellSelectionParams;
} lu_ModeOnlyCellSelectionParamsWithFreqDiff_t;

typedef struct
{
  uint16_t START_FREQUENCY;
  uint8_t BSIC;

  uint8_t Exist_lu_ModeCellSelection;
  lu_ModeOnlyCellSelection_t lu_ModeOnlyCellSelection;

  uint8_t NR_OF_FREQUENCIES;
  uint8_t FREQ_DIFF_LENGTH;

  lu_ModeOnlyCellSelectionParamsWithFreqDiff_t lu_ModeOnlyCellSelectionParamsWithFreqDiff[32];
} Add_lu_ModeOnlyFrequencyList_t;

typedef struct
{
  uint8_t Count_Add_lu_ModeOnlyFrequencyList;
  Add_lu_ModeOnlyFrequencyList_t Add_lu_ModeOnlyFrequencyList[32];
} NC_lu_ModeOnlyCapableCellList_t;


typedef struct
{
  uint8_t                  NumberOfFrequencyIndexes;
  uint8_t                  UTRAN_FREQUENCY_INDEX_a[18];

  bool                     existUTRAN_PRIORITY;
  uint8_t                  UTRAN_PRIORITY;

  uint8_t                  THRESH_UTRAN_high;

  bool                     existTHRESH_UTRAN_low;
  uint8_t                  THRESH_UTRAN_low;

  bool                     existUTRAN_QRXLEVMIN;
  uint8_t                  UTRAN_QRXLEVMIN;
} RepeatedUTRAN_PriorityParameters_t;

typedef struct
{
  bool                                existDEFAULT_UTRAN_Parameters;
  uint8_t                             DEFAULT_UTRAN_PRIORITY;
  uint8_t                             DEFAULT_THRESH_UTRAN;
  uint8_t                             DEFAULT_UTRAN_QRXLEVMIN;

  uint8_t                             NumberOfPriorityParameters;
  RepeatedUTRAN_PriorityParameters_t  RepeatedUTRAN_PriorityParameters_a[8];
} PriorityParametersDescription3G_PMO_t;

typedef struct
{
  bool existEUTRAN_FDD_REPORTING_THRESHOLD_OFFSET;
  uint8_t  EUTRAN_FDD_REPORTING_THRESHOLD;
  bool existEUTRAN_FDD_REPORTING_THRESHOLD_2;
  uint8_t  EUTRAN_FDD_REPORTING_THRESHOLD_2;
  bool existEUTRAN_FDD_REPORTING_OFFSET;
  uint8_t  EUTRAN_FDD_REPORTING_OFFSET;

  bool existEUTRAN_TDD_REPORTING_THRESHOLD_OFFSET;
  uint8_t  EUTRAN_TDD_REPORTING_THRESHOLD;
  bool existEUTRAN_TDD_REPORTING_THRESHOLD_2;
  uint8_t  EUTRAN_TDD_REPORTING_THRESHOLD_2;
  bool existEUTRAN_TDD_REPORTING_OFFSET;
  uint8_t  EUTRAN_TDD_REPORTING_OFFSET;
} EUTRAN_REPORTING_THRESHOLD_OFFSET_t;

typedef struct
{
  uint8_t                              Qsearch_P_EUTRAN;
  uint8_t                              EUTRAN_REP_QUANT;
  uint8_t                              EUTRAN_MULTIRAT_REPORTING;
  EUTRAN_REPORTING_THRESHOLD_OFFSET_t EUTRAN_REPORTING_THRESHOLD_OFFSET;
} GPRS_EUTRAN_MeasurementParametersDescription_t;

typedef struct
{
  uint16_t EARFCN;
  bool existMeasurementBandwidth;
  uint8_t  MeasurementBandwidth;
} RepeatedEUTRAN_Cells_t;

typedef struct
{
  uint8_t                  nbrOfEUTRAN_Cells;
  RepeatedEUTRAN_Cells_t  EUTRAN_Cells_a[6];

  bool                     existEUTRAN_PRIORITY;
  uint8_t                  EUTRAN_PRIORITY;

  uint8_t                  THRESH_EUTRAN_high;

  bool                     existTHRESH_EUTRAN_low;
  uint8_t                  THRESH_EUTRAN_low;

  bool                     existEUTRAN_QRXLEVMIN;
  uint8_t                  EUTRAN_QRXLEVMIN;
} RepeatedEUTRAN_NeighbourCells_t;

typedef struct
{
  uint16_t PCID;
} PCID_t;

typedef struct
{
  uint8_t PCID_Pattern_length;
  uint8_t PCID_Pattern;
  uint8_t PCID_Pattern_sense;
} PCID_Pattern_t;

typedef struct
{
  uint8_t         NumberOfPCIDs;
  uint16_t        PCID_a[11];

  bool            existPCID_BITMAP_GROUP;
  uint8_t         PCID_BITMAP_GROUP;

  uint8_t         NumberOfPCID_Patterns;
  PCID_Pattern_t PCID_Pattern_a[19];
} PCID_Group_IE_t;

typedef struct
{
  uint8_t EUTRAN_FREQUENCY_INDEX;
} EUTRAN_FREQUENCY_INDEX_t;

typedef struct
{
  PCID_Group_IE_t          NotAllowedCells;
  uint8_t                   NumberOfFrequencyIndexes;
  EUTRAN_FREQUENCY_INDEX_t EUTRAN_FREQUENCY_INDEX_a[28];
} RepeatedEUTRAN_NotAllowedCells_t;

typedef struct
{
  uint8_t                   NumberOfMappings;
  PCID_Group_IE_t          PCID_ToTA_Mapping_a[14];

  uint8_t                   NumberOfFrequencyIndexes;
  EUTRAN_FREQUENCY_INDEX_t EUTRAN_FREQUENCY_INDEX_a[28];
} RepeatedEUTRAN_PCID_to_TA_mapping_t;

typedef struct
{
  uint8_t EUTRAN_CCN_ACTIVE;

  bool                                           existGPRS_EUTRAN_MeasurementParametersDescription;
  GPRS_EUTRAN_MeasurementParametersDescription_t GPRS_EUTRAN_MeasurementParametersDescription;

  uint8_t                                        nbrOfRepeatedEUTRAN_NeighbourCellsStructs;
  RepeatedEUTRAN_NeighbourCells_t                RepeatedEUTRAN_NeighbourCells_a[4];

  uint8_t                                        NumberOfNotAllowedCells;
  RepeatedEUTRAN_NotAllowedCells_t               RepeatedEUTRAN_NotAllowedCells_a[14];

  uint8_t                                        NumberOfMappings;
  RepeatedEUTRAN_PCID_to_TA_mapping_t            RepeatedEUTRAN_PCID_to_TA_mapping_a[19];
} EUTRAN_ParametersDescription_PMO_t;

typedef struct
{
  uint8_t GERAN_PRIORITY;
  uint8_t THRESH_Priority_Search;
  uint8_t THRESH_GSM_low;
  uint8_t H_PRIO;
  uint8_t T_Reselection;
} ServingCellPriorityParametersDescription_t;

typedef struct
{
  bool                                       existServingCellPriorityParametersDescription;
  ServingCellPriorityParametersDescription_t ServingCellPriorityParametersDescription;

  bool                                       existPriorityParametersDescription3G_PMO;
  PriorityParametersDescription3G_PMO_t      PriorityParametersDescription3G_PMO;

  bool                                       existEUTRAN_ParametersDescription_PMO;
  EUTRAN_ParametersDescription_PMO_t         EUTRAN_ParametersDescription_PMO;
} PriorityAndEUTRAN_ParametersDescription_PMO_t;

typedef struct
{
  uint8_t PSC_Pattern_length;
  uint8_t PSC_Pattern;
  bool PSC_Pattern_sense;
} PSC_Pattern_t;

typedef struct
{
  uint8_t PSC_Count;
  uint16_t PSC[32];
  uint8_t PSC_Pattern_Count;
  PSC_Pattern_t PSC_Pattern[32];
} PSC_Group_t;

typedef struct
{
  PSC_Group_t CSG_PSC_SPLIT;
  uint8_t     Count;
  uint8_t     UTRAN_FREQUENCY_INDEX[32];
} ThreeG_CSG_Description_Body_t;

typedef struct
{
  uint8_t Count;
  ThreeG_CSG_Description_Body_t  ThreeG_CSG_Description_Body[32];
} ThreeG_CSG_Description_t;

typedef struct
{
  PSC_Group_t CSG_PCI_SPLIT;
  uint8_t Count;
  uint8_t EUTRAN_FREQUENCY_INDEX[32];
} EUTRAN_CSG_Description_Body_t;

typedef struct
{
  uint8_t Count;
  EUTRAN_CSG_Description_Body_t EUTRAN_CSG_Description_Body[32];
} EUTRAN_CSG_Description_t;

typedef struct
{
  bool      existMeasurement_Control_EUTRAN;
  bool      Measurement_Control_EUTRAN;
  uint8_t   EUTRAN_FREQUENCY_INDEX_top;
  uint8_t   Count_EUTRAN_FREQUENCY_INDEX;
  uint8_t   EUTRAN_FREQUENCY_INDEX[32];

  bool      existMeasurement_Control_UTRAN;
  bool      Measurement_Control_UTRAN;
  uint8_t   UTRAN_FREQUENCY_INDEX_top;
  uint8_t   Count_UTRAN_FREQUENCY_INDEX;
  uint8_t   UTRAN_FREQUENCY_INDEX[32];
} Meas_Ctrl_Param_Desp_t;

typedef struct
{
  uint8_t   THRESH_EUTRAN_high_Q;
  bool existTHRESH_EUTRAN_low_Q;
  uint8_t   THRESH_EUTRAN_low_Q;
  bool existEUTRAN_QQUALMIN;
  uint8_t   EUTRAN_QQUALMIN;
  bool existEUTRAN_RSRPmin;
  uint8_t   EUTRAN_RSRPmin;
} Reselection_Based_On_RSRQ_t;

typedef struct
{
  uint8_t Count_EUTRAN_FREQUENCY_INDEX;
  uint8_t EUTRAN_FREQUENCY_INDEX[32];
  uint8_t UnionType;
  union
  {
    uint8_t          EUTRAN_Qmin;
    Reselection_Based_On_RSRQ_t Reselection_Based_On_RSRQ;
  } u;
} Rept_EUTRAN_Enh_Cell_Resel_Param_t;

typedef struct
{
  uint8_t                            Count;
  Rept_EUTRAN_Enh_Cell_Resel_Param_t  Repeated_EUTRAN_Enhanced_Cell_Reselection_Parameters[32];
} Enh_Cell_Reselect_Param_Desp_t;

typedef struct
{
  bool      existUTRAN_CSG_FDD_REPORTING_THRESHOLD;
  uint8_t    UTRAN_CSG_FDD_REPORTING_THRESHOLD;
  uint8_t    UTRAN_CSG_FDD_REPORTING_THRESHOLD_2;
  bool      existUTRAN_CSG_TDD_REPORTING_THRESHOLD;
  uint8_t    UTRAN_CSG_TDD_REPORTING_THRESHOLD;
} UTRAN_CSG_Cells_Reporting_Desp_t;

typedef struct
{
  bool      existEUTRAN_CSG_FDD_REPORTING_THRESHOLD;
  uint8_t    EUTRAN_CSG_FDD_REPORTING_THRESHOLD;
  uint8_t    EUTRAN_CSG_FDD_REPORTING_THRESHOLD_2;
  bool      existEUTRAN_CSG_TDD_REPORTING_THRESHOLD;
  uint8_t    EUTRAN_CSG_TDD_REPORTING_THRESHOLD;
  uint8_t    EUTRAN_CSG_TDD_REPORTING_THRESHOLD_2;
} EUTRAN_CSG_Cells_Reporting_Desp_t;

typedef struct
{
  bool                              existUTRAN_CSG_Cells_Reporting_Description;
  UTRAN_CSG_Cells_Reporting_Desp_t   UTRAN_CSG_Cells_Reporting_Description;
  bool                              existEUTRAN_CSG_Cells_Reporting_Description;
  EUTRAN_CSG_Cells_Reporting_Desp_t  EUTRAN_CSG_Cells_Reporting_Description;
} CSG_Cells_Reporting_Desp_t;

typedef struct
{
  bool                           existEnhanced_Cell_Reselection_Parameters_Description;
  Enh_Cell_Reselect_Param_Desp_t  Enhanced_Cell_Reselection_Parameters_Description;

  bool                           existCSG_Cells_Reporting_Description;
  CSG_Cells_Reporting_Desp_t      CSG_Cells_Reporting_Description;
} PMO_AdditionsR9_t;

typedef struct
{
  uint8_t dummy;
} Delete_All_Stored_Individual_Priorities_t;

typedef struct
{
  uint8_t Count;
  uint16_t FDD_ARFCN[32];
} Individual_UTRAN_Priority_FDD_t;

typedef struct
{
  uint8_t Count;
  uint16_t TDD_ARFCN[32];
} Individual_UTRAN_Priority_TDD_t;

typedef struct
{
  uint8_t UnionType;
  union
  {
    Individual_UTRAN_Priority_FDD_t Individual_UTRAN_Priority_FDD;
    Individual_UTRAN_Priority_TDD_t Individual_UTRAN_Priority_TDD;
  } u;
  uint8_t UTRAN_PRIORITY;
} Repeated_Individual_UTRAN_Priority_Parameters_t;

typedef struct
{
  uint8_t Exist_DEFAULT_UTRAN_PRIORITY;
  uint8_t DEFAULT_UTRAN_PRIORITY;
  uint8_t Repeated_Individual_UTRAN_Priority_Parameters_Count;
  Repeated_Individual_UTRAN_Priority_Parameters_t Repeated_Individual_UTRAN_Priority_Parameters[32];
} ThreeG_Individual_Priority_Parameters_Description_t;

typedef struct
{
  uint8_t Count;
  uint16_t EARFCN[32];
  uint8_t EUTRAN_PRIORITY;
} Repeated_Individual_EUTRAN_Priority_Parameters_t;

typedef struct
{
  uint8_t Exist_DEFAULT_EUTRAN_PRIORITY;
  uint8_t DEFAULT_EUTRAN_PRIORITY;
  uint8_t Count;
  Repeated_Individual_EUTRAN_Priority_Parameters_t Repeated_Individual_EUTRAN_Priority_Parameters[32];
} EUTRAN_Individual_Priority_Parameters_Description_t;

typedef struct
{
  uint8_t GERAN_PRIORITY;
  uint8_t Exist_3G_Individual_Priority_Parameters_Description;
  ThreeG_Individual_Priority_Parameters_Description_t ThreeG_Individual_Priority_Parameters_Description;
  uint8_t Exist_EUTRAN_Individual_Priority_Parameters_Description;
  EUTRAN_Individual_Priority_Parameters_Description_t EUTRAN_Individual_Priority_Parameters_Description;
  uint8_t Exist_T3230_timeout_value;
  uint8_t T3230_timeout_value;
} Provide_Individual_Priorities_t;

typedef struct
{
  uint8_t UnionType;
  union
  {
    Delete_All_Stored_Individual_Priorities_t Delete_All_Stored_Individual_Priorities;
    Provide_Individual_Priorities_t Provide_Individual_Priorities;
  } u;
} Individual_Priorities_t;

typedef struct
{
  bool              existBA_IND_3G_PMO_IND;
  uint8_t           BA_IND_3G;
  uint8_t           PMO_IND;

  bool              existPriorityAndEUTRAN_ParametersDescription_PMO;
  PriorityAndEUTRAN_ParametersDescription_PMO_t PriorityAndEUTRAN_ParametersDescription_PMO;

  bool              existIndividualPriorities_PMO;
  Individual_Priorities_t  IndividualPriorities_PMO;

  bool              existThreeG_CSG_Description;
  ThreeG_CSG_Description_t  ThreeG_CSG_Description_PMO;

  bool              existEUTRAN_CSG_Description;
  EUTRAN_CSG_Description_t  EUTRAN_CSG_Description_PMO;

  bool              existMeasurement_Control_Parameters_Description;
  Meas_Ctrl_Param_Desp_t Measurement_Control_Parameters_Description_PMO;

  bool              existAdditionsR9;
  PMO_AdditionsR9_t AdditionsR9;
} PMO_AdditionsR8_t;

typedef struct
{
  bool              existREPORTING_OFFSET_THRESHOLD_700;
  uint8_t           REPORTING_OFFSET_700;
  uint8_t           REPORTING_THRESHOLD_700;

  bool              existREPORTING_OFFSET_THRESHOLD_810;
  uint8_t           REPORTING_OFFSET_810;
  uint8_t           REPORTING_THRESHOLD_810;

  uint8_t existAdditionsR8;
  PMO_AdditionsR8_t additionsR8;
} PMO_AdditionsR7_t;

typedef struct
{
  uint8_t CCN_ACTIVE_3G;
  uint8_t existAdditionsR7;
  PMO_AdditionsR7_t additionsR7;
} PMO_AdditionsR6_t;

typedef struct
{
  uint8_t CCN_ACTIVE_3G;
} PCCO_AdditionsR6_t;

typedef struct
{
  uint8_t existGRNTI_Extension;
  uint8_t GRNTI;
  uint8_t exist_lu_ModeNeighbourCellParams;
  uint8_t count_lu_ModeNeighbourCellParams;
  lu_ModeNeighbourCellParams_t lu_ModeNeighbourCellParams[32];
  uint8_t existNC_lu_ModeOnlyCapableCellList;
  NC_lu_ModeOnlyCapableCellList_t NC_lu_ModeOnlyCapableCellList;
  uint8_t existGPRS_AdditionalMeasurementParams3G;
  GPRS_AdditionalMeasurementParams3G_t GPRS_AdditionalMeasurementParams3G;
  uint8_t existAdditionsR6;
  PMO_AdditionsR6_t additionsR6;
} PMO_AdditionsR5_t;

typedef struct
{
  uint8_t existGRNTI_Extension;
  uint8_t GRNTI;
  uint8_t exist_lu_ModeNeighbourCellParams;
  uint8_t count_lu_ModeNeighbourCellParams;
  lu_ModeNeighbourCellParams_t lu_ModeNeighbourCellParams[32];
  uint8_t existNC_lu_ModeOnlyCapableCellList;
  NC_lu_ModeOnlyCapableCellList_t NC_lu_ModeOnlyCapableCellList;
  uint8_t existGPRS_AdditionalMeasurementParams3G;
  GPRS_AdditionalMeasurementParams3G_t GPRS_AdditionalMeasurementParams3G;
  uint8_t existAdditionsR6;
  PCCO_AdditionsR6_t additionsR6;
} PCCO_AdditionsR5_t;

typedef struct
{
  uint8_t CCN_ACTIVE;
  uint8_t Exist_CCN_Support_Description_ID;
  CCN_Support_Description_t CCN_Support_Description;
  uint8_t Exist_AdditionsR5;
  PMO_AdditionsR5_t AdditionsR5;
} PMO_AdditionsR4_t;

typedef struct
{
  uint8_t CCN_ACTIVE;
  uint8_t Exist_Container_ID;
  uint8_t CONTAINER_ID;
  uint8_t Exist_CCN_Support_Description_ID;
  CCN_Support_Description_t CCN_Support_Description;
  uint8_t Exist_AdditionsR5;
  PCCO_AdditionsR5_t AdditionsR5;
} PCCO_AdditionsR4_t;

typedef struct
{
  ENH_Measurement_Parameters_PCCO_t ENH_Measurement_Parameters;
  uint8_t Exist_AdditionsR4;
  PCCO_AdditionsR4_t AdditionsR4;
} PCCO_AdditionsR99_t;

typedef struct
{
  uint8_t Exist_ENH_Measurement_Parameters;
  ENH_Measurement_Parameters_PMO_t ENH_Measurement_Parameters;
  uint8_t Exist_AdditionsR4;
  PMO_AdditionsR4_t AdditionsR4;
} PMO_AdditionsR99_t;

typedef struct
{
  uint8_t Exist_LSA_Parameters;
  LSA_Parameters_t LSA_Parameters;

  uint8_t Exist_AdditionsR99;
  PMO_AdditionsR99_t AdditionsR99;
} PMO_AdditionsR98_t;

typedef struct
{
  uint8_t Exist_LSA_Parameters;
  LSA_Parameters_t LSA_Parameters;

  uint8_t Exist_AdditionsR99;
  PCCO_AdditionsR99_t AdditionsR99;
} PCCO_AdditionsR98_t;

typedef struct
{
  uint8_t IMMEDIATE_REL;
  uint16_t ARFCN;
  uint8_t BSIC;
  NC_Measurement_Parameters_with_Frequency_List_t NC_Measurement_Parameters;

  uint8_t Exist_AdditionsR98;
  PCCO_AdditionsR98_t AdditionsR98;
} Target_Cell_GSM_t;

typedef struct
{
  uint8_t Exist_EUTRAN_Target_Cell;
  EUTRAN_Target_Cell_t EUTRAN_Target_Cell;
  uint8_t Exist_Individual_Priorities;
  Individual_Priorities_t Individual_Priorities;
} Target_Cell_3G_AdditionsR8_t;

typedef struct
{
  uint8_t Exist_G_RNTI_Extention;
  uint8_t G_RNTI_Extention;
  uint8_t Exist_AdditionsR8;
  Target_Cell_3G_AdditionsR8_t AdditionsR8;
} Target_Cell_3G_AdditionsR5_t;

typedef struct
{
  /* 00 -- Message escape */
  uint8_t IMMEDIATE_REL;
  uint8_t Exist_FDD_Description;
  FDD_Target_Cell_t FDD_Target_Cell;
  uint8_t Exist_TDD_Description;
  TDD_Target_Cell_t TDD_Target_Cell;
  uint8_t Exist_AdditionsR5;
  Target_Cell_3G_AdditionsR5_t AdditionsR5;
} Target_Cell_3G_t;

#if 0
#define TARGET_CELL_GSM 0
#define TARGET_CELL_3G 1
#endif

typedef struct
{
  uint8_t MESSAGE_TYPE;
  uint8_t PAGE_MODE;

  PacketCellChangeOrderID_t ID;

  uint8_t UnionType;
  union
  {
    Target_Cell_GSM_t Target_Cell_GSM;
    Target_Cell_3G_t Target_Cell_3G;
  } u;

} Packet_Cell_Change_Order_t;

/* < Packet Cell Change Continue message contents > */
typedef struct
{
  uint8_t MESSAGE_TYPE;
  uint8_t PAGE_MODE;

  Global_TFI_t Global_TFI;
  uint8_t Exist_ID;
  uint16_t ARFCN;
  uint8_t BSIC;
  uint8_t CONTAINER_ID;
} Packet_Cell_Change_Continue_t;


/* < Packet Neighbour Cell Data message contents > */
typedef struct
{
  uint16_t ARFCN;
  uint8_t BSIC;
  uint8_t CONTAINER[17];     /* PD (3 bits) + CD_LENGTH (5 bits) + 16 bytes of CONTAINER_DATA (max!) */
} PNCD_Container_With_ID_t;

typedef struct
{
  uint8_t CONTAINER[19];     /* PD (3 bits) + CD_LENGTH (5 bits) + 18 bytes of CONTAINER_DATA (max!) */
} PNCD_Container_Without_ID_t;

typedef struct
{
  uint8_t UnionType;
  union
  {
    PNCD_Container_Without_ID_t PNCD_Container_Without_ID;
    PNCD_Container_With_ID_t PNCD_Container_With_ID;
  } u;
} PNCDContainer_t;

typedef struct
{
  uint8_t MESSAGE_TYPE;
  uint8_t PAGE_MODE;
  /* Fixed 0 */
  Global_TFI_t Global_TFI;
  uint8_t CONTAINER_ID;
  uint8_t spare;
  uint8_t CONTAINER_INDEX;

  PNCDContainer_t Container;
} Packet_Neighbour_Cell_Data_t;

/* < Packet Serving Cell Data message contents > */
typedef struct
{
  uint8_t MESSAGE_TYPE;
  uint8_t PAGE_MODE;
  /* Fixed 0 */
  Global_TFI_t Global_TFI;
  uint8_t spare;
  uint8_t CONTAINER_INDEX;
  uint8_t CONTAINER[19];     /* PD (3 bits) + CD_LENGTH (5 bits) + 18 bytes of CONTAINER_DATA (max!) */
} Packet_Serving_Cell_Data_t;

/* < Packet Measurement Order message contents > */
typedef struct
{
  uint16_t START_FREQUENCY;
  uint8_t NR_OF_FREQUENCIES;
  uint8_t FREQ_DIFF_LENGTH;

  uint8_t Count_FREQUENCY_DIFF;
  uint8_t FREQUENCY_DIFF[31];/* bit (FREQ_DIFF_LENGTH) * NR_OF_FREQUENCIES --> MAX is bit(7) * 31 */
} EXT_Frequency_List_t;

typedef struct
{
  uint8_t MESSAGE_TYPE;
  uint8_t PAGE_MODE;

  PacketDownlinkID_t ID; /* use the PDA ID as it is the same as the PMO */

  uint8_t PMO_INDEX;
  uint8_t PMO_COUNT;

  uint8_t Exist_NC_Measurement_Parameters;
  NC_Measurement_Parameters_with_Frequency_List_t NC_Measurement_Parameters;

  uint8_t Exist_EXT_Measurement_Parameters;

  uint8_t Exist_AdditionsR98;
  PMO_AdditionsR98_t AdditionsR98;
} Packet_Measurement_Order_t;

/* Enhanced measurement report */

typedef struct
{
  uint8_t  RXLEV_SERVING_CELL;
} ServingCellData_t;

typedef struct
{
  uint8_t  BCCH_FREQ_NCELL;
  uint8_t  BSIC;
  uint8_t  RXLEV_NCELL;
} Repeated_Invalid_BSIC_Info_t;

typedef struct
{
  bool Exist_REPORTING_QUANTITY;
  uint8_t  REPORTING_QUANTITY;
} REPORTING_QUANTITY_t;

typedef struct
{
  uint8_t               NC_MODE;
  uint8_t UnionType;
  union
  {
    BA_USED_t           BA_USED;
    uint8_t             PSI3_CHANGE_MARK;
  } u;
  uint8_t PMO_USED;
  uint8_t SCALE;
  uint8_t Exist_ServingCellData;
  ServingCellData_t   ServingCellData;
  uint8_t  Count_Repeated_Invalid_BSIC_Info;
  Repeated_Invalid_BSIC_Info_t Repeated_Invalid_BSIC_Info[32];

  bool Exist_Repeated_REPORTING_QUANTITY;
  uint8_t  Count_Repeated_Reporting_Quantity;
  REPORTING_QUANTITY_t   Repeated_REPORTING_QUANTITY[96];
} NC_MeasurementReport_t;

/* Packet Handover  PHO ----------------- */

typedef struct
{
  uint8_t UnionType;
  union
  {
    uint8_t MS_TimeslotAllocation;
    Power_Control_Parameters_t Power_Control_Parameters;
  } u;
} GlobalTimeslotDescription_t;

typedef struct
{
  uint8_t TimeslotAllocation;
  uint8_t PFI;
  uint8_t RLC_Mode;
  uint8_t TFI_Assignment;
  uint8_t ControlACK;
  uint8_t Exist_EGPRS_WindowSize;
  uint8_t EGPRS_WindowSize;
} PHO_DownlinkAssignment_t;

typedef struct
{
  bool Exist_USF;
  uint8_t USF;
} PHO_USF_1_7_t;

typedef struct
{
  uint8_t USF_0;
  PHO_USF_1_7_t USF_1_7[7];
  uint8_t NBR_OfAllocatedTimeslots;
} USF_AllocationArray_t;

typedef struct
{
  uint8_t PFI;
  uint8_t RLC_Mode;
  uint8_t TFI_Assignment;
  uint8_t Exist_ChannelCodingCommand;
  uint8_t ChannelCodingCommand;
  uint8_t Exist_EGPRS_ChannelCodingCommand;
  uint8_t EGPRS_ChannelCodingCommand;
  uint8_t Exist_EGPRS_WindowSize;
  uint8_t EGPRS_WindowSize;
  uint8_t USF_Granularity;
  uint8_t Exist_TBF_TimeslotAllocation;
  uint8_t TBF_TimeslotAllocation;
  uint8_t UnionType;
  union
  {
    uint8_t USF_SingleAllocation;
    USF_AllocationArray_t USF_AllocationArray;
  } u;
} PHO_UplinkAssignment_t;

typedef struct
{
  GlobalTimeslotDescription_t GlobalTimeslotDescription;
  uint8_t Exist_PHO_UA;
  PHO_UplinkAssignment_t PHO_UA;
} GlobalTimeslotDescription_UA_t;

typedef struct
{
  uint8_t Exist_ChannelCodingCommand;
  uint8_t ChannelCodingCommand;
  uint8_t Exist_GlobalTimeslotDescription_UA;
  GlobalTimeslotDescription_UA_t GTD_UA;
  uint8_t Exist_DownlinkAssignment;
  PHO_DownlinkAssignment_t DownlinkAssignment;
} PHO_GPRS_t;


typedef struct
{
  uint8_t Exist_EGPRS_WindowSize;
  uint8_t EGPRS_WindowSize;
  uint8_t LinkQualityMeasurementMode;
  uint8_t Exist_BEP_Period2;
  uint8_t BEP_Period2;
} EGPRS_Description_t;

typedef struct
{
  uint8_t Exist_EGPRS_Description;
  EGPRS_Description_t EGPRS_Description;
  uint8_t Exist_DownlinkAssignment;
  PHO_DownlinkAssignment_t DownlinkAssignment;
} DownlinkTBF_t;

typedef struct
{
  uint8_t Exist_EGPRS_WindowSize;
  uint8_t EGPRS_WindowSize;
  uint8_t Exist_EGPRS_ChannelCodingCommand;
  uint8_t EGPRS_ChannelCodingCommand;
  uint8_t Exist_BEP_Period2;
  uint8_t BEP_Period2;
  uint8_t Exist_GlobalTimeslotDescription_UA;
  GlobalTimeslotDescription_UA_t GTD_UA;
  uint8_t Exist_DownlinkTBF;
  DownlinkTBF_t DownlinkTBF;
} PHO_EGPRS_t;

typedef struct
{
  Global_Packet_Timing_Advance_t    GlobalPacketTimingAdvance;
  uint8_t Exist_PacketExtendedTimingAdvance;
  uint8_t PacketExtendedTimingAdvance;
} PHO_TimingAdvance_t;

typedef struct
{
  uint8_t NAS_ContainerLength;
  uint8_t Spare_1a;
  uint8_t Spare_1b;
  uint8_t Spare_1c;
  uint8_t Old_XID;
  uint8_t Spare_1e;
  uint8_t Type_of_Ciphering_Algo;
  uint32_t IOV_UI_value;
} NAS_Container_For_PS_HO_t;

typedef struct
{
  uint8_t RRC_ContainerLength;
} PS_HandoverTo_UTRAN_Payload_t;

typedef struct
{
  uint8_t RRC_ContainerLength;
} PS_HandoverTo_E_UTRAN_Payload_t;

typedef struct
{
  uint8_t Exist_HandoverReference;
  uint8_t HandoverReference;
  uint8_t ARFCN;
  uint8_t SI;
  uint8_t NCI;
  uint8_t BSIC;
  uint8_t Exist_CCN_Active;
  uint8_t CCN_Active;
  uint8_t Exist_CCN_Active_3G;
  uint8_t CCN_Active_3G;
  uint8_t Exist_CCN_Support_Description;
  CCN_Support_Description_t CCN_Support_Description;
  Frequency_Parameters_t    Frequency_Parameters;
  uint8_t NetworkControlOrder;
  uint8_t Exist_PHO_TimingAdvance;
  PHO_TimingAdvance_t PHO_TimingAdvance;
  uint8_t Extended_Dynamic_Allocation;
  uint8_t RLC_Reset;
  uint8_t Exist_PO_PR;
  uint8_t PO;
  uint8_t PR_Mode;
  uint8_t Exist_UplinkControlTimeslot;
  uint8_t UplinkControlTimeslot;
  uint8_t UnionType;
  union
  {
    PHO_GPRS_t  PHO_GPRS_Mode;
    PHO_EGPRS_t PHO_EGPRS_Mode;
  } u;
} PHO_RadioResources_t;

typedef struct
{
  PHO_RadioResources_t PHO_RadioResources;
  uint8_t Exist_NAS_Container;
  NAS_Container_For_PS_HO_t NAS_Container;
} PS_HandoverTo_A_GB_ModePayload_t;

typedef struct
{
  uint8_t MessageType;
  uint8_t PageMode;
  Global_TFI_t Global_TFI;
  uint8_t ContainerID;
  uint8_t UnionType;
  union
  {
    PS_HandoverTo_A_GB_ModePayload_t PS_HandoverTo_A_GB_ModePayload;
    PS_HandoverTo_UTRAN_Payload_t    PS_HandoverTo_UTRAN_Payload;
    PS_HandoverTo_E_UTRAN_Payload_t  PS_HandoverTo_E_UTRAN_Payload;
  } u;
} Packet_Handover_Command_t;

/* End Packet Handover */

/* Packet Physical Information ----------------- */

typedef struct
{
  uint8_t MessageType;
  uint8_t PageMode;
  Global_TFI_t Global_TFI;
  uint8_t TimingAdvance;
} Packet_PhysicalInformation_t;

/* End Packet Physical Information */



/*  ADDITIONAL MS RADIO ACCESS CAPABILITIES -----------------*/
typedef struct
{
  uint8_t UnionType;
  union
  {
    Global_TFI_t Global_TFI;
    uint32_t TLLI;
  } u;
} AdditionalMsRadAccessCapID_t;


typedef struct
{
  uint8_t MESSAGE_TYPE;
  uint8_t PayloadType;
  uint8_t spare;
  uint8_t R;

  AdditionalMsRadAccessCapID_t ID;
  MS_Radio_Access_capability_t MS_Radio_Access_capability2;
} Additional_MS_Rad_Access_Cap_t;

/* End ADDITIONAL MS RADIO ACCESS CAPABILITIES */


/* Packet Pause -----------------*/

typedef struct
{
  uint8_t MESSAGE_TYPE;

  uint32_t TLLI;
  uint8_t RAI[48/8];
} Packet_Pause_t;

/* End Packet Pause */


/* < Payload Type Data MAC Header content > */
typedef struct
{
  uint8_t Payload_Type;
  uint8_t Countdown_Value;
  uint8_t SI;
  uint8_t R;
} UL_Data_Mac_Header_t;

typedef struct
{
  UL_Data_Mac_Header_t UL_Data_Mac_Header;
  uint8_t Spare;
  uint8_t PI;
  uint8_t TFI;
  uint8_t TI;
  uint8_t BSN;
  uint8_t E;
} UL_Data_Block_GPRS_t;

typedef struct
{
   uint8_t MESSAGE_TYPE;
   uint8_t CTRL_ACK;
}UL_Packet_Control_Ack_11_t;

typedef struct
{
   uint8_t MESSAGE_TYPE;
   uint8_t TN_RRBP;
   uint8_t CTRL_ACK;
}UL_Packet_Control_Ack_TN_RRBP_11_t;

typedef struct
{
   uint8_t MESSAGE_TYPE;
   uint8_t CTRL_ACK;
}UL_Packet_Control_Ack_8_t;

typedef struct
{
   uint8_t MESSAGE_TYPE;
   uint8_t TN_RRBP;
   uint8_t CTRL_ACK;
}UL_Packet_Control_Ack_TN_RRBP_8_t;

typedef struct
{
  uint8_t Payload_Type;
  uint8_t RRBP;
  uint8_t S_P;
  uint8_t USF;
} DL_Data_Mac_Header_t;

typedef struct
{
  DL_Data_Mac_Header_t DL_Data_Mac_Header;
  uint8_t Power_Reduction;
  uint8_t TFI;
  uint8_t FBI;
  uint8_t BSN;
  uint8_t E;
} DL_Data_Block_GPRS_t;

typedef struct
{
  uint8_t TFI;
  uint8_t RRBP;
  uint8_t ES_P;
  uint8_t USF;
  uint16_t BSN1;
  uint16_t BSN2_offset;
  uint8_t Power_Reduction;
  uint8_t SPB;
  uint8_t CPS;
  uint8_t PI;
  uint8_t ECS_P;
  uint8_t CC;
  uint8_t SPARE1;
  uint8_t SPARE2;
  uint8_t SPARE3;
} DL_Data_Block_EGPRS_Header_t;

typedef DL_Data_Block_EGPRS_Header_t DL_Data_Block_EGPRS_Header_Type1_t;
typedef DL_Data_Block_EGPRS_Header_t DL_Data_Block_EGPRS_Header_Type2_t;
typedef DL_Data_Block_EGPRS_Header_t DL_Data_Block_EGPRS_Header_Type3_t;
typedef DL_Data_Block_EGPRS_Header_t DL_Data_Block_EC_EGPRS_Header_Type1_t;
typedef DL_Data_Block_EGPRS_Header_t DL_Data_Block_EC_EGPRS_Header_Type2_t;
typedef DL_Data_Block_EGPRS_Header_t DL_Data_Block_EC_EGPRS_Header_Type3_t;

typedef DL_Data_Block_EGPRS_Header_t DL_Data_Block_EGPRS_Header_Type1_EC_t;

typedef struct
{
  uint8_t TFI;
  uint8_t Countdown_Value;
  uint8_t SI;
  uint8_t R;
  uint16_t BSN1;
  uint16_t BSN2_offset;
  uint8_t PI;
  uint8_t RSB;
  uint8_t SPB;
  uint8_t CPS;
  uint8_t FOI;
  uint8_t RI;
  uint8_t DL_CC_EST;
  uint8_t RTLLI;
  uint8_t SPARE1;
  uint8_t SPARE2;
  uint8_t dummy;
} UL_Data_Block_EGPRS_Header_t;

typedef UL_Data_Block_EGPRS_Header_t UL_Data_Block_EGPRS_Header_Type1_t;
typedef UL_Data_Block_EGPRS_Header_t UL_Data_Block_EGPRS_Header_Type2_t;
typedef UL_Data_Block_EGPRS_Header_t UL_Data_Block_EGPRS_Header_Type3_t;
typedef UL_Data_Block_EGPRS_Header_t UL_Data_Block_EC_EGPRS_Header_Type1_t;
typedef UL_Data_Block_EGPRS_Header_t UL_Data_Block_EC_EGPRS_Header_Type2_t;
typedef UL_Data_Block_EGPRS_Header_t UL_Data_Block_EC_EGPRS_Header_Type3_t;

typedef struct
{
  uint8_t                       DOWNLINK_TFI;
  uint8_t                       Exist_Wait;
  uint8_t                       WAIT_INDICATION;
  uint8_t                       WAIT_INDICATION_SIZE;
}
EC_Reject_t;

typedef struct
{
  uint8_t                       MESSAGE_TYPE;
  uint8_t                       USED_DL_COVERAGE_CLASS;
  uint8_t                       Reject_Count;
  EC_Reject_t                   Reject[16];
}
EC_Packet_Access_Reject_t;

typedef struct
{
  uint8_t                       EC_MA_NUMBER;
  uint8_t                       TSC;
  uint8_t                       Primary_TSC_Set;
}
EC_Frequency_Parameters_t;

typedef struct {
  uint8_t                       TIMING_ADVANCE_VALUE;
} EC_Packet_Timing_Advance_t;

typedef struct
{
  uint8_t                       MESSAGE_TYPE;
  uint8_t                       USED_DL_COVERAGE_CLASS;
  Global_TFI_t                  Global_TFI;
  uint8_t                       CONTROL_ACK;

  bool                          Exist_Frequency_Parameters;
  EC_Frequency_Parameters_t     Frequency_Parameters;

  uint8_t                       DL_COVERAGE_CLASS;
  uint8_t                       STARTING_DL_TIMESLOT;
  uint8_t                       TIMESLOT_MULTIPLICATOR;
  uint8_t                       DOWNLINK_TFI_ASSIGNMENT;
  uint8_t                       UL_COVERAGE_CLASS;
  uint8_t                       STARTING_UL_TIMESLOT_OFFSET;

  bool                          Exist_EC_Packet_Timing_Advance;
  EC_Packet_Timing_Advance_t    EC_Packet_Timing_Advance;

  bool                          Exist_P0_and_PR_MODE;
  uint8_t                       P0;
  uint8_t                       PR_MODE;

  bool                          Exist_GAMMA;
  uint8_t                       GAMMA;

  uint8_t                       ALPHA_Enable;

}
EC_Packet_Downlink_Assignment_t;

typedef struct
{
  uint8_t                       MESSAGE_TYPE;
  uint8_t                       USED_DL_COVERAGE_CLASS;
  Global_TFI_t                  Global_TFI;
  uint8_t                       TYPE_OF_ACK;
}
EC_Packet_Polling_Req_t;

typedef struct
{
  uint8_t                       MESSAGE_TYPE;
  uint8_t                       USED_DL_COVERAGE_CLASS;
  Global_TFI_t                  Global_TFI;

  bool                          Exist_T_AVG_T;
  uint8_t                       T_AVG_T;

  bool                          Exist_EC_Packet_Timing_Advance;
  EC_Packet_Timing_Advance_t    EC_Packet_Timing_Advance;

  bool                          Exist_GAMMA;
  uint8_t                       GAMMA;
}
EC_Packet_Power_Control_Timing_Advance_t;

typedef struct
{
  uint8_t                       MESSAGE_TYPE;
  uint8_t                       USED_DL_COVERAGE_CLASS;
  Global_TFI_t                  Global_TFI;
  uint8_t                       TBF_RELEASE_CAUSE;

  uint8_t                       Exist_Wait;
  uint8_t                       WAIT_INDICATION;
  uint8_t                       WAIT_INDICATION_SIZE;
}
EC_Packet_Tbf_Release_t;

typedef struct{
  bool                          Exist_DELAY_NEXT_UL_RLC_DATA_BLOCK;
  uint8_t                       DELAY_NEXT_UL_RLC_DATA_BLOCK;
}
FUA_Delay_t;

typedef struct
{
  bool                          Exist_BSN_OFFSET;
  uint8_t                       BSN_OFFSET;
  uint8_t                       START_FIRST_UL_RLC_DATA_BLOCK;
  uint8_t                       Count_FUA_Delay;
  FUA_Delay_t                   FUA_Delay[16]; /* Max RLC window size */
}
PUAN_Fixed_Uplink_Allocation_t;

typedef struct{
  uint8_t                       STARTING_SEQUENCE_NUMBER;
  uint16_t                      RECEIVED_BLOCK_BITMAP;
}
EC_AckNack_Description_t;

typedef struct{
  uint8_t                       STARTING_SEQUENCE_NUMBER;
  uint8_t                       RECEIVED_BLOCK_BITMAP;
}
EC_Primary_AckNack_Description_t;

typedef struct{
  uint32_t                          CONTENTION_RESOLUTION_TLLI;
  EC_Primary_AckNack_Description_t  EC_AckNack_Description;
}
EC_Primary_AckNack_Description_TLLI_t;

typedef struct{
  uint32_t                          CONTENTION_RESOLUTION_rTLLI;
  EC_Primary_AckNack_Description_t  EC_AckNack_Description;
}
EC_Primary_AckNack_Description_rTLLI_t;

typedef struct{
  uint8_t                         EC_AckNack_Description_Type;
  union
  {
    EC_AckNack_Description_t      EC_AckNack_Description;
    EC_Primary_AckNack_Description_TLLI_t  EC_Primary_AckNack_Description_TLLI;
    EC_Primary_AckNack_Description_rTLLI_t EC_Primary_AckNack_Description_rTLLI;
  } u;

  PUAN_Fixed_Uplink_Allocation_t  PUAN_Fixed_Uplink_Allocation;
  uint8_t                       RESEGMENT;

  bool                          Exist_EGPRS_Channel_Coding_Command;
  uint8_t                       EGPRS_Channel_Coding_Command;

  bool                          Exist_CC_TS;
  uint8_t                       UL_COVERAGE_CLASS;
  uint8_t                       STARTING_UL_TIMESLOT;
  uint8_t                       DL_COVERAGE_CLASS;
  uint8_t                       STARTING_DL_TIMESLOT_OFFSET;
  uint8_t                       TIMESLOT_MULTIPLICATOR;
} EC_Packet_Uplink_Ack_Nack_fai0_t;
typedef struct{
  bool                          Exist_CONTENTION_RESOLUTION_TLLI;
  uint32_t                      CONTENTION_RESOLUTION_TLLI;

  bool                          Exist_MONITOR_EC_PACCH;
  uint8_t                       T3238;
  uint8_t                       Initial_Waiting_Time;
  uint8_t                       EC_PACCH_Monitoring_Pattern;

} EC_Packet_Uplink_Ack_Nack_fai1_t;

typedef struct
{
  uint8_t                       MESSAGE_TYPE;
  uint8_t                       USED_DL_COVERAGE_CLASS;
  uint8_t                       UPLINK_TFI;
  uint8_t                       Final_Ack_Indicator;
  union
  {
    EC_Packet_Uplink_Ack_Nack_fai0_t fai0;
    EC_Packet_Uplink_Ack_Nack_fai1_t fai1;
  } u;

  bool                          Exist_EC_Packet_Timing_Advance;
  EC_Packet_Timing_Advance_t    EC_Packet_Timing_Advance;

  bool                          Exist_GAMMA;
  uint8_t                       GAMMA;
  uint8_t                       ALPHA_Enable;
}
EC_Packet_Uplink_Ack_Nack_t;

typedef struct
{
  uint8_t                       START_FIRST_UL_RLC_DATA_BLOCK;
  uint8_t                       Count_FUA_Delay;
  FUA_Delay_t                   FUA_Delay[16]; /* Max RLC window size */
}
Fixed_Uplink_Allocation_t;

typedef struct
{
  uint8_t                       MESSAGE_TYPE;
  uint8_t                       USED_DL_COVERAGE_CLASS;
  Global_TFI_t                  Global_TFI;

  bool                          Exist_UPLINK_TFI_ASSIGNMENT;
  uint8_t                       UPLINK_TFI_ASSIGNMENT;

  bool                          Exist_EGPRS_Channel_Coding_Command;
  uint8_t                       EGPRS_Channel_Coding_Command;

  uint8_t                       Overlaid_CDMA_Code;

  bool                          Exist_EC_Packet_Timing_Advance;
  EC_Packet_Timing_Advance_t    EC_Packet_Timing_Advance;

  bool                          Exist_Frequency_Parameters;
  EC_Frequency_Parameters_t     Frequency_Parameters;

  uint8_t                       UL_COVERAGE_CLASS;
  uint8_t                       STARTING_UL_TIMESLOT;
  uint8_t                       TIMESLOT_MULTIPLICATOR;

  Fixed_Uplink_Allocation_t     Fixed_Uplink_Allocation;

  bool                          Exist_P0_and_PR_MODE;
  uint8_t                       P0;
  uint8_t                       PR_MODE;

  bool                          Exist_GAMMA;
  uint8_t                       GAMMA;
  uint8_t                       ALPHA_Enable;

  uint8_t                       DL_COVERAGE_CLASS;
  uint8_t                       STARTING_DL_TIMESLOT_OFFSET;

}
EC_Packet_Uplink_Assignment_t;

typedef struct
{
  uint8_t                          MESSAGE_TYPE;
  uint8_t                          USED_DL_COVERAGE_CLASS;
  uint8_t                          UPLINK_TFI;
  uint32_t                         CONTENTION_RESOLUTION_TLLI;
  EC_Primary_AckNack_Description_t EC_AckNack_Description;

  Fixed_Uplink_Allocation_t        PUANCR_Fixed_Uplink_Allocation;
  uint8_t                          RESEGMENT;
}
EC_Packet_Uplink_Ack_Nack_And_Contention_Resolution_t;

typedef struct
{
  uint8_t                       MESSAGE_TYPE;
  uint8_t                       USED_DL_COVERAGE_CLASS;
}
EC_Packet_Downlink_Dummy_Control_Block_t;

typedef struct
{
  uint8_t                       MESSAGE_TYPE;
  uint32_t                      TLLI;
  uint8_t                       CTRL_ACK;
  uint8_t                       DL_CC_EST;
}
EC_Packet_Control_Acknowledgement_t;

typedef struct
{
  uint8_t                       PRIORITY;
  uint8_t                       NUMBER_OF_UL_DATA_BLOCKS;
}
EC_Channel_Request_Description_t;

typedef struct
{
  bool                          Exist_GMSK;
  uint8_t                       GMSK_MEAN_BEP;
  uint8_t                       GMSK_CV_BEP;
  bool                          Exist_8PSK;
  uint8_t                       PSK_MEAN_BEP;
  uint8_t                       PSK_CV_BEP;
  uint8_t                       C_VALUE;
}
EC_Channel_Quality_Report_t;

typedef struct
{
  uint8_t                       MESSAGE_TYPE;
  uint8_t                       DOWNLINK_TFI;
  uint8_t                       MS_OUT_OF_MEMORY;
  uint8_t                       Final_Ack_Indicator;

  EC_AckNack_Description_t      EC_AckNack_Description;

  bool                          Exist_EC_Channel_Quality_Report; /* DL CC EST is also conditional on this */
  EC_Channel_Quality_Report_t   EC_Channel_Quality_Report;
  uint8_t                       DL_CC_EST;

  bool                             Exist_EC_Channel_Request_Description;
  EC_Channel_Request_Description_t EC_Channel_Request_Description;
}
EC_Packet_Downlink_Ack_Nack_t;

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

/* < Downlink EC-GSM-IoT RLC/MAC control messages > */
#define MT_EC_PACKET_ACCESS_REJECT                               0x11
#define MT_EC_PACKET_DOWNLINK_ASSIGNMENT                         0x01
#define MT_EC_PACKET_POLLING_REQ                                 0x02
#define MT_EC_PACKET_POWER_CONTROL_TIMING_ADVANCE                0x03
#define MT_EC_PACKET_TBF_RELEASE                                 0x04
#define MT_EC_PACKET_UPLINK_ACK_NACK                             0x05
#define MT_EC_PACKET_UPLINK_ASSIGNMENT                           0x06
#define MT_EC_PACKET_UPLINK_ACK_NACK_AND_CONTENTION_RESOLUTION   0x07
#define MT_EC_PACKET_DOWNLINK_DUMMY_CONTROL_BLOCK                0x12

/* < Uplink EC-GSM-IoT RLC/MAC control messages > */
#define MT_EC_PACKET_CONTROL_ACKNOWLEDGEMENT      0x01
#define MT_EC_PACKET_DOWNLINK_ACK_NACK            0x02

typedef enum
{
    RLCMAC_PRACH = 0x20,
    RLCMAC_CS1 = 0x21,
    RLCMAC_CS2 = 0x22,
    RLCMAC_CS3 = 0x23,
    RLCMAC_CS4 = 0x24,
    RLCMAC_HDR_TYPE_1 = 0x31,
    RLCMAC_HDR_TYPE_2 = 0x32,
    RLCMAC_HDR_TYPE_3 = 0x33,
    RLCMAC_HDR_TYPE_4 = 0x34,
    RLCMAC_HDR_TYPE_5 = 0x35,
    RLCMAC_HDR_TYPE_6 = 0x36,
    RLCMAC_HDR_TYPE_7 = 0x37,
    RLCMAC_HDR_TYPE_8 = 0x38,
    RLCMAC_HDR_TYPE_9 = 0x39,
    RLCMAC_HDR_TYPE_10 = 0x3a,
    RLCMAC_EC_CS1 = 0x40,
    RLCMAC_HDR_TYPE_1_EC   = 0x41,
    RLCMAC_HDR_TYPE_2_EC   = 0x42,
    RLCMAC_HDR_TYPE_3_EC   = 0x43
}RLCMAC_block_format_t;

/* < Downlink RLC/MAC control message > */
typedef struct
{
  union
  {
    uint8_t                                  MESSAGE_TYPE;
    DL_Data_Block_GPRS_t                     DL_Data_Block_GPRS;
    DL_Data_Block_EGPRS_Header_t             DL_Data_Block_EGPRS_Header;
    Packet_Access_Reject_t                   Packet_Access_Reject;
    Packet_Cell_Change_Order_t               Packet_Cell_Change_Order;
    Packet_Cell_Change_Continue_t            Packet_Cell_Change_Continue;
    Packet_Downlink_Assignment_t             Packet_Downlink_Assignment;
    Packet_Measurement_Order_t               Packet_Measurement_Order;
    Packet_Neighbour_Cell_Data_t             Packet_Neighbour_Cell_Data;
    Packet_Serving_Cell_Data_t               Packet_Serving_Cell_Data;
    Packet_Paging_Request_t                  Packet_Paging_Request;
    Packet_PDCH_Release_t                    Packet_PDCH_Release;
    Packet_Polling_Request_t                 Packet_Polling_Request;
    Packet_Power_Control_Timing_Advance_t    Packet_Power_Control_Timing_Advance;
    Packet_PRACH_Parameters_t                Packet_PRACH_Parameters;
    Packet_Queueing_Notification_t           Packet_Queueing_Notification;
    Packet_Timeslot_Reconfigure_t            Packet_Timeslot_Reconfigure;
    Packet_TBF_Release_t                     Packet_TBF_Release;
    Packet_Uplink_Ack_Nack_t                 Packet_Uplink_Ack_Nack;
    Packet_Uplink_Assignment_t               Packet_Uplink_Assignment;
    Packet_Handover_Command_t                Packet_Handover_Command;
    Packet_PhysicalInformation_t             Packet_PhysicalInformation;
    Packet_Downlink_Dummy_Control_Block_t    Packet_Downlink_Dummy_Control_Block;
    PSI1_t                                   PSI1;
    PSI2_t                                   PSI2;
    PSI3_t                                   PSI3;
    PSI5_t                                   PSI5;
    PSI13_t                                  PSI13;
    EC_Packet_Access_Reject_t                EC_Packet_Access_Reject;
    EC_Packet_Downlink_Assignment_t          EC_Packet_Downlink_Assignment;
    EC_Packet_Polling_Req_t                  EC_Packet_Polling_Req;
    EC_Packet_Power_Control_Timing_Advance_t EC_Packet_Power_Control_Timing_Advance;
    EC_Packet_Tbf_Release_t                  EC_Packet_Tbf_Release;
    EC_Packet_Uplink_Ack_Nack_t              EC_Packet_Uplink_Ack_Nack;
    EC_Packet_Uplink_Assignment_t            EC_Packet_Uplink_Assignment;
    EC_Packet_Uplink_Ack_Nack_And_Contention_Resolution_t EC_Packet_Uplink_Ack_Nack_And_Contention_Resolution;
    EC_Packet_Downlink_Dummy_Control_Block_t EC_Packet_Downlink_Dummy_Control_Block;
  } u;

  RLCMAC_block_format_t block_format;
  unsigned         flags;
} RlcMacDownlink_t;

typedef int16_t MSGGPRS_Status_t;
/* < Uplink RLC/MAC control message > */
typedef struct
{
  union
  {
    uint8_t MESSAGE_TYPE;
    Packet_Cell_Change_Failure_t          Packet_Cell_Change_Failure;
    Packet_Control_Acknowledgement_t      Packet_Control_Acknowledgement;
    Packet_Downlink_Ack_Nack_t            Packet_Downlink_Ack_Nack;
    Packet_Uplink_Dummy_Control_Block_t   Packet_Uplink_Dummy_Control_Block;
    Packet_Measurement_Report_t           Packet_Measurement_Report;
    Packet_Resource_Request_t             Packet_Resource_Request;
    Packet_Mobile_TBF_Status_t            Packet_Mobile_TBF_Status;
    Packet_PSI_Status_t                   Packet_PSI_Status;
    EGPRS_PD_AckNack_t                    Egprs_Packet_Downlink_Ack_Nack;
    Packet_Pause_t                        Packet_Pause;
    Packet_Enh_Measurement_Report_t       Packet_Enh_Measurement_Report;
    Additional_MS_Rad_Access_Cap_t        Additional_MS_Rad_Access_Cap;
    Packet_Cell_Change_Notification_t     Packet_Cell_Change_Notification;
    Packet_SI_Status_t                    Packet_SI_Status;
    UL_Data_Block_GPRS_t                  UL_Data_Block_GPRS;
    UL_Data_Block_EGPRS_Header_t          UL_Data_Block_EGPRS_Header;
    UL_Packet_Control_Ack_11_t            UL_Packet_Control_Ack_11;
    UL_Packet_Control_Ack_TN_RRBP_11_t    UL_Packet_Control_Ack_TN_RRBP_11;
    UL_Packet_Control_Ack_8_t             UL_Packet_Control_Ack_8;
    UL_Packet_Control_Ack_TN_RRBP_8_t     UL_Packet_Control_Ack_TN_RRBP_8;
    EC_Packet_Control_Acknowledgement_t   EC_Packet_Control_Acknowledgement;
    EC_Packet_Downlink_Ack_Nack_t         EC_Packet_Downlink_Ack_Nack;
  } u;
  RLCMAC_block_format_t block_format;
  unsigned         flags;
} RlcMacUplink_t;

typedef struct
{
   uint16_t bsn1;
   uint16_t bsn2;
   uint8_t pi;
}egprs_ul_header_info_t;

typedef struct
{
   uint16_t bsn1;
   uint16_t bsn2;
}egprs_dl_header_info_t;

typedef struct
{
   unsigned         magic;
   RLCMAC_block_format_t block_format;
   uint8_t          mcs;
   unsigned         frame_number;
#define GSM_RLC_MAC_EGPRS_BLOCK1 0x01
#define GSM_RLC_MAC_EGPRS_BLOCK2 0x02
#define GSM_RLC_MAC_EGPRS_FANR_FLAG 0x08
   unsigned         flags;
   union
   {
      egprs_ul_header_info_t egprs_ul_header_info;
      egprs_dl_header_info_t egprs_dl_header_info;
   }u;
} RlcMacPrivateData_t;


#if 0
void GPRSMSG_Profile(int16_t i);
#endif

/* SI1_RestOctet_t */

typedef struct
{
  bool                Exist_NCH_Position;
  uint8_t             NCH_Position;

  uint8_t             BandIndicator;
} SI1_RestOctet_t;

/* SI3_Rest_Octet_t */
typedef struct
{
  uint8_t CBQ;
  uint8_t CELL_RESELECT_OFFSET;
  uint8_t TEMPORARY_OFFSET;
  uint8_t PENALTY_TIME;
} Selection_Parameters_t;

typedef struct
{
  uint8_t Exist_Selection_Parameters;
  Selection_Parameters_t Selection_Parameters;

  uint8_t Exist_Power_Offset;
  uint8_t Power_Offset;

  uint8_t System_Information_2ter_Indicator;
  uint8_t Early_Classmark_Sending_Control;

  uint8_t Exist_WHERE;
  uint8_t WHERE;

  uint8_t Exist_GPRS_Indicator;
  uint8_t RA_COLOUR;
  uint8_t SI13_POSITION;
  uint8_t ECS_Restriction3G;
  uint8_t ExistSI2quaterIndicator;
  uint8_t SI2quaterIndicator;
} SI3_Rest_Octet_t;

typedef struct
{
  uint8_t Exist_Selection_Parameters;
  Selection_Parameters_t Selection_Parameters;

  uint8_t Exist_Power_Offset;
  uint8_t Power_Offset;

  uint8_t Exist_GPRS_Indicator;
  uint8_t RA_COLOUR;
  uint8_t SI13_POSITION;
} SI4_Rest_Octet_t;

#if 0
typedef SI4_Rest_Octet_t SI7_Rest_Octet_t;
typedef SI4_Rest_Octet_t SI8_Rest_Octet_t;
#endif

/* SI6_RestOctet_t */

typedef struct
{
  uint8_t  PagingChannelRestructuring;
  uint8_t  NLN_SACCH;

  bool Exist_CallPriority;
  uint8_t  CallPriority;

  uint8_t  NLN_Status;
} PCH_and_NCH_Info_t;

typedef struct
{
  bool                Exist_PCH_and_NCH_Info;
  PCH_and_NCH_Info_t PCH_and_NCH_Info;

  bool                Exist_VBS_VGCS_Options;
  uint8_t             VBS_VGCS_Options;

  /* The meaning of Exist_DTM_Support is as follows:
   * false => DTM is not supported in the serving cell, RAC and MAX_LAPDm are absent in bitstream
   * true  => DTM is supported in the serving cell, RAC and MAX_LAPDm are present in bitstream
   */
  bool                Exist_DTM_Support;
  uint8_t             RAC;
  uint8_t             MAX_LAPDm;

  uint8_t             BandIndicator; /* bit(1) L/H, L => ARFCN in 1800 band H => ARFCN in 1900 band */
} SI6_RestOctet_t;

/*************************************************
 * Enhanced Measurement Report. TS 04.18 9.1.55. *
 *************************************************/

typedef struct
{
  uint8_t       DTX_USED;
  uint8_t       RXLEV_VAL;
  uint8_t       RX_QUAL_FULL;
  uint8_t       MEAN_BEP;
  uint8_t       CV_BEP;
  uint8_t       NBR_RCVD_BLOCKS;
} EMR_ServingCell_t;

typedef struct
{
  uint8_t RR_Short_PD;
  uint8_t MESSAGE_TYPE;
  uint8_t ShortLayer2_Header;

  BA_USED_t BA_USED;
  uint8_t BSIC_Seen;

  uint8_t SCALE;

  uint8_t Exist_ServingCellData;
  EMR_ServingCell_t ServingCellData;

  uint8_t Count_RepeatedInvalid_BSIC_Info; /* Number of instances */
  RepeatedInvalid_BSIC_Info_t RepeatedInvalid_BSIC_Info[INV_BSIC_LIST_LEN];

  uint8_t Exist_ReportBitmap;
  uint8_t Count_REPORTING_QUANTITY_Instances; /* Number of instances */
  REPORTING_QUANTITY_Instance_t REPORTING_QUANTITY_Instances[REPORT_QUANTITY_LIST_LEN];

} EnhancedMeasurementReport_t;

extern const uint8_t gsm_rlcmac_gprs_cs_to_block_length[];
extern const uint8_t gsm_rlcmac_egprs_header_type_to_dl_header_block_length[];
extern const uint8_t gsm_rlcmac_egprs_header_type_to_ul_header_block_length[];
extern const uint8_t gsm_rlcmac_egprs_mcs_to_data_block_length[];

#endif /* __PACKET_GSM_RLCMAC_H__ */

/*
 * Editor modelines  -  https://www.wireshark.org/tools/modelines.html
 *
 * Local Variables:
 * c-basic-offset: 2
 * tab-width: 8
 * indent-tabs-mode: nil
 * End:
 *
 * vi: set shiftwidth=2 tabstop=8 expandtab:
 * :indentSize=2:tabSize=8:noTabs=true:
 */
