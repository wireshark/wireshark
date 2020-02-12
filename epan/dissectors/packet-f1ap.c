/* Do not modify this file. Changes will be overwritten.                      */
/* Generated automatically by the ASN.1 to Wireshark dissector compiler       */
/* packet-f1ap.c                                                              */
/* asn2wrs.py -p f1ap -c ./f1ap.cnf -s ./packet-f1ap-template -D . -O ../.. F1AP-CommonDataTypes.asn F1AP-Constants.asn F1AP-Containers.asn F1AP-IEs.asn F1AP-PDU-Contents.asn F1AP-PDU-Descriptions.asn */

/* Input file: packet-f1ap-template.c */

#line 1 "./asn1/f1ap/packet-f1ap-template.c"
/* packet-f1ap.c
 * Routines for E-UTRAN F1 Application Protocol (F1AP) packet dissection
 * Copyright 2018-2020, Pascal Quantin <pascal@wireshark.org>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * References: 3GPP TS 38.473 V15.8.0 (2019-12)
 */

#include "config.h"

#include <epan/packet.h>

#include <epan/asn1.h>
#include <epan/sctpppids.h>
#include <epan/proto_data.h>

#include "packet-per.h"
#include "packet-x2ap.h"
#include "packet-nr-rrc.h"
#include "packet-e212.h"
#include "packet-pdcp-nr.h"

#define PNAME  "F1 Application Protocol"
#define PSNAME "F1AP"
#define PFNAME "f1ap"

#define SCTP_PORT_F1AP 38472

void proto_register_f1ap(void);
void proto_reg_handoff_f1ap(void);


/*--- Included file: packet-f1ap-val.h ---*/
#line 1 "./asn1/f1ap/packet-f1ap-val.h"
#define maxPrivateIEs                  65535
#define maxProtocolExtensions          65535
#define maxProtocolIEs                 65535
#define maxNRARFCN                     3279165
#define maxnoofErrors                  256
#define maxnoofIndividualF1ConnectionsToReset 65536
#define maxCellingNBDU                 512
#define maxnoofSCells                  32
#define maxnoofSRBs                    8
#define maxnoofDRBs                    64
#define maxnoofULUPTNLInformation      2
#define maxnoofDLUPTNLInformation      2
#define maxnoofBPLMNs                  6
#define maxnoofCandidateSpCells        64
#define maxnoofPotentialSpCells        64
#define maxnoofNrCellBands             32
#define maxnoofSIBTypes                32
#define maxnoofSITypes                 32
#define maxnoofPagingCells             512
#define maxnoofTNLAssociations         32
#define maxnoofQoSFlows                64
#define maxnoofSliceItems              1024
#define maxCellineNB                   256
#define maxnoofExtendedBPLMNs          6
#define maxnoofUEIDs                   65536
#define maxnoofBPLMNsNRminus1          11
#define maxnoofUACPLMNs                12
#define maxnoofUACperPLMN              64
#define maxnoofAdditionalSIBs          63

typedef enum _ProcedureCode_enum {
  id_Reset     =   0,
  id_F1Setup   =   1,
  id_ErrorIndication =   2,
  id_gNBDUConfigurationUpdate =   3,
  id_gNBCUConfigurationUpdate =   4,
  id_UEContextSetup =   5,
  id_UEContextRelease =   6,
  id_UEContextModification =   7,
  id_UEContextModificationRequired =   8,
  id_UEMobilityCommand =   9,
  id_UEContextReleaseRequest =  10,
  id_InitialULRRCMessageTransfer =  11,
  id_DLRRCMessageTransfer =  12,
  id_ULRRCMessageTransfer =  13,
  id_privateMessage =  14,
  id_UEInactivityNotification =  15,
  id_GNBDUResourceCoordination =  16,
  id_SystemInformationDeliveryCommand =  17,
  id_Paging    =  18,
  id_Notify    =  19,
  id_WriteReplaceWarning =  20,
  id_PWSCancel =  21,
  id_PWSRestartIndication =  22,
  id_PWSFailureIndication =  23,
  id_GNBDUStatusIndication =  24,
  id_RRCDeliveryReport =  25,
  id_F1Removal =  26,
  id_NetworkAccessRateReduction =  27
} ProcedureCode_enum;

typedef enum _ProtocolIE_ID_enum {
  id_Cause     =   0,
  id_Cells_Failed_to_be_Activated_List =   1,
  id_Cells_Failed_to_be_Activated_List_Item =   2,
  id_Cells_to_be_Activated_List =   3,
  id_Cells_to_be_Activated_List_Item =   4,
  id_Cells_to_be_Deactivated_List =   5,
  id_Cells_to_be_Deactivated_List_Item =   6,
  id_CriticalityDiagnostics =   7,
  id_CUtoDURRCInformation =   9,
  id_Unknown_10 =  10,
  id_Unknown_11 =  11,
  id_DRBs_FailedToBeModified_Item =  12,
  id_DRBs_FailedToBeModified_List =  13,
  id_DRBs_FailedToBeSetup_Item =  14,
  id_DRBs_FailedToBeSetup_List =  15,
  id_DRBs_FailedToBeSetupMod_Item =  16,
  id_DRBs_FailedToBeSetupMod_List =  17,
  id_DRBs_ModifiedConf_Item =  18,
  id_DRBs_ModifiedConf_List =  19,
  id_DRBs_Modified_Item =  20,
  id_DRBs_Modified_List =  21,
  id_DRBs_Required_ToBeModified_Item =  22,
  id_DRBs_Required_ToBeModified_List =  23,
  id_DRBs_Required_ToBeReleased_Item =  24,
  id_DRBs_Required_ToBeReleased_List =  25,
  id_DRBs_Setup_Item =  26,
  id_DRBs_Setup_List =  27,
  id_DRBs_SetupMod_Item =  28,
  id_DRBs_SetupMod_List =  29,
  id_DRBs_ToBeModified_Item =  30,
  id_DRBs_ToBeModified_List =  31,
  id_DRBs_ToBeReleased_Item =  32,
  id_DRBs_ToBeReleased_List =  33,
  id_DRBs_ToBeSetup_Item =  34,
  id_DRBs_ToBeSetup_List =  35,
  id_DRBs_ToBeSetupMod_Item =  36,
  id_DRBs_ToBeSetupMod_List =  37,
  id_DRXCycle  =  38,
  id_DUtoCURRCInformation =  39,
  id_gNB_CU_UE_F1AP_ID =  40,
  id_gNB_DU_UE_F1AP_ID =  41,
  id_gNB_DU_ID =  42,
  id_GNB_DU_Served_Cells_Item =  43,
  id_gNB_DU_Served_Cells_List =  44,
  id_gNB_DU_Name =  45,
  id_NRCellID  =  46,
  id_oldgNB_DU_UE_F1AP_ID =  47,
  id_ResetType =  48,
  id_ResourceCoordinationTransferContainer =  49,
  id_RRCContainer =  50,
  id_SCell_ToBeRemoved_Item =  51,
  id_SCell_ToBeRemoved_List =  52,
  id_SCell_ToBeSetup_Item =  53,
  id_SCell_ToBeSetup_List =  54,
  id_SCell_ToBeSetupMod_Item =  55,
  id_SCell_ToBeSetupMod_List =  56,
  id_Served_Cells_To_Add_Item =  57,
  id_Served_Cells_To_Add_List =  58,
  id_Served_Cells_To_Delete_Item =  59,
  id_Served_Cells_To_Delete_List =  60,
  id_Served_Cells_To_Modify_Item =  61,
  id_Served_Cells_To_Modify_List =  62,
  id_SpCell_ID =  63,
  id_SRBID     =  64,
  id_SRBs_FailedToBeSetup_Item =  65,
  id_SRBs_FailedToBeSetup_List =  66,
  id_SRBs_FailedToBeSetupMod_Item =  67,
  id_SRBs_FailedToBeSetupMod_List =  68,
  id_SRBs_Required_ToBeReleased_Item =  69,
  id_SRBs_Required_ToBeReleased_List =  70,
  id_SRBs_ToBeReleased_Item =  71,
  id_SRBs_ToBeReleased_List =  72,
  id_SRBs_ToBeSetup_Item =  73,
  id_SRBs_ToBeSetup_List =  74,
  id_SRBs_ToBeSetupMod_Item =  75,
  id_SRBs_ToBeSetupMod_List =  76,
  id_TimeToWait =  77,
  id_TransactionID =  78,
  id_TransmissionActionIndicator =  79,
  id_UE_associatedLogicalF1_ConnectionItem =  80,
  id_UE_associatedLogicalF1_ConnectionListResAck =  81,
  id_gNB_CU_Name =  82,
  id_SCell_FailedtoSetup_List =  83,
  id_SCell_FailedtoSetup_Item =  84,
  id_SCell_FailedtoSetupMod_List =  85,
  id_SCell_FailedtoSetupMod_Item =  86,
  id_RRCReconfigurationCompleteIndicator =  87,
  id_Cells_Status_Item =  88,
  id_Cells_Status_List =  89,
  id_Candidate_SpCell_List =  90,
  id_Candidate_SpCell_Item =  91,
  id_Potential_SpCell_List =  92,
  id_Potential_SpCell_Item =  93,
  id_FullConfiguration =  94,
  id_C_RNTI    =  95,
  id_SpCellULConfigured =  96,
  id_InactivityMonitoringRequest =  97,
  id_InactivityMonitoringResponse =  98,
  id_DRB_Activity_Item =  99,
  id_DRB_Activity_List = 100,
  id_EUTRA_NR_CellResourceCoordinationReq_Container = 101,
  id_EUTRA_NR_CellResourceCoordinationReqAck_Container = 102,
  id_Unknown_103 = 103,
  id_Unknown_104 = 104,
  id_Protected_EUTRA_Resources_List = 105,
  id_RequestType = 106,
  id_ServCellIndex = 107,
  id_RAT_FrequencyPriorityInformation = 108,
  id_ExecuteDuplication = 109,
  id_Unknown_110 = 110,
  id_NRCGI     = 111,
  id_PagingCell_Item = 112,
  id_PagingCell_List = 113,
  id_PagingDRX = 114,
  id_PagingPriority = 115,
  id_SItype_List = 116,
  id_UEIdentityIndexValue = 117,
  id_gNB_CUSystemInformation = 118,
  id_HandoverPreparationInformation = 119,
  id_GNB_CU_TNL_Association_To_Add_Item = 120,
  id_GNB_CU_TNL_Association_To_Add_List = 121,
  id_GNB_CU_TNL_Association_To_Remove_Item = 122,
  id_GNB_CU_TNL_Association_To_Remove_List = 123,
  id_GNB_CU_TNL_Association_To_Update_Item = 124,
  id_GNB_CU_TNL_Association_To_Update_List = 125,
  id_MaskedIMEISV = 126,
  id_PagingIdentity = 127,
  id_DUtoCURRCContainer = 128,
  id_Cells_to_be_Barred_List = 129,
  id_Cells_to_be_Barred_Item = 130,
  id_TAISliceSupportList = 131,
  id_GNB_CU_TNL_Association_Setup_List = 132,
  id_GNB_CU_TNL_Association_Setup_Item = 133,
  id_GNB_CU_TNL_Association_Failed_To_Setup_List = 134,
  id_GNB_CU_TNL_Association_Failed_To_Setup_Item = 135,
  id_DRB_Notify_Item = 136,
  id_DRB_Notify_List = 137,
  id_NotficationControl = 138,
  id_RANAC     = 139,
  id_PWSSystemInformation = 140,
  id_RepetitionPeriod = 141,
  id_NumberofBroadcastRequest = 142,
  id_Unknown_143 = 143,
  id_Cells_To_Be_Broadcast_List = 144,
  id_Cells_To_Be_Broadcast_Item = 145,
  id_Cells_Broadcast_Completed_List = 146,
  id_Cells_Broadcast_Completed_Item = 147,
  id_Broadcast_To_Be_Cancelled_List = 148,
  id_Broadcast_To_Be_Cancelled_Item = 149,
  id_Cells_Broadcast_Cancelled_List = 150,
  id_Cells_Broadcast_Cancelled_Item = 151,
  id_NR_CGI_List_For_Restart_List = 152,
  id_NR_CGI_List_For_Restart_Item = 153,
  id_PWS_Failed_NR_CGI_List = 154,
  id_PWS_Failed_NR_CGI_Item = 155,
  id_ConfirmedUEID = 156,
  id_Cancel_all_Warning_Messages_Indicator = 157,
  id_GNB_DU_UE_AMBR_UL = 158,
  id_DRXConfigurationIndicator = 159,
  id_RLC_Status = 160,
  id_DLPDCPSNLength = 161,
  id_GNB_DUConfigurationQuery = 162,
  id_MeasurementTimingConfiguration = 163,
  id_DRB_Information = 164,
  id_ServingPLMN = 165,
  id_Unknown_166 = 166,
  id_Unknown_167 = 167,
  id_Protected_EUTRA_Resources_Item = 168,
  id_Unknown_169 = 169,
  id_GNB_CU_RRC_Version = 170,
  id_GNB_DU_RRC_Version = 171,
  id_GNBDUOverloadInformation = 172,
  id_CellGroupConfig = 173,
  id_RLCFailureIndication = 174,
  id_UplinkTxDirectCurrentListInformation = 175,
  id_DC_Based_Duplication_Configured = 176,
  id_DC_Based_Duplication_Activation = 177,
  id_SULAccessIndication = 178,
  id_AvailablePLMNList = 179,
  id_PDUSessionID = 180,
  id_ULPDUSessionAggregateMaximumBitRate = 181,
  id_ServingCellMO = 182,
  id_QoSFlowMappingIndication = 183,
  id_RRCDeliveryStatusRequest = 184,
  id_RRCDeliveryStatus = 185,
  id_BearerTypeChange = 186,
  id_RLCMode   = 187,
  id_Duplication_Activation = 188,
  id_Dedicated_SIDelivery_NeededUE_List = 189,
  id_Dedicated_SIDelivery_NeededUE_Item = 190,
  id_DRX_LongCycleStartOffset = 191,
  id_ULPDCPSNLength = 192,
  id_SelectedBandCombinationIndex = 193,
  id_SelectedFeatureSetEntryIndex = 194,
  id_ResourceCoordinationTransferInformation = 195,
  id_ExtendedServedPLMNs_List = 196,
  id_ExtendedAvailablePLMN_List = 197,
  id_Associated_SCell_List = 198,
  id_latest_RRC_Version_Enhanced = 199,
  id_Associated_SCell_Item = 200,
  id_Cell_Direction = 201,
  id_SRBs_Setup_List = 202,
  id_SRBs_Setup_Item = 203,
  id_SRBs_SetupMod_List = 204,
  id_SRBs_SetupMod_Item = 205,
  id_SRBs_Modified_List = 206,
  id_SRBs_Modified_Item = 207,
  id_Ph_InfoSCG = 208,
  id_RequestedBandCombinationIndex = 209,
  id_RequestedFeatureSetEntryIndex = 210,
  id_RequestedP_MaxFR2 = 211,
  id_DRX_Config = 212,
  id_IgnoreResourceCoordinationContainer = 213,
  id_UEAssistanceInformation = 214,
  id_NeedforGap = 215,
  id_PagingOrigin = 216,
  id_new_gNB_CU_UE_F1AP_ID = 217,
  id_RedirectedRRCmessage = 218,
  id_new_gNB_DU_UE_F1AP_ID = 219,
  id_NotificationInformation = 220,
  id_PLMNAssistanceInfoForNetShar = 221,
  id_UEContextNotRetrievable = 222,
  id_BPLMN_ID_Info_List = 223,
  id_SelectedPLMNID = 224,
  id_UAC_Assistance_Info = 225,
  id_RANUEID   = 226,
  id_GNB_DU_TNL_Association_To_Remove_Item = 227,
  id_GNB_DU_TNL_Association_To_Remove_List = 228,
  id_TNLAssociationTransportLayerAddressgNBDU = 229,
  id_portNumber = 230,
  id_AdditionalSIBMessageList = 231,
  id_Cell_Type = 232,
  id_IgnorePRACHConfiguration = 233,
  id_CG_Config = 234,
  id_PDCCH_BlindDetectionSCG = 235,
  id_Requested_PDCCH_BlindDetectionSCG = 236,
  id_Ph_InfoMCG = 237,
  id_MeasGapSharingConfig = 238,
  id_systemInformationAreaID = 239,
  id_areaScope = 240,
  id_RRCContainer_RRCSetupComplete = 241
} ProtocolIE_ID_enum;

/*--- End of included file: packet-f1ap-val.h ---*/
#line 38 "./asn1/f1ap/packet-f1ap-template.c"

/* Initialize the protocol and registered fields */
static int proto_f1ap = -1;

static int hf_f1ap_transportLayerAddressIPv4 = -1;
static int hf_f1ap_transportLayerAddressIPv6 = -1;

/*--- Included file: packet-f1ap-hf.c ---*/
#line 1 "./asn1/f1ap/packet-f1ap-hf.c"
static int hf_f1ap_AdditionalSIBMessageList_PDU = -1;  /* AdditionalSIBMessageList */
static int hf_f1ap_Associated_SCell_Item_PDU = -1;  /* Associated_SCell_Item */
static int hf_f1ap_AvailablePLMNList_PDU = -1;    /* AvailablePLMNList */
static int hf_f1ap_AreaScope_PDU = -1;            /* AreaScope */
static int hf_f1ap_BitRate_PDU = -1;              /* BitRate */
static int hf_f1ap_BearerTypeChange_PDU = -1;     /* BearerTypeChange */
static int hf_f1ap_BPLMN_ID_Info_List_PDU = -1;   /* BPLMN_ID_Info_List */
static int hf_f1ap_Cancel_all_Warning_Messages_Indicator_PDU = -1;  /* Cancel_all_Warning_Messages_Indicator */
static int hf_f1ap_Candidate_SpCell_Item_PDU = -1;  /* Candidate_SpCell_Item */
static int hf_f1ap_Cause_PDU = -1;                /* Cause */
static int hf_f1ap_CellGroupConfig_PDU = -1;      /* CellGroupConfig */
static int hf_f1ap_Cell_Direction_PDU = -1;       /* Cell_Direction */
static int hf_f1ap_Cells_Failed_to_be_Activated_List_Item_PDU = -1;  /* Cells_Failed_to_be_Activated_List_Item */
static int hf_f1ap_Cells_Status_Item_PDU = -1;    /* Cells_Status_Item */
static int hf_f1ap_Cells_To_Be_Broadcast_Item_PDU = -1;  /* Cells_To_Be_Broadcast_Item */
static int hf_f1ap_Cells_Broadcast_Completed_Item_PDU = -1;  /* Cells_Broadcast_Completed_Item */
static int hf_f1ap_Broadcast_To_Be_Cancelled_Item_PDU = -1;  /* Broadcast_To_Be_Cancelled_Item */
static int hf_f1ap_Cells_Broadcast_Cancelled_Item_PDU = -1;  /* Cells_Broadcast_Cancelled_Item */
static int hf_f1ap_Cells_to_be_Activated_List_Item_PDU = -1;  /* Cells_to_be_Activated_List_Item */
static int hf_f1ap_Cells_to_be_Deactivated_List_Item_PDU = -1;  /* Cells_to_be_Deactivated_List_Item */
static int hf_f1ap_Cells_to_be_Barred_Item_PDU = -1;  /* Cells_to_be_Barred_Item */
static int hf_f1ap_CellType_PDU = -1;             /* CellType */
static int hf_f1ap_CellULConfigured_PDU = -1;     /* CellULConfigured */
static int hf_f1ap_CP_TransportLayerAddress_PDU = -1;  /* CP_TransportLayerAddress */
static int hf_f1ap_CriticalityDiagnostics_PDU = -1;  /* CriticalityDiagnostics */
static int hf_f1ap_C_RNTI_PDU = -1;               /* C_RNTI */
static int hf_f1ap_CUtoDURRCInformation_PDU = -1;  /* CUtoDURRCInformation */
static int hf_f1ap_DCBasedDuplicationConfigured_PDU = -1;  /* DCBasedDuplicationConfigured */
static int hf_f1ap_Dedicated_SIDelivery_NeededUE_Item_PDU = -1;  /* Dedicated_SIDelivery_NeededUE_Item */
static int hf_f1ap_DRB_Activity_Item_PDU = -1;    /* DRB_Activity_Item */
static int hf_f1ap_DRBs_FailedToBeModified_Item_PDU = -1;  /* DRBs_FailedToBeModified_Item */
static int hf_f1ap_DRBs_FailedToBeSetup_Item_PDU = -1;  /* DRBs_FailedToBeSetup_Item */
static int hf_f1ap_DRBs_FailedToBeSetupMod_Item_PDU = -1;  /* DRBs_FailedToBeSetupMod_Item */
static int hf_f1ap_DRB_Information_PDU = -1;      /* DRB_Information */
static int hf_f1ap_DRBs_Modified_Item_PDU = -1;   /* DRBs_Modified_Item */
static int hf_f1ap_DRBs_ModifiedConf_Item_PDU = -1;  /* DRBs_ModifiedConf_Item */
static int hf_f1ap_DRB_Notify_Item_PDU = -1;      /* DRB_Notify_Item */
static int hf_f1ap_DRBs_Required_ToBeModified_Item_PDU = -1;  /* DRBs_Required_ToBeModified_Item */
static int hf_f1ap_DRBs_Required_ToBeReleased_Item_PDU = -1;  /* DRBs_Required_ToBeReleased_Item */
static int hf_f1ap_DRBs_Setup_Item_PDU = -1;      /* DRBs_Setup_Item */
static int hf_f1ap_DRBs_SetupMod_Item_PDU = -1;   /* DRBs_SetupMod_Item */
static int hf_f1ap_DRBs_ToBeModified_Item_PDU = -1;  /* DRBs_ToBeModified_Item */
static int hf_f1ap_DRBs_ToBeReleased_Item_PDU = -1;  /* DRBs_ToBeReleased_Item */
static int hf_f1ap_DRBs_ToBeSetup_Item_PDU = -1;  /* DRBs_ToBeSetup_Item */
static int hf_f1ap_DRBs_ToBeSetupMod_Item_PDU = -1;  /* DRBs_ToBeSetupMod_Item */
static int hf_f1ap_DRXCycle_PDU = -1;             /* DRXCycle */
static int hf_f1ap_DRX_Config_PDU = -1;           /* DRX_Config */
static int hf_f1ap_DRXConfigurationIndicator_PDU = -1;  /* DRXConfigurationIndicator */
static int hf_f1ap_DRX_LongCycleStartOffset_PDU = -1;  /* DRX_LongCycleStartOffset */
static int hf_f1ap_DUtoCURRCContainer_PDU = -1;   /* DUtoCURRCContainer */
static int hf_f1ap_DUtoCURRCInformation_PDU = -1;  /* DUtoCURRCInformation */
static int hf_f1ap_DuplicationActivation_PDU = -1;  /* DuplicationActivation */
static int hf_f1ap_ExtendedAvailablePLMN_List_PDU = -1;  /* ExtendedAvailablePLMN_List */
static int hf_f1ap_ExtendedServedPLMNs_List_PDU = -1;  /* ExtendedServedPLMNs_List */
static int hf_f1ap_ExecuteDuplication_PDU = -1;   /* ExecuteDuplication */
static int hf_f1ap_EUTRA_NR_CellResourceCoordinationReq_Container_PDU = -1;  /* EUTRA_NR_CellResourceCoordinationReq_Container */
static int hf_f1ap_EUTRA_NR_CellResourceCoordinationReqAck_Container_PDU = -1;  /* EUTRA_NR_CellResourceCoordinationReqAck_Container */
static int hf_f1ap_FullConfiguration_PDU = -1;    /* FullConfiguration */
static int hf_f1ap_CG_Config_PDU = -1;            /* CG_Config */
static int hf_f1ap_GNB_CUSystemInformation_PDU = -1;  /* GNB_CUSystemInformation */
static int hf_f1ap_GNB_CU_TNL_Association_Setup_Item_PDU = -1;  /* GNB_CU_TNL_Association_Setup_Item */
static int hf_f1ap_GNB_CU_TNL_Association_Failed_To_Setup_Item_PDU = -1;  /* GNB_CU_TNL_Association_Failed_To_Setup_Item */
static int hf_f1ap_GNB_CU_TNL_Association_To_Add_Item_PDU = -1;  /* GNB_CU_TNL_Association_To_Add_Item */
static int hf_f1ap_GNB_CU_TNL_Association_To_Remove_Item_PDU = -1;  /* GNB_CU_TNL_Association_To_Remove_Item */
static int hf_f1ap_GNB_CU_TNL_Association_To_Update_Item_PDU = -1;  /* GNB_CU_TNL_Association_To_Update_Item */
static int hf_f1ap_GNB_CU_UE_F1AP_ID_PDU = -1;    /* GNB_CU_UE_F1AP_ID */
static int hf_f1ap_GNB_DU_UE_F1AP_ID_PDU = -1;    /* GNB_DU_UE_F1AP_ID */
static int hf_f1ap_GNB_DU_ID_PDU = -1;            /* GNB_DU_ID */
static int hf_f1ap_GNB_CU_Name_PDU = -1;          /* GNB_CU_Name */
static int hf_f1ap_GNB_DU_Name_PDU = -1;          /* GNB_DU_Name */
static int hf_f1ap_GNB_DU_Served_Cells_Item_PDU = -1;  /* GNB_DU_Served_Cells_Item */
static int hf_f1ap_GNB_DUConfigurationQuery_PDU = -1;  /* GNB_DUConfigurationQuery */
static int hf_f1ap_GNBDUOverloadInformation_PDU = -1;  /* GNBDUOverloadInformation */
static int hf_f1ap_GNB_DU_TNL_Association_To_Remove_Item_PDU = -1;  /* GNB_DU_TNL_Association_To_Remove_Item */
static int hf_f1ap_HandoverPreparationInformation_PDU = -1;  /* HandoverPreparationInformation */
static int hf_f1ap_IgnorePRACHConfiguration_PDU = -1;  /* IgnorePRACHConfiguration */
static int hf_f1ap_IgnoreResourceCoordinationContainer_PDU = -1;  /* IgnoreResourceCoordinationContainer */
static int hf_f1ap_InactivityMonitoringRequest_PDU = -1;  /* InactivityMonitoringRequest */
static int hf_f1ap_InactivityMonitoringResponse_PDU = -1;  /* InactivityMonitoringResponse */
static int hf_f1ap_MaskedIMEISV_PDU = -1;         /* MaskedIMEISV */
static int hf_f1ap_MeasGapSharingConfig_PDU = -1;  /* MeasGapSharingConfig */
static int hf_f1ap_MeasurementTimingConfiguration_PDU = -1;  /* MeasurementTimingConfiguration */
static int hf_f1ap_NeedforGap_PDU = -1;           /* NeedforGap */
static int hf_f1ap_NR_CGI_List_For_Restart_Item_PDU = -1;  /* NR_CGI_List_For_Restart_Item */
static int hf_f1ap_NotificationInformation_PDU = -1;  /* NotificationInformation */
static int hf_f1ap_NRCGI_PDU = -1;                /* NRCGI */
static int hf_f1ap_NumberofBroadcastRequest_PDU = -1;  /* NumberofBroadcastRequest */
static int hf_f1ap_PagingCell_Item_PDU = -1;      /* PagingCell_Item */
static int hf_f1ap_PagingDRX_PDU = -1;            /* PagingDRX */
static int hf_f1ap_PagingIdentity_PDU = -1;       /* PagingIdentity */
static int hf_f1ap_PagingOrigin_PDU = -1;         /* PagingOrigin */
static int hf_f1ap_PagingPriority_PDU = -1;       /* PagingPriority */
static int hf_f1ap_PDCCH_BlindDetectionSCG_PDU = -1;  /* PDCCH_BlindDetectionSCG */
static int hf_f1ap_PDCPSNLength_PDU = -1;         /* PDCPSNLength */
static int hf_f1ap_PDUSessionID_PDU = -1;         /* PDUSessionID */
static int hf_f1ap_Ph_InfoMCG_PDU = -1;           /* Ph_InfoMCG */
static int hf_f1ap_Ph_InfoSCG_PDU = -1;           /* Ph_InfoSCG */
static int hf_f1ap_PLMN_Identity_PDU = -1;        /* PLMN_Identity */
static int hf_f1ap_PortNumber_PDU = -1;           /* PortNumber */
static int hf_f1ap_Protected_EUTRA_Resources_Item_PDU = -1;  /* Protected_EUTRA_Resources_Item */
static int hf_f1ap_Potential_SpCell_Item_PDU = -1;  /* Potential_SpCell_Item */
static int hf_f1ap_PWS_Failed_NR_CGI_Item_PDU = -1;  /* PWS_Failed_NR_CGI_Item */
static int hf_f1ap_PWSSystemInformation_PDU = -1;  /* PWSSystemInformation */
static int hf_f1ap_QoSFlowMappingIndication_PDU = -1;  /* QoSFlowMappingIndication */
static int hf_f1ap_RANAC_PDU = -1;                /* RANAC */
static int hf_f1ap_RANUEID_PDU = -1;              /* RANUEID */
static int hf_f1ap_RAT_FrequencyPriorityInformation_PDU = -1;  /* RAT_FrequencyPriorityInformation */
static int hf_f1ap_RequestedBandCombinationIndex_PDU = -1;  /* RequestedBandCombinationIndex */
static int hf_f1ap_RequestedFeatureSetEntryIndex_PDU = -1;  /* RequestedFeatureSetEntryIndex */
static int hf_f1ap_Requested_PDCCH_BlindDetectionSCG_PDU = -1;  /* Requested_PDCCH_BlindDetectionSCG */
static int hf_f1ap_RequestedP_MaxFR2_PDU = -1;    /* RequestedP_MaxFR2 */
static int hf_f1ap_RequestType_PDU = -1;          /* RequestType */
static int hf_f1ap_ResourceCoordinationTransferInformation_PDU = -1;  /* ResourceCoordinationTransferInformation */
static int hf_f1ap_ResourceCoordinationTransferContainer_PDU = -1;  /* ResourceCoordinationTransferContainer */
static int hf_f1ap_RepetitionPeriod_PDU = -1;     /* RepetitionPeriod */
static int hf_f1ap_RLCFailureIndication_PDU = -1;  /* RLCFailureIndication */
static int hf_f1ap_RLCMode_PDU = -1;              /* RLCMode */
static int hf_f1ap_RLC_Status_PDU = -1;           /* RLC_Status */
static int hf_f1ap_RRCContainer_PDU = -1;         /* RRCContainer */
static int hf_f1ap_RRCContainer_RRCSetupComplete_PDU = -1;  /* RRCContainer_RRCSetupComplete */
static int hf_f1ap_RRCDeliveryStatus_PDU = -1;    /* RRCDeliveryStatus */
static int hf_f1ap_RRCDeliveryStatusRequest_PDU = -1;  /* RRCDeliveryStatusRequest */
static int hf_f1ap_RRCReconfigurationCompleteIndicator_PDU = -1;  /* RRCReconfigurationCompleteIndicator */
static int hf_f1ap_RRC_Version_PDU = -1;          /* RRC_Version */
static int hf_f1ap_Latest_RRC_Version_Enhanced_PDU = -1;  /* Latest_RRC_Version_Enhanced */
static int hf_f1ap_SCell_FailedtoSetup_Item_PDU = -1;  /* SCell_FailedtoSetup_Item */
static int hf_f1ap_SCell_FailedtoSetupMod_Item_PDU = -1;  /* SCell_FailedtoSetupMod_Item */
static int hf_f1ap_SCell_ToBeRemoved_Item_PDU = -1;  /* SCell_ToBeRemoved_Item */
static int hf_f1ap_SCell_ToBeSetup_Item_PDU = -1;  /* SCell_ToBeSetup_Item */
static int hf_f1ap_SCell_ToBeSetupMod_Item_PDU = -1;  /* SCell_ToBeSetupMod_Item */
static int hf_f1ap_SelectedBandCombinationIndex_PDU = -1;  /* SelectedBandCombinationIndex */
static int hf_f1ap_SelectedFeatureSetEntryIndex_PDU = -1;  /* SelectedFeatureSetEntryIndex */
static int hf_f1ap_ServCellIndex_PDU = -1;        /* ServCellIndex */
static int hf_f1ap_ServingCellMO_PDU = -1;        /* ServingCellMO */
static int hf_f1ap_Served_Cells_To_Add_Item_PDU = -1;  /* Served_Cells_To_Add_Item */
static int hf_f1ap_Served_Cells_To_Delete_Item_PDU = -1;  /* Served_Cells_To_Delete_Item */
static int hf_f1ap_Served_Cells_To_Modify_Item_PDU = -1;  /* Served_Cells_To_Modify_Item */
static int hf_f1ap_SItype_List_PDU = -1;          /* SItype_List */
static int hf_f1ap_SliceSupportList_PDU = -1;     /* SliceSupportList */
static int hf_f1ap_SRBID_PDU = -1;                /* SRBID */
static int hf_f1ap_SRBs_FailedToBeSetup_Item_PDU = -1;  /* SRBs_FailedToBeSetup_Item */
static int hf_f1ap_SRBs_FailedToBeSetupMod_Item_PDU = -1;  /* SRBs_FailedToBeSetupMod_Item */
static int hf_f1ap_SRBs_Modified_Item_PDU = -1;   /* SRBs_Modified_Item */
static int hf_f1ap_SRBs_Required_ToBeReleased_Item_PDU = -1;  /* SRBs_Required_ToBeReleased_Item */
static int hf_f1ap_SRBs_Setup_Item_PDU = -1;      /* SRBs_Setup_Item */
static int hf_f1ap_SRBs_SetupMod_Item_PDU = -1;   /* SRBs_SetupMod_Item */
static int hf_f1ap_SRBs_ToBeReleased_Item_PDU = -1;  /* SRBs_ToBeReleased_Item */
static int hf_f1ap_SRBs_ToBeSetup_Item_PDU = -1;  /* SRBs_ToBeSetup_Item */
static int hf_f1ap_SRBs_ToBeSetupMod_Item_PDU = -1;  /* SRBs_ToBeSetupMod_Item */
static int hf_f1ap_SULAccessIndication_PDU = -1;  /* SULAccessIndication */
static int hf_f1ap_SystemInformationAreaID_PDU = -1;  /* SystemInformationAreaID */
static int hf_f1ap_TimeToWait_PDU = -1;           /* TimeToWait */
static int hf_f1ap_TransactionID_PDU = -1;        /* TransactionID */
static int hf_f1ap_TransmissionActionIndicator_PDU = -1;  /* TransmissionActionIndicator */
static int hf_f1ap_UAC_Assistance_Info_PDU = -1;  /* UAC_Assistance_Info */
static int hf_f1ap_UE_associatedLogicalF1_ConnectionItem_PDU = -1;  /* UE_associatedLogicalF1_ConnectionItem */
static int hf_f1ap_UEAssistanceInformation_PDU = -1;  /* UEAssistanceInformation */
static int hf_f1ap_UEContextNotRetrievable_PDU = -1;  /* UEContextNotRetrievable */
static int hf_f1ap_UEIdentityIndexValue_PDU = -1;  /* UEIdentityIndexValue */
static int hf_f1ap_UplinkTxDirectCurrentListInformation_PDU = -1;  /* UplinkTxDirectCurrentListInformation */
static int hf_f1ap_Reset_PDU = -1;                /* Reset */
static int hf_f1ap_ResetType_PDU = -1;            /* ResetType */
static int hf_f1ap_ResetAcknowledge_PDU = -1;     /* ResetAcknowledge */
static int hf_f1ap_UE_associatedLogicalF1_ConnectionListResAck_PDU = -1;  /* UE_associatedLogicalF1_ConnectionListResAck */
static int hf_f1ap_ErrorIndication_PDU = -1;      /* ErrorIndication */
static int hf_f1ap_F1SetupRequest_PDU = -1;       /* F1SetupRequest */
static int hf_f1ap_GNB_DU_Served_Cells_List_PDU = -1;  /* GNB_DU_Served_Cells_List */
static int hf_f1ap_F1SetupResponse_PDU = -1;      /* F1SetupResponse */
static int hf_f1ap_Cells_to_be_Activated_List_PDU = -1;  /* Cells_to_be_Activated_List */
static int hf_f1ap_F1SetupFailure_PDU = -1;       /* F1SetupFailure */
static int hf_f1ap_GNBDUConfigurationUpdate_PDU = -1;  /* GNBDUConfigurationUpdate */
static int hf_f1ap_Served_Cells_To_Add_List_PDU = -1;  /* Served_Cells_To_Add_List */
static int hf_f1ap_Served_Cells_To_Modify_List_PDU = -1;  /* Served_Cells_To_Modify_List */
static int hf_f1ap_Served_Cells_To_Delete_List_PDU = -1;  /* Served_Cells_To_Delete_List */
static int hf_f1ap_Cells_Status_List_PDU = -1;    /* Cells_Status_List */
static int hf_f1ap_Dedicated_SIDelivery_NeededUE_List_PDU = -1;  /* Dedicated_SIDelivery_NeededUE_List */
static int hf_f1ap_GNB_DU_TNL_Association_To_Remove_List_PDU = -1;  /* GNB_DU_TNL_Association_To_Remove_List */
static int hf_f1ap_GNBDUConfigurationUpdateAcknowledge_PDU = -1;  /* GNBDUConfigurationUpdateAcknowledge */
static int hf_f1ap_GNBDUConfigurationUpdateFailure_PDU = -1;  /* GNBDUConfigurationUpdateFailure */
static int hf_f1ap_GNBCUConfigurationUpdate_PDU = -1;  /* GNBCUConfigurationUpdate */
static int hf_f1ap_Cells_to_be_Deactivated_List_PDU = -1;  /* Cells_to_be_Deactivated_List */
static int hf_f1ap_GNB_CU_TNL_Association_To_Add_List_PDU = -1;  /* GNB_CU_TNL_Association_To_Add_List */
static int hf_f1ap_GNB_CU_TNL_Association_To_Remove_List_PDU = -1;  /* GNB_CU_TNL_Association_To_Remove_List */
static int hf_f1ap_GNB_CU_TNL_Association_To_Update_List_PDU = -1;  /* GNB_CU_TNL_Association_To_Update_List */
static int hf_f1ap_Cells_to_be_Barred_List_PDU = -1;  /* Cells_to_be_Barred_List */
static int hf_f1ap_Protected_EUTRA_Resources_List_PDU = -1;  /* Protected_EUTRA_Resources_List */
static int hf_f1ap_GNBCUConfigurationUpdateAcknowledge_PDU = -1;  /* GNBCUConfigurationUpdateAcknowledge */
static int hf_f1ap_Cells_Failed_to_be_Activated_List_PDU = -1;  /* Cells_Failed_to_be_Activated_List */
static int hf_f1ap_GNB_CU_TNL_Association_Setup_List_PDU = -1;  /* GNB_CU_TNL_Association_Setup_List */
static int hf_f1ap_GNB_CU_TNL_Association_Failed_To_Setup_List_PDU = -1;  /* GNB_CU_TNL_Association_Failed_To_Setup_List */
static int hf_f1ap_GNBCUConfigurationUpdateFailure_PDU = -1;  /* GNBCUConfigurationUpdateFailure */
static int hf_f1ap_GNBDUResourceCoordinationRequest_PDU = -1;  /* GNBDUResourceCoordinationRequest */
static int hf_f1ap_GNBDUResourceCoordinationResponse_PDU = -1;  /* GNBDUResourceCoordinationResponse */
static int hf_f1ap_UEContextSetupRequest_PDU = -1;  /* UEContextSetupRequest */
static int hf_f1ap_Candidate_SpCell_List_PDU = -1;  /* Candidate_SpCell_List */
static int hf_f1ap_SCell_ToBeSetup_List_PDU = -1;  /* SCell_ToBeSetup_List */
static int hf_f1ap_SRBs_ToBeSetup_List_PDU = -1;  /* SRBs_ToBeSetup_List */
static int hf_f1ap_DRBs_ToBeSetup_List_PDU = -1;  /* DRBs_ToBeSetup_List */
static int hf_f1ap_UEContextSetupResponse_PDU = -1;  /* UEContextSetupResponse */
static int hf_f1ap_DRBs_Setup_List_PDU = -1;      /* DRBs_Setup_List */
static int hf_f1ap_SRBs_FailedToBeSetup_List_PDU = -1;  /* SRBs_FailedToBeSetup_List */
static int hf_f1ap_DRBs_FailedToBeSetup_List_PDU = -1;  /* DRBs_FailedToBeSetup_List */
static int hf_f1ap_SCell_FailedtoSetup_List_PDU = -1;  /* SCell_FailedtoSetup_List */
static int hf_f1ap_SRBs_Setup_List_PDU = -1;      /* SRBs_Setup_List */
static int hf_f1ap_UEContextSetupFailure_PDU = -1;  /* UEContextSetupFailure */
static int hf_f1ap_Potential_SpCell_List_PDU = -1;  /* Potential_SpCell_List */
static int hf_f1ap_UEContextReleaseRequest_PDU = -1;  /* UEContextReleaseRequest */
static int hf_f1ap_UEContextReleaseCommand_PDU = -1;  /* UEContextReleaseCommand */
static int hf_f1ap_UEContextReleaseComplete_PDU = -1;  /* UEContextReleaseComplete */
static int hf_f1ap_UEContextModificationRequest_PDU = -1;  /* UEContextModificationRequest */
static int hf_f1ap_SCell_ToBeSetupMod_List_PDU = -1;  /* SCell_ToBeSetupMod_List */
static int hf_f1ap_SCell_ToBeRemoved_List_PDU = -1;  /* SCell_ToBeRemoved_List */
static int hf_f1ap_SRBs_ToBeSetupMod_List_PDU = -1;  /* SRBs_ToBeSetupMod_List */
static int hf_f1ap_DRBs_ToBeSetupMod_List_PDU = -1;  /* DRBs_ToBeSetupMod_List */
static int hf_f1ap_DRBs_ToBeModified_List_PDU = -1;  /* DRBs_ToBeModified_List */
static int hf_f1ap_SRBs_ToBeReleased_List_PDU = -1;  /* SRBs_ToBeReleased_List */
static int hf_f1ap_DRBs_ToBeReleased_List_PDU = -1;  /* DRBs_ToBeReleased_List */
static int hf_f1ap_UEContextModificationResponse_PDU = -1;  /* UEContextModificationResponse */
static int hf_f1ap_DRBs_SetupMod_List_PDU = -1;   /* DRBs_SetupMod_List */
static int hf_f1ap_DRBs_Modified_List_PDU = -1;   /* DRBs_Modified_List */
static int hf_f1ap_SRBs_SetupMod_List_PDU = -1;   /* SRBs_SetupMod_List */
static int hf_f1ap_SRBs_Modified_List_PDU = -1;   /* SRBs_Modified_List */
static int hf_f1ap_DRBs_FailedToBeModified_List_PDU = -1;  /* DRBs_FailedToBeModified_List */
static int hf_f1ap_SRBs_FailedToBeSetupMod_List_PDU = -1;  /* SRBs_FailedToBeSetupMod_List */
static int hf_f1ap_DRBs_FailedToBeSetupMod_List_PDU = -1;  /* DRBs_FailedToBeSetupMod_List */
static int hf_f1ap_SCell_FailedtoSetupMod_List_PDU = -1;  /* SCell_FailedtoSetupMod_List */
static int hf_f1ap_Associated_SCell_List_PDU = -1;  /* Associated_SCell_List */
static int hf_f1ap_UEContextModificationFailure_PDU = -1;  /* UEContextModificationFailure */
static int hf_f1ap_UEContextModificationRequired_PDU = -1;  /* UEContextModificationRequired */
static int hf_f1ap_DRBs_Required_ToBeModified_List_PDU = -1;  /* DRBs_Required_ToBeModified_List */
static int hf_f1ap_DRBs_Required_ToBeReleased_List_PDU = -1;  /* DRBs_Required_ToBeReleased_List */
static int hf_f1ap_SRBs_Required_ToBeReleased_List_PDU = -1;  /* SRBs_Required_ToBeReleased_List */
static int hf_f1ap_UEContextModificationConfirm_PDU = -1;  /* UEContextModificationConfirm */
static int hf_f1ap_DRBs_ModifiedConf_List_PDU = -1;  /* DRBs_ModifiedConf_List */
static int hf_f1ap_UEContextModificationRefuse_PDU = -1;  /* UEContextModificationRefuse */
static int hf_f1ap_WriteReplaceWarningRequest_PDU = -1;  /* WriteReplaceWarningRequest */
static int hf_f1ap_Cells_To_Be_Broadcast_List_PDU = -1;  /* Cells_To_Be_Broadcast_List */
static int hf_f1ap_WriteReplaceWarningResponse_PDU = -1;  /* WriteReplaceWarningResponse */
static int hf_f1ap_Cells_Broadcast_Completed_List_PDU = -1;  /* Cells_Broadcast_Completed_List */
static int hf_f1ap_PWSCancelRequest_PDU = -1;     /* PWSCancelRequest */
static int hf_f1ap_Broadcast_To_Be_Cancelled_List_PDU = -1;  /* Broadcast_To_Be_Cancelled_List */
static int hf_f1ap_PWSCancelResponse_PDU = -1;    /* PWSCancelResponse */
static int hf_f1ap_Cells_Broadcast_Cancelled_List_PDU = -1;  /* Cells_Broadcast_Cancelled_List */
static int hf_f1ap_UEInactivityNotification_PDU = -1;  /* UEInactivityNotification */
static int hf_f1ap_DRB_Activity_List_PDU = -1;    /* DRB_Activity_List */
static int hf_f1ap_InitialULRRCMessageTransfer_PDU = -1;  /* InitialULRRCMessageTransfer */
static int hf_f1ap_DLRRCMessageTransfer_PDU = -1;  /* DLRRCMessageTransfer */
static int hf_f1ap_RedirectedRRCmessage_PDU = -1;  /* RedirectedRRCmessage */
static int hf_f1ap_ULRRCMessageTransfer_PDU = -1;  /* ULRRCMessageTransfer */
static int hf_f1ap_PrivateMessage_PDU = -1;       /* PrivateMessage */
static int hf_f1ap_SystemInformationDeliveryCommand_PDU = -1;  /* SystemInformationDeliveryCommand */
static int hf_f1ap_Paging_PDU = -1;               /* Paging */
static int hf_f1ap_PagingCell_list_PDU = -1;      /* PagingCell_list */
static int hf_f1ap_Notify_PDU = -1;               /* Notify */
static int hf_f1ap_DRB_Notify_List_PDU = -1;      /* DRB_Notify_List */
static int hf_f1ap_NetworkAccessRateReduction_PDU = -1;  /* NetworkAccessRateReduction */
static int hf_f1ap_PWSRestartIndication_PDU = -1;  /* PWSRestartIndication */
static int hf_f1ap_NR_CGI_List_For_Restart_List_PDU = -1;  /* NR_CGI_List_For_Restart_List */
static int hf_f1ap_PWSFailureIndication_PDU = -1;  /* PWSFailureIndication */
static int hf_f1ap_PWS_Failed_NR_CGI_List_PDU = -1;  /* PWS_Failed_NR_CGI_List */
static int hf_f1ap_GNBDUStatusIndication_PDU = -1;  /* GNBDUStatusIndication */
static int hf_f1ap_RRCDeliveryReport_PDU = -1;    /* RRCDeliveryReport */
static int hf_f1ap_F1RemovalRequest_PDU = -1;     /* F1RemovalRequest */
static int hf_f1ap_F1RemovalResponse_PDU = -1;    /* F1RemovalResponse */
static int hf_f1ap_F1RemovalFailure_PDU = -1;     /* F1RemovalFailure */
static int hf_f1ap_F1AP_PDU_PDU = -1;             /* F1AP_PDU */
static int hf_f1ap_local = -1;                    /* INTEGER_0_65535 */
static int hf_f1ap_global = -1;                   /* T_global */
static int hf_f1ap_ProtocolIE_Container_item = -1;  /* ProtocolIE_Field */
static int hf_f1ap_id = -1;                       /* ProtocolIE_ID */
static int hf_f1ap_criticality = -1;              /* Criticality */
static int hf_f1ap_ie_field_value = -1;           /* T_ie_field_value */
static int hf_f1ap_ProtocolExtensionContainer_item = -1;  /* ProtocolExtensionField */
static int hf_f1ap_ext_id = -1;                   /* ProtocolExtensionID */
static int hf_f1ap_extensionValue = -1;           /* T_extensionValue */
static int hf_f1ap_PrivateIE_Container_item = -1;  /* PrivateIE_Field */
static int hf_f1ap_private_id = -1;               /* PrivateIE_ID */
static int hf_f1ap_value = -1;                    /* T_value */
static int hf_f1ap_AdditionalSIBMessageList_item = -1;  /* AdditionalSIBMessageList_Item */
static int hf_f1ap_additionalSIB = -1;            /* T_additionalSIB */
static int hf_f1ap_iE_Extensions = -1;            /* ProtocolExtensionContainer */
static int hf_f1ap_priorityLevel = -1;            /* PriorityLevel */
static int hf_f1ap_pre_emptionCapability = -1;    /* Pre_emptionCapability */
static int hf_f1ap_pre_emptionVulnerability = -1;  /* Pre_emptionVulnerability */
static int hf_f1ap_sCell_ID = -1;                 /* NRCGI */
static int hf_f1ap_AvailablePLMNList_item = -1;   /* AvailablePLMNList_Item */
static int hf_f1ap_pLMNIdentity = -1;             /* PLMN_Identity */
static int hf_f1ap_BPLMN_ID_Info_List_item = -1;  /* BPLMN_ID_Info_Item */
static int hf_f1ap_pLMN_Identity_List = -1;       /* AvailablePLMNList */
static int hf_f1ap_extended_PLMN_Identity_List = -1;  /* ExtendedAvailablePLMN_List */
static int hf_f1ap_fiveGS_TAC = -1;               /* FiveGS_TAC */
static int hf_f1ap_nr_cell_ID = -1;               /* NRCellIdentity */
static int hf_f1ap_ranac = -1;                    /* RANAC */
static int hf_f1ap_ServedPLMNs_List_item = -1;    /* ServedPLMNs_Item */
static int hf_f1ap_pLMN_Identity = -1;            /* PLMN_Identity */
static int hf_f1ap_candidate_SpCell_ID = -1;      /* NRCGI */
static int hf_f1ap_radioNetwork = -1;             /* CauseRadioNetwork */
static int hf_f1ap_transport = -1;                /* CauseTransport */
static int hf_f1ap_protocol = -1;                 /* CauseProtocol */
static int hf_f1ap_misc = -1;                     /* CauseMisc */
static int hf_f1ap_choice_extension = -1;         /* ProtocolIE_SingleContainer */
static int hf_f1ap_nRCGI = -1;                    /* NRCGI */
static int hf_f1ap_cause = -1;                    /* Cause */
static int hf_f1ap_service_status = -1;           /* Service_Status */
static int hf_f1ap_numberOfBroadcasts = -1;       /* NumberOfBroadcasts */
static int hf_f1ap_nRPCI = -1;                    /* NRPCI */
static int hf_f1ap_cellBarred = -1;               /* CellBarred */
static int hf_f1ap_cellSize = -1;                 /* CellSize */
static int hf_f1ap_fiveG_S_TMSI = -1;             /* BIT_STRING_SIZE_48 */
static int hf_f1ap_endpoint_IP_address = -1;      /* TransportLayerAddress */
static int hf_f1ap_endpoint_IP_address_and_port = -1;  /* Endpoint_IP_address_and_port */
static int hf_f1ap_procedureCode = -1;            /* ProcedureCode */
static int hf_f1ap_triggeringMessage = -1;        /* TriggeringMessage */
static int hf_f1ap_procedureCriticality = -1;     /* Criticality */
static int hf_f1ap_transactionID = -1;            /* TransactionID */
static int hf_f1ap_iEsCriticalityDiagnostics = -1;  /* CriticalityDiagnostics_IE_List */
static int hf_f1ap_CriticalityDiagnostics_IE_List_item = -1;  /* CriticalityDiagnostics_IE_Item */
static int hf_f1ap_iECriticality = -1;            /* Criticality */
static int hf_f1ap_iE_ID = -1;                    /* ProtocolIE_ID */
static int hf_f1ap_typeOfError = -1;              /* TypeOfError */
static int hf_f1ap_cG_ConfigInfo = -1;            /* CG_ConfigInfo */
static int hf_f1ap_uE_CapabilityRAT_ContainerList = -1;  /* UE_CapabilityRAT_ContainerList */
static int hf_f1ap_measConfig = -1;               /* MeasConfig */
static int hf_f1ap_gNB_CU_UE_F1AP_ID = -1;        /* GNB_CU_UE_F1AP_ID */
static int hf_f1ap_DLUPTNLInformation_ToBeSetup_List_item = -1;  /* DLUPTNLInformation_ToBeSetup_Item */
static int hf_f1ap_dLUPTNLInformation = -1;       /* UPTransportLayerInformation */
static int hf_f1ap_dRBID = -1;                    /* DRBID */
static int hf_f1ap_dRB_Activity = -1;             /* DRB_Activity */
static int hf_f1ap_dRB_QoS = -1;                  /* QoSFlowLevelQoSParameters */
static int hf_f1ap_sNSSAI = -1;                   /* SNSSAI */
static int hf_f1ap_notificationControl = -1;      /* NotificationControl */
static int hf_f1ap_flows_Mapped_To_DRB_List = -1;  /* Flows_Mapped_To_DRB_List */
static int hf_f1ap_lCID = -1;                     /* LCID */
static int hf_f1ap_dLUPTNLInformation_ToBeSetup_List = -1;  /* DLUPTNLInformation_ToBeSetup_List */
static int hf_f1ap_uLUPTNLInformation_ToBeSetup_List = -1;  /* ULUPTNLInformation_ToBeSetup_List */
static int hf_f1ap_notification_Cause = -1;       /* Notification_Cause */
static int hf_f1ap_qoSInformation = -1;           /* QoSInformation */
static int hf_f1ap_uLConfiguration = -1;          /* ULConfiguration */
static int hf_f1ap_rLCMode = -1;                  /* RLCMode */
static int hf_f1ap_duplicationActivation = -1;    /* DuplicationActivation */
static int hf_f1ap_longDRXCycleLength = -1;       /* LongDRXCycleLength */
static int hf_f1ap_shortDRXCycleLength = -1;      /* ShortDRXCycleLength */
static int hf_f1ap_shortDRXCycleTimer = -1;       /* ShortDRXCycleTimer */
static int hf_f1ap_cellGroupConfig = -1;          /* CellGroupConfig */
static int hf_f1ap_measGapConfig = -1;            /* MeasGapConfig */
static int hf_f1ap_requestedP_MaxFR1 = -1;        /* T_requestedP_MaxFR1 */
static int hf_f1ap_qoSPriorityLevel = -1;         /* INTEGER_1_127 */
static int hf_f1ap_packetDelayBudget = -1;        /* PacketDelayBudget */
static int hf_f1ap_packetErrorRate = -1;          /* PacketErrorRate */
static int hf_f1ap_fiveQI = -1;                   /* INTEGER_0_255_ */
static int hf_f1ap_delayCritical = -1;            /* T_delayCritical */
static int hf_f1ap_averagingWindow = -1;          /* AveragingWindow */
static int hf_f1ap_maxDataBurstVolume = -1;       /* MaxDataBurstVolume */
static int hf_f1ap_endpointIPAddress = -1;        /* TransportLayerAddress */
static int hf_f1ap_ExtendedAvailablePLMN_List_item = -1;  /* ExtendedAvailablePLMN_Item */
static int hf_f1ap_ExtendedServedPLMNs_List_item = -1;  /* ExtendedServedPLMNs_Item */
static int hf_f1ap_tAISliceSupportList = -1;      /* SliceSupportList */
static int hf_f1ap_EUTRACells_List_item = -1;     /* EUTRACells_List_item */
static int hf_f1ap_eUTRA_Cell_ID = -1;            /* EUTRA_Cell_ID */
static int hf_f1ap_served_EUTRA_Cells_Information = -1;  /* Served_EUTRA_Cells_Information */
static int hf_f1ap_uL_EARFCN = -1;                /* ExtendedEARFCN */
static int hf_f1ap_dL_EARFCN = -1;                /* ExtendedEARFCN */
static int hf_f1ap_uL_Transmission_Bandwidth = -1;  /* EUTRA_Transmission_Bandwidth */
static int hf_f1ap_dL_Transmission_Bandwidth = -1;  /* EUTRA_Transmission_Bandwidth */
static int hf_f1ap_fDD = -1;                      /* EUTRA_Coex_FDD_Info */
static int hf_f1ap_tDD = -1;                      /* EUTRA_Coex_TDD_Info */
static int hf_f1ap_eARFCN = -1;                   /* ExtendedEARFCN */
static int hf_f1ap_transmission_Bandwidth = -1;   /* EUTRA_Transmission_Bandwidth */
static int hf_f1ap_subframeAssignment = -1;       /* EUTRA_SubframeAssignment */
static int hf_f1ap_specialSubframe_Info = -1;     /* EUTRA_SpecialSubframe_Info */
static int hf_f1ap_rootSequenceIndex = -1;        /* INTEGER_0_837 */
static int hf_f1ap_zeroCorrelationIndex = -1;     /* INTEGER_0_15 */
static int hf_f1ap_highSpeedFlag = -1;            /* BOOLEAN */
static int hf_f1ap_prach_FreqOffset = -1;         /* INTEGER_0_94 */
static int hf_f1ap_prach_ConfigIndex = -1;        /* INTEGER_0_63 */
static int hf_f1ap_specialSubframePatterns = -1;  /* EUTRA_SpecialSubframePatterns */
static int hf_f1ap_cyclicPrefixDL = -1;           /* EUTRA_CyclicPrefixDL */
static int hf_f1ap_cyclicPrefixUL = -1;           /* EUTRA_CyclicPrefixUL */
static int hf_f1ap_qCI = -1;                      /* QCI */
static int hf_f1ap_allocationAndRetentionPriority = -1;  /* AllocationAndRetentionPriority */
static int hf_f1ap_gbrQosInformation = -1;        /* GBR_QosInformation */
static int hf_f1ap_eUTRAFDD = -1;                 /* EUTRA_FDD_Info */
static int hf_f1ap_eUTRATDD = -1;                 /* EUTRA_TDD_Info */
static int hf_f1ap_uL_offsetToPointA = -1;        /* OffsetToPointA */
static int hf_f1ap_dL_offsetToPointA = -1;        /* OffsetToPointA */
static int hf_f1ap_offsetToPointA = -1;           /* OffsetToPointA */
static int hf_f1ap_uL_NRFreqInfo = -1;            /* NRFreqInfo */
static int hf_f1ap_dL_NRFreqInfo = -1;            /* NRFreqInfo */
static int hf_f1ap_uL_Transmission_Bandwidth_01 = -1;  /* Transmission_Bandwidth */
static int hf_f1ap_dL_Transmission_Bandwidth_01 = -1;  /* Transmission_Bandwidth */
static int hf_f1ap_Flows_Mapped_To_DRB_List_item = -1;  /* Flows_Mapped_To_DRB_Item */
static int hf_f1ap_qoSFlowIdentifier = -1;        /* QoSFlowIdentifier */
static int hf_f1ap_qoSFlowLevelQoSParameters = -1;  /* QoSFlowLevelQoSParameters */
static int hf_f1ap_freqBandIndicatorNr = -1;      /* INTEGER_1_1024_ */
static int hf_f1ap_supportedSULBandList = -1;     /* SEQUENCE_SIZE_0_maxnoofNrCellBands_OF_SupportedSULFreqBandItem */
static int hf_f1ap_supportedSULBandList_item = -1;  /* SupportedSULFreqBandItem */
static int hf_f1ap_e_RAB_MaximumBitrateDL = -1;   /* BitRate */
static int hf_f1ap_e_RAB_MaximumBitrateUL = -1;   /* BitRate */
static int hf_f1ap_e_RAB_GuaranteedBitrateDL = -1;  /* BitRate */
static int hf_f1ap_e_RAB_GuaranteedBitrateUL = -1;  /* BitRate */
static int hf_f1ap_maxFlowBitRateDownlink = -1;   /* BitRate */
static int hf_f1ap_maxFlowBitRateUplink = -1;     /* BitRate */
static int hf_f1ap_guaranteedFlowBitRateDownlink = -1;  /* BitRate */
static int hf_f1ap_guaranteedFlowBitRateUplink = -1;  /* BitRate */
static int hf_f1ap_maxPacketLossRateDownlink = -1;  /* MaxPacketLossRate */
static int hf_f1ap_maxPacketLossRateUplink = -1;  /* MaxPacketLossRate */
static int hf_f1ap_sibtypetobeupdatedlist = -1;   /* SEQUENCE_SIZE_1_maxnoofSIBTypes_OF_SibtypetobeupdatedListItem */
static int hf_f1ap_sibtypetobeupdatedlist_item = -1;  /* SibtypetobeupdatedListItem */
static int hf_f1ap_tNLAssociationTransportLayerAddress = -1;  /* CP_TransportLayerAddress */
static int hf_f1ap_tNLAssociationUsage = -1;      /* TNLAssociationUsage */
static int hf_f1ap_served_Cell_Information = -1;  /* Served_Cell_Information */
static int hf_f1ap_gNB_DU_System_Information = -1;  /* GNB_DU_System_Information */
static int hf_f1ap_mIB_message = -1;              /* MIB_message */
static int hf_f1ap_sIB1_message = -1;             /* SIB1_message */
static int hf_f1ap_tNLAssociationTransportLayerAddressgNBCU = -1;  /* CP_TransportLayerAddress */
static int hf_f1ap_transportLayerAddress = -1;    /* TransportLayerAddress */
static int hf_f1ap_gTP_TEID = -1;                 /* GTP_TEID */
static int hf_f1ap_message_Identifier = -1;       /* MessageIdentifier */
static int hf_f1ap_serialNumber = -1;             /* SerialNumber */
static int hf_f1ap_nRARFCN = -1;                  /* INTEGER_0_maxNRARFCN */
static int hf_f1ap_sul_Information = -1;          /* SUL_Information */
static int hf_f1ap_freqBandListNr = -1;           /* SEQUENCE_SIZE_1_maxnoofNrCellBands_OF_FreqBandNrItem */
static int hf_f1ap_freqBandListNr_item = -1;      /* FreqBandNrItem */
static int hf_f1ap_nRCellIdentity = -1;           /* NRCellIdentity */
static int hf_f1ap_fDD_01 = -1;                   /* FDD_Info */
static int hf_f1ap_tDD_01 = -1;                   /* TDD_Info */
static int hf_f1ap_pER_Scalar = -1;               /* PER_Scalar */
static int hf_f1ap_pER_Exponent = -1;             /* PER_Exponent */
static int hf_f1ap_rANUEPagingIdentity = -1;      /* RANUEPagingIdentity */
static int hf_f1ap_cNUEPagingIdentity = -1;       /* CNUEPagingIdentity */
static int hf_f1ap_spectrumSharingGroupID = -1;   /* SpectrumSharingGroupID */
static int hf_f1ap_eUTRACells_List = -1;          /* EUTRACells_List */
static int hf_f1ap_potential_SpCell_ID = -1;      /* NRCGI */
static int hf_f1ap_sIBtype = -1;                  /* SIBType_PWS */
static int hf_f1ap_sIBmessage = -1;               /* T_sIBmessage */
static int hf_f1ap_non_Dynamic_5QI = -1;          /* NonDynamic5QIDescriptor */
static int hf_f1ap_dynamic_5QI = -1;              /* Dynamic5QIDescriptor */
static int hf_f1ap_qoS_Characteristics = -1;      /* QoS_Characteristics */
static int hf_f1ap_nGRANallocationRetentionPriority = -1;  /* NGRANAllocationAndRetentionPriority */
static int hf_f1ap_gBR_QoS_Flow_Information = -1;  /* GBR_QoSFlowInformation */
static int hf_f1ap_reflective_QoS_Attribute = -1;  /* T_reflective_QoS_Attribute */
static int hf_f1ap_eUTRANQoS = -1;                /* EUTRANQoS */
static int hf_f1ap_iRNTI = -1;                    /* BIT_STRING_SIZE_40 */
static int hf_f1ap_eNDC = -1;                     /* SubscriberProfileIDforRFP */
static int hf_f1ap_nGRAN = -1;                    /* RAT_FrequencySelectionPriority */
static int hf_f1ap_eUTRA_Mode_Info = -1;          /* EUTRA_Coex_Mode_Info */
static int hf_f1ap_eUTRA_PRACH_Configuration = -1;  /* EUTRA_PRACH_Configuration */
static int hf_f1ap_meNB_Cell_ID = -1;             /* EUTRA_Cell_ID */
static int hf_f1ap_resourceCoordinationEUTRACellInfo = -1;  /* ResourceCoordinationEUTRACellInfo */
static int hf_f1ap_assocatedLCID = -1;            /* LCID */
static int hf_f1ap_reestablishment_Indication = -1;  /* Reestablishment_Indication */
static int hf_f1ap_delivery_status = -1;          /* PDCP_SN */
static int hf_f1ap_triggering_message = -1;       /* PDCP_SN */
static int hf_f1ap_latest_RRC_Version = -1;       /* BIT_STRING_SIZE_3 */
static int hf_f1ap_sCellIndex = -1;               /* SCellIndex */
static int hf_f1ap_sCellULConfigured = -1;        /* CellULConfigured */
static int hf_f1ap_configured_EPS_TAC = -1;       /* Configured_EPS_TAC */
static int hf_f1ap_servedPLMNs = -1;              /* ServedPLMNs_List */
static int hf_f1ap_nR_Mode_Info = -1;             /* NR_Mode_Info */
static int hf_f1ap_measurementTimingConfiguration = -1;  /* T_measurementTimingConfiguration */
static int hf_f1ap_oldNRCGI = -1;                 /* NRCGI */
static int hf_f1ap_eUTRA_Mode_Info_01 = -1;       /* EUTRA_Mode_Info */
static int hf_f1ap_protectedEUTRAResourceIndication = -1;  /* ProtectedEUTRAResourceIndication */
static int hf_f1ap_service_state = -1;            /* Service_State */
static int hf_f1ap_switchingOffOngoing = -1;      /* T_switchingOffOngoing */
static int hf_f1ap_SItype_List_item = -1;         /* SItype_Item */
static int hf_f1ap_sItype = -1;                   /* SItype */
static int hf_f1ap_sIBtype_01 = -1;               /* T_sIBtype */
static int hf_f1ap_sIBmessage_01 = -1;            /* T_sIBmessage_01 */
static int hf_f1ap_valueTag = -1;                 /* INTEGER_0_31_ */
static int hf_f1ap_SliceSupportList_item = -1;    /* SliceSupportItem */
static int hf_f1ap_sST = -1;                      /* OCTET_STRING_SIZE_1 */
static int hf_f1ap_sD = -1;                       /* OCTET_STRING_SIZE_3 */
static int hf_f1ap_sRBID = -1;                    /* SRBID */
static int hf_f1ap_duplicationIndication = -1;    /* DuplicationIndication */
static int hf_f1ap_sUL_NRARFCN = -1;              /* INTEGER_0_maxNRARFCN */
static int hf_f1ap_sUL_transmission_Bandwidth = -1;  /* Transmission_Bandwidth */
static int hf_f1ap_nRFreqInfo = -1;               /* NRFreqInfo */
static int hf_f1ap_transmission_Bandwidth_01 = -1;  /* Transmission_Bandwidth */
static int hf_f1ap_nRSCS = -1;                    /* NRSCS */
static int hf_f1ap_nRNRB = -1;                    /* NRNRB */
static int hf_f1ap_uACPLMN_List = -1;             /* UACPLMN_List */
static int hf_f1ap_UACPLMN_List_item = -1;        /* UACPLMN_Item */
static int hf_f1ap_uACType_List = -1;             /* UACType_List */
static int hf_f1ap_UACType_List_item = -1;        /* UACType_Item */
static int hf_f1ap_uACReductionIndication = -1;   /* UACReductionIndication */
static int hf_f1ap_uACCategoryType = -1;          /* UACCategoryType */
static int hf_f1ap_uACstandardized = -1;          /* UACAction */
static int hf_f1ap_uACOperatorDefined = -1;       /* UACOperatorDefined */
static int hf_f1ap_accessCategory = -1;           /* INTEGER_32_63_ */
static int hf_f1ap_accessIdentity = -1;           /* BIT_STRING_SIZE_7 */
static int hf_f1ap_gNB_DU_UE_F1AP_ID = -1;        /* GNB_DU_UE_F1AP_ID */
static int hf_f1ap_indexLength10 = -1;            /* BIT_STRING_SIZE_10 */
static int hf_f1ap_uLUEConfiguration = -1;        /* ULUEConfiguration */
static int hf_f1ap_ULUPTNLInformation_ToBeSetup_List_item = -1;  /* ULUPTNLInformation_ToBeSetup_Item */
static int hf_f1ap_uLUPTNLInformation = -1;       /* UPTransportLayerInformation */
static int hf_f1ap_gTPTunnel = -1;                /* GTPTunnel */
static int hf_f1ap_protocolIEs = -1;              /* ProtocolIE_Container */
static int hf_f1ap_f1_Interface = -1;             /* ResetAll */
static int hf_f1ap_partOfF1_Interface = -1;       /* UE_associatedLogicalF1_ConnectionListRes */
static int hf_f1ap_UE_associatedLogicalF1_ConnectionListRes_item = -1;  /* ProtocolIE_SingleContainer */
static int hf_f1ap_UE_associatedLogicalF1_ConnectionListResAck_item = -1;  /* ProtocolIE_SingleContainer */
static int hf_f1ap_GNB_DU_Served_Cells_List_item = -1;  /* ProtocolIE_SingleContainer */
static int hf_f1ap_Cells_to_be_Activated_List_item = -1;  /* ProtocolIE_SingleContainer */
static int hf_f1ap_Served_Cells_To_Add_List_item = -1;  /* ProtocolIE_SingleContainer */
static int hf_f1ap_Served_Cells_To_Modify_List_item = -1;  /* ProtocolIE_SingleContainer */
static int hf_f1ap_Served_Cells_To_Delete_List_item = -1;  /* ProtocolIE_SingleContainer */
static int hf_f1ap_Cells_Status_List_item = -1;   /* ProtocolIE_SingleContainer */
static int hf_f1ap_Dedicated_SIDelivery_NeededUE_List_item = -1;  /* ProtocolIE_SingleContainer */
static int hf_f1ap_GNB_DU_TNL_Association_To_Remove_List_item = -1;  /* ProtocolIE_SingleContainer */
static int hf_f1ap_Cells_to_be_Deactivated_List_item = -1;  /* ProtocolIE_SingleContainer */
static int hf_f1ap_GNB_CU_TNL_Association_To_Add_List_item = -1;  /* ProtocolIE_SingleContainer */
static int hf_f1ap_GNB_CU_TNL_Association_To_Remove_List_item = -1;  /* ProtocolIE_SingleContainer */
static int hf_f1ap_GNB_CU_TNL_Association_To_Update_List_item = -1;  /* ProtocolIE_SingleContainer */
static int hf_f1ap_Cells_to_be_Barred_List_item = -1;  /* ProtocolIE_SingleContainer */
static int hf_f1ap_Protected_EUTRA_Resources_List_item = -1;  /* ProtocolIE_SingleContainer */
static int hf_f1ap_Cells_Failed_to_be_Activated_List_item = -1;  /* ProtocolIE_SingleContainer */
static int hf_f1ap_GNB_CU_TNL_Association_Setup_List_item = -1;  /* ProtocolIE_SingleContainer */
static int hf_f1ap_GNB_CU_TNL_Association_Failed_To_Setup_List_item = -1;  /* ProtocolIE_SingleContainer */
static int hf_f1ap_Candidate_SpCell_List_item = -1;  /* ProtocolIE_SingleContainer */
static int hf_f1ap_SCell_ToBeSetup_List_item = -1;  /* ProtocolIE_SingleContainer */
static int hf_f1ap_SRBs_ToBeSetup_List_item = -1;  /* ProtocolIE_SingleContainer */
static int hf_f1ap_DRBs_ToBeSetup_List_item = -1;  /* ProtocolIE_SingleContainer */
static int hf_f1ap_DRBs_Setup_List_item = -1;     /* ProtocolIE_SingleContainer */
static int hf_f1ap_SRBs_FailedToBeSetup_List_item = -1;  /* ProtocolIE_SingleContainer */
static int hf_f1ap_DRBs_FailedToBeSetup_List_item = -1;  /* ProtocolIE_SingleContainer */
static int hf_f1ap_SCell_FailedtoSetup_List_item = -1;  /* ProtocolIE_SingleContainer */
static int hf_f1ap_SRBs_Setup_List_item = -1;     /* ProtocolIE_SingleContainer */
static int hf_f1ap_Potential_SpCell_List_item = -1;  /* ProtocolIE_SingleContainer */
static int hf_f1ap_SCell_ToBeSetupMod_List_item = -1;  /* ProtocolIE_SingleContainer */
static int hf_f1ap_SCell_ToBeRemoved_List_item = -1;  /* ProtocolIE_SingleContainer */
static int hf_f1ap_SRBs_ToBeSetupMod_List_item = -1;  /* ProtocolIE_SingleContainer */
static int hf_f1ap_DRBs_ToBeSetupMod_List_item = -1;  /* ProtocolIE_SingleContainer */
static int hf_f1ap_DRBs_ToBeModified_List_item = -1;  /* ProtocolIE_SingleContainer */
static int hf_f1ap_SRBs_ToBeReleased_List_item = -1;  /* ProtocolIE_SingleContainer */
static int hf_f1ap_DRBs_ToBeReleased_List_item = -1;  /* ProtocolIE_SingleContainer */
static int hf_f1ap_DRBs_SetupMod_List_item = -1;  /* ProtocolIE_SingleContainer */
static int hf_f1ap_DRBs_Modified_List_item = -1;  /* ProtocolIE_SingleContainer */
static int hf_f1ap_SRBs_SetupMod_List_item = -1;  /* ProtocolIE_SingleContainer */
static int hf_f1ap_SRBs_Modified_List_item = -1;  /* ProtocolIE_SingleContainer */
static int hf_f1ap_DRBs_FailedToBeModified_List_item = -1;  /* ProtocolIE_SingleContainer */
static int hf_f1ap_SRBs_FailedToBeSetupMod_List_item = -1;  /* ProtocolIE_SingleContainer */
static int hf_f1ap_DRBs_FailedToBeSetupMod_List_item = -1;  /* ProtocolIE_SingleContainer */
static int hf_f1ap_SCell_FailedtoSetupMod_List_item = -1;  /* ProtocolIE_SingleContainer */
static int hf_f1ap_Associated_SCell_List_item = -1;  /* ProtocolIE_SingleContainer */
static int hf_f1ap_DRBs_Required_ToBeModified_List_item = -1;  /* ProtocolIE_SingleContainer */
static int hf_f1ap_DRBs_Required_ToBeReleased_List_item = -1;  /* ProtocolIE_SingleContainer */
static int hf_f1ap_SRBs_Required_ToBeReleased_List_item = -1;  /* ProtocolIE_SingleContainer */
static int hf_f1ap_DRBs_ModifiedConf_List_item = -1;  /* ProtocolIE_SingleContainer */
static int hf_f1ap_Cells_To_Be_Broadcast_List_item = -1;  /* ProtocolIE_SingleContainer */
static int hf_f1ap_Cells_Broadcast_Completed_List_item = -1;  /* ProtocolIE_SingleContainer */
static int hf_f1ap_Broadcast_To_Be_Cancelled_List_item = -1;  /* ProtocolIE_SingleContainer */
static int hf_f1ap_Cells_Broadcast_Cancelled_List_item = -1;  /* ProtocolIE_SingleContainer */
static int hf_f1ap_DRB_Activity_List_item = -1;   /* ProtocolIE_SingleContainer */
static int hf_f1ap_privateIEs = -1;               /* PrivateIE_Container */
static int hf_f1ap_PagingCell_list_item = -1;     /* ProtocolIE_SingleContainer */
static int hf_f1ap_DRB_Notify_List_item = -1;     /* ProtocolIE_SingleContainer */
static int hf_f1ap_NR_CGI_List_For_Restart_List_item = -1;  /* ProtocolIE_SingleContainer */
static int hf_f1ap_PWS_Failed_NR_CGI_List_item = -1;  /* ProtocolIE_SingleContainer */
static int hf_f1ap_initiatingMessage = -1;        /* InitiatingMessage */
static int hf_f1ap_successfulOutcome = -1;        /* SuccessfulOutcome */
static int hf_f1ap_unsuccessfulOutcome = -1;      /* UnsuccessfulOutcome */
static int hf_f1ap_initiatingMessagevalue = -1;   /* InitiatingMessage_value */
static int hf_f1ap_successfulOutcome_value = -1;  /* SuccessfulOutcome_value */
static int hf_f1ap_unsuccessfulOutcome_value = -1;  /* UnsuccessfulOutcome_value */

/*--- End of included file: packet-f1ap-hf.c ---*/
#line 45 "./asn1/f1ap/packet-f1ap-template.c"

/* Initialize the subtree pointers */
static gint ett_f1ap = -1;
static gint ett_f1ap_ResourceCoordinationTransferContainer = -1;
static gint ett_f1ap_PLMN_Identity = -1;
static gint ett_f1ap_MIB_message = -1;
static gint ett_f1ap_SIB1_message = -1;
static gint ett_f1ap_CG_ConfigInfo = -1;
static gint ett_f1ap_CellGroupConfig = -1;
static gint ett_f1ap_TransportLayerAddress = -1;
static gint ett_f1ap_UE_CapabilityRAT_ContainerList = -1;
static gint ett_f1ap_measurementTimingConfiguration = -1;
static gint ett_f1ap_DUtoCURRCContainer = -1;
static gint ett_f1ap_requestedP_MaxFR1 = -1;
static gint ett_f1ap_HandoverPreparationInformation = -1;
static gint ett_f1ap_MeasConfig = -1;
static gint ett_f1ap_MeasGapConfig = -1;
static gint ett_f1ap_MeasGapSharingConfig = -1;
static gint ett_f1ap_EUTRA_NR_CellResourceCoordinationReq_Container = -1;
static gint ett_f1ap_EUTRA_NR_CellResourceCoordinationReqAck_Container = -1;
static gint ett_f1ap_ProtectedEUTRAResourceIndication = -1;
static gint ett_f1ap_RRCContainer = -1;
static gint ett_f1ap_RRCContainer_RRCSetupComplete = -1;
static gint ett_f1ap_sIBmessage = -1;
static gint ett_f1ap_UplinkTxDirectCurrentListInformation = -1;
static gint ett_f1ap_DRX_Config = -1;
static gint ett_f1ap_Ph_InfoSCG = -1;
static gint ett_f1ap_RequestedBandCombinationIndex = -1;
static gint ett_f1ap_RequestedFeatureSetEntryIndex = -1;
static gint ett_f1ap_RequestedP_MaxFR2 = -1;
static gint ett_f1ap_UEAssistanceInformation = -1;
static gint ett_f1ap_CG_Config = -1;
static gint ett_f1ap_Ph_InfoMCG = -1;

/*--- Included file: packet-f1ap-ett.c ---*/
#line 1 "./asn1/f1ap/packet-f1ap-ett.c"
static gint ett_f1ap_PrivateIE_ID = -1;
static gint ett_f1ap_ProtocolIE_Container = -1;
static gint ett_f1ap_ProtocolIE_Field = -1;
static gint ett_f1ap_ProtocolExtensionContainer = -1;
static gint ett_f1ap_ProtocolExtensionField = -1;
static gint ett_f1ap_PrivateIE_Container = -1;
static gint ett_f1ap_PrivateIE_Field = -1;
static gint ett_f1ap_AdditionalSIBMessageList = -1;
static gint ett_f1ap_AdditionalSIBMessageList_Item = -1;
static gint ett_f1ap_AllocationAndRetentionPriority = -1;
static gint ett_f1ap_Associated_SCell_Item = -1;
static gint ett_f1ap_AvailablePLMNList = -1;
static gint ett_f1ap_AvailablePLMNList_Item = -1;
static gint ett_f1ap_BPLMN_ID_Info_List = -1;
static gint ett_f1ap_BPLMN_ID_Info_Item = -1;
static gint ett_f1ap_ServedPLMNs_List = -1;
static gint ett_f1ap_ServedPLMNs_Item = -1;
static gint ett_f1ap_Candidate_SpCell_Item = -1;
static gint ett_f1ap_Cause = -1;
static gint ett_f1ap_Cells_Failed_to_be_Activated_List_Item = -1;
static gint ett_f1ap_Cells_Status_Item = -1;
static gint ett_f1ap_Cells_To_Be_Broadcast_Item = -1;
static gint ett_f1ap_Cells_Broadcast_Completed_Item = -1;
static gint ett_f1ap_Broadcast_To_Be_Cancelled_Item = -1;
static gint ett_f1ap_Cells_Broadcast_Cancelled_Item = -1;
static gint ett_f1ap_Cells_to_be_Activated_List_Item = -1;
static gint ett_f1ap_Cells_to_be_Deactivated_List_Item = -1;
static gint ett_f1ap_Cells_to_be_Barred_Item = -1;
static gint ett_f1ap_CellType = -1;
static gint ett_f1ap_CNUEPagingIdentity = -1;
static gint ett_f1ap_CP_TransportLayerAddress = -1;
static gint ett_f1ap_CriticalityDiagnostics = -1;
static gint ett_f1ap_CriticalityDiagnostics_IE_List = -1;
static gint ett_f1ap_CriticalityDiagnostics_IE_Item = -1;
static gint ett_f1ap_CUtoDURRCInformation = -1;
static gint ett_f1ap_Dedicated_SIDelivery_NeededUE_Item = -1;
static gint ett_f1ap_DLUPTNLInformation_ToBeSetup_List = -1;
static gint ett_f1ap_DLUPTNLInformation_ToBeSetup_Item = -1;
static gint ett_f1ap_DRB_Activity_Item = -1;
static gint ett_f1ap_DRBs_FailedToBeModified_Item = -1;
static gint ett_f1ap_DRBs_FailedToBeSetup_Item = -1;
static gint ett_f1ap_DRBs_FailedToBeSetupMod_Item = -1;
static gint ett_f1ap_DRB_Information = -1;
static gint ett_f1ap_DRBs_Modified_Item = -1;
static gint ett_f1ap_DRBs_ModifiedConf_Item = -1;
static gint ett_f1ap_DRB_Notify_Item = -1;
static gint ett_f1ap_DRBs_Required_ToBeModified_Item = -1;
static gint ett_f1ap_DRBs_Required_ToBeReleased_Item = -1;
static gint ett_f1ap_DRBs_Setup_Item = -1;
static gint ett_f1ap_DRBs_SetupMod_Item = -1;
static gint ett_f1ap_DRBs_ToBeModified_Item = -1;
static gint ett_f1ap_DRBs_ToBeReleased_Item = -1;
static gint ett_f1ap_DRBs_ToBeSetup_Item = -1;
static gint ett_f1ap_DRBs_ToBeSetupMod_Item = -1;
static gint ett_f1ap_DRXCycle = -1;
static gint ett_f1ap_DUtoCURRCInformation = -1;
static gint ett_f1ap_Dynamic5QIDescriptor = -1;
static gint ett_f1ap_Endpoint_IP_address_and_port = -1;
static gint ett_f1ap_ExtendedAvailablePLMN_List = -1;
static gint ett_f1ap_ExtendedAvailablePLMN_Item = -1;
static gint ett_f1ap_ExtendedServedPLMNs_List = -1;
static gint ett_f1ap_ExtendedServedPLMNs_Item = -1;
static gint ett_f1ap_EUTRACells_List = -1;
static gint ett_f1ap_EUTRACells_List_item = -1;
static gint ett_f1ap_EUTRA_Coex_FDD_Info = -1;
static gint ett_f1ap_EUTRA_Coex_Mode_Info = -1;
static gint ett_f1ap_EUTRA_Coex_TDD_Info = -1;
static gint ett_f1ap_EUTRA_PRACH_Configuration = -1;
static gint ett_f1ap_EUTRA_SpecialSubframe_Info = -1;
static gint ett_f1ap_EUTRANQoS = -1;
static gint ett_f1ap_EUTRA_Mode_Info = -1;
static gint ett_f1ap_EUTRA_FDD_Info = -1;
static gint ett_f1ap_EUTRA_TDD_Info = -1;
static gint ett_f1ap_FDD_Info = -1;
static gint ett_f1ap_Flows_Mapped_To_DRB_List = -1;
static gint ett_f1ap_Flows_Mapped_To_DRB_Item = -1;
static gint ett_f1ap_FreqBandNrItem = -1;
static gint ett_f1ap_SEQUENCE_SIZE_0_maxnoofNrCellBands_OF_SupportedSULFreqBandItem = -1;
static gint ett_f1ap_GBR_QosInformation = -1;
static gint ett_f1ap_GBR_QoSFlowInformation = -1;
static gint ett_f1ap_GNB_CUSystemInformation = -1;
static gint ett_f1ap_SEQUENCE_SIZE_1_maxnoofSIBTypes_OF_SibtypetobeupdatedListItem = -1;
static gint ett_f1ap_GNB_CU_TNL_Association_Setup_Item = -1;
static gint ett_f1ap_GNB_CU_TNL_Association_Failed_To_Setup_Item = -1;
static gint ett_f1ap_GNB_CU_TNL_Association_To_Add_Item = -1;
static gint ett_f1ap_GNB_CU_TNL_Association_To_Remove_Item = -1;
static gint ett_f1ap_GNB_CU_TNL_Association_To_Update_Item = -1;
static gint ett_f1ap_GNB_DU_Served_Cells_Item = -1;
static gint ett_f1ap_GNB_DU_System_Information = -1;
static gint ett_f1ap_GNB_DU_TNL_Association_To_Remove_Item = -1;
static gint ett_f1ap_GTPTunnel = -1;
static gint ett_f1ap_NGRANAllocationAndRetentionPriority = -1;
static gint ett_f1ap_NR_CGI_List_For_Restart_Item = -1;
static gint ett_f1ap_NonDynamic5QIDescriptor = -1;
static gint ett_f1ap_NotificationInformation = -1;
static gint ett_f1ap_NRFreqInfo = -1;
static gint ett_f1ap_SEQUENCE_SIZE_1_maxnoofNrCellBands_OF_FreqBandNrItem = -1;
static gint ett_f1ap_NRCGI = -1;
static gint ett_f1ap_NR_Mode_Info = -1;
static gint ett_f1ap_PacketErrorRate = -1;
static gint ett_f1ap_PagingCell_Item = -1;
static gint ett_f1ap_PagingIdentity = -1;
static gint ett_f1ap_Protected_EUTRA_Resources_Item = -1;
static gint ett_f1ap_Potential_SpCell_Item = -1;
static gint ett_f1ap_PWS_Failed_NR_CGI_Item = -1;
static gint ett_f1ap_PWSSystemInformation = -1;
static gint ett_f1ap_QoS_Characteristics = -1;
static gint ett_f1ap_QoSFlowLevelQoSParameters = -1;
static gint ett_f1ap_QoSInformation = -1;
static gint ett_f1ap_RANUEPagingIdentity = -1;
static gint ett_f1ap_RAT_FrequencyPriorityInformation = -1;
static gint ett_f1ap_ResourceCoordinationEUTRACellInfo = -1;
static gint ett_f1ap_ResourceCoordinationTransferInformation = -1;
static gint ett_f1ap_RLCFailureIndication = -1;
static gint ett_f1ap_RLC_Status = -1;
static gint ett_f1ap_RRCDeliveryStatus = -1;
static gint ett_f1ap_RRC_Version = -1;
static gint ett_f1ap_SCell_FailedtoSetup_Item = -1;
static gint ett_f1ap_SCell_FailedtoSetupMod_Item = -1;
static gint ett_f1ap_SCell_ToBeRemoved_Item = -1;
static gint ett_f1ap_SCell_ToBeSetup_Item = -1;
static gint ett_f1ap_SCell_ToBeSetupMod_Item = -1;
static gint ett_f1ap_Served_Cell_Information = -1;
static gint ett_f1ap_Served_Cells_To_Add_Item = -1;
static gint ett_f1ap_Served_Cells_To_Delete_Item = -1;
static gint ett_f1ap_Served_Cells_To_Modify_Item = -1;
static gint ett_f1ap_Served_EUTRA_Cells_Information = -1;
static gint ett_f1ap_Service_Status = -1;
static gint ett_f1ap_SItype_List = -1;
static gint ett_f1ap_SItype_Item = -1;
static gint ett_f1ap_SibtypetobeupdatedListItem = -1;
static gint ett_f1ap_SliceSupportList = -1;
static gint ett_f1ap_SliceSupportItem = -1;
static gint ett_f1ap_SNSSAI = -1;
static gint ett_f1ap_SRBs_FailedToBeSetup_Item = -1;
static gint ett_f1ap_SRBs_FailedToBeSetupMod_Item = -1;
static gint ett_f1ap_SRBs_Modified_Item = -1;
static gint ett_f1ap_SRBs_Required_ToBeReleased_Item = -1;
static gint ett_f1ap_SRBs_Setup_Item = -1;
static gint ett_f1ap_SRBs_SetupMod_Item = -1;
static gint ett_f1ap_SRBs_ToBeReleased_Item = -1;
static gint ett_f1ap_SRBs_ToBeSetup_Item = -1;
static gint ett_f1ap_SRBs_ToBeSetupMod_Item = -1;
static gint ett_f1ap_SUL_Information = -1;
static gint ett_f1ap_SupportedSULFreqBandItem = -1;
static gint ett_f1ap_TDD_Info = -1;
static gint ett_f1ap_Transmission_Bandwidth = -1;
static gint ett_f1ap_UAC_Assistance_Info = -1;
static gint ett_f1ap_UACPLMN_List = -1;
static gint ett_f1ap_UACPLMN_Item = -1;
static gint ett_f1ap_UACType_List = -1;
static gint ett_f1ap_UACType_Item = -1;
static gint ett_f1ap_UACCategoryType = -1;
static gint ett_f1ap_UACOperatorDefined = -1;
static gint ett_f1ap_UE_associatedLogicalF1_ConnectionItem = -1;
static gint ett_f1ap_UEIdentityIndexValue = -1;
static gint ett_f1ap_ULConfiguration = -1;
static gint ett_f1ap_ULUPTNLInformation_ToBeSetup_List = -1;
static gint ett_f1ap_ULUPTNLInformation_ToBeSetup_Item = -1;
static gint ett_f1ap_UPTransportLayerInformation = -1;
static gint ett_f1ap_Reset = -1;
static gint ett_f1ap_ResetType = -1;
static gint ett_f1ap_UE_associatedLogicalF1_ConnectionListRes = -1;
static gint ett_f1ap_ResetAcknowledge = -1;
static gint ett_f1ap_UE_associatedLogicalF1_ConnectionListResAck = -1;
static gint ett_f1ap_ErrorIndication = -1;
static gint ett_f1ap_F1SetupRequest = -1;
static gint ett_f1ap_GNB_DU_Served_Cells_List = -1;
static gint ett_f1ap_F1SetupResponse = -1;
static gint ett_f1ap_Cells_to_be_Activated_List = -1;
static gint ett_f1ap_F1SetupFailure = -1;
static gint ett_f1ap_GNBDUConfigurationUpdate = -1;
static gint ett_f1ap_Served_Cells_To_Add_List = -1;
static gint ett_f1ap_Served_Cells_To_Modify_List = -1;
static gint ett_f1ap_Served_Cells_To_Delete_List = -1;
static gint ett_f1ap_Cells_Status_List = -1;
static gint ett_f1ap_Dedicated_SIDelivery_NeededUE_List = -1;
static gint ett_f1ap_GNB_DU_TNL_Association_To_Remove_List = -1;
static gint ett_f1ap_GNBDUConfigurationUpdateAcknowledge = -1;
static gint ett_f1ap_GNBDUConfigurationUpdateFailure = -1;
static gint ett_f1ap_GNBCUConfigurationUpdate = -1;
static gint ett_f1ap_Cells_to_be_Deactivated_List = -1;
static gint ett_f1ap_GNB_CU_TNL_Association_To_Add_List = -1;
static gint ett_f1ap_GNB_CU_TNL_Association_To_Remove_List = -1;
static gint ett_f1ap_GNB_CU_TNL_Association_To_Update_List = -1;
static gint ett_f1ap_Cells_to_be_Barred_List = -1;
static gint ett_f1ap_Protected_EUTRA_Resources_List = -1;
static gint ett_f1ap_GNBCUConfigurationUpdateAcknowledge = -1;
static gint ett_f1ap_Cells_Failed_to_be_Activated_List = -1;
static gint ett_f1ap_GNB_CU_TNL_Association_Setup_List = -1;
static gint ett_f1ap_GNB_CU_TNL_Association_Failed_To_Setup_List = -1;
static gint ett_f1ap_GNBCUConfigurationUpdateFailure = -1;
static gint ett_f1ap_GNBDUResourceCoordinationRequest = -1;
static gint ett_f1ap_GNBDUResourceCoordinationResponse = -1;
static gint ett_f1ap_UEContextSetupRequest = -1;
static gint ett_f1ap_Candidate_SpCell_List = -1;
static gint ett_f1ap_SCell_ToBeSetup_List = -1;
static gint ett_f1ap_SRBs_ToBeSetup_List = -1;
static gint ett_f1ap_DRBs_ToBeSetup_List = -1;
static gint ett_f1ap_UEContextSetupResponse = -1;
static gint ett_f1ap_DRBs_Setup_List = -1;
static gint ett_f1ap_SRBs_FailedToBeSetup_List = -1;
static gint ett_f1ap_DRBs_FailedToBeSetup_List = -1;
static gint ett_f1ap_SCell_FailedtoSetup_List = -1;
static gint ett_f1ap_SRBs_Setup_List = -1;
static gint ett_f1ap_UEContextSetupFailure = -1;
static gint ett_f1ap_Potential_SpCell_List = -1;
static gint ett_f1ap_UEContextReleaseRequest = -1;
static gint ett_f1ap_UEContextReleaseCommand = -1;
static gint ett_f1ap_UEContextReleaseComplete = -1;
static gint ett_f1ap_UEContextModificationRequest = -1;
static gint ett_f1ap_SCell_ToBeSetupMod_List = -1;
static gint ett_f1ap_SCell_ToBeRemoved_List = -1;
static gint ett_f1ap_SRBs_ToBeSetupMod_List = -1;
static gint ett_f1ap_DRBs_ToBeSetupMod_List = -1;
static gint ett_f1ap_DRBs_ToBeModified_List = -1;
static gint ett_f1ap_SRBs_ToBeReleased_List = -1;
static gint ett_f1ap_DRBs_ToBeReleased_List = -1;
static gint ett_f1ap_UEContextModificationResponse = -1;
static gint ett_f1ap_DRBs_SetupMod_List = -1;
static gint ett_f1ap_DRBs_Modified_List = -1;
static gint ett_f1ap_SRBs_SetupMod_List = -1;
static gint ett_f1ap_SRBs_Modified_List = -1;
static gint ett_f1ap_DRBs_FailedToBeModified_List = -1;
static gint ett_f1ap_SRBs_FailedToBeSetupMod_List = -1;
static gint ett_f1ap_DRBs_FailedToBeSetupMod_List = -1;
static gint ett_f1ap_SCell_FailedtoSetupMod_List = -1;
static gint ett_f1ap_Associated_SCell_List = -1;
static gint ett_f1ap_UEContextModificationFailure = -1;
static gint ett_f1ap_UEContextModificationRequired = -1;
static gint ett_f1ap_DRBs_Required_ToBeModified_List = -1;
static gint ett_f1ap_DRBs_Required_ToBeReleased_List = -1;
static gint ett_f1ap_SRBs_Required_ToBeReleased_List = -1;
static gint ett_f1ap_UEContextModificationConfirm = -1;
static gint ett_f1ap_DRBs_ModifiedConf_List = -1;
static gint ett_f1ap_UEContextModificationRefuse = -1;
static gint ett_f1ap_WriteReplaceWarningRequest = -1;
static gint ett_f1ap_Cells_To_Be_Broadcast_List = -1;
static gint ett_f1ap_WriteReplaceWarningResponse = -1;
static gint ett_f1ap_Cells_Broadcast_Completed_List = -1;
static gint ett_f1ap_PWSCancelRequest = -1;
static gint ett_f1ap_Broadcast_To_Be_Cancelled_List = -1;
static gint ett_f1ap_PWSCancelResponse = -1;
static gint ett_f1ap_Cells_Broadcast_Cancelled_List = -1;
static gint ett_f1ap_UEInactivityNotification = -1;
static gint ett_f1ap_DRB_Activity_List = -1;
static gint ett_f1ap_InitialULRRCMessageTransfer = -1;
static gint ett_f1ap_DLRRCMessageTransfer = -1;
static gint ett_f1ap_ULRRCMessageTransfer = -1;
static gint ett_f1ap_PrivateMessage = -1;
static gint ett_f1ap_SystemInformationDeliveryCommand = -1;
static gint ett_f1ap_Paging = -1;
static gint ett_f1ap_PagingCell_list = -1;
static gint ett_f1ap_Notify = -1;
static gint ett_f1ap_DRB_Notify_List = -1;
static gint ett_f1ap_NetworkAccessRateReduction = -1;
static gint ett_f1ap_PWSRestartIndication = -1;
static gint ett_f1ap_NR_CGI_List_For_Restart_List = -1;
static gint ett_f1ap_PWSFailureIndication = -1;
static gint ett_f1ap_PWS_Failed_NR_CGI_List = -1;
static gint ett_f1ap_GNBDUStatusIndication = -1;
static gint ett_f1ap_RRCDeliveryReport = -1;
static gint ett_f1ap_F1RemovalRequest = -1;
static gint ett_f1ap_F1RemovalResponse = -1;
static gint ett_f1ap_F1RemovalFailure = -1;
static gint ett_f1ap_F1AP_PDU = -1;
static gint ett_f1ap_InitiatingMessage = -1;
static gint ett_f1ap_SuccessfulOutcome = -1;
static gint ett_f1ap_UnsuccessfulOutcome = -1;

/*--- End of included file: packet-f1ap-ett.c ---*/
#line 79 "./asn1/f1ap/packet-f1ap-template.c"

enum{
  INITIATING_MESSAGE,
  SUCCESSFUL_OUTCOME,
  UNSUCCESSFUL_OUTCOME
};

typedef struct {
  guint32 message_type;
  guint32 procedure_code;
  guint32 protocol_ie_id;
  guint32 protocol_extension_id;
  const char *obj_id;
  guint32 sib_type;
  guint32 srb_id;
} f1ap_private_data_t;

typedef struct {
  guint32 message_type;
  guint32 ProcedureCode;
  guint32 ProtocolIE_ID;
  guint32 ProtocolExtensionID;
} f1ap_ctx_t;

/* Global variables */
static dissector_handle_t f1ap_handle;
static dissector_handle_t nr_rrc_ul_ccch_handle;
static dissector_handle_t nr_rrc_dl_ccch_handle;
static dissector_handle_t nr_rrc_ul_dcch_handle;
static dissector_handle_t nr_pdcp_handle;

/* Dissector tables */
static dissector_table_t f1ap_ies_dissector_table;
static dissector_table_t f1ap_extension_dissector_table;
static dissector_table_t f1ap_proc_imsg_dissector_table;
static dissector_table_t f1ap_proc_sout_dissector_table;
static dissector_table_t f1ap_proc_uout_dissector_table;

static int dissect_ProtocolIEFieldValue(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *);
static int dissect_ProtocolExtensionFieldExtensionValue(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *);
static int dissect_InitiatingMessageValue(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *);
static int dissect_SuccessfulOutcomeValue(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *);
static int dissect_UnsuccessfulOutcomeValue(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *);

static void
f1ap_MaxPacketLossRate_fmt(gchar *s, guint32 v)
{
  g_snprintf(s, ITEM_LABEL_LENGTH, "%.1f%% (%u)", (float)v/10, v);
}

static void
f1ap_PacketDelayBudget_fmt(gchar *s, guint32 v)
{
  g_snprintf(s, ITEM_LABEL_LENGTH, "%.1fms (%u)", (float)v/2, v);
}

static f1ap_private_data_t*
f1ap_get_private_data(packet_info *pinfo)
{
  f1ap_private_data_t *f1ap_data = (f1ap_private_data_t*)p_get_proto_data(wmem_file_scope(), pinfo, proto_f1ap, 0);
  if (!f1ap_data) {
    f1ap_data = wmem_new0(wmem_file_scope(), f1ap_private_data_t);
    f1ap_data->srb_id = -1;
    p_add_proto_data(wmem_file_scope(), pinfo, proto_f1ap, 0, f1ap_data);
  }
  return f1ap_data;
}

static void
add_nr_pdcp_meta_data(packet_info *pinfo, guint8 direction, guint8 srb_id)
{
  pdcp_nr_info *p_pdcp_nr_info;

  /* Only need to set info once per session. */
  if (get_pdcp_nr_proto_data(pinfo)) {
      return;
  }

  p_pdcp_nr_info = wmem_new0(wmem_file_scope(), pdcp_nr_info);
  p_pdcp_nr_info->direction = direction;
  p_pdcp_nr_info->bearerType = Bearer_DCCH;
  p_pdcp_nr_info->bearerId = srb_id;
  p_pdcp_nr_info->plane = NR_SIGNALING_PLANE;
  p_pdcp_nr_info->seqnum_length = PDCP_NR_SN_LENGTH_12_BITS;
  p_pdcp_nr_info->maci_present = TRUE;
  set_pdcp_nr_proto_data(pinfo, p_pdcp_nr_info);
}


/*--- Included file: packet-f1ap-fn.c ---*/
#line 1 "./asn1/f1ap/packet-f1ap-fn.c"

static const value_string f1ap_Criticality_vals[] = {
  {   0, "reject" },
  {   1, "ignore" },
  {   2, "notify" },
  { 0, NULL }
};


static int
dissect_f1ap_Criticality(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     3, NULL, FALSE, 0, NULL);

  return offset;
}



static int
dissect_f1ap_INTEGER_0_65535(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 65535U, NULL, FALSE);

  return offset;
}



static int
dissect_f1ap_T_global(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 96 "./asn1/f1ap/f1ap.cnf"
  f1ap_private_data_t *f1ap_data = f1ap_get_private_data(actx->pinfo);
  offset = dissect_per_object_identifier_str(tvb, offset, actx, tree, hf_index, &f1ap_data->obj_id);




  return offset;
}


static const value_string f1ap_PrivateIE_ID_vals[] = {
  {   0, "local" },
  {   1, "global" },
  { 0, NULL }
};

static const per_choice_t PrivateIE_ID_choice[] = {
  {   0, &hf_f1ap_local          , ASN1_NO_EXTENSIONS     , dissect_f1ap_INTEGER_0_65535 },
  {   1, &hf_f1ap_global         , ASN1_NO_EXTENSIONS     , dissect_f1ap_T_global },
  { 0, NULL, 0, NULL }
};

static int
dissect_f1ap_PrivateIE_ID(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 92 "./asn1/f1ap/f1ap.cnf"
  f1ap_private_data_t *f1ap_data = f1ap_get_private_data(actx->pinfo);
  f1ap_data->obj_id = NULL;


  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_f1ap_PrivateIE_ID, PrivateIE_ID_choice,
                                 NULL);

  return offset;
}


static const value_string f1ap_ProcedureCode_vals[] = {
  { id_Reset, "id-Reset" },
  { id_F1Setup, "id-F1Setup" },
  { id_ErrorIndication, "id-ErrorIndication" },
  { id_gNBDUConfigurationUpdate, "id-gNBDUConfigurationUpdate" },
  { id_gNBCUConfigurationUpdate, "id-gNBCUConfigurationUpdate" },
  { id_UEContextSetup, "id-UEContextSetup" },
  { id_UEContextRelease, "id-UEContextRelease" },
  { id_UEContextModification, "id-UEContextModification" },
  { id_UEContextModificationRequired, "id-UEContextModificationRequired" },
  { id_UEMobilityCommand, "id-UEMobilityCommand" },
  { id_UEContextReleaseRequest, "id-UEContextReleaseRequest" },
  { id_InitialULRRCMessageTransfer, "id-InitialULRRCMessageTransfer" },
  { id_DLRRCMessageTransfer, "id-DLRRCMessageTransfer" },
  { id_ULRRCMessageTransfer, "id-ULRRCMessageTransfer" },
  { id_privateMessage, "id-privateMessage" },
  { id_UEInactivityNotification, "id-UEInactivityNotification" },
  { id_GNBDUResourceCoordination, "id-GNBDUResourceCoordination" },
  { id_SystemInformationDeliveryCommand, "id-SystemInformationDeliveryCommand" },
  { id_Paging, "id-Paging" },
  { id_Notify, "id-Notify" },
  { id_WriteReplaceWarning, "id-WriteReplaceWarning" },
  { id_PWSCancel, "id-PWSCancel" },
  { id_PWSRestartIndication, "id-PWSRestartIndication" },
  { id_PWSFailureIndication, "id-PWSFailureIndication" },
  { id_GNBDUStatusIndication, "id-GNBDUStatusIndication" },
  { id_RRCDeliveryReport, "id-RRCDeliveryReport" },
  { id_F1Removal, "id-F1Removal" },
  { id_NetworkAccessRateReduction, "id-NetworkAccessRateReduction" },
  { 0, NULL }
};

static value_string_ext f1ap_ProcedureCode_vals_ext = VALUE_STRING_EXT_INIT(f1ap_ProcedureCode_vals);


static int
dissect_f1ap_ProcedureCode(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 73 "./asn1/f1ap/f1ap.cnf"
  f1ap_private_data_t *f1ap_data = f1ap_get_private_data(actx->pinfo);
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 255U, &f1ap_data->procedure_code, FALSE);



  return offset;
}



static int
dissect_f1ap_ProtocolExtensionID(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 67 "./asn1/f1ap/f1ap.cnf"
  f1ap_private_data_t *f1ap_data = f1ap_get_private_data(actx->pinfo);
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 65535U, &f1ap_data->protocol_extension_id, FALSE);




  return offset;
}


static const value_string f1ap_ProtocolIE_ID_vals[] = {
  { id_Cause, "id-Cause" },
  { id_Cells_Failed_to_be_Activated_List, "id-Cells-Failed-to-be-Activated-List" },
  { id_Cells_Failed_to_be_Activated_List_Item, "id-Cells-Failed-to-be-Activated-List-Item" },
  { id_Cells_to_be_Activated_List, "id-Cells-to-be-Activated-List" },
  { id_Cells_to_be_Activated_List_Item, "id-Cells-to-be-Activated-List-Item" },
  { id_Cells_to_be_Deactivated_List, "id-Cells-to-be-Deactivated-List" },
  { id_Cells_to_be_Deactivated_List_Item, "id-Cells-to-be-Deactivated-List-Item" },
  { id_CriticalityDiagnostics, "id-CriticalityDiagnostics" },
  { id_CUtoDURRCInformation, "id-CUtoDURRCInformation" },
  { id_Unknown_10, "id-Unknown-10" },
  { id_Unknown_11, "id-Unknown-11" },
  { id_DRBs_FailedToBeModified_Item, "id-DRBs-FailedToBeModified-Item" },
  { id_DRBs_FailedToBeModified_List, "id-DRBs-FailedToBeModified-List" },
  { id_DRBs_FailedToBeSetup_Item, "id-DRBs-FailedToBeSetup-Item" },
  { id_DRBs_FailedToBeSetup_List, "id-DRBs-FailedToBeSetup-List" },
  { id_DRBs_FailedToBeSetupMod_Item, "id-DRBs-FailedToBeSetupMod-Item" },
  { id_DRBs_FailedToBeSetupMod_List, "id-DRBs-FailedToBeSetupMod-List" },
  { id_DRBs_ModifiedConf_Item, "id-DRBs-ModifiedConf-Item" },
  { id_DRBs_ModifiedConf_List, "id-DRBs-ModifiedConf-List" },
  { id_DRBs_Modified_Item, "id-DRBs-Modified-Item" },
  { id_DRBs_Modified_List, "id-DRBs-Modified-List" },
  { id_DRBs_Required_ToBeModified_Item, "id-DRBs-Required-ToBeModified-Item" },
  { id_DRBs_Required_ToBeModified_List, "id-DRBs-Required-ToBeModified-List" },
  { id_DRBs_Required_ToBeReleased_Item, "id-DRBs-Required-ToBeReleased-Item" },
  { id_DRBs_Required_ToBeReleased_List, "id-DRBs-Required-ToBeReleased-List" },
  { id_DRBs_Setup_Item, "id-DRBs-Setup-Item" },
  { id_DRBs_Setup_List, "id-DRBs-Setup-List" },
  { id_DRBs_SetupMod_Item, "id-DRBs-SetupMod-Item" },
  { id_DRBs_SetupMod_List, "id-DRBs-SetupMod-List" },
  { id_DRBs_ToBeModified_Item, "id-DRBs-ToBeModified-Item" },
  { id_DRBs_ToBeModified_List, "id-DRBs-ToBeModified-List" },
  { id_DRBs_ToBeReleased_Item, "id-DRBs-ToBeReleased-Item" },
  { id_DRBs_ToBeReleased_List, "id-DRBs-ToBeReleased-List" },
  { id_DRBs_ToBeSetup_Item, "id-DRBs-ToBeSetup-Item" },
  { id_DRBs_ToBeSetup_List, "id-DRBs-ToBeSetup-List" },
  { id_DRBs_ToBeSetupMod_Item, "id-DRBs-ToBeSetupMod-Item" },
  { id_DRBs_ToBeSetupMod_List, "id-DRBs-ToBeSetupMod-List" },
  { id_DRXCycle, "id-DRXCycle" },
  { id_DUtoCURRCInformation, "id-DUtoCURRCInformation" },
  { id_gNB_CU_UE_F1AP_ID, "id-gNB-CU-UE-F1AP-ID" },
  { id_gNB_DU_UE_F1AP_ID, "id-gNB-DU-UE-F1AP-ID" },
  { id_gNB_DU_ID, "id-gNB-DU-ID" },
  { id_GNB_DU_Served_Cells_Item, "id-GNB-DU-Served-Cells-Item" },
  { id_gNB_DU_Served_Cells_List, "id-gNB-DU-Served-Cells-List" },
  { id_gNB_DU_Name, "id-gNB-DU-Name" },
  { id_NRCellID, "id-NRCellID" },
  { id_oldgNB_DU_UE_F1AP_ID, "id-oldgNB-DU-UE-F1AP-ID" },
  { id_ResetType, "id-ResetType" },
  { id_ResourceCoordinationTransferContainer, "id-ResourceCoordinationTransferContainer" },
  { id_RRCContainer, "id-RRCContainer" },
  { id_SCell_ToBeRemoved_Item, "id-SCell-ToBeRemoved-Item" },
  { id_SCell_ToBeRemoved_List, "id-SCell-ToBeRemoved-List" },
  { id_SCell_ToBeSetup_Item, "id-SCell-ToBeSetup-Item" },
  { id_SCell_ToBeSetup_List, "id-SCell-ToBeSetup-List" },
  { id_SCell_ToBeSetupMod_Item, "id-SCell-ToBeSetupMod-Item" },
  { id_SCell_ToBeSetupMod_List, "id-SCell-ToBeSetupMod-List" },
  { id_Served_Cells_To_Add_Item, "id-Served-Cells-To-Add-Item" },
  { id_Served_Cells_To_Add_List, "id-Served-Cells-To-Add-List" },
  { id_Served_Cells_To_Delete_Item, "id-Served-Cells-To-Delete-Item" },
  { id_Served_Cells_To_Delete_List, "id-Served-Cells-To-Delete-List" },
  { id_Served_Cells_To_Modify_Item, "id-Served-Cells-To-Modify-Item" },
  { id_Served_Cells_To_Modify_List, "id-Served-Cells-To-Modify-List" },
  { id_SpCell_ID, "id-SpCell-ID" },
  { id_SRBID, "id-SRBID" },
  { id_SRBs_FailedToBeSetup_Item, "id-SRBs-FailedToBeSetup-Item" },
  { id_SRBs_FailedToBeSetup_List, "id-SRBs-FailedToBeSetup-List" },
  { id_SRBs_FailedToBeSetupMod_Item, "id-SRBs-FailedToBeSetupMod-Item" },
  { id_SRBs_FailedToBeSetupMod_List, "id-SRBs-FailedToBeSetupMod-List" },
  { id_SRBs_Required_ToBeReleased_Item, "id-SRBs-Required-ToBeReleased-Item" },
  { id_SRBs_Required_ToBeReleased_List, "id-SRBs-Required-ToBeReleased-List" },
  { id_SRBs_ToBeReleased_Item, "id-SRBs-ToBeReleased-Item" },
  { id_SRBs_ToBeReleased_List, "id-SRBs-ToBeReleased-List" },
  { id_SRBs_ToBeSetup_Item, "id-SRBs-ToBeSetup-Item" },
  { id_SRBs_ToBeSetup_List, "id-SRBs-ToBeSetup-List" },
  { id_SRBs_ToBeSetupMod_Item, "id-SRBs-ToBeSetupMod-Item" },
  { id_SRBs_ToBeSetupMod_List, "id-SRBs-ToBeSetupMod-List" },
  { id_TimeToWait, "id-TimeToWait" },
  { id_TransactionID, "id-TransactionID" },
  { id_TransmissionActionIndicator, "id-TransmissionActionIndicator" },
  { id_UE_associatedLogicalF1_ConnectionItem, "id-UE-associatedLogicalF1-ConnectionItem" },
  { id_UE_associatedLogicalF1_ConnectionListResAck, "id-UE-associatedLogicalF1-ConnectionListResAck" },
  { id_gNB_CU_Name, "id-gNB-CU-Name" },
  { id_SCell_FailedtoSetup_List, "id-SCell-FailedtoSetup-List" },
  { id_SCell_FailedtoSetup_Item, "id-SCell-FailedtoSetup-Item" },
  { id_SCell_FailedtoSetupMod_List, "id-SCell-FailedtoSetupMod-List" },
  { id_SCell_FailedtoSetupMod_Item, "id-SCell-FailedtoSetupMod-Item" },
  { id_RRCReconfigurationCompleteIndicator, "id-RRCReconfigurationCompleteIndicator" },
  { id_Cells_Status_Item, "id-Cells-Status-Item" },
  { id_Cells_Status_List, "id-Cells-Status-List" },
  { id_Candidate_SpCell_List, "id-Candidate-SpCell-List" },
  { id_Candidate_SpCell_Item, "id-Candidate-SpCell-Item" },
  { id_Potential_SpCell_List, "id-Potential-SpCell-List" },
  { id_Potential_SpCell_Item, "id-Potential-SpCell-Item" },
  { id_FullConfiguration, "id-FullConfiguration" },
  { id_C_RNTI, "id-C-RNTI" },
  { id_SpCellULConfigured, "id-SpCellULConfigured" },
  { id_InactivityMonitoringRequest, "id-InactivityMonitoringRequest" },
  { id_InactivityMonitoringResponse, "id-InactivityMonitoringResponse" },
  { id_DRB_Activity_Item, "id-DRB-Activity-Item" },
  { id_DRB_Activity_List, "id-DRB-Activity-List" },
  { id_EUTRA_NR_CellResourceCoordinationReq_Container, "id-EUTRA-NR-CellResourceCoordinationReq-Container" },
  { id_EUTRA_NR_CellResourceCoordinationReqAck_Container, "id-EUTRA-NR-CellResourceCoordinationReqAck-Container" },
  { id_Unknown_103, "id-Unknown-103" },
  { id_Unknown_104, "id-Unknown-104" },
  { id_Protected_EUTRA_Resources_List, "id-Protected-EUTRA-Resources-List" },
  { id_RequestType, "id-RequestType" },
  { id_ServCellIndex, "id-ServCellIndex" },
  { id_RAT_FrequencyPriorityInformation, "id-RAT-FrequencyPriorityInformation" },
  { id_ExecuteDuplication, "id-ExecuteDuplication" },
  { id_Unknown_110, "id-Unknown-110" },
  { id_NRCGI, "id-NRCGI" },
  { id_PagingCell_Item, "id-PagingCell-Item" },
  { id_PagingCell_List, "id-PagingCell-List" },
  { id_PagingDRX, "id-PagingDRX" },
  { id_PagingPriority, "id-PagingPriority" },
  { id_SItype_List, "id-SItype-List" },
  { id_UEIdentityIndexValue, "id-UEIdentityIndexValue" },
  { id_gNB_CUSystemInformation, "id-gNB-CUSystemInformation" },
  { id_HandoverPreparationInformation, "id-HandoverPreparationInformation" },
  { id_GNB_CU_TNL_Association_To_Add_Item, "id-GNB-CU-TNL-Association-To-Add-Item" },
  { id_GNB_CU_TNL_Association_To_Add_List, "id-GNB-CU-TNL-Association-To-Add-List" },
  { id_GNB_CU_TNL_Association_To_Remove_Item, "id-GNB-CU-TNL-Association-To-Remove-Item" },
  { id_GNB_CU_TNL_Association_To_Remove_List, "id-GNB-CU-TNL-Association-To-Remove-List" },
  { id_GNB_CU_TNL_Association_To_Update_Item, "id-GNB-CU-TNL-Association-To-Update-Item" },
  { id_GNB_CU_TNL_Association_To_Update_List, "id-GNB-CU-TNL-Association-To-Update-List" },
  { id_MaskedIMEISV, "id-MaskedIMEISV" },
  { id_PagingIdentity, "id-PagingIdentity" },
  { id_DUtoCURRCContainer, "id-DUtoCURRCContainer" },
  { id_Cells_to_be_Barred_List, "id-Cells-to-be-Barred-List" },
  { id_Cells_to_be_Barred_Item, "id-Cells-to-be-Barred-Item" },
  { id_TAISliceSupportList, "id-TAISliceSupportList" },
  { id_GNB_CU_TNL_Association_Setup_List, "id-GNB-CU-TNL-Association-Setup-List" },
  { id_GNB_CU_TNL_Association_Setup_Item, "id-GNB-CU-TNL-Association-Setup-Item" },
  { id_GNB_CU_TNL_Association_Failed_To_Setup_List, "id-GNB-CU-TNL-Association-Failed-To-Setup-List" },
  { id_GNB_CU_TNL_Association_Failed_To_Setup_Item, "id-GNB-CU-TNL-Association-Failed-To-Setup-Item" },
  { id_DRB_Notify_Item, "id-DRB-Notify-Item" },
  { id_DRB_Notify_List, "id-DRB-Notify-List" },
  { id_NotficationControl, "id-NotficationControl" },
  { id_RANAC, "id-RANAC" },
  { id_PWSSystemInformation, "id-PWSSystemInformation" },
  { id_RepetitionPeriod, "id-RepetitionPeriod" },
  { id_NumberofBroadcastRequest, "id-NumberofBroadcastRequest" },
  { id_Unknown_143, "id-Unknown-143" },
  { id_Cells_To_Be_Broadcast_List, "id-Cells-To-Be-Broadcast-List" },
  { id_Cells_To_Be_Broadcast_Item, "id-Cells-To-Be-Broadcast-Item" },
  { id_Cells_Broadcast_Completed_List, "id-Cells-Broadcast-Completed-List" },
  { id_Cells_Broadcast_Completed_Item, "id-Cells-Broadcast-Completed-Item" },
  { id_Broadcast_To_Be_Cancelled_List, "id-Broadcast-To-Be-Cancelled-List" },
  { id_Broadcast_To_Be_Cancelled_Item, "id-Broadcast-To-Be-Cancelled-Item" },
  { id_Cells_Broadcast_Cancelled_List, "id-Cells-Broadcast-Cancelled-List" },
  { id_Cells_Broadcast_Cancelled_Item, "id-Cells-Broadcast-Cancelled-Item" },
  { id_NR_CGI_List_For_Restart_List, "id-NR-CGI-List-For-Restart-List" },
  { id_NR_CGI_List_For_Restart_Item, "id-NR-CGI-List-For-Restart-Item" },
  { id_PWS_Failed_NR_CGI_List, "id-PWS-Failed-NR-CGI-List" },
  { id_PWS_Failed_NR_CGI_Item, "id-PWS-Failed-NR-CGI-Item" },
  { id_ConfirmedUEID, "id-ConfirmedUEID" },
  { id_Cancel_all_Warning_Messages_Indicator, "id-Cancel-all-Warning-Messages-Indicator" },
  { id_GNB_DU_UE_AMBR_UL, "id-GNB-DU-UE-AMBR-UL" },
  { id_DRXConfigurationIndicator, "id-DRXConfigurationIndicator" },
  { id_RLC_Status, "id-RLC-Status" },
  { id_DLPDCPSNLength, "id-DLPDCPSNLength" },
  { id_GNB_DUConfigurationQuery, "id-GNB-DUConfigurationQuery" },
  { id_MeasurementTimingConfiguration, "id-MeasurementTimingConfiguration" },
  { id_DRB_Information, "id-DRB-Information" },
  { id_ServingPLMN, "id-ServingPLMN" },
  { id_Unknown_166, "id-Unknown-166" },
  { id_Unknown_167, "id-Unknown-167" },
  { id_Protected_EUTRA_Resources_Item, "id-Protected-EUTRA-Resources-Item" },
  { id_Unknown_169, "id-Unknown-169" },
  { id_GNB_CU_RRC_Version, "id-GNB-CU-RRC-Version" },
  { id_GNB_DU_RRC_Version, "id-GNB-DU-RRC-Version" },
  { id_GNBDUOverloadInformation, "id-GNBDUOverloadInformation" },
  { id_CellGroupConfig, "id-CellGroupConfig" },
  { id_RLCFailureIndication, "id-RLCFailureIndication" },
  { id_UplinkTxDirectCurrentListInformation, "id-UplinkTxDirectCurrentListInformation" },
  { id_DC_Based_Duplication_Configured, "id-DC-Based-Duplication-Configured" },
  { id_DC_Based_Duplication_Activation, "id-DC-Based-Duplication-Activation" },
  { id_SULAccessIndication, "id-SULAccessIndication" },
  { id_AvailablePLMNList, "id-AvailablePLMNList" },
  { id_PDUSessionID, "id-PDUSessionID" },
  { id_ULPDUSessionAggregateMaximumBitRate, "id-ULPDUSessionAggregateMaximumBitRate" },
  { id_ServingCellMO, "id-ServingCellMO" },
  { id_QoSFlowMappingIndication, "id-QoSFlowMappingIndication" },
  { id_RRCDeliveryStatusRequest, "id-RRCDeliveryStatusRequest" },
  { id_RRCDeliveryStatus, "id-RRCDeliveryStatus" },
  { id_BearerTypeChange, "id-BearerTypeChange" },
  { id_RLCMode, "id-RLCMode" },
  { id_Duplication_Activation, "id-Duplication-Activation" },
  { id_Dedicated_SIDelivery_NeededUE_List, "id-Dedicated-SIDelivery-NeededUE-List" },
  { id_Dedicated_SIDelivery_NeededUE_Item, "id-Dedicated-SIDelivery-NeededUE-Item" },
  { id_DRX_LongCycleStartOffset, "id-DRX-LongCycleStartOffset" },
  { id_ULPDCPSNLength, "id-ULPDCPSNLength" },
  { id_SelectedBandCombinationIndex, "id-SelectedBandCombinationIndex" },
  { id_SelectedFeatureSetEntryIndex, "id-SelectedFeatureSetEntryIndex" },
  { id_ResourceCoordinationTransferInformation, "id-ResourceCoordinationTransferInformation" },
  { id_ExtendedServedPLMNs_List, "id-ExtendedServedPLMNs-List" },
  { id_ExtendedAvailablePLMN_List, "id-ExtendedAvailablePLMN-List" },
  { id_Associated_SCell_List, "id-Associated-SCell-List" },
  { id_latest_RRC_Version_Enhanced, "id-latest-RRC-Version-Enhanced" },
  { id_Associated_SCell_Item, "id-Associated-SCell-Item" },
  { id_Cell_Direction, "id-Cell-Direction" },
  { id_SRBs_Setup_List, "id-SRBs-Setup-List" },
  { id_SRBs_Setup_Item, "id-SRBs-Setup-Item" },
  { id_SRBs_SetupMod_List, "id-SRBs-SetupMod-List" },
  { id_SRBs_SetupMod_Item, "id-SRBs-SetupMod-Item" },
  { id_SRBs_Modified_List, "id-SRBs-Modified-List" },
  { id_SRBs_Modified_Item, "id-SRBs-Modified-Item" },
  { id_Ph_InfoSCG, "id-Ph-InfoSCG" },
  { id_RequestedBandCombinationIndex, "id-RequestedBandCombinationIndex" },
  { id_RequestedFeatureSetEntryIndex, "id-RequestedFeatureSetEntryIndex" },
  { id_RequestedP_MaxFR2, "id-RequestedP-MaxFR2" },
  { id_DRX_Config, "id-DRX-Config" },
  { id_IgnoreResourceCoordinationContainer, "id-IgnoreResourceCoordinationContainer" },
  { id_UEAssistanceInformation, "id-UEAssistanceInformation" },
  { id_NeedforGap, "id-NeedforGap" },
  { id_PagingOrigin, "id-PagingOrigin" },
  { id_new_gNB_CU_UE_F1AP_ID, "id-new-gNB-CU-UE-F1AP-ID" },
  { id_RedirectedRRCmessage, "id-RedirectedRRCmessage" },
  { id_new_gNB_DU_UE_F1AP_ID, "id-new-gNB-DU-UE-F1AP-ID" },
  { id_NotificationInformation, "id-NotificationInformation" },
  { id_PLMNAssistanceInfoForNetShar, "id-PLMNAssistanceInfoForNetShar" },
  { id_UEContextNotRetrievable, "id-UEContextNotRetrievable" },
  { id_BPLMN_ID_Info_List, "id-BPLMN-ID-Info-List" },
  { id_SelectedPLMNID, "id-SelectedPLMNID" },
  { id_UAC_Assistance_Info, "id-UAC-Assistance-Info" },
  { id_RANUEID, "id-RANUEID" },
  { id_GNB_DU_TNL_Association_To_Remove_Item, "id-GNB-DU-TNL-Association-To-Remove-Item" },
  { id_GNB_DU_TNL_Association_To_Remove_List, "id-GNB-DU-TNL-Association-To-Remove-List" },
  { id_TNLAssociationTransportLayerAddressgNBDU, "id-TNLAssociationTransportLayerAddressgNBDU" },
  { id_portNumber, "id-portNumber" },
  { id_AdditionalSIBMessageList, "id-AdditionalSIBMessageList" },
  { id_Cell_Type, "id-Cell-Type" },
  { id_IgnorePRACHConfiguration, "id-IgnorePRACHConfiguration" },
  { id_CG_Config, "id-CG-Config" },
  { id_PDCCH_BlindDetectionSCG, "id-PDCCH-BlindDetectionSCG" },
  { id_Requested_PDCCH_BlindDetectionSCG, "id-Requested-PDCCH-BlindDetectionSCG" },
  { id_Ph_InfoMCG, "id-Ph-InfoMCG" },
  { id_MeasGapSharingConfig, "id-MeasGapSharingConfig" },
  { id_systemInformationAreaID, "id-systemInformationAreaID" },
  { id_areaScope, "id-areaScope" },
  { id_RRCContainer_RRCSetupComplete, "id-RRCContainer-RRCSetupComplete" },
  { 0, NULL }
};

static value_string_ext f1ap_ProtocolIE_ID_vals_ext = VALUE_STRING_EXT_INIT(f1ap_ProtocolIE_ID_vals);


static int
dissect_f1ap_ProtocolIE_ID(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 55 "./asn1/f1ap/f1ap.cnf"
  f1ap_private_data_t *f1ap_data = f1ap_get_private_data(actx->pinfo);
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 65535U, &f1ap_data->protocol_ie_id, FALSE);




#line 59 "./asn1/f1ap/f1ap.cnf"
  if (tree) {
    proto_item_append_text(proto_item_get_parent_nth(actx->created_item, 2), ": %s",
                           val_to_str_ext(f1ap_data->protocol_ie_id, &f1ap_ProtocolIE_ID_vals_ext, "unknown (%d)"));
  }


  return offset;
}


static const value_string f1ap_TriggeringMessage_vals[] = {
  {   0, "initiating-message" },
  {   1, "successful-outcome" },
  {   2, "unsuccessful-outcome" },
  { 0, NULL }
};


static int
dissect_f1ap_TriggeringMessage(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     3, NULL, FALSE, 0, NULL);

  return offset;
}



static int
dissect_f1ap_T_ie_field_value(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_open_type_pdu_new(tvb, offset, actx, tree, hf_index, dissect_ProtocolIEFieldValue);

  return offset;
}


static const per_sequence_t ProtocolIE_Field_sequence[] = {
  { &hf_f1ap_id             , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_f1ap_ProtocolIE_ID },
  { &hf_f1ap_criticality    , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_f1ap_Criticality },
  { &hf_f1ap_ie_field_value , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_f1ap_T_ie_field_value },
  { NULL, 0, 0, NULL }
};

static int
dissect_f1ap_ProtocolIE_Field(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_f1ap_ProtocolIE_Field, ProtocolIE_Field_sequence);

  return offset;
}


static const per_sequence_t ProtocolIE_Container_sequence_of[1] = {
  { &hf_f1ap_ProtocolIE_Container_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_f1ap_ProtocolIE_Field },
};

static int
dissect_f1ap_ProtocolIE_Container(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_f1ap_ProtocolIE_Container, ProtocolIE_Container_sequence_of,
                                                  0, maxProtocolIEs, FALSE);

  return offset;
}



static int
dissect_f1ap_ProtocolIE_SingleContainer(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_f1ap_ProtocolIE_Field(tvb, offset, actx, tree, hf_index);

  return offset;
}



static int
dissect_f1ap_T_extensionValue(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_open_type_pdu_new(tvb, offset, actx, tree, hf_index, dissect_ProtocolExtensionFieldExtensionValue);

  return offset;
}


static const per_sequence_t ProtocolExtensionField_sequence[] = {
  { &hf_f1ap_ext_id         , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_f1ap_ProtocolExtensionID },
  { &hf_f1ap_criticality    , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_f1ap_Criticality },
  { &hf_f1ap_extensionValue , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_f1ap_T_extensionValue },
  { NULL, 0, 0, NULL }
};

static int
dissect_f1ap_ProtocolExtensionField(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_f1ap_ProtocolExtensionField, ProtocolExtensionField_sequence);

  return offset;
}


static const per_sequence_t ProtocolExtensionContainer_sequence_of[1] = {
  { &hf_f1ap_ProtocolExtensionContainer_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_f1ap_ProtocolExtensionField },
};

static int
dissect_f1ap_ProtocolExtensionContainer(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_f1ap_ProtocolExtensionContainer, ProtocolExtensionContainer_sequence_of,
                                                  1, maxProtocolExtensions, FALSE);

  return offset;
}



static int
dissect_f1ap_T_value(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 100 "./asn1/f1ap/f1ap.cnf"
  f1ap_private_data_t *f1ap_data = f1ap_get_private_data(actx->pinfo);
  if (f1ap_data->obj_id) {
    offset = call_per_oid_callback(f1ap_data->obj_id, tvb, actx->pinfo, tree, offset, actx, hf_index);
  } else {
  offset = dissect_per_open_type(tvb, offset, actx, tree, hf_index, NULL);

  }



  return offset;
}


static const per_sequence_t PrivateIE_Field_sequence[] = {
  { &hf_f1ap_private_id     , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_f1ap_PrivateIE_ID },
  { &hf_f1ap_criticality    , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_f1ap_Criticality },
  { &hf_f1ap_value          , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_f1ap_T_value },
  { NULL, 0, 0, NULL }
};

static int
dissect_f1ap_PrivateIE_Field(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_f1ap_PrivateIE_Field, PrivateIE_Field_sequence);

  return offset;
}


static const per_sequence_t PrivateIE_Container_sequence_of[1] = {
  { &hf_f1ap_PrivateIE_Container_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_f1ap_PrivateIE_Field },
};

static int
dissect_f1ap_PrivateIE_Container(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_f1ap_PrivateIE_Container, PrivateIE_Container_sequence_of,
                                                  1, maxPrivateIEs, FALSE);

  return offset;
}



static int
dissect_f1ap_T_additionalSIB(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 686 "./asn1/f1ap/f1ap.cnf"
  tvbuff_t *param_tvb = NULL;
  offset = dissect_per_octet_string(tvb, offset, actx, tree, hf_index,
                                       NO_BOUND, NO_BOUND, FALSE, &param_tvb);

  if (param_tvb) {
    f1ap_private_data_t *f1ap_data = f1ap_get_private_data(actx->pinfo);
    proto_tree *subtree = proto_item_add_subtree(actx->created_item, ett_f1ap_sIBmessage);
    switch (f1ap_data->sib_type) {
    case 6:
      dissect_nr_rrc_SIB6_PDU(param_tvb, actx->pinfo, subtree, NULL);
      break;
    case 7:
      dissect_nr_rrc_SIB7_PDU(param_tvb, actx->pinfo, subtree, NULL);
      break;
    case 8:
      dissect_nr_rrc_SIB8_PDU(param_tvb, actx->pinfo, subtree, NULL);
      break;
    default:
      break;
    }
  }



  return offset;
}


static const per_sequence_t AdditionalSIBMessageList_Item_sequence[] = {
  { &hf_f1ap_additionalSIB  , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_f1ap_T_additionalSIB },
  { &hf_f1ap_iE_Extensions  , ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_f1ap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_f1ap_AdditionalSIBMessageList_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_f1ap_AdditionalSIBMessageList_Item, AdditionalSIBMessageList_Item_sequence);

  return offset;
}


static const per_sequence_t AdditionalSIBMessageList_sequence_of[1] = {
  { &hf_f1ap_AdditionalSIBMessageList_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_f1ap_AdditionalSIBMessageList_Item },
};

static int
dissect_f1ap_AdditionalSIBMessageList(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_f1ap_AdditionalSIBMessageList, AdditionalSIBMessageList_sequence_of,
                                                  1, maxnoofAdditionalSIBs, FALSE);

  return offset;
}


static const value_string f1ap_PriorityLevel_vals[] = {
  {   0, "spare" },
  {   1, "highest" },
  {  14, "lowest" },
  {  15, "no-priority" },
  { 0, NULL }
};


static int
dissect_f1ap_PriorityLevel(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 15U, NULL, FALSE);

  return offset;
}


static const value_string f1ap_Pre_emptionCapability_vals[] = {
  {   0, "shall-not-trigger-pre-emption" },
  {   1, "may-trigger-pre-emption" },
  { 0, NULL }
};


static int
dissect_f1ap_Pre_emptionCapability(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     2, NULL, FALSE, 0, NULL);

  return offset;
}


static const value_string f1ap_Pre_emptionVulnerability_vals[] = {
  {   0, "not-pre-emptable" },
  {   1, "pre-emptable" },
  { 0, NULL }
};


static int
dissect_f1ap_Pre_emptionVulnerability(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     2, NULL, FALSE, 0, NULL);

  return offset;
}


static const per_sequence_t AllocationAndRetentionPriority_sequence[] = {
  { &hf_f1ap_priorityLevel  , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_f1ap_PriorityLevel },
  { &hf_f1ap_pre_emptionCapability, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_f1ap_Pre_emptionCapability },
  { &hf_f1ap_pre_emptionVulnerability, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_f1ap_Pre_emptionVulnerability },
  { &hf_f1ap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_f1ap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_f1ap_AllocationAndRetentionPriority(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_f1ap_AllocationAndRetentionPriority, AllocationAndRetentionPriority_sequence);

  return offset;
}



static int
dissect_f1ap_PLMN_Identity(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 853 "./asn1/f1ap/f1ap.cnf"
  tvbuff_t *param_tvb = NULL;
  offset = dissect_per_octet_string(tvb, offset, actx, tree, hf_index,
                                       3, 3, FALSE, &param_tvb);

  if (param_tvb) {
    proto_tree *subtree = proto_item_add_subtree(actx->created_item, ett_f1ap_PLMN_Identity);
    dissect_e212_mcc_mnc(param_tvb, actx->pinfo, subtree, 0, E212_NONE, FALSE);
  }



  return offset;
}



static int
dissect_f1ap_NRCellIdentity(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_bit_string(tvb, offset, actx, tree, hf_index,
                                     36, 36, FALSE, NULL, 0, NULL, NULL);

  return offset;
}


static const per_sequence_t NRCGI_sequence[] = {
  { &hf_f1ap_pLMN_Identity  , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_f1ap_PLMN_Identity },
  { &hf_f1ap_nRCellIdentity , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_f1ap_NRCellIdentity },
  { &hf_f1ap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_f1ap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_f1ap_NRCGI(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_f1ap_NRCGI, NRCGI_sequence);

  return offset;
}


static const per_sequence_t Associated_SCell_Item_sequence[] = {
  { &hf_f1ap_sCell_ID       , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_f1ap_NRCGI },
  { &hf_f1ap_iE_Extensions  , ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_f1ap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_f1ap_Associated_SCell_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_f1ap_Associated_SCell_Item, Associated_SCell_Item_sequence);

  return offset;
}


static const per_sequence_t AvailablePLMNList_Item_sequence[] = {
  { &hf_f1ap_pLMNIdentity   , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_f1ap_PLMN_Identity },
  { &hf_f1ap_iE_Extensions  , ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_f1ap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_f1ap_AvailablePLMNList_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_f1ap_AvailablePLMNList_Item, AvailablePLMNList_Item_sequence);

  return offset;
}


static const per_sequence_t AvailablePLMNList_sequence_of[1] = {
  { &hf_f1ap_AvailablePLMNList_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_f1ap_AvailablePLMNList_Item },
};

static int
dissect_f1ap_AvailablePLMNList(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_f1ap_AvailablePLMNList, AvailablePLMNList_sequence_of,
                                                  1, maxnoofBPLMNs, FALSE);

  return offset;
}



static int
dissect_f1ap_AveragingWindow(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 4095U, NULL, TRUE);

  return offset;
}


static const value_string f1ap_AreaScope_vals[] = {
  {   0, "true" },
  { 0, NULL }
};


static int
dissect_f1ap_AreaScope(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     1, NULL, TRUE, 0, NULL);

  return offset;
}



static int
dissect_f1ap_BitRate(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer_64b(tvb, offset, actx, tree, hf_index,
                                                            0U, G_GUINT64_CONSTANT(4000000000000), NULL, TRUE);

  return offset;
}


static const value_string f1ap_BearerTypeChange_vals[] = {
  {   0, "true" },
  { 0, NULL }
};


static int
dissect_f1ap_BearerTypeChange(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     1, NULL, TRUE, 0, NULL);

  return offset;
}


static const per_sequence_t ExtendedAvailablePLMN_Item_sequence[] = {
  { &hf_f1ap_pLMNIdentity   , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_f1ap_PLMN_Identity },
  { &hf_f1ap_iE_Extensions  , ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_f1ap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_f1ap_ExtendedAvailablePLMN_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_f1ap_ExtendedAvailablePLMN_Item, ExtendedAvailablePLMN_Item_sequence);

  return offset;
}


static const per_sequence_t ExtendedAvailablePLMN_List_sequence_of[1] = {
  { &hf_f1ap_ExtendedAvailablePLMN_List_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_f1ap_ExtendedAvailablePLMN_Item },
};

static int
dissect_f1ap_ExtendedAvailablePLMN_List(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_f1ap_ExtendedAvailablePLMN_List, ExtendedAvailablePLMN_List_sequence_of,
                                                  1, maxnoofExtendedBPLMNs, FALSE);

  return offset;
}



static int
dissect_f1ap_FiveGS_TAC(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 972 "./asn1/f1ap/f1ap.cnf"
  tvbuff_t *parameter_tvb = NULL;
  offset = dissect_per_octet_string(tvb, offset, actx, tree, -1,
                                       3, 3, FALSE, &parameter_tvb);

  if (parameter_tvb) {
    actx->created_item = proto_tree_add_item(tree, hf_index, parameter_tvb, 0, 3, ENC_BIG_ENDIAN);
  }



  return offset;
}



static int
dissect_f1ap_RANAC(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 255U, NULL, FALSE);

  return offset;
}


static const per_sequence_t BPLMN_ID_Info_Item_sequence[] = {
  { &hf_f1ap_pLMN_Identity_List, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_f1ap_AvailablePLMNList },
  { &hf_f1ap_extended_PLMN_Identity_List, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_f1ap_ExtendedAvailablePLMN_List },
  { &hf_f1ap_fiveGS_TAC     , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_f1ap_FiveGS_TAC },
  { &hf_f1ap_nr_cell_ID     , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_f1ap_NRCellIdentity },
  { &hf_f1ap_ranac          , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_f1ap_RANAC },
  { &hf_f1ap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_f1ap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_f1ap_BPLMN_ID_Info_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_f1ap_BPLMN_ID_Info_Item, BPLMN_ID_Info_Item_sequence);

  return offset;
}


static const per_sequence_t BPLMN_ID_Info_List_sequence_of[1] = {
  { &hf_f1ap_BPLMN_ID_Info_List_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_f1ap_BPLMN_ID_Info_Item },
};

static int
dissect_f1ap_BPLMN_ID_Info_List(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_f1ap_BPLMN_ID_Info_List, BPLMN_ID_Info_List_sequence_of,
                                                  1, maxnoofBPLMNsNRminus1, FALSE);

  return offset;
}


static const per_sequence_t ServedPLMNs_Item_sequence[] = {
  { &hf_f1ap_pLMN_Identity  , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_f1ap_PLMN_Identity },
  { &hf_f1ap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_f1ap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_f1ap_ServedPLMNs_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_f1ap_ServedPLMNs_Item, ServedPLMNs_Item_sequence);

  return offset;
}


static const per_sequence_t ServedPLMNs_List_sequence_of[1] = {
  { &hf_f1ap_ServedPLMNs_List_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_f1ap_ServedPLMNs_Item },
};

static int
dissect_f1ap_ServedPLMNs_List(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_f1ap_ServedPLMNs_List, ServedPLMNs_List_sequence_of,
                                                  1, maxnoofBPLMNs, FALSE);

  return offset;
}


static const value_string f1ap_Cancel_all_Warning_Messages_Indicator_vals[] = {
  {   0, "true" },
  { 0, NULL }
};


static int
dissect_f1ap_Cancel_all_Warning_Messages_Indicator(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     1, NULL, TRUE, 0, NULL);

  return offset;
}


static const per_sequence_t Candidate_SpCell_Item_sequence[] = {
  { &hf_f1ap_candidate_SpCell_ID, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_f1ap_NRCGI },
  { &hf_f1ap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_f1ap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_f1ap_Candidate_SpCell_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_f1ap_Candidate_SpCell_Item, Candidate_SpCell_Item_sequence);

  return offset;
}


static const value_string f1ap_CauseRadioNetwork_vals[] = {
  {   0, "unspecified" },
  {   1, "rl-failure-rlc" },
  {   2, "unknown-or-already-allocated-gnb-cu-ue-f1ap-id" },
  {   3, "unknown-or-already-allocated-gnb-du-ue-f1ap-id" },
  {   4, "unknown-or-inconsistent-pair-of-ue-f1ap-id" },
  {   5, "interaction-with-other-procedure" },
  {   6, "not-supported-qci-Value" },
  {   7, "action-desirable-for-radio-reasons" },
  {   8, "no-radio-resources-available" },
  {   9, "procedure-cancelled" },
  {  10, "normal-release" },
  {  11, "cell-not-available" },
  {  12, "rl-failure-others" },
  {  13, "ue-rejection" },
  {  14, "resources-not-available-for-the-slice" },
  {  15, "amf-initiated-abnormal-release" },
  {  16, "release-due-to-pre-emption" },
  {  17, "plmn-not-served-by-the-gNB-CU" },
  {  18, "multiple-drb-id-instances" },
  {  19, "unknown-drb-id" },
  { 0, NULL }
};


static int
dissect_f1ap_CauseRadioNetwork(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     11, NULL, TRUE, 9, NULL);

  return offset;
}


static const value_string f1ap_CauseTransport_vals[] = {
  {   0, "unspecified" },
  {   1, "transport-resource-unavailable" },
  { 0, NULL }
};


static int
dissect_f1ap_CauseTransport(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     2, NULL, TRUE, 0, NULL);

  return offset;
}


static const value_string f1ap_CauseProtocol_vals[] = {
  {   0, "transfer-syntax-error" },
  {   1, "abstract-syntax-error-reject" },
  {   2, "abstract-syntax-error-ignore-and-notify" },
  {   3, "message-not-compatible-with-receiver-state" },
  {   4, "semantic-error" },
  {   5, "abstract-syntax-error-falsely-constructed-message" },
  {   6, "unspecified" },
  { 0, NULL }
};


static int
dissect_f1ap_CauseProtocol(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     7, NULL, TRUE, 0, NULL);

  return offset;
}


static const value_string f1ap_CauseMisc_vals[] = {
  {   0, "control-processing-overload" },
  {   1, "not-enough-user-plane-processing-resources" },
  {   2, "hardware-failure" },
  {   3, "om-intervention" },
  {   4, "unspecified" },
  { 0, NULL }
};


static int
dissect_f1ap_CauseMisc(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     5, NULL, TRUE, 0, NULL);

  return offset;
}


static const value_string f1ap_Cause_vals[] = {
  {   0, "radioNetwork" },
  {   1, "transport" },
  {   2, "protocol" },
  {   3, "misc" },
  {   4, "choice-extension" },
  { 0, NULL }
};

static const per_choice_t Cause_choice[] = {
  {   0, &hf_f1ap_radioNetwork   , ASN1_NO_EXTENSIONS     , dissect_f1ap_CauseRadioNetwork },
  {   1, &hf_f1ap_transport      , ASN1_NO_EXTENSIONS     , dissect_f1ap_CauseTransport },
  {   2, &hf_f1ap_protocol       , ASN1_NO_EXTENSIONS     , dissect_f1ap_CauseProtocol },
  {   3, &hf_f1ap_misc           , ASN1_NO_EXTENSIONS     , dissect_f1ap_CauseMisc },
  {   4, &hf_f1ap_choice_extension, ASN1_NO_EXTENSIONS     , dissect_f1ap_ProtocolIE_SingleContainer },
  { 0, NULL, 0, NULL }
};

static int
dissect_f1ap_Cause(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_f1ap_Cause, Cause_choice,
                                 NULL);

  return offset;
}



static int
dissect_f1ap_CellGroupConfig(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 930 "./asn1/f1ap/f1ap.cnf"
  tvbuff_t *param_tvb = NULL;
  offset = dissect_per_octet_string(tvb, offset, actx, tree, hf_index,
                                       NO_BOUND, NO_BOUND, FALSE, &param_tvb);

  if (param_tvb) {
    proto_tree *subtree = proto_item_add_subtree(actx->created_item, ett_f1ap_CellGroupConfig);
    dissect_nr_rrc_CellGroupConfig_PDU(param_tvb, actx->pinfo, subtree, NULL);
  }



  return offset;
}


static const value_string f1ap_Cell_Direction_vals[] = {
  {   0, "dl-only" },
  {   1, "ul-only" },
  { 0, NULL }
};


static int
dissect_f1ap_Cell_Direction(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     2, NULL, FALSE, 0, NULL);

  return offset;
}


static const per_sequence_t Cells_Failed_to_be_Activated_List_Item_sequence[] = {
  { &hf_f1ap_nRCGI          , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_f1ap_NRCGI },
  { &hf_f1ap_cause          , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_f1ap_Cause },
  { &hf_f1ap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_f1ap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_f1ap_Cells_Failed_to_be_Activated_List_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_f1ap_Cells_Failed_to_be_Activated_List_Item, Cells_Failed_to_be_Activated_List_Item_sequence);

  return offset;
}


static const value_string f1ap_Service_State_vals[] = {
  {   0, "in-service" },
  {   1, "out-of-service" },
  { 0, NULL }
};


static int
dissect_f1ap_Service_State(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     2, NULL, TRUE, 0, NULL);

  return offset;
}


static const value_string f1ap_T_switchingOffOngoing_vals[] = {
  {   0, "true" },
  { 0, NULL }
};


static int
dissect_f1ap_T_switchingOffOngoing(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     1, NULL, TRUE, 0, NULL);

  return offset;
}


static const per_sequence_t Service_Status_sequence[] = {
  { &hf_f1ap_service_state  , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_f1ap_Service_State },
  { &hf_f1ap_switchingOffOngoing, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_f1ap_T_switchingOffOngoing },
  { &hf_f1ap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_f1ap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_f1ap_Service_Status(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_f1ap_Service_Status, Service_Status_sequence);

  return offset;
}


static const per_sequence_t Cells_Status_Item_sequence[] = {
  { &hf_f1ap_nRCGI          , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_f1ap_NRCGI },
  { &hf_f1ap_service_status , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_f1ap_Service_Status },
  { &hf_f1ap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_f1ap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_f1ap_Cells_Status_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_f1ap_Cells_Status_Item, Cells_Status_Item_sequence);

  return offset;
}


static const per_sequence_t Cells_To_Be_Broadcast_Item_sequence[] = {
  { &hf_f1ap_nRCGI          , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_f1ap_NRCGI },
  { &hf_f1ap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_f1ap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_f1ap_Cells_To_Be_Broadcast_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_f1ap_Cells_To_Be_Broadcast_Item, Cells_To_Be_Broadcast_Item_sequence);

  return offset;
}


static const per_sequence_t Cells_Broadcast_Completed_Item_sequence[] = {
  { &hf_f1ap_nRCGI          , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_f1ap_NRCGI },
  { &hf_f1ap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_f1ap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_f1ap_Cells_Broadcast_Completed_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_f1ap_Cells_Broadcast_Completed_Item, Cells_Broadcast_Completed_Item_sequence);

  return offset;
}


static const per_sequence_t Broadcast_To_Be_Cancelled_Item_sequence[] = {
  { &hf_f1ap_nRCGI          , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_f1ap_NRCGI },
  { &hf_f1ap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_f1ap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_f1ap_Broadcast_To_Be_Cancelled_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_f1ap_Broadcast_To_Be_Cancelled_Item, Broadcast_To_Be_Cancelled_Item_sequence);

  return offset;
}



static int
dissect_f1ap_NumberOfBroadcasts(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 65535U, NULL, FALSE);

  return offset;
}


static const per_sequence_t Cells_Broadcast_Cancelled_Item_sequence[] = {
  { &hf_f1ap_nRCGI          , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_f1ap_NRCGI },
  { &hf_f1ap_numberOfBroadcasts, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_f1ap_NumberOfBroadcasts },
  { &hf_f1ap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_f1ap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_f1ap_Cells_Broadcast_Cancelled_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_f1ap_Cells_Broadcast_Cancelled_Item, Cells_Broadcast_Cancelled_Item_sequence);

  return offset;
}



static int
dissect_f1ap_NRPCI(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 1007U, NULL, FALSE);

  return offset;
}


static const per_sequence_t Cells_to_be_Activated_List_Item_sequence[] = {
  { &hf_f1ap_nRCGI          , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_f1ap_NRCGI },
  { &hf_f1ap_nRPCI          , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_f1ap_NRPCI },
  { &hf_f1ap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_f1ap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_f1ap_Cells_to_be_Activated_List_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_f1ap_Cells_to_be_Activated_List_Item, Cells_to_be_Activated_List_Item_sequence);

  return offset;
}


static const per_sequence_t Cells_to_be_Deactivated_List_Item_sequence[] = {
  { &hf_f1ap_nRCGI          , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_f1ap_NRCGI },
  { &hf_f1ap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_f1ap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_f1ap_Cells_to_be_Deactivated_List_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_f1ap_Cells_to_be_Deactivated_List_Item, Cells_to_be_Deactivated_List_Item_sequence);

  return offset;
}


static const value_string f1ap_CellBarred_vals[] = {
  {   0, "barred" },
  {   1, "not-barred" },
  { 0, NULL }
};


static int
dissect_f1ap_CellBarred(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     2, NULL, TRUE, 0, NULL);

  return offset;
}


static const per_sequence_t Cells_to_be_Barred_Item_sequence[] = {
  { &hf_f1ap_nRCGI          , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_f1ap_NRCGI },
  { &hf_f1ap_cellBarred     , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_f1ap_CellBarred },
  { &hf_f1ap_iE_Extensions  , ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_f1ap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_f1ap_Cells_to_be_Barred_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_f1ap_Cells_to_be_Barred_Item, Cells_to_be_Barred_Item_sequence);

  return offset;
}


static const value_string f1ap_CellSize_vals[] = {
  {   0, "verysmall" },
  {   1, "small" },
  {   2, "medium" },
  {   3, "large" },
  { 0, NULL }
};


static int
dissect_f1ap_CellSize(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     4, NULL, TRUE, 0, NULL);

  return offset;
}


static const per_sequence_t CellType_sequence[] = {
  { &hf_f1ap_cellSize       , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_f1ap_CellSize },
  { &hf_f1ap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_f1ap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_f1ap_CellType(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_f1ap_CellType, CellType_sequence);

  return offset;
}


static const value_string f1ap_CellULConfigured_vals[] = {
  {   0, "none" },
  {   1, "ul" },
  {   2, "sul" },
  {   3, "ul-and-sul" },
  { 0, NULL }
};


static int
dissect_f1ap_CellULConfigured(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     4, NULL, TRUE, 0, NULL);

  return offset;
}



static int
dissect_f1ap_BIT_STRING_SIZE_48(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_bit_string(tvb, offset, actx, tree, hf_index,
                                     48, 48, FALSE, NULL, 0, NULL, NULL);

  return offset;
}


static const value_string f1ap_CNUEPagingIdentity_vals[] = {
  {   0, "fiveG-S-TMSI" },
  {   1, "choice-extension" },
  { 0, NULL }
};

static const per_choice_t CNUEPagingIdentity_choice[] = {
  {   0, &hf_f1ap_fiveG_S_TMSI   , ASN1_NO_EXTENSIONS     , dissect_f1ap_BIT_STRING_SIZE_48 },
  {   1, &hf_f1ap_choice_extension, ASN1_NO_EXTENSIONS     , dissect_f1ap_ProtocolIE_SingleContainer },
  { 0, NULL, 0, NULL }
};

static int
dissect_f1ap_CNUEPagingIdentity(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_f1ap_CNUEPagingIdentity, CNUEPagingIdentity_choice,
                                 NULL);

  return offset;
}



static int
dissect_f1ap_TransportLayerAddress(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 1089 "./asn1/f1ap/f1ap.cnf"
  tvbuff_t *param_tvb = NULL;
  offset = dissect_per_bit_string(tvb, offset, actx, tree, hf_index,
                                     1, 160, TRUE, NULL, 0, &param_tvb, NULL);

  if (param_tvb) {
    proto_tree *subtree;
    gint tvb_len;

    tvb_len = tvb_reported_length(param_tvb);
    subtree = proto_item_add_subtree(actx->created_item, ett_f1ap_TransportLayerAddress);
    if (tvb_len == 4) {
      /* IPv4 */
       proto_tree_add_item(subtree, hf_f1ap_transportLayerAddressIPv4, param_tvb, 0, 4, ENC_BIG_ENDIAN);
    } else if (tvb_len == 16) {
      /* IPv6 */
       proto_tree_add_item(subtree, hf_f1ap_transportLayerAddressIPv6, param_tvb, 0, 16, ENC_NA);
    } else if (tvb_len == 20) {
      /* IPv4 */
       proto_tree_add_item(subtree, hf_f1ap_transportLayerAddressIPv4, param_tvb, 0, 4, ENC_BIG_ENDIAN);
      /* IPv6 */
       proto_tree_add_item(subtree, hf_f1ap_transportLayerAddressIPv6, param_tvb, 4, 16, ENC_NA);
    }
  }



  return offset;
}


static const per_sequence_t Endpoint_IP_address_and_port_sequence[] = {
  { &hf_f1ap_endpointIPAddress, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_f1ap_TransportLayerAddress },
  { &hf_f1ap_iE_Extensions  , ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_f1ap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_f1ap_Endpoint_IP_address_and_port(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_f1ap_Endpoint_IP_address_and_port, Endpoint_IP_address_and_port_sequence);

  return offset;
}


static const value_string f1ap_CP_TransportLayerAddress_vals[] = {
  {   0, "endpoint-IP-address" },
  {   1, "endpoint-IP-address-and-port" },
  {   2, "choice-extension" },
  { 0, NULL }
};

static const per_choice_t CP_TransportLayerAddress_choice[] = {
  {   0, &hf_f1ap_endpoint_IP_address, ASN1_NO_EXTENSIONS     , dissect_f1ap_TransportLayerAddress },
  {   1, &hf_f1ap_endpoint_IP_address_and_port, ASN1_NO_EXTENSIONS     , dissect_f1ap_Endpoint_IP_address_and_port },
  {   2, &hf_f1ap_choice_extension, ASN1_NO_EXTENSIONS     , dissect_f1ap_ProtocolIE_SingleContainer },
  { 0, NULL, 0, NULL }
};

static int
dissect_f1ap_CP_TransportLayerAddress(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_f1ap_CP_TransportLayerAddress, CP_TransportLayerAddress_choice,
                                 NULL);

  return offset;
}



static int
dissect_f1ap_TransactionID(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 255U, NULL, TRUE);

  return offset;
}


static const value_string f1ap_TypeOfError_vals[] = {
  {   0, "not-understood" },
  {   1, "missing" },
  { 0, NULL }
};


static int
dissect_f1ap_TypeOfError(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     2, NULL, TRUE, 0, NULL);

  return offset;
}


static const per_sequence_t CriticalityDiagnostics_IE_Item_sequence[] = {
  { &hf_f1ap_iECriticality  , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_f1ap_Criticality },
  { &hf_f1ap_iE_ID          , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_f1ap_ProtocolIE_ID },
  { &hf_f1ap_typeOfError    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_f1ap_TypeOfError },
  { &hf_f1ap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_f1ap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_f1ap_CriticalityDiagnostics_IE_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_f1ap_CriticalityDiagnostics_IE_Item, CriticalityDiagnostics_IE_Item_sequence);

  return offset;
}


static const per_sequence_t CriticalityDiagnostics_IE_List_sequence_of[1] = {
  { &hf_f1ap_CriticalityDiagnostics_IE_List_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_f1ap_CriticalityDiagnostics_IE_Item },
};

static int
dissect_f1ap_CriticalityDiagnostics_IE_List(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_f1ap_CriticalityDiagnostics_IE_List, CriticalityDiagnostics_IE_List_sequence_of,
                                                  1, maxnoofErrors, FALSE);

  return offset;
}


static const per_sequence_t CriticalityDiagnostics_sequence[] = {
  { &hf_f1ap_procedureCode  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_f1ap_ProcedureCode },
  { &hf_f1ap_triggeringMessage, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_f1ap_TriggeringMessage },
  { &hf_f1ap_procedureCriticality, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_f1ap_Criticality },
  { &hf_f1ap_transactionID  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_f1ap_TransactionID },
  { &hf_f1ap_iEsCriticalityDiagnostics, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_f1ap_CriticalityDiagnostics_IE_List },
  { &hf_f1ap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_f1ap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_f1ap_CriticalityDiagnostics(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_f1ap_CriticalityDiagnostics, CriticalityDiagnostics_sequence);

  return offset;
}



static int
dissect_f1ap_C_RNTI(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 65535U, NULL, TRUE);

  return offset;
}



static int
dissect_f1ap_CG_ConfigInfo(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 898 "./asn1/f1ap/f1ap.cnf"
  tvbuff_t *param_tvb = NULL;
  offset = dissect_per_octet_string(tvb, offset, actx, tree, hf_index,
                                       NO_BOUND, NO_BOUND, FALSE, &param_tvb);

  if (param_tvb) {
    proto_tree *subtree = proto_item_add_subtree(actx->created_item, ett_f1ap_CG_ConfigInfo);
    dissect_nr_rrc_CG_ConfigInfo_PDU(param_tvb, actx->pinfo, subtree, NULL);
  }



  return offset;
}



static int
dissect_f1ap_UE_CapabilityRAT_ContainerList(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 906 "./asn1/f1ap/f1ap.cnf"
  tvbuff_t *param_tvb = NULL;
  offset = dissect_per_octet_string(tvb, offset, actx, tree, hf_index,
                                       NO_BOUND, NO_BOUND, FALSE, &param_tvb);

  if (param_tvb) {
    proto_tree *subtree = proto_item_add_subtree(actx->created_item, ett_f1ap_UE_CapabilityRAT_ContainerList);
    dissect_nr_rrc_UE_CapabilityRAT_ContainerList_PDU(param_tvb, actx->pinfo, subtree, NULL);
  }



  return offset;
}



static int
dissect_f1ap_MeasConfig(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 914 "./asn1/f1ap/f1ap.cnf"
  tvbuff_t *param_tvb = NULL;
  offset = dissect_per_octet_string(tvb, offset, actx, tree, hf_index,
                                       NO_BOUND, NO_BOUND, FALSE, &param_tvb);

  if (param_tvb) {
    proto_tree *subtree = proto_item_add_subtree(actx->created_item, ett_f1ap_MeasConfig);
    dissect_nr_rrc_MeasConfig_PDU(param_tvb, actx->pinfo, subtree, NULL);
  }



  return offset;
}


static const per_sequence_t CUtoDURRCInformation_sequence[] = {
  { &hf_f1ap_cG_ConfigInfo  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_f1ap_CG_ConfigInfo },
  { &hf_f1ap_uE_CapabilityRAT_ContainerList, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_f1ap_UE_CapabilityRAT_ContainerList },
  { &hf_f1ap_measConfig     , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_f1ap_MeasConfig },
  { &hf_f1ap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_f1ap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_f1ap_CUtoDURRCInformation(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_f1ap_CUtoDURRCInformation, CUtoDURRCInformation_sequence);

  return offset;
}


static const value_string f1ap_DCBasedDuplicationConfigured_vals[] = {
  {   0, "true" },
  {   1, "false" },
  { 0, NULL }
};


static int
dissect_f1ap_DCBasedDuplicationConfigured(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     1, NULL, TRUE, 1, NULL);

  return offset;
}



static int
dissect_f1ap_GNB_CU_UE_F1AP_ID(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 4294967295U, NULL, FALSE);

  return offset;
}


static const per_sequence_t Dedicated_SIDelivery_NeededUE_Item_sequence[] = {
  { &hf_f1ap_gNB_CU_UE_F1AP_ID, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_f1ap_GNB_CU_UE_F1AP_ID },
  { &hf_f1ap_nRCGI          , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_f1ap_NRCGI },
  { &hf_f1ap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_f1ap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_f1ap_Dedicated_SIDelivery_NeededUE_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_f1ap_Dedicated_SIDelivery_NeededUE_Item, Dedicated_SIDelivery_NeededUE_Item_sequence);

  return offset;
}



static int
dissect_f1ap_GTP_TEID(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_octet_string(tvb, offset, actx, tree, hf_index,
                                       4, 4, FALSE, NULL);

  return offset;
}


static const per_sequence_t GTPTunnel_sequence[] = {
  { &hf_f1ap_transportLayerAddress, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_f1ap_TransportLayerAddress },
  { &hf_f1ap_gTP_TEID       , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_f1ap_GTP_TEID },
  { &hf_f1ap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_f1ap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_f1ap_GTPTunnel(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_f1ap_GTPTunnel, GTPTunnel_sequence);

  return offset;
}


static const value_string f1ap_UPTransportLayerInformation_vals[] = {
  {   0, "gTPTunnel" },
  {   1, "choice-extension" },
  { 0, NULL }
};

static const per_choice_t UPTransportLayerInformation_choice[] = {
  {   0, &hf_f1ap_gTPTunnel      , ASN1_NO_EXTENSIONS     , dissect_f1ap_GTPTunnel },
  {   1, &hf_f1ap_choice_extension, ASN1_NO_EXTENSIONS     , dissect_f1ap_ProtocolIE_SingleContainer },
  { 0, NULL, 0, NULL }
};

static int
dissect_f1ap_UPTransportLayerInformation(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_f1ap_UPTransportLayerInformation, UPTransportLayerInformation_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t DLUPTNLInformation_ToBeSetup_Item_sequence[] = {
  { &hf_f1ap_dLUPTNLInformation, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_f1ap_UPTransportLayerInformation },
  { &hf_f1ap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_f1ap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_f1ap_DLUPTNLInformation_ToBeSetup_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_f1ap_DLUPTNLInformation_ToBeSetup_Item, DLUPTNLInformation_ToBeSetup_Item_sequence);

  return offset;
}


static const per_sequence_t DLUPTNLInformation_ToBeSetup_List_sequence_of[1] = {
  { &hf_f1ap_DLUPTNLInformation_ToBeSetup_List_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_f1ap_DLUPTNLInformation_ToBeSetup_Item },
};

static int
dissect_f1ap_DLUPTNLInformation_ToBeSetup_List(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_f1ap_DLUPTNLInformation_ToBeSetup_List, DLUPTNLInformation_ToBeSetup_List_sequence_of,
                                                  1, maxnoofDLUPTNLInformation, FALSE);

  return offset;
}



static int
dissect_f1ap_DRBID(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            1U, 32U, NULL, TRUE);

  return offset;
}


static const value_string f1ap_DRB_Activity_vals[] = {
  {   0, "active" },
  {   1, "not-active" },
  { 0, NULL }
};


static int
dissect_f1ap_DRB_Activity(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     2, NULL, FALSE, 0, NULL);

  return offset;
}


static const per_sequence_t DRB_Activity_Item_sequence[] = {
  { &hf_f1ap_dRBID          , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_f1ap_DRBID },
  { &hf_f1ap_dRB_Activity   , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_f1ap_DRB_Activity },
  { &hf_f1ap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_f1ap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_f1ap_DRB_Activity_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_f1ap_DRB_Activity_Item, DRB_Activity_Item_sequence);

  return offset;
}


static const per_sequence_t DRBs_FailedToBeModified_Item_sequence[] = {
  { &hf_f1ap_dRBID          , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_f1ap_DRBID },
  { &hf_f1ap_cause          , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_f1ap_Cause },
  { &hf_f1ap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_f1ap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_f1ap_DRBs_FailedToBeModified_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_f1ap_DRBs_FailedToBeModified_Item, DRBs_FailedToBeModified_Item_sequence);

  return offset;
}


static const per_sequence_t DRBs_FailedToBeSetup_Item_sequence[] = {
  { &hf_f1ap_dRBID          , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_f1ap_DRBID },
  { &hf_f1ap_cause          , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_f1ap_Cause },
  { &hf_f1ap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_f1ap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_f1ap_DRBs_FailedToBeSetup_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_f1ap_DRBs_FailedToBeSetup_Item, DRBs_FailedToBeSetup_Item_sequence);

  return offset;
}


static const per_sequence_t DRBs_FailedToBeSetupMod_Item_sequence[] = {
  { &hf_f1ap_dRBID          , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_f1ap_DRBID },
  { &hf_f1ap_cause          , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_f1ap_Cause },
  { &hf_f1ap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_f1ap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_f1ap_DRBs_FailedToBeSetupMod_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_f1ap_DRBs_FailedToBeSetupMod_Item, DRBs_FailedToBeSetupMod_Item_sequence);

  return offset;
}



static int
dissect_f1ap_INTEGER_0_255_(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 255U, NULL, TRUE);

  return offset;
}



static int
dissect_f1ap_INTEGER_1_127(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            1U, 127U, NULL, FALSE);

  return offset;
}



static int
dissect_f1ap_MaxDataBurstVolume(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 4095U, NULL, TRUE);

  return offset;
}


static const per_sequence_t NonDynamic5QIDescriptor_sequence[] = {
  { &hf_f1ap_fiveQI         , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_f1ap_INTEGER_0_255_ },
  { &hf_f1ap_qoSPriorityLevel, ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_f1ap_INTEGER_1_127 },
  { &hf_f1ap_averagingWindow, ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_f1ap_AveragingWindow },
  { &hf_f1ap_maxDataBurstVolume, ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_f1ap_MaxDataBurstVolume },
  { &hf_f1ap_iE_Extensions  , ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_f1ap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_f1ap_NonDynamic5QIDescriptor(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_f1ap_NonDynamic5QIDescriptor, NonDynamic5QIDescriptor_sequence);

  return offset;
}



static int
dissect_f1ap_PacketDelayBudget(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 1023U, NULL, TRUE);

  return offset;
}



static int
dissect_f1ap_PER_Scalar(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 9U, NULL, TRUE);

  return offset;
}



static int
dissect_f1ap_PER_Exponent(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 9U, NULL, TRUE);

  return offset;
}


static const per_sequence_t PacketErrorRate_sequence[] = {
  { &hf_f1ap_pER_Scalar     , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_f1ap_PER_Scalar },
  { &hf_f1ap_pER_Exponent   , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_f1ap_PER_Exponent },
  { &hf_f1ap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_f1ap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_f1ap_PacketErrorRate(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_f1ap_PacketErrorRate, PacketErrorRate_sequence);

  return offset;
}


static const value_string f1ap_T_delayCritical_vals[] = {
  {   0, "delay-critical" },
  {   1, "non-delay-critical" },
  { 0, NULL }
};


static int
dissect_f1ap_T_delayCritical(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     2, NULL, FALSE, 0, NULL);

  return offset;
}


static const per_sequence_t Dynamic5QIDescriptor_sequence[] = {
  { &hf_f1ap_qoSPriorityLevel, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_f1ap_INTEGER_1_127 },
  { &hf_f1ap_packetDelayBudget, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_f1ap_PacketDelayBudget },
  { &hf_f1ap_packetErrorRate, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_f1ap_PacketErrorRate },
  { &hf_f1ap_fiveQI         , ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_f1ap_INTEGER_0_255_ },
  { &hf_f1ap_delayCritical  , ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_f1ap_T_delayCritical },
  { &hf_f1ap_averagingWindow, ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_f1ap_AveragingWindow },
  { &hf_f1ap_maxDataBurstVolume, ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_f1ap_MaxDataBurstVolume },
  { &hf_f1ap_iE_Extensions  , ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_f1ap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_f1ap_Dynamic5QIDescriptor(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_f1ap_Dynamic5QIDescriptor, Dynamic5QIDescriptor_sequence);

  return offset;
}


static const value_string f1ap_QoS_Characteristics_vals[] = {
  {   0, "non-Dynamic-5QI" },
  {   1, "dynamic-5QI" },
  {   2, "choice-extension" },
  { 0, NULL }
};

static const per_choice_t QoS_Characteristics_choice[] = {
  {   0, &hf_f1ap_non_Dynamic_5QI, ASN1_NO_EXTENSIONS     , dissect_f1ap_NonDynamic5QIDescriptor },
  {   1, &hf_f1ap_dynamic_5QI    , ASN1_NO_EXTENSIONS     , dissect_f1ap_Dynamic5QIDescriptor },
  {   2, &hf_f1ap_choice_extension, ASN1_NO_EXTENSIONS     , dissect_f1ap_ProtocolIE_SingleContainer },
  { 0, NULL, 0, NULL }
};

static int
dissect_f1ap_QoS_Characteristics(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_f1ap_QoS_Characteristics, QoS_Characteristics_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t NGRANAllocationAndRetentionPriority_sequence[] = {
  { &hf_f1ap_priorityLevel  , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_f1ap_PriorityLevel },
  { &hf_f1ap_pre_emptionCapability, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_f1ap_Pre_emptionCapability },
  { &hf_f1ap_pre_emptionVulnerability, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_f1ap_Pre_emptionVulnerability },
  { &hf_f1ap_iE_Extensions  , ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_f1ap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_f1ap_NGRANAllocationAndRetentionPriority(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_f1ap_NGRANAllocationAndRetentionPriority, NGRANAllocationAndRetentionPriority_sequence);

  return offset;
}



static int
dissect_f1ap_MaxPacketLossRate(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 1000U, NULL, FALSE);

  return offset;
}


static const per_sequence_t GBR_QoSFlowInformation_sequence[] = {
  { &hf_f1ap_maxFlowBitRateDownlink, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_f1ap_BitRate },
  { &hf_f1ap_maxFlowBitRateUplink, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_f1ap_BitRate },
  { &hf_f1ap_guaranteedFlowBitRateDownlink, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_f1ap_BitRate },
  { &hf_f1ap_guaranteedFlowBitRateUplink, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_f1ap_BitRate },
  { &hf_f1ap_maxPacketLossRateDownlink, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_f1ap_MaxPacketLossRate },
  { &hf_f1ap_maxPacketLossRateUplink, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_f1ap_MaxPacketLossRate },
  { &hf_f1ap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_f1ap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_f1ap_GBR_QoSFlowInformation(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_f1ap_GBR_QoSFlowInformation, GBR_QoSFlowInformation_sequence);

  return offset;
}


static const value_string f1ap_T_reflective_QoS_Attribute_vals[] = {
  {   0, "subject-to" },
  { 0, NULL }
};


static int
dissect_f1ap_T_reflective_QoS_Attribute(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     1, NULL, TRUE, 0, NULL);

  return offset;
}


static const per_sequence_t QoSFlowLevelQoSParameters_sequence[] = {
  { &hf_f1ap_qoS_Characteristics, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_f1ap_QoS_Characteristics },
  { &hf_f1ap_nGRANallocationRetentionPriority, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_f1ap_NGRANAllocationAndRetentionPriority },
  { &hf_f1ap_gBR_QoS_Flow_Information, ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_f1ap_GBR_QoSFlowInformation },
  { &hf_f1ap_reflective_QoS_Attribute, ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_f1ap_T_reflective_QoS_Attribute },
  { &hf_f1ap_iE_Extensions  , ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_f1ap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_f1ap_QoSFlowLevelQoSParameters(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_f1ap_QoSFlowLevelQoSParameters, QoSFlowLevelQoSParameters_sequence);

  return offset;
}



static int
dissect_f1ap_OCTET_STRING_SIZE_1(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_octet_string(tvb, offset, actx, tree, hf_index,
                                       1, 1, FALSE, NULL);

  return offset;
}



static int
dissect_f1ap_OCTET_STRING_SIZE_3(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_octet_string(tvb, offset, actx, tree, hf_index,
                                       3, 3, FALSE, NULL);

  return offset;
}


static const per_sequence_t SNSSAI_sequence[] = {
  { &hf_f1ap_sST            , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_f1ap_OCTET_STRING_SIZE_1 },
  { &hf_f1ap_sD             , ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_f1ap_OCTET_STRING_SIZE_3 },
  { &hf_f1ap_iE_Extensions  , ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_f1ap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_f1ap_SNSSAI(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_f1ap_SNSSAI, SNSSAI_sequence);

  return offset;
}


static const value_string f1ap_NotificationControl_vals[] = {
  {   0, "active" },
  {   1, "not-active" },
  { 0, NULL }
};


static int
dissect_f1ap_NotificationControl(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     2, NULL, TRUE, 0, NULL);

  return offset;
}



static int
dissect_f1ap_QoSFlowIdentifier(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 63U, NULL, FALSE);

  return offset;
}


static const per_sequence_t Flows_Mapped_To_DRB_Item_sequence[] = {
  { &hf_f1ap_qoSFlowIdentifier, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_f1ap_QoSFlowIdentifier },
  { &hf_f1ap_qoSFlowLevelQoSParameters, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_f1ap_QoSFlowLevelQoSParameters },
  { &hf_f1ap_iE_Extensions  , ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_f1ap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_f1ap_Flows_Mapped_To_DRB_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_f1ap_Flows_Mapped_To_DRB_Item, Flows_Mapped_To_DRB_Item_sequence);

  return offset;
}


static const per_sequence_t Flows_Mapped_To_DRB_List_sequence_of[1] = {
  { &hf_f1ap_Flows_Mapped_To_DRB_List_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_f1ap_Flows_Mapped_To_DRB_Item },
};

static int
dissect_f1ap_Flows_Mapped_To_DRB_List(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_f1ap_Flows_Mapped_To_DRB_List, Flows_Mapped_To_DRB_List_sequence_of,
                                                  1, maxnoofQoSFlows, FALSE);

  return offset;
}


static const per_sequence_t DRB_Information_sequence[] = {
  { &hf_f1ap_dRB_QoS        , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_f1ap_QoSFlowLevelQoSParameters },
  { &hf_f1ap_sNSSAI         , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_f1ap_SNSSAI },
  { &hf_f1ap_notificationControl, ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_f1ap_NotificationControl },
  { &hf_f1ap_flows_Mapped_To_DRB_List, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_f1ap_Flows_Mapped_To_DRB_List },
  { &hf_f1ap_iE_Extensions  , ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_f1ap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_f1ap_DRB_Information(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_f1ap_DRB_Information, DRB_Information_sequence);

  return offset;
}



static int
dissect_f1ap_LCID(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            1U, 32U, NULL, TRUE);

  return offset;
}


static const per_sequence_t DRBs_Modified_Item_sequence[] = {
  { &hf_f1ap_dRBID          , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_f1ap_DRBID },
  { &hf_f1ap_lCID           , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_f1ap_LCID },
  { &hf_f1ap_dLUPTNLInformation_ToBeSetup_List, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_f1ap_DLUPTNLInformation_ToBeSetup_List },
  { &hf_f1ap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_f1ap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_f1ap_DRBs_Modified_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_f1ap_DRBs_Modified_Item, DRBs_Modified_Item_sequence);

  return offset;
}


static const per_sequence_t ULUPTNLInformation_ToBeSetup_Item_sequence[] = {
  { &hf_f1ap_uLUPTNLInformation, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_f1ap_UPTransportLayerInformation },
  { &hf_f1ap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_f1ap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_f1ap_ULUPTNLInformation_ToBeSetup_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_f1ap_ULUPTNLInformation_ToBeSetup_Item, ULUPTNLInformation_ToBeSetup_Item_sequence);

  return offset;
}


static const per_sequence_t ULUPTNLInformation_ToBeSetup_List_sequence_of[1] = {
  { &hf_f1ap_ULUPTNLInformation_ToBeSetup_List_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_f1ap_ULUPTNLInformation_ToBeSetup_Item },
};

static int
dissect_f1ap_ULUPTNLInformation_ToBeSetup_List(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_f1ap_ULUPTNLInformation_ToBeSetup_List, ULUPTNLInformation_ToBeSetup_List_sequence_of,
                                                  1, maxnoofULUPTNLInformation, FALSE);

  return offset;
}


static const per_sequence_t DRBs_ModifiedConf_Item_sequence[] = {
  { &hf_f1ap_dRBID          , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_f1ap_DRBID },
  { &hf_f1ap_uLUPTNLInformation_ToBeSetup_List, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_f1ap_ULUPTNLInformation_ToBeSetup_List },
  { &hf_f1ap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_f1ap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_f1ap_DRBs_ModifiedConf_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_f1ap_DRBs_ModifiedConf_Item, DRBs_ModifiedConf_Item_sequence);

  return offset;
}


static const value_string f1ap_Notification_Cause_vals[] = {
  {   0, "fulfilled" },
  {   1, "not-fulfilled" },
  { 0, NULL }
};


static int
dissect_f1ap_Notification_Cause(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     2, NULL, TRUE, 0, NULL);

  return offset;
}


static const per_sequence_t DRB_Notify_Item_sequence[] = {
  { &hf_f1ap_dRBID          , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_f1ap_DRBID },
  { &hf_f1ap_notification_Cause, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_f1ap_Notification_Cause },
  { &hf_f1ap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_f1ap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_f1ap_DRB_Notify_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_f1ap_DRB_Notify_Item, DRB_Notify_Item_sequence);

  return offset;
}


static const per_sequence_t DRBs_Required_ToBeModified_Item_sequence[] = {
  { &hf_f1ap_dRBID          , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_f1ap_DRBID },
  { &hf_f1ap_dLUPTNLInformation_ToBeSetup_List, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_f1ap_DLUPTNLInformation_ToBeSetup_List },
  { &hf_f1ap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_f1ap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_f1ap_DRBs_Required_ToBeModified_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_f1ap_DRBs_Required_ToBeModified_Item, DRBs_Required_ToBeModified_Item_sequence);

  return offset;
}


static const per_sequence_t DRBs_Required_ToBeReleased_Item_sequence[] = {
  { &hf_f1ap_dRBID          , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_f1ap_DRBID },
  { &hf_f1ap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_f1ap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_f1ap_DRBs_Required_ToBeReleased_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_f1ap_DRBs_Required_ToBeReleased_Item, DRBs_Required_ToBeReleased_Item_sequence);

  return offset;
}


static const per_sequence_t DRBs_Setup_Item_sequence[] = {
  { &hf_f1ap_dRBID          , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_f1ap_DRBID },
  { &hf_f1ap_lCID           , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_f1ap_LCID },
  { &hf_f1ap_dLUPTNLInformation_ToBeSetup_List, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_f1ap_DLUPTNLInformation_ToBeSetup_List },
  { &hf_f1ap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_f1ap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_f1ap_DRBs_Setup_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_f1ap_DRBs_Setup_Item, DRBs_Setup_Item_sequence);

  return offset;
}


static const per_sequence_t DRBs_SetupMod_Item_sequence[] = {
  { &hf_f1ap_dRBID          , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_f1ap_DRBID },
  { &hf_f1ap_lCID           , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_f1ap_LCID },
  { &hf_f1ap_dLUPTNLInformation_ToBeSetup_List, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_f1ap_DLUPTNLInformation_ToBeSetup_List },
  { &hf_f1ap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_f1ap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_f1ap_DRBs_SetupMod_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_f1ap_DRBs_SetupMod_Item, DRBs_SetupMod_Item_sequence);

  return offset;
}



static int
dissect_f1ap_QCI(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 255U, NULL, FALSE);

  return offset;
}


static const per_sequence_t GBR_QosInformation_sequence[] = {
  { &hf_f1ap_e_RAB_MaximumBitrateDL, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_f1ap_BitRate },
  { &hf_f1ap_e_RAB_MaximumBitrateUL, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_f1ap_BitRate },
  { &hf_f1ap_e_RAB_GuaranteedBitrateDL, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_f1ap_BitRate },
  { &hf_f1ap_e_RAB_GuaranteedBitrateUL, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_f1ap_BitRate },
  { &hf_f1ap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_f1ap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_f1ap_GBR_QosInformation(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_f1ap_GBR_QosInformation, GBR_QosInformation_sequence);

  return offset;
}


static const per_sequence_t EUTRANQoS_sequence[] = {
  { &hf_f1ap_qCI            , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_f1ap_QCI },
  { &hf_f1ap_allocationAndRetentionPriority, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_f1ap_AllocationAndRetentionPriority },
  { &hf_f1ap_gbrQosInformation, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_f1ap_GBR_QosInformation },
  { &hf_f1ap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_f1ap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_f1ap_EUTRANQoS(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_f1ap_EUTRANQoS, EUTRANQoS_sequence);

  return offset;
}


static const value_string f1ap_QoSInformation_vals[] = {
  {   0, "eUTRANQoS" },
  {   1, "choice-extension" },
  { 0, NULL }
};

static const per_choice_t QoSInformation_choice[] = {
  {   0, &hf_f1ap_eUTRANQoS      , ASN1_NO_EXTENSIONS     , dissect_f1ap_EUTRANQoS },
  {   1, &hf_f1ap_choice_extension, ASN1_NO_EXTENSIONS     , dissect_f1ap_ProtocolIE_SingleContainer },
  { 0, NULL, 0, NULL }
};

static int
dissect_f1ap_QoSInformation(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_f1ap_QoSInformation, QoSInformation_choice,
                                 NULL);

  return offset;
}


static const value_string f1ap_ULUEConfiguration_vals[] = {
  {   0, "no-data" },
  {   1, "shared" },
  {   2, "only" },
  { 0, NULL }
};


static int
dissect_f1ap_ULUEConfiguration(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     3, NULL, TRUE, 0, NULL);

  return offset;
}


static const per_sequence_t ULConfiguration_sequence[] = {
  { &hf_f1ap_uLUEConfiguration, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_f1ap_ULUEConfiguration },
  { &hf_f1ap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_f1ap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_f1ap_ULConfiguration(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_f1ap_ULConfiguration, ULConfiguration_sequence);

  return offset;
}


static const per_sequence_t DRBs_ToBeModified_Item_sequence[] = {
  { &hf_f1ap_dRBID          , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_f1ap_DRBID },
  { &hf_f1ap_qoSInformation , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_f1ap_QoSInformation },
  { &hf_f1ap_uLUPTNLInformation_ToBeSetup_List, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_f1ap_ULUPTNLInformation_ToBeSetup_List },
  { &hf_f1ap_uLConfiguration, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_f1ap_ULConfiguration },
  { &hf_f1ap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_f1ap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_f1ap_DRBs_ToBeModified_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_f1ap_DRBs_ToBeModified_Item, DRBs_ToBeModified_Item_sequence);

  return offset;
}


static const per_sequence_t DRBs_ToBeReleased_Item_sequence[] = {
  { &hf_f1ap_dRBID          , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_f1ap_DRBID },
  { &hf_f1ap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_f1ap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_f1ap_DRBs_ToBeReleased_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_f1ap_DRBs_ToBeReleased_Item, DRBs_ToBeReleased_Item_sequence);

  return offset;
}


static const value_string f1ap_RLCMode_vals[] = {
  {   0, "rlc-am" },
  {   1, "rlc-um-bidirectional" },
  {   2, "rlc-um-unidirectional-ul" },
  {   3, "rlc-um-unidirectional-dl" },
  { 0, NULL }
};


static int
dissect_f1ap_RLCMode(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     4, NULL, TRUE, 0, NULL);

  return offset;
}


static const value_string f1ap_DuplicationActivation_vals[] = {
  {   0, "active" },
  {   1, "inactive" },
  { 0, NULL }
};


static int
dissect_f1ap_DuplicationActivation(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     2, NULL, TRUE, 0, NULL);

  return offset;
}


static const per_sequence_t DRBs_ToBeSetup_Item_sequence[] = {
  { &hf_f1ap_dRBID          , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_f1ap_DRBID },
  { &hf_f1ap_qoSInformation , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_f1ap_QoSInformation },
  { &hf_f1ap_uLUPTNLInformation_ToBeSetup_List, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_f1ap_ULUPTNLInformation_ToBeSetup_List },
  { &hf_f1ap_rLCMode        , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_f1ap_RLCMode },
  { &hf_f1ap_uLConfiguration, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_f1ap_ULConfiguration },
  { &hf_f1ap_duplicationActivation, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_f1ap_DuplicationActivation },
  { &hf_f1ap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_f1ap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_f1ap_DRBs_ToBeSetup_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_f1ap_DRBs_ToBeSetup_Item, DRBs_ToBeSetup_Item_sequence);

  return offset;
}


static const per_sequence_t DRBs_ToBeSetupMod_Item_sequence[] = {
  { &hf_f1ap_dRBID          , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_f1ap_DRBID },
  { &hf_f1ap_qoSInformation , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_f1ap_QoSInformation },
  { &hf_f1ap_uLUPTNLInformation_ToBeSetup_List, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_f1ap_ULUPTNLInformation_ToBeSetup_List },
  { &hf_f1ap_rLCMode        , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_f1ap_RLCMode },
  { &hf_f1ap_uLConfiguration, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_f1ap_ULConfiguration },
  { &hf_f1ap_duplicationActivation, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_f1ap_DuplicationActivation },
  { &hf_f1ap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_f1ap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_f1ap_DRBs_ToBeSetupMod_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_f1ap_DRBs_ToBeSetupMod_Item, DRBs_ToBeSetupMod_Item_sequence);

  return offset;
}


static const value_string f1ap_LongDRXCycleLength_vals[] = {
  {   0, "ms10" },
  {   1, "ms20" },
  {   2, "ms32" },
  {   3, "ms40" },
  {   4, "ms60" },
  {   5, "ms64" },
  {   6, "ms70" },
  {   7, "ms80" },
  {   8, "ms128" },
  {   9, "ms160" },
  {  10, "ms256" },
  {  11, "ms320" },
  {  12, "ms512" },
  {  13, "ms640" },
  {  14, "ms1024" },
  {  15, "ms1280" },
  {  16, "ms2048" },
  {  17, "ms2560" },
  {  18, "ms5120" },
  {  19, "ms10240" },
  { 0, NULL }
};

static value_string_ext f1ap_LongDRXCycleLength_vals_ext = VALUE_STRING_EXT_INIT(f1ap_LongDRXCycleLength_vals);


static int
dissect_f1ap_LongDRXCycleLength(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     20, NULL, TRUE, 0, NULL);

  return offset;
}


static const value_string f1ap_ShortDRXCycleLength_vals[] = {
  {   0, "ms2" },
  {   1, "ms3" },
  {   2, "ms4" },
  {   3, "ms5" },
  {   4, "ms6" },
  {   5, "ms7" },
  {   6, "ms8" },
  {   7, "ms10" },
  {   8, "ms14" },
  {   9, "ms16" },
  {  10, "ms20" },
  {  11, "ms30" },
  {  12, "ms32" },
  {  13, "ms35" },
  {  14, "ms40" },
  {  15, "ms64" },
  {  16, "ms80" },
  {  17, "ms128" },
  {  18, "ms160" },
  {  19, "ms256" },
  {  20, "ms320" },
  {  21, "ms512" },
  {  22, "ms640" },
  { 0, NULL }
};

static value_string_ext f1ap_ShortDRXCycleLength_vals_ext = VALUE_STRING_EXT_INIT(f1ap_ShortDRXCycleLength_vals);


static int
dissect_f1ap_ShortDRXCycleLength(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     23, NULL, TRUE, 0, NULL);

  return offset;
}



static int
dissect_f1ap_ShortDRXCycleTimer(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            1U, 16U, NULL, FALSE);

  return offset;
}


static const per_sequence_t DRXCycle_sequence[] = {
  { &hf_f1ap_longDRXCycleLength, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_f1ap_LongDRXCycleLength },
  { &hf_f1ap_shortDRXCycleLength, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_f1ap_ShortDRXCycleLength },
  { &hf_f1ap_shortDRXCycleTimer, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_f1ap_ShortDRXCycleTimer },
  { &hf_f1ap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_f1ap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_f1ap_DRXCycle(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_f1ap_DRXCycle, DRXCycle_sequence);

  return offset;
}



static int
dissect_f1ap_DRX_Config(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 1115 "./asn1/f1ap/f1ap.cnf"
  tvbuff_t *param_tvb = NULL;
  offset = dissect_per_octet_string(tvb, offset, actx, tree, hf_index,
                                       NO_BOUND, NO_BOUND, FALSE, &param_tvb);

  if (param_tvb) {
    proto_tree *subtree = proto_item_add_subtree(actx->created_item, ett_f1ap_DRX_Config);
    dissect_nr_rrc_DRX_Config_PDU(param_tvb, actx->pinfo, subtree, NULL);
  }



  return offset;
}


static const value_string f1ap_DRXConfigurationIndicator_vals[] = {
  {   0, "release" },
  { 0, NULL }
};


static int
dissect_f1ap_DRXConfigurationIndicator(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     1, NULL, TRUE, 0, NULL);

  return offset;
}



static int
dissect_f1ap_DRX_LongCycleStartOffset(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 10239U, NULL, FALSE);

  return offset;
}



static int
dissect_f1ap_DUtoCURRCContainer(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 837 "./asn1/f1ap/f1ap.cnf"
  tvbuff_t *param_tvb = NULL;
  offset = dissect_per_octet_string(tvb, offset, actx, tree, hf_index,
                                       NO_BOUND, NO_BOUND, FALSE, &param_tvb);

  if (param_tvb) {
    proto_tree *subtree = proto_item_add_subtree(actx->created_item, ett_f1ap_DUtoCURRCContainer);
    dissect_nr_rrc_CellGroupConfig_PDU(param_tvb, actx->pinfo, subtree, NULL);
  }



  return offset;
}



static int
dissect_f1ap_MeasGapConfig(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 946 "./asn1/f1ap/f1ap.cnf"
  tvbuff_t *param_tvb = NULL;
  offset = dissect_per_octet_string(tvb, offset, actx, tree, hf_index,
                                       NO_BOUND, NO_BOUND, FALSE, &param_tvb);

  if (param_tvb) {
    proto_tree *subtree = proto_item_add_subtree(actx->created_item, ett_f1ap_MeasGapConfig);
    dissect_nr_rrc_MeasGapConfig_PDU(param_tvb, actx->pinfo, subtree, NULL);
  }



  return offset;
}



static int
dissect_f1ap_T_requestedP_MaxFR1(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 962 "./asn1/f1ap/f1ap.cnf"
  tvbuff_t *param_tvb = NULL;
  offset = dissect_per_octet_string(tvb, offset, actx, tree, hf_index,
                                       NO_BOUND, NO_BOUND, FALSE, &param_tvb);

  if (param_tvb) {
    proto_tree *subtree = proto_item_add_subtree(actx->created_item, ett_f1ap_requestedP_MaxFR1);
    dissect_nr_rrc_P_Max_PDU(param_tvb, actx->pinfo, subtree, NULL);
  }



  return offset;
}


static const per_sequence_t DUtoCURRCInformation_sequence[] = {
  { &hf_f1ap_cellGroupConfig, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_f1ap_CellGroupConfig },
  { &hf_f1ap_measGapConfig  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_f1ap_MeasGapConfig },
  { &hf_f1ap_requestedP_MaxFR1, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_f1ap_T_requestedP_MaxFR1 },
  { &hf_f1ap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_f1ap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_f1ap_DUtoCURRCInformation(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_f1ap_DUtoCURRCInformation, DUtoCURRCInformation_sequence);

  return offset;
}


static const value_string f1ap_DuplicationIndication_vals[] = {
  {   0, "true" },
  {   1, "false" },
  { 0, NULL }
};


static int
dissect_f1ap_DuplicationIndication(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     1, NULL, TRUE, 1, NULL);

  return offset;
}


static const per_sequence_t SliceSupportItem_sequence[] = {
  { &hf_f1ap_sNSSAI         , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_f1ap_SNSSAI },
  { &hf_f1ap_iE_Extensions  , ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_f1ap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_f1ap_SliceSupportItem(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_f1ap_SliceSupportItem, SliceSupportItem_sequence);

  return offset;
}


static const per_sequence_t SliceSupportList_sequence_of[1] = {
  { &hf_f1ap_SliceSupportList_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_f1ap_SliceSupportItem },
};

static int
dissect_f1ap_SliceSupportList(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_f1ap_SliceSupportList, SliceSupportList_sequence_of,
                                                  1, maxnoofSliceItems, FALSE);

  return offset;
}


static const per_sequence_t ExtendedServedPLMNs_Item_sequence[] = {
  { &hf_f1ap_pLMN_Identity  , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_f1ap_PLMN_Identity },
  { &hf_f1ap_tAISliceSupportList, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_f1ap_SliceSupportList },
  { &hf_f1ap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_f1ap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_f1ap_ExtendedServedPLMNs_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_f1ap_ExtendedServedPLMNs_Item, ExtendedServedPLMNs_Item_sequence);

  return offset;
}


static const per_sequence_t ExtendedServedPLMNs_List_sequence_of[1] = {
  { &hf_f1ap_ExtendedServedPLMNs_List_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_f1ap_ExtendedServedPLMNs_Item },
};

static int
dissect_f1ap_ExtendedServedPLMNs_List(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_f1ap_ExtendedServedPLMNs_List, ExtendedServedPLMNs_List_sequence_of,
                                                  1, maxnoofExtendedBPLMNs, FALSE);

  return offset;
}



static int
dissect_f1ap_EUTRA_Cell_ID(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_bit_string(tvb, offset, actx, tree, hf_index,
                                     28, 28, FALSE, NULL, 0, NULL, NULL);

  return offset;
}



static int
dissect_f1ap_OffsetToPointA(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 2199U, NULL, TRUE);

  return offset;
}


static const per_sequence_t EUTRA_FDD_Info_sequence[] = {
  { &hf_f1ap_uL_offsetToPointA, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_f1ap_OffsetToPointA },
  { &hf_f1ap_dL_offsetToPointA, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_f1ap_OffsetToPointA },
  { &hf_f1ap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_f1ap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_f1ap_EUTRA_FDD_Info(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_f1ap_EUTRA_FDD_Info, EUTRA_FDD_Info_sequence);

  return offset;
}


static const per_sequence_t EUTRA_TDD_Info_sequence[] = {
  { &hf_f1ap_offsetToPointA , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_f1ap_OffsetToPointA },
  { &hf_f1ap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_f1ap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_f1ap_EUTRA_TDD_Info(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_f1ap_EUTRA_TDD_Info, EUTRA_TDD_Info_sequence);

  return offset;
}


static const value_string f1ap_EUTRA_Mode_Info_vals[] = {
  {   0, "eUTRAFDD" },
  {   1, "eUTRATDD" },
  {   2, "choice-extension" },
  { 0, NULL }
};

static const per_choice_t EUTRA_Mode_Info_choice[] = {
  {   0, &hf_f1ap_eUTRAFDD       , ASN1_NO_EXTENSIONS     , dissect_f1ap_EUTRA_FDD_Info },
  {   1, &hf_f1ap_eUTRATDD       , ASN1_NO_EXTENSIONS     , dissect_f1ap_EUTRA_TDD_Info },
  {   2, &hf_f1ap_choice_extension, ASN1_NO_EXTENSIONS     , dissect_f1ap_ProtocolIE_SingleContainer },
  { 0, NULL, 0, NULL }
};

static int
dissect_f1ap_EUTRA_Mode_Info(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_f1ap_EUTRA_Mode_Info, EUTRA_Mode_Info_choice,
                                 NULL);

  return offset;
}



static int
dissect_f1ap_ProtectedEUTRAResourceIndication(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 1065 "./asn1/f1ap/f1ap.cnf"
  tvbuff_t *param_tvb = NULL;
  offset = dissect_per_octet_string(tvb, offset, actx, tree, hf_index,
                                       NO_BOUND, NO_BOUND, FALSE, &param_tvb);

  if (param_tvb) {
    proto_tree *subtree = proto_item_add_subtree(actx->created_item, ett_f1ap_ProtectedEUTRAResourceIndication);
    dissect_x2ap_ProtectedEUTRAResourceIndication_PDU(param_tvb, actx->pinfo, subtree, NULL);
  }



  return offset;
}


static const per_sequence_t Served_EUTRA_Cells_Information_sequence[] = {
  { &hf_f1ap_eUTRA_Mode_Info_01, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_f1ap_EUTRA_Mode_Info },
  { &hf_f1ap_protectedEUTRAResourceIndication, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_f1ap_ProtectedEUTRAResourceIndication },
  { &hf_f1ap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_f1ap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_f1ap_Served_EUTRA_Cells_Information(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_f1ap_Served_EUTRA_Cells_Information, Served_EUTRA_Cells_Information_sequence);

  return offset;
}


static const per_sequence_t EUTRACells_List_item_sequence[] = {
  { &hf_f1ap_eUTRA_Cell_ID  , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_f1ap_EUTRA_Cell_ID },
  { &hf_f1ap_served_EUTRA_Cells_Information, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_f1ap_Served_EUTRA_Cells_Information },
  { &hf_f1ap_iE_Extensions  , ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_f1ap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_f1ap_EUTRACells_List_item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_f1ap_EUTRACells_List_item, EUTRACells_List_item_sequence);

  return offset;
}


static const per_sequence_t EUTRACells_List_sequence_of[1] = {
  { &hf_f1ap_EUTRACells_List_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_f1ap_EUTRACells_List_item },
};

static int
dissect_f1ap_EUTRACells_List(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_f1ap_EUTRACells_List, EUTRACells_List_sequence_of,
                                                  1, maxCellineNB, FALSE);

  return offset;
}



static int
dissect_f1ap_ExtendedEARFCN(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 262143U, NULL, FALSE);

  return offset;
}


static const value_string f1ap_EUTRA_Transmission_Bandwidth_vals[] = {
  {   0, "bw6" },
  {   1, "bw15" },
  {   2, "bw25" },
  {   3, "bw50" },
  {   4, "bw75" },
  {   5, "bw100" },
  { 0, NULL }
};


static int
dissect_f1ap_EUTRA_Transmission_Bandwidth(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     6, NULL, TRUE, 0, NULL);

  return offset;
}


static const per_sequence_t EUTRA_Coex_FDD_Info_sequence[] = {
  { &hf_f1ap_uL_EARFCN      , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_f1ap_ExtendedEARFCN },
  { &hf_f1ap_dL_EARFCN      , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_f1ap_ExtendedEARFCN },
  { &hf_f1ap_uL_Transmission_Bandwidth, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_f1ap_EUTRA_Transmission_Bandwidth },
  { &hf_f1ap_dL_Transmission_Bandwidth, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_f1ap_EUTRA_Transmission_Bandwidth },
  { &hf_f1ap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_f1ap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_f1ap_EUTRA_Coex_FDD_Info(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_f1ap_EUTRA_Coex_FDD_Info, EUTRA_Coex_FDD_Info_sequence);

  return offset;
}


static const value_string f1ap_EUTRA_SubframeAssignment_vals[] = {
  {   0, "sa0" },
  {   1, "sa1" },
  {   2, "sa2" },
  {   3, "sa3" },
  {   4, "sa4" },
  {   5, "sa5" },
  {   6, "sa6" },
  { 0, NULL }
};


static int
dissect_f1ap_EUTRA_SubframeAssignment(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     7, NULL, TRUE, 0, NULL);

  return offset;
}


static const value_string f1ap_EUTRA_SpecialSubframePatterns_vals[] = {
  {   0, "ssp0" },
  {   1, "ssp1" },
  {   2, "ssp2" },
  {   3, "ssp3" },
  {   4, "ssp4" },
  {   5, "ssp5" },
  {   6, "ssp6" },
  {   7, "ssp7" },
  {   8, "ssp8" },
  {   9, "ssp9" },
  {  10, "ssp10" },
  { 0, NULL }
};


static int
dissect_f1ap_EUTRA_SpecialSubframePatterns(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     11, NULL, TRUE, 0, NULL);

  return offset;
}


static const value_string f1ap_EUTRA_CyclicPrefixDL_vals[] = {
  {   0, "normal" },
  {   1, "extended" },
  { 0, NULL }
};


static int
dissect_f1ap_EUTRA_CyclicPrefixDL(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     2, NULL, TRUE, 0, NULL);

  return offset;
}


static const value_string f1ap_EUTRA_CyclicPrefixUL_vals[] = {
  {   0, "normal" },
  {   1, "extended" },
  { 0, NULL }
};


static int
dissect_f1ap_EUTRA_CyclicPrefixUL(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     2, NULL, TRUE, 0, NULL);

  return offset;
}


static const per_sequence_t EUTRA_SpecialSubframe_Info_sequence[] = {
  { &hf_f1ap_specialSubframePatterns, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_f1ap_EUTRA_SpecialSubframePatterns },
  { &hf_f1ap_cyclicPrefixDL , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_f1ap_EUTRA_CyclicPrefixDL },
  { &hf_f1ap_cyclicPrefixUL , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_f1ap_EUTRA_CyclicPrefixUL },
  { &hf_f1ap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_f1ap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_f1ap_EUTRA_SpecialSubframe_Info(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_f1ap_EUTRA_SpecialSubframe_Info, EUTRA_SpecialSubframe_Info_sequence);

  return offset;
}


static const per_sequence_t EUTRA_Coex_TDD_Info_sequence[] = {
  { &hf_f1ap_eARFCN         , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_f1ap_ExtendedEARFCN },
  { &hf_f1ap_transmission_Bandwidth, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_f1ap_EUTRA_Transmission_Bandwidth },
  { &hf_f1ap_subframeAssignment, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_f1ap_EUTRA_SubframeAssignment },
  { &hf_f1ap_specialSubframe_Info, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_f1ap_EUTRA_SpecialSubframe_Info },
  { &hf_f1ap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_f1ap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_f1ap_EUTRA_Coex_TDD_Info(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_f1ap_EUTRA_Coex_TDD_Info, EUTRA_Coex_TDD_Info_sequence);

  return offset;
}


static const value_string f1ap_EUTRA_Coex_Mode_Info_vals[] = {
  {   0, "fDD" },
  {   1, "tDD" },
  { 0, NULL }
};

static const per_choice_t EUTRA_Coex_Mode_Info_choice[] = {
  {   0, &hf_f1ap_fDD            , ASN1_EXTENSION_ROOT    , dissect_f1ap_EUTRA_Coex_FDD_Info },
  {   1, &hf_f1ap_tDD            , ASN1_EXTENSION_ROOT    , dissect_f1ap_EUTRA_Coex_TDD_Info },
  { 0, NULL, 0, NULL }
};

static int
dissect_f1ap_EUTRA_Coex_Mode_Info(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_f1ap_EUTRA_Coex_Mode_Info, EUTRA_Coex_Mode_Info_choice,
                                 NULL);

  return offset;
}



static int
dissect_f1ap_INTEGER_0_837(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 837U, NULL, FALSE);

  return offset;
}



static int
dissect_f1ap_INTEGER_0_15(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 15U, NULL, FALSE);

  return offset;
}



static int
dissect_f1ap_BOOLEAN(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_boolean(tvb, offset, actx, tree, hf_index, NULL);

  return offset;
}



static int
dissect_f1ap_INTEGER_0_94(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 94U, NULL, FALSE);

  return offset;
}



static int
dissect_f1ap_INTEGER_0_63(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 63U, NULL, FALSE);

  return offset;
}


static const per_sequence_t EUTRA_PRACH_Configuration_sequence[] = {
  { &hf_f1ap_rootSequenceIndex, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_f1ap_INTEGER_0_837 },
  { &hf_f1ap_zeroCorrelationIndex, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_f1ap_INTEGER_0_15 },
  { &hf_f1ap_highSpeedFlag  , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_f1ap_BOOLEAN },
  { &hf_f1ap_prach_FreqOffset, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_f1ap_INTEGER_0_94 },
  { &hf_f1ap_prach_ConfigIndex, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_f1ap_INTEGER_0_63 },
  { &hf_f1ap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_f1ap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_f1ap_EUTRA_PRACH_Configuration(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_f1ap_EUTRA_PRACH_Configuration, EUTRA_PRACH_Configuration_sequence);

  return offset;
}


static const value_string f1ap_ExecuteDuplication_vals[] = {
  {   0, "true" },
  { 0, NULL }
};


static int
dissect_f1ap_ExecuteDuplication(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     1, NULL, TRUE, 0, NULL);

  return offset;
}



static int
dissect_f1ap_EUTRA_NR_CellResourceCoordinationReq_Container(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 707 "./asn1/f1ap/f1ap.cnf"
  tvbuff_t *param_tvb = NULL;
  offset = dissect_per_octet_string(tvb, offset, actx, tree, hf_index,
                                       NO_BOUND, NO_BOUND, FALSE, &param_tvb);

  if (param_tvb) {
    proto_tree *subtree = proto_item_add_subtree(actx->created_item, ett_f1ap_EUTRA_NR_CellResourceCoordinationReq_Container);
    dissect_x2ap_EUTRANRCellResourceCoordinationRequest_PDU(param_tvb, actx->pinfo, subtree, NULL);
  }



  return offset;
}



static int
dissect_f1ap_EUTRA_NR_CellResourceCoordinationReqAck_Container(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 715 "./asn1/f1ap/f1ap.cnf"
  tvbuff_t *param_tvb = NULL;
  offset = dissect_per_octet_string(tvb, offset, actx, tree, hf_index,
                                       NO_BOUND, NO_BOUND, FALSE, &param_tvb);

  if (param_tvb) {
    proto_tree *subtree = proto_item_add_subtree(actx->created_item, ett_f1ap_EUTRA_NR_CellResourceCoordinationReqAck_Container);
    dissect_x2ap_EUTRANRCellResourceCoordinationResponse_PDU(param_tvb, actx->pinfo, subtree, NULL);
  }



  return offset;
}



static int
dissect_f1ap_INTEGER_0_maxNRARFCN(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, maxNRARFCN, NULL, FALSE);

  return offset;
}


static const value_string f1ap_NRSCS_vals[] = {
  {   0, "scs15" },
  {   1, "scs30" },
  {   2, "scs60" },
  {   3, "scs120" },
  { 0, NULL }
};


static int
dissect_f1ap_NRSCS(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     4, NULL, TRUE, 0, NULL);

  return offset;
}


static const value_string f1ap_NRNRB_vals[] = {
  {   0, "nrb11" },
  {   1, "nrb18" },
  {   2, "nrb24" },
  {   3, "nrb25" },
  {   4, "nrb31" },
  {   5, "nrb32" },
  {   6, "nrb38" },
  {   7, "nrb51" },
  {   8, "nrb52" },
  {   9, "nrb65" },
  {  10, "nrb66" },
  {  11, "nrb78" },
  {  12, "nrb79" },
  {  13, "nrb93" },
  {  14, "nrb106" },
  {  15, "nrb107" },
  {  16, "nrb121" },
  {  17, "nrb132" },
  {  18, "nrb133" },
  {  19, "nrb135" },
  {  20, "nrb160" },
  {  21, "nrb162" },
  {  22, "nrb189" },
  {  23, "nrb216" },
  {  24, "nrb217" },
  {  25, "nrb245" },
  {  26, "nrb264" },
  {  27, "nrb270" },
  {  28, "nrb273" },
  { 0, NULL }
};

static value_string_ext f1ap_NRNRB_vals_ext = VALUE_STRING_EXT_INIT(f1ap_NRNRB_vals);


static int
dissect_f1ap_NRNRB(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     29, NULL, TRUE, 0, NULL);

  return offset;
}


static const per_sequence_t Transmission_Bandwidth_sequence[] = {
  { &hf_f1ap_nRSCS          , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_f1ap_NRSCS },
  { &hf_f1ap_nRNRB          , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_f1ap_NRNRB },
  { &hf_f1ap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_f1ap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_f1ap_Transmission_Bandwidth(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_f1ap_Transmission_Bandwidth, Transmission_Bandwidth_sequence);

  return offset;
}


static const per_sequence_t SUL_Information_sequence[] = {
  { &hf_f1ap_sUL_NRARFCN    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_f1ap_INTEGER_0_maxNRARFCN },
  { &hf_f1ap_sUL_transmission_Bandwidth, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_f1ap_Transmission_Bandwidth },
  { &hf_f1ap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_f1ap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_f1ap_SUL_Information(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_f1ap_SUL_Information, SUL_Information_sequence);

  return offset;
}



static int
dissect_f1ap_INTEGER_1_1024_(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            1U, 1024U, NULL, TRUE);

  return offset;
}


static const per_sequence_t SupportedSULFreqBandItem_sequence[] = {
  { &hf_f1ap_freqBandIndicatorNr, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_f1ap_INTEGER_1_1024_ },
  { &hf_f1ap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_f1ap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_f1ap_SupportedSULFreqBandItem(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_f1ap_SupportedSULFreqBandItem, SupportedSULFreqBandItem_sequence);

  return offset;
}


static const per_sequence_t SEQUENCE_SIZE_0_maxnoofNrCellBands_OF_SupportedSULFreqBandItem_sequence_of[1] = {
  { &hf_f1ap_supportedSULBandList_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_f1ap_SupportedSULFreqBandItem },
};

static int
dissect_f1ap_SEQUENCE_SIZE_0_maxnoofNrCellBands_OF_SupportedSULFreqBandItem(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_f1ap_SEQUENCE_SIZE_0_maxnoofNrCellBands_OF_SupportedSULFreqBandItem, SEQUENCE_SIZE_0_maxnoofNrCellBands_OF_SupportedSULFreqBandItem_sequence_of,
                                                  0, maxnoofNrCellBands, FALSE);

  return offset;
}


static const per_sequence_t FreqBandNrItem_sequence[] = {
  { &hf_f1ap_freqBandIndicatorNr, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_f1ap_INTEGER_1_1024_ },
  { &hf_f1ap_supportedSULBandList, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_f1ap_SEQUENCE_SIZE_0_maxnoofNrCellBands_OF_SupportedSULFreqBandItem },
  { &hf_f1ap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_f1ap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_f1ap_FreqBandNrItem(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_f1ap_FreqBandNrItem, FreqBandNrItem_sequence);

  return offset;
}


static const per_sequence_t SEQUENCE_SIZE_1_maxnoofNrCellBands_OF_FreqBandNrItem_sequence_of[1] = {
  { &hf_f1ap_freqBandListNr_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_f1ap_FreqBandNrItem },
};

static int
dissect_f1ap_SEQUENCE_SIZE_1_maxnoofNrCellBands_OF_FreqBandNrItem(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_f1ap_SEQUENCE_SIZE_1_maxnoofNrCellBands_OF_FreqBandNrItem, SEQUENCE_SIZE_1_maxnoofNrCellBands_OF_FreqBandNrItem_sequence_of,
                                                  1, maxnoofNrCellBands, FALSE);

  return offset;
}


static const per_sequence_t NRFreqInfo_sequence[] = {
  { &hf_f1ap_nRARFCN        , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_f1ap_INTEGER_0_maxNRARFCN },
  { &hf_f1ap_sul_Information, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_f1ap_SUL_Information },
  { &hf_f1ap_freqBandListNr , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_f1ap_SEQUENCE_SIZE_1_maxnoofNrCellBands_OF_FreqBandNrItem },
  { &hf_f1ap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_f1ap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_f1ap_NRFreqInfo(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_f1ap_NRFreqInfo, NRFreqInfo_sequence);

  return offset;
}


static const per_sequence_t FDD_Info_sequence[] = {
  { &hf_f1ap_uL_NRFreqInfo  , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_f1ap_NRFreqInfo },
  { &hf_f1ap_dL_NRFreqInfo  , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_f1ap_NRFreqInfo },
  { &hf_f1ap_uL_Transmission_Bandwidth_01, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_f1ap_Transmission_Bandwidth },
  { &hf_f1ap_dL_Transmission_Bandwidth_01, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_f1ap_Transmission_Bandwidth },
  { &hf_f1ap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_f1ap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_f1ap_FDD_Info(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_f1ap_FDD_Info, FDD_Info_sequence);

  return offset;
}


static const value_string f1ap_FullConfiguration_vals[] = {
  {   0, "full" },
  { 0, NULL }
};


static int
dissect_f1ap_FullConfiguration(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     1, NULL, TRUE, 0, NULL);

  return offset;
}



static int
dissect_f1ap_CG_Config(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 890 "./asn1/f1ap/f1ap.cnf"
  tvbuff_t *param_tvb = NULL;
  offset = dissect_per_octet_string(tvb, offset, actx, tree, hf_index,
                                       NO_BOUND, NO_BOUND, FALSE, &param_tvb);

  if (param_tvb) {
    proto_tree *subtree = proto_item_add_subtree(actx->created_item, ett_f1ap_CG_Config);
    dissect_nr_rrc_CG_Config_PDU(param_tvb, actx->pinfo, subtree, NULL);
  }



  return offset;
}



static int
dissect_f1ap_T_sIBtype(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 988 "./asn1/f1ap/f1ap.cnf"
  f1ap_private_data_t *f1ap_data = f1ap_get_private_data(actx->pinfo);
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            2U, 32U, &f1ap_data->sib_type, TRUE);




  return offset;
}



static int
dissect_f1ap_T_sIBmessage_01(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 992 "./asn1/f1ap/f1ap.cnf"
  tvbuff_t *param_tvb = NULL;
  offset = dissect_per_octet_string(tvb, offset, actx, tree, hf_index,
                                       NO_BOUND, NO_BOUND, FALSE, &param_tvb);

  if (param_tvb) {
    f1ap_private_data_t *f1ap_data = f1ap_get_private_data(actx->pinfo);
    proto_tree *subtree = proto_item_add_subtree(actx->created_item, ett_f1ap_sIBmessage);
    switch (f1ap_data->sib_type) {
    case 2:
      dissect_nr_rrc_SIB2_PDU(param_tvb, actx->pinfo, subtree, NULL);
      break;
    case 3:
      dissect_nr_rrc_SIB3_PDU(param_tvb, actx->pinfo, subtree, NULL);
      break;
    case 4:
      dissect_nr_rrc_SIB4_PDU(param_tvb, actx->pinfo, subtree, NULL);
      break;
    case 5:
      dissect_nr_rrc_SIB5_PDU(param_tvb, actx->pinfo, subtree, NULL);
      break;
    case 6:
      dissect_nr_rrc_SIB6_PDU(param_tvb, actx->pinfo, subtree, NULL);
      break;
    case 7:
      dissect_nr_rrc_SIB7_PDU(param_tvb, actx->pinfo, subtree, NULL);
      break;
    case 8:
      dissect_nr_rrc_SIB8_PDU(param_tvb, actx->pinfo, subtree, NULL);
      break;
    case 9:
      dissect_nr_rrc_SIB9_PDU(param_tvb, actx->pinfo, subtree, NULL);
      break;
    default:
      break;
    }
  }



  return offset;
}



static int
dissect_f1ap_INTEGER_0_31_(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 31U, NULL, TRUE);

  return offset;
}


static const per_sequence_t SibtypetobeupdatedListItem_sequence[] = {
  { &hf_f1ap_sIBtype_01     , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_f1ap_T_sIBtype },
  { &hf_f1ap_sIBmessage_01  , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_f1ap_T_sIBmessage_01 },
  { &hf_f1ap_valueTag       , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_f1ap_INTEGER_0_31_ },
  { &hf_f1ap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_f1ap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_f1ap_SibtypetobeupdatedListItem(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_f1ap_SibtypetobeupdatedListItem, SibtypetobeupdatedListItem_sequence);

  return offset;
}


static const per_sequence_t SEQUENCE_SIZE_1_maxnoofSIBTypes_OF_SibtypetobeupdatedListItem_sequence_of[1] = {
  { &hf_f1ap_sibtypetobeupdatedlist_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_f1ap_SibtypetobeupdatedListItem },
};

static int
dissect_f1ap_SEQUENCE_SIZE_1_maxnoofSIBTypes_OF_SibtypetobeupdatedListItem(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_f1ap_SEQUENCE_SIZE_1_maxnoofSIBTypes_OF_SibtypetobeupdatedListItem, SEQUENCE_SIZE_1_maxnoofSIBTypes_OF_SibtypetobeupdatedListItem_sequence_of,
                                                  1, maxnoofSIBTypes, FALSE);

  return offset;
}


static const per_sequence_t GNB_CUSystemInformation_sequence[] = {
  { &hf_f1ap_sibtypetobeupdatedlist, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_f1ap_SEQUENCE_SIZE_1_maxnoofSIBTypes_OF_SibtypetobeupdatedListItem },
  { &hf_f1ap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_f1ap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_f1ap_GNB_CUSystemInformation(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_f1ap_GNB_CUSystemInformation, GNB_CUSystemInformation_sequence);

  return offset;
}


static const per_sequence_t GNB_CU_TNL_Association_Setup_Item_sequence[] = {
  { &hf_f1ap_tNLAssociationTransportLayerAddress, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_f1ap_CP_TransportLayerAddress },
  { &hf_f1ap_iE_Extensions  , ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_f1ap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_f1ap_GNB_CU_TNL_Association_Setup_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_f1ap_GNB_CU_TNL_Association_Setup_Item, GNB_CU_TNL_Association_Setup_Item_sequence);

  return offset;
}


static const per_sequence_t GNB_CU_TNL_Association_Failed_To_Setup_Item_sequence[] = {
  { &hf_f1ap_tNLAssociationTransportLayerAddress, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_f1ap_CP_TransportLayerAddress },
  { &hf_f1ap_cause          , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_f1ap_Cause },
  { &hf_f1ap_iE_Extensions  , ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_f1ap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_f1ap_GNB_CU_TNL_Association_Failed_To_Setup_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_f1ap_GNB_CU_TNL_Association_Failed_To_Setup_Item, GNB_CU_TNL_Association_Failed_To_Setup_Item_sequence);

  return offset;
}


static const value_string f1ap_TNLAssociationUsage_vals[] = {
  {   0, "ue" },
  {   1, "non-ue" },
  {   2, "both" },
  { 0, NULL }
};


static int
dissect_f1ap_TNLAssociationUsage(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     3, NULL, TRUE, 0, NULL);

  return offset;
}


static const per_sequence_t GNB_CU_TNL_Association_To_Add_Item_sequence[] = {
  { &hf_f1ap_tNLAssociationTransportLayerAddress, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_f1ap_CP_TransportLayerAddress },
  { &hf_f1ap_tNLAssociationUsage, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_f1ap_TNLAssociationUsage },
  { &hf_f1ap_iE_Extensions  , ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_f1ap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_f1ap_GNB_CU_TNL_Association_To_Add_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_f1ap_GNB_CU_TNL_Association_To_Add_Item, GNB_CU_TNL_Association_To_Add_Item_sequence);

  return offset;
}


static const per_sequence_t GNB_CU_TNL_Association_To_Remove_Item_sequence[] = {
  { &hf_f1ap_tNLAssociationTransportLayerAddress, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_f1ap_CP_TransportLayerAddress },
  { &hf_f1ap_iE_Extensions  , ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_f1ap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_f1ap_GNB_CU_TNL_Association_To_Remove_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_f1ap_GNB_CU_TNL_Association_To_Remove_Item, GNB_CU_TNL_Association_To_Remove_Item_sequence);

  return offset;
}


static const per_sequence_t GNB_CU_TNL_Association_To_Update_Item_sequence[] = {
  { &hf_f1ap_tNLAssociationTransportLayerAddress, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_f1ap_CP_TransportLayerAddress },
  { &hf_f1ap_tNLAssociationUsage, ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_f1ap_TNLAssociationUsage },
  { &hf_f1ap_iE_Extensions  , ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_f1ap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_f1ap_GNB_CU_TNL_Association_To_Update_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_f1ap_GNB_CU_TNL_Association_To_Update_Item, GNB_CU_TNL_Association_To_Update_Item_sequence);

  return offset;
}



static int
dissect_f1ap_GNB_DU_UE_F1AP_ID(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 4294967295U, NULL, FALSE);

  return offset;
}



static int
dissect_f1ap_GNB_DU_ID(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer_64b(tvb, offset, actx, tree, hf_index,
                                                            0U, G_GUINT64_CONSTANT(68719476735), NULL, FALSE);

  return offset;
}



static int
dissect_f1ap_GNB_CU_Name(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_PrintableString(tvb, offset, actx, tree, hf_index,
                                          1, 150, TRUE);

  return offset;
}



static int
dissect_f1ap_GNB_DU_Name(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_PrintableString(tvb, offset, actx, tree, hf_index,
                                          1, 150, TRUE);

  return offset;
}



static int
dissect_f1ap_Configured_EPS_TAC(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 981 "./asn1/f1ap/f1ap.cnf"
  tvbuff_t *parameter_tvb = NULL;
  offset = dissect_per_octet_string(tvb, offset, actx, tree, -1,
                                       2, 2, FALSE, &parameter_tvb);

  if (parameter_tvb) {
    actx->created_item = proto_tree_add_item(tree, hf_index, parameter_tvb, 0, 2, ENC_BIG_ENDIAN);
  }



  return offset;
}


static const per_sequence_t TDD_Info_sequence[] = {
  { &hf_f1ap_nRFreqInfo     , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_f1ap_NRFreqInfo },
  { &hf_f1ap_transmission_Bandwidth_01, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_f1ap_Transmission_Bandwidth },
  { &hf_f1ap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_f1ap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_f1ap_TDD_Info(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_f1ap_TDD_Info, TDD_Info_sequence);

  return offset;
}


static const value_string f1ap_NR_Mode_Info_vals[] = {
  {   0, "fDD" },
  {   1, "tDD" },
  {   2, "choice-extension" },
  { 0, NULL }
};

static const per_choice_t NR_Mode_Info_choice[] = {
  {   0, &hf_f1ap_fDD_01         , ASN1_NO_EXTENSIONS     , dissect_f1ap_FDD_Info },
  {   1, &hf_f1ap_tDD_01         , ASN1_NO_EXTENSIONS     , dissect_f1ap_TDD_Info },
  {   2, &hf_f1ap_choice_extension, ASN1_NO_EXTENSIONS     , dissect_f1ap_ProtocolIE_SingleContainer },
  { 0, NULL, 0, NULL }
};

static int
dissect_f1ap_NR_Mode_Info(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_f1ap_NR_Mode_Info, NR_Mode_Info_choice,
                                 NULL);

  return offset;
}



static int
dissect_f1ap_T_measurementTimingConfiguration(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 845 "./asn1/f1ap/f1ap.cnf"
  tvbuff_t *param_tvb = NULL;
  offset = dissect_per_octet_string(tvb, offset, actx, tree, hf_index,
                                       NO_BOUND, NO_BOUND, FALSE, &param_tvb);

  if (param_tvb) {
    proto_tree *subtree = proto_item_add_subtree(actx->created_item, ett_f1ap_measurementTimingConfiguration);
    dissect_nr_rrc_MeasurementTimingConfiguration_PDU(param_tvb, actx->pinfo, subtree, NULL);
  }



  return offset;
}


static const per_sequence_t Served_Cell_Information_sequence[] = {
  { &hf_f1ap_nRCGI          , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_f1ap_NRCGI },
  { &hf_f1ap_nRPCI          , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_f1ap_NRPCI },
  { &hf_f1ap_fiveGS_TAC     , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_f1ap_FiveGS_TAC },
  { &hf_f1ap_configured_EPS_TAC, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_f1ap_Configured_EPS_TAC },
  { &hf_f1ap_servedPLMNs    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_f1ap_ServedPLMNs_List },
  { &hf_f1ap_nR_Mode_Info   , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_f1ap_NR_Mode_Info },
  { &hf_f1ap_measurementTimingConfiguration, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_f1ap_T_measurementTimingConfiguration },
  { &hf_f1ap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_f1ap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_f1ap_Served_Cell_Information(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_f1ap_Served_Cell_Information, Served_Cell_Information_sequence);

  return offset;
}



static int
dissect_f1ap_MIB_message(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 871 "./asn1/f1ap/f1ap.cnf"
  tvbuff_t *param_tvb = NULL;
  offset = dissect_per_octet_string(tvb, offset, actx, tree, hf_index,
                                       NO_BOUND, NO_BOUND, FALSE, &param_tvb);

  if (param_tvb) {
    proto_tree *subtree = proto_item_add_subtree(actx->created_item, ett_f1ap_MIB_message);
    dissect_nr_rrc_MIB_PDU(param_tvb, actx->pinfo, subtree, NULL);
  }



  return offset;
}



static int
dissect_f1ap_SIB1_message(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 879 "./asn1/f1ap/f1ap.cnf"
  tvbuff_t *param_tvb = NULL;
  offset = dissect_per_octet_string(tvb, offset, actx, tree, hf_index,
                                       NO_BOUND, NO_BOUND, FALSE, &param_tvb);

  if (param_tvb) {
    proto_tree *subtree = proto_item_add_subtree(actx->created_item, ett_f1ap_SIB1_message);
    dissect_nr_rrc_SIB1_PDU(param_tvb, actx->pinfo, subtree, NULL);
  }



  return offset;
}


static const per_sequence_t GNB_DU_System_Information_sequence[] = {
  { &hf_f1ap_mIB_message    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_f1ap_MIB_message },
  { &hf_f1ap_sIB1_message   , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_f1ap_SIB1_message },
  { &hf_f1ap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_f1ap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_f1ap_GNB_DU_System_Information(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_f1ap_GNB_DU_System_Information, GNB_DU_System_Information_sequence);

  return offset;
}


static const per_sequence_t GNB_DU_Served_Cells_Item_sequence[] = {
  { &hf_f1ap_served_Cell_Information, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_f1ap_Served_Cell_Information },
  { &hf_f1ap_gNB_DU_System_Information, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_f1ap_GNB_DU_System_Information },
  { &hf_f1ap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_f1ap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_f1ap_GNB_DU_Served_Cells_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_f1ap_GNB_DU_Served_Cells_Item, GNB_DU_Served_Cells_Item_sequence);

  return offset;
}


static const value_string f1ap_GNB_DUConfigurationQuery_vals[] = {
  {   0, "true" },
  { 0, NULL }
};


static int
dissect_f1ap_GNB_DUConfigurationQuery(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     1, NULL, TRUE, 0, NULL);

  return offset;
}


static const value_string f1ap_GNBDUOverloadInformation_vals[] = {
  {   0, "overloaded" },
  {   1, "not-overloaded" },
  { 0, NULL }
};


static int
dissect_f1ap_GNBDUOverloadInformation(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     2, NULL, FALSE, 0, NULL);

  return offset;
}


static const per_sequence_t GNB_DU_TNL_Association_To_Remove_Item_sequence[] = {
  { &hf_f1ap_tNLAssociationTransportLayerAddress, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_f1ap_CP_TransportLayerAddress },
  { &hf_f1ap_tNLAssociationTransportLayerAddressgNBCU, ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_f1ap_CP_TransportLayerAddress },
  { &hf_f1ap_iE_Extensions  , ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_f1ap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_f1ap_GNB_DU_TNL_Association_To_Remove_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_f1ap_GNB_DU_TNL_Association_To_Remove_Item, GNB_DU_TNL_Association_To_Remove_Item_sequence);

  return offset;
}



static int
dissect_f1ap_HandoverPreparationInformation(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 922 "./asn1/f1ap/f1ap.cnf"
  tvbuff_t *param_tvb = NULL;
  offset = dissect_per_octet_string(tvb, offset, actx, tree, hf_index,
                                       NO_BOUND, NO_BOUND, FALSE, &param_tvb);

  if (param_tvb) {
    proto_tree *subtree = proto_item_add_subtree(actx->created_item, ett_f1ap_HandoverPreparationInformation);
    dissect_nr_rrc_HandoverPreparationInformation_PDU(param_tvb, actx->pinfo, subtree, NULL);
  }



  return offset;
}


static const value_string f1ap_IgnorePRACHConfiguration_vals[] = {
  {   0, "true" },
  { 0, NULL }
};


static int
dissect_f1ap_IgnorePRACHConfiguration(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     1, NULL, TRUE, 0, NULL);

  return offset;
}


static const value_string f1ap_IgnoreResourceCoordinationContainer_vals[] = {
  {   0, "yes" },
  { 0, NULL }
};


static int
dissect_f1ap_IgnoreResourceCoordinationContainer(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     1, NULL, TRUE, 0, NULL);

  return offset;
}


static const value_string f1ap_InactivityMonitoringRequest_vals[] = {
  {   0, "true" },
  { 0, NULL }
};


static int
dissect_f1ap_InactivityMonitoringRequest(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     1, NULL, TRUE, 0, NULL);

  return offset;
}


static const value_string f1ap_InactivityMonitoringResponse_vals[] = {
  {   0, "not-supported" },
  { 0, NULL }
};


static int
dissect_f1ap_InactivityMonitoringResponse(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     1, NULL, TRUE, 0, NULL);

  return offset;
}



static int
dissect_f1ap_MaskedIMEISV(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_bit_string(tvb, offset, actx, tree, hf_index,
                                     64, 64, FALSE, NULL, 0, NULL, NULL);

  return offset;
}



static int
dissect_f1ap_MeasGapSharingConfig(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 954 "./asn1/f1ap/f1ap.cnf"
  tvbuff_t *param_tvb = NULL;
  offset = dissect_per_octet_string(tvb, offset, actx, tree, hf_index,
                                       NO_BOUND, NO_BOUND, FALSE, &param_tvb);

  if (param_tvb) {
    proto_tree *subtree = proto_item_add_subtree(actx->created_item, ett_f1ap_MeasGapSharingConfig);
    dissect_nr_rrc_MeasGapSharingConfig_PDU(param_tvb, actx->pinfo, subtree, NULL);
  }



  return offset;
}



static int
dissect_f1ap_MeasurementTimingConfiguration(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 938 "./asn1/f1ap/f1ap.cnf"
  tvbuff_t *param_tvb = NULL;
  offset = dissect_per_octet_string(tvb, offset, actx, tree, hf_index,
                                       NO_BOUND, NO_BOUND, FALSE, &param_tvb);

  if (param_tvb) {
    proto_tree *subtree = proto_item_add_subtree(actx->created_item, ett_f1ap_measurementTimingConfiguration);
    dissect_nr_rrc_MeasurementTimingConfiguration_PDU(param_tvb, actx->pinfo, subtree, NULL);
  }



  return offset;
}



static int
dissect_f1ap_MessageIdentifier(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_bit_string(tvb, offset, actx, tree, hf_index,
                                     16, 16, FALSE, NULL, 0, NULL, NULL);

  return offset;
}


static const value_string f1ap_NeedforGap_vals[] = {
  {   0, "true" },
  { 0, NULL }
};


static int
dissect_f1ap_NeedforGap(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     1, NULL, TRUE, 0, NULL);

  return offset;
}


static const per_sequence_t NR_CGI_List_For_Restart_Item_sequence[] = {
  { &hf_f1ap_nRCGI          , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_f1ap_NRCGI },
  { &hf_f1ap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_f1ap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_f1ap_NR_CGI_List_For_Restart_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_f1ap_NR_CGI_List_For_Restart_Item, NR_CGI_List_For_Restart_Item_sequence);

  return offset;
}



static int
dissect_f1ap_SerialNumber(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_bit_string(tvb, offset, actx, tree, hf_index,
                                     16, 16, FALSE, NULL, 0, NULL, NULL);

  return offset;
}


static const per_sequence_t NotificationInformation_sequence[] = {
  { &hf_f1ap_message_Identifier, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_f1ap_MessageIdentifier },
  { &hf_f1ap_serialNumber   , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_f1ap_SerialNumber },
  { &hf_f1ap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_f1ap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_f1ap_NotificationInformation(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_f1ap_NotificationInformation, NotificationInformation_sequence);

  return offset;
}



static int
dissect_f1ap_NumberofBroadcastRequest(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 65535U, NULL, FALSE);

  return offset;
}


static const per_sequence_t PagingCell_Item_sequence[] = {
  { &hf_f1ap_nRCGI          , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_f1ap_NRCGI },
  { &hf_f1ap_iE_Extensions  , ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_f1ap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_f1ap_PagingCell_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_f1ap_PagingCell_Item, PagingCell_Item_sequence);

  return offset;
}


static const value_string f1ap_PagingDRX_vals[] = {
  {   0, "v32" },
  {   1, "v64" },
  {   2, "v128" },
  {   3, "v256" },
  { 0, NULL }
};


static int
dissect_f1ap_PagingDRX(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     4, NULL, TRUE, 0, NULL);

  return offset;
}



static int
dissect_f1ap_BIT_STRING_SIZE_40(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_bit_string(tvb, offset, actx, tree, hf_index,
                                     40, 40, FALSE, NULL, 0, NULL, NULL);

  return offset;
}


static const per_sequence_t RANUEPagingIdentity_sequence[] = {
  { &hf_f1ap_iRNTI          , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_f1ap_BIT_STRING_SIZE_40 },
  { &hf_f1ap_iE_Extensions  , ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_f1ap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_f1ap_RANUEPagingIdentity(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_f1ap_RANUEPagingIdentity, RANUEPagingIdentity_sequence);

  return offset;
}


static const value_string f1ap_PagingIdentity_vals[] = {
  {   0, "rANUEPagingIdentity" },
  {   1, "cNUEPagingIdentity" },
  {   2, "choice-extension" },
  { 0, NULL }
};

static const per_choice_t PagingIdentity_choice[] = {
  {   0, &hf_f1ap_rANUEPagingIdentity, ASN1_NO_EXTENSIONS     , dissect_f1ap_RANUEPagingIdentity },
  {   1, &hf_f1ap_cNUEPagingIdentity, ASN1_NO_EXTENSIONS     , dissect_f1ap_CNUEPagingIdentity },
  {   2, &hf_f1ap_choice_extension, ASN1_NO_EXTENSIONS     , dissect_f1ap_ProtocolIE_SingleContainer },
  { 0, NULL, 0, NULL }
};

static int
dissect_f1ap_PagingIdentity(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_f1ap_PagingIdentity, PagingIdentity_choice,
                                 NULL);

  return offset;
}


static const value_string f1ap_PagingOrigin_vals[] = {
  {   0, "non-3gpp" },
  { 0, NULL }
};


static int
dissect_f1ap_PagingOrigin(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     1, NULL, TRUE, 0, NULL);

  return offset;
}


static const value_string f1ap_PagingPriority_vals[] = {
  {   0, "priolevel1" },
  {   1, "priolevel2" },
  {   2, "priolevel3" },
  {   3, "priolevel4" },
  {   4, "priolevel5" },
  {   5, "priolevel6" },
  {   6, "priolevel7" },
  {   7, "priolevel8" },
  { 0, NULL }
};


static int
dissect_f1ap_PagingPriority(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     8, NULL, TRUE, 0, NULL);

  return offset;
}



static int
dissect_f1ap_PDCCH_BlindDetectionSCG(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 1123 "./asn1/f1ap/f1ap.cnf"
  tvbuff_t *parameter_tvb = NULL;
  offset = dissect_per_octet_string(tvb, offset, actx, tree, -1,
                                       NO_BOUND, NO_BOUND, FALSE, &parameter_tvb);

  if (parameter_tvb) {
    actx->created_item = proto_tree_add_item(tree, hf_index, parameter_tvb, 0, 1, ENC_BIG_ENDIAN);
  }



  return offset;
}



static int
dissect_f1ap_PDCP_SN(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 4095U, NULL, FALSE);

  return offset;
}


static const value_string f1ap_PDCPSNLength_vals[] = {
  {   0, "twelve-bits" },
  {   1, "eighteen-bits" },
  { 0, NULL }
};


static int
dissect_f1ap_PDCPSNLength(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     2, NULL, TRUE, 0, NULL);

  return offset;
}



static int
dissect_f1ap_PDUSessionID(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 255U, NULL, FALSE);

  return offset;
}



static int
dissect_f1ap_Ph_InfoMCG(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 1143 "./asn1/f1ap/f1ap.cnf"
  tvbuff_t *param_tvb = NULL;
  offset = dissect_per_octet_string(tvb, offset, actx, tree, hf_index,
                                       NO_BOUND, NO_BOUND, FALSE, &param_tvb);

  if (param_tvb) {
    proto_tree *subtree = proto_item_add_subtree(actx->created_item, ett_f1ap_Ph_InfoMCG);
    dissect_nr_rrc_PH_TypeListMCG_PDU(param_tvb, actx->pinfo, subtree, NULL);
  }



  return offset;
}



static int
dissect_f1ap_Ph_InfoSCG(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 1151 "./asn1/f1ap/f1ap.cnf"
  tvbuff_t *param_tvb = NULL;
  offset = dissect_per_octet_string(tvb, offset, actx, tree, hf_index,
                                       NO_BOUND, NO_BOUND, FALSE, &param_tvb);

  if (param_tvb) {
    proto_tree *subtree = proto_item_add_subtree(actx->created_item, ett_f1ap_Ph_InfoSCG);
    dissect_nr_rrc_PH_TypeListSCG_PDU(param_tvb, actx->pinfo, subtree, NULL);
  }



  return offset;
}



static int
dissect_f1ap_PortNumber(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 864 "./asn1/f1ap/f1ap.cnf"
  tvbuff_t *parameter_tvb = NULL;
  offset = dissect_per_bit_string(tvb, offset, actx, tree, -1,
                                     16, 16, FALSE, NULL, 0, &parameter_tvb, NULL);

  if (parameter_tvb) {
    actx->created_item = proto_tree_add_item(tree, hf_index, parameter_tvb, 0, 2, ENC_BIG_ENDIAN);
  }



  return offset;
}



static int
dissect_f1ap_SpectrumSharingGroupID(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            1U, maxCellineNB, NULL, FALSE);

  return offset;
}


static const per_sequence_t Protected_EUTRA_Resources_Item_sequence[] = {
  { &hf_f1ap_spectrumSharingGroupID, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_f1ap_SpectrumSharingGroupID },
  { &hf_f1ap_eUTRACells_List, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_f1ap_EUTRACells_List },
  { &hf_f1ap_iE_Extensions  , ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_f1ap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_f1ap_Protected_EUTRA_Resources_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_f1ap_Protected_EUTRA_Resources_Item, Protected_EUTRA_Resources_Item_sequence);

  return offset;
}


static const per_sequence_t Potential_SpCell_Item_sequence[] = {
  { &hf_f1ap_potential_SpCell_ID, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_f1ap_NRCGI },
  { &hf_f1ap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_f1ap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_f1ap_Potential_SpCell_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_f1ap_Potential_SpCell_Item, Potential_SpCell_Item_sequence);

  return offset;
}


static const per_sequence_t PWS_Failed_NR_CGI_Item_sequence[] = {
  { &hf_f1ap_nRCGI          , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_f1ap_NRCGI },
  { &hf_f1ap_numberOfBroadcasts, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_f1ap_NumberOfBroadcasts },
  { &hf_f1ap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_f1ap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_f1ap_PWS_Failed_NR_CGI_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_f1ap_PWS_Failed_NR_CGI_Item, PWS_Failed_NR_CGI_Item_sequence);

  return offset;
}



static int
dissect_f1ap_SIBType_PWS(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 1028 "./asn1/f1ap/f1ap.cnf"
  f1ap_private_data_t *f1ap_data = f1ap_get_private_data(actx->pinfo);
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            6U, 8U, &f1ap_data->sib_type, TRUE);




  return offset;
}



static int
dissect_f1ap_T_sIBmessage(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 1032 "./asn1/f1ap/f1ap.cnf"
  tvbuff_t *param_tvb = NULL;
  offset = dissect_per_octet_string(tvb, offset, actx, tree, hf_index,
                                       NO_BOUND, NO_BOUND, FALSE, &param_tvb);

  if (param_tvb) {
    f1ap_private_data_t *f1ap_data = f1ap_get_private_data(actx->pinfo);
    proto_tree *subtree = proto_item_add_subtree(actx->created_item, ett_f1ap_sIBmessage);
    switch (f1ap_data->sib_type) {
    case 6:
      dissect_nr_rrc_SIB6_PDU(param_tvb, actx->pinfo, subtree, NULL);
      break;
    case 7:
      dissect_nr_rrc_SIB7_PDU(param_tvb, actx->pinfo, subtree, NULL);
      break;
    case 8:
      dissect_nr_rrc_SIB8_PDU(param_tvb, actx->pinfo, subtree, NULL);
      break;
    default:
      break;
    }
  }



  return offset;
}


static const per_sequence_t PWSSystemInformation_sequence[] = {
  { &hf_f1ap_sIBtype        , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_f1ap_SIBType_PWS },
  { &hf_f1ap_sIBmessage     , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_f1ap_T_sIBmessage },
  { &hf_f1ap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_f1ap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_f1ap_PWSSystemInformation(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_f1ap_PWSSystemInformation, PWSSystemInformation_sequence);

  return offset;
}


static const value_string f1ap_QoSFlowMappingIndication_vals[] = {
  {   0, "ul" },
  {   1, "dl" },
  { 0, NULL }
};


static int
dissect_f1ap_QoSFlowMappingIndication(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     2, NULL, TRUE, 0, NULL);

  return offset;
}



static int
dissect_f1ap_RANUEID(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_octet_string(tvb, offset, actx, tree, hf_index,
                                       8, 8, FALSE, NULL);

  return offset;
}



static int
dissect_f1ap_SubscriberProfileIDforRFP(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            1U, 256U, NULL, TRUE);

  return offset;
}



static int
dissect_f1ap_RAT_FrequencySelectionPriority(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            1U, 256U, NULL, TRUE);

  return offset;
}


static const value_string f1ap_RAT_FrequencyPriorityInformation_vals[] = {
  {   0, "eNDC" },
  {   1, "nGRAN" },
  {   2, "choice-extension" },
  { 0, NULL }
};

static const per_choice_t RAT_FrequencyPriorityInformation_choice[] = {
  {   0, &hf_f1ap_eNDC           , ASN1_NO_EXTENSIONS     , dissect_f1ap_SubscriberProfileIDforRFP },
  {   1, &hf_f1ap_nGRAN          , ASN1_NO_EXTENSIONS     , dissect_f1ap_RAT_FrequencySelectionPriority },
  {   2, &hf_f1ap_choice_extension, ASN1_NO_EXTENSIONS     , dissect_f1ap_ProtocolIE_SingleContainer },
  { 0, NULL, 0, NULL }
};

static int
dissect_f1ap_RAT_FrequencyPriorityInformation(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_f1ap_RAT_FrequencyPriorityInformation, RAT_FrequencyPriorityInformation_choice,
                                 NULL);

  return offset;
}


static const value_string f1ap_Reestablishment_Indication_vals[] = {
  {   0, "reestablished" },
  { 0, NULL }
};


static int
dissect_f1ap_Reestablishment_Indication(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     1, NULL, TRUE, 0, NULL);

  return offset;
}



static int
dissect_f1ap_RequestedBandCombinationIndex(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 1159 "./asn1/f1ap/f1ap.cnf"
  tvbuff_t *param_tvb = NULL;
  offset = dissect_per_octet_string(tvb, offset, actx, tree, hf_index,
                                       NO_BOUND, NO_BOUND, FALSE, &param_tvb);

  if (param_tvb) {
    proto_tree *subtree = proto_item_add_subtree(actx->created_item, ett_f1ap_RequestedBandCombinationIndex);
    dissect_nr_rrc_BandCombinationIndex_PDU(param_tvb, actx->pinfo, subtree, NULL);
  }



  return offset;
}



static int
dissect_f1ap_RequestedFeatureSetEntryIndex(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 1167 "./asn1/f1ap/f1ap.cnf"
  tvbuff_t *param_tvb = NULL;
  offset = dissect_per_octet_string(tvb, offset, actx, tree, hf_index,
                                       NO_BOUND, NO_BOUND, FALSE, &param_tvb);

  if (param_tvb) {
    proto_tree *subtree = proto_item_add_subtree(actx->created_item, ett_f1ap_RequestedFeatureSetEntryIndex);
    dissect_nr_rrc_FeatureSetEntryIndex_PDU(param_tvb, actx->pinfo, subtree, NULL);
  }



  return offset;
}



static int
dissect_f1ap_Requested_PDCCH_BlindDetectionSCG(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 1133 "./asn1/f1ap/f1ap.cnf"
  tvbuff_t *parameter_tvb = NULL;
  offset = dissect_per_octet_string(tvb, offset, actx, tree, -1,
                                       NO_BOUND, NO_BOUND, FALSE, &parameter_tvb);

  if (parameter_tvb) {
    actx->created_item = proto_tree_add_item(tree, hf_index, parameter_tvb, 0, 1, ENC_BIG_ENDIAN);
  }



  return offset;
}



static int
dissect_f1ap_RequestedP_MaxFR2(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 1175 "./asn1/f1ap/f1ap.cnf"
  tvbuff_t *param_tvb = NULL;
  offset = dissect_per_octet_string(tvb, offset, actx, tree, hf_index,
                                       NO_BOUND, NO_BOUND, FALSE, &param_tvb);

  if (param_tvb) {
    proto_tree *subtree = proto_item_add_subtree(actx->created_item, ett_f1ap_RequestedP_MaxFR2);
    dissect_nr_rrc_P_Max_PDU(param_tvb, actx->pinfo, subtree, NULL);
  }



  return offset;
}


static const value_string f1ap_RequestType_vals[] = {
  {   0, "offer" },
  {   1, "execution" },
  { 0, NULL }
};


static int
dissect_f1ap_RequestType(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     2, NULL, TRUE, 0, NULL);

  return offset;
}


static const per_sequence_t ResourceCoordinationEUTRACellInfo_sequence[] = {
  { &hf_f1ap_eUTRA_Mode_Info, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_f1ap_EUTRA_Coex_Mode_Info },
  { &hf_f1ap_eUTRA_PRACH_Configuration, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_f1ap_EUTRA_PRACH_Configuration },
  { &hf_f1ap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_f1ap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_f1ap_ResourceCoordinationEUTRACellInfo(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_f1ap_ResourceCoordinationEUTRACellInfo, ResourceCoordinationEUTRACellInfo_sequence);

  return offset;
}


static const per_sequence_t ResourceCoordinationTransferInformation_sequence[] = {
  { &hf_f1ap_meNB_Cell_ID   , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_f1ap_EUTRA_Cell_ID },
  { &hf_f1ap_resourceCoordinationEUTRACellInfo, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_f1ap_ResourceCoordinationEUTRACellInfo },
  { &hf_f1ap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_f1ap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_f1ap_ResourceCoordinationTransferInformation(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_f1ap_ResourceCoordinationTransferInformation, ResourceCoordinationTransferInformation_sequence);

  return offset;
}



static int
dissect_f1ap_ResourceCoordinationTransferContainer(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 723 "./asn1/f1ap/f1ap.cnf"
  tvbuff_t *param_tvb = NULL;
  offset = dissect_per_octet_string(tvb, offset, actx, tree, hf_index,
                                       NO_BOUND, NO_BOUND, FALSE, &param_tvb);

  if (param_tvb) {
    proto_tree *subtree;
    f1ap_private_data_t *f1ap_data = f1ap_get_private_data(actx->pinfo);

    subtree = proto_item_add_subtree(actx->created_item, ett_f1ap_ResourceCoordinationTransferContainer);
    switch (f1ap_data->message_type) {
    case INITIATING_MESSAGE:
      switch (f1ap_data->procedure_code) {
      case id_UEContextSetup:
      case id_UEContextModification:
        dissect_x2ap_MeNBResourceCoordinationInformation_PDU(param_tvb, actx->pinfo, subtree, NULL);
        break;
      case id_UEContextModificationRequired:
        dissect_x2ap_SgNBResourceCoordinationInformation_PDU(param_tvb, actx->pinfo, subtree, NULL);
        break;
      default:
        break;
      }
      break;
    case SUCCESSFUL_OUTCOME:
      switch (f1ap_data->procedure_code) {
      case id_UEContextSetup:
      case id_UEContextModification:
        dissect_x2ap_SgNBResourceCoordinationInformation_PDU(param_tvb, actx->pinfo, subtree, NULL);
        break;
      case id_UEContextModificationRequired:
        dissect_x2ap_MeNBResourceCoordinationInformation_PDU(param_tvb, actx->pinfo, subtree, NULL);
        break;
      default:
        break;
      }
      break;
    default:
      break;
    }
  }



  return offset;
}



static int
dissect_f1ap_RepetitionPeriod(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 131071U, NULL, TRUE);

  return offset;
}


static const per_sequence_t RLCFailureIndication_sequence[] = {
  { &hf_f1ap_assocatedLCID  , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_f1ap_LCID },
  { &hf_f1ap_iE_Extensions  , ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_f1ap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_f1ap_RLCFailureIndication(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_f1ap_RLCFailureIndication, RLCFailureIndication_sequence);

  return offset;
}


static const per_sequence_t RLC_Status_sequence[] = {
  { &hf_f1ap_reestablishment_Indication, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_f1ap_Reestablishment_Indication },
  { &hf_f1ap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_f1ap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_f1ap_RLC_Status(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_f1ap_RLC_Status, RLC_Status_sequence);

  return offset;
}



static int
dissect_f1ap_RRCContainer(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 763 "./asn1/f1ap/f1ap.cnf"
  tvbuff_t *param_tvb = NULL;
  offset = dissect_per_octet_string(tvb, offset, actx, tree, hf_index,
                                       NO_BOUND, NO_BOUND, FALSE, &param_tvb);

  if (param_tvb) {
    proto_tree *subtree;
    f1ap_private_data_t *f1ap_data = f1ap_get_private_data(actx->pinfo);

    subtree = proto_item_add_subtree(actx->created_item, ett_f1ap_RRCContainer);
    switch (f1ap_data->message_type) {
    case INITIATING_MESSAGE:
      switch (f1ap_data->procedure_code) {
      case id_InitialULRRCMessageTransfer:
        col_append_str(actx->pinfo->cinfo, COL_PROTOCOL, "/");
        col_set_fence(actx->pinfo->cinfo, COL_PROTOCOL);
        call_dissector(nr_rrc_ul_ccch_handle, param_tvb, actx->pinfo, subtree);
        break;
      case id_ULRRCMessageTransfer:
        switch (f1ap_data->srb_id) {
        case 1:
        case 2:
        case 3:
          col_append_str(actx->pinfo->cinfo, COL_PROTOCOL, "/");
          col_set_fence(actx->pinfo->cinfo, COL_PROTOCOL);
          add_nr_pdcp_meta_data(actx->pinfo, PDCP_NR_DIRECTION_UPLINK, f1ap_data->srb_id);
          call_dissector(nr_pdcp_handle, param_tvb, actx->pinfo, subtree);
          break;
        default:
          break;
        }
        break;
      case id_DLRRCMessageTransfer:
      case id_UEContextRelease:
        switch (f1ap_data->srb_id) {
        case 0:
          col_append_str(actx->pinfo->cinfo, COL_PROTOCOL, "/");
          col_set_fence(actx->pinfo->cinfo, COL_PROTOCOL);
          call_dissector(nr_rrc_dl_ccch_handle, param_tvb, actx->pinfo, subtree);
          break;
        case 1:
        case 2:
        case 3:
          col_append_str(actx->pinfo->cinfo, COL_PROTOCOL, "/");
          col_set_fence(actx->pinfo->cinfo, COL_PROTOCOL);
          add_nr_pdcp_meta_data(actx->pinfo, PDCP_NR_DIRECTION_DOWNLINK, f1ap_data->srb_id);
          call_dissector(nr_pdcp_handle, param_tvb, actx->pinfo, subtree);
          break;
        default:
          break;
        }
        break;
      default:
        break;
      }
      break;
    default:
      break;
    }
  }



  return offset;
}



static int
dissect_f1ap_RRCContainer_RRCSetupComplete(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 826 "./asn1/f1ap/f1ap.cnf"
  tvbuff_t *param_tvb = NULL;
  offset = dissect_per_octet_string(tvb, offset, actx, tree, hf_index,
                                       NO_BOUND, NO_BOUND, FALSE, &param_tvb);

  if (param_tvb) {
    proto_tree *subtree;
    subtree = proto_item_add_subtree(actx->created_item, ett_f1ap_RRCContainer_RRCSetupComplete);
    col_append_str(actx->pinfo->cinfo, COL_PROTOCOL, "/");
    col_set_fence(actx->pinfo->cinfo, COL_PROTOCOL);
    call_dissector(nr_rrc_ul_dcch_handle, param_tvb, actx->pinfo, subtree);
  }



  return offset;
}


static const per_sequence_t RRCDeliveryStatus_sequence[] = {
  { &hf_f1ap_delivery_status, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_f1ap_PDCP_SN },
  { &hf_f1ap_triggering_message, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_f1ap_PDCP_SN },
  { &hf_f1ap_iE_Extensions  , ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_f1ap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_f1ap_RRCDeliveryStatus(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_f1ap_RRCDeliveryStatus, RRCDeliveryStatus_sequence);

  return offset;
}


static const value_string f1ap_RRCDeliveryStatusRequest_vals[] = {
  {   0, "true" },
  { 0, NULL }
};


static int
dissect_f1ap_RRCDeliveryStatusRequest(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     1, NULL, TRUE, 0, NULL);

  return offset;
}


static const value_string f1ap_RRCReconfigurationCompleteIndicator_vals[] = {
  {   0, "true" },
  {   1, "failure" },
  { 0, NULL }
};


static int
dissect_f1ap_RRCReconfigurationCompleteIndicator(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     1, NULL, TRUE, 1, NULL);

  return offset;
}



static int
dissect_f1ap_BIT_STRING_SIZE_3(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_bit_string(tvb, offset, actx, tree, hf_index,
                                     3, 3, FALSE, NULL, 0, NULL, NULL);

  return offset;
}


static const per_sequence_t RRC_Version_sequence[] = {
  { &hf_f1ap_latest_RRC_Version, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_f1ap_BIT_STRING_SIZE_3 },
  { &hf_f1ap_iE_Extensions  , ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_f1ap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_f1ap_RRC_Version(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_f1ap_RRC_Version, RRC_Version_sequence);

  return offset;
}



static int
dissect_f1ap_Latest_RRC_Version_Enhanced(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 1081 "./asn1/f1ap/f1ap.cnf"
  tvbuff_t *param_tvb = NULL;
  offset = dissect_per_octet_string(tvb, offset, actx, tree, hf_index,
                                       3, 3, FALSE, &param_tvb);



#line 1084 "./asn1/f1ap/f1ap.cnf"
  if (param_tvb) {
    proto_item_set_text(actx->created_item, "%u.%u.%u", tvb_get_guint8(param_tvb, 0), tvb_get_guint8(param_tvb, 1), tvb_get_guint8(param_tvb, 2));
  }


  return offset;
}


static const per_sequence_t SCell_FailedtoSetup_Item_sequence[] = {
  { &hf_f1ap_sCell_ID       , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_f1ap_NRCGI },
  { &hf_f1ap_cause          , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_f1ap_Cause },
  { &hf_f1ap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_f1ap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_f1ap_SCell_FailedtoSetup_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_f1ap_SCell_FailedtoSetup_Item, SCell_FailedtoSetup_Item_sequence);

  return offset;
}


static const per_sequence_t SCell_FailedtoSetupMod_Item_sequence[] = {
  { &hf_f1ap_sCell_ID       , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_f1ap_NRCGI },
  { &hf_f1ap_cause          , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_f1ap_Cause },
  { &hf_f1ap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_f1ap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_f1ap_SCell_FailedtoSetupMod_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_f1ap_SCell_FailedtoSetupMod_Item, SCell_FailedtoSetupMod_Item_sequence);

  return offset;
}


static const per_sequence_t SCell_ToBeRemoved_Item_sequence[] = {
  { &hf_f1ap_sCell_ID       , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_f1ap_NRCGI },
  { &hf_f1ap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_f1ap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_f1ap_SCell_ToBeRemoved_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_f1ap_SCell_ToBeRemoved_Item, SCell_ToBeRemoved_Item_sequence);

  return offset;
}



static int
dissect_f1ap_SCellIndex(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            1U, 31U, NULL, TRUE);

  return offset;
}


static const per_sequence_t SCell_ToBeSetup_Item_sequence[] = {
  { &hf_f1ap_sCell_ID       , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_f1ap_NRCGI },
  { &hf_f1ap_sCellIndex     , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_f1ap_SCellIndex },
  { &hf_f1ap_sCellULConfigured, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_f1ap_CellULConfigured },
  { &hf_f1ap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_f1ap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_f1ap_SCell_ToBeSetup_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_f1ap_SCell_ToBeSetup_Item, SCell_ToBeSetup_Item_sequence);

  return offset;
}


static const per_sequence_t SCell_ToBeSetupMod_Item_sequence[] = {
  { &hf_f1ap_sCell_ID       , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_f1ap_NRCGI },
  { &hf_f1ap_sCellIndex     , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_f1ap_SCellIndex },
  { &hf_f1ap_sCellULConfigured, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_f1ap_CellULConfigured },
  { &hf_f1ap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_f1ap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_f1ap_SCell_ToBeSetupMod_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_f1ap_SCell_ToBeSetupMod_Item, SCell_ToBeSetupMod_Item_sequence);

  return offset;
}



static int
dissect_f1ap_SelectedBandCombinationIndex(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_octet_string(tvb, offset, actx, tree, hf_index,
                                       NO_BOUND, NO_BOUND, FALSE, NULL);

  return offset;
}



static int
dissect_f1ap_SelectedFeatureSetEntryIndex(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_octet_string(tvb, offset, actx, tree, hf_index,
                                       NO_BOUND, NO_BOUND, FALSE, NULL);

  return offset;
}



static int
dissect_f1ap_ServCellIndex(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 31U, NULL, TRUE);

  return offset;
}



static int
dissect_f1ap_ServingCellMO(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            1U, 64U, NULL, TRUE);

  return offset;
}


static const per_sequence_t Served_Cells_To_Add_Item_sequence[] = {
  { &hf_f1ap_served_Cell_Information, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_f1ap_Served_Cell_Information },
  { &hf_f1ap_gNB_DU_System_Information, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_f1ap_GNB_DU_System_Information },
  { &hf_f1ap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_f1ap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_f1ap_Served_Cells_To_Add_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_f1ap_Served_Cells_To_Add_Item, Served_Cells_To_Add_Item_sequence);

  return offset;
}


static const per_sequence_t Served_Cells_To_Delete_Item_sequence[] = {
  { &hf_f1ap_oldNRCGI       , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_f1ap_NRCGI },
  { &hf_f1ap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_f1ap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_f1ap_Served_Cells_To_Delete_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_f1ap_Served_Cells_To_Delete_Item, Served_Cells_To_Delete_Item_sequence);

  return offset;
}


static const per_sequence_t Served_Cells_To_Modify_Item_sequence[] = {
  { &hf_f1ap_oldNRCGI       , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_f1ap_NRCGI },
  { &hf_f1ap_served_Cell_Information, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_f1ap_Served_Cell_Information },
  { &hf_f1ap_gNB_DU_System_Information, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_f1ap_GNB_DU_System_Information },
  { &hf_f1ap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_f1ap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_f1ap_Served_Cells_To_Modify_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_f1ap_Served_Cells_To_Modify_Item, Served_Cells_To_Modify_Item_sequence);

  return offset;
}



static int
dissect_f1ap_SItype(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            1U, 32U, NULL, TRUE);

  return offset;
}


static const per_sequence_t SItype_Item_sequence[] = {
  { &hf_f1ap_sItype         , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_f1ap_SItype },
  { &hf_f1ap_iE_Extensions  , ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_f1ap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_f1ap_SItype_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_f1ap_SItype_Item, SItype_Item_sequence);

  return offset;
}


static const per_sequence_t SItype_List_sequence_of[1] = {
  { &hf_f1ap_SItype_List_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_f1ap_SItype_Item },
};

static int
dissect_f1ap_SItype_List(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_f1ap_SItype_List, SItype_List_sequence_of,
                                                  1, maxnoofSITypes, FALSE);

  return offset;
}



static int
dissect_f1ap_SRBID(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 822 "./asn1/f1ap/f1ap.cnf"
  f1ap_private_data_t *f1ap_data = f1ap_get_private_data(actx->pinfo);
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 3U, &f1ap_data->srb_id, TRUE);




  return offset;
}


static const per_sequence_t SRBs_FailedToBeSetup_Item_sequence[] = {
  { &hf_f1ap_sRBID          , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_f1ap_SRBID },
  { &hf_f1ap_cause          , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_f1ap_Cause },
  { &hf_f1ap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_f1ap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_f1ap_SRBs_FailedToBeSetup_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_f1ap_SRBs_FailedToBeSetup_Item, SRBs_FailedToBeSetup_Item_sequence);

  return offset;
}


static const per_sequence_t SRBs_FailedToBeSetupMod_Item_sequence[] = {
  { &hf_f1ap_sRBID          , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_f1ap_SRBID },
  { &hf_f1ap_cause          , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_f1ap_Cause },
  { &hf_f1ap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_f1ap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_f1ap_SRBs_FailedToBeSetupMod_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_f1ap_SRBs_FailedToBeSetupMod_Item, SRBs_FailedToBeSetupMod_Item_sequence);

  return offset;
}


static const per_sequence_t SRBs_Modified_Item_sequence[] = {
  { &hf_f1ap_sRBID          , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_f1ap_SRBID },
  { &hf_f1ap_lCID           , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_f1ap_LCID },
  { &hf_f1ap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_f1ap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_f1ap_SRBs_Modified_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_f1ap_SRBs_Modified_Item, SRBs_Modified_Item_sequence);

  return offset;
}


static const per_sequence_t SRBs_Required_ToBeReleased_Item_sequence[] = {
  { &hf_f1ap_sRBID          , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_f1ap_SRBID },
  { &hf_f1ap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_f1ap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_f1ap_SRBs_Required_ToBeReleased_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_f1ap_SRBs_Required_ToBeReleased_Item, SRBs_Required_ToBeReleased_Item_sequence);

  return offset;
}


static const per_sequence_t SRBs_Setup_Item_sequence[] = {
  { &hf_f1ap_sRBID          , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_f1ap_SRBID },
  { &hf_f1ap_lCID           , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_f1ap_LCID },
  { &hf_f1ap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_f1ap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_f1ap_SRBs_Setup_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_f1ap_SRBs_Setup_Item, SRBs_Setup_Item_sequence);

  return offset;
}


static const per_sequence_t SRBs_SetupMod_Item_sequence[] = {
  { &hf_f1ap_sRBID          , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_f1ap_SRBID },
  { &hf_f1ap_lCID           , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_f1ap_LCID },
  { &hf_f1ap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_f1ap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_f1ap_SRBs_SetupMod_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_f1ap_SRBs_SetupMod_Item, SRBs_SetupMod_Item_sequence);

  return offset;
}


static const per_sequence_t SRBs_ToBeReleased_Item_sequence[] = {
  { &hf_f1ap_sRBID          , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_f1ap_SRBID },
  { &hf_f1ap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_f1ap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_f1ap_SRBs_ToBeReleased_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_f1ap_SRBs_ToBeReleased_Item, SRBs_ToBeReleased_Item_sequence);

  return offset;
}


static const per_sequence_t SRBs_ToBeSetup_Item_sequence[] = {
  { &hf_f1ap_sRBID          , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_f1ap_SRBID },
  { &hf_f1ap_duplicationIndication, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_f1ap_DuplicationIndication },
  { &hf_f1ap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_f1ap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_f1ap_SRBs_ToBeSetup_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_f1ap_SRBs_ToBeSetup_Item, SRBs_ToBeSetup_Item_sequence);

  return offset;
}


static const per_sequence_t SRBs_ToBeSetupMod_Item_sequence[] = {
  { &hf_f1ap_sRBID          , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_f1ap_SRBID },
  { &hf_f1ap_duplicationIndication, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_f1ap_DuplicationIndication },
  { &hf_f1ap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_f1ap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_f1ap_SRBs_ToBeSetupMod_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_f1ap_SRBs_ToBeSetupMod_Item, SRBs_ToBeSetupMod_Item_sequence);

  return offset;
}


static const value_string f1ap_SULAccessIndication_vals[] = {
  {   0, "true" },
  { 0, NULL }
};


static int
dissect_f1ap_SULAccessIndication(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     1, NULL, TRUE, 0, NULL);

  return offset;
}



static int
dissect_f1ap_SystemInformationAreaID(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_bit_string(tvb, offset, actx, tree, hf_index,
                                     24, 24, FALSE, NULL, 0, NULL, NULL);

  return offset;
}


static const value_string f1ap_TimeToWait_vals[] = {
  {   0, "v1s" },
  {   1, "v2s" },
  {   2, "v5s" },
  {   3, "v10s" },
  {   4, "v20s" },
  {   5, "v60s" },
  { 0, NULL }
};


static int
dissect_f1ap_TimeToWait(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     6, NULL, TRUE, 0, NULL);

  return offset;
}


static const value_string f1ap_TransmissionActionIndicator_vals[] = {
  {   0, "stop" },
  {   1, "restart" },
  { 0, NULL }
};


static int
dissect_f1ap_TransmissionActionIndicator(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     1, NULL, TRUE, 1, NULL);

  return offset;
}



static int
dissect_f1ap_UACReductionIndication(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 100U, NULL, FALSE);

  return offset;
}


static const value_string f1ap_UACAction_vals[] = {
  {   0, "reject-non-emergency-mo-dt" },
  {   1, "reject-rrc-cr-signalling" },
  {   2, "permit-emergency-sessions-and-mobile-terminated-services-only" },
  {   3, "permit-high-priority-sessions-and-mobile-terminated-services-only" },
  { 0, NULL }
};


static int
dissect_f1ap_UACAction(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     4, NULL, TRUE, 0, NULL);

  return offset;
}



static int
dissect_f1ap_INTEGER_32_63_(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            32U, 63U, NULL, TRUE);

  return offset;
}



static int
dissect_f1ap_BIT_STRING_SIZE_7(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_bit_string(tvb, offset, actx, tree, hf_index,
                                     7, 7, FALSE, NULL, 0, NULL, NULL);

  return offset;
}


static const per_sequence_t UACOperatorDefined_sequence[] = {
  { &hf_f1ap_accessCategory , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_f1ap_INTEGER_32_63_ },
  { &hf_f1ap_accessIdentity , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_f1ap_BIT_STRING_SIZE_7 },
  { &hf_f1ap_iE_Extensions  , ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_f1ap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_f1ap_UACOperatorDefined(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_f1ap_UACOperatorDefined, UACOperatorDefined_sequence);

  return offset;
}


static const value_string f1ap_UACCategoryType_vals[] = {
  {   0, "uACstandardized" },
  {   1, "uACOperatorDefined" },
  {   2, "choice-extension" },
  { 0, NULL }
};

static const per_choice_t UACCategoryType_choice[] = {
  {   0, &hf_f1ap_uACstandardized, ASN1_NO_EXTENSIONS     , dissect_f1ap_UACAction },
  {   1, &hf_f1ap_uACOperatorDefined, ASN1_NO_EXTENSIONS     , dissect_f1ap_UACOperatorDefined },
  {   2, &hf_f1ap_choice_extension, ASN1_NO_EXTENSIONS     , dissect_f1ap_ProtocolIE_SingleContainer },
  { 0, NULL, 0, NULL }
};

static int
dissect_f1ap_UACCategoryType(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_f1ap_UACCategoryType, UACCategoryType_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t UACType_Item_sequence[] = {
  { &hf_f1ap_uACReductionIndication, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_f1ap_UACReductionIndication },
  { &hf_f1ap_uACCategoryType, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_f1ap_UACCategoryType },
  { &hf_f1ap_iE_Extensions  , ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_f1ap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_f1ap_UACType_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_f1ap_UACType_Item, UACType_Item_sequence);

  return offset;
}


static const per_sequence_t UACType_List_sequence_of[1] = {
  { &hf_f1ap_UACType_List_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_f1ap_UACType_Item },
};

static int
dissect_f1ap_UACType_List(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_f1ap_UACType_List, UACType_List_sequence_of,
                                                  1, maxnoofUACperPLMN, FALSE);

  return offset;
}


static const per_sequence_t UACPLMN_Item_sequence[] = {
  { &hf_f1ap_pLMNIdentity   , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_f1ap_PLMN_Identity },
  { &hf_f1ap_uACType_List   , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_f1ap_UACType_List },
  { &hf_f1ap_iE_Extensions  , ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_f1ap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_f1ap_UACPLMN_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_f1ap_UACPLMN_Item, UACPLMN_Item_sequence);

  return offset;
}


static const per_sequence_t UACPLMN_List_sequence_of[1] = {
  { &hf_f1ap_UACPLMN_List_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_f1ap_UACPLMN_Item },
};

static int
dissect_f1ap_UACPLMN_List(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_f1ap_UACPLMN_List, UACPLMN_List_sequence_of,
                                                  1, maxnoofUACPLMNs, FALSE);

  return offset;
}


static const per_sequence_t UAC_Assistance_Info_sequence[] = {
  { &hf_f1ap_uACPLMN_List   , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_f1ap_UACPLMN_List },
  { &hf_f1ap_iE_Extensions  , ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_f1ap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_f1ap_UAC_Assistance_Info(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_f1ap_UAC_Assistance_Info, UAC_Assistance_Info_sequence);

  return offset;
}


static const per_sequence_t UE_associatedLogicalF1_ConnectionItem_sequence[] = {
  { &hf_f1ap_gNB_CU_UE_F1AP_ID, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_f1ap_GNB_CU_UE_F1AP_ID },
  { &hf_f1ap_gNB_DU_UE_F1AP_ID, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_f1ap_GNB_DU_UE_F1AP_ID },
  { &hf_f1ap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_f1ap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_f1ap_UE_associatedLogicalF1_ConnectionItem(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_f1ap_UE_associatedLogicalF1_ConnectionItem, UE_associatedLogicalF1_ConnectionItem_sequence);

  return offset;
}



static int
dissect_f1ap_UEAssistanceInformation(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 1183 "./asn1/f1ap/f1ap.cnf"
  tvbuff_t *param_tvb = NULL;
  offset = dissect_per_octet_string(tvb, offset, actx, tree, hf_index,
                                       NO_BOUND, NO_BOUND, FALSE, &param_tvb);

  if (param_tvb) {
    proto_tree *subtree = proto_item_add_subtree(actx->created_item, ett_f1ap_UEAssistanceInformation);
    dissect_nr_rrc_UEAssistanceInformation_PDU(param_tvb, actx->pinfo, subtree, NULL);
  }



  return offset;
}


static const value_string f1ap_UEContextNotRetrievable_vals[] = {
  {   0, "true" },
  { 0, NULL }
};


static int
dissect_f1ap_UEContextNotRetrievable(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     1, NULL, TRUE, 0, NULL);

  return offset;
}



static int
dissect_f1ap_BIT_STRING_SIZE_10(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_bit_string(tvb, offset, actx, tree, hf_index,
                                     10, 10, FALSE, NULL, 0, NULL, NULL);

  return offset;
}


static const value_string f1ap_UEIdentityIndexValue_vals[] = {
  {   0, "indexLength10" },
  {   1, "choice-extension" },
  { 0, NULL }
};

static const per_choice_t UEIdentityIndexValue_choice[] = {
  {   0, &hf_f1ap_indexLength10  , ASN1_NO_EXTENSIONS     , dissect_f1ap_BIT_STRING_SIZE_10 },
  {   1, &hf_f1ap_choice_extension, ASN1_NO_EXTENSIONS     , dissect_f1ap_ProtocolIE_SingleContainer },
  { 0, NULL, 0, NULL }
};

static int
dissect_f1ap_UEIdentityIndexValue(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_f1ap_UEIdentityIndexValue, UEIdentityIndexValue_choice,
                                 NULL);

  return offset;
}



static int
dissect_f1ap_UplinkTxDirectCurrentListInformation(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 1073 "./asn1/f1ap/f1ap.cnf"
  tvbuff_t *param_tvb = NULL;
  offset = dissect_per_octet_string(tvb, offset, actx, tree, hf_index,
                                       NO_BOUND, NO_BOUND, FALSE, &param_tvb);

  if (param_tvb) {
    proto_tree *subtree = proto_item_add_subtree(actx->created_item, ett_f1ap_UplinkTxDirectCurrentListInformation);
    dissect_nr_rrc_UplinkTxDirectCurrentList_PDU(param_tvb, actx->pinfo, subtree, NULL);
  }



  return offset;
}


static const per_sequence_t Reset_sequence[] = {
  { &hf_f1ap_protocolIEs    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_f1ap_ProtocolIE_Container },
  { NULL, 0, 0, NULL }
};

static int
dissect_f1ap_Reset(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 1191 "./asn1/f1ap/f1ap.cnf"
  col_append_sep_str(actx->pinfo->cinfo, COL_INFO, NULL, "Reset");

  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_f1ap_Reset, Reset_sequence);

  return offset;
}


static const value_string f1ap_ResetAll_vals[] = {
  {   0, "reset-all" },
  { 0, NULL }
};


static int
dissect_f1ap_ResetAll(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     1, NULL, TRUE, 0, NULL);

  return offset;
}


static const per_sequence_t UE_associatedLogicalF1_ConnectionListRes_sequence_of[1] = {
  { &hf_f1ap_UE_associatedLogicalF1_ConnectionListRes_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_f1ap_ProtocolIE_SingleContainer },
};

static int
dissect_f1ap_UE_associatedLogicalF1_ConnectionListRes(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_f1ap_UE_associatedLogicalF1_ConnectionListRes, UE_associatedLogicalF1_ConnectionListRes_sequence_of,
                                                  1, maxnoofIndividualF1ConnectionsToReset, FALSE);

  return offset;
}


static const value_string f1ap_ResetType_vals[] = {
  {   0, "f1-Interface" },
  {   1, "partOfF1-Interface" },
  {   2, "choice-extension" },
  { 0, NULL }
};

static const per_choice_t ResetType_choice[] = {
  {   0, &hf_f1ap_f1_Interface   , ASN1_NO_EXTENSIONS     , dissect_f1ap_ResetAll },
  {   1, &hf_f1ap_partOfF1_Interface, ASN1_NO_EXTENSIONS     , dissect_f1ap_UE_associatedLogicalF1_ConnectionListRes },
  {   2, &hf_f1ap_choice_extension, ASN1_NO_EXTENSIONS     , dissect_f1ap_ProtocolIE_SingleContainer },
  { 0, NULL, 0, NULL }
};

static int
dissect_f1ap_ResetType(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_f1ap_ResetType, ResetType_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t ResetAcknowledge_sequence[] = {
  { &hf_f1ap_protocolIEs    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_f1ap_ProtocolIE_Container },
  { NULL, 0, 0, NULL }
};

static int
dissect_f1ap_ResetAcknowledge(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 1193 "./asn1/f1ap/f1ap.cnf"
  col_append_sep_str(actx->pinfo->cinfo, COL_INFO, NULL, "ResetAcknowledge");

  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_f1ap_ResetAcknowledge, ResetAcknowledge_sequence);

  return offset;
}


static const per_sequence_t UE_associatedLogicalF1_ConnectionListResAck_sequence_of[1] = {
  { &hf_f1ap_UE_associatedLogicalF1_ConnectionListResAck_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_f1ap_ProtocolIE_SingleContainer },
};

static int
dissect_f1ap_UE_associatedLogicalF1_ConnectionListResAck(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_f1ap_UE_associatedLogicalF1_ConnectionListResAck, UE_associatedLogicalF1_ConnectionListResAck_sequence_of,
                                                  1, maxnoofIndividualF1ConnectionsToReset, FALSE);

  return offset;
}


static const per_sequence_t ErrorIndication_sequence[] = {
  { &hf_f1ap_protocolIEs    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_f1ap_ProtocolIE_Container },
  { NULL, 0, 0, NULL }
};

static int
dissect_f1ap_ErrorIndication(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 1243 "./asn1/f1ap/f1ap.cnf"
  col_append_sep_str(actx->pinfo->cinfo, COL_INFO, NULL, "ErrorIndication");

  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_f1ap_ErrorIndication, ErrorIndication_sequence);

  return offset;
}


static const per_sequence_t F1SetupRequest_sequence[] = {
  { &hf_f1ap_protocolIEs    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_f1ap_ProtocolIE_Container },
  { NULL, 0, 0, NULL }
};

static int
dissect_f1ap_F1SetupRequest(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 1195 "./asn1/f1ap/f1ap.cnf"
  col_append_sep_str(actx->pinfo->cinfo, COL_INFO, NULL, "F1SetupRequest");

  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_f1ap_F1SetupRequest, F1SetupRequest_sequence);

  return offset;
}


static const per_sequence_t GNB_DU_Served_Cells_List_sequence_of[1] = {
  { &hf_f1ap_GNB_DU_Served_Cells_List_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_f1ap_ProtocolIE_SingleContainer },
};

static int
dissect_f1ap_GNB_DU_Served_Cells_List(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_f1ap_GNB_DU_Served_Cells_List, GNB_DU_Served_Cells_List_sequence_of,
                                                  1, maxCellingNBDU, FALSE);

  return offset;
}


static const per_sequence_t F1SetupResponse_sequence[] = {
  { &hf_f1ap_protocolIEs    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_f1ap_ProtocolIE_Container },
  { NULL, 0, 0, NULL }
};

static int
dissect_f1ap_F1SetupResponse(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 1197 "./asn1/f1ap/f1ap.cnf"
  col_append_sep_str(actx->pinfo->cinfo, COL_INFO, NULL, "F1SetupResponse");

  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_f1ap_F1SetupResponse, F1SetupResponse_sequence);

  return offset;
}


static const per_sequence_t Cells_to_be_Activated_List_sequence_of[1] = {
  { &hf_f1ap_Cells_to_be_Activated_List_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_f1ap_ProtocolIE_SingleContainer },
};

static int
dissect_f1ap_Cells_to_be_Activated_List(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_f1ap_Cells_to_be_Activated_List, Cells_to_be_Activated_List_sequence_of,
                                                  1, maxCellingNBDU, FALSE);

  return offset;
}


static const per_sequence_t F1SetupFailure_sequence[] = {
  { &hf_f1ap_protocolIEs    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_f1ap_ProtocolIE_Container },
  { NULL, 0, 0, NULL }
};

static int
dissect_f1ap_F1SetupFailure(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 1199 "./asn1/f1ap/f1ap.cnf"
  col_append_sep_str(actx->pinfo->cinfo, COL_INFO, NULL, "F1SetupFailure");

  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_f1ap_F1SetupFailure, F1SetupFailure_sequence);

  return offset;
}


static const per_sequence_t GNBDUConfigurationUpdate_sequence[] = {
  { &hf_f1ap_protocolIEs    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_f1ap_ProtocolIE_Container },
  { NULL, 0, 0, NULL }
};

static int
dissect_f1ap_GNBDUConfigurationUpdate(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 1201 "./asn1/f1ap/f1ap.cnf"
  col_append_sep_str(actx->pinfo->cinfo, COL_INFO, NULL, "GNBDUConfigurationUpdate");

  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_f1ap_GNBDUConfigurationUpdate, GNBDUConfigurationUpdate_sequence);

  return offset;
}


static const per_sequence_t Served_Cells_To_Add_List_sequence_of[1] = {
  { &hf_f1ap_Served_Cells_To_Add_List_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_f1ap_ProtocolIE_SingleContainer },
};

static int
dissect_f1ap_Served_Cells_To_Add_List(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_f1ap_Served_Cells_To_Add_List, Served_Cells_To_Add_List_sequence_of,
                                                  1, maxCellingNBDU, FALSE);

  return offset;
}


static const per_sequence_t Served_Cells_To_Modify_List_sequence_of[1] = {
  { &hf_f1ap_Served_Cells_To_Modify_List_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_f1ap_ProtocolIE_SingleContainer },
};

static int
dissect_f1ap_Served_Cells_To_Modify_List(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_f1ap_Served_Cells_To_Modify_List, Served_Cells_To_Modify_List_sequence_of,
                                                  1, maxCellingNBDU, FALSE);

  return offset;
}


static const per_sequence_t Served_Cells_To_Delete_List_sequence_of[1] = {
  { &hf_f1ap_Served_Cells_To_Delete_List_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_f1ap_ProtocolIE_SingleContainer },
};

static int
dissect_f1ap_Served_Cells_To_Delete_List(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_f1ap_Served_Cells_To_Delete_List, Served_Cells_To_Delete_List_sequence_of,
                                                  1, maxCellingNBDU, FALSE);

  return offset;
}


static const per_sequence_t Cells_Status_List_sequence_of[1] = {
  { &hf_f1ap_Cells_Status_List_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_f1ap_ProtocolIE_SingleContainer },
};

static int
dissect_f1ap_Cells_Status_List(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_f1ap_Cells_Status_List, Cells_Status_List_sequence_of,
                                                  0, maxCellingNBDU, FALSE);

  return offset;
}


static const per_sequence_t Dedicated_SIDelivery_NeededUE_List_sequence_of[1] = {
  { &hf_f1ap_Dedicated_SIDelivery_NeededUE_List_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_f1ap_ProtocolIE_SingleContainer },
};

static int
dissect_f1ap_Dedicated_SIDelivery_NeededUE_List(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_f1ap_Dedicated_SIDelivery_NeededUE_List, Dedicated_SIDelivery_NeededUE_List_sequence_of,
                                                  1, maxnoofUEIDs, FALSE);

  return offset;
}


static const per_sequence_t GNB_DU_TNL_Association_To_Remove_List_sequence_of[1] = {
  { &hf_f1ap_GNB_DU_TNL_Association_To_Remove_List_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_f1ap_ProtocolIE_SingleContainer },
};

static int
dissect_f1ap_GNB_DU_TNL_Association_To_Remove_List(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_f1ap_GNB_DU_TNL_Association_To_Remove_List, GNB_DU_TNL_Association_To_Remove_List_sequence_of,
                                                  1, maxnoofTNLAssociations, FALSE);

  return offset;
}


static const per_sequence_t GNBDUConfigurationUpdateAcknowledge_sequence[] = {
  { &hf_f1ap_protocolIEs    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_f1ap_ProtocolIE_Container },
  { NULL, 0, 0, NULL }
};

static int
dissect_f1ap_GNBDUConfigurationUpdateAcknowledge(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 1203 "./asn1/f1ap/f1ap.cnf"
  col_append_sep_str(actx->pinfo->cinfo, COL_INFO, NULL, "GNBDUConfigurationUpdateAcknowledge");

  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_f1ap_GNBDUConfigurationUpdateAcknowledge, GNBDUConfigurationUpdateAcknowledge_sequence);

  return offset;
}


static const per_sequence_t GNBDUConfigurationUpdateFailure_sequence[] = {
  { &hf_f1ap_protocolIEs    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_f1ap_ProtocolIE_Container },
  { NULL, 0, 0, NULL }
};

static int
dissect_f1ap_GNBDUConfigurationUpdateFailure(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 1205 "./asn1/f1ap/f1ap.cnf"
  col_append_sep_str(actx->pinfo->cinfo, COL_INFO, NULL, "GNBDUConfigurationUpdateFailure");

  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_f1ap_GNBDUConfigurationUpdateFailure, GNBDUConfigurationUpdateFailure_sequence);

  return offset;
}


static const per_sequence_t GNBCUConfigurationUpdate_sequence[] = {
  { &hf_f1ap_protocolIEs    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_f1ap_ProtocolIE_Container },
  { NULL, 0, 0, NULL }
};

static int
dissect_f1ap_GNBCUConfigurationUpdate(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 1207 "./asn1/f1ap/f1ap.cnf"
  col_append_sep_str(actx->pinfo->cinfo, COL_INFO, NULL, "GNBCUConfigurationUpdate");

  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_f1ap_GNBCUConfigurationUpdate, GNBCUConfigurationUpdate_sequence);

  return offset;
}


static const per_sequence_t Cells_to_be_Deactivated_List_sequence_of[1] = {
  { &hf_f1ap_Cells_to_be_Deactivated_List_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_f1ap_ProtocolIE_SingleContainer },
};

static int
dissect_f1ap_Cells_to_be_Deactivated_List(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_f1ap_Cells_to_be_Deactivated_List, Cells_to_be_Deactivated_List_sequence_of,
                                                  1, maxCellingNBDU, FALSE);

  return offset;
}


static const per_sequence_t GNB_CU_TNL_Association_To_Add_List_sequence_of[1] = {
  { &hf_f1ap_GNB_CU_TNL_Association_To_Add_List_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_f1ap_ProtocolIE_SingleContainer },
};

static int
dissect_f1ap_GNB_CU_TNL_Association_To_Add_List(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_f1ap_GNB_CU_TNL_Association_To_Add_List, GNB_CU_TNL_Association_To_Add_List_sequence_of,
                                                  1, maxnoofTNLAssociations, FALSE);

  return offset;
}


static const per_sequence_t GNB_CU_TNL_Association_To_Remove_List_sequence_of[1] = {
  { &hf_f1ap_GNB_CU_TNL_Association_To_Remove_List_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_f1ap_ProtocolIE_SingleContainer },
};

static int
dissect_f1ap_GNB_CU_TNL_Association_To_Remove_List(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_f1ap_GNB_CU_TNL_Association_To_Remove_List, GNB_CU_TNL_Association_To_Remove_List_sequence_of,
                                                  1, maxnoofTNLAssociations, FALSE);

  return offset;
}


static const per_sequence_t GNB_CU_TNL_Association_To_Update_List_sequence_of[1] = {
  { &hf_f1ap_GNB_CU_TNL_Association_To_Update_List_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_f1ap_ProtocolIE_SingleContainer },
};

static int
dissect_f1ap_GNB_CU_TNL_Association_To_Update_List(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_f1ap_GNB_CU_TNL_Association_To_Update_List, GNB_CU_TNL_Association_To_Update_List_sequence_of,
                                                  1, maxnoofTNLAssociations, FALSE);

  return offset;
}


static const per_sequence_t Cells_to_be_Barred_List_sequence_of[1] = {
  { &hf_f1ap_Cells_to_be_Barred_List_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_f1ap_ProtocolIE_SingleContainer },
};

static int
dissect_f1ap_Cells_to_be_Barred_List(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_f1ap_Cells_to_be_Barred_List, Cells_to_be_Barred_List_sequence_of,
                                                  1, maxCellingNBDU, FALSE);

  return offset;
}


static const per_sequence_t Protected_EUTRA_Resources_List_sequence_of[1] = {
  { &hf_f1ap_Protected_EUTRA_Resources_List_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_f1ap_ProtocolIE_SingleContainer },
};

static int
dissect_f1ap_Protected_EUTRA_Resources_List(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_f1ap_Protected_EUTRA_Resources_List, Protected_EUTRA_Resources_List_sequence_of,
                                                  1, maxCellineNB, FALSE);

  return offset;
}


static const per_sequence_t GNBCUConfigurationUpdateAcknowledge_sequence[] = {
  { &hf_f1ap_protocolIEs    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_f1ap_ProtocolIE_Container },
  { NULL, 0, 0, NULL }
};

static int
dissect_f1ap_GNBCUConfigurationUpdateAcknowledge(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 1209 "./asn1/f1ap/f1ap.cnf"
  col_append_sep_str(actx->pinfo->cinfo, COL_INFO, NULL, "GNBCUConfigurationUpdateAcknowledge");

  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_f1ap_GNBCUConfigurationUpdateAcknowledge, GNBCUConfigurationUpdateAcknowledge_sequence);

  return offset;
}


static const per_sequence_t Cells_Failed_to_be_Activated_List_sequence_of[1] = {
  { &hf_f1ap_Cells_Failed_to_be_Activated_List_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_f1ap_ProtocolIE_SingleContainer },
};

static int
dissect_f1ap_Cells_Failed_to_be_Activated_List(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_f1ap_Cells_Failed_to_be_Activated_List, Cells_Failed_to_be_Activated_List_sequence_of,
                                                  1, maxCellingNBDU, FALSE);

  return offset;
}


static const per_sequence_t GNB_CU_TNL_Association_Setup_List_sequence_of[1] = {
  { &hf_f1ap_GNB_CU_TNL_Association_Setup_List_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_f1ap_ProtocolIE_SingleContainer },
};

static int
dissect_f1ap_GNB_CU_TNL_Association_Setup_List(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_f1ap_GNB_CU_TNL_Association_Setup_List, GNB_CU_TNL_Association_Setup_List_sequence_of,
                                                  1, maxnoofTNLAssociations, FALSE);

  return offset;
}


static const per_sequence_t GNB_CU_TNL_Association_Failed_To_Setup_List_sequence_of[1] = {
  { &hf_f1ap_GNB_CU_TNL_Association_Failed_To_Setup_List_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_f1ap_ProtocolIE_SingleContainer },
};

static int
dissect_f1ap_GNB_CU_TNL_Association_Failed_To_Setup_List(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_f1ap_GNB_CU_TNL_Association_Failed_To_Setup_List, GNB_CU_TNL_Association_Failed_To_Setup_List_sequence_of,
                                                  1, maxnoofTNLAssociations, FALSE);

  return offset;
}


static const per_sequence_t GNBCUConfigurationUpdateFailure_sequence[] = {
  { &hf_f1ap_protocolIEs    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_f1ap_ProtocolIE_Container },
  { NULL, 0, 0, NULL }
};

static int
dissect_f1ap_GNBCUConfigurationUpdateFailure(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 1211 "./asn1/f1ap/f1ap.cnf"
  col_append_sep_str(actx->pinfo->cinfo, COL_INFO, NULL, "GNBCUConfigurationUpdateFailure");

  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_f1ap_GNBCUConfigurationUpdateFailure, GNBCUConfigurationUpdateFailure_sequence);

  return offset;
}


static const per_sequence_t GNBDUResourceCoordinationRequest_sequence[] = {
  { &hf_f1ap_protocolIEs    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_f1ap_ProtocolIE_Container },
  { NULL, 0, 0, NULL }
};

static int
dissect_f1ap_GNBDUResourceCoordinationRequest(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 1255 "./asn1/f1ap/f1ap.cnf"
  col_append_sep_str(actx->pinfo->cinfo, COL_INFO, NULL, "GNBDUResourceCoordinationRequest");

  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_f1ap_GNBDUResourceCoordinationRequest, GNBDUResourceCoordinationRequest_sequence);

  return offset;
}


static const per_sequence_t GNBDUResourceCoordinationResponse_sequence[] = {
  { &hf_f1ap_protocolIEs    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_f1ap_ProtocolIE_Container },
  { NULL, 0, 0, NULL }
};

static int
dissect_f1ap_GNBDUResourceCoordinationResponse(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 1257 "./asn1/f1ap/f1ap.cnf"
  col_append_sep_str(actx->pinfo->cinfo, COL_INFO, NULL, "GNBDUResourceCoordinationResponse");

  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_f1ap_GNBDUResourceCoordinationResponse, GNBDUResourceCoordinationResponse_sequence);

  return offset;
}


static const per_sequence_t UEContextSetupRequest_sequence[] = {
  { &hf_f1ap_protocolIEs    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_f1ap_ProtocolIE_Container },
  { NULL, 0, 0, NULL }
};

static int
dissect_f1ap_UEContextSetupRequest(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 1213 "./asn1/f1ap/f1ap.cnf"
  col_append_sep_str(actx->pinfo->cinfo, COL_INFO, NULL, "UEContextSetupRequest");

  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_f1ap_UEContextSetupRequest, UEContextSetupRequest_sequence);

  return offset;
}


static const per_sequence_t Candidate_SpCell_List_sequence_of[1] = {
  { &hf_f1ap_Candidate_SpCell_List_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_f1ap_ProtocolIE_SingleContainer },
};

static int
dissect_f1ap_Candidate_SpCell_List(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_f1ap_Candidate_SpCell_List, Candidate_SpCell_List_sequence_of,
                                                  1, maxnoofCandidateSpCells, FALSE);

  return offset;
}


static const per_sequence_t SCell_ToBeSetup_List_sequence_of[1] = {
  { &hf_f1ap_SCell_ToBeSetup_List_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_f1ap_ProtocolIE_SingleContainer },
};

static int
dissect_f1ap_SCell_ToBeSetup_List(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_f1ap_SCell_ToBeSetup_List, SCell_ToBeSetup_List_sequence_of,
                                                  1, maxnoofSCells, FALSE);

  return offset;
}


static const per_sequence_t SRBs_ToBeSetup_List_sequence_of[1] = {
  { &hf_f1ap_SRBs_ToBeSetup_List_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_f1ap_ProtocolIE_SingleContainer },
};

static int
dissect_f1ap_SRBs_ToBeSetup_List(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_f1ap_SRBs_ToBeSetup_List, SRBs_ToBeSetup_List_sequence_of,
                                                  1, maxnoofSRBs, FALSE);

  return offset;
}


static const per_sequence_t DRBs_ToBeSetup_List_sequence_of[1] = {
  { &hf_f1ap_DRBs_ToBeSetup_List_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_f1ap_ProtocolIE_SingleContainer },
};

static int
dissect_f1ap_DRBs_ToBeSetup_List(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_f1ap_DRBs_ToBeSetup_List, DRBs_ToBeSetup_List_sequence_of,
                                                  1, maxnoofDRBs, FALSE);

  return offset;
}


static const per_sequence_t UEContextSetupResponse_sequence[] = {
  { &hf_f1ap_protocolIEs    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_f1ap_ProtocolIE_Container },
  { NULL, 0, 0, NULL }
};

static int
dissect_f1ap_UEContextSetupResponse(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 1215 "./asn1/f1ap/f1ap.cnf"
  col_append_sep_str(actx->pinfo->cinfo, COL_INFO, NULL, "UEContextSetupResponse");

  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_f1ap_UEContextSetupResponse, UEContextSetupResponse_sequence);

  return offset;
}


static const per_sequence_t DRBs_Setup_List_sequence_of[1] = {
  { &hf_f1ap_DRBs_Setup_List_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_f1ap_ProtocolIE_SingleContainer },
};

static int
dissect_f1ap_DRBs_Setup_List(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_f1ap_DRBs_Setup_List, DRBs_Setup_List_sequence_of,
                                                  1, maxnoofDRBs, FALSE);

  return offset;
}


static const per_sequence_t SRBs_FailedToBeSetup_List_sequence_of[1] = {
  { &hf_f1ap_SRBs_FailedToBeSetup_List_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_f1ap_ProtocolIE_SingleContainer },
};

static int
dissect_f1ap_SRBs_FailedToBeSetup_List(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_f1ap_SRBs_FailedToBeSetup_List, SRBs_FailedToBeSetup_List_sequence_of,
                                                  1, maxnoofSRBs, FALSE);

  return offset;
}


static const per_sequence_t DRBs_FailedToBeSetup_List_sequence_of[1] = {
  { &hf_f1ap_DRBs_FailedToBeSetup_List_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_f1ap_ProtocolIE_SingleContainer },
};

static int
dissect_f1ap_DRBs_FailedToBeSetup_List(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_f1ap_DRBs_FailedToBeSetup_List, DRBs_FailedToBeSetup_List_sequence_of,
                                                  1, maxnoofDRBs, FALSE);

  return offset;
}


static const per_sequence_t SCell_FailedtoSetup_List_sequence_of[1] = {
  { &hf_f1ap_SCell_FailedtoSetup_List_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_f1ap_ProtocolIE_SingleContainer },
};

static int
dissect_f1ap_SCell_FailedtoSetup_List(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_f1ap_SCell_FailedtoSetup_List, SCell_FailedtoSetup_List_sequence_of,
                                                  1, maxnoofSCells, FALSE);

  return offset;
}


static const per_sequence_t SRBs_Setup_List_sequence_of[1] = {
  { &hf_f1ap_SRBs_Setup_List_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_f1ap_ProtocolIE_SingleContainer },
};

static int
dissect_f1ap_SRBs_Setup_List(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_f1ap_SRBs_Setup_List, SRBs_Setup_List_sequence_of,
                                                  1, maxnoofSRBs, FALSE);

  return offset;
}


static const per_sequence_t UEContextSetupFailure_sequence[] = {
  { &hf_f1ap_protocolIEs    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_f1ap_ProtocolIE_Container },
  { NULL, 0, 0, NULL }
};

static int
dissect_f1ap_UEContextSetupFailure(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 1217 "./asn1/f1ap/f1ap.cnf"
  col_append_sep_str(actx->pinfo->cinfo, COL_INFO, NULL, "UEContextSetupFailure");

  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_f1ap_UEContextSetupFailure, UEContextSetupFailure_sequence);

  return offset;
}


static const per_sequence_t Potential_SpCell_List_sequence_of[1] = {
  { &hf_f1ap_Potential_SpCell_List_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_f1ap_ProtocolIE_SingleContainer },
};

static int
dissect_f1ap_Potential_SpCell_List(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_f1ap_Potential_SpCell_List, Potential_SpCell_List_sequence_of,
                                                  0, maxnoofPotentialSpCells, FALSE);

  return offset;
}


static const per_sequence_t UEContextReleaseRequest_sequence[] = {
  { &hf_f1ap_protocolIEs    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_f1ap_ProtocolIE_Container },
  { NULL, 0, 0, NULL }
};

static int
dissect_f1ap_UEContextReleaseRequest(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 1245 "./asn1/f1ap/f1ap.cnf"
  col_append_sep_str(actx->pinfo->cinfo, COL_INFO, NULL, "UEContextReleaseRequest");

  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_f1ap_UEContextReleaseRequest, UEContextReleaseRequest_sequence);

  return offset;
}


static const per_sequence_t UEContextReleaseCommand_sequence[] = {
  { &hf_f1ap_protocolIEs    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_f1ap_ProtocolIE_Container },
  { NULL, 0, 0, NULL }
};

static int
dissect_f1ap_UEContextReleaseCommand(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 1219 "./asn1/f1ap/f1ap.cnf"
  col_append_sep_str(actx->pinfo->cinfo, COL_INFO, NULL, "UEContextReleaseCommand");

  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_f1ap_UEContextReleaseCommand, UEContextReleaseCommand_sequence);

  return offset;
}


static const per_sequence_t UEContextReleaseComplete_sequence[] = {
  { &hf_f1ap_protocolIEs    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_f1ap_ProtocolIE_Container },
  { NULL, 0, 0, NULL }
};

static int
dissect_f1ap_UEContextReleaseComplete(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 1221 "./asn1/f1ap/f1ap.cnf"
  col_append_sep_str(actx->pinfo->cinfo, COL_INFO, NULL, "UEContextReleaseComplete");

  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_f1ap_UEContextReleaseComplete, UEContextReleaseComplete_sequence);

  return offset;
}


static const per_sequence_t UEContextModificationRequest_sequence[] = {
  { &hf_f1ap_protocolIEs    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_f1ap_ProtocolIE_Container },
  { NULL, 0, 0, NULL }
};

static int
dissect_f1ap_UEContextModificationRequest(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 1223 "./asn1/f1ap/f1ap.cnf"
  col_append_sep_str(actx->pinfo->cinfo, COL_INFO, NULL, "UEContextModificationRequest");

  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_f1ap_UEContextModificationRequest, UEContextModificationRequest_sequence);

  return offset;
}


static const per_sequence_t SCell_ToBeSetupMod_List_sequence_of[1] = {
  { &hf_f1ap_SCell_ToBeSetupMod_List_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_f1ap_ProtocolIE_SingleContainer },
};

static int
dissect_f1ap_SCell_ToBeSetupMod_List(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_f1ap_SCell_ToBeSetupMod_List, SCell_ToBeSetupMod_List_sequence_of,
                                                  1, maxnoofSCells, FALSE);

  return offset;
}


static const per_sequence_t SCell_ToBeRemoved_List_sequence_of[1] = {
  { &hf_f1ap_SCell_ToBeRemoved_List_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_f1ap_ProtocolIE_SingleContainer },
};

static int
dissect_f1ap_SCell_ToBeRemoved_List(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_f1ap_SCell_ToBeRemoved_List, SCell_ToBeRemoved_List_sequence_of,
                                                  1, maxnoofSCells, FALSE);

  return offset;
}


static const per_sequence_t SRBs_ToBeSetupMod_List_sequence_of[1] = {
  { &hf_f1ap_SRBs_ToBeSetupMod_List_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_f1ap_ProtocolIE_SingleContainer },
};

static int
dissect_f1ap_SRBs_ToBeSetupMod_List(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_f1ap_SRBs_ToBeSetupMod_List, SRBs_ToBeSetupMod_List_sequence_of,
                                                  1, maxnoofSRBs, FALSE);

  return offset;
}


static const per_sequence_t DRBs_ToBeSetupMod_List_sequence_of[1] = {
  { &hf_f1ap_DRBs_ToBeSetupMod_List_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_f1ap_ProtocolIE_SingleContainer },
};

static int
dissect_f1ap_DRBs_ToBeSetupMod_List(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_f1ap_DRBs_ToBeSetupMod_List, DRBs_ToBeSetupMod_List_sequence_of,
                                                  1, maxnoofDRBs, FALSE);

  return offset;
}


static const per_sequence_t DRBs_ToBeModified_List_sequence_of[1] = {
  { &hf_f1ap_DRBs_ToBeModified_List_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_f1ap_ProtocolIE_SingleContainer },
};

static int
dissect_f1ap_DRBs_ToBeModified_List(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_f1ap_DRBs_ToBeModified_List, DRBs_ToBeModified_List_sequence_of,
                                                  1, maxnoofDRBs, FALSE);

  return offset;
}


static const per_sequence_t SRBs_ToBeReleased_List_sequence_of[1] = {
  { &hf_f1ap_SRBs_ToBeReleased_List_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_f1ap_ProtocolIE_SingleContainer },
};

static int
dissect_f1ap_SRBs_ToBeReleased_List(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_f1ap_SRBs_ToBeReleased_List, SRBs_ToBeReleased_List_sequence_of,
                                                  1, maxnoofSRBs, FALSE);

  return offset;
}


static const per_sequence_t DRBs_ToBeReleased_List_sequence_of[1] = {
  { &hf_f1ap_DRBs_ToBeReleased_List_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_f1ap_ProtocolIE_SingleContainer },
};

static int
dissect_f1ap_DRBs_ToBeReleased_List(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_f1ap_DRBs_ToBeReleased_List, DRBs_ToBeReleased_List_sequence_of,
                                                  1, maxnoofDRBs, FALSE);

  return offset;
}


static const per_sequence_t UEContextModificationResponse_sequence[] = {
  { &hf_f1ap_protocolIEs    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_f1ap_ProtocolIE_Container },
  { NULL, 0, 0, NULL }
};

static int
dissect_f1ap_UEContextModificationResponse(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 1225 "./asn1/f1ap/f1ap.cnf"
  col_append_sep_str(actx->pinfo->cinfo, COL_INFO, NULL, "UEContextModificationResponse");

  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_f1ap_UEContextModificationResponse, UEContextModificationResponse_sequence);

  return offset;
}


static const per_sequence_t DRBs_SetupMod_List_sequence_of[1] = {
  { &hf_f1ap_DRBs_SetupMod_List_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_f1ap_ProtocolIE_SingleContainer },
};

static int
dissect_f1ap_DRBs_SetupMod_List(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_f1ap_DRBs_SetupMod_List, DRBs_SetupMod_List_sequence_of,
                                                  1, maxnoofDRBs, FALSE);

  return offset;
}


static const per_sequence_t DRBs_Modified_List_sequence_of[1] = {
  { &hf_f1ap_DRBs_Modified_List_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_f1ap_ProtocolIE_SingleContainer },
};

static int
dissect_f1ap_DRBs_Modified_List(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_f1ap_DRBs_Modified_List, DRBs_Modified_List_sequence_of,
                                                  1, maxnoofDRBs, FALSE);

  return offset;
}


static const per_sequence_t SRBs_SetupMod_List_sequence_of[1] = {
  { &hf_f1ap_SRBs_SetupMod_List_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_f1ap_ProtocolIE_SingleContainer },
};

static int
dissect_f1ap_SRBs_SetupMod_List(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_f1ap_SRBs_SetupMod_List, SRBs_SetupMod_List_sequence_of,
                                                  1, maxnoofSRBs, FALSE);

  return offset;
}


static const per_sequence_t SRBs_Modified_List_sequence_of[1] = {
  { &hf_f1ap_SRBs_Modified_List_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_f1ap_ProtocolIE_SingleContainer },
};

static int
dissect_f1ap_SRBs_Modified_List(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_f1ap_SRBs_Modified_List, SRBs_Modified_List_sequence_of,
                                                  1, maxnoofSRBs, FALSE);

  return offset;
}


static const per_sequence_t DRBs_FailedToBeModified_List_sequence_of[1] = {
  { &hf_f1ap_DRBs_FailedToBeModified_List_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_f1ap_ProtocolIE_SingleContainer },
};

static int
dissect_f1ap_DRBs_FailedToBeModified_List(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_f1ap_DRBs_FailedToBeModified_List, DRBs_FailedToBeModified_List_sequence_of,
                                                  1, maxnoofDRBs, FALSE);

  return offset;
}


static const per_sequence_t SRBs_FailedToBeSetupMod_List_sequence_of[1] = {
  { &hf_f1ap_SRBs_FailedToBeSetupMod_List_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_f1ap_ProtocolIE_SingleContainer },
};

static int
dissect_f1ap_SRBs_FailedToBeSetupMod_List(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_f1ap_SRBs_FailedToBeSetupMod_List, SRBs_FailedToBeSetupMod_List_sequence_of,
                                                  1, maxnoofSRBs, FALSE);

  return offset;
}


static const per_sequence_t DRBs_FailedToBeSetupMod_List_sequence_of[1] = {
  { &hf_f1ap_DRBs_FailedToBeSetupMod_List_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_f1ap_ProtocolIE_SingleContainer },
};

static int
dissect_f1ap_DRBs_FailedToBeSetupMod_List(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_f1ap_DRBs_FailedToBeSetupMod_List, DRBs_FailedToBeSetupMod_List_sequence_of,
                                                  1, maxnoofDRBs, FALSE);

  return offset;
}


static const per_sequence_t SCell_FailedtoSetupMod_List_sequence_of[1] = {
  { &hf_f1ap_SCell_FailedtoSetupMod_List_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_f1ap_ProtocolIE_SingleContainer },
};

static int
dissect_f1ap_SCell_FailedtoSetupMod_List(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_f1ap_SCell_FailedtoSetupMod_List, SCell_FailedtoSetupMod_List_sequence_of,
                                                  1, maxnoofSCells, FALSE);

  return offset;
}


static const per_sequence_t Associated_SCell_List_sequence_of[1] = {
  { &hf_f1ap_Associated_SCell_List_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_f1ap_ProtocolIE_SingleContainer },
};

static int
dissect_f1ap_Associated_SCell_List(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_f1ap_Associated_SCell_List, Associated_SCell_List_sequence_of,
                                                  1, maxnoofSCells, FALSE);

  return offset;
}


static const per_sequence_t UEContextModificationFailure_sequence[] = {
  { &hf_f1ap_protocolIEs    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_f1ap_ProtocolIE_Container },
  { NULL, 0, 0, NULL }
};

static int
dissect_f1ap_UEContextModificationFailure(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 1227 "./asn1/f1ap/f1ap.cnf"
  col_append_sep_str(actx->pinfo->cinfo, COL_INFO, NULL, "UEContextModificationFailure");

  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_f1ap_UEContextModificationFailure, UEContextModificationFailure_sequence);

  return offset;
}


static const per_sequence_t UEContextModificationRequired_sequence[] = {
  { &hf_f1ap_protocolIEs    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_f1ap_ProtocolIE_Container },
  { NULL, 0, 0, NULL }
};

static int
dissect_f1ap_UEContextModificationRequired(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 1229 "./asn1/f1ap/f1ap.cnf"
  col_append_sep_str(actx->pinfo->cinfo, COL_INFO, NULL, "UEContextModificationRequired");

  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_f1ap_UEContextModificationRequired, UEContextModificationRequired_sequence);

  return offset;
}


static const per_sequence_t DRBs_Required_ToBeModified_List_sequence_of[1] = {
  { &hf_f1ap_DRBs_Required_ToBeModified_List_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_f1ap_ProtocolIE_SingleContainer },
};

static int
dissect_f1ap_DRBs_Required_ToBeModified_List(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_f1ap_DRBs_Required_ToBeModified_List, DRBs_Required_ToBeModified_List_sequence_of,
                                                  1, maxnoofDRBs, FALSE);

  return offset;
}


static const per_sequence_t DRBs_Required_ToBeReleased_List_sequence_of[1] = {
  { &hf_f1ap_DRBs_Required_ToBeReleased_List_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_f1ap_ProtocolIE_SingleContainer },
};

static int
dissect_f1ap_DRBs_Required_ToBeReleased_List(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_f1ap_DRBs_Required_ToBeReleased_List, DRBs_Required_ToBeReleased_List_sequence_of,
                                                  1, maxnoofDRBs, FALSE);

  return offset;
}


static const per_sequence_t SRBs_Required_ToBeReleased_List_sequence_of[1] = {
  { &hf_f1ap_SRBs_Required_ToBeReleased_List_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_f1ap_ProtocolIE_SingleContainer },
};

static int
dissect_f1ap_SRBs_Required_ToBeReleased_List(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_f1ap_SRBs_Required_ToBeReleased_List, SRBs_Required_ToBeReleased_List_sequence_of,
                                                  1, maxnoofSRBs, FALSE);

  return offset;
}


static const per_sequence_t UEContextModificationConfirm_sequence[] = {
  { &hf_f1ap_protocolIEs    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_f1ap_ProtocolIE_Container },
  { NULL, 0, 0, NULL }
};

static int
dissect_f1ap_UEContextModificationConfirm(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 1231 "./asn1/f1ap/f1ap.cnf"
  col_append_sep_str(actx->pinfo->cinfo, COL_INFO, NULL, "UEContextModificationConfirm");

  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_f1ap_UEContextModificationConfirm, UEContextModificationConfirm_sequence);

  return offset;
}


static const per_sequence_t DRBs_ModifiedConf_List_sequence_of[1] = {
  { &hf_f1ap_DRBs_ModifiedConf_List_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_f1ap_ProtocolIE_SingleContainer },
};

static int
dissect_f1ap_DRBs_ModifiedConf_List(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_f1ap_DRBs_ModifiedConf_List, DRBs_ModifiedConf_List_sequence_of,
                                                  1, maxnoofDRBs, FALSE);

  return offset;
}


static const per_sequence_t UEContextModificationRefuse_sequence[] = {
  { &hf_f1ap_protocolIEs    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_f1ap_ProtocolIE_Container },
  { NULL, 0, 0, NULL }
};

static int
dissect_f1ap_UEContextModificationRefuse(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 1233 "./asn1/f1ap/f1ap.cnf"
  col_append_sep_str(actx->pinfo->cinfo, COL_INFO, NULL, "UEContextModificationRefuse");

  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_f1ap_UEContextModificationRefuse, UEContextModificationRefuse_sequence);

  return offset;
}


static const per_sequence_t WriteReplaceWarningRequest_sequence[] = {
  { &hf_f1ap_protocolIEs    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_f1ap_ProtocolIE_Container },
  { NULL, 0, 0, NULL }
};

static int
dissect_f1ap_WriteReplaceWarningRequest(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 1235 "./asn1/f1ap/f1ap.cnf"
  col_append_sep_str(actx->pinfo->cinfo, COL_INFO, NULL, "WriteReplaceWarningRequest");

  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_f1ap_WriteReplaceWarningRequest, WriteReplaceWarningRequest_sequence);

  return offset;
}


static const per_sequence_t Cells_To_Be_Broadcast_List_sequence_of[1] = {
  { &hf_f1ap_Cells_To_Be_Broadcast_List_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_f1ap_ProtocolIE_SingleContainer },
};

static int
dissect_f1ap_Cells_To_Be_Broadcast_List(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_f1ap_Cells_To_Be_Broadcast_List, Cells_To_Be_Broadcast_List_sequence_of,
                                                  1, maxCellingNBDU, FALSE);

  return offset;
}


static const per_sequence_t WriteReplaceWarningResponse_sequence[] = {
  { &hf_f1ap_protocolIEs    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_f1ap_ProtocolIE_Container },
  { NULL, 0, 0, NULL }
};

static int
dissect_f1ap_WriteReplaceWarningResponse(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 1237 "./asn1/f1ap/f1ap.cnf"
  col_append_sep_str(actx->pinfo->cinfo, COL_INFO, NULL, "WriteReplaceWarningResponse");

  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_f1ap_WriteReplaceWarningResponse, WriteReplaceWarningResponse_sequence);

  return offset;
}


static const per_sequence_t Cells_Broadcast_Completed_List_sequence_of[1] = {
  { &hf_f1ap_Cells_Broadcast_Completed_List_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_f1ap_ProtocolIE_SingleContainer },
};

static int
dissect_f1ap_Cells_Broadcast_Completed_List(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_f1ap_Cells_Broadcast_Completed_List, Cells_Broadcast_Completed_List_sequence_of,
                                                  1, maxCellingNBDU, FALSE);

  return offset;
}


static const per_sequence_t PWSCancelRequest_sequence[] = {
  { &hf_f1ap_protocolIEs    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_f1ap_ProtocolIE_Container },
  { NULL, 0, 0, NULL }
};

static int
dissect_f1ap_PWSCancelRequest(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 1239 "./asn1/f1ap/f1ap.cnf"
  col_append_sep_str(actx->pinfo->cinfo, COL_INFO, NULL, "PWSCancelRequest");

  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_f1ap_PWSCancelRequest, PWSCancelRequest_sequence);

  return offset;
}


static const per_sequence_t Broadcast_To_Be_Cancelled_List_sequence_of[1] = {
  { &hf_f1ap_Broadcast_To_Be_Cancelled_List_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_f1ap_ProtocolIE_SingleContainer },
};

static int
dissect_f1ap_Broadcast_To_Be_Cancelled_List(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_f1ap_Broadcast_To_Be_Cancelled_List, Broadcast_To_Be_Cancelled_List_sequence_of,
                                                  1, maxCellingNBDU, FALSE);

  return offset;
}


static const per_sequence_t PWSCancelResponse_sequence[] = {
  { &hf_f1ap_protocolIEs    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_f1ap_ProtocolIE_Container },
  { NULL, 0, 0, NULL }
};

static int
dissect_f1ap_PWSCancelResponse(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 1241 "./asn1/f1ap/f1ap.cnf"
  col_append_sep_str(actx->pinfo->cinfo, COL_INFO, NULL, "PWSCancelResponse");

  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_f1ap_PWSCancelResponse, PWSCancelResponse_sequence);

  return offset;
}


static const per_sequence_t Cells_Broadcast_Cancelled_List_sequence_of[1] = {
  { &hf_f1ap_Cells_Broadcast_Cancelled_List_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_f1ap_ProtocolIE_SingleContainer },
};

static int
dissect_f1ap_Cells_Broadcast_Cancelled_List(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_f1ap_Cells_Broadcast_Cancelled_List, Cells_Broadcast_Cancelled_List_sequence_of,
                                                  1, maxCellingNBDU, FALSE);

  return offset;
}


static const per_sequence_t UEInactivityNotification_sequence[] = {
  { &hf_f1ap_protocolIEs    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_f1ap_ProtocolIE_Container },
  { NULL, 0, 0, NULL }
};

static int
dissect_f1ap_UEInactivityNotification(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 1253 "./asn1/f1ap/f1ap.cnf"
  col_append_sep_str(actx->pinfo->cinfo, COL_INFO, NULL, "UEInactivityNotification");

  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_f1ap_UEInactivityNotification, UEInactivityNotification_sequence);

  return offset;
}


static const per_sequence_t DRB_Activity_List_sequence_of[1] = {
  { &hf_f1ap_DRB_Activity_List_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_f1ap_ProtocolIE_SingleContainer },
};

static int
dissect_f1ap_DRB_Activity_List(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_f1ap_DRB_Activity_List, DRB_Activity_List_sequence_of,
                                                  1, maxnoofDRBs, FALSE);

  return offset;
}


static const per_sequence_t InitialULRRCMessageTransfer_sequence[] = {
  { &hf_f1ap_protocolIEs    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_f1ap_ProtocolIE_Container },
  { NULL, 0, 0, NULL }
};

static int
dissect_f1ap_InitialULRRCMessageTransfer(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 1247 "./asn1/f1ap/f1ap.cnf"
  col_append_sep_str(actx->pinfo->cinfo, COL_INFO, NULL, "InitialULRRCMessageTransfer");

  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_f1ap_InitialULRRCMessageTransfer, InitialULRRCMessageTransfer_sequence);

  return offset;
}


static const per_sequence_t DLRRCMessageTransfer_sequence[] = {
  { &hf_f1ap_protocolIEs    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_f1ap_ProtocolIE_Container },
  { NULL, 0, 0, NULL }
};

static int
dissect_f1ap_DLRRCMessageTransfer(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 1249 "./asn1/f1ap/f1ap.cnf"
  col_append_sep_str(actx->pinfo->cinfo, COL_INFO, NULL, "DLRRCMessageTransfer");

  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_f1ap_DLRRCMessageTransfer, DLRRCMessageTransfer_sequence);

  return offset;
}



static int
dissect_f1ap_RedirectedRRCmessage(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_octet_string(tvb, offset, actx, tree, hf_index,
                                       NO_BOUND, NO_BOUND, FALSE, NULL);

  return offset;
}


static const per_sequence_t ULRRCMessageTransfer_sequence[] = {
  { &hf_f1ap_protocolIEs    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_f1ap_ProtocolIE_Container },
  { NULL, 0, 0, NULL }
};

static int
dissect_f1ap_ULRRCMessageTransfer(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 1251 "./asn1/f1ap/f1ap.cnf"
  col_append_sep_str(actx->pinfo->cinfo, COL_INFO, NULL, "ULRRCMessageTransfer");

  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_f1ap_ULRRCMessageTransfer, ULRRCMessageTransfer_sequence);

  return offset;
}


static const per_sequence_t PrivateMessage_sequence[] = {
  { &hf_f1ap_privateIEs     , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_f1ap_PrivateIE_Container },
  { NULL, 0, 0, NULL }
};

static int
dissect_f1ap_PrivateMessage(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 1259 "./asn1/f1ap/f1ap.cnf"
  col_append_sep_str(actx->pinfo->cinfo, COL_INFO, NULL, "PrivateMessage");

  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_f1ap_PrivateMessage, PrivateMessage_sequence);

  return offset;
}


static const per_sequence_t SystemInformationDeliveryCommand_sequence[] = {
  { &hf_f1ap_protocolIEs    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_f1ap_ProtocolIE_Container },
  { NULL, 0, 0, NULL }
};

static int
dissect_f1ap_SystemInformationDeliveryCommand(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 1261 "./asn1/f1ap/f1ap.cnf"
  col_append_sep_str(actx->pinfo->cinfo, COL_INFO, NULL, "SystemInformationDeliveryCommand");

  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_f1ap_SystemInformationDeliveryCommand, SystemInformationDeliveryCommand_sequence);

  return offset;
}


static const per_sequence_t Paging_sequence[] = {
  { &hf_f1ap_protocolIEs    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_f1ap_ProtocolIE_Container },
  { NULL, 0, 0, NULL }
};

static int
dissect_f1ap_Paging(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 1263 "./asn1/f1ap/f1ap.cnf"
  col_append_sep_str(actx->pinfo->cinfo, COL_INFO, NULL, "Paging");

  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_f1ap_Paging, Paging_sequence);

  return offset;
}


static const per_sequence_t PagingCell_list_sequence_of[1] = {
  { &hf_f1ap_PagingCell_list_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_f1ap_ProtocolIE_SingleContainer },
};

static int
dissect_f1ap_PagingCell_list(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_f1ap_PagingCell_list, PagingCell_list_sequence_of,
                                                  1, maxnoofPagingCells, FALSE);

  return offset;
}


static const per_sequence_t Notify_sequence[] = {
  { &hf_f1ap_protocolIEs    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_f1ap_ProtocolIE_Container },
  { NULL, 0, 0, NULL }
};

static int
dissect_f1ap_Notify(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 1265 "./asn1/f1ap/f1ap.cnf"
  col_append_sep_str(actx->pinfo->cinfo, COL_INFO, NULL, "Notify");

  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_f1ap_Notify, Notify_sequence);

  return offset;
}


static const per_sequence_t DRB_Notify_List_sequence_of[1] = {
  { &hf_f1ap_DRB_Notify_List_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_f1ap_ProtocolIE_SingleContainer },
};

static int
dissect_f1ap_DRB_Notify_List(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_f1ap_DRB_Notify_List, DRB_Notify_List_sequence_of,
                                                  1, maxnoofDRBs, FALSE);

  return offset;
}


static const per_sequence_t NetworkAccessRateReduction_sequence[] = {
  { &hf_f1ap_protocolIEs    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_f1ap_ProtocolIE_Container },
  { NULL, 0, 0, NULL }
};

static int
dissect_f1ap_NetworkAccessRateReduction(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 1267 "./asn1/f1ap/f1ap.cnf"
  col_append_sep_str(actx->pinfo->cinfo, COL_INFO, NULL, "NetworkAccessRateReduction");

  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_f1ap_NetworkAccessRateReduction, NetworkAccessRateReduction_sequence);

  return offset;
}


static const per_sequence_t PWSRestartIndication_sequence[] = {
  { &hf_f1ap_protocolIEs    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_f1ap_ProtocolIE_Container },
  { NULL, 0, 0, NULL }
};

static int
dissect_f1ap_PWSRestartIndication(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 1269 "./asn1/f1ap/f1ap.cnf"
  col_append_sep_str(actx->pinfo->cinfo, COL_INFO, NULL, "PWSRestartIndication");

  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_f1ap_PWSRestartIndication, PWSRestartIndication_sequence);

  return offset;
}


static const per_sequence_t NR_CGI_List_For_Restart_List_sequence_of[1] = {
  { &hf_f1ap_NR_CGI_List_For_Restart_List_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_f1ap_ProtocolIE_SingleContainer },
};

static int
dissect_f1ap_NR_CGI_List_For_Restart_List(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_f1ap_NR_CGI_List_For_Restart_List, NR_CGI_List_For_Restart_List_sequence_of,
                                                  1, maxCellingNBDU, FALSE);

  return offset;
}


static const per_sequence_t PWSFailureIndication_sequence[] = {
  { &hf_f1ap_protocolIEs    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_f1ap_ProtocolIE_Container },
  { NULL, 0, 0, NULL }
};

static int
dissect_f1ap_PWSFailureIndication(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 1271 "./asn1/f1ap/f1ap.cnf"
  col_append_sep_str(actx->pinfo->cinfo, COL_INFO, NULL, "PWSFailureIndication");

  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_f1ap_PWSFailureIndication, PWSFailureIndication_sequence);

  return offset;
}


static const per_sequence_t PWS_Failed_NR_CGI_List_sequence_of[1] = {
  { &hf_f1ap_PWS_Failed_NR_CGI_List_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_f1ap_ProtocolIE_SingleContainer },
};

static int
dissect_f1ap_PWS_Failed_NR_CGI_List(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_f1ap_PWS_Failed_NR_CGI_List, PWS_Failed_NR_CGI_List_sequence_of,
                                                  1, maxCellingNBDU, FALSE);

  return offset;
}


static const per_sequence_t GNBDUStatusIndication_sequence[] = {
  { &hf_f1ap_protocolIEs    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_f1ap_ProtocolIE_Container },
  { NULL, 0, 0, NULL }
};

static int
dissect_f1ap_GNBDUStatusIndication(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 1273 "./asn1/f1ap/f1ap.cnf"
  col_append_sep_str(actx->pinfo->cinfo, COL_INFO, NULL, "GNBDUStatusIndication");

  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_f1ap_GNBDUStatusIndication, GNBDUStatusIndication_sequence);

  return offset;
}


static const per_sequence_t RRCDeliveryReport_sequence[] = {
  { &hf_f1ap_protocolIEs    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_f1ap_ProtocolIE_Container },
  { NULL, 0, 0, NULL }
};

static int
dissect_f1ap_RRCDeliveryReport(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 1275 "./asn1/f1ap/f1ap.cnf"
  col_append_sep_str(actx->pinfo->cinfo, COL_INFO, NULL, "RRCDeliveryReport");

  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_f1ap_RRCDeliveryReport, RRCDeliveryReport_sequence);

  return offset;
}


static const per_sequence_t F1RemovalRequest_sequence[] = {
  { &hf_f1ap_protocolIEs    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_f1ap_ProtocolIE_Container },
  { NULL, 0, 0, NULL }
};

static int
dissect_f1ap_F1RemovalRequest(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 1278 "./asn1/f1ap/f1ap.cnf"
  col_append_sep_str(actx->pinfo->cinfo, COL_INFO, NULL, "F1RemovalRequest");

  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_f1ap_F1RemovalRequest, F1RemovalRequest_sequence);

  return offset;
}


static const per_sequence_t F1RemovalResponse_sequence[] = {
  { &hf_f1ap_protocolIEs    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_f1ap_ProtocolIE_Container },
  { NULL, 0, 0, NULL }
};

static int
dissect_f1ap_F1RemovalResponse(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 1281 "./asn1/f1ap/f1ap.cnf"
  col_append_sep_str(actx->pinfo->cinfo, COL_INFO, NULL, "F1RemovalResponse");

  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_f1ap_F1RemovalResponse, F1RemovalResponse_sequence);

  return offset;
}


static const per_sequence_t F1RemovalFailure_sequence[] = {
  { &hf_f1ap_protocolIEs    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_f1ap_ProtocolIE_Container },
  { NULL, 0, 0, NULL }
};

static int
dissect_f1ap_F1RemovalFailure(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 1284 "./asn1/f1ap/f1ap.cnf"
  col_append_sep_str(actx->pinfo->cinfo, COL_INFO, NULL, "F1RemovalFailure");

  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_f1ap_F1RemovalFailure, F1RemovalFailure_sequence);

  return offset;
}



static int
dissect_f1ap_InitiatingMessage_value(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 79 "./asn1/f1ap/f1ap.cnf"
  f1ap_private_data_t *f1ap_data = f1ap_get_private_data(actx->pinfo);
  f1ap_data->message_type = INITIATING_MESSAGE;

  offset = dissect_per_open_type_pdu_new(tvb, offset, actx, tree, hf_index, dissect_InitiatingMessageValue);

  return offset;
}


static const per_sequence_t InitiatingMessage_sequence[] = {
  { &hf_f1ap_procedureCode  , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_f1ap_ProcedureCode },
  { &hf_f1ap_criticality    , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_f1ap_Criticality },
  { &hf_f1ap_initiatingMessagevalue, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_f1ap_InitiatingMessage_value },
  { NULL, 0, 0, NULL }
};

static int
dissect_f1ap_InitiatingMessage(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_f1ap_InitiatingMessage, InitiatingMessage_sequence);

  return offset;
}



static int
dissect_f1ap_SuccessfulOutcome_value(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 83 "./asn1/f1ap/f1ap.cnf"
  f1ap_private_data_t *f1ap_data = f1ap_get_private_data(actx->pinfo);
  f1ap_data->message_type = SUCCESSFUL_OUTCOME;

  offset = dissect_per_open_type_pdu_new(tvb, offset, actx, tree, hf_index, dissect_SuccessfulOutcomeValue);

  return offset;
}


static const per_sequence_t SuccessfulOutcome_sequence[] = {
  { &hf_f1ap_procedureCode  , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_f1ap_ProcedureCode },
  { &hf_f1ap_criticality    , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_f1ap_Criticality },
  { &hf_f1ap_successfulOutcome_value, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_f1ap_SuccessfulOutcome_value },
  { NULL, 0, 0, NULL }
};

static int
dissect_f1ap_SuccessfulOutcome(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_f1ap_SuccessfulOutcome, SuccessfulOutcome_sequence);

  return offset;
}



static int
dissect_f1ap_UnsuccessfulOutcome_value(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 87 "./asn1/f1ap/f1ap.cnf"
  f1ap_private_data_t *f1ap_data = f1ap_get_private_data(actx->pinfo);
  f1ap_data->message_type = UNSUCCESSFUL_OUTCOME;

  offset = dissect_per_open_type_pdu_new(tvb, offset, actx, tree, hf_index, dissect_UnsuccessfulOutcomeValue);

  return offset;
}


static const per_sequence_t UnsuccessfulOutcome_sequence[] = {
  { &hf_f1ap_procedureCode  , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_f1ap_ProcedureCode },
  { &hf_f1ap_criticality    , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_f1ap_Criticality },
  { &hf_f1ap_unsuccessfulOutcome_value, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_f1ap_UnsuccessfulOutcome_value },
  { NULL, 0, 0, NULL }
};

static int
dissect_f1ap_UnsuccessfulOutcome(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_f1ap_UnsuccessfulOutcome, UnsuccessfulOutcome_sequence);

  return offset;
}


static const value_string f1ap_F1AP_PDU_vals[] = {
  {   0, "initiatingMessage" },
  {   1, "successfulOutcome" },
  {   2, "unsuccessfulOutcome" },
  {   3, "choice-extension" },
  { 0, NULL }
};

static const per_choice_t F1AP_PDU_choice[] = {
  {   0, &hf_f1ap_initiatingMessage, ASN1_NO_EXTENSIONS     , dissect_f1ap_InitiatingMessage },
  {   1, &hf_f1ap_successfulOutcome, ASN1_NO_EXTENSIONS     , dissect_f1ap_SuccessfulOutcome },
  {   2, &hf_f1ap_unsuccessfulOutcome, ASN1_NO_EXTENSIONS     , dissect_f1ap_UnsuccessfulOutcome },
  {   3, &hf_f1ap_choice_extension, ASN1_NO_EXTENSIONS     , dissect_f1ap_ProtocolIE_SingleContainer },
  { 0, NULL, 0, NULL }
};

static int
dissect_f1ap_F1AP_PDU(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_f1ap_F1AP_PDU, F1AP_PDU_choice,
                                 NULL);

  return offset;
}

/*--- PDUs ---*/

static int dissect_AdditionalSIBMessageList_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_f1ap_AdditionalSIBMessageList(tvb, offset, &asn1_ctx, tree, hf_f1ap_AdditionalSIBMessageList_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_Associated_SCell_Item_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_f1ap_Associated_SCell_Item(tvb, offset, &asn1_ctx, tree, hf_f1ap_Associated_SCell_Item_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_AvailablePLMNList_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_f1ap_AvailablePLMNList(tvb, offset, &asn1_ctx, tree, hf_f1ap_AvailablePLMNList_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_AreaScope_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_f1ap_AreaScope(tvb, offset, &asn1_ctx, tree, hf_f1ap_AreaScope_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_BitRate_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_f1ap_BitRate(tvb, offset, &asn1_ctx, tree, hf_f1ap_BitRate_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_BearerTypeChange_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_f1ap_BearerTypeChange(tvb, offset, &asn1_ctx, tree, hf_f1ap_BearerTypeChange_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_BPLMN_ID_Info_List_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_f1ap_BPLMN_ID_Info_List(tvb, offset, &asn1_ctx, tree, hf_f1ap_BPLMN_ID_Info_List_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_Cancel_all_Warning_Messages_Indicator_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_f1ap_Cancel_all_Warning_Messages_Indicator(tvb, offset, &asn1_ctx, tree, hf_f1ap_Cancel_all_Warning_Messages_Indicator_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_Candidate_SpCell_Item_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_f1ap_Candidate_SpCell_Item(tvb, offset, &asn1_ctx, tree, hf_f1ap_Candidate_SpCell_Item_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_Cause_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_f1ap_Cause(tvb, offset, &asn1_ctx, tree, hf_f1ap_Cause_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_CellGroupConfig_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_f1ap_CellGroupConfig(tvb, offset, &asn1_ctx, tree, hf_f1ap_CellGroupConfig_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_Cell_Direction_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_f1ap_Cell_Direction(tvb, offset, &asn1_ctx, tree, hf_f1ap_Cell_Direction_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_Cells_Failed_to_be_Activated_List_Item_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_f1ap_Cells_Failed_to_be_Activated_List_Item(tvb, offset, &asn1_ctx, tree, hf_f1ap_Cells_Failed_to_be_Activated_List_Item_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_Cells_Status_Item_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_f1ap_Cells_Status_Item(tvb, offset, &asn1_ctx, tree, hf_f1ap_Cells_Status_Item_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_Cells_To_Be_Broadcast_Item_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_f1ap_Cells_To_Be_Broadcast_Item(tvb, offset, &asn1_ctx, tree, hf_f1ap_Cells_To_Be_Broadcast_Item_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_Cells_Broadcast_Completed_Item_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_f1ap_Cells_Broadcast_Completed_Item(tvb, offset, &asn1_ctx, tree, hf_f1ap_Cells_Broadcast_Completed_Item_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_Broadcast_To_Be_Cancelled_Item_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_f1ap_Broadcast_To_Be_Cancelled_Item(tvb, offset, &asn1_ctx, tree, hf_f1ap_Broadcast_To_Be_Cancelled_Item_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_Cells_Broadcast_Cancelled_Item_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_f1ap_Cells_Broadcast_Cancelled_Item(tvb, offset, &asn1_ctx, tree, hf_f1ap_Cells_Broadcast_Cancelled_Item_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_Cells_to_be_Activated_List_Item_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_f1ap_Cells_to_be_Activated_List_Item(tvb, offset, &asn1_ctx, tree, hf_f1ap_Cells_to_be_Activated_List_Item_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_Cells_to_be_Deactivated_List_Item_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_f1ap_Cells_to_be_Deactivated_List_Item(tvb, offset, &asn1_ctx, tree, hf_f1ap_Cells_to_be_Deactivated_List_Item_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_Cells_to_be_Barred_Item_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_f1ap_Cells_to_be_Barred_Item(tvb, offset, &asn1_ctx, tree, hf_f1ap_Cells_to_be_Barred_Item_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_CellType_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_f1ap_CellType(tvb, offset, &asn1_ctx, tree, hf_f1ap_CellType_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_CellULConfigured_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_f1ap_CellULConfigured(tvb, offset, &asn1_ctx, tree, hf_f1ap_CellULConfigured_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_CP_TransportLayerAddress_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_f1ap_CP_TransportLayerAddress(tvb, offset, &asn1_ctx, tree, hf_f1ap_CP_TransportLayerAddress_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_CriticalityDiagnostics_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_f1ap_CriticalityDiagnostics(tvb, offset, &asn1_ctx, tree, hf_f1ap_CriticalityDiagnostics_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_C_RNTI_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_f1ap_C_RNTI(tvb, offset, &asn1_ctx, tree, hf_f1ap_C_RNTI_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_CUtoDURRCInformation_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_f1ap_CUtoDURRCInformation(tvb, offset, &asn1_ctx, tree, hf_f1ap_CUtoDURRCInformation_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_DCBasedDuplicationConfigured_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_f1ap_DCBasedDuplicationConfigured(tvb, offset, &asn1_ctx, tree, hf_f1ap_DCBasedDuplicationConfigured_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_Dedicated_SIDelivery_NeededUE_Item_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_f1ap_Dedicated_SIDelivery_NeededUE_Item(tvb, offset, &asn1_ctx, tree, hf_f1ap_Dedicated_SIDelivery_NeededUE_Item_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_DRB_Activity_Item_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_f1ap_DRB_Activity_Item(tvb, offset, &asn1_ctx, tree, hf_f1ap_DRB_Activity_Item_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_DRBs_FailedToBeModified_Item_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_f1ap_DRBs_FailedToBeModified_Item(tvb, offset, &asn1_ctx, tree, hf_f1ap_DRBs_FailedToBeModified_Item_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_DRBs_FailedToBeSetup_Item_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_f1ap_DRBs_FailedToBeSetup_Item(tvb, offset, &asn1_ctx, tree, hf_f1ap_DRBs_FailedToBeSetup_Item_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_DRBs_FailedToBeSetupMod_Item_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_f1ap_DRBs_FailedToBeSetupMod_Item(tvb, offset, &asn1_ctx, tree, hf_f1ap_DRBs_FailedToBeSetupMod_Item_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_DRB_Information_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_f1ap_DRB_Information(tvb, offset, &asn1_ctx, tree, hf_f1ap_DRB_Information_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_DRBs_Modified_Item_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_f1ap_DRBs_Modified_Item(tvb, offset, &asn1_ctx, tree, hf_f1ap_DRBs_Modified_Item_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_DRBs_ModifiedConf_Item_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_f1ap_DRBs_ModifiedConf_Item(tvb, offset, &asn1_ctx, tree, hf_f1ap_DRBs_ModifiedConf_Item_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_DRB_Notify_Item_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_f1ap_DRB_Notify_Item(tvb, offset, &asn1_ctx, tree, hf_f1ap_DRB_Notify_Item_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_DRBs_Required_ToBeModified_Item_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_f1ap_DRBs_Required_ToBeModified_Item(tvb, offset, &asn1_ctx, tree, hf_f1ap_DRBs_Required_ToBeModified_Item_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_DRBs_Required_ToBeReleased_Item_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_f1ap_DRBs_Required_ToBeReleased_Item(tvb, offset, &asn1_ctx, tree, hf_f1ap_DRBs_Required_ToBeReleased_Item_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_DRBs_Setup_Item_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_f1ap_DRBs_Setup_Item(tvb, offset, &asn1_ctx, tree, hf_f1ap_DRBs_Setup_Item_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_DRBs_SetupMod_Item_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_f1ap_DRBs_SetupMod_Item(tvb, offset, &asn1_ctx, tree, hf_f1ap_DRBs_SetupMod_Item_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_DRBs_ToBeModified_Item_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_f1ap_DRBs_ToBeModified_Item(tvb, offset, &asn1_ctx, tree, hf_f1ap_DRBs_ToBeModified_Item_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_DRBs_ToBeReleased_Item_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_f1ap_DRBs_ToBeReleased_Item(tvb, offset, &asn1_ctx, tree, hf_f1ap_DRBs_ToBeReleased_Item_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_DRBs_ToBeSetup_Item_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_f1ap_DRBs_ToBeSetup_Item(tvb, offset, &asn1_ctx, tree, hf_f1ap_DRBs_ToBeSetup_Item_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_DRBs_ToBeSetupMod_Item_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_f1ap_DRBs_ToBeSetupMod_Item(tvb, offset, &asn1_ctx, tree, hf_f1ap_DRBs_ToBeSetupMod_Item_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_DRXCycle_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_f1ap_DRXCycle(tvb, offset, &asn1_ctx, tree, hf_f1ap_DRXCycle_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_DRX_Config_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_f1ap_DRX_Config(tvb, offset, &asn1_ctx, tree, hf_f1ap_DRX_Config_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_DRXConfigurationIndicator_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_f1ap_DRXConfigurationIndicator(tvb, offset, &asn1_ctx, tree, hf_f1ap_DRXConfigurationIndicator_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_DRX_LongCycleStartOffset_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_f1ap_DRX_LongCycleStartOffset(tvb, offset, &asn1_ctx, tree, hf_f1ap_DRX_LongCycleStartOffset_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_DUtoCURRCContainer_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_f1ap_DUtoCURRCContainer(tvb, offset, &asn1_ctx, tree, hf_f1ap_DUtoCURRCContainer_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_DUtoCURRCInformation_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_f1ap_DUtoCURRCInformation(tvb, offset, &asn1_ctx, tree, hf_f1ap_DUtoCURRCInformation_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_DuplicationActivation_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_f1ap_DuplicationActivation(tvb, offset, &asn1_ctx, tree, hf_f1ap_DuplicationActivation_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_ExtendedAvailablePLMN_List_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_f1ap_ExtendedAvailablePLMN_List(tvb, offset, &asn1_ctx, tree, hf_f1ap_ExtendedAvailablePLMN_List_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_ExtendedServedPLMNs_List_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_f1ap_ExtendedServedPLMNs_List(tvb, offset, &asn1_ctx, tree, hf_f1ap_ExtendedServedPLMNs_List_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_ExecuteDuplication_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_f1ap_ExecuteDuplication(tvb, offset, &asn1_ctx, tree, hf_f1ap_ExecuteDuplication_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_EUTRA_NR_CellResourceCoordinationReq_Container_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_f1ap_EUTRA_NR_CellResourceCoordinationReq_Container(tvb, offset, &asn1_ctx, tree, hf_f1ap_EUTRA_NR_CellResourceCoordinationReq_Container_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_EUTRA_NR_CellResourceCoordinationReqAck_Container_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_f1ap_EUTRA_NR_CellResourceCoordinationReqAck_Container(tvb, offset, &asn1_ctx, tree, hf_f1ap_EUTRA_NR_CellResourceCoordinationReqAck_Container_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_FullConfiguration_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_f1ap_FullConfiguration(tvb, offset, &asn1_ctx, tree, hf_f1ap_FullConfiguration_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_CG_Config_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_f1ap_CG_Config(tvb, offset, &asn1_ctx, tree, hf_f1ap_CG_Config_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_GNB_CUSystemInformation_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_f1ap_GNB_CUSystemInformation(tvb, offset, &asn1_ctx, tree, hf_f1ap_GNB_CUSystemInformation_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_GNB_CU_TNL_Association_Setup_Item_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_f1ap_GNB_CU_TNL_Association_Setup_Item(tvb, offset, &asn1_ctx, tree, hf_f1ap_GNB_CU_TNL_Association_Setup_Item_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_GNB_CU_TNL_Association_Failed_To_Setup_Item_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_f1ap_GNB_CU_TNL_Association_Failed_To_Setup_Item(tvb, offset, &asn1_ctx, tree, hf_f1ap_GNB_CU_TNL_Association_Failed_To_Setup_Item_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_GNB_CU_TNL_Association_To_Add_Item_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_f1ap_GNB_CU_TNL_Association_To_Add_Item(tvb, offset, &asn1_ctx, tree, hf_f1ap_GNB_CU_TNL_Association_To_Add_Item_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_GNB_CU_TNL_Association_To_Remove_Item_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_f1ap_GNB_CU_TNL_Association_To_Remove_Item(tvb, offset, &asn1_ctx, tree, hf_f1ap_GNB_CU_TNL_Association_To_Remove_Item_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_GNB_CU_TNL_Association_To_Update_Item_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_f1ap_GNB_CU_TNL_Association_To_Update_Item(tvb, offset, &asn1_ctx, tree, hf_f1ap_GNB_CU_TNL_Association_To_Update_Item_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_GNB_CU_UE_F1AP_ID_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_f1ap_GNB_CU_UE_F1AP_ID(tvb, offset, &asn1_ctx, tree, hf_f1ap_GNB_CU_UE_F1AP_ID_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_GNB_DU_UE_F1AP_ID_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_f1ap_GNB_DU_UE_F1AP_ID(tvb, offset, &asn1_ctx, tree, hf_f1ap_GNB_DU_UE_F1AP_ID_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_GNB_DU_ID_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_f1ap_GNB_DU_ID(tvb, offset, &asn1_ctx, tree, hf_f1ap_GNB_DU_ID_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_GNB_CU_Name_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_f1ap_GNB_CU_Name(tvb, offset, &asn1_ctx, tree, hf_f1ap_GNB_CU_Name_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_GNB_DU_Name_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_f1ap_GNB_DU_Name(tvb, offset, &asn1_ctx, tree, hf_f1ap_GNB_DU_Name_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_GNB_DU_Served_Cells_Item_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_f1ap_GNB_DU_Served_Cells_Item(tvb, offset, &asn1_ctx, tree, hf_f1ap_GNB_DU_Served_Cells_Item_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_GNB_DUConfigurationQuery_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_f1ap_GNB_DUConfigurationQuery(tvb, offset, &asn1_ctx, tree, hf_f1ap_GNB_DUConfigurationQuery_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_GNBDUOverloadInformation_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_f1ap_GNBDUOverloadInformation(tvb, offset, &asn1_ctx, tree, hf_f1ap_GNBDUOverloadInformation_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_GNB_DU_TNL_Association_To_Remove_Item_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_f1ap_GNB_DU_TNL_Association_To_Remove_Item(tvb, offset, &asn1_ctx, tree, hf_f1ap_GNB_DU_TNL_Association_To_Remove_Item_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_HandoverPreparationInformation_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_f1ap_HandoverPreparationInformation(tvb, offset, &asn1_ctx, tree, hf_f1ap_HandoverPreparationInformation_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_IgnorePRACHConfiguration_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_f1ap_IgnorePRACHConfiguration(tvb, offset, &asn1_ctx, tree, hf_f1ap_IgnorePRACHConfiguration_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_IgnoreResourceCoordinationContainer_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_f1ap_IgnoreResourceCoordinationContainer(tvb, offset, &asn1_ctx, tree, hf_f1ap_IgnoreResourceCoordinationContainer_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_InactivityMonitoringRequest_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_f1ap_InactivityMonitoringRequest(tvb, offset, &asn1_ctx, tree, hf_f1ap_InactivityMonitoringRequest_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_InactivityMonitoringResponse_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_f1ap_InactivityMonitoringResponse(tvb, offset, &asn1_ctx, tree, hf_f1ap_InactivityMonitoringResponse_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_MaskedIMEISV_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_f1ap_MaskedIMEISV(tvb, offset, &asn1_ctx, tree, hf_f1ap_MaskedIMEISV_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_MeasGapSharingConfig_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_f1ap_MeasGapSharingConfig(tvb, offset, &asn1_ctx, tree, hf_f1ap_MeasGapSharingConfig_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_MeasurementTimingConfiguration_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_f1ap_MeasurementTimingConfiguration(tvb, offset, &asn1_ctx, tree, hf_f1ap_MeasurementTimingConfiguration_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_NeedforGap_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_f1ap_NeedforGap(tvb, offset, &asn1_ctx, tree, hf_f1ap_NeedforGap_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_NR_CGI_List_For_Restart_Item_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_f1ap_NR_CGI_List_For_Restart_Item(tvb, offset, &asn1_ctx, tree, hf_f1ap_NR_CGI_List_For_Restart_Item_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_NotificationInformation_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_f1ap_NotificationInformation(tvb, offset, &asn1_ctx, tree, hf_f1ap_NotificationInformation_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_NRCGI_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_f1ap_NRCGI(tvb, offset, &asn1_ctx, tree, hf_f1ap_NRCGI_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_NumberofBroadcastRequest_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_f1ap_NumberofBroadcastRequest(tvb, offset, &asn1_ctx, tree, hf_f1ap_NumberofBroadcastRequest_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_PagingCell_Item_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_f1ap_PagingCell_Item(tvb, offset, &asn1_ctx, tree, hf_f1ap_PagingCell_Item_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_PagingDRX_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_f1ap_PagingDRX(tvb, offset, &asn1_ctx, tree, hf_f1ap_PagingDRX_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_PagingIdentity_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_f1ap_PagingIdentity(tvb, offset, &asn1_ctx, tree, hf_f1ap_PagingIdentity_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_PagingOrigin_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_f1ap_PagingOrigin(tvb, offset, &asn1_ctx, tree, hf_f1ap_PagingOrigin_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_PagingPriority_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_f1ap_PagingPriority(tvb, offset, &asn1_ctx, tree, hf_f1ap_PagingPriority_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_PDCCH_BlindDetectionSCG_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_f1ap_PDCCH_BlindDetectionSCG(tvb, offset, &asn1_ctx, tree, hf_f1ap_PDCCH_BlindDetectionSCG_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_PDCPSNLength_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_f1ap_PDCPSNLength(tvb, offset, &asn1_ctx, tree, hf_f1ap_PDCPSNLength_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_PDUSessionID_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_f1ap_PDUSessionID(tvb, offset, &asn1_ctx, tree, hf_f1ap_PDUSessionID_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_Ph_InfoMCG_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_f1ap_Ph_InfoMCG(tvb, offset, &asn1_ctx, tree, hf_f1ap_Ph_InfoMCG_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_Ph_InfoSCG_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_f1ap_Ph_InfoSCG(tvb, offset, &asn1_ctx, tree, hf_f1ap_Ph_InfoSCG_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_PLMN_Identity_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_f1ap_PLMN_Identity(tvb, offset, &asn1_ctx, tree, hf_f1ap_PLMN_Identity_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_PortNumber_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_f1ap_PortNumber(tvb, offset, &asn1_ctx, tree, hf_f1ap_PortNumber_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_Protected_EUTRA_Resources_Item_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_f1ap_Protected_EUTRA_Resources_Item(tvb, offset, &asn1_ctx, tree, hf_f1ap_Protected_EUTRA_Resources_Item_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_Potential_SpCell_Item_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_f1ap_Potential_SpCell_Item(tvb, offset, &asn1_ctx, tree, hf_f1ap_Potential_SpCell_Item_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_PWS_Failed_NR_CGI_Item_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_f1ap_PWS_Failed_NR_CGI_Item(tvb, offset, &asn1_ctx, tree, hf_f1ap_PWS_Failed_NR_CGI_Item_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_PWSSystemInformation_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_f1ap_PWSSystemInformation(tvb, offset, &asn1_ctx, tree, hf_f1ap_PWSSystemInformation_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_QoSFlowMappingIndication_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_f1ap_QoSFlowMappingIndication(tvb, offset, &asn1_ctx, tree, hf_f1ap_QoSFlowMappingIndication_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_RANAC_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_f1ap_RANAC(tvb, offset, &asn1_ctx, tree, hf_f1ap_RANAC_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_RANUEID_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_f1ap_RANUEID(tvb, offset, &asn1_ctx, tree, hf_f1ap_RANUEID_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_RAT_FrequencyPriorityInformation_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_f1ap_RAT_FrequencyPriorityInformation(tvb, offset, &asn1_ctx, tree, hf_f1ap_RAT_FrequencyPriorityInformation_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_RequestedBandCombinationIndex_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_f1ap_RequestedBandCombinationIndex(tvb, offset, &asn1_ctx, tree, hf_f1ap_RequestedBandCombinationIndex_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_RequestedFeatureSetEntryIndex_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_f1ap_RequestedFeatureSetEntryIndex(tvb, offset, &asn1_ctx, tree, hf_f1ap_RequestedFeatureSetEntryIndex_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_Requested_PDCCH_BlindDetectionSCG_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_f1ap_Requested_PDCCH_BlindDetectionSCG(tvb, offset, &asn1_ctx, tree, hf_f1ap_Requested_PDCCH_BlindDetectionSCG_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_RequestedP_MaxFR2_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_f1ap_RequestedP_MaxFR2(tvb, offset, &asn1_ctx, tree, hf_f1ap_RequestedP_MaxFR2_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_RequestType_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_f1ap_RequestType(tvb, offset, &asn1_ctx, tree, hf_f1ap_RequestType_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_ResourceCoordinationTransferInformation_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_f1ap_ResourceCoordinationTransferInformation(tvb, offset, &asn1_ctx, tree, hf_f1ap_ResourceCoordinationTransferInformation_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_ResourceCoordinationTransferContainer_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_f1ap_ResourceCoordinationTransferContainer(tvb, offset, &asn1_ctx, tree, hf_f1ap_ResourceCoordinationTransferContainer_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_RepetitionPeriod_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_f1ap_RepetitionPeriod(tvb, offset, &asn1_ctx, tree, hf_f1ap_RepetitionPeriod_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_RLCFailureIndication_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_f1ap_RLCFailureIndication(tvb, offset, &asn1_ctx, tree, hf_f1ap_RLCFailureIndication_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_RLCMode_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_f1ap_RLCMode(tvb, offset, &asn1_ctx, tree, hf_f1ap_RLCMode_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_RLC_Status_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_f1ap_RLC_Status(tvb, offset, &asn1_ctx, tree, hf_f1ap_RLC_Status_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_RRCContainer_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_f1ap_RRCContainer(tvb, offset, &asn1_ctx, tree, hf_f1ap_RRCContainer_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_RRCContainer_RRCSetupComplete_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_f1ap_RRCContainer_RRCSetupComplete(tvb, offset, &asn1_ctx, tree, hf_f1ap_RRCContainer_RRCSetupComplete_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_RRCDeliveryStatus_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_f1ap_RRCDeliveryStatus(tvb, offset, &asn1_ctx, tree, hf_f1ap_RRCDeliveryStatus_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_RRCDeliveryStatusRequest_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_f1ap_RRCDeliveryStatusRequest(tvb, offset, &asn1_ctx, tree, hf_f1ap_RRCDeliveryStatusRequest_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_RRCReconfigurationCompleteIndicator_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_f1ap_RRCReconfigurationCompleteIndicator(tvb, offset, &asn1_ctx, tree, hf_f1ap_RRCReconfigurationCompleteIndicator_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_RRC_Version_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_f1ap_RRC_Version(tvb, offset, &asn1_ctx, tree, hf_f1ap_RRC_Version_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_Latest_RRC_Version_Enhanced_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_f1ap_Latest_RRC_Version_Enhanced(tvb, offset, &asn1_ctx, tree, hf_f1ap_Latest_RRC_Version_Enhanced_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_SCell_FailedtoSetup_Item_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_f1ap_SCell_FailedtoSetup_Item(tvb, offset, &asn1_ctx, tree, hf_f1ap_SCell_FailedtoSetup_Item_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_SCell_FailedtoSetupMod_Item_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_f1ap_SCell_FailedtoSetupMod_Item(tvb, offset, &asn1_ctx, tree, hf_f1ap_SCell_FailedtoSetupMod_Item_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_SCell_ToBeRemoved_Item_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_f1ap_SCell_ToBeRemoved_Item(tvb, offset, &asn1_ctx, tree, hf_f1ap_SCell_ToBeRemoved_Item_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_SCell_ToBeSetup_Item_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_f1ap_SCell_ToBeSetup_Item(tvb, offset, &asn1_ctx, tree, hf_f1ap_SCell_ToBeSetup_Item_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_SCell_ToBeSetupMod_Item_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_f1ap_SCell_ToBeSetupMod_Item(tvb, offset, &asn1_ctx, tree, hf_f1ap_SCell_ToBeSetupMod_Item_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_SelectedBandCombinationIndex_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_f1ap_SelectedBandCombinationIndex(tvb, offset, &asn1_ctx, tree, hf_f1ap_SelectedBandCombinationIndex_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_SelectedFeatureSetEntryIndex_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_f1ap_SelectedFeatureSetEntryIndex(tvb, offset, &asn1_ctx, tree, hf_f1ap_SelectedFeatureSetEntryIndex_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_ServCellIndex_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_f1ap_ServCellIndex(tvb, offset, &asn1_ctx, tree, hf_f1ap_ServCellIndex_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_ServingCellMO_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_f1ap_ServingCellMO(tvb, offset, &asn1_ctx, tree, hf_f1ap_ServingCellMO_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_Served_Cells_To_Add_Item_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_f1ap_Served_Cells_To_Add_Item(tvb, offset, &asn1_ctx, tree, hf_f1ap_Served_Cells_To_Add_Item_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_Served_Cells_To_Delete_Item_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_f1ap_Served_Cells_To_Delete_Item(tvb, offset, &asn1_ctx, tree, hf_f1ap_Served_Cells_To_Delete_Item_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_Served_Cells_To_Modify_Item_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_f1ap_Served_Cells_To_Modify_Item(tvb, offset, &asn1_ctx, tree, hf_f1ap_Served_Cells_To_Modify_Item_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_SItype_List_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_f1ap_SItype_List(tvb, offset, &asn1_ctx, tree, hf_f1ap_SItype_List_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_SliceSupportList_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_f1ap_SliceSupportList(tvb, offset, &asn1_ctx, tree, hf_f1ap_SliceSupportList_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_SRBID_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_f1ap_SRBID(tvb, offset, &asn1_ctx, tree, hf_f1ap_SRBID_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_SRBs_FailedToBeSetup_Item_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_f1ap_SRBs_FailedToBeSetup_Item(tvb, offset, &asn1_ctx, tree, hf_f1ap_SRBs_FailedToBeSetup_Item_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_SRBs_FailedToBeSetupMod_Item_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_f1ap_SRBs_FailedToBeSetupMod_Item(tvb, offset, &asn1_ctx, tree, hf_f1ap_SRBs_FailedToBeSetupMod_Item_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_SRBs_Modified_Item_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_f1ap_SRBs_Modified_Item(tvb, offset, &asn1_ctx, tree, hf_f1ap_SRBs_Modified_Item_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_SRBs_Required_ToBeReleased_Item_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_f1ap_SRBs_Required_ToBeReleased_Item(tvb, offset, &asn1_ctx, tree, hf_f1ap_SRBs_Required_ToBeReleased_Item_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_SRBs_Setup_Item_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_f1ap_SRBs_Setup_Item(tvb, offset, &asn1_ctx, tree, hf_f1ap_SRBs_Setup_Item_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_SRBs_SetupMod_Item_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_f1ap_SRBs_SetupMod_Item(tvb, offset, &asn1_ctx, tree, hf_f1ap_SRBs_SetupMod_Item_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_SRBs_ToBeReleased_Item_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_f1ap_SRBs_ToBeReleased_Item(tvb, offset, &asn1_ctx, tree, hf_f1ap_SRBs_ToBeReleased_Item_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_SRBs_ToBeSetup_Item_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_f1ap_SRBs_ToBeSetup_Item(tvb, offset, &asn1_ctx, tree, hf_f1ap_SRBs_ToBeSetup_Item_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_SRBs_ToBeSetupMod_Item_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_f1ap_SRBs_ToBeSetupMod_Item(tvb, offset, &asn1_ctx, tree, hf_f1ap_SRBs_ToBeSetupMod_Item_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_SULAccessIndication_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_f1ap_SULAccessIndication(tvb, offset, &asn1_ctx, tree, hf_f1ap_SULAccessIndication_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_SystemInformationAreaID_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_f1ap_SystemInformationAreaID(tvb, offset, &asn1_ctx, tree, hf_f1ap_SystemInformationAreaID_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_TimeToWait_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_f1ap_TimeToWait(tvb, offset, &asn1_ctx, tree, hf_f1ap_TimeToWait_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_TransactionID_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_f1ap_TransactionID(tvb, offset, &asn1_ctx, tree, hf_f1ap_TransactionID_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_TransmissionActionIndicator_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_f1ap_TransmissionActionIndicator(tvb, offset, &asn1_ctx, tree, hf_f1ap_TransmissionActionIndicator_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_UAC_Assistance_Info_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_f1ap_UAC_Assistance_Info(tvb, offset, &asn1_ctx, tree, hf_f1ap_UAC_Assistance_Info_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_UE_associatedLogicalF1_ConnectionItem_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_f1ap_UE_associatedLogicalF1_ConnectionItem(tvb, offset, &asn1_ctx, tree, hf_f1ap_UE_associatedLogicalF1_ConnectionItem_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_UEAssistanceInformation_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_f1ap_UEAssistanceInformation(tvb, offset, &asn1_ctx, tree, hf_f1ap_UEAssistanceInformation_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_UEContextNotRetrievable_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_f1ap_UEContextNotRetrievable(tvb, offset, &asn1_ctx, tree, hf_f1ap_UEContextNotRetrievable_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_UEIdentityIndexValue_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_f1ap_UEIdentityIndexValue(tvb, offset, &asn1_ctx, tree, hf_f1ap_UEIdentityIndexValue_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_UplinkTxDirectCurrentListInformation_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_f1ap_UplinkTxDirectCurrentListInformation(tvb, offset, &asn1_ctx, tree, hf_f1ap_UplinkTxDirectCurrentListInformation_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_Reset_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_f1ap_Reset(tvb, offset, &asn1_ctx, tree, hf_f1ap_Reset_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_ResetType_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_f1ap_ResetType(tvb, offset, &asn1_ctx, tree, hf_f1ap_ResetType_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_ResetAcknowledge_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_f1ap_ResetAcknowledge(tvb, offset, &asn1_ctx, tree, hf_f1ap_ResetAcknowledge_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_UE_associatedLogicalF1_ConnectionListResAck_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_f1ap_UE_associatedLogicalF1_ConnectionListResAck(tvb, offset, &asn1_ctx, tree, hf_f1ap_UE_associatedLogicalF1_ConnectionListResAck_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_ErrorIndication_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_f1ap_ErrorIndication(tvb, offset, &asn1_ctx, tree, hf_f1ap_ErrorIndication_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_F1SetupRequest_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_f1ap_F1SetupRequest(tvb, offset, &asn1_ctx, tree, hf_f1ap_F1SetupRequest_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_GNB_DU_Served_Cells_List_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_f1ap_GNB_DU_Served_Cells_List(tvb, offset, &asn1_ctx, tree, hf_f1ap_GNB_DU_Served_Cells_List_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_F1SetupResponse_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_f1ap_F1SetupResponse(tvb, offset, &asn1_ctx, tree, hf_f1ap_F1SetupResponse_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_Cells_to_be_Activated_List_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_f1ap_Cells_to_be_Activated_List(tvb, offset, &asn1_ctx, tree, hf_f1ap_Cells_to_be_Activated_List_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_F1SetupFailure_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_f1ap_F1SetupFailure(tvb, offset, &asn1_ctx, tree, hf_f1ap_F1SetupFailure_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_GNBDUConfigurationUpdate_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_f1ap_GNBDUConfigurationUpdate(tvb, offset, &asn1_ctx, tree, hf_f1ap_GNBDUConfigurationUpdate_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_Served_Cells_To_Add_List_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_f1ap_Served_Cells_To_Add_List(tvb, offset, &asn1_ctx, tree, hf_f1ap_Served_Cells_To_Add_List_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_Served_Cells_To_Modify_List_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_f1ap_Served_Cells_To_Modify_List(tvb, offset, &asn1_ctx, tree, hf_f1ap_Served_Cells_To_Modify_List_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_Served_Cells_To_Delete_List_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_f1ap_Served_Cells_To_Delete_List(tvb, offset, &asn1_ctx, tree, hf_f1ap_Served_Cells_To_Delete_List_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_Cells_Status_List_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_f1ap_Cells_Status_List(tvb, offset, &asn1_ctx, tree, hf_f1ap_Cells_Status_List_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_Dedicated_SIDelivery_NeededUE_List_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_f1ap_Dedicated_SIDelivery_NeededUE_List(tvb, offset, &asn1_ctx, tree, hf_f1ap_Dedicated_SIDelivery_NeededUE_List_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_GNB_DU_TNL_Association_To_Remove_List_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_f1ap_GNB_DU_TNL_Association_To_Remove_List(tvb, offset, &asn1_ctx, tree, hf_f1ap_GNB_DU_TNL_Association_To_Remove_List_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_GNBDUConfigurationUpdateAcknowledge_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_f1ap_GNBDUConfigurationUpdateAcknowledge(tvb, offset, &asn1_ctx, tree, hf_f1ap_GNBDUConfigurationUpdateAcknowledge_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_GNBDUConfigurationUpdateFailure_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_f1ap_GNBDUConfigurationUpdateFailure(tvb, offset, &asn1_ctx, tree, hf_f1ap_GNBDUConfigurationUpdateFailure_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_GNBCUConfigurationUpdate_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_f1ap_GNBCUConfigurationUpdate(tvb, offset, &asn1_ctx, tree, hf_f1ap_GNBCUConfigurationUpdate_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_Cells_to_be_Deactivated_List_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_f1ap_Cells_to_be_Deactivated_List(tvb, offset, &asn1_ctx, tree, hf_f1ap_Cells_to_be_Deactivated_List_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_GNB_CU_TNL_Association_To_Add_List_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_f1ap_GNB_CU_TNL_Association_To_Add_List(tvb, offset, &asn1_ctx, tree, hf_f1ap_GNB_CU_TNL_Association_To_Add_List_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_GNB_CU_TNL_Association_To_Remove_List_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_f1ap_GNB_CU_TNL_Association_To_Remove_List(tvb, offset, &asn1_ctx, tree, hf_f1ap_GNB_CU_TNL_Association_To_Remove_List_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_GNB_CU_TNL_Association_To_Update_List_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_f1ap_GNB_CU_TNL_Association_To_Update_List(tvb, offset, &asn1_ctx, tree, hf_f1ap_GNB_CU_TNL_Association_To_Update_List_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_Cells_to_be_Barred_List_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_f1ap_Cells_to_be_Barred_List(tvb, offset, &asn1_ctx, tree, hf_f1ap_Cells_to_be_Barred_List_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_Protected_EUTRA_Resources_List_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_f1ap_Protected_EUTRA_Resources_List(tvb, offset, &asn1_ctx, tree, hf_f1ap_Protected_EUTRA_Resources_List_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_GNBCUConfigurationUpdateAcknowledge_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_f1ap_GNBCUConfigurationUpdateAcknowledge(tvb, offset, &asn1_ctx, tree, hf_f1ap_GNBCUConfigurationUpdateAcknowledge_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_Cells_Failed_to_be_Activated_List_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_f1ap_Cells_Failed_to_be_Activated_List(tvb, offset, &asn1_ctx, tree, hf_f1ap_Cells_Failed_to_be_Activated_List_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_GNB_CU_TNL_Association_Setup_List_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_f1ap_GNB_CU_TNL_Association_Setup_List(tvb, offset, &asn1_ctx, tree, hf_f1ap_GNB_CU_TNL_Association_Setup_List_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_GNB_CU_TNL_Association_Failed_To_Setup_List_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_f1ap_GNB_CU_TNL_Association_Failed_To_Setup_List(tvb, offset, &asn1_ctx, tree, hf_f1ap_GNB_CU_TNL_Association_Failed_To_Setup_List_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_GNBCUConfigurationUpdateFailure_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_f1ap_GNBCUConfigurationUpdateFailure(tvb, offset, &asn1_ctx, tree, hf_f1ap_GNBCUConfigurationUpdateFailure_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_GNBDUResourceCoordinationRequest_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_f1ap_GNBDUResourceCoordinationRequest(tvb, offset, &asn1_ctx, tree, hf_f1ap_GNBDUResourceCoordinationRequest_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_GNBDUResourceCoordinationResponse_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_f1ap_GNBDUResourceCoordinationResponse(tvb, offset, &asn1_ctx, tree, hf_f1ap_GNBDUResourceCoordinationResponse_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_UEContextSetupRequest_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_f1ap_UEContextSetupRequest(tvb, offset, &asn1_ctx, tree, hf_f1ap_UEContextSetupRequest_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_Candidate_SpCell_List_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_f1ap_Candidate_SpCell_List(tvb, offset, &asn1_ctx, tree, hf_f1ap_Candidate_SpCell_List_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_SCell_ToBeSetup_List_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_f1ap_SCell_ToBeSetup_List(tvb, offset, &asn1_ctx, tree, hf_f1ap_SCell_ToBeSetup_List_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_SRBs_ToBeSetup_List_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_f1ap_SRBs_ToBeSetup_List(tvb, offset, &asn1_ctx, tree, hf_f1ap_SRBs_ToBeSetup_List_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_DRBs_ToBeSetup_List_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_f1ap_DRBs_ToBeSetup_List(tvb, offset, &asn1_ctx, tree, hf_f1ap_DRBs_ToBeSetup_List_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_UEContextSetupResponse_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_f1ap_UEContextSetupResponse(tvb, offset, &asn1_ctx, tree, hf_f1ap_UEContextSetupResponse_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_DRBs_Setup_List_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_f1ap_DRBs_Setup_List(tvb, offset, &asn1_ctx, tree, hf_f1ap_DRBs_Setup_List_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_SRBs_FailedToBeSetup_List_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_f1ap_SRBs_FailedToBeSetup_List(tvb, offset, &asn1_ctx, tree, hf_f1ap_SRBs_FailedToBeSetup_List_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_DRBs_FailedToBeSetup_List_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_f1ap_DRBs_FailedToBeSetup_List(tvb, offset, &asn1_ctx, tree, hf_f1ap_DRBs_FailedToBeSetup_List_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_SCell_FailedtoSetup_List_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_f1ap_SCell_FailedtoSetup_List(tvb, offset, &asn1_ctx, tree, hf_f1ap_SCell_FailedtoSetup_List_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_SRBs_Setup_List_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_f1ap_SRBs_Setup_List(tvb, offset, &asn1_ctx, tree, hf_f1ap_SRBs_Setup_List_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_UEContextSetupFailure_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_f1ap_UEContextSetupFailure(tvb, offset, &asn1_ctx, tree, hf_f1ap_UEContextSetupFailure_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_Potential_SpCell_List_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_f1ap_Potential_SpCell_List(tvb, offset, &asn1_ctx, tree, hf_f1ap_Potential_SpCell_List_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_UEContextReleaseRequest_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_f1ap_UEContextReleaseRequest(tvb, offset, &asn1_ctx, tree, hf_f1ap_UEContextReleaseRequest_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_UEContextReleaseCommand_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_f1ap_UEContextReleaseCommand(tvb, offset, &asn1_ctx, tree, hf_f1ap_UEContextReleaseCommand_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_UEContextReleaseComplete_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_f1ap_UEContextReleaseComplete(tvb, offset, &asn1_ctx, tree, hf_f1ap_UEContextReleaseComplete_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_UEContextModificationRequest_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_f1ap_UEContextModificationRequest(tvb, offset, &asn1_ctx, tree, hf_f1ap_UEContextModificationRequest_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_SCell_ToBeSetupMod_List_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_f1ap_SCell_ToBeSetupMod_List(tvb, offset, &asn1_ctx, tree, hf_f1ap_SCell_ToBeSetupMod_List_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_SCell_ToBeRemoved_List_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_f1ap_SCell_ToBeRemoved_List(tvb, offset, &asn1_ctx, tree, hf_f1ap_SCell_ToBeRemoved_List_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_SRBs_ToBeSetupMod_List_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_f1ap_SRBs_ToBeSetupMod_List(tvb, offset, &asn1_ctx, tree, hf_f1ap_SRBs_ToBeSetupMod_List_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_DRBs_ToBeSetupMod_List_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_f1ap_DRBs_ToBeSetupMod_List(tvb, offset, &asn1_ctx, tree, hf_f1ap_DRBs_ToBeSetupMod_List_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_DRBs_ToBeModified_List_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_f1ap_DRBs_ToBeModified_List(tvb, offset, &asn1_ctx, tree, hf_f1ap_DRBs_ToBeModified_List_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_SRBs_ToBeReleased_List_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_f1ap_SRBs_ToBeReleased_List(tvb, offset, &asn1_ctx, tree, hf_f1ap_SRBs_ToBeReleased_List_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_DRBs_ToBeReleased_List_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_f1ap_DRBs_ToBeReleased_List(tvb, offset, &asn1_ctx, tree, hf_f1ap_DRBs_ToBeReleased_List_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_UEContextModificationResponse_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_f1ap_UEContextModificationResponse(tvb, offset, &asn1_ctx, tree, hf_f1ap_UEContextModificationResponse_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_DRBs_SetupMod_List_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_f1ap_DRBs_SetupMod_List(tvb, offset, &asn1_ctx, tree, hf_f1ap_DRBs_SetupMod_List_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_DRBs_Modified_List_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_f1ap_DRBs_Modified_List(tvb, offset, &asn1_ctx, tree, hf_f1ap_DRBs_Modified_List_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_SRBs_SetupMod_List_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_f1ap_SRBs_SetupMod_List(tvb, offset, &asn1_ctx, tree, hf_f1ap_SRBs_SetupMod_List_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_SRBs_Modified_List_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_f1ap_SRBs_Modified_List(tvb, offset, &asn1_ctx, tree, hf_f1ap_SRBs_Modified_List_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_DRBs_FailedToBeModified_List_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_f1ap_DRBs_FailedToBeModified_List(tvb, offset, &asn1_ctx, tree, hf_f1ap_DRBs_FailedToBeModified_List_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_SRBs_FailedToBeSetupMod_List_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_f1ap_SRBs_FailedToBeSetupMod_List(tvb, offset, &asn1_ctx, tree, hf_f1ap_SRBs_FailedToBeSetupMod_List_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_DRBs_FailedToBeSetupMod_List_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_f1ap_DRBs_FailedToBeSetupMod_List(tvb, offset, &asn1_ctx, tree, hf_f1ap_DRBs_FailedToBeSetupMod_List_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_SCell_FailedtoSetupMod_List_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_f1ap_SCell_FailedtoSetupMod_List(tvb, offset, &asn1_ctx, tree, hf_f1ap_SCell_FailedtoSetupMod_List_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_Associated_SCell_List_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_f1ap_Associated_SCell_List(tvb, offset, &asn1_ctx, tree, hf_f1ap_Associated_SCell_List_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_UEContextModificationFailure_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_f1ap_UEContextModificationFailure(tvb, offset, &asn1_ctx, tree, hf_f1ap_UEContextModificationFailure_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_UEContextModificationRequired_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_f1ap_UEContextModificationRequired(tvb, offset, &asn1_ctx, tree, hf_f1ap_UEContextModificationRequired_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_DRBs_Required_ToBeModified_List_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_f1ap_DRBs_Required_ToBeModified_List(tvb, offset, &asn1_ctx, tree, hf_f1ap_DRBs_Required_ToBeModified_List_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_DRBs_Required_ToBeReleased_List_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_f1ap_DRBs_Required_ToBeReleased_List(tvb, offset, &asn1_ctx, tree, hf_f1ap_DRBs_Required_ToBeReleased_List_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_SRBs_Required_ToBeReleased_List_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_f1ap_SRBs_Required_ToBeReleased_List(tvb, offset, &asn1_ctx, tree, hf_f1ap_SRBs_Required_ToBeReleased_List_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_UEContextModificationConfirm_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_f1ap_UEContextModificationConfirm(tvb, offset, &asn1_ctx, tree, hf_f1ap_UEContextModificationConfirm_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_DRBs_ModifiedConf_List_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_f1ap_DRBs_ModifiedConf_List(tvb, offset, &asn1_ctx, tree, hf_f1ap_DRBs_ModifiedConf_List_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_UEContextModificationRefuse_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_f1ap_UEContextModificationRefuse(tvb, offset, &asn1_ctx, tree, hf_f1ap_UEContextModificationRefuse_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_WriteReplaceWarningRequest_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_f1ap_WriteReplaceWarningRequest(tvb, offset, &asn1_ctx, tree, hf_f1ap_WriteReplaceWarningRequest_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_Cells_To_Be_Broadcast_List_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_f1ap_Cells_To_Be_Broadcast_List(tvb, offset, &asn1_ctx, tree, hf_f1ap_Cells_To_Be_Broadcast_List_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_WriteReplaceWarningResponse_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_f1ap_WriteReplaceWarningResponse(tvb, offset, &asn1_ctx, tree, hf_f1ap_WriteReplaceWarningResponse_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_Cells_Broadcast_Completed_List_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_f1ap_Cells_Broadcast_Completed_List(tvb, offset, &asn1_ctx, tree, hf_f1ap_Cells_Broadcast_Completed_List_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_PWSCancelRequest_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_f1ap_PWSCancelRequest(tvb, offset, &asn1_ctx, tree, hf_f1ap_PWSCancelRequest_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_Broadcast_To_Be_Cancelled_List_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_f1ap_Broadcast_To_Be_Cancelled_List(tvb, offset, &asn1_ctx, tree, hf_f1ap_Broadcast_To_Be_Cancelled_List_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_PWSCancelResponse_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_f1ap_PWSCancelResponse(tvb, offset, &asn1_ctx, tree, hf_f1ap_PWSCancelResponse_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_Cells_Broadcast_Cancelled_List_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_f1ap_Cells_Broadcast_Cancelled_List(tvb, offset, &asn1_ctx, tree, hf_f1ap_Cells_Broadcast_Cancelled_List_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_UEInactivityNotification_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_f1ap_UEInactivityNotification(tvb, offset, &asn1_ctx, tree, hf_f1ap_UEInactivityNotification_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_DRB_Activity_List_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_f1ap_DRB_Activity_List(tvb, offset, &asn1_ctx, tree, hf_f1ap_DRB_Activity_List_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_InitialULRRCMessageTransfer_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_f1ap_InitialULRRCMessageTransfer(tvb, offset, &asn1_ctx, tree, hf_f1ap_InitialULRRCMessageTransfer_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_DLRRCMessageTransfer_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_f1ap_DLRRCMessageTransfer(tvb, offset, &asn1_ctx, tree, hf_f1ap_DLRRCMessageTransfer_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_RedirectedRRCmessage_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_f1ap_RedirectedRRCmessage(tvb, offset, &asn1_ctx, tree, hf_f1ap_RedirectedRRCmessage_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_ULRRCMessageTransfer_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_f1ap_ULRRCMessageTransfer(tvb, offset, &asn1_ctx, tree, hf_f1ap_ULRRCMessageTransfer_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_PrivateMessage_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_f1ap_PrivateMessage(tvb, offset, &asn1_ctx, tree, hf_f1ap_PrivateMessage_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_SystemInformationDeliveryCommand_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_f1ap_SystemInformationDeliveryCommand(tvb, offset, &asn1_ctx, tree, hf_f1ap_SystemInformationDeliveryCommand_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_Paging_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_f1ap_Paging(tvb, offset, &asn1_ctx, tree, hf_f1ap_Paging_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_PagingCell_list_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_f1ap_PagingCell_list(tvb, offset, &asn1_ctx, tree, hf_f1ap_PagingCell_list_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_Notify_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_f1ap_Notify(tvb, offset, &asn1_ctx, tree, hf_f1ap_Notify_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_DRB_Notify_List_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_f1ap_DRB_Notify_List(tvb, offset, &asn1_ctx, tree, hf_f1ap_DRB_Notify_List_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_NetworkAccessRateReduction_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_f1ap_NetworkAccessRateReduction(tvb, offset, &asn1_ctx, tree, hf_f1ap_NetworkAccessRateReduction_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_PWSRestartIndication_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_f1ap_PWSRestartIndication(tvb, offset, &asn1_ctx, tree, hf_f1ap_PWSRestartIndication_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_NR_CGI_List_For_Restart_List_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_f1ap_NR_CGI_List_For_Restart_List(tvb, offset, &asn1_ctx, tree, hf_f1ap_NR_CGI_List_For_Restart_List_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_PWSFailureIndication_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_f1ap_PWSFailureIndication(tvb, offset, &asn1_ctx, tree, hf_f1ap_PWSFailureIndication_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_PWS_Failed_NR_CGI_List_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_f1ap_PWS_Failed_NR_CGI_List(tvb, offset, &asn1_ctx, tree, hf_f1ap_PWS_Failed_NR_CGI_List_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_GNBDUStatusIndication_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_f1ap_GNBDUStatusIndication(tvb, offset, &asn1_ctx, tree, hf_f1ap_GNBDUStatusIndication_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_RRCDeliveryReport_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_f1ap_RRCDeliveryReport(tvb, offset, &asn1_ctx, tree, hf_f1ap_RRCDeliveryReport_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_F1RemovalRequest_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_f1ap_F1RemovalRequest(tvb, offset, &asn1_ctx, tree, hf_f1ap_F1RemovalRequest_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_F1RemovalResponse_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_f1ap_F1RemovalResponse(tvb, offset, &asn1_ctx, tree, hf_f1ap_F1RemovalResponse_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_F1RemovalFailure_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_f1ap_F1RemovalFailure(tvb, offset, &asn1_ctx, tree, hf_f1ap_F1RemovalFailure_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_F1AP_PDU_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_f1ap_F1AP_PDU(tvb, offset, &asn1_ctx, tree, hf_f1ap_F1AP_PDU_PDU);
  offset += 7; offset >>= 3;
  return offset;
}


/*--- End of included file: packet-f1ap-fn.c ---*/
#line 168 "./asn1/f1ap/packet-f1ap-template.c"

static int dissect_ProtocolIEFieldValue(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
  f1ap_ctx_t f1ap_ctx;
  f1ap_private_data_t *f1ap_data = f1ap_get_private_data(pinfo);

  f1ap_ctx.message_type        = f1ap_data->message_type;
  f1ap_ctx.ProcedureCode       = f1ap_data->procedure_code;
  f1ap_ctx.ProtocolIE_ID       = f1ap_data->protocol_ie_id;
  f1ap_ctx.ProtocolExtensionID = f1ap_data->protocol_extension_id;

  return (dissector_try_uint_new(f1ap_ies_dissector_table, f1ap_data->protocol_ie_id, tvb, pinfo, tree, FALSE, &f1ap_ctx)) ? tvb_captured_length(tvb) : 0;
}

static int dissect_ProtocolExtensionFieldExtensionValue(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
  f1ap_ctx_t f1ap_ctx;
  f1ap_private_data_t *f1ap_data = f1ap_get_private_data(pinfo);

  f1ap_ctx.message_type        = f1ap_data->message_type;
  f1ap_ctx.ProcedureCode       = f1ap_data->procedure_code;
  f1ap_ctx.ProtocolIE_ID       = f1ap_data->protocol_ie_id;
  f1ap_ctx.ProtocolExtensionID = f1ap_data->protocol_extension_id;

  return (dissector_try_uint_new(f1ap_extension_dissector_table, f1ap_data->protocol_extension_id, tvb, pinfo, tree, FALSE, &f1ap_ctx)) ? tvb_captured_length(tvb) : 0;
}

static int dissect_InitiatingMessageValue(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data)
{
  f1ap_private_data_t *f1ap_data = f1ap_get_private_data(pinfo);

  return (dissector_try_uint_new(f1ap_proc_imsg_dissector_table, f1ap_data->procedure_code, tvb, pinfo, tree, FALSE, data)) ? tvb_captured_length(tvb) : 0;
}

static int dissect_SuccessfulOutcomeValue(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data)
{
  f1ap_private_data_t *f1ap_data = f1ap_get_private_data(pinfo);

  return (dissector_try_uint_new(f1ap_proc_sout_dissector_table, f1ap_data->procedure_code, tvb, pinfo, tree, FALSE, data)) ? tvb_captured_length(tvb) : 0;
}

static int dissect_UnsuccessfulOutcomeValue(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data)
{
  f1ap_private_data_t *f1ap_data = f1ap_get_private_data(pinfo);

  return (dissector_try_uint_new(f1ap_proc_uout_dissector_table, f1ap_data->procedure_code, tvb, pinfo, tree, FALSE, data)) ? tvb_captured_length(tvb) : 0;
}


static int
dissect_f1ap(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
  proto_item *f1ap_item = NULL;
  proto_tree *f1ap_tree = NULL;

  /* make entry in the Protocol column on summary display */
  col_set_str(pinfo->cinfo, COL_PROTOCOL, "F1AP");
  col_clear(pinfo->cinfo, COL_INFO);

  /* create the f1ap protocol tree */
  f1ap_item = proto_tree_add_item(tree, proto_f1ap, tvb, 0, -1, ENC_NA);
  f1ap_tree = proto_item_add_subtree(f1ap_item, ett_f1ap);

  dissect_F1AP_PDU_PDU(tvb, pinfo, f1ap_tree, NULL);
  return tvb_captured_length(tvb);
}

void proto_register_f1ap(void) {

  /* List of fields */

  static hf_register_info hf[] = {
    { &hf_f1ap_transportLayerAddressIPv4,
      { "IPv4 transportLayerAddress", "f1ap.transportLayerAddressIPv4",
        FT_IPv4, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_f1ap_transportLayerAddressIPv6,
      { "IPv6 transportLayerAddress", "f1ap.transportLayerAddressIPv6",
        FT_IPv6, BASE_NONE, NULL, 0,
        NULL, HFILL }},

/*--- Included file: packet-f1ap-hfarr.c ---*/
#line 1 "./asn1/f1ap/packet-f1ap-hfarr.c"
    { &hf_f1ap_AdditionalSIBMessageList_PDU,
      { "AdditionalSIBMessageList", "f1ap.AdditionalSIBMessageList",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_f1ap_Associated_SCell_Item_PDU,
      { "Associated-SCell-Item", "f1ap.Associated_SCell_Item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_f1ap_AvailablePLMNList_PDU,
      { "AvailablePLMNList", "f1ap.AvailablePLMNList",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_f1ap_AreaScope_PDU,
      { "AreaScope", "f1ap.AreaScope",
        FT_UINT32, BASE_DEC, VALS(f1ap_AreaScope_vals), 0,
        NULL, HFILL }},
    { &hf_f1ap_BitRate_PDU,
      { "BitRate", "f1ap.BitRate",
        FT_UINT64, BASE_DEC|BASE_UNIT_STRING, &units_bit_sec, 0,
        NULL, HFILL }},
    { &hf_f1ap_BearerTypeChange_PDU,
      { "BearerTypeChange", "f1ap.BearerTypeChange",
        FT_UINT32, BASE_DEC, VALS(f1ap_BearerTypeChange_vals), 0,
        NULL, HFILL }},
    { &hf_f1ap_BPLMN_ID_Info_List_PDU,
      { "BPLMN-ID-Info-List", "f1ap.BPLMN_ID_Info_List",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_f1ap_Cancel_all_Warning_Messages_Indicator_PDU,
      { "Cancel-all-Warning-Messages-Indicator", "f1ap.Cancel_all_Warning_Messages_Indicator",
        FT_UINT32, BASE_DEC, VALS(f1ap_Cancel_all_Warning_Messages_Indicator_vals), 0,
        NULL, HFILL }},
    { &hf_f1ap_Candidate_SpCell_Item_PDU,
      { "Candidate-SpCell-Item", "f1ap.Candidate_SpCell_Item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_f1ap_Cause_PDU,
      { "Cause", "f1ap.Cause",
        FT_UINT32, BASE_DEC, VALS(f1ap_Cause_vals), 0,
        NULL, HFILL }},
    { &hf_f1ap_CellGroupConfig_PDU,
      { "CellGroupConfig", "f1ap.CellGroupConfig",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_f1ap_Cell_Direction_PDU,
      { "Cell-Direction", "f1ap.Cell_Direction",
        FT_UINT32, BASE_DEC, VALS(f1ap_Cell_Direction_vals), 0,
        NULL, HFILL }},
    { &hf_f1ap_Cells_Failed_to_be_Activated_List_Item_PDU,
      { "Cells-Failed-to-be-Activated-List-Item", "f1ap.Cells_Failed_to_be_Activated_List_Item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_f1ap_Cells_Status_Item_PDU,
      { "Cells-Status-Item", "f1ap.Cells_Status_Item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_f1ap_Cells_To_Be_Broadcast_Item_PDU,
      { "Cells-To-Be-Broadcast-Item", "f1ap.Cells_To_Be_Broadcast_Item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_f1ap_Cells_Broadcast_Completed_Item_PDU,
      { "Cells-Broadcast-Completed-Item", "f1ap.Cells_Broadcast_Completed_Item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_f1ap_Broadcast_To_Be_Cancelled_Item_PDU,
      { "Broadcast-To-Be-Cancelled-Item", "f1ap.Broadcast_To_Be_Cancelled_Item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_f1ap_Cells_Broadcast_Cancelled_Item_PDU,
      { "Cells-Broadcast-Cancelled-Item", "f1ap.Cells_Broadcast_Cancelled_Item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_f1ap_Cells_to_be_Activated_List_Item_PDU,
      { "Cells-to-be-Activated-List-Item", "f1ap.Cells_to_be_Activated_List_Item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_f1ap_Cells_to_be_Deactivated_List_Item_PDU,
      { "Cells-to-be-Deactivated-List-Item", "f1ap.Cells_to_be_Deactivated_List_Item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_f1ap_Cells_to_be_Barred_Item_PDU,
      { "Cells-to-be-Barred-Item", "f1ap.Cells_to_be_Barred_Item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_f1ap_CellType_PDU,
      { "CellType", "f1ap.CellType_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_f1ap_CellULConfigured_PDU,
      { "CellULConfigured", "f1ap.CellULConfigured",
        FT_UINT32, BASE_DEC, VALS(f1ap_CellULConfigured_vals), 0,
        NULL, HFILL }},
    { &hf_f1ap_CP_TransportLayerAddress_PDU,
      { "CP-TransportLayerAddress", "f1ap.CP_TransportLayerAddress",
        FT_UINT32, BASE_DEC, VALS(f1ap_CP_TransportLayerAddress_vals), 0,
        NULL, HFILL }},
    { &hf_f1ap_CriticalityDiagnostics_PDU,
      { "CriticalityDiagnostics", "f1ap.CriticalityDiagnostics_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_f1ap_C_RNTI_PDU,
      { "C-RNTI", "f1ap.C_RNTI",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_f1ap_CUtoDURRCInformation_PDU,
      { "CUtoDURRCInformation", "f1ap.CUtoDURRCInformation_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_f1ap_DCBasedDuplicationConfigured_PDU,
      { "DCBasedDuplicationConfigured", "f1ap.DCBasedDuplicationConfigured",
        FT_UINT32, BASE_DEC, VALS(f1ap_DCBasedDuplicationConfigured_vals), 0,
        NULL, HFILL }},
    { &hf_f1ap_Dedicated_SIDelivery_NeededUE_Item_PDU,
      { "Dedicated-SIDelivery-NeededUE-Item", "f1ap.Dedicated_SIDelivery_NeededUE_Item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_f1ap_DRB_Activity_Item_PDU,
      { "DRB-Activity-Item", "f1ap.DRB_Activity_Item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_f1ap_DRBs_FailedToBeModified_Item_PDU,
      { "DRBs-FailedToBeModified-Item", "f1ap.DRBs_FailedToBeModified_Item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_f1ap_DRBs_FailedToBeSetup_Item_PDU,
      { "DRBs-FailedToBeSetup-Item", "f1ap.DRBs_FailedToBeSetup_Item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_f1ap_DRBs_FailedToBeSetupMod_Item_PDU,
      { "DRBs-FailedToBeSetupMod-Item", "f1ap.DRBs_FailedToBeSetupMod_Item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_f1ap_DRB_Information_PDU,
      { "DRB-Information", "f1ap.DRB_Information_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_f1ap_DRBs_Modified_Item_PDU,
      { "DRBs-Modified-Item", "f1ap.DRBs_Modified_Item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_f1ap_DRBs_ModifiedConf_Item_PDU,
      { "DRBs-ModifiedConf-Item", "f1ap.DRBs_ModifiedConf_Item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_f1ap_DRB_Notify_Item_PDU,
      { "DRB-Notify-Item", "f1ap.DRB_Notify_Item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_f1ap_DRBs_Required_ToBeModified_Item_PDU,
      { "DRBs-Required-ToBeModified-Item", "f1ap.DRBs_Required_ToBeModified_Item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_f1ap_DRBs_Required_ToBeReleased_Item_PDU,
      { "DRBs-Required-ToBeReleased-Item", "f1ap.DRBs_Required_ToBeReleased_Item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_f1ap_DRBs_Setup_Item_PDU,
      { "DRBs-Setup-Item", "f1ap.DRBs_Setup_Item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_f1ap_DRBs_SetupMod_Item_PDU,
      { "DRBs-SetupMod-Item", "f1ap.DRBs_SetupMod_Item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_f1ap_DRBs_ToBeModified_Item_PDU,
      { "DRBs-ToBeModified-Item", "f1ap.DRBs_ToBeModified_Item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_f1ap_DRBs_ToBeReleased_Item_PDU,
      { "DRBs-ToBeReleased-Item", "f1ap.DRBs_ToBeReleased_Item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_f1ap_DRBs_ToBeSetup_Item_PDU,
      { "DRBs-ToBeSetup-Item", "f1ap.DRBs_ToBeSetup_Item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_f1ap_DRBs_ToBeSetupMod_Item_PDU,
      { "DRBs-ToBeSetupMod-Item", "f1ap.DRBs_ToBeSetupMod_Item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_f1ap_DRXCycle_PDU,
      { "DRXCycle", "f1ap.DRXCycle_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_f1ap_DRX_Config_PDU,
      { "DRX-Config", "f1ap.DRX_Config",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_f1ap_DRXConfigurationIndicator_PDU,
      { "DRXConfigurationIndicator", "f1ap.DRXConfigurationIndicator",
        FT_UINT32, BASE_DEC, VALS(f1ap_DRXConfigurationIndicator_vals), 0,
        NULL, HFILL }},
    { &hf_f1ap_DRX_LongCycleStartOffset_PDU,
      { "DRX-LongCycleStartOffset", "f1ap.DRX_LongCycleStartOffset",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_f1ap_DUtoCURRCContainer_PDU,
      { "DUtoCURRCContainer", "f1ap.DUtoCURRCContainer",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_f1ap_DUtoCURRCInformation_PDU,
      { "DUtoCURRCInformation", "f1ap.DUtoCURRCInformation_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_f1ap_DuplicationActivation_PDU,
      { "DuplicationActivation", "f1ap.DuplicationActivation",
        FT_UINT32, BASE_DEC, VALS(f1ap_DuplicationActivation_vals), 0,
        NULL, HFILL }},
    { &hf_f1ap_ExtendedAvailablePLMN_List_PDU,
      { "ExtendedAvailablePLMN-List", "f1ap.ExtendedAvailablePLMN_List",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_f1ap_ExtendedServedPLMNs_List_PDU,
      { "ExtendedServedPLMNs-List", "f1ap.ExtendedServedPLMNs_List",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_f1ap_ExecuteDuplication_PDU,
      { "ExecuteDuplication", "f1ap.ExecuteDuplication",
        FT_UINT32, BASE_DEC, VALS(f1ap_ExecuteDuplication_vals), 0,
        NULL, HFILL }},
    { &hf_f1ap_EUTRA_NR_CellResourceCoordinationReq_Container_PDU,
      { "EUTRA-NR-CellResourceCoordinationReq-Container", "f1ap.EUTRA_NR_CellResourceCoordinationReq_Container",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_f1ap_EUTRA_NR_CellResourceCoordinationReqAck_Container_PDU,
      { "EUTRA-NR-CellResourceCoordinationReqAck-Container", "f1ap.EUTRA_NR_CellResourceCoordinationReqAck_Container",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_f1ap_FullConfiguration_PDU,
      { "FullConfiguration", "f1ap.FullConfiguration",
        FT_UINT32, BASE_DEC, VALS(f1ap_FullConfiguration_vals), 0,
        NULL, HFILL }},
    { &hf_f1ap_CG_Config_PDU,
      { "CG-Config", "f1ap.CG_Config",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_f1ap_GNB_CUSystemInformation_PDU,
      { "GNB-CUSystemInformation", "f1ap.GNB_CUSystemInformation_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_f1ap_GNB_CU_TNL_Association_Setup_Item_PDU,
      { "GNB-CU-TNL-Association-Setup-Item", "f1ap.GNB_CU_TNL_Association_Setup_Item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_f1ap_GNB_CU_TNL_Association_Failed_To_Setup_Item_PDU,
      { "GNB-CU-TNL-Association-Failed-To-Setup-Item", "f1ap.GNB_CU_TNL_Association_Failed_To_Setup_Item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_f1ap_GNB_CU_TNL_Association_To_Add_Item_PDU,
      { "GNB-CU-TNL-Association-To-Add-Item", "f1ap.GNB_CU_TNL_Association_To_Add_Item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_f1ap_GNB_CU_TNL_Association_To_Remove_Item_PDU,
      { "GNB-CU-TNL-Association-To-Remove-Item", "f1ap.GNB_CU_TNL_Association_To_Remove_Item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_f1ap_GNB_CU_TNL_Association_To_Update_Item_PDU,
      { "GNB-CU-TNL-Association-To-Update-Item", "f1ap.GNB_CU_TNL_Association_To_Update_Item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_f1ap_GNB_CU_UE_F1AP_ID_PDU,
      { "GNB-CU-UE-F1AP-ID", "f1ap.GNB_CU_UE_F1AP_ID",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_f1ap_GNB_DU_UE_F1AP_ID_PDU,
      { "GNB-DU-UE-F1AP-ID", "f1ap.GNB_DU_UE_F1AP_ID",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_f1ap_GNB_DU_ID_PDU,
      { "GNB-DU-ID", "f1ap.GNB_DU_ID",
        FT_UINT64, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_f1ap_GNB_CU_Name_PDU,
      { "GNB-CU-Name", "f1ap.GNB_CU_Name",
        FT_STRING, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_f1ap_GNB_DU_Name_PDU,
      { "GNB-DU-Name", "f1ap.GNB_DU_Name",
        FT_STRING, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_f1ap_GNB_DU_Served_Cells_Item_PDU,
      { "GNB-DU-Served-Cells-Item", "f1ap.GNB_DU_Served_Cells_Item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_f1ap_GNB_DUConfigurationQuery_PDU,
      { "GNB-DUConfigurationQuery", "f1ap.GNB_DUConfigurationQuery",
        FT_UINT32, BASE_DEC, VALS(f1ap_GNB_DUConfigurationQuery_vals), 0,
        NULL, HFILL }},
    { &hf_f1ap_GNBDUOverloadInformation_PDU,
      { "GNBDUOverloadInformation", "f1ap.GNBDUOverloadInformation",
        FT_UINT32, BASE_DEC, VALS(f1ap_GNBDUOverloadInformation_vals), 0,
        NULL, HFILL }},
    { &hf_f1ap_GNB_DU_TNL_Association_To_Remove_Item_PDU,
      { "GNB-DU-TNL-Association-To-Remove-Item", "f1ap.GNB_DU_TNL_Association_To_Remove_Item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_f1ap_HandoverPreparationInformation_PDU,
      { "HandoverPreparationInformation", "f1ap.HandoverPreparationInformation",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_f1ap_IgnorePRACHConfiguration_PDU,
      { "IgnorePRACHConfiguration", "f1ap.IgnorePRACHConfiguration",
        FT_UINT32, BASE_DEC, VALS(f1ap_IgnorePRACHConfiguration_vals), 0,
        NULL, HFILL }},
    { &hf_f1ap_IgnoreResourceCoordinationContainer_PDU,
      { "IgnoreResourceCoordinationContainer", "f1ap.IgnoreResourceCoordinationContainer",
        FT_UINT32, BASE_DEC, VALS(f1ap_IgnoreResourceCoordinationContainer_vals), 0,
        NULL, HFILL }},
    { &hf_f1ap_InactivityMonitoringRequest_PDU,
      { "InactivityMonitoringRequest", "f1ap.InactivityMonitoringRequest",
        FT_UINT32, BASE_DEC, VALS(f1ap_InactivityMonitoringRequest_vals), 0,
        NULL, HFILL }},
    { &hf_f1ap_InactivityMonitoringResponse_PDU,
      { "InactivityMonitoringResponse", "f1ap.InactivityMonitoringResponse",
        FT_UINT32, BASE_DEC, VALS(f1ap_InactivityMonitoringResponse_vals), 0,
        NULL, HFILL }},
    { &hf_f1ap_MaskedIMEISV_PDU,
      { "MaskedIMEISV", "f1ap.MaskedIMEISV",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_f1ap_MeasGapSharingConfig_PDU,
      { "MeasGapSharingConfig", "f1ap.MeasGapSharingConfig",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_f1ap_MeasurementTimingConfiguration_PDU,
      { "MeasurementTimingConfiguration", "f1ap.MeasurementTimingConfiguration",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_f1ap_NeedforGap_PDU,
      { "NeedforGap", "f1ap.NeedforGap",
        FT_UINT32, BASE_DEC, VALS(f1ap_NeedforGap_vals), 0,
        NULL, HFILL }},
    { &hf_f1ap_NR_CGI_List_For_Restart_Item_PDU,
      { "NR-CGI-List-For-Restart-Item", "f1ap.NR_CGI_List_For_Restart_Item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_f1ap_NotificationInformation_PDU,
      { "NotificationInformation", "f1ap.NotificationInformation_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_f1ap_NRCGI_PDU,
      { "NRCGI", "f1ap.NRCGI_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_f1ap_NumberofBroadcastRequest_PDU,
      { "NumberofBroadcastRequest", "f1ap.NumberofBroadcastRequest",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_f1ap_PagingCell_Item_PDU,
      { "PagingCell-Item", "f1ap.PagingCell_Item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_f1ap_PagingDRX_PDU,
      { "PagingDRX", "f1ap.PagingDRX",
        FT_UINT32, BASE_DEC, VALS(f1ap_PagingDRX_vals), 0,
        NULL, HFILL }},
    { &hf_f1ap_PagingIdentity_PDU,
      { "PagingIdentity", "f1ap.PagingIdentity",
        FT_UINT32, BASE_DEC, VALS(f1ap_PagingIdentity_vals), 0,
        NULL, HFILL }},
    { &hf_f1ap_PagingOrigin_PDU,
      { "PagingOrigin", "f1ap.PagingOrigin",
        FT_UINT32, BASE_DEC, VALS(f1ap_PagingOrigin_vals), 0,
        NULL, HFILL }},
    { &hf_f1ap_PagingPriority_PDU,
      { "PagingPriority", "f1ap.PagingPriority",
        FT_UINT32, BASE_DEC, VALS(f1ap_PagingPriority_vals), 0,
        NULL, HFILL }},
    { &hf_f1ap_PDCCH_BlindDetectionSCG_PDU,
      { "PDCCH-BlindDetectionSCG", "f1ap.PDCCH_BlindDetectionSCG",
        FT_UINT8, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_f1ap_PDCPSNLength_PDU,
      { "PDCPSNLength", "f1ap.PDCPSNLength",
        FT_UINT32, BASE_DEC, VALS(f1ap_PDCPSNLength_vals), 0,
        NULL, HFILL }},
    { &hf_f1ap_PDUSessionID_PDU,
      { "PDUSessionID", "f1ap.PDUSessionID",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_f1ap_Ph_InfoMCG_PDU,
      { "Ph-InfoMCG", "f1ap.Ph_InfoMCG",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_f1ap_Ph_InfoSCG_PDU,
      { "Ph-InfoSCG", "f1ap.Ph_InfoSCG",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_f1ap_PLMN_Identity_PDU,
      { "PLMN-Identity", "f1ap.PLMN_Identity",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_f1ap_PortNumber_PDU,
      { "PortNumber", "f1ap.PortNumber",
        FT_UINT16, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_f1ap_Protected_EUTRA_Resources_Item_PDU,
      { "Protected-EUTRA-Resources-Item", "f1ap.Protected_EUTRA_Resources_Item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_f1ap_Potential_SpCell_Item_PDU,
      { "Potential-SpCell-Item", "f1ap.Potential_SpCell_Item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_f1ap_PWS_Failed_NR_CGI_Item_PDU,
      { "PWS-Failed-NR-CGI-Item", "f1ap.PWS_Failed_NR_CGI_Item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_f1ap_PWSSystemInformation_PDU,
      { "PWSSystemInformation", "f1ap.PWSSystemInformation_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_f1ap_QoSFlowMappingIndication_PDU,
      { "QoSFlowMappingIndication", "f1ap.QoSFlowMappingIndication",
        FT_UINT32, BASE_DEC, VALS(f1ap_QoSFlowMappingIndication_vals), 0,
        NULL, HFILL }},
    { &hf_f1ap_RANAC_PDU,
      { "RANAC", "f1ap.RANAC",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_f1ap_RANUEID_PDU,
      { "RANUEID", "f1ap.RANUEID",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_f1ap_RAT_FrequencyPriorityInformation_PDU,
      { "RAT-FrequencyPriorityInformation", "f1ap.RAT_FrequencyPriorityInformation",
        FT_UINT32, BASE_DEC, VALS(f1ap_RAT_FrequencyPriorityInformation_vals), 0,
        NULL, HFILL }},
    { &hf_f1ap_RequestedBandCombinationIndex_PDU,
      { "RequestedBandCombinationIndex", "f1ap.RequestedBandCombinationIndex",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_f1ap_RequestedFeatureSetEntryIndex_PDU,
      { "RequestedFeatureSetEntryIndex", "f1ap.RequestedFeatureSetEntryIndex",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_f1ap_Requested_PDCCH_BlindDetectionSCG_PDU,
      { "Requested-PDCCH-BlindDetectionSCG", "f1ap.Requested_PDCCH_BlindDetectionSCG",
        FT_UINT8, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_f1ap_RequestedP_MaxFR2_PDU,
      { "RequestedP-MaxFR2", "f1ap.RequestedP_MaxFR2",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_f1ap_RequestType_PDU,
      { "RequestType", "f1ap.RequestType",
        FT_UINT32, BASE_DEC, VALS(f1ap_RequestType_vals), 0,
        NULL, HFILL }},
    { &hf_f1ap_ResourceCoordinationTransferInformation_PDU,
      { "ResourceCoordinationTransferInformation", "f1ap.ResourceCoordinationTransferInformation_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_f1ap_ResourceCoordinationTransferContainer_PDU,
      { "ResourceCoordinationTransferContainer", "f1ap.ResourceCoordinationTransferContainer",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_f1ap_RepetitionPeriod_PDU,
      { "RepetitionPeriod", "f1ap.RepetitionPeriod",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_f1ap_RLCFailureIndication_PDU,
      { "RLCFailureIndication", "f1ap.RLCFailureIndication_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_f1ap_RLCMode_PDU,
      { "RLCMode", "f1ap.RLCMode",
        FT_UINT32, BASE_DEC, VALS(f1ap_RLCMode_vals), 0,
        NULL, HFILL }},
    { &hf_f1ap_RLC_Status_PDU,
      { "RLC-Status", "f1ap.RLC_Status_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_f1ap_RRCContainer_PDU,
      { "RRCContainer", "f1ap.RRCContainer",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_f1ap_RRCContainer_RRCSetupComplete_PDU,
      { "RRCContainer-RRCSetupComplete", "f1ap.RRCContainer_RRCSetupComplete",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_f1ap_RRCDeliveryStatus_PDU,
      { "RRCDeliveryStatus", "f1ap.RRCDeliveryStatus_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_f1ap_RRCDeliveryStatusRequest_PDU,
      { "RRCDeliveryStatusRequest", "f1ap.RRCDeliveryStatusRequest",
        FT_UINT32, BASE_DEC, VALS(f1ap_RRCDeliveryStatusRequest_vals), 0,
        NULL, HFILL }},
    { &hf_f1ap_RRCReconfigurationCompleteIndicator_PDU,
      { "RRCReconfigurationCompleteIndicator", "f1ap.RRCReconfigurationCompleteIndicator",
        FT_UINT32, BASE_DEC, VALS(f1ap_RRCReconfigurationCompleteIndicator_vals), 0,
        NULL, HFILL }},
    { &hf_f1ap_RRC_Version_PDU,
      { "RRC-Version", "f1ap.RRC_Version_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_f1ap_Latest_RRC_Version_Enhanced_PDU,
      { "Latest-RRC-Version-Enhanced", "f1ap.Latest_RRC_Version_Enhanced",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_f1ap_SCell_FailedtoSetup_Item_PDU,
      { "SCell-FailedtoSetup-Item", "f1ap.SCell_FailedtoSetup_Item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_f1ap_SCell_FailedtoSetupMod_Item_PDU,
      { "SCell-FailedtoSetupMod-Item", "f1ap.SCell_FailedtoSetupMod_Item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_f1ap_SCell_ToBeRemoved_Item_PDU,
      { "SCell-ToBeRemoved-Item", "f1ap.SCell_ToBeRemoved_Item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_f1ap_SCell_ToBeSetup_Item_PDU,
      { "SCell-ToBeSetup-Item", "f1ap.SCell_ToBeSetup_Item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_f1ap_SCell_ToBeSetupMod_Item_PDU,
      { "SCell-ToBeSetupMod-Item", "f1ap.SCell_ToBeSetupMod_Item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_f1ap_SelectedBandCombinationIndex_PDU,
      { "SelectedBandCombinationIndex", "f1ap.SelectedBandCombinationIndex",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_f1ap_SelectedFeatureSetEntryIndex_PDU,
      { "SelectedFeatureSetEntryIndex", "f1ap.SelectedFeatureSetEntryIndex",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_f1ap_ServCellIndex_PDU,
      { "ServCellIndex", "f1ap.ServCellIndex",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_f1ap_ServingCellMO_PDU,
      { "ServingCellMO", "f1ap.ServingCellMO",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_f1ap_Served_Cells_To_Add_Item_PDU,
      { "Served-Cells-To-Add-Item", "f1ap.Served_Cells_To_Add_Item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_f1ap_Served_Cells_To_Delete_Item_PDU,
      { "Served-Cells-To-Delete-Item", "f1ap.Served_Cells_To_Delete_Item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_f1ap_Served_Cells_To_Modify_Item_PDU,
      { "Served-Cells-To-Modify-Item", "f1ap.Served_Cells_To_Modify_Item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_f1ap_SItype_List_PDU,
      { "SItype-List", "f1ap.SItype_List",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_f1ap_SliceSupportList_PDU,
      { "SliceSupportList", "f1ap.SliceSupportList",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_f1ap_SRBID_PDU,
      { "SRBID", "f1ap.SRBID",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_f1ap_SRBs_FailedToBeSetup_Item_PDU,
      { "SRBs-FailedToBeSetup-Item", "f1ap.SRBs_FailedToBeSetup_Item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_f1ap_SRBs_FailedToBeSetupMod_Item_PDU,
      { "SRBs-FailedToBeSetupMod-Item", "f1ap.SRBs_FailedToBeSetupMod_Item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_f1ap_SRBs_Modified_Item_PDU,
      { "SRBs-Modified-Item", "f1ap.SRBs_Modified_Item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_f1ap_SRBs_Required_ToBeReleased_Item_PDU,
      { "SRBs-Required-ToBeReleased-Item", "f1ap.SRBs_Required_ToBeReleased_Item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_f1ap_SRBs_Setup_Item_PDU,
      { "SRBs-Setup-Item", "f1ap.SRBs_Setup_Item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_f1ap_SRBs_SetupMod_Item_PDU,
      { "SRBs-SetupMod-Item", "f1ap.SRBs_SetupMod_Item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_f1ap_SRBs_ToBeReleased_Item_PDU,
      { "SRBs-ToBeReleased-Item", "f1ap.SRBs_ToBeReleased_Item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_f1ap_SRBs_ToBeSetup_Item_PDU,
      { "SRBs-ToBeSetup-Item", "f1ap.SRBs_ToBeSetup_Item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_f1ap_SRBs_ToBeSetupMod_Item_PDU,
      { "SRBs-ToBeSetupMod-Item", "f1ap.SRBs_ToBeSetupMod_Item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_f1ap_SULAccessIndication_PDU,
      { "SULAccessIndication", "f1ap.SULAccessIndication",
        FT_UINT32, BASE_DEC, VALS(f1ap_SULAccessIndication_vals), 0,
        NULL, HFILL }},
    { &hf_f1ap_SystemInformationAreaID_PDU,
      { "SystemInformationAreaID", "f1ap.SystemInformationAreaID",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_f1ap_TimeToWait_PDU,
      { "TimeToWait", "f1ap.TimeToWait",
        FT_UINT32, BASE_DEC, VALS(f1ap_TimeToWait_vals), 0,
        NULL, HFILL }},
    { &hf_f1ap_TransactionID_PDU,
      { "TransactionID", "f1ap.TransactionID",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_f1ap_TransmissionActionIndicator_PDU,
      { "TransmissionActionIndicator", "f1ap.TransmissionActionIndicator",
        FT_UINT32, BASE_DEC, VALS(f1ap_TransmissionActionIndicator_vals), 0,
        NULL, HFILL }},
    { &hf_f1ap_UAC_Assistance_Info_PDU,
      { "UAC-Assistance-Info", "f1ap.UAC_Assistance_Info_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_f1ap_UE_associatedLogicalF1_ConnectionItem_PDU,
      { "UE-associatedLogicalF1-ConnectionItem", "f1ap.UE_associatedLogicalF1_ConnectionItem_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_f1ap_UEAssistanceInformation_PDU,
      { "UEAssistanceInformation", "f1ap.UEAssistanceInformation",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_f1ap_UEContextNotRetrievable_PDU,
      { "UEContextNotRetrievable", "f1ap.UEContextNotRetrievable",
        FT_UINT32, BASE_DEC, VALS(f1ap_UEContextNotRetrievable_vals), 0,
        NULL, HFILL }},
    { &hf_f1ap_UEIdentityIndexValue_PDU,
      { "UEIdentityIndexValue", "f1ap.UEIdentityIndexValue",
        FT_UINT32, BASE_DEC, VALS(f1ap_UEIdentityIndexValue_vals), 0,
        NULL, HFILL }},
    { &hf_f1ap_UplinkTxDirectCurrentListInformation_PDU,
      { "UplinkTxDirectCurrentListInformation", "f1ap.UplinkTxDirectCurrentListInformation",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_f1ap_Reset_PDU,
      { "Reset", "f1ap.Reset_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_f1ap_ResetType_PDU,
      { "ResetType", "f1ap.ResetType",
        FT_UINT32, BASE_DEC, VALS(f1ap_ResetType_vals), 0,
        NULL, HFILL }},
    { &hf_f1ap_ResetAcknowledge_PDU,
      { "ResetAcknowledge", "f1ap.ResetAcknowledge_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_f1ap_UE_associatedLogicalF1_ConnectionListResAck_PDU,
      { "UE-associatedLogicalF1-ConnectionListResAck", "f1ap.UE_associatedLogicalF1_ConnectionListResAck",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_f1ap_ErrorIndication_PDU,
      { "ErrorIndication", "f1ap.ErrorIndication_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_f1ap_F1SetupRequest_PDU,
      { "F1SetupRequest", "f1ap.F1SetupRequest_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_f1ap_GNB_DU_Served_Cells_List_PDU,
      { "GNB-DU-Served-Cells-List", "f1ap.GNB_DU_Served_Cells_List",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_f1ap_F1SetupResponse_PDU,
      { "F1SetupResponse", "f1ap.F1SetupResponse_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_f1ap_Cells_to_be_Activated_List_PDU,
      { "Cells-to-be-Activated-List", "f1ap.Cells_to_be_Activated_List",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_f1ap_F1SetupFailure_PDU,
      { "F1SetupFailure", "f1ap.F1SetupFailure_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_f1ap_GNBDUConfigurationUpdate_PDU,
      { "GNBDUConfigurationUpdate", "f1ap.GNBDUConfigurationUpdate_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_f1ap_Served_Cells_To_Add_List_PDU,
      { "Served-Cells-To-Add-List", "f1ap.Served_Cells_To_Add_List",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_f1ap_Served_Cells_To_Modify_List_PDU,
      { "Served-Cells-To-Modify-List", "f1ap.Served_Cells_To_Modify_List",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_f1ap_Served_Cells_To_Delete_List_PDU,
      { "Served-Cells-To-Delete-List", "f1ap.Served_Cells_To_Delete_List",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_f1ap_Cells_Status_List_PDU,
      { "Cells-Status-List", "f1ap.Cells_Status_List",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_f1ap_Dedicated_SIDelivery_NeededUE_List_PDU,
      { "Dedicated-SIDelivery-NeededUE-List", "f1ap.Dedicated_SIDelivery_NeededUE_List",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_f1ap_GNB_DU_TNL_Association_To_Remove_List_PDU,
      { "GNB-DU-TNL-Association-To-Remove-List", "f1ap.GNB_DU_TNL_Association_To_Remove_List",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_f1ap_GNBDUConfigurationUpdateAcknowledge_PDU,
      { "GNBDUConfigurationUpdateAcknowledge", "f1ap.GNBDUConfigurationUpdateAcknowledge_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_f1ap_GNBDUConfigurationUpdateFailure_PDU,
      { "GNBDUConfigurationUpdateFailure", "f1ap.GNBDUConfigurationUpdateFailure_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_f1ap_GNBCUConfigurationUpdate_PDU,
      { "GNBCUConfigurationUpdate", "f1ap.GNBCUConfigurationUpdate_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_f1ap_Cells_to_be_Deactivated_List_PDU,
      { "Cells-to-be-Deactivated-List", "f1ap.Cells_to_be_Deactivated_List",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_f1ap_GNB_CU_TNL_Association_To_Add_List_PDU,
      { "GNB-CU-TNL-Association-To-Add-List", "f1ap.GNB_CU_TNL_Association_To_Add_List",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_f1ap_GNB_CU_TNL_Association_To_Remove_List_PDU,
      { "GNB-CU-TNL-Association-To-Remove-List", "f1ap.GNB_CU_TNL_Association_To_Remove_List",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_f1ap_GNB_CU_TNL_Association_To_Update_List_PDU,
      { "GNB-CU-TNL-Association-To-Update-List", "f1ap.GNB_CU_TNL_Association_To_Update_List",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_f1ap_Cells_to_be_Barred_List_PDU,
      { "Cells-to-be-Barred-List", "f1ap.Cells_to_be_Barred_List",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_f1ap_Protected_EUTRA_Resources_List_PDU,
      { "Protected-EUTRA-Resources-List", "f1ap.Protected_EUTRA_Resources_List",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_f1ap_GNBCUConfigurationUpdateAcknowledge_PDU,
      { "GNBCUConfigurationUpdateAcknowledge", "f1ap.GNBCUConfigurationUpdateAcknowledge_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_f1ap_Cells_Failed_to_be_Activated_List_PDU,
      { "Cells-Failed-to-be-Activated-List", "f1ap.Cells_Failed_to_be_Activated_List",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_f1ap_GNB_CU_TNL_Association_Setup_List_PDU,
      { "GNB-CU-TNL-Association-Setup-List", "f1ap.GNB_CU_TNL_Association_Setup_List",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_f1ap_GNB_CU_TNL_Association_Failed_To_Setup_List_PDU,
      { "GNB-CU-TNL-Association-Failed-To-Setup-List", "f1ap.GNB_CU_TNL_Association_Failed_To_Setup_List",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_f1ap_GNBCUConfigurationUpdateFailure_PDU,
      { "GNBCUConfigurationUpdateFailure", "f1ap.GNBCUConfigurationUpdateFailure_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_f1ap_GNBDUResourceCoordinationRequest_PDU,
      { "GNBDUResourceCoordinationRequest", "f1ap.GNBDUResourceCoordinationRequest_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_f1ap_GNBDUResourceCoordinationResponse_PDU,
      { "GNBDUResourceCoordinationResponse", "f1ap.GNBDUResourceCoordinationResponse_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_f1ap_UEContextSetupRequest_PDU,
      { "UEContextSetupRequest", "f1ap.UEContextSetupRequest_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_f1ap_Candidate_SpCell_List_PDU,
      { "Candidate-SpCell-List", "f1ap.Candidate_SpCell_List",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_f1ap_SCell_ToBeSetup_List_PDU,
      { "SCell-ToBeSetup-List", "f1ap.SCell_ToBeSetup_List",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_f1ap_SRBs_ToBeSetup_List_PDU,
      { "SRBs-ToBeSetup-List", "f1ap.SRBs_ToBeSetup_List",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_f1ap_DRBs_ToBeSetup_List_PDU,
      { "DRBs-ToBeSetup-List", "f1ap.DRBs_ToBeSetup_List",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_f1ap_UEContextSetupResponse_PDU,
      { "UEContextSetupResponse", "f1ap.UEContextSetupResponse_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_f1ap_DRBs_Setup_List_PDU,
      { "DRBs-Setup-List", "f1ap.DRBs_Setup_List",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_f1ap_SRBs_FailedToBeSetup_List_PDU,
      { "SRBs-FailedToBeSetup-List", "f1ap.SRBs_FailedToBeSetup_List",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_f1ap_DRBs_FailedToBeSetup_List_PDU,
      { "DRBs-FailedToBeSetup-List", "f1ap.DRBs_FailedToBeSetup_List",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_f1ap_SCell_FailedtoSetup_List_PDU,
      { "SCell-FailedtoSetup-List", "f1ap.SCell_FailedtoSetup_List",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_f1ap_SRBs_Setup_List_PDU,
      { "SRBs-Setup-List", "f1ap.SRBs_Setup_List",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_f1ap_UEContextSetupFailure_PDU,
      { "UEContextSetupFailure", "f1ap.UEContextSetupFailure_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_f1ap_Potential_SpCell_List_PDU,
      { "Potential-SpCell-List", "f1ap.Potential_SpCell_List",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_f1ap_UEContextReleaseRequest_PDU,
      { "UEContextReleaseRequest", "f1ap.UEContextReleaseRequest_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_f1ap_UEContextReleaseCommand_PDU,
      { "UEContextReleaseCommand", "f1ap.UEContextReleaseCommand_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_f1ap_UEContextReleaseComplete_PDU,
      { "UEContextReleaseComplete", "f1ap.UEContextReleaseComplete_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_f1ap_UEContextModificationRequest_PDU,
      { "UEContextModificationRequest", "f1ap.UEContextModificationRequest_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_f1ap_SCell_ToBeSetupMod_List_PDU,
      { "SCell-ToBeSetupMod-List", "f1ap.SCell_ToBeSetupMod_List",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_f1ap_SCell_ToBeRemoved_List_PDU,
      { "SCell-ToBeRemoved-List", "f1ap.SCell_ToBeRemoved_List",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_f1ap_SRBs_ToBeSetupMod_List_PDU,
      { "SRBs-ToBeSetupMod-List", "f1ap.SRBs_ToBeSetupMod_List",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_f1ap_DRBs_ToBeSetupMod_List_PDU,
      { "DRBs-ToBeSetupMod-List", "f1ap.DRBs_ToBeSetupMod_List",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_f1ap_DRBs_ToBeModified_List_PDU,
      { "DRBs-ToBeModified-List", "f1ap.DRBs_ToBeModified_List",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_f1ap_SRBs_ToBeReleased_List_PDU,
      { "SRBs-ToBeReleased-List", "f1ap.SRBs_ToBeReleased_List",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_f1ap_DRBs_ToBeReleased_List_PDU,
      { "DRBs-ToBeReleased-List", "f1ap.DRBs_ToBeReleased_List",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_f1ap_UEContextModificationResponse_PDU,
      { "UEContextModificationResponse", "f1ap.UEContextModificationResponse_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_f1ap_DRBs_SetupMod_List_PDU,
      { "DRBs-SetupMod-List", "f1ap.DRBs_SetupMod_List",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_f1ap_DRBs_Modified_List_PDU,
      { "DRBs-Modified-List", "f1ap.DRBs_Modified_List",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_f1ap_SRBs_SetupMod_List_PDU,
      { "SRBs-SetupMod-List", "f1ap.SRBs_SetupMod_List",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_f1ap_SRBs_Modified_List_PDU,
      { "SRBs-Modified-List", "f1ap.SRBs_Modified_List",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_f1ap_DRBs_FailedToBeModified_List_PDU,
      { "DRBs-FailedToBeModified-List", "f1ap.DRBs_FailedToBeModified_List",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_f1ap_SRBs_FailedToBeSetupMod_List_PDU,
      { "SRBs-FailedToBeSetupMod-List", "f1ap.SRBs_FailedToBeSetupMod_List",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_f1ap_DRBs_FailedToBeSetupMod_List_PDU,
      { "DRBs-FailedToBeSetupMod-List", "f1ap.DRBs_FailedToBeSetupMod_List",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_f1ap_SCell_FailedtoSetupMod_List_PDU,
      { "SCell-FailedtoSetupMod-List", "f1ap.SCell_FailedtoSetupMod_List",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_f1ap_Associated_SCell_List_PDU,
      { "Associated-SCell-List", "f1ap.Associated_SCell_List",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_f1ap_UEContextModificationFailure_PDU,
      { "UEContextModificationFailure", "f1ap.UEContextModificationFailure_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_f1ap_UEContextModificationRequired_PDU,
      { "UEContextModificationRequired", "f1ap.UEContextModificationRequired_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_f1ap_DRBs_Required_ToBeModified_List_PDU,
      { "DRBs-Required-ToBeModified-List", "f1ap.DRBs_Required_ToBeModified_List",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_f1ap_DRBs_Required_ToBeReleased_List_PDU,
      { "DRBs-Required-ToBeReleased-List", "f1ap.DRBs_Required_ToBeReleased_List",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_f1ap_SRBs_Required_ToBeReleased_List_PDU,
      { "SRBs-Required-ToBeReleased-List", "f1ap.SRBs_Required_ToBeReleased_List",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_f1ap_UEContextModificationConfirm_PDU,
      { "UEContextModificationConfirm", "f1ap.UEContextModificationConfirm_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_f1ap_DRBs_ModifiedConf_List_PDU,
      { "DRBs-ModifiedConf-List", "f1ap.DRBs_ModifiedConf_List",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_f1ap_UEContextModificationRefuse_PDU,
      { "UEContextModificationRefuse", "f1ap.UEContextModificationRefuse_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_f1ap_WriteReplaceWarningRequest_PDU,
      { "WriteReplaceWarningRequest", "f1ap.WriteReplaceWarningRequest_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_f1ap_Cells_To_Be_Broadcast_List_PDU,
      { "Cells-To-Be-Broadcast-List", "f1ap.Cells_To_Be_Broadcast_List",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_f1ap_WriteReplaceWarningResponse_PDU,
      { "WriteReplaceWarningResponse", "f1ap.WriteReplaceWarningResponse_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_f1ap_Cells_Broadcast_Completed_List_PDU,
      { "Cells-Broadcast-Completed-List", "f1ap.Cells_Broadcast_Completed_List",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_f1ap_PWSCancelRequest_PDU,
      { "PWSCancelRequest", "f1ap.PWSCancelRequest_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_f1ap_Broadcast_To_Be_Cancelled_List_PDU,
      { "Broadcast-To-Be-Cancelled-List", "f1ap.Broadcast_To_Be_Cancelled_List",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_f1ap_PWSCancelResponse_PDU,
      { "PWSCancelResponse", "f1ap.PWSCancelResponse_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_f1ap_Cells_Broadcast_Cancelled_List_PDU,
      { "Cells-Broadcast-Cancelled-List", "f1ap.Cells_Broadcast_Cancelled_List",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_f1ap_UEInactivityNotification_PDU,
      { "UEInactivityNotification", "f1ap.UEInactivityNotification_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_f1ap_DRB_Activity_List_PDU,
      { "DRB-Activity-List", "f1ap.DRB_Activity_List",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_f1ap_InitialULRRCMessageTransfer_PDU,
      { "InitialULRRCMessageTransfer", "f1ap.InitialULRRCMessageTransfer_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_f1ap_DLRRCMessageTransfer_PDU,
      { "DLRRCMessageTransfer", "f1ap.DLRRCMessageTransfer_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_f1ap_RedirectedRRCmessage_PDU,
      { "RedirectedRRCmessage", "f1ap.RedirectedRRCmessage",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_f1ap_ULRRCMessageTransfer_PDU,
      { "ULRRCMessageTransfer", "f1ap.ULRRCMessageTransfer_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_f1ap_PrivateMessage_PDU,
      { "PrivateMessage", "f1ap.PrivateMessage_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_f1ap_SystemInformationDeliveryCommand_PDU,
      { "SystemInformationDeliveryCommand", "f1ap.SystemInformationDeliveryCommand_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_f1ap_Paging_PDU,
      { "Paging", "f1ap.Paging_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_f1ap_PagingCell_list_PDU,
      { "PagingCell-list", "f1ap.PagingCell_list",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_f1ap_Notify_PDU,
      { "Notify", "f1ap.Notify_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_f1ap_DRB_Notify_List_PDU,
      { "DRB-Notify-List", "f1ap.DRB_Notify_List",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_f1ap_NetworkAccessRateReduction_PDU,
      { "NetworkAccessRateReduction", "f1ap.NetworkAccessRateReduction_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_f1ap_PWSRestartIndication_PDU,
      { "PWSRestartIndication", "f1ap.PWSRestartIndication_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_f1ap_NR_CGI_List_For_Restart_List_PDU,
      { "NR-CGI-List-For-Restart-List", "f1ap.NR_CGI_List_For_Restart_List",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_f1ap_PWSFailureIndication_PDU,
      { "PWSFailureIndication", "f1ap.PWSFailureIndication_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_f1ap_PWS_Failed_NR_CGI_List_PDU,
      { "PWS-Failed-NR-CGI-List", "f1ap.PWS_Failed_NR_CGI_List",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_f1ap_GNBDUStatusIndication_PDU,
      { "GNBDUStatusIndication", "f1ap.GNBDUStatusIndication_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_f1ap_RRCDeliveryReport_PDU,
      { "RRCDeliveryReport", "f1ap.RRCDeliveryReport_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_f1ap_F1RemovalRequest_PDU,
      { "F1RemovalRequest", "f1ap.F1RemovalRequest_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_f1ap_F1RemovalResponse_PDU,
      { "F1RemovalResponse", "f1ap.F1RemovalResponse_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_f1ap_F1RemovalFailure_PDU,
      { "F1RemovalFailure", "f1ap.F1RemovalFailure_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_f1ap_F1AP_PDU_PDU,
      { "F1AP-PDU", "f1ap.F1AP_PDU",
        FT_UINT32, BASE_DEC, VALS(f1ap_F1AP_PDU_vals), 0,
        NULL, HFILL }},
    { &hf_f1ap_local,
      { "local", "f1ap.local",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_65535", HFILL }},
    { &hf_f1ap_global,
      { "global", "f1ap.global",
        FT_OID, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_f1ap_ProtocolIE_Container_item,
      { "ProtocolIE-Field", "f1ap.ProtocolIE_Field_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_f1ap_id,
      { "id", "f1ap.id",
        FT_UINT32, BASE_DEC|BASE_EXT_STRING, &f1ap_ProtocolIE_ID_vals_ext, 0,
        "ProtocolIE_ID", HFILL }},
    { &hf_f1ap_criticality,
      { "criticality", "f1ap.criticality",
        FT_UINT32, BASE_DEC, VALS(f1ap_Criticality_vals), 0,
        NULL, HFILL }},
    { &hf_f1ap_ie_field_value,
      { "value", "f1ap.value_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "T_ie_field_value", HFILL }},
    { &hf_f1ap_ProtocolExtensionContainer_item,
      { "ProtocolExtensionField", "f1ap.ProtocolExtensionField_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_f1ap_ext_id,
      { "id", "f1ap.id",
        FT_UINT32, BASE_DEC, NULL, 0,
        "ProtocolExtensionID", HFILL }},
    { &hf_f1ap_extensionValue,
      { "extensionValue", "f1ap.extensionValue_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_f1ap_PrivateIE_Container_item,
      { "PrivateIE-Field", "f1ap.PrivateIE_Field_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_f1ap_private_id,
      { "id", "f1ap.id",
        FT_UINT32, BASE_DEC, VALS(f1ap_PrivateIE_ID_vals), 0,
        "PrivateIE_ID", HFILL }},
    { &hf_f1ap_value,
      { "value", "f1ap.value_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_f1ap_AdditionalSIBMessageList_item,
      { "AdditionalSIBMessageList-Item", "f1ap.AdditionalSIBMessageList_Item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_f1ap_additionalSIB,
      { "additionalSIB", "f1ap.additionalSIB",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_f1ap_iE_Extensions,
      { "iE-Extensions", "f1ap.iE_Extensions",
        FT_UINT32, BASE_DEC, NULL, 0,
        "ProtocolExtensionContainer", HFILL }},
    { &hf_f1ap_priorityLevel,
      { "priorityLevel", "f1ap.priorityLevel",
        FT_UINT32, BASE_DEC, VALS(f1ap_PriorityLevel_vals), 0,
        NULL, HFILL }},
    { &hf_f1ap_pre_emptionCapability,
      { "pre-emptionCapability", "f1ap.pre_emptionCapability",
        FT_UINT32, BASE_DEC, VALS(f1ap_Pre_emptionCapability_vals), 0,
        NULL, HFILL }},
    { &hf_f1ap_pre_emptionVulnerability,
      { "pre-emptionVulnerability", "f1ap.pre_emptionVulnerability",
        FT_UINT32, BASE_DEC, VALS(f1ap_Pre_emptionVulnerability_vals), 0,
        NULL, HFILL }},
    { &hf_f1ap_sCell_ID,
      { "sCell-ID", "f1ap.sCell_ID_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "NRCGI", HFILL }},
    { &hf_f1ap_AvailablePLMNList_item,
      { "AvailablePLMNList-Item", "f1ap.AvailablePLMNList_Item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_f1ap_pLMNIdentity,
      { "pLMNIdentity", "f1ap.pLMNIdentity",
        FT_BYTES, BASE_NONE, NULL, 0,
        "PLMN_Identity", HFILL }},
    { &hf_f1ap_BPLMN_ID_Info_List_item,
      { "BPLMN-ID-Info-Item", "f1ap.BPLMN_ID_Info_Item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_f1ap_pLMN_Identity_List,
      { "pLMN-Identity-List", "f1ap.pLMN_Identity_List",
        FT_UINT32, BASE_DEC, NULL, 0,
        "AvailablePLMNList", HFILL }},
    { &hf_f1ap_extended_PLMN_Identity_List,
      { "extended-PLMN-Identity-List", "f1ap.extended_PLMN_Identity_List",
        FT_UINT32, BASE_DEC, NULL, 0,
        "ExtendedAvailablePLMN_List", HFILL }},
    { &hf_f1ap_fiveGS_TAC,
      { "fiveGS-TAC", "f1ap.fiveGS_TAC",
        FT_UINT24, BASE_DEC_HEX, NULL, 0,
        NULL, HFILL }},
    { &hf_f1ap_nr_cell_ID,
      { "nr-cell-ID", "f1ap.nr_cell_ID",
        FT_BYTES, BASE_NONE, NULL, 0,
        "NRCellIdentity", HFILL }},
    { &hf_f1ap_ranac,
      { "ranac", "f1ap.ranac",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_f1ap_ServedPLMNs_List_item,
      { "ServedPLMNs-Item", "f1ap.ServedPLMNs_Item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_f1ap_pLMN_Identity,
      { "pLMN-Identity", "f1ap.pLMN_Identity",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_f1ap_candidate_SpCell_ID,
      { "candidate-SpCell-ID", "f1ap.candidate_SpCell_ID_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "NRCGI", HFILL }},
    { &hf_f1ap_radioNetwork,
      { "radioNetwork", "f1ap.radioNetwork",
        FT_UINT32, BASE_DEC, VALS(f1ap_CauseRadioNetwork_vals), 0,
        "CauseRadioNetwork", HFILL }},
    { &hf_f1ap_transport,
      { "transport", "f1ap.transport",
        FT_UINT32, BASE_DEC, VALS(f1ap_CauseTransport_vals), 0,
        "CauseTransport", HFILL }},
    { &hf_f1ap_protocol,
      { "protocol", "f1ap.protocol",
        FT_UINT32, BASE_DEC, VALS(f1ap_CauseProtocol_vals), 0,
        "CauseProtocol", HFILL }},
    { &hf_f1ap_misc,
      { "misc", "f1ap.misc",
        FT_UINT32, BASE_DEC, VALS(f1ap_CauseMisc_vals), 0,
        "CauseMisc", HFILL }},
    { &hf_f1ap_choice_extension,
      { "choice-extension", "f1ap.choice_extension_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "ProtocolIE_SingleContainer", HFILL }},
    { &hf_f1ap_nRCGI,
      { "nRCGI", "f1ap.nRCGI_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_f1ap_cause,
      { "cause", "f1ap.cause",
        FT_UINT32, BASE_DEC, VALS(f1ap_Cause_vals), 0,
        NULL, HFILL }},
    { &hf_f1ap_service_status,
      { "service-status", "f1ap.service_status_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_f1ap_numberOfBroadcasts,
      { "numberOfBroadcasts", "f1ap.numberOfBroadcasts",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_f1ap_nRPCI,
      { "nRPCI", "f1ap.nRPCI",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_f1ap_cellBarred,
      { "cellBarred", "f1ap.cellBarred",
        FT_UINT32, BASE_DEC, VALS(f1ap_CellBarred_vals), 0,
        NULL, HFILL }},
    { &hf_f1ap_cellSize,
      { "cellSize", "f1ap.cellSize",
        FT_UINT32, BASE_DEC, VALS(f1ap_CellSize_vals), 0,
        NULL, HFILL }},
    { &hf_f1ap_fiveG_S_TMSI,
      { "fiveG-S-TMSI", "f1ap.fiveG_S_TMSI",
        FT_BYTES, BASE_NONE, NULL, 0,
        "BIT_STRING_SIZE_48", HFILL }},
    { &hf_f1ap_endpoint_IP_address,
      { "endpoint-IP-address", "f1ap.endpoint_IP_address",
        FT_BYTES, BASE_NONE, NULL, 0,
        "TransportLayerAddress", HFILL }},
    { &hf_f1ap_endpoint_IP_address_and_port,
      { "endpoint-IP-address-and-port", "f1ap.endpoint_IP_address_and_port_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_f1ap_procedureCode,
      { "procedureCode", "f1ap.procedureCode",
        FT_UINT32, BASE_DEC|BASE_EXT_STRING, &f1ap_ProcedureCode_vals_ext, 0,
        NULL, HFILL }},
    { &hf_f1ap_triggeringMessage,
      { "triggeringMessage", "f1ap.triggeringMessage",
        FT_UINT32, BASE_DEC, VALS(f1ap_TriggeringMessage_vals), 0,
        NULL, HFILL }},
    { &hf_f1ap_procedureCriticality,
      { "procedureCriticality", "f1ap.procedureCriticality",
        FT_UINT32, BASE_DEC, VALS(f1ap_Criticality_vals), 0,
        "Criticality", HFILL }},
    { &hf_f1ap_transactionID,
      { "transactionID", "f1ap.transactionID",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_f1ap_iEsCriticalityDiagnostics,
      { "iEsCriticalityDiagnostics", "f1ap.iEsCriticalityDiagnostics",
        FT_UINT32, BASE_DEC, NULL, 0,
        "CriticalityDiagnostics_IE_List", HFILL }},
    { &hf_f1ap_CriticalityDiagnostics_IE_List_item,
      { "CriticalityDiagnostics-IE-Item", "f1ap.CriticalityDiagnostics_IE_Item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_f1ap_iECriticality,
      { "iECriticality", "f1ap.iECriticality",
        FT_UINT32, BASE_DEC, VALS(f1ap_Criticality_vals), 0,
        "Criticality", HFILL }},
    { &hf_f1ap_iE_ID,
      { "iE-ID", "f1ap.iE_ID",
        FT_UINT32, BASE_DEC|BASE_EXT_STRING, &f1ap_ProtocolIE_ID_vals_ext, 0,
        "ProtocolIE_ID", HFILL }},
    { &hf_f1ap_typeOfError,
      { "typeOfError", "f1ap.typeOfError",
        FT_UINT32, BASE_DEC, VALS(f1ap_TypeOfError_vals), 0,
        NULL, HFILL }},
    { &hf_f1ap_cG_ConfigInfo,
      { "cG-ConfigInfo", "f1ap.cG_ConfigInfo",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_f1ap_uE_CapabilityRAT_ContainerList,
      { "uE-CapabilityRAT-ContainerList", "f1ap.uE_CapabilityRAT_ContainerList",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_f1ap_measConfig,
      { "measConfig", "f1ap.measConfig",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_f1ap_gNB_CU_UE_F1AP_ID,
      { "gNB-CU-UE-F1AP-ID", "f1ap.gNB_CU_UE_F1AP_ID",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_f1ap_DLUPTNLInformation_ToBeSetup_List_item,
      { "DLUPTNLInformation-ToBeSetup-Item", "f1ap.DLUPTNLInformation_ToBeSetup_Item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_f1ap_dLUPTNLInformation,
      { "dLUPTNLInformation", "f1ap.dLUPTNLInformation",
        FT_UINT32, BASE_DEC, VALS(f1ap_UPTransportLayerInformation_vals), 0,
        "UPTransportLayerInformation", HFILL }},
    { &hf_f1ap_dRBID,
      { "dRBID", "f1ap.dRBID",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_f1ap_dRB_Activity,
      { "dRB-Activity", "f1ap.dRB_Activity",
        FT_UINT32, BASE_DEC, VALS(f1ap_DRB_Activity_vals), 0,
        NULL, HFILL }},
    { &hf_f1ap_dRB_QoS,
      { "dRB-QoS", "f1ap.dRB_QoS_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "QoSFlowLevelQoSParameters", HFILL }},
    { &hf_f1ap_sNSSAI,
      { "sNSSAI", "f1ap.sNSSAI_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_f1ap_notificationControl,
      { "notificationControl", "f1ap.notificationControl",
        FT_UINT32, BASE_DEC, VALS(f1ap_NotificationControl_vals), 0,
        NULL, HFILL }},
    { &hf_f1ap_flows_Mapped_To_DRB_List,
      { "flows-Mapped-To-DRB-List", "f1ap.flows_Mapped_To_DRB_List",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_f1ap_lCID,
      { "lCID", "f1ap.lCID",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_f1ap_dLUPTNLInformation_ToBeSetup_List,
      { "dLUPTNLInformation-ToBeSetup-List", "f1ap.dLUPTNLInformation_ToBeSetup_List",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_f1ap_uLUPTNLInformation_ToBeSetup_List,
      { "uLUPTNLInformation-ToBeSetup-List", "f1ap.uLUPTNLInformation_ToBeSetup_List",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_f1ap_notification_Cause,
      { "notification-Cause", "f1ap.notification_Cause",
        FT_UINT32, BASE_DEC, VALS(f1ap_Notification_Cause_vals), 0,
        NULL, HFILL }},
    { &hf_f1ap_qoSInformation,
      { "qoSInformation", "f1ap.qoSInformation",
        FT_UINT32, BASE_DEC, VALS(f1ap_QoSInformation_vals), 0,
        NULL, HFILL }},
    { &hf_f1ap_uLConfiguration,
      { "uLConfiguration", "f1ap.uLConfiguration_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_f1ap_rLCMode,
      { "rLCMode", "f1ap.rLCMode",
        FT_UINT32, BASE_DEC, VALS(f1ap_RLCMode_vals), 0,
        NULL, HFILL }},
    { &hf_f1ap_duplicationActivation,
      { "duplicationActivation", "f1ap.duplicationActivation",
        FT_UINT32, BASE_DEC, VALS(f1ap_DuplicationActivation_vals), 0,
        NULL, HFILL }},
    { &hf_f1ap_longDRXCycleLength,
      { "longDRXCycleLength", "f1ap.longDRXCycleLength",
        FT_UINT32, BASE_DEC|BASE_EXT_STRING, &f1ap_LongDRXCycleLength_vals_ext, 0,
        NULL, HFILL }},
    { &hf_f1ap_shortDRXCycleLength,
      { "shortDRXCycleLength", "f1ap.shortDRXCycleLength",
        FT_UINT32, BASE_DEC|BASE_EXT_STRING, &f1ap_ShortDRXCycleLength_vals_ext, 0,
        NULL, HFILL }},
    { &hf_f1ap_shortDRXCycleTimer,
      { "shortDRXCycleTimer", "f1ap.shortDRXCycleTimer",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_f1ap_cellGroupConfig,
      { "cellGroupConfig", "f1ap.cellGroupConfig",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_f1ap_measGapConfig,
      { "measGapConfig", "f1ap.measGapConfig",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_f1ap_requestedP_MaxFR1,
      { "requestedP-MaxFR1", "f1ap.requestedP_MaxFR1",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_f1ap_qoSPriorityLevel,
      { "qoSPriorityLevel", "f1ap.qoSPriorityLevel",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_1_127", HFILL }},
    { &hf_f1ap_packetDelayBudget,
      { "packetDelayBudget", "f1ap.packetDelayBudget",
        FT_UINT32, BASE_CUSTOM, CF_FUNC(f1ap_PacketDelayBudget_fmt), 0,
        NULL, HFILL }},
    { &hf_f1ap_packetErrorRate,
      { "packetErrorRate", "f1ap.packetErrorRate_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_f1ap_fiveQI,
      { "fiveQI", "f1ap.fiveQI",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_255_", HFILL }},
    { &hf_f1ap_delayCritical,
      { "delayCritical", "f1ap.delayCritical",
        FT_UINT32, BASE_DEC, VALS(f1ap_T_delayCritical_vals), 0,
        NULL, HFILL }},
    { &hf_f1ap_averagingWindow,
      { "averagingWindow", "f1ap.averagingWindow",
        FT_UINT32, BASE_DEC|BASE_UNIT_STRING, &units_milliseconds, 0,
        NULL, HFILL }},
    { &hf_f1ap_maxDataBurstVolume,
      { "maxDataBurstVolume", "f1ap.maxDataBurstVolume",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_f1ap_endpointIPAddress,
      { "endpointIPAddress", "f1ap.endpointIPAddress",
        FT_BYTES, BASE_NONE, NULL, 0,
        "TransportLayerAddress", HFILL }},
    { &hf_f1ap_ExtendedAvailablePLMN_List_item,
      { "ExtendedAvailablePLMN-Item", "f1ap.ExtendedAvailablePLMN_Item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_f1ap_ExtendedServedPLMNs_List_item,
      { "ExtendedServedPLMNs-Item", "f1ap.ExtendedServedPLMNs_Item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_f1ap_tAISliceSupportList,
      { "tAISliceSupportList", "f1ap.tAISliceSupportList",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SliceSupportList", HFILL }},
    { &hf_f1ap_EUTRACells_List_item,
      { "EUTRACells-List-item", "f1ap.EUTRACells_List_item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_f1ap_eUTRA_Cell_ID,
      { "eUTRA-Cell-ID", "f1ap.eUTRA_Cell_ID",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_f1ap_served_EUTRA_Cells_Information,
      { "served-EUTRA-Cells-Information", "f1ap.served_EUTRA_Cells_Information_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_f1ap_uL_EARFCN,
      { "uL-EARFCN", "f1ap.uL_EARFCN",
        FT_UINT32, BASE_DEC, NULL, 0,
        "ExtendedEARFCN", HFILL }},
    { &hf_f1ap_dL_EARFCN,
      { "dL-EARFCN", "f1ap.dL_EARFCN",
        FT_UINT32, BASE_DEC, NULL, 0,
        "ExtendedEARFCN", HFILL }},
    { &hf_f1ap_uL_Transmission_Bandwidth,
      { "uL-Transmission-Bandwidth", "f1ap.uL_Transmission_Bandwidth",
        FT_UINT32, BASE_DEC, VALS(f1ap_EUTRA_Transmission_Bandwidth_vals), 0,
        "EUTRA_Transmission_Bandwidth", HFILL }},
    { &hf_f1ap_dL_Transmission_Bandwidth,
      { "dL-Transmission-Bandwidth", "f1ap.dL_Transmission_Bandwidth",
        FT_UINT32, BASE_DEC, VALS(f1ap_EUTRA_Transmission_Bandwidth_vals), 0,
        "EUTRA_Transmission_Bandwidth", HFILL }},
    { &hf_f1ap_fDD,
      { "fDD", "f1ap.fDD_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "EUTRA_Coex_FDD_Info", HFILL }},
    { &hf_f1ap_tDD,
      { "tDD", "f1ap.tDD_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "EUTRA_Coex_TDD_Info", HFILL }},
    { &hf_f1ap_eARFCN,
      { "eARFCN", "f1ap.eARFCN",
        FT_UINT32, BASE_DEC, NULL, 0,
        "ExtendedEARFCN", HFILL }},
    { &hf_f1ap_transmission_Bandwidth,
      { "transmission-Bandwidth", "f1ap.transmission_Bandwidth",
        FT_UINT32, BASE_DEC, VALS(f1ap_EUTRA_Transmission_Bandwidth_vals), 0,
        "EUTRA_Transmission_Bandwidth", HFILL }},
    { &hf_f1ap_subframeAssignment,
      { "subframeAssignment", "f1ap.subframeAssignment",
        FT_UINT32, BASE_DEC, VALS(f1ap_EUTRA_SubframeAssignment_vals), 0,
        "EUTRA_SubframeAssignment", HFILL }},
    { &hf_f1ap_specialSubframe_Info,
      { "specialSubframe-Info", "f1ap.specialSubframe_Info_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "EUTRA_SpecialSubframe_Info", HFILL }},
    { &hf_f1ap_rootSequenceIndex,
      { "rootSequenceIndex", "f1ap.rootSequenceIndex",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_837", HFILL }},
    { &hf_f1ap_zeroCorrelationIndex,
      { "zeroCorrelationIndex", "f1ap.zeroCorrelationIndex",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_15", HFILL }},
    { &hf_f1ap_highSpeedFlag,
      { "highSpeedFlag", "f1ap.highSpeedFlag",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_f1ap_prach_FreqOffset,
      { "prach-FreqOffset", "f1ap.prach_FreqOffset",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_94", HFILL }},
    { &hf_f1ap_prach_ConfigIndex,
      { "prach-ConfigIndex", "f1ap.prach_ConfigIndex",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_63", HFILL }},
    { &hf_f1ap_specialSubframePatterns,
      { "specialSubframePatterns", "f1ap.specialSubframePatterns",
        FT_UINT32, BASE_DEC, VALS(f1ap_EUTRA_SpecialSubframePatterns_vals), 0,
        "EUTRA_SpecialSubframePatterns", HFILL }},
    { &hf_f1ap_cyclicPrefixDL,
      { "cyclicPrefixDL", "f1ap.cyclicPrefixDL",
        FT_UINT32, BASE_DEC, VALS(f1ap_EUTRA_CyclicPrefixDL_vals), 0,
        "EUTRA_CyclicPrefixDL", HFILL }},
    { &hf_f1ap_cyclicPrefixUL,
      { "cyclicPrefixUL", "f1ap.cyclicPrefixUL",
        FT_UINT32, BASE_DEC, VALS(f1ap_EUTRA_CyclicPrefixUL_vals), 0,
        "EUTRA_CyclicPrefixUL", HFILL }},
    { &hf_f1ap_qCI,
      { "qCI", "f1ap.qCI",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_f1ap_allocationAndRetentionPriority,
      { "allocationAndRetentionPriority", "f1ap.allocationAndRetentionPriority_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_f1ap_gbrQosInformation,
      { "gbrQosInformation", "f1ap.gbrQosInformation_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "GBR_QosInformation", HFILL }},
    { &hf_f1ap_eUTRAFDD,
      { "eUTRAFDD", "f1ap.eUTRAFDD_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "EUTRA_FDD_Info", HFILL }},
    { &hf_f1ap_eUTRATDD,
      { "eUTRATDD", "f1ap.eUTRATDD_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "EUTRA_TDD_Info", HFILL }},
    { &hf_f1ap_uL_offsetToPointA,
      { "uL-offsetToPointA", "f1ap.uL_offsetToPointA",
        FT_UINT32, BASE_DEC, NULL, 0,
        "OffsetToPointA", HFILL }},
    { &hf_f1ap_dL_offsetToPointA,
      { "dL-offsetToPointA", "f1ap.dL_offsetToPointA",
        FT_UINT32, BASE_DEC, NULL, 0,
        "OffsetToPointA", HFILL }},
    { &hf_f1ap_offsetToPointA,
      { "offsetToPointA", "f1ap.offsetToPointA",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_f1ap_uL_NRFreqInfo,
      { "uL-NRFreqInfo", "f1ap.uL_NRFreqInfo_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "NRFreqInfo", HFILL }},
    { &hf_f1ap_dL_NRFreqInfo,
      { "dL-NRFreqInfo", "f1ap.dL_NRFreqInfo_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "NRFreqInfo", HFILL }},
    { &hf_f1ap_uL_Transmission_Bandwidth_01,
      { "uL-Transmission-Bandwidth", "f1ap.uL_Transmission_Bandwidth_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "Transmission_Bandwidth", HFILL }},
    { &hf_f1ap_dL_Transmission_Bandwidth_01,
      { "dL-Transmission-Bandwidth", "f1ap.dL_Transmission_Bandwidth_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "Transmission_Bandwidth", HFILL }},
    { &hf_f1ap_Flows_Mapped_To_DRB_List_item,
      { "Flows-Mapped-To-DRB-Item", "f1ap.Flows_Mapped_To_DRB_Item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_f1ap_qoSFlowIdentifier,
      { "qoSFlowIdentifier", "f1ap.qoSFlowIdentifier",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_f1ap_qoSFlowLevelQoSParameters,
      { "qoSFlowLevelQoSParameters", "f1ap.qoSFlowLevelQoSParameters_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_f1ap_freqBandIndicatorNr,
      { "freqBandIndicatorNr", "f1ap.freqBandIndicatorNr",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_1_1024_", HFILL }},
    { &hf_f1ap_supportedSULBandList,
      { "supportedSULBandList", "f1ap.supportedSULBandList",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_SIZE_0_maxnoofNrCellBands_OF_SupportedSULFreqBandItem", HFILL }},
    { &hf_f1ap_supportedSULBandList_item,
      { "SupportedSULFreqBandItem", "f1ap.SupportedSULFreqBandItem_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_f1ap_e_RAB_MaximumBitrateDL,
      { "e-RAB-MaximumBitrateDL", "f1ap.e_RAB_MaximumBitrateDL",
        FT_UINT64, BASE_DEC|BASE_UNIT_STRING, &units_bit_sec, 0,
        "BitRate", HFILL }},
    { &hf_f1ap_e_RAB_MaximumBitrateUL,
      { "e-RAB-MaximumBitrateUL", "f1ap.e_RAB_MaximumBitrateUL",
        FT_UINT64, BASE_DEC|BASE_UNIT_STRING, &units_bit_sec, 0,
        "BitRate", HFILL }},
    { &hf_f1ap_e_RAB_GuaranteedBitrateDL,
      { "e-RAB-GuaranteedBitrateDL", "f1ap.e_RAB_GuaranteedBitrateDL",
        FT_UINT64, BASE_DEC|BASE_UNIT_STRING, &units_bit_sec, 0,
        "BitRate", HFILL }},
    { &hf_f1ap_e_RAB_GuaranteedBitrateUL,
      { "e-RAB-GuaranteedBitrateUL", "f1ap.e_RAB_GuaranteedBitrateUL",
        FT_UINT64, BASE_DEC|BASE_UNIT_STRING, &units_bit_sec, 0,
        "BitRate", HFILL }},
    { &hf_f1ap_maxFlowBitRateDownlink,
      { "maxFlowBitRateDownlink", "f1ap.maxFlowBitRateDownlink",
        FT_UINT64, BASE_DEC|BASE_UNIT_STRING, &units_bit_sec, 0,
        "BitRate", HFILL }},
    { &hf_f1ap_maxFlowBitRateUplink,
      { "maxFlowBitRateUplink", "f1ap.maxFlowBitRateUplink",
        FT_UINT64, BASE_DEC|BASE_UNIT_STRING, &units_bit_sec, 0,
        "BitRate", HFILL }},
    { &hf_f1ap_guaranteedFlowBitRateDownlink,
      { "guaranteedFlowBitRateDownlink", "f1ap.guaranteedFlowBitRateDownlink",
        FT_UINT64, BASE_DEC|BASE_UNIT_STRING, &units_bit_sec, 0,
        "BitRate", HFILL }},
    { &hf_f1ap_guaranteedFlowBitRateUplink,
      { "guaranteedFlowBitRateUplink", "f1ap.guaranteedFlowBitRateUplink",
        FT_UINT64, BASE_DEC|BASE_UNIT_STRING, &units_bit_sec, 0,
        "BitRate", HFILL }},
    { &hf_f1ap_maxPacketLossRateDownlink,
      { "maxPacketLossRateDownlink", "f1ap.maxPacketLossRateDownlink",
        FT_UINT32, BASE_CUSTOM, CF_FUNC(f1ap_MaxPacketLossRate_fmt), 0,
        "MaxPacketLossRate", HFILL }},
    { &hf_f1ap_maxPacketLossRateUplink,
      { "maxPacketLossRateUplink", "f1ap.maxPacketLossRateUplink",
        FT_UINT32, BASE_CUSTOM, CF_FUNC(f1ap_MaxPacketLossRate_fmt), 0,
        "MaxPacketLossRate", HFILL }},
    { &hf_f1ap_sibtypetobeupdatedlist,
      { "sibtypetobeupdatedlist", "f1ap.sibtypetobeupdatedlist",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_SIZE_1_maxnoofSIBTypes_OF_SibtypetobeupdatedListItem", HFILL }},
    { &hf_f1ap_sibtypetobeupdatedlist_item,
      { "SibtypetobeupdatedListItem", "f1ap.SibtypetobeupdatedListItem_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_f1ap_tNLAssociationTransportLayerAddress,
      { "tNLAssociationTransportLayerAddress", "f1ap.tNLAssociationTransportLayerAddress",
        FT_UINT32, BASE_DEC, VALS(f1ap_CP_TransportLayerAddress_vals), 0,
        "CP_TransportLayerAddress", HFILL }},
    { &hf_f1ap_tNLAssociationUsage,
      { "tNLAssociationUsage", "f1ap.tNLAssociationUsage",
        FT_UINT32, BASE_DEC, VALS(f1ap_TNLAssociationUsage_vals), 0,
        NULL, HFILL }},
    { &hf_f1ap_served_Cell_Information,
      { "served-Cell-Information", "f1ap.served_Cell_Information_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_f1ap_gNB_DU_System_Information,
      { "gNB-DU-System-Information", "f1ap.gNB_DU_System_Information_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_f1ap_mIB_message,
      { "mIB-message", "f1ap.mIB_message",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_f1ap_sIB1_message,
      { "sIB1-message", "f1ap.sIB1_message",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_f1ap_tNLAssociationTransportLayerAddressgNBCU,
      { "tNLAssociationTransportLayerAddressgNBCU", "f1ap.tNLAssociationTransportLayerAddressgNBCU",
        FT_UINT32, BASE_DEC, VALS(f1ap_CP_TransportLayerAddress_vals), 0,
        "CP_TransportLayerAddress", HFILL }},
    { &hf_f1ap_transportLayerAddress,
      { "transportLayerAddress", "f1ap.transportLayerAddress",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_f1ap_gTP_TEID,
      { "gTP-TEID", "f1ap.gTP_TEID",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_f1ap_message_Identifier,
      { "message-Identifier", "f1ap.message_Identifier",
        FT_BYTES, BASE_NONE, NULL, 0,
        "MessageIdentifier", HFILL }},
    { &hf_f1ap_serialNumber,
      { "serialNumber", "f1ap.serialNumber",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_f1ap_nRARFCN,
      { "nRARFCN", "f1ap.nRARFCN",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_maxNRARFCN", HFILL }},
    { &hf_f1ap_sul_Information,
      { "sul-Information", "f1ap.sul_Information_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_f1ap_freqBandListNr,
      { "freqBandListNr", "f1ap.freqBandListNr",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_SIZE_1_maxnoofNrCellBands_OF_FreqBandNrItem", HFILL }},
    { &hf_f1ap_freqBandListNr_item,
      { "FreqBandNrItem", "f1ap.FreqBandNrItem_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_f1ap_nRCellIdentity,
      { "nRCellIdentity", "f1ap.nRCellIdentity",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_f1ap_fDD_01,
      { "fDD", "f1ap.fDD_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "FDD_Info", HFILL }},
    { &hf_f1ap_tDD_01,
      { "tDD", "f1ap.tDD_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "TDD_Info", HFILL }},
    { &hf_f1ap_pER_Scalar,
      { "pER-Scalar", "f1ap.pER_Scalar",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_f1ap_pER_Exponent,
      { "pER-Exponent", "f1ap.pER_Exponent",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_f1ap_rANUEPagingIdentity,
      { "rANUEPagingIdentity", "f1ap.rANUEPagingIdentity_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_f1ap_cNUEPagingIdentity,
      { "cNUEPagingIdentity", "f1ap.cNUEPagingIdentity",
        FT_UINT32, BASE_DEC, VALS(f1ap_CNUEPagingIdentity_vals), 0,
        NULL, HFILL }},
    { &hf_f1ap_spectrumSharingGroupID,
      { "spectrumSharingGroupID", "f1ap.spectrumSharingGroupID",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_f1ap_eUTRACells_List,
      { "eUTRACells-List", "f1ap.eUTRACells_List",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_f1ap_potential_SpCell_ID,
      { "potential-SpCell-ID", "f1ap.potential_SpCell_ID_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "NRCGI", HFILL }},
    { &hf_f1ap_sIBtype,
      { "sIBtype", "f1ap.sIBtype",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SIBType_PWS", HFILL }},
    { &hf_f1ap_sIBmessage,
      { "sIBmessage", "f1ap.sIBmessage",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_f1ap_non_Dynamic_5QI,
      { "non-Dynamic-5QI", "f1ap.non_Dynamic_5QI_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "NonDynamic5QIDescriptor", HFILL }},
    { &hf_f1ap_dynamic_5QI,
      { "dynamic-5QI", "f1ap.dynamic_5QI_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "Dynamic5QIDescriptor", HFILL }},
    { &hf_f1ap_qoS_Characteristics,
      { "qoS-Characteristics", "f1ap.qoS_Characteristics",
        FT_UINT32, BASE_DEC, VALS(f1ap_QoS_Characteristics_vals), 0,
        NULL, HFILL }},
    { &hf_f1ap_nGRANallocationRetentionPriority,
      { "nGRANallocationRetentionPriority", "f1ap.nGRANallocationRetentionPriority_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "NGRANAllocationAndRetentionPriority", HFILL }},
    { &hf_f1ap_gBR_QoS_Flow_Information,
      { "gBR-QoS-Flow-Information", "f1ap.gBR_QoS_Flow_Information_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "GBR_QoSFlowInformation", HFILL }},
    { &hf_f1ap_reflective_QoS_Attribute,
      { "reflective-QoS-Attribute", "f1ap.reflective_QoS_Attribute",
        FT_UINT32, BASE_DEC, VALS(f1ap_T_reflective_QoS_Attribute_vals), 0,
        NULL, HFILL }},
    { &hf_f1ap_eUTRANQoS,
      { "eUTRANQoS", "f1ap.eUTRANQoS_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_f1ap_iRNTI,
      { "iRNTI", "f1ap.iRNTI",
        FT_BYTES, BASE_NONE, NULL, 0,
        "BIT_STRING_SIZE_40", HFILL }},
    { &hf_f1ap_eNDC,
      { "eNDC", "f1ap.eNDC",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SubscriberProfileIDforRFP", HFILL }},
    { &hf_f1ap_nGRAN,
      { "nGRAN", "f1ap.nGRAN",
        FT_UINT32, BASE_DEC, NULL, 0,
        "RAT_FrequencySelectionPriority", HFILL }},
    { &hf_f1ap_eUTRA_Mode_Info,
      { "eUTRA-Mode-Info", "f1ap.eUTRA_Mode_Info",
        FT_UINT32, BASE_DEC, VALS(f1ap_EUTRA_Coex_Mode_Info_vals), 0,
        "EUTRA_Coex_Mode_Info", HFILL }},
    { &hf_f1ap_eUTRA_PRACH_Configuration,
      { "eUTRA-PRACH-Configuration", "f1ap.eUTRA_PRACH_Configuration_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_f1ap_meNB_Cell_ID,
      { "meNB-Cell-ID", "f1ap.meNB_Cell_ID",
        FT_BYTES, BASE_NONE, NULL, 0,
        "EUTRA_Cell_ID", HFILL }},
    { &hf_f1ap_resourceCoordinationEUTRACellInfo,
      { "resourceCoordinationEUTRACellInfo", "f1ap.resourceCoordinationEUTRACellInfo_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_f1ap_assocatedLCID,
      { "assocatedLCID", "f1ap.assocatedLCID",
        FT_UINT32, BASE_DEC, NULL, 0,
        "LCID", HFILL }},
    { &hf_f1ap_reestablishment_Indication,
      { "reestablishment-Indication", "f1ap.reestablishment_Indication",
        FT_UINT32, BASE_DEC, VALS(f1ap_Reestablishment_Indication_vals), 0,
        NULL, HFILL }},
    { &hf_f1ap_delivery_status,
      { "delivery-status", "f1ap.delivery_status",
        FT_UINT32, BASE_DEC, NULL, 0,
        "PDCP_SN", HFILL }},
    { &hf_f1ap_triggering_message,
      { "triggering-message", "f1ap.triggering_message",
        FT_UINT32, BASE_DEC, NULL, 0,
        "PDCP_SN", HFILL }},
    { &hf_f1ap_latest_RRC_Version,
      { "latest-RRC-Version", "f1ap.latest_RRC_Version",
        FT_BYTES, BASE_NONE, NULL, 0,
        "BIT_STRING_SIZE_3", HFILL }},
    { &hf_f1ap_sCellIndex,
      { "sCellIndex", "f1ap.sCellIndex",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_f1ap_sCellULConfigured,
      { "sCellULConfigured", "f1ap.sCellULConfigured",
        FT_UINT32, BASE_DEC, VALS(f1ap_CellULConfigured_vals), 0,
        "CellULConfigured", HFILL }},
    { &hf_f1ap_configured_EPS_TAC,
      { "configured-EPS-TAC", "f1ap.configured_EPS_TAC",
        FT_UINT16, BASE_DEC_HEX, NULL, 0,
        NULL, HFILL }},
    { &hf_f1ap_servedPLMNs,
      { "servedPLMNs", "f1ap.servedPLMNs",
        FT_UINT32, BASE_DEC, NULL, 0,
        "ServedPLMNs_List", HFILL }},
    { &hf_f1ap_nR_Mode_Info,
      { "nR-Mode-Info", "f1ap.nR_Mode_Info",
        FT_UINT32, BASE_DEC, VALS(f1ap_NR_Mode_Info_vals), 0,
        NULL, HFILL }},
    { &hf_f1ap_measurementTimingConfiguration,
      { "measurementTimingConfiguration", "f1ap.measurementTimingConfiguration",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_f1ap_oldNRCGI,
      { "oldNRCGI", "f1ap.oldNRCGI_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "NRCGI", HFILL }},
    { &hf_f1ap_eUTRA_Mode_Info_01,
      { "eUTRA-Mode-Info", "f1ap.eUTRA_Mode_Info",
        FT_UINT32, BASE_DEC, VALS(f1ap_EUTRA_Mode_Info_vals), 0,
        NULL, HFILL }},
    { &hf_f1ap_protectedEUTRAResourceIndication,
      { "protectedEUTRAResourceIndication", "f1ap.protectedEUTRAResourceIndication",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_f1ap_service_state,
      { "service-state", "f1ap.service_state",
        FT_UINT32, BASE_DEC, VALS(f1ap_Service_State_vals), 0,
        NULL, HFILL }},
    { &hf_f1ap_switchingOffOngoing,
      { "switchingOffOngoing", "f1ap.switchingOffOngoing",
        FT_UINT32, BASE_DEC, VALS(f1ap_T_switchingOffOngoing_vals), 0,
        NULL, HFILL }},
    { &hf_f1ap_SItype_List_item,
      { "SItype-Item", "f1ap.SItype_Item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_f1ap_sItype,
      { "sItype", "f1ap.sItype",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_f1ap_sIBtype_01,
      { "sIBtype", "f1ap.sIBtype",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_f1ap_sIBmessage_01,
      { "sIBmessage", "f1ap.sIBmessage",
        FT_BYTES, BASE_NONE, NULL, 0,
        "T_sIBmessage_01", HFILL }},
    { &hf_f1ap_valueTag,
      { "valueTag", "f1ap.valueTag",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_31_", HFILL }},
    { &hf_f1ap_SliceSupportList_item,
      { "SliceSupportItem", "f1ap.SliceSupportItem_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_f1ap_sST,
      { "sST", "f1ap.sST",
        FT_BYTES, BASE_NONE, NULL, 0,
        "OCTET_STRING_SIZE_1", HFILL }},
    { &hf_f1ap_sD,
      { "sD", "f1ap.sD",
        FT_BYTES, BASE_NONE, NULL, 0,
        "OCTET_STRING_SIZE_3", HFILL }},
    { &hf_f1ap_sRBID,
      { "sRBID", "f1ap.sRBID",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_f1ap_duplicationIndication,
      { "duplicationIndication", "f1ap.duplicationIndication",
        FT_UINT32, BASE_DEC, VALS(f1ap_DuplicationIndication_vals), 0,
        NULL, HFILL }},
    { &hf_f1ap_sUL_NRARFCN,
      { "sUL-NRARFCN", "f1ap.sUL_NRARFCN",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_maxNRARFCN", HFILL }},
    { &hf_f1ap_sUL_transmission_Bandwidth,
      { "sUL-transmission-Bandwidth", "f1ap.sUL_transmission_Bandwidth_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "Transmission_Bandwidth", HFILL }},
    { &hf_f1ap_nRFreqInfo,
      { "nRFreqInfo", "f1ap.nRFreqInfo_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_f1ap_transmission_Bandwidth_01,
      { "transmission-Bandwidth", "f1ap.transmission_Bandwidth_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_f1ap_nRSCS,
      { "nRSCS", "f1ap.nRSCS",
        FT_UINT32, BASE_DEC, VALS(f1ap_NRSCS_vals), 0,
        NULL, HFILL }},
    { &hf_f1ap_nRNRB,
      { "nRNRB", "f1ap.nRNRB",
        FT_UINT32, BASE_DEC|BASE_EXT_STRING, &f1ap_NRNRB_vals_ext, 0,
        NULL, HFILL }},
    { &hf_f1ap_uACPLMN_List,
      { "uACPLMN-List", "f1ap.uACPLMN_List",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_f1ap_UACPLMN_List_item,
      { "UACPLMN-Item", "f1ap.UACPLMN_Item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_f1ap_uACType_List,
      { "uACType-List", "f1ap.uACType_List",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_f1ap_UACType_List_item,
      { "UACType-Item", "f1ap.UACType_Item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_f1ap_uACReductionIndication,
      { "uACReductionIndication", "f1ap.uACReductionIndication",
        FT_UINT32, BASE_DEC|BASE_UNIT_STRING, &units_percent, 0,
        NULL, HFILL }},
    { &hf_f1ap_uACCategoryType,
      { "uACCategoryType", "f1ap.uACCategoryType",
        FT_UINT32, BASE_DEC, VALS(f1ap_UACCategoryType_vals), 0,
        NULL, HFILL }},
    { &hf_f1ap_uACstandardized,
      { "uACstandardized", "f1ap.uACstandardized",
        FT_UINT32, BASE_DEC, VALS(f1ap_UACAction_vals), 0,
        "UACAction", HFILL }},
    { &hf_f1ap_uACOperatorDefined,
      { "uACOperatorDefined", "f1ap.uACOperatorDefined_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_f1ap_accessCategory,
      { "accessCategory", "f1ap.accessCategory",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_32_63_", HFILL }},
    { &hf_f1ap_accessIdentity,
      { "accessIdentity", "f1ap.accessIdentity",
        FT_BYTES, BASE_NONE, NULL, 0,
        "BIT_STRING_SIZE_7", HFILL }},
    { &hf_f1ap_gNB_DU_UE_F1AP_ID,
      { "gNB-DU-UE-F1AP-ID", "f1ap.gNB_DU_UE_F1AP_ID",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_f1ap_indexLength10,
      { "indexLength10", "f1ap.indexLength10",
        FT_BYTES, BASE_NONE, NULL, 0,
        "BIT_STRING_SIZE_10", HFILL }},
    { &hf_f1ap_uLUEConfiguration,
      { "uLUEConfiguration", "f1ap.uLUEConfiguration",
        FT_UINT32, BASE_DEC, VALS(f1ap_ULUEConfiguration_vals), 0,
        NULL, HFILL }},
    { &hf_f1ap_ULUPTNLInformation_ToBeSetup_List_item,
      { "ULUPTNLInformation-ToBeSetup-Item", "f1ap.ULUPTNLInformation_ToBeSetup_Item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_f1ap_uLUPTNLInformation,
      { "uLUPTNLInformation", "f1ap.uLUPTNLInformation",
        FT_UINT32, BASE_DEC, VALS(f1ap_UPTransportLayerInformation_vals), 0,
        "UPTransportLayerInformation", HFILL }},
    { &hf_f1ap_gTPTunnel,
      { "gTPTunnel", "f1ap.gTPTunnel_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_f1ap_protocolIEs,
      { "protocolIEs", "f1ap.protocolIEs",
        FT_UINT32, BASE_DEC, NULL, 0,
        "ProtocolIE_Container", HFILL }},
    { &hf_f1ap_f1_Interface,
      { "f1-Interface", "f1ap.f1_Interface",
        FT_UINT32, BASE_DEC, VALS(f1ap_ResetAll_vals), 0,
        "ResetAll", HFILL }},
    { &hf_f1ap_partOfF1_Interface,
      { "partOfF1-Interface", "f1ap.partOfF1_Interface",
        FT_UINT32, BASE_DEC, NULL, 0,
        "UE_associatedLogicalF1_ConnectionListRes", HFILL }},
    { &hf_f1ap_UE_associatedLogicalF1_ConnectionListRes_item,
      { "ProtocolIE-SingleContainer", "f1ap.ProtocolIE_SingleContainer_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_f1ap_UE_associatedLogicalF1_ConnectionListResAck_item,
      { "ProtocolIE-SingleContainer", "f1ap.ProtocolIE_SingleContainer_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_f1ap_GNB_DU_Served_Cells_List_item,
      { "ProtocolIE-SingleContainer", "f1ap.ProtocolIE_SingleContainer_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_f1ap_Cells_to_be_Activated_List_item,
      { "ProtocolIE-SingleContainer", "f1ap.ProtocolIE_SingleContainer_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_f1ap_Served_Cells_To_Add_List_item,
      { "ProtocolIE-SingleContainer", "f1ap.ProtocolIE_SingleContainer_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_f1ap_Served_Cells_To_Modify_List_item,
      { "ProtocolIE-SingleContainer", "f1ap.ProtocolIE_SingleContainer_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_f1ap_Served_Cells_To_Delete_List_item,
      { "ProtocolIE-SingleContainer", "f1ap.ProtocolIE_SingleContainer_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_f1ap_Cells_Status_List_item,
      { "ProtocolIE-SingleContainer", "f1ap.ProtocolIE_SingleContainer_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_f1ap_Dedicated_SIDelivery_NeededUE_List_item,
      { "ProtocolIE-SingleContainer", "f1ap.ProtocolIE_SingleContainer_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_f1ap_GNB_DU_TNL_Association_To_Remove_List_item,
      { "ProtocolIE-SingleContainer", "f1ap.ProtocolIE_SingleContainer_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_f1ap_Cells_to_be_Deactivated_List_item,
      { "ProtocolIE-SingleContainer", "f1ap.ProtocolIE_SingleContainer_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_f1ap_GNB_CU_TNL_Association_To_Add_List_item,
      { "ProtocolIE-SingleContainer", "f1ap.ProtocolIE_SingleContainer_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_f1ap_GNB_CU_TNL_Association_To_Remove_List_item,
      { "ProtocolIE-SingleContainer", "f1ap.ProtocolIE_SingleContainer_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_f1ap_GNB_CU_TNL_Association_To_Update_List_item,
      { "ProtocolIE-SingleContainer", "f1ap.ProtocolIE_SingleContainer_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_f1ap_Cells_to_be_Barred_List_item,
      { "ProtocolIE-SingleContainer", "f1ap.ProtocolIE_SingleContainer_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_f1ap_Protected_EUTRA_Resources_List_item,
      { "ProtocolIE-SingleContainer", "f1ap.ProtocolIE_SingleContainer_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_f1ap_Cells_Failed_to_be_Activated_List_item,
      { "ProtocolIE-SingleContainer", "f1ap.ProtocolIE_SingleContainer_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_f1ap_GNB_CU_TNL_Association_Setup_List_item,
      { "ProtocolIE-SingleContainer", "f1ap.ProtocolIE_SingleContainer_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_f1ap_GNB_CU_TNL_Association_Failed_To_Setup_List_item,
      { "ProtocolIE-SingleContainer", "f1ap.ProtocolIE_SingleContainer_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_f1ap_Candidate_SpCell_List_item,
      { "ProtocolIE-SingleContainer", "f1ap.ProtocolIE_SingleContainer_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_f1ap_SCell_ToBeSetup_List_item,
      { "ProtocolIE-SingleContainer", "f1ap.ProtocolIE_SingleContainer_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_f1ap_SRBs_ToBeSetup_List_item,
      { "ProtocolIE-SingleContainer", "f1ap.ProtocolIE_SingleContainer_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_f1ap_DRBs_ToBeSetup_List_item,
      { "ProtocolIE-SingleContainer", "f1ap.ProtocolIE_SingleContainer_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_f1ap_DRBs_Setup_List_item,
      { "ProtocolIE-SingleContainer", "f1ap.ProtocolIE_SingleContainer_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_f1ap_SRBs_FailedToBeSetup_List_item,
      { "ProtocolIE-SingleContainer", "f1ap.ProtocolIE_SingleContainer_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_f1ap_DRBs_FailedToBeSetup_List_item,
      { "ProtocolIE-SingleContainer", "f1ap.ProtocolIE_SingleContainer_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_f1ap_SCell_FailedtoSetup_List_item,
      { "ProtocolIE-SingleContainer", "f1ap.ProtocolIE_SingleContainer_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_f1ap_SRBs_Setup_List_item,
      { "ProtocolIE-SingleContainer", "f1ap.ProtocolIE_SingleContainer_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_f1ap_Potential_SpCell_List_item,
      { "ProtocolIE-SingleContainer", "f1ap.ProtocolIE_SingleContainer_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_f1ap_SCell_ToBeSetupMod_List_item,
      { "ProtocolIE-SingleContainer", "f1ap.ProtocolIE_SingleContainer_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_f1ap_SCell_ToBeRemoved_List_item,
      { "ProtocolIE-SingleContainer", "f1ap.ProtocolIE_SingleContainer_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_f1ap_SRBs_ToBeSetupMod_List_item,
      { "ProtocolIE-SingleContainer", "f1ap.ProtocolIE_SingleContainer_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_f1ap_DRBs_ToBeSetupMod_List_item,
      { "ProtocolIE-SingleContainer", "f1ap.ProtocolIE_SingleContainer_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_f1ap_DRBs_ToBeModified_List_item,
      { "ProtocolIE-SingleContainer", "f1ap.ProtocolIE_SingleContainer_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_f1ap_SRBs_ToBeReleased_List_item,
      { "ProtocolIE-SingleContainer", "f1ap.ProtocolIE_SingleContainer_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_f1ap_DRBs_ToBeReleased_List_item,
      { "ProtocolIE-SingleContainer", "f1ap.ProtocolIE_SingleContainer_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_f1ap_DRBs_SetupMod_List_item,
      { "ProtocolIE-SingleContainer", "f1ap.ProtocolIE_SingleContainer_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_f1ap_DRBs_Modified_List_item,
      { "ProtocolIE-SingleContainer", "f1ap.ProtocolIE_SingleContainer_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_f1ap_SRBs_SetupMod_List_item,
      { "ProtocolIE-SingleContainer", "f1ap.ProtocolIE_SingleContainer_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_f1ap_SRBs_Modified_List_item,
      { "ProtocolIE-SingleContainer", "f1ap.ProtocolIE_SingleContainer_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_f1ap_DRBs_FailedToBeModified_List_item,
      { "ProtocolIE-SingleContainer", "f1ap.ProtocolIE_SingleContainer_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_f1ap_SRBs_FailedToBeSetupMod_List_item,
      { "ProtocolIE-SingleContainer", "f1ap.ProtocolIE_SingleContainer_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_f1ap_DRBs_FailedToBeSetupMod_List_item,
      { "ProtocolIE-SingleContainer", "f1ap.ProtocolIE_SingleContainer_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_f1ap_SCell_FailedtoSetupMod_List_item,
      { "ProtocolIE-SingleContainer", "f1ap.ProtocolIE_SingleContainer_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_f1ap_Associated_SCell_List_item,
      { "ProtocolIE-SingleContainer", "f1ap.ProtocolIE_SingleContainer_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_f1ap_DRBs_Required_ToBeModified_List_item,
      { "ProtocolIE-SingleContainer", "f1ap.ProtocolIE_SingleContainer_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_f1ap_DRBs_Required_ToBeReleased_List_item,
      { "ProtocolIE-SingleContainer", "f1ap.ProtocolIE_SingleContainer_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_f1ap_SRBs_Required_ToBeReleased_List_item,
      { "ProtocolIE-SingleContainer", "f1ap.ProtocolIE_SingleContainer_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_f1ap_DRBs_ModifiedConf_List_item,
      { "ProtocolIE-SingleContainer", "f1ap.ProtocolIE_SingleContainer_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_f1ap_Cells_To_Be_Broadcast_List_item,
      { "ProtocolIE-SingleContainer", "f1ap.ProtocolIE_SingleContainer_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_f1ap_Cells_Broadcast_Completed_List_item,
      { "ProtocolIE-SingleContainer", "f1ap.ProtocolIE_SingleContainer_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_f1ap_Broadcast_To_Be_Cancelled_List_item,
      { "ProtocolIE-SingleContainer", "f1ap.ProtocolIE_SingleContainer_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_f1ap_Cells_Broadcast_Cancelled_List_item,
      { "ProtocolIE-SingleContainer", "f1ap.ProtocolIE_SingleContainer_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_f1ap_DRB_Activity_List_item,
      { "ProtocolIE-SingleContainer", "f1ap.ProtocolIE_SingleContainer_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_f1ap_privateIEs,
      { "privateIEs", "f1ap.privateIEs",
        FT_UINT32, BASE_DEC, NULL, 0,
        "PrivateIE_Container", HFILL }},
    { &hf_f1ap_PagingCell_list_item,
      { "ProtocolIE-SingleContainer", "f1ap.ProtocolIE_SingleContainer_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_f1ap_DRB_Notify_List_item,
      { "ProtocolIE-SingleContainer", "f1ap.ProtocolIE_SingleContainer_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_f1ap_NR_CGI_List_For_Restart_List_item,
      { "ProtocolIE-SingleContainer", "f1ap.ProtocolIE_SingleContainer_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_f1ap_PWS_Failed_NR_CGI_List_item,
      { "ProtocolIE-SingleContainer", "f1ap.ProtocolIE_SingleContainer_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_f1ap_initiatingMessage,
      { "initiatingMessage", "f1ap.initiatingMessage_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_f1ap_successfulOutcome,
      { "successfulOutcome", "f1ap.successfulOutcome_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_f1ap_unsuccessfulOutcome,
      { "unsuccessfulOutcome", "f1ap.unsuccessfulOutcome_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_f1ap_initiatingMessagevalue,
      { "value", "f1ap.value_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "InitiatingMessage_value", HFILL }},
    { &hf_f1ap_successfulOutcome_value,
      { "value", "f1ap.value_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "SuccessfulOutcome_value", HFILL }},
    { &hf_f1ap_unsuccessfulOutcome_value,
      { "value", "f1ap.value_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "UnsuccessfulOutcome_value", HFILL }},

/*--- End of included file: packet-f1ap-hfarr.c ---*/
#line 249 "./asn1/f1ap/packet-f1ap-template.c"
  };

  /* List of subtrees */
  static gint *ett[] = {
    &ett_f1ap,
    &ett_f1ap_ResourceCoordinationTransferContainer,
    &ett_f1ap_PLMN_Identity,
    &ett_f1ap_MIB_message,
    &ett_f1ap_SIB1_message,
    &ett_f1ap_CG_ConfigInfo,
    &ett_f1ap_CellGroupConfig,
    &ett_f1ap_TransportLayerAddress,
    &ett_f1ap_UE_CapabilityRAT_ContainerList,
    &ett_f1ap_measurementTimingConfiguration,
    &ett_f1ap_DUtoCURRCContainer,
    &ett_f1ap_requestedP_MaxFR1,
    &ett_f1ap_HandoverPreparationInformation,
    &ett_f1ap_MeasConfig,
    &ett_f1ap_MeasGapConfig,
    &ett_f1ap_MeasGapSharingConfig,
    &ett_f1ap_EUTRA_NR_CellResourceCoordinationReq_Container,
    &ett_f1ap_EUTRA_NR_CellResourceCoordinationReqAck_Container,
    &ett_f1ap_ProtectedEUTRAResourceIndication,
    &ett_f1ap_RRCContainer,
    &ett_f1ap_RRCContainer_RRCSetupComplete,
    &ett_f1ap_sIBmessage,
    &ett_f1ap_UplinkTxDirectCurrentListInformation,
    &ett_f1ap_DRX_Config,
    &ett_f1ap_Ph_InfoSCG,
    &ett_f1ap_RequestedBandCombinationIndex,
    &ett_f1ap_RequestedFeatureSetEntryIndex,
    &ett_f1ap_RequestedP_MaxFR2,
    &ett_f1ap_UEAssistanceInformation,
    &ett_f1ap_CG_Config,
    &ett_f1ap_Ph_InfoMCG,

/*--- Included file: packet-f1ap-ettarr.c ---*/
#line 1 "./asn1/f1ap/packet-f1ap-ettarr.c"
    &ett_f1ap_PrivateIE_ID,
    &ett_f1ap_ProtocolIE_Container,
    &ett_f1ap_ProtocolIE_Field,
    &ett_f1ap_ProtocolExtensionContainer,
    &ett_f1ap_ProtocolExtensionField,
    &ett_f1ap_PrivateIE_Container,
    &ett_f1ap_PrivateIE_Field,
    &ett_f1ap_AdditionalSIBMessageList,
    &ett_f1ap_AdditionalSIBMessageList_Item,
    &ett_f1ap_AllocationAndRetentionPriority,
    &ett_f1ap_Associated_SCell_Item,
    &ett_f1ap_AvailablePLMNList,
    &ett_f1ap_AvailablePLMNList_Item,
    &ett_f1ap_BPLMN_ID_Info_List,
    &ett_f1ap_BPLMN_ID_Info_Item,
    &ett_f1ap_ServedPLMNs_List,
    &ett_f1ap_ServedPLMNs_Item,
    &ett_f1ap_Candidate_SpCell_Item,
    &ett_f1ap_Cause,
    &ett_f1ap_Cells_Failed_to_be_Activated_List_Item,
    &ett_f1ap_Cells_Status_Item,
    &ett_f1ap_Cells_To_Be_Broadcast_Item,
    &ett_f1ap_Cells_Broadcast_Completed_Item,
    &ett_f1ap_Broadcast_To_Be_Cancelled_Item,
    &ett_f1ap_Cells_Broadcast_Cancelled_Item,
    &ett_f1ap_Cells_to_be_Activated_List_Item,
    &ett_f1ap_Cells_to_be_Deactivated_List_Item,
    &ett_f1ap_Cells_to_be_Barred_Item,
    &ett_f1ap_CellType,
    &ett_f1ap_CNUEPagingIdentity,
    &ett_f1ap_CP_TransportLayerAddress,
    &ett_f1ap_CriticalityDiagnostics,
    &ett_f1ap_CriticalityDiagnostics_IE_List,
    &ett_f1ap_CriticalityDiagnostics_IE_Item,
    &ett_f1ap_CUtoDURRCInformation,
    &ett_f1ap_Dedicated_SIDelivery_NeededUE_Item,
    &ett_f1ap_DLUPTNLInformation_ToBeSetup_List,
    &ett_f1ap_DLUPTNLInformation_ToBeSetup_Item,
    &ett_f1ap_DRB_Activity_Item,
    &ett_f1ap_DRBs_FailedToBeModified_Item,
    &ett_f1ap_DRBs_FailedToBeSetup_Item,
    &ett_f1ap_DRBs_FailedToBeSetupMod_Item,
    &ett_f1ap_DRB_Information,
    &ett_f1ap_DRBs_Modified_Item,
    &ett_f1ap_DRBs_ModifiedConf_Item,
    &ett_f1ap_DRB_Notify_Item,
    &ett_f1ap_DRBs_Required_ToBeModified_Item,
    &ett_f1ap_DRBs_Required_ToBeReleased_Item,
    &ett_f1ap_DRBs_Setup_Item,
    &ett_f1ap_DRBs_SetupMod_Item,
    &ett_f1ap_DRBs_ToBeModified_Item,
    &ett_f1ap_DRBs_ToBeReleased_Item,
    &ett_f1ap_DRBs_ToBeSetup_Item,
    &ett_f1ap_DRBs_ToBeSetupMod_Item,
    &ett_f1ap_DRXCycle,
    &ett_f1ap_DUtoCURRCInformation,
    &ett_f1ap_Dynamic5QIDescriptor,
    &ett_f1ap_Endpoint_IP_address_and_port,
    &ett_f1ap_ExtendedAvailablePLMN_List,
    &ett_f1ap_ExtendedAvailablePLMN_Item,
    &ett_f1ap_ExtendedServedPLMNs_List,
    &ett_f1ap_ExtendedServedPLMNs_Item,
    &ett_f1ap_EUTRACells_List,
    &ett_f1ap_EUTRACells_List_item,
    &ett_f1ap_EUTRA_Coex_FDD_Info,
    &ett_f1ap_EUTRA_Coex_Mode_Info,
    &ett_f1ap_EUTRA_Coex_TDD_Info,
    &ett_f1ap_EUTRA_PRACH_Configuration,
    &ett_f1ap_EUTRA_SpecialSubframe_Info,
    &ett_f1ap_EUTRANQoS,
    &ett_f1ap_EUTRA_Mode_Info,
    &ett_f1ap_EUTRA_FDD_Info,
    &ett_f1ap_EUTRA_TDD_Info,
    &ett_f1ap_FDD_Info,
    &ett_f1ap_Flows_Mapped_To_DRB_List,
    &ett_f1ap_Flows_Mapped_To_DRB_Item,
    &ett_f1ap_FreqBandNrItem,
    &ett_f1ap_SEQUENCE_SIZE_0_maxnoofNrCellBands_OF_SupportedSULFreqBandItem,
    &ett_f1ap_GBR_QosInformation,
    &ett_f1ap_GBR_QoSFlowInformation,
    &ett_f1ap_GNB_CUSystemInformation,
    &ett_f1ap_SEQUENCE_SIZE_1_maxnoofSIBTypes_OF_SibtypetobeupdatedListItem,
    &ett_f1ap_GNB_CU_TNL_Association_Setup_Item,
    &ett_f1ap_GNB_CU_TNL_Association_Failed_To_Setup_Item,
    &ett_f1ap_GNB_CU_TNL_Association_To_Add_Item,
    &ett_f1ap_GNB_CU_TNL_Association_To_Remove_Item,
    &ett_f1ap_GNB_CU_TNL_Association_To_Update_Item,
    &ett_f1ap_GNB_DU_Served_Cells_Item,
    &ett_f1ap_GNB_DU_System_Information,
    &ett_f1ap_GNB_DU_TNL_Association_To_Remove_Item,
    &ett_f1ap_GTPTunnel,
    &ett_f1ap_NGRANAllocationAndRetentionPriority,
    &ett_f1ap_NR_CGI_List_For_Restart_Item,
    &ett_f1ap_NonDynamic5QIDescriptor,
    &ett_f1ap_NotificationInformation,
    &ett_f1ap_NRFreqInfo,
    &ett_f1ap_SEQUENCE_SIZE_1_maxnoofNrCellBands_OF_FreqBandNrItem,
    &ett_f1ap_NRCGI,
    &ett_f1ap_NR_Mode_Info,
    &ett_f1ap_PacketErrorRate,
    &ett_f1ap_PagingCell_Item,
    &ett_f1ap_PagingIdentity,
    &ett_f1ap_Protected_EUTRA_Resources_Item,
    &ett_f1ap_Potential_SpCell_Item,
    &ett_f1ap_PWS_Failed_NR_CGI_Item,
    &ett_f1ap_PWSSystemInformation,
    &ett_f1ap_QoS_Characteristics,
    &ett_f1ap_QoSFlowLevelQoSParameters,
    &ett_f1ap_QoSInformation,
    &ett_f1ap_RANUEPagingIdentity,
    &ett_f1ap_RAT_FrequencyPriorityInformation,
    &ett_f1ap_ResourceCoordinationEUTRACellInfo,
    &ett_f1ap_ResourceCoordinationTransferInformation,
    &ett_f1ap_RLCFailureIndication,
    &ett_f1ap_RLC_Status,
    &ett_f1ap_RRCDeliveryStatus,
    &ett_f1ap_RRC_Version,
    &ett_f1ap_SCell_FailedtoSetup_Item,
    &ett_f1ap_SCell_FailedtoSetupMod_Item,
    &ett_f1ap_SCell_ToBeRemoved_Item,
    &ett_f1ap_SCell_ToBeSetup_Item,
    &ett_f1ap_SCell_ToBeSetupMod_Item,
    &ett_f1ap_Served_Cell_Information,
    &ett_f1ap_Served_Cells_To_Add_Item,
    &ett_f1ap_Served_Cells_To_Delete_Item,
    &ett_f1ap_Served_Cells_To_Modify_Item,
    &ett_f1ap_Served_EUTRA_Cells_Information,
    &ett_f1ap_Service_Status,
    &ett_f1ap_SItype_List,
    &ett_f1ap_SItype_Item,
    &ett_f1ap_SibtypetobeupdatedListItem,
    &ett_f1ap_SliceSupportList,
    &ett_f1ap_SliceSupportItem,
    &ett_f1ap_SNSSAI,
    &ett_f1ap_SRBs_FailedToBeSetup_Item,
    &ett_f1ap_SRBs_FailedToBeSetupMod_Item,
    &ett_f1ap_SRBs_Modified_Item,
    &ett_f1ap_SRBs_Required_ToBeReleased_Item,
    &ett_f1ap_SRBs_Setup_Item,
    &ett_f1ap_SRBs_SetupMod_Item,
    &ett_f1ap_SRBs_ToBeReleased_Item,
    &ett_f1ap_SRBs_ToBeSetup_Item,
    &ett_f1ap_SRBs_ToBeSetupMod_Item,
    &ett_f1ap_SUL_Information,
    &ett_f1ap_SupportedSULFreqBandItem,
    &ett_f1ap_TDD_Info,
    &ett_f1ap_Transmission_Bandwidth,
    &ett_f1ap_UAC_Assistance_Info,
    &ett_f1ap_UACPLMN_List,
    &ett_f1ap_UACPLMN_Item,
    &ett_f1ap_UACType_List,
    &ett_f1ap_UACType_Item,
    &ett_f1ap_UACCategoryType,
    &ett_f1ap_UACOperatorDefined,
    &ett_f1ap_UE_associatedLogicalF1_ConnectionItem,
    &ett_f1ap_UEIdentityIndexValue,
    &ett_f1ap_ULConfiguration,
    &ett_f1ap_ULUPTNLInformation_ToBeSetup_List,
    &ett_f1ap_ULUPTNLInformation_ToBeSetup_Item,
    &ett_f1ap_UPTransportLayerInformation,
    &ett_f1ap_Reset,
    &ett_f1ap_ResetType,
    &ett_f1ap_UE_associatedLogicalF1_ConnectionListRes,
    &ett_f1ap_ResetAcknowledge,
    &ett_f1ap_UE_associatedLogicalF1_ConnectionListResAck,
    &ett_f1ap_ErrorIndication,
    &ett_f1ap_F1SetupRequest,
    &ett_f1ap_GNB_DU_Served_Cells_List,
    &ett_f1ap_F1SetupResponse,
    &ett_f1ap_Cells_to_be_Activated_List,
    &ett_f1ap_F1SetupFailure,
    &ett_f1ap_GNBDUConfigurationUpdate,
    &ett_f1ap_Served_Cells_To_Add_List,
    &ett_f1ap_Served_Cells_To_Modify_List,
    &ett_f1ap_Served_Cells_To_Delete_List,
    &ett_f1ap_Cells_Status_List,
    &ett_f1ap_Dedicated_SIDelivery_NeededUE_List,
    &ett_f1ap_GNB_DU_TNL_Association_To_Remove_List,
    &ett_f1ap_GNBDUConfigurationUpdateAcknowledge,
    &ett_f1ap_GNBDUConfigurationUpdateFailure,
    &ett_f1ap_GNBCUConfigurationUpdate,
    &ett_f1ap_Cells_to_be_Deactivated_List,
    &ett_f1ap_GNB_CU_TNL_Association_To_Add_List,
    &ett_f1ap_GNB_CU_TNL_Association_To_Remove_List,
    &ett_f1ap_GNB_CU_TNL_Association_To_Update_List,
    &ett_f1ap_Cells_to_be_Barred_List,
    &ett_f1ap_Protected_EUTRA_Resources_List,
    &ett_f1ap_GNBCUConfigurationUpdateAcknowledge,
    &ett_f1ap_Cells_Failed_to_be_Activated_List,
    &ett_f1ap_GNB_CU_TNL_Association_Setup_List,
    &ett_f1ap_GNB_CU_TNL_Association_Failed_To_Setup_List,
    &ett_f1ap_GNBCUConfigurationUpdateFailure,
    &ett_f1ap_GNBDUResourceCoordinationRequest,
    &ett_f1ap_GNBDUResourceCoordinationResponse,
    &ett_f1ap_UEContextSetupRequest,
    &ett_f1ap_Candidate_SpCell_List,
    &ett_f1ap_SCell_ToBeSetup_List,
    &ett_f1ap_SRBs_ToBeSetup_List,
    &ett_f1ap_DRBs_ToBeSetup_List,
    &ett_f1ap_UEContextSetupResponse,
    &ett_f1ap_DRBs_Setup_List,
    &ett_f1ap_SRBs_FailedToBeSetup_List,
    &ett_f1ap_DRBs_FailedToBeSetup_List,
    &ett_f1ap_SCell_FailedtoSetup_List,
    &ett_f1ap_SRBs_Setup_List,
    &ett_f1ap_UEContextSetupFailure,
    &ett_f1ap_Potential_SpCell_List,
    &ett_f1ap_UEContextReleaseRequest,
    &ett_f1ap_UEContextReleaseCommand,
    &ett_f1ap_UEContextReleaseComplete,
    &ett_f1ap_UEContextModificationRequest,
    &ett_f1ap_SCell_ToBeSetupMod_List,
    &ett_f1ap_SCell_ToBeRemoved_List,
    &ett_f1ap_SRBs_ToBeSetupMod_List,
    &ett_f1ap_DRBs_ToBeSetupMod_List,
    &ett_f1ap_DRBs_ToBeModified_List,
    &ett_f1ap_SRBs_ToBeReleased_List,
    &ett_f1ap_DRBs_ToBeReleased_List,
    &ett_f1ap_UEContextModificationResponse,
    &ett_f1ap_DRBs_SetupMod_List,
    &ett_f1ap_DRBs_Modified_List,
    &ett_f1ap_SRBs_SetupMod_List,
    &ett_f1ap_SRBs_Modified_List,
    &ett_f1ap_DRBs_FailedToBeModified_List,
    &ett_f1ap_SRBs_FailedToBeSetupMod_List,
    &ett_f1ap_DRBs_FailedToBeSetupMod_List,
    &ett_f1ap_SCell_FailedtoSetupMod_List,
    &ett_f1ap_Associated_SCell_List,
    &ett_f1ap_UEContextModificationFailure,
    &ett_f1ap_UEContextModificationRequired,
    &ett_f1ap_DRBs_Required_ToBeModified_List,
    &ett_f1ap_DRBs_Required_ToBeReleased_List,
    &ett_f1ap_SRBs_Required_ToBeReleased_List,
    &ett_f1ap_UEContextModificationConfirm,
    &ett_f1ap_DRBs_ModifiedConf_List,
    &ett_f1ap_UEContextModificationRefuse,
    &ett_f1ap_WriteReplaceWarningRequest,
    &ett_f1ap_Cells_To_Be_Broadcast_List,
    &ett_f1ap_WriteReplaceWarningResponse,
    &ett_f1ap_Cells_Broadcast_Completed_List,
    &ett_f1ap_PWSCancelRequest,
    &ett_f1ap_Broadcast_To_Be_Cancelled_List,
    &ett_f1ap_PWSCancelResponse,
    &ett_f1ap_Cells_Broadcast_Cancelled_List,
    &ett_f1ap_UEInactivityNotification,
    &ett_f1ap_DRB_Activity_List,
    &ett_f1ap_InitialULRRCMessageTransfer,
    &ett_f1ap_DLRRCMessageTransfer,
    &ett_f1ap_ULRRCMessageTransfer,
    &ett_f1ap_PrivateMessage,
    &ett_f1ap_SystemInformationDeliveryCommand,
    &ett_f1ap_Paging,
    &ett_f1ap_PagingCell_list,
    &ett_f1ap_Notify,
    &ett_f1ap_DRB_Notify_List,
    &ett_f1ap_NetworkAccessRateReduction,
    &ett_f1ap_PWSRestartIndication,
    &ett_f1ap_NR_CGI_List_For_Restart_List,
    &ett_f1ap_PWSFailureIndication,
    &ett_f1ap_PWS_Failed_NR_CGI_List,
    &ett_f1ap_GNBDUStatusIndication,
    &ett_f1ap_RRCDeliveryReport,
    &ett_f1ap_F1RemovalRequest,
    &ett_f1ap_F1RemovalResponse,
    &ett_f1ap_F1RemovalFailure,
    &ett_f1ap_F1AP_PDU,
    &ett_f1ap_InitiatingMessage,
    &ett_f1ap_SuccessfulOutcome,
    &ett_f1ap_UnsuccessfulOutcome,

/*--- End of included file: packet-f1ap-ettarr.c ---*/
#line 285 "./asn1/f1ap/packet-f1ap-template.c"
  };

  /* Register protocol */
  proto_f1ap = proto_register_protocol(PNAME, PSNAME, PFNAME);
  /* Register fields and subtrees */
  proto_register_field_array(proto_f1ap, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));

  /* Register dissector */
  f1ap_handle = register_dissector("f1ap", dissect_f1ap, proto_f1ap);

  /* Register dissector tables */
  f1ap_ies_dissector_table = register_dissector_table("f1ap.ies", "F1AP-PROTOCOL-IES", proto_f1ap, FT_UINT32, BASE_DEC);
  f1ap_extension_dissector_table = register_dissector_table("f1ap.extension", "F1AP-PROTOCOL-EXTENSION", proto_f1ap, FT_UINT32, BASE_DEC);
  f1ap_proc_imsg_dissector_table = register_dissector_table("f1ap.proc.imsg", "F1AP-ELEMENTARY-PROCEDURE InitiatingMessage", proto_f1ap, FT_UINT32, BASE_DEC);
  f1ap_proc_sout_dissector_table = register_dissector_table("f1ap.proc.sout", "F1AP-ELEMENTARY-PROCEDURE SuccessfulOutcome", proto_f1ap, FT_UINT32, BASE_DEC);
  f1ap_proc_uout_dissector_table = register_dissector_table("f1ap.proc.uout", "F1AP-ELEMENTARY-PROCEDURE UnsuccessfulOutcome", proto_f1ap, FT_UINT32, BASE_DEC);
}

void
proto_reg_handoff_f1ap(void)
{
  dissector_add_uint_with_preference("sctp.port", SCTP_PORT_F1AP, f1ap_handle);
  dissector_add_uint("sctp.ppi", F1AP_PROTOCOL_ID, f1ap_handle);
  nr_rrc_ul_ccch_handle = find_dissector_add_dependency("nr-rrc.ul.ccch", proto_f1ap);
  nr_rrc_dl_ccch_handle = find_dissector_add_dependency("nr-rrc.dl.ccch", proto_f1ap);
  nr_rrc_ul_dcch_handle = find_dissector_add_dependency("nr-rrc.ul.dcch", proto_f1ap);
  nr_pdcp_handle = find_dissector_add_dependency("pdcp-nr", proto_f1ap);

/*--- Included file: packet-f1ap-dis-tab.c ---*/
#line 1 "./asn1/f1ap/packet-f1ap-dis-tab.c"
  dissector_add_uint("f1ap.ies", id_Cause, create_dissector_handle(dissect_Cause_PDU, proto_f1ap));
  dissector_add_uint("f1ap.ies", id_Cells_Failed_to_be_Activated_List, create_dissector_handle(dissect_Cells_Failed_to_be_Activated_List_PDU, proto_f1ap));
  dissector_add_uint("f1ap.ies", id_Cells_Failed_to_be_Activated_List_Item, create_dissector_handle(dissect_Cells_Failed_to_be_Activated_List_Item_PDU, proto_f1ap));
  dissector_add_uint("f1ap.ies", id_Cells_to_be_Activated_List, create_dissector_handle(dissect_Cells_to_be_Activated_List_PDU, proto_f1ap));
  dissector_add_uint("f1ap.ies", id_Cells_to_be_Activated_List_Item, create_dissector_handle(dissect_Cells_to_be_Activated_List_Item_PDU, proto_f1ap));
  dissector_add_uint("f1ap.ies", id_Cells_to_be_Deactivated_List, create_dissector_handle(dissect_Cells_to_be_Deactivated_List_PDU, proto_f1ap));
  dissector_add_uint("f1ap.ies", id_Cells_to_be_Deactivated_List_Item, create_dissector_handle(dissect_Cells_to_be_Deactivated_List_Item_PDU, proto_f1ap));
  dissector_add_uint("f1ap.ies", id_CriticalityDiagnostics, create_dissector_handle(dissect_CriticalityDiagnostics_PDU, proto_f1ap));
  dissector_add_uint("f1ap.ies", id_CUtoDURRCInformation, create_dissector_handle(dissect_CUtoDURRCInformation_PDU, proto_f1ap));
  dissector_add_uint("f1ap.ies", id_DRBs_FailedToBeModified_Item, create_dissector_handle(dissect_DRBs_FailedToBeModified_Item_PDU, proto_f1ap));
  dissector_add_uint("f1ap.ies", id_DRBs_FailedToBeModified_List, create_dissector_handle(dissect_DRBs_FailedToBeModified_List_PDU, proto_f1ap));
  dissector_add_uint("f1ap.ies", id_DRBs_FailedToBeSetup_Item, create_dissector_handle(dissect_DRBs_FailedToBeSetup_Item_PDU, proto_f1ap));
  dissector_add_uint("f1ap.ies", id_DRBs_FailedToBeSetup_List, create_dissector_handle(dissect_DRBs_FailedToBeSetup_List_PDU, proto_f1ap));
  dissector_add_uint("f1ap.ies", id_DRBs_FailedToBeSetupMod_Item, create_dissector_handle(dissect_DRBs_FailedToBeSetupMod_Item_PDU, proto_f1ap));
  dissector_add_uint("f1ap.ies", id_DRBs_FailedToBeSetupMod_List, create_dissector_handle(dissect_DRBs_FailedToBeSetupMod_List_PDU, proto_f1ap));
  dissector_add_uint("f1ap.ies", id_DRBs_ModifiedConf_Item, create_dissector_handle(dissect_DRBs_ModifiedConf_Item_PDU, proto_f1ap));
  dissector_add_uint("f1ap.ies", id_DRBs_ModifiedConf_List, create_dissector_handle(dissect_DRBs_ModifiedConf_List_PDU, proto_f1ap));
  dissector_add_uint("f1ap.ies", id_DRBs_Modified_Item, create_dissector_handle(dissect_DRBs_Modified_Item_PDU, proto_f1ap));
  dissector_add_uint("f1ap.ies", id_DRBs_Modified_List, create_dissector_handle(dissect_DRBs_Modified_List_PDU, proto_f1ap));
  dissector_add_uint("f1ap.ies", id_DRBs_Required_ToBeModified_Item, create_dissector_handle(dissect_DRBs_Required_ToBeModified_Item_PDU, proto_f1ap));
  dissector_add_uint("f1ap.ies", id_DRBs_Required_ToBeModified_List, create_dissector_handle(dissect_DRBs_Required_ToBeModified_List_PDU, proto_f1ap));
  dissector_add_uint("f1ap.ies", id_DRBs_Required_ToBeReleased_Item, create_dissector_handle(dissect_DRBs_Required_ToBeReleased_Item_PDU, proto_f1ap));
  dissector_add_uint("f1ap.ies", id_DRBs_Required_ToBeReleased_List, create_dissector_handle(dissect_DRBs_Required_ToBeReleased_List_PDU, proto_f1ap));
  dissector_add_uint("f1ap.ies", id_DRBs_Setup_Item, create_dissector_handle(dissect_DRBs_Setup_Item_PDU, proto_f1ap));
  dissector_add_uint("f1ap.ies", id_DRBs_Setup_List, create_dissector_handle(dissect_DRBs_Setup_List_PDU, proto_f1ap));
  dissector_add_uint("f1ap.ies", id_DRBs_SetupMod_Item, create_dissector_handle(dissect_DRBs_SetupMod_Item_PDU, proto_f1ap));
  dissector_add_uint("f1ap.ies", id_DRBs_SetupMod_List, create_dissector_handle(dissect_DRBs_SetupMod_List_PDU, proto_f1ap));
  dissector_add_uint("f1ap.ies", id_DRBs_ToBeModified_Item, create_dissector_handle(dissect_DRBs_ToBeModified_Item_PDU, proto_f1ap));
  dissector_add_uint("f1ap.ies", id_DRBs_ToBeModified_List, create_dissector_handle(dissect_DRBs_ToBeModified_List_PDU, proto_f1ap));
  dissector_add_uint("f1ap.ies", id_DRBs_ToBeReleased_Item, create_dissector_handle(dissect_DRBs_ToBeReleased_Item_PDU, proto_f1ap));
  dissector_add_uint("f1ap.ies", id_DRBs_ToBeReleased_List, create_dissector_handle(dissect_DRBs_ToBeReleased_List_PDU, proto_f1ap));
  dissector_add_uint("f1ap.ies", id_DRBs_ToBeSetup_Item, create_dissector_handle(dissect_DRBs_ToBeSetup_Item_PDU, proto_f1ap));
  dissector_add_uint("f1ap.ies", id_DRBs_ToBeSetup_List, create_dissector_handle(dissect_DRBs_ToBeSetup_List_PDU, proto_f1ap));
  dissector_add_uint("f1ap.ies", id_DRBs_ToBeSetupMod_Item, create_dissector_handle(dissect_DRBs_ToBeSetupMod_Item_PDU, proto_f1ap));
  dissector_add_uint("f1ap.ies", id_DRBs_ToBeSetupMod_List, create_dissector_handle(dissect_DRBs_ToBeSetupMod_List_PDU, proto_f1ap));
  dissector_add_uint("f1ap.ies", id_DRXCycle, create_dissector_handle(dissect_DRXCycle_PDU, proto_f1ap));
  dissector_add_uint("f1ap.ies", id_DUtoCURRCInformation, create_dissector_handle(dissect_DUtoCURRCInformation_PDU, proto_f1ap));
  dissector_add_uint("f1ap.ies", id_gNB_CU_UE_F1AP_ID, create_dissector_handle(dissect_GNB_CU_UE_F1AP_ID_PDU, proto_f1ap));
  dissector_add_uint("f1ap.ies", id_gNB_DU_UE_F1AP_ID, create_dissector_handle(dissect_GNB_DU_UE_F1AP_ID_PDU, proto_f1ap));
  dissector_add_uint("f1ap.ies", id_gNB_DU_ID, create_dissector_handle(dissect_GNB_DU_ID_PDU, proto_f1ap));
  dissector_add_uint("f1ap.ies", id_GNB_DU_Served_Cells_Item, create_dissector_handle(dissect_GNB_DU_Served_Cells_Item_PDU, proto_f1ap));
  dissector_add_uint("f1ap.ies", id_gNB_DU_Served_Cells_List, create_dissector_handle(dissect_GNB_DU_Served_Cells_List_PDU, proto_f1ap));
  dissector_add_uint("f1ap.ies", id_gNB_DU_Name, create_dissector_handle(dissect_GNB_DU_Name_PDU, proto_f1ap));
  dissector_add_uint("f1ap.ies", id_oldgNB_DU_UE_F1AP_ID, create_dissector_handle(dissect_GNB_DU_UE_F1AP_ID_PDU, proto_f1ap));
  dissector_add_uint("f1ap.ies", id_ResetType, create_dissector_handle(dissect_ResetType_PDU, proto_f1ap));
  dissector_add_uint("f1ap.ies", id_ResourceCoordinationTransferContainer, create_dissector_handle(dissect_ResourceCoordinationTransferContainer_PDU, proto_f1ap));
  dissector_add_uint("f1ap.ies", id_RRCContainer, create_dissector_handle(dissect_RRCContainer_PDU, proto_f1ap));
  dissector_add_uint("f1ap.ies", id_SCell_ToBeRemoved_Item, create_dissector_handle(dissect_SCell_ToBeRemoved_Item_PDU, proto_f1ap));
  dissector_add_uint("f1ap.ies", id_SCell_ToBeRemoved_List, create_dissector_handle(dissect_SCell_ToBeRemoved_List_PDU, proto_f1ap));
  dissector_add_uint("f1ap.ies", id_SCell_ToBeSetup_Item, create_dissector_handle(dissect_SCell_ToBeSetup_Item_PDU, proto_f1ap));
  dissector_add_uint("f1ap.ies", id_SCell_ToBeSetup_List, create_dissector_handle(dissect_SCell_ToBeSetup_List_PDU, proto_f1ap));
  dissector_add_uint("f1ap.ies", id_SCell_ToBeSetupMod_Item, create_dissector_handle(dissect_SCell_ToBeSetupMod_Item_PDU, proto_f1ap));
  dissector_add_uint("f1ap.ies", id_SCell_ToBeSetupMod_List, create_dissector_handle(dissect_SCell_ToBeSetupMod_List_PDU, proto_f1ap));
  dissector_add_uint("f1ap.ies", id_Served_Cells_To_Add_Item, create_dissector_handle(dissect_Served_Cells_To_Add_Item_PDU, proto_f1ap));
  dissector_add_uint("f1ap.ies", id_Served_Cells_To_Add_List, create_dissector_handle(dissect_Served_Cells_To_Add_List_PDU, proto_f1ap));
  dissector_add_uint("f1ap.ies", id_Served_Cells_To_Delete_Item, create_dissector_handle(dissect_Served_Cells_To_Delete_Item_PDU, proto_f1ap));
  dissector_add_uint("f1ap.ies", id_Served_Cells_To_Delete_List, create_dissector_handle(dissect_Served_Cells_To_Delete_List_PDU, proto_f1ap));
  dissector_add_uint("f1ap.ies", id_Served_Cells_To_Modify_Item, create_dissector_handle(dissect_Served_Cells_To_Modify_Item_PDU, proto_f1ap));
  dissector_add_uint("f1ap.ies", id_Served_Cells_To_Modify_List, create_dissector_handle(dissect_Served_Cells_To_Modify_List_PDU, proto_f1ap));
  dissector_add_uint("f1ap.ies", id_SpCell_ID, create_dissector_handle(dissect_NRCGI_PDU, proto_f1ap));
  dissector_add_uint("f1ap.ies", id_SRBID, create_dissector_handle(dissect_SRBID_PDU, proto_f1ap));
  dissector_add_uint("f1ap.ies", id_SRBs_FailedToBeSetup_Item, create_dissector_handle(dissect_SRBs_FailedToBeSetup_Item_PDU, proto_f1ap));
  dissector_add_uint("f1ap.ies", id_SRBs_FailedToBeSetup_List, create_dissector_handle(dissect_SRBs_FailedToBeSetup_List_PDU, proto_f1ap));
  dissector_add_uint("f1ap.ies", id_SRBs_FailedToBeSetupMod_Item, create_dissector_handle(dissect_SRBs_FailedToBeSetupMod_Item_PDU, proto_f1ap));
  dissector_add_uint("f1ap.ies", id_SRBs_FailedToBeSetupMod_List, create_dissector_handle(dissect_SRBs_FailedToBeSetupMod_List_PDU, proto_f1ap));
  dissector_add_uint("f1ap.ies", id_SRBs_Required_ToBeReleased_Item, create_dissector_handle(dissect_SRBs_Required_ToBeReleased_Item_PDU, proto_f1ap));
  dissector_add_uint("f1ap.ies", id_SRBs_Required_ToBeReleased_List, create_dissector_handle(dissect_SRBs_Required_ToBeReleased_List_PDU, proto_f1ap));
  dissector_add_uint("f1ap.ies", id_SRBs_ToBeReleased_Item, create_dissector_handle(dissect_SRBs_ToBeReleased_Item_PDU, proto_f1ap));
  dissector_add_uint("f1ap.ies", id_SRBs_ToBeReleased_List, create_dissector_handle(dissect_SRBs_ToBeReleased_List_PDU, proto_f1ap));
  dissector_add_uint("f1ap.ies", id_SRBs_ToBeSetup_Item, create_dissector_handle(dissect_SRBs_ToBeSetup_Item_PDU, proto_f1ap));
  dissector_add_uint("f1ap.ies", id_SRBs_ToBeSetup_List, create_dissector_handle(dissect_SRBs_ToBeSetup_List_PDU, proto_f1ap));
  dissector_add_uint("f1ap.ies", id_SRBs_ToBeSetupMod_Item, create_dissector_handle(dissect_SRBs_ToBeSetupMod_Item_PDU, proto_f1ap));
  dissector_add_uint("f1ap.ies", id_SRBs_ToBeSetupMod_List, create_dissector_handle(dissect_SRBs_ToBeSetupMod_List_PDU, proto_f1ap));
  dissector_add_uint("f1ap.ies", id_TimeToWait, create_dissector_handle(dissect_TimeToWait_PDU, proto_f1ap));
  dissector_add_uint("f1ap.ies", id_TransactionID, create_dissector_handle(dissect_TransactionID_PDU, proto_f1ap));
  dissector_add_uint("f1ap.ies", id_TransmissionActionIndicator, create_dissector_handle(dissect_TransmissionActionIndicator_PDU, proto_f1ap));
  dissector_add_uint("f1ap.ies", id_UE_associatedLogicalF1_ConnectionItem, create_dissector_handle(dissect_UE_associatedLogicalF1_ConnectionItem_PDU, proto_f1ap));
  dissector_add_uint("f1ap.ies", id_UE_associatedLogicalF1_ConnectionListResAck, create_dissector_handle(dissect_UE_associatedLogicalF1_ConnectionListResAck_PDU, proto_f1ap));
  dissector_add_uint("f1ap.ies", id_gNB_CU_Name, create_dissector_handle(dissect_GNB_CU_Name_PDU, proto_f1ap));
  dissector_add_uint("f1ap.ies", id_SCell_FailedtoSetup_List, create_dissector_handle(dissect_SCell_FailedtoSetup_List_PDU, proto_f1ap));
  dissector_add_uint("f1ap.ies", id_SCell_FailedtoSetup_Item, create_dissector_handle(dissect_SCell_FailedtoSetup_Item_PDU, proto_f1ap));
  dissector_add_uint("f1ap.ies", id_SCell_FailedtoSetupMod_List, create_dissector_handle(dissect_SCell_FailedtoSetupMod_List_PDU, proto_f1ap));
  dissector_add_uint("f1ap.ies", id_SCell_FailedtoSetupMod_Item, create_dissector_handle(dissect_SCell_FailedtoSetupMod_Item_PDU, proto_f1ap));
  dissector_add_uint("f1ap.ies", id_RRCReconfigurationCompleteIndicator, create_dissector_handle(dissect_RRCReconfigurationCompleteIndicator_PDU, proto_f1ap));
  dissector_add_uint("f1ap.ies", id_Cells_Status_Item, create_dissector_handle(dissect_Cells_Status_Item_PDU, proto_f1ap));
  dissector_add_uint("f1ap.ies", id_Cells_Status_List, create_dissector_handle(dissect_Cells_Status_List_PDU, proto_f1ap));
  dissector_add_uint("f1ap.ies", id_Candidate_SpCell_List, create_dissector_handle(dissect_Candidate_SpCell_List_PDU, proto_f1ap));
  dissector_add_uint("f1ap.ies", id_Candidate_SpCell_Item, create_dissector_handle(dissect_Candidate_SpCell_Item_PDU, proto_f1ap));
  dissector_add_uint("f1ap.ies", id_Potential_SpCell_List, create_dissector_handle(dissect_Potential_SpCell_List_PDU, proto_f1ap));
  dissector_add_uint("f1ap.ies", id_Potential_SpCell_Item, create_dissector_handle(dissect_Potential_SpCell_Item_PDU, proto_f1ap));
  dissector_add_uint("f1ap.ies", id_FullConfiguration, create_dissector_handle(dissect_FullConfiguration_PDU, proto_f1ap));
  dissector_add_uint("f1ap.ies", id_C_RNTI, create_dissector_handle(dissect_C_RNTI_PDU, proto_f1ap));
  dissector_add_uint("f1ap.ies", id_SpCellULConfigured, create_dissector_handle(dissect_CellULConfigured_PDU, proto_f1ap));
  dissector_add_uint("f1ap.ies", id_InactivityMonitoringRequest, create_dissector_handle(dissect_InactivityMonitoringRequest_PDU, proto_f1ap));
  dissector_add_uint("f1ap.ies", id_InactivityMonitoringResponse, create_dissector_handle(dissect_InactivityMonitoringResponse_PDU, proto_f1ap));
  dissector_add_uint("f1ap.ies", id_DRB_Activity_Item, create_dissector_handle(dissect_DRB_Activity_Item_PDU, proto_f1ap));
  dissector_add_uint("f1ap.ies", id_DRB_Activity_List, create_dissector_handle(dissect_DRB_Activity_List_PDU, proto_f1ap));
  dissector_add_uint("f1ap.ies", id_EUTRA_NR_CellResourceCoordinationReq_Container, create_dissector_handle(dissect_EUTRA_NR_CellResourceCoordinationReq_Container_PDU, proto_f1ap));
  dissector_add_uint("f1ap.ies", id_EUTRA_NR_CellResourceCoordinationReqAck_Container, create_dissector_handle(dissect_EUTRA_NR_CellResourceCoordinationReqAck_Container_PDU, proto_f1ap));
  dissector_add_uint("f1ap.ies", id_Protected_EUTRA_Resources_List, create_dissector_handle(dissect_Protected_EUTRA_Resources_List_PDU, proto_f1ap));
  dissector_add_uint("f1ap.ies", id_RequestType, create_dissector_handle(dissect_RequestType_PDU, proto_f1ap));
  dissector_add_uint("f1ap.ies", id_ServCellIndex, create_dissector_handle(dissect_ServCellIndex_PDU, proto_f1ap));
  dissector_add_uint("f1ap.ies", id_RAT_FrequencyPriorityInformation, create_dissector_handle(dissect_RAT_FrequencyPriorityInformation_PDU, proto_f1ap));
  dissector_add_uint("f1ap.ies", id_ExecuteDuplication, create_dissector_handle(dissect_ExecuteDuplication_PDU, proto_f1ap));
  dissector_add_uint("f1ap.ies", id_NRCGI, create_dissector_handle(dissect_NRCGI_PDU, proto_f1ap));
  dissector_add_uint("f1ap.ies", id_PagingCell_Item, create_dissector_handle(dissect_PagingCell_Item_PDU, proto_f1ap));
  dissector_add_uint("f1ap.ies", id_PagingCell_List, create_dissector_handle(dissect_PagingCell_list_PDU, proto_f1ap));
  dissector_add_uint("f1ap.ies", id_PagingDRX, create_dissector_handle(dissect_PagingDRX_PDU, proto_f1ap));
  dissector_add_uint("f1ap.ies", id_PagingPriority, create_dissector_handle(dissect_PagingPriority_PDU, proto_f1ap));
  dissector_add_uint("f1ap.ies", id_SItype_List, create_dissector_handle(dissect_SItype_List_PDU, proto_f1ap));
  dissector_add_uint("f1ap.ies", id_UEIdentityIndexValue, create_dissector_handle(dissect_UEIdentityIndexValue_PDU, proto_f1ap));
  dissector_add_uint("f1ap.ies", id_GNB_CU_TNL_Association_To_Add_Item, create_dissector_handle(dissect_GNB_CU_TNL_Association_To_Add_Item_PDU, proto_f1ap));
  dissector_add_uint("f1ap.ies", id_GNB_CU_TNL_Association_To_Add_List, create_dissector_handle(dissect_GNB_CU_TNL_Association_To_Add_List_PDU, proto_f1ap));
  dissector_add_uint("f1ap.ies", id_GNB_CU_TNL_Association_To_Remove_Item, create_dissector_handle(dissect_GNB_CU_TNL_Association_To_Remove_Item_PDU, proto_f1ap));
  dissector_add_uint("f1ap.ies", id_GNB_CU_TNL_Association_To_Remove_List, create_dissector_handle(dissect_GNB_CU_TNL_Association_To_Remove_List_PDU, proto_f1ap));
  dissector_add_uint("f1ap.ies", id_GNB_CU_TNL_Association_To_Update_Item, create_dissector_handle(dissect_GNB_CU_TNL_Association_To_Update_Item_PDU, proto_f1ap));
  dissector_add_uint("f1ap.ies", id_GNB_CU_TNL_Association_To_Update_List, create_dissector_handle(dissect_GNB_CU_TNL_Association_To_Update_List_PDU, proto_f1ap));
  dissector_add_uint("f1ap.ies", id_MaskedIMEISV, create_dissector_handle(dissect_MaskedIMEISV_PDU, proto_f1ap));
  dissector_add_uint("f1ap.ies", id_PagingIdentity, create_dissector_handle(dissect_PagingIdentity_PDU, proto_f1ap));
  dissector_add_uint("f1ap.ies", id_DUtoCURRCContainer, create_dissector_handle(dissect_DUtoCURRCContainer_PDU, proto_f1ap));
  dissector_add_uint("f1ap.ies", id_Cells_to_be_Barred_List, create_dissector_handle(dissect_Cells_to_be_Barred_List_PDU, proto_f1ap));
  dissector_add_uint("f1ap.ies", id_Cells_to_be_Barred_Item, create_dissector_handle(dissect_Cells_to_be_Barred_Item_PDU, proto_f1ap));
  dissector_add_uint("f1ap.ies", id_GNB_CU_TNL_Association_Setup_List, create_dissector_handle(dissect_GNB_CU_TNL_Association_Setup_List_PDU, proto_f1ap));
  dissector_add_uint("f1ap.ies", id_GNB_CU_TNL_Association_Setup_Item, create_dissector_handle(dissect_GNB_CU_TNL_Association_Setup_Item_PDU, proto_f1ap));
  dissector_add_uint("f1ap.ies", id_GNB_CU_TNL_Association_Failed_To_Setup_List, create_dissector_handle(dissect_GNB_CU_TNL_Association_Failed_To_Setup_List_PDU, proto_f1ap));
  dissector_add_uint("f1ap.ies", id_GNB_CU_TNL_Association_Failed_To_Setup_Item, create_dissector_handle(dissect_GNB_CU_TNL_Association_Failed_To_Setup_Item_PDU, proto_f1ap));
  dissector_add_uint("f1ap.ies", id_DRB_Notify_Item, create_dissector_handle(dissect_DRB_Notify_Item_PDU, proto_f1ap));
  dissector_add_uint("f1ap.ies", id_DRB_Notify_List, create_dissector_handle(dissect_DRB_Notify_List_PDU, proto_f1ap));
  dissector_add_uint("f1ap.ies", id_PWSSystemInformation, create_dissector_handle(dissect_PWSSystemInformation_PDU, proto_f1ap));
  dissector_add_uint("f1ap.ies", id_RepetitionPeriod, create_dissector_handle(dissect_RepetitionPeriod_PDU, proto_f1ap));
  dissector_add_uint("f1ap.ies", id_NumberofBroadcastRequest, create_dissector_handle(dissect_NumberofBroadcastRequest_PDU, proto_f1ap));
  dissector_add_uint("f1ap.ies", id_Cells_To_Be_Broadcast_List, create_dissector_handle(dissect_Cells_To_Be_Broadcast_List_PDU, proto_f1ap));
  dissector_add_uint("f1ap.ies", id_Cells_To_Be_Broadcast_Item, create_dissector_handle(dissect_Cells_To_Be_Broadcast_Item_PDU, proto_f1ap));
  dissector_add_uint("f1ap.ies", id_Cells_Broadcast_Completed_List, create_dissector_handle(dissect_Cells_Broadcast_Completed_List_PDU, proto_f1ap));
  dissector_add_uint("f1ap.ies", id_Cells_Broadcast_Completed_Item, create_dissector_handle(dissect_Cells_Broadcast_Completed_Item_PDU, proto_f1ap));
  dissector_add_uint("f1ap.ies", id_Broadcast_To_Be_Cancelled_List, create_dissector_handle(dissect_Broadcast_To_Be_Cancelled_List_PDU, proto_f1ap));
  dissector_add_uint("f1ap.ies", id_Broadcast_To_Be_Cancelled_Item, create_dissector_handle(dissect_Broadcast_To_Be_Cancelled_Item_PDU, proto_f1ap));
  dissector_add_uint("f1ap.ies", id_Cells_Broadcast_Cancelled_List, create_dissector_handle(dissect_Cells_Broadcast_Cancelled_List_PDU, proto_f1ap));
  dissector_add_uint("f1ap.ies", id_Cells_Broadcast_Cancelled_Item, create_dissector_handle(dissect_Cells_Broadcast_Cancelled_Item_PDU, proto_f1ap));
  dissector_add_uint("f1ap.ies", id_NR_CGI_List_For_Restart_List, create_dissector_handle(dissect_NR_CGI_List_For_Restart_List_PDU, proto_f1ap));
  dissector_add_uint("f1ap.ies", id_NR_CGI_List_For_Restart_Item, create_dissector_handle(dissect_NR_CGI_List_For_Restart_Item_PDU, proto_f1ap));
  dissector_add_uint("f1ap.ies", id_PWS_Failed_NR_CGI_List, create_dissector_handle(dissect_PWS_Failed_NR_CGI_List_PDU, proto_f1ap));
  dissector_add_uint("f1ap.ies", id_PWS_Failed_NR_CGI_Item, create_dissector_handle(dissect_PWS_Failed_NR_CGI_Item_PDU, proto_f1ap));
  dissector_add_uint("f1ap.ies", id_ConfirmedUEID, create_dissector_handle(dissect_GNB_DU_UE_F1AP_ID_PDU, proto_f1ap));
  dissector_add_uint("f1ap.ies", id_Cancel_all_Warning_Messages_Indicator, create_dissector_handle(dissect_Cancel_all_Warning_Messages_Indicator_PDU, proto_f1ap));
  dissector_add_uint("f1ap.ies", id_GNB_DU_UE_AMBR_UL, create_dissector_handle(dissect_BitRate_PDU, proto_f1ap));
  dissector_add_uint("f1ap.ies", id_DRXConfigurationIndicator, create_dissector_handle(dissect_DRXConfigurationIndicator_PDU, proto_f1ap));
  dissector_add_uint("f1ap.ies", id_GNB_DUConfigurationQuery, create_dissector_handle(dissect_GNB_DUConfigurationQuery_PDU, proto_f1ap));
  dissector_add_uint("f1ap.ies", id_DRB_Information, create_dissector_handle(dissect_DRB_Information_PDU, proto_f1ap));
  dissector_add_uint("f1ap.ies", id_ServingPLMN, create_dissector_handle(dissect_PLMN_Identity_PDU, proto_f1ap));
  dissector_add_uint("f1ap.ies", id_Protected_EUTRA_Resources_Item, create_dissector_handle(dissect_Protected_EUTRA_Resources_Item_PDU, proto_f1ap));
  dissector_add_uint("f1ap.ies", id_GNB_CU_RRC_Version, create_dissector_handle(dissect_RRC_Version_PDU, proto_f1ap));
  dissector_add_uint("f1ap.ies", id_GNB_DU_RRC_Version, create_dissector_handle(dissect_RRC_Version_PDU, proto_f1ap));
  dissector_add_uint("f1ap.ies", id_GNBDUOverloadInformation, create_dissector_handle(dissect_GNBDUOverloadInformation_PDU, proto_f1ap));
  dissector_add_uint("f1ap.ies", id_RLCFailureIndication, create_dissector_handle(dissect_RLCFailureIndication_PDU, proto_f1ap));
  dissector_add_uint("f1ap.ies", id_UplinkTxDirectCurrentListInformation, create_dissector_handle(dissect_UplinkTxDirectCurrentListInformation_PDU, proto_f1ap));
  dissector_add_uint("f1ap.ies", id_SULAccessIndication, create_dissector_handle(dissect_SULAccessIndication_PDU, proto_f1ap));
  dissector_add_uint("f1ap.ies", id_ServingCellMO, create_dissector_handle(dissect_ServingCellMO_PDU, proto_f1ap));
  dissector_add_uint("f1ap.ies", id_RRCDeliveryStatusRequest, create_dissector_handle(dissect_RRCDeliveryStatusRequest_PDU, proto_f1ap));
  dissector_add_uint("f1ap.ies", id_RRCDeliveryStatus, create_dissector_handle(dissect_RRCDeliveryStatus_PDU, proto_f1ap));
  dissector_add_uint("f1ap.ies", id_Dedicated_SIDelivery_NeededUE_List, create_dissector_handle(dissect_Dedicated_SIDelivery_NeededUE_List_PDU, proto_f1ap));
  dissector_add_uint("f1ap.ies", id_Dedicated_SIDelivery_NeededUE_Item, create_dissector_handle(dissect_Dedicated_SIDelivery_NeededUE_Item_PDU, proto_f1ap));
  dissector_add_uint("f1ap.ies", id_Associated_SCell_List, create_dissector_handle(dissect_Associated_SCell_List_PDU, proto_f1ap));
  dissector_add_uint("f1ap.ies", id_Associated_SCell_Item, create_dissector_handle(dissect_Associated_SCell_Item_PDU, proto_f1ap));
  dissector_add_uint("f1ap.ies", id_SRBs_Setup_List, create_dissector_handle(dissect_SRBs_Setup_List_PDU, proto_f1ap));
  dissector_add_uint("f1ap.ies", id_SRBs_Setup_Item, create_dissector_handle(dissect_SRBs_Setup_Item_PDU, proto_f1ap));
  dissector_add_uint("f1ap.ies", id_SRBs_SetupMod_List, create_dissector_handle(dissect_SRBs_SetupMod_List_PDU, proto_f1ap));
  dissector_add_uint("f1ap.ies", id_SRBs_SetupMod_Item, create_dissector_handle(dissect_SRBs_SetupMod_Item_PDU, proto_f1ap));
  dissector_add_uint("f1ap.ies", id_SRBs_Modified_List, create_dissector_handle(dissect_SRBs_Modified_List_PDU, proto_f1ap));
  dissector_add_uint("f1ap.ies", id_SRBs_Modified_Item, create_dissector_handle(dissect_SRBs_Modified_Item_PDU, proto_f1ap));
  dissector_add_uint("f1ap.ies", id_IgnoreResourceCoordinationContainer, create_dissector_handle(dissect_IgnoreResourceCoordinationContainer_PDU, proto_f1ap));
  dissector_add_uint("f1ap.ies", id_NeedforGap, create_dissector_handle(dissect_NeedforGap_PDU, proto_f1ap));
  dissector_add_uint("f1ap.ies", id_PagingOrigin, create_dissector_handle(dissect_PagingOrigin_PDU, proto_f1ap));
  dissector_add_uint("f1ap.ies", id_new_gNB_CU_UE_F1AP_ID, create_dissector_handle(dissect_GNB_CU_UE_F1AP_ID_PDU, proto_f1ap));
  dissector_add_uint("f1ap.ies", id_RedirectedRRCmessage, create_dissector_handle(dissect_RedirectedRRCmessage_PDU, proto_f1ap));
  dissector_add_uint("f1ap.ies", id_new_gNB_DU_UE_F1AP_ID, create_dissector_handle(dissect_GNB_DU_UE_F1AP_ID_PDU, proto_f1ap));
  dissector_add_uint("f1ap.ies", id_PLMNAssistanceInfoForNetShar, create_dissector_handle(dissect_PLMN_Identity_PDU, proto_f1ap));
  dissector_add_uint("f1ap.ies", id_UEContextNotRetrievable, create_dissector_handle(dissect_UEContextNotRetrievable_PDU, proto_f1ap));
  dissector_add_uint("f1ap.ies", id_SelectedPLMNID, create_dissector_handle(dissect_PLMN_Identity_PDU, proto_f1ap));
  dissector_add_uint("f1ap.ies", id_UAC_Assistance_Info, create_dissector_handle(dissect_UAC_Assistance_Info_PDU, proto_f1ap));
  dissector_add_uint("f1ap.ies", id_RANUEID, create_dissector_handle(dissect_RANUEID_PDU, proto_f1ap));
  dissector_add_uint("f1ap.ies", id_GNB_DU_TNL_Association_To_Remove_Item, create_dissector_handle(dissect_GNB_DU_TNL_Association_To_Remove_Item_PDU, proto_f1ap));
  dissector_add_uint("f1ap.ies", id_GNB_DU_TNL_Association_To_Remove_List, create_dissector_handle(dissect_GNB_DU_TNL_Association_To_Remove_List_PDU, proto_f1ap));
  dissector_add_uint("f1ap.ies", id_RRCContainer_RRCSetupComplete, create_dissector_handle(dissect_RRCContainer_RRCSetupComplete_PDU, proto_f1ap));
  dissector_add_uint("f1ap.extension", id_gNB_CUSystemInformation, create_dissector_handle(dissect_GNB_CUSystemInformation_PDU, proto_f1ap));
  dissector_add_uint("f1ap.extension", id_HandoverPreparationInformation, create_dissector_handle(dissect_HandoverPreparationInformation_PDU, proto_f1ap));
  dissector_add_uint("f1ap.extension", id_TAISliceSupportList, create_dissector_handle(dissect_SliceSupportList_PDU, proto_f1ap));
  dissector_add_uint("f1ap.extension", id_RANAC, create_dissector_handle(dissect_RANAC_PDU, proto_f1ap));
  dissector_add_uint("f1ap.extension", id_RLC_Status, create_dissector_handle(dissect_RLC_Status_PDU, proto_f1ap));
  dissector_add_uint("f1ap.extension", id_DLPDCPSNLength, create_dissector_handle(dissect_PDCPSNLength_PDU, proto_f1ap));
  dissector_add_uint("f1ap.extension", id_MeasurementTimingConfiguration, create_dissector_handle(dissect_MeasurementTimingConfiguration_PDU, proto_f1ap));
  dissector_add_uint("f1ap.extension", id_CellGroupConfig, create_dissector_handle(dissect_CellGroupConfig_PDU, proto_f1ap));
  dissector_add_uint("f1ap.extension", id_DC_Based_Duplication_Configured, create_dissector_handle(dissect_DCBasedDuplicationConfigured_PDU, proto_f1ap));
  dissector_add_uint("f1ap.extension", id_DC_Based_Duplication_Activation, create_dissector_handle(dissect_DuplicationActivation_PDU, proto_f1ap));
  dissector_add_uint("f1ap.extension", id_AvailablePLMNList, create_dissector_handle(dissect_AvailablePLMNList_PDU, proto_f1ap));
  dissector_add_uint("f1ap.extension", id_PDUSessionID, create_dissector_handle(dissect_PDUSessionID_PDU, proto_f1ap));
  dissector_add_uint("f1ap.extension", id_ULPDUSessionAggregateMaximumBitRate, create_dissector_handle(dissect_BitRate_PDU, proto_f1ap));
  dissector_add_uint("f1ap.extension", id_ServingCellMO, create_dissector_handle(dissect_ServingCellMO_PDU, proto_f1ap));
  dissector_add_uint("f1ap.extension", id_QoSFlowMappingIndication, create_dissector_handle(dissect_QoSFlowMappingIndication_PDU, proto_f1ap));
  dissector_add_uint("f1ap.extension", id_BearerTypeChange, create_dissector_handle(dissect_BearerTypeChange_PDU, proto_f1ap));
  dissector_add_uint("f1ap.extension", id_RLCMode, create_dissector_handle(dissect_RLCMode_PDU, proto_f1ap));
  dissector_add_uint("f1ap.extension", id_Duplication_Activation, create_dissector_handle(dissect_DuplicationActivation_PDU, proto_f1ap));
  dissector_add_uint("f1ap.extension", id_DRX_LongCycleStartOffset, create_dissector_handle(dissect_DRX_LongCycleStartOffset_PDU, proto_f1ap));
  dissector_add_uint("f1ap.extension", id_ULPDCPSNLength, create_dissector_handle(dissect_PDCPSNLength_PDU, proto_f1ap));
  dissector_add_uint("f1ap.extension", id_SelectedBandCombinationIndex, create_dissector_handle(dissect_SelectedBandCombinationIndex_PDU, proto_f1ap));
  dissector_add_uint("f1ap.extension", id_SelectedFeatureSetEntryIndex, create_dissector_handle(dissect_SelectedFeatureSetEntryIndex_PDU, proto_f1ap));
  dissector_add_uint("f1ap.extension", id_ResourceCoordinationTransferInformation, create_dissector_handle(dissect_ResourceCoordinationTransferInformation_PDU, proto_f1ap));
  dissector_add_uint("f1ap.extension", id_ExtendedServedPLMNs_List, create_dissector_handle(dissect_ExtendedServedPLMNs_List_PDU, proto_f1ap));
  dissector_add_uint("f1ap.extension", id_ExtendedAvailablePLMN_List, create_dissector_handle(dissect_ExtendedAvailablePLMN_List_PDU, proto_f1ap));
  dissector_add_uint("f1ap.extension", id_latest_RRC_Version_Enhanced, create_dissector_handle(dissect_Latest_RRC_Version_Enhanced_PDU, proto_f1ap));
  dissector_add_uint("f1ap.extension", id_Cell_Direction, create_dissector_handle(dissect_Cell_Direction_PDU, proto_f1ap));
  dissector_add_uint("f1ap.extension", id_Ph_InfoSCG, create_dissector_handle(dissect_Ph_InfoSCG_PDU, proto_f1ap));
  dissector_add_uint("f1ap.extension", id_RequestedBandCombinationIndex, create_dissector_handle(dissect_RequestedBandCombinationIndex_PDU, proto_f1ap));
  dissector_add_uint("f1ap.extension", id_RequestedFeatureSetEntryIndex, create_dissector_handle(dissect_RequestedFeatureSetEntryIndex_PDU, proto_f1ap));
  dissector_add_uint("f1ap.extension", id_RequestedP_MaxFR2, create_dissector_handle(dissect_RequestedP_MaxFR2_PDU, proto_f1ap));
  dissector_add_uint("f1ap.extension", id_DRX_Config, create_dissector_handle(dissect_DRX_Config_PDU, proto_f1ap));
  dissector_add_uint("f1ap.extension", id_UEAssistanceInformation, create_dissector_handle(dissect_UEAssistanceInformation_PDU, proto_f1ap));
  dissector_add_uint("f1ap.extension", id_NotificationInformation, create_dissector_handle(dissect_NotificationInformation_PDU, proto_f1ap));
  dissector_add_uint("f1ap.extension", id_BPLMN_ID_Info_List, create_dissector_handle(dissect_BPLMN_ID_Info_List_PDU, proto_f1ap));
  dissector_add_uint("f1ap.extension", id_TNLAssociationTransportLayerAddressgNBDU, create_dissector_handle(dissect_CP_TransportLayerAddress_PDU, proto_f1ap));
  dissector_add_uint("f1ap.extension", id_portNumber, create_dissector_handle(dissect_PortNumber_PDU, proto_f1ap));
  dissector_add_uint("f1ap.extension", id_AdditionalSIBMessageList, create_dissector_handle(dissect_AdditionalSIBMessageList_PDU, proto_f1ap));
  dissector_add_uint("f1ap.extension", id_Cell_Type, create_dissector_handle(dissect_CellType_PDU, proto_f1ap));
  dissector_add_uint("f1ap.extension", id_IgnorePRACHConfiguration, create_dissector_handle(dissect_IgnorePRACHConfiguration_PDU, proto_f1ap));
  dissector_add_uint("f1ap.extension", id_CG_Config, create_dissector_handle(dissect_CG_Config_PDU, proto_f1ap));
  dissector_add_uint("f1ap.extension", id_PDCCH_BlindDetectionSCG, create_dissector_handle(dissect_PDCCH_BlindDetectionSCG_PDU, proto_f1ap));
  dissector_add_uint("f1ap.extension", id_Requested_PDCCH_BlindDetectionSCG, create_dissector_handle(dissect_Requested_PDCCH_BlindDetectionSCG_PDU, proto_f1ap));
  dissector_add_uint("f1ap.extension", id_Ph_InfoMCG, create_dissector_handle(dissect_Ph_InfoMCG_PDU, proto_f1ap));
  dissector_add_uint("f1ap.extension", id_MeasGapSharingConfig, create_dissector_handle(dissect_MeasGapSharingConfig_PDU, proto_f1ap));
  dissector_add_uint("f1ap.extension", id_systemInformationAreaID, create_dissector_handle(dissect_SystemInformationAreaID_PDU, proto_f1ap));
  dissector_add_uint("f1ap.extension", id_areaScope, create_dissector_handle(dissect_AreaScope_PDU, proto_f1ap));
  dissector_add_uint("f1ap.proc.imsg", id_Reset, create_dissector_handle(dissect_Reset_PDU, proto_f1ap));
  dissector_add_uint("f1ap.proc.sout", id_Reset, create_dissector_handle(dissect_ResetAcknowledge_PDU, proto_f1ap));
  dissector_add_uint("f1ap.proc.imsg", id_F1Setup, create_dissector_handle(dissect_F1SetupRequest_PDU, proto_f1ap));
  dissector_add_uint("f1ap.proc.sout", id_F1Setup, create_dissector_handle(dissect_F1SetupResponse_PDU, proto_f1ap));
  dissector_add_uint("f1ap.proc.uout", id_F1Setup, create_dissector_handle(dissect_F1SetupFailure_PDU, proto_f1ap));
  dissector_add_uint("f1ap.proc.imsg", id_gNBDUConfigurationUpdate, create_dissector_handle(dissect_GNBDUConfigurationUpdate_PDU, proto_f1ap));
  dissector_add_uint("f1ap.proc.sout", id_gNBDUConfigurationUpdate, create_dissector_handle(dissect_GNBDUConfigurationUpdateAcknowledge_PDU, proto_f1ap));
  dissector_add_uint("f1ap.proc.uout", id_gNBDUConfigurationUpdate, create_dissector_handle(dissect_GNBDUConfigurationUpdateFailure_PDU, proto_f1ap));
  dissector_add_uint("f1ap.proc.imsg", id_gNBCUConfigurationUpdate, create_dissector_handle(dissect_GNBCUConfigurationUpdate_PDU, proto_f1ap));
  dissector_add_uint("f1ap.proc.sout", id_gNBCUConfigurationUpdate, create_dissector_handle(dissect_GNBCUConfigurationUpdateAcknowledge_PDU, proto_f1ap));
  dissector_add_uint("f1ap.proc.uout", id_gNBCUConfigurationUpdate, create_dissector_handle(dissect_GNBCUConfigurationUpdateFailure_PDU, proto_f1ap));
  dissector_add_uint("f1ap.proc.imsg", id_UEContextSetup, create_dissector_handle(dissect_UEContextSetupRequest_PDU, proto_f1ap));
  dissector_add_uint("f1ap.proc.sout", id_UEContextSetup, create_dissector_handle(dissect_UEContextSetupResponse_PDU, proto_f1ap));
  dissector_add_uint("f1ap.proc.uout", id_UEContextSetup, create_dissector_handle(dissect_UEContextSetupFailure_PDU, proto_f1ap));
  dissector_add_uint("f1ap.proc.imsg", id_UEContextRelease, create_dissector_handle(dissect_UEContextReleaseCommand_PDU, proto_f1ap));
  dissector_add_uint("f1ap.proc.sout", id_UEContextRelease, create_dissector_handle(dissect_UEContextReleaseComplete_PDU, proto_f1ap));
  dissector_add_uint("f1ap.proc.imsg", id_UEContextModification, create_dissector_handle(dissect_UEContextModificationRequest_PDU, proto_f1ap));
  dissector_add_uint("f1ap.proc.sout", id_UEContextModification, create_dissector_handle(dissect_UEContextModificationResponse_PDU, proto_f1ap));
  dissector_add_uint("f1ap.proc.uout", id_UEContextModification, create_dissector_handle(dissect_UEContextModificationFailure_PDU, proto_f1ap));
  dissector_add_uint("f1ap.proc.imsg", id_UEContextModificationRequired, create_dissector_handle(dissect_UEContextModificationRequired_PDU, proto_f1ap));
  dissector_add_uint("f1ap.proc.sout", id_UEContextModificationRequired, create_dissector_handle(dissect_UEContextModificationConfirm_PDU, proto_f1ap));
  dissector_add_uint("f1ap.proc.uout", id_UEContextModificationRequired, create_dissector_handle(dissect_UEContextModificationRefuse_PDU, proto_f1ap));
  dissector_add_uint("f1ap.proc.imsg", id_WriteReplaceWarning, create_dissector_handle(dissect_WriteReplaceWarningRequest_PDU, proto_f1ap));
  dissector_add_uint("f1ap.proc.sout", id_WriteReplaceWarning, create_dissector_handle(dissect_WriteReplaceWarningResponse_PDU, proto_f1ap));
  dissector_add_uint("f1ap.proc.imsg", id_PWSCancel, create_dissector_handle(dissect_PWSCancelRequest_PDU, proto_f1ap));
  dissector_add_uint("f1ap.proc.sout", id_PWSCancel, create_dissector_handle(dissect_PWSCancelResponse_PDU, proto_f1ap));
  dissector_add_uint("f1ap.proc.imsg", id_ErrorIndication, create_dissector_handle(dissect_ErrorIndication_PDU, proto_f1ap));
  dissector_add_uint("f1ap.proc.imsg", id_UEContextReleaseRequest, create_dissector_handle(dissect_UEContextReleaseRequest_PDU, proto_f1ap));
  dissector_add_uint("f1ap.proc.imsg", id_InitialULRRCMessageTransfer, create_dissector_handle(dissect_InitialULRRCMessageTransfer_PDU, proto_f1ap));
  dissector_add_uint("f1ap.proc.imsg", id_DLRRCMessageTransfer, create_dissector_handle(dissect_DLRRCMessageTransfer_PDU, proto_f1ap));
  dissector_add_uint("f1ap.proc.imsg", id_ULRRCMessageTransfer, create_dissector_handle(dissect_ULRRCMessageTransfer_PDU, proto_f1ap));
  dissector_add_uint("f1ap.proc.imsg", id_UEInactivityNotification, create_dissector_handle(dissect_UEInactivityNotification_PDU, proto_f1ap));
  dissector_add_uint("f1ap.proc.imsg", id_GNBDUResourceCoordination, create_dissector_handle(dissect_GNBDUResourceCoordinationRequest_PDU, proto_f1ap));
  dissector_add_uint("f1ap.proc.sout", id_GNBDUResourceCoordination, create_dissector_handle(dissect_GNBDUResourceCoordinationResponse_PDU, proto_f1ap));
  dissector_add_uint("f1ap.proc.imsg", id_privateMessage, create_dissector_handle(dissect_PrivateMessage_PDU, proto_f1ap));
  dissector_add_uint("f1ap.proc.imsg", id_SystemInformationDeliveryCommand, create_dissector_handle(dissect_SystemInformationDeliveryCommand_PDU, proto_f1ap));
  dissector_add_uint("f1ap.proc.imsg", id_Paging, create_dissector_handle(dissect_Paging_PDU, proto_f1ap));
  dissector_add_uint("f1ap.proc.imsg", id_Notify, create_dissector_handle(dissect_Notify_PDU, proto_f1ap));
  dissector_add_uint("f1ap.proc.imsg", id_NetworkAccessRateReduction, create_dissector_handle(dissect_NetworkAccessRateReduction_PDU, proto_f1ap));
  dissector_add_uint("f1ap.proc.imsg", id_PWSRestartIndication, create_dissector_handle(dissect_PWSRestartIndication_PDU, proto_f1ap));
  dissector_add_uint("f1ap.proc.imsg", id_PWSFailureIndication, create_dissector_handle(dissect_PWSFailureIndication_PDU, proto_f1ap));
  dissector_add_uint("f1ap.proc.imsg", id_GNBDUStatusIndication, create_dissector_handle(dissect_GNBDUStatusIndication_PDU, proto_f1ap));
  dissector_add_uint("f1ap.proc.imsg", id_RRCDeliveryReport, create_dissector_handle(dissect_RRCDeliveryReport_PDU, proto_f1ap));
  dissector_add_uint("f1ap.proc.imsg", id_F1Removal, create_dissector_handle(dissect_F1RemovalRequest_PDU, proto_f1ap));
  dissector_add_uint("f1ap.proc.sout", id_F1Removal, create_dissector_handle(dissect_F1RemovalResponse_PDU, proto_f1ap));
  dissector_add_uint("f1ap.proc.uout", id_F1Removal, create_dissector_handle(dissect_F1RemovalFailure_PDU, proto_f1ap));


/*--- End of included file: packet-f1ap-dis-tab.c ---*/
#line 314 "./asn1/f1ap/packet-f1ap-template.c"
}

/*
 * Editor modelines
 *
 * Local Variables:
 * c-basic-offset: 2
 * tab-width: 8
 * indent-tabs-mode: nil
 * End:
 *
 * ex: set shiftwidth=2 tabstop=8 expandtab:
 * :indentSize=2:tabSize=8:noTabs=true:
 */
