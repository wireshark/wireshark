/* Do not modify this file.                                                   */
/* It is created automatically by the ASN.1 to Wireshark dissector compiler   */
/* packet-ranap.c                                                             */
/* ../../tools/asn2wrs.py -p ranap -c ./ranap.cnf -s ./packet-ranap-template -D . -O ../../epan/dissectors RANAP-CommonDataTypes.asn RANAP-Constants.asn RANAP-Containers.asn RANAP-IEs.asn RANAP-PDU-Contents.asn RANAP-PDU-Descriptions.asn */

/* Input file: packet-ranap-template.c */

#line 1 "../../asn1/ranap/packet-ranap-template.c"
/* packet-ranap.c
 * Routines for UMTS Node B Application Part(RANAP) packet dissection
 * Copyright 2005 - 2010, Anders Broman <anders.broman[AT]ericsson.com>
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
 *
 * References: 3GPP TS 25.413 version 6.6.0 Release
 */

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <glib.h>
#include <epan/packet.h>

#include <epan/emem.h>
#include <epan/strutil.h>
#include <epan/asn1.h>
#include <epan/prefs.h>

#include "packet-ber.h"
#include "packet-per.h"
#include "packet-gsm_map.h"
#include "packet-ranap.h"
#include "packet-e212.h"
#include "packet-sccp.h"
#include "packet-gsm_a_common.h"
#include "packet-isup.h"

#ifdef _MSC_VER
/* disable: "warning C4146: unary minus operator applied to unsigned type, result still unsigned" */
#pragma warning(disable:4146)
#endif

#define SCCP_SSN_RANAP 142

#define PNAME  "Radio Access Network Application Part"
#define PSNAME "RANAP"
#define PFNAME "ranap"

/* Higest Ranap_ProcedureCode_value, use in heuristics */
#define RANAP_MAX_PC  45 /* id_RANAPenhancedRelocation =  45 */


/*--- Included file: packet-ranap-val.h ---*/
#line 1 "../../asn1/ranap/packet-ranap-val.h"
#define maxPrivateIEs                  65535
#define maxProtocolExtensions          65535
#define maxProtocolIEs                 65535
#define maxNrOfDTs                     15
#define maxNrOfErrors                  256
#define maxNrOfIuSigConIds             250
#define maxNrOfPDPDirections           2
#define maxNrOfPoints                  15
#define maxNrOfRABs                    256
#define maxNrOfSeparateTrafficDirections 2
#define maxNrOfSRBs                    8
#define maxNrOfVol                     2
#define maxNrOfLevels                  256
#define maxNrOfAltValues               16
#define maxNrOfPLMNsSN                 32
#define maxNrOfLAs                     65536
#define maxNrOfSNAs                    65536
#define maxNrOfUEsToBeTraced           64
#define maxNrOfInterfaces              16
#define maxRAB_Subflows                7
#define maxRAB_SubflowCombination      64
#define maxSet                         9
#define maxNrOfHSDSCHMACdFlows_1       7
#define maxnoofMulticastServicesPerUE  128
#define maxnoofMulticastServicesPerRNC 512
#define maxMBMSSA                      256
#define maxMBMSRA                      65536
#define maxNrOfEDCHMACdFlows_1         7
#define maxGANSSSet                    9
#define maxNrOfCSGs                    256
#define maxNrOfEUTRAFreqs              8
#define maxNrOfCellIds                 32
#define maxNrOfRACs                    8
#define maxNrOfLAIs                    8
#define id_RABParametersList           248

typedef enum _ProcedureCode_enum {
  id_RAB_Assignment =   0,
  id_Iu_Release =   1,
  id_RelocationPreparation =   2,
  id_RelocationResourceAllocation =   3,
  id_RelocationCancel =   4,
  id_SRNS_ContextTransfer =   5,
  id_SecurityModeControl =   6,
  id_DataVolumeReport =   7,
  id_Not_Used_8 =   8,
  id_Reset     =   9,
  id_RAB_ReleaseRequest =  10,
  id_Iu_ReleaseRequest =  11,
  id_RelocationDetect =  12,
  id_RelocationComplete =  13,
  id_Paging    =  14,
  id_CommonID  =  15,
  id_CN_InvokeTrace =  16,
  id_LocationReportingControl =  17,
  id_LocationReport =  18,
  id_InitialUE_Message =  19,
  id_DirectTransfer =  20,
  id_OverloadControl =  21,
  id_ErrorIndication =  22,
  id_SRNS_DataForward =  23,
  id_ForwardSRNS_Context =  24,
  id_privateMessage =  25,
  id_CN_DeactivateTrace =  26,
  id_ResetResource =  27,
  id_RANAP_Relocation =  28,
  id_RAB_ModifyRequest =  29,
  id_LocationRelatedData =  30,
  id_InformationTransfer =  31,
  id_UESpecificInformation =  32,
  id_UplinkInformationExchange =  33,
  id_DirectInformationTransfer =  34,
  id_MBMSSessionStart =  35,
  id_MBMSSessionUpdate =  36,
  id_MBMSSessionStop =  37,
  id_MBMSUELinking =  38,
  id_MBMSRegistration =  39,
  id_MBMSCNDe_Registration_Procedure =  40,
  id_MBMSRABEstablishmentIndication =  41,
  id_MBMSRABRelease =  42,
  id_enhancedRelocationComplete =  43,
  id_enhancedRelocationCompleteConfirm =  44,
  id_RANAPenhancedRelocation =  45,
  id_SRVCCPreparation =  46
} ProcedureCode_enum;

typedef enum _ProtocolIE_ID_enum {
  id_AreaIdentity =   0,
  id_Not_Used_1 =   1,
  id_Not_Used_2 =   2,
  id_CN_DomainIndicator =   3,
  id_Cause     =   4,
  id_ChosenEncryptionAlgorithm =   5,
  id_ChosenIntegrityProtectionAlgorithm =   6,
  id_ClassmarkInformation2 =   7,
  id_ClassmarkInformation3 =   8,
  id_CriticalityDiagnostics =   9,
  id_DL_GTP_PDU_SequenceNumber =  10,
  id_EncryptionInformation =  11,
  id_IntegrityProtectionInformation =  12,
  id_IuTransportAssociation =  13,
  id_L3_Information =  14,
  id_LAI       =  15,
  id_NAS_PDU   =  16,
  id_NonSearchingIndication =  17,
  id_NumberOfSteps =  18,
  id_OMC_ID    =  19,
  id_OldBSS_ToNewBSS_Information =  20,
  id_PagingAreaID =  21,
  id_PagingCause =  22,
  id_PermanentNAS_UE_ID =  23,
  id_RAB_ContextItem =  24,
  id_RAB_ContextList =  25,
  id_RAB_DataForwardingItem =  26,
  id_RAB_DataForwardingItem_SRNS_CtxReq =  27,
  id_RAB_DataForwardingList =  28,
  id_RAB_DataForwardingList_SRNS_CtxReq =  29,
  id_RAB_DataVolumeReportItem =  30,
  id_RAB_DataVolumeReportList =  31,
  id_RAB_DataVolumeReportRequestItem =  32,
  id_RAB_DataVolumeReportRequestList =  33,
  id_RAB_FailedItem =  34,
  id_RAB_FailedList =  35,
  id_RAB_ID    =  36,
  id_RAB_QueuedItem =  37,
  id_RAB_QueuedList =  38,
  id_RAB_ReleaseFailedList =  39,
  id_RAB_ReleaseItem =  40,
  id_RAB_ReleaseList =  41,
  id_RAB_ReleasedItem =  42,
  id_RAB_ReleasedList =  43,
  id_RAB_ReleasedList_IuRelComp =  44,
  id_RAB_RelocationReleaseItem =  45,
  id_RAB_RelocationReleaseList =  46,
  id_RAB_SetupItem_RelocReq =  47,
  id_RAB_SetupItem_RelocReqAck =  48,
  id_RAB_SetupList_RelocReq =  49,
  id_RAB_SetupList_RelocReqAck =  50,
  id_RAB_SetupOrModifiedItem =  51,
  id_RAB_SetupOrModifiedList =  52,
  id_RAB_SetupOrModifyItem =  53,
  id_RAB_SetupOrModifyList =  54,
  id_RAC       =  55,
  id_RelocationType =  56,
  id_RequestType =  57,
  id_SAI       =  58,
  id_SAPI      =  59,
  id_SourceID  =  60,
  id_Source_ToTarget_TransparentContainer =  61,
  id_TargetID  =  62,
  id_Target_ToSource_TransparentContainer =  63,
  id_TemporaryUE_ID =  64,
  id_TraceReference =  65,
  id_TraceType =  66,
  id_TransportLayerAddress =  67,
  id_TriggerID =  68,
  id_UE_ID     =  69,
  id_UL_GTP_PDU_SequenceNumber =  70,
  id_RAB_FailedtoReportItem =  71,
  id_RAB_FailedtoReportList =  72,
  id_Not_Used_73 =  73,
  id_Not_Used_74 =  74,
  id_KeyStatus =  75,
  id_DRX_CycleLengthCoefficient =  76,
  id_IuSigConIdList =  77,
  id_IuSigConIdItem =  78,
  id_IuSigConId =  79,
  id_DirectTransferInformationItem_RANAP_RelocInf =  80,
  id_DirectTransferInformationList_RANAP_RelocInf =  81,
  id_RAB_ContextItem_RANAP_RelocInf =  82,
  id_RAB_ContextList_RANAP_RelocInf =  83,
  id_RAB_ContextFailedtoTransferItem =  84,
  id_RAB_ContextFailedtoTransferList =  85,
  id_GlobalRNC_ID =  86,
  id_RAB_ReleasedItem_IuRelComp =  87,
  id_MessageStructure =  88,
  id_Alt_RAB_Parameters =  89,
  id_Ass_RAB_Parameters =  90,
  id_RAB_ModifyList =  91,
  id_RAB_ModifyItem =  92,
  id_TypeOfError =  93,
  id_BroadcastAssistanceDataDecipheringKeys =  94,
  id_LocationRelatedDataRequestType =  95,
  id_GlobalCN_ID =  96,
  id_LastKnownServiceArea =  97,
  id_SRB_TrCH_Mapping =  98,
  id_InterSystemInformation_TransparentContainer =  99,
  id_NewBSS_To_OldBSS_Information = 100,
  id_Not_Used_101 = 101,
  id_Not_Used_102 = 102,
  id_SourceRNC_PDCP_context_info = 103,
  id_InformationTransferID = 104,
  id_SNA_Access_Information = 105,
  id_ProvidedData = 106,
  id_GERAN_BSC_Container = 107,
  id_GERAN_Classmark = 108,
  id_GERAN_Iumode_RAB_Failed_RABAssgntResponse_Item = 109,
  id_GERAN_Iumode_RAB_FailedList_RABAssgntResponse = 110,
  id_VerticalAccuracyCode = 111,
  id_ResponseTime = 112,
  id_PositioningPriority = 113,
  id_ClientType = 114,
  id_LocationRelatedDataRequestTypeSpecificToGERANIuMode = 115,
  id_SignallingIndication = 116,
  id_hS_DSCH_MAC_d_Flow_ID = 117,
  id_UESBI_Iu  = 118,
  id_PositionData = 119,
  id_PositionDataSpecificToGERANIuMode = 120,
  id_CellLoadInformationGroup = 121,
  id_AccuracyFulfilmentIndicator = 122,
  id_InformationTransferType = 123,
  id_TraceRecordingSessionInformation = 124,
  id_TracePropagationParameters = 125,
  id_InterSystemInformationTransferType = 126,
  id_SelectedPLMN_ID = 127,
  id_RedirectionCompleted = 128,
  id_RedirectionIndication = 129,
  id_NAS_SequenceNumber = 130,
  id_RejectCauseValue = 131,
  id_APN       = 132,
  id_CNMBMSLinkingInformation = 133,
  id_DeltaRAListofIdleModeUEs = 134,
  id_FrequenceLayerConvergenceFlag = 135,
  id_InformationExchangeID = 136,
  id_InformationExchangeType = 137,
  id_InformationRequested = 138,
  id_InformationRequestType = 139,
  id_IPMulticastAddress = 140,
  id_JoinedMBMSBearerServicesList = 141,
  id_LeftMBMSBearerServicesList = 142,
  id_MBMSBearerServiceType = 143,
  id_MBMSCNDe_Registration = 144,
  id_MBMSServiceArea = 145,
  id_MBMSSessionDuration = 146,
  id_MBMSSessionIdentity = 147,
  id_PDP_TypeInformation = 148,
  id_RAB_Parameters = 149,
  id_RAListofIdleModeUEs = 150,
  id_MBMSRegistrationRequestType = 151,
  id_SessionUpdateID = 152,
  id_TMGI      = 153,
  id_TransportLayerInformation = 154,
  id_UnsuccessfulLinkingList = 155,
  id_MBMSLinkingInformation = 156,
  id_MBMSSessionRepetitionNumber = 157,
  id_AlternativeRABConfiguration = 158,
  id_AlternativeRABConfigurationRequest = 159,
  id_E_DCH_MAC_d_Flow_ID = 160,
  id_SourceBSS_ToTargetBSS_TransparentContainer = 161,
  id_TargetBSS_ToSourceBSS_TransparentContainer = 162,
  id_TimeToMBMSDataTransfer = 163,
  id_IncludeVelocity = 164,
  id_VelocityEstimate = 165,
  id_RedirectAttemptFlag = 166,
  id_RAT_Type  = 167,
  id_PeriodicLocationInfo = 168,
  id_MBMSCountingInformation = 169,
  id_170_not_to_be_used_for_IE_ids = 170,
  id_ExtendedRNC_ID = 171,
  id_Alt_RAB_Parameter_ExtendedGuaranteedBitrateInf = 172,
  id_Alt_RAB_Parameter_ExtendedMaxBitrateInf = 173,
  id_Ass_RAB_Parameter_ExtendedGuaranteedBitrateList = 174,
  id_Ass_RAB_Parameter_ExtendedMaxBitrateList = 175,
  id_RAB_Parameter_ExtendedGuaranteedBitrateList = 176,
  id_RAB_Parameter_ExtendedMaxBitrateList = 177,
  id_Requested_RAB_Parameter_ExtendedMaxBitrateList = 178,
  id_Requested_RAB_Parameter_ExtendedGuaranteedBitrateList = 179,
  id_LAofIdleModeUEs = 180,
  id_newLAListofIdleModeUEs = 181,
  id_LAListwithNoIdleModeUEsAnyMore = 182,
  id_183_not_to_be_used_for_IE_ids = 183,
  id_GANSS_PositioningDataSet = 184,
  id_RequestedGANSSAssistanceData = 185,
  id_BroadcastGANSSAssistanceDataDecipheringKeys = 186,
  id_d_RNTI_for_NoIuCSUP = 187,
  id_RAB_SetupList_EnhancedRelocCompleteReq = 188,
  id_RAB_SetupItem_EnhancedRelocCompleteReq = 189,
  id_RAB_SetupList_EnhancedRelocCompleteRes = 190,
  id_RAB_SetupItem_EnhancedRelocCompleteRes = 191,
  id_RAB_SetupList_EnhRelocInfoReq = 192,
  id_RAB_SetupItem_EnhRelocInfoReq = 193,
  id_RAB_SetupList_EnhRelocInfoRes = 194,
  id_RAB_SetupItem_EnhRelocInfoRes = 195,
  id_OldIuSigConId = 196,
  id_RAB_FailedList_EnhRelocInfoRes = 197,
  id_RAB_FailedItem_EnhRelocInfoRes = 198,
  id_Global_ENB_ID = 199,
  id_UE_History_Information = 200,
  id_MBMSSynchronisationInformation = 201,
  id_SubscriberProfileIDforRFP = 202,
  id_CSG_Id    = 203,
  id_OldIuSigConIdCS = 204,
  id_OldIuSigConIdPS = 205,
  id_GlobalCN_IDCS = 206,
  id_GlobalCN_IDPS = 207,
  id_SourceExtendedRNC_ID = 208,
  id_RAB_ToBeReleasedItem_EnhancedRelocCompleteRes = 209,
  id_RAB_ToBeReleasedList_EnhancedRelocCompleteRes = 210,
  id_SourceRNC_ID = 211,
  id_Relocation_TargetRNC_ID = 212,
  id_Relocation_TargetExtendedRNC_ID = 213,
  id_Alt_RAB_Parameter_SupportedGuaranteedBitrateInf = 214,
  id_Alt_RAB_Parameter_SupportedMaxBitrateInf = 215,
  id_Ass_RAB_Parameter_SupportedGuaranteedBitrateList = 216,
  id_Ass_RAB_Parameter_SupportedMaxBitrateList = 217,
  id_RAB_Parameter_SupportedGuaranteedBitrateList = 218,
  id_RAB_Parameter_SupportedMaxBitrateList = 219,
  id_Requested_RAB_Parameter_SupportedMaxBitrateList = 220,
  id_Requested_RAB_Parameter_SupportedGuaranteedBitrateList = 221,
  id_Relocation_SourceRNC_ID = 222,
  id_Relocation_SourceExtendedRNC_ID = 223,
  id_EncryptionKey = 224,
  id_IntegrityProtectionKey = 225,
  id_SRVCC_HO_Indication = 226,
  id_SRVCC_Information = 227,
  id_SRVCC_Operation_Possible = 228,
  id_CSG_Id_List = 229,
  id_PSRABtobeReplaced = 230,
  id_E_UTRAN_Service_Handover = 231,
  id_Not_Used_232 = 232,
  id_UE_AggregateMaximumBitRate = 233,
  id_CSG_Membership_Status = 234,
  id_Cell_Access_Mode = 235,
  id_IP_Source_Address = 236,
  id_CSFB_Information = 237,
  id_PDP_TypeInformation_extension = 238,
  id_MSISDN    = 239,
  id_Offload_RAB_Parameters = 240,
  id_LGW_TransportLayerAddress = 241,
  id_Correlation_ID = 242,
  id_IRAT_Measurement_Configuration = 243,
  id_MDT_Configuration = 244,
  id_Priority_Class_Indicator = 245,
  id_Not_Used_246 = 246,
  id_RNSAPRelocationParameters = 247,
  id_Management_Based_MDT_Allowed = 249
} ProtocolIE_ID_enum;

/*--- End of included file: packet-ranap-val.h ---*/
#line 64 "../../asn1/ranap/packet-ranap-template.c"

/* Initialize the protocol and registered fields */
static int proto_ranap = -1;

/* initialise sub-dissector handles */
static dissector_handle_t rrc_s_to_trnc_handle = NULL;
static dissector_handle_t rrc_t_to_srnc_handle = NULL;
static dissector_handle_t rrc_ho_to_utran_cmd = NULL;

static int hf_ranap_imsi_digits = -1;
static int hf_ranap_transportLayerAddress_ipv4 = -1;
static int hf_ranap_transportLayerAddress_ipv6 = -1;
static int hf_ranap_transportLayerAddress_nsap = -1;


/*--- Included file: packet-ranap-hf.c ---*/
#line 1 "../../asn1/ranap/packet-ranap-hf.c"
static int hf_ranap_AccuracyFulfilmentIndicator_PDU = -1;  /* AccuracyFulfilmentIndicator */
static int hf_ranap_Alt_RAB_Parameters_PDU = -1;  /* Alt_RAB_Parameters */
static int hf_ranap_Alt_RAB_Parameter_ExtendedGuaranteedBitrateInf_PDU = -1;  /* Alt_RAB_Parameter_ExtendedGuaranteedBitrateInf */
static int hf_ranap_Alt_RAB_Parameter_SupportedGuaranteedBitrateInf_PDU = -1;  /* Alt_RAB_Parameter_SupportedGuaranteedBitrateInf */
static int hf_ranap_Alt_RAB_Parameter_ExtendedMaxBitrateInf_PDU = -1;  /* Alt_RAB_Parameter_ExtendedMaxBitrateInf */
static int hf_ranap_Alt_RAB_Parameter_SupportedMaxBitrateInf_PDU = -1;  /* Alt_RAB_Parameter_SupportedMaxBitrateInf */
static int hf_ranap_AlternativeRABConfigurationRequest_PDU = -1;  /* AlternativeRABConfigurationRequest */
static int hf_ranap_APN_PDU = -1;                 /* APN */
static int hf_ranap_AreaIdentity_PDU = -1;        /* AreaIdentity */
static int hf_ranap_Ass_RAB_Parameters_PDU = -1;  /* Ass_RAB_Parameters */
static int hf_ranap_Ass_RAB_Parameter_ExtendedGuaranteedBitrateList_PDU = -1;  /* Ass_RAB_Parameter_ExtendedGuaranteedBitrateList */
static int hf_ranap_Ass_RAB_Parameter_ExtendedMaxBitrateList_PDU = -1;  /* Ass_RAB_Parameter_ExtendedMaxBitrateList */
static int hf_ranap_BroadcastAssistanceDataDecipheringKeys_PDU = -1;  /* BroadcastAssistanceDataDecipheringKeys */
static int hf_ranap_Cause_PDU = -1;               /* Cause */
static int hf_ranap_Cell_Access_Mode_PDU = -1;    /* Cell_Access_Mode */
static int hf_ranap_CellLoadInformationGroup_PDU = -1;  /* CellLoadInformationGroup */
static int hf_ranap_ClientType_PDU = -1;          /* ClientType */
static int hf_ranap_CriticalityDiagnostics_PDU = -1;  /* CriticalityDiagnostics */
static int hf_ranap_MessageStructure_PDU = -1;    /* MessageStructure */
static int hf_ranap_ChosenEncryptionAlgorithm_PDU = -1;  /* ChosenEncryptionAlgorithm */
static int hf_ranap_ChosenIntegrityProtectionAlgorithm_PDU = -1;  /* ChosenIntegrityProtectionAlgorithm */
static int hf_ranap_ClassmarkInformation2_PDU = -1;  /* ClassmarkInformation2 */
static int hf_ranap_ClassmarkInformation3_PDU = -1;  /* ClassmarkInformation3 */
static int hf_ranap_CN_DomainIndicator_PDU = -1;  /* CN_DomainIndicator */
static int hf_ranap_Correlation_ID_PDU = -1;      /* Correlation_ID */
static int hf_ranap_CSFB_Information_PDU = -1;    /* CSFB_Information */
static int hf_ranap_CSG_Id_PDU = -1;              /* CSG_Id */
static int hf_ranap_CSG_Id_List_PDU = -1;         /* CSG_Id_List */
static int hf_ranap_CSG_Membership_Status_PDU = -1;  /* CSG_Membership_Status */
static int hf_ranap_DeltaRAListofIdleModeUEs_PDU = -1;  /* DeltaRAListofIdleModeUEs */
static int hf_ranap_DRX_CycleLengthCoefficient_PDU = -1;  /* DRX_CycleLengthCoefficient */
static int hf_ranap_E_DCH_MAC_d_Flow_ID_PDU = -1;  /* E_DCH_MAC_d_Flow_ID */
static int hf_ranap_EncryptionInformation_PDU = -1;  /* EncryptionInformation */
static int hf_ranap_EncryptionKey_PDU = -1;       /* EncryptionKey */
static int hf_ranap_E_UTRAN_Service_Handover_PDU = -1;  /* E_UTRAN_Service_Handover */
static int hf_ranap_ExtendedRNC_ID_PDU = -1;      /* ExtendedRNC_ID */
static int hf_ranap_FrequenceLayerConvergenceFlag_PDU = -1;  /* FrequenceLayerConvergenceFlag */
static int hf_ranap_GANSS_PositioningDataSet_PDU = -1;  /* GANSS_PositioningDataSet */
static int hf_ranap_GERAN_BSC_Container_PDU = -1;  /* GERAN_BSC_Container */
static int hf_ranap_GERAN_Classmark_PDU = -1;     /* GERAN_Classmark */
static int hf_ranap_GlobalCN_ID_PDU = -1;         /* GlobalCN_ID */
static int hf_ranap_GlobalRNC_ID_PDU = -1;        /* GlobalRNC_ID */
static int hf_ranap_HS_DSCH_MAC_d_Flow_ID_PDU = -1;  /* HS_DSCH_MAC_d_Flow_ID */
static int hf_ranap_IncludeVelocity_PDU = -1;     /* IncludeVelocity */
static int hf_ranap_InformationExchangeID_PDU = -1;  /* InformationExchangeID */
static int hf_ranap_InformationExchangeType_PDU = -1;  /* InformationExchangeType */
static int hf_ranap_InformationRequested_PDU = -1;  /* InformationRequested */
static int hf_ranap_InformationRequestType_PDU = -1;  /* InformationRequestType */
static int hf_ranap_InformationTransferID_PDU = -1;  /* InformationTransferID */
static int hf_ranap_InformationTransferType_PDU = -1;  /* InformationTransferType */
static int hf_ranap_IntegrityProtectionInformation_PDU = -1;  /* IntegrityProtectionInformation */
static int hf_ranap_IntegrityProtectionKey_PDU = -1;  /* IntegrityProtectionKey */
static int hf_ranap_InterSystemInformationTransferType_PDU = -1;  /* InterSystemInformationTransferType */
static int hf_ranap_InterSystemInformation_TransparentContainer_PDU = -1;  /* InterSystemInformation_TransparentContainer */
static int hf_ranap_IPMulticastAddress_PDU = -1;  /* IPMulticastAddress */
static int hf_ranap_IuSignallingConnectionIdentifier_PDU = -1;  /* IuSignallingConnectionIdentifier */
static int hf_ranap_IuTransportAssociation_PDU = -1;  /* IuTransportAssociation */
static int hf_ranap_KeyStatus_PDU = -1;           /* KeyStatus */
static int hf_ranap_LAI_PDU = -1;                 /* LAI */
static int hf_ranap_LastKnownServiceArea_PDU = -1;  /* LastKnownServiceArea */
static int hf_ranap_LocationRelatedDataRequestType_PDU = -1;  /* LocationRelatedDataRequestType */
static int hf_ranap_LocationRelatedDataRequestTypeSpecificToGERANIuMode_PDU = -1;  /* LocationRelatedDataRequestTypeSpecificToGERANIuMode */
static int hf_ranap_L3_Information_PDU = -1;      /* L3_Information */
static int hf_ranap_Management_Based_MDT_Allowed_PDU = -1;  /* Management_Based_MDT_Allowed */
static int hf_ranap_MBMSBearerServiceType_PDU = -1;  /* MBMSBearerServiceType */
static int hf_ranap_MBMSCNDe_Registration_PDU = -1;  /* MBMSCNDe_Registration */
static int hf_ranap_MBMSCountingInformation_PDU = -1;  /* MBMSCountingInformation */
static int hf_ranap_MBMSLinkingInformation_PDU = -1;  /* MBMSLinkingInformation */
static int hf_ranap_MBMSRegistrationRequestType_PDU = -1;  /* MBMSRegistrationRequestType */
static int hf_ranap_MBMSServiceArea_PDU = -1;     /* MBMSServiceArea */
static int hf_ranap_MBMSSessionDuration_PDU = -1;  /* MBMSSessionDuration */
static int hf_ranap_MBMSSessionIdentity_PDU = -1;  /* MBMSSessionIdentity */
static int hf_ranap_MBMSSessionRepetitionNumber_PDU = -1;  /* MBMSSessionRepetitionNumber */
static int hf_ranap_MDT_Configuration_PDU = -1;   /* MDT_Configuration */
static int hf_ranap_MSISDN_PDU = -1;              /* MSISDN */
static int hf_ranap_NAS_PDU_PDU = -1;             /* NAS_PDU */
static int hf_ranap_NAS_SequenceNumber_PDU = -1;  /* NAS_SequenceNumber */
static int hf_ranap_NewBSS_To_OldBSS_Information_PDU = -1;  /* NewBSS_To_OldBSS_Information */
static int hf_ranap_NonSearchingIndication_PDU = -1;  /* NonSearchingIndication */
static int hf_ranap_NumberOfSteps_PDU = -1;       /* NumberOfSteps */
static int hf_ranap_Offload_RAB_Parameters_PDU = -1;  /* Offload_RAB_Parameters */
static int hf_ranap_OldBSS_ToNewBSS_Information_PDU = -1;  /* OldBSS_ToNewBSS_Information */
static int hf_ranap_OMC_ID_PDU = -1;              /* OMC_ID */
static int hf_ranap_PagingAreaID_PDU = -1;        /* PagingAreaID */
static int hf_ranap_PagingCause_PDU = -1;         /* PagingCause */
static int hf_ranap_PDP_TypeInformation_PDU = -1;  /* PDP_TypeInformation */
static int hf_ranap_PDP_TypeInformation_extension_PDU = -1;  /* PDP_TypeInformation_extension */
static int hf_ranap_PeriodicLocationInfo_PDU = -1;  /* PeriodicLocationInfo */
static int hf_ranap_PermanentNAS_UE_ID_PDU = -1;  /* PermanentNAS_UE_ID */
static int hf_ranap_PLMNidentity_PDU = -1;        /* PLMNidentity */
static int hf_ranap_PositioningPriority_PDU = -1;  /* PositioningPriority */
static int hf_ranap_PositionData_PDU = -1;        /* PositionData */
static int hf_ranap_PositionDataSpecificToGERANIuMode_PDU = -1;  /* PositionDataSpecificToGERANIuMode */
static int hf_ranap_Priority_Class_Indicator_PDU = -1;  /* Priority_Class_Indicator */
static int hf_ranap_ProvidedData_PDU = -1;        /* ProvidedData */
static int hf_ranap_RAB_ID_PDU = -1;              /* RAB_ID */
static int hf_ranap_RAB_Parameter_ExtendedGuaranteedBitrateList_PDU = -1;  /* RAB_Parameter_ExtendedGuaranteedBitrateList */
static int hf_ranap_RAB_Parameter_ExtendedMaxBitrateList_PDU = -1;  /* RAB_Parameter_ExtendedMaxBitrateList */
static int hf_ranap_RAB_Parameters_PDU = -1;      /* RAB_Parameters */
static int hf_ranap_RABParametersList_PDU = -1;   /* RABParametersList */
static int hf_ranap_RAC_PDU = -1;                 /* RAC */
static int hf_ranap_RAListofIdleModeUEs_PDU = -1;  /* RAListofIdleModeUEs */
static int hf_ranap_LAListofIdleModeUEs_PDU = -1;  /* LAListofIdleModeUEs */
static int hf_ranap_RAT_Type_PDU = -1;            /* RAT_Type */
static int hf_ranap_RedirectAttemptFlag_PDU = -1;  /* RedirectAttemptFlag */
static int hf_ranap_RedirectionCompleted_PDU = -1;  /* RedirectionCompleted */
static int hf_ranap_RejectCauseValue_PDU = -1;    /* RejectCauseValue */
static int hf_ranap_RelocationType_PDU = -1;      /* RelocationType */
static int hf_ranap_RequestedGANSSAssistanceData_PDU = -1;  /* RequestedGANSSAssistanceData */
static int hf_ranap_Requested_RAB_Parameter_ExtendedMaxBitrateList_PDU = -1;  /* Requested_RAB_Parameter_ExtendedMaxBitrateList */
static int hf_ranap_Requested_RAB_Parameter_ExtendedGuaranteedBitrateList_PDU = -1;  /* Requested_RAB_Parameter_ExtendedGuaranteedBitrateList */
static int hf_ranap_RequestType_PDU = -1;         /* RequestType */
static int hf_ranap_ResponseTime_PDU = -1;        /* ResponseTime */
static int hf_ranap_RNSAPRelocationParameters_PDU = -1;  /* RNSAPRelocationParameters */
static int hf_ranap_RRC_Container_PDU = -1;       /* RRC_Container */
static int hf_ranap_SAI_PDU = -1;                 /* SAI */
static int hf_ranap_SAPI_PDU = -1;                /* SAPI */
static int hf_ranap_SessionUpdateID_PDU = -1;     /* SessionUpdateID */
static int hf_ranap_SignallingIndication_PDU = -1;  /* SignallingIndication */
static int hf_ranap_SNA_Access_Information_PDU = -1;  /* SNA_Access_Information */
static int hf_ranap_Source_ToTarget_TransparentContainer_PDU = -1;  /* Source_ToTarget_TransparentContainer */
static int hf_ranap_ranap_SourceCellID_PDU = -1;  /* SourceCellID */
static int hf_ranap_SourceBSS_ToTargetBSS_TransparentContainer_PDU = -1;  /* SourceBSS_ToTargetBSS_TransparentContainer */
static int hf_ranap_SourceID_PDU = -1;            /* SourceID */
static int hf_ranap_ranap_SourceRNC_ToTargetRNC_TransparentContainer_PDU = -1;  /* SourceRNC_ToTargetRNC_TransparentContainer */
static int hf_ranap_IRAT_Measurement_Configuration_PDU = -1;  /* IRAT_Measurement_Configuration */
static int hf_ranap_SubscriberProfileIDforRFP_PDU = -1;  /* SubscriberProfileIDforRFP */
static int hf_ranap_SupportedRAB_ParameterBitrateList_PDU = -1;  /* SupportedRAB_ParameterBitrateList */
static int hf_ranap_SRB_TrCH_Mapping_PDU = -1;    /* SRB_TrCH_Mapping */
static int hf_ranap_SRVCC_HO_Indication_PDU = -1;  /* SRVCC_HO_Indication */
static int hf_ranap_SRVCC_Information_PDU = -1;   /* SRVCC_Information */
static int hf_ranap_SRVCC_Operation_Possible_PDU = -1;  /* SRVCC_Operation_Possible */
static int hf_ranap_Target_ToSource_TransparentContainer_PDU = -1;  /* Target_ToSource_TransparentContainer */
static int hf_ranap_TargetBSS_ToSourceBSS_TransparentContainer_PDU = -1;  /* TargetBSS_ToSourceBSS_TransparentContainer */
static int hf_ranap_TargetID_PDU = -1;            /* TargetID */
static int hf_ranap_ranap_TargetRNC_ID_PDU = -1;  /* TargetRNC_ID */
static int hf_ranap_TargetRNC_ToSourceRNC_TransparentContainer_PDU = -1;  /* TargetRNC_ToSourceRNC_TransparentContainer */
static int hf_ranap_TemporaryUE_ID_PDU = -1;      /* TemporaryUE_ID */
static int hf_ranap_TimeToMBMSDataTransfer_PDU = -1;  /* TimeToMBMSDataTransfer */
static int hf_ranap_TMGI_PDU = -1;                /* TMGI */
static int hf_ranap_TracePropagationParameters_PDU = -1;  /* TracePropagationParameters */
static int hf_ranap_TraceRecordingSessionInformation_PDU = -1;  /* TraceRecordingSessionInformation */
static int hf_ranap_TraceReference_PDU = -1;      /* TraceReference */
static int hf_ranap_TraceType_PDU = -1;           /* TraceType */
static int hf_ranap_TransportLayerAddress_PDU = -1;  /* TransportLayerAddress */
static int hf_ranap_TriggerID_PDU = -1;           /* TriggerID */
static int hf_ranap_TypeOfError_PDU = -1;         /* TypeOfError */
static int hf_ranap_UE_AggregateMaximumBitRate_PDU = -1;  /* UE_AggregateMaximumBitRate */
static int hf_ranap_UE_History_Information_PDU = -1;  /* UE_History_Information */
static int hf_ranap_UE_ID_PDU = -1;               /* UE_ID */
static int hf_ranap_UESBI_Iu_PDU = -1;            /* UESBI_Iu */
static int hf_ranap_VelocityEstimate_PDU = -1;    /* VelocityEstimate */
static int hf_ranap_VerticalAccuracyCode_PDU = -1;  /* VerticalAccuracyCode */
static int hf_ranap_Iu_ReleaseCommand_PDU = -1;   /* Iu_ReleaseCommand */
static int hf_ranap_Iu_ReleaseComplete_PDU = -1;  /* Iu_ReleaseComplete */
static int hf_ranap_RAB_DataVolumeReportList_PDU = -1;  /* RAB_DataVolumeReportList */
static int hf_ranap_RAB_DataVolumeReportItem_PDU = -1;  /* RAB_DataVolumeReportItem */
static int hf_ranap_RAB_ReleasedList_IuRelComp_PDU = -1;  /* RAB_ReleasedList_IuRelComp */
static int hf_ranap_RAB_ReleasedItem_IuRelComp_PDU = -1;  /* RAB_ReleasedItem_IuRelComp */
static int hf_ranap_RelocationRequired_PDU = -1;  /* RelocationRequired */
static int hf_ranap_RelocationCommand_PDU = -1;   /* RelocationCommand */
static int hf_ranap_RAB_RelocationReleaseList_PDU = -1;  /* RAB_RelocationReleaseList */
static int hf_ranap_RAB_RelocationReleaseItem_PDU = -1;  /* RAB_RelocationReleaseItem */
static int hf_ranap_RAB_DataForwardingList_PDU = -1;  /* RAB_DataForwardingList */
static int hf_ranap_RAB_DataForwardingItem_PDU = -1;  /* RAB_DataForwardingItem */
static int hf_ranap_RelocationPreparationFailure_PDU = -1;  /* RelocationPreparationFailure */
static int hf_ranap_RelocationRequest_PDU = -1;   /* RelocationRequest */
static int hf_ranap_RAB_SetupList_RelocReq_PDU = -1;  /* RAB_SetupList_RelocReq */
static int hf_ranap_RAB_SetupItem_RelocReq_PDU = -1;  /* RAB_SetupItem_RelocReq */
static int hf_ranap_CNMBMSLinkingInformation_PDU = -1;  /* CNMBMSLinkingInformation */
static int hf_ranap_JoinedMBMSBearerService_IEs_PDU = -1;  /* JoinedMBMSBearerService_IEs */
static int hf_ranap_RelocationRequestAcknowledge_PDU = -1;  /* RelocationRequestAcknowledge */
static int hf_ranap_RAB_SetupList_RelocReqAck_PDU = -1;  /* RAB_SetupList_RelocReqAck */
static int hf_ranap_RAB_SetupItem_RelocReqAck_PDU = -1;  /* RAB_SetupItem_RelocReqAck */
static int hf_ranap_RAB_FailedList_PDU = -1;      /* RAB_FailedList */
static int hf_ranap_RAB_FailedItem_PDU = -1;      /* RAB_FailedItem */
static int hf_ranap_RelocationFailure_PDU = -1;   /* RelocationFailure */
static int hf_ranap_RelocationCancel_PDU = -1;    /* RelocationCancel */
static int hf_ranap_RelocationCancelAcknowledge_PDU = -1;  /* RelocationCancelAcknowledge */
static int hf_ranap_SRNS_ContextRequest_PDU = -1;  /* SRNS_ContextRequest */
static int hf_ranap_RAB_DataForwardingList_SRNS_CtxReq_PDU = -1;  /* RAB_DataForwardingList_SRNS_CtxReq */
static int hf_ranap_RAB_DataForwardingItem_SRNS_CtxReq_PDU = -1;  /* RAB_DataForwardingItem_SRNS_CtxReq */
static int hf_ranap_SRNS_ContextResponse_PDU = -1;  /* SRNS_ContextResponse */
static int hf_ranap_RAB_ContextList_PDU = -1;     /* RAB_ContextList */
static int hf_ranap_RAB_ContextItem_PDU = -1;     /* RAB_ContextItem */
static int hf_ranap_RAB_ContextFailedtoTransferList_PDU = -1;  /* RAB_ContextFailedtoTransferList */
static int hf_ranap_RABs_ContextFailedtoTransferItem_PDU = -1;  /* RABs_ContextFailedtoTransferItem */
static int hf_ranap_SecurityModeCommand_PDU = -1;  /* SecurityModeCommand */
static int hf_ranap_SecurityModeComplete_PDU = -1;  /* SecurityModeComplete */
static int hf_ranap_SecurityModeReject_PDU = -1;  /* SecurityModeReject */
static int hf_ranap_DataVolumeReportRequest_PDU = -1;  /* DataVolumeReportRequest */
static int hf_ranap_RAB_DataVolumeReportRequestList_PDU = -1;  /* RAB_DataVolumeReportRequestList */
static int hf_ranap_RAB_DataVolumeReportRequestItem_PDU = -1;  /* RAB_DataVolumeReportRequestItem */
static int hf_ranap_DataVolumeReport_PDU = -1;    /* DataVolumeReport */
static int hf_ranap_RAB_FailedtoReportList_PDU = -1;  /* RAB_FailedtoReportList */
static int hf_ranap_RABs_failed_to_reportItem_PDU = -1;  /* RABs_failed_to_reportItem */
static int hf_ranap_Reset_PDU = -1;               /* Reset */
static int hf_ranap_ResetAcknowledge_PDU = -1;    /* ResetAcknowledge */
static int hf_ranap_ResetResource_PDU = -1;       /* ResetResource */
static int hf_ranap_ResetResourceList_PDU = -1;   /* ResetResourceList */
static int hf_ranap_ResetResourceItem_PDU = -1;   /* ResetResourceItem */
static int hf_ranap_ResetResourceAcknowledge_PDU = -1;  /* ResetResourceAcknowledge */
static int hf_ranap_ResetResourceAckList_PDU = -1;  /* ResetResourceAckList */
static int hf_ranap_ResetResourceAckItem_PDU = -1;  /* ResetResourceAckItem */
static int hf_ranap_RAB_ReleaseRequest_PDU = -1;  /* RAB_ReleaseRequest */
static int hf_ranap_RAB_ReleaseList_PDU = -1;     /* RAB_ReleaseList */
static int hf_ranap_RAB_ReleaseItem_PDU = -1;     /* RAB_ReleaseItem */
static int hf_ranap_Iu_ReleaseRequest_PDU = -1;   /* Iu_ReleaseRequest */
static int hf_ranap_RelocationDetect_PDU = -1;    /* RelocationDetect */
static int hf_ranap_RelocationComplete_PDU = -1;  /* RelocationComplete */
static int hf_ranap_EnhancedRelocationCompleteRequest_PDU = -1;  /* EnhancedRelocationCompleteRequest */
static int hf_ranap_RAB_SetupList_EnhancedRelocCompleteReq_PDU = -1;  /* RAB_SetupList_EnhancedRelocCompleteReq */
static int hf_ranap_RAB_SetupItem_EnhancedRelocCompleteReq_PDU = -1;  /* RAB_SetupItem_EnhancedRelocCompleteReq */
static int hf_ranap_EnhancedRelocationCompleteResponse_PDU = -1;  /* EnhancedRelocationCompleteResponse */
static int hf_ranap_RAB_SetupList_EnhancedRelocCompleteRes_PDU = -1;  /* RAB_SetupList_EnhancedRelocCompleteRes */
static int hf_ranap_RAB_SetupItem_EnhancedRelocCompleteRes_PDU = -1;  /* RAB_SetupItem_EnhancedRelocCompleteRes */
static int hf_ranap_RAB_ToBeReleasedList_EnhancedRelocCompleteRes_PDU = -1;  /* RAB_ToBeReleasedList_EnhancedRelocCompleteRes */
static int hf_ranap_RAB_ToBeReleasedItem_EnhancedRelocCompleteRes_PDU = -1;  /* RAB_ToBeReleasedItem_EnhancedRelocCompleteRes */
static int hf_ranap_EnhancedRelocationCompleteFailure_PDU = -1;  /* EnhancedRelocationCompleteFailure */
static int hf_ranap_EnhancedRelocationCompleteConfirm_PDU = -1;  /* EnhancedRelocationCompleteConfirm */
static int hf_ranap_Paging_PDU = -1;              /* Paging */
static int hf_ranap_CommonID_PDU = -1;            /* CommonID */
static int hf_ranap_CN_InvokeTrace_PDU = -1;      /* CN_InvokeTrace */
static int hf_ranap_CN_DeactivateTrace_PDU = -1;  /* CN_DeactivateTrace */
static int hf_ranap_LocationReportingControl_PDU = -1;  /* LocationReportingControl */
static int hf_ranap_LocationReport_PDU = -1;      /* LocationReport */
static int hf_ranap_InitialUE_Message_PDU = -1;   /* InitialUE_Message */
static int hf_ranap_DirectTransfer_PDU = -1;      /* DirectTransfer */
static int hf_ranap_RedirectionIndication_PDU = -1;  /* RedirectionIndication */
static int hf_ranap_Overload_PDU = -1;            /* Overload */
static int hf_ranap_ErrorIndication_PDU = -1;     /* ErrorIndication */
static int hf_ranap_SRNS_DataForwardCommand_PDU = -1;  /* SRNS_DataForwardCommand */
static int hf_ranap_ForwardSRNS_Context_PDU = -1;  /* ForwardSRNS_Context */
static int hf_ranap_RAB_AssignmentRequest_PDU = -1;  /* RAB_AssignmentRequest */
static int hf_ranap_RAB_SetupOrModifyList_PDU = -1;  /* RAB_SetupOrModifyList */
static int hf_ranap_RAB_SetupOrModifyItemFirst_PDU = -1;  /* RAB_SetupOrModifyItemFirst */
static int hf_ranap_TransportLayerInformation_PDU = -1;  /* TransportLayerInformation */
static int hf_ranap_RAB_SetupOrModifyItemSecond_PDU = -1;  /* RAB_SetupOrModifyItemSecond */
static int hf_ranap_RAB_AssignmentResponse_PDU = -1;  /* RAB_AssignmentResponse */
static int hf_ranap_RAB_SetupOrModifiedList_PDU = -1;  /* RAB_SetupOrModifiedList */
static int hf_ranap_RAB_SetupOrModifiedItem_PDU = -1;  /* RAB_SetupOrModifiedItem */
static int hf_ranap_RAB_ReleasedList_PDU = -1;    /* RAB_ReleasedList */
static int hf_ranap_RAB_ReleasedItem_PDU = -1;    /* RAB_ReleasedItem */
static int hf_ranap_RAB_QueuedList_PDU = -1;      /* RAB_QueuedList */
static int hf_ranap_RAB_QueuedItem_PDU = -1;      /* RAB_QueuedItem */
static int hf_ranap_RAB_ReleaseFailedList_PDU = -1;  /* RAB_ReleaseFailedList */
static int hf_ranap_GERAN_Iumode_RAB_FailedList_RABAssgntResponse_PDU = -1;  /* GERAN_Iumode_RAB_FailedList_RABAssgntResponse */
static int hf_ranap_GERAN_Iumode_RAB_Failed_RABAssgntResponse_Item_PDU = -1;  /* GERAN_Iumode_RAB_Failed_RABAssgntResponse_Item */
static int hf_ranap_PrivateMessage_PDU = -1;      /* PrivateMessage */
static int hf_ranap_RANAP_RelocationInformation_PDU = -1;  /* RANAP_RelocationInformation */
static int hf_ranap_DirectTransferInformationList_RANAP_RelocInf_PDU = -1;  /* DirectTransferInformationList_RANAP_RelocInf */
static int hf_ranap_DirectTransferInformationItem_RANAP_RelocInf_PDU = -1;  /* DirectTransferInformationItem_RANAP_RelocInf */
static int hf_ranap_RAB_ContextList_RANAP_RelocInf_PDU = -1;  /* RAB_ContextList_RANAP_RelocInf */
static int hf_ranap_RAB_ContextItem_RANAP_RelocInf_PDU = -1;  /* RAB_ContextItem_RANAP_RelocInf */
static int hf_ranap_RANAP_EnhancedRelocationInformationRequest_PDU = -1;  /* RANAP_EnhancedRelocationInformationRequest */
static int hf_ranap_RAB_SetupList_EnhRelocInfoReq_PDU = -1;  /* RAB_SetupList_EnhRelocInfoReq */
static int hf_ranap_RAB_SetupItem_EnhRelocInfoReq_PDU = -1;  /* RAB_SetupItem_EnhRelocInfoReq */
static int hf_ranap_RANAP_EnhancedRelocationInformationResponse_PDU = -1;  /* RANAP_EnhancedRelocationInformationResponse */
static int hf_ranap_RAB_SetupList_EnhRelocInfoRes_PDU = -1;  /* RAB_SetupList_EnhRelocInfoRes */
static int hf_ranap_RAB_SetupItem_EnhRelocInfoRes_PDU = -1;  /* RAB_SetupItem_EnhRelocInfoRes */
static int hf_ranap_RAB_FailedList_EnhRelocInfoRes_PDU = -1;  /* RAB_FailedList_EnhRelocInfoRes */
static int hf_ranap_RAB_FailedItem_EnhRelocInfoRes_PDU = -1;  /* RAB_FailedItem_EnhRelocInfoRes */
static int hf_ranap_RAB_ModifyRequest_PDU = -1;   /* RAB_ModifyRequest */
static int hf_ranap_RAB_ModifyList_PDU = -1;      /* RAB_ModifyList */
static int hf_ranap_RAB_ModifyItem_PDU = -1;      /* RAB_ModifyItem */
static int hf_ranap_LocationRelatedDataRequest_PDU = -1;  /* LocationRelatedDataRequest */
static int hf_ranap_LocationRelatedDataResponse_PDU = -1;  /* LocationRelatedDataResponse */
static int hf_ranap_LocationRelatedDataFailure_PDU = -1;  /* LocationRelatedDataFailure */
static int hf_ranap_InformationTransferIndication_PDU = -1;  /* InformationTransferIndication */
static int hf_ranap_InformationTransferConfirmation_PDU = -1;  /* InformationTransferConfirmation */
static int hf_ranap_InformationTransferFailure_PDU = -1;  /* InformationTransferFailure */
static int hf_ranap_UESpecificInformationIndication_PDU = -1;  /* UESpecificInformationIndication */
static int hf_ranap_DirectInformationTransfer_PDU = -1;  /* DirectInformationTransfer */
static int hf_ranap_UplinkInformationExchangeRequest_PDU = -1;  /* UplinkInformationExchangeRequest */
static int hf_ranap_UplinkInformationExchangeResponse_PDU = -1;  /* UplinkInformationExchangeResponse */
static int hf_ranap_UplinkInformationExchangeFailure_PDU = -1;  /* UplinkInformationExchangeFailure */
static int hf_ranap_MBMSSessionStart_PDU = -1;    /* MBMSSessionStart */
static int hf_ranap_MBMSSynchronisationInformation_PDU = -1;  /* MBMSSynchronisationInformation */
static int hf_ranap_MBMSSessionStartResponse_PDU = -1;  /* MBMSSessionStartResponse */
static int hf_ranap_MBMSSessionStartFailure_PDU = -1;  /* MBMSSessionStartFailure */
static int hf_ranap_MBMSSessionUpdate_PDU = -1;   /* MBMSSessionUpdate */
static int hf_ranap_MBMSSessionUpdateResponse_PDU = -1;  /* MBMSSessionUpdateResponse */
static int hf_ranap_MBMSSessionUpdateFailure_PDU = -1;  /* MBMSSessionUpdateFailure */
static int hf_ranap_MBMSSessionStop_PDU = -1;     /* MBMSSessionStop */
static int hf_ranap_MBMSSessionStopResponse_PDU = -1;  /* MBMSSessionStopResponse */
static int hf_ranap_MBMSUELinkingRequest_PDU = -1;  /* MBMSUELinkingRequest */
static int hf_ranap_LeftMBMSBearerService_IEs_PDU = -1;  /* LeftMBMSBearerService_IEs */
static int hf_ranap_MBMSUELinkingResponse_PDU = -1;  /* MBMSUELinkingResponse */
static int hf_ranap_UnsuccessfulLinking_IEs_PDU = -1;  /* UnsuccessfulLinking_IEs */
static int hf_ranap_MBMSRegistrationRequest_PDU = -1;  /* MBMSRegistrationRequest */
static int hf_ranap_MBMSRegistrationResponse_PDU = -1;  /* MBMSRegistrationResponse */
static int hf_ranap_MBMSRegistrationFailure_PDU = -1;  /* MBMSRegistrationFailure */
static int hf_ranap_MBMSCNDe_RegistrationRequest_PDU = -1;  /* MBMSCNDe_RegistrationRequest */
static int hf_ranap_MBMSCNDe_RegistrationResponse_PDU = -1;  /* MBMSCNDe_RegistrationResponse */
static int hf_ranap_MBMSRABEstablishmentIndication_PDU = -1;  /* MBMSRABEstablishmentIndication */
static int hf_ranap_MBMSRABReleaseRequest_PDU = -1;  /* MBMSRABReleaseRequest */
static int hf_ranap_MBMSRABRelease_PDU = -1;      /* MBMSRABRelease */
static int hf_ranap_MBMSRABReleaseFailure_PDU = -1;  /* MBMSRABReleaseFailure */
static int hf_ranap_SRVCC_CSKeysRequest_PDU = -1;  /* SRVCC_CSKeysRequest */
static int hf_ranap_SRVCC_CSKeysResponse_PDU = -1;  /* SRVCC_CSKeysResponse */
static int hf_ranap_RANAP_PDU_PDU = -1;           /* RANAP_PDU */
static int hf_ranap_local = -1;                   /* INTEGER_0_65535 */
static int hf_ranap_global = -1;                  /* OBJECT_IDENTIFIER */
static int hf_ranap_ProtocolIE_Container_item = -1;  /* ProtocolIE_Field */
static int hf_ranap_id = -1;                      /* ProtocolIE_ID */
static int hf_ranap_criticality = -1;             /* Criticality */
static int hf_ranap_ie_field_value = -1;          /* T_ie_field_value */
static int hf_ranap_ProtocolIE_ContainerPair_item = -1;  /* ProtocolIE_FieldPair */
static int hf_ranap_firstCriticality = -1;        /* Criticality */
static int hf_ranap_firstValue = -1;              /* T_firstValue */
static int hf_ranap_secondCriticality = -1;       /* Criticality */
static int hf_ranap_secondValue = -1;             /* T_secondValue */
static int hf_ranap_ProtocolIE_ContainerList_item = -1;  /* ProtocolIE_Container */
static int hf_ranap_ProtocolIE_ContainerPairList_item = -1;  /* ProtocolIE_ContainerPair */
static int hf_ranap_ProtocolExtensionContainer_item = -1;  /* ProtocolExtensionField */
static int hf_ranap_ext_id = -1;                  /* ProtocolExtensionID */
static int hf_ranap_extensionValue = -1;          /* T_extensionValue */
static int hf_ranap_PrivateIE_Container_item = -1;  /* PrivateIE_Field */
static int hf_ranap_private_id = -1;              /* PrivateIE_ID */
static int hf_ranap_private_value = -1;           /* T_private_value */
static int hf_ranap_priorityLevel = -1;           /* PriorityLevel */
static int hf_ranap_pre_emptionCapability = -1;   /* Pre_emptionCapability */
static int hf_ranap_pre_emptionVulnerability = -1;  /* Pre_emptionVulnerability */
static int hf_ranap_queuingAllowed = -1;          /* QueuingAllowed */
static int hf_ranap_iE_Extensions = -1;           /* ProtocolExtensionContainer */
static int hf_ranap_altMaxBitrateInf = -1;        /* Alt_RAB_Parameter_MaxBitrateInf */
static int hf_ranap_altGuaranteedBitRateInf = -1;  /* Alt_RAB_Parameter_GuaranteedBitrateInf */
static int hf_ranap_altExtendedGuaranteedBitrateType = -1;  /* Alt_RAB_Parameter_GuaranteedBitrateType */
static int hf_ranap_altExtendedGuaranteedBitrates = -1;  /* Alt_RAB_Parameter_ExtendedGuaranteedBitrates */
static int hf_ranap_Alt_RAB_Parameter_ExtendedGuaranteedBitrates_item = -1;  /* Alt_RAB_Parameter_ExtendedGuaranteedBitrateList */
static int hf_ranap_Alt_RAB_Parameter_ExtendedGuaranteedBitrateList_item = -1;  /* ExtendedGuaranteedBitrate */
static int hf_ranap_altGuaranteedBitrateType = -1;  /* Alt_RAB_Parameter_GuaranteedBitrateType */
static int hf_ranap_altGuaranteedBitrates = -1;   /* Alt_RAB_Parameter_GuaranteedBitrates */
static int hf_ranap_Alt_RAB_Parameter_GuaranteedBitrates_item = -1;  /* Alt_RAB_Parameter_GuaranteedBitrateList */
static int hf_ranap_Alt_RAB_Parameter_GuaranteedBitrateList_item = -1;  /* GuaranteedBitrate */
static int hf_ranap_altSupportedGuaranteedBitrateType = -1;  /* Alt_RAB_Parameter_GuaranteedBitrateType */
static int hf_ranap_altSupportedGuaranteedBitrates = -1;  /* Alt_RAB_Parameter_SupportedGuaranteedBitrates */
static int hf_ranap_Alt_RAB_Parameter_SupportedGuaranteedBitrates_item = -1;  /* SupportedRAB_ParameterBitrateList */
static int hf_ranap_altExtendedMaxBitrateType = -1;  /* Alt_RAB_Parameter_MaxBitrateType */
static int hf_ranap_altExtendedMaxBitrates = -1;  /* Alt_RAB_Parameter_ExtendedMaxBitrates */
static int hf_ranap_Alt_RAB_Parameter_ExtendedMaxBitrates_item = -1;  /* Alt_RAB_Parameter_ExtendedMaxBitrateList */
static int hf_ranap_Alt_RAB_Parameter_ExtendedMaxBitrateList_item = -1;  /* ExtendedMaxBitrate */
static int hf_ranap_altMaxBitrateType = -1;       /* Alt_RAB_Parameter_MaxBitrateType */
static int hf_ranap_altMaxBitrates = -1;          /* Alt_RAB_Parameter_MaxBitrates */
static int hf_ranap_Alt_RAB_Parameter_MaxBitrates_item = -1;  /* Alt_RAB_Parameter_MaxBitrateList */
static int hf_ranap_Alt_RAB_Parameter_MaxBitrateList_item = -1;  /* MaxBitrate */
static int hf_ranap_altSupportedMaxBitrateType = -1;  /* Alt_RAB_Parameter_MaxBitrateType */
static int hf_ranap_altSupportedMaxBitrates = -1;  /* Alt_RAB_Parameter_SupportedMaxBitrates */
static int hf_ranap_Alt_RAB_Parameter_SupportedMaxBitrates_item = -1;  /* SupportedRAB_ParameterBitrateList */
static int hf_ranap_sAI = -1;                     /* SAI */
static int hf_ranap_geographicalArea = -1;        /* GeographicalArea */
static int hf_ranap_assMaxBitrateInf = -1;        /* Ass_RAB_Parameter_MaxBitrateList */
static int hf_ranap_assGuaranteedBitRateInf = -1;  /* Ass_RAB_Parameter_GuaranteedBitrateList */
static int hf_ranap_Ass_RAB_Parameter_ExtendedGuaranteedBitrateList_item = -1;  /* ExtendedGuaranteedBitrate */
static int hf_ranap_Ass_RAB_Parameter_ExtendedMaxBitrateList_item = -1;  /* ExtendedMaxBitrate */
static int hf_ranap_Ass_RAB_Parameter_GuaranteedBitrateList_item = -1;  /* GuaranteedBitrate */
static int hf_ranap_Ass_RAB_Parameter_MaxBitrateList_item = -1;  /* MaxBitrate */
static int hf_ranap_AuthorisedPLMNs_item = -1;    /* AuthorisedPLMNs_item */
static int hf_ranap_pLMNidentity = -1;            /* PLMNidentity */
static int hf_ranap_authorisedSNAsList = -1;      /* AuthorisedSNAs */
static int hf_ranap_AuthorisedSNAs_item = -1;     /* SNAC */
static int hf_ranap_cipheringKeyFlag = -1;        /* BIT_STRING_SIZE_1 */
static int hf_ranap_currentDecipheringKey = -1;   /* BIT_STRING_SIZE_56 */
static int hf_ranap_nextDecipheringKey = -1;      /* BIT_STRING_SIZE_56 */
static int hf_ranap_radioNetwork = -1;            /* CauseRadioNetwork */
static int hf_ranap_transmissionNetwork = -1;     /* CauseTransmissionNetwork */
static int hf_ranap_nAS = -1;                     /* CauseNAS */
static int hf_ranap_protocol = -1;                /* CauseProtocol */
static int hf_ranap_misc = -1;                    /* CauseMisc */
static int hf_ranap_non_Standard = -1;            /* CauseNon_Standard */
static int hf_ranap_radioNetworkExtension = -1;   /* CauseRadioNetworkExtension */
static int hf_ranap_cellIdList = -1;              /* CellIdList */
static int hf_ranap_CellIdList_item = -1;         /* Cell_Id */
static int hf_ranap_cell_Capacity_Class_Value = -1;  /* Cell_Capacity_Class_Value */
static int hf_ranap_loadValue = -1;               /* LoadValue */
static int hf_ranap_rTLoadValue = -1;             /* RTLoadValue */
static int hf_ranap_nRTLoadInformationValue = -1;  /* NRTLoadInformationValue */
static int hf_ranap_sourceCellID = -1;            /* SourceCellID */
static int hf_ranap_uplinkCellLoadInformation = -1;  /* CellLoadInformation */
static int hf_ranap_downlinkCellLoadInformation = -1;  /* CellLoadInformation */
static int hf_ranap_procedureCode = -1;           /* ProcedureCode */
static int hf_ranap_triggeringMessage = -1;       /* TriggeringMessage */
static int hf_ranap_procedureCriticality = -1;    /* Criticality */
static int hf_ranap_iEsCriticalityDiagnostics = -1;  /* CriticalityDiagnostics_IE_List */
static int hf_ranap_CriticalityDiagnostics_IE_List_item = -1;  /* CriticalityDiagnostics_IE_List_item */
static int hf_ranap_iECriticality = -1;           /* Criticality */
static int hf_ranap_iE_ID = -1;                   /* ProtocolIE_ID */
static int hf_ranap_repetitionNumber = -1;        /* RepetitionNumber0 */
static int hf_ranap_MessageStructure_item = -1;   /* MessageStructure_item */
static int hf_ranap_item_repetitionNumber = -1;   /* RepetitionNumber1 */
static int hf_ranap_lAC = -1;                     /* LAC */
static int hf_ranap_cI = -1;                      /* CI */
static int hf_ranap_CSG_Id_List_item = -1;        /* CSG_Id */
static int hf_ranap_newRAListofIdleModeUEs = -1;  /* NewRAListofIdleModeUEs */
static int hf_ranap_rAListwithNoIdleModeUEsAnyMore = -1;  /* RAListwithNoIdleModeUEsAnyMore */
static int hf_ranap_NewRAListofIdleModeUEs_item = -1;  /* RAC */
static int hf_ranap_RAListwithNoIdleModeUEsAnyMore_item = -1;  /* RAC */
static int hf_ranap_macroENB_ID = -1;             /* BIT_STRING_SIZE_20 */
static int hf_ranap_homeENB_ID = -1;              /* BIT_STRING_SIZE_28 */
static int hf_ranap_permittedAlgorithms = -1;     /* PermittedEncryptionAlgorithms */
static int hf_ranap_key = -1;                     /* EncryptionKey */
static int hf_ranap_iMEIlist = -1;                /* IMEIList */
static int hf_ranap_iMEISVlist = -1;              /* IMEISVList */
static int hf_ranap_iMEIgroup = -1;               /* IMEIGroup */
static int hf_ranap_iMEISVgroup = -1;             /* IMEISVGroup */
static int hf_ranap_measurementQuantity = -1;     /* MeasurementQuantity */
static int hf_ranap_threshold = -1;               /* INTEGER_M120_165 */
static int hf_ranap_threshold_01 = -1;            /* INTEGER_M120_M25 */
static int hf_ranap_GANSS_PositioningDataSet_item = -1;  /* GANSS_PositioningMethodAndUsage */
static int hf_ranap_point = -1;                   /* GA_Point */
static int hf_ranap_pointWithUnCertainty = -1;    /* GA_PointWithUnCertainty */
static int hf_ranap_polygon = -1;                 /* GA_Polygon */
static int hf_ranap_pointWithUncertaintyEllipse = -1;  /* GA_PointWithUnCertaintyEllipse */
static int hf_ranap_pointWithAltitude = -1;       /* GA_PointWithAltitude */
static int hf_ranap_pointWithAltitudeAndUncertaintyEllipsoid = -1;  /* GA_PointWithAltitudeAndUncertaintyEllipsoid */
static int hf_ranap_ellipsoidArc = -1;            /* GA_EllipsoidArc */
static int hf_ranap_latitudeSign = -1;            /* T_latitudeSign */
static int hf_ranap_latitude = -1;                /* INTEGER_0_8388607 */
static int hf_ranap_longitude = -1;               /* INTEGER_M8388608_8388607 */
static int hf_ranap_directionOfAltitude = -1;     /* T_directionOfAltitude */
static int hf_ranap_altitude = -1;                /* INTEGER_0_32767 */
static int hf_ranap_geographicalCoordinates = -1;  /* GeographicalCoordinates */
static int hf_ranap_innerRadius = -1;             /* INTEGER_0_65535 */
static int hf_ranap_uncertaintyRadius = -1;       /* INTEGER_0_127 */
static int hf_ranap_offsetAngle = -1;             /* INTEGER_0_179 */
static int hf_ranap_includedAngle = -1;           /* INTEGER_0_179 */
static int hf_ranap_confidence = -1;              /* INTEGER_0_127 */
static int hf_ranap_altitudeAndDirection = -1;    /* GA_AltitudeAndDirection */
static int hf_ranap_uncertaintyEllipse = -1;      /* GA_UncertaintyEllipse */
static int hf_ranap_uncertaintyAltitude = -1;     /* INTEGER_0_127 */
static int hf_ranap_uncertaintyCode = -1;         /* INTEGER_0_127 */
static int hf_ranap_GA_Polygon_item = -1;         /* GA_Polygon_item */
static int hf_ranap_uncertaintySemi_major = -1;   /* INTEGER_0_127 */
static int hf_ranap_uncertaintySemi_minor = -1;   /* INTEGER_0_127 */
static int hf_ranap_orientationOfMajorAxis = -1;  /* INTEGER_0_179 */
static int hf_ranap_lAI = -1;                     /* LAI */
static int hf_ranap_rAC = -1;                     /* RAC */
static int hf_ranap_cN_ID = -1;                   /* CN_ID */
static int hf_ranap_rNC_ID = -1;                  /* RNC_ID */
static int hf_ranap_iMEI = -1;                    /* IMEI */
static int hf_ranap_iMEIMask = -1;                /* BIT_STRING_SIZE_7 */
static int hf_ranap_IMEIList_item = -1;           /* IMEI */
static int hf_ranap_iMEISV = -1;                  /* IMEISV */
static int hf_ranap_iMEISVMask = -1;              /* BIT_STRING_SIZE_7 */
static int hf_ranap_IMEISVList_item = -1;         /* IMEISV */
static int hf_ranap_measurementsToActivate = -1;  /* MeasurementsToActivate */
static int hf_ranap_m1report = -1;                /* M1Report */
static int hf_ranap_m2report = -1;                /* M2Report */
static int hf_ranap_requestedMBMSIPMulticastAddressandAPNRequest = -1;  /* RequestedMBMSIPMulticastAddressandAPNRequest */
static int hf_ranap_requestedMulticastServiceList = -1;  /* RequestedMulticastServiceList */
static int hf_ranap_mBMSIPMulticastAddressandAPNRequest = -1;  /* MBMSIPMulticastAddressandAPNRequest */
static int hf_ranap_permanentNAS_UE_ID = -1;      /* PermanentNAS_UE_ID */
static int hf_ranap_rNCTraceInformation = -1;     /* RNCTraceInformation */
static int hf_ranap_permittedAlgorithms_01 = -1;  /* PermittedIntegrityProtectionAlgorithms */
static int hf_ranap_key_01 = -1;                  /* IntegrityProtectionKey */
static int hf_ranap_rIM_Transfer = -1;            /* RIM_Transfer */
static int hf_ranap_gTP_TEI = -1;                 /* GTP_TEI */
static int hf_ranap_bindingID = -1;               /* BindingID */
static int hf_ranap_LA_LIST_item = -1;            /* LA_LIST_item */
static int hf_ranap_listOF_SNAs = -1;             /* ListOF_SNAs */
static int hf_ranap_ageOfSAI = -1;                /* INTEGER_0_32767 */
static int hf_ranap_ListOF_SNAs_item = -1;        /* SNAC */
static int hf_ranap_ListOfInterfacesToTrace_item = -1;  /* InterfacesToTraceItem */
static int hf_ranap_interface = -1;               /* T_interface */
static int hf_ranap_requestedLocationRelatedDataType = -1;  /* RequestedLocationRelatedDataType */
static int hf_ranap_requestedGPSAssistanceData = -1;  /* RequestedGPSAssistanceData */
static int hf_ranap_reportChangeOfSAI = -1;       /* ReportChangeOfSAI */
static int hf_ranap_periodicReportingIndicator = -1;  /* PeriodicReportingIndicator */
static int hf_ranap_directReportingIndicator = -1;  /* DirectReportingIndicator */
static int hf_ranap_verticalAccuracyCode = -1;    /* VerticalAccuracyCode */
static int hf_ranap_positioningPriorityChangeSAI = -1;  /* PositioningPriority */
static int hf_ranap_positioningPriorityDirect = -1;  /* PositioningPriority */
static int hf_ranap_clientTypePeriodic = -1;      /* ClientType */
static int hf_ranap_clientTypeDirect = -1;        /* ClientType */
static int hf_ranap_responseTime = -1;            /* ResponseTime */
static int hf_ranap_includeVelocity = -1;         /* IncludeVelocity */
static int hf_ranap_periodicLocationInfo = -1;    /* PeriodicLocationInfo */
static int hf_ranap_periodic = -1;                /* MDT_Report_Parameters */
static int hf_ranap_event1F = -1;                 /* Event1F_Parameters */
static int hf_ranap_event1I = -1;                 /* Event1I_Parameters */
static int hf_ranap_MBMSIPMulticastAddressandAPNRequest_item = -1;  /* TMGI */
static int hf_ranap_cellbased = -1;               /* CellBased */
static int hf_ranap_labased = -1;                 /* LABased */
static int hf_ranap_rabased = -1;                 /* RABased */
static int hf_ranap_plmn_area_based = -1;         /* PLMNAreaBased */
static int hf_ranap_mdtRecordingSessionReference = -1;  /* TraceRecordingSessionReference */
static int hf_ranap_mdtActivation = -1;           /* MDT_Activation */
static int hf_ranap_mdtAreaScope = -1;            /* MDTAreaScope */
static int hf_ranap_mdtMode = -1;                 /* MDTMode */
static int hf_ranap_immediateMDT = -1;            /* ImmediateMDT */
static int hf_ranap_loggedMDT = -1;               /* LoggedMDT */
static int hf_ranap_reportInterval = -1;          /* ReportInterval */
static int hf_ranap_reportAmount = -1;            /* ReportAmount */
static int hf_ranap_accessPointName = -1;         /* Offload_RAB_Parameters_APN */
static int hf_ranap_chargingCharacteristics = -1;  /* Offload_RAB_Parameters_ChargingCharacteristics */
static int hf_ranap_rAI = -1;                     /* RAI */
static int hf_ranap_PDP_TypeInformation_item = -1;  /* PDP_Type */
static int hf_ranap_PDP_TypeInformation_extension_item = -1;  /* PDP_Type_extension */
static int hf_ranap_reportingAmount = -1;         /* INTEGER_1_8639999_ */
static int hf_ranap_reportingInterval = -1;       /* INTEGER_1_8639999_ */
static int hf_ranap_iMSI = -1;                    /* IMSI */
static int hf_ranap_PermittedEncryptionAlgorithms_item = -1;  /* EncryptionAlgorithm */
static int hf_ranap_PermittedIntegrityProtectionAlgorithms_item = -1;  /* IntegrityProtectionAlgorithm */
static int hf_ranap_laiList = -1;                 /* LAI_List */
static int hf_ranap_LAI_List_item = -1;           /* LAI */
static int hf_ranap_loggingInterval = -1;         /* LoggingInterval */
static int hf_ranap_loggingDuration = -1;         /* LoggingDuration */
static int hf_ranap_plmnID = -1;                  /* PLMNidentity */
static int hf_ranap_PLMNs_in_shared_network_item = -1;  /* PLMNs_in_shared_network_item */
static int hf_ranap_lA_LIST = -1;                 /* LA_LIST */
static int hf_ranap_PositioningDataSet_item = -1;  /* PositioningMethodAndUsage */
static int hf_ranap_positioningDataDiscriminator = -1;  /* PositioningDataDiscriminator */
static int hf_ranap_positioningDataSet = -1;      /* PositioningDataSet */
static int hf_ranap_shared_network_information = -1;  /* Shared_Network_Information */
static int hf_ranap_racList = -1;                 /* RAC_List */
static int hf_ranap_RAC_List_item = -1;           /* RAC */
static int hf_ranap_RABDataVolumeReport_item = -1;  /* RABDataVolumeReport_item */
static int hf_ranap_dl_UnsuccessfullyTransmittedDataVolume = -1;  /* UnsuccessfullyTransmittedDataVolume */
static int hf_ranap_dataVolumeReference = -1;     /* DataVolumeReference */
static int hf_ranap_RAB_Parameter_ExtendedGuaranteedBitrateList_item = -1;  /* ExtendedGuaranteedBitrate */
static int hf_ranap_RAB_Parameter_ExtendedMaxBitrateList_item = -1;  /* ExtendedMaxBitrate */
static int hf_ranap_RAB_Parameter_GuaranteedBitrateList_item = -1;  /* GuaranteedBitrate */
static int hf_ranap_RAB_Parameter_MaxBitrateList_item = -1;  /* MaxBitrate */
static int hf_ranap_trafficClass = -1;            /* TrafficClass */
static int hf_ranap_rAB_AsymmetryIndicator = -1;  /* RAB_AsymmetryIndicator */
static int hf_ranap_maxBitrate = -1;              /* RAB_Parameter_MaxBitrateList */
static int hf_ranap_guaranteedBitRate = -1;       /* RAB_Parameter_GuaranteedBitrateList */
static int hf_ranap_deliveryOrder = -1;           /* DeliveryOrder */
static int hf_ranap_maxSDU_Size = -1;             /* MaxSDU_Size */
static int hf_ranap_sDU_Parameters = -1;          /* SDU_Parameters */
static int hf_ranap_transferDelay = -1;           /* TransferDelay */
static int hf_ranap_trafficHandlingPriority = -1;  /* TrafficHandlingPriority */
static int hf_ranap_allocationOrRetentionPriority = -1;  /* AllocationOrRetentionPriority */
static int hf_ranap_sourceStatisticsDescriptor = -1;  /* SourceStatisticsDescriptor */
static int hf_ranap_relocationRequirement = -1;   /* RelocationRequirement */
static int hf_ranap_RABParametersList_item = -1;  /* RABParametersList_item */
static int hf_ranap_rab_Id = -1;                  /* RAB_ID */
static int hf_ranap_cn_domain = -1;               /* CN_DomainIndicator */
static int hf_ranap_rabDataVolumeReport = -1;     /* RABDataVolumeReport */
static int hf_ranap_upInformation = -1;           /* UPInformation */
static int hf_ranap_RAB_TrCH_Mapping_item = -1;   /* RAB_TrCH_MappingItem */
static int hf_ranap_rAB_ID = -1;                  /* RAB_ID */
static int hf_ranap_trCH_ID_List = -1;            /* TrCH_ID_List */
static int hf_ranap_notEmptyRAListofIdleModeUEs = -1;  /* NotEmptyRAListofIdleModeUEs */
static int hf_ranap_emptyFullRAListofIdleModeUEs = -1;  /* T_emptyFullRAListofIdleModeUEs */
static int hf_ranap_rAofIdleModeUEs = -1;         /* RAofIdleModeUEs */
static int hf_ranap_RAofIdleModeUEs_item = -1;    /* RAC */
static int hf_ranap_LAListofIdleModeUEs_item = -1;  /* LAI */
static int hf_ranap_RequestedMBMSIPMulticastAddressandAPNRequest_item = -1;  /* MBMSIPMulticastAddressandAPNlist */
static int hf_ranap_tMGI = -1;                    /* TMGI */
static int hf_ranap_iPMulticastAddress = -1;      /* IPMulticastAddress */
static int hf_ranap_aPN = -1;                     /* APN */
static int hf_ranap_RequestedMulticastServiceList_item = -1;  /* TMGI */
static int hf_ranap_requestedMaxBitrates = -1;    /* Requested_RAB_Parameter_MaxBitrateList */
static int hf_ranap_requestedGuaranteedBitrates = -1;  /* Requested_RAB_Parameter_GuaranteedBitrateList */
static int hf_ranap_Requested_RAB_Parameter_ExtendedMaxBitrateList_item = -1;  /* ExtendedMaxBitrate */
static int hf_ranap_Requested_RAB_Parameter_ExtendedGuaranteedBitrateList_item = -1;  /* ExtendedGuaranteedBitrate */
static int hf_ranap_Requested_RAB_Parameter_MaxBitrateList_item = -1;  /* MaxBitrate */
static int hf_ranap_Requested_RAB_Parameter_GuaranteedBitrateList_item = -1;  /* GuaranteedBitrate */
static int hf_ranap_event = -1;                   /* Event */
static int hf_ranap_reportArea = -1;              /* ReportArea */
static int hf_ranap_accuracyCode = -1;            /* INTEGER_0_127 */
static int hf_ranap_mantissa = -1;                /* INTEGER_1_9 */
static int hf_ranap_exponent = -1;                /* INTEGER_1_8 */
static int hf_ranap_rIMInformation = -1;          /* RIMInformation */
static int hf_ranap_rIMRoutingAddress = -1;       /* RIMRoutingAddress */
static int hf_ranap_targetRNC_ID = -1;            /* TargetRNC_ID */
static int hf_ranap_gERAN_Cell_ID = -1;           /* GERAN_Cell_ID */
static int hf_ranap_targeteNB_ID = -1;            /* TargetENB_ID */
static int hf_ranap_traceReference = -1;          /* TraceReference */
static int hf_ranap_traceActivationIndicator = -1;  /* T_traceActivationIndicator */
static int hf_ranap_equipmentsToBeTraced = -1;    /* EquipmentsToBeTraced */
static int hf_ranap_rabParmetersList = -1;        /* RABParametersList */
static int hf_ranap_locationReporting = -1;       /* LocationReportingTransferInformation */
static int hf_ranap_traceInformation = -1;        /* TraceInformation */
static int hf_ranap_sourceSAI = -1;               /* SAI */
static int hf_ranap_sAC = -1;                     /* SAC */
static int hf_ranap_pLMNs_in_shared_network = -1;  /* PLMNs_in_shared_network */
static int hf_ranap_exponent_1_8 = -1;            /* INTEGER_1_6 */
static int hf_ranap_SDU_FormatInformationParameters_item = -1;  /* SDU_FormatInformationParameters_item */
static int hf_ranap_subflowSDU_Size = -1;         /* SubflowSDU_Size */
static int hf_ranap_rAB_SubflowCombinationBitRate = -1;  /* RAB_SubflowCombinationBitRate */
static int hf_ranap_SDU_Parameters_item = -1;     /* SDU_Parameters_item */
static int hf_ranap_sDU_ErrorRatio = -1;          /* SDU_ErrorRatio */
static int hf_ranap_residualBitErrorRatio = -1;   /* ResidualBitErrorRatio */
static int hf_ranap_deliveryOfErroneousSDU = -1;  /* DeliveryOfErroneousSDU */
static int hf_ranap_sDU_FormatInformationParameters = -1;  /* SDU_FormatInformationParameters */
static int hf_ranap_authorisedPLMNs = -1;         /* AuthorisedPLMNs */
static int hf_ranap_sourceUTRANCellID = -1;       /* SourceUTRANCellID */
static int hf_ranap_sourceGERANCellID = -1;       /* CGI */
static int hf_ranap_sourceRNC_ID = -1;            /* SourceRNC_ID */
static int hf_ranap_rRC_Container = -1;           /* RRC_Container */
static int hf_ranap_numberOfIuInstances = -1;     /* NumberOfIuInstances */
static int hf_ranap_relocationType = -1;          /* RelocationType */
static int hf_ranap_chosenIntegrityProtectionAlgorithm = -1;  /* ChosenIntegrityProtectionAlgorithm */
static int hf_ranap_integrityProtectionKey = -1;  /* IntegrityProtectionKey */
static int hf_ranap_chosenEncryptionAlgorithForSignalling = -1;  /* ChosenEncryptionAlgorithm */
static int hf_ranap_cipheringKey = -1;            /* EncryptionKey */
static int hf_ranap_chosenEncryptionAlgorithForCS = -1;  /* ChosenEncryptionAlgorithm */
static int hf_ranap_chosenEncryptionAlgorithForPS = -1;  /* ChosenEncryptionAlgorithm */
static int hf_ranap_d_RNTI = -1;                  /* D_RNTI */
static int hf_ranap_targetCellId = -1;            /* TargetCellId */
static int hf_ranap_rAB_TrCH_Mapping = -1;        /* RAB_TrCH_Mapping */
static int hf_ranap_rSRP = -1;                    /* INTEGER_0_97 */
static int hf_ranap_rSRQ = -1;                    /* INTEGER_0_34 */
static int hf_ranap_iRATmeasurementParameters = -1;  /* IRATmeasurementParameters */
static int hf_ranap_measurementDuration = -1;     /* INTEGER_1_100 */
static int hf_ranap_eUTRANFrequencies = -1;       /* EUTRANFrequencies */
static int hf_ranap_EUTRANFrequencies_item = -1;  /* EUTRANFrequencies_item */
static int hf_ranap_earfcn = -1;                  /* INTEGER_0_65535 */
static int hf_ranap_measBand = -1;                /* MeasBand */
static int hf_ranap_SupportedRAB_ParameterBitrateList_item = -1;  /* SupportedBitrate */
static int hf_ranap_uTRANcellID = -1;             /* TargetCellId */
static int hf_ranap_SRB_TrCH_Mapping_item = -1;   /* SRB_TrCH_MappingItem */
static int hf_ranap_sRB_ID = -1;                  /* SRB_ID */
static int hf_ranap_trCH_ID = -1;                 /* TrCH_ID */
static int hf_ranap_nonce = -1;                   /* BIT_STRING_SIZE_128 */
static int hf_ranap_tAC = -1;                     /* TAC */
static int hf_ranap_cGI = -1;                     /* CGI */
static int hf_ranap_eNB_ID = -1;                  /* ENB_ID */
static int hf_ranap_selectedTAI = -1;             /* TAI */
static int hf_ranap_tMSI = -1;                    /* TMSI */
static int hf_ranap_p_TMSI = -1;                  /* P_TMSI */
static int hf_ranap_serviceID = -1;               /* OCTET_STRING_SIZE_3 */
static int hf_ranap_ue_identity = -1;             /* UE_ID */
static int hf_ranap_tracePropagationParameters = -1;  /* TracePropagationParameters */
static int hf_ranap_traceRecordingSessionReference = -1;  /* TraceRecordingSessionReference */
static int hf_ranap_traceDepth = -1;              /* TraceDepth */
static int hf_ranap_listOfInterfacesToTrace = -1;  /* ListOfInterfacesToTrace */
static int hf_ranap_dCH_ID = -1;                  /* DCH_ID */
static int hf_ranap_dSCH_ID = -1;                 /* DSCH_ID */
static int hf_ranap_uSCH_ID = -1;                 /* USCH_ID */
static int hf_ranap_TrCH_ID_List_item = -1;       /* TrCH_ID */
static int hf_ranap_uE_AggregateMaximumBitRateDownlink = -1;  /* UE_AggregateMaximumBitRateDownlink */
static int hf_ranap_uE_AggregateMaximumBitRateUplink = -1;  /* UE_AggregateMaximumBitRateUplink */
static int hf_ranap_imsi = -1;                    /* IMSI */
static int hf_ranap_imei = -1;                    /* IMEI */
static int hf_ranap_imeisv = -1;                  /* IMEISV */
static int hf_ranap_uESBI_IuA = -1;               /* UESBI_IuA */
static int hf_ranap_uESBI_IuB = -1;               /* UESBI_IuB */
static int hf_ranap_frameSeqNoUL = -1;            /* FrameSequenceNumber */
static int hf_ranap_frameSeqNoDL = -1;            /* FrameSequenceNumber */
static int hf_ranap_pdu14FrameSeqNoUL = -1;       /* PDUType14FrameSequenceNumber */
static int hf_ranap_pdu14FrameSeqNoDL = -1;       /* PDUType14FrameSequenceNumber */
static int hf_ranap_dataPDUType = -1;             /* DataPDUType */
static int hf_ranap_upinitialisationFrame = -1;   /* UPInitialisationFrame */
static int hf_ranap_horizontalVelocity = -1;      /* HorizontalVelocity */
static int hf_ranap_horizontalWithVerticalVelocity = -1;  /* HorizontalWithVerticalVelocity */
static int hf_ranap_horizontalVelocityWithUncertainty = -1;  /* HorizontalVelocityWithUncertainty */
static int hf_ranap_horizontalWithVeritcalVelocityAndUncertainty = -1;  /* HorizontalWithVerticalVelocityAndUncertainty */
static int hf_ranap_horizontalSpeedAndBearing = -1;  /* HorizontalSpeedAndBearing */
static int hf_ranap_veritcalVelocity = -1;        /* VerticalVelocity */
static int hf_ranap_uncertaintySpeed = -1;        /* INTEGER_0_255 */
static int hf_ranap_horizontalUncertaintySpeed = -1;  /* INTEGER_0_255 */
static int hf_ranap_verticalUncertaintySpeed = -1;  /* INTEGER_0_255 */
static int hf_ranap_bearing = -1;                 /* INTEGER_0_359 */
static int hf_ranap_horizontalSpeed = -1;         /* INTEGER_0_2047 */
static int hf_ranap_veritcalSpeed = -1;           /* INTEGER_0_255 */
static int hf_ranap_veritcalSpeedDirection = -1;  /* VerticalSpeedDirection */
static int hf_ranap_protocolIEs = -1;             /* ProtocolIE_Container */
static int hf_ranap_protocolExtensions = -1;      /* ProtocolExtensionContainer */
static int hf_ranap_rab_dl_UnsuccessfullyTransmittedDataVolume = -1;  /* DataVolumeList */
static int hf_ranap_dL_GTP_PDU_SequenceNumber = -1;  /* DL_GTP_PDU_SequenceNumber */
static int hf_ranap_uL_GTP_PDU_SequenceNumber = -1;  /* UL_GTP_PDU_SequenceNumber */
static int hf_ranap_transportLayerAddress = -1;   /* TransportLayerAddress */
static int hf_ranap_iuTransportAssociation = -1;  /* IuTransportAssociation */
static int hf_ranap_nAS_SynchronisationIndicator = -1;  /* NAS_SynchronisationIndicator */
static int hf_ranap_rAB_Parameters = -1;          /* RAB_Parameters */
static int hf_ranap_dataVolumeReportingIndication = -1;  /* DataVolumeReportingIndication */
static int hf_ranap_pDP_TypeInformation = -1;     /* PDP_TypeInformation */
static int hf_ranap_userPlaneInformation = -1;    /* UserPlaneInformation */
static int hf_ranap_service_Handover = -1;        /* Service_Handover */
static int hf_ranap_userPlaneMode = -1;           /* UserPlaneMode */
static int hf_ranap_uP_ModeVersions = -1;         /* UP_ModeVersions */
static int hf_ranap_joinedMBMSBearerService_IEs = -1;  /* JoinedMBMSBearerService_IEs */
static int hf_ranap_JoinedMBMSBearerService_IEs_item = -1;  /* JoinedMBMSBearerService_IEs_item */
static int hf_ranap_mBMS_PTP_RAB_ID = -1;         /* MBMS_PTP_RAB_ID */
static int hf_ranap_cause = -1;                   /* Cause */
static int hf_ranap_dl_GTP_PDU_SequenceNumber = -1;  /* DL_GTP_PDU_SequenceNumber */
static int hf_ranap_ul_GTP_PDU_SequenceNumber = -1;  /* UL_GTP_PDU_SequenceNumber */
static int hf_ranap_dl_N_PDU_SequenceNumber = -1;  /* DL_N_PDU_SequenceNumber */
static int hf_ranap_ul_N_PDU_SequenceNumber = -1;  /* UL_N_PDU_SequenceNumber */
static int hf_ranap_iuSigConId = -1;              /* IuSignallingConnectionIdentifier */
static int hf_ranap_transportLayerAddressReq1 = -1;  /* TransportLayerAddress */
static int hf_ranap_iuTransportAssociationReq1 = -1;  /* IuTransportAssociation */
static int hf_ranap_ass_RAB_Parameters = -1;      /* Ass_RAB_Parameters */
static int hf_ranap_transportLayerAddressRes1 = -1;  /* TransportLayerAddress */
static int hf_ranap_iuTransportAssociationRes1 = -1;  /* IuTransportAssociation */
static int hf_ranap_rab2beReleasedList = -1;      /* RAB_ToBeReleasedList_EnhancedRelocCompleteRes */
static int hf_ranap_transportLayerInformation = -1;  /* TransportLayerInformation */
static int hf_ranap_dl_dataVolumes = -1;          /* DataVolumeList */
static int hf_ranap_DataVolumeList_item = -1;     /* DataVolumeList_item */
static int hf_ranap_gERAN_Classmark = -1;         /* GERAN_Classmark */
static int hf_ranap_privateIEs = -1;              /* PrivateIE_Container */
static int hf_ranap_nAS_PDU = -1;                 /* NAS_PDU */
static int hf_ranap_sAPI = -1;                    /* SAPI */
static int hf_ranap_cN_DomainIndicator = -1;      /* CN_DomainIndicator */
static int hf_ranap_dataForwardingInformation = -1;  /* TNLInformationEnhRelInfoReq */
static int hf_ranap_sourceSideIuULTNLInfo = -1;   /* TNLInformationEnhRelInfoReq */
static int hf_ranap_alt_RAB_Parameters = -1;      /* Alt_RAB_Parameters */
static int hf_ranap_dataForwardingInformation_01 = -1;  /* TNLInformationEnhRelInfoRes */
static int hf_ranap_dl_forwardingTransportLayerAddress = -1;  /* TransportLayerAddress */
static int hf_ranap_dl_forwardingTransportAssociation = -1;  /* IuTransportAssociation */
static int hf_ranap_requested_RAB_Parameter_Values = -1;  /* Requested_RAB_Parameter_Values */
static int hf_ranap_mBMSHCIndicator = -1;         /* MBMSHCIndicator */
static int hf_ranap_gTPDLTEID = -1;               /* GTP_TEI */
static int hf_ranap_LeftMBMSBearerService_IEs_item = -1;  /* LeftMBMSBearerService_IEs_item */
static int hf_ranap_UnsuccessfulLinking_IEs_item = -1;  /* UnsuccessfulLinking_IEs_item */
static int hf_ranap_initiatingMessage = -1;       /* InitiatingMessage */
static int hf_ranap_successfulOutcome = -1;       /* SuccessfulOutcome */
static int hf_ranap_unsuccessfulOutcome = -1;     /* UnsuccessfulOutcome */
static int hf_ranap_outcome = -1;                 /* Outcome */
static int hf_ranap_initiatingMessagevalue = -1;  /* InitiatingMessage_value */
static int hf_ranap_successfulOutcome_value = -1;  /* SuccessfulOutcome_value */
static int hf_ranap_unsuccessfulOutcome_value = -1;  /* UnsuccessfulOutcome_value */
static int hf_ranap_value = -1;                   /* T_value */

/*--- End of included file: packet-ranap-hf.c ---*/
#line 79 "../../asn1/ranap/packet-ranap-template.c"

/* Initialize the subtree pointers */
static int ett_ranap = -1;
static int ett_ranap_TransportLayerAddress = -1;
static int ett_ranap_TransportLayerAddress_nsap = -1;


/*--- Included file: packet-ranap-ett.c ---*/
#line 1 "../../asn1/ranap/packet-ranap-ett.c"
static gint ett_ranap_PrivateIE_ID = -1;
static gint ett_ranap_ProtocolIE_Container = -1;
static gint ett_ranap_ProtocolIE_Field = -1;
static gint ett_ranap_ProtocolIE_ContainerPair = -1;
static gint ett_ranap_ProtocolIE_FieldPair = -1;
static gint ett_ranap_ProtocolIE_ContainerList = -1;
static gint ett_ranap_ProtocolIE_ContainerPairList = -1;
static gint ett_ranap_ProtocolExtensionContainer = -1;
static gint ett_ranap_ProtocolExtensionField = -1;
static gint ett_ranap_PrivateIE_Container = -1;
static gint ett_ranap_PrivateIE_Field = -1;
static gint ett_ranap_AllocationOrRetentionPriority = -1;
static gint ett_ranap_Alt_RAB_Parameters = -1;
static gint ett_ranap_Alt_RAB_Parameter_ExtendedGuaranteedBitrateInf = -1;
static gint ett_ranap_Alt_RAB_Parameter_ExtendedGuaranteedBitrates = -1;
static gint ett_ranap_Alt_RAB_Parameter_ExtendedGuaranteedBitrateList = -1;
static gint ett_ranap_Alt_RAB_Parameter_GuaranteedBitrateInf = -1;
static gint ett_ranap_Alt_RAB_Parameter_GuaranteedBitrates = -1;
static gint ett_ranap_Alt_RAB_Parameter_GuaranteedBitrateList = -1;
static gint ett_ranap_Alt_RAB_Parameter_SupportedGuaranteedBitrateInf = -1;
static gint ett_ranap_Alt_RAB_Parameter_SupportedGuaranteedBitrates = -1;
static gint ett_ranap_Alt_RAB_Parameter_ExtendedMaxBitrateInf = -1;
static gint ett_ranap_Alt_RAB_Parameter_ExtendedMaxBitrates = -1;
static gint ett_ranap_Alt_RAB_Parameter_ExtendedMaxBitrateList = -1;
static gint ett_ranap_Alt_RAB_Parameter_MaxBitrateInf = -1;
static gint ett_ranap_Alt_RAB_Parameter_MaxBitrates = -1;
static gint ett_ranap_Alt_RAB_Parameter_MaxBitrateList = -1;
static gint ett_ranap_Alt_RAB_Parameter_SupportedMaxBitrateInf = -1;
static gint ett_ranap_Alt_RAB_Parameter_SupportedMaxBitrates = -1;
static gint ett_ranap_AreaIdentity = -1;
static gint ett_ranap_Ass_RAB_Parameters = -1;
static gint ett_ranap_Ass_RAB_Parameter_ExtendedGuaranteedBitrateList = -1;
static gint ett_ranap_Ass_RAB_Parameter_ExtendedMaxBitrateList = -1;
static gint ett_ranap_Ass_RAB_Parameter_GuaranteedBitrateList = -1;
static gint ett_ranap_Ass_RAB_Parameter_MaxBitrateList = -1;
static gint ett_ranap_AuthorisedPLMNs = -1;
static gint ett_ranap_AuthorisedPLMNs_item = -1;
static gint ett_ranap_AuthorisedSNAs = -1;
static gint ett_ranap_BroadcastAssistanceDataDecipheringKeys = -1;
static gint ett_ranap_Cause = -1;
static gint ett_ranap_CellBased = -1;
static gint ett_ranap_CellIdList = -1;
static gint ett_ranap_CellLoadInformation = -1;
static gint ett_ranap_CellLoadInformationGroup = -1;
static gint ett_ranap_CriticalityDiagnostics = -1;
static gint ett_ranap_CriticalityDiagnostics_IE_List = -1;
static gint ett_ranap_CriticalityDiagnostics_IE_List_item = -1;
static gint ett_ranap_MessageStructure = -1;
static gint ett_ranap_MessageStructure_item = -1;
static gint ett_ranap_CGI = -1;
static gint ett_ranap_CSG_Id_List = -1;
static gint ett_ranap_DeltaRAListofIdleModeUEs = -1;
static gint ett_ranap_NewRAListofIdleModeUEs = -1;
static gint ett_ranap_RAListwithNoIdleModeUEsAnyMore = -1;
static gint ett_ranap_ENB_ID = -1;
static gint ett_ranap_EncryptionInformation = -1;
static gint ett_ranap_EquipmentsToBeTraced = -1;
static gint ett_ranap_Event1F_Parameters = -1;
static gint ett_ranap_Event1I_Parameters = -1;
static gint ett_ranap_GANSS_PositioningDataSet = -1;
static gint ett_ranap_GeographicalArea = -1;
static gint ett_ranap_GeographicalCoordinates = -1;
static gint ett_ranap_GA_AltitudeAndDirection = -1;
static gint ett_ranap_GA_EllipsoidArc = -1;
static gint ett_ranap_GA_Point = -1;
static gint ett_ranap_GA_PointWithAltitude = -1;
static gint ett_ranap_GA_PointWithAltitudeAndUncertaintyEllipsoid = -1;
static gint ett_ranap_GA_PointWithUnCertainty = -1;
static gint ett_ranap_GA_PointWithUnCertaintyEllipse = -1;
static gint ett_ranap_GA_Polygon = -1;
static gint ett_ranap_GA_Polygon_item = -1;
static gint ett_ranap_GA_UncertaintyEllipse = -1;
static gint ett_ranap_GERAN_Cell_ID = -1;
static gint ett_ranap_GlobalCN_ID = -1;
static gint ett_ranap_GlobalRNC_ID = -1;
static gint ett_ranap_IMEIGroup = -1;
static gint ett_ranap_IMEIList = -1;
static gint ett_ranap_IMEISVGroup = -1;
static gint ett_ranap_IMEISVList = -1;
static gint ett_ranap_ImmediateMDT = -1;
static gint ett_ranap_InformationRequested = -1;
static gint ett_ranap_InformationRequestType = -1;
static gint ett_ranap_InformationTransferType = -1;
static gint ett_ranap_IntegrityProtectionInformation = -1;
static gint ett_ranap_InterSystemInformationTransferType = -1;
static gint ett_ranap_InterSystemInformation_TransparentContainer = -1;
static gint ett_ranap_IuTransportAssociation = -1;
static gint ett_ranap_LA_LIST = -1;
static gint ett_ranap_LA_LIST_item = -1;
static gint ett_ranap_LAI = -1;
static gint ett_ranap_LastKnownServiceArea = -1;
static gint ett_ranap_ListOF_SNAs = -1;
static gint ett_ranap_ListOfInterfacesToTrace = -1;
static gint ett_ranap_InterfacesToTraceItem = -1;
static gint ett_ranap_LocationRelatedDataRequestType = -1;
static gint ett_ranap_LocationReportingTransferInformation = -1;
static gint ett_ranap_M1Report = -1;
static gint ett_ranap_M2Report = -1;
static gint ett_ranap_MBMSIPMulticastAddressandAPNRequest = -1;
static gint ett_ranap_MDTAreaScope = -1;
static gint ett_ranap_MDT_Configuration = -1;
static gint ett_ranap_MDTMode = -1;
static gint ett_ranap_MDT_Report_Parameters = -1;
static gint ett_ranap_Offload_RAB_Parameters = -1;
static gint ett_ranap_PagingAreaID = -1;
static gint ett_ranap_PDP_TypeInformation = -1;
static gint ett_ranap_PDP_TypeInformation_extension = -1;
static gint ett_ranap_PeriodicLocationInfo = -1;
static gint ett_ranap_PermanentNAS_UE_ID = -1;
static gint ett_ranap_PermittedEncryptionAlgorithms = -1;
static gint ett_ranap_PermittedIntegrityProtectionAlgorithms = -1;
static gint ett_ranap_LABased = -1;
static gint ett_ranap_LAI_List = -1;
static gint ett_ranap_LoggedMDT = -1;
static gint ett_ranap_PLMNAreaBased = -1;
static gint ett_ranap_PLMNs_in_shared_network = -1;
static gint ett_ranap_PLMNs_in_shared_network_item = -1;
static gint ett_ranap_PositioningDataSet = -1;
static gint ett_ranap_PositionData = -1;
static gint ett_ranap_ProvidedData = -1;
static gint ett_ranap_RABased = -1;
static gint ett_ranap_RAC_List = -1;
static gint ett_ranap_RABDataVolumeReport = -1;
static gint ett_ranap_RABDataVolumeReport_item = -1;
static gint ett_ranap_RAB_Parameter_ExtendedGuaranteedBitrateList = -1;
static gint ett_ranap_RAB_Parameter_ExtendedMaxBitrateList = -1;
static gint ett_ranap_RAB_Parameter_GuaranteedBitrateList = -1;
static gint ett_ranap_RAB_Parameter_MaxBitrateList = -1;
static gint ett_ranap_RAB_Parameters = -1;
static gint ett_ranap_RABParametersList = -1;
static gint ett_ranap_RABParametersList_item = -1;
static gint ett_ranap_RAB_TrCH_Mapping = -1;
static gint ett_ranap_RAB_TrCH_MappingItem = -1;
static gint ett_ranap_RAI = -1;
static gint ett_ranap_RAListofIdleModeUEs = -1;
static gint ett_ranap_NotEmptyRAListofIdleModeUEs = -1;
static gint ett_ranap_RAofIdleModeUEs = -1;
static gint ett_ranap_LAListofIdleModeUEs = -1;
static gint ett_ranap_RequestedMBMSIPMulticastAddressandAPNRequest = -1;
static gint ett_ranap_MBMSIPMulticastAddressandAPNlist = -1;
static gint ett_ranap_RequestedMulticastServiceList = -1;
static gint ett_ranap_Requested_RAB_Parameter_Values = -1;
static gint ett_ranap_Requested_RAB_Parameter_ExtendedMaxBitrateList = -1;
static gint ett_ranap_Requested_RAB_Parameter_ExtendedGuaranteedBitrateList = -1;
static gint ett_ranap_Requested_RAB_Parameter_MaxBitrateList = -1;
static gint ett_ranap_Requested_RAB_Parameter_GuaranteedBitrateList = -1;
static gint ett_ranap_RequestType = -1;
static gint ett_ranap_ResidualBitErrorRatio = -1;
static gint ett_ranap_RIM_Transfer = -1;
static gint ett_ranap_RIMRoutingAddress = -1;
static gint ett_ranap_RNCTraceInformation = -1;
static gint ett_ranap_RNSAPRelocationParameters = -1;
static gint ett_ranap_SAI = -1;
static gint ett_ranap_Shared_Network_Information = -1;
static gint ett_ranap_SDU_ErrorRatio = -1;
static gint ett_ranap_SDU_FormatInformationParameters = -1;
static gint ett_ranap_SDU_FormatInformationParameters_item = -1;
static gint ett_ranap_SDU_Parameters = -1;
static gint ett_ranap_SDU_Parameters_item = -1;
static gint ett_ranap_SNA_Access_Information = -1;
static gint ett_ranap_SourceCellID = -1;
static gint ett_ranap_SourceID = -1;
static gint ett_ranap_SourceRNC_ID = -1;
static gint ett_ranap_SourceRNC_ToTargetRNC_TransparentContainer = -1;
static gint ett_ranap_IRAT_Measurement_Configuration = -1;
static gint ett_ranap_IRATmeasurementParameters = -1;
static gint ett_ranap_EUTRANFrequencies = -1;
static gint ett_ranap_EUTRANFrequencies_item = -1;
static gint ett_ranap_SupportedRAB_ParameterBitrateList = -1;
static gint ett_ranap_SourceUTRANCellID = -1;
static gint ett_ranap_SRB_TrCH_Mapping = -1;
static gint ett_ranap_SRB_TrCH_MappingItem = -1;
static gint ett_ranap_SRVCC_Information = -1;
static gint ett_ranap_TAI = -1;
static gint ett_ranap_TargetID = -1;
static gint ett_ranap_TargetENB_ID = -1;
static gint ett_ranap_TargetRNC_ID = -1;
static gint ett_ranap_TargetRNC_ToSourceRNC_TransparentContainer = -1;
static gint ett_ranap_TemporaryUE_ID = -1;
static gint ett_ranap_TMGI = -1;
static gint ett_ranap_TraceInformation = -1;
static gint ett_ranap_TracePropagationParameters = -1;
static gint ett_ranap_TraceRecordingSessionInformation = -1;
static gint ett_ranap_TrCH_ID = -1;
static gint ett_ranap_TrCH_ID_List = -1;
static gint ett_ranap_UE_AggregateMaximumBitRate = -1;
static gint ett_ranap_UE_ID = -1;
static gint ett_ranap_UESBI_Iu = -1;
static gint ett_ranap_UPInformation = -1;
static gint ett_ranap_VelocityEstimate = -1;
static gint ett_ranap_HorizontalVelocity = -1;
static gint ett_ranap_HorizontalWithVerticalVelocity = -1;
static gint ett_ranap_HorizontalVelocityWithUncertainty = -1;
static gint ett_ranap_HorizontalWithVerticalVelocityAndUncertainty = -1;
static gint ett_ranap_HorizontalSpeedAndBearing = -1;
static gint ett_ranap_VerticalVelocity = -1;
static gint ett_ranap_Iu_ReleaseCommand = -1;
static gint ett_ranap_Iu_ReleaseComplete = -1;
static gint ett_ranap_RAB_DataVolumeReportItem = -1;
static gint ett_ranap_RAB_ReleasedItem_IuRelComp = -1;
static gint ett_ranap_RelocationRequired = -1;
static gint ett_ranap_RelocationCommand = -1;
static gint ett_ranap_RAB_RelocationReleaseItem = -1;
static gint ett_ranap_RAB_DataForwardingItem = -1;
static gint ett_ranap_RelocationPreparationFailure = -1;
static gint ett_ranap_RelocationRequest = -1;
static gint ett_ranap_RAB_SetupItem_RelocReq = -1;
static gint ett_ranap_UserPlaneInformation = -1;
static gint ett_ranap_CNMBMSLinkingInformation = -1;
static gint ett_ranap_JoinedMBMSBearerService_IEs = -1;
static gint ett_ranap_JoinedMBMSBearerService_IEs_item = -1;
static gint ett_ranap_RelocationRequestAcknowledge = -1;
static gint ett_ranap_RAB_SetupItem_RelocReqAck = -1;
static gint ett_ranap_RAB_FailedItem = -1;
static gint ett_ranap_RelocationFailure = -1;
static gint ett_ranap_RelocationCancel = -1;
static gint ett_ranap_RelocationCancelAcknowledge = -1;
static gint ett_ranap_SRNS_ContextRequest = -1;
static gint ett_ranap_RAB_DataForwardingItem_SRNS_CtxReq = -1;
static gint ett_ranap_SRNS_ContextResponse = -1;
static gint ett_ranap_RAB_ContextItem = -1;
static gint ett_ranap_RABs_ContextFailedtoTransferItem = -1;
static gint ett_ranap_SecurityModeCommand = -1;
static gint ett_ranap_SecurityModeComplete = -1;
static gint ett_ranap_SecurityModeReject = -1;
static gint ett_ranap_DataVolumeReportRequest = -1;
static gint ett_ranap_RAB_DataVolumeReportRequestItem = -1;
static gint ett_ranap_DataVolumeReport = -1;
static gint ett_ranap_RABs_failed_to_reportItem = -1;
static gint ett_ranap_Reset = -1;
static gint ett_ranap_ResetAcknowledge = -1;
static gint ett_ranap_ResetResource = -1;
static gint ett_ranap_ResetResourceItem = -1;
static gint ett_ranap_ResetResourceAcknowledge = -1;
static gint ett_ranap_ResetResourceAckItem = -1;
static gint ett_ranap_RAB_ReleaseRequest = -1;
static gint ett_ranap_RAB_ReleaseItem = -1;
static gint ett_ranap_Iu_ReleaseRequest = -1;
static gint ett_ranap_RelocationDetect = -1;
static gint ett_ranap_RelocationComplete = -1;
static gint ett_ranap_EnhancedRelocationCompleteRequest = -1;
static gint ett_ranap_RAB_SetupItem_EnhancedRelocCompleteReq = -1;
static gint ett_ranap_EnhancedRelocationCompleteResponse = -1;
static gint ett_ranap_RAB_SetupItem_EnhancedRelocCompleteRes = -1;
static gint ett_ranap_RAB_ToBeReleasedItem_EnhancedRelocCompleteRes = -1;
static gint ett_ranap_EnhancedRelocationCompleteFailure = -1;
static gint ett_ranap_EnhancedRelocationCompleteConfirm = -1;
static gint ett_ranap_Paging = -1;
static gint ett_ranap_CommonID = -1;
static gint ett_ranap_CN_InvokeTrace = -1;
static gint ett_ranap_CN_DeactivateTrace = -1;
static gint ett_ranap_LocationReportingControl = -1;
static gint ett_ranap_LocationReport = -1;
static gint ett_ranap_InitialUE_Message = -1;
static gint ett_ranap_DirectTransfer = -1;
static gint ett_ranap_Overload = -1;
static gint ett_ranap_ErrorIndication = -1;
static gint ett_ranap_SRNS_DataForwardCommand = -1;
static gint ett_ranap_ForwardSRNS_Context = -1;
static gint ett_ranap_RAB_AssignmentRequest = -1;
static gint ett_ranap_RAB_SetupOrModifyItemFirst = -1;
static gint ett_ranap_TransportLayerInformation = -1;
static gint ett_ranap_RAB_SetupOrModifyItemSecond = -1;
static gint ett_ranap_RAB_AssignmentResponse = -1;
static gint ett_ranap_RAB_SetupOrModifiedItem = -1;
static gint ett_ranap_RAB_ReleasedItem = -1;
static gint ett_ranap_DataVolumeList = -1;
static gint ett_ranap_DataVolumeList_item = -1;
static gint ett_ranap_RAB_QueuedItem = -1;
static gint ett_ranap_GERAN_Iumode_RAB_Failed_RABAssgntResponse_Item = -1;
static gint ett_ranap_PrivateMessage = -1;
static gint ett_ranap_RANAP_RelocationInformation = -1;
static gint ett_ranap_DirectTransferInformationItem_RANAP_RelocInf = -1;
static gint ett_ranap_RAB_ContextItem_RANAP_RelocInf = -1;
static gint ett_ranap_RANAP_EnhancedRelocationInformationRequest = -1;
static gint ett_ranap_RAB_SetupItem_EnhRelocInfoReq = -1;
static gint ett_ranap_TNLInformationEnhRelInfoReq = -1;
static gint ett_ranap_RANAP_EnhancedRelocationInformationResponse = -1;
static gint ett_ranap_RAB_SetupItem_EnhRelocInfoRes = -1;
static gint ett_ranap_RAB_FailedItem_EnhRelocInfoRes = -1;
static gint ett_ranap_TNLInformationEnhRelInfoRes = -1;
static gint ett_ranap_RAB_ModifyRequest = -1;
static gint ett_ranap_RAB_ModifyItem = -1;
static gint ett_ranap_LocationRelatedDataRequest = -1;
static gint ett_ranap_LocationRelatedDataResponse = -1;
static gint ett_ranap_LocationRelatedDataFailure = -1;
static gint ett_ranap_InformationTransferIndication = -1;
static gint ett_ranap_InformationTransferConfirmation = -1;
static gint ett_ranap_InformationTransferFailure = -1;
static gint ett_ranap_UESpecificInformationIndication = -1;
static gint ett_ranap_DirectInformationTransfer = -1;
static gint ett_ranap_UplinkInformationExchangeRequest = -1;
static gint ett_ranap_UplinkInformationExchangeResponse = -1;
static gint ett_ranap_UplinkInformationExchangeFailure = -1;
static gint ett_ranap_MBMSSessionStart = -1;
static gint ett_ranap_MBMSSynchronisationInformation = -1;
static gint ett_ranap_MBMSSessionStartResponse = -1;
static gint ett_ranap_MBMSSessionStartFailure = -1;
static gint ett_ranap_MBMSSessionUpdate = -1;
static gint ett_ranap_MBMSSessionUpdateResponse = -1;
static gint ett_ranap_MBMSSessionUpdateFailure = -1;
static gint ett_ranap_MBMSSessionStop = -1;
static gint ett_ranap_MBMSSessionStopResponse = -1;
static gint ett_ranap_MBMSUELinkingRequest = -1;
static gint ett_ranap_LeftMBMSBearerService_IEs = -1;
static gint ett_ranap_LeftMBMSBearerService_IEs_item = -1;
static gint ett_ranap_MBMSUELinkingResponse = -1;
static gint ett_ranap_UnsuccessfulLinking_IEs = -1;
static gint ett_ranap_UnsuccessfulLinking_IEs_item = -1;
static gint ett_ranap_MBMSRegistrationRequest = -1;
static gint ett_ranap_MBMSRegistrationResponse = -1;
static gint ett_ranap_MBMSRegistrationFailure = -1;
static gint ett_ranap_MBMSCNDe_RegistrationRequest = -1;
static gint ett_ranap_MBMSCNDe_RegistrationResponse = -1;
static gint ett_ranap_MBMSRABEstablishmentIndication = -1;
static gint ett_ranap_MBMSRABReleaseRequest = -1;
static gint ett_ranap_MBMSRABRelease = -1;
static gint ett_ranap_MBMSRABReleaseFailure = -1;
static gint ett_ranap_SRVCC_CSKeysRequest = -1;
static gint ett_ranap_SRVCC_CSKeysResponse = -1;
static gint ett_ranap_RANAP_PDU = -1;
static gint ett_ranap_InitiatingMessage = -1;
static gint ett_ranap_SuccessfulOutcome = -1;
static gint ett_ranap_UnsuccessfulOutcome = -1;
static gint ett_ranap_Outcome = -1;

/*--- End of included file: packet-ranap-ett.c ---*/
#line 86 "../../asn1/ranap/packet-ranap-template.c"

/* Global variables */
static guint32 ProcedureCode;
static guint32 ProtocolIE_ID;
static guint32 ProtocolExtensionID;

/* Some IE:s identities uses the same value for different IE:s
 * depending on PDU type:
 * InitiatingMessage
 * SuccessfulOutcome
 * UnsuccessfulOutcome
 * Outcome
 * As a workarond a value is added to the IE:id in the .cnf file.
 * Example:
 * ResetResourceList                N rnsap.ies IMSG||id-IuSigConIdList  # no spaces are allowed in value as a space is delimiter
 * PDU type is stored in a global variable and can is used in the IE decoding section.
 */
/*
 * 	&InitiatingMessage				,
 *	&SuccessfulOutcome				OPTIONAL,
 *	&UnsuccessfulOutcome				OPTIONAL,
 *	&Outcome					OPTIONAL,
 *
 * Only these two needed currently
 */
#define IMSG (1<<16)
#define SOUT (2<<16)
#define SPECIAL (4<<16)

int pdu_type = 0; /* 0 means wildcard */

/* Initialise the Preferences */
static gint global_ranap_sccp_ssn = SCCP_SSN_RANAP;

/* Dissector tables */
static dissector_table_t ranap_ies_dissector_table;
static dissector_table_t ranap_ies_p1_dissector_table;
static dissector_table_t ranap_ies_p2_dissector_table;
static dissector_table_t ranap_extension_dissector_table;
static dissector_table_t ranap_proc_imsg_dissector_table;
static dissector_table_t ranap_proc_sout_dissector_table;
static dissector_table_t ranap_proc_uout_dissector_table;
static dissector_table_t ranap_proc_out_dissector_table;
static dissector_table_t nas_pdu_dissector_table;

static int dissect_ProtocolIEFieldValue(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);
static int dissect_ProtocolIEFieldPairFirstValue(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);
static int dissect_ProtocolIEFieldPairSecondValue(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);
static int dissect_ProtocolExtensionFieldExtensionValue(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);
static int dissect_InitiatingMessageValue(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);
static int dissect_SuccessfulOutcomeValue(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);
static int dissect_UnsuccessfulOutcomeValue(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);
static int dissect_OutcomeValue(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);

static int dissect_ranap_SourceRNC_ToTargetRNC_TransparentContainer(tvbuff_t *tvb, int offset, asn1_ctx_t *actx, proto_tree *tree, int hf_index);
static int dissect_ranap_TargetRNC_ToSourceRNC_TransparentContainer(tvbuff_t *tvb, int offset, asn1_ctx_t *actx, proto_tree *tree, int hf_index);

void proto_reg_handoff_ranap(void);


/*--- Included file: packet-ranap-fn.c ---*/
#line 1 "../../asn1/ranap/packet-ranap-fn.c"

static const value_string ranap_Criticality_vals[] = {
  {   0, "reject" },
  {   1, "ignore" },
  {   2, "notify" },
  { 0, NULL }
};


static int
dissect_ranap_Criticality(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     3, NULL, FALSE, 0, NULL);

  return offset;
}



static int
dissect_ranap_INTEGER_0_65535(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 65535U, NULL, FALSE);

  return offset;
}



static int
dissect_ranap_OBJECT_IDENTIFIER(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_object_identifier(tvb, offset, actx, tree, hf_index, NULL);

  return offset;
}


static const value_string ranap_PrivateIE_ID_vals[] = {
  {   0, "local" },
  {   1, "global" },
  { 0, NULL }
};

static const per_choice_t PrivateIE_ID_choice[] = {
  {   0, &hf_ranap_local         , ASN1_NO_EXTENSIONS     , dissect_ranap_INTEGER_0_65535 },
  {   1, &hf_ranap_global        , ASN1_NO_EXTENSIONS     , dissect_ranap_OBJECT_IDENTIFIER },
  { 0, NULL, 0, NULL }
};

static int
dissect_ranap_PrivateIE_ID(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_ranap_PrivateIE_ID, PrivateIE_ID_choice,
                                 NULL);

  return offset;
}


static const value_string ranap_ProcedureCode_vals[] = {
  { id_RAB_Assignment, "id-RAB-Assignment" },
  { id_Iu_Release, "id-Iu-Release" },
  { id_RelocationPreparation, "id-RelocationPreparation" },
  { id_RelocationResourceAllocation, "id-RelocationResourceAllocation" },
  { id_RelocationCancel, "id-RelocationCancel" },
  { id_SRNS_ContextTransfer, "id-SRNS-ContextTransfer" },
  { id_SecurityModeControl, "id-SecurityModeControl" },
  { id_DataVolumeReport, "id-DataVolumeReport" },
  { id_Not_Used_8, "id-Not-Used-8" },
  { id_Reset, "id-Reset" },
  { id_RAB_ReleaseRequest, "id-RAB-ReleaseRequest" },
  { id_Iu_ReleaseRequest, "id-Iu-ReleaseRequest" },
  { id_RelocationDetect, "id-RelocationDetect" },
  { id_RelocationComplete, "id-RelocationComplete" },
  { id_Paging, "id-Paging" },
  { id_CommonID, "id-CommonID" },
  { id_CN_InvokeTrace, "id-CN-InvokeTrace" },
  { id_LocationReportingControl, "id-LocationReportingControl" },
  { id_LocationReport, "id-LocationReport" },
  { id_InitialUE_Message, "id-InitialUE-Message" },
  { id_DirectTransfer, "id-DirectTransfer" },
  { id_OverloadControl, "id-OverloadControl" },
  { id_ErrorIndication, "id-ErrorIndication" },
  { id_SRNS_DataForward, "id-SRNS-DataForward" },
  { id_ForwardSRNS_Context, "id-ForwardSRNS-Context" },
  { id_privateMessage, "id-privateMessage" },
  { id_CN_DeactivateTrace, "id-CN-DeactivateTrace" },
  { id_ResetResource, "id-ResetResource" },
  { id_RANAP_Relocation, "id-RANAP-Relocation" },
  { id_RAB_ModifyRequest, "id-RAB-ModifyRequest" },
  { id_LocationRelatedData, "id-LocationRelatedData" },
  { id_InformationTransfer, "id-InformationTransfer" },
  { id_UESpecificInformation, "id-UESpecificInformation" },
  { id_UplinkInformationExchange, "id-UplinkInformationExchange" },
  { id_DirectInformationTransfer, "id-DirectInformationTransfer" },
  { id_MBMSSessionStart, "id-MBMSSessionStart" },
  { id_MBMSSessionUpdate, "id-MBMSSessionUpdate" },
  { id_MBMSSessionStop, "id-MBMSSessionStop" },
  { id_MBMSUELinking, "id-MBMSUELinking" },
  { id_MBMSRegistration, "id-MBMSRegistration" },
  { id_MBMSCNDe_Registration_Procedure, "id-MBMSCNDe-Registration-Procedure" },
  { id_MBMSRABEstablishmentIndication, "id-MBMSRABEstablishmentIndication" },
  { id_MBMSRABRelease, "id-MBMSRABRelease" },
  { id_enhancedRelocationComplete, "id-enhancedRelocationComplete" },
  { id_enhancedRelocationCompleteConfirm, "id-enhancedRelocationCompleteConfirm" },
  { id_RANAPenhancedRelocation, "id-RANAPenhancedRelocation" },
  { id_SRVCCPreparation, "id-SRVCCPreparation" },
  { 0, NULL }
};

static value_string_ext ranap_ProcedureCode_vals_ext = VALUE_STRING_EXT_INIT(ranap_ProcedureCode_vals);


static int
dissect_ranap_ProcedureCode(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 255U, &ProcedureCode, FALSE);

#line 91 "../../asn1/ranap/ranap.cnf"
     col_add_fstr(actx->pinfo->cinfo, COL_INFO, "%s ",
                 val_to_str_ext_const(ProcedureCode, &ranap_ProcedureCode_vals_ext,
                            "unknown message"));

  return offset;
}



static int
dissect_ranap_ProtocolExtensionID(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 65535U, &ProtocolExtensionID, FALSE);

  return offset;
}


static const value_string ranap_ProtocolIE_ID_vals[] = {
  { id_AreaIdentity, "id-AreaIdentity" },
  { id_Not_Used_1, "id-Not-Used-1" },
  { id_Not_Used_2, "id-Not-Used-2" },
  { id_CN_DomainIndicator, "id-CN-DomainIndicator" },
  { id_Cause, "id-Cause" },
  { id_ChosenEncryptionAlgorithm, "id-ChosenEncryptionAlgorithm" },
  { id_ChosenIntegrityProtectionAlgorithm, "id-ChosenIntegrityProtectionAlgorithm" },
  { id_ClassmarkInformation2, "id-ClassmarkInformation2" },
  { id_ClassmarkInformation3, "id-ClassmarkInformation3" },
  { id_CriticalityDiagnostics, "id-CriticalityDiagnostics" },
  { id_DL_GTP_PDU_SequenceNumber, "id-DL-GTP-PDU-SequenceNumber" },
  { id_EncryptionInformation, "id-EncryptionInformation" },
  { id_IntegrityProtectionInformation, "id-IntegrityProtectionInformation" },
  { id_IuTransportAssociation, "id-IuTransportAssociation" },
  { id_L3_Information, "id-L3-Information" },
  { id_LAI, "id-LAI" },
  { id_NAS_PDU, "id-NAS-PDU" },
  { id_NonSearchingIndication, "id-NonSearchingIndication" },
  { id_NumberOfSteps, "id-NumberOfSteps" },
  { id_OMC_ID, "id-OMC-ID" },
  { id_OldBSS_ToNewBSS_Information, "id-OldBSS-ToNewBSS-Information" },
  { id_PagingAreaID, "id-PagingAreaID" },
  { id_PagingCause, "id-PagingCause" },
  { id_PermanentNAS_UE_ID, "id-PermanentNAS-UE-ID" },
  { id_RAB_ContextItem, "id-RAB-ContextItem" },
  { id_RAB_ContextList, "id-RAB-ContextList" },
  { id_RAB_DataForwardingItem, "id-RAB-DataForwardingItem" },
  { id_RAB_DataForwardingItem_SRNS_CtxReq, "id-RAB-DataForwardingItem-SRNS-CtxReq" },
  { id_RAB_DataForwardingList, "id-RAB-DataForwardingList" },
  { id_RAB_DataForwardingList_SRNS_CtxReq, "id-RAB-DataForwardingList-SRNS-CtxReq" },
  { id_RAB_DataVolumeReportItem, "id-RAB-DataVolumeReportItem" },
  { id_RAB_DataVolumeReportList, "id-RAB-DataVolumeReportList" },
  { id_RAB_DataVolumeReportRequestItem, "id-RAB-DataVolumeReportRequestItem" },
  { id_RAB_DataVolumeReportRequestList, "id-RAB-DataVolumeReportRequestList" },
  { id_RAB_FailedItem, "id-RAB-FailedItem" },
  { id_RAB_FailedList, "id-RAB-FailedList" },
  { id_RAB_ID, "id-RAB-ID" },
  { id_RAB_QueuedItem, "id-RAB-QueuedItem" },
  { id_RAB_QueuedList, "id-RAB-QueuedList" },
  { id_RAB_ReleaseFailedList, "id-RAB-ReleaseFailedList" },
  { id_RAB_ReleaseItem, "id-RAB-ReleaseItem" },
  { id_RAB_ReleaseList, "id-RAB-ReleaseList" },
  { id_RAB_ReleasedItem, "id-RAB-ReleasedItem" },
  { id_RAB_ReleasedList, "id-RAB-ReleasedList" },
  { id_RAB_ReleasedList_IuRelComp, "id-RAB-ReleasedList-IuRelComp" },
  { id_RAB_RelocationReleaseItem, "id-RAB-RelocationReleaseItem" },
  { id_RAB_RelocationReleaseList, "id-RAB-RelocationReleaseList" },
  { id_RAB_SetupItem_RelocReq, "id-RAB-SetupItem-RelocReq" },
  { id_RAB_SetupItem_RelocReqAck, "id-RAB-SetupItem-RelocReqAck" },
  { id_RAB_SetupList_RelocReq, "id-RAB-SetupList-RelocReq" },
  { id_RAB_SetupList_RelocReqAck, "id-RAB-SetupList-RelocReqAck" },
  { id_RAB_SetupOrModifiedItem, "id-RAB-SetupOrModifiedItem" },
  { id_RAB_SetupOrModifiedList, "id-RAB-SetupOrModifiedList" },
  { id_RAB_SetupOrModifyItem, "id-RAB-SetupOrModifyItem" },
  { id_RAB_SetupOrModifyList, "id-RAB-SetupOrModifyList" },
  { id_RAC, "id-RAC" },
  { id_RelocationType, "id-RelocationType" },
  { id_RequestType, "id-RequestType" },
  { id_SAI, "id-SAI" },
  { id_SAPI, "id-SAPI" },
  { id_SourceID, "id-SourceID" },
  { id_Source_ToTarget_TransparentContainer, "id-Source-ToTarget-TransparentContainer" },
  { id_TargetID, "id-TargetID" },
  { id_Target_ToSource_TransparentContainer, "id-Target-ToSource-TransparentContainer" },
  { id_TemporaryUE_ID, "id-TemporaryUE-ID" },
  { id_TraceReference, "id-TraceReference" },
  { id_TraceType, "id-TraceType" },
  { id_TransportLayerAddress, "id-TransportLayerAddress" },
  { id_TriggerID, "id-TriggerID" },
  { id_UE_ID, "id-UE-ID" },
  { id_UL_GTP_PDU_SequenceNumber, "id-UL-GTP-PDU-SequenceNumber" },
  { id_RAB_FailedtoReportItem, "id-RAB-FailedtoReportItem" },
  { id_RAB_FailedtoReportList, "id-RAB-FailedtoReportList" },
  { id_Not_Used_73, "id-Not-Used-73" },
  { id_Not_Used_74, "id-Not-Used-74" },
  { id_KeyStatus, "id-KeyStatus" },
  { id_DRX_CycleLengthCoefficient, "id-DRX-CycleLengthCoefficient" },
  { id_IuSigConIdList, "id-IuSigConIdList" },
  { id_IuSigConIdItem, "id-IuSigConIdItem" },
  { id_IuSigConId, "id-IuSigConId" },
  { id_DirectTransferInformationItem_RANAP_RelocInf, "id-DirectTransferInformationItem-RANAP-RelocInf" },
  { id_DirectTransferInformationList_RANAP_RelocInf, "id-DirectTransferInformationList-RANAP-RelocInf" },
  { id_RAB_ContextItem_RANAP_RelocInf, "id-RAB-ContextItem-RANAP-RelocInf" },
  { id_RAB_ContextList_RANAP_RelocInf, "id-RAB-ContextList-RANAP-RelocInf" },
  { id_RAB_ContextFailedtoTransferItem, "id-RAB-ContextFailedtoTransferItem" },
  { id_RAB_ContextFailedtoTransferList, "id-RAB-ContextFailedtoTransferList" },
  { id_GlobalRNC_ID, "id-GlobalRNC-ID" },
  { id_RAB_ReleasedItem_IuRelComp, "id-RAB-ReleasedItem-IuRelComp" },
  { id_MessageStructure, "id-MessageStructure" },
  { id_Alt_RAB_Parameters, "id-Alt-RAB-Parameters" },
  { id_Ass_RAB_Parameters, "id-Ass-RAB-Parameters" },
  { id_RAB_ModifyList, "id-RAB-ModifyList" },
  { id_RAB_ModifyItem, "id-RAB-ModifyItem" },
  { id_TypeOfError, "id-TypeOfError" },
  { id_BroadcastAssistanceDataDecipheringKeys, "id-BroadcastAssistanceDataDecipheringKeys" },
  { id_LocationRelatedDataRequestType, "id-LocationRelatedDataRequestType" },
  { id_GlobalCN_ID, "id-GlobalCN-ID" },
  { id_LastKnownServiceArea, "id-LastKnownServiceArea" },
  { id_SRB_TrCH_Mapping, "id-SRB-TrCH-Mapping" },
  { id_InterSystemInformation_TransparentContainer, "id-InterSystemInformation-TransparentContainer" },
  { id_NewBSS_To_OldBSS_Information, "id-NewBSS-To-OldBSS-Information" },
  { id_Not_Used_101, "id-Not-Used-101" },
  { id_Not_Used_102, "id-Not-Used-102" },
  { id_SourceRNC_PDCP_context_info, "id-SourceRNC-PDCP-context-info" },
  { id_InformationTransferID, "id-InformationTransferID" },
  { id_SNA_Access_Information, "id-SNA-Access-Information" },
  { id_ProvidedData, "id-ProvidedData" },
  { id_GERAN_BSC_Container, "id-GERAN-BSC-Container" },
  { id_GERAN_Classmark, "id-GERAN-Classmark" },
  { id_GERAN_Iumode_RAB_Failed_RABAssgntResponse_Item, "id-GERAN-Iumode-RAB-Failed-RABAssgntResponse-Item" },
  { id_GERAN_Iumode_RAB_FailedList_RABAssgntResponse, "id-GERAN-Iumode-RAB-FailedList-RABAssgntResponse" },
  { id_VerticalAccuracyCode, "id-VerticalAccuracyCode" },
  { id_ResponseTime, "id-ResponseTime" },
  { id_PositioningPriority, "id-PositioningPriority" },
  { id_ClientType, "id-ClientType" },
  { id_LocationRelatedDataRequestTypeSpecificToGERANIuMode, "id-LocationRelatedDataRequestTypeSpecificToGERANIuMode" },
  { id_SignallingIndication, "id-SignallingIndication" },
  { id_hS_DSCH_MAC_d_Flow_ID, "id-hS-DSCH-MAC-d-Flow-ID" },
  { id_UESBI_Iu, "id-UESBI-Iu" },
  { id_PositionData, "id-PositionData" },
  { id_PositionDataSpecificToGERANIuMode, "id-PositionDataSpecificToGERANIuMode" },
  { id_CellLoadInformationGroup, "id-CellLoadInformationGroup" },
  { id_AccuracyFulfilmentIndicator, "id-AccuracyFulfilmentIndicator" },
  { id_InformationTransferType, "id-InformationTransferType" },
  { id_TraceRecordingSessionInformation, "id-TraceRecordingSessionInformation" },
  { id_TracePropagationParameters, "id-TracePropagationParameters" },
  { id_InterSystemInformationTransferType, "id-InterSystemInformationTransferType" },
  { id_SelectedPLMN_ID, "id-SelectedPLMN-ID" },
  { id_RedirectionCompleted, "id-RedirectionCompleted" },
  { id_RedirectionIndication, "id-RedirectionIndication" },
  { id_NAS_SequenceNumber, "id-NAS-SequenceNumber" },
  { id_RejectCauseValue, "id-RejectCauseValue" },
  { id_APN, "id-APN" },
  { id_CNMBMSLinkingInformation, "id-CNMBMSLinkingInformation" },
  { id_DeltaRAListofIdleModeUEs, "id-DeltaRAListofIdleModeUEs" },
  { id_FrequenceLayerConvergenceFlag, "id-FrequenceLayerConvergenceFlag" },
  { id_InformationExchangeID, "id-InformationExchangeID" },
  { id_InformationExchangeType, "id-InformationExchangeType" },
  { id_InformationRequested, "id-InformationRequested" },
  { id_InformationRequestType, "id-InformationRequestType" },
  { id_IPMulticastAddress, "id-IPMulticastAddress" },
  { id_JoinedMBMSBearerServicesList, "id-JoinedMBMSBearerServicesList" },
  { id_LeftMBMSBearerServicesList, "id-LeftMBMSBearerServicesList" },
  { id_MBMSBearerServiceType, "id-MBMSBearerServiceType" },
  { id_MBMSCNDe_Registration, "id-MBMSCNDe-Registration" },
  { id_MBMSServiceArea, "id-MBMSServiceArea" },
  { id_MBMSSessionDuration, "id-MBMSSessionDuration" },
  { id_MBMSSessionIdentity, "id-MBMSSessionIdentity" },
  { id_PDP_TypeInformation, "id-PDP-TypeInformation" },
  { id_RAB_Parameters, "id-RAB-Parameters" },
  { id_RAListofIdleModeUEs, "id-RAListofIdleModeUEs" },
  { id_MBMSRegistrationRequestType, "id-MBMSRegistrationRequestType" },
  { id_SessionUpdateID, "id-SessionUpdateID" },
  { id_TMGI, "id-TMGI" },
  { id_TransportLayerInformation, "id-TransportLayerInformation" },
  { id_UnsuccessfulLinkingList, "id-UnsuccessfulLinkingList" },
  { id_MBMSLinkingInformation, "id-MBMSLinkingInformation" },
  { id_MBMSSessionRepetitionNumber, "id-MBMSSessionRepetitionNumber" },
  { id_AlternativeRABConfiguration, "id-AlternativeRABConfiguration" },
  { id_AlternativeRABConfigurationRequest, "id-AlternativeRABConfigurationRequest" },
  { id_E_DCH_MAC_d_Flow_ID, "id-E-DCH-MAC-d-Flow-ID" },
  { id_SourceBSS_ToTargetBSS_TransparentContainer, "id-SourceBSS-ToTargetBSS-TransparentContainer" },
  { id_TargetBSS_ToSourceBSS_TransparentContainer, "id-TargetBSS-ToSourceBSS-TransparentContainer" },
  { id_TimeToMBMSDataTransfer, "id-TimeToMBMSDataTransfer" },
  { id_IncludeVelocity, "id-IncludeVelocity" },
  { id_VelocityEstimate, "id-VelocityEstimate" },
  { id_RedirectAttemptFlag, "id-RedirectAttemptFlag" },
  { id_RAT_Type, "id-RAT-Type" },
  { id_PeriodicLocationInfo, "id-PeriodicLocationInfo" },
  { id_MBMSCountingInformation, "id-MBMSCountingInformation" },
  { id_170_not_to_be_used_for_IE_ids, "id-170-not-to-be-used-for-IE-ids" },
  { id_ExtendedRNC_ID, "id-ExtendedRNC-ID" },
  { id_Alt_RAB_Parameter_ExtendedGuaranteedBitrateInf, "id-Alt-RAB-Parameter-ExtendedGuaranteedBitrateInf" },
  { id_Alt_RAB_Parameter_ExtendedMaxBitrateInf, "id-Alt-RAB-Parameter-ExtendedMaxBitrateInf" },
  { id_Ass_RAB_Parameter_ExtendedGuaranteedBitrateList, "id-Ass-RAB-Parameter-ExtendedGuaranteedBitrateList" },
  { id_Ass_RAB_Parameter_ExtendedMaxBitrateList, "id-Ass-RAB-Parameter-ExtendedMaxBitrateList" },
  { id_RAB_Parameter_ExtendedGuaranteedBitrateList, "id-RAB-Parameter-ExtendedGuaranteedBitrateList" },
  { id_RAB_Parameter_ExtendedMaxBitrateList, "id-RAB-Parameter-ExtendedMaxBitrateList" },
  { id_Requested_RAB_Parameter_ExtendedMaxBitrateList, "id-Requested-RAB-Parameter-ExtendedMaxBitrateList" },
  { id_Requested_RAB_Parameter_ExtendedGuaranteedBitrateList, "id-Requested-RAB-Parameter-ExtendedGuaranteedBitrateList" },
  { id_LAofIdleModeUEs, "id-LAofIdleModeUEs" },
  { id_newLAListofIdleModeUEs, "id-newLAListofIdleModeUEs" },
  { id_LAListwithNoIdleModeUEsAnyMore, "id-LAListwithNoIdleModeUEsAnyMore" },
  { id_183_not_to_be_used_for_IE_ids, "id-183-not-to-be-used-for-IE-ids" },
  { id_GANSS_PositioningDataSet, "id-GANSS-PositioningDataSet" },
  { id_RequestedGANSSAssistanceData, "id-RequestedGANSSAssistanceData" },
  { id_BroadcastGANSSAssistanceDataDecipheringKeys, "id-BroadcastGANSSAssistanceDataDecipheringKeys" },
  { id_d_RNTI_for_NoIuCSUP, "id-d-RNTI-for-NoIuCSUP" },
  { id_RAB_SetupList_EnhancedRelocCompleteReq, "id-RAB-SetupList-EnhancedRelocCompleteReq" },
  { id_RAB_SetupItem_EnhancedRelocCompleteReq, "id-RAB-SetupItem-EnhancedRelocCompleteReq" },
  { id_RAB_SetupList_EnhancedRelocCompleteRes, "id-RAB-SetupList-EnhancedRelocCompleteRes" },
  { id_RAB_SetupItem_EnhancedRelocCompleteRes, "id-RAB-SetupItem-EnhancedRelocCompleteRes" },
  { id_RAB_SetupList_EnhRelocInfoReq, "id-RAB-SetupList-EnhRelocInfoReq" },
  { id_RAB_SetupItem_EnhRelocInfoReq, "id-RAB-SetupItem-EnhRelocInfoReq" },
  { id_RAB_SetupList_EnhRelocInfoRes, "id-RAB-SetupList-EnhRelocInfoRes" },
  { id_RAB_SetupItem_EnhRelocInfoRes, "id-RAB-SetupItem-EnhRelocInfoRes" },
  { id_OldIuSigConId, "id-OldIuSigConId" },
  { id_RAB_FailedList_EnhRelocInfoRes, "id-RAB-FailedList-EnhRelocInfoRes" },
  { id_RAB_FailedItem_EnhRelocInfoRes, "id-RAB-FailedItem-EnhRelocInfoRes" },
  { id_Global_ENB_ID, "id-Global-ENB-ID" },
  { id_UE_History_Information, "id-UE-History-Information" },
  { id_MBMSSynchronisationInformation, "id-MBMSSynchronisationInformation" },
  { id_SubscriberProfileIDforRFP, "id-SubscriberProfileIDforRFP" },
  { id_CSG_Id, "id-CSG-Id" },
  { id_OldIuSigConIdCS, "id-OldIuSigConIdCS" },
  { id_OldIuSigConIdPS, "id-OldIuSigConIdPS" },
  { id_GlobalCN_IDCS, "id-GlobalCN-IDCS" },
  { id_GlobalCN_IDPS, "id-GlobalCN-IDPS" },
  { id_SourceExtendedRNC_ID, "id-SourceExtendedRNC-ID" },
  { id_RAB_ToBeReleasedItem_EnhancedRelocCompleteRes, "id-RAB-ToBeReleasedItem-EnhancedRelocCompleteRes" },
  { id_RAB_ToBeReleasedList_EnhancedRelocCompleteRes, "id-RAB-ToBeReleasedList-EnhancedRelocCompleteRes" },
  { id_SourceRNC_ID, "id-SourceRNC-ID" },
  { id_Relocation_TargetRNC_ID, "id-Relocation-TargetRNC-ID" },
  { id_Relocation_TargetExtendedRNC_ID, "id-Relocation-TargetExtendedRNC-ID" },
  { id_Alt_RAB_Parameter_SupportedGuaranteedBitrateInf, "id-Alt-RAB-Parameter-SupportedGuaranteedBitrateInf" },
  { id_Alt_RAB_Parameter_SupportedMaxBitrateInf, "id-Alt-RAB-Parameter-SupportedMaxBitrateInf" },
  { id_Ass_RAB_Parameter_SupportedGuaranteedBitrateList, "id-Ass-RAB-Parameter-SupportedGuaranteedBitrateList" },
  { id_Ass_RAB_Parameter_SupportedMaxBitrateList, "id-Ass-RAB-Parameter-SupportedMaxBitrateList" },
  { id_RAB_Parameter_SupportedGuaranteedBitrateList, "id-RAB-Parameter-SupportedGuaranteedBitrateList" },
  { id_RAB_Parameter_SupportedMaxBitrateList, "id-RAB-Parameter-SupportedMaxBitrateList" },
  { id_Requested_RAB_Parameter_SupportedMaxBitrateList, "id-Requested-RAB-Parameter-SupportedMaxBitrateList" },
  { id_Requested_RAB_Parameter_SupportedGuaranteedBitrateList, "id-Requested-RAB-Parameter-SupportedGuaranteedBitrateList" },
  { id_Relocation_SourceRNC_ID, "id-Relocation-SourceRNC-ID" },
  { id_Relocation_SourceExtendedRNC_ID, "id-Relocation-SourceExtendedRNC-ID" },
  { id_EncryptionKey, "id-EncryptionKey" },
  { id_IntegrityProtectionKey, "id-IntegrityProtectionKey" },
  { id_SRVCC_HO_Indication, "id-SRVCC-HO-Indication" },
  { id_SRVCC_Information, "id-SRVCC-Information" },
  { id_SRVCC_Operation_Possible, "id-SRVCC-Operation-Possible" },
  { id_CSG_Id_List, "id-CSG-Id-List" },
  { id_PSRABtobeReplaced, "id-PSRABtobeReplaced" },
  { id_E_UTRAN_Service_Handover, "id-E-UTRAN-Service-Handover" },
  { id_Not_Used_232, "id-Not-Used-232" },
  { id_UE_AggregateMaximumBitRate, "id-UE-AggregateMaximumBitRate" },
  { id_CSG_Membership_Status, "id-CSG-Membership-Status" },
  { id_Cell_Access_Mode, "id-Cell-Access-Mode" },
  { id_IP_Source_Address, "id-IP-Source-Address" },
  { id_CSFB_Information, "id-CSFB-Information" },
  { id_PDP_TypeInformation_extension, "id-PDP-TypeInformation-extension" },
  { id_MSISDN, "id-MSISDN" },
  { id_Offload_RAB_Parameters, "id-Offload-RAB-Parameters" },
  { id_LGW_TransportLayerAddress, "id-LGW-TransportLayerAddress" },
  { id_Correlation_ID, "id-Correlation-ID" },
  { id_IRAT_Measurement_Configuration, "id-IRAT-Measurement-Configuration" },
  { id_MDT_Configuration, "id-MDT-Configuration" },
  { id_Priority_Class_Indicator, "id-Priority-Class-Indicator" },
  { id_Not_Used_246, "id-Not-Used-246" },
  { id_RNSAPRelocationParameters, "id-RNSAPRelocationParameters" },
  { id_Management_Based_MDT_Allowed, "id-Management-Based-MDT-Allowed" },
  { 0, NULL }
};

static value_string_ext ranap_ProtocolIE_ID_vals_ext = VALUE_STRING_EXT_INIT(ranap_ProtocolIE_ID_vals);


static int
dissect_ranap_ProtocolIE_ID(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 65535U, &ProtocolIE_ID, FALSE);

#line 75 "../../asn1/ranap/ranap.cnf"
  if (tree) {
    proto_item_append_text(proto_item_get_parent_nth(actx->created_item, 2), ": %s", val_to_str_ext(ProtocolIE_ID, &ranap_ProtocolIE_ID_vals_ext, "unknown (%d)"));
  }

  return offset;
}


static const value_string ranap_TriggeringMessage_vals[] = {
  {   0, "initiating-message" },
  {   1, "successful-outcome" },
  {   2, "unsuccessfull-outcome" },
  {   3, "outcome" },
  { 0, NULL }
};


static int
dissect_ranap_TriggeringMessage(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     4, NULL, FALSE, 0, NULL);

  return offset;
}



static int
dissect_ranap_T_ie_field_value(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_open_type_pdu_new(tvb, offset, actx, tree, hf_index, dissect_ProtocolIEFieldValue);

  return offset;
}


static const per_sequence_t ProtocolIE_Field_sequence[] = {
  { &hf_ranap_id            , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ranap_ProtocolIE_ID },
  { &hf_ranap_criticality   , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ranap_Criticality },
  { &hf_ranap_ie_field_value, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ranap_T_ie_field_value },
  { NULL, 0, 0, NULL }
};

static int
dissect_ranap_ProtocolIE_Field(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ranap_ProtocolIE_Field, ProtocolIE_Field_sequence);

  return offset;
}


static const per_sequence_t ProtocolIE_Container_sequence_of[1] = {
  { &hf_ranap_ProtocolIE_Container_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ranap_ProtocolIE_Field },
};

static int
dissect_ranap_ProtocolIE_Container(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_ranap_ProtocolIE_Container, ProtocolIE_Container_sequence_of,
                                                  0, maxProtocolIEs, FALSE);

  return offset;
}



static int
dissect_ranap_T_firstValue(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_open_type_pdu_new(tvb, offset, actx, tree, hf_index, dissect_ProtocolIEFieldPairFirstValue);

  return offset;
}



static int
dissect_ranap_T_secondValue(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_open_type_pdu_new(tvb, offset, actx, tree, hf_index, dissect_ProtocolIEFieldPairSecondValue);

  return offset;
}


static const per_sequence_t ProtocolIE_FieldPair_sequence[] = {
  { &hf_ranap_id            , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ranap_ProtocolIE_ID },
  { &hf_ranap_firstCriticality, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ranap_Criticality },
  { &hf_ranap_firstValue    , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ranap_T_firstValue },
  { &hf_ranap_secondCriticality, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ranap_Criticality },
  { &hf_ranap_secondValue   , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ranap_T_secondValue },
  { NULL, 0, 0, NULL }
};

static int
dissect_ranap_ProtocolIE_FieldPair(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ranap_ProtocolIE_FieldPair, ProtocolIE_FieldPair_sequence);

  return offset;
}


static const per_sequence_t ProtocolIE_ContainerPair_sequence_of[1] = {
  { &hf_ranap_ProtocolIE_ContainerPair_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ranap_ProtocolIE_FieldPair },
};

static int
dissect_ranap_ProtocolIE_ContainerPair(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_ranap_ProtocolIE_ContainerPair, ProtocolIE_ContainerPair_sequence_of,
                                                  0, maxProtocolIEs, FALSE);

  return offset;
}


static const per_sequence_t ProtocolIE_ContainerList_sequence_of[1] = {
  { &hf_ranap_ProtocolIE_ContainerList_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ranap_ProtocolIE_Container },
};

static int
dissect_ranap_ProtocolIE_ContainerList(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 115 "../../asn1/ranap/ranap.cnf"
  static const asn1_par_def_t ProtocolIE_ContainerList_pars[] = {
    { "lowerBound", ASN1_PAR_INTEGER },
    { "upperBound", ASN1_PAR_INTEGER },
    { NULL, 0 }
  };
  asn1_stack_frame_check(actx, "ProtocolIE-ContainerList", ProtocolIE_ContainerList_pars);

  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_ranap_ProtocolIE_ContainerList, ProtocolIE_ContainerList_sequence_of,
                                                  asn1_param_get_integer(actx,"lowerBound"), asn1_param_get_integer(actx,"upperBound"), FALSE);

  return offset;
}


static const per_sequence_t ProtocolIE_ContainerPairList_sequence_of[1] = {
  { &hf_ranap_ProtocolIE_ContainerPairList_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ranap_ProtocolIE_ContainerPair },
};

static int
dissect_ranap_ProtocolIE_ContainerPairList(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 131 "../../asn1/ranap/ranap.cnf"
  static const asn1_par_def_t ProtocolIE_ContainerPairList_pars[] = {
    { "lowerBound", ASN1_PAR_INTEGER },
    { "upperBound", ASN1_PAR_INTEGER },
    { NULL, 0 }
  };
  asn1_stack_frame_check(actx, "ProtocolIE-ContainerPairList", ProtocolIE_ContainerPairList_pars);

  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_ranap_ProtocolIE_ContainerPairList, ProtocolIE_ContainerPairList_sequence_of,
                                                  asn1_param_get_integer(actx,"lowerBound"), asn1_param_get_integer(actx,"upperBound"), FALSE);

  return offset;
}



static int
dissect_ranap_T_extensionValue(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_open_type_pdu_new(tvb, offset, actx, tree, hf_index, dissect_ProtocolExtensionFieldExtensionValue);

  return offset;
}


static const per_sequence_t ProtocolExtensionField_sequence[] = {
  { &hf_ranap_ext_id        , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ranap_ProtocolExtensionID },
  { &hf_ranap_criticality   , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ranap_Criticality },
  { &hf_ranap_extensionValue, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ranap_T_extensionValue },
  { NULL, 0, 0, NULL }
};

static int
dissect_ranap_ProtocolExtensionField(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ranap_ProtocolExtensionField, ProtocolExtensionField_sequence);

  return offset;
}


static const per_sequence_t ProtocolExtensionContainer_sequence_of[1] = {
  { &hf_ranap_ProtocolExtensionContainer_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ranap_ProtocolExtensionField },
};

static int
dissect_ranap_ProtocolExtensionContainer(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_ranap_ProtocolExtensionContainer, ProtocolExtensionContainer_sequence_of,
                                                  1, maxProtocolExtensions, FALSE);

  return offset;
}



static int
dissect_ranap_T_private_value(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_open_type(tvb, offset, actx, tree, hf_index, NULL);

  return offset;
}


static const per_sequence_t PrivateIE_Field_sequence[] = {
  { &hf_ranap_private_id    , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ranap_PrivateIE_ID },
  { &hf_ranap_criticality   , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ranap_Criticality },
  { &hf_ranap_private_value , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ranap_T_private_value },
  { NULL, 0, 0, NULL }
};

static int
dissect_ranap_PrivateIE_Field(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ranap_PrivateIE_Field, PrivateIE_Field_sequence);

  return offset;
}


static const per_sequence_t PrivateIE_Container_sequence_of[1] = {
  { &hf_ranap_PrivateIE_Container_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ranap_PrivateIE_Field },
};

static int
dissect_ranap_PrivateIE_Container(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_ranap_PrivateIE_Container, PrivateIE_Container_sequence_of,
                                                  1, maxPrivateIEs, FALSE);

  return offset;
}


static const value_string ranap_AccuracyFulfilmentIndicator_vals[] = {
  {   0, "requested-Accuracy-Fulfilled" },
  {   1, "requested-Accuracy-Not-Fulfilled" },
  { 0, NULL }
};


static int
dissect_ranap_AccuracyFulfilmentIndicator(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     2, NULL, TRUE, 0, NULL);

  return offset;
}


static const value_string ranap_PriorityLevel_vals[] = {
  {   0, "spare" },
  {   1, "highest" },
  {  14, "lowest" },
  {  15, "no-priority" },
  { 0, NULL }
};


static int
dissect_ranap_PriorityLevel(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 15U, NULL, FALSE);

  return offset;
}


static const value_string ranap_Pre_emptionCapability_vals[] = {
  {   0, "shall-not-trigger-pre-emption" },
  {   1, "may-trigger-pre-emption" },
  { 0, NULL }
};


static int
dissect_ranap_Pre_emptionCapability(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     2, NULL, FALSE, 0, NULL);

  return offset;
}


static const value_string ranap_Pre_emptionVulnerability_vals[] = {
  {   0, "not-pre-emptable" },
  {   1, "pre-emptable" },
  { 0, NULL }
};


static int
dissect_ranap_Pre_emptionVulnerability(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     2, NULL, FALSE, 0, NULL);

  return offset;
}


static const value_string ranap_QueuingAllowed_vals[] = {
  {   0, "queueing-not-allowed" },
  {   1, "queueing-allowed" },
  { 0, NULL }
};


static int
dissect_ranap_QueuingAllowed(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     2, NULL, FALSE, 0, NULL);

  return offset;
}


static const per_sequence_t AllocationOrRetentionPriority_sequence[] = {
  { &hf_ranap_priorityLevel , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ranap_PriorityLevel },
  { &hf_ranap_pre_emptionCapability, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ranap_Pre_emptionCapability },
  { &hf_ranap_pre_emptionVulnerability, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ranap_Pre_emptionVulnerability },
  { &hf_ranap_queuingAllowed, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ranap_QueuingAllowed },
  { &hf_ranap_iE_Extensions , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ranap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_ranap_AllocationOrRetentionPriority(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ranap_AllocationOrRetentionPriority, AllocationOrRetentionPriority_sequence);

  return offset;
}


static const value_string ranap_Alt_RAB_Parameter_MaxBitrateType_vals[] = {
  {   0, "unspecified" },
  {   1, "value-range" },
  {   2, "discrete-values" },
  { 0, NULL }
};


static int
dissect_ranap_Alt_RAB_Parameter_MaxBitrateType(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     3, NULL, TRUE, 0, NULL);

  return offset;
}



static int
dissect_ranap_MaxBitrate(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            1U, 16000000U, NULL, FALSE);

  return offset;
}


static const per_sequence_t Alt_RAB_Parameter_MaxBitrateList_sequence_of[1] = {
  { &hf_ranap_Alt_RAB_Parameter_MaxBitrateList_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ranap_MaxBitrate },
};

static int
dissect_ranap_Alt_RAB_Parameter_MaxBitrateList(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_ranap_Alt_RAB_Parameter_MaxBitrateList, Alt_RAB_Parameter_MaxBitrateList_sequence_of,
                                                  1, maxNrOfSeparateTrafficDirections, FALSE);

  return offset;
}


static const per_sequence_t Alt_RAB_Parameter_MaxBitrates_sequence_of[1] = {
  { &hf_ranap_Alt_RAB_Parameter_MaxBitrates_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ranap_Alt_RAB_Parameter_MaxBitrateList },
};

static int
dissect_ranap_Alt_RAB_Parameter_MaxBitrates(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_ranap_Alt_RAB_Parameter_MaxBitrates, Alt_RAB_Parameter_MaxBitrates_sequence_of,
                                                  1, maxNrOfAltValues, FALSE);

  return offset;
}


static const per_sequence_t Alt_RAB_Parameter_MaxBitrateInf_sequence[] = {
  { &hf_ranap_altMaxBitrateType, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ranap_Alt_RAB_Parameter_MaxBitrateType },
  { &hf_ranap_altMaxBitrates, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ranap_Alt_RAB_Parameter_MaxBitrates },
  { NULL, 0, 0, NULL }
};

static int
dissect_ranap_Alt_RAB_Parameter_MaxBitrateInf(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ranap_Alt_RAB_Parameter_MaxBitrateInf, Alt_RAB_Parameter_MaxBitrateInf_sequence);

  return offset;
}


static const value_string ranap_Alt_RAB_Parameter_GuaranteedBitrateType_vals[] = {
  {   0, "unspecified" },
  {   1, "value-range" },
  {   2, "discrete-values" },
  { 0, NULL }
};


static int
dissect_ranap_Alt_RAB_Parameter_GuaranteedBitrateType(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     3, NULL, TRUE, 0, NULL);

  return offset;
}



static int
dissect_ranap_GuaranteedBitrate(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 16000000U, NULL, FALSE);

  return offset;
}


static const per_sequence_t Alt_RAB_Parameter_GuaranteedBitrateList_sequence_of[1] = {
  { &hf_ranap_Alt_RAB_Parameter_GuaranteedBitrateList_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ranap_GuaranteedBitrate },
};

static int
dissect_ranap_Alt_RAB_Parameter_GuaranteedBitrateList(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_ranap_Alt_RAB_Parameter_GuaranteedBitrateList, Alt_RAB_Parameter_GuaranteedBitrateList_sequence_of,
                                                  1, maxNrOfSeparateTrafficDirections, FALSE);

  return offset;
}


static const per_sequence_t Alt_RAB_Parameter_GuaranteedBitrates_sequence_of[1] = {
  { &hf_ranap_Alt_RAB_Parameter_GuaranteedBitrates_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ranap_Alt_RAB_Parameter_GuaranteedBitrateList },
};

static int
dissect_ranap_Alt_RAB_Parameter_GuaranteedBitrates(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_ranap_Alt_RAB_Parameter_GuaranteedBitrates, Alt_RAB_Parameter_GuaranteedBitrates_sequence_of,
                                                  1, maxNrOfAltValues, FALSE);

  return offset;
}


static const per_sequence_t Alt_RAB_Parameter_GuaranteedBitrateInf_sequence[] = {
  { &hf_ranap_altGuaranteedBitrateType, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ranap_Alt_RAB_Parameter_GuaranteedBitrateType },
  { &hf_ranap_altGuaranteedBitrates, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ranap_Alt_RAB_Parameter_GuaranteedBitrates },
  { NULL, 0, 0, NULL }
};

static int
dissect_ranap_Alt_RAB_Parameter_GuaranteedBitrateInf(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ranap_Alt_RAB_Parameter_GuaranteedBitrateInf, Alt_RAB_Parameter_GuaranteedBitrateInf_sequence);

  return offset;
}


static const per_sequence_t Alt_RAB_Parameters_sequence[] = {
  { &hf_ranap_altMaxBitrateInf, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ranap_Alt_RAB_Parameter_MaxBitrateInf },
  { &hf_ranap_altGuaranteedBitRateInf, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ranap_Alt_RAB_Parameter_GuaranteedBitrateInf },
  { &hf_ranap_iE_Extensions , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ranap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_ranap_Alt_RAB_Parameters(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ranap_Alt_RAB_Parameters, Alt_RAB_Parameters_sequence);

  return offset;
}



static int
dissect_ranap_ExtendedGuaranteedBitrate(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            16000001U, 256000000U, NULL, FALSE);

  return offset;
}


static const per_sequence_t Alt_RAB_Parameter_ExtendedGuaranteedBitrateList_sequence_of[1] = {
  { &hf_ranap_Alt_RAB_Parameter_ExtendedGuaranteedBitrateList_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ranap_ExtendedGuaranteedBitrate },
};

static int
dissect_ranap_Alt_RAB_Parameter_ExtendedGuaranteedBitrateList(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_ranap_Alt_RAB_Parameter_ExtendedGuaranteedBitrateList, Alt_RAB_Parameter_ExtendedGuaranteedBitrateList_sequence_of,
                                                  1, maxNrOfSeparateTrafficDirections, FALSE);

  return offset;
}


static const per_sequence_t Alt_RAB_Parameter_ExtendedGuaranteedBitrates_sequence_of[1] = {
  { &hf_ranap_Alt_RAB_Parameter_ExtendedGuaranteedBitrates_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ranap_Alt_RAB_Parameter_ExtendedGuaranteedBitrateList },
};

static int
dissect_ranap_Alt_RAB_Parameter_ExtendedGuaranteedBitrates(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_ranap_Alt_RAB_Parameter_ExtendedGuaranteedBitrates, Alt_RAB_Parameter_ExtendedGuaranteedBitrates_sequence_of,
                                                  1, maxNrOfAltValues, FALSE);

  return offset;
}


static const per_sequence_t Alt_RAB_Parameter_ExtendedGuaranteedBitrateInf_sequence[] = {
  { &hf_ranap_altExtendedGuaranteedBitrateType, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ranap_Alt_RAB_Parameter_GuaranteedBitrateType },
  { &hf_ranap_altExtendedGuaranteedBitrates, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ranap_Alt_RAB_Parameter_ExtendedGuaranteedBitrates },
  { NULL, 0, 0, NULL }
};

static int
dissect_ranap_Alt_RAB_Parameter_ExtendedGuaranteedBitrateInf(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ranap_Alt_RAB_Parameter_ExtendedGuaranteedBitrateInf, Alt_RAB_Parameter_ExtendedGuaranteedBitrateInf_sequence);

  return offset;
}



static int
dissect_ranap_SupportedBitrate(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            1U, 1000000000U, NULL, TRUE);

  return offset;
}


static const per_sequence_t SupportedRAB_ParameterBitrateList_sequence_of[1] = {
  { &hf_ranap_SupportedRAB_ParameterBitrateList_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ranap_SupportedBitrate },
};

static int
dissect_ranap_SupportedRAB_ParameterBitrateList(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_ranap_SupportedRAB_ParameterBitrateList, SupportedRAB_ParameterBitrateList_sequence_of,
                                                  1, maxNrOfSeparateTrafficDirections, FALSE);

  return offset;
}


static const per_sequence_t Alt_RAB_Parameter_SupportedGuaranteedBitrates_sequence_of[1] = {
  { &hf_ranap_Alt_RAB_Parameter_SupportedGuaranteedBitrates_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ranap_SupportedRAB_ParameterBitrateList },
};

static int
dissect_ranap_Alt_RAB_Parameter_SupportedGuaranteedBitrates(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_ranap_Alt_RAB_Parameter_SupportedGuaranteedBitrates, Alt_RAB_Parameter_SupportedGuaranteedBitrates_sequence_of,
                                                  1, maxNrOfAltValues, FALSE);

  return offset;
}


static const per_sequence_t Alt_RAB_Parameter_SupportedGuaranteedBitrateInf_sequence[] = {
  { &hf_ranap_altSupportedGuaranteedBitrateType, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ranap_Alt_RAB_Parameter_GuaranteedBitrateType },
  { &hf_ranap_altSupportedGuaranteedBitrates, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ranap_Alt_RAB_Parameter_SupportedGuaranteedBitrates },
  { &hf_ranap_iE_Extensions , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ranap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_ranap_Alt_RAB_Parameter_SupportedGuaranteedBitrateInf(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ranap_Alt_RAB_Parameter_SupportedGuaranteedBitrateInf, Alt_RAB_Parameter_SupportedGuaranteedBitrateInf_sequence);

  return offset;
}



static int
dissect_ranap_ExtendedMaxBitrate(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            16000001U, 256000000U, NULL, FALSE);

  return offset;
}


static const per_sequence_t Alt_RAB_Parameter_ExtendedMaxBitrateList_sequence_of[1] = {
  { &hf_ranap_Alt_RAB_Parameter_ExtendedMaxBitrateList_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ranap_ExtendedMaxBitrate },
};

static int
dissect_ranap_Alt_RAB_Parameter_ExtendedMaxBitrateList(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_ranap_Alt_RAB_Parameter_ExtendedMaxBitrateList, Alt_RAB_Parameter_ExtendedMaxBitrateList_sequence_of,
                                                  1, maxNrOfSeparateTrafficDirections, FALSE);

  return offset;
}


static const per_sequence_t Alt_RAB_Parameter_ExtendedMaxBitrates_sequence_of[1] = {
  { &hf_ranap_Alt_RAB_Parameter_ExtendedMaxBitrates_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ranap_Alt_RAB_Parameter_ExtendedMaxBitrateList },
};

static int
dissect_ranap_Alt_RAB_Parameter_ExtendedMaxBitrates(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_ranap_Alt_RAB_Parameter_ExtendedMaxBitrates, Alt_RAB_Parameter_ExtendedMaxBitrates_sequence_of,
                                                  1, maxNrOfAltValues, FALSE);

  return offset;
}


static const per_sequence_t Alt_RAB_Parameter_ExtendedMaxBitrateInf_sequence[] = {
  { &hf_ranap_altExtendedMaxBitrateType, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ranap_Alt_RAB_Parameter_MaxBitrateType },
  { &hf_ranap_altExtendedMaxBitrates, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ranap_Alt_RAB_Parameter_ExtendedMaxBitrates },
  { NULL, 0, 0, NULL }
};

static int
dissect_ranap_Alt_RAB_Parameter_ExtendedMaxBitrateInf(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ranap_Alt_RAB_Parameter_ExtendedMaxBitrateInf, Alt_RAB_Parameter_ExtendedMaxBitrateInf_sequence);

  return offset;
}


static const per_sequence_t Alt_RAB_Parameter_SupportedMaxBitrates_sequence_of[1] = {
  { &hf_ranap_Alt_RAB_Parameter_SupportedMaxBitrates_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ranap_SupportedRAB_ParameterBitrateList },
};

static int
dissect_ranap_Alt_RAB_Parameter_SupportedMaxBitrates(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_ranap_Alt_RAB_Parameter_SupportedMaxBitrates, Alt_RAB_Parameter_SupportedMaxBitrates_sequence_of,
                                                  1, maxNrOfAltValues, FALSE);

  return offset;
}


static const per_sequence_t Alt_RAB_Parameter_SupportedMaxBitrateInf_sequence[] = {
  { &hf_ranap_altSupportedMaxBitrateType, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ranap_Alt_RAB_Parameter_MaxBitrateType },
  { &hf_ranap_altSupportedMaxBitrates, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ranap_Alt_RAB_Parameter_SupportedMaxBitrates },
  { &hf_ranap_iE_Extensions , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ranap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_ranap_Alt_RAB_Parameter_SupportedMaxBitrateInf(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ranap_Alt_RAB_Parameter_SupportedMaxBitrateInf, Alt_RAB_Parameter_SupportedMaxBitrateInf_sequence);

  return offset;
}


static const value_string ranap_AlternativeRABConfigurationRequest_vals[] = {
  {   0, "alternative-RAB-configuration-Requested" },
  { 0, NULL }
};


static int
dissect_ranap_AlternativeRABConfigurationRequest(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     1, NULL, TRUE, 0, NULL);

  return offset;
}



static int
dissect_ranap_APN(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_octet_string(tvb, offset, actx, tree, hf_index,
                                       1, 255, FALSE, NULL);

  return offset;
}




static int
dissect_ranap_PLMNidentity(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 278 "../../asn1/ranap/ranap.cnf"
  tvbuff_t *parameter_tvb=NULL;

  offset = dissect_per_octet_string(tvb, offset, actx, tree, hf_index,
                                       3, 3, FALSE, &parameter_tvb);

	 if (!parameter_tvb)
		return offset;
	dissect_e212_mcc_mnc(parameter_tvb, actx->pinfo, tree, 0, FALSE);


  return offset;
}



static int
dissect_ranap_LAC(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_octet_string(tvb, offset, actx, tree, hf_index,
                                       2, 2, FALSE, NULL);

  return offset;
}



static int
dissect_ranap_SAC(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_octet_string(tvb, offset, actx, tree, hf_index,
                                       2, 2, FALSE, NULL);

  return offset;
}


static const per_sequence_t SAI_sequence[] = {
  { &hf_ranap_pLMNidentity  , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ranap_PLMNidentity },
  { &hf_ranap_lAC           , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ranap_LAC },
  { &hf_ranap_sAC           , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ranap_SAC },
  { &hf_ranap_iE_Extensions , ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_ranap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_ranap_SAI(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ranap_SAI, SAI_sequence);

  return offset;
}


static const value_string ranap_T_latitudeSign_vals[] = {
  {   0, "north" },
  {   1, "south" },
  { 0, NULL }
};


static int
dissect_ranap_T_latitudeSign(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     2, NULL, FALSE, 0, NULL);

  return offset;
}



static int
dissect_ranap_INTEGER_0_8388607(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 8388607U, NULL, FALSE);

  return offset;
}



static int
dissect_ranap_INTEGER_M8388608_8388607(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            -8388608, 8388607U, NULL, FALSE);

  return offset;
}


static const per_sequence_t GeographicalCoordinates_sequence[] = {
  { &hf_ranap_latitudeSign  , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ranap_T_latitudeSign },
  { &hf_ranap_latitude      , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ranap_INTEGER_0_8388607 },
  { &hf_ranap_longitude     , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ranap_INTEGER_M8388608_8388607 },
  { &hf_ranap_iE_Extensions , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ranap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_ranap_GeographicalCoordinates(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ranap_GeographicalCoordinates, GeographicalCoordinates_sequence);

  return offset;
}


static const per_sequence_t GA_Point_sequence[] = {
  { &hf_ranap_geographicalCoordinates, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ranap_GeographicalCoordinates },
  { &hf_ranap_iE_Extensions , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ranap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_ranap_GA_Point(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ranap_GA_Point, GA_Point_sequence);

  return offset;
}



static int
dissect_ranap_INTEGER_0_127(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 127U, NULL, FALSE);

  return offset;
}


static const per_sequence_t GA_PointWithUnCertainty_sequence[] = {
  { &hf_ranap_geographicalCoordinates, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ranap_GeographicalCoordinates },
  { &hf_ranap_iE_Extensions , ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_ranap_ProtocolExtensionContainer },
  { &hf_ranap_uncertaintyCode, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ranap_INTEGER_0_127 },
  { NULL, 0, 0, NULL }
};

static int
dissect_ranap_GA_PointWithUnCertainty(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ranap_GA_PointWithUnCertainty, GA_PointWithUnCertainty_sequence);

  return offset;
}


static const per_sequence_t GA_Polygon_item_sequence[] = {
  { &hf_ranap_geographicalCoordinates, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ranap_GeographicalCoordinates },
  { &hf_ranap_iE_Extensions , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ranap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_ranap_GA_Polygon_item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ranap_GA_Polygon_item, GA_Polygon_item_sequence);

  return offset;
}


static const per_sequence_t GA_Polygon_sequence_of[1] = {
  { &hf_ranap_GA_Polygon_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ranap_GA_Polygon_item },
};

static int
dissect_ranap_GA_Polygon(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_ranap_GA_Polygon, GA_Polygon_sequence_of,
                                                  1, maxNrOfPoints, FALSE);

  return offset;
}



static int
dissect_ranap_INTEGER_0_179(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 179U, NULL, FALSE);

  return offset;
}


static const per_sequence_t GA_UncertaintyEllipse_sequence[] = {
  { &hf_ranap_uncertaintySemi_major, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ranap_INTEGER_0_127 },
  { &hf_ranap_uncertaintySemi_minor, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ranap_INTEGER_0_127 },
  { &hf_ranap_orientationOfMajorAxis, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ranap_INTEGER_0_179 },
  { NULL, 0, 0, NULL }
};

static int
dissect_ranap_GA_UncertaintyEllipse(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ranap_GA_UncertaintyEllipse, GA_UncertaintyEllipse_sequence);

  return offset;
}


static const per_sequence_t GA_PointWithUnCertaintyEllipse_sequence[] = {
  { &hf_ranap_geographicalCoordinates, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ranap_GeographicalCoordinates },
  { &hf_ranap_uncertaintyEllipse, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ranap_GA_UncertaintyEllipse },
  { &hf_ranap_confidence    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ranap_INTEGER_0_127 },
  { &hf_ranap_iE_Extensions , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ranap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_ranap_GA_PointWithUnCertaintyEllipse(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ranap_GA_PointWithUnCertaintyEllipse, GA_PointWithUnCertaintyEllipse_sequence);

  return offset;
}


static const value_string ranap_T_directionOfAltitude_vals[] = {
  {   0, "height" },
  {   1, "depth" },
  { 0, NULL }
};


static int
dissect_ranap_T_directionOfAltitude(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     2, NULL, FALSE, 0, NULL);

  return offset;
}



static int
dissect_ranap_INTEGER_0_32767(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 32767U, NULL, FALSE);

  return offset;
}


static const per_sequence_t GA_AltitudeAndDirection_sequence[] = {
  { &hf_ranap_directionOfAltitude, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ranap_T_directionOfAltitude },
  { &hf_ranap_altitude      , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ranap_INTEGER_0_32767 },
  { NULL, 0, 0, NULL }
};

static int
dissect_ranap_GA_AltitudeAndDirection(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ranap_GA_AltitudeAndDirection, GA_AltitudeAndDirection_sequence);

  return offset;
}


static const per_sequence_t GA_PointWithAltitude_sequence[] = {
  { &hf_ranap_geographicalCoordinates, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ranap_GeographicalCoordinates },
  { &hf_ranap_altitudeAndDirection, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ranap_GA_AltitudeAndDirection },
  { &hf_ranap_iE_Extensions , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ranap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_ranap_GA_PointWithAltitude(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ranap_GA_PointWithAltitude, GA_PointWithAltitude_sequence);

  return offset;
}


static const per_sequence_t GA_PointWithAltitudeAndUncertaintyEllipsoid_sequence[] = {
  { &hf_ranap_geographicalCoordinates, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ranap_GeographicalCoordinates },
  { &hf_ranap_altitudeAndDirection, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ranap_GA_AltitudeAndDirection },
  { &hf_ranap_uncertaintyEllipse, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ranap_GA_UncertaintyEllipse },
  { &hf_ranap_uncertaintyAltitude, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ranap_INTEGER_0_127 },
  { &hf_ranap_confidence    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ranap_INTEGER_0_127 },
  { &hf_ranap_iE_Extensions , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ranap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_ranap_GA_PointWithAltitudeAndUncertaintyEllipsoid(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ranap_GA_PointWithAltitudeAndUncertaintyEllipsoid, GA_PointWithAltitudeAndUncertaintyEllipsoid_sequence);

  return offset;
}


static const per_sequence_t GA_EllipsoidArc_sequence[] = {
  { &hf_ranap_geographicalCoordinates, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ranap_GeographicalCoordinates },
  { &hf_ranap_innerRadius   , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ranap_INTEGER_0_65535 },
  { &hf_ranap_uncertaintyRadius, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ranap_INTEGER_0_127 },
  { &hf_ranap_offsetAngle   , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ranap_INTEGER_0_179 },
  { &hf_ranap_includedAngle , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ranap_INTEGER_0_179 },
  { &hf_ranap_confidence    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ranap_INTEGER_0_127 },
  { &hf_ranap_iE_Extensions , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ranap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_ranap_GA_EllipsoidArc(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ranap_GA_EllipsoidArc, GA_EllipsoidArc_sequence);

  return offset;
}


static const value_string ranap_GeographicalArea_vals[] = {
  {   0, "point" },
  {   1, "pointWithUnCertainty" },
  {   2, "polygon" },
  {   3, "pointWithUncertaintyEllipse" },
  {   4, "pointWithAltitude" },
  {   5, "pointWithAltitudeAndUncertaintyEllipsoid" },
  {   6, "ellipsoidArc" },
  { 0, NULL }
};

static const per_choice_t GeographicalArea_choice[] = {
  {   0, &hf_ranap_point         , ASN1_EXTENSION_ROOT    , dissect_ranap_GA_Point },
  {   1, &hf_ranap_pointWithUnCertainty, ASN1_EXTENSION_ROOT    , dissect_ranap_GA_PointWithUnCertainty },
  {   2, &hf_ranap_polygon       , ASN1_EXTENSION_ROOT    , dissect_ranap_GA_Polygon },
  {   3, &hf_ranap_pointWithUncertaintyEllipse, ASN1_NOT_EXTENSION_ROOT, dissect_ranap_GA_PointWithUnCertaintyEllipse },
  {   4, &hf_ranap_pointWithAltitude, ASN1_NOT_EXTENSION_ROOT, dissect_ranap_GA_PointWithAltitude },
  {   5, &hf_ranap_pointWithAltitudeAndUncertaintyEllipsoid, ASN1_NOT_EXTENSION_ROOT, dissect_ranap_GA_PointWithAltitudeAndUncertaintyEllipsoid },
  {   6, &hf_ranap_ellipsoidArc  , ASN1_NOT_EXTENSION_ROOT, dissect_ranap_GA_EllipsoidArc },
  { 0, NULL, 0, NULL }
};

static int
dissect_ranap_GeographicalArea(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_ranap_GeographicalArea, GeographicalArea_choice,
                                 NULL);

  return offset;
}


static const value_string ranap_AreaIdentity_vals[] = {
  {   0, "sAI" },
  {   1, "geographicalArea" },
  { 0, NULL }
};

static const per_choice_t AreaIdentity_choice[] = {
  {   0, &hf_ranap_sAI           , ASN1_EXTENSION_ROOT    , dissect_ranap_SAI },
  {   1, &hf_ranap_geographicalArea, ASN1_EXTENSION_ROOT    , dissect_ranap_GeographicalArea },
  { 0, NULL, 0, NULL }
};

static int
dissect_ranap_AreaIdentity(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_ranap_AreaIdentity, AreaIdentity_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t Ass_RAB_Parameter_MaxBitrateList_sequence_of[1] = {
  { &hf_ranap_Ass_RAB_Parameter_MaxBitrateList_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ranap_MaxBitrate },
};

static int
dissect_ranap_Ass_RAB_Parameter_MaxBitrateList(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_ranap_Ass_RAB_Parameter_MaxBitrateList, Ass_RAB_Parameter_MaxBitrateList_sequence_of,
                                                  1, maxNrOfSeparateTrafficDirections, FALSE);

  return offset;
}


static const per_sequence_t Ass_RAB_Parameter_GuaranteedBitrateList_sequence_of[1] = {
  { &hf_ranap_Ass_RAB_Parameter_GuaranteedBitrateList_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ranap_GuaranteedBitrate },
};

static int
dissect_ranap_Ass_RAB_Parameter_GuaranteedBitrateList(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_ranap_Ass_RAB_Parameter_GuaranteedBitrateList, Ass_RAB_Parameter_GuaranteedBitrateList_sequence_of,
                                                  1, maxNrOfSeparateTrafficDirections, FALSE);

  return offset;
}


static const per_sequence_t Ass_RAB_Parameters_sequence[] = {
  { &hf_ranap_assMaxBitrateInf, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ranap_Ass_RAB_Parameter_MaxBitrateList },
  { &hf_ranap_assGuaranteedBitRateInf, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ranap_Ass_RAB_Parameter_GuaranteedBitrateList },
  { &hf_ranap_iE_Extensions , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ranap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_ranap_Ass_RAB_Parameters(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ranap_Ass_RAB_Parameters, Ass_RAB_Parameters_sequence);

  return offset;
}


static const per_sequence_t Ass_RAB_Parameter_ExtendedGuaranteedBitrateList_sequence_of[1] = {
  { &hf_ranap_Ass_RAB_Parameter_ExtendedGuaranteedBitrateList_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ranap_ExtendedGuaranteedBitrate },
};

static int
dissect_ranap_Ass_RAB_Parameter_ExtendedGuaranteedBitrateList(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_ranap_Ass_RAB_Parameter_ExtendedGuaranteedBitrateList, Ass_RAB_Parameter_ExtendedGuaranteedBitrateList_sequence_of,
                                                  1, maxNrOfSeparateTrafficDirections, FALSE);

  return offset;
}


static const per_sequence_t Ass_RAB_Parameter_ExtendedMaxBitrateList_sequence_of[1] = {
  { &hf_ranap_Ass_RAB_Parameter_ExtendedMaxBitrateList_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ranap_ExtendedMaxBitrate },
};

static int
dissect_ranap_Ass_RAB_Parameter_ExtendedMaxBitrateList(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_ranap_Ass_RAB_Parameter_ExtendedMaxBitrateList, Ass_RAB_Parameter_ExtendedMaxBitrateList_sequence_of,
                                                  1, maxNrOfSeparateTrafficDirections, FALSE);

  return offset;
}



static int
dissect_ranap_SNAC(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 65535U, NULL, FALSE);

  return offset;
}


static const per_sequence_t AuthorisedSNAs_sequence_of[1] = {
  { &hf_ranap_AuthorisedSNAs_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ranap_SNAC },
};

static int
dissect_ranap_AuthorisedSNAs(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_ranap_AuthorisedSNAs, AuthorisedSNAs_sequence_of,
                                                  1, maxNrOfSNAs, FALSE);

  return offset;
}


static const per_sequence_t AuthorisedPLMNs_item_sequence[] = {
  { &hf_ranap_pLMNidentity  , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ranap_PLMNidentity },
  { &hf_ranap_authorisedSNAsList, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ranap_AuthorisedSNAs },
  { &hf_ranap_iE_Extensions , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ranap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_ranap_AuthorisedPLMNs_item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ranap_AuthorisedPLMNs_item, AuthorisedPLMNs_item_sequence);

  return offset;
}


static const per_sequence_t AuthorisedPLMNs_sequence_of[1] = {
  { &hf_ranap_AuthorisedPLMNs_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ranap_AuthorisedPLMNs_item },
};

static int
dissect_ranap_AuthorisedPLMNs(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_ranap_AuthorisedPLMNs, AuthorisedPLMNs_sequence_of,
                                                  1, maxNrOfPLMNsSN, FALSE);

  return offset;
}



static int
dissect_ranap_BindingID(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_octet_string(tvb, offset, actx, tree, hf_index,
                                       4, 4, FALSE, NULL);

  return offset;
}



static int
dissect_ranap_BIT_STRING_SIZE_1(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_bit_string(tvb, offset, actx, tree, hf_index,
                                     1, 1, FALSE, NULL);

  return offset;
}



static int
dissect_ranap_BIT_STRING_SIZE_56(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_bit_string(tvb, offset, actx, tree, hf_index,
                                     56, 56, FALSE, NULL);

  return offset;
}


static const per_sequence_t BroadcastAssistanceDataDecipheringKeys_sequence[] = {
  { &hf_ranap_cipheringKeyFlag, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ranap_BIT_STRING_SIZE_1 },
  { &hf_ranap_currentDecipheringKey, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ranap_BIT_STRING_SIZE_56 },
  { &hf_ranap_nextDecipheringKey, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ranap_BIT_STRING_SIZE_56 },
  { NULL, 0, 0, NULL }
};

static int
dissect_ranap_BroadcastAssistanceDataDecipheringKeys(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ranap_BroadcastAssistanceDataDecipheringKeys, BroadcastAssistanceDataDecipheringKeys_sequence);

  return offset;
}


static const value_string ranap_CauseRadioNetwork_vals[] = {
  {   1, "rab-pre-empted" },
  {   2, "trelocoverall-expiry" },
  {   3, "trelocprep-expiry" },
  {   4, "treloccomplete-expiry" },
  {   5, "tqueing-expiry" },
  {   6, "relocation-triggered" },
  {   7, "trellocalloc-expiry" },
  {   8, "unable-to-establish-during-relocation" },
  {   9, "unknown-target-rnc" },
  {  10, "relocation-cancelled" },
  {  11, "successful-relocation" },
  {  12, "requested-ciphering-and-or-integrity-protection-algorithms-not-supported" },
  {  13, "conflict-with-already-existing-integrity-protection-and-or-ciphering-information" },
  {  14, "failure-in-the-radio-interface-procedure" },
  {  15, "release-due-to-utran-generated-reason" },
  {  16, "user-inactivity" },
  {  17, "time-critical-relocation" },
  {  18, "requested-traffic-class-not-available" },
  {  19, "invalid-rab-parameters-value" },
  {  20, "requested-maximum-bit-rate-not-available" },
  {  21, "requested-guaranteed-bit-rate-not-available" },
  {  22, "requested-transfer-delay-not-achievable" },
  {  23, "invalid-rab-parameters-combination" },
  {  24, "condition-violation-for-sdu-parameters" },
  {  25, "condition-violation-for-traffic-handling-priority" },
  {  26, "condition-violation-for-guaranteed-bit-rate" },
  {  27, "user-plane-versions-not-supported" },
  {  28, "iu-up-failure" },
  {  29, "relocation-failure-in-target-CN-RNC-or-target-system" },
  {  30, "invalid-RAB-ID" },
  {  31, "no-remaining-rab" },
  {  32, "interaction-with-other-procedure" },
  {  33, "requested-maximum-bit-rate-for-dl-not-available" },
  {  34, "requested-maximum-bit-rate-for-ul-not-available" },
  {  35, "requested-guaranteed-bit-rate-for-dl-not-available" },
  {  36, "requested-guaranteed-bit-rate-for-ul-not-available" },
  {  37, "repeated-integrity-checking-failure" },
  {  38, "requested-request-type-not-supported" },
  {  39, "request-superseded" },
  {  40, "release-due-to-UE-generated-signalling-connection-release" },
  {  41, "resource-optimisation-relocation" },
  {  42, "requested-information-not-available" },
  {  43, "relocation-desirable-for-radio-reasons" },
  {  44, "relocation-not-supported-in-target-RNC-or-target-system" },
  {  45, "directed-retry" },
  {  46, "radio-connection-with-UE-Lost" },
  {  47, "rNC-unable-to-establish-all-RFCs" },
  {  48, "deciphering-keys-not-available" },
  {  49, "dedicated-assistance-data-not-available" },
  {  50, "relocation-target-not-allowed" },
  {  51, "location-reporting-congestion" },
  {  52, "reduce-load-in-serving-cell" },
  {  53, "no-radio-resources-available-in-target-cell" },
  {  54, "gERAN-Iumode-failure" },
  {  55, "access-restricted-due-to-shared-networks" },
  {  56, "incoming-relocation-not-supported-due-to-PUESBINE-feature" },
  {  57, "traffic-load-in-the-target-cell-higher-than-in-the-source-cell" },
  {  58, "mBMS-no-multicast-service-for-this-UE" },
  {  59, "mBMS-unknown-UE-ID" },
  {  60, "successful-MBMS-session-start-no-data-bearer-necessary" },
  {  61, "mBMS-superseded-due-to-NNSF" },
  {  62, "mBMS-UE-linking-already-done" },
  {  63, "mBMS-UE-de-linking-failure-no-existing-UE-linking" },
  {  64, "tMGI-unknown" },
  { 0, NULL }
};

static value_string_ext ranap_CauseRadioNetwork_vals_ext = VALUE_STRING_EXT_INIT(ranap_CauseRadioNetwork_vals);


static int
dissect_ranap_CauseRadioNetwork(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            1U, 64U, NULL, FALSE);

  return offset;
}


static const value_string ranap_CauseTransmissionNetwork_vals[] = {
  {  65, "signalling-transport-resource-failure" },
  {  66, "iu-transport-connection-failed-to-establish" },
  { 0, NULL }
};


static int
dissect_ranap_CauseTransmissionNetwork(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            65U, 80U, NULL, FALSE);

  return offset;
}


static const value_string ranap_CauseNAS_vals[] = {
  {  81, "user-restriction-start-indication" },
  {  82, "user-restriction-end-indication" },
  {  83, "normal-release" },
  {  84, "csg-subscription-expiry" },
  { 0, NULL }
};


static int
dissect_ranap_CauseNAS(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            81U, 96U, NULL, FALSE);

  return offset;
}


static const value_string ranap_CauseProtocol_vals[] = {
  {  97, "transfer-syntax-error" },
  {  98, "semantic-error" },
  {  99, "message-not-compatible-with-receiver-state" },
  { 100, "abstract-syntax-error-reject" },
  { 101, "abstract-syntax-error-ignore-and-notify" },
  { 102, "abstract-syntax-error-falsely-constructed-message" },
  { 0, NULL }
};


static int
dissect_ranap_CauseProtocol(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            97U, 112U, NULL, FALSE);

  return offset;
}


static const value_string ranap_CauseMisc_vals[] = {
  { 113, "om-intervention" },
  { 114, "no-resource-available" },
  { 115, "unspecified-failure" },
  { 116, "network-optimisation" },
  { 0, NULL }
};


static int
dissect_ranap_CauseMisc(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            113U, 128U, NULL, FALSE);

  return offset;
}



static int
dissect_ranap_CauseNon_Standard(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            129U, 256U, NULL, FALSE);

  return offset;
}


static const value_string ranap_CauseRadioNetworkExtension_vals[] = {
  { 257, "iP-multicast-address-and-APN-not-valid" },
  { 258, "mBMS-de-registration-rejected-due-to-implicit-registration" },
  { 259, "mBMS-request-superseded" },
  { 260, "mBMS-de-registration-during-session-not-allowed" },
  { 261, "mBMS-no-data-bearer-necessary" },
  { 262, "periodicLocationInformationNotAvailable" },
  { 263, "gTP-Resources-Unavailable" },
  { 264, "tMGI-inUse-overlapping-MBMS-service-area" },
  { 265, "mBMS-no-cell-in-MBMS-service-area" },
  { 266, "no-Iu-CS-UP-relocation" },
  { 267, "successful-MBMS-Session-Start-IP-Multicast-Bearer-established" },
  { 268, "cS-fallback-triggered" },
  { 269, "invalid-CSG-Id" },
  { 0, NULL }
};


static int
dissect_ranap_CauseRadioNetworkExtension(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            257U, 512U, NULL, FALSE);

  return offset;
}


static const value_string ranap_Cause_vals[] = {
  {   0, "radioNetwork" },
  {   1, "transmissionNetwork" },
  {   2, "nAS" },
  {   3, "protocol" },
  {   4, "misc" },
  {   5, "non-Standard" },
  {   6, "radioNetworkExtension" },
  { 0, NULL }
};

static const per_choice_t Cause_choice[] = {
  {   0, &hf_ranap_radioNetwork  , ASN1_EXTENSION_ROOT    , dissect_ranap_CauseRadioNetwork },
  {   1, &hf_ranap_transmissionNetwork, ASN1_EXTENSION_ROOT    , dissect_ranap_CauseTransmissionNetwork },
  {   2, &hf_ranap_nAS           , ASN1_EXTENSION_ROOT    , dissect_ranap_CauseNAS },
  {   3, &hf_ranap_protocol      , ASN1_EXTENSION_ROOT    , dissect_ranap_CauseProtocol },
  {   4, &hf_ranap_misc          , ASN1_EXTENSION_ROOT    , dissect_ranap_CauseMisc },
  {   5, &hf_ranap_non_Standard  , ASN1_EXTENSION_ROOT    , dissect_ranap_CauseNon_Standard },
  {   6, &hf_ranap_radioNetworkExtension, ASN1_NOT_EXTENSION_ROOT, dissect_ranap_CauseRadioNetworkExtension },
  { 0, NULL, 0, NULL }
};

static int
dissect_ranap_Cause(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_ranap_Cause, Cause_choice,
                                 NULL);

  return offset;
}


static const value_string ranap_Cell_Access_Mode_vals[] = {
  {   0, "hybrid" },
  { 0, NULL }
};


static int
dissect_ranap_Cell_Access_Mode(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     1, NULL, TRUE, 0, NULL);

  return offset;
}



static int
dissect_ranap_Cell_Id(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 268435455U, NULL, FALSE);

  return offset;
}


static const per_sequence_t CellIdList_sequence_of[1] = {
  { &hf_ranap_CellIdList_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ranap_Cell_Id },
};

static int
dissect_ranap_CellIdList(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_ranap_CellIdList, CellIdList_sequence_of,
                                                  1, maxNrOfCellIds, FALSE);

  return offset;
}


static const per_sequence_t CellBased_sequence[] = {
  { &hf_ranap_cellIdList    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ranap_CellIdList },
  { &hf_ranap_iE_Extensions , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ranap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_ranap_CellBased(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ranap_CellBased, CellBased_sequence);

  return offset;
}



static int
dissect_ranap_Cell_Capacity_Class_Value(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            1U, 100U, NULL, TRUE);

  return offset;
}



static int
dissect_ranap_LoadValue(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 100U, NULL, FALSE);

  return offset;
}



static int
dissect_ranap_RTLoadValue(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 100U, NULL, FALSE);

  return offset;
}



static int
dissect_ranap_NRTLoadInformationValue(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 3U, NULL, FALSE);

  return offset;
}


static const per_sequence_t CellLoadInformation_sequence[] = {
  { &hf_ranap_cell_Capacity_Class_Value, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ranap_Cell_Capacity_Class_Value },
  { &hf_ranap_loadValue     , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ranap_LoadValue },
  { &hf_ranap_rTLoadValue   , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ranap_RTLoadValue },
  { &hf_ranap_nRTLoadInformationValue, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ranap_NRTLoadInformationValue },
  { &hf_ranap_iE_Extensions , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ranap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_ranap_CellLoadInformation(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ranap_CellLoadInformation, CellLoadInformation_sequence);

  return offset;
}



static int
dissect_ranap_TargetCellId(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 268435455U, NULL, FALSE);

  return offset;
}


static const per_sequence_t SourceUTRANCellID_sequence[] = {
  { &hf_ranap_pLMNidentity  , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ranap_PLMNidentity },
  { &hf_ranap_uTRANcellID   , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ranap_TargetCellId },
  { &hf_ranap_iE_Extensions , ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_ranap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_ranap_SourceUTRANCellID(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ranap_SourceUTRANCellID, SourceUTRANCellID_sequence);

  return offset;
}



static int
dissect_ranap_CI(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_octet_string(tvb, offset, actx, tree, hf_index,
                                       2, 2, FALSE, NULL);

  return offset;
}


static const per_sequence_t CGI_sequence[] = {
  { &hf_ranap_pLMNidentity  , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ranap_PLMNidentity },
  { &hf_ranap_lAC           , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ranap_LAC },
  { &hf_ranap_cI            , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ranap_CI },
  { &hf_ranap_iE_Extensions , ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_ranap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_ranap_CGI(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ranap_CGI, CGI_sequence);

  return offset;
}


static const value_string ranap_SourceCellID_vals[] = {
  {   0, "sourceUTRANCellID" },
  {   1, "sourceGERANCellID" },
  { 0, NULL }
};

static const per_choice_t SourceCellID_choice[] = {
  {   0, &hf_ranap_sourceUTRANCellID, ASN1_EXTENSION_ROOT    , dissect_ranap_SourceUTRANCellID },
  {   1, &hf_ranap_sourceGERANCellID, ASN1_EXTENSION_ROOT    , dissect_ranap_CGI },
  { 0, NULL, 0, NULL }
};

static int
dissect_ranap_SourceCellID(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_ranap_SourceCellID, SourceCellID_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t CellLoadInformationGroup_sequence[] = {
  { &hf_ranap_sourceCellID  , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ranap_SourceCellID },
  { &hf_ranap_uplinkCellLoadInformation, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ranap_CellLoadInformation },
  { &hf_ranap_downlinkCellLoadInformation, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ranap_CellLoadInformation },
  { &hf_ranap_iE_Extensions , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ranap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_ranap_CellLoadInformationGroup(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ranap_CellLoadInformationGroup, CellLoadInformationGroup_sequence);

  return offset;
}


static const value_string ranap_ClientType_vals[] = {
  {   0, "emergency-Services" },
  {   1, "value-Added-Services" },
  {   2, "pLMN-Operator-Services" },
  {   3, "lawful-Intercept-Services" },
  {   4, "pLMN-Operator-Broadcast-Services" },
  {   5, "pLMN-Operator-O-et-M" },
  {   6, "pLMN-Operator-Anonymous-Statistics" },
  {   7, "pLMN-Operator-Target-MS-Service-Support" },
  { 0, NULL }
};


static int
dissect_ranap_ClientType(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     8, NULL, TRUE, 0, NULL);

  return offset;
}



static int
dissect_ranap_RepetitionNumber0(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 255U, NULL, FALSE);

  return offset;
}


static const per_sequence_t CriticalityDiagnostics_IE_List_item_sequence[] = {
  { &hf_ranap_iECriticality , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ranap_Criticality },
  { &hf_ranap_iE_ID         , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ranap_ProtocolIE_ID },
  { &hf_ranap_repetitionNumber, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ranap_RepetitionNumber0 },
  { &hf_ranap_iE_Extensions , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ranap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_ranap_CriticalityDiagnostics_IE_List_item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ranap_CriticalityDiagnostics_IE_List_item, CriticalityDiagnostics_IE_List_item_sequence);

  return offset;
}


static const per_sequence_t CriticalityDiagnostics_IE_List_sequence_of[1] = {
  { &hf_ranap_CriticalityDiagnostics_IE_List_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ranap_CriticalityDiagnostics_IE_List_item },
};

static int
dissect_ranap_CriticalityDiagnostics_IE_List(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_ranap_CriticalityDiagnostics_IE_List, CriticalityDiagnostics_IE_List_sequence_of,
                                                  1, maxNrOfErrors, FALSE);

  return offset;
}


static const per_sequence_t CriticalityDiagnostics_sequence[] = {
  { &hf_ranap_procedureCode , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ranap_ProcedureCode },
  { &hf_ranap_triggeringMessage, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ranap_TriggeringMessage },
  { &hf_ranap_procedureCriticality, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ranap_Criticality },
  { &hf_ranap_iEsCriticalityDiagnostics, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ranap_CriticalityDiagnostics_IE_List },
  { &hf_ranap_iE_Extensions , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ranap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_ranap_CriticalityDiagnostics(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ranap_CriticalityDiagnostics, CriticalityDiagnostics_sequence);

  return offset;
}



static int
dissect_ranap_RepetitionNumber1(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            1U, 256U, NULL, FALSE);

  return offset;
}


static const per_sequence_t MessageStructure_item_sequence[] = {
  { &hf_ranap_iE_ID         , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ranap_ProtocolIE_ID },
  { &hf_ranap_item_repetitionNumber, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ranap_RepetitionNumber1 },
  { &hf_ranap_iE_Extensions , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ranap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_ranap_MessageStructure_item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ranap_MessageStructure_item, MessageStructure_item_sequence);

  return offset;
}


static const per_sequence_t MessageStructure_sequence_of[1] = {
  { &hf_ranap_MessageStructure_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ranap_MessageStructure_item },
};

static int
dissect_ranap_MessageStructure(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_ranap_MessageStructure, MessageStructure_sequence_of,
                                                  1, maxNrOfLevels, FALSE);

  return offset;
}


static const value_string ranap_EncryptionAlgorithm_vals[] = {
  {   0, "no-encryption" },
  {   1, "standard-UMTS-encryption-algorith-UEA1" },
  {   2, "standard-UMTS-encryption-algorithm-UEA2" },
  { 0, NULL }
};


static int
dissect_ranap_EncryptionAlgorithm(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 15U, NULL, FALSE);

  return offset;
}



static int
dissect_ranap_ChosenEncryptionAlgorithm(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ranap_EncryptionAlgorithm(tvb, offset, actx, tree, hf_index);

  return offset;
}


static const value_string ranap_IntegrityProtectionAlgorithm_vals[] = {
  {   0, "standard-UMTS-integrity-algorithm-UIA1" },
  {   1, "standard-UMTS-integrity-algorithm-UIA2" },
  {  15, "no-value" },
  { 0, NULL }
};


static int
dissect_ranap_IntegrityProtectionAlgorithm(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 15U, NULL, FALSE);

  return offset;
}



static int
dissect_ranap_ChosenIntegrityProtectionAlgorithm(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ranap_IntegrityProtectionAlgorithm(tvb, offset, actx, tree, hf_index);

  return offset;
}



static int
dissect_ranap_ClassmarkInformation2(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_octet_string(tvb, offset, actx, tree, hf_index,
                                       NO_BOUND, NO_BOUND, FALSE, NULL);

  return offset;
}



static int
dissect_ranap_ClassmarkInformation3(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_octet_string(tvb, offset, actx, tree, hf_index,
                                       NO_BOUND, NO_BOUND, FALSE, NULL);

  return offset;
}


static const value_string ranap_CN_DomainIndicator_vals[] = {
  {   0, "cs-domain" },
  {   1, "ps-domain" },
  { 0, NULL }
};


static int
dissect_ranap_CN_DomainIndicator(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     2, NULL, FALSE, 0, NULL);

  return offset;
}



static int
dissect_ranap_CN_ID(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 4095U, NULL, FALSE);

  return offset;
}



static int
dissect_ranap_Correlation_ID(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_octet_string(tvb, offset, actx, tree, hf_index,
                                       4, 4, FALSE, NULL);

  return offset;
}


static const value_string ranap_CSFB_Information_vals[] = {
  {   0, "csfb" },
  {   1, "csfb-high-priority" },
  { 0, NULL }
};


static int
dissect_ranap_CSFB_Information(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     2, NULL, TRUE, 0, NULL);

  return offset;
}



static int
dissect_ranap_CSG_Id(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_bit_string(tvb, offset, actx, tree, hf_index,
                                     27, 27, FALSE, NULL);

  return offset;
}


static const per_sequence_t CSG_Id_List_sequence_of[1] = {
  { &hf_ranap_CSG_Id_List_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ranap_CSG_Id },
};

static int
dissect_ranap_CSG_Id_List(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_ranap_CSG_Id_List, CSG_Id_List_sequence_of,
                                                  1, maxNrOfCSGs, FALSE);

  return offset;
}


static const value_string ranap_CSG_Membership_Status_vals[] = {
  {   0, "member" },
  {   1, "non-member" },
  { 0, NULL }
};


static int
dissect_ranap_CSG_Membership_Status(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     2, NULL, TRUE, 0, NULL);

  return offset;
}


static const value_string ranap_DataPDUType_vals[] = {
  {   0, "pDUtype0" },
  {   1, "pDUtype1" },
  { 0, NULL }
};


static int
dissect_ranap_DataPDUType(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     2, NULL, TRUE, 0, NULL);

  return offset;
}



static int
dissect_ranap_DataVolumeReference(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 255U, NULL, FALSE);

  return offset;
}


static const value_string ranap_DataVolumeReportingIndication_vals[] = {
  {   0, "do-report" },
  {   1, "do-not-report" },
  { 0, NULL }
};


static int
dissect_ranap_DataVolumeReportingIndication(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     2, NULL, FALSE, 0, NULL);

  return offset;
}



static int
dissect_ranap_DCH_ID(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 255U, NULL, FALSE);

  return offset;
}


static const value_string ranap_DeliveryOfErroneousSDU_vals[] = {
  {   0, "yes" },
  {   1, "no" },
  {   2, "no-error-detection-consideration" },
  { 0, NULL }
};


static int
dissect_ranap_DeliveryOfErroneousSDU(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     3, NULL, FALSE, 0, NULL);

  return offset;
}


static const value_string ranap_DeliveryOrder_vals[] = {
  {   0, "delivery-order-requested" },
  {   1, "delivery-order-not-requested" },
  { 0, NULL }
};


static int
dissect_ranap_DeliveryOrder(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     2, NULL, FALSE, 0, NULL);

  return offset;
}



static int
dissect_ranap_RAC(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_octet_string(tvb, offset, actx, tree, hf_index,
                                       1, 1, FALSE, NULL);

  return offset;
}


static const per_sequence_t NewRAListofIdleModeUEs_sequence_of[1] = {
  { &hf_ranap_NewRAListofIdleModeUEs_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ranap_RAC },
};

static int
dissect_ranap_NewRAListofIdleModeUEs(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_ranap_NewRAListofIdleModeUEs, NewRAListofIdleModeUEs_sequence_of,
                                                  1, maxMBMSRA, FALSE);

  return offset;
}


static const per_sequence_t RAListwithNoIdleModeUEsAnyMore_sequence_of[1] = {
  { &hf_ranap_RAListwithNoIdleModeUEsAnyMore_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ranap_RAC },
};

static int
dissect_ranap_RAListwithNoIdleModeUEsAnyMore(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_ranap_RAListwithNoIdleModeUEsAnyMore, RAListwithNoIdleModeUEsAnyMore_sequence_of,
                                                  1, maxMBMSRA, FALSE);

  return offset;
}


static const per_sequence_t DeltaRAListofIdleModeUEs_sequence[] = {
  { &hf_ranap_newRAListofIdleModeUEs, ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_ranap_NewRAListofIdleModeUEs },
  { &hf_ranap_rAListwithNoIdleModeUEsAnyMore, ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_ranap_RAListwithNoIdleModeUEsAnyMore },
  { &hf_ranap_iE_Extensions , ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_ranap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_ranap_DeltaRAListofIdleModeUEs(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ranap_DeltaRAListofIdleModeUEs, DeltaRAListofIdleModeUEs_sequence);

  return offset;
}



static int
dissect_ranap_DL_GTP_PDU_SequenceNumber(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 65535U, NULL, FALSE);

  return offset;
}



static int
dissect_ranap_DL_N_PDU_SequenceNumber(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 65535U, NULL, FALSE);

  return offset;
}



static int
dissect_ranap_D_RNTI(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 1048575U, NULL, FALSE);

  return offset;
}



static int
dissect_ranap_DRX_CycleLengthCoefficient(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            6U, 9U, NULL, FALSE);

  return offset;
}



static int
dissect_ranap_DSCH_ID(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 255U, NULL, FALSE);

  return offset;
}



static int
dissect_ranap_E_DCH_MAC_d_Flow_ID(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, maxNrOfEDCHMACdFlows_1, NULL, FALSE);

  return offset;
}



static int
dissect_ranap_BIT_STRING_SIZE_20(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_bit_string(tvb, offset, actx, tree, hf_index,
                                     20, 20, FALSE, NULL);

  return offset;
}



static int
dissect_ranap_BIT_STRING_SIZE_28(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_bit_string(tvb, offset, actx, tree, hf_index,
                                     28, 28, FALSE, NULL);

  return offset;
}


static const value_string ranap_ENB_ID_vals[] = {
  {   0, "macroENB-ID" },
  {   1, "homeENB-ID" },
  { 0, NULL }
};

static const per_choice_t ENB_ID_choice[] = {
  {   0, &hf_ranap_macroENB_ID   , ASN1_EXTENSION_ROOT    , dissect_ranap_BIT_STRING_SIZE_20 },
  {   1, &hf_ranap_homeENB_ID    , ASN1_EXTENSION_ROOT    , dissect_ranap_BIT_STRING_SIZE_28 },
  { 0, NULL, 0, NULL }
};

static int
dissect_ranap_ENB_ID(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_ranap_ENB_ID, ENB_ID_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t PermittedEncryptionAlgorithms_sequence_of[1] = {
  { &hf_ranap_PermittedEncryptionAlgorithms_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ranap_EncryptionAlgorithm },
};

static int
dissect_ranap_PermittedEncryptionAlgorithms(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_ranap_PermittedEncryptionAlgorithms, PermittedEncryptionAlgorithms_sequence_of,
                                                  1, 16, FALSE);

  return offset;
}



static int
dissect_ranap_EncryptionKey(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_bit_string(tvb, offset, actx, tree, hf_index,
                                     128, 128, FALSE, NULL);

  return offset;
}


static const per_sequence_t EncryptionInformation_sequence[] = {
  { &hf_ranap_permittedAlgorithms, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ranap_PermittedEncryptionAlgorithms },
  { &hf_ranap_key           , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ranap_EncryptionKey },
  { &hf_ranap_iE_Extensions , ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_ranap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

int
dissect_ranap_EncryptionInformation(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ranap_EncryptionInformation, EncryptionInformation_sequence);

  return offset;
}



static int
dissect_ranap_IMEI(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_octet_string(tvb, offset, actx, tree, hf_index,
                                       8, 8, FALSE, NULL);

  return offset;
}


static const per_sequence_t IMEIList_sequence_of[1] = {
  { &hf_ranap_IMEIList_item , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ranap_IMEI },
};

static int
dissect_ranap_IMEIList(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_ranap_IMEIList, IMEIList_sequence_of,
                                                  1, maxNrOfUEsToBeTraced, FALSE);

  return offset;
}



static int
dissect_ranap_IMEISV(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_octet_string(tvb, offset, actx, tree, hf_index,
                                       8, 8, FALSE, NULL);

  return offset;
}


static const per_sequence_t IMEISVList_sequence_of[1] = {
  { &hf_ranap_IMEISVList_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ranap_IMEISV },
};

static int
dissect_ranap_IMEISVList(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_ranap_IMEISVList, IMEISVList_sequence_of,
                                                  1, maxNrOfUEsToBeTraced, FALSE);

  return offset;
}



static int
dissect_ranap_BIT_STRING_SIZE_7(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_bit_string(tvb, offset, actx, tree, hf_index,
                                     7, 7, FALSE, NULL);

  return offset;
}


static const per_sequence_t IMEIGroup_sequence[] = {
  { &hf_ranap_iMEI          , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ranap_IMEI },
  { &hf_ranap_iMEIMask      , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ranap_BIT_STRING_SIZE_7 },
  { &hf_ranap_iE_Extensions , ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_ranap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_ranap_IMEIGroup(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ranap_IMEIGroup, IMEIGroup_sequence);

  return offset;
}


static const per_sequence_t IMEISVGroup_sequence[] = {
  { &hf_ranap_iMEISV        , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ranap_IMEISV },
  { &hf_ranap_iMEISVMask    , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ranap_BIT_STRING_SIZE_7 },
  { &hf_ranap_iE_Extensions , ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_ranap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_ranap_IMEISVGroup(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ranap_IMEISVGroup, IMEISVGroup_sequence);

  return offset;
}


static const value_string ranap_EquipmentsToBeTraced_vals[] = {
  {   0, "iMEIlist" },
  {   1, "iMEISVlist" },
  {   2, "iMEIgroup" },
  {   3, "iMEISVgroup" },
  { 0, NULL }
};

static const per_choice_t EquipmentsToBeTraced_choice[] = {
  {   0, &hf_ranap_iMEIlist      , ASN1_EXTENSION_ROOT    , dissect_ranap_IMEIList },
  {   1, &hf_ranap_iMEISVlist    , ASN1_EXTENSION_ROOT    , dissect_ranap_IMEISVList },
  {   2, &hf_ranap_iMEIgroup     , ASN1_EXTENSION_ROOT    , dissect_ranap_IMEIGroup },
  {   3, &hf_ranap_iMEISVgroup   , ASN1_EXTENSION_ROOT    , dissect_ranap_IMEISVGroup },
  { 0, NULL, 0, NULL }
};

static int
dissect_ranap_EquipmentsToBeTraced(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_ranap_EquipmentsToBeTraced, EquipmentsToBeTraced_choice,
                                 NULL);

  return offset;
}


static const value_string ranap_E_UTRAN_Service_Handover_vals[] = {
  {   0, "handover-to-E-UTRAN-shall-not-be-performed" },
  { 0, NULL }
};


static int
dissect_ranap_E_UTRAN_Service_Handover(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     1, NULL, TRUE, 0, NULL);

  return offset;
}


static const value_string ranap_Event_vals[] = {
  {   0, "stop-change-of-service-area" },
  {   1, "direct" },
  {   2, "change-of-servicearea" },
  {   3, "stop-direct" },
  {   4, "periodic" },
  {   5, "stop-periodic" },
  { 0, NULL }
};


static int
dissect_ranap_Event(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     3, NULL, TRUE, 3, NULL);

  return offset;
}


static const value_string ranap_MeasurementQuantity_vals[] = {
  {   0, "cpichEcNo" },
  {   1, "cpichRSCP" },
  {   2, "pathloss" },
  { 0, NULL }
};


static int
dissect_ranap_MeasurementQuantity(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     3, NULL, TRUE, 0, NULL);

  return offset;
}



static int
dissect_ranap_INTEGER_M120_165(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            -120, 165U, NULL, FALSE);

  return offset;
}


static const per_sequence_t Event1F_Parameters_sequence[] = {
  { &hf_ranap_measurementQuantity, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ranap_MeasurementQuantity },
  { &hf_ranap_threshold     , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ranap_INTEGER_M120_165 },
  { NULL, 0, 0, NULL }
};

static int
dissect_ranap_Event1F_Parameters(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ranap_Event1F_Parameters, Event1F_Parameters_sequence);

  return offset;
}



static int
dissect_ranap_INTEGER_M120_M25(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            -120, -25, NULL, FALSE);

  return offset;
}


static const per_sequence_t Event1I_Parameters_sequence[] = {
  { &hf_ranap_threshold_01  , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ranap_INTEGER_M120_M25 },
  { NULL, 0, 0, NULL }
};

static int
dissect_ranap_Event1I_Parameters(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ranap_Event1I_Parameters, Event1I_Parameters_sequence);

  return offset;
}



static int
dissect_ranap_ExtendedRNC_ID(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            4096U, 65535U, NULL, FALSE);

  return offset;
}



static int
dissect_ranap_FrameSequenceNumber(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 15U, NULL, FALSE);

  return offset;
}


static const value_string ranap_FrequenceLayerConvergenceFlag_vals[] = {
  {   0, "no-FLC-flag" },
  { 0, NULL }
};


static int
dissect_ranap_FrequenceLayerConvergenceFlag(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     1, NULL, TRUE, 0, NULL);

  return offset;
}



static int
dissect_ranap_GANSS_PositioningMethodAndUsage(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_octet_string(tvb, offset, actx, tree, hf_index,
                                       1, 1, FALSE, NULL);

  return offset;
}


static const per_sequence_t GANSS_PositioningDataSet_sequence_of[1] = {
  { &hf_ranap_GANSS_PositioningDataSet_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ranap_GANSS_PositioningMethodAndUsage },
};

static int
dissect_ranap_GANSS_PositioningDataSet(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_ranap_GANSS_PositioningDataSet, GANSS_PositioningDataSet_sequence_of,
                                                  1, maxGANSSSet, FALSE);

  return offset;
}



static int
dissect_ranap_GERAN_BSC_Container(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_octet_string(tvb, offset, actx, tree, hf_index,
                                       NO_BOUND, NO_BOUND, FALSE, NULL);

  return offset;
}


static const per_sequence_t LAI_sequence[] = {
  { &hf_ranap_pLMNidentity  , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ranap_PLMNidentity },
  { &hf_ranap_lAC           , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ranap_LAC },
  { &hf_ranap_iE_Extensions , ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_ranap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_ranap_LAI(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ranap_LAI, LAI_sequence);

  return offset;
}


static const per_sequence_t GERAN_Cell_ID_sequence[] = {
  { &hf_ranap_lAI           , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ranap_LAI },
  { &hf_ranap_rAC           , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ranap_RAC },
  { &hf_ranap_cI            , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ranap_CI },
  { &hf_ranap_iE_Extensions , ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_ranap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_ranap_GERAN_Cell_ID(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ranap_GERAN_Cell_ID, GERAN_Cell_ID_sequence);

  return offset;
}



static int
dissect_ranap_GERAN_Classmark(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_octet_string(tvb, offset, actx, tree, hf_index,
                                       NO_BOUND, NO_BOUND, FALSE, NULL);

  return offset;
}


static const per_sequence_t GlobalCN_ID_sequence[] = {
  { &hf_ranap_pLMNidentity  , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ranap_PLMNidentity },
  { &hf_ranap_cN_ID         , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ranap_CN_ID },
  { NULL, 0, 0, NULL }
};

static int
dissect_ranap_GlobalCN_ID(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ranap_GlobalCN_ID, GlobalCN_ID_sequence);

  return offset;
}



static int
dissect_ranap_RNC_ID(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 4095U, NULL, FALSE);

  return offset;
}


static const per_sequence_t GlobalRNC_ID_sequence[] = {
  { &hf_ranap_pLMNidentity  , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ranap_PLMNidentity },
  { &hf_ranap_rNC_ID        , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ranap_RNC_ID },
  { NULL, 0, 0, NULL }
};

static int
dissect_ranap_GlobalRNC_ID(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ranap_GlobalRNC_ID, GlobalRNC_ID_sequence);

  return offset;
}



static int
dissect_ranap_GTP_TEI(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 329 "../../asn1/ranap/ranap.cnf"
  tvbuff_t *parameter_tvb=NULL;	
  int saved_hf;
  
  saved_hf = hf_index;
  hf_index = -1;
  offset = dissect_per_octet_string(tvb, offset, actx, tree, hf_index,
                                       4, 4, FALSE, &parameter_tvb);


  if (!parameter_tvb)
    return offset;
  proto_tree_add_item(tree, saved_hf, parameter_tvb, 0, 4, FALSE);  



  return offset;
}



static int
dissect_ranap_HS_DSCH_MAC_d_Flow_ID(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, maxNrOfHSDSCHMACdFlows_1, NULL, FALSE);

  return offset;
}



static int
dissect_ranap_MeasurementsToActivate(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_bit_string(tvb, offset, actx, tree, hf_index,
                                     8, 8, FALSE, NULL);

  return offset;
}


static const value_string ranap_ReportInterval_vals[] = {
  {   0, "ms250" },
  {   1, "ms500" },
  {   2, "ms1000" },
  {   3, "ms2000" },
  {   4, "ms3000" },
  {   5, "ms4000" },
  {   6, "ms6000" },
  {   7, "ms12000" },
  {   8, "ms16000" },
  {   9, "ms20000" },
  {  10, "ms24000" },
  {  11, "ms32000" },
  {  12, "ms64000" },
  { 0, NULL }
};


static int
dissect_ranap_ReportInterval(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     13, NULL, TRUE, 0, NULL);

  return offset;
}


static const value_string ranap_ReportAmount_vals[] = {
  {   0, "n1" },
  {   1, "n2" },
  {   2, "n4" },
  {   3, "n8" },
  {   4, "n16" },
  {   5, "n32" },
  {   6, "n64" },
  {   7, "infinity" },
  { 0, NULL }
};


static int
dissect_ranap_ReportAmount(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     8, NULL, TRUE, 0, NULL);

  return offset;
}


static const per_sequence_t MDT_Report_Parameters_sequence[] = {
  { &hf_ranap_reportInterval, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ranap_ReportInterval },
  { &hf_ranap_reportAmount  , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ranap_ReportAmount },
  { NULL, 0, 0, NULL }
};

static int
dissect_ranap_MDT_Report_Parameters(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ranap_MDT_Report_Parameters, MDT_Report_Parameters_sequence);

  return offset;
}


static const value_string ranap_M1Report_vals[] = {
  {   0, "periodic" },
  {   1, "event1F" },
  { 0, NULL }
};

static const per_choice_t M1Report_choice[] = {
  {   0, &hf_ranap_periodic      , ASN1_EXTENSION_ROOT    , dissect_ranap_MDT_Report_Parameters },
  {   1, &hf_ranap_event1F       , ASN1_EXTENSION_ROOT    , dissect_ranap_Event1F_Parameters },
  { 0, NULL, 0, NULL }
};

static int
dissect_ranap_M1Report(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_ranap_M1Report, M1Report_choice,
                                 NULL);

  return offset;
}


static const value_string ranap_M2Report_vals[] = {
  {   0, "periodic" },
  {   1, "event1I" },
  { 0, NULL }
};

static const per_choice_t M2Report_choice[] = {
  {   0, &hf_ranap_periodic      , ASN1_EXTENSION_ROOT    , dissect_ranap_MDT_Report_Parameters },
  {   1, &hf_ranap_event1I       , ASN1_EXTENSION_ROOT    , dissect_ranap_Event1I_Parameters },
  { 0, NULL, 0, NULL }
};

static int
dissect_ranap_M2Report(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_ranap_M2Report, M2Report_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t ImmediateMDT_sequence[] = {
  { &hf_ranap_measurementsToActivate, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ranap_MeasurementsToActivate },
  { &hf_ranap_m1report      , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ranap_M1Report },
  { &hf_ranap_m2report      , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ranap_M2Report },
  { NULL, 0, 0, NULL }
};

static int
dissect_ranap_ImmediateMDT(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ranap_ImmediateMDT, ImmediateMDT_sequence);

  return offset;
}



static int
dissect_ranap_IMSI(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 188 "../../asn1/ranap/ranap.cnf"
  tvbuff_t* imsi_tvb;
  const char	*digit_str;

  offset = dissect_per_octet_string(tvb, offset, actx, tree, hf_index,
                                       3, 8, FALSE, &imsi_tvb);
  
	if(!imsi_tvb)
		return offset;
	if ( actx->pinfo->sccp_info
		 && actx->pinfo->sccp_info->data.co.assoc
		 && ! actx->pinfo->sccp_info->data.co.assoc->calling_party ) {
	   
		guint len = tvb_length(imsi_tvb);
		guint8* bytes = ep_tvb_memdup(imsi_tvb,0,len);

		actx->pinfo->sccp_info->data.co.assoc->calling_party = 
			se_strdup_printf("IMSI: %s", bytes_to_str(bytes, len) );
	}
	digit_str = unpack_digits(imsi_tvb, 0);
	proto_tree_add_string(tree, hf_ranap_imsi_digits, imsi_tvb, 0, -1, digit_str);


  return offset;
}


static const value_string ranap_IncludeVelocity_vals[] = {
  {   0, "requested" },
  { 0, NULL }
};


static int
dissect_ranap_IncludeVelocity(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     1, NULL, FALSE, 0, NULL);

  return offset;
}



static int
dissect_ranap_InformationExchangeID(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 1048575U, NULL, FALSE);

  return offset;
}


static const value_string ranap_InformationExchangeType_vals[] = {
  {   0, "transfer" },
  {   1, "request" },
  { 0, NULL }
};


static int
dissect_ranap_InformationExchangeType(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     2, NULL, TRUE, 0, NULL);

  return offset;
}



static int
dissect_ranap_OCTET_STRING_SIZE_3(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_octet_string(tvb, offset, actx, tree, hf_index,
                                       3, 3, FALSE, NULL);

  return offset;
}


static const per_sequence_t TMGI_sequence[] = {
  { &hf_ranap_pLMNidentity  , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ranap_PLMNidentity },
  { &hf_ranap_serviceID     , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ranap_OCTET_STRING_SIZE_3 },
  { &hf_ranap_iE_Extensions , ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_ranap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_ranap_TMGI(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ranap_TMGI, TMGI_sequence);

  return offset;
}



static int
dissect_ranap_IPMulticastAddress(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_octet_string(tvb, offset, actx, tree, hf_index,
                                       4, 16, FALSE, NULL);

  return offset;
}


static const per_sequence_t MBMSIPMulticastAddressandAPNlist_sequence[] = {
  { &hf_ranap_tMGI          , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ranap_TMGI },
  { &hf_ranap_iPMulticastAddress, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ranap_IPMulticastAddress },
  { &hf_ranap_aPN           , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ranap_APN },
  { &hf_ranap_iE_Extensions , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ranap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_ranap_MBMSIPMulticastAddressandAPNlist(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ranap_MBMSIPMulticastAddressandAPNlist, MBMSIPMulticastAddressandAPNlist_sequence);

  return offset;
}


static const per_sequence_t RequestedMBMSIPMulticastAddressandAPNRequest_sequence_of[1] = {
  { &hf_ranap_RequestedMBMSIPMulticastAddressandAPNRequest_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ranap_MBMSIPMulticastAddressandAPNlist },
};

static int
dissect_ranap_RequestedMBMSIPMulticastAddressandAPNRequest(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_ranap_RequestedMBMSIPMulticastAddressandAPNRequest, RequestedMBMSIPMulticastAddressandAPNRequest_sequence_of,
                                                  1, maxnoofMulticastServicesPerRNC, FALSE);

  return offset;
}


static const per_sequence_t RequestedMulticastServiceList_sequence_of[1] = {
  { &hf_ranap_RequestedMulticastServiceList_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ranap_TMGI },
};

static int
dissect_ranap_RequestedMulticastServiceList(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_ranap_RequestedMulticastServiceList, RequestedMulticastServiceList_sequence_of,
                                                  1, maxnoofMulticastServicesPerUE, FALSE);

  return offset;
}


static const value_string ranap_InformationRequested_vals[] = {
  {   0, "requestedMBMSIPMulticastAddressandAPNRequest" },
  {   1, "requestedMulticastServiceList" },
  { 0, NULL }
};

static const per_choice_t InformationRequested_choice[] = {
  {   0, &hf_ranap_requestedMBMSIPMulticastAddressandAPNRequest, ASN1_EXTENSION_ROOT    , dissect_ranap_RequestedMBMSIPMulticastAddressandAPNRequest },
  {   1, &hf_ranap_requestedMulticastServiceList, ASN1_EXTENSION_ROOT    , dissect_ranap_RequestedMulticastServiceList },
  { 0, NULL, 0, NULL }
};

static int
dissect_ranap_InformationRequested(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_ranap_InformationRequested, InformationRequested_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t MBMSIPMulticastAddressandAPNRequest_sequence_of[1] = {
  { &hf_ranap_MBMSIPMulticastAddressandAPNRequest_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ranap_TMGI },
};

static int
dissect_ranap_MBMSIPMulticastAddressandAPNRequest(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_ranap_MBMSIPMulticastAddressandAPNRequest, MBMSIPMulticastAddressandAPNRequest_sequence_of,
                                                  1, maxnoofMulticastServicesPerRNC, FALSE);

  return offset;
}


static const value_string ranap_PermanentNAS_UE_ID_vals[] = {
  {   0, "iMSI" },
  { 0, NULL }
};

static const per_choice_t PermanentNAS_UE_ID_choice[] = {
  {   0, &hf_ranap_iMSI          , ASN1_EXTENSION_ROOT    , dissect_ranap_IMSI },
  { 0, NULL, 0, NULL }
};

static int
dissect_ranap_PermanentNAS_UE_ID(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_ranap_PermanentNAS_UE_ID, PermanentNAS_UE_ID_choice,
                                 NULL);

  return offset;
}


static const value_string ranap_InformationRequestType_vals[] = {
  {   0, "mBMSIPMulticastAddressandAPNRequest" },
  {   1, "permanentNAS-UE-ID" },
  { 0, NULL }
};

static const per_choice_t InformationRequestType_choice[] = {
  {   0, &hf_ranap_mBMSIPMulticastAddressandAPNRequest, ASN1_EXTENSION_ROOT    , dissect_ranap_MBMSIPMulticastAddressandAPNRequest },
  {   1, &hf_ranap_permanentNAS_UE_ID, ASN1_EXTENSION_ROOT    , dissect_ranap_PermanentNAS_UE_ID },
  { 0, NULL, 0, NULL }
};

static int
dissect_ranap_InformationRequestType(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_ranap_InformationRequestType, InformationRequestType_choice,
                                 NULL);

  return offset;
}



static int
dissect_ranap_InformationTransferID(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 1048575U, NULL, FALSE);

  return offset;
}



static int
dissect_ranap_TraceReference(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_octet_string(tvb, offset, actx, tree, hf_index,
                                       2, 3, FALSE, NULL);

  return offset;
}


static const value_string ranap_T_traceActivationIndicator_vals[] = {
  {   0, "activated" },
  {   1, "deactivated" },
  { 0, NULL }
};


static int
dissect_ranap_T_traceActivationIndicator(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     2, NULL, FALSE, 0, NULL);

  return offset;
}


static const per_sequence_t RNCTraceInformation_sequence[] = {
  { &hf_ranap_traceReference, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ranap_TraceReference },
  { &hf_ranap_traceActivationIndicator, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ranap_T_traceActivationIndicator },
  { &hf_ranap_equipmentsToBeTraced, ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_ranap_EquipmentsToBeTraced },
  { &hf_ranap_iE_Extensions , ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_ranap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_ranap_RNCTraceInformation(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ranap_RNCTraceInformation, RNCTraceInformation_sequence);

  return offset;
}


static const value_string ranap_InformationTransferType_vals[] = {
  {   0, "rNCTraceInformation" },
  { 0, NULL }
};

static const per_choice_t InformationTransferType_choice[] = {
  {   0, &hf_ranap_rNCTraceInformation, ASN1_EXTENSION_ROOT    , dissect_ranap_RNCTraceInformation },
  { 0, NULL, 0, NULL }
};

static int
dissect_ranap_InformationTransferType(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_ranap_InformationTransferType, InformationTransferType_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t PermittedIntegrityProtectionAlgorithms_sequence_of[1] = {
  { &hf_ranap_PermittedIntegrityProtectionAlgorithms_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ranap_IntegrityProtectionAlgorithm },
};

static int
dissect_ranap_PermittedIntegrityProtectionAlgorithms(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_ranap_PermittedIntegrityProtectionAlgorithms, PermittedIntegrityProtectionAlgorithms_sequence_of,
                                                  1, 16, FALSE);

  return offset;
}



static int
dissect_ranap_IntegrityProtectionKey(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_bit_string(tvb, offset, actx, tree, hf_index,
                                     128, 128, FALSE, NULL);

  return offset;
}


static const per_sequence_t IntegrityProtectionInformation_sequence[] = {
  { &hf_ranap_permittedAlgorithms_01, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ranap_PermittedIntegrityProtectionAlgorithms },
  { &hf_ranap_key_01        , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ranap_IntegrityProtectionKey },
  { &hf_ranap_iE_Extensions , ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_ranap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

int
dissect_ranap_IntegrityProtectionInformation(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ranap_IntegrityProtectionInformation, IntegrityProtectionInformation_sequence);

  return offset;
}



static int
dissect_ranap_RIMInformation(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_octet_string(tvb, offset, actx, tree, hf_index,
                                       NO_BOUND, NO_BOUND, FALSE, NULL);

  return offset;
}


static const per_sequence_t TargetRNC_ID_sequence[] = {
  { &hf_ranap_lAI           , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ranap_LAI },
  { &hf_ranap_rAC           , ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_ranap_RAC },
  { &hf_ranap_rNC_ID        , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ranap_RNC_ID },
  { &hf_ranap_iE_Extensions , ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_ranap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

int
dissect_ranap_TargetRNC_ID(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ranap_TargetRNC_ID, TargetRNC_ID_sequence);

  return offset;
}



static int
dissect_ranap_TAC(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_octet_string(tvb, offset, actx, tree, hf_index,
                                       2, 2, FALSE, NULL);

  return offset;
}


static const per_sequence_t TAI_sequence[] = {
  { &hf_ranap_pLMNidentity  , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ranap_PLMNidentity },
  { &hf_ranap_tAC           , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ranap_TAC },
  { &hf_ranap_iE_Extensions , ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_ranap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_ranap_TAI(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ranap_TAI, TAI_sequence);

  return offset;
}


static const per_sequence_t TargetENB_ID_sequence[] = {
  { &hf_ranap_pLMNidentity  , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ranap_PLMNidentity },
  { &hf_ranap_eNB_ID        , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ranap_ENB_ID },
  { &hf_ranap_iE_Extensions , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ranap_ProtocolExtensionContainer },
  { &hf_ranap_selectedTAI   , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ranap_TAI },
  { NULL, 0, 0, NULL }
};

static int
dissect_ranap_TargetENB_ID(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ranap_TargetENB_ID, TargetENB_ID_sequence);

  return offset;
}


static const value_string ranap_RIMRoutingAddress_vals[] = {
  {   0, "targetRNC-ID" },
  {   1, "gERAN-Cell-ID" },
  {   2, "targeteNB-ID" },
  { 0, NULL }
};

static const per_choice_t RIMRoutingAddress_choice[] = {
  {   0, &hf_ranap_targetRNC_ID  , ASN1_EXTENSION_ROOT    , dissect_ranap_TargetRNC_ID },
  {   1, &hf_ranap_gERAN_Cell_ID , ASN1_EXTENSION_ROOT    , dissect_ranap_GERAN_Cell_ID },
  {   2, &hf_ranap_targeteNB_ID  , ASN1_NOT_EXTENSION_ROOT, dissect_ranap_TargetENB_ID },
  { 0, NULL, 0, NULL }
};

static int
dissect_ranap_RIMRoutingAddress(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_ranap_RIMRoutingAddress, RIMRoutingAddress_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t RIM_Transfer_sequence[] = {
  { &hf_ranap_rIMInformation, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ranap_RIMInformation },
  { &hf_ranap_rIMRoutingAddress, ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_ranap_RIMRoutingAddress },
  { &hf_ranap_iE_Extensions , ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_ranap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_ranap_RIM_Transfer(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ranap_RIM_Transfer, RIM_Transfer_sequence);

  return offset;
}


static const value_string ranap_InterSystemInformationTransferType_vals[] = {
  {   0, "rIM-Transfer" },
  { 0, NULL }
};

static const per_choice_t InterSystemInformationTransferType_choice[] = {
  {   0, &hf_ranap_rIM_Transfer  , ASN1_EXTENSION_ROOT    , dissect_ranap_RIM_Transfer },
  { 0, NULL, 0, NULL }
};

static int
dissect_ranap_InterSystemInformationTransferType(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_ranap_InterSystemInformationTransferType, InterSystemInformationTransferType_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t InterSystemInformation_TransparentContainer_sequence[] = {
  { &hf_ranap_downlinkCellLoadInformation, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ranap_CellLoadInformation },
  { &hf_ranap_uplinkCellLoadInformation, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ranap_CellLoadInformation },
  { &hf_ranap_iE_Extensions , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ranap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_ranap_InterSystemInformation_TransparentContainer(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ranap_InterSystemInformation_TransparentContainer, InterSystemInformation_TransparentContainer_sequence);

  return offset;
}



static int
dissect_ranap_IuSignallingConnectionIdentifier(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_bit_string(tvb, offset, actx, tree, hf_index,
                                     24, 24, FALSE, NULL);

  return offset;
}


static const value_string ranap_IuTransportAssociation_vals[] = {
  {   0, "gTP-TEI" },
  {   1, "bindingID" },
  { 0, NULL }
};

static const per_choice_t IuTransportAssociation_choice[] = {
  {   0, &hf_ranap_gTP_TEI       , ASN1_EXTENSION_ROOT    , dissect_ranap_GTP_TEI },
  {   1, &hf_ranap_bindingID     , ASN1_EXTENSION_ROOT    , dissect_ranap_BindingID },
  { 0, NULL, 0, NULL }
};

static int
dissect_ranap_IuTransportAssociation(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_ranap_IuTransportAssociation, IuTransportAssociation_choice,
                                 NULL);

  return offset;
}


static const value_string ranap_KeyStatus_vals[] = {
  {   0, "old" },
  {   1, "new" },
  { 0, NULL }
};


static int
dissect_ranap_KeyStatus(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     2, NULL, TRUE, 0, NULL);

  return offset;
}


static const per_sequence_t ListOF_SNAs_sequence_of[1] = {
  { &hf_ranap_ListOF_SNAs_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ranap_SNAC },
};

static int
dissect_ranap_ListOF_SNAs(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_ranap_ListOF_SNAs, ListOF_SNAs_sequence_of,
                                                  1, maxNrOfSNAs, FALSE);

  return offset;
}


static const per_sequence_t LA_LIST_item_sequence[] = {
  { &hf_ranap_lAC           , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ranap_LAC },
  { &hf_ranap_listOF_SNAs   , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ranap_ListOF_SNAs },
  { &hf_ranap_iE_Extensions , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ranap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_ranap_LA_LIST_item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ranap_LA_LIST_item, LA_LIST_item_sequence);

  return offset;
}


static const per_sequence_t LA_LIST_sequence_of[1] = {
  { &hf_ranap_LA_LIST_item  , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ranap_LA_LIST_item },
};

static int
dissect_ranap_LA_LIST(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_ranap_LA_LIST, LA_LIST_sequence_of,
                                                  1, maxNrOfLAs, FALSE);

  return offset;
}


static const per_sequence_t LastKnownServiceArea_sequence[] = {
  { &hf_ranap_sAI           , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ranap_SAI },
  { &hf_ranap_ageOfSAI      , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ranap_INTEGER_0_32767 },
  { &hf_ranap_iE_Extensions , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ranap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_ranap_LastKnownServiceArea(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ranap_LastKnownServiceArea, LastKnownServiceArea_sequence);

  return offset;
}


static const value_string ranap_T_interface_vals[] = {
  {   0, "iu-cs" },
  {   1, "iu-ps" },
  {   2, "iur" },
  {   3, "iub" },
  {   4, "uu" },
  { 0, NULL }
};


static int
dissect_ranap_T_interface(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     5, NULL, TRUE, 0, NULL);

  return offset;
}


static const per_sequence_t InterfacesToTraceItem_sequence[] = {
  { &hf_ranap_interface     , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ranap_T_interface },
  { &hf_ranap_iE_Extensions , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ranap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_ranap_InterfacesToTraceItem(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ranap_InterfacesToTraceItem, InterfacesToTraceItem_sequence);

  return offset;
}


static const per_sequence_t ListOfInterfacesToTrace_sequence_of[1] = {
  { &hf_ranap_ListOfInterfacesToTrace_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ranap_InterfacesToTraceItem },
};

static int
dissect_ranap_ListOfInterfacesToTrace(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_ranap_ListOfInterfacesToTrace, ListOfInterfacesToTrace_sequence_of,
                                                  1, maxNrOfInterfaces, FALSE);

  return offset;
}


static const value_string ranap_RequestedLocationRelatedDataType_vals[] = {
  {   0, "decipheringKeysUEBasedOTDOA" },
  {   1, "decipheringKeysAssistedGPS" },
  {   2, "dedicatedAssistanceDataUEBasedOTDOA" },
  {   3, "dedicatedAssistanceDataAssistedGPS" },
  {   4, "decipheringKeysAssistedGANSS" },
  {   5, "dedicatedAssistanceDataAssistedGANSS" },
  {   6, "decipheringKeysAssistedGPSandGANSS" },
  {   7, "dedicatedAssistanceDataAssistedGPSandGANSS" },
  { 0, NULL }
};


static int
dissect_ranap_RequestedLocationRelatedDataType(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     4, NULL, TRUE, 4, NULL);

  return offset;
}



static int
dissect_ranap_RequestedGPSAssistanceData(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_octet_string(tvb, offset, actx, tree, hf_index,
                                       1, 38, FALSE, NULL);

  return offset;
}


static const per_sequence_t LocationRelatedDataRequestType_sequence[] = {
  { &hf_ranap_requestedLocationRelatedDataType, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ranap_RequestedLocationRelatedDataType },
  { &hf_ranap_requestedGPSAssistanceData, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ranap_RequestedGPSAssistanceData },
  { NULL, 0, 0, NULL }
};

static int
dissect_ranap_LocationRelatedDataRequestType(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ranap_LocationRelatedDataRequestType, LocationRelatedDataRequestType_sequence);

  return offset;
}


static const value_string ranap_LocationRelatedDataRequestTypeSpecificToGERANIuMode_vals[] = {
  {   0, "decipheringKeysEOTD" },
  {   1, "dedicatedMobileAssistedEOTDAssistanceData" },
  {   2, "dedicatedMobileBasedEOTDAssistanceData" },
  { 0, NULL }
};


static int
dissect_ranap_LocationRelatedDataRequestTypeSpecificToGERANIuMode(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     3, NULL, TRUE, 0, NULL);

  return offset;
}


static const value_string ranap_ReportChangeOfSAI_vals[] = {
  {   0, "requested" },
  { 0, NULL }
};


static int
dissect_ranap_ReportChangeOfSAI(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     1, NULL, TRUE, 0, NULL);

  return offset;
}


static const value_string ranap_PeriodicReportingIndicator_vals[] = {
  {   0, "periodicSAI" },
  {   1, "periodicGeo" },
  { 0, NULL }
};


static int
dissect_ranap_PeriodicReportingIndicator(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     2, NULL, TRUE, 0, NULL);

  return offset;
}


static const value_string ranap_DirectReportingIndicator_vals[] = {
  {   0, "directSAI" },
  {   1, "directGeo" },
  { 0, NULL }
};


static int
dissect_ranap_DirectReportingIndicator(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     2, NULL, TRUE, 0, NULL);

  return offset;
}



static int
dissect_ranap_VerticalAccuracyCode(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 127U, NULL, FALSE);

  return offset;
}


static const value_string ranap_PositioningPriority_vals[] = {
  {   0, "high-Priority" },
  {   1, "normal-Priority" },
  { 0, NULL }
};


static int
dissect_ranap_PositioningPriority(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     2, NULL, TRUE, 0, NULL);

  return offset;
}


static const value_string ranap_ResponseTime_vals[] = {
  {   0, "lowdelay" },
  {   1, "delaytolerant" },
  { 0, NULL }
};


static int
dissect_ranap_ResponseTime(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     2, NULL, TRUE, 0, NULL);

  return offset;
}



static int
dissect_ranap_INTEGER_1_8639999_(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            1U, 8639999U, NULL, TRUE);

  return offset;
}


static const per_sequence_t PeriodicLocationInfo_sequence[] = {
  { &hf_ranap_reportingAmount, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ranap_INTEGER_1_8639999_ },
  { &hf_ranap_reportingInterval, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ranap_INTEGER_1_8639999_ },
  { &hf_ranap_iE_Extensions , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ranap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_ranap_PeriodicLocationInfo(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ranap_PeriodicLocationInfo, PeriodicLocationInfo_sequence);

  return offset;
}


static const per_sequence_t LocationReportingTransferInformation_sequence[] = {
  { &hf_ranap_reportChangeOfSAI, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ranap_ReportChangeOfSAI },
  { &hf_ranap_periodicReportingIndicator, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ranap_PeriodicReportingIndicator },
  { &hf_ranap_directReportingIndicator, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ranap_DirectReportingIndicator },
  { &hf_ranap_verticalAccuracyCode, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ranap_VerticalAccuracyCode },
  { &hf_ranap_positioningPriorityChangeSAI, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ranap_PositioningPriority },
  { &hf_ranap_positioningPriorityDirect, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ranap_PositioningPriority },
  { &hf_ranap_clientTypePeriodic, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ranap_ClientType },
  { &hf_ranap_clientTypeDirect, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ranap_ClientType },
  { &hf_ranap_responseTime  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ranap_ResponseTime },
  { &hf_ranap_includeVelocity, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ranap_IncludeVelocity },
  { &hf_ranap_periodicLocationInfo, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ranap_PeriodicLocationInfo },
  { &hf_ranap_iE_Extensions , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ranap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_ranap_LocationReportingTransferInformation(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ranap_LocationReportingTransferInformation, LocationReportingTransferInformation_sequence);

  return offset;
}



static int
dissect_ranap_L3_Information(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 266 "../../asn1/ranap/ranap.cnf"
  tvbuff_t *l3_info_tvb=NULL;

  offset = dissect_per_octet_string(tvb, offset, actx, tree, hf_index,
                                       NO_BOUND, NO_BOUND, FALSE, &l3_info_tvb);

	if (l3_info_tvb)
		dissector_try_uint(nas_pdu_dissector_table, 0x1, l3_info_tvb, actx->pinfo, proto_tree_get_root(tree));


  return offset;
}


static const value_string ranap_Management_Based_MDT_Allowed_vals[] = {
  {   0, "allowed" },
  { 0, NULL }
};


static int
dissect_ranap_Management_Based_MDT_Allowed(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     1, NULL, TRUE, 0, NULL);

  return offset;
}



static int
dissect_ranap_MaxSDU_Size(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 32768U, NULL, FALSE);

  return offset;
}



static int
dissect_ranap_MBMS_PTP_RAB_ID(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_bit_string(tvb, offset, actx, tree, hf_index,
                                     8, 8, FALSE, NULL);

  return offset;
}


static const value_string ranap_MBMSBearerServiceType_vals[] = {
  {   0, "multicast" },
  {   1, "broadcast" },
  { 0, NULL }
};


static int
dissect_ranap_MBMSBearerServiceType(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     2, NULL, TRUE, 0, NULL);

  return offset;
}


static const value_string ranap_MBMSCNDe_Registration_vals[] = {
  {   0, "normalsessionstop" },
  {   1, "deregister" },
  { 0, NULL }
};


static int
dissect_ranap_MBMSCNDe_Registration(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     2, NULL, TRUE, 0, NULL);

  return offset;
}


static const value_string ranap_MBMSCountingInformation_vals[] = {
  {   0, "counting" },
  {   1, "notcounting" },
  { 0, NULL }
};


static int
dissect_ranap_MBMSCountingInformation(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     2, NULL, TRUE, 0, NULL);

  return offset;
}


static const value_string ranap_MBMSHCIndicator_vals[] = {
  {   0, "uncompressed-header" },
  {   1, "compressed-header" },
  { 0, NULL }
};


static int
dissect_ranap_MBMSHCIndicator(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     2, NULL, TRUE, 0, NULL);

  return offset;
}


static const value_string ranap_MBMSLinkingInformation_vals[] = {
  {   0, "uE-has-joined-multicast-services" },
  { 0, NULL }
};


static int
dissect_ranap_MBMSLinkingInformation(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     1, NULL, TRUE, 0, NULL);

  return offset;
}


static const value_string ranap_MBMSRegistrationRequestType_vals[] = {
  {   0, "register" },
  {   1, "deregister" },
  { 0, NULL }
};


static int
dissect_ranap_MBMSRegistrationRequestType(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     2, NULL, TRUE, 0, NULL);

  return offset;
}



static int
dissect_ranap_MBMSServiceArea(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_octet_string(tvb, offset, actx, tree, hf_index,
                                       NO_BOUND, NO_BOUND, FALSE, NULL);

  return offset;
}



static int
dissect_ranap_MBMSSessionDuration(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_octet_string(tvb, offset, actx, tree, hf_index,
                                       3, 3, FALSE, NULL);

  return offset;
}



static int
dissect_ranap_MBMSSessionIdentity(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_octet_string(tvb, offset, actx, tree, hf_index,
                                       1, 1, FALSE, NULL);

  return offset;
}



static int
dissect_ranap_MBMSSessionRepetitionNumber(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_octet_string(tvb, offset, actx, tree, hf_index,
                                       1, 1, FALSE, NULL);

  return offset;
}


static const value_string ranap_MDT_Activation_vals[] = {
  {   0, "immediateMDTonly" },
  {   1, "loggedMDTonly" },
  {   2, "immediateMDTandTrace" },
  { 0, NULL }
};


static int
dissect_ranap_MDT_Activation(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     3, NULL, TRUE, 0, NULL);

  return offset;
}


static const per_sequence_t LAI_List_sequence_of[1] = {
  { &hf_ranap_LAI_List_item , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ranap_LAI },
};

static int
dissect_ranap_LAI_List(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_ranap_LAI_List, LAI_List_sequence_of,
                                                  1, maxNrOfLAIs, FALSE);

  return offset;
}


static const per_sequence_t LABased_sequence[] = {
  { &hf_ranap_laiList       , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ranap_LAI_List },
  { &hf_ranap_iE_Extensions , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ranap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_ranap_LABased(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ranap_LABased, LABased_sequence);

  return offset;
}


static const per_sequence_t RAC_List_sequence_of[1] = {
  { &hf_ranap_RAC_List_item , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ranap_RAC },
};

static int
dissect_ranap_RAC_List(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_ranap_RAC_List, RAC_List_sequence_of,
                                                  1, maxNrOfRACs, FALSE);

  return offset;
}


static const per_sequence_t RABased_sequence[] = {
  { &hf_ranap_racList       , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ranap_RAC_List },
  { &hf_ranap_iE_Extensions , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ranap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_ranap_RABased(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ranap_RABased, RABased_sequence);

  return offset;
}


static const per_sequence_t PLMNAreaBased_sequence[] = {
  { &hf_ranap_plmnID        , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ranap_PLMNidentity },
  { &hf_ranap_iE_Extensions , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ranap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_ranap_PLMNAreaBased(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ranap_PLMNAreaBased, PLMNAreaBased_sequence);

  return offset;
}


static const value_string ranap_MDTAreaScope_vals[] = {
  {   0, "cellbased" },
  {   1, "labased" },
  {   2, "rabased" },
  {   3, "plmn-area-based" },
  { 0, NULL }
};

static const per_choice_t MDTAreaScope_choice[] = {
  {   0, &hf_ranap_cellbased     , ASN1_EXTENSION_ROOT    , dissect_ranap_CellBased },
  {   1, &hf_ranap_labased       , ASN1_EXTENSION_ROOT    , dissect_ranap_LABased },
  {   2, &hf_ranap_rabased       , ASN1_EXTENSION_ROOT    , dissect_ranap_RABased },
  {   3, &hf_ranap_plmn_area_based, ASN1_EXTENSION_ROOT    , dissect_ranap_PLMNAreaBased },
  { 0, NULL, 0, NULL }
};

static int
dissect_ranap_MDTAreaScope(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_ranap_MDTAreaScope, MDTAreaScope_choice,
                                 NULL);

  return offset;
}



static int
dissect_ranap_TraceRecordingSessionReference(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 65535U, NULL, FALSE);

  return offset;
}


static const value_string ranap_LoggingInterval_vals[] = {
  {   0, "s1d28" },
  {   1, "s2d56" },
  {   2, "s5d12" },
  {   3, "s10d24" },
  {   4, "s20d48" },
  {   5, "s30d72" },
  {   6, "s40d96" },
  {   7, "s61d44" },
  { 0, NULL }
};


static int
dissect_ranap_LoggingInterval(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     8, NULL, TRUE, 0, NULL);

  return offset;
}


static const value_string ranap_LoggingDuration_vals[] = {
  {   0, "min10" },
  {   1, "min20" },
  {   2, "min40" },
  {   3, "min60" },
  {   4, "min90" },
  {   5, "min120" },
  { 0, NULL }
};


static int
dissect_ranap_LoggingDuration(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     6, NULL, TRUE, 0, NULL);

  return offset;
}


static const per_sequence_t LoggedMDT_sequence[] = {
  { &hf_ranap_loggingInterval, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ranap_LoggingInterval },
  { &hf_ranap_loggingDuration, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ranap_LoggingDuration },
  { &hf_ranap_iE_Extensions , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ranap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_ranap_LoggedMDT(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ranap_LoggedMDT, LoggedMDT_sequence);

  return offset;
}


static const value_string ranap_MDTMode_vals[] = {
  {   0, "immediateMDT" },
  {   1, "loggedMDT" },
  { 0, NULL }
};

static const per_choice_t MDTMode_choice[] = {
  {   0, &hf_ranap_immediateMDT  , ASN1_EXTENSION_ROOT    , dissect_ranap_ImmediateMDT },
  {   1, &hf_ranap_loggedMDT     , ASN1_EXTENSION_ROOT    , dissect_ranap_LoggedMDT },
  { 0, NULL, 0, NULL }
};

static int
dissect_ranap_MDTMode(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_ranap_MDTMode, MDTMode_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t MDT_Configuration_sequence[] = {
  { &hf_ranap_mdtRecordingSessionReference, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ranap_TraceRecordingSessionReference },
  { &hf_ranap_mdtActivation , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ranap_MDT_Activation },
  { &hf_ranap_mdtAreaScope  , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ranap_MDTAreaScope },
  { &hf_ranap_mdtMode       , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ranap_MDTMode },
  { &hf_ranap_iE_Extensions , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ranap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_ranap_MDT_Configuration(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ranap_MDT_Configuration, MDT_Configuration_sequence);

  return offset;
}



static int
dissect_ranap_MSISDN(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_octet_string(tvb, offset, actx, tree, hf_index,
                                       1, 9, FALSE, NULL);

  return offset;
}



static int
dissect_ranap_NAS_PDU(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 211 "../../asn1/ranap/ranap.cnf"
  tvbuff_t *nas_pdu_tvb=NULL;

  offset = dissect_per_octet_string(tvb, offset, actx, tree, hf_index,
                                       NO_BOUND, NO_BOUND, FALSE, &nas_pdu_tvb);


	if (nas_pdu_tvb)
		dissector_try_uint(nas_pdu_dissector_table, 0x1, nas_pdu_tvb, actx->pinfo, proto_tree_get_root(tree));


  return offset;
}



static int
dissect_ranap_NAS_SequenceNumber(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_bit_string(tvb, offset, actx, tree, hf_index,
                                     2, 2, FALSE, NULL);

  return offset;
}



static int
dissect_ranap_NAS_SynchronisationIndicator(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_bit_string(tvb, offset, actx, tree, hf_index,
                                     4, 4, FALSE, NULL);

  return offset;
}



static int
dissect_ranap_NewBSS_To_OldBSS_Information(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 258 "../../asn1/ranap/ranap.cnf"
  tvbuff_t *bss_info_tvb=NULL;

  offset = dissect_per_octet_string(tvb, offset, actx, tree, hf_index,
                                       NO_BOUND, NO_BOUND, FALSE, &bss_info_tvb);

	if (bss_info_tvb)
            bssmap_new_bss_to_old_bss_info(bss_info_tvb, tree, actx->pinfo);


  return offset;
}


static const value_string ranap_NonSearchingIndication_vals[] = {
  {   0, "non-searching" },
  {   1, "searching" },
  { 0, NULL }
};


static int
dissect_ranap_NonSearchingIndication(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     2, NULL, FALSE, 0, NULL);

  return offset;
}



static int
dissect_ranap_NumberOfIuInstances(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            1U, 2U, NULL, FALSE);

  return offset;
}



static int
dissect_ranap_NumberOfSteps(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            1U, 16U, NULL, FALSE);

  return offset;
}



static int
dissect_ranap_Offload_RAB_Parameters_APN(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_octet_string(tvb, offset, actx, tree, hf_index,
                                       1, 255, FALSE, NULL);

  return offset;
}



static int
dissect_ranap_Offload_RAB_Parameters_ChargingCharacteristics(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_octet_string(tvb, offset, actx, tree, hf_index,
                                       2, 2, FALSE, NULL);

  return offset;
}


static const per_sequence_t Offload_RAB_Parameters_sequence[] = {
  { &hf_ranap_accessPointName, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ranap_Offload_RAB_Parameters_APN },
  { &hf_ranap_chargingCharacteristics, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ranap_Offload_RAB_Parameters_ChargingCharacteristics },
  { &hf_ranap_iE_Extensions , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ranap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_ranap_Offload_RAB_Parameters(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ranap_Offload_RAB_Parameters, Offload_RAB_Parameters_sequence);

  return offset;
}



static int
dissect_ranap_OldBSS_ToNewBSS_Information(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 250 "../../asn1/ranap/ranap.cnf"
  tvbuff_t *bss_info_tvb=NULL;

  offset = dissect_per_octet_string(tvb, offset, actx, tree, hf_index,
                                       NO_BOUND, NO_BOUND, FALSE, &bss_info_tvb);

	if (bss_info_tvb)
            bssmap_old_bss_to_new_bss_info(bss_info_tvb, tree, actx->pinfo);


  return offset;
}



static int
dissect_ranap_OMC_ID(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_octet_string(tvb, offset, actx, tree, hf_index,
                                       3, 22, FALSE, NULL);

  return offset;
}


static const per_sequence_t RAI_sequence[] = {
  { &hf_ranap_lAI           , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ranap_LAI },
  { &hf_ranap_rAC           , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ranap_RAC },
  { &hf_ranap_iE_Extensions , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ranap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_ranap_RAI(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ranap_RAI, RAI_sequence);

  return offset;
}


static const value_string ranap_PagingAreaID_vals[] = {
  {   0, "lAI" },
  {   1, "rAI" },
  { 0, NULL }
};

static const per_choice_t PagingAreaID_choice[] = {
  {   0, &hf_ranap_lAI           , ASN1_EXTENSION_ROOT    , dissect_ranap_LAI },
  {   1, &hf_ranap_rAI           , ASN1_EXTENSION_ROOT    , dissect_ranap_RAI },
  { 0, NULL, 0, NULL }
};

static int
dissect_ranap_PagingAreaID(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_ranap_PagingAreaID, PagingAreaID_choice,
                                 NULL);

  return offset;
}


static const value_string ranap_PagingCause_vals[] = {
  {   0, "terminating-conversational-call" },
  {   1, "terminating-streaming-call" },
  {   2, "terminating-interactive-call" },
  {   3, "terminating-background-call" },
  {   4, "terminating-low-priority-signalling" },
  {   5, "terminating-high-priority-signalling" },
  { 0, NULL }
};


static int
dissect_ranap_PagingCause(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     5, NULL, TRUE, 1, NULL);

  return offset;
}


static const value_string ranap_PDP_Type_vals[] = {
  {   0, "empty" },
  {   1, "ppp" },
  {   2, "osp-ihoss" },
  {   3, "ipv4" },
  {   4, "ipv6" },
  { 0, NULL }
};


static int
dissect_ranap_PDP_Type(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     5, NULL, TRUE, 0, NULL);

  return offset;
}


static const per_sequence_t PDP_TypeInformation_sequence_of[1] = {
  { &hf_ranap_PDP_TypeInformation_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ranap_PDP_Type },
};

static int
dissect_ranap_PDP_TypeInformation(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_ranap_PDP_TypeInformation, PDP_TypeInformation_sequence_of,
                                                  1, maxNrOfPDPDirections, FALSE);

  return offset;
}


static const value_string ranap_PDP_Type_extension_vals[] = {
  {   0, "ipv4-and-ipv6" },
  { 0, NULL }
};


static int
dissect_ranap_PDP_Type_extension(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     1, NULL, TRUE, 0, NULL);

  return offset;
}


static const per_sequence_t PDP_TypeInformation_extension_sequence_of[1] = {
  { &hf_ranap_PDP_TypeInformation_extension_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ranap_PDP_Type_extension },
};

static int
dissect_ranap_PDP_TypeInformation_extension(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_ranap_PDP_TypeInformation_extension, PDP_TypeInformation_extension_sequence_of,
                                                  1, maxNrOfPDPDirections, FALSE);

  return offset;
}



static int
dissect_ranap_PDUType14FrameSequenceNumber(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 3U, NULL, FALSE);

  return offset;
}


static const per_sequence_t PLMNs_in_shared_network_item_sequence[] = {
  { &hf_ranap_pLMNidentity  , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ranap_PLMNidentity },
  { &hf_ranap_lA_LIST       , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ranap_LA_LIST },
  { &hf_ranap_iE_Extensions , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ranap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_ranap_PLMNs_in_shared_network_item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ranap_PLMNs_in_shared_network_item, PLMNs_in_shared_network_item_sequence);

  return offset;
}


static const per_sequence_t PLMNs_in_shared_network_sequence_of[1] = {
  { &hf_ranap_PLMNs_in_shared_network_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ranap_PLMNs_in_shared_network_item },
};

static int
dissect_ranap_PLMNs_in_shared_network(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_ranap_PLMNs_in_shared_network, PLMNs_in_shared_network_sequence_of,
                                                  1, maxNrOfPLMNsSN, FALSE);

  return offset;
}



static int
dissect_ranap_PositioningDataDiscriminator(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_bit_string(tvb, offset, actx, tree, hf_index,
                                     4, 4, FALSE, NULL);

  return offset;
}



static int
dissect_ranap_PositioningMethodAndUsage(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_octet_string(tvb, offset, actx, tree, hf_index,
                                       1, 1, FALSE, NULL);

  return offset;
}


static const per_sequence_t PositioningDataSet_sequence_of[1] = {
  { &hf_ranap_PositioningDataSet_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ranap_PositioningMethodAndUsage },
};

static int
dissect_ranap_PositioningDataSet(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_ranap_PositioningDataSet, PositioningDataSet_sequence_of,
                                                  1, maxSet, FALSE);

  return offset;
}


static const per_sequence_t PositionData_sequence[] = {
  { &hf_ranap_positioningDataDiscriminator, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ranap_PositioningDataDiscriminator },
  { &hf_ranap_positioningDataSet, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ranap_PositioningDataSet },
  { &hf_ranap_iE_Extensions , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ranap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_ranap_PositionData(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ranap_PositionData, PositionData_sequence);

  return offset;
}



static int
dissect_ranap_PositionDataSpecificToGERANIuMode(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_octet_string(tvb, offset, actx, tree, hf_index,
                                       NO_BOUND, NO_BOUND, FALSE, NULL);

  return offset;
}



static int
dissect_ranap_Priority_Class_Indicator(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_bit_string(tvb, offset, actx, tree, hf_index,
                                     8, 8, FALSE, NULL);

  return offset;
}


static const per_sequence_t Shared_Network_Information_sequence[] = {
  { &hf_ranap_pLMNs_in_shared_network, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ranap_PLMNs_in_shared_network },
  { &hf_ranap_iE_Extensions , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ranap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_ranap_Shared_Network_Information(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ranap_Shared_Network_Information, Shared_Network_Information_sequence);

  return offset;
}


static const value_string ranap_ProvidedData_vals[] = {
  {   0, "shared-network-information" },
  { 0, NULL }
};

static const per_choice_t ProvidedData_choice[] = {
  {   0, &hf_ranap_shared_network_information, ASN1_EXTENSION_ROOT    , dissect_ranap_Shared_Network_Information },
  { 0, NULL, 0, NULL }
};

static int
dissect_ranap_ProvidedData(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_ranap_ProvidedData, ProvidedData_choice,
                                 NULL);

  return offset;
}



static int
dissect_ranap_P_TMSI(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_octet_string(tvb, offset, actx, tree, hf_index,
                                       4, 4, FALSE, NULL);

  return offset;
}


static const value_string ranap_RAB_AsymmetryIndicator_vals[] = {
  {   0, "symmetric-bidirectional" },
  {   1, "asymmetric-unidirectional-downlink" },
  {   2, "asymmetric-unidirectional-uplink" },
  {   3, "asymmetric-bidirectional" },
  { 0, NULL }
};


static int
dissect_ranap_RAB_AsymmetryIndicator(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     4, NULL, TRUE, 0, NULL);

  return offset;
}



static int
dissect_ranap_UnsuccessfullyTransmittedDataVolume(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 4294967295U, NULL, FALSE);

  return offset;
}


static const per_sequence_t RABDataVolumeReport_item_sequence[] = {
  { &hf_ranap_dl_UnsuccessfullyTransmittedDataVolume, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ranap_UnsuccessfullyTransmittedDataVolume },
  { &hf_ranap_dataVolumeReference, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ranap_DataVolumeReference },
  { &hf_ranap_iE_Extensions , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ranap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_ranap_RABDataVolumeReport_item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ranap_RABDataVolumeReport_item, RABDataVolumeReport_item_sequence);

  return offset;
}


static const per_sequence_t RABDataVolumeReport_sequence_of[1] = {
  { &hf_ranap_RABDataVolumeReport_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ranap_RABDataVolumeReport_item },
};

static int
dissect_ranap_RABDataVolumeReport(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_ranap_RABDataVolumeReport, RABDataVolumeReport_sequence_of,
                                                  1, maxNrOfVol, FALSE);

  return offset;
}



static int
dissect_ranap_RAB_ID(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_bit_string(tvb, offset, actx, tree, hf_index,
                                     8, 8, FALSE, NULL);

  return offset;
}


static const per_sequence_t RAB_Parameter_ExtendedGuaranteedBitrateList_sequence_of[1] = {
  { &hf_ranap_RAB_Parameter_ExtendedGuaranteedBitrateList_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ranap_ExtendedGuaranteedBitrate },
};

static int
dissect_ranap_RAB_Parameter_ExtendedGuaranteedBitrateList(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_ranap_RAB_Parameter_ExtendedGuaranteedBitrateList, RAB_Parameter_ExtendedGuaranteedBitrateList_sequence_of,
                                                  1, maxNrOfSeparateTrafficDirections, FALSE);

  return offset;
}


static const per_sequence_t RAB_Parameter_ExtendedMaxBitrateList_sequence_of[1] = {
  { &hf_ranap_RAB_Parameter_ExtendedMaxBitrateList_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ranap_ExtendedMaxBitrate },
};

static int
dissect_ranap_RAB_Parameter_ExtendedMaxBitrateList(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_ranap_RAB_Parameter_ExtendedMaxBitrateList, RAB_Parameter_ExtendedMaxBitrateList_sequence_of,
                                                  1, maxNrOfSeparateTrafficDirections, FALSE);

  return offset;
}


static const per_sequence_t RAB_Parameter_GuaranteedBitrateList_sequence_of[1] = {
  { &hf_ranap_RAB_Parameter_GuaranteedBitrateList_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ranap_GuaranteedBitrate },
};

static int
dissect_ranap_RAB_Parameter_GuaranteedBitrateList(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_ranap_RAB_Parameter_GuaranteedBitrateList, RAB_Parameter_GuaranteedBitrateList_sequence_of,
                                                  1, maxNrOfSeparateTrafficDirections, FALSE);

  return offset;
}


static const per_sequence_t RAB_Parameter_MaxBitrateList_sequence_of[1] = {
  { &hf_ranap_RAB_Parameter_MaxBitrateList_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ranap_MaxBitrate },
};

static int
dissect_ranap_RAB_Parameter_MaxBitrateList(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_ranap_RAB_Parameter_MaxBitrateList, RAB_Parameter_MaxBitrateList_sequence_of,
                                                  1, maxNrOfSeparateTrafficDirections, FALSE);

  return offset;
}


static const value_string ranap_TrafficClass_vals[] = {
  {   0, "conversational" },
  {   1, "streaming" },
  {   2, "interactive" },
  {   3, "background" },
  { 0, NULL }
};


static int
dissect_ranap_TrafficClass(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     4, NULL, TRUE, 0, NULL);

  return offset;
}



static int
dissect_ranap_INTEGER_1_9(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            1U, 9U, NULL, FALSE);

  return offset;
}



static int
dissect_ranap_INTEGER_1_6(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            1U, 6U, NULL, FALSE);

  return offset;
}


static const per_sequence_t SDU_ErrorRatio_sequence[] = {
  { &hf_ranap_mantissa      , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ranap_INTEGER_1_9 },
  { &hf_ranap_exponent_1_8  , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ranap_INTEGER_1_6 },
  { &hf_ranap_iE_Extensions , ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_ranap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_ranap_SDU_ErrorRatio(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ranap_SDU_ErrorRatio, SDU_ErrorRatio_sequence);

  return offset;
}



static int
dissect_ranap_INTEGER_1_8(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            1U, 8U, NULL, FALSE);

  return offset;
}


static const per_sequence_t ResidualBitErrorRatio_sequence[] = {
  { &hf_ranap_mantissa      , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ranap_INTEGER_1_9 },
  { &hf_ranap_exponent      , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ranap_INTEGER_1_8 },
  { &hf_ranap_iE_Extensions , ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_ranap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_ranap_ResidualBitErrorRatio(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ranap_ResidualBitErrorRatio, ResidualBitErrorRatio_sequence);

  return offset;
}



static int
dissect_ranap_SubflowSDU_Size(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 4095U, NULL, FALSE);

  return offset;
}



static int
dissect_ranap_RAB_SubflowCombinationBitRate(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 16000000U, NULL, FALSE);

  return offset;
}


static const per_sequence_t SDU_FormatInformationParameters_item_sequence[] = {
  { &hf_ranap_subflowSDU_Size, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ranap_SubflowSDU_Size },
  { &hf_ranap_rAB_SubflowCombinationBitRate, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ranap_RAB_SubflowCombinationBitRate },
  { &hf_ranap_iE_Extensions , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ranap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_ranap_SDU_FormatInformationParameters_item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ranap_SDU_FormatInformationParameters_item, SDU_FormatInformationParameters_item_sequence);

  return offset;
}


static const per_sequence_t SDU_FormatInformationParameters_sequence_of[1] = {
  { &hf_ranap_SDU_FormatInformationParameters_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ranap_SDU_FormatInformationParameters_item },
};

static int
dissect_ranap_SDU_FormatInformationParameters(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_ranap_SDU_FormatInformationParameters, SDU_FormatInformationParameters_sequence_of,
                                                  1, maxRAB_SubflowCombination, FALSE);

  return offset;
}


static const per_sequence_t SDU_Parameters_item_sequence[] = {
  { &hf_ranap_sDU_ErrorRatio, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ranap_SDU_ErrorRatio },
  { &hf_ranap_residualBitErrorRatio, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ranap_ResidualBitErrorRatio },
  { &hf_ranap_deliveryOfErroneousSDU, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ranap_DeliveryOfErroneousSDU },
  { &hf_ranap_sDU_FormatInformationParameters, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ranap_SDU_FormatInformationParameters },
  { &hf_ranap_iE_Extensions , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ranap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_ranap_SDU_Parameters_item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ranap_SDU_Parameters_item, SDU_Parameters_item_sequence);

  return offset;
}


static const per_sequence_t SDU_Parameters_sequence_of[1] = {
  { &hf_ranap_SDU_Parameters_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ranap_SDU_Parameters_item },
};

static int
dissect_ranap_SDU_Parameters(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_ranap_SDU_Parameters, SDU_Parameters_sequence_of,
                                                  1, maxRAB_Subflows, FALSE);

  return offset;
}



static int
dissect_ranap_TransferDelay(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 65535U, NULL, FALSE);

  return offset;
}


static const value_string ranap_TrafficHandlingPriority_vals[] = {
  {   0, "spare" },
  {   1, "highest" },
  {  14, "lowest" },
  {  15, "no-priority-used" },
  { 0, NULL }
};


static int
dissect_ranap_TrafficHandlingPriority(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 15U, NULL, FALSE);

  return offset;
}


static const value_string ranap_SourceStatisticsDescriptor_vals[] = {
  {   0, "speech" },
  {   1, "unknown" },
  { 0, NULL }
};


static int
dissect_ranap_SourceStatisticsDescriptor(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     2, NULL, TRUE, 0, NULL);

  return offset;
}


static const value_string ranap_RelocationRequirement_vals[] = {
  {   0, "lossless" },
  {   1, "none" },
  {   2, "realtime" },
  { 0, NULL }
};


static int
dissect_ranap_RelocationRequirement(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     2, NULL, TRUE, 1, NULL);

  return offset;
}


static const per_sequence_t RAB_Parameters_sequence[] = {
  { &hf_ranap_trafficClass  , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ranap_TrafficClass },
  { &hf_ranap_rAB_AsymmetryIndicator, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ranap_RAB_AsymmetryIndicator },
  { &hf_ranap_maxBitrate    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ranap_RAB_Parameter_MaxBitrateList },
  { &hf_ranap_guaranteedBitRate, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ranap_RAB_Parameter_GuaranteedBitrateList },
  { &hf_ranap_deliveryOrder , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ranap_DeliveryOrder },
  { &hf_ranap_maxSDU_Size   , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ranap_MaxSDU_Size },
  { &hf_ranap_sDU_Parameters, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ranap_SDU_Parameters },
  { &hf_ranap_transferDelay , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ranap_TransferDelay },
  { &hf_ranap_trafficHandlingPriority, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ranap_TrafficHandlingPriority },
  { &hf_ranap_allocationOrRetentionPriority, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ranap_AllocationOrRetentionPriority },
  { &hf_ranap_sourceStatisticsDescriptor, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ranap_SourceStatisticsDescriptor },
  { &hf_ranap_relocationRequirement, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ranap_RelocationRequirement },
  { &hf_ranap_iE_Extensions , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ranap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_ranap_RAB_Parameters(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ranap_RAB_Parameters, RAB_Parameters_sequence);

  return offset;
}



static int
dissect_ranap_UPInitialisationFrame(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_octet_string(tvb, offset, actx, tree, hf_index,
                                       NO_BOUND, NO_BOUND, FALSE, NULL);

  return offset;
}


static const per_sequence_t UPInformation_sequence[] = {
  { &hf_ranap_frameSeqNoUL  , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ranap_FrameSequenceNumber },
  { &hf_ranap_frameSeqNoDL  , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ranap_FrameSequenceNumber },
  { &hf_ranap_pdu14FrameSeqNoUL, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ranap_PDUType14FrameSequenceNumber },
  { &hf_ranap_pdu14FrameSeqNoDL, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ranap_PDUType14FrameSequenceNumber },
  { &hf_ranap_dataPDUType   , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ranap_DataPDUType },
  { &hf_ranap_upinitialisationFrame, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ranap_UPInitialisationFrame },
  { &hf_ranap_iE_Extensions , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ranap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_ranap_UPInformation(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ranap_UPInformation, UPInformation_sequence);

  return offset;
}


static const per_sequence_t RABParametersList_item_sequence[] = {
  { &hf_ranap_rab_Id        , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ranap_RAB_ID },
  { &hf_ranap_cn_domain     , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ranap_CN_DomainIndicator },
  { &hf_ranap_rabDataVolumeReport, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ranap_RABDataVolumeReport },
  { &hf_ranap_upInformation , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ranap_UPInformation },
  { &hf_ranap_iE_Extensions , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ranap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_ranap_RABParametersList_item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ranap_RABParametersList_item, RABParametersList_item_sequence);

  return offset;
}


static const per_sequence_t RABParametersList_sequence_of[1] = {
  { &hf_ranap_RABParametersList_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ranap_RABParametersList_item },
};

static int
dissect_ranap_RABParametersList(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_ranap_RABParametersList, RABParametersList_sequence_of,
                                                  1, maxNrOfRABs, FALSE);

  return offset;
}



static int
dissect_ranap_USCH_ID(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 255U, NULL, FALSE);

  return offset;
}


static const per_sequence_t TrCH_ID_sequence[] = {
  { &hf_ranap_dCH_ID        , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ranap_DCH_ID },
  { &hf_ranap_dSCH_ID       , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ranap_DSCH_ID },
  { &hf_ranap_uSCH_ID       , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ranap_USCH_ID },
  { &hf_ranap_iE_Extensions , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ranap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_ranap_TrCH_ID(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ranap_TrCH_ID, TrCH_ID_sequence);

  return offset;
}


static const per_sequence_t TrCH_ID_List_sequence_of[1] = {
  { &hf_ranap_TrCH_ID_List_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ranap_TrCH_ID },
};

static int
dissect_ranap_TrCH_ID_List(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_ranap_TrCH_ID_List, TrCH_ID_List_sequence_of,
                                                  1, maxRAB_Subflows, FALSE);

  return offset;
}


static const per_sequence_t RAB_TrCH_MappingItem_sequence[] = {
  { &hf_ranap_rAB_ID        , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ranap_RAB_ID },
  { &hf_ranap_trCH_ID_List  , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ranap_TrCH_ID_List },
  { &hf_ranap_iE_Extensions , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ranap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_ranap_RAB_TrCH_MappingItem(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ranap_RAB_TrCH_MappingItem, RAB_TrCH_MappingItem_sequence);

  return offset;
}


static const per_sequence_t RAB_TrCH_Mapping_sequence_of[1] = {
  { &hf_ranap_RAB_TrCH_Mapping_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ranap_RAB_TrCH_MappingItem },
};

static int
dissect_ranap_RAB_TrCH_Mapping(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_ranap_RAB_TrCH_Mapping, RAB_TrCH_Mapping_sequence_of,
                                                  1, maxNrOfRABs, FALSE);

  return offset;
}


static const per_sequence_t RAofIdleModeUEs_sequence_of[1] = {
  { &hf_ranap_RAofIdleModeUEs_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ranap_RAC },
};

static int
dissect_ranap_RAofIdleModeUEs(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_ranap_RAofIdleModeUEs, RAofIdleModeUEs_sequence_of,
                                                  1, maxMBMSRA, FALSE);

  return offset;
}


static const per_sequence_t NotEmptyRAListofIdleModeUEs_sequence[] = {
  { &hf_ranap_rAofIdleModeUEs, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ranap_RAofIdleModeUEs },
  { &hf_ranap_iE_Extensions , ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_ranap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_ranap_NotEmptyRAListofIdleModeUEs(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ranap_NotEmptyRAListofIdleModeUEs, NotEmptyRAListofIdleModeUEs_sequence);

  return offset;
}


static const value_string ranap_T_emptyFullRAListofIdleModeUEs_vals[] = {
  {   0, "emptylist" },
  {   1, "fulllist" },
  { 0, NULL }
};


static int
dissect_ranap_T_emptyFullRAListofIdleModeUEs(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     2, NULL, TRUE, 0, NULL);

  return offset;
}


static const value_string ranap_RAListofIdleModeUEs_vals[] = {
  {   0, "notEmptyRAListofIdleModeUEs" },
  {   1, "emptyFullRAListofIdleModeUEs" },
  { 0, NULL }
};

static const per_choice_t RAListofIdleModeUEs_choice[] = {
  {   0, &hf_ranap_notEmptyRAListofIdleModeUEs, ASN1_EXTENSION_ROOT    , dissect_ranap_NotEmptyRAListofIdleModeUEs },
  {   1, &hf_ranap_emptyFullRAListofIdleModeUEs, ASN1_EXTENSION_ROOT    , dissect_ranap_T_emptyFullRAListofIdleModeUEs },
  { 0, NULL, 0, NULL }
};

static int
dissect_ranap_RAListofIdleModeUEs(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_ranap_RAListofIdleModeUEs, RAListofIdleModeUEs_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t LAListofIdleModeUEs_sequence_of[1] = {
  { &hf_ranap_LAListofIdleModeUEs_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ranap_LAI },
};

static int
dissect_ranap_LAListofIdleModeUEs(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_ranap_LAListofIdleModeUEs, LAListofIdleModeUEs_sequence_of,
                                                  1, maxMBMSRA, FALSE);

  return offset;
}


static const value_string ranap_RAT_Type_vals[] = {
  {   0, "utran" },
  {   1, "geran" },
  { 0, NULL }
};


static int
dissect_ranap_RAT_Type(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     2, NULL, TRUE, 0, NULL);

  return offset;
}



static int
dissect_ranap_RedirectAttemptFlag(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_null(tvb, offset, actx, tree, hf_index);

  return offset;
}


static const value_string ranap_RedirectionCompleted_vals[] = {
  {   0, "redirection-completed" },
  { 0, NULL }
};


static int
dissect_ranap_RedirectionCompleted(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     1, NULL, TRUE, 0, NULL);

  return offset;
}


static const value_string ranap_RejectCauseValue_vals[] = {
  {   0, "pLMN-Not-Allowed" },
  {   1, "location-Area-Not-Allowed" },
  {   2, "roaming-Not-Allowed-In-This-Location-Area" },
  {   3, "no-Suitable-Cell-In-Location-Area" },
  {   4, "gPRS-Services-Not-Allowed-In-This-PLMN" },
  {   5, "cS-PS-coordination-required" },
  { 0, NULL }
};


static int
dissect_ranap_RejectCauseValue(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     6, NULL, TRUE, 0, NULL);

  return offset;
}


static const value_string ranap_RelocationType_vals[] = {
  {   0, "ue-not-involved" },
  {   1, "ue-involved" },
  { 0, NULL }
};


static int
dissect_ranap_RelocationType(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     2, NULL, TRUE, 0, NULL);

  return offset;
}


static const value_string ranap_ReportArea_vals[] = {
  {   0, "service-area" },
  {   1, "geographical-area" },
  { 0, NULL }
};


static int
dissect_ranap_ReportArea(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     2, NULL, TRUE, 0, NULL);

  return offset;
}



static int
dissect_ranap_RequestedGANSSAssistanceData(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_octet_string(tvb, offset, actx, tree, hf_index,
                                       1, 201, FALSE, NULL);

  return offset;
}


static const per_sequence_t Requested_RAB_Parameter_MaxBitrateList_sequence_of[1] = {
  { &hf_ranap_Requested_RAB_Parameter_MaxBitrateList_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ranap_MaxBitrate },
};

static int
dissect_ranap_Requested_RAB_Parameter_MaxBitrateList(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_ranap_Requested_RAB_Parameter_MaxBitrateList, Requested_RAB_Parameter_MaxBitrateList_sequence_of,
                                                  1, maxNrOfSeparateTrafficDirections, FALSE);

  return offset;
}


static const per_sequence_t Requested_RAB_Parameter_GuaranteedBitrateList_sequence_of[1] = {
  { &hf_ranap_Requested_RAB_Parameter_GuaranteedBitrateList_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ranap_GuaranteedBitrate },
};

static int
dissect_ranap_Requested_RAB_Parameter_GuaranteedBitrateList(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_ranap_Requested_RAB_Parameter_GuaranteedBitrateList, Requested_RAB_Parameter_GuaranteedBitrateList_sequence_of,
                                                  1, maxNrOfSeparateTrafficDirections, FALSE);

  return offset;
}


static const per_sequence_t Requested_RAB_Parameter_Values_sequence[] = {
  { &hf_ranap_requestedMaxBitrates, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ranap_Requested_RAB_Parameter_MaxBitrateList },
  { &hf_ranap_requestedGuaranteedBitrates, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ranap_Requested_RAB_Parameter_GuaranteedBitrateList },
  { &hf_ranap_iE_Extensions , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ranap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_ranap_Requested_RAB_Parameter_Values(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ranap_Requested_RAB_Parameter_Values, Requested_RAB_Parameter_Values_sequence);

  return offset;
}


static const per_sequence_t Requested_RAB_Parameter_ExtendedMaxBitrateList_sequence_of[1] = {
  { &hf_ranap_Requested_RAB_Parameter_ExtendedMaxBitrateList_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ranap_ExtendedMaxBitrate },
};

static int
dissect_ranap_Requested_RAB_Parameter_ExtendedMaxBitrateList(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_ranap_Requested_RAB_Parameter_ExtendedMaxBitrateList, Requested_RAB_Parameter_ExtendedMaxBitrateList_sequence_of,
                                                  1, maxNrOfSeparateTrafficDirections, FALSE);

  return offset;
}


static const per_sequence_t Requested_RAB_Parameter_ExtendedGuaranteedBitrateList_sequence_of[1] = {
  { &hf_ranap_Requested_RAB_Parameter_ExtendedGuaranteedBitrateList_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ranap_ExtendedGuaranteedBitrate },
};

static int
dissect_ranap_Requested_RAB_Parameter_ExtendedGuaranteedBitrateList(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_ranap_Requested_RAB_Parameter_ExtendedGuaranteedBitrateList, Requested_RAB_Parameter_ExtendedGuaranteedBitrateList_sequence_of,
                                                  1, maxNrOfSeparateTrafficDirections, FALSE);

  return offset;
}


static const per_sequence_t RequestType_sequence[] = {
  { &hf_ranap_event         , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ranap_Event },
  { &hf_ranap_reportArea    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ranap_ReportArea },
  { &hf_ranap_accuracyCode  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ranap_INTEGER_0_127 },
  { NULL, 0, 0, NULL }
};

static int
dissect_ranap_RequestType(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ranap_RequestType, RequestType_sequence);

  return offset;
}


static const value_string ranap_UE_ID_vals[] = {
  {   0, "imsi" },
  {   1, "imei" },
  {   2, "imeisv" },
  { 0, NULL }
};

static const per_choice_t UE_ID_choice[] = {
  {   0, &hf_ranap_imsi          , ASN1_EXTENSION_ROOT    , dissect_ranap_IMSI },
  {   1, &hf_ranap_imei          , ASN1_EXTENSION_ROOT    , dissect_ranap_IMEI },
  {   2, &hf_ranap_imeisv        , ASN1_NOT_EXTENSION_ROOT, dissect_ranap_IMEISV },
  { 0, NULL, 0, NULL }
};

static int
dissect_ranap_UE_ID(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_ranap_UE_ID, UE_ID_choice,
                                 NULL);

  return offset;
}


static const value_string ranap_TraceDepth_vals[] = {
  {   0, "minimum" },
  {   1, "medium" },
  {   2, "maximum" },
  { 0, NULL }
};


static int
dissect_ranap_TraceDepth(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     3, NULL, TRUE, 0, NULL);

  return offset;
}


static const per_sequence_t TracePropagationParameters_sequence[] = {
  { &hf_ranap_traceRecordingSessionReference, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ranap_TraceRecordingSessionReference },
  { &hf_ranap_traceDepth    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ranap_TraceDepth },
  { &hf_ranap_listOfInterfacesToTrace, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ranap_ListOfInterfacesToTrace },
  { &hf_ranap_iE_Extensions , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ranap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_ranap_TracePropagationParameters(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ranap_TracePropagationParameters, TracePropagationParameters_sequence);

  return offset;
}


static const per_sequence_t TraceInformation_sequence[] = {
  { &hf_ranap_traceReference, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ranap_TraceReference },
  { &hf_ranap_ue_identity   , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ranap_UE_ID },
  { &hf_ranap_tracePropagationParameters, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ranap_TracePropagationParameters },
  { &hf_ranap_iE_Extensions , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ranap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_ranap_TraceInformation(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ranap_TraceInformation, TraceInformation_sequence);

  return offset;
}


static const per_sequence_t RNSAPRelocationParameters_sequence[] = {
  { &hf_ranap_rabParmetersList, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ranap_RABParametersList },
  { &hf_ranap_locationReporting, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ranap_LocationReportingTransferInformation },
  { &hf_ranap_traceInformation, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ranap_TraceInformation },
  { &hf_ranap_sourceSAI     , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ranap_SAI },
  { &hf_ranap_iE_Extensions , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ranap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_ranap_RNSAPRelocationParameters(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ranap_RNSAPRelocationParameters, RNSAPRelocationParameters_sequence);

  return offset;
}



static int
dissect_ranap_RRC_Container(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 220 "../../asn1/ranap/ranap.cnf"
  tvbuff_t *rrc_message_tvb=NULL;

  offset = dissect_per_octet_string(tvb, offset, actx, tree, hf_index,
                                       NO_BOUND, NO_BOUND, FALSE, &rrc_message_tvb);


	if ((rrc_message_tvb)&&(tvb_length(rrc_message_tvb)!=0)){
		switch(ProtocolIE_ID){
			case id_Source_ToTarget_TransparentContainer: /* INTEGER ::= 61 */
				/* 9.2.1.30a Source to Target Transparent Container
				 * Note: In the current version of this specification, this IE may
				 * either carry the Source RNC to Target RNC Transparent Container 
				 * or the Source eNB to Target eNB Transparent Container IE as defined in [49]...
				 */
				call_dissector(rrc_s_to_trnc_handle,rrc_message_tvb,actx->pinfo, proto_tree_get_root(tree));
				break;
			case id_Target_ToSource_TransparentContainer: /* INTEGER ::= 63 */
				/* 9.2.1.30b Target to Source Transparent Container
				 * In the current version of this specification, this IE may
				 * either carry the Target RNC to Source RNC Transparent Container 
				 * or the Target eNB to Source eNB Transparent Container IE as defined in [49]...
				 */
				call_dissector(rrc_t_to_srnc_handle,rrc_message_tvb,actx->pinfo, proto_tree_get_root(tree));
				break;
			default:
				break;
		}
	}



  return offset;
}


static const value_string ranap_SAPI_vals[] = {
  {   0, "sapi-0" },
  {   1, "sapi-3" },
  { 0, NULL }
};


static int
dissect_ranap_SAPI(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     2, NULL, TRUE, 0, NULL);

  return offset;
}



static int
dissect_ranap_SessionUpdateID(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 1048575U, NULL, FALSE);

  return offset;
}


static const value_string ranap_SignallingIndication_vals[] = {
  {   0, "signalling" },
  { 0, NULL }
};


static int
dissect_ranap_SignallingIndication(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     1, NULL, TRUE, 0, NULL);

  return offset;
}


static const per_sequence_t SNA_Access_Information_sequence[] = {
  { &hf_ranap_authorisedPLMNs, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ranap_AuthorisedPLMNs },
  { &hf_ranap_iE_Extensions , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ranap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_ranap_SNA_Access_Information(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ranap_SNA_Access_Information, SNA_Access_Information_sequence);

  return offset;
}


const value_string ranap_Service_Handover_vals[] = {
  {   0, "handover-to-GSM-should-be-performed" },
  {   1, "handover-to-GSM-should-not-be-performed" },
  {   2, "handover-to-GSM-shall-not-be-performed" },
  { 0, NULL }
};


int
dissect_ranap_Service_Handover(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     3, NULL, TRUE, 0, NULL);

  return offset;
}



static int
dissect_ranap_Source_ToTarget_TransparentContainer(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 355 "../../asn1/ranap/ranap.cnf"

dissect_ranap_SourceRNC_ToTargetRNC_TransparentContainer(tvb , offset, actx ,tree , hf_ranap_ranap_SourceRNC_ToTargetRNC_TransparentContainer_PDU );



  return offset;
}



static int
dissect_ranap_SourceBSS_ToTargetBSS_TransparentContainer(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_octet_string(tvb, offset, actx, tree, hf_index,
                                       NO_BOUND, NO_BOUND, FALSE, NULL);

  return offset;
}


static const per_sequence_t SourceRNC_ID_sequence[] = {
  { &hf_ranap_pLMNidentity  , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ranap_PLMNidentity },
  { &hf_ranap_rNC_ID        , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ranap_RNC_ID },
  { &hf_ranap_iE_Extensions , ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_ranap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_ranap_SourceRNC_ID(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ranap_SourceRNC_ID, SourceRNC_ID_sequence);

  return offset;
}


static const value_string ranap_SourceID_vals[] = {
  {   0, "sourceRNC-ID" },
  {   1, "sAI" },
  { 0, NULL }
};

static const per_choice_t SourceID_choice[] = {
  {   0, &hf_ranap_sourceRNC_ID  , ASN1_EXTENSION_ROOT    , dissect_ranap_SourceRNC_ID },
  {   1, &hf_ranap_sAI           , ASN1_EXTENSION_ROOT    , dissect_ranap_SAI },
  { 0, NULL, 0, NULL }
};

static int
dissect_ranap_SourceID(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_ranap_SourceID, SourceID_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t SourceRNC_ToTargetRNC_TransparentContainer_sequence[] = {
  { &hf_ranap_rRC_Container , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ranap_RRC_Container },
  { &hf_ranap_numberOfIuInstances, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ranap_NumberOfIuInstances },
  { &hf_ranap_relocationType, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ranap_RelocationType },
  { &hf_ranap_chosenIntegrityProtectionAlgorithm, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ranap_ChosenIntegrityProtectionAlgorithm },
  { &hf_ranap_integrityProtectionKey, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ranap_IntegrityProtectionKey },
  { &hf_ranap_chosenEncryptionAlgorithForSignalling, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ranap_ChosenEncryptionAlgorithm },
  { &hf_ranap_cipheringKey  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ranap_EncryptionKey },
  { &hf_ranap_chosenEncryptionAlgorithForCS, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ranap_ChosenEncryptionAlgorithm },
  { &hf_ranap_chosenEncryptionAlgorithForPS, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ranap_ChosenEncryptionAlgorithm },
  { &hf_ranap_d_RNTI        , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ranap_D_RNTI },
  { &hf_ranap_targetCellId  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ranap_TargetCellId },
  { &hf_ranap_rAB_TrCH_Mapping, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ranap_RAB_TrCH_Mapping },
  { &hf_ranap_iE_Extensions , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ranap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_ranap_SourceRNC_ToTargetRNC_TransparentContainer(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 341 "../../asn1/ranap/ranap.cnf"
/* If SourceRNC-ToTargetRNC-TransparentContainer is called trough 
   dissect_ranap_SourceRNC_ToTargetRNC_TransparentContainer_PDU
   ProtocolIE_ID may be unset
   */
   
   
   ProtocolIE_ID = id_Source_ToTarget_TransparentContainer; 


  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ranap_SourceRNC_ToTargetRNC_TransparentContainer, SourceRNC_ToTargetRNC_TransparentContainer_sequence);

  return offset;
}



static int
dissect_ranap_INTEGER_0_97(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 97U, NULL, FALSE);

  return offset;
}



static int
dissect_ranap_INTEGER_0_34(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 34U, NULL, FALSE);

  return offset;
}



static int
dissect_ranap_INTEGER_1_100(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            1U, 100U, NULL, FALSE);

  return offset;
}


static const value_string ranap_MeasBand_vals[] = {
  {   0, "v6" },
  {   1, "v15" },
  {   2, "v25" },
  {   3, "v50" },
  {   4, "v75" },
  {   5, "v100" },
  { 0, NULL }
};


static int
dissect_ranap_MeasBand(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     6, NULL, FALSE, 0, NULL);

  return offset;
}


static const per_sequence_t EUTRANFrequencies_item_sequence[] = {
  { &hf_ranap_earfcn        , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ranap_INTEGER_0_65535 },
  { &hf_ranap_measBand      , ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_ranap_MeasBand },
  { &hf_ranap_iE_Extensions , ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_ranap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_ranap_EUTRANFrequencies_item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ranap_EUTRANFrequencies_item, EUTRANFrequencies_item_sequence);

  return offset;
}


static const per_sequence_t EUTRANFrequencies_sequence_of[1] = {
  { &hf_ranap_EUTRANFrequencies_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ranap_EUTRANFrequencies_item },
};

static int
dissect_ranap_EUTRANFrequencies(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_ranap_EUTRANFrequencies, EUTRANFrequencies_sequence_of,
                                                  1, maxNrOfEUTRAFreqs, FALSE);

  return offset;
}


static const per_sequence_t IRATmeasurementParameters_sequence[] = {
  { &hf_ranap_measurementDuration, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ranap_INTEGER_1_100 },
  { &hf_ranap_eUTRANFrequencies, ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_ranap_EUTRANFrequencies },
  { &hf_ranap_iE_Extensions , ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_ranap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_ranap_IRATmeasurementParameters(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ranap_IRATmeasurementParameters, IRATmeasurementParameters_sequence);

  return offset;
}


static const per_sequence_t IRAT_Measurement_Configuration_sequence[] = {
  { &hf_ranap_rSRP          , ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_ranap_INTEGER_0_97 },
  { &hf_ranap_rSRQ          , ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_ranap_INTEGER_0_34 },
  { &hf_ranap_iRATmeasurementParameters, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ranap_IRATmeasurementParameters },
  { &hf_ranap_iE_Extensions , ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_ranap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_ranap_IRAT_Measurement_Configuration(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ranap_IRAT_Measurement_Configuration, IRAT_Measurement_Configuration_sequence);

  return offset;
}



static int
dissect_ranap_SubscriberProfileIDforRFP(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            1U, 256U, NULL, FALSE);

  return offset;
}



static int
dissect_ranap_SRB_ID(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            1U, 32U, NULL, FALSE);

  return offset;
}


static const per_sequence_t SRB_TrCH_MappingItem_sequence[] = {
  { &hf_ranap_sRB_ID        , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ranap_SRB_ID },
  { &hf_ranap_trCH_ID       , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ranap_TrCH_ID },
  { &hf_ranap_iE_Extensions , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ranap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_ranap_SRB_TrCH_MappingItem(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ranap_SRB_TrCH_MappingItem, SRB_TrCH_MappingItem_sequence);

  return offset;
}


static const per_sequence_t SRB_TrCH_Mapping_sequence_of[1] = {
  { &hf_ranap_SRB_TrCH_Mapping_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ranap_SRB_TrCH_MappingItem },
};

static int
dissect_ranap_SRB_TrCH_Mapping(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_ranap_SRB_TrCH_Mapping, SRB_TrCH_Mapping_sequence_of,
                                                  1, maxNrOfSRBs, FALSE);

  return offset;
}


static const value_string ranap_SRVCC_HO_Indication_vals[] = {
  {   0, "ps-and-cs" },
  {   1, "cs-only" },
  { 0, NULL }
};


static int
dissect_ranap_SRVCC_HO_Indication(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     2, NULL, TRUE, 0, NULL);

  return offset;
}



static int
dissect_ranap_BIT_STRING_SIZE_128(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_bit_string(tvb, offset, actx, tree, hf_index,
                                     128, 128, FALSE, NULL);

  return offset;
}


static const per_sequence_t SRVCC_Information_sequence[] = {
  { &hf_ranap_nonce         , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ranap_BIT_STRING_SIZE_128 },
  { &hf_ranap_iE_Extensions , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ranap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_ranap_SRVCC_Information(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ranap_SRVCC_Information, SRVCC_Information_sequence);

  return offset;
}


static const value_string ranap_SRVCC_Operation_Possible_vals[] = {
  {   0, "srvcc-possible" },
  { 0, NULL }
};


static int
dissect_ranap_SRVCC_Operation_Possible(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     1, NULL, TRUE, 0, NULL);

  return offset;
}



static int
dissect_ranap_Target_ToSource_TransparentContainer(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 365 "../../asn1/ranap/ranap.cnf"

dissect_ranap_TargetRNC_ToSourceRNC_TransparentContainer(tvb , offset, actx ,tree , hf_ranap_TargetRNC_ToSourceRNC_TransparentContainer_PDU );



  return offset;
}



static int
dissect_ranap_TargetBSS_ToSourceBSS_TransparentContainer(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_octet_string(tvb, offset, actx, tree, hf_index,
                                       NO_BOUND, NO_BOUND, FALSE, NULL);

  return offset;
}


static const value_string ranap_TargetID_vals[] = {
  {   0, "targetRNC-ID" },
  {   1, "cGI" },
  {   2, "targeteNB-ID" },
  { 0, NULL }
};

static const per_choice_t TargetID_choice[] = {
  {   0, &hf_ranap_targetRNC_ID  , ASN1_EXTENSION_ROOT    , dissect_ranap_TargetRNC_ID },
  {   1, &hf_ranap_cGI           , ASN1_EXTENSION_ROOT    , dissect_ranap_CGI },
  {   2, &hf_ranap_targeteNB_ID  , ASN1_NOT_EXTENSION_ROOT, dissect_ranap_TargetENB_ID },
  { 0, NULL, 0, NULL }
};

static int
dissect_ranap_TargetID(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_ranap_TargetID, TargetID_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t TargetRNC_ToSourceRNC_TransparentContainer_sequence[] = {
  { &hf_ranap_rRC_Container , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ranap_RRC_Container },
  { &hf_ranap_d_RNTI        , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ranap_D_RNTI },
  { &hf_ranap_iE_Extensions , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ranap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_ranap_TargetRNC_ToSourceRNC_TransparentContainer(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ranap_TargetRNC_ToSourceRNC_TransparentContainer, TargetRNC_ToSourceRNC_TransparentContainer_sequence);

  return offset;
}



static int
dissect_ranap_TMSI(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_octet_string(tvb, offset, actx, tree, hf_index,
                                       4, 4, FALSE, NULL);

  return offset;
}


static const value_string ranap_TemporaryUE_ID_vals[] = {
  {   0, "tMSI" },
  {   1, "p-TMSI" },
  { 0, NULL }
};

static const per_choice_t TemporaryUE_ID_choice[] = {
  {   0, &hf_ranap_tMSI          , ASN1_EXTENSION_ROOT    , dissect_ranap_TMSI },
  {   1, &hf_ranap_p_TMSI        , ASN1_EXTENSION_ROOT    , dissect_ranap_P_TMSI },
  { 0, NULL, 0, NULL }
};

static int
dissect_ranap_TemporaryUE_ID(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_ranap_TemporaryUE_ID, TemporaryUE_ID_choice,
                                 NULL);

  return offset;
}



static int
dissect_ranap_TimeToMBMSDataTransfer(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_octet_string(tvb, offset, actx, tree, hf_index,
                                       1, 1, FALSE, NULL);

  return offset;
}


static const per_sequence_t TraceRecordingSessionInformation_sequence[] = {
  { &hf_ranap_traceReference, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ranap_TraceReference },
  { &hf_ranap_traceRecordingSessionReference, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ranap_TraceRecordingSessionReference },
  { &hf_ranap_iE_Extensions , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ranap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_ranap_TraceRecordingSessionInformation(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ranap_TraceRecordingSessionInformation, TraceRecordingSessionInformation_sequence);

  return offset;
}



static int
dissect_ranap_TraceType(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_octet_string(tvb, offset, actx, tree, hf_index,
                                       1, 1, FALSE, NULL);

  return offset;
}



static int
dissect_ranap_TransportLayerAddress(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 301 "../../asn1/ranap/ranap.cnf"
  tvbuff_t *parameter_tvb=NULL;
  proto_tree *item;
  proto_tree *subtree, *nsap_tree;
  gint tvb_len;
  
  offset = dissect_per_bit_string(tvb, offset, actx, tree, hf_index,
                                     1, 160, TRUE, &parameter_tvb);

  if (!parameter_tvb)
    return offset;
	/* Get the length */
	tvb_len = tvb_length(parameter_tvb);
	subtree = proto_item_add_subtree(actx->created_item, ett_ranap_TransportLayerAddress);
	if (tvb_len==4){
		/* IPv4 */
		 proto_tree_add_item(subtree, hf_ranap_transportLayerAddress_ipv4, parameter_tvb, 0, tvb_len, ENC_NA);
	}
	if (tvb_len==16){
		/* IPv6 */
		 proto_tree_add_item(subtree, hf_ranap_transportLayerAddress_ipv6, parameter_tvb, 0, tvb_len, ENC_NA);
	}
	if (tvb_len==20){
		item = proto_tree_add_item(subtree, hf_ranap_transportLayerAddress_nsap, parameter_tvb, 0, tvb_len, ENC_NA);
		nsap_tree = proto_item_add_subtree(item, ett_ranap_TransportLayerAddress_nsap);
		dissect_nsap(parameter_tvb, 0, 20, nsap_tree);
	}
	


  return offset;
}



static int
dissect_ranap_TriggerID(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_octet_string(tvb, offset, actx, tree, hf_index,
                                       3, 22, FALSE, NULL);

  return offset;
}


static const value_string ranap_TypeOfError_vals[] = {
  {   0, "not-understood" },
  {   1, "missing" },
  { 0, NULL }
};


static int
dissect_ranap_TypeOfError(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     2, NULL, TRUE, 0, NULL);

  return offset;
}



static int
dissect_ranap_UE_AggregateMaximumBitRateDownlink(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer_64b(tvb, offset, actx, tree, hf_index,
                                                            1U, 1000000000U, NULL, FALSE);

  return offset;
}



static int
dissect_ranap_UE_AggregateMaximumBitRateUplink(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer_64b(tvb, offset, actx, tree, hf_index,
                                                            1U, 1000000000U, NULL, FALSE);

  return offset;
}


static const per_sequence_t UE_AggregateMaximumBitRate_sequence[] = {
  { &hf_ranap_uE_AggregateMaximumBitRateDownlink, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ranap_UE_AggregateMaximumBitRateDownlink },
  { &hf_ranap_uE_AggregateMaximumBitRateUplink, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ranap_UE_AggregateMaximumBitRateUplink },
  { NULL, 0, 0, NULL }
};

static int
dissect_ranap_UE_AggregateMaximumBitRate(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ranap_UE_AggregateMaximumBitRate, UE_AggregateMaximumBitRate_sequence);

  return offset;
}



static int
dissect_ranap_UE_History_Information(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_octet_string(tvb, offset, actx, tree, hf_index,
                                       NO_BOUND, NO_BOUND, FALSE, NULL);

  return offset;
}



static int
dissect_ranap_UESBI_IuA(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_bit_string(tvb, offset, actx, tree, hf_index,
                                     1, 128, FALSE, NULL);

  return offset;
}



static int
dissect_ranap_UESBI_IuB(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_bit_string(tvb, offset, actx, tree, hf_index,
                                     1, 128, FALSE, NULL);

  return offset;
}


static const per_sequence_t UESBI_Iu_sequence[] = {
  { &hf_ranap_uESBI_IuA     , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ranap_UESBI_IuA },
  { &hf_ranap_uESBI_IuB     , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ranap_UESBI_IuB },
  { &hf_ranap_iE_Extensions , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ranap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_ranap_UESBI_Iu(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ranap_UESBI_Iu, UESBI_Iu_sequence);

  return offset;
}



static int
dissect_ranap_UL_GTP_PDU_SequenceNumber(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 65535U, NULL, FALSE);

  return offset;
}



static int
dissect_ranap_UL_N_PDU_SequenceNumber(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 65535U, NULL, FALSE);

  return offset;
}



static int
dissect_ranap_UP_ModeVersions(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_bit_string(tvb, offset, actx, tree, hf_index,
                                     16, 16, FALSE, NULL);

  return offset;
}


static const value_string ranap_UserPlaneMode_vals[] = {
  {   0, "transparent-mode" },
  {   1, "support-mode-for-predefined-SDU-sizes" },
  { 0, NULL }
};


static int
dissect_ranap_UserPlaneMode(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     2, NULL, TRUE, 0, NULL);

  return offset;
}



static int
dissect_ranap_INTEGER_0_359(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 359U, NULL, FALSE);

  return offset;
}



static int
dissect_ranap_INTEGER_0_2047(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 2047U, NULL, FALSE);

  return offset;
}


static const per_sequence_t HorizontalSpeedAndBearing_sequence[] = {
  { &hf_ranap_bearing       , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ranap_INTEGER_0_359 },
  { &hf_ranap_horizontalSpeed, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ranap_INTEGER_0_2047 },
  { NULL, 0, 0, NULL }
};

static int
dissect_ranap_HorizontalSpeedAndBearing(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ranap_HorizontalSpeedAndBearing, HorizontalSpeedAndBearing_sequence);

  return offset;
}


static const per_sequence_t HorizontalVelocity_sequence[] = {
  { &hf_ranap_horizontalSpeedAndBearing, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ranap_HorizontalSpeedAndBearing },
  { &hf_ranap_iE_Extensions , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ranap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_ranap_HorizontalVelocity(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ranap_HorizontalVelocity, HorizontalVelocity_sequence);

  return offset;
}



static int
dissect_ranap_INTEGER_0_255(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 255U, NULL, FALSE);

  return offset;
}


static const value_string ranap_VerticalSpeedDirection_vals[] = {
  {   0, "upward" },
  {   1, "downward" },
  { 0, NULL }
};


static int
dissect_ranap_VerticalSpeedDirection(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     2, NULL, FALSE, 0, NULL);

  return offset;
}


static const per_sequence_t VerticalVelocity_sequence[] = {
  { &hf_ranap_veritcalSpeed , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ranap_INTEGER_0_255 },
  { &hf_ranap_veritcalSpeedDirection, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ranap_VerticalSpeedDirection },
  { NULL, 0, 0, NULL }
};

static int
dissect_ranap_VerticalVelocity(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ranap_VerticalVelocity, VerticalVelocity_sequence);

  return offset;
}


static const per_sequence_t HorizontalWithVerticalVelocity_sequence[] = {
  { &hf_ranap_horizontalSpeedAndBearing, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ranap_HorizontalSpeedAndBearing },
  { &hf_ranap_veritcalVelocity, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ranap_VerticalVelocity },
  { &hf_ranap_iE_Extensions , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ranap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_ranap_HorizontalWithVerticalVelocity(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ranap_HorizontalWithVerticalVelocity, HorizontalWithVerticalVelocity_sequence);

  return offset;
}


static const per_sequence_t HorizontalVelocityWithUncertainty_sequence[] = {
  { &hf_ranap_horizontalSpeedAndBearing, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ranap_HorizontalSpeedAndBearing },
  { &hf_ranap_uncertaintySpeed, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ranap_INTEGER_0_255 },
  { &hf_ranap_iE_Extensions , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ranap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_ranap_HorizontalVelocityWithUncertainty(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ranap_HorizontalVelocityWithUncertainty, HorizontalVelocityWithUncertainty_sequence);

  return offset;
}


static const per_sequence_t HorizontalWithVerticalVelocityAndUncertainty_sequence[] = {
  { &hf_ranap_horizontalSpeedAndBearing, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ranap_HorizontalSpeedAndBearing },
  { &hf_ranap_veritcalVelocity, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ranap_VerticalVelocity },
  { &hf_ranap_horizontalUncertaintySpeed, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ranap_INTEGER_0_255 },
  { &hf_ranap_verticalUncertaintySpeed, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ranap_INTEGER_0_255 },
  { &hf_ranap_iE_Extensions , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ranap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_ranap_HorizontalWithVerticalVelocityAndUncertainty(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ranap_HorizontalWithVerticalVelocityAndUncertainty, HorizontalWithVerticalVelocityAndUncertainty_sequence);

  return offset;
}


static const value_string ranap_VelocityEstimate_vals[] = {
  {   0, "horizontalVelocity" },
  {   1, "horizontalWithVerticalVelocity" },
  {   2, "horizontalVelocityWithUncertainty" },
  {   3, "horizontalWithVeritcalVelocityAndUncertainty" },
  { 0, NULL }
};

static const per_choice_t VelocityEstimate_choice[] = {
  {   0, &hf_ranap_horizontalVelocity, ASN1_EXTENSION_ROOT    , dissect_ranap_HorizontalVelocity },
  {   1, &hf_ranap_horizontalWithVerticalVelocity, ASN1_EXTENSION_ROOT    , dissect_ranap_HorizontalWithVerticalVelocity },
  {   2, &hf_ranap_horizontalVelocityWithUncertainty, ASN1_EXTENSION_ROOT    , dissect_ranap_HorizontalVelocityWithUncertainty },
  {   3, &hf_ranap_horizontalWithVeritcalVelocityAndUncertainty, ASN1_EXTENSION_ROOT    , dissect_ranap_HorizontalWithVerticalVelocityAndUncertainty },
  { 0, NULL, 0, NULL }
};

static int
dissect_ranap_VelocityEstimate(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_ranap_VelocityEstimate, VelocityEstimate_choice,
                                 NULL);

  return offset;
}



static int
dissect_ranap_RAB_IE_ContainerList(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 141 "../../asn1/ranap/ranap.cnf"
  asn1_stack_frame_push(actx, "ProtocolIE-ContainerList");
  asn1_param_push_integer(actx, 1);
  asn1_param_push_integer(actx, maxNrOfRABs);
  offset = dissect_ranap_ProtocolIE_ContainerList(tvb, offset, actx, tree, hf_index);

  asn1_stack_frame_pop(actx, "ProtocolIE-ContainerList");


  return offset;
}



static int
dissect_ranap_RAB_IE_ContainerPairList(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 149 "../../asn1/ranap/ranap.cnf"
  asn1_stack_frame_push(actx, "ProtocolIE-ContainerPairList");
  asn1_param_push_integer(actx, 1);
  asn1_param_push_integer(actx, maxNrOfRABs);
  offset = dissect_ranap_ProtocolIE_ContainerPairList(tvb, offset, actx, tree, hf_index);

  asn1_stack_frame_pop(actx, "ProtocolIE-ContainerPairList");


  return offset;
}



static int
dissect_ranap_IuSigConId_IE_ContainerList(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 166 "../../asn1/ranap/ranap.cnf"
  asn1_stack_frame_push(actx, "ProtocolIE-ContainerList");
  asn1_param_push_integer(actx, 1);
  asn1_param_push_integer(actx, maxNrOfIuSigConIds);
  offset = dissect_ranap_ProtocolIE_ContainerList(tvb, offset, actx, tree, hf_index);

  asn1_stack_frame_pop(actx, "ProtocolIE-ContainerList");


  return offset;
}



static int
dissect_ranap_DirectTransfer_IE_ContainerList(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 174 "../../asn1/ranap/ranap.cnf"
  asn1_stack_frame_push(actx, "ProtocolIE-ContainerList");
  asn1_param_push_integer(actx, 1);
  asn1_param_push_integer(actx, maxNrOfDTs);
  offset = dissect_ranap_ProtocolIE_ContainerList(tvb, offset, actx, tree, hf_index);

  asn1_stack_frame_pop(actx, "ProtocolIE-ContainerList");


  return offset;
}


static const per_sequence_t Iu_ReleaseCommand_sequence[] = {
  { &hf_ranap_protocolIEs   , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ranap_ProtocolIE_Container },
  { &hf_ranap_protocolExtensions, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ranap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_ranap_Iu_ReleaseCommand(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ranap_Iu_ReleaseCommand, Iu_ReleaseCommand_sequence);

  return offset;
}


static const per_sequence_t Iu_ReleaseComplete_sequence[] = {
  { &hf_ranap_protocolIEs   , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ranap_ProtocolIE_Container },
  { &hf_ranap_protocolExtensions, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ranap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_ranap_Iu_ReleaseComplete(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ranap_Iu_ReleaseComplete, Iu_ReleaseComplete_sequence);

  return offset;
}



static int
dissect_ranap_RAB_DataVolumeReportList(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ranap_RAB_IE_ContainerList(tvb, offset, actx, tree, hf_index);

  return offset;
}


static const per_sequence_t DataVolumeList_item_sequence[] = {
  { &hf_ranap_dl_UnsuccessfullyTransmittedDataVolume, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ranap_UnsuccessfullyTransmittedDataVolume },
  { &hf_ranap_dataVolumeReference, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ranap_DataVolumeReference },
  { &hf_ranap_iE_Extensions , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ranap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_ranap_DataVolumeList_item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ranap_DataVolumeList_item, DataVolumeList_item_sequence);

  return offset;
}


static const per_sequence_t DataVolumeList_sequence_of[1] = {
  { &hf_ranap_DataVolumeList_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ranap_DataVolumeList_item },
};

static int
dissect_ranap_DataVolumeList(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_ranap_DataVolumeList, DataVolumeList_sequence_of,
                                                  1, maxNrOfVol, FALSE);

  return offset;
}


static const per_sequence_t RAB_DataVolumeReportItem_sequence[] = {
  { &hf_ranap_rAB_ID        , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ranap_RAB_ID },
  { &hf_ranap_rab_dl_UnsuccessfullyTransmittedDataVolume, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ranap_DataVolumeList },
  { &hf_ranap_iE_Extensions , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ranap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_ranap_RAB_DataVolumeReportItem(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ranap_RAB_DataVolumeReportItem, RAB_DataVolumeReportItem_sequence);

  return offset;
}



static int
dissect_ranap_RAB_ReleasedList_IuRelComp(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ranap_RAB_IE_ContainerList(tvb, offset, actx, tree, hf_index);

  return offset;
}


static const per_sequence_t RAB_ReleasedItem_IuRelComp_sequence[] = {
  { &hf_ranap_rAB_ID        , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ranap_RAB_ID },
  { &hf_ranap_dL_GTP_PDU_SequenceNumber, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ranap_DL_GTP_PDU_SequenceNumber },
  { &hf_ranap_uL_GTP_PDU_SequenceNumber, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ranap_UL_GTP_PDU_SequenceNumber },
  { &hf_ranap_iE_Extensions , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ranap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_ranap_RAB_ReleasedItem_IuRelComp(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ranap_RAB_ReleasedItem_IuRelComp, RAB_ReleasedItem_IuRelComp_sequence);

  return offset;
}


static const per_sequence_t RelocationRequired_sequence[] = {
  { &hf_ranap_protocolIEs   , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ranap_ProtocolIE_Container },
  { &hf_ranap_protocolExtensions, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ranap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_ranap_RelocationRequired(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ranap_RelocationRequired, RelocationRequired_sequence);

  return offset;
}


static const per_sequence_t RelocationCommand_sequence[] = {
  { &hf_ranap_protocolIEs   , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ranap_ProtocolIE_Container },
  { &hf_ranap_protocolExtensions, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ranap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_ranap_RelocationCommand(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ranap_RelocationCommand, RelocationCommand_sequence);

  return offset;
}



static int
dissect_ranap_RAB_RelocationReleaseList(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ranap_RAB_IE_ContainerList(tvb, offset, actx, tree, hf_index);

  return offset;
}


static const per_sequence_t RAB_RelocationReleaseItem_sequence[] = {
  { &hf_ranap_rAB_ID        , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ranap_RAB_ID },
  { &hf_ranap_iE_Extensions , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ranap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_ranap_RAB_RelocationReleaseItem(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ranap_RAB_RelocationReleaseItem, RAB_RelocationReleaseItem_sequence);

  return offset;
}



static int
dissect_ranap_RAB_DataForwardingList(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ranap_RAB_IE_ContainerList(tvb, offset, actx, tree, hf_index);

  return offset;
}


static const per_sequence_t RAB_DataForwardingItem_sequence[] = {
  { &hf_ranap_rAB_ID        , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ranap_RAB_ID },
  { &hf_ranap_transportLayerAddress, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ranap_TransportLayerAddress },
  { &hf_ranap_iuTransportAssociation, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ranap_IuTransportAssociation },
  { &hf_ranap_iE_Extensions , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ranap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_ranap_RAB_DataForwardingItem(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ranap_RAB_DataForwardingItem, RAB_DataForwardingItem_sequence);

  return offset;
}


static const per_sequence_t RelocationPreparationFailure_sequence[] = {
  { &hf_ranap_protocolIEs   , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ranap_ProtocolIE_Container },
  { &hf_ranap_protocolExtensions, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ranap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_ranap_RelocationPreparationFailure(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ranap_RelocationPreparationFailure, RelocationPreparationFailure_sequence);

  return offset;
}


static const per_sequence_t RelocationRequest_sequence[] = {
  { &hf_ranap_protocolIEs   , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ranap_ProtocolIE_Container },
  { &hf_ranap_protocolExtensions, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ranap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_ranap_RelocationRequest(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ranap_RelocationRequest, RelocationRequest_sequence);

  return offset;
}



static int
dissect_ranap_RAB_SetupList_RelocReq(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ranap_RAB_IE_ContainerList(tvb, offset, actx, tree, hf_index);

  return offset;
}


static const per_sequence_t UserPlaneInformation_sequence[] = {
  { &hf_ranap_userPlaneMode , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ranap_UserPlaneMode },
  { &hf_ranap_uP_ModeVersions, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ranap_UP_ModeVersions },
  { &hf_ranap_iE_Extensions , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ranap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_ranap_UserPlaneInformation(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ranap_UserPlaneInformation, UserPlaneInformation_sequence);

  return offset;
}


static const per_sequence_t RAB_SetupItem_RelocReq_sequence[] = {
  { &hf_ranap_rAB_ID        , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ranap_RAB_ID },
  { &hf_ranap_nAS_SynchronisationIndicator, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ranap_NAS_SynchronisationIndicator },
  { &hf_ranap_rAB_Parameters, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ranap_RAB_Parameters },
  { &hf_ranap_dataVolumeReportingIndication, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ranap_DataVolumeReportingIndication },
  { &hf_ranap_pDP_TypeInformation, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ranap_PDP_TypeInformation },
  { &hf_ranap_userPlaneInformation, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ranap_UserPlaneInformation },
  { &hf_ranap_transportLayerAddress, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ranap_TransportLayerAddress },
  { &hf_ranap_iuTransportAssociation, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ranap_IuTransportAssociation },
  { &hf_ranap_service_Handover, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ranap_Service_Handover },
  { &hf_ranap_iE_Extensions , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ranap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_ranap_RAB_SetupItem_RelocReq(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ranap_RAB_SetupItem_RelocReq, RAB_SetupItem_RelocReq_sequence);

  return offset;
}


static const per_sequence_t JoinedMBMSBearerService_IEs_item_sequence[] = {
  { &hf_ranap_tMGI          , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ranap_TMGI },
  { &hf_ranap_mBMS_PTP_RAB_ID, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ranap_MBMS_PTP_RAB_ID },
  { &hf_ranap_iE_Extensions , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ranap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_ranap_JoinedMBMSBearerService_IEs_item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ranap_JoinedMBMSBearerService_IEs_item, JoinedMBMSBearerService_IEs_item_sequence);

  return offset;
}


static const per_sequence_t JoinedMBMSBearerService_IEs_sequence_of[1] = {
  { &hf_ranap_JoinedMBMSBearerService_IEs_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ranap_JoinedMBMSBearerService_IEs_item },
};

static int
dissect_ranap_JoinedMBMSBearerService_IEs(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_ranap_JoinedMBMSBearerService_IEs, JoinedMBMSBearerService_IEs_sequence_of,
                                                  1, maxnoofMulticastServicesPerUE, FALSE);

  return offset;
}


static const per_sequence_t CNMBMSLinkingInformation_sequence[] = {
  { &hf_ranap_joinedMBMSBearerService_IEs, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ranap_JoinedMBMSBearerService_IEs },
  { &hf_ranap_iE_Extensions , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ranap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_ranap_CNMBMSLinkingInformation(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ranap_CNMBMSLinkingInformation, CNMBMSLinkingInformation_sequence);

  return offset;
}


static const per_sequence_t RelocationRequestAcknowledge_sequence[] = {
  { &hf_ranap_protocolIEs   , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ranap_ProtocolIE_Container },
  { &hf_ranap_protocolExtensions, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ranap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_ranap_RelocationRequestAcknowledge(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ranap_RelocationRequestAcknowledge, RelocationRequestAcknowledge_sequence);

  return offset;
}



static int
dissect_ranap_RAB_SetupList_RelocReqAck(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ranap_RAB_IE_ContainerList(tvb, offset, actx, tree, hf_index);

  return offset;
}


static const per_sequence_t RAB_SetupItem_RelocReqAck_sequence[] = {
  { &hf_ranap_rAB_ID        , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ranap_RAB_ID },
  { &hf_ranap_transportLayerAddress, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ranap_TransportLayerAddress },
  { &hf_ranap_iuTransportAssociation, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ranap_IuTransportAssociation },
  { &hf_ranap_iE_Extensions , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ranap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_ranap_RAB_SetupItem_RelocReqAck(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ranap_RAB_SetupItem_RelocReqAck, RAB_SetupItem_RelocReqAck_sequence);

  return offset;
}



static int
dissect_ranap_RAB_FailedList(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ranap_RAB_IE_ContainerList(tvb, offset, actx, tree, hf_index);

  return offset;
}


static const per_sequence_t RAB_FailedItem_sequence[] = {
  { &hf_ranap_rAB_ID        , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ranap_RAB_ID },
  { &hf_ranap_cause         , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ranap_Cause },
  { &hf_ranap_iE_Extensions , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ranap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_ranap_RAB_FailedItem(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ranap_RAB_FailedItem, RAB_FailedItem_sequence);

  return offset;
}


static const per_sequence_t RelocationFailure_sequence[] = {
  { &hf_ranap_protocolIEs   , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ranap_ProtocolIE_Container },
  { &hf_ranap_protocolExtensions, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ranap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_ranap_RelocationFailure(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ranap_RelocationFailure, RelocationFailure_sequence);

  return offset;
}


static const per_sequence_t RelocationCancel_sequence[] = {
  { &hf_ranap_protocolIEs   , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ranap_ProtocolIE_Container },
  { &hf_ranap_protocolExtensions, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ranap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_ranap_RelocationCancel(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ranap_RelocationCancel, RelocationCancel_sequence);

  return offset;
}


static const per_sequence_t RelocationCancelAcknowledge_sequence[] = {
  { &hf_ranap_protocolIEs   , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ranap_ProtocolIE_Container },
  { &hf_ranap_protocolExtensions, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ranap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_ranap_RelocationCancelAcknowledge(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ranap_RelocationCancelAcknowledge, RelocationCancelAcknowledge_sequence);

  return offset;
}


static const per_sequence_t SRNS_ContextRequest_sequence[] = {
  { &hf_ranap_protocolIEs   , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ranap_ProtocolIE_Container },
  { &hf_ranap_protocolExtensions, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ranap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_ranap_SRNS_ContextRequest(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ranap_SRNS_ContextRequest, SRNS_ContextRequest_sequence);

  return offset;
}



static int
dissect_ranap_RAB_DataForwardingList_SRNS_CtxReq(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ranap_RAB_IE_ContainerList(tvb, offset, actx, tree, hf_index);

  return offset;
}


static const per_sequence_t RAB_DataForwardingItem_SRNS_CtxReq_sequence[] = {
  { &hf_ranap_rAB_ID        , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ranap_RAB_ID },
  { &hf_ranap_iE_Extensions , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ranap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_ranap_RAB_DataForwardingItem_SRNS_CtxReq(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ranap_RAB_DataForwardingItem_SRNS_CtxReq, RAB_DataForwardingItem_SRNS_CtxReq_sequence);

  return offset;
}


static const per_sequence_t SRNS_ContextResponse_sequence[] = {
  { &hf_ranap_protocolIEs   , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ranap_ProtocolIE_Container },
  { &hf_ranap_protocolExtensions, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ranap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_ranap_SRNS_ContextResponse(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ranap_SRNS_ContextResponse, SRNS_ContextResponse_sequence);

  return offset;
}



static int
dissect_ranap_RAB_ContextList(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ranap_RAB_IE_ContainerList(tvb, offset, actx, tree, hf_index);

  return offset;
}


static const per_sequence_t RAB_ContextItem_sequence[] = {
  { &hf_ranap_rAB_ID        , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ranap_RAB_ID },
  { &hf_ranap_dl_GTP_PDU_SequenceNumber, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ranap_DL_GTP_PDU_SequenceNumber },
  { &hf_ranap_ul_GTP_PDU_SequenceNumber, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ranap_UL_GTP_PDU_SequenceNumber },
  { &hf_ranap_dl_N_PDU_SequenceNumber, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ranap_DL_N_PDU_SequenceNumber },
  { &hf_ranap_ul_N_PDU_SequenceNumber, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ranap_UL_N_PDU_SequenceNumber },
  { &hf_ranap_iE_Extensions , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ranap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_ranap_RAB_ContextItem(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ranap_RAB_ContextItem, RAB_ContextItem_sequence);

  return offset;
}



static int
dissect_ranap_RAB_ContextFailedtoTransferList(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ranap_RAB_IE_ContainerList(tvb, offset, actx, tree, hf_index);

  return offset;
}


static const per_sequence_t RABs_ContextFailedtoTransferItem_sequence[] = {
  { &hf_ranap_rAB_ID        , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ranap_RAB_ID },
  { &hf_ranap_cause         , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ranap_Cause },
  { &hf_ranap_iE_Extensions , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ranap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_ranap_RABs_ContextFailedtoTransferItem(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ranap_RABs_ContextFailedtoTransferItem, RABs_ContextFailedtoTransferItem_sequence);

  return offset;
}


static const per_sequence_t SecurityModeCommand_sequence[] = {
  { &hf_ranap_protocolIEs   , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ranap_ProtocolIE_Container },
  { &hf_ranap_protocolExtensions, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ranap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_ranap_SecurityModeCommand(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ranap_SecurityModeCommand, SecurityModeCommand_sequence);

  return offset;
}


static const per_sequence_t SecurityModeComplete_sequence[] = {
  { &hf_ranap_protocolIEs   , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ranap_ProtocolIE_Container },
  { &hf_ranap_protocolExtensions, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ranap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_ranap_SecurityModeComplete(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ranap_SecurityModeComplete, SecurityModeComplete_sequence);

  return offset;
}


static const per_sequence_t SecurityModeReject_sequence[] = {
  { &hf_ranap_protocolIEs   , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ranap_ProtocolIE_Container },
  { &hf_ranap_protocolExtensions, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ranap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_ranap_SecurityModeReject(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ranap_SecurityModeReject, SecurityModeReject_sequence);

  return offset;
}


static const per_sequence_t DataVolumeReportRequest_sequence[] = {
  { &hf_ranap_protocolIEs   , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ranap_ProtocolIE_Container },
  { &hf_ranap_protocolExtensions, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ranap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_ranap_DataVolumeReportRequest(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ranap_DataVolumeReportRequest, DataVolumeReportRequest_sequence);

  return offset;
}



static int
dissect_ranap_RAB_DataVolumeReportRequestList(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ranap_RAB_IE_ContainerList(tvb, offset, actx, tree, hf_index);

  return offset;
}


static const per_sequence_t RAB_DataVolumeReportRequestItem_sequence[] = {
  { &hf_ranap_rAB_ID        , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ranap_RAB_ID },
  { &hf_ranap_iE_Extensions , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ranap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_ranap_RAB_DataVolumeReportRequestItem(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ranap_RAB_DataVolumeReportRequestItem, RAB_DataVolumeReportRequestItem_sequence);

  return offset;
}


static const per_sequence_t DataVolumeReport_sequence[] = {
  { &hf_ranap_protocolIEs   , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ranap_ProtocolIE_Container },
  { &hf_ranap_protocolExtensions, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ranap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_ranap_DataVolumeReport(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ranap_DataVolumeReport, DataVolumeReport_sequence);

  return offset;
}



static int
dissect_ranap_RAB_FailedtoReportList(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ranap_RAB_IE_ContainerList(tvb, offset, actx, tree, hf_index);

  return offset;
}


static const per_sequence_t RABs_failed_to_reportItem_sequence[] = {
  { &hf_ranap_rAB_ID        , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ranap_RAB_ID },
  { &hf_ranap_cause         , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ranap_Cause },
  { &hf_ranap_iE_Extensions , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ranap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_ranap_RABs_failed_to_reportItem(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ranap_RABs_failed_to_reportItem, RABs_failed_to_reportItem_sequence);

  return offset;
}


static const per_sequence_t Reset_sequence[] = {
  { &hf_ranap_protocolIEs   , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ranap_ProtocolIE_Container },
  { &hf_ranap_protocolExtensions, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ranap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_ranap_Reset(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ranap_Reset, Reset_sequence);

  return offset;
}


static const per_sequence_t ResetAcknowledge_sequence[] = {
  { &hf_ranap_protocolIEs   , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ranap_ProtocolIE_Container },
  { &hf_ranap_protocolExtensions, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ranap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_ranap_ResetAcknowledge(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ranap_ResetAcknowledge, ResetAcknowledge_sequence);

  return offset;
}


static const per_sequence_t ResetResource_sequence[] = {
  { &hf_ranap_protocolIEs   , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ranap_ProtocolIE_Container },
  { &hf_ranap_protocolExtensions, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ranap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_ranap_ResetResource(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ranap_ResetResource, ResetResource_sequence);

  return offset;
}



static int
dissect_ranap_ResetResourceList(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ranap_IuSigConId_IE_ContainerList(tvb, offset, actx, tree, hf_index);

  return offset;
}


static const per_sequence_t ResetResourceItem_sequence[] = {
  { &hf_ranap_iuSigConId    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ranap_IuSignallingConnectionIdentifier },
  { &hf_ranap_iE_Extensions , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ranap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_ranap_ResetResourceItem(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ranap_ResetResourceItem, ResetResourceItem_sequence);

  return offset;
}


static const per_sequence_t ResetResourceAcknowledge_sequence[] = {
  { &hf_ranap_protocolIEs   , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ranap_ProtocolIE_Container },
  { &hf_ranap_protocolExtensions, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ranap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_ranap_ResetResourceAcknowledge(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ranap_ResetResourceAcknowledge, ResetResourceAcknowledge_sequence);

  return offset;
}



static int
dissect_ranap_ResetResourceAckList(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ranap_IuSigConId_IE_ContainerList(tvb, offset, actx, tree, hf_index);

  return offset;
}


static const per_sequence_t ResetResourceAckItem_sequence[] = {
  { &hf_ranap_iuSigConId    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ranap_IuSignallingConnectionIdentifier },
  { &hf_ranap_iE_Extensions , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ranap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_ranap_ResetResourceAckItem(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ranap_ResetResourceAckItem, ResetResourceAckItem_sequence);

  return offset;
}


static const per_sequence_t RAB_ReleaseRequest_sequence[] = {
  { &hf_ranap_protocolIEs   , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ranap_ProtocolIE_Container },
  { &hf_ranap_protocolExtensions, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ranap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_ranap_RAB_ReleaseRequest(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ranap_RAB_ReleaseRequest, RAB_ReleaseRequest_sequence);

  return offset;
}



static int
dissect_ranap_RAB_ReleaseList(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ranap_RAB_IE_ContainerList(tvb, offset, actx, tree, hf_index);

  return offset;
}


static const per_sequence_t RAB_ReleaseItem_sequence[] = {
  { &hf_ranap_rAB_ID        , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ranap_RAB_ID },
  { &hf_ranap_cause         , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ranap_Cause },
  { &hf_ranap_iE_Extensions , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ranap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_ranap_RAB_ReleaseItem(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ranap_RAB_ReleaseItem, RAB_ReleaseItem_sequence);

  return offset;
}


static const per_sequence_t Iu_ReleaseRequest_sequence[] = {
  { &hf_ranap_protocolIEs   , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ranap_ProtocolIE_Container },
  { &hf_ranap_protocolExtensions, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ranap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_ranap_Iu_ReleaseRequest(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ranap_Iu_ReleaseRequest, Iu_ReleaseRequest_sequence);

  return offset;
}


static const per_sequence_t RelocationDetect_sequence[] = {
  { &hf_ranap_protocolIEs   , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ranap_ProtocolIE_Container },
  { &hf_ranap_protocolExtensions, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ranap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_ranap_RelocationDetect(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ranap_RelocationDetect, RelocationDetect_sequence);

  return offset;
}


static const per_sequence_t RelocationComplete_sequence[] = {
  { &hf_ranap_protocolIEs   , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ranap_ProtocolIE_Container },
  { &hf_ranap_protocolExtensions, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ranap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_ranap_RelocationComplete(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ranap_RelocationComplete, RelocationComplete_sequence);

  return offset;
}


static const per_sequence_t EnhancedRelocationCompleteRequest_sequence[] = {
  { &hf_ranap_protocolIEs   , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ranap_ProtocolIE_Container },
  { &hf_ranap_protocolExtensions, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ranap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_ranap_EnhancedRelocationCompleteRequest(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ranap_EnhancedRelocationCompleteRequest, EnhancedRelocationCompleteRequest_sequence);

  return offset;
}



static int
dissect_ranap_RAB_SetupList_EnhancedRelocCompleteReq(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ranap_RAB_IE_ContainerList(tvb, offset, actx, tree, hf_index);

  return offset;
}


static const per_sequence_t RAB_SetupItem_EnhancedRelocCompleteReq_sequence[] = {
  { &hf_ranap_rAB_ID        , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ranap_RAB_ID },
  { &hf_ranap_transportLayerAddressReq1, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ranap_TransportLayerAddress },
  { &hf_ranap_iuTransportAssociationReq1, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ranap_IuTransportAssociation },
  { &hf_ranap_ass_RAB_Parameters, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ranap_Ass_RAB_Parameters },
  { &hf_ranap_iE_Extensions , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ranap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_ranap_RAB_SetupItem_EnhancedRelocCompleteReq(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ranap_RAB_SetupItem_EnhancedRelocCompleteReq, RAB_SetupItem_EnhancedRelocCompleteReq_sequence);

  return offset;
}


static const per_sequence_t EnhancedRelocationCompleteResponse_sequence[] = {
  { &hf_ranap_protocolIEs   , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ranap_ProtocolIE_Container },
  { &hf_ranap_protocolExtensions, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ranap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_ranap_EnhancedRelocationCompleteResponse(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ranap_EnhancedRelocationCompleteResponse, EnhancedRelocationCompleteResponse_sequence);

  return offset;
}



static int
dissect_ranap_RAB_SetupList_EnhancedRelocCompleteRes(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ranap_RAB_IE_ContainerList(tvb, offset, actx, tree, hf_index);

  return offset;
}



static int
dissect_ranap_RAB_ToBeReleasedList_EnhancedRelocCompleteRes(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ranap_RAB_IE_ContainerList(tvb, offset, actx, tree, hf_index);

  return offset;
}


static const per_sequence_t RAB_SetupItem_EnhancedRelocCompleteRes_sequence[] = {
  { &hf_ranap_rAB_ID        , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ranap_RAB_ID },
  { &hf_ranap_rAB_Parameters, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ranap_RAB_Parameters },
  { &hf_ranap_userPlaneInformation, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ranap_UserPlaneInformation },
  { &hf_ranap_transportLayerAddressRes1, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ranap_TransportLayerAddress },
  { &hf_ranap_iuTransportAssociationRes1, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ranap_IuTransportAssociation },
  { &hf_ranap_rab2beReleasedList, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ranap_RAB_ToBeReleasedList_EnhancedRelocCompleteRes },
  { &hf_ranap_iE_Extensions , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ranap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_ranap_RAB_SetupItem_EnhancedRelocCompleteRes(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ranap_RAB_SetupItem_EnhancedRelocCompleteRes, RAB_SetupItem_EnhancedRelocCompleteRes_sequence);

  return offset;
}


static const per_sequence_t RAB_ToBeReleasedItem_EnhancedRelocCompleteRes_sequence[] = {
  { &hf_ranap_rAB_ID        , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ranap_RAB_ID },
  { &hf_ranap_cause         , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ranap_Cause },
  { &hf_ranap_iE_Extensions , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ranap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_ranap_RAB_ToBeReleasedItem_EnhancedRelocCompleteRes(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ranap_RAB_ToBeReleasedItem_EnhancedRelocCompleteRes, RAB_ToBeReleasedItem_EnhancedRelocCompleteRes_sequence);

  return offset;
}


static const per_sequence_t EnhancedRelocationCompleteFailure_sequence[] = {
  { &hf_ranap_protocolIEs   , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ranap_ProtocolIE_Container },
  { &hf_ranap_protocolExtensions, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ranap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_ranap_EnhancedRelocationCompleteFailure(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ranap_EnhancedRelocationCompleteFailure, EnhancedRelocationCompleteFailure_sequence);

  return offset;
}


static const per_sequence_t EnhancedRelocationCompleteConfirm_sequence[] = {
  { &hf_ranap_protocolIEs   , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ranap_ProtocolIE_Container },
  { &hf_ranap_protocolExtensions, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ranap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_ranap_EnhancedRelocationCompleteConfirm(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ranap_EnhancedRelocationCompleteConfirm, EnhancedRelocationCompleteConfirm_sequence);

  return offset;
}


static const per_sequence_t Paging_sequence[] = {
  { &hf_ranap_protocolIEs   , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ranap_ProtocolIE_Container },
  { &hf_ranap_protocolExtensions, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ranap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_ranap_Paging(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ranap_Paging, Paging_sequence);

  return offset;
}


static const per_sequence_t CommonID_sequence[] = {
  { &hf_ranap_protocolIEs   , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ranap_ProtocolIE_Container },
  { &hf_ranap_protocolExtensions, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ranap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_ranap_CommonID(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ranap_CommonID, CommonID_sequence);

  return offset;
}


static const per_sequence_t CN_InvokeTrace_sequence[] = {
  { &hf_ranap_protocolIEs   , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ranap_ProtocolIE_Container },
  { &hf_ranap_protocolExtensions, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ranap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_ranap_CN_InvokeTrace(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ranap_CN_InvokeTrace, CN_InvokeTrace_sequence);

  return offset;
}


static const per_sequence_t CN_DeactivateTrace_sequence[] = {
  { &hf_ranap_protocolIEs   , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ranap_ProtocolIE_Container },
  { &hf_ranap_protocolExtensions, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ranap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_ranap_CN_DeactivateTrace(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ranap_CN_DeactivateTrace, CN_DeactivateTrace_sequence);

  return offset;
}


static const per_sequence_t LocationReportingControl_sequence[] = {
  { &hf_ranap_protocolIEs   , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ranap_ProtocolIE_Container },
  { &hf_ranap_protocolExtensions, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ranap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_ranap_LocationReportingControl(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ranap_LocationReportingControl, LocationReportingControl_sequence);

  return offset;
}


static const per_sequence_t LocationReport_sequence[] = {
  { &hf_ranap_protocolIEs   , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ranap_ProtocolIE_Container },
  { &hf_ranap_protocolExtensions, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ranap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_ranap_LocationReport(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ranap_LocationReport, LocationReport_sequence);

  return offset;
}


static const per_sequence_t InitialUE_Message_sequence[] = {
  { &hf_ranap_protocolIEs   , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ranap_ProtocolIE_Container },
  { &hf_ranap_protocolExtensions, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ranap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_ranap_InitialUE_Message(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ranap_InitialUE_Message, InitialUE_Message_sequence);

  return offset;
}


static const per_sequence_t DirectTransfer_sequence[] = {
  { &hf_ranap_protocolIEs   , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ranap_ProtocolIE_Container },
  { &hf_ranap_protocolExtensions, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ranap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_ranap_DirectTransfer(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ranap_DirectTransfer, DirectTransfer_sequence);

  return offset;
}



static int
dissect_ranap_RedirectionIndication(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ranap_ProtocolIE_Container(tvb, offset, actx, tree, hf_index);

  return offset;
}


static const per_sequence_t Overload_sequence[] = {
  { &hf_ranap_protocolIEs   , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ranap_ProtocolIE_Container },
  { &hf_ranap_protocolExtensions, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ranap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_ranap_Overload(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ranap_Overload, Overload_sequence);

  return offset;
}


static const per_sequence_t ErrorIndication_sequence[] = {
  { &hf_ranap_protocolIEs   , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ranap_ProtocolIE_Container },
  { &hf_ranap_protocolExtensions, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ranap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_ranap_ErrorIndication(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ranap_ErrorIndication, ErrorIndication_sequence);

  return offset;
}


static const per_sequence_t SRNS_DataForwardCommand_sequence[] = {
  { &hf_ranap_protocolIEs   , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ranap_ProtocolIE_Container },
  { &hf_ranap_protocolExtensions, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ranap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_ranap_SRNS_DataForwardCommand(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ranap_SRNS_DataForwardCommand, SRNS_DataForwardCommand_sequence);

  return offset;
}


static const per_sequence_t ForwardSRNS_Context_sequence[] = {
  { &hf_ranap_protocolIEs   , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ranap_ProtocolIE_Container },
  { &hf_ranap_protocolExtensions, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ranap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_ranap_ForwardSRNS_Context(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ranap_ForwardSRNS_Context, ForwardSRNS_Context_sequence);

  return offset;
}


static const per_sequence_t RAB_AssignmentRequest_sequence[] = {
  { &hf_ranap_protocolIEs   , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ranap_ProtocolIE_Container },
  { &hf_ranap_protocolExtensions, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ranap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_ranap_RAB_AssignmentRequest(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ranap_RAB_AssignmentRequest, RAB_AssignmentRequest_sequence);

  return offset;
}



static int
dissect_ranap_RAB_SetupOrModifyList(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ranap_RAB_IE_ContainerPairList(tvb, offset, actx, tree, hf_index);

  return offset;
}


static const per_sequence_t TransportLayerInformation_sequence[] = {
  { &hf_ranap_transportLayerAddress, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ranap_TransportLayerAddress },
  { &hf_ranap_iuTransportAssociation, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ranap_IuTransportAssociation },
  { &hf_ranap_iE_Extensions , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ranap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_ranap_TransportLayerInformation(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ranap_TransportLayerInformation, TransportLayerInformation_sequence);

  return offset;
}


static const per_sequence_t RAB_SetupOrModifyItemFirst_sequence[] = {
  { &hf_ranap_rAB_ID        , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ranap_RAB_ID },
  { &hf_ranap_nAS_SynchronisationIndicator, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ranap_NAS_SynchronisationIndicator },
  { &hf_ranap_rAB_Parameters, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ranap_RAB_Parameters },
  { &hf_ranap_userPlaneInformation, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ranap_UserPlaneInformation },
  { &hf_ranap_transportLayerInformation, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ranap_TransportLayerInformation },
  { &hf_ranap_service_Handover, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ranap_Service_Handover },
  { &hf_ranap_iE_Extensions , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ranap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_ranap_RAB_SetupOrModifyItemFirst(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ranap_RAB_SetupOrModifyItemFirst, RAB_SetupOrModifyItemFirst_sequence);

  return offset;
}


static const per_sequence_t RAB_SetupOrModifyItemSecond_sequence[] = {
  { &hf_ranap_pDP_TypeInformation, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ranap_PDP_TypeInformation },
  { &hf_ranap_dataVolumeReportingIndication, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ranap_DataVolumeReportingIndication },
  { &hf_ranap_dl_GTP_PDU_SequenceNumber, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ranap_DL_GTP_PDU_SequenceNumber },
  { &hf_ranap_ul_GTP_PDU_SequenceNumber, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ranap_UL_GTP_PDU_SequenceNumber },
  { &hf_ranap_dl_N_PDU_SequenceNumber, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ranap_DL_N_PDU_SequenceNumber },
  { &hf_ranap_ul_N_PDU_SequenceNumber, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ranap_UL_N_PDU_SequenceNumber },
  { &hf_ranap_iE_Extensions , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ranap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_ranap_RAB_SetupOrModifyItemSecond(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ranap_RAB_SetupOrModifyItemSecond, RAB_SetupOrModifyItemSecond_sequence);

  return offset;
}


static const per_sequence_t RAB_AssignmentResponse_sequence[] = {
  { &hf_ranap_protocolIEs   , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ranap_ProtocolIE_Container },
  { &hf_ranap_protocolExtensions, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ranap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_ranap_RAB_AssignmentResponse(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ranap_RAB_AssignmentResponse, RAB_AssignmentResponse_sequence);

  return offset;
}



static int
dissect_ranap_RAB_SetupOrModifiedList(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ranap_RAB_IE_ContainerList(tvb, offset, actx, tree, hf_index);

  return offset;
}


static const per_sequence_t RAB_SetupOrModifiedItem_sequence[] = {
  { &hf_ranap_rAB_ID        , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ranap_RAB_ID },
  { &hf_ranap_transportLayerAddress, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ranap_TransportLayerAddress },
  { &hf_ranap_iuTransportAssociation, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ranap_IuTransportAssociation },
  { &hf_ranap_dl_dataVolumes, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ranap_DataVolumeList },
  { &hf_ranap_iE_Extensions , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ranap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_ranap_RAB_SetupOrModifiedItem(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ranap_RAB_SetupOrModifiedItem, RAB_SetupOrModifiedItem_sequence);

  return offset;
}



static int
dissect_ranap_RAB_ReleasedList(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ranap_RAB_IE_ContainerList(tvb, offset, actx, tree, hf_index);

  return offset;
}


static const per_sequence_t RAB_ReleasedItem_sequence[] = {
  { &hf_ranap_rAB_ID        , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ranap_RAB_ID },
  { &hf_ranap_dl_dataVolumes, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ranap_DataVolumeList },
  { &hf_ranap_dL_GTP_PDU_SequenceNumber, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ranap_DL_GTP_PDU_SequenceNumber },
  { &hf_ranap_uL_GTP_PDU_SequenceNumber, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ranap_UL_GTP_PDU_SequenceNumber },
  { &hf_ranap_iE_Extensions , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ranap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_ranap_RAB_ReleasedItem(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ranap_RAB_ReleasedItem, RAB_ReleasedItem_sequence);

  return offset;
}



static int
dissect_ranap_RAB_QueuedList(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ranap_RAB_IE_ContainerList(tvb, offset, actx, tree, hf_index);

  return offset;
}


static const per_sequence_t RAB_QueuedItem_sequence[] = {
  { &hf_ranap_rAB_ID        , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ranap_RAB_ID },
  { &hf_ranap_iE_Extensions , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ranap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_ranap_RAB_QueuedItem(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ranap_RAB_QueuedItem, RAB_QueuedItem_sequence);

  return offset;
}



static int
dissect_ranap_RAB_ReleaseFailedList(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ranap_RAB_FailedList(tvb, offset, actx, tree, hf_index);

  return offset;
}



static int
dissect_ranap_GERAN_Iumode_RAB_FailedList_RABAssgntResponse(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ranap_RAB_IE_ContainerList(tvb, offset, actx, tree, hf_index);

  return offset;
}


static const per_sequence_t GERAN_Iumode_RAB_Failed_RABAssgntResponse_Item_sequence[] = {
  { &hf_ranap_rAB_ID        , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ranap_RAB_ID },
  { &hf_ranap_cause         , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ranap_Cause },
  { &hf_ranap_gERAN_Classmark, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ranap_GERAN_Classmark },
  { &hf_ranap_iE_Extensions , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ranap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_ranap_GERAN_Iumode_RAB_Failed_RABAssgntResponse_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ranap_GERAN_Iumode_RAB_Failed_RABAssgntResponse_Item, GERAN_Iumode_RAB_Failed_RABAssgntResponse_Item_sequence);

  return offset;
}


static const per_sequence_t PrivateMessage_sequence[] = {
  { &hf_ranap_privateIEs    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ranap_PrivateIE_Container },
  { NULL, 0, 0, NULL }
};

static int
dissect_ranap_PrivateMessage(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ranap_PrivateMessage, PrivateMessage_sequence);

  return offset;
}


static const per_sequence_t RANAP_RelocationInformation_sequence[] = {
  { &hf_ranap_protocolIEs   , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ranap_ProtocolIE_Container },
  { &hf_ranap_protocolExtensions, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ranap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_ranap_RANAP_RelocationInformation(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ranap_RANAP_RelocationInformation, RANAP_RelocationInformation_sequence);

  return offset;
}



static int
dissect_ranap_DirectTransferInformationList_RANAP_RelocInf(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ranap_DirectTransfer_IE_ContainerList(tvb, offset, actx, tree, hf_index);

  return offset;
}


static const per_sequence_t DirectTransferInformationItem_RANAP_RelocInf_sequence[] = {
  { &hf_ranap_nAS_PDU       , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ranap_NAS_PDU },
  { &hf_ranap_sAPI          , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ranap_SAPI },
  { &hf_ranap_cN_DomainIndicator, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ranap_CN_DomainIndicator },
  { &hf_ranap_iE_Extensions , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ranap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_ranap_DirectTransferInformationItem_RANAP_RelocInf(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ranap_DirectTransferInformationItem_RANAP_RelocInf, DirectTransferInformationItem_RANAP_RelocInf_sequence);

  return offset;
}



static int
dissect_ranap_RAB_ContextList_RANAP_RelocInf(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ranap_RAB_IE_ContainerList(tvb, offset, actx, tree, hf_index);

  return offset;
}


static const per_sequence_t RAB_ContextItem_RANAP_RelocInf_sequence[] = {
  { &hf_ranap_rAB_ID        , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ranap_RAB_ID },
  { &hf_ranap_dl_GTP_PDU_SequenceNumber, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ranap_DL_GTP_PDU_SequenceNumber },
  { &hf_ranap_ul_GTP_PDU_SequenceNumber, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ranap_UL_GTP_PDU_SequenceNumber },
  { &hf_ranap_dl_N_PDU_SequenceNumber, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ranap_DL_N_PDU_SequenceNumber },
  { &hf_ranap_ul_N_PDU_SequenceNumber, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ranap_UL_N_PDU_SequenceNumber },
  { &hf_ranap_iE_Extensions , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ranap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_ranap_RAB_ContextItem_RANAP_RelocInf(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ranap_RAB_ContextItem_RANAP_RelocInf, RAB_ContextItem_RANAP_RelocInf_sequence);

  return offset;
}


static const per_sequence_t RANAP_EnhancedRelocationInformationRequest_sequence[] = {
  { &hf_ranap_protocolIEs   , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ranap_ProtocolIE_Container },
  { &hf_ranap_protocolExtensions, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ranap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_ranap_RANAP_EnhancedRelocationInformationRequest(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ranap_RANAP_EnhancedRelocationInformationRequest, RANAP_EnhancedRelocationInformationRequest_sequence);

  return offset;
}



static int
dissect_ranap_RAB_SetupList_EnhRelocInfoReq(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ranap_RAB_IE_ContainerList(tvb, offset, actx, tree, hf_index);

  return offset;
}


static const per_sequence_t TNLInformationEnhRelInfoReq_sequence[] = {
  { &hf_ranap_transportLayerAddress, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ranap_TransportLayerAddress },
  { &hf_ranap_iuTransportAssociation, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ranap_IuTransportAssociation },
  { &hf_ranap_iE_Extensions , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ranap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_ranap_TNLInformationEnhRelInfoReq(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ranap_TNLInformationEnhRelInfoReq, TNLInformationEnhRelInfoReq_sequence);

  return offset;
}


static const per_sequence_t RAB_SetupItem_EnhRelocInfoReq_sequence[] = {
  { &hf_ranap_rAB_ID        , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ranap_RAB_ID },
  { &hf_ranap_cN_DomainIndicator, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ranap_CN_DomainIndicator },
  { &hf_ranap_rAB_Parameters, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ranap_RAB_Parameters },
  { &hf_ranap_dataVolumeReportingIndication, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ranap_DataVolumeReportingIndication },
  { &hf_ranap_pDP_TypeInformation, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ranap_PDP_TypeInformation },
  { &hf_ranap_userPlaneInformation, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ranap_UserPlaneInformation },
  { &hf_ranap_dataForwardingInformation, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ranap_TNLInformationEnhRelInfoReq },
  { &hf_ranap_sourceSideIuULTNLInfo, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ranap_TNLInformationEnhRelInfoReq },
  { &hf_ranap_service_Handover, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ranap_Service_Handover },
  { &hf_ranap_alt_RAB_Parameters, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ranap_Alt_RAB_Parameters },
  { &hf_ranap_iE_Extensions , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ranap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_ranap_RAB_SetupItem_EnhRelocInfoReq(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ranap_RAB_SetupItem_EnhRelocInfoReq, RAB_SetupItem_EnhRelocInfoReq_sequence);

  return offset;
}


static const per_sequence_t RANAP_EnhancedRelocationInformationResponse_sequence[] = {
  { &hf_ranap_protocolIEs   , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ranap_ProtocolIE_Container },
  { &hf_ranap_protocolExtensions, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ranap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_ranap_RANAP_EnhancedRelocationInformationResponse(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ranap_RANAP_EnhancedRelocationInformationResponse, RANAP_EnhancedRelocationInformationResponse_sequence);

  return offset;
}



static int
dissect_ranap_RAB_SetupList_EnhRelocInfoRes(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ranap_RAB_IE_ContainerList(tvb, offset, actx, tree, hf_index);

  return offset;
}


static const per_sequence_t TNLInformationEnhRelInfoRes_sequence[] = {
  { &hf_ranap_dl_forwardingTransportLayerAddress, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ranap_TransportLayerAddress },
  { &hf_ranap_dl_forwardingTransportAssociation, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ranap_IuTransportAssociation },
  { &hf_ranap_iE_Extensions , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ranap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_ranap_TNLInformationEnhRelInfoRes(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ranap_TNLInformationEnhRelInfoRes, TNLInformationEnhRelInfoRes_sequence);

  return offset;
}


static const per_sequence_t RAB_SetupItem_EnhRelocInfoRes_sequence[] = {
  { &hf_ranap_cN_DomainIndicator, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ranap_CN_DomainIndicator },
  { &hf_ranap_rAB_ID        , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ranap_RAB_ID },
  { &hf_ranap_dataForwardingInformation_01, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ranap_TNLInformationEnhRelInfoRes },
  { &hf_ranap_ass_RAB_Parameters, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ranap_Ass_RAB_Parameters },
  { &hf_ranap_iE_Extensions , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ranap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_ranap_RAB_SetupItem_EnhRelocInfoRes(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ranap_RAB_SetupItem_EnhRelocInfoRes, RAB_SetupItem_EnhRelocInfoRes_sequence);

  return offset;
}



static int
dissect_ranap_RAB_FailedList_EnhRelocInfoRes(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ranap_RAB_IE_ContainerList(tvb, offset, actx, tree, hf_index);

  return offset;
}


static const per_sequence_t RAB_FailedItem_EnhRelocInfoRes_sequence[] = {
  { &hf_ranap_cN_DomainIndicator, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ranap_CN_DomainIndicator },
  { &hf_ranap_rAB_ID        , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ranap_RAB_ID },
  { &hf_ranap_cause         , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ranap_Cause },
  { &hf_ranap_iE_Extensions , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ranap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_ranap_RAB_FailedItem_EnhRelocInfoRes(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ranap_RAB_FailedItem_EnhRelocInfoRes, RAB_FailedItem_EnhRelocInfoRes_sequence);

  return offset;
}


static const per_sequence_t RAB_ModifyRequest_sequence[] = {
  { &hf_ranap_protocolIEs   , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ranap_ProtocolIE_Container },
  { &hf_ranap_protocolExtensions, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ranap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_ranap_RAB_ModifyRequest(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ranap_RAB_ModifyRequest, RAB_ModifyRequest_sequence);

  return offset;
}



static int
dissect_ranap_RAB_ModifyList(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ranap_RAB_IE_ContainerList(tvb, offset, actx, tree, hf_index);

  return offset;
}


static const per_sequence_t RAB_ModifyItem_sequence[] = {
  { &hf_ranap_rAB_ID        , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ranap_RAB_ID },
  { &hf_ranap_requested_RAB_Parameter_Values, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ranap_Requested_RAB_Parameter_Values },
  { &hf_ranap_iE_Extensions , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ranap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_ranap_RAB_ModifyItem(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ranap_RAB_ModifyItem, RAB_ModifyItem_sequence);

  return offset;
}


static const per_sequence_t LocationRelatedDataRequest_sequence[] = {
  { &hf_ranap_protocolIEs   , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ranap_ProtocolIE_Container },
  { &hf_ranap_protocolExtensions, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ranap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_ranap_LocationRelatedDataRequest(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ranap_LocationRelatedDataRequest, LocationRelatedDataRequest_sequence);

  return offset;
}


static const per_sequence_t LocationRelatedDataResponse_sequence[] = {
  { &hf_ranap_protocolIEs   , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ranap_ProtocolIE_Container },
  { &hf_ranap_protocolExtensions, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ranap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_ranap_LocationRelatedDataResponse(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ranap_LocationRelatedDataResponse, LocationRelatedDataResponse_sequence);

  return offset;
}


static const per_sequence_t LocationRelatedDataFailure_sequence[] = {
  { &hf_ranap_protocolIEs   , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ranap_ProtocolIE_Container },
  { &hf_ranap_protocolExtensions, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ranap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_ranap_LocationRelatedDataFailure(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ranap_LocationRelatedDataFailure, LocationRelatedDataFailure_sequence);

  return offset;
}


static const per_sequence_t InformationTransferIndication_sequence[] = {
  { &hf_ranap_protocolIEs   , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ranap_ProtocolIE_Container },
  { &hf_ranap_protocolExtensions, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ranap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_ranap_InformationTransferIndication(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ranap_InformationTransferIndication, InformationTransferIndication_sequence);

  return offset;
}


static const per_sequence_t InformationTransferConfirmation_sequence[] = {
  { &hf_ranap_protocolIEs   , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ranap_ProtocolIE_Container },
  { &hf_ranap_protocolExtensions, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ranap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_ranap_InformationTransferConfirmation(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ranap_InformationTransferConfirmation, InformationTransferConfirmation_sequence);

  return offset;
}


static const per_sequence_t InformationTransferFailure_sequence[] = {
  { &hf_ranap_protocolIEs   , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ranap_ProtocolIE_Container },
  { &hf_ranap_protocolExtensions, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ranap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_ranap_InformationTransferFailure(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ranap_InformationTransferFailure, InformationTransferFailure_sequence);

  return offset;
}


static const per_sequence_t UESpecificInformationIndication_sequence[] = {
  { &hf_ranap_protocolIEs   , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ranap_ProtocolIE_Container },
  { &hf_ranap_protocolExtensions, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ranap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_ranap_UESpecificInformationIndication(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ranap_UESpecificInformationIndication, UESpecificInformationIndication_sequence);

  return offset;
}


static const per_sequence_t DirectInformationTransfer_sequence[] = {
  { &hf_ranap_protocolIEs   , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ranap_ProtocolIE_Container },
  { &hf_ranap_protocolExtensions, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ranap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_ranap_DirectInformationTransfer(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ranap_DirectInformationTransfer, DirectInformationTransfer_sequence);

  return offset;
}


static const per_sequence_t UplinkInformationExchangeRequest_sequence[] = {
  { &hf_ranap_protocolIEs   , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ranap_ProtocolIE_Container },
  { &hf_ranap_protocolExtensions, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ranap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_ranap_UplinkInformationExchangeRequest(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ranap_UplinkInformationExchangeRequest, UplinkInformationExchangeRequest_sequence);

  return offset;
}


static const per_sequence_t UplinkInformationExchangeResponse_sequence[] = {
  { &hf_ranap_protocolIEs   , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ranap_ProtocolIE_Container },
  { &hf_ranap_protocolExtensions, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ranap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_ranap_UplinkInformationExchangeResponse(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ranap_UplinkInformationExchangeResponse, UplinkInformationExchangeResponse_sequence);

  return offset;
}


static const per_sequence_t UplinkInformationExchangeFailure_sequence[] = {
  { &hf_ranap_protocolIEs   , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ranap_ProtocolIE_Container },
  { &hf_ranap_protocolExtensions, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ranap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_ranap_UplinkInformationExchangeFailure(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ranap_UplinkInformationExchangeFailure, UplinkInformationExchangeFailure_sequence);

  return offset;
}


static const per_sequence_t MBMSSessionStart_sequence[] = {
  { &hf_ranap_protocolIEs   , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ranap_ProtocolIE_Container },
  { &hf_ranap_protocolExtensions, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ranap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_ranap_MBMSSessionStart(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ranap_MBMSSessionStart, MBMSSessionStart_sequence);

  return offset;
}


static const per_sequence_t MBMSSynchronisationInformation_sequence[] = {
  { &hf_ranap_mBMSHCIndicator, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ranap_MBMSHCIndicator },
  { &hf_ranap_iPMulticastAddress, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ranap_IPMulticastAddress },
  { &hf_ranap_gTPDLTEID     , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ranap_GTP_TEI },
  { &hf_ranap_iE_Extensions , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ranap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_ranap_MBMSSynchronisationInformation(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ranap_MBMSSynchronisationInformation, MBMSSynchronisationInformation_sequence);

  return offset;
}


static const per_sequence_t MBMSSessionStartResponse_sequence[] = {
  { &hf_ranap_protocolIEs   , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ranap_ProtocolIE_Container },
  { &hf_ranap_protocolExtensions, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ranap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_ranap_MBMSSessionStartResponse(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ranap_MBMSSessionStartResponse, MBMSSessionStartResponse_sequence);

  return offset;
}


static const per_sequence_t MBMSSessionStartFailure_sequence[] = {
  { &hf_ranap_protocolIEs   , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ranap_ProtocolIE_Container },
  { &hf_ranap_protocolExtensions, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ranap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_ranap_MBMSSessionStartFailure(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ranap_MBMSSessionStartFailure, MBMSSessionStartFailure_sequence);

  return offset;
}


static const per_sequence_t MBMSSessionUpdate_sequence[] = {
  { &hf_ranap_protocolIEs   , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ranap_ProtocolIE_Container },
  { &hf_ranap_protocolExtensions, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ranap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_ranap_MBMSSessionUpdate(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ranap_MBMSSessionUpdate, MBMSSessionUpdate_sequence);

  return offset;
}


static const per_sequence_t MBMSSessionUpdateResponse_sequence[] = {
  { &hf_ranap_protocolIEs   , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ranap_ProtocolIE_Container },
  { &hf_ranap_protocolExtensions, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ranap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_ranap_MBMSSessionUpdateResponse(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ranap_MBMSSessionUpdateResponse, MBMSSessionUpdateResponse_sequence);

  return offset;
}


static const per_sequence_t MBMSSessionUpdateFailure_sequence[] = {
  { &hf_ranap_protocolIEs   , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ranap_ProtocolIE_Container },
  { &hf_ranap_protocolExtensions, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ranap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_ranap_MBMSSessionUpdateFailure(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ranap_MBMSSessionUpdateFailure, MBMSSessionUpdateFailure_sequence);

  return offset;
}


static const per_sequence_t MBMSSessionStop_sequence[] = {
  { &hf_ranap_protocolIEs   , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ranap_ProtocolIE_Container },
  { &hf_ranap_protocolExtensions, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ranap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_ranap_MBMSSessionStop(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ranap_MBMSSessionStop, MBMSSessionStop_sequence);

  return offset;
}


static const per_sequence_t MBMSSessionStopResponse_sequence[] = {
  { &hf_ranap_protocolIEs   , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ranap_ProtocolIE_Container },
  { &hf_ranap_protocolExtensions, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ranap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_ranap_MBMSSessionStopResponse(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ranap_MBMSSessionStopResponse, MBMSSessionStopResponse_sequence);

  return offset;
}


static const per_sequence_t MBMSUELinkingRequest_sequence[] = {
  { &hf_ranap_protocolIEs   , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ranap_ProtocolIE_Container },
  { &hf_ranap_protocolExtensions, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ranap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_ranap_MBMSUELinkingRequest(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ranap_MBMSUELinkingRequest, MBMSUELinkingRequest_sequence);

  return offset;
}


static const per_sequence_t LeftMBMSBearerService_IEs_item_sequence[] = {
  { &hf_ranap_tMGI          , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ranap_TMGI },
  { &hf_ranap_iE_Extensions , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ranap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_ranap_LeftMBMSBearerService_IEs_item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ranap_LeftMBMSBearerService_IEs_item, LeftMBMSBearerService_IEs_item_sequence);

  return offset;
}


static const per_sequence_t LeftMBMSBearerService_IEs_sequence_of[1] = {
  { &hf_ranap_LeftMBMSBearerService_IEs_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ranap_LeftMBMSBearerService_IEs_item },
};

static int
dissect_ranap_LeftMBMSBearerService_IEs(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_ranap_LeftMBMSBearerService_IEs, LeftMBMSBearerService_IEs_sequence_of,
                                                  1, maxnoofMulticastServicesPerUE, FALSE);

  return offset;
}


static const per_sequence_t MBMSUELinkingResponse_sequence[] = {
  { &hf_ranap_protocolIEs   , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ranap_ProtocolIE_Container },
  { &hf_ranap_protocolExtensions, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ranap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_ranap_MBMSUELinkingResponse(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ranap_MBMSUELinkingResponse, MBMSUELinkingResponse_sequence);

  return offset;
}


static const per_sequence_t UnsuccessfulLinking_IEs_item_sequence[] = {
  { &hf_ranap_tMGI          , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ranap_TMGI },
  { &hf_ranap_cause         , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ranap_Cause },
  { &hf_ranap_iE_Extensions , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ranap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_ranap_UnsuccessfulLinking_IEs_item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ranap_UnsuccessfulLinking_IEs_item, UnsuccessfulLinking_IEs_item_sequence);

  return offset;
}


static const per_sequence_t UnsuccessfulLinking_IEs_sequence_of[1] = {
  { &hf_ranap_UnsuccessfulLinking_IEs_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ranap_UnsuccessfulLinking_IEs_item },
};

static int
dissect_ranap_UnsuccessfulLinking_IEs(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_ranap_UnsuccessfulLinking_IEs, UnsuccessfulLinking_IEs_sequence_of,
                                                  1, maxnoofMulticastServicesPerUE, FALSE);

  return offset;
}


static const per_sequence_t MBMSRegistrationRequest_sequence[] = {
  { &hf_ranap_protocolIEs   , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ranap_ProtocolIE_Container },
  { &hf_ranap_protocolExtensions, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ranap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_ranap_MBMSRegistrationRequest(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ranap_MBMSRegistrationRequest, MBMSRegistrationRequest_sequence);

  return offset;
}


static const per_sequence_t MBMSRegistrationResponse_sequence[] = {
  { &hf_ranap_protocolIEs   , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ranap_ProtocolIE_Container },
  { &hf_ranap_protocolExtensions, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ranap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_ranap_MBMSRegistrationResponse(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ranap_MBMSRegistrationResponse, MBMSRegistrationResponse_sequence);

  return offset;
}


static const per_sequence_t MBMSRegistrationFailure_sequence[] = {
  { &hf_ranap_protocolIEs   , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ranap_ProtocolIE_Container },
  { &hf_ranap_protocolExtensions, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ranap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_ranap_MBMSRegistrationFailure(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ranap_MBMSRegistrationFailure, MBMSRegistrationFailure_sequence);

  return offset;
}


static const per_sequence_t MBMSCNDe_RegistrationRequest_sequence[] = {
  { &hf_ranap_protocolIEs   , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ranap_ProtocolIE_Container },
  { &hf_ranap_protocolExtensions, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ranap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_ranap_MBMSCNDe_RegistrationRequest(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ranap_MBMSCNDe_RegistrationRequest, MBMSCNDe_RegistrationRequest_sequence);

  return offset;
}


static const per_sequence_t MBMSCNDe_RegistrationResponse_sequence[] = {
  { &hf_ranap_protocolIEs   , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ranap_ProtocolIE_Container },
  { &hf_ranap_protocolExtensions, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ranap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_ranap_MBMSCNDe_RegistrationResponse(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ranap_MBMSCNDe_RegistrationResponse, MBMSCNDe_RegistrationResponse_sequence);

  return offset;
}


static const per_sequence_t MBMSRABEstablishmentIndication_sequence[] = {
  { &hf_ranap_protocolIEs   , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ranap_ProtocolIE_Container },
  { &hf_ranap_protocolExtensions, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ranap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_ranap_MBMSRABEstablishmentIndication(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ranap_MBMSRABEstablishmentIndication, MBMSRABEstablishmentIndication_sequence);

  return offset;
}


static const per_sequence_t MBMSRABReleaseRequest_sequence[] = {
  { &hf_ranap_protocolIEs   , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ranap_ProtocolIE_Container },
  { &hf_ranap_protocolExtensions, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ranap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_ranap_MBMSRABReleaseRequest(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ranap_MBMSRABReleaseRequest, MBMSRABReleaseRequest_sequence);

  return offset;
}


static const per_sequence_t MBMSRABRelease_sequence[] = {
  { &hf_ranap_protocolIEs   , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ranap_ProtocolIE_Container },
  { &hf_ranap_protocolExtensions, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ranap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_ranap_MBMSRABRelease(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ranap_MBMSRABRelease, MBMSRABRelease_sequence);

  return offset;
}


static const per_sequence_t MBMSRABReleaseFailure_sequence[] = {
  { &hf_ranap_protocolIEs   , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ranap_ProtocolIE_Container },
  { &hf_ranap_protocolExtensions, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ranap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_ranap_MBMSRABReleaseFailure(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ranap_MBMSRABReleaseFailure, MBMSRABReleaseFailure_sequence);

  return offset;
}


static const per_sequence_t SRVCC_CSKeysRequest_sequence[] = {
  { &hf_ranap_protocolIEs   , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ranap_ProtocolIE_Container },
  { &hf_ranap_protocolExtensions, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ranap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_ranap_SRVCC_CSKeysRequest(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ranap_SRVCC_CSKeysRequest, SRVCC_CSKeysRequest_sequence);

  return offset;
}


static const per_sequence_t SRVCC_CSKeysResponse_sequence[] = {
  { &hf_ranap_protocolIEs   , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ranap_ProtocolIE_Container },
  { &hf_ranap_protocolExtensions, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ranap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_ranap_SRVCC_CSKeysResponse(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ranap_SRVCC_CSKeysResponse, SRVCC_CSKeysResponse_sequence);

  return offset;
}



static int
dissect_ranap_InitiatingMessage_value(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_open_type_pdu_new(tvb, offset, actx, tree, hf_index, dissect_InitiatingMessageValue);

  return offset;
}


static const per_sequence_t InitiatingMessage_sequence[] = {
  { &hf_ranap_procedureCode , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ranap_ProcedureCode },
  { &hf_ranap_criticality   , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ranap_Criticality },
  { &hf_ranap_initiatingMessagevalue, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ranap_InitiatingMessage_value },
  { NULL, 0, 0, NULL }
};

static int
dissect_ranap_InitiatingMessage(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ranap_InitiatingMessage, InitiatingMessage_sequence);

  return offset;
}



static int
dissect_ranap_SuccessfulOutcome_value(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_open_type_pdu_new(tvb, offset, actx, tree, hf_index, dissect_SuccessfulOutcomeValue);

  return offset;
}


static const per_sequence_t SuccessfulOutcome_sequence[] = {
  { &hf_ranap_procedureCode , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ranap_ProcedureCode },
  { &hf_ranap_criticality   , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ranap_Criticality },
  { &hf_ranap_successfulOutcome_value, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ranap_SuccessfulOutcome_value },
  { NULL, 0, 0, NULL }
};

static int
dissect_ranap_SuccessfulOutcome(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ranap_SuccessfulOutcome, SuccessfulOutcome_sequence);

  return offset;
}



static int
dissect_ranap_UnsuccessfulOutcome_value(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_open_type_pdu_new(tvb, offset, actx, tree, hf_index, dissect_UnsuccessfulOutcomeValue);

  return offset;
}


static const per_sequence_t UnsuccessfulOutcome_sequence[] = {
  { &hf_ranap_procedureCode , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ranap_ProcedureCode },
  { &hf_ranap_criticality   , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ranap_Criticality },
  { &hf_ranap_unsuccessfulOutcome_value, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ranap_UnsuccessfulOutcome_value },
  { NULL, 0, 0, NULL }
};

static int
dissect_ranap_UnsuccessfulOutcome(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ranap_UnsuccessfulOutcome, UnsuccessfulOutcome_sequence);

  return offset;
}



static int
dissect_ranap_T_value(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_open_type_pdu_new(tvb, offset, actx, tree, hf_index, dissect_OutcomeValue);

  return offset;
}


static const per_sequence_t Outcome_sequence[] = {
  { &hf_ranap_procedureCode , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ranap_ProcedureCode },
  { &hf_ranap_criticality   , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ranap_Criticality },
  { &hf_ranap_value         , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ranap_T_value },
  { NULL, 0, 0, NULL }
};

static int
dissect_ranap_Outcome(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ranap_Outcome, Outcome_sequence);

  return offset;
}


static const value_string ranap_RANAP_PDU_vals[] = {
  {   0, "initiatingMessage" },
  {   1, "successfulOutcome" },
  {   2, "unsuccessfulOutcome" },
  {   3, "outcome" },
  { 0, NULL }
};

static const per_choice_t RANAP_PDU_choice[] = {
  {   0, &hf_ranap_initiatingMessage, ASN1_EXTENSION_ROOT    , dissect_ranap_InitiatingMessage },
  {   1, &hf_ranap_successfulOutcome, ASN1_EXTENSION_ROOT    , dissect_ranap_SuccessfulOutcome },
  {   2, &hf_ranap_unsuccessfulOutcome, ASN1_EXTENSION_ROOT    , dissect_ranap_UnsuccessfulOutcome },
  {   3, &hf_ranap_outcome       , ASN1_EXTENSION_ROOT    , dissect_ranap_Outcome },
  { 0, NULL, 0, NULL }
};

static int
dissect_ranap_RANAP_PDU(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_ranap_RANAP_PDU, RANAP_PDU_choice,
                                 NULL);

  return offset;
}

/*--- PDUs ---*/

static int dissect_AccuracyFulfilmentIndicator_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_ranap_AccuracyFulfilmentIndicator(tvb, offset, &asn1_ctx, tree, hf_ranap_AccuracyFulfilmentIndicator_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_Alt_RAB_Parameters_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_ranap_Alt_RAB_Parameters(tvb, offset, &asn1_ctx, tree, hf_ranap_Alt_RAB_Parameters_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_Alt_RAB_Parameter_ExtendedGuaranteedBitrateInf_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_ranap_Alt_RAB_Parameter_ExtendedGuaranteedBitrateInf(tvb, offset, &asn1_ctx, tree, hf_ranap_Alt_RAB_Parameter_ExtendedGuaranteedBitrateInf_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_Alt_RAB_Parameter_SupportedGuaranteedBitrateInf_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_ranap_Alt_RAB_Parameter_SupportedGuaranteedBitrateInf(tvb, offset, &asn1_ctx, tree, hf_ranap_Alt_RAB_Parameter_SupportedGuaranteedBitrateInf_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_Alt_RAB_Parameter_ExtendedMaxBitrateInf_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_ranap_Alt_RAB_Parameter_ExtendedMaxBitrateInf(tvb, offset, &asn1_ctx, tree, hf_ranap_Alt_RAB_Parameter_ExtendedMaxBitrateInf_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_Alt_RAB_Parameter_SupportedMaxBitrateInf_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_ranap_Alt_RAB_Parameter_SupportedMaxBitrateInf(tvb, offset, &asn1_ctx, tree, hf_ranap_Alt_RAB_Parameter_SupportedMaxBitrateInf_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_AlternativeRABConfigurationRequest_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_ranap_AlternativeRABConfigurationRequest(tvb, offset, &asn1_ctx, tree, hf_ranap_AlternativeRABConfigurationRequest_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_APN_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_ranap_APN(tvb, offset, &asn1_ctx, tree, hf_ranap_APN_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_AreaIdentity_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_ranap_AreaIdentity(tvb, offset, &asn1_ctx, tree, hf_ranap_AreaIdentity_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_Ass_RAB_Parameters_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_ranap_Ass_RAB_Parameters(tvb, offset, &asn1_ctx, tree, hf_ranap_Ass_RAB_Parameters_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_Ass_RAB_Parameter_ExtendedGuaranteedBitrateList_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_ranap_Ass_RAB_Parameter_ExtendedGuaranteedBitrateList(tvb, offset, &asn1_ctx, tree, hf_ranap_Ass_RAB_Parameter_ExtendedGuaranteedBitrateList_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_Ass_RAB_Parameter_ExtendedMaxBitrateList_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_ranap_Ass_RAB_Parameter_ExtendedMaxBitrateList(tvb, offset, &asn1_ctx, tree, hf_ranap_Ass_RAB_Parameter_ExtendedMaxBitrateList_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_BroadcastAssistanceDataDecipheringKeys_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_ranap_BroadcastAssistanceDataDecipheringKeys(tvb, offset, &asn1_ctx, tree, hf_ranap_BroadcastAssistanceDataDecipheringKeys_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_Cause_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_ranap_Cause(tvb, offset, &asn1_ctx, tree, hf_ranap_Cause_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_Cell_Access_Mode_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_ranap_Cell_Access_Mode(tvb, offset, &asn1_ctx, tree, hf_ranap_Cell_Access_Mode_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_CellLoadInformationGroup_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_ranap_CellLoadInformationGroup(tvb, offset, &asn1_ctx, tree, hf_ranap_CellLoadInformationGroup_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_ClientType_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_ranap_ClientType(tvb, offset, &asn1_ctx, tree, hf_ranap_ClientType_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_CriticalityDiagnostics_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_ranap_CriticalityDiagnostics(tvb, offset, &asn1_ctx, tree, hf_ranap_CriticalityDiagnostics_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_MessageStructure_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_ranap_MessageStructure(tvb, offset, &asn1_ctx, tree, hf_ranap_MessageStructure_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_ChosenEncryptionAlgorithm_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_ranap_ChosenEncryptionAlgorithm(tvb, offset, &asn1_ctx, tree, hf_ranap_ChosenEncryptionAlgorithm_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_ChosenIntegrityProtectionAlgorithm_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_ranap_ChosenIntegrityProtectionAlgorithm(tvb, offset, &asn1_ctx, tree, hf_ranap_ChosenIntegrityProtectionAlgorithm_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_ClassmarkInformation2_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_ranap_ClassmarkInformation2(tvb, offset, &asn1_ctx, tree, hf_ranap_ClassmarkInformation2_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_ClassmarkInformation3_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_ranap_ClassmarkInformation3(tvb, offset, &asn1_ctx, tree, hf_ranap_ClassmarkInformation3_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_CN_DomainIndicator_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_ranap_CN_DomainIndicator(tvb, offset, &asn1_ctx, tree, hf_ranap_CN_DomainIndicator_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_Correlation_ID_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_ranap_Correlation_ID(tvb, offset, &asn1_ctx, tree, hf_ranap_Correlation_ID_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_CSFB_Information_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_ranap_CSFB_Information(tvb, offset, &asn1_ctx, tree, hf_ranap_CSFB_Information_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_CSG_Id_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_ranap_CSG_Id(tvb, offset, &asn1_ctx, tree, hf_ranap_CSG_Id_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_CSG_Id_List_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_ranap_CSG_Id_List(tvb, offset, &asn1_ctx, tree, hf_ranap_CSG_Id_List_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_CSG_Membership_Status_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_ranap_CSG_Membership_Status(tvb, offset, &asn1_ctx, tree, hf_ranap_CSG_Membership_Status_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_DeltaRAListofIdleModeUEs_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_ranap_DeltaRAListofIdleModeUEs(tvb, offset, &asn1_ctx, tree, hf_ranap_DeltaRAListofIdleModeUEs_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_DRX_CycleLengthCoefficient_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_ranap_DRX_CycleLengthCoefficient(tvb, offset, &asn1_ctx, tree, hf_ranap_DRX_CycleLengthCoefficient_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_E_DCH_MAC_d_Flow_ID_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_ranap_E_DCH_MAC_d_Flow_ID(tvb, offset, &asn1_ctx, tree, hf_ranap_E_DCH_MAC_d_Flow_ID_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_EncryptionInformation_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_ranap_EncryptionInformation(tvb, offset, &asn1_ctx, tree, hf_ranap_EncryptionInformation_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_EncryptionKey_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_ranap_EncryptionKey(tvb, offset, &asn1_ctx, tree, hf_ranap_EncryptionKey_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_E_UTRAN_Service_Handover_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_ranap_E_UTRAN_Service_Handover(tvb, offset, &asn1_ctx, tree, hf_ranap_E_UTRAN_Service_Handover_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_ExtendedRNC_ID_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_ranap_ExtendedRNC_ID(tvb, offset, &asn1_ctx, tree, hf_ranap_ExtendedRNC_ID_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_FrequenceLayerConvergenceFlag_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_ranap_FrequenceLayerConvergenceFlag(tvb, offset, &asn1_ctx, tree, hf_ranap_FrequenceLayerConvergenceFlag_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_GANSS_PositioningDataSet_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_ranap_GANSS_PositioningDataSet(tvb, offset, &asn1_ctx, tree, hf_ranap_GANSS_PositioningDataSet_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_GERAN_BSC_Container_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_ranap_GERAN_BSC_Container(tvb, offset, &asn1_ctx, tree, hf_ranap_GERAN_BSC_Container_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_GERAN_Classmark_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_ranap_GERAN_Classmark(tvb, offset, &asn1_ctx, tree, hf_ranap_GERAN_Classmark_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_GlobalCN_ID_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_ranap_GlobalCN_ID(tvb, offset, &asn1_ctx, tree, hf_ranap_GlobalCN_ID_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_GlobalRNC_ID_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_ranap_GlobalRNC_ID(tvb, offset, &asn1_ctx, tree, hf_ranap_GlobalRNC_ID_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_HS_DSCH_MAC_d_Flow_ID_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_ranap_HS_DSCH_MAC_d_Flow_ID(tvb, offset, &asn1_ctx, tree, hf_ranap_HS_DSCH_MAC_d_Flow_ID_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_IncludeVelocity_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_ranap_IncludeVelocity(tvb, offset, &asn1_ctx, tree, hf_ranap_IncludeVelocity_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_InformationExchangeID_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_ranap_InformationExchangeID(tvb, offset, &asn1_ctx, tree, hf_ranap_InformationExchangeID_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_InformationExchangeType_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_ranap_InformationExchangeType(tvb, offset, &asn1_ctx, tree, hf_ranap_InformationExchangeType_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_InformationRequested_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_ranap_InformationRequested(tvb, offset, &asn1_ctx, tree, hf_ranap_InformationRequested_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_InformationRequestType_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_ranap_InformationRequestType(tvb, offset, &asn1_ctx, tree, hf_ranap_InformationRequestType_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_InformationTransferID_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_ranap_InformationTransferID(tvb, offset, &asn1_ctx, tree, hf_ranap_InformationTransferID_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_InformationTransferType_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_ranap_InformationTransferType(tvb, offset, &asn1_ctx, tree, hf_ranap_InformationTransferType_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_IntegrityProtectionInformation_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_ranap_IntegrityProtectionInformation(tvb, offset, &asn1_ctx, tree, hf_ranap_IntegrityProtectionInformation_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_IntegrityProtectionKey_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_ranap_IntegrityProtectionKey(tvb, offset, &asn1_ctx, tree, hf_ranap_IntegrityProtectionKey_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_InterSystemInformationTransferType_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_ranap_InterSystemInformationTransferType(tvb, offset, &asn1_ctx, tree, hf_ranap_InterSystemInformationTransferType_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_InterSystemInformation_TransparentContainer_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_ranap_InterSystemInformation_TransparentContainer(tvb, offset, &asn1_ctx, tree, hf_ranap_InterSystemInformation_TransparentContainer_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_IPMulticastAddress_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_ranap_IPMulticastAddress(tvb, offset, &asn1_ctx, tree, hf_ranap_IPMulticastAddress_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_IuSignallingConnectionIdentifier_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_ranap_IuSignallingConnectionIdentifier(tvb, offset, &asn1_ctx, tree, hf_ranap_IuSignallingConnectionIdentifier_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_IuTransportAssociation_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_ranap_IuTransportAssociation(tvb, offset, &asn1_ctx, tree, hf_ranap_IuTransportAssociation_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_KeyStatus_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_ranap_KeyStatus(tvb, offset, &asn1_ctx, tree, hf_ranap_KeyStatus_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_LAI_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_ranap_LAI(tvb, offset, &asn1_ctx, tree, hf_ranap_LAI_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_LastKnownServiceArea_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_ranap_LastKnownServiceArea(tvb, offset, &asn1_ctx, tree, hf_ranap_LastKnownServiceArea_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_LocationRelatedDataRequestType_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_ranap_LocationRelatedDataRequestType(tvb, offset, &asn1_ctx, tree, hf_ranap_LocationRelatedDataRequestType_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_LocationRelatedDataRequestTypeSpecificToGERANIuMode_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_ranap_LocationRelatedDataRequestTypeSpecificToGERANIuMode(tvb, offset, &asn1_ctx, tree, hf_ranap_LocationRelatedDataRequestTypeSpecificToGERANIuMode_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_L3_Information_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_ranap_L3_Information(tvb, offset, &asn1_ctx, tree, hf_ranap_L3_Information_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_Management_Based_MDT_Allowed_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_ranap_Management_Based_MDT_Allowed(tvb, offset, &asn1_ctx, tree, hf_ranap_Management_Based_MDT_Allowed_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_MBMSBearerServiceType_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_ranap_MBMSBearerServiceType(tvb, offset, &asn1_ctx, tree, hf_ranap_MBMSBearerServiceType_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_MBMSCNDe_Registration_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_ranap_MBMSCNDe_Registration(tvb, offset, &asn1_ctx, tree, hf_ranap_MBMSCNDe_Registration_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_MBMSCountingInformation_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_ranap_MBMSCountingInformation(tvb, offset, &asn1_ctx, tree, hf_ranap_MBMSCountingInformation_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_MBMSLinkingInformation_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_ranap_MBMSLinkingInformation(tvb, offset, &asn1_ctx, tree, hf_ranap_MBMSLinkingInformation_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_MBMSRegistrationRequestType_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_ranap_MBMSRegistrationRequestType(tvb, offset, &asn1_ctx, tree, hf_ranap_MBMSRegistrationRequestType_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_MBMSServiceArea_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_ranap_MBMSServiceArea(tvb, offset, &asn1_ctx, tree, hf_ranap_MBMSServiceArea_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_MBMSSessionDuration_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_ranap_MBMSSessionDuration(tvb, offset, &asn1_ctx, tree, hf_ranap_MBMSSessionDuration_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_MBMSSessionIdentity_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_ranap_MBMSSessionIdentity(tvb, offset, &asn1_ctx, tree, hf_ranap_MBMSSessionIdentity_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_MBMSSessionRepetitionNumber_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_ranap_MBMSSessionRepetitionNumber(tvb, offset, &asn1_ctx, tree, hf_ranap_MBMSSessionRepetitionNumber_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_MDT_Configuration_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_ranap_MDT_Configuration(tvb, offset, &asn1_ctx, tree, hf_ranap_MDT_Configuration_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_MSISDN_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_ranap_MSISDN(tvb, offset, &asn1_ctx, tree, hf_ranap_MSISDN_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_NAS_PDU_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_ranap_NAS_PDU(tvb, offset, &asn1_ctx, tree, hf_ranap_NAS_PDU_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_NAS_SequenceNumber_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_ranap_NAS_SequenceNumber(tvb, offset, &asn1_ctx, tree, hf_ranap_NAS_SequenceNumber_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_NewBSS_To_OldBSS_Information_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_ranap_NewBSS_To_OldBSS_Information(tvb, offset, &asn1_ctx, tree, hf_ranap_NewBSS_To_OldBSS_Information_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_NonSearchingIndication_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_ranap_NonSearchingIndication(tvb, offset, &asn1_ctx, tree, hf_ranap_NonSearchingIndication_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_NumberOfSteps_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_ranap_NumberOfSteps(tvb, offset, &asn1_ctx, tree, hf_ranap_NumberOfSteps_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_Offload_RAB_Parameters_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_ranap_Offload_RAB_Parameters(tvb, offset, &asn1_ctx, tree, hf_ranap_Offload_RAB_Parameters_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_OldBSS_ToNewBSS_Information_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_ranap_OldBSS_ToNewBSS_Information(tvb, offset, &asn1_ctx, tree, hf_ranap_OldBSS_ToNewBSS_Information_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_OMC_ID_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_ranap_OMC_ID(tvb, offset, &asn1_ctx, tree, hf_ranap_OMC_ID_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_PagingAreaID_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_ranap_PagingAreaID(tvb, offset, &asn1_ctx, tree, hf_ranap_PagingAreaID_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_PagingCause_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_ranap_PagingCause(tvb, offset, &asn1_ctx, tree, hf_ranap_PagingCause_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_PDP_TypeInformation_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_ranap_PDP_TypeInformation(tvb, offset, &asn1_ctx, tree, hf_ranap_PDP_TypeInformation_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_PDP_TypeInformation_extension_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_ranap_PDP_TypeInformation_extension(tvb, offset, &asn1_ctx, tree, hf_ranap_PDP_TypeInformation_extension_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_PeriodicLocationInfo_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_ranap_PeriodicLocationInfo(tvb, offset, &asn1_ctx, tree, hf_ranap_PeriodicLocationInfo_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_PermanentNAS_UE_ID_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_ranap_PermanentNAS_UE_ID(tvb, offset, &asn1_ctx, tree, hf_ranap_PermanentNAS_UE_ID_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_PLMNidentity_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_ranap_PLMNidentity(tvb, offset, &asn1_ctx, tree, hf_ranap_PLMNidentity_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_PositioningPriority_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_ranap_PositioningPriority(tvb, offset, &asn1_ctx, tree, hf_ranap_PositioningPriority_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_PositionData_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_ranap_PositionData(tvb, offset, &asn1_ctx, tree, hf_ranap_PositionData_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_PositionDataSpecificToGERANIuMode_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_ranap_PositionDataSpecificToGERANIuMode(tvb, offset, &asn1_ctx, tree, hf_ranap_PositionDataSpecificToGERANIuMode_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_Priority_Class_Indicator_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_ranap_Priority_Class_Indicator(tvb, offset, &asn1_ctx, tree, hf_ranap_Priority_Class_Indicator_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_ProvidedData_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_ranap_ProvidedData(tvb, offset, &asn1_ctx, tree, hf_ranap_ProvidedData_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_RAB_ID_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_ranap_RAB_ID(tvb, offset, &asn1_ctx, tree, hf_ranap_RAB_ID_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_RAB_Parameter_ExtendedGuaranteedBitrateList_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_ranap_RAB_Parameter_ExtendedGuaranteedBitrateList(tvb, offset, &asn1_ctx, tree, hf_ranap_RAB_Parameter_ExtendedGuaranteedBitrateList_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_RAB_Parameter_ExtendedMaxBitrateList_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_ranap_RAB_Parameter_ExtendedMaxBitrateList(tvb, offset, &asn1_ctx, tree, hf_ranap_RAB_Parameter_ExtendedMaxBitrateList_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_RAB_Parameters_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_ranap_RAB_Parameters(tvb, offset, &asn1_ctx, tree, hf_ranap_RAB_Parameters_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_RABParametersList_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_ranap_RABParametersList(tvb, offset, &asn1_ctx, tree, hf_ranap_RABParametersList_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_RAC_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_ranap_RAC(tvb, offset, &asn1_ctx, tree, hf_ranap_RAC_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_RAListofIdleModeUEs_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_ranap_RAListofIdleModeUEs(tvb, offset, &asn1_ctx, tree, hf_ranap_RAListofIdleModeUEs_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_LAListofIdleModeUEs_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_ranap_LAListofIdleModeUEs(tvb, offset, &asn1_ctx, tree, hf_ranap_LAListofIdleModeUEs_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_RAT_Type_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_ranap_RAT_Type(tvb, offset, &asn1_ctx, tree, hf_ranap_RAT_Type_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_RedirectAttemptFlag_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_ranap_RedirectAttemptFlag(tvb, offset, &asn1_ctx, tree, hf_ranap_RedirectAttemptFlag_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_RedirectionCompleted_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_ranap_RedirectionCompleted(tvb, offset, &asn1_ctx, tree, hf_ranap_RedirectionCompleted_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_RejectCauseValue_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_ranap_RejectCauseValue(tvb, offset, &asn1_ctx, tree, hf_ranap_RejectCauseValue_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_RelocationType_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_ranap_RelocationType(tvb, offset, &asn1_ctx, tree, hf_ranap_RelocationType_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_RequestedGANSSAssistanceData_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_ranap_RequestedGANSSAssistanceData(tvb, offset, &asn1_ctx, tree, hf_ranap_RequestedGANSSAssistanceData_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_Requested_RAB_Parameter_ExtendedMaxBitrateList_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_ranap_Requested_RAB_Parameter_ExtendedMaxBitrateList(tvb, offset, &asn1_ctx, tree, hf_ranap_Requested_RAB_Parameter_ExtendedMaxBitrateList_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_Requested_RAB_Parameter_ExtendedGuaranteedBitrateList_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_ranap_Requested_RAB_Parameter_ExtendedGuaranteedBitrateList(tvb, offset, &asn1_ctx, tree, hf_ranap_Requested_RAB_Parameter_ExtendedGuaranteedBitrateList_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_RequestType_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_ranap_RequestType(tvb, offset, &asn1_ctx, tree, hf_ranap_RequestType_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_ResponseTime_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_ranap_ResponseTime(tvb, offset, &asn1_ctx, tree, hf_ranap_ResponseTime_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_RNSAPRelocationParameters_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_ranap_RNSAPRelocationParameters(tvb, offset, &asn1_ctx, tree, hf_ranap_RNSAPRelocationParameters_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_RRC_Container_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_ranap_RRC_Container(tvb, offset, &asn1_ctx, tree, hf_ranap_RRC_Container_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_SAI_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_ranap_SAI(tvb, offset, &asn1_ctx, tree, hf_ranap_SAI_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_SAPI_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_ranap_SAPI(tvb, offset, &asn1_ctx, tree, hf_ranap_SAPI_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_SessionUpdateID_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_ranap_SessionUpdateID(tvb, offset, &asn1_ctx, tree, hf_ranap_SessionUpdateID_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_SignallingIndication_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_ranap_SignallingIndication(tvb, offset, &asn1_ctx, tree, hf_ranap_SignallingIndication_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_SNA_Access_Information_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_ranap_SNA_Access_Information(tvb, offset, &asn1_ctx, tree, hf_ranap_SNA_Access_Information_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_Source_ToTarget_TransparentContainer_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_ranap_Source_ToTarget_TransparentContainer(tvb, offset, &asn1_ctx, tree, hf_ranap_Source_ToTarget_TransparentContainer_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
int dissect_ranap_SourceCellID_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_ranap_SourceCellID(tvb, offset, &asn1_ctx, tree, hf_ranap_ranap_SourceCellID_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_SourceBSS_ToTargetBSS_TransparentContainer_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_ranap_SourceBSS_ToTargetBSS_TransparentContainer(tvb, offset, &asn1_ctx, tree, hf_ranap_SourceBSS_ToTargetBSS_TransparentContainer_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_SourceID_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_ranap_SourceID(tvb, offset, &asn1_ctx, tree, hf_ranap_SourceID_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
int dissect_ranap_SourceRNC_ToTargetRNC_TransparentContainer_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_ranap_SourceRNC_ToTargetRNC_TransparentContainer(tvb, offset, &asn1_ctx, tree, hf_ranap_ranap_SourceRNC_ToTargetRNC_TransparentContainer_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_IRAT_Measurement_Configuration_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_ranap_IRAT_Measurement_Configuration(tvb, offset, &asn1_ctx, tree, hf_ranap_IRAT_Measurement_Configuration_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_SubscriberProfileIDforRFP_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_ranap_SubscriberProfileIDforRFP(tvb, offset, &asn1_ctx, tree, hf_ranap_SubscriberProfileIDforRFP_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_SupportedRAB_ParameterBitrateList_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_ranap_SupportedRAB_ParameterBitrateList(tvb, offset, &asn1_ctx, tree, hf_ranap_SupportedRAB_ParameterBitrateList_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_SRB_TrCH_Mapping_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_ranap_SRB_TrCH_Mapping(tvb, offset, &asn1_ctx, tree, hf_ranap_SRB_TrCH_Mapping_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_SRVCC_HO_Indication_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_ranap_SRVCC_HO_Indication(tvb, offset, &asn1_ctx, tree, hf_ranap_SRVCC_HO_Indication_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_SRVCC_Information_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_ranap_SRVCC_Information(tvb, offset, &asn1_ctx, tree, hf_ranap_SRVCC_Information_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_SRVCC_Operation_Possible_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_ranap_SRVCC_Operation_Possible(tvb, offset, &asn1_ctx, tree, hf_ranap_SRVCC_Operation_Possible_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_Target_ToSource_TransparentContainer_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_ranap_Target_ToSource_TransparentContainer(tvb, offset, &asn1_ctx, tree, hf_ranap_Target_ToSource_TransparentContainer_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_TargetBSS_ToSourceBSS_TransparentContainer_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_ranap_TargetBSS_ToSourceBSS_TransparentContainer(tvb, offset, &asn1_ctx, tree, hf_ranap_TargetBSS_ToSourceBSS_TransparentContainer_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_TargetID_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_ranap_TargetID(tvb, offset, &asn1_ctx, tree, hf_ranap_TargetID_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
int dissect_ranap_TargetRNC_ID_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_ranap_TargetRNC_ID(tvb, offset, &asn1_ctx, tree, hf_ranap_ranap_TargetRNC_ID_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_TargetRNC_ToSourceRNC_TransparentContainer_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_ranap_TargetRNC_ToSourceRNC_TransparentContainer(tvb, offset, &asn1_ctx, tree, hf_ranap_TargetRNC_ToSourceRNC_TransparentContainer_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_TemporaryUE_ID_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_ranap_TemporaryUE_ID(tvb, offset, &asn1_ctx, tree, hf_ranap_TemporaryUE_ID_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_TimeToMBMSDataTransfer_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_ranap_TimeToMBMSDataTransfer(tvb, offset, &asn1_ctx, tree, hf_ranap_TimeToMBMSDataTransfer_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_TMGI_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_ranap_TMGI(tvb, offset, &asn1_ctx, tree, hf_ranap_TMGI_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_TracePropagationParameters_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_ranap_TracePropagationParameters(tvb, offset, &asn1_ctx, tree, hf_ranap_TracePropagationParameters_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_TraceRecordingSessionInformation_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_ranap_TraceRecordingSessionInformation(tvb, offset, &asn1_ctx, tree, hf_ranap_TraceRecordingSessionInformation_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_TraceReference_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_ranap_TraceReference(tvb, offset, &asn1_ctx, tree, hf_ranap_TraceReference_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_TraceType_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_ranap_TraceType(tvb, offset, &asn1_ctx, tree, hf_ranap_TraceType_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_TransportLayerAddress_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_ranap_TransportLayerAddress(tvb, offset, &asn1_ctx, tree, hf_ranap_TransportLayerAddress_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_TriggerID_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_ranap_TriggerID(tvb, offset, &asn1_ctx, tree, hf_ranap_TriggerID_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_TypeOfError_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_ranap_TypeOfError(tvb, offset, &asn1_ctx, tree, hf_ranap_TypeOfError_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_UE_AggregateMaximumBitRate_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_ranap_UE_AggregateMaximumBitRate(tvb, offset, &asn1_ctx, tree, hf_ranap_UE_AggregateMaximumBitRate_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_UE_History_Information_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_ranap_UE_History_Information(tvb, offset, &asn1_ctx, tree, hf_ranap_UE_History_Information_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_UE_ID_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_ranap_UE_ID(tvb, offset, &asn1_ctx, tree, hf_ranap_UE_ID_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_UESBI_Iu_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_ranap_UESBI_Iu(tvb, offset, &asn1_ctx, tree, hf_ranap_UESBI_Iu_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_VelocityEstimate_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_ranap_VelocityEstimate(tvb, offset, &asn1_ctx, tree, hf_ranap_VelocityEstimate_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_VerticalAccuracyCode_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_ranap_VerticalAccuracyCode(tvb, offset, &asn1_ctx, tree, hf_ranap_VerticalAccuracyCode_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_Iu_ReleaseCommand_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_ranap_Iu_ReleaseCommand(tvb, offset, &asn1_ctx, tree, hf_ranap_Iu_ReleaseCommand_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_Iu_ReleaseComplete_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_ranap_Iu_ReleaseComplete(tvb, offset, &asn1_ctx, tree, hf_ranap_Iu_ReleaseComplete_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_RAB_DataVolumeReportList_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_ranap_RAB_DataVolumeReportList(tvb, offset, &asn1_ctx, tree, hf_ranap_RAB_DataVolumeReportList_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_RAB_DataVolumeReportItem_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_ranap_RAB_DataVolumeReportItem(tvb, offset, &asn1_ctx, tree, hf_ranap_RAB_DataVolumeReportItem_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_RAB_ReleasedList_IuRelComp_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_ranap_RAB_ReleasedList_IuRelComp(tvb, offset, &asn1_ctx, tree, hf_ranap_RAB_ReleasedList_IuRelComp_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_RAB_ReleasedItem_IuRelComp_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_ranap_RAB_ReleasedItem_IuRelComp(tvb, offset, &asn1_ctx, tree, hf_ranap_RAB_ReleasedItem_IuRelComp_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_RelocationRequired_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_ranap_RelocationRequired(tvb, offset, &asn1_ctx, tree, hf_ranap_RelocationRequired_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_RelocationCommand_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_ranap_RelocationCommand(tvb, offset, &asn1_ctx, tree, hf_ranap_RelocationCommand_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_RAB_RelocationReleaseList_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_ranap_RAB_RelocationReleaseList(tvb, offset, &asn1_ctx, tree, hf_ranap_RAB_RelocationReleaseList_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_RAB_RelocationReleaseItem_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_ranap_RAB_RelocationReleaseItem(tvb, offset, &asn1_ctx, tree, hf_ranap_RAB_RelocationReleaseItem_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_RAB_DataForwardingList_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_ranap_RAB_DataForwardingList(tvb, offset, &asn1_ctx, tree, hf_ranap_RAB_DataForwardingList_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_RAB_DataForwardingItem_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_ranap_RAB_DataForwardingItem(tvb, offset, &asn1_ctx, tree, hf_ranap_RAB_DataForwardingItem_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_RelocationPreparationFailure_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_ranap_RelocationPreparationFailure(tvb, offset, &asn1_ctx, tree, hf_ranap_RelocationPreparationFailure_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_RelocationRequest_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_ranap_RelocationRequest(tvb, offset, &asn1_ctx, tree, hf_ranap_RelocationRequest_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_RAB_SetupList_RelocReq_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_ranap_RAB_SetupList_RelocReq(tvb, offset, &asn1_ctx, tree, hf_ranap_RAB_SetupList_RelocReq_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_RAB_SetupItem_RelocReq_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_ranap_RAB_SetupItem_RelocReq(tvb, offset, &asn1_ctx, tree, hf_ranap_RAB_SetupItem_RelocReq_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_CNMBMSLinkingInformation_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_ranap_CNMBMSLinkingInformation(tvb, offset, &asn1_ctx, tree, hf_ranap_CNMBMSLinkingInformation_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_JoinedMBMSBearerService_IEs_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_ranap_JoinedMBMSBearerService_IEs(tvb, offset, &asn1_ctx, tree, hf_ranap_JoinedMBMSBearerService_IEs_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_RelocationRequestAcknowledge_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_ranap_RelocationRequestAcknowledge(tvb, offset, &asn1_ctx, tree, hf_ranap_RelocationRequestAcknowledge_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_RAB_SetupList_RelocReqAck_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_ranap_RAB_SetupList_RelocReqAck(tvb, offset, &asn1_ctx, tree, hf_ranap_RAB_SetupList_RelocReqAck_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_RAB_SetupItem_RelocReqAck_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_ranap_RAB_SetupItem_RelocReqAck(tvb, offset, &asn1_ctx, tree, hf_ranap_RAB_SetupItem_RelocReqAck_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_RAB_FailedList_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_ranap_RAB_FailedList(tvb, offset, &asn1_ctx, tree, hf_ranap_RAB_FailedList_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_RAB_FailedItem_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_ranap_RAB_FailedItem(tvb, offset, &asn1_ctx, tree, hf_ranap_RAB_FailedItem_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_RelocationFailure_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_ranap_RelocationFailure(tvb, offset, &asn1_ctx, tree, hf_ranap_RelocationFailure_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_RelocationCancel_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_ranap_RelocationCancel(tvb, offset, &asn1_ctx, tree, hf_ranap_RelocationCancel_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_RelocationCancelAcknowledge_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_ranap_RelocationCancelAcknowledge(tvb, offset, &asn1_ctx, tree, hf_ranap_RelocationCancelAcknowledge_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_SRNS_ContextRequest_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_ranap_SRNS_ContextRequest(tvb, offset, &asn1_ctx, tree, hf_ranap_SRNS_ContextRequest_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_RAB_DataForwardingList_SRNS_CtxReq_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_ranap_RAB_DataForwardingList_SRNS_CtxReq(tvb, offset, &asn1_ctx, tree, hf_ranap_RAB_DataForwardingList_SRNS_CtxReq_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_RAB_DataForwardingItem_SRNS_CtxReq_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_ranap_RAB_DataForwardingItem_SRNS_CtxReq(tvb, offset, &asn1_ctx, tree, hf_ranap_RAB_DataForwardingItem_SRNS_CtxReq_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_SRNS_ContextResponse_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_ranap_SRNS_ContextResponse(tvb, offset, &asn1_ctx, tree, hf_ranap_SRNS_ContextResponse_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_RAB_ContextList_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_ranap_RAB_ContextList(tvb, offset, &asn1_ctx, tree, hf_ranap_RAB_ContextList_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_RAB_ContextItem_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_ranap_RAB_ContextItem(tvb, offset, &asn1_ctx, tree, hf_ranap_RAB_ContextItem_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_RAB_ContextFailedtoTransferList_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_ranap_RAB_ContextFailedtoTransferList(tvb, offset, &asn1_ctx, tree, hf_ranap_RAB_ContextFailedtoTransferList_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_RABs_ContextFailedtoTransferItem_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_ranap_RABs_ContextFailedtoTransferItem(tvb, offset, &asn1_ctx, tree, hf_ranap_RABs_ContextFailedtoTransferItem_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_SecurityModeCommand_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_ranap_SecurityModeCommand(tvb, offset, &asn1_ctx, tree, hf_ranap_SecurityModeCommand_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_SecurityModeComplete_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_ranap_SecurityModeComplete(tvb, offset, &asn1_ctx, tree, hf_ranap_SecurityModeComplete_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_SecurityModeReject_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_ranap_SecurityModeReject(tvb, offset, &asn1_ctx, tree, hf_ranap_SecurityModeReject_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_DataVolumeReportRequest_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_ranap_DataVolumeReportRequest(tvb, offset, &asn1_ctx, tree, hf_ranap_DataVolumeReportRequest_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_RAB_DataVolumeReportRequestList_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_ranap_RAB_DataVolumeReportRequestList(tvb, offset, &asn1_ctx, tree, hf_ranap_RAB_DataVolumeReportRequestList_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_RAB_DataVolumeReportRequestItem_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_ranap_RAB_DataVolumeReportRequestItem(tvb, offset, &asn1_ctx, tree, hf_ranap_RAB_DataVolumeReportRequestItem_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_DataVolumeReport_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_ranap_DataVolumeReport(tvb, offset, &asn1_ctx, tree, hf_ranap_DataVolumeReport_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_RAB_FailedtoReportList_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_ranap_RAB_FailedtoReportList(tvb, offset, &asn1_ctx, tree, hf_ranap_RAB_FailedtoReportList_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_RABs_failed_to_reportItem_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_ranap_RABs_failed_to_reportItem(tvb, offset, &asn1_ctx, tree, hf_ranap_RABs_failed_to_reportItem_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_Reset_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_ranap_Reset(tvb, offset, &asn1_ctx, tree, hf_ranap_Reset_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_ResetAcknowledge_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_ranap_ResetAcknowledge(tvb, offset, &asn1_ctx, tree, hf_ranap_ResetAcknowledge_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_ResetResource_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_ranap_ResetResource(tvb, offset, &asn1_ctx, tree, hf_ranap_ResetResource_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_ResetResourceList_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_ranap_ResetResourceList(tvb, offset, &asn1_ctx, tree, hf_ranap_ResetResourceList_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_ResetResourceItem_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_ranap_ResetResourceItem(tvb, offset, &asn1_ctx, tree, hf_ranap_ResetResourceItem_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_ResetResourceAcknowledge_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_ranap_ResetResourceAcknowledge(tvb, offset, &asn1_ctx, tree, hf_ranap_ResetResourceAcknowledge_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_ResetResourceAckList_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_ranap_ResetResourceAckList(tvb, offset, &asn1_ctx, tree, hf_ranap_ResetResourceAckList_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_ResetResourceAckItem_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_ranap_ResetResourceAckItem(tvb, offset, &asn1_ctx, tree, hf_ranap_ResetResourceAckItem_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_RAB_ReleaseRequest_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_ranap_RAB_ReleaseRequest(tvb, offset, &asn1_ctx, tree, hf_ranap_RAB_ReleaseRequest_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_RAB_ReleaseList_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_ranap_RAB_ReleaseList(tvb, offset, &asn1_ctx, tree, hf_ranap_RAB_ReleaseList_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_RAB_ReleaseItem_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_ranap_RAB_ReleaseItem(tvb, offset, &asn1_ctx, tree, hf_ranap_RAB_ReleaseItem_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_Iu_ReleaseRequest_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_ranap_Iu_ReleaseRequest(tvb, offset, &asn1_ctx, tree, hf_ranap_Iu_ReleaseRequest_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_RelocationDetect_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_ranap_RelocationDetect(tvb, offset, &asn1_ctx, tree, hf_ranap_RelocationDetect_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_RelocationComplete_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_ranap_RelocationComplete(tvb, offset, &asn1_ctx, tree, hf_ranap_RelocationComplete_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_EnhancedRelocationCompleteRequest_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_ranap_EnhancedRelocationCompleteRequest(tvb, offset, &asn1_ctx, tree, hf_ranap_EnhancedRelocationCompleteRequest_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_RAB_SetupList_EnhancedRelocCompleteReq_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_ranap_RAB_SetupList_EnhancedRelocCompleteReq(tvb, offset, &asn1_ctx, tree, hf_ranap_RAB_SetupList_EnhancedRelocCompleteReq_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_RAB_SetupItem_EnhancedRelocCompleteReq_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_ranap_RAB_SetupItem_EnhancedRelocCompleteReq(tvb, offset, &asn1_ctx, tree, hf_ranap_RAB_SetupItem_EnhancedRelocCompleteReq_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_EnhancedRelocationCompleteResponse_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_ranap_EnhancedRelocationCompleteResponse(tvb, offset, &asn1_ctx, tree, hf_ranap_EnhancedRelocationCompleteResponse_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_RAB_SetupList_EnhancedRelocCompleteRes_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_ranap_RAB_SetupList_EnhancedRelocCompleteRes(tvb, offset, &asn1_ctx, tree, hf_ranap_RAB_SetupList_EnhancedRelocCompleteRes_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_RAB_SetupItem_EnhancedRelocCompleteRes_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_ranap_RAB_SetupItem_EnhancedRelocCompleteRes(tvb, offset, &asn1_ctx, tree, hf_ranap_RAB_SetupItem_EnhancedRelocCompleteRes_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_RAB_ToBeReleasedList_EnhancedRelocCompleteRes_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_ranap_RAB_ToBeReleasedList_EnhancedRelocCompleteRes(tvb, offset, &asn1_ctx, tree, hf_ranap_RAB_ToBeReleasedList_EnhancedRelocCompleteRes_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_RAB_ToBeReleasedItem_EnhancedRelocCompleteRes_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_ranap_RAB_ToBeReleasedItem_EnhancedRelocCompleteRes(tvb, offset, &asn1_ctx, tree, hf_ranap_RAB_ToBeReleasedItem_EnhancedRelocCompleteRes_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_EnhancedRelocationCompleteFailure_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_ranap_EnhancedRelocationCompleteFailure(tvb, offset, &asn1_ctx, tree, hf_ranap_EnhancedRelocationCompleteFailure_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_EnhancedRelocationCompleteConfirm_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_ranap_EnhancedRelocationCompleteConfirm(tvb, offset, &asn1_ctx, tree, hf_ranap_EnhancedRelocationCompleteConfirm_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_Paging_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_ranap_Paging(tvb, offset, &asn1_ctx, tree, hf_ranap_Paging_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_CommonID_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_ranap_CommonID(tvb, offset, &asn1_ctx, tree, hf_ranap_CommonID_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_CN_InvokeTrace_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_ranap_CN_InvokeTrace(tvb, offset, &asn1_ctx, tree, hf_ranap_CN_InvokeTrace_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_CN_DeactivateTrace_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_ranap_CN_DeactivateTrace(tvb, offset, &asn1_ctx, tree, hf_ranap_CN_DeactivateTrace_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_LocationReportingControl_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_ranap_LocationReportingControl(tvb, offset, &asn1_ctx, tree, hf_ranap_LocationReportingControl_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_LocationReport_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_ranap_LocationReport(tvb, offset, &asn1_ctx, tree, hf_ranap_LocationReport_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_InitialUE_Message_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_ranap_InitialUE_Message(tvb, offset, &asn1_ctx, tree, hf_ranap_InitialUE_Message_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_DirectTransfer_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_ranap_DirectTransfer(tvb, offset, &asn1_ctx, tree, hf_ranap_DirectTransfer_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_RedirectionIndication_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_ranap_RedirectionIndication(tvb, offset, &asn1_ctx, tree, hf_ranap_RedirectionIndication_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_Overload_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_ranap_Overload(tvb, offset, &asn1_ctx, tree, hf_ranap_Overload_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_ErrorIndication_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_ranap_ErrorIndication(tvb, offset, &asn1_ctx, tree, hf_ranap_ErrorIndication_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_SRNS_DataForwardCommand_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_ranap_SRNS_DataForwardCommand(tvb, offset, &asn1_ctx, tree, hf_ranap_SRNS_DataForwardCommand_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_ForwardSRNS_Context_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_ranap_ForwardSRNS_Context(tvb, offset, &asn1_ctx, tree, hf_ranap_ForwardSRNS_Context_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_RAB_AssignmentRequest_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_ranap_RAB_AssignmentRequest(tvb, offset, &asn1_ctx, tree, hf_ranap_RAB_AssignmentRequest_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_RAB_SetupOrModifyList_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_ranap_RAB_SetupOrModifyList(tvb, offset, &asn1_ctx, tree, hf_ranap_RAB_SetupOrModifyList_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_RAB_SetupOrModifyItemFirst_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_ranap_RAB_SetupOrModifyItemFirst(tvb, offset, &asn1_ctx, tree, hf_ranap_RAB_SetupOrModifyItemFirst_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_TransportLayerInformation_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_ranap_TransportLayerInformation(tvb, offset, &asn1_ctx, tree, hf_ranap_TransportLayerInformation_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_RAB_SetupOrModifyItemSecond_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_ranap_RAB_SetupOrModifyItemSecond(tvb, offset, &asn1_ctx, tree, hf_ranap_RAB_SetupOrModifyItemSecond_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_RAB_AssignmentResponse_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_ranap_RAB_AssignmentResponse(tvb, offset, &asn1_ctx, tree, hf_ranap_RAB_AssignmentResponse_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_RAB_SetupOrModifiedList_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_ranap_RAB_SetupOrModifiedList(tvb, offset, &asn1_ctx, tree, hf_ranap_RAB_SetupOrModifiedList_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_RAB_SetupOrModifiedItem_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_ranap_RAB_SetupOrModifiedItem(tvb, offset, &asn1_ctx, tree, hf_ranap_RAB_SetupOrModifiedItem_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_RAB_ReleasedList_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_ranap_RAB_ReleasedList(tvb, offset, &asn1_ctx, tree, hf_ranap_RAB_ReleasedList_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_RAB_ReleasedItem_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_ranap_RAB_ReleasedItem(tvb, offset, &asn1_ctx, tree, hf_ranap_RAB_ReleasedItem_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_RAB_QueuedList_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_ranap_RAB_QueuedList(tvb, offset, &asn1_ctx, tree, hf_ranap_RAB_QueuedList_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_RAB_QueuedItem_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_ranap_RAB_QueuedItem(tvb, offset, &asn1_ctx, tree, hf_ranap_RAB_QueuedItem_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_RAB_ReleaseFailedList_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_ranap_RAB_ReleaseFailedList(tvb, offset, &asn1_ctx, tree, hf_ranap_RAB_ReleaseFailedList_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_GERAN_Iumode_RAB_FailedList_RABAssgntResponse_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_ranap_GERAN_Iumode_RAB_FailedList_RABAssgntResponse(tvb, offset, &asn1_ctx, tree, hf_ranap_GERAN_Iumode_RAB_FailedList_RABAssgntResponse_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_GERAN_Iumode_RAB_Failed_RABAssgntResponse_Item_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_ranap_GERAN_Iumode_RAB_Failed_RABAssgntResponse_Item(tvb, offset, &asn1_ctx, tree, hf_ranap_GERAN_Iumode_RAB_Failed_RABAssgntResponse_Item_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_PrivateMessage_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_ranap_PrivateMessage(tvb, offset, &asn1_ctx, tree, hf_ranap_PrivateMessage_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_RANAP_RelocationInformation_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_ranap_RANAP_RelocationInformation(tvb, offset, &asn1_ctx, tree, hf_ranap_RANAP_RelocationInformation_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_DirectTransferInformationList_RANAP_RelocInf_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_ranap_DirectTransferInformationList_RANAP_RelocInf(tvb, offset, &asn1_ctx, tree, hf_ranap_DirectTransferInformationList_RANAP_RelocInf_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_DirectTransferInformationItem_RANAP_RelocInf_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_ranap_DirectTransferInformationItem_RANAP_RelocInf(tvb, offset, &asn1_ctx, tree, hf_ranap_DirectTransferInformationItem_RANAP_RelocInf_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_RAB_ContextList_RANAP_RelocInf_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_ranap_RAB_ContextList_RANAP_RelocInf(tvb, offset, &asn1_ctx, tree, hf_ranap_RAB_ContextList_RANAP_RelocInf_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_RAB_ContextItem_RANAP_RelocInf_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_ranap_RAB_ContextItem_RANAP_RelocInf(tvb, offset, &asn1_ctx, tree, hf_ranap_RAB_ContextItem_RANAP_RelocInf_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_RANAP_EnhancedRelocationInformationRequest_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_ranap_RANAP_EnhancedRelocationInformationRequest(tvb, offset, &asn1_ctx, tree, hf_ranap_RANAP_EnhancedRelocationInformationRequest_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_RAB_SetupList_EnhRelocInfoReq_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_ranap_RAB_SetupList_EnhRelocInfoReq(tvb, offset, &asn1_ctx, tree, hf_ranap_RAB_SetupList_EnhRelocInfoReq_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_RAB_SetupItem_EnhRelocInfoReq_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_ranap_RAB_SetupItem_EnhRelocInfoReq(tvb, offset, &asn1_ctx, tree, hf_ranap_RAB_SetupItem_EnhRelocInfoReq_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_RANAP_EnhancedRelocationInformationResponse_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_ranap_RANAP_EnhancedRelocationInformationResponse(tvb, offset, &asn1_ctx, tree, hf_ranap_RANAP_EnhancedRelocationInformationResponse_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_RAB_SetupList_EnhRelocInfoRes_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_ranap_RAB_SetupList_EnhRelocInfoRes(tvb, offset, &asn1_ctx, tree, hf_ranap_RAB_SetupList_EnhRelocInfoRes_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_RAB_SetupItem_EnhRelocInfoRes_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_ranap_RAB_SetupItem_EnhRelocInfoRes(tvb, offset, &asn1_ctx, tree, hf_ranap_RAB_SetupItem_EnhRelocInfoRes_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_RAB_FailedList_EnhRelocInfoRes_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_ranap_RAB_FailedList_EnhRelocInfoRes(tvb, offset, &asn1_ctx, tree, hf_ranap_RAB_FailedList_EnhRelocInfoRes_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_RAB_FailedItem_EnhRelocInfoRes_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_ranap_RAB_FailedItem_EnhRelocInfoRes(tvb, offset, &asn1_ctx, tree, hf_ranap_RAB_FailedItem_EnhRelocInfoRes_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_RAB_ModifyRequest_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_ranap_RAB_ModifyRequest(tvb, offset, &asn1_ctx, tree, hf_ranap_RAB_ModifyRequest_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_RAB_ModifyList_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_ranap_RAB_ModifyList(tvb, offset, &asn1_ctx, tree, hf_ranap_RAB_ModifyList_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_RAB_ModifyItem_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_ranap_RAB_ModifyItem(tvb, offset, &asn1_ctx, tree, hf_ranap_RAB_ModifyItem_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_LocationRelatedDataRequest_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_ranap_LocationRelatedDataRequest(tvb, offset, &asn1_ctx, tree, hf_ranap_LocationRelatedDataRequest_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_LocationRelatedDataResponse_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_ranap_LocationRelatedDataResponse(tvb, offset, &asn1_ctx, tree, hf_ranap_LocationRelatedDataResponse_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_LocationRelatedDataFailure_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_ranap_LocationRelatedDataFailure(tvb, offset, &asn1_ctx, tree, hf_ranap_LocationRelatedDataFailure_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_InformationTransferIndication_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_ranap_InformationTransferIndication(tvb, offset, &asn1_ctx, tree, hf_ranap_InformationTransferIndication_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_InformationTransferConfirmation_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_ranap_InformationTransferConfirmation(tvb, offset, &asn1_ctx, tree, hf_ranap_InformationTransferConfirmation_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_InformationTransferFailure_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_ranap_InformationTransferFailure(tvb, offset, &asn1_ctx, tree, hf_ranap_InformationTransferFailure_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_UESpecificInformationIndication_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_ranap_UESpecificInformationIndication(tvb, offset, &asn1_ctx, tree, hf_ranap_UESpecificInformationIndication_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_DirectInformationTransfer_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_ranap_DirectInformationTransfer(tvb, offset, &asn1_ctx, tree, hf_ranap_DirectInformationTransfer_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_UplinkInformationExchangeRequest_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_ranap_UplinkInformationExchangeRequest(tvb, offset, &asn1_ctx, tree, hf_ranap_UplinkInformationExchangeRequest_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_UplinkInformationExchangeResponse_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_ranap_UplinkInformationExchangeResponse(tvb, offset, &asn1_ctx, tree, hf_ranap_UplinkInformationExchangeResponse_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_UplinkInformationExchangeFailure_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_ranap_UplinkInformationExchangeFailure(tvb, offset, &asn1_ctx, tree, hf_ranap_UplinkInformationExchangeFailure_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_MBMSSessionStart_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_ranap_MBMSSessionStart(tvb, offset, &asn1_ctx, tree, hf_ranap_MBMSSessionStart_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_MBMSSynchronisationInformation_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_ranap_MBMSSynchronisationInformation(tvb, offset, &asn1_ctx, tree, hf_ranap_MBMSSynchronisationInformation_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_MBMSSessionStartResponse_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_ranap_MBMSSessionStartResponse(tvb, offset, &asn1_ctx, tree, hf_ranap_MBMSSessionStartResponse_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_MBMSSessionStartFailure_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_ranap_MBMSSessionStartFailure(tvb, offset, &asn1_ctx, tree, hf_ranap_MBMSSessionStartFailure_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_MBMSSessionUpdate_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_ranap_MBMSSessionUpdate(tvb, offset, &asn1_ctx, tree, hf_ranap_MBMSSessionUpdate_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_MBMSSessionUpdateResponse_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_ranap_MBMSSessionUpdateResponse(tvb, offset, &asn1_ctx, tree, hf_ranap_MBMSSessionUpdateResponse_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_MBMSSessionUpdateFailure_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_ranap_MBMSSessionUpdateFailure(tvb, offset, &asn1_ctx, tree, hf_ranap_MBMSSessionUpdateFailure_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_MBMSSessionStop_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_ranap_MBMSSessionStop(tvb, offset, &asn1_ctx, tree, hf_ranap_MBMSSessionStop_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_MBMSSessionStopResponse_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_ranap_MBMSSessionStopResponse(tvb, offset, &asn1_ctx, tree, hf_ranap_MBMSSessionStopResponse_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_MBMSUELinkingRequest_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_ranap_MBMSUELinkingRequest(tvb, offset, &asn1_ctx, tree, hf_ranap_MBMSUELinkingRequest_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_LeftMBMSBearerService_IEs_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_ranap_LeftMBMSBearerService_IEs(tvb, offset, &asn1_ctx, tree, hf_ranap_LeftMBMSBearerService_IEs_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_MBMSUELinkingResponse_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_ranap_MBMSUELinkingResponse(tvb, offset, &asn1_ctx, tree, hf_ranap_MBMSUELinkingResponse_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_UnsuccessfulLinking_IEs_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_ranap_UnsuccessfulLinking_IEs(tvb, offset, &asn1_ctx, tree, hf_ranap_UnsuccessfulLinking_IEs_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_MBMSRegistrationRequest_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_ranap_MBMSRegistrationRequest(tvb, offset, &asn1_ctx, tree, hf_ranap_MBMSRegistrationRequest_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_MBMSRegistrationResponse_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_ranap_MBMSRegistrationResponse(tvb, offset, &asn1_ctx, tree, hf_ranap_MBMSRegistrationResponse_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_MBMSRegistrationFailure_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_ranap_MBMSRegistrationFailure(tvb, offset, &asn1_ctx, tree, hf_ranap_MBMSRegistrationFailure_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_MBMSCNDe_RegistrationRequest_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_ranap_MBMSCNDe_RegistrationRequest(tvb, offset, &asn1_ctx, tree, hf_ranap_MBMSCNDe_RegistrationRequest_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_MBMSCNDe_RegistrationResponse_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_ranap_MBMSCNDe_RegistrationResponse(tvb, offset, &asn1_ctx, tree, hf_ranap_MBMSCNDe_RegistrationResponse_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_MBMSRABEstablishmentIndication_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_ranap_MBMSRABEstablishmentIndication(tvb, offset, &asn1_ctx, tree, hf_ranap_MBMSRABEstablishmentIndication_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_MBMSRABReleaseRequest_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_ranap_MBMSRABReleaseRequest(tvb, offset, &asn1_ctx, tree, hf_ranap_MBMSRABReleaseRequest_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_MBMSRABRelease_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_ranap_MBMSRABRelease(tvb, offset, &asn1_ctx, tree, hf_ranap_MBMSRABRelease_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_MBMSRABReleaseFailure_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_ranap_MBMSRABReleaseFailure(tvb, offset, &asn1_ctx, tree, hf_ranap_MBMSRABReleaseFailure_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_SRVCC_CSKeysRequest_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_ranap_SRVCC_CSKeysRequest(tvb, offset, &asn1_ctx, tree, hf_ranap_SRVCC_CSKeysRequest_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_SRVCC_CSKeysResponse_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_ranap_SRVCC_CSKeysResponse(tvb, offset, &asn1_ctx, tree, hf_ranap_SRVCC_CSKeysResponse_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_RANAP_PDU_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_ranap_RANAP_PDU(tvb, offset, &asn1_ctx, tree, hf_ranap_RANAP_PDU_PDU);
  offset += 7; offset >>= 3;
  return offset;
}


/*--- End of included file: packet-ranap-fn.c ---*/
#line 146 "../../asn1/ranap/packet-ranap-template.c"

static int
dissect_ProtocolIEFieldValue(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{

  int ret = 0;
  int key;

  /* Special handling, same ID used for different IE's depending on signal */
  switch(ProcedureCode){
	  case id_RelocationPreparation:
		  if((ProtocolIE_ID == id_Source_ToTarget_TransparentContainer)||(ProtocolIE_ID == id_Target_ToSource_TransparentContainer)){
			  key = SPECIAL | ProtocolIE_ID;
			  ret = (dissector_try_uint_new(ranap_ies_dissector_table, key, tvb, pinfo, tree, FALSE)) ? tvb_length(tvb) : 0;
			  break;
		  }
		  /* Fall trough */
	  default:
		  /* no special handling */
		  ret = (dissector_try_uint_new(ranap_ies_dissector_table, ProtocolIE_ID, tvb, pinfo, tree, FALSE)) ? tvb_length(tvb) : 0;
		  if (ret == 0) {
			  key = pdu_type | ProtocolIE_ID;
			  ret = (dissector_try_uint_new(ranap_ies_dissector_table, key, tvb, pinfo, tree, FALSE)) ? tvb_length(tvb) : 0;
		  }
		  break;
  }
  return ret;
}

static int
dissect_ProtocolIEFieldPairFirstValue(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
  return (dissector_try_uint_new(ranap_ies_p1_dissector_table, ProtocolIE_ID, tvb, pinfo, tree, FALSE)) ? tvb_length(tvb) : 0;
}

static int
dissect_ProtocolIEFieldPairSecondValue(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
  return (dissector_try_uint_new(ranap_ies_p2_dissector_table, ProtocolIE_ID, tvb, pinfo, tree, FALSE)) ? tvb_length(tvb) : 0;
}

static int
dissect_ProtocolExtensionFieldExtensionValue(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
  return (dissector_try_uint_new(ranap_extension_dissector_table, ProtocolExtensionID, tvb, pinfo, tree, FALSE)) ? tvb_length(tvb) : 0;
}

static int
dissect_InitiatingMessageValue(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
  gboolean ret;

  pdu_type = IMSG;
  ret = dissector_try_uint_new(ranap_proc_imsg_dissector_table, ProcedureCode, tvb, pinfo, tree, FALSE);
  pdu_type = 0;
  return ret ? tvb_length(tvb) : 0;
}

static int
dissect_SuccessfulOutcomeValue(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
  gboolean ret;

  pdu_type = SOUT;
  ret = dissector_try_uint_new(ranap_proc_sout_dissector_table, ProcedureCode, tvb, pinfo, tree, FALSE);
  pdu_type = 0;
  return ret ? tvb_length(tvb) : 0;
}

static int
dissect_UnsuccessfulOutcomeValue(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
  return (dissector_try_uint_new(ranap_proc_uout_dissector_table, ProcedureCode, tvb, pinfo, tree, FALSE)) ? tvb_length(tvb) : 0;
}

static int
dissect_OutcomeValue(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
  return (dissector_try_uint_new(ranap_proc_out_dissector_table, ProcedureCode, tvb, pinfo, tree, FALSE)) ? tvb_length(tvb) : 0;
}

static void
dissect_ranap(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	proto_item	*ranap_item = NULL;
	proto_tree	*ranap_tree = NULL;

	pdu_type = 0;
	ProtocolIE_ID = 0;

	/* make entry in the Protocol column on summary display */
	col_set_str(pinfo->cinfo, COL_PROTOCOL, "RANAP");

	/* create the ranap protocol tree */
	ranap_item = proto_tree_add_item(tree, proto_ranap, tvb, 0, -1, FALSE);
	ranap_tree = proto_item_add_subtree(ranap_item, ett_ranap);

	dissect_RANAP_PDU_PDU(tvb, pinfo, ranap_tree);
	if (pinfo->sccp_info) {
		sccp_msg_info_t* sccp_msg_lcl = pinfo->sccp_info;

		if (sccp_msg_lcl->data.co.assoc)
			sccp_msg_lcl->data.co.assoc->payload = SCCP_PLOAD_RANAP;

		if (! sccp_msg_lcl->data.co.label && ProcedureCode != 0xFFFFFFFF) {
			const gchar* str = val_to_str(ProcedureCode, ranap_ProcedureCode_vals,"Unknown RANAP");
			sccp_msg_lcl->data.co.label = se_strdup(str);
		}
	}
}

static gboolean
dissect_sccp_ranap_heur(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    guint8 temp;
	asn1_ctx_t asn1_ctx;
	guint length;
	int offset;

	asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);

    /* Is it a ranap packet?
     *
     * 4th octet should be the length of the rest of the message.
     * 2nd octet is the message-type e Z[0, 28]
     * (obviously there must be at least four octets)
     *
     * If both hold true we'll assume its RANAP
     */

    #define LENGTH_OFFSET 3
    #define MSG_TYPE_OFFSET 1
    if (tvb_length(tvb) < 4) { return FALSE; }
    /*if (tvb_get_guint8(tvb, LENGTH_OFFSET) != (tvb_length(tvb) - 4)) { return FALSE; }*/
	/* Read the length NOTE offset in bits */
	offset = dissect_per_length_determinant(tvb, LENGTH_OFFSET<<3, &asn1_ctx, tree, -1, &length);
	offset = offset>>3;
	if (length!= (tvb_length(tvb) - offset)){
		return FALSE;
	}

    temp = tvb_get_guint8(tvb, MSG_TYPE_OFFSET);
    if (temp > RANAP_MAX_PC) { return FALSE; }

    dissect_ranap(tvb, pinfo, tree);

    return TRUE;
}

/*--- proto_register_ranap -------------------------------------------*/
void proto_register_ranap(void) {
  module_t *ranap_module;

  /* List of fields */

  static hf_register_info hf[] = {
	{ &hf_ranap_imsi_digits,
      { "IMSI digits", "ranap.imsi_digits",
        FT_STRING, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_transportLayerAddress_ipv4,
      { "transportLayerAddress IPv4", "ranap.transportLayerAddress_ipv4",
        FT_IPv4, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_transportLayerAddress_ipv6,
      { "transportLayerAddress IPv6", "ranap.transportLayerAddress_ipv6",
        FT_IPv6, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_transportLayerAddress_nsap,
      { "transportLayerAddress NSAP", "ranap.transportLayerAddress_NSAP",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},



/*--- Included file: packet-ranap-hfarr.c ---*/
#line 1 "../../asn1/ranap/packet-ranap-hfarr.c"
    { &hf_ranap_AccuracyFulfilmentIndicator_PDU,
      { "AccuracyFulfilmentIndicator", "ranap.AccuracyFulfilmentIndicator",
        FT_UINT32, BASE_DEC, VALS(ranap_AccuracyFulfilmentIndicator_vals), 0,
        NULL, HFILL }},
    { &hf_ranap_Alt_RAB_Parameters_PDU,
      { "Alt-RAB-Parameters", "ranap.Alt_RAB_Parameters",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_Alt_RAB_Parameter_ExtendedGuaranteedBitrateInf_PDU,
      { "Alt-RAB-Parameter-ExtendedGuaranteedBitrateInf", "ranap.Alt_RAB_Parameter_ExtendedGuaranteedBitrateInf",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_Alt_RAB_Parameter_SupportedGuaranteedBitrateInf_PDU,
      { "Alt-RAB-Parameter-SupportedGuaranteedBitrateInf", "ranap.Alt_RAB_Parameter_SupportedGuaranteedBitrateInf",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_Alt_RAB_Parameter_ExtendedMaxBitrateInf_PDU,
      { "Alt-RAB-Parameter-ExtendedMaxBitrateInf", "ranap.Alt_RAB_Parameter_ExtendedMaxBitrateInf",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_Alt_RAB_Parameter_SupportedMaxBitrateInf_PDU,
      { "Alt-RAB-Parameter-SupportedMaxBitrateInf", "ranap.Alt_RAB_Parameter_SupportedMaxBitrateInf",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_AlternativeRABConfigurationRequest_PDU,
      { "AlternativeRABConfigurationRequest", "ranap.AlternativeRABConfigurationRequest",
        FT_UINT32, BASE_DEC, VALS(ranap_AlternativeRABConfigurationRequest_vals), 0,
        NULL, HFILL }},
    { &hf_ranap_APN_PDU,
      { "APN", "ranap.APN",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_AreaIdentity_PDU,
      { "AreaIdentity", "ranap.AreaIdentity",
        FT_UINT32, BASE_DEC, VALS(ranap_AreaIdentity_vals), 0,
        NULL, HFILL }},
    { &hf_ranap_Ass_RAB_Parameters_PDU,
      { "Ass-RAB-Parameters", "ranap.Ass_RAB_Parameters",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_Ass_RAB_Parameter_ExtendedGuaranteedBitrateList_PDU,
      { "Ass-RAB-Parameter-ExtendedGuaranteedBitrateList", "ranap.Ass_RAB_Parameter_ExtendedGuaranteedBitrateList",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_Ass_RAB_Parameter_ExtendedMaxBitrateList_PDU,
      { "Ass-RAB-Parameter-ExtendedMaxBitrateList", "ranap.Ass_RAB_Parameter_ExtendedMaxBitrateList",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_BroadcastAssistanceDataDecipheringKeys_PDU,
      { "BroadcastAssistanceDataDecipheringKeys", "ranap.BroadcastAssistanceDataDecipheringKeys",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_Cause_PDU,
      { "Cause", "ranap.Cause",
        FT_UINT32, BASE_DEC, VALS(ranap_Cause_vals), 0,
        NULL, HFILL }},
    { &hf_ranap_Cell_Access_Mode_PDU,
      { "Cell-Access-Mode", "ranap.Cell_Access_Mode",
        FT_UINT32, BASE_DEC, VALS(ranap_Cell_Access_Mode_vals), 0,
        NULL, HFILL }},
    { &hf_ranap_CellLoadInformationGroup_PDU,
      { "CellLoadInformationGroup", "ranap.CellLoadInformationGroup",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_ClientType_PDU,
      { "ClientType", "ranap.ClientType",
        FT_UINT32, BASE_DEC, VALS(ranap_ClientType_vals), 0,
        NULL, HFILL }},
    { &hf_ranap_CriticalityDiagnostics_PDU,
      { "CriticalityDiagnostics", "ranap.CriticalityDiagnostics",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_MessageStructure_PDU,
      { "MessageStructure", "ranap.MessageStructure",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_ChosenEncryptionAlgorithm_PDU,
      { "ChosenEncryptionAlgorithm", "ranap.ChosenEncryptionAlgorithm",
        FT_UINT32, BASE_DEC, VALS(ranap_EncryptionAlgorithm_vals), 0,
        NULL, HFILL }},
    { &hf_ranap_ChosenIntegrityProtectionAlgorithm_PDU,
      { "ChosenIntegrityProtectionAlgorithm", "ranap.ChosenIntegrityProtectionAlgorithm",
        FT_UINT32, BASE_DEC, VALS(ranap_IntegrityProtectionAlgorithm_vals), 0,
        NULL, HFILL }},
    { &hf_ranap_ClassmarkInformation2_PDU,
      { "ClassmarkInformation2", "ranap.ClassmarkInformation2",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_ClassmarkInformation3_PDU,
      { "ClassmarkInformation3", "ranap.ClassmarkInformation3",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_CN_DomainIndicator_PDU,
      { "CN-DomainIndicator", "ranap.CN_DomainIndicator",
        FT_UINT32, BASE_DEC, VALS(ranap_CN_DomainIndicator_vals), 0,
        NULL, HFILL }},
    { &hf_ranap_Correlation_ID_PDU,
      { "Correlation-ID", "ranap.Correlation_ID",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_CSFB_Information_PDU,
      { "CSFB-Information", "ranap.CSFB_Information",
        FT_UINT32, BASE_DEC, VALS(ranap_CSFB_Information_vals), 0,
        NULL, HFILL }},
    { &hf_ranap_CSG_Id_PDU,
      { "CSG-Id", "ranap.CSG_Id",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_CSG_Id_List_PDU,
      { "CSG-Id-List", "ranap.CSG_Id_List",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_CSG_Membership_Status_PDU,
      { "CSG-Membership-Status", "ranap.CSG_Membership_Status",
        FT_UINT32, BASE_DEC, VALS(ranap_CSG_Membership_Status_vals), 0,
        NULL, HFILL }},
    { &hf_ranap_DeltaRAListofIdleModeUEs_PDU,
      { "DeltaRAListofIdleModeUEs", "ranap.DeltaRAListofIdleModeUEs",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_DRX_CycleLengthCoefficient_PDU,
      { "DRX-CycleLengthCoefficient", "ranap.DRX_CycleLengthCoefficient",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_E_DCH_MAC_d_Flow_ID_PDU,
      { "E-DCH-MAC-d-Flow-ID", "ranap.E_DCH_MAC_d_Flow_ID",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_EncryptionInformation_PDU,
      { "EncryptionInformation", "ranap.EncryptionInformation",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_EncryptionKey_PDU,
      { "EncryptionKey", "ranap.EncryptionKey",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_E_UTRAN_Service_Handover_PDU,
      { "E-UTRAN-Service-Handover", "ranap.E_UTRAN_Service_Handover",
        FT_UINT32, BASE_DEC, VALS(ranap_E_UTRAN_Service_Handover_vals), 0,
        NULL, HFILL }},
    { &hf_ranap_ExtendedRNC_ID_PDU,
      { "ExtendedRNC-ID", "ranap.ExtendedRNC_ID",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_FrequenceLayerConvergenceFlag_PDU,
      { "FrequenceLayerConvergenceFlag", "ranap.FrequenceLayerConvergenceFlag",
        FT_UINT32, BASE_DEC, VALS(ranap_FrequenceLayerConvergenceFlag_vals), 0,
        NULL, HFILL }},
    { &hf_ranap_GANSS_PositioningDataSet_PDU,
      { "GANSS-PositioningDataSet", "ranap.GANSS_PositioningDataSet",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_GERAN_BSC_Container_PDU,
      { "GERAN-BSC-Container", "ranap.GERAN_BSC_Container",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_GERAN_Classmark_PDU,
      { "GERAN-Classmark", "ranap.GERAN_Classmark",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_GlobalCN_ID_PDU,
      { "GlobalCN-ID", "ranap.GlobalCN_ID",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_GlobalRNC_ID_PDU,
      { "GlobalRNC-ID", "ranap.GlobalRNC_ID",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_HS_DSCH_MAC_d_Flow_ID_PDU,
      { "HS-DSCH-MAC-d-Flow-ID", "ranap.HS_DSCH_MAC_d_Flow_ID",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_IncludeVelocity_PDU,
      { "IncludeVelocity", "ranap.IncludeVelocity",
        FT_UINT32, BASE_DEC, VALS(ranap_IncludeVelocity_vals), 0,
        NULL, HFILL }},
    { &hf_ranap_InformationExchangeID_PDU,
      { "InformationExchangeID", "ranap.InformationExchangeID",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_InformationExchangeType_PDU,
      { "InformationExchangeType", "ranap.InformationExchangeType",
        FT_UINT32, BASE_DEC, VALS(ranap_InformationExchangeType_vals), 0,
        NULL, HFILL }},
    { &hf_ranap_InformationRequested_PDU,
      { "InformationRequested", "ranap.InformationRequested",
        FT_UINT32, BASE_DEC, VALS(ranap_InformationRequested_vals), 0,
        NULL, HFILL }},
    { &hf_ranap_InformationRequestType_PDU,
      { "InformationRequestType", "ranap.InformationRequestType",
        FT_UINT32, BASE_DEC, VALS(ranap_InformationRequestType_vals), 0,
        NULL, HFILL }},
    { &hf_ranap_InformationTransferID_PDU,
      { "InformationTransferID", "ranap.InformationTransferID",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_InformationTransferType_PDU,
      { "InformationTransferType", "ranap.InformationTransferType",
        FT_UINT32, BASE_DEC, VALS(ranap_InformationTransferType_vals), 0,
        NULL, HFILL }},
    { &hf_ranap_IntegrityProtectionInformation_PDU,
      { "IntegrityProtectionInformation", "ranap.IntegrityProtectionInformation",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_IntegrityProtectionKey_PDU,
      { "IntegrityProtectionKey", "ranap.IntegrityProtectionKey",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_InterSystemInformationTransferType_PDU,
      { "InterSystemInformationTransferType", "ranap.InterSystemInformationTransferType",
        FT_UINT32, BASE_DEC, VALS(ranap_InterSystemInformationTransferType_vals), 0,
        NULL, HFILL }},
    { &hf_ranap_InterSystemInformation_TransparentContainer_PDU,
      { "InterSystemInformation-TransparentContainer", "ranap.InterSystemInformation_TransparentContainer",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_IPMulticastAddress_PDU,
      { "IPMulticastAddress", "ranap.IPMulticastAddress",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_IuSignallingConnectionIdentifier_PDU,
      { "IuSignallingConnectionIdentifier", "ranap.IuSignallingConnectionIdentifier",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_IuTransportAssociation_PDU,
      { "IuTransportAssociation", "ranap.IuTransportAssociation",
        FT_UINT32, BASE_DEC, VALS(ranap_IuTransportAssociation_vals), 0,
        NULL, HFILL }},
    { &hf_ranap_KeyStatus_PDU,
      { "KeyStatus", "ranap.KeyStatus",
        FT_UINT32, BASE_DEC, VALS(ranap_KeyStatus_vals), 0,
        NULL, HFILL }},
    { &hf_ranap_LAI_PDU,
      { "LAI", "ranap.LAI",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_LastKnownServiceArea_PDU,
      { "LastKnownServiceArea", "ranap.LastKnownServiceArea",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_LocationRelatedDataRequestType_PDU,
      { "LocationRelatedDataRequestType", "ranap.LocationRelatedDataRequestType",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_LocationRelatedDataRequestTypeSpecificToGERANIuMode_PDU,
      { "LocationRelatedDataRequestTypeSpecificToGERANIuMode", "ranap.LocationRelatedDataRequestTypeSpecificToGERANIuMode",
        FT_UINT32, BASE_DEC, VALS(ranap_LocationRelatedDataRequestTypeSpecificToGERANIuMode_vals), 0,
        NULL, HFILL }},
    { &hf_ranap_L3_Information_PDU,
      { "L3-Information", "ranap.L3_Information",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_Management_Based_MDT_Allowed_PDU,
      { "Management-Based-MDT-Allowed", "ranap.Management_Based_MDT_Allowed",
        FT_UINT32, BASE_DEC, VALS(ranap_Management_Based_MDT_Allowed_vals), 0,
        NULL, HFILL }},
    { &hf_ranap_MBMSBearerServiceType_PDU,
      { "MBMSBearerServiceType", "ranap.MBMSBearerServiceType",
        FT_UINT32, BASE_DEC, VALS(ranap_MBMSBearerServiceType_vals), 0,
        NULL, HFILL }},
    { &hf_ranap_MBMSCNDe_Registration_PDU,
      { "MBMSCNDe-Registration", "ranap.MBMSCNDe_Registration",
        FT_UINT32, BASE_DEC, VALS(ranap_MBMSCNDe_Registration_vals), 0,
        NULL, HFILL }},
    { &hf_ranap_MBMSCountingInformation_PDU,
      { "MBMSCountingInformation", "ranap.MBMSCountingInformation",
        FT_UINT32, BASE_DEC, VALS(ranap_MBMSCountingInformation_vals), 0,
        NULL, HFILL }},
    { &hf_ranap_MBMSLinkingInformation_PDU,
      { "MBMSLinkingInformation", "ranap.MBMSLinkingInformation",
        FT_UINT32, BASE_DEC, VALS(ranap_MBMSLinkingInformation_vals), 0,
        NULL, HFILL }},
    { &hf_ranap_MBMSRegistrationRequestType_PDU,
      { "MBMSRegistrationRequestType", "ranap.MBMSRegistrationRequestType",
        FT_UINT32, BASE_DEC, VALS(ranap_MBMSRegistrationRequestType_vals), 0,
        NULL, HFILL }},
    { &hf_ranap_MBMSServiceArea_PDU,
      { "MBMSServiceArea", "ranap.MBMSServiceArea",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_MBMSSessionDuration_PDU,
      { "MBMSSessionDuration", "ranap.MBMSSessionDuration",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_MBMSSessionIdentity_PDU,
      { "MBMSSessionIdentity", "ranap.MBMSSessionIdentity",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_MBMSSessionRepetitionNumber_PDU,
      { "MBMSSessionRepetitionNumber", "ranap.MBMSSessionRepetitionNumber",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_MDT_Configuration_PDU,
      { "MDT-Configuration", "ranap.MDT_Configuration",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_MSISDN_PDU,
      { "MSISDN", "ranap.MSISDN",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_NAS_PDU_PDU,
      { "NAS-PDU", "ranap.NAS_PDU",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_NAS_SequenceNumber_PDU,
      { "NAS-SequenceNumber", "ranap.NAS_SequenceNumber",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_NewBSS_To_OldBSS_Information_PDU,
      { "NewBSS-To-OldBSS-Information", "ranap.NewBSS_To_OldBSS_Information",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_NonSearchingIndication_PDU,
      { "NonSearchingIndication", "ranap.NonSearchingIndication",
        FT_UINT32, BASE_DEC, VALS(ranap_NonSearchingIndication_vals), 0,
        NULL, HFILL }},
    { &hf_ranap_NumberOfSteps_PDU,
      { "NumberOfSteps", "ranap.NumberOfSteps",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_Offload_RAB_Parameters_PDU,
      { "Offload-RAB-Parameters", "ranap.Offload_RAB_Parameters",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_OldBSS_ToNewBSS_Information_PDU,
      { "OldBSS-ToNewBSS-Information", "ranap.OldBSS_ToNewBSS_Information",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_OMC_ID_PDU,
      { "OMC-ID", "ranap.OMC_ID",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_PagingAreaID_PDU,
      { "PagingAreaID", "ranap.PagingAreaID",
        FT_UINT32, BASE_DEC, VALS(ranap_PagingAreaID_vals), 0,
        NULL, HFILL }},
    { &hf_ranap_PagingCause_PDU,
      { "PagingCause", "ranap.PagingCause",
        FT_UINT32, BASE_DEC, VALS(ranap_PagingCause_vals), 0,
        NULL, HFILL }},
    { &hf_ranap_PDP_TypeInformation_PDU,
      { "PDP-TypeInformation", "ranap.PDP_TypeInformation",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_PDP_TypeInformation_extension_PDU,
      { "PDP-TypeInformation-extension", "ranap.PDP_TypeInformation_extension",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_PeriodicLocationInfo_PDU,
      { "PeriodicLocationInfo", "ranap.PeriodicLocationInfo",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_PermanentNAS_UE_ID_PDU,
      { "PermanentNAS-UE-ID", "ranap.PermanentNAS_UE_ID",
        FT_UINT32, BASE_DEC, VALS(ranap_PermanentNAS_UE_ID_vals), 0,
        NULL, HFILL }},
    { &hf_ranap_PLMNidentity_PDU,
      { "PLMNidentity", "ranap.PLMNidentity",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_PositioningPriority_PDU,
      { "PositioningPriority", "ranap.PositioningPriority",
        FT_UINT32, BASE_DEC, VALS(ranap_PositioningPriority_vals), 0,
        NULL, HFILL }},
    { &hf_ranap_PositionData_PDU,
      { "PositionData", "ranap.PositionData",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_PositionDataSpecificToGERANIuMode_PDU,
      { "PositionDataSpecificToGERANIuMode", "ranap.PositionDataSpecificToGERANIuMode",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_Priority_Class_Indicator_PDU,
      { "Priority-Class-Indicator", "ranap.Priority_Class_Indicator",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_ProvidedData_PDU,
      { "ProvidedData", "ranap.ProvidedData",
        FT_UINT32, BASE_DEC, VALS(ranap_ProvidedData_vals), 0,
        NULL, HFILL }},
    { &hf_ranap_RAB_ID_PDU,
      { "RAB-ID", "ranap.RAB_ID",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_RAB_Parameter_ExtendedGuaranteedBitrateList_PDU,
      { "RAB-Parameter-ExtendedGuaranteedBitrateList", "ranap.RAB_Parameter_ExtendedGuaranteedBitrateList",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_RAB_Parameter_ExtendedMaxBitrateList_PDU,
      { "RAB-Parameter-ExtendedMaxBitrateList", "ranap.RAB_Parameter_ExtendedMaxBitrateList",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_RAB_Parameters_PDU,
      { "RAB-Parameters", "ranap.RAB_Parameters",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_RABParametersList_PDU,
      { "RABParametersList", "ranap.RABParametersList",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_RAC_PDU,
      { "RAC", "ranap.RAC",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_RAListofIdleModeUEs_PDU,
      { "RAListofIdleModeUEs", "ranap.RAListofIdleModeUEs",
        FT_UINT32, BASE_DEC, VALS(ranap_RAListofIdleModeUEs_vals), 0,
        NULL, HFILL }},
    { &hf_ranap_LAListofIdleModeUEs_PDU,
      { "LAListofIdleModeUEs", "ranap.LAListofIdleModeUEs",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_RAT_Type_PDU,
      { "RAT-Type", "ranap.RAT_Type",
        FT_UINT32, BASE_DEC, VALS(ranap_RAT_Type_vals), 0,
        NULL, HFILL }},
    { &hf_ranap_RedirectAttemptFlag_PDU,
      { "RedirectAttemptFlag", "ranap.RedirectAttemptFlag",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_RedirectionCompleted_PDU,
      { "RedirectionCompleted", "ranap.RedirectionCompleted",
        FT_UINT32, BASE_DEC, VALS(ranap_RedirectionCompleted_vals), 0,
        NULL, HFILL }},
    { &hf_ranap_RejectCauseValue_PDU,
      { "RejectCauseValue", "ranap.RejectCauseValue",
        FT_UINT32, BASE_DEC, VALS(ranap_RejectCauseValue_vals), 0,
        NULL, HFILL }},
    { &hf_ranap_RelocationType_PDU,
      { "RelocationType", "ranap.RelocationType",
        FT_UINT32, BASE_DEC, VALS(ranap_RelocationType_vals), 0,
        NULL, HFILL }},
    { &hf_ranap_RequestedGANSSAssistanceData_PDU,
      { "RequestedGANSSAssistanceData", "ranap.RequestedGANSSAssistanceData",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_Requested_RAB_Parameter_ExtendedMaxBitrateList_PDU,
      { "Requested-RAB-Parameter-ExtendedMaxBitrateList", "ranap.Requested_RAB_Parameter_ExtendedMaxBitrateList",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_Requested_RAB_Parameter_ExtendedGuaranteedBitrateList_PDU,
      { "Requested-RAB-Parameter-ExtendedGuaranteedBitrateList", "ranap.Requested_RAB_Parameter_ExtendedGuaranteedBitrateList",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_RequestType_PDU,
      { "RequestType", "ranap.RequestType",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_ResponseTime_PDU,
      { "ResponseTime", "ranap.ResponseTime",
        FT_UINT32, BASE_DEC, VALS(ranap_ResponseTime_vals), 0,
        NULL, HFILL }},
    { &hf_ranap_RNSAPRelocationParameters_PDU,
      { "RNSAPRelocationParameters", "ranap.RNSAPRelocationParameters",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_RRC_Container_PDU,
      { "RRC-Container", "ranap.RRC_Container",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_SAI_PDU,
      { "SAI", "ranap.SAI",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_SAPI_PDU,
      { "SAPI", "ranap.SAPI",
        FT_UINT32, BASE_DEC, VALS(ranap_SAPI_vals), 0,
        NULL, HFILL }},
    { &hf_ranap_SessionUpdateID_PDU,
      { "SessionUpdateID", "ranap.SessionUpdateID",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_SignallingIndication_PDU,
      { "SignallingIndication", "ranap.SignallingIndication",
        FT_UINT32, BASE_DEC, VALS(ranap_SignallingIndication_vals), 0,
        NULL, HFILL }},
    { &hf_ranap_SNA_Access_Information_PDU,
      { "SNA-Access-Information", "ranap.SNA_Access_Information",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_Source_ToTarget_TransparentContainer_PDU,
      { "Source-ToTarget-TransparentContainer", "ranap.Source_ToTarget_TransparentContainer",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_ranap_SourceCellID_PDU,
      { "SourceCellID", "ranap.SourceCellID",
        FT_UINT32, BASE_DEC, VALS(ranap_SourceCellID_vals), 0,
        NULL, HFILL }},
    { &hf_ranap_SourceBSS_ToTargetBSS_TransparentContainer_PDU,
      { "SourceBSS-ToTargetBSS-TransparentContainer", "ranap.SourceBSS_ToTargetBSS_TransparentContainer",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_SourceID_PDU,
      { "SourceID", "ranap.SourceID",
        FT_UINT32, BASE_DEC, VALS(ranap_SourceID_vals), 0,
        NULL, HFILL }},
    { &hf_ranap_ranap_SourceRNC_ToTargetRNC_TransparentContainer_PDU,
      { "SourceRNC-ToTargetRNC-TransparentContainer", "ranap.SourceRNC_ToTargetRNC_TransparentContainer",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_IRAT_Measurement_Configuration_PDU,
      { "IRAT-Measurement-Configuration", "ranap.IRAT_Measurement_Configuration",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_SubscriberProfileIDforRFP_PDU,
      { "SubscriberProfileIDforRFP", "ranap.SubscriberProfileIDforRFP",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_SupportedRAB_ParameterBitrateList_PDU,
      { "SupportedRAB-ParameterBitrateList", "ranap.SupportedRAB_ParameterBitrateList",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_SRB_TrCH_Mapping_PDU,
      { "SRB-TrCH-Mapping", "ranap.SRB_TrCH_Mapping",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_SRVCC_HO_Indication_PDU,
      { "SRVCC-HO-Indication", "ranap.SRVCC_HO_Indication",
        FT_UINT32, BASE_DEC, VALS(ranap_SRVCC_HO_Indication_vals), 0,
        NULL, HFILL }},
    { &hf_ranap_SRVCC_Information_PDU,
      { "SRVCC-Information", "ranap.SRVCC_Information",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_SRVCC_Operation_Possible_PDU,
      { "SRVCC-Operation-Possible", "ranap.SRVCC_Operation_Possible",
        FT_UINT32, BASE_DEC, VALS(ranap_SRVCC_Operation_Possible_vals), 0,
        NULL, HFILL }},
    { &hf_ranap_Target_ToSource_TransparentContainer_PDU,
      { "Target-ToSource-TransparentContainer", "ranap.Target_ToSource_TransparentContainer",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_TargetBSS_ToSourceBSS_TransparentContainer_PDU,
      { "TargetBSS-ToSourceBSS-TransparentContainer", "ranap.TargetBSS_ToSourceBSS_TransparentContainer",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_TargetID_PDU,
      { "TargetID", "ranap.TargetID",
        FT_UINT32, BASE_DEC, VALS(ranap_TargetID_vals), 0,
        NULL, HFILL }},
    { &hf_ranap_ranap_TargetRNC_ID_PDU,
      { "TargetRNC-ID", "ranap.TargetRNC_ID",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_TargetRNC_ToSourceRNC_TransparentContainer_PDU,
      { "TargetRNC-ToSourceRNC-TransparentContainer", "ranap.TargetRNC_ToSourceRNC_TransparentContainer",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_TemporaryUE_ID_PDU,
      { "TemporaryUE-ID", "ranap.TemporaryUE_ID",
        FT_UINT32, BASE_DEC, VALS(ranap_TemporaryUE_ID_vals), 0,
        NULL, HFILL }},
    { &hf_ranap_TimeToMBMSDataTransfer_PDU,
      { "TimeToMBMSDataTransfer", "ranap.TimeToMBMSDataTransfer",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_TMGI_PDU,
      { "TMGI", "ranap.TMGI",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_TracePropagationParameters_PDU,
      { "TracePropagationParameters", "ranap.TracePropagationParameters",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_TraceRecordingSessionInformation_PDU,
      { "TraceRecordingSessionInformation", "ranap.TraceRecordingSessionInformation",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_TraceReference_PDU,
      { "TraceReference", "ranap.TraceReference",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_TraceType_PDU,
      { "TraceType", "ranap.TraceType",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_TransportLayerAddress_PDU,
      { "TransportLayerAddress", "ranap.TransportLayerAddress",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_TriggerID_PDU,
      { "TriggerID", "ranap.TriggerID",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_TypeOfError_PDU,
      { "TypeOfError", "ranap.TypeOfError",
        FT_UINT32, BASE_DEC, VALS(ranap_TypeOfError_vals), 0,
        NULL, HFILL }},
    { &hf_ranap_UE_AggregateMaximumBitRate_PDU,
      { "UE-AggregateMaximumBitRate", "ranap.UE_AggregateMaximumBitRate",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_UE_History_Information_PDU,
      { "UE-History-Information", "ranap.UE_History_Information",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_UE_ID_PDU,
      { "UE-ID", "ranap.UE_ID",
        FT_UINT32, BASE_DEC, VALS(ranap_UE_ID_vals), 0,
        NULL, HFILL }},
    { &hf_ranap_UESBI_Iu_PDU,
      { "UESBI-Iu", "ranap.UESBI_Iu",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_VelocityEstimate_PDU,
      { "VelocityEstimate", "ranap.VelocityEstimate",
        FT_UINT32, BASE_DEC, VALS(ranap_VelocityEstimate_vals), 0,
        NULL, HFILL }},
    { &hf_ranap_VerticalAccuracyCode_PDU,
      { "VerticalAccuracyCode", "ranap.VerticalAccuracyCode",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_Iu_ReleaseCommand_PDU,
      { "Iu-ReleaseCommand", "ranap.Iu_ReleaseCommand",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_Iu_ReleaseComplete_PDU,
      { "Iu-ReleaseComplete", "ranap.Iu_ReleaseComplete",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_RAB_DataVolumeReportList_PDU,
      { "RAB-DataVolumeReportList", "ranap.RAB_DataVolumeReportList",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_RAB_DataVolumeReportItem_PDU,
      { "RAB-DataVolumeReportItem", "ranap.RAB_DataVolumeReportItem",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_RAB_ReleasedList_IuRelComp_PDU,
      { "RAB-ReleasedList-IuRelComp", "ranap.RAB_ReleasedList_IuRelComp",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_RAB_ReleasedItem_IuRelComp_PDU,
      { "RAB-ReleasedItem-IuRelComp", "ranap.RAB_ReleasedItem_IuRelComp",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_RelocationRequired_PDU,
      { "RelocationRequired", "ranap.RelocationRequired",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_RelocationCommand_PDU,
      { "RelocationCommand", "ranap.RelocationCommand",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_RAB_RelocationReleaseList_PDU,
      { "RAB-RelocationReleaseList", "ranap.RAB_RelocationReleaseList",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_RAB_RelocationReleaseItem_PDU,
      { "RAB-RelocationReleaseItem", "ranap.RAB_RelocationReleaseItem",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_RAB_DataForwardingList_PDU,
      { "RAB-DataForwardingList", "ranap.RAB_DataForwardingList",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_RAB_DataForwardingItem_PDU,
      { "RAB-DataForwardingItem", "ranap.RAB_DataForwardingItem",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_RelocationPreparationFailure_PDU,
      { "RelocationPreparationFailure", "ranap.RelocationPreparationFailure",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_RelocationRequest_PDU,
      { "RelocationRequest", "ranap.RelocationRequest",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_RAB_SetupList_RelocReq_PDU,
      { "RAB-SetupList-RelocReq", "ranap.RAB_SetupList_RelocReq",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_RAB_SetupItem_RelocReq_PDU,
      { "RAB-SetupItem-RelocReq", "ranap.RAB_SetupItem_RelocReq",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_CNMBMSLinkingInformation_PDU,
      { "CNMBMSLinkingInformation", "ranap.CNMBMSLinkingInformation",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_JoinedMBMSBearerService_IEs_PDU,
      { "JoinedMBMSBearerService-IEs", "ranap.JoinedMBMSBearerService_IEs",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_RelocationRequestAcknowledge_PDU,
      { "RelocationRequestAcknowledge", "ranap.RelocationRequestAcknowledge",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_RAB_SetupList_RelocReqAck_PDU,
      { "RAB-SetupList-RelocReqAck", "ranap.RAB_SetupList_RelocReqAck",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_RAB_SetupItem_RelocReqAck_PDU,
      { "RAB-SetupItem-RelocReqAck", "ranap.RAB_SetupItem_RelocReqAck",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_RAB_FailedList_PDU,
      { "RAB-FailedList", "ranap.RAB_FailedList",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_RAB_FailedItem_PDU,
      { "RAB-FailedItem", "ranap.RAB_FailedItem",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_RelocationFailure_PDU,
      { "RelocationFailure", "ranap.RelocationFailure",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_RelocationCancel_PDU,
      { "RelocationCancel", "ranap.RelocationCancel",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_RelocationCancelAcknowledge_PDU,
      { "RelocationCancelAcknowledge", "ranap.RelocationCancelAcknowledge",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_SRNS_ContextRequest_PDU,
      { "SRNS-ContextRequest", "ranap.SRNS_ContextRequest",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_RAB_DataForwardingList_SRNS_CtxReq_PDU,
      { "RAB-DataForwardingList-SRNS-CtxReq", "ranap.RAB_DataForwardingList_SRNS_CtxReq",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_RAB_DataForwardingItem_SRNS_CtxReq_PDU,
      { "RAB-DataForwardingItem-SRNS-CtxReq", "ranap.RAB_DataForwardingItem_SRNS_CtxReq",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_SRNS_ContextResponse_PDU,
      { "SRNS-ContextResponse", "ranap.SRNS_ContextResponse",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_RAB_ContextList_PDU,
      { "RAB-ContextList", "ranap.RAB_ContextList",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_RAB_ContextItem_PDU,
      { "RAB-ContextItem", "ranap.RAB_ContextItem",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_RAB_ContextFailedtoTransferList_PDU,
      { "RAB-ContextFailedtoTransferList", "ranap.RAB_ContextFailedtoTransferList",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_RABs_ContextFailedtoTransferItem_PDU,
      { "RABs-ContextFailedtoTransferItem", "ranap.RABs_ContextFailedtoTransferItem",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_SecurityModeCommand_PDU,
      { "SecurityModeCommand", "ranap.SecurityModeCommand",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_SecurityModeComplete_PDU,
      { "SecurityModeComplete", "ranap.SecurityModeComplete",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_SecurityModeReject_PDU,
      { "SecurityModeReject", "ranap.SecurityModeReject",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_DataVolumeReportRequest_PDU,
      { "DataVolumeReportRequest", "ranap.DataVolumeReportRequest",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_RAB_DataVolumeReportRequestList_PDU,
      { "RAB-DataVolumeReportRequestList", "ranap.RAB_DataVolumeReportRequestList",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_RAB_DataVolumeReportRequestItem_PDU,
      { "RAB-DataVolumeReportRequestItem", "ranap.RAB_DataVolumeReportRequestItem",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_DataVolumeReport_PDU,
      { "DataVolumeReport", "ranap.DataVolumeReport",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_RAB_FailedtoReportList_PDU,
      { "RAB-FailedtoReportList", "ranap.RAB_FailedtoReportList",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_RABs_failed_to_reportItem_PDU,
      { "RABs-failed-to-reportItem", "ranap.RABs_failed_to_reportItem",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_Reset_PDU,
      { "Reset", "ranap.Reset",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_ResetAcknowledge_PDU,
      { "ResetAcknowledge", "ranap.ResetAcknowledge",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_ResetResource_PDU,
      { "ResetResource", "ranap.ResetResource",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_ResetResourceList_PDU,
      { "ResetResourceList", "ranap.ResetResourceList",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_ResetResourceItem_PDU,
      { "ResetResourceItem", "ranap.ResetResourceItem",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_ResetResourceAcknowledge_PDU,
      { "ResetResourceAcknowledge", "ranap.ResetResourceAcknowledge",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_ResetResourceAckList_PDU,
      { "ResetResourceAckList", "ranap.ResetResourceAckList",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_ResetResourceAckItem_PDU,
      { "ResetResourceAckItem", "ranap.ResetResourceAckItem",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_RAB_ReleaseRequest_PDU,
      { "RAB-ReleaseRequest", "ranap.RAB_ReleaseRequest",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_RAB_ReleaseList_PDU,
      { "RAB-ReleaseList", "ranap.RAB_ReleaseList",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_RAB_ReleaseItem_PDU,
      { "RAB-ReleaseItem", "ranap.RAB_ReleaseItem",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_Iu_ReleaseRequest_PDU,
      { "Iu-ReleaseRequest", "ranap.Iu_ReleaseRequest",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_RelocationDetect_PDU,
      { "RelocationDetect", "ranap.RelocationDetect",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_RelocationComplete_PDU,
      { "RelocationComplete", "ranap.RelocationComplete",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_EnhancedRelocationCompleteRequest_PDU,
      { "EnhancedRelocationCompleteRequest", "ranap.EnhancedRelocationCompleteRequest",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_RAB_SetupList_EnhancedRelocCompleteReq_PDU,
      { "RAB-SetupList-EnhancedRelocCompleteReq", "ranap.RAB_SetupList_EnhancedRelocCompleteReq",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_RAB_SetupItem_EnhancedRelocCompleteReq_PDU,
      { "RAB-SetupItem-EnhancedRelocCompleteReq", "ranap.RAB_SetupItem_EnhancedRelocCompleteReq",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_EnhancedRelocationCompleteResponse_PDU,
      { "EnhancedRelocationCompleteResponse", "ranap.EnhancedRelocationCompleteResponse",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_RAB_SetupList_EnhancedRelocCompleteRes_PDU,
      { "RAB-SetupList-EnhancedRelocCompleteRes", "ranap.RAB_SetupList_EnhancedRelocCompleteRes",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_RAB_SetupItem_EnhancedRelocCompleteRes_PDU,
      { "RAB-SetupItem-EnhancedRelocCompleteRes", "ranap.RAB_SetupItem_EnhancedRelocCompleteRes",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_RAB_ToBeReleasedList_EnhancedRelocCompleteRes_PDU,
      { "RAB-ToBeReleasedList-EnhancedRelocCompleteRes", "ranap.RAB_ToBeReleasedList_EnhancedRelocCompleteRes",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_RAB_ToBeReleasedItem_EnhancedRelocCompleteRes_PDU,
      { "RAB-ToBeReleasedItem-EnhancedRelocCompleteRes", "ranap.RAB_ToBeReleasedItem_EnhancedRelocCompleteRes",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_EnhancedRelocationCompleteFailure_PDU,
      { "EnhancedRelocationCompleteFailure", "ranap.EnhancedRelocationCompleteFailure",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_EnhancedRelocationCompleteConfirm_PDU,
      { "EnhancedRelocationCompleteConfirm", "ranap.EnhancedRelocationCompleteConfirm",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_Paging_PDU,
      { "Paging", "ranap.Paging",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_CommonID_PDU,
      { "CommonID", "ranap.CommonID",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_CN_InvokeTrace_PDU,
      { "CN-InvokeTrace", "ranap.CN_InvokeTrace",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_CN_DeactivateTrace_PDU,
      { "CN-DeactivateTrace", "ranap.CN_DeactivateTrace",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_LocationReportingControl_PDU,
      { "LocationReportingControl", "ranap.LocationReportingControl",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_LocationReport_PDU,
      { "LocationReport", "ranap.LocationReport",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_InitialUE_Message_PDU,
      { "InitialUE-Message", "ranap.InitialUE_Message",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_DirectTransfer_PDU,
      { "DirectTransfer", "ranap.DirectTransfer",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_RedirectionIndication_PDU,
      { "RedirectionIndication", "ranap.RedirectionIndication",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_Overload_PDU,
      { "Overload", "ranap.Overload",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_ErrorIndication_PDU,
      { "ErrorIndication", "ranap.ErrorIndication",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_SRNS_DataForwardCommand_PDU,
      { "SRNS-DataForwardCommand", "ranap.SRNS_DataForwardCommand",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_ForwardSRNS_Context_PDU,
      { "ForwardSRNS-Context", "ranap.ForwardSRNS_Context",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_RAB_AssignmentRequest_PDU,
      { "RAB-AssignmentRequest", "ranap.RAB_AssignmentRequest",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_RAB_SetupOrModifyList_PDU,
      { "RAB-SetupOrModifyList", "ranap.RAB_SetupOrModifyList",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_RAB_SetupOrModifyItemFirst_PDU,
      { "RAB-SetupOrModifyItemFirst", "ranap.RAB_SetupOrModifyItemFirst",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_TransportLayerInformation_PDU,
      { "TransportLayerInformation", "ranap.TransportLayerInformation",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_RAB_SetupOrModifyItemSecond_PDU,
      { "RAB-SetupOrModifyItemSecond", "ranap.RAB_SetupOrModifyItemSecond",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_RAB_AssignmentResponse_PDU,
      { "RAB-AssignmentResponse", "ranap.RAB_AssignmentResponse",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_RAB_SetupOrModifiedList_PDU,
      { "RAB-SetupOrModifiedList", "ranap.RAB_SetupOrModifiedList",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_RAB_SetupOrModifiedItem_PDU,
      { "RAB-SetupOrModifiedItem", "ranap.RAB_SetupOrModifiedItem",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_RAB_ReleasedList_PDU,
      { "RAB-ReleasedList", "ranap.RAB_ReleasedList",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_RAB_ReleasedItem_PDU,
      { "RAB-ReleasedItem", "ranap.RAB_ReleasedItem",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_RAB_QueuedList_PDU,
      { "RAB-QueuedList", "ranap.RAB_QueuedList",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_RAB_QueuedItem_PDU,
      { "RAB-QueuedItem", "ranap.RAB_QueuedItem",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_RAB_ReleaseFailedList_PDU,
      { "RAB-ReleaseFailedList", "ranap.RAB_ReleaseFailedList",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_GERAN_Iumode_RAB_FailedList_RABAssgntResponse_PDU,
      { "GERAN-Iumode-RAB-FailedList-RABAssgntResponse", "ranap.GERAN_Iumode_RAB_FailedList_RABAssgntResponse",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_GERAN_Iumode_RAB_Failed_RABAssgntResponse_Item_PDU,
      { "GERAN-Iumode-RAB-Failed-RABAssgntResponse-Item", "ranap.GERAN_Iumode_RAB_Failed_RABAssgntResponse_Item",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_PrivateMessage_PDU,
      { "PrivateMessage", "ranap.PrivateMessage",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_RANAP_RelocationInformation_PDU,
      { "RANAP-RelocationInformation", "ranap.RANAP_RelocationInformation",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_DirectTransferInformationList_RANAP_RelocInf_PDU,
      { "DirectTransferInformationList-RANAP-RelocInf", "ranap.DirectTransferInformationList_RANAP_RelocInf",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_DirectTransferInformationItem_RANAP_RelocInf_PDU,
      { "DirectTransferInformationItem-RANAP-RelocInf", "ranap.DirectTransferInformationItem_RANAP_RelocInf",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_RAB_ContextList_RANAP_RelocInf_PDU,
      { "RAB-ContextList-RANAP-RelocInf", "ranap.RAB_ContextList_RANAP_RelocInf",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_RAB_ContextItem_RANAP_RelocInf_PDU,
      { "RAB-ContextItem-RANAP-RelocInf", "ranap.RAB_ContextItem_RANAP_RelocInf",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_RANAP_EnhancedRelocationInformationRequest_PDU,
      { "RANAP-EnhancedRelocationInformationRequest", "ranap.RANAP_EnhancedRelocationInformationRequest",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_RAB_SetupList_EnhRelocInfoReq_PDU,
      { "RAB-SetupList-EnhRelocInfoReq", "ranap.RAB_SetupList_EnhRelocInfoReq",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_RAB_SetupItem_EnhRelocInfoReq_PDU,
      { "RAB-SetupItem-EnhRelocInfoReq", "ranap.RAB_SetupItem_EnhRelocInfoReq",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_RANAP_EnhancedRelocationInformationResponse_PDU,
      { "RANAP-EnhancedRelocationInformationResponse", "ranap.RANAP_EnhancedRelocationInformationResponse",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_RAB_SetupList_EnhRelocInfoRes_PDU,
      { "RAB-SetupList-EnhRelocInfoRes", "ranap.RAB_SetupList_EnhRelocInfoRes",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_RAB_SetupItem_EnhRelocInfoRes_PDU,
      { "RAB-SetupItem-EnhRelocInfoRes", "ranap.RAB_SetupItem_EnhRelocInfoRes",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_RAB_FailedList_EnhRelocInfoRes_PDU,
      { "RAB-FailedList-EnhRelocInfoRes", "ranap.RAB_FailedList_EnhRelocInfoRes",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_RAB_FailedItem_EnhRelocInfoRes_PDU,
      { "RAB-FailedItem-EnhRelocInfoRes", "ranap.RAB_FailedItem_EnhRelocInfoRes",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_RAB_ModifyRequest_PDU,
      { "RAB-ModifyRequest", "ranap.RAB_ModifyRequest",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_RAB_ModifyList_PDU,
      { "RAB-ModifyList", "ranap.RAB_ModifyList",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_RAB_ModifyItem_PDU,
      { "RAB-ModifyItem", "ranap.RAB_ModifyItem",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_LocationRelatedDataRequest_PDU,
      { "LocationRelatedDataRequest", "ranap.LocationRelatedDataRequest",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_LocationRelatedDataResponse_PDU,
      { "LocationRelatedDataResponse", "ranap.LocationRelatedDataResponse",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_LocationRelatedDataFailure_PDU,
      { "LocationRelatedDataFailure", "ranap.LocationRelatedDataFailure",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_InformationTransferIndication_PDU,
      { "InformationTransferIndication", "ranap.InformationTransferIndication",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_InformationTransferConfirmation_PDU,
      { "InformationTransferConfirmation", "ranap.InformationTransferConfirmation",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_InformationTransferFailure_PDU,
      { "InformationTransferFailure", "ranap.InformationTransferFailure",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_UESpecificInformationIndication_PDU,
      { "UESpecificInformationIndication", "ranap.UESpecificInformationIndication",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_DirectInformationTransfer_PDU,
      { "DirectInformationTransfer", "ranap.DirectInformationTransfer",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_UplinkInformationExchangeRequest_PDU,
      { "UplinkInformationExchangeRequest", "ranap.UplinkInformationExchangeRequest",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_UplinkInformationExchangeResponse_PDU,
      { "UplinkInformationExchangeResponse", "ranap.UplinkInformationExchangeResponse",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_UplinkInformationExchangeFailure_PDU,
      { "UplinkInformationExchangeFailure", "ranap.UplinkInformationExchangeFailure",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_MBMSSessionStart_PDU,
      { "MBMSSessionStart", "ranap.MBMSSessionStart",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_MBMSSynchronisationInformation_PDU,
      { "MBMSSynchronisationInformation", "ranap.MBMSSynchronisationInformation",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_MBMSSessionStartResponse_PDU,
      { "MBMSSessionStartResponse", "ranap.MBMSSessionStartResponse",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_MBMSSessionStartFailure_PDU,
      { "MBMSSessionStartFailure", "ranap.MBMSSessionStartFailure",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_MBMSSessionUpdate_PDU,
      { "MBMSSessionUpdate", "ranap.MBMSSessionUpdate",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_MBMSSessionUpdateResponse_PDU,
      { "MBMSSessionUpdateResponse", "ranap.MBMSSessionUpdateResponse",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_MBMSSessionUpdateFailure_PDU,
      { "MBMSSessionUpdateFailure", "ranap.MBMSSessionUpdateFailure",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_MBMSSessionStop_PDU,
      { "MBMSSessionStop", "ranap.MBMSSessionStop",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_MBMSSessionStopResponse_PDU,
      { "MBMSSessionStopResponse", "ranap.MBMSSessionStopResponse",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_MBMSUELinkingRequest_PDU,
      { "MBMSUELinkingRequest", "ranap.MBMSUELinkingRequest",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_LeftMBMSBearerService_IEs_PDU,
      { "LeftMBMSBearerService-IEs", "ranap.LeftMBMSBearerService_IEs",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_MBMSUELinkingResponse_PDU,
      { "MBMSUELinkingResponse", "ranap.MBMSUELinkingResponse",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_UnsuccessfulLinking_IEs_PDU,
      { "UnsuccessfulLinking-IEs", "ranap.UnsuccessfulLinking_IEs",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_MBMSRegistrationRequest_PDU,
      { "MBMSRegistrationRequest", "ranap.MBMSRegistrationRequest",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_MBMSRegistrationResponse_PDU,
      { "MBMSRegistrationResponse", "ranap.MBMSRegistrationResponse",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_MBMSRegistrationFailure_PDU,
      { "MBMSRegistrationFailure", "ranap.MBMSRegistrationFailure",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_MBMSCNDe_RegistrationRequest_PDU,
      { "MBMSCNDe-RegistrationRequest", "ranap.MBMSCNDe_RegistrationRequest",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_MBMSCNDe_RegistrationResponse_PDU,
      { "MBMSCNDe-RegistrationResponse", "ranap.MBMSCNDe_RegistrationResponse",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_MBMSRABEstablishmentIndication_PDU,
      { "MBMSRABEstablishmentIndication", "ranap.MBMSRABEstablishmentIndication",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_MBMSRABReleaseRequest_PDU,
      { "MBMSRABReleaseRequest", "ranap.MBMSRABReleaseRequest",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_MBMSRABRelease_PDU,
      { "MBMSRABRelease", "ranap.MBMSRABRelease",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_MBMSRABReleaseFailure_PDU,
      { "MBMSRABReleaseFailure", "ranap.MBMSRABReleaseFailure",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_SRVCC_CSKeysRequest_PDU,
      { "SRVCC-CSKeysRequest", "ranap.SRVCC_CSKeysRequest",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_SRVCC_CSKeysResponse_PDU,
      { "SRVCC-CSKeysResponse", "ranap.SRVCC_CSKeysResponse",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_RANAP_PDU_PDU,
      { "RANAP-PDU", "ranap.RANAP_PDU",
        FT_UINT32, BASE_DEC, VALS(ranap_RANAP_PDU_vals), 0,
        NULL, HFILL }},
    { &hf_ranap_local,
      { "local", "ranap.local",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_65535", HFILL }},
    { &hf_ranap_global,
      { "global", "ranap.global",
        FT_OID, BASE_NONE, NULL, 0,
        "OBJECT_IDENTIFIER", HFILL }},
    { &hf_ranap_ProtocolIE_Container_item,
      { "ProtocolIE-Field", "ranap.ProtocolIE_Field",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_id,
      { "id", "ranap.id",
        FT_UINT32, BASE_DEC|BASE_EXT_STRING, &ranap_ProtocolIE_ID_vals_ext, 0,
        "ProtocolIE_ID", HFILL }},
    { &hf_ranap_criticality,
      { "criticality", "ranap.criticality",
        FT_UINT32, BASE_DEC, VALS(ranap_Criticality_vals), 0,
        NULL, HFILL }},
    { &hf_ranap_ie_field_value,
      { "value", "ranap.value",
        FT_NONE, BASE_NONE, NULL, 0,
        "T_ie_field_value", HFILL }},
    { &hf_ranap_ProtocolIE_ContainerPair_item,
      { "ProtocolIE-FieldPair", "ranap.ProtocolIE_FieldPair",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_firstCriticality,
      { "firstCriticality", "ranap.firstCriticality",
        FT_UINT32, BASE_DEC, VALS(ranap_Criticality_vals), 0,
        "Criticality", HFILL }},
    { &hf_ranap_firstValue,
      { "firstValue", "ranap.firstValue",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_secondCriticality,
      { "secondCriticality", "ranap.secondCriticality",
        FT_UINT32, BASE_DEC, VALS(ranap_Criticality_vals), 0,
        "Criticality", HFILL }},
    { &hf_ranap_secondValue,
      { "secondValue", "ranap.secondValue",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_ProtocolIE_ContainerList_item,
      { "ProtocolIE-Container", "ranap.ProtocolIE_Container",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_ProtocolIE_ContainerPairList_item,
      { "ProtocolIE-ContainerPair", "ranap.ProtocolIE_ContainerPair",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_ProtocolExtensionContainer_item,
      { "ProtocolExtensionField", "ranap.ProtocolExtensionField",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_ext_id,
      { "id", "ranap.id",
        FT_UINT8, BASE_DEC|BASE_EXT_STRING, &ranap_ProtocolIE_ID_vals_ext, 0,
        "ProtocolExtensionID", HFILL }},
    { &hf_ranap_extensionValue,
      { "extensionValue", "ranap.extensionValue",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_PrivateIE_Container_item,
      { "PrivateIE-Field", "ranap.PrivateIE_Field",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_private_id,
      { "id", "ranap.id",
        FT_UINT32, BASE_DEC, VALS(ranap_PrivateIE_ID_vals), 0,
        "PrivateIE_ID", HFILL }},
    { &hf_ranap_private_value,
      { "value", "ranap.value",
        FT_NONE, BASE_NONE, NULL, 0,
        "T_private_value", HFILL }},
    { &hf_ranap_priorityLevel,
      { "priorityLevel", "ranap.priorityLevel",
        FT_UINT32, BASE_DEC, VALS(ranap_PriorityLevel_vals), 0,
        NULL, HFILL }},
    { &hf_ranap_pre_emptionCapability,
      { "pre-emptionCapability", "ranap.pre_emptionCapability",
        FT_UINT32, BASE_DEC, VALS(ranap_Pre_emptionCapability_vals), 0,
        NULL, HFILL }},
    { &hf_ranap_pre_emptionVulnerability,
      { "pre-emptionVulnerability", "ranap.pre_emptionVulnerability",
        FT_UINT32, BASE_DEC, VALS(ranap_Pre_emptionVulnerability_vals), 0,
        NULL, HFILL }},
    { &hf_ranap_queuingAllowed,
      { "queuingAllowed", "ranap.queuingAllowed",
        FT_UINT32, BASE_DEC, VALS(ranap_QueuingAllowed_vals), 0,
        NULL, HFILL }},
    { &hf_ranap_iE_Extensions,
      { "iE-Extensions", "ranap.iE_Extensions",
        FT_UINT32, BASE_DEC, NULL, 0,
        "ProtocolExtensionContainer", HFILL }},
    { &hf_ranap_altMaxBitrateInf,
      { "altMaxBitrateInf", "ranap.altMaxBitrateInf",
        FT_NONE, BASE_NONE, NULL, 0,
        "Alt_RAB_Parameter_MaxBitrateInf", HFILL }},
    { &hf_ranap_altGuaranteedBitRateInf,
      { "altGuaranteedBitRateInf", "ranap.altGuaranteedBitRateInf",
        FT_NONE, BASE_NONE, NULL, 0,
        "Alt_RAB_Parameter_GuaranteedBitrateInf", HFILL }},
    { &hf_ranap_altExtendedGuaranteedBitrateType,
      { "altExtendedGuaranteedBitrateType", "ranap.altExtendedGuaranteedBitrateType",
        FT_UINT32, BASE_DEC, VALS(ranap_Alt_RAB_Parameter_GuaranteedBitrateType_vals), 0,
        "Alt_RAB_Parameter_GuaranteedBitrateType", HFILL }},
    { &hf_ranap_altExtendedGuaranteedBitrates,
      { "altExtendedGuaranteedBitrates", "ranap.altExtendedGuaranteedBitrates",
        FT_UINT32, BASE_DEC, NULL, 0,
        "Alt_RAB_Parameter_ExtendedGuaranteedBitrates", HFILL }},
    { &hf_ranap_Alt_RAB_Parameter_ExtendedGuaranteedBitrates_item,
      { "Alt-RAB-Parameter-ExtendedGuaranteedBitrateList", "ranap.Alt_RAB_Parameter_ExtendedGuaranteedBitrateList",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_Alt_RAB_Parameter_ExtendedGuaranteedBitrateList_item,
      { "ExtendedGuaranteedBitrate", "ranap.ExtendedGuaranteedBitrate",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_altGuaranteedBitrateType,
      { "altGuaranteedBitrateType", "ranap.altGuaranteedBitrateType",
        FT_UINT32, BASE_DEC, VALS(ranap_Alt_RAB_Parameter_GuaranteedBitrateType_vals), 0,
        "Alt_RAB_Parameter_GuaranteedBitrateType", HFILL }},
    { &hf_ranap_altGuaranteedBitrates,
      { "altGuaranteedBitrates", "ranap.altGuaranteedBitrates",
        FT_UINT32, BASE_DEC, NULL, 0,
        "Alt_RAB_Parameter_GuaranteedBitrates", HFILL }},
    { &hf_ranap_Alt_RAB_Parameter_GuaranteedBitrates_item,
      { "Alt-RAB-Parameter-GuaranteedBitrateList", "ranap.Alt_RAB_Parameter_GuaranteedBitrateList",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_Alt_RAB_Parameter_GuaranteedBitrateList_item,
      { "GuaranteedBitrate", "ranap.GuaranteedBitrate",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_altSupportedGuaranteedBitrateType,
      { "altSupportedGuaranteedBitrateType", "ranap.altSupportedGuaranteedBitrateType",
        FT_UINT32, BASE_DEC, VALS(ranap_Alt_RAB_Parameter_GuaranteedBitrateType_vals), 0,
        "Alt_RAB_Parameter_GuaranteedBitrateType", HFILL }},
    { &hf_ranap_altSupportedGuaranteedBitrates,
      { "altSupportedGuaranteedBitrates", "ranap.altSupportedGuaranteedBitrates",
        FT_UINT32, BASE_DEC, NULL, 0,
        "Alt_RAB_Parameter_SupportedGuaranteedBitrates", HFILL }},
    { &hf_ranap_Alt_RAB_Parameter_SupportedGuaranteedBitrates_item,
      { "SupportedRAB-ParameterBitrateList", "ranap.SupportedRAB_ParameterBitrateList",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_altExtendedMaxBitrateType,
      { "altExtendedMaxBitrateType", "ranap.altExtendedMaxBitrateType",
        FT_UINT32, BASE_DEC, VALS(ranap_Alt_RAB_Parameter_MaxBitrateType_vals), 0,
        "Alt_RAB_Parameter_MaxBitrateType", HFILL }},
    { &hf_ranap_altExtendedMaxBitrates,
      { "altExtendedMaxBitrates", "ranap.altExtendedMaxBitrates",
        FT_UINT32, BASE_DEC, NULL, 0,
        "Alt_RAB_Parameter_ExtendedMaxBitrates", HFILL }},
    { &hf_ranap_Alt_RAB_Parameter_ExtendedMaxBitrates_item,
      { "Alt-RAB-Parameter-ExtendedMaxBitrateList", "ranap.Alt_RAB_Parameter_ExtendedMaxBitrateList",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_Alt_RAB_Parameter_ExtendedMaxBitrateList_item,
      { "ExtendedMaxBitrate", "ranap.ExtendedMaxBitrate",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_altMaxBitrateType,
      { "altMaxBitrateType", "ranap.altMaxBitrateType",
        FT_UINT32, BASE_DEC, VALS(ranap_Alt_RAB_Parameter_MaxBitrateType_vals), 0,
        "Alt_RAB_Parameter_MaxBitrateType", HFILL }},
    { &hf_ranap_altMaxBitrates,
      { "altMaxBitrates", "ranap.altMaxBitrates",
        FT_UINT32, BASE_DEC, NULL, 0,
        "Alt_RAB_Parameter_MaxBitrates", HFILL }},
    { &hf_ranap_Alt_RAB_Parameter_MaxBitrates_item,
      { "Alt-RAB-Parameter-MaxBitrateList", "ranap.Alt_RAB_Parameter_MaxBitrateList",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_Alt_RAB_Parameter_MaxBitrateList_item,
      { "MaxBitrate", "ranap.MaxBitrate",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_altSupportedMaxBitrateType,
      { "altSupportedMaxBitrateType", "ranap.altSupportedMaxBitrateType",
        FT_UINT32, BASE_DEC, VALS(ranap_Alt_RAB_Parameter_MaxBitrateType_vals), 0,
        "Alt_RAB_Parameter_MaxBitrateType", HFILL }},
    { &hf_ranap_altSupportedMaxBitrates,
      { "altSupportedMaxBitrates", "ranap.altSupportedMaxBitrates",
        FT_UINT32, BASE_DEC, NULL, 0,
        "Alt_RAB_Parameter_SupportedMaxBitrates", HFILL }},
    { &hf_ranap_Alt_RAB_Parameter_SupportedMaxBitrates_item,
      { "SupportedRAB-ParameterBitrateList", "ranap.SupportedRAB_ParameterBitrateList",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_sAI,
      { "sAI", "ranap.sAI",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_geographicalArea,
      { "geographicalArea", "ranap.geographicalArea",
        FT_UINT32, BASE_DEC, VALS(ranap_GeographicalArea_vals), 0,
        NULL, HFILL }},
    { &hf_ranap_assMaxBitrateInf,
      { "assMaxBitrateInf", "ranap.assMaxBitrateInf",
        FT_UINT32, BASE_DEC, NULL, 0,
        "Ass_RAB_Parameter_MaxBitrateList", HFILL }},
    { &hf_ranap_assGuaranteedBitRateInf,
      { "assGuaranteedBitRateInf", "ranap.assGuaranteedBitRateInf",
        FT_UINT32, BASE_DEC, NULL, 0,
        "Ass_RAB_Parameter_GuaranteedBitrateList", HFILL }},
    { &hf_ranap_Ass_RAB_Parameter_ExtendedGuaranteedBitrateList_item,
      { "ExtendedGuaranteedBitrate", "ranap.ExtendedGuaranteedBitrate",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_Ass_RAB_Parameter_ExtendedMaxBitrateList_item,
      { "ExtendedMaxBitrate", "ranap.ExtendedMaxBitrate",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_Ass_RAB_Parameter_GuaranteedBitrateList_item,
      { "GuaranteedBitrate", "ranap.GuaranteedBitrate",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_Ass_RAB_Parameter_MaxBitrateList_item,
      { "MaxBitrate", "ranap.MaxBitrate",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_AuthorisedPLMNs_item,
      { "AuthorisedPLMNs item", "ranap.AuthorisedPLMNs_item",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_pLMNidentity,
      { "pLMNidentity", "ranap.pLMNidentity",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_authorisedSNAsList,
      { "authorisedSNAsList", "ranap.authorisedSNAsList",
        FT_UINT32, BASE_DEC, NULL, 0,
        "AuthorisedSNAs", HFILL }},
    { &hf_ranap_AuthorisedSNAs_item,
      { "SNAC", "ranap.SNAC",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_cipheringKeyFlag,
      { "cipheringKeyFlag", "ranap.cipheringKeyFlag",
        FT_BYTES, BASE_NONE, NULL, 0,
        "BIT_STRING_SIZE_1", HFILL }},
    { &hf_ranap_currentDecipheringKey,
      { "currentDecipheringKey", "ranap.currentDecipheringKey",
        FT_BYTES, BASE_NONE, NULL, 0,
        "BIT_STRING_SIZE_56", HFILL }},
    { &hf_ranap_nextDecipheringKey,
      { "nextDecipheringKey", "ranap.nextDecipheringKey",
        FT_BYTES, BASE_NONE, NULL, 0,
        "BIT_STRING_SIZE_56", HFILL }},
    { &hf_ranap_radioNetwork,
      { "radioNetwork", "ranap.radioNetwork",
        FT_UINT32, BASE_DEC|BASE_EXT_STRING, &ranap_CauseRadioNetwork_vals_ext, 0,
        "CauseRadioNetwork", HFILL }},
    { &hf_ranap_transmissionNetwork,
      { "transmissionNetwork", "ranap.transmissionNetwork",
        FT_UINT32, BASE_DEC, VALS(ranap_CauseTransmissionNetwork_vals), 0,
        "CauseTransmissionNetwork", HFILL }},
    { &hf_ranap_nAS,
      { "nAS", "ranap.nAS",
        FT_UINT32, BASE_DEC, VALS(ranap_CauseNAS_vals), 0,
        "CauseNAS", HFILL }},
    { &hf_ranap_protocol,
      { "protocol", "ranap.protocol",
        FT_UINT32, BASE_DEC, VALS(ranap_CauseProtocol_vals), 0,
        "CauseProtocol", HFILL }},
    { &hf_ranap_misc,
      { "misc", "ranap.misc",
        FT_UINT32, BASE_DEC, VALS(ranap_CauseMisc_vals), 0,
        "CauseMisc", HFILL }},
    { &hf_ranap_non_Standard,
      { "non-Standard", "ranap.non_Standard",
        FT_UINT32, BASE_DEC, NULL, 0,
        "CauseNon_Standard", HFILL }},
    { &hf_ranap_radioNetworkExtension,
      { "radioNetworkExtension", "ranap.radioNetworkExtension",
        FT_UINT32, BASE_DEC, VALS(ranap_CauseRadioNetworkExtension_vals), 0,
        "CauseRadioNetworkExtension", HFILL }},
    { &hf_ranap_cellIdList,
      { "cellIdList", "ranap.cellIdList",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_CellIdList_item,
      { "Cell-Id", "ranap.Cell_Id",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_cell_Capacity_Class_Value,
      { "cell-Capacity-Class-Value", "ranap.cell_Capacity_Class_Value",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_loadValue,
      { "loadValue", "ranap.loadValue",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_rTLoadValue,
      { "rTLoadValue", "ranap.rTLoadValue",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_nRTLoadInformationValue,
      { "nRTLoadInformationValue", "ranap.nRTLoadInformationValue",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_sourceCellID,
      { "sourceCellID", "ranap.sourceCellID",
        FT_UINT32, BASE_DEC, VALS(ranap_SourceCellID_vals), 0,
        NULL, HFILL }},
    { &hf_ranap_uplinkCellLoadInformation,
      { "uplinkCellLoadInformation", "ranap.uplinkCellLoadInformation",
        FT_NONE, BASE_NONE, NULL, 0,
        "CellLoadInformation", HFILL }},
    { &hf_ranap_downlinkCellLoadInformation,
      { "downlinkCellLoadInformation", "ranap.downlinkCellLoadInformation",
        FT_NONE, BASE_NONE, NULL, 0,
        "CellLoadInformation", HFILL }},
    { &hf_ranap_procedureCode,
      { "procedureCode", "ranap.procedureCode",
        FT_UINT32, BASE_DEC|BASE_EXT_STRING, &ranap_ProcedureCode_vals_ext, 0,
        NULL, HFILL }},
    { &hf_ranap_triggeringMessage,
      { "triggeringMessage", "ranap.triggeringMessage",
        FT_UINT32, BASE_DEC, VALS(ranap_TriggeringMessage_vals), 0,
        NULL, HFILL }},
    { &hf_ranap_procedureCriticality,
      { "procedureCriticality", "ranap.procedureCriticality",
        FT_UINT32, BASE_DEC, VALS(ranap_Criticality_vals), 0,
        "Criticality", HFILL }},
    { &hf_ranap_iEsCriticalityDiagnostics,
      { "iEsCriticalityDiagnostics", "ranap.iEsCriticalityDiagnostics",
        FT_UINT32, BASE_DEC, NULL, 0,
        "CriticalityDiagnostics_IE_List", HFILL }},
    { &hf_ranap_CriticalityDiagnostics_IE_List_item,
      { "CriticalityDiagnostics-IE-List item", "ranap.CriticalityDiagnostics_IE_List_item",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_iECriticality,
      { "iECriticality", "ranap.iECriticality",
        FT_UINT32, BASE_DEC, VALS(ranap_Criticality_vals), 0,
        "Criticality", HFILL }},
    { &hf_ranap_iE_ID,
      { "iE-ID", "ranap.iE_ID",
        FT_UINT32, BASE_DEC|BASE_EXT_STRING, &ranap_ProtocolIE_ID_vals_ext, 0,
        "ProtocolIE_ID", HFILL }},
    { &hf_ranap_repetitionNumber,
      { "repetitionNumber", "ranap.repetitionNumber",
        FT_UINT32, BASE_DEC, NULL, 0,
        "RepetitionNumber0", HFILL }},
    { &hf_ranap_MessageStructure_item,
      { "MessageStructure item", "ranap.MessageStructure_item",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_item_repetitionNumber,
      { "repetitionNumber", "ranap.repetitionNumber",
        FT_UINT32, BASE_DEC, NULL, 0,
        "RepetitionNumber1", HFILL }},
    { &hf_ranap_lAC,
      { "lAC", "ranap.lAC",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_cI,
      { "cI", "ranap.cI",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_CSG_Id_List_item,
      { "CSG-Id", "ranap.CSG_Id",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_newRAListofIdleModeUEs,
      { "newRAListofIdleModeUEs", "ranap.newRAListofIdleModeUEs",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_rAListwithNoIdleModeUEsAnyMore,
      { "rAListwithNoIdleModeUEsAnyMore", "ranap.rAListwithNoIdleModeUEsAnyMore",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_NewRAListofIdleModeUEs_item,
      { "RAC", "ranap.RAC",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_RAListwithNoIdleModeUEsAnyMore_item,
      { "RAC", "ranap.RAC",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_macroENB_ID,
      { "macroENB-ID", "ranap.macroENB_ID",
        FT_BYTES, BASE_NONE, NULL, 0,
        "BIT_STRING_SIZE_20", HFILL }},
    { &hf_ranap_homeENB_ID,
      { "homeENB-ID", "ranap.homeENB_ID",
        FT_BYTES, BASE_NONE, NULL, 0,
        "BIT_STRING_SIZE_28", HFILL }},
    { &hf_ranap_permittedAlgorithms,
      { "permittedAlgorithms", "ranap.permittedAlgorithms",
        FT_UINT32, BASE_DEC, NULL, 0,
        "PermittedEncryptionAlgorithms", HFILL }},
    { &hf_ranap_key,
      { "key", "ranap.key",
        FT_BYTES, BASE_NONE, NULL, 0,
        "EncryptionKey", HFILL }},
    { &hf_ranap_iMEIlist,
      { "iMEIlist", "ranap.iMEIlist",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_iMEISVlist,
      { "iMEISVlist", "ranap.iMEISVlist",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_iMEIgroup,
      { "iMEIgroup", "ranap.iMEIgroup",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_iMEISVgroup,
      { "iMEISVgroup", "ranap.iMEISVgroup",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_measurementQuantity,
      { "measurementQuantity", "ranap.measurementQuantity",
        FT_UINT32, BASE_DEC, VALS(ranap_MeasurementQuantity_vals), 0,
        NULL, HFILL }},
    { &hf_ranap_threshold,
      { "threshold", "ranap.threshold",
        FT_INT32, BASE_DEC, NULL, 0,
        "INTEGER_M120_165", HFILL }},
    { &hf_ranap_threshold_01,
      { "threshold", "ranap.threshold",
        FT_INT32, BASE_DEC, NULL, 0,
        "INTEGER_M120_M25", HFILL }},
    { &hf_ranap_GANSS_PositioningDataSet_item,
      { "GANSS-PositioningMethodAndUsage", "ranap.GANSS_PositioningMethodAndUsage",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_point,
      { "point", "ranap.point",
        FT_NONE, BASE_NONE, NULL, 0,
        "GA_Point", HFILL }},
    { &hf_ranap_pointWithUnCertainty,
      { "pointWithUnCertainty", "ranap.pointWithUnCertainty",
        FT_NONE, BASE_NONE, NULL, 0,
        "GA_PointWithUnCertainty", HFILL }},
    { &hf_ranap_polygon,
      { "polygon", "ranap.polygon",
        FT_UINT32, BASE_DEC, NULL, 0,
        "GA_Polygon", HFILL }},
    { &hf_ranap_pointWithUncertaintyEllipse,
      { "pointWithUncertaintyEllipse", "ranap.pointWithUncertaintyEllipse",
        FT_NONE, BASE_NONE, NULL, 0,
        "GA_PointWithUnCertaintyEllipse", HFILL }},
    { &hf_ranap_pointWithAltitude,
      { "pointWithAltitude", "ranap.pointWithAltitude",
        FT_NONE, BASE_NONE, NULL, 0,
        "GA_PointWithAltitude", HFILL }},
    { &hf_ranap_pointWithAltitudeAndUncertaintyEllipsoid,
      { "pointWithAltitudeAndUncertaintyEllipsoid", "ranap.pointWithAltitudeAndUncertaintyEllipsoid",
        FT_NONE, BASE_NONE, NULL, 0,
        "GA_PointWithAltitudeAndUncertaintyEllipsoid", HFILL }},
    { &hf_ranap_ellipsoidArc,
      { "ellipsoidArc", "ranap.ellipsoidArc",
        FT_NONE, BASE_NONE, NULL, 0,
        "GA_EllipsoidArc", HFILL }},
    { &hf_ranap_latitudeSign,
      { "latitudeSign", "ranap.latitudeSign",
        FT_UINT32, BASE_DEC, VALS(ranap_T_latitudeSign_vals), 0,
        NULL, HFILL }},
    { &hf_ranap_latitude,
      { "latitude", "ranap.latitude",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_8388607", HFILL }},
    { &hf_ranap_longitude,
      { "longitude", "ranap.longitude",
        FT_INT32, BASE_DEC, NULL, 0,
        "INTEGER_M8388608_8388607", HFILL }},
    { &hf_ranap_directionOfAltitude,
      { "directionOfAltitude", "ranap.directionOfAltitude",
        FT_UINT32, BASE_DEC, VALS(ranap_T_directionOfAltitude_vals), 0,
        NULL, HFILL }},
    { &hf_ranap_altitude,
      { "altitude", "ranap.altitude",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_32767", HFILL }},
    { &hf_ranap_geographicalCoordinates,
      { "geographicalCoordinates", "ranap.geographicalCoordinates",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_innerRadius,
      { "innerRadius", "ranap.innerRadius",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_65535", HFILL }},
    { &hf_ranap_uncertaintyRadius,
      { "uncertaintyRadius", "ranap.uncertaintyRadius",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_127", HFILL }},
    { &hf_ranap_offsetAngle,
      { "offsetAngle", "ranap.offsetAngle",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_179", HFILL }},
    { &hf_ranap_includedAngle,
      { "includedAngle", "ranap.includedAngle",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_179", HFILL }},
    { &hf_ranap_confidence,
      { "confidence", "ranap.confidence",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_127", HFILL }},
    { &hf_ranap_altitudeAndDirection,
      { "altitudeAndDirection", "ranap.altitudeAndDirection",
        FT_NONE, BASE_NONE, NULL, 0,
        "GA_AltitudeAndDirection", HFILL }},
    { &hf_ranap_uncertaintyEllipse,
      { "uncertaintyEllipse", "ranap.uncertaintyEllipse",
        FT_NONE, BASE_NONE, NULL, 0,
        "GA_UncertaintyEllipse", HFILL }},
    { &hf_ranap_uncertaintyAltitude,
      { "uncertaintyAltitude", "ranap.uncertaintyAltitude",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_127", HFILL }},
    { &hf_ranap_uncertaintyCode,
      { "uncertaintyCode", "ranap.uncertaintyCode",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_127", HFILL }},
    { &hf_ranap_GA_Polygon_item,
      { "GA-Polygon item", "ranap.GA_Polygon_item",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_uncertaintySemi_major,
      { "uncertaintySemi-major", "ranap.uncertaintySemi_major",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_127", HFILL }},
    { &hf_ranap_uncertaintySemi_minor,
      { "uncertaintySemi-minor", "ranap.uncertaintySemi_minor",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_127", HFILL }},
    { &hf_ranap_orientationOfMajorAxis,
      { "orientationOfMajorAxis", "ranap.orientationOfMajorAxis",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_179", HFILL }},
    { &hf_ranap_lAI,
      { "lAI", "ranap.lAI",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_rAC,
      { "rAC", "ranap.rAC",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_cN_ID,
      { "cN-ID", "ranap.cN_ID",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_rNC_ID,
      { "rNC-ID", "ranap.rNC_ID",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_iMEI,
      { "iMEI", "ranap.iMEI",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_iMEIMask,
      { "iMEIMask", "ranap.iMEIMask",
        FT_BYTES, BASE_NONE, NULL, 0,
        "BIT_STRING_SIZE_7", HFILL }},
    { &hf_ranap_IMEIList_item,
      { "IMEI", "ranap.IMEI",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_iMEISV,
      { "iMEISV", "ranap.iMEISV",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_iMEISVMask,
      { "iMEISVMask", "ranap.iMEISVMask",
        FT_BYTES, BASE_NONE, NULL, 0,
        "BIT_STRING_SIZE_7", HFILL }},
    { &hf_ranap_IMEISVList_item,
      { "IMEISV", "ranap.IMEISV",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_measurementsToActivate,
      { "measurementsToActivate", "ranap.measurementsToActivate",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_m1report,
      { "m1report", "ranap.m1report",
        FT_UINT32, BASE_DEC, VALS(ranap_M1Report_vals), 0,
        NULL, HFILL }},
    { &hf_ranap_m2report,
      { "m2report", "ranap.m2report",
        FT_UINT32, BASE_DEC, VALS(ranap_M2Report_vals), 0,
        NULL, HFILL }},
    { &hf_ranap_requestedMBMSIPMulticastAddressandAPNRequest,
      { "requestedMBMSIPMulticastAddressandAPNRequest", "ranap.requestedMBMSIPMulticastAddressandAPNRequest",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_requestedMulticastServiceList,
      { "requestedMulticastServiceList", "ranap.requestedMulticastServiceList",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_mBMSIPMulticastAddressandAPNRequest,
      { "mBMSIPMulticastAddressandAPNRequest", "ranap.mBMSIPMulticastAddressandAPNRequest",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_permanentNAS_UE_ID,
      { "permanentNAS-UE-ID", "ranap.permanentNAS_UE_ID",
        FT_UINT32, BASE_DEC, VALS(ranap_PermanentNAS_UE_ID_vals), 0,
        NULL, HFILL }},
    { &hf_ranap_rNCTraceInformation,
      { "rNCTraceInformation", "ranap.rNCTraceInformation",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_permittedAlgorithms_01,
      { "permittedAlgorithms", "ranap.permittedAlgorithms",
        FT_UINT32, BASE_DEC, NULL, 0,
        "PermittedIntegrityProtectionAlgorithms", HFILL }},
    { &hf_ranap_key_01,
      { "key", "ranap.key",
        FT_BYTES, BASE_NONE, NULL, 0,
        "IntegrityProtectionKey", HFILL }},
    { &hf_ranap_rIM_Transfer,
      { "rIM-Transfer", "ranap.rIM_Transfer",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_gTP_TEI,
      { "gTP-TEI", "ranap.gTP_TEI",
        FT_UINT32, BASE_HEX_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_bindingID,
      { "bindingID", "ranap.bindingID",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_LA_LIST_item,
      { "LA-LIST item", "ranap.LA_LIST_item",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_listOF_SNAs,
      { "listOF-SNAs", "ranap.listOF_SNAs",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_ageOfSAI,
      { "ageOfSAI", "ranap.ageOfSAI",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_32767", HFILL }},
    { &hf_ranap_ListOF_SNAs_item,
      { "SNAC", "ranap.SNAC",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_ListOfInterfacesToTrace_item,
      { "InterfacesToTraceItem", "ranap.InterfacesToTraceItem",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_interface,
      { "interface", "ranap.interface",
        FT_UINT32, BASE_DEC, VALS(ranap_T_interface_vals), 0,
        NULL, HFILL }},
    { &hf_ranap_requestedLocationRelatedDataType,
      { "requestedLocationRelatedDataType", "ranap.requestedLocationRelatedDataType",
        FT_UINT32, BASE_DEC, VALS(ranap_RequestedLocationRelatedDataType_vals), 0,
        NULL, HFILL }},
    { &hf_ranap_requestedGPSAssistanceData,
      { "requestedGPSAssistanceData", "ranap.requestedGPSAssistanceData",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_reportChangeOfSAI,
      { "reportChangeOfSAI", "ranap.reportChangeOfSAI",
        FT_UINT32, BASE_DEC, VALS(ranap_ReportChangeOfSAI_vals), 0,
        NULL, HFILL }},
    { &hf_ranap_periodicReportingIndicator,
      { "periodicReportingIndicator", "ranap.periodicReportingIndicator",
        FT_UINT32, BASE_DEC, VALS(ranap_PeriodicReportingIndicator_vals), 0,
        NULL, HFILL }},
    { &hf_ranap_directReportingIndicator,
      { "directReportingIndicator", "ranap.directReportingIndicator",
        FT_UINT32, BASE_DEC, VALS(ranap_DirectReportingIndicator_vals), 0,
        NULL, HFILL }},
    { &hf_ranap_verticalAccuracyCode,
      { "verticalAccuracyCode", "ranap.verticalAccuracyCode",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_positioningPriorityChangeSAI,
      { "positioningPriorityChangeSAI", "ranap.positioningPriorityChangeSAI",
        FT_UINT32, BASE_DEC, VALS(ranap_PositioningPriority_vals), 0,
        "PositioningPriority", HFILL }},
    { &hf_ranap_positioningPriorityDirect,
      { "positioningPriorityDirect", "ranap.positioningPriorityDirect",
        FT_UINT32, BASE_DEC, VALS(ranap_PositioningPriority_vals), 0,
        "PositioningPriority", HFILL }},
    { &hf_ranap_clientTypePeriodic,
      { "clientTypePeriodic", "ranap.clientTypePeriodic",
        FT_UINT32, BASE_DEC, VALS(ranap_ClientType_vals), 0,
        "ClientType", HFILL }},
    { &hf_ranap_clientTypeDirect,
      { "clientTypeDirect", "ranap.clientTypeDirect",
        FT_UINT32, BASE_DEC, VALS(ranap_ClientType_vals), 0,
        "ClientType", HFILL }},
    { &hf_ranap_responseTime,
      { "responseTime", "ranap.responseTime",
        FT_UINT32, BASE_DEC, VALS(ranap_ResponseTime_vals), 0,
        NULL, HFILL }},
    { &hf_ranap_includeVelocity,
      { "includeVelocity", "ranap.includeVelocity",
        FT_UINT32, BASE_DEC, VALS(ranap_IncludeVelocity_vals), 0,
        NULL, HFILL }},
    { &hf_ranap_periodicLocationInfo,
      { "periodicLocationInfo", "ranap.periodicLocationInfo",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_periodic,
      { "periodic", "ranap.periodic",
        FT_NONE, BASE_NONE, NULL, 0,
        "MDT_Report_Parameters", HFILL }},
    { &hf_ranap_event1F,
      { "event1F", "ranap.event1F",
        FT_NONE, BASE_NONE, NULL, 0,
        "Event1F_Parameters", HFILL }},
    { &hf_ranap_event1I,
      { "event1I", "ranap.event1I",
        FT_NONE, BASE_NONE, NULL, 0,
        "Event1I_Parameters", HFILL }},
    { &hf_ranap_MBMSIPMulticastAddressandAPNRequest_item,
      { "TMGI", "ranap.TMGI",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_cellbased,
      { "cellbased", "ranap.cellbased",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_labased,
      { "labased", "ranap.labased",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_rabased,
      { "rabased", "ranap.rabased",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_plmn_area_based,
      { "plmn-area-based", "ranap.plmn_area_based",
        FT_NONE, BASE_NONE, NULL, 0,
        "PLMNAreaBased", HFILL }},
    { &hf_ranap_mdtRecordingSessionReference,
      { "mdtRecordingSessionReference", "ranap.mdtRecordingSessionReference",
        FT_UINT32, BASE_DEC, NULL, 0,
        "TraceRecordingSessionReference", HFILL }},
    { &hf_ranap_mdtActivation,
      { "mdtActivation", "ranap.mdtActivation",
        FT_UINT32, BASE_DEC, VALS(ranap_MDT_Activation_vals), 0,
        "MDT_Activation", HFILL }},
    { &hf_ranap_mdtAreaScope,
      { "mdtAreaScope", "ranap.mdtAreaScope",
        FT_UINT32, BASE_DEC, VALS(ranap_MDTAreaScope_vals), 0,
        NULL, HFILL }},
    { &hf_ranap_mdtMode,
      { "mdtMode", "ranap.mdtMode",
        FT_UINT32, BASE_DEC, VALS(ranap_MDTMode_vals), 0,
        NULL, HFILL }},
    { &hf_ranap_immediateMDT,
      { "immediateMDT", "ranap.immediateMDT",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_loggedMDT,
      { "loggedMDT", "ranap.loggedMDT",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_reportInterval,
      { "reportInterval", "ranap.reportInterval",
        FT_UINT32, BASE_DEC, VALS(ranap_ReportInterval_vals), 0,
        NULL, HFILL }},
    { &hf_ranap_reportAmount,
      { "reportAmount", "ranap.reportAmount",
        FT_UINT32, BASE_DEC, VALS(ranap_ReportAmount_vals), 0,
        NULL, HFILL }},
    { &hf_ranap_accessPointName,
      { "accessPointName", "ranap.accessPointName",
        FT_BYTES, BASE_NONE, NULL, 0,
        "Offload_RAB_Parameters_APN", HFILL }},
    { &hf_ranap_chargingCharacteristics,
      { "chargingCharacteristics", "ranap.chargingCharacteristics",
        FT_BYTES, BASE_NONE, NULL, 0,
        "Offload_RAB_Parameters_ChargingCharacteristics", HFILL }},
    { &hf_ranap_rAI,
      { "rAI", "ranap.rAI",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_PDP_TypeInformation_item,
      { "PDP-Type", "ranap.PDP_Type",
        FT_UINT32, BASE_DEC, VALS(ranap_PDP_Type_vals), 0,
        NULL, HFILL }},
    { &hf_ranap_PDP_TypeInformation_extension_item,
      { "PDP-Type-extension", "ranap.PDP_Type_extension",
        FT_UINT32, BASE_DEC, VALS(ranap_PDP_Type_extension_vals), 0,
        NULL, HFILL }},
    { &hf_ranap_reportingAmount,
      { "reportingAmount", "ranap.reportingAmount",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_1_8639999_", HFILL }},
    { &hf_ranap_reportingInterval,
      { "reportingInterval", "ranap.reportingInterval",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_1_8639999_", HFILL }},
    { &hf_ranap_iMSI,
      { "iMSI", "ranap.iMSI",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_PermittedEncryptionAlgorithms_item,
      { "EncryptionAlgorithm", "ranap.EncryptionAlgorithm",
        FT_UINT32, BASE_DEC, VALS(ranap_EncryptionAlgorithm_vals), 0,
        NULL, HFILL }},
    { &hf_ranap_PermittedIntegrityProtectionAlgorithms_item,
      { "IntegrityProtectionAlgorithm", "ranap.IntegrityProtectionAlgorithm",
        FT_UINT32, BASE_DEC, VALS(ranap_IntegrityProtectionAlgorithm_vals), 0,
        NULL, HFILL }},
    { &hf_ranap_laiList,
      { "laiList", "ranap.laiList",
        FT_UINT32, BASE_DEC, NULL, 0,
        "LAI_List", HFILL }},
    { &hf_ranap_LAI_List_item,
      { "LAI", "ranap.LAI",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_loggingInterval,
      { "loggingInterval", "ranap.loggingInterval",
        FT_UINT32, BASE_DEC, VALS(ranap_LoggingInterval_vals), 0,
        NULL, HFILL }},
    { &hf_ranap_loggingDuration,
      { "loggingDuration", "ranap.loggingDuration",
        FT_UINT32, BASE_DEC, VALS(ranap_LoggingDuration_vals), 0,
        NULL, HFILL }},
    { &hf_ranap_plmnID,
      { "plmnID", "ranap.plmnID",
        FT_BYTES, BASE_NONE, NULL, 0,
        "PLMNidentity", HFILL }},
    { &hf_ranap_PLMNs_in_shared_network_item,
      { "PLMNs-in-shared-network item", "ranap.PLMNs_in_shared_network_item",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_lA_LIST,
      { "lA-LIST", "ranap.lA_LIST",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_PositioningDataSet_item,
      { "PositioningMethodAndUsage", "ranap.PositioningMethodAndUsage",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_positioningDataDiscriminator,
      { "positioningDataDiscriminator", "ranap.positioningDataDiscriminator",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_positioningDataSet,
      { "positioningDataSet", "ranap.positioningDataSet",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_shared_network_information,
      { "shared-network-information", "ranap.shared_network_information",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_racList,
      { "racList", "ranap.racList",
        FT_UINT32, BASE_DEC, NULL, 0,
        "RAC_List", HFILL }},
    { &hf_ranap_RAC_List_item,
      { "RAC", "ranap.RAC",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_RABDataVolumeReport_item,
      { "RABDataVolumeReport item", "ranap.RABDataVolumeReport_item",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_dl_UnsuccessfullyTransmittedDataVolume,
      { "dl-UnsuccessfullyTransmittedDataVolume", "ranap.dl_UnsuccessfullyTransmittedDataVolume",
        FT_UINT32, BASE_DEC, NULL, 0,
        "UnsuccessfullyTransmittedDataVolume", HFILL }},
    { &hf_ranap_dataVolumeReference,
      { "dataVolumeReference", "ranap.dataVolumeReference",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_RAB_Parameter_ExtendedGuaranteedBitrateList_item,
      { "ExtendedGuaranteedBitrate", "ranap.ExtendedGuaranteedBitrate",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_RAB_Parameter_ExtendedMaxBitrateList_item,
      { "ExtendedMaxBitrate", "ranap.ExtendedMaxBitrate",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_RAB_Parameter_GuaranteedBitrateList_item,
      { "GuaranteedBitrate", "ranap.GuaranteedBitrate",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_RAB_Parameter_MaxBitrateList_item,
      { "MaxBitrate", "ranap.MaxBitrate",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_trafficClass,
      { "trafficClass", "ranap.trafficClass",
        FT_UINT32, BASE_DEC, VALS(ranap_TrafficClass_vals), 0,
        NULL, HFILL }},
    { &hf_ranap_rAB_AsymmetryIndicator,
      { "rAB-AsymmetryIndicator", "ranap.rAB_AsymmetryIndicator",
        FT_UINT32, BASE_DEC, VALS(ranap_RAB_AsymmetryIndicator_vals), 0,
        NULL, HFILL }},
    { &hf_ranap_maxBitrate,
      { "maxBitrate", "ranap.maxBitrate",
        FT_UINT32, BASE_DEC, NULL, 0,
        "RAB_Parameter_MaxBitrateList", HFILL }},
    { &hf_ranap_guaranteedBitRate,
      { "guaranteedBitRate", "ranap.guaranteedBitRate",
        FT_UINT32, BASE_DEC, NULL, 0,
        "RAB_Parameter_GuaranteedBitrateList", HFILL }},
    { &hf_ranap_deliveryOrder,
      { "deliveryOrder", "ranap.deliveryOrder",
        FT_UINT32, BASE_DEC, VALS(ranap_DeliveryOrder_vals), 0,
        NULL, HFILL }},
    { &hf_ranap_maxSDU_Size,
      { "maxSDU-Size", "ranap.maxSDU_Size",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_sDU_Parameters,
      { "sDU-Parameters", "ranap.sDU_Parameters",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_transferDelay,
      { "transferDelay", "ranap.transferDelay",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_trafficHandlingPriority,
      { "trafficHandlingPriority", "ranap.trafficHandlingPriority",
        FT_UINT32, BASE_DEC, VALS(ranap_TrafficHandlingPriority_vals), 0,
        NULL, HFILL }},
    { &hf_ranap_allocationOrRetentionPriority,
      { "allocationOrRetentionPriority", "ranap.allocationOrRetentionPriority",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_sourceStatisticsDescriptor,
      { "sourceStatisticsDescriptor", "ranap.sourceStatisticsDescriptor",
        FT_UINT32, BASE_DEC, VALS(ranap_SourceStatisticsDescriptor_vals), 0,
        NULL, HFILL }},
    { &hf_ranap_relocationRequirement,
      { "relocationRequirement", "ranap.relocationRequirement",
        FT_UINT32, BASE_DEC, VALS(ranap_RelocationRequirement_vals), 0,
        NULL, HFILL }},
    { &hf_ranap_RABParametersList_item,
      { "RABParametersList item", "ranap.RABParametersList_item",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_rab_Id,
      { "rab-Id", "ranap.rab_Id",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_cn_domain,
      { "cn-domain", "ranap.cn_domain",
        FT_UINT32, BASE_DEC, VALS(ranap_CN_DomainIndicator_vals), 0,
        "CN_DomainIndicator", HFILL }},
    { &hf_ranap_rabDataVolumeReport,
      { "rabDataVolumeReport", "ranap.rabDataVolumeReport",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_upInformation,
      { "upInformation", "ranap.upInformation",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_RAB_TrCH_Mapping_item,
      { "RAB-TrCH-MappingItem", "ranap.RAB_TrCH_MappingItem",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_rAB_ID,
      { "rAB-ID", "ranap.rAB_ID",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_trCH_ID_List,
      { "trCH-ID-List", "ranap.trCH_ID_List",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_notEmptyRAListofIdleModeUEs,
      { "notEmptyRAListofIdleModeUEs", "ranap.notEmptyRAListofIdleModeUEs",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_emptyFullRAListofIdleModeUEs,
      { "emptyFullRAListofIdleModeUEs", "ranap.emptyFullRAListofIdleModeUEs",
        FT_UINT32, BASE_DEC, VALS(ranap_T_emptyFullRAListofIdleModeUEs_vals), 0,
        NULL, HFILL }},
    { &hf_ranap_rAofIdleModeUEs,
      { "rAofIdleModeUEs", "ranap.rAofIdleModeUEs",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_RAofIdleModeUEs_item,
      { "RAC", "ranap.RAC",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_LAListofIdleModeUEs_item,
      { "LAI", "ranap.LAI",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_RequestedMBMSIPMulticastAddressandAPNRequest_item,
      { "MBMSIPMulticastAddressandAPNlist", "ranap.MBMSIPMulticastAddressandAPNlist",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_tMGI,
      { "tMGI", "ranap.tMGI",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_iPMulticastAddress,
      { "iPMulticastAddress", "ranap.iPMulticastAddress",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_aPN,
      { "aPN", "ranap.aPN",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_RequestedMulticastServiceList_item,
      { "TMGI", "ranap.TMGI",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_requestedMaxBitrates,
      { "requestedMaxBitrates", "ranap.requestedMaxBitrates",
        FT_UINT32, BASE_DEC, NULL, 0,
        "Requested_RAB_Parameter_MaxBitrateList", HFILL }},
    { &hf_ranap_requestedGuaranteedBitrates,
      { "requestedGuaranteedBitrates", "ranap.requestedGuaranteedBitrates",
        FT_UINT32, BASE_DEC, NULL, 0,
        "Requested_RAB_Parameter_GuaranteedBitrateList", HFILL }},
    { &hf_ranap_Requested_RAB_Parameter_ExtendedMaxBitrateList_item,
      { "ExtendedMaxBitrate", "ranap.ExtendedMaxBitrate",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_Requested_RAB_Parameter_ExtendedGuaranteedBitrateList_item,
      { "ExtendedGuaranteedBitrate", "ranap.ExtendedGuaranteedBitrate",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_Requested_RAB_Parameter_MaxBitrateList_item,
      { "MaxBitrate", "ranap.MaxBitrate",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_Requested_RAB_Parameter_GuaranteedBitrateList_item,
      { "GuaranteedBitrate", "ranap.GuaranteedBitrate",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_event,
      { "event", "ranap.event",
        FT_UINT32, BASE_DEC, VALS(ranap_Event_vals), 0,
        NULL, HFILL }},
    { &hf_ranap_reportArea,
      { "reportArea", "ranap.reportArea",
        FT_UINT32, BASE_DEC, VALS(ranap_ReportArea_vals), 0,
        NULL, HFILL }},
    { &hf_ranap_accuracyCode,
      { "accuracyCode", "ranap.accuracyCode",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_127", HFILL }},
    { &hf_ranap_mantissa,
      { "mantissa", "ranap.mantissa",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_1_9", HFILL }},
    { &hf_ranap_exponent,
      { "exponent", "ranap.exponent",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_1_8", HFILL }},
    { &hf_ranap_rIMInformation,
      { "rIMInformation", "ranap.rIMInformation",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_rIMRoutingAddress,
      { "rIMRoutingAddress", "ranap.rIMRoutingAddress",
        FT_UINT32, BASE_DEC, VALS(ranap_RIMRoutingAddress_vals), 0,
        NULL, HFILL }},
    { &hf_ranap_targetRNC_ID,
      { "targetRNC-ID", "ranap.targetRNC_ID",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_gERAN_Cell_ID,
      { "gERAN-Cell-ID", "ranap.gERAN_Cell_ID",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_targeteNB_ID,
      { "targeteNB-ID", "ranap.targeteNB_ID",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_traceReference,
      { "traceReference", "ranap.traceReference",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_traceActivationIndicator,
      { "traceActivationIndicator", "ranap.traceActivationIndicator",
        FT_UINT32, BASE_DEC, VALS(ranap_T_traceActivationIndicator_vals), 0,
        NULL, HFILL }},
    { &hf_ranap_equipmentsToBeTraced,
      { "equipmentsToBeTraced", "ranap.equipmentsToBeTraced",
        FT_UINT32, BASE_DEC, VALS(ranap_EquipmentsToBeTraced_vals), 0,
        NULL, HFILL }},
    { &hf_ranap_rabParmetersList,
      { "rabParmetersList", "ranap.rabParmetersList",
        FT_UINT32, BASE_DEC, NULL, 0,
        "RABParametersList", HFILL }},
    { &hf_ranap_locationReporting,
      { "locationReporting", "ranap.locationReporting",
        FT_NONE, BASE_NONE, NULL, 0,
        "LocationReportingTransferInformation", HFILL }},
    { &hf_ranap_traceInformation,
      { "traceInformation", "ranap.traceInformation",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_sourceSAI,
      { "sourceSAI", "ranap.sourceSAI",
        FT_NONE, BASE_NONE, NULL, 0,
        "SAI", HFILL }},
    { &hf_ranap_sAC,
      { "sAC", "ranap.sAC",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_pLMNs_in_shared_network,
      { "pLMNs-in-shared-network", "ranap.pLMNs_in_shared_network",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_exponent_1_8,
      { "exponent", "ranap.exponent",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_1_6", HFILL }},
    { &hf_ranap_SDU_FormatInformationParameters_item,
      { "SDU-FormatInformationParameters item", "ranap.SDU_FormatInformationParameters_item",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_subflowSDU_Size,
      { "subflowSDU-Size", "ranap.subflowSDU_Size",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_rAB_SubflowCombinationBitRate,
      { "rAB-SubflowCombinationBitRate", "ranap.rAB_SubflowCombinationBitRate",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_SDU_Parameters_item,
      { "SDU-Parameters item", "ranap.SDU_Parameters_item",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_sDU_ErrorRatio,
      { "sDU-ErrorRatio", "ranap.sDU_ErrorRatio",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_residualBitErrorRatio,
      { "residualBitErrorRatio", "ranap.residualBitErrorRatio",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_deliveryOfErroneousSDU,
      { "deliveryOfErroneousSDU", "ranap.deliveryOfErroneousSDU",
        FT_UINT32, BASE_DEC, VALS(ranap_DeliveryOfErroneousSDU_vals), 0,
        NULL, HFILL }},
    { &hf_ranap_sDU_FormatInformationParameters,
      { "sDU-FormatInformationParameters", "ranap.sDU_FormatInformationParameters",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_authorisedPLMNs,
      { "authorisedPLMNs", "ranap.authorisedPLMNs",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_sourceUTRANCellID,
      { "sourceUTRANCellID", "ranap.sourceUTRANCellID",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_sourceGERANCellID,
      { "sourceGERANCellID", "ranap.sourceGERANCellID",
        FT_NONE, BASE_NONE, NULL, 0,
        "CGI", HFILL }},
    { &hf_ranap_sourceRNC_ID,
      { "sourceRNC-ID", "ranap.sourceRNC_ID",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_rRC_Container,
      { "rRC-Container", "ranap.rRC_Container",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_numberOfIuInstances,
      { "numberOfIuInstances", "ranap.numberOfIuInstances",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_relocationType,
      { "relocationType", "ranap.relocationType",
        FT_UINT32, BASE_DEC, VALS(ranap_RelocationType_vals), 0,
        NULL, HFILL }},
    { &hf_ranap_chosenIntegrityProtectionAlgorithm,
      { "chosenIntegrityProtectionAlgorithm", "ranap.chosenIntegrityProtectionAlgorithm",
        FT_UINT32, BASE_DEC, VALS(ranap_IntegrityProtectionAlgorithm_vals), 0,
        NULL, HFILL }},
    { &hf_ranap_integrityProtectionKey,
      { "integrityProtectionKey", "ranap.integrityProtectionKey",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_chosenEncryptionAlgorithForSignalling,
      { "chosenEncryptionAlgorithForSignalling", "ranap.chosenEncryptionAlgorithForSignalling",
        FT_UINT32, BASE_DEC, VALS(ranap_EncryptionAlgorithm_vals), 0,
        "ChosenEncryptionAlgorithm", HFILL }},
    { &hf_ranap_cipheringKey,
      { "cipheringKey", "ranap.cipheringKey",
        FT_BYTES, BASE_NONE, NULL, 0,
        "EncryptionKey", HFILL }},
    { &hf_ranap_chosenEncryptionAlgorithForCS,
      { "chosenEncryptionAlgorithForCS", "ranap.chosenEncryptionAlgorithForCS",
        FT_UINT32, BASE_DEC, VALS(ranap_EncryptionAlgorithm_vals), 0,
        "ChosenEncryptionAlgorithm", HFILL }},
    { &hf_ranap_chosenEncryptionAlgorithForPS,
      { "chosenEncryptionAlgorithForPS", "ranap.chosenEncryptionAlgorithForPS",
        FT_UINT32, BASE_DEC, VALS(ranap_EncryptionAlgorithm_vals), 0,
        "ChosenEncryptionAlgorithm", HFILL }},
    { &hf_ranap_d_RNTI,
      { "d-RNTI", "ranap.d_RNTI",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_targetCellId,
      { "targetCellId", "ranap.targetCellId",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_rAB_TrCH_Mapping,
      { "rAB-TrCH-Mapping", "ranap.rAB_TrCH_Mapping",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_rSRP,
      { "rSRP", "ranap.rSRP",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_97", HFILL }},
    { &hf_ranap_rSRQ,
      { "rSRQ", "ranap.rSRQ",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_34", HFILL }},
    { &hf_ranap_iRATmeasurementParameters,
      { "iRATmeasurementParameters", "ranap.iRATmeasurementParameters",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_measurementDuration,
      { "measurementDuration", "ranap.measurementDuration",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_1_100", HFILL }},
    { &hf_ranap_eUTRANFrequencies,
      { "eUTRANFrequencies", "ranap.eUTRANFrequencies",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_EUTRANFrequencies_item,
      { "EUTRANFrequencies item", "ranap.EUTRANFrequencies_item",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_earfcn,
      { "earfcn", "ranap.earfcn",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_65535", HFILL }},
    { &hf_ranap_measBand,
      { "measBand", "ranap.measBand",
        FT_UINT32, BASE_DEC, VALS(ranap_MeasBand_vals), 0,
        NULL, HFILL }},
    { &hf_ranap_SupportedRAB_ParameterBitrateList_item,
      { "SupportedBitrate", "ranap.SupportedBitrate",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_uTRANcellID,
      { "uTRANcellID", "ranap.uTRANcellID",
        FT_UINT32, BASE_DEC, NULL, 0,
        "TargetCellId", HFILL }},
    { &hf_ranap_SRB_TrCH_Mapping_item,
      { "SRB-TrCH-MappingItem", "ranap.SRB_TrCH_MappingItem",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_sRB_ID,
      { "sRB-ID", "ranap.sRB_ID",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_trCH_ID,
      { "trCH-ID", "ranap.trCH_ID",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_nonce,
      { "nonce", "ranap.nonce",
        FT_BYTES, BASE_NONE, NULL, 0,
        "BIT_STRING_SIZE_128", HFILL }},
    { &hf_ranap_tAC,
      { "tAC", "ranap.tAC",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_cGI,
      { "cGI", "ranap.cGI",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_eNB_ID,
      { "eNB-ID", "ranap.eNB_ID",
        FT_UINT32, BASE_DEC, VALS(ranap_ENB_ID_vals), 0,
        NULL, HFILL }},
    { &hf_ranap_selectedTAI,
      { "selectedTAI", "ranap.selectedTAI",
        FT_NONE, BASE_NONE, NULL, 0,
        "TAI", HFILL }},
    { &hf_ranap_tMSI,
      { "tMSI", "ranap.tMSI",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_p_TMSI,
      { "p-TMSI", "ranap.p_TMSI",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_serviceID,
      { "serviceID", "ranap.serviceID",
        FT_BYTES, BASE_NONE, NULL, 0,
        "OCTET_STRING_SIZE_3", HFILL }},
    { &hf_ranap_ue_identity,
      { "ue-identity", "ranap.ue_identity",
        FT_UINT32, BASE_DEC, VALS(ranap_UE_ID_vals), 0,
        "UE_ID", HFILL }},
    { &hf_ranap_tracePropagationParameters,
      { "tracePropagationParameters", "ranap.tracePropagationParameters",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_traceRecordingSessionReference,
      { "traceRecordingSessionReference", "ranap.traceRecordingSessionReference",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_traceDepth,
      { "traceDepth", "ranap.traceDepth",
        FT_UINT32, BASE_DEC, VALS(ranap_TraceDepth_vals), 0,
        NULL, HFILL }},
    { &hf_ranap_listOfInterfacesToTrace,
      { "listOfInterfacesToTrace", "ranap.listOfInterfacesToTrace",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_dCH_ID,
      { "dCH-ID", "ranap.dCH_ID",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_dSCH_ID,
      { "dSCH-ID", "ranap.dSCH_ID",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_uSCH_ID,
      { "uSCH-ID", "ranap.uSCH_ID",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_TrCH_ID_List_item,
      { "TrCH-ID", "ranap.TrCH_ID",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_uE_AggregateMaximumBitRateDownlink,
      { "uE-AggregateMaximumBitRateDownlink", "ranap.uE_AggregateMaximumBitRateDownlink",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_uE_AggregateMaximumBitRateUplink,
      { "uE-AggregateMaximumBitRateUplink", "ranap.uE_AggregateMaximumBitRateUplink",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_imsi,
      { "imsi", "ranap.imsi",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_imei,
      { "imei", "ranap.imei",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_imeisv,
      { "imeisv", "ranap.imeisv",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_uESBI_IuA,
      { "uESBI-IuA", "ranap.uESBI_IuA",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_uESBI_IuB,
      { "uESBI-IuB", "ranap.uESBI_IuB",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_frameSeqNoUL,
      { "frameSeqNoUL", "ranap.frameSeqNoUL",
        FT_UINT32, BASE_DEC, NULL, 0,
        "FrameSequenceNumber", HFILL }},
    { &hf_ranap_frameSeqNoDL,
      { "frameSeqNoDL", "ranap.frameSeqNoDL",
        FT_UINT32, BASE_DEC, NULL, 0,
        "FrameSequenceNumber", HFILL }},
    { &hf_ranap_pdu14FrameSeqNoUL,
      { "pdu14FrameSeqNoUL", "ranap.pdu14FrameSeqNoUL",
        FT_UINT32, BASE_DEC, NULL, 0,
        "PDUType14FrameSequenceNumber", HFILL }},
    { &hf_ranap_pdu14FrameSeqNoDL,
      { "pdu14FrameSeqNoDL", "ranap.pdu14FrameSeqNoDL",
        FT_UINT32, BASE_DEC, NULL, 0,
        "PDUType14FrameSequenceNumber", HFILL }},
    { &hf_ranap_dataPDUType,
      { "dataPDUType", "ranap.dataPDUType",
        FT_UINT32, BASE_DEC, VALS(ranap_DataPDUType_vals), 0,
        NULL, HFILL }},
    { &hf_ranap_upinitialisationFrame,
      { "upinitialisationFrame", "ranap.upinitialisationFrame",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_horizontalVelocity,
      { "horizontalVelocity", "ranap.horizontalVelocity",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_horizontalWithVerticalVelocity,
      { "horizontalWithVerticalVelocity", "ranap.horizontalWithVerticalVelocity",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_horizontalVelocityWithUncertainty,
      { "horizontalVelocityWithUncertainty", "ranap.horizontalVelocityWithUncertainty",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_horizontalWithVeritcalVelocityAndUncertainty,
      { "horizontalWithVeritcalVelocityAndUncertainty", "ranap.horizontalWithVeritcalVelocityAndUncertainty",
        FT_NONE, BASE_NONE, NULL, 0,
        "HorizontalWithVerticalVelocityAndUncertainty", HFILL }},
    { &hf_ranap_horizontalSpeedAndBearing,
      { "horizontalSpeedAndBearing", "ranap.horizontalSpeedAndBearing",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_veritcalVelocity,
      { "veritcalVelocity", "ranap.veritcalVelocity",
        FT_NONE, BASE_NONE, NULL, 0,
        "VerticalVelocity", HFILL }},
    { &hf_ranap_uncertaintySpeed,
      { "uncertaintySpeed", "ranap.uncertaintySpeed",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_255", HFILL }},
    { &hf_ranap_horizontalUncertaintySpeed,
      { "horizontalUncertaintySpeed", "ranap.horizontalUncertaintySpeed",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_255", HFILL }},
    { &hf_ranap_verticalUncertaintySpeed,
      { "verticalUncertaintySpeed", "ranap.verticalUncertaintySpeed",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_255", HFILL }},
    { &hf_ranap_bearing,
      { "bearing", "ranap.bearing",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_359", HFILL }},
    { &hf_ranap_horizontalSpeed,
      { "horizontalSpeed", "ranap.horizontalSpeed",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_2047", HFILL }},
    { &hf_ranap_veritcalSpeed,
      { "veritcalSpeed", "ranap.veritcalSpeed",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_255", HFILL }},
    { &hf_ranap_veritcalSpeedDirection,
      { "veritcalSpeedDirection", "ranap.veritcalSpeedDirection",
        FT_UINT32, BASE_DEC, VALS(ranap_VerticalSpeedDirection_vals), 0,
        "VerticalSpeedDirection", HFILL }},
    { &hf_ranap_protocolIEs,
      { "protocolIEs", "ranap.protocolIEs",
        FT_UINT32, BASE_DEC, NULL, 0,
        "ProtocolIE_Container", HFILL }},
    { &hf_ranap_protocolExtensions,
      { "protocolExtensions", "ranap.protocolExtensions",
        FT_UINT32, BASE_DEC, NULL, 0,
        "ProtocolExtensionContainer", HFILL }},
    { &hf_ranap_rab_dl_UnsuccessfullyTransmittedDataVolume,
      { "dl-UnsuccessfullyTransmittedDataVolume", "ranap.dl_UnsuccessfullyTransmittedDataVolume",
        FT_UINT32, BASE_DEC, NULL, 0,
        "DataVolumeList", HFILL }},
    { &hf_ranap_dL_GTP_PDU_SequenceNumber,
      { "dL-GTP-PDU-SequenceNumber", "ranap.dL_GTP_PDU_SequenceNumber",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_uL_GTP_PDU_SequenceNumber,
      { "uL-GTP-PDU-SequenceNumber", "ranap.uL_GTP_PDU_SequenceNumber",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_transportLayerAddress,
      { "transportLayerAddress", "ranap.transportLayerAddress",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_iuTransportAssociation,
      { "iuTransportAssociation", "ranap.iuTransportAssociation",
        FT_UINT32, BASE_DEC, VALS(ranap_IuTransportAssociation_vals), 0,
        NULL, HFILL }},
    { &hf_ranap_nAS_SynchronisationIndicator,
      { "nAS-SynchronisationIndicator", "ranap.nAS_SynchronisationIndicator",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_rAB_Parameters,
      { "rAB-Parameters", "ranap.rAB_Parameters",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_dataVolumeReportingIndication,
      { "dataVolumeReportingIndication", "ranap.dataVolumeReportingIndication",
        FT_UINT32, BASE_DEC, VALS(ranap_DataVolumeReportingIndication_vals), 0,
        NULL, HFILL }},
    { &hf_ranap_pDP_TypeInformation,
      { "pDP-TypeInformation", "ranap.pDP_TypeInformation",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_userPlaneInformation,
      { "userPlaneInformation", "ranap.userPlaneInformation",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_service_Handover,
      { "service-Handover", "ranap.service_Handover",
        FT_UINT32, BASE_DEC, VALS(ranap_Service_Handover_vals), 0,
        NULL, HFILL }},
    { &hf_ranap_userPlaneMode,
      { "userPlaneMode", "ranap.userPlaneMode",
        FT_UINT32, BASE_DEC, VALS(ranap_UserPlaneMode_vals), 0,
        NULL, HFILL }},
    { &hf_ranap_uP_ModeVersions,
      { "uP-ModeVersions", "ranap.uP_ModeVersions",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_joinedMBMSBearerService_IEs,
      { "joinedMBMSBearerService-IEs", "ranap.joinedMBMSBearerService_IEs",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_JoinedMBMSBearerService_IEs_item,
      { "JoinedMBMSBearerService-IEs item", "ranap.JoinedMBMSBearerService_IEs_item",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_mBMS_PTP_RAB_ID,
      { "mBMS-PTP-RAB-ID", "ranap.mBMS_PTP_RAB_ID",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_cause,
      { "cause", "ranap.cause",
        FT_UINT32, BASE_DEC, VALS(ranap_Cause_vals), 0,
        NULL, HFILL }},
    { &hf_ranap_dl_GTP_PDU_SequenceNumber,
      { "dl-GTP-PDU-SequenceNumber", "ranap.dl_GTP_PDU_SequenceNumber",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_ul_GTP_PDU_SequenceNumber,
      { "ul-GTP-PDU-SequenceNumber", "ranap.ul_GTP_PDU_SequenceNumber",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_dl_N_PDU_SequenceNumber,
      { "dl-N-PDU-SequenceNumber", "ranap.dl_N_PDU_SequenceNumber",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_ul_N_PDU_SequenceNumber,
      { "ul-N-PDU-SequenceNumber", "ranap.ul_N_PDU_SequenceNumber",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_iuSigConId,
      { "iuSigConId", "ranap.iuSigConId",
        FT_BYTES, BASE_NONE, NULL, 0,
        "IuSignallingConnectionIdentifier", HFILL }},
    { &hf_ranap_transportLayerAddressReq1,
      { "transportLayerAddressReq1", "ranap.transportLayerAddressReq1",
        FT_BYTES, BASE_NONE, NULL, 0,
        "TransportLayerAddress", HFILL }},
    { &hf_ranap_iuTransportAssociationReq1,
      { "iuTransportAssociationReq1", "ranap.iuTransportAssociationReq1",
        FT_UINT32, BASE_DEC, VALS(ranap_IuTransportAssociation_vals), 0,
        "IuTransportAssociation", HFILL }},
    { &hf_ranap_ass_RAB_Parameters,
      { "ass-RAB-Parameters", "ranap.ass_RAB_Parameters",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_transportLayerAddressRes1,
      { "transportLayerAddressRes1", "ranap.transportLayerAddressRes1",
        FT_BYTES, BASE_NONE, NULL, 0,
        "TransportLayerAddress", HFILL }},
    { &hf_ranap_iuTransportAssociationRes1,
      { "iuTransportAssociationRes1", "ranap.iuTransportAssociationRes1",
        FT_UINT32, BASE_DEC, VALS(ranap_IuTransportAssociation_vals), 0,
        "IuTransportAssociation", HFILL }},
    { &hf_ranap_rab2beReleasedList,
      { "rab2beReleasedList", "ranap.rab2beReleasedList",
        FT_UINT32, BASE_DEC, NULL, 0,
        "RAB_ToBeReleasedList_EnhancedRelocCompleteRes", HFILL }},
    { &hf_ranap_transportLayerInformation,
      { "transportLayerInformation", "ranap.transportLayerInformation",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_dl_dataVolumes,
      { "dl-dataVolumes", "ranap.dl_dataVolumes",
        FT_UINT32, BASE_DEC, NULL, 0,
        "DataVolumeList", HFILL }},
    { &hf_ranap_DataVolumeList_item,
      { "DataVolumeList item", "ranap.DataVolumeList_item",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_gERAN_Classmark,
      { "gERAN-Classmark", "ranap.gERAN_Classmark",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_privateIEs,
      { "privateIEs", "ranap.privateIEs",
        FT_UINT32, BASE_DEC, NULL, 0,
        "PrivateIE_Container", HFILL }},
    { &hf_ranap_nAS_PDU,
      { "nAS-PDU", "ranap.nAS_PDU",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_sAPI,
      { "sAPI", "ranap.sAPI",
        FT_UINT32, BASE_DEC, VALS(ranap_SAPI_vals), 0,
        NULL, HFILL }},
    { &hf_ranap_cN_DomainIndicator,
      { "cN-DomainIndicator", "ranap.cN_DomainIndicator",
        FT_UINT32, BASE_DEC, VALS(ranap_CN_DomainIndicator_vals), 0,
        NULL, HFILL }},
    { &hf_ranap_dataForwardingInformation,
      { "dataForwardingInformation", "ranap.dataForwardingInformation",
        FT_NONE, BASE_NONE, NULL, 0,
        "TNLInformationEnhRelInfoReq", HFILL }},
    { &hf_ranap_sourceSideIuULTNLInfo,
      { "sourceSideIuULTNLInfo", "ranap.sourceSideIuULTNLInfo",
        FT_NONE, BASE_NONE, NULL, 0,
        "TNLInformationEnhRelInfoReq", HFILL }},
    { &hf_ranap_alt_RAB_Parameters,
      { "alt-RAB-Parameters", "ranap.alt_RAB_Parameters",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_dataForwardingInformation_01,
      { "dataForwardingInformation", "ranap.dataForwardingInformation",
        FT_NONE, BASE_NONE, NULL, 0,
        "TNLInformationEnhRelInfoRes", HFILL }},
    { &hf_ranap_dl_forwardingTransportLayerAddress,
      { "dl-forwardingTransportLayerAddress", "ranap.dl_forwardingTransportLayerAddress",
        FT_BYTES, BASE_NONE, NULL, 0,
        "TransportLayerAddress", HFILL }},
    { &hf_ranap_dl_forwardingTransportAssociation,
      { "dl-forwardingTransportAssociation", "ranap.dl_forwardingTransportAssociation",
        FT_UINT32, BASE_DEC, VALS(ranap_IuTransportAssociation_vals), 0,
        "IuTransportAssociation", HFILL }},
    { &hf_ranap_requested_RAB_Parameter_Values,
      { "requested-RAB-Parameter-Values", "ranap.requested_RAB_Parameter_Values",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_mBMSHCIndicator,
      { "mBMSHCIndicator", "ranap.mBMSHCIndicator",
        FT_UINT32, BASE_DEC, VALS(ranap_MBMSHCIndicator_vals), 0,
        NULL, HFILL }},
    { &hf_ranap_gTPDLTEID,
      { "gTPDLTEID", "ranap.gTPDLTEID",
        FT_UINT32, BASE_HEX_DEC, NULL, 0,
        "GTP_TEI", HFILL }},
    { &hf_ranap_LeftMBMSBearerService_IEs_item,
      { "LeftMBMSBearerService-IEs item", "ranap.LeftMBMSBearerService_IEs_item",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_UnsuccessfulLinking_IEs_item,
      { "UnsuccessfulLinking-IEs item", "ranap.UnsuccessfulLinking_IEs_item",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_initiatingMessage,
      { "initiatingMessage", "ranap.initiatingMessage",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_successfulOutcome,
      { "successfulOutcome", "ranap.successfulOutcome",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_unsuccessfulOutcome,
      { "unsuccessfulOutcome", "ranap.unsuccessfulOutcome",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_outcome,
      { "outcome", "ranap.outcome",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_initiatingMessagevalue,
      { "value", "ranap.value",
        FT_NONE, BASE_NONE, NULL, 0,
        "InitiatingMessage_value", HFILL }},
    { &hf_ranap_successfulOutcome_value,
      { "value", "ranap.value",
        FT_NONE, BASE_NONE, NULL, 0,
        "SuccessfulOutcome_value", HFILL }},
    { &hf_ranap_unsuccessfulOutcome_value,
      { "value", "ranap.value",
        FT_NONE, BASE_NONE, NULL, 0,
        "UnsuccessfulOutcome_value", HFILL }},
    { &hf_ranap_value,
      { "value", "ranap.value",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},

/*--- End of included file: packet-ranap-hfarr.c ---*/
#line 321 "../../asn1/ranap/packet-ranap-template.c"
  };

  /* List of subtrees */
  static gint *ett[] = {
		  &ett_ranap,
		  &ett_ranap_TransportLayerAddress,
		  &ett_ranap_TransportLayerAddress_nsap,

/*--- Included file: packet-ranap-ettarr.c ---*/
#line 1 "../../asn1/ranap/packet-ranap-ettarr.c"
    &ett_ranap_PrivateIE_ID,
    &ett_ranap_ProtocolIE_Container,
    &ett_ranap_ProtocolIE_Field,
    &ett_ranap_ProtocolIE_ContainerPair,
    &ett_ranap_ProtocolIE_FieldPair,
    &ett_ranap_ProtocolIE_ContainerList,
    &ett_ranap_ProtocolIE_ContainerPairList,
    &ett_ranap_ProtocolExtensionContainer,
    &ett_ranap_ProtocolExtensionField,
    &ett_ranap_PrivateIE_Container,
    &ett_ranap_PrivateIE_Field,
    &ett_ranap_AllocationOrRetentionPriority,
    &ett_ranap_Alt_RAB_Parameters,
    &ett_ranap_Alt_RAB_Parameter_ExtendedGuaranteedBitrateInf,
    &ett_ranap_Alt_RAB_Parameter_ExtendedGuaranteedBitrates,
    &ett_ranap_Alt_RAB_Parameter_ExtendedGuaranteedBitrateList,
    &ett_ranap_Alt_RAB_Parameter_GuaranteedBitrateInf,
    &ett_ranap_Alt_RAB_Parameter_GuaranteedBitrates,
    &ett_ranap_Alt_RAB_Parameter_GuaranteedBitrateList,
    &ett_ranap_Alt_RAB_Parameter_SupportedGuaranteedBitrateInf,
    &ett_ranap_Alt_RAB_Parameter_SupportedGuaranteedBitrates,
    &ett_ranap_Alt_RAB_Parameter_ExtendedMaxBitrateInf,
    &ett_ranap_Alt_RAB_Parameter_ExtendedMaxBitrates,
    &ett_ranap_Alt_RAB_Parameter_ExtendedMaxBitrateList,
    &ett_ranap_Alt_RAB_Parameter_MaxBitrateInf,
    &ett_ranap_Alt_RAB_Parameter_MaxBitrates,
    &ett_ranap_Alt_RAB_Parameter_MaxBitrateList,
    &ett_ranap_Alt_RAB_Parameter_SupportedMaxBitrateInf,
    &ett_ranap_Alt_RAB_Parameter_SupportedMaxBitrates,
    &ett_ranap_AreaIdentity,
    &ett_ranap_Ass_RAB_Parameters,
    &ett_ranap_Ass_RAB_Parameter_ExtendedGuaranteedBitrateList,
    &ett_ranap_Ass_RAB_Parameter_ExtendedMaxBitrateList,
    &ett_ranap_Ass_RAB_Parameter_GuaranteedBitrateList,
    &ett_ranap_Ass_RAB_Parameter_MaxBitrateList,
    &ett_ranap_AuthorisedPLMNs,
    &ett_ranap_AuthorisedPLMNs_item,
    &ett_ranap_AuthorisedSNAs,
    &ett_ranap_BroadcastAssistanceDataDecipheringKeys,
    &ett_ranap_Cause,
    &ett_ranap_CellBased,
    &ett_ranap_CellIdList,
    &ett_ranap_CellLoadInformation,
    &ett_ranap_CellLoadInformationGroup,
    &ett_ranap_CriticalityDiagnostics,
    &ett_ranap_CriticalityDiagnostics_IE_List,
    &ett_ranap_CriticalityDiagnostics_IE_List_item,
    &ett_ranap_MessageStructure,
    &ett_ranap_MessageStructure_item,
    &ett_ranap_CGI,
    &ett_ranap_CSG_Id_List,
    &ett_ranap_DeltaRAListofIdleModeUEs,
    &ett_ranap_NewRAListofIdleModeUEs,
    &ett_ranap_RAListwithNoIdleModeUEsAnyMore,
    &ett_ranap_ENB_ID,
    &ett_ranap_EncryptionInformation,
    &ett_ranap_EquipmentsToBeTraced,
    &ett_ranap_Event1F_Parameters,
    &ett_ranap_Event1I_Parameters,
    &ett_ranap_GANSS_PositioningDataSet,
    &ett_ranap_GeographicalArea,
    &ett_ranap_GeographicalCoordinates,
    &ett_ranap_GA_AltitudeAndDirection,
    &ett_ranap_GA_EllipsoidArc,
    &ett_ranap_GA_Point,
    &ett_ranap_GA_PointWithAltitude,
    &ett_ranap_GA_PointWithAltitudeAndUncertaintyEllipsoid,
    &ett_ranap_GA_PointWithUnCertainty,
    &ett_ranap_GA_PointWithUnCertaintyEllipse,
    &ett_ranap_GA_Polygon,
    &ett_ranap_GA_Polygon_item,
    &ett_ranap_GA_UncertaintyEllipse,
    &ett_ranap_GERAN_Cell_ID,
    &ett_ranap_GlobalCN_ID,
    &ett_ranap_GlobalRNC_ID,
    &ett_ranap_IMEIGroup,
    &ett_ranap_IMEIList,
    &ett_ranap_IMEISVGroup,
    &ett_ranap_IMEISVList,
    &ett_ranap_ImmediateMDT,
    &ett_ranap_InformationRequested,
    &ett_ranap_InformationRequestType,
    &ett_ranap_InformationTransferType,
    &ett_ranap_IntegrityProtectionInformation,
    &ett_ranap_InterSystemInformationTransferType,
    &ett_ranap_InterSystemInformation_TransparentContainer,
    &ett_ranap_IuTransportAssociation,
    &ett_ranap_LA_LIST,
    &ett_ranap_LA_LIST_item,
    &ett_ranap_LAI,
    &ett_ranap_LastKnownServiceArea,
    &ett_ranap_ListOF_SNAs,
    &ett_ranap_ListOfInterfacesToTrace,
    &ett_ranap_InterfacesToTraceItem,
    &ett_ranap_LocationRelatedDataRequestType,
    &ett_ranap_LocationReportingTransferInformation,
    &ett_ranap_M1Report,
    &ett_ranap_M2Report,
    &ett_ranap_MBMSIPMulticastAddressandAPNRequest,
    &ett_ranap_MDTAreaScope,
    &ett_ranap_MDT_Configuration,
    &ett_ranap_MDTMode,
    &ett_ranap_MDT_Report_Parameters,
    &ett_ranap_Offload_RAB_Parameters,
    &ett_ranap_PagingAreaID,
    &ett_ranap_PDP_TypeInformation,
    &ett_ranap_PDP_TypeInformation_extension,
    &ett_ranap_PeriodicLocationInfo,
    &ett_ranap_PermanentNAS_UE_ID,
    &ett_ranap_PermittedEncryptionAlgorithms,
    &ett_ranap_PermittedIntegrityProtectionAlgorithms,
    &ett_ranap_LABased,
    &ett_ranap_LAI_List,
    &ett_ranap_LoggedMDT,
    &ett_ranap_PLMNAreaBased,
    &ett_ranap_PLMNs_in_shared_network,
    &ett_ranap_PLMNs_in_shared_network_item,
    &ett_ranap_PositioningDataSet,
    &ett_ranap_PositionData,
    &ett_ranap_ProvidedData,
    &ett_ranap_RABased,
    &ett_ranap_RAC_List,
    &ett_ranap_RABDataVolumeReport,
    &ett_ranap_RABDataVolumeReport_item,
    &ett_ranap_RAB_Parameter_ExtendedGuaranteedBitrateList,
    &ett_ranap_RAB_Parameter_ExtendedMaxBitrateList,
    &ett_ranap_RAB_Parameter_GuaranteedBitrateList,
    &ett_ranap_RAB_Parameter_MaxBitrateList,
    &ett_ranap_RAB_Parameters,
    &ett_ranap_RABParametersList,
    &ett_ranap_RABParametersList_item,
    &ett_ranap_RAB_TrCH_Mapping,
    &ett_ranap_RAB_TrCH_MappingItem,
    &ett_ranap_RAI,
    &ett_ranap_RAListofIdleModeUEs,
    &ett_ranap_NotEmptyRAListofIdleModeUEs,
    &ett_ranap_RAofIdleModeUEs,
    &ett_ranap_LAListofIdleModeUEs,
    &ett_ranap_RequestedMBMSIPMulticastAddressandAPNRequest,
    &ett_ranap_MBMSIPMulticastAddressandAPNlist,
    &ett_ranap_RequestedMulticastServiceList,
    &ett_ranap_Requested_RAB_Parameter_Values,
    &ett_ranap_Requested_RAB_Parameter_ExtendedMaxBitrateList,
    &ett_ranap_Requested_RAB_Parameter_ExtendedGuaranteedBitrateList,
    &ett_ranap_Requested_RAB_Parameter_MaxBitrateList,
    &ett_ranap_Requested_RAB_Parameter_GuaranteedBitrateList,
    &ett_ranap_RequestType,
    &ett_ranap_ResidualBitErrorRatio,
    &ett_ranap_RIM_Transfer,
    &ett_ranap_RIMRoutingAddress,
    &ett_ranap_RNCTraceInformation,
    &ett_ranap_RNSAPRelocationParameters,
    &ett_ranap_SAI,
    &ett_ranap_Shared_Network_Information,
    &ett_ranap_SDU_ErrorRatio,
    &ett_ranap_SDU_FormatInformationParameters,
    &ett_ranap_SDU_FormatInformationParameters_item,
    &ett_ranap_SDU_Parameters,
    &ett_ranap_SDU_Parameters_item,
    &ett_ranap_SNA_Access_Information,
    &ett_ranap_SourceCellID,
    &ett_ranap_SourceID,
    &ett_ranap_SourceRNC_ID,
    &ett_ranap_SourceRNC_ToTargetRNC_TransparentContainer,
    &ett_ranap_IRAT_Measurement_Configuration,
    &ett_ranap_IRATmeasurementParameters,
    &ett_ranap_EUTRANFrequencies,
    &ett_ranap_EUTRANFrequencies_item,
    &ett_ranap_SupportedRAB_ParameterBitrateList,
    &ett_ranap_SourceUTRANCellID,
    &ett_ranap_SRB_TrCH_Mapping,
    &ett_ranap_SRB_TrCH_MappingItem,
    &ett_ranap_SRVCC_Information,
    &ett_ranap_TAI,
    &ett_ranap_TargetID,
    &ett_ranap_TargetENB_ID,
    &ett_ranap_TargetRNC_ID,
    &ett_ranap_TargetRNC_ToSourceRNC_TransparentContainer,
    &ett_ranap_TemporaryUE_ID,
    &ett_ranap_TMGI,
    &ett_ranap_TraceInformation,
    &ett_ranap_TracePropagationParameters,
    &ett_ranap_TraceRecordingSessionInformation,
    &ett_ranap_TrCH_ID,
    &ett_ranap_TrCH_ID_List,
    &ett_ranap_UE_AggregateMaximumBitRate,
    &ett_ranap_UE_ID,
    &ett_ranap_UESBI_Iu,
    &ett_ranap_UPInformation,
    &ett_ranap_VelocityEstimate,
    &ett_ranap_HorizontalVelocity,
    &ett_ranap_HorizontalWithVerticalVelocity,
    &ett_ranap_HorizontalVelocityWithUncertainty,
    &ett_ranap_HorizontalWithVerticalVelocityAndUncertainty,
    &ett_ranap_HorizontalSpeedAndBearing,
    &ett_ranap_VerticalVelocity,
    &ett_ranap_Iu_ReleaseCommand,
    &ett_ranap_Iu_ReleaseComplete,
    &ett_ranap_RAB_DataVolumeReportItem,
    &ett_ranap_RAB_ReleasedItem_IuRelComp,
    &ett_ranap_RelocationRequired,
    &ett_ranap_RelocationCommand,
    &ett_ranap_RAB_RelocationReleaseItem,
    &ett_ranap_RAB_DataForwardingItem,
    &ett_ranap_RelocationPreparationFailure,
    &ett_ranap_RelocationRequest,
    &ett_ranap_RAB_SetupItem_RelocReq,
    &ett_ranap_UserPlaneInformation,
    &ett_ranap_CNMBMSLinkingInformation,
    &ett_ranap_JoinedMBMSBearerService_IEs,
    &ett_ranap_JoinedMBMSBearerService_IEs_item,
    &ett_ranap_RelocationRequestAcknowledge,
    &ett_ranap_RAB_SetupItem_RelocReqAck,
    &ett_ranap_RAB_FailedItem,
    &ett_ranap_RelocationFailure,
    &ett_ranap_RelocationCancel,
    &ett_ranap_RelocationCancelAcknowledge,
    &ett_ranap_SRNS_ContextRequest,
    &ett_ranap_RAB_DataForwardingItem_SRNS_CtxReq,
    &ett_ranap_SRNS_ContextResponse,
    &ett_ranap_RAB_ContextItem,
    &ett_ranap_RABs_ContextFailedtoTransferItem,
    &ett_ranap_SecurityModeCommand,
    &ett_ranap_SecurityModeComplete,
    &ett_ranap_SecurityModeReject,
    &ett_ranap_DataVolumeReportRequest,
    &ett_ranap_RAB_DataVolumeReportRequestItem,
    &ett_ranap_DataVolumeReport,
    &ett_ranap_RABs_failed_to_reportItem,
    &ett_ranap_Reset,
    &ett_ranap_ResetAcknowledge,
    &ett_ranap_ResetResource,
    &ett_ranap_ResetResourceItem,
    &ett_ranap_ResetResourceAcknowledge,
    &ett_ranap_ResetResourceAckItem,
    &ett_ranap_RAB_ReleaseRequest,
    &ett_ranap_RAB_ReleaseItem,
    &ett_ranap_Iu_ReleaseRequest,
    &ett_ranap_RelocationDetect,
    &ett_ranap_RelocationComplete,
    &ett_ranap_EnhancedRelocationCompleteRequest,
    &ett_ranap_RAB_SetupItem_EnhancedRelocCompleteReq,
    &ett_ranap_EnhancedRelocationCompleteResponse,
    &ett_ranap_RAB_SetupItem_EnhancedRelocCompleteRes,
    &ett_ranap_RAB_ToBeReleasedItem_EnhancedRelocCompleteRes,
    &ett_ranap_EnhancedRelocationCompleteFailure,
    &ett_ranap_EnhancedRelocationCompleteConfirm,
    &ett_ranap_Paging,
    &ett_ranap_CommonID,
    &ett_ranap_CN_InvokeTrace,
    &ett_ranap_CN_DeactivateTrace,
    &ett_ranap_LocationReportingControl,
    &ett_ranap_LocationReport,
    &ett_ranap_InitialUE_Message,
    &ett_ranap_DirectTransfer,
    &ett_ranap_Overload,
    &ett_ranap_ErrorIndication,
    &ett_ranap_SRNS_DataForwardCommand,
    &ett_ranap_ForwardSRNS_Context,
    &ett_ranap_RAB_AssignmentRequest,
    &ett_ranap_RAB_SetupOrModifyItemFirst,
    &ett_ranap_TransportLayerInformation,
    &ett_ranap_RAB_SetupOrModifyItemSecond,
    &ett_ranap_RAB_AssignmentResponse,
    &ett_ranap_RAB_SetupOrModifiedItem,
    &ett_ranap_RAB_ReleasedItem,
    &ett_ranap_DataVolumeList,
    &ett_ranap_DataVolumeList_item,
    &ett_ranap_RAB_QueuedItem,
    &ett_ranap_GERAN_Iumode_RAB_Failed_RABAssgntResponse_Item,
    &ett_ranap_PrivateMessage,
    &ett_ranap_RANAP_RelocationInformation,
    &ett_ranap_DirectTransferInformationItem_RANAP_RelocInf,
    &ett_ranap_RAB_ContextItem_RANAP_RelocInf,
    &ett_ranap_RANAP_EnhancedRelocationInformationRequest,
    &ett_ranap_RAB_SetupItem_EnhRelocInfoReq,
    &ett_ranap_TNLInformationEnhRelInfoReq,
    &ett_ranap_RANAP_EnhancedRelocationInformationResponse,
    &ett_ranap_RAB_SetupItem_EnhRelocInfoRes,
    &ett_ranap_RAB_FailedItem_EnhRelocInfoRes,
    &ett_ranap_TNLInformationEnhRelInfoRes,
    &ett_ranap_RAB_ModifyRequest,
    &ett_ranap_RAB_ModifyItem,
    &ett_ranap_LocationRelatedDataRequest,
    &ett_ranap_LocationRelatedDataResponse,
    &ett_ranap_LocationRelatedDataFailure,
    &ett_ranap_InformationTransferIndication,
    &ett_ranap_InformationTransferConfirmation,
    &ett_ranap_InformationTransferFailure,
    &ett_ranap_UESpecificInformationIndication,
    &ett_ranap_DirectInformationTransfer,
    &ett_ranap_UplinkInformationExchangeRequest,
    &ett_ranap_UplinkInformationExchangeResponse,
    &ett_ranap_UplinkInformationExchangeFailure,
    &ett_ranap_MBMSSessionStart,
    &ett_ranap_MBMSSynchronisationInformation,
    &ett_ranap_MBMSSessionStartResponse,
    &ett_ranap_MBMSSessionStartFailure,
    &ett_ranap_MBMSSessionUpdate,
    &ett_ranap_MBMSSessionUpdateResponse,
    &ett_ranap_MBMSSessionUpdateFailure,
    &ett_ranap_MBMSSessionStop,
    &ett_ranap_MBMSSessionStopResponse,
    &ett_ranap_MBMSUELinkingRequest,
    &ett_ranap_LeftMBMSBearerService_IEs,
    &ett_ranap_LeftMBMSBearerService_IEs_item,
    &ett_ranap_MBMSUELinkingResponse,
    &ett_ranap_UnsuccessfulLinking_IEs,
    &ett_ranap_UnsuccessfulLinking_IEs_item,
    &ett_ranap_MBMSRegistrationRequest,
    &ett_ranap_MBMSRegistrationResponse,
    &ett_ranap_MBMSRegistrationFailure,
    &ett_ranap_MBMSCNDe_RegistrationRequest,
    &ett_ranap_MBMSCNDe_RegistrationResponse,
    &ett_ranap_MBMSRABEstablishmentIndication,
    &ett_ranap_MBMSRABReleaseRequest,
    &ett_ranap_MBMSRABRelease,
    &ett_ranap_MBMSRABReleaseFailure,
    &ett_ranap_SRVCC_CSKeysRequest,
    &ett_ranap_SRVCC_CSKeysResponse,
    &ett_ranap_RANAP_PDU,
    &ett_ranap_InitiatingMessage,
    &ett_ranap_SuccessfulOutcome,
    &ett_ranap_UnsuccessfulOutcome,
    &ett_ranap_Outcome,

/*--- End of included file: packet-ranap-ettarr.c ---*/
#line 329 "../../asn1/ranap/packet-ranap-template.c"
  };


  /* Register protocol */
  proto_ranap = proto_register_protocol(PNAME, PSNAME, PFNAME);
  /* Register fields and subtrees */
  proto_register_field_array(proto_ranap, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));

  /* Register dissector */
  register_dissector("ranap", dissect_ranap, proto_ranap);

  /* Register dissector tables */
  ranap_ies_dissector_table = register_dissector_table("ranap.ies", "RANAP-PROTOCOL-IES", FT_UINT32, BASE_DEC);
  ranap_ies_p1_dissector_table = register_dissector_table("ranap.ies.pair.first", "RANAP-PROTOCOL-IES-PAIR FirstValue", FT_UINT32, BASE_DEC);
  ranap_ies_p2_dissector_table = register_dissector_table("ranap.ies.pair.second", "RANAP-PROTOCOL-IES-PAIR SecondValue", FT_UINT32, BASE_DEC);
  ranap_extension_dissector_table = register_dissector_table("ranap.extension", "RANAP-PROTOCOL-EXTENSION", FT_UINT32, BASE_DEC);
  ranap_proc_imsg_dissector_table = register_dissector_table("ranap.proc.imsg", "RANAP-ELEMENTARY-PROCEDURE InitiatingMessage", FT_UINT32, BASE_DEC);
  ranap_proc_sout_dissector_table = register_dissector_table("ranap.proc.sout", "RANAP-ELEMENTARY-PROCEDURE SuccessfulOutcome", FT_UINT32, BASE_DEC);
  ranap_proc_uout_dissector_table = register_dissector_table("ranap.proc.uout", "RANAP-ELEMENTARY-PROCEDURE UnsuccessfulOutcome", FT_UINT32, BASE_DEC);
  ranap_proc_out_dissector_table = register_dissector_table("ranap.proc.out", "RANAP-ELEMENTARY-PROCEDURE Outcome", FT_UINT32, BASE_DEC);

  nas_pdu_dissector_table = register_dissector_table("ranap.nas_pdu", "RANAP NAS PDU", FT_UINT8, BASE_DEC);

  ranap_module = prefs_register_protocol(proto_ranap, proto_reg_handoff_ranap);
  prefs_register_uint_preference(ranap_module, "sccp_ssn", "SCCP SSN for RANAP",
				 "The SCCP SubSystem Number for RANAP (default 142)", 10,
				 &global_ranap_sccp_ssn);
}


/*--- proto_reg_handoff_ranap ---------------------------------------*/
void
proto_reg_handoff_ranap(void)
{
	static gboolean initialized = FALSE;
	static dissector_handle_t ranap_handle;
	static gint local_ranap_sccp_ssn;

	if (!initialized) {
		ranap_handle = find_dissector("ranap");
		rrc_s_to_trnc_handle = find_dissector("rrc.s_to_trnc_cont");
		rrc_t_to_srnc_handle = find_dissector("rrc.t_to_srnc_cont");
		rrc_ho_to_utran_cmd = find_dissector("rrc.irat.ho_to_utran_cmd");
		initialized = TRUE;

/*--- Included file: packet-ranap-dis-tab.c ---*/
#line 1 "../../asn1/ranap/packet-ranap-dis-tab.c"
  dissector_add_uint("ranap.ies", id_Cause, new_create_dissector_handle(dissect_Cause_PDU, proto_ranap));
  dissector_add_uint("ranap.ies", id_RAB_DataVolumeReportList, new_create_dissector_handle(dissect_RAB_DataVolumeReportList_PDU, proto_ranap));
  dissector_add_uint("ranap.ies", id_RAB_ReleasedList_IuRelComp, new_create_dissector_handle(dissect_RAB_ReleasedList_IuRelComp_PDU, proto_ranap));
  dissector_add_uint("ranap.ies", id_CriticalityDiagnostics, new_create_dissector_handle(dissect_CriticalityDiagnostics_PDU, proto_ranap));
  dissector_add_uint("ranap.ies", id_RAB_DataVolumeReportItem, new_create_dissector_handle(dissect_RAB_DataVolumeReportItem_PDU, proto_ranap));
  dissector_add_uint("ranap.ies", id_RAB_ReleasedItem_IuRelComp, new_create_dissector_handle(dissect_RAB_ReleasedItem_IuRelComp_PDU, proto_ranap));
  dissector_add_uint("ranap.ies", id_RelocationType, new_create_dissector_handle(dissect_RelocationType_PDU, proto_ranap));
  dissector_add_uint("ranap.ies", id_SourceID, new_create_dissector_handle(dissect_SourceID_PDU, proto_ranap));
  dissector_add_uint("ranap.ies", id_Source_ToTarget_TransparentContainer, new_create_dissector_handle(dissect_ranap_SourceRNC_ToTargetRNC_TransparentContainer_PDU, proto_ranap));
  dissector_add_uint("ranap.ies", SPECIAL|id_Source_ToTarget_TransparentContainer, new_create_dissector_handle(dissect_Source_ToTarget_TransparentContainer_PDU, proto_ranap));
  dissector_add_uint("ranap.ies", id_TargetID, new_create_dissector_handle(dissect_TargetID_PDU, proto_ranap));
  dissector_add_uint("ranap.ies", id_Target_ToSource_TransparentContainer, new_create_dissector_handle(dissect_TargetRNC_ToSourceRNC_TransparentContainer_PDU, proto_ranap));
  dissector_add_uint("ranap.ies", SPECIAL|id_Target_ToSource_TransparentContainer, new_create_dissector_handle(dissect_Target_ToSource_TransparentContainer_PDU, proto_ranap));
  dissector_add_uint("ranap.ies", id_ClassmarkInformation2, new_create_dissector_handle(dissect_ClassmarkInformation2_PDU, proto_ranap));
  dissector_add_uint("ranap.ies", id_ClassmarkInformation3, new_create_dissector_handle(dissect_ClassmarkInformation3_PDU, proto_ranap));
  dissector_add_uint("ranap.ies", id_OldBSS_ToNewBSS_Information, new_create_dissector_handle(dissect_OldBSS_ToNewBSS_Information_PDU, proto_ranap));
  dissector_add_uint("ranap.ies", id_L3_Information, new_create_dissector_handle(dissect_L3_Information_PDU, proto_ranap));
  dissector_add_uint("ranap.ies", id_RAB_RelocationReleaseList, new_create_dissector_handle(dissect_RAB_RelocationReleaseList_PDU, proto_ranap));
  dissector_add_uint("ranap.ies", id_RAB_DataForwardingList, new_create_dissector_handle(dissect_RAB_DataForwardingList_PDU, proto_ranap));
  dissector_add_uint("ranap.ies", id_RAB_RelocationReleaseItem, new_create_dissector_handle(dissect_RAB_RelocationReleaseItem_PDU, proto_ranap));
  dissector_add_uint("ranap.ies", id_RAB_DataForwardingItem, new_create_dissector_handle(dissect_RAB_DataForwardingItem_PDU, proto_ranap));
  dissector_add_uint("ranap.ies", id_PermanentNAS_UE_ID, new_create_dissector_handle(dissect_PermanentNAS_UE_ID_PDU, proto_ranap));
  dissector_add_uint("ranap.ies", id_CN_DomainIndicator, new_create_dissector_handle(dissect_CN_DomainIndicator_PDU, proto_ranap));
  dissector_add_uint("ranap.ies", id_RAB_SetupList_RelocReq, new_create_dissector_handle(dissect_RAB_SetupList_RelocReq_PDU, proto_ranap));
  dissector_add_uint("ranap.ies", id_IntegrityProtectionInformation, new_create_dissector_handle(dissect_IntegrityProtectionInformation_PDU, proto_ranap));
  dissector_add_uint("ranap.ies", id_EncryptionInformation, new_create_dissector_handle(dissect_EncryptionInformation_PDU, proto_ranap));
  dissector_add_uint("ranap.ies", id_IuSigConId, new_create_dissector_handle(dissect_IuSignallingConnectionIdentifier_PDU, proto_ranap));
  dissector_add_uint("ranap.ies", id_DirectTransferInformationList_RANAP_RelocInf, new_create_dissector_handle(dissect_DirectTransferInformationList_RANAP_RelocInf_PDU, proto_ranap));
  dissector_add_uint("ranap.ies", id_DirectTransferInformationItem_RANAP_RelocInf, new_create_dissector_handle(dissect_DirectTransferInformationItem_RANAP_RelocInf_PDU, proto_ranap));
  dissector_add_uint("ranap.ies", id_RAB_SetupItem_RelocReq, new_create_dissector_handle(dissect_RAB_SetupItem_RelocReq_PDU, proto_ranap));
  dissector_add_uint("ranap.ies", id_RAB_SetupList_RelocReqAck, new_create_dissector_handle(dissect_RAB_SetupList_RelocReqAck_PDU, proto_ranap));
  dissector_add_uint("ranap.ies", id_RAB_FailedList, new_create_dissector_handle(dissect_RAB_FailedList_PDU, proto_ranap));
  dissector_add_uint("ranap.ies", id_ChosenIntegrityProtectionAlgorithm, new_create_dissector_handle(dissect_ChosenIntegrityProtectionAlgorithm_PDU, proto_ranap));
  dissector_add_uint("ranap.ies", id_ChosenEncryptionAlgorithm, new_create_dissector_handle(dissect_ChosenEncryptionAlgorithm_PDU, proto_ranap));
  dissector_add_uint("ranap.ies", id_RAB_SetupItem_RelocReqAck, new_create_dissector_handle(dissect_RAB_SetupItem_RelocReqAck_PDU, proto_ranap));
  dissector_add_uint("ranap.ies", id_RAB_FailedItem, new_create_dissector_handle(dissect_RAB_FailedItem_PDU, proto_ranap));
  dissector_add_uint("ranap.ies", id_RAB_DataForwardingList_SRNS_CtxReq, new_create_dissector_handle(dissect_RAB_DataForwardingList_SRNS_CtxReq_PDU, proto_ranap));
  dissector_add_uint("ranap.ies", id_RAB_DataForwardingItem_SRNS_CtxReq, new_create_dissector_handle(dissect_RAB_DataForwardingItem_SRNS_CtxReq_PDU, proto_ranap));
  dissector_add_uint("ranap.ies", id_RAB_ContextList, new_create_dissector_handle(dissect_RAB_ContextList_PDU, proto_ranap));
  dissector_add_uint("ranap.ies", id_RAB_ContextFailedtoTransferList, new_create_dissector_handle(dissect_RAB_ContextFailedtoTransferList_PDU, proto_ranap));
  dissector_add_uint("ranap.ies", id_RAB_ContextItem, new_create_dissector_handle(dissect_RAB_ContextItem_PDU, proto_ranap));
  dissector_add_uint("ranap.ies", id_RAB_ContextFailedtoTransferItem, new_create_dissector_handle(dissect_RABs_ContextFailedtoTransferItem_PDU, proto_ranap));
  dissector_add_uint("ranap.ies", id_KeyStatus, new_create_dissector_handle(dissect_KeyStatus_PDU, proto_ranap));
  dissector_add_uint("ranap.ies", id_RAB_DataVolumeReportRequestList, new_create_dissector_handle(dissect_RAB_DataVolumeReportRequestList_PDU, proto_ranap));
  dissector_add_uint("ranap.ies", id_RAB_DataVolumeReportRequestItem, new_create_dissector_handle(dissect_RAB_DataVolumeReportRequestItem_PDU, proto_ranap));
  dissector_add_uint("ranap.ies", id_RAB_FailedtoReportList, new_create_dissector_handle(dissect_RAB_FailedtoReportList_PDU, proto_ranap));
  dissector_add_uint("ranap.ies", id_RAB_FailedtoReportItem, new_create_dissector_handle(dissect_RABs_failed_to_reportItem_PDU, proto_ranap));
  dissector_add_uint("ranap.ies", id_GlobalRNC_ID, new_create_dissector_handle(dissect_GlobalRNC_ID_PDU, proto_ranap));
  dissector_add_uint("ranap.ies", IMSG|id_IuSigConIdList, new_create_dissector_handle(dissect_ResetResourceList_PDU, proto_ranap));
  dissector_add_uint("ranap.ies", IMSG|id_IuSigConIdItem, new_create_dissector_handle(dissect_ResetResourceItem_PDU, proto_ranap));
  dissector_add_uint("ranap.ies", SOUT|id_IuSigConIdList, new_create_dissector_handle(dissect_ResetResourceAckList_PDU, proto_ranap));
  dissector_add_uint("ranap.ies", SOUT|id_IuSigConIdItem, new_create_dissector_handle(dissect_ResetResourceAckItem_PDU, proto_ranap));
  dissector_add_uint("ranap.ies", id_RAB_ReleaseList, new_create_dissector_handle(dissect_RAB_ReleaseList_PDU, proto_ranap));
  dissector_add_uint("ranap.ies", id_RAB_ReleaseItem, new_create_dissector_handle(dissect_RAB_ReleaseItem_PDU, proto_ranap));
  dissector_add_uint("ranap.ies", id_TemporaryUE_ID, new_create_dissector_handle(dissect_TemporaryUE_ID_PDU, proto_ranap));
  dissector_add_uint("ranap.ies", id_PagingAreaID, new_create_dissector_handle(dissect_PagingAreaID_PDU, proto_ranap));
  dissector_add_uint("ranap.ies", id_PagingCause, new_create_dissector_handle(dissect_PagingCause_PDU, proto_ranap));
  dissector_add_uint("ranap.ies", id_NonSearchingIndication, new_create_dissector_handle(dissect_NonSearchingIndication_PDU, proto_ranap));
  dissector_add_uint("ranap.ies", id_DRX_CycleLengthCoefficient, new_create_dissector_handle(dissect_DRX_CycleLengthCoefficient_PDU, proto_ranap));
  dissector_add_uint("ranap.ies", id_TraceType, new_create_dissector_handle(dissect_TraceType_PDU, proto_ranap));
  dissector_add_uint("ranap.ies", id_TraceReference, new_create_dissector_handle(dissect_TraceReference_PDU, proto_ranap));
  dissector_add_uint("ranap.ies", id_TriggerID, new_create_dissector_handle(dissect_TriggerID_PDU, proto_ranap));
  dissector_add_uint("ranap.ies", id_UE_ID, new_create_dissector_handle(dissect_UE_ID_PDU, proto_ranap));
  dissector_add_uint("ranap.ies", id_OMC_ID, new_create_dissector_handle(dissect_OMC_ID_PDU, proto_ranap));
  dissector_add_uint("ranap.ies", id_RequestType, new_create_dissector_handle(dissect_RequestType_PDU, proto_ranap));
  dissector_add_uint("ranap.ies", id_AreaIdentity, new_create_dissector_handle(dissect_AreaIdentity_PDU, proto_ranap));
  dissector_add_uint("ranap.ies", id_LAI, new_create_dissector_handle(dissect_LAI_PDU, proto_ranap));
  dissector_add_uint("ranap.ies", id_RAC, new_create_dissector_handle(dissect_RAC_PDU, proto_ranap));
  dissector_add_uint("ranap.ies", id_SAI, new_create_dissector_handle(dissect_SAI_PDU, proto_ranap));
  dissector_add_uint("ranap.ies", id_NAS_PDU, new_create_dissector_handle(dissect_NAS_PDU_PDU, proto_ranap));
  dissector_add_uint("ranap.ies", id_SAPI, new_create_dissector_handle(dissect_SAPI_PDU, proto_ranap));
  dissector_add_uint("ranap.ies", id_RejectCauseValue, new_create_dissector_handle(dissect_RejectCauseValue_PDU, proto_ranap));
  dissector_add_uint("ranap.ies", id_NAS_SequenceNumber, new_create_dissector_handle(dissect_NAS_SequenceNumber_PDU, proto_ranap));
  dissector_add_uint("ranap.ies", id_NumberOfSteps, new_create_dissector_handle(dissect_NumberOfSteps_PDU, proto_ranap));
  dissector_add_uint("ranap.ies", id_RAB_SetupOrModifyList, new_create_dissector_handle(dissect_RAB_SetupOrModifyList_PDU, proto_ranap));
  dissector_add_uint("ranap.ies", id_RAB_SetupOrModifiedList, new_create_dissector_handle(dissect_RAB_SetupOrModifiedList_PDU, proto_ranap));
  dissector_add_uint("ranap.ies", id_RAB_ReleasedList, new_create_dissector_handle(dissect_RAB_ReleasedList_PDU, proto_ranap));
  dissector_add_uint("ranap.ies", id_RAB_QueuedList, new_create_dissector_handle(dissect_RAB_QueuedList_PDU, proto_ranap));
  dissector_add_uint("ranap.ies", id_RAB_ReleaseFailedList, new_create_dissector_handle(dissect_RAB_ReleaseFailedList_PDU, proto_ranap));
  dissector_add_uint("ranap.ies", id_RAB_SetupOrModifiedItem, new_create_dissector_handle(dissect_RAB_SetupOrModifiedItem_PDU, proto_ranap));
  dissector_add_uint("ranap.ies", id_RAB_ReleasedItem, new_create_dissector_handle(dissect_RAB_ReleasedItem_PDU, proto_ranap));
  dissector_add_uint("ranap.ies", id_RAB_QueuedItem, new_create_dissector_handle(dissect_RAB_QueuedItem_PDU, proto_ranap));
  dissector_add_uint("ranap.ies", id_GERAN_Iumode_RAB_Failed_RABAssgntResponse_Item, new_create_dissector_handle(dissect_GERAN_Iumode_RAB_Failed_RABAssgntResponse_Item_PDU, proto_ranap));
  dissector_add_uint("ranap.ies", id_RAB_ContextList_RANAP_RelocInf, new_create_dissector_handle(dissect_RAB_ContextList_RANAP_RelocInf_PDU, proto_ranap));
  dissector_add_uint("ranap.ies", id_RAB_ContextItem_RANAP_RelocInf, new_create_dissector_handle(dissect_RAB_ContextItem_RANAP_RelocInf_PDU, proto_ranap));
  dissector_add_uint("ranap.ies", id_RAB_ModifyList, new_create_dissector_handle(dissect_RAB_ModifyList_PDU, proto_ranap));
  dissector_add_uint("ranap.ies", id_RAB_ModifyItem, new_create_dissector_handle(dissect_RAB_ModifyItem_PDU, proto_ranap));
  dissector_add_uint("ranap.ies", id_LocationRelatedDataRequestType, new_create_dissector_handle(dissect_LocationRelatedDataRequestType_PDU, proto_ranap));
  dissector_add_uint("ranap.ies", id_BroadcastAssistanceDataDecipheringKeys, new_create_dissector_handle(dissect_BroadcastAssistanceDataDecipheringKeys_PDU, proto_ranap));
  dissector_add_uint("ranap.ies", id_InformationTransferID, new_create_dissector_handle(dissect_InformationTransferID_PDU, proto_ranap));
  dissector_add_uint("ranap.ies", id_ProvidedData, new_create_dissector_handle(dissect_ProvidedData_PDU, proto_ranap));
  dissector_add_uint("ranap.ies", id_GlobalCN_ID, new_create_dissector_handle(dissect_GlobalCN_ID_PDU, proto_ranap));
  dissector_add_uint("ranap.ies", id_UESBI_Iu, new_create_dissector_handle(dissect_UESBI_Iu_PDU, proto_ranap));
  dissector_add_uint("ranap.ies", id_InterSystemInformationTransferType, new_create_dissector_handle(dissect_InterSystemInformationTransferType_PDU, proto_ranap));
  dissector_add_uint("ranap.ies", id_InformationExchangeID, new_create_dissector_handle(dissect_InformationExchangeID_PDU, proto_ranap));
  dissector_add_uint("ranap.ies", id_InformationExchangeType, new_create_dissector_handle(dissect_InformationExchangeType_PDU, proto_ranap));
  dissector_add_uint("ranap.ies", id_InformationTransferType, new_create_dissector_handle(dissect_InformationTransferType_PDU, proto_ranap));
  dissector_add_uint("ranap.ies", id_InformationRequestType, new_create_dissector_handle(dissect_InformationRequestType_PDU, proto_ranap));
  dissector_add_uint("ranap.ies", id_InformationRequested, new_create_dissector_handle(dissect_InformationRequested_PDU, proto_ranap));
  dissector_add_uint("ranap.ies", id_TMGI, new_create_dissector_handle(dissect_TMGI_PDU, proto_ranap));
  dissector_add_uint("ranap.ies", id_MBMSSessionIdentity, new_create_dissector_handle(dissect_MBMSSessionIdentity_PDU, proto_ranap));
  dissector_add_uint("ranap.ies", id_MBMSBearerServiceType, new_create_dissector_handle(dissect_MBMSBearerServiceType_PDU, proto_ranap));
  dissector_add_uint("ranap.ies", id_RAB_Parameters, new_create_dissector_handle(dissect_RAB_Parameters_PDU, proto_ranap));
  dissector_add_uint("ranap.ies", id_PDP_TypeInformation, new_create_dissector_handle(dissect_PDP_TypeInformation_PDU, proto_ranap));
  dissector_add_uint("ranap.ies", id_MBMSSessionDuration, new_create_dissector_handle(dissect_MBMSSessionDuration_PDU, proto_ranap));
  dissector_add_uint("ranap.ies", id_MBMSServiceArea, new_create_dissector_handle(dissect_MBMSServiceArea_PDU, proto_ranap));
  dissector_add_uint("ranap.ies", id_FrequenceLayerConvergenceFlag, new_create_dissector_handle(dissect_FrequenceLayerConvergenceFlag_PDU, proto_ranap));
  dissector_add_uint("ranap.ies", id_RAListofIdleModeUEs, new_create_dissector_handle(dissect_RAListofIdleModeUEs_PDU, proto_ranap));
  dissector_add_uint("ranap.ies", id_MBMSSessionRepetitionNumber, new_create_dissector_handle(dissect_MBMSSessionRepetitionNumber_PDU, proto_ranap));
  dissector_add_uint("ranap.ies", id_TimeToMBMSDataTransfer, new_create_dissector_handle(dissect_TimeToMBMSDataTransfer_PDU, proto_ranap));
  dissector_add_uint("ranap.ies", id_TransportLayerInformation, new_create_dissector_handle(dissect_TransportLayerInformation_PDU, proto_ranap));
  dissector_add_uint("ranap.ies", id_SessionUpdateID, new_create_dissector_handle(dissect_SessionUpdateID_PDU, proto_ranap));
  dissector_add_uint("ranap.ies", id_DeltaRAListofIdleModeUEs, new_create_dissector_handle(dissect_DeltaRAListofIdleModeUEs_PDU, proto_ranap));
  dissector_add_uint("ranap.ies", id_MBMSCNDe_Registration, new_create_dissector_handle(dissect_MBMSCNDe_Registration_PDU, proto_ranap));
  dissector_add_uint("ranap.ies", id_JoinedMBMSBearerServicesList, new_create_dissector_handle(dissect_JoinedMBMSBearerService_IEs_PDU, proto_ranap));
  dissector_add_uint("ranap.ies", id_LeftMBMSBearerServicesList, new_create_dissector_handle(dissect_LeftMBMSBearerService_IEs_PDU, proto_ranap));
  dissector_add_uint("ranap.ies", id_UnsuccessfulLinkingList, new_create_dissector_handle(dissect_UnsuccessfulLinking_IEs_PDU, proto_ranap));
  dissector_add_uint("ranap.ies", id_MBMSRegistrationRequestType, new_create_dissector_handle(dissect_MBMSRegistrationRequestType_PDU, proto_ranap));
  dissector_add_uint("ranap.ies", id_IPMulticastAddress, new_create_dissector_handle(dissect_IPMulticastAddress_PDU, proto_ranap));
  dissector_add_uint("ranap.ies", id_APN, new_create_dissector_handle(dissect_APN_PDU, proto_ranap));
  dissector_add_uint("ranap.ies", id_RAB_SetupList_EnhancedRelocCompleteReq, new_create_dissector_handle(dissect_RAB_SetupList_EnhancedRelocCompleteReq_PDU, proto_ranap));
  dissector_add_uint("ranap.ies", id_RAB_SetupItem_EnhancedRelocCompleteReq, new_create_dissector_handle(dissect_RAB_SetupItem_EnhancedRelocCompleteReq_PDU, proto_ranap));
  dissector_add_uint("ranap.ies", id_RAB_SetupList_EnhancedRelocCompleteRes, new_create_dissector_handle(dissect_RAB_SetupList_EnhancedRelocCompleteRes_PDU, proto_ranap));
  dissector_add_uint("ranap.ies", id_RAB_SetupItem_EnhancedRelocCompleteRes, new_create_dissector_handle(dissect_RAB_SetupItem_EnhancedRelocCompleteRes_PDU, proto_ranap));
  dissector_add_uint("ranap.ies", id_RAB_SetupList_EnhRelocInfoReq, new_create_dissector_handle(dissect_RAB_SetupList_EnhRelocInfoReq_PDU, proto_ranap));
  dissector_add_uint("ranap.ies", id_RAB_SetupItem_EnhRelocInfoReq, new_create_dissector_handle(dissect_RAB_SetupItem_EnhRelocInfoReq_PDU, proto_ranap));
  dissector_add_uint("ranap.ies", id_RAB_SetupList_EnhRelocInfoRes, new_create_dissector_handle(dissect_RAB_SetupList_EnhRelocInfoRes_PDU, proto_ranap));
  dissector_add_uint("ranap.ies", id_RAB_SetupItem_EnhRelocInfoRes, new_create_dissector_handle(dissect_RAB_SetupItem_EnhRelocInfoRes_PDU, proto_ranap));
  dissector_add_uint("ranap.ies", id_OldIuSigConId, new_create_dissector_handle(dissect_IuSignallingConnectionIdentifier_PDU, proto_ranap));
  dissector_add_uint("ranap.ies", id_RAB_FailedList_EnhRelocInfoRes, new_create_dissector_handle(dissect_RAB_FailedList_EnhRelocInfoRes_PDU, proto_ranap));
  dissector_add_uint("ranap.ies", id_RAB_FailedItem_EnhRelocInfoRes, new_create_dissector_handle(dissect_RAB_FailedItem_EnhRelocInfoRes_PDU, proto_ranap));
  dissector_add_uint("ranap.ies", id_OldIuSigConIdCS, new_create_dissector_handle(dissect_IuSignallingConnectionIdentifier_PDU, proto_ranap));
  dissector_add_uint("ranap.ies", id_OldIuSigConIdPS, new_create_dissector_handle(dissect_IuSignallingConnectionIdentifier_PDU, proto_ranap));
  dissector_add_uint("ranap.ies", id_GlobalCN_IDCS, new_create_dissector_handle(dissect_GlobalCN_ID_PDU, proto_ranap));
  dissector_add_uint("ranap.ies", id_RAB_ToBeReleasedItem_EnhancedRelocCompleteRes, new_create_dissector_handle(dissect_RAB_ToBeReleasedItem_EnhancedRelocCompleteRes_PDU, proto_ranap));
  dissector_add_uint("ranap.ies", id_RAB_ToBeReleasedList_EnhancedRelocCompleteRes, new_create_dissector_handle(dissect_RAB_ToBeReleasedList_EnhancedRelocCompleteRes_PDU, proto_ranap));
  dissector_add_uint("ranap.ies", id_Relocation_TargetRNC_ID, new_create_dissector_handle(dissect_GlobalRNC_ID_PDU, proto_ranap));
  dissector_add_uint("ranap.ies", id_Relocation_TargetExtendedRNC_ID, new_create_dissector_handle(dissect_ExtendedRNC_ID_PDU, proto_ranap));
  dissector_add_uint("ranap.ies", id_Alt_RAB_Parameter_SupportedGuaranteedBitrateInf, new_create_dissector_handle(dissect_Alt_RAB_Parameter_SupportedGuaranteedBitrateInf_PDU, proto_ranap));
  dissector_add_uint("ranap.ies", id_Alt_RAB_Parameter_SupportedMaxBitrateInf, new_create_dissector_handle(dissect_Alt_RAB_Parameter_SupportedMaxBitrateInf_PDU, proto_ranap));
  dissector_add_uint("ranap.ies", id_Relocation_SourceRNC_ID, new_create_dissector_handle(dissect_GlobalRNC_ID_PDU, proto_ranap));
  dissector_add_uint("ranap.ies", id_Relocation_SourceExtendedRNC_ID, new_create_dissector_handle(dissect_ExtendedRNC_ID_PDU, proto_ranap));
  dissector_add_uint("ranap.ies", id_EncryptionKey, new_create_dissector_handle(dissect_EncryptionKey_PDU, proto_ranap));
  dissector_add_uint("ranap.ies", id_IntegrityProtectionKey, new_create_dissector_handle(dissect_IntegrityProtectionKey_PDU, proto_ranap));
  dissector_add_uint("ranap.ies", id_SRVCC_Information, new_create_dissector_handle(dissect_SRVCC_Information_PDU, proto_ranap));
  dissector_add_uint("ranap.ies", id_GlobalCN_IDPS, new_create_dissector_handle(dissect_GlobalCN_ID_PDU, proto_ranap));
  dissector_add_uint("ranap.ies.pair.first", id_RAB_SetupOrModifyItem, new_create_dissector_handle(dissect_RAB_SetupOrModifyItemFirst_PDU, proto_ranap));
  dissector_add_uint("ranap.ies.pair.second", id_RAB_SetupOrModifyItem, new_create_dissector_handle(dissect_RAB_SetupOrModifyItemSecond_PDU, proto_ranap));
  dissector_add_uint("ranap.extension", id_AlternativeRABConfiguration, new_create_dissector_handle(dissect_RAB_Parameters_PDU, proto_ranap));
  dissector_add_uint("ranap.extension", id_Alt_RAB_Parameter_ExtendedGuaranteedBitrateInf, new_create_dissector_handle(dissect_Alt_RAB_Parameter_ExtendedGuaranteedBitrateInf_PDU, proto_ranap));
  dissector_add_uint("ranap.extension", id_Alt_RAB_Parameter_ExtendedMaxBitrateInf, new_create_dissector_handle(dissect_Alt_RAB_Parameter_ExtendedMaxBitrateInf_PDU, proto_ranap));
  dissector_add_uint("ranap.extension", id_Ass_RAB_Parameter_ExtendedGuaranteedBitrateList, new_create_dissector_handle(dissect_Ass_RAB_Parameter_ExtendedGuaranteedBitrateList_PDU, proto_ranap));
  dissector_add_uint("ranap.extension", id_Ass_RAB_Parameter_ExtendedMaxBitrateList, new_create_dissector_handle(dissect_Ass_RAB_Parameter_ExtendedMaxBitrateList_PDU, proto_ranap));
  dissector_add_uint("ranap.extension", id_MessageStructure, new_create_dissector_handle(dissect_MessageStructure_PDU, proto_ranap));
  dissector_add_uint("ranap.extension", id_TypeOfError, new_create_dissector_handle(dissect_TypeOfError_PDU, proto_ranap));
  dissector_add_uint("ranap.extension", id_RAC, new_create_dissector_handle(dissect_RAC_PDU, proto_ranap));
  dissector_add_uint("ranap.extension", id_newLAListofIdleModeUEs, new_create_dissector_handle(dissect_LAListofIdleModeUEs_PDU, proto_ranap));
  dissector_add_uint("ranap.extension", id_LAListwithNoIdleModeUEsAnyMore, new_create_dissector_handle(dissect_LAListofIdleModeUEs_PDU, proto_ranap));
  dissector_add_uint("ranap.extension", id_GANSS_PositioningDataSet, new_create_dissector_handle(dissect_GANSS_PositioningDataSet_PDU, proto_ranap));
  dissector_add_uint("ranap.extension", id_SignallingIndication, new_create_dissector_handle(dissect_SignallingIndication_PDU, proto_ranap));
  dissector_add_uint("ranap.extension", id_RAB_Parameter_ExtendedGuaranteedBitrateList, new_create_dissector_handle(dissect_RAB_Parameter_ExtendedGuaranteedBitrateList_PDU, proto_ranap));
  dissector_add_uint("ranap.extension", id_RAB_Parameter_ExtendedMaxBitrateList, new_create_dissector_handle(dissect_RAB_Parameter_ExtendedMaxBitrateList_PDU, proto_ranap));
  dissector_add_uint("ranap.extension", id_CN_DomainIndicator, new_create_dissector_handle(dissect_CN_DomainIndicator_PDU, proto_ranap));
  dissector_add_uint("ranap.extension", id_LAofIdleModeUEs, new_create_dissector_handle(dissect_LAListofIdleModeUEs_PDU, proto_ranap));
  dissector_add_uint("ranap.extension", id_AlternativeRABConfigurationRequest, new_create_dissector_handle(dissect_AlternativeRABConfigurationRequest_PDU, proto_ranap));
  dissector_add_uint("ranap.extension", id_Requested_RAB_Parameter_ExtendedMaxBitrateList, new_create_dissector_handle(dissect_Requested_RAB_Parameter_ExtendedMaxBitrateList_PDU, proto_ranap));
  dissector_add_uint("ranap.extension", id_Requested_RAB_Parameter_ExtendedGuaranteedBitrateList, new_create_dissector_handle(dissect_Requested_RAB_Parameter_ExtendedGuaranteedBitrateList_PDU, proto_ranap));
  dissector_add_uint("ranap.extension", id_ExtendedRNC_ID, new_create_dissector_handle(dissect_ExtendedRNC_ID_PDU, proto_ranap));
  dissector_add_uint("ranap.extension", id_SRB_TrCH_Mapping, new_create_dissector_handle(dissect_SRB_TrCH_Mapping_PDU, proto_ranap));
  dissector_add_uint("ranap.extension", id_CellLoadInformationGroup, new_create_dissector_handle(dissect_CellLoadInformationGroup_PDU, proto_ranap));
  dissector_add_uint("ranap.extension", id_TraceRecordingSessionInformation, new_create_dissector_handle(dissect_TraceRecordingSessionInformation_PDU, proto_ranap));
  dissector_add_uint("ranap.extension", id_MBMSLinkingInformation, new_create_dissector_handle(dissect_MBMSLinkingInformation_PDU, proto_ranap));
  dissector_add_uint("ranap.extension", id_hS_DSCH_MAC_d_Flow_ID, new_create_dissector_handle(dissect_HS_DSCH_MAC_d_Flow_ID_PDU, proto_ranap));
  dissector_add_uint("ranap.extension", id_E_DCH_MAC_d_Flow_ID, new_create_dissector_handle(dissect_E_DCH_MAC_d_Flow_ID_PDU, proto_ranap));
  dissector_add_uint("ranap.extension", id_GERAN_Classmark, new_create_dissector_handle(dissect_GERAN_Classmark_PDU, proto_ranap));
  dissector_add_uint("ranap.extension", id_SourceBSS_ToTargetBSS_TransparentContainer, new_create_dissector_handle(dissect_SourceBSS_ToTargetBSS_TransparentContainer_PDU, proto_ranap));
  dissector_add_uint("ranap.extension", id_TransportLayerAddress, new_create_dissector_handle(dissect_TransportLayerAddress_PDU, proto_ranap));
  dissector_add_uint("ranap.extension", id_IuTransportAssociation, new_create_dissector_handle(dissect_IuTransportAssociation_PDU, proto_ranap));
  dissector_add_uint("ranap.extension", id_InterSystemInformation_TransparentContainer, new_create_dissector_handle(dissect_InterSystemInformation_TransparentContainer_PDU, proto_ranap));
  dissector_add_uint("ranap.extension", id_TargetBSS_ToSourceBSS_TransparentContainer, new_create_dissector_handle(dissect_TargetBSS_ToSourceBSS_TransparentContainer_PDU, proto_ranap));
  dissector_add_uint("ranap.extension", id_Alt_RAB_Parameters, new_create_dissector_handle(dissect_Alt_RAB_Parameters_PDU, proto_ranap));
  dissector_add_uint("ranap.extension", id_GERAN_BSC_Container, new_create_dissector_handle(dissect_GERAN_BSC_Container_PDU, proto_ranap));
  dissector_add_uint("ranap.extension", id_GlobalCN_ID, new_create_dissector_handle(dissect_GlobalCN_ID_PDU, proto_ranap));
  dissector_add_uint("ranap.extension", id_SNA_Access_Information, new_create_dissector_handle(dissect_SNA_Access_Information_PDU, proto_ranap));
  dissector_add_uint("ranap.extension", id_UESBI_Iu, new_create_dissector_handle(dissect_UESBI_Iu_PDU, proto_ranap));
  dissector_add_uint("ranap.extension", id_SelectedPLMN_ID, new_create_dissector_handle(dissect_PLMNidentity_PDU, proto_ranap));
  dissector_add_uint("ranap.extension", id_CNMBMSLinkingInformation, new_create_dissector_handle(dissect_CNMBMSLinkingInformation_PDU, proto_ranap));
  dissector_add_uint("ranap.extension", id_Ass_RAB_Parameters, new_create_dissector_handle(dissect_Ass_RAB_Parameters_PDU, proto_ranap));
  dissector_add_uint("ranap.extension", id_NewBSS_To_OldBSS_Information, new_create_dissector_handle(dissect_NewBSS_To_OldBSS_Information_PDU, proto_ranap));
  dissector_add_uint("ranap.extension", id_RAT_Type, new_create_dissector_handle(dissect_RAT_Type_PDU, proto_ranap));
  dissector_add_uint("ranap.extension", id_TracePropagationParameters, new_create_dissector_handle(dissect_TracePropagationParameters_PDU, proto_ranap));
  dissector_add_uint("ranap.extension", id_VerticalAccuracyCode, new_create_dissector_handle(dissect_VerticalAccuracyCode_PDU, proto_ranap));
  dissector_add_uint("ranap.extension", id_ResponseTime, new_create_dissector_handle(dissect_ResponseTime_PDU, proto_ranap));
  dissector_add_uint("ranap.extension", id_PositioningPriority, new_create_dissector_handle(dissect_PositioningPriority_PDU, proto_ranap));
  dissector_add_uint("ranap.extension", id_ClientType, new_create_dissector_handle(dissect_ClientType_PDU, proto_ranap));
  dissector_add_uint("ranap.extension", id_IncludeVelocity, new_create_dissector_handle(dissect_IncludeVelocity_PDU, proto_ranap));
  dissector_add_uint("ranap.extension", id_PeriodicLocationInfo, new_create_dissector_handle(dissect_PeriodicLocationInfo_PDU, proto_ranap));
  dissector_add_uint("ranap.extension", id_LastKnownServiceArea, new_create_dissector_handle(dissect_LastKnownServiceArea_PDU, proto_ranap));
  dissector_add_uint("ranap.extension", id_PositionData, new_create_dissector_handle(dissect_PositionData_PDU, proto_ranap));
  dissector_add_uint("ranap.extension", id_PositionDataSpecificToGERANIuMode, new_create_dissector_handle(dissect_PositionDataSpecificToGERANIuMode_PDU, proto_ranap));
  dissector_add_uint("ranap.extension", id_AccuracyFulfilmentIndicator, new_create_dissector_handle(dissect_AccuracyFulfilmentIndicator_PDU, proto_ranap));
  dissector_add_uint("ranap.extension", id_VelocityEstimate, new_create_dissector_handle(dissect_VelocityEstimate_PDU, proto_ranap));
  dissector_add_uint("ranap.extension", id_PermanentNAS_UE_ID, new_create_dissector_handle(dissect_PermanentNAS_UE_ID_PDU, proto_ranap));
  dissector_add_uint("ranap.extension", id_NAS_SequenceNumber, new_create_dissector_handle(dissect_NAS_SequenceNumber_PDU, proto_ranap));
  dissector_add_uint("ranap.extension", id_RedirectAttemptFlag, new_create_dissector_handle(dissect_RedirectAttemptFlag_PDU, proto_ranap));
  dissector_add_uint("ranap.extension", id_RedirectionIndication, new_create_dissector_handle(dissect_RedirectionIndication_PDU, proto_ranap));
  dissector_add_uint("ranap.extension", id_RedirectionCompleted, new_create_dissector_handle(dissect_RedirectionCompleted_PDU, proto_ranap));
  dissector_add_uint("ranap.extension", id_SourceRNC_PDCP_context_info, new_create_dissector_handle(dissect_RRC_Container_PDU, proto_ranap));
  dissector_add_uint("ranap.extension", id_GERAN_Iumode_RAB_FailedList_RABAssgntResponse, new_create_dissector_handle(dissect_GERAN_Iumode_RAB_FailedList_RABAssgntResponse_PDU, proto_ranap));
  dissector_add_uint("ranap.extension", id_LocationRelatedDataRequestTypeSpecificToGERANIuMode, new_create_dissector_handle(dissect_LocationRelatedDataRequestTypeSpecificToGERANIuMode_PDU, proto_ranap));
  dissector_add_uint("ranap.extension", id_RequestedGANSSAssistanceData, new_create_dissector_handle(dissect_RequestedGANSSAssistanceData_PDU, proto_ranap));
  dissector_add_uint("ranap.extension", id_CriticalityDiagnostics, new_create_dissector_handle(dissect_CriticalityDiagnostics_PDU, proto_ranap));
  dissector_add_uint("ranap.extension", id_MBMSCountingInformation, new_create_dissector_handle(dissect_MBMSCountingInformation_PDU, proto_ranap));
  dissector_add_uint("ranap.extension", id_UE_History_Information, new_create_dissector_handle(dissect_UE_History_Information_PDU, proto_ranap));
  dissector_add_uint("ranap.extension", id_MBMSSynchronisationInformation, new_create_dissector_handle(dissect_MBMSSynchronisationInformation_PDU, proto_ranap));
  dissector_add_uint("ranap.extension", id_SubscriberProfileIDforRFP, new_create_dissector_handle(dissect_SubscriberProfileIDforRFP_PDU, proto_ranap));
  dissector_add_uint("ranap.extension", id_CSG_Id, new_create_dissector_handle(dissect_CSG_Id_PDU, proto_ranap));
  dissector_add_uint("ranap.extension", id_Ass_RAB_Parameter_SupportedGuaranteedBitrateList, new_create_dissector_handle(dissect_SupportedRAB_ParameterBitrateList_PDU, proto_ranap));
  dissector_add_uint("ranap.extension", id_Ass_RAB_Parameter_SupportedMaxBitrateList, new_create_dissector_handle(dissect_SupportedRAB_ParameterBitrateList_PDU, proto_ranap));
  dissector_add_uint("ranap.extension", id_RAB_Parameter_SupportedGuaranteedBitrateList, new_create_dissector_handle(dissect_SupportedRAB_ParameterBitrateList_PDU, proto_ranap));
  dissector_add_uint("ranap.extension", id_RAB_Parameter_SupportedMaxBitrateList, new_create_dissector_handle(dissect_SupportedRAB_ParameterBitrateList_PDU, proto_ranap));
  dissector_add_uint("ranap.extension", id_Requested_RAB_Parameter_SupportedMaxBitrateList, new_create_dissector_handle(dissect_SupportedRAB_ParameterBitrateList_PDU, proto_ranap));
  dissector_add_uint("ranap.extension", id_Requested_RAB_Parameter_SupportedGuaranteedBitrateList, new_create_dissector_handle(dissect_SupportedRAB_ParameterBitrateList_PDU, proto_ranap));
  dissector_add_uint("ranap.extension", id_SRVCC_HO_Indication, new_create_dissector_handle(dissect_SRVCC_HO_Indication_PDU, proto_ranap));
  dissector_add_uint("ranap.extension", id_SRVCC_Operation_Possible, new_create_dissector_handle(dissect_SRVCC_Operation_Possible_PDU, proto_ranap));
  dissector_add_uint("ranap.extension", id_CSG_Id_List, new_create_dissector_handle(dissect_CSG_Id_List_PDU, proto_ranap));
  dissector_add_uint("ranap.extension", id_PSRABtobeReplaced, new_create_dissector_handle(dissect_RAB_ID_PDU, proto_ranap));
  dissector_add_uint("ranap.extension", id_E_UTRAN_Service_Handover, new_create_dissector_handle(dissect_E_UTRAN_Service_Handover_PDU, proto_ranap));
  dissector_add_uint("ranap.extension", id_UE_AggregateMaximumBitRate, new_create_dissector_handle(dissect_UE_AggregateMaximumBitRate_PDU, proto_ranap));
  dissector_add_uint("ranap.extension", id_CSG_Membership_Status, new_create_dissector_handle(dissect_CSG_Membership_Status_PDU, proto_ranap));
  dissector_add_uint("ranap.extension", id_Cell_Access_Mode, new_create_dissector_handle(dissect_Cell_Access_Mode_PDU, proto_ranap));
  dissector_add_uint("ranap.extension", id_IP_Source_Address, new_create_dissector_handle(dissect_IPMulticastAddress_PDU, proto_ranap));
  dissector_add_uint("ranap.extension", id_CSFB_Information, new_create_dissector_handle(dissect_CSFB_Information_PDU, proto_ranap));
  dissector_add_uint("ranap.extension", id_PDP_TypeInformation_extension, new_create_dissector_handle(dissect_PDP_TypeInformation_extension_PDU, proto_ranap));
  dissector_add_uint("ranap.extension", id_MSISDN, new_create_dissector_handle(dissect_MSISDN_PDU, proto_ranap));
  dissector_add_uint("ranap.extension", id_Offload_RAB_Parameters, new_create_dissector_handle(dissect_Offload_RAB_Parameters_PDU, proto_ranap));
  dissector_add_uint("ranap.extension", id_LGW_TransportLayerAddress, new_create_dissector_handle(dissect_TransportLayerAddress_PDU, proto_ranap));
  dissector_add_uint("ranap.extension", id_Correlation_ID, new_create_dissector_handle(dissect_Correlation_ID_PDU, proto_ranap));
  dissector_add_uint("ranap.extension", id_IRAT_Measurement_Configuration, new_create_dissector_handle(dissect_IRAT_Measurement_Configuration_PDU, proto_ranap));
  dissector_add_uint("ranap.extension", id_MDT_Configuration, new_create_dissector_handle(dissect_MDT_Configuration_PDU, proto_ranap));
  dissector_add_uint("ranap.extension", id_Priority_Class_Indicator, new_create_dissector_handle(dissect_Priority_Class_Indicator_PDU, proto_ranap));
  dissector_add_uint("ranap.extension", id_RNSAPRelocationParameters, new_create_dissector_handle(dissect_RNSAPRelocationParameters_PDU, proto_ranap));
  dissector_add_uint("ranap.extension", id_RABParametersList, new_create_dissector_handle(dissect_RABParametersList_PDU, proto_ranap));
  dissector_add_uint("ranap.extension", id_Management_Based_MDT_Allowed, new_create_dissector_handle(dissect_Management_Based_MDT_Allowed_PDU, proto_ranap));
  dissector_add_uint("ranap.proc.imsg", id_Iu_Release, new_create_dissector_handle(dissect_Iu_ReleaseCommand_PDU, proto_ranap));
  dissector_add_uint("ranap.proc.sout", id_Iu_Release, new_create_dissector_handle(dissect_Iu_ReleaseComplete_PDU, proto_ranap));
  dissector_add_uint("ranap.proc.imsg", id_RelocationPreparation, new_create_dissector_handle(dissect_RelocationRequired_PDU, proto_ranap));
  dissector_add_uint("ranap.proc.sout", id_RelocationPreparation, new_create_dissector_handle(dissect_RelocationCommand_PDU, proto_ranap));
  dissector_add_uint("ranap.proc.uout", id_RelocationPreparation, new_create_dissector_handle(dissect_RelocationPreparationFailure_PDU, proto_ranap));
  dissector_add_uint("ranap.proc.imsg", id_RelocationResourceAllocation, new_create_dissector_handle(dissect_RelocationRequest_PDU, proto_ranap));
  dissector_add_uint("ranap.proc.sout", id_RelocationResourceAllocation, new_create_dissector_handle(dissect_RelocationRequestAcknowledge_PDU, proto_ranap));
  dissector_add_uint("ranap.proc.uout", id_RelocationResourceAllocation, new_create_dissector_handle(dissect_RelocationFailure_PDU, proto_ranap));
  dissector_add_uint("ranap.proc.imsg", id_RelocationCancel, new_create_dissector_handle(dissect_RelocationCancel_PDU, proto_ranap));
  dissector_add_uint("ranap.proc.sout", id_RelocationCancel, new_create_dissector_handle(dissect_RelocationCancelAcknowledge_PDU, proto_ranap));
  dissector_add_uint("ranap.proc.imsg", id_SRNS_ContextTransfer, new_create_dissector_handle(dissect_SRNS_ContextRequest_PDU, proto_ranap));
  dissector_add_uint("ranap.proc.sout", id_SRNS_ContextTransfer, new_create_dissector_handle(dissect_SRNS_ContextResponse_PDU, proto_ranap));
  dissector_add_uint("ranap.proc.imsg", id_SecurityModeControl, new_create_dissector_handle(dissect_SecurityModeCommand_PDU, proto_ranap));
  dissector_add_uint("ranap.proc.sout", id_SecurityModeControl, new_create_dissector_handle(dissect_SecurityModeComplete_PDU, proto_ranap));
  dissector_add_uint("ranap.proc.uout", id_SecurityModeControl, new_create_dissector_handle(dissect_SecurityModeReject_PDU, proto_ranap));
  dissector_add_uint("ranap.proc.imsg", id_DataVolumeReport, new_create_dissector_handle(dissect_DataVolumeReportRequest_PDU, proto_ranap));
  dissector_add_uint("ranap.proc.sout", id_DataVolumeReport, new_create_dissector_handle(dissect_DataVolumeReport_PDU, proto_ranap));
  dissector_add_uint("ranap.proc.imsg", id_Reset, new_create_dissector_handle(dissect_Reset_PDU, proto_ranap));
  dissector_add_uint("ranap.proc.sout", id_Reset, new_create_dissector_handle(dissect_ResetAcknowledge_PDU, proto_ranap));
  dissector_add_uint("ranap.proc.imsg", id_RAB_ReleaseRequest, new_create_dissector_handle(dissect_RAB_ReleaseRequest_PDU, proto_ranap));
  dissector_add_uint("ranap.proc.imsg", id_Iu_ReleaseRequest, new_create_dissector_handle(dissect_Iu_ReleaseRequest_PDU, proto_ranap));
  dissector_add_uint("ranap.proc.imsg", id_RelocationDetect, new_create_dissector_handle(dissect_RelocationDetect_PDU, proto_ranap));
  dissector_add_uint("ranap.proc.imsg", id_RelocationComplete, new_create_dissector_handle(dissect_RelocationComplete_PDU, proto_ranap));
  dissector_add_uint("ranap.proc.imsg", id_Paging, new_create_dissector_handle(dissect_Paging_PDU, proto_ranap));
  dissector_add_uint("ranap.proc.imsg", id_CommonID, new_create_dissector_handle(dissect_CommonID_PDU, proto_ranap));
  dissector_add_uint("ranap.proc.imsg", id_CN_InvokeTrace, new_create_dissector_handle(dissect_CN_InvokeTrace_PDU, proto_ranap));
  dissector_add_uint("ranap.proc.imsg", id_CN_DeactivateTrace, new_create_dissector_handle(dissect_CN_DeactivateTrace_PDU, proto_ranap));
  dissector_add_uint("ranap.proc.imsg", id_LocationReportingControl, new_create_dissector_handle(dissect_LocationReportingControl_PDU, proto_ranap));
  dissector_add_uint("ranap.proc.imsg", id_LocationReport, new_create_dissector_handle(dissect_LocationReport_PDU, proto_ranap));
  dissector_add_uint("ranap.proc.imsg", id_InitialUE_Message, new_create_dissector_handle(dissect_InitialUE_Message_PDU, proto_ranap));
  dissector_add_uint("ranap.proc.imsg", id_DirectTransfer, new_create_dissector_handle(dissect_DirectTransfer_PDU, proto_ranap));
  dissector_add_uint("ranap.proc.imsg", id_OverloadControl, new_create_dissector_handle(dissect_Overload_PDU, proto_ranap));
  dissector_add_uint("ranap.proc.imsg", id_ErrorIndication, new_create_dissector_handle(dissect_ErrorIndication_PDU, proto_ranap));
  dissector_add_uint("ranap.proc.imsg", id_SRNS_DataForward, new_create_dissector_handle(dissect_SRNS_DataForwardCommand_PDU, proto_ranap));
  dissector_add_uint("ranap.proc.imsg", id_ForwardSRNS_Context, new_create_dissector_handle(dissect_ForwardSRNS_Context_PDU, proto_ranap));
  dissector_add_uint("ranap.proc.imsg", id_RAB_Assignment, new_create_dissector_handle(dissect_RAB_AssignmentRequest_PDU, proto_ranap));
  dissector_add_uint("ranap.proc.out", id_RAB_Assignment, new_create_dissector_handle(dissect_RAB_AssignmentResponse_PDU, proto_ranap));
  dissector_add_uint("ranap.proc.imsg", id_privateMessage, new_create_dissector_handle(dissect_PrivateMessage_PDU, proto_ranap));
  dissector_add_uint("ranap.proc.imsg", id_ResetResource, new_create_dissector_handle(dissect_ResetResource_PDU, proto_ranap));
  dissector_add_uint("ranap.proc.sout", id_ResetResource, new_create_dissector_handle(dissect_ResetResourceAcknowledge_PDU, proto_ranap));
  dissector_add_uint("ranap.proc.imsg", id_RANAP_Relocation, new_create_dissector_handle(dissect_RANAP_RelocationInformation_PDU, proto_ranap));
  dissector_add_uint("ranap.proc.imsg", id_RAB_ModifyRequest, new_create_dissector_handle(dissect_RAB_ModifyRequest_PDU, proto_ranap));
  dissector_add_uint("ranap.proc.imsg", id_LocationRelatedData, new_create_dissector_handle(dissect_LocationRelatedDataRequest_PDU, proto_ranap));
  dissector_add_uint("ranap.proc.sout", id_LocationRelatedData, new_create_dissector_handle(dissect_LocationRelatedDataResponse_PDU, proto_ranap));
  dissector_add_uint("ranap.proc.uout", id_LocationRelatedData, new_create_dissector_handle(dissect_LocationRelatedDataFailure_PDU, proto_ranap));
  dissector_add_uint("ranap.proc.imsg", id_InformationTransfer, new_create_dissector_handle(dissect_InformationTransferIndication_PDU, proto_ranap));
  dissector_add_uint("ranap.proc.sout", id_InformationTransfer, new_create_dissector_handle(dissect_InformationTransferConfirmation_PDU, proto_ranap));
  dissector_add_uint("ranap.proc.uout", id_InformationTransfer, new_create_dissector_handle(dissect_InformationTransferFailure_PDU, proto_ranap));
  dissector_add_uint("ranap.proc.imsg", id_UESpecificInformation, new_create_dissector_handle(dissect_UESpecificInformationIndication_PDU, proto_ranap));
  dissector_add_uint("ranap.proc.imsg", id_DirectInformationTransfer, new_create_dissector_handle(dissect_DirectInformationTransfer_PDU, proto_ranap));
  dissector_add_uint("ranap.proc.imsg", id_UplinkInformationExchange, new_create_dissector_handle(dissect_UplinkInformationExchangeRequest_PDU, proto_ranap));
  dissector_add_uint("ranap.proc.sout", id_UplinkInformationExchange, new_create_dissector_handle(dissect_UplinkInformationExchangeResponse_PDU, proto_ranap));
  dissector_add_uint("ranap.proc.uout", id_UplinkInformationExchange, new_create_dissector_handle(dissect_UplinkInformationExchangeFailure_PDU, proto_ranap));
  dissector_add_uint("ranap.proc.imsg", id_MBMSSessionStart, new_create_dissector_handle(dissect_MBMSSessionStart_PDU, proto_ranap));
  dissector_add_uint("ranap.proc.sout", id_MBMSSessionStart, new_create_dissector_handle(dissect_MBMSSessionStartResponse_PDU, proto_ranap));
  dissector_add_uint("ranap.proc.uout", id_MBMSSessionStart, new_create_dissector_handle(dissect_MBMSSessionStartFailure_PDU, proto_ranap));
  dissector_add_uint("ranap.proc.imsg", id_MBMSSessionUpdate, new_create_dissector_handle(dissect_MBMSSessionUpdate_PDU, proto_ranap));
  dissector_add_uint("ranap.proc.sout", id_MBMSSessionUpdate, new_create_dissector_handle(dissect_MBMSSessionUpdateResponse_PDU, proto_ranap));
  dissector_add_uint("ranap.proc.uout", id_MBMSSessionUpdate, new_create_dissector_handle(dissect_MBMSSessionUpdateFailure_PDU, proto_ranap));
  dissector_add_uint("ranap.proc.imsg", id_MBMSSessionStop, new_create_dissector_handle(dissect_MBMSSessionStop_PDU, proto_ranap));
  dissector_add_uint("ranap.proc.sout", id_MBMSSessionStop, new_create_dissector_handle(dissect_MBMSSessionStopResponse_PDU, proto_ranap));
  dissector_add_uint("ranap.proc.imsg", id_MBMSUELinking, new_create_dissector_handle(dissect_MBMSUELinkingRequest_PDU, proto_ranap));
  dissector_add_uint("ranap.proc.out", id_MBMSUELinking, new_create_dissector_handle(dissect_MBMSUELinkingResponse_PDU, proto_ranap));
  dissector_add_uint("ranap.proc.imsg", id_MBMSRegistration, new_create_dissector_handle(dissect_MBMSRegistrationRequest_PDU, proto_ranap));
  dissector_add_uint("ranap.proc.sout", id_MBMSRegistration, new_create_dissector_handle(dissect_MBMSRegistrationResponse_PDU, proto_ranap));
  dissector_add_uint("ranap.proc.uout", id_MBMSRegistration, new_create_dissector_handle(dissect_MBMSRegistrationFailure_PDU, proto_ranap));
  dissector_add_uint("ranap.proc.imsg", id_MBMSCNDe_Registration_Procedure, new_create_dissector_handle(dissect_MBMSCNDe_RegistrationRequest_PDU, proto_ranap));
  dissector_add_uint("ranap.proc.sout", id_MBMSCNDe_Registration_Procedure, new_create_dissector_handle(dissect_MBMSCNDe_RegistrationResponse_PDU, proto_ranap));
  dissector_add_uint("ranap.proc.imsg", id_MBMSRABEstablishmentIndication, new_create_dissector_handle(dissect_MBMSRABEstablishmentIndication_PDU, proto_ranap));
  dissector_add_uint("ranap.proc.imsg", id_MBMSRABRelease, new_create_dissector_handle(dissect_MBMSRABReleaseRequest_PDU, proto_ranap));
  dissector_add_uint("ranap.proc.sout", id_MBMSRABRelease, new_create_dissector_handle(dissect_MBMSRABRelease_PDU, proto_ranap));
  dissector_add_uint("ranap.proc.uout", id_MBMSRABRelease, new_create_dissector_handle(dissect_MBMSRABReleaseFailure_PDU, proto_ranap));
  dissector_add_uint("ranap.proc.imsg", id_enhancedRelocationComplete, new_create_dissector_handle(dissect_EnhancedRelocationCompleteRequest_PDU, proto_ranap));
  dissector_add_uint("ranap.proc.sout", id_enhancedRelocationComplete, new_create_dissector_handle(dissect_EnhancedRelocationCompleteResponse_PDU, proto_ranap));
  dissector_add_uint("ranap.proc.uout", id_enhancedRelocationComplete, new_create_dissector_handle(dissect_EnhancedRelocationCompleteFailure_PDU, proto_ranap));
  dissector_add_uint("ranap.proc.imsg", id_enhancedRelocationCompleteConfirm, new_create_dissector_handle(dissect_EnhancedRelocationCompleteConfirm_PDU, proto_ranap));
  dissector_add_uint("ranap.proc.imsg", id_RANAPenhancedRelocation, new_create_dissector_handle(dissect_RANAP_EnhancedRelocationInformationRequest_PDU, proto_ranap));
  dissector_add_uint("ranap.proc.sout", id_RANAPenhancedRelocation, new_create_dissector_handle(dissect_RANAP_EnhancedRelocationInformationResponse_PDU, proto_ranap));
  dissector_add_uint("ranap.proc.imsg", id_SRVCCPreparation, new_create_dissector_handle(dissect_SRVCC_CSKeysRequest_PDU, proto_ranap));
  dissector_add_uint("ranap.proc.out", id_SRVCCPreparation, new_create_dissector_handle(dissect_SRVCC_CSKeysResponse_PDU, proto_ranap));


/*--- End of included file: packet-ranap-dis-tab.c ---*/
#line 375 "../../asn1/ranap/packet-ranap-template.c"
	} else {
		dissector_delete_uint("sccp.ssn", local_ranap_sccp_ssn, ranap_handle);
	}

	dissector_add_uint("sccp.ssn", global_ranap_sccp_ssn, ranap_handle);
	local_ranap_sccp_ssn = global_ranap_sccp_ssn;
	/* Add heuristic dissector
	* Perhaps we want a preference whether the heuristic dissector
	* is or isn't enabled
	*/
	heur_dissector_add("sccp", dissect_sccp_ranap_heur, proto_ranap);
	heur_dissector_add("sua", dissect_sccp_ranap_heur, proto_ranap);
}


