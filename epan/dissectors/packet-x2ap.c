/* Do not modify this file. Changes will be overwritten.                      */
/* Generated automatically by the ASN.1 to Wireshark dissector compiler       */
/* packet-x2ap.c                                                              */
/* asn2wrs.py -p x2ap -c ./x2ap.cnf -s ./packet-x2ap-template -D . -O ../.. X2AP-CommonDataTypes.asn X2AP-Constants.asn X2AP-Containers.asn X2AP-IEs.asn X2AP-PDU-Contents.asn X2AP-PDU-Descriptions.asn */

/* Input file: packet-x2ap-template.c */

#line 1 "./asn1/x2ap/packet-x2ap-template.c"
/* packet-x2ap.c
 * Routines for dissecting Evolved Universal Terrestrial Radio Access Network (EUTRAN);
 * X2 Application Protocol (X2AP);
 * 3GPP TS 36.423 packet dissection
 * Copyright 2007-2014, Anders Broman <anders.broman@ericsson.com>
 * Copyright 2016, Pascal Quantin <pacal.quantin@gmail.com>
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 *
 * Ref:
 * 3GPP TS 36.423 V13.6.0 (2017-01)
 */

#include "config.h"

#include <epan/packet.h>
#include <epan/tfs.h>
#include <epan/asn1.h>
#include <epan/prefs.h>
#include <epan/sctpppids.h>
#include <epan/proto_data.h>

#include "packet-per.h"
#include "packet-e212.h"
#include "packet-lte-rrc.h"

#ifdef _MSC_VER
/* disable: "warning C4146: unary minus operator applied to unsigned type, result still unsigned" */
#pragma warning(disable:4146)
#endif

#define PNAME  "EUTRAN X2 Application Protocol (X2AP)"
#define PSNAME "X2AP"
#define PFNAME "x2ap"

void proto_register_x2ap(void);

/* Dissector will use SCTP PPID 27 or SCTP port. IANA assigned port = 36422 */
#define SCTP_PORT_X2AP	36422


/*--- Included file: packet-x2ap-val.h ---*/
#line 1 "./asn1/x2ap/packet-x2ap-val.h"
#define maxPrivateIEs                  65535
#define maxProtocolExtensions          65535
#define maxProtocolIEs                 65535
#define maxEARFCN                      65535
#define maxEARFCNPlusOne               65536
#define newmaxEARFCN                   262143
#define maxInterfaces                  16
#define maxCellineNB                   256
#define maxnoofBands                   16
#define maxnoofBearers                 256
#define maxNrOfErrors                  256
#define maxnoofPDCP_SN                 16
#define maxnoofEPLMNs                  15
#define maxnoofEPLMNsPlusOne           16
#define maxnoofForbLACs                4096
#define maxnoofForbTACs                4096
#define maxnoofBPLMNs                  6
#define maxnoofNeighbours              512
#define maxnoofPRBs                    110
#define maxPools                       16
#define maxnoofCells                   16
#define maxnoofMBSFN                   8
#define maxFailedMeasObjects           32
#define maxnoofCellIDforMDT            32
#define maxnoofTAforMDT                8
#define maxnoofMBMSServiceAreaIdentities 256
#define maxnoofMDTPLMNs                16
#define maxnoofCoMPHypothesisSet       256
#define maxnoofCoMPCells               32
#define maxUEReport                    128
#define maxCellReport                  9
#define maxnoofPA                      3
#define maxCSIProcess                  4
#define maxCSIReport                   2
#define maxSubband                     14

typedef enum _ProcedureCode_enum {
  id_handoverPreparation =   0,
  id_handoverCancel =   1,
  id_loadIndication =   2,
  id_errorIndication =   3,
  id_snStatusTransfer =   4,
  id_uEContextRelease =   5,
  id_x2Setup   =   6,
  id_reset     =   7,
  id_eNBConfigurationUpdate =   8,
  id_resourceStatusReportingInitiation =   9,
  id_resourceStatusReporting =  10,
  id_privateMessage =  11,
  id_mobilitySettingsChange =  12,
  id_rLFIndication =  13,
  id_handoverReport =  14,
  id_cellActivation =  15,
  id_x2Release =  16,
  id_x2APMessageTransfer =  17,
  id_x2Removal =  18,
  id_seNBAdditionPreparation =  19,
  id_seNBReconfigurationCompletion =  20,
  id_meNBinitiatedSeNBModificationPreparation =  21,
  id_seNBinitiatedSeNBModification =  22,
  id_meNBinitiatedSeNBRelease =  23,
  id_seNBinitiatedSeNBRelease =  24,
  id_seNBCounterCheck =  25,
  id_retrieveUEContext =  26
} ProcedureCode_enum;

typedef enum _ProtocolIE_ID_enum {
  id_E_RABs_Admitted_Item =   0,
  id_E_RABs_Admitted_List =   1,
  id_E_RAB_Item =   2,
  id_E_RABs_NotAdmitted_List =   3,
  id_E_RABs_ToBeSetup_Item =   4,
  id_Cause     =   5,
  id_CellInformation =   6,
  id_CellInformation_Item =   7,
  id_New_eNB_UE_X2AP_ID =   9,
  id_Old_eNB_UE_X2AP_ID =  10,
  id_TargetCell_ID =  11,
  id_TargeteNBtoSource_eNBTransparentContainer =  12,
  id_TraceActivation =  13,
  id_UE_ContextInformation =  14,
  id_UE_HistoryInformation =  15,
  id_UE_X2AP_ID =  16,
  id_CriticalityDiagnostics =  17,
  id_E_RABs_SubjectToStatusTransfer_List =  18,
  id_E_RABs_SubjectToStatusTransfer_Item =  19,
  id_ServedCells =  20,
  id_GlobalENB_ID =  21,
  id_TimeToWait =  22,
  id_GUMMEI_ID =  23,
  id_GUGroupIDList =  24,
  id_ServedCellsToAdd =  25,
  id_ServedCellsToModify =  26,
  id_ServedCellsToDelete =  27,
  id_Registration_Request =  28,
  id_CellToReport =  29,
  id_ReportingPeriodicity =  30,
  id_CellToReport_Item =  31,
  id_CellMeasurementResult =  32,
  id_CellMeasurementResult_Item =  33,
  id_GUGroupIDToAddList =  34,
  id_GUGroupIDToDeleteList =  35,
  id_SRVCCOperationPossible =  36,
  id_Measurement_ID =  37,
  id_ReportCharacteristics =  38,
  id_ENB1_Measurement_ID =  39,
  id_ENB2_Measurement_ID =  40,
  id_Number_of_Antennaports =  41,
  id_CompositeAvailableCapacityGroup =  42,
  id_ENB1_Cell_ID =  43,
  id_ENB2_Cell_ID =  44,
  id_ENB2_Proposed_Mobility_Parameters =  45,
  id_ENB1_Mobility_Parameters =  46,
  id_ENB2_Mobility_Parameters_Modification_Range =  47,
  id_FailureCellPCI =  48,
  id_Re_establishmentCellECGI =  49,
  id_FailureCellCRNTI =  50,
  id_ShortMAC_I =  51,
  id_SourceCellECGI =  52,
  id_FailureCellECGI =  53,
  id_HandoverReportType =  54,
  id_PRACH_Configuration =  55,
  id_MBSFN_Subframe_Info =  56,
  id_ServedCellsToActivate =  57,
  id_ActivatedCellList =  58,
  id_DeactivationIndication =  59,
  id_UE_RLF_Report_Container =  60,
  id_ABSInformation =  61,
  id_InvokeIndication =  62,
  id_ABS_Status =  63,
  id_PartialSuccessIndicator =  64,
  id_MeasurementInitiationResult_List =  65,
  id_MeasurementInitiationResult_Item =  66,
  id_MeasurementFailureCause_Item =  67,
  id_CompleteFailureCauseInformation_List =  68,
  id_CompleteFailureCauseInformation_Item =  69,
  id_CSG_Id    =  70,
  id_CSGMembershipStatus =  71,
  id_MDTConfiguration =  72,
  id_ManagementBasedMDTallowed =  74,
  id_RRCConnSetupIndicator =  75,
  id_NeighbourTAC =  76,
  id_Time_UE_StayedInCell_EnhancedGranularity =  77,
  id_RRCConnReestabIndicator =  78,
  id_MBMS_Service_Area_List =  79,
  id_HO_cause  =  80,
  id_TargetCellInUTRAN =  81,
  id_MobilityInformation =  82,
  id_SourceCellCRNTI =  83,
  id_MultibandInfoList =  84,
  id_M3Configuration =  85,
  id_M4Configuration =  86,
  id_M5Configuration =  87,
  id_MDT_Location_Info =  88,
  id_ManagementBasedMDTPLMNList =  89,
  id_SignallingBasedMDTPLMNList =  90,
  id_ReceiveStatusOfULPDCPSDUsExtended =  91,
  id_ULCOUNTValueExtended =  92,
  id_DLCOUNTValueExtended =  93,
  id_eARFCNExtension =  94,
  id_UL_EARFCNExtension =  95,
  id_DL_EARFCNExtension =  96,
  id_AdditionalSpecialSubframe_Info =  97,
  id_Masked_IMEISV =  98,
  id_IntendedULDLConfiguration =  99,
  id_ExtendedULInterferenceOverloadInfo = 100,
  id_RNL_Header = 101,
  id_x2APMessage = 102,
  id_ProSeAuthorized = 103,
  id_ExpectedUEBehaviour = 104,
  id_UE_HistoryInformationFromTheUE = 105,
  id_DynamicDLTransmissionInformation = 106,
  id_UE_RLF_Report_Container_for_extended_bands = 107,
  id_CoMPInformation = 108,
  id_ReportingPeriodicityRSRPMR = 109,
  id_RSRPMRList = 110,
  id_MeNB_UE_X2AP_ID = 111,
  id_SeNB_UE_X2AP_ID = 112,
  id_UE_SecurityCapabilities = 113,
  id_SeNBSecurityKey = 114,
  id_SeNBUEAggregateMaximumBitRate = 115,
  id_ServingPLMN = 116,
  id_E_RABs_ToBeAdded_List = 117,
  id_E_RABs_ToBeAdded_Item = 118,
  id_MeNBtoSeNBContainer = 119,
  id_E_RABs_Admitted_ToBeAdded_List = 120,
  id_E_RABs_Admitted_ToBeAdded_Item = 121,
  id_SeNBtoMeNBContainer = 122,
  id_ResponseInformationSeNBReconfComp = 123,
  id_UE_ContextInformationSeNBModReq = 124,
  id_E_RABs_ToBeAdded_ModReqItem = 125,
  id_E_RABs_ToBeModified_ModReqItem = 126,
  id_E_RABs_ToBeReleased_ModReqItem = 127,
  id_E_RABs_Admitted_ToBeAdded_ModAckList = 128,
  id_E_RABs_Admitted_ToBeModified_ModAckList = 129,
  id_E_RABs_Admitted_ToBeReleased_ModAckList = 130,
  id_E_RABs_Admitted_ToBeAdded_ModAckItem = 131,
  id_E_RABs_Admitted_ToBeModified_ModAckItem = 132,
  id_E_RABs_Admitted_ToBeReleased_ModAckItem = 133,
  id_E_RABs_ToBeReleased_ModReqd = 134,
  id_E_RABs_ToBeReleased_ModReqdItem = 135,
  id_SCGChangeIndication = 136,
  id_E_RABs_ToBeReleased_List_RelReq = 137,
  id_E_RABs_ToBeReleased_RelReqItem = 138,
  id_E_RABs_ToBeReleased_List_RelConf = 139,
  id_E_RABs_ToBeReleased_RelConfItem = 140,
  id_E_RABs_SubjectToCounterCheck_List = 141,
  id_E_RABs_SubjectToCounterCheckItem = 142,
  id_CoverageModificationList = 143,
  id_ReportingPeriodicityCSIR = 145,
  id_CSIReportList = 146,
  id_UEID      = 147,
  id_enhancedRNTP = 148,
  id_ProSeUEtoNetworkRelaying = 149,
  id_ReceiveStatusOfULPDCPSDUsPDCP_SNlength18 = 150,
  id_ULCOUNTValuePDCP_SNlength18 = 151,
  id_DLCOUNTValuePDCP_SNlength18 = 152,
  id_UE_ContextReferenceAtSeNB = 153,
  id_UE_ContextKeptIndicator = 154,
  id_New_eNB_UE_X2AP_ID_Extension = 155,
  id_Old_eNB_UE_X2AP_ID_Extension = 156,
  id_MeNB_UE_X2AP_ID_Extension = 157,
  id_SeNB_UE_X2AP_ID_Extension = 158,
  id_LHN_ID    = 159,
  id_FreqBandIndicatorPriority = 160,
  id_M6Configuration = 161,
  id_M7Configuration = 162,
  id_Tunnel_Information_for_BBF = 163,
  id_SIPTO_BearerDeactivationIndication = 164,
  id_GW_TransportLayerAddress = 165,
  id_Correlation_ID = 166,
  id_SIPTO_Correlation_ID = 167,
  id_SIPTO_L_GW_TransportLayerAddress = 168,
  id_X2RemovalThreshold = 169,
  id_CellReportingIndicator = 170,
  id_BearerType = 171,
  id_resumeID  = 172,
  id_UE_ContextInformationRetrieve = 173,
  id_E_RABs_ToBeSetupRetrieve_Item = 174,
  id_NewEUTRANCellIdentifier = 175,
  id_OffsetOfNbiotChannelNumberToDL_EARFCN = 177,
  id_OffsetOfNbiotChannelNumberToUL_EARFCN = 178
} ProtocolIE_ID_enum;

/*--- End of included file: packet-x2ap-val.h ---*/
#line 58 "./asn1/x2ap/packet-x2ap-template.c"

/* Initialize the protocol and registered fields */
static int proto_x2ap = -1;
static int hf_x2ap_transportLayerAddressIPv4 = -1;
static int hf_x2ap_transportLayerAddressIPv6 = -1;
static int hf_x2ap_ReportCharacteristics_PRBPeriodic = -1;
static int hf_x2ap_ReportCharacteristics_TNLLoadIndPeriodic = -1;
static int hf_x2ap_ReportCharacteristics_HWLoadIndPeriodic = -1;
static int hf_x2ap_ReportCharacteristics_CompositeAvailableCapacityPeriodic = -1;
static int hf_x2ap_ReportCharacteristics_ABSStatusPeriodic = -1;
static int hf_x2ap_ReportCharacteristics_RSRPMeasurementReportPeriodic = -1;
static int hf_x2ap_ReportCharacteristics_CSIReportPeriodic = -1;
static int hf_x2ap_ReportCharacteristics_Reserved = -1;
static int hf_x2ap_measurementFailedReportCharacteristics_PRBPeriodic = -1;
static int hf_x2ap_measurementFailedReportCharacteristics_TNLLoadIndPeriodic = -1;
static int hf_x2ap_measurementFailedReportCharacteristics_HWLoadIndPeriodic = -1;
static int hf_x2ap_measurementFailedReportCharacteristics_CompositeAvailableCapacityPeriodic = -1;
static int hf_x2ap_measurementFailedReportCharacteristics_ABSStatusPeriodic = -1;
static int hf_x2ap_measurementFailedReportCharacteristics_RSRPMeasurementReportPeriodic = -1;
static int hf_x2ap_measurementFailedReportCharacteristics_CSIReportPeriodic = -1;
static int hf_x2ap_measurementFailedReportCharacteristics_Reserved = -1;
static int hf_x2ap_eUTRANTraceID_TraceID = -1;
static int hf_x2ap_eUTRANTraceID_TraceRecordingSessionReference = -1;
static int hf_x2ap_interfacesToTrace_S1_MME = -1;
static int hf_x2ap_interfacesToTrace_X2 = -1;
static int hf_x2ap_interfacesToTrace_Uu = -1;
static int hf_x2ap_interfacesToTrace_Reserved = -1;
static int hf_x2ap_traceCollectionEntityIPAddress_IPv4 = -1;
static int hf_x2ap_traceCollectionEntityIPAddress_IPv6 = -1;
static int hf_x2ap_encryptionAlgorithms_EEA1 = -1;
static int hf_x2ap_encryptionAlgorithms_EEA2 = -1;
static int hf_x2ap_encryptionAlgorithms_EEA3 = -1;
static int hf_x2ap_encryptionAlgorithms_Reserved = -1;
static int hf_x2ap_integrityProtectionAlgorithms_EIA1 = -1;
static int hf_x2ap_integrityProtectionAlgorithms_EIA2 = -1;
static int hf_x2ap_integrityProtectionAlgorithms_EIA3 = -1;
static int hf_x2ap_integrityProtectionAlgorithms_Reserved = -1;
static int hf_x2ap_measurementsToActivate_M1 = -1;
static int hf_x2ap_measurementsToActivate_M2 = -1;
static int hf_x2ap_measurementsToActivate_M3 = -1;
static int hf_x2ap_measurementsToActivate_M4 = -1;
static int hf_x2ap_measurementsToActivate_M5 = -1;
static int hf_x2ap_measurementsToActivate_LoggingM1FromEventTriggered = -1;
static int hf_x2ap_measurementsToActivate_M6 = -1;
static int hf_x2ap_measurementsToActivate_M7 = -1;
static int hf_x2ap_MDT_Location_Info_GNSS = -1;
static int hf_x2ap_MDT_Location_Info_E_CID = -1;
static int hf_x2ap_MDT_Location_Info_Reserved = -1;
static int hf_x2ap_MDT_transmissionModes_tm1 = -1;
static int hf_x2ap_MDT_transmissionModes_tm2 = -1;
static int hf_x2ap_MDT_transmissionModes_tm3 = -1;
static int hf_x2ap_MDT_transmissionModes_tm4 = -1;
static int hf_x2ap_MDT_transmissionModes_tm6 = -1;
static int hf_x2ap_MDT_transmissionModes_tm8 = -1;
static int hf_x2ap_MDT_transmissionModes_tm9 = -1;
static int hf_x2ap_MDT_transmissionModes_tm10 = -1;

/*--- Included file: packet-x2ap-hf.c ---*/
#line 1 "./asn1/x2ap/packet-x2ap-hf.c"
static int hf_x2ap_ABSInformation_PDU = -1;       /* ABSInformation */
static int hf_x2ap_ABS_Status_PDU = -1;           /* ABS_Status */
static int hf_x2ap_AdditionalSpecialSubframe_Info_PDU = -1;  /* AdditionalSpecialSubframe_Info */
static int hf_x2ap_BearerType_PDU = -1;           /* BearerType */
static int hf_x2ap_Cause_PDU = -1;                /* Cause */
static int hf_x2ap_CellReportingIndicator_PDU = -1;  /* CellReportingIndicator */
static int hf_x2ap_CoMPInformation_PDU = -1;      /* CoMPInformation */
static int hf_x2ap_CompositeAvailableCapacityGroup_PDU = -1;  /* CompositeAvailableCapacityGroup */
static int hf_x2ap_Correlation_ID_PDU = -1;       /* Correlation_ID */
static int hf_x2ap_COUNTValueExtended_PDU = -1;   /* COUNTValueExtended */
static int hf_x2ap_COUNTvaluePDCP_SNlength18_PDU = -1;  /* COUNTvaluePDCP_SNlength18 */
static int hf_x2ap_CoverageModificationList_PDU = -1;  /* CoverageModificationList */
static int hf_x2ap_CriticalityDiagnostics_PDU = -1;  /* CriticalityDiagnostics */
static int hf_x2ap_CRNTI_PDU = -1;                /* CRNTI */
static int hf_x2ap_CSGMembershipStatus_PDU = -1;  /* CSGMembershipStatus */
static int hf_x2ap_CSG_Id_PDU = -1;               /* CSG_Id */
static int hf_x2ap_CSIReportList_PDU = -1;        /* CSIReportList */
static int hf_x2ap_DeactivationIndication_PDU = -1;  /* DeactivationIndication */
static int hf_x2ap_DynamicDLTransmissionInformation_PDU = -1;  /* DynamicDLTransmissionInformation */
static int hf_x2ap_EARFCNExtension_PDU = -1;      /* EARFCNExtension */
static int hf_x2ap_ECGI_PDU = -1;                 /* ECGI */
static int hf_x2ap_EnhancedRNTP_PDU = -1;         /* EnhancedRNTP */
static int hf_x2ap_E_RAB_List_PDU = -1;           /* E_RAB_List */
static int hf_x2ap_E_RAB_Item_PDU = -1;           /* E_RAB_Item */
static int hf_x2ap_EUTRANCellIdentifier_PDU = -1;  /* EUTRANCellIdentifier */
static int hf_x2ap_ExpectedUEBehaviour_PDU = -1;  /* ExpectedUEBehaviour */
static int hf_x2ap_ExtendedULInterferenceOverloadInfo_PDU = -1;  /* ExtendedULInterferenceOverloadInfo */
static int hf_x2ap_FreqBandIndicatorPriority_PDU = -1;  /* FreqBandIndicatorPriority */
static int hf_x2ap_GlobalENB_ID_PDU = -1;         /* GlobalENB_ID */
static int hf_x2ap_GUGroupIDList_PDU = -1;        /* GUGroupIDList */
static int hf_x2ap_GUMMEI_PDU = -1;               /* GUMMEI */
static int hf_x2ap_HandoverReportType_PDU = -1;   /* HandoverReportType */
static int hf_x2ap_InvokeIndication_PDU = -1;     /* InvokeIndication */
static int hf_x2ap_LHN_ID_PDU = -1;               /* LHN_ID */
static int hf_x2ap_M3Configuration_PDU = -1;      /* M3Configuration */
static int hf_x2ap_M4Configuration_PDU = -1;      /* M4Configuration */
static int hf_x2ap_M5Configuration_PDU = -1;      /* M5Configuration */
static int hf_x2ap_M6Configuration_PDU = -1;      /* M6Configuration */
static int hf_x2ap_M7Configuration_PDU = -1;      /* M7Configuration */
static int hf_x2ap_ManagementBasedMDTallowed_PDU = -1;  /* ManagementBasedMDTallowed */
static int hf_x2ap_Masked_IMEISV_PDU = -1;        /* Masked_IMEISV */
static int hf_x2ap_MDT_Configuration_PDU = -1;    /* MDT_Configuration */
static int hf_x2ap_MDTPLMNList_PDU = -1;          /* MDTPLMNList */
static int hf_x2ap_MDT_Location_Info_PDU = -1;    /* MDT_Location_Info */
static int hf_x2ap_Measurement_ID_PDU = -1;       /* Measurement_ID */
static int hf_x2ap_MeNBtoSeNBContainer_PDU = -1;  /* MeNBtoSeNBContainer */
static int hf_x2ap_MBMS_Service_Area_Identity_List_PDU = -1;  /* MBMS_Service_Area_Identity_List */
static int hf_x2ap_MBSFN_Subframe_Infolist_PDU = -1;  /* MBSFN_Subframe_Infolist */
static int hf_x2ap_MobilityParametersModificationRange_PDU = -1;  /* MobilityParametersModificationRange */
static int hf_x2ap_MobilityParametersInformation_PDU = -1;  /* MobilityParametersInformation */
static int hf_x2ap_MultibandInfoList_PDU = -1;    /* MultibandInfoList */
static int hf_x2ap_Number_of_Antennaports_PDU = -1;  /* Number_of_Antennaports */
static int hf_x2ap_OffsetOfNbiotChannelNumberToEARFCN_PDU = -1;  /* OffsetOfNbiotChannelNumberToEARFCN */
static int hf_x2ap_PCI_PDU = -1;                  /* PCI */
static int hf_x2ap_PLMN_Identity_PDU = -1;        /* PLMN_Identity */
static int hf_x2ap_PRACH_Configuration_PDU = -1;  /* PRACH_Configuration */
static int hf_x2ap_ProSeAuthorized_PDU = -1;      /* ProSeAuthorized */
static int hf_x2ap_ProSeUEtoNetworkRelaying_PDU = -1;  /* ProSeUEtoNetworkRelaying */
static int hf_x2ap_ReceiveStatusOfULPDCPSDUsExtended_PDU = -1;  /* ReceiveStatusOfULPDCPSDUsExtended */
static int hf_x2ap_ReceiveStatusOfULPDCPSDUsPDCP_SNlength18_PDU = -1;  /* ReceiveStatusOfULPDCPSDUsPDCP_SNlength18 */
static int hf_x2ap_Registration_Request_PDU = -1;  /* Registration_Request */
static int hf_x2ap_ReportCharacteristics_PDU = -1;  /* ReportCharacteristics */
static int hf_x2ap_ReportingPeriodicityCSIR_PDU = -1;  /* ReportingPeriodicityCSIR */
static int hf_x2ap_ReportingPeriodicityRSRPMR_PDU = -1;  /* ReportingPeriodicityRSRPMR */
static int hf_x2ap_ResumeID_PDU = -1;             /* ResumeID */
static int hf_x2ap_RRCConnReestabIndicator_PDU = -1;  /* RRCConnReestabIndicator */
static int hf_x2ap_RRCConnSetupIndicator_PDU = -1;  /* RRCConnSetupIndicator */
static int hf_x2ap_RSRPMRList_PDU = -1;           /* RSRPMRList */
static int hf_x2ap_SCGChangeIndication_PDU = -1;  /* SCGChangeIndication */
static int hf_x2ap_SeNBSecurityKey_PDU = -1;      /* SeNBSecurityKey */
static int hf_x2ap_SeNBtoMeNBContainer_PDU = -1;  /* SeNBtoMeNBContainer */
static int hf_x2ap_ServedCells_PDU = -1;          /* ServedCells */
static int hf_x2ap_SIPTOBearerDeactivationIndication_PDU = -1;  /* SIPTOBearerDeactivationIndication */
static int hf_x2ap_ShortMAC_I_PDU = -1;           /* ShortMAC_I */
static int hf_x2ap_SRVCCOperationPossible_PDU = -1;  /* SRVCCOperationPossible */
static int hf_x2ap_SubframeAssignment_PDU = -1;   /* SubframeAssignment */
static int hf_x2ap_TAC_PDU = -1;                  /* TAC */
static int hf_x2ap_TargetCellInUTRAN_PDU = -1;    /* TargetCellInUTRAN */
static int hf_x2ap_TargeteNBtoSource_eNBTransparentContainer_PDU = -1;  /* TargeteNBtoSource_eNBTransparentContainer */
static int hf_x2ap_TimeToWait_PDU = -1;           /* TimeToWait */
static int hf_x2ap_Time_UE_StayedInCell_EnhancedGranularity_PDU = -1;  /* Time_UE_StayedInCell_EnhancedGranularity */
static int hf_x2ap_TraceActivation_PDU = -1;      /* TraceActivation */
static int hf_x2ap_TransportLayerAddress_PDU = -1;  /* TransportLayerAddress */
static int hf_x2ap_TunnelInformation_PDU = -1;    /* TunnelInformation */
static int hf_x2ap_UEAggregateMaximumBitRate_PDU = -1;  /* UEAggregateMaximumBitRate */
static int hf_x2ap_UE_ContextKeptIndicator_PDU = -1;  /* UE_ContextKeptIndicator */
static int hf_x2ap_UEID_PDU = -1;                 /* UEID */
static int hf_x2ap_UE_HistoryInformation_PDU = -1;  /* UE_HistoryInformation */
static int hf_x2ap_UE_HistoryInformationFromTheUE_PDU = -1;  /* UE_HistoryInformationFromTheUE */
static int hf_x2ap_UE_X2AP_ID_PDU = -1;           /* UE_X2AP_ID */
static int hf_x2ap_UE_X2AP_ID_Extension_PDU = -1;  /* UE_X2AP_ID_Extension */
static int hf_x2ap_UE_RLF_Report_Container_PDU = -1;  /* UE_RLF_Report_Container */
static int hf_x2ap_UE_RLF_Report_Container_for_extended_bands_PDU = -1;  /* UE_RLF_Report_Container_for_extended_bands */
static int hf_x2ap_UESecurityCapabilities_PDU = -1;  /* UESecurityCapabilities */
static int hf_x2ap_X2BenefitValue_PDU = -1;       /* X2BenefitValue */
static int hf_x2ap_HandoverRequest_PDU = -1;      /* HandoverRequest */
static int hf_x2ap_UE_ContextInformation_PDU = -1;  /* UE_ContextInformation */
static int hf_x2ap_E_RABs_ToBeSetup_Item_PDU = -1;  /* E_RABs_ToBeSetup_Item */
static int hf_x2ap_MobilityInformation_PDU = -1;  /* MobilityInformation */
static int hf_x2ap_UE_ContextReferenceAtSeNB_PDU = -1;  /* UE_ContextReferenceAtSeNB */
static int hf_x2ap_HandoverRequestAcknowledge_PDU = -1;  /* HandoverRequestAcknowledge */
static int hf_x2ap_E_RABs_Admitted_List_PDU = -1;  /* E_RABs_Admitted_List */
static int hf_x2ap_E_RABs_Admitted_Item_PDU = -1;  /* E_RABs_Admitted_Item */
static int hf_x2ap_HandoverPreparationFailure_PDU = -1;  /* HandoverPreparationFailure */
static int hf_x2ap_HandoverReport_PDU = -1;       /* HandoverReport */
static int hf_x2ap_SNStatusTransfer_PDU = -1;     /* SNStatusTransfer */
static int hf_x2ap_E_RABs_SubjectToStatusTransfer_List_PDU = -1;  /* E_RABs_SubjectToStatusTransfer_List */
static int hf_x2ap_E_RABs_SubjectToStatusTransfer_Item_PDU = -1;  /* E_RABs_SubjectToStatusTransfer_Item */
static int hf_x2ap_UEContextRelease_PDU = -1;     /* UEContextRelease */
static int hf_x2ap_HandoverCancel_PDU = -1;       /* HandoverCancel */
static int hf_x2ap_ErrorIndication_PDU = -1;      /* ErrorIndication */
static int hf_x2ap_ResetRequest_PDU = -1;         /* ResetRequest */
static int hf_x2ap_ResetResponse_PDU = -1;        /* ResetResponse */
static int hf_x2ap_X2SetupRequest_PDU = -1;       /* X2SetupRequest */
static int hf_x2ap_X2SetupResponse_PDU = -1;      /* X2SetupResponse */
static int hf_x2ap_X2SetupFailure_PDU = -1;       /* X2SetupFailure */
static int hf_x2ap_LoadInformation_PDU = -1;      /* LoadInformation */
static int hf_x2ap_CellInformation_List_PDU = -1;  /* CellInformation_List */
static int hf_x2ap_CellInformation_Item_PDU = -1;  /* CellInformation_Item */
static int hf_x2ap_ENBConfigurationUpdate_PDU = -1;  /* ENBConfigurationUpdate */
static int hf_x2ap_ServedCellsToModify_PDU = -1;  /* ServedCellsToModify */
static int hf_x2ap_Old_ECGIs_PDU = -1;            /* Old_ECGIs */
static int hf_x2ap_ENBConfigurationUpdateAcknowledge_PDU = -1;  /* ENBConfigurationUpdateAcknowledge */
static int hf_x2ap_ENBConfigurationUpdateFailure_PDU = -1;  /* ENBConfigurationUpdateFailure */
static int hf_x2ap_ResourceStatusRequest_PDU = -1;  /* ResourceStatusRequest */
static int hf_x2ap_CellToReport_List_PDU = -1;    /* CellToReport_List */
static int hf_x2ap_CellToReport_Item_PDU = -1;    /* CellToReport_Item */
static int hf_x2ap_ReportingPeriodicity_PDU = -1;  /* ReportingPeriodicity */
static int hf_x2ap_PartialSuccessIndicator_PDU = -1;  /* PartialSuccessIndicator */
static int hf_x2ap_ResourceStatusResponse_PDU = -1;  /* ResourceStatusResponse */
static int hf_x2ap_MeasurementInitiationResult_List_PDU = -1;  /* MeasurementInitiationResult_List */
static int hf_x2ap_MeasurementInitiationResult_Item_PDU = -1;  /* MeasurementInitiationResult_Item */
static int hf_x2ap_MeasurementFailureCause_Item_PDU = -1;  /* MeasurementFailureCause_Item */
static int hf_x2ap_ResourceStatusFailure_PDU = -1;  /* ResourceStatusFailure */
static int hf_x2ap_CompleteFailureCauseInformation_List_PDU = -1;  /* CompleteFailureCauseInformation_List */
static int hf_x2ap_CompleteFailureCauseInformation_Item_PDU = -1;  /* CompleteFailureCauseInformation_Item */
static int hf_x2ap_ResourceStatusUpdate_PDU = -1;  /* ResourceStatusUpdate */
static int hf_x2ap_CellMeasurementResult_List_PDU = -1;  /* CellMeasurementResult_List */
static int hf_x2ap_CellMeasurementResult_Item_PDU = -1;  /* CellMeasurementResult_Item */
static int hf_x2ap_PrivateMessage_PDU = -1;       /* PrivateMessage */
static int hf_x2ap_MobilityChangeRequest_PDU = -1;  /* MobilityChangeRequest */
static int hf_x2ap_MobilityChangeAcknowledge_PDU = -1;  /* MobilityChangeAcknowledge */
static int hf_x2ap_MobilityChangeFailure_PDU = -1;  /* MobilityChangeFailure */
static int hf_x2ap_RLFIndication_PDU = -1;        /* RLFIndication */
static int hf_x2ap_CellActivationRequest_PDU = -1;  /* CellActivationRequest */
static int hf_x2ap_ServedCellsToActivate_PDU = -1;  /* ServedCellsToActivate */
static int hf_x2ap_CellActivationResponse_PDU = -1;  /* CellActivationResponse */
static int hf_x2ap_ActivatedCellList_PDU = -1;    /* ActivatedCellList */
static int hf_x2ap_CellActivationFailure_PDU = -1;  /* CellActivationFailure */
static int hf_x2ap_X2Release_PDU = -1;            /* X2Release */
static int hf_x2ap_X2APMessageTransfer_PDU = -1;  /* X2APMessageTransfer */
static int hf_x2ap_RNL_Header_PDU = -1;           /* RNL_Header */
static int hf_x2ap_X2AP_Message_PDU = -1;         /* X2AP_Message */
static int hf_x2ap_SeNBAdditionRequest_PDU = -1;  /* SeNBAdditionRequest */
static int hf_x2ap_E_RABs_ToBeAdded_List_PDU = -1;  /* E_RABs_ToBeAdded_List */
static int hf_x2ap_E_RABs_ToBeAdded_Item_PDU = -1;  /* E_RABs_ToBeAdded_Item */
static int hf_x2ap_SeNBAdditionRequestAcknowledge_PDU = -1;  /* SeNBAdditionRequestAcknowledge */
static int hf_x2ap_E_RABs_Admitted_ToBeAdded_List_PDU = -1;  /* E_RABs_Admitted_ToBeAdded_List */
static int hf_x2ap_E_RABs_Admitted_ToBeAdded_Item_PDU = -1;  /* E_RABs_Admitted_ToBeAdded_Item */
static int hf_x2ap_SeNBAdditionRequestReject_PDU = -1;  /* SeNBAdditionRequestReject */
static int hf_x2ap_SeNBReconfigurationComplete_PDU = -1;  /* SeNBReconfigurationComplete */
static int hf_x2ap_ResponseInformationSeNBReconfComp_PDU = -1;  /* ResponseInformationSeNBReconfComp */
static int hf_x2ap_SeNBModificationRequest_PDU = -1;  /* SeNBModificationRequest */
static int hf_x2ap_UE_ContextInformationSeNBModReq_PDU = -1;  /* UE_ContextInformationSeNBModReq */
static int hf_x2ap_E_RABs_ToBeAdded_ModReqItem_PDU = -1;  /* E_RABs_ToBeAdded_ModReqItem */
static int hf_x2ap_E_RABs_ToBeModified_ModReqItem_PDU = -1;  /* E_RABs_ToBeModified_ModReqItem */
static int hf_x2ap_E_RABs_ToBeReleased_ModReqItem_PDU = -1;  /* E_RABs_ToBeReleased_ModReqItem */
static int hf_x2ap_SeNBModificationRequestAcknowledge_PDU = -1;  /* SeNBModificationRequestAcknowledge */
static int hf_x2ap_E_RABs_Admitted_ToBeAdded_ModAckList_PDU = -1;  /* E_RABs_Admitted_ToBeAdded_ModAckList */
static int hf_x2ap_E_RABs_Admitted_ToBeAdded_ModAckItem_PDU = -1;  /* E_RABs_Admitted_ToBeAdded_ModAckItem */
static int hf_x2ap_E_RABs_Admitted_ToBeModified_ModAckList_PDU = -1;  /* E_RABs_Admitted_ToBeModified_ModAckList */
static int hf_x2ap_E_RABs_Admitted_ToBeModified_ModAckItem_PDU = -1;  /* E_RABs_Admitted_ToBeModified_ModAckItem */
static int hf_x2ap_E_RABs_Admitted_ToBeReleased_ModAckList_PDU = -1;  /* E_RABs_Admitted_ToBeReleased_ModAckList */
static int hf_x2ap_E_RABs_Admitted_ToReleased_ModAckItem_PDU = -1;  /* E_RABs_Admitted_ToReleased_ModAckItem */
static int hf_x2ap_SeNBModificationRequestReject_PDU = -1;  /* SeNBModificationRequestReject */
static int hf_x2ap_SeNBModificationRequired_PDU = -1;  /* SeNBModificationRequired */
static int hf_x2ap_E_RABs_ToBeReleased_ModReqd_PDU = -1;  /* E_RABs_ToBeReleased_ModReqd */
static int hf_x2ap_E_RABs_ToBeReleased_ModReqdItem_PDU = -1;  /* E_RABs_ToBeReleased_ModReqdItem */
static int hf_x2ap_SeNBModificationConfirm_PDU = -1;  /* SeNBModificationConfirm */
static int hf_x2ap_SeNBModificationRefuse_PDU = -1;  /* SeNBModificationRefuse */
static int hf_x2ap_SeNBReleaseRequest_PDU = -1;   /* SeNBReleaseRequest */
static int hf_x2ap_E_RABs_ToBeReleased_List_RelReq_PDU = -1;  /* E_RABs_ToBeReleased_List_RelReq */
static int hf_x2ap_E_RABs_ToBeReleased_RelReqItem_PDU = -1;  /* E_RABs_ToBeReleased_RelReqItem */
static int hf_x2ap_SeNBReleaseRequired_PDU = -1;  /* SeNBReleaseRequired */
static int hf_x2ap_SeNBReleaseConfirm_PDU = -1;   /* SeNBReleaseConfirm */
static int hf_x2ap_E_RABs_ToBeReleased_List_RelConf_PDU = -1;  /* E_RABs_ToBeReleased_List_RelConf */
static int hf_x2ap_E_RABs_ToBeReleased_RelConfItem_PDU = -1;  /* E_RABs_ToBeReleased_RelConfItem */
static int hf_x2ap_SeNBCounterCheckRequest_PDU = -1;  /* SeNBCounterCheckRequest */
static int hf_x2ap_E_RABs_SubjectToCounterCheck_List_PDU = -1;  /* E_RABs_SubjectToCounterCheck_List */
static int hf_x2ap_E_RABs_SubjectToCounterCheckItem_PDU = -1;  /* E_RABs_SubjectToCounterCheckItem */
static int hf_x2ap_X2RemovalRequest_PDU = -1;     /* X2RemovalRequest */
static int hf_x2ap_X2RemovalResponse_PDU = -1;    /* X2RemovalResponse */
static int hf_x2ap_X2RemovalFailure_PDU = -1;     /* X2RemovalFailure */
static int hf_x2ap_RetrieveUEContextRequest_PDU = -1;  /* RetrieveUEContextRequest */
static int hf_x2ap_RetrieveUEContextResponse_PDU = -1;  /* RetrieveUEContextResponse */
static int hf_x2ap_UE_ContextInformationRetrieve_PDU = -1;  /* UE_ContextInformationRetrieve */
static int hf_x2ap_E_RABs_ToBeSetupRetrieve_Item_PDU = -1;  /* E_RABs_ToBeSetupRetrieve_Item */
static int hf_x2ap_RetrieveUEContextFailure_PDU = -1;  /* RetrieveUEContextFailure */
static int hf_x2ap_X2AP_PDU_PDU = -1;             /* X2AP_PDU */
static int hf_x2ap_local = -1;                    /* INTEGER_0_maxPrivateIEs */
static int hf_x2ap_global = -1;                   /* OBJECT_IDENTIFIER */
static int hf_x2ap_ProtocolIE_Container_item = -1;  /* ProtocolIE_Field */
static int hf_x2ap_id = -1;                       /* ProtocolIE_ID */
static int hf_x2ap_criticality = -1;              /* Criticality */
static int hf_x2ap_protocolIE_Field_value = -1;   /* ProtocolIE_Field_value */
static int hf_x2ap_ProtocolExtensionContainer_item = -1;  /* ProtocolExtensionField */
static int hf_x2ap_extension_id = -1;             /* ProtocolIE_ID */
static int hf_x2ap_extensionValue = -1;           /* T_extensionValue */
static int hf_x2ap_PrivateIE_Container_item = -1;  /* PrivateIE_Field */
static int hf_x2ap_private_id = -1;               /* PrivateIE_ID */
static int hf_x2ap_privateIE_Field_value = -1;    /* PrivateIE_Field_value */
static int hf_x2ap_fdd = -1;                      /* ABSInformationFDD */
static int hf_x2ap_tdd = -1;                      /* ABSInformationTDD */
static int hf_x2ap_abs_inactive = -1;             /* NULL */
static int hf_x2ap_abs_pattern_info = -1;         /* BIT_STRING_SIZE_40 */
static int hf_x2ap_numberOfCellSpecificAntennaPorts = -1;  /* T_numberOfCellSpecificAntennaPorts */
static int hf_x2ap_measurement_subset = -1;       /* BIT_STRING_SIZE_40 */
static int hf_x2ap_iE_Extensions = -1;            /* ProtocolExtensionContainer */
static int hf_x2ap_abs_pattern_info_01 = -1;      /* BIT_STRING_SIZE_1_70_ */
static int hf_x2ap_numberOfCellSpecificAntennaPorts_01 = -1;  /* T_numberOfCellSpecificAntennaPorts_01 */
static int hf_x2ap_measurement_subset_01 = -1;    /* BIT_STRING_SIZE_1_70_ */
static int hf_x2ap_dL_ABS_status = -1;            /* DL_ABS_status */
static int hf_x2ap_usableABSInformation = -1;     /* UsableABSInformation */
static int hf_x2ap_additionalspecialSubframePatterns = -1;  /* AdditionalSpecialSubframePatterns */
static int hf_x2ap_cyclicPrefixDL = -1;           /* CyclicPrefixDL */
static int hf_x2ap_cyclicPrefixUL = -1;           /* CyclicPrefixUL */
static int hf_x2ap_priorityLevel = -1;            /* PriorityLevel */
static int hf_x2ap_pre_emptionCapability = -1;    /* Pre_emptionCapability */
static int hf_x2ap_pre_emptionVulnerability = -1;  /* Pre_emptionVulnerability */
static int hf_x2ap_cellBased = -1;                /* CellBasedMDT */
static int hf_x2ap_tABased = -1;                  /* TABasedMDT */
static int hf_x2ap_pLMNWide = -1;                 /* NULL */
static int hf_x2ap_tAIBased = -1;                 /* TAIBasedMDT */
static int hf_x2ap_key_eNodeB_star = -1;          /* Key_eNodeB_Star */
static int hf_x2ap_nextHopChainingCount = -1;     /* NextHopChainingCount */
static int hf_x2ap_BroadcastPLMNs_Item_item = -1;  /* PLMN_Identity */
static int hf_x2ap_radioNetwork = -1;             /* CauseRadioNetwork */
static int hf_x2ap_transport = -1;                /* CauseTransport */
static int hf_x2ap_protocol = -1;                 /* CauseProtocol */
static int hf_x2ap_misc = -1;                     /* CauseMisc */
static int hf_x2ap_cellIdListforMDT = -1;         /* CellIdListforMDT */
static int hf_x2ap_CellIdListforMDT_item = -1;    /* ECGI */
static int hf_x2ap_replacingCellsList = -1;       /* ReplacingCellsList */
static int hf_x2ap_cell_Size = -1;                /* Cell_Size */
static int hf_x2ap_CoMPHypothesisSet_item = -1;   /* CoMPHypothesisSetItem */
static int hf_x2ap_coMPCellID = -1;               /* ECGI */
static int hf_x2ap_coMPHypothesis = -1;           /* BIT_STRING_SIZE_6_4400_ */
static int hf_x2ap_coMPInformationItem = -1;      /* CoMPInformationItem */
static int hf_x2ap_coMPInformationStartTime = -1;  /* CoMPInformationStartTime */
static int hf_x2ap_CoMPInformationItem_item = -1;  /* CoMPInformationItem_item */
static int hf_x2ap_coMPHypothesisSet = -1;        /* CoMPHypothesisSet */
static int hf_x2ap_benefitMetric = -1;            /* BenefitMetric */
static int hf_x2ap_CoMPInformationStartTime_item = -1;  /* CoMPInformationStartTime_item */
static int hf_x2ap_startSFN = -1;                 /* INTEGER_0_1023_ */
static int hf_x2ap_startSubframeNumber = -1;      /* INTEGER_0_9_ */
static int hf_x2ap_cellCapacityClassValue = -1;   /* CellCapacityClassValue */
static int hf_x2ap_capacityValue = -1;            /* CapacityValue */
static int hf_x2ap_dL_CompositeAvailableCapacity = -1;  /* CompositeAvailableCapacity */
static int hf_x2ap_uL_CompositeAvailableCapacity = -1;  /* CompositeAvailableCapacity */
static int hf_x2ap_pDCP_SN = -1;                  /* PDCP_SN */
static int hf_x2ap_hFN = -1;                      /* HFN */
static int hf_x2ap_pDCP_SNExtended = -1;          /* PDCP_SNExtended */
static int hf_x2ap_hFNModified = -1;              /* HFNModified */
static int hf_x2ap_pDCP_SNlength18 = -1;          /* PDCP_SNlength18 */
static int hf_x2ap_hFNforPDCP_SNlength18 = -1;    /* HFNforPDCP_SNlength18 */
static int hf_x2ap_CoverageModificationList_item = -1;  /* CoverageModification_Item */
static int hf_x2ap_eCGI = -1;                     /* ECGI */
static int hf_x2ap_coverageState = -1;            /* INTEGER_0_15_ */
static int hf_x2ap_cellDeploymentStatusIndicator = -1;  /* CellDeploymentStatusIndicator */
static int hf_x2ap_cellReplacingInfo = -1;        /* CellReplacingInfo */
static int hf_x2ap_procedureCode = -1;            /* ProcedureCode */
static int hf_x2ap_triggeringMessage = -1;        /* TriggeringMessage */
static int hf_x2ap_procedureCriticality = -1;     /* Criticality */
static int hf_x2ap_iEsCriticalityDiagnostics = -1;  /* CriticalityDiagnostics_IE_List */
static int hf_x2ap_CriticalityDiagnostics_IE_List_item = -1;  /* CriticalityDiagnostics_IE_List_item */
static int hf_x2ap_iECriticality = -1;            /* Criticality */
static int hf_x2ap_iE_ID = -1;                    /* ProtocolIE_ID */
static int hf_x2ap_typeOfError = -1;              /* TypeOfError */
static int hf_x2ap_CSIReportList_item = -1;       /* CSIReportList_item */
static int hf_x2ap_uEID = -1;                     /* UEID */
static int hf_x2ap_cSIReportPerCSIProcess = -1;   /* CSIReportPerCSIProcess */
static int hf_x2ap_CSIReportPerCSIProcess_item = -1;  /* CSIReportPerCSIProcess_item */
static int hf_x2ap_cSIProcessConfigurationIndex = -1;  /* INTEGER_1_7_ */
static int hf_x2ap_cSIReportPerCSIProcessItem = -1;  /* CSIReportPerCSIProcessItem */
static int hf_x2ap_CSIReportPerCSIProcessItem_item = -1;  /* CSIReportPerCSIProcessItem_item */
static int hf_x2ap_rI = -1;                       /* INTEGER_1_8_ */
static int hf_x2ap_widebandCQI = -1;              /* WidebandCQI */
static int hf_x2ap_subbandSize = -1;              /* SubbandSize */
static int hf_x2ap_subbandCQIList = -1;           /* SubbandCQIList */
static int hf_x2ap_naics_active = -1;             /* DynamicNAICSInformation */
static int hf_x2ap_naics_inactive = -1;           /* NULL */
static int hf_x2ap_transmissionModes = -1;        /* T_transmissionModes */
static int hf_x2ap_pB_information = -1;           /* INTEGER_0_3 */
static int hf_x2ap_pA_list = -1;                  /* SEQUENCE_SIZE_0_maxnoofPA_OF_PA_Values */
static int hf_x2ap_pA_list_item = -1;             /* PA_Values */
static int hf_x2ap_pLMN_Identity = -1;            /* PLMN_Identity */
static int hf_x2ap_eUTRANcellIdentifier = -1;     /* EUTRANCellIdentifier */
static int hf_x2ap_enhancedRNTPBitmap = -1;       /* BIT_STRING_SIZE_12_8800_ */
static int hf_x2ap_rNTP_High_Power_Threshold = -1;  /* RNTP_Threshold */
static int hf_x2ap_enhancedRNTPStartTime = -1;    /* EnhancedRNTPStartTime */
static int hf_x2ap_macro_eNB_ID = -1;             /* BIT_STRING_SIZE_20 */
static int hf_x2ap_home_eNB_ID = -1;              /* BIT_STRING_SIZE_28 */
static int hf_x2ap_EPLMNs_item = -1;              /* PLMN_Identity */
static int hf_x2ap_qCI = -1;                      /* QCI */
static int hf_x2ap_allocationAndRetentionPriority = -1;  /* AllocationAndRetentionPriority */
static int hf_x2ap_gbrQosInformation = -1;        /* GBR_QosInformation */
static int hf_x2ap_E_RAB_List_item = -1;          /* ProtocolIE_Single_Container */
static int hf_x2ap_e_RAB_ID = -1;                 /* E_RAB_ID */
static int hf_x2ap_cause = -1;                    /* Cause */
static int hf_x2ap_fDD = -1;                      /* FDD_Info */
static int hf_x2ap_tDD = -1;                      /* TDD_Info */
static int hf_x2ap_expectedActivity = -1;         /* ExpectedUEActivityBehaviour */
static int hf_x2ap_expectedHOInterval = -1;       /* ExpectedHOInterval */
static int hf_x2ap_expectedActivityPeriod = -1;   /* ExpectedActivityPeriod */
static int hf_x2ap_expectedIdlePeriod = -1;       /* ExpectedIdlePeriod */
static int hf_x2ap_sourceofUEActivityBehaviourInformation = -1;  /* SourceOfUEActivityBehaviourInformation */
static int hf_x2ap_associatedSubframes = -1;      /* BIT_STRING_SIZE_5 */
static int hf_x2ap_extended_ul_InterferenceOverloadIndication = -1;  /* UL_InterferenceOverloadIndication */
static int hf_x2ap_uL_EARFCN = -1;                /* EARFCN */
static int hf_x2ap_dL_EARFCN = -1;                /* EARFCN */
static int hf_x2ap_uL_Transmission_Bandwidth = -1;  /* Transmission_Bandwidth */
static int hf_x2ap_dL_Transmission_Bandwidth = -1;  /* Transmission_Bandwidth */
static int hf_x2ap_ForbiddenTAs_item = -1;        /* ForbiddenTAs_Item */
static int hf_x2ap_forbiddenTACs = -1;            /* ForbiddenTACs */
static int hf_x2ap_ForbiddenTACs_item = -1;       /* TAC */
static int hf_x2ap_ForbiddenLAs_item = -1;        /* ForbiddenLAs_Item */
static int hf_x2ap_forbiddenLACs = -1;            /* ForbiddenLACs */
static int hf_x2ap_ForbiddenLACs_item = -1;       /* LAC */
static int hf_x2ap_e_RAB_MaximumBitrateDL = -1;   /* BitRate */
static int hf_x2ap_e_RAB_MaximumBitrateUL = -1;   /* BitRate */
static int hf_x2ap_e_RAB_GuaranteedBitrateDL = -1;  /* BitRate */
static int hf_x2ap_e_RAB_GuaranteedBitrateUL = -1;  /* BitRate */
static int hf_x2ap_eNB_ID = -1;                   /* ENB_ID */
static int hf_x2ap_transportLayerAddress = -1;    /* TransportLayerAddress */
static int hf_x2ap_gTP_TEID = -1;                 /* GTP_TEI */
static int hf_x2ap_GUGroupIDList_item = -1;       /* GU_Group_ID */
static int hf_x2ap_mME_Group_ID = -1;             /* MME_Group_ID */
static int hf_x2ap_gU_Group_ID = -1;              /* GU_Group_ID */
static int hf_x2ap_mME_Code = -1;                 /* MME_Code */
static int hf_x2ap_servingPLMN = -1;              /* PLMN_Identity */
static int hf_x2ap_equivalentPLMNs = -1;          /* EPLMNs */
static int hf_x2ap_forbiddenTAs = -1;             /* ForbiddenTAs */
static int hf_x2ap_forbiddenLAs = -1;             /* ForbiddenLAs */
static int hf_x2ap_forbiddenInterRATs = -1;       /* ForbiddenInterRATs */
static int hf_x2ap_dLHWLoadIndicator = -1;        /* LoadIndicator */
static int hf_x2ap_uLHWLoadIndicator = -1;        /* LoadIndicator */
static int hf_x2ap_e_UTRAN_Cell = -1;             /* LastVisitedEUTRANCellInformation */
static int hf_x2ap_uTRAN_Cell = -1;               /* LastVisitedUTRANCellInformation */
static int hf_x2ap_gERAN_Cell = -1;               /* LastVisitedGERANCellInformation */
static int hf_x2ap_global_Cell_ID = -1;           /* ECGI */
static int hf_x2ap_cellType = -1;                 /* CellType */
static int hf_x2ap_time_UE_StayedInCell = -1;     /* Time_UE_StayedInCell */
static int hf_x2ap_undefined = -1;                /* NULL */
static int hf_x2ap_eventType = -1;                /* EventType */
static int hf_x2ap_reportArea = -1;               /* ReportArea */
static int hf_x2ap_reportInterval = -1;           /* ReportIntervalMDT */
static int hf_x2ap_reportAmount = -1;             /* ReportAmountMDT */
static int hf_x2ap_measurementThreshold = -1;     /* MeasurementThresholdA2 */
static int hf_x2ap_m3period = -1;                 /* M3period */
static int hf_x2ap_m4period = -1;                 /* M4period */
static int hf_x2ap_m4_links_to_log = -1;          /* Links_to_log */
static int hf_x2ap_m5period = -1;                 /* M5period */
static int hf_x2ap_m5_links_to_log = -1;          /* Links_to_log */
static int hf_x2ap_m6report_interval = -1;        /* M6report_interval */
static int hf_x2ap_m6delay_threshold = -1;        /* M6delay_threshold */
static int hf_x2ap_m6_links_to_log = -1;          /* Links_to_log */
static int hf_x2ap_m7period = -1;                 /* M7period */
static int hf_x2ap_m7_links_to_log = -1;          /* Links_to_log */
static int hf_x2ap_mdt_Activation = -1;           /* MDT_Activation */
static int hf_x2ap_areaScopeOfMDT = -1;           /* AreaScopeOfMDT */
static int hf_x2ap_measurementsToActivate = -1;   /* MeasurementsToActivate */
static int hf_x2ap_m1reportingTrigger = -1;       /* M1ReportingTrigger */
static int hf_x2ap_m1thresholdeventA2 = -1;       /* M1ThresholdEventA2 */
static int hf_x2ap_m1periodicReporting = -1;      /* M1PeriodicReporting */
static int hf_x2ap_MDTPLMNList_item = -1;         /* PLMN_Identity */
static int hf_x2ap_threshold_RSRP = -1;           /* Threshold_RSRP */
static int hf_x2ap_threshold_RSRQ = -1;           /* Threshold_RSRQ */
static int hf_x2ap_MBMS_Service_Area_Identity_List_item = -1;  /* MBMS_Service_Area_Identity */
static int hf_x2ap_MBSFN_Subframe_Infolist_item = -1;  /* MBSFN_Subframe_Info */
static int hf_x2ap_radioframeAllocationPeriod = -1;  /* RadioframeAllocationPeriod */
static int hf_x2ap_radioframeAllocationOffset = -1;  /* RadioframeAllocationOffset */
static int hf_x2ap_subframeAllocation = -1;       /* SubframeAllocation */
static int hf_x2ap_handoverTriggerChangeLowerLimit = -1;  /* INTEGER_M20_20 */
static int hf_x2ap_handoverTriggerChangeUpperLimit = -1;  /* INTEGER_M20_20 */
static int hf_x2ap_handoverTriggerChange = -1;    /* INTEGER_M20_20 */
static int hf_x2ap_MultibandInfoList_item = -1;   /* BandInfo */
static int hf_x2ap_freqBandIndicator = -1;        /* FreqBandIndicator */
static int hf_x2ap_Neighbour_Information_item = -1;  /* Neighbour_Information_item */
static int hf_x2ap_pCI = -1;                      /* PCI */
static int hf_x2ap_eARFCN = -1;                   /* EARFCN */
static int hf_x2ap_rootSequenceIndex = -1;        /* INTEGER_0_837 */
static int hf_x2ap_zeroCorrelationIndex = -1;     /* INTEGER_0_15 */
static int hf_x2ap_highSpeedFlag = -1;            /* BOOLEAN */
static int hf_x2ap_prach_FreqOffset = -1;         /* INTEGER_0_94 */
static int hf_x2ap_prach_ConfigIndex = -1;        /* INTEGER_0_63 */
static int hf_x2ap_proSeDirectDiscovery = -1;     /* ProSeDirectDiscovery */
static int hf_x2ap_proSeDirectCommunication = -1;  /* ProSeDirectCommunication */
static int hf_x2ap_dL_GBR_PRB_usage = -1;         /* DL_GBR_PRB_usage */
static int hf_x2ap_uL_GBR_PRB_usage = -1;         /* UL_GBR_PRB_usage */
static int hf_x2ap_dL_non_GBR_PRB_usage = -1;     /* DL_non_GBR_PRB_usage */
static int hf_x2ap_uL_non_GBR_PRB_usage = -1;     /* UL_non_GBR_PRB_usage */
static int hf_x2ap_dL_Total_PRB_usage = -1;       /* DL_Total_PRB_usage */
static int hf_x2ap_uL_Total_PRB_usage = -1;       /* UL_Total_PRB_usage */
static int hf_x2ap_rNTP_PerPRB = -1;              /* BIT_STRING_SIZE_6_110_ */
static int hf_x2ap_rNTP_Threshold = -1;           /* RNTP_Threshold */
static int hf_x2ap_numberOfCellSpecificAntennaPorts_02 = -1;  /* T_numberOfCellSpecificAntennaPorts_02 */
static int hf_x2ap_p_B = -1;                      /* INTEGER_0_3_ */
static int hf_x2ap_pDCCH_InterferenceImpact = -1;  /* INTEGER_0_4_ */
static int hf_x2ap_ReplacingCellsList_item = -1;  /* ReplacingCellsList_Item */
static int hf_x2ap_non_truncated = -1;            /* BIT_STRING_SIZE_40 */
static int hf_x2ap_truncated = -1;                /* BIT_STRING_SIZE_24 */
static int hf_x2ap_RSRPMeasurementResult_item = -1;  /* RSRPMeasurementResult_item */
static int hf_x2ap_rSRPCellID = -1;               /* ECGI */
static int hf_x2ap_rSRPMeasured = -1;             /* INTEGER_0_97_ */
static int hf_x2ap_RSRPMRList_item = -1;          /* RSRPMRList_item */
static int hf_x2ap_rSRPMeasurementResult = -1;    /* RSRPMeasurementResult */
static int hf_x2ap_dLS1TNLLoadIndicator = -1;     /* LoadIndicator */
static int hf_x2ap_uLS1TNLLoadIndicator = -1;     /* LoadIndicator */
static int hf_x2ap_ServedCells_item = -1;         /* ServedCells_item */
static int hf_x2ap_servedCellInfo = -1;           /* ServedCell_Information */
static int hf_x2ap_neighbour_Info = -1;           /* Neighbour_Information */
static int hf_x2ap_cellId = -1;                   /* ECGI */
static int hf_x2ap_tAC = -1;                      /* TAC */
static int hf_x2ap_broadcastPLMNs = -1;           /* BroadcastPLMNs_Item */
static int hf_x2ap_eUTRA_Mode_Info = -1;          /* EUTRA_Mode_Info */
static int hf_x2ap_specialSubframePatterns = -1;  /* SpecialSubframePatterns */
static int hf_x2ap_subbandCQICodeword0 = -1;      /* SubbandCQICodeword0 */
static int hf_x2ap_subbandCQICodeword1 = -1;      /* SubbandCQICodeword1 */
static int hf_x2ap_four_bitCQI = -1;              /* INTEGER_0_15_ */
static int hf_x2ap_two_bitSubbandDifferentialCQI = -1;  /* INTEGER_0_3_ */
static int hf_x2ap_two_bitDifferentialCQI = -1;   /* INTEGER_0_3_ */
static int hf_x2ap_three_bitSpatialDifferentialCQI = -1;  /* INTEGER_0_7_ */
static int hf_x2ap_SubbandCQIList_item = -1;      /* SubbandCQIItem */
static int hf_x2ap_subbandCQI = -1;               /* SubbandCQI */
static int hf_x2ap_subbandIndex = -1;             /* INTEGER_0_27_ */
static int hf_x2ap_oneframe = -1;                 /* Oneframe */
static int hf_x2ap_fourframes = -1;               /* Fourframes */
static int hf_x2ap_tAListforMDT = -1;             /* TAListforMDT */
static int hf_x2ap_tAIListforMDT = -1;            /* TAIListforMDT */
static int hf_x2ap_TAIListforMDT_item = -1;       /* TAI_Item */
static int hf_x2ap_TAListforMDT_item = -1;        /* TAC */
static int hf_x2ap_transmission_Bandwidth = -1;   /* Transmission_Bandwidth */
static int hf_x2ap_subframeAssignment = -1;       /* SubframeAssignment */
static int hf_x2ap_specialSubframe_Info = -1;     /* SpecialSubframe_Info */
static int hf_x2ap_eUTRANTraceID = -1;            /* EUTRANTraceID */
static int hf_x2ap_interfacesToTrace = -1;        /* InterfacesToTrace */
static int hf_x2ap_traceDepth = -1;               /* TraceDepth */
static int hf_x2ap_traceCollectionEntityIPAddress = -1;  /* TraceCollectionEntityIPAddress */
static int hf_x2ap_uDP_Port_Number = -1;          /* Port_Number */
static int hf_x2ap_uEaggregateMaximumBitRateDownlink = -1;  /* BitRate */
static int hf_x2ap_uEaggregateMaximumBitRateUplink = -1;  /* BitRate */
static int hf_x2ap_UE_HistoryInformation_item = -1;  /* LastVisitedCell_Item */
static int hf_x2ap_encryptionAlgorithms = -1;     /* EncryptionAlgorithms */
static int hf_x2ap_integrityProtectionAlgorithms = -1;  /* IntegrityProtectionAlgorithms */
static int hf_x2ap_UL_HighInterferenceIndicationInfo_item = -1;  /* UL_HighInterferenceIndicationInfo_Item */
static int hf_x2ap_target_Cell_ID = -1;           /* ECGI */
static int hf_x2ap_ul_interferenceindication = -1;  /* UL_HighInterferenceIndication */
static int hf_x2ap_UL_InterferenceOverloadIndication_item = -1;  /* UL_InterferenceOverloadIndication_Item */
static int hf_x2ap_fdd_01 = -1;                   /* UsableABSInformationFDD */
static int hf_x2ap_tdd_01 = -1;                   /* UsableABSInformationTDD */
static int hf_x2ap_usable_abs_pattern_info = -1;  /* BIT_STRING_SIZE_40 */
static int hf_x2ap_usaable_abs_pattern_info = -1;  /* BIT_STRING_SIZE_1_70_ */
static int hf_x2ap_widebandCQICodeword0 = -1;     /* INTEGER_0_15_ */
static int hf_x2ap_widebandCQICodeword1 = -1;     /* WidebandCQICodeword1 */
static int hf_x2ap_protocolIEs = -1;              /* ProtocolIE_Container */
static int hf_x2ap_mME_UE_S1AP_ID = -1;           /* UE_S1AP_ID */
static int hf_x2ap_uESecurityCapabilities = -1;   /* UESecurityCapabilities */
static int hf_x2ap_aS_SecurityInformation = -1;   /* AS_SecurityInformation */
static int hf_x2ap_uEaggregateMaximumBitRate = -1;  /* UEAggregateMaximumBitRate */
static int hf_x2ap_subscriberProfileIDforRFP = -1;  /* SubscriberProfileIDforRFP */
static int hf_x2ap_e_RABs_ToBeSetup_List = -1;    /* E_RABs_ToBeSetup_List */
static int hf_x2ap_rRC_Context = -1;              /* RRC_Context */
static int hf_x2ap_handoverRestrictionList = -1;  /* HandoverRestrictionList */
static int hf_x2ap_locationReportingInformation = -1;  /* LocationReportingInformation */
static int hf_x2ap_E_RABs_ToBeSetup_List_item = -1;  /* ProtocolIE_Single_Container */
static int hf_x2ap_e_RAB_Level_QoS_Parameters = -1;  /* E_RAB_Level_QoS_Parameters */
static int hf_x2ap_dL_Forwarding = -1;            /* DL_Forwarding */
static int hf_x2ap_uL_GTPtunnelEndpoint = -1;     /* GTPtunnelEndpoint */
static int hf_x2ap_source_GlobalSeNB_ID = -1;     /* GlobalENB_ID */
static int hf_x2ap_seNB_UE_X2AP_ID = -1;          /* UE_X2AP_ID */
static int hf_x2ap_seNB_UE_X2AP_ID_Extension = -1;  /* UE_X2AP_ID_Extension */
static int hf_x2ap_E_RABs_Admitted_List_item = -1;  /* ProtocolIE_Single_Container */
static int hf_x2ap_uL_GTP_TunnelEndpoint = -1;    /* GTPtunnelEndpoint */
static int hf_x2ap_dL_GTP_TunnelEndpoint = -1;    /* GTPtunnelEndpoint */
static int hf_x2ap_E_RABs_SubjectToStatusTransfer_List_item = -1;  /* ProtocolIE_Single_Container */
static int hf_x2ap_receiveStatusofULPDCPSDUs = -1;  /* ReceiveStatusofULPDCPSDUs */
static int hf_x2ap_uL_COUNTvalue = -1;            /* COUNTvalue */
static int hf_x2ap_dL_COUNTvalue = -1;            /* COUNTvalue */
static int hf_x2ap_CellInformation_List_item = -1;  /* ProtocolIE_Single_Container */
static int hf_x2ap_cell_ID = -1;                  /* ECGI */
static int hf_x2ap_ul_InterferenceOverloadIndication = -1;  /* UL_InterferenceOverloadIndication */
static int hf_x2ap_ul_HighInterferenceIndicationInfo = -1;  /* UL_HighInterferenceIndicationInfo */
static int hf_x2ap_relativeNarrowbandTxPower = -1;  /* RelativeNarrowbandTxPower */
static int hf_x2ap_ServedCellsToModify_item = -1;  /* ServedCellsToModify_Item */
static int hf_x2ap_old_ecgi = -1;                 /* ECGI */
static int hf_x2ap_Old_ECGIs_item = -1;           /* ECGI */
static int hf_x2ap_CellToReport_List_item = -1;   /* ProtocolIE_Single_Container */
static int hf_x2ap_MeasurementInitiationResult_List_item = -1;  /* ProtocolIE_Single_Container */
static int hf_x2ap_measurementFailureCause_List = -1;  /* MeasurementFailureCause_List */
static int hf_x2ap_MeasurementFailureCause_List_item = -1;  /* ProtocolIE_Single_Container */
static int hf_x2ap_measurementFailedReportCharacteristics = -1;  /* T_measurementFailedReportCharacteristics */
static int hf_x2ap_CompleteFailureCauseInformation_List_item = -1;  /* ProtocolIE_Single_Container */
static int hf_x2ap_CellMeasurementResult_List_item = -1;  /* ProtocolIE_Single_Container */
static int hf_x2ap_hWLoadIndicator = -1;          /* HWLoadIndicator */
static int hf_x2ap_s1TNLLoadIndicator = -1;       /* S1TNLLoadIndicator */
static int hf_x2ap_radioResourceStatus = -1;      /* RadioResourceStatus */
static int hf_x2ap_privateIEs = -1;               /* PrivateIE_Container */
static int hf_x2ap_ServedCellsToActivate_item = -1;  /* ServedCellsToActivate_Item */
static int hf_x2ap_ecgi = -1;                     /* ECGI */
static int hf_x2ap_ActivatedCellList_item = -1;   /* ActivatedCellList_Item */
static int hf_x2ap_source_GlobalENB_ID = -1;      /* GlobalENB_ID */
static int hf_x2ap_target_GlobalENB_ID = -1;      /* GlobalENB_ID */
static int hf_x2ap_E_RABs_ToBeAdded_List_item = -1;  /* ProtocolIE_Single_Container */
static int hf_x2ap_sCG_Bearer = -1;               /* E_RABs_ToBeAdded_Item_SCG_Bearer */
static int hf_x2ap_split_Bearer = -1;             /* E_RABs_ToBeAdded_Item_Split_Bearer */
static int hf_x2ap_s1_UL_GTPtunnelEndpoint = -1;  /* GTPtunnelEndpoint */
static int hf_x2ap_meNB_GTPtunnelEndpoint = -1;   /* GTPtunnelEndpoint */
static int hf_x2ap_E_RABs_Admitted_ToBeAdded_List_item = -1;  /* ProtocolIE_Single_Container */
static int hf_x2ap_sCG_Bearer_01 = -1;            /* E_RABs_Admitted_ToBeAdded_Item_SCG_Bearer */
static int hf_x2ap_split_Bearer_01 = -1;          /* E_RABs_Admitted_ToBeAdded_Item_Split_Bearer */
static int hf_x2ap_s1_DL_GTPtunnelEndpoint = -1;  /* GTPtunnelEndpoint */
static int hf_x2ap_dL_Forwarding_GTPtunnelEndpoint = -1;  /* GTPtunnelEndpoint */
static int hf_x2ap_uL_Forwarding_GTPtunnelEndpoint = -1;  /* GTPtunnelEndpoint */
static int hf_x2ap_seNB_GTPtunnelEndpoint = -1;   /* GTPtunnelEndpoint */
static int hf_x2ap_success = -1;                  /* ResponseInformationSeNBReconfComp_SuccessItem */
static int hf_x2ap_reject_by_MeNB = -1;           /* ResponseInformationSeNBReconfComp_RejectByMeNBItem */
static int hf_x2ap_meNBtoSeNBContainer = -1;      /* MeNBtoSeNBContainer */
static int hf_x2ap_uE_SecurityCapabilities = -1;  /* UESecurityCapabilities */
static int hf_x2ap_seNB_SecurityKey = -1;         /* SeNBSecurityKey */
static int hf_x2ap_seNBUEAggregateMaximumBitRate = -1;  /* UEAggregateMaximumBitRate */
static int hf_x2ap_e_RABs_ToBeAdded = -1;         /* E_RABs_ToBeAdded_List_ModReq */
static int hf_x2ap_e_RABs_ToBeModified = -1;      /* E_RABs_ToBeModified_List_ModReq */
static int hf_x2ap_e_RABs_ToBeReleased = -1;      /* E_RABs_ToBeReleased_List_ModReq */
static int hf_x2ap_E_RABs_ToBeAdded_List_ModReq_item = -1;  /* ProtocolIE_Single_Container */
static int hf_x2ap_sCG_Bearer_02 = -1;            /* E_RABs_ToBeAdded_ModReqItem_SCG_Bearer */
static int hf_x2ap_split_Bearer_02 = -1;          /* E_RABs_ToBeAdded_ModReqItem_Split_Bearer */
static int hf_x2ap_E_RABs_ToBeModified_List_ModReq_item = -1;  /* ProtocolIE_Single_Container */
static int hf_x2ap_sCG_Bearer_03 = -1;            /* E_RABs_ToBeModified_ModReqItem_SCG_Bearer */
static int hf_x2ap_split_Bearer_03 = -1;          /* E_RABs_ToBeModified_ModReqItem_Split_Bearer */
static int hf_x2ap_E_RABs_ToBeReleased_List_ModReq_item = -1;  /* ProtocolIE_Single_Container */
static int hf_x2ap_sCG_Bearer_04 = -1;            /* E_RABs_ToBeReleased_ModReqItem_SCG_Bearer */
static int hf_x2ap_split_Bearer_04 = -1;          /* E_RABs_ToBeReleased_ModReqItem_Split_Bearer */
static int hf_x2ap_dL_GTPtunnelEndpoint = -1;     /* GTPtunnelEndpoint */
static int hf_x2ap_E_RABs_Admitted_ToBeAdded_ModAckList_item = -1;  /* ProtocolIE_Single_Container */
static int hf_x2ap_sCG_Bearer_05 = -1;            /* E_RABs_Admitted_ToBeAdded_ModAckItem_SCG_Bearer */
static int hf_x2ap_split_Bearer_05 = -1;          /* E_RABs_Admitted_ToBeAdded_ModAckItem_Split_Bearer */
static int hf_x2ap_E_RABs_Admitted_ToBeModified_ModAckList_item = -1;  /* ProtocolIE_Single_Container */
static int hf_x2ap_sCG_Bearer_06 = -1;            /* E_RABs_Admitted_ToBeModified_ModAckItem_SCG_Bearer */
static int hf_x2ap_split_Bearer_06 = -1;          /* E_RABs_Admitted_ToBeModified_ModAckItem_Split_Bearer */
static int hf_x2ap_E_RABs_Admitted_ToBeReleased_ModAckList_item = -1;  /* ProtocolIE_Single_Container */
static int hf_x2ap_sCG_Bearer_07 = -1;            /* E_RABs_Admitted_ToBeReleased_ModAckItem_SCG_Bearer */
static int hf_x2ap_split_Bearer_07 = -1;          /* E_RABs_Admitted_ToBeReleased_ModAckItem_Split_Bearer */
static int hf_x2ap_E_RABs_ToBeReleased_ModReqd_item = -1;  /* ProtocolIE_Single_Container */
static int hf_x2ap_E_RABs_ToBeReleased_List_RelReq_item = -1;  /* ProtocolIE_Single_Container */
static int hf_x2ap_sCG_Bearer_08 = -1;            /* E_RABs_ToBeReleased_RelReqItem_SCG_Bearer */
static int hf_x2ap_split_Bearer_08 = -1;          /* E_RABs_ToBeReleased_RelReqItem_Split_Bearer */
static int hf_x2ap_E_RABs_ToBeReleased_List_RelConf_item = -1;  /* ProtocolIE_Single_Container */
static int hf_x2ap_sCG_Bearer_09 = -1;            /* E_RABs_ToBeReleased_RelConfItem_SCG_Bearer */
static int hf_x2ap_split_Bearer_09 = -1;          /* E_RABs_ToBeReleased_RelConfItem_Split_Bearer */
static int hf_x2ap_E_RABs_SubjectToCounterCheck_List_item = -1;  /* ProtocolIE_Single_Container */
static int hf_x2ap_uL_Count = -1;                 /* INTEGER_0_4294967295 */
static int hf_x2ap_dL_Count = -1;                 /* INTEGER_0_4294967295 */
static int hf_x2ap_e_RABs_ToBeSetup_ListRetrieve = -1;  /* E_RABs_ToBeSetup_ListRetrieve */
static int hf_x2ap_managBasedMDTallowed = -1;     /* ManagementBasedMDTallowed */
static int hf_x2ap_managBasedMDTPLMNList = -1;    /* MDTPLMNList */
static int hf_x2ap_E_RABs_ToBeSetup_ListRetrieve_item = -1;  /* ProtocolIE_Single_Container */
static int hf_x2ap_bearerType = -1;               /* BearerType */
static int hf_x2ap_initiatingMessage = -1;        /* InitiatingMessage */
static int hf_x2ap_successfulOutcome = -1;        /* SuccessfulOutcome */
static int hf_x2ap_unsuccessfulOutcome = -1;      /* UnsuccessfulOutcome */
static int hf_x2ap_initiatingMessage_value = -1;  /* InitiatingMessage_value */
static int hf_x2ap_successfulOutcome_value = -1;  /* SuccessfulOutcome_value */
static int hf_x2ap_value = -1;                    /* UnsuccessfulOutcome_value */

/*--- End of included file: packet-x2ap-hf.c ---*/
#line 115 "./asn1/x2ap/packet-x2ap-template.c"

/* Initialize the subtree pointers */
static int ett_x2ap = -1;
static int ett_x2ap_TransportLayerAddress = -1;
static int ett_x2ap_PLMN_Identity = -1;
static int ett_x2ap_TargeteNBtoSource_eNBTransparentContainer = -1;
static int ett_x2ap_RRC_Context = -1;
static int ett_x2ap_UE_HistoryInformationFromTheUE = -1;
static int ett_x2ap_ReportCharacteristics = -1;
static int ett_x2ap_measurementFailedReportCharacteristics = -1;
static int ett_x2ap_UE_RLF_Report_Container = -1;
static int ett_x2ap_UE_RLF_Report_Container_for_extended_bands = -1;
static int ett_x2ap_MeNBtoSeNBContainer = -1;
static int ett_x2ap_SeNBtoMeNBContainer = -1;
static int ett_x2ap_EUTRANTraceID = -1;
static int ett_x2ap_InterfacesToTrace = -1;
static int ett_x2ap_TraceCollectionEntityIPAddress = -1;
static int ett_x2ap_EncryptionAlgorithms = -1;
static int ett_x2ap_IntegrityProtectionAlgorithms = -1;
static int ett_x2ap_MeasurementsToActivate = -1;
static int ett_x2ap_MDT_Location_Info = -1;
static int ett_x2ap_transmissionModes = -1;
static int ett_x2ap_X2AP_Message = -1;

/*--- Included file: packet-x2ap-ett.c ---*/
#line 1 "./asn1/x2ap/packet-x2ap-ett.c"
static gint ett_x2ap_PrivateIE_ID = -1;
static gint ett_x2ap_ProtocolIE_Container = -1;
static gint ett_x2ap_ProtocolIE_Field = -1;
static gint ett_x2ap_ProtocolExtensionContainer = -1;
static gint ett_x2ap_ProtocolExtensionField = -1;
static gint ett_x2ap_PrivateIE_Container = -1;
static gint ett_x2ap_PrivateIE_Field = -1;
static gint ett_x2ap_ABSInformation = -1;
static gint ett_x2ap_ABSInformationFDD = -1;
static gint ett_x2ap_ABSInformationTDD = -1;
static gint ett_x2ap_ABS_Status = -1;
static gint ett_x2ap_AdditionalSpecialSubframe_Info = -1;
static gint ett_x2ap_AllocationAndRetentionPriority = -1;
static gint ett_x2ap_AreaScopeOfMDT = -1;
static gint ett_x2ap_AS_SecurityInformation = -1;
static gint ett_x2ap_BroadcastPLMNs_Item = -1;
static gint ett_x2ap_Cause = -1;
static gint ett_x2ap_CellBasedMDT = -1;
static gint ett_x2ap_CellIdListforMDT = -1;
static gint ett_x2ap_CellReplacingInfo = -1;
static gint ett_x2ap_CellType = -1;
static gint ett_x2ap_CoMPHypothesisSet = -1;
static gint ett_x2ap_CoMPHypothesisSetItem = -1;
static gint ett_x2ap_CoMPInformation = -1;
static gint ett_x2ap_CoMPInformationItem = -1;
static gint ett_x2ap_CoMPInformationItem_item = -1;
static gint ett_x2ap_CoMPInformationStartTime = -1;
static gint ett_x2ap_CoMPInformationStartTime_item = -1;
static gint ett_x2ap_CompositeAvailableCapacity = -1;
static gint ett_x2ap_CompositeAvailableCapacityGroup = -1;
static gint ett_x2ap_COUNTvalue = -1;
static gint ett_x2ap_COUNTValueExtended = -1;
static gint ett_x2ap_COUNTvaluePDCP_SNlength18 = -1;
static gint ett_x2ap_CoverageModificationList = -1;
static gint ett_x2ap_CoverageModification_Item = -1;
static gint ett_x2ap_CriticalityDiagnostics = -1;
static gint ett_x2ap_CriticalityDiagnostics_IE_List = -1;
static gint ett_x2ap_CriticalityDiagnostics_IE_List_item = -1;
static gint ett_x2ap_CSIReportList = -1;
static gint ett_x2ap_CSIReportList_item = -1;
static gint ett_x2ap_CSIReportPerCSIProcess = -1;
static gint ett_x2ap_CSIReportPerCSIProcess_item = -1;
static gint ett_x2ap_CSIReportPerCSIProcessItem = -1;
static gint ett_x2ap_CSIReportPerCSIProcessItem_item = -1;
static gint ett_x2ap_DynamicDLTransmissionInformation = -1;
static gint ett_x2ap_DynamicNAICSInformation = -1;
static gint ett_x2ap_SEQUENCE_SIZE_0_maxnoofPA_OF_PA_Values = -1;
static gint ett_x2ap_ECGI = -1;
static gint ett_x2ap_EnhancedRNTP = -1;
static gint ett_x2ap_EnhancedRNTPStartTime = -1;
static gint ett_x2ap_ENB_ID = -1;
static gint ett_x2ap_EPLMNs = -1;
static gint ett_x2ap_E_RAB_Level_QoS_Parameters = -1;
static gint ett_x2ap_E_RAB_List = -1;
static gint ett_x2ap_E_RAB_Item = -1;
static gint ett_x2ap_EUTRA_Mode_Info = -1;
static gint ett_x2ap_ExpectedUEBehaviour = -1;
static gint ett_x2ap_ExpectedUEActivityBehaviour = -1;
static gint ett_x2ap_ExtendedULInterferenceOverloadInfo = -1;
static gint ett_x2ap_FDD_Info = -1;
static gint ett_x2ap_ForbiddenTAs = -1;
static gint ett_x2ap_ForbiddenTAs_Item = -1;
static gint ett_x2ap_ForbiddenTACs = -1;
static gint ett_x2ap_ForbiddenLAs = -1;
static gint ett_x2ap_ForbiddenLAs_Item = -1;
static gint ett_x2ap_ForbiddenLACs = -1;
static gint ett_x2ap_GBR_QosInformation = -1;
static gint ett_x2ap_GlobalENB_ID = -1;
static gint ett_x2ap_GTPtunnelEndpoint = -1;
static gint ett_x2ap_GUGroupIDList = -1;
static gint ett_x2ap_GU_Group_ID = -1;
static gint ett_x2ap_GUMMEI = -1;
static gint ett_x2ap_HandoverRestrictionList = -1;
static gint ett_x2ap_HWLoadIndicator = -1;
static gint ett_x2ap_LastVisitedCell_Item = -1;
static gint ett_x2ap_LastVisitedEUTRANCellInformation = -1;
static gint ett_x2ap_LastVisitedGERANCellInformation = -1;
static gint ett_x2ap_LocationReportingInformation = -1;
static gint ett_x2ap_M1PeriodicReporting = -1;
static gint ett_x2ap_M1ThresholdEventA2 = -1;
static gint ett_x2ap_M3Configuration = -1;
static gint ett_x2ap_M4Configuration = -1;
static gint ett_x2ap_M5Configuration = -1;
static gint ett_x2ap_M6Configuration = -1;
static gint ett_x2ap_M7Configuration = -1;
static gint ett_x2ap_MDT_Configuration = -1;
static gint ett_x2ap_MDTPLMNList = -1;
static gint ett_x2ap_MeasurementThresholdA2 = -1;
static gint ett_x2ap_MBMS_Service_Area_Identity_List = -1;
static gint ett_x2ap_MBSFN_Subframe_Infolist = -1;
static gint ett_x2ap_MBSFN_Subframe_Info = -1;
static gint ett_x2ap_MobilityParametersModificationRange = -1;
static gint ett_x2ap_MobilityParametersInformation = -1;
static gint ett_x2ap_MultibandInfoList = -1;
static gint ett_x2ap_BandInfo = -1;
static gint ett_x2ap_Neighbour_Information = -1;
static gint ett_x2ap_Neighbour_Information_item = -1;
static gint ett_x2ap_PRACH_Configuration = -1;
static gint ett_x2ap_ProSeAuthorized = -1;
static gint ett_x2ap_RadioResourceStatus = -1;
static gint ett_x2ap_RelativeNarrowbandTxPower = -1;
static gint ett_x2ap_ReplacingCellsList = -1;
static gint ett_x2ap_ReplacingCellsList_Item = -1;
static gint ett_x2ap_ResumeID = -1;
static gint ett_x2ap_RSRPMeasurementResult = -1;
static gint ett_x2ap_RSRPMeasurementResult_item = -1;
static gint ett_x2ap_RSRPMRList = -1;
static gint ett_x2ap_RSRPMRList_item = -1;
static gint ett_x2ap_S1TNLLoadIndicator = -1;
static gint ett_x2ap_ServedCells = -1;
static gint ett_x2ap_ServedCells_item = -1;
static gint ett_x2ap_ServedCell_Information = -1;
static gint ett_x2ap_SpecialSubframe_Info = -1;
static gint ett_x2ap_SubbandCQI = -1;
static gint ett_x2ap_SubbandCQICodeword0 = -1;
static gint ett_x2ap_SubbandCQICodeword1 = -1;
static gint ett_x2ap_SubbandCQIList = -1;
static gint ett_x2ap_SubbandCQIItem = -1;
static gint ett_x2ap_SubframeAllocation = -1;
static gint ett_x2ap_TABasedMDT = -1;
static gint ett_x2ap_TAIBasedMDT = -1;
static gint ett_x2ap_TAIListforMDT = -1;
static gint ett_x2ap_TAI_Item = -1;
static gint ett_x2ap_TAListforMDT = -1;
static gint ett_x2ap_TDD_Info = -1;
static gint ett_x2ap_TraceActivation = -1;
static gint ett_x2ap_TunnelInformation = -1;
static gint ett_x2ap_UEAggregateMaximumBitRate = -1;
static gint ett_x2ap_UE_HistoryInformation = -1;
static gint ett_x2ap_UESecurityCapabilities = -1;
static gint ett_x2ap_UL_HighInterferenceIndicationInfo = -1;
static gint ett_x2ap_UL_HighInterferenceIndicationInfo_Item = -1;
static gint ett_x2ap_UL_InterferenceOverloadIndication = -1;
static gint ett_x2ap_UsableABSInformation = -1;
static gint ett_x2ap_UsableABSInformationFDD = -1;
static gint ett_x2ap_UsableABSInformationTDD = -1;
static gint ett_x2ap_WidebandCQI = -1;
static gint ett_x2ap_WidebandCQICodeword1 = -1;
static gint ett_x2ap_HandoverRequest = -1;
static gint ett_x2ap_UE_ContextInformation = -1;
static gint ett_x2ap_E_RABs_ToBeSetup_List = -1;
static gint ett_x2ap_E_RABs_ToBeSetup_Item = -1;
static gint ett_x2ap_UE_ContextReferenceAtSeNB = -1;
static gint ett_x2ap_HandoverRequestAcknowledge = -1;
static gint ett_x2ap_E_RABs_Admitted_List = -1;
static gint ett_x2ap_E_RABs_Admitted_Item = -1;
static gint ett_x2ap_HandoverPreparationFailure = -1;
static gint ett_x2ap_HandoverReport = -1;
static gint ett_x2ap_SNStatusTransfer = -1;
static gint ett_x2ap_E_RABs_SubjectToStatusTransfer_List = -1;
static gint ett_x2ap_E_RABs_SubjectToStatusTransfer_Item = -1;
static gint ett_x2ap_UEContextRelease = -1;
static gint ett_x2ap_HandoverCancel = -1;
static gint ett_x2ap_ErrorIndication = -1;
static gint ett_x2ap_ResetRequest = -1;
static gint ett_x2ap_ResetResponse = -1;
static gint ett_x2ap_X2SetupRequest = -1;
static gint ett_x2ap_X2SetupResponse = -1;
static gint ett_x2ap_X2SetupFailure = -1;
static gint ett_x2ap_LoadInformation = -1;
static gint ett_x2ap_CellInformation_List = -1;
static gint ett_x2ap_CellInformation_Item = -1;
static gint ett_x2ap_ENBConfigurationUpdate = -1;
static gint ett_x2ap_ServedCellsToModify = -1;
static gint ett_x2ap_ServedCellsToModify_Item = -1;
static gint ett_x2ap_Old_ECGIs = -1;
static gint ett_x2ap_ENBConfigurationUpdateAcknowledge = -1;
static gint ett_x2ap_ENBConfigurationUpdateFailure = -1;
static gint ett_x2ap_ResourceStatusRequest = -1;
static gint ett_x2ap_CellToReport_List = -1;
static gint ett_x2ap_CellToReport_Item = -1;
static gint ett_x2ap_ResourceStatusResponse = -1;
static gint ett_x2ap_MeasurementInitiationResult_List = -1;
static gint ett_x2ap_MeasurementInitiationResult_Item = -1;
static gint ett_x2ap_MeasurementFailureCause_List = -1;
static gint ett_x2ap_MeasurementFailureCause_Item = -1;
static gint ett_x2ap_ResourceStatusFailure = -1;
static gint ett_x2ap_CompleteFailureCauseInformation_List = -1;
static gint ett_x2ap_CompleteFailureCauseInformation_Item = -1;
static gint ett_x2ap_ResourceStatusUpdate = -1;
static gint ett_x2ap_CellMeasurementResult_List = -1;
static gint ett_x2ap_CellMeasurementResult_Item = -1;
static gint ett_x2ap_PrivateMessage = -1;
static gint ett_x2ap_MobilityChangeRequest = -1;
static gint ett_x2ap_MobilityChangeAcknowledge = -1;
static gint ett_x2ap_MobilityChangeFailure = -1;
static gint ett_x2ap_RLFIndication = -1;
static gint ett_x2ap_CellActivationRequest = -1;
static gint ett_x2ap_ServedCellsToActivate = -1;
static gint ett_x2ap_ServedCellsToActivate_Item = -1;
static gint ett_x2ap_CellActivationResponse = -1;
static gint ett_x2ap_ActivatedCellList = -1;
static gint ett_x2ap_ActivatedCellList_Item = -1;
static gint ett_x2ap_CellActivationFailure = -1;
static gint ett_x2ap_X2Release = -1;
static gint ett_x2ap_X2APMessageTransfer = -1;
static gint ett_x2ap_RNL_Header = -1;
static gint ett_x2ap_SeNBAdditionRequest = -1;
static gint ett_x2ap_E_RABs_ToBeAdded_List = -1;
static gint ett_x2ap_E_RABs_ToBeAdded_Item = -1;
static gint ett_x2ap_E_RABs_ToBeAdded_Item_SCG_Bearer = -1;
static gint ett_x2ap_E_RABs_ToBeAdded_Item_Split_Bearer = -1;
static gint ett_x2ap_SeNBAdditionRequestAcknowledge = -1;
static gint ett_x2ap_E_RABs_Admitted_ToBeAdded_List = -1;
static gint ett_x2ap_E_RABs_Admitted_ToBeAdded_Item = -1;
static gint ett_x2ap_E_RABs_Admitted_ToBeAdded_Item_SCG_Bearer = -1;
static gint ett_x2ap_E_RABs_Admitted_ToBeAdded_Item_Split_Bearer = -1;
static gint ett_x2ap_SeNBAdditionRequestReject = -1;
static gint ett_x2ap_SeNBReconfigurationComplete = -1;
static gint ett_x2ap_ResponseInformationSeNBReconfComp = -1;
static gint ett_x2ap_ResponseInformationSeNBReconfComp_SuccessItem = -1;
static gint ett_x2ap_ResponseInformationSeNBReconfComp_RejectByMeNBItem = -1;
static gint ett_x2ap_SeNBModificationRequest = -1;
static gint ett_x2ap_UE_ContextInformationSeNBModReq = -1;
static gint ett_x2ap_E_RABs_ToBeAdded_List_ModReq = -1;
static gint ett_x2ap_E_RABs_ToBeAdded_ModReqItem = -1;
static gint ett_x2ap_E_RABs_ToBeAdded_ModReqItem_SCG_Bearer = -1;
static gint ett_x2ap_E_RABs_ToBeAdded_ModReqItem_Split_Bearer = -1;
static gint ett_x2ap_E_RABs_ToBeModified_List_ModReq = -1;
static gint ett_x2ap_E_RABs_ToBeModified_ModReqItem = -1;
static gint ett_x2ap_E_RABs_ToBeModified_ModReqItem_SCG_Bearer = -1;
static gint ett_x2ap_E_RABs_ToBeModified_ModReqItem_Split_Bearer = -1;
static gint ett_x2ap_E_RABs_ToBeReleased_List_ModReq = -1;
static gint ett_x2ap_E_RABs_ToBeReleased_ModReqItem = -1;
static gint ett_x2ap_E_RABs_ToBeReleased_ModReqItem_SCG_Bearer = -1;
static gint ett_x2ap_E_RABs_ToBeReleased_ModReqItem_Split_Bearer = -1;
static gint ett_x2ap_SeNBModificationRequestAcknowledge = -1;
static gint ett_x2ap_E_RABs_Admitted_ToBeAdded_ModAckList = -1;
static gint ett_x2ap_E_RABs_Admitted_ToBeAdded_ModAckItem = -1;
static gint ett_x2ap_E_RABs_Admitted_ToBeAdded_ModAckItem_SCG_Bearer = -1;
static gint ett_x2ap_E_RABs_Admitted_ToBeAdded_ModAckItem_Split_Bearer = -1;
static gint ett_x2ap_E_RABs_Admitted_ToBeModified_ModAckList = -1;
static gint ett_x2ap_E_RABs_Admitted_ToBeModified_ModAckItem = -1;
static gint ett_x2ap_E_RABs_Admitted_ToBeModified_ModAckItem_SCG_Bearer = -1;
static gint ett_x2ap_E_RABs_Admitted_ToBeModified_ModAckItem_Split_Bearer = -1;
static gint ett_x2ap_E_RABs_Admitted_ToBeReleased_ModAckList = -1;
static gint ett_x2ap_E_RABs_Admitted_ToReleased_ModAckItem = -1;
static gint ett_x2ap_E_RABs_Admitted_ToBeReleased_ModAckItem_SCG_Bearer = -1;
static gint ett_x2ap_E_RABs_Admitted_ToBeReleased_ModAckItem_Split_Bearer = -1;
static gint ett_x2ap_SeNBModificationRequestReject = -1;
static gint ett_x2ap_SeNBModificationRequired = -1;
static gint ett_x2ap_E_RABs_ToBeReleased_ModReqd = -1;
static gint ett_x2ap_E_RABs_ToBeReleased_ModReqdItem = -1;
static gint ett_x2ap_SeNBModificationConfirm = -1;
static gint ett_x2ap_SeNBModificationRefuse = -1;
static gint ett_x2ap_SeNBReleaseRequest = -1;
static gint ett_x2ap_E_RABs_ToBeReleased_List_RelReq = -1;
static gint ett_x2ap_E_RABs_ToBeReleased_RelReqItem = -1;
static gint ett_x2ap_E_RABs_ToBeReleased_RelReqItem_SCG_Bearer = -1;
static gint ett_x2ap_E_RABs_ToBeReleased_RelReqItem_Split_Bearer = -1;
static gint ett_x2ap_SeNBReleaseRequired = -1;
static gint ett_x2ap_SeNBReleaseConfirm = -1;
static gint ett_x2ap_E_RABs_ToBeReleased_List_RelConf = -1;
static gint ett_x2ap_E_RABs_ToBeReleased_RelConfItem = -1;
static gint ett_x2ap_E_RABs_ToBeReleased_RelConfItem_SCG_Bearer = -1;
static gint ett_x2ap_E_RABs_ToBeReleased_RelConfItem_Split_Bearer = -1;
static gint ett_x2ap_SeNBCounterCheckRequest = -1;
static gint ett_x2ap_E_RABs_SubjectToCounterCheck_List = -1;
static gint ett_x2ap_E_RABs_SubjectToCounterCheckItem = -1;
static gint ett_x2ap_X2RemovalRequest = -1;
static gint ett_x2ap_X2RemovalResponse = -1;
static gint ett_x2ap_X2RemovalFailure = -1;
static gint ett_x2ap_RetrieveUEContextRequest = -1;
static gint ett_x2ap_RetrieveUEContextResponse = -1;
static gint ett_x2ap_UE_ContextInformationRetrieve = -1;
static gint ett_x2ap_E_RABs_ToBeSetup_ListRetrieve = -1;
static gint ett_x2ap_E_RABs_ToBeSetupRetrieve_Item = -1;
static gint ett_x2ap_RetrieveUEContextFailure = -1;
static gint ett_x2ap_X2AP_PDU = -1;
static gint ett_x2ap_InitiatingMessage = -1;
static gint ett_x2ap_SuccessfulOutcome = -1;
static gint ett_x2ap_UnsuccessfulOutcome = -1;

/*--- End of included file: packet-x2ap-ett.c ---*/
#line 139 "./asn1/x2ap/packet-x2ap-template.c"

struct x2ap_private_data {
  guint32 procedure_code;
  guint32 protocol_ie_id;
};

enum {
  X2AP_RRC_CONTEXT_LTE,
  X2AP_RRC_CONTEXT_NBIOT
};

static const enum_val_t x2ap_rrc_context_vals[] = {
  {"lte", "LTE", X2AP_RRC_CONTEXT_LTE},
  {"nb-iot","NB-IoT", X2AP_RRC_CONTEXT_NBIOT},
  {NULL, NULL, -1}
};

/* Global variables */
static guint gbl_x2apSctpPort=SCTP_PORT_X2AP;
static gint g_x2ap_dissect_rrc_context_as = X2AP_RRC_CONTEXT_LTE;

/* Dissector tables */
static dissector_table_t x2ap_ies_dissector_table;
static dissector_table_t x2ap_extension_dissector_table;
static dissector_table_t x2ap_proc_imsg_dissector_table;
static dissector_table_t x2ap_proc_sout_dissector_table;
static dissector_table_t x2ap_proc_uout_dissector_table;

static int dissect_ProtocolIEFieldValue(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *);
static int dissect_ProtocolExtensionFieldExtensionValue(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *);
static int dissect_InitiatingMessageValue(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *);
static int dissect_SuccessfulOutcomeValue(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *);
static int dissect_UnsuccessfulOutcomeValue(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *);
static int dissect_X2AP_PDU_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_);
void proto_reg_handoff_x2ap(void);

static dissector_handle_t x2ap_handle;

static const true_false_string x2ap_tfs_failed_succeeded = {
  "Failed",
  "Succeeded"
};

static const true_false_string x2ap_tfs_interfacesToTrace = {
  "Should be traced",
  "Should not be traced"
};

static const true_false_string x2ap_tfs_activate_do_not_activate = {
  "Activate",
  "Do not activate"
};

static void
x2ap_Time_UE_StayedInCell_EnhancedGranularity_fmt(gchar *s, guint32 v)
{
  g_snprintf(s, ITEM_LABEL_LENGTH, "%.1fs", ((float)v)/10);
}

static void
x2ap_handoverTriggerChange_fmt(gchar *s, guint32 v)
{
  g_snprintf(s, ITEM_LABEL_LENGTH, "%.1fdB (%d)", ((float)v)/2, (gint32)v);
}

static void
x2ap_Threshold_RSRP_fmt(gchar *s, guint32 v)
{
  g_snprintf(s, ITEM_LABEL_LENGTH, "%ddBm (%u)", (gint32)v-140, v);
}

static void
x2ap_Threshold_RSRQ_fmt(gchar *s, guint32 v)
{
  g_snprintf(s, ITEM_LABEL_LENGTH, "%.1fdB (%u)", ((float)v/2)-20, v);
}

static struct x2ap_private_data*
x2ap_get_private_data(packet_info *pinfo)
{
  struct x2ap_private_data *x2ap_data = (struct x2ap_private_data*)p_get_proto_data(pinfo->pool, pinfo, proto_x2ap, 0);
  if (!x2ap_data) {
    x2ap_data = wmem_new0(pinfo->pool, struct x2ap_private_data);
    p_add_proto_data(pinfo->pool, pinfo, proto_x2ap, 0, x2ap_data);
  }
  return x2ap_data;
}


/*--- Included file: packet-x2ap-fn.c ---*/
#line 1 "./asn1/x2ap/packet-x2ap-fn.c"

static const value_string x2ap_Criticality_vals[] = {
  {   0, "reject" },
  {   1, "ignore" },
  {   2, "notify" },
  { 0, NULL }
};


static int
dissect_x2ap_Criticality(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     3, NULL, FALSE, 0, NULL);

  return offset;
}



static int
dissect_x2ap_INTEGER_0_maxPrivateIEs(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, maxPrivateIEs, NULL, FALSE);

  return offset;
}



static int
dissect_x2ap_OBJECT_IDENTIFIER(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_object_identifier(tvb, offset, actx, tree, hf_index, NULL);

  return offset;
}


static const value_string x2ap_PrivateIE_ID_vals[] = {
  {   0, "local" },
  {   1, "global" },
  { 0, NULL }
};

static const per_choice_t PrivateIE_ID_choice[] = {
  {   0, &hf_x2ap_local          , ASN1_NO_EXTENSIONS     , dissect_x2ap_INTEGER_0_maxPrivateIEs },
  {   1, &hf_x2ap_global         , ASN1_NO_EXTENSIONS     , dissect_x2ap_OBJECT_IDENTIFIER },
  { 0, NULL, 0, NULL }
};

static int
dissect_x2ap_PrivateIE_ID(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_x2ap_PrivateIE_ID, PrivateIE_ID_choice,
                                 NULL);

  return offset;
}


static const value_string x2ap_ProcedureCode_vals[] = {
  { id_handoverPreparation, "id-handoverPreparation" },
  { id_handoverCancel, "id-handoverCancel" },
  { id_loadIndication, "id-loadIndication" },
  { id_errorIndication, "id-errorIndication" },
  { id_snStatusTransfer, "id-snStatusTransfer" },
  { id_uEContextRelease, "id-uEContextRelease" },
  { id_x2Setup, "id-x2Setup" },
  { id_reset, "id-reset" },
  { id_eNBConfigurationUpdate, "id-eNBConfigurationUpdate" },
  { id_resourceStatusReportingInitiation, "id-resourceStatusReportingInitiation" },
  { id_resourceStatusReporting, "id-resourceStatusReporting" },
  { id_privateMessage, "id-privateMessage" },
  { id_mobilitySettingsChange, "id-mobilitySettingsChange" },
  { id_rLFIndication, "id-rLFIndication" },
  { id_handoverReport, "id-handoverReport" },
  { id_cellActivation, "id-cellActivation" },
  { id_x2Release, "id-x2Release" },
  { id_x2APMessageTransfer, "id-x2APMessageTransfer" },
  { id_x2Removal, "id-x2Removal" },
  { id_seNBAdditionPreparation, "id-seNBAdditionPreparation" },
  { id_seNBReconfigurationCompletion, "id-seNBReconfigurationCompletion" },
  { id_meNBinitiatedSeNBModificationPreparation, "id-meNBinitiatedSeNBModificationPreparation" },
  { id_seNBinitiatedSeNBModification, "id-seNBinitiatedSeNBModification" },
  { id_meNBinitiatedSeNBRelease, "id-meNBinitiatedSeNBRelease" },
  { id_seNBinitiatedSeNBRelease, "id-seNBinitiatedSeNBRelease" },
  { id_seNBCounterCheck, "id-seNBCounterCheck" },
  { id_retrieveUEContext, "id-retrieveUEContext" },
  { 0, NULL }
};

static value_string_ext x2ap_ProcedureCode_vals_ext = VALUE_STRING_EXT_INIT(x2ap_ProcedureCode_vals);


static int
dissect_x2ap_ProcedureCode(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 65 "./asn1/x2ap/x2ap.cnf"
  struct x2ap_private_data *x2ap_data = x2ap_get_private_data(actx->pinfo);
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 255U, &x2ap_data->procedure_code, FALSE);



  return offset;
}


static const value_string x2ap_ProtocolIE_ID_vals[] = {
  { id_E_RABs_Admitted_Item, "id-E-RABs-Admitted-Item" },
  { id_E_RABs_Admitted_List, "id-E-RABs-Admitted-List" },
  { id_E_RAB_Item, "id-E-RAB-Item" },
  { id_E_RABs_NotAdmitted_List, "id-E-RABs-NotAdmitted-List" },
  { id_E_RABs_ToBeSetup_Item, "id-E-RABs-ToBeSetup-Item" },
  { id_Cause, "id-Cause" },
  { id_CellInformation, "id-CellInformation" },
  { id_CellInformation_Item, "id-CellInformation-Item" },
  { id_New_eNB_UE_X2AP_ID, "id-New-eNB-UE-X2AP-ID" },
  { id_Old_eNB_UE_X2AP_ID, "id-Old-eNB-UE-X2AP-ID" },
  { id_TargetCell_ID, "id-TargetCell-ID" },
  { id_TargeteNBtoSource_eNBTransparentContainer, "id-TargeteNBtoSource-eNBTransparentContainer" },
  { id_TraceActivation, "id-TraceActivation" },
  { id_UE_ContextInformation, "id-UE-ContextInformation" },
  { id_UE_HistoryInformation, "id-UE-HistoryInformation" },
  { id_UE_X2AP_ID, "id-UE-X2AP-ID" },
  { id_CriticalityDiagnostics, "id-CriticalityDiagnostics" },
  { id_E_RABs_SubjectToStatusTransfer_List, "id-E-RABs-SubjectToStatusTransfer-List" },
  { id_E_RABs_SubjectToStatusTransfer_Item, "id-E-RABs-SubjectToStatusTransfer-Item" },
  { id_ServedCells, "id-ServedCells" },
  { id_GlobalENB_ID, "id-GlobalENB-ID" },
  { id_TimeToWait, "id-TimeToWait" },
  { id_GUMMEI_ID, "id-GUMMEI-ID" },
  { id_GUGroupIDList, "id-GUGroupIDList" },
  { id_ServedCellsToAdd, "id-ServedCellsToAdd" },
  { id_ServedCellsToModify, "id-ServedCellsToModify" },
  { id_ServedCellsToDelete, "id-ServedCellsToDelete" },
  { id_Registration_Request, "id-Registration-Request" },
  { id_CellToReport, "id-CellToReport" },
  { id_ReportingPeriodicity, "id-ReportingPeriodicity" },
  { id_CellToReport_Item, "id-CellToReport-Item" },
  { id_CellMeasurementResult, "id-CellMeasurementResult" },
  { id_CellMeasurementResult_Item, "id-CellMeasurementResult-Item" },
  { id_GUGroupIDToAddList, "id-GUGroupIDToAddList" },
  { id_GUGroupIDToDeleteList, "id-GUGroupIDToDeleteList" },
  { id_SRVCCOperationPossible, "id-SRVCCOperationPossible" },
  { id_Measurement_ID, "id-Measurement-ID" },
  { id_ReportCharacteristics, "id-ReportCharacteristics" },
  { id_ENB1_Measurement_ID, "id-ENB1-Measurement-ID" },
  { id_ENB2_Measurement_ID, "id-ENB2-Measurement-ID" },
  { id_Number_of_Antennaports, "id-Number-of-Antennaports" },
  { id_CompositeAvailableCapacityGroup, "id-CompositeAvailableCapacityGroup" },
  { id_ENB1_Cell_ID, "id-ENB1-Cell-ID" },
  { id_ENB2_Cell_ID, "id-ENB2-Cell-ID" },
  { id_ENB2_Proposed_Mobility_Parameters, "id-ENB2-Proposed-Mobility-Parameters" },
  { id_ENB1_Mobility_Parameters, "id-ENB1-Mobility-Parameters" },
  { id_ENB2_Mobility_Parameters_Modification_Range, "id-ENB2-Mobility-Parameters-Modification-Range" },
  { id_FailureCellPCI, "id-FailureCellPCI" },
  { id_Re_establishmentCellECGI, "id-Re-establishmentCellECGI" },
  { id_FailureCellCRNTI, "id-FailureCellCRNTI" },
  { id_ShortMAC_I, "id-ShortMAC-I" },
  { id_SourceCellECGI, "id-SourceCellECGI" },
  { id_FailureCellECGI, "id-FailureCellECGI" },
  { id_HandoverReportType, "id-HandoverReportType" },
  { id_PRACH_Configuration, "id-PRACH-Configuration" },
  { id_MBSFN_Subframe_Info, "id-MBSFN-Subframe-Info" },
  { id_ServedCellsToActivate, "id-ServedCellsToActivate" },
  { id_ActivatedCellList, "id-ActivatedCellList" },
  { id_DeactivationIndication, "id-DeactivationIndication" },
  { id_UE_RLF_Report_Container, "id-UE-RLF-Report-Container" },
  { id_ABSInformation, "id-ABSInformation" },
  { id_InvokeIndication, "id-InvokeIndication" },
  { id_ABS_Status, "id-ABS-Status" },
  { id_PartialSuccessIndicator, "id-PartialSuccessIndicator" },
  { id_MeasurementInitiationResult_List, "id-MeasurementInitiationResult-List" },
  { id_MeasurementInitiationResult_Item, "id-MeasurementInitiationResult-Item" },
  { id_MeasurementFailureCause_Item, "id-MeasurementFailureCause-Item" },
  { id_CompleteFailureCauseInformation_List, "id-CompleteFailureCauseInformation-List" },
  { id_CompleteFailureCauseInformation_Item, "id-CompleteFailureCauseInformation-Item" },
  { id_CSG_Id, "id-CSG-Id" },
  { id_CSGMembershipStatus, "id-CSGMembershipStatus" },
  { id_MDTConfiguration, "id-MDTConfiguration" },
  { id_ManagementBasedMDTallowed, "id-ManagementBasedMDTallowed" },
  { id_RRCConnSetupIndicator, "id-RRCConnSetupIndicator" },
  { id_NeighbourTAC, "id-NeighbourTAC" },
  { id_Time_UE_StayedInCell_EnhancedGranularity, "id-Time-UE-StayedInCell-EnhancedGranularity" },
  { id_RRCConnReestabIndicator, "id-RRCConnReestabIndicator" },
  { id_MBMS_Service_Area_List, "id-MBMS-Service-Area-List" },
  { id_HO_cause, "id-HO-cause" },
  { id_TargetCellInUTRAN, "id-TargetCellInUTRAN" },
  { id_MobilityInformation, "id-MobilityInformation" },
  { id_SourceCellCRNTI, "id-SourceCellCRNTI" },
  { id_MultibandInfoList, "id-MultibandInfoList" },
  { id_M3Configuration, "id-M3Configuration" },
  { id_M4Configuration, "id-M4Configuration" },
  { id_M5Configuration, "id-M5Configuration" },
  { id_MDT_Location_Info, "id-MDT-Location-Info" },
  { id_ManagementBasedMDTPLMNList, "id-ManagementBasedMDTPLMNList" },
  { id_SignallingBasedMDTPLMNList, "id-SignallingBasedMDTPLMNList" },
  { id_ReceiveStatusOfULPDCPSDUsExtended, "id-ReceiveStatusOfULPDCPSDUsExtended" },
  { id_ULCOUNTValueExtended, "id-ULCOUNTValueExtended" },
  { id_DLCOUNTValueExtended, "id-DLCOUNTValueExtended" },
  { id_eARFCNExtension, "id-eARFCNExtension" },
  { id_UL_EARFCNExtension, "id-UL-EARFCNExtension" },
  { id_DL_EARFCNExtension, "id-DL-EARFCNExtension" },
  { id_AdditionalSpecialSubframe_Info, "id-AdditionalSpecialSubframe-Info" },
  { id_Masked_IMEISV, "id-Masked-IMEISV" },
  { id_IntendedULDLConfiguration, "id-IntendedULDLConfiguration" },
  { id_ExtendedULInterferenceOverloadInfo, "id-ExtendedULInterferenceOverloadInfo" },
  { id_RNL_Header, "id-RNL-Header" },
  { id_x2APMessage, "id-x2APMessage" },
  { id_ProSeAuthorized, "id-ProSeAuthorized" },
  { id_ExpectedUEBehaviour, "id-ExpectedUEBehaviour" },
  { id_UE_HistoryInformationFromTheUE, "id-UE-HistoryInformationFromTheUE" },
  { id_DynamicDLTransmissionInformation, "id-DynamicDLTransmissionInformation" },
  { id_UE_RLF_Report_Container_for_extended_bands, "id-UE-RLF-Report-Container-for-extended-bands" },
  { id_CoMPInformation, "id-CoMPInformation" },
  { id_ReportingPeriodicityRSRPMR, "id-ReportingPeriodicityRSRPMR" },
  { id_RSRPMRList, "id-RSRPMRList" },
  { id_MeNB_UE_X2AP_ID, "id-MeNB-UE-X2AP-ID" },
  { id_SeNB_UE_X2AP_ID, "id-SeNB-UE-X2AP-ID" },
  { id_UE_SecurityCapabilities, "id-UE-SecurityCapabilities" },
  { id_SeNBSecurityKey, "id-SeNBSecurityKey" },
  { id_SeNBUEAggregateMaximumBitRate, "id-SeNBUEAggregateMaximumBitRate" },
  { id_ServingPLMN, "id-ServingPLMN" },
  { id_E_RABs_ToBeAdded_List, "id-E-RABs-ToBeAdded-List" },
  { id_E_RABs_ToBeAdded_Item, "id-E-RABs-ToBeAdded-Item" },
  { id_MeNBtoSeNBContainer, "id-MeNBtoSeNBContainer" },
  { id_E_RABs_Admitted_ToBeAdded_List, "id-E-RABs-Admitted-ToBeAdded-List" },
  { id_E_RABs_Admitted_ToBeAdded_Item, "id-E-RABs-Admitted-ToBeAdded-Item" },
  { id_SeNBtoMeNBContainer, "id-SeNBtoMeNBContainer" },
  { id_ResponseInformationSeNBReconfComp, "id-ResponseInformationSeNBReconfComp" },
  { id_UE_ContextInformationSeNBModReq, "id-UE-ContextInformationSeNBModReq" },
  { id_E_RABs_ToBeAdded_ModReqItem, "id-E-RABs-ToBeAdded-ModReqItem" },
  { id_E_RABs_ToBeModified_ModReqItem, "id-E-RABs-ToBeModified-ModReqItem" },
  { id_E_RABs_ToBeReleased_ModReqItem, "id-E-RABs-ToBeReleased-ModReqItem" },
  { id_E_RABs_Admitted_ToBeAdded_ModAckList, "id-E-RABs-Admitted-ToBeAdded-ModAckList" },
  { id_E_RABs_Admitted_ToBeModified_ModAckList, "id-E-RABs-Admitted-ToBeModified-ModAckList" },
  { id_E_RABs_Admitted_ToBeReleased_ModAckList, "id-E-RABs-Admitted-ToBeReleased-ModAckList" },
  { id_E_RABs_Admitted_ToBeAdded_ModAckItem, "id-E-RABs-Admitted-ToBeAdded-ModAckItem" },
  { id_E_RABs_Admitted_ToBeModified_ModAckItem, "id-E-RABs-Admitted-ToBeModified-ModAckItem" },
  { id_E_RABs_Admitted_ToBeReleased_ModAckItem, "id-E-RABs-Admitted-ToBeReleased-ModAckItem" },
  { id_E_RABs_ToBeReleased_ModReqd, "id-E-RABs-ToBeReleased-ModReqd" },
  { id_E_RABs_ToBeReleased_ModReqdItem, "id-E-RABs-ToBeReleased-ModReqdItem" },
  { id_SCGChangeIndication, "id-SCGChangeIndication" },
  { id_E_RABs_ToBeReleased_List_RelReq, "id-E-RABs-ToBeReleased-List-RelReq" },
  { id_E_RABs_ToBeReleased_RelReqItem, "id-E-RABs-ToBeReleased-RelReqItem" },
  { id_E_RABs_ToBeReleased_List_RelConf, "id-E-RABs-ToBeReleased-List-RelConf" },
  { id_E_RABs_ToBeReleased_RelConfItem, "id-E-RABs-ToBeReleased-RelConfItem" },
  { id_E_RABs_SubjectToCounterCheck_List, "id-E-RABs-SubjectToCounterCheck-List" },
  { id_E_RABs_SubjectToCounterCheckItem, "id-E-RABs-SubjectToCounterCheckItem" },
  { id_CoverageModificationList, "id-CoverageModificationList" },
  { id_ReportingPeriodicityCSIR, "id-ReportingPeriodicityCSIR" },
  { id_CSIReportList, "id-CSIReportList" },
  { id_UEID, "id-UEID" },
  { id_enhancedRNTP, "id-enhancedRNTP" },
  { id_ProSeUEtoNetworkRelaying, "id-ProSeUEtoNetworkRelaying" },
  { id_ReceiveStatusOfULPDCPSDUsPDCP_SNlength18, "id-ReceiveStatusOfULPDCPSDUsPDCP-SNlength18" },
  { id_ULCOUNTValuePDCP_SNlength18, "id-ULCOUNTValuePDCP-SNlength18" },
  { id_DLCOUNTValuePDCP_SNlength18, "id-DLCOUNTValuePDCP-SNlength18" },
  { id_UE_ContextReferenceAtSeNB, "id-UE-ContextReferenceAtSeNB" },
  { id_UE_ContextKeptIndicator, "id-UE-ContextKeptIndicator" },
  { id_New_eNB_UE_X2AP_ID_Extension, "id-New-eNB-UE-X2AP-ID-Extension" },
  { id_Old_eNB_UE_X2AP_ID_Extension, "id-Old-eNB-UE-X2AP-ID-Extension" },
  { id_MeNB_UE_X2AP_ID_Extension, "id-MeNB-UE-X2AP-ID-Extension" },
  { id_SeNB_UE_X2AP_ID_Extension, "id-SeNB-UE-X2AP-ID-Extension" },
  { id_LHN_ID, "id-LHN-ID" },
  { id_FreqBandIndicatorPriority, "id-FreqBandIndicatorPriority" },
  { id_M6Configuration, "id-M6Configuration" },
  { id_M7Configuration, "id-M7Configuration" },
  { id_Tunnel_Information_for_BBF, "id-Tunnel-Information-for-BBF" },
  { id_SIPTO_BearerDeactivationIndication, "id-SIPTO-BearerDeactivationIndication" },
  { id_GW_TransportLayerAddress, "id-GW-TransportLayerAddress" },
  { id_Correlation_ID, "id-Correlation-ID" },
  { id_SIPTO_Correlation_ID, "id-SIPTO-Correlation-ID" },
  { id_SIPTO_L_GW_TransportLayerAddress, "id-SIPTO-L-GW-TransportLayerAddress" },
  { id_X2RemovalThreshold, "id-X2RemovalThreshold" },
  { id_CellReportingIndicator, "id-CellReportingIndicator" },
  { id_BearerType, "id-BearerType" },
  { id_resumeID, "id-resumeID" },
  { id_UE_ContextInformationRetrieve, "id-UE-ContextInformationRetrieve" },
  { id_E_RABs_ToBeSetupRetrieve_Item, "id-E-RABs-ToBeSetupRetrieve-Item" },
  { id_NewEUTRANCellIdentifier, "id-NewEUTRANCellIdentifier" },
  { id_OffsetOfNbiotChannelNumberToDL_EARFCN, "id-OffsetOfNbiotChannelNumberToDL-EARFCN" },
  { id_OffsetOfNbiotChannelNumberToUL_EARFCN, "id-OffsetOfNbiotChannelNumberToUL-EARFCN" },
  { 0, NULL }
};

static value_string_ext x2ap_ProtocolIE_ID_vals_ext = VALUE_STRING_EXT_INIT(x2ap_ProtocolIE_ID_vals);


static int
dissect_x2ap_ProtocolIE_ID(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 52 "./asn1/x2ap/x2ap.cnf"
  struct x2ap_private_data *x2ap_data = x2ap_get_private_data(actx->pinfo);
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, maxProtocolIEs, &x2ap_data->protocol_ie_id, FALSE);



#line 55 "./asn1/x2ap/x2ap.cnf"
  if (tree) {
    proto_item_append_text(proto_item_get_parent_nth(actx->created_item, 2), ": %s", val_to_str_ext(x2ap_data->protocol_ie_id, &x2ap_ProtocolIE_ID_vals_ext, "unknown (%d)"));
  }

  return offset;
}


static const value_string x2ap_TriggeringMessage_vals[] = {
  {   0, "initiating-message" },
  {   1, "successful-outcome" },
  {   2, "unsuccessful-outcome" },
  { 0, NULL }
};


static int
dissect_x2ap_TriggeringMessage(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     3, NULL, FALSE, 0, NULL);

  return offset;
}



static int
dissect_x2ap_ProtocolIE_Field_value(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_open_type_pdu_new(tvb, offset, actx, tree, hf_index, dissect_ProtocolIEFieldValue);

  return offset;
}


static const per_sequence_t ProtocolIE_Field_sequence[] = {
  { &hf_x2ap_id             , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_x2ap_ProtocolIE_ID },
  { &hf_x2ap_criticality    , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_x2ap_Criticality },
  { &hf_x2ap_protocolIE_Field_value, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_x2ap_ProtocolIE_Field_value },
  { NULL, 0, 0, NULL }
};

static int
dissect_x2ap_ProtocolIE_Field(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_x2ap_ProtocolIE_Field, ProtocolIE_Field_sequence);

  return offset;
}


static const per_sequence_t ProtocolIE_Container_sequence_of[1] = {
  { &hf_x2ap_ProtocolIE_Container_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_x2ap_ProtocolIE_Field },
};

static int
dissect_x2ap_ProtocolIE_Container(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_x2ap_ProtocolIE_Container, ProtocolIE_Container_sequence_of,
                                                  0, maxProtocolIEs, FALSE);

  return offset;
}



static int
dissect_x2ap_ProtocolIE_Single_Container(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_x2ap_ProtocolIE_Field(tvb, offset, actx, tree, hf_index);

  return offset;
}



static int
dissect_x2ap_T_extensionValue(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_open_type_pdu_new(tvb, offset, actx, tree, hf_index, dissect_ProtocolExtensionFieldExtensionValue);

  return offset;
}


static const per_sequence_t ProtocolExtensionField_sequence[] = {
  { &hf_x2ap_extension_id   , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_x2ap_ProtocolIE_ID },
  { &hf_x2ap_criticality    , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_x2ap_Criticality },
  { &hf_x2ap_extensionValue , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_x2ap_T_extensionValue },
  { NULL, 0, 0, NULL }
};

static int
dissect_x2ap_ProtocolExtensionField(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_x2ap_ProtocolExtensionField, ProtocolExtensionField_sequence);

  return offset;
}


static const per_sequence_t ProtocolExtensionContainer_sequence_of[1] = {
  { &hf_x2ap_ProtocolExtensionContainer_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_x2ap_ProtocolExtensionField },
};

static int
dissect_x2ap_ProtocolExtensionContainer(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_x2ap_ProtocolExtensionContainer, ProtocolExtensionContainer_sequence_of,
                                                  1, maxProtocolExtensions, FALSE);

  return offset;
}



static int
dissect_x2ap_PrivateIE_Field_value(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_open_type(tvb, offset, actx, tree, hf_index, NULL);

  return offset;
}


static const per_sequence_t PrivateIE_Field_sequence[] = {
  { &hf_x2ap_private_id     , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_x2ap_PrivateIE_ID },
  { &hf_x2ap_criticality    , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_x2ap_Criticality },
  { &hf_x2ap_privateIE_Field_value, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_x2ap_PrivateIE_Field_value },
  { NULL, 0, 0, NULL }
};

static int
dissect_x2ap_PrivateIE_Field(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_x2ap_PrivateIE_Field, PrivateIE_Field_sequence);

  return offset;
}


static const per_sequence_t PrivateIE_Container_sequence_of[1] = {
  { &hf_x2ap_PrivateIE_Container_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_x2ap_PrivateIE_Field },
};

static int
dissect_x2ap_PrivateIE_Container(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_x2ap_PrivateIE_Container, PrivateIE_Container_sequence_of,
                                                  1, maxPrivateIEs, FALSE);

  return offset;
}



static int
dissect_x2ap_BIT_STRING_SIZE_40(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_bit_string(tvb, offset, actx, tree, hf_index,
                                     40, 40, FALSE, NULL, NULL);

  return offset;
}


static const value_string x2ap_T_numberOfCellSpecificAntennaPorts_vals[] = {
  {   0, "one" },
  {   1, "two" },
  {   2, "four" },
  { 0, NULL }
};


static int
dissect_x2ap_T_numberOfCellSpecificAntennaPorts(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     3, NULL, TRUE, 0, NULL);

  return offset;
}


static const per_sequence_t ABSInformationFDD_sequence[] = {
  { &hf_x2ap_abs_pattern_info, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_x2ap_BIT_STRING_SIZE_40 },
  { &hf_x2ap_numberOfCellSpecificAntennaPorts, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_x2ap_T_numberOfCellSpecificAntennaPorts },
  { &hf_x2ap_measurement_subset, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_x2ap_BIT_STRING_SIZE_40 },
  { &hf_x2ap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_x2ap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_x2ap_ABSInformationFDD(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_x2ap_ABSInformationFDD, ABSInformationFDD_sequence);

  return offset;
}



static int
dissect_x2ap_BIT_STRING_SIZE_1_70_(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_bit_string(tvb, offset, actx, tree, hf_index,
                                     1, 70, TRUE, NULL, NULL);

  return offset;
}


static const value_string x2ap_T_numberOfCellSpecificAntennaPorts_01_vals[] = {
  {   0, "one" },
  {   1, "two" },
  {   2, "four" },
  { 0, NULL }
};


static int
dissect_x2ap_T_numberOfCellSpecificAntennaPorts_01(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     3, NULL, TRUE, 0, NULL);

  return offset;
}


static const per_sequence_t ABSInformationTDD_sequence[] = {
  { &hf_x2ap_abs_pattern_info_01, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_x2ap_BIT_STRING_SIZE_1_70_ },
  { &hf_x2ap_numberOfCellSpecificAntennaPorts_01, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_x2ap_T_numberOfCellSpecificAntennaPorts_01 },
  { &hf_x2ap_measurement_subset_01, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_x2ap_BIT_STRING_SIZE_1_70_ },
  { &hf_x2ap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_x2ap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_x2ap_ABSInformationTDD(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_x2ap_ABSInformationTDD, ABSInformationTDD_sequence);

  return offset;
}



static int
dissect_x2ap_NULL(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_null(tvb, offset, actx, tree, hf_index);

  return offset;
}


static const value_string x2ap_ABSInformation_vals[] = {
  {   0, "fdd" },
  {   1, "tdd" },
  {   2, "abs-inactive" },
  { 0, NULL }
};

static const per_choice_t ABSInformation_choice[] = {
  {   0, &hf_x2ap_fdd            , ASN1_EXTENSION_ROOT    , dissect_x2ap_ABSInformationFDD },
  {   1, &hf_x2ap_tdd            , ASN1_EXTENSION_ROOT    , dissect_x2ap_ABSInformationTDD },
  {   2, &hf_x2ap_abs_inactive   , ASN1_EXTENSION_ROOT    , dissect_x2ap_NULL },
  { 0, NULL, 0, NULL }
};

static int
dissect_x2ap_ABSInformation(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_x2ap_ABSInformation, ABSInformation_choice,
                                 NULL);

  return offset;
}



static int
dissect_x2ap_DL_ABS_status(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 100U, NULL, FALSE);

  return offset;
}


static const per_sequence_t UsableABSInformationFDD_sequence[] = {
  { &hf_x2ap_usable_abs_pattern_info, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_x2ap_BIT_STRING_SIZE_40 },
  { &hf_x2ap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_x2ap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_x2ap_UsableABSInformationFDD(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_x2ap_UsableABSInformationFDD, UsableABSInformationFDD_sequence);

  return offset;
}


static const per_sequence_t UsableABSInformationTDD_sequence[] = {
  { &hf_x2ap_usaable_abs_pattern_info, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_x2ap_BIT_STRING_SIZE_1_70_ },
  { &hf_x2ap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_x2ap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_x2ap_UsableABSInformationTDD(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_x2ap_UsableABSInformationTDD, UsableABSInformationTDD_sequence);

  return offset;
}


static const value_string x2ap_UsableABSInformation_vals[] = {
  {   0, "fdd" },
  {   1, "tdd" },
  { 0, NULL }
};

static const per_choice_t UsableABSInformation_choice[] = {
  {   0, &hf_x2ap_fdd_01         , ASN1_EXTENSION_ROOT    , dissect_x2ap_UsableABSInformationFDD },
  {   1, &hf_x2ap_tdd_01         , ASN1_EXTENSION_ROOT    , dissect_x2ap_UsableABSInformationTDD },
  { 0, NULL, 0, NULL }
};

static int
dissect_x2ap_UsableABSInformation(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_x2ap_UsableABSInformation, UsableABSInformation_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t ABS_Status_sequence[] = {
  { &hf_x2ap_dL_ABS_status  , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_x2ap_DL_ABS_status },
  { &hf_x2ap_usableABSInformation, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_x2ap_UsableABSInformation },
  { &hf_x2ap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_x2ap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_x2ap_ABS_Status(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_x2ap_ABS_Status, ABS_Status_sequence);

  return offset;
}


static const value_string x2ap_AdditionalSpecialSubframePatterns_vals[] = {
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
  { 0, NULL }
};


static int
dissect_x2ap_AdditionalSpecialSubframePatterns(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     10, NULL, TRUE, 0, NULL);

  return offset;
}


static const value_string x2ap_CyclicPrefixDL_vals[] = {
  {   0, "normal" },
  {   1, "extended" },
  { 0, NULL }
};


static int
dissect_x2ap_CyclicPrefixDL(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     2, NULL, TRUE, 0, NULL);

  return offset;
}


static const value_string x2ap_CyclicPrefixUL_vals[] = {
  {   0, "normal" },
  {   1, "extended" },
  { 0, NULL }
};


static int
dissect_x2ap_CyclicPrefixUL(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     2, NULL, TRUE, 0, NULL);

  return offset;
}


static const per_sequence_t AdditionalSpecialSubframe_Info_sequence[] = {
  { &hf_x2ap_additionalspecialSubframePatterns, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_x2ap_AdditionalSpecialSubframePatterns },
  { &hf_x2ap_cyclicPrefixDL , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_x2ap_CyclicPrefixDL },
  { &hf_x2ap_cyclicPrefixUL , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_x2ap_CyclicPrefixUL },
  { &hf_x2ap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_x2ap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_x2ap_AdditionalSpecialSubframe_Info(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_x2ap_AdditionalSpecialSubframe_Info, AdditionalSpecialSubframe_Info_sequence);

  return offset;
}


static const value_string x2ap_PriorityLevel_vals[] = {
  {   0, "spare" },
  {   1, "highest" },
  {  14, "lowest" },
  {  15, "no-priority" },
  { 0, NULL }
};


static int
dissect_x2ap_PriorityLevel(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 15U, NULL, FALSE);

  return offset;
}


static const value_string x2ap_Pre_emptionCapability_vals[] = {
  {   0, "shall-not-trigger-pre-emption" },
  {   1, "may-trigger-pre-emption" },
  { 0, NULL }
};


static int
dissect_x2ap_Pre_emptionCapability(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     2, NULL, FALSE, 0, NULL);

  return offset;
}


static const value_string x2ap_Pre_emptionVulnerability_vals[] = {
  {   0, "not-pre-emptable" },
  {   1, "pre-emptable" },
  { 0, NULL }
};


static int
dissect_x2ap_Pre_emptionVulnerability(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     2, NULL, FALSE, 0, NULL);

  return offset;
}


static const per_sequence_t AllocationAndRetentionPriority_sequence[] = {
  { &hf_x2ap_priorityLevel  , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_x2ap_PriorityLevel },
  { &hf_x2ap_pre_emptionCapability, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_x2ap_Pre_emptionCapability },
  { &hf_x2ap_pre_emptionVulnerability, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_x2ap_Pre_emptionVulnerability },
  { &hf_x2ap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_x2ap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_x2ap_AllocationAndRetentionPriority(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_x2ap_AllocationAndRetentionPriority, AllocationAndRetentionPriority_sequence);

  return offset;
}



static int
dissect_x2ap_PLMN_Identity(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 299 "./asn1/x2ap/x2ap.cnf"
  tvbuff_t *parameter_tvb = NULL;
  proto_tree *subtree;

  offset = dissect_per_octet_string(tvb, offset, actx, tree, hf_index,
                                       3, 3, FALSE, &parameter_tvb);


  if(tvb_reported_length(tvb)==0)
    return offset;

  if (!parameter_tvb)
    return offset;

  subtree = proto_item_add_subtree(actx->created_item, ett_x2ap_PLMN_Identity);
  dissect_e212_mcc_mnc(parameter_tvb, actx->pinfo, subtree, 0, E212_NONE, FALSE);



  return offset;
}



static int
dissect_x2ap_EUTRANCellIdentifier(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_bit_string(tvb, offset, actx, tree, hf_index,
                                     28, 28, FALSE, NULL, NULL);

  return offset;
}


static const per_sequence_t ECGI_sequence[] = {
  { &hf_x2ap_pLMN_Identity  , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_x2ap_PLMN_Identity },
  { &hf_x2ap_eUTRANcellIdentifier, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_x2ap_EUTRANCellIdentifier },
  { &hf_x2ap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_x2ap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_x2ap_ECGI(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_x2ap_ECGI, ECGI_sequence);

  return offset;
}


static const per_sequence_t CellIdListforMDT_sequence_of[1] = {
  { &hf_x2ap_CellIdListforMDT_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_x2ap_ECGI },
};

static int
dissect_x2ap_CellIdListforMDT(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_x2ap_CellIdListforMDT, CellIdListforMDT_sequence_of,
                                                  1, maxnoofCellIDforMDT, FALSE);

  return offset;
}


static const per_sequence_t CellBasedMDT_sequence[] = {
  { &hf_x2ap_cellIdListforMDT, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_x2ap_CellIdListforMDT },
  { &hf_x2ap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_x2ap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_x2ap_CellBasedMDT(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_x2ap_CellBasedMDT, CellBasedMDT_sequence);

  return offset;
}



static int
dissect_x2ap_TAC(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 283 "./asn1/x2ap/x2ap.cnf"
  tvbuff_t *parameter_tvb = NULL;
  offset = dissect_per_octet_string(tvb, offset, actx, tree, -1,
                                       2, 2, FALSE, &parameter_tvb);

  if (parameter_tvb) {
    actx->created_item = proto_tree_add_item(tree, hf_index, parameter_tvb, 0, 2, ENC_BIG_ENDIAN);
  }



  return offset;
}


static const per_sequence_t TAListforMDT_sequence_of[1] = {
  { &hf_x2ap_TAListforMDT_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_x2ap_TAC },
};

static int
dissect_x2ap_TAListforMDT(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_x2ap_TAListforMDT, TAListforMDT_sequence_of,
                                                  1, maxnoofTAforMDT, FALSE);

  return offset;
}


static const per_sequence_t TABasedMDT_sequence[] = {
  { &hf_x2ap_tAListforMDT   , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_x2ap_TAListforMDT },
  { &hf_x2ap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_x2ap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_x2ap_TABasedMDT(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_x2ap_TABasedMDT, TABasedMDT_sequence);

  return offset;
}


static const per_sequence_t TAI_Item_sequence[] = {
  { &hf_x2ap_tAC            , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_x2ap_TAC },
  { &hf_x2ap_pLMN_Identity  , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_x2ap_PLMN_Identity },
  { &hf_x2ap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_x2ap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_x2ap_TAI_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_x2ap_TAI_Item, TAI_Item_sequence);

  return offset;
}


static const per_sequence_t TAIListforMDT_sequence_of[1] = {
  { &hf_x2ap_TAIListforMDT_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_x2ap_TAI_Item },
};

static int
dissect_x2ap_TAIListforMDT(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_x2ap_TAIListforMDT, TAIListforMDT_sequence_of,
                                                  1, maxnoofTAforMDT, FALSE);

  return offset;
}


static const per_sequence_t TAIBasedMDT_sequence[] = {
  { &hf_x2ap_tAIListforMDT  , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_x2ap_TAIListforMDT },
  { &hf_x2ap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_x2ap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_x2ap_TAIBasedMDT(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_x2ap_TAIBasedMDT, TAIBasedMDT_sequence);

  return offset;
}


static const value_string x2ap_AreaScopeOfMDT_vals[] = {
  {   0, "cellBased" },
  {   1, "tABased" },
  {   2, "pLMNWide" },
  {   3, "tAIBased" },
  { 0, NULL }
};

static const per_choice_t AreaScopeOfMDT_choice[] = {
  {   0, &hf_x2ap_cellBased      , ASN1_EXTENSION_ROOT    , dissect_x2ap_CellBasedMDT },
  {   1, &hf_x2ap_tABased        , ASN1_EXTENSION_ROOT    , dissect_x2ap_TABasedMDT },
  {   2, &hf_x2ap_pLMNWide       , ASN1_EXTENSION_ROOT    , dissect_x2ap_NULL },
  {   3, &hf_x2ap_tAIBased       , ASN1_NOT_EXTENSION_ROOT, dissect_x2ap_TAIBasedMDT },
  { 0, NULL, 0, NULL }
};

static int
dissect_x2ap_AreaScopeOfMDT(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_x2ap_AreaScopeOfMDT, AreaScopeOfMDT_choice,
                                 NULL);

  return offset;
}



static int
dissect_x2ap_Key_eNodeB_Star(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_bit_string(tvb, offset, actx, tree, hf_index,
                                     256, 256, FALSE, NULL, NULL);

  return offset;
}



static int
dissect_x2ap_NextHopChainingCount(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 7U, NULL, FALSE);

  return offset;
}


static const per_sequence_t AS_SecurityInformation_sequence[] = {
  { &hf_x2ap_key_eNodeB_star, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_x2ap_Key_eNodeB_Star },
  { &hf_x2ap_nextHopChainingCount, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_x2ap_NextHopChainingCount },
  { &hf_x2ap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_x2ap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_x2ap_AS_SecurityInformation(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_x2ap_AS_SecurityInformation, AS_SecurityInformation_sequence);

  return offset;
}


static const value_string x2ap_BearerType_vals[] = {
  {   0, "non-IP" },
  { 0, NULL }
};


static int
dissect_x2ap_BearerType(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     1, NULL, TRUE, 0, NULL);

  return offset;
}



static int
dissect_x2ap_BenefitMetric(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            -101, 100U, NULL, TRUE);

  return offset;
}



static int
dissect_x2ap_BitRate(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer_64b(tvb, offset, actx, tree, hf_index,
                                                            0U, G_GUINT64_CONSTANT(10000000000), NULL, FALSE);

  return offset;
}


static const per_sequence_t BroadcastPLMNs_Item_sequence_of[1] = {
  { &hf_x2ap_BroadcastPLMNs_Item_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_x2ap_PLMN_Identity },
};

static int
dissect_x2ap_BroadcastPLMNs_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_x2ap_BroadcastPLMNs_Item, BroadcastPLMNs_Item_sequence_of,
                                                  1, maxnoofBPLMNs, FALSE);

  return offset;
}



static int
dissect_x2ap_CapacityValue(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 100U, NULL, FALSE);

  return offset;
}


static const value_string x2ap_CauseRadioNetwork_vals[] = {
  {   0, "handover-desirable-for-radio-reasons" },
  {   1, "time-critical-handover" },
  {   2, "resource-optimisation-handover" },
  {   3, "reduce-load-in-serving-cell" },
  {   4, "partial-handover" },
  {   5, "unknown-new-eNB-UE-X2AP-ID" },
  {   6, "unknown-old-eNB-UE-X2AP-ID" },
  {   7, "unknown-pair-of-UE-X2AP-ID" },
  {   8, "ho-target-not-allowed" },
  {   9, "tx2relocoverall-expiry" },
  {  10, "trelocprep-expiry" },
  {  11, "cell-not-available" },
  {  12, "no-radio-resources-available-in-target-cell" },
  {  13, "invalid-MME-GroupID" },
  {  14, "unknown-MME-Code" },
  {  15, "encryption-and-or-integrity-protection-algorithms-not-supported" },
  {  16, "reportCharacteristicsEmpty" },
  {  17, "noReportPeriodicity" },
  {  18, "existingMeasurementID" },
  {  19, "unknown-eNB-Measurement-ID" },
  {  20, "measurement-temporarily-not-available" },
  {  21, "unspecified" },
  {  22, "load-balancing" },
  {  23, "handover-optimisation" },
  {  24, "value-out-of-allowed-range" },
  {  25, "multiple-E-RAB-ID-instances" },
  {  26, "switch-off-ongoing" },
  {  27, "not-supported-QCI-value" },
  {  28, "measurement-not-supported-for-the-object" },
  {  29, "tDCoverall-expiry" },
  {  30, "tDCprep-expiry" },
  {  31, "action-desirable-for-radio-reasons" },
  {  32, "reduce-load" },
  {  33, "resource-optimisation" },
  {  34, "time-critical-action" },
  {  35, "target-not-allowed" },
  {  36, "no-radio-resources-available" },
  {  37, "invalid-QoS-combination" },
  {  38, "encryption-algorithms-not-aupported" },
  {  39, "procedure-cancelled" },
  {  40, "rRM-purpose" },
  {  41, "improve-user-bit-rate" },
  {  42, "user-inactivity" },
  {  43, "radio-connection-with-UE-lost" },
  {  44, "failure-in-the-radio-interface-procedure" },
  {  45, "bearer-option-not-supported" },
  { 0, NULL }
};

static value_string_ext x2ap_CauseRadioNetwork_vals_ext = VALUE_STRING_EXT_INIT(x2ap_CauseRadioNetwork_vals);


static int
dissect_x2ap_CauseRadioNetwork(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     22, NULL, TRUE, 24, NULL);

  return offset;
}


static const value_string x2ap_CauseTransport_vals[] = {
  {   0, "transport-resource-unavailable" },
  {   1, "unspecified" },
  { 0, NULL }
};


static int
dissect_x2ap_CauseTransport(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     2, NULL, TRUE, 0, NULL);

  return offset;
}


static const value_string x2ap_CauseProtocol_vals[] = {
  {   0, "transfer-syntax-error" },
  {   1, "abstract-syntax-error-reject" },
  {   2, "abstract-syntax-error-ignore-and-notify" },
  {   3, "message-not-compatible-with-receiver-state" },
  {   4, "semantic-error" },
  {   5, "unspecified" },
  {   6, "abstract-syntax-error-falsely-constructed-message" },
  { 0, NULL }
};


static int
dissect_x2ap_CauseProtocol(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     7, NULL, TRUE, 0, NULL);

  return offset;
}


static const value_string x2ap_CauseMisc_vals[] = {
  {   0, "control-processing-overload" },
  {   1, "hardware-failure" },
  {   2, "om-intervention" },
  {   3, "not-enough-user-plane-processing-resources" },
  {   4, "unspecified" },
  { 0, NULL }
};


static int
dissect_x2ap_CauseMisc(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     5, NULL, TRUE, 0, NULL);

  return offset;
}


static const value_string x2ap_Cause_vals[] = {
  {   0, "radioNetwork" },
  {   1, "transport" },
  {   2, "protocol" },
  {   3, "misc" },
  { 0, NULL }
};

static const per_choice_t Cause_choice[] = {
  {   0, &hf_x2ap_radioNetwork   , ASN1_EXTENSION_ROOT    , dissect_x2ap_CauseRadioNetwork },
  {   1, &hf_x2ap_transport      , ASN1_EXTENSION_ROOT    , dissect_x2ap_CauseTransport },
  {   2, &hf_x2ap_protocol       , ASN1_EXTENSION_ROOT    , dissect_x2ap_CauseProtocol },
  {   3, &hf_x2ap_misc           , ASN1_EXTENSION_ROOT    , dissect_x2ap_CauseMisc },
  { 0, NULL, 0, NULL }
};

static int
dissect_x2ap_Cause(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_x2ap_Cause, Cause_choice,
                                 NULL);

  return offset;
}



static int
dissect_x2ap_CellCapacityClassValue(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            1U, 100U, NULL, TRUE);

  return offset;
}


static const value_string x2ap_CellDeploymentStatusIndicator_vals[] = {
  {   0, "pre-change-notification" },
  { 0, NULL }
};


static int
dissect_x2ap_CellDeploymentStatusIndicator(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     1, NULL, TRUE, 0, NULL);

  return offset;
}


static const per_sequence_t ReplacingCellsList_Item_sequence[] = {
  { &hf_x2ap_eCGI           , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_x2ap_ECGI },
  { NULL, 0, 0, NULL }
};

static int
dissect_x2ap_ReplacingCellsList_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_x2ap_ReplacingCellsList_Item, ReplacingCellsList_Item_sequence);

  return offset;
}


static const per_sequence_t ReplacingCellsList_sequence_of[1] = {
  { &hf_x2ap_ReplacingCellsList_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_x2ap_ReplacingCellsList_Item },
};

static int
dissect_x2ap_ReplacingCellsList(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_x2ap_ReplacingCellsList, ReplacingCellsList_sequence_of,
                                                  0, maxCellineNB, FALSE);

  return offset;
}


static const per_sequence_t CellReplacingInfo_sequence[] = {
  { &hf_x2ap_replacingCellsList, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_x2ap_ReplacingCellsList },
  { &hf_x2ap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_x2ap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_x2ap_CellReplacingInfo(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_x2ap_CellReplacingInfo, CellReplacingInfo_sequence);

  return offset;
}


static const value_string x2ap_CellReportingIndicator_vals[] = {
  {   0, "stop-request" },
  { 0, NULL }
};


static int
dissect_x2ap_CellReportingIndicator(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     1, NULL, TRUE, 0, NULL);

  return offset;
}


static const value_string x2ap_Cell_Size_vals[] = {
  {   0, "verysmall" },
  {   1, "small" },
  {   2, "medium" },
  {   3, "large" },
  { 0, NULL }
};


static int
dissect_x2ap_Cell_Size(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     4, NULL, TRUE, 0, NULL);

  return offset;
}


static const per_sequence_t CellType_sequence[] = {
  { &hf_x2ap_cell_Size      , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_x2ap_Cell_Size },
  { &hf_x2ap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_x2ap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_x2ap_CellType(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_x2ap_CellType, CellType_sequence);

  return offset;
}



static int
dissect_x2ap_BIT_STRING_SIZE_6_4400_(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_bit_string(tvb, offset, actx, tree, hf_index,
                                     6, 4400, TRUE, NULL, NULL);

  return offset;
}


static const per_sequence_t CoMPHypothesisSetItem_sequence[] = {
  { &hf_x2ap_coMPCellID     , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_x2ap_ECGI },
  { &hf_x2ap_coMPHypothesis , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_x2ap_BIT_STRING_SIZE_6_4400_ },
  { &hf_x2ap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_x2ap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_x2ap_CoMPHypothesisSetItem(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_x2ap_CoMPHypothesisSetItem, CoMPHypothesisSetItem_sequence);

  return offset;
}


static const per_sequence_t CoMPHypothesisSet_sequence_of[1] = {
  { &hf_x2ap_CoMPHypothesisSet_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_x2ap_CoMPHypothesisSetItem },
};

static int
dissect_x2ap_CoMPHypothesisSet(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_x2ap_CoMPHypothesisSet, CoMPHypothesisSet_sequence_of,
                                                  1, maxnoofCoMPCells, FALSE);

  return offset;
}


static const per_sequence_t CoMPInformationItem_item_sequence[] = {
  { &hf_x2ap_coMPHypothesisSet, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_x2ap_CoMPHypothesisSet },
  { &hf_x2ap_benefitMetric  , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_x2ap_BenefitMetric },
  { &hf_x2ap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_x2ap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_x2ap_CoMPInformationItem_item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_x2ap_CoMPInformationItem_item, CoMPInformationItem_item_sequence);

  return offset;
}


static const per_sequence_t CoMPInformationItem_sequence_of[1] = {
  { &hf_x2ap_CoMPInformationItem_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_x2ap_CoMPInformationItem_item },
};

static int
dissect_x2ap_CoMPInformationItem(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_x2ap_CoMPInformationItem, CoMPInformationItem_sequence_of,
                                                  1, maxnoofCoMPHypothesisSet, FALSE);

  return offset;
}



static int
dissect_x2ap_INTEGER_0_1023_(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 1023U, NULL, TRUE);

  return offset;
}



static int
dissect_x2ap_INTEGER_0_9_(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 9U, NULL, TRUE);

  return offset;
}


static const per_sequence_t CoMPInformationStartTime_item_sequence[] = {
  { &hf_x2ap_startSFN       , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_x2ap_INTEGER_0_1023_ },
  { &hf_x2ap_startSubframeNumber, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_x2ap_INTEGER_0_9_ },
  { &hf_x2ap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_x2ap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_x2ap_CoMPInformationStartTime_item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_x2ap_CoMPInformationStartTime_item, CoMPInformationStartTime_item_sequence);

  return offset;
}


static const per_sequence_t CoMPInformationStartTime_sequence_of[1] = {
  { &hf_x2ap_CoMPInformationStartTime_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_x2ap_CoMPInformationStartTime_item },
};

static int
dissect_x2ap_CoMPInformationStartTime(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_x2ap_CoMPInformationStartTime, CoMPInformationStartTime_sequence_of,
                                                  0, 1, FALSE);

  return offset;
}


static const per_sequence_t CoMPInformation_sequence[] = {
  { &hf_x2ap_coMPInformationItem, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_x2ap_CoMPInformationItem },
  { &hf_x2ap_coMPInformationStartTime, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_x2ap_CoMPInformationStartTime },
  { &hf_x2ap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_x2ap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_x2ap_CoMPInformation(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_x2ap_CoMPInformation, CoMPInformation_sequence);

  return offset;
}


static const per_sequence_t CompositeAvailableCapacity_sequence[] = {
  { &hf_x2ap_cellCapacityClassValue, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_x2ap_CellCapacityClassValue },
  { &hf_x2ap_capacityValue  , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_x2ap_CapacityValue },
  { &hf_x2ap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_x2ap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_x2ap_CompositeAvailableCapacity(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_x2ap_CompositeAvailableCapacity, CompositeAvailableCapacity_sequence);

  return offset;
}


static const per_sequence_t CompositeAvailableCapacityGroup_sequence[] = {
  { &hf_x2ap_dL_CompositeAvailableCapacity, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_x2ap_CompositeAvailableCapacity },
  { &hf_x2ap_uL_CompositeAvailableCapacity, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_x2ap_CompositeAvailableCapacity },
  { &hf_x2ap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_x2ap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_x2ap_CompositeAvailableCapacityGroup(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_x2ap_CompositeAvailableCapacityGroup, CompositeAvailableCapacityGroup_sequence);

  return offset;
}



static int
dissect_x2ap_Correlation_ID(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_octet_string(tvb, offset, actx, tree, hf_index,
                                       4, 4, FALSE, NULL);

  return offset;
}



static int
dissect_x2ap_PDCP_SN(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 4095U, NULL, FALSE);

  return offset;
}



static int
dissect_x2ap_HFN(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 1048575U, NULL, FALSE);

  return offset;
}


static const per_sequence_t COUNTvalue_sequence[] = {
  { &hf_x2ap_pDCP_SN        , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_x2ap_PDCP_SN },
  { &hf_x2ap_hFN            , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_x2ap_HFN },
  { &hf_x2ap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_x2ap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_x2ap_COUNTvalue(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_x2ap_COUNTvalue, COUNTvalue_sequence);

  return offset;
}



static int
dissect_x2ap_PDCP_SNExtended(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 32767U, NULL, FALSE);

  return offset;
}



static int
dissect_x2ap_HFNModified(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 131071U, NULL, FALSE);

  return offset;
}


static const per_sequence_t COUNTValueExtended_sequence[] = {
  { &hf_x2ap_pDCP_SNExtended, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_x2ap_PDCP_SNExtended },
  { &hf_x2ap_hFNModified    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_x2ap_HFNModified },
  { &hf_x2ap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_x2ap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_x2ap_COUNTValueExtended(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_x2ap_COUNTValueExtended, COUNTValueExtended_sequence);

  return offset;
}



static int
dissect_x2ap_PDCP_SNlength18(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 262143U, NULL, FALSE);

  return offset;
}



static int
dissect_x2ap_HFNforPDCP_SNlength18(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 16383U, NULL, FALSE);

  return offset;
}


static const per_sequence_t COUNTvaluePDCP_SNlength18_sequence[] = {
  { &hf_x2ap_pDCP_SNlength18, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_x2ap_PDCP_SNlength18 },
  { &hf_x2ap_hFNforPDCP_SNlength18, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_x2ap_HFNforPDCP_SNlength18 },
  { &hf_x2ap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_x2ap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_x2ap_COUNTvaluePDCP_SNlength18(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_x2ap_COUNTvaluePDCP_SNlength18, COUNTvaluePDCP_SNlength18_sequence);

  return offset;
}



static int
dissect_x2ap_INTEGER_0_15_(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 15U, NULL, TRUE);

  return offset;
}


static const per_sequence_t CoverageModification_Item_sequence[] = {
  { &hf_x2ap_eCGI           , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_x2ap_ECGI },
  { &hf_x2ap_coverageState  , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_x2ap_INTEGER_0_15_ },
  { &hf_x2ap_cellDeploymentStatusIndicator, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_x2ap_CellDeploymentStatusIndicator },
  { &hf_x2ap_cellReplacingInfo, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_x2ap_CellReplacingInfo },
  { NULL, 0, 0, NULL }
};

static int
dissect_x2ap_CoverageModification_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_x2ap_CoverageModification_Item, CoverageModification_Item_sequence);

  return offset;
}


static const per_sequence_t CoverageModificationList_sequence_of[1] = {
  { &hf_x2ap_CoverageModificationList_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_x2ap_CoverageModification_Item },
};

static int
dissect_x2ap_CoverageModificationList(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_x2ap_CoverageModificationList, CoverageModificationList_sequence_of,
                                                  1, maxCellineNB, FALSE);

  return offset;
}


static const value_string x2ap_TypeOfError_vals[] = {
  {   0, "not-understood" },
  {   1, "missing" },
  { 0, NULL }
};


static int
dissect_x2ap_TypeOfError(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     2, NULL, TRUE, 0, NULL);

  return offset;
}


static const per_sequence_t CriticalityDiagnostics_IE_List_item_sequence[] = {
  { &hf_x2ap_iECriticality  , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_x2ap_Criticality },
  { &hf_x2ap_iE_ID          , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_x2ap_ProtocolIE_ID },
  { &hf_x2ap_typeOfError    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_x2ap_TypeOfError },
  { &hf_x2ap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_x2ap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_x2ap_CriticalityDiagnostics_IE_List_item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_x2ap_CriticalityDiagnostics_IE_List_item, CriticalityDiagnostics_IE_List_item_sequence);

  return offset;
}


static const per_sequence_t CriticalityDiagnostics_IE_List_sequence_of[1] = {
  { &hf_x2ap_CriticalityDiagnostics_IE_List_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_x2ap_CriticalityDiagnostics_IE_List_item },
};

static int
dissect_x2ap_CriticalityDiagnostics_IE_List(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_x2ap_CriticalityDiagnostics_IE_List, CriticalityDiagnostics_IE_List_sequence_of,
                                                  1, maxNrOfErrors, FALSE);

  return offset;
}


static const per_sequence_t CriticalityDiagnostics_sequence[] = {
  { &hf_x2ap_procedureCode  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_x2ap_ProcedureCode },
  { &hf_x2ap_triggeringMessage, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_x2ap_TriggeringMessage },
  { &hf_x2ap_procedureCriticality, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_x2ap_Criticality },
  { &hf_x2ap_iEsCriticalityDiagnostics, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_x2ap_CriticalityDiagnostics_IE_List },
  { &hf_x2ap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_x2ap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_x2ap_CriticalityDiagnostics(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_x2ap_CriticalityDiagnostics, CriticalityDiagnostics_sequence);

  return offset;
}



static int
dissect_x2ap_CRNTI(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_bit_string(tvb, offset, actx, tree, hf_index,
                                     16, 16, FALSE, NULL, NULL);

  return offset;
}


static const value_string x2ap_CSGMembershipStatus_vals[] = {
  {   0, "member" },
  {   1, "not-member" },
  { 0, NULL }
};


static int
dissect_x2ap_CSGMembershipStatus(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     2, NULL, FALSE, 0, NULL);

  return offset;
}



static int
dissect_x2ap_CSG_Id(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_bit_string(tvb, offset, actx, tree, hf_index,
                                     27, 27, FALSE, NULL, NULL);

  return offset;
}



static int
dissect_x2ap_UEID(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_bit_string(tvb, offset, actx, tree, hf_index,
                                     16, 16, FALSE, NULL, NULL);

  return offset;
}



static int
dissect_x2ap_INTEGER_1_7_(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            1U, 7U, NULL, TRUE);

  return offset;
}



static int
dissect_x2ap_INTEGER_1_8_(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            1U, 8U, NULL, TRUE);

  return offset;
}



static int
dissect_x2ap_INTEGER_0_7_(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 7U, NULL, TRUE);

  return offset;
}


static const value_string x2ap_WidebandCQICodeword1_vals[] = {
  {   0, "four-bitCQI" },
  {   1, "three-bitSpatialDifferentialCQI" },
  { 0, NULL }
};

static const per_choice_t WidebandCQICodeword1_choice[] = {
  {   0, &hf_x2ap_four_bitCQI    , ASN1_EXTENSION_ROOT    , dissect_x2ap_INTEGER_0_15_ },
  {   1, &hf_x2ap_three_bitSpatialDifferentialCQI, ASN1_EXTENSION_ROOT    , dissect_x2ap_INTEGER_0_7_ },
  { 0, NULL, 0, NULL }
};

static int
dissect_x2ap_WidebandCQICodeword1(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_x2ap_WidebandCQICodeword1, WidebandCQICodeword1_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t WidebandCQI_sequence[] = {
  { &hf_x2ap_widebandCQICodeword0, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_x2ap_INTEGER_0_15_ },
  { &hf_x2ap_widebandCQICodeword1, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_x2ap_WidebandCQICodeword1 },
  { &hf_x2ap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_x2ap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_x2ap_WidebandCQI(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_x2ap_WidebandCQI, WidebandCQI_sequence);

  return offset;
}


static const value_string x2ap_SubbandSize_vals[] = {
  {   0, "size2" },
  {   1, "size3" },
  {   2, "size4" },
  {   3, "size6" },
  {   4, "size8" },
  { 0, NULL }
};


static int
dissect_x2ap_SubbandSize(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     5, NULL, TRUE, 0, NULL);

  return offset;
}



static int
dissect_x2ap_INTEGER_0_3_(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 3U, NULL, TRUE);

  return offset;
}


static const value_string x2ap_SubbandCQICodeword0_vals[] = {
  {   0, "four-bitCQI" },
  {   1, "two-bitSubbandDifferentialCQI" },
  {   2, "two-bitDifferentialCQI" },
  { 0, NULL }
};

static const per_choice_t SubbandCQICodeword0_choice[] = {
  {   0, &hf_x2ap_four_bitCQI    , ASN1_EXTENSION_ROOT    , dissect_x2ap_INTEGER_0_15_ },
  {   1, &hf_x2ap_two_bitSubbandDifferentialCQI, ASN1_EXTENSION_ROOT    , dissect_x2ap_INTEGER_0_3_ },
  {   2, &hf_x2ap_two_bitDifferentialCQI, ASN1_EXTENSION_ROOT    , dissect_x2ap_INTEGER_0_3_ },
  { 0, NULL, 0, NULL }
};

static int
dissect_x2ap_SubbandCQICodeword0(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_x2ap_SubbandCQICodeword0, SubbandCQICodeword0_choice,
                                 NULL);

  return offset;
}


static const value_string x2ap_SubbandCQICodeword1_vals[] = {
  {   0, "four-bitCQI" },
  {   1, "three-bitSpatialDifferentialCQI" },
  {   2, "two-bitSubbandDifferentialCQI" },
  {   3, "two-bitDifferentialCQI" },
  { 0, NULL }
};

static const per_choice_t SubbandCQICodeword1_choice[] = {
  {   0, &hf_x2ap_four_bitCQI    , ASN1_EXTENSION_ROOT    , dissect_x2ap_INTEGER_0_15_ },
  {   1, &hf_x2ap_three_bitSpatialDifferentialCQI, ASN1_EXTENSION_ROOT    , dissect_x2ap_INTEGER_0_7_ },
  {   2, &hf_x2ap_two_bitSubbandDifferentialCQI, ASN1_EXTENSION_ROOT    , dissect_x2ap_INTEGER_0_3_ },
  {   3, &hf_x2ap_two_bitDifferentialCQI, ASN1_EXTENSION_ROOT    , dissect_x2ap_INTEGER_0_3_ },
  { 0, NULL, 0, NULL }
};

static int
dissect_x2ap_SubbandCQICodeword1(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_x2ap_SubbandCQICodeword1, SubbandCQICodeword1_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t SubbandCQI_sequence[] = {
  { &hf_x2ap_subbandCQICodeword0, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_x2ap_SubbandCQICodeword0 },
  { &hf_x2ap_subbandCQICodeword1, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_x2ap_SubbandCQICodeword1 },
  { &hf_x2ap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_x2ap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_x2ap_SubbandCQI(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_x2ap_SubbandCQI, SubbandCQI_sequence);

  return offset;
}



static int
dissect_x2ap_INTEGER_0_27_(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 27U, NULL, TRUE);

  return offset;
}


static const per_sequence_t SubbandCQIItem_sequence[] = {
  { &hf_x2ap_subbandCQI     , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_x2ap_SubbandCQI },
  { &hf_x2ap_subbandIndex   , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_x2ap_INTEGER_0_27_ },
  { &hf_x2ap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_x2ap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_x2ap_SubbandCQIItem(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_x2ap_SubbandCQIItem, SubbandCQIItem_sequence);

  return offset;
}


static const per_sequence_t SubbandCQIList_sequence_of[1] = {
  { &hf_x2ap_SubbandCQIList_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_x2ap_SubbandCQIItem },
};

static int
dissect_x2ap_SubbandCQIList(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_x2ap_SubbandCQIList, SubbandCQIList_sequence_of,
                                                  1, maxSubband, FALSE);

  return offset;
}


static const per_sequence_t CSIReportPerCSIProcessItem_item_sequence[] = {
  { &hf_x2ap_rI             , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_x2ap_INTEGER_1_8_ },
  { &hf_x2ap_widebandCQI    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_x2ap_WidebandCQI },
  { &hf_x2ap_subbandSize    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_x2ap_SubbandSize },
  { &hf_x2ap_subbandCQIList , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_x2ap_SubbandCQIList },
  { &hf_x2ap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_x2ap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_x2ap_CSIReportPerCSIProcessItem_item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_x2ap_CSIReportPerCSIProcessItem_item, CSIReportPerCSIProcessItem_item_sequence);

  return offset;
}


static const per_sequence_t CSIReportPerCSIProcessItem_sequence_of[1] = {
  { &hf_x2ap_CSIReportPerCSIProcessItem_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_x2ap_CSIReportPerCSIProcessItem_item },
};

static int
dissect_x2ap_CSIReportPerCSIProcessItem(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_x2ap_CSIReportPerCSIProcessItem, CSIReportPerCSIProcessItem_sequence_of,
                                                  1, maxCSIReport, FALSE);

  return offset;
}


static const per_sequence_t CSIReportPerCSIProcess_item_sequence[] = {
  { &hf_x2ap_cSIProcessConfigurationIndex, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_x2ap_INTEGER_1_7_ },
  { &hf_x2ap_cSIReportPerCSIProcessItem, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_x2ap_CSIReportPerCSIProcessItem },
  { &hf_x2ap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_x2ap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_x2ap_CSIReportPerCSIProcess_item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_x2ap_CSIReportPerCSIProcess_item, CSIReportPerCSIProcess_item_sequence);

  return offset;
}


static const per_sequence_t CSIReportPerCSIProcess_sequence_of[1] = {
  { &hf_x2ap_CSIReportPerCSIProcess_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_x2ap_CSIReportPerCSIProcess_item },
};

static int
dissect_x2ap_CSIReportPerCSIProcess(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_x2ap_CSIReportPerCSIProcess, CSIReportPerCSIProcess_sequence_of,
                                                  1, maxCSIProcess, FALSE);

  return offset;
}


static const per_sequence_t CSIReportList_item_sequence[] = {
  { &hf_x2ap_uEID           , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_x2ap_UEID },
  { &hf_x2ap_cSIReportPerCSIProcess, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_x2ap_CSIReportPerCSIProcess },
  { &hf_x2ap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_x2ap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_x2ap_CSIReportList_item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_x2ap_CSIReportList_item, CSIReportList_item_sequence);

  return offset;
}


static const per_sequence_t CSIReportList_sequence_of[1] = {
  { &hf_x2ap_CSIReportList_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_x2ap_CSIReportList_item },
};

static int
dissect_x2ap_CSIReportList(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_x2ap_CSIReportList, CSIReportList_sequence_of,
                                                  1, maxUEReport, FALSE);

  return offset;
}


static const value_string x2ap_DeactivationIndication_vals[] = {
  {   0, "deactivated" },
  { 0, NULL }
};


static int
dissect_x2ap_DeactivationIndication(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     1, NULL, TRUE, 0, NULL);

  return offset;
}


static const value_string x2ap_DL_Forwarding_vals[] = {
  {   0, "dL-forwardingProposed" },
  { 0, NULL }
};


static int
dissect_x2ap_DL_Forwarding(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     1, NULL, TRUE, 0, NULL);

  return offset;
}



static int
dissect_x2ap_DL_GBR_PRB_usage(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 100U, NULL, FALSE);

  return offset;
}



static int
dissect_x2ap_DL_non_GBR_PRB_usage(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 100U, NULL, FALSE);

  return offset;
}



static int
dissect_x2ap_DL_Total_PRB_usage(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 100U, NULL, FALSE);

  return offset;
}



static int
dissect_x2ap_T_transmissionModes(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 428 "./asn1/x2ap/x2ap.cnf"
  tvbuff_t *parameter_tvb = NULL;
  offset = dissect_per_bit_string(tvb, offset, actx, tree, hf_index,
                                     8, 8, FALSE, &parameter_tvb, NULL);

  if(parameter_tvb){
    const gint *fields[] = {
      &hf_x2ap_MDT_transmissionModes_tm1,
      &hf_x2ap_MDT_transmissionModes_tm2,
      &hf_x2ap_MDT_transmissionModes_tm3,
      &hf_x2ap_MDT_transmissionModes_tm4,
      &hf_x2ap_MDT_transmissionModes_tm6,
      &hf_x2ap_MDT_transmissionModes_tm8,
      &hf_x2ap_MDT_transmissionModes_tm9,
      &hf_x2ap_MDT_transmissionModes_tm10,
      NULL
    };
    proto_tree *subtree = proto_item_add_subtree(actx->created_item, ett_x2ap_transmissionModes);
    proto_tree_add_bitmask_list(subtree, parameter_tvb, 0, 1, fields, ENC_BIG_ENDIAN);
  }



  return offset;
}



static int
dissect_x2ap_INTEGER_0_3(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 3U, NULL, FALSE);

  return offset;
}


static const value_string x2ap_PA_Values_vals[] = {
  {   0, "dB-6" },
  {   1, "dB-4dot77" },
  {   2, "dB-3" },
  {   3, "dB-1dot77" },
  {   4, "dB0" },
  {   5, "dB1" },
  {   6, "dB2" },
  {   7, "dB3" },
  { 0, NULL }
};


static int
dissect_x2ap_PA_Values(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     8, NULL, TRUE, 0, NULL);

  return offset;
}


static const per_sequence_t SEQUENCE_SIZE_0_maxnoofPA_OF_PA_Values_sequence_of[1] = {
  { &hf_x2ap_pA_list_item   , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_x2ap_PA_Values },
};

static int
dissect_x2ap_SEQUENCE_SIZE_0_maxnoofPA_OF_PA_Values(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_x2ap_SEQUENCE_SIZE_0_maxnoofPA_OF_PA_Values, SEQUENCE_SIZE_0_maxnoofPA_OF_PA_Values_sequence_of,
                                                  0, maxnoofPA, FALSE);

  return offset;
}


static const per_sequence_t DynamicNAICSInformation_sequence[] = {
  { &hf_x2ap_transmissionModes, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_x2ap_T_transmissionModes },
  { &hf_x2ap_pB_information , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_x2ap_INTEGER_0_3 },
  { &hf_x2ap_pA_list        , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_x2ap_SEQUENCE_SIZE_0_maxnoofPA_OF_PA_Values },
  { &hf_x2ap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_x2ap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_x2ap_DynamicNAICSInformation(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_x2ap_DynamicNAICSInformation, DynamicNAICSInformation_sequence);

  return offset;
}


static const value_string x2ap_DynamicDLTransmissionInformation_vals[] = {
  {   0, "naics-active" },
  {   1, "naics-inactive" },
  { 0, NULL }
};

static const per_choice_t DynamicDLTransmissionInformation_choice[] = {
  {   0, &hf_x2ap_naics_active   , ASN1_EXTENSION_ROOT    , dissect_x2ap_DynamicNAICSInformation },
  {   1, &hf_x2ap_naics_inactive , ASN1_EXTENSION_ROOT    , dissect_x2ap_NULL },
  { 0, NULL, 0, NULL }
};

static int
dissect_x2ap_DynamicDLTransmissionInformation(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_x2ap_DynamicDLTransmissionInformation, DynamicDLTransmissionInformation_choice,
                                 NULL);

  return offset;
}



static int
dissect_x2ap_EARFCN(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, maxEARFCN, NULL, FALSE);

  return offset;
}



static int
dissect_x2ap_EARFCNExtension(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            maxEARFCNPlusOne, newmaxEARFCN, NULL, TRUE);

  return offset;
}



static int
dissect_x2ap_BIT_STRING_SIZE_12_8800_(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_bit_string(tvb, offset, actx, tree, hf_index,
                                     12, 8800, TRUE, NULL, NULL);

  return offset;
}


static const value_string x2ap_RNTP_Threshold_vals[] = {
  {   0, "minusInfinity" },
  {   1, "minusEleven" },
  {   2, "minusTen" },
  {   3, "minusNine" },
  {   4, "minusEight" },
  {   5, "minusSeven" },
  {   6, "minusSix" },
  {   7, "minusFive" },
  {   8, "minusFour" },
  {   9, "minusThree" },
  {  10, "minusTwo" },
  {  11, "minusOne" },
  {  12, "zero" },
  {  13, "one" },
  {  14, "two" },
  {  15, "three" },
  { 0, NULL }
};


static int
dissect_x2ap_RNTP_Threshold(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     16, NULL, TRUE, 0, NULL);

  return offset;
}


static const per_sequence_t EnhancedRNTPStartTime_sequence[] = {
  { &hf_x2ap_startSFN       , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_x2ap_INTEGER_0_1023_ },
  { &hf_x2ap_startSubframeNumber, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_x2ap_INTEGER_0_9_ },
  { &hf_x2ap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_x2ap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_x2ap_EnhancedRNTPStartTime(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_x2ap_EnhancedRNTPStartTime, EnhancedRNTPStartTime_sequence);

  return offset;
}


static const per_sequence_t EnhancedRNTP_sequence[] = {
  { &hf_x2ap_enhancedRNTPBitmap, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_x2ap_BIT_STRING_SIZE_12_8800_ },
  { &hf_x2ap_rNTP_High_Power_Threshold, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_x2ap_RNTP_Threshold },
  { &hf_x2ap_enhancedRNTPStartTime, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_x2ap_EnhancedRNTPStartTime },
  { &hf_x2ap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_x2ap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_x2ap_EnhancedRNTP(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_x2ap_EnhancedRNTP, EnhancedRNTP_sequence);

  return offset;
}



static int
dissect_x2ap_BIT_STRING_SIZE_20(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_bit_string(tvb, offset, actx, tree, hf_index,
                                     20, 20, FALSE, NULL, NULL);

  return offset;
}



static int
dissect_x2ap_BIT_STRING_SIZE_28(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_bit_string(tvb, offset, actx, tree, hf_index,
                                     28, 28, FALSE, NULL, NULL);

  return offset;
}


static const value_string x2ap_ENB_ID_vals[] = {
  {   0, "macro-eNB-ID" },
  {   1, "home-eNB-ID" },
  { 0, NULL }
};

static const per_choice_t ENB_ID_choice[] = {
  {   0, &hf_x2ap_macro_eNB_ID   , ASN1_EXTENSION_ROOT    , dissect_x2ap_BIT_STRING_SIZE_20 },
  {   1, &hf_x2ap_home_eNB_ID    , ASN1_EXTENSION_ROOT    , dissect_x2ap_BIT_STRING_SIZE_28 },
  { 0, NULL, 0, NULL }
};

static int
dissect_x2ap_ENB_ID(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_x2ap_ENB_ID, ENB_ID_choice,
                                 NULL);

  return offset;
}



static int
dissect_x2ap_EncryptionAlgorithms(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 335 "./asn1/x2ap/x2ap.cnf"
  tvbuff_t *parameter_tvb = NULL;
  offset = dissect_per_bit_string(tvb, offset, actx, tree, hf_index,
                                     16, 16, TRUE, &parameter_tvb, NULL);

  if(parameter_tvb){
    const gint *fields[] = {
      &hf_x2ap_encryptionAlgorithms_EEA1,
      &hf_x2ap_encryptionAlgorithms_EEA2,
      &hf_x2ap_encryptionAlgorithms_EEA3,
      &hf_x2ap_encryptionAlgorithms_Reserved,
      NULL
    };
    proto_tree *subtree = proto_item_add_subtree(actx->created_item, ett_x2ap_EncryptionAlgorithms);
    proto_tree_add_bitmask_list(subtree, parameter_tvb, 0, 2, fields, ENC_BIG_ENDIAN);
  }



  return offset;
}


static const per_sequence_t EPLMNs_sequence_of[1] = {
  { &hf_x2ap_EPLMNs_item    , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_x2ap_PLMN_Identity },
};

static int
dissect_x2ap_EPLMNs(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_x2ap_EPLMNs, EPLMNs_sequence_of,
                                                  1, maxnoofEPLMNs, FALSE);

  return offset;
}



static int
dissect_x2ap_E_RAB_ID(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 15U, NULL, TRUE);

  return offset;
}



static int
dissect_x2ap_QCI(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 255U, NULL, FALSE);

  return offset;
}


static const per_sequence_t GBR_QosInformation_sequence[] = {
  { &hf_x2ap_e_RAB_MaximumBitrateDL, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_x2ap_BitRate },
  { &hf_x2ap_e_RAB_MaximumBitrateUL, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_x2ap_BitRate },
  { &hf_x2ap_e_RAB_GuaranteedBitrateDL, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_x2ap_BitRate },
  { &hf_x2ap_e_RAB_GuaranteedBitrateUL, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_x2ap_BitRate },
  { &hf_x2ap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_x2ap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_x2ap_GBR_QosInformation(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_x2ap_GBR_QosInformation, GBR_QosInformation_sequence);

  return offset;
}


static const per_sequence_t E_RAB_Level_QoS_Parameters_sequence[] = {
  { &hf_x2ap_qCI            , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_x2ap_QCI },
  { &hf_x2ap_allocationAndRetentionPriority, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_x2ap_AllocationAndRetentionPriority },
  { &hf_x2ap_gbrQosInformation, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_x2ap_GBR_QosInformation },
  { &hf_x2ap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_x2ap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_x2ap_E_RAB_Level_QoS_Parameters(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_x2ap_E_RAB_Level_QoS_Parameters, E_RAB_Level_QoS_Parameters_sequence);

  return offset;
}


static const per_sequence_t E_RAB_List_sequence_of[1] = {
  { &hf_x2ap_E_RAB_List_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_x2ap_ProtocolIE_Single_Container },
};

static int
dissect_x2ap_E_RAB_List(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_x2ap_E_RAB_List, E_RAB_List_sequence_of,
                                                  1, maxnoofBearers, FALSE);

  return offset;
}


static const per_sequence_t E_RAB_Item_sequence[] = {
  { &hf_x2ap_e_RAB_ID       , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_x2ap_E_RAB_ID },
  { &hf_x2ap_cause          , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_x2ap_Cause },
  { &hf_x2ap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_x2ap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_x2ap_E_RAB_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_x2ap_E_RAB_Item, E_RAB_Item_sequence);

  return offset;
}


static const value_string x2ap_Transmission_Bandwidth_vals[] = {
  {   0, "bw6" },
  {   1, "bw15" },
  {   2, "bw25" },
  {   3, "bw50" },
  {   4, "bw75" },
  {   5, "bw100" },
  {   6, "bw1" },
  { 0, NULL }
};


static int
dissect_x2ap_Transmission_Bandwidth(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     6, NULL, TRUE, 1, NULL);

  return offset;
}


static const per_sequence_t FDD_Info_sequence[] = {
  { &hf_x2ap_uL_EARFCN      , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_x2ap_EARFCN },
  { &hf_x2ap_dL_EARFCN      , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_x2ap_EARFCN },
  { &hf_x2ap_uL_Transmission_Bandwidth, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_x2ap_Transmission_Bandwidth },
  { &hf_x2ap_dL_Transmission_Bandwidth, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_x2ap_Transmission_Bandwidth },
  { &hf_x2ap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_x2ap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_x2ap_FDD_Info(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_x2ap_FDD_Info, FDD_Info_sequence);

  return offset;
}


static const value_string x2ap_SubframeAssignment_vals[] = {
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
dissect_x2ap_SubframeAssignment(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     7, NULL, TRUE, 0, NULL);

  return offset;
}


static const value_string x2ap_SpecialSubframePatterns_vals[] = {
  {   0, "ssp0" },
  {   1, "ssp1" },
  {   2, "ssp2" },
  {   3, "ssp3" },
  {   4, "ssp4" },
  {   5, "ssp5" },
  {   6, "ssp6" },
  {   7, "ssp7" },
  {   8, "ssp8" },
  { 0, NULL }
};


static int
dissect_x2ap_SpecialSubframePatterns(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     9, NULL, TRUE, 0, NULL);

  return offset;
}


static const per_sequence_t SpecialSubframe_Info_sequence[] = {
  { &hf_x2ap_specialSubframePatterns, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_x2ap_SpecialSubframePatterns },
  { &hf_x2ap_cyclicPrefixDL , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_x2ap_CyclicPrefixDL },
  { &hf_x2ap_cyclicPrefixUL , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_x2ap_CyclicPrefixUL },
  { &hf_x2ap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_x2ap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_x2ap_SpecialSubframe_Info(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_x2ap_SpecialSubframe_Info, SpecialSubframe_Info_sequence);

  return offset;
}


static const per_sequence_t TDD_Info_sequence[] = {
  { &hf_x2ap_eARFCN         , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_x2ap_EARFCN },
  { &hf_x2ap_transmission_Bandwidth, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_x2ap_Transmission_Bandwidth },
  { &hf_x2ap_subframeAssignment, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_x2ap_SubframeAssignment },
  { &hf_x2ap_specialSubframe_Info, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_x2ap_SpecialSubframe_Info },
  { &hf_x2ap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_x2ap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_x2ap_TDD_Info(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_x2ap_TDD_Info, TDD_Info_sequence);

  return offset;
}


static const value_string x2ap_EUTRA_Mode_Info_vals[] = {
  {   0, "fDD" },
  {   1, "tDD" },
  { 0, NULL }
};

static const per_choice_t EUTRA_Mode_Info_choice[] = {
  {   0, &hf_x2ap_fDD            , ASN1_EXTENSION_ROOT    , dissect_x2ap_FDD_Info },
  {   1, &hf_x2ap_tDD            , ASN1_EXTENSION_ROOT    , dissect_x2ap_TDD_Info },
  { 0, NULL, 0, NULL }
};

static int
dissect_x2ap_EUTRA_Mode_Info(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_x2ap_EUTRA_Mode_Info, EUTRA_Mode_Info_choice,
                                 NULL);

  return offset;
}



static int
dissect_x2ap_EUTRANTraceID(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 232 "./asn1/x2ap/x2ap.cnf"
 tvbuff_t *parameter_tvb;
 proto_tree *subtree = NULL;
  offset = dissect_per_octet_string(tvb, offset, actx, tree, hf_index,
                                       8, 8, FALSE, &parameter_tvb);

  if (!parameter_tvb)
    return offset;
  subtree = proto_item_add_subtree(actx->created_item, ett_x2ap_EUTRANTraceID);
  dissect_e212_mcc_mnc(parameter_tvb, actx->pinfo, subtree, 0, E212_NONE, FALSE);
  proto_tree_add_item(subtree, hf_x2ap_eUTRANTraceID_TraceID, parameter_tvb, 3, 3, ENC_BIG_ENDIAN);
  proto_tree_add_item(subtree, hf_x2ap_eUTRANTraceID_TraceRecordingSessionReference, parameter_tvb, 6, 2, ENC_BIG_ENDIAN);



  return offset;
}


static const value_string x2ap_EventType_vals[] = {
  {   0, "change-of-serving-cell" },
  { 0, NULL }
};


static int
dissect_x2ap_EventType(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     1, NULL, TRUE, 0, NULL);

  return offset;
}



static int
dissect_x2ap_ExpectedActivityPeriod(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            1U, 181U, NULL, FALSE);

  return offset;
}



static int
dissect_x2ap_ExpectedIdlePeriod(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            1U, 181U, NULL, FALSE);

  return offset;
}


static const value_string x2ap_SourceOfUEActivityBehaviourInformation_vals[] = {
  {   0, "subscription-information" },
  {   1, "statistics" },
  { 0, NULL }
};


static int
dissect_x2ap_SourceOfUEActivityBehaviourInformation(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     2, NULL, TRUE, 0, NULL);

  return offset;
}


static const per_sequence_t ExpectedUEActivityBehaviour_sequence[] = {
  { &hf_x2ap_expectedActivityPeriod, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_x2ap_ExpectedActivityPeriod },
  { &hf_x2ap_expectedIdlePeriod, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_x2ap_ExpectedIdlePeriod },
  { &hf_x2ap_sourceofUEActivityBehaviourInformation, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_x2ap_SourceOfUEActivityBehaviourInformation },
  { &hf_x2ap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_x2ap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_x2ap_ExpectedUEActivityBehaviour(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_x2ap_ExpectedUEActivityBehaviour, ExpectedUEActivityBehaviour_sequence);

  return offset;
}


static const value_string x2ap_ExpectedHOInterval_vals[] = {
  {   0, "sec15" },
  {   1, "sec30" },
  {   2, "sec60" },
  {   3, "sec90" },
  {   4, "sec120" },
  {   5, "sec180" },
  {   6, "long-time" },
  { 0, NULL }
};


static int
dissect_x2ap_ExpectedHOInterval(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     7, NULL, TRUE, 0, NULL);

  return offset;
}


static const per_sequence_t ExpectedUEBehaviour_sequence[] = {
  { &hf_x2ap_expectedActivity, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_x2ap_ExpectedUEActivityBehaviour },
  { &hf_x2ap_expectedHOInterval, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_x2ap_ExpectedHOInterval },
  { &hf_x2ap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_x2ap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_x2ap_ExpectedUEBehaviour(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_x2ap_ExpectedUEBehaviour, ExpectedUEBehaviour_sequence);

  return offset;
}



static int
dissect_x2ap_BIT_STRING_SIZE_5(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_bit_string(tvb, offset, actx, tree, hf_index,
                                     5, 5, FALSE, NULL, NULL);

  return offset;
}


static const value_string x2ap_UL_InterferenceOverloadIndication_Item_vals[] = {
  {   0, "high-interference" },
  {   1, "medium-interference" },
  {   2, "low-interference" },
  { 0, NULL }
};


static int
dissect_x2ap_UL_InterferenceOverloadIndication_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     3, NULL, TRUE, 0, NULL);

  return offset;
}


static const per_sequence_t UL_InterferenceOverloadIndication_sequence_of[1] = {
  { &hf_x2ap_UL_InterferenceOverloadIndication_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_x2ap_UL_InterferenceOverloadIndication_Item },
};

static int
dissect_x2ap_UL_InterferenceOverloadIndication(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_x2ap_UL_InterferenceOverloadIndication, UL_InterferenceOverloadIndication_sequence_of,
                                                  1, maxnoofPRBs, FALSE);

  return offset;
}


static const per_sequence_t ExtendedULInterferenceOverloadInfo_sequence[] = {
  { &hf_x2ap_associatedSubframes, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_x2ap_BIT_STRING_SIZE_5 },
  { &hf_x2ap_extended_ul_InterferenceOverloadIndication, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_x2ap_UL_InterferenceOverloadIndication },
  { &hf_x2ap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_x2ap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_x2ap_ExtendedULInterferenceOverloadInfo(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_x2ap_ExtendedULInterferenceOverloadInfo, ExtendedULInterferenceOverloadInfo_sequence);

  return offset;
}


static const value_string x2ap_ForbiddenInterRATs_vals[] = {
  {   0, "all" },
  {   1, "geran" },
  {   2, "utran" },
  {   3, "cdma2000" },
  {   4, "geranandutran" },
  {   5, "cdma2000andutran" },
  { 0, NULL }
};


static int
dissect_x2ap_ForbiddenInterRATs(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     4, NULL, TRUE, 2, NULL);

  return offset;
}


static const per_sequence_t ForbiddenTACs_sequence_of[1] = {
  { &hf_x2ap_ForbiddenTACs_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_x2ap_TAC },
};

static int
dissect_x2ap_ForbiddenTACs(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_x2ap_ForbiddenTACs, ForbiddenTACs_sequence_of,
                                                  1, maxnoofForbTACs, FALSE);

  return offset;
}


static const per_sequence_t ForbiddenTAs_Item_sequence[] = {
  { &hf_x2ap_pLMN_Identity  , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_x2ap_PLMN_Identity },
  { &hf_x2ap_forbiddenTACs  , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_x2ap_ForbiddenTACs },
  { &hf_x2ap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_x2ap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_x2ap_ForbiddenTAs_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_x2ap_ForbiddenTAs_Item, ForbiddenTAs_Item_sequence);

  return offset;
}


static const per_sequence_t ForbiddenTAs_sequence_of[1] = {
  { &hf_x2ap_ForbiddenTAs_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_x2ap_ForbiddenTAs_Item },
};

static int
dissect_x2ap_ForbiddenTAs(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_x2ap_ForbiddenTAs, ForbiddenTAs_sequence_of,
                                                  1, maxnoofEPLMNsPlusOne, FALSE);

  return offset;
}



static int
dissect_x2ap_LAC(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 292 "./asn1/x2ap/x2ap.cnf"
  tvbuff_t *parameter_tvb = NULL;
  offset = dissect_per_octet_string(tvb, offset, actx, tree, -1,
                                       2, 2, FALSE, &parameter_tvb);

  if (parameter_tvb) {
    actx->created_item = proto_tree_add_item(tree, hf_index, parameter_tvb, 0, 2, ENC_BIG_ENDIAN);
  }



  return offset;
}


static const per_sequence_t ForbiddenLACs_sequence_of[1] = {
  { &hf_x2ap_ForbiddenLACs_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_x2ap_LAC },
};

static int
dissect_x2ap_ForbiddenLACs(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_x2ap_ForbiddenLACs, ForbiddenLACs_sequence_of,
                                                  1, maxnoofForbLACs, FALSE);

  return offset;
}


static const per_sequence_t ForbiddenLAs_Item_sequence[] = {
  { &hf_x2ap_pLMN_Identity  , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_x2ap_PLMN_Identity },
  { &hf_x2ap_forbiddenLACs  , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_x2ap_ForbiddenLACs },
  { &hf_x2ap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_x2ap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_x2ap_ForbiddenLAs_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_x2ap_ForbiddenLAs_Item, ForbiddenLAs_Item_sequence);

  return offset;
}


static const per_sequence_t ForbiddenLAs_sequence_of[1] = {
  { &hf_x2ap_ForbiddenLAs_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_x2ap_ForbiddenLAs_Item },
};

static int
dissect_x2ap_ForbiddenLAs(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_x2ap_ForbiddenLAs, ForbiddenLAs_sequence_of,
                                                  1, maxnoofEPLMNsPlusOne, FALSE);

  return offset;
}



static int
dissect_x2ap_Fourframes(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_bit_string(tvb, offset, actx, tree, hf_index,
                                     24, 24, FALSE, NULL, NULL);

  return offset;
}



static int
dissect_x2ap_FreqBandIndicator(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            1U, 256U, NULL, TRUE);

  return offset;
}


static const value_string x2ap_FreqBandIndicatorPriority_vals[] = {
  {   0, "not-broadcasted" },
  {   1, "broadcasted" },
  { 0, NULL }
};


static int
dissect_x2ap_FreqBandIndicatorPriority(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     2, NULL, TRUE, 0, NULL);

  return offset;
}


static const per_sequence_t GlobalENB_ID_sequence[] = {
  { &hf_x2ap_pLMN_Identity  , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_x2ap_PLMN_Identity },
  { &hf_x2ap_eNB_ID         , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_x2ap_ENB_ID },
  { &hf_x2ap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_x2ap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_x2ap_GlobalENB_ID(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_x2ap_GlobalENB_ID, GlobalENB_ID_sequence);

  return offset;
}



static int
dissect_x2ap_TransportLayerAddress(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 95 "./asn1/x2ap/x2ap.cnf"
  tvbuff_t *parameter_tvb = NULL;
  proto_tree *subtree;
  int len;

  offset = dissect_per_bit_string(tvb, offset, actx, tree, hf_index,
                                     1, 160, TRUE, &parameter_tvb, &len);

  if (!parameter_tvb)
    return offset;

  subtree = proto_item_add_subtree(actx->created_item, ett_x2ap_TransportLayerAddress);
  if (len == 32) {
    /* IPv4 */
     proto_tree_add_item(subtree, hf_x2ap_transportLayerAddressIPv4, parameter_tvb, 0, 4, ENC_BIG_ENDIAN);
  } else if (len == 128) {
    /* IPv6 */
     proto_tree_add_item(subtree, hf_x2ap_transportLayerAddressIPv6, parameter_tvb, 0, 16, ENC_NA);
  } else if (len == 160) {
    /* IPv4 */
     proto_tree_add_item(subtree, hf_x2ap_transportLayerAddressIPv4, parameter_tvb, 0, 4, ENC_BIG_ENDIAN);
    /* IPv6 */
     proto_tree_add_item(subtree, hf_x2ap_transportLayerAddressIPv6, parameter_tvb, 4, 16, ENC_NA);
  }



  return offset;
}



static int
dissect_x2ap_GTP_TEI(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_octet_string(tvb, offset, actx, tree, hf_index,
                                       4, 4, FALSE, NULL);

  return offset;
}


static const per_sequence_t GTPtunnelEndpoint_sequence[] = {
  { &hf_x2ap_transportLayerAddress, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_x2ap_TransportLayerAddress },
  { &hf_x2ap_gTP_TEID       , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_x2ap_GTP_TEI },
  { &hf_x2ap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_x2ap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_x2ap_GTPtunnelEndpoint(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_x2ap_GTPtunnelEndpoint, GTPtunnelEndpoint_sequence);

  return offset;
}



static int
dissect_x2ap_MME_Group_ID(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 328 "./asn1/x2ap/x2ap.cnf"
  tvbuff_t *parameter_tvb = NULL;
  offset = dissect_per_octet_string(tvb, offset, actx, tree, -1,
                                       2, 2, FALSE, &parameter_tvb);

  if (parameter_tvb) {
    actx->created_item = proto_tree_add_item(tree, hf_index, parameter_tvb, 0, 2, ENC_BIG_ENDIAN);
  }



  return offset;
}


static const per_sequence_t GU_Group_ID_sequence[] = {
  { &hf_x2ap_pLMN_Identity  , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_x2ap_PLMN_Identity },
  { &hf_x2ap_mME_Group_ID   , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_x2ap_MME_Group_ID },
  { &hf_x2ap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_x2ap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_x2ap_GU_Group_ID(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_x2ap_GU_Group_ID, GU_Group_ID_sequence);

  return offset;
}


static const per_sequence_t GUGroupIDList_sequence_of[1] = {
  { &hf_x2ap_GUGroupIDList_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_x2ap_GU_Group_ID },
};

static int
dissect_x2ap_GUGroupIDList(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_x2ap_GUGroupIDList, GUGroupIDList_sequence_of,
                                                  1, maxPools, FALSE);

  return offset;
}



static int
dissect_x2ap_MME_Code(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 319 "./asn1/x2ap/x2ap.cnf"
  tvbuff_t *parameter_tvb = NULL;
  offset = dissect_per_octet_string(tvb, offset, actx, tree, -1,
                                       1, 1, FALSE, &parameter_tvb);

  if (parameter_tvb) {
    actx->created_item = proto_tree_add_item(tree, hf_index, parameter_tvb, 0, 1, ENC_BIG_ENDIAN);
  }



  return offset;
}


static const per_sequence_t GUMMEI_sequence[] = {
  { &hf_x2ap_gU_Group_ID    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_x2ap_GU_Group_ID },
  { &hf_x2ap_mME_Code       , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_x2ap_MME_Code },
  { &hf_x2ap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_x2ap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_x2ap_GUMMEI(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_x2ap_GUMMEI, GUMMEI_sequence);

  return offset;
}


static const value_string x2ap_HandoverReportType_vals[] = {
  {   0, "hoTooEarly" },
  {   1, "hoToWrongCell" },
  {   2, "interRATpingpong" },
  { 0, NULL }
};


static int
dissect_x2ap_HandoverReportType(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     2, NULL, TRUE, 1, NULL);

  return offset;
}


static const per_sequence_t HandoverRestrictionList_sequence[] = {
  { &hf_x2ap_servingPLMN    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_x2ap_PLMN_Identity },
  { &hf_x2ap_equivalentPLMNs, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_x2ap_EPLMNs },
  { &hf_x2ap_forbiddenTAs   , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_x2ap_ForbiddenTAs },
  { &hf_x2ap_forbiddenLAs   , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_x2ap_ForbiddenLAs },
  { &hf_x2ap_forbiddenInterRATs, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_x2ap_ForbiddenInterRATs },
  { &hf_x2ap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_x2ap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_x2ap_HandoverRestrictionList(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_x2ap_HandoverRestrictionList, HandoverRestrictionList_sequence);

  return offset;
}


static const value_string x2ap_LoadIndicator_vals[] = {
  {   0, "lowLoad" },
  {   1, "mediumLoad" },
  {   2, "highLoad" },
  {   3, "overLoad" },
  { 0, NULL }
};


static int
dissect_x2ap_LoadIndicator(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     4, NULL, TRUE, 0, NULL);

  return offset;
}


static const per_sequence_t HWLoadIndicator_sequence[] = {
  { &hf_x2ap_dLHWLoadIndicator, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_x2ap_LoadIndicator },
  { &hf_x2ap_uLHWLoadIndicator, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_x2ap_LoadIndicator },
  { &hf_x2ap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_x2ap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_x2ap_HWLoadIndicator(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_x2ap_HWLoadIndicator, HWLoadIndicator_sequence);

  return offset;
}



static int
dissect_x2ap_IntegrityProtectionAlgorithms(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 350 "./asn1/x2ap/x2ap.cnf"
  tvbuff_t *parameter_tvb = NULL;
  offset = dissect_per_bit_string(tvb, offset, actx, tree, hf_index,
                                     16, 16, TRUE, &parameter_tvb, NULL);

  if(parameter_tvb){
    const gint *fields[] = {
      &hf_x2ap_integrityProtectionAlgorithms_EIA1,
      &hf_x2ap_integrityProtectionAlgorithms_EIA2,
      &hf_x2ap_integrityProtectionAlgorithms_EIA3,
      &hf_x2ap_integrityProtectionAlgorithms_Reserved,
      NULL
    };
    proto_tree *subtree = proto_item_add_subtree(actx->created_item, ett_x2ap_IntegrityProtectionAlgorithms);
    proto_tree_add_bitmask_list(subtree, parameter_tvb, 0, 2, fields, ENC_BIG_ENDIAN);
  }



  return offset;
}



static int
dissect_x2ap_InterfacesToTrace(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 243 "./asn1/x2ap/x2ap.cnf"
  tvbuff_t *parameter_tvb = NULL;
  offset = dissect_per_bit_string(tvb, offset, actx, tree, hf_index,
                                     8, 8, FALSE, &parameter_tvb, NULL);

  if(parameter_tvb){
    const gint *fields[] = {
      &hf_x2ap_interfacesToTrace_S1_MME,
      &hf_x2ap_interfacesToTrace_X2,
      &hf_x2ap_interfacesToTrace_Uu,
      &hf_x2ap_interfacesToTrace_Reserved,
      NULL
    };
    proto_tree *subtree = proto_item_add_subtree(actx->created_item, ett_x2ap_InterfacesToTrace);
    proto_tree_add_bitmask_list(subtree, parameter_tvb, 0, 1, fields, ENC_BIG_ENDIAN);
  }



  return offset;
}


static const value_string x2ap_InvokeIndication_vals[] = {
  {   0, "abs-information" },
  {   1, "naics-information-start" },
  {   2, "naics-information-stop" },
  { 0, NULL }
};


static int
dissect_x2ap_InvokeIndication(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     1, NULL, TRUE, 2, NULL);

  return offset;
}



static int
dissect_x2ap_Time_UE_StayedInCell(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 4095U, NULL, FALSE);

  return offset;
}


static const per_sequence_t LastVisitedEUTRANCellInformation_sequence[] = {
  { &hf_x2ap_global_Cell_ID , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_x2ap_ECGI },
  { &hf_x2ap_cellType       , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_x2ap_CellType },
  { &hf_x2ap_time_UE_StayedInCell, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_x2ap_Time_UE_StayedInCell },
  { &hf_x2ap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_x2ap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_x2ap_LastVisitedEUTRANCellInformation(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_x2ap_LastVisitedEUTRANCellInformation, LastVisitedEUTRANCellInformation_sequence);

  return offset;
}



static int
dissect_x2ap_LastVisitedUTRANCellInformation(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_octet_string(tvb, offset, actx, tree, hf_index,
                                       NO_BOUND, NO_BOUND, FALSE, NULL);

  return offset;
}


static const value_string x2ap_LastVisitedGERANCellInformation_vals[] = {
  {   0, "undefined" },
  { 0, NULL }
};

static const per_choice_t LastVisitedGERANCellInformation_choice[] = {
  {   0, &hf_x2ap_undefined      , ASN1_EXTENSION_ROOT    , dissect_x2ap_NULL },
  { 0, NULL, 0, NULL }
};

static int
dissect_x2ap_LastVisitedGERANCellInformation(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_x2ap_LastVisitedGERANCellInformation, LastVisitedGERANCellInformation_choice,
                                 NULL);

  return offset;
}


static const value_string x2ap_LastVisitedCell_Item_vals[] = {
  {   0, "e-UTRAN-Cell" },
  {   1, "uTRAN-Cell" },
  {   2, "gERAN-Cell" },
  { 0, NULL }
};

static const per_choice_t LastVisitedCell_Item_choice[] = {
  {   0, &hf_x2ap_e_UTRAN_Cell   , ASN1_EXTENSION_ROOT    , dissect_x2ap_LastVisitedEUTRANCellInformation },
  {   1, &hf_x2ap_uTRAN_Cell     , ASN1_EXTENSION_ROOT    , dissect_x2ap_LastVisitedUTRANCellInformation },
  {   2, &hf_x2ap_gERAN_Cell     , ASN1_EXTENSION_ROOT    , dissect_x2ap_LastVisitedGERANCellInformation },
  { 0, NULL, 0, NULL }
};

static int
dissect_x2ap_LastVisitedCell_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_x2ap_LastVisitedCell_Item, LastVisitedCell_Item_choice,
                                 NULL);

  return offset;
}



static int
dissect_x2ap_LHN_ID(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 449 "./asn1/x2ap/x2ap.cnf"
  tvbuff_t *parameter_tvb = NULL;
  offset = dissect_per_octet_string(tvb, offset, actx, tree, -1,
                                       32, 256, FALSE, &parameter_tvb);

  actx->created_item = proto_tree_add_item(tree, hf_index, parameter_tvb, 0, -1, ENC_UTF_8|ENC_NA);



  return offset;
}


static const value_string x2ap_Links_to_log_vals[] = {
  {   0, "uplink" },
  {   1, "downlink" },
  {   2, "both-uplink-and-downlink" },
  { 0, NULL }
};


static int
dissect_x2ap_Links_to_log(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     3, NULL, TRUE, 0, NULL);

  return offset;
}


static const value_string x2ap_ReportArea_vals[] = {
  {   0, "ecgi" },
  { 0, NULL }
};


static int
dissect_x2ap_ReportArea(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     1, NULL, TRUE, 0, NULL);

  return offset;
}


static const per_sequence_t LocationReportingInformation_sequence[] = {
  { &hf_x2ap_eventType      , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_x2ap_EventType },
  { &hf_x2ap_reportArea     , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_x2ap_ReportArea },
  { &hf_x2ap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_x2ap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_x2ap_LocationReportingInformation(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_x2ap_LocationReportingInformation, LocationReportingInformation_sequence);

  return offset;
}


static const value_string x2ap_ReportIntervalMDT_vals[] = {
  {   0, "ms120" },
  {   1, "ms240" },
  {   2, "ms480" },
  {   3, "ms640" },
  {   4, "ms1024" },
  {   5, "ms2048" },
  {   6, "ms5120" },
  {   7, "ms10240" },
  {   8, "min1" },
  {   9, "min6" },
  {  10, "min12" },
  {  11, "min30" },
  {  12, "min60" },
  { 0, NULL }
};


static int
dissect_x2ap_ReportIntervalMDT(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     13, NULL, FALSE, 0, NULL);

  return offset;
}


static const value_string x2ap_ReportAmountMDT_vals[] = {
  {   0, "r1" },
  {   1, "r2" },
  {   2, "r4" },
  {   3, "r8" },
  {   4, "r16" },
  {   5, "r32" },
  {   6, "r64" },
  {   7, "rinfinity" },
  { 0, NULL }
};


static int
dissect_x2ap_ReportAmountMDT(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     8, NULL, FALSE, 0, NULL);

  return offset;
}


static const per_sequence_t M1PeriodicReporting_sequence[] = {
  { &hf_x2ap_reportInterval , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_x2ap_ReportIntervalMDT },
  { &hf_x2ap_reportAmount   , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_x2ap_ReportAmountMDT },
  { &hf_x2ap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_x2ap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_x2ap_M1PeriodicReporting(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_x2ap_M1PeriodicReporting, M1PeriodicReporting_sequence);

  return offset;
}


static const value_string x2ap_M1ReportingTrigger_vals[] = {
  {   0, "periodic" },
  {   1, "a2eventtriggered" },
  {   2, "a2eventtriggered-periodic" },
  { 0, NULL }
};


static int
dissect_x2ap_M1ReportingTrigger(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     2, NULL, TRUE, 1, NULL);

  return offset;
}



static int
dissect_x2ap_Threshold_RSRP(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 97U, NULL, FALSE);

  return offset;
}



static int
dissect_x2ap_Threshold_RSRQ(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 34U, NULL, FALSE);

  return offset;
}


static const value_string x2ap_MeasurementThresholdA2_vals[] = {
  {   0, "threshold-RSRP" },
  {   1, "threshold-RSRQ" },
  { 0, NULL }
};

static const per_choice_t MeasurementThresholdA2_choice[] = {
  {   0, &hf_x2ap_threshold_RSRP , ASN1_EXTENSION_ROOT    , dissect_x2ap_Threshold_RSRP },
  {   1, &hf_x2ap_threshold_RSRQ , ASN1_EXTENSION_ROOT    , dissect_x2ap_Threshold_RSRQ },
  { 0, NULL, 0, NULL }
};

static int
dissect_x2ap_MeasurementThresholdA2(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_x2ap_MeasurementThresholdA2, MeasurementThresholdA2_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t M1ThresholdEventA2_sequence[] = {
  { &hf_x2ap_measurementThreshold, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_x2ap_MeasurementThresholdA2 },
  { &hf_x2ap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_x2ap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_x2ap_M1ThresholdEventA2(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_x2ap_M1ThresholdEventA2, M1ThresholdEventA2_sequence);

  return offset;
}


static const value_string x2ap_M3period_vals[] = {
  {   0, "ms100" },
  {   1, "ms1000" },
  {   2, "ms10000" },
  { 0, NULL }
};


static int
dissect_x2ap_M3period(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     3, NULL, TRUE, 0, NULL);

  return offset;
}


static const per_sequence_t M3Configuration_sequence[] = {
  { &hf_x2ap_m3period       , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_x2ap_M3period },
  { &hf_x2ap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_x2ap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_x2ap_M3Configuration(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_x2ap_M3Configuration, M3Configuration_sequence);

  return offset;
}


static const value_string x2ap_M4period_vals[] = {
  {   0, "ms1024" },
  {   1, "ms2048" },
  {   2, "ms5120" },
  {   3, "ms10240" },
  {   4, "min1" },
  { 0, NULL }
};


static int
dissect_x2ap_M4period(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     5, NULL, TRUE, 0, NULL);

  return offset;
}


static const per_sequence_t M4Configuration_sequence[] = {
  { &hf_x2ap_m4period       , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_x2ap_M4period },
  { &hf_x2ap_m4_links_to_log, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_x2ap_Links_to_log },
  { &hf_x2ap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_x2ap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_x2ap_M4Configuration(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_x2ap_M4Configuration, M4Configuration_sequence);

  return offset;
}


static const value_string x2ap_M5period_vals[] = {
  {   0, "ms1024" },
  {   1, "ms2048" },
  {   2, "ms5120" },
  {   3, "ms10240" },
  {   4, "min1" },
  { 0, NULL }
};


static int
dissect_x2ap_M5period(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     5, NULL, TRUE, 0, NULL);

  return offset;
}


static const per_sequence_t M5Configuration_sequence[] = {
  { &hf_x2ap_m5period       , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_x2ap_M5period },
  { &hf_x2ap_m5_links_to_log, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_x2ap_Links_to_log },
  { &hf_x2ap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_x2ap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_x2ap_M5Configuration(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_x2ap_M5Configuration, M5Configuration_sequence);

  return offset;
}


static const value_string x2ap_M6report_interval_vals[] = {
  {   0, "ms1024" },
  {   1, "ms2048" },
  {   2, "ms5120" },
  {   3, "ms10240" },
  { 0, NULL }
};


static int
dissect_x2ap_M6report_interval(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     4, NULL, TRUE, 0, NULL);

  return offset;
}


static const value_string x2ap_M6delay_threshold_vals[] = {
  {   0, "ms30" },
  {   1, "ms40" },
  {   2, "ms50" },
  {   3, "ms60" },
  {   4, "ms70" },
  {   5, "ms80" },
  {   6, "ms90" },
  {   7, "ms100" },
  {   8, "ms150" },
  {   9, "ms300" },
  {  10, "ms500" },
  {  11, "ms750" },
  { 0, NULL }
};


static int
dissect_x2ap_M6delay_threshold(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     12, NULL, TRUE, 0, NULL);

  return offset;
}


static const per_sequence_t M6Configuration_sequence[] = {
  { &hf_x2ap_m6report_interval, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_x2ap_M6report_interval },
  { &hf_x2ap_m6delay_threshold, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_x2ap_M6delay_threshold },
  { &hf_x2ap_m6_links_to_log, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_x2ap_Links_to_log },
  { &hf_x2ap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_x2ap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_x2ap_M6Configuration(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_x2ap_M6Configuration, M6Configuration_sequence);

  return offset;
}



static int
dissect_x2ap_M7period(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            1U, 60U, NULL, TRUE);

  return offset;
}


static const per_sequence_t M7Configuration_sequence[] = {
  { &hf_x2ap_m7period       , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_x2ap_M7period },
  { &hf_x2ap_m7_links_to_log, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_x2ap_Links_to_log },
  { &hf_x2ap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_x2ap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_x2ap_M7Configuration(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_x2ap_M7Configuration, M7Configuration_sequence);

  return offset;
}


static const value_string x2ap_ManagementBasedMDTallowed_vals[] = {
  {   0, "allowed" },
  { 0, NULL }
};


static int
dissect_x2ap_ManagementBasedMDTallowed(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     1, NULL, TRUE, 0, NULL);

  return offset;
}



static int
dissect_x2ap_Masked_IMEISV(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_bit_string(tvb, offset, actx, tree, hf_index,
                                     64, 64, FALSE, NULL, NULL);

  return offset;
}


static const value_string x2ap_MDT_Activation_vals[] = {
  {   0, "immediate-MDT-only" },
  {   1, "immediate-MDT-and-Trace" },
  { 0, NULL }
};


static int
dissect_x2ap_MDT_Activation(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     2, NULL, TRUE, 0, NULL);

  return offset;
}



static int
dissect_x2ap_MeasurementsToActivate(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 380 "./asn1/x2ap/x2ap.cnf"
  tvbuff_t *parameter_tvb = NULL;
  offset = dissect_per_bit_string(tvb, offset, actx, tree, hf_index,
                                     8, 8, FALSE, &parameter_tvb, NULL);

  if(parameter_tvb){
    const gint *fields[] = {
      &hf_x2ap_measurementsToActivate_M1,
      &hf_x2ap_measurementsToActivate_M2,
      &hf_x2ap_measurementsToActivate_M3,
      &hf_x2ap_measurementsToActivate_M4,
      &hf_x2ap_measurementsToActivate_M5,
      &hf_x2ap_measurementsToActivate_LoggingM1FromEventTriggered,
      &hf_x2ap_measurementsToActivate_M6,
      &hf_x2ap_measurementsToActivate_M7,
      NULL
    };
    proto_tree *subtree = proto_item_add_subtree(actx->created_item, ett_x2ap_MeasurementsToActivate);
    proto_tree_add_bitmask_list(subtree, parameter_tvb, 0, 1, fields, ENC_BIG_ENDIAN);
  }



  return offset;
}


static const per_sequence_t MDT_Configuration_sequence[] = {
  { &hf_x2ap_mdt_Activation , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_x2ap_MDT_Activation },
  { &hf_x2ap_areaScopeOfMDT , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_x2ap_AreaScopeOfMDT },
  { &hf_x2ap_measurementsToActivate, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_x2ap_MeasurementsToActivate },
  { &hf_x2ap_m1reportingTrigger, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_x2ap_M1ReportingTrigger },
  { &hf_x2ap_m1thresholdeventA2, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_x2ap_M1ThresholdEventA2 },
  { &hf_x2ap_m1periodicReporting, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_x2ap_M1PeriodicReporting },
  { &hf_x2ap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_x2ap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_x2ap_MDT_Configuration(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_x2ap_MDT_Configuration, MDT_Configuration_sequence);

  return offset;
}


static const per_sequence_t MDTPLMNList_sequence_of[1] = {
  { &hf_x2ap_MDTPLMNList_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_x2ap_PLMN_Identity },
};

static int
dissect_x2ap_MDTPLMNList(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_x2ap_MDTPLMNList, MDTPLMNList_sequence_of,
                                                  1, maxnoofMDTPLMNs, FALSE);

  return offset;
}



static int
dissect_x2ap_MDT_Location_Info(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 405 "./asn1/x2ap/x2ap.cnf"
  tvbuff_t *parameter_tvb = NULL;
  offset = dissect_per_bit_string(tvb, offset, actx, tree, hf_index,
                                     8, 8, FALSE, &parameter_tvb, NULL);

  if(parameter_tvb){
    const gint *fields[] = {
      &hf_x2ap_MDT_Location_Info_GNSS,
      &hf_x2ap_MDT_Location_Info_E_CID,
      &hf_x2ap_MDT_Location_Info_Reserved,
      NULL
    };
    proto_tree *subtree = proto_item_add_subtree(actx->created_item, ett_x2ap_MDT_Location_Info);
    proto_tree_add_bitmask_list(subtree, parameter_tvb, 0, 1, fields, ENC_BIG_ENDIAN);
  }



  return offset;
}



static int
dissect_x2ap_Measurement_ID(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            1U, 4095U, NULL, TRUE);

  return offset;
}



static int
dissect_x2ap_MeNBtoSeNBContainer(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 214 "./asn1/x2ap/x2ap.cnf"
 tvbuff_t *parameter_tvb;
 proto_tree *subtree = NULL;
  offset = dissect_per_octet_string(tvb, offset, actx, tree, hf_index,
                                       NO_BOUND, NO_BOUND, FALSE, &parameter_tvb);

  if (!parameter_tvb)
    return offset;
  subtree = proto_item_add_subtree(actx->created_item, ett_x2ap_MeNBtoSeNBContainer);
  dissect_lte_rrc_SCG_ConfigInfo_r12_PDU(parameter_tvb, actx->pinfo, subtree, NULL);



  return offset;
}



static int
dissect_x2ap_MBMS_Service_Area_Identity(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_octet_string(tvb, offset, actx, tree, hf_index,
                                       2, 2, FALSE, NULL);

  return offset;
}


static const per_sequence_t MBMS_Service_Area_Identity_List_sequence_of[1] = {
  { &hf_x2ap_MBMS_Service_Area_Identity_List_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_x2ap_MBMS_Service_Area_Identity },
};

static int
dissect_x2ap_MBMS_Service_Area_Identity_List(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_x2ap_MBMS_Service_Area_Identity_List, MBMS_Service_Area_Identity_List_sequence_of,
                                                  1, maxnoofMBMSServiceAreaIdentities, FALSE);

  return offset;
}


static const value_string x2ap_RadioframeAllocationPeriod_vals[] = {
  {   0, "n1" },
  {   1, "n2" },
  {   2, "n4" },
  {   3, "n8" },
  {   4, "n16" },
  {   5, "n32" },
  { 0, NULL }
};


static int
dissect_x2ap_RadioframeAllocationPeriod(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     6, NULL, TRUE, 0, NULL);

  return offset;
}



static int
dissect_x2ap_RadioframeAllocationOffset(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 7U, NULL, TRUE);

  return offset;
}



static int
dissect_x2ap_Oneframe(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_bit_string(tvb, offset, actx, tree, hf_index,
                                     6, 6, FALSE, NULL, NULL);

  return offset;
}


static const value_string x2ap_SubframeAllocation_vals[] = {
  {   0, "oneframe" },
  {   1, "fourframes" },
  { 0, NULL }
};

static const per_choice_t SubframeAllocation_choice[] = {
  {   0, &hf_x2ap_oneframe       , ASN1_EXTENSION_ROOT    , dissect_x2ap_Oneframe },
  {   1, &hf_x2ap_fourframes     , ASN1_EXTENSION_ROOT    , dissect_x2ap_Fourframes },
  { 0, NULL, 0, NULL }
};

static int
dissect_x2ap_SubframeAllocation(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_x2ap_SubframeAllocation, SubframeAllocation_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t MBSFN_Subframe_Info_sequence[] = {
  { &hf_x2ap_radioframeAllocationPeriod, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_x2ap_RadioframeAllocationPeriod },
  { &hf_x2ap_radioframeAllocationOffset, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_x2ap_RadioframeAllocationOffset },
  { &hf_x2ap_subframeAllocation, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_x2ap_SubframeAllocation },
  { &hf_x2ap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_x2ap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_x2ap_MBSFN_Subframe_Info(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_x2ap_MBSFN_Subframe_Info, MBSFN_Subframe_Info_sequence);

  return offset;
}


static const per_sequence_t MBSFN_Subframe_Infolist_sequence_of[1] = {
  { &hf_x2ap_MBSFN_Subframe_Infolist_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_x2ap_MBSFN_Subframe_Info },
};

static int
dissect_x2ap_MBSFN_Subframe_Infolist(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_x2ap_MBSFN_Subframe_Infolist, MBSFN_Subframe_Infolist_sequence_of,
                                                  1, maxnoofMBSFN, FALSE);

  return offset;
}



static int
dissect_x2ap_INTEGER_M20_20(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            -20, 20U, NULL, FALSE);

  return offset;
}


static const per_sequence_t MobilityParametersModificationRange_sequence[] = {
  { &hf_x2ap_handoverTriggerChangeLowerLimit, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_x2ap_INTEGER_M20_20 },
  { &hf_x2ap_handoverTriggerChangeUpperLimit, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_x2ap_INTEGER_M20_20 },
  { NULL, 0, 0, NULL }
};

static int
dissect_x2ap_MobilityParametersModificationRange(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_x2ap_MobilityParametersModificationRange, MobilityParametersModificationRange_sequence);

  return offset;
}


static const per_sequence_t MobilityParametersInformation_sequence[] = {
  { &hf_x2ap_handoverTriggerChange, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_x2ap_INTEGER_M20_20 },
  { NULL, 0, 0, NULL }
};

static int
dissect_x2ap_MobilityParametersInformation(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_x2ap_MobilityParametersInformation, MobilityParametersInformation_sequence);

  return offset;
}


static const per_sequence_t BandInfo_sequence[] = {
  { &hf_x2ap_freqBandIndicator, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_x2ap_FreqBandIndicator },
  { &hf_x2ap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_x2ap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_x2ap_BandInfo(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_x2ap_BandInfo, BandInfo_sequence);

  return offset;
}


static const per_sequence_t MultibandInfoList_sequence_of[1] = {
  { &hf_x2ap_MultibandInfoList_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_x2ap_BandInfo },
};

static int
dissect_x2ap_MultibandInfoList(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_x2ap_MultibandInfoList, MultibandInfoList_sequence_of,
                                                  1, maxnoofBands, FALSE);

  return offset;
}



static int
dissect_x2ap_PCI(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 503U, NULL, TRUE);

  return offset;
}


static const per_sequence_t Neighbour_Information_item_sequence[] = {
  { &hf_x2ap_eCGI           , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_x2ap_ECGI },
  { &hf_x2ap_pCI            , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_x2ap_PCI },
  { &hf_x2ap_eARFCN         , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_x2ap_EARFCN },
  { &hf_x2ap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_x2ap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_x2ap_Neighbour_Information_item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_x2ap_Neighbour_Information_item, Neighbour_Information_item_sequence);

  return offset;
}


static const per_sequence_t Neighbour_Information_sequence_of[1] = {
  { &hf_x2ap_Neighbour_Information_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_x2ap_Neighbour_Information_item },
};

static int
dissect_x2ap_Neighbour_Information(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_x2ap_Neighbour_Information, Neighbour_Information_sequence_of,
                                                  0, maxnoofNeighbours, FALSE);

  return offset;
}


static const value_string x2ap_Number_of_Antennaports_vals[] = {
  {   0, "an1" },
  {   1, "an2" },
  {   2, "an4" },
  { 0, NULL }
};


static int
dissect_x2ap_Number_of_Antennaports(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     3, NULL, TRUE, 0, NULL);

  return offset;
}


static const value_string x2ap_OffsetOfNbiotChannelNumberToEARFCN_vals[] = {
  {   0, "minusTen" },
  {   1, "minusNine" },
  {   2, "minusEight" },
  {   3, "minusSeven" },
  {   4, "minusSix" },
  {   5, "minusFive" },
  {   6, "minusFour" },
  {   7, "minusThree" },
  {   8, "minusTwo" },
  {   9, "minusOne" },
  {  10, "minusZeroDotFive" },
  {  11, "zero" },
  {  12, "one" },
  {  13, "two" },
  {  14, "three" },
  {  15, "four" },
  {  16, "five" },
  {  17, "six" },
  {  18, "seven" },
  {  19, "eight" },
  {  20, "nine" },
  { 0, NULL }
};

static value_string_ext x2ap_OffsetOfNbiotChannelNumberToEARFCN_vals_ext = VALUE_STRING_EXT_INIT(x2ap_OffsetOfNbiotChannelNumberToEARFCN_vals);


static int
dissect_x2ap_OffsetOfNbiotChannelNumberToEARFCN(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     21, NULL, TRUE, 0, NULL);

  return offset;
}



static int
dissect_x2ap_Port_Number(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 120 "./asn1/x2ap/x2ap.cnf"
  tvbuff_t *parameter_tvb = NULL;
  offset = dissect_per_octet_string(tvb, offset, actx, tree, -1,
                                       2, 2, FALSE, &parameter_tvb);

  if (parameter_tvb) {
    actx->created_item = proto_tree_add_item(tree, hf_index, parameter_tvb, 0, 2, ENC_BIG_ENDIAN);
  }



  return offset;
}



static int
dissect_x2ap_INTEGER_0_837(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 837U, NULL, FALSE);

  return offset;
}



static int
dissect_x2ap_INTEGER_0_15(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 15U, NULL, FALSE);

  return offset;
}



static int
dissect_x2ap_BOOLEAN(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_boolean(tvb, offset, actx, tree, hf_index, NULL);

  return offset;
}



static int
dissect_x2ap_INTEGER_0_94(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 94U, NULL, FALSE);

  return offset;
}



static int
dissect_x2ap_INTEGER_0_63(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 63U, NULL, FALSE);

  return offset;
}


static const per_sequence_t PRACH_Configuration_sequence[] = {
  { &hf_x2ap_rootSequenceIndex, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_x2ap_INTEGER_0_837 },
  { &hf_x2ap_zeroCorrelationIndex, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_x2ap_INTEGER_0_15 },
  { &hf_x2ap_highSpeedFlag  , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_x2ap_BOOLEAN },
  { &hf_x2ap_prach_FreqOffset, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_x2ap_INTEGER_0_94 },
  { &hf_x2ap_prach_ConfigIndex, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_x2ap_INTEGER_0_63 },
  { &hf_x2ap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_x2ap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_x2ap_PRACH_Configuration(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_x2ap_PRACH_Configuration, PRACH_Configuration_sequence);

  return offset;
}


static const value_string x2ap_ProSeDirectDiscovery_vals[] = {
  {   0, "authorized" },
  {   1, "not-authorized" },
  { 0, NULL }
};


static int
dissect_x2ap_ProSeDirectDiscovery(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     2, NULL, TRUE, 0, NULL);

  return offset;
}


static const value_string x2ap_ProSeDirectCommunication_vals[] = {
  {   0, "authorized" },
  {   1, "not-authorized" },
  { 0, NULL }
};


static int
dissect_x2ap_ProSeDirectCommunication(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     2, NULL, TRUE, 0, NULL);

  return offset;
}


static const per_sequence_t ProSeAuthorized_sequence[] = {
  { &hf_x2ap_proSeDirectDiscovery, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_x2ap_ProSeDirectDiscovery },
  { &hf_x2ap_proSeDirectCommunication, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_x2ap_ProSeDirectCommunication },
  { &hf_x2ap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_x2ap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_x2ap_ProSeAuthorized(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_x2ap_ProSeAuthorized, ProSeAuthorized_sequence);

  return offset;
}


static const value_string x2ap_ProSeUEtoNetworkRelaying_vals[] = {
  {   0, "authorized" },
  {   1, "not-authorized" },
  { 0, NULL }
};


static int
dissect_x2ap_ProSeUEtoNetworkRelaying(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     2, NULL, TRUE, 0, NULL);

  return offset;
}



static int
dissect_x2ap_UL_GBR_PRB_usage(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 100U, NULL, FALSE);

  return offset;
}



static int
dissect_x2ap_UL_non_GBR_PRB_usage(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 100U, NULL, FALSE);

  return offset;
}



static int
dissect_x2ap_UL_Total_PRB_usage(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 100U, NULL, FALSE);

  return offset;
}


static const per_sequence_t RadioResourceStatus_sequence[] = {
  { &hf_x2ap_dL_GBR_PRB_usage, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_x2ap_DL_GBR_PRB_usage },
  { &hf_x2ap_uL_GBR_PRB_usage, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_x2ap_UL_GBR_PRB_usage },
  { &hf_x2ap_dL_non_GBR_PRB_usage, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_x2ap_DL_non_GBR_PRB_usage },
  { &hf_x2ap_uL_non_GBR_PRB_usage, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_x2ap_UL_non_GBR_PRB_usage },
  { &hf_x2ap_dL_Total_PRB_usage, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_x2ap_DL_Total_PRB_usage },
  { &hf_x2ap_uL_Total_PRB_usage, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_x2ap_UL_Total_PRB_usage },
  { &hf_x2ap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_x2ap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_x2ap_RadioResourceStatus(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_x2ap_RadioResourceStatus, RadioResourceStatus_sequence);

  return offset;
}



static int
dissect_x2ap_ReceiveStatusofULPDCPSDUs(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_bit_string(tvb, offset, actx, tree, hf_index,
                                     4096, 4096, FALSE, NULL, NULL);

  return offset;
}



static int
dissect_x2ap_ReceiveStatusOfULPDCPSDUsExtended(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_bit_string(tvb, offset, actx, tree, hf_index,
                                     1, 16384, FALSE, NULL, NULL);

  return offset;
}



static int
dissect_x2ap_ReceiveStatusOfULPDCPSDUsPDCP_SNlength18(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_bit_string(tvb, offset, actx, tree, hf_index,
                                     1, 131072, FALSE, NULL, NULL);

  return offset;
}


static const value_string x2ap_Registration_Request_vals[] = {
  {   0, "start" },
  {   1, "stop" },
  {   2, "partial-stop" },
  {   3, "add" },
  { 0, NULL }
};


static int
dissect_x2ap_Registration_Request(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     2, NULL, TRUE, 2, NULL);

  return offset;
}



static int
dissect_x2ap_BIT_STRING_SIZE_6_110_(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_bit_string(tvb, offset, actx, tree, hf_index,
                                     6, 110, TRUE, NULL, NULL);

  return offset;
}


static const value_string x2ap_T_numberOfCellSpecificAntennaPorts_02_vals[] = {
  {   0, "one" },
  {   1, "two" },
  {   2, "four" },
  { 0, NULL }
};


static int
dissect_x2ap_T_numberOfCellSpecificAntennaPorts_02(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     3, NULL, TRUE, 0, NULL);

  return offset;
}



static int
dissect_x2ap_INTEGER_0_4_(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 4U, NULL, TRUE);

  return offset;
}


static const per_sequence_t RelativeNarrowbandTxPower_sequence[] = {
  { &hf_x2ap_rNTP_PerPRB    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_x2ap_BIT_STRING_SIZE_6_110_ },
  { &hf_x2ap_rNTP_Threshold , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_x2ap_RNTP_Threshold },
  { &hf_x2ap_numberOfCellSpecificAntennaPorts_02, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_x2ap_T_numberOfCellSpecificAntennaPorts_02 },
  { &hf_x2ap_p_B            , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_x2ap_INTEGER_0_3_ },
  { &hf_x2ap_pDCCH_InterferenceImpact, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_x2ap_INTEGER_0_4_ },
  { &hf_x2ap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_x2ap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_x2ap_RelativeNarrowbandTxPower(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_x2ap_RelativeNarrowbandTxPower, RelativeNarrowbandTxPower_sequence);

  return offset;
}



static int
dissect_x2ap_ReportCharacteristics(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 155 "./asn1/x2ap/x2ap.cnf"
  tvbuff_t *parameter_tvb = NULL;
  offset = dissect_per_bit_string(tvb, offset, actx, tree, hf_index,
                                     32, 32, FALSE, &parameter_tvb, NULL);

  if(parameter_tvb){
    const gint *fields[] = {
      &hf_x2ap_ReportCharacteristics_PRBPeriodic,
      &hf_x2ap_ReportCharacteristics_TNLLoadIndPeriodic,
      &hf_x2ap_ReportCharacteristics_HWLoadIndPeriodic,
      &hf_x2ap_ReportCharacteristics_CompositeAvailableCapacityPeriodic,
      &hf_x2ap_ReportCharacteristics_ABSStatusPeriodic,
      &hf_x2ap_ReportCharacteristics_RSRPMeasurementReportPeriodic,
      &hf_x2ap_ReportCharacteristics_CSIReportPeriodic,
      &hf_x2ap_ReportCharacteristics_Reserved,
      NULL
    };
    proto_tree *subtree = proto_item_add_subtree(actx->created_item, ett_x2ap_ReportCharacteristics);
    proto_tree_add_bitmask_list(subtree, parameter_tvb, 0, 4, fields, ENC_BIG_ENDIAN);
  }



  return offset;
}


static const value_string x2ap_ReportingPeriodicityCSIR_vals[] = {
  {   0, "ms5" },
  {   1, "ms10" },
  {   2, "ms20" },
  {   3, "ms40" },
  {   4, "ms80" },
  { 0, NULL }
};


static int
dissect_x2ap_ReportingPeriodicityCSIR(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     5, NULL, TRUE, 0, NULL);

  return offset;
}


static const value_string x2ap_ReportingPeriodicityRSRPMR_vals[] = {
  {   0, "one-hundred-20-ms" },
  {   1, "two-hundred-40-ms" },
  {   2, "four-hundred-80-ms" },
  {   3, "six-hundred-40-ms" },
  { 0, NULL }
};


static int
dissect_x2ap_ReportingPeriodicityRSRPMR(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     4, NULL, TRUE, 0, NULL);

  return offset;
}



static int
dissect_x2ap_BIT_STRING_SIZE_24(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_bit_string(tvb, offset, actx, tree, hf_index,
                                     24, 24, FALSE, NULL, NULL);

  return offset;
}


static const value_string x2ap_ResumeID_vals[] = {
  {   0, "non-truncated" },
  {   1, "truncated" },
  { 0, NULL }
};

static const per_choice_t ResumeID_choice[] = {
  {   0, &hf_x2ap_non_truncated  , ASN1_EXTENSION_ROOT    , dissect_x2ap_BIT_STRING_SIZE_40 },
  {   1, &hf_x2ap_truncated      , ASN1_EXTENSION_ROOT    , dissect_x2ap_BIT_STRING_SIZE_24 },
  { 0, NULL, 0, NULL }
};

static int
dissect_x2ap_ResumeID(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_x2ap_ResumeID, ResumeID_choice,
                                 NULL);

  return offset;
}



static int
dissect_x2ap_RRC_Context(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 131 "./asn1/x2ap/x2ap.cnf"
  tvbuff_t *parameter_tvb = NULL;
  proto_tree *subtree;

  offset = dissect_per_octet_string(tvb, offset, actx, tree, hf_index,
                                       NO_BOUND, NO_BOUND, FALSE, &parameter_tvb);

  if (!parameter_tvb)
    return offset;

  subtree = proto_item_add_subtree(actx->created_item, ett_x2ap_RRC_Context);
  if (g_x2ap_dissect_rrc_context_as == X2AP_RRC_CONTEXT_NBIOT) {
    dissect_lte_rrc_HandoverPreparationInformation_NB_PDU(parameter_tvb, actx->pinfo, subtree, NULL);
  } else {
    dissect_lte_rrc_HandoverPreparationInformation_PDU(parameter_tvb, actx->pinfo, subtree, NULL);
  }



  return offset;
}


static const value_string x2ap_RRCConnReestabIndicator_vals[] = {
  {   0, "reconfigurationFailure" },
  {   1, "handoverFailure" },
  {   2, "otherFailure" },
  { 0, NULL }
};


static int
dissect_x2ap_RRCConnReestabIndicator(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     3, NULL, TRUE, 0, NULL);

  return offset;
}


static const value_string x2ap_RRCConnSetupIndicator_vals[] = {
  {   0, "rrcConnSetup" },
  { 0, NULL }
};


static int
dissect_x2ap_RRCConnSetupIndicator(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     1, NULL, TRUE, 0, NULL);

  return offset;
}



static int
dissect_x2ap_INTEGER_0_97_(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 97U, NULL, TRUE);

  return offset;
}


static const per_sequence_t RSRPMeasurementResult_item_sequence[] = {
  { &hf_x2ap_rSRPCellID     , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_x2ap_ECGI },
  { &hf_x2ap_rSRPMeasured   , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_x2ap_INTEGER_0_97_ },
  { &hf_x2ap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_x2ap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_x2ap_RSRPMeasurementResult_item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_x2ap_RSRPMeasurementResult_item, RSRPMeasurementResult_item_sequence);

  return offset;
}


static const per_sequence_t RSRPMeasurementResult_sequence_of[1] = {
  { &hf_x2ap_RSRPMeasurementResult_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_x2ap_RSRPMeasurementResult_item },
};

static int
dissect_x2ap_RSRPMeasurementResult(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_x2ap_RSRPMeasurementResult, RSRPMeasurementResult_sequence_of,
                                                  1, maxCellReport, FALSE);

  return offset;
}


static const per_sequence_t RSRPMRList_item_sequence[] = {
  { &hf_x2ap_rSRPMeasurementResult, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_x2ap_RSRPMeasurementResult },
  { &hf_x2ap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_x2ap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_x2ap_RSRPMRList_item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_x2ap_RSRPMRList_item, RSRPMRList_item_sequence);

  return offset;
}


static const per_sequence_t RSRPMRList_sequence_of[1] = {
  { &hf_x2ap_RSRPMRList_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_x2ap_RSRPMRList_item },
};

static int
dissect_x2ap_RSRPMRList(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_x2ap_RSRPMRList, RSRPMRList_sequence_of,
                                                  1, maxUEReport, FALSE);

  return offset;
}


static const per_sequence_t S1TNLLoadIndicator_sequence[] = {
  { &hf_x2ap_dLS1TNLLoadIndicator, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_x2ap_LoadIndicator },
  { &hf_x2ap_uLS1TNLLoadIndicator, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_x2ap_LoadIndicator },
  { &hf_x2ap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_x2ap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_x2ap_S1TNLLoadIndicator(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_x2ap_S1TNLLoadIndicator, S1TNLLoadIndicator_sequence);

  return offset;
}


static const value_string x2ap_SCGChangeIndication_vals[] = {
  {   0, "pDCPCountWrapAround" },
  {   1, "pSCellChange" },
  {   2, "other" },
  { 0, NULL }
};


static int
dissect_x2ap_SCGChangeIndication(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     3, NULL, TRUE, 0, NULL);

  return offset;
}



static int
dissect_x2ap_SeNBSecurityKey(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_bit_string(tvb, offset, actx, tree, hf_index,
                                     256, 256, FALSE, NULL, NULL);

  return offset;
}



static int
dissect_x2ap_SeNBtoMeNBContainer(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 223 "./asn1/x2ap/x2ap.cnf"
 tvbuff_t *parameter_tvb;
 proto_tree *subtree = NULL;
  offset = dissect_per_octet_string(tvb, offset, actx, tree, hf_index,
                                       NO_BOUND, NO_BOUND, FALSE, &parameter_tvb);

  if (!parameter_tvb)
    return offset;
  subtree = proto_item_add_subtree(actx->created_item, ett_x2ap_SeNBtoMeNBContainer);
  dissect_lte_rrc_SCG_ConfigInfo_r12_PDU(parameter_tvb, actx->pinfo, subtree, NULL);



  return offset;
}


static const per_sequence_t ServedCell_Information_sequence[] = {
  { &hf_x2ap_pCI            , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_x2ap_PCI },
  { &hf_x2ap_cellId         , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_x2ap_ECGI },
  { &hf_x2ap_tAC            , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_x2ap_TAC },
  { &hf_x2ap_broadcastPLMNs , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_x2ap_BroadcastPLMNs_Item },
  { &hf_x2ap_eUTRA_Mode_Info, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_x2ap_EUTRA_Mode_Info },
  { &hf_x2ap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_x2ap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_x2ap_ServedCell_Information(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_x2ap_ServedCell_Information, ServedCell_Information_sequence);

  return offset;
}


static const per_sequence_t ServedCells_item_sequence[] = {
  { &hf_x2ap_servedCellInfo , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_x2ap_ServedCell_Information },
  { &hf_x2ap_neighbour_Info , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_x2ap_Neighbour_Information },
  { &hf_x2ap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_x2ap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_x2ap_ServedCells_item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_x2ap_ServedCells_item, ServedCells_item_sequence);

  return offset;
}


static const per_sequence_t ServedCells_sequence_of[1] = {
  { &hf_x2ap_ServedCells_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_x2ap_ServedCells_item },
};

static int
dissect_x2ap_ServedCells(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_x2ap_ServedCells, ServedCells_sequence_of,
                                                  1, maxCellineNB, FALSE);

  return offset;
}


static const value_string x2ap_SIPTOBearerDeactivationIndication_vals[] = {
  {   0, "true" },
  { 0, NULL }
};


static int
dissect_x2ap_SIPTOBearerDeactivationIndication(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     1, NULL, TRUE, 0, NULL);

  return offset;
}



static int
dissect_x2ap_ShortMAC_I(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_bit_string(tvb, offset, actx, tree, hf_index,
                                     16, 16, FALSE, NULL, NULL);

  return offset;
}


static const value_string x2ap_SRVCCOperationPossible_vals[] = {
  {   0, "possible" },
  { 0, NULL }
};


static int
dissect_x2ap_SRVCCOperationPossible(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     1, NULL, TRUE, 0, NULL);

  return offset;
}



static int
dissect_x2ap_SubscriberProfileIDforRFP(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            1U, 256U, NULL, FALSE);

  return offset;
}



static int
dissect_x2ap_TargetCellInUTRAN(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_octet_string(tvb, offset, actx, tree, hf_index,
                                       NO_BOUND, NO_BOUND, FALSE, NULL);

  return offset;
}



static int
dissect_x2ap_TargeteNBtoSource_eNBTransparentContainer(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 76 "./asn1/x2ap/x2ap.cnf"
  tvbuff_t *parameter_tvb = NULL;
  proto_tree *subtree;

  offset = dissect_per_octet_string(tvb, offset, actx, tree, hf_index,
                                       NO_BOUND, NO_BOUND, FALSE, &parameter_tvb);

  if (!parameter_tvb)
    return offset;

  subtree = proto_item_add_subtree(actx->created_item, ett_x2ap_TargeteNBtoSource_eNBTransparentContainer);
  dissect_lte_rrc_HandoverCommand_PDU(parameter_tvb, actx->pinfo, subtree, NULL);



  return offset;
}


static const value_string x2ap_TimeToWait_vals[] = {
  {   0, "v1s" },
  {   1, "v2s" },
  {   2, "v5s" },
  {   3, "v10s" },
  {   4, "v20s" },
  {   5, "v60s" },
  { 0, NULL }
};


static int
dissect_x2ap_TimeToWait(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     6, NULL, TRUE, 0, NULL);

  return offset;
}



static int
dissect_x2ap_Time_UE_StayedInCell_EnhancedGranularity(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 40950U, NULL, FALSE);

  return offset;
}


static const value_string x2ap_TraceDepth_vals[] = {
  {   0, "minimum" },
  {   1, "medium" },
  {   2, "maximum" },
  {   3, "minimumWithoutVendorSpecificExtension" },
  {   4, "mediumWithoutVendorSpecificExtension" },
  {   5, "maximumWithoutVendorSpecificExtension" },
  { 0, NULL }
};


static int
dissect_x2ap_TraceDepth(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     6, NULL, TRUE, 0, NULL);

  return offset;
}



static int
dissect_x2ap_TraceCollectionEntityIPAddress(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 258 "./asn1/x2ap/x2ap.cnf"
  tvbuff_t *parameter_tvb = NULL;
  proto_tree *subtree;
  int len;

  offset = dissect_per_bit_string(tvb, offset, actx, tree, hf_index,
                                     1, 160, TRUE, &parameter_tvb, &len);

  if (!parameter_tvb)
    return offset;

  subtree = proto_item_add_subtree(actx->created_item, ett_x2ap_TraceCollectionEntityIPAddress);
  if (len == 32) {
    /* IPv4 */
     proto_tree_add_item(subtree, hf_x2ap_traceCollectionEntityIPAddress_IPv4, parameter_tvb, 0, 4, ENC_BIG_ENDIAN);
  } else if (len == 128) {
    /* IPv6 */
     proto_tree_add_item(subtree, hf_x2ap_traceCollectionEntityIPAddress_IPv6, parameter_tvb, 0, 16, ENC_NA);
  } else if (len == 160) {
    /* IPv4 */
     proto_tree_add_item(subtree, hf_x2ap_traceCollectionEntityIPAddress_IPv4, parameter_tvb, 0, 4, ENC_BIG_ENDIAN);
    /* IPv6 */
     proto_tree_add_item(subtree, hf_x2ap_traceCollectionEntityIPAddress_IPv6, parameter_tvb, 4, 16, ENC_NA);
  }



  return offset;
}


static const per_sequence_t TraceActivation_sequence[] = {
  { &hf_x2ap_eUTRANTraceID  , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_x2ap_EUTRANTraceID },
  { &hf_x2ap_interfacesToTrace, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_x2ap_InterfacesToTrace },
  { &hf_x2ap_traceDepth     , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_x2ap_TraceDepth },
  { &hf_x2ap_traceCollectionEntityIPAddress, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_x2ap_TraceCollectionEntityIPAddress },
  { &hf_x2ap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_x2ap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_x2ap_TraceActivation(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_x2ap_TraceActivation, TraceActivation_sequence);

  return offset;
}


static const per_sequence_t TunnelInformation_sequence[] = {
  { &hf_x2ap_transportLayerAddress, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_x2ap_TransportLayerAddress },
  { &hf_x2ap_uDP_Port_Number, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_x2ap_Port_Number },
  { &hf_x2ap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_x2ap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_x2ap_TunnelInformation(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_x2ap_TunnelInformation, TunnelInformation_sequence);

  return offset;
}


static const per_sequence_t UEAggregateMaximumBitRate_sequence[] = {
  { &hf_x2ap_uEaggregateMaximumBitRateDownlink, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_x2ap_BitRate },
  { &hf_x2ap_uEaggregateMaximumBitRateUplink, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_x2ap_BitRate },
  { &hf_x2ap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_x2ap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_x2ap_UEAggregateMaximumBitRate(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_x2ap_UEAggregateMaximumBitRate, UEAggregateMaximumBitRate_sequence);

  return offset;
}


static const value_string x2ap_UE_ContextKeptIndicator_vals[] = {
  {   0, "true" },
  { 0, NULL }
};


static int
dissect_x2ap_UE_ContextKeptIndicator(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     1, NULL, TRUE, 0, NULL);

  return offset;
}


static const per_sequence_t UE_HistoryInformation_sequence_of[1] = {
  { &hf_x2ap_UE_HistoryInformation_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_x2ap_LastVisitedCell_Item },
};

static int
dissect_x2ap_UE_HistoryInformation(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_x2ap_UE_HistoryInformation, UE_HistoryInformation_sequence_of,
                                                  1, maxnoofCells, FALSE);

  return offset;
}



static int
dissect_x2ap_UE_HistoryInformationFromTheUE(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 146 "./asn1/x2ap/x2ap.cnf"
  tvbuff_t *parameter_tvb = NULL;
  proto_tree *subtree;
  offset = dissect_per_octet_string(tvb, offset, actx, tree, hf_index,
                                       NO_BOUND, NO_BOUND, FALSE, &parameter_tvb);

  if (!parameter_tvb)
    return offset;
  subtree = proto_item_add_subtree(actx->created_item, ett_x2ap_UE_HistoryInformationFromTheUE);
  dissect_lte_rrc_VisitedCellInfoList_r12_PDU(parameter_tvb, actx->pinfo, subtree, NULL);



  return offset;
}



static int
dissect_x2ap_UE_S1AP_ID(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 4294967295U, NULL, FALSE);

  return offset;
}



static int
dissect_x2ap_UE_X2AP_ID(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 4095U, NULL, FALSE);

  return offset;
}



static int
dissect_x2ap_UE_X2AP_ID_Extension(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 4095U, NULL, TRUE);

  return offset;
}



static int
dissect_x2ap_UE_RLF_Report_Container(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 196 "./asn1/x2ap/x2ap.cnf"
 tvbuff_t *parameter_tvb;
 proto_tree *subtree = NULL;
  offset = dissect_per_octet_string(tvb, offset, actx, tree, hf_index,
                                       NO_BOUND, NO_BOUND, FALSE, &parameter_tvb);

  if (!parameter_tvb)
    return offset;
  subtree = proto_item_add_subtree(actx->created_item, ett_x2ap_UE_RLF_Report_Container);
  dissect_lte_rrc_RLF_Report_r9_PDU(parameter_tvb, actx->pinfo, subtree, NULL);



  return offset;
}



static int
dissect_x2ap_UE_RLF_Report_Container_for_extended_bands(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 205 "./asn1/x2ap/x2ap.cnf"
 tvbuff_t *parameter_tvb;
 proto_tree *subtree = NULL;
  offset = dissect_per_octet_string(tvb, offset, actx, tree, hf_index,
                                       NO_BOUND, NO_BOUND, FALSE, &parameter_tvb);

  if (!parameter_tvb)
    return offset;
  subtree = proto_item_add_subtree(actx->created_item, ett_x2ap_UE_RLF_Report_Container_for_extended_bands);
  dissect_lte_rrc_RLF_Report_v9e0_PDU(parameter_tvb, actx->pinfo, subtree, NULL);



  return offset;
}


static const per_sequence_t UESecurityCapabilities_sequence[] = {
  { &hf_x2ap_encryptionAlgorithms, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_x2ap_EncryptionAlgorithms },
  { &hf_x2ap_integrityProtectionAlgorithms, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_x2ap_IntegrityProtectionAlgorithms },
  { &hf_x2ap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_x2ap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_x2ap_UESecurityCapabilities(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_x2ap_UESecurityCapabilities, UESecurityCapabilities_sequence);

  return offset;
}



static int
dissect_x2ap_UL_HighInterferenceIndication(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_bit_string(tvb, offset, actx, tree, hf_index,
                                     1, 110, TRUE, NULL, NULL);

  return offset;
}


static const per_sequence_t UL_HighInterferenceIndicationInfo_Item_sequence[] = {
  { &hf_x2ap_target_Cell_ID , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_x2ap_ECGI },
  { &hf_x2ap_ul_interferenceindication, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_x2ap_UL_HighInterferenceIndication },
  { &hf_x2ap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_x2ap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_x2ap_UL_HighInterferenceIndicationInfo_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_x2ap_UL_HighInterferenceIndicationInfo_Item, UL_HighInterferenceIndicationInfo_Item_sequence);

  return offset;
}


static const per_sequence_t UL_HighInterferenceIndicationInfo_sequence_of[1] = {
  { &hf_x2ap_UL_HighInterferenceIndicationInfo_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_x2ap_UL_HighInterferenceIndicationInfo_Item },
};

static int
dissect_x2ap_UL_HighInterferenceIndicationInfo(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_x2ap_UL_HighInterferenceIndicationInfo, UL_HighInterferenceIndicationInfo_sequence_of,
                                                  1, maxCellineNB, FALSE);

  return offset;
}



static int
dissect_x2ap_X2BenefitValue(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            1U, 8U, NULL, TRUE);

  return offset;
}


static const per_sequence_t HandoverRequest_sequence[] = {
  { &hf_x2ap_protocolIEs    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_x2ap_ProtocolIE_Container },
  { NULL, 0, 0, NULL }
};

static int
dissect_x2ap_HandoverRequest(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 463 "./asn1/x2ap/x2ap.cnf"
  col_append_sep_str(actx->pinfo->cinfo, COL_INFO, NULL, "HandoverRequest");

  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_x2ap_HandoverRequest, HandoverRequest_sequence);

  return offset;
}


static const per_sequence_t E_RABs_ToBeSetup_List_sequence_of[1] = {
  { &hf_x2ap_E_RABs_ToBeSetup_List_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_x2ap_ProtocolIE_Single_Container },
};

static int
dissect_x2ap_E_RABs_ToBeSetup_List(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_x2ap_E_RABs_ToBeSetup_List, E_RABs_ToBeSetup_List_sequence_of,
                                                  1, maxnoofBearers, FALSE);

  return offset;
}


static const per_sequence_t UE_ContextInformation_sequence[] = {
  { &hf_x2ap_mME_UE_S1AP_ID , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_x2ap_UE_S1AP_ID },
  { &hf_x2ap_uESecurityCapabilities, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_x2ap_UESecurityCapabilities },
  { &hf_x2ap_aS_SecurityInformation, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_x2ap_AS_SecurityInformation },
  { &hf_x2ap_uEaggregateMaximumBitRate, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_x2ap_UEAggregateMaximumBitRate },
  { &hf_x2ap_subscriberProfileIDforRFP, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_x2ap_SubscriberProfileIDforRFP },
  { &hf_x2ap_e_RABs_ToBeSetup_List, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_x2ap_E_RABs_ToBeSetup_List },
  { &hf_x2ap_rRC_Context    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_x2ap_RRC_Context },
  { &hf_x2ap_handoverRestrictionList, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_x2ap_HandoverRestrictionList },
  { &hf_x2ap_locationReportingInformation, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_x2ap_LocationReportingInformation },
  { &hf_x2ap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_x2ap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_x2ap_UE_ContextInformation(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_x2ap_UE_ContextInformation, UE_ContextInformation_sequence);

  return offset;
}


static const per_sequence_t E_RABs_ToBeSetup_Item_sequence[] = {
  { &hf_x2ap_e_RAB_ID       , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_x2ap_E_RAB_ID },
  { &hf_x2ap_e_RAB_Level_QoS_Parameters, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_x2ap_E_RAB_Level_QoS_Parameters },
  { &hf_x2ap_dL_Forwarding  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_x2ap_DL_Forwarding },
  { &hf_x2ap_uL_GTPtunnelEndpoint, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_x2ap_GTPtunnelEndpoint },
  { &hf_x2ap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_x2ap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_x2ap_E_RABs_ToBeSetup_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_x2ap_E_RABs_ToBeSetup_Item, E_RABs_ToBeSetup_Item_sequence);

  return offset;
}



static int
dissect_x2ap_MobilityInformation(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_bit_string(tvb, offset, actx, tree, hf_index,
                                     32, 32, FALSE, NULL, NULL);

  return offset;
}


static const per_sequence_t UE_ContextReferenceAtSeNB_sequence[] = {
  { &hf_x2ap_source_GlobalSeNB_ID, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_x2ap_GlobalENB_ID },
  { &hf_x2ap_seNB_UE_X2AP_ID, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_x2ap_UE_X2AP_ID },
  { &hf_x2ap_seNB_UE_X2AP_ID_Extension, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_x2ap_UE_X2AP_ID_Extension },
  { &hf_x2ap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_x2ap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_x2ap_UE_ContextReferenceAtSeNB(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_x2ap_UE_ContextReferenceAtSeNB, UE_ContextReferenceAtSeNB_sequence);

  return offset;
}


static const per_sequence_t HandoverRequestAcknowledge_sequence[] = {
  { &hf_x2ap_protocolIEs    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_x2ap_ProtocolIE_Container },
  { NULL, 0, 0, NULL }
};

static int
dissect_x2ap_HandoverRequestAcknowledge(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 465 "./asn1/x2ap/x2ap.cnf"
  col_append_sep_str(actx->pinfo->cinfo, COL_INFO, NULL, "HandoverRequestAcknowledge");

  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_x2ap_HandoverRequestAcknowledge, HandoverRequestAcknowledge_sequence);

  return offset;
}


static const per_sequence_t E_RABs_Admitted_List_sequence_of[1] = {
  { &hf_x2ap_E_RABs_Admitted_List_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_x2ap_ProtocolIE_Single_Container },
};

static int
dissect_x2ap_E_RABs_Admitted_List(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_x2ap_E_RABs_Admitted_List, E_RABs_Admitted_List_sequence_of,
                                                  1, maxnoofBearers, FALSE);

  return offset;
}


static const per_sequence_t E_RABs_Admitted_Item_sequence[] = {
  { &hf_x2ap_e_RAB_ID       , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_x2ap_E_RAB_ID },
  { &hf_x2ap_uL_GTP_TunnelEndpoint, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_x2ap_GTPtunnelEndpoint },
  { &hf_x2ap_dL_GTP_TunnelEndpoint, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_x2ap_GTPtunnelEndpoint },
  { &hf_x2ap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_x2ap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_x2ap_E_RABs_Admitted_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_x2ap_E_RABs_Admitted_Item, E_RABs_Admitted_Item_sequence);

  return offset;
}


static const per_sequence_t HandoverPreparationFailure_sequence[] = {
  { &hf_x2ap_protocolIEs    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_x2ap_ProtocolIE_Container },
  { NULL, 0, 0, NULL }
};

static int
dissect_x2ap_HandoverPreparationFailure(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 467 "./asn1/x2ap/x2ap.cnf"
  col_append_sep_str(actx->pinfo->cinfo, COL_INFO, NULL, "HandoverPreparationFailure");

  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_x2ap_HandoverPreparationFailure, HandoverPreparationFailure_sequence);

  return offset;
}


static const per_sequence_t HandoverReport_sequence[] = {
  { &hf_x2ap_protocolIEs    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_x2ap_ProtocolIE_Container },
  { NULL, 0, 0, NULL }
};

static int
dissect_x2ap_HandoverReport(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 505 "./asn1/x2ap/x2ap.cnf"
  col_append_sep_str(actx->pinfo->cinfo, COL_INFO, NULL, "HandoverReport");

  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_x2ap_HandoverReport, HandoverReport_sequence);

  return offset;
}


static const per_sequence_t SNStatusTransfer_sequence[] = {
  { &hf_x2ap_protocolIEs    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_x2ap_ProtocolIE_Container },
  { NULL, 0, 0, NULL }
};

static int
dissect_x2ap_SNStatusTransfer(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 469 "./asn1/x2ap/x2ap.cnf"
  col_append_sep_str(actx->pinfo->cinfo, COL_INFO, NULL, "SNStatusTransfer");

  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_x2ap_SNStatusTransfer, SNStatusTransfer_sequence);

  return offset;
}


static const per_sequence_t E_RABs_SubjectToStatusTransfer_List_sequence_of[1] = {
  { &hf_x2ap_E_RABs_SubjectToStatusTransfer_List_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_x2ap_ProtocolIE_Single_Container },
};

static int
dissect_x2ap_E_RABs_SubjectToStatusTransfer_List(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_x2ap_E_RABs_SubjectToStatusTransfer_List, E_RABs_SubjectToStatusTransfer_List_sequence_of,
                                                  1, maxnoofBearers, FALSE);

  return offset;
}


static const per_sequence_t E_RABs_SubjectToStatusTransfer_Item_sequence[] = {
  { &hf_x2ap_e_RAB_ID       , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_x2ap_E_RAB_ID },
  { &hf_x2ap_receiveStatusofULPDCPSDUs, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_x2ap_ReceiveStatusofULPDCPSDUs },
  { &hf_x2ap_uL_COUNTvalue  , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_x2ap_COUNTvalue },
  { &hf_x2ap_dL_COUNTvalue  , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_x2ap_COUNTvalue },
  { &hf_x2ap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_x2ap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_x2ap_E_RABs_SubjectToStatusTransfer_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_x2ap_E_RABs_SubjectToStatusTransfer_Item, E_RABs_SubjectToStatusTransfer_Item_sequence);

  return offset;
}


static const per_sequence_t UEContextRelease_sequence[] = {
  { &hf_x2ap_protocolIEs    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_x2ap_ProtocolIE_Container },
  { NULL, 0, 0, NULL }
};

static int
dissect_x2ap_UEContextRelease(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 471 "./asn1/x2ap/x2ap.cnf"
  col_append_sep_str(actx->pinfo->cinfo, COL_INFO, NULL, "UEContextRelease");

  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_x2ap_UEContextRelease, UEContextRelease_sequence);

  return offset;
}


static const per_sequence_t HandoverCancel_sequence[] = {
  { &hf_x2ap_protocolIEs    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_x2ap_ProtocolIE_Container },
  { NULL, 0, 0, NULL }
};

static int
dissect_x2ap_HandoverCancel(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 473 "./asn1/x2ap/x2ap.cnf"
  col_append_sep_str(actx->pinfo->cinfo, COL_INFO, NULL, "HandoverCancel");

  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_x2ap_HandoverCancel, HandoverCancel_sequence);

  return offset;
}


static const per_sequence_t ErrorIndication_sequence[] = {
  { &hf_x2ap_protocolIEs    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_x2ap_ProtocolIE_Container },
  { NULL, 0, 0, NULL }
};

static int
dissect_x2ap_ErrorIndication(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 475 "./asn1/x2ap/x2ap.cnf"
  col_append_sep_str(actx->pinfo->cinfo, COL_INFO, NULL, "ErrorIndication");

  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_x2ap_ErrorIndication, ErrorIndication_sequence);

  return offset;
}


static const per_sequence_t ResetRequest_sequence[] = {
  { &hf_x2ap_protocolIEs    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_x2ap_ProtocolIE_Container },
  { NULL, 0, 0, NULL }
};

static int
dissect_x2ap_ResetRequest(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 477 "./asn1/x2ap/x2ap.cnf"
  col_append_sep_str(actx->pinfo->cinfo, COL_INFO, NULL, "ResetRequest");

  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_x2ap_ResetRequest, ResetRequest_sequence);

  return offset;
}


static const per_sequence_t ResetResponse_sequence[] = {
  { &hf_x2ap_protocolIEs    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_x2ap_ProtocolIE_Container },
  { NULL, 0, 0, NULL }
};

static int
dissect_x2ap_ResetResponse(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 479 "./asn1/x2ap/x2ap.cnf"
  col_append_sep_str(actx->pinfo->cinfo, COL_INFO, NULL, "ResetResponse");

  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_x2ap_ResetResponse, ResetResponse_sequence);

  return offset;
}


static const per_sequence_t X2SetupRequest_sequence[] = {
  { &hf_x2ap_protocolIEs    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_x2ap_ProtocolIE_Container },
  { NULL, 0, 0, NULL }
};

static int
dissect_x2ap_X2SetupRequest(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 481 "./asn1/x2ap/x2ap.cnf"
  col_append_sep_str(actx->pinfo->cinfo, COL_INFO, NULL, "X2SetupRequest");

  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_x2ap_X2SetupRequest, X2SetupRequest_sequence);

  return offset;
}


static const per_sequence_t X2SetupResponse_sequence[] = {
  { &hf_x2ap_protocolIEs    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_x2ap_ProtocolIE_Container },
  { NULL, 0, 0, NULL }
};

static int
dissect_x2ap_X2SetupResponse(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 483 "./asn1/x2ap/x2ap.cnf"
  col_append_sep_str(actx->pinfo->cinfo, COL_INFO, NULL, "X2SetupResponse");

  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_x2ap_X2SetupResponse, X2SetupResponse_sequence);

  return offset;
}


static const per_sequence_t X2SetupFailure_sequence[] = {
  { &hf_x2ap_protocolIEs    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_x2ap_ProtocolIE_Container },
  { NULL, 0, 0, NULL }
};

static int
dissect_x2ap_X2SetupFailure(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 485 "./asn1/x2ap/x2ap.cnf"
  col_append_sep_str(actx->pinfo->cinfo, COL_INFO, NULL, "X2SetupFailure");

  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_x2ap_X2SetupFailure, X2SetupFailure_sequence);

  return offset;
}


static const per_sequence_t LoadInformation_sequence[] = {
  { &hf_x2ap_protocolIEs    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_x2ap_ProtocolIE_Container },
  { NULL, 0, 0, NULL }
};

static int
dissect_x2ap_LoadInformation(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 487 "./asn1/x2ap/x2ap.cnf"
  col_append_sep_str(actx->pinfo->cinfo, COL_INFO, NULL, "LoadInformation");

  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_x2ap_LoadInformation, LoadInformation_sequence);

  return offset;
}


static const per_sequence_t CellInformation_List_sequence_of[1] = {
  { &hf_x2ap_CellInformation_List_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_x2ap_ProtocolIE_Single_Container },
};

static int
dissect_x2ap_CellInformation_List(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_x2ap_CellInformation_List, CellInformation_List_sequence_of,
                                                  1, maxCellineNB, FALSE);

  return offset;
}


static const per_sequence_t CellInformation_Item_sequence[] = {
  { &hf_x2ap_cell_ID        , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_x2ap_ECGI },
  { &hf_x2ap_ul_InterferenceOverloadIndication, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_x2ap_UL_InterferenceOverloadIndication },
  { &hf_x2ap_ul_HighInterferenceIndicationInfo, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_x2ap_UL_HighInterferenceIndicationInfo },
  { &hf_x2ap_relativeNarrowbandTxPower, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_x2ap_RelativeNarrowbandTxPower },
  { &hf_x2ap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_x2ap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_x2ap_CellInformation_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_x2ap_CellInformation_Item, CellInformation_Item_sequence);

  return offset;
}


static const per_sequence_t ENBConfigurationUpdate_sequence[] = {
  { &hf_x2ap_protocolIEs    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_x2ap_ProtocolIE_Container },
  { NULL, 0, 0, NULL }
};

static int
dissect_x2ap_ENBConfigurationUpdate(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 489 "./asn1/x2ap/x2ap.cnf"
  col_append_sep_str(actx->pinfo->cinfo, COL_INFO, NULL, "ENBConfigurationUpdate");

  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_x2ap_ENBConfigurationUpdate, ENBConfigurationUpdate_sequence);

  return offset;
}


static const per_sequence_t ServedCellsToModify_Item_sequence[] = {
  { &hf_x2ap_old_ecgi       , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_x2ap_ECGI },
  { &hf_x2ap_servedCellInfo , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_x2ap_ServedCell_Information },
  { &hf_x2ap_neighbour_Info , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_x2ap_Neighbour_Information },
  { &hf_x2ap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_x2ap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_x2ap_ServedCellsToModify_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_x2ap_ServedCellsToModify_Item, ServedCellsToModify_Item_sequence);

  return offset;
}


static const per_sequence_t ServedCellsToModify_sequence_of[1] = {
  { &hf_x2ap_ServedCellsToModify_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_x2ap_ServedCellsToModify_Item },
};

static int
dissect_x2ap_ServedCellsToModify(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_x2ap_ServedCellsToModify, ServedCellsToModify_sequence_of,
                                                  1, maxCellineNB, FALSE);

  return offset;
}


static const per_sequence_t Old_ECGIs_sequence_of[1] = {
  { &hf_x2ap_Old_ECGIs_item , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_x2ap_ECGI },
};

static int
dissect_x2ap_Old_ECGIs(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_x2ap_Old_ECGIs, Old_ECGIs_sequence_of,
                                                  1, maxCellineNB, FALSE);

  return offset;
}


static const per_sequence_t ENBConfigurationUpdateAcknowledge_sequence[] = {
  { &hf_x2ap_protocolIEs    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_x2ap_ProtocolIE_Container },
  { NULL, 0, 0, NULL }
};

static int
dissect_x2ap_ENBConfigurationUpdateAcknowledge(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 491 "./asn1/x2ap/x2ap.cnf"
  col_append_sep_str(actx->pinfo->cinfo, COL_INFO, NULL, "ENBConfigurationUpdateAcknowledge");

  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_x2ap_ENBConfigurationUpdateAcknowledge, ENBConfigurationUpdateAcknowledge_sequence);

  return offset;
}


static const per_sequence_t ENBConfigurationUpdateFailure_sequence[] = {
  { &hf_x2ap_protocolIEs    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_x2ap_ProtocolIE_Container },
  { NULL, 0, 0, NULL }
};

static int
dissect_x2ap_ENBConfigurationUpdateFailure(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 493 "./asn1/x2ap/x2ap.cnf"
  col_append_sep_str(actx->pinfo->cinfo, COL_INFO, NULL, "ENBConfigurationUpdateFailure");

  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_x2ap_ENBConfigurationUpdateFailure, ENBConfigurationUpdateFailure_sequence);

  return offset;
}


static const per_sequence_t ResourceStatusRequest_sequence[] = {
  { &hf_x2ap_protocolIEs    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_x2ap_ProtocolIE_Container },
  { NULL, 0, 0, NULL }
};

static int
dissect_x2ap_ResourceStatusRequest(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 495 "./asn1/x2ap/x2ap.cnf"
  col_append_sep_str(actx->pinfo->cinfo, COL_INFO, NULL, "ResourceStatusRequest");

  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_x2ap_ResourceStatusRequest, ResourceStatusRequest_sequence);

  return offset;
}


static const per_sequence_t CellToReport_List_sequence_of[1] = {
  { &hf_x2ap_CellToReport_List_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_x2ap_ProtocolIE_Single_Container },
};

static int
dissect_x2ap_CellToReport_List(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_x2ap_CellToReport_List, CellToReport_List_sequence_of,
                                                  1, maxCellineNB, FALSE);

  return offset;
}


static const per_sequence_t CellToReport_Item_sequence[] = {
  { &hf_x2ap_cell_ID        , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_x2ap_ECGI },
  { &hf_x2ap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_x2ap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_x2ap_CellToReport_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_x2ap_CellToReport_Item, CellToReport_Item_sequence);

  return offset;
}


static const value_string x2ap_ReportingPeriodicity_vals[] = {
  {   0, "one-thousand-ms" },
  {   1, "two-thousand-ms" },
  {   2, "five-thousand-ms" },
  {   3, "ten-thousand-ms" },
  { 0, NULL }
};


static int
dissect_x2ap_ReportingPeriodicity(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     4, NULL, TRUE, 0, NULL);

  return offset;
}


static const value_string x2ap_PartialSuccessIndicator_vals[] = {
  {   0, "partial-success-allowed" },
  { 0, NULL }
};


static int
dissect_x2ap_PartialSuccessIndicator(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     1, NULL, TRUE, 0, NULL);

  return offset;
}


static const per_sequence_t ResourceStatusResponse_sequence[] = {
  { &hf_x2ap_protocolIEs    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_x2ap_ProtocolIE_Container },
  { NULL, 0, 0, NULL }
};

static int
dissect_x2ap_ResourceStatusResponse(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 497 "./asn1/x2ap/x2ap.cnf"
  col_append_sep_str(actx->pinfo->cinfo, COL_INFO, NULL, "ResourceStatusResponse");

  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_x2ap_ResourceStatusResponse, ResourceStatusResponse_sequence);

  return offset;
}


static const per_sequence_t MeasurementInitiationResult_List_sequence_of[1] = {
  { &hf_x2ap_MeasurementInitiationResult_List_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_x2ap_ProtocolIE_Single_Container },
};

static int
dissect_x2ap_MeasurementInitiationResult_List(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_x2ap_MeasurementInitiationResult_List, MeasurementInitiationResult_List_sequence_of,
                                                  1, maxCellineNB, FALSE);

  return offset;
}


static const per_sequence_t MeasurementFailureCause_List_sequence_of[1] = {
  { &hf_x2ap_MeasurementFailureCause_List_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_x2ap_ProtocolIE_Single_Container },
};

static int
dissect_x2ap_MeasurementFailureCause_List(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_x2ap_MeasurementFailureCause_List, MeasurementFailureCause_List_sequence_of,
                                                  1, maxFailedMeasObjects, FALSE);

  return offset;
}


static const per_sequence_t MeasurementInitiationResult_Item_sequence[] = {
  { &hf_x2ap_cell_ID        , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_x2ap_ECGI },
  { &hf_x2ap_measurementFailureCause_List, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_x2ap_MeasurementFailureCause_List },
  { &hf_x2ap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_x2ap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_x2ap_MeasurementInitiationResult_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_x2ap_MeasurementInitiationResult_Item, MeasurementInitiationResult_Item_sequence);

  return offset;
}



static int
dissect_x2ap_T_measurementFailedReportCharacteristics(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 174 "./asn1/x2ap/x2ap.cnf"
  tvbuff_t *parameter_tvb = NULL;

  offset = dissect_per_bit_string(tvb, offset, actx, tree, hf_index,
                                     32, 32, FALSE, &parameter_tvb, NULL);

  if(parameter_tvb){
    const gint *fields[] = {
      &hf_x2ap_measurementFailedReportCharacteristics_PRBPeriodic,
      &hf_x2ap_measurementFailedReportCharacteristics_TNLLoadIndPeriodic,
      &hf_x2ap_measurementFailedReportCharacteristics_HWLoadIndPeriodic,
      &hf_x2ap_measurementFailedReportCharacteristics_CompositeAvailableCapacityPeriodic,
      &hf_x2ap_measurementFailedReportCharacteristics_ABSStatusPeriodic,
      &hf_x2ap_measurementFailedReportCharacteristics_RSRPMeasurementReportPeriodic,
      &hf_x2ap_measurementFailedReportCharacteristics_CSIReportPeriodic,
      &hf_x2ap_measurementFailedReportCharacteristics_Reserved,
      NULL
    };
    proto_tree *subtree = proto_item_add_subtree(actx->created_item, ett_x2ap_measurementFailedReportCharacteristics);
    proto_tree_add_bitmask_list(subtree, parameter_tvb, 0, 4, fields, ENC_BIG_ENDIAN);
  }



  return offset;
}


static const per_sequence_t MeasurementFailureCause_Item_sequence[] = {
  { &hf_x2ap_measurementFailedReportCharacteristics, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_x2ap_T_measurementFailedReportCharacteristics },
  { &hf_x2ap_cause          , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_x2ap_Cause },
  { &hf_x2ap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_x2ap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_x2ap_MeasurementFailureCause_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_x2ap_MeasurementFailureCause_Item, MeasurementFailureCause_Item_sequence);

  return offset;
}


static const per_sequence_t ResourceStatusFailure_sequence[] = {
  { &hf_x2ap_protocolIEs    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_x2ap_ProtocolIE_Container },
  { NULL, 0, 0, NULL }
};

static int
dissect_x2ap_ResourceStatusFailure(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 499 "./asn1/x2ap/x2ap.cnf"
  col_append_sep_str(actx->pinfo->cinfo, COL_INFO, NULL, "ResourceStatusFailure");

  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_x2ap_ResourceStatusFailure, ResourceStatusFailure_sequence);

  return offset;
}


static const per_sequence_t CompleteFailureCauseInformation_List_sequence_of[1] = {
  { &hf_x2ap_CompleteFailureCauseInformation_List_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_x2ap_ProtocolIE_Single_Container },
};

static int
dissect_x2ap_CompleteFailureCauseInformation_List(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_x2ap_CompleteFailureCauseInformation_List, CompleteFailureCauseInformation_List_sequence_of,
                                                  1, maxCellineNB, FALSE);

  return offset;
}


static const per_sequence_t CompleteFailureCauseInformation_Item_sequence[] = {
  { &hf_x2ap_cell_ID        , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_x2ap_ECGI },
  { &hf_x2ap_measurementFailureCause_List, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_x2ap_MeasurementFailureCause_List },
  { &hf_x2ap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_x2ap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_x2ap_CompleteFailureCauseInformation_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_x2ap_CompleteFailureCauseInformation_Item, CompleteFailureCauseInformation_Item_sequence);

  return offset;
}


static const per_sequence_t ResourceStatusUpdate_sequence[] = {
  { &hf_x2ap_protocolIEs    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_x2ap_ProtocolIE_Container },
  { NULL, 0, 0, NULL }
};

static int
dissect_x2ap_ResourceStatusUpdate(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 501 "./asn1/x2ap/x2ap.cnf"
  col_append_sep_str(actx->pinfo->cinfo, COL_INFO, NULL, "ResourceStatusUpdate");

  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_x2ap_ResourceStatusUpdate, ResourceStatusUpdate_sequence);

  return offset;
}


static const per_sequence_t CellMeasurementResult_List_sequence_of[1] = {
  { &hf_x2ap_CellMeasurementResult_List_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_x2ap_ProtocolIE_Single_Container },
};

static int
dissect_x2ap_CellMeasurementResult_List(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_x2ap_CellMeasurementResult_List, CellMeasurementResult_List_sequence_of,
                                                  1, maxCellineNB, FALSE);

  return offset;
}


static const per_sequence_t CellMeasurementResult_Item_sequence[] = {
  { &hf_x2ap_cell_ID        , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_x2ap_ECGI },
  { &hf_x2ap_hWLoadIndicator, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_x2ap_HWLoadIndicator },
  { &hf_x2ap_s1TNLLoadIndicator, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_x2ap_S1TNLLoadIndicator },
  { &hf_x2ap_radioResourceStatus, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_x2ap_RadioResourceStatus },
  { &hf_x2ap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_x2ap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_x2ap_CellMeasurementResult_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_x2ap_CellMeasurementResult_Item, CellMeasurementResult_Item_sequence);

  return offset;
}


static const per_sequence_t PrivateMessage_sequence[] = {
  { &hf_x2ap_privateIEs     , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_x2ap_PrivateIE_Container },
  { NULL, 0, 0, NULL }
};

static int
dissect_x2ap_PrivateMessage(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 503 "./asn1/x2ap/x2ap.cnf"
  col_append_sep_str(actx->pinfo->cinfo, COL_INFO, NULL, "PrivateMessage");

  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_x2ap_PrivateMessage, PrivateMessage_sequence);

  return offset;
}


static const per_sequence_t MobilityChangeRequest_sequence[] = {
  { &hf_x2ap_protocolIEs    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_x2ap_ProtocolIE_Container },
  { NULL, 0, 0, NULL }
};

static int
dissect_x2ap_MobilityChangeRequest(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 509 "./asn1/x2ap/x2ap.cnf"
  col_append_sep_str(actx->pinfo->cinfo, COL_INFO, NULL, "MobilityChangeRequest");

  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_x2ap_MobilityChangeRequest, MobilityChangeRequest_sequence);

  return offset;
}


static const per_sequence_t MobilityChangeAcknowledge_sequence[] = {
  { &hf_x2ap_protocolIEs    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_x2ap_ProtocolIE_Container },
  { NULL, 0, 0, NULL }
};

static int
dissect_x2ap_MobilityChangeAcknowledge(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 511 "./asn1/x2ap/x2ap.cnf"
  col_append_sep_str(actx->pinfo->cinfo, COL_INFO, NULL, "MobilityChangeAcknowledge");

  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_x2ap_MobilityChangeAcknowledge, MobilityChangeAcknowledge_sequence);

  return offset;
}


static const per_sequence_t MobilityChangeFailure_sequence[] = {
  { &hf_x2ap_protocolIEs    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_x2ap_ProtocolIE_Container },
  { NULL, 0, 0, NULL }
};

static int
dissect_x2ap_MobilityChangeFailure(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 513 "./asn1/x2ap/x2ap.cnf"
  col_append_sep_str(actx->pinfo->cinfo, COL_INFO, NULL, "MobilityChangeFailure");

  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_x2ap_MobilityChangeFailure, MobilityChangeFailure_sequence);

  return offset;
}


static const per_sequence_t RLFIndication_sequence[] = {
  { &hf_x2ap_protocolIEs    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_x2ap_ProtocolIE_Container },
  { NULL, 0, 0, NULL }
};

static int
dissect_x2ap_RLFIndication(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 507 "./asn1/x2ap/x2ap.cnf"
  col_append_sep_str(actx->pinfo->cinfo, COL_INFO, NULL, "RLFIndication");

  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_x2ap_RLFIndication, RLFIndication_sequence);

  return offset;
}


static const per_sequence_t CellActivationRequest_sequence[] = {
  { &hf_x2ap_protocolIEs    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_x2ap_ProtocolIE_Container },
  { NULL, 0, 0, NULL }
};

static int
dissect_x2ap_CellActivationRequest(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 515 "./asn1/x2ap/x2ap.cnf"
  col_append_sep_str(actx->pinfo->cinfo, COL_INFO, NULL, "CellActivationRequest");

  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_x2ap_CellActivationRequest, CellActivationRequest_sequence);

  return offset;
}


static const per_sequence_t ServedCellsToActivate_Item_sequence[] = {
  { &hf_x2ap_ecgi           , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_x2ap_ECGI },
  { &hf_x2ap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_x2ap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_x2ap_ServedCellsToActivate_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_x2ap_ServedCellsToActivate_Item, ServedCellsToActivate_Item_sequence);

  return offset;
}


static const per_sequence_t ServedCellsToActivate_sequence_of[1] = {
  { &hf_x2ap_ServedCellsToActivate_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_x2ap_ServedCellsToActivate_Item },
};

static int
dissect_x2ap_ServedCellsToActivate(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_x2ap_ServedCellsToActivate, ServedCellsToActivate_sequence_of,
                                                  1, maxCellineNB, FALSE);

  return offset;
}


static const per_sequence_t CellActivationResponse_sequence[] = {
  { &hf_x2ap_protocolIEs    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_x2ap_ProtocolIE_Container },
  { NULL, 0, 0, NULL }
};

static int
dissect_x2ap_CellActivationResponse(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 517 "./asn1/x2ap/x2ap.cnf"
  col_append_sep_str(actx->pinfo->cinfo, COL_INFO, NULL, "CellActivationResponse");

  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_x2ap_CellActivationResponse, CellActivationResponse_sequence);

  return offset;
}


static const per_sequence_t ActivatedCellList_Item_sequence[] = {
  { &hf_x2ap_ecgi           , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_x2ap_ECGI },
  { &hf_x2ap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_x2ap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_x2ap_ActivatedCellList_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_x2ap_ActivatedCellList_Item, ActivatedCellList_Item_sequence);

  return offset;
}


static const per_sequence_t ActivatedCellList_sequence_of[1] = {
  { &hf_x2ap_ActivatedCellList_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_x2ap_ActivatedCellList_Item },
};

static int
dissect_x2ap_ActivatedCellList(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_x2ap_ActivatedCellList, ActivatedCellList_sequence_of,
                                                  1, maxCellineNB, FALSE);

  return offset;
}


static const per_sequence_t CellActivationFailure_sequence[] = {
  { &hf_x2ap_protocolIEs    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_x2ap_ProtocolIE_Container },
  { NULL, 0, 0, NULL }
};

static int
dissect_x2ap_CellActivationFailure(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 519 "./asn1/x2ap/x2ap.cnf"
  col_append_sep_str(actx->pinfo->cinfo, COL_INFO, NULL, "CellActivationFailure");

  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_x2ap_CellActivationFailure, CellActivationFailure_sequence);

  return offset;
}


static const per_sequence_t X2Release_sequence[] = {
  { &hf_x2ap_protocolIEs    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_x2ap_ProtocolIE_Container },
  { NULL, 0, 0, NULL }
};

static int
dissect_x2ap_X2Release(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 521 "./asn1/x2ap/x2ap.cnf"
  col_append_sep_str(actx->pinfo->cinfo, COL_INFO, NULL, "X2Release");

  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_x2ap_X2Release, X2Release_sequence);

  return offset;
}


static const per_sequence_t X2APMessageTransfer_sequence[] = {
  { &hf_x2ap_protocolIEs    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_x2ap_ProtocolIE_Container },
  { NULL, 0, 0, NULL }
};

static int
dissect_x2ap_X2APMessageTransfer(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 523 "./asn1/x2ap/x2ap.cnf"
  col_append_sep_str(actx->pinfo->cinfo, COL_INFO, NULL, "X2APMessageTransfer");

  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_x2ap_X2APMessageTransfer, X2APMessageTransfer_sequence);

  return offset;
}


static const per_sequence_t RNL_Header_sequence[] = {
  { &hf_x2ap_source_GlobalENB_ID, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_x2ap_GlobalENB_ID },
  { &hf_x2ap_target_GlobalENB_ID, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_x2ap_GlobalENB_ID },
  { &hf_x2ap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_x2ap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_x2ap_RNL_Header(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_x2ap_RNL_Header, RNL_Header_sequence);

  return offset;
}



static int
dissect_x2ap_X2AP_Message(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 454 "./asn1/x2ap/x2ap.cnf"
  tvbuff_t *parameter_tvb;
  offset = dissect_per_octet_string(tvb, offset, actx, tree, hf_index,
                                       NO_BOUND, NO_BOUND, FALSE, &parameter_tvb);

  if (parameter_tvb) {
    proto_tree *subtree = proto_item_add_subtree(actx->created_item, ett_x2ap_X2AP_Message);
    dissect_X2AP_PDU_PDU(parameter_tvb, actx->pinfo, subtree, NULL);
  }


  return offset;
}


static const per_sequence_t SeNBAdditionRequest_sequence[] = {
  { &hf_x2ap_protocolIEs    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_x2ap_ProtocolIE_Container },
  { NULL, 0, 0, NULL }
};

static int
dissect_x2ap_SeNBAdditionRequest(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 531 "./asn1/x2ap/x2ap.cnf"
  col_append_sep_str(actx->pinfo->cinfo, COL_INFO, NULL, "SeNBAdditionRequest");

  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_x2ap_SeNBAdditionRequest, SeNBAdditionRequest_sequence);

  return offset;
}


static const per_sequence_t E_RABs_ToBeAdded_List_sequence_of[1] = {
  { &hf_x2ap_E_RABs_ToBeAdded_List_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_x2ap_ProtocolIE_Single_Container },
};

static int
dissect_x2ap_E_RABs_ToBeAdded_List(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_x2ap_E_RABs_ToBeAdded_List, E_RABs_ToBeAdded_List_sequence_of,
                                                  1, maxnoofBearers, FALSE);

  return offset;
}


static const per_sequence_t E_RABs_ToBeAdded_Item_SCG_Bearer_sequence[] = {
  { &hf_x2ap_e_RAB_ID       , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_x2ap_E_RAB_ID },
  { &hf_x2ap_e_RAB_Level_QoS_Parameters, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_x2ap_E_RAB_Level_QoS_Parameters },
  { &hf_x2ap_dL_Forwarding  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_x2ap_DL_Forwarding },
  { &hf_x2ap_s1_UL_GTPtunnelEndpoint, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_x2ap_GTPtunnelEndpoint },
  { &hf_x2ap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_x2ap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_x2ap_E_RABs_ToBeAdded_Item_SCG_Bearer(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_x2ap_E_RABs_ToBeAdded_Item_SCG_Bearer, E_RABs_ToBeAdded_Item_SCG_Bearer_sequence);

  return offset;
}


static const per_sequence_t E_RABs_ToBeAdded_Item_Split_Bearer_sequence[] = {
  { &hf_x2ap_e_RAB_ID       , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_x2ap_E_RAB_ID },
  { &hf_x2ap_e_RAB_Level_QoS_Parameters, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_x2ap_E_RAB_Level_QoS_Parameters },
  { &hf_x2ap_meNB_GTPtunnelEndpoint, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_x2ap_GTPtunnelEndpoint },
  { &hf_x2ap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_x2ap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_x2ap_E_RABs_ToBeAdded_Item_Split_Bearer(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_x2ap_E_RABs_ToBeAdded_Item_Split_Bearer, E_RABs_ToBeAdded_Item_Split_Bearer_sequence);

  return offset;
}


static const value_string x2ap_E_RABs_ToBeAdded_Item_vals[] = {
  {   0, "sCG-Bearer" },
  {   1, "split-Bearer" },
  { 0, NULL }
};

static const per_choice_t E_RABs_ToBeAdded_Item_choice[] = {
  {   0, &hf_x2ap_sCG_Bearer     , ASN1_EXTENSION_ROOT    , dissect_x2ap_E_RABs_ToBeAdded_Item_SCG_Bearer },
  {   1, &hf_x2ap_split_Bearer   , ASN1_EXTENSION_ROOT    , dissect_x2ap_E_RABs_ToBeAdded_Item_Split_Bearer },
  { 0, NULL, 0, NULL }
};

static int
dissect_x2ap_E_RABs_ToBeAdded_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_x2ap_E_RABs_ToBeAdded_Item, E_RABs_ToBeAdded_Item_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t SeNBAdditionRequestAcknowledge_sequence[] = {
  { &hf_x2ap_protocolIEs    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_x2ap_ProtocolIE_Container },
  { NULL, 0, 0, NULL }
};

static int
dissect_x2ap_SeNBAdditionRequestAcknowledge(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 533 "./asn1/x2ap/x2ap.cnf"
  col_append_sep_str(actx->pinfo->cinfo, COL_INFO, NULL, "SeNBAdditionRequestAcknowledge");

  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_x2ap_SeNBAdditionRequestAcknowledge, SeNBAdditionRequestAcknowledge_sequence);

  return offset;
}


static const per_sequence_t E_RABs_Admitted_ToBeAdded_List_sequence_of[1] = {
  { &hf_x2ap_E_RABs_Admitted_ToBeAdded_List_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_x2ap_ProtocolIE_Single_Container },
};

static int
dissect_x2ap_E_RABs_Admitted_ToBeAdded_List(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_x2ap_E_RABs_Admitted_ToBeAdded_List, E_RABs_Admitted_ToBeAdded_List_sequence_of,
                                                  1, maxnoofBearers, FALSE);

  return offset;
}


static const per_sequence_t E_RABs_Admitted_ToBeAdded_Item_SCG_Bearer_sequence[] = {
  { &hf_x2ap_e_RAB_ID       , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_x2ap_E_RAB_ID },
  { &hf_x2ap_s1_DL_GTPtunnelEndpoint, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_x2ap_GTPtunnelEndpoint },
  { &hf_x2ap_dL_Forwarding_GTPtunnelEndpoint, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_x2ap_GTPtunnelEndpoint },
  { &hf_x2ap_uL_Forwarding_GTPtunnelEndpoint, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_x2ap_GTPtunnelEndpoint },
  { &hf_x2ap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_x2ap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_x2ap_E_RABs_Admitted_ToBeAdded_Item_SCG_Bearer(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_x2ap_E_RABs_Admitted_ToBeAdded_Item_SCG_Bearer, E_RABs_Admitted_ToBeAdded_Item_SCG_Bearer_sequence);

  return offset;
}


static const per_sequence_t E_RABs_Admitted_ToBeAdded_Item_Split_Bearer_sequence[] = {
  { &hf_x2ap_e_RAB_ID       , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_x2ap_E_RAB_ID },
  { &hf_x2ap_seNB_GTPtunnelEndpoint, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_x2ap_GTPtunnelEndpoint },
  { &hf_x2ap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_x2ap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_x2ap_E_RABs_Admitted_ToBeAdded_Item_Split_Bearer(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_x2ap_E_RABs_Admitted_ToBeAdded_Item_Split_Bearer, E_RABs_Admitted_ToBeAdded_Item_Split_Bearer_sequence);

  return offset;
}


static const value_string x2ap_E_RABs_Admitted_ToBeAdded_Item_vals[] = {
  {   0, "sCG-Bearer" },
  {   1, "split-Bearer" },
  { 0, NULL }
};

static const per_choice_t E_RABs_Admitted_ToBeAdded_Item_choice[] = {
  {   0, &hf_x2ap_sCG_Bearer_01  , ASN1_EXTENSION_ROOT    , dissect_x2ap_E_RABs_Admitted_ToBeAdded_Item_SCG_Bearer },
  {   1, &hf_x2ap_split_Bearer_01, ASN1_EXTENSION_ROOT    , dissect_x2ap_E_RABs_Admitted_ToBeAdded_Item_Split_Bearer },
  { 0, NULL, 0, NULL }
};

static int
dissect_x2ap_E_RABs_Admitted_ToBeAdded_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_x2ap_E_RABs_Admitted_ToBeAdded_Item, E_RABs_Admitted_ToBeAdded_Item_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t SeNBAdditionRequestReject_sequence[] = {
  { &hf_x2ap_protocolIEs    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_x2ap_ProtocolIE_Container },
  { NULL, 0, 0, NULL }
};

static int
dissect_x2ap_SeNBAdditionRequestReject(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 535 "./asn1/x2ap/x2ap.cnf"
  col_append_sep_str(actx->pinfo->cinfo, COL_INFO, NULL, "SeNBAdditionRequestReject");

  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_x2ap_SeNBAdditionRequestReject, SeNBAdditionRequestReject_sequence);

  return offset;
}


static const per_sequence_t SeNBReconfigurationComplete_sequence[] = {
  { &hf_x2ap_protocolIEs    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_x2ap_ProtocolIE_Container },
  { NULL, 0, 0, NULL }
};

static int
dissect_x2ap_SeNBReconfigurationComplete(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 537 "./asn1/x2ap/x2ap.cnf"
  col_append_sep_str(actx->pinfo->cinfo, COL_INFO, NULL, "SeNBReconfigurationComplete");

  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_x2ap_SeNBReconfigurationComplete, SeNBReconfigurationComplete_sequence);

  return offset;
}


static const per_sequence_t ResponseInformationSeNBReconfComp_SuccessItem_sequence[] = {
  { &hf_x2ap_meNBtoSeNBContainer, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_x2ap_MeNBtoSeNBContainer },
  { &hf_x2ap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_x2ap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_x2ap_ResponseInformationSeNBReconfComp_SuccessItem(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_x2ap_ResponseInformationSeNBReconfComp_SuccessItem, ResponseInformationSeNBReconfComp_SuccessItem_sequence);

  return offset;
}


static const per_sequence_t ResponseInformationSeNBReconfComp_RejectByMeNBItem_sequence[] = {
  { &hf_x2ap_cause          , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_x2ap_Cause },
  { &hf_x2ap_meNBtoSeNBContainer, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_x2ap_MeNBtoSeNBContainer },
  { &hf_x2ap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_x2ap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_x2ap_ResponseInformationSeNBReconfComp_RejectByMeNBItem(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_x2ap_ResponseInformationSeNBReconfComp_RejectByMeNBItem, ResponseInformationSeNBReconfComp_RejectByMeNBItem_sequence);

  return offset;
}


static const value_string x2ap_ResponseInformationSeNBReconfComp_vals[] = {
  {   0, "success" },
  {   1, "reject-by-MeNB" },
  { 0, NULL }
};

static const per_choice_t ResponseInformationSeNBReconfComp_choice[] = {
  {   0, &hf_x2ap_success        , ASN1_EXTENSION_ROOT    , dissect_x2ap_ResponseInformationSeNBReconfComp_SuccessItem },
  {   1, &hf_x2ap_reject_by_MeNB , ASN1_EXTENSION_ROOT    , dissect_x2ap_ResponseInformationSeNBReconfComp_RejectByMeNBItem },
  { 0, NULL, 0, NULL }
};

static int
dissect_x2ap_ResponseInformationSeNBReconfComp(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_x2ap_ResponseInformationSeNBReconfComp, ResponseInformationSeNBReconfComp_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t SeNBModificationRequest_sequence[] = {
  { &hf_x2ap_protocolIEs    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_x2ap_ProtocolIE_Container },
  { NULL, 0, 0, NULL }
};

static int
dissect_x2ap_SeNBModificationRequest(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 539 "./asn1/x2ap/x2ap.cnf"
  col_append_sep_str(actx->pinfo->cinfo, COL_INFO, NULL, "SeNBModificationRequest");

  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_x2ap_SeNBModificationRequest, SeNBModificationRequest_sequence);

  return offset;
}


static const per_sequence_t E_RABs_ToBeAdded_List_ModReq_sequence_of[1] = {
  { &hf_x2ap_E_RABs_ToBeAdded_List_ModReq_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_x2ap_ProtocolIE_Single_Container },
};

static int
dissect_x2ap_E_RABs_ToBeAdded_List_ModReq(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_x2ap_E_RABs_ToBeAdded_List_ModReq, E_RABs_ToBeAdded_List_ModReq_sequence_of,
                                                  1, maxnoofBearers, FALSE);

  return offset;
}


static const per_sequence_t E_RABs_ToBeModified_List_ModReq_sequence_of[1] = {
  { &hf_x2ap_E_RABs_ToBeModified_List_ModReq_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_x2ap_ProtocolIE_Single_Container },
};

static int
dissect_x2ap_E_RABs_ToBeModified_List_ModReq(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_x2ap_E_RABs_ToBeModified_List_ModReq, E_RABs_ToBeModified_List_ModReq_sequence_of,
                                                  1, maxnoofBearers, FALSE);

  return offset;
}


static const per_sequence_t E_RABs_ToBeReleased_List_ModReq_sequence_of[1] = {
  { &hf_x2ap_E_RABs_ToBeReleased_List_ModReq_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_x2ap_ProtocolIE_Single_Container },
};

static int
dissect_x2ap_E_RABs_ToBeReleased_List_ModReq(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_x2ap_E_RABs_ToBeReleased_List_ModReq, E_RABs_ToBeReleased_List_ModReq_sequence_of,
                                                  1, maxnoofBearers, FALSE);

  return offset;
}


static const per_sequence_t UE_ContextInformationSeNBModReq_sequence[] = {
  { &hf_x2ap_uE_SecurityCapabilities, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_x2ap_UESecurityCapabilities },
  { &hf_x2ap_seNB_SecurityKey, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_x2ap_SeNBSecurityKey },
  { &hf_x2ap_seNBUEAggregateMaximumBitRate, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_x2ap_UEAggregateMaximumBitRate },
  { &hf_x2ap_e_RABs_ToBeAdded, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_x2ap_E_RABs_ToBeAdded_List_ModReq },
  { &hf_x2ap_e_RABs_ToBeModified, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_x2ap_E_RABs_ToBeModified_List_ModReq },
  { &hf_x2ap_e_RABs_ToBeReleased, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_x2ap_E_RABs_ToBeReleased_List_ModReq },
  { &hf_x2ap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_x2ap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_x2ap_UE_ContextInformationSeNBModReq(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_x2ap_UE_ContextInformationSeNBModReq, UE_ContextInformationSeNBModReq_sequence);

  return offset;
}


static const per_sequence_t E_RABs_ToBeAdded_ModReqItem_SCG_Bearer_sequence[] = {
  { &hf_x2ap_e_RAB_ID       , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_x2ap_E_RAB_ID },
  { &hf_x2ap_e_RAB_Level_QoS_Parameters, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_x2ap_E_RAB_Level_QoS_Parameters },
  { &hf_x2ap_dL_Forwarding  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_x2ap_DL_Forwarding },
  { &hf_x2ap_s1_UL_GTPtunnelEndpoint, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_x2ap_GTPtunnelEndpoint },
  { &hf_x2ap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_x2ap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_x2ap_E_RABs_ToBeAdded_ModReqItem_SCG_Bearer(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_x2ap_E_RABs_ToBeAdded_ModReqItem_SCG_Bearer, E_RABs_ToBeAdded_ModReqItem_SCG_Bearer_sequence);

  return offset;
}


static const per_sequence_t E_RABs_ToBeAdded_ModReqItem_Split_Bearer_sequence[] = {
  { &hf_x2ap_e_RAB_ID       , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_x2ap_E_RAB_ID },
  { &hf_x2ap_e_RAB_Level_QoS_Parameters, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_x2ap_E_RAB_Level_QoS_Parameters },
  { &hf_x2ap_meNB_GTPtunnelEndpoint, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_x2ap_GTPtunnelEndpoint },
  { &hf_x2ap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_x2ap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_x2ap_E_RABs_ToBeAdded_ModReqItem_Split_Bearer(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_x2ap_E_RABs_ToBeAdded_ModReqItem_Split_Bearer, E_RABs_ToBeAdded_ModReqItem_Split_Bearer_sequence);

  return offset;
}


static const value_string x2ap_E_RABs_ToBeAdded_ModReqItem_vals[] = {
  {   0, "sCG-Bearer" },
  {   1, "split-Bearer" },
  { 0, NULL }
};

static const per_choice_t E_RABs_ToBeAdded_ModReqItem_choice[] = {
  {   0, &hf_x2ap_sCG_Bearer_02  , ASN1_EXTENSION_ROOT    , dissect_x2ap_E_RABs_ToBeAdded_ModReqItem_SCG_Bearer },
  {   1, &hf_x2ap_split_Bearer_02, ASN1_EXTENSION_ROOT    , dissect_x2ap_E_RABs_ToBeAdded_ModReqItem_Split_Bearer },
  { 0, NULL, 0, NULL }
};

static int
dissect_x2ap_E_RABs_ToBeAdded_ModReqItem(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_x2ap_E_RABs_ToBeAdded_ModReqItem, E_RABs_ToBeAdded_ModReqItem_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t E_RABs_ToBeModified_ModReqItem_SCG_Bearer_sequence[] = {
  { &hf_x2ap_e_RAB_ID       , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_x2ap_E_RAB_ID },
  { &hf_x2ap_e_RAB_Level_QoS_Parameters, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_x2ap_E_RAB_Level_QoS_Parameters },
  { &hf_x2ap_s1_UL_GTPtunnelEndpoint, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_x2ap_GTPtunnelEndpoint },
  { &hf_x2ap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_x2ap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_x2ap_E_RABs_ToBeModified_ModReqItem_SCG_Bearer(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_x2ap_E_RABs_ToBeModified_ModReqItem_SCG_Bearer, E_RABs_ToBeModified_ModReqItem_SCG_Bearer_sequence);

  return offset;
}


static const per_sequence_t E_RABs_ToBeModified_ModReqItem_Split_Bearer_sequence[] = {
  { &hf_x2ap_e_RAB_ID       , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_x2ap_E_RAB_ID },
  { &hf_x2ap_e_RAB_Level_QoS_Parameters, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_x2ap_E_RAB_Level_QoS_Parameters },
  { &hf_x2ap_meNB_GTPtunnelEndpoint, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_x2ap_GTPtunnelEndpoint },
  { &hf_x2ap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_x2ap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_x2ap_E_RABs_ToBeModified_ModReqItem_Split_Bearer(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_x2ap_E_RABs_ToBeModified_ModReqItem_Split_Bearer, E_RABs_ToBeModified_ModReqItem_Split_Bearer_sequence);

  return offset;
}


static const value_string x2ap_E_RABs_ToBeModified_ModReqItem_vals[] = {
  {   0, "sCG-Bearer" },
  {   1, "split-Bearer" },
  { 0, NULL }
};

static const per_choice_t E_RABs_ToBeModified_ModReqItem_choice[] = {
  {   0, &hf_x2ap_sCG_Bearer_03  , ASN1_EXTENSION_ROOT    , dissect_x2ap_E_RABs_ToBeModified_ModReqItem_SCG_Bearer },
  {   1, &hf_x2ap_split_Bearer_03, ASN1_EXTENSION_ROOT    , dissect_x2ap_E_RABs_ToBeModified_ModReqItem_Split_Bearer },
  { 0, NULL, 0, NULL }
};

static int
dissect_x2ap_E_RABs_ToBeModified_ModReqItem(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_x2ap_E_RABs_ToBeModified_ModReqItem, E_RABs_ToBeModified_ModReqItem_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t E_RABs_ToBeReleased_ModReqItem_SCG_Bearer_sequence[] = {
  { &hf_x2ap_e_RAB_ID       , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_x2ap_E_RAB_ID },
  { &hf_x2ap_dL_GTPtunnelEndpoint, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_x2ap_GTPtunnelEndpoint },
  { &hf_x2ap_uL_GTPtunnelEndpoint, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_x2ap_GTPtunnelEndpoint },
  { &hf_x2ap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_x2ap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_x2ap_E_RABs_ToBeReleased_ModReqItem_SCG_Bearer(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_x2ap_E_RABs_ToBeReleased_ModReqItem_SCG_Bearer, E_RABs_ToBeReleased_ModReqItem_SCG_Bearer_sequence);

  return offset;
}


static const per_sequence_t E_RABs_ToBeReleased_ModReqItem_Split_Bearer_sequence[] = {
  { &hf_x2ap_e_RAB_ID       , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_x2ap_E_RAB_ID },
  { &hf_x2ap_dL_GTPtunnelEndpoint, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_x2ap_GTPtunnelEndpoint },
  { &hf_x2ap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_x2ap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_x2ap_E_RABs_ToBeReleased_ModReqItem_Split_Bearer(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_x2ap_E_RABs_ToBeReleased_ModReqItem_Split_Bearer, E_RABs_ToBeReleased_ModReqItem_Split_Bearer_sequence);

  return offset;
}


static const value_string x2ap_E_RABs_ToBeReleased_ModReqItem_vals[] = {
  {   0, "sCG-Bearer" },
  {   1, "split-Bearer" },
  { 0, NULL }
};

static const per_choice_t E_RABs_ToBeReleased_ModReqItem_choice[] = {
  {   0, &hf_x2ap_sCG_Bearer_04  , ASN1_EXTENSION_ROOT    , dissect_x2ap_E_RABs_ToBeReleased_ModReqItem_SCG_Bearer },
  {   1, &hf_x2ap_split_Bearer_04, ASN1_EXTENSION_ROOT    , dissect_x2ap_E_RABs_ToBeReleased_ModReqItem_Split_Bearer },
  { 0, NULL, 0, NULL }
};

static int
dissect_x2ap_E_RABs_ToBeReleased_ModReqItem(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_x2ap_E_RABs_ToBeReleased_ModReqItem, E_RABs_ToBeReleased_ModReqItem_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t SeNBModificationRequestAcknowledge_sequence[] = {
  { &hf_x2ap_protocolIEs    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_x2ap_ProtocolIE_Container },
  { NULL, 0, 0, NULL }
};

static int
dissect_x2ap_SeNBModificationRequestAcknowledge(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 541 "./asn1/x2ap/x2ap.cnf"
  col_append_sep_str(actx->pinfo->cinfo, COL_INFO, NULL, "SeNBModificationRequestAcknowledge");

  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_x2ap_SeNBModificationRequestAcknowledge, SeNBModificationRequestAcknowledge_sequence);

  return offset;
}


static const per_sequence_t E_RABs_Admitted_ToBeAdded_ModAckList_sequence_of[1] = {
  { &hf_x2ap_E_RABs_Admitted_ToBeAdded_ModAckList_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_x2ap_ProtocolIE_Single_Container },
};

static int
dissect_x2ap_E_RABs_Admitted_ToBeAdded_ModAckList(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_x2ap_E_RABs_Admitted_ToBeAdded_ModAckList, E_RABs_Admitted_ToBeAdded_ModAckList_sequence_of,
                                                  1, maxnoofBearers, FALSE);

  return offset;
}


static const per_sequence_t E_RABs_Admitted_ToBeAdded_ModAckItem_SCG_Bearer_sequence[] = {
  { &hf_x2ap_e_RAB_ID       , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_x2ap_E_RAB_ID },
  { &hf_x2ap_s1_DL_GTPtunnelEndpoint, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_x2ap_GTPtunnelEndpoint },
  { &hf_x2ap_dL_Forwarding_GTPtunnelEndpoint, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_x2ap_GTPtunnelEndpoint },
  { &hf_x2ap_uL_Forwarding_GTPtunnelEndpoint, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_x2ap_GTPtunnelEndpoint },
  { &hf_x2ap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_x2ap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_x2ap_E_RABs_Admitted_ToBeAdded_ModAckItem_SCG_Bearer(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_x2ap_E_RABs_Admitted_ToBeAdded_ModAckItem_SCG_Bearer, E_RABs_Admitted_ToBeAdded_ModAckItem_SCG_Bearer_sequence);

  return offset;
}


static const per_sequence_t E_RABs_Admitted_ToBeAdded_ModAckItem_Split_Bearer_sequence[] = {
  { &hf_x2ap_e_RAB_ID       , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_x2ap_E_RAB_ID },
  { &hf_x2ap_seNB_GTPtunnelEndpoint, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_x2ap_GTPtunnelEndpoint },
  { &hf_x2ap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_x2ap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_x2ap_E_RABs_Admitted_ToBeAdded_ModAckItem_Split_Bearer(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_x2ap_E_RABs_Admitted_ToBeAdded_ModAckItem_Split_Bearer, E_RABs_Admitted_ToBeAdded_ModAckItem_Split_Bearer_sequence);

  return offset;
}


static const value_string x2ap_E_RABs_Admitted_ToBeAdded_ModAckItem_vals[] = {
  {   0, "sCG-Bearer" },
  {   1, "split-Bearer" },
  { 0, NULL }
};

static const per_choice_t E_RABs_Admitted_ToBeAdded_ModAckItem_choice[] = {
  {   0, &hf_x2ap_sCG_Bearer_05  , ASN1_EXTENSION_ROOT    , dissect_x2ap_E_RABs_Admitted_ToBeAdded_ModAckItem_SCG_Bearer },
  {   1, &hf_x2ap_split_Bearer_05, ASN1_EXTENSION_ROOT    , dissect_x2ap_E_RABs_Admitted_ToBeAdded_ModAckItem_Split_Bearer },
  { 0, NULL, 0, NULL }
};

static int
dissect_x2ap_E_RABs_Admitted_ToBeAdded_ModAckItem(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_x2ap_E_RABs_Admitted_ToBeAdded_ModAckItem, E_RABs_Admitted_ToBeAdded_ModAckItem_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t E_RABs_Admitted_ToBeModified_ModAckList_sequence_of[1] = {
  { &hf_x2ap_E_RABs_Admitted_ToBeModified_ModAckList_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_x2ap_ProtocolIE_Single_Container },
};

static int
dissect_x2ap_E_RABs_Admitted_ToBeModified_ModAckList(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_x2ap_E_RABs_Admitted_ToBeModified_ModAckList, E_RABs_Admitted_ToBeModified_ModAckList_sequence_of,
                                                  1, maxnoofBearers, FALSE);

  return offset;
}


static const per_sequence_t E_RABs_Admitted_ToBeModified_ModAckItem_SCG_Bearer_sequence[] = {
  { &hf_x2ap_e_RAB_ID       , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_x2ap_E_RAB_ID },
  { &hf_x2ap_s1_DL_GTPtunnelEndpoint, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_x2ap_GTPtunnelEndpoint },
  { &hf_x2ap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_x2ap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_x2ap_E_RABs_Admitted_ToBeModified_ModAckItem_SCG_Bearer(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_x2ap_E_RABs_Admitted_ToBeModified_ModAckItem_SCG_Bearer, E_RABs_Admitted_ToBeModified_ModAckItem_SCG_Bearer_sequence);

  return offset;
}


static const per_sequence_t E_RABs_Admitted_ToBeModified_ModAckItem_Split_Bearer_sequence[] = {
  { &hf_x2ap_e_RAB_ID       , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_x2ap_E_RAB_ID },
  { &hf_x2ap_seNB_GTPtunnelEndpoint, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_x2ap_GTPtunnelEndpoint },
  { &hf_x2ap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_x2ap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_x2ap_E_RABs_Admitted_ToBeModified_ModAckItem_Split_Bearer(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_x2ap_E_RABs_Admitted_ToBeModified_ModAckItem_Split_Bearer, E_RABs_Admitted_ToBeModified_ModAckItem_Split_Bearer_sequence);

  return offset;
}


static const value_string x2ap_E_RABs_Admitted_ToBeModified_ModAckItem_vals[] = {
  {   0, "sCG-Bearer" },
  {   1, "split-Bearer" },
  { 0, NULL }
};

static const per_choice_t E_RABs_Admitted_ToBeModified_ModAckItem_choice[] = {
  {   0, &hf_x2ap_sCG_Bearer_06  , ASN1_EXTENSION_ROOT    , dissect_x2ap_E_RABs_Admitted_ToBeModified_ModAckItem_SCG_Bearer },
  {   1, &hf_x2ap_split_Bearer_06, ASN1_EXTENSION_ROOT    , dissect_x2ap_E_RABs_Admitted_ToBeModified_ModAckItem_Split_Bearer },
  { 0, NULL, 0, NULL }
};

static int
dissect_x2ap_E_RABs_Admitted_ToBeModified_ModAckItem(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_x2ap_E_RABs_Admitted_ToBeModified_ModAckItem, E_RABs_Admitted_ToBeModified_ModAckItem_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t E_RABs_Admitted_ToBeReleased_ModAckList_sequence_of[1] = {
  { &hf_x2ap_E_RABs_Admitted_ToBeReleased_ModAckList_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_x2ap_ProtocolIE_Single_Container },
};

static int
dissect_x2ap_E_RABs_Admitted_ToBeReleased_ModAckList(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_x2ap_E_RABs_Admitted_ToBeReleased_ModAckList, E_RABs_Admitted_ToBeReleased_ModAckList_sequence_of,
                                                  1, maxnoofBearers, FALSE);

  return offset;
}


static const per_sequence_t E_RABs_Admitted_ToBeReleased_ModAckItem_SCG_Bearer_sequence[] = {
  { &hf_x2ap_e_RAB_ID       , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_x2ap_E_RAB_ID },
  { &hf_x2ap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_x2ap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_x2ap_E_RABs_Admitted_ToBeReleased_ModAckItem_SCG_Bearer(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_x2ap_E_RABs_Admitted_ToBeReleased_ModAckItem_SCG_Bearer, E_RABs_Admitted_ToBeReleased_ModAckItem_SCG_Bearer_sequence);

  return offset;
}


static const per_sequence_t E_RABs_Admitted_ToBeReleased_ModAckItem_Split_Bearer_sequence[] = {
  { &hf_x2ap_e_RAB_ID       , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_x2ap_E_RAB_ID },
  { &hf_x2ap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_x2ap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_x2ap_E_RABs_Admitted_ToBeReleased_ModAckItem_Split_Bearer(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_x2ap_E_RABs_Admitted_ToBeReleased_ModAckItem_Split_Bearer, E_RABs_Admitted_ToBeReleased_ModAckItem_Split_Bearer_sequence);

  return offset;
}


static const value_string x2ap_E_RABs_Admitted_ToReleased_ModAckItem_vals[] = {
  {   0, "sCG-Bearer" },
  {   1, "split-Bearer" },
  { 0, NULL }
};

static const per_choice_t E_RABs_Admitted_ToReleased_ModAckItem_choice[] = {
  {   0, &hf_x2ap_sCG_Bearer_07  , ASN1_EXTENSION_ROOT    , dissect_x2ap_E_RABs_Admitted_ToBeReleased_ModAckItem_SCG_Bearer },
  {   1, &hf_x2ap_split_Bearer_07, ASN1_EXTENSION_ROOT    , dissect_x2ap_E_RABs_Admitted_ToBeReleased_ModAckItem_Split_Bearer },
  { 0, NULL, 0, NULL }
};

static int
dissect_x2ap_E_RABs_Admitted_ToReleased_ModAckItem(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_x2ap_E_RABs_Admitted_ToReleased_ModAckItem, E_RABs_Admitted_ToReleased_ModAckItem_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t SeNBModificationRequestReject_sequence[] = {
  { &hf_x2ap_protocolIEs    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_x2ap_ProtocolIE_Container },
  { NULL, 0, 0, NULL }
};

static int
dissect_x2ap_SeNBModificationRequestReject(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 543 "./asn1/x2ap/x2ap.cnf"
  col_append_sep_str(actx->pinfo->cinfo, COL_INFO, NULL, "SeNBModificationRequestReject");

  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_x2ap_SeNBModificationRequestReject, SeNBModificationRequestReject_sequence);

  return offset;
}


static const per_sequence_t SeNBModificationRequired_sequence[] = {
  { &hf_x2ap_protocolIEs    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_x2ap_ProtocolIE_Container },
  { NULL, 0, 0, NULL }
};

static int
dissect_x2ap_SeNBModificationRequired(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 545 "./asn1/x2ap/x2ap.cnf"
  col_append_sep_str(actx->pinfo->cinfo, COL_INFO, NULL, "SeNBModificationRequired");

  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_x2ap_SeNBModificationRequired, SeNBModificationRequired_sequence);

  return offset;
}


static const per_sequence_t E_RABs_ToBeReleased_ModReqd_sequence_of[1] = {
  { &hf_x2ap_E_RABs_ToBeReleased_ModReqd_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_x2ap_ProtocolIE_Single_Container },
};

static int
dissect_x2ap_E_RABs_ToBeReleased_ModReqd(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_x2ap_E_RABs_ToBeReleased_ModReqd, E_RABs_ToBeReleased_ModReqd_sequence_of,
                                                  1, maxnoofBearers, FALSE);

  return offset;
}


static const per_sequence_t E_RABs_ToBeReleased_ModReqdItem_sequence[] = {
  { &hf_x2ap_e_RAB_ID       , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_x2ap_E_RAB_ID },
  { &hf_x2ap_cause          , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_x2ap_Cause },
  { &hf_x2ap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_x2ap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_x2ap_E_RABs_ToBeReleased_ModReqdItem(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_x2ap_E_RABs_ToBeReleased_ModReqdItem, E_RABs_ToBeReleased_ModReqdItem_sequence);

  return offset;
}


static const per_sequence_t SeNBModificationConfirm_sequence[] = {
  { &hf_x2ap_protocolIEs    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_x2ap_ProtocolIE_Container },
  { NULL, 0, 0, NULL }
};

static int
dissect_x2ap_SeNBModificationConfirm(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 547 "./asn1/x2ap/x2ap.cnf"
  col_append_sep_str(actx->pinfo->cinfo, COL_INFO, NULL, "SeNBModificationConfirm");

  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_x2ap_SeNBModificationConfirm, SeNBModificationConfirm_sequence);

  return offset;
}


static const per_sequence_t SeNBModificationRefuse_sequence[] = {
  { &hf_x2ap_protocolIEs    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_x2ap_ProtocolIE_Container },
  { NULL, 0, 0, NULL }
};

static int
dissect_x2ap_SeNBModificationRefuse(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 549 "./asn1/x2ap/x2ap.cnf"
  col_append_sep_str(actx->pinfo->cinfo, COL_INFO, NULL, "SeNBModificationRefuse");

  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_x2ap_SeNBModificationRefuse, SeNBModificationRefuse_sequence);

  return offset;
}


static const per_sequence_t SeNBReleaseRequest_sequence[] = {
  { &hf_x2ap_protocolIEs    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_x2ap_ProtocolIE_Container },
  { NULL, 0, 0, NULL }
};

static int
dissect_x2ap_SeNBReleaseRequest(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 551 "./asn1/x2ap/x2ap.cnf"
  col_append_sep_str(actx->pinfo->cinfo, COL_INFO, NULL, "SeNBReleaseRequest");

  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_x2ap_SeNBReleaseRequest, SeNBReleaseRequest_sequence);

  return offset;
}


static const per_sequence_t E_RABs_ToBeReleased_List_RelReq_sequence_of[1] = {
  { &hf_x2ap_E_RABs_ToBeReleased_List_RelReq_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_x2ap_ProtocolIE_Single_Container },
};

static int
dissect_x2ap_E_RABs_ToBeReleased_List_RelReq(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_x2ap_E_RABs_ToBeReleased_List_RelReq, E_RABs_ToBeReleased_List_RelReq_sequence_of,
                                                  1, maxnoofBearers, FALSE);

  return offset;
}


static const per_sequence_t E_RABs_ToBeReleased_RelReqItem_SCG_Bearer_sequence[] = {
  { &hf_x2ap_e_RAB_ID       , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_x2ap_E_RAB_ID },
  { &hf_x2ap_uL_GTPtunnelEndpoint, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_x2ap_GTPtunnelEndpoint },
  { &hf_x2ap_dL_GTPtunnelEndpoint, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_x2ap_GTPtunnelEndpoint },
  { &hf_x2ap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_x2ap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_x2ap_E_RABs_ToBeReleased_RelReqItem_SCG_Bearer(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_x2ap_E_RABs_ToBeReleased_RelReqItem_SCG_Bearer, E_RABs_ToBeReleased_RelReqItem_SCG_Bearer_sequence);

  return offset;
}


static const per_sequence_t E_RABs_ToBeReleased_RelReqItem_Split_Bearer_sequence[] = {
  { &hf_x2ap_e_RAB_ID       , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_x2ap_E_RAB_ID },
  { &hf_x2ap_dL_GTPtunnelEndpoint, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_x2ap_GTPtunnelEndpoint },
  { &hf_x2ap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_x2ap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_x2ap_E_RABs_ToBeReleased_RelReqItem_Split_Bearer(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_x2ap_E_RABs_ToBeReleased_RelReqItem_Split_Bearer, E_RABs_ToBeReleased_RelReqItem_Split_Bearer_sequence);

  return offset;
}


static const value_string x2ap_E_RABs_ToBeReleased_RelReqItem_vals[] = {
  {   0, "sCG-Bearer" },
  {   1, "split-Bearer" },
  { 0, NULL }
};

static const per_choice_t E_RABs_ToBeReleased_RelReqItem_choice[] = {
  {   0, &hf_x2ap_sCG_Bearer_08  , ASN1_EXTENSION_ROOT    , dissect_x2ap_E_RABs_ToBeReleased_RelReqItem_SCG_Bearer },
  {   1, &hf_x2ap_split_Bearer_08, ASN1_EXTENSION_ROOT    , dissect_x2ap_E_RABs_ToBeReleased_RelReqItem_Split_Bearer },
  { 0, NULL, 0, NULL }
};

static int
dissect_x2ap_E_RABs_ToBeReleased_RelReqItem(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_x2ap_E_RABs_ToBeReleased_RelReqItem, E_RABs_ToBeReleased_RelReqItem_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t SeNBReleaseRequired_sequence[] = {
  { &hf_x2ap_protocolIEs    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_x2ap_ProtocolIE_Container },
  { NULL, 0, 0, NULL }
};

static int
dissect_x2ap_SeNBReleaseRequired(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 553 "./asn1/x2ap/x2ap.cnf"
  col_append_sep_str(actx->pinfo->cinfo, COL_INFO, NULL, "SeNBReleaseRequired");

  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_x2ap_SeNBReleaseRequired, SeNBReleaseRequired_sequence);

  return offset;
}


static const per_sequence_t SeNBReleaseConfirm_sequence[] = {
  { &hf_x2ap_protocolIEs    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_x2ap_ProtocolIE_Container },
  { NULL, 0, 0, NULL }
};

static int
dissect_x2ap_SeNBReleaseConfirm(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 555 "./asn1/x2ap/x2ap.cnf"
  col_append_sep_str(actx->pinfo->cinfo, COL_INFO, NULL, "SeNBReleaseConfirm");

  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_x2ap_SeNBReleaseConfirm, SeNBReleaseConfirm_sequence);

  return offset;
}


static const per_sequence_t E_RABs_ToBeReleased_List_RelConf_sequence_of[1] = {
  { &hf_x2ap_E_RABs_ToBeReleased_List_RelConf_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_x2ap_ProtocolIE_Single_Container },
};

static int
dissect_x2ap_E_RABs_ToBeReleased_List_RelConf(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_x2ap_E_RABs_ToBeReleased_List_RelConf, E_RABs_ToBeReleased_List_RelConf_sequence_of,
                                                  1, maxnoofBearers, FALSE);

  return offset;
}


static const per_sequence_t E_RABs_ToBeReleased_RelConfItem_SCG_Bearer_sequence[] = {
  { &hf_x2ap_e_RAB_ID       , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_x2ap_E_RAB_ID },
  { &hf_x2ap_uL_GTPtunnelEndpoint, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_x2ap_GTPtunnelEndpoint },
  { &hf_x2ap_dL_GTPtunnelEndpoint, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_x2ap_GTPtunnelEndpoint },
  { &hf_x2ap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_x2ap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_x2ap_E_RABs_ToBeReleased_RelConfItem_SCG_Bearer(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_x2ap_E_RABs_ToBeReleased_RelConfItem_SCG_Bearer, E_RABs_ToBeReleased_RelConfItem_SCG_Bearer_sequence);

  return offset;
}


static const per_sequence_t E_RABs_ToBeReleased_RelConfItem_Split_Bearer_sequence[] = {
  { &hf_x2ap_e_RAB_ID       , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_x2ap_E_RAB_ID },
  { &hf_x2ap_dL_GTPtunnelEndpoint, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_x2ap_GTPtunnelEndpoint },
  { &hf_x2ap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_x2ap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_x2ap_E_RABs_ToBeReleased_RelConfItem_Split_Bearer(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_x2ap_E_RABs_ToBeReleased_RelConfItem_Split_Bearer, E_RABs_ToBeReleased_RelConfItem_Split_Bearer_sequence);

  return offset;
}


static const value_string x2ap_E_RABs_ToBeReleased_RelConfItem_vals[] = {
  {   0, "sCG-Bearer" },
  {   1, "split-Bearer" },
  { 0, NULL }
};

static const per_choice_t E_RABs_ToBeReleased_RelConfItem_choice[] = {
  {   0, &hf_x2ap_sCG_Bearer_09  , ASN1_EXTENSION_ROOT    , dissect_x2ap_E_RABs_ToBeReleased_RelConfItem_SCG_Bearer },
  {   1, &hf_x2ap_split_Bearer_09, ASN1_EXTENSION_ROOT    , dissect_x2ap_E_RABs_ToBeReleased_RelConfItem_Split_Bearer },
  { 0, NULL, 0, NULL }
};

static int
dissect_x2ap_E_RABs_ToBeReleased_RelConfItem(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_x2ap_E_RABs_ToBeReleased_RelConfItem, E_RABs_ToBeReleased_RelConfItem_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t SeNBCounterCheckRequest_sequence[] = {
  { &hf_x2ap_protocolIEs    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_x2ap_ProtocolIE_Container },
  { NULL, 0, 0, NULL }
};

static int
dissect_x2ap_SeNBCounterCheckRequest(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 557 "./asn1/x2ap/x2ap.cnf"
  col_append_sep_str(actx->pinfo->cinfo, COL_INFO, NULL, "SeNBCounterCheckRequest");

  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_x2ap_SeNBCounterCheckRequest, SeNBCounterCheckRequest_sequence);

  return offset;
}


static const per_sequence_t E_RABs_SubjectToCounterCheck_List_sequence_of[1] = {
  { &hf_x2ap_E_RABs_SubjectToCounterCheck_List_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_x2ap_ProtocolIE_Single_Container },
};

static int
dissect_x2ap_E_RABs_SubjectToCounterCheck_List(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_x2ap_E_RABs_SubjectToCounterCheck_List, E_RABs_SubjectToCounterCheck_List_sequence_of,
                                                  1, maxnoofBearers, FALSE);

  return offset;
}



static int
dissect_x2ap_INTEGER_0_4294967295(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 4294967295U, NULL, FALSE);

  return offset;
}


static const per_sequence_t E_RABs_SubjectToCounterCheckItem_sequence[] = {
  { &hf_x2ap_e_RAB_ID       , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_x2ap_E_RAB_ID },
  { &hf_x2ap_uL_Count       , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_x2ap_INTEGER_0_4294967295 },
  { &hf_x2ap_dL_Count       , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_x2ap_INTEGER_0_4294967295 },
  { &hf_x2ap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_x2ap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_x2ap_E_RABs_SubjectToCounterCheckItem(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_x2ap_E_RABs_SubjectToCounterCheckItem, E_RABs_SubjectToCounterCheckItem_sequence);

  return offset;
}


static const per_sequence_t X2RemovalRequest_sequence[] = {
  { &hf_x2ap_protocolIEs    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_x2ap_ProtocolIE_Container },
  { NULL, 0, 0, NULL }
};

static int
dissect_x2ap_X2RemovalRequest(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 525 "./asn1/x2ap/x2ap.cnf"
  col_append_sep_str(actx->pinfo->cinfo, COL_INFO, NULL, "X2RemovalRequest");

  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_x2ap_X2RemovalRequest, X2RemovalRequest_sequence);

  return offset;
}


static const per_sequence_t X2RemovalResponse_sequence[] = {
  { &hf_x2ap_protocolIEs    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_x2ap_ProtocolIE_Container },
  { NULL, 0, 0, NULL }
};

static int
dissect_x2ap_X2RemovalResponse(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 527 "./asn1/x2ap/x2ap.cnf"
  col_append_sep_str(actx->pinfo->cinfo, COL_INFO, NULL, "X2RemovalResponse");

  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_x2ap_X2RemovalResponse, X2RemovalResponse_sequence);

  return offset;
}


static const per_sequence_t X2RemovalFailure_sequence[] = {
  { &hf_x2ap_protocolIEs    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_x2ap_ProtocolIE_Container },
  { NULL, 0, 0, NULL }
};

static int
dissect_x2ap_X2RemovalFailure(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 529 "./asn1/x2ap/x2ap.cnf"
  col_append_sep_str(actx->pinfo->cinfo, COL_INFO, NULL, "X2RemovalFailure");

  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_x2ap_X2RemovalFailure, X2RemovalFailure_sequence);

  return offset;
}


static const per_sequence_t RetrieveUEContextRequest_sequence[] = {
  { &hf_x2ap_protocolIEs    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_x2ap_ProtocolIE_Container },
  { NULL, 0, 0, NULL }
};

static int
dissect_x2ap_RetrieveUEContextRequest(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 559 "./asn1/x2ap/x2ap.cnf"
  col_append_sep_str(actx->pinfo->cinfo, COL_INFO, NULL, "RetrieveUEContextRequest");

  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_x2ap_RetrieveUEContextRequest, RetrieveUEContextRequest_sequence);

  return offset;
}


static const per_sequence_t RetrieveUEContextResponse_sequence[] = {
  { &hf_x2ap_protocolIEs    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_x2ap_ProtocolIE_Container },
  { NULL, 0, 0, NULL }
};

static int
dissect_x2ap_RetrieveUEContextResponse(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 561 "./asn1/x2ap/x2ap.cnf"
  col_append_sep_str(actx->pinfo->cinfo, COL_INFO, NULL, "RetrieveUEContextResponse");

  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_x2ap_RetrieveUEContextResponse, RetrieveUEContextResponse_sequence);

  return offset;
}


static const per_sequence_t E_RABs_ToBeSetup_ListRetrieve_sequence_of[1] = {
  { &hf_x2ap_E_RABs_ToBeSetup_ListRetrieve_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_x2ap_ProtocolIE_Single_Container },
};

static int
dissect_x2ap_E_RABs_ToBeSetup_ListRetrieve(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_x2ap_E_RABs_ToBeSetup_ListRetrieve, E_RABs_ToBeSetup_ListRetrieve_sequence_of,
                                                  1, maxnoofBearers, FALSE);

  return offset;
}


static const per_sequence_t UE_ContextInformationRetrieve_sequence[] = {
  { &hf_x2ap_mME_UE_S1AP_ID , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_x2ap_UE_S1AP_ID },
  { &hf_x2ap_uESecurityCapabilities, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_x2ap_UESecurityCapabilities },
  { &hf_x2ap_aS_SecurityInformation, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_x2ap_AS_SecurityInformation },
  { &hf_x2ap_uEaggregateMaximumBitRate, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_x2ap_UEAggregateMaximumBitRate },
  { &hf_x2ap_subscriberProfileIDforRFP, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_x2ap_SubscriberProfileIDforRFP },
  { &hf_x2ap_e_RABs_ToBeSetup_ListRetrieve, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_x2ap_E_RABs_ToBeSetup_ListRetrieve },
  { &hf_x2ap_rRC_Context    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_x2ap_RRC_Context },
  { &hf_x2ap_handoverRestrictionList, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_x2ap_HandoverRestrictionList },
  { &hf_x2ap_locationReportingInformation, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_x2ap_LocationReportingInformation },
  { &hf_x2ap_managBasedMDTallowed, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_x2ap_ManagementBasedMDTallowed },
  { &hf_x2ap_managBasedMDTPLMNList, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_x2ap_MDTPLMNList },
  { &hf_x2ap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_x2ap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_x2ap_UE_ContextInformationRetrieve(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_x2ap_UE_ContextInformationRetrieve, UE_ContextInformationRetrieve_sequence);

  return offset;
}


static const per_sequence_t E_RABs_ToBeSetupRetrieve_Item_sequence[] = {
  { &hf_x2ap_e_RAB_ID       , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_x2ap_E_RAB_ID },
  { &hf_x2ap_e_RAB_Level_QoS_Parameters, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_x2ap_E_RAB_Level_QoS_Parameters },
  { &hf_x2ap_bearerType     , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_x2ap_BearerType },
  { &hf_x2ap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_x2ap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_x2ap_E_RABs_ToBeSetupRetrieve_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_x2ap_E_RABs_ToBeSetupRetrieve_Item, E_RABs_ToBeSetupRetrieve_Item_sequence);

  return offset;
}


static const per_sequence_t RetrieveUEContextFailure_sequence[] = {
  { &hf_x2ap_protocolIEs    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_x2ap_ProtocolIE_Container },
  { NULL, 0, 0, NULL }
};

static int
dissect_x2ap_RetrieveUEContextFailure(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 563 "./asn1/x2ap/x2ap.cnf"
  col_append_sep_str(actx->pinfo->cinfo, COL_INFO, NULL, "RetrieveUEContextFailure");


  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_x2ap_RetrieveUEContextFailure, RetrieveUEContextFailure_sequence);

  return offset;
}



static int
dissect_x2ap_InitiatingMessage_value(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_open_type_pdu_new(tvb, offset, actx, tree, hf_index, dissect_InitiatingMessageValue);

  return offset;
}


static const per_sequence_t InitiatingMessage_sequence[] = {
  { &hf_x2ap_procedureCode  , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_x2ap_ProcedureCode },
  { &hf_x2ap_criticality    , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_x2ap_Criticality },
  { &hf_x2ap_initiatingMessage_value, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_x2ap_InitiatingMessage_value },
  { NULL, 0, 0, NULL }
};

static int
dissect_x2ap_InitiatingMessage(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_x2ap_InitiatingMessage, InitiatingMessage_sequence);

  return offset;
}



static int
dissect_x2ap_SuccessfulOutcome_value(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_open_type_pdu_new(tvb, offset, actx, tree, hf_index, dissect_SuccessfulOutcomeValue);

  return offset;
}


static const per_sequence_t SuccessfulOutcome_sequence[] = {
  { &hf_x2ap_procedureCode  , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_x2ap_ProcedureCode },
  { &hf_x2ap_criticality    , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_x2ap_Criticality },
  { &hf_x2ap_successfulOutcome_value, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_x2ap_SuccessfulOutcome_value },
  { NULL, 0, 0, NULL }
};

static int
dissect_x2ap_SuccessfulOutcome(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_x2ap_SuccessfulOutcome, SuccessfulOutcome_sequence);

  return offset;
}



static int
dissect_x2ap_UnsuccessfulOutcome_value(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_open_type_pdu_new(tvb, offset, actx, tree, hf_index, dissect_UnsuccessfulOutcomeValue);

  return offset;
}


static const per_sequence_t UnsuccessfulOutcome_sequence[] = {
  { &hf_x2ap_procedureCode  , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_x2ap_ProcedureCode },
  { &hf_x2ap_criticality    , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_x2ap_Criticality },
  { &hf_x2ap_value          , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_x2ap_UnsuccessfulOutcome_value },
  { NULL, 0, 0, NULL }
};

static int
dissect_x2ap_UnsuccessfulOutcome(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_x2ap_UnsuccessfulOutcome, UnsuccessfulOutcome_sequence);

  return offset;
}


static const value_string x2ap_X2AP_PDU_vals[] = {
  {   0, "initiatingMessage" },
  {   1, "successfulOutcome" },
  {   2, "unsuccessfulOutcome" },
  { 0, NULL }
};

static const per_choice_t X2AP_PDU_choice[] = {
  {   0, &hf_x2ap_initiatingMessage, ASN1_EXTENSION_ROOT    , dissect_x2ap_InitiatingMessage },
  {   1, &hf_x2ap_successfulOutcome, ASN1_EXTENSION_ROOT    , dissect_x2ap_SuccessfulOutcome },
  {   2, &hf_x2ap_unsuccessfulOutcome, ASN1_EXTENSION_ROOT    , dissect_x2ap_UnsuccessfulOutcome },
  { 0, NULL, 0, NULL }
};

static int
dissect_x2ap_X2AP_PDU(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_x2ap_X2AP_PDU, X2AP_PDU_choice,
                                 NULL);

  return offset;
}

/*--- PDUs ---*/

static int dissect_ABSInformation_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_x2ap_ABSInformation(tvb, offset, &asn1_ctx, tree, hf_x2ap_ABSInformation_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_ABS_Status_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_x2ap_ABS_Status(tvb, offset, &asn1_ctx, tree, hf_x2ap_ABS_Status_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_AdditionalSpecialSubframe_Info_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_x2ap_AdditionalSpecialSubframe_Info(tvb, offset, &asn1_ctx, tree, hf_x2ap_AdditionalSpecialSubframe_Info_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_BearerType_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_x2ap_BearerType(tvb, offset, &asn1_ctx, tree, hf_x2ap_BearerType_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_Cause_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_x2ap_Cause(tvb, offset, &asn1_ctx, tree, hf_x2ap_Cause_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_CellReportingIndicator_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_x2ap_CellReportingIndicator(tvb, offset, &asn1_ctx, tree, hf_x2ap_CellReportingIndicator_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_CoMPInformation_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_x2ap_CoMPInformation(tvb, offset, &asn1_ctx, tree, hf_x2ap_CoMPInformation_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_CompositeAvailableCapacityGroup_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_x2ap_CompositeAvailableCapacityGroup(tvb, offset, &asn1_ctx, tree, hf_x2ap_CompositeAvailableCapacityGroup_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_Correlation_ID_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_x2ap_Correlation_ID(tvb, offset, &asn1_ctx, tree, hf_x2ap_Correlation_ID_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_COUNTValueExtended_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_x2ap_COUNTValueExtended(tvb, offset, &asn1_ctx, tree, hf_x2ap_COUNTValueExtended_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_COUNTvaluePDCP_SNlength18_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_x2ap_COUNTvaluePDCP_SNlength18(tvb, offset, &asn1_ctx, tree, hf_x2ap_COUNTvaluePDCP_SNlength18_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_CoverageModificationList_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_x2ap_CoverageModificationList(tvb, offset, &asn1_ctx, tree, hf_x2ap_CoverageModificationList_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_CriticalityDiagnostics_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_x2ap_CriticalityDiagnostics(tvb, offset, &asn1_ctx, tree, hf_x2ap_CriticalityDiagnostics_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_CRNTI_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_x2ap_CRNTI(tvb, offset, &asn1_ctx, tree, hf_x2ap_CRNTI_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_CSGMembershipStatus_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_x2ap_CSGMembershipStatus(tvb, offset, &asn1_ctx, tree, hf_x2ap_CSGMembershipStatus_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_CSG_Id_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_x2ap_CSG_Id(tvb, offset, &asn1_ctx, tree, hf_x2ap_CSG_Id_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_CSIReportList_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_x2ap_CSIReportList(tvb, offset, &asn1_ctx, tree, hf_x2ap_CSIReportList_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_DeactivationIndication_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_x2ap_DeactivationIndication(tvb, offset, &asn1_ctx, tree, hf_x2ap_DeactivationIndication_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_DynamicDLTransmissionInformation_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_x2ap_DynamicDLTransmissionInformation(tvb, offset, &asn1_ctx, tree, hf_x2ap_DynamicDLTransmissionInformation_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_EARFCNExtension_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_x2ap_EARFCNExtension(tvb, offset, &asn1_ctx, tree, hf_x2ap_EARFCNExtension_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_ECGI_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_x2ap_ECGI(tvb, offset, &asn1_ctx, tree, hf_x2ap_ECGI_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_EnhancedRNTP_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_x2ap_EnhancedRNTP(tvb, offset, &asn1_ctx, tree, hf_x2ap_EnhancedRNTP_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_E_RAB_List_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_x2ap_E_RAB_List(tvb, offset, &asn1_ctx, tree, hf_x2ap_E_RAB_List_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_E_RAB_Item_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_x2ap_E_RAB_Item(tvb, offset, &asn1_ctx, tree, hf_x2ap_E_RAB_Item_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_EUTRANCellIdentifier_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_x2ap_EUTRANCellIdentifier(tvb, offset, &asn1_ctx, tree, hf_x2ap_EUTRANCellIdentifier_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_ExpectedUEBehaviour_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_x2ap_ExpectedUEBehaviour(tvb, offset, &asn1_ctx, tree, hf_x2ap_ExpectedUEBehaviour_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_ExtendedULInterferenceOverloadInfo_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_x2ap_ExtendedULInterferenceOverloadInfo(tvb, offset, &asn1_ctx, tree, hf_x2ap_ExtendedULInterferenceOverloadInfo_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_FreqBandIndicatorPriority_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_x2ap_FreqBandIndicatorPriority(tvb, offset, &asn1_ctx, tree, hf_x2ap_FreqBandIndicatorPriority_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_GlobalENB_ID_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_x2ap_GlobalENB_ID(tvb, offset, &asn1_ctx, tree, hf_x2ap_GlobalENB_ID_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_GUGroupIDList_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_x2ap_GUGroupIDList(tvb, offset, &asn1_ctx, tree, hf_x2ap_GUGroupIDList_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_GUMMEI_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_x2ap_GUMMEI(tvb, offset, &asn1_ctx, tree, hf_x2ap_GUMMEI_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_HandoverReportType_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_x2ap_HandoverReportType(tvb, offset, &asn1_ctx, tree, hf_x2ap_HandoverReportType_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_InvokeIndication_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_x2ap_InvokeIndication(tvb, offset, &asn1_ctx, tree, hf_x2ap_InvokeIndication_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_LHN_ID_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_x2ap_LHN_ID(tvb, offset, &asn1_ctx, tree, hf_x2ap_LHN_ID_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_M3Configuration_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_x2ap_M3Configuration(tvb, offset, &asn1_ctx, tree, hf_x2ap_M3Configuration_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_M4Configuration_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_x2ap_M4Configuration(tvb, offset, &asn1_ctx, tree, hf_x2ap_M4Configuration_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_M5Configuration_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_x2ap_M5Configuration(tvb, offset, &asn1_ctx, tree, hf_x2ap_M5Configuration_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_M6Configuration_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_x2ap_M6Configuration(tvb, offset, &asn1_ctx, tree, hf_x2ap_M6Configuration_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_M7Configuration_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_x2ap_M7Configuration(tvb, offset, &asn1_ctx, tree, hf_x2ap_M7Configuration_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_ManagementBasedMDTallowed_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_x2ap_ManagementBasedMDTallowed(tvb, offset, &asn1_ctx, tree, hf_x2ap_ManagementBasedMDTallowed_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_Masked_IMEISV_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_x2ap_Masked_IMEISV(tvb, offset, &asn1_ctx, tree, hf_x2ap_Masked_IMEISV_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_MDT_Configuration_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_x2ap_MDT_Configuration(tvb, offset, &asn1_ctx, tree, hf_x2ap_MDT_Configuration_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_MDTPLMNList_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_x2ap_MDTPLMNList(tvb, offset, &asn1_ctx, tree, hf_x2ap_MDTPLMNList_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_MDT_Location_Info_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_x2ap_MDT_Location_Info(tvb, offset, &asn1_ctx, tree, hf_x2ap_MDT_Location_Info_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_Measurement_ID_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_x2ap_Measurement_ID(tvb, offset, &asn1_ctx, tree, hf_x2ap_Measurement_ID_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_MeNBtoSeNBContainer_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_x2ap_MeNBtoSeNBContainer(tvb, offset, &asn1_ctx, tree, hf_x2ap_MeNBtoSeNBContainer_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_MBMS_Service_Area_Identity_List_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_x2ap_MBMS_Service_Area_Identity_List(tvb, offset, &asn1_ctx, tree, hf_x2ap_MBMS_Service_Area_Identity_List_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_MBSFN_Subframe_Infolist_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_x2ap_MBSFN_Subframe_Infolist(tvb, offset, &asn1_ctx, tree, hf_x2ap_MBSFN_Subframe_Infolist_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_MobilityParametersModificationRange_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_x2ap_MobilityParametersModificationRange(tvb, offset, &asn1_ctx, tree, hf_x2ap_MobilityParametersModificationRange_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_MobilityParametersInformation_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_x2ap_MobilityParametersInformation(tvb, offset, &asn1_ctx, tree, hf_x2ap_MobilityParametersInformation_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_MultibandInfoList_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_x2ap_MultibandInfoList(tvb, offset, &asn1_ctx, tree, hf_x2ap_MultibandInfoList_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_Number_of_Antennaports_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_x2ap_Number_of_Antennaports(tvb, offset, &asn1_ctx, tree, hf_x2ap_Number_of_Antennaports_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_OffsetOfNbiotChannelNumberToEARFCN_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_x2ap_OffsetOfNbiotChannelNumberToEARFCN(tvb, offset, &asn1_ctx, tree, hf_x2ap_OffsetOfNbiotChannelNumberToEARFCN_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_PCI_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_x2ap_PCI(tvb, offset, &asn1_ctx, tree, hf_x2ap_PCI_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_PLMN_Identity_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_x2ap_PLMN_Identity(tvb, offset, &asn1_ctx, tree, hf_x2ap_PLMN_Identity_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_PRACH_Configuration_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_x2ap_PRACH_Configuration(tvb, offset, &asn1_ctx, tree, hf_x2ap_PRACH_Configuration_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_ProSeAuthorized_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_x2ap_ProSeAuthorized(tvb, offset, &asn1_ctx, tree, hf_x2ap_ProSeAuthorized_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_ProSeUEtoNetworkRelaying_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_x2ap_ProSeUEtoNetworkRelaying(tvb, offset, &asn1_ctx, tree, hf_x2ap_ProSeUEtoNetworkRelaying_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_ReceiveStatusOfULPDCPSDUsExtended_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_x2ap_ReceiveStatusOfULPDCPSDUsExtended(tvb, offset, &asn1_ctx, tree, hf_x2ap_ReceiveStatusOfULPDCPSDUsExtended_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_ReceiveStatusOfULPDCPSDUsPDCP_SNlength18_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_x2ap_ReceiveStatusOfULPDCPSDUsPDCP_SNlength18(tvb, offset, &asn1_ctx, tree, hf_x2ap_ReceiveStatusOfULPDCPSDUsPDCP_SNlength18_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_Registration_Request_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_x2ap_Registration_Request(tvb, offset, &asn1_ctx, tree, hf_x2ap_Registration_Request_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_ReportCharacteristics_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_x2ap_ReportCharacteristics(tvb, offset, &asn1_ctx, tree, hf_x2ap_ReportCharacteristics_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_ReportingPeriodicityCSIR_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_x2ap_ReportingPeriodicityCSIR(tvb, offset, &asn1_ctx, tree, hf_x2ap_ReportingPeriodicityCSIR_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_ReportingPeriodicityRSRPMR_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_x2ap_ReportingPeriodicityRSRPMR(tvb, offset, &asn1_ctx, tree, hf_x2ap_ReportingPeriodicityRSRPMR_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_ResumeID_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_x2ap_ResumeID(tvb, offset, &asn1_ctx, tree, hf_x2ap_ResumeID_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_RRCConnReestabIndicator_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_x2ap_RRCConnReestabIndicator(tvb, offset, &asn1_ctx, tree, hf_x2ap_RRCConnReestabIndicator_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_RRCConnSetupIndicator_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_x2ap_RRCConnSetupIndicator(tvb, offset, &asn1_ctx, tree, hf_x2ap_RRCConnSetupIndicator_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_RSRPMRList_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_x2ap_RSRPMRList(tvb, offset, &asn1_ctx, tree, hf_x2ap_RSRPMRList_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_SCGChangeIndication_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_x2ap_SCGChangeIndication(tvb, offset, &asn1_ctx, tree, hf_x2ap_SCGChangeIndication_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_SeNBSecurityKey_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_x2ap_SeNBSecurityKey(tvb, offset, &asn1_ctx, tree, hf_x2ap_SeNBSecurityKey_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_SeNBtoMeNBContainer_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_x2ap_SeNBtoMeNBContainer(tvb, offset, &asn1_ctx, tree, hf_x2ap_SeNBtoMeNBContainer_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_ServedCells_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_x2ap_ServedCells(tvb, offset, &asn1_ctx, tree, hf_x2ap_ServedCells_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_SIPTOBearerDeactivationIndication_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_x2ap_SIPTOBearerDeactivationIndication(tvb, offset, &asn1_ctx, tree, hf_x2ap_SIPTOBearerDeactivationIndication_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_ShortMAC_I_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_x2ap_ShortMAC_I(tvb, offset, &asn1_ctx, tree, hf_x2ap_ShortMAC_I_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_SRVCCOperationPossible_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_x2ap_SRVCCOperationPossible(tvb, offset, &asn1_ctx, tree, hf_x2ap_SRVCCOperationPossible_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_SubframeAssignment_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_x2ap_SubframeAssignment(tvb, offset, &asn1_ctx, tree, hf_x2ap_SubframeAssignment_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_TAC_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_x2ap_TAC(tvb, offset, &asn1_ctx, tree, hf_x2ap_TAC_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_TargetCellInUTRAN_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_x2ap_TargetCellInUTRAN(tvb, offset, &asn1_ctx, tree, hf_x2ap_TargetCellInUTRAN_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_TargeteNBtoSource_eNBTransparentContainer_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_x2ap_TargeteNBtoSource_eNBTransparentContainer(tvb, offset, &asn1_ctx, tree, hf_x2ap_TargeteNBtoSource_eNBTransparentContainer_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_TimeToWait_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_x2ap_TimeToWait(tvb, offset, &asn1_ctx, tree, hf_x2ap_TimeToWait_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_Time_UE_StayedInCell_EnhancedGranularity_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_x2ap_Time_UE_StayedInCell_EnhancedGranularity(tvb, offset, &asn1_ctx, tree, hf_x2ap_Time_UE_StayedInCell_EnhancedGranularity_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_TraceActivation_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_x2ap_TraceActivation(tvb, offset, &asn1_ctx, tree, hf_x2ap_TraceActivation_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_TransportLayerAddress_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_x2ap_TransportLayerAddress(tvb, offset, &asn1_ctx, tree, hf_x2ap_TransportLayerAddress_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_TunnelInformation_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_x2ap_TunnelInformation(tvb, offset, &asn1_ctx, tree, hf_x2ap_TunnelInformation_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_UEAggregateMaximumBitRate_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_x2ap_UEAggregateMaximumBitRate(tvb, offset, &asn1_ctx, tree, hf_x2ap_UEAggregateMaximumBitRate_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_UE_ContextKeptIndicator_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_x2ap_UE_ContextKeptIndicator(tvb, offset, &asn1_ctx, tree, hf_x2ap_UE_ContextKeptIndicator_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_UEID_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_x2ap_UEID(tvb, offset, &asn1_ctx, tree, hf_x2ap_UEID_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_UE_HistoryInformation_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_x2ap_UE_HistoryInformation(tvb, offset, &asn1_ctx, tree, hf_x2ap_UE_HistoryInformation_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_UE_HistoryInformationFromTheUE_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_x2ap_UE_HistoryInformationFromTheUE(tvb, offset, &asn1_ctx, tree, hf_x2ap_UE_HistoryInformationFromTheUE_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_UE_X2AP_ID_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_x2ap_UE_X2AP_ID(tvb, offset, &asn1_ctx, tree, hf_x2ap_UE_X2AP_ID_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_UE_X2AP_ID_Extension_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_x2ap_UE_X2AP_ID_Extension(tvb, offset, &asn1_ctx, tree, hf_x2ap_UE_X2AP_ID_Extension_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_UE_RLF_Report_Container_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_x2ap_UE_RLF_Report_Container(tvb, offset, &asn1_ctx, tree, hf_x2ap_UE_RLF_Report_Container_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_UE_RLF_Report_Container_for_extended_bands_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_x2ap_UE_RLF_Report_Container_for_extended_bands(tvb, offset, &asn1_ctx, tree, hf_x2ap_UE_RLF_Report_Container_for_extended_bands_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_UESecurityCapabilities_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_x2ap_UESecurityCapabilities(tvb, offset, &asn1_ctx, tree, hf_x2ap_UESecurityCapabilities_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_X2BenefitValue_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_x2ap_X2BenefitValue(tvb, offset, &asn1_ctx, tree, hf_x2ap_X2BenefitValue_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_HandoverRequest_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_x2ap_HandoverRequest(tvb, offset, &asn1_ctx, tree, hf_x2ap_HandoverRequest_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_UE_ContextInformation_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_x2ap_UE_ContextInformation(tvb, offset, &asn1_ctx, tree, hf_x2ap_UE_ContextInformation_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_E_RABs_ToBeSetup_Item_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_x2ap_E_RABs_ToBeSetup_Item(tvb, offset, &asn1_ctx, tree, hf_x2ap_E_RABs_ToBeSetup_Item_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_MobilityInformation_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_x2ap_MobilityInformation(tvb, offset, &asn1_ctx, tree, hf_x2ap_MobilityInformation_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_UE_ContextReferenceAtSeNB_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_x2ap_UE_ContextReferenceAtSeNB(tvb, offset, &asn1_ctx, tree, hf_x2ap_UE_ContextReferenceAtSeNB_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_HandoverRequestAcknowledge_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_x2ap_HandoverRequestAcknowledge(tvb, offset, &asn1_ctx, tree, hf_x2ap_HandoverRequestAcknowledge_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_E_RABs_Admitted_List_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_x2ap_E_RABs_Admitted_List(tvb, offset, &asn1_ctx, tree, hf_x2ap_E_RABs_Admitted_List_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_E_RABs_Admitted_Item_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_x2ap_E_RABs_Admitted_Item(tvb, offset, &asn1_ctx, tree, hf_x2ap_E_RABs_Admitted_Item_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_HandoverPreparationFailure_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_x2ap_HandoverPreparationFailure(tvb, offset, &asn1_ctx, tree, hf_x2ap_HandoverPreparationFailure_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_HandoverReport_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_x2ap_HandoverReport(tvb, offset, &asn1_ctx, tree, hf_x2ap_HandoverReport_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_SNStatusTransfer_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_x2ap_SNStatusTransfer(tvb, offset, &asn1_ctx, tree, hf_x2ap_SNStatusTransfer_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_E_RABs_SubjectToStatusTransfer_List_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_x2ap_E_RABs_SubjectToStatusTransfer_List(tvb, offset, &asn1_ctx, tree, hf_x2ap_E_RABs_SubjectToStatusTransfer_List_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_E_RABs_SubjectToStatusTransfer_Item_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_x2ap_E_RABs_SubjectToStatusTransfer_Item(tvb, offset, &asn1_ctx, tree, hf_x2ap_E_RABs_SubjectToStatusTransfer_Item_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_UEContextRelease_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_x2ap_UEContextRelease(tvb, offset, &asn1_ctx, tree, hf_x2ap_UEContextRelease_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_HandoverCancel_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_x2ap_HandoverCancel(tvb, offset, &asn1_ctx, tree, hf_x2ap_HandoverCancel_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_ErrorIndication_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_x2ap_ErrorIndication(tvb, offset, &asn1_ctx, tree, hf_x2ap_ErrorIndication_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_ResetRequest_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_x2ap_ResetRequest(tvb, offset, &asn1_ctx, tree, hf_x2ap_ResetRequest_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_ResetResponse_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_x2ap_ResetResponse(tvb, offset, &asn1_ctx, tree, hf_x2ap_ResetResponse_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_X2SetupRequest_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_x2ap_X2SetupRequest(tvb, offset, &asn1_ctx, tree, hf_x2ap_X2SetupRequest_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_X2SetupResponse_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_x2ap_X2SetupResponse(tvb, offset, &asn1_ctx, tree, hf_x2ap_X2SetupResponse_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_X2SetupFailure_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_x2ap_X2SetupFailure(tvb, offset, &asn1_ctx, tree, hf_x2ap_X2SetupFailure_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_LoadInformation_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_x2ap_LoadInformation(tvb, offset, &asn1_ctx, tree, hf_x2ap_LoadInformation_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_CellInformation_List_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_x2ap_CellInformation_List(tvb, offset, &asn1_ctx, tree, hf_x2ap_CellInformation_List_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_CellInformation_Item_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_x2ap_CellInformation_Item(tvb, offset, &asn1_ctx, tree, hf_x2ap_CellInformation_Item_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_ENBConfigurationUpdate_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_x2ap_ENBConfigurationUpdate(tvb, offset, &asn1_ctx, tree, hf_x2ap_ENBConfigurationUpdate_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_ServedCellsToModify_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_x2ap_ServedCellsToModify(tvb, offset, &asn1_ctx, tree, hf_x2ap_ServedCellsToModify_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_Old_ECGIs_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_x2ap_Old_ECGIs(tvb, offset, &asn1_ctx, tree, hf_x2ap_Old_ECGIs_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_ENBConfigurationUpdateAcknowledge_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_x2ap_ENBConfigurationUpdateAcknowledge(tvb, offset, &asn1_ctx, tree, hf_x2ap_ENBConfigurationUpdateAcknowledge_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_ENBConfigurationUpdateFailure_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_x2ap_ENBConfigurationUpdateFailure(tvb, offset, &asn1_ctx, tree, hf_x2ap_ENBConfigurationUpdateFailure_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_ResourceStatusRequest_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_x2ap_ResourceStatusRequest(tvb, offset, &asn1_ctx, tree, hf_x2ap_ResourceStatusRequest_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_CellToReport_List_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_x2ap_CellToReport_List(tvb, offset, &asn1_ctx, tree, hf_x2ap_CellToReport_List_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_CellToReport_Item_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_x2ap_CellToReport_Item(tvb, offset, &asn1_ctx, tree, hf_x2ap_CellToReport_Item_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_ReportingPeriodicity_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_x2ap_ReportingPeriodicity(tvb, offset, &asn1_ctx, tree, hf_x2ap_ReportingPeriodicity_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_PartialSuccessIndicator_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_x2ap_PartialSuccessIndicator(tvb, offset, &asn1_ctx, tree, hf_x2ap_PartialSuccessIndicator_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_ResourceStatusResponse_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_x2ap_ResourceStatusResponse(tvb, offset, &asn1_ctx, tree, hf_x2ap_ResourceStatusResponse_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_MeasurementInitiationResult_List_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_x2ap_MeasurementInitiationResult_List(tvb, offset, &asn1_ctx, tree, hf_x2ap_MeasurementInitiationResult_List_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_MeasurementInitiationResult_Item_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_x2ap_MeasurementInitiationResult_Item(tvb, offset, &asn1_ctx, tree, hf_x2ap_MeasurementInitiationResult_Item_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_MeasurementFailureCause_Item_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_x2ap_MeasurementFailureCause_Item(tvb, offset, &asn1_ctx, tree, hf_x2ap_MeasurementFailureCause_Item_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_ResourceStatusFailure_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_x2ap_ResourceStatusFailure(tvb, offset, &asn1_ctx, tree, hf_x2ap_ResourceStatusFailure_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_CompleteFailureCauseInformation_List_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_x2ap_CompleteFailureCauseInformation_List(tvb, offset, &asn1_ctx, tree, hf_x2ap_CompleteFailureCauseInformation_List_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_CompleteFailureCauseInformation_Item_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_x2ap_CompleteFailureCauseInformation_Item(tvb, offset, &asn1_ctx, tree, hf_x2ap_CompleteFailureCauseInformation_Item_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_ResourceStatusUpdate_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_x2ap_ResourceStatusUpdate(tvb, offset, &asn1_ctx, tree, hf_x2ap_ResourceStatusUpdate_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_CellMeasurementResult_List_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_x2ap_CellMeasurementResult_List(tvb, offset, &asn1_ctx, tree, hf_x2ap_CellMeasurementResult_List_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_CellMeasurementResult_Item_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_x2ap_CellMeasurementResult_Item(tvb, offset, &asn1_ctx, tree, hf_x2ap_CellMeasurementResult_Item_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_PrivateMessage_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_x2ap_PrivateMessage(tvb, offset, &asn1_ctx, tree, hf_x2ap_PrivateMessage_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_MobilityChangeRequest_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_x2ap_MobilityChangeRequest(tvb, offset, &asn1_ctx, tree, hf_x2ap_MobilityChangeRequest_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_MobilityChangeAcknowledge_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_x2ap_MobilityChangeAcknowledge(tvb, offset, &asn1_ctx, tree, hf_x2ap_MobilityChangeAcknowledge_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_MobilityChangeFailure_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_x2ap_MobilityChangeFailure(tvb, offset, &asn1_ctx, tree, hf_x2ap_MobilityChangeFailure_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_RLFIndication_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_x2ap_RLFIndication(tvb, offset, &asn1_ctx, tree, hf_x2ap_RLFIndication_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_CellActivationRequest_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_x2ap_CellActivationRequest(tvb, offset, &asn1_ctx, tree, hf_x2ap_CellActivationRequest_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_ServedCellsToActivate_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_x2ap_ServedCellsToActivate(tvb, offset, &asn1_ctx, tree, hf_x2ap_ServedCellsToActivate_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_CellActivationResponse_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_x2ap_CellActivationResponse(tvb, offset, &asn1_ctx, tree, hf_x2ap_CellActivationResponse_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_ActivatedCellList_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_x2ap_ActivatedCellList(tvb, offset, &asn1_ctx, tree, hf_x2ap_ActivatedCellList_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_CellActivationFailure_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_x2ap_CellActivationFailure(tvb, offset, &asn1_ctx, tree, hf_x2ap_CellActivationFailure_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_X2Release_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_x2ap_X2Release(tvb, offset, &asn1_ctx, tree, hf_x2ap_X2Release_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_X2APMessageTransfer_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_x2ap_X2APMessageTransfer(tvb, offset, &asn1_ctx, tree, hf_x2ap_X2APMessageTransfer_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_RNL_Header_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_x2ap_RNL_Header(tvb, offset, &asn1_ctx, tree, hf_x2ap_RNL_Header_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_X2AP_Message_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_x2ap_X2AP_Message(tvb, offset, &asn1_ctx, tree, hf_x2ap_X2AP_Message_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_SeNBAdditionRequest_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_x2ap_SeNBAdditionRequest(tvb, offset, &asn1_ctx, tree, hf_x2ap_SeNBAdditionRequest_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_E_RABs_ToBeAdded_List_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_x2ap_E_RABs_ToBeAdded_List(tvb, offset, &asn1_ctx, tree, hf_x2ap_E_RABs_ToBeAdded_List_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_E_RABs_ToBeAdded_Item_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_x2ap_E_RABs_ToBeAdded_Item(tvb, offset, &asn1_ctx, tree, hf_x2ap_E_RABs_ToBeAdded_Item_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_SeNBAdditionRequestAcknowledge_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_x2ap_SeNBAdditionRequestAcknowledge(tvb, offset, &asn1_ctx, tree, hf_x2ap_SeNBAdditionRequestAcknowledge_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_E_RABs_Admitted_ToBeAdded_List_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_x2ap_E_RABs_Admitted_ToBeAdded_List(tvb, offset, &asn1_ctx, tree, hf_x2ap_E_RABs_Admitted_ToBeAdded_List_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_E_RABs_Admitted_ToBeAdded_Item_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_x2ap_E_RABs_Admitted_ToBeAdded_Item(tvb, offset, &asn1_ctx, tree, hf_x2ap_E_RABs_Admitted_ToBeAdded_Item_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_SeNBAdditionRequestReject_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_x2ap_SeNBAdditionRequestReject(tvb, offset, &asn1_ctx, tree, hf_x2ap_SeNBAdditionRequestReject_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_SeNBReconfigurationComplete_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_x2ap_SeNBReconfigurationComplete(tvb, offset, &asn1_ctx, tree, hf_x2ap_SeNBReconfigurationComplete_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_ResponseInformationSeNBReconfComp_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_x2ap_ResponseInformationSeNBReconfComp(tvb, offset, &asn1_ctx, tree, hf_x2ap_ResponseInformationSeNBReconfComp_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_SeNBModificationRequest_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_x2ap_SeNBModificationRequest(tvb, offset, &asn1_ctx, tree, hf_x2ap_SeNBModificationRequest_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_UE_ContextInformationSeNBModReq_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_x2ap_UE_ContextInformationSeNBModReq(tvb, offset, &asn1_ctx, tree, hf_x2ap_UE_ContextInformationSeNBModReq_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_E_RABs_ToBeAdded_ModReqItem_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_x2ap_E_RABs_ToBeAdded_ModReqItem(tvb, offset, &asn1_ctx, tree, hf_x2ap_E_RABs_ToBeAdded_ModReqItem_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_E_RABs_ToBeModified_ModReqItem_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_x2ap_E_RABs_ToBeModified_ModReqItem(tvb, offset, &asn1_ctx, tree, hf_x2ap_E_RABs_ToBeModified_ModReqItem_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_E_RABs_ToBeReleased_ModReqItem_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_x2ap_E_RABs_ToBeReleased_ModReqItem(tvb, offset, &asn1_ctx, tree, hf_x2ap_E_RABs_ToBeReleased_ModReqItem_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_SeNBModificationRequestAcknowledge_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_x2ap_SeNBModificationRequestAcknowledge(tvb, offset, &asn1_ctx, tree, hf_x2ap_SeNBModificationRequestAcknowledge_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_E_RABs_Admitted_ToBeAdded_ModAckList_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_x2ap_E_RABs_Admitted_ToBeAdded_ModAckList(tvb, offset, &asn1_ctx, tree, hf_x2ap_E_RABs_Admitted_ToBeAdded_ModAckList_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_E_RABs_Admitted_ToBeAdded_ModAckItem_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_x2ap_E_RABs_Admitted_ToBeAdded_ModAckItem(tvb, offset, &asn1_ctx, tree, hf_x2ap_E_RABs_Admitted_ToBeAdded_ModAckItem_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_E_RABs_Admitted_ToBeModified_ModAckList_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_x2ap_E_RABs_Admitted_ToBeModified_ModAckList(tvb, offset, &asn1_ctx, tree, hf_x2ap_E_RABs_Admitted_ToBeModified_ModAckList_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_E_RABs_Admitted_ToBeModified_ModAckItem_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_x2ap_E_RABs_Admitted_ToBeModified_ModAckItem(tvb, offset, &asn1_ctx, tree, hf_x2ap_E_RABs_Admitted_ToBeModified_ModAckItem_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_E_RABs_Admitted_ToBeReleased_ModAckList_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_x2ap_E_RABs_Admitted_ToBeReleased_ModAckList(tvb, offset, &asn1_ctx, tree, hf_x2ap_E_RABs_Admitted_ToBeReleased_ModAckList_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_E_RABs_Admitted_ToReleased_ModAckItem_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_x2ap_E_RABs_Admitted_ToReleased_ModAckItem(tvb, offset, &asn1_ctx, tree, hf_x2ap_E_RABs_Admitted_ToReleased_ModAckItem_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_SeNBModificationRequestReject_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_x2ap_SeNBModificationRequestReject(tvb, offset, &asn1_ctx, tree, hf_x2ap_SeNBModificationRequestReject_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_SeNBModificationRequired_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_x2ap_SeNBModificationRequired(tvb, offset, &asn1_ctx, tree, hf_x2ap_SeNBModificationRequired_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_E_RABs_ToBeReleased_ModReqd_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_x2ap_E_RABs_ToBeReleased_ModReqd(tvb, offset, &asn1_ctx, tree, hf_x2ap_E_RABs_ToBeReleased_ModReqd_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_E_RABs_ToBeReleased_ModReqdItem_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_x2ap_E_RABs_ToBeReleased_ModReqdItem(tvb, offset, &asn1_ctx, tree, hf_x2ap_E_RABs_ToBeReleased_ModReqdItem_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_SeNBModificationConfirm_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_x2ap_SeNBModificationConfirm(tvb, offset, &asn1_ctx, tree, hf_x2ap_SeNBModificationConfirm_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_SeNBModificationRefuse_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_x2ap_SeNBModificationRefuse(tvb, offset, &asn1_ctx, tree, hf_x2ap_SeNBModificationRefuse_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_SeNBReleaseRequest_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_x2ap_SeNBReleaseRequest(tvb, offset, &asn1_ctx, tree, hf_x2ap_SeNBReleaseRequest_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_E_RABs_ToBeReleased_List_RelReq_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_x2ap_E_RABs_ToBeReleased_List_RelReq(tvb, offset, &asn1_ctx, tree, hf_x2ap_E_RABs_ToBeReleased_List_RelReq_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_E_RABs_ToBeReleased_RelReqItem_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_x2ap_E_RABs_ToBeReleased_RelReqItem(tvb, offset, &asn1_ctx, tree, hf_x2ap_E_RABs_ToBeReleased_RelReqItem_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_SeNBReleaseRequired_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_x2ap_SeNBReleaseRequired(tvb, offset, &asn1_ctx, tree, hf_x2ap_SeNBReleaseRequired_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_SeNBReleaseConfirm_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_x2ap_SeNBReleaseConfirm(tvb, offset, &asn1_ctx, tree, hf_x2ap_SeNBReleaseConfirm_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_E_RABs_ToBeReleased_List_RelConf_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_x2ap_E_RABs_ToBeReleased_List_RelConf(tvb, offset, &asn1_ctx, tree, hf_x2ap_E_RABs_ToBeReleased_List_RelConf_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_E_RABs_ToBeReleased_RelConfItem_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_x2ap_E_RABs_ToBeReleased_RelConfItem(tvb, offset, &asn1_ctx, tree, hf_x2ap_E_RABs_ToBeReleased_RelConfItem_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_SeNBCounterCheckRequest_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_x2ap_SeNBCounterCheckRequest(tvb, offset, &asn1_ctx, tree, hf_x2ap_SeNBCounterCheckRequest_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_E_RABs_SubjectToCounterCheck_List_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_x2ap_E_RABs_SubjectToCounterCheck_List(tvb, offset, &asn1_ctx, tree, hf_x2ap_E_RABs_SubjectToCounterCheck_List_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_E_RABs_SubjectToCounterCheckItem_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_x2ap_E_RABs_SubjectToCounterCheckItem(tvb, offset, &asn1_ctx, tree, hf_x2ap_E_RABs_SubjectToCounterCheckItem_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_X2RemovalRequest_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_x2ap_X2RemovalRequest(tvb, offset, &asn1_ctx, tree, hf_x2ap_X2RemovalRequest_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_X2RemovalResponse_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_x2ap_X2RemovalResponse(tvb, offset, &asn1_ctx, tree, hf_x2ap_X2RemovalResponse_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_X2RemovalFailure_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_x2ap_X2RemovalFailure(tvb, offset, &asn1_ctx, tree, hf_x2ap_X2RemovalFailure_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_RetrieveUEContextRequest_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_x2ap_RetrieveUEContextRequest(tvb, offset, &asn1_ctx, tree, hf_x2ap_RetrieveUEContextRequest_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_RetrieveUEContextResponse_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_x2ap_RetrieveUEContextResponse(tvb, offset, &asn1_ctx, tree, hf_x2ap_RetrieveUEContextResponse_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_UE_ContextInformationRetrieve_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_x2ap_UE_ContextInformationRetrieve(tvb, offset, &asn1_ctx, tree, hf_x2ap_UE_ContextInformationRetrieve_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_E_RABs_ToBeSetupRetrieve_Item_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_x2ap_E_RABs_ToBeSetupRetrieve_Item(tvb, offset, &asn1_ctx, tree, hf_x2ap_E_RABs_ToBeSetupRetrieve_Item_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_RetrieveUEContextFailure_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_x2ap_RetrieveUEContextFailure(tvb, offset, &asn1_ctx, tree, hf_x2ap_RetrieveUEContextFailure_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_X2AP_PDU_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_x2ap_X2AP_PDU(tvb, offset, &asn1_ctx, tree, hf_x2ap_X2AP_PDU_PDU);
  offset += 7; offset >>= 3;
  return offset;
}


/*--- End of included file: packet-x2ap-fn.c ---*/
#line 228 "./asn1/x2ap/packet-x2ap-template.c"

static int dissect_ProtocolIEFieldValue(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
  struct x2ap_private_data *x2ap_data = x2ap_get_private_data(pinfo);

  return (dissector_try_uint(x2ap_ies_dissector_table, x2ap_data->protocol_ie_id, tvb, pinfo, tree)) ? tvb_captured_length(tvb) : 0;
}

static int dissect_ProtocolExtensionFieldExtensionValue(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
  struct x2ap_private_data *x2ap_data = x2ap_get_private_data(pinfo);

  return (dissector_try_uint(x2ap_extension_dissector_table, x2ap_data->protocol_ie_id, tvb, pinfo, tree)) ? tvb_captured_length(tvb) : 0;
}

static int dissect_InitiatingMessageValue(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
  struct x2ap_private_data *x2ap_data = x2ap_get_private_data(pinfo);

  return (dissector_try_uint(x2ap_proc_imsg_dissector_table, x2ap_data->procedure_code, tvb, pinfo, tree)) ? tvb_captured_length(tvb) : 0;
}

static int dissect_SuccessfulOutcomeValue(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
  struct x2ap_private_data *x2ap_data = x2ap_get_private_data(pinfo);

  return (dissector_try_uint(x2ap_proc_sout_dissector_table, x2ap_data->procedure_code, tvb, pinfo, tree)) ? tvb_captured_length(tvb) : 0;
}

static int dissect_UnsuccessfulOutcomeValue(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
  struct x2ap_private_data *x2ap_data = x2ap_get_private_data(pinfo);

  return (dissector_try_uint(x2ap_proc_uout_dissector_table, x2ap_data->procedure_code, tvb, pinfo, tree)) ? tvb_captured_length(tvb) : 0;
}

static int
dissect_x2ap(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data)
{
  proto_item *x2ap_item;
  proto_tree *x2ap_tree;

  /* make entry in the Protocol column on summary display */
  col_set_str(pinfo->cinfo, COL_PROTOCOL, "X2AP");
  col_clear_fence(pinfo->cinfo, COL_INFO);
  col_clear(pinfo->cinfo, COL_INFO);

  /* create the x2ap protocol tree */
  x2ap_item = proto_tree_add_item(tree, proto_x2ap, tvb, 0, -1, ENC_NA);
  x2ap_tree = proto_item_add_subtree(x2ap_item, ett_x2ap);

  return dissect_X2AP_PDU_PDU(tvb, pinfo, x2ap_tree, data);
}

/*--- proto_register_x2ap -------------------------------------------*/
void proto_register_x2ap(void) {

  /* List of fields */

  static hf_register_info hf[] = {
    { &hf_x2ap_transportLayerAddressIPv4,
      { "transportLayerAddress(IPv4)", "x2ap.transportLayerAddressIPv4",
        FT_IPv4, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_x2ap_transportLayerAddressIPv6,
      { "transportLayerAddress(IPv6)", "x2ap.transportLayerAddressIPv6",
        FT_IPv6, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_x2ap_ReportCharacteristics_PRBPeriodic,
      { "PRBPeriodic", "x2ap.ReportCharacteristics.PRBPeriodic",
        FT_BOOLEAN, 32, TFS(&tfs_requested_not_requested), 0x80000000,
        NULL, HFILL }},
    { &hf_x2ap_ReportCharacteristics_TNLLoadIndPeriodic,
      { "TNLLoadIndPeriodic", "x2ap.ReportCharacteristics.TNLLoadIndPeriodic",
        FT_BOOLEAN, 32, TFS(&tfs_requested_not_requested), 0x40000000,
        NULL, HFILL }},
    { &hf_x2ap_ReportCharacteristics_HWLoadIndPeriodic,
      { "HWLoadIndPeriodic", "x2ap.ReportCharacteristics.HWLoadIndPeriodic",
        FT_BOOLEAN, 32, TFS(&tfs_requested_not_requested), 0x20000000,
        NULL, HFILL }},
    { &hf_x2ap_ReportCharacteristics_CompositeAvailableCapacityPeriodic,
      { "CompositeAvailableCapacityPeriodic", "x2ap.ReportCharacteristics.CompositeAvailableCapacityPeriodic",
        FT_BOOLEAN, 32, TFS(&tfs_requested_not_requested), 0x10000000,
        NULL, HFILL }},
    { &hf_x2ap_ReportCharacteristics_ABSStatusPeriodic,
      { "ABSStatusPeriodic", "x2ap.ReportCharacteristics.ABSStatusPeriodic",
        FT_BOOLEAN, 32, TFS(&tfs_requested_not_requested), 0x08000000,
        NULL, HFILL }},
    { &hf_x2ap_ReportCharacteristics_RSRPMeasurementReportPeriodic,
      { "RSRPMeasurementReportPeriodic", "x2ap.ReportCharacteristics.RSRPMeasurementReportPeriodic",
        FT_BOOLEAN, 32, TFS(&tfs_requested_not_requested), 0x04000000,
        NULL, HFILL }},
    { &hf_x2ap_ReportCharacteristics_CSIReportPeriodic,
      { "CSIReportPeriodic", "x2ap.ReportCharacteristics.CSIReportPeriodic",
        FT_BOOLEAN, 32, TFS(&tfs_requested_not_requested), 0x02000000,
        NULL, HFILL }},
    { &hf_x2ap_ReportCharacteristics_Reserved,
      { "Reserved", "x2ap.ReportCharacteristics.Reserved",
        FT_UINT32, BASE_HEX, NULL, 0x01ffffff,
        NULL, HFILL }},
    { &hf_x2ap_measurementFailedReportCharacteristics_PRBPeriodic,
      { "PRBPeriodic", "x2ap.measurementFailedReportCharacteristics.PRBPeriodic",
        FT_BOOLEAN, 32, TFS(&x2ap_tfs_failed_succeeded), 0x80000000,
        NULL, HFILL }},
    { &hf_x2ap_measurementFailedReportCharacteristics_TNLLoadIndPeriodic,
      { "TNLLoadIndPeriodic", "x2ap.measurementFailedReportCharacteristics.TNLLoadIndPeriodic",
        FT_BOOLEAN, 32, TFS(&x2ap_tfs_failed_succeeded), 0x40000000,
        NULL, HFILL }},
    { &hf_x2ap_measurementFailedReportCharacteristics_HWLoadIndPeriodic,
      { "HWLoadIndPeriodic", "x2ap.measurementFailedReportCharacteristics.HWLoadIndPeriodic",
        FT_BOOLEAN, 32, TFS(&x2ap_tfs_failed_succeeded), 0x20000000,
        NULL, HFILL }},
    { &hf_x2ap_measurementFailedReportCharacteristics_CompositeAvailableCapacityPeriodic,
      { "CompositeAvailableCapacityPeriodic", "x2ap.measurementFailedReportCharacteristics.CompositeAvailableCapacityPeriodic",
        FT_BOOLEAN, 32, TFS(&x2ap_tfs_failed_succeeded), 0x10000000,
        NULL, HFILL }},
    { &hf_x2ap_measurementFailedReportCharacteristics_ABSStatusPeriodic,
      { "ABSStatusPeriodic", "x2ap.measurementFailedReportCharacteristics.ABSStatusPeriodic",
        FT_BOOLEAN, 32, TFS(&x2ap_tfs_failed_succeeded), 0x08000000,
        NULL, HFILL }},
    { &hf_x2ap_measurementFailedReportCharacteristics_RSRPMeasurementReportPeriodic,
      { "RSRPMeasurementReportPeriodic", "x2ap.measurementFailedReportCharacteristics.RSRPMeasurementReportPeriodic",
        FT_BOOLEAN, 32, TFS(&x2ap_tfs_failed_succeeded), 0x04000000,
        NULL, HFILL }},
    { &hf_x2ap_measurementFailedReportCharacteristics_CSIReportPeriodic,
      { "CSIReportPeriodic", "x2ap.measurementFailedReportCharacteristics.CSIReportPeriodic",
        FT_BOOLEAN, 32, TFS(&x2ap_tfs_failed_succeeded), 0x02000000,
        NULL, HFILL }},
    { &hf_x2ap_measurementFailedReportCharacteristics_Reserved,
      { "Reserved", "x2ap.measurementFailedReportCharacteristics.Reserved",
        FT_UINT32, BASE_HEX, NULL, 0x01ffffff,
        NULL, HFILL }},
    { &hf_x2ap_eUTRANTraceID_TraceID,
      { "TraceID", "x2ap.eUTRANTraceID.TraceID",
        FT_UINT24, BASE_HEX, NULL, 0,
        NULL, HFILL }},
    { &hf_x2ap_eUTRANTraceID_TraceRecordingSessionReference,
      { "TraceRecordingSessionReference", "x2ap.eUTRANTraceID.TraceRecordingSessionReference",
        FT_UINT16, BASE_HEX, NULL, 0,
        NULL, HFILL }},
    { &hf_x2ap_interfacesToTrace_S1_MME,
      { "S1-MME", "x2ap.interfacesToTrace.S1_MME",
        FT_BOOLEAN, 8, TFS(&x2ap_tfs_interfacesToTrace), 0x80,
        NULL, HFILL }},
    { &hf_x2ap_interfacesToTrace_X2,
      { "X2", "x2ap.interfacesToTrace.X2",
        FT_BOOLEAN, 8, TFS(&x2ap_tfs_interfacesToTrace), 0x40,
        NULL, HFILL }},
    { &hf_x2ap_interfacesToTrace_Uu,
      { "Uu", "x2ap.interfacesToTrace.Uu",
        FT_BOOLEAN, 8, TFS(&x2ap_tfs_interfacesToTrace), 0x20,
        NULL, HFILL }},
    { &hf_x2ap_interfacesToTrace_Reserved,
      { "Reserved", "x2ap.interfacesToTrace.Reserved",
        FT_UINT8, BASE_HEX, NULL, 0x1f,
        NULL, HFILL }},
    { &hf_x2ap_traceCollectionEntityIPAddress_IPv4,
      { "IPv4", "x2ap.traceCollectionEntityIPAddress.IPv4",
        FT_IPv4, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_x2ap_traceCollectionEntityIPAddress_IPv6,
      { "IPv6", "x2ap.traceCollectionEntityIPAddress.IPv6",
        FT_IPv6, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_x2ap_encryptionAlgorithms_EEA1,
      { "128-EEA1", "x2ap.encryptionAlgorithms.EEA1",
        FT_BOOLEAN, 16, TFS(&tfs_supported_not_supported), 0x8000,
        NULL, HFILL }},
    { &hf_x2ap_encryptionAlgorithms_EEA2,
      { "128-EEA2", "x2ap.encryptionAlgorithms.EEA2",
        FT_BOOLEAN, 16, TFS(&tfs_supported_not_supported), 0x4000,
        NULL, HFILL }},
    { &hf_x2ap_encryptionAlgorithms_EEA3,
      { "128-EEA3", "x2ap.encryptionAlgorithms.EEA3",
        FT_BOOLEAN, 16, TFS(&tfs_supported_not_supported), 0x2000,
        NULL, HFILL }},
    { &hf_x2ap_encryptionAlgorithms_Reserved,
      { "Reserved", "x2ap.encryptionAlgorithms.Reserved",
        FT_UINT16, BASE_HEX, NULL, 0x1fff,
        NULL, HFILL }},
    { &hf_x2ap_integrityProtectionAlgorithms_EIA1,
      { "128-EIA1", "x2ap.integrityProtectionAlgorithms.EIA1",
        FT_BOOLEAN, 16, TFS(&tfs_supported_not_supported), 0x8000,
        NULL, HFILL }},
    { &hf_x2ap_integrityProtectionAlgorithms_EIA2,
      { "128-EIA2", "x2ap.integrityProtectionAlgorithms.EIA2",
        FT_BOOLEAN, 16, TFS(&tfs_supported_not_supported), 0x4000,
        NULL, HFILL }},
    { &hf_x2ap_integrityProtectionAlgorithms_EIA3,
      { "128-EIA3", "x2ap.integrityProtectionAlgorithms.EIA3",
        FT_BOOLEAN, 16, TFS(&tfs_supported_not_supported), 0x2000,
        NULL, HFILL }},
    { &hf_x2ap_integrityProtectionAlgorithms_Reserved,
      { "Reserved", "x2ap.integrityProtectionAlgorithms.Reserved",
        FT_UINT16, BASE_HEX, NULL, 0x1fff,
        NULL, HFILL }},
    { &hf_x2ap_measurementsToActivate_M1,
      { "M1", "x2ap.measurementsToActivate.M1",
        FT_BOOLEAN, 8, TFS(&x2ap_tfs_activate_do_not_activate), 0x80,
        NULL, HFILL }},
    { &hf_x2ap_measurementsToActivate_M2,
      { "M2", "x2ap.measurementsToActivate.M2",
        FT_BOOLEAN, 8, TFS(&x2ap_tfs_activate_do_not_activate), 0x40,
        NULL, HFILL }},
    { &hf_x2ap_measurementsToActivate_M3,
      { "M3", "x2ap.measurementsToActivate.M3",
        FT_BOOLEAN, 8, TFS(&x2ap_tfs_activate_do_not_activate), 0x20,
        NULL, HFILL }},
    { &hf_x2ap_measurementsToActivate_M4,
      { "M4", "x2ap.measurementsToActivate.M4",
        FT_BOOLEAN, 8, TFS(&x2ap_tfs_activate_do_not_activate), 0x10,
        NULL, HFILL }},
    { &hf_x2ap_measurementsToActivate_M5,
      { "M5", "x2ap.measurementsToActivate.M5",
        FT_BOOLEAN, 8, TFS(&x2ap_tfs_activate_do_not_activate), 0x08,
        NULL, HFILL }},
    { &hf_x2ap_measurementsToActivate_LoggingM1FromEventTriggered,
      { "LoggingOfM1FromEventTriggeredMeasurementReports", "x2ap.measurementsToActivate.LoggingM1FromEventTriggered",
        FT_BOOLEAN, 8, TFS(&x2ap_tfs_activate_do_not_activate), 0x04,
        NULL, HFILL }},
    { &hf_x2ap_measurementsToActivate_M6,
      { "M6", "x2ap.measurementsToActivate.M6",
        FT_BOOLEAN, 8, TFS(&x2ap_tfs_activate_do_not_activate), 0x02,
        NULL, HFILL }},
    { &hf_x2ap_measurementsToActivate_M7,
      { "M7", "x2ap.measurementsToActivate.M7",
        FT_BOOLEAN, 8, TFS(&x2ap_tfs_activate_do_not_activate), 0x01,
        NULL, HFILL }},
    { &hf_x2ap_MDT_Location_Info_GNSS,
      { "GNSS", "x2ap.MDT_Location_Info.GNSS",
        FT_BOOLEAN, 8, TFS(&x2ap_tfs_activate_do_not_activate), 0x80,
        NULL, HFILL }},
    { &hf_x2ap_MDT_Location_Info_E_CID,
      { "E-CID", "x2ap.MDT_Location_Info.E_CID",
        FT_BOOLEAN, 8, TFS(&x2ap_tfs_activate_do_not_activate), 0x40,
        NULL, HFILL }},
    { &hf_x2ap_MDT_Location_Info_Reserved,
      { "Reserved", "x2ap.MDT_Location_Info.Reserved",
        FT_UINT8, BASE_HEX, NULL, 0x3f,
        NULL, HFILL }},
    { &hf_x2ap_MDT_transmissionModes_tm1,
      { "TM1", "x2ap.MDT_Location_Info.transmissionModes.tm1",
        FT_BOOLEAN, 8, TFS(&tfs_yes_no), 0x80,
        NULL, HFILL }},
    { &hf_x2ap_MDT_transmissionModes_tm2,
      { "TM2", "x2ap.MDT_Location_Info.transmissionModes.tm2",
        FT_BOOLEAN, 8, TFS(&tfs_yes_no), 0x40,
        NULL, HFILL }},
    { &hf_x2ap_MDT_transmissionModes_tm3,
      { "TM3", "x2ap.MDT_Location_Info.transmissionModes.tm3",
        FT_BOOLEAN, 8, TFS(&tfs_yes_no), 0x20,
        NULL, HFILL }},
    { &hf_x2ap_MDT_transmissionModes_tm4,
      { "TM4", "x2ap.MDT_Location_Info.transmissionModes.tm4",
        FT_BOOLEAN, 8, TFS(&tfs_yes_no), 0x10,
        NULL, HFILL }},
    { &hf_x2ap_MDT_transmissionModes_tm6,
      { "TM6", "x2ap.MDT_Location_Info.transmissionModes.tm6",
        FT_BOOLEAN, 8, TFS(&tfs_yes_no), 0x08,
        NULL, HFILL }},
    { &hf_x2ap_MDT_transmissionModes_tm8,
      { "TM8", "x2ap.MDT_Location_Info.transmissionModes.tm8",
        FT_BOOLEAN, 8, TFS(&tfs_yes_no), 0x04,
        NULL, HFILL }},
    { &hf_x2ap_MDT_transmissionModes_tm9,
      { "TM9", "x2ap.MDT_Location_Info.transmissionModes.tm9",
        FT_BOOLEAN, 8, TFS(&tfs_yes_no), 0x02,
        NULL, HFILL }},
    { &hf_x2ap_MDT_transmissionModes_tm10,
      { "TM10", "x2ap.MDT_Location_Info.transmissionModes.tm10",
        FT_BOOLEAN, 8, TFS(&tfs_yes_no), 0x01,
        NULL, HFILL }},

/*--- Included file: packet-x2ap-hfarr.c ---*/
#line 1 "./asn1/x2ap/packet-x2ap-hfarr.c"
    { &hf_x2ap_ABSInformation_PDU,
      { "ABSInformation", "x2ap.ABSInformation",
        FT_UINT32, BASE_DEC, VALS(x2ap_ABSInformation_vals), 0,
        NULL, HFILL }},
    { &hf_x2ap_ABS_Status_PDU,
      { "ABS-Status", "x2ap.ABS_Status_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_x2ap_AdditionalSpecialSubframe_Info_PDU,
      { "AdditionalSpecialSubframe-Info", "x2ap.AdditionalSpecialSubframe_Info_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_x2ap_BearerType_PDU,
      { "BearerType", "x2ap.BearerType",
        FT_UINT32, BASE_DEC, VALS(x2ap_BearerType_vals), 0,
        NULL, HFILL }},
    { &hf_x2ap_Cause_PDU,
      { "Cause", "x2ap.Cause",
        FT_UINT32, BASE_DEC, VALS(x2ap_Cause_vals), 0,
        NULL, HFILL }},
    { &hf_x2ap_CellReportingIndicator_PDU,
      { "CellReportingIndicator", "x2ap.CellReportingIndicator",
        FT_UINT32, BASE_DEC, VALS(x2ap_CellReportingIndicator_vals), 0,
        NULL, HFILL }},
    { &hf_x2ap_CoMPInformation_PDU,
      { "CoMPInformation", "x2ap.CoMPInformation_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_x2ap_CompositeAvailableCapacityGroup_PDU,
      { "CompositeAvailableCapacityGroup", "x2ap.CompositeAvailableCapacityGroup_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_x2ap_Correlation_ID_PDU,
      { "Correlation-ID", "x2ap.Correlation_ID",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_x2ap_COUNTValueExtended_PDU,
      { "COUNTValueExtended", "x2ap.COUNTValueExtended_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_x2ap_COUNTvaluePDCP_SNlength18_PDU,
      { "COUNTvaluePDCP-SNlength18", "x2ap.COUNTvaluePDCP_SNlength18_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_x2ap_CoverageModificationList_PDU,
      { "CoverageModificationList", "x2ap.CoverageModificationList",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_x2ap_CriticalityDiagnostics_PDU,
      { "CriticalityDiagnostics", "x2ap.CriticalityDiagnostics_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_x2ap_CRNTI_PDU,
      { "CRNTI", "x2ap.CRNTI",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_x2ap_CSGMembershipStatus_PDU,
      { "CSGMembershipStatus", "x2ap.CSGMembershipStatus",
        FT_UINT32, BASE_DEC, VALS(x2ap_CSGMembershipStatus_vals), 0,
        NULL, HFILL }},
    { &hf_x2ap_CSG_Id_PDU,
      { "CSG-Id", "x2ap.CSG_Id",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_x2ap_CSIReportList_PDU,
      { "CSIReportList", "x2ap.CSIReportList",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_x2ap_DeactivationIndication_PDU,
      { "DeactivationIndication", "x2ap.DeactivationIndication",
        FT_UINT32, BASE_DEC, VALS(x2ap_DeactivationIndication_vals), 0,
        NULL, HFILL }},
    { &hf_x2ap_DynamicDLTransmissionInformation_PDU,
      { "DynamicDLTransmissionInformation", "x2ap.DynamicDLTransmissionInformation",
        FT_UINT32, BASE_DEC, VALS(x2ap_DynamicDLTransmissionInformation_vals), 0,
        NULL, HFILL }},
    { &hf_x2ap_EARFCNExtension_PDU,
      { "EARFCNExtension", "x2ap.EARFCNExtension",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_x2ap_ECGI_PDU,
      { "ECGI", "x2ap.ECGI_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_x2ap_EnhancedRNTP_PDU,
      { "EnhancedRNTP", "x2ap.EnhancedRNTP_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_x2ap_E_RAB_List_PDU,
      { "E-RAB-List", "x2ap.E_RAB_List",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_x2ap_E_RAB_Item_PDU,
      { "E-RAB-Item", "x2ap.E_RAB_Item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_x2ap_EUTRANCellIdentifier_PDU,
      { "EUTRANCellIdentifier", "x2ap.EUTRANCellIdentifier",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_x2ap_ExpectedUEBehaviour_PDU,
      { "ExpectedUEBehaviour", "x2ap.ExpectedUEBehaviour_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_x2ap_ExtendedULInterferenceOverloadInfo_PDU,
      { "ExtendedULInterferenceOverloadInfo", "x2ap.ExtendedULInterferenceOverloadInfo_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_x2ap_FreqBandIndicatorPriority_PDU,
      { "FreqBandIndicatorPriority", "x2ap.FreqBandIndicatorPriority",
        FT_UINT32, BASE_DEC, VALS(x2ap_FreqBandIndicatorPriority_vals), 0,
        NULL, HFILL }},
    { &hf_x2ap_GlobalENB_ID_PDU,
      { "GlobalENB-ID", "x2ap.GlobalENB_ID_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_x2ap_GUGroupIDList_PDU,
      { "GUGroupIDList", "x2ap.GUGroupIDList",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_x2ap_GUMMEI_PDU,
      { "GUMMEI", "x2ap.GUMMEI_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_x2ap_HandoverReportType_PDU,
      { "HandoverReportType", "x2ap.HandoverReportType",
        FT_UINT32, BASE_DEC, VALS(x2ap_HandoverReportType_vals), 0,
        NULL, HFILL }},
    { &hf_x2ap_InvokeIndication_PDU,
      { "InvokeIndication", "x2ap.InvokeIndication",
        FT_UINT32, BASE_DEC, VALS(x2ap_InvokeIndication_vals), 0,
        NULL, HFILL }},
    { &hf_x2ap_LHN_ID_PDU,
      { "LHN-ID", "x2ap.LHN_ID",
        FT_STRING, STR_UNICODE, NULL, 0,
        NULL, HFILL }},
    { &hf_x2ap_M3Configuration_PDU,
      { "M3Configuration", "x2ap.M3Configuration_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_x2ap_M4Configuration_PDU,
      { "M4Configuration", "x2ap.M4Configuration_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_x2ap_M5Configuration_PDU,
      { "M5Configuration", "x2ap.M5Configuration_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_x2ap_M6Configuration_PDU,
      { "M6Configuration", "x2ap.M6Configuration_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_x2ap_M7Configuration_PDU,
      { "M7Configuration", "x2ap.M7Configuration_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_x2ap_ManagementBasedMDTallowed_PDU,
      { "ManagementBasedMDTallowed", "x2ap.ManagementBasedMDTallowed",
        FT_UINT32, BASE_DEC, VALS(x2ap_ManagementBasedMDTallowed_vals), 0,
        NULL, HFILL }},
    { &hf_x2ap_Masked_IMEISV_PDU,
      { "Masked-IMEISV", "x2ap.Masked_IMEISV",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_x2ap_MDT_Configuration_PDU,
      { "MDT-Configuration", "x2ap.MDT_Configuration_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_x2ap_MDTPLMNList_PDU,
      { "MDTPLMNList", "x2ap.MDTPLMNList",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_x2ap_MDT_Location_Info_PDU,
      { "MDT-Location-Info", "x2ap.MDT_Location_Info",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_x2ap_Measurement_ID_PDU,
      { "Measurement-ID", "x2ap.Measurement_ID",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_x2ap_MeNBtoSeNBContainer_PDU,
      { "MeNBtoSeNBContainer", "x2ap.MeNBtoSeNBContainer",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_x2ap_MBMS_Service_Area_Identity_List_PDU,
      { "MBMS-Service-Area-Identity-List", "x2ap.MBMS_Service_Area_Identity_List",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_x2ap_MBSFN_Subframe_Infolist_PDU,
      { "MBSFN-Subframe-Infolist", "x2ap.MBSFN_Subframe_Infolist",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_x2ap_MobilityParametersModificationRange_PDU,
      { "MobilityParametersModificationRange", "x2ap.MobilityParametersModificationRange_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_x2ap_MobilityParametersInformation_PDU,
      { "MobilityParametersInformation", "x2ap.MobilityParametersInformation_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_x2ap_MultibandInfoList_PDU,
      { "MultibandInfoList", "x2ap.MultibandInfoList",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_x2ap_Number_of_Antennaports_PDU,
      { "Number-of-Antennaports", "x2ap.Number_of_Antennaports",
        FT_UINT32, BASE_DEC, VALS(x2ap_Number_of_Antennaports_vals), 0,
        NULL, HFILL }},
    { &hf_x2ap_OffsetOfNbiotChannelNumberToEARFCN_PDU,
      { "OffsetOfNbiotChannelNumberToEARFCN", "x2ap.OffsetOfNbiotChannelNumberToEARFCN",
        FT_UINT32, BASE_DEC|BASE_EXT_STRING, &x2ap_OffsetOfNbiotChannelNumberToEARFCN_vals_ext, 0,
        NULL, HFILL }},
    { &hf_x2ap_PCI_PDU,
      { "PCI", "x2ap.PCI",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_x2ap_PLMN_Identity_PDU,
      { "PLMN-Identity", "x2ap.PLMN_Identity",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_x2ap_PRACH_Configuration_PDU,
      { "PRACH-Configuration", "x2ap.PRACH_Configuration_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_x2ap_ProSeAuthorized_PDU,
      { "ProSeAuthorized", "x2ap.ProSeAuthorized_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_x2ap_ProSeUEtoNetworkRelaying_PDU,
      { "ProSeUEtoNetworkRelaying", "x2ap.ProSeUEtoNetworkRelaying",
        FT_UINT32, BASE_DEC, VALS(x2ap_ProSeUEtoNetworkRelaying_vals), 0,
        NULL, HFILL }},
    { &hf_x2ap_ReceiveStatusOfULPDCPSDUsExtended_PDU,
      { "ReceiveStatusOfULPDCPSDUsExtended", "x2ap.ReceiveStatusOfULPDCPSDUsExtended",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_x2ap_ReceiveStatusOfULPDCPSDUsPDCP_SNlength18_PDU,
      { "ReceiveStatusOfULPDCPSDUsPDCP-SNlength18", "x2ap.ReceiveStatusOfULPDCPSDUsPDCP_SNlength18",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_x2ap_Registration_Request_PDU,
      { "Registration-Request", "x2ap.Registration_Request",
        FT_UINT32, BASE_DEC, VALS(x2ap_Registration_Request_vals), 0,
        NULL, HFILL }},
    { &hf_x2ap_ReportCharacteristics_PDU,
      { "ReportCharacteristics", "x2ap.ReportCharacteristics",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_x2ap_ReportingPeriodicityCSIR_PDU,
      { "ReportingPeriodicityCSIR", "x2ap.ReportingPeriodicityCSIR",
        FT_UINT32, BASE_DEC, VALS(x2ap_ReportingPeriodicityCSIR_vals), 0,
        NULL, HFILL }},
    { &hf_x2ap_ReportingPeriodicityRSRPMR_PDU,
      { "ReportingPeriodicityRSRPMR", "x2ap.ReportingPeriodicityRSRPMR",
        FT_UINT32, BASE_DEC, VALS(x2ap_ReportingPeriodicityRSRPMR_vals), 0,
        NULL, HFILL }},
    { &hf_x2ap_ResumeID_PDU,
      { "ResumeID", "x2ap.ResumeID",
        FT_UINT32, BASE_DEC, VALS(x2ap_ResumeID_vals), 0,
        NULL, HFILL }},
    { &hf_x2ap_RRCConnReestabIndicator_PDU,
      { "RRCConnReestabIndicator", "x2ap.RRCConnReestabIndicator",
        FT_UINT32, BASE_DEC, VALS(x2ap_RRCConnReestabIndicator_vals), 0,
        NULL, HFILL }},
    { &hf_x2ap_RRCConnSetupIndicator_PDU,
      { "RRCConnSetupIndicator", "x2ap.RRCConnSetupIndicator",
        FT_UINT32, BASE_DEC, VALS(x2ap_RRCConnSetupIndicator_vals), 0,
        NULL, HFILL }},
    { &hf_x2ap_RSRPMRList_PDU,
      { "RSRPMRList", "x2ap.RSRPMRList",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_x2ap_SCGChangeIndication_PDU,
      { "SCGChangeIndication", "x2ap.SCGChangeIndication",
        FT_UINT32, BASE_DEC, VALS(x2ap_SCGChangeIndication_vals), 0,
        NULL, HFILL }},
    { &hf_x2ap_SeNBSecurityKey_PDU,
      { "SeNBSecurityKey", "x2ap.SeNBSecurityKey",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_x2ap_SeNBtoMeNBContainer_PDU,
      { "SeNBtoMeNBContainer", "x2ap.SeNBtoMeNBContainer",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_x2ap_ServedCells_PDU,
      { "ServedCells", "x2ap.ServedCells",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_x2ap_SIPTOBearerDeactivationIndication_PDU,
      { "SIPTOBearerDeactivationIndication", "x2ap.SIPTOBearerDeactivationIndication",
        FT_UINT32, BASE_DEC, VALS(x2ap_SIPTOBearerDeactivationIndication_vals), 0,
        NULL, HFILL }},
    { &hf_x2ap_ShortMAC_I_PDU,
      { "ShortMAC-I", "x2ap.ShortMAC_I",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_x2ap_SRVCCOperationPossible_PDU,
      { "SRVCCOperationPossible", "x2ap.SRVCCOperationPossible",
        FT_UINT32, BASE_DEC, VALS(x2ap_SRVCCOperationPossible_vals), 0,
        NULL, HFILL }},
    { &hf_x2ap_SubframeAssignment_PDU,
      { "SubframeAssignment", "x2ap.SubframeAssignment",
        FT_UINT32, BASE_DEC, VALS(x2ap_SubframeAssignment_vals), 0,
        NULL, HFILL }},
    { &hf_x2ap_TAC_PDU,
      { "TAC", "x2ap.TAC",
        FT_UINT16, BASE_DEC_HEX, NULL, 0,
        NULL, HFILL }},
    { &hf_x2ap_TargetCellInUTRAN_PDU,
      { "TargetCellInUTRAN", "x2ap.TargetCellInUTRAN",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_x2ap_TargeteNBtoSource_eNBTransparentContainer_PDU,
      { "TargeteNBtoSource-eNBTransparentContainer", "x2ap.TargeteNBtoSource_eNBTransparentContainer",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_x2ap_TimeToWait_PDU,
      { "TimeToWait", "x2ap.TimeToWait",
        FT_UINT32, BASE_DEC, VALS(x2ap_TimeToWait_vals), 0,
        NULL, HFILL }},
    { &hf_x2ap_Time_UE_StayedInCell_EnhancedGranularity_PDU,
      { "Time-UE-StayedInCell-EnhancedGranularity", "x2ap.Time_UE_StayedInCell_EnhancedGranularity",
        FT_UINT32, BASE_CUSTOM, CF_FUNC(x2ap_Time_UE_StayedInCell_EnhancedGranularity_fmt), 0,
        NULL, HFILL }},
    { &hf_x2ap_TraceActivation_PDU,
      { "TraceActivation", "x2ap.TraceActivation_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_x2ap_TransportLayerAddress_PDU,
      { "TransportLayerAddress", "x2ap.TransportLayerAddress",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_x2ap_TunnelInformation_PDU,
      { "TunnelInformation", "x2ap.TunnelInformation_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_x2ap_UEAggregateMaximumBitRate_PDU,
      { "UEAggregateMaximumBitRate", "x2ap.UEAggregateMaximumBitRate_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_x2ap_UE_ContextKeptIndicator_PDU,
      { "UE-ContextKeptIndicator", "x2ap.UE_ContextKeptIndicator",
        FT_UINT32, BASE_DEC, VALS(x2ap_UE_ContextKeptIndicator_vals), 0,
        NULL, HFILL }},
    { &hf_x2ap_UEID_PDU,
      { "UEID", "x2ap.UEID",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_x2ap_UE_HistoryInformation_PDU,
      { "UE-HistoryInformation", "x2ap.UE_HistoryInformation",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_x2ap_UE_HistoryInformationFromTheUE_PDU,
      { "UE-HistoryInformationFromTheUE", "x2ap.UE_HistoryInformationFromTheUE",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_x2ap_UE_X2AP_ID_PDU,
      { "UE-X2AP-ID", "x2ap.UE_X2AP_ID",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_x2ap_UE_X2AP_ID_Extension_PDU,
      { "UE-X2AP-ID-Extension", "x2ap.UE_X2AP_ID_Extension",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_x2ap_UE_RLF_Report_Container_PDU,
      { "UE-RLF-Report-Container", "x2ap.UE_RLF_Report_Container",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_x2ap_UE_RLF_Report_Container_for_extended_bands_PDU,
      { "UE-RLF-Report-Container-for-extended-bands", "x2ap.UE_RLF_Report_Container_for_extended_bands",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_x2ap_UESecurityCapabilities_PDU,
      { "UESecurityCapabilities", "x2ap.UESecurityCapabilities_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_x2ap_X2BenefitValue_PDU,
      { "X2BenefitValue", "x2ap.X2BenefitValue",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_x2ap_HandoverRequest_PDU,
      { "HandoverRequest", "x2ap.HandoverRequest_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_x2ap_UE_ContextInformation_PDU,
      { "UE-ContextInformation", "x2ap.UE_ContextInformation_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_x2ap_E_RABs_ToBeSetup_Item_PDU,
      { "E-RABs-ToBeSetup-Item", "x2ap.E_RABs_ToBeSetup_Item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_x2ap_MobilityInformation_PDU,
      { "MobilityInformation", "x2ap.MobilityInformation",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_x2ap_UE_ContextReferenceAtSeNB_PDU,
      { "UE-ContextReferenceAtSeNB", "x2ap.UE_ContextReferenceAtSeNB_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_x2ap_HandoverRequestAcknowledge_PDU,
      { "HandoverRequestAcknowledge", "x2ap.HandoverRequestAcknowledge_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_x2ap_E_RABs_Admitted_List_PDU,
      { "E-RABs-Admitted-List", "x2ap.E_RABs_Admitted_List",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_x2ap_E_RABs_Admitted_Item_PDU,
      { "E-RABs-Admitted-Item", "x2ap.E_RABs_Admitted_Item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_x2ap_HandoverPreparationFailure_PDU,
      { "HandoverPreparationFailure", "x2ap.HandoverPreparationFailure_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_x2ap_HandoverReport_PDU,
      { "HandoverReport", "x2ap.HandoverReport_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_x2ap_SNStatusTransfer_PDU,
      { "SNStatusTransfer", "x2ap.SNStatusTransfer_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_x2ap_E_RABs_SubjectToStatusTransfer_List_PDU,
      { "E-RABs-SubjectToStatusTransfer-List", "x2ap.E_RABs_SubjectToStatusTransfer_List",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_x2ap_E_RABs_SubjectToStatusTransfer_Item_PDU,
      { "E-RABs-SubjectToStatusTransfer-Item", "x2ap.E_RABs_SubjectToStatusTransfer_Item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_x2ap_UEContextRelease_PDU,
      { "UEContextRelease", "x2ap.UEContextRelease_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_x2ap_HandoverCancel_PDU,
      { "HandoverCancel", "x2ap.HandoverCancel_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_x2ap_ErrorIndication_PDU,
      { "ErrorIndication", "x2ap.ErrorIndication_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_x2ap_ResetRequest_PDU,
      { "ResetRequest", "x2ap.ResetRequest_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_x2ap_ResetResponse_PDU,
      { "ResetResponse", "x2ap.ResetResponse_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_x2ap_X2SetupRequest_PDU,
      { "X2SetupRequest", "x2ap.X2SetupRequest_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_x2ap_X2SetupResponse_PDU,
      { "X2SetupResponse", "x2ap.X2SetupResponse_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_x2ap_X2SetupFailure_PDU,
      { "X2SetupFailure", "x2ap.X2SetupFailure_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_x2ap_LoadInformation_PDU,
      { "LoadInformation", "x2ap.LoadInformation_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_x2ap_CellInformation_List_PDU,
      { "CellInformation-List", "x2ap.CellInformation_List",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_x2ap_CellInformation_Item_PDU,
      { "CellInformation-Item", "x2ap.CellInformation_Item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_x2ap_ENBConfigurationUpdate_PDU,
      { "ENBConfigurationUpdate", "x2ap.ENBConfigurationUpdate_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_x2ap_ServedCellsToModify_PDU,
      { "ServedCellsToModify", "x2ap.ServedCellsToModify",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_x2ap_Old_ECGIs_PDU,
      { "Old-ECGIs", "x2ap.Old_ECGIs",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_x2ap_ENBConfigurationUpdateAcknowledge_PDU,
      { "ENBConfigurationUpdateAcknowledge", "x2ap.ENBConfigurationUpdateAcknowledge_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_x2ap_ENBConfigurationUpdateFailure_PDU,
      { "ENBConfigurationUpdateFailure", "x2ap.ENBConfigurationUpdateFailure_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_x2ap_ResourceStatusRequest_PDU,
      { "ResourceStatusRequest", "x2ap.ResourceStatusRequest_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_x2ap_CellToReport_List_PDU,
      { "CellToReport-List", "x2ap.CellToReport_List",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_x2ap_CellToReport_Item_PDU,
      { "CellToReport-Item", "x2ap.CellToReport_Item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_x2ap_ReportingPeriodicity_PDU,
      { "ReportingPeriodicity", "x2ap.ReportingPeriodicity",
        FT_UINT32, BASE_DEC, VALS(x2ap_ReportingPeriodicity_vals), 0,
        NULL, HFILL }},
    { &hf_x2ap_PartialSuccessIndicator_PDU,
      { "PartialSuccessIndicator", "x2ap.PartialSuccessIndicator",
        FT_UINT32, BASE_DEC, VALS(x2ap_PartialSuccessIndicator_vals), 0,
        NULL, HFILL }},
    { &hf_x2ap_ResourceStatusResponse_PDU,
      { "ResourceStatusResponse", "x2ap.ResourceStatusResponse_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_x2ap_MeasurementInitiationResult_List_PDU,
      { "MeasurementInitiationResult-List", "x2ap.MeasurementInitiationResult_List",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_x2ap_MeasurementInitiationResult_Item_PDU,
      { "MeasurementInitiationResult-Item", "x2ap.MeasurementInitiationResult_Item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_x2ap_MeasurementFailureCause_Item_PDU,
      { "MeasurementFailureCause-Item", "x2ap.MeasurementFailureCause_Item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_x2ap_ResourceStatusFailure_PDU,
      { "ResourceStatusFailure", "x2ap.ResourceStatusFailure_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_x2ap_CompleteFailureCauseInformation_List_PDU,
      { "CompleteFailureCauseInformation-List", "x2ap.CompleteFailureCauseInformation_List",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_x2ap_CompleteFailureCauseInformation_Item_PDU,
      { "CompleteFailureCauseInformation-Item", "x2ap.CompleteFailureCauseInformation_Item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_x2ap_ResourceStatusUpdate_PDU,
      { "ResourceStatusUpdate", "x2ap.ResourceStatusUpdate_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_x2ap_CellMeasurementResult_List_PDU,
      { "CellMeasurementResult-List", "x2ap.CellMeasurementResult_List",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_x2ap_CellMeasurementResult_Item_PDU,
      { "CellMeasurementResult-Item", "x2ap.CellMeasurementResult_Item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_x2ap_PrivateMessage_PDU,
      { "PrivateMessage", "x2ap.PrivateMessage_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_x2ap_MobilityChangeRequest_PDU,
      { "MobilityChangeRequest", "x2ap.MobilityChangeRequest_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_x2ap_MobilityChangeAcknowledge_PDU,
      { "MobilityChangeAcknowledge", "x2ap.MobilityChangeAcknowledge_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_x2ap_MobilityChangeFailure_PDU,
      { "MobilityChangeFailure", "x2ap.MobilityChangeFailure_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_x2ap_RLFIndication_PDU,
      { "RLFIndication", "x2ap.RLFIndication_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_x2ap_CellActivationRequest_PDU,
      { "CellActivationRequest", "x2ap.CellActivationRequest_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_x2ap_ServedCellsToActivate_PDU,
      { "ServedCellsToActivate", "x2ap.ServedCellsToActivate",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_x2ap_CellActivationResponse_PDU,
      { "CellActivationResponse", "x2ap.CellActivationResponse_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_x2ap_ActivatedCellList_PDU,
      { "ActivatedCellList", "x2ap.ActivatedCellList",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_x2ap_CellActivationFailure_PDU,
      { "CellActivationFailure", "x2ap.CellActivationFailure_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_x2ap_X2Release_PDU,
      { "X2Release", "x2ap.X2Release_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_x2ap_X2APMessageTransfer_PDU,
      { "X2APMessageTransfer", "x2ap.X2APMessageTransfer_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_x2ap_RNL_Header_PDU,
      { "RNL-Header", "x2ap.RNL_Header_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_x2ap_X2AP_Message_PDU,
      { "X2AP-Message", "x2ap.X2AP_Message",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_x2ap_SeNBAdditionRequest_PDU,
      { "SeNBAdditionRequest", "x2ap.SeNBAdditionRequest_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_x2ap_E_RABs_ToBeAdded_List_PDU,
      { "E-RABs-ToBeAdded-List", "x2ap.E_RABs_ToBeAdded_List",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_x2ap_E_RABs_ToBeAdded_Item_PDU,
      { "E-RABs-ToBeAdded-Item", "x2ap.E_RABs_ToBeAdded_Item",
        FT_UINT32, BASE_DEC, VALS(x2ap_E_RABs_ToBeAdded_Item_vals), 0,
        NULL, HFILL }},
    { &hf_x2ap_SeNBAdditionRequestAcknowledge_PDU,
      { "SeNBAdditionRequestAcknowledge", "x2ap.SeNBAdditionRequestAcknowledge_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_x2ap_E_RABs_Admitted_ToBeAdded_List_PDU,
      { "E-RABs-Admitted-ToBeAdded-List", "x2ap.E_RABs_Admitted_ToBeAdded_List",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_x2ap_E_RABs_Admitted_ToBeAdded_Item_PDU,
      { "E-RABs-Admitted-ToBeAdded-Item", "x2ap.E_RABs_Admitted_ToBeAdded_Item",
        FT_UINT32, BASE_DEC, VALS(x2ap_E_RABs_Admitted_ToBeAdded_Item_vals), 0,
        NULL, HFILL }},
    { &hf_x2ap_SeNBAdditionRequestReject_PDU,
      { "SeNBAdditionRequestReject", "x2ap.SeNBAdditionRequestReject_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_x2ap_SeNBReconfigurationComplete_PDU,
      { "SeNBReconfigurationComplete", "x2ap.SeNBReconfigurationComplete_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_x2ap_ResponseInformationSeNBReconfComp_PDU,
      { "ResponseInformationSeNBReconfComp", "x2ap.ResponseInformationSeNBReconfComp",
        FT_UINT32, BASE_DEC, VALS(x2ap_ResponseInformationSeNBReconfComp_vals), 0,
        NULL, HFILL }},
    { &hf_x2ap_SeNBModificationRequest_PDU,
      { "SeNBModificationRequest", "x2ap.SeNBModificationRequest_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_x2ap_UE_ContextInformationSeNBModReq_PDU,
      { "UE-ContextInformationSeNBModReq", "x2ap.UE_ContextInformationSeNBModReq_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_x2ap_E_RABs_ToBeAdded_ModReqItem_PDU,
      { "E-RABs-ToBeAdded-ModReqItem", "x2ap.E_RABs_ToBeAdded_ModReqItem",
        FT_UINT32, BASE_DEC, VALS(x2ap_E_RABs_ToBeAdded_ModReqItem_vals), 0,
        NULL, HFILL }},
    { &hf_x2ap_E_RABs_ToBeModified_ModReqItem_PDU,
      { "E-RABs-ToBeModified-ModReqItem", "x2ap.E_RABs_ToBeModified_ModReqItem",
        FT_UINT32, BASE_DEC, VALS(x2ap_E_RABs_ToBeModified_ModReqItem_vals), 0,
        NULL, HFILL }},
    { &hf_x2ap_E_RABs_ToBeReleased_ModReqItem_PDU,
      { "E-RABs-ToBeReleased-ModReqItem", "x2ap.E_RABs_ToBeReleased_ModReqItem",
        FT_UINT32, BASE_DEC, VALS(x2ap_E_RABs_ToBeReleased_ModReqItem_vals), 0,
        NULL, HFILL }},
    { &hf_x2ap_SeNBModificationRequestAcknowledge_PDU,
      { "SeNBModificationRequestAcknowledge", "x2ap.SeNBModificationRequestAcknowledge_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_x2ap_E_RABs_Admitted_ToBeAdded_ModAckList_PDU,
      { "E-RABs-Admitted-ToBeAdded-ModAckList", "x2ap.E_RABs_Admitted_ToBeAdded_ModAckList",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_x2ap_E_RABs_Admitted_ToBeAdded_ModAckItem_PDU,
      { "E-RABs-Admitted-ToBeAdded-ModAckItem", "x2ap.E_RABs_Admitted_ToBeAdded_ModAckItem",
        FT_UINT32, BASE_DEC, VALS(x2ap_E_RABs_Admitted_ToBeAdded_ModAckItem_vals), 0,
        NULL, HFILL }},
    { &hf_x2ap_E_RABs_Admitted_ToBeModified_ModAckList_PDU,
      { "E-RABs-Admitted-ToBeModified-ModAckList", "x2ap.E_RABs_Admitted_ToBeModified_ModAckList",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_x2ap_E_RABs_Admitted_ToBeModified_ModAckItem_PDU,
      { "E-RABs-Admitted-ToBeModified-ModAckItem", "x2ap.E_RABs_Admitted_ToBeModified_ModAckItem",
        FT_UINT32, BASE_DEC, VALS(x2ap_E_RABs_Admitted_ToBeModified_ModAckItem_vals), 0,
        NULL, HFILL }},
    { &hf_x2ap_E_RABs_Admitted_ToBeReleased_ModAckList_PDU,
      { "E-RABs-Admitted-ToBeReleased-ModAckList", "x2ap.E_RABs_Admitted_ToBeReleased_ModAckList",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_x2ap_E_RABs_Admitted_ToReleased_ModAckItem_PDU,
      { "E-RABs-Admitted-ToReleased-ModAckItem", "x2ap.E_RABs_Admitted_ToReleased_ModAckItem",
        FT_UINT32, BASE_DEC, VALS(x2ap_E_RABs_Admitted_ToReleased_ModAckItem_vals), 0,
        NULL, HFILL }},
    { &hf_x2ap_SeNBModificationRequestReject_PDU,
      { "SeNBModificationRequestReject", "x2ap.SeNBModificationRequestReject_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_x2ap_SeNBModificationRequired_PDU,
      { "SeNBModificationRequired", "x2ap.SeNBModificationRequired_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_x2ap_E_RABs_ToBeReleased_ModReqd_PDU,
      { "E-RABs-ToBeReleased-ModReqd", "x2ap.E_RABs_ToBeReleased_ModReqd",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_x2ap_E_RABs_ToBeReleased_ModReqdItem_PDU,
      { "E-RABs-ToBeReleased-ModReqdItem", "x2ap.E_RABs_ToBeReleased_ModReqdItem_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_x2ap_SeNBModificationConfirm_PDU,
      { "SeNBModificationConfirm", "x2ap.SeNBModificationConfirm_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_x2ap_SeNBModificationRefuse_PDU,
      { "SeNBModificationRefuse", "x2ap.SeNBModificationRefuse_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_x2ap_SeNBReleaseRequest_PDU,
      { "SeNBReleaseRequest", "x2ap.SeNBReleaseRequest_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_x2ap_E_RABs_ToBeReleased_List_RelReq_PDU,
      { "E-RABs-ToBeReleased-List-RelReq", "x2ap.E_RABs_ToBeReleased_List_RelReq",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_x2ap_E_RABs_ToBeReleased_RelReqItem_PDU,
      { "E-RABs-ToBeReleased-RelReqItem", "x2ap.E_RABs_ToBeReleased_RelReqItem",
        FT_UINT32, BASE_DEC, VALS(x2ap_E_RABs_ToBeReleased_RelReqItem_vals), 0,
        NULL, HFILL }},
    { &hf_x2ap_SeNBReleaseRequired_PDU,
      { "SeNBReleaseRequired", "x2ap.SeNBReleaseRequired_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_x2ap_SeNBReleaseConfirm_PDU,
      { "SeNBReleaseConfirm", "x2ap.SeNBReleaseConfirm_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_x2ap_E_RABs_ToBeReleased_List_RelConf_PDU,
      { "E-RABs-ToBeReleased-List-RelConf", "x2ap.E_RABs_ToBeReleased_List_RelConf",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_x2ap_E_RABs_ToBeReleased_RelConfItem_PDU,
      { "E-RABs-ToBeReleased-RelConfItem", "x2ap.E_RABs_ToBeReleased_RelConfItem",
        FT_UINT32, BASE_DEC, VALS(x2ap_E_RABs_ToBeReleased_RelConfItem_vals), 0,
        NULL, HFILL }},
    { &hf_x2ap_SeNBCounterCheckRequest_PDU,
      { "SeNBCounterCheckRequest", "x2ap.SeNBCounterCheckRequest_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_x2ap_E_RABs_SubjectToCounterCheck_List_PDU,
      { "E-RABs-SubjectToCounterCheck-List", "x2ap.E_RABs_SubjectToCounterCheck_List",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_x2ap_E_RABs_SubjectToCounterCheckItem_PDU,
      { "E-RABs-SubjectToCounterCheckItem", "x2ap.E_RABs_SubjectToCounterCheckItem_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_x2ap_X2RemovalRequest_PDU,
      { "X2RemovalRequest", "x2ap.X2RemovalRequest_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_x2ap_X2RemovalResponse_PDU,
      { "X2RemovalResponse", "x2ap.X2RemovalResponse_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_x2ap_X2RemovalFailure_PDU,
      { "X2RemovalFailure", "x2ap.X2RemovalFailure_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_x2ap_RetrieveUEContextRequest_PDU,
      { "RetrieveUEContextRequest", "x2ap.RetrieveUEContextRequest_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_x2ap_RetrieveUEContextResponse_PDU,
      { "RetrieveUEContextResponse", "x2ap.RetrieveUEContextResponse_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_x2ap_UE_ContextInformationRetrieve_PDU,
      { "UE-ContextInformationRetrieve", "x2ap.UE_ContextInformationRetrieve_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_x2ap_E_RABs_ToBeSetupRetrieve_Item_PDU,
      { "E-RABs-ToBeSetupRetrieve-Item", "x2ap.E_RABs_ToBeSetupRetrieve_Item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_x2ap_RetrieveUEContextFailure_PDU,
      { "RetrieveUEContextFailure", "x2ap.RetrieveUEContextFailure_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_x2ap_X2AP_PDU_PDU,
      { "X2AP-PDU", "x2ap.X2AP_PDU",
        FT_UINT32, BASE_DEC, VALS(x2ap_X2AP_PDU_vals), 0,
        NULL, HFILL }},
    { &hf_x2ap_local,
      { "local", "x2ap.local",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_maxPrivateIEs", HFILL }},
    { &hf_x2ap_global,
      { "global", "x2ap.global",
        FT_OID, BASE_NONE, NULL, 0,
        "OBJECT_IDENTIFIER", HFILL }},
    { &hf_x2ap_ProtocolIE_Container_item,
      { "ProtocolIE-Field", "x2ap.ProtocolIE_Field_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_x2ap_id,
      { "id", "x2ap.id",
        FT_UINT32, BASE_DEC|BASE_EXT_STRING, &x2ap_ProtocolIE_ID_vals_ext, 0,
        "ProtocolIE_ID", HFILL }},
    { &hf_x2ap_criticality,
      { "criticality", "x2ap.criticality",
        FT_UINT32, BASE_DEC, VALS(x2ap_Criticality_vals), 0,
        NULL, HFILL }},
    { &hf_x2ap_protocolIE_Field_value,
      { "value", "x2ap.value_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "ProtocolIE_Field_value", HFILL }},
    { &hf_x2ap_ProtocolExtensionContainer_item,
      { "ProtocolExtensionField", "x2ap.ProtocolExtensionField_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_x2ap_extension_id,
      { "id", "x2ap.id",
        FT_UINT32, BASE_DEC|BASE_EXT_STRING, &x2ap_ProtocolIE_ID_vals_ext, 0,
        "ProtocolIE_ID", HFILL }},
    { &hf_x2ap_extensionValue,
      { "extensionValue", "x2ap.extensionValue_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_x2ap_PrivateIE_Container_item,
      { "PrivateIE-Field", "x2ap.PrivateIE_Field_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_x2ap_private_id,
      { "id", "x2ap.id",
        FT_UINT32, BASE_DEC, VALS(x2ap_PrivateIE_ID_vals), 0,
        "PrivateIE_ID", HFILL }},
    { &hf_x2ap_privateIE_Field_value,
      { "value", "x2ap.value_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "PrivateIE_Field_value", HFILL }},
    { &hf_x2ap_fdd,
      { "fdd", "x2ap.fdd_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "ABSInformationFDD", HFILL }},
    { &hf_x2ap_tdd,
      { "tdd", "x2ap.tdd_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "ABSInformationTDD", HFILL }},
    { &hf_x2ap_abs_inactive,
      { "abs-inactive", "x2ap.abs_inactive_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_x2ap_abs_pattern_info,
      { "abs-pattern-info", "x2ap.abs_pattern_info",
        FT_BYTES, BASE_NONE, NULL, 0,
        "BIT_STRING_SIZE_40", HFILL }},
    { &hf_x2ap_numberOfCellSpecificAntennaPorts,
      { "numberOfCellSpecificAntennaPorts", "x2ap.numberOfCellSpecificAntennaPorts",
        FT_UINT32, BASE_DEC, VALS(x2ap_T_numberOfCellSpecificAntennaPorts_vals), 0,
        NULL, HFILL }},
    { &hf_x2ap_measurement_subset,
      { "measurement-subset", "x2ap.measurement_subset",
        FT_BYTES, BASE_NONE, NULL, 0,
        "BIT_STRING_SIZE_40", HFILL }},
    { &hf_x2ap_iE_Extensions,
      { "iE-Extensions", "x2ap.iE_Extensions",
        FT_UINT32, BASE_DEC, NULL, 0,
        "ProtocolExtensionContainer", HFILL }},
    { &hf_x2ap_abs_pattern_info_01,
      { "abs-pattern-info", "x2ap.abs_pattern_info",
        FT_BYTES, BASE_NONE, NULL, 0,
        "BIT_STRING_SIZE_1_70_", HFILL }},
    { &hf_x2ap_numberOfCellSpecificAntennaPorts_01,
      { "numberOfCellSpecificAntennaPorts", "x2ap.numberOfCellSpecificAntennaPorts",
        FT_UINT32, BASE_DEC, VALS(x2ap_T_numberOfCellSpecificAntennaPorts_01_vals), 0,
        "T_numberOfCellSpecificAntennaPorts_01", HFILL }},
    { &hf_x2ap_measurement_subset_01,
      { "measurement-subset", "x2ap.measurement_subset",
        FT_BYTES, BASE_NONE, NULL, 0,
        "BIT_STRING_SIZE_1_70_", HFILL }},
    { &hf_x2ap_dL_ABS_status,
      { "dL-ABS-status", "x2ap.dL_ABS_status",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_x2ap_usableABSInformation,
      { "usableABSInformation", "x2ap.usableABSInformation",
        FT_UINT32, BASE_DEC, VALS(x2ap_UsableABSInformation_vals), 0,
        NULL, HFILL }},
    { &hf_x2ap_additionalspecialSubframePatterns,
      { "additionalspecialSubframePatterns", "x2ap.additionalspecialSubframePatterns",
        FT_UINT32, BASE_DEC, VALS(x2ap_AdditionalSpecialSubframePatterns_vals), 0,
        NULL, HFILL }},
    { &hf_x2ap_cyclicPrefixDL,
      { "cyclicPrefixDL", "x2ap.cyclicPrefixDL",
        FT_UINT32, BASE_DEC, VALS(x2ap_CyclicPrefixDL_vals), 0,
        NULL, HFILL }},
    { &hf_x2ap_cyclicPrefixUL,
      { "cyclicPrefixUL", "x2ap.cyclicPrefixUL",
        FT_UINT32, BASE_DEC, VALS(x2ap_CyclicPrefixUL_vals), 0,
        NULL, HFILL }},
    { &hf_x2ap_priorityLevel,
      { "priorityLevel", "x2ap.priorityLevel",
        FT_UINT32, BASE_DEC, VALS(x2ap_PriorityLevel_vals), 0,
        NULL, HFILL }},
    { &hf_x2ap_pre_emptionCapability,
      { "pre-emptionCapability", "x2ap.pre_emptionCapability",
        FT_UINT32, BASE_DEC, VALS(x2ap_Pre_emptionCapability_vals), 0,
        NULL, HFILL }},
    { &hf_x2ap_pre_emptionVulnerability,
      { "pre-emptionVulnerability", "x2ap.pre_emptionVulnerability",
        FT_UINT32, BASE_DEC, VALS(x2ap_Pre_emptionVulnerability_vals), 0,
        NULL, HFILL }},
    { &hf_x2ap_cellBased,
      { "cellBased", "x2ap.cellBased_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "CellBasedMDT", HFILL }},
    { &hf_x2ap_tABased,
      { "tABased", "x2ap.tABased_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "TABasedMDT", HFILL }},
    { &hf_x2ap_pLMNWide,
      { "pLMNWide", "x2ap.pLMNWide_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_x2ap_tAIBased,
      { "tAIBased", "x2ap.tAIBased_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "TAIBasedMDT", HFILL }},
    { &hf_x2ap_key_eNodeB_star,
      { "key-eNodeB-star", "x2ap.key_eNodeB_star",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_x2ap_nextHopChainingCount,
      { "nextHopChainingCount", "x2ap.nextHopChainingCount",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_x2ap_BroadcastPLMNs_Item_item,
      { "PLMN-Identity", "x2ap.PLMN_Identity",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_x2ap_radioNetwork,
      { "radioNetwork", "x2ap.radioNetwork",
        FT_UINT32, BASE_DEC|BASE_EXT_STRING, &x2ap_CauseRadioNetwork_vals_ext, 0,
        "CauseRadioNetwork", HFILL }},
    { &hf_x2ap_transport,
      { "transport", "x2ap.transport",
        FT_UINT32, BASE_DEC, VALS(x2ap_CauseTransport_vals), 0,
        "CauseTransport", HFILL }},
    { &hf_x2ap_protocol,
      { "protocol", "x2ap.protocol",
        FT_UINT32, BASE_DEC, VALS(x2ap_CauseProtocol_vals), 0,
        "CauseProtocol", HFILL }},
    { &hf_x2ap_misc,
      { "misc", "x2ap.misc",
        FT_UINT32, BASE_DEC, VALS(x2ap_CauseMisc_vals), 0,
        "CauseMisc", HFILL }},
    { &hf_x2ap_cellIdListforMDT,
      { "cellIdListforMDT", "x2ap.cellIdListforMDT",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_x2ap_CellIdListforMDT_item,
      { "ECGI", "x2ap.ECGI_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_x2ap_replacingCellsList,
      { "replacingCellsList", "x2ap.replacingCellsList",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_x2ap_cell_Size,
      { "cell-Size", "x2ap.cell_Size",
        FT_UINT32, BASE_DEC, VALS(x2ap_Cell_Size_vals), 0,
        NULL, HFILL }},
    { &hf_x2ap_CoMPHypothesisSet_item,
      { "CoMPHypothesisSetItem", "x2ap.CoMPHypothesisSetItem_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_x2ap_coMPCellID,
      { "coMPCellID", "x2ap.coMPCellID_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "ECGI", HFILL }},
    { &hf_x2ap_coMPHypothesis,
      { "coMPHypothesis", "x2ap.coMPHypothesis",
        FT_BYTES, BASE_NONE, NULL, 0,
        "BIT_STRING_SIZE_6_4400_", HFILL }},
    { &hf_x2ap_coMPInformationItem,
      { "coMPInformationItem", "x2ap.coMPInformationItem",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_x2ap_coMPInformationStartTime,
      { "coMPInformationStartTime", "x2ap.coMPInformationStartTime",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_x2ap_CoMPInformationItem_item,
      { "CoMPInformationItem item", "x2ap.CoMPInformationItem_item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_x2ap_coMPHypothesisSet,
      { "coMPHypothesisSet", "x2ap.coMPHypothesisSet",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_x2ap_benefitMetric,
      { "benefitMetric", "x2ap.benefitMetric",
        FT_INT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_x2ap_CoMPInformationStartTime_item,
      { "CoMPInformationStartTime item", "x2ap.CoMPInformationStartTime_item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_x2ap_startSFN,
      { "startSFN", "x2ap.startSFN",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_1023_", HFILL }},
    { &hf_x2ap_startSubframeNumber,
      { "startSubframeNumber", "x2ap.startSubframeNumber",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_9_", HFILL }},
    { &hf_x2ap_cellCapacityClassValue,
      { "cellCapacityClassValue", "x2ap.cellCapacityClassValue",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_x2ap_capacityValue,
      { "capacityValue", "x2ap.capacityValue",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_x2ap_dL_CompositeAvailableCapacity,
      { "dL-CompositeAvailableCapacity", "x2ap.dL_CompositeAvailableCapacity_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "CompositeAvailableCapacity", HFILL }},
    { &hf_x2ap_uL_CompositeAvailableCapacity,
      { "uL-CompositeAvailableCapacity", "x2ap.uL_CompositeAvailableCapacity_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "CompositeAvailableCapacity", HFILL }},
    { &hf_x2ap_pDCP_SN,
      { "pDCP-SN", "x2ap.pDCP_SN",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_x2ap_hFN,
      { "hFN", "x2ap.hFN",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_x2ap_pDCP_SNExtended,
      { "pDCP-SNExtended", "x2ap.pDCP_SNExtended",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_x2ap_hFNModified,
      { "hFNModified", "x2ap.hFNModified",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_x2ap_pDCP_SNlength18,
      { "pDCP-SNlength18", "x2ap.pDCP_SNlength18",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_x2ap_hFNforPDCP_SNlength18,
      { "hFNforPDCP-SNlength18", "x2ap.hFNforPDCP_SNlength18",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_x2ap_CoverageModificationList_item,
      { "CoverageModification-Item", "x2ap.CoverageModification_Item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_x2ap_eCGI,
      { "eCGI", "x2ap.eCGI_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_x2ap_coverageState,
      { "coverageState", "x2ap.coverageState",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_15_", HFILL }},
    { &hf_x2ap_cellDeploymentStatusIndicator,
      { "cellDeploymentStatusIndicator", "x2ap.cellDeploymentStatusIndicator",
        FT_UINT32, BASE_DEC, VALS(x2ap_CellDeploymentStatusIndicator_vals), 0,
        NULL, HFILL }},
    { &hf_x2ap_cellReplacingInfo,
      { "cellReplacingInfo", "x2ap.cellReplacingInfo_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_x2ap_procedureCode,
      { "procedureCode", "x2ap.procedureCode",
        FT_UINT32, BASE_DEC|BASE_EXT_STRING, &x2ap_ProcedureCode_vals_ext, 0,
        NULL, HFILL }},
    { &hf_x2ap_triggeringMessage,
      { "triggeringMessage", "x2ap.triggeringMessage",
        FT_UINT32, BASE_DEC, VALS(x2ap_TriggeringMessage_vals), 0,
        NULL, HFILL }},
    { &hf_x2ap_procedureCriticality,
      { "procedureCriticality", "x2ap.procedureCriticality",
        FT_UINT32, BASE_DEC, VALS(x2ap_Criticality_vals), 0,
        "Criticality", HFILL }},
    { &hf_x2ap_iEsCriticalityDiagnostics,
      { "iEsCriticalityDiagnostics", "x2ap.iEsCriticalityDiagnostics",
        FT_UINT32, BASE_DEC, NULL, 0,
        "CriticalityDiagnostics_IE_List", HFILL }},
    { &hf_x2ap_CriticalityDiagnostics_IE_List_item,
      { "CriticalityDiagnostics-IE-List item", "x2ap.CriticalityDiagnostics_IE_List_item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_x2ap_iECriticality,
      { "iECriticality", "x2ap.iECriticality",
        FT_UINT32, BASE_DEC, VALS(x2ap_Criticality_vals), 0,
        "Criticality", HFILL }},
    { &hf_x2ap_iE_ID,
      { "iE-ID", "x2ap.iE_ID",
        FT_UINT32, BASE_DEC|BASE_EXT_STRING, &x2ap_ProtocolIE_ID_vals_ext, 0,
        "ProtocolIE_ID", HFILL }},
    { &hf_x2ap_typeOfError,
      { "typeOfError", "x2ap.typeOfError",
        FT_UINT32, BASE_DEC, VALS(x2ap_TypeOfError_vals), 0,
        NULL, HFILL }},
    { &hf_x2ap_CSIReportList_item,
      { "CSIReportList item", "x2ap.CSIReportList_item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_x2ap_uEID,
      { "uEID", "x2ap.uEID",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_x2ap_cSIReportPerCSIProcess,
      { "cSIReportPerCSIProcess", "x2ap.cSIReportPerCSIProcess",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_x2ap_CSIReportPerCSIProcess_item,
      { "CSIReportPerCSIProcess item", "x2ap.CSIReportPerCSIProcess_item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_x2ap_cSIProcessConfigurationIndex,
      { "cSIProcessConfigurationIndex", "x2ap.cSIProcessConfigurationIndex",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_1_7_", HFILL }},
    { &hf_x2ap_cSIReportPerCSIProcessItem,
      { "cSIReportPerCSIProcessItem", "x2ap.cSIReportPerCSIProcessItem",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_x2ap_CSIReportPerCSIProcessItem_item,
      { "CSIReportPerCSIProcessItem item", "x2ap.CSIReportPerCSIProcessItem_item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_x2ap_rI,
      { "rI", "x2ap.rI",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_1_8_", HFILL }},
    { &hf_x2ap_widebandCQI,
      { "widebandCQI", "x2ap.widebandCQI_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_x2ap_subbandSize,
      { "subbandSize", "x2ap.subbandSize",
        FT_UINT32, BASE_DEC, VALS(x2ap_SubbandSize_vals), 0,
        NULL, HFILL }},
    { &hf_x2ap_subbandCQIList,
      { "subbandCQIList", "x2ap.subbandCQIList",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_x2ap_naics_active,
      { "naics-active", "x2ap.naics_active_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "DynamicNAICSInformation", HFILL }},
    { &hf_x2ap_naics_inactive,
      { "naics-inactive", "x2ap.naics_inactive_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_x2ap_transmissionModes,
      { "transmissionModes", "x2ap.transmissionModes",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_x2ap_pB_information,
      { "pB-information", "x2ap.pB_information",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_3", HFILL }},
    { &hf_x2ap_pA_list,
      { "pA-list", "x2ap.pA_list",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_SIZE_0_maxnoofPA_OF_PA_Values", HFILL }},
    { &hf_x2ap_pA_list_item,
      { "PA-Values", "x2ap.PA_Values",
        FT_UINT32, BASE_DEC, VALS(x2ap_PA_Values_vals), 0,
        NULL, HFILL }},
    { &hf_x2ap_pLMN_Identity,
      { "pLMN-Identity", "x2ap.pLMN_Identity",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_x2ap_eUTRANcellIdentifier,
      { "eUTRANcellIdentifier", "x2ap.eUTRANcellIdentifier",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_x2ap_enhancedRNTPBitmap,
      { "enhancedRNTPBitmap", "x2ap.enhancedRNTPBitmap",
        FT_BYTES, BASE_NONE, NULL, 0,
        "BIT_STRING_SIZE_12_8800_", HFILL }},
    { &hf_x2ap_rNTP_High_Power_Threshold,
      { "rNTP-High-Power-Threshold", "x2ap.rNTP_High_Power_Threshold",
        FT_UINT32, BASE_DEC, VALS(x2ap_RNTP_Threshold_vals), 0,
        "RNTP_Threshold", HFILL }},
    { &hf_x2ap_enhancedRNTPStartTime,
      { "enhancedRNTPStartTime", "x2ap.enhancedRNTPStartTime_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_x2ap_macro_eNB_ID,
      { "macro-eNB-ID", "x2ap.macro_eNB_ID",
        FT_BYTES, BASE_NONE, NULL, 0,
        "BIT_STRING_SIZE_20", HFILL }},
    { &hf_x2ap_home_eNB_ID,
      { "home-eNB-ID", "x2ap.home_eNB_ID",
        FT_BYTES, BASE_NONE, NULL, 0,
        "BIT_STRING_SIZE_28", HFILL }},
    { &hf_x2ap_EPLMNs_item,
      { "PLMN-Identity", "x2ap.PLMN_Identity",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_x2ap_qCI,
      { "qCI", "x2ap.qCI",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_x2ap_allocationAndRetentionPriority,
      { "allocationAndRetentionPriority", "x2ap.allocationAndRetentionPriority_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_x2ap_gbrQosInformation,
      { "gbrQosInformation", "x2ap.gbrQosInformation_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "GBR_QosInformation", HFILL }},
    { &hf_x2ap_E_RAB_List_item,
      { "ProtocolIE-Single-Container", "x2ap.ProtocolIE_Single_Container_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_x2ap_e_RAB_ID,
      { "e-RAB-ID", "x2ap.e_RAB_ID",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_x2ap_cause,
      { "cause", "x2ap.cause",
        FT_UINT32, BASE_DEC, VALS(x2ap_Cause_vals), 0,
        NULL, HFILL }},
    { &hf_x2ap_fDD,
      { "fDD", "x2ap.fDD_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "FDD_Info", HFILL }},
    { &hf_x2ap_tDD,
      { "tDD", "x2ap.tDD_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "TDD_Info", HFILL }},
    { &hf_x2ap_expectedActivity,
      { "expectedActivity", "x2ap.expectedActivity_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "ExpectedUEActivityBehaviour", HFILL }},
    { &hf_x2ap_expectedHOInterval,
      { "expectedHOInterval", "x2ap.expectedHOInterval",
        FT_UINT32, BASE_DEC, VALS(x2ap_ExpectedHOInterval_vals), 0,
        NULL, HFILL }},
    { &hf_x2ap_expectedActivityPeriod,
      { "expectedActivityPeriod", "x2ap.expectedActivityPeriod",
        FT_UINT32, BASE_DEC|BASE_UNIT_STRING, &units_seconds, 0,
        NULL, HFILL }},
    { &hf_x2ap_expectedIdlePeriod,
      { "expectedIdlePeriod", "x2ap.expectedIdlePeriod",
        FT_UINT32, BASE_DEC|BASE_UNIT_STRING, &units_seconds, 0,
        NULL, HFILL }},
    { &hf_x2ap_sourceofUEActivityBehaviourInformation,
      { "sourceofUEActivityBehaviourInformation", "x2ap.sourceofUEActivityBehaviourInformation",
        FT_UINT32, BASE_DEC, VALS(x2ap_SourceOfUEActivityBehaviourInformation_vals), 0,
        NULL, HFILL }},
    { &hf_x2ap_associatedSubframes,
      { "associatedSubframes", "x2ap.associatedSubframes",
        FT_BYTES, BASE_NONE, NULL, 0,
        "BIT_STRING_SIZE_5", HFILL }},
    { &hf_x2ap_extended_ul_InterferenceOverloadIndication,
      { "extended-ul-InterferenceOverloadIndication", "x2ap.extended_ul_InterferenceOverloadIndication",
        FT_UINT32, BASE_DEC, NULL, 0,
        "UL_InterferenceOverloadIndication", HFILL }},
    { &hf_x2ap_uL_EARFCN,
      { "uL-EARFCN", "x2ap.uL_EARFCN",
        FT_UINT32, BASE_DEC, NULL, 0,
        "EARFCN", HFILL }},
    { &hf_x2ap_dL_EARFCN,
      { "dL-EARFCN", "x2ap.dL_EARFCN",
        FT_UINT32, BASE_DEC, NULL, 0,
        "EARFCN", HFILL }},
    { &hf_x2ap_uL_Transmission_Bandwidth,
      { "uL-Transmission-Bandwidth", "x2ap.uL_Transmission_Bandwidth",
        FT_UINT32, BASE_DEC, VALS(x2ap_Transmission_Bandwidth_vals), 0,
        "Transmission_Bandwidth", HFILL }},
    { &hf_x2ap_dL_Transmission_Bandwidth,
      { "dL-Transmission-Bandwidth", "x2ap.dL_Transmission_Bandwidth",
        FT_UINT32, BASE_DEC, VALS(x2ap_Transmission_Bandwidth_vals), 0,
        "Transmission_Bandwidth", HFILL }},
    { &hf_x2ap_ForbiddenTAs_item,
      { "ForbiddenTAs-Item", "x2ap.ForbiddenTAs_Item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_x2ap_forbiddenTACs,
      { "forbiddenTACs", "x2ap.forbiddenTACs",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_x2ap_ForbiddenTACs_item,
      { "TAC", "x2ap.TAC",
        FT_UINT16, BASE_DEC_HEX, NULL, 0,
        NULL, HFILL }},
    { &hf_x2ap_ForbiddenLAs_item,
      { "ForbiddenLAs-Item", "x2ap.ForbiddenLAs_Item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_x2ap_forbiddenLACs,
      { "forbiddenLACs", "x2ap.forbiddenLACs",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_x2ap_ForbiddenLACs_item,
      { "LAC", "x2ap.LAC",
        FT_UINT16, BASE_DEC_HEX, NULL, 0,
        NULL, HFILL }},
    { &hf_x2ap_e_RAB_MaximumBitrateDL,
      { "e-RAB-MaximumBitrateDL", "x2ap.e_RAB_MaximumBitrateDL",
        FT_UINT64, BASE_DEC|BASE_UNIT_STRING, &units_bit_sec, 0,
        "BitRate", HFILL }},
    { &hf_x2ap_e_RAB_MaximumBitrateUL,
      { "e-RAB-MaximumBitrateUL", "x2ap.e_RAB_MaximumBitrateUL",
        FT_UINT64, BASE_DEC|BASE_UNIT_STRING, &units_bit_sec, 0,
        "BitRate", HFILL }},
    { &hf_x2ap_e_RAB_GuaranteedBitrateDL,
      { "e-RAB-GuaranteedBitrateDL", "x2ap.e_RAB_GuaranteedBitrateDL",
        FT_UINT64, BASE_DEC|BASE_UNIT_STRING, &units_bit_sec, 0,
        "BitRate", HFILL }},
    { &hf_x2ap_e_RAB_GuaranteedBitrateUL,
      { "e-RAB-GuaranteedBitrateUL", "x2ap.e_RAB_GuaranteedBitrateUL",
        FT_UINT64, BASE_DEC|BASE_UNIT_STRING, &units_bit_sec, 0,
        "BitRate", HFILL }},
    { &hf_x2ap_eNB_ID,
      { "eNB-ID", "x2ap.eNB_ID",
        FT_UINT32, BASE_DEC, VALS(x2ap_ENB_ID_vals), 0,
        NULL, HFILL }},
    { &hf_x2ap_transportLayerAddress,
      { "transportLayerAddress", "x2ap.transportLayerAddress",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_x2ap_gTP_TEID,
      { "gTP-TEID", "x2ap.gTP_TEID",
        FT_BYTES, BASE_NONE, NULL, 0,
        "GTP_TEI", HFILL }},
    { &hf_x2ap_GUGroupIDList_item,
      { "GU-Group-ID", "x2ap.GU_Group_ID_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_x2ap_mME_Group_ID,
      { "mME-Group-ID", "x2ap.mME_Group_ID",
        FT_UINT16, BASE_DEC_HEX, NULL, 0,
        NULL, HFILL }},
    { &hf_x2ap_gU_Group_ID,
      { "gU-Group-ID", "x2ap.gU_Group_ID_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_x2ap_mME_Code,
      { "mME-Code", "x2ap.mME_Code",
        FT_UINT8, BASE_DEC_HEX, NULL, 0,
        NULL, HFILL }},
    { &hf_x2ap_servingPLMN,
      { "servingPLMN", "x2ap.servingPLMN",
        FT_BYTES, BASE_NONE, NULL, 0,
        "PLMN_Identity", HFILL }},
    { &hf_x2ap_equivalentPLMNs,
      { "equivalentPLMNs", "x2ap.equivalentPLMNs",
        FT_UINT32, BASE_DEC, NULL, 0,
        "EPLMNs", HFILL }},
    { &hf_x2ap_forbiddenTAs,
      { "forbiddenTAs", "x2ap.forbiddenTAs",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_x2ap_forbiddenLAs,
      { "forbiddenLAs", "x2ap.forbiddenLAs",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_x2ap_forbiddenInterRATs,
      { "forbiddenInterRATs", "x2ap.forbiddenInterRATs",
        FT_UINT32, BASE_DEC, VALS(x2ap_ForbiddenInterRATs_vals), 0,
        NULL, HFILL }},
    { &hf_x2ap_dLHWLoadIndicator,
      { "dLHWLoadIndicator", "x2ap.dLHWLoadIndicator",
        FT_UINT32, BASE_DEC, VALS(x2ap_LoadIndicator_vals), 0,
        "LoadIndicator", HFILL }},
    { &hf_x2ap_uLHWLoadIndicator,
      { "uLHWLoadIndicator", "x2ap.uLHWLoadIndicator",
        FT_UINT32, BASE_DEC, VALS(x2ap_LoadIndicator_vals), 0,
        "LoadIndicator", HFILL }},
    { &hf_x2ap_e_UTRAN_Cell,
      { "e-UTRAN-Cell", "x2ap.e_UTRAN_Cell_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "LastVisitedEUTRANCellInformation", HFILL }},
    { &hf_x2ap_uTRAN_Cell,
      { "uTRAN-Cell", "x2ap.uTRAN_Cell",
        FT_BYTES, BASE_NONE, NULL, 0,
        "LastVisitedUTRANCellInformation", HFILL }},
    { &hf_x2ap_gERAN_Cell,
      { "gERAN-Cell", "x2ap.gERAN_Cell",
        FT_UINT32, BASE_DEC, VALS(x2ap_LastVisitedGERANCellInformation_vals), 0,
        "LastVisitedGERANCellInformation", HFILL }},
    { &hf_x2ap_global_Cell_ID,
      { "global-Cell-ID", "x2ap.global_Cell_ID_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "ECGI", HFILL }},
    { &hf_x2ap_cellType,
      { "cellType", "x2ap.cellType_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_x2ap_time_UE_StayedInCell,
      { "time-UE-StayedInCell", "x2ap.time_UE_StayedInCell",
        FT_UINT32, BASE_DEC|BASE_UNIT_STRING, &units_seconds, 0,
        NULL, HFILL }},
    { &hf_x2ap_undefined,
      { "undefined", "x2ap.undefined_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_x2ap_eventType,
      { "eventType", "x2ap.eventType",
        FT_UINT32, BASE_DEC, VALS(x2ap_EventType_vals), 0,
        NULL, HFILL }},
    { &hf_x2ap_reportArea,
      { "reportArea", "x2ap.reportArea",
        FT_UINT32, BASE_DEC, VALS(x2ap_ReportArea_vals), 0,
        NULL, HFILL }},
    { &hf_x2ap_reportInterval,
      { "reportInterval", "x2ap.reportInterval",
        FT_UINT32, BASE_DEC, VALS(x2ap_ReportIntervalMDT_vals), 0,
        "ReportIntervalMDT", HFILL }},
    { &hf_x2ap_reportAmount,
      { "reportAmount", "x2ap.reportAmount",
        FT_UINT32, BASE_DEC, VALS(x2ap_ReportAmountMDT_vals), 0,
        "ReportAmountMDT", HFILL }},
    { &hf_x2ap_measurementThreshold,
      { "measurementThreshold", "x2ap.measurementThreshold",
        FT_UINT32, BASE_DEC, VALS(x2ap_MeasurementThresholdA2_vals), 0,
        "MeasurementThresholdA2", HFILL }},
    { &hf_x2ap_m3period,
      { "m3period", "x2ap.m3period",
        FT_UINT32, BASE_DEC, VALS(x2ap_M3period_vals), 0,
        NULL, HFILL }},
    { &hf_x2ap_m4period,
      { "m4period", "x2ap.m4period",
        FT_UINT32, BASE_DEC, VALS(x2ap_M4period_vals), 0,
        NULL, HFILL }},
    { &hf_x2ap_m4_links_to_log,
      { "m4-links-to-log", "x2ap.m4_links_to_log",
        FT_UINT32, BASE_DEC, VALS(x2ap_Links_to_log_vals), 0,
        "Links_to_log", HFILL }},
    { &hf_x2ap_m5period,
      { "m5period", "x2ap.m5period",
        FT_UINT32, BASE_DEC, VALS(x2ap_M5period_vals), 0,
        NULL, HFILL }},
    { &hf_x2ap_m5_links_to_log,
      { "m5-links-to-log", "x2ap.m5_links_to_log",
        FT_UINT32, BASE_DEC, VALS(x2ap_Links_to_log_vals), 0,
        "Links_to_log", HFILL }},
    { &hf_x2ap_m6report_interval,
      { "m6report-interval", "x2ap.m6report_interval",
        FT_UINT32, BASE_DEC, VALS(x2ap_M6report_interval_vals), 0,
        NULL, HFILL }},
    { &hf_x2ap_m6delay_threshold,
      { "m6delay-threshold", "x2ap.m6delay_threshold",
        FT_UINT32, BASE_DEC, VALS(x2ap_M6delay_threshold_vals), 0,
        NULL, HFILL }},
    { &hf_x2ap_m6_links_to_log,
      { "m6-links-to-log", "x2ap.m6_links_to_log",
        FT_UINT32, BASE_DEC, VALS(x2ap_Links_to_log_vals), 0,
        "Links_to_log", HFILL }},
    { &hf_x2ap_m7period,
      { "m7period", "x2ap.m7period",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_x2ap_m7_links_to_log,
      { "m7-links-to-log", "x2ap.m7_links_to_log",
        FT_UINT32, BASE_DEC, VALS(x2ap_Links_to_log_vals), 0,
        "Links_to_log", HFILL }},
    { &hf_x2ap_mdt_Activation,
      { "mdt-Activation", "x2ap.mdt_Activation",
        FT_UINT32, BASE_DEC, VALS(x2ap_MDT_Activation_vals), 0,
        NULL, HFILL }},
    { &hf_x2ap_areaScopeOfMDT,
      { "areaScopeOfMDT", "x2ap.areaScopeOfMDT",
        FT_UINT32, BASE_DEC, VALS(x2ap_AreaScopeOfMDT_vals), 0,
        NULL, HFILL }},
    { &hf_x2ap_measurementsToActivate,
      { "measurementsToActivate", "x2ap.measurementsToActivate",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_x2ap_m1reportingTrigger,
      { "m1reportingTrigger", "x2ap.m1reportingTrigger",
        FT_UINT32, BASE_DEC, VALS(x2ap_M1ReportingTrigger_vals), 0,
        NULL, HFILL }},
    { &hf_x2ap_m1thresholdeventA2,
      { "m1thresholdeventA2", "x2ap.m1thresholdeventA2_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_x2ap_m1periodicReporting,
      { "m1periodicReporting", "x2ap.m1periodicReporting_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_x2ap_MDTPLMNList_item,
      { "PLMN-Identity", "x2ap.PLMN_Identity",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_x2ap_threshold_RSRP,
      { "threshold-RSRP", "x2ap.threshold_RSRP",
        FT_UINT32, BASE_CUSTOM, CF_FUNC(x2ap_Threshold_RSRP_fmt), 0,
        NULL, HFILL }},
    { &hf_x2ap_threshold_RSRQ,
      { "threshold-RSRQ", "x2ap.threshold_RSRQ",
        FT_UINT32, BASE_CUSTOM, CF_FUNC(x2ap_Threshold_RSRQ_fmt), 0,
        NULL, HFILL }},
    { &hf_x2ap_MBMS_Service_Area_Identity_List_item,
      { "MBMS-Service-Area-Identity", "x2ap.MBMS_Service_Area_Identity",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_x2ap_MBSFN_Subframe_Infolist_item,
      { "MBSFN-Subframe-Info", "x2ap.MBSFN_Subframe_Info_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_x2ap_radioframeAllocationPeriod,
      { "radioframeAllocationPeriod", "x2ap.radioframeAllocationPeriod",
        FT_UINT32, BASE_DEC, VALS(x2ap_RadioframeAllocationPeriod_vals), 0,
        NULL, HFILL }},
    { &hf_x2ap_radioframeAllocationOffset,
      { "radioframeAllocationOffset", "x2ap.radioframeAllocationOffset",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_x2ap_subframeAllocation,
      { "subframeAllocation", "x2ap.subframeAllocation",
        FT_UINT32, BASE_DEC, VALS(x2ap_SubframeAllocation_vals), 0,
        NULL, HFILL }},
    { &hf_x2ap_handoverTriggerChangeLowerLimit,
      { "handoverTriggerChangeLowerLimit", "x2ap.handoverTriggerChangeLowerLimit",
        FT_INT32, BASE_CUSTOM, CF_FUNC(x2ap_handoverTriggerChange_fmt), 0,
        "INTEGER_M20_20", HFILL }},
    { &hf_x2ap_handoverTriggerChangeUpperLimit,
      { "handoverTriggerChangeUpperLimit", "x2ap.handoverTriggerChangeUpperLimit",
        FT_INT32, BASE_CUSTOM, CF_FUNC(x2ap_handoverTriggerChange_fmt), 0,
        "INTEGER_M20_20", HFILL }},
    { &hf_x2ap_handoverTriggerChange,
      { "handoverTriggerChange", "x2ap.handoverTriggerChange",
        FT_INT32, BASE_CUSTOM, CF_FUNC(x2ap_handoverTriggerChange_fmt), 0,
        "INTEGER_M20_20", HFILL }},
    { &hf_x2ap_MultibandInfoList_item,
      { "BandInfo", "x2ap.BandInfo_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_x2ap_freqBandIndicator,
      { "freqBandIndicator", "x2ap.freqBandIndicator",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_x2ap_Neighbour_Information_item,
      { "Neighbour-Information item", "x2ap.Neighbour_Information_item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_x2ap_pCI,
      { "pCI", "x2ap.pCI",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_x2ap_eARFCN,
      { "eARFCN", "x2ap.eARFCN",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_x2ap_rootSequenceIndex,
      { "rootSequenceIndex", "x2ap.rootSequenceIndex",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_837", HFILL }},
    { &hf_x2ap_zeroCorrelationIndex,
      { "zeroCorrelationIndex", "x2ap.zeroCorrelationIndex",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_15", HFILL }},
    { &hf_x2ap_highSpeedFlag,
      { "highSpeedFlag", "x2ap.highSpeedFlag",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_x2ap_prach_FreqOffset,
      { "prach-FreqOffset", "x2ap.prach_FreqOffset",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_94", HFILL }},
    { &hf_x2ap_prach_ConfigIndex,
      { "prach-ConfigIndex", "x2ap.prach_ConfigIndex",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_63", HFILL }},
    { &hf_x2ap_proSeDirectDiscovery,
      { "proSeDirectDiscovery", "x2ap.proSeDirectDiscovery",
        FT_UINT32, BASE_DEC, VALS(x2ap_ProSeDirectDiscovery_vals), 0,
        NULL, HFILL }},
    { &hf_x2ap_proSeDirectCommunication,
      { "proSeDirectCommunication", "x2ap.proSeDirectCommunication",
        FT_UINT32, BASE_DEC, VALS(x2ap_ProSeDirectCommunication_vals), 0,
        NULL, HFILL }},
    { &hf_x2ap_dL_GBR_PRB_usage,
      { "dL-GBR-PRB-usage", "x2ap.dL_GBR_PRB_usage",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_x2ap_uL_GBR_PRB_usage,
      { "uL-GBR-PRB-usage", "x2ap.uL_GBR_PRB_usage",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_x2ap_dL_non_GBR_PRB_usage,
      { "dL-non-GBR-PRB-usage", "x2ap.dL_non_GBR_PRB_usage",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_x2ap_uL_non_GBR_PRB_usage,
      { "uL-non-GBR-PRB-usage", "x2ap.uL_non_GBR_PRB_usage",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_x2ap_dL_Total_PRB_usage,
      { "dL-Total-PRB-usage", "x2ap.dL_Total_PRB_usage",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_x2ap_uL_Total_PRB_usage,
      { "uL-Total-PRB-usage", "x2ap.uL_Total_PRB_usage",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_x2ap_rNTP_PerPRB,
      { "rNTP-PerPRB", "x2ap.rNTP_PerPRB",
        FT_BYTES, BASE_NONE, NULL, 0,
        "BIT_STRING_SIZE_6_110_", HFILL }},
    { &hf_x2ap_rNTP_Threshold,
      { "rNTP-Threshold", "x2ap.rNTP_Threshold",
        FT_UINT32, BASE_DEC, VALS(x2ap_RNTP_Threshold_vals), 0,
        NULL, HFILL }},
    { &hf_x2ap_numberOfCellSpecificAntennaPorts_02,
      { "numberOfCellSpecificAntennaPorts", "x2ap.numberOfCellSpecificAntennaPorts",
        FT_UINT32, BASE_DEC, VALS(x2ap_T_numberOfCellSpecificAntennaPorts_02_vals), 0,
        "T_numberOfCellSpecificAntennaPorts_02", HFILL }},
    { &hf_x2ap_p_B,
      { "p-B", "x2ap.p_B",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_3_", HFILL }},
    { &hf_x2ap_pDCCH_InterferenceImpact,
      { "pDCCH-InterferenceImpact", "x2ap.pDCCH_InterferenceImpact",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_4_", HFILL }},
    { &hf_x2ap_ReplacingCellsList_item,
      { "ReplacingCellsList-Item", "x2ap.ReplacingCellsList_Item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_x2ap_non_truncated,
      { "non-truncated", "x2ap.non_truncated",
        FT_BYTES, BASE_NONE, NULL, 0,
        "BIT_STRING_SIZE_40", HFILL }},
    { &hf_x2ap_truncated,
      { "truncated", "x2ap.truncated",
        FT_BYTES, BASE_NONE, NULL, 0,
        "BIT_STRING_SIZE_24", HFILL }},
    { &hf_x2ap_RSRPMeasurementResult_item,
      { "RSRPMeasurementResult item", "x2ap.RSRPMeasurementResult_item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_x2ap_rSRPCellID,
      { "rSRPCellID", "x2ap.rSRPCellID_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "ECGI", HFILL }},
    { &hf_x2ap_rSRPMeasured,
      { "rSRPMeasured", "x2ap.rSRPMeasured",
        FT_UINT32, BASE_CUSTOM, CF_FUNC(x2ap_Threshold_RSRP_fmt), 0,
        "INTEGER_0_97_", HFILL }},
    { &hf_x2ap_RSRPMRList_item,
      { "RSRPMRList item", "x2ap.RSRPMRList_item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_x2ap_rSRPMeasurementResult,
      { "rSRPMeasurementResult", "x2ap.rSRPMeasurementResult",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_x2ap_dLS1TNLLoadIndicator,
      { "dLS1TNLLoadIndicator", "x2ap.dLS1TNLLoadIndicator",
        FT_UINT32, BASE_DEC, VALS(x2ap_LoadIndicator_vals), 0,
        "LoadIndicator", HFILL }},
    { &hf_x2ap_uLS1TNLLoadIndicator,
      { "uLS1TNLLoadIndicator", "x2ap.uLS1TNLLoadIndicator",
        FT_UINT32, BASE_DEC, VALS(x2ap_LoadIndicator_vals), 0,
        "LoadIndicator", HFILL }},
    { &hf_x2ap_ServedCells_item,
      { "ServedCells item", "x2ap.ServedCells_item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_x2ap_servedCellInfo,
      { "servedCellInfo", "x2ap.servedCellInfo_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "ServedCell_Information", HFILL }},
    { &hf_x2ap_neighbour_Info,
      { "neighbour-Info", "x2ap.neighbour_Info",
        FT_UINT32, BASE_DEC, NULL, 0,
        "Neighbour_Information", HFILL }},
    { &hf_x2ap_cellId,
      { "cellId", "x2ap.cellId_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "ECGI", HFILL }},
    { &hf_x2ap_tAC,
      { "tAC", "x2ap.tAC",
        FT_UINT16, BASE_DEC_HEX, NULL, 0,
        NULL, HFILL }},
    { &hf_x2ap_broadcastPLMNs,
      { "broadcastPLMNs", "x2ap.broadcastPLMNs",
        FT_UINT32, BASE_DEC, NULL, 0,
        "BroadcastPLMNs_Item", HFILL }},
    { &hf_x2ap_eUTRA_Mode_Info,
      { "eUTRA-Mode-Info", "x2ap.eUTRA_Mode_Info",
        FT_UINT32, BASE_DEC, VALS(x2ap_EUTRA_Mode_Info_vals), 0,
        NULL, HFILL }},
    { &hf_x2ap_specialSubframePatterns,
      { "specialSubframePatterns", "x2ap.specialSubframePatterns",
        FT_UINT32, BASE_DEC, VALS(x2ap_SpecialSubframePatterns_vals), 0,
        NULL, HFILL }},
    { &hf_x2ap_subbandCQICodeword0,
      { "subbandCQICodeword0", "x2ap.subbandCQICodeword0",
        FT_UINT32, BASE_DEC, VALS(x2ap_SubbandCQICodeword0_vals), 0,
        NULL, HFILL }},
    { &hf_x2ap_subbandCQICodeword1,
      { "subbandCQICodeword1", "x2ap.subbandCQICodeword1",
        FT_UINT32, BASE_DEC, VALS(x2ap_SubbandCQICodeword1_vals), 0,
        NULL, HFILL }},
    { &hf_x2ap_four_bitCQI,
      { "four-bitCQI", "x2ap.four_bitCQI",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_15_", HFILL }},
    { &hf_x2ap_two_bitSubbandDifferentialCQI,
      { "two-bitSubbandDifferentialCQI", "x2ap.two_bitSubbandDifferentialCQI",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_3_", HFILL }},
    { &hf_x2ap_two_bitDifferentialCQI,
      { "two-bitDifferentialCQI", "x2ap.two_bitDifferentialCQI",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_3_", HFILL }},
    { &hf_x2ap_three_bitSpatialDifferentialCQI,
      { "three-bitSpatialDifferentialCQI", "x2ap.three_bitSpatialDifferentialCQI",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_7_", HFILL }},
    { &hf_x2ap_SubbandCQIList_item,
      { "SubbandCQIItem", "x2ap.SubbandCQIItem_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_x2ap_subbandCQI,
      { "subbandCQI", "x2ap.subbandCQI_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_x2ap_subbandIndex,
      { "subbandIndex", "x2ap.subbandIndex",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_27_", HFILL }},
    { &hf_x2ap_oneframe,
      { "oneframe", "x2ap.oneframe",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_x2ap_fourframes,
      { "fourframes", "x2ap.fourframes",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_x2ap_tAListforMDT,
      { "tAListforMDT", "x2ap.tAListforMDT",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_x2ap_tAIListforMDT,
      { "tAIListforMDT", "x2ap.tAIListforMDT",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_x2ap_TAIListforMDT_item,
      { "TAI-Item", "x2ap.TAI_Item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_x2ap_TAListforMDT_item,
      { "TAC", "x2ap.TAC",
        FT_UINT16, BASE_DEC_HEX, NULL, 0,
        NULL, HFILL }},
    { &hf_x2ap_transmission_Bandwidth,
      { "transmission-Bandwidth", "x2ap.transmission_Bandwidth",
        FT_UINT32, BASE_DEC, VALS(x2ap_Transmission_Bandwidth_vals), 0,
        NULL, HFILL }},
    { &hf_x2ap_subframeAssignment,
      { "subframeAssignment", "x2ap.subframeAssignment",
        FT_UINT32, BASE_DEC, VALS(x2ap_SubframeAssignment_vals), 0,
        NULL, HFILL }},
    { &hf_x2ap_specialSubframe_Info,
      { "specialSubframe-Info", "x2ap.specialSubframe_Info_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_x2ap_eUTRANTraceID,
      { "eUTRANTraceID", "x2ap.eUTRANTraceID",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_x2ap_interfacesToTrace,
      { "interfacesToTrace", "x2ap.interfacesToTrace",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_x2ap_traceDepth,
      { "traceDepth", "x2ap.traceDepth",
        FT_UINT32, BASE_DEC, VALS(x2ap_TraceDepth_vals), 0,
        NULL, HFILL }},
    { &hf_x2ap_traceCollectionEntityIPAddress,
      { "traceCollectionEntityIPAddress", "x2ap.traceCollectionEntityIPAddress",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_x2ap_uDP_Port_Number,
      { "uDP-Port-Number", "x2ap.uDP_Port_Number",
        FT_UINT16, BASE_DEC, NULL, 0,
        "Port_Number", HFILL }},
    { &hf_x2ap_uEaggregateMaximumBitRateDownlink,
      { "uEaggregateMaximumBitRateDownlink", "x2ap.uEaggregateMaximumBitRateDownlink",
        FT_UINT64, BASE_DEC|BASE_UNIT_STRING, &units_bit_sec, 0,
        "BitRate", HFILL }},
    { &hf_x2ap_uEaggregateMaximumBitRateUplink,
      { "uEaggregateMaximumBitRateUplink", "x2ap.uEaggregateMaximumBitRateUplink",
        FT_UINT64, BASE_DEC|BASE_UNIT_STRING, &units_bit_sec, 0,
        "BitRate", HFILL }},
    { &hf_x2ap_UE_HistoryInformation_item,
      { "LastVisitedCell-Item", "x2ap.LastVisitedCell_Item",
        FT_UINT32, BASE_DEC, VALS(x2ap_LastVisitedCell_Item_vals), 0,
        NULL, HFILL }},
    { &hf_x2ap_encryptionAlgorithms,
      { "encryptionAlgorithms", "x2ap.encryptionAlgorithms",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_x2ap_integrityProtectionAlgorithms,
      { "integrityProtectionAlgorithms", "x2ap.integrityProtectionAlgorithms",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_x2ap_UL_HighInterferenceIndicationInfo_item,
      { "UL-HighInterferenceIndicationInfo-Item", "x2ap.UL_HighInterferenceIndicationInfo_Item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_x2ap_target_Cell_ID,
      { "target-Cell-ID", "x2ap.target_Cell_ID_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "ECGI", HFILL }},
    { &hf_x2ap_ul_interferenceindication,
      { "ul-interferenceindication", "x2ap.ul_interferenceindication",
        FT_BYTES, BASE_NONE, NULL, 0,
        "UL_HighInterferenceIndication", HFILL }},
    { &hf_x2ap_UL_InterferenceOverloadIndication_item,
      { "UL-InterferenceOverloadIndication-Item", "x2ap.UL_InterferenceOverloadIndication_Item",
        FT_UINT32, BASE_DEC, VALS(x2ap_UL_InterferenceOverloadIndication_Item_vals), 0,
        NULL, HFILL }},
    { &hf_x2ap_fdd_01,
      { "fdd", "x2ap.fdd_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "UsableABSInformationFDD", HFILL }},
    { &hf_x2ap_tdd_01,
      { "tdd", "x2ap.tdd_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "UsableABSInformationTDD", HFILL }},
    { &hf_x2ap_usable_abs_pattern_info,
      { "usable-abs-pattern-info", "x2ap.usable_abs_pattern_info",
        FT_BYTES, BASE_NONE, NULL, 0,
        "BIT_STRING_SIZE_40", HFILL }},
    { &hf_x2ap_usaable_abs_pattern_info,
      { "usaable-abs-pattern-info", "x2ap.usaable_abs_pattern_info",
        FT_BYTES, BASE_NONE, NULL, 0,
        "BIT_STRING_SIZE_1_70_", HFILL }},
    { &hf_x2ap_widebandCQICodeword0,
      { "widebandCQICodeword0", "x2ap.widebandCQICodeword0",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_15_", HFILL }},
    { &hf_x2ap_widebandCQICodeword1,
      { "widebandCQICodeword1", "x2ap.widebandCQICodeword1",
        FT_UINT32, BASE_DEC, VALS(x2ap_WidebandCQICodeword1_vals), 0,
        NULL, HFILL }},
    { &hf_x2ap_protocolIEs,
      { "protocolIEs", "x2ap.protocolIEs",
        FT_UINT32, BASE_DEC, NULL, 0,
        "ProtocolIE_Container", HFILL }},
    { &hf_x2ap_mME_UE_S1AP_ID,
      { "mME-UE-S1AP-ID", "x2ap.mME_UE_S1AP_ID",
        FT_UINT32, BASE_DEC, NULL, 0,
        "UE_S1AP_ID", HFILL }},
    { &hf_x2ap_uESecurityCapabilities,
      { "uESecurityCapabilities", "x2ap.uESecurityCapabilities_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_x2ap_aS_SecurityInformation,
      { "aS-SecurityInformation", "x2ap.aS_SecurityInformation_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_x2ap_uEaggregateMaximumBitRate,
      { "uEaggregateMaximumBitRate", "x2ap.uEaggregateMaximumBitRate_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_x2ap_subscriberProfileIDforRFP,
      { "subscriberProfileIDforRFP", "x2ap.subscriberProfileIDforRFP",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_x2ap_e_RABs_ToBeSetup_List,
      { "e-RABs-ToBeSetup-List", "x2ap.e_RABs_ToBeSetup_List",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_x2ap_rRC_Context,
      { "rRC-Context", "x2ap.rRC_Context",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_x2ap_handoverRestrictionList,
      { "handoverRestrictionList", "x2ap.handoverRestrictionList_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_x2ap_locationReportingInformation,
      { "locationReportingInformation", "x2ap.locationReportingInformation_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_x2ap_E_RABs_ToBeSetup_List_item,
      { "ProtocolIE-Single-Container", "x2ap.ProtocolIE_Single_Container_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_x2ap_e_RAB_Level_QoS_Parameters,
      { "e-RAB-Level-QoS-Parameters", "x2ap.e_RAB_Level_QoS_Parameters_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_x2ap_dL_Forwarding,
      { "dL-Forwarding", "x2ap.dL_Forwarding",
        FT_UINT32, BASE_DEC, VALS(x2ap_DL_Forwarding_vals), 0,
        NULL, HFILL }},
    { &hf_x2ap_uL_GTPtunnelEndpoint,
      { "uL-GTPtunnelEndpoint", "x2ap.uL_GTPtunnelEndpoint_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "GTPtunnelEndpoint", HFILL }},
    { &hf_x2ap_source_GlobalSeNB_ID,
      { "source-GlobalSeNB-ID", "x2ap.source_GlobalSeNB_ID_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "GlobalENB_ID", HFILL }},
    { &hf_x2ap_seNB_UE_X2AP_ID,
      { "seNB-UE-X2AP-ID", "x2ap.seNB_UE_X2AP_ID",
        FT_UINT32, BASE_DEC, NULL, 0,
        "UE_X2AP_ID", HFILL }},
    { &hf_x2ap_seNB_UE_X2AP_ID_Extension,
      { "seNB-UE-X2AP-ID-Extension", "x2ap.seNB_UE_X2AP_ID_Extension",
        FT_UINT32, BASE_DEC, NULL, 0,
        "UE_X2AP_ID_Extension", HFILL }},
    { &hf_x2ap_E_RABs_Admitted_List_item,
      { "ProtocolIE-Single-Container", "x2ap.ProtocolIE_Single_Container_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_x2ap_uL_GTP_TunnelEndpoint,
      { "uL-GTP-TunnelEndpoint", "x2ap.uL_GTP_TunnelEndpoint_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "GTPtunnelEndpoint", HFILL }},
    { &hf_x2ap_dL_GTP_TunnelEndpoint,
      { "dL-GTP-TunnelEndpoint", "x2ap.dL_GTP_TunnelEndpoint_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "GTPtunnelEndpoint", HFILL }},
    { &hf_x2ap_E_RABs_SubjectToStatusTransfer_List_item,
      { "ProtocolIE-Single-Container", "x2ap.ProtocolIE_Single_Container_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_x2ap_receiveStatusofULPDCPSDUs,
      { "receiveStatusofULPDCPSDUs", "x2ap.receiveStatusofULPDCPSDUs",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_x2ap_uL_COUNTvalue,
      { "uL-COUNTvalue", "x2ap.uL_COUNTvalue_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "COUNTvalue", HFILL }},
    { &hf_x2ap_dL_COUNTvalue,
      { "dL-COUNTvalue", "x2ap.dL_COUNTvalue_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "COUNTvalue", HFILL }},
    { &hf_x2ap_CellInformation_List_item,
      { "ProtocolIE-Single-Container", "x2ap.ProtocolIE_Single_Container_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_x2ap_cell_ID,
      { "cell-ID", "x2ap.cell_ID_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "ECGI", HFILL }},
    { &hf_x2ap_ul_InterferenceOverloadIndication,
      { "ul-InterferenceOverloadIndication", "x2ap.ul_InterferenceOverloadIndication",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_x2ap_ul_HighInterferenceIndicationInfo,
      { "ul-HighInterferenceIndicationInfo", "x2ap.ul_HighInterferenceIndicationInfo",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_x2ap_relativeNarrowbandTxPower,
      { "relativeNarrowbandTxPower", "x2ap.relativeNarrowbandTxPower_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_x2ap_ServedCellsToModify_item,
      { "ServedCellsToModify-Item", "x2ap.ServedCellsToModify_Item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_x2ap_old_ecgi,
      { "old-ecgi", "x2ap.old_ecgi_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "ECGI", HFILL }},
    { &hf_x2ap_Old_ECGIs_item,
      { "ECGI", "x2ap.ECGI_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_x2ap_CellToReport_List_item,
      { "ProtocolIE-Single-Container", "x2ap.ProtocolIE_Single_Container_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_x2ap_MeasurementInitiationResult_List_item,
      { "ProtocolIE-Single-Container", "x2ap.ProtocolIE_Single_Container_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_x2ap_measurementFailureCause_List,
      { "measurementFailureCause-List", "x2ap.measurementFailureCause_List",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_x2ap_MeasurementFailureCause_List_item,
      { "ProtocolIE-Single-Container", "x2ap.ProtocolIE_Single_Container_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_x2ap_measurementFailedReportCharacteristics,
      { "measurementFailedReportCharacteristics", "x2ap.measurementFailedReportCharacteristics",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_x2ap_CompleteFailureCauseInformation_List_item,
      { "ProtocolIE-Single-Container", "x2ap.ProtocolIE_Single_Container_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_x2ap_CellMeasurementResult_List_item,
      { "ProtocolIE-Single-Container", "x2ap.ProtocolIE_Single_Container_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_x2ap_hWLoadIndicator,
      { "hWLoadIndicator", "x2ap.hWLoadIndicator_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_x2ap_s1TNLLoadIndicator,
      { "s1TNLLoadIndicator", "x2ap.s1TNLLoadIndicator_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_x2ap_radioResourceStatus,
      { "radioResourceStatus", "x2ap.radioResourceStatus_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_x2ap_privateIEs,
      { "privateIEs", "x2ap.privateIEs",
        FT_UINT32, BASE_DEC, NULL, 0,
        "PrivateIE_Container", HFILL }},
    { &hf_x2ap_ServedCellsToActivate_item,
      { "ServedCellsToActivate-Item", "x2ap.ServedCellsToActivate_Item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_x2ap_ecgi,
      { "ecgi", "x2ap.ecgi_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_x2ap_ActivatedCellList_item,
      { "ActivatedCellList-Item", "x2ap.ActivatedCellList_Item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_x2ap_source_GlobalENB_ID,
      { "source-GlobalENB-ID", "x2ap.source_GlobalENB_ID_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "GlobalENB_ID", HFILL }},
    { &hf_x2ap_target_GlobalENB_ID,
      { "target-GlobalENB-ID", "x2ap.target_GlobalENB_ID_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "GlobalENB_ID", HFILL }},
    { &hf_x2ap_E_RABs_ToBeAdded_List_item,
      { "ProtocolIE-Single-Container", "x2ap.ProtocolIE_Single_Container_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_x2ap_sCG_Bearer,
      { "sCG-Bearer", "x2ap.sCG_Bearer_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "E_RABs_ToBeAdded_Item_SCG_Bearer", HFILL }},
    { &hf_x2ap_split_Bearer,
      { "split-Bearer", "x2ap.split_Bearer_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "E_RABs_ToBeAdded_Item_Split_Bearer", HFILL }},
    { &hf_x2ap_s1_UL_GTPtunnelEndpoint,
      { "s1-UL-GTPtunnelEndpoint", "x2ap.s1_UL_GTPtunnelEndpoint_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "GTPtunnelEndpoint", HFILL }},
    { &hf_x2ap_meNB_GTPtunnelEndpoint,
      { "meNB-GTPtunnelEndpoint", "x2ap.meNB_GTPtunnelEndpoint_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "GTPtunnelEndpoint", HFILL }},
    { &hf_x2ap_E_RABs_Admitted_ToBeAdded_List_item,
      { "ProtocolIE-Single-Container", "x2ap.ProtocolIE_Single_Container_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_x2ap_sCG_Bearer_01,
      { "sCG-Bearer", "x2ap.sCG_Bearer_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "E_RABs_Admitted_ToBeAdded_Item_SCG_Bearer", HFILL }},
    { &hf_x2ap_split_Bearer_01,
      { "split-Bearer", "x2ap.split_Bearer_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "E_RABs_Admitted_ToBeAdded_Item_Split_Bearer", HFILL }},
    { &hf_x2ap_s1_DL_GTPtunnelEndpoint,
      { "s1-DL-GTPtunnelEndpoint", "x2ap.s1_DL_GTPtunnelEndpoint_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "GTPtunnelEndpoint", HFILL }},
    { &hf_x2ap_dL_Forwarding_GTPtunnelEndpoint,
      { "dL-Forwarding-GTPtunnelEndpoint", "x2ap.dL_Forwarding_GTPtunnelEndpoint_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "GTPtunnelEndpoint", HFILL }},
    { &hf_x2ap_uL_Forwarding_GTPtunnelEndpoint,
      { "uL-Forwarding-GTPtunnelEndpoint", "x2ap.uL_Forwarding_GTPtunnelEndpoint_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "GTPtunnelEndpoint", HFILL }},
    { &hf_x2ap_seNB_GTPtunnelEndpoint,
      { "seNB-GTPtunnelEndpoint", "x2ap.seNB_GTPtunnelEndpoint_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "GTPtunnelEndpoint", HFILL }},
    { &hf_x2ap_success,
      { "success", "x2ap.success_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "ResponseInformationSeNBReconfComp_SuccessItem", HFILL }},
    { &hf_x2ap_reject_by_MeNB,
      { "reject-by-MeNB", "x2ap.reject_by_MeNB_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "ResponseInformationSeNBReconfComp_RejectByMeNBItem", HFILL }},
    { &hf_x2ap_meNBtoSeNBContainer,
      { "meNBtoSeNBContainer", "x2ap.meNBtoSeNBContainer",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_x2ap_uE_SecurityCapabilities,
      { "uE-SecurityCapabilities", "x2ap.uE_SecurityCapabilities_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "UESecurityCapabilities", HFILL }},
    { &hf_x2ap_seNB_SecurityKey,
      { "seNB-SecurityKey", "x2ap.seNB_SecurityKey",
        FT_BYTES, BASE_NONE, NULL, 0,
        "SeNBSecurityKey", HFILL }},
    { &hf_x2ap_seNBUEAggregateMaximumBitRate,
      { "seNBUEAggregateMaximumBitRate", "x2ap.seNBUEAggregateMaximumBitRate_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "UEAggregateMaximumBitRate", HFILL }},
    { &hf_x2ap_e_RABs_ToBeAdded,
      { "e-RABs-ToBeAdded", "x2ap.e_RABs_ToBeAdded",
        FT_UINT32, BASE_DEC, NULL, 0,
        "E_RABs_ToBeAdded_List_ModReq", HFILL }},
    { &hf_x2ap_e_RABs_ToBeModified,
      { "e-RABs-ToBeModified", "x2ap.e_RABs_ToBeModified",
        FT_UINT32, BASE_DEC, NULL, 0,
        "E_RABs_ToBeModified_List_ModReq", HFILL }},
    { &hf_x2ap_e_RABs_ToBeReleased,
      { "e-RABs-ToBeReleased", "x2ap.e_RABs_ToBeReleased",
        FT_UINT32, BASE_DEC, NULL, 0,
        "E_RABs_ToBeReleased_List_ModReq", HFILL }},
    { &hf_x2ap_E_RABs_ToBeAdded_List_ModReq_item,
      { "ProtocolIE-Single-Container", "x2ap.ProtocolIE_Single_Container_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_x2ap_sCG_Bearer_02,
      { "sCG-Bearer", "x2ap.sCG_Bearer_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "E_RABs_ToBeAdded_ModReqItem_SCG_Bearer", HFILL }},
    { &hf_x2ap_split_Bearer_02,
      { "split-Bearer", "x2ap.split_Bearer_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "E_RABs_ToBeAdded_ModReqItem_Split_Bearer", HFILL }},
    { &hf_x2ap_E_RABs_ToBeModified_List_ModReq_item,
      { "ProtocolIE-Single-Container", "x2ap.ProtocolIE_Single_Container_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_x2ap_sCG_Bearer_03,
      { "sCG-Bearer", "x2ap.sCG_Bearer_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "E_RABs_ToBeModified_ModReqItem_SCG_Bearer", HFILL }},
    { &hf_x2ap_split_Bearer_03,
      { "split-Bearer", "x2ap.split_Bearer_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "E_RABs_ToBeModified_ModReqItem_Split_Bearer", HFILL }},
    { &hf_x2ap_E_RABs_ToBeReleased_List_ModReq_item,
      { "ProtocolIE-Single-Container", "x2ap.ProtocolIE_Single_Container_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_x2ap_sCG_Bearer_04,
      { "sCG-Bearer", "x2ap.sCG_Bearer_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "E_RABs_ToBeReleased_ModReqItem_SCG_Bearer", HFILL }},
    { &hf_x2ap_split_Bearer_04,
      { "split-Bearer", "x2ap.split_Bearer_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "E_RABs_ToBeReleased_ModReqItem_Split_Bearer", HFILL }},
    { &hf_x2ap_dL_GTPtunnelEndpoint,
      { "dL-GTPtunnelEndpoint", "x2ap.dL_GTPtunnelEndpoint_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "GTPtunnelEndpoint", HFILL }},
    { &hf_x2ap_E_RABs_Admitted_ToBeAdded_ModAckList_item,
      { "ProtocolIE-Single-Container", "x2ap.ProtocolIE_Single_Container_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_x2ap_sCG_Bearer_05,
      { "sCG-Bearer", "x2ap.sCG_Bearer_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "E_RABs_Admitted_ToBeAdded_ModAckItem_SCG_Bearer", HFILL }},
    { &hf_x2ap_split_Bearer_05,
      { "split-Bearer", "x2ap.split_Bearer_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "E_RABs_Admitted_ToBeAdded_ModAckItem_Split_Bearer", HFILL }},
    { &hf_x2ap_E_RABs_Admitted_ToBeModified_ModAckList_item,
      { "ProtocolIE-Single-Container", "x2ap.ProtocolIE_Single_Container_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_x2ap_sCG_Bearer_06,
      { "sCG-Bearer", "x2ap.sCG_Bearer_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "E_RABs_Admitted_ToBeModified_ModAckItem_SCG_Bearer", HFILL }},
    { &hf_x2ap_split_Bearer_06,
      { "split-Bearer", "x2ap.split_Bearer_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "E_RABs_Admitted_ToBeModified_ModAckItem_Split_Bearer", HFILL }},
    { &hf_x2ap_E_RABs_Admitted_ToBeReleased_ModAckList_item,
      { "ProtocolIE-Single-Container", "x2ap.ProtocolIE_Single_Container_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_x2ap_sCG_Bearer_07,
      { "sCG-Bearer", "x2ap.sCG_Bearer_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "E_RABs_Admitted_ToBeReleased_ModAckItem_SCG_Bearer", HFILL }},
    { &hf_x2ap_split_Bearer_07,
      { "split-Bearer", "x2ap.split_Bearer_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "E_RABs_Admitted_ToBeReleased_ModAckItem_Split_Bearer", HFILL }},
    { &hf_x2ap_E_RABs_ToBeReleased_ModReqd_item,
      { "ProtocolIE-Single-Container", "x2ap.ProtocolIE_Single_Container_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_x2ap_E_RABs_ToBeReleased_List_RelReq_item,
      { "ProtocolIE-Single-Container", "x2ap.ProtocolIE_Single_Container_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_x2ap_sCG_Bearer_08,
      { "sCG-Bearer", "x2ap.sCG_Bearer_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "E_RABs_ToBeReleased_RelReqItem_SCG_Bearer", HFILL }},
    { &hf_x2ap_split_Bearer_08,
      { "split-Bearer", "x2ap.split_Bearer_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "E_RABs_ToBeReleased_RelReqItem_Split_Bearer", HFILL }},
    { &hf_x2ap_E_RABs_ToBeReleased_List_RelConf_item,
      { "ProtocolIE-Single-Container", "x2ap.ProtocolIE_Single_Container_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_x2ap_sCG_Bearer_09,
      { "sCG-Bearer", "x2ap.sCG_Bearer_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "E_RABs_ToBeReleased_RelConfItem_SCG_Bearer", HFILL }},
    { &hf_x2ap_split_Bearer_09,
      { "split-Bearer", "x2ap.split_Bearer_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "E_RABs_ToBeReleased_RelConfItem_Split_Bearer", HFILL }},
    { &hf_x2ap_E_RABs_SubjectToCounterCheck_List_item,
      { "ProtocolIE-Single-Container", "x2ap.ProtocolIE_Single_Container_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_x2ap_uL_Count,
      { "uL-Count", "x2ap.uL_Count",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_4294967295", HFILL }},
    { &hf_x2ap_dL_Count,
      { "dL-Count", "x2ap.dL_Count",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_4294967295", HFILL }},
    { &hf_x2ap_e_RABs_ToBeSetup_ListRetrieve,
      { "e-RABs-ToBeSetup-ListRetrieve", "x2ap.e_RABs_ToBeSetup_ListRetrieve",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_x2ap_managBasedMDTallowed,
      { "managBasedMDTallowed", "x2ap.managBasedMDTallowed",
        FT_UINT32, BASE_DEC, VALS(x2ap_ManagementBasedMDTallowed_vals), 0,
        "ManagementBasedMDTallowed", HFILL }},
    { &hf_x2ap_managBasedMDTPLMNList,
      { "managBasedMDTPLMNList", "x2ap.managBasedMDTPLMNList",
        FT_UINT32, BASE_DEC, NULL, 0,
        "MDTPLMNList", HFILL }},
    { &hf_x2ap_E_RABs_ToBeSetup_ListRetrieve_item,
      { "ProtocolIE-Single-Container", "x2ap.ProtocolIE_Single_Container_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_x2ap_bearerType,
      { "bearerType", "x2ap.bearerType",
        FT_UINT32, BASE_DEC, VALS(x2ap_BearerType_vals), 0,
        NULL, HFILL }},
    { &hf_x2ap_initiatingMessage,
      { "initiatingMessage", "x2ap.initiatingMessage_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_x2ap_successfulOutcome,
      { "successfulOutcome", "x2ap.successfulOutcome_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_x2ap_unsuccessfulOutcome,
      { "unsuccessfulOutcome", "x2ap.unsuccessfulOutcome_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_x2ap_initiatingMessage_value,
      { "value", "x2ap.value_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "InitiatingMessage_value", HFILL }},
    { &hf_x2ap_successfulOutcome_value,
      { "value", "x2ap.value_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "SuccessfulOutcome_value", HFILL }},
    { &hf_x2ap_value,
      { "value", "x2ap.value_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "UnsuccessfulOutcome_value", HFILL }},

/*--- End of included file: packet-x2ap-hfarr.c ---*/
#line 501 "./asn1/x2ap/packet-x2ap-template.c"
  };

  /* List of subtrees */
  static gint *ett[] = {
    &ett_x2ap,
    &ett_x2ap_TransportLayerAddress,
    &ett_x2ap_PLMN_Identity,
    &ett_x2ap_TargeteNBtoSource_eNBTransparentContainer,
    &ett_x2ap_RRC_Context,
    &ett_x2ap_UE_HistoryInformationFromTheUE,
    &ett_x2ap_ReportCharacteristics,
    &ett_x2ap_measurementFailedReportCharacteristics,
    &ett_x2ap_UE_RLF_Report_Container,
    &ett_x2ap_UE_RLF_Report_Container_for_extended_bands,
    &ett_x2ap_MeNBtoSeNBContainer,
    &ett_x2ap_SeNBtoMeNBContainer,
    &ett_x2ap_EUTRANTraceID,
    &ett_x2ap_InterfacesToTrace,
    &ett_x2ap_TraceCollectionEntityIPAddress,
    &ett_x2ap_EncryptionAlgorithms,
    &ett_x2ap_IntegrityProtectionAlgorithms,
    &ett_x2ap_MeasurementsToActivate,
    &ett_x2ap_MDT_Location_Info,
    &ett_x2ap_transmissionModes,
    &ett_x2ap_X2AP_Message,

/*--- Included file: packet-x2ap-ettarr.c ---*/
#line 1 "./asn1/x2ap/packet-x2ap-ettarr.c"
    &ett_x2ap_PrivateIE_ID,
    &ett_x2ap_ProtocolIE_Container,
    &ett_x2ap_ProtocolIE_Field,
    &ett_x2ap_ProtocolExtensionContainer,
    &ett_x2ap_ProtocolExtensionField,
    &ett_x2ap_PrivateIE_Container,
    &ett_x2ap_PrivateIE_Field,
    &ett_x2ap_ABSInformation,
    &ett_x2ap_ABSInformationFDD,
    &ett_x2ap_ABSInformationTDD,
    &ett_x2ap_ABS_Status,
    &ett_x2ap_AdditionalSpecialSubframe_Info,
    &ett_x2ap_AllocationAndRetentionPriority,
    &ett_x2ap_AreaScopeOfMDT,
    &ett_x2ap_AS_SecurityInformation,
    &ett_x2ap_BroadcastPLMNs_Item,
    &ett_x2ap_Cause,
    &ett_x2ap_CellBasedMDT,
    &ett_x2ap_CellIdListforMDT,
    &ett_x2ap_CellReplacingInfo,
    &ett_x2ap_CellType,
    &ett_x2ap_CoMPHypothesisSet,
    &ett_x2ap_CoMPHypothesisSetItem,
    &ett_x2ap_CoMPInformation,
    &ett_x2ap_CoMPInformationItem,
    &ett_x2ap_CoMPInformationItem_item,
    &ett_x2ap_CoMPInformationStartTime,
    &ett_x2ap_CoMPInformationStartTime_item,
    &ett_x2ap_CompositeAvailableCapacity,
    &ett_x2ap_CompositeAvailableCapacityGroup,
    &ett_x2ap_COUNTvalue,
    &ett_x2ap_COUNTValueExtended,
    &ett_x2ap_COUNTvaluePDCP_SNlength18,
    &ett_x2ap_CoverageModificationList,
    &ett_x2ap_CoverageModification_Item,
    &ett_x2ap_CriticalityDiagnostics,
    &ett_x2ap_CriticalityDiagnostics_IE_List,
    &ett_x2ap_CriticalityDiagnostics_IE_List_item,
    &ett_x2ap_CSIReportList,
    &ett_x2ap_CSIReportList_item,
    &ett_x2ap_CSIReportPerCSIProcess,
    &ett_x2ap_CSIReportPerCSIProcess_item,
    &ett_x2ap_CSIReportPerCSIProcessItem,
    &ett_x2ap_CSIReportPerCSIProcessItem_item,
    &ett_x2ap_DynamicDLTransmissionInformation,
    &ett_x2ap_DynamicNAICSInformation,
    &ett_x2ap_SEQUENCE_SIZE_0_maxnoofPA_OF_PA_Values,
    &ett_x2ap_ECGI,
    &ett_x2ap_EnhancedRNTP,
    &ett_x2ap_EnhancedRNTPStartTime,
    &ett_x2ap_ENB_ID,
    &ett_x2ap_EPLMNs,
    &ett_x2ap_E_RAB_Level_QoS_Parameters,
    &ett_x2ap_E_RAB_List,
    &ett_x2ap_E_RAB_Item,
    &ett_x2ap_EUTRA_Mode_Info,
    &ett_x2ap_ExpectedUEBehaviour,
    &ett_x2ap_ExpectedUEActivityBehaviour,
    &ett_x2ap_ExtendedULInterferenceOverloadInfo,
    &ett_x2ap_FDD_Info,
    &ett_x2ap_ForbiddenTAs,
    &ett_x2ap_ForbiddenTAs_Item,
    &ett_x2ap_ForbiddenTACs,
    &ett_x2ap_ForbiddenLAs,
    &ett_x2ap_ForbiddenLAs_Item,
    &ett_x2ap_ForbiddenLACs,
    &ett_x2ap_GBR_QosInformation,
    &ett_x2ap_GlobalENB_ID,
    &ett_x2ap_GTPtunnelEndpoint,
    &ett_x2ap_GUGroupIDList,
    &ett_x2ap_GU_Group_ID,
    &ett_x2ap_GUMMEI,
    &ett_x2ap_HandoverRestrictionList,
    &ett_x2ap_HWLoadIndicator,
    &ett_x2ap_LastVisitedCell_Item,
    &ett_x2ap_LastVisitedEUTRANCellInformation,
    &ett_x2ap_LastVisitedGERANCellInformation,
    &ett_x2ap_LocationReportingInformation,
    &ett_x2ap_M1PeriodicReporting,
    &ett_x2ap_M1ThresholdEventA2,
    &ett_x2ap_M3Configuration,
    &ett_x2ap_M4Configuration,
    &ett_x2ap_M5Configuration,
    &ett_x2ap_M6Configuration,
    &ett_x2ap_M7Configuration,
    &ett_x2ap_MDT_Configuration,
    &ett_x2ap_MDTPLMNList,
    &ett_x2ap_MeasurementThresholdA2,
    &ett_x2ap_MBMS_Service_Area_Identity_List,
    &ett_x2ap_MBSFN_Subframe_Infolist,
    &ett_x2ap_MBSFN_Subframe_Info,
    &ett_x2ap_MobilityParametersModificationRange,
    &ett_x2ap_MobilityParametersInformation,
    &ett_x2ap_MultibandInfoList,
    &ett_x2ap_BandInfo,
    &ett_x2ap_Neighbour_Information,
    &ett_x2ap_Neighbour_Information_item,
    &ett_x2ap_PRACH_Configuration,
    &ett_x2ap_ProSeAuthorized,
    &ett_x2ap_RadioResourceStatus,
    &ett_x2ap_RelativeNarrowbandTxPower,
    &ett_x2ap_ReplacingCellsList,
    &ett_x2ap_ReplacingCellsList_Item,
    &ett_x2ap_ResumeID,
    &ett_x2ap_RSRPMeasurementResult,
    &ett_x2ap_RSRPMeasurementResult_item,
    &ett_x2ap_RSRPMRList,
    &ett_x2ap_RSRPMRList_item,
    &ett_x2ap_S1TNLLoadIndicator,
    &ett_x2ap_ServedCells,
    &ett_x2ap_ServedCells_item,
    &ett_x2ap_ServedCell_Information,
    &ett_x2ap_SpecialSubframe_Info,
    &ett_x2ap_SubbandCQI,
    &ett_x2ap_SubbandCQICodeword0,
    &ett_x2ap_SubbandCQICodeword1,
    &ett_x2ap_SubbandCQIList,
    &ett_x2ap_SubbandCQIItem,
    &ett_x2ap_SubframeAllocation,
    &ett_x2ap_TABasedMDT,
    &ett_x2ap_TAIBasedMDT,
    &ett_x2ap_TAIListforMDT,
    &ett_x2ap_TAI_Item,
    &ett_x2ap_TAListforMDT,
    &ett_x2ap_TDD_Info,
    &ett_x2ap_TraceActivation,
    &ett_x2ap_TunnelInformation,
    &ett_x2ap_UEAggregateMaximumBitRate,
    &ett_x2ap_UE_HistoryInformation,
    &ett_x2ap_UESecurityCapabilities,
    &ett_x2ap_UL_HighInterferenceIndicationInfo,
    &ett_x2ap_UL_HighInterferenceIndicationInfo_Item,
    &ett_x2ap_UL_InterferenceOverloadIndication,
    &ett_x2ap_UsableABSInformation,
    &ett_x2ap_UsableABSInformationFDD,
    &ett_x2ap_UsableABSInformationTDD,
    &ett_x2ap_WidebandCQI,
    &ett_x2ap_WidebandCQICodeword1,
    &ett_x2ap_HandoverRequest,
    &ett_x2ap_UE_ContextInformation,
    &ett_x2ap_E_RABs_ToBeSetup_List,
    &ett_x2ap_E_RABs_ToBeSetup_Item,
    &ett_x2ap_UE_ContextReferenceAtSeNB,
    &ett_x2ap_HandoverRequestAcknowledge,
    &ett_x2ap_E_RABs_Admitted_List,
    &ett_x2ap_E_RABs_Admitted_Item,
    &ett_x2ap_HandoverPreparationFailure,
    &ett_x2ap_HandoverReport,
    &ett_x2ap_SNStatusTransfer,
    &ett_x2ap_E_RABs_SubjectToStatusTransfer_List,
    &ett_x2ap_E_RABs_SubjectToStatusTransfer_Item,
    &ett_x2ap_UEContextRelease,
    &ett_x2ap_HandoverCancel,
    &ett_x2ap_ErrorIndication,
    &ett_x2ap_ResetRequest,
    &ett_x2ap_ResetResponse,
    &ett_x2ap_X2SetupRequest,
    &ett_x2ap_X2SetupResponse,
    &ett_x2ap_X2SetupFailure,
    &ett_x2ap_LoadInformation,
    &ett_x2ap_CellInformation_List,
    &ett_x2ap_CellInformation_Item,
    &ett_x2ap_ENBConfigurationUpdate,
    &ett_x2ap_ServedCellsToModify,
    &ett_x2ap_ServedCellsToModify_Item,
    &ett_x2ap_Old_ECGIs,
    &ett_x2ap_ENBConfigurationUpdateAcknowledge,
    &ett_x2ap_ENBConfigurationUpdateFailure,
    &ett_x2ap_ResourceStatusRequest,
    &ett_x2ap_CellToReport_List,
    &ett_x2ap_CellToReport_Item,
    &ett_x2ap_ResourceStatusResponse,
    &ett_x2ap_MeasurementInitiationResult_List,
    &ett_x2ap_MeasurementInitiationResult_Item,
    &ett_x2ap_MeasurementFailureCause_List,
    &ett_x2ap_MeasurementFailureCause_Item,
    &ett_x2ap_ResourceStatusFailure,
    &ett_x2ap_CompleteFailureCauseInformation_List,
    &ett_x2ap_CompleteFailureCauseInformation_Item,
    &ett_x2ap_ResourceStatusUpdate,
    &ett_x2ap_CellMeasurementResult_List,
    &ett_x2ap_CellMeasurementResult_Item,
    &ett_x2ap_PrivateMessage,
    &ett_x2ap_MobilityChangeRequest,
    &ett_x2ap_MobilityChangeAcknowledge,
    &ett_x2ap_MobilityChangeFailure,
    &ett_x2ap_RLFIndication,
    &ett_x2ap_CellActivationRequest,
    &ett_x2ap_ServedCellsToActivate,
    &ett_x2ap_ServedCellsToActivate_Item,
    &ett_x2ap_CellActivationResponse,
    &ett_x2ap_ActivatedCellList,
    &ett_x2ap_ActivatedCellList_Item,
    &ett_x2ap_CellActivationFailure,
    &ett_x2ap_X2Release,
    &ett_x2ap_X2APMessageTransfer,
    &ett_x2ap_RNL_Header,
    &ett_x2ap_SeNBAdditionRequest,
    &ett_x2ap_E_RABs_ToBeAdded_List,
    &ett_x2ap_E_RABs_ToBeAdded_Item,
    &ett_x2ap_E_RABs_ToBeAdded_Item_SCG_Bearer,
    &ett_x2ap_E_RABs_ToBeAdded_Item_Split_Bearer,
    &ett_x2ap_SeNBAdditionRequestAcknowledge,
    &ett_x2ap_E_RABs_Admitted_ToBeAdded_List,
    &ett_x2ap_E_RABs_Admitted_ToBeAdded_Item,
    &ett_x2ap_E_RABs_Admitted_ToBeAdded_Item_SCG_Bearer,
    &ett_x2ap_E_RABs_Admitted_ToBeAdded_Item_Split_Bearer,
    &ett_x2ap_SeNBAdditionRequestReject,
    &ett_x2ap_SeNBReconfigurationComplete,
    &ett_x2ap_ResponseInformationSeNBReconfComp,
    &ett_x2ap_ResponseInformationSeNBReconfComp_SuccessItem,
    &ett_x2ap_ResponseInformationSeNBReconfComp_RejectByMeNBItem,
    &ett_x2ap_SeNBModificationRequest,
    &ett_x2ap_UE_ContextInformationSeNBModReq,
    &ett_x2ap_E_RABs_ToBeAdded_List_ModReq,
    &ett_x2ap_E_RABs_ToBeAdded_ModReqItem,
    &ett_x2ap_E_RABs_ToBeAdded_ModReqItem_SCG_Bearer,
    &ett_x2ap_E_RABs_ToBeAdded_ModReqItem_Split_Bearer,
    &ett_x2ap_E_RABs_ToBeModified_List_ModReq,
    &ett_x2ap_E_RABs_ToBeModified_ModReqItem,
    &ett_x2ap_E_RABs_ToBeModified_ModReqItem_SCG_Bearer,
    &ett_x2ap_E_RABs_ToBeModified_ModReqItem_Split_Bearer,
    &ett_x2ap_E_RABs_ToBeReleased_List_ModReq,
    &ett_x2ap_E_RABs_ToBeReleased_ModReqItem,
    &ett_x2ap_E_RABs_ToBeReleased_ModReqItem_SCG_Bearer,
    &ett_x2ap_E_RABs_ToBeReleased_ModReqItem_Split_Bearer,
    &ett_x2ap_SeNBModificationRequestAcknowledge,
    &ett_x2ap_E_RABs_Admitted_ToBeAdded_ModAckList,
    &ett_x2ap_E_RABs_Admitted_ToBeAdded_ModAckItem,
    &ett_x2ap_E_RABs_Admitted_ToBeAdded_ModAckItem_SCG_Bearer,
    &ett_x2ap_E_RABs_Admitted_ToBeAdded_ModAckItem_Split_Bearer,
    &ett_x2ap_E_RABs_Admitted_ToBeModified_ModAckList,
    &ett_x2ap_E_RABs_Admitted_ToBeModified_ModAckItem,
    &ett_x2ap_E_RABs_Admitted_ToBeModified_ModAckItem_SCG_Bearer,
    &ett_x2ap_E_RABs_Admitted_ToBeModified_ModAckItem_Split_Bearer,
    &ett_x2ap_E_RABs_Admitted_ToBeReleased_ModAckList,
    &ett_x2ap_E_RABs_Admitted_ToReleased_ModAckItem,
    &ett_x2ap_E_RABs_Admitted_ToBeReleased_ModAckItem_SCG_Bearer,
    &ett_x2ap_E_RABs_Admitted_ToBeReleased_ModAckItem_Split_Bearer,
    &ett_x2ap_SeNBModificationRequestReject,
    &ett_x2ap_SeNBModificationRequired,
    &ett_x2ap_E_RABs_ToBeReleased_ModReqd,
    &ett_x2ap_E_RABs_ToBeReleased_ModReqdItem,
    &ett_x2ap_SeNBModificationConfirm,
    &ett_x2ap_SeNBModificationRefuse,
    &ett_x2ap_SeNBReleaseRequest,
    &ett_x2ap_E_RABs_ToBeReleased_List_RelReq,
    &ett_x2ap_E_RABs_ToBeReleased_RelReqItem,
    &ett_x2ap_E_RABs_ToBeReleased_RelReqItem_SCG_Bearer,
    &ett_x2ap_E_RABs_ToBeReleased_RelReqItem_Split_Bearer,
    &ett_x2ap_SeNBReleaseRequired,
    &ett_x2ap_SeNBReleaseConfirm,
    &ett_x2ap_E_RABs_ToBeReleased_List_RelConf,
    &ett_x2ap_E_RABs_ToBeReleased_RelConfItem,
    &ett_x2ap_E_RABs_ToBeReleased_RelConfItem_SCG_Bearer,
    &ett_x2ap_E_RABs_ToBeReleased_RelConfItem_Split_Bearer,
    &ett_x2ap_SeNBCounterCheckRequest,
    &ett_x2ap_E_RABs_SubjectToCounterCheck_List,
    &ett_x2ap_E_RABs_SubjectToCounterCheckItem,
    &ett_x2ap_X2RemovalRequest,
    &ett_x2ap_X2RemovalResponse,
    &ett_x2ap_X2RemovalFailure,
    &ett_x2ap_RetrieveUEContextRequest,
    &ett_x2ap_RetrieveUEContextResponse,
    &ett_x2ap_UE_ContextInformationRetrieve,
    &ett_x2ap_E_RABs_ToBeSetup_ListRetrieve,
    &ett_x2ap_E_RABs_ToBeSetupRetrieve_Item,
    &ett_x2ap_RetrieveUEContextFailure,
    &ett_x2ap_X2AP_PDU,
    &ett_x2ap_InitiatingMessage,
    &ett_x2ap_SuccessfulOutcome,
    &ett_x2ap_UnsuccessfulOutcome,

/*--- End of included file: packet-x2ap-ettarr.c ---*/
#line 527 "./asn1/x2ap/packet-x2ap-template.c"
  };

  module_t *x2ap_module;

  /* Register protocol */
  proto_x2ap = proto_register_protocol(PNAME, PSNAME, PFNAME);
  /* Register fields and subtrees */
  proto_register_field_array(proto_x2ap, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));

  /* Register dissector */
  x2ap_handle = register_dissector("x2ap", dissect_x2ap, proto_x2ap);

  /* Register dissector tables */
  x2ap_ies_dissector_table = register_dissector_table("x2ap.ies", "X2AP-PROTOCOL-IES", proto_x2ap, FT_UINT32, BASE_DEC);
  x2ap_extension_dissector_table = register_dissector_table("x2ap.extension", "X2AP-PROTOCOL-EXTENSION", proto_x2ap, FT_UINT32, BASE_DEC);
  x2ap_proc_imsg_dissector_table = register_dissector_table("x2ap.proc.imsg", "X2AP-ELEMENTARY-PROCEDURE InitiatingMessage", proto_x2ap, FT_UINT32, BASE_DEC);
  x2ap_proc_sout_dissector_table = register_dissector_table("x2ap.proc.sout", "X2AP-ELEMENTARY-PROCEDURE SuccessfulOutcome", proto_x2ap, FT_UINT32, BASE_DEC);
  x2ap_proc_uout_dissector_table = register_dissector_table("x2ap.proc.uout", "X2AP-ELEMENTARY-PROCEDURE UnsuccessfulOutcome", proto_x2ap, FT_UINT32, BASE_DEC);

  /* Register configuration options for ports */
  x2ap_module = prefs_register_protocol(proto_x2ap, proto_reg_handoff_x2ap);

  prefs_register_uint_preference(x2ap_module, "sctp.port",
                                 "X2AP SCTP Port",
                                 "Set the SCTP port for X2AP messages",
                                 10,
                                 &gbl_x2apSctpPort);
  prefs_register_enum_preference(x2ap_module, "dissect_rrc_context_as", "Dissect RRC Context as",
                                 "Select whether RRC Context should be dissected as legacy LTE or NB-IOT",
                                 &g_x2ap_dissect_rrc_context_as, x2ap_rrc_context_vals, FALSE);
}


/*--- proto_reg_handoff_x2ap ---------------------------------------*/
void
proto_reg_handoff_x2ap(void)
{
  static gboolean Initialized=FALSE;
  static guint SctpPort;

  if (!Initialized) {
    dissector_add_for_decode_as("sctp.port", x2ap_handle);
    dissector_add_uint("sctp.ppi", X2AP_PAYLOAD_PROTOCOL_ID, x2ap_handle);
    Initialized=TRUE;

/*--- Included file: packet-x2ap-dis-tab.c ---*/
#line 1 "./asn1/x2ap/packet-x2ap-dis-tab.c"
  dissector_add_uint("x2ap.ies", id_E_RABs_Admitted_Item, create_dissector_handle(dissect_E_RABs_Admitted_Item_PDU, proto_x2ap));
  dissector_add_uint("x2ap.ies", id_E_RABs_Admitted_List, create_dissector_handle(dissect_E_RABs_Admitted_List_PDU, proto_x2ap));
  dissector_add_uint("x2ap.ies", id_E_RAB_Item, create_dissector_handle(dissect_E_RAB_Item_PDU, proto_x2ap));
  dissector_add_uint("x2ap.ies", id_E_RABs_NotAdmitted_List, create_dissector_handle(dissect_E_RAB_List_PDU, proto_x2ap));
  dissector_add_uint("x2ap.ies", id_E_RABs_ToBeSetup_Item, create_dissector_handle(dissect_E_RABs_ToBeSetup_Item_PDU, proto_x2ap));
  dissector_add_uint("x2ap.ies", id_Cause, create_dissector_handle(dissect_Cause_PDU, proto_x2ap));
  dissector_add_uint("x2ap.ies", id_CellInformation, create_dissector_handle(dissect_CellInformation_List_PDU, proto_x2ap));
  dissector_add_uint("x2ap.ies", id_CellInformation_Item, create_dissector_handle(dissect_CellInformation_Item_PDU, proto_x2ap));
  dissector_add_uint("x2ap.ies", id_New_eNB_UE_X2AP_ID, create_dissector_handle(dissect_UE_X2AP_ID_PDU, proto_x2ap));
  dissector_add_uint("x2ap.ies", id_Old_eNB_UE_X2AP_ID, create_dissector_handle(dissect_UE_X2AP_ID_PDU, proto_x2ap));
  dissector_add_uint("x2ap.ies", id_TargetCell_ID, create_dissector_handle(dissect_ECGI_PDU, proto_x2ap));
  dissector_add_uint("x2ap.ies", id_TargeteNBtoSource_eNBTransparentContainer, create_dissector_handle(dissect_TargeteNBtoSource_eNBTransparentContainer_PDU, proto_x2ap));
  dissector_add_uint("x2ap.ies", id_TraceActivation, create_dissector_handle(dissect_TraceActivation_PDU, proto_x2ap));
  dissector_add_uint("x2ap.ies", id_UE_ContextInformation, create_dissector_handle(dissect_UE_ContextInformation_PDU, proto_x2ap));
  dissector_add_uint("x2ap.ies", id_UE_HistoryInformation, create_dissector_handle(dissect_UE_HistoryInformation_PDU, proto_x2ap));
  dissector_add_uint("x2ap.ies", id_UE_X2AP_ID, create_dissector_handle(dissect_UE_X2AP_ID_PDU, proto_x2ap));
  dissector_add_uint("x2ap.ies", id_CriticalityDiagnostics, create_dissector_handle(dissect_CriticalityDiagnostics_PDU, proto_x2ap));
  dissector_add_uint("x2ap.ies", id_E_RABs_SubjectToStatusTransfer_List, create_dissector_handle(dissect_E_RABs_SubjectToStatusTransfer_List_PDU, proto_x2ap));
  dissector_add_uint("x2ap.ies", id_E_RABs_SubjectToStatusTransfer_Item, create_dissector_handle(dissect_E_RABs_SubjectToStatusTransfer_Item_PDU, proto_x2ap));
  dissector_add_uint("x2ap.ies", id_ServedCells, create_dissector_handle(dissect_ServedCells_PDU, proto_x2ap));
  dissector_add_uint("x2ap.ies", id_GlobalENB_ID, create_dissector_handle(dissect_GlobalENB_ID_PDU, proto_x2ap));
  dissector_add_uint("x2ap.ies", id_TimeToWait, create_dissector_handle(dissect_TimeToWait_PDU, proto_x2ap));
  dissector_add_uint("x2ap.ies", id_GUMMEI_ID, create_dissector_handle(dissect_GUMMEI_PDU, proto_x2ap));
  dissector_add_uint("x2ap.ies", id_GUGroupIDList, create_dissector_handle(dissect_GUGroupIDList_PDU, proto_x2ap));
  dissector_add_uint("x2ap.ies", id_ServedCellsToAdd, create_dissector_handle(dissect_ServedCells_PDU, proto_x2ap));
  dissector_add_uint("x2ap.ies", id_ServedCellsToModify, create_dissector_handle(dissect_ServedCellsToModify_PDU, proto_x2ap));
  dissector_add_uint("x2ap.ies", id_ServedCellsToDelete, create_dissector_handle(dissect_Old_ECGIs_PDU, proto_x2ap));
  dissector_add_uint("x2ap.ies", id_Registration_Request, create_dissector_handle(dissect_Registration_Request_PDU, proto_x2ap));
  dissector_add_uint("x2ap.ies", id_CellToReport, create_dissector_handle(dissect_CellToReport_List_PDU, proto_x2ap));
  dissector_add_uint("x2ap.ies", id_ReportingPeriodicity, create_dissector_handle(dissect_ReportingPeriodicity_PDU, proto_x2ap));
  dissector_add_uint("x2ap.ies", id_CellToReport_Item, create_dissector_handle(dissect_CellToReport_Item_PDU, proto_x2ap));
  dissector_add_uint("x2ap.ies", id_CellMeasurementResult, create_dissector_handle(dissect_CellMeasurementResult_List_PDU, proto_x2ap));
  dissector_add_uint("x2ap.ies", id_CellMeasurementResult_Item, create_dissector_handle(dissect_CellMeasurementResult_Item_PDU, proto_x2ap));
  dissector_add_uint("x2ap.ies", id_GUGroupIDToAddList, create_dissector_handle(dissect_GUGroupIDList_PDU, proto_x2ap));
  dissector_add_uint("x2ap.ies", id_GUGroupIDToDeleteList, create_dissector_handle(dissect_GUGroupIDList_PDU, proto_x2ap));
  dissector_add_uint("x2ap.ies", id_SRVCCOperationPossible, create_dissector_handle(dissect_SRVCCOperationPossible_PDU, proto_x2ap));
  dissector_add_uint("x2ap.ies", id_ReportCharacteristics, create_dissector_handle(dissect_ReportCharacteristics_PDU, proto_x2ap));
  dissector_add_uint("x2ap.ies", id_ENB1_Measurement_ID, create_dissector_handle(dissect_Measurement_ID_PDU, proto_x2ap));
  dissector_add_uint("x2ap.ies", id_ENB2_Measurement_ID, create_dissector_handle(dissect_Measurement_ID_PDU, proto_x2ap));
  dissector_add_uint("x2ap.ies", id_ENB1_Cell_ID, create_dissector_handle(dissect_ECGI_PDU, proto_x2ap));
  dissector_add_uint("x2ap.ies", id_ENB2_Cell_ID, create_dissector_handle(dissect_ECGI_PDU, proto_x2ap));
  dissector_add_uint("x2ap.ies", id_ENB2_Proposed_Mobility_Parameters, create_dissector_handle(dissect_MobilityParametersInformation_PDU, proto_x2ap));
  dissector_add_uint("x2ap.ies", id_ENB1_Mobility_Parameters, create_dissector_handle(dissect_MobilityParametersInformation_PDU, proto_x2ap));
  dissector_add_uint("x2ap.ies", id_ENB2_Mobility_Parameters_Modification_Range, create_dissector_handle(dissect_MobilityParametersModificationRange_PDU, proto_x2ap));
  dissector_add_uint("x2ap.ies", id_FailureCellPCI, create_dissector_handle(dissect_PCI_PDU, proto_x2ap));
  dissector_add_uint("x2ap.ies", id_Re_establishmentCellECGI, create_dissector_handle(dissect_ECGI_PDU, proto_x2ap));
  dissector_add_uint("x2ap.ies", id_FailureCellCRNTI, create_dissector_handle(dissect_CRNTI_PDU, proto_x2ap));
  dissector_add_uint("x2ap.ies", id_ShortMAC_I, create_dissector_handle(dissect_ShortMAC_I_PDU, proto_x2ap));
  dissector_add_uint("x2ap.ies", id_SourceCellECGI, create_dissector_handle(dissect_ECGI_PDU, proto_x2ap));
  dissector_add_uint("x2ap.ies", id_FailureCellECGI, create_dissector_handle(dissect_ECGI_PDU, proto_x2ap));
  dissector_add_uint("x2ap.ies", id_HandoverReportType, create_dissector_handle(dissect_HandoverReportType_PDU, proto_x2ap));
  dissector_add_uint("x2ap.ies", id_UE_RLF_Report_Container, create_dissector_handle(dissect_UE_RLF_Report_Container_PDU, proto_x2ap));
  dissector_add_uint("x2ap.ies", id_ServedCellsToActivate, create_dissector_handle(dissect_ServedCellsToActivate_PDU, proto_x2ap));
  dissector_add_uint("x2ap.ies", id_ActivatedCellList, create_dissector_handle(dissect_ActivatedCellList_PDU, proto_x2ap));
  dissector_add_uint("x2ap.ies", id_PartialSuccessIndicator, create_dissector_handle(dissect_PartialSuccessIndicator_PDU, proto_x2ap));
  dissector_add_uint("x2ap.ies", id_MeasurementInitiationResult_List, create_dissector_handle(dissect_MeasurementInitiationResult_List_PDU, proto_x2ap));
  dissector_add_uint("x2ap.ies", id_MeasurementInitiationResult_Item, create_dissector_handle(dissect_MeasurementInitiationResult_Item_PDU, proto_x2ap));
  dissector_add_uint("x2ap.ies", id_MeasurementFailureCause_Item, create_dissector_handle(dissect_MeasurementFailureCause_Item_PDU, proto_x2ap));
  dissector_add_uint("x2ap.ies", id_CompleteFailureCauseInformation_List, create_dissector_handle(dissect_CompleteFailureCauseInformation_List_PDU, proto_x2ap));
  dissector_add_uint("x2ap.ies", id_CompleteFailureCauseInformation_Item, create_dissector_handle(dissect_CompleteFailureCauseInformation_Item_PDU, proto_x2ap));
  dissector_add_uint("x2ap.ies", id_CSGMembershipStatus, create_dissector_handle(dissect_CSGMembershipStatus_PDU, proto_x2ap));
  dissector_add_uint("x2ap.ies", id_RRCConnSetupIndicator, create_dissector_handle(dissect_RRCConnSetupIndicator_PDU, proto_x2ap));
  dissector_add_uint("x2ap.ies", id_RRCConnReestabIndicator, create_dissector_handle(dissect_RRCConnReestabIndicator_PDU, proto_x2ap));
  dissector_add_uint("x2ap.ies", id_TargetCellInUTRAN, create_dissector_handle(dissect_TargetCellInUTRAN_PDU, proto_x2ap));
  dissector_add_uint("x2ap.ies", id_MobilityInformation, create_dissector_handle(dissect_MobilityInformation_PDU, proto_x2ap));
  dissector_add_uint("x2ap.ies", id_SourceCellCRNTI, create_dissector_handle(dissect_CRNTI_PDU, proto_x2ap));
  dissector_add_uint("x2ap.ies", id_Masked_IMEISV, create_dissector_handle(dissect_Masked_IMEISV_PDU, proto_x2ap));
  dissector_add_uint("x2ap.ies", id_RNL_Header, create_dissector_handle(dissect_RNL_Header_PDU, proto_x2ap));
  dissector_add_uint("x2ap.ies", id_x2APMessage, create_dissector_handle(dissect_X2AP_Message_PDU, proto_x2ap));
  dissector_add_uint("x2ap.ies", id_ProSeAuthorized, create_dissector_handle(dissect_ProSeAuthorized_PDU, proto_x2ap));
  dissector_add_uint("x2ap.ies", id_ExpectedUEBehaviour, create_dissector_handle(dissect_ExpectedUEBehaviour_PDU, proto_x2ap));
  dissector_add_uint("x2ap.ies", id_UE_HistoryInformationFromTheUE, create_dissector_handle(dissect_UE_HistoryInformationFromTheUE_PDU, proto_x2ap));
  dissector_add_uint("x2ap.ies", id_UE_RLF_Report_Container_for_extended_bands, create_dissector_handle(dissect_UE_RLF_Report_Container_for_extended_bands_PDU, proto_x2ap));
  dissector_add_uint("x2ap.ies", id_ReportingPeriodicityRSRPMR, create_dissector_handle(dissect_ReportingPeriodicityRSRPMR_PDU, proto_x2ap));
  dissector_add_uint("x2ap.ies", id_MeNB_UE_X2AP_ID, create_dissector_handle(dissect_UE_X2AP_ID_PDU, proto_x2ap));
  dissector_add_uint("x2ap.ies", id_SeNB_UE_X2AP_ID, create_dissector_handle(dissect_UE_X2AP_ID_PDU, proto_x2ap));
  dissector_add_uint("x2ap.ies", id_UE_SecurityCapabilities, create_dissector_handle(dissect_UESecurityCapabilities_PDU, proto_x2ap));
  dissector_add_uint("x2ap.ies", id_SeNBSecurityKey, create_dissector_handle(dissect_SeNBSecurityKey_PDU, proto_x2ap));
  dissector_add_uint("x2ap.ies", id_SeNBUEAggregateMaximumBitRate, create_dissector_handle(dissect_UEAggregateMaximumBitRate_PDU, proto_x2ap));
  dissector_add_uint("x2ap.ies", id_ServingPLMN, create_dissector_handle(dissect_PLMN_Identity_PDU, proto_x2ap));
  dissector_add_uint("x2ap.ies", id_E_RABs_ToBeAdded_List, create_dissector_handle(dissect_E_RABs_ToBeAdded_List_PDU, proto_x2ap));
  dissector_add_uint("x2ap.ies", id_E_RABs_ToBeAdded_Item, create_dissector_handle(dissect_E_RABs_ToBeAdded_Item_PDU, proto_x2ap));
  dissector_add_uint("x2ap.ies", id_MeNBtoSeNBContainer, create_dissector_handle(dissect_MeNBtoSeNBContainer_PDU, proto_x2ap));
  dissector_add_uint("x2ap.ies", id_E_RABs_Admitted_ToBeAdded_List, create_dissector_handle(dissect_E_RABs_Admitted_ToBeAdded_List_PDU, proto_x2ap));
  dissector_add_uint("x2ap.ies", id_E_RABs_Admitted_ToBeAdded_Item, create_dissector_handle(dissect_E_RABs_Admitted_ToBeAdded_Item_PDU, proto_x2ap));
  dissector_add_uint("x2ap.ies", id_SeNBtoMeNBContainer, create_dissector_handle(dissect_SeNBtoMeNBContainer_PDU, proto_x2ap));
  dissector_add_uint("x2ap.ies", id_ResponseInformationSeNBReconfComp, create_dissector_handle(dissect_ResponseInformationSeNBReconfComp_PDU, proto_x2ap));
  dissector_add_uint("x2ap.ies", id_UE_ContextInformationSeNBModReq, create_dissector_handle(dissect_UE_ContextInformationSeNBModReq_PDU, proto_x2ap));
  dissector_add_uint("x2ap.ies", id_E_RABs_ToBeAdded_ModReqItem, create_dissector_handle(dissect_E_RABs_ToBeAdded_ModReqItem_PDU, proto_x2ap));
  dissector_add_uint("x2ap.ies", id_E_RABs_ToBeModified_ModReqItem, create_dissector_handle(dissect_E_RABs_ToBeModified_ModReqItem_PDU, proto_x2ap));
  dissector_add_uint("x2ap.ies", id_E_RABs_ToBeReleased_ModReqItem, create_dissector_handle(dissect_E_RABs_ToBeReleased_ModReqItem_PDU, proto_x2ap));
  dissector_add_uint("x2ap.ies", id_E_RABs_Admitted_ToBeAdded_ModAckList, create_dissector_handle(dissect_E_RABs_Admitted_ToBeAdded_ModAckList_PDU, proto_x2ap));
  dissector_add_uint("x2ap.ies", id_E_RABs_Admitted_ToBeModified_ModAckList, create_dissector_handle(dissect_E_RABs_Admitted_ToBeModified_ModAckList_PDU, proto_x2ap));
  dissector_add_uint("x2ap.ies", id_E_RABs_Admitted_ToBeReleased_ModAckList, create_dissector_handle(dissect_E_RABs_Admitted_ToBeReleased_ModAckList_PDU, proto_x2ap));
  dissector_add_uint("x2ap.ies", id_E_RABs_Admitted_ToBeAdded_ModAckItem, create_dissector_handle(dissect_E_RABs_Admitted_ToBeAdded_ModAckItem_PDU, proto_x2ap));
  dissector_add_uint("x2ap.ies", id_E_RABs_Admitted_ToBeModified_ModAckItem, create_dissector_handle(dissect_E_RABs_Admitted_ToBeModified_ModAckItem_PDU, proto_x2ap));
  dissector_add_uint("x2ap.ies", id_E_RABs_Admitted_ToBeReleased_ModAckItem, create_dissector_handle(dissect_E_RABs_Admitted_ToReleased_ModAckItem_PDU, proto_x2ap));
  dissector_add_uint("x2ap.ies", id_E_RABs_ToBeReleased_ModReqd, create_dissector_handle(dissect_E_RABs_ToBeReleased_ModReqd_PDU, proto_x2ap));
  dissector_add_uint("x2ap.ies", id_E_RABs_ToBeReleased_ModReqdItem, create_dissector_handle(dissect_E_RABs_ToBeReleased_ModReqdItem_PDU, proto_x2ap));
  dissector_add_uint("x2ap.ies", id_SCGChangeIndication, create_dissector_handle(dissect_SCGChangeIndication_PDU, proto_x2ap));
  dissector_add_uint("x2ap.ies", id_E_RABs_ToBeReleased_List_RelReq, create_dissector_handle(dissect_E_RABs_ToBeReleased_List_RelReq_PDU, proto_x2ap));
  dissector_add_uint("x2ap.ies", id_E_RABs_ToBeReleased_RelReqItem, create_dissector_handle(dissect_E_RABs_ToBeReleased_RelReqItem_PDU, proto_x2ap));
  dissector_add_uint("x2ap.ies", id_E_RABs_ToBeReleased_List_RelConf, create_dissector_handle(dissect_E_RABs_ToBeReleased_List_RelConf_PDU, proto_x2ap));
  dissector_add_uint("x2ap.ies", id_E_RABs_ToBeReleased_RelConfItem, create_dissector_handle(dissect_E_RABs_ToBeReleased_RelConfItem_PDU, proto_x2ap));
  dissector_add_uint("x2ap.ies", id_E_RABs_SubjectToCounterCheck_List, create_dissector_handle(dissect_E_RABs_SubjectToCounterCheck_List_PDU, proto_x2ap));
  dissector_add_uint("x2ap.ies", id_E_RABs_SubjectToCounterCheckItem, create_dissector_handle(dissect_E_RABs_SubjectToCounterCheckItem_PDU, proto_x2ap));
  dissector_add_uint("x2ap.ies", id_CoverageModificationList, create_dissector_handle(dissect_CoverageModificationList_PDU, proto_x2ap));
  dissector_add_uint("x2ap.ies", id_ReportingPeriodicityCSIR, create_dissector_handle(dissect_ReportingPeriodicityCSIR_PDU, proto_x2ap));
  dissector_add_uint("x2ap.ies", id_UE_ContextReferenceAtSeNB, create_dissector_handle(dissect_UE_ContextReferenceAtSeNB_PDU, proto_x2ap));
  dissector_add_uint("x2ap.ies", id_UE_ContextKeptIndicator, create_dissector_handle(dissect_UE_ContextKeptIndicator_PDU, proto_x2ap));
  dissector_add_uint("x2ap.ies", id_New_eNB_UE_X2AP_ID_Extension, create_dissector_handle(dissect_UE_X2AP_ID_Extension_PDU, proto_x2ap));
  dissector_add_uint("x2ap.ies", id_Old_eNB_UE_X2AP_ID_Extension, create_dissector_handle(dissect_UE_X2AP_ID_Extension_PDU, proto_x2ap));
  dissector_add_uint("x2ap.ies", id_MeNB_UE_X2AP_ID_Extension, create_dissector_handle(dissect_UE_X2AP_ID_Extension_PDU, proto_x2ap));
  dissector_add_uint("x2ap.ies", id_SeNB_UE_X2AP_ID_Extension, create_dissector_handle(dissect_UE_X2AP_ID_Extension_PDU, proto_x2ap));
  dissector_add_uint("x2ap.ies", id_LHN_ID, create_dissector_handle(dissect_LHN_ID_PDU, proto_x2ap));
  dissector_add_uint("x2ap.ies", id_Tunnel_Information_for_BBF, create_dissector_handle(dissect_TunnelInformation_PDU, proto_x2ap));
  dissector_add_uint("x2ap.ies", id_SIPTO_BearerDeactivationIndication, create_dissector_handle(dissect_SIPTOBearerDeactivationIndication_PDU, proto_x2ap));
  dissector_add_uint("x2ap.ies", id_GW_TransportLayerAddress, create_dissector_handle(dissect_TransportLayerAddress_PDU, proto_x2ap));
  dissector_add_uint("x2ap.ies", id_SIPTO_L_GW_TransportLayerAddress, create_dissector_handle(dissect_TransportLayerAddress_PDU, proto_x2ap));
  dissector_add_uint("x2ap.ies", id_X2RemovalThreshold, create_dissector_handle(dissect_X2BenefitValue_PDU, proto_x2ap));
  dissector_add_uint("x2ap.ies", id_resumeID, create_dissector_handle(dissect_ResumeID_PDU, proto_x2ap));
  dissector_add_uint("x2ap.ies", id_UE_ContextInformationRetrieve, create_dissector_handle(dissect_UE_ContextInformationRetrieve_PDU, proto_x2ap));
  dissector_add_uint("x2ap.ies", id_E_RABs_ToBeSetupRetrieve_Item, create_dissector_handle(dissect_E_RABs_ToBeSetupRetrieve_Item_PDU, proto_x2ap));
  dissector_add_uint("x2ap.ies", id_NewEUTRANCellIdentifier, create_dissector_handle(dissect_EUTRANCellIdentifier_PDU, proto_x2ap));
  dissector_add_uint("x2ap.extension", id_Number_of_Antennaports, create_dissector_handle(dissect_Number_of_Antennaports_PDU, proto_x2ap));
  dissector_add_uint("x2ap.extension", id_CompositeAvailableCapacityGroup, create_dissector_handle(dissect_CompositeAvailableCapacityGroup_PDU, proto_x2ap));
  dissector_add_uint("x2ap.extension", id_PRACH_Configuration, create_dissector_handle(dissect_PRACH_Configuration_PDU, proto_x2ap));
  dissector_add_uint("x2ap.extension", id_MBSFN_Subframe_Info, create_dissector_handle(dissect_MBSFN_Subframe_Infolist_PDU, proto_x2ap));
  dissector_add_uint("x2ap.extension", id_DeactivationIndication, create_dissector_handle(dissect_DeactivationIndication_PDU, proto_x2ap));
  dissector_add_uint("x2ap.extension", id_ABSInformation, create_dissector_handle(dissect_ABSInformation_PDU, proto_x2ap));
  dissector_add_uint("x2ap.extension", id_InvokeIndication, create_dissector_handle(dissect_InvokeIndication_PDU, proto_x2ap));
  dissector_add_uint("x2ap.extension", id_ABS_Status, create_dissector_handle(dissect_ABS_Status_PDU, proto_x2ap));
  dissector_add_uint("x2ap.extension", id_CSG_Id, create_dissector_handle(dissect_CSG_Id_PDU, proto_x2ap));
  dissector_add_uint("x2ap.extension", id_MDTConfiguration, create_dissector_handle(dissect_MDT_Configuration_PDU, proto_x2ap));
  dissector_add_uint("x2ap.extension", id_ManagementBasedMDTallowed, create_dissector_handle(dissect_ManagementBasedMDTallowed_PDU, proto_x2ap));
  dissector_add_uint("x2ap.extension", id_NeighbourTAC, create_dissector_handle(dissect_TAC_PDU, proto_x2ap));
  dissector_add_uint("x2ap.extension", id_Time_UE_StayedInCell_EnhancedGranularity, create_dissector_handle(dissect_Time_UE_StayedInCell_EnhancedGranularity_PDU, proto_x2ap));
  dissector_add_uint("x2ap.extension", id_MBMS_Service_Area_List, create_dissector_handle(dissect_MBMS_Service_Area_Identity_List_PDU, proto_x2ap));
  dissector_add_uint("x2ap.extension", id_HO_cause, create_dissector_handle(dissect_Cause_PDU, proto_x2ap));
  dissector_add_uint("x2ap.extension", id_MultibandInfoList, create_dissector_handle(dissect_MultibandInfoList_PDU, proto_x2ap));
  dissector_add_uint("x2ap.extension", id_M3Configuration, create_dissector_handle(dissect_M3Configuration_PDU, proto_x2ap));
  dissector_add_uint("x2ap.extension", id_M4Configuration, create_dissector_handle(dissect_M4Configuration_PDU, proto_x2ap));
  dissector_add_uint("x2ap.extension", id_M5Configuration, create_dissector_handle(dissect_M5Configuration_PDU, proto_x2ap));
  dissector_add_uint("x2ap.extension", id_MDT_Location_Info, create_dissector_handle(dissect_MDT_Location_Info_PDU, proto_x2ap));
  dissector_add_uint("x2ap.extension", id_ManagementBasedMDTPLMNList, create_dissector_handle(dissect_MDTPLMNList_PDU, proto_x2ap));
  dissector_add_uint("x2ap.extension", id_SignallingBasedMDTPLMNList, create_dissector_handle(dissect_MDTPLMNList_PDU, proto_x2ap));
  dissector_add_uint("x2ap.extension", id_ReceiveStatusOfULPDCPSDUsExtended, create_dissector_handle(dissect_ReceiveStatusOfULPDCPSDUsExtended_PDU, proto_x2ap));
  dissector_add_uint("x2ap.extension", id_ULCOUNTValueExtended, create_dissector_handle(dissect_COUNTValueExtended_PDU, proto_x2ap));
  dissector_add_uint("x2ap.extension", id_DLCOUNTValueExtended, create_dissector_handle(dissect_COUNTValueExtended_PDU, proto_x2ap));
  dissector_add_uint("x2ap.extension", id_eARFCNExtension, create_dissector_handle(dissect_EARFCNExtension_PDU, proto_x2ap));
  dissector_add_uint("x2ap.extension", id_UL_EARFCNExtension, create_dissector_handle(dissect_EARFCNExtension_PDU, proto_x2ap));
  dissector_add_uint("x2ap.extension", id_DL_EARFCNExtension, create_dissector_handle(dissect_EARFCNExtension_PDU, proto_x2ap));
  dissector_add_uint("x2ap.extension", id_AdditionalSpecialSubframe_Info, create_dissector_handle(dissect_AdditionalSpecialSubframe_Info_PDU, proto_x2ap));
  dissector_add_uint("x2ap.extension", id_IntendedULDLConfiguration, create_dissector_handle(dissect_SubframeAssignment_PDU, proto_x2ap));
  dissector_add_uint("x2ap.extension", id_ExtendedULInterferenceOverloadInfo, create_dissector_handle(dissect_ExtendedULInterferenceOverloadInfo_PDU, proto_x2ap));
  dissector_add_uint("x2ap.extension", id_DynamicDLTransmissionInformation, create_dissector_handle(dissect_DynamicDLTransmissionInformation_PDU, proto_x2ap));
  dissector_add_uint("x2ap.extension", id_CoMPInformation, create_dissector_handle(dissect_CoMPInformation_PDU, proto_x2ap));
  dissector_add_uint("x2ap.extension", id_RSRPMRList, create_dissector_handle(dissect_RSRPMRList_PDU, proto_x2ap));
  dissector_add_uint("x2ap.extension", id_CSIReportList, create_dissector_handle(dissect_CSIReportList_PDU, proto_x2ap));
  dissector_add_uint("x2ap.extension", id_UEID, create_dissector_handle(dissect_UEID_PDU, proto_x2ap));
  dissector_add_uint("x2ap.extension", id_enhancedRNTP, create_dissector_handle(dissect_EnhancedRNTP_PDU, proto_x2ap));
  dissector_add_uint("x2ap.extension", id_ProSeUEtoNetworkRelaying, create_dissector_handle(dissect_ProSeUEtoNetworkRelaying_PDU, proto_x2ap));
  dissector_add_uint("x2ap.extension", id_ReceiveStatusOfULPDCPSDUsPDCP_SNlength18, create_dissector_handle(dissect_ReceiveStatusOfULPDCPSDUsPDCP_SNlength18_PDU, proto_x2ap));
  dissector_add_uint("x2ap.extension", id_ULCOUNTValuePDCP_SNlength18, create_dissector_handle(dissect_COUNTvaluePDCP_SNlength18_PDU, proto_x2ap));
  dissector_add_uint("x2ap.extension", id_DLCOUNTValuePDCP_SNlength18, create_dissector_handle(dissect_COUNTvaluePDCP_SNlength18_PDU, proto_x2ap));
  dissector_add_uint("x2ap.extension", id_FreqBandIndicatorPriority, create_dissector_handle(dissect_FreqBandIndicatorPriority_PDU, proto_x2ap));
  dissector_add_uint("x2ap.extension", id_M6Configuration, create_dissector_handle(dissect_M6Configuration_PDU, proto_x2ap));
  dissector_add_uint("x2ap.extension", id_M7Configuration, create_dissector_handle(dissect_M7Configuration_PDU, proto_x2ap));
  dissector_add_uint("x2ap.extension", id_Correlation_ID, create_dissector_handle(dissect_Correlation_ID_PDU, proto_x2ap));
  dissector_add_uint("x2ap.extension", id_SIPTO_Correlation_ID, create_dissector_handle(dissect_Correlation_ID_PDU, proto_x2ap));
  dissector_add_uint("x2ap.extension", id_CellReportingIndicator, create_dissector_handle(dissect_CellReportingIndicator_PDU, proto_x2ap));
  dissector_add_uint("x2ap.extension", id_BearerType, create_dissector_handle(dissect_BearerType_PDU, proto_x2ap));
  dissector_add_uint("x2ap.extension", id_OffsetOfNbiotChannelNumberToDL_EARFCN, create_dissector_handle(dissect_OffsetOfNbiotChannelNumberToEARFCN_PDU, proto_x2ap));
  dissector_add_uint("x2ap.extension", id_OffsetOfNbiotChannelNumberToUL_EARFCN, create_dissector_handle(dissect_OffsetOfNbiotChannelNumberToEARFCN_PDU, proto_x2ap));
  dissector_add_uint("x2ap.proc.imsg", id_handoverPreparation, create_dissector_handle(dissect_HandoverRequest_PDU, proto_x2ap));
  dissector_add_uint("x2ap.proc.sout", id_handoverPreparation, create_dissector_handle(dissect_HandoverRequestAcknowledge_PDU, proto_x2ap));
  dissector_add_uint("x2ap.proc.uout", id_handoverPreparation, create_dissector_handle(dissect_HandoverPreparationFailure_PDU, proto_x2ap));
  dissector_add_uint("x2ap.proc.imsg", id_snStatusTransfer, create_dissector_handle(dissect_SNStatusTransfer_PDU, proto_x2ap));
  dissector_add_uint("x2ap.proc.imsg", id_uEContextRelease, create_dissector_handle(dissect_UEContextRelease_PDU, proto_x2ap));
  dissector_add_uint("x2ap.proc.imsg", id_handoverCancel, create_dissector_handle(dissect_HandoverCancel_PDU, proto_x2ap));
  dissector_add_uint("x2ap.proc.imsg", id_errorIndication, create_dissector_handle(dissect_ErrorIndication_PDU, proto_x2ap));
  dissector_add_uint("x2ap.proc.imsg", id_reset, create_dissector_handle(dissect_ResetRequest_PDU, proto_x2ap));
  dissector_add_uint("x2ap.proc.sout", id_reset, create_dissector_handle(dissect_ResetResponse_PDU, proto_x2ap));
  dissector_add_uint("x2ap.proc.imsg", id_x2Setup, create_dissector_handle(dissect_X2SetupRequest_PDU, proto_x2ap));
  dissector_add_uint("x2ap.proc.sout", id_x2Setup, create_dissector_handle(dissect_X2SetupResponse_PDU, proto_x2ap));
  dissector_add_uint("x2ap.proc.uout", id_x2Setup, create_dissector_handle(dissect_X2SetupFailure_PDU, proto_x2ap));
  dissector_add_uint("x2ap.proc.imsg", id_loadIndication, create_dissector_handle(dissect_LoadInformation_PDU, proto_x2ap));
  dissector_add_uint("x2ap.proc.imsg", id_eNBConfigurationUpdate, create_dissector_handle(dissect_ENBConfigurationUpdate_PDU, proto_x2ap));
  dissector_add_uint("x2ap.proc.sout", id_eNBConfigurationUpdate, create_dissector_handle(dissect_ENBConfigurationUpdateAcknowledge_PDU, proto_x2ap));
  dissector_add_uint("x2ap.proc.uout", id_eNBConfigurationUpdate, create_dissector_handle(dissect_ENBConfigurationUpdateFailure_PDU, proto_x2ap));
  dissector_add_uint("x2ap.proc.imsg", id_resourceStatusReportingInitiation, create_dissector_handle(dissect_ResourceStatusRequest_PDU, proto_x2ap));
  dissector_add_uint("x2ap.proc.sout", id_resourceStatusReportingInitiation, create_dissector_handle(dissect_ResourceStatusResponse_PDU, proto_x2ap));
  dissector_add_uint("x2ap.proc.uout", id_resourceStatusReportingInitiation, create_dissector_handle(dissect_ResourceStatusFailure_PDU, proto_x2ap));
  dissector_add_uint("x2ap.proc.imsg", id_resourceStatusReporting, create_dissector_handle(dissect_ResourceStatusUpdate_PDU, proto_x2ap));
  dissector_add_uint("x2ap.proc.imsg", id_privateMessage, create_dissector_handle(dissect_PrivateMessage_PDU, proto_x2ap));
  dissector_add_uint("x2ap.proc.imsg", id_handoverReport, create_dissector_handle(dissect_HandoverReport_PDU, proto_x2ap));
  dissector_add_uint("x2ap.proc.imsg", id_rLFIndication, create_dissector_handle(dissect_RLFIndication_PDU, proto_x2ap));
  dissector_add_uint("x2ap.proc.imsg", id_mobilitySettingsChange, create_dissector_handle(dissect_MobilityChangeRequest_PDU, proto_x2ap));
  dissector_add_uint("x2ap.proc.sout", id_mobilitySettingsChange, create_dissector_handle(dissect_MobilityChangeAcknowledge_PDU, proto_x2ap));
  dissector_add_uint("x2ap.proc.uout", id_mobilitySettingsChange, create_dissector_handle(dissect_MobilityChangeFailure_PDU, proto_x2ap));
  dissector_add_uint("x2ap.proc.imsg", id_cellActivation, create_dissector_handle(dissect_CellActivationRequest_PDU, proto_x2ap));
  dissector_add_uint("x2ap.proc.sout", id_cellActivation, create_dissector_handle(dissect_CellActivationResponse_PDU, proto_x2ap));
  dissector_add_uint("x2ap.proc.uout", id_cellActivation, create_dissector_handle(dissect_CellActivationFailure_PDU, proto_x2ap));
  dissector_add_uint("x2ap.proc.imsg", id_x2Release, create_dissector_handle(dissect_X2Release_PDU, proto_x2ap));
  dissector_add_uint("x2ap.proc.imsg", id_x2APMessageTransfer, create_dissector_handle(dissect_X2APMessageTransfer_PDU, proto_x2ap));
  dissector_add_uint("x2ap.proc.imsg", id_x2Removal, create_dissector_handle(dissect_X2RemovalRequest_PDU, proto_x2ap));
  dissector_add_uint("x2ap.proc.sout", id_x2Removal, create_dissector_handle(dissect_X2RemovalResponse_PDU, proto_x2ap));
  dissector_add_uint("x2ap.proc.uout", id_x2Removal, create_dissector_handle(dissect_X2RemovalFailure_PDU, proto_x2ap));
  dissector_add_uint("x2ap.proc.imsg", id_seNBAdditionPreparation, create_dissector_handle(dissect_SeNBAdditionRequest_PDU, proto_x2ap));
  dissector_add_uint("x2ap.proc.sout", id_seNBAdditionPreparation, create_dissector_handle(dissect_SeNBAdditionRequestAcknowledge_PDU, proto_x2ap));
  dissector_add_uint("x2ap.proc.uout", id_seNBAdditionPreparation, create_dissector_handle(dissect_SeNBAdditionRequestReject_PDU, proto_x2ap));
  dissector_add_uint("x2ap.proc.imsg", id_seNBReconfigurationCompletion, create_dissector_handle(dissect_SeNBReconfigurationComplete_PDU, proto_x2ap));
  dissector_add_uint("x2ap.proc.imsg", id_meNBinitiatedSeNBModificationPreparation, create_dissector_handle(dissect_SeNBModificationRequest_PDU, proto_x2ap));
  dissector_add_uint("x2ap.proc.sout", id_meNBinitiatedSeNBModificationPreparation, create_dissector_handle(dissect_SeNBModificationRequestAcknowledge_PDU, proto_x2ap));
  dissector_add_uint("x2ap.proc.uout", id_meNBinitiatedSeNBModificationPreparation, create_dissector_handle(dissect_SeNBModificationRequestReject_PDU, proto_x2ap));
  dissector_add_uint("x2ap.proc.imsg", id_seNBinitiatedSeNBModification, create_dissector_handle(dissect_SeNBModificationRequired_PDU, proto_x2ap));
  dissector_add_uint("x2ap.proc.sout", id_seNBinitiatedSeNBModification, create_dissector_handle(dissect_SeNBModificationConfirm_PDU, proto_x2ap));
  dissector_add_uint("x2ap.proc.uout", id_seNBinitiatedSeNBModification, create_dissector_handle(dissect_SeNBModificationRefuse_PDU, proto_x2ap));
  dissector_add_uint("x2ap.proc.imsg", id_meNBinitiatedSeNBRelease, create_dissector_handle(dissect_SeNBReleaseRequest_PDU, proto_x2ap));
  dissector_add_uint("x2ap.proc.imsg", id_seNBinitiatedSeNBRelease, create_dissector_handle(dissect_SeNBReleaseRequired_PDU, proto_x2ap));
  dissector_add_uint("x2ap.proc.sout", id_seNBinitiatedSeNBRelease, create_dissector_handle(dissect_SeNBReleaseConfirm_PDU, proto_x2ap));
  dissector_add_uint("x2ap.proc.imsg", id_seNBCounterCheck, create_dissector_handle(dissect_SeNBCounterCheckRequest_PDU, proto_x2ap));
  dissector_add_uint("x2ap.proc.imsg", id_retrieveUEContext, create_dissector_handle(dissect_RetrieveUEContextRequest_PDU, proto_x2ap));
  dissector_add_uint("x2ap.proc.sout", id_retrieveUEContext, create_dissector_handle(dissect_RetrieveUEContextResponse_PDU, proto_x2ap));
  dissector_add_uint("x2ap.proc.uout", id_retrieveUEContext, create_dissector_handle(dissect_RetrieveUEContextFailure_PDU, proto_x2ap));


/*--- End of included file: packet-x2ap-dis-tab.c ---*/
#line 573 "./asn1/x2ap/packet-x2ap-template.c"
  } else {
    if (SctpPort != 0) {
      dissector_delete_uint("sctp.port", SctpPort, x2ap_handle);
    }
  }

  SctpPort=gbl_x2apSctpPort;
  if (SctpPort != 0) {
    dissector_add_uint("sctp.port", SctpPort, x2ap_handle);
  }
}


