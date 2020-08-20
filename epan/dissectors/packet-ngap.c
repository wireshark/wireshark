/* Do not modify this file. Changes will be overwritten.                      */
/* Generated automatically by the ASN.1 to Wireshark dissector compiler       */
/* packet-ngap.c                                                              */
/* asn2wrs.py -p ngap -c ./ngap.cnf -s ./packet-ngap-template -D . -O ../.. NGAP-CommonDataTypes.asn NGAP-Constants.asn NGAP-Containers.asn NGAP-IEs.asn NGAP-PDU-Contents.asn NGAP-PDU-Descriptions.asn */

/* Input file: packet-ngap-template.c */

#line 1 "./asn1/ngap/packet-ngap-template.c"
/* packet-ngap.c
 * Routines for NG-RAN NG Application Protocol (NGAP) packet dissection
 * Copyright 2018, Anders Broman <anders.broman@ericsson.com>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * References: 3GPP TS 38.413 v15.6.0 (2019-12)
 */

#include "config.h"
#include <stdio.h>

#include <epan/packet.h>
#include <epan/strutil.h>
#include <epan/asn1.h>
#include <epan/prefs.h>
#include <epan/sctpppids.h>
#include <epan/expert.h>
#include <epan/proto_data.h>
#include <epan/conversation.h>
#include <epan/exceptions.h>
#include <epan/show_exception.h>
#include <wsutil/wsjson.h>

#include "packet-ngap.h"
#include "packet-per.h"
#include "packet-e212.h"
#include "packet-s1ap.h"
#include "packet-ranap.h"
#include "packet-lte-rrc.h"
#include "packet-nr-rrc.h"
#include "packet-gsm_map.h"
#include "packet-cell_broadcast.h"
#include "packet-ntp.h"
#include "packet-gsm_a_common.h"
#include "packet-http.h"
#include "packet-ngap.h"

#define PNAME  "NG Application Protocol"
#define PSNAME "NGAP"
#define PFNAME "ngap"

/* Dissector will use SCTP PPID 18 or SCTP port. IANA assigned port = 36412 */
#define SCTP_PORT_NGAP 38412

void proto_register_ngap(void);
void proto_reg_handoff_ngap(void);

static dissector_handle_t ngap_handle;
static dissector_handle_t ngap_media_type_handle;
static dissector_handle_t nas_5gs_handle;
static dissector_handle_t nr_rrc_ue_radio_paging_info_handle;
static dissector_handle_t nr_rrc_ue_radio_access_cap_info_handle;
static dissector_handle_t lte_rrc_ue_radio_paging_info_handle;
static dissector_handle_t nrppa_handle;

static int proto_json = -1;


/*--- Included file: packet-ngap-val.h ---*/
#line 1 "./asn1/ngap/packet-ngap-val.h"
#define maxPrivateIEs                  65535
#define maxProtocolExtensions          65535
#define maxProtocolIEs                 65535
#define maxnoofAllowedAreas            16
#define maxnoofAllowedS_NSSAIs         8
#define maxnoofBPLMNs                  12
#define maxnoofCellIDforWarning        65535
#define maxnoofCellinAoI               256
#define maxnoofCellinEAI               65535
#define maxnoofCellinTAI               65535
#define maxnoofCellsingNB              16384
#define maxnoofCellsinngeNB            256
#define maxnoofCellsinUEHistoryInfo    16
#define maxnoofCellsUEMovingTrajectory 16
#define maxnoofDRBs                    32
#define maxnoofEmergencyAreaID         65535
#define maxnoofEAIforRestart           256
#define maxnoofEPLMNs                  15
#define maxnoofEPLMNsPlusOne           16
#define maxnoofE_RABs                  256
#define maxnoofErrors                  256
#define maxnoofForbTACs                4096
#define maxnoofMultiConnectivity       4
#define maxnoofMultiConnectivityMinusOne 3
#define maxnoofNGConnectionsToReset    65536
#define maxnoofPDUSessions             256
#define maxnoofPLMNs                   12
#define maxnoofQosFlows                64
#define maxnoofRANNodeinAoI            64
#define maxnoofRecommendedCells        16
#define maxnoofRecommendedRANNodes     16
#define maxnoofAoI                     64
#define maxnoofServedGUAMIs            256
#define maxnoofSliceItems              1024
#define maxnoofTACs                    256
#define maxnoofTAIforInactive          16
#define maxnoofTAIforPaging            16
#define maxnoofTAIforRestart           2048
#define maxnoofTAIforWarning           65535
#define maxnoofTAIinAoI                16
#define maxnoofTimePeriods             2
#define maxnoofTNLAssociations         32
#define maxnoofXnExtTLAs               16
#define maxnoofXnGTP_TLAs              16
#define maxnoofXnTLAs                  2

typedef enum _ProcedureCode_enum {
  id_AMFConfigurationUpdate =   0,
  id_AMFStatusIndication =   1,
  id_CellTrafficTrace =   2,
  id_DeactivateTrace =   3,
  id_DownlinkNASTransport =   4,
  id_DownlinkNonUEAssociatedNRPPaTransport =   5,
  id_DownlinkRANConfigurationTransfer =   6,
  id_DownlinkRANStatusTransfer =   7,
  id_DownlinkUEAssociatedNRPPaTransport =   8,
  id_ErrorIndication =   9,
  id_HandoverCancel =  10,
  id_HandoverNotification =  11,
  id_HandoverPreparation =  12,
  id_HandoverResourceAllocation =  13,
  id_InitialContextSetup =  14,
  id_InitialUEMessage =  15,
  id_LocationReportingControl =  16,
  id_LocationReportingFailureIndication =  17,
  id_LocationReport =  18,
  id_NASNonDeliveryIndication =  19,
  id_NGReset   =  20,
  id_NGSetup   =  21,
  id_OverloadStart =  22,
  id_OverloadStop =  23,
  id_Paging    =  24,
  id_PathSwitchRequest =  25,
  id_PDUSessionResourceModify =  26,
  id_PDUSessionResourceModifyIndication =  27,
  id_PDUSessionResourceRelease =  28,
  id_PDUSessionResourceSetup =  29,
  id_PDUSessionResourceNotify =  30,
  id_PrivateMessage =  31,
  id_PWSCancel =  32,
  id_PWSFailureIndication =  33,
  id_PWSRestartIndication =  34,
  id_RANConfigurationUpdate =  35,
  id_RerouteNASRequest =  36,
  id_RRCInactiveTransitionReport =  37,
  id_TraceFailureIndication =  38,
  id_TraceStart =  39,
  id_UEContextModification =  40,
  id_UEContextRelease =  41,
  id_UEContextReleaseRequest =  42,
  id_UERadioCapabilityCheck =  43,
  id_UERadioCapabilityInfoIndication =  44,
  id_UETNLABindingRelease =  45,
  id_UplinkNASTransport =  46,
  id_UplinkNonUEAssociatedNRPPaTransport =  47,
  id_UplinkRANConfigurationTransfer =  48,
  id_UplinkRANStatusTransfer =  49,
  id_UplinkUEAssociatedNRPPaTransport =  50,
  id_WriteReplaceWarning =  51,
  id_SecondaryRATDataUsageReport =  52
} ProcedureCode_enum;

typedef enum _ProtocolIE_ID_enum {
  id_AllowedNSSAI =   0,
  id_AMFName   =   1,
  id_AMFOverloadResponse =   2,
  id_AMFSetID  =   3,
  id_AMF_TNLAssociationFailedToSetupList =   4,
  id_AMF_TNLAssociationSetupList =   5,
  id_AMF_TNLAssociationToAddList =   6,
  id_AMF_TNLAssociationToRemoveList =   7,
  id_AMF_TNLAssociationToUpdateList =   8,
  id_AMFTrafficLoadReductionIndication =   9,
  id_AMF_UE_NGAP_ID =  10,
  id_AssistanceDataForPaging =  11,
  id_BroadcastCancelledAreaList =  12,
  id_BroadcastCompletedAreaList =  13,
  id_CancelAllWarningMessages =  14,
  id_Cause     =  15,
  id_CellIDListForRestart =  16,
  id_ConcurrentWarningMessageInd =  17,
  id_CoreNetworkAssistanceInformationForInactive =  18,
  id_CriticalityDiagnostics =  19,
  id_DataCodingScheme =  20,
  id_DefaultPagingDRX =  21,
  id_DirectForwardingPathAvailability =  22,
  id_EmergencyAreaIDListForRestart =  23,
  id_EmergencyFallbackIndicator =  24,
  id_EUTRA_CGI =  25,
  id_FiveG_S_TMSI =  26,
  id_GlobalRANNodeID =  27,
  id_GUAMI     =  28,
  id_HandoverType =  29,
  id_IMSVoiceSupportIndicator =  30,
  id_IndexToRFSP =  31,
  id_InfoOnRecommendedCellsAndRANNodesForPaging =  32,
  id_LocationReportingRequestType =  33,
  id_MaskedIMEISV =  34,
  id_MessageIdentifier =  35,
  id_MobilityRestrictionList =  36,
  id_NASC      =  37,
  id_NAS_PDU   =  38,
  id_NASSecurityParametersFromNGRAN =  39,
  id_NewAMF_UE_NGAP_ID =  40,
  id_NewSecurityContextInd =  41,
  id_NGAP_Message =  42,
  id_NGRAN_CGI =  43,
  id_NGRANTraceID =  44,
  id_NR_CGI    =  45,
  id_NRPPa_PDU =  46,
  id_NumberOfBroadcastsRequested =  47,
  id_OldAMF    =  48,
  id_OverloadStartNSSAIList =  49,
  id_PagingDRX =  50,
  id_PagingOrigin =  51,
  id_PagingPriority =  52,
  id_PDUSessionResourceAdmittedList =  53,
  id_PDUSessionResourceFailedToModifyListModRes =  54,
  id_PDUSessionResourceFailedToSetupListCxtRes =  55,
  id_PDUSessionResourceFailedToSetupListHOAck =  56,
  id_PDUSessionResourceFailedToSetupListPSReq =  57,
  id_PDUSessionResourceFailedToSetupListSURes =  58,
  id_PDUSessionResourceHandoverList =  59,
  id_PDUSessionResourceListCxtRelCpl =  60,
  id_PDUSessionResourceListHORqd =  61,
  id_PDUSessionResourceModifyListModCfm =  62,
  id_PDUSessionResourceModifyListModInd =  63,
  id_PDUSessionResourceModifyListModReq =  64,
  id_PDUSessionResourceModifyListModRes =  65,
  id_PDUSessionResourceNotifyList =  66,
  id_PDUSessionResourceReleasedListNot =  67,
  id_PDUSessionResourceReleasedListPSAck =  68,
  id_PDUSessionResourceReleasedListPSFail =  69,
  id_PDUSessionResourceReleasedListRelRes =  70,
  id_PDUSessionResourceSetupListCxtReq =  71,
  id_PDUSessionResourceSetupListCxtRes =  72,
  id_PDUSessionResourceSetupListHOReq =  73,
  id_PDUSessionResourceSetupListSUReq =  74,
  id_PDUSessionResourceSetupListSURes =  75,
  id_PDUSessionResourceToBeSwitchedDLList =  76,
  id_PDUSessionResourceSwitchedList =  77,
  id_PDUSessionResourceToReleaseListHOCmd =  78,
  id_PDUSessionResourceToReleaseListRelCmd =  79,
  id_PLMNSupportList =  80,
  id_PWSFailedCellIDList =  81,
  id_RANNodeName =  82,
  id_RANPagingPriority =  83,
  id_RANStatusTransfer_TransparentContainer =  84,
  id_RAN_UE_NGAP_ID =  85,
  id_RelativeAMFCapacity =  86,
  id_RepetitionPeriod =  87,
  id_ResetType =  88,
  id_RoutingID =  89,
  id_RRCEstablishmentCause =  90,
  id_RRCInactiveTransitionReportRequest =  91,
  id_RRCState  =  92,
  id_SecurityContext =  93,
  id_SecurityKey =  94,
  id_SerialNumber =  95,
  id_ServedGUAMIList =  96,
  id_SliceSupportList =  97,
  id_SONConfigurationTransferDL =  98,
  id_SONConfigurationTransferUL =  99,
  id_SourceAMF_UE_NGAP_ID = 100,
  id_SourceToTarget_TransparentContainer = 101,
  id_SupportedTAList = 102,
  id_TAIListForPaging = 103,
  id_TAIListForRestart = 104,
  id_TargetID  = 105,
  id_TargetToSource_TransparentContainer = 106,
  id_TimeToWait = 107,
  id_TraceActivation = 108,
  id_TraceCollectionEntityIPAddress = 109,
  id_UEAggregateMaximumBitRate = 110,
  id_UE_associatedLogicalNG_connectionList = 111,
  id_UEContextRequest = 112,
  id_Unknown_113 = 113,
  id_UE_NGAP_IDs = 114,
  id_UEPagingIdentity = 115,
  id_UEPresenceInAreaOfInterestList = 116,
  id_UERadioCapability = 117,
  id_UERadioCapabilityForPaging = 118,
  id_UESecurityCapabilities = 119,
  id_UnavailableGUAMIList = 120,
  id_UserLocationInformation = 121,
  id_WarningAreaList = 122,
  id_WarningMessageContents = 123,
  id_WarningSecurityInfo = 124,
  id_WarningType = 125,
  id_AdditionalUL_NGU_UP_TNLInformation = 126,
  id_DataForwardingNotPossible = 127,
  id_DL_NGU_UP_TNLInformation = 128,
  id_NetworkInstance = 129,
  id_PDUSessionAggregateMaximumBitRate = 130,
  id_PDUSessionResourceFailedToModifyListModCfm = 131,
  id_PDUSessionResourceFailedToSetupListCxtFail = 132,
  id_PDUSessionResourceListCxtRelReq = 133,
  id_PDUSessionType = 134,
  id_QosFlowAddOrModifyRequestList = 135,
  id_QosFlowSetupRequestList = 136,
  id_QosFlowToReleaseList = 137,
  id_SecurityIndication = 138,
  id_UL_NGU_UP_TNLInformation = 139,
  id_UL_NGU_UP_TNLModifyList = 140,
  id_WarningAreaCoordinates = 141,
  id_PDUSessionResourceSecondaryRATUsageList = 142,
  id_HandoverFlag = 143,
  id_SecondaryRATUsageInformation = 144,
  id_PDUSessionResourceReleaseResponseTransfer = 145,
  id_RedirectionVoiceFallback = 146,
  id_UERetentionInformation = 147,
  id_S_NSSAI   = 148,
  id_PSCellInformation = 149,
  id_LastEUTRAN_PLMNIdentity = 150,
  id_MaximumIntegrityProtectedDataRate_DL = 151,
  id_AdditionalDLForwardingUPTNLInformation = 152,
  id_AdditionalDLUPTNLInformationForHOList = 153,
  id_AdditionalNGU_UP_TNLInformation = 154,
  id_AdditionalDLQosFlowPerTNLInformation = 155,
  id_SecurityResult = 156,
  id_ENDC_SONConfigurationTransferDL = 157,
  id_ENDC_SONConfigurationTransferUL = 158,
  id_OldAssociatedQosFlowList_ULendmarkerexpected = 159,
  id_CNTypeRestrictionsForEquivalent = 160,
  id_CNTypeRestrictionsForServing = 161,
  id_NewGUAMI  = 162,
  id_ULForwarding = 163,
  id_ULForwardingUP_TNLInformation = 164,
  id_CNAssistedRANTuning = 165,
  id_CommonNetworkInstance = 166,
  id_NGRAN_TNLAssociationToRemoveList = 167,
  id_TNLAssociationTransportLayerAddressNGRAN = 168,
  id_EndpointIPAddressAndPort = 169,
  id_LocationReportingAdditionalInfo = 170,
  id_SourceToTarget_AMFInformationReroute = 171,
  id_AdditionalULForwardingUPTNLInformation = 172,
  id_SCTP_TLAs = 173
} ProtocolIE_ID_enum;

typedef enum _GlobalRANNodeID_enum {
  globalGNB_ID =   0,
  globalNgENB_ID =   1,
  globalN3IWF_ID =   2,
  choice_Extensions =   3
} GlobalRANNodeID_enum;

typedef enum _HandoverType_enum {
  intra5gs     =   0,
  fivegs_to_eps =   1,
  eps_to_5gs   =   2
} HandoverType_enum;

/*--- End of included file: packet-ngap-val.h ---*/
#line 64 "./asn1/ngap/packet-ngap-template.c"

/* Initialize the protocol and registered fields */
static int proto_ngap = -1;
static int hf_ngap_transportLayerAddressIPv4 = -1;
static int hf_ngap_transportLayerAddressIPv6 = -1;
static int hf_ngap_WarningMessageContents_nb_pages = -1;
static int hf_ngap_WarningMessageContents_decoded_page = -1;
static int hf_ngap_NGRANTraceID_TraceID = -1;
static int hf_ngap_NGRANTraceID_TraceRecordingSessionReference = -1;
static int hf_ngap_InterfacesToTrace_NG_C = -1;
static int hf_ngap_InterfacesToTrace_Xn_C = -1;
static int hf_ngap_InterfacesToTrace_Uu = -1;
static int hf_ngap_InterfacesToTrace_F1_C = -1;
static int hf_ngap_InterfacesToTrace_E1 = -1;
static int hf_ngap_InterfacesToTrace_reserved = -1;
static int hf_ngap_RATRestrictionInformation_e_UTRA = -1;
static int hf_ngap_RATRestrictionInformation_nR = -1;
static int hf_ngap_RATRestrictionInformation_reserved = -1;
static int hf_ngap_NrencyptionAlgorithms_nea1 = -1;
static int hf_ngap_NrencyptionAlgorithms_nea2 = -1;
static int hf_ngap_NrencyptionAlgorithms_nea3 = -1;
static int hf_ngap_NrencyptionAlgorithms_reserved = -1;
static int hf_ngap_NrintegrityProtectionAlgorithms_nia1 = -1;
static int hf_ngap_NrintegrityProtectionAlgorithms_nia2 = -1;
static int hf_ngap_NrintegrityProtectionAlgorithms_nia3 = -1;
static int hf_ngap_NrintegrityProtectionAlgorithms_reserved = -1;
static int hf_ngap_EUTRAencryptionAlgorithms_eea1 = -1;
static int hf_ngap_EUTRAencryptionAlgorithms_eea2 = -1;
static int hf_ngap_EUTRAencryptionAlgorithms_eea3 = -1;
static int hf_ngap_EUTRAencryptionAlgorithms_reserved = -1;
static int hf_ngap_EUTRAintegrityProtectionAlgorithms_eia1 = -1;
static int hf_ngap_EUTRAintegrityProtectionAlgorithms_eia2 = -1;
static int hf_ngap_EUTRAintegrityProtectionAlgorithms_eia3 = -1;
static int hf_ngap_EUTRAintegrityProtectionAlgorithms_reserved = -1;

/*--- Included file: packet-ngap-hf.c ---*/
#line 1 "./asn1/ngap/packet-ngap-hf.c"
static int hf_ngap_AdditionalDLUPTNLInformationForHOList_PDU = -1;  /* AdditionalDLUPTNLInformationForHOList */
static int hf_ngap_AllowedNSSAI_PDU = -1;         /* AllowedNSSAI */
static int hf_ngap_AMFName_PDU = -1;              /* AMFName */
static int hf_ngap_AMFSetID_PDU = -1;             /* AMFSetID */
static int hf_ngap_AMF_TNLAssociationSetupList_PDU = -1;  /* AMF_TNLAssociationSetupList */
static int hf_ngap_AMF_TNLAssociationToAddList_PDU = -1;  /* AMF_TNLAssociationToAddList */
static int hf_ngap_AMF_TNLAssociationToRemoveList_PDU = -1;  /* AMF_TNLAssociationToRemoveList */
static int hf_ngap_AMF_TNLAssociationToUpdateList_PDU = -1;  /* AMF_TNLAssociationToUpdateList */
static int hf_ngap_AMF_UE_NGAP_ID_PDU = -1;       /* AMF_UE_NGAP_ID */
static int hf_ngap_AssistanceDataForPaging_PDU = -1;  /* AssistanceDataForPaging */
static int hf_ngap_AssociatedQosFlowList_PDU = -1;  /* AssociatedQosFlowList */
static int hf_ngap_BroadcastCancelledAreaList_PDU = -1;  /* BroadcastCancelledAreaList */
static int hf_ngap_BroadcastCompletedAreaList_PDU = -1;  /* BroadcastCompletedAreaList */
static int hf_ngap_CancelAllWarningMessages_PDU = -1;  /* CancelAllWarningMessages */
static int hf_ngap_Cause_PDU = -1;                /* Cause */
static int hf_ngap_CellIDListForRestart_PDU = -1;  /* CellIDListForRestart */
static int hf_ngap_CNAssistedRANTuning_PDU = -1;  /* CNAssistedRANTuning */
static int hf_ngap_CNTypeRestrictionsForEquivalent_PDU = -1;  /* CNTypeRestrictionsForEquivalent */
static int hf_ngap_CNTypeRestrictionsForServing_PDU = -1;  /* CNTypeRestrictionsForServing */
static int hf_ngap_CommonNetworkInstance_PDU = -1;  /* CommonNetworkInstance */
static int hf_ngap_ConcurrentWarningMessageInd_PDU = -1;  /* ConcurrentWarningMessageInd */
static int hf_ngap_CoreNetworkAssistanceInformationForInactive_PDU = -1;  /* CoreNetworkAssistanceInformationForInactive */
static int hf_ngap_CPTransportLayerInformation_PDU = -1;  /* CPTransportLayerInformation */
static int hf_ngap_CriticalityDiagnostics_PDU = -1;  /* CriticalityDiagnostics */
static int hf_ngap_DataCodingScheme_PDU = -1;     /* DataCodingScheme */
static int hf_ngap_DataForwardingNotPossible_PDU = -1;  /* DataForwardingNotPossible */
static int hf_ngap_DirectForwardingPathAvailability_PDU = -1;  /* DirectForwardingPathAvailability */
static int hf_ngap_EmergencyAreaIDListForRestart_PDU = -1;  /* EmergencyAreaIDListForRestart */
static int hf_ngap_EmergencyFallbackIndicator_PDU = -1;  /* EmergencyFallbackIndicator */
static int hf_ngap_EN_DCSONConfigurationTransfer_PDU = -1;  /* EN_DCSONConfigurationTransfer */
static int hf_ngap_EndpointIPAddressAndPort_PDU = -1;  /* EndpointIPAddressAndPort */
static int hf_ngap_EUTRA_CGI_PDU = -1;            /* EUTRA_CGI */
static int hf_ngap_FiveG_S_TMSI_PDU = -1;         /* FiveG_S_TMSI */
static int hf_ngap_GlobalRANNodeID_PDU = -1;      /* GlobalRANNodeID */
static int hf_ngap_GUAMI_PDU = -1;                /* GUAMI */
static int hf_ngap_HandoverCommandTransfer_PDU = -1;  /* HandoverCommandTransfer */
static int hf_ngap_HandoverFlag_PDU = -1;         /* HandoverFlag */
static int hf_ngap_HandoverPreparationUnsuccessfulTransfer_PDU = -1;  /* HandoverPreparationUnsuccessfulTransfer */
static int hf_ngap_HandoverRequestAcknowledgeTransfer_PDU = -1;  /* HandoverRequestAcknowledgeTransfer */
static int hf_ngap_HandoverRequiredTransfer_PDU = -1;  /* HandoverRequiredTransfer */
static int hf_ngap_HandoverResourceAllocationUnsuccessfulTransfer_PDU = -1;  /* HandoverResourceAllocationUnsuccessfulTransfer */
static int hf_ngap_HandoverType_PDU = -1;         /* HandoverType */
static int hf_ngap_IMSVoiceSupportIndicator_PDU = -1;  /* IMSVoiceSupportIndicator */
static int hf_ngap_IndexToRFSP_PDU = -1;          /* IndexToRFSP */
static int hf_ngap_InfoOnRecommendedCellsAndRANNodesForPaging_PDU = -1;  /* InfoOnRecommendedCellsAndRANNodesForPaging */
static int hf_ngap_ngap_LastVisitedNGRANCellInformation_PDU = -1;  /* LastVisitedNGRANCellInformation */
static int hf_ngap_LocationReportingAdditionalInfo_PDU = -1;  /* LocationReportingAdditionalInfo */
static int hf_ngap_LocationReportingRequestType_PDU = -1;  /* LocationReportingRequestType */
static int hf_ngap_MaskedIMEISV_PDU = -1;         /* MaskedIMEISV */
static int hf_ngap_MessageIdentifier_PDU = -1;    /* MessageIdentifier */
static int hf_ngap_MaximumIntegrityProtectedDataRate_PDU = -1;  /* MaximumIntegrityProtectedDataRate */
static int hf_ngap_ngap_MobilityRestrictionList_PDU = -1;  /* MobilityRestrictionList */
static int hf_ngap_NAS_PDU_PDU = -1;              /* NAS_PDU */
static int hf_ngap_NASSecurityParametersFromNGRAN_PDU = -1;  /* NASSecurityParametersFromNGRAN */
static int hf_ngap_NetworkInstance_PDU = -1;      /* NetworkInstance */
static int hf_ngap_NewSecurityContextInd_PDU = -1;  /* NewSecurityContextInd */
static int hf_ngap_ngap_NGRAN_CGI_PDU = -1;       /* NGRAN_CGI */
static int hf_ngap_NGRAN_TNLAssociationToRemoveList_PDU = -1;  /* NGRAN_TNLAssociationToRemoveList */
static int hf_ngap_NGRANTraceID_PDU = -1;         /* NGRANTraceID */
static int hf_ngap_NR_CGI_PDU = -1;               /* NR_CGI */
static int hf_ngap_NRPPa_PDU_PDU = -1;            /* NRPPa_PDU */
static int hf_ngap_NumberOfBroadcastsRequested_PDU = -1;  /* NumberOfBroadcastsRequested */
static int hf_ngap_OverloadResponse_PDU = -1;     /* OverloadResponse */
static int hf_ngap_OverloadStartNSSAIList_PDU = -1;  /* OverloadStartNSSAIList */
static int hf_ngap_PagingDRX_PDU = -1;            /* PagingDRX */
static int hf_ngap_PagingOrigin_PDU = -1;         /* PagingOrigin */
static int hf_ngap_PagingPriority_PDU = -1;       /* PagingPriority */
static int hf_ngap_PathSwitchRequestAcknowledgeTransfer_PDU = -1;  /* PathSwitchRequestAcknowledgeTransfer */
static int hf_ngap_PathSwitchRequestSetupFailedTransfer_PDU = -1;  /* PathSwitchRequestSetupFailedTransfer */
static int hf_ngap_PathSwitchRequestTransfer_PDU = -1;  /* PathSwitchRequestTransfer */
static int hf_ngap_PathSwitchRequestUnsuccessfulTransfer_PDU = -1;  /* PathSwitchRequestUnsuccessfulTransfer */
static int hf_ngap_PDUSessionAggregateMaximumBitRate_PDU = -1;  /* PDUSessionAggregateMaximumBitRate */
static int hf_ngap_PDUSessionResourceAdmittedList_PDU = -1;  /* PDUSessionResourceAdmittedList */
static int hf_ngap_PDUSessionResourceFailedToModifyListModCfm_PDU = -1;  /* PDUSessionResourceFailedToModifyListModCfm */
static int hf_ngap_PDUSessionResourceFailedToModifyListModRes_PDU = -1;  /* PDUSessionResourceFailedToModifyListModRes */
static int hf_ngap_PDUSessionResourceFailedToSetupListCxtFail_PDU = -1;  /* PDUSessionResourceFailedToSetupListCxtFail */
static int hf_ngap_PDUSessionResourceFailedToSetupListCxtRes_PDU = -1;  /* PDUSessionResourceFailedToSetupListCxtRes */
static int hf_ngap_PDUSessionResourceFailedToSetupListHOAck_PDU = -1;  /* PDUSessionResourceFailedToSetupListHOAck */
static int hf_ngap_PDUSessionResourceFailedToSetupListPSReq_PDU = -1;  /* PDUSessionResourceFailedToSetupListPSReq */
static int hf_ngap_PDUSessionResourceFailedToSetupListSURes_PDU = -1;  /* PDUSessionResourceFailedToSetupListSURes */
static int hf_ngap_PDUSessionResourceHandoverList_PDU = -1;  /* PDUSessionResourceHandoverList */
static int hf_ngap_PDUSessionResourceListCxtRelCpl_PDU = -1;  /* PDUSessionResourceListCxtRelCpl */
static int hf_ngap_PDUSessionResourceReleaseResponseTransfer_OCTET_STRING_PDU = -1;  /* PDUSessionResourceReleaseResponseTransfer_OCTET_STRING */
static int hf_ngap_PDUSessionResourceListCxtRelReq_PDU = -1;  /* PDUSessionResourceListCxtRelReq */
static int hf_ngap_PDUSessionResourceListHORqd_PDU = -1;  /* PDUSessionResourceListHORqd */
static int hf_ngap_PDUSessionResourceModifyConfirmTransfer_PDU = -1;  /* PDUSessionResourceModifyConfirmTransfer */
static int hf_ngap_PDUSessionResourceModifyRequestTransfer_PDU = -1;  /* PDUSessionResourceModifyRequestTransfer */
static int hf_ngap_PDUSessionResourceModifyResponseTransfer_PDU = -1;  /* PDUSessionResourceModifyResponseTransfer */
static int hf_ngap_PDUSessionResourceModifyIndicationTransfer_PDU = -1;  /* PDUSessionResourceModifyIndicationTransfer */
static int hf_ngap_PDUSessionResourceModifyListModCfm_PDU = -1;  /* PDUSessionResourceModifyListModCfm */
static int hf_ngap_PDUSessionResourceModifyListModInd_PDU = -1;  /* PDUSessionResourceModifyListModInd */
static int hf_ngap_PDUSessionResourceModifyListModReq_PDU = -1;  /* PDUSessionResourceModifyListModReq */
static int hf_ngap_PDUSessionResourceModifyListModRes_PDU = -1;  /* PDUSessionResourceModifyListModRes */
static int hf_ngap_PDUSessionResourceModifyUnsuccessfulTransfer_PDU = -1;  /* PDUSessionResourceModifyUnsuccessfulTransfer */
static int hf_ngap_PDUSessionResourceNotifyList_PDU = -1;  /* PDUSessionResourceNotifyList */
static int hf_ngap_PDUSessionResourceNotifyReleasedTransfer_PDU = -1;  /* PDUSessionResourceNotifyReleasedTransfer */
static int hf_ngap_PDUSessionResourceNotifyTransfer_PDU = -1;  /* PDUSessionResourceNotifyTransfer */
static int hf_ngap_PDUSessionResourceReleaseCommandTransfer_PDU = -1;  /* PDUSessionResourceReleaseCommandTransfer */
static int hf_ngap_PDUSessionResourceReleasedListNot_PDU = -1;  /* PDUSessionResourceReleasedListNot */
static int hf_ngap_PDUSessionResourceReleasedListPSAck_PDU = -1;  /* PDUSessionResourceReleasedListPSAck */
static int hf_ngap_PDUSessionResourceReleasedListPSFail_PDU = -1;  /* PDUSessionResourceReleasedListPSFail */
static int hf_ngap_PDUSessionResourceReleasedListRelRes_PDU = -1;  /* PDUSessionResourceReleasedListRelRes */
static int hf_ngap_PDUSessionResourceReleaseResponseTransfer_PDU = -1;  /* PDUSessionResourceReleaseResponseTransfer */
static int hf_ngap_PDUSessionResourceSecondaryRATUsageList_PDU = -1;  /* PDUSessionResourceSecondaryRATUsageList */
static int hf_ngap_PDUSessionResourceSetupListCxtReq_PDU = -1;  /* PDUSessionResourceSetupListCxtReq */
static int hf_ngap_PDUSessionResourceSetupListCxtRes_PDU = -1;  /* PDUSessionResourceSetupListCxtRes */
static int hf_ngap_PDUSessionResourceSetupListHOReq_PDU = -1;  /* PDUSessionResourceSetupListHOReq */
static int hf_ngap_PDUSessionResourceSetupListSUReq_PDU = -1;  /* PDUSessionResourceSetupListSUReq */
static int hf_ngap_PDUSessionResourceSetupListSURes_PDU = -1;  /* PDUSessionResourceSetupListSURes */
static int hf_ngap_PDUSessionResourceSetupRequestTransfer_PDU = -1;  /* PDUSessionResourceSetupRequestTransfer */
static int hf_ngap_PDUSessionResourceSetupResponseTransfer_PDU = -1;  /* PDUSessionResourceSetupResponseTransfer */
static int hf_ngap_PDUSessionResourceSetupUnsuccessfulTransfer_PDU = -1;  /* PDUSessionResourceSetupUnsuccessfulTransfer */
static int hf_ngap_PDUSessionResourceSwitchedList_PDU = -1;  /* PDUSessionResourceSwitchedList */
static int hf_ngap_PDUSessionResourceToBeSwitchedDLList_PDU = -1;  /* PDUSessionResourceToBeSwitchedDLList */
static int hf_ngap_PDUSessionResourceToReleaseListHOCmd_PDU = -1;  /* PDUSessionResourceToReleaseListHOCmd */
static int hf_ngap_PDUSessionResourceToReleaseListRelCmd_PDU = -1;  /* PDUSessionResourceToReleaseListRelCmd */
static int hf_ngap_PDUSessionType_PDU = -1;       /* PDUSessionType */
static int hf_ngap_PLMNIdentity_PDU = -1;         /* PLMNIdentity */
static int hf_ngap_PLMNSupportList_PDU = -1;      /* PLMNSupportList */
static int hf_ngap_PWSFailedCellIDList_PDU = -1;  /* PWSFailedCellIDList */
static int hf_ngap_QosFlowAddOrModifyRequestList_PDU = -1;  /* QosFlowAddOrModifyRequestList */
static int hf_ngap_QosFlowListWithCause_PDU = -1;  /* QosFlowListWithCause */
static int hf_ngap_QosFlowPerTNLInformationList_PDU = -1;  /* QosFlowPerTNLInformationList */
static int hf_ngap_QosFlowSetupRequestList_PDU = -1;  /* QosFlowSetupRequestList */
static int hf_ngap_RANNodeName_PDU = -1;          /* RANNodeName */
static int hf_ngap_RANPagingPriority_PDU = -1;    /* RANPagingPriority */
static int hf_ngap_RANStatusTransfer_TransparentContainer_PDU = -1;  /* RANStatusTransfer_TransparentContainer */
static int hf_ngap_RAN_UE_NGAP_ID_PDU = -1;       /* RAN_UE_NGAP_ID */
static int hf_ngap_RedirectionVoiceFallback_PDU = -1;  /* RedirectionVoiceFallback */
static int hf_ngap_RelativeAMFCapacity_PDU = -1;  /* RelativeAMFCapacity */
static int hf_ngap_RepetitionPeriod_PDU = -1;     /* RepetitionPeriod */
static int hf_ngap_ResetType_PDU = -1;            /* ResetType */
static int hf_ngap_RoutingID_PDU = -1;            /* RoutingID */
static int hf_ngap_RRCEstablishmentCause_PDU = -1;  /* RRCEstablishmentCause */
static int hf_ngap_RRCInactiveTransitionReportRequest_PDU = -1;  /* RRCInactiveTransitionReportRequest */
static int hf_ngap_RRCState_PDU = -1;             /* RRCState */
static int hf_ngap_SCTP_TLAs_PDU = -1;            /* SCTP_TLAs */
static int hf_ngap_SecondaryRATUsageInformation_PDU = -1;  /* SecondaryRATUsageInformation */
static int hf_ngap_SecurityContext_PDU = -1;      /* SecurityContext */
static int hf_ngap_SecurityIndication_PDU = -1;   /* SecurityIndication */
static int hf_ngap_SecurityKey_PDU = -1;          /* SecurityKey */
static int hf_ngap_SecurityResult_PDU = -1;       /* SecurityResult */
static int hf_ngap_SerialNumber_PDU = -1;         /* SerialNumber */
static int hf_ngap_ServedGUAMIList_PDU = -1;      /* ServedGUAMIList */
static int hf_ngap_SliceSupportList_PDU = -1;     /* SliceSupportList */
static int hf_ngap_S_NSSAI_PDU = -1;              /* S_NSSAI */
static int hf_ngap_SONConfigurationTransfer_PDU = -1;  /* SONConfigurationTransfer */
static int hf_ngap_ngap_SourceNGRANNode_ToTargetNGRANNode_TransparentContainer_PDU = -1;  /* SourceNGRANNode_ToTargetNGRANNode_TransparentContainer */
static int hf_ngap_SourceToTarget_TransparentContainer_PDU = -1;  /* SourceToTarget_TransparentContainer */
static int hf_ngap_SourceToTarget_AMFInformationReroute_PDU = -1;  /* SourceToTarget_AMFInformationReroute */
static int hf_ngap_SupportedTAList_PDU = -1;      /* SupportedTAList */
static int hf_ngap_TAIListForPaging_PDU = -1;     /* TAIListForPaging */
static int hf_ngap_TAIListForRestart_PDU = -1;    /* TAIListForRestart */
static int hf_ngap_TargetID_PDU = -1;             /* TargetID */
static int hf_ngap_ngap_TargetNGRANNode_ToSourceNGRANNode_TransparentContainer_PDU = -1;  /* TargetNGRANNode_ToSourceNGRANNode_TransparentContainer */
static int hf_ngap_TargetToSource_TransparentContainer_PDU = -1;  /* TargetToSource_TransparentContainer */
static int hf_ngap_TimeToWait_PDU = -1;           /* TimeToWait */
static int hf_ngap_TNLAssociationList_PDU = -1;   /* TNLAssociationList */
static int hf_ngap_TraceActivation_PDU = -1;      /* TraceActivation */
static int hf_ngap_TrafficLoadReductionIndication_PDU = -1;  /* TrafficLoadReductionIndication */
static int hf_ngap_TransportLayerAddress_PDU = -1;  /* TransportLayerAddress */
static int hf_ngap_UEAggregateMaximumBitRate_PDU = -1;  /* UEAggregateMaximumBitRate */
static int hf_ngap_UE_associatedLogicalNG_connectionList_PDU = -1;  /* UE_associatedLogicalNG_connectionList */
static int hf_ngap_UEContextRequest_PDU = -1;     /* UEContextRequest */
static int hf_ngap_UE_NGAP_IDs_PDU = -1;          /* UE_NGAP_IDs */
static int hf_ngap_UEPagingIdentity_PDU = -1;     /* UEPagingIdentity */
static int hf_ngap_UEPresenceInAreaOfInterestList_PDU = -1;  /* UEPresenceInAreaOfInterestList */
static int hf_ngap_UERadioCapability_PDU = -1;    /* UERadioCapability */
static int hf_ngap_UERadioCapabilityForPaging_PDU = -1;  /* UERadioCapabilityForPaging */
static int hf_ngap_UERetentionInformation_PDU = -1;  /* UERetentionInformation */
static int hf_ngap_UESecurityCapabilities_PDU = -1;  /* UESecurityCapabilities */
static int hf_ngap_UL_NGU_UP_TNLModifyList_PDU = -1;  /* UL_NGU_UP_TNLModifyList */
static int hf_ngap_UnavailableGUAMIList_PDU = -1;  /* UnavailableGUAMIList */
static int hf_ngap_ULForwarding_PDU = -1;         /* ULForwarding */
static int hf_ngap_UPTransportLayerInformation_PDU = -1;  /* UPTransportLayerInformation */
static int hf_ngap_UPTransportLayerInformationList_PDU = -1;  /* UPTransportLayerInformationList */
static int hf_ngap_UPTransportLayerInformationPairList_PDU = -1;  /* UPTransportLayerInformationPairList */
static int hf_ngap_UserLocationInformation_PDU = -1;  /* UserLocationInformation */
static int hf_ngap_WarningAreaCoordinates_PDU = -1;  /* WarningAreaCoordinates */
static int hf_ngap_WarningAreaList_PDU = -1;      /* WarningAreaList */
static int hf_ngap_WarningMessageContents_PDU = -1;  /* WarningMessageContents */
static int hf_ngap_WarningSecurityInfo_PDU = -1;  /* WarningSecurityInfo */
static int hf_ngap_WarningType_PDU = -1;          /* WarningType */
static int hf_ngap_PDUSessionResourceSetupRequest_PDU = -1;  /* PDUSessionResourceSetupRequest */
static int hf_ngap_PDUSessionResourceSetupResponse_PDU = -1;  /* PDUSessionResourceSetupResponse */
static int hf_ngap_PDUSessionResourceReleaseCommand_PDU = -1;  /* PDUSessionResourceReleaseCommand */
static int hf_ngap_PDUSessionResourceReleaseResponse_PDU = -1;  /* PDUSessionResourceReleaseResponse */
static int hf_ngap_PDUSessionResourceModifyRequest_PDU = -1;  /* PDUSessionResourceModifyRequest */
static int hf_ngap_PDUSessionResourceModifyResponse_PDU = -1;  /* PDUSessionResourceModifyResponse */
static int hf_ngap_PDUSessionResourceNotify_PDU = -1;  /* PDUSessionResourceNotify */
static int hf_ngap_PDUSessionResourceModifyIndication_PDU = -1;  /* PDUSessionResourceModifyIndication */
static int hf_ngap_PDUSessionResourceModifyConfirm_PDU = -1;  /* PDUSessionResourceModifyConfirm */
static int hf_ngap_InitialContextSetupRequest_PDU = -1;  /* InitialContextSetupRequest */
static int hf_ngap_InitialContextSetupResponse_PDU = -1;  /* InitialContextSetupResponse */
static int hf_ngap_InitialContextSetupFailure_PDU = -1;  /* InitialContextSetupFailure */
static int hf_ngap_UEContextReleaseRequest_PDU = -1;  /* UEContextReleaseRequest */
static int hf_ngap_UEContextReleaseCommand_PDU = -1;  /* UEContextReleaseCommand */
static int hf_ngap_UEContextReleaseComplete_PDU = -1;  /* UEContextReleaseComplete */
static int hf_ngap_UEContextModificationRequest_PDU = -1;  /* UEContextModificationRequest */
static int hf_ngap_UEContextModificationResponse_PDU = -1;  /* UEContextModificationResponse */
static int hf_ngap_UEContextModificationFailure_PDU = -1;  /* UEContextModificationFailure */
static int hf_ngap_RRCInactiveTransitionReport_PDU = -1;  /* RRCInactiveTransitionReport */
static int hf_ngap_HandoverRequired_PDU = -1;     /* HandoverRequired */
static int hf_ngap_HandoverCommand_PDU = -1;      /* HandoverCommand */
static int hf_ngap_HandoverPreparationFailure_PDU = -1;  /* HandoverPreparationFailure */
static int hf_ngap_HandoverRequest_PDU = -1;      /* HandoverRequest */
static int hf_ngap_HandoverRequestAcknowledge_PDU = -1;  /* HandoverRequestAcknowledge */
static int hf_ngap_HandoverFailure_PDU = -1;      /* HandoverFailure */
static int hf_ngap_HandoverNotify_PDU = -1;       /* HandoverNotify */
static int hf_ngap_PathSwitchRequest_PDU = -1;    /* PathSwitchRequest */
static int hf_ngap_PathSwitchRequestAcknowledge_PDU = -1;  /* PathSwitchRequestAcknowledge */
static int hf_ngap_PathSwitchRequestFailure_PDU = -1;  /* PathSwitchRequestFailure */
static int hf_ngap_HandoverCancel_PDU = -1;       /* HandoverCancel */
static int hf_ngap_HandoverCancelAcknowledge_PDU = -1;  /* HandoverCancelAcknowledge */
static int hf_ngap_UplinkRANStatusTransfer_PDU = -1;  /* UplinkRANStatusTransfer */
static int hf_ngap_DownlinkRANStatusTransfer_PDU = -1;  /* DownlinkRANStatusTransfer */
static int hf_ngap_Paging_PDU = -1;               /* Paging */
static int hf_ngap_InitialUEMessage_PDU = -1;     /* InitialUEMessage */
static int hf_ngap_DownlinkNASTransport_PDU = -1;  /* DownlinkNASTransport */
static int hf_ngap_UplinkNASTransport_PDU = -1;   /* UplinkNASTransport */
static int hf_ngap_NASNonDeliveryIndication_PDU = -1;  /* NASNonDeliveryIndication */
static int hf_ngap_RerouteNASRequest_PDU = -1;    /* RerouteNASRequest */
static int hf_ngap_NGAP_Message_PDU = -1;         /* NGAP_Message */
static int hf_ngap_NGSetupRequest_PDU = -1;       /* NGSetupRequest */
static int hf_ngap_NGSetupResponse_PDU = -1;      /* NGSetupResponse */
static int hf_ngap_NGSetupFailure_PDU = -1;       /* NGSetupFailure */
static int hf_ngap_RANConfigurationUpdate_PDU = -1;  /* RANConfigurationUpdate */
static int hf_ngap_RANConfigurationUpdateAcknowledge_PDU = -1;  /* RANConfigurationUpdateAcknowledge */
static int hf_ngap_RANConfigurationUpdateFailure_PDU = -1;  /* RANConfigurationUpdateFailure */
static int hf_ngap_AMFConfigurationUpdate_PDU = -1;  /* AMFConfigurationUpdate */
static int hf_ngap_AMFConfigurationUpdateAcknowledge_PDU = -1;  /* AMFConfigurationUpdateAcknowledge */
static int hf_ngap_AMFConfigurationUpdateFailure_PDU = -1;  /* AMFConfigurationUpdateFailure */
static int hf_ngap_AMFStatusIndication_PDU = -1;  /* AMFStatusIndication */
static int hf_ngap_NGReset_PDU = -1;              /* NGReset */
static int hf_ngap_NGResetAcknowledge_PDU = -1;   /* NGResetAcknowledge */
static int hf_ngap_ErrorIndication_PDU = -1;      /* ErrorIndication */
static int hf_ngap_OverloadStart_PDU = -1;        /* OverloadStart */
static int hf_ngap_OverloadStop_PDU = -1;         /* OverloadStop */
static int hf_ngap_UplinkRANConfigurationTransfer_PDU = -1;  /* UplinkRANConfigurationTransfer */
static int hf_ngap_DownlinkRANConfigurationTransfer_PDU = -1;  /* DownlinkRANConfigurationTransfer */
static int hf_ngap_WriteReplaceWarningRequest_PDU = -1;  /* WriteReplaceWarningRequest */
static int hf_ngap_WriteReplaceWarningResponse_PDU = -1;  /* WriteReplaceWarningResponse */
static int hf_ngap_PWSCancelRequest_PDU = -1;     /* PWSCancelRequest */
static int hf_ngap_PWSCancelResponse_PDU = -1;    /* PWSCancelResponse */
static int hf_ngap_PWSRestartIndication_PDU = -1;  /* PWSRestartIndication */
static int hf_ngap_PWSFailureIndication_PDU = -1;  /* PWSFailureIndication */
static int hf_ngap_DownlinkUEAssociatedNRPPaTransport_PDU = -1;  /* DownlinkUEAssociatedNRPPaTransport */
static int hf_ngap_UplinkUEAssociatedNRPPaTransport_PDU = -1;  /* UplinkUEAssociatedNRPPaTransport */
static int hf_ngap_DownlinkNonUEAssociatedNRPPaTransport_PDU = -1;  /* DownlinkNonUEAssociatedNRPPaTransport */
static int hf_ngap_UplinkNonUEAssociatedNRPPaTransport_PDU = -1;  /* UplinkNonUEAssociatedNRPPaTransport */
static int hf_ngap_TraceStart_PDU = -1;           /* TraceStart */
static int hf_ngap_TraceFailureIndication_PDU = -1;  /* TraceFailureIndication */
static int hf_ngap_DeactivateTrace_PDU = -1;      /* DeactivateTrace */
static int hf_ngap_CellTrafficTrace_PDU = -1;     /* CellTrafficTrace */
static int hf_ngap_LocationReportingControl_PDU = -1;  /* LocationReportingControl */
static int hf_ngap_LocationReportingFailureIndication_PDU = -1;  /* LocationReportingFailureIndication */
static int hf_ngap_LocationReport_PDU = -1;       /* LocationReport */
static int hf_ngap_UETNLABindingReleaseRequest_PDU = -1;  /* UETNLABindingReleaseRequest */
static int hf_ngap_UERadioCapabilityInfoIndication_PDU = -1;  /* UERadioCapabilityInfoIndication */
static int hf_ngap_UERadioCapabilityCheckRequest_PDU = -1;  /* UERadioCapabilityCheckRequest */
static int hf_ngap_UERadioCapabilityCheckResponse_PDU = -1;  /* UERadioCapabilityCheckResponse */
static int hf_ngap_PrivateMessage_PDU = -1;       /* PrivateMessage */
static int hf_ngap_SecondaryRATDataUsageReport_PDU = -1;  /* SecondaryRATDataUsageReport */
static int hf_ngap_NGAP_PDU_PDU = -1;             /* NGAP_PDU */
static int hf_ngap_PDUSessionResourceModifyIndicationUnsuccessfulTransfer_PDU = -1;  /* PDUSessionResourceModifyIndicationUnsuccessfulTransfer */
static int hf_ngap_SecondaryRATDataUsageReportTransfer_PDU = -1;  /* SecondaryRATDataUsageReportTransfer */
static int hf_ngap_local = -1;                    /* INTEGER_0_65535 */
static int hf_ngap_global = -1;                   /* OBJECT_IDENTIFIER */
static int hf_ngap_ProtocolIE_Container_item = -1;  /* ProtocolIE_Field */
static int hf_ngap_id = -1;                       /* ProtocolIE_ID */
static int hf_ngap_criticality = -1;              /* Criticality */
static int hf_ngap_ie_field_value = -1;           /* T_ie_field_value */
static int hf_ngap_ProtocolExtensionContainer_item = -1;  /* ProtocolExtensionField */
static int hf_ngap_ext_id = -1;                   /* ProtocolExtensionID */
static int hf_ngap_extensionValue = -1;           /* T_extensionValue */
static int hf_ngap_PrivateIE_Container_item = -1;  /* PrivateIE_Field */
static int hf_ngap_private_id = -1;               /* PrivateIE_ID */
static int hf_ngap_private_value = -1;            /* T_private_value */
static int hf_ngap_AdditionalDLUPTNLInformationForHOList_item = -1;  /* AdditionalDLUPTNLInformationForHOItem */
static int hf_ngap_additionalDL_NGU_UP_TNLInformation = -1;  /* UPTransportLayerInformation */
static int hf_ngap_additionalQosFlowSetupResponseList = -1;  /* QosFlowListWithDataForwarding */
static int hf_ngap_additionalDLForwardingUPTNLInformation = -1;  /* UPTransportLayerInformation */
static int hf_ngap_iE_Extensions = -1;            /* ProtocolExtensionContainer */
static int hf_ngap_priorityLevelARP = -1;         /* PriorityLevelARP */
static int hf_ngap_pre_emptionCapability = -1;    /* Pre_emptionCapability */
static int hf_ngap_pre_emptionVulnerability = -1;  /* Pre_emptionVulnerability */
static int hf_ngap_AllowedNSSAI_item = -1;        /* AllowedNSSAI_Item */
static int hf_ngap_s_NSSAI = -1;                  /* S_NSSAI */
static int hf_ngap_AllowedTACs_item = -1;         /* TAC */
static int hf_ngap_globalRANNodeID = -1;          /* GlobalRANNodeID */
static int hf_ngap_tAI = -1;                      /* TAI */
static int hf_ngap_choice_Extensions = -1;        /* ProtocolIE_SingleContainer */
static int hf_ngap_AMF_TNLAssociationSetupList_item = -1;  /* AMF_TNLAssociationSetupItem */
static int hf_ngap_aMF_TNLAssociationAddress = -1;  /* CPTransportLayerInformation */
static int hf_ngap_AMF_TNLAssociationToAddList_item = -1;  /* AMF_TNLAssociationToAddItem */
static int hf_ngap_tNLAssociationUsage = -1;      /* TNLAssociationUsage */
static int hf_ngap_tNLAddressWeightFactor = -1;   /* TNLAddressWeightFactor */
static int hf_ngap_AMF_TNLAssociationToRemoveList_item = -1;  /* AMF_TNLAssociationToRemoveItem */
static int hf_ngap_AMF_TNLAssociationToUpdateList_item = -1;  /* AMF_TNLAssociationToUpdateItem */
static int hf_ngap_areaOfInterestTAIList = -1;    /* AreaOfInterestTAIList */
static int hf_ngap_areaOfInterestCellList = -1;   /* AreaOfInterestCellList */
static int hf_ngap_areaOfInterestRANNodeList = -1;  /* AreaOfInterestRANNodeList */
static int hf_ngap_AreaOfInterestCellList_item = -1;  /* AreaOfInterestCellItem */
static int hf_ngap_nGRAN_CGI = -1;                /* NGRAN_CGI */
static int hf_ngap_AreaOfInterestList_item = -1;  /* AreaOfInterestItem */
static int hf_ngap_areaOfInterest = -1;           /* AreaOfInterest */
static int hf_ngap_locationReportingReferenceID = -1;  /* LocationReportingReferenceID */
static int hf_ngap_AreaOfInterestRANNodeList_item = -1;  /* AreaOfInterestRANNodeItem */
static int hf_ngap_AreaOfInterestTAIList_item = -1;  /* AreaOfInterestTAIItem */
static int hf_ngap_assistanceDataForRecommendedCells = -1;  /* AssistanceDataForRecommendedCells */
static int hf_ngap_pagingAttemptInformation = -1;  /* PagingAttemptInformation */
static int hf_ngap_recommendedCellsForPaging = -1;  /* RecommendedCellsForPaging */
static int hf_ngap_AssociatedQosFlowList_item = -1;  /* AssociatedQosFlowItem */
static int hf_ngap_qosFlowIdentifier = -1;        /* QosFlowIdentifier */
static int hf_ngap_qosFlowMappingIndication = -1;  /* T_qosFlowMappingIndication */
static int hf_ngap_cellIDCancelledEUTRA = -1;     /* CellIDCancelledEUTRA */
static int hf_ngap_tAICancelledEUTRA = -1;        /* TAICancelledEUTRA */
static int hf_ngap_emergencyAreaIDCancelledEUTRA = -1;  /* EmergencyAreaIDCancelledEUTRA */
static int hf_ngap_cellIDCancelledNR = -1;        /* CellIDCancelledNR */
static int hf_ngap_tAICancelledNR = -1;           /* TAICancelledNR */
static int hf_ngap_emergencyAreaIDCancelledNR = -1;  /* EmergencyAreaIDCancelledNR */
static int hf_ngap_cellIDBroadcastEUTRA = -1;     /* CellIDBroadcastEUTRA */
static int hf_ngap_tAIBroadcastEUTRA = -1;        /* TAIBroadcastEUTRA */
static int hf_ngap_emergencyAreaIDBroadcastEUTRA = -1;  /* EmergencyAreaIDBroadcastEUTRA */
static int hf_ngap_cellIDBroadcastNR = -1;        /* CellIDBroadcastNR */
static int hf_ngap_tAIBroadcastNR = -1;           /* TAIBroadcastNR */
static int hf_ngap_emergencyAreaIDBroadcastNR = -1;  /* EmergencyAreaIDBroadcastNR */
static int hf_ngap_BroadcastPLMNList_item = -1;   /* BroadcastPLMNItem */
static int hf_ngap_pLMNIdentity = -1;             /* PLMNIdentity */
static int hf_ngap_tAISliceSupportList = -1;      /* SliceSupportList */
static int hf_ngap_CancelledCellsInEAI_EUTRA_item = -1;  /* CancelledCellsInEAI_EUTRA_Item */
static int hf_ngap_eUTRA_CGI = -1;                /* EUTRA_CGI */
static int hf_ngap_numberOfBroadcasts = -1;       /* NumberOfBroadcasts */
static int hf_ngap_CancelledCellsInEAI_NR_item = -1;  /* CancelledCellsInEAI_NR_Item */
static int hf_ngap_nR_CGI = -1;                   /* NR_CGI */
static int hf_ngap_CancelledCellsInTAI_EUTRA_item = -1;  /* CancelledCellsInTAI_EUTRA_Item */
static int hf_ngap_CancelledCellsInTAI_NR_item = -1;  /* CancelledCellsInTAI_NR_Item */
static int hf_ngap_radioNetwork = -1;             /* CauseRadioNetwork */
static int hf_ngap_transport = -1;                /* CauseTransport */
static int hf_ngap_nas = -1;                      /* CauseNas */
static int hf_ngap_protocol = -1;                 /* CauseProtocol */
static int hf_ngap_misc = -1;                     /* CauseMisc */
static int hf_ngap_CellIDBroadcastEUTRA_item = -1;  /* CellIDBroadcastEUTRA_Item */
static int hf_ngap_CellIDBroadcastNR_item = -1;   /* CellIDBroadcastNR_Item */
static int hf_ngap_CellIDCancelledEUTRA_item = -1;  /* CellIDCancelledEUTRA_Item */
static int hf_ngap_CellIDCancelledNR_item = -1;   /* CellIDCancelledNR_Item */
static int hf_ngap_eUTRA_CGIListforRestart = -1;  /* EUTRA_CGIList */
static int hf_ngap_nR_CGIListforRestart = -1;     /* NR_CGIList */
static int hf_ngap_cellSize = -1;                 /* CellSize */
static int hf_ngap_expectedUEBehaviour = -1;      /* ExpectedUEBehaviour */
static int hf_ngap_CNTypeRestrictionsForEquivalent_item = -1;  /* CNTypeRestrictionsForEquivalentItem */
static int hf_ngap_plmnIdentity = -1;             /* PLMNIdentity */
static int hf_ngap_cn_Type = -1;                  /* T_cn_Type */
static int hf_ngap_CompletedCellsInEAI_EUTRA_item = -1;  /* CompletedCellsInEAI_EUTRA_Item */
static int hf_ngap_CompletedCellsInEAI_NR_item = -1;  /* CompletedCellsInEAI_NR_Item */
static int hf_ngap_CompletedCellsInTAI_EUTRA_item = -1;  /* CompletedCellsInTAI_EUTRA_Item */
static int hf_ngap_CompletedCellsInTAI_NR_item = -1;  /* CompletedCellsInTAI_NR_Item */
static int hf_ngap_uEIdentityIndexValue = -1;     /* UEIdentityIndexValue */
static int hf_ngap_uESpecificDRX = -1;            /* PagingDRX */
static int hf_ngap_periodicRegistrationUpdateTimer = -1;  /* PeriodicRegistrationUpdateTimer */
static int hf_ngap_mICOModeIndication = -1;       /* MICOModeIndication */
static int hf_ngap_tAIListForInactive = -1;       /* TAIListForInactive */
static int hf_ngap_pDCP_SN12 = -1;                /* INTEGER_0_4095 */
static int hf_ngap_hFN_PDCP_SN12 = -1;            /* INTEGER_0_1048575 */
static int hf_ngap_pDCP_SN18 = -1;                /* INTEGER_0_262143 */
static int hf_ngap_hFN_PDCP_SN18 = -1;            /* INTEGER_0_16383 */
static int hf_ngap_endpointIPAddress = -1;        /* TransportLayerAddress */
static int hf_ngap_procedureCode = -1;            /* ProcedureCode */
static int hf_ngap_triggeringMessage = -1;        /* TriggeringMessage */
static int hf_ngap_procedureCriticality = -1;     /* Criticality */
static int hf_ngap_iEsCriticalityDiagnostics = -1;  /* CriticalityDiagnostics_IE_List */
static int hf_ngap_CriticalityDiagnostics_IE_List_item = -1;  /* CriticalityDiagnostics_IE_Item */
static int hf_ngap_iECriticality = -1;            /* Criticality */
static int hf_ngap_iE_ID = -1;                    /* ProtocolIE_ID */
static int hf_ngap_typeOfError = -1;              /* TypeOfError */
static int hf_ngap_DataForwardingResponseDRBList_item = -1;  /* DataForwardingResponseDRBItem */
static int hf_ngap_dRB_ID = -1;                   /* DRB_ID */
static int hf_ngap_dLForwardingUP_TNLInformation = -1;  /* UPTransportLayerInformation */
static int hf_ngap_uLForwardingUP_TNLInformation = -1;  /* UPTransportLayerInformation */
static int hf_ngap_DRBsSubjectToStatusTransferList_item = -1;  /* DRBsSubjectToStatusTransferItem */
static int hf_ngap_dRBStatusUL = -1;              /* DRBStatusUL */
static int hf_ngap_dRBStatusDL = -1;              /* DRBStatusDL */
static int hf_ngap_iE_Extension = -1;             /* ProtocolExtensionContainer */
static int hf_ngap_dRBStatusDL12 = -1;            /* DRBStatusDL12 */
static int hf_ngap_dRBStatusDL18 = -1;            /* DRBStatusDL18 */
static int hf_ngap_dL_COUNTValue = -1;            /* COUNTValueForPDCP_SN12 */
static int hf_ngap_dL_COUNTValue_01 = -1;         /* COUNTValueForPDCP_SN18 */
static int hf_ngap_dRBStatusUL12 = -1;            /* DRBStatusUL12 */
static int hf_ngap_dRBStatusUL18 = -1;            /* DRBStatusUL18 */
static int hf_ngap_uL_COUNTValue = -1;            /* COUNTValueForPDCP_SN12 */
static int hf_ngap_receiveStatusOfUL_PDCP_SDUs = -1;  /* BIT_STRING_SIZE_1_2048 */
static int hf_ngap_uL_COUNTValue_01 = -1;         /* COUNTValueForPDCP_SN18 */
static int hf_ngap_receiveStatusOfUL_PDCP_SDUs_01 = -1;  /* BIT_STRING_SIZE_1_131072 */
static int hf_ngap_DRBsToQosFlowsMappingList_item = -1;  /* DRBsToQosFlowsMappingItem */
static int hf_ngap_associatedQosFlowList = -1;    /* AssociatedQosFlowList */
static int hf_ngap_priorityLevelQos = -1;         /* PriorityLevelQos */
static int hf_ngap_packetDelayBudget = -1;        /* PacketDelayBudget */
static int hf_ngap_packetErrorRate = -1;          /* PacketErrorRate */
static int hf_ngap_fiveQI = -1;                   /* FiveQI */
static int hf_ngap_delayCritical = -1;            /* DelayCritical */
static int hf_ngap_averagingWindow = -1;          /* AveragingWindow */
static int hf_ngap_maximumDataBurstVolume = -1;   /* MaximumDataBurstVolume */
static int hf_ngap_EmergencyAreaIDBroadcastEUTRA_item = -1;  /* EmergencyAreaIDBroadcastEUTRA_Item */
static int hf_ngap_emergencyAreaID = -1;          /* EmergencyAreaID */
static int hf_ngap_completedCellsInEAI_EUTRA = -1;  /* CompletedCellsInEAI_EUTRA */
static int hf_ngap_EmergencyAreaIDBroadcastNR_item = -1;  /* EmergencyAreaIDBroadcastNR_Item */
static int hf_ngap_completedCellsInEAI_NR = -1;   /* CompletedCellsInEAI_NR */
static int hf_ngap_EmergencyAreaIDCancelledEUTRA_item = -1;  /* EmergencyAreaIDCancelledEUTRA_Item */
static int hf_ngap_cancelledCellsInEAI_EUTRA = -1;  /* CancelledCellsInEAI_EUTRA */
static int hf_ngap_EmergencyAreaIDCancelledNR_item = -1;  /* EmergencyAreaIDCancelledNR_Item */
static int hf_ngap_cancelledCellsInEAI_NR = -1;   /* CancelledCellsInEAI_NR */
static int hf_ngap_EmergencyAreaIDList_item = -1;  /* EmergencyAreaID */
static int hf_ngap_EmergencyAreaIDListForRestart_item = -1;  /* EmergencyAreaID */
static int hf_ngap_emergencyFallbackRequestIndicator = -1;  /* EmergencyFallbackRequestIndicator */
static int hf_ngap_emergencyServiceTargetCN = -1;  /* EmergencyServiceTargetCN */
static int hf_ngap_portNumber = -1;               /* PortNumber */
static int hf_ngap_EquivalentPLMNs_item = -1;     /* PLMNIdentity */
static int hf_ngap_ePS_TAC = -1;                  /* EPS_TAC */
static int hf_ngap_E_RABInformationList_item = -1;  /* E_RABInformationItem */
static int hf_ngap_e_RAB_ID = -1;                 /* E_RAB_ID */
static int hf_ngap_dLForwarding = -1;             /* DLForwarding */
static int hf_ngap_eUTRACellIdentity = -1;        /* EUTRACellIdentity */
static int hf_ngap_EUTRA_CGIList_item = -1;       /* EUTRA_CGI */
static int hf_ngap_EUTRA_CGIListForWarning_item = -1;  /* EUTRA_CGI */
static int hf_ngap_expectedActivityPeriod = -1;   /* ExpectedActivityPeriod */
static int hf_ngap_expectedIdlePeriod = -1;       /* ExpectedIdlePeriod */
static int hf_ngap_sourceOfUEActivityBehaviourInformation = -1;  /* SourceOfUEActivityBehaviourInformation */
static int hf_ngap_expectedUEActivityBehaviour = -1;  /* ExpectedUEActivityBehaviour */
static int hf_ngap_expectedHOInterval = -1;       /* ExpectedHOInterval */
static int hf_ngap_expectedUEMobility = -1;       /* ExpectedUEMobility */
static int hf_ngap_expectedUEMovingTrajectory = -1;  /* ExpectedUEMovingTrajectory */
static int hf_ngap_ExpectedUEMovingTrajectory_item = -1;  /* ExpectedUEMovingTrajectoryItem */
static int hf_ngap_timeStayedInCell = -1;         /* INTEGER_0_4095 */
static int hf_ngap_aMFSetID = -1;                 /* AMFSetID */
static int hf_ngap_aMFPointer = -1;               /* AMFPointer */
static int hf_ngap_fiveG_TMSI = -1;               /* FiveG_TMSI */
static int hf_ngap_ForbiddenAreaInformation_item = -1;  /* ForbiddenAreaInformation_Item */
static int hf_ngap_forbiddenTACs = -1;            /* ForbiddenTACs */
static int hf_ngap_ForbiddenTACs_item = -1;       /* TAC */
static int hf_ngap_maximumFlowBitRateDL = -1;     /* BitRate */
static int hf_ngap_maximumFlowBitRateUL = -1;     /* BitRate */
static int hf_ngap_guaranteedFlowBitRateDL = -1;  /* BitRate */
static int hf_ngap_guaranteedFlowBitRateUL = -1;  /* BitRate */
static int hf_ngap_notificationControl = -1;      /* NotificationControl */
static int hf_ngap_maximumPacketLossRateDL = -1;  /* PacketLossRate */
static int hf_ngap_maximumPacketLossRateUL = -1;  /* PacketLossRate */
static int hf_ngap_gNB_ID = -1;                   /* GNB_ID */
static int hf_ngap_n3IWF_ID = -1;                 /* N3IWF_ID */
static int hf_ngap_ngENB_ID = -1;                 /* NgENB_ID */
static int hf_ngap_globalGNB_ID = -1;             /* GlobalGNB_ID */
static int hf_ngap_globalNgENB_ID = -1;           /* GlobalNgENB_ID */
static int hf_ngap_globalN3IWF_ID = -1;           /* GlobalN3IWF_ID */
static int hf_ngap_gNB_ID_01 = -1;                /* BIT_STRING_SIZE_22_32 */
static int hf_ngap_transportLayerAddress = -1;    /* TransportLayerAddress */
static int hf_ngap_gTP_TEID = -1;                 /* GTP_TEID */
static int hf_ngap_aMFRegionID = -1;              /* AMFRegionID */
static int hf_ngap_qosFlowToBeForwardedList = -1;  /* QosFlowToBeForwardedList */
static int hf_ngap_dataForwardingResponseDRBList = -1;  /* DataForwardingResponseDRBList */
static int hf_ngap_cause = -1;                    /* Cause */
static int hf_ngap_dL_NGU_UP_TNLInformation = -1;  /* UPTransportLayerInformation */
static int hf_ngap_securityResult = -1;           /* SecurityResult */
static int hf_ngap_qosFlowSetupResponseList = -1;  /* QosFlowListWithDataForwarding */
static int hf_ngap_qosFlowFailedToSetupList = -1;  /* QosFlowListWithCause */
static int hf_ngap_directForwardingPathAvailability = -1;  /* DirectForwardingPathAvailability */
static int hf_ngap_criticalityDiagnostics = -1;   /* CriticalityDiagnostics */
static int hf_ngap_recommendRANNodesForPaging = -1;  /* RecommendedRANNodesForPaging */
static int hf_ngap_nGRANCell = -1;                /* LastVisitedNGRANCellInformation */
static int hf_ngap_eUTRANCell = -1;               /* LastVisitedEUTRANCellInformation */
static int hf_ngap_uTRANCell = -1;                /* LastVisitedUTRANCellInformation */
static int hf_ngap_gERANCell = -1;                /* LastVisitedGERANCellInformation */
static int hf_ngap_lastVisitedCellInformation = -1;  /* LastVisitedCellInformation */
static int hf_ngap_globalCellID = -1;             /* NGRAN_CGI */
static int hf_ngap_cellType = -1;                 /* CellType */
static int hf_ngap_timeUEStayedInCell = -1;       /* TimeUEStayedInCell */
static int hf_ngap_timeUEStayedInCellEnhancedGranularity = -1;  /* TimeUEStayedInCellEnhancedGranularity */
static int hf_ngap_hOCauseValue = -1;             /* Cause */
static int hf_ngap_eventType = -1;                /* EventType */
static int hf_ngap_reportArea = -1;               /* ReportArea */
static int hf_ngap_areaOfInterestList = -1;       /* AreaOfInterestList */
static int hf_ngap_locationReportingReferenceIDToBeCancelled = -1;  /* LocationReportingReferenceID */
static int hf_ngap_servingPLMN = -1;              /* PLMNIdentity */
static int hf_ngap_equivalentPLMNs = -1;          /* EquivalentPLMNs */
static int hf_ngap_rATRestrictions = -1;          /* RATRestrictions */
static int hf_ngap_forbiddenAreaInformation = -1;  /* ForbiddenAreaInformation */
static int hf_ngap_serviceAreaInformation = -1;   /* ServiceAreaInformation */
static int hf_ngap_n3IWF_ID_01 = -1;              /* BIT_STRING_SIZE_16 */
static int hf_ngap_macroNgENB_ID = -1;            /* BIT_STRING_SIZE_20 */
static int hf_ngap_shortMacroNgENB_ID = -1;       /* BIT_STRING_SIZE_18 */
static int hf_ngap_longMacroNgENB_ID = -1;        /* BIT_STRING_SIZE_21 */
static int hf_ngap_NGRAN_TNLAssociationToRemoveList_item = -1;  /* NGRAN_TNLAssociationToRemoveItem */
static int hf_ngap_tNLAssociationTransportLayerAddress = -1;  /* CPTransportLayerInformation */
static int hf_ngap_tNLAssociationTransportLayerAddressAMF = -1;  /* CPTransportLayerInformation */
static int hf_ngap_NotAllowedTACs_item = -1;      /* TAC */
static int hf_ngap_nRCellIdentity = -1;           /* NRCellIdentity */
static int hf_ngap_NR_CGIList_item = -1;          /* NR_CGI */
static int hf_ngap_NR_CGIListForWarning_item = -1;  /* NR_CGI */
static int hf_ngap_overloadAction = -1;           /* OverloadAction */
static int hf_ngap_OverloadStartNSSAIList_item = -1;  /* OverloadStartNSSAIItem */
static int hf_ngap_sliceOverloadList = -1;        /* SliceOverloadList */
static int hf_ngap_sliceOverloadResponse = -1;    /* OverloadResponse */
static int hf_ngap_sliceTrafficLoadReductionIndication = -1;  /* TrafficLoadReductionIndication */
static int hf_ngap_pERScalar = -1;                /* INTEGER_0_9_ */
static int hf_ngap_pERExponent = -1;              /* INTEGER_0_9_ */
static int hf_ngap_pagingAttemptCount = -1;       /* PagingAttemptCount */
static int hf_ngap_intendedNumberOfPagingAttempts = -1;  /* IntendedNumberOfPagingAttempts */
static int hf_ngap_nextPagingAreaScope = -1;      /* NextPagingAreaScope */
static int hf_ngap_uL_NGU_UP_TNLInformation = -1;  /* UPTransportLayerInformation */
static int hf_ngap_securityIndication = -1;       /* SecurityIndication */
static int hf_ngap_dL_NGU_TNLInformationReused = -1;  /* DL_NGU_TNLInformationReused */
static int hf_ngap_userPlaneSecurityInformation = -1;  /* UserPlaneSecurityInformation */
static int hf_ngap_qosFlowAcceptedList = -1;      /* QosFlowAcceptedList */
static int hf_ngap_pDUSessionAggregateMaximumBitRateDL = -1;  /* BitRate */
static int hf_ngap_pDUSessionAggregateMaximumBitRateUL = -1;  /* BitRate */
static int hf_ngap_PDUSessionResourceAdmittedList_item = -1;  /* PDUSessionResourceAdmittedItem */
static int hf_ngap_pDUSessionID = -1;             /* PDUSessionID */
static int hf_ngap_handoverRequestAcknowledgeTransfer = -1;  /* T_handoverRequestAcknowledgeTransfer */
static int hf_ngap_PDUSessionResourceFailedToModifyListModCfm_item = -1;  /* PDUSessionResourceFailedToModifyItemModCfm */
static int hf_ngap_pDUSessionResourceModifyIndicationUnsuccessfulTransfer = -1;  /* T_pDUSessionResourceModifyIndicationUnsuccessfulTransfer */
static int hf_ngap_PDUSessionResourceFailedToModifyListModRes_item = -1;  /* PDUSessionResourceFailedToModifyItemModRes */
static int hf_ngap_pDUSessionResourceModifyUnsuccessfulTransfer = -1;  /* T_pDUSessionResourceModifyUnsuccessfulTransfer */
static int hf_ngap_PDUSessionResourceFailedToSetupListCxtFail_item = -1;  /* PDUSessionResourceFailedToSetupItemCxtFail */
static int hf_ngap_pDUSessionResourceSetupUnsuccessfulTransfer = -1;  /* T_pDUSessionResourceSetupUnsuccessfulTransfer */
static int hf_ngap_PDUSessionResourceFailedToSetupListCxtRes_item = -1;  /* PDUSessionResourceFailedToSetupItemCxtRes */
static int hf_ngap_pDUSessionResourceSetupUnsuccessfulTransfer_01 = -1;  /* T_pDUSessionResourceSetupUnsuccessfulTransfer_01 */
static int hf_ngap_PDUSessionResourceFailedToSetupListHOAck_item = -1;  /* PDUSessionResourceFailedToSetupItemHOAck */
static int hf_ngap_handoverResourceAllocationUnsuccessfulTransfer = -1;  /* T_handoverResourceAllocationUnsuccessfulTransfer */
static int hf_ngap_PDUSessionResourceFailedToSetupListPSReq_item = -1;  /* PDUSessionResourceFailedToSetupItemPSReq */
static int hf_ngap_pathSwitchRequestSetupFailedTransfer = -1;  /* T_pathSwitchRequestSetupFailedTransfer */
static int hf_ngap_PDUSessionResourceFailedToSetupListSURes_item = -1;  /* PDUSessionResourceFailedToSetupItemSURes */
static int hf_ngap_pDUSessionResourceSetupUnsuccessfulTransfer_02 = -1;  /* T_pDUSessionResourceSetupUnsuccessfulTransfer_02 */
static int hf_ngap_PDUSessionResourceHandoverList_item = -1;  /* PDUSessionResourceHandoverItem */
static int hf_ngap_handoverCommandTransfer = -1;  /* T_handoverCommandTransfer */
static int hf_ngap_PDUSessionResourceInformationList_item = -1;  /* PDUSessionResourceInformationItem */
static int hf_ngap_qosFlowInformationList = -1;   /* QosFlowInformationList */
static int hf_ngap_dRBsToQosFlowsMappingList = -1;  /* DRBsToQosFlowsMappingList */
static int hf_ngap_PDUSessionResourceListCxtRelCpl_item = -1;  /* PDUSessionResourceItemCxtRelCpl */
static int hf_ngap_PDUSessionResourceListCxtRelReq_item = -1;  /* PDUSessionResourceItemCxtRelReq */
static int hf_ngap_PDUSessionResourceListHORqd_item = -1;  /* PDUSessionResourceItemHORqd */
static int hf_ngap_handoverRequiredTransfer = -1;  /* T_handoverRequiredTransfer */
static int hf_ngap_qosFlowModifyConfirmList = -1;  /* QosFlowModifyConfirmList */
static int hf_ngap_uLNGU_UP_TNLInformation = -1;  /* UPTransportLayerInformation */
static int hf_ngap_additionalNG_UUPTNLInformation = -1;  /* UPTransportLayerInformationPairList */
static int hf_ngap_qosFlowFailedToModifyList = -1;  /* QosFlowListWithCause */
static int hf_ngap_protocolIEs = -1;              /* ProtocolIE_Container */
static int hf_ngap_qosFlowAddOrModifyResponseList = -1;  /* QosFlowAddOrModifyResponseList */
static int hf_ngap_additionalDLQosFlowPerTNLInformation = -1;  /* QosFlowPerTNLInformationList */
static int hf_ngap_qosFlowFailedToAddOrModifyList = -1;  /* QosFlowListWithCause */
static int hf_ngap_dLQosFlowPerTNLInformation = -1;  /* QosFlowPerTNLInformation */
static int hf_ngap_PDUSessionResourceModifyListModCfm_item = -1;  /* PDUSessionResourceModifyItemModCfm */
static int hf_ngap_pDUSessionResourceModifyConfirmTransfer = -1;  /* T_pDUSessionResourceModifyConfirmTransfer */
static int hf_ngap_PDUSessionResourceModifyListModInd_item = -1;  /* PDUSessionResourceModifyItemModInd */
static int hf_ngap_pDUSessionResourceModifyIndicationTransfer = -1;  /* T_pDUSessionResourceModifyIndicationTransfer */
static int hf_ngap_PDUSessionResourceModifyListModReq_item = -1;  /* PDUSessionResourceModifyItemModReq */
static int hf_ngap_nAS_PDU = -1;                  /* NAS_PDU */
static int hf_ngap_pDUSessionResourceModifyRequestTransfer = -1;  /* T_pDUSessionResourceModifyRequestTransfer */
static int hf_ngap_PDUSessionResourceModifyListModRes_item = -1;  /* PDUSessionResourceModifyItemModRes */
static int hf_ngap_pDUSessionResourceModifyResponseTransfer = -1;  /* T_pDUSessionResourceModifyResponseTransfer */
static int hf_ngap_PDUSessionResourceNotifyList_item = -1;  /* PDUSessionResourceNotifyItem */
static int hf_ngap_pDUSessionResourceNotifyTransfer = -1;  /* T_pDUSessionResourceNotifyTransfer */
static int hf_ngap_qosFlowNotifyList = -1;        /* QosFlowNotifyList */
static int hf_ngap_qosFlowReleasedList = -1;      /* QosFlowListWithCause */
static int hf_ngap_PDUSessionResourceReleasedListNot_item = -1;  /* PDUSessionResourceReleasedItemNot */
static int hf_ngap_pDUSessionResourceNotifyReleasedTransfer = -1;  /* T_pDUSessionResourceNotifyReleasedTransfer */
static int hf_ngap_PDUSessionResourceReleasedListPSAck_item = -1;  /* PDUSessionResourceReleasedItemPSAck */
static int hf_ngap_pathSwitchRequestUnsuccessfulTransfer = -1;  /* T_pathSwitchRequestUnsuccessfulTransfer */
static int hf_ngap_PDUSessionResourceReleasedListPSFail_item = -1;  /* PDUSessionResourceReleasedItemPSFail */
static int hf_ngap_pathSwitchRequestUnsuccessfulTransfer_01 = -1;  /* T_pathSwitchRequestUnsuccessfulTransfer_01 */
static int hf_ngap_PDUSessionResourceReleasedListRelRes_item = -1;  /* PDUSessionResourceReleasedItemRelRes */
static int hf_ngap_pDUSessionResourceReleaseResponseTransfer = -1;  /* T_pDUSessionResourceReleaseResponseTransfer */
static int hf_ngap_PDUSessionResourceSecondaryRATUsageList_item = -1;  /* PDUSessionResourceSecondaryRATUsageItem */
static int hf_ngap_secondaryRATDataUsageReportTransfer = -1;  /* T_secondaryRATDataUsageReportTransfer */
static int hf_ngap_PDUSessionResourceSetupListCxtReq_item = -1;  /* PDUSessionResourceSetupItemCxtReq */
static int hf_ngap_pDUSessionResourceSetupRequestTransfer = -1;  /* T_pDUSessionResourceSetupRequestTransfer */
static int hf_ngap_PDUSessionResourceSetupListCxtRes_item = -1;  /* PDUSessionResourceSetupItemCxtRes */
static int hf_ngap_pDUSessionResourceSetupResponseTransfer = -1;  /* T_pDUSessionResourceSetupResponseTransfer */
static int hf_ngap_PDUSessionResourceSetupListHOReq_item = -1;  /* PDUSessionResourceSetupItemHOReq */
static int hf_ngap_handoverRequestTransfer = -1;  /* T_handoverRequestTransfer */
static int hf_ngap_PDUSessionResourceSetupListSUReq_item = -1;  /* PDUSessionResourceSetupItemSUReq */
static int hf_ngap_pDUSessionNAS_PDU = -1;        /* NAS_PDU */
static int hf_ngap_pDUSessionResourceSetupRequestTransfer_01 = -1;  /* T_pDUSessionResourceSetupRequestTransfer_01 */
static int hf_ngap_PDUSessionResourceSetupListSURes_item = -1;  /* PDUSessionResourceSetupItemSURes */
static int hf_ngap_pDUSessionResourceSetupResponseTransfer_01 = -1;  /* T_pDUSessionResourceSetupResponseTransfer_01 */
static int hf_ngap_PDUSessionResourceSwitchedList_item = -1;  /* PDUSessionResourceSwitchedItem */
static int hf_ngap_pathSwitchRequestAcknowledgeTransfer = -1;  /* T_pathSwitchRequestAcknowledgeTransfer */
static int hf_ngap_PDUSessionResourceToBeSwitchedDLList_item = -1;  /* PDUSessionResourceToBeSwitchedDLItem */
static int hf_ngap_pathSwitchRequestTransfer = -1;  /* T_pathSwitchRequestTransfer */
static int hf_ngap_PDUSessionResourceToReleaseListHOCmd_item = -1;  /* PDUSessionResourceToReleaseItemHOCmd */
static int hf_ngap_handoverPreparationUnsuccessfulTransfer = -1;  /* T_handoverPreparationUnsuccessfulTransfer */
static int hf_ngap_PDUSessionResourceToReleaseListRelCmd_item = -1;  /* PDUSessionResourceToReleaseItemRelCmd */
static int hf_ngap_pDUSessionResourceReleaseCommandTransfer = -1;  /* T_pDUSessionResourceReleaseCommandTransfer */
static int hf_ngap_rATType = -1;                  /* T_rATType */
static int hf_ngap_pDUSessionTimedReportList = -1;  /* VolumeTimedReportList */
static int hf_ngap_PLMNSupportList_item = -1;     /* PLMNSupportItem */
static int hf_ngap_sliceSupportList = -1;         /* SliceSupportList */
static int hf_ngap_eUTRA_CGI_PWSFailedList = -1;  /* EUTRA_CGIList */
static int hf_ngap_nR_CGI_PWSFailedList = -1;     /* NR_CGIList */
static int hf_ngap_nonDynamic5QI = -1;            /* NonDynamic5QIDescriptor */
static int hf_ngap_dynamic5QI = -1;               /* Dynamic5QIDescriptor */
static int hf_ngap_QosFlowAcceptedList_item = -1;  /* QosFlowAcceptedItem */
static int hf_ngap_QosFlowAddOrModifyRequestList_item = -1;  /* QosFlowAddOrModifyRequestItem */
static int hf_ngap_qosFlowLevelQosParameters = -1;  /* QosFlowLevelQosParameters */
static int hf_ngap_QosFlowAddOrModifyResponseList_item = -1;  /* QosFlowAddOrModifyResponseItem */
static int hf_ngap_QosFlowInformationList_item = -1;  /* QosFlowInformationItem */
static int hf_ngap_qosCharacteristics = -1;       /* QosCharacteristics */
static int hf_ngap_allocationAndRetentionPriority = -1;  /* AllocationAndRetentionPriority */
static int hf_ngap_gBR_QosInformation = -1;       /* GBR_QosInformation */
static int hf_ngap_reflectiveQosAttribute = -1;   /* ReflectiveQosAttribute */
static int hf_ngap_additionalQosFlowInformation = -1;  /* AdditionalQosFlowInformation */
static int hf_ngap_QosFlowListWithCause_item = -1;  /* QosFlowWithCauseItem */
static int hf_ngap_QosFlowModifyConfirmList_item = -1;  /* QosFlowModifyConfirmItem */
static int hf_ngap_QosFlowNotifyList_item = -1;   /* QosFlowNotifyItem */
static int hf_ngap_notificationCause = -1;        /* NotificationCause */
static int hf_ngap_uPTransportLayerInformation = -1;  /* UPTransportLayerInformation */
static int hf_ngap_QosFlowPerTNLInformationList_item = -1;  /* QosFlowPerTNLInformationItem */
static int hf_ngap_qosFlowPerTNLInformation = -1;  /* QosFlowPerTNLInformation */
static int hf_ngap_QosFlowSetupRequestList_item = -1;  /* QosFlowSetupRequestItem */
static int hf_ngap_QosFlowListWithDataForwarding_item = -1;  /* QosFlowItemWithDataForwarding */
static int hf_ngap_dataForwardingAccepted = -1;   /* DataForwardingAccepted */
static int hf_ngap_QosFlowToBeForwardedList_item = -1;  /* QosFlowToBeForwardedItem */
static int hf_ngap_QoSFlowsUsageReportList_item = -1;  /* QoSFlowsUsageReport_Item */
static int hf_ngap_rATType_01 = -1;               /* T_rATType_01 */
static int hf_ngap_qoSFlowsTimedReportList = -1;  /* VolumeTimedReportList */
static int hf_ngap_dRBsSubjectToStatusTransferList = -1;  /* DRBsSubjectToStatusTransferList */
static int hf_ngap_RATRestrictions_item = -1;     /* RATRestrictions_Item */
static int hf_ngap_rATRestrictionInformation = -1;  /* RATRestrictionInformation */
static int hf_ngap_recommendedCellList = -1;      /* RecommendedCellList */
static int hf_ngap_RecommendedCellList_item = -1;  /* RecommendedCellItem */
static int hf_ngap_recommendedRANNodeList = -1;   /* RecommendedRANNodeList */
static int hf_ngap_RecommendedRANNodeList_item = -1;  /* RecommendedRANNodeItem */
static int hf_ngap_aMFPagingTarget = -1;          /* AMFPagingTarget */
static int hf_ngap_nG_Interface = -1;             /* ResetAll */
static int hf_ngap_partOfNG_Interface = -1;       /* UE_associatedLogicalNG_connectionList */
static int hf_ngap_SCTP_TLAs_item = -1;           /* TransportLayerAddress */
static int hf_ngap_pDUSessionUsageReport = -1;    /* PDUSessionUsageReport */
static int hf_ngap_qosFlowsUsageReportList = -1;  /* QoSFlowsUsageReportList */
static int hf_ngap_secondaryRATUsageInformation = -1;  /* SecondaryRATUsageInformation */
static int hf_ngap_nextHopChainingCount = -1;     /* NextHopChainingCount */
static int hf_ngap_nextHopNH = -1;                /* SecurityKey */
static int hf_ngap_integrityProtectionIndication = -1;  /* IntegrityProtectionIndication */
static int hf_ngap_confidentialityProtectionIndication = -1;  /* ConfidentialityProtectionIndication */
static int hf_ngap_maximumIntegrityProtectedDataRate_UL = -1;  /* MaximumIntegrityProtectedDataRate */
static int hf_ngap_integrityProtectionResult = -1;  /* IntegrityProtectionResult */
static int hf_ngap_confidentialityProtectionResult = -1;  /* ConfidentialityProtectionResult */
static int hf_ngap_ServedGUAMIList_item = -1;     /* ServedGUAMIItem */
static int hf_ngap_gUAMI = -1;                    /* GUAMI */
static int hf_ngap_backupAMFName = -1;            /* AMFName */
static int hf_ngap_ServiceAreaInformation_item = -1;  /* ServiceAreaInformation_Item */
static int hf_ngap_allowedTACs = -1;              /* AllowedTACs */
static int hf_ngap_notAllowedTACs = -1;           /* NotAllowedTACs */
static int hf_ngap_SliceOverloadList_item = -1;   /* SliceOverloadItem */
static int hf_ngap_SliceSupportList_item = -1;    /* SliceSupportItem */
static int hf_ngap_sST = -1;                      /* SST */
static int hf_ngap_sD = -1;                       /* SD */
static int hf_ngap_targetRANNodeID = -1;          /* TargetRANNodeID */
static int hf_ngap_sourceRANNodeID = -1;          /* SourceRANNodeID */
static int hf_ngap_sONInformation = -1;           /* SONInformation */
static int hf_ngap_xnTNLConfigurationInfo = -1;   /* XnTNLConfigurationInfo */
static int hf_ngap_sONInformationRequest = -1;    /* SONInformationRequest */
static int hf_ngap_sONInformationReply = -1;      /* SONInformationReply */
static int hf_ngap_rRCContainer = -1;             /* RRCContainer */
static int hf_ngap_pDUSessionResourceInformationList = -1;  /* PDUSessionResourceInformationList */
static int hf_ngap_e_RABInformationList = -1;     /* E_RABInformationList */
static int hf_ngap_targetCell_ID = -1;            /* NGRAN_CGI */
static int hf_ngap_indexToRFSP = -1;              /* IndexToRFSP */
static int hf_ngap_uEHistoryInformation = -1;     /* UEHistoryInformation */
static int hf_ngap_selectedTAI = -1;              /* TAI */
static int hf_ngap_configuredNSSAI = -1;          /* ConfiguredNSSAI */
static int hf_ngap_rejectedNSSAIinPLMN = -1;      /* RejectedNSSAIinPLMN */
static int hf_ngap_rejectedNSSAIinTA = -1;        /* RejectedNSSAIinTA */
static int hf_ngap_SupportedTAList_item = -1;     /* SupportedTAItem */
static int hf_ngap_tAC = -1;                      /* TAC */
static int hf_ngap_broadcastPLMNList = -1;        /* BroadcastPLMNList */
static int hf_ngap_TAIBroadcastEUTRA_item = -1;   /* TAIBroadcastEUTRA_Item */
static int hf_ngap_completedCellsInTAI_EUTRA = -1;  /* CompletedCellsInTAI_EUTRA */
static int hf_ngap_TAIBroadcastNR_item = -1;      /* TAIBroadcastNR_Item */
static int hf_ngap_completedCellsInTAI_NR = -1;   /* CompletedCellsInTAI_NR */
static int hf_ngap_TAICancelledEUTRA_item = -1;   /* TAICancelledEUTRA_Item */
static int hf_ngap_cancelledCellsInTAI_EUTRA = -1;  /* CancelledCellsInTAI_EUTRA */
static int hf_ngap_TAICancelledNR_item = -1;      /* TAICancelledNR_Item */
static int hf_ngap_cancelledCellsInTAI_NR = -1;   /* CancelledCellsInTAI_NR */
static int hf_ngap_TAIListForInactive_item = -1;  /* TAIListForInactiveItem */
static int hf_ngap_TAIListForPaging_item = -1;    /* TAIListForPagingItem */
static int hf_ngap_TAIListForRestart_item = -1;   /* TAI */
static int hf_ngap_TAIListForWarning_item = -1;   /* TAI */
static int hf_ngap_globalENB_ID = -1;             /* GlobalNgENB_ID */
static int hf_ngap_selected_EPS_TAI = -1;         /* EPS_TAI */
static int hf_ngap_targeteNB_ID = -1;             /* TargeteNB_ID */
static int hf_ngap_TNLAssociationList_item = -1;  /* TNLAssociationItem */
static int hf_ngap_tNLAssociationAddress = -1;    /* CPTransportLayerInformation */
static int hf_ngap_nGRANTraceID = -1;             /* NGRANTraceID */
static int hf_ngap_interfacesToTrace = -1;        /* InterfacesToTrace */
static int hf_ngap_traceDepth = -1;               /* TraceDepth */
static int hf_ngap_traceCollectionEntityIPAddress = -1;  /* TransportLayerAddress */
static int hf_ngap_uEAggregateMaximumBitRateDL = -1;  /* BitRate */
static int hf_ngap_uEAggregateMaximumBitRateUL = -1;  /* BitRate */
static int hf_ngap_UE_associatedLogicalNG_connectionList_item = -1;  /* UE_associatedLogicalNG_connectionItem */
static int hf_ngap_aMF_UE_NGAP_ID = -1;           /* AMF_UE_NGAP_ID */
static int hf_ngap_rAN_UE_NGAP_ID = -1;           /* RAN_UE_NGAP_ID */
static int hf_ngap_UEHistoryInformation_item = -1;  /* LastVisitedCellItem */
static int hf_ngap_indexLength10 = -1;            /* BIT_STRING_SIZE_10 */
static int hf_ngap_uE_NGAP_ID_pair = -1;          /* UE_NGAP_ID_pair */
static int hf_ngap_fiveG_S_TMSI = -1;             /* FiveG_S_TMSI */
static int hf_ngap_UEPresenceInAreaOfInterestList_item = -1;  /* UEPresenceInAreaOfInterestItem */
static int hf_ngap_uEPresence = -1;               /* UEPresence */
static int hf_ngap_uERadioCapabilityForPagingOfNR = -1;  /* UERadioCapabilityForPagingOfNR */
static int hf_ngap_uERadioCapabilityForPagingOfEUTRA = -1;  /* UERadioCapabilityForPagingOfEUTRA */
static int hf_ngap_nRencryptionAlgorithms = -1;   /* NRencryptionAlgorithms */
static int hf_ngap_nRintegrityProtectionAlgorithms = -1;  /* NRintegrityProtectionAlgorithms */
static int hf_ngap_eUTRAencryptionAlgorithms = -1;  /* EUTRAencryptionAlgorithms */
static int hf_ngap_eUTRAintegrityProtectionAlgorithms = -1;  /* EUTRAintegrityProtectionAlgorithms */
static int hf_ngap_UL_NGU_UP_TNLModifyList_item = -1;  /* UL_NGU_UP_TNLModifyItem */
static int hf_ngap_UnavailableGUAMIList_item = -1;  /* UnavailableGUAMIItem */
static int hf_ngap_timerApproachForGUAMIRemoval = -1;  /* TimerApproachForGUAMIRemoval */
static int hf_ngap_gTPTunnel = -1;                /* GTPTunnel */
static int hf_ngap_UPTransportLayerInformationList_item = -1;  /* UPTransportLayerInformationItem */
static int hf_ngap_nGU_UP_TNLInformation = -1;    /* UPTransportLayerInformation */
static int hf_ngap_UPTransportLayerInformationPairList_item = -1;  /* UPTransportLayerInformationPairItem */
static int hf_ngap_userLocationInformationEUTRA = -1;  /* UserLocationInformationEUTRA */
static int hf_ngap_userLocationInformationNR = -1;  /* UserLocationInformationNR */
static int hf_ngap_userLocationInformationN3IWF = -1;  /* UserLocationInformationN3IWF */
static int hf_ngap_timeStamp = -1;                /* TimeStamp */
static int hf_ngap_iPAddress = -1;                /* TransportLayerAddress */
static int hf_ngap_VolumeTimedReportList_item = -1;  /* VolumeTimedReport_Item */
static int hf_ngap_startTimeStamp = -1;           /* T_startTimeStamp */
static int hf_ngap_endTimeStamp = -1;             /* T_endTimeStamp */
static int hf_ngap_usageCountUL = -1;             /* INTEGER_0_18446744073709551615 */
static int hf_ngap_usageCountDL = -1;             /* INTEGER_0_18446744073709551615 */
static int hf_ngap_eUTRA_CGIListForWarning = -1;  /* EUTRA_CGIListForWarning */
static int hf_ngap_nR_CGIListForWarning = -1;     /* NR_CGIListForWarning */
static int hf_ngap_tAIListForWarning = -1;        /* TAIListForWarning */
static int hf_ngap_emergencyAreaIDList = -1;      /* EmergencyAreaIDList */
static int hf_ngap_XnExtTLAs_item = -1;           /* XnExtTLA_Item */
static int hf_ngap_iPsecTLA = -1;                 /* TransportLayerAddress */
static int hf_ngap_gTP_TLAs = -1;                 /* XnGTP_TLAs */
static int hf_ngap_XnGTP_TLAs_item = -1;          /* TransportLayerAddress */
static int hf_ngap_XnTLAs_item = -1;              /* TransportLayerAddress */
static int hf_ngap_xnTransportLayerAddresses = -1;  /* XnTLAs */
static int hf_ngap_xnExtendedTransportLayerAddresses = -1;  /* XnExtTLAs */
static int hf_ngap_privateIEs = -1;               /* PrivateIE_Container */
static int hf_ngap_initiatingMessage = -1;        /* InitiatingMessage */
static int hf_ngap_successfulOutcome = -1;        /* SuccessfulOutcome */
static int hf_ngap_unsuccessfulOutcome = -1;      /* UnsuccessfulOutcome */
static int hf_ngap_initiatingMessagevalue = -1;   /* InitiatingMessage_value */
static int hf_ngap_successfulOutcome_value = -1;  /* SuccessfulOutcome_value */
static int hf_ngap_unsuccessfulOutcome_value = -1;  /* UnsuccessfulOutcome_value */

/*--- End of included file: packet-ngap-hf.c ---*/
#line 99 "./asn1/ngap/packet-ngap-template.c"

/* Initialize the subtree pointers */
static gint ett_ngap = -1;
static gint ett_ngap_TransportLayerAddress = -1;
static gint ett_ngap_DataCodingScheme = -1;
static gint ett_ngap_WarningMessageContents = -1;
static gint ett_ngap_PLMNIdentity = -1;
static gint ett_ngap_NGAP_Message = -1;
static gint ett_ngap_NGRANTraceID = -1;
static gint ett_ngap_InterfacesToTrace = -1;
static gint ett_ngap_SourceToTarget_TransparentContainer = -1;
static gint ett_ngap_TargetToSource_TransparentContainer = -1;
static gint ett_ngap_RRCContainer = -1;
static gint ett_ngap_RATRestrictionInformation = -1;
static gint ett_ngap_NrencryptionAlgorithms = -1;
static gint ett_ngap_NrintegrityProtectionAlgorithms = -1;
static gint ett_ngap_EUTRAencryptionAlgorithms = -1;
static gint ett_ngap_EUTRAintegrityProtectionAlgorithms = -1;
static gint ett_ngap_UERadioCapabilityForPagingOfNR = -1;
static gint ett_ngap_UERadioCapabilityForPagingOfEUTRA = -1;
static gint ett_ngap_UERadioCapability = -1;
static gint ett_ngap_LastVisitedEUTRANCellInformation = -1;
static gint ett_ngap_LastVisitedUTRANCellInformation = -1;
static gint ett_ngap_LastVisitedGERANCellInformation = -1;
static gint ett_ngap_NASSecurityParametersFromNGRAN = -1;
static gint ett_ngap_NASC = -1;
static gint ett_ngap_NAS_PDU = -1;
static gint ett_ngap_EN_DCSONConfigurationTransfer = -1;

/*--- Included file: packet-ngap-ett.c ---*/
#line 1 "./asn1/ngap/packet-ngap-ett.c"
static gint ett_ngap_PrivateIE_ID = -1;
static gint ett_ngap_ProtocolIE_Container = -1;
static gint ett_ngap_ProtocolIE_Field = -1;
static gint ett_ngap_ProtocolExtensionContainer = -1;
static gint ett_ngap_ProtocolExtensionField = -1;
static gint ett_ngap_PrivateIE_Container = -1;
static gint ett_ngap_PrivateIE_Field = -1;
static gint ett_ngap_AdditionalDLUPTNLInformationForHOList = -1;
static gint ett_ngap_AdditionalDLUPTNLInformationForHOItem = -1;
static gint ett_ngap_AllocationAndRetentionPriority = -1;
static gint ett_ngap_AllowedNSSAI = -1;
static gint ett_ngap_AllowedNSSAI_Item = -1;
static gint ett_ngap_AllowedTACs = -1;
static gint ett_ngap_AMFPagingTarget = -1;
static gint ett_ngap_AMF_TNLAssociationSetupList = -1;
static gint ett_ngap_AMF_TNLAssociationSetupItem = -1;
static gint ett_ngap_AMF_TNLAssociationToAddList = -1;
static gint ett_ngap_AMF_TNLAssociationToAddItem = -1;
static gint ett_ngap_AMF_TNLAssociationToRemoveList = -1;
static gint ett_ngap_AMF_TNLAssociationToRemoveItem = -1;
static gint ett_ngap_AMF_TNLAssociationToUpdateList = -1;
static gint ett_ngap_AMF_TNLAssociationToUpdateItem = -1;
static gint ett_ngap_AreaOfInterest = -1;
static gint ett_ngap_AreaOfInterestCellList = -1;
static gint ett_ngap_AreaOfInterestCellItem = -1;
static gint ett_ngap_AreaOfInterestList = -1;
static gint ett_ngap_AreaOfInterestItem = -1;
static gint ett_ngap_AreaOfInterestRANNodeList = -1;
static gint ett_ngap_AreaOfInterestRANNodeItem = -1;
static gint ett_ngap_AreaOfInterestTAIList = -1;
static gint ett_ngap_AreaOfInterestTAIItem = -1;
static gint ett_ngap_AssistanceDataForPaging = -1;
static gint ett_ngap_AssistanceDataForRecommendedCells = -1;
static gint ett_ngap_AssociatedQosFlowList = -1;
static gint ett_ngap_AssociatedQosFlowItem = -1;
static gint ett_ngap_BroadcastCancelledAreaList = -1;
static gint ett_ngap_BroadcastCompletedAreaList = -1;
static gint ett_ngap_BroadcastPLMNList = -1;
static gint ett_ngap_BroadcastPLMNItem = -1;
static gint ett_ngap_CancelledCellsInEAI_EUTRA = -1;
static gint ett_ngap_CancelledCellsInEAI_EUTRA_Item = -1;
static gint ett_ngap_CancelledCellsInEAI_NR = -1;
static gint ett_ngap_CancelledCellsInEAI_NR_Item = -1;
static gint ett_ngap_CancelledCellsInTAI_EUTRA = -1;
static gint ett_ngap_CancelledCellsInTAI_EUTRA_Item = -1;
static gint ett_ngap_CancelledCellsInTAI_NR = -1;
static gint ett_ngap_CancelledCellsInTAI_NR_Item = -1;
static gint ett_ngap_Cause = -1;
static gint ett_ngap_CellIDBroadcastEUTRA = -1;
static gint ett_ngap_CellIDBroadcastEUTRA_Item = -1;
static gint ett_ngap_CellIDBroadcastNR = -1;
static gint ett_ngap_CellIDBroadcastNR_Item = -1;
static gint ett_ngap_CellIDCancelledEUTRA = -1;
static gint ett_ngap_CellIDCancelledEUTRA_Item = -1;
static gint ett_ngap_CellIDCancelledNR = -1;
static gint ett_ngap_CellIDCancelledNR_Item = -1;
static gint ett_ngap_CellIDListForRestart = -1;
static gint ett_ngap_CellType = -1;
static gint ett_ngap_CNAssistedRANTuning = -1;
static gint ett_ngap_CNTypeRestrictionsForEquivalent = -1;
static gint ett_ngap_CNTypeRestrictionsForEquivalentItem = -1;
static gint ett_ngap_CompletedCellsInEAI_EUTRA = -1;
static gint ett_ngap_CompletedCellsInEAI_EUTRA_Item = -1;
static gint ett_ngap_CompletedCellsInEAI_NR = -1;
static gint ett_ngap_CompletedCellsInEAI_NR_Item = -1;
static gint ett_ngap_CompletedCellsInTAI_EUTRA = -1;
static gint ett_ngap_CompletedCellsInTAI_EUTRA_Item = -1;
static gint ett_ngap_CompletedCellsInTAI_NR = -1;
static gint ett_ngap_CompletedCellsInTAI_NR_Item = -1;
static gint ett_ngap_CoreNetworkAssistanceInformationForInactive = -1;
static gint ett_ngap_COUNTValueForPDCP_SN12 = -1;
static gint ett_ngap_COUNTValueForPDCP_SN18 = -1;
static gint ett_ngap_CPTransportLayerInformation = -1;
static gint ett_ngap_CriticalityDiagnostics = -1;
static gint ett_ngap_CriticalityDiagnostics_IE_List = -1;
static gint ett_ngap_CriticalityDiagnostics_IE_Item = -1;
static gint ett_ngap_DataForwardingResponseDRBList = -1;
static gint ett_ngap_DataForwardingResponseDRBItem = -1;
static gint ett_ngap_DRBsSubjectToStatusTransferList = -1;
static gint ett_ngap_DRBsSubjectToStatusTransferItem = -1;
static gint ett_ngap_DRBStatusDL = -1;
static gint ett_ngap_DRBStatusDL12 = -1;
static gint ett_ngap_DRBStatusDL18 = -1;
static gint ett_ngap_DRBStatusUL = -1;
static gint ett_ngap_DRBStatusUL12 = -1;
static gint ett_ngap_DRBStatusUL18 = -1;
static gint ett_ngap_DRBsToQosFlowsMappingList = -1;
static gint ett_ngap_DRBsToQosFlowsMappingItem = -1;
static gint ett_ngap_Dynamic5QIDescriptor = -1;
static gint ett_ngap_EmergencyAreaIDBroadcastEUTRA = -1;
static gint ett_ngap_EmergencyAreaIDBroadcastEUTRA_Item = -1;
static gint ett_ngap_EmergencyAreaIDBroadcastNR = -1;
static gint ett_ngap_EmergencyAreaIDBroadcastNR_Item = -1;
static gint ett_ngap_EmergencyAreaIDCancelledEUTRA = -1;
static gint ett_ngap_EmergencyAreaIDCancelledEUTRA_Item = -1;
static gint ett_ngap_EmergencyAreaIDCancelledNR = -1;
static gint ett_ngap_EmergencyAreaIDCancelledNR_Item = -1;
static gint ett_ngap_EmergencyAreaIDList = -1;
static gint ett_ngap_EmergencyAreaIDListForRestart = -1;
static gint ett_ngap_EmergencyFallbackIndicator = -1;
static gint ett_ngap_EndpointIPAddressAndPort = -1;
static gint ett_ngap_EquivalentPLMNs = -1;
static gint ett_ngap_EPS_TAI = -1;
static gint ett_ngap_E_RABInformationList = -1;
static gint ett_ngap_E_RABInformationItem = -1;
static gint ett_ngap_EUTRA_CGI = -1;
static gint ett_ngap_EUTRA_CGIList = -1;
static gint ett_ngap_EUTRA_CGIListForWarning = -1;
static gint ett_ngap_ExpectedUEActivityBehaviour = -1;
static gint ett_ngap_ExpectedUEBehaviour = -1;
static gint ett_ngap_ExpectedUEMovingTrajectory = -1;
static gint ett_ngap_ExpectedUEMovingTrajectoryItem = -1;
static gint ett_ngap_FiveG_S_TMSI = -1;
static gint ett_ngap_ForbiddenAreaInformation = -1;
static gint ett_ngap_ForbiddenAreaInformation_Item = -1;
static gint ett_ngap_ForbiddenTACs = -1;
static gint ett_ngap_GBR_QosInformation = -1;
static gint ett_ngap_GlobalGNB_ID = -1;
static gint ett_ngap_GlobalN3IWF_ID = -1;
static gint ett_ngap_GlobalNgENB_ID = -1;
static gint ett_ngap_GlobalRANNodeID = -1;
static gint ett_ngap_GNB_ID = -1;
static gint ett_ngap_GTPTunnel = -1;
static gint ett_ngap_GUAMI = -1;
static gint ett_ngap_HandoverCommandTransfer = -1;
static gint ett_ngap_HandoverPreparationUnsuccessfulTransfer = -1;
static gint ett_ngap_HandoverRequestAcknowledgeTransfer = -1;
static gint ett_ngap_HandoverRequiredTransfer = -1;
static gint ett_ngap_HandoverResourceAllocationUnsuccessfulTransfer = -1;
static gint ett_ngap_InfoOnRecommendedCellsAndRANNodesForPaging = -1;
static gint ett_ngap_LastVisitedCellInformation = -1;
static gint ett_ngap_LastVisitedCellItem = -1;
static gint ett_ngap_LastVisitedNGRANCellInformation = -1;
static gint ett_ngap_LocationReportingRequestType = -1;
static gint ett_ngap_MobilityRestrictionList = -1;
static gint ett_ngap_N3IWF_ID = -1;
static gint ett_ngap_NgENB_ID = -1;
static gint ett_ngap_NGRAN_CGI = -1;
static gint ett_ngap_NGRAN_TNLAssociationToRemoveList = -1;
static gint ett_ngap_NGRAN_TNLAssociationToRemoveItem = -1;
static gint ett_ngap_NonDynamic5QIDescriptor = -1;
static gint ett_ngap_NotAllowedTACs = -1;
static gint ett_ngap_NR_CGI = -1;
static gint ett_ngap_NR_CGIList = -1;
static gint ett_ngap_NR_CGIListForWarning = -1;
static gint ett_ngap_OverloadResponse = -1;
static gint ett_ngap_OverloadStartNSSAIList = -1;
static gint ett_ngap_OverloadStartNSSAIItem = -1;
static gint ett_ngap_PacketErrorRate = -1;
static gint ett_ngap_PagingAttemptInformation = -1;
static gint ett_ngap_PathSwitchRequestAcknowledgeTransfer = -1;
static gint ett_ngap_PathSwitchRequestSetupFailedTransfer = -1;
static gint ett_ngap_PathSwitchRequestTransfer = -1;
static gint ett_ngap_PathSwitchRequestUnsuccessfulTransfer = -1;
static gint ett_ngap_PDUSessionAggregateMaximumBitRate = -1;
static gint ett_ngap_PDUSessionResourceAdmittedList = -1;
static gint ett_ngap_PDUSessionResourceAdmittedItem = -1;
static gint ett_ngap_PDUSessionResourceFailedToModifyListModCfm = -1;
static gint ett_ngap_PDUSessionResourceFailedToModifyItemModCfm = -1;
static gint ett_ngap_PDUSessionResourceFailedToModifyListModRes = -1;
static gint ett_ngap_PDUSessionResourceFailedToModifyItemModRes = -1;
static gint ett_ngap_PDUSessionResourceFailedToSetupListCxtFail = -1;
static gint ett_ngap_PDUSessionResourceFailedToSetupItemCxtFail = -1;
static gint ett_ngap_PDUSessionResourceFailedToSetupListCxtRes = -1;
static gint ett_ngap_PDUSessionResourceFailedToSetupItemCxtRes = -1;
static gint ett_ngap_PDUSessionResourceFailedToSetupListHOAck = -1;
static gint ett_ngap_PDUSessionResourceFailedToSetupItemHOAck = -1;
static gint ett_ngap_PDUSessionResourceFailedToSetupListPSReq = -1;
static gint ett_ngap_PDUSessionResourceFailedToSetupItemPSReq = -1;
static gint ett_ngap_PDUSessionResourceFailedToSetupListSURes = -1;
static gint ett_ngap_PDUSessionResourceFailedToSetupItemSURes = -1;
static gint ett_ngap_PDUSessionResourceHandoverList = -1;
static gint ett_ngap_PDUSessionResourceHandoverItem = -1;
static gint ett_ngap_PDUSessionResourceInformationList = -1;
static gint ett_ngap_PDUSessionResourceInformationItem = -1;
static gint ett_ngap_PDUSessionResourceListCxtRelCpl = -1;
static gint ett_ngap_PDUSessionResourceItemCxtRelCpl = -1;
static gint ett_ngap_PDUSessionResourceListCxtRelReq = -1;
static gint ett_ngap_PDUSessionResourceItemCxtRelReq = -1;
static gint ett_ngap_PDUSessionResourceListHORqd = -1;
static gint ett_ngap_PDUSessionResourceItemHORqd = -1;
static gint ett_ngap_PDUSessionResourceModifyConfirmTransfer = -1;
static gint ett_ngap_PDUSessionResourceModifyIndicationUnsuccessfulTransfer = -1;
static gint ett_ngap_PDUSessionResourceModifyRequestTransfer = -1;
static gint ett_ngap_PDUSessionResourceModifyResponseTransfer = -1;
static gint ett_ngap_PDUSessionResourceModifyIndicationTransfer = -1;
static gint ett_ngap_PDUSessionResourceModifyListModCfm = -1;
static gint ett_ngap_PDUSessionResourceModifyItemModCfm = -1;
static gint ett_ngap_PDUSessionResourceModifyListModInd = -1;
static gint ett_ngap_PDUSessionResourceModifyItemModInd = -1;
static gint ett_ngap_PDUSessionResourceModifyListModReq = -1;
static gint ett_ngap_PDUSessionResourceModifyItemModReq = -1;
static gint ett_ngap_PDUSessionResourceModifyListModRes = -1;
static gint ett_ngap_PDUSessionResourceModifyItemModRes = -1;
static gint ett_ngap_PDUSessionResourceModifyUnsuccessfulTransfer = -1;
static gint ett_ngap_PDUSessionResourceNotifyList = -1;
static gint ett_ngap_PDUSessionResourceNotifyItem = -1;
static gint ett_ngap_PDUSessionResourceNotifyReleasedTransfer = -1;
static gint ett_ngap_PDUSessionResourceNotifyTransfer = -1;
static gint ett_ngap_PDUSessionResourceReleaseCommandTransfer = -1;
static gint ett_ngap_PDUSessionResourceReleasedListNot = -1;
static gint ett_ngap_PDUSessionResourceReleasedItemNot = -1;
static gint ett_ngap_PDUSessionResourceReleasedListPSAck = -1;
static gint ett_ngap_PDUSessionResourceReleasedItemPSAck = -1;
static gint ett_ngap_PDUSessionResourceReleasedListPSFail = -1;
static gint ett_ngap_PDUSessionResourceReleasedItemPSFail = -1;
static gint ett_ngap_PDUSessionResourceReleasedListRelRes = -1;
static gint ett_ngap_PDUSessionResourceReleasedItemRelRes = -1;
static gint ett_ngap_PDUSessionResourceReleaseResponseTransfer = -1;
static gint ett_ngap_PDUSessionResourceSecondaryRATUsageList = -1;
static gint ett_ngap_PDUSessionResourceSecondaryRATUsageItem = -1;
static gint ett_ngap_PDUSessionResourceSetupListCxtReq = -1;
static gint ett_ngap_PDUSessionResourceSetupItemCxtReq = -1;
static gint ett_ngap_PDUSessionResourceSetupListCxtRes = -1;
static gint ett_ngap_PDUSessionResourceSetupItemCxtRes = -1;
static gint ett_ngap_PDUSessionResourceSetupListHOReq = -1;
static gint ett_ngap_PDUSessionResourceSetupItemHOReq = -1;
static gint ett_ngap_PDUSessionResourceSetupListSUReq = -1;
static gint ett_ngap_PDUSessionResourceSetupItemSUReq = -1;
static gint ett_ngap_PDUSessionResourceSetupListSURes = -1;
static gint ett_ngap_PDUSessionResourceSetupItemSURes = -1;
static gint ett_ngap_PDUSessionResourceSetupRequestTransfer = -1;
static gint ett_ngap_PDUSessionResourceSetupResponseTransfer = -1;
static gint ett_ngap_PDUSessionResourceSetupUnsuccessfulTransfer = -1;
static gint ett_ngap_PDUSessionResourceSwitchedList = -1;
static gint ett_ngap_PDUSessionResourceSwitchedItem = -1;
static gint ett_ngap_PDUSessionResourceToBeSwitchedDLList = -1;
static gint ett_ngap_PDUSessionResourceToBeSwitchedDLItem = -1;
static gint ett_ngap_PDUSessionResourceToReleaseListHOCmd = -1;
static gint ett_ngap_PDUSessionResourceToReleaseItemHOCmd = -1;
static gint ett_ngap_PDUSessionResourceToReleaseListRelCmd = -1;
static gint ett_ngap_PDUSessionResourceToReleaseItemRelCmd = -1;
static gint ett_ngap_PDUSessionUsageReport = -1;
static gint ett_ngap_PLMNSupportList = -1;
static gint ett_ngap_PLMNSupportItem = -1;
static gint ett_ngap_PWSFailedCellIDList = -1;
static gint ett_ngap_QosCharacteristics = -1;
static gint ett_ngap_QosFlowAcceptedList = -1;
static gint ett_ngap_QosFlowAcceptedItem = -1;
static gint ett_ngap_QosFlowAddOrModifyRequestList = -1;
static gint ett_ngap_QosFlowAddOrModifyRequestItem = -1;
static gint ett_ngap_QosFlowAddOrModifyResponseList = -1;
static gint ett_ngap_QosFlowAddOrModifyResponseItem = -1;
static gint ett_ngap_QosFlowInformationList = -1;
static gint ett_ngap_QosFlowInformationItem = -1;
static gint ett_ngap_QosFlowLevelQosParameters = -1;
static gint ett_ngap_QosFlowListWithCause = -1;
static gint ett_ngap_QosFlowWithCauseItem = -1;
static gint ett_ngap_QosFlowModifyConfirmList = -1;
static gint ett_ngap_QosFlowModifyConfirmItem = -1;
static gint ett_ngap_QosFlowNotifyList = -1;
static gint ett_ngap_QosFlowNotifyItem = -1;
static gint ett_ngap_QosFlowPerTNLInformation = -1;
static gint ett_ngap_QosFlowPerTNLInformationList = -1;
static gint ett_ngap_QosFlowPerTNLInformationItem = -1;
static gint ett_ngap_QosFlowSetupRequestList = -1;
static gint ett_ngap_QosFlowSetupRequestItem = -1;
static gint ett_ngap_QosFlowListWithDataForwarding = -1;
static gint ett_ngap_QosFlowItemWithDataForwarding = -1;
static gint ett_ngap_QosFlowToBeForwardedList = -1;
static gint ett_ngap_QosFlowToBeForwardedItem = -1;
static gint ett_ngap_QoSFlowsUsageReportList = -1;
static gint ett_ngap_QoSFlowsUsageReport_Item = -1;
static gint ett_ngap_RANStatusTransfer_TransparentContainer = -1;
static gint ett_ngap_RATRestrictions = -1;
static gint ett_ngap_RATRestrictions_Item = -1;
static gint ett_ngap_RecommendedCellsForPaging = -1;
static gint ett_ngap_RecommendedCellList = -1;
static gint ett_ngap_RecommendedCellItem = -1;
static gint ett_ngap_RecommendedRANNodesForPaging = -1;
static gint ett_ngap_RecommendedRANNodeList = -1;
static gint ett_ngap_RecommendedRANNodeItem = -1;
static gint ett_ngap_ResetType = -1;
static gint ett_ngap_SCTP_TLAs = -1;
static gint ett_ngap_SecondaryRATUsageInformation = -1;
static gint ett_ngap_SecondaryRATDataUsageReportTransfer = -1;
static gint ett_ngap_SecurityContext = -1;
static gint ett_ngap_SecurityIndication = -1;
static gint ett_ngap_SecurityResult = -1;
static gint ett_ngap_ServedGUAMIList = -1;
static gint ett_ngap_ServedGUAMIItem = -1;
static gint ett_ngap_ServiceAreaInformation = -1;
static gint ett_ngap_ServiceAreaInformation_Item = -1;
static gint ett_ngap_SliceOverloadList = -1;
static gint ett_ngap_SliceOverloadItem = -1;
static gint ett_ngap_SliceSupportList = -1;
static gint ett_ngap_SliceSupportItem = -1;
static gint ett_ngap_S_NSSAI = -1;
static gint ett_ngap_SONConfigurationTransfer = -1;
static gint ett_ngap_SONInformation = -1;
static gint ett_ngap_SONInformationReply = -1;
static gint ett_ngap_SourceNGRANNode_ToTargetNGRANNode_TransparentContainer = -1;
static gint ett_ngap_SourceRANNodeID = -1;
static gint ett_ngap_SourceToTarget_AMFInformationReroute = -1;
static gint ett_ngap_SupportedTAList = -1;
static gint ett_ngap_SupportedTAItem = -1;
static gint ett_ngap_TAI = -1;
static gint ett_ngap_TAIBroadcastEUTRA = -1;
static gint ett_ngap_TAIBroadcastEUTRA_Item = -1;
static gint ett_ngap_TAIBroadcastNR = -1;
static gint ett_ngap_TAIBroadcastNR_Item = -1;
static gint ett_ngap_TAICancelledEUTRA = -1;
static gint ett_ngap_TAICancelledEUTRA_Item = -1;
static gint ett_ngap_TAICancelledNR = -1;
static gint ett_ngap_TAICancelledNR_Item = -1;
static gint ett_ngap_TAIListForInactive = -1;
static gint ett_ngap_TAIListForInactiveItem = -1;
static gint ett_ngap_TAIListForPaging = -1;
static gint ett_ngap_TAIListForPagingItem = -1;
static gint ett_ngap_TAIListForRestart = -1;
static gint ett_ngap_TAIListForWarning = -1;
static gint ett_ngap_TargeteNB_ID = -1;
static gint ett_ngap_TargetID = -1;
static gint ett_ngap_TargetNGRANNode_ToSourceNGRANNode_TransparentContainer = -1;
static gint ett_ngap_TargetRANNodeID = -1;
static gint ett_ngap_TNLAssociationList = -1;
static gint ett_ngap_TNLAssociationItem = -1;
static gint ett_ngap_TraceActivation = -1;
static gint ett_ngap_UEAggregateMaximumBitRate = -1;
static gint ett_ngap_UE_associatedLogicalNG_connectionList = -1;
static gint ett_ngap_UE_associatedLogicalNG_connectionItem = -1;
static gint ett_ngap_UEHistoryInformation = -1;
static gint ett_ngap_UEIdentityIndexValue = -1;
static gint ett_ngap_UE_NGAP_IDs = -1;
static gint ett_ngap_UE_NGAP_ID_pair = -1;
static gint ett_ngap_UEPagingIdentity = -1;
static gint ett_ngap_UEPresenceInAreaOfInterestList = -1;
static gint ett_ngap_UEPresenceInAreaOfInterestItem = -1;
static gint ett_ngap_UERadioCapabilityForPaging = -1;
static gint ett_ngap_UESecurityCapabilities = -1;
static gint ett_ngap_UL_NGU_UP_TNLModifyList = -1;
static gint ett_ngap_UL_NGU_UP_TNLModifyItem = -1;
static gint ett_ngap_UnavailableGUAMIList = -1;
static gint ett_ngap_UnavailableGUAMIItem = -1;
static gint ett_ngap_UPTransportLayerInformation = -1;
static gint ett_ngap_UPTransportLayerInformationList = -1;
static gint ett_ngap_UPTransportLayerInformationItem = -1;
static gint ett_ngap_UPTransportLayerInformationPairList = -1;
static gint ett_ngap_UPTransportLayerInformationPairItem = -1;
static gint ett_ngap_UserLocationInformation = -1;
static gint ett_ngap_UserLocationInformationEUTRA = -1;
static gint ett_ngap_UserLocationInformationN3IWF = -1;
static gint ett_ngap_UserLocationInformationNR = -1;
static gint ett_ngap_UserPlaneSecurityInformation = -1;
static gint ett_ngap_VolumeTimedReportList = -1;
static gint ett_ngap_VolumeTimedReport_Item = -1;
static gint ett_ngap_WarningAreaList = -1;
static gint ett_ngap_XnExtTLAs = -1;
static gint ett_ngap_XnExtTLA_Item = -1;
static gint ett_ngap_XnGTP_TLAs = -1;
static gint ett_ngap_XnTLAs = -1;
static gint ett_ngap_XnTNLConfigurationInfo = -1;
static gint ett_ngap_PDUSessionResourceSetupRequest = -1;
static gint ett_ngap_PDUSessionResourceSetupResponse = -1;
static gint ett_ngap_PDUSessionResourceReleaseCommand = -1;
static gint ett_ngap_PDUSessionResourceReleaseResponse = -1;
static gint ett_ngap_PDUSessionResourceModifyRequest = -1;
static gint ett_ngap_PDUSessionResourceModifyResponse = -1;
static gint ett_ngap_PDUSessionResourceNotify = -1;
static gint ett_ngap_PDUSessionResourceModifyIndication = -1;
static gint ett_ngap_PDUSessionResourceModifyConfirm = -1;
static gint ett_ngap_InitialContextSetupRequest = -1;
static gint ett_ngap_InitialContextSetupResponse = -1;
static gint ett_ngap_InitialContextSetupFailure = -1;
static gint ett_ngap_UEContextReleaseRequest = -1;
static gint ett_ngap_UEContextReleaseCommand = -1;
static gint ett_ngap_UEContextReleaseComplete = -1;
static gint ett_ngap_UEContextModificationRequest = -1;
static gint ett_ngap_UEContextModificationResponse = -1;
static gint ett_ngap_UEContextModificationFailure = -1;
static gint ett_ngap_RRCInactiveTransitionReport = -1;
static gint ett_ngap_HandoverRequired = -1;
static gint ett_ngap_HandoverCommand = -1;
static gint ett_ngap_HandoverPreparationFailure = -1;
static gint ett_ngap_HandoverRequest = -1;
static gint ett_ngap_HandoverRequestAcknowledge = -1;
static gint ett_ngap_HandoverFailure = -1;
static gint ett_ngap_HandoverNotify = -1;
static gint ett_ngap_PathSwitchRequest = -1;
static gint ett_ngap_PathSwitchRequestAcknowledge = -1;
static gint ett_ngap_PathSwitchRequestFailure = -1;
static gint ett_ngap_HandoverCancel = -1;
static gint ett_ngap_HandoverCancelAcknowledge = -1;
static gint ett_ngap_UplinkRANStatusTransfer = -1;
static gint ett_ngap_DownlinkRANStatusTransfer = -1;
static gint ett_ngap_Paging = -1;
static gint ett_ngap_InitialUEMessage = -1;
static gint ett_ngap_DownlinkNASTransport = -1;
static gint ett_ngap_UplinkNASTransport = -1;
static gint ett_ngap_NASNonDeliveryIndication = -1;
static gint ett_ngap_RerouteNASRequest = -1;
static gint ett_ngap_NGSetupRequest = -1;
static gint ett_ngap_NGSetupResponse = -1;
static gint ett_ngap_NGSetupFailure = -1;
static gint ett_ngap_RANConfigurationUpdate = -1;
static gint ett_ngap_RANConfigurationUpdateAcknowledge = -1;
static gint ett_ngap_RANConfigurationUpdateFailure = -1;
static gint ett_ngap_AMFConfigurationUpdate = -1;
static gint ett_ngap_AMFConfigurationUpdateAcknowledge = -1;
static gint ett_ngap_AMFConfigurationUpdateFailure = -1;
static gint ett_ngap_AMFStatusIndication = -1;
static gint ett_ngap_NGReset = -1;
static gint ett_ngap_NGResetAcknowledge = -1;
static gint ett_ngap_ErrorIndication = -1;
static gint ett_ngap_OverloadStart = -1;
static gint ett_ngap_OverloadStop = -1;
static gint ett_ngap_UplinkRANConfigurationTransfer = -1;
static gint ett_ngap_DownlinkRANConfigurationTransfer = -1;
static gint ett_ngap_WriteReplaceWarningRequest = -1;
static gint ett_ngap_WriteReplaceWarningResponse = -1;
static gint ett_ngap_PWSCancelRequest = -1;
static gint ett_ngap_PWSCancelResponse = -1;
static gint ett_ngap_PWSRestartIndication = -1;
static gint ett_ngap_PWSFailureIndication = -1;
static gint ett_ngap_DownlinkUEAssociatedNRPPaTransport = -1;
static gint ett_ngap_UplinkUEAssociatedNRPPaTransport = -1;
static gint ett_ngap_DownlinkNonUEAssociatedNRPPaTransport = -1;
static gint ett_ngap_UplinkNonUEAssociatedNRPPaTransport = -1;
static gint ett_ngap_TraceStart = -1;
static gint ett_ngap_TraceFailureIndication = -1;
static gint ett_ngap_DeactivateTrace = -1;
static gint ett_ngap_CellTrafficTrace = -1;
static gint ett_ngap_LocationReportingControl = -1;
static gint ett_ngap_LocationReportingFailureIndication = -1;
static gint ett_ngap_LocationReport = -1;
static gint ett_ngap_UETNLABindingReleaseRequest = -1;
static gint ett_ngap_UERadioCapabilityInfoIndication = -1;
static gint ett_ngap_UERadioCapabilityCheckRequest = -1;
static gint ett_ngap_UERadioCapabilityCheckResponse = -1;
static gint ett_ngap_PrivateMessage = -1;
static gint ett_ngap_SecondaryRATDataUsageReport = -1;
static gint ett_ngap_NGAP_PDU = -1;
static gint ett_ngap_InitiatingMessage = -1;
static gint ett_ngap_SuccessfulOutcome = -1;
static gint ett_ngap_UnsuccessfulOutcome = -1;

/*--- End of included file: packet-ngap-ett.c ---*/
#line 128 "./asn1/ngap/packet-ngap-template.c"

static expert_field ei_ngap_number_pages_le15 = EI_INIT;

enum{
  INITIATING_MESSAGE,
  SUCCESSFUL_OUTCOME,
  UNSUCCESSFUL_OUTCOME
};

typedef struct _ngap_ctx_t {
    guint32 message_type;
    guint32 ProcedureCode;
    guint32 ProtocolIE_ID;
    guint32 ProtocolExtensionID;
} ngap_ctx_t;

struct ngap_conv_info {
  address addr_a;
  guint32 port_a;
  GlobalRANNodeID_enum ranmode_id_a;
  address addr_b;
  guint32 port_b;
  GlobalRANNodeID_enum ranmode_id_b;
};

enum {
  SOURCE_TO_TARGET_TRANSPARENT_CONTAINER = 1,
  TARGET_TO_SOURCE_TRANSPARENT_CONTAINER
};

struct ngap_private_data {
  struct ngap_conv_info *ngap_conv;
  guint32 procedure_code;
  guint32 protocol_ie_id;
  guint32 protocol_extension_id;
  guint32 message_type;
  guint32 handover_type_value;
  guint8 data_coding_scheme;
  guint8 transparent_container_type;
};

enum {
  NGAP_NG_RAN_CONTAINER_AUTOMATIC,
  NGAP_NG_RAN_CONTAINER_GNB,
  NGAP_NG_RAN_CONTAINER_NG_ENB
};

static const enum_val_t ngap_target_ng_ran_container_vals[] = {
  {"automatic", "automatic", NGAP_NG_RAN_CONTAINER_AUTOMATIC},
  {"gnb", "gNB", NGAP_NG_RAN_CONTAINER_GNB},
  {"ng-enb","ng-eNB", NGAP_NG_RAN_CONTAINER_NG_ENB},
  {NULL, NULL, -1}
};

/* Global variables */
static guint gbl_ngapSctpPort = SCTP_PORT_NGAP;
static gboolean ngap_dissect_container = TRUE;
static gint ngap_dissect_target_ng_ran_container_as = NGAP_NG_RAN_CONTAINER_AUTOMATIC;

/* Dissector tables */
static dissector_table_t ngap_ies_dissector_table;
static dissector_table_t ngap_ies_p1_dissector_table;
static dissector_table_t ngap_ies_p2_dissector_table;
static dissector_table_t ngap_extension_dissector_table;
static dissector_table_t ngap_proc_imsg_dissector_table;
static dissector_table_t ngap_proc_sout_dissector_table;
static dissector_table_t ngap_proc_uout_dissector_table;
static dissector_table_t ngap_n2_ie_type_dissector_table;

static int dissect_ProtocolIEFieldValue(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *);
/* Currently not used
static int dissect_ProtocolIEFieldPairFirstValue(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);
static int dissect_ProtocolIEFieldPairSecondValue(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);
*/
static int dissect_ProtocolExtensionFieldExtensionValue(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *);
static int dissect_InitiatingMessageValue(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *);
static int dissect_SuccessfulOutcomeValue(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *);
static int dissect_UnsuccessfulOutcomeValue(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *);

static int dissect_InitialUEMessage_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data);
static int dissect_PDUSessionResourceReleaseResponseTransfer_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_);
static int dissect_HandoverRequestAcknowledgeTransfer_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_);
static int dissect_PDUSessionResourceModifyUnsuccessfulTransfer_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_);
static int dissect_PDUSessionResourceSetupUnsuccessfulTransfer_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_);
static int dissect_HandoverResourceAllocationUnsuccessfulTransfer_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_);
static int dissect_PathSwitchRequestSetupFailedTransfer_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_);
static int dissect_HandoverCommandTransfer_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_);
static int dissect_HandoverRequiredTransfer_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_);
static int dissect_PDUSessionResourceModifyConfirmTransfer_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_);
static int dissect_PDUSessionResourceModifyIndicationTransfer_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_);
static int dissect_PDUSessionResourceModifyRequestTransfer_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_);
static int dissect_PDUSessionResourceModifyResponseTransfer_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_);
static int dissect_PDUSessionResourceNotifyTransfer_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_);
static int dissect_PDUSessionResourceNotifyReleasedTransfer_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_);
static int dissect_PathSwitchRequestUnsuccessfulTransfer_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_);
static int dissect_PDUSessionResourceSetupRequestTransfer_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_);
static int dissect_PDUSessionResourceSetupResponseTransfer_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_);
static int dissect_PathSwitchRequestAcknowledgeTransfer_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_);
static int dissect_PathSwitchRequestTransfer_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_);
static int dissect_HandoverPreparationUnsuccessfulTransfer_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_);
static int dissect_PDUSessionResourceReleaseCommandTransfer_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_);

const value_string ngap_serialNumber_gs_vals[] = {
  { 0, "Display mode iamfdiate, cell wide"},
  { 1, "Display mode normal, PLMN wide"},
  { 2, "Display mode normal, tracking area wide"},
  { 3, "Display mode normal, cell wide"},
  { 0, NULL},
};

const value_string ngap_warningType_vals[] = {
  { 0, "Earthquake"},
  { 1, "Tsunami"},
  { 2, "Earthquake and Tsunami"},
  { 3, "Test"},
  { 4, "Other"},
  { 0, NULL},
};

static void
dissect_ngap_warningMessageContents(tvbuff_t *warning_msg_tvb, proto_tree *tree, packet_info *pinfo, guint8 dcs, int hf_nb_pages, int hf_decoded_page)
{
  guint32 offset;
  guint8 nb_of_pages, length, *str;
  proto_item *ti;
  tvbuff_t *cb_data_page_tvb, *cb_data_tvb;
  int i;

  nb_of_pages = tvb_get_guint8(warning_msg_tvb, 0);
  ti = proto_tree_add_uint(tree, hf_nb_pages, warning_msg_tvb, 0, 1, nb_of_pages);
  if (nb_of_pages > 15) {
    expert_add_info_format(pinfo, ti, &ei_ngap_number_pages_le15,
                           "Number of pages should be <=15 (found %u)", nb_of_pages);
    nb_of_pages = 15;
  }
  for (i = 0, offset = 1; i < nb_of_pages; i++) {
    length = tvb_get_guint8(warning_msg_tvb, offset+82);
    cb_data_page_tvb = tvb_new_subset_length(warning_msg_tvb, offset, length);
    cb_data_tvb = dissect_cbs_data(dcs, cb_data_page_tvb, tree, pinfo, 0);
    if (cb_data_tvb) {
      str = tvb_get_string_enc(wmem_packet_scope(), cb_data_tvb, 0, tvb_reported_length(cb_data_tvb), ENC_UTF_8|ENC_NA);
      proto_tree_add_string_format(tree, hf_decoded_page, warning_msg_tvb, offset, 83,
                                   str, "Decoded Page %u: %s", i+1, str);
    }
    offset += 83;
  }
}

static void
ngap_PacketLossRate_fmt(gchar *s, guint32 v)
{
  g_snprintf(s, ITEM_LABEL_LENGTH, "%.1f%% (%u)", (float)v/10, v);
}

static void
ngap_PacketDelayBudget_fmt(gchar *s, guint32 v)
{
  g_snprintf(s, ITEM_LABEL_LENGTH, "%.1fms (%u)", (float)v/2, v);
}

static void
ngap_TimeUEStayedInCellEnhancedGranularity_fmt(gchar *s, guint32 v)
{
  g_snprintf(s, ITEM_LABEL_LENGTH, "%.1fs", ((float)v)/10);
}

static void
ngap_PeriodicRegistrationUpdateTimer_fmt(gchar *s, guint32 v)
{
  guint32 val = v & 0x1f;

  switch (v>>5) {
    case 0:
      g_snprintf(s, ITEM_LABEL_LENGTH, "%u min (%u)", val * 10, v);
      break;
    case 1:
    default:
      g_snprintf(s, ITEM_LABEL_LENGTH, "%u hr (%u)", val, v);
      break;
    case 2:
      g_snprintf(s, ITEM_LABEL_LENGTH, "%u hr (%u)", val * 10, v);
      break;
    case 3:
      g_snprintf(s, ITEM_LABEL_LENGTH, "%u sec (%u)", val * 2, v);
      break;
    case 4:
      g_snprintf(s, ITEM_LABEL_LENGTH, "%u sec (%u)", val * 30, v);
      break;
    case 5:
      g_snprintf(s, ITEM_LABEL_LENGTH, "%u min (%u)", val, v);
      break;
    case 7:
      g_snprintf(s, ITEM_LABEL_LENGTH, "deactivated (%u)", v);
      break;
  }
}

static struct ngap_private_data*
ngap_get_private_data(packet_info *pinfo)
{
  struct ngap_private_data *ngap_data = (struct ngap_private_data*)p_get_proto_data(pinfo->pool, pinfo, proto_ngap, 0);
  if (!ngap_data) {
    ngap_data = wmem_new0(pinfo->pool, struct ngap_private_data);
    ngap_data->handover_type_value = -1;
    p_add_proto_data(pinfo->pool, pinfo, proto_ngap, 0, ngap_data);
  }
  return ngap_data;
}

static GlobalRANNodeID_enum
ngap_get_ranmode_id(address *addr, guint32 port, packet_info *pinfo)
{
  struct ngap_private_data *ngap_data = ngap_get_private_data(pinfo);
  GlobalRANNodeID_enum ranmode_id = (GlobalRANNodeID_enum)-1;

  if (ngap_data->ngap_conv) {
    if (addresses_equal(addr, &ngap_data->ngap_conv->addr_a) && port == ngap_data->ngap_conv->port_a) {
      ranmode_id = ngap_data->ngap_conv->ranmode_id_a;
    } else if (addresses_equal(addr, &ngap_data->ngap_conv->addr_b) && port == ngap_data->ngap_conv->port_b) {
      ranmode_id = ngap_data->ngap_conv->ranmode_id_b;
    }
  }
  return ranmode_id;
}


/*--- Included file: packet-ngap-fn.c ---*/
#line 1 "./asn1/ngap/packet-ngap-fn.c"
/*--- PDUs declarations ---*/
static int dissect_PDUSessionResourceModifyIndicationUnsuccessfulTransfer_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_);
static int dissect_SecondaryRATDataUsageReportTransfer_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_);


static const value_string ngap_Criticality_vals[] = {
  {   0, "reject" },
  {   1, "ignore" },
  {   2, "notify" },
  { 0, NULL }
};


static int
dissect_ngap_Criticality(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     3, NULL, FALSE, 0, NULL);

  return offset;
}



static int
dissect_ngap_INTEGER_0_65535(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 65535U, NULL, FALSE);

  return offset;
}



static int
dissect_ngap_OBJECT_IDENTIFIER(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_object_identifier(tvb, offset, actx, tree, hf_index, NULL);

  return offset;
}


static const value_string ngap_PrivateIE_ID_vals[] = {
  {   0, "local" },
  {   1, "global" },
  { 0, NULL }
};

static const per_choice_t PrivateIE_ID_choice[] = {
  {   0, &hf_ngap_local          , ASN1_NO_EXTENSIONS     , dissect_ngap_INTEGER_0_65535 },
  {   1, &hf_ngap_global         , ASN1_NO_EXTENSIONS     , dissect_ngap_OBJECT_IDENTIFIER },
  { 0, NULL, 0, NULL }
};

static int
dissect_ngap_PrivateIE_ID(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_ngap_PrivateIE_ID, PrivateIE_ID_choice,
                                 NULL);

  return offset;
}


static const value_string ngap_ProcedureCode_vals[] = {
  { id_AMFConfigurationUpdate, "id-AMFConfigurationUpdate" },
  { id_AMFStatusIndication, "id-AMFStatusIndication" },
  { id_CellTrafficTrace, "id-CellTrafficTrace" },
  { id_DeactivateTrace, "id-DeactivateTrace" },
  { id_DownlinkNASTransport, "id-DownlinkNASTransport" },
  { id_DownlinkNonUEAssociatedNRPPaTransport, "id-DownlinkNonUEAssociatedNRPPaTransport" },
  { id_DownlinkRANConfigurationTransfer, "id-DownlinkRANConfigurationTransfer" },
  { id_DownlinkRANStatusTransfer, "id-DownlinkRANStatusTransfer" },
  { id_DownlinkUEAssociatedNRPPaTransport, "id-DownlinkUEAssociatedNRPPaTransport" },
  { id_ErrorIndication, "id-ErrorIndication" },
  { id_HandoverCancel, "id-HandoverCancel" },
  { id_HandoverNotification, "id-HandoverNotification" },
  { id_HandoverPreparation, "id-HandoverPreparation" },
  { id_HandoverResourceAllocation, "id-HandoverResourceAllocation" },
  { id_InitialContextSetup, "id-InitialContextSetup" },
  { id_InitialUEMessage, "id-InitialUEMessage" },
  { id_LocationReportingControl, "id-LocationReportingControl" },
  { id_LocationReportingFailureIndication, "id-LocationReportingFailureIndication" },
  { id_LocationReport, "id-LocationReport" },
  { id_NASNonDeliveryIndication, "id-NASNonDeliveryIndication" },
  { id_NGReset, "id-NGReset" },
  { id_NGSetup, "id-NGSetup" },
  { id_OverloadStart, "id-OverloadStart" },
  { id_OverloadStop, "id-OverloadStop" },
  { id_Paging, "id-Paging" },
  { id_PathSwitchRequest, "id-PathSwitchRequest" },
  { id_PDUSessionResourceModify, "id-PDUSessionResourceModify" },
  { id_PDUSessionResourceModifyIndication, "id-PDUSessionResourceModifyIndication" },
  { id_PDUSessionResourceRelease, "id-PDUSessionResourceRelease" },
  { id_PDUSessionResourceSetup, "id-PDUSessionResourceSetup" },
  { id_PDUSessionResourceNotify, "id-PDUSessionResourceNotify" },
  { id_PrivateMessage, "id-PrivateMessage" },
  { id_PWSCancel, "id-PWSCancel" },
  { id_PWSFailureIndication, "id-PWSFailureIndication" },
  { id_PWSRestartIndication, "id-PWSRestartIndication" },
  { id_RANConfigurationUpdate, "id-RANConfigurationUpdate" },
  { id_RerouteNASRequest, "id-RerouteNASRequest" },
  { id_RRCInactiveTransitionReport, "id-RRCInactiveTransitionReport" },
  { id_TraceFailureIndication, "id-TraceFailureIndication" },
  { id_TraceStart, "id-TraceStart" },
  { id_UEContextModification, "id-UEContextModification" },
  { id_UEContextRelease, "id-UEContextRelease" },
  { id_UEContextReleaseRequest, "id-UEContextReleaseRequest" },
  { id_UERadioCapabilityCheck, "id-UERadioCapabilityCheck" },
  { id_UERadioCapabilityInfoIndication, "id-UERadioCapabilityInfoIndication" },
  { id_UETNLABindingRelease, "id-UETNLABindingRelease" },
  { id_UplinkNASTransport, "id-UplinkNASTransport" },
  { id_UplinkNonUEAssociatedNRPPaTransport, "id-UplinkNonUEAssociatedNRPPaTransport" },
  { id_UplinkRANConfigurationTransfer, "id-UplinkRANConfigurationTransfer" },
  { id_UplinkRANStatusTransfer, "id-UplinkRANStatusTransfer" },
  { id_UplinkUEAssociatedNRPPaTransport, "id-UplinkUEAssociatedNRPPaTransport" },
  { id_WriteReplaceWarning, "id-WriteReplaceWarning" },
  { id_SecondaryRATDataUsageReport, "id-SecondaryRATDataUsageReport" },
  { 0, NULL }
};

static value_string_ext ngap_ProcedureCode_vals_ext = VALUE_STRING_EXT_INIT(ngap_ProcedureCode_vals);


static int
dissect_ngap_ProcedureCode(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 107 "./asn1/ngap/ngap.cnf"
  struct ngap_private_data *ngap_data = ngap_get_private_data(actx->pinfo);
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 255U, &ngap_data->procedure_code, FALSE);



  return offset;
}



static int
dissect_ngap_ProtocolExtensionID(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 101 "./asn1/ngap/ngap.cnf"
  struct ngap_private_data *ngap_data = ngap_get_private_data(actx->pinfo);
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 65535U, &ngap_data->protocol_extension_id, FALSE);




  return offset;
}


static const value_string ngap_ProtocolIE_ID_vals[] = {
  { id_AllowedNSSAI, "id-AllowedNSSAI" },
  { id_AMFName, "id-AMFName" },
  { id_AMFOverloadResponse, "id-AMFOverloadResponse" },
  { id_AMFSetID, "id-AMFSetID" },
  { id_AMF_TNLAssociationFailedToSetupList, "id-AMF-TNLAssociationFailedToSetupList" },
  { id_AMF_TNLAssociationSetupList, "id-AMF-TNLAssociationSetupList" },
  { id_AMF_TNLAssociationToAddList, "id-AMF-TNLAssociationToAddList" },
  { id_AMF_TNLAssociationToRemoveList, "id-AMF-TNLAssociationToRemoveList" },
  { id_AMF_TNLAssociationToUpdateList, "id-AMF-TNLAssociationToUpdateList" },
  { id_AMFTrafficLoadReductionIndication, "id-AMFTrafficLoadReductionIndication" },
  { id_AMF_UE_NGAP_ID, "id-AMF-UE-NGAP-ID" },
  { id_AssistanceDataForPaging, "id-AssistanceDataForPaging" },
  { id_BroadcastCancelledAreaList, "id-BroadcastCancelledAreaList" },
  { id_BroadcastCompletedAreaList, "id-BroadcastCompletedAreaList" },
  { id_CancelAllWarningMessages, "id-CancelAllWarningMessages" },
  { id_Cause, "id-Cause" },
  { id_CellIDListForRestart, "id-CellIDListForRestart" },
  { id_ConcurrentWarningMessageInd, "id-ConcurrentWarningMessageInd" },
  { id_CoreNetworkAssistanceInformationForInactive, "id-CoreNetworkAssistanceInformationForInactive" },
  { id_CriticalityDiagnostics, "id-CriticalityDiagnostics" },
  { id_DataCodingScheme, "id-DataCodingScheme" },
  { id_DefaultPagingDRX, "id-DefaultPagingDRX" },
  { id_DirectForwardingPathAvailability, "id-DirectForwardingPathAvailability" },
  { id_EmergencyAreaIDListForRestart, "id-EmergencyAreaIDListForRestart" },
  { id_EmergencyFallbackIndicator, "id-EmergencyFallbackIndicator" },
  { id_EUTRA_CGI, "id-EUTRA-CGI" },
  { id_FiveG_S_TMSI, "id-FiveG-S-TMSI" },
  { id_GlobalRANNodeID, "id-GlobalRANNodeID" },
  { id_GUAMI, "id-GUAMI" },
  { id_HandoverType, "id-HandoverType" },
  { id_IMSVoiceSupportIndicator, "id-IMSVoiceSupportIndicator" },
  { id_IndexToRFSP, "id-IndexToRFSP" },
  { id_InfoOnRecommendedCellsAndRANNodesForPaging, "id-InfoOnRecommendedCellsAndRANNodesForPaging" },
  { id_LocationReportingRequestType, "id-LocationReportingRequestType" },
  { id_MaskedIMEISV, "id-MaskedIMEISV" },
  { id_MessageIdentifier, "id-MessageIdentifier" },
  { id_MobilityRestrictionList, "id-MobilityRestrictionList" },
  { id_NASC, "id-NASC" },
  { id_NAS_PDU, "id-NAS-PDU" },
  { id_NASSecurityParametersFromNGRAN, "id-NASSecurityParametersFromNGRAN" },
  { id_NewAMF_UE_NGAP_ID, "id-NewAMF-UE-NGAP-ID" },
  { id_NewSecurityContextInd, "id-NewSecurityContextInd" },
  { id_NGAP_Message, "id-NGAP-Message" },
  { id_NGRAN_CGI, "id-NGRAN-CGI" },
  { id_NGRANTraceID, "id-NGRANTraceID" },
  { id_NR_CGI, "id-NR-CGI" },
  { id_NRPPa_PDU, "id-NRPPa-PDU" },
  { id_NumberOfBroadcastsRequested, "id-NumberOfBroadcastsRequested" },
  { id_OldAMF, "id-OldAMF" },
  { id_OverloadStartNSSAIList, "id-OverloadStartNSSAIList" },
  { id_PagingDRX, "id-PagingDRX" },
  { id_PagingOrigin, "id-PagingOrigin" },
  { id_PagingPriority, "id-PagingPriority" },
  { id_PDUSessionResourceAdmittedList, "id-PDUSessionResourceAdmittedList" },
  { id_PDUSessionResourceFailedToModifyListModRes, "id-PDUSessionResourceFailedToModifyListModRes" },
  { id_PDUSessionResourceFailedToSetupListCxtRes, "id-PDUSessionResourceFailedToSetupListCxtRes" },
  { id_PDUSessionResourceFailedToSetupListHOAck, "id-PDUSessionResourceFailedToSetupListHOAck" },
  { id_PDUSessionResourceFailedToSetupListPSReq, "id-PDUSessionResourceFailedToSetupListPSReq" },
  { id_PDUSessionResourceFailedToSetupListSURes, "id-PDUSessionResourceFailedToSetupListSURes" },
  { id_PDUSessionResourceHandoverList, "id-PDUSessionResourceHandoverList" },
  { id_PDUSessionResourceListCxtRelCpl, "id-PDUSessionResourceListCxtRelCpl" },
  { id_PDUSessionResourceListHORqd, "id-PDUSessionResourceListHORqd" },
  { id_PDUSessionResourceModifyListModCfm, "id-PDUSessionResourceModifyListModCfm" },
  { id_PDUSessionResourceModifyListModInd, "id-PDUSessionResourceModifyListModInd" },
  { id_PDUSessionResourceModifyListModReq, "id-PDUSessionResourceModifyListModReq" },
  { id_PDUSessionResourceModifyListModRes, "id-PDUSessionResourceModifyListModRes" },
  { id_PDUSessionResourceNotifyList, "id-PDUSessionResourceNotifyList" },
  { id_PDUSessionResourceReleasedListNot, "id-PDUSessionResourceReleasedListNot" },
  { id_PDUSessionResourceReleasedListPSAck, "id-PDUSessionResourceReleasedListPSAck" },
  { id_PDUSessionResourceReleasedListPSFail, "id-PDUSessionResourceReleasedListPSFail" },
  { id_PDUSessionResourceReleasedListRelRes, "id-PDUSessionResourceReleasedListRelRes" },
  { id_PDUSessionResourceSetupListCxtReq, "id-PDUSessionResourceSetupListCxtReq" },
  { id_PDUSessionResourceSetupListCxtRes, "id-PDUSessionResourceSetupListCxtRes" },
  { id_PDUSessionResourceSetupListHOReq, "id-PDUSessionResourceSetupListHOReq" },
  { id_PDUSessionResourceSetupListSUReq, "id-PDUSessionResourceSetupListSUReq" },
  { id_PDUSessionResourceSetupListSURes, "id-PDUSessionResourceSetupListSURes" },
  { id_PDUSessionResourceToBeSwitchedDLList, "id-PDUSessionResourceToBeSwitchedDLList" },
  { id_PDUSessionResourceSwitchedList, "id-PDUSessionResourceSwitchedList" },
  { id_PDUSessionResourceToReleaseListHOCmd, "id-PDUSessionResourceToReleaseListHOCmd" },
  { id_PDUSessionResourceToReleaseListRelCmd, "id-PDUSessionResourceToReleaseListRelCmd" },
  { id_PLMNSupportList, "id-PLMNSupportList" },
  { id_PWSFailedCellIDList, "id-PWSFailedCellIDList" },
  { id_RANNodeName, "id-RANNodeName" },
  { id_RANPagingPriority, "id-RANPagingPriority" },
  { id_RANStatusTransfer_TransparentContainer, "id-RANStatusTransfer-TransparentContainer" },
  { id_RAN_UE_NGAP_ID, "id-RAN-UE-NGAP-ID" },
  { id_RelativeAMFCapacity, "id-RelativeAMFCapacity" },
  { id_RepetitionPeriod, "id-RepetitionPeriod" },
  { id_ResetType, "id-ResetType" },
  { id_RoutingID, "id-RoutingID" },
  { id_RRCEstablishmentCause, "id-RRCEstablishmentCause" },
  { id_RRCInactiveTransitionReportRequest, "id-RRCInactiveTransitionReportRequest" },
  { id_RRCState, "id-RRCState" },
  { id_SecurityContext, "id-SecurityContext" },
  { id_SecurityKey, "id-SecurityKey" },
  { id_SerialNumber, "id-SerialNumber" },
  { id_ServedGUAMIList, "id-ServedGUAMIList" },
  { id_SliceSupportList, "id-SliceSupportList" },
  { id_SONConfigurationTransferDL, "id-SONConfigurationTransferDL" },
  { id_SONConfigurationTransferUL, "id-SONConfigurationTransferUL" },
  { id_SourceAMF_UE_NGAP_ID, "id-SourceAMF-UE-NGAP-ID" },
  { id_SourceToTarget_TransparentContainer, "id-SourceToTarget-TransparentContainer" },
  { id_SupportedTAList, "id-SupportedTAList" },
  { id_TAIListForPaging, "id-TAIListForPaging" },
  { id_TAIListForRestart, "id-TAIListForRestart" },
  { id_TargetID, "id-TargetID" },
  { id_TargetToSource_TransparentContainer, "id-TargetToSource-TransparentContainer" },
  { id_TimeToWait, "id-TimeToWait" },
  { id_TraceActivation, "id-TraceActivation" },
  { id_TraceCollectionEntityIPAddress, "id-TraceCollectionEntityIPAddress" },
  { id_UEAggregateMaximumBitRate, "id-UEAggregateMaximumBitRate" },
  { id_UE_associatedLogicalNG_connectionList, "id-UE-associatedLogicalNG-connectionList" },
  { id_UEContextRequest, "id-UEContextRequest" },
  { id_Unknown_113, "id-Unknown-113" },
  { id_UE_NGAP_IDs, "id-UE-NGAP-IDs" },
  { id_UEPagingIdentity, "id-UEPagingIdentity" },
  { id_UEPresenceInAreaOfInterestList, "id-UEPresenceInAreaOfInterestList" },
  { id_UERadioCapability, "id-UERadioCapability" },
  { id_UERadioCapabilityForPaging, "id-UERadioCapabilityForPaging" },
  { id_UESecurityCapabilities, "id-UESecurityCapabilities" },
  { id_UnavailableGUAMIList, "id-UnavailableGUAMIList" },
  { id_UserLocationInformation, "id-UserLocationInformation" },
  { id_WarningAreaList, "id-WarningAreaList" },
  { id_WarningMessageContents, "id-WarningMessageContents" },
  { id_WarningSecurityInfo, "id-WarningSecurityInfo" },
  { id_WarningType, "id-WarningType" },
  { id_AdditionalUL_NGU_UP_TNLInformation, "id-AdditionalUL-NGU-UP-TNLInformation" },
  { id_DataForwardingNotPossible, "id-DataForwardingNotPossible" },
  { id_DL_NGU_UP_TNLInformation, "id-DL-NGU-UP-TNLInformation" },
  { id_NetworkInstance, "id-NetworkInstance" },
  { id_PDUSessionAggregateMaximumBitRate, "id-PDUSessionAggregateMaximumBitRate" },
  { id_PDUSessionResourceFailedToModifyListModCfm, "id-PDUSessionResourceFailedToModifyListModCfm" },
  { id_PDUSessionResourceFailedToSetupListCxtFail, "id-PDUSessionResourceFailedToSetupListCxtFail" },
  { id_PDUSessionResourceListCxtRelReq, "id-PDUSessionResourceListCxtRelReq" },
  { id_PDUSessionType, "id-PDUSessionType" },
  { id_QosFlowAddOrModifyRequestList, "id-QosFlowAddOrModifyRequestList" },
  { id_QosFlowSetupRequestList, "id-QosFlowSetupRequestList" },
  { id_QosFlowToReleaseList, "id-QosFlowToReleaseList" },
  { id_SecurityIndication, "id-SecurityIndication" },
  { id_UL_NGU_UP_TNLInformation, "id-UL-NGU-UP-TNLInformation" },
  { id_UL_NGU_UP_TNLModifyList, "id-UL-NGU-UP-TNLModifyList" },
  { id_WarningAreaCoordinates, "id-WarningAreaCoordinates" },
  { id_PDUSessionResourceSecondaryRATUsageList, "id-PDUSessionResourceSecondaryRATUsageList" },
  { id_HandoverFlag, "id-HandoverFlag" },
  { id_SecondaryRATUsageInformation, "id-SecondaryRATUsageInformation" },
  { id_PDUSessionResourceReleaseResponseTransfer, "id-PDUSessionResourceReleaseResponseTransfer" },
  { id_RedirectionVoiceFallback, "id-RedirectionVoiceFallback" },
  { id_UERetentionInformation, "id-UERetentionInformation" },
  { id_S_NSSAI, "id-S-NSSAI" },
  { id_PSCellInformation, "id-PSCellInformation" },
  { id_LastEUTRAN_PLMNIdentity, "id-LastEUTRAN-PLMNIdentity" },
  { id_MaximumIntegrityProtectedDataRate_DL, "id-MaximumIntegrityProtectedDataRate-DL" },
  { id_AdditionalDLForwardingUPTNLInformation, "id-AdditionalDLForwardingUPTNLInformation" },
  { id_AdditionalDLUPTNLInformationForHOList, "id-AdditionalDLUPTNLInformationForHOList" },
  { id_AdditionalNGU_UP_TNLInformation, "id-AdditionalNGU-UP-TNLInformation" },
  { id_AdditionalDLQosFlowPerTNLInformation, "id-AdditionalDLQosFlowPerTNLInformation" },
  { id_SecurityResult, "id-SecurityResult" },
  { id_ENDC_SONConfigurationTransferDL, "id-ENDC-SONConfigurationTransferDL" },
  { id_ENDC_SONConfigurationTransferUL, "id-ENDC-SONConfigurationTransferUL" },
  { id_OldAssociatedQosFlowList_ULendmarkerexpected, "id-OldAssociatedQosFlowList-ULendmarkerexpected" },
  { id_CNTypeRestrictionsForEquivalent, "id-CNTypeRestrictionsForEquivalent" },
  { id_CNTypeRestrictionsForServing, "id-CNTypeRestrictionsForServing" },
  { id_NewGUAMI, "id-NewGUAMI" },
  { id_ULForwarding, "id-ULForwarding" },
  { id_ULForwardingUP_TNLInformation, "id-ULForwardingUP-TNLInformation" },
  { id_CNAssistedRANTuning, "id-CNAssistedRANTuning" },
  { id_CommonNetworkInstance, "id-CommonNetworkInstance" },
  { id_NGRAN_TNLAssociationToRemoveList, "id-NGRAN-TNLAssociationToRemoveList" },
  { id_TNLAssociationTransportLayerAddressNGRAN, "id-TNLAssociationTransportLayerAddressNGRAN" },
  { id_EndpointIPAddressAndPort, "id-EndpointIPAddressAndPort" },
  { id_LocationReportingAdditionalInfo, "id-LocationReportingAdditionalInfo" },
  { id_SourceToTarget_AMFInformationReroute, "id-SourceToTarget-AMFInformationReroute" },
  { id_AdditionalULForwardingUPTNLInformation, "id-AdditionalULForwardingUPTNLInformation" },
  { id_SCTP_TLAs, "id-SCTP-TLAs" },
  { 0, NULL }
};

static value_string_ext ngap_ProtocolIE_ID_vals_ext = VALUE_STRING_EXT_INIT(ngap_ProtocolIE_ID_vals);


static int
dissect_ngap_ProtocolIE_ID(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 83 "./asn1/ngap/ngap.cnf"
  struct ngap_private_data *ngap_data = ngap_get_private_data(actx->pinfo);
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 65535U, &ngap_data->protocol_ie_id, FALSE);




#line 87 "./asn1/ngap/ngap.cnf"
  if (tree) {
    proto_item_append_text(proto_item_get_parent_nth(actx->created_item, 2), ": %s",
                           val_to_str_ext(ngap_data->protocol_ie_id, &ngap_ProtocolIE_ID_vals_ext, "unknown (%d)"));
  }

  return offset;
}


static const value_string ngap_TriggeringMessage_vals[] = {
  {   0, "initiating-message" },
  {   1, "successful-outcome" },
  {   2, "unsuccessfull-outcome" },
  { 0, NULL }
};


static int
dissect_ngap_TriggeringMessage(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     3, NULL, FALSE, 0, NULL);

  return offset;
}



static int
dissect_ngap_T_ie_field_value(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_open_type_pdu_new(tvb, offset, actx, tree, hf_index, dissect_ProtocolIEFieldValue);

  return offset;
}


static const per_sequence_t ProtocolIE_Field_sequence[] = {
  { &hf_ngap_id             , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ngap_ProtocolIE_ID },
  { &hf_ngap_criticality    , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ngap_Criticality },
  { &hf_ngap_ie_field_value , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ngap_T_ie_field_value },
  { NULL, 0, 0, NULL }
};

static int
dissect_ngap_ProtocolIE_Field(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ngap_ProtocolIE_Field, ProtocolIE_Field_sequence);

  return offset;
}


static const per_sequence_t ProtocolIE_Container_sequence_of[1] = {
  { &hf_ngap_ProtocolIE_Container_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ngap_ProtocolIE_Field },
};

static int
dissect_ngap_ProtocolIE_Container(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_ngap_ProtocolIE_Container, ProtocolIE_Container_sequence_of,
                                                  0, maxProtocolIEs, FALSE);

  return offset;
}



static int
dissect_ngap_ProtocolIE_SingleContainer(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ngap_ProtocolIE_Field(tvb, offset, actx, tree, hf_index);

  return offset;
}



static int
dissect_ngap_T_extensionValue(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_open_type_pdu_new(tvb, offset, actx, tree, hf_index, dissect_ProtocolExtensionFieldExtensionValue);

  return offset;
}


static const per_sequence_t ProtocolExtensionField_sequence[] = {
  { &hf_ngap_ext_id         , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ngap_ProtocolExtensionID },
  { &hf_ngap_criticality    , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ngap_Criticality },
  { &hf_ngap_extensionValue , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ngap_T_extensionValue },
  { NULL, 0, 0, NULL }
};

static int
dissect_ngap_ProtocolExtensionField(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ngap_ProtocolExtensionField, ProtocolExtensionField_sequence);

  return offset;
}


static const per_sequence_t ProtocolExtensionContainer_sequence_of[1] = {
  { &hf_ngap_ProtocolExtensionContainer_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ngap_ProtocolExtensionField },
};

static int
dissect_ngap_ProtocolExtensionContainer(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_ngap_ProtocolExtensionContainer, ProtocolExtensionContainer_sequence_of,
                                                  1, maxProtocolExtensions, FALSE);

  return offset;
}



static int
dissect_ngap_T_private_value(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_open_type(tvb, offset, actx, tree, hf_index, NULL);

  return offset;
}


static const per_sequence_t PrivateIE_Field_sequence[] = {
  { &hf_ngap_private_id     , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ngap_PrivateIE_ID },
  { &hf_ngap_criticality    , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ngap_Criticality },
  { &hf_ngap_private_value  , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ngap_T_private_value },
  { NULL, 0, 0, NULL }
};

static int
dissect_ngap_PrivateIE_Field(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ngap_PrivateIE_Field, PrivateIE_Field_sequence);

  return offset;
}


static const per_sequence_t PrivateIE_Container_sequence_of[1] = {
  { &hf_ngap_PrivateIE_Container_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ngap_PrivateIE_Field },
};

static int
dissect_ngap_PrivateIE_Container(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_ngap_PrivateIE_Container, PrivateIE_Container_sequence_of,
                                                  1, maxPrivateIEs, FALSE);

  return offset;
}



static int
dissect_ngap_TransportLayerAddress(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 377 "./asn1/ngap/ngap.cnf"
  tvbuff_t *parameter_tvb = NULL;
  proto_tree *subtree;
  int len;

  offset = dissect_per_bit_string(tvb, offset, actx, tree, hf_index,
                                     1, 160, TRUE, NULL, 0, &parameter_tvb, &len);

  if (!parameter_tvb)
    return offset;

  subtree = proto_item_add_subtree(actx->created_item, ett_ngap_TransportLayerAddress);
  if (len == 32) {
    /* IPv4 */
     proto_tree_add_item(subtree, hf_ngap_transportLayerAddressIPv4, parameter_tvb, 0, 4, ENC_BIG_ENDIAN);
  } else if (len == 128) {
    /* IPv6 */
     proto_tree_add_item(subtree, hf_ngap_transportLayerAddressIPv6, parameter_tvb, 0, 16, ENC_NA);
  } else if (len == 160) {
    /* IPv4 */
     proto_tree_add_item(subtree, hf_ngap_transportLayerAddressIPv4, parameter_tvb, 0, 4, ENC_BIG_ENDIAN);
    /* IPv6 */
     proto_tree_add_item(subtree, hf_ngap_transportLayerAddressIPv6, parameter_tvb, 4, 16, ENC_NA);
  }



  return offset;
}



static int
dissect_ngap_GTP_TEID(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_octet_string(tvb, offset, actx, tree, hf_index,
                                       4, 4, FALSE, NULL);

  return offset;
}


static const per_sequence_t GTPTunnel_sequence[] = {
  { &hf_ngap_transportLayerAddress, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ngap_TransportLayerAddress },
  { &hf_ngap_gTP_TEID       , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ngap_GTP_TEID },
  { &hf_ngap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ngap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_ngap_GTPTunnel(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ngap_GTPTunnel, GTPTunnel_sequence);

  return offset;
}


static const value_string ngap_UPTransportLayerInformation_vals[] = {
  {   0, "gTPTunnel" },
  {   1, "choice-Extensions" },
  { 0, NULL }
};

static const per_choice_t UPTransportLayerInformation_choice[] = {
  {   0, &hf_ngap_gTPTunnel      , ASN1_NO_EXTENSIONS     , dissect_ngap_GTPTunnel },
  {   1, &hf_ngap_choice_Extensions, ASN1_NO_EXTENSIONS     , dissect_ngap_ProtocolIE_SingleContainer },
  { 0, NULL, 0, NULL }
};

static int
dissect_ngap_UPTransportLayerInformation(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_ngap_UPTransportLayerInformation, UPTransportLayerInformation_choice,
                                 NULL);

  return offset;
}



static int
dissect_ngap_QosFlowIdentifier(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 63U, NULL, TRUE);

  return offset;
}


static const value_string ngap_DataForwardingAccepted_vals[] = {
  {   0, "data-forwarding-accepted" },
  { 0, NULL }
};


static int
dissect_ngap_DataForwardingAccepted(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     1, NULL, TRUE, 0, NULL);

  return offset;
}


static const per_sequence_t QosFlowItemWithDataForwarding_sequence[] = {
  { &hf_ngap_qosFlowIdentifier, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ngap_QosFlowIdentifier },
  { &hf_ngap_dataForwardingAccepted, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ngap_DataForwardingAccepted },
  { &hf_ngap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ngap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_ngap_QosFlowItemWithDataForwarding(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ngap_QosFlowItemWithDataForwarding, QosFlowItemWithDataForwarding_sequence);

  return offset;
}


static const per_sequence_t QosFlowListWithDataForwarding_sequence_of[1] = {
  { &hf_ngap_QosFlowListWithDataForwarding_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ngap_QosFlowItemWithDataForwarding },
};

static int
dissect_ngap_QosFlowListWithDataForwarding(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_ngap_QosFlowListWithDataForwarding, QosFlowListWithDataForwarding_sequence_of,
                                                  1, maxnoofQosFlows, FALSE);

  return offset;
}


static const per_sequence_t AdditionalDLUPTNLInformationForHOItem_sequence[] = {
  { &hf_ngap_additionalDL_NGU_UP_TNLInformation, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ngap_UPTransportLayerInformation },
  { &hf_ngap_additionalQosFlowSetupResponseList, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ngap_QosFlowListWithDataForwarding },
  { &hf_ngap_additionalDLForwardingUPTNLInformation, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ngap_UPTransportLayerInformation },
  { &hf_ngap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ngap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_ngap_AdditionalDLUPTNLInformationForHOItem(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ngap_AdditionalDLUPTNLInformationForHOItem, AdditionalDLUPTNLInformationForHOItem_sequence);

  return offset;
}


static const per_sequence_t AdditionalDLUPTNLInformationForHOList_sequence_of[1] = {
  { &hf_ngap_AdditionalDLUPTNLInformationForHOList_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ngap_AdditionalDLUPTNLInformationForHOItem },
};

static int
dissect_ngap_AdditionalDLUPTNLInformationForHOList(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_ngap_AdditionalDLUPTNLInformationForHOList, AdditionalDLUPTNLInformationForHOList_sequence_of,
                                                  1, maxnoofMultiConnectivityMinusOne, FALSE);

  return offset;
}


static const value_string ngap_AdditionalQosFlowInformation_vals[] = {
  {   0, "more-likely" },
  { 0, NULL }
};


static int
dissect_ngap_AdditionalQosFlowInformation(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     1, NULL, TRUE, 0, NULL);

  return offset;
}



static int
dissect_ngap_PriorityLevelARP(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            1U, 15U, NULL, FALSE);

  return offset;
}


static const value_string ngap_Pre_emptionCapability_vals[] = {
  {   0, "shall-not-trigger-pre-emption" },
  {   1, "may-trigger-pre-emption" },
  { 0, NULL }
};


static int
dissect_ngap_Pre_emptionCapability(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     2, NULL, TRUE, 0, NULL);

  return offset;
}


static const value_string ngap_Pre_emptionVulnerability_vals[] = {
  {   0, "not-pre-emptable" },
  {   1, "pre-emptable" },
  { 0, NULL }
};


static int
dissect_ngap_Pre_emptionVulnerability(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     2, NULL, TRUE, 0, NULL);

  return offset;
}


static const per_sequence_t AllocationAndRetentionPriority_sequence[] = {
  { &hf_ngap_priorityLevelARP, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ngap_PriorityLevelARP },
  { &hf_ngap_pre_emptionCapability, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ngap_Pre_emptionCapability },
  { &hf_ngap_pre_emptionVulnerability, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ngap_Pre_emptionVulnerability },
  { &hf_ngap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ngap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_ngap_AllocationAndRetentionPriority(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ngap_AllocationAndRetentionPriority, AllocationAndRetentionPriority_sequence);

  return offset;
}



static int
dissect_ngap_SST(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_octet_string(tvb, offset, actx, tree, hf_index,
                                       1, 1, FALSE, NULL);

  return offset;
}



static int
dissect_ngap_SD(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_octet_string(tvb, offset, actx, tree, hf_index,
                                       3, 3, FALSE, NULL);

  return offset;
}


static const per_sequence_t S_NSSAI_sequence[] = {
  { &hf_ngap_sST            , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ngap_SST },
  { &hf_ngap_sD             , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ngap_SD },
  { &hf_ngap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ngap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_ngap_S_NSSAI(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ngap_S_NSSAI, S_NSSAI_sequence);

  return offset;
}


static const per_sequence_t AllowedNSSAI_Item_sequence[] = {
  { &hf_ngap_s_NSSAI        , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ngap_S_NSSAI },
  { &hf_ngap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ngap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_ngap_AllowedNSSAI_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ngap_AllowedNSSAI_Item, AllowedNSSAI_Item_sequence);

  return offset;
}


static const per_sequence_t AllowedNSSAI_sequence_of[1] = {
  { &hf_ngap_AllowedNSSAI_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ngap_AllowedNSSAI_Item },
};

static int
dissect_ngap_AllowedNSSAI(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_ngap_AllowedNSSAI, AllowedNSSAI_sequence_of,
                                                  1, maxnoofAllowedS_NSSAIs, FALSE);

  return offset;
}



static int
dissect_ngap_TAC(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 358 "./asn1/ngap/ngap.cnf"
  tvbuff_t *parameter_tvb = NULL;
  offset = dissect_per_octet_string(tvb, offset, actx, tree, -1,
                                       3, 3, FALSE, &parameter_tvb);

  if (parameter_tvb) {
    actx->created_item = proto_tree_add_item(tree, hf_index, parameter_tvb, 0, 3, ENC_BIG_ENDIAN);
  }



  return offset;
}


static const per_sequence_t AllowedTACs_sequence_of[1] = {
  { &hf_ngap_AllowedTACs_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ngap_TAC },
};

static int
dissect_ngap_AllowedTACs(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_ngap_AllowedTACs, AllowedTACs_sequence_of,
                                                  1, maxnoofAllowedAreas, FALSE);

  return offset;
}



static int
dissect_ngap_AMFName(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_PrintableString(tvb, offset, actx, tree, hf_index,
                                          1, 150, TRUE);

  return offset;
}



static int
dissect_ngap_PLMNIdentity(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 365 "./asn1/ngap/ngap.cnf"
  tvbuff_t *parameter_tvb = NULL;
  proto_tree *subtree;

  offset = dissect_per_octet_string(tvb, offset, actx, tree, hf_index,
                                       3, 3, FALSE, &parameter_tvb);


  if (!parameter_tvb)
    return offset;

  subtree = proto_item_add_subtree(actx->created_item, ett_ngap_PLMNIdentity);
  dissect_e212_mcc_mnc(parameter_tvb, actx->pinfo, subtree, 0, E212_NONE, FALSE);



  return offset;
}



static int
dissect_ngap_BIT_STRING_SIZE_22_32(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_bit_string(tvb, offset, actx, tree, hf_index,
                                     22, 32, FALSE, NULL, 0, NULL, NULL);

  return offset;
}


static const value_string ngap_GNB_ID_vals[] = {
  {   0, "gNB-ID" },
  {   1, "choice-Extensions" },
  { 0, NULL }
};

static const per_choice_t GNB_ID_choice[] = {
  {   0, &hf_ngap_gNB_ID_01      , ASN1_NO_EXTENSIONS     , dissect_ngap_BIT_STRING_SIZE_22_32 },
  {   1, &hf_ngap_choice_Extensions, ASN1_NO_EXTENSIONS     , dissect_ngap_ProtocolIE_SingleContainer },
  { 0, NULL, 0, NULL }
};

static int
dissect_ngap_GNB_ID(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_ngap_GNB_ID, GNB_ID_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t GlobalGNB_ID_sequence[] = {
  { &hf_ngap_pLMNIdentity   , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ngap_PLMNIdentity },
  { &hf_ngap_gNB_ID         , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ngap_GNB_ID },
  { &hf_ngap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ngap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_ngap_GlobalGNB_ID(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ngap_GlobalGNB_ID, GlobalGNB_ID_sequence);

  return offset;
}



static int
dissect_ngap_BIT_STRING_SIZE_20(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_bit_string(tvb, offset, actx, tree, hf_index,
                                     20, 20, FALSE, NULL, 0, NULL, NULL);

  return offset;
}



static int
dissect_ngap_BIT_STRING_SIZE_18(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_bit_string(tvb, offset, actx, tree, hf_index,
                                     18, 18, FALSE, NULL, 0, NULL, NULL);

  return offset;
}



static int
dissect_ngap_BIT_STRING_SIZE_21(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_bit_string(tvb, offset, actx, tree, hf_index,
                                     21, 21, FALSE, NULL, 0, NULL, NULL);

  return offset;
}


static const value_string ngap_NgENB_ID_vals[] = {
  {   0, "macroNgENB-ID" },
  {   1, "shortMacroNgENB-ID" },
  {   2, "longMacroNgENB-ID" },
  {   3, "choice-Extensions" },
  { 0, NULL }
};

static const per_choice_t NgENB_ID_choice[] = {
  {   0, &hf_ngap_macroNgENB_ID  , ASN1_NO_EXTENSIONS     , dissect_ngap_BIT_STRING_SIZE_20 },
  {   1, &hf_ngap_shortMacroNgENB_ID, ASN1_NO_EXTENSIONS     , dissect_ngap_BIT_STRING_SIZE_18 },
  {   2, &hf_ngap_longMacroNgENB_ID, ASN1_NO_EXTENSIONS     , dissect_ngap_BIT_STRING_SIZE_21 },
  {   3, &hf_ngap_choice_Extensions, ASN1_NO_EXTENSIONS     , dissect_ngap_ProtocolIE_SingleContainer },
  { 0, NULL, 0, NULL }
};

static int
dissect_ngap_NgENB_ID(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_ngap_NgENB_ID, NgENB_ID_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t GlobalNgENB_ID_sequence[] = {
  { &hf_ngap_pLMNIdentity   , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ngap_PLMNIdentity },
  { &hf_ngap_ngENB_ID       , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ngap_NgENB_ID },
  { &hf_ngap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ngap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_ngap_GlobalNgENB_ID(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ngap_GlobalNgENB_ID, GlobalNgENB_ID_sequence);

  return offset;
}



static int
dissect_ngap_BIT_STRING_SIZE_16(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_bit_string(tvb, offset, actx, tree, hf_index,
                                     16, 16, FALSE, NULL, 0, NULL, NULL);

  return offset;
}


static const value_string ngap_N3IWF_ID_vals[] = {
  {   0, "n3IWF-ID" },
  {   1, "choice-Extensions" },
  { 0, NULL }
};

static const per_choice_t N3IWF_ID_choice[] = {
  {   0, &hf_ngap_n3IWF_ID_01    , ASN1_NO_EXTENSIONS     , dissect_ngap_BIT_STRING_SIZE_16 },
  {   1, &hf_ngap_choice_Extensions, ASN1_NO_EXTENSIONS     , dissect_ngap_ProtocolIE_SingleContainer },
  { 0, NULL, 0, NULL }
};

static int
dissect_ngap_N3IWF_ID(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_ngap_N3IWF_ID, N3IWF_ID_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t GlobalN3IWF_ID_sequence[] = {
  { &hf_ngap_pLMNIdentity   , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ngap_PLMNIdentity },
  { &hf_ngap_n3IWF_ID       , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ngap_N3IWF_ID },
  { &hf_ngap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ngap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_ngap_GlobalN3IWF_ID(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ngap_GlobalN3IWF_ID, GlobalN3IWF_ID_sequence);

  return offset;
}


static const value_string ngap_GlobalRANNodeID_vals[] = {
  { globalGNB_ID, "globalGNB-ID" },
  { globalNgENB_ID, "globalNgENB-ID" },
  { globalN3IWF_ID, "globalN3IWF-ID" },
  { choice_Extensions, "choice-Extensions" },
  { 0, NULL }
};

static const per_choice_t GlobalRANNodeID_choice[] = {
  { globalGNB_ID, &hf_ngap_globalGNB_ID   , ASN1_NO_EXTENSIONS     , dissect_ngap_GlobalGNB_ID },
  { globalNgENB_ID, &hf_ngap_globalNgENB_ID , ASN1_NO_EXTENSIONS     , dissect_ngap_GlobalNgENB_ID },
  { globalN3IWF_ID, &hf_ngap_globalN3IWF_ID , ASN1_NO_EXTENSIONS     , dissect_ngap_GlobalN3IWF_ID },
  { choice_Extensions, &hf_ngap_choice_Extensions, ASN1_NO_EXTENSIONS     , dissect_ngap_ProtocolIE_SingleContainer },
  { 0, NULL, 0, NULL }
};

static int
dissect_ngap_GlobalRANNodeID(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 483 "./asn1/ngap/ngap.cnf"
  gint value;
  struct ngap_private_data *ngap_data = ngap_get_private_data(actx->pinfo);

  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_ngap_GlobalRANNodeID, GlobalRANNodeID_choice,
                                 &value);

  if (ngap_data->ngap_conv && ngap_data->procedure_code == id_NGSetup) {
    if (addresses_equal(&actx->pinfo->src, &ngap_data->ngap_conv->addr_a) &&
        actx->pinfo->srcport == ngap_data->ngap_conv->port_a) {
      ngap_data->ngap_conv->ranmode_id_a = (GlobalRANNodeID_enum)value;
    } else if (addresses_equal(&actx->pinfo->src, &ngap_data->ngap_conv->addr_b) &&
               actx->pinfo->srcport == ngap_data->ngap_conv->port_b) {
      ngap_data->ngap_conv->ranmode_id_b = (GlobalRANNodeID_enum)value;
    }
  }



  return offset;
}


static const per_sequence_t TAI_sequence[] = {
  { &hf_ngap_pLMNIdentity   , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ngap_PLMNIdentity },
  { &hf_ngap_tAC            , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ngap_TAC },
  { &hf_ngap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ngap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_ngap_TAI(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ngap_TAI, TAI_sequence);

  return offset;
}


static const value_string ngap_AMFPagingTarget_vals[] = {
  {   0, "globalRANNodeID" },
  {   1, "tAI" },
  {   2, "choice-Extensions" },
  { 0, NULL }
};

static const per_choice_t AMFPagingTarget_choice[] = {
  {   0, &hf_ngap_globalRANNodeID, ASN1_NO_EXTENSIONS     , dissect_ngap_GlobalRANNodeID },
  {   1, &hf_ngap_tAI            , ASN1_NO_EXTENSIONS     , dissect_ngap_TAI },
  {   2, &hf_ngap_choice_Extensions, ASN1_NO_EXTENSIONS     , dissect_ngap_ProtocolIE_SingleContainer },
  { 0, NULL, 0, NULL }
};

static int
dissect_ngap_AMFPagingTarget(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_ngap_AMFPagingTarget, AMFPagingTarget_choice,
                                 NULL);

  return offset;
}



static int
dissect_ngap_AMFPointer(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_bit_string(tvb, offset, actx, tree, hf_index,
                                     6, 6, FALSE, NULL, 0, NULL, NULL);

  return offset;
}



static int
dissect_ngap_AMFRegionID(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_bit_string(tvb, offset, actx, tree, hf_index,
                                     8, 8, FALSE, NULL, 0, NULL, NULL);

  return offset;
}



static int
dissect_ngap_AMFSetID(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_bit_string(tvb, offset, actx, tree, hf_index,
                                     10, 10, FALSE, NULL, 0, NULL, NULL);

  return offset;
}


static const value_string ngap_CPTransportLayerInformation_vals[] = {
  {   0, "endpointIPAddress" },
  {   1, "choice-Extensions" },
  { 0, NULL }
};

static const per_choice_t CPTransportLayerInformation_choice[] = {
  {   0, &hf_ngap_endpointIPAddress, ASN1_NO_EXTENSIONS     , dissect_ngap_TransportLayerAddress },
  {   1, &hf_ngap_choice_Extensions, ASN1_NO_EXTENSIONS     , dissect_ngap_ProtocolIE_SingleContainer },
  { 0, NULL, 0, NULL }
};

static int
dissect_ngap_CPTransportLayerInformation(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_ngap_CPTransportLayerInformation, CPTransportLayerInformation_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t AMF_TNLAssociationSetupItem_sequence[] = {
  { &hf_ngap_aMF_TNLAssociationAddress, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ngap_CPTransportLayerInformation },
  { &hf_ngap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ngap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_ngap_AMF_TNLAssociationSetupItem(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ngap_AMF_TNLAssociationSetupItem, AMF_TNLAssociationSetupItem_sequence);

  return offset;
}


static const per_sequence_t AMF_TNLAssociationSetupList_sequence_of[1] = {
  { &hf_ngap_AMF_TNLAssociationSetupList_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ngap_AMF_TNLAssociationSetupItem },
};

static int
dissect_ngap_AMF_TNLAssociationSetupList(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_ngap_AMF_TNLAssociationSetupList, AMF_TNLAssociationSetupList_sequence_of,
                                                  1, maxnoofTNLAssociations, FALSE);

  return offset;
}


static const value_string ngap_TNLAssociationUsage_vals[] = {
  {   0, "ue" },
  {   1, "non-ue" },
  {   2, "both" },
  { 0, NULL }
};


static int
dissect_ngap_TNLAssociationUsage(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     3, NULL, TRUE, 0, NULL);

  return offset;
}



static int
dissect_ngap_TNLAddressWeightFactor(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 255U, NULL, FALSE);

  return offset;
}


static const per_sequence_t AMF_TNLAssociationToAddItem_sequence[] = {
  { &hf_ngap_aMF_TNLAssociationAddress, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ngap_CPTransportLayerInformation },
  { &hf_ngap_tNLAssociationUsage, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ngap_TNLAssociationUsage },
  { &hf_ngap_tNLAddressWeightFactor, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ngap_TNLAddressWeightFactor },
  { &hf_ngap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ngap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_ngap_AMF_TNLAssociationToAddItem(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ngap_AMF_TNLAssociationToAddItem, AMF_TNLAssociationToAddItem_sequence);

  return offset;
}


static const per_sequence_t AMF_TNLAssociationToAddList_sequence_of[1] = {
  { &hf_ngap_AMF_TNLAssociationToAddList_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ngap_AMF_TNLAssociationToAddItem },
};

static int
dissect_ngap_AMF_TNLAssociationToAddList(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_ngap_AMF_TNLAssociationToAddList, AMF_TNLAssociationToAddList_sequence_of,
                                                  1, maxnoofTNLAssociations, FALSE);

  return offset;
}


static const per_sequence_t AMF_TNLAssociationToRemoveItem_sequence[] = {
  { &hf_ngap_aMF_TNLAssociationAddress, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ngap_CPTransportLayerInformation },
  { &hf_ngap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ngap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_ngap_AMF_TNLAssociationToRemoveItem(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ngap_AMF_TNLAssociationToRemoveItem, AMF_TNLAssociationToRemoveItem_sequence);

  return offset;
}


static const per_sequence_t AMF_TNLAssociationToRemoveList_sequence_of[1] = {
  { &hf_ngap_AMF_TNLAssociationToRemoveList_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ngap_AMF_TNLAssociationToRemoveItem },
};

static int
dissect_ngap_AMF_TNLAssociationToRemoveList(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_ngap_AMF_TNLAssociationToRemoveList, AMF_TNLAssociationToRemoveList_sequence_of,
                                                  1, maxnoofTNLAssociations, FALSE);

  return offset;
}


static const per_sequence_t AMF_TNLAssociationToUpdateItem_sequence[] = {
  { &hf_ngap_aMF_TNLAssociationAddress, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ngap_CPTransportLayerInformation },
  { &hf_ngap_tNLAssociationUsage, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ngap_TNLAssociationUsage },
  { &hf_ngap_tNLAddressWeightFactor, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ngap_TNLAddressWeightFactor },
  { &hf_ngap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ngap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_ngap_AMF_TNLAssociationToUpdateItem(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ngap_AMF_TNLAssociationToUpdateItem, AMF_TNLAssociationToUpdateItem_sequence);

  return offset;
}


static const per_sequence_t AMF_TNLAssociationToUpdateList_sequence_of[1] = {
  { &hf_ngap_AMF_TNLAssociationToUpdateList_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ngap_AMF_TNLAssociationToUpdateItem },
};

static int
dissect_ngap_AMF_TNLAssociationToUpdateList(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_ngap_AMF_TNLAssociationToUpdateList, AMF_TNLAssociationToUpdateList_sequence_of,
                                                  1, maxnoofTNLAssociations, FALSE);

  return offset;
}



static int
dissect_ngap_AMF_UE_NGAP_ID(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer_64b(tvb, offset, actx, tree, hf_index,
                                                            0U, G_GUINT64_CONSTANT(1099511627775), NULL, FALSE);

  return offset;
}


static const per_sequence_t AreaOfInterestTAIItem_sequence[] = {
  { &hf_ngap_tAI            , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ngap_TAI },
  { &hf_ngap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ngap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_ngap_AreaOfInterestTAIItem(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ngap_AreaOfInterestTAIItem, AreaOfInterestTAIItem_sequence);

  return offset;
}


static const per_sequence_t AreaOfInterestTAIList_sequence_of[1] = {
  { &hf_ngap_AreaOfInterestTAIList_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ngap_AreaOfInterestTAIItem },
};

static int
dissect_ngap_AreaOfInterestTAIList(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_ngap_AreaOfInterestTAIList, AreaOfInterestTAIList_sequence_of,
                                                  1, maxnoofTAIinAoI, FALSE);

  return offset;
}



static int
dissect_ngap_NRCellIdentity(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 425 "./asn1/ngap/ngap.cnf"
  tvbuff_t *cell_id_tvb = NULL;
  offset = dissect_per_bit_string(tvb, offset, actx, tree, -1,
                                     36, 36, FALSE, NULL, 0, &cell_id_tvb, NULL);

  if (cell_id_tvb) {
    guint64 cell_id = tvb_get_bits64(cell_id_tvb, 0, 36, ENC_BIG_ENDIAN);
    actx->created_item = proto_tree_add_uint64(tree, hf_index, cell_id_tvb, 0, 5, cell_id);
  }



  return offset;
}


static const per_sequence_t NR_CGI_sequence[] = {
  { &hf_ngap_pLMNIdentity   , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ngap_PLMNIdentity },
  { &hf_ngap_nRCellIdentity , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ngap_NRCellIdentity },
  { &hf_ngap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ngap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_ngap_NR_CGI(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ngap_NR_CGI, NR_CGI_sequence);

  return offset;
}



static int
dissect_ngap_EUTRACellIdentity(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 436 "./asn1/ngap/ngap.cnf"
  tvbuff_t *cell_id_tvb = NULL;
  offset = dissect_per_bit_string(tvb, offset, actx, tree, -1,
                                     28, 28, FALSE, NULL, 0, &cell_id_tvb, NULL);

  if (cell_id_tvb) {
    guint32 cell_id = tvb_get_bits32(cell_id_tvb, 0, 28, ENC_BIG_ENDIAN);
    actx->created_item = proto_tree_add_uint(tree, hf_index, cell_id_tvb, 0, 4, cell_id);
  }



  return offset;
}


static const per_sequence_t EUTRA_CGI_sequence[] = {
  { &hf_ngap_pLMNIdentity   , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ngap_PLMNIdentity },
  { &hf_ngap_eUTRACellIdentity, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ngap_EUTRACellIdentity },
  { &hf_ngap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ngap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_ngap_EUTRA_CGI(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ngap_EUTRA_CGI, EUTRA_CGI_sequence);

  return offset;
}


static const value_string ngap_NGRAN_CGI_vals[] = {
  {   0, "nR-CGI" },
  {   1, "eUTRA-CGI" },
  {   2, "choice-Extensions" },
  { 0, NULL }
};

static const per_choice_t NGRAN_CGI_choice[] = {
  {   0, &hf_ngap_nR_CGI         , ASN1_NO_EXTENSIONS     , dissect_ngap_NR_CGI },
  {   1, &hf_ngap_eUTRA_CGI      , ASN1_NO_EXTENSIONS     , dissect_ngap_EUTRA_CGI },
  {   2, &hf_ngap_choice_Extensions, ASN1_NO_EXTENSIONS     , dissect_ngap_ProtocolIE_SingleContainer },
  { 0, NULL, 0, NULL }
};

static int
dissect_ngap_NGRAN_CGI(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_ngap_NGRAN_CGI, NGRAN_CGI_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t AreaOfInterestCellItem_sequence[] = {
  { &hf_ngap_nGRAN_CGI      , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ngap_NGRAN_CGI },
  { &hf_ngap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ngap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_ngap_AreaOfInterestCellItem(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ngap_AreaOfInterestCellItem, AreaOfInterestCellItem_sequence);

  return offset;
}


static const per_sequence_t AreaOfInterestCellList_sequence_of[1] = {
  { &hf_ngap_AreaOfInterestCellList_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ngap_AreaOfInterestCellItem },
};

static int
dissect_ngap_AreaOfInterestCellList(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_ngap_AreaOfInterestCellList, AreaOfInterestCellList_sequence_of,
                                                  1, maxnoofCellinAoI, FALSE);

  return offset;
}


static const per_sequence_t AreaOfInterestRANNodeItem_sequence[] = {
  { &hf_ngap_globalRANNodeID, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ngap_GlobalRANNodeID },
  { &hf_ngap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ngap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_ngap_AreaOfInterestRANNodeItem(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ngap_AreaOfInterestRANNodeItem, AreaOfInterestRANNodeItem_sequence);

  return offset;
}


static const per_sequence_t AreaOfInterestRANNodeList_sequence_of[1] = {
  { &hf_ngap_AreaOfInterestRANNodeList_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ngap_AreaOfInterestRANNodeItem },
};

static int
dissect_ngap_AreaOfInterestRANNodeList(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_ngap_AreaOfInterestRANNodeList, AreaOfInterestRANNodeList_sequence_of,
                                                  1, maxnoofRANNodeinAoI, FALSE);

  return offset;
}


static const per_sequence_t AreaOfInterest_sequence[] = {
  { &hf_ngap_areaOfInterestTAIList, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ngap_AreaOfInterestTAIList },
  { &hf_ngap_areaOfInterestCellList, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ngap_AreaOfInterestCellList },
  { &hf_ngap_areaOfInterestRANNodeList, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ngap_AreaOfInterestRANNodeList },
  { &hf_ngap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ngap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_ngap_AreaOfInterest(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ngap_AreaOfInterest, AreaOfInterest_sequence);

  return offset;
}



static int
dissect_ngap_LocationReportingReferenceID(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            1U, 64U, NULL, TRUE);

  return offset;
}


static const per_sequence_t AreaOfInterestItem_sequence[] = {
  { &hf_ngap_areaOfInterest , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ngap_AreaOfInterest },
  { &hf_ngap_locationReportingReferenceID, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ngap_LocationReportingReferenceID },
  { &hf_ngap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ngap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_ngap_AreaOfInterestItem(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ngap_AreaOfInterestItem, AreaOfInterestItem_sequence);

  return offset;
}


static const per_sequence_t AreaOfInterestList_sequence_of[1] = {
  { &hf_ngap_AreaOfInterestList_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ngap_AreaOfInterestItem },
};

static int
dissect_ngap_AreaOfInterestList(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_ngap_AreaOfInterestList, AreaOfInterestList_sequence_of,
                                                  1, maxnoofAoI, FALSE);

  return offset;
}



static int
dissect_ngap_INTEGER_0_4095(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 4095U, NULL, FALSE);

  return offset;
}


static const per_sequence_t RecommendedCellItem_sequence[] = {
  { &hf_ngap_nGRAN_CGI      , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ngap_NGRAN_CGI },
  { &hf_ngap_timeStayedInCell, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ngap_INTEGER_0_4095 },
  { &hf_ngap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ngap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_ngap_RecommendedCellItem(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ngap_RecommendedCellItem, RecommendedCellItem_sequence);

  return offset;
}


static const per_sequence_t RecommendedCellList_sequence_of[1] = {
  { &hf_ngap_RecommendedCellList_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ngap_RecommendedCellItem },
};

static int
dissect_ngap_RecommendedCellList(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_ngap_RecommendedCellList, RecommendedCellList_sequence_of,
                                                  1, maxnoofRecommendedCells, FALSE);

  return offset;
}


static const per_sequence_t RecommendedCellsForPaging_sequence[] = {
  { &hf_ngap_recommendedCellList, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ngap_RecommendedCellList },
  { &hf_ngap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ngap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_ngap_RecommendedCellsForPaging(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ngap_RecommendedCellsForPaging, RecommendedCellsForPaging_sequence);

  return offset;
}


static const per_sequence_t AssistanceDataForRecommendedCells_sequence[] = {
  { &hf_ngap_recommendedCellsForPaging, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ngap_RecommendedCellsForPaging },
  { &hf_ngap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ngap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_ngap_AssistanceDataForRecommendedCells(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ngap_AssistanceDataForRecommendedCells, AssistanceDataForRecommendedCells_sequence);

  return offset;
}



static int
dissect_ngap_PagingAttemptCount(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            1U, 16U, NULL, TRUE);

  return offset;
}



static int
dissect_ngap_IntendedNumberOfPagingAttempts(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            1U, 16U, NULL, TRUE);

  return offset;
}


static const value_string ngap_NextPagingAreaScope_vals[] = {
  {   0, "same" },
  {   1, "changed" },
  { 0, NULL }
};


static int
dissect_ngap_NextPagingAreaScope(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     2, NULL, TRUE, 0, NULL);

  return offset;
}


static const per_sequence_t PagingAttemptInformation_sequence[] = {
  { &hf_ngap_pagingAttemptCount, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ngap_PagingAttemptCount },
  { &hf_ngap_intendedNumberOfPagingAttempts, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ngap_IntendedNumberOfPagingAttempts },
  { &hf_ngap_nextPagingAreaScope, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ngap_NextPagingAreaScope },
  { &hf_ngap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ngap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_ngap_PagingAttemptInformation(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ngap_PagingAttemptInformation, PagingAttemptInformation_sequence);

  return offset;
}


static const per_sequence_t AssistanceDataForPaging_sequence[] = {
  { &hf_ngap_assistanceDataForRecommendedCells, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ngap_AssistanceDataForRecommendedCells },
  { &hf_ngap_pagingAttemptInformation, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ngap_PagingAttemptInformation },
  { &hf_ngap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ngap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_ngap_AssistanceDataForPaging(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ngap_AssistanceDataForPaging, AssistanceDataForPaging_sequence);

  return offset;
}


static const value_string ngap_T_qosFlowMappingIndication_vals[] = {
  {   0, "ul" },
  {   1, "dl" },
  { 0, NULL }
};


static int
dissect_ngap_T_qosFlowMappingIndication(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     2, NULL, TRUE, 0, NULL);

  return offset;
}


static const per_sequence_t AssociatedQosFlowItem_sequence[] = {
  { &hf_ngap_qosFlowIdentifier, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ngap_QosFlowIdentifier },
  { &hf_ngap_qosFlowMappingIndication, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ngap_T_qosFlowMappingIndication },
  { &hf_ngap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ngap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_ngap_AssociatedQosFlowItem(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ngap_AssociatedQosFlowItem, AssociatedQosFlowItem_sequence);

  return offset;
}


static const per_sequence_t AssociatedQosFlowList_sequence_of[1] = {
  { &hf_ngap_AssociatedQosFlowList_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ngap_AssociatedQosFlowItem },
};

static int
dissect_ngap_AssociatedQosFlowList(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_ngap_AssociatedQosFlowList, AssociatedQosFlowList_sequence_of,
                                                  1, maxnoofQosFlows, FALSE);

  return offset;
}



static int
dissect_ngap_AveragingWindow(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 4095U, NULL, TRUE);

  return offset;
}



static int
dissect_ngap_BitRate(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer_64b(tvb, offset, actx, tree, hf_index,
                                                            0U, G_GUINT64_CONSTANT(4000000000000), NULL, TRUE);

  return offset;
}



static int
dissect_ngap_NumberOfBroadcasts(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 65535U, NULL, FALSE);

  return offset;
}


static const per_sequence_t CellIDCancelledEUTRA_Item_sequence[] = {
  { &hf_ngap_eUTRA_CGI      , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ngap_EUTRA_CGI },
  { &hf_ngap_numberOfBroadcasts, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ngap_NumberOfBroadcasts },
  { &hf_ngap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ngap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_ngap_CellIDCancelledEUTRA_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ngap_CellIDCancelledEUTRA_Item, CellIDCancelledEUTRA_Item_sequence);

  return offset;
}


static const per_sequence_t CellIDCancelledEUTRA_sequence_of[1] = {
  { &hf_ngap_CellIDCancelledEUTRA_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ngap_CellIDCancelledEUTRA_Item },
};

static int
dissect_ngap_CellIDCancelledEUTRA(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_ngap_CellIDCancelledEUTRA, CellIDCancelledEUTRA_sequence_of,
                                                  1, maxnoofCellIDforWarning, FALSE);

  return offset;
}


static const per_sequence_t CancelledCellsInTAI_EUTRA_Item_sequence[] = {
  { &hf_ngap_eUTRA_CGI      , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ngap_EUTRA_CGI },
  { &hf_ngap_numberOfBroadcasts, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ngap_NumberOfBroadcasts },
  { &hf_ngap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ngap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_ngap_CancelledCellsInTAI_EUTRA_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ngap_CancelledCellsInTAI_EUTRA_Item, CancelledCellsInTAI_EUTRA_Item_sequence);

  return offset;
}


static const per_sequence_t CancelledCellsInTAI_EUTRA_sequence_of[1] = {
  { &hf_ngap_CancelledCellsInTAI_EUTRA_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ngap_CancelledCellsInTAI_EUTRA_Item },
};

static int
dissect_ngap_CancelledCellsInTAI_EUTRA(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_ngap_CancelledCellsInTAI_EUTRA, CancelledCellsInTAI_EUTRA_sequence_of,
                                                  1, maxnoofCellinTAI, FALSE);

  return offset;
}


static const per_sequence_t TAICancelledEUTRA_Item_sequence[] = {
  { &hf_ngap_tAI            , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ngap_TAI },
  { &hf_ngap_cancelledCellsInTAI_EUTRA, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ngap_CancelledCellsInTAI_EUTRA },
  { &hf_ngap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ngap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_ngap_TAICancelledEUTRA_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ngap_TAICancelledEUTRA_Item, TAICancelledEUTRA_Item_sequence);

  return offset;
}


static const per_sequence_t TAICancelledEUTRA_sequence_of[1] = {
  { &hf_ngap_TAICancelledEUTRA_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ngap_TAICancelledEUTRA_Item },
};

static int
dissect_ngap_TAICancelledEUTRA(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_ngap_TAICancelledEUTRA, TAICancelledEUTRA_sequence_of,
                                                  1, maxnoofTAIforWarning, FALSE);

  return offset;
}



static int
dissect_ngap_EmergencyAreaID(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_octet_string(tvb, offset, actx, tree, hf_index,
                                       3, 3, FALSE, NULL);

  return offset;
}


static const per_sequence_t CancelledCellsInEAI_EUTRA_Item_sequence[] = {
  { &hf_ngap_eUTRA_CGI      , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ngap_EUTRA_CGI },
  { &hf_ngap_numberOfBroadcasts, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ngap_NumberOfBroadcasts },
  { &hf_ngap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ngap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_ngap_CancelledCellsInEAI_EUTRA_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ngap_CancelledCellsInEAI_EUTRA_Item, CancelledCellsInEAI_EUTRA_Item_sequence);

  return offset;
}


static const per_sequence_t CancelledCellsInEAI_EUTRA_sequence_of[1] = {
  { &hf_ngap_CancelledCellsInEAI_EUTRA_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ngap_CancelledCellsInEAI_EUTRA_Item },
};

static int
dissect_ngap_CancelledCellsInEAI_EUTRA(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_ngap_CancelledCellsInEAI_EUTRA, CancelledCellsInEAI_EUTRA_sequence_of,
                                                  1, maxnoofCellinEAI, FALSE);

  return offset;
}


static const per_sequence_t EmergencyAreaIDCancelledEUTRA_Item_sequence[] = {
  { &hf_ngap_emergencyAreaID, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ngap_EmergencyAreaID },
  { &hf_ngap_cancelledCellsInEAI_EUTRA, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ngap_CancelledCellsInEAI_EUTRA },
  { &hf_ngap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ngap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_ngap_EmergencyAreaIDCancelledEUTRA_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ngap_EmergencyAreaIDCancelledEUTRA_Item, EmergencyAreaIDCancelledEUTRA_Item_sequence);

  return offset;
}


static const per_sequence_t EmergencyAreaIDCancelledEUTRA_sequence_of[1] = {
  { &hf_ngap_EmergencyAreaIDCancelledEUTRA_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ngap_EmergencyAreaIDCancelledEUTRA_Item },
};

static int
dissect_ngap_EmergencyAreaIDCancelledEUTRA(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_ngap_EmergencyAreaIDCancelledEUTRA, EmergencyAreaIDCancelledEUTRA_sequence_of,
                                                  1, maxnoofEmergencyAreaID, FALSE);

  return offset;
}


static const per_sequence_t CellIDCancelledNR_Item_sequence[] = {
  { &hf_ngap_nR_CGI         , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ngap_NR_CGI },
  { &hf_ngap_numberOfBroadcasts, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ngap_NumberOfBroadcasts },
  { &hf_ngap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ngap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_ngap_CellIDCancelledNR_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ngap_CellIDCancelledNR_Item, CellIDCancelledNR_Item_sequence);

  return offset;
}


static const per_sequence_t CellIDCancelledNR_sequence_of[1] = {
  { &hf_ngap_CellIDCancelledNR_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ngap_CellIDCancelledNR_Item },
};

static int
dissect_ngap_CellIDCancelledNR(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_ngap_CellIDCancelledNR, CellIDCancelledNR_sequence_of,
                                                  1, maxnoofCellIDforWarning, FALSE);

  return offset;
}


static const per_sequence_t CancelledCellsInTAI_NR_Item_sequence[] = {
  { &hf_ngap_nR_CGI         , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ngap_NR_CGI },
  { &hf_ngap_numberOfBroadcasts, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ngap_NumberOfBroadcasts },
  { &hf_ngap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ngap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_ngap_CancelledCellsInTAI_NR_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ngap_CancelledCellsInTAI_NR_Item, CancelledCellsInTAI_NR_Item_sequence);

  return offset;
}


static const per_sequence_t CancelledCellsInTAI_NR_sequence_of[1] = {
  { &hf_ngap_CancelledCellsInTAI_NR_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ngap_CancelledCellsInTAI_NR_Item },
};

static int
dissect_ngap_CancelledCellsInTAI_NR(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_ngap_CancelledCellsInTAI_NR, CancelledCellsInTAI_NR_sequence_of,
                                                  1, maxnoofCellinTAI, FALSE);

  return offset;
}


static const per_sequence_t TAICancelledNR_Item_sequence[] = {
  { &hf_ngap_tAI            , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ngap_TAI },
  { &hf_ngap_cancelledCellsInTAI_NR, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ngap_CancelledCellsInTAI_NR },
  { &hf_ngap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ngap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_ngap_TAICancelledNR_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ngap_TAICancelledNR_Item, TAICancelledNR_Item_sequence);

  return offset;
}


static const per_sequence_t TAICancelledNR_sequence_of[1] = {
  { &hf_ngap_TAICancelledNR_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ngap_TAICancelledNR_Item },
};

static int
dissect_ngap_TAICancelledNR(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_ngap_TAICancelledNR, TAICancelledNR_sequence_of,
                                                  1, maxnoofTAIforWarning, FALSE);

  return offset;
}


static const per_sequence_t CancelledCellsInEAI_NR_Item_sequence[] = {
  { &hf_ngap_nR_CGI         , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ngap_NR_CGI },
  { &hf_ngap_numberOfBroadcasts, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ngap_NumberOfBroadcasts },
  { &hf_ngap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ngap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_ngap_CancelledCellsInEAI_NR_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ngap_CancelledCellsInEAI_NR_Item, CancelledCellsInEAI_NR_Item_sequence);

  return offset;
}


static const per_sequence_t CancelledCellsInEAI_NR_sequence_of[1] = {
  { &hf_ngap_CancelledCellsInEAI_NR_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ngap_CancelledCellsInEAI_NR_Item },
};

static int
dissect_ngap_CancelledCellsInEAI_NR(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_ngap_CancelledCellsInEAI_NR, CancelledCellsInEAI_NR_sequence_of,
                                                  1, maxnoofCellinEAI, FALSE);

  return offset;
}


static const per_sequence_t EmergencyAreaIDCancelledNR_Item_sequence[] = {
  { &hf_ngap_emergencyAreaID, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ngap_EmergencyAreaID },
  { &hf_ngap_cancelledCellsInEAI_NR, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ngap_CancelledCellsInEAI_NR },
  { &hf_ngap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ngap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_ngap_EmergencyAreaIDCancelledNR_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ngap_EmergencyAreaIDCancelledNR_Item, EmergencyAreaIDCancelledNR_Item_sequence);

  return offset;
}


static const per_sequence_t EmergencyAreaIDCancelledNR_sequence_of[1] = {
  { &hf_ngap_EmergencyAreaIDCancelledNR_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ngap_EmergencyAreaIDCancelledNR_Item },
};

static int
dissect_ngap_EmergencyAreaIDCancelledNR(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_ngap_EmergencyAreaIDCancelledNR, EmergencyAreaIDCancelledNR_sequence_of,
                                                  1, maxnoofEmergencyAreaID, FALSE);

  return offset;
}


static const value_string ngap_BroadcastCancelledAreaList_vals[] = {
  {   0, "cellIDCancelledEUTRA" },
  {   1, "tAICancelledEUTRA" },
  {   2, "emergencyAreaIDCancelledEUTRA" },
  {   3, "cellIDCancelledNR" },
  {   4, "tAICancelledNR" },
  {   5, "emergencyAreaIDCancelledNR" },
  {   6, "choice-Extensions" },
  { 0, NULL }
};

static const per_choice_t BroadcastCancelledAreaList_choice[] = {
  {   0, &hf_ngap_cellIDCancelledEUTRA, ASN1_NO_EXTENSIONS     , dissect_ngap_CellIDCancelledEUTRA },
  {   1, &hf_ngap_tAICancelledEUTRA, ASN1_NO_EXTENSIONS     , dissect_ngap_TAICancelledEUTRA },
  {   2, &hf_ngap_emergencyAreaIDCancelledEUTRA, ASN1_NO_EXTENSIONS     , dissect_ngap_EmergencyAreaIDCancelledEUTRA },
  {   3, &hf_ngap_cellIDCancelledNR, ASN1_NO_EXTENSIONS     , dissect_ngap_CellIDCancelledNR },
  {   4, &hf_ngap_tAICancelledNR , ASN1_NO_EXTENSIONS     , dissect_ngap_TAICancelledNR },
  {   5, &hf_ngap_emergencyAreaIDCancelledNR, ASN1_NO_EXTENSIONS     , dissect_ngap_EmergencyAreaIDCancelledNR },
  {   6, &hf_ngap_choice_Extensions, ASN1_NO_EXTENSIONS     , dissect_ngap_ProtocolIE_SingleContainer },
  { 0, NULL, 0, NULL }
};

static int
dissect_ngap_BroadcastCancelledAreaList(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_ngap_BroadcastCancelledAreaList, BroadcastCancelledAreaList_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t CellIDBroadcastEUTRA_Item_sequence[] = {
  { &hf_ngap_eUTRA_CGI      , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ngap_EUTRA_CGI },
  { &hf_ngap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ngap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_ngap_CellIDBroadcastEUTRA_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ngap_CellIDBroadcastEUTRA_Item, CellIDBroadcastEUTRA_Item_sequence);

  return offset;
}


static const per_sequence_t CellIDBroadcastEUTRA_sequence_of[1] = {
  { &hf_ngap_CellIDBroadcastEUTRA_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ngap_CellIDBroadcastEUTRA_Item },
};

static int
dissect_ngap_CellIDBroadcastEUTRA(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_ngap_CellIDBroadcastEUTRA, CellIDBroadcastEUTRA_sequence_of,
                                                  1, maxnoofCellIDforWarning, FALSE);

  return offset;
}


static const per_sequence_t CompletedCellsInTAI_EUTRA_Item_sequence[] = {
  { &hf_ngap_eUTRA_CGI      , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ngap_EUTRA_CGI },
  { &hf_ngap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ngap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_ngap_CompletedCellsInTAI_EUTRA_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ngap_CompletedCellsInTAI_EUTRA_Item, CompletedCellsInTAI_EUTRA_Item_sequence);

  return offset;
}


static const per_sequence_t CompletedCellsInTAI_EUTRA_sequence_of[1] = {
  { &hf_ngap_CompletedCellsInTAI_EUTRA_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ngap_CompletedCellsInTAI_EUTRA_Item },
};

static int
dissect_ngap_CompletedCellsInTAI_EUTRA(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_ngap_CompletedCellsInTAI_EUTRA, CompletedCellsInTAI_EUTRA_sequence_of,
                                                  1, maxnoofCellinTAI, FALSE);

  return offset;
}


static const per_sequence_t TAIBroadcastEUTRA_Item_sequence[] = {
  { &hf_ngap_tAI            , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ngap_TAI },
  { &hf_ngap_completedCellsInTAI_EUTRA, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ngap_CompletedCellsInTAI_EUTRA },
  { &hf_ngap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ngap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_ngap_TAIBroadcastEUTRA_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ngap_TAIBroadcastEUTRA_Item, TAIBroadcastEUTRA_Item_sequence);

  return offset;
}


static const per_sequence_t TAIBroadcastEUTRA_sequence_of[1] = {
  { &hf_ngap_TAIBroadcastEUTRA_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ngap_TAIBroadcastEUTRA_Item },
};

static int
dissect_ngap_TAIBroadcastEUTRA(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_ngap_TAIBroadcastEUTRA, TAIBroadcastEUTRA_sequence_of,
                                                  1, maxnoofTAIforWarning, FALSE);

  return offset;
}


static const per_sequence_t CompletedCellsInEAI_EUTRA_Item_sequence[] = {
  { &hf_ngap_eUTRA_CGI      , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ngap_EUTRA_CGI },
  { &hf_ngap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ngap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_ngap_CompletedCellsInEAI_EUTRA_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ngap_CompletedCellsInEAI_EUTRA_Item, CompletedCellsInEAI_EUTRA_Item_sequence);

  return offset;
}


static const per_sequence_t CompletedCellsInEAI_EUTRA_sequence_of[1] = {
  { &hf_ngap_CompletedCellsInEAI_EUTRA_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ngap_CompletedCellsInEAI_EUTRA_Item },
};

static int
dissect_ngap_CompletedCellsInEAI_EUTRA(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_ngap_CompletedCellsInEAI_EUTRA, CompletedCellsInEAI_EUTRA_sequence_of,
                                                  1, maxnoofCellinEAI, FALSE);

  return offset;
}


static const per_sequence_t EmergencyAreaIDBroadcastEUTRA_Item_sequence[] = {
  { &hf_ngap_emergencyAreaID, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ngap_EmergencyAreaID },
  { &hf_ngap_completedCellsInEAI_EUTRA, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ngap_CompletedCellsInEAI_EUTRA },
  { &hf_ngap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ngap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_ngap_EmergencyAreaIDBroadcastEUTRA_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ngap_EmergencyAreaIDBroadcastEUTRA_Item, EmergencyAreaIDBroadcastEUTRA_Item_sequence);

  return offset;
}


static const per_sequence_t EmergencyAreaIDBroadcastEUTRA_sequence_of[1] = {
  { &hf_ngap_EmergencyAreaIDBroadcastEUTRA_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ngap_EmergencyAreaIDBroadcastEUTRA_Item },
};

static int
dissect_ngap_EmergencyAreaIDBroadcastEUTRA(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_ngap_EmergencyAreaIDBroadcastEUTRA, EmergencyAreaIDBroadcastEUTRA_sequence_of,
                                                  1, maxnoofEmergencyAreaID, FALSE);

  return offset;
}


static const per_sequence_t CellIDBroadcastNR_Item_sequence[] = {
  { &hf_ngap_nR_CGI         , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ngap_NR_CGI },
  { &hf_ngap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ngap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_ngap_CellIDBroadcastNR_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ngap_CellIDBroadcastNR_Item, CellIDBroadcastNR_Item_sequence);

  return offset;
}


static const per_sequence_t CellIDBroadcastNR_sequence_of[1] = {
  { &hf_ngap_CellIDBroadcastNR_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ngap_CellIDBroadcastNR_Item },
};

static int
dissect_ngap_CellIDBroadcastNR(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_ngap_CellIDBroadcastNR, CellIDBroadcastNR_sequence_of,
                                                  1, maxnoofCellIDforWarning, FALSE);

  return offset;
}


static const per_sequence_t CompletedCellsInTAI_NR_Item_sequence[] = {
  { &hf_ngap_nR_CGI         , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ngap_NR_CGI },
  { &hf_ngap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ngap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_ngap_CompletedCellsInTAI_NR_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ngap_CompletedCellsInTAI_NR_Item, CompletedCellsInTAI_NR_Item_sequence);

  return offset;
}


static const per_sequence_t CompletedCellsInTAI_NR_sequence_of[1] = {
  { &hf_ngap_CompletedCellsInTAI_NR_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ngap_CompletedCellsInTAI_NR_Item },
};

static int
dissect_ngap_CompletedCellsInTAI_NR(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_ngap_CompletedCellsInTAI_NR, CompletedCellsInTAI_NR_sequence_of,
                                                  1, maxnoofCellinTAI, FALSE);

  return offset;
}


static const per_sequence_t TAIBroadcastNR_Item_sequence[] = {
  { &hf_ngap_tAI            , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ngap_TAI },
  { &hf_ngap_completedCellsInTAI_NR, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ngap_CompletedCellsInTAI_NR },
  { &hf_ngap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ngap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_ngap_TAIBroadcastNR_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ngap_TAIBroadcastNR_Item, TAIBroadcastNR_Item_sequence);

  return offset;
}


static const per_sequence_t TAIBroadcastNR_sequence_of[1] = {
  { &hf_ngap_TAIBroadcastNR_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ngap_TAIBroadcastNR_Item },
};

static int
dissect_ngap_TAIBroadcastNR(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_ngap_TAIBroadcastNR, TAIBroadcastNR_sequence_of,
                                                  1, maxnoofTAIforWarning, FALSE);

  return offset;
}


static const per_sequence_t CompletedCellsInEAI_NR_Item_sequence[] = {
  { &hf_ngap_nR_CGI         , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ngap_NR_CGI },
  { &hf_ngap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ngap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_ngap_CompletedCellsInEAI_NR_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ngap_CompletedCellsInEAI_NR_Item, CompletedCellsInEAI_NR_Item_sequence);

  return offset;
}


static const per_sequence_t CompletedCellsInEAI_NR_sequence_of[1] = {
  { &hf_ngap_CompletedCellsInEAI_NR_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ngap_CompletedCellsInEAI_NR_Item },
};

static int
dissect_ngap_CompletedCellsInEAI_NR(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_ngap_CompletedCellsInEAI_NR, CompletedCellsInEAI_NR_sequence_of,
                                                  1, maxnoofCellinEAI, FALSE);

  return offset;
}


static const per_sequence_t EmergencyAreaIDBroadcastNR_Item_sequence[] = {
  { &hf_ngap_emergencyAreaID, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ngap_EmergencyAreaID },
  { &hf_ngap_completedCellsInEAI_NR, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ngap_CompletedCellsInEAI_NR },
  { &hf_ngap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ngap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_ngap_EmergencyAreaIDBroadcastNR_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ngap_EmergencyAreaIDBroadcastNR_Item, EmergencyAreaIDBroadcastNR_Item_sequence);

  return offset;
}


static const per_sequence_t EmergencyAreaIDBroadcastNR_sequence_of[1] = {
  { &hf_ngap_EmergencyAreaIDBroadcastNR_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ngap_EmergencyAreaIDBroadcastNR_Item },
};

static int
dissect_ngap_EmergencyAreaIDBroadcastNR(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_ngap_EmergencyAreaIDBroadcastNR, EmergencyAreaIDBroadcastNR_sequence_of,
                                                  1, maxnoofEmergencyAreaID, FALSE);

  return offset;
}


static const value_string ngap_BroadcastCompletedAreaList_vals[] = {
  {   0, "cellIDBroadcastEUTRA" },
  {   1, "tAIBroadcastEUTRA" },
  {   2, "emergencyAreaIDBroadcastEUTRA" },
  {   3, "cellIDBroadcastNR" },
  {   4, "tAIBroadcastNR" },
  {   5, "emergencyAreaIDBroadcastNR" },
  {   6, "choice-Extensions" },
  { 0, NULL }
};

static const per_choice_t BroadcastCompletedAreaList_choice[] = {
  {   0, &hf_ngap_cellIDBroadcastEUTRA, ASN1_NO_EXTENSIONS     , dissect_ngap_CellIDBroadcastEUTRA },
  {   1, &hf_ngap_tAIBroadcastEUTRA, ASN1_NO_EXTENSIONS     , dissect_ngap_TAIBroadcastEUTRA },
  {   2, &hf_ngap_emergencyAreaIDBroadcastEUTRA, ASN1_NO_EXTENSIONS     , dissect_ngap_EmergencyAreaIDBroadcastEUTRA },
  {   3, &hf_ngap_cellIDBroadcastNR, ASN1_NO_EXTENSIONS     , dissect_ngap_CellIDBroadcastNR },
  {   4, &hf_ngap_tAIBroadcastNR , ASN1_NO_EXTENSIONS     , dissect_ngap_TAIBroadcastNR },
  {   5, &hf_ngap_emergencyAreaIDBroadcastNR, ASN1_NO_EXTENSIONS     , dissect_ngap_EmergencyAreaIDBroadcastNR },
  {   6, &hf_ngap_choice_Extensions, ASN1_NO_EXTENSIONS     , dissect_ngap_ProtocolIE_SingleContainer },
  { 0, NULL, 0, NULL }
};

static int
dissect_ngap_BroadcastCompletedAreaList(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_ngap_BroadcastCompletedAreaList, BroadcastCompletedAreaList_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t SliceSupportItem_sequence[] = {
  { &hf_ngap_s_NSSAI        , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ngap_S_NSSAI },
  { &hf_ngap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ngap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_ngap_SliceSupportItem(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ngap_SliceSupportItem, SliceSupportItem_sequence);

  return offset;
}


static const per_sequence_t SliceSupportList_sequence_of[1] = {
  { &hf_ngap_SliceSupportList_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ngap_SliceSupportItem },
};

static int
dissect_ngap_SliceSupportList(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_ngap_SliceSupportList, SliceSupportList_sequence_of,
                                                  1, maxnoofSliceItems, FALSE);

  return offset;
}


static const per_sequence_t BroadcastPLMNItem_sequence[] = {
  { &hf_ngap_pLMNIdentity   , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ngap_PLMNIdentity },
  { &hf_ngap_tAISliceSupportList, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ngap_SliceSupportList },
  { &hf_ngap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ngap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_ngap_BroadcastPLMNItem(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ngap_BroadcastPLMNItem, BroadcastPLMNItem_sequence);

  return offset;
}


static const per_sequence_t BroadcastPLMNList_sequence_of[1] = {
  { &hf_ngap_BroadcastPLMNList_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ngap_BroadcastPLMNItem },
};

static int
dissect_ngap_BroadcastPLMNList(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_ngap_BroadcastPLMNList, BroadcastPLMNList_sequence_of,
                                                  1, maxnoofBPLMNs, FALSE);

  return offset;
}


static const value_string ngap_CancelAllWarningMessages_vals[] = {
  {   0, "true" },
  { 0, NULL }
};


static int
dissect_ngap_CancelAllWarningMessages(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     1, NULL, TRUE, 0, NULL);

  return offset;
}


static const value_string ngap_CauseRadioNetwork_vals[] = {
  {   0, "unspecified" },
  {   1, "txnrelocoverall-expiry" },
  {   2, "successful-handover" },
  {   3, "release-due-to-ngran-generated-reason" },
  {   4, "release-due-to-5gc-generated-reason" },
  {   5, "handover-cancelled" },
  {   6, "partial-handover" },
  {   7, "ho-failure-in-target-5GC-ngran-node-or-target-system" },
  {   8, "ho-target-not-allowed" },
  {   9, "tngrelocoverall-expiry" },
  {  10, "tngrelocprep-expiry" },
  {  11, "cell-not-available" },
  {  12, "unknown-targetID" },
  {  13, "no-radio-resources-available-in-target-cell" },
  {  14, "unknown-local-UE-NGAP-ID" },
  {  15, "inconsistent-remote-UE-NGAP-ID" },
  {  16, "handover-desirable-for-radio-reason" },
  {  17, "time-critical-handover" },
  {  18, "resource-optimisation-handover" },
  {  19, "reduce-load-in-serving-cell" },
  {  20, "user-inactivity" },
  {  21, "radio-connection-with-ue-lost" },
  {  22, "radio-resources-not-available" },
  {  23, "invalid-qos-combination" },
  {  24, "failure-in-radio-interface-procedure" },
  {  25, "interaction-with-other-procedure" },
  {  26, "unknown-PDU-session-ID" },
  {  27, "unkown-qos-flow-ID" },
  {  28, "multiple-PDU-session-ID-instances" },
  {  29, "multiple-qos-flow-ID-instances" },
  {  30, "encryption-and-or-integrity-protection-algorithms-not-supported" },
  {  31, "ng-intra-system-handover-triggered" },
  {  32, "ng-inter-system-handover-triggered" },
  {  33, "xn-handover-triggered" },
  {  34, "not-supported-5QI-value" },
  {  35, "ue-context-transfer" },
  {  36, "ims-voice-eps-fallback-or-rat-fallback-triggered" },
  {  37, "up-integrity-protection-not-possible" },
  {  38, "up-confidentiality-protection-not-possible" },
  {  39, "slice-not-supported" },
  {  40, "ue-in-rrc-inactive-state-not-reachable" },
  {  41, "redirection" },
  {  42, "resources-not-available-for-the-slice" },
  {  43, "ue-max-integrity-protected-data-rate-reason" },
  {  44, "release-due-to-cn-detected-mobility" },
  {  45, "n26-interface-not-available" },
  {  46, "release-due-to-pre-emption" },
  {  47, "multiple-location-reporting-reference-ID-instances" },
  { 0, NULL }
};

static value_string_ext ngap_CauseRadioNetwork_vals_ext = VALUE_STRING_EXT_INIT(ngap_CauseRadioNetwork_vals);


static int
dissect_ngap_CauseRadioNetwork(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     45, NULL, TRUE, 3, NULL);

  return offset;
}


static const value_string ngap_CauseTransport_vals[] = {
  {   0, "transport-resource-unavailable" },
  {   1, "unspecified" },
  { 0, NULL }
};


static int
dissect_ngap_CauseTransport(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     2, NULL, TRUE, 0, NULL);

  return offset;
}


static const value_string ngap_CauseNas_vals[] = {
  {   0, "normal-release" },
  {   1, "authentication-failure" },
  {   2, "deregister" },
  {   3, "unspecified" },
  { 0, NULL }
};


static int
dissect_ngap_CauseNas(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     4, NULL, TRUE, 0, NULL);

  return offset;
}


static const value_string ngap_CauseProtocol_vals[] = {
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
dissect_ngap_CauseProtocol(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     7, NULL, TRUE, 0, NULL);

  return offset;
}


static const value_string ngap_CauseMisc_vals[] = {
  {   0, "control-processing-overload" },
  {   1, "not-enough-user-plane-processing-resources" },
  {   2, "hardware-failure" },
  {   3, "om-intervention" },
  {   4, "unknown-PLMN" },
  {   5, "unspecified" },
  { 0, NULL }
};


static int
dissect_ngap_CauseMisc(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     6, NULL, TRUE, 0, NULL);

  return offset;
}


static const value_string ngap_Cause_vals[] = {
  {   0, "radioNetwork" },
  {   1, "transport" },
  {   2, "nas" },
  {   3, "protocol" },
  {   4, "misc" },
  {   5, "choice-Extensions" },
  { 0, NULL }
};

static const per_choice_t Cause_choice[] = {
  {   0, &hf_ngap_radioNetwork   , ASN1_NO_EXTENSIONS     , dissect_ngap_CauseRadioNetwork },
  {   1, &hf_ngap_transport      , ASN1_NO_EXTENSIONS     , dissect_ngap_CauseTransport },
  {   2, &hf_ngap_nas            , ASN1_NO_EXTENSIONS     , dissect_ngap_CauseNas },
  {   3, &hf_ngap_protocol       , ASN1_NO_EXTENSIONS     , dissect_ngap_CauseProtocol },
  {   4, &hf_ngap_misc           , ASN1_NO_EXTENSIONS     , dissect_ngap_CauseMisc },
  {   5, &hf_ngap_choice_Extensions, ASN1_NO_EXTENSIONS     , dissect_ngap_ProtocolIE_SingleContainer },
  { 0, NULL, 0, NULL }
};

static int
dissect_ngap_Cause(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_ngap_Cause, Cause_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t EUTRA_CGIList_sequence_of[1] = {
  { &hf_ngap_EUTRA_CGIList_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ngap_EUTRA_CGI },
};

static int
dissect_ngap_EUTRA_CGIList(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_ngap_EUTRA_CGIList, EUTRA_CGIList_sequence_of,
                                                  1, maxnoofCellsinngeNB, FALSE);

  return offset;
}


static const per_sequence_t NR_CGIList_sequence_of[1] = {
  { &hf_ngap_NR_CGIList_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ngap_NR_CGI },
};

static int
dissect_ngap_NR_CGIList(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_ngap_NR_CGIList, NR_CGIList_sequence_of,
                                                  1, maxnoofCellsingNB, FALSE);

  return offset;
}


static const value_string ngap_CellIDListForRestart_vals[] = {
  {   0, "eUTRA-CGIListforRestart" },
  {   1, "nR-CGIListforRestart" },
  {   2, "choice-Extensions" },
  { 0, NULL }
};

static const per_choice_t CellIDListForRestart_choice[] = {
  {   0, &hf_ngap_eUTRA_CGIListforRestart, ASN1_NO_EXTENSIONS     , dissect_ngap_EUTRA_CGIList },
  {   1, &hf_ngap_nR_CGIListforRestart, ASN1_NO_EXTENSIONS     , dissect_ngap_NR_CGIList },
  {   2, &hf_ngap_choice_Extensions, ASN1_NO_EXTENSIONS     , dissect_ngap_ProtocolIE_SingleContainer },
  { 0, NULL, 0, NULL }
};

static int
dissect_ngap_CellIDListForRestart(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_ngap_CellIDListForRestart, CellIDListForRestart_choice,
                                 NULL);

  return offset;
}


static const value_string ngap_CellSize_vals[] = {
  {   0, "verysmall" },
  {   1, "small" },
  {   2, "medium" },
  {   3, "large" },
  { 0, NULL }
};


static int
dissect_ngap_CellSize(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     4, NULL, TRUE, 0, NULL);

  return offset;
}


static const per_sequence_t CellType_sequence[] = {
  { &hf_ngap_cellSize       , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ngap_CellSize },
  { &hf_ngap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ngap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_ngap_CellType(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ngap_CellType, CellType_sequence);

  return offset;
}



static int
dissect_ngap_ExpectedActivityPeriod(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            1U, 181U, NULL, TRUE);

  return offset;
}



static int
dissect_ngap_ExpectedIdlePeriod(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            1U, 181U, NULL, TRUE);

  return offset;
}


static const value_string ngap_SourceOfUEActivityBehaviourInformation_vals[] = {
  {   0, "subscription-information" },
  {   1, "statistics" },
  { 0, NULL }
};


static int
dissect_ngap_SourceOfUEActivityBehaviourInformation(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     2, NULL, TRUE, 0, NULL);

  return offset;
}


static const per_sequence_t ExpectedUEActivityBehaviour_sequence[] = {
  { &hf_ngap_expectedActivityPeriod, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ngap_ExpectedActivityPeriod },
  { &hf_ngap_expectedIdlePeriod, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ngap_ExpectedIdlePeriod },
  { &hf_ngap_sourceOfUEActivityBehaviourInformation, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ngap_SourceOfUEActivityBehaviourInformation },
  { &hf_ngap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ngap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_ngap_ExpectedUEActivityBehaviour(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ngap_ExpectedUEActivityBehaviour, ExpectedUEActivityBehaviour_sequence);

  return offset;
}


static const value_string ngap_ExpectedHOInterval_vals[] = {
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
dissect_ngap_ExpectedHOInterval(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     7, NULL, TRUE, 0, NULL);

  return offset;
}


static const value_string ngap_ExpectedUEMobility_vals[] = {
  {   0, "stationary" },
  {   1, "mobile" },
  { 0, NULL }
};


static int
dissect_ngap_ExpectedUEMobility(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     2, NULL, TRUE, 0, NULL);

  return offset;
}


static const per_sequence_t ExpectedUEMovingTrajectoryItem_sequence[] = {
  { &hf_ngap_nGRAN_CGI      , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ngap_NGRAN_CGI },
  { &hf_ngap_timeStayedInCell, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ngap_INTEGER_0_4095 },
  { &hf_ngap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ngap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_ngap_ExpectedUEMovingTrajectoryItem(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ngap_ExpectedUEMovingTrajectoryItem, ExpectedUEMovingTrajectoryItem_sequence);

  return offset;
}


static const per_sequence_t ExpectedUEMovingTrajectory_sequence_of[1] = {
  { &hf_ngap_ExpectedUEMovingTrajectory_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ngap_ExpectedUEMovingTrajectoryItem },
};

static int
dissect_ngap_ExpectedUEMovingTrajectory(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_ngap_ExpectedUEMovingTrajectory, ExpectedUEMovingTrajectory_sequence_of,
                                                  1, maxnoofCellsUEMovingTrajectory, FALSE);

  return offset;
}


static const per_sequence_t ExpectedUEBehaviour_sequence[] = {
  { &hf_ngap_expectedUEActivityBehaviour, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ngap_ExpectedUEActivityBehaviour },
  { &hf_ngap_expectedHOInterval, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ngap_ExpectedHOInterval },
  { &hf_ngap_expectedUEMobility, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ngap_ExpectedUEMobility },
  { &hf_ngap_expectedUEMovingTrajectory, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ngap_ExpectedUEMovingTrajectory },
  { &hf_ngap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ngap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_ngap_ExpectedUEBehaviour(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ngap_ExpectedUEBehaviour, ExpectedUEBehaviour_sequence);

  return offset;
}


static const per_sequence_t CNAssistedRANTuning_sequence[] = {
  { &hf_ngap_expectedUEBehaviour, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ngap_ExpectedUEBehaviour },
  { &hf_ngap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ngap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_ngap_CNAssistedRANTuning(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ngap_CNAssistedRANTuning, CNAssistedRANTuning_sequence);

  return offset;
}


static const value_string ngap_T_cn_Type_vals[] = {
  {   0, "epc-forbidden" },
  {   1, "fiveGC-forbidden" },
  { 0, NULL }
};


static int
dissect_ngap_T_cn_Type(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     2, NULL, TRUE, 0, NULL);

  return offset;
}


static const per_sequence_t CNTypeRestrictionsForEquivalentItem_sequence[] = {
  { &hf_ngap_plmnIdentity   , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ngap_PLMNIdentity },
  { &hf_ngap_cn_Type        , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ngap_T_cn_Type },
  { &hf_ngap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ngap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_ngap_CNTypeRestrictionsForEquivalentItem(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ngap_CNTypeRestrictionsForEquivalentItem, CNTypeRestrictionsForEquivalentItem_sequence);

  return offset;
}


static const per_sequence_t CNTypeRestrictionsForEquivalent_sequence_of[1] = {
  { &hf_ngap_CNTypeRestrictionsForEquivalent_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ngap_CNTypeRestrictionsForEquivalentItem },
};

static int
dissect_ngap_CNTypeRestrictionsForEquivalent(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_ngap_CNTypeRestrictionsForEquivalent, CNTypeRestrictionsForEquivalent_sequence_of,
                                                  1, maxnoofEPLMNs, FALSE);

  return offset;
}


static const value_string ngap_CNTypeRestrictionsForServing_vals[] = {
  {   0, "epc-forbidden" },
  { 0, NULL }
};


static int
dissect_ngap_CNTypeRestrictionsForServing(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     1, NULL, TRUE, 0, NULL);

  return offset;
}



static int
dissect_ngap_CommonNetworkInstance(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_octet_string(tvb, offset, actx, tree, hf_index,
                                       NO_BOUND, NO_BOUND, FALSE, NULL);

  return offset;
}


static const value_string ngap_ConcurrentWarningMessageInd_vals[] = {
  {   0, "true" },
  { 0, NULL }
};


static int
dissect_ngap_ConcurrentWarningMessageInd(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     1, NULL, TRUE, 0, NULL);

  return offset;
}


static const value_string ngap_ConfidentialityProtectionIndication_vals[] = {
  {   0, "required" },
  {   1, "preferred" },
  {   2, "not-needed" },
  { 0, NULL }
};


static int
dissect_ngap_ConfidentialityProtectionIndication(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     3, NULL, TRUE, 0, NULL);

  return offset;
}


static const value_string ngap_ConfidentialityProtectionResult_vals[] = {
  {   0, "performed" },
  {   1, "not-performed" },
  { 0, NULL }
};


static int
dissect_ngap_ConfidentialityProtectionResult(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     2, NULL, TRUE, 0, NULL);

  return offset;
}



static int
dissect_ngap_BIT_STRING_SIZE_10(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_bit_string(tvb, offset, actx, tree, hf_index,
                                     10, 10, FALSE, NULL, 0, NULL, NULL);

  return offset;
}


static const value_string ngap_UEIdentityIndexValue_vals[] = {
  {   0, "indexLength10" },
  {   1, "choice-Extensions" },
  { 0, NULL }
};

static const per_choice_t UEIdentityIndexValue_choice[] = {
  {   0, &hf_ngap_indexLength10  , ASN1_NO_EXTENSIONS     , dissect_ngap_BIT_STRING_SIZE_10 },
  {   1, &hf_ngap_choice_Extensions, ASN1_NO_EXTENSIONS     , dissect_ngap_ProtocolIE_SingleContainer },
  { 0, NULL, 0, NULL }
};

static int
dissect_ngap_UEIdentityIndexValue(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_ngap_UEIdentityIndexValue, UEIdentityIndexValue_choice,
                                 NULL);

  return offset;
}


static const value_string ngap_PagingDRX_vals[] = {
  {   0, "v32" },
  {   1, "v64" },
  {   2, "v128" },
  {   3, "v256" },
  { 0, NULL }
};


static int
dissect_ngap_PagingDRX(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     4, NULL, TRUE, 0, NULL);

  return offset;
}



static int
dissect_ngap_PeriodicRegistrationUpdateTimer(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 709 "./asn1/ngap/ngap.cnf"
  tvbuff_t *val_tvb = NULL;
  offset = dissect_per_bit_string(tvb, offset, actx, tree, -1,
                                     8, 8, FALSE, NULL, 0, &val_tvb, NULL);

  if (val_tvb) {
    guint32 val = tvb_get_guint8(val_tvb, 0);
    actx->created_item = proto_tree_add_uint(tree, hf_index, val_tvb, 0, 1, val);
  }



  return offset;
}


static const value_string ngap_MICOModeIndication_vals[] = {
  {   0, "true" },
  { 0, NULL }
};


static int
dissect_ngap_MICOModeIndication(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     1, NULL, TRUE, 0, NULL);

  return offset;
}


static const per_sequence_t TAIListForInactiveItem_sequence[] = {
  { &hf_ngap_tAI            , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ngap_TAI },
  { &hf_ngap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ngap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_ngap_TAIListForInactiveItem(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ngap_TAIListForInactiveItem, TAIListForInactiveItem_sequence);

  return offset;
}


static const per_sequence_t TAIListForInactive_sequence_of[1] = {
  { &hf_ngap_TAIListForInactive_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ngap_TAIListForInactiveItem },
};

static int
dissect_ngap_TAIListForInactive(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_ngap_TAIListForInactive, TAIListForInactive_sequence_of,
                                                  1, maxnoofTAIforInactive, FALSE);

  return offset;
}


static const per_sequence_t CoreNetworkAssistanceInformationForInactive_sequence[] = {
  { &hf_ngap_uEIdentityIndexValue, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ngap_UEIdentityIndexValue },
  { &hf_ngap_uESpecificDRX  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ngap_PagingDRX },
  { &hf_ngap_periodicRegistrationUpdateTimer, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ngap_PeriodicRegistrationUpdateTimer },
  { &hf_ngap_mICOModeIndication, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ngap_MICOModeIndication },
  { &hf_ngap_tAIListForInactive, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ngap_TAIListForInactive },
  { &hf_ngap_expectedUEBehaviour, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ngap_ExpectedUEBehaviour },
  { &hf_ngap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ngap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_ngap_CoreNetworkAssistanceInformationForInactive(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ngap_CoreNetworkAssistanceInformationForInactive, CoreNetworkAssistanceInformationForInactive_sequence);

  return offset;
}



static int
dissect_ngap_INTEGER_0_1048575(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 1048575U, NULL, FALSE);

  return offset;
}


static const per_sequence_t COUNTValueForPDCP_SN12_sequence[] = {
  { &hf_ngap_pDCP_SN12      , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ngap_INTEGER_0_4095 },
  { &hf_ngap_hFN_PDCP_SN12  , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ngap_INTEGER_0_1048575 },
  { &hf_ngap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ngap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_ngap_COUNTValueForPDCP_SN12(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ngap_COUNTValueForPDCP_SN12, COUNTValueForPDCP_SN12_sequence);

  return offset;
}



static int
dissect_ngap_INTEGER_0_262143(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 262143U, NULL, FALSE);

  return offset;
}



static int
dissect_ngap_INTEGER_0_16383(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 16383U, NULL, FALSE);

  return offset;
}


static const per_sequence_t COUNTValueForPDCP_SN18_sequence[] = {
  { &hf_ngap_pDCP_SN18      , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ngap_INTEGER_0_262143 },
  { &hf_ngap_hFN_PDCP_SN18  , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ngap_INTEGER_0_16383 },
  { &hf_ngap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ngap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_ngap_COUNTValueForPDCP_SN18(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ngap_COUNTValueForPDCP_SN18, COUNTValueForPDCP_SN18_sequence);

  return offset;
}


static const value_string ngap_TypeOfError_vals[] = {
  {   0, "not-understood" },
  {   1, "missing" },
  { 0, NULL }
};


static int
dissect_ngap_TypeOfError(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     2, NULL, TRUE, 0, NULL);

  return offset;
}


static const per_sequence_t CriticalityDiagnostics_IE_Item_sequence[] = {
  { &hf_ngap_iECriticality  , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ngap_Criticality },
  { &hf_ngap_iE_ID          , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ngap_ProtocolIE_ID },
  { &hf_ngap_typeOfError    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ngap_TypeOfError },
  { &hf_ngap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ngap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_ngap_CriticalityDiagnostics_IE_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ngap_CriticalityDiagnostics_IE_Item, CriticalityDiagnostics_IE_Item_sequence);

  return offset;
}


static const per_sequence_t CriticalityDiagnostics_IE_List_sequence_of[1] = {
  { &hf_ngap_CriticalityDiagnostics_IE_List_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ngap_CriticalityDiagnostics_IE_Item },
};

static int
dissect_ngap_CriticalityDiagnostics_IE_List(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_ngap_CriticalityDiagnostics_IE_List, CriticalityDiagnostics_IE_List_sequence_of,
                                                  1, maxnoofErrors, FALSE);

  return offset;
}


static const per_sequence_t CriticalityDiagnostics_sequence[] = {
  { &hf_ngap_procedureCode  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ngap_ProcedureCode },
  { &hf_ngap_triggeringMessage, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ngap_TriggeringMessage },
  { &hf_ngap_procedureCriticality, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ngap_Criticality },
  { &hf_ngap_iEsCriticalityDiagnostics, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ngap_CriticalityDiagnostics_IE_List },
  { &hf_ngap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ngap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_ngap_CriticalityDiagnostics(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ngap_CriticalityDiagnostics, CriticalityDiagnostics_sequence);

  return offset;
}



static int
dissect_ngap_DataCodingScheme(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 326 "./asn1/ngap/ngap.cnf"
  tvbuff_t *parameter_tvb = NULL;
  offset = dissect_per_bit_string(tvb, offset, actx, tree, hf_index,
                                     8, 8, FALSE, NULL, 0, &parameter_tvb, NULL);

  if (parameter_tvb) {
    struct ngap_private_data *ngap_data = ngap_get_private_data(actx->pinfo);
    proto_tree *subtree;

    subtree = proto_item_add_subtree(actx->created_item, ett_ngap_DataCodingScheme);
    ngap_data->data_coding_scheme = dissect_cbs_data_coding_scheme(parameter_tvb, actx->pinfo, subtree, 0);
  }



  return offset;
}


static const value_string ngap_DataForwardingNotPossible_vals[] = {
  {   0, "data-forwarding-not-possible" },
  { 0, NULL }
};


static int
dissect_ngap_DataForwardingNotPossible(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     1, NULL, TRUE, 0, NULL);

  return offset;
}



static int
dissect_ngap_DRB_ID(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            1U, 32U, NULL, TRUE);

  return offset;
}


static const per_sequence_t DataForwardingResponseDRBItem_sequence[] = {
  { &hf_ngap_dRB_ID         , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ngap_DRB_ID },
  { &hf_ngap_dLForwardingUP_TNLInformation, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ngap_UPTransportLayerInformation },
  { &hf_ngap_uLForwardingUP_TNLInformation, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ngap_UPTransportLayerInformation },
  { &hf_ngap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ngap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_ngap_DataForwardingResponseDRBItem(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ngap_DataForwardingResponseDRBItem, DataForwardingResponseDRBItem_sequence);

  return offset;
}


static const per_sequence_t DataForwardingResponseDRBList_sequence_of[1] = {
  { &hf_ngap_DataForwardingResponseDRBList_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ngap_DataForwardingResponseDRBItem },
};

static int
dissect_ngap_DataForwardingResponseDRBList(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_ngap_DataForwardingResponseDRBList, DataForwardingResponseDRBList_sequence_of,
                                                  1, maxnoofDRBs, FALSE);

  return offset;
}


static const value_string ngap_DelayCritical_vals[] = {
  {   0, "delay-critical" },
  {   1, "non-delay-critical" },
  { 0, NULL }
};


static int
dissect_ngap_DelayCritical(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     2, NULL, TRUE, 0, NULL);

  return offset;
}


static const value_string ngap_DLForwarding_vals[] = {
  {   0, "dl-forwarding-proposed" },
  { 0, NULL }
};


static int
dissect_ngap_DLForwarding(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     1, NULL, TRUE, 0, NULL);

  return offset;
}


static const value_string ngap_DL_NGU_TNLInformationReused_vals[] = {
  {   0, "true" },
  { 0, NULL }
};


static int
dissect_ngap_DL_NGU_TNLInformationReused(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     1, NULL, TRUE, 0, NULL);

  return offset;
}


static const value_string ngap_DirectForwardingPathAvailability_vals[] = {
  {   0, "direct-path-available" },
  { 0, NULL }
};


static int
dissect_ngap_DirectForwardingPathAvailability(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     1, NULL, TRUE, 0, NULL);

  return offset;
}



static int
dissect_ngap_BIT_STRING_SIZE_1_2048(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_bit_string(tvb, offset, actx, tree, hf_index,
                                     1, 2048, FALSE, NULL, 0, NULL, NULL);

  return offset;
}


static const per_sequence_t DRBStatusUL12_sequence[] = {
  { &hf_ngap_uL_COUNTValue  , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ngap_COUNTValueForPDCP_SN12 },
  { &hf_ngap_receiveStatusOfUL_PDCP_SDUs, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ngap_BIT_STRING_SIZE_1_2048 },
  { &hf_ngap_iE_Extension   , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ngap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_ngap_DRBStatusUL12(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ngap_DRBStatusUL12, DRBStatusUL12_sequence);

  return offset;
}



static int
dissect_ngap_BIT_STRING_SIZE_1_131072(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_bit_string(tvb, offset, actx, tree, hf_index,
                                     1, 131072, FALSE, NULL, 0, NULL, NULL);

  return offset;
}


static const per_sequence_t DRBStatusUL18_sequence[] = {
  { &hf_ngap_uL_COUNTValue_01, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ngap_COUNTValueForPDCP_SN18 },
  { &hf_ngap_receiveStatusOfUL_PDCP_SDUs_01, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ngap_BIT_STRING_SIZE_1_131072 },
  { &hf_ngap_iE_Extension   , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ngap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_ngap_DRBStatusUL18(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ngap_DRBStatusUL18, DRBStatusUL18_sequence);

  return offset;
}


static const value_string ngap_DRBStatusUL_vals[] = {
  {   0, "dRBStatusUL12" },
  {   1, "dRBStatusUL18" },
  {   2, "choice-Extensions" },
  { 0, NULL }
};

static const per_choice_t DRBStatusUL_choice[] = {
  {   0, &hf_ngap_dRBStatusUL12  , ASN1_NO_EXTENSIONS     , dissect_ngap_DRBStatusUL12 },
  {   1, &hf_ngap_dRBStatusUL18  , ASN1_NO_EXTENSIONS     , dissect_ngap_DRBStatusUL18 },
  {   2, &hf_ngap_choice_Extensions, ASN1_NO_EXTENSIONS     , dissect_ngap_ProtocolIE_SingleContainer },
  { 0, NULL, 0, NULL }
};

static int
dissect_ngap_DRBStatusUL(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_ngap_DRBStatusUL, DRBStatusUL_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t DRBStatusDL12_sequence[] = {
  { &hf_ngap_dL_COUNTValue  , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ngap_COUNTValueForPDCP_SN12 },
  { &hf_ngap_iE_Extension   , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ngap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_ngap_DRBStatusDL12(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ngap_DRBStatusDL12, DRBStatusDL12_sequence);

  return offset;
}


static const per_sequence_t DRBStatusDL18_sequence[] = {
  { &hf_ngap_dL_COUNTValue_01, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ngap_COUNTValueForPDCP_SN18 },
  { &hf_ngap_iE_Extension   , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ngap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_ngap_DRBStatusDL18(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ngap_DRBStatusDL18, DRBStatusDL18_sequence);

  return offset;
}


static const value_string ngap_DRBStatusDL_vals[] = {
  {   0, "dRBStatusDL12" },
  {   1, "dRBStatusDL18" },
  {   2, "choice-Extensions" },
  { 0, NULL }
};

static const per_choice_t DRBStatusDL_choice[] = {
  {   0, &hf_ngap_dRBStatusDL12  , ASN1_NO_EXTENSIONS     , dissect_ngap_DRBStatusDL12 },
  {   1, &hf_ngap_dRBStatusDL18  , ASN1_NO_EXTENSIONS     , dissect_ngap_DRBStatusDL18 },
  {   2, &hf_ngap_choice_Extensions, ASN1_NO_EXTENSIONS     , dissect_ngap_ProtocolIE_SingleContainer },
  { 0, NULL, 0, NULL }
};

static int
dissect_ngap_DRBStatusDL(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_ngap_DRBStatusDL, DRBStatusDL_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t DRBsSubjectToStatusTransferItem_sequence[] = {
  { &hf_ngap_dRB_ID         , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ngap_DRB_ID },
  { &hf_ngap_dRBStatusUL    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ngap_DRBStatusUL },
  { &hf_ngap_dRBStatusDL    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ngap_DRBStatusDL },
  { &hf_ngap_iE_Extension   , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ngap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_ngap_DRBsSubjectToStatusTransferItem(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ngap_DRBsSubjectToStatusTransferItem, DRBsSubjectToStatusTransferItem_sequence);

  return offset;
}


static const per_sequence_t DRBsSubjectToStatusTransferList_sequence_of[1] = {
  { &hf_ngap_DRBsSubjectToStatusTransferList_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ngap_DRBsSubjectToStatusTransferItem },
};

static int
dissect_ngap_DRBsSubjectToStatusTransferList(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_ngap_DRBsSubjectToStatusTransferList, DRBsSubjectToStatusTransferList_sequence_of,
                                                  1, maxnoofDRBs, FALSE);

  return offset;
}


static const per_sequence_t DRBsToQosFlowsMappingItem_sequence[] = {
  { &hf_ngap_dRB_ID         , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ngap_DRB_ID },
  { &hf_ngap_associatedQosFlowList, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ngap_AssociatedQosFlowList },
  { &hf_ngap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ngap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_ngap_DRBsToQosFlowsMappingItem(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ngap_DRBsToQosFlowsMappingItem, DRBsToQosFlowsMappingItem_sequence);

  return offset;
}


static const per_sequence_t DRBsToQosFlowsMappingList_sequence_of[1] = {
  { &hf_ngap_DRBsToQosFlowsMappingList_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ngap_DRBsToQosFlowsMappingItem },
};

static int
dissect_ngap_DRBsToQosFlowsMappingList(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_ngap_DRBsToQosFlowsMappingList, DRBsToQosFlowsMappingList_sequence_of,
                                                  1, maxnoofDRBs, FALSE);

  return offset;
}



static int
dissect_ngap_PriorityLevelQos(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            1U, 127U, NULL, TRUE);

  return offset;
}



static int
dissect_ngap_PacketDelayBudget(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 1023U, NULL, TRUE);

  return offset;
}



static int
dissect_ngap_INTEGER_0_9_(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 9U, NULL, TRUE);

  return offset;
}


static const per_sequence_t PacketErrorRate_sequence[] = {
  { &hf_ngap_pERScalar      , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ngap_INTEGER_0_9_ },
  { &hf_ngap_pERExponent    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ngap_INTEGER_0_9_ },
  { &hf_ngap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ngap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_ngap_PacketErrorRate(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ngap_PacketErrorRate, PacketErrorRate_sequence);

  return offset;
}



static int
dissect_ngap_FiveQI(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 255U, NULL, TRUE);

  return offset;
}



static int
dissect_ngap_MaximumDataBurstVolume(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 4095U, NULL, TRUE);

  return offset;
}


static const per_sequence_t Dynamic5QIDescriptor_sequence[] = {
  { &hf_ngap_priorityLevelQos, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ngap_PriorityLevelQos },
  { &hf_ngap_packetDelayBudget, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ngap_PacketDelayBudget },
  { &hf_ngap_packetErrorRate, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ngap_PacketErrorRate },
  { &hf_ngap_fiveQI         , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ngap_FiveQI },
  { &hf_ngap_delayCritical  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ngap_DelayCritical },
  { &hf_ngap_averagingWindow, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ngap_AveragingWindow },
  { &hf_ngap_maximumDataBurstVolume, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ngap_MaximumDataBurstVolume },
  { &hf_ngap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ngap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_ngap_Dynamic5QIDescriptor(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ngap_Dynamic5QIDescriptor, Dynamic5QIDescriptor_sequence);

  return offset;
}


static const per_sequence_t EmergencyAreaIDList_sequence_of[1] = {
  { &hf_ngap_EmergencyAreaIDList_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ngap_EmergencyAreaID },
};

static int
dissect_ngap_EmergencyAreaIDList(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_ngap_EmergencyAreaIDList, EmergencyAreaIDList_sequence_of,
                                                  1, maxnoofEmergencyAreaID, FALSE);

  return offset;
}


static const per_sequence_t EmergencyAreaIDListForRestart_sequence_of[1] = {
  { &hf_ngap_EmergencyAreaIDListForRestart_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ngap_EmergencyAreaID },
};

static int
dissect_ngap_EmergencyAreaIDListForRestart(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_ngap_EmergencyAreaIDListForRestart, EmergencyAreaIDListForRestart_sequence_of,
                                                  1, maxnoofEAIforRestart, FALSE);

  return offset;
}


static const value_string ngap_EmergencyFallbackRequestIndicator_vals[] = {
  {   0, "emergency-fallback-requested" },
  { 0, NULL }
};


static int
dissect_ngap_EmergencyFallbackRequestIndicator(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     1, NULL, TRUE, 0, NULL);

  return offset;
}


static const value_string ngap_EmergencyServiceTargetCN_vals[] = {
  {   0, "fiveGC" },
  {   1, "epc" },
  { 0, NULL }
};


static int
dissect_ngap_EmergencyServiceTargetCN(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     2, NULL, TRUE, 0, NULL);

  return offset;
}


static const per_sequence_t EmergencyFallbackIndicator_sequence[] = {
  { &hf_ngap_emergencyFallbackRequestIndicator, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ngap_EmergencyFallbackRequestIndicator },
  { &hf_ngap_emergencyServiceTargetCN, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ngap_EmergencyServiceTargetCN },
  { &hf_ngap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ngap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_ngap_EmergencyFallbackIndicator(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ngap_EmergencyFallbackIndicator, EmergencyFallbackIndicator_sequence);

  return offset;
}



static int
dissect_ngap_EN_DCSONConfigurationTransfer(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 731 "./asn1/ngap/ngap.cnf"
  tvbuff_t *parameter_tvb = NULL;
  proto_tree *subtree;
  offset = dissect_per_octet_string(tvb, offset, actx, tree, hf_index,
                                       NO_BOUND, NO_BOUND, FALSE, &parameter_tvb);

  if (parameter_tvb) {
    subtree = proto_item_add_subtree(actx->created_item, ett_ngap_EN_DCSONConfigurationTransfer);
    dissect_s1ap_EN_DCSONConfigurationTransfer_PDU(parameter_tvb, actx->pinfo, subtree, NULL);
  }



  return offset;
}



static int
dissect_ngap_PortNumber(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 476 "./asn1/ngap/ngap.cnf"
  tvbuff_t *parameter_tvb = NULL;
  offset = dissect_per_octet_string(tvb, offset, actx, tree, -1,
                                       2, 2, FALSE, &parameter_tvb);

  if (parameter_tvb) {
    actx->created_item = proto_tree_add_item(tree, hf_index, parameter_tvb, 0, 2, ENC_BIG_ENDIAN);
  }



  return offset;
}


static const per_sequence_t EndpointIPAddressAndPort_sequence[] = {
  { &hf_ngap_endpointIPAddress, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ngap_TransportLayerAddress },
  { &hf_ngap_portNumber     , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ngap_PortNumber },
  { &hf_ngap_iE_Extensions  , ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_ngap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_ngap_EndpointIPAddressAndPort(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ngap_EndpointIPAddressAndPort, EndpointIPAddressAndPort_sequence);

  return offset;
}


static const per_sequence_t EquivalentPLMNs_sequence_of[1] = {
  { &hf_ngap_EquivalentPLMNs_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ngap_PLMNIdentity },
};

static int
dissect_ngap_EquivalentPLMNs(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_ngap_EquivalentPLMNs, EquivalentPLMNs_sequence_of,
                                                  1, maxnoofEPLMNs, FALSE);

  return offset;
}



static int
dissect_ngap_EPS_TAC(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 349 "./asn1/ngap/ngap.cnf"
  tvbuff_t *parameter_tvb = NULL;
  offset = dissect_per_octet_string(tvb, offset, actx, tree, -1,
                                       2, 2, FALSE, &parameter_tvb);

  if (parameter_tvb) {
    actx->created_item = proto_tree_add_item(tree, hf_index, parameter_tvb, 0, 2, ENC_BIG_ENDIAN);
  }



  return offset;
}


static const per_sequence_t EPS_TAI_sequence[] = {
  { &hf_ngap_pLMNIdentity   , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ngap_PLMNIdentity },
  { &hf_ngap_ePS_TAC        , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ngap_EPS_TAC },
  { &hf_ngap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ngap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_ngap_EPS_TAI(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ngap_EPS_TAI, EPS_TAI_sequence);

  return offset;
}



static int
dissect_ngap_E_RAB_ID(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 15U, NULL, TRUE);

  return offset;
}


static const per_sequence_t E_RABInformationItem_sequence[] = {
  { &hf_ngap_e_RAB_ID       , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ngap_E_RAB_ID },
  { &hf_ngap_dLForwarding   , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ngap_DLForwarding },
  { &hf_ngap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ngap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_ngap_E_RABInformationItem(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ngap_E_RABInformationItem, E_RABInformationItem_sequence);

  return offset;
}


static const per_sequence_t E_RABInformationList_sequence_of[1] = {
  { &hf_ngap_E_RABInformationList_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ngap_E_RABInformationItem },
};

static int
dissect_ngap_E_RABInformationList(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_ngap_E_RABInformationList, E_RABInformationList_sequence_of,
                                                  1, maxnoofE_RABs, FALSE);

  return offset;
}


static const per_sequence_t EUTRA_CGIListForWarning_sequence_of[1] = {
  { &hf_ngap_EUTRA_CGIListForWarning_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ngap_EUTRA_CGI },
};

static int
dissect_ngap_EUTRA_CGIListForWarning(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_ngap_EUTRA_CGIListForWarning, EUTRA_CGIListForWarning_sequence_of,
                                                  1, maxnoofCellIDforWarning, FALSE);

  return offset;
}



static int
dissect_ngap_EUTRAencryptionAlgorithms(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 634 "./asn1/ngap/ngap.cnf"
  tvbuff_t *parameter_tvb = NULL;
  offset = dissect_per_bit_string(tvb, offset, actx, tree, hf_index,
                                     16, 16, TRUE, NULL, 0, &parameter_tvb, NULL);

  if (parameter_tvb) {
    static int * const fields[] = {
      &hf_ngap_EUTRAencryptionAlgorithms_eea1,
      &hf_ngap_EUTRAencryptionAlgorithms_eea2,
      &hf_ngap_EUTRAencryptionAlgorithms_eea3,
      &hf_ngap_EUTRAencryptionAlgorithms_reserved,
      NULL
    };
    proto_tree *subtree = proto_item_add_subtree(actx->created_item, ett_ngap_EUTRAencryptionAlgorithms);
    proto_tree_add_bitmask_list(subtree, parameter_tvb, 0, 2, fields, ENC_BIG_ENDIAN);
  }



  return offset;
}



static int
dissect_ngap_EUTRAintegrityProtectionAlgorithms(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 649 "./asn1/ngap/ngap.cnf"
  tvbuff_t *parameter_tvb = NULL;
  offset = dissect_per_bit_string(tvb, offset, actx, tree, hf_index,
                                     16, 16, TRUE, NULL, 0, &parameter_tvb, NULL);

  if (parameter_tvb) {
    static int * const fields[] = {
      &hf_ngap_EUTRAintegrityProtectionAlgorithms_eia1,
      &hf_ngap_EUTRAintegrityProtectionAlgorithms_eia2,
      &hf_ngap_EUTRAintegrityProtectionAlgorithms_eia3,
      &hf_ngap_EUTRAintegrityProtectionAlgorithms_reserved,
      NULL
    };
    proto_tree *subtree = proto_item_add_subtree(actx->created_item, ett_ngap_EUTRAintegrityProtectionAlgorithms);
    proto_tree_add_bitmask_list(subtree, parameter_tvb, 0, 2, fields, ENC_BIG_ENDIAN);
  }



  return offset;
}


static const value_string ngap_EventType_vals[] = {
  {   0, "direct" },
  {   1, "change-of-serve-cell" },
  {   2, "ue-presence-in-area-of-interest" },
  {   3, "stop-change-of-serve-cell" },
  {   4, "stop-ue-presence-in-area-of-interest" },
  {   5, "cancel-location-reporting-for-the-ue" },
  { 0, NULL }
};


static int
dissect_ngap_EventType(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     6, NULL, TRUE, 0, NULL);

  return offset;
}



static int
dissect_ngap_FiveG_TMSI(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_octet_string(tvb, offset, actx, tree, hf_index,
                                       4, 4, FALSE, NULL);

  return offset;
}


static const per_sequence_t FiveG_S_TMSI_sequence[] = {
  { &hf_ngap_aMFSetID       , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ngap_AMFSetID },
  { &hf_ngap_aMFPointer     , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ngap_AMFPointer },
  { &hf_ngap_fiveG_TMSI     , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ngap_FiveG_TMSI },
  { &hf_ngap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ngap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_ngap_FiveG_S_TMSI(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ngap_FiveG_S_TMSI, FiveG_S_TMSI_sequence);

  return offset;
}


static const per_sequence_t ForbiddenTACs_sequence_of[1] = {
  { &hf_ngap_ForbiddenTACs_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ngap_TAC },
};

static int
dissect_ngap_ForbiddenTACs(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_ngap_ForbiddenTACs, ForbiddenTACs_sequence_of,
                                                  1, maxnoofForbTACs, FALSE);

  return offset;
}


static const per_sequence_t ForbiddenAreaInformation_Item_sequence[] = {
  { &hf_ngap_pLMNIdentity   , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ngap_PLMNIdentity },
  { &hf_ngap_forbiddenTACs  , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ngap_ForbiddenTACs },
  { &hf_ngap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ngap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_ngap_ForbiddenAreaInformation_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ngap_ForbiddenAreaInformation_Item, ForbiddenAreaInformation_Item_sequence);

  return offset;
}


static const per_sequence_t ForbiddenAreaInformation_sequence_of[1] = {
  { &hf_ngap_ForbiddenAreaInformation_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ngap_ForbiddenAreaInformation_Item },
};

static int
dissect_ngap_ForbiddenAreaInformation(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_ngap_ForbiddenAreaInformation, ForbiddenAreaInformation_sequence_of,
                                                  1, maxnoofEPLMNsPlusOne, FALSE);

  return offset;
}


static const value_string ngap_NotificationControl_vals[] = {
  {   0, "notification-requested" },
  { 0, NULL }
};


static int
dissect_ngap_NotificationControl(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     1, NULL, TRUE, 0, NULL);

  return offset;
}



static int
dissect_ngap_PacketLossRate(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 1000U, NULL, TRUE);

  return offset;
}


static const per_sequence_t GBR_QosInformation_sequence[] = {
  { &hf_ngap_maximumFlowBitRateDL, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ngap_BitRate },
  { &hf_ngap_maximumFlowBitRateUL, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ngap_BitRate },
  { &hf_ngap_guaranteedFlowBitRateDL, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ngap_BitRate },
  { &hf_ngap_guaranteedFlowBitRateUL, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ngap_BitRate },
  { &hf_ngap_notificationControl, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ngap_NotificationControl },
  { &hf_ngap_maximumPacketLossRateDL, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ngap_PacketLossRate },
  { &hf_ngap_maximumPacketLossRateUL, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ngap_PacketLossRate },
  { &hf_ngap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ngap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_ngap_GBR_QosInformation(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ngap_GBR_QosInformation, GBR_QosInformation_sequence);

  return offset;
}


static const per_sequence_t GUAMI_sequence[] = {
  { &hf_ngap_pLMNIdentity   , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ngap_PLMNIdentity },
  { &hf_ngap_aMFRegionID    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ngap_AMFRegionID },
  { &hf_ngap_aMFSetID       , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ngap_AMFSetID },
  { &hf_ngap_aMFPointer     , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ngap_AMFPointer },
  { &hf_ngap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ngap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_ngap_GUAMI(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ngap_GUAMI, GUAMI_sequence);

  return offset;
}


static const per_sequence_t QosFlowToBeForwardedItem_sequence[] = {
  { &hf_ngap_qosFlowIdentifier, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ngap_QosFlowIdentifier },
  { &hf_ngap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ngap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_ngap_QosFlowToBeForwardedItem(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ngap_QosFlowToBeForwardedItem, QosFlowToBeForwardedItem_sequence);

  return offset;
}


static const per_sequence_t QosFlowToBeForwardedList_sequence_of[1] = {
  { &hf_ngap_QosFlowToBeForwardedList_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ngap_QosFlowToBeForwardedItem },
};

static int
dissect_ngap_QosFlowToBeForwardedList(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_ngap_QosFlowToBeForwardedList, QosFlowToBeForwardedList_sequence_of,
                                                  1, maxnoofQosFlows, FALSE);

  return offset;
}


static const per_sequence_t HandoverCommandTransfer_sequence[] = {
  { &hf_ngap_dLForwardingUP_TNLInformation, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ngap_UPTransportLayerInformation },
  { &hf_ngap_qosFlowToBeForwardedList, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ngap_QosFlowToBeForwardedList },
  { &hf_ngap_dataForwardingResponseDRBList, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ngap_DataForwardingResponseDRBList },
  { &hf_ngap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ngap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_ngap_HandoverCommandTransfer(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ngap_HandoverCommandTransfer, HandoverCommandTransfer_sequence);

  return offset;
}


static const value_string ngap_HandoverFlag_vals[] = {
  {   0, "handover-preparation" },
  { 0, NULL }
};


static int
dissect_ngap_HandoverFlag(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     1, NULL, TRUE, 0, NULL);

  return offset;
}


static const per_sequence_t HandoverPreparationUnsuccessfulTransfer_sequence[] = {
  { &hf_ngap_cause          , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ngap_Cause },
  { &hf_ngap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ngap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_ngap_HandoverPreparationUnsuccessfulTransfer(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ngap_HandoverPreparationUnsuccessfulTransfer, HandoverPreparationUnsuccessfulTransfer_sequence);

  return offset;
}


static const value_string ngap_IntegrityProtectionResult_vals[] = {
  {   0, "performed" },
  {   1, "not-performed" },
  { 0, NULL }
};


static int
dissect_ngap_IntegrityProtectionResult(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     2, NULL, TRUE, 0, NULL);

  return offset;
}


static const per_sequence_t SecurityResult_sequence[] = {
  { &hf_ngap_integrityProtectionResult, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ngap_IntegrityProtectionResult },
  { &hf_ngap_confidentialityProtectionResult, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ngap_ConfidentialityProtectionResult },
  { &hf_ngap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ngap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_ngap_SecurityResult(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ngap_SecurityResult, SecurityResult_sequence);

  return offset;
}


static const per_sequence_t QosFlowWithCauseItem_sequence[] = {
  { &hf_ngap_qosFlowIdentifier, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ngap_QosFlowIdentifier },
  { &hf_ngap_cause          , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ngap_Cause },
  { &hf_ngap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ngap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_ngap_QosFlowWithCauseItem(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ngap_QosFlowWithCauseItem, QosFlowWithCauseItem_sequence);

  return offset;
}


static const per_sequence_t QosFlowListWithCause_sequence_of[1] = {
  { &hf_ngap_QosFlowListWithCause_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ngap_QosFlowWithCauseItem },
};

static int
dissect_ngap_QosFlowListWithCause(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_ngap_QosFlowListWithCause, QosFlowListWithCause_sequence_of,
                                                  1, maxnoofQosFlows, FALSE);

  return offset;
}


static const per_sequence_t HandoverRequestAcknowledgeTransfer_sequence[] = {
  { &hf_ngap_dL_NGU_UP_TNLInformation, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ngap_UPTransportLayerInformation },
  { &hf_ngap_dLForwardingUP_TNLInformation, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ngap_UPTransportLayerInformation },
  { &hf_ngap_securityResult , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ngap_SecurityResult },
  { &hf_ngap_qosFlowSetupResponseList, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ngap_QosFlowListWithDataForwarding },
  { &hf_ngap_qosFlowFailedToSetupList, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ngap_QosFlowListWithCause },
  { &hf_ngap_dataForwardingResponseDRBList, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ngap_DataForwardingResponseDRBList },
  { &hf_ngap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ngap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_ngap_HandoverRequestAcknowledgeTransfer(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ngap_HandoverRequestAcknowledgeTransfer, HandoverRequestAcknowledgeTransfer_sequence);

  return offset;
}


static const per_sequence_t HandoverRequiredTransfer_sequence[] = {
  { &hf_ngap_directForwardingPathAvailability, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ngap_DirectForwardingPathAvailability },
  { &hf_ngap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ngap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_ngap_HandoverRequiredTransfer(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ngap_HandoverRequiredTransfer, HandoverRequiredTransfer_sequence);

  return offset;
}


static const per_sequence_t HandoverResourceAllocationUnsuccessfulTransfer_sequence[] = {
  { &hf_ngap_cause          , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ngap_Cause },
  { &hf_ngap_criticalityDiagnostics, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ngap_CriticalityDiagnostics },
  { &hf_ngap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ngap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_ngap_HandoverResourceAllocationUnsuccessfulTransfer(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ngap_HandoverResourceAllocationUnsuccessfulTransfer, HandoverResourceAllocationUnsuccessfulTransfer_sequence);

  return offset;
}


static const value_string ngap_HandoverType_vals[] = {
  { intra5gs, "intra5gs" },
  { fivegs_to_eps, "fivegs-to-eps" },
  { eps_to_5gs, "eps-to-5gs" },
  { 0, NULL }
};


static int
dissect_ngap_HandoverType(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 255 "./asn1/ngap/ngap.cnf"
  struct ngap_private_data *ngap_data = ngap_get_private_data(actx->pinfo);
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     3, &ngap_data->handover_type_value, TRUE, 0, NULL);




  return offset;
}


static const value_string ngap_IMSVoiceSupportIndicator_vals[] = {
  {   0, "supported" },
  {   1, "not-supported" },
  { 0, NULL }
};


static int
dissect_ngap_IMSVoiceSupportIndicator(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     2, NULL, TRUE, 0, NULL);

  return offset;
}



static int
dissect_ngap_IndexToRFSP(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            1U, 256U, NULL, TRUE);

  return offset;
}


static const per_sequence_t RecommendedRANNodeItem_sequence[] = {
  { &hf_ngap_aMFPagingTarget, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ngap_AMFPagingTarget },
  { &hf_ngap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ngap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_ngap_RecommendedRANNodeItem(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ngap_RecommendedRANNodeItem, RecommendedRANNodeItem_sequence);

  return offset;
}


static const per_sequence_t RecommendedRANNodeList_sequence_of[1] = {
  { &hf_ngap_RecommendedRANNodeList_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ngap_RecommendedRANNodeItem },
};

static int
dissect_ngap_RecommendedRANNodeList(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_ngap_RecommendedRANNodeList, RecommendedRANNodeList_sequence_of,
                                                  1, maxnoofRecommendedRANNodes, FALSE);

  return offset;
}


static const per_sequence_t RecommendedRANNodesForPaging_sequence[] = {
  { &hf_ngap_recommendedRANNodeList, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ngap_RecommendedRANNodeList },
  { &hf_ngap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ngap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_ngap_RecommendedRANNodesForPaging(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ngap_RecommendedRANNodesForPaging, RecommendedRANNodesForPaging_sequence);

  return offset;
}


static const per_sequence_t InfoOnRecommendedCellsAndRANNodesForPaging_sequence[] = {
  { &hf_ngap_recommendedCellsForPaging, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ngap_RecommendedCellsForPaging },
  { &hf_ngap_recommendRANNodesForPaging, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ngap_RecommendedRANNodesForPaging },
  { &hf_ngap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ngap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_ngap_InfoOnRecommendedCellsAndRANNodesForPaging(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ngap_InfoOnRecommendedCellsAndRANNodesForPaging, InfoOnRecommendedCellsAndRANNodesForPaging_sequence);

  return offset;
}


static const value_string ngap_IntegrityProtectionIndication_vals[] = {
  {   0, "required" },
  {   1, "preferred" },
  {   2, "not-needed" },
  { 0, NULL }
};


static int
dissect_ngap_IntegrityProtectionIndication(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     3, NULL, TRUE, 0, NULL);

  return offset;
}



static int
dissect_ngap_InterfacesToTrace(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 456 "./asn1/ngap/ngap.cnf"
  tvbuff_t *parameter_tvb = NULL;
  offset = dissect_per_bit_string(tvb, offset, actx, tree, hf_index,
                                     8, 8, FALSE, NULL, 0, &parameter_tvb, NULL);

  if (parameter_tvb) {
    static int * const fields[] = {
      &hf_ngap_InterfacesToTrace_NG_C,
      &hf_ngap_InterfacesToTrace_Xn_C,
      &hf_ngap_InterfacesToTrace_Uu,
      &hf_ngap_InterfacesToTrace_F1_C,
      &hf_ngap_InterfacesToTrace_E1,
      &hf_ngap_InterfacesToTrace_reserved,
      NULL
    };
    proto_tree *subtree = proto_item_add_subtree(actx->created_item, ett_ngap_InterfacesToTrace);
    proto_tree_add_bitmask_list(subtree, parameter_tvb, 0, 1, fields, ENC_BIG_ENDIAN);
  }



  return offset;
}



static int
dissect_ngap_TimeUEStayedInCell(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 4095U, NULL, FALSE);

  return offset;
}



static int
dissect_ngap_TimeUEStayedInCellEnhancedGranularity(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 40950U, NULL, FALSE);

  return offset;
}


static const per_sequence_t LastVisitedNGRANCellInformation_sequence[] = {
  { &hf_ngap_globalCellID   , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ngap_NGRAN_CGI },
  { &hf_ngap_cellType       , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ngap_CellType },
  { &hf_ngap_timeUEStayedInCell, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ngap_TimeUEStayedInCell },
  { &hf_ngap_timeUEStayedInCellEnhancedGranularity, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ngap_TimeUEStayedInCellEnhancedGranularity },
  { &hf_ngap_hOCauseValue   , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ngap_Cause },
  { &hf_ngap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ngap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_ngap_LastVisitedNGRANCellInformation(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ngap_LastVisitedNGRANCellInformation, LastVisitedNGRANCellInformation_sequence);

  return offset;
}



static int
dissect_ngap_LastVisitedEUTRANCellInformation(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 667 "./asn1/ngap/ngap.cnf"
  tvbuff_t *parameter_tvb = NULL;
  proto_tree *subtree;
  offset = dissect_per_octet_string(tvb, offset, actx, tree, hf_index,
                                       NO_BOUND, NO_BOUND, FALSE, &parameter_tvb);

  if (parameter_tvb) {
    subtree = proto_item_add_subtree(actx->created_item, ett_ngap_LastVisitedEUTRANCellInformation);
    dissect_s1ap_LastVisitedEUTRANCellInformation_PDU(parameter_tvb, actx->pinfo, subtree, NULL);
  }



  return offset;
}



static int
dissect_ngap_LastVisitedUTRANCellInformation(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 676 "./asn1/ngap/ngap.cnf"
  tvbuff_t *parameter_tvb = NULL;
  proto_tree *subtree;
  offset = dissect_per_octet_string(tvb, offset, actx, tree, hf_index,
                                       NO_BOUND, NO_BOUND, FALSE, &parameter_tvb);

  if (parameter_tvb) {
    subtree = proto_item_add_subtree(actx->created_item, ett_ngap_LastVisitedUTRANCellInformation);
    dissect_ranap_LastVisitedUTRANCell_Item_PDU(parameter_tvb, actx->pinfo, subtree, NULL);
  }



  return offset;
}



static int
dissect_ngap_LastVisitedGERANCellInformation(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 685 "./asn1/ngap/ngap.cnf"
  tvbuff_t *parameter_tvb = NULL;
  proto_tree *subtree;
  offset = dissect_per_octet_string(tvb, offset, actx, tree, hf_index,
                                       NO_BOUND, NO_BOUND, FALSE, &parameter_tvb);

  if (parameter_tvb) {
    subtree = proto_item_add_subtree(actx->created_item, ett_ngap_LastVisitedGERANCellInformation);
    dissect_s1ap_LastVisitedGERANCellInformation_PDU(parameter_tvb, actx->pinfo, subtree, NULL);
  }



  return offset;
}


static const value_string ngap_LastVisitedCellInformation_vals[] = {
  {   0, "nGRANCell" },
  {   1, "eUTRANCell" },
  {   2, "uTRANCell" },
  {   3, "gERANCell" },
  {   4, "choice-Extensions" },
  { 0, NULL }
};

static const per_choice_t LastVisitedCellInformation_choice[] = {
  {   0, &hf_ngap_nGRANCell      , ASN1_NO_EXTENSIONS     , dissect_ngap_LastVisitedNGRANCellInformation },
  {   1, &hf_ngap_eUTRANCell     , ASN1_NO_EXTENSIONS     , dissect_ngap_LastVisitedEUTRANCellInformation },
  {   2, &hf_ngap_uTRANCell      , ASN1_NO_EXTENSIONS     , dissect_ngap_LastVisitedUTRANCellInformation },
  {   3, &hf_ngap_gERANCell      , ASN1_NO_EXTENSIONS     , dissect_ngap_LastVisitedGERANCellInformation },
  {   4, &hf_ngap_choice_Extensions, ASN1_NO_EXTENSIONS     , dissect_ngap_ProtocolIE_SingleContainer },
  { 0, NULL, 0, NULL }
};

static int
dissect_ngap_LastVisitedCellInformation(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_ngap_LastVisitedCellInformation, LastVisitedCellInformation_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t LastVisitedCellItem_sequence[] = {
  { &hf_ngap_lastVisitedCellInformation, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ngap_LastVisitedCellInformation },
  { &hf_ngap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ngap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_ngap_LastVisitedCellItem(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ngap_LastVisitedCellItem, LastVisitedCellItem_sequence);

  return offset;
}


static const value_string ngap_LocationReportingAdditionalInfo_vals[] = {
  {   0, "includePSCell" },
  { 0, NULL }
};


static int
dissect_ngap_LocationReportingAdditionalInfo(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     1, NULL, TRUE, 0, NULL);

  return offset;
}


static const value_string ngap_ReportArea_vals[] = {
  {   0, "cell" },
  { 0, NULL }
};


static int
dissect_ngap_ReportArea(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     1, NULL, TRUE, 0, NULL);

  return offset;
}


static const per_sequence_t LocationReportingRequestType_sequence[] = {
  { &hf_ngap_eventType      , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ngap_EventType },
  { &hf_ngap_reportArea     , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ngap_ReportArea },
  { &hf_ngap_areaOfInterestList, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ngap_AreaOfInterestList },
  { &hf_ngap_locationReportingReferenceIDToBeCancelled, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ngap_LocationReportingReferenceID },
  { &hf_ngap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ngap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_ngap_LocationReportingRequestType(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ngap_LocationReportingRequestType, LocationReportingRequestType_sequence);

  return offset;
}



static int
dissect_ngap_MaskedIMEISV(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_bit_string(tvb, offset, actx, tree, hf_index,
                                     64, 64, FALSE, NULL, 0, NULL, NULL);

  return offset;
}



static int
dissect_ngap_MessageIdentifier(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_bit_string(tvb, offset, actx, tree, hf_index,
                                     16, 16, FALSE, NULL, 0, NULL, NULL);

  return offset;
}


static const value_string ngap_MaximumIntegrityProtectedDataRate_vals[] = {
  {   0, "bitrate64kbs" },
  {   1, "maximum-UE-rate" },
  { 0, NULL }
};


static int
dissect_ngap_MaximumIntegrityProtectedDataRate(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     2, NULL, TRUE, 0, NULL);

  return offset;
}



static int
dissect_ngap_RATRestrictionInformation(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 590 "./asn1/ngap/ngap.cnf"
  tvbuff_t *parameter_tvb = NULL;
  offset = dissect_per_bit_string(tvb, offset, actx, tree, hf_index,
                                     8, 8, TRUE, NULL, 0, &parameter_tvb, NULL);

  if (parameter_tvb) {
    static int * const fields[] = {
      &hf_ngap_RATRestrictionInformation_e_UTRA,
      &hf_ngap_RATRestrictionInformation_nR,
      &hf_ngap_RATRestrictionInformation_reserved,
      NULL
    };
    proto_tree *subtree = proto_item_add_subtree(actx->created_item, ett_ngap_RATRestrictionInformation);
    proto_tree_add_bitmask_list(subtree, parameter_tvb, 0, 1, fields, ENC_BIG_ENDIAN);
  }



  return offset;
}


static const per_sequence_t RATRestrictions_Item_sequence[] = {
  { &hf_ngap_pLMNIdentity   , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ngap_PLMNIdentity },
  { &hf_ngap_rATRestrictionInformation, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ngap_RATRestrictionInformation },
  { &hf_ngap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ngap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_ngap_RATRestrictions_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ngap_RATRestrictions_Item, RATRestrictions_Item_sequence);

  return offset;
}


static const per_sequence_t RATRestrictions_sequence_of[1] = {
  { &hf_ngap_RATRestrictions_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ngap_RATRestrictions_Item },
};

static int
dissect_ngap_RATRestrictions(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_ngap_RATRestrictions, RATRestrictions_sequence_of,
                                                  1, maxnoofEPLMNsPlusOne, FALSE);

  return offset;
}


static const per_sequence_t NotAllowedTACs_sequence_of[1] = {
  { &hf_ngap_NotAllowedTACs_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ngap_TAC },
};

static int
dissect_ngap_NotAllowedTACs(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_ngap_NotAllowedTACs, NotAllowedTACs_sequence_of,
                                                  1, maxnoofAllowedAreas, FALSE);

  return offset;
}


static const per_sequence_t ServiceAreaInformation_Item_sequence[] = {
  { &hf_ngap_pLMNIdentity   , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ngap_PLMNIdentity },
  { &hf_ngap_allowedTACs    , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ngap_AllowedTACs },
  { &hf_ngap_notAllowedTACs , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ngap_NotAllowedTACs },
  { &hf_ngap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ngap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_ngap_ServiceAreaInformation_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ngap_ServiceAreaInformation_Item, ServiceAreaInformation_Item_sequence);

  return offset;
}


static const per_sequence_t ServiceAreaInformation_sequence_of[1] = {
  { &hf_ngap_ServiceAreaInformation_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ngap_ServiceAreaInformation_Item },
};

static int
dissect_ngap_ServiceAreaInformation(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_ngap_ServiceAreaInformation, ServiceAreaInformation_sequence_of,
                                                  1, maxnoofEPLMNsPlusOne, FALSE);

  return offset;
}


static const per_sequence_t MobilityRestrictionList_sequence[] = {
  { &hf_ngap_servingPLMN    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ngap_PLMNIdentity },
  { &hf_ngap_equivalentPLMNs, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ngap_EquivalentPLMNs },
  { &hf_ngap_rATRestrictions, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ngap_RATRestrictions },
  { &hf_ngap_forbiddenAreaInformation, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ngap_ForbiddenAreaInformation },
  { &hf_ngap_serviceAreaInformation, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ngap_ServiceAreaInformation },
  { &hf_ngap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ngap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_ngap_MobilityRestrictionList(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ngap_MobilityRestrictionList, MobilityRestrictionList_sequence);

  return offset;
}



static int
dissect_ngap_NAS_PDU(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 207 "./asn1/ngap/ngap.cnf"

  tvbuff_t *parameter_tvb=NULL;
  guint tvb_len;

  offset = dissect_per_octet_string(tvb, offset, actx, tree, hf_index,
                                       NO_BOUND, NO_BOUND, FALSE, &parameter_tvb);


  tvb_len = tvb_reported_length(parameter_tvb);
  if (tvb_len > 0) {
    struct ngap_private_data *ngap_data = ngap_get_private_data(actx->pinfo);
    if (ngap_data->protocol_ie_id == id_NASC) {
      proto_tree *subtree = proto_item_add_subtree(actx->created_item, ett_ngap_NASC);
      /* use an heuristic based on the payload length to identify the Intra N1 mode
         NAS transparent container or the S1 mode to N1 mode NAS transparent container */
      if (tvb_len == 8)
        de_nas_5gs_s1_mode_to_n1_mode_nas_transparent_cont(parameter_tvb, subtree, actx->pinfo);
      else
        de_nas_5gs_intra_n1_mode_nas_transparent_cont(parameter_tvb, subtree, actx->pinfo);
    } else {
      if (nas_5gs_handle) {
        proto_tree *subtree = proto_item_add_subtree(actx->created_item, ett_ngap_NAS_PDU);
        TRY {
          call_dissector(nas_5gs_handle, parameter_tvb, actx->pinfo, subtree);
        }
        CATCH_BOUNDS_ERRORS {
          show_exception(tvb, actx->pinfo, subtree, EXCEPT_CODE, GET_MESSAGE);
        }
        ENDTRY;
      }
    }
  }



  return offset;
}



static int
dissect_ngap_NASSecurityParametersFromNGRAN(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 720 "./asn1/ngap/ngap.cnf"
  tvbuff_t *parameter_tvb = NULL;

  offset = dissect_per_octet_string(tvb, offset, actx, tree, hf_index,
                                       NO_BOUND, NO_BOUND, FALSE, &parameter_tvb);

  if (parameter_tvb) {
    proto_tree *subtree;

    subtree = proto_item_add_subtree(actx->created_item, ett_ngap_NASSecurityParametersFromNGRAN);
    de_nas_5gs_n1_mode_to_s1_mode_nas_transparent_cont(parameter_tvb, subtree, actx->pinfo);
  }



  return offset;
}



static int
dissect_ngap_NetworkInstance(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            1U, 256U, NULL, TRUE);

  return offset;
}


static const value_string ngap_NewSecurityContextInd_vals[] = {
  {   0, "true" },
  { 0, NULL }
};


static int
dissect_ngap_NewSecurityContextInd(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     1, NULL, TRUE, 0, NULL);

  return offset;
}



static int
dissect_ngap_NextHopChainingCount(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 7U, NULL, FALSE);

  return offset;
}


static const per_sequence_t NGRAN_TNLAssociationToRemoveItem_sequence[] = {
  { &hf_ngap_tNLAssociationTransportLayerAddress, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ngap_CPTransportLayerInformation },
  { &hf_ngap_tNLAssociationTransportLayerAddressAMF, ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_ngap_CPTransportLayerInformation },
  { &hf_ngap_iE_Extensions  , ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_ngap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_ngap_NGRAN_TNLAssociationToRemoveItem(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ngap_NGRAN_TNLAssociationToRemoveItem, NGRAN_TNLAssociationToRemoveItem_sequence);

  return offset;
}


static const per_sequence_t NGRAN_TNLAssociationToRemoveList_sequence_of[1] = {
  { &hf_ngap_NGRAN_TNLAssociationToRemoveList_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ngap_NGRAN_TNLAssociationToRemoveItem },
};

static int
dissect_ngap_NGRAN_TNLAssociationToRemoveList(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_ngap_NGRAN_TNLAssociationToRemoveList, NGRAN_TNLAssociationToRemoveList_sequence_of,
                                                  1, maxnoofTNLAssociations, FALSE);

  return offset;
}



static int
dissect_ngap_NGRANTraceID(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 411 "./asn1/ngap/ngap.cnf"
  tvbuff_t *parameter_tvb;
  proto_tree *subtree = NULL;
  offset = dissect_per_octet_string(tvb, offset, actx, tree, hf_index,
                                       8, 8, FALSE, &parameter_tvb);

  if (!parameter_tvb)
    return offset;
  subtree = proto_item_add_subtree(actx->created_item, ett_ngap_NGRANTraceID);
  dissect_e212_mcc_mnc(parameter_tvb, actx->pinfo, subtree, 0, E212_NONE, FALSE);
  proto_tree_add_item(subtree, hf_ngap_NGRANTraceID_TraceID, parameter_tvb, 3, 3, ENC_BIG_ENDIAN);
  proto_tree_add_item(subtree, hf_ngap_NGRANTraceID_TraceRecordingSessionReference, parameter_tvb, 6, 2, ENC_BIG_ENDIAN);



  return offset;
}


static const per_sequence_t NonDynamic5QIDescriptor_sequence[] = {
  { &hf_ngap_fiveQI         , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ngap_FiveQI },
  { &hf_ngap_priorityLevelQos, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ngap_PriorityLevelQos },
  { &hf_ngap_averagingWindow, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ngap_AveragingWindow },
  { &hf_ngap_maximumDataBurstVolume, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ngap_MaximumDataBurstVolume },
  { &hf_ngap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ngap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_ngap_NonDynamic5QIDescriptor(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ngap_NonDynamic5QIDescriptor, NonDynamic5QIDescriptor_sequence);

  return offset;
}


static const value_string ngap_NotificationCause_vals[] = {
  {   0, "fulfilled" },
  {   1, "not-fulfilled" },
  { 0, NULL }
};


static int
dissect_ngap_NotificationCause(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     2, NULL, TRUE, 0, NULL);

  return offset;
}


static const per_sequence_t NR_CGIListForWarning_sequence_of[1] = {
  { &hf_ngap_NR_CGIListForWarning_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ngap_NR_CGI },
};

static int
dissect_ngap_NR_CGIListForWarning(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_ngap_NR_CGIListForWarning, NR_CGIListForWarning_sequence_of,
                                                  1, maxnoofCellIDforWarning, FALSE);

  return offset;
}



static int
dissect_ngap_NRencryptionAlgorithms(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 604 "./asn1/ngap/ngap.cnf"
  tvbuff_t *parameter_tvb = NULL;
  offset = dissect_per_bit_string(tvb, offset, actx, tree, hf_index,
                                     16, 16, TRUE, NULL, 0, &parameter_tvb, NULL);

  if (parameter_tvb) {
    static int * const fields[] = {
      &hf_ngap_NrencyptionAlgorithms_nea1,
      &hf_ngap_NrencyptionAlgorithms_nea2,
      &hf_ngap_NrencyptionAlgorithms_nea3,
      &hf_ngap_NrencyptionAlgorithms_reserved,
      NULL
    };
    proto_tree *subtree = proto_item_add_subtree(actx->created_item, ett_ngap_NrencryptionAlgorithms);
    proto_tree_add_bitmask_list(subtree, parameter_tvb, 0, 2, fields, ENC_BIG_ENDIAN);
  }



  return offset;
}



static int
dissect_ngap_NRintegrityProtectionAlgorithms(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 619 "./asn1/ngap/ngap.cnf"
  tvbuff_t *parameter_tvb = NULL;
  offset = dissect_per_bit_string(tvb, offset, actx, tree, hf_index,
                                     16, 16, TRUE, NULL, 0, &parameter_tvb, NULL);

  if (parameter_tvb) {
    static int * const fields[] = {
      &hf_ngap_NrintegrityProtectionAlgorithms_nia1,
      &hf_ngap_NrintegrityProtectionAlgorithms_nia2,
      &hf_ngap_NrintegrityProtectionAlgorithms_nia3,
      &hf_ngap_NrintegrityProtectionAlgorithms_reserved,
      NULL
    };
    proto_tree *subtree = proto_item_add_subtree(actx->created_item, ett_ngap_NrintegrityProtectionAlgorithms);
    proto_tree_add_bitmask_list(subtree, parameter_tvb, 0, 2, fields, ENC_BIG_ENDIAN);
  }



  return offset;
}



static int
dissect_ngap_NRPPa_PDU(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 758 "./asn1/ngap/ngap.cnf"

  tvbuff_t *parameter_tvb=NULL;

  offset = dissect_per_octet_string(tvb, offset, actx, tree, hf_index,
                                       NO_BOUND, NO_BOUND, FALSE, &parameter_tvb);


  if ((tvb_reported_length(parameter_tvb)>0)&&(nrppa_handle))
    call_dissector(nrppa_handle, parameter_tvb, actx->pinfo, tree);



  return offset;
}



static int
dissect_ngap_NumberOfBroadcastsRequested(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 65535U, NULL, FALSE);

  return offset;
}


static const value_string ngap_OverloadAction_vals[] = {
  {   0, "reject-non-emergency-mo-dt" },
  {   1, "reject-rrc-cr-signalling" },
  {   2, "permit-emergency-sessions-and-mobile-terminated-services-only" },
  {   3, "permit-high-priority-sessions-and-mobile-terminated-services-only" },
  { 0, NULL }
};


static int
dissect_ngap_OverloadAction(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     4, NULL, TRUE, 0, NULL);

  return offset;
}


static const value_string ngap_OverloadResponse_vals[] = {
  {   0, "overloadAction" },
  {   1, "choice-Extensions" },
  { 0, NULL }
};

static const per_choice_t OverloadResponse_choice[] = {
  {   0, &hf_ngap_overloadAction , ASN1_NO_EXTENSIONS     , dissect_ngap_OverloadAction },
  {   1, &hf_ngap_choice_Extensions, ASN1_NO_EXTENSIONS     , dissect_ngap_ProtocolIE_SingleContainer },
  { 0, NULL, 0, NULL }
};

static int
dissect_ngap_OverloadResponse(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_ngap_OverloadResponse, OverloadResponse_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t SliceOverloadItem_sequence[] = {
  { &hf_ngap_s_NSSAI        , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ngap_S_NSSAI },
  { &hf_ngap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ngap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_ngap_SliceOverloadItem(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ngap_SliceOverloadItem, SliceOverloadItem_sequence);

  return offset;
}


static const per_sequence_t SliceOverloadList_sequence_of[1] = {
  { &hf_ngap_SliceOverloadList_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ngap_SliceOverloadItem },
};

static int
dissect_ngap_SliceOverloadList(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_ngap_SliceOverloadList, SliceOverloadList_sequence_of,
                                                  1, maxnoofSliceItems, FALSE);

  return offset;
}



static int
dissect_ngap_TrafficLoadReductionIndication(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            1U, 99U, NULL, FALSE);

  return offset;
}


static const per_sequence_t OverloadStartNSSAIItem_sequence[] = {
  { &hf_ngap_sliceOverloadList, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ngap_SliceOverloadList },
  { &hf_ngap_sliceOverloadResponse, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ngap_OverloadResponse },
  { &hf_ngap_sliceTrafficLoadReductionIndication, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ngap_TrafficLoadReductionIndication },
  { &hf_ngap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ngap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_ngap_OverloadStartNSSAIItem(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ngap_OverloadStartNSSAIItem, OverloadStartNSSAIItem_sequence);

  return offset;
}


static const per_sequence_t OverloadStartNSSAIList_sequence_of[1] = {
  { &hf_ngap_OverloadStartNSSAIList_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ngap_OverloadStartNSSAIItem },
};

static int
dissect_ngap_OverloadStartNSSAIList(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_ngap_OverloadStartNSSAIList, OverloadStartNSSAIList_sequence_of,
                                                  1, maxnoofSliceItems, FALSE);

  return offset;
}


static const value_string ngap_PagingOrigin_vals[] = {
  {   0, "non-3gpp" },
  { 0, NULL }
};


static int
dissect_ngap_PagingOrigin(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     1, NULL, TRUE, 0, NULL);

  return offset;
}


static const value_string ngap_PagingPriority_vals[] = {
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
dissect_ngap_PagingPriority(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     8, NULL, TRUE, 0, NULL);

  return offset;
}


static const per_sequence_t SecurityIndication_sequence[] = {
  { &hf_ngap_integrityProtectionIndication, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ngap_IntegrityProtectionIndication },
  { &hf_ngap_confidentialityProtectionIndication, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ngap_ConfidentialityProtectionIndication },
  { &hf_ngap_maximumIntegrityProtectedDataRate_UL, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ngap_MaximumIntegrityProtectedDataRate },
  { &hf_ngap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ngap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_ngap_SecurityIndication(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ngap_SecurityIndication, SecurityIndication_sequence);

  return offset;
}


static const per_sequence_t PathSwitchRequestAcknowledgeTransfer_sequence[] = {
  { &hf_ngap_uL_NGU_UP_TNLInformation, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ngap_UPTransportLayerInformation },
  { &hf_ngap_securityIndication, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ngap_SecurityIndication },
  { &hf_ngap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ngap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_ngap_PathSwitchRequestAcknowledgeTransfer(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ngap_PathSwitchRequestAcknowledgeTransfer, PathSwitchRequestAcknowledgeTransfer_sequence);

  return offset;
}


static const per_sequence_t PathSwitchRequestSetupFailedTransfer_sequence[] = {
  { &hf_ngap_cause          , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ngap_Cause },
  { &hf_ngap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ngap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_ngap_PathSwitchRequestSetupFailedTransfer(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ngap_PathSwitchRequestSetupFailedTransfer, PathSwitchRequestSetupFailedTransfer_sequence);

  return offset;
}


static const per_sequence_t UserPlaneSecurityInformation_sequence[] = {
  { &hf_ngap_securityResult , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ngap_SecurityResult },
  { &hf_ngap_securityIndication, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ngap_SecurityIndication },
  { &hf_ngap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ngap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_ngap_UserPlaneSecurityInformation(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ngap_UserPlaneSecurityInformation, UserPlaneSecurityInformation_sequence);

  return offset;
}


static const per_sequence_t QosFlowAcceptedItem_sequence[] = {
  { &hf_ngap_qosFlowIdentifier, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ngap_QosFlowIdentifier },
  { &hf_ngap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ngap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_ngap_QosFlowAcceptedItem(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ngap_QosFlowAcceptedItem, QosFlowAcceptedItem_sequence);

  return offset;
}


static const per_sequence_t QosFlowAcceptedList_sequence_of[1] = {
  { &hf_ngap_QosFlowAcceptedList_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ngap_QosFlowAcceptedItem },
};

static int
dissect_ngap_QosFlowAcceptedList(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_ngap_QosFlowAcceptedList, QosFlowAcceptedList_sequence_of,
                                                  1, maxnoofQosFlows, FALSE);

  return offset;
}


static const per_sequence_t PathSwitchRequestTransfer_sequence[] = {
  { &hf_ngap_dL_NGU_UP_TNLInformation, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ngap_UPTransportLayerInformation },
  { &hf_ngap_dL_NGU_TNLInformationReused, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ngap_DL_NGU_TNLInformationReused },
  { &hf_ngap_userPlaneSecurityInformation, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ngap_UserPlaneSecurityInformation },
  { &hf_ngap_qosFlowAcceptedList, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ngap_QosFlowAcceptedList },
  { &hf_ngap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ngap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_ngap_PathSwitchRequestTransfer(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ngap_PathSwitchRequestTransfer, PathSwitchRequestTransfer_sequence);

  return offset;
}


static const per_sequence_t PathSwitchRequestUnsuccessfulTransfer_sequence[] = {
  { &hf_ngap_cause          , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ngap_Cause },
  { &hf_ngap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ngap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_ngap_PathSwitchRequestUnsuccessfulTransfer(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ngap_PathSwitchRequestUnsuccessfulTransfer, PathSwitchRequestUnsuccessfulTransfer_sequence);

  return offset;
}


static const per_sequence_t PDUSessionAggregateMaximumBitRate_sequence[] = {
  { &hf_ngap_pDUSessionAggregateMaximumBitRateDL, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ngap_BitRate },
  { &hf_ngap_pDUSessionAggregateMaximumBitRateUL, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ngap_BitRate },
  { &hf_ngap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ngap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_ngap_PDUSessionAggregateMaximumBitRate(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ngap_PDUSessionAggregateMaximumBitRate, PDUSessionAggregateMaximumBitRate_sequence);

  return offset;
}



static int
dissect_ngap_PDUSessionID(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 255U, NULL, FALSE);

  return offset;
}



static int
dissect_ngap_T_handoverRequestAcknowledgeTransfer(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_octet_string_containing_pdu_new(tvb, offset, actx, tree, hf_index,
                                                                NO_BOUND, NO_BOUND, FALSE, dissect_HandoverRequestAcknowledgeTransfer_PDU);

  return offset;
}


static const per_sequence_t PDUSessionResourceAdmittedItem_sequence[] = {
  { &hf_ngap_pDUSessionID   , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ngap_PDUSessionID },
  { &hf_ngap_handoverRequestAcknowledgeTransfer, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ngap_T_handoverRequestAcknowledgeTransfer },
  { &hf_ngap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ngap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_ngap_PDUSessionResourceAdmittedItem(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ngap_PDUSessionResourceAdmittedItem, PDUSessionResourceAdmittedItem_sequence);

  return offset;
}


static const per_sequence_t PDUSessionResourceAdmittedList_sequence_of[1] = {
  { &hf_ngap_PDUSessionResourceAdmittedList_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ngap_PDUSessionResourceAdmittedItem },
};

static int
dissect_ngap_PDUSessionResourceAdmittedList(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_ngap_PDUSessionResourceAdmittedList, PDUSessionResourceAdmittedList_sequence_of,
                                                  1, maxnoofPDUSessions, FALSE);

  return offset;
}



static int
dissect_ngap_T_pDUSessionResourceModifyIndicationUnsuccessfulTransfer(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_octet_string_containing_pdu_new(tvb, offset, actx, tree, hf_index,
                                                                NO_BOUND, NO_BOUND, FALSE, dissect_PDUSessionResourceModifyIndicationUnsuccessfulTransfer_PDU);

  return offset;
}


static const per_sequence_t PDUSessionResourceFailedToModifyItemModCfm_sequence[] = {
  { &hf_ngap_pDUSessionID   , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ngap_PDUSessionID },
  { &hf_ngap_pDUSessionResourceModifyIndicationUnsuccessfulTransfer, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ngap_T_pDUSessionResourceModifyIndicationUnsuccessfulTransfer },
  { &hf_ngap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ngap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_ngap_PDUSessionResourceFailedToModifyItemModCfm(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ngap_PDUSessionResourceFailedToModifyItemModCfm, PDUSessionResourceFailedToModifyItemModCfm_sequence);

  return offset;
}


static const per_sequence_t PDUSessionResourceFailedToModifyListModCfm_sequence_of[1] = {
  { &hf_ngap_PDUSessionResourceFailedToModifyListModCfm_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ngap_PDUSessionResourceFailedToModifyItemModCfm },
};

static int
dissect_ngap_PDUSessionResourceFailedToModifyListModCfm(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_ngap_PDUSessionResourceFailedToModifyListModCfm, PDUSessionResourceFailedToModifyListModCfm_sequence_of,
                                                  1, maxnoofPDUSessions, FALSE);

  return offset;
}



static int
dissect_ngap_T_pDUSessionResourceModifyUnsuccessfulTransfer(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_octet_string_containing_pdu_new(tvb, offset, actx, tree, hf_index,
                                                                NO_BOUND, NO_BOUND, FALSE, dissect_PDUSessionResourceModifyUnsuccessfulTransfer_PDU);

  return offset;
}


static const per_sequence_t PDUSessionResourceFailedToModifyItemModRes_sequence[] = {
  { &hf_ngap_pDUSessionID   , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ngap_PDUSessionID },
  { &hf_ngap_pDUSessionResourceModifyUnsuccessfulTransfer, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ngap_T_pDUSessionResourceModifyUnsuccessfulTransfer },
  { &hf_ngap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ngap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_ngap_PDUSessionResourceFailedToModifyItemModRes(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ngap_PDUSessionResourceFailedToModifyItemModRes, PDUSessionResourceFailedToModifyItemModRes_sequence);

  return offset;
}


static const per_sequence_t PDUSessionResourceFailedToModifyListModRes_sequence_of[1] = {
  { &hf_ngap_PDUSessionResourceFailedToModifyListModRes_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ngap_PDUSessionResourceFailedToModifyItemModRes },
};

static int
dissect_ngap_PDUSessionResourceFailedToModifyListModRes(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_ngap_PDUSessionResourceFailedToModifyListModRes, PDUSessionResourceFailedToModifyListModRes_sequence_of,
                                                  1, maxnoofPDUSessions, FALSE);

  return offset;
}



static int
dissect_ngap_T_pDUSessionResourceSetupUnsuccessfulTransfer(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_octet_string_containing_pdu_new(tvb, offset, actx, tree, hf_index,
                                                                NO_BOUND, NO_BOUND, FALSE, dissect_PDUSessionResourceSetupUnsuccessfulTransfer_PDU);

  return offset;
}


static const per_sequence_t PDUSessionResourceFailedToSetupItemCxtFail_sequence[] = {
  { &hf_ngap_pDUSessionID   , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ngap_PDUSessionID },
  { &hf_ngap_pDUSessionResourceSetupUnsuccessfulTransfer, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ngap_T_pDUSessionResourceSetupUnsuccessfulTransfer },
  { &hf_ngap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ngap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_ngap_PDUSessionResourceFailedToSetupItemCxtFail(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ngap_PDUSessionResourceFailedToSetupItemCxtFail, PDUSessionResourceFailedToSetupItemCxtFail_sequence);

  return offset;
}


static const per_sequence_t PDUSessionResourceFailedToSetupListCxtFail_sequence_of[1] = {
  { &hf_ngap_PDUSessionResourceFailedToSetupListCxtFail_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ngap_PDUSessionResourceFailedToSetupItemCxtFail },
};

static int
dissect_ngap_PDUSessionResourceFailedToSetupListCxtFail(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_ngap_PDUSessionResourceFailedToSetupListCxtFail, PDUSessionResourceFailedToSetupListCxtFail_sequence_of,
                                                  1, maxnoofPDUSessions, FALSE);

  return offset;
}



static int
dissect_ngap_T_pDUSessionResourceSetupUnsuccessfulTransfer_01(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_octet_string_containing_pdu_new(tvb, offset, actx, tree, hf_index,
                                                                NO_BOUND, NO_BOUND, FALSE, dissect_PDUSessionResourceSetupUnsuccessfulTransfer_PDU);

  return offset;
}


static const per_sequence_t PDUSessionResourceFailedToSetupItemCxtRes_sequence[] = {
  { &hf_ngap_pDUSessionID   , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ngap_PDUSessionID },
  { &hf_ngap_pDUSessionResourceSetupUnsuccessfulTransfer_01, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ngap_T_pDUSessionResourceSetupUnsuccessfulTransfer_01 },
  { &hf_ngap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ngap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_ngap_PDUSessionResourceFailedToSetupItemCxtRes(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ngap_PDUSessionResourceFailedToSetupItemCxtRes, PDUSessionResourceFailedToSetupItemCxtRes_sequence);

  return offset;
}


static const per_sequence_t PDUSessionResourceFailedToSetupListCxtRes_sequence_of[1] = {
  { &hf_ngap_PDUSessionResourceFailedToSetupListCxtRes_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ngap_PDUSessionResourceFailedToSetupItemCxtRes },
};

static int
dissect_ngap_PDUSessionResourceFailedToSetupListCxtRes(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_ngap_PDUSessionResourceFailedToSetupListCxtRes, PDUSessionResourceFailedToSetupListCxtRes_sequence_of,
                                                  1, maxnoofPDUSessions, FALSE);

  return offset;
}



static int
dissect_ngap_T_handoverResourceAllocationUnsuccessfulTransfer(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_octet_string_containing_pdu_new(tvb, offset, actx, tree, hf_index,
                                                                NO_BOUND, NO_BOUND, FALSE, dissect_HandoverResourceAllocationUnsuccessfulTransfer_PDU);

  return offset;
}


static const per_sequence_t PDUSessionResourceFailedToSetupItemHOAck_sequence[] = {
  { &hf_ngap_pDUSessionID   , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ngap_PDUSessionID },
  { &hf_ngap_handoverResourceAllocationUnsuccessfulTransfer, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ngap_T_handoverResourceAllocationUnsuccessfulTransfer },
  { &hf_ngap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ngap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_ngap_PDUSessionResourceFailedToSetupItemHOAck(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ngap_PDUSessionResourceFailedToSetupItemHOAck, PDUSessionResourceFailedToSetupItemHOAck_sequence);

  return offset;
}


static const per_sequence_t PDUSessionResourceFailedToSetupListHOAck_sequence_of[1] = {
  { &hf_ngap_PDUSessionResourceFailedToSetupListHOAck_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ngap_PDUSessionResourceFailedToSetupItemHOAck },
};

static int
dissect_ngap_PDUSessionResourceFailedToSetupListHOAck(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_ngap_PDUSessionResourceFailedToSetupListHOAck, PDUSessionResourceFailedToSetupListHOAck_sequence_of,
                                                  1, maxnoofPDUSessions, FALSE);

  return offset;
}



static int
dissect_ngap_T_pathSwitchRequestSetupFailedTransfer(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_octet_string_containing_pdu_new(tvb, offset, actx, tree, hf_index,
                                                                NO_BOUND, NO_BOUND, FALSE, dissect_PathSwitchRequestSetupFailedTransfer_PDU);

  return offset;
}


static const per_sequence_t PDUSessionResourceFailedToSetupItemPSReq_sequence[] = {
  { &hf_ngap_pDUSessionID   , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ngap_PDUSessionID },
  { &hf_ngap_pathSwitchRequestSetupFailedTransfer, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ngap_T_pathSwitchRequestSetupFailedTransfer },
  { &hf_ngap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ngap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_ngap_PDUSessionResourceFailedToSetupItemPSReq(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ngap_PDUSessionResourceFailedToSetupItemPSReq, PDUSessionResourceFailedToSetupItemPSReq_sequence);

  return offset;
}


static const per_sequence_t PDUSessionResourceFailedToSetupListPSReq_sequence_of[1] = {
  { &hf_ngap_PDUSessionResourceFailedToSetupListPSReq_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ngap_PDUSessionResourceFailedToSetupItemPSReq },
};

static int
dissect_ngap_PDUSessionResourceFailedToSetupListPSReq(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_ngap_PDUSessionResourceFailedToSetupListPSReq, PDUSessionResourceFailedToSetupListPSReq_sequence_of,
                                                  1, maxnoofPDUSessions, FALSE);

  return offset;
}



static int
dissect_ngap_T_pDUSessionResourceSetupUnsuccessfulTransfer_02(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_octet_string_containing_pdu_new(tvb, offset, actx, tree, hf_index,
                                                                NO_BOUND, NO_BOUND, FALSE, dissect_PDUSessionResourceSetupUnsuccessfulTransfer_PDU);

  return offset;
}


static const per_sequence_t PDUSessionResourceFailedToSetupItemSURes_sequence[] = {
  { &hf_ngap_pDUSessionID   , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ngap_PDUSessionID },
  { &hf_ngap_pDUSessionResourceSetupUnsuccessfulTransfer_02, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ngap_T_pDUSessionResourceSetupUnsuccessfulTransfer_02 },
  { &hf_ngap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ngap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_ngap_PDUSessionResourceFailedToSetupItemSURes(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ngap_PDUSessionResourceFailedToSetupItemSURes, PDUSessionResourceFailedToSetupItemSURes_sequence);

  return offset;
}


static const per_sequence_t PDUSessionResourceFailedToSetupListSURes_sequence_of[1] = {
  { &hf_ngap_PDUSessionResourceFailedToSetupListSURes_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ngap_PDUSessionResourceFailedToSetupItemSURes },
};

static int
dissect_ngap_PDUSessionResourceFailedToSetupListSURes(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_ngap_PDUSessionResourceFailedToSetupListSURes, PDUSessionResourceFailedToSetupListSURes_sequence_of,
                                                  1, maxnoofPDUSessions, FALSE);

  return offset;
}



static int
dissect_ngap_T_handoverCommandTransfer(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_octet_string_containing_pdu_new(tvb, offset, actx, tree, hf_index,
                                                                NO_BOUND, NO_BOUND, FALSE, dissect_HandoverCommandTransfer_PDU);

  return offset;
}


static const per_sequence_t PDUSessionResourceHandoverItem_sequence[] = {
  { &hf_ngap_pDUSessionID   , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ngap_PDUSessionID },
  { &hf_ngap_handoverCommandTransfer, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ngap_T_handoverCommandTransfer },
  { &hf_ngap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ngap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_ngap_PDUSessionResourceHandoverItem(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ngap_PDUSessionResourceHandoverItem, PDUSessionResourceHandoverItem_sequence);

  return offset;
}


static const per_sequence_t PDUSessionResourceHandoverList_sequence_of[1] = {
  { &hf_ngap_PDUSessionResourceHandoverList_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ngap_PDUSessionResourceHandoverItem },
};

static int
dissect_ngap_PDUSessionResourceHandoverList(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_ngap_PDUSessionResourceHandoverList, PDUSessionResourceHandoverList_sequence_of,
                                                  1, maxnoofPDUSessions, FALSE);

  return offset;
}


static const per_sequence_t QosFlowInformationItem_sequence[] = {
  { &hf_ngap_qosFlowIdentifier, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ngap_QosFlowIdentifier },
  { &hf_ngap_dLForwarding   , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ngap_DLForwarding },
  { &hf_ngap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ngap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_ngap_QosFlowInformationItem(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ngap_QosFlowInformationItem, QosFlowInformationItem_sequence);

  return offset;
}


static const per_sequence_t QosFlowInformationList_sequence_of[1] = {
  { &hf_ngap_QosFlowInformationList_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ngap_QosFlowInformationItem },
};

static int
dissect_ngap_QosFlowInformationList(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_ngap_QosFlowInformationList, QosFlowInformationList_sequence_of,
                                                  1, maxnoofQosFlows, FALSE);

  return offset;
}


static const per_sequence_t PDUSessionResourceInformationItem_sequence[] = {
  { &hf_ngap_pDUSessionID   , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ngap_PDUSessionID },
  { &hf_ngap_qosFlowInformationList, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ngap_QosFlowInformationList },
  { &hf_ngap_dRBsToQosFlowsMappingList, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ngap_DRBsToQosFlowsMappingList },
  { &hf_ngap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ngap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_ngap_PDUSessionResourceInformationItem(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ngap_PDUSessionResourceInformationItem, PDUSessionResourceInformationItem_sequence);

  return offset;
}


static const per_sequence_t PDUSessionResourceInformationList_sequence_of[1] = {
  { &hf_ngap_PDUSessionResourceInformationList_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ngap_PDUSessionResourceInformationItem },
};

static int
dissect_ngap_PDUSessionResourceInformationList(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_ngap_PDUSessionResourceInformationList, PDUSessionResourceInformationList_sequence_of,
                                                  1, maxnoofPDUSessions, FALSE);

  return offset;
}


static const per_sequence_t PDUSessionResourceItemCxtRelCpl_sequence[] = {
  { &hf_ngap_pDUSessionID   , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ngap_PDUSessionID },
  { &hf_ngap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ngap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_ngap_PDUSessionResourceItemCxtRelCpl(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ngap_PDUSessionResourceItemCxtRelCpl, PDUSessionResourceItemCxtRelCpl_sequence);

  return offset;
}


static const per_sequence_t PDUSessionResourceListCxtRelCpl_sequence_of[1] = {
  { &hf_ngap_PDUSessionResourceListCxtRelCpl_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ngap_PDUSessionResourceItemCxtRelCpl },
};

static int
dissect_ngap_PDUSessionResourceListCxtRelCpl(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_ngap_PDUSessionResourceListCxtRelCpl, PDUSessionResourceListCxtRelCpl_sequence_of,
                                                  1, maxnoofPDUSessions, FALSE);

  return offset;
}



static int
dissect_ngap_PDUSessionResourceReleaseResponseTransfer_OCTET_STRING(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_octet_string_containing_pdu_new(tvb, offset, actx, tree, hf_index,
                                                                NO_BOUND, NO_BOUND, FALSE, dissect_PDUSessionResourceReleaseResponseTransfer_PDU);

  return offset;
}


static const per_sequence_t PDUSessionResourceItemCxtRelReq_sequence[] = {
  { &hf_ngap_pDUSessionID   , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ngap_PDUSessionID },
  { &hf_ngap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ngap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_ngap_PDUSessionResourceItemCxtRelReq(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ngap_PDUSessionResourceItemCxtRelReq, PDUSessionResourceItemCxtRelReq_sequence);

  return offset;
}


static const per_sequence_t PDUSessionResourceListCxtRelReq_sequence_of[1] = {
  { &hf_ngap_PDUSessionResourceListCxtRelReq_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ngap_PDUSessionResourceItemCxtRelReq },
};

static int
dissect_ngap_PDUSessionResourceListCxtRelReq(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_ngap_PDUSessionResourceListCxtRelReq, PDUSessionResourceListCxtRelReq_sequence_of,
                                                  1, maxnoofPDUSessions, FALSE);

  return offset;
}



static int
dissect_ngap_T_handoverRequiredTransfer(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_octet_string_containing_pdu_new(tvb, offset, actx, tree, hf_index,
                                                                NO_BOUND, NO_BOUND, FALSE, dissect_HandoverRequiredTransfer_PDU);

  return offset;
}


static const per_sequence_t PDUSessionResourceItemHORqd_sequence[] = {
  { &hf_ngap_pDUSessionID   , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ngap_PDUSessionID },
  { &hf_ngap_handoverRequiredTransfer, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ngap_T_handoverRequiredTransfer },
  { &hf_ngap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ngap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_ngap_PDUSessionResourceItemHORqd(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ngap_PDUSessionResourceItemHORqd, PDUSessionResourceItemHORqd_sequence);

  return offset;
}


static const per_sequence_t PDUSessionResourceListHORqd_sequence_of[1] = {
  { &hf_ngap_PDUSessionResourceListHORqd_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ngap_PDUSessionResourceItemHORqd },
};

static int
dissect_ngap_PDUSessionResourceListHORqd(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_ngap_PDUSessionResourceListHORqd, PDUSessionResourceListHORqd_sequence_of,
                                                  1, maxnoofPDUSessions, FALSE);

  return offset;
}


static const per_sequence_t QosFlowModifyConfirmItem_sequence[] = {
  { &hf_ngap_qosFlowIdentifier, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ngap_QosFlowIdentifier },
  { &hf_ngap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ngap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_ngap_QosFlowModifyConfirmItem(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ngap_QosFlowModifyConfirmItem, QosFlowModifyConfirmItem_sequence);

  return offset;
}


static const per_sequence_t QosFlowModifyConfirmList_sequence_of[1] = {
  { &hf_ngap_QosFlowModifyConfirmList_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ngap_QosFlowModifyConfirmItem },
};

static int
dissect_ngap_QosFlowModifyConfirmList(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_ngap_QosFlowModifyConfirmList, QosFlowModifyConfirmList_sequence_of,
                                                  1, maxnoofQosFlows, FALSE);

  return offset;
}


static const per_sequence_t UPTransportLayerInformationPairItem_sequence[] = {
  { &hf_ngap_uL_NGU_UP_TNLInformation, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ngap_UPTransportLayerInformation },
  { &hf_ngap_dL_NGU_UP_TNLInformation, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ngap_UPTransportLayerInformation },
  { &hf_ngap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ngap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_ngap_UPTransportLayerInformationPairItem(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ngap_UPTransportLayerInformationPairItem, UPTransportLayerInformationPairItem_sequence);

  return offset;
}


static const per_sequence_t UPTransportLayerInformationPairList_sequence_of[1] = {
  { &hf_ngap_UPTransportLayerInformationPairList_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ngap_UPTransportLayerInformationPairItem },
};

static int
dissect_ngap_UPTransportLayerInformationPairList(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_ngap_UPTransportLayerInformationPairList, UPTransportLayerInformationPairList_sequence_of,
                                                  1, maxnoofMultiConnectivityMinusOne, FALSE);

  return offset;
}


static const per_sequence_t PDUSessionResourceModifyConfirmTransfer_sequence[] = {
  { &hf_ngap_qosFlowModifyConfirmList, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ngap_QosFlowModifyConfirmList },
  { &hf_ngap_uLNGU_UP_TNLInformation, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ngap_UPTransportLayerInformation },
  { &hf_ngap_additionalNG_UUPTNLInformation, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ngap_UPTransportLayerInformationPairList },
  { &hf_ngap_qosFlowFailedToModifyList, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ngap_QosFlowListWithCause },
  { &hf_ngap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ngap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_ngap_PDUSessionResourceModifyConfirmTransfer(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ngap_PDUSessionResourceModifyConfirmTransfer, PDUSessionResourceModifyConfirmTransfer_sequence);

  return offset;
}


static const per_sequence_t PDUSessionResourceModifyIndicationUnsuccessfulTransfer_sequence[] = {
  { &hf_ngap_cause          , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ngap_Cause },
  { &hf_ngap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ngap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_ngap_PDUSessionResourceModifyIndicationUnsuccessfulTransfer(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ngap_PDUSessionResourceModifyIndicationUnsuccessfulTransfer, PDUSessionResourceModifyIndicationUnsuccessfulTransfer_sequence);

  return offset;
}


static const per_sequence_t PDUSessionResourceModifyRequestTransfer_sequence[] = {
  { &hf_ngap_protocolIEs    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ngap_ProtocolIE_Container },
  { NULL, 0, 0, NULL }
};

static int
dissect_ngap_PDUSessionResourceModifyRequestTransfer(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ngap_PDUSessionResourceModifyRequestTransfer, PDUSessionResourceModifyRequestTransfer_sequence);

  return offset;
}


static const per_sequence_t QosFlowAddOrModifyResponseItem_sequence[] = {
  { &hf_ngap_qosFlowIdentifier, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ngap_QosFlowIdentifier },
  { &hf_ngap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ngap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_ngap_QosFlowAddOrModifyResponseItem(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ngap_QosFlowAddOrModifyResponseItem, QosFlowAddOrModifyResponseItem_sequence);

  return offset;
}


static const per_sequence_t QosFlowAddOrModifyResponseList_sequence_of[1] = {
  { &hf_ngap_QosFlowAddOrModifyResponseList_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ngap_QosFlowAddOrModifyResponseItem },
};

static int
dissect_ngap_QosFlowAddOrModifyResponseList(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_ngap_QosFlowAddOrModifyResponseList, QosFlowAddOrModifyResponseList_sequence_of,
                                                  1, maxnoofQosFlows, FALSE);

  return offset;
}


static const per_sequence_t QosFlowPerTNLInformation_sequence[] = {
  { &hf_ngap_uPTransportLayerInformation, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ngap_UPTransportLayerInformation },
  { &hf_ngap_associatedQosFlowList, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ngap_AssociatedQosFlowList },
  { &hf_ngap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ngap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_ngap_QosFlowPerTNLInformation(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ngap_QosFlowPerTNLInformation, QosFlowPerTNLInformation_sequence);

  return offset;
}


static const per_sequence_t QosFlowPerTNLInformationItem_sequence[] = {
  { &hf_ngap_qosFlowPerTNLInformation, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ngap_QosFlowPerTNLInformation },
  { &hf_ngap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ngap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_ngap_QosFlowPerTNLInformationItem(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ngap_QosFlowPerTNLInformationItem, QosFlowPerTNLInformationItem_sequence);

  return offset;
}


static const per_sequence_t QosFlowPerTNLInformationList_sequence_of[1] = {
  { &hf_ngap_QosFlowPerTNLInformationList_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ngap_QosFlowPerTNLInformationItem },
};

static int
dissect_ngap_QosFlowPerTNLInformationList(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_ngap_QosFlowPerTNLInformationList, QosFlowPerTNLInformationList_sequence_of,
                                                  1, maxnoofMultiConnectivityMinusOne, FALSE);

  return offset;
}


static const per_sequence_t PDUSessionResourceModifyResponseTransfer_sequence[] = {
  { &hf_ngap_dL_NGU_UP_TNLInformation, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ngap_UPTransportLayerInformation },
  { &hf_ngap_uL_NGU_UP_TNLInformation, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ngap_UPTransportLayerInformation },
  { &hf_ngap_qosFlowAddOrModifyResponseList, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ngap_QosFlowAddOrModifyResponseList },
  { &hf_ngap_additionalDLQosFlowPerTNLInformation, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ngap_QosFlowPerTNLInformationList },
  { &hf_ngap_qosFlowFailedToAddOrModifyList, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ngap_QosFlowListWithCause },
  { &hf_ngap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ngap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_ngap_PDUSessionResourceModifyResponseTransfer(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ngap_PDUSessionResourceModifyResponseTransfer, PDUSessionResourceModifyResponseTransfer_sequence);

  return offset;
}


static const per_sequence_t PDUSessionResourceModifyIndicationTransfer_sequence[] = {
  { &hf_ngap_dLQosFlowPerTNLInformation, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ngap_QosFlowPerTNLInformation },
  { &hf_ngap_additionalDLQosFlowPerTNLInformation, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ngap_QosFlowPerTNLInformationList },
  { &hf_ngap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ngap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_ngap_PDUSessionResourceModifyIndicationTransfer(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ngap_PDUSessionResourceModifyIndicationTransfer, PDUSessionResourceModifyIndicationTransfer_sequence);

  return offset;
}



static int
dissect_ngap_T_pDUSessionResourceModifyConfirmTransfer(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_octet_string_containing_pdu_new(tvb, offset, actx, tree, hf_index,
                                                                NO_BOUND, NO_BOUND, FALSE, dissect_PDUSessionResourceModifyConfirmTransfer_PDU);

  return offset;
}


static const per_sequence_t PDUSessionResourceModifyItemModCfm_sequence[] = {
  { &hf_ngap_pDUSessionID   , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ngap_PDUSessionID },
  { &hf_ngap_pDUSessionResourceModifyConfirmTransfer, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ngap_T_pDUSessionResourceModifyConfirmTransfer },
  { &hf_ngap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ngap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_ngap_PDUSessionResourceModifyItemModCfm(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ngap_PDUSessionResourceModifyItemModCfm, PDUSessionResourceModifyItemModCfm_sequence);

  return offset;
}


static const per_sequence_t PDUSessionResourceModifyListModCfm_sequence_of[1] = {
  { &hf_ngap_PDUSessionResourceModifyListModCfm_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ngap_PDUSessionResourceModifyItemModCfm },
};

static int
dissect_ngap_PDUSessionResourceModifyListModCfm(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_ngap_PDUSessionResourceModifyListModCfm, PDUSessionResourceModifyListModCfm_sequence_of,
                                                  1, maxnoofPDUSessions, FALSE);

  return offset;
}



static int
dissect_ngap_T_pDUSessionResourceModifyIndicationTransfer(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_octet_string_containing_pdu_new(tvb, offset, actx, tree, hf_index,
                                                                NO_BOUND, NO_BOUND, FALSE, dissect_PDUSessionResourceModifyIndicationTransfer_PDU);

  return offset;
}


static const per_sequence_t PDUSessionResourceModifyItemModInd_sequence[] = {
  { &hf_ngap_pDUSessionID   , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ngap_PDUSessionID },
  { &hf_ngap_pDUSessionResourceModifyIndicationTransfer, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ngap_T_pDUSessionResourceModifyIndicationTransfer },
  { &hf_ngap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ngap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_ngap_PDUSessionResourceModifyItemModInd(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ngap_PDUSessionResourceModifyItemModInd, PDUSessionResourceModifyItemModInd_sequence);

  return offset;
}


static const per_sequence_t PDUSessionResourceModifyListModInd_sequence_of[1] = {
  { &hf_ngap_PDUSessionResourceModifyListModInd_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ngap_PDUSessionResourceModifyItemModInd },
};

static int
dissect_ngap_PDUSessionResourceModifyListModInd(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_ngap_PDUSessionResourceModifyListModInd, PDUSessionResourceModifyListModInd_sequence_of,
                                                  1, maxnoofPDUSessions, FALSE);

  return offset;
}



static int
dissect_ngap_T_pDUSessionResourceModifyRequestTransfer(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_octet_string_containing_pdu_new(tvb, offset, actx, tree, hf_index,
                                                                NO_BOUND, NO_BOUND, FALSE, dissect_PDUSessionResourceModifyRequestTransfer_PDU);

  return offset;
}


static const per_sequence_t PDUSessionResourceModifyItemModReq_sequence[] = {
  { &hf_ngap_pDUSessionID   , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ngap_PDUSessionID },
  { &hf_ngap_nAS_PDU        , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ngap_NAS_PDU },
  { &hf_ngap_pDUSessionResourceModifyRequestTransfer, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ngap_T_pDUSessionResourceModifyRequestTransfer },
  { &hf_ngap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ngap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_ngap_PDUSessionResourceModifyItemModReq(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ngap_PDUSessionResourceModifyItemModReq, PDUSessionResourceModifyItemModReq_sequence);

  return offset;
}


static const per_sequence_t PDUSessionResourceModifyListModReq_sequence_of[1] = {
  { &hf_ngap_PDUSessionResourceModifyListModReq_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ngap_PDUSessionResourceModifyItemModReq },
};

static int
dissect_ngap_PDUSessionResourceModifyListModReq(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_ngap_PDUSessionResourceModifyListModReq, PDUSessionResourceModifyListModReq_sequence_of,
                                                  1, maxnoofPDUSessions, FALSE);

  return offset;
}



static int
dissect_ngap_T_pDUSessionResourceModifyResponseTransfer(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_octet_string_containing_pdu_new(tvb, offset, actx, tree, hf_index,
                                                                NO_BOUND, NO_BOUND, FALSE, dissect_PDUSessionResourceModifyResponseTransfer_PDU);

  return offset;
}


static const per_sequence_t PDUSessionResourceModifyItemModRes_sequence[] = {
  { &hf_ngap_pDUSessionID   , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ngap_PDUSessionID },
  { &hf_ngap_pDUSessionResourceModifyResponseTransfer, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ngap_T_pDUSessionResourceModifyResponseTransfer },
  { &hf_ngap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ngap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_ngap_PDUSessionResourceModifyItemModRes(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ngap_PDUSessionResourceModifyItemModRes, PDUSessionResourceModifyItemModRes_sequence);

  return offset;
}


static const per_sequence_t PDUSessionResourceModifyListModRes_sequence_of[1] = {
  { &hf_ngap_PDUSessionResourceModifyListModRes_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ngap_PDUSessionResourceModifyItemModRes },
};

static int
dissect_ngap_PDUSessionResourceModifyListModRes(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_ngap_PDUSessionResourceModifyListModRes, PDUSessionResourceModifyListModRes_sequence_of,
                                                  1, maxnoofPDUSessions, FALSE);

  return offset;
}


static const per_sequence_t PDUSessionResourceModifyUnsuccessfulTransfer_sequence[] = {
  { &hf_ngap_cause          , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ngap_Cause },
  { &hf_ngap_criticalityDiagnostics, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ngap_CriticalityDiagnostics },
  { &hf_ngap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ngap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_ngap_PDUSessionResourceModifyUnsuccessfulTransfer(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ngap_PDUSessionResourceModifyUnsuccessfulTransfer, PDUSessionResourceModifyUnsuccessfulTransfer_sequence);

  return offset;
}



static int
dissect_ngap_T_pDUSessionResourceNotifyTransfer(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_octet_string_containing_pdu_new(tvb, offset, actx, tree, hf_index,
                                                                NO_BOUND, NO_BOUND, FALSE, dissect_PDUSessionResourceNotifyTransfer_PDU);

  return offset;
}


static const per_sequence_t PDUSessionResourceNotifyItem_sequence[] = {
  { &hf_ngap_pDUSessionID   , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ngap_PDUSessionID },
  { &hf_ngap_pDUSessionResourceNotifyTransfer, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ngap_T_pDUSessionResourceNotifyTransfer },
  { &hf_ngap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ngap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_ngap_PDUSessionResourceNotifyItem(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ngap_PDUSessionResourceNotifyItem, PDUSessionResourceNotifyItem_sequence);

  return offset;
}


static const per_sequence_t PDUSessionResourceNotifyList_sequence_of[1] = {
  { &hf_ngap_PDUSessionResourceNotifyList_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ngap_PDUSessionResourceNotifyItem },
};

static int
dissect_ngap_PDUSessionResourceNotifyList(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_ngap_PDUSessionResourceNotifyList, PDUSessionResourceNotifyList_sequence_of,
                                                  1, maxnoofPDUSessions, FALSE);

  return offset;
}


static const per_sequence_t PDUSessionResourceNotifyReleasedTransfer_sequence[] = {
  { &hf_ngap_cause          , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ngap_Cause },
  { &hf_ngap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ngap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_ngap_PDUSessionResourceNotifyReleasedTransfer(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ngap_PDUSessionResourceNotifyReleasedTransfer, PDUSessionResourceNotifyReleasedTransfer_sequence);

  return offset;
}


static const per_sequence_t QosFlowNotifyItem_sequence[] = {
  { &hf_ngap_qosFlowIdentifier, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ngap_QosFlowIdentifier },
  { &hf_ngap_notificationCause, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ngap_NotificationCause },
  { &hf_ngap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ngap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_ngap_QosFlowNotifyItem(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ngap_QosFlowNotifyItem, QosFlowNotifyItem_sequence);

  return offset;
}


static const per_sequence_t QosFlowNotifyList_sequence_of[1] = {
  { &hf_ngap_QosFlowNotifyList_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ngap_QosFlowNotifyItem },
};

static int
dissect_ngap_QosFlowNotifyList(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_ngap_QosFlowNotifyList, QosFlowNotifyList_sequence_of,
                                                  1, maxnoofQosFlows, FALSE);

  return offset;
}


static const per_sequence_t PDUSessionResourceNotifyTransfer_sequence[] = {
  { &hf_ngap_qosFlowNotifyList, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ngap_QosFlowNotifyList },
  { &hf_ngap_qosFlowReleasedList, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ngap_QosFlowListWithCause },
  { &hf_ngap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ngap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_ngap_PDUSessionResourceNotifyTransfer(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ngap_PDUSessionResourceNotifyTransfer, PDUSessionResourceNotifyTransfer_sequence);

  return offset;
}


static const per_sequence_t PDUSessionResourceReleaseCommandTransfer_sequence[] = {
  { &hf_ngap_cause          , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ngap_Cause },
  { &hf_ngap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ngap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_ngap_PDUSessionResourceReleaseCommandTransfer(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ngap_PDUSessionResourceReleaseCommandTransfer, PDUSessionResourceReleaseCommandTransfer_sequence);

  return offset;
}



static int
dissect_ngap_T_pDUSessionResourceNotifyReleasedTransfer(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_octet_string_containing_pdu_new(tvb, offset, actx, tree, hf_index,
                                                                NO_BOUND, NO_BOUND, FALSE, dissect_PDUSessionResourceNotifyReleasedTransfer_PDU);

  return offset;
}


static const per_sequence_t PDUSessionResourceReleasedItemNot_sequence[] = {
  { &hf_ngap_pDUSessionID   , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ngap_PDUSessionID },
  { &hf_ngap_pDUSessionResourceNotifyReleasedTransfer, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ngap_T_pDUSessionResourceNotifyReleasedTransfer },
  { &hf_ngap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ngap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_ngap_PDUSessionResourceReleasedItemNot(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ngap_PDUSessionResourceReleasedItemNot, PDUSessionResourceReleasedItemNot_sequence);

  return offset;
}


static const per_sequence_t PDUSessionResourceReleasedListNot_sequence_of[1] = {
  { &hf_ngap_PDUSessionResourceReleasedListNot_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ngap_PDUSessionResourceReleasedItemNot },
};

static int
dissect_ngap_PDUSessionResourceReleasedListNot(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_ngap_PDUSessionResourceReleasedListNot, PDUSessionResourceReleasedListNot_sequence_of,
                                                  1, maxnoofPDUSessions, FALSE);

  return offset;
}



static int
dissect_ngap_T_pathSwitchRequestUnsuccessfulTransfer(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_octet_string_containing_pdu_new(tvb, offset, actx, tree, hf_index,
                                                                NO_BOUND, NO_BOUND, FALSE, dissect_PathSwitchRequestUnsuccessfulTransfer_PDU);

  return offset;
}


static const per_sequence_t PDUSessionResourceReleasedItemPSAck_sequence[] = {
  { &hf_ngap_pDUSessionID   , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ngap_PDUSessionID },
  { &hf_ngap_pathSwitchRequestUnsuccessfulTransfer, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ngap_T_pathSwitchRequestUnsuccessfulTransfer },
  { &hf_ngap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ngap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_ngap_PDUSessionResourceReleasedItemPSAck(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ngap_PDUSessionResourceReleasedItemPSAck, PDUSessionResourceReleasedItemPSAck_sequence);

  return offset;
}


static const per_sequence_t PDUSessionResourceReleasedListPSAck_sequence_of[1] = {
  { &hf_ngap_PDUSessionResourceReleasedListPSAck_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ngap_PDUSessionResourceReleasedItemPSAck },
};

static int
dissect_ngap_PDUSessionResourceReleasedListPSAck(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_ngap_PDUSessionResourceReleasedListPSAck, PDUSessionResourceReleasedListPSAck_sequence_of,
                                                  1, maxnoofPDUSessions, FALSE);

  return offset;
}



static int
dissect_ngap_T_pathSwitchRequestUnsuccessfulTransfer_01(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_octet_string_containing_pdu_new(tvb, offset, actx, tree, hf_index,
                                                                NO_BOUND, NO_BOUND, FALSE, dissect_PathSwitchRequestUnsuccessfulTransfer_PDU);

  return offset;
}


static const per_sequence_t PDUSessionResourceReleasedItemPSFail_sequence[] = {
  { &hf_ngap_pDUSessionID   , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ngap_PDUSessionID },
  { &hf_ngap_pathSwitchRequestUnsuccessfulTransfer_01, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ngap_T_pathSwitchRequestUnsuccessfulTransfer_01 },
  { &hf_ngap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ngap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_ngap_PDUSessionResourceReleasedItemPSFail(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ngap_PDUSessionResourceReleasedItemPSFail, PDUSessionResourceReleasedItemPSFail_sequence);

  return offset;
}


static const per_sequence_t PDUSessionResourceReleasedListPSFail_sequence_of[1] = {
  { &hf_ngap_PDUSessionResourceReleasedListPSFail_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ngap_PDUSessionResourceReleasedItemPSFail },
};

static int
dissect_ngap_PDUSessionResourceReleasedListPSFail(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_ngap_PDUSessionResourceReleasedListPSFail, PDUSessionResourceReleasedListPSFail_sequence_of,
                                                  1, maxnoofPDUSessions, FALSE);

  return offset;
}



static int
dissect_ngap_T_pDUSessionResourceReleaseResponseTransfer(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_octet_string_containing_pdu_new(tvb, offset, actx, tree, hf_index,
                                                                NO_BOUND, NO_BOUND, FALSE, dissect_PDUSessionResourceReleaseResponseTransfer_PDU);

  return offset;
}


static const per_sequence_t PDUSessionResourceReleasedItemRelRes_sequence[] = {
  { &hf_ngap_pDUSessionID   , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ngap_PDUSessionID },
  { &hf_ngap_pDUSessionResourceReleaseResponseTransfer, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ngap_T_pDUSessionResourceReleaseResponseTransfer },
  { &hf_ngap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ngap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_ngap_PDUSessionResourceReleasedItemRelRes(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ngap_PDUSessionResourceReleasedItemRelRes, PDUSessionResourceReleasedItemRelRes_sequence);

  return offset;
}


static const per_sequence_t PDUSessionResourceReleasedListRelRes_sequence_of[1] = {
  { &hf_ngap_PDUSessionResourceReleasedListRelRes_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ngap_PDUSessionResourceReleasedItemRelRes },
};

static int
dissect_ngap_PDUSessionResourceReleasedListRelRes(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_ngap_PDUSessionResourceReleasedListRelRes, PDUSessionResourceReleasedListRelRes_sequence_of,
                                                  1, maxnoofPDUSessions, FALSE);

  return offset;
}


static const per_sequence_t PDUSessionResourceReleaseResponseTransfer_sequence[] = {
  { &hf_ngap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ngap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_ngap_PDUSessionResourceReleaseResponseTransfer(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ngap_PDUSessionResourceReleaseResponseTransfer, PDUSessionResourceReleaseResponseTransfer_sequence);

  return offset;
}



static int
dissect_ngap_T_secondaryRATDataUsageReportTransfer(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_octet_string_containing_pdu_new(tvb, offset, actx, tree, hf_index,
                                                                NO_BOUND, NO_BOUND, FALSE, dissect_SecondaryRATDataUsageReportTransfer_PDU);

  return offset;
}


static const per_sequence_t PDUSessionResourceSecondaryRATUsageItem_sequence[] = {
  { &hf_ngap_pDUSessionID   , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ngap_PDUSessionID },
  { &hf_ngap_secondaryRATDataUsageReportTransfer, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ngap_T_secondaryRATDataUsageReportTransfer },
  { &hf_ngap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ngap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_ngap_PDUSessionResourceSecondaryRATUsageItem(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ngap_PDUSessionResourceSecondaryRATUsageItem, PDUSessionResourceSecondaryRATUsageItem_sequence);

  return offset;
}


static const per_sequence_t PDUSessionResourceSecondaryRATUsageList_sequence_of[1] = {
  { &hf_ngap_PDUSessionResourceSecondaryRATUsageList_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ngap_PDUSessionResourceSecondaryRATUsageItem },
};

static int
dissect_ngap_PDUSessionResourceSecondaryRATUsageList(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_ngap_PDUSessionResourceSecondaryRATUsageList, PDUSessionResourceSecondaryRATUsageList_sequence_of,
                                                  1, maxnoofPDUSessions, FALSE);

  return offset;
}



static int
dissect_ngap_T_pDUSessionResourceSetupRequestTransfer(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_octet_string_containing_pdu_new(tvb, offset, actx, tree, hf_index,
                                                                NO_BOUND, NO_BOUND, FALSE, dissect_PDUSessionResourceSetupRequestTransfer_PDU);

  return offset;
}


static const per_sequence_t PDUSessionResourceSetupItemCxtReq_sequence[] = {
  { &hf_ngap_pDUSessionID   , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ngap_PDUSessionID },
  { &hf_ngap_nAS_PDU        , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ngap_NAS_PDU },
  { &hf_ngap_s_NSSAI        , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ngap_S_NSSAI },
  { &hf_ngap_pDUSessionResourceSetupRequestTransfer, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ngap_T_pDUSessionResourceSetupRequestTransfer },
  { &hf_ngap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ngap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_ngap_PDUSessionResourceSetupItemCxtReq(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ngap_PDUSessionResourceSetupItemCxtReq, PDUSessionResourceSetupItemCxtReq_sequence);

  return offset;
}


static const per_sequence_t PDUSessionResourceSetupListCxtReq_sequence_of[1] = {
  { &hf_ngap_PDUSessionResourceSetupListCxtReq_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ngap_PDUSessionResourceSetupItemCxtReq },
};

static int
dissect_ngap_PDUSessionResourceSetupListCxtReq(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_ngap_PDUSessionResourceSetupListCxtReq, PDUSessionResourceSetupListCxtReq_sequence_of,
                                                  1, maxnoofPDUSessions, FALSE);

  return offset;
}



static int
dissect_ngap_T_pDUSessionResourceSetupResponseTransfer(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_octet_string_containing_pdu_new(tvb, offset, actx, tree, hf_index,
                                                                NO_BOUND, NO_BOUND, FALSE, dissect_PDUSessionResourceSetupResponseTransfer_PDU);

  return offset;
}


static const per_sequence_t PDUSessionResourceSetupItemCxtRes_sequence[] = {
  { &hf_ngap_pDUSessionID   , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ngap_PDUSessionID },
  { &hf_ngap_pDUSessionResourceSetupResponseTransfer, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ngap_T_pDUSessionResourceSetupResponseTransfer },
  { &hf_ngap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ngap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_ngap_PDUSessionResourceSetupItemCxtRes(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ngap_PDUSessionResourceSetupItemCxtRes, PDUSessionResourceSetupItemCxtRes_sequence);

  return offset;
}


static const per_sequence_t PDUSessionResourceSetupListCxtRes_sequence_of[1] = {
  { &hf_ngap_PDUSessionResourceSetupListCxtRes_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ngap_PDUSessionResourceSetupItemCxtRes },
};

static int
dissect_ngap_PDUSessionResourceSetupListCxtRes(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_ngap_PDUSessionResourceSetupListCxtRes, PDUSessionResourceSetupListCxtRes_sequence_of,
                                                  1, maxnoofPDUSessions, FALSE);

  return offset;
}



static int
dissect_ngap_T_handoverRequestTransfer(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_octet_string_containing_pdu_new(tvb, offset, actx, tree, hf_index,
                                                                NO_BOUND, NO_BOUND, FALSE, dissect_PDUSessionResourceSetupRequestTransfer_PDU);

  return offset;
}


static const per_sequence_t PDUSessionResourceSetupItemHOReq_sequence[] = {
  { &hf_ngap_pDUSessionID   , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ngap_PDUSessionID },
  { &hf_ngap_s_NSSAI        , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ngap_S_NSSAI },
  { &hf_ngap_handoverRequestTransfer, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ngap_T_handoverRequestTransfer },
  { &hf_ngap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ngap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_ngap_PDUSessionResourceSetupItemHOReq(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ngap_PDUSessionResourceSetupItemHOReq, PDUSessionResourceSetupItemHOReq_sequence);

  return offset;
}


static const per_sequence_t PDUSessionResourceSetupListHOReq_sequence_of[1] = {
  { &hf_ngap_PDUSessionResourceSetupListHOReq_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ngap_PDUSessionResourceSetupItemHOReq },
};

static int
dissect_ngap_PDUSessionResourceSetupListHOReq(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_ngap_PDUSessionResourceSetupListHOReq, PDUSessionResourceSetupListHOReq_sequence_of,
                                                  1, maxnoofPDUSessions, FALSE);

  return offset;
}



static int
dissect_ngap_T_pDUSessionResourceSetupRequestTransfer_01(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_octet_string_containing_pdu_new(tvb, offset, actx, tree, hf_index,
                                                                NO_BOUND, NO_BOUND, FALSE, dissect_PDUSessionResourceSetupRequestTransfer_PDU);

  return offset;
}


static const per_sequence_t PDUSessionResourceSetupItemSUReq_sequence[] = {
  { &hf_ngap_pDUSessionID   , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ngap_PDUSessionID },
  { &hf_ngap_pDUSessionNAS_PDU, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ngap_NAS_PDU },
  { &hf_ngap_s_NSSAI        , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ngap_S_NSSAI },
  { &hf_ngap_pDUSessionResourceSetupRequestTransfer_01, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ngap_T_pDUSessionResourceSetupRequestTransfer_01 },
  { &hf_ngap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ngap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_ngap_PDUSessionResourceSetupItemSUReq(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ngap_PDUSessionResourceSetupItemSUReq, PDUSessionResourceSetupItemSUReq_sequence);

  return offset;
}


static const per_sequence_t PDUSessionResourceSetupListSUReq_sequence_of[1] = {
  { &hf_ngap_PDUSessionResourceSetupListSUReq_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ngap_PDUSessionResourceSetupItemSUReq },
};

static int
dissect_ngap_PDUSessionResourceSetupListSUReq(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_ngap_PDUSessionResourceSetupListSUReq, PDUSessionResourceSetupListSUReq_sequence_of,
                                                  1, maxnoofPDUSessions, FALSE);

  return offset;
}



static int
dissect_ngap_T_pDUSessionResourceSetupResponseTransfer_01(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_octet_string_containing_pdu_new(tvb, offset, actx, tree, hf_index,
                                                                NO_BOUND, NO_BOUND, FALSE, dissect_PDUSessionResourceSetupResponseTransfer_PDU);

  return offset;
}


static const per_sequence_t PDUSessionResourceSetupItemSURes_sequence[] = {
  { &hf_ngap_pDUSessionID   , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ngap_PDUSessionID },
  { &hf_ngap_pDUSessionResourceSetupResponseTransfer_01, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ngap_T_pDUSessionResourceSetupResponseTransfer_01 },
  { &hf_ngap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ngap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_ngap_PDUSessionResourceSetupItemSURes(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ngap_PDUSessionResourceSetupItemSURes, PDUSessionResourceSetupItemSURes_sequence);

  return offset;
}


static const per_sequence_t PDUSessionResourceSetupListSURes_sequence_of[1] = {
  { &hf_ngap_PDUSessionResourceSetupListSURes_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ngap_PDUSessionResourceSetupItemSURes },
};

static int
dissect_ngap_PDUSessionResourceSetupListSURes(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_ngap_PDUSessionResourceSetupListSURes, PDUSessionResourceSetupListSURes_sequence_of,
                                                  1, maxnoofPDUSessions, FALSE);

  return offset;
}


static const per_sequence_t PDUSessionResourceSetupRequestTransfer_sequence[] = {
  { &hf_ngap_protocolIEs    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ngap_ProtocolIE_Container },
  { NULL, 0, 0, NULL }
};

static int
dissect_ngap_PDUSessionResourceSetupRequestTransfer(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ngap_PDUSessionResourceSetupRequestTransfer, PDUSessionResourceSetupRequestTransfer_sequence);

  return offset;
}


static const per_sequence_t PDUSessionResourceSetupResponseTransfer_sequence[] = {
  { &hf_ngap_dLQosFlowPerTNLInformation, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ngap_QosFlowPerTNLInformation },
  { &hf_ngap_additionalDLQosFlowPerTNLInformation, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ngap_QosFlowPerTNLInformationList },
  { &hf_ngap_securityResult , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ngap_SecurityResult },
  { &hf_ngap_qosFlowFailedToSetupList, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ngap_QosFlowListWithCause },
  { &hf_ngap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ngap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_ngap_PDUSessionResourceSetupResponseTransfer(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ngap_PDUSessionResourceSetupResponseTransfer, PDUSessionResourceSetupResponseTransfer_sequence);

  return offset;
}


static const per_sequence_t PDUSessionResourceSetupUnsuccessfulTransfer_sequence[] = {
  { &hf_ngap_cause          , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ngap_Cause },
  { &hf_ngap_criticalityDiagnostics, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ngap_CriticalityDiagnostics },
  { &hf_ngap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ngap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_ngap_PDUSessionResourceSetupUnsuccessfulTransfer(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ngap_PDUSessionResourceSetupUnsuccessfulTransfer, PDUSessionResourceSetupUnsuccessfulTransfer_sequence);

  return offset;
}



static int
dissect_ngap_T_pathSwitchRequestAcknowledgeTransfer(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_octet_string_containing_pdu_new(tvb, offset, actx, tree, hf_index,
                                                                NO_BOUND, NO_BOUND, FALSE, dissect_PathSwitchRequestAcknowledgeTransfer_PDU);

  return offset;
}


static const per_sequence_t PDUSessionResourceSwitchedItem_sequence[] = {
  { &hf_ngap_pDUSessionID   , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ngap_PDUSessionID },
  { &hf_ngap_pathSwitchRequestAcknowledgeTransfer, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ngap_T_pathSwitchRequestAcknowledgeTransfer },
  { &hf_ngap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ngap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_ngap_PDUSessionResourceSwitchedItem(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ngap_PDUSessionResourceSwitchedItem, PDUSessionResourceSwitchedItem_sequence);

  return offset;
}


static const per_sequence_t PDUSessionResourceSwitchedList_sequence_of[1] = {
  { &hf_ngap_PDUSessionResourceSwitchedList_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ngap_PDUSessionResourceSwitchedItem },
};

static int
dissect_ngap_PDUSessionResourceSwitchedList(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_ngap_PDUSessionResourceSwitchedList, PDUSessionResourceSwitchedList_sequence_of,
                                                  1, maxnoofPDUSessions, FALSE);

  return offset;
}



static int
dissect_ngap_T_pathSwitchRequestTransfer(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_octet_string_containing_pdu_new(tvb, offset, actx, tree, hf_index,
                                                                NO_BOUND, NO_BOUND, FALSE, dissect_PathSwitchRequestTransfer_PDU);

  return offset;
}


static const per_sequence_t PDUSessionResourceToBeSwitchedDLItem_sequence[] = {
  { &hf_ngap_pDUSessionID   , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ngap_PDUSessionID },
  { &hf_ngap_pathSwitchRequestTransfer, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ngap_T_pathSwitchRequestTransfer },
  { &hf_ngap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ngap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_ngap_PDUSessionResourceToBeSwitchedDLItem(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ngap_PDUSessionResourceToBeSwitchedDLItem, PDUSessionResourceToBeSwitchedDLItem_sequence);

  return offset;
}


static const per_sequence_t PDUSessionResourceToBeSwitchedDLList_sequence_of[1] = {
  { &hf_ngap_PDUSessionResourceToBeSwitchedDLList_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ngap_PDUSessionResourceToBeSwitchedDLItem },
};

static int
dissect_ngap_PDUSessionResourceToBeSwitchedDLList(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_ngap_PDUSessionResourceToBeSwitchedDLList, PDUSessionResourceToBeSwitchedDLList_sequence_of,
                                                  1, maxnoofPDUSessions, FALSE);

  return offset;
}



static int
dissect_ngap_T_handoverPreparationUnsuccessfulTransfer(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_octet_string_containing_pdu_new(tvb, offset, actx, tree, hf_index,
                                                                NO_BOUND, NO_BOUND, FALSE, dissect_HandoverPreparationUnsuccessfulTransfer_PDU);

  return offset;
}


static const per_sequence_t PDUSessionResourceToReleaseItemHOCmd_sequence[] = {
  { &hf_ngap_pDUSessionID   , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ngap_PDUSessionID },
  { &hf_ngap_handoverPreparationUnsuccessfulTransfer, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ngap_T_handoverPreparationUnsuccessfulTransfer },
  { &hf_ngap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ngap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_ngap_PDUSessionResourceToReleaseItemHOCmd(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ngap_PDUSessionResourceToReleaseItemHOCmd, PDUSessionResourceToReleaseItemHOCmd_sequence);

  return offset;
}


static const per_sequence_t PDUSessionResourceToReleaseListHOCmd_sequence_of[1] = {
  { &hf_ngap_PDUSessionResourceToReleaseListHOCmd_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ngap_PDUSessionResourceToReleaseItemHOCmd },
};

static int
dissect_ngap_PDUSessionResourceToReleaseListHOCmd(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_ngap_PDUSessionResourceToReleaseListHOCmd, PDUSessionResourceToReleaseListHOCmd_sequence_of,
                                                  1, maxnoofPDUSessions, FALSE);

  return offset;
}



static int
dissect_ngap_T_pDUSessionResourceReleaseCommandTransfer(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_octet_string_containing_pdu_new(tvb, offset, actx, tree, hf_index,
                                                                NO_BOUND, NO_BOUND, FALSE, dissect_PDUSessionResourceReleaseCommandTransfer_PDU);

  return offset;
}


static const per_sequence_t PDUSessionResourceToReleaseItemRelCmd_sequence[] = {
  { &hf_ngap_pDUSessionID   , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ngap_PDUSessionID },
  { &hf_ngap_pDUSessionResourceReleaseCommandTransfer, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ngap_T_pDUSessionResourceReleaseCommandTransfer },
  { &hf_ngap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ngap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_ngap_PDUSessionResourceToReleaseItemRelCmd(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ngap_PDUSessionResourceToReleaseItemRelCmd, PDUSessionResourceToReleaseItemRelCmd_sequence);

  return offset;
}


static const per_sequence_t PDUSessionResourceToReleaseListRelCmd_sequence_of[1] = {
  { &hf_ngap_PDUSessionResourceToReleaseListRelCmd_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ngap_PDUSessionResourceToReleaseItemRelCmd },
};

static int
dissect_ngap_PDUSessionResourceToReleaseListRelCmd(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_ngap_PDUSessionResourceToReleaseListRelCmd, PDUSessionResourceToReleaseListRelCmd_sequence_of,
                                                  1, maxnoofPDUSessions, FALSE);

  return offset;
}


static const value_string ngap_PDUSessionType_vals[] = {
  {   0, "ipv4" },
  {   1, "ipv6" },
  {   2, "ipv4v6" },
  {   3, "ethernet" },
  {   4, "unstructured" },
  { 0, NULL }
};


static int
dissect_ngap_PDUSessionType(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     5, NULL, TRUE, 0, NULL);

  return offset;
}


static const value_string ngap_T_rATType_vals[] = {
  {   0, "nr" },
  {   1, "eutra" },
  { 0, NULL }
};


static int
dissect_ngap_T_rATType(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     2, NULL, TRUE, 0, NULL);

  return offset;
}



static int
dissect_ngap_T_startTimeStamp(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 740 "./asn1/ngap/ngap.cnf"
  tvbuff_t *timestamp_tvb = NULL;
  offset = dissect_per_octet_string(tvb, offset, actx, tree, hf_index,
                                       4, 4, FALSE, &timestamp_tvb);




#line 744 "./asn1/ngap/ngap.cnf"
  if (timestamp_tvb) {
    proto_item_append_text(actx->created_item, " (%s)", tvb_ntp_fmt_ts_sec(timestamp_tvb, 0));
  }


  return offset;
}



static int
dissect_ngap_T_endTimeStamp(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 749 "./asn1/ngap/ngap.cnf"
  tvbuff_t *timestamp_tvb = NULL;
  offset = dissect_per_octet_string(tvb, offset, actx, tree, hf_index,
                                       4, 4, FALSE, &timestamp_tvb);




#line 753 "./asn1/ngap/ngap.cnf"
  if (timestamp_tvb) {
    proto_item_append_text(actx->created_item, " (%s)", tvb_ntp_fmt_ts_sec(timestamp_tvb, 0));
  }


  return offset;
}



static int
dissect_ngap_INTEGER_0_18446744073709551615(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer_64b(tvb, offset, actx, tree, hf_index,
                                                            0U, G_GUINT64_CONSTANT(18446744073709551615), NULL, FALSE);

  return offset;
}


static const per_sequence_t VolumeTimedReport_Item_sequence[] = {
  { &hf_ngap_startTimeStamp , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ngap_T_startTimeStamp },
  { &hf_ngap_endTimeStamp   , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ngap_T_endTimeStamp },
  { &hf_ngap_usageCountUL   , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ngap_INTEGER_0_18446744073709551615 },
  { &hf_ngap_usageCountDL   , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ngap_INTEGER_0_18446744073709551615 },
  { &hf_ngap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ngap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_ngap_VolumeTimedReport_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ngap_VolumeTimedReport_Item, VolumeTimedReport_Item_sequence);

  return offset;
}


static const per_sequence_t VolumeTimedReportList_sequence_of[1] = {
  { &hf_ngap_VolumeTimedReportList_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ngap_VolumeTimedReport_Item },
};

static int
dissect_ngap_VolumeTimedReportList(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_ngap_VolumeTimedReportList, VolumeTimedReportList_sequence_of,
                                                  1, maxnoofTimePeriods, FALSE);

  return offset;
}


static const per_sequence_t PDUSessionUsageReport_sequence[] = {
  { &hf_ngap_rATType        , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ngap_T_rATType },
  { &hf_ngap_pDUSessionTimedReportList, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ngap_VolumeTimedReportList },
  { &hf_ngap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ngap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_ngap_PDUSessionUsageReport(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ngap_PDUSessionUsageReport, PDUSessionUsageReport_sequence);

  return offset;
}


static const per_sequence_t PLMNSupportItem_sequence[] = {
  { &hf_ngap_pLMNIdentity   , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ngap_PLMNIdentity },
  { &hf_ngap_sliceSupportList, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ngap_SliceSupportList },
  { &hf_ngap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ngap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_ngap_PLMNSupportItem(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ngap_PLMNSupportItem, PLMNSupportItem_sequence);

  return offset;
}


static const per_sequence_t PLMNSupportList_sequence_of[1] = {
  { &hf_ngap_PLMNSupportList_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ngap_PLMNSupportItem },
};

static int
dissect_ngap_PLMNSupportList(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_ngap_PLMNSupportList, PLMNSupportList_sequence_of,
                                                  1, maxnoofPLMNs, FALSE);

  return offset;
}


static const value_string ngap_PWSFailedCellIDList_vals[] = {
  {   0, "eUTRA-CGI-PWSFailedList" },
  {   1, "nR-CGI-PWSFailedList" },
  {   2, "choice-Extensions" },
  { 0, NULL }
};

static const per_choice_t PWSFailedCellIDList_choice[] = {
  {   0, &hf_ngap_eUTRA_CGI_PWSFailedList, ASN1_NO_EXTENSIONS     , dissect_ngap_EUTRA_CGIList },
  {   1, &hf_ngap_nR_CGI_PWSFailedList, ASN1_NO_EXTENSIONS     , dissect_ngap_NR_CGIList },
  {   2, &hf_ngap_choice_Extensions, ASN1_NO_EXTENSIONS     , dissect_ngap_ProtocolIE_SingleContainer },
  { 0, NULL, 0, NULL }
};

static int
dissect_ngap_PWSFailedCellIDList(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_ngap_PWSFailedCellIDList, PWSFailedCellIDList_choice,
                                 NULL);

  return offset;
}


static const value_string ngap_QosCharacteristics_vals[] = {
  {   0, "nonDynamic5QI" },
  {   1, "dynamic5QI" },
  {   2, "choice-Extensions" },
  { 0, NULL }
};

static const per_choice_t QosCharacteristics_choice[] = {
  {   0, &hf_ngap_nonDynamic5QI  , ASN1_NO_EXTENSIONS     , dissect_ngap_NonDynamic5QIDescriptor },
  {   1, &hf_ngap_dynamic5QI     , ASN1_NO_EXTENSIONS     , dissect_ngap_Dynamic5QIDescriptor },
  {   2, &hf_ngap_choice_Extensions, ASN1_NO_EXTENSIONS     , dissect_ngap_ProtocolIE_SingleContainer },
  { 0, NULL, 0, NULL }
};

static int
dissect_ngap_QosCharacteristics(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_ngap_QosCharacteristics, QosCharacteristics_choice,
                                 NULL);

  return offset;
}


static const value_string ngap_ReflectiveQosAttribute_vals[] = {
  {   0, "subject-to" },
  { 0, NULL }
};


static int
dissect_ngap_ReflectiveQosAttribute(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     1, NULL, TRUE, 0, NULL);

  return offset;
}


static const per_sequence_t QosFlowLevelQosParameters_sequence[] = {
  { &hf_ngap_qosCharacteristics, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ngap_QosCharacteristics },
  { &hf_ngap_allocationAndRetentionPriority, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ngap_AllocationAndRetentionPriority },
  { &hf_ngap_gBR_QosInformation, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ngap_GBR_QosInformation },
  { &hf_ngap_reflectiveQosAttribute, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ngap_ReflectiveQosAttribute },
  { &hf_ngap_additionalQosFlowInformation, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ngap_AdditionalQosFlowInformation },
  { &hf_ngap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ngap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_ngap_QosFlowLevelQosParameters(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ngap_QosFlowLevelQosParameters, QosFlowLevelQosParameters_sequence);

  return offset;
}


static const per_sequence_t QosFlowAddOrModifyRequestItem_sequence[] = {
  { &hf_ngap_qosFlowIdentifier, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ngap_QosFlowIdentifier },
  { &hf_ngap_qosFlowLevelQosParameters, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ngap_QosFlowLevelQosParameters },
  { &hf_ngap_e_RAB_ID       , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ngap_E_RAB_ID },
  { &hf_ngap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ngap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_ngap_QosFlowAddOrModifyRequestItem(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ngap_QosFlowAddOrModifyRequestItem, QosFlowAddOrModifyRequestItem_sequence);

  return offset;
}


static const per_sequence_t QosFlowAddOrModifyRequestList_sequence_of[1] = {
  { &hf_ngap_QosFlowAddOrModifyRequestList_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ngap_QosFlowAddOrModifyRequestItem },
};

static int
dissect_ngap_QosFlowAddOrModifyRequestList(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_ngap_QosFlowAddOrModifyRequestList, QosFlowAddOrModifyRequestList_sequence_of,
                                                  1, maxnoofQosFlows, FALSE);

  return offset;
}


static const per_sequence_t QosFlowSetupRequestItem_sequence[] = {
  { &hf_ngap_qosFlowIdentifier, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ngap_QosFlowIdentifier },
  { &hf_ngap_qosFlowLevelQosParameters, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ngap_QosFlowLevelQosParameters },
  { &hf_ngap_e_RAB_ID       , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ngap_E_RAB_ID },
  { &hf_ngap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ngap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_ngap_QosFlowSetupRequestItem(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ngap_QosFlowSetupRequestItem, QosFlowSetupRequestItem_sequence);

  return offset;
}


static const per_sequence_t QosFlowSetupRequestList_sequence_of[1] = {
  { &hf_ngap_QosFlowSetupRequestList_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ngap_QosFlowSetupRequestItem },
};

static int
dissect_ngap_QosFlowSetupRequestList(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_ngap_QosFlowSetupRequestList, QosFlowSetupRequestList_sequence_of,
                                                  1, maxnoofQosFlows, FALSE);

  return offset;
}


static const value_string ngap_T_rATType_01_vals[] = {
  {   0, "nr" },
  {   1, "eutra" },
  { 0, NULL }
};


static int
dissect_ngap_T_rATType_01(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     2, NULL, TRUE, 0, NULL);

  return offset;
}


static const per_sequence_t QoSFlowsUsageReport_Item_sequence[] = {
  { &hf_ngap_qosFlowIdentifier, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ngap_QosFlowIdentifier },
  { &hf_ngap_rATType_01     , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ngap_T_rATType_01 },
  { &hf_ngap_qoSFlowsTimedReportList, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ngap_VolumeTimedReportList },
  { &hf_ngap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ngap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_ngap_QoSFlowsUsageReport_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ngap_QoSFlowsUsageReport_Item, QoSFlowsUsageReport_Item_sequence);

  return offset;
}


static const per_sequence_t QoSFlowsUsageReportList_sequence_of[1] = {
  { &hf_ngap_QoSFlowsUsageReportList_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ngap_QoSFlowsUsageReport_Item },
};

static int
dissect_ngap_QoSFlowsUsageReportList(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_ngap_QoSFlowsUsageReportList, QoSFlowsUsageReportList_sequence_of,
                                                  1, maxnoofQosFlows, FALSE);

  return offset;
}



static int
dissect_ngap_RANNodeName(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_PrintableString(tvb, offset, actx, tree, hf_index,
                                          1, 150, TRUE);

  return offset;
}



static int
dissect_ngap_RANPagingPriority(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            1U, 256U, NULL, FALSE);

  return offset;
}


static const per_sequence_t RANStatusTransfer_TransparentContainer_sequence[] = {
  { &hf_ngap_dRBsSubjectToStatusTransferList, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ngap_DRBsSubjectToStatusTransferList },
  { &hf_ngap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ngap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_ngap_RANStatusTransfer_TransparentContainer(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ngap_RANStatusTransfer_TransparentContainer, RANStatusTransfer_TransparentContainer_sequence);

  return offset;
}



static int
dissect_ngap_RAN_UE_NGAP_ID(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 4294967295U, NULL, FALSE);

  return offset;
}


static const value_string ngap_RedirectionVoiceFallback_vals[] = {
  {   0, "possible" },
  {   1, "not-possible" },
  { 0, NULL }
};


static int
dissect_ngap_RedirectionVoiceFallback(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     2, NULL, TRUE, 0, NULL);

  return offset;
}



static int
dissect_ngap_RelativeAMFCapacity(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 255U, NULL, FALSE);

  return offset;
}



static int
dissect_ngap_RepetitionPeriod(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 131071U, NULL, FALSE);

  return offset;
}


static const value_string ngap_ResetAll_vals[] = {
  {   0, "reset-all" },
  { 0, NULL }
};


static int
dissect_ngap_ResetAll(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     1, NULL, TRUE, 0, NULL);

  return offset;
}


static const per_sequence_t UE_associatedLogicalNG_connectionItem_sequence[] = {
  { &hf_ngap_aMF_UE_NGAP_ID , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ngap_AMF_UE_NGAP_ID },
  { &hf_ngap_rAN_UE_NGAP_ID , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ngap_RAN_UE_NGAP_ID },
  { &hf_ngap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ngap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_ngap_UE_associatedLogicalNG_connectionItem(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ngap_UE_associatedLogicalNG_connectionItem, UE_associatedLogicalNG_connectionItem_sequence);

  return offset;
}


static const per_sequence_t UE_associatedLogicalNG_connectionList_sequence_of[1] = {
  { &hf_ngap_UE_associatedLogicalNG_connectionList_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ngap_UE_associatedLogicalNG_connectionItem },
};

static int
dissect_ngap_UE_associatedLogicalNG_connectionList(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_ngap_UE_associatedLogicalNG_connectionList, UE_associatedLogicalNG_connectionList_sequence_of,
                                                  1, maxnoofNGConnectionsToReset, FALSE);

  return offset;
}


static const value_string ngap_ResetType_vals[] = {
  {   0, "nG-Interface" },
  {   1, "partOfNG-Interface" },
  {   2, "choice-Extensions" },
  { 0, NULL }
};

static const per_choice_t ResetType_choice[] = {
  {   0, &hf_ngap_nG_Interface   , ASN1_NO_EXTENSIONS     , dissect_ngap_ResetAll },
  {   1, &hf_ngap_partOfNG_Interface, ASN1_NO_EXTENSIONS     , dissect_ngap_UE_associatedLogicalNG_connectionList },
  {   2, &hf_ngap_choice_Extensions, ASN1_NO_EXTENSIONS     , dissect_ngap_ProtocolIE_SingleContainer },
  { 0, NULL, 0, NULL }
};

static int
dissect_ngap_ResetType(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_ngap_ResetType, ResetType_choice,
                                 NULL);

  return offset;
}



static int
dissect_ngap_RoutingID(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_octet_string(tvb, offset, actx, tree, hf_index,
                                       NO_BOUND, NO_BOUND, FALSE, NULL);

  return offset;
}



static int
dissect_ngap_RRCContainer(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 509 "./asn1/ngap/ngap.cnf"
  tvbuff_t *parameter_tvb = NULL;

  offset = dissect_per_octet_string(tvb, offset, actx, tree, hf_index,
                                       NO_BOUND, NO_BOUND, FALSE, &parameter_tvb);

  if (parameter_tvb) {
    struct ngap_private_data *ngap_data = ngap_get_private_data(actx->pinfo);
    proto_tree *subtree;
    GlobalRANNodeID_enum ranmode_id;

    if (ngap_data->transparent_container_type == SOURCE_TO_TARGET_TRANSPARENT_CONTAINER) {
      ranmode_id = ngap_get_ranmode_id(&actx->pinfo->dst, actx->pinfo->destport, actx->pinfo);
    } else if (ngap_data->transparent_container_type == TARGET_TO_SOURCE_TRANSPARENT_CONTAINER) {
      ranmode_id = ngap_get_ranmode_id(&actx->pinfo->src, actx->pinfo->srcport, actx->pinfo);
    } else {
      ranmode_id = (GlobalRANNodeID_enum)-1;
    }
    subtree = proto_item_add_subtree(actx->created_item, ett_ngap_RRCContainer);
    if ((ngap_dissect_target_ng_ran_container_as == NGAP_NG_RAN_CONTAINER_AUTOMATIC &&
         ranmode_id == globalGNB_ID) ||
        (ngap_dissect_target_ng_ran_container_as == NGAP_NG_RAN_CONTAINER_GNB)) {
      if (ngap_data->transparent_container_type == SOURCE_TO_TARGET_TRANSPARENT_CONTAINER) {
        dissect_nr_rrc_HandoverPreparationInformation_PDU(parameter_tvb, actx->pinfo, subtree, NULL);
      } else if (ngap_data->transparent_container_type == TARGET_TO_SOURCE_TRANSPARENT_CONTAINER) {
        dissect_nr_rrc_HandoverCommand_PDU(parameter_tvb, actx->pinfo, subtree, NULL);
      }
    } else if ((ngap_dissect_target_ng_ran_container_as == NGAP_NG_RAN_CONTAINER_AUTOMATIC &&
                ranmode_id == globalNgENB_ID) ||
               (ngap_dissect_target_ng_ran_container_as == NGAP_NG_RAN_CONTAINER_NG_ENB)) {
      if (ngap_data->transparent_container_type == SOURCE_TO_TARGET_TRANSPARENT_CONTAINER) {
        dissect_lte_rrc_HandoverPreparationInformation_PDU(parameter_tvb, actx->pinfo, subtree, NULL);
      } else if (ngap_data->transparent_container_type == TARGET_TO_SOURCE_TRANSPARENT_CONTAINER) {
        dissect_lte_rrc_HandoverCommand_PDU(parameter_tvb, actx->pinfo, subtree, NULL);
      }
    }
  }



  return offset;
}


static const value_string ngap_RRCEstablishmentCause_vals[] = {
  {   0, "emergency" },
  {   1, "highPriorityAccess" },
  {   2, "mt-Access" },
  {   3, "mo-Signalling" },
  {   4, "mo-Data" },
  {   5, "mo-VoiceCall" },
  {   6, "mo-VideoCall" },
  {   7, "mo-SMS" },
  {   8, "mps-PriorityAccess" },
  {   9, "mcs-PriorityAccess" },
  {  10, "notAvailable" },
  { 0, NULL }
};


static int
dissect_ngap_RRCEstablishmentCause(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     10, NULL, TRUE, 1, NULL);

  return offset;
}


static const value_string ngap_RRCInactiveTransitionReportRequest_vals[] = {
  {   0, "subsequent-state-transition-report" },
  {   1, "single-rrc-connected-state-report" },
  {   2, "cancel-report" },
  { 0, NULL }
};


static int
dissect_ngap_RRCInactiveTransitionReportRequest(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     3, NULL, TRUE, 0, NULL);

  return offset;
}


static const value_string ngap_RRCState_vals[] = {
  {   0, "inactive" },
  {   1, "connected" },
  { 0, NULL }
};


static int
dissect_ngap_RRCState(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     2, NULL, TRUE, 0, NULL);

  return offset;
}


static const per_sequence_t SCTP_TLAs_sequence_of[1] = {
  { &hf_ngap_SCTP_TLAs_item , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ngap_TransportLayerAddress },
};

static int
dissect_ngap_SCTP_TLAs(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_ngap_SCTP_TLAs, SCTP_TLAs_sequence_of,
                                                  1, maxnoofXnTLAs, FALSE);

  return offset;
}


static const per_sequence_t SecondaryRATUsageInformation_sequence[] = {
  { &hf_ngap_pDUSessionUsageReport, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ngap_PDUSessionUsageReport },
  { &hf_ngap_qosFlowsUsageReportList, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ngap_QoSFlowsUsageReportList },
  { &hf_ngap_iE_Extension   , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ngap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_ngap_SecondaryRATUsageInformation(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ngap_SecondaryRATUsageInformation, SecondaryRATUsageInformation_sequence);

  return offset;
}


static const per_sequence_t SecondaryRATDataUsageReportTransfer_sequence[] = {
  { &hf_ngap_secondaryRATUsageInformation, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ngap_SecondaryRATUsageInformation },
  { &hf_ngap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ngap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_ngap_SecondaryRATDataUsageReportTransfer(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ngap_SecondaryRATDataUsageReportTransfer, SecondaryRATDataUsageReportTransfer_sequence);

  return offset;
}



static int
dissect_ngap_SecurityKey(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_bit_string(tvb, offset, actx, tree, hf_index,
                                     256, 256, FALSE, NULL, 0, NULL, NULL);

  return offset;
}


static const per_sequence_t SecurityContext_sequence[] = {
  { &hf_ngap_nextHopChainingCount, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ngap_NextHopChainingCount },
  { &hf_ngap_nextHopNH      , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ngap_SecurityKey },
  { &hf_ngap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ngap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_ngap_SecurityContext(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ngap_SecurityContext, SecurityContext_sequence);

  return offset;
}



static int
dissect_ngap_SerialNumber(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_bit_string(tvb, offset, actx, tree, hf_index,
                                     16, 16, FALSE, NULL, 0, NULL, NULL);

  return offset;
}


static const per_sequence_t ServedGUAMIItem_sequence[] = {
  { &hf_ngap_gUAMI          , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ngap_GUAMI },
  { &hf_ngap_backupAMFName  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ngap_AMFName },
  { &hf_ngap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ngap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_ngap_ServedGUAMIItem(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ngap_ServedGUAMIItem, ServedGUAMIItem_sequence);

  return offset;
}


static const per_sequence_t ServedGUAMIList_sequence_of[1] = {
  { &hf_ngap_ServedGUAMIList_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ngap_ServedGUAMIItem },
};

static int
dissect_ngap_ServedGUAMIList(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_ngap_ServedGUAMIList, ServedGUAMIList_sequence_of,
                                                  1, maxnoofServedGUAMIs, FALSE);

  return offset;
}


static const per_sequence_t TargetRANNodeID_sequence[] = {
  { &hf_ngap_globalRANNodeID, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ngap_GlobalRANNodeID },
  { &hf_ngap_selectedTAI    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ngap_TAI },
  { &hf_ngap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ngap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_ngap_TargetRANNodeID(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ngap_TargetRANNodeID, TargetRANNodeID_sequence);

  return offset;
}


static const per_sequence_t SourceRANNodeID_sequence[] = {
  { &hf_ngap_globalRANNodeID, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ngap_GlobalRANNodeID },
  { &hf_ngap_selectedTAI    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ngap_TAI },
  { &hf_ngap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ngap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_ngap_SourceRANNodeID(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ngap_SourceRANNodeID, SourceRANNodeID_sequence);

  return offset;
}


static const value_string ngap_SONInformationRequest_vals[] = {
  {   0, "xn-TNL-configuration-info" },
  { 0, NULL }
};


static int
dissect_ngap_SONInformationRequest(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     1, NULL, TRUE, 0, NULL);

  return offset;
}


static const per_sequence_t XnTLAs_sequence_of[1] = {
  { &hf_ngap_XnTLAs_item    , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ngap_TransportLayerAddress },
};

static int
dissect_ngap_XnTLAs(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_ngap_XnTLAs, XnTLAs_sequence_of,
                                                  1, maxnoofXnTLAs, FALSE);

  return offset;
}


static const per_sequence_t XnGTP_TLAs_sequence_of[1] = {
  { &hf_ngap_XnGTP_TLAs_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ngap_TransportLayerAddress },
};

static int
dissect_ngap_XnGTP_TLAs(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_ngap_XnGTP_TLAs, XnGTP_TLAs_sequence_of,
                                                  1, maxnoofXnGTP_TLAs, FALSE);

  return offset;
}


static const per_sequence_t XnExtTLA_Item_sequence[] = {
  { &hf_ngap_iPsecTLA       , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ngap_TransportLayerAddress },
  { &hf_ngap_gTP_TLAs       , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ngap_XnGTP_TLAs },
  { &hf_ngap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ngap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_ngap_XnExtTLA_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ngap_XnExtTLA_Item, XnExtTLA_Item_sequence);

  return offset;
}


static const per_sequence_t XnExtTLAs_sequence_of[1] = {
  { &hf_ngap_XnExtTLAs_item , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ngap_XnExtTLA_Item },
};

static int
dissect_ngap_XnExtTLAs(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_ngap_XnExtTLAs, XnExtTLAs_sequence_of,
                                                  1, maxnoofXnExtTLAs, FALSE);

  return offset;
}


static const per_sequence_t XnTNLConfigurationInfo_sequence[] = {
  { &hf_ngap_xnTransportLayerAddresses, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ngap_XnTLAs },
  { &hf_ngap_xnExtendedTransportLayerAddresses, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ngap_XnExtTLAs },
  { &hf_ngap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ngap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_ngap_XnTNLConfigurationInfo(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ngap_XnTNLConfigurationInfo, XnTNLConfigurationInfo_sequence);

  return offset;
}


static const per_sequence_t SONInformationReply_sequence[] = {
  { &hf_ngap_xnTNLConfigurationInfo, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ngap_XnTNLConfigurationInfo },
  { &hf_ngap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ngap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_ngap_SONInformationReply(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ngap_SONInformationReply, SONInformationReply_sequence);

  return offset;
}


static const value_string ngap_SONInformation_vals[] = {
  {   0, "sONInformationRequest" },
  {   1, "sONInformationReply" },
  {   2, "choice-Extensions" },
  { 0, NULL }
};

static const per_choice_t SONInformation_choice[] = {
  {   0, &hf_ngap_sONInformationRequest, ASN1_NO_EXTENSIONS     , dissect_ngap_SONInformationRequest },
  {   1, &hf_ngap_sONInformationReply, ASN1_NO_EXTENSIONS     , dissect_ngap_SONInformationReply },
  {   2, &hf_ngap_choice_Extensions, ASN1_NO_EXTENSIONS     , dissect_ngap_ProtocolIE_SingleContainer },
  { 0, NULL, 0, NULL }
};

static int
dissect_ngap_SONInformation(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_ngap_SONInformation, SONInformation_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t SONConfigurationTransfer_sequence[] = {
  { &hf_ngap_targetRANNodeID, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ngap_TargetRANNodeID },
  { &hf_ngap_sourceRANNodeID, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ngap_SourceRANNodeID },
  { &hf_ngap_sONInformation , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ngap_SONInformation },
  { &hf_ngap_xnTNLConfigurationInfo, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ngap_XnTNLConfigurationInfo },
  { &hf_ngap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ngap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_ngap_SONConfigurationTransfer(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ngap_SONConfigurationTransfer, SONConfigurationTransfer_sequence);

  return offset;
}


static const per_sequence_t UEHistoryInformation_sequence_of[1] = {
  { &hf_ngap_UEHistoryInformation_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ngap_LastVisitedCellItem },
};

static int
dissect_ngap_UEHistoryInformation(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_ngap_UEHistoryInformation, UEHistoryInformation_sequence_of,
                                                  1, maxnoofCellsinUEHistoryInfo, FALSE);

  return offset;
}


static const per_sequence_t SourceNGRANNode_ToTargetNGRANNode_TransparentContainer_sequence[] = {
  { &hf_ngap_rRCContainer   , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ngap_RRCContainer },
  { &hf_ngap_pDUSessionResourceInformationList, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ngap_PDUSessionResourceInformationList },
  { &hf_ngap_e_RABInformationList, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ngap_E_RABInformationList },
  { &hf_ngap_targetCell_ID  , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ngap_NGRAN_CGI },
  { &hf_ngap_indexToRFSP    , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ngap_IndexToRFSP },
  { &hf_ngap_uEHistoryInformation, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ngap_UEHistoryInformation },
  { &hf_ngap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ngap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_ngap_SourceNGRANNode_ToTargetNGRANNode_TransparentContainer(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 498 "./asn1/ngap/ngap.cnf"
  struct ngap_private_data *ngap_data = ngap_get_private_data(actx->pinfo);

  ngap_data->transparent_container_type = SOURCE_TO_TARGET_TRANSPARENT_CONTAINER;



  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ngap_SourceNGRANNode_ToTargetNGRANNode_TransparentContainer, SourceNGRANNode_ToTargetNGRANNode_TransparentContainer_sequence);

  return offset;
}



static int
dissect_ngap_SourceToTarget_TransparentContainer(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 259 "./asn1/ngap/ngap.cnf"
  tvbuff_t *parameter_tvb;
  proto_tree *subtree;
  offset = dissect_per_octet_string(tvb, offset, actx, tree, hf_index,
                                       NO_BOUND, NO_BOUND, FALSE, &parameter_tvb);

  if (ngap_dissect_container && parameter_tvb &&
      tvb_reported_length(parameter_tvb) > 0) {
    struct ngap_private_data *ngap_data = ngap_get_private_data(actx->pinfo);
    /* Don't want elements inside container to write to info column */
    col_set_writable(actx->pinfo->cinfo, COL_INFO, FALSE);
    subtree = proto_item_add_subtree(actx->created_item, ett_ngap_SourceToTarget_TransparentContainer);
    switch(ngap_data->handover_type_value) {
    case intra5gs:
    case eps_to_5gs:
      dissect_ngap_SourceNGRANNode_ToTargetNGRANNode_TransparentContainer_PDU(parameter_tvb, actx->pinfo, subtree, NULL);
      break;
    case fivegs_to_eps:
      dissect_s1ap_SourceeNB_ToTargeteNB_TransparentContainer_PDU(parameter_tvb, actx->pinfo, subtree, NULL);
      break;
    default:
      break;
    }
    /* Enable writing of the column again */
    col_set_writable(actx->pinfo->cinfo, COL_INFO, TRUE);
  }



  return offset;
}



static int
dissect_ngap_ConfiguredNSSAI(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_octet_string(tvb, offset, actx, tree, hf_index,
                                       128, 128, FALSE, NULL);

  return offset;
}



static int
dissect_ngap_RejectedNSSAIinPLMN(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_octet_string(tvb, offset, actx, tree, hf_index,
                                       32, 32, FALSE, NULL);

  return offset;
}



static int
dissect_ngap_RejectedNSSAIinTA(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_octet_string(tvb, offset, actx, tree, hf_index,
                                       32, 32, FALSE, NULL);

  return offset;
}


static const per_sequence_t SourceToTarget_AMFInformationReroute_sequence[] = {
  { &hf_ngap_configuredNSSAI, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ngap_ConfiguredNSSAI },
  { &hf_ngap_rejectedNSSAIinPLMN, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ngap_RejectedNSSAIinPLMN },
  { &hf_ngap_rejectedNSSAIinTA, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ngap_RejectedNSSAIinTA },
  { &hf_ngap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ngap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_ngap_SourceToTarget_AMFInformationReroute(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ngap_SourceToTarget_AMFInformationReroute, SourceToTarget_AMFInformationReroute_sequence);

  return offset;
}


static const per_sequence_t SupportedTAItem_sequence[] = {
  { &hf_ngap_tAC            , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ngap_TAC },
  { &hf_ngap_broadcastPLMNList, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ngap_BroadcastPLMNList },
  { &hf_ngap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ngap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_ngap_SupportedTAItem(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ngap_SupportedTAItem, SupportedTAItem_sequence);

  return offset;
}


static const per_sequence_t SupportedTAList_sequence_of[1] = {
  { &hf_ngap_SupportedTAList_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ngap_SupportedTAItem },
};

static int
dissect_ngap_SupportedTAList(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_ngap_SupportedTAList, SupportedTAList_sequence_of,
                                                  1, maxnoofTACs, FALSE);

  return offset;
}


static const per_sequence_t TAIListForPagingItem_sequence[] = {
  { &hf_ngap_tAI            , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ngap_TAI },
  { &hf_ngap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ngap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_ngap_TAIListForPagingItem(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ngap_TAIListForPagingItem, TAIListForPagingItem_sequence);

  return offset;
}


static const per_sequence_t TAIListForPaging_sequence_of[1] = {
  { &hf_ngap_TAIListForPaging_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ngap_TAIListForPagingItem },
};

static int
dissect_ngap_TAIListForPaging(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_ngap_TAIListForPaging, TAIListForPaging_sequence_of,
                                                  1, maxnoofTAIforPaging, FALSE);

  return offset;
}


static const per_sequence_t TAIListForRestart_sequence_of[1] = {
  { &hf_ngap_TAIListForRestart_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ngap_TAI },
};

static int
dissect_ngap_TAIListForRestart(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_ngap_TAIListForRestart, TAIListForRestart_sequence_of,
                                                  1, maxnoofTAIforRestart, FALSE);

  return offset;
}


static const per_sequence_t TAIListForWarning_sequence_of[1] = {
  { &hf_ngap_TAIListForWarning_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ngap_TAI },
};

static int
dissect_ngap_TAIListForWarning(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_ngap_TAIListForWarning, TAIListForWarning_sequence_of,
                                                  1, maxnoofTAIforWarning, FALSE);

  return offset;
}


static const per_sequence_t TargeteNB_ID_sequence[] = {
  { &hf_ngap_globalENB_ID   , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ngap_GlobalNgENB_ID },
  { &hf_ngap_selected_EPS_TAI, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ngap_EPS_TAI },
  { &hf_ngap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ngap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_ngap_TargeteNB_ID(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ngap_TargeteNB_ID, TargeteNB_ID_sequence);

  return offset;
}


static const value_string ngap_TargetID_vals[] = {
  {   0, "targetRANNodeID" },
  {   1, "targeteNB-ID" },
  {   2, "choice-Extensions" },
  { 0, NULL }
};

static const per_choice_t TargetID_choice[] = {
  {   0, &hf_ngap_targetRANNodeID, ASN1_NO_EXTENSIONS     , dissect_ngap_TargetRANNodeID },
  {   1, &hf_ngap_targeteNB_ID   , ASN1_NO_EXTENSIONS     , dissect_ngap_TargeteNB_ID },
  {   2, &hf_ngap_choice_Extensions, ASN1_NO_EXTENSIONS     , dissect_ngap_ProtocolIE_SingleContainer },
  { 0, NULL, 0, NULL }
};

static int
dissect_ngap_TargetID(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_ngap_TargetID, TargetID_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t TargetNGRANNode_ToSourceNGRANNode_TransparentContainer_sequence[] = {
  { &hf_ngap_rRCContainer   , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ngap_RRCContainer },
  { &hf_ngap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ngap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_ngap_TargetNGRANNode_ToSourceNGRANNode_TransparentContainer(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 504 "./asn1/ngap/ngap.cnf"
  struct ngap_private_data *ngap_data = ngap_get_private_data(actx->pinfo);

  ngap_data->transparent_container_type = TARGET_TO_SOURCE_TRANSPARENT_CONTAINER;


  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ngap_TargetNGRANNode_ToSourceNGRANNode_TransparentContainer, TargetNGRANNode_ToSourceNGRANNode_TransparentContainer_sequence);

  return offset;
}



static int
dissect_ngap_TargetToSource_TransparentContainer(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 284 "./asn1/ngap/ngap.cnf"
  tvbuff_t *parameter_tvb;
  proto_tree *subtree;
  offset = dissect_per_octet_string(tvb, offset, actx, tree, hf_index,
                                       NO_BOUND, NO_BOUND, FALSE, &parameter_tvb);

  if (ngap_dissect_container && parameter_tvb &&
      tvb_reported_length(parameter_tvb) > 0) {
    struct ngap_private_data *ngap_data = ngap_get_private_data(actx->pinfo);
    /* Don't want elements inside container to write to info column */
    col_set_writable(actx->pinfo->cinfo, COL_INFO, FALSE);
    subtree = proto_item_add_subtree(actx->created_item, ett_ngap_TargetToSource_TransparentContainer);
    if (ngap_data->procedure_code == id_HandoverPreparation) {
      switch(ngap_data->handover_type_value) {
      case intra5gs:
      case eps_to_5gs:
        dissect_ngap_TargetNGRANNode_ToSourceNGRANNode_TransparentContainer_PDU(parameter_tvb, actx->pinfo, subtree, NULL);
        break;
      case fivegs_to_eps:
        dissect_s1ap_TargeteNB_ToSourceeNB_TransparentContainer_PDU(parameter_tvb, actx->pinfo, subtree, NULL);
        break;
      default:
        break;
      }
    } else {
      if (ngap_dissect_target_ng_ran_container_as == NGAP_NG_RAN_CONTAINER_GNB) {
        dissect_ngap_TargetNGRANNode_ToSourceNGRANNode_TransparentContainer_PDU(parameter_tvb, actx->pinfo, subtree, NULL);
      } else if (ngap_dissect_target_ng_ran_container_as == NGAP_NG_RAN_CONTAINER_NG_ENB) {
        dissect_s1ap_TargeteNB_ToSourceeNB_TransparentContainer_PDU(parameter_tvb, actx->pinfo, subtree, NULL);
      }
    }
    /* Enable writing of the column again */
    col_set_writable(actx->pinfo->cinfo, COL_INFO, TRUE);
  }



  return offset;
}


static const value_string ngap_TimerApproachForGUAMIRemoval_vals[] = {
  {   0, "apply-timer" },
  { 0, NULL }
};


static int
dissect_ngap_TimerApproachForGUAMIRemoval(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     1, NULL, TRUE, 0, NULL);

  return offset;
}



static int
dissect_ngap_TimeStamp(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 581 "./asn1/ngap/ngap.cnf"
  tvbuff_t *timestamp_tvb = NULL;
  offset = dissect_per_octet_string(tvb, offset, actx, tree, hf_index,
                                       4, 4, FALSE, &timestamp_tvb);




#line 585 "./asn1/ngap/ngap.cnf"
  if (timestamp_tvb) {
    proto_item_append_text(actx->created_item, " (%s)", tvb_ntp_fmt_ts_sec(timestamp_tvb, 0));
  }


  return offset;
}


static const value_string ngap_TimeToWait_vals[] = {
  {   0, "v1s" },
  {   1, "v2s" },
  {   2, "v5s" },
  {   3, "v10s" },
  {   4, "v20s" },
  {   5, "v60s" },
  { 0, NULL }
};


static int
dissect_ngap_TimeToWait(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     6, NULL, TRUE, 0, NULL);

  return offset;
}


static const per_sequence_t TNLAssociationItem_sequence[] = {
  { &hf_ngap_tNLAssociationAddress, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ngap_CPTransportLayerInformation },
  { &hf_ngap_cause          , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ngap_Cause },
  { &hf_ngap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ngap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_ngap_TNLAssociationItem(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ngap_TNLAssociationItem, TNLAssociationItem_sequence);

  return offset;
}


static const per_sequence_t TNLAssociationList_sequence_of[1] = {
  { &hf_ngap_TNLAssociationList_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ngap_TNLAssociationItem },
};

static int
dissect_ngap_TNLAssociationList(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_ngap_TNLAssociationList, TNLAssociationList_sequence_of,
                                                  1, maxnoofTNLAssociations, FALSE);

  return offset;
}


static const value_string ngap_TraceDepth_vals[] = {
  {   0, "minimum" },
  {   1, "medium" },
  {   2, "maximum" },
  {   3, "minimumWithoutVendorSpecificExtension" },
  {   4, "mediumWithoutVendorSpecificExtension" },
  {   5, "maximumWithoutVendorSpecificExtension" },
  { 0, NULL }
};


static int
dissect_ngap_TraceDepth(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     6, NULL, TRUE, 0, NULL);

  return offset;
}


static const per_sequence_t TraceActivation_sequence[] = {
  { &hf_ngap_nGRANTraceID   , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ngap_NGRANTraceID },
  { &hf_ngap_interfacesToTrace, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ngap_InterfacesToTrace },
  { &hf_ngap_traceDepth     , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ngap_TraceDepth },
  { &hf_ngap_traceCollectionEntityIPAddress, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ngap_TransportLayerAddress },
  { &hf_ngap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ngap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_ngap_TraceActivation(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ngap_TraceActivation, TraceActivation_sequence);

  return offset;
}


static const per_sequence_t UEAggregateMaximumBitRate_sequence[] = {
  { &hf_ngap_uEAggregateMaximumBitRateDL, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ngap_BitRate },
  { &hf_ngap_uEAggregateMaximumBitRateUL, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ngap_BitRate },
  { &hf_ngap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ngap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_ngap_UEAggregateMaximumBitRate(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ngap_UEAggregateMaximumBitRate, UEAggregateMaximumBitRate_sequence);

  return offset;
}


static const value_string ngap_UEContextRequest_vals[] = {
  {   0, "requested" },
  { 0, NULL }
};


static int
dissect_ngap_UEContextRequest(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     1, NULL, TRUE, 0, NULL);

  return offset;
}


static const per_sequence_t UE_NGAP_ID_pair_sequence[] = {
  { &hf_ngap_aMF_UE_NGAP_ID , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ngap_AMF_UE_NGAP_ID },
  { &hf_ngap_rAN_UE_NGAP_ID , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ngap_RAN_UE_NGAP_ID },
  { &hf_ngap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ngap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_ngap_UE_NGAP_ID_pair(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ngap_UE_NGAP_ID_pair, UE_NGAP_ID_pair_sequence);

  return offset;
}


static const value_string ngap_UE_NGAP_IDs_vals[] = {
  {   0, "uE-NGAP-ID-pair" },
  {   1, "aMF-UE-NGAP-ID" },
  {   2, "choice-Extensions" },
  { 0, NULL }
};

static const per_choice_t UE_NGAP_IDs_choice[] = {
  {   0, &hf_ngap_uE_NGAP_ID_pair, ASN1_NO_EXTENSIONS     , dissect_ngap_UE_NGAP_ID_pair },
  {   1, &hf_ngap_aMF_UE_NGAP_ID , ASN1_NO_EXTENSIONS     , dissect_ngap_AMF_UE_NGAP_ID },
  {   2, &hf_ngap_choice_Extensions, ASN1_NO_EXTENSIONS     , dissect_ngap_ProtocolIE_SingleContainer },
  { 0, NULL, 0, NULL }
};

static int
dissect_ngap_UE_NGAP_IDs(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_ngap_UE_NGAP_IDs, UE_NGAP_IDs_choice,
                                 NULL);

  return offset;
}


static const value_string ngap_UEPagingIdentity_vals[] = {
  {   0, "fiveG-S-TMSI" },
  {   1, "choice-Extensions" },
  { 0, NULL }
};

static const per_choice_t UEPagingIdentity_choice[] = {
  {   0, &hf_ngap_fiveG_S_TMSI   , ASN1_NO_EXTENSIONS     , dissect_ngap_FiveG_S_TMSI },
  {   1, &hf_ngap_choice_Extensions, ASN1_NO_EXTENSIONS     , dissect_ngap_ProtocolIE_SingleContainer },
  { 0, NULL, 0, NULL }
};

static int
dissect_ngap_UEPagingIdentity(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_ngap_UEPagingIdentity, UEPagingIdentity_choice,
                                 NULL);

  return offset;
}


static const value_string ngap_UEPresence_vals[] = {
  {   0, "in" },
  {   1, "out" },
  {   2, "unknown" },
  { 0, NULL }
};


static int
dissect_ngap_UEPresence(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     3, NULL, TRUE, 0, NULL);

  return offset;
}


static const per_sequence_t UEPresenceInAreaOfInterestItem_sequence[] = {
  { &hf_ngap_locationReportingReferenceID, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ngap_LocationReportingReferenceID },
  { &hf_ngap_uEPresence     , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ngap_UEPresence },
  { &hf_ngap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ngap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_ngap_UEPresenceInAreaOfInterestItem(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ngap_UEPresenceInAreaOfInterestItem, UEPresenceInAreaOfInterestItem_sequence);

  return offset;
}


static const per_sequence_t UEPresenceInAreaOfInterestList_sequence_of[1] = {
  { &hf_ngap_UEPresenceInAreaOfInterestList_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ngap_UEPresenceInAreaOfInterestItem },
};

static int
dissect_ngap_UEPresenceInAreaOfInterestList(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_ngap_UEPresenceInAreaOfInterestList, UEPresenceInAreaOfInterestList_sequence_of,
                                                  1, maxnoofAoI, FALSE);

  return offset;
}



static int
dissect_ngap_UERadioCapability(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 570 "./asn1/ngap/ngap.cnf"
  tvbuff_t *parameter_tvb = NULL;

  offset = dissect_per_octet_string(tvb, offset, actx, tree, hf_index,
                                       NO_BOUND, NO_BOUND, FALSE, &parameter_tvb);

  if (parameter_tvb && nr_rrc_ue_radio_access_cap_info_handle) {
    proto_tree *subtree;

    subtree = proto_item_add_subtree(actx->created_item, ett_ngap_UERadioCapability);
    call_dissector(nr_rrc_ue_radio_access_cap_info_handle, parameter_tvb, actx->pinfo, subtree);
  }



  return offset;
}



static int
dissect_ngap_UERadioCapabilityForPagingOfNR(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 545 "./asn1/ngap/ngap.cnf"
  tvbuff_t *parameter_tvb = NULL;

  offset = dissect_per_octet_string(tvb, offset, actx, tree, hf_index,
                                       NO_BOUND, NO_BOUND, FALSE, &parameter_tvb);

  if (parameter_tvb && nr_rrc_ue_radio_paging_info_handle) {
    proto_tree *subtree;

    subtree = proto_item_add_subtree(actx->created_item, ett_ngap_UERadioCapabilityForPagingOfNR);
    call_dissector(nr_rrc_ue_radio_paging_info_handle, parameter_tvb, actx->pinfo, subtree);
  }



  return offset;
}



static int
dissect_ngap_UERadioCapabilityForPagingOfEUTRA(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 556 "./asn1/ngap/ngap.cnf"
  tvbuff_t *parameter_tvb = NULL;

  offset = dissect_per_octet_string(tvb, offset, actx, tree, hf_index,
                                       NO_BOUND, NO_BOUND, FALSE, &parameter_tvb);

  if (parameter_tvb && lte_rrc_ue_radio_paging_info_handle) {
    proto_tree *subtree;

    subtree = proto_item_add_subtree(actx->created_item, ett_ngap_UERadioCapabilityForPagingOfEUTRA);
    call_dissector(lte_rrc_ue_radio_paging_info_handle, parameter_tvb, actx->pinfo, subtree);
  }



  return offset;
}


static const per_sequence_t UERadioCapabilityForPaging_sequence[] = {
  { &hf_ngap_uERadioCapabilityForPagingOfNR, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ngap_UERadioCapabilityForPagingOfNR },
  { &hf_ngap_uERadioCapabilityForPagingOfEUTRA, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ngap_UERadioCapabilityForPagingOfEUTRA },
  { &hf_ngap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ngap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_ngap_UERadioCapabilityForPaging(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ngap_UERadioCapabilityForPaging, UERadioCapabilityForPaging_sequence);

  return offset;
}


static const value_string ngap_UERetentionInformation_vals[] = {
  {   0, "ues-retained" },
  { 0, NULL }
};


static int
dissect_ngap_UERetentionInformation(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     1, NULL, TRUE, 0, NULL);

  return offset;
}


static const per_sequence_t UESecurityCapabilities_sequence[] = {
  { &hf_ngap_nRencryptionAlgorithms, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ngap_NRencryptionAlgorithms },
  { &hf_ngap_nRintegrityProtectionAlgorithms, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ngap_NRintegrityProtectionAlgorithms },
  { &hf_ngap_eUTRAencryptionAlgorithms, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ngap_EUTRAencryptionAlgorithms },
  { &hf_ngap_eUTRAintegrityProtectionAlgorithms, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ngap_EUTRAintegrityProtectionAlgorithms },
  { &hf_ngap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ngap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_ngap_UESecurityCapabilities(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ngap_UESecurityCapabilities, UESecurityCapabilities_sequence);

  return offset;
}


static const per_sequence_t UL_NGU_UP_TNLModifyItem_sequence[] = {
  { &hf_ngap_uL_NGU_UP_TNLInformation, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ngap_UPTransportLayerInformation },
  { &hf_ngap_dL_NGU_UP_TNLInformation, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ngap_UPTransportLayerInformation },
  { &hf_ngap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ngap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_ngap_UL_NGU_UP_TNLModifyItem(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ngap_UL_NGU_UP_TNLModifyItem, UL_NGU_UP_TNLModifyItem_sequence);

  return offset;
}


static const per_sequence_t UL_NGU_UP_TNLModifyList_sequence_of[1] = {
  { &hf_ngap_UL_NGU_UP_TNLModifyList_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ngap_UL_NGU_UP_TNLModifyItem },
};

static int
dissect_ngap_UL_NGU_UP_TNLModifyList(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_ngap_UL_NGU_UP_TNLModifyList, UL_NGU_UP_TNLModifyList_sequence_of,
                                                  1, maxnoofMultiConnectivity, FALSE);

  return offset;
}


static const per_sequence_t UnavailableGUAMIItem_sequence[] = {
  { &hf_ngap_gUAMI          , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ngap_GUAMI },
  { &hf_ngap_timerApproachForGUAMIRemoval, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ngap_TimerApproachForGUAMIRemoval },
  { &hf_ngap_backupAMFName  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ngap_AMFName },
  { &hf_ngap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ngap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_ngap_UnavailableGUAMIItem(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ngap_UnavailableGUAMIItem, UnavailableGUAMIItem_sequence);

  return offset;
}


static const per_sequence_t UnavailableGUAMIList_sequence_of[1] = {
  { &hf_ngap_UnavailableGUAMIList_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ngap_UnavailableGUAMIItem },
};

static int
dissect_ngap_UnavailableGUAMIList(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_ngap_UnavailableGUAMIList, UnavailableGUAMIList_sequence_of,
                                                  1, maxnoofServedGUAMIs, FALSE);

  return offset;
}


static const value_string ngap_ULForwarding_vals[] = {
  {   0, "ul-forwarding-proposed" },
  { 0, NULL }
};


static int
dissect_ngap_ULForwarding(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     1, NULL, TRUE, 0, NULL);

  return offset;
}


static const per_sequence_t UPTransportLayerInformationItem_sequence[] = {
  { &hf_ngap_nGU_UP_TNLInformation, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ngap_UPTransportLayerInformation },
  { &hf_ngap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ngap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_ngap_UPTransportLayerInformationItem(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ngap_UPTransportLayerInformationItem, UPTransportLayerInformationItem_sequence);

  return offset;
}


static const per_sequence_t UPTransportLayerInformationList_sequence_of[1] = {
  { &hf_ngap_UPTransportLayerInformationList_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ngap_UPTransportLayerInformationItem },
};

static int
dissect_ngap_UPTransportLayerInformationList(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_ngap_UPTransportLayerInformationList, UPTransportLayerInformationList_sequence_of,
                                                  1, maxnoofMultiConnectivityMinusOne, FALSE);

  return offset;
}


static const per_sequence_t UserLocationInformationEUTRA_sequence[] = {
  { &hf_ngap_eUTRA_CGI      , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ngap_EUTRA_CGI },
  { &hf_ngap_tAI            , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ngap_TAI },
  { &hf_ngap_timeStamp      , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ngap_TimeStamp },
  { &hf_ngap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ngap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_ngap_UserLocationInformationEUTRA(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ngap_UserLocationInformationEUTRA, UserLocationInformationEUTRA_sequence);

  return offset;
}


static const per_sequence_t UserLocationInformationNR_sequence[] = {
  { &hf_ngap_nR_CGI         , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ngap_NR_CGI },
  { &hf_ngap_tAI            , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ngap_TAI },
  { &hf_ngap_timeStamp      , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ngap_TimeStamp },
  { &hf_ngap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ngap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_ngap_UserLocationInformationNR(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ngap_UserLocationInformationNR, UserLocationInformationNR_sequence);

  return offset;
}


static const per_sequence_t UserLocationInformationN3IWF_sequence[] = {
  { &hf_ngap_iPAddress      , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ngap_TransportLayerAddress },
  { &hf_ngap_portNumber     , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ngap_PortNumber },
  { &hf_ngap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ngap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_ngap_UserLocationInformationN3IWF(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ngap_UserLocationInformationN3IWF, UserLocationInformationN3IWF_sequence);

  return offset;
}


static const value_string ngap_UserLocationInformation_vals[] = {
  {   0, "userLocationInformationEUTRA" },
  {   1, "userLocationInformationNR" },
  {   2, "userLocationInformationN3IWF" },
  {   3, "choice-Extensions" },
  { 0, NULL }
};

static const per_choice_t UserLocationInformation_choice[] = {
  {   0, &hf_ngap_userLocationInformationEUTRA, ASN1_NO_EXTENSIONS     , dissect_ngap_UserLocationInformationEUTRA },
  {   1, &hf_ngap_userLocationInformationNR, ASN1_NO_EXTENSIONS     , dissect_ngap_UserLocationInformationNR },
  {   2, &hf_ngap_userLocationInformationN3IWF, ASN1_NO_EXTENSIONS     , dissect_ngap_UserLocationInformationN3IWF },
  {   3, &hf_ngap_choice_Extensions, ASN1_NO_EXTENSIONS     , dissect_ngap_ProtocolIE_SingleContainer },
  { 0, NULL, 0, NULL }
};

static int
dissect_ngap_UserLocationInformation(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_ngap_UserLocationInformation, UserLocationInformation_choice,
                                 NULL);

  return offset;
}



static int
dissect_ngap_WarningAreaCoordinates(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_octet_string(tvb, offset, actx, tree, hf_index,
                                       1, 1024, FALSE, NULL);

  return offset;
}


static const value_string ngap_WarningAreaList_vals[] = {
  {   0, "eUTRA-CGIListForWarning" },
  {   1, "nR-CGIListForWarning" },
  {   2, "tAIListForWarning" },
  {   3, "emergencyAreaIDList" },
  {   4, "choice-Extensions" },
  { 0, NULL }
};

static const per_choice_t WarningAreaList_choice[] = {
  {   0, &hf_ngap_eUTRA_CGIListForWarning, ASN1_NO_EXTENSIONS     , dissect_ngap_EUTRA_CGIListForWarning },
  {   1, &hf_ngap_nR_CGIListForWarning, ASN1_NO_EXTENSIONS     , dissect_ngap_NR_CGIListForWarning },
  {   2, &hf_ngap_tAIListForWarning, ASN1_NO_EXTENSIONS     , dissect_ngap_TAIListForWarning },
  {   3, &hf_ngap_emergencyAreaIDList, ASN1_NO_EXTENSIONS     , dissect_ngap_EmergencyAreaIDList },
  {   4, &hf_ngap_choice_Extensions, ASN1_NO_EXTENSIONS     , dissect_ngap_ProtocolIE_SingleContainer },
  { 0, NULL, 0, NULL }
};

static int
dissect_ngap_WarningAreaList(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_ngap_WarningAreaList, WarningAreaList_choice,
                                 NULL);

  return offset;
}



static int
dissect_ngap_WarningMessageContents(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 337 "./asn1/ngap/ngap.cnf"
  tvbuff_t *parameter_tvb = NULL;
  offset = dissect_per_octet_string(tvb, offset, actx, tree, hf_index,
                                       1, 9600, FALSE, &parameter_tvb);

  if (parameter_tvb) {
    struct ngap_private_data *ngap_data = ngap_get_private_data(actx->pinfo);
    proto_tree *subtree = proto_item_add_subtree(actx->created_item, ett_ngap_WarningMessageContents);
    dissect_ngap_warningMessageContents(parameter_tvb, subtree, actx->pinfo, ngap_data->data_coding_scheme,
                                        hf_ngap_WarningMessageContents_nb_pages, hf_ngap_WarningMessageContents_decoded_page);
  }



  return offset;
}



static int
dissect_ngap_WarningSecurityInfo(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_octet_string(tvb, offset, actx, tree, hf_index,
                                       50, 50, FALSE, NULL);

  return offset;
}



static int
dissect_ngap_WarningType(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_octet_string(tvb, offset, actx, tree, hf_index,
                                       2, 2, FALSE, NULL);

  return offset;
}


static const per_sequence_t PDUSessionResourceSetupRequest_sequence[] = {
  { &hf_ngap_protocolIEs    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ngap_ProtocolIE_Container },
  { NULL, 0, 0, NULL }
};

static int
dissect_ngap_PDUSessionResourceSetupRequest(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 1491 "./asn1/ngap/ngap.cnf"
  col_append_sep_str(actx->pinfo->cinfo, COL_INFO, NULL, "PDUSessionResourceSetupRequest");


  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ngap_PDUSessionResourceSetupRequest, PDUSessionResourceSetupRequest_sequence);

  return offset;
}


static const per_sequence_t PDUSessionResourceSetupResponse_sequence[] = {
  { &hf_ngap_protocolIEs    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ngap_ProtocolIE_Container },
  { NULL, 0, 0, NULL }
};

static int
dissect_ngap_PDUSessionResourceSetupResponse(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 1494 "./asn1/ngap/ngap.cnf"
  col_append_sep_str(actx->pinfo->cinfo, COL_INFO, NULL, "PDUSessionResourceSetupResponse");


  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ngap_PDUSessionResourceSetupResponse, PDUSessionResourceSetupResponse_sequence);

  return offset;
}


static const per_sequence_t PDUSessionResourceReleaseCommand_sequence[] = {
  { &hf_ngap_protocolIEs    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ngap_ProtocolIE_Container },
  { NULL, 0, 0, NULL }
};

static int
dissect_ngap_PDUSessionResourceReleaseCommand(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 1485 "./asn1/ngap/ngap.cnf"
  col_append_sep_str(actx->pinfo->cinfo, COL_INFO, NULL, "PDUSessionResourceReleaseCommand");


  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ngap_PDUSessionResourceReleaseCommand, PDUSessionResourceReleaseCommand_sequence);

  return offset;
}


static const per_sequence_t PDUSessionResourceReleaseResponse_sequence[] = {
  { &hf_ngap_protocolIEs    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ngap_ProtocolIE_Container },
  { NULL, 0, 0, NULL }
};

static int
dissect_ngap_PDUSessionResourceReleaseResponse(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 1488 "./asn1/ngap/ngap.cnf"
  col_append_sep_str(actx->pinfo->cinfo, COL_INFO, NULL, "PDUSessionResourceReleaseResponse");


  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ngap_PDUSessionResourceReleaseResponse, PDUSessionResourceReleaseResponse_sequence);

  return offset;
}


static const per_sequence_t PDUSessionResourceModifyRequest_sequence[] = {
  { &hf_ngap_protocolIEs    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ngap_ProtocolIE_Container },
  { NULL, 0, 0, NULL }
};

static int
dissect_ngap_PDUSessionResourceModifyRequest(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 1470 "./asn1/ngap/ngap.cnf"
  col_append_sep_str(actx->pinfo->cinfo, COL_INFO, NULL, "PDUSessionResourceModifyRequest");


  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ngap_PDUSessionResourceModifyRequest, PDUSessionResourceModifyRequest_sequence);

  return offset;
}


static const per_sequence_t PDUSessionResourceModifyResponse_sequence[] = {
  { &hf_ngap_protocolIEs    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ngap_ProtocolIE_Container },
  { NULL, 0, 0, NULL }
};

static int
dissect_ngap_PDUSessionResourceModifyResponse(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 1473 "./asn1/ngap/ngap.cnf"
  col_append_sep_str(actx->pinfo->cinfo, COL_INFO, NULL, "PDUSessionResourceModifyResponse");


  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ngap_PDUSessionResourceModifyResponse, PDUSessionResourceModifyResponse_sequence);

  return offset;
}


static const per_sequence_t PDUSessionResourceNotify_sequence[] = {
  { &hf_ngap_protocolIEs    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ngap_ProtocolIE_Container },
  { NULL, 0, 0, NULL }
};

static int
dissect_ngap_PDUSessionResourceNotify(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 1482 "./asn1/ngap/ngap.cnf"
  col_append_sep_str(actx->pinfo->cinfo, COL_INFO, NULL, "PDUSessionResourceNotify");


  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ngap_PDUSessionResourceNotify, PDUSessionResourceNotify_sequence);

  return offset;
}


static const per_sequence_t PDUSessionResourceModifyIndication_sequence[] = {
  { &hf_ngap_protocolIEs    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ngap_ProtocolIE_Container },
  { NULL, 0, 0, NULL }
};

static int
dissect_ngap_PDUSessionResourceModifyIndication(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 1476 "./asn1/ngap/ngap.cnf"
  col_append_sep_str(actx->pinfo->cinfo, COL_INFO, NULL, "PDUSessionResourceModifyIndication");


  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ngap_PDUSessionResourceModifyIndication, PDUSessionResourceModifyIndication_sequence);

  return offset;
}


static const per_sequence_t PDUSessionResourceModifyConfirm_sequence[] = {
  { &hf_ngap_protocolIEs    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ngap_ProtocolIE_Container },
  { NULL, 0, 0, NULL }
};

static int
dissect_ngap_PDUSessionResourceModifyConfirm(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 1479 "./asn1/ngap/ngap.cnf"
  col_append_sep_str(actx->pinfo->cinfo, COL_INFO, NULL, "PDUSessionResourceModifyConfirm");


  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ngap_PDUSessionResourceModifyConfirm, PDUSessionResourceModifyConfirm_sequence);

  return offset;
}


static const per_sequence_t InitialContextSetupRequest_sequence[] = {
  { &hf_ngap_protocolIEs    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ngap_ProtocolIE_Container },
  { NULL, 0, 0, NULL }
};

static int
dissect_ngap_InitialContextSetupRequest(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 1413 "./asn1/ngap/ngap.cnf"
  col_append_sep_str(actx->pinfo->cinfo, COL_INFO, NULL, "InitialContextSetupRequest");


  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ngap_InitialContextSetupRequest, InitialContextSetupRequest_sequence);

  return offset;
}


static const per_sequence_t InitialContextSetupResponse_sequence[] = {
  { &hf_ngap_protocolIEs    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ngap_ProtocolIE_Container },
  { NULL, 0, 0, NULL }
};

static int
dissect_ngap_InitialContextSetupResponse(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 1416 "./asn1/ngap/ngap.cnf"
  col_append_sep_str(actx->pinfo->cinfo, COL_INFO, NULL, "InitialContextSetupResponse");


  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ngap_InitialContextSetupResponse, InitialContextSetupResponse_sequence);

  return offset;
}


static const per_sequence_t InitialContextSetupFailure_sequence[] = {
  { &hf_ngap_protocolIEs    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ngap_ProtocolIE_Container },
  { NULL, 0, 0, NULL }
};

static int
dissect_ngap_InitialContextSetupFailure(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 1419 "./asn1/ngap/ngap.cnf"
  col_append_sep_str(actx->pinfo->cinfo, COL_INFO, NULL, "InitialContextSetupFailure");


  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ngap_InitialContextSetupFailure, InitialContextSetupFailure_sequence);

  return offset;
}


static const per_sequence_t UEContextReleaseRequest_sequence[] = {
  { &hf_ngap_protocolIEs    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ngap_ProtocolIE_Container },
  { NULL, 0, 0, NULL }
};

static int
dissect_ngap_UEContextReleaseRequest(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 1551 "./asn1/ngap/ngap.cnf"
  col_append_sep_str(actx->pinfo->cinfo, COL_INFO, NULL, "UEContextReleaseRequest");


  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ngap_UEContextReleaseRequest, UEContextReleaseRequest_sequence);

  return offset;
}


static const per_sequence_t UEContextReleaseCommand_sequence[] = {
  { &hf_ngap_protocolIEs    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ngap_ProtocolIE_Container },
  { NULL, 0, 0, NULL }
};

static int
dissect_ngap_UEContextReleaseCommand(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 1545 "./asn1/ngap/ngap.cnf"
  col_append_sep_str(actx->pinfo->cinfo, COL_INFO, NULL, "UEContextReleaseCommand");


  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ngap_UEContextReleaseCommand, UEContextReleaseCommand_sequence);

  return offset;
}


static const per_sequence_t UEContextReleaseComplete_sequence[] = {
  { &hf_ngap_protocolIEs    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ngap_ProtocolIE_Container },
  { NULL, 0, 0, NULL }
};

static int
dissect_ngap_UEContextReleaseComplete(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 1548 "./asn1/ngap/ngap.cnf"
  col_append_sep_str(actx->pinfo->cinfo, COL_INFO, NULL, "UEContextReleaseComplete");


  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ngap_UEContextReleaseComplete, UEContextReleaseComplete_sequence);

  return offset;
}


static const per_sequence_t UEContextModificationRequest_sequence[] = {
  { &hf_ngap_protocolIEs    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ngap_ProtocolIE_Container },
  { NULL, 0, 0, NULL }
};

static int
dissect_ngap_UEContextModificationRequest(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 1536 "./asn1/ngap/ngap.cnf"
  col_append_sep_str(actx->pinfo->cinfo, COL_INFO, NULL, "UEContextModificationRequest");


  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ngap_UEContextModificationRequest, UEContextModificationRequest_sequence);

  return offset;
}


static const per_sequence_t UEContextModificationResponse_sequence[] = {
  { &hf_ngap_protocolIEs    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ngap_ProtocolIE_Container },
  { NULL, 0, 0, NULL }
};

static int
dissect_ngap_UEContextModificationResponse(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 1539 "./asn1/ngap/ngap.cnf"
  col_append_sep_str(actx->pinfo->cinfo, COL_INFO, NULL, "UEContextModificationResponse");


  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ngap_UEContextModificationResponse, UEContextModificationResponse_sequence);

  return offset;
}


static const per_sequence_t UEContextModificationFailure_sequence[] = {
  { &hf_ngap_protocolIEs    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ngap_ProtocolIE_Container },
  { NULL, 0, 0, NULL }
};

static int
dissect_ngap_UEContextModificationFailure(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 1542 "./asn1/ngap/ngap.cnf"
  col_append_sep_str(actx->pinfo->cinfo, COL_INFO, NULL, "UEContextModificationFailure");


  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ngap_UEContextModificationFailure, UEContextModificationFailure_sequence);

  return offset;
}


static const per_sequence_t RRCInactiveTransitionReport_sequence[] = {
  { &hf_ngap_protocolIEs    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ngap_ProtocolIE_Container },
  { NULL, 0, 0, NULL }
};

static int
dissect_ngap_RRCInactiveTransitionReport(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 1524 "./asn1/ngap/ngap.cnf"
  col_append_sep_str(actx->pinfo->cinfo, COL_INFO, NULL, "RRCInactiveTransitionReport");


  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ngap_RRCInactiveTransitionReport, RRCInactiveTransitionReport_sequence);

  return offset;
}


static const per_sequence_t HandoverRequired_sequence[] = {
  { &hf_ngap_protocolIEs    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ngap_ProtocolIE_Container },
  { NULL, 0, 0, NULL }
};

static int
dissect_ngap_HandoverRequired(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 1395 "./asn1/ngap/ngap.cnf"
  col_append_sep_str(actx->pinfo->cinfo, COL_INFO, NULL, "HandoverRequired");


  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ngap_HandoverRequired, HandoverRequired_sequence);

  return offset;
}


static const per_sequence_t HandoverCommand_sequence[] = {
  { &hf_ngap_protocolIEs    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ngap_ProtocolIE_Container },
  { NULL, 0, 0, NULL }
};

static int
dissect_ngap_HandoverCommand(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 1398 "./asn1/ngap/ngap.cnf"
  col_append_sep_str(actx->pinfo->cinfo, COL_INFO, NULL, "HandoverCommand");


  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ngap_HandoverCommand, HandoverCommand_sequence);

  return offset;
}


static const per_sequence_t HandoverPreparationFailure_sequence[] = {
  { &hf_ngap_protocolIEs    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ngap_ProtocolIE_Container },
  { NULL, 0, 0, NULL }
};

static int
dissect_ngap_HandoverPreparationFailure(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 1401 "./asn1/ngap/ngap.cnf"
  col_append_sep_str(actx->pinfo->cinfo, COL_INFO, NULL, "HandoverPreparationFailure");


  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ngap_HandoverPreparationFailure, HandoverPreparationFailure_sequence);

  return offset;
}


static const per_sequence_t HandoverRequest_sequence[] = {
  { &hf_ngap_protocolIEs    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ngap_ProtocolIE_Container },
  { NULL, 0, 0, NULL }
};

static int
dissect_ngap_HandoverRequest(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 251 "./asn1/ngap/ngap.cnf"
  /* Set the direction of the message */
  actx->pinfo->link_dir=P2P_DIR_DL;

  col_append_sep_str(actx->pinfo->cinfo, COL_INFO, NULL, "HandoverRequest");


  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ngap_HandoverRequest, HandoverRequest_sequence);

  return offset;
}


static const per_sequence_t HandoverRequestAcknowledge_sequence[] = {
  { &hf_ngap_protocolIEs    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ngap_ProtocolIE_Container },
  { NULL, 0, 0, NULL }
};

static int
dissect_ngap_HandoverRequestAcknowledge(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 1407 "./asn1/ngap/ngap.cnf"
  col_append_sep_str(actx->pinfo->cinfo, COL_INFO, NULL, "HandoverRequestAcknowledge");


  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ngap_HandoverRequestAcknowledge, HandoverRequestAcknowledge_sequence);

  return offset;
}


static const per_sequence_t HandoverFailure_sequence[] = {
  { &hf_ngap_protocolIEs    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ngap_ProtocolIE_Container },
  { NULL, 0, 0, NULL }
};

static int
dissect_ngap_HandoverFailure(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 1410 "./asn1/ngap/ngap.cnf"
  col_append_sep_str(actx->pinfo->cinfo, COL_INFO, NULL, "HandoverFailure");


  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ngap_HandoverFailure, HandoverFailure_sequence);

  return offset;
}


static const per_sequence_t HandoverNotify_sequence[] = {
  { &hf_ngap_protocolIEs    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ngap_ProtocolIE_Container },
  { NULL, 0, 0, NULL }
};

static int
dissect_ngap_HandoverNotify(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 1392 "./asn1/ngap/ngap.cnf"
  col_append_sep_str(actx->pinfo->cinfo, COL_INFO, NULL, "HandoverNotify");


  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ngap_HandoverNotify, HandoverNotify_sequence);

  return offset;
}


static const per_sequence_t PathSwitchRequest_sequence[] = {
  { &hf_ngap_protocolIEs    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ngap_ProtocolIE_Container },
  { NULL, 0, 0, NULL }
};

static int
dissect_ngap_PathSwitchRequest(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 1461 "./asn1/ngap/ngap.cnf"
  col_append_sep_str(actx->pinfo->cinfo, COL_INFO, NULL, "PathSwitchRequest");


  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ngap_PathSwitchRequest, PathSwitchRequest_sequence);

  return offset;
}


static const per_sequence_t PathSwitchRequestAcknowledge_sequence[] = {
  { &hf_ngap_protocolIEs    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ngap_ProtocolIE_Container },
  { NULL, 0, 0, NULL }
};

static int
dissect_ngap_PathSwitchRequestAcknowledge(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 1464 "./asn1/ngap/ngap.cnf"
  col_append_sep_str(actx->pinfo->cinfo, COL_INFO, NULL, "PathSwitchRequestAcknowledge");


  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ngap_PathSwitchRequestAcknowledge, PathSwitchRequestAcknowledge_sequence);

  return offset;
}


static const per_sequence_t PathSwitchRequestFailure_sequence[] = {
  { &hf_ngap_protocolIEs    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ngap_ProtocolIE_Container },
  { NULL, 0, 0, NULL }
};

static int
dissect_ngap_PathSwitchRequestFailure(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 1467 "./asn1/ngap/ngap.cnf"
  col_append_sep_str(actx->pinfo->cinfo, COL_INFO, NULL, "PathSwitchRequestFailure");


  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ngap_PathSwitchRequestFailure, PathSwitchRequestFailure_sequence);

  return offset;
}


static const per_sequence_t HandoverCancel_sequence[] = {
  { &hf_ngap_protocolIEs    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ngap_ProtocolIE_Container },
  { NULL, 0, 0, NULL }
};

static int
dissect_ngap_HandoverCancel(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 1386 "./asn1/ngap/ngap.cnf"
  col_append_sep_str(actx->pinfo->cinfo, COL_INFO, NULL, "HandoverCancel");


  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ngap_HandoverCancel, HandoverCancel_sequence);

  return offset;
}


static const per_sequence_t HandoverCancelAcknowledge_sequence[] = {
  { &hf_ngap_protocolIEs    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ngap_ProtocolIE_Container },
  { NULL, 0, 0, NULL }
};

static int
dissect_ngap_HandoverCancelAcknowledge(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 1389 "./asn1/ngap/ngap.cnf"
  col_append_sep_str(actx->pinfo->cinfo, COL_INFO, NULL, "HandoverCancelAcknowledge");


  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ngap_HandoverCancelAcknowledge, HandoverCancelAcknowledge_sequence);

  return offset;
}


static const per_sequence_t UplinkRANStatusTransfer_sequence[] = {
  { &hf_ngap_protocolIEs    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ngap_ProtocolIE_Container },
  { NULL, 0, 0, NULL }
};

static int
dissect_ngap_UplinkRANStatusTransfer(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 1575 "./asn1/ngap/ngap.cnf"
  col_append_sep_str(actx->pinfo->cinfo, COL_INFO, NULL, "UplinkRANStatusTransfer");


  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ngap_UplinkRANStatusTransfer, UplinkRANStatusTransfer_sequence);

  return offset;
}


static const per_sequence_t DownlinkRANStatusTransfer_sequence[] = {
  { &hf_ngap_protocolIEs    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ngap_ProtocolIE_Container },
  { NULL, 0, 0, NULL }
};

static int
dissect_ngap_DownlinkRANStatusTransfer(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 1377 "./asn1/ngap/ngap.cnf"
  col_append_sep_str(actx->pinfo->cinfo, COL_INFO, NULL, "DownlinkRANStatusTransfer");


  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ngap_DownlinkRANStatusTransfer, DownlinkRANStatusTransfer_sequence);

  return offset;
}


static const per_sequence_t Paging_sequence[] = {
  { &hf_ngap_protocolIEs    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ngap_ProtocolIE_Container },
  { NULL, 0, 0, NULL }
};

static int
dissect_ngap_Paging(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 1458 "./asn1/ngap/ngap.cnf"
  col_append_sep_str(actx->pinfo->cinfo, COL_INFO, NULL, "Paging");


  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ngap_Paging, Paging_sequence);

  return offset;
}


static const per_sequence_t InitialUEMessage_sequence[] = {
  { &hf_ngap_protocolIEs    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ngap_ProtocolIE_Container },
  { NULL, 0, 0, NULL }
};

static int
dissect_ngap_InitialUEMessage(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 239 "./asn1/ngap/ngap.cnf"
  /* Set the direction of the message */
  actx->pinfo->link_dir=P2P_DIR_UL;

  col_append_sep_str(actx->pinfo->cinfo, COL_INFO, NULL, "InitialUEMessage");


  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ngap_InitialUEMessage, InitialUEMessage_sequence);

  return offset;
}


static const per_sequence_t DownlinkNASTransport_sequence[] = {
  { &hf_ngap_protocolIEs    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ngap_ProtocolIE_Container },
  { NULL, 0, 0, NULL }
};

static int
dissect_ngap_DownlinkNASTransport(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 243 "./asn1/ngap/ngap.cnf"
  /* Set the direction of the message */
  actx->pinfo->link_dir=P2P_DIR_DL;

  col_append_sep_str(actx->pinfo->cinfo, COL_INFO, NULL, "DownlinkNASTransport");


  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ngap_DownlinkNASTransport, DownlinkNASTransport_sequence);

  return offset;
}


static const per_sequence_t UplinkNASTransport_sequence[] = {
  { &hf_ngap_protocolIEs    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ngap_ProtocolIE_Container },
  { NULL, 0, 0, NULL }
};

static int
dissect_ngap_UplinkNASTransport(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 247 "./asn1/ngap/ngap.cnf"
  /* Set the direction of the message */
  actx->pinfo->link_dir=P2P_DIR_UL;

  col_append_sep_str(actx->pinfo->cinfo, COL_INFO, NULL, "UplinkNASTransport");


  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ngap_UplinkNASTransport, UplinkNASTransport_sequence);

  return offset;
}


static const per_sequence_t NASNonDeliveryIndication_sequence[] = {
  { &hf_ngap_protocolIEs    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ngap_ProtocolIE_Container },
  { NULL, 0, 0, NULL }
};

static int
dissect_ngap_NASNonDeliveryIndication(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 1434 "./asn1/ngap/ngap.cnf"
  col_append_sep_str(actx->pinfo->cinfo, COL_INFO, NULL, "NASNonDeliveryIndication");


  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ngap_NASNonDeliveryIndication, NASNonDeliveryIndication_sequence);

  return offset;
}


static const per_sequence_t RerouteNASRequest_sequence[] = {
  { &hf_ngap_protocolIEs    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ngap_ProtocolIE_Container },
  { NULL, 0, 0, NULL }
};

static int
dissect_ngap_RerouteNASRequest(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 1521 "./asn1/ngap/ngap.cnf"
  col_append_sep_str(actx->pinfo->cinfo, COL_INFO, NULL, "RerouteNASRequest");


  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ngap_RerouteNASRequest, RerouteNASRequest_sequence);

  return offset;
}



static int
dissect_ngap_NGAP_Message(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 400 "./asn1/ngap/ngap.cnf"
  tvbuff_t *parameter_tvb;
  proto_tree *subtree;
  offset = dissect_per_octet_string(tvb, offset, actx, tree, hf_index,
                                       NO_BOUND, NO_BOUND, FALSE, &parameter_tvb);

  if (!parameter_tvb)
    return offset;

  subtree = proto_item_add_subtree(actx->created_item, ett_ngap_NGAP_Message);
  col_set_fence(actx->pinfo->cinfo, COL_INFO);
  call_dissector(ngap_handle, parameter_tvb, actx->pinfo, subtree);



  return offset;
}


static const per_sequence_t NGSetupRequest_sequence[] = {
  { &hf_ngap_protocolIEs    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ngap_ProtocolIE_Container },
  { NULL, 0, 0, NULL }
};

static int
dissect_ngap_NGSetupRequest(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 1443 "./asn1/ngap/ngap.cnf"
  col_append_sep_str(actx->pinfo->cinfo, COL_INFO, NULL, "NGSetupRequest");


  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ngap_NGSetupRequest, NGSetupRequest_sequence);

  return offset;
}


static const per_sequence_t NGSetupResponse_sequence[] = {
  { &hf_ngap_protocolIEs    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ngap_ProtocolIE_Container },
  { NULL, 0, 0, NULL }
};

static int
dissect_ngap_NGSetupResponse(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 1446 "./asn1/ngap/ngap.cnf"
  col_append_sep_str(actx->pinfo->cinfo, COL_INFO, NULL, "NGSetupResponse");


  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ngap_NGSetupResponse, NGSetupResponse_sequence);

  return offset;
}


static const per_sequence_t NGSetupFailure_sequence[] = {
  { &hf_ngap_protocolIEs    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ngap_ProtocolIE_Container },
  { NULL, 0, 0, NULL }
};

static int
dissect_ngap_NGSetupFailure(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 1449 "./asn1/ngap/ngap.cnf"
  col_append_sep_str(actx->pinfo->cinfo, COL_INFO, NULL, "NGSetupFailure");


  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ngap_NGSetupFailure, NGSetupFailure_sequence);

  return offset;
}


static const per_sequence_t RANConfigurationUpdate_sequence[] = {
  { &hf_ngap_protocolIEs    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ngap_ProtocolIE_Container },
  { NULL, 0, 0, NULL }
};

static int
dissect_ngap_RANConfigurationUpdate(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 1512 "./asn1/ngap/ngap.cnf"
  col_append_sep_str(actx->pinfo->cinfo, COL_INFO, NULL, "RANConfigurationUpdate");


  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ngap_RANConfigurationUpdate, RANConfigurationUpdate_sequence);

  return offset;
}


static const per_sequence_t RANConfigurationUpdateAcknowledge_sequence[] = {
  { &hf_ngap_protocolIEs    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ngap_ProtocolIE_Container },
  { NULL, 0, 0, NULL }
};

static int
dissect_ngap_RANConfigurationUpdateAcknowledge(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 1515 "./asn1/ngap/ngap.cnf"
  col_append_sep_str(actx->pinfo->cinfo, COL_INFO, NULL, "RANConfigurationUpdateAcknowledge");


  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ngap_RANConfigurationUpdateAcknowledge, RANConfigurationUpdateAcknowledge_sequence);

  return offset;
}


static const per_sequence_t RANConfigurationUpdateFailure_sequence[] = {
  { &hf_ngap_protocolIEs    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ngap_ProtocolIE_Container },
  { NULL, 0, 0, NULL }
};

static int
dissect_ngap_RANConfigurationUpdateFailure(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 1518 "./asn1/ngap/ngap.cnf"
  col_append_sep_str(actx->pinfo->cinfo, COL_INFO, NULL, "RANConfigurationUpdateFailure");


  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ngap_RANConfigurationUpdateFailure, RANConfigurationUpdateFailure_sequence);

  return offset;
}


static const per_sequence_t AMFConfigurationUpdate_sequence[] = {
  { &hf_ngap_protocolIEs    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ngap_ProtocolIE_Container },
  { NULL, 0, 0, NULL }
};

static int
dissect_ngap_AMFConfigurationUpdate(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 1350 "./asn1/ngap/ngap.cnf"
  col_append_sep_str(actx->pinfo->cinfo, COL_INFO, NULL, "AMFConfigurationUpdate");


  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ngap_AMFConfigurationUpdate, AMFConfigurationUpdate_sequence);

  return offset;
}


static const per_sequence_t AMFConfigurationUpdateAcknowledge_sequence[] = {
  { &hf_ngap_protocolIEs    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ngap_ProtocolIE_Container },
  { NULL, 0, 0, NULL }
};

static int
dissect_ngap_AMFConfigurationUpdateAcknowledge(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 1353 "./asn1/ngap/ngap.cnf"
  col_append_sep_str(actx->pinfo->cinfo, COL_INFO, NULL, "AMFConfigurationUpdateAcknowledge");


  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ngap_AMFConfigurationUpdateAcknowledge, AMFConfigurationUpdateAcknowledge_sequence);

  return offset;
}


static const per_sequence_t AMFConfigurationUpdateFailure_sequence[] = {
  { &hf_ngap_protocolIEs    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ngap_ProtocolIE_Container },
  { NULL, 0, 0, NULL }
};

static int
dissect_ngap_AMFConfigurationUpdateFailure(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 1356 "./asn1/ngap/ngap.cnf"
  col_append_sep_str(actx->pinfo->cinfo, COL_INFO, NULL, "AMFConfigurationUpdateFailure");


  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ngap_AMFConfigurationUpdateFailure, AMFConfigurationUpdateFailure_sequence);

  return offset;
}


static const per_sequence_t AMFStatusIndication_sequence[] = {
  { &hf_ngap_protocolIEs    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ngap_ProtocolIE_Container },
  { NULL, 0, 0, NULL }
};

static int
dissect_ngap_AMFStatusIndication(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 1359 "./asn1/ngap/ngap.cnf"
  col_append_sep_str(actx->pinfo->cinfo, COL_INFO, NULL, "AMFStatusIndication");


  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ngap_AMFStatusIndication, AMFStatusIndication_sequence);

  return offset;
}


static const per_sequence_t NGReset_sequence[] = {
  { &hf_ngap_protocolIEs    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ngap_ProtocolIE_Container },
  { NULL, 0, 0, NULL }
};

static int
dissect_ngap_NGReset(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 1437 "./asn1/ngap/ngap.cnf"
  col_append_sep_str(actx->pinfo->cinfo, COL_INFO, NULL, "NGReset");


  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ngap_NGReset, NGReset_sequence);

  return offset;
}


static const per_sequence_t NGResetAcknowledge_sequence[] = {
  { &hf_ngap_protocolIEs    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ngap_ProtocolIE_Container },
  { NULL, 0, 0, NULL }
};

static int
dissect_ngap_NGResetAcknowledge(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 1440 "./asn1/ngap/ngap.cnf"
  col_append_sep_str(actx->pinfo->cinfo, COL_INFO, NULL, "NGResetAcknowledge");


  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ngap_NGResetAcknowledge, NGResetAcknowledge_sequence);

  return offset;
}


static const per_sequence_t ErrorIndication_sequence[] = {
  { &hf_ngap_protocolIEs    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ngap_ProtocolIE_Container },
  { NULL, 0, 0, NULL }
};

static int
dissect_ngap_ErrorIndication(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 1383 "./asn1/ngap/ngap.cnf"
  col_append_sep_str(actx->pinfo->cinfo, COL_INFO, NULL, "ErrorIndication");


  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ngap_ErrorIndication, ErrorIndication_sequence);

  return offset;
}


static const per_sequence_t OverloadStart_sequence[] = {
  { &hf_ngap_protocolIEs    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ngap_ProtocolIE_Container },
  { NULL, 0, 0, NULL }
};

static int
dissect_ngap_OverloadStart(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 1452 "./asn1/ngap/ngap.cnf"
  col_append_sep_str(actx->pinfo->cinfo, COL_INFO, NULL, "OverloadStart");


  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ngap_OverloadStart, OverloadStart_sequence);

  return offset;
}


static const per_sequence_t OverloadStop_sequence[] = {
  { &hf_ngap_protocolIEs    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ngap_ProtocolIE_Container },
  { NULL, 0, 0, NULL }
};

static int
dissect_ngap_OverloadStop(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 1455 "./asn1/ngap/ngap.cnf"
  col_append_sep_str(actx->pinfo->cinfo, COL_INFO, NULL, "OverloadStop");


  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ngap_OverloadStop, OverloadStop_sequence);

  return offset;
}


static const per_sequence_t UplinkRANConfigurationTransfer_sequence[] = {
  { &hf_ngap_protocolIEs    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ngap_ProtocolIE_Container },
  { NULL, 0, 0, NULL }
};

static int
dissect_ngap_UplinkRANConfigurationTransfer(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 1572 "./asn1/ngap/ngap.cnf"
  col_append_sep_str(actx->pinfo->cinfo, COL_INFO, NULL, "UplinkRANConfigurationTransfer");


  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ngap_UplinkRANConfigurationTransfer, UplinkRANConfigurationTransfer_sequence);

  return offset;
}


static const per_sequence_t DownlinkRANConfigurationTransfer_sequence[] = {
  { &hf_ngap_protocolIEs    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ngap_ProtocolIE_Container },
  { NULL, 0, 0, NULL }
};

static int
dissect_ngap_DownlinkRANConfigurationTransfer(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 1374 "./asn1/ngap/ngap.cnf"
  col_append_sep_str(actx->pinfo->cinfo, COL_INFO, NULL, "DownlinkRANConfigurationTransfer");


  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ngap_DownlinkRANConfigurationTransfer, DownlinkRANConfigurationTransfer_sequence);

  return offset;
}


static const per_sequence_t WriteReplaceWarningRequest_sequence[] = {
  { &hf_ngap_protocolIEs    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ngap_ProtocolIE_Container },
  { NULL, 0, 0, NULL }
};

static int
dissect_ngap_WriteReplaceWarningRequest(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 1581 "./asn1/ngap/ngap.cnf"
  col_append_sep_str(actx->pinfo->cinfo, COL_INFO, NULL, "WriteReplaceWarningRequest");


  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ngap_WriteReplaceWarningRequest, WriteReplaceWarningRequest_sequence);

  return offset;
}


static const per_sequence_t WriteReplaceWarningResponse_sequence[] = {
  { &hf_ngap_protocolIEs    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ngap_ProtocolIE_Container },
  { NULL, 0, 0, NULL }
};

static int
dissect_ngap_WriteReplaceWarningResponse(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 1584 "./asn1/ngap/ngap.cnf"
  col_append_sep_str(actx->pinfo->cinfo, COL_INFO, NULL, "WriteReplaceWarningResponse");



  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ngap_WriteReplaceWarningResponse, WriteReplaceWarningResponse_sequence);

  return offset;
}


static const per_sequence_t PWSCancelRequest_sequence[] = {
  { &hf_ngap_protocolIEs    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ngap_ProtocolIE_Container },
  { NULL, 0, 0, NULL }
};

static int
dissect_ngap_PWSCancelRequest(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 1500 "./asn1/ngap/ngap.cnf"
  col_append_sep_str(actx->pinfo->cinfo, COL_INFO, NULL, "PWSCancelRequest");


  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ngap_PWSCancelRequest, PWSCancelRequest_sequence);

  return offset;
}


static const per_sequence_t PWSCancelResponse_sequence[] = {
  { &hf_ngap_protocolIEs    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ngap_ProtocolIE_Container },
  { NULL, 0, 0, NULL }
};

static int
dissect_ngap_PWSCancelResponse(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 1503 "./asn1/ngap/ngap.cnf"
  col_append_sep_str(actx->pinfo->cinfo, COL_INFO, NULL, "PWSCancelResponse");


  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ngap_PWSCancelResponse, PWSCancelResponse_sequence);

  return offset;
}


static const per_sequence_t PWSRestartIndication_sequence[] = {
  { &hf_ngap_protocolIEs    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ngap_ProtocolIE_Container },
  { NULL, 0, 0, NULL }
};

static int
dissect_ngap_PWSRestartIndication(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 1509 "./asn1/ngap/ngap.cnf"
  col_append_sep_str(actx->pinfo->cinfo, COL_INFO, NULL, "PWSRestartIndication");


  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ngap_PWSRestartIndication, PWSRestartIndication_sequence);

  return offset;
}


static const per_sequence_t PWSFailureIndication_sequence[] = {
  { &hf_ngap_protocolIEs    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ngap_ProtocolIE_Container },
  { NULL, 0, 0, NULL }
};

static int
dissect_ngap_PWSFailureIndication(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 1506 "./asn1/ngap/ngap.cnf"
  col_append_sep_str(actx->pinfo->cinfo, COL_INFO, NULL, "PWSFailureIndication");


  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ngap_PWSFailureIndication, PWSFailureIndication_sequence);

  return offset;
}


static const per_sequence_t DownlinkUEAssociatedNRPPaTransport_sequence[] = {
  { &hf_ngap_protocolIEs    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ngap_ProtocolIE_Container },
  { NULL, 0, 0, NULL }
};

static int
dissect_ngap_DownlinkUEAssociatedNRPPaTransport(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 1380 "./asn1/ngap/ngap.cnf"
  col_append_sep_str(actx->pinfo->cinfo, COL_INFO, NULL, "DownlinkUEAssociatedNRPPaTransport");


  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ngap_DownlinkUEAssociatedNRPPaTransport, DownlinkUEAssociatedNRPPaTransport_sequence);

  return offset;
}


static const per_sequence_t UplinkUEAssociatedNRPPaTransport_sequence[] = {
  { &hf_ngap_protocolIEs    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ngap_ProtocolIE_Container },
  { NULL, 0, 0, NULL }
};

static int
dissect_ngap_UplinkUEAssociatedNRPPaTransport(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 1578 "./asn1/ngap/ngap.cnf"
  col_append_sep_str(actx->pinfo->cinfo, COL_INFO, NULL, "UplinkUEAssociatedNRPPaTransport");


  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ngap_UplinkUEAssociatedNRPPaTransport, UplinkUEAssociatedNRPPaTransport_sequence);

  return offset;
}


static const per_sequence_t DownlinkNonUEAssociatedNRPPaTransport_sequence[] = {
  { &hf_ngap_protocolIEs    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ngap_ProtocolIE_Container },
  { NULL, 0, 0, NULL }
};

static int
dissect_ngap_DownlinkNonUEAssociatedNRPPaTransport(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 1371 "./asn1/ngap/ngap.cnf"
  col_append_sep_str(actx->pinfo->cinfo, COL_INFO, NULL, "DownlinkNonUEAssociatedNRPPaTransport");


  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ngap_DownlinkNonUEAssociatedNRPPaTransport, DownlinkNonUEAssociatedNRPPaTransport_sequence);

  return offset;
}


static const per_sequence_t UplinkNonUEAssociatedNRPPaTransport_sequence[] = {
  { &hf_ngap_protocolIEs    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ngap_ProtocolIE_Container },
  { NULL, 0, 0, NULL }
};

static int
dissect_ngap_UplinkNonUEAssociatedNRPPaTransport(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 1569 "./asn1/ngap/ngap.cnf"
  col_append_sep_str(actx->pinfo->cinfo, COL_INFO, NULL, "UplinkNonUEAssociatedNRPPaTransport");


  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ngap_UplinkNonUEAssociatedNRPPaTransport, UplinkNonUEAssociatedNRPPaTransport_sequence);

  return offset;
}


static const per_sequence_t TraceStart_sequence[] = {
  { &hf_ngap_protocolIEs    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ngap_ProtocolIE_Container },
  { NULL, 0, 0, NULL }
};

static int
dissect_ngap_TraceStart(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 1533 "./asn1/ngap/ngap.cnf"
  col_append_sep_str(actx->pinfo->cinfo, COL_INFO, NULL, "TraceStart");


  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ngap_TraceStart, TraceStart_sequence);

  return offset;
}


static const per_sequence_t TraceFailureIndication_sequence[] = {
  { &hf_ngap_protocolIEs    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ngap_ProtocolIE_Container },
  { NULL, 0, 0, NULL }
};

static int
dissect_ngap_TraceFailureIndication(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 1530 "./asn1/ngap/ngap.cnf"
  col_append_sep_str(actx->pinfo->cinfo, COL_INFO, NULL, "TraceFailureIndication");


  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ngap_TraceFailureIndication, TraceFailureIndication_sequence);

  return offset;
}


static const per_sequence_t DeactivateTrace_sequence[] = {
  { &hf_ngap_protocolIEs    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ngap_ProtocolIE_Container },
  { NULL, 0, 0, NULL }
};

static int
dissect_ngap_DeactivateTrace(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 1365 "./asn1/ngap/ngap.cnf"
  col_append_sep_str(actx->pinfo->cinfo, COL_INFO, NULL, "DeactivateTrace");


  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ngap_DeactivateTrace, DeactivateTrace_sequence);

  return offset;
}


static const per_sequence_t CellTrafficTrace_sequence[] = {
  { &hf_ngap_protocolIEs    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ngap_ProtocolIE_Container },
  { NULL, 0, 0, NULL }
};

static int
dissect_ngap_CellTrafficTrace(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 1362 "./asn1/ngap/ngap.cnf"
  col_append_sep_str(actx->pinfo->cinfo, COL_INFO, NULL, "CellTrafficTrace");


  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ngap_CellTrafficTrace, CellTrafficTrace_sequence);

  return offset;
}


static const per_sequence_t LocationReportingControl_sequence[] = {
  { &hf_ngap_protocolIEs    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ngap_ProtocolIE_Container },
  { NULL, 0, 0, NULL }
};

static int
dissect_ngap_LocationReportingControl(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 1428 "./asn1/ngap/ngap.cnf"
  col_append_sep_str(actx->pinfo->cinfo, COL_INFO, NULL, "LocationReportingControl");


  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ngap_LocationReportingControl, LocationReportingControl_sequence);

  return offset;
}


static const per_sequence_t LocationReportingFailureIndication_sequence[] = {
  { &hf_ngap_protocolIEs    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ngap_ProtocolIE_Container },
  { NULL, 0, 0, NULL }
};

static int
dissect_ngap_LocationReportingFailureIndication(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 1431 "./asn1/ngap/ngap.cnf"
  col_append_sep_str(actx->pinfo->cinfo, COL_INFO, NULL, "LocationReportingFailureIndication");


  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ngap_LocationReportingFailureIndication, LocationReportingFailureIndication_sequence);

  return offset;
}


static const per_sequence_t LocationReport_sequence[] = {
  { &hf_ngap_protocolIEs    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ngap_ProtocolIE_Container },
  { NULL, 0, 0, NULL }
};

static int
dissect_ngap_LocationReport(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 1425 "./asn1/ngap/ngap.cnf"
  col_append_sep_str(actx->pinfo->cinfo, COL_INFO, NULL, "LocationReport");


  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ngap_LocationReport, LocationReport_sequence);

  return offset;
}


static const per_sequence_t UETNLABindingReleaseRequest_sequence[] = {
  { &hf_ngap_protocolIEs    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ngap_ProtocolIE_Container },
  { NULL, 0, 0, NULL }
};

static int
dissect_ngap_UETNLABindingReleaseRequest(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 1560 "./asn1/ngap/ngap.cnf"
  col_append_sep_str(actx->pinfo->cinfo, COL_INFO, NULL, "UETNLABindingReleaseRequest");


  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ngap_UETNLABindingReleaseRequest, UETNLABindingReleaseRequest_sequence);

  return offset;
}


static const per_sequence_t UERadioCapabilityInfoIndication_sequence[] = {
  { &hf_ngap_protocolIEs    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ngap_ProtocolIE_Container },
  { NULL, 0, 0, NULL }
};

static int
dissect_ngap_UERadioCapabilityInfoIndication(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 1563 "./asn1/ngap/ngap.cnf"
  col_append_sep_str(actx->pinfo->cinfo, COL_INFO, NULL, "UERadioCapabilityInfoIndication");


  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ngap_UERadioCapabilityInfoIndication, UERadioCapabilityInfoIndication_sequence);

  return offset;
}


static const per_sequence_t UERadioCapabilityCheckRequest_sequence[] = {
  { &hf_ngap_protocolIEs    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ngap_ProtocolIE_Container },
  { NULL, 0, 0, NULL }
};

static int
dissect_ngap_UERadioCapabilityCheckRequest(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 1554 "./asn1/ngap/ngap.cnf"
  col_append_sep_str(actx->pinfo->cinfo, COL_INFO, NULL, "UERadioCapabilityCheckRequest");


  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ngap_UERadioCapabilityCheckRequest, UERadioCapabilityCheckRequest_sequence);

  return offset;
}


static const per_sequence_t UERadioCapabilityCheckResponse_sequence[] = {
  { &hf_ngap_protocolIEs    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ngap_ProtocolIE_Container },
  { NULL, 0, 0, NULL }
};

static int
dissect_ngap_UERadioCapabilityCheckResponse(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 1557 "./asn1/ngap/ngap.cnf"
  col_append_sep_str(actx->pinfo->cinfo, COL_INFO, NULL, "UERadioCapabilityCheckResponse");


  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ngap_UERadioCapabilityCheckResponse, UERadioCapabilityCheckResponse_sequence);

  return offset;
}


static const per_sequence_t PrivateMessage_sequence[] = {
  { &hf_ngap_privateIEs     , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ngap_PrivateIE_Container },
  { NULL, 0, 0, NULL }
};

static int
dissect_ngap_PrivateMessage(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 1497 "./asn1/ngap/ngap.cnf"
  col_append_sep_str(actx->pinfo->cinfo, COL_INFO, NULL, "PrivateMessage");


  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ngap_PrivateMessage, PrivateMessage_sequence);

  return offset;
}


static const per_sequence_t SecondaryRATDataUsageReport_sequence[] = {
  { &hf_ngap_protocolIEs    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ngap_ProtocolIE_Container },
  { NULL, 0, 0, NULL }
};

static int
dissect_ngap_SecondaryRATDataUsageReport(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 1527 "./asn1/ngap/ngap.cnf"
  col_append_sep_str(actx->pinfo->cinfo, COL_INFO, NULL, "SecondaryRATDataUsageReport");


  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ngap_SecondaryRATDataUsageReport, SecondaryRATDataUsageReport_sequence);

  return offset;
}



static int
dissect_ngap_InitiatingMessage_value(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 113 "./asn1/ngap/ngap.cnf"
  struct ngap_private_data *ngap_data = ngap_get_private_data(actx->pinfo);
  ngap_data->message_type = INITIATING_MESSAGE;

  offset = dissect_per_open_type_pdu_new(tvb, offset, actx, tree, hf_index, dissect_InitiatingMessageValue);

  return offset;
}


static const per_sequence_t InitiatingMessage_sequence[] = {
  { &hf_ngap_procedureCode  , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ngap_ProcedureCode },
  { &hf_ngap_criticality    , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ngap_Criticality },
  { &hf_ngap_initiatingMessagevalue, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ngap_InitiatingMessage_value },
  { NULL, 0, 0, NULL }
};

static int
dissect_ngap_InitiatingMessage(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ngap_InitiatingMessage, InitiatingMessage_sequence);

  return offset;
}



static int
dissect_ngap_SuccessfulOutcome_value(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 117 "./asn1/ngap/ngap.cnf"
  struct ngap_private_data *ngap_data = ngap_get_private_data(actx->pinfo);
  ngap_data->message_type = SUCCESSFUL_OUTCOME;

  offset = dissect_per_open_type_pdu_new(tvb, offset, actx, tree, hf_index, dissect_SuccessfulOutcomeValue);

  return offset;
}


static const per_sequence_t SuccessfulOutcome_sequence[] = {
  { &hf_ngap_procedureCode  , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ngap_ProcedureCode },
  { &hf_ngap_criticality    , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ngap_Criticality },
  { &hf_ngap_successfulOutcome_value, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ngap_SuccessfulOutcome_value },
  { NULL, 0, 0, NULL }
};

static int
dissect_ngap_SuccessfulOutcome(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ngap_SuccessfulOutcome, SuccessfulOutcome_sequence);

  return offset;
}



static int
dissect_ngap_UnsuccessfulOutcome_value(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 121 "./asn1/ngap/ngap.cnf"
  struct ngap_private_data *ngap_data = ngap_get_private_data(actx->pinfo);
  ngap_data->message_type = UNSUCCESSFUL_OUTCOME;















  offset = dissect_per_open_type_pdu_new(tvb, offset, actx, tree, hf_index, dissect_UnsuccessfulOutcomeValue);

  return offset;
}


static const per_sequence_t UnsuccessfulOutcome_sequence[] = {
  { &hf_ngap_procedureCode  , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ngap_ProcedureCode },
  { &hf_ngap_criticality    , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ngap_Criticality },
  { &hf_ngap_unsuccessfulOutcome_value, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ngap_UnsuccessfulOutcome_value },
  { NULL, 0, 0, NULL }
};

static int
dissect_ngap_UnsuccessfulOutcome(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ngap_UnsuccessfulOutcome, UnsuccessfulOutcome_sequence);

  return offset;
}


static const value_string ngap_NGAP_PDU_vals[] = {
  {   0, "initiatingMessage" },
  {   1, "successfulOutcome" },
  {   2, "unsuccessfulOutcome" },
  { 0, NULL }
};

static const per_choice_t NGAP_PDU_choice[] = {
  {   0, &hf_ngap_initiatingMessage, ASN1_EXTENSION_ROOT    , dissect_ngap_InitiatingMessage },
  {   1, &hf_ngap_successfulOutcome, ASN1_EXTENSION_ROOT    , dissect_ngap_SuccessfulOutcome },
  {   2, &hf_ngap_unsuccessfulOutcome, ASN1_EXTENSION_ROOT    , dissect_ngap_UnsuccessfulOutcome },
  { 0, NULL, 0, NULL }
};

static int
dissect_ngap_NGAP_PDU(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_ngap_NGAP_PDU, NGAP_PDU_choice,
                                 NULL);

  return offset;
}

/*--- PDUs ---*/

static int dissect_AdditionalDLUPTNLInformationForHOList_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_ngap_AdditionalDLUPTNLInformationForHOList(tvb, offset, &asn1_ctx, tree, hf_ngap_AdditionalDLUPTNLInformationForHOList_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_AllowedNSSAI_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_ngap_AllowedNSSAI(tvb, offset, &asn1_ctx, tree, hf_ngap_AllowedNSSAI_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_AMFName_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_ngap_AMFName(tvb, offset, &asn1_ctx, tree, hf_ngap_AMFName_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_AMFSetID_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_ngap_AMFSetID(tvb, offset, &asn1_ctx, tree, hf_ngap_AMFSetID_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_AMF_TNLAssociationSetupList_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_ngap_AMF_TNLAssociationSetupList(tvb, offset, &asn1_ctx, tree, hf_ngap_AMF_TNLAssociationSetupList_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_AMF_TNLAssociationToAddList_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_ngap_AMF_TNLAssociationToAddList(tvb, offset, &asn1_ctx, tree, hf_ngap_AMF_TNLAssociationToAddList_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_AMF_TNLAssociationToRemoveList_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_ngap_AMF_TNLAssociationToRemoveList(tvb, offset, &asn1_ctx, tree, hf_ngap_AMF_TNLAssociationToRemoveList_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_AMF_TNLAssociationToUpdateList_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_ngap_AMF_TNLAssociationToUpdateList(tvb, offset, &asn1_ctx, tree, hf_ngap_AMF_TNLAssociationToUpdateList_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_AMF_UE_NGAP_ID_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_ngap_AMF_UE_NGAP_ID(tvb, offset, &asn1_ctx, tree, hf_ngap_AMF_UE_NGAP_ID_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_AssistanceDataForPaging_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_ngap_AssistanceDataForPaging(tvb, offset, &asn1_ctx, tree, hf_ngap_AssistanceDataForPaging_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_AssociatedQosFlowList_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_ngap_AssociatedQosFlowList(tvb, offset, &asn1_ctx, tree, hf_ngap_AssociatedQosFlowList_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_BroadcastCancelledAreaList_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_ngap_BroadcastCancelledAreaList(tvb, offset, &asn1_ctx, tree, hf_ngap_BroadcastCancelledAreaList_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_BroadcastCompletedAreaList_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_ngap_BroadcastCompletedAreaList(tvb, offset, &asn1_ctx, tree, hf_ngap_BroadcastCompletedAreaList_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_CancelAllWarningMessages_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_ngap_CancelAllWarningMessages(tvb, offset, &asn1_ctx, tree, hf_ngap_CancelAllWarningMessages_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_Cause_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_ngap_Cause(tvb, offset, &asn1_ctx, tree, hf_ngap_Cause_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_CellIDListForRestart_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_ngap_CellIDListForRestart(tvb, offset, &asn1_ctx, tree, hf_ngap_CellIDListForRestart_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_CNAssistedRANTuning_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_ngap_CNAssistedRANTuning(tvb, offset, &asn1_ctx, tree, hf_ngap_CNAssistedRANTuning_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_CNTypeRestrictionsForEquivalent_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_ngap_CNTypeRestrictionsForEquivalent(tvb, offset, &asn1_ctx, tree, hf_ngap_CNTypeRestrictionsForEquivalent_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_CNTypeRestrictionsForServing_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_ngap_CNTypeRestrictionsForServing(tvb, offset, &asn1_ctx, tree, hf_ngap_CNTypeRestrictionsForServing_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_CommonNetworkInstance_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_ngap_CommonNetworkInstance(tvb, offset, &asn1_ctx, tree, hf_ngap_CommonNetworkInstance_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_ConcurrentWarningMessageInd_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_ngap_ConcurrentWarningMessageInd(tvb, offset, &asn1_ctx, tree, hf_ngap_ConcurrentWarningMessageInd_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_CoreNetworkAssistanceInformationForInactive_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_ngap_CoreNetworkAssistanceInformationForInactive(tvb, offset, &asn1_ctx, tree, hf_ngap_CoreNetworkAssistanceInformationForInactive_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_CPTransportLayerInformation_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_ngap_CPTransportLayerInformation(tvb, offset, &asn1_ctx, tree, hf_ngap_CPTransportLayerInformation_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_CriticalityDiagnostics_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_ngap_CriticalityDiagnostics(tvb, offset, &asn1_ctx, tree, hf_ngap_CriticalityDiagnostics_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_DataCodingScheme_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_ngap_DataCodingScheme(tvb, offset, &asn1_ctx, tree, hf_ngap_DataCodingScheme_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_DataForwardingNotPossible_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_ngap_DataForwardingNotPossible(tvb, offset, &asn1_ctx, tree, hf_ngap_DataForwardingNotPossible_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_DirectForwardingPathAvailability_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_ngap_DirectForwardingPathAvailability(tvb, offset, &asn1_ctx, tree, hf_ngap_DirectForwardingPathAvailability_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_EmergencyAreaIDListForRestart_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_ngap_EmergencyAreaIDListForRestart(tvb, offset, &asn1_ctx, tree, hf_ngap_EmergencyAreaIDListForRestart_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_EmergencyFallbackIndicator_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_ngap_EmergencyFallbackIndicator(tvb, offset, &asn1_ctx, tree, hf_ngap_EmergencyFallbackIndicator_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_EN_DCSONConfigurationTransfer_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_ngap_EN_DCSONConfigurationTransfer(tvb, offset, &asn1_ctx, tree, hf_ngap_EN_DCSONConfigurationTransfer_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_EndpointIPAddressAndPort_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_ngap_EndpointIPAddressAndPort(tvb, offset, &asn1_ctx, tree, hf_ngap_EndpointIPAddressAndPort_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_EUTRA_CGI_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_ngap_EUTRA_CGI(tvb, offset, &asn1_ctx, tree, hf_ngap_EUTRA_CGI_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_FiveG_S_TMSI_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_ngap_FiveG_S_TMSI(tvb, offset, &asn1_ctx, tree, hf_ngap_FiveG_S_TMSI_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_GlobalRANNodeID_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_ngap_GlobalRANNodeID(tvb, offset, &asn1_ctx, tree, hf_ngap_GlobalRANNodeID_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_GUAMI_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_ngap_GUAMI(tvb, offset, &asn1_ctx, tree, hf_ngap_GUAMI_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_HandoverCommandTransfer_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_ngap_HandoverCommandTransfer(tvb, offset, &asn1_ctx, tree, hf_ngap_HandoverCommandTransfer_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_HandoverFlag_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_ngap_HandoverFlag(tvb, offset, &asn1_ctx, tree, hf_ngap_HandoverFlag_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_HandoverPreparationUnsuccessfulTransfer_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_ngap_HandoverPreparationUnsuccessfulTransfer(tvb, offset, &asn1_ctx, tree, hf_ngap_HandoverPreparationUnsuccessfulTransfer_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_HandoverRequestAcknowledgeTransfer_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_ngap_HandoverRequestAcknowledgeTransfer(tvb, offset, &asn1_ctx, tree, hf_ngap_HandoverRequestAcknowledgeTransfer_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_HandoverRequiredTransfer_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_ngap_HandoverRequiredTransfer(tvb, offset, &asn1_ctx, tree, hf_ngap_HandoverRequiredTransfer_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_HandoverResourceAllocationUnsuccessfulTransfer_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_ngap_HandoverResourceAllocationUnsuccessfulTransfer(tvb, offset, &asn1_ctx, tree, hf_ngap_HandoverResourceAllocationUnsuccessfulTransfer_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_HandoverType_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_ngap_HandoverType(tvb, offset, &asn1_ctx, tree, hf_ngap_HandoverType_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_IMSVoiceSupportIndicator_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_ngap_IMSVoiceSupportIndicator(tvb, offset, &asn1_ctx, tree, hf_ngap_IMSVoiceSupportIndicator_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_IndexToRFSP_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_ngap_IndexToRFSP(tvb, offset, &asn1_ctx, tree, hf_ngap_IndexToRFSP_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_InfoOnRecommendedCellsAndRANNodesForPaging_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_ngap_InfoOnRecommendedCellsAndRANNodesForPaging(tvb, offset, &asn1_ctx, tree, hf_ngap_InfoOnRecommendedCellsAndRANNodesForPaging_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
int dissect_ngap_LastVisitedNGRANCellInformation_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_ngap_LastVisitedNGRANCellInformation(tvb, offset, &asn1_ctx, tree, hf_ngap_ngap_LastVisitedNGRANCellInformation_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_LocationReportingAdditionalInfo_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_ngap_LocationReportingAdditionalInfo(tvb, offset, &asn1_ctx, tree, hf_ngap_LocationReportingAdditionalInfo_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_LocationReportingRequestType_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_ngap_LocationReportingRequestType(tvb, offset, &asn1_ctx, tree, hf_ngap_LocationReportingRequestType_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_MaskedIMEISV_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_ngap_MaskedIMEISV(tvb, offset, &asn1_ctx, tree, hf_ngap_MaskedIMEISV_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_MessageIdentifier_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_ngap_MessageIdentifier(tvb, offset, &asn1_ctx, tree, hf_ngap_MessageIdentifier_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_MaximumIntegrityProtectedDataRate_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_ngap_MaximumIntegrityProtectedDataRate(tvb, offset, &asn1_ctx, tree, hf_ngap_MaximumIntegrityProtectedDataRate_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
int dissect_ngap_MobilityRestrictionList_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_ngap_MobilityRestrictionList(tvb, offset, &asn1_ctx, tree, hf_ngap_ngap_MobilityRestrictionList_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_NAS_PDU_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_ngap_NAS_PDU(tvb, offset, &asn1_ctx, tree, hf_ngap_NAS_PDU_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_NASSecurityParametersFromNGRAN_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_ngap_NASSecurityParametersFromNGRAN(tvb, offset, &asn1_ctx, tree, hf_ngap_NASSecurityParametersFromNGRAN_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_NetworkInstance_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_ngap_NetworkInstance(tvb, offset, &asn1_ctx, tree, hf_ngap_NetworkInstance_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_NewSecurityContextInd_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_ngap_NewSecurityContextInd(tvb, offset, &asn1_ctx, tree, hf_ngap_NewSecurityContextInd_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
int dissect_ngap_NGRAN_CGI_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_ngap_NGRAN_CGI(tvb, offset, &asn1_ctx, tree, hf_ngap_ngap_NGRAN_CGI_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_NGRAN_TNLAssociationToRemoveList_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_ngap_NGRAN_TNLAssociationToRemoveList(tvb, offset, &asn1_ctx, tree, hf_ngap_NGRAN_TNLAssociationToRemoveList_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_NGRANTraceID_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_ngap_NGRANTraceID(tvb, offset, &asn1_ctx, tree, hf_ngap_NGRANTraceID_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_NR_CGI_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_ngap_NR_CGI(tvb, offset, &asn1_ctx, tree, hf_ngap_NR_CGI_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_NRPPa_PDU_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_ngap_NRPPa_PDU(tvb, offset, &asn1_ctx, tree, hf_ngap_NRPPa_PDU_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_NumberOfBroadcastsRequested_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_ngap_NumberOfBroadcastsRequested(tvb, offset, &asn1_ctx, tree, hf_ngap_NumberOfBroadcastsRequested_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_OverloadResponse_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_ngap_OverloadResponse(tvb, offset, &asn1_ctx, tree, hf_ngap_OverloadResponse_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_OverloadStartNSSAIList_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_ngap_OverloadStartNSSAIList(tvb, offset, &asn1_ctx, tree, hf_ngap_OverloadStartNSSAIList_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_PagingDRX_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_ngap_PagingDRX(tvb, offset, &asn1_ctx, tree, hf_ngap_PagingDRX_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_PagingOrigin_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_ngap_PagingOrigin(tvb, offset, &asn1_ctx, tree, hf_ngap_PagingOrigin_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_PagingPriority_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_ngap_PagingPriority(tvb, offset, &asn1_ctx, tree, hf_ngap_PagingPriority_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_PathSwitchRequestAcknowledgeTransfer_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_ngap_PathSwitchRequestAcknowledgeTransfer(tvb, offset, &asn1_ctx, tree, hf_ngap_PathSwitchRequestAcknowledgeTransfer_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_PathSwitchRequestSetupFailedTransfer_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_ngap_PathSwitchRequestSetupFailedTransfer(tvb, offset, &asn1_ctx, tree, hf_ngap_PathSwitchRequestSetupFailedTransfer_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_PathSwitchRequestTransfer_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_ngap_PathSwitchRequestTransfer(tvb, offset, &asn1_ctx, tree, hf_ngap_PathSwitchRequestTransfer_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_PathSwitchRequestUnsuccessfulTransfer_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_ngap_PathSwitchRequestUnsuccessfulTransfer(tvb, offset, &asn1_ctx, tree, hf_ngap_PathSwitchRequestUnsuccessfulTransfer_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_PDUSessionAggregateMaximumBitRate_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_ngap_PDUSessionAggregateMaximumBitRate(tvb, offset, &asn1_ctx, tree, hf_ngap_PDUSessionAggregateMaximumBitRate_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_PDUSessionResourceAdmittedList_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_ngap_PDUSessionResourceAdmittedList(tvb, offset, &asn1_ctx, tree, hf_ngap_PDUSessionResourceAdmittedList_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_PDUSessionResourceFailedToModifyListModCfm_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_ngap_PDUSessionResourceFailedToModifyListModCfm(tvb, offset, &asn1_ctx, tree, hf_ngap_PDUSessionResourceFailedToModifyListModCfm_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_PDUSessionResourceFailedToModifyListModRes_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_ngap_PDUSessionResourceFailedToModifyListModRes(tvb, offset, &asn1_ctx, tree, hf_ngap_PDUSessionResourceFailedToModifyListModRes_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_PDUSessionResourceFailedToSetupListCxtFail_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_ngap_PDUSessionResourceFailedToSetupListCxtFail(tvb, offset, &asn1_ctx, tree, hf_ngap_PDUSessionResourceFailedToSetupListCxtFail_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_PDUSessionResourceFailedToSetupListCxtRes_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_ngap_PDUSessionResourceFailedToSetupListCxtRes(tvb, offset, &asn1_ctx, tree, hf_ngap_PDUSessionResourceFailedToSetupListCxtRes_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_PDUSessionResourceFailedToSetupListHOAck_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_ngap_PDUSessionResourceFailedToSetupListHOAck(tvb, offset, &asn1_ctx, tree, hf_ngap_PDUSessionResourceFailedToSetupListHOAck_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_PDUSessionResourceFailedToSetupListPSReq_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_ngap_PDUSessionResourceFailedToSetupListPSReq(tvb, offset, &asn1_ctx, tree, hf_ngap_PDUSessionResourceFailedToSetupListPSReq_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_PDUSessionResourceFailedToSetupListSURes_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_ngap_PDUSessionResourceFailedToSetupListSURes(tvb, offset, &asn1_ctx, tree, hf_ngap_PDUSessionResourceFailedToSetupListSURes_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_PDUSessionResourceHandoverList_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_ngap_PDUSessionResourceHandoverList(tvb, offset, &asn1_ctx, tree, hf_ngap_PDUSessionResourceHandoverList_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_PDUSessionResourceListCxtRelCpl_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_ngap_PDUSessionResourceListCxtRelCpl(tvb, offset, &asn1_ctx, tree, hf_ngap_PDUSessionResourceListCxtRelCpl_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_PDUSessionResourceReleaseResponseTransfer_OCTET_STRING_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_ngap_PDUSessionResourceReleaseResponseTransfer_OCTET_STRING(tvb, offset, &asn1_ctx, tree, hf_ngap_PDUSessionResourceReleaseResponseTransfer_OCTET_STRING_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_PDUSessionResourceListCxtRelReq_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_ngap_PDUSessionResourceListCxtRelReq(tvb, offset, &asn1_ctx, tree, hf_ngap_PDUSessionResourceListCxtRelReq_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_PDUSessionResourceListHORqd_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_ngap_PDUSessionResourceListHORqd(tvb, offset, &asn1_ctx, tree, hf_ngap_PDUSessionResourceListHORqd_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_PDUSessionResourceModifyConfirmTransfer_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_ngap_PDUSessionResourceModifyConfirmTransfer(tvb, offset, &asn1_ctx, tree, hf_ngap_PDUSessionResourceModifyConfirmTransfer_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_PDUSessionResourceModifyRequestTransfer_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_ngap_PDUSessionResourceModifyRequestTransfer(tvb, offset, &asn1_ctx, tree, hf_ngap_PDUSessionResourceModifyRequestTransfer_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_PDUSessionResourceModifyResponseTransfer_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_ngap_PDUSessionResourceModifyResponseTransfer(tvb, offset, &asn1_ctx, tree, hf_ngap_PDUSessionResourceModifyResponseTransfer_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_PDUSessionResourceModifyIndicationTransfer_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_ngap_PDUSessionResourceModifyIndicationTransfer(tvb, offset, &asn1_ctx, tree, hf_ngap_PDUSessionResourceModifyIndicationTransfer_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_PDUSessionResourceModifyListModCfm_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_ngap_PDUSessionResourceModifyListModCfm(tvb, offset, &asn1_ctx, tree, hf_ngap_PDUSessionResourceModifyListModCfm_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_PDUSessionResourceModifyListModInd_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_ngap_PDUSessionResourceModifyListModInd(tvb, offset, &asn1_ctx, tree, hf_ngap_PDUSessionResourceModifyListModInd_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_PDUSessionResourceModifyListModReq_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_ngap_PDUSessionResourceModifyListModReq(tvb, offset, &asn1_ctx, tree, hf_ngap_PDUSessionResourceModifyListModReq_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_PDUSessionResourceModifyListModRes_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_ngap_PDUSessionResourceModifyListModRes(tvb, offset, &asn1_ctx, tree, hf_ngap_PDUSessionResourceModifyListModRes_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_PDUSessionResourceModifyUnsuccessfulTransfer_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_ngap_PDUSessionResourceModifyUnsuccessfulTransfer(tvb, offset, &asn1_ctx, tree, hf_ngap_PDUSessionResourceModifyUnsuccessfulTransfer_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_PDUSessionResourceNotifyList_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_ngap_PDUSessionResourceNotifyList(tvb, offset, &asn1_ctx, tree, hf_ngap_PDUSessionResourceNotifyList_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_PDUSessionResourceNotifyReleasedTransfer_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_ngap_PDUSessionResourceNotifyReleasedTransfer(tvb, offset, &asn1_ctx, tree, hf_ngap_PDUSessionResourceNotifyReleasedTransfer_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_PDUSessionResourceNotifyTransfer_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_ngap_PDUSessionResourceNotifyTransfer(tvb, offset, &asn1_ctx, tree, hf_ngap_PDUSessionResourceNotifyTransfer_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_PDUSessionResourceReleaseCommandTransfer_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_ngap_PDUSessionResourceReleaseCommandTransfer(tvb, offset, &asn1_ctx, tree, hf_ngap_PDUSessionResourceReleaseCommandTransfer_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_PDUSessionResourceReleasedListNot_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_ngap_PDUSessionResourceReleasedListNot(tvb, offset, &asn1_ctx, tree, hf_ngap_PDUSessionResourceReleasedListNot_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_PDUSessionResourceReleasedListPSAck_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_ngap_PDUSessionResourceReleasedListPSAck(tvb, offset, &asn1_ctx, tree, hf_ngap_PDUSessionResourceReleasedListPSAck_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_PDUSessionResourceReleasedListPSFail_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_ngap_PDUSessionResourceReleasedListPSFail(tvb, offset, &asn1_ctx, tree, hf_ngap_PDUSessionResourceReleasedListPSFail_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_PDUSessionResourceReleasedListRelRes_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_ngap_PDUSessionResourceReleasedListRelRes(tvb, offset, &asn1_ctx, tree, hf_ngap_PDUSessionResourceReleasedListRelRes_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_PDUSessionResourceReleaseResponseTransfer_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_ngap_PDUSessionResourceReleaseResponseTransfer(tvb, offset, &asn1_ctx, tree, hf_ngap_PDUSessionResourceReleaseResponseTransfer_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_PDUSessionResourceSecondaryRATUsageList_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_ngap_PDUSessionResourceSecondaryRATUsageList(tvb, offset, &asn1_ctx, tree, hf_ngap_PDUSessionResourceSecondaryRATUsageList_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_PDUSessionResourceSetupListCxtReq_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_ngap_PDUSessionResourceSetupListCxtReq(tvb, offset, &asn1_ctx, tree, hf_ngap_PDUSessionResourceSetupListCxtReq_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_PDUSessionResourceSetupListCxtRes_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_ngap_PDUSessionResourceSetupListCxtRes(tvb, offset, &asn1_ctx, tree, hf_ngap_PDUSessionResourceSetupListCxtRes_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_PDUSessionResourceSetupListHOReq_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_ngap_PDUSessionResourceSetupListHOReq(tvb, offset, &asn1_ctx, tree, hf_ngap_PDUSessionResourceSetupListHOReq_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_PDUSessionResourceSetupListSUReq_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_ngap_PDUSessionResourceSetupListSUReq(tvb, offset, &asn1_ctx, tree, hf_ngap_PDUSessionResourceSetupListSUReq_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_PDUSessionResourceSetupListSURes_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_ngap_PDUSessionResourceSetupListSURes(tvb, offset, &asn1_ctx, tree, hf_ngap_PDUSessionResourceSetupListSURes_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_PDUSessionResourceSetupRequestTransfer_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_ngap_PDUSessionResourceSetupRequestTransfer(tvb, offset, &asn1_ctx, tree, hf_ngap_PDUSessionResourceSetupRequestTransfer_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_PDUSessionResourceSetupResponseTransfer_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_ngap_PDUSessionResourceSetupResponseTransfer(tvb, offset, &asn1_ctx, tree, hf_ngap_PDUSessionResourceSetupResponseTransfer_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_PDUSessionResourceSetupUnsuccessfulTransfer_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_ngap_PDUSessionResourceSetupUnsuccessfulTransfer(tvb, offset, &asn1_ctx, tree, hf_ngap_PDUSessionResourceSetupUnsuccessfulTransfer_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_PDUSessionResourceSwitchedList_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_ngap_PDUSessionResourceSwitchedList(tvb, offset, &asn1_ctx, tree, hf_ngap_PDUSessionResourceSwitchedList_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_PDUSessionResourceToBeSwitchedDLList_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_ngap_PDUSessionResourceToBeSwitchedDLList(tvb, offset, &asn1_ctx, tree, hf_ngap_PDUSessionResourceToBeSwitchedDLList_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_PDUSessionResourceToReleaseListHOCmd_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_ngap_PDUSessionResourceToReleaseListHOCmd(tvb, offset, &asn1_ctx, tree, hf_ngap_PDUSessionResourceToReleaseListHOCmd_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_PDUSessionResourceToReleaseListRelCmd_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_ngap_PDUSessionResourceToReleaseListRelCmd(tvb, offset, &asn1_ctx, tree, hf_ngap_PDUSessionResourceToReleaseListRelCmd_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_PDUSessionType_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_ngap_PDUSessionType(tvb, offset, &asn1_ctx, tree, hf_ngap_PDUSessionType_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_PLMNIdentity_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_ngap_PLMNIdentity(tvb, offset, &asn1_ctx, tree, hf_ngap_PLMNIdentity_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_PLMNSupportList_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_ngap_PLMNSupportList(tvb, offset, &asn1_ctx, tree, hf_ngap_PLMNSupportList_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_PWSFailedCellIDList_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_ngap_PWSFailedCellIDList(tvb, offset, &asn1_ctx, tree, hf_ngap_PWSFailedCellIDList_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_QosFlowAddOrModifyRequestList_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_ngap_QosFlowAddOrModifyRequestList(tvb, offset, &asn1_ctx, tree, hf_ngap_QosFlowAddOrModifyRequestList_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_QosFlowListWithCause_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_ngap_QosFlowListWithCause(tvb, offset, &asn1_ctx, tree, hf_ngap_QosFlowListWithCause_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_QosFlowPerTNLInformationList_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_ngap_QosFlowPerTNLInformationList(tvb, offset, &asn1_ctx, tree, hf_ngap_QosFlowPerTNLInformationList_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_QosFlowSetupRequestList_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_ngap_QosFlowSetupRequestList(tvb, offset, &asn1_ctx, tree, hf_ngap_QosFlowSetupRequestList_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_RANNodeName_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_ngap_RANNodeName(tvb, offset, &asn1_ctx, tree, hf_ngap_RANNodeName_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_RANPagingPriority_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_ngap_RANPagingPriority(tvb, offset, &asn1_ctx, tree, hf_ngap_RANPagingPriority_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_RANStatusTransfer_TransparentContainer_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_ngap_RANStatusTransfer_TransparentContainer(tvb, offset, &asn1_ctx, tree, hf_ngap_RANStatusTransfer_TransparentContainer_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_RAN_UE_NGAP_ID_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_ngap_RAN_UE_NGAP_ID(tvb, offset, &asn1_ctx, tree, hf_ngap_RAN_UE_NGAP_ID_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_RedirectionVoiceFallback_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_ngap_RedirectionVoiceFallback(tvb, offset, &asn1_ctx, tree, hf_ngap_RedirectionVoiceFallback_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_RelativeAMFCapacity_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_ngap_RelativeAMFCapacity(tvb, offset, &asn1_ctx, tree, hf_ngap_RelativeAMFCapacity_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_RepetitionPeriod_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_ngap_RepetitionPeriod(tvb, offset, &asn1_ctx, tree, hf_ngap_RepetitionPeriod_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_ResetType_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_ngap_ResetType(tvb, offset, &asn1_ctx, tree, hf_ngap_ResetType_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_RoutingID_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_ngap_RoutingID(tvb, offset, &asn1_ctx, tree, hf_ngap_RoutingID_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_RRCEstablishmentCause_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_ngap_RRCEstablishmentCause(tvb, offset, &asn1_ctx, tree, hf_ngap_RRCEstablishmentCause_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_RRCInactiveTransitionReportRequest_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_ngap_RRCInactiveTransitionReportRequest(tvb, offset, &asn1_ctx, tree, hf_ngap_RRCInactiveTransitionReportRequest_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_RRCState_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_ngap_RRCState(tvb, offset, &asn1_ctx, tree, hf_ngap_RRCState_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_SCTP_TLAs_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_ngap_SCTP_TLAs(tvb, offset, &asn1_ctx, tree, hf_ngap_SCTP_TLAs_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_SecondaryRATUsageInformation_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_ngap_SecondaryRATUsageInformation(tvb, offset, &asn1_ctx, tree, hf_ngap_SecondaryRATUsageInformation_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_SecurityContext_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_ngap_SecurityContext(tvb, offset, &asn1_ctx, tree, hf_ngap_SecurityContext_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_SecurityIndication_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_ngap_SecurityIndication(tvb, offset, &asn1_ctx, tree, hf_ngap_SecurityIndication_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_SecurityKey_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_ngap_SecurityKey(tvb, offset, &asn1_ctx, tree, hf_ngap_SecurityKey_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_SecurityResult_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_ngap_SecurityResult(tvb, offset, &asn1_ctx, tree, hf_ngap_SecurityResult_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_SerialNumber_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_ngap_SerialNumber(tvb, offset, &asn1_ctx, tree, hf_ngap_SerialNumber_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_ServedGUAMIList_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_ngap_ServedGUAMIList(tvb, offset, &asn1_ctx, tree, hf_ngap_ServedGUAMIList_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_SliceSupportList_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_ngap_SliceSupportList(tvb, offset, &asn1_ctx, tree, hf_ngap_SliceSupportList_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_S_NSSAI_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_ngap_S_NSSAI(tvb, offset, &asn1_ctx, tree, hf_ngap_S_NSSAI_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_SONConfigurationTransfer_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_ngap_SONConfigurationTransfer(tvb, offset, &asn1_ctx, tree, hf_ngap_SONConfigurationTransfer_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
int dissect_ngap_SourceNGRANNode_ToTargetNGRANNode_TransparentContainer_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_ngap_SourceNGRANNode_ToTargetNGRANNode_TransparentContainer(tvb, offset, &asn1_ctx, tree, hf_ngap_ngap_SourceNGRANNode_ToTargetNGRANNode_TransparentContainer_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_SourceToTarget_TransparentContainer_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_ngap_SourceToTarget_TransparentContainer(tvb, offset, &asn1_ctx, tree, hf_ngap_SourceToTarget_TransparentContainer_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_SourceToTarget_AMFInformationReroute_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_ngap_SourceToTarget_AMFInformationReroute(tvb, offset, &asn1_ctx, tree, hf_ngap_SourceToTarget_AMFInformationReroute_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_SupportedTAList_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_ngap_SupportedTAList(tvb, offset, &asn1_ctx, tree, hf_ngap_SupportedTAList_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_TAIListForPaging_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_ngap_TAIListForPaging(tvb, offset, &asn1_ctx, tree, hf_ngap_TAIListForPaging_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_TAIListForRestart_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_ngap_TAIListForRestart(tvb, offset, &asn1_ctx, tree, hf_ngap_TAIListForRestart_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_TargetID_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_ngap_TargetID(tvb, offset, &asn1_ctx, tree, hf_ngap_TargetID_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
int dissect_ngap_TargetNGRANNode_ToSourceNGRANNode_TransparentContainer_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_ngap_TargetNGRANNode_ToSourceNGRANNode_TransparentContainer(tvb, offset, &asn1_ctx, tree, hf_ngap_ngap_TargetNGRANNode_ToSourceNGRANNode_TransparentContainer_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_TargetToSource_TransparentContainer_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_ngap_TargetToSource_TransparentContainer(tvb, offset, &asn1_ctx, tree, hf_ngap_TargetToSource_TransparentContainer_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_TimeToWait_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_ngap_TimeToWait(tvb, offset, &asn1_ctx, tree, hf_ngap_TimeToWait_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_TNLAssociationList_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_ngap_TNLAssociationList(tvb, offset, &asn1_ctx, tree, hf_ngap_TNLAssociationList_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_TraceActivation_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_ngap_TraceActivation(tvb, offset, &asn1_ctx, tree, hf_ngap_TraceActivation_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_TrafficLoadReductionIndication_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_ngap_TrafficLoadReductionIndication(tvb, offset, &asn1_ctx, tree, hf_ngap_TrafficLoadReductionIndication_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_TransportLayerAddress_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_ngap_TransportLayerAddress(tvb, offset, &asn1_ctx, tree, hf_ngap_TransportLayerAddress_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_UEAggregateMaximumBitRate_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_ngap_UEAggregateMaximumBitRate(tvb, offset, &asn1_ctx, tree, hf_ngap_UEAggregateMaximumBitRate_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_UE_associatedLogicalNG_connectionList_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_ngap_UE_associatedLogicalNG_connectionList(tvb, offset, &asn1_ctx, tree, hf_ngap_UE_associatedLogicalNG_connectionList_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_UEContextRequest_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_ngap_UEContextRequest(tvb, offset, &asn1_ctx, tree, hf_ngap_UEContextRequest_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_UE_NGAP_IDs_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_ngap_UE_NGAP_IDs(tvb, offset, &asn1_ctx, tree, hf_ngap_UE_NGAP_IDs_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_UEPagingIdentity_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_ngap_UEPagingIdentity(tvb, offset, &asn1_ctx, tree, hf_ngap_UEPagingIdentity_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_UEPresenceInAreaOfInterestList_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_ngap_UEPresenceInAreaOfInterestList(tvb, offset, &asn1_ctx, tree, hf_ngap_UEPresenceInAreaOfInterestList_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_UERadioCapability_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_ngap_UERadioCapability(tvb, offset, &asn1_ctx, tree, hf_ngap_UERadioCapability_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_UERadioCapabilityForPaging_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_ngap_UERadioCapabilityForPaging(tvb, offset, &asn1_ctx, tree, hf_ngap_UERadioCapabilityForPaging_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_UERetentionInformation_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_ngap_UERetentionInformation(tvb, offset, &asn1_ctx, tree, hf_ngap_UERetentionInformation_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_UESecurityCapabilities_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_ngap_UESecurityCapabilities(tvb, offset, &asn1_ctx, tree, hf_ngap_UESecurityCapabilities_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_UL_NGU_UP_TNLModifyList_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_ngap_UL_NGU_UP_TNLModifyList(tvb, offset, &asn1_ctx, tree, hf_ngap_UL_NGU_UP_TNLModifyList_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_UnavailableGUAMIList_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_ngap_UnavailableGUAMIList(tvb, offset, &asn1_ctx, tree, hf_ngap_UnavailableGUAMIList_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_ULForwarding_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_ngap_ULForwarding(tvb, offset, &asn1_ctx, tree, hf_ngap_ULForwarding_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_UPTransportLayerInformation_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_ngap_UPTransportLayerInformation(tvb, offset, &asn1_ctx, tree, hf_ngap_UPTransportLayerInformation_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_UPTransportLayerInformationList_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_ngap_UPTransportLayerInformationList(tvb, offset, &asn1_ctx, tree, hf_ngap_UPTransportLayerInformationList_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_UPTransportLayerInformationPairList_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_ngap_UPTransportLayerInformationPairList(tvb, offset, &asn1_ctx, tree, hf_ngap_UPTransportLayerInformationPairList_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_UserLocationInformation_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_ngap_UserLocationInformation(tvb, offset, &asn1_ctx, tree, hf_ngap_UserLocationInformation_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_WarningAreaCoordinates_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_ngap_WarningAreaCoordinates(tvb, offset, &asn1_ctx, tree, hf_ngap_WarningAreaCoordinates_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_WarningAreaList_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_ngap_WarningAreaList(tvb, offset, &asn1_ctx, tree, hf_ngap_WarningAreaList_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_WarningMessageContents_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_ngap_WarningMessageContents(tvb, offset, &asn1_ctx, tree, hf_ngap_WarningMessageContents_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_WarningSecurityInfo_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_ngap_WarningSecurityInfo(tvb, offset, &asn1_ctx, tree, hf_ngap_WarningSecurityInfo_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_WarningType_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_ngap_WarningType(tvb, offset, &asn1_ctx, tree, hf_ngap_WarningType_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_PDUSessionResourceSetupRequest_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_ngap_PDUSessionResourceSetupRequest(tvb, offset, &asn1_ctx, tree, hf_ngap_PDUSessionResourceSetupRequest_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_PDUSessionResourceSetupResponse_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_ngap_PDUSessionResourceSetupResponse(tvb, offset, &asn1_ctx, tree, hf_ngap_PDUSessionResourceSetupResponse_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_PDUSessionResourceReleaseCommand_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_ngap_PDUSessionResourceReleaseCommand(tvb, offset, &asn1_ctx, tree, hf_ngap_PDUSessionResourceReleaseCommand_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_PDUSessionResourceReleaseResponse_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_ngap_PDUSessionResourceReleaseResponse(tvb, offset, &asn1_ctx, tree, hf_ngap_PDUSessionResourceReleaseResponse_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_PDUSessionResourceModifyRequest_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_ngap_PDUSessionResourceModifyRequest(tvb, offset, &asn1_ctx, tree, hf_ngap_PDUSessionResourceModifyRequest_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_PDUSessionResourceModifyResponse_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_ngap_PDUSessionResourceModifyResponse(tvb, offset, &asn1_ctx, tree, hf_ngap_PDUSessionResourceModifyResponse_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_PDUSessionResourceNotify_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_ngap_PDUSessionResourceNotify(tvb, offset, &asn1_ctx, tree, hf_ngap_PDUSessionResourceNotify_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_PDUSessionResourceModifyIndication_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_ngap_PDUSessionResourceModifyIndication(tvb, offset, &asn1_ctx, tree, hf_ngap_PDUSessionResourceModifyIndication_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_PDUSessionResourceModifyConfirm_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_ngap_PDUSessionResourceModifyConfirm(tvb, offset, &asn1_ctx, tree, hf_ngap_PDUSessionResourceModifyConfirm_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_InitialContextSetupRequest_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_ngap_InitialContextSetupRequest(tvb, offset, &asn1_ctx, tree, hf_ngap_InitialContextSetupRequest_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_InitialContextSetupResponse_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_ngap_InitialContextSetupResponse(tvb, offset, &asn1_ctx, tree, hf_ngap_InitialContextSetupResponse_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_InitialContextSetupFailure_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_ngap_InitialContextSetupFailure(tvb, offset, &asn1_ctx, tree, hf_ngap_InitialContextSetupFailure_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_UEContextReleaseRequest_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_ngap_UEContextReleaseRequest(tvb, offset, &asn1_ctx, tree, hf_ngap_UEContextReleaseRequest_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_UEContextReleaseCommand_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_ngap_UEContextReleaseCommand(tvb, offset, &asn1_ctx, tree, hf_ngap_UEContextReleaseCommand_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_UEContextReleaseComplete_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_ngap_UEContextReleaseComplete(tvb, offset, &asn1_ctx, tree, hf_ngap_UEContextReleaseComplete_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_UEContextModificationRequest_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_ngap_UEContextModificationRequest(tvb, offset, &asn1_ctx, tree, hf_ngap_UEContextModificationRequest_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_UEContextModificationResponse_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_ngap_UEContextModificationResponse(tvb, offset, &asn1_ctx, tree, hf_ngap_UEContextModificationResponse_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_UEContextModificationFailure_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_ngap_UEContextModificationFailure(tvb, offset, &asn1_ctx, tree, hf_ngap_UEContextModificationFailure_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_RRCInactiveTransitionReport_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_ngap_RRCInactiveTransitionReport(tvb, offset, &asn1_ctx, tree, hf_ngap_RRCInactiveTransitionReport_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_HandoverRequired_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_ngap_HandoverRequired(tvb, offset, &asn1_ctx, tree, hf_ngap_HandoverRequired_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_HandoverCommand_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_ngap_HandoverCommand(tvb, offset, &asn1_ctx, tree, hf_ngap_HandoverCommand_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_HandoverPreparationFailure_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_ngap_HandoverPreparationFailure(tvb, offset, &asn1_ctx, tree, hf_ngap_HandoverPreparationFailure_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_HandoverRequest_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_ngap_HandoverRequest(tvb, offset, &asn1_ctx, tree, hf_ngap_HandoverRequest_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_HandoverRequestAcknowledge_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_ngap_HandoverRequestAcknowledge(tvb, offset, &asn1_ctx, tree, hf_ngap_HandoverRequestAcknowledge_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_HandoverFailure_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_ngap_HandoverFailure(tvb, offset, &asn1_ctx, tree, hf_ngap_HandoverFailure_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_HandoverNotify_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_ngap_HandoverNotify(tvb, offset, &asn1_ctx, tree, hf_ngap_HandoverNotify_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_PathSwitchRequest_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_ngap_PathSwitchRequest(tvb, offset, &asn1_ctx, tree, hf_ngap_PathSwitchRequest_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_PathSwitchRequestAcknowledge_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_ngap_PathSwitchRequestAcknowledge(tvb, offset, &asn1_ctx, tree, hf_ngap_PathSwitchRequestAcknowledge_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_PathSwitchRequestFailure_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_ngap_PathSwitchRequestFailure(tvb, offset, &asn1_ctx, tree, hf_ngap_PathSwitchRequestFailure_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_HandoverCancel_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_ngap_HandoverCancel(tvb, offset, &asn1_ctx, tree, hf_ngap_HandoverCancel_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_HandoverCancelAcknowledge_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_ngap_HandoverCancelAcknowledge(tvb, offset, &asn1_ctx, tree, hf_ngap_HandoverCancelAcknowledge_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_UplinkRANStatusTransfer_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_ngap_UplinkRANStatusTransfer(tvb, offset, &asn1_ctx, tree, hf_ngap_UplinkRANStatusTransfer_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_DownlinkRANStatusTransfer_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_ngap_DownlinkRANStatusTransfer(tvb, offset, &asn1_ctx, tree, hf_ngap_DownlinkRANStatusTransfer_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_Paging_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_ngap_Paging(tvb, offset, &asn1_ctx, tree, hf_ngap_Paging_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_InitialUEMessage_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_ngap_InitialUEMessage(tvb, offset, &asn1_ctx, tree, hf_ngap_InitialUEMessage_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_DownlinkNASTransport_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_ngap_DownlinkNASTransport(tvb, offset, &asn1_ctx, tree, hf_ngap_DownlinkNASTransport_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_UplinkNASTransport_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_ngap_UplinkNASTransport(tvb, offset, &asn1_ctx, tree, hf_ngap_UplinkNASTransport_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_NASNonDeliveryIndication_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_ngap_NASNonDeliveryIndication(tvb, offset, &asn1_ctx, tree, hf_ngap_NASNonDeliveryIndication_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_RerouteNASRequest_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_ngap_RerouteNASRequest(tvb, offset, &asn1_ctx, tree, hf_ngap_RerouteNASRequest_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_NGAP_Message_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_ngap_NGAP_Message(tvb, offset, &asn1_ctx, tree, hf_ngap_NGAP_Message_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_NGSetupRequest_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_ngap_NGSetupRequest(tvb, offset, &asn1_ctx, tree, hf_ngap_NGSetupRequest_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_NGSetupResponse_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_ngap_NGSetupResponse(tvb, offset, &asn1_ctx, tree, hf_ngap_NGSetupResponse_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_NGSetupFailure_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_ngap_NGSetupFailure(tvb, offset, &asn1_ctx, tree, hf_ngap_NGSetupFailure_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_RANConfigurationUpdate_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_ngap_RANConfigurationUpdate(tvb, offset, &asn1_ctx, tree, hf_ngap_RANConfigurationUpdate_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_RANConfigurationUpdateAcknowledge_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_ngap_RANConfigurationUpdateAcknowledge(tvb, offset, &asn1_ctx, tree, hf_ngap_RANConfigurationUpdateAcknowledge_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_RANConfigurationUpdateFailure_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_ngap_RANConfigurationUpdateFailure(tvb, offset, &asn1_ctx, tree, hf_ngap_RANConfigurationUpdateFailure_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_AMFConfigurationUpdate_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_ngap_AMFConfigurationUpdate(tvb, offset, &asn1_ctx, tree, hf_ngap_AMFConfigurationUpdate_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_AMFConfigurationUpdateAcknowledge_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_ngap_AMFConfigurationUpdateAcknowledge(tvb, offset, &asn1_ctx, tree, hf_ngap_AMFConfigurationUpdateAcknowledge_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_AMFConfigurationUpdateFailure_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_ngap_AMFConfigurationUpdateFailure(tvb, offset, &asn1_ctx, tree, hf_ngap_AMFConfigurationUpdateFailure_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_AMFStatusIndication_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_ngap_AMFStatusIndication(tvb, offset, &asn1_ctx, tree, hf_ngap_AMFStatusIndication_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_NGReset_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_ngap_NGReset(tvb, offset, &asn1_ctx, tree, hf_ngap_NGReset_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_NGResetAcknowledge_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_ngap_NGResetAcknowledge(tvb, offset, &asn1_ctx, tree, hf_ngap_NGResetAcknowledge_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_ErrorIndication_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_ngap_ErrorIndication(tvb, offset, &asn1_ctx, tree, hf_ngap_ErrorIndication_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_OverloadStart_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_ngap_OverloadStart(tvb, offset, &asn1_ctx, tree, hf_ngap_OverloadStart_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_OverloadStop_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_ngap_OverloadStop(tvb, offset, &asn1_ctx, tree, hf_ngap_OverloadStop_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_UplinkRANConfigurationTransfer_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_ngap_UplinkRANConfigurationTransfer(tvb, offset, &asn1_ctx, tree, hf_ngap_UplinkRANConfigurationTransfer_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_DownlinkRANConfigurationTransfer_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_ngap_DownlinkRANConfigurationTransfer(tvb, offset, &asn1_ctx, tree, hf_ngap_DownlinkRANConfigurationTransfer_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_WriteReplaceWarningRequest_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_ngap_WriteReplaceWarningRequest(tvb, offset, &asn1_ctx, tree, hf_ngap_WriteReplaceWarningRequest_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_WriteReplaceWarningResponse_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_ngap_WriteReplaceWarningResponse(tvb, offset, &asn1_ctx, tree, hf_ngap_WriteReplaceWarningResponse_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_PWSCancelRequest_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_ngap_PWSCancelRequest(tvb, offset, &asn1_ctx, tree, hf_ngap_PWSCancelRequest_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_PWSCancelResponse_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_ngap_PWSCancelResponse(tvb, offset, &asn1_ctx, tree, hf_ngap_PWSCancelResponse_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_PWSRestartIndication_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_ngap_PWSRestartIndication(tvb, offset, &asn1_ctx, tree, hf_ngap_PWSRestartIndication_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_PWSFailureIndication_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_ngap_PWSFailureIndication(tvb, offset, &asn1_ctx, tree, hf_ngap_PWSFailureIndication_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_DownlinkUEAssociatedNRPPaTransport_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_ngap_DownlinkUEAssociatedNRPPaTransport(tvb, offset, &asn1_ctx, tree, hf_ngap_DownlinkUEAssociatedNRPPaTransport_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_UplinkUEAssociatedNRPPaTransport_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_ngap_UplinkUEAssociatedNRPPaTransport(tvb, offset, &asn1_ctx, tree, hf_ngap_UplinkUEAssociatedNRPPaTransport_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_DownlinkNonUEAssociatedNRPPaTransport_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_ngap_DownlinkNonUEAssociatedNRPPaTransport(tvb, offset, &asn1_ctx, tree, hf_ngap_DownlinkNonUEAssociatedNRPPaTransport_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_UplinkNonUEAssociatedNRPPaTransport_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_ngap_UplinkNonUEAssociatedNRPPaTransport(tvb, offset, &asn1_ctx, tree, hf_ngap_UplinkNonUEAssociatedNRPPaTransport_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_TraceStart_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_ngap_TraceStart(tvb, offset, &asn1_ctx, tree, hf_ngap_TraceStart_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_TraceFailureIndication_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_ngap_TraceFailureIndication(tvb, offset, &asn1_ctx, tree, hf_ngap_TraceFailureIndication_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_DeactivateTrace_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_ngap_DeactivateTrace(tvb, offset, &asn1_ctx, tree, hf_ngap_DeactivateTrace_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_CellTrafficTrace_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_ngap_CellTrafficTrace(tvb, offset, &asn1_ctx, tree, hf_ngap_CellTrafficTrace_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_LocationReportingControl_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_ngap_LocationReportingControl(tvb, offset, &asn1_ctx, tree, hf_ngap_LocationReportingControl_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_LocationReportingFailureIndication_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_ngap_LocationReportingFailureIndication(tvb, offset, &asn1_ctx, tree, hf_ngap_LocationReportingFailureIndication_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_LocationReport_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_ngap_LocationReport(tvb, offset, &asn1_ctx, tree, hf_ngap_LocationReport_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_UETNLABindingReleaseRequest_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_ngap_UETNLABindingReleaseRequest(tvb, offset, &asn1_ctx, tree, hf_ngap_UETNLABindingReleaseRequest_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_UERadioCapabilityInfoIndication_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_ngap_UERadioCapabilityInfoIndication(tvb, offset, &asn1_ctx, tree, hf_ngap_UERadioCapabilityInfoIndication_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_UERadioCapabilityCheckRequest_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_ngap_UERadioCapabilityCheckRequest(tvb, offset, &asn1_ctx, tree, hf_ngap_UERadioCapabilityCheckRequest_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_UERadioCapabilityCheckResponse_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_ngap_UERadioCapabilityCheckResponse(tvb, offset, &asn1_ctx, tree, hf_ngap_UERadioCapabilityCheckResponse_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_PrivateMessage_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_ngap_PrivateMessage(tvb, offset, &asn1_ctx, tree, hf_ngap_PrivateMessage_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_SecondaryRATDataUsageReport_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_ngap_SecondaryRATDataUsageReport(tvb, offset, &asn1_ctx, tree, hf_ngap_SecondaryRATDataUsageReport_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_NGAP_PDU_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_ngap_NGAP_PDU(tvb, offset, &asn1_ctx, tree, hf_ngap_NGAP_PDU_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_PDUSessionResourceModifyIndicationUnsuccessfulTransfer_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_ngap_PDUSessionResourceModifyIndicationUnsuccessfulTransfer(tvb, offset, &asn1_ctx, tree, hf_ngap_PDUSessionResourceModifyIndicationUnsuccessfulTransfer_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_SecondaryRATDataUsageReportTransfer_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_ngap_SecondaryRATDataUsageReportTransfer(tvb, offset, &asn1_ctx, tree, hf_ngap_SecondaryRATDataUsageReportTransfer_PDU);
  offset += 7; offset >>= 3;
  return offset;
}


/*--- End of included file: packet-ngap-fn.c ---*/
#line 354 "./asn1/ngap/packet-ngap-template.c"

static int dissect_ProtocolIEFieldValue(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
  ngap_ctx_t ngap_ctx;
  struct ngap_private_data *ngap_data = ngap_get_private_data(pinfo);

  ngap_ctx.message_type        = ngap_data->message_type;
  ngap_ctx.ProcedureCode       = ngap_data->procedure_code;
  ngap_ctx.ProtocolIE_ID       = ngap_data->protocol_ie_id;
  ngap_ctx.ProtocolExtensionID = ngap_data->protocol_extension_id;

  return (dissector_try_uint_new(ngap_ies_dissector_table, ngap_data->protocol_ie_id, tvb, pinfo, tree, FALSE, &ngap_ctx)) ? tvb_captured_length(tvb) : 0;
}
/* Currently not used
static int dissect_ProtocolIEFieldPairFirstValue(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
  struct ngap_private_data *ngap_data = ngap_get_private_data(pinfo);

  return (dissector_try_uint(ngap_ies_p1_dissector_table, ngap_data->protocol_ie_id, tvb, pinfo, tree)) ? tvb_captured_length(tvb) : 0;
}

static int dissect_ProtocolIEFieldPairSecondValue(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
  struct ngap_private_data *ngap_data = ngap_get_private_data(pinfo);

  return (dissector_try_uint(ngap_ies_p2_dissector_table, ngap_data->protocol_ie_id, tvb, pinfo, tree)) ? tvb_captured_length(tvb) : 0;
}
*/

static int dissect_ProtocolExtensionFieldExtensionValue(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
  ngap_ctx_t ngap_ctx;
  struct ngap_private_data *ngap_data = ngap_get_private_data(pinfo);

  ngap_ctx.message_type        = ngap_data->message_type;
  ngap_ctx.ProcedureCode       = ngap_data->procedure_code;
  ngap_ctx.ProtocolIE_ID       = ngap_data->protocol_ie_id;
  ngap_ctx.ProtocolExtensionID = ngap_data->protocol_extension_id;

  return (dissector_try_uint_new(ngap_extension_dissector_table, ngap_data->protocol_extension_id, tvb, pinfo, tree, TRUE, &ngap_ctx)) ? tvb_captured_length(tvb) : 0;
}

static int dissect_InitiatingMessageValue(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data)
{
  struct ngap_private_data *ngap_data = ngap_get_private_data(pinfo);

  return (dissector_try_uint_new(ngap_proc_imsg_dissector_table, ngap_data->procedure_code, tvb, pinfo, tree, TRUE, data)) ? tvb_captured_length(tvb) : 0;
}

static int dissect_SuccessfulOutcomeValue(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data)
{
  struct ngap_private_data *ngap_data = ngap_get_private_data(pinfo);

  return (dissector_try_uint_new(ngap_proc_sout_dissector_table, ngap_data->procedure_code, tvb, pinfo, tree, TRUE, data)) ? tvb_captured_length(tvb) : 0;
}

static int dissect_UnsuccessfulOutcomeValue(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data)
{
  struct ngap_private_data *ngap_data = ngap_get_private_data(pinfo);

  return (dissector_try_uint_new(ngap_proc_uout_dissector_table, ngap_data->procedure_code, tvb, pinfo, tree, TRUE, data)) ? tvb_captured_length(tvb) : 0;
}


static int
dissect_ngap(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
  proto_item *ngap_item = NULL;
  proto_tree *ngap_tree = NULL;
  conversation_t *conversation;
  struct ngap_private_data *ngap_data;
  wmem_list_frame_t *prev_layer;

  /* make entry in the Protocol column on summary display */
  col_set_str(pinfo->cinfo, COL_PROTOCOL, "NGAP");
  /* ensure that parent dissector is not NGAP before clearing fence */
  prev_layer = wmem_list_frame_prev(wmem_list_tail(pinfo->layers));
  if (prev_layer && GPOINTER_TO_INT(wmem_list_frame_data(prev_layer)) != proto_ngap)
    col_clear_fence(pinfo->cinfo, COL_INFO);
  col_clear(pinfo->cinfo, COL_INFO);

  /* create the ngap protocol tree */
  ngap_item = proto_tree_add_item(tree, proto_ngap, tvb, 0, -1, ENC_NA);
  ngap_tree = proto_item_add_subtree(ngap_item, ett_ngap);

  ngap_data = ngap_get_private_data(pinfo);
  conversation = find_or_create_conversation(pinfo);
  ngap_data->ngap_conv = (struct ngap_conv_info *)conversation_get_proto_data(conversation, proto_ngap);
  if (!ngap_data->ngap_conv) {
    ngap_data->ngap_conv = wmem_new0(wmem_file_scope(), struct ngap_conv_info);
    copy_address_wmem(wmem_file_scope(), &ngap_data->ngap_conv->addr_a, &pinfo->src);
    ngap_data->ngap_conv->port_a = pinfo->srcport;
    ngap_data->ngap_conv->ranmode_id_a = (GlobalRANNodeID_enum)-1;
    copy_address_wmem(wmem_file_scope(), &ngap_data->ngap_conv->addr_b, &pinfo->dst);
    ngap_data->ngap_conv->port_b = pinfo->destport;
    ngap_data->ngap_conv->ranmode_id_b = (GlobalRANNodeID_enum)-1;
    conversation_add_proto_data(conversation, proto_ngap, ngap_data->ngap_conv);
  }

  return dissect_NGAP_PDU_PDU(tvb, pinfo, ngap_tree, NULL);
}

/* 3GPP TS 29.502 chapter 6.1.6.4.3 and 29.518 chapter 6.1.6.4.3 */
static int
dissect_ngap_media_type(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data)
{
  int ret;
  char *json_data;
  const char *n2_info_class, *str, *content_id_str;
  jsmntok_t *tokens, *cur_tok, *n2_info_content_tok;
  dissector_handle_t subdissector;
  tvbuff_t* json_tvb = (tvbuff_t*)p_get_proto_data(pinfo->pool, pinfo, proto_json, 0);
  http_message_info_t *message_info = (http_message_info_t *)data;

  if (!json_tvb || !message_info || !message_info->content_id)
    return 0;

  json_data = tvb_get_string_enc(wmem_packet_scope(), json_tvb, 0, tvb_reported_length(json_tvb), ENC_UTF_8|ENC_NA);
  ret = json_parse(json_data, NULL, 0);
  if (ret <= 0)
    return 0;
  tokens = wmem_alloc_array(wmem_packet_scope(), jsmntok_t, ret);
  if (json_parse(json_data, tokens, ret) <= 0)
    return 0;
  cur_tok = json_get_object(json_data, tokens, "n2InfoContainer");
  if (!cur_tok) {
      /* look for n2Information too*/
      cur_tok = json_get_object(json_data, tokens, "n2Information");
  }
  if (cur_tok) {
    n2_info_class = json_get_string(json_data, cur_tok, "n2InformationClass");
    if (!n2_info_class)
      return 0;
    if (!strcmp(n2_info_class, "SM")) {
      cur_tok = json_get_object(json_data, cur_tok, "smInfo");
      if (!cur_tok)
        return 0;
      n2_info_content_tok = json_get_object(json_data, cur_tok, "n2InfoContent");
      if (!n2_info_content_tok)
        return 0;
      str = json_get_string(json_data, n2_info_content_tok, "ngapIeType");
      if (!str)
        return 0;
      subdissector = dissector_get_string_handle(ngap_n2_ie_type_dissector_table, str);
    } else if (!strcmp(n2_info_class, "RAN")) {
      cur_tok = json_get_object(json_data, cur_tok, "ranInfo");
      if (!cur_tok)
        return 0;
      n2_info_content_tok = json_get_object(json_data, cur_tok, "n2InfoContent");
      if (!n2_info_content_tok)
        return 0;
      str = json_get_string(json_data, n2_info_content_tok, "ngapIeType");
      if (!str)
        return 0;
      subdissector = dissector_get_string_handle(ngap_n2_ie_type_dissector_table, str);
    } else if (!strcmp(n2_info_class, "NRPPa")) {
      cur_tok = json_get_object(json_data, cur_tok, "nrppaInfo");
      if (!cur_tok)
        return 0;
      n2_info_content_tok = json_get_object(json_data, cur_tok, "nrppaPdu");
      if (!n2_info_content_tok)
        return 0;
      str = json_get_string(json_data, n2_info_content_tok, "ngapIeType");
      if (!str)
        return 0;
      subdissector = dissector_get_string_handle(ngap_n2_ie_type_dissector_table, str);
    } else if (!strcmp(n2_info_class, "PWS") ||
               !strcmp(n2_info_class, "PWS-BCAL") ||
               !strcmp(n2_info_class, "PWS-RF")) {
      cur_tok = json_get_object(json_data, cur_tok, "pwsInfo");
      if (!cur_tok)
        return 0;
      n2_info_content_tok = json_get_object(json_data, cur_tok, "pwsContainer");
      if (!n2_info_content_tok)
        return 0;
      subdissector = ngap_handle;
    } else {
      return 0;
    }
    cur_tok = json_get_object(json_data, n2_info_content_tok, "ngapData");
    if (!cur_tok)
      return 0;
    content_id_str = json_get_string(json_data, cur_tok, "contentId");
  } else {
    cur_tok = json_get_object(json_data, tokens, "n2SmInfo");
    if (cur_tok) {
      content_id_str = json_get_string(json_data, cur_tok, "contentId");
      str = json_get_string(json_data, tokens, "n2SmInfoType");
      if (!str)
        return 0;
      subdissector = dissector_get_string_handle(ngap_n2_ie_type_dissector_table, str);
    } else {
      return 0;
    }
  }

  if (subdissector) {
    proto_item *ngap_item;
    proto_tree *ngap_tree;

    if (!content_id_str || strcmp(content_id_str, message_info->content_id))
      return 0;
    col_append_sep_str(pinfo->cinfo, COL_PROTOCOL, "/", "NGAP");
    ngap_item = proto_tree_add_item(tree, proto_ngap, tvb, 0, -1, ENC_NA);
    ngap_tree = proto_item_add_subtree(ngap_item, ett_ngap);
    gboolean save_writable = col_get_writable(pinfo->cinfo, COL_PROTOCOL);
    col_set_writable(pinfo->cinfo, COL_PROTOCOL, FALSE);
    call_dissector_with_data(subdissector, tvb, pinfo, ngap_tree, NULL);
    col_set_writable(pinfo->cinfo, COL_PROTOCOL, save_writable);
    return tvb_captured_length(tvb);
  } else {
    return 0;
  }
}

/*--- proto_reg_handoff_ngap ---------------------------------------*/
void
proto_reg_handoff_ngap(void)
{
  static gboolean Initialized=FALSE;
  static guint SctpPort;

  if (!Initialized) {
    nas_5gs_handle = find_dissector_add_dependency("nas-5gs", proto_ngap);
    nr_rrc_ue_radio_paging_info_handle = find_dissector_add_dependency("nr-rrc.ue_radio_paging_info", proto_ngap);
    nr_rrc_ue_radio_access_cap_info_handle = find_dissector_add_dependency("nr-rrc.ue_radio_access_cap_info", proto_ngap);
    lte_rrc_ue_radio_paging_info_handle = find_dissector_add_dependency("lte-rrc.ue_radio_paging_info", proto_ngap);
    dissector_add_for_decode_as("sctp.port", ngap_handle);
    dissector_add_uint("sctp.ppi", NGAP_PROTOCOL_ID,   ngap_handle);
    Initialized=TRUE;

/*--- Included file: packet-ngap-dis-tab.c ---*/
#line 1 "./asn1/ngap/packet-ngap-dis-tab.c"
  dissector_add_uint("ngap.ies", id_AllowedNSSAI, create_dissector_handle(dissect_AllowedNSSAI_PDU, proto_ngap));
  dissector_add_uint("ngap.ies", id_AMFName, create_dissector_handle(dissect_AMFName_PDU, proto_ngap));
  dissector_add_uint("ngap.ies", id_AMFOverloadResponse, create_dissector_handle(dissect_OverloadResponse_PDU, proto_ngap));
  dissector_add_uint("ngap.ies", id_AMFSetID, create_dissector_handle(dissect_AMFSetID_PDU, proto_ngap));
  dissector_add_uint("ngap.ies", id_AMF_TNLAssociationFailedToSetupList, create_dissector_handle(dissect_TNLAssociationList_PDU, proto_ngap));
  dissector_add_uint("ngap.ies", id_AMF_TNLAssociationSetupList, create_dissector_handle(dissect_AMF_TNLAssociationSetupList_PDU, proto_ngap));
  dissector_add_uint("ngap.ies", id_AMF_TNLAssociationToAddList, create_dissector_handle(dissect_AMF_TNLAssociationToAddList_PDU, proto_ngap));
  dissector_add_uint("ngap.ies", id_AMF_TNLAssociationToRemoveList, create_dissector_handle(dissect_AMF_TNLAssociationToRemoveList_PDU, proto_ngap));
  dissector_add_uint("ngap.ies", id_AMF_TNLAssociationToUpdateList, create_dissector_handle(dissect_AMF_TNLAssociationToUpdateList_PDU, proto_ngap));
  dissector_add_uint("ngap.ies", id_AMFTrafficLoadReductionIndication, create_dissector_handle(dissect_TrafficLoadReductionIndication_PDU, proto_ngap));
  dissector_add_uint("ngap.ies", id_AMF_UE_NGAP_ID, create_dissector_handle(dissect_AMF_UE_NGAP_ID_PDU, proto_ngap));
  dissector_add_uint("ngap.ies", id_AssistanceDataForPaging, create_dissector_handle(dissect_AssistanceDataForPaging_PDU, proto_ngap));
  dissector_add_uint("ngap.ies", id_BroadcastCancelledAreaList, create_dissector_handle(dissect_BroadcastCancelledAreaList_PDU, proto_ngap));
  dissector_add_uint("ngap.ies", id_BroadcastCompletedAreaList, create_dissector_handle(dissect_BroadcastCompletedAreaList_PDU, proto_ngap));
  dissector_add_uint("ngap.ies", id_CancelAllWarningMessages, create_dissector_handle(dissect_CancelAllWarningMessages_PDU, proto_ngap));
  dissector_add_uint("ngap.ies", id_Cause, create_dissector_handle(dissect_Cause_PDU, proto_ngap));
  dissector_add_uint("ngap.ies", id_CellIDListForRestart, create_dissector_handle(dissect_CellIDListForRestart_PDU, proto_ngap));
  dissector_add_uint("ngap.ies", id_ConcurrentWarningMessageInd, create_dissector_handle(dissect_ConcurrentWarningMessageInd_PDU, proto_ngap));
  dissector_add_uint("ngap.ies", id_CoreNetworkAssistanceInformationForInactive, create_dissector_handle(dissect_CoreNetworkAssistanceInformationForInactive_PDU, proto_ngap));
  dissector_add_uint("ngap.ies", id_CriticalityDiagnostics, create_dissector_handle(dissect_CriticalityDiagnostics_PDU, proto_ngap));
  dissector_add_uint("ngap.ies", id_DataCodingScheme, create_dissector_handle(dissect_DataCodingScheme_PDU, proto_ngap));
  dissector_add_uint("ngap.ies", id_DefaultPagingDRX, create_dissector_handle(dissect_PagingDRX_PDU, proto_ngap));
  dissector_add_uint("ngap.ies", id_DirectForwardingPathAvailability, create_dissector_handle(dissect_DirectForwardingPathAvailability_PDU, proto_ngap));
  dissector_add_uint("ngap.ies", id_EmergencyAreaIDListForRestart, create_dissector_handle(dissect_EmergencyAreaIDListForRestart_PDU, proto_ngap));
  dissector_add_uint("ngap.ies", id_EmergencyFallbackIndicator, create_dissector_handle(dissect_EmergencyFallbackIndicator_PDU, proto_ngap));
  dissector_add_uint("ngap.ies", id_EUTRA_CGI, create_dissector_handle(dissect_EUTRA_CGI_PDU, proto_ngap));
  dissector_add_uint("ngap.ies", id_FiveG_S_TMSI, create_dissector_handle(dissect_FiveG_S_TMSI_PDU, proto_ngap));
  dissector_add_uint("ngap.ies", id_GlobalRANNodeID, create_dissector_handle(dissect_GlobalRANNodeID_PDU, proto_ngap));
  dissector_add_uint("ngap.ies", id_GUAMI, create_dissector_handle(dissect_GUAMI_PDU, proto_ngap));
  dissector_add_uint("ngap.ies", id_HandoverType, create_dissector_handle(dissect_HandoverType_PDU, proto_ngap));
  dissector_add_uint("ngap.ies", id_IMSVoiceSupportIndicator, create_dissector_handle(dissect_IMSVoiceSupportIndicator_PDU, proto_ngap));
  dissector_add_uint("ngap.ies", id_IndexToRFSP, create_dissector_handle(dissect_IndexToRFSP_PDU, proto_ngap));
  dissector_add_uint("ngap.ies", id_InfoOnRecommendedCellsAndRANNodesForPaging, create_dissector_handle(dissect_InfoOnRecommendedCellsAndRANNodesForPaging_PDU, proto_ngap));
  dissector_add_uint("ngap.ies", id_LocationReportingRequestType, create_dissector_handle(dissect_LocationReportingRequestType_PDU, proto_ngap));
  dissector_add_uint("ngap.ies", id_MaskedIMEISV, create_dissector_handle(dissect_MaskedIMEISV_PDU, proto_ngap));
  dissector_add_uint("ngap.ies", id_MessageIdentifier, create_dissector_handle(dissect_MessageIdentifier_PDU, proto_ngap));
  dissector_add_uint("ngap.ies", id_MobilityRestrictionList, create_dissector_handle(dissect_ngap_MobilityRestrictionList_PDU, proto_ngap));
  dissector_add_uint("ngap.ies", id_NASC, create_dissector_handle(dissect_NAS_PDU_PDU, proto_ngap));
  dissector_add_uint("ngap.ies", id_NAS_PDU, create_dissector_handle(dissect_NAS_PDU_PDU, proto_ngap));
  dissector_add_uint("ngap.ies", id_NASSecurityParametersFromNGRAN, create_dissector_handle(dissect_NASSecurityParametersFromNGRAN_PDU, proto_ngap));
  dissector_add_uint("ngap.ies", id_NewAMF_UE_NGAP_ID, create_dissector_handle(dissect_AMF_UE_NGAP_ID_PDU, proto_ngap));
  dissector_add_uint("ngap.ies", id_NewSecurityContextInd, create_dissector_handle(dissect_NewSecurityContextInd_PDU, proto_ngap));
  dissector_add_uint("ngap.ies", id_NGAP_Message, create_dissector_handle(dissect_NGAP_Message_PDU, proto_ngap));
  dissector_add_uint("ngap.ies", id_NGRAN_CGI, create_dissector_handle(dissect_ngap_NGRAN_CGI_PDU, proto_ngap));
  dissector_add_uint("ngap.ies", id_NGRANTraceID, create_dissector_handle(dissect_NGRANTraceID_PDU, proto_ngap));
  dissector_add_uint("ngap.ies", id_NR_CGI, create_dissector_handle(dissect_NR_CGI_PDU, proto_ngap));
  dissector_add_uint("ngap.ies", id_NRPPa_PDU, create_dissector_handle(dissect_NRPPa_PDU_PDU, proto_ngap));
  dissector_add_uint("ngap.ies", id_NumberOfBroadcastsRequested, create_dissector_handle(dissect_NumberOfBroadcastsRequested_PDU, proto_ngap));
  dissector_add_uint("ngap.ies", id_OldAMF, create_dissector_handle(dissect_AMFName_PDU, proto_ngap));
  dissector_add_uint("ngap.ies", id_OverloadStartNSSAIList, create_dissector_handle(dissect_OverloadStartNSSAIList_PDU, proto_ngap));
  dissector_add_uint("ngap.ies", id_PagingDRX, create_dissector_handle(dissect_PagingDRX_PDU, proto_ngap));
  dissector_add_uint("ngap.ies", id_PagingOrigin, create_dissector_handle(dissect_PagingOrigin_PDU, proto_ngap));
  dissector_add_uint("ngap.ies", id_PagingPriority, create_dissector_handle(dissect_PagingPriority_PDU, proto_ngap));
  dissector_add_uint("ngap.ies", id_PDUSessionResourceAdmittedList, create_dissector_handle(dissect_PDUSessionResourceAdmittedList_PDU, proto_ngap));
  dissector_add_uint("ngap.ies", id_PDUSessionResourceFailedToModifyListModRes, create_dissector_handle(dissect_PDUSessionResourceFailedToModifyListModRes_PDU, proto_ngap));
  dissector_add_uint("ngap.ies", id_PDUSessionResourceFailedToSetupListCxtRes, create_dissector_handle(dissect_PDUSessionResourceFailedToSetupListCxtRes_PDU, proto_ngap));
  dissector_add_uint("ngap.ies", id_PDUSessionResourceFailedToSetupListHOAck, create_dissector_handle(dissect_PDUSessionResourceFailedToSetupListHOAck_PDU, proto_ngap));
  dissector_add_uint("ngap.ies", id_PDUSessionResourceFailedToSetupListPSReq, create_dissector_handle(dissect_PDUSessionResourceFailedToSetupListPSReq_PDU, proto_ngap));
  dissector_add_uint("ngap.ies", id_PDUSessionResourceFailedToSetupListSURes, create_dissector_handle(dissect_PDUSessionResourceFailedToSetupListSURes_PDU, proto_ngap));
  dissector_add_uint("ngap.ies", id_PDUSessionResourceHandoverList, create_dissector_handle(dissect_PDUSessionResourceHandoverList_PDU, proto_ngap));
  dissector_add_uint("ngap.ies", id_PDUSessionResourceListCxtRelCpl, create_dissector_handle(dissect_PDUSessionResourceListCxtRelCpl_PDU, proto_ngap));
  dissector_add_uint("ngap.ies", id_PDUSessionResourceListHORqd, create_dissector_handle(dissect_PDUSessionResourceListHORqd_PDU, proto_ngap));
  dissector_add_uint("ngap.ies", id_PDUSessionResourceModifyListModCfm, create_dissector_handle(dissect_PDUSessionResourceModifyListModCfm_PDU, proto_ngap));
  dissector_add_uint("ngap.ies", id_PDUSessionResourceModifyListModInd, create_dissector_handle(dissect_PDUSessionResourceModifyListModInd_PDU, proto_ngap));
  dissector_add_uint("ngap.ies", id_PDUSessionResourceModifyListModReq, create_dissector_handle(dissect_PDUSessionResourceModifyListModReq_PDU, proto_ngap));
  dissector_add_uint("ngap.ies", id_PDUSessionResourceModifyListModRes, create_dissector_handle(dissect_PDUSessionResourceModifyListModRes_PDU, proto_ngap));
  dissector_add_uint("ngap.ies", id_PDUSessionResourceNotifyList, create_dissector_handle(dissect_PDUSessionResourceNotifyList_PDU, proto_ngap));
  dissector_add_uint("ngap.ies", id_PDUSessionResourceReleasedListNot, create_dissector_handle(dissect_PDUSessionResourceReleasedListNot_PDU, proto_ngap));
  dissector_add_uint("ngap.ies", id_PDUSessionResourceReleasedListPSAck, create_dissector_handle(dissect_PDUSessionResourceReleasedListPSAck_PDU, proto_ngap));
  dissector_add_uint("ngap.ies", id_PDUSessionResourceReleasedListPSFail, create_dissector_handle(dissect_PDUSessionResourceReleasedListPSFail_PDU, proto_ngap));
  dissector_add_uint("ngap.ies", id_PDUSessionResourceReleasedListRelRes, create_dissector_handle(dissect_PDUSessionResourceReleasedListRelRes_PDU, proto_ngap));
  dissector_add_uint("ngap.ies", id_PDUSessionResourceSetupListCxtReq, create_dissector_handle(dissect_PDUSessionResourceSetupListCxtReq_PDU, proto_ngap));
  dissector_add_uint("ngap.ies", id_PDUSessionResourceSetupListCxtRes, create_dissector_handle(dissect_PDUSessionResourceSetupListCxtRes_PDU, proto_ngap));
  dissector_add_uint("ngap.ies", id_PDUSessionResourceSetupListHOReq, create_dissector_handle(dissect_PDUSessionResourceSetupListHOReq_PDU, proto_ngap));
  dissector_add_uint("ngap.ies", id_PDUSessionResourceSetupListSUReq, create_dissector_handle(dissect_PDUSessionResourceSetupListSUReq_PDU, proto_ngap));
  dissector_add_uint("ngap.ies", id_PDUSessionResourceSetupListSURes, create_dissector_handle(dissect_PDUSessionResourceSetupListSURes_PDU, proto_ngap));
  dissector_add_uint("ngap.ies", id_PDUSessionResourceToBeSwitchedDLList, create_dissector_handle(dissect_PDUSessionResourceToBeSwitchedDLList_PDU, proto_ngap));
  dissector_add_uint("ngap.ies", id_PDUSessionResourceSwitchedList, create_dissector_handle(dissect_PDUSessionResourceSwitchedList_PDU, proto_ngap));
  dissector_add_uint("ngap.ies", id_PDUSessionResourceToReleaseListHOCmd, create_dissector_handle(dissect_PDUSessionResourceToReleaseListHOCmd_PDU, proto_ngap));
  dissector_add_uint("ngap.ies", id_PDUSessionResourceToReleaseListRelCmd, create_dissector_handle(dissect_PDUSessionResourceToReleaseListRelCmd_PDU, proto_ngap));
  dissector_add_uint("ngap.ies", id_PLMNSupportList, create_dissector_handle(dissect_PLMNSupportList_PDU, proto_ngap));
  dissector_add_uint("ngap.ies", id_PWSFailedCellIDList, create_dissector_handle(dissect_PWSFailedCellIDList_PDU, proto_ngap));
  dissector_add_uint("ngap.ies", id_RANNodeName, create_dissector_handle(dissect_RANNodeName_PDU, proto_ngap));
  dissector_add_uint("ngap.ies", id_RANPagingPriority, create_dissector_handle(dissect_RANPagingPriority_PDU, proto_ngap));
  dissector_add_uint("ngap.ies", id_RANStatusTransfer_TransparentContainer, create_dissector_handle(dissect_RANStatusTransfer_TransparentContainer_PDU, proto_ngap));
  dissector_add_uint("ngap.ies", id_RAN_UE_NGAP_ID, create_dissector_handle(dissect_RAN_UE_NGAP_ID_PDU, proto_ngap));
  dissector_add_uint("ngap.ies", id_RelativeAMFCapacity, create_dissector_handle(dissect_RelativeAMFCapacity_PDU, proto_ngap));
  dissector_add_uint("ngap.ies", id_RepetitionPeriod, create_dissector_handle(dissect_RepetitionPeriod_PDU, proto_ngap));
  dissector_add_uint("ngap.ies", id_ResetType, create_dissector_handle(dissect_ResetType_PDU, proto_ngap));
  dissector_add_uint("ngap.ies", id_RoutingID, create_dissector_handle(dissect_RoutingID_PDU, proto_ngap));
  dissector_add_uint("ngap.ies", id_RRCEstablishmentCause, create_dissector_handle(dissect_RRCEstablishmentCause_PDU, proto_ngap));
  dissector_add_uint("ngap.ies", id_RRCInactiveTransitionReportRequest, create_dissector_handle(dissect_RRCInactiveTransitionReportRequest_PDU, proto_ngap));
  dissector_add_uint("ngap.ies", id_RRCState, create_dissector_handle(dissect_RRCState_PDU, proto_ngap));
  dissector_add_uint("ngap.ies", id_SecurityContext, create_dissector_handle(dissect_SecurityContext_PDU, proto_ngap));
  dissector_add_uint("ngap.ies", id_SecurityKey, create_dissector_handle(dissect_SecurityKey_PDU, proto_ngap));
  dissector_add_uint("ngap.ies", id_SerialNumber, create_dissector_handle(dissect_SerialNumber_PDU, proto_ngap));
  dissector_add_uint("ngap.ies", id_ServedGUAMIList, create_dissector_handle(dissect_ServedGUAMIList_PDU, proto_ngap));
  dissector_add_uint("ngap.ies", id_SliceSupportList, create_dissector_handle(dissect_SliceSupportList_PDU, proto_ngap));
  dissector_add_uint("ngap.ies", id_SONConfigurationTransferDL, create_dissector_handle(dissect_SONConfigurationTransfer_PDU, proto_ngap));
  dissector_add_uint("ngap.ies", id_SONConfigurationTransferUL, create_dissector_handle(dissect_SONConfigurationTransfer_PDU, proto_ngap));
  dissector_add_uint("ngap.ies", id_SourceAMF_UE_NGAP_ID, create_dissector_handle(dissect_AMF_UE_NGAP_ID_PDU, proto_ngap));
  dissector_add_uint("ngap.ies", id_SourceToTarget_TransparentContainer, create_dissector_handle(dissect_SourceToTarget_TransparentContainer_PDU, proto_ngap));
  dissector_add_uint("ngap.ies", id_SupportedTAList, create_dissector_handle(dissect_SupportedTAList_PDU, proto_ngap));
  dissector_add_uint("ngap.ies", id_TAIListForPaging, create_dissector_handle(dissect_TAIListForPaging_PDU, proto_ngap));
  dissector_add_uint("ngap.ies", id_TAIListForRestart, create_dissector_handle(dissect_TAIListForRestart_PDU, proto_ngap));
  dissector_add_uint("ngap.ies", id_TargetID, create_dissector_handle(dissect_TargetID_PDU, proto_ngap));
  dissector_add_uint("ngap.ies", id_TargetToSource_TransparentContainer, create_dissector_handle(dissect_TargetToSource_TransparentContainer_PDU, proto_ngap));
  dissector_add_uint("ngap.ies", id_TimeToWait, create_dissector_handle(dissect_TimeToWait_PDU, proto_ngap));
  dissector_add_uint("ngap.ies", id_TraceActivation, create_dissector_handle(dissect_TraceActivation_PDU, proto_ngap));
  dissector_add_uint("ngap.ies", id_TraceCollectionEntityIPAddress, create_dissector_handle(dissect_TransportLayerAddress_PDU, proto_ngap));
  dissector_add_uint("ngap.ies", id_UEAggregateMaximumBitRate, create_dissector_handle(dissect_UEAggregateMaximumBitRate_PDU, proto_ngap));
  dissector_add_uint("ngap.ies", id_UE_associatedLogicalNG_connectionList, create_dissector_handle(dissect_UE_associatedLogicalNG_connectionList_PDU, proto_ngap));
  dissector_add_uint("ngap.ies", id_UEContextRequest, create_dissector_handle(dissect_UEContextRequest_PDU, proto_ngap));
  dissector_add_uint("ngap.ies", id_UE_NGAP_IDs, create_dissector_handle(dissect_UE_NGAP_IDs_PDU, proto_ngap));
  dissector_add_uint("ngap.ies", id_UEPagingIdentity, create_dissector_handle(dissect_UEPagingIdentity_PDU, proto_ngap));
  dissector_add_uint("ngap.ies", id_UEPresenceInAreaOfInterestList, create_dissector_handle(dissect_UEPresenceInAreaOfInterestList_PDU, proto_ngap));
  dissector_add_uint("ngap.ies", id_UERadioCapability, create_dissector_handle(dissect_UERadioCapability_PDU, proto_ngap));
  dissector_add_uint("ngap.ies", id_UERadioCapabilityForPaging, create_dissector_handle(dissect_UERadioCapabilityForPaging_PDU, proto_ngap));
  dissector_add_uint("ngap.ies", id_UESecurityCapabilities, create_dissector_handle(dissect_UESecurityCapabilities_PDU, proto_ngap));
  dissector_add_uint("ngap.ies", id_UnavailableGUAMIList, create_dissector_handle(dissect_UnavailableGUAMIList_PDU, proto_ngap));
  dissector_add_uint("ngap.ies", id_UserLocationInformation, create_dissector_handle(dissect_UserLocationInformation_PDU, proto_ngap));
  dissector_add_uint("ngap.ies", id_WarningAreaList, create_dissector_handle(dissect_WarningAreaList_PDU, proto_ngap));
  dissector_add_uint("ngap.ies", id_WarningMessageContents, create_dissector_handle(dissect_WarningMessageContents_PDU, proto_ngap));
  dissector_add_uint("ngap.ies", id_WarningSecurityInfo, create_dissector_handle(dissect_WarningSecurityInfo_PDU, proto_ngap));
  dissector_add_uint("ngap.ies", id_WarningType, create_dissector_handle(dissect_WarningType_PDU, proto_ngap));
  dissector_add_uint("ngap.ies", id_AdditionalUL_NGU_UP_TNLInformation, create_dissector_handle(dissect_UPTransportLayerInformationList_PDU, proto_ngap));
  dissector_add_uint("ngap.ies", id_DataForwardingNotPossible, create_dissector_handle(dissect_DataForwardingNotPossible_PDU, proto_ngap));
  dissector_add_uint("ngap.ies", id_NetworkInstance, create_dissector_handle(dissect_NetworkInstance_PDU, proto_ngap));
  dissector_add_uint("ngap.ies", id_PDUSessionAggregateMaximumBitRate, create_dissector_handle(dissect_PDUSessionAggregateMaximumBitRate_PDU, proto_ngap));
  dissector_add_uint("ngap.ies", id_PDUSessionResourceFailedToModifyListModCfm, create_dissector_handle(dissect_PDUSessionResourceFailedToModifyListModCfm_PDU, proto_ngap));
  dissector_add_uint("ngap.ies", id_PDUSessionResourceFailedToSetupListCxtFail, create_dissector_handle(dissect_PDUSessionResourceFailedToSetupListCxtFail_PDU, proto_ngap));
  dissector_add_uint("ngap.ies", id_PDUSessionResourceListCxtRelReq, create_dissector_handle(dissect_PDUSessionResourceListCxtRelReq_PDU, proto_ngap));
  dissector_add_uint("ngap.ies", id_PDUSessionType, create_dissector_handle(dissect_PDUSessionType_PDU, proto_ngap));
  dissector_add_uint("ngap.ies", id_QosFlowAddOrModifyRequestList, create_dissector_handle(dissect_QosFlowAddOrModifyRequestList_PDU, proto_ngap));
  dissector_add_uint("ngap.ies", id_QosFlowSetupRequestList, create_dissector_handle(dissect_QosFlowSetupRequestList_PDU, proto_ngap));
  dissector_add_uint("ngap.ies", id_QosFlowToReleaseList, create_dissector_handle(dissect_QosFlowListWithCause_PDU, proto_ngap));
  dissector_add_uint("ngap.ies", id_SecurityIndication, create_dissector_handle(dissect_SecurityIndication_PDU, proto_ngap));
  dissector_add_uint("ngap.ies", id_UL_NGU_UP_TNLInformation, create_dissector_handle(dissect_UPTransportLayerInformation_PDU, proto_ngap));
  dissector_add_uint("ngap.ies", id_UL_NGU_UP_TNLModifyList, create_dissector_handle(dissect_UL_NGU_UP_TNLModifyList_PDU, proto_ngap));
  dissector_add_uint("ngap.ies", id_WarningAreaCoordinates, create_dissector_handle(dissect_WarningAreaCoordinates_PDU, proto_ngap));
  dissector_add_uint("ngap.ies", id_PDUSessionResourceSecondaryRATUsageList, create_dissector_handle(dissect_PDUSessionResourceSecondaryRATUsageList_PDU, proto_ngap));
  dissector_add_uint("ngap.ies", id_HandoverFlag, create_dissector_handle(dissect_HandoverFlag_PDU, proto_ngap));
  dissector_add_uint("ngap.ies", id_RedirectionVoiceFallback, create_dissector_handle(dissect_RedirectionVoiceFallback_PDU, proto_ngap));
  dissector_add_uint("ngap.ies", id_UERetentionInformation, create_dissector_handle(dissect_UERetentionInformation_PDU, proto_ngap));
  dissector_add_uint("ngap.ies", id_PSCellInformation, create_dissector_handle(dissect_ngap_NGRAN_CGI_PDU, proto_ngap));
  dissector_add_uint("ngap.ies", id_ENDC_SONConfigurationTransferDL, create_dissector_handle(dissect_EN_DCSONConfigurationTransfer_PDU, proto_ngap));
  dissector_add_uint("ngap.ies", id_ENDC_SONConfigurationTransferUL, create_dissector_handle(dissect_EN_DCSONConfigurationTransfer_PDU, proto_ngap));
  dissector_add_uint("ngap.ies", id_NewGUAMI, create_dissector_handle(dissect_GUAMI_PDU, proto_ngap));
  dissector_add_uint("ngap.ies", id_CNAssistedRANTuning, create_dissector_handle(dissect_CNAssistedRANTuning_PDU, proto_ngap));
  dissector_add_uint("ngap.ies", id_CommonNetworkInstance, create_dissector_handle(dissect_CommonNetworkInstance_PDU, proto_ngap));
  dissector_add_uint("ngap.ies", id_NGRAN_TNLAssociationToRemoveList, create_dissector_handle(dissect_NGRAN_TNLAssociationToRemoveList_PDU, proto_ngap));
  dissector_add_uint("ngap.ies", id_EndpointIPAddressAndPort, create_dissector_handle(dissect_EndpointIPAddressAndPort_PDU, proto_ngap));
  dissector_add_uint("ngap.ies", id_SourceToTarget_AMFInformationReroute, create_dissector_handle(dissect_SourceToTarget_AMFInformationReroute_PDU, proto_ngap));
  dissector_add_uint("ngap.extension", id_SecondaryRATUsageInformation, create_dissector_handle(dissect_SecondaryRATUsageInformation_PDU, proto_ngap));
  dissector_add_uint("ngap.extension", id_PDUSessionResourceReleaseResponseTransfer, create_dissector_handle(dissect_PDUSessionResourceReleaseResponseTransfer_OCTET_STRING_PDU, proto_ngap));
  dissector_add_uint("ngap.extension", id_S_NSSAI, create_dissector_handle(dissect_S_NSSAI_PDU, proto_ngap));
  dissector_add_uint("ngap.extension", id_LastEUTRAN_PLMNIdentity, create_dissector_handle(dissect_PLMNIdentity_PDU, proto_ngap));
  dissector_add_uint("ngap.extension", id_MaximumIntegrityProtectedDataRate_DL, create_dissector_handle(dissect_MaximumIntegrityProtectedDataRate_PDU, proto_ngap));
  dissector_add_uint("ngap.extension", id_AdditionalDLForwardingUPTNLInformation, create_dissector_handle(dissect_QosFlowPerTNLInformationList_PDU, proto_ngap));
  dissector_add_uint("ngap.extension", id_AdditionalDLUPTNLInformationForHOList, create_dissector_handle(dissect_AdditionalDLUPTNLInformationForHOList_PDU, proto_ngap));
  dissector_add_uint("ngap.extension", id_AdditionalNGU_UP_TNLInformation, create_dissector_handle(dissect_UPTransportLayerInformationPairList_PDU, proto_ngap));
  dissector_add_uint("ngap.extension", id_AdditionalDLQosFlowPerTNLInformation, create_dissector_handle(dissect_QosFlowPerTNLInformationList_PDU, proto_ngap));
  dissector_add_uint("ngap.extension", id_SecurityResult, create_dissector_handle(dissect_SecurityResult_PDU, proto_ngap));
  dissector_add_uint("ngap.extension", id_OldAssociatedQosFlowList_ULendmarkerexpected, create_dissector_handle(dissect_AssociatedQosFlowList_PDU, proto_ngap));
  dissector_add_uint("ngap.extension", id_CNTypeRestrictionsForEquivalent, create_dissector_handle(dissect_CNTypeRestrictionsForEquivalent_PDU, proto_ngap));
  dissector_add_uint("ngap.extension", id_CNTypeRestrictionsForServing, create_dissector_handle(dissect_CNTypeRestrictionsForServing_PDU, proto_ngap));
  dissector_add_uint("ngap.extension", id_ULForwarding, create_dissector_handle(dissect_ULForwarding_PDU, proto_ngap));
  dissector_add_uint("ngap.extension", id_ULForwardingUP_TNLInformation, create_dissector_handle(dissect_UPTransportLayerInformation_PDU, proto_ngap));
  dissector_add_uint("ngap.extension", id_TNLAssociationTransportLayerAddressNGRAN, create_dissector_handle(dissect_CPTransportLayerInformation_PDU, proto_ngap));
  dissector_add_uint("ngap.extension", id_LocationReportingAdditionalInfo, create_dissector_handle(dissect_LocationReportingAdditionalInfo_PDU, proto_ngap));
  dissector_add_uint("ngap.extension", id_AdditionalULForwardingUPTNLInformation, create_dissector_handle(dissect_UPTransportLayerInformationList_PDU, proto_ngap));
  dissector_add_uint("ngap.extension", id_SCTP_TLAs, create_dissector_handle(dissect_SCTP_TLAs_PDU, proto_ngap));
  dissector_add_uint("ngap.proc.imsg", id_AMFConfigurationUpdate, create_dissector_handle(dissect_AMFConfigurationUpdate_PDU, proto_ngap));
  dissector_add_uint("ngap.proc.sout", id_AMFConfigurationUpdate, create_dissector_handle(dissect_AMFConfigurationUpdateAcknowledge_PDU, proto_ngap));
  dissector_add_uint("ngap.proc.uout", id_AMFConfigurationUpdate, create_dissector_handle(dissect_AMFConfigurationUpdateFailure_PDU, proto_ngap));
  dissector_add_uint("ngap.proc.imsg", id_AMFStatusIndication, create_dissector_handle(dissect_AMFStatusIndication_PDU, proto_ngap));
  dissector_add_uint("ngap.proc.imsg", id_CellTrafficTrace, create_dissector_handle(dissect_CellTrafficTrace_PDU, proto_ngap));
  dissector_add_uint("ngap.proc.imsg", id_DeactivateTrace, create_dissector_handle(dissect_DeactivateTrace_PDU, proto_ngap));
  dissector_add_uint("ngap.proc.imsg", id_DownlinkNASTransport, create_dissector_handle(dissect_DownlinkNASTransport_PDU, proto_ngap));
  dissector_add_uint("ngap.proc.imsg", id_DownlinkNonUEAssociatedNRPPaTransport, create_dissector_handle(dissect_DownlinkNonUEAssociatedNRPPaTransport_PDU, proto_ngap));
  dissector_add_uint("ngap.proc.imsg", id_DownlinkRANConfigurationTransfer, create_dissector_handle(dissect_DownlinkRANConfigurationTransfer_PDU, proto_ngap));
  dissector_add_uint("ngap.proc.imsg", id_DownlinkRANStatusTransfer, create_dissector_handle(dissect_DownlinkRANStatusTransfer_PDU, proto_ngap));
  dissector_add_uint("ngap.proc.imsg", id_DownlinkUEAssociatedNRPPaTransport, create_dissector_handle(dissect_DownlinkUEAssociatedNRPPaTransport_PDU, proto_ngap));
  dissector_add_uint("ngap.proc.imsg", id_ErrorIndication, create_dissector_handle(dissect_ErrorIndication_PDU, proto_ngap));
  dissector_add_uint("ngap.proc.imsg", id_HandoverCancel, create_dissector_handle(dissect_HandoverCancel_PDU, proto_ngap));
  dissector_add_uint("ngap.proc.sout", id_HandoverCancel, create_dissector_handle(dissect_HandoverCancelAcknowledge_PDU, proto_ngap));
  dissector_add_uint("ngap.proc.imsg", id_HandoverNotification, create_dissector_handle(dissect_HandoverNotify_PDU, proto_ngap));
  dissector_add_uint("ngap.proc.imsg", id_HandoverPreparation, create_dissector_handle(dissect_HandoverRequired_PDU, proto_ngap));
  dissector_add_uint("ngap.proc.sout", id_HandoverPreparation, create_dissector_handle(dissect_HandoverCommand_PDU, proto_ngap));
  dissector_add_uint("ngap.proc.uout", id_HandoverPreparation, create_dissector_handle(dissect_HandoverPreparationFailure_PDU, proto_ngap));
  dissector_add_uint("ngap.proc.imsg", id_HandoverResourceAllocation, create_dissector_handle(dissect_HandoverRequest_PDU, proto_ngap));
  dissector_add_uint("ngap.proc.sout", id_HandoverResourceAllocation, create_dissector_handle(dissect_HandoverRequestAcknowledge_PDU, proto_ngap));
  dissector_add_uint("ngap.proc.uout", id_HandoverResourceAllocation, create_dissector_handle(dissect_HandoverFailure_PDU, proto_ngap));
  dissector_add_uint("ngap.proc.imsg", id_InitialContextSetup, create_dissector_handle(dissect_InitialContextSetupRequest_PDU, proto_ngap));
  dissector_add_uint("ngap.proc.sout", id_InitialContextSetup, create_dissector_handle(dissect_InitialContextSetupResponse_PDU, proto_ngap));
  dissector_add_uint("ngap.proc.uout", id_InitialContextSetup, create_dissector_handle(dissect_InitialContextSetupFailure_PDU, proto_ngap));
  dissector_add_uint("ngap.proc.imsg", id_InitialUEMessage, create_dissector_handle(dissect_InitialUEMessage_PDU, proto_ngap));
  dissector_add_uint("ngap.proc.imsg", id_LocationReport, create_dissector_handle(dissect_LocationReport_PDU, proto_ngap));
  dissector_add_uint("ngap.proc.imsg", id_LocationReportingControl, create_dissector_handle(dissect_LocationReportingControl_PDU, proto_ngap));
  dissector_add_uint("ngap.proc.imsg", id_LocationReportingFailureIndication, create_dissector_handle(dissect_LocationReportingFailureIndication_PDU, proto_ngap));
  dissector_add_uint("ngap.proc.imsg", id_NASNonDeliveryIndication, create_dissector_handle(dissect_NASNonDeliveryIndication_PDU, proto_ngap));
  dissector_add_uint("ngap.proc.imsg", id_NGReset, create_dissector_handle(dissect_NGReset_PDU, proto_ngap));
  dissector_add_uint("ngap.proc.sout", id_NGReset, create_dissector_handle(dissect_NGResetAcknowledge_PDU, proto_ngap));
  dissector_add_uint("ngap.proc.imsg", id_NGSetup, create_dissector_handle(dissect_NGSetupRequest_PDU, proto_ngap));
  dissector_add_uint("ngap.proc.sout", id_NGSetup, create_dissector_handle(dissect_NGSetupResponse_PDU, proto_ngap));
  dissector_add_uint("ngap.proc.uout", id_NGSetup, create_dissector_handle(dissect_NGSetupFailure_PDU, proto_ngap));
  dissector_add_uint("ngap.proc.imsg", id_OverloadStart, create_dissector_handle(dissect_OverloadStart_PDU, proto_ngap));
  dissector_add_uint("ngap.proc.imsg", id_OverloadStop, create_dissector_handle(dissect_OverloadStop_PDU, proto_ngap));
  dissector_add_uint("ngap.proc.imsg", id_Paging, create_dissector_handle(dissect_Paging_PDU, proto_ngap));
  dissector_add_uint("ngap.proc.imsg", id_PathSwitchRequest, create_dissector_handle(dissect_PathSwitchRequest_PDU, proto_ngap));
  dissector_add_uint("ngap.proc.sout", id_PathSwitchRequest, create_dissector_handle(dissect_PathSwitchRequestAcknowledge_PDU, proto_ngap));
  dissector_add_uint("ngap.proc.uout", id_PathSwitchRequest, create_dissector_handle(dissect_PathSwitchRequestFailure_PDU, proto_ngap));
  dissector_add_uint("ngap.proc.imsg", id_PDUSessionResourceModify, create_dissector_handle(dissect_PDUSessionResourceModifyRequest_PDU, proto_ngap));
  dissector_add_uint("ngap.proc.sout", id_PDUSessionResourceModify, create_dissector_handle(dissect_PDUSessionResourceModifyResponse_PDU, proto_ngap));
  dissector_add_uint("ngap.proc.imsg", id_PDUSessionResourceModifyIndication, create_dissector_handle(dissect_PDUSessionResourceModifyIndication_PDU, proto_ngap));
  dissector_add_uint("ngap.proc.sout", id_PDUSessionResourceModifyIndication, create_dissector_handle(dissect_PDUSessionResourceModifyConfirm_PDU, proto_ngap));
  dissector_add_uint("ngap.proc.imsg", id_PDUSessionResourceNotify, create_dissector_handle(dissect_PDUSessionResourceNotify_PDU, proto_ngap));
  dissector_add_uint("ngap.proc.imsg", id_PDUSessionResourceRelease, create_dissector_handle(dissect_PDUSessionResourceReleaseCommand_PDU, proto_ngap));
  dissector_add_uint("ngap.proc.sout", id_PDUSessionResourceRelease, create_dissector_handle(dissect_PDUSessionResourceReleaseResponse_PDU, proto_ngap));
  dissector_add_uint("ngap.proc.imsg", id_PDUSessionResourceSetup, create_dissector_handle(dissect_PDUSessionResourceSetupRequest_PDU, proto_ngap));
  dissector_add_uint("ngap.proc.sout", id_PDUSessionResourceSetup, create_dissector_handle(dissect_PDUSessionResourceSetupResponse_PDU, proto_ngap));
  dissector_add_uint("ngap.proc.imsg", id_PrivateMessage, create_dissector_handle(dissect_PrivateMessage_PDU, proto_ngap));
  dissector_add_uint("ngap.proc.imsg", id_PWSCancel, create_dissector_handle(dissect_PWSCancelRequest_PDU, proto_ngap));
  dissector_add_uint("ngap.proc.sout", id_PWSCancel, create_dissector_handle(dissect_PWSCancelResponse_PDU, proto_ngap));
  dissector_add_uint("ngap.proc.imsg", id_PWSFailureIndication, create_dissector_handle(dissect_PWSFailureIndication_PDU, proto_ngap));
  dissector_add_uint("ngap.proc.imsg", id_PWSRestartIndication, create_dissector_handle(dissect_PWSRestartIndication_PDU, proto_ngap));
  dissector_add_uint("ngap.proc.imsg", id_RANConfigurationUpdate, create_dissector_handle(dissect_RANConfigurationUpdate_PDU, proto_ngap));
  dissector_add_uint("ngap.proc.sout", id_RANConfigurationUpdate, create_dissector_handle(dissect_RANConfigurationUpdateAcknowledge_PDU, proto_ngap));
  dissector_add_uint("ngap.proc.uout", id_RANConfigurationUpdate, create_dissector_handle(dissect_RANConfigurationUpdateFailure_PDU, proto_ngap));
  dissector_add_uint("ngap.proc.imsg", id_RerouteNASRequest, create_dissector_handle(dissect_RerouteNASRequest_PDU, proto_ngap));
  dissector_add_uint("ngap.proc.imsg", id_RRCInactiveTransitionReport, create_dissector_handle(dissect_RRCInactiveTransitionReport_PDU, proto_ngap));
  dissector_add_uint("ngap.proc.imsg", id_SecondaryRATDataUsageReport, create_dissector_handle(dissect_SecondaryRATDataUsageReport_PDU, proto_ngap));
  dissector_add_uint("ngap.proc.imsg", id_TraceFailureIndication, create_dissector_handle(dissect_TraceFailureIndication_PDU, proto_ngap));
  dissector_add_uint("ngap.proc.imsg", id_TraceStart, create_dissector_handle(dissect_TraceStart_PDU, proto_ngap));
  dissector_add_uint("ngap.proc.imsg", id_UEContextModification, create_dissector_handle(dissect_UEContextModificationRequest_PDU, proto_ngap));
  dissector_add_uint("ngap.proc.sout", id_UEContextModification, create_dissector_handle(dissect_UEContextModificationResponse_PDU, proto_ngap));
  dissector_add_uint("ngap.proc.uout", id_UEContextModification, create_dissector_handle(dissect_UEContextModificationFailure_PDU, proto_ngap));
  dissector_add_uint("ngap.proc.imsg", id_UEContextRelease, create_dissector_handle(dissect_UEContextReleaseCommand_PDU, proto_ngap));
  dissector_add_uint("ngap.proc.sout", id_UEContextRelease, create_dissector_handle(dissect_UEContextReleaseComplete_PDU, proto_ngap));
  dissector_add_uint("ngap.proc.imsg", id_UEContextReleaseRequest, create_dissector_handle(dissect_UEContextReleaseRequest_PDU, proto_ngap));
  dissector_add_uint("ngap.proc.imsg", id_UERadioCapabilityCheck, create_dissector_handle(dissect_UERadioCapabilityCheckRequest_PDU, proto_ngap));
  dissector_add_uint("ngap.proc.sout", id_UERadioCapabilityCheck, create_dissector_handle(dissect_UERadioCapabilityCheckResponse_PDU, proto_ngap));
  dissector_add_uint("ngap.proc.imsg", id_UERadioCapabilityInfoIndication, create_dissector_handle(dissect_UERadioCapabilityInfoIndication_PDU, proto_ngap));
  dissector_add_uint("ngap.proc.imsg", id_UETNLABindingRelease, create_dissector_handle(dissect_UETNLABindingReleaseRequest_PDU, proto_ngap));
  dissector_add_uint("ngap.proc.imsg", id_UplinkNASTransport, create_dissector_handle(dissect_UplinkNASTransport_PDU, proto_ngap));
  dissector_add_uint("ngap.proc.imsg", id_UplinkNonUEAssociatedNRPPaTransport, create_dissector_handle(dissect_UplinkNonUEAssociatedNRPPaTransport_PDU, proto_ngap));
  dissector_add_uint("ngap.proc.imsg", id_UplinkRANConfigurationTransfer, create_dissector_handle(dissect_UplinkRANConfigurationTransfer_PDU, proto_ngap));
  dissector_add_uint("ngap.proc.imsg", id_UplinkRANStatusTransfer, create_dissector_handle(dissect_UplinkRANStatusTransfer_PDU, proto_ngap));
  dissector_add_uint("ngap.proc.imsg", id_UplinkUEAssociatedNRPPaTransport, create_dissector_handle(dissect_UplinkUEAssociatedNRPPaTransport_PDU, proto_ngap));
  dissector_add_uint("ngap.proc.imsg", id_WriteReplaceWarning, create_dissector_handle(dissect_WriteReplaceWarningRequest_PDU, proto_ngap));
  dissector_add_uint("ngap.proc.sout", id_WriteReplaceWarning, create_dissector_handle(dissect_WriteReplaceWarningResponse_PDU, proto_ngap));
  dissector_add_string("ngap.n2_ie_type", "PDU_RES_SETUP_REQ", create_dissector_handle(dissect_PDUSessionResourceSetupRequestTransfer_PDU, proto_ngap));
  dissector_add_string("ngap.n2_ie_type", "PDU_RES_SETUP_RSP", create_dissector_handle(dissect_PDUSessionResourceSetupResponseTransfer_PDU, proto_ngap));
  dissector_add_string("ngap.n2_ie_type", "PDU_RES_SETUP_FAIL", create_dissector_handle(dissect_PDUSessionResourceSetupUnsuccessfulTransfer_PDU, proto_ngap));
  dissector_add_string("ngap.n2_ie_type", "PDU_RES_REL_CMD", create_dissector_handle(dissect_PDUSessionResourceReleaseCommandTransfer_PDU, proto_ngap));
  dissector_add_string("ngap.n2_ie_type", "PDU_RES_REL_RSP", create_dissector_handle(dissect_PDUSessionResourceReleaseResponseTransfer_PDU, proto_ngap));
  dissector_add_string("ngap.n2_ie_type", "PDU_RES_MOD_REQ", create_dissector_handle(dissect_PDUSessionResourceModifyRequestTransfer_PDU, proto_ngap));
  dissector_add_string("ngap.n2_ie_type", "PDU_RES_MOD_RSP", create_dissector_handle(dissect_PDUSessionResourceModifyResponseTransfer_PDU, proto_ngap));
  dissector_add_string("ngap.n2_ie_type", "PDU_RES_MOD_FAIL", create_dissector_handle(dissect_PDUSessionResourceModifyUnsuccessfulTransfer_PDU, proto_ngap));
  dissector_add_string("ngap.n2_ie_type", "PDU_RES_NTY", create_dissector_handle(dissect_PDUSessionResourceNotifyTransfer_PDU, proto_ngap));
  dissector_add_string("ngap.n2_ie_type", "PDU_RES_NTY_REL", create_dissector_handle(dissect_PDUSessionResourceNotifyReleasedTransfer_PDU, proto_ngap));
  dissector_add_string("ngap.n2_ie_type", "PDU_RES_MOD_IND", create_dissector_handle(dissect_PDUSessionResourceModifyIndicationTransfer_PDU, proto_ngap));
  dissector_add_string("ngap.n2_ie_type", "PDU_RES_MOD_CFM", create_dissector_handle(dissect_PDUSessionResourceModifyConfirmTransfer_PDU, proto_ngap));
  dissector_add_string("ngap.n2_ie_type", "PATH_SWITCH_REQ", create_dissector_handle(dissect_PathSwitchRequestTransfer_PDU, proto_ngap));
  dissector_add_string("ngap.n2_ie_type", "PATH_SWITCH_SETUP_FAIL", create_dissector_handle(dissect_PathSwitchRequestSetupFailedTransfer_PDU, proto_ngap));
  dissector_add_string("ngap.n2_ie_type", "PATH_SWITCH_REQ_ACK", create_dissector_handle(dissect_PathSwitchRequestAcknowledgeTransfer_PDU, proto_ngap));
  dissector_add_string("ngap.n2_ie_type", "PATH_SWITCH_REQ_FAIL", create_dissector_handle(dissect_PathSwitchRequestUnsuccessfulTransfer_PDU, proto_ngap));
  dissector_add_string("ngap.n2_ie_type", "HANDOVER_REQUIRED", create_dissector_handle(dissect_HandoverRequiredTransfer_PDU, proto_ngap));
  dissector_add_string("ngap.n2_ie_type", "HANDOVER_CMD", create_dissector_handle(dissect_HandoverCommandTransfer_PDU, proto_ngap));
  dissector_add_string("ngap.n2_ie_type", "HANDOVER_PREP_FAIL", create_dissector_handle(dissect_HandoverPreparationUnsuccessfulTransfer_PDU, proto_ngap));
  dissector_add_string("ngap.n2_ie_type", "HANDOVER_REQ_ACK", create_dissector_handle(dissect_HandoverRequestAcknowledgeTransfer_PDU, proto_ngap));
  dissector_add_string("ngap.n2_ie_type", "HANDOVER_RES_ALLOC_FAIL", create_dissector_handle(dissect_HandoverResourceAllocationUnsuccessfulTransfer_PDU, proto_ngap));
  dissector_add_string("ngap.n2_ie_type", "SRC_TO_TAR_CONTAINER", create_dissector_handle(dissect_SourceToTarget_TransparentContainer_PDU, proto_ngap));
  dissector_add_string("ngap.n2_ie_type", "TAR_TO_SRC_CONTAINER", create_dissector_handle(dissect_TargetToSource_TransparentContainer_PDU, proto_ngap));
  dissector_add_string("ngap.n2_ie_type", "RAN_STATUS_TRANS_CONTAINER", create_dissector_handle(dissect_RANStatusTransfer_TransparentContainer_PDU, proto_ngap));
  dissector_add_string("ngap.n2_ie_type", "SON_CONFIG_TRANSFER", create_dissector_handle(dissect_SONConfigurationTransfer_PDU, proto_ngap));
  dissector_add_string("ngap.n2_ie_type", "NRPPA_PDU", create_dissector_handle(dissect_NRPPa_PDU_PDU, proto_ngap));
  dissector_add_string("ngap.n2_ie_type", "UE_RADIO_CAPABILITY", create_dissector_handle(dissect_UERadioCapability_PDU, proto_ngap));


/*--- End of included file: packet-ngap-dis-tab.c ---*/
#line 585 "./asn1/ngap/packet-ngap-template.c"

    dissector_add_string("media_type", "application/vnd.3gpp.ngap", ngap_media_type_handle);
  } else {
    if (SctpPort != 0) {
      dissector_delete_uint("sctp.port", SctpPort, ngap_handle);
    }
  }

  nrppa_handle = find_dissector_add_dependency("nrppa", proto_ngap);
  proto_json = proto_get_id_by_filter_name("json");

  SctpPort=gbl_ngapSctpPort;
  if (SctpPort != 0) {
    dissector_add_uint("sctp.port", SctpPort, ngap_handle);
  }
}

/*--- proto_register_ngap -------------------------------------------*/
void proto_register_ngap(void) {

  /* List of fields */

  static hf_register_info hf[] = {
    { &hf_ngap_transportLayerAddressIPv4,
      { "TransportLayerAddress (IPv4)", "ngap.TransportLayerAddressIPv4",
        FT_IPv4, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ngap_transportLayerAddressIPv6,
      { "TransportLayerAddress (IPv6)", "ngap.TransportLayerAddressIPv6",
        FT_IPv6, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ngap_WarningMessageContents_nb_pages,
      { "Number of Pages", "ngap.WarningMessageContents.nb_pages",
        FT_UINT8, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_ngap_WarningMessageContents_decoded_page,
      { "Decoded Page", "ngap.WarningMessageContents.decoded_page",
        FT_STRING, STR_UNICODE, NULL, 0,
        NULL, HFILL }},
    { &hf_ngap_NGRANTraceID_TraceID,
      { "TraceID", "ngap.NGRANTraceID.TraceID",
        FT_UINT24, BASE_HEX, NULL, 0,
        NULL, HFILL }},
    { &hf_ngap_NGRANTraceID_TraceRecordingSessionReference,
      { "TraceRecordingSessionReference", "ngap.NGRANTraceID.TraceRecordingSessionReference",
        FT_UINT16, BASE_HEX, NULL, 0,
        NULL, HFILL }},
    { &hf_ngap_InterfacesToTrace_NG_C,
      { "NG-C", "ngap.InterfacesToTrace.NG_C",
        FT_BOOLEAN, 8, NULL, 0x80,
        NULL, HFILL }},
    { &hf_ngap_InterfacesToTrace_Xn_C,
      { "Xn-C", "ngap.InterfacesToTrace.Xn_C",
        FT_BOOLEAN, 8, NULL, 0x40,
        NULL, HFILL }},
    { &hf_ngap_InterfacesToTrace_Uu,
      { "Uu", "ngap.InterfacesToTrace.Uu",
        FT_BOOLEAN, 8, NULL, 0x20,
        NULL, HFILL }},
    { &hf_ngap_InterfacesToTrace_F1_C,
      { "F1-C", "ngap.InterfacesToTrace.F1_C",
        FT_BOOLEAN, 8, NULL, 0x10,
        NULL, HFILL }},
    { &hf_ngap_InterfacesToTrace_E1,
      { "E1", "ngap.InterfacesToTrace.E1",
        FT_BOOLEAN, 8, NULL, 0x08,
        NULL, HFILL }},
    { &hf_ngap_InterfacesToTrace_reserved,
      { "Reserved", "ngap.InterfacesToTrace.reserved",
        FT_UINT8, BASE_HEX, NULL, 0x07,
        NULL, HFILL }},
    { &hf_ngap_RATRestrictionInformation_e_UTRA,
      { "e-UTRA", "ngap.RATRestrictionInformation.e_UTRA",
        FT_BOOLEAN, 8, TFS(&tfs_restricted_not_restricted), 0x80,
        NULL, HFILL }},
    { &hf_ngap_RATRestrictionInformation_nR,
      { "nR", "ngap.RATRestrictionInformation.nR",
        FT_BOOLEAN, 8, TFS(&tfs_restricted_not_restricted), 0x40,
        NULL, HFILL }},
    { &hf_ngap_RATRestrictionInformation_reserved,
      { "reserved", "ngap.RATRestrictionInformation.reserved",
        FT_UINT8, BASE_HEX, NULL, 0x3f,
        NULL, HFILL }},
    { &hf_ngap_NrencyptionAlgorithms_nea1,
      { "128-NEA1", "ngap.NrencyptionAlgorithms.nea1",
        FT_BOOLEAN, 16, TFS(&tfs_supported_not_supported), 0x8000,
        NULL, HFILL }},
    { &hf_ngap_NrencyptionAlgorithms_nea2,
      { "128-NEA2", "ngap.NrencyptionAlgorithms.nea2",
        FT_BOOLEAN, 16, TFS(&tfs_supported_not_supported), 0x4000,
        NULL, HFILL }},
    { &hf_ngap_NrencyptionAlgorithms_nea3,
      { "128-NEA3", "ngap.NrencyptionAlgorithms.nea3",
        FT_BOOLEAN, 16, TFS(&tfs_supported_not_supported), 0x2000,
        NULL, HFILL }},
    { &hf_ngap_NrencyptionAlgorithms_reserved,
      { "Reserved", "ngap.NrencyptionAlgorithms.reserved",
        FT_UINT16, BASE_HEX, NULL, 0x1fff,
        NULL, HFILL }},
    { &hf_ngap_NrintegrityProtectionAlgorithms_nia1,
      { "128-NIA1", "ngap.NrintegrityProtectionAlgorithms.nia1",
        FT_BOOLEAN, 16, TFS(&tfs_supported_not_supported), 0x8000,
        NULL, HFILL }},
    { &hf_ngap_NrintegrityProtectionAlgorithms_nia2,
      { "128-NIA2", "ngap.NrintegrityProtectionAlgorithms.nia2",
        FT_BOOLEAN, 16, TFS(&tfs_supported_not_supported), 0x4000,
        NULL, HFILL }},
    { &hf_ngap_NrintegrityProtectionAlgorithms_nia3,
      { "128-NIA3", "ngap.NrintegrityProtectionAlgorithms.nia3",
        FT_BOOLEAN, 16, TFS(&tfs_supported_not_supported), 0x2000,
        NULL, HFILL }},
    { &hf_ngap_NrintegrityProtectionAlgorithms_reserved,
      { "Reserved", "ngap.NrintegrityProtectionAlgorithms.reserved",
        FT_UINT16, BASE_HEX, NULL, 0x1fff,
        NULL, HFILL }},
    { &hf_ngap_EUTRAencryptionAlgorithms_eea1,
      { "128-EEA1", "ngap.EUTRAencryptionAlgorithms.eea1",
        FT_BOOLEAN, 16, TFS(&tfs_supported_not_supported), 0x8000,
        NULL, HFILL }},
    { &hf_ngap_EUTRAencryptionAlgorithms_eea2,
      { "128-EEA2", "ngap.EUTRAencryptionAlgorithms.eea2",
        FT_BOOLEAN, 16, TFS(&tfs_supported_not_supported), 0x4000,
        NULL, HFILL }},
    { &hf_ngap_EUTRAencryptionAlgorithms_eea3,
      { "128-EEA3", "ngap.EUTRAencryptionAlgorithms.eea3",
        FT_BOOLEAN, 16, TFS(&tfs_supported_not_supported), 0x2000,
        NULL, HFILL }},
    { &hf_ngap_EUTRAencryptionAlgorithms_reserved,
      { "Reserved", "ngap.EUTRAencryptionAlgorithms.reserved",
        FT_UINT16, BASE_HEX, NULL, 0x1fff,
        NULL, HFILL }},
    { &hf_ngap_EUTRAintegrityProtectionAlgorithms_eia1,
      { "128-EIA1", "ngap.EUTRAintegrityProtectionAlgorithms.eia1",
        FT_BOOLEAN, 16, TFS(&tfs_supported_not_supported), 0x8000,
        NULL, HFILL }},
    { &hf_ngap_EUTRAintegrityProtectionAlgorithms_eia2,
      { "128-EIA2", "ngap.EUTRAintegrityProtectionAlgorithms.eia2",
        FT_BOOLEAN, 16, TFS(&tfs_supported_not_supported), 0x4000,
        NULL, HFILL }},
    { &hf_ngap_EUTRAintegrityProtectionAlgorithms_eia3,
      { "128-EIA3", "ngap.EUTRAintegrityProtectionAlgorithms.eia3",
        FT_BOOLEAN, 16, TFS(&tfs_supported_not_supported), 0x2000,
        NULL, HFILL }},
    { &hf_ngap_EUTRAintegrityProtectionAlgorithms_reserved,
      { "Reserved", "ngap.EUTRAintegrityProtectionAlgorithms.reserved",
        FT_UINT16, BASE_HEX, NULL, 0x1fff,
        NULL, HFILL }},

/*--- Included file: packet-ngap-hfarr.c ---*/
#line 1 "./asn1/ngap/packet-ngap-hfarr.c"
    { &hf_ngap_AdditionalDLUPTNLInformationForHOList_PDU,
      { "AdditionalDLUPTNLInformationForHOList", "ngap.AdditionalDLUPTNLInformationForHOList",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_ngap_AllowedNSSAI_PDU,
      { "AllowedNSSAI", "ngap.AllowedNSSAI",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_ngap_AMFName_PDU,
      { "AMFName", "ngap.AMFName",
        FT_STRING, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ngap_AMFSetID_PDU,
      { "AMFSetID", "ngap.AMFSetID",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ngap_AMF_TNLAssociationSetupList_PDU,
      { "AMF-TNLAssociationSetupList", "ngap.AMF_TNLAssociationSetupList",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_ngap_AMF_TNLAssociationToAddList_PDU,
      { "AMF-TNLAssociationToAddList", "ngap.AMF_TNLAssociationToAddList",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_ngap_AMF_TNLAssociationToRemoveList_PDU,
      { "AMF-TNLAssociationToRemoveList", "ngap.AMF_TNLAssociationToRemoveList",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_ngap_AMF_TNLAssociationToUpdateList_PDU,
      { "AMF-TNLAssociationToUpdateList", "ngap.AMF_TNLAssociationToUpdateList",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_ngap_AMF_UE_NGAP_ID_PDU,
      { "AMF-UE-NGAP-ID", "ngap.AMF_UE_NGAP_ID",
        FT_UINT64, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_ngap_AssistanceDataForPaging_PDU,
      { "AssistanceDataForPaging", "ngap.AssistanceDataForPaging_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ngap_AssociatedQosFlowList_PDU,
      { "AssociatedQosFlowList", "ngap.AssociatedQosFlowList",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_ngap_BroadcastCancelledAreaList_PDU,
      { "BroadcastCancelledAreaList", "ngap.BroadcastCancelledAreaList",
        FT_UINT32, BASE_DEC, VALS(ngap_BroadcastCancelledAreaList_vals), 0,
        NULL, HFILL }},
    { &hf_ngap_BroadcastCompletedAreaList_PDU,
      { "BroadcastCompletedAreaList", "ngap.BroadcastCompletedAreaList",
        FT_UINT32, BASE_DEC, VALS(ngap_BroadcastCompletedAreaList_vals), 0,
        NULL, HFILL }},
    { &hf_ngap_CancelAllWarningMessages_PDU,
      { "CancelAllWarningMessages", "ngap.CancelAllWarningMessages",
        FT_UINT32, BASE_DEC, VALS(ngap_CancelAllWarningMessages_vals), 0,
        NULL, HFILL }},
    { &hf_ngap_Cause_PDU,
      { "Cause", "ngap.Cause",
        FT_UINT32, BASE_DEC, VALS(ngap_Cause_vals), 0,
        NULL, HFILL }},
    { &hf_ngap_CellIDListForRestart_PDU,
      { "CellIDListForRestart", "ngap.CellIDListForRestart",
        FT_UINT32, BASE_DEC, VALS(ngap_CellIDListForRestart_vals), 0,
        NULL, HFILL }},
    { &hf_ngap_CNAssistedRANTuning_PDU,
      { "CNAssistedRANTuning", "ngap.CNAssistedRANTuning_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ngap_CNTypeRestrictionsForEquivalent_PDU,
      { "CNTypeRestrictionsForEquivalent", "ngap.CNTypeRestrictionsForEquivalent",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_ngap_CNTypeRestrictionsForServing_PDU,
      { "CNTypeRestrictionsForServing", "ngap.CNTypeRestrictionsForServing",
        FT_UINT32, BASE_DEC, VALS(ngap_CNTypeRestrictionsForServing_vals), 0,
        NULL, HFILL }},
    { &hf_ngap_CommonNetworkInstance_PDU,
      { "CommonNetworkInstance", "ngap.CommonNetworkInstance",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ngap_ConcurrentWarningMessageInd_PDU,
      { "ConcurrentWarningMessageInd", "ngap.ConcurrentWarningMessageInd",
        FT_UINT32, BASE_DEC, VALS(ngap_ConcurrentWarningMessageInd_vals), 0,
        NULL, HFILL }},
    { &hf_ngap_CoreNetworkAssistanceInformationForInactive_PDU,
      { "CoreNetworkAssistanceInformationForInactive", "ngap.CoreNetworkAssistanceInformationForInactive_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ngap_CPTransportLayerInformation_PDU,
      { "CPTransportLayerInformation", "ngap.CPTransportLayerInformation",
        FT_UINT32, BASE_DEC, VALS(ngap_CPTransportLayerInformation_vals), 0,
        NULL, HFILL }},
    { &hf_ngap_CriticalityDiagnostics_PDU,
      { "CriticalityDiagnostics", "ngap.CriticalityDiagnostics_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ngap_DataCodingScheme_PDU,
      { "DataCodingScheme", "ngap.DataCodingScheme",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ngap_DataForwardingNotPossible_PDU,
      { "DataForwardingNotPossible", "ngap.DataForwardingNotPossible",
        FT_UINT32, BASE_DEC, VALS(ngap_DataForwardingNotPossible_vals), 0,
        NULL, HFILL }},
    { &hf_ngap_DirectForwardingPathAvailability_PDU,
      { "DirectForwardingPathAvailability", "ngap.DirectForwardingPathAvailability",
        FT_UINT32, BASE_DEC, VALS(ngap_DirectForwardingPathAvailability_vals), 0,
        NULL, HFILL }},
    { &hf_ngap_EmergencyAreaIDListForRestart_PDU,
      { "EmergencyAreaIDListForRestart", "ngap.EmergencyAreaIDListForRestart",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_ngap_EmergencyFallbackIndicator_PDU,
      { "EmergencyFallbackIndicator", "ngap.EmergencyFallbackIndicator_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ngap_EN_DCSONConfigurationTransfer_PDU,
      { "EN-DCSONConfigurationTransfer", "ngap.EN_DCSONConfigurationTransfer",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ngap_EndpointIPAddressAndPort_PDU,
      { "EndpointIPAddressAndPort", "ngap.EndpointIPAddressAndPort_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ngap_EUTRA_CGI_PDU,
      { "EUTRA-CGI", "ngap.EUTRA_CGI_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ngap_FiveG_S_TMSI_PDU,
      { "FiveG-S-TMSI", "ngap.FiveG_S_TMSI_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ngap_GlobalRANNodeID_PDU,
      { "GlobalRANNodeID", "ngap.GlobalRANNodeID",
        FT_UINT32, BASE_DEC, VALS(ngap_GlobalRANNodeID_vals), 0,
        NULL, HFILL }},
    { &hf_ngap_GUAMI_PDU,
      { "GUAMI", "ngap.GUAMI_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ngap_HandoverCommandTransfer_PDU,
      { "HandoverCommandTransfer", "ngap.HandoverCommandTransfer_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ngap_HandoverFlag_PDU,
      { "HandoverFlag", "ngap.HandoverFlag",
        FT_UINT32, BASE_DEC, VALS(ngap_HandoverFlag_vals), 0,
        NULL, HFILL }},
    { &hf_ngap_HandoverPreparationUnsuccessfulTransfer_PDU,
      { "HandoverPreparationUnsuccessfulTransfer", "ngap.HandoverPreparationUnsuccessfulTransfer_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ngap_HandoverRequestAcknowledgeTransfer_PDU,
      { "HandoverRequestAcknowledgeTransfer", "ngap.HandoverRequestAcknowledgeTransfer_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ngap_HandoverRequiredTransfer_PDU,
      { "HandoverRequiredTransfer", "ngap.HandoverRequiredTransfer_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ngap_HandoverResourceAllocationUnsuccessfulTransfer_PDU,
      { "HandoverResourceAllocationUnsuccessfulTransfer", "ngap.HandoverResourceAllocationUnsuccessfulTransfer_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ngap_HandoverType_PDU,
      { "HandoverType", "ngap.HandoverType",
        FT_UINT32, BASE_DEC, VALS(ngap_HandoverType_vals), 0,
        NULL, HFILL }},
    { &hf_ngap_IMSVoiceSupportIndicator_PDU,
      { "IMSVoiceSupportIndicator", "ngap.IMSVoiceSupportIndicator",
        FT_UINT32, BASE_DEC, VALS(ngap_IMSVoiceSupportIndicator_vals), 0,
        NULL, HFILL }},
    { &hf_ngap_IndexToRFSP_PDU,
      { "IndexToRFSP", "ngap.IndexToRFSP",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_ngap_InfoOnRecommendedCellsAndRANNodesForPaging_PDU,
      { "InfoOnRecommendedCellsAndRANNodesForPaging", "ngap.InfoOnRecommendedCellsAndRANNodesForPaging_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ngap_ngap_LastVisitedNGRANCellInformation_PDU,
      { "LastVisitedNGRANCellInformation", "ngap.LastVisitedNGRANCellInformation_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ngap_LocationReportingAdditionalInfo_PDU,
      { "LocationReportingAdditionalInfo", "ngap.LocationReportingAdditionalInfo",
        FT_UINT32, BASE_DEC, VALS(ngap_LocationReportingAdditionalInfo_vals), 0,
        NULL, HFILL }},
    { &hf_ngap_LocationReportingRequestType_PDU,
      { "LocationReportingRequestType", "ngap.LocationReportingRequestType_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ngap_MaskedIMEISV_PDU,
      { "MaskedIMEISV", "ngap.MaskedIMEISV",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ngap_MessageIdentifier_PDU,
      { "MessageIdentifier", "ngap.MessageIdentifier",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ngap_MaximumIntegrityProtectedDataRate_PDU,
      { "MaximumIntegrityProtectedDataRate", "ngap.MaximumIntegrityProtectedDataRate",
        FT_UINT32, BASE_DEC, VALS(ngap_MaximumIntegrityProtectedDataRate_vals), 0,
        NULL, HFILL }},
    { &hf_ngap_ngap_MobilityRestrictionList_PDU,
      { "MobilityRestrictionList", "ngap.MobilityRestrictionList_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ngap_NAS_PDU_PDU,
      { "NAS-PDU", "ngap.NAS_PDU",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ngap_NASSecurityParametersFromNGRAN_PDU,
      { "NASSecurityParametersFromNGRAN", "ngap.NASSecurityParametersFromNGRAN",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ngap_NetworkInstance_PDU,
      { "NetworkInstance", "ngap.NetworkInstance",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_ngap_NewSecurityContextInd_PDU,
      { "NewSecurityContextInd", "ngap.NewSecurityContextInd",
        FT_UINT32, BASE_DEC, VALS(ngap_NewSecurityContextInd_vals), 0,
        NULL, HFILL }},
    { &hf_ngap_ngap_NGRAN_CGI_PDU,
      { "NGRAN-CGI", "ngap.NGRAN_CGI",
        FT_UINT32, BASE_DEC, VALS(ngap_NGRAN_CGI_vals), 0,
        NULL, HFILL }},
    { &hf_ngap_NGRAN_TNLAssociationToRemoveList_PDU,
      { "NGRAN-TNLAssociationToRemoveList", "ngap.NGRAN_TNLAssociationToRemoveList",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_ngap_NGRANTraceID_PDU,
      { "NGRANTraceID", "ngap.NGRANTraceID",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ngap_NR_CGI_PDU,
      { "NR-CGI", "ngap.NR_CGI_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ngap_NRPPa_PDU_PDU,
      { "NRPPa-PDU", "ngap.NRPPa_PDU",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ngap_NumberOfBroadcastsRequested_PDU,
      { "NumberOfBroadcastsRequested", "ngap.NumberOfBroadcastsRequested",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_ngap_OverloadResponse_PDU,
      { "OverloadResponse", "ngap.OverloadResponse",
        FT_UINT32, BASE_DEC, VALS(ngap_OverloadResponse_vals), 0,
        NULL, HFILL }},
    { &hf_ngap_OverloadStartNSSAIList_PDU,
      { "OverloadStartNSSAIList", "ngap.OverloadStartNSSAIList",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_ngap_PagingDRX_PDU,
      { "PagingDRX", "ngap.PagingDRX",
        FT_UINT32, BASE_DEC, VALS(ngap_PagingDRX_vals), 0,
        NULL, HFILL }},
    { &hf_ngap_PagingOrigin_PDU,
      { "PagingOrigin", "ngap.PagingOrigin",
        FT_UINT32, BASE_DEC, VALS(ngap_PagingOrigin_vals), 0,
        NULL, HFILL }},
    { &hf_ngap_PagingPriority_PDU,
      { "PagingPriority", "ngap.PagingPriority",
        FT_UINT32, BASE_DEC, VALS(ngap_PagingPriority_vals), 0,
        NULL, HFILL }},
    { &hf_ngap_PathSwitchRequestAcknowledgeTransfer_PDU,
      { "PathSwitchRequestAcknowledgeTransfer", "ngap.PathSwitchRequestAcknowledgeTransfer_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ngap_PathSwitchRequestSetupFailedTransfer_PDU,
      { "PathSwitchRequestSetupFailedTransfer", "ngap.PathSwitchRequestSetupFailedTransfer_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ngap_PathSwitchRequestTransfer_PDU,
      { "PathSwitchRequestTransfer", "ngap.PathSwitchRequestTransfer_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ngap_PathSwitchRequestUnsuccessfulTransfer_PDU,
      { "PathSwitchRequestUnsuccessfulTransfer", "ngap.PathSwitchRequestUnsuccessfulTransfer_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ngap_PDUSessionAggregateMaximumBitRate_PDU,
      { "PDUSessionAggregateMaximumBitRate", "ngap.PDUSessionAggregateMaximumBitRate_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ngap_PDUSessionResourceAdmittedList_PDU,
      { "PDUSessionResourceAdmittedList", "ngap.PDUSessionResourceAdmittedList",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_ngap_PDUSessionResourceFailedToModifyListModCfm_PDU,
      { "PDUSessionResourceFailedToModifyListModCfm", "ngap.PDUSessionResourceFailedToModifyListModCfm",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_ngap_PDUSessionResourceFailedToModifyListModRes_PDU,
      { "PDUSessionResourceFailedToModifyListModRes", "ngap.PDUSessionResourceFailedToModifyListModRes",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_ngap_PDUSessionResourceFailedToSetupListCxtFail_PDU,
      { "PDUSessionResourceFailedToSetupListCxtFail", "ngap.PDUSessionResourceFailedToSetupListCxtFail",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_ngap_PDUSessionResourceFailedToSetupListCxtRes_PDU,
      { "PDUSessionResourceFailedToSetupListCxtRes", "ngap.PDUSessionResourceFailedToSetupListCxtRes",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_ngap_PDUSessionResourceFailedToSetupListHOAck_PDU,
      { "PDUSessionResourceFailedToSetupListHOAck", "ngap.PDUSessionResourceFailedToSetupListHOAck",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_ngap_PDUSessionResourceFailedToSetupListPSReq_PDU,
      { "PDUSessionResourceFailedToSetupListPSReq", "ngap.PDUSessionResourceFailedToSetupListPSReq",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_ngap_PDUSessionResourceFailedToSetupListSURes_PDU,
      { "PDUSessionResourceFailedToSetupListSURes", "ngap.PDUSessionResourceFailedToSetupListSURes",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_ngap_PDUSessionResourceHandoverList_PDU,
      { "PDUSessionResourceHandoverList", "ngap.PDUSessionResourceHandoverList",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_ngap_PDUSessionResourceListCxtRelCpl_PDU,
      { "PDUSessionResourceListCxtRelCpl", "ngap.PDUSessionResourceListCxtRelCpl",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_ngap_PDUSessionResourceReleaseResponseTransfer_OCTET_STRING_PDU,
      { "PDUSessionResourceReleaseResponseTransfer-OCTET-STRING", "ngap.PDUSessionResourceReleaseResponseTransfer_OCTET_STRING",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ngap_PDUSessionResourceListCxtRelReq_PDU,
      { "PDUSessionResourceListCxtRelReq", "ngap.PDUSessionResourceListCxtRelReq",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_ngap_PDUSessionResourceListHORqd_PDU,
      { "PDUSessionResourceListHORqd", "ngap.PDUSessionResourceListHORqd",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_ngap_PDUSessionResourceModifyConfirmTransfer_PDU,
      { "PDUSessionResourceModifyConfirmTransfer", "ngap.PDUSessionResourceModifyConfirmTransfer_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ngap_PDUSessionResourceModifyRequestTransfer_PDU,
      { "PDUSessionResourceModifyRequestTransfer", "ngap.PDUSessionResourceModifyRequestTransfer_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ngap_PDUSessionResourceModifyResponseTransfer_PDU,
      { "PDUSessionResourceModifyResponseTransfer", "ngap.PDUSessionResourceModifyResponseTransfer_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ngap_PDUSessionResourceModifyIndicationTransfer_PDU,
      { "PDUSessionResourceModifyIndicationTransfer", "ngap.PDUSessionResourceModifyIndicationTransfer_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ngap_PDUSessionResourceModifyListModCfm_PDU,
      { "PDUSessionResourceModifyListModCfm", "ngap.PDUSessionResourceModifyListModCfm",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_ngap_PDUSessionResourceModifyListModInd_PDU,
      { "PDUSessionResourceModifyListModInd", "ngap.PDUSessionResourceModifyListModInd",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_ngap_PDUSessionResourceModifyListModReq_PDU,
      { "PDUSessionResourceModifyListModReq", "ngap.PDUSessionResourceModifyListModReq",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_ngap_PDUSessionResourceModifyListModRes_PDU,
      { "PDUSessionResourceModifyListModRes", "ngap.PDUSessionResourceModifyListModRes",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_ngap_PDUSessionResourceModifyUnsuccessfulTransfer_PDU,
      { "PDUSessionResourceModifyUnsuccessfulTransfer", "ngap.PDUSessionResourceModifyUnsuccessfulTransfer_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ngap_PDUSessionResourceNotifyList_PDU,
      { "PDUSessionResourceNotifyList", "ngap.PDUSessionResourceNotifyList",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_ngap_PDUSessionResourceNotifyReleasedTransfer_PDU,
      { "PDUSessionResourceNotifyReleasedTransfer", "ngap.PDUSessionResourceNotifyReleasedTransfer_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ngap_PDUSessionResourceNotifyTransfer_PDU,
      { "PDUSessionResourceNotifyTransfer", "ngap.PDUSessionResourceNotifyTransfer_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ngap_PDUSessionResourceReleaseCommandTransfer_PDU,
      { "PDUSessionResourceReleaseCommandTransfer", "ngap.PDUSessionResourceReleaseCommandTransfer_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ngap_PDUSessionResourceReleasedListNot_PDU,
      { "PDUSessionResourceReleasedListNot", "ngap.PDUSessionResourceReleasedListNot",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_ngap_PDUSessionResourceReleasedListPSAck_PDU,
      { "PDUSessionResourceReleasedListPSAck", "ngap.PDUSessionResourceReleasedListPSAck",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_ngap_PDUSessionResourceReleasedListPSFail_PDU,
      { "PDUSessionResourceReleasedListPSFail", "ngap.PDUSessionResourceReleasedListPSFail",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_ngap_PDUSessionResourceReleasedListRelRes_PDU,
      { "PDUSessionResourceReleasedListRelRes", "ngap.PDUSessionResourceReleasedListRelRes",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_ngap_PDUSessionResourceReleaseResponseTransfer_PDU,
      { "PDUSessionResourceReleaseResponseTransfer", "ngap.PDUSessionResourceReleaseResponseTransfer_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ngap_PDUSessionResourceSecondaryRATUsageList_PDU,
      { "PDUSessionResourceSecondaryRATUsageList", "ngap.PDUSessionResourceSecondaryRATUsageList",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_ngap_PDUSessionResourceSetupListCxtReq_PDU,
      { "PDUSessionResourceSetupListCxtReq", "ngap.PDUSessionResourceSetupListCxtReq",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_ngap_PDUSessionResourceSetupListCxtRes_PDU,
      { "PDUSessionResourceSetupListCxtRes", "ngap.PDUSessionResourceSetupListCxtRes",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_ngap_PDUSessionResourceSetupListHOReq_PDU,
      { "PDUSessionResourceSetupListHOReq", "ngap.PDUSessionResourceSetupListHOReq",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_ngap_PDUSessionResourceSetupListSUReq_PDU,
      { "PDUSessionResourceSetupListSUReq", "ngap.PDUSessionResourceSetupListSUReq",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_ngap_PDUSessionResourceSetupListSURes_PDU,
      { "PDUSessionResourceSetupListSURes", "ngap.PDUSessionResourceSetupListSURes",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_ngap_PDUSessionResourceSetupRequestTransfer_PDU,
      { "PDUSessionResourceSetupRequestTransfer", "ngap.PDUSessionResourceSetupRequestTransfer_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ngap_PDUSessionResourceSetupResponseTransfer_PDU,
      { "PDUSessionResourceSetupResponseTransfer", "ngap.PDUSessionResourceSetupResponseTransfer_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ngap_PDUSessionResourceSetupUnsuccessfulTransfer_PDU,
      { "PDUSessionResourceSetupUnsuccessfulTransfer", "ngap.PDUSessionResourceSetupUnsuccessfulTransfer_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ngap_PDUSessionResourceSwitchedList_PDU,
      { "PDUSessionResourceSwitchedList", "ngap.PDUSessionResourceSwitchedList",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_ngap_PDUSessionResourceToBeSwitchedDLList_PDU,
      { "PDUSessionResourceToBeSwitchedDLList", "ngap.PDUSessionResourceToBeSwitchedDLList",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_ngap_PDUSessionResourceToReleaseListHOCmd_PDU,
      { "PDUSessionResourceToReleaseListHOCmd", "ngap.PDUSessionResourceToReleaseListHOCmd",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_ngap_PDUSessionResourceToReleaseListRelCmd_PDU,
      { "PDUSessionResourceToReleaseListRelCmd", "ngap.PDUSessionResourceToReleaseListRelCmd",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_ngap_PDUSessionType_PDU,
      { "PDUSessionType", "ngap.PDUSessionType",
        FT_UINT32, BASE_DEC, VALS(ngap_PDUSessionType_vals), 0,
        NULL, HFILL }},
    { &hf_ngap_PLMNIdentity_PDU,
      { "PLMNIdentity", "ngap.PLMNIdentity",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ngap_PLMNSupportList_PDU,
      { "PLMNSupportList", "ngap.PLMNSupportList",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_ngap_PWSFailedCellIDList_PDU,
      { "PWSFailedCellIDList", "ngap.PWSFailedCellIDList",
        FT_UINT32, BASE_DEC, VALS(ngap_PWSFailedCellIDList_vals), 0,
        NULL, HFILL }},
    { &hf_ngap_QosFlowAddOrModifyRequestList_PDU,
      { "QosFlowAddOrModifyRequestList", "ngap.QosFlowAddOrModifyRequestList",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_ngap_QosFlowListWithCause_PDU,
      { "QosFlowListWithCause", "ngap.QosFlowListWithCause",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_ngap_QosFlowPerTNLInformationList_PDU,
      { "QosFlowPerTNLInformationList", "ngap.QosFlowPerTNLInformationList",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_ngap_QosFlowSetupRequestList_PDU,
      { "QosFlowSetupRequestList", "ngap.QosFlowSetupRequestList",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_ngap_RANNodeName_PDU,
      { "RANNodeName", "ngap.RANNodeName",
        FT_STRING, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ngap_RANPagingPriority_PDU,
      { "RANPagingPriority", "ngap.RANPagingPriority",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_ngap_RANStatusTransfer_TransparentContainer_PDU,
      { "RANStatusTransfer-TransparentContainer", "ngap.RANStatusTransfer_TransparentContainer_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ngap_RAN_UE_NGAP_ID_PDU,
      { "RAN-UE-NGAP-ID", "ngap.RAN_UE_NGAP_ID",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_ngap_RedirectionVoiceFallback_PDU,
      { "RedirectionVoiceFallback", "ngap.RedirectionVoiceFallback",
        FT_UINT32, BASE_DEC, VALS(ngap_RedirectionVoiceFallback_vals), 0,
        NULL, HFILL }},
    { &hf_ngap_RelativeAMFCapacity_PDU,
      { "RelativeAMFCapacity", "ngap.RelativeAMFCapacity",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_ngap_RepetitionPeriod_PDU,
      { "RepetitionPeriod", "ngap.RepetitionPeriod",
        FT_UINT32, BASE_DEC|BASE_UNIT_STRING, &units_seconds, 0,
        NULL, HFILL }},
    { &hf_ngap_ResetType_PDU,
      { "ResetType", "ngap.ResetType",
        FT_UINT32, BASE_DEC, VALS(ngap_ResetType_vals), 0,
        NULL, HFILL }},
    { &hf_ngap_RoutingID_PDU,
      { "RoutingID", "ngap.RoutingID",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ngap_RRCEstablishmentCause_PDU,
      { "RRCEstablishmentCause", "ngap.RRCEstablishmentCause",
        FT_UINT32, BASE_DEC, VALS(ngap_RRCEstablishmentCause_vals), 0,
        NULL, HFILL }},
    { &hf_ngap_RRCInactiveTransitionReportRequest_PDU,
      { "RRCInactiveTransitionReportRequest", "ngap.RRCInactiveTransitionReportRequest",
        FT_UINT32, BASE_DEC, VALS(ngap_RRCInactiveTransitionReportRequest_vals), 0,
        NULL, HFILL }},
    { &hf_ngap_RRCState_PDU,
      { "RRCState", "ngap.RRCState",
        FT_UINT32, BASE_DEC, VALS(ngap_RRCState_vals), 0,
        NULL, HFILL }},
    { &hf_ngap_SCTP_TLAs_PDU,
      { "SCTP-TLAs", "ngap.SCTP_TLAs",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_ngap_SecondaryRATUsageInformation_PDU,
      { "SecondaryRATUsageInformation", "ngap.SecondaryRATUsageInformation_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ngap_SecurityContext_PDU,
      { "SecurityContext", "ngap.SecurityContext_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ngap_SecurityIndication_PDU,
      { "SecurityIndication", "ngap.SecurityIndication_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ngap_SecurityKey_PDU,
      { "SecurityKey", "ngap.SecurityKey",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ngap_SecurityResult_PDU,
      { "SecurityResult", "ngap.SecurityResult_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ngap_SerialNumber_PDU,
      { "SerialNumber", "ngap.SerialNumber",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ngap_ServedGUAMIList_PDU,
      { "ServedGUAMIList", "ngap.ServedGUAMIList",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_ngap_SliceSupportList_PDU,
      { "SliceSupportList", "ngap.SliceSupportList",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_ngap_S_NSSAI_PDU,
      { "S-NSSAI", "ngap.S_NSSAI_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ngap_SONConfigurationTransfer_PDU,
      { "SONConfigurationTransfer", "ngap.SONConfigurationTransfer_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ngap_ngap_SourceNGRANNode_ToTargetNGRANNode_TransparentContainer_PDU,
      { "SourceNGRANNode-ToTargetNGRANNode-TransparentContainer", "ngap.SourceNGRANNode_ToTargetNGRANNode_TransparentContainer_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ngap_SourceToTarget_TransparentContainer_PDU,
      { "SourceToTarget-TransparentContainer", "ngap.SourceToTarget_TransparentContainer",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ngap_SourceToTarget_AMFInformationReroute_PDU,
      { "SourceToTarget-AMFInformationReroute", "ngap.SourceToTarget_AMFInformationReroute_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ngap_SupportedTAList_PDU,
      { "SupportedTAList", "ngap.SupportedTAList",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_ngap_TAIListForPaging_PDU,
      { "TAIListForPaging", "ngap.TAIListForPaging",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_ngap_TAIListForRestart_PDU,
      { "TAIListForRestart", "ngap.TAIListForRestart",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_ngap_TargetID_PDU,
      { "TargetID", "ngap.TargetID",
        FT_UINT32, BASE_DEC, VALS(ngap_TargetID_vals), 0,
        NULL, HFILL }},
    { &hf_ngap_ngap_TargetNGRANNode_ToSourceNGRANNode_TransparentContainer_PDU,
      { "TargetNGRANNode-ToSourceNGRANNode-TransparentContainer", "ngap.TargetNGRANNode_ToSourceNGRANNode_TransparentContainer_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ngap_TargetToSource_TransparentContainer_PDU,
      { "TargetToSource-TransparentContainer", "ngap.TargetToSource_TransparentContainer",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ngap_TimeToWait_PDU,
      { "TimeToWait", "ngap.TimeToWait",
        FT_UINT32, BASE_DEC, VALS(ngap_TimeToWait_vals), 0,
        NULL, HFILL }},
    { &hf_ngap_TNLAssociationList_PDU,
      { "TNLAssociationList", "ngap.TNLAssociationList",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_ngap_TraceActivation_PDU,
      { "TraceActivation", "ngap.TraceActivation_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ngap_TrafficLoadReductionIndication_PDU,
      { "TrafficLoadReductionIndication", "ngap.TrafficLoadReductionIndication",
        FT_UINT32, BASE_DEC|BASE_UNIT_STRING, &units_percent, 0,
        NULL, HFILL }},
    { &hf_ngap_TransportLayerAddress_PDU,
      { "TransportLayerAddress", "ngap.TransportLayerAddress",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ngap_UEAggregateMaximumBitRate_PDU,
      { "UEAggregateMaximumBitRate", "ngap.UEAggregateMaximumBitRate_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ngap_UE_associatedLogicalNG_connectionList_PDU,
      { "UE-associatedLogicalNG-connectionList", "ngap.UE_associatedLogicalNG_connectionList",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_ngap_UEContextRequest_PDU,
      { "UEContextRequest", "ngap.UEContextRequest",
        FT_UINT32, BASE_DEC, VALS(ngap_UEContextRequest_vals), 0,
        NULL, HFILL }},
    { &hf_ngap_UE_NGAP_IDs_PDU,
      { "UE-NGAP-IDs", "ngap.UE_NGAP_IDs",
        FT_UINT32, BASE_DEC, VALS(ngap_UE_NGAP_IDs_vals), 0,
        NULL, HFILL }},
    { &hf_ngap_UEPagingIdentity_PDU,
      { "UEPagingIdentity", "ngap.UEPagingIdentity",
        FT_UINT32, BASE_DEC, VALS(ngap_UEPagingIdentity_vals), 0,
        NULL, HFILL }},
    { &hf_ngap_UEPresenceInAreaOfInterestList_PDU,
      { "UEPresenceInAreaOfInterestList", "ngap.UEPresenceInAreaOfInterestList",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_ngap_UERadioCapability_PDU,
      { "UERadioCapability", "ngap.UERadioCapability",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ngap_UERadioCapabilityForPaging_PDU,
      { "UERadioCapabilityForPaging", "ngap.UERadioCapabilityForPaging_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ngap_UERetentionInformation_PDU,
      { "UERetentionInformation", "ngap.UERetentionInformation",
        FT_UINT32, BASE_DEC, VALS(ngap_UERetentionInformation_vals), 0,
        NULL, HFILL }},
    { &hf_ngap_UESecurityCapabilities_PDU,
      { "UESecurityCapabilities", "ngap.UESecurityCapabilities_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ngap_UL_NGU_UP_TNLModifyList_PDU,
      { "UL-NGU-UP-TNLModifyList", "ngap.UL_NGU_UP_TNLModifyList",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_ngap_UnavailableGUAMIList_PDU,
      { "UnavailableGUAMIList", "ngap.UnavailableGUAMIList",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_ngap_ULForwarding_PDU,
      { "ULForwarding", "ngap.ULForwarding",
        FT_UINT32, BASE_DEC, VALS(ngap_ULForwarding_vals), 0,
        NULL, HFILL }},
    { &hf_ngap_UPTransportLayerInformation_PDU,
      { "UPTransportLayerInformation", "ngap.UPTransportLayerInformation",
        FT_UINT32, BASE_DEC, VALS(ngap_UPTransportLayerInformation_vals), 0,
        NULL, HFILL }},
    { &hf_ngap_UPTransportLayerInformationList_PDU,
      { "UPTransportLayerInformationList", "ngap.UPTransportLayerInformationList",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_ngap_UPTransportLayerInformationPairList_PDU,
      { "UPTransportLayerInformationPairList", "ngap.UPTransportLayerInformationPairList",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_ngap_UserLocationInformation_PDU,
      { "UserLocationInformation", "ngap.UserLocationInformation",
        FT_UINT32, BASE_DEC, VALS(ngap_UserLocationInformation_vals), 0,
        NULL, HFILL }},
    { &hf_ngap_WarningAreaCoordinates_PDU,
      { "WarningAreaCoordinates", "ngap.WarningAreaCoordinates",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ngap_WarningAreaList_PDU,
      { "WarningAreaList", "ngap.WarningAreaList",
        FT_UINT32, BASE_DEC, VALS(ngap_WarningAreaList_vals), 0,
        NULL, HFILL }},
    { &hf_ngap_WarningMessageContents_PDU,
      { "WarningMessageContents", "ngap.WarningMessageContents",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ngap_WarningSecurityInfo_PDU,
      { "WarningSecurityInfo", "ngap.WarningSecurityInfo",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ngap_WarningType_PDU,
      { "WarningType", "ngap.WarningType",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ngap_PDUSessionResourceSetupRequest_PDU,
      { "PDUSessionResourceSetupRequest", "ngap.PDUSessionResourceSetupRequest_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ngap_PDUSessionResourceSetupResponse_PDU,
      { "PDUSessionResourceSetupResponse", "ngap.PDUSessionResourceSetupResponse_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ngap_PDUSessionResourceReleaseCommand_PDU,
      { "PDUSessionResourceReleaseCommand", "ngap.PDUSessionResourceReleaseCommand_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ngap_PDUSessionResourceReleaseResponse_PDU,
      { "PDUSessionResourceReleaseResponse", "ngap.PDUSessionResourceReleaseResponse_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ngap_PDUSessionResourceModifyRequest_PDU,
      { "PDUSessionResourceModifyRequest", "ngap.PDUSessionResourceModifyRequest_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ngap_PDUSessionResourceModifyResponse_PDU,
      { "PDUSessionResourceModifyResponse", "ngap.PDUSessionResourceModifyResponse_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ngap_PDUSessionResourceNotify_PDU,
      { "PDUSessionResourceNotify", "ngap.PDUSessionResourceNotify_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ngap_PDUSessionResourceModifyIndication_PDU,
      { "PDUSessionResourceModifyIndication", "ngap.PDUSessionResourceModifyIndication_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ngap_PDUSessionResourceModifyConfirm_PDU,
      { "PDUSessionResourceModifyConfirm", "ngap.PDUSessionResourceModifyConfirm_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ngap_InitialContextSetupRequest_PDU,
      { "InitialContextSetupRequest", "ngap.InitialContextSetupRequest_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ngap_InitialContextSetupResponse_PDU,
      { "InitialContextSetupResponse", "ngap.InitialContextSetupResponse_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ngap_InitialContextSetupFailure_PDU,
      { "InitialContextSetupFailure", "ngap.InitialContextSetupFailure_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ngap_UEContextReleaseRequest_PDU,
      { "UEContextReleaseRequest", "ngap.UEContextReleaseRequest_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ngap_UEContextReleaseCommand_PDU,
      { "UEContextReleaseCommand", "ngap.UEContextReleaseCommand_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ngap_UEContextReleaseComplete_PDU,
      { "UEContextReleaseComplete", "ngap.UEContextReleaseComplete_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ngap_UEContextModificationRequest_PDU,
      { "UEContextModificationRequest", "ngap.UEContextModificationRequest_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ngap_UEContextModificationResponse_PDU,
      { "UEContextModificationResponse", "ngap.UEContextModificationResponse_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ngap_UEContextModificationFailure_PDU,
      { "UEContextModificationFailure", "ngap.UEContextModificationFailure_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ngap_RRCInactiveTransitionReport_PDU,
      { "RRCInactiveTransitionReport", "ngap.RRCInactiveTransitionReport_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ngap_HandoverRequired_PDU,
      { "HandoverRequired", "ngap.HandoverRequired_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ngap_HandoverCommand_PDU,
      { "HandoverCommand", "ngap.HandoverCommand_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ngap_HandoverPreparationFailure_PDU,
      { "HandoverPreparationFailure", "ngap.HandoverPreparationFailure_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ngap_HandoverRequest_PDU,
      { "HandoverRequest", "ngap.HandoverRequest_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ngap_HandoverRequestAcknowledge_PDU,
      { "HandoverRequestAcknowledge", "ngap.HandoverRequestAcknowledge_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ngap_HandoverFailure_PDU,
      { "HandoverFailure", "ngap.HandoverFailure_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ngap_HandoverNotify_PDU,
      { "HandoverNotify", "ngap.HandoverNotify_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ngap_PathSwitchRequest_PDU,
      { "PathSwitchRequest", "ngap.PathSwitchRequest_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ngap_PathSwitchRequestAcknowledge_PDU,
      { "PathSwitchRequestAcknowledge", "ngap.PathSwitchRequestAcknowledge_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ngap_PathSwitchRequestFailure_PDU,
      { "PathSwitchRequestFailure", "ngap.PathSwitchRequestFailure_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ngap_HandoverCancel_PDU,
      { "HandoverCancel", "ngap.HandoverCancel_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ngap_HandoverCancelAcknowledge_PDU,
      { "HandoverCancelAcknowledge", "ngap.HandoverCancelAcknowledge_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ngap_UplinkRANStatusTransfer_PDU,
      { "UplinkRANStatusTransfer", "ngap.UplinkRANStatusTransfer_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ngap_DownlinkRANStatusTransfer_PDU,
      { "DownlinkRANStatusTransfer", "ngap.DownlinkRANStatusTransfer_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ngap_Paging_PDU,
      { "Paging", "ngap.Paging_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ngap_InitialUEMessage_PDU,
      { "InitialUEMessage", "ngap.InitialUEMessage_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ngap_DownlinkNASTransport_PDU,
      { "DownlinkNASTransport", "ngap.DownlinkNASTransport_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ngap_UplinkNASTransport_PDU,
      { "UplinkNASTransport", "ngap.UplinkNASTransport_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ngap_NASNonDeliveryIndication_PDU,
      { "NASNonDeliveryIndication", "ngap.NASNonDeliveryIndication_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ngap_RerouteNASRequest_PDU,
      { "RerouteNASRequest", "ngap.RerouteNASRequest_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ngap_NGAP_Message_PDU,
      { "NGAP-Message", "ngap.NGAP_Message",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ngap_NGSetupRequest_PDU,
      { "NGSetupRequest", "ngap.NGSetupRequest_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ngap_NGSetupResponse_PDU,
      { "NGSetupResponse", "ngap.NGSetupResponse_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ngap_NGSetupFailure_PDU,
      { "NGSetupFailure", "ngap.NGSetupFailure_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ngap_RANConfigurationUpdate_PDU,
      { "RANConfigurationUpdate", "ngap.RANConfigurationUpdate_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ngap_RANConfigurationUpdateAcknowledge_PDU,
      { "RANConfigurationUpdateAcknowledge", "ngap.RANConfigurationUpdateAcknowledge_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ngap_RANConfigurationUpdateFailure_PDU,
      { "RANConfigurationUpdateFailure", "ngap.RANConfigurationUpdateFailure_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ngap_AMFConfigurationUpdate_PDU,
      { "AMFConfigurationUpdate", "ngap.AMFConfigurationUpdate_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ngap_AMFConfigurationUpdateAcknowledge_PDU,
      { "AMFConfigurationUpdateAcknowledge", "ngap.AMFConfigurationUpdateAcknowledge_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ngap_AMFConfigurationUpdateFailure_PDU,
      { "AMFConfigurationUpdateFailure", "ngap.AMFConfigurationUpdateFailure_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ngap_AMFStatusIndication_PDU,
      { "AMFStatusIndication", "ngap.AMFStatusIndication_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ngap_NGReset_PDU,
      { "NGReset", "ngap.NGReset_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ngap_NGResetAcknowledge_PDU,
      { "NGResetAcknowledge", "ngap.NGResetAcknowledge_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ngap_ErrorIndication_PDU,
      { "ErrorIndication", "ngap.ErrorIndication_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ngap_OverloadStart_PDU,
      { "OverloadStart", "ngap.OverloadStart_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ngap_OverloadStop_PDU,
      { "OverloadStop", "ngap.OverloadStop_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ngap_UplinkRANConfigurationTransfer_PDU,
      { "UplinkRANConfigurationTransfer", "ngap.UplinkRANConfigurationTransfer_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ngap_DownlinkRANConfigurationTransfer_PDU,
      { "DownlinkRANConfigurationTransfer", "ngap.DownlinkRANConfigurationTransfer_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ngap_WriteReplaceWarningRequest_PDU,
      { "WriteReplaceWarningRequest", "ngap.WriteReplaceWarningRequest_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ngap_WriteReplaceWarningResponse_PDU,
      { "WriteReplaceWarningResponse", "ngap.WriteReplaceWarningResponse_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ngap_PWSCancelRequest_PDU,
      { "PWSCancelRequest", "ngap.PWSCancelRequest_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ngap_PWSCancelResponse_PDU,
      { "PWSCancelResponse", "ngap.PWSCancelResponse_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ngap_PWSRestartIndication_PDU,
      { "PWSRestartIndication", "ngap.PWSRestartIndication_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ngap_PWSFailureIndication_PDU,
      { "PWSFailureIndication", "ngap.PWSFailureIndication_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ngap_DownlinkUEAssociatedNRPPaTransport_PDU,
      { "DownlinkUEAssociatedNRPPaTransport", "ngap.DownlinkUEAssociatedNRPPaTransport_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ngap_UplinkUEAssociatedNRPPaTransport_PDU,
      { "UplinkUEAssociatedNRPPaTransport", "ngap.UplinkUEAssociatedNRPPaTransport_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ngap_DownlinkNonUEAssociatedNRPPaTransport_PDU,
      { "DownlinkNonUEAssociatedNRPPaTransport", "ngap.DownlinkNonUEAssociatedNRPPaTransport_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ngap_UplinkNonUEAssociatedNRPPaTransport_PDU,
      { "UplinkNonUEAssociatedNRPPaTransport", "ngap.UplinkNonUEAssociatedNRPPaTransport_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ngap_TraceStart_PDU,
      { "TraceStart", "ngap.TraceStart_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ngap_TraceFailureIndication_PDU,
      { "TraceFailureIndication", "ngap.TraceFailureIndication_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ngap_DeactivateTrace_PDU,
      { "DeactivateTrace", "ngap.DeactivateTrace_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ngap_CellTrafficTrace_PDU,
      { "CellTrafficTrace", "ngap.CellTrafficTrace_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ngap_LocationReportingControl_PDU,
      { "LocationReportingControl", "ngap.LocationReportingControl_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ngap_LocationReportingFailureIndication_PDU,
      { "LocationReportingFailureIndication", "ngap.LocationReportingFailureIndication_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ngap_LocationReport_PDU,
      { "LocationReport", "ngap.LocationReport_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ngap_UETNLABindingReleaseRequest_PDU,
      { "UETNLABindingReleaseRequest", "ngap.UETNLABindingReleaseRequest_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ngap_UERadioCapabilityInfoIndication_PDU,
      { "UERadioCapabilityInfoIndication", "ngap.UERadioCapabilityInfoIndication_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ngap_UERadioCapabilityCheckRequest_PDU,
      { "UERadioCapabilityCheckRequest", "ngap.UERadioCapabilityCheckRequest_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ngap_UERadioCapabilityCheckResponse_PDU,
      { "UERadioCapabilityCheckResponse", "ngap.UERadioCapabilityCheckResponse_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ngap_PrivateMessage_PDU,
      { "PrivateMessage", "ngap.PrivateMessage_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ngap_SecondaryRATDataUsageReport_PDU,
      { "SecondaryRATDataUsageReport", "ngap.SecondaryRATDataUsageReport_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ngap_NGAP_PDU_PDU,
      { "NGAP-PDU", "ngap.NGAP_PDU",
        FT_UINT32, BASE_DEC, VALS(ngap_NGAP_PDU_vals), 0,
        NULL, HFILL }},
    { &hf_ngap_PDUSessionResourceModifyIndicationUnsuccessfulTransfer_PDU,
      { "PDUSessionResourceModifyIndicationUnsuccessfulTransfer", "ngap.PDUSessionResourceModifyIndicationUnsuccessfulTransfer_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ngap_SecondaryRATDataUsageReportTransfer_PDU,
      { "SecondaryRATDataUsageReportTransfer", "ngap.SecondaryRATDataUsageReportTransfer_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ngap_local,
      { "local", "ngap.local",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_65535", HFILL }},
    { &hf_ngap_global,
      { "global", "ngap.global",
        FT_OID, BASE_NONE, NULL, 0,
        "OBJECT_IDENTIFIER", HFILL }},
    { &hf_ngap_ProtocolIE_Container_item,
      { "ProtocolIE-Field", "ngap.ProtocolIE_Field_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ngap_id,
      { "id", "ngap.id",
        FT_UINT32, BASE_DEC|BASE_EXT_STRING, &ngap_ProtocolIE_ID_vals_ext, 0,
        "ProtocolIE_ID", HFILL }},
    { &hf_ngap_criticality,
      { "criticality", "ngap.criticality",
        FT_UINT32, BASE_DEC, VALS(ngap_Criticality_vals), 0,
        NULL, HFILL }},
    { &hf_ngap_ie_field_value,
      { "value", "ngap.value_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "T_ie_field_value", HFILL }},
    { &hf_ngap_ProtocolExtensionContainer_item,
      { "ProtocolExtensionField", "ngap.ProtocolExtensionField_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ngap_ext_id,
      { "id", "ngap.id",
        FT_UINT8, BASE_DEC|BASE_EXT_STRING, &ngap_ProtocolIE_ID_vals_ext, 0,
        "ProtocolExtensionID", HFILL }},
    { &hf_ngap_extensionValue,
      { "extensionValue", "ngap.extensionValue_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ngap_PrivateIE_Container_item,
      { "PrivateIE-Field", "ngap.PrivateIE_Field_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ngap_private_id,
      { "id", "ngap.id",
        FT_UINT32, BASE_DEC, VALS(ngap_PrivateIE_ID_vals), 0,
        "PrivateIE_ID", HFILL }},
    { &hf_ngap_private_value,
      { "value", "ngap.value_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "T_private_value", HFILL }},
    { &hf_ngap_AdditionalDLUPTNLInformationForHOList_item,
      { "AdditionalDLUPTNLInformationForHOItem", "ngap.AdditionalDLUPTNLInformationForHOItem_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ngap_additionalDL_NGU_UP_TNLInformation,
      { "additionalDL-NGU-UP-TNLInformation", "ngap.additionalDL_NGU_UP_TNLInformation",
        FT_UINT32, BASE_DEC, VALS(ngap_UPTransportLayerInformation_vals), 0,
        "UPTransportLayerInformation", HFILL }},
    { &hf_ngap_additionalQosFlowSetupResponseList,
      { "additionalQosFlowSetupResponseList", "ngap.additionalQosFlowSetupResponseList",
        FT_UINT32, BASE_DEC, NULL, 0,
        "QosFlowListWithDataForwarding", HFILL }},
    { &hf_ngap_additionalDLForwardingUPTNLInformation,
      { "additionalDLForwardingUPTNLInformation", "ngap.additionalDLForwardingUPTNLInformation",
        FT_UINT32, BASE_DEC, VALS(ngap_UPTransportLayerInformation_vals), 0,
        "UPTransportLayerInformation", HFILL }},
    { &hf_ngap_iE_Extensions,
      { "iE-Extensions", "ngap.iE_Extensions",
        FT_UINT32, BASE_DEC, NULL, 0,
        "ProtocolExtensionContainer", HFILL }},
    { &hf_ngap_priorityLevelARP,
      { "priorityLevelARP", "ngap.priorityLevelARP",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_ngap_pre_emptionCapability,
      { "pre-emptionCapability", "ngap.pre_emptionCapability",
        FT_UINT32, BASE_DEC, VALS(ngap_Pre_emptionCapability_vals), 0,
        NULL, HFILL }},
    { &hf_ngap_pre_emptionVulnerability,
      { "pre-emptionVulnerability", "ngap.pre_emptionVulnerability",
        FT_UINT32, BASE_DEC, VALS(ngap_Pre_emptionVulnerability_vals), 0,
        NULL, HFILL }},
    { &hf_ngap_AllowedNSSAI_item,
      { "AllowedNSSAI-Item", "ngap.AllowedNSSAI_Item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ngap_s_NSSAI,
      { "s-NSSAI", "ngap.s_NSSAI_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ngap_AllowedTACs_item,
      { "TAC", "ngap.TAC",
        FT_UINT24, BASE_DEC_HEX, NULL, 0,
        NULL, HFILL }},
    { &hf_ngap_globalRANNodeID,
      { "globalRANNodeID", "ngap.globalRANNodeID",
        FT_UINT32, BASE_DEC, VALS(ngap_GlobalRANNodeID_vals), 0,
        NULL, HFILL }},
    { &hf_ngap_tAI,
      { "tAI", "ngap.tAI_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ngap_choice_Extensions,
      { "choice-Extensions", "ngap.choice_Extensions_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "ProtocolIE_SingleContainer", HFILL }},
    { &hf_ngap_AMF_TNLAssociationSetupList_item,
      { "AMF-TNLAssociationSetupItem", "ngap.AMF_TNLAssociationSetupItem_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ngap_aMF_TNLAssociationAddress,
      { "aMF-TNLAssociationAddress", "ngap.aMF_TNLAssociationAddress",
        FT_UINT32, BASE_DEC, VALS(ngap_CPTransportLayerInformation_vals), 0,
        "CPTransportLayerInformation", HFILL }},
    { &hf_ngap_AMF_TNLAssociationToAddList_item,
      { "AMF-TNLAssociationToAddItem", "ngap.AMF_TNLAssociationToAddItem_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ngap_tNLAssociationUsage,
      { "tNLAssociationUsage", "ngap.tNLAssociationUsage",
        FT_UINT32, BASE_DEC, VALS(ngap_TNLAssociationUsage_vals), 0,
        NULL, HFILL }},
    { &hf_ngap_tNLAddressWeightFactor,
      { "tNLAddressWeightFactor", "ngap.tNLAddressWeightFactor",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_ngap_AMF_TNLAssociationToRemoveList_item,
      { "AMF-TNLAssociationToRemoveItem", "ngap.AMF_TNLAssociationToRemoveItem_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ngap_AMF_TNLAssociationToUpdateList_item,
      { "AMF-TNLAssociationToUpdateItem", "ngap.AMF_TNLAssociationToUpdateItem_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ngap_areaOfInterestTAIList,
      { "areaOfInterestTAIList", "ngap.areaOfInterestTAIList",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_ngap_areaOfInterestCellList,
      { "areaOfInterestCellList", "ngap.areaOfInterestCellList",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_ngap_areaOfInterestRANNodeList,
      { "areaOfInterestRANNodeList", "ngap.areaOfInterestRANNodeList",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_ngap_AreaOfInterestCellList_item,
      { "AreaOfInterestCellItem", "ngap.AreaOfInterestCellItem_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ngap_nGRAN_CGI,
      { "nGRAN-CGI", "ngap.nGRAN_CGI",
        FT_UINT32, BASE_DEC, VALS(ngap_NGRAN_CGI_vals), 0,
        NULL, HFILL }},
    { &hf_ngap_AreaOfInterestList_item,
      { "AreaOfInterestItem", "ngap.AreaOfInterestItem_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ngap_areaOfInterest,
      { "areaOfInterest", "ngap.areaOfInterest_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ngap_locationReportingReferenceID,
      { "locationReportingReferenceID", "ngap.locationReportingReferenceID",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_ngap_AreaOfInterestRANNodeList_item,
      { "AreaOfInterestRANNodeItem", "ngap.AreaOfInterestRANNodeItem_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ngap_AreaOfInterestTAIList_item,
      { "AreaOfInterestTAIItem", "ngap.AreaOfInterestTAIItem_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ngap_assistanceDataForRecommendedCells,
      { "assistanceDataForRecommendedCells", "ngap.assistanceDataForRecommendedCells_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ngap_pagingAttemptInformation,
      { "pagingAttemptInformation", "ngap.pagingAttemptInformation_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ngap_recommendedCellsForPaging,
      { "recommendedCellsForPaging", "ngap.recommendedCellsForPaging_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ngap_AssociatedQosFlowList_item,
      { "AssociatedQosFlowItem", "ngap.AssociatedQosFlowItem_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ngap_qosFlowIdentifier,
      { "qosFlowIdentifier", "ngap.qosFlowIdentifier",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_ngap_qosFlowMappingIndication,
      { "qosFlowMappingIndication", "ngap.qosFlowMappingIndication",
        FT_UINT32, BASE_DEC, VALS(ngap_T_qosFlowMappingIndication_vals), 0,
        NULL, HFILL }},
    { &hf_ngap_cellIDCancelledEUTRA,
      { "cellIDCancelledEUTRA", "ngap.cellIDCancelledEUTRA",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_ngap_tAICancelledEUTRA,
      { "tAICancelledEUTRA", "ngap.tAICancelledEUTRA",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_ngap_emergencyAreaIDCancelledEUTRA,
      { "emergencyAreaIDCancelledEUTRA", "ngap.emergencyAreaIDCancelledEUTRA",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_ngap_cellIDCancelledNR,
      { "cellIDCancelledNR", "ngap.cellIDCancelledNR",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_ngap_tAICancelledNR,
      { "tAICancelledNR", "ngap.tAICancelledNR",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_ngap_emergencyAreaIDCancelledNR,
      { "emergencyAreaIDCancelledNR", "ngap.emergencyAreaIDCancelledNR",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_ngap_cellIDBroadcastEUTRA,
      { "cellIDBroadcastEUTRA", "ngap.cellIDBroadcastEUTRA",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_ngap_tAIBroadcastEUTRA,
      { "tAIBroadcastEUTRA", "ngap.tAIBroadcastEUTRA",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_ngap_emergencyAreaIDBroadcastEUTRA,
      { "emergencyAreaIDBroadcastEUTRA", "ngap.emergencyAreaIDBroadcastEUTRA",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_ngap_cellIDBroadcastNR,
      { "cellIDBroadcastNR", "ngap.cellIDBroadcastNR",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_ngap_tAIBroadcastNR,
      { "tAIBroadcastNR", "ngap.tAIBroadcastNR",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_ngap_emergencyAreaIDBroadcastNR,
      { "emergencyAreaIDBroadcastNR", "ngap.emergencyAreaIDBroadcastNR",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_ngap_BroadcastPLMNList_item,
      { "BroadcastPLMNItem", "ngap.BroadcastPLMNItem_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ngap_pLMNIdentity,
      { "pLMNIdentity", "ngap.pLMNIdentity",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ngap_tAISliceSupportList,
      { "tAISliceSupportList", "ngap.tAISliceSupportList",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SliceSupportList", HFILL }},
    { &hf_ngap_CancelledCellsInEAI_EUTRA_item,
      { "CancelledCellsInEAI-EUTRA-Item", "ngap.CancelledCellsInEAI_EUTRA_Item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ngap_eUTRA_CGI,
      { "eUTRA-CGI", "ngap.eUTRA_CGI_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ngap_numberOfBroadcasts,
      { "numberOfBroadcasts", "ngap.numberOfBroadcasts",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_ngap_CancelledCellsInEAI_NR_item,
      { "CancelledCellsInEAI-NR-Item", "ngap.CancelledCellsInEAI_NR_Item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ngap_nR_CGI,
      { "nR-CGI", "ngap.nR_CGI_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ngap_CancelledCellsInTAI_EUTRA_item,
      { "CancelledCellsInTAI-EUTRA-Item", "ngap.CancelledCellsInTAI_EUTRA_Item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ngap_CancelledCellsInTAI_NR_item,
      { "CancelledCellsInTAI-NR-Item", "ngap.CancelledCellsInTAI_NR_Item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ngap_radioNetwork,
      { "radioNetwork", "ngap.radioNetwork",
        FT_UINT32, BASE_DEC|BASE_EXT_STRING, &ngap_CauseRadioNetwork_vals_ext, 0,
        "CauseRadioNetwork", HFILL }},
    { &hf_ngap_transport,
      { "transport", "ngap.transport",
        FT_UINT32, BASE_DEC, VALS(ngap_CauseTransport_vals), 0,
        "CauseTransport", HFILL }},
    { &hf_ngap_nas,
      { "nas", "ngap.nas",
        FT_UINT32, BASE_DEC, VALS(ngap_CauseNas_vals), 0,
        "CauseNas", HFILL }},
    { &hf_ngap_protocol,
      { "protocol", "ngap.protocol",
        FT_UINT32, BASE_DEC, VALS(ngap_CauseProtocol_vals), 0,
        "CauseProtocol", HFILL }},
    { &hf_ngap_misc,
      { "misc", "ngap.misc",
        FT_UINT32, BASE_DEC, VALS(ngap_CauseMisc_vals), 0,
        "CauseMisc", HFILL }},
    { &hf_ngap_CellIDBroadcastEUTRA_item,
      { "CellIDBroadcastEUTRA-Item", "ngap.CellIDBroadcastEUTRA_Item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ngap_CellIDBroadcastNR_item,
      { "CellIDBroadcastNR-Item", "ngap.CellIDBroadcastNR_Item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ngap_CellIDCancelledEUTRA_item,
      { "CellIDCancelledEUTRA-Item", "ngap.CellIDCancelledEUTRA_Item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ngap_CellIDCancelledNR_item,
      { "CellIDCancelledNR-Item", "ngap.CellIDCancelledNR_Item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ngap_eUTRA_CGIListforRestart,
      { "eUTRA-CGIListforRestart", "ngap.eUTRA_CGIListforRestart",
        FT_UINT32, BASE_DEC, NULL, 0,
        "EUTRA_CGIList", HFILL }},
    { &hf_ngap_nR_CGIListforRestart,
      { "nR-CGIListforRestart", "ngap.nR_CGIListforRestart",
        FT_UINT32, BASE_DEC, NULL, 0,
        "NR_CGIList", HFILL }},
    { &hf_ngap_cellSize,
      { "cellSize", "ngap.cellSize",
        FT_UINT32, BASE_DEC, VALS(ngap_CellSize_vals), 0,
        NULL, HFILL }},
    { &hf_ngap_expectedUEBehaviour,
      { "expectedUEBehaviour", "ngap.expectedUEBehaviour_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ngap_CNTypeRestrictionsForEquivalent_item,
      { "CNTypeRestrictionsForEquivalentItem", "ngap.CNTypeRestrictionsForEquivalentItem_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ngap_plmnIdentity,
      { "plmnIdentity", "ngap.plmnIdentity",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ngap_cn_Type,
      { "cn-Type", "ngap.cn_Type",
        FT_UINT32, BASE_DEC, VALS(ngap_T_cn_Type_vals), 0,
        NULL, HFILL }},
    { &hf_ngap_CompletedCellsInEAI_EUTRA_item,
      { "CompletedCellsInEAI-EUTRA-Item", "ngap.CompletedCellsInEAI_EUTRA_Item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ngap_CompletedCellsInEAI_NR_item,
      { "CompletedCellsInEAI-NR-Item", "ngap.CompletedCellsInEAI_NR_Item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ngap_CompletedCellsInTAI_EUTRA_item,
      { "CompletedCellsInTAI-EUTRA-Item", "ngap.CompletedCellsInTAI_EUTRA_Item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ngap_CompletedCellsInTAI_NR_item,
      { "CompletedCellsInTAI-NR-Item", "ngap.CompletedCellsInTAI_NR_Item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ngap_uEIdentityIndexValue,
      { "uEIdentityIndexValue", "ngap.uEIdentityIndexValue",
        FT_UINT32, BASE_DEC, VALS(ngap_UEIdentityIndexValue_vals), 0,
        NULL, HFILL }},
    { &hf_ngap_uESpecificDRX,
      { "uESpecificDRX", "ngap.uESpecificDRX",
        FT_UINT32, BASE_DEC, VALS(ngap_PagingDRX_vals), 0,
        "PagingDRX", HFILL }},
    { &hf_ngap_periodicRegistrationUpdateTimer,
      { "periodicRegistrationUpdateTimer", "ngap.periodicRegistrationUpdateTimer",
        FT_UINT8, BASE_CUSTOM, CF_FUNC(ngap_PeriodicRegistrationUpdateTimer_fmt), 0,
        NULL, HFILL }},
    { &hf_ngap_mICOModeIndication,
      { "mICOModeIndication", "ngap.mICOModeIndication",
        FT_UINT32, BASE_DEC, VALS(ngap_MICOModeIndication_vals), 0,
        NULL, HFILL }},
    { &hf_ngap_tAIListForInactive,
      { "tAIListForInactive", "ngap.tAIListForInactive",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_ngap_pDCP_SN12,
      { "pDCP-SN12", "ngap.pDCP_SN12",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_4095", HFILL }},
    { &hf_ngap_hFN_PDCP_SN12,
      { "hFN-PDCP-SN12", "ngap.hFN_PDCP_SN12",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_1048575", HFILL }},
    { &hf_ngap_pDCP_SN18,
      { "pDCP-SN18", "ngap.pDCP_SN18",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_262143", HFILL }},
    { &hf_ngap_hFN_PDCP_SN18,
      { "hFN-PDCP-SN18", "ngap.hFN_PDCP_SN18",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_16383", HFILL }},
    { &hf_ngap_endpointIPAddress,
      { "endpointIPAddress", "ngap.endpointIPAddress",
        FT_BYTES, BASE_NONE, NULL, 0,
        "TransportLayerAddress", HFILL }},
    { &hf_ngap_procedureCode,
      { "procedureCode", "ngap.procedureCode",
        FT_UINT32, BASE_DEC|BASE_EXT_STRING, &ngap_ProcedureCode_vals_ext, 0,
        NULL, HFILL }},
    { &hf_ngap_triggeringMessage,
      { "triggeringMessage", "ngap.triggeringMessage",
        FT_UINT32, BASE_DEC, VALS(ngap_TriggeringMessage_vals), 0,
        NULL, HFILL }},
    { &hf_ngap_procedureCriticality,
      { "procedureCriticality", "ngap.procedureCriticality",
        FT_UINT32, BASE_DEC, VALS(ngap_Criticality_vals), 0,
        "Criticality", HFILL }},
    { &hf_ngap_iEsCriticalityDiagnostics,
      { "iEsCriticalityDiagnostics", "ngap.iEsCriticalityDiagnostics",
        FT_UINT32, BASE_DEC, NULL, 0,
        "CriticalityDiagnostics_IE_List", HFILL }},
    { &hf_ngap_CriticalityDiagnostics_IE_List_item,
      { "CriticalityDiagnostics-IE-Item", "ngap.CriticalityDiagnostics_IE_Item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ngap_iECriticality,
      { "iECriticality", "ngap.iECriticality",
        FT_UINT32, BASE_DEC, VALS(ngap_Criticality_vals), 0,
        "Criticality", HFILL }},
    { &hf_ngap_iE_ID,
      { "iE-ID", "ngap.iE_ID",
        FT_UINT32, BASE_DEC|BASE_EXT_STRING, &ngap_ProtocolIE_ID_vals_ext, 0,
        "ProtocolIE_ID", HFILL }},
    { &hf_ngap_typeOfError,
      { "typeOfError", "ngap.typeOfError",
        FT_UINT32, BASE_DEC, VALS(ngap_TypeOfError_vals), 0,
        NULL, HFILL }},
    { &hf_ngap_DataForwardingResponseDRBList_item,
      { "DataForwardingResponseDRBItem", "ngap.DataForwardingResponseDRBItem_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ngap_dRB_ID,
      { "dRB-ID", "ngap.dRB_ID",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_ngap_dLForwardingUP_TNLInformation,
      { "dLForwardingUP-TNLInformation", "ngap.dLForwardingUP_TNLInformation",
        FT_UINT32, BASE_DEC, VALS(ngap_UPTransportLayerInformation_vals), 0,
        "UPTransportLayerInformation", HFILL }},
    { &hf_ngap_uLForwardingUP_TNLInformation,
      { "uLForwardingUP-TNLInformation", "ngap.uLForwardingUP_TNLInformation",
        FT_UINT32, BASE_DEC, VALS(ngap_UPTransportLayerInformation_vals), 0,
        "UPTransportLayerInformation", HFILL }},
    { &hf_ngap_DRBsSubjectToStatusTransferList_item,
      { "DRBsSubjectToStatusTransferItem", "ngap.DRBsSubjectToStatusTransferItem_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ngap_dRBStatusUL,
      { "dRBStatusUL", "ngap.dRBStatusUL",
        FT_UINT32, BASE_DEC, VALS(ngap_DRBStatusUL_vals), 0,
        NULL, HFILL }},
    { &hf_ngap_dRBStatusDL,
      { "dRBStatusDL", "ngap.dRBStatusDL",
        FT_UINT32, BASE_DEC, VALS(ngap_DRBStatusDL_vals), 0,
        NULL, HFILL }},
    { &hf_ngap_iE_Extension,
      { "iE-Extension", "ngap.iE_Extension",
        FT_UINT32, BASE_DEC, NULL, 0,
        "ProtocolExtensionContainer", HFILL }},
    { &hf_ngap_dRBStatusDL12,
      { "dRBStatusDL12", "ngap.dRBStatusDL12_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ngap_dRBStatusDL18,
      { "dRBStatusDL18", "ngap.dRBStatusDL18_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ngap_dL_COUNTValue,
      { "dL-COUNTValue", "ngap.dL_COUNTValue_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "COUNTValueForPDCP_SN12", HFILL }},
    { &hf_ngap_dL_COUNTValue_01,
      { "dL-COUNTValue", "ngap.dL_COUNTValue_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "COUNTValueForPDCP_SN18", HFILL }},
    { &hf_ngap_dRBStatusUL12,
      { "dRBStatusUL12", "ngap.dRBStatusUL12_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ngap_dRBStatusUL18,
      { "dRBStatusUL18", "ngap.dRBStatusUL18_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ngap_uL_COUNTValue,
      { "uL-COUNTValue", "ngap.uL_COUNTValue_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "COUNTValueForPDCP_SN12", HFILL }},
    { &hf_ngap_receiveStatusOfUL_PDCP_SDUs,
      { "receiveStatusOfUL-PDCP-SDUs", "ngap.receiveStatusOfUL_PDCP_SDUs",
        FT_BYTES, BASE_NONE, NULL, 0,
        "BIT_STRING_SIZE_1_2048", HFILL }},
    { &hf_ngap_uL_COUNTValue_01,
      { "uL-COUNTValue", "ngap.uL_COUNTValue_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "COUNTValueForPDCP_SN18", HFILL }},
    { &hf_ngap_receiveStatusOfUL_PDCP_SDUs_01,
      { "receiveStatusOfUL-PDCP-SDUs", "ngap.receiveStatusOfUL_PDCP_SDUs",
        FT_BYTES, BASE_NONE, NULL, 0,
        "BIT_STRING_SIZE_1_131072", HFILL }},
    { &hf_ngap_DRBsToQosFlowsMappingList_item,
      { "DRBsToQosFlowsMappingItem", "ngap.DRBsToQosFlowsMappingItem_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ngap_associatedQosFlowList,
      { "associatedQosFlowList", "ngap.associatedQosFlowList",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_ngap_priorityLevelQos,
      { "priorityLevelQos", "ngap.priorityLevelQos",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_ngap_packetDelayBudget,
      { "packetDelayBudget", "ngap.packetDelayBudget",
        FT_UINT32, BASE_CUSTOM, CF_FUNC(ngap_PacketDelayBudget_fmt), 0,
        NULL, HFILL }},
    { &hf_ngap_packetErrorRate,
      { "packetErrorRate", "ngap.packetErrorRate_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ngap_fiveQI,
      { "fiveQI", "ngap.fiveQI",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_ngap_delayCritical,
      { "delayCritical", "ngap.delayCritical",
        FT_UINT32, BASE_DEC, VALS(ngap_DelayCritical_vals), 0,
        NULL, HFILL }},
    { &hf_ngap_averagingWindow,
      { "averagingWindow", "ngap.averagingWindow",
        FT_UINT32, BASE_DEC|BASE_UNIT_STRING, &units_milliseconds, 0,
        NULL, HFILL }},
    { &hf_ngap_maximumDataBurstVolume,
      { "maximumDataBurstVolume", "ngap.maximumDataBurstVolume",
        FT_UINT32, BASE_DEC|BASE_UNIT_STRING, &units_byte_bytes, 0,
        NULL, HFILL }},
    { &hf_ngap_EmergencyAreaIDBroadcastEUTRA_item,
      { "EmergencyAreaIDBroadcastEUTRA-Item", "ngap.EmergencyAreaIDBroadcastEUTRA_Item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ngap_emergencyAreaID,
      { "emergencyAreaID", "ngap.emergencyAreaID",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ngap_completedCellsInEAI_EUTRA,
      { "completedCellsInEAI-EUTRA", "ngap.completedCellsInEAI_EUTRA",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_ngap_EmergencyAreaIDBroadcastNR_item,
      { "EmergencyAreaIDBroadcastNR-Item", "ngap.EmergencyAreaIDBroadcastNR_Item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ngap_completedCellsInEAI_NR,
      { "completedCellsInEAI-NR", "ngap.completedCellsInEAI_NR",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_ngap_EmergencyAreaIDCancelledEUTRA_item,
      { "EmergencyAreaIDCancelledEUTRA-Item", "ngap.EmergencyAreaIDCancelledEUTRA_Item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ngap_cancelledCellsInEAI_EUTRA,
      { "cancelledCellsInEAI-EUTRA", "ngap.cancelledCellsInEAI_EUTRA",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_ngap_EmergencyAreaIDCancelledNR_item,
      { "EmergencyAreaIDCancelledNR-Item", "ngap.EmergencyAreaIDCancelledNR_Item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ngap_cancelledCellsInEAI_NR,
      { "cancelledCellsInEAI-NR", "ngap.cancelledCellsInEAI_NR",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_ngap_EmergencyAreaIDList_item,
      { "EmergencyAreaID", "ngap.EmergencyAreaID",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ngap_EmergencyAreaIDListForRestart_item,
      { "EmergencyAreaID", "ngap.EmergencyAreaID",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ngap_emergencyFallbackRequestIndicator,
      { "emergencyFallbackRequestIndicator", "ngap.emergencyFallbackRequestIndicator",
        FT_UINT32, BASE_DEC, VALS(ngap_EmergencyFallbackRequestIndicator_vals), 0,
        NULL, HFILL }},
    { &hf_ngap_emergencyServiceTargetCN,
      { "emergencyServiceTargetCN", "ngap.emergencyServiceTargetCN",
        FT_UINT32, BASE_DEC, VALS(ngap_EmergencyServiceTargetCN_vals), 0,
        NULL, HFILL }},
    { &hf_ngap_portNumber,
      { "portNumber", "ngap.portNumber",
        FT_UINT16, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_ngap_EquivalentPLMNs_item,
      { "PLMNIdentity", "ngap.PLMNIdentity",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ngap_ePS_TAC,
      { "ePS-TAC", "ngap.ePS_TAC",
        FT_UINT16, BASE_DEC_HEX, NULL, 0,
        NULL, HFILL }},
    { &hf_ngap_E_RABInformationList_item,
      { "E-RABInformationItem", "ngap.E_RABInformationItem_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ngap_e_RAB_ID,
      { "e-RAB-ID", "ngap.e_RAB_ID",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_ngap_dLForwarding,
      { "dLForwarding", "ngap.dLForwarding",
        FT_UINT32, BASE_DEC, VALS(ngap_DLForwarding_vals), 0,
        NULL, HFILL }},
    { &hf_ngap_eUTRACellIdentity,
      { "eUTRACellIdentity", "ngap.EUTRACellIdentity",
        FT_UINT32, BASE_HEX, NULL, 0,
        NULL, HFILL }},
    { &hf_ngap_EUTRA_CGIList_item,
      { "EUTRA-CGI", "ngap.EUTRA_CGI_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ngap_EUTRA_CGIListForWarning_item,
      { "EUTRA-CGI", "ngap.EUTRA_CGI_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ngap_expectedActivityPeriod,
      { "expectedActivityPeriod", "ngap.expectedActivityPeriod",
        FT_UINT32, BASE_DEC|BASE_UNIT_STRING, &units_seconds, 0,
        NULL, HFILL }},
    { &hf_ngap_expectedIdlePeriod,
      { "expectedIdlePeriod", "ngap.expectedIdlePeriod",
        FT_UINT32, BASE_DEC|BASE_UNIT_STRING, &units_seconds, 0,
        NULL, HFILL }},
    { &hf_ngap_sourceOfUEActivityBehaviourInformation,
      { "sourceOfUEActivityBehaviourInformation", "ngap.sourceOfUEActivityBehaviourInformation",
        FT_UINT32, BASE_DEC, VALS(ngap_SourceOfUEActivityBehaviourInformation_vals), 0,
        NULL, HFILL }},
    { &hf_ngap_expectedUEActivityBehaviour,
      { "expectedUEActivityBehaviour", "ngap.expectedUEActivityBehaviour_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ngap_expectedHOInterval,
      { "expectedHOInterval", "ngap.expectedHOInterval",
        FT_UINT32, BASE_DEC, VALS(ngap_ExpectedHOInterval_vals), 0,
        NULL, HFILL }},
    { &hf_ngap_expectedUEMobility,
      { "expectedUEMobility", "ngap.expectedUEMobility",
        FT_UINT32, BASE_DEC, VALS(ngap_ExpectedUEMobility_vals), 0,
        NULL, HFILL }},
    { &hf_ngap_expectedUEMovingTrajectory,
      { "expectedUEMovingTrajectory", "ngap.expectedUEMovingTrajectory",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_ngap_ExpectedUEMovingTrajectory_item,
      { "ExpectedUEMovingTrajectoryItem", "ngap.ExpectedUEMovingTrajectoryItem_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ngap_timeStayedInCell,
      { "timeStayedInCell", "ngap.timeStayedInCell",
        FT_UINT32, BASE_DEC|BASE_UNIT_STRING, &units_seconds, 0,
        "INTEGER_0_4095", HFILL }},
    { &hf_ngap_aMFSetID,
      { "aMFSetID", "ngap.aMFSetID",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ngap_aMFPointer,
      { "aMFPointer", "ngap.aMFPointer",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ngap_fiveG_TMSI,
      { "fiveG-TMSI", "ngap.fiveG_TMSI",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ngap_ForbiddenAreaInformation_item,
      { "ForbiddenAreaInformation-Item", "ngap.ForbiddenAreaInformation_Item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ngap_forbiddenTACs,
      { "forbiddenTACs", "ngap.forbiddenTACs",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_ngap_ForbiddenTACs_item,
      { "TAC", "ngap.TAC",
        FT_UINT24, BASE_DEC_HEX, NULL, 0,
        NULL, HFILL }},
    { &hf_ngap_maximumFlowBitRateDL,
      { "maximumFlowBitRateDL", "ngap.maximumFlowBitRateDL",
        FT_UINT64, BASE_DEC|BASE_UNIT_STRING, &units_bit_sec, 0,
        "BitRate", HFILL }},
    { &hf_ngap_maximumFlowBitRateUL,
      { "maximumFlowBitRateUL", "ngap.maximumFlowBitRateUL",
        FT_UINT64, BASE_DEC|BASE_UNIT_STRING, &units_bit_sec, 0,
        "BitRate", HFILL }},
    { &hf_ngap_guaranteedFlowBitRateDL,
      { "guaranteedFlowBitRateDL", "ngap.guaranteedFlowBitRateDL",
        FT_UINT64, BASE_DEC|BASE_UNIT_STRING, &units_bit_sec, 0,
        "BitRate", HFILL }},
    { &hf_ngap_guaranteedFlowBitRateUL,
      { "guaranteedFlowBitRateUL", "ngap.guaranteedFlowBitRateUL",
        FT_UINT64, BASE_DEC|BASE_UNIT_STRING, &units_bit_sec, 0,
        "BitRate", HFILL }},
    { &hf_ngap_notificationControl,
      { "notificationControl", "ngap.notificationControl",
        FT_UINT32, BASE_DEC, VALS(ngap_NotificationControl_vals), 0,
        NULL, HFILL }},
    { &hf_ngap_maximumPacketLossRateDL,
      { "maximumPacketLossRateDL", "ngap.maximumPacketLossRateDL",
        FT_UINT32, BASE_CUSTOM, CF_FUNC(ngap_PacketLossRate_fmt), 0,
        "PacketLossRate", HFILL }},
    { &hf_ngap_maximumPacketLossRateUL,
      { "maximumPacketLossRateUL", "ngap.maximumPacketLossRateUL",
        FT_UINT32, BASE_CUSTOM, CF_FUNC(ngap_PacketLossRate_fmt), 0,
        "PacketLossRate", HFILL }},
    { &hf_ngap_gNB_ID,
      { "gNB-ID", "ngap.gNB_ID",
        FT_UINT32, BASE_DEC, VALS(ngap_GNB_ID_vals), 0,
        NULL, HFILL }},
    { &hf_ngap_n3IWF_ID,
      { "n3IWF-ID", "ngap.n3IWF_ID",
        FT_UINT32, BASE_DEC, VALS(ngap_N3IWF_ID_vals), 0,
        NULL, HFILL }},
    { &hf_ngap_ngENB_ID,
      { "ngENB-ID", "ngap.ngENB_ID",
        FT_UINT32, BASE_DEC, VALS(ngap_NgENB_ID_vals), 0,
        NULL, HFILL }},
    { &hf_ngap_globalGNB_ID,
      { "globalGNB-ID", "ngap.globalGNB_ID_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ngap_globalNgENB_ID,
      { "globalNgENB-ID", "ngap.globalNgENB_ID_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ngap_globalN3IWF_ID,
      { "globalN3IWF-ID", "ngap.globalN3IWF_ID_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ngap_gNB_ID_01,
      { "gNB-ID", "ngap.gNB_ID",
        FT_BYTES, BASE_NONE, NULL, 0,
        "BIT_STRING_SIZE_22_32", HFILL }},
    { &hf_ngap_transportLayerAddress,
      { "transportLayerAddress", "ngap.transportLayerAddress",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ngap_gTP_TEID,
      { "gTP-TEID", "ngap.gTP_TEID",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ngap_aMFRegionID,
      { "aMFRegionID", "ngap.aMFRegionID",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ngap_qosFlowToBeForwardedList,
      { "qosFlowToBeForwardedList", "ngap.qosFlowToBeForwardedList",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_ngap_dataForwardingResponseDRBList,
      { "dataForwardingResponseDRBList", "ngap.dataForwardingResponseDRBList",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_ngap_cause,
      { "cause", "ngap.cause",
        FT_UINT32, BASE_DEC, VALS(ngap_Cause_vals), 0,
        NULL, HFILL }},
    { &hf_ngap_dL_NGU_UP_TNLInformation,
      { "dL-NGU-UP-TNLInformation", "ngap.dL_NGU_UP_TNLInformation",
        FT_UINT32, BASE_DEC, VALS(ngap_UPTransportLayerInformation_vals), 0,
        "UPTransportLayerInformation", HFILL }},
    { &hf_ngap_securityResult,
      { "securityResult", "ngap.securityResult_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ngap_qosFlowSetupResponseList,
      { "qosFlowSetupResponseList", "ngap.qosFlowSetupResponseList",
        FT_UINT32, BASE_DEC, NULL, 0,
        "QosFlowListWithDataForwarding", HFILL }},
    { &hf_ngap_qosFlowFailedToSetupList,
      { "qosFlowFailedToSetupList", "ngap.qosFlowFailedToSetupList",
        FT_UINT32, BASE_DEC, NULL, 0,
        "QosFlowListWithCause", HFILL }},
    { &hf_ngap_directForwardingPathAvailability,
      { "directForwardingPathAvailability", "ngap.directForwardingPathAvailability",
        FT_UINT32, BASE_DEC, VALS(ngap_DirectForwardingPathAvailability_vals), 0,
        NULL, HFILL }},
    { &hf_ngap_criticalityDiagnostics,
      { "criticalityDiagnostics", "ngap.criticalityDiagnostics_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ngap_recommendRANNodesForPaging,
      { "recommendRANNodesForPaging", "ngap.recommendRANNodesForPaging_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "RecommendedRANNodesForPaging", HFILL }},
    { &hf_ngap_nGRANCell,
      { "nGRANCell", "ngap.nGRANCell_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "LastVisitedNGRANCellInformation", HFILL }},
    { &hf_ngap_eUTRANCell,
      { "eUTRANCell", "ngap.eUTRANCell",
        FT_BYTES, BASE_NONE, NULL, 0,
        "LastVisitedEUTRANCellInformation", HFILL }},
    { &hf_ngap_uTRANCell,
      { "uTRANCell", "ngap.uTRANCell",
        FT_BYTES, BASE_NONE, NULL, 0,
        "LastVisitedUTRANCellInformation", HFILL }},
    { &hf_ngap_gERANCell,
      { "gERANCell", "ngap.gERANCell",
        FT_BYTES, BASE_NONE, NULL, 0,
        "LastVisitedGERANCellInformation", HFILL }},
    { &hf_ngap_lastVisitedCellInformation,
      { "lastVisitedCellInformation", "ngap.lastVisitedCellInformation",
        FT_UINT32, BASE_DEC, VALS(ngap_LastVisitedCellInformation_vals), 0,
        NULL, HFILL }},
    { &hf_ngap_globalCellID,
      { "globalCellID", "ngap.globalCellID",
        FT_UINT32, BASE_DEC, VALS(ngap_NGRAN_CGI_vals), 0,
        "NGRAN_CGI", HFILL }},
    { &hf_ngap_cellType,
      { "cellType", "ngap.cellType_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ngap_timeUEStayedInCell,
      { "timeUEStayedInCell", "ngap.timeUEStayedInCell",
        FT_UINT32, BASE_DEC|BASE_UNIT_STRING, &units_seconds, 0,
        NULL, HFILL }},
    { &hf_ngap_timeUEStayedInCellEnhancedGranularity,
      { "timeUEStayedInCellEnhancedGranularity", "ngap.timeUEStayedInCellEnhancedGranularity",
        FT_UINT32, BASE_CUSTOM, CF_FUNC(ngap_TimeUEStayedInCellEnhancedGranularity_fmt), 0,
        NULL, HFILL }},
    { &hf_ngap_hOCauseValue,
      { "hOCauseValue", "ngap.hOCauseValue",
        FT_UINT32, BASE_DEC, VALS(ngap_Cause_vals), 0,
        "Cause", HFILL }},
    { &hf_ngap_eventType,
      { "eventType", "ngap.eventType",
        FT_UINT32, BASE_DEC, VALS(ngap_EventType_vals), 0,
        NULL, HFILL }},
    { &hf_ngap_reportArea,
      { "reportArea", "ngap.reportArea",
        FT_UINT32, BASE_DEC, VALS(ngap_ReportArea_vals), 0,
        NULL, HFILL }},
    { &hf_ngap_areaOfInterestList,
      { "areaOfInterestList", "ngap.areaOfInterestList",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_ngap_locationReportingReferenceIDToBeCancelled,
      { "locationReportingReferenceIDToBeCancelled", "ngap.locationReportingReferenceIDToBeCancelled",
        FT_UINT32, BASE_DEC, NULL, 0,
        "LocationReportingReferenceID", HFILL }},
    { &hf_ngap_servingPLMN,
      { "servingPLMN", "ngap.servingPLMN",
        FT_BYTES, BASE_NONE, NULL, 0,
        "PLMNIdentity", HFILL }},
    { &hf_ngap_equivalentPLMNs,
      { "equivalentPLMNs", "ngap.equivalentPLMNs",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_ngap_rATRestrictions,
      { "rATRestrictions", "ngap.rATRestrictions",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_ngap_forbiddenAreaInformation,
      { "forbiddenAreaInformation", "ngap.forbiddenAreaInformation",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_ngap_serviceAreaInformation,
      { "serviceAreaInformation", "ngap.serviceAreaInformation",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_ngap_n3IWF_ID_01,
      { "n3IWF-ID", "ngap.n3IWF_ID",
        FT_BYTES, BASE_NONE, NULL, 0,
        "BIT_STRING_SIZE_16", HFILL }},
    { &hf_ngap_macroNgENB_ID,
      { "macroNgENB-ID", "ngap.macroNgENB_ID",
        FT_BYTES, BASE_NONE, NULL, 0,
        "BIT_STRING_SIZE_20", HFILL }},
    { &hf_ngap_shortMacroNgENB_ID,
      { "shortMacroNgENB-ID", "ngap.shortMacroNgENB_ID",
        FT_BYTES, BASE_NONE, NULL, 0,
        "BIT_STRING_SIZE_18", HFILL }},
    { &hf_ngap_longMacroNgENB_ID,
      { "longMacroNgENB-ID", "ngap.longMacroNgENB_ID",
        FT_BYTES, BASE_NONE, NULL, 0,
        "BIT_STRING_SIZE_21", HFILL }},
    { &hf_ngap_NGRAN_TNLAssociationToRemoveList_item,
      { "NGRAN-TNLAssociationToRemoveItem", "ngap.NGRAN_TNLAssociationToRemoveItem_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ngap_tNLAssociationTransportLayerAddress,
      { "tNLAssociationTransportLayerAddress", "ngap.tNLAssociationTransportLayerAddress",
        FT_UINT32, BASE_DEC, VALS(ngap_CPTransportLayerInformation_vals), 0,
        "CPTransportLayerInformation", HFILL }},
    { &hf_ngap_tNLAssociationTransportLayerAddressAMF,
      { "tNLAssociationTransportLayerAddressAMF", "ngap.tNLAssociationTransportLayerAddressAMF",
        FT_UINT32, BASE_DEC, VALS(ngap_CPTransportLayerInformation_vals), 0,
        "CPTransportLayerInformation", HFILL }},
    { &hf_ngap_NotAllowedTACs_item,
      { "TAC", "ngap.TAC",
        FT_UINT24, BASE_DEC_HEX, NULL, 0,
        NULL, HFILL }},
    { &hf_ngap_nRCellIdentity,
      { "nRCellIdentity", "ngap.NRCellIdentity",
        FT_UINT40, BASE_HEX, NULL, 0,
        NULL, HFILL }},
    { &hf_ngap_NR_CGIList_item,
      { "NR-CGI", "ngap.NR_CGI_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ngap_NR_CGIListForWarning_item,
      { "NR-CGI", "ngap.NR_CGI_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ngap_overloadAction,
      { "overloadAction", "ngap.overloadAction",
        FT_UINT32, BASE_DEC, VALS(ngap_OverloadAction_vals), 0,
        NULL, HFILL }},
    { &hf_ngap_OverloadStartNSSAIList_item,
      { "OverloadStartNSSAIItem", "ngap.OverloadStartNSSAIItem_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ngap_sliceOverloadList,
      { "sliceOverloadList", "ngap.sliceOverloadList",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_ngap_sliceOverloadResponse,
      { "sliceOverloadResponse", "ngap.sliceOverloadResponse",
        FT_UINT32, BASE_DEC, VALS(ngap_OverloadResponse_vals), 0,
        "OverloadResponse", HFILL }},
    { &hf_ngap_sliceTrafficLoadReductionIndication,
      { "sliceTrafficLoadReductionIndication", "ngap.sliceTrafficLoadReductionIndication",
        FT_UINT32, BASE_DEC|BASE_UNIT_STRING, &units_percent, 0,
        "TrafficLoadReductionIndication", HFILL }},
    { &hf_ngap_pERScalar,
      { "pERScalar", "ngap.pERScalar",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_9_", HFILL }},
    { &hf_ngap_pERExponent,
      { "pERExponent", "ngap.pERExponent",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_9_", HFILL }},
    { &hf_ngap_pagingAttemptCount,
      { "pagingAttemptCount", "ngap.pagingAttemptCount",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_ngap_intendedNumberOfPagingAttempts,
      { "intendedNumberOfPagingAttempts", "ngap.intendedNumberOfPagingAttempts",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_ngap_nextPagingAreaScope,
      { "nextPagingAreaScope", "ngap.nextPagingAreaScope",
        FT_UINT32, BASE_DEC, VALS(ngap_NextPagingAreaScope_vals), 0,
        NULL, HFILL }},
    { &hf_ngap_uL_NGU_UP_TNLInformation,
      { "uL-NGU-UP-TNLInformation", "ngap.uL_NGU_UP_TNLInformation",
        FT_UINT32, BASE_DEC, VALS(ngap_UPTransportLayerInformation_vals), 0,
        "UPTransportLayerInformation", HFILL }},
    { &hf_ngap_securityIndication,
      { "securityIndication", "ngap.securityIndication_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ngap_dL_NGU_TNLInformationReused,
      { "dL-NGU-TNLInformationReused", "ngap.dL_NGU_TNLInformationReused",
        FT_UINT32, BASE_DEC, VALS(ngap_DL_NGU_TNLInformationReused_vals), 0,
        NULL, HFILL }},
    { &hf_ngap_userPlaneSecurityInformation,
      { "userPlaneSecurityInformation", "ngap.userPlaneSecurityInformation_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ngap_qosFlowAcceptedList,
      { "qosFlowAcceptedList", "ngap.qosFlowAcceptedList",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_ngap_pDUSessionAggregateMaximumBitRateDL,
      { "pDUSessionAggregateMaximumBitRateDL", "ngap.pDUSessionAggregateMaximumBitRateDL",
        FT_UINT64, BASE_DEC|BASE_UNIT_STRING, &units_bit_sec, 0,
        "BitRate", HFILL }},
    { &hf_ngap_pDUSessionAggregateMaximumBitRateUL,
      { "pDUSessionAggregateMaximumBitRateUL", "ngap.pDUSessionAggregateMaximumBitRateUL",
        FT_UINT64, BASE_DEC|BASE_UNIT_STRING, &units_bit_sec, 0,
        "BitRate", HFILL }},
    { &hf_ngap_PDUSessionResourceAdmittedList_item,
      { "PDUSessionResourceAdmittedItem", "ngap.PDUSessionResourceAdmittedItem_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ngap_pDUSessionID,
      { "pDUSessionID", "ngap.pDUSessionID",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_ngap_handoverRequestAcknowledgeTransfer,
      { "handoverRequestAcknowledgeTransfer", "ngap.handoverRequestAcknowledgeTransfer",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ngap_PDUSessionResourceFailedToModifyListModCfm_item,
      { "PDUSessionResourceFailedToModifyItemModCfm", "ngap.PDUSessionResourceFailedToModifyItemModCfm_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ngap_pDUSessionResourceModifyIndicationUnsuccessfulTransfer,
      { "pDUSessionResourceModifyIndicationUnsuccessfulTransfer", "ngap.pDUSessionResourceModifyIndicationUnsuccessfulTransfer",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ngap_PDUSessionResourceFailedToModifyListModRes_item,
      { "PDUSessionResourceFailedToModifyItemModRes", "ngap.PDUSessionResourceFailedToModifyItemModRes_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ngap_pDUSessionResourceModifyUnsuccessfulTransfer,
      { "pDUSessionResourceModifyUnsuccessfulTransfer", "ngap.pDUSessionResourceModifyUnsuccessfulTransfer",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ngap_PDUSessionResourceFailedToSetupListCxtFail_item,
      { "PDUSessionResourceFailedToSetupItemCxtFail", "ngap.PDUSessionResourceFailedToSetupItemCxtFail_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ngap_pDUSessionResourceSetupUnsuccessfulTransfer,
      { "pDUSessionResourceSetupUnsuccessfulTransfer", "ngap.pDUSessionResourceSetupUnsuccessfulTransfer",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ngap_PDUSessionResourceFailedToSetupListCxtRes_item,
      { "PDUSessionResourceFailedToSetupItemCxtRes", "ngap.PDUSessionResourceFailedToSetupItemCxtRes_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ngap_pDUSessionResourceSetupUnsuccessfulTransfer_01,
      { "pDUSessionResourceSetupUnsuccessfulTransfer", "ngap.pDUSessionResourceSetupUnsuccessfulTransfer",
        FT_BYTES, BASE_NONE, NULL, 0,
        "T_pDUSessionResourceSetupUnsuccessfulTransfer_01", HFILL }},
    { &hf_ngap_PDUSessionResourceFailedToSetupListHOAck_item,
      { "PDUSessionResourceFailedToSetupItemHOAck", "ngap.PDUSessionResourceFailedToSetupItemHOAck_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ngap_handoverResourceAllocationUnsuccessfulTransfer,
      { "handoverResourceAllocationUnsuccessfulTransfer", "ngap.handoverResourceAllocationUnsuccessfulTransfer",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ngap_PDUSessionResourceFailedToSetupListPSReq_item,
      { "PDUSessionResourceFailedToSetupItemPSReq", "ngap.PDUSessionResourceFailedToSetupItemPSReq_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ngap_pathSwitchRequestSetupFailedTransfer,
      { "pathSwitchRequestSetupFailedTransfer", "ngap.pathSwitchRequestSetupFailedTransfer",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ngap_PDUSessionResourceFailedToSetupListSURes_item,
      { "PDUSessionResourceFailedToSetupItemSURes", "ngap.PDUSessionResourceFailedToSetupItemSURes_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ngap_pDUSessionResourceSetupUnsuccessfulTransfer_02,
      { "pDUSessionResourceSetupUnsuccessfulTransfer", "ngap.pDUSessionResourceSetupUnsuccessfulTransfer",
        FT_BYTES, BASE_NONE, NULL, 0,
        "T_pDUSessionResourceSetupUnsuccessfulTransfer_02", HFILL }},
    { &hf_ngap_PDUSessionResourceHandoverList_item,
      { "PDUSessionResourceHandoverItem", "ngap.PDUSessionResourceHandoverItem_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ngap_handoverCommandTransfer,
      { "handoverCommandTransfer", "ngap.handoverCommandTransfer",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ngap_PDUSessionResourceInformationList_item,
      { "PDUSessionResourceInformationItem", "ngap.PDUSessionResourceInformationItem_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ngap_qosFlowInformationList,
      { "qosFlowInformationList", "ngap.qosFlowInformationList",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_ngap_dRBsToQosFlowsMappingList,
      { "dRBsToQosFlowsMappingList", "ngap.dRBsToQosFlowsMappingList",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_ngap_PDUSessionResourceListCxtRelCpl_item,
      { "PDUSessionResourceItemCxtRelCpl", "ngap.PDUSessionResourceItemCxtRelCpl_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ngap_PDUSessionResourceListCxtRelReq_item,
      { "PDUSessionResourceItemCxtRelReq", "ngap.PDUSessionResourceItemCxtRelReq_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ngap_PDUSessionResourceListHORqd_item,
      { "PDUSessionResourceItemHORqd", "ngap.PDUSessionResourceItemHORqd_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ngap_handoverRequiredTransfer,
      { "handoverRequiredTransfer", "ngap.handoverRequiredTransfer",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ngap_qosFlowModifyConfirmList,
      { "qosFlowModifyConfirmList", "ngap.qosFlowModifyConfirmList",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_ngap_uLNGU_UP_TNLInformation,
      { "uLNGU-UP-TNLInformation", "ngap.uLNGU_UP_TNLInformation",
        FT_UINT32, BASE_DEC, VALS(ngap_UPTransportLayerInformation_vals), 0,
        "UPTransportLayerInformation", HFILL }},
    { &hf_ngap_additionalNG_UUPTNLInformation,
      { "additionalNG-UUPTNLInformation", "ngap.additionalNG_UUPTNLInformation",
        FT_UINT32, BASE_DEC, NULL, 0,
        "UPTransportLayerInformationPairList", HFILL }},
    { &hf_ngap_qosFlowFailedToModifyList,
      { "qosFlowFailedToModifyList", "ngap.qosFlowFailedToModifyList",
        FT_UINT32, BASE_DEC, NULL, 0,
        "QosFlowListWithCause", HFILL }},
    { &hf_ngap_protocolIEs,
      { "protocolIEs", "ngap.protocolIEs",
        FT_UINT32, BASE_DEC, NULL, 0,
        "ProtocolIE_Container", HFILL }},
    { &hf_ngap_qosFlowAddOrModifyResponseList,
      { "qosFlowAddOrModifyResponseList", "ngap.qosFlowAddOrModifyResponseList",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_ngap_additionalDLQosFlowPerTNLInformation,
      { "additionalDLQosFlowPerTNLInformation", "ngap.additionalDLQosFlowPerTNLInformation",
        FT_UINT32, BASE_DEC, NULL, 0,
        "QosFlowPerTNLInformationList", HFILL }},
    { &hf_ngap_qosFlowFailedToAddOrModifyList,
      { "qosFlowFailedToAddOrModifyList", "ngap.qosFlowFailedToAddOrModifyList",
        FT_UINT32, BASE_DEC, NULL, 0,
        "QosFlowListWithCause", HFILL }},
    { &hf_ngap_dLQosFlowPerTNLInformation,
      { "dLQosFlowPerTNLInformation", "ngap.dLQosFlowPerTNLInformation_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "QosFlowPerTNLInformation", HFILL }},
    { &hf_ngap_PDUSessionResourceModifyListModCfm_item,
      { "PDUSessionResourceModifyItemModCfm", "ngap.PDUSessionResourceModifyItemModCfm_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ngap_pDUSessionResourceModifyConfirmTransfer,
      { "pDUSessionResourceModifyConfirmTransfer", "ngap.pDUSessionResourceModifyConfirmTransfer",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ngap_PDUSessionResourceModifyListModInd_item,
      { "PDUSessionResourceModifyItemModInd", "ngap.PDUSessionResourceModifyItemModInd_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ngap_pDUSessionResourceModifyIndicationTransfer,
      { "pDUSessionResourceModifyIndicationTransfer", "ngap.pDUSessionResourceModifyIndicationTransfer",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ngap_PDUSessionResourceModifyListModReq_item,
      { "PDUSessionResourceModifyItemModReq", "ngap.PDUSessionResourceModifyItemModReq_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ngap_nAS_PDU,
      { "nAS-PDU", "ngap.nAS_PDU",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ngap_pDUSessionResourceModifyRequestTransfer,
      { "pDUSessionResourceModifyRequestTransfer", "ngap.pDUSessionResourceModifyRequestTransfer",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ngap_PDUSessionResourceModifyListModRes_item,
      { "PDUSessionResourceModifyItemModRes", "ngap.PDUSessionResourceModifyItemModRes_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ngap_pDUSessionResourceModifyResponseTransfer,
      { "pDUSessionResourceModifyResponseTransfer", "ngap.pDUSessionResourceModifyResponseTransfer",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ngap_PDUSessionResourceNotifyList_item,
      { "PDUSessionResourceNotifyItem", "ngap.PDUSessionResourceNotifyItem_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ngap_pDUSessionResourceNotifyTransfer,
      { "pDUSessionResourceNotifyTransfer", "ngap.pDUSessionResourceNotifyTransfer",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ngap_qosFlowNotifyList,
      { "qosFlowNotifyList", "ngap.qosFlowNotifyList",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_ngap_qosFlowReleasedList,
      { "qosFlowReleasedList", "ngap.qosFlowReleasedList",
        FT_UINT32, BASE_DEC, NULL, 0,
        "QosFlowListWithCause", HFILL }},
    { &hf_ngap_PDUSessionResourceReleasedListNot_item,
      { "PDUSessionResourceReleasedItemNot", "ngap.PDUSessionResourceReleasedItemNot_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ngap_pDUSessionResourceNotifyReleasedTransfer,
      { "pDUSessionResourceNotifyReleasedTransfer", "ngap.pDUSessionResourceNotifyReleasedTransfer",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ngap_PDUSessionResourceReleasedListPSAck_item,
      { "PDUSessionResourceReleasedItemPSAck", "ngap.PDUSessionResourceReleasedItemPSAck_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ngap_pathSwitchRequestUnsuccessfulTransfer,
      { "pathSwitchRequestUnsuccessfulTransfer", "ngap.pathSwitchRequestUnsuccessfulTransfer",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ngap_PDUSessionResourceReleasedListPSFail_item,
      { "PDUSessionResourceReleasedItemPSFail", "ngap.PDUSessionResourceReleasedItemPSFail_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ngap_pathSwitchRequestUnsuccessfulTransfer_01,
      { "pathSwitchRequestUnsuccessfulTransfer", "ngap.pathSwitchRequestUnsuccessfulTransfer",
        FT_BYTES, BASE_NONE, NULL, 0,
        "T_pathSwitchRequestUnsuccessfulTransfer_01", HFILL }},
    { &hf_ngap_PDUSessionResourceReleasedListRelRes_item,
      { "PDUSessionResourceReleasedItemRelRes", "ngap.PDUSessionResourceReleasedItemRelRes_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ngap_pDUSessionResourceReleaseResponseTransfer,
      { "pDUSessionResourceReleaseResponseTransfer", "ngap.pDUSessionResourceReleaseResponseTransfer",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ngap_PDUSessionResourceSecondaryRATUsageList_item,
      { "PDUSessionResourceSecondaryRATUsageItem", "ngap.PDUSessionResourceSecondaryRATUsageItem_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ngap_secondaryRATDataUsageReportTransfer,
      { "secondaryRATDataUsageReportTransfer", "ngap.secondaryRATDataUsageReportTransfer",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ngap_PDUSessionResourceSetupListCxtReq_item,
      { "PDUSessionResourceSetupItemCxtReq", "ngap.PDUSessionResourceSetupItemCxtReq_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ngap_pDUSessionResourceSetupRequestTransfer,
      { "pDUSessionResourceSetupRequestTransfer", "ngap.pDUSessionResourceSetupRequestTransfer",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ngap_PDUSessionResourceSetupListCxtRes_item,
      { "PDUSessionResourceSetupItemCxtRes", "ngap.PDUSessionResourceSetupItemCxtRes_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ngap_pDUSessionResourceSetupResponseTransfer,
      { "pDUSessionResourceSetupResponseTransfer", "ngap.pDUSessionResourceSetupResponseTransfer",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ngap_PDUSessionResourceSetupListHOReq_item,
      { "PDUSessionResourceSetupItemHOReq", "ngap.PDUSessionResourceSetupItemHOReq_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ngap_handoverRequestTransfer,
      { "handoverRequestTransfer", "ngap.handoverRequestTransfer",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ngap_PDUSessionResourceSetupListSUReq_item,
      { "PDUSessionResourceSetupItemSUReq", "ngap.PDUSessionResourceSetupItemSUReq_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ngap_pDUSessionNAS_PDU,
      { "pDUSessionNAS-PDU", "ngap.pDUSessionNAS_PDU",
        FT_BYTES, BASE_NONE, NULL, 0,
        "NAS_PDU", HFILL }},
    { &hf_ngap_pDUSessionResourceSetupRequestTransfer_01,
      { "pDUSessionResourceSetupRequestTransfer", "ngap.pDUSessionResourceSetupRequestTransfer",
        FT_BYTES, BASE_NONE, NULL, 0,
        "T_pDUSessionResourceSetupRequestTransfer_01", HFILL }},
    { &hf_ngap_PDUSessionResourceSetupListSURes_item,
      { "PDUSessionResourceSetupItemSURes", "ngap.PDUSessionResourceSetupItemSURes_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ngap_pDUSessionResourceSetupResponseTransfer_01,
      { "pDUSessionResourceSetupResponseTransfer", "ngap.pDUSessionResourceSetupResponseTransfer",
        FT_BYTES, BASE_NONE, NULL, 0,
        "T_pDUSessionResourceSetupResponseTransfer_01", HFILL }},
    { &hf_ngap_PDUSessionResourceSwitchedList_item,
      { "PDUSessionResourceSwitchedItem", "ngap.PDUSessionResourceSwitchedItem_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ngap_pathSwitchRequestAcknowledgeTransfer,
      { "pathSwitchRequestAcknowledgeTransfer", "ngap.pathSwitchRequestAcknowledgeTransfer",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ngap_PDUSessionResourceToBeSwitchedDLList_item,
      { "PDUSessionResourceToBeSwitchedDLItem", "ngap.PDUSessionResourceToBeSwitchedDLItem_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ngap_pathSwitchRequestTransfer,
      { "pathSwitchRequestTransfer", "ngap.pathSwitchRequestTransfer",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ngap_PDUSessionResourceToReleaseListHOCmd_item,
      { "PDUSessionResourceToReleaseItemHOCmd", "ngap.PDUSessionResourceToReleaseItemHOCmd_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ngap_handoverPreparationUnsuccessfulTransfer,
      { "handoverPreparationUnsuccessfulTransfer", "ngap.handoverPreparationUnsuccessfulTransfer",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ngap_PDUSessionResourceToReleaseListRelCmd_item,
      { "PDUSessionResourceToReleaseItemRelCmd", "ngap.PDUSessionResourceToReleaseItemRelCmd_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ngap_pDUSessionResourceReleaseCommandTransfer,
      { "pDUSessionResourceReleaseCommandTransfer", "ngap.pDUSessionResourceReleaseCommandTransfer",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ngap_rATType,
      { "rATType", "ngap.rATType",
        FT_UINT32, BASE_DEC, VALS(ngap_T_rATType_vals), 0,
        NULL, HFILL }},
    { &hf_ngap_pDUSessionTimedReportList,
      { "pDUSessionTimedReportList", "ngap.pDUSessionTimedReportList",
        FT_UINT32, BASE_DEC, NULL, 0,
        "VolumeTimedReportList", HFILL }},
    { &hf_ngap_PLMNSupportList_item,
      { "PLMNSupportItem", "ngap.PLMNSupportItem_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ngap_sliceSupportList,
      { "sliceSupportList", "ngap.sliceSupportList",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_ngap_eUTRA_CGI_PWSFailedList,
      { "eUTRA-CGI-PWSFailedList", "ngap.eUTRA_CGI_PWSFailedList",
        FT_UINT32, BASE_DEC, NULL, 0,
        "EUTRA_CGIList", HFILL }},
    { &hf_ngap_nR_CGI_PWSFailedList,
      { "nR-CGI-PWSFailedList", "ngap.nR_CGI_PWSFailedList",
        FT_UINT32, BASE_DEC, NULL, 0,
        "NR_CGIList", HFILL }},
    { &hf_ngap_nonDynamic5QI,
      { "nonDynamic5QI", "ngap.nonDynamic5QI_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "NonDynamic5QIDescriptor", HFILL }},
    { &hf_ngap_dynamic5QI,
      { "dynamic5QI", "ngap.dynamic5QI_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "Dynamic5QIDescriptor", HFILL }},
    { &hf_ngap_QosFlowAcceptedList_item,
      { "QosFlowAcceptedItem", "ngap.QosFlowAcceptedItem_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ngap_QosFlowAddOrModifyRequestList_item,
      { "QosFlowAddOrModifyRequestItem", "ngap.QosFlowAddOrModifyRequestItem_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ngap_qosFlowLevelQosParameters,
      { "qosFlowLevelQosParameters", "ngap.qosFlowLevelQosParameters_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ngap_QosFlowAddOrModifyResponseList_item,
      { "QosFlowAddOrModifyResponseItem", "ngap.QosFlowAddOrModifyResponseItem_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ngap_QosFlowInformationList_item,
      { "QosFlowInformationItem", "ngap.QosFlowInformationItem_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ngap_qosCharacteristics,
      { "qosCharacteristics", "ngap.qosCharacteristics",
        FT_UINT32, BASE_DEC, VALS(ngap_QosCharacteristics_vals), 0,
        NULL, HFILL }},
    { &hf_ngap_allocationAndRetentionPriority,
      { "allocationAndRetentionPriority", "ngap.allocationAndRetentionPriority_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ngap_gBR_QosInformation,
      { "gBR-QosInformation", "ngap.gBR_QosInformation_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ngap_reflectiveQosAttribute,
      { "reflectiveQosAttribute", "ngap.reflectiveQosAttribute",
        FT_UINT32, BASE_DEC, VALS(ngap_ReflectiveQosAttribute_vals), 0,
        NULL, HFILL }},
    { &hf_ngap_additionalQosFlowInformation,
      { "additionalQosFlowInformation", "ngap.additionalQosFlowInformation",
        FT_UINT32, BASE_DEC, VALS(ngap_AdditionalQosFlowInformation_vals), 0,
        NULL, HFILL }},
    { &hf_ngap_QosFlowListWithCause_item,
      { "QosFlowWithCauseItem", "ngap.QosFlowWithCauseItem_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ngap_QosFlowModifyConfirmList_item,
      { "QosFlowModifyConfirmItem", "ngap.QosFlowModifyConfirmItem_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ngap_QosFlowNotifyList_item,
      { "QosFlowNotifyItem", "ngap.QosFlowNotifyItem_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ngap_notificationCause,
      { "notificationCause", "ngap.notificationCause",
        FT_UINT32, BASE_DEC, VALS(ngap_NotificationCause_vals), 0,
        NULL, HFILL }},
    { &hf_ngap_uPTransportLayerInformation,
      { "uPTransportLayerInformation", "ngap.uPTransportLayerInformation",
        FT_UINT32, BASE_DEC, VALS(ngap_UPTransportLayerInformation_vals), 0,
        NULL, HFILL }},
    { &hf_ngap_QosFlowPerTNLInformationList_item,
      { "QosFlowPerTNLInformationItem", "ngap.QosFlowPerTNLInformationItem_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ngap_qosFlowPerTNLInformation,
      { "qosFlowPerTNLInformation", "ngap.qosFlowPerTNLInformation_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ngap_QosFlowSetupRequestList_item,
      { "QosFlowSetupRequestItem", "ngap.QosFlowSetupRequestItem_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ngap_QosFlowListWithDataForwarding_item,
      { "QosFlowItemWithDataForwarding", "ngap.QosFlowItemWithDataForwarding_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ngap_dataForwardingAccepted,
      { "dataForwardingAccepted", "ngap.dataForwardingAccepted",
        FT_UINT32, BASE_DEC, VALS(ngap_DataForwardingAccepted_vals), 0,
        NULL, HFILL }},
    { &hf_ngap_QosFlowToBeForwardedList_item,
      { "QosFlowToBeForwardedItem", "ngap.QosFlowToBeForwardedItem_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ngap_QoSFlowsUsageReportList_item,
      { "QoSFlowsUsageReport-Item", "ngap.QoSFlowsUsageReport_Item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ngap_rATType_01,
      { "rATType", "ngap.rATType",
        FT_UINT32, BASE_DEC, VALS(ngap_T_rATType_01_vals), 0,
        "T_rATType_01", HFILL }},
    { &hf_ngap_qoSFlowsTimedReportList,
      { "qoSFlowsTimedReportList", "ngap.qoSFlowsTimedReportList",
        FT_UINT32, BASE_DEC, NULL, 0,
        "VolumeTimedReportList", HFILL }},
    { &hf_ngap_dRBsSubjectToStatusTransferList,
      { "dRBsSubjectToStatusTransferList", "ngap.dRBsSubjectToStatusTransferList",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_ngap_RATRestrictions_item,
      { "RATRestrictions-Item", "ngap.RATRestrictions_Item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ngap_rATRestrictionInformation,
      { "rATRestrictionInformation", "ngap.rATRestrictionInformation",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ngap_recommendedCellList,
      { "recommendedCellList", "ngap.recommendedCellList",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_ngap_RecommendedCellList_item,
      { "RecommendedCellItem", "ngap.RecommendedCellItem_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ngap_recommendedRANNodeList,
      { "recommendedRANNodeList", "ngap.recommendedRANNodeList",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_ngap_RecommendedRANNodeList_item,
      { "RecommendedRANNodeItem", "ngap.RecommendedRANNodeItem_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ngap_aMFPagingTarget,
      { "aMFPagingTarget", "ngap.aMFPagingTarget",
        FT_UINT32, BASE_DEC, VALS(ngap_AMFPagingTarget_vals), 0,
        NULL, HFILL }},
    { &hf_ngap_nG_Interface,
      { "nG-Interface", "ngap.nG_Interface",
        FT_UINT32, BASE_DEC, VALS(ngap_ResetAll_vals), 0,
        "ResetAll", HFILL }},
    { &hf_ngap_partOfNG_Interface,
      { "partOfNG-Interface", "ngap.partOfNG_Interface",
        FT_UINT32, BASE_DEC, NULL, 0,
        "UE_associatedLogicalNG_connectionList", HFILL }},
    { &hf_ngap_SCTP_TLAs_item,
      { "TransportLayerAddress", "ngap.TransportLayerAddress",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ngap_pDUSessionUsageReport,
      { "pDUSessionUsageReport", "ngap.pDUSessionUsageReport_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ngap_qosFlowsUsageReportList,
      { "qosFlowsUsageReportList", "ngap.qosFlowsUsageReportList",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_ngap_secondaryRATUsageInformation,
      { "secondaryRATUsageInformation", "ngap.secondaryRATUsageInformation_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ngap_nextHopChainingCount,
      { "nextHopChainingCount", "ngap.nextHopChainingCount",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_ngap_nextHopNH,
      { "nextHopNH", "ngap.nextHopNH",
        FT_BYTES, BASE_NONE, NULL, 0,
        "SecurityKey", HFILL }},
    { &hf_ngap_integrityProtectionIndication,
      { "integrityProtectionIndication", "ngap.integrityProtectionIndication",
        FT_UINT32, BASE_DEC, VALS(ngap_IntegrityProtectionIndication_vals), 0,
        NULL, HFILL }},
    { &hf_ngap_confidentialityProtectionIndication,
      { "confidentialityProtectionIndication", "ngap.confidentialityProtectionIndication",
        FT_UINT32, BASE_DEC, VALS(ngap_ConfidentialityProtectionIndication_vals), 0,
        NULL, HFILL }},
    { &hf_ngap_maximumIntegrityProtectedDataRate_UL,
      { "maximumIntegrityProtectedDataRate-UL", "ngap.maximumIntegrityProtectedDataRate_UL",
        FT_UINT32, BASE_DEC, VALS(ngap_MaximumIntegrityProtectedDataRate_vals), 0,
        "MaximumIntegrityProtectedDataRate", HFILL }},
    { &hf_ngap_integrityProtectionResult,
      { "integrityProtectionResult", "ngap.integrityProtectionResult",
        FT_UINT32, BASE_DEC, VALS(ngap_IntegrityProtectionResult_vals), 0,
        NULL, HFILL }},
    { &hf_ngap_confidentialityProtectionResult,
      { "confidentialityProtectionResult", "ngap.confidentialityProtectionResult",
        FT_UINT32, BASE_DEC, VALS(ngap_ConfidentialityProtectionResult_vals), 0,
        NULL, HFILL }},
    { &hf_ngap_ServedGUAMIList_item,
      { "ServedGUAMIItem", "ngap.ServedGUAMIItem_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ngap_gUAMI,
      { "gUAMI", "ngap.gUAMI_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ngap_backupAMFName,
      { "backupAMFName", "ngap.backupAMFName",
        FT_STRING, BASE_NONE, NULL, 0,
        "AMFName", HFILL }},
    { &hf_ngap_ServiceAreaInformation_item,
      { "ServiceAreaInformation-Item", "ngap.ServiceAreaInformation_Item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ngap_allowedTACs,
      { "allowedTACs", "ngap.allowedTACs",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_ngap_notAllowedTACs,
      { "notAllowedTACs", "ngap.notAllowedTACs",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_ngap_SliceOverloadList_item,
      { "SliceOverloadItem", "ngap.SliceOverloadItem_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ngap_SliceSupportList_item,
      { "SliceSupportItem", "ngap.SliceSupportItem_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ngap_sST,
      { "sST", "ngap.sST",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ngap_sD,
      { "sD", "ngap.sD",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ngap_targetRANNodeID,
      { "targetRANNodeID", "ngap.targetRANNodeID_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ngap_sourceRANNodeID,
      { "sourceRANNodeID", "ngap.sourceRANNodeID_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ngap_sONInformation,
      { "sONInformation", "ngap.sONInformation",
        FT_UINT32, BASE_DEC, VALS(ngap_SONInformation_vals), 0,
        NULL, HFILL }},
    { &hf_ngap_xnTNLConfigurationInfo,
      { "xnTNLConfigurationInfo", "ngap.xnTNLConfigurationInfo_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ngap_sONInformationRequest,
      { "sONInformationRequest", "ngap.sONInformationRequest",
        FT_UINT32, BASE_DEC, VALS(ngap_SONInformationRequest_vals), 0,
        NULL, HFILL }},
    { &hf_ngap_sONInformationReply,
      { "sONInformationReply", "ngap.sONInformationReply_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ngap_rRCContainer,
      { "rRCContainer", "ngap.rRCContainer",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ngap_pDUSessionResourceInformationList,
      { "pDUSessionResourceInformationList", "ngap.pDUSessionResourceInformationList",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_ngap_e_RABInformationList,
      { "e-RABInformationList", "ngap.e_RABInformationList",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_ngap_targetCell_ID,
      { "targetCell-ID", "ngap.targetCell_ID",
        FT_UINT32, BASE_DEC, VALS(ngap_NGRAN_CGI_vals), 0,
        "NGRAN_CGI", HFILL }},
    { &hf_ngap_indexToRFSP,
      { "indexToRFSP", "ngap.indexToRFSP",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_ngap_uEHistoryInformation,
      { "uEHistoryInformation", "ngap.uEHistoryInformation",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_ngap_selectedTAI,
      { "selectedTAI", "ngap.selectedTAI_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "TAI", HFILL }},
    { &hf_ngap_configuredNSSAI,
      { "configuredNSSAI", "ngap.configuredNSSAI",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ngap_rejectedNSSAIinPLMN,
      { "rejectedNSSAIinPLMN", "ngap.rejectedNSSAIinPLMN",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ngap_rejectedNSSAIinTA,
      { "rejectedNSSAIinTA", "ngap.rejectedNSSAIinTA",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ngap_SupportedTAList_item,
      { "SupportedTAItem", "ngap.SupportedTAItem_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ngap_tAC,
      { "tAC", "ngap.tAC",
        FT_UINT24, BASE_DEC_HEX, NULL, 0,
        NULL, HFILL }},
    { &hf_ngap_broadcastPLMNList,
      { "broadcastPLMNList", "ngap.broadcastPLMNList",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_ngap_TAIBroadcastEUTRA_item,
      { "TAIBroadcastEUTRA-Item", "ngap.TAIBroadcastEUTRA_Item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ngap_completedCellsInTAI_EUTRA,
      { "completedCellsInTAI-EUTRA", "ngap.completedCellsInTAI_EUTRA",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_ngap_TAIBroadcastNR_item,
      { "TAIBroadcastNR-Item", "ngap.TAIBroadcastNR_Item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ngap_completedCellsInTAI_NR,
      { "completedCellsInTAI-NR", "ngap.completedCellsInTAI_NR",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_ngap_TAICancelledEUTRA_item,
      { "TAICancelledEUTRA-Item", "ngap.TAICancelledEUTRA_Item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ngap_cancelledCellsInTAI_EUTRA,
      { "cancelledCellsInTAI-EUTRA", "ngap.cancelledCellsInTAI_EUTRA",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_ngap_TAICancelledNR_item,
      { "TAICancelledNR-Item", "ngap.TAICancelledNR_Item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ngap_cancelledCellsInTAI_NR,
      { "cancelledCellsInTAI-NR", "ngap.cancelledCellsInTAI_NR",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_ngap_TAIListForInactive_item,
      { "TAIListForInactiveItem", "ngap.TAIListForInactiveItem_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ngap_TAIListForPaging_item,
      { "TAIListForPagingItem", "ngap.TAIListForPagingItem_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ngap_TAIListForRestart_item,
      { "TAI", "ngap.TAI_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ngap_TAIListForWarning_item,
      { "TAI", "ngap.TAI_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ngap_globalENB_ID,
      { "globalENB-ID", "ngap.globalENB_ID_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "GlobalNgENB_ID", HFILL }},
    { &hf_ngap_selected_EPS_TAI,
      { "selected-EPS-TAI", "ngap.selected_EPS_TAI_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "EPS_TAI", HFILL }},
    { &hf_ngap_targeteNB_ID,
      { "targeteNB-ID", "ngap.targeteNB_ID_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ngap_TNLAssociationList_item,
      { "TNLAssociationItem", "ngap.TNLAssociationItem_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ngap_tNLAssociationAddress,
      { "tNLAssociationAddress", "ngap.tNLAssociationAddress",
        FT_UINT32, BASE_DEC, VALS(ngap_CPTransportLayerInformation_vals), 0,
        "CPTransportLayerInformation", HFILL }},
    { &hf_ngap_nGRANTraceID,
      { "nGRANTraceID", "ngap.nGRANTraceID",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ngap_interfacesToTrace,
      { "interfacesToTrace", "ngap.interfacesToTrace",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ngap_traceDepth,
      { "traceDepth", "ngap.traceDepth",
        FT_UINT32, BASE_DEC, VALS(ngap_TraceDepth_vals), 0,
        NULL, HFILL }},
    { &hf_ngap_traceCollectionEntityIPAddress,
      { "traceCollectionEntityIPAddress", "ngap.traceCollectionEntityIPAddress",
        FT_BYTES, BASE_NONE, NULL, 0,
        "TransportLayerAddress", HFILL }},
    { &hf_ngap_uEAggregateMaximumBitRateDL,
      { "uEAggregateMaximumBitRateDL", "ngap.uEAggregateMaximumBitRateDL",
        FT_UINT64, BASE_DEC|BASE_UNIT_STRING, &units_bit_sec, 0,
        "BitRate", HFILL }},
    { &hf_ngap_uEAggregateMaximumBitRateUL,
      { "uEAggregateMaximumBitRateUL", "ngap.uEAggregateMaximumBitRateUL",
        FT_UINT64, BASE_DEC|BASE_UNIT_STRING, &units_bit_sec, 0,
        "BitRate", HFILL }},
    { &hf_ngap_UE_associatedLogicalNG_connectionList_item,
      { "UE-associatedLogicalNG-connectionItem", "ngap.UE_associatedLogicalNG_connectionItem_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ngap_aMF_UE_NGAP_ID,
      { "aMF-UE-NGAP-ID", "ngap.aMF_UE_NGAP_ID",
        FT_UINT64, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_ngap_rAN_UE_NGAP_ID,
      { "rAN-UE-NGAP-ID", "ngap.rAN_UE_NGAP_ID",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_ngap_UEHistoryInformation_item,
      { "LastVisitedCellItem", "ngap.LastVisitedCellItem_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ngap_indexLength10,
      { "indexLength10", "ngap.indexLength10",
        FT_BYTES, BASE_NONE, NULL, 0,
        "BIT_STRING_SIZE_10", HFILL }},
    { &hf_ngap_uE_NGAP_ID_pair,
      { "uE-NGAP-ID-pair", "ngap.uE_NGAP_ID_pair_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ngap_fiveG_S_TMSI,
      { "fiveG-S-TMSI", "ngap.fiveG_S_TMSI_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ngap_UEPresenceInAreaOfInterestList_item,
      { "UEPresenceInAreaOfInterestItem", "ngap.UEPresenceInAreaOfInterestItem_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ngap_uEPresence,
      { "uEPresence", "ngap.uEPresence",
        FT_UINT32, BASE_DEC, VALS(ngap_UEPresence_vals), 0,
        NULL, HFILL }},
    { &hf_ngap_uERadioCapabilityForPagingOfNR,
      { "uERadioCapabilityForPagingOfNR", "ngap.uERadioCapabilityForPagingOfNR",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ngap_uERadioCapabilityForPagingOfEUTRA,
      { "uERadioCapabilityForPagingOfEUTRA", "ngap.uERadioCapabilityForPagingOfEUTRA",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ngap_nRencryptionAlgorithms,
      { "nRencryptionAlgorithms", "ngap.nRencryptionAlgorithms",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ngap_nRintegrityProtectionAlgorithms,
      { "nRintegrityProtectionAlgorithms", "ngap.nRintegrityProtectionAlgorithms",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ngap_eUTRAencryptionAlgorithms,
      { "eUTRAencryptionAlgorithms", "ngap.eUTRAencryptionAlgorithms",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ngap_eUTRAintegrityProtectionAlgorithms,
      { "eUTRAintegrityProtectionAlgorithms", "ngap.eUTRAintegrityProtectionAlgorithms",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ngap_UL_NGU_UP_TNLModifyList_item,
      { "UL-NGU-UP-TNLModifyItem", "ngap.UL_NGU_UP_TNLModifyItem_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ngap_UnavailableGUAMIList_item,
      { "UnavailableGUAMIItem", "ngap.UnavailableGUAMIItem_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ngap_timerApproachForGUAMIRemoval,
      { "timerApproachForGUAMIRemoval", "ngap.timerApproachForGUAMIRemoval",
        FT_UINT32, BASE_DEC, VALS(ngap_TimerApproachForGUAMIRemoval_vals), 0,
        NULL, HFILL }},
    { &hf_ngap_gTPTunnel,
      { "gTPTunnel", "ngap.gTPTunnel_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ngap_UPTransportLayerInformationList_item,
      { "UPTransportLayerInformationItem", "ngap.UPTransportLayerInformationItem_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ngap_nGU_UP_TNLInformation,
      { "nGU-UP-TNLInformation", "ngap.nGU_UP_TNLInformation",
        FT_UINT32, BASE_DEC, VALS(ngap_UPTransportLayerInformation_vals), 0,
        "UPTransportLayerInformation", HFILL }},
    { &hf_ngap_UPTransportLayerInformationPairList_item,
      { "UPTransportLayerInformationPairItem", "ngap.UPTransportLayerInformationPairItem_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ngap_userLocationInformationEUTRA,
      { "userLocationInformationEUTRA", "ngap.userLocationInformationEUTRA_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ngap_userLocationInformationNR,
      { "userLocationInformationNR", "ngap.userLocationInformationNR_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ngap_userLocationInformationN3IWF,
      { "userLocationInformationN3IWF", "ngap.userLocationInformationN3IWF_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ngap_timeStamp,
      { "timeStamp", "ngap.timeStamp",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ngap_iPAddress,
      { "iPAddress", "ngap.iPAddress",
        FT_BYTES, BASE_NONE, NULL, 0,
        "TransportLayerAddress", HFILL }},
    { &hf_ngap_VolumeTimedReportList_item,
      { "VolumeTimedReport-Item", "ngap.VolumeTimedReport_Item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ngap_startTimeStamp,
      { "startTimeStamp", "ngap.startTimeStamp",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ngap_endTimeStamp,
      { "endTimeStamp", "ngap.endTimeStamp",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ngap_usageCountUL,
      { "usageCountUL", "ngap.usageCountUL",
        FT_UINT64, BASE_DEC|BASE_UNIT_STRING, &units_octet_octets, 0,
        "INTEGER_0_18446744073709551615", HFILL }},
    { &hf_ngap_usageCountDL,
      { "usageCountDL", "ngap.usageCountDL",
        FT_UINT64, BASE_DEC|BASE_UNIT_STRING, &units_octet_octets, 0,
        "INTEGER_0_18446744073709551615", HFILL }},
    { &hf_ngap_eUTRA_CGIListForWarning,
      { "eUTRA-CGIListForWarning", "ngap.eUTRA_CGIListForWarning",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_ngap_nR_CGIListForWarning,
      { "nR-CGIListForWarning", "ngap.nR_CGIListForWarning",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_ngap_tAIListForWarning,
      { "tAIListForWarning", "ngap.tAIListForWarning",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_ngap_emergencyAreaIDList,
      { "emergencyAreaIDList", "ngap.emergencyAreaIDList",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_ngap_XnExtTLAs_item,
      { "XnExtTLA-Item", "ngap.XnExtTLA_Item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ngap_iPsecTLA,
      { "iPsecTLA", "ngap.iPsecTLA",
        FT_BYTES, BASE_NONE, NULL, 0,
        "TransportLayerAddress", HFILL }},
    { &hf_ngap_gTP_TLAs,
      { "gTP-TLAs", "ngap.gTP_TLAs",
        FT_UINT32, BASE_DEC, NULL, 0,
        "XnGTP_TLAs", HFILL }},
    { &hf_ngap_XnGTP_TLAs_item,
      { "TransportLayerAddress", "ngap.TransportLayerAddress",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ngap_XnTLAs_item,
      { "TransportLayerAddress", "ngap.TransportLayerAddress",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ngap_xnTransportLayerAddresses,
      { "xnTransportLayerAddresses", "ngap.xnTransportLayerAddresses",
        FT_UINT32, BASE_DEC, NULL, 0,
        "XnTLAs", HFILL }},
    { &hf_ngap_xnExtendedTransportLayerAddresses,
      { "xnExtendedTransportLayerAddresses", "ngap.xnExtendedTransportLayerAddresses",
        FT_UINT32, BASE_DEC, NULL, 0,
        "XnExtTLAs", HFILL }},
    { &hf_ngap_privateIEs,
      { "privateIEs", "ngap.privateIEs",
        FT_UINT32, BASE_DEC, NULL, 0,
        "PrivateIE_Container", HFILL }},
    { &hf_ngap_initiatingMessage,
      { "initiatingMessage", "ngap.initiatingMessage_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ngap_successfulOutcome,
      { "successfulOutcome", "ngap.successfulOutcome_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ngap_unsuccessfulOutcome,
      { "unsuccessfulOutcome", "ngap.unsuccessfulOutcome_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ngap_initiatingMessagevalue,
      { "value", "ngap.value_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "InitiatingMessage_value", HFILL }},
    { &hf_ngap_successfulOutcome_value,
      { "value", "ngap.value_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "SuccessfulOutcome_value", HFILL }},
    { &hf_ngap_unsuccessfulOutcome_value,
      { "value", "ngap.value_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "UnsuccessfulOutcome_value", HFILL }},

/*--- End of included file: packet-ngap-hfarr.c ---*/
#line 733 "./asn1/ngap/packet-ngap-template.c"
  };

  /* List of subtrees */
  static gint *ett[] = {
    &ett_ngap,
    &ett_ngap_TransportLayerAddress,
    &ett_ngap_DataCodingScheme,
    &ett_ngap_WarningMessageContents,
    &ett_ngap_PLMNIdentity,
    &ett_ngap_NGAP_Message,
    &ett_ngap_NGRANTraceID,
    &ett_ngap_InterfacesToTrace,
    &ett_ngap_SourceToTarget_TransparentContainer,
    &ett_ngap_TargetToSource_TransparentContainer,
    &ett_ngap_RRCContainer,
    &ett_ngap_RATRestrictionInformation,
    &ett_ngap_NrencryptionAlgorithms,
    &ett_ngap_NrintegrityProtectionAlgorithms,
    &ett_ngap_EUTRAencryptionAlgorithms,
    &ett_ngap_EUTRAintegrityProtectionAlgorithms,
    &ett_ngap_UERadioCapabilityForPagingOfNR,
    &ett_ngap_UERadioCapabilityForPagingOfEUTRA,
    &ett_ngap_UERadioCapability,
    &ett_ngap_LastVisitedEUTRANCellInformation,
    &ett_ngap_LastVisitedUTRANCellInformation,
    &ett_ngap_LastVisitedGERANCellInformation,
    &ett_ngap_NASSecurityParametersFromNGRAN,
    &ett_ngap_NASC,
    &ett_ngap_NAS_PDU,
    &ett_ngap_EN_DCSONConfigurationTransfer,

/*--- Included file: packet-ngap-ettarr.c ---*/
#line 1 "./asn1/ngap/packet-ngap-ettarr.c"
    &ett_ngap_PrivateIE_ID,
    &ett_ngap_ProtocolIE_Container,
    &ett_ngap_ProtocolIE_Field,
    &ett_ngap_ProtocolExtensionContainer,
    &ett_ngap_ProtocolExtensionField,
    &ett_ngap_PrivateIE_Container,
    &ett_ngap_PrivateIE_Field,
    &ett_ngap_AdditionalDLUPTNLInformationForHOList,
    &ett_ngap_AdditionalDLUPTNLInformationForHOItem,
    &ett_ngap_AllocationAndRetentionPriority,
    &ett_ngap_AllowedNSSAI,
    &ett_ngap_AllowedNSSAI_Item,
    &ett_ngap_AllowedTACs,
    &ett_ngap_AMFPagingTarget,
    &ett_ngap_AMF_TNLAssociationSetupList,
    &ett_ngap_AMF_TNLAssociationSetupItem,
    &ett_ngap_AMF_TNLAssociationToAddList,
    &ett_ngap_AMF_TNLAssociationToAddItem,
    &ett_ngap_AMF_TNLAssociationToRemoveList,
    &ett_ngap_AMF_TNLAssociationToRemoveItem,
    &ett_ngap_AMF_TNLAssociationToUpdateList,
    &ett_ngap_AMF_TNLAssociationToUpdateItem,
    &ett_ngap_AreaOfInterest,
    &ett_ngap_AreaOfInterestCellList,
    &ett_ngap_AreaOfInterestCellItem,
    &ett_ngap_AreaOfInterestList,
    &ett_ngap_AreaOfInterestItem,
    &ett_ngap_AreaOfInterestRANNodeList,
    &ett_ngap_AreaOfInterestRANNodeItem,
    &ett_ngap_AreaOfInterestTAIList,
    &ett_ngap_AreaOfInterestTAIItem,
    &ett_ngap_AssistanceDataForPaging,
    &ett_ngap_AssistanceDataForRecommendedCells,
    &ett_ngap_AssociatedQosFlowList,
    &ett_ngap_AssociatedQosFlowItem,
    &ett_ngap_BroadcastCancelledAreaList,
    &ett_ngap_BroadcastCompletedAreaList,
    &ett_ngap_BroadcastPLMNList,
    &ett_ngap_BroadcastPLMNItem,
    &ett_ngap_CancelledCellsInEAI_EUTRA,
    &ett_ngap_CancelledCellsInEAI_EUTRA_Item,
    &ett_ngap_CancelledCellsInEAI_NR,
    &ett_ngap_CancelledCellsInEAI_NR_Item,
    &ett_ngap_CancelledCellsInTAI_EUTRA,
    &ett_ngap_CancelledCellsInTAI_EUTRA_Item,
    &ett_ngap_CancelledCellsInTAI_NR,
    &ett_ngap_CancelledCellsInTAI_NR_Item,
    &ett_ngap_Cause,
    &ett_ngap_CellIDBroadcastEUTRA,
    &ett_ngap_CellIDBroadcastEUTRA_Item,
    &ett_ngap_CellIDBroadcastNR,
    &ett_ngap_CellIDBroadcastNR_Item,
    &ett_ngap_CellIDCancelledEUTRA,
    &ett_ngap_CellIDCancelledEUTRA_Item,
    &ett_ngap_CellIDCancelledNR,
    &ett_ngap_CellIDCancelledNR_Item,
    &ett_ngap_CellIDListForRestart,
    &ett_ngap_CellType,
    &ett_ngap_CNAssistedRANTuning,
    &ett_ngap_CNTypeRestrictionsForEquivalent,
    &ett_ngap_CNTypeRestrictionsForEquivalentItem,
    &ett_ngap_CompletedCellsInEAI_EUTRA,
    &ett_ngap_CompletedCellsInEAI_EUTRA_Item,
    &ett_ngap_CompletedCellsInEAI_NR,
    &ett_ngap_CompletedCellsInEAI_NR_Item,
    &ett_ngap_CompletedCellsInTAI_EUTRA,
    &ett_ngap_CompletedCellsInTAI_EUTRA_Item,
    &ett_ngap_CompletedCellsInTAI_NR,
    &ett_ngap_CompletedCellsInTAI_NR_Item,
    &ett_ngap_CoreNetworkAssistanceInformationForInactive,
    &ett_ngap_COUNTValueForPDCP_SN12,
    &ett_ngap_COUNTValueForPDCP_SN18,
    &ett_ngap_CPTransportLayerInformation,
    &ett_ngap_CriticalityDiagnostics,
    &ett_ngap_CriticalityDiagnostics_IE_List,
    &ett_ngap_CriticalityDiagnostics_IE_Item,
    &ett_ngap_DataForwardingResponseDRBList,
    &ett_ngap_DataForwardingResponseDRBItem,
    &ett_ngap_DRBsSubjectToStatusTransferList,
    &ett_ngap_DRBsSubjectToStatusTransferItem,
    &ett_ngap_DRBStatusDL,
    &ett_ngap_DRBStatusDL12,
    &ett_ngap_DRBStatusDL18,
    &ett_ngap_DRBStatusUL,
    &ett_ngap_DRBStatusUL12,
    &ett_ngap_DRBStatusUL18,
    &ett_ngap_DRBsToQosFlowsMappingList,
    &ett_ngap_DRBsToQosFlowsMappingItem,
    &ett_ngap_Dynamic5QIDescriptor,
    &ett_ngap_EmergencyAreaIDBroadcastEUTRA,
    &ett_ngap_EmergencyAreaIDBroadcastEUTRA_Item,
    &ett_ngap_EmergencyAreaIDBroadcastNR,
    &ett_ngap_EmergencyAreaIDBroadcastNR_Item,
    &ett_ngap_EmergencyAreaIDCancelledEUTRA,
    &ett_ngap_EmergencyAreaIDCancelledEUTRA_Item,
    &ett_ngap_EmergencyAreaIDCancelledNR,
    &ett_ngap_EmergencyAreaIDCancelledNR_Item,
    &ett_ngap_EmergencyAreaIDList,
    &ett_ngap_EmergencyAreaIDListForRestart,
    &ett_ngap_EmergencyFallbackIndicator,
    &ett_ngap_EndpointIPAddressAndPort,
    &ett_ngap_EquivalentPLMNs,
    &ett_ngap_EPS_TAI,
    &ett_ngap_E_RABInformationList,
    &ett_ngap_E_RABInformationItem,
    &ett_ngap_EUTRA_CGI,
    &ett_ngap_EUTRA_CGIList,
    &ett_ngap_EUTRA_CGIListForWarning,
    &ett_ngap_ExpectedUEActivityBehaviour,
    &ett_ngap_ExpectedUEBehaviour,
    &ett_ngap_ExpectedUEMovingTrajectory,
    &ett_ngap_ExpectedUEMovingTrajectoryItem,
    &ett_ngap_FiveG_S_TMSI,
    &ett_ngap_ForbiddenAreaInformation,
    &ett_ngap_ForbiddenAreaInformation_Item,
    &ett_ngap_ForbiddenTACs,
    &ett_ngap_GBR_QosInformation,
    &ett_ngap_GlobalGNB_ID,
    &ett_ngap_GlobalN3IWF_ID,
    &ett_ngap_GlobalNgENB_ID,
    &ett_ngap_GlobalRANNodeID,
    &ett_ngap_GNB_ID,
    &ett_ngap_GTPTunnel,
    &ett_ngap_GUAMI,
    &ett_ngap_HandoverCommandTransfer,
    &ett_ngap_HandoverPreparationUnsuccessfulTransfer,
    &ett_ngap_HandoverRequestAcknowledgeTransfer,
    &ett_ngap_HandoverRequiredTransfer,
    &ett_ngap_HandoverResourceAllocationUnsuccessfulTransfer,
    &ett_ngap_InfoOnRecommendedCellsAndRANNodesForPaging,
    &ett_ngap_LastVisitedCellInformation,
    &ett_ngap_LastVisitedCellItem,
    &ett_ngap_LastVisitedNGRANCellInformation,
    &ett_ngap_LocationReportingRequestType,
    &ett_ngap_MobilityRestrictionList,
    &ett_ngap_N3IWF_ID,
    &ett_ngap_NgENB_ID,
    &ett_ngap_NGRAN_CGI,
    &ett_ngap_NGRAN_TNLAssociationToRemoveList,
    &ett_ngap_NGRAN_TNLAssociationToRemoveItem,
    &ett_ngap_NonDynamic5QIDescriptor,
    &ett_ngap_NotAllowedTACs,
    &ett_ngap_NR_CGI,
    &ett_ngap_NR_CGIList,
    &ett_ngap_NR_CGIListForWarning,
    &ett_ngap_OverloadResponse,
    &ett_ngap_OverloadStartNSSAIList,
    &ett_ngap_OverloadStartNSSAIItem,
    &ett_ngap_PacketErrorRate,
    &ett_ngap_PagingAttemptInformation,
    &ett_ngap_PathSwitchRequestAcknowledgeTransfer,
    &ett_ngap_PathSwitchRequestSetupFailedTransfer,
    &ett_ngap_PathSwitchRequestTransfer,
    &ett_ngap_PathSwitchRequestUnsuccessfulTransfer,
    &ett_ngap_PDUSessionAggregateMaximumBitRate,
    &ett_ngap_PDUSessionResourceAdmittedList,
    &ett_ngap_PDUSessionResourceAdmittedItem,
    &ett_ngap_PDUSessionResourceFailedToModifyListModCfm,
    &ett_ngap_PDUSessionResourceFailedToModifyItemModCfm,
    &ett_ngap_PDUSessionResourceFailedToModifyListModRes,
    &ett_ngap_PDUSessionResourceFailedToModifyItemModRes,
    &ett_ngap_PDUSessionResourceFailedToSetupListCxtFail,
    &ett_ngap_PDUSessionResourceFailedToSetupItemCxtFail,
    &ett_ngap_PDUSessionResourceFailedToSetupListCxtRes,
    &ett_ngap_PDUSessionResourceFailedToSetupItemCxtRes,
    &ett_ngap_PDUSessionResourceFailedToSetupListHOAck,
    &ett_ngap_PDUSessionResourceFailedToSetupItemHOAck,
    &ett_ngap_PDUSessionResourceFailedToSetupListPSReq,
    &ett_ngap_PDUSessionResourceFailedToSetupItemPSReq,
    &ett_ngap_PDUSessionResourceFailedToSetupListSURes,
    &ett_ngap_PDUSessionResourceFailedToSetupItemSURes,
    &ett_ngap_PDUSessionResourceHandoverList,
    &ett_ngap_PDUSessionResourceHandoverItem,
    &ett_ngap_PDUSessionResourceInformationList,
    &ett_ngap_PDUSessionResourceInformationItem,
    &ett_ngap_PDUSessionResourceListCxtRelCpl,
    &ett_ngap_PDUSessionResourceItemCxtRelCpl,
    &ett_ngap_PDUSessionResourceListCxtRelReq,
    &ett_ngap_PDUSessionResourceItemCxtRelReq,
    &ett_ngap_PDUSessionResourceListHORqd,
    &ett_ngap_PDUSessionResourceItemHORqd,
    &ett_ngap_PDUSessionResourceModifyConfirmTransfer,
    &ett_ngap_PDUSessionResourceModifyIndicationUnsuccessfulTransfer,
    &ett_ngap_PDUSessionResourceModifyRequestTransfer,
    &ett_ngap_PDUSessionResourceModifyResponseTransfer,
    &ett_ngap_PDUSessionResourceModifyIndicationTransfer,
    &ett_ngap_PDUSessionResourceModifyListModCfm,
    &ett_ngap_PDUSessionResourceModifyItemModCfm,
    &ett_ngap_PDUSessionResourceModifyListModInd,
    &ett_ngap_PDUSessionResourceModifyItemModInd,
    &ett_ngap_PDUSessionResourceModifyListModReq,
    &ett_ngap_PDUSessionResourceModifyItemModReq,
    &ett_ngap_PDUSessionResourceModifyListModRes,
    &ett_ngap_PDUSessionResourceModifyItemModRes,
    &ett_ngap_PDUSessionResourceModifyUnsuccessfulTransfer,
    &ett_ngap_PDUSessionResourceNotifyList,
    &ett_ngap_PDUSessionResourceNotifyItem,
    &ett_ngap_PDUSessionResourceNotifyReleasedTransfer,
    &ett_ngap_PDUSessionResourceNotifyTransfer,
    &ett_ngap_PDUSessionResourceReleaseCommandTransfer,
    &ett_ngap_PDUSessionResourceReleasedListNot,
    &ett_ngap_PDUSessionResourceReleasedItemNot,
    &ett_ngap_PDUSessionResourceReleasedListPSAck,
    &ett_ngap_PDUSessionResourceReleasedItemPSAck,
    &ett_ngap_PDUSessionResourceReleasedListPSFail,
    &ett_ngap_PDUSessionResourceReleasedItemPSFail,
    &ett_ngap_PDUSessionResourceReleasedListRelRes,
    &ett_ngap_PDUSessionResourceReleasedItemRelRes,
    &ett_ngap_PDUSessionResourceReleaseResponseTransfer,
    &ett_ngap_PDUSessionResourceSecondaryRATUsageList,
    &ett_ngap_PDUSessionResourceSecondaryRATUsageItem,
    &ett_ngap_PDUSessionResourceSetupListCxtReq,
    &ett_ngap_PDUSessionResourceSetupItemCxtReq,
    &ett_ngap_PDUSessionResourceSetupListCxtRes,
    &ett_ngap_PDUSessionResourceSetupItemCxtRes,
    &ett_ngap_PDUSessionResourceSetupListHOReq,
    &ett_ngap_PDUSessionResourceSetupItemHOReq,
    &ett_ngap_PDUSessionResourceSetupListSUReq,
    &ett_ngap_PDUSessionResourceSetupItemSUReq,
    &ett_ngap_PDUSessionResourceSetupListSURes,
    &ett_ngap_PDUSessionResourceSetupItemSURes,
    &ett_ngap_PDUSessionResourceSetupRequestTransfer,
    &ett_ngap_PDUSessionResourceSetupResponseTransfer,
    &ett_ngap_PDUSessionResourceSetupUnsuccessfulTransfer,
    &ett_ngap_PDUSessionResourceSwitchedList,
    &ett_ngap_PDUSessionResourceSwitchedItem,
    &ett_ngap_PDUSessionResourceToBeSwitchedDLList,
    &ett_ngap_PDUSessionResourceToBeSwitchedDLItem,
    &ett_ngap_PDUSessionResourceToReleaseListHOCmd,
    &ett_ngap_PDUSessionResourceToReleaseItemHOCmd,
    &ett_ngap_PDUSessionResourceToReleaseListRelCmd,
    &ett_ngap_PDUSessionResourceToReleaseItemRelCmd,
    &ett_ngap_PDUSessionUsageReport,
    &ett_ngap_PLMNSupportList,
    &ett_ngap_PLMNSupportItem,
    &ett_ngap_PWSFailedCellIDList,
    &ett_ngap_QosCharacteristics,
    &ett_ngap_QosFlowAcceptedList,
    &ett_ngap_QosFlowAcceptedItem,
    &ett_ngap_QosFlowAddOrModifyRequestList,
    &ett_ngap_QosFlowAddOrModifyRequestItem,
    &ett_ngap_QosFlowAddOrModifyResponseList,
    &ett_ngap_QosFlowAddOrModifyResponseItem,
    &ett_ngap_QosFlowInformationList,
    &ett_ngap_QosFlowInformationItem,
    &ett_ngap_QosFlowLevelQosParameters,
    &ett_ngap_QosFlowListWithCause,
    &ett_ngap_QosFlowWithCauseItem,
    &ett_ngap_QosFlowModifyConfirmList,
    &ett_ngap_QosFlowModifyConfirmItem,
    &ett_ngap_QosFlowNotifyList,
    &ett_ngap_QosFlowNotifyItem,
    &ett_ngap_QosFlowPerTNLInformation,
    &ett_ngap_QosFlowPerTNLInformationList,
    &ett_ngap_QosFlowPerTNLInformationItem,
    &ett_ngap_QosFlowSetupRequestList,
    &ett_ngap_QosFlowSetupRequestItem,
    &ett_ngap_QosFlowListWithDataForwarding,
    &ett_ngap_QosFlowItemWithDataForwarding,
    &ett_ngap_QosFlowToBeForwardedList,
    &ett_ngap_QosFlowToBeForwardedItem,
    &ett_ngap_QoSFlowsUsageReportList,
    &ett_ngap_QoSFlowsUsageReport_Item,
    &ett_ngap_RANStatusTransfer_TransparentContainer,
    &ett_ngap_RATRestrictions,
    &ett_ngap_RATRestrictions_Item,
    &ett_ngap_RecommendedCellsForPaging,
    &ett_ngap_RecommendedCellList,
    &ett_ngap_RecommendedCellItem,
    &ett_ngap_RecommendedRANNodesForPaging,
    &ett_ngap_RecommendedRANNodeList,
    &ett_ngap_RecommendedRANNodeItem,
    &ett_ngap_ResetType,
    &ett_ngap_SCTP_TLAs,
    &ett_ngap_SecondaryRATUsageInformation,
    &ett_ngap_SecondaryRATDataUsageReportTransfer,
    &ett_ngap_SecurityContext,
    &ett_ngap_SecurityIndication,
    &ett_ngap_SecurityResult,
    &ett_ngap_ServedGUAMIList,
    &ett_ngap_ServedGUAMIItem,
    &ett_ngap_ServiceAreaInformation,
    &ett_ngap_ServiceAreaInformation_Item,
    &ett_ngap_SliceOverloadList,
    &ett_ngap_SliceOverloadItem,
    &ett_ngap_SliceSupportList,
    &ett_ngap_SliceSupportItem,
    &ett_ngap_S_NSSAI,
    &ett_ngap_SONConfigurationTransfer,
    &ett_ngap_SONInformation,
    &ett_ngap_SONInformationReply,
    &ett_ngap_SourceNGRANNode_ToTargetNGRANNode_TransparentContainer,
    &ett_ngap_SourceRANNodeID,
    &ett_ngap_SourceToTarget_AMFInformationReroute,
    &ett_ngap_SupportedTAList,
    &ett_ngap_SupportedTAItem,
    &ett_ngap_TAI,
    &ett_ngap_TAIBroadcastEUTRA,
    &ett_ngap_TAIBroadcastEUTRA_Item,
    &ett_ngap_TAIBroadcastNR,
    &ett_ngap_TAIBroadcastNR_Item,
    &ett_ngap_TAICancelledEUTRA,
    &ett_ngap_TAICancelledEUTRA_Item,
    &ett_ngap_TAICancelledNR,
    &ett_ngap_TAICancelledNR_Item,
    &ett_ngap_TAIListForInactive,
    &ett_ngap_TAIListForInactiveItem,
    &ett_ngap_TAIListForPaging,
    &ett_ngap_TAIListForPagingItem,
    &ett_ngap_TAIListForRestart,
    &ett_ngap_TAIListForWarning,
    &ett_ngap_TargeteNB_ID,
    &ett_ngap_TargetID,
    &ett_ngap_TargetNGRANNode_ToSourceNGRANNode_TransparentContainer,
    &ett_ngap_TargetRANNodeID,
    &ett_ngap_TNLAssociationList,
    &ett_ngap_TNLAssociationItem,
    &ett_ngap_TraceActivation,
    &ett_ngap_UEAggregateMaximumBitRate,
    &ett_ngap_UE_associatedLogicalNG_connectionList,
    &ett_ngap_UE_associatedLogicalNG_connectionItem,
    &ett_ngap_UEHistoryInformation,
    &ett_ngap_UEIdentityIndexValue,
    &ett_ngap_UE_NGAP_IDs,
    &ett_ngap_UE_NGAP_ID_pair,
    &ett_ngap_UEPagingIdentity,
    &ett_ngap_UEPresenceInAreaOfInterestList,
    &ett_ngap_UEPresenceInAreaOfInterestItem,
    &ett_ngap_UERadioCapabilityForPaging,
    &ett_ngap_UESecurityCapabilities,
    &ett_ngap_UL_NGU_UP_TNLModifyList,
    &ett_ngap_UL_NGU_UP_TNLModifyItem,
    &ett_ngap_UnavailableGUAMIList,
    &ett_ngap_UnavailableGUAMIItem,
    &ett_ngap_UPTransportLayerInformation,
    &ett_ngap_UPTransportLayerInformationList,
    &ett_ngap_UPTransportLayerInformationItem,
    &ett_ngap_UPTransportLayerInformationPairList,
    &ett_ngap_UPTransportLayerInformationPairItem,
    &ett_ngap_UserLocationInformation,
    &ett_ngap_UserLocationInformationEUTRA,
    &ett_ngap_UserLocationInformationN3IWF,
    &ett_ngap_UserLocationInformationNR,
    &ett_ngap_UserPlaneSecurityInformation,
    &ett_ngap_VolumeTimedReportList,
    &ett_ngap_VolumeTimedReport_Item,
    &ett_ngap_WarningAreaList,
    &ett_ngap_XnExtTLAs,
    &ett_ngap_XnExtTLA_Item,
    &ett_ngap_XnGTP_TLAs,
    &ett_ngap_XnTLAs,
    &ett_ngap_XnTNLConfigurationInfo,
    &ett_ngap_PDUSessionResourceSetupRequest,
    &ett_ngap_PDUSessionResourceSetupResponse,
    &ett_ngap_PDUSessionResourceReleaseCommand,
    &ett_ngap_PDUSessionResourceReleaseResponse,
    &ett_ngap_PDUSessionResourceModifyRequest,
    &ett_ngap_PDUSessionResourceModifyResponse,
    &ett_ngap_PDUSessionResourceNotify,
    &ett_ngap_PDUSessionResourceModifyIndication,
    &ett_ngap_PDUSessionResourceModifyConfirm,
    &ett_ngap_InitialContextSetupRequest,
    &ett_ngap_InitialContextSetupResponse,
    &ett_ngap_InitialContextSetupFailure,
    &ett_ngap_UEContextReleaseRequest,
    &ett_ngap_UEContextReleaseCommand,
    &ett_ngap_UEContextReleaseComplete,
    &ett_ngap_UEContextModificationRequest,
    &ett_ngap_UEContextModificationResponse,
    &ett_ngap_UEContextModificationFailure,
    &ett_ngap_RRCInactiveTransitionReport,
    &ett_ngap_HandoverRequired,
    &ett_ngap_HandoverCommand,
    &ett_ngap_HandoverPreparationFailure,
    &ett_ngap_HandoverRequest,
    &ett_ngap_HandoverRequestAcknowledge,
    &ett_ngap_HandoverFailure,
    &ett_ngap_HandoverNotify,
    &ett_ngap_PathSwitchRequest,
    &ett_ngap_PathSwitchRequestAcknowledge,
    &ett_ngap_PathSwitchRequestFailure,
    &ett_ngap_HandoverCancel,
    &ett_ngap_HandoverCancelAcknowledge,
    &ett_ngap_UplinkRANStatusTransfer,
    &ett_ngap_DownlinkRANStatusTransfer,
    &ett_ngap_Paging,
    &ett_ngap_InitialUEMessage,
    &ett_ngap_DownlinkNASTransport,
    &ett_ngap_UplinkNASTransport,
    &ett_ngap_NASNonDeliveryIndication,
    &ett_ngap_RerouteNASRequest,
    &ett_ngap_NGSetupRequest,
    &ett_ngap_NGSetupResponse,
    &ett_ngap_NGSetupFailure,
    &ett_ngap_RANConfigurationUpdate,
    &ett_ngap_RANConfigurationUpdateAcknowledge,
    &ett_ngap_RANConfigurationUpdateFailure,
    &ett_ngap_AMFConfigurationUpdate,
    &ett_ngap_AMFConfigurationUpdateAcknowledge,
    &ett_ngap_AMFConfigurationUpdateFailure,
    &ett_ngap_AMFStatusIndication,
    &ett_ngap_NGReset,
    &ett_ngap_NGResetAcknowledge,
    &ett_ngap_ErrorIndication,
    &ett_ngap_OverloadStart,
    &ett_ngap_OverloadStop,
    &ett_ngap_UplinkRANConfigurationTransfer,
    &ett_ngap_DownlinkRANConfigurationTransfer,
    &ett_ngap_WriteReplaceWarningRequest,
    &ett_ngap_WriteReplaceWarningResponse,
    &ett_ngap_PWSCancelRequest,
    &ett_ngap_PWSCancelResponse,
    &ett_ngap_PWSRestartIndication,
    &ett_ngap_PWSFailureIndication,
    &ett_ngap_DownlinkUEAssociatedNRPPaTransport,
    &ett_ngap_UplinkUEAssociatedNRPPaTransport,
    &ett_ngap_DownlinkNonUEAssociatedNRPPaTransport,
    &ett_ngap_UplinkNonUEAssociatedNRPPaTransport,
    &ett_ngap_TraceStart,
    &ett_ngap_TraceFailureIndication,
    &ett_ngap_DeactivateTrace,
    &ett_ngap_CellTrafficTrace,
    &ett_ngap_LocationReportingControl,
    &ett_ngap_LocationReportingFailureIndication,
    &ett_ngap_LocationReport,
    &ett_ngap_UETNLABindingReleaseRequest,
    &ett_ngap_UERadioCapabilityInfoIndication,
    &ett_ngap_UERadioCapabilityCheckRequest,
    &ett_ngap_UERadioCapabilityCheckResponse,
    &ett_ngap_PrivateMessage,
    &ett_ngap_SecondaryRATDataUsageReport,
    &ett_ngap_NGAP_PDU,
    &ett_ngap_InitiatingMessage,
    &ett_ngap_SuccessfulOutcome,
    &ett_ngap_UnsuccessfulOutcome,

/*--- End of included file: packet-ngap-ettarr.c ---*/
#line 764 "./asn1/ngap/packet-ngap-template.c"
  };

  static ei_register_info ei[] = {
    { &ei_ngap_number_pages_le15, { "ngap.number_pages_le15", PI_MALFORMED, PI_ERROR, "Number of pages should be <=15", EXPFILL }}
  };

  module_t *ngap_module;
  expert_module_t* expert_ngap;

  /* Register protocol */
  proto_ngap = proto_register_protocol(PNAME, PSNAME, PFNAME);
  /* Register fields and subtrees */
  proto_register_field_array(proto_ngap, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));
  expert_ngap = expert_register_protocol(proto_ngap);
  expert_register_field_array(expert_ngap, ei, array_length(ei));

  /* Register dissector */
  ngap_handle = register_dissector("ngap", dissect_ngap, proto_ngap);
  ngap_media_type_handle = register_dissector("ngap_media_type", dissect_ngap_media_type, proto_ngap);

  /* Register dissector tables */
  ngap_ies_dissector_table = register_dissector_table("ngap.ies", "NGAP-PROTOCOL-IES", proto_ngap, FT_UINT32, BASE_DEC);
  ngap_ies_p1_dissector_table = register_dissector_table("ngap.ies.pair.first", "NGAP-PROTOCOL-IES-PAIR FirstValue", proto_ngap, FT_UINT32, BASE_DEC);
  ngap_ies_p2_dissector_table = register_dissector_table("ngap.ies.pair.second", "NGAP-PROTOCOL-IES-PAIR SecondValue", proto_ngap, FT_UINT32, BASE_DEC);
  ngap_extension_dissector_table = register_dissector_table("ngap.extension", "NGAP-PROTOCOL-EXTENSION", proto_ngap, FT_UINT32, BASE_DEC);
  ngap_proc_imsg_dissector_table = register_dissector_table("ngap.proc.imsg", "NGAP-ELEMENTARY-PROCEDURE InitiatingMessage", proto_ngap, FT_UINT32, BASE_DEC);
  ngap_proc_sout_dissector_table = register_dissector_table("ngap.proc.sout", "NGAP-ELEMENTARY-PROCEDURE SuccessfulOutcome", proto_ngap, FT_UINT32, BASE_DEC);
  ngap_proc_uout_dissector_table = register_dissector_table("ngap.proc.uout", "NGAP-ELEMENTARY-PROCEDURE UnsuccessfulOutcome", proto_ngap, FT_UINT32, BASE_DEC);
  ngap_n2_ie_type_dissector_table = register_dissector_table("ngap.n2_ie_type", "NGAP N2 IE Type", proto_ngap, FT_STRING, FALSE);

  /* Register configuration options for ports */
  ngap_module = prefs_register_protocol(proto_ngap, proto_reg_handoff_ngap);

  prefs_register_uint_preference(ngap_module, "sctp.port",
                                 "NGAP SCTP Port",
                                 "Set the SCTP port for NGAP messages",
                                 10,
                                 &gbl_ngapSctpPort);
  prefs_register_bool_preference(ngap_module, "dissect_container",
                                 "Dissect TransparentContainer",
                                 "Dissect TransparentContainers that are opaque to NGAP",
                                 &ngap_dissect_container);
  prefs_register_enum_preference(ngap_module, "dissect_target_ng_ran_container_as",
                                 "Dissect target NG-RAN container as",
                                 "Select whether target NG-RAN container should be decoded automatically"
                                 " (based on NG Setup procedure) or manually",
                                 &ngap_dissect_target_ng_ran_container_as, ngap_target_ng_ran_container_vals, FALSE);
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
