/* Do not modify this file. Changes will be overwritten.                      */
/* Generated automatically by the ASN.1 to Wireshark dissector compiler       */
/* packet-xnap.c                                                              */
/* asn2wrs.py -p xnap -c ./xnap.cnf -s ./packet-xnap-template -D . -O ../.. XnAP-CommonDataTypes.asn XnAP-Constants.asn XnAP-Containers.asn XnAP-IEs.asn XnAP-PDU-Contents.asn XnAP-PDU-Descriptions.asn */

/* Input file: packet-xnap-template.c */

#line 1 "./asn1/xnap/packet-xnap-template.c"
/* packet-xnap.c
 * Routines for dissecting NG-RAN Xn application protocol (XnAP)
 * 3GPP TS 38.423 packet dissection
 * Copyright 2018-2019, Pascal Quantin <pascal@wireshark.org>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * Ref:
 * 3GPP TS 38.423 V15.7.0 (2020-03)
 */

#include "config.h"

#include <epan/packet.h>
#include <epan/asn1.h>
#include <epan/prefs.h>
#include <epan/sctpppids.h>
#include <epan/proto_data.h>
#include <epan/conversation.h>

#include "packet-per.h"
#include "packet-lte-rrc.h"
#include "packet-nr-rrc.h"
#include "packet-e212.h"
#include "packet-ngap.h"
#include "packet-s1ap.h"
#include "packet-ranap.h"
#include "packet-ntp.h"

#ifdef _MSC_VER
/* disable: "warning C4146: unary minus operator applied to unsigned type, result still unsigned" */
#pragma warning(disable:4146)
#endif

#define PNAME  "NG-RAN Xn Application Protocol (XnAP)"
#define PSNAME "XnAP"
#define PFNAME "xnap"

/* Dissector will use SCTP PPID 61 or SCTP port. IANA assigned port = 38422 */
#define SCTP_PORT_XnAP	38422


/*--- Included file: packet-xnap-val.h ---*/
#line 1 "./asn1/xnap/packet-xnap-val.h"
#define maxPrivateIEs                  65535
#define maxProtocolExtensions          65535
#define maxProtocolIEs                 65535
#define maxEARFCN                      262143
#define maxnoofAllowedAreas            16
#define maxnoofAMFRegions              16
#define maxnoofAoIs                    64
#define maxnoofBPLMNs                  12
#define maxnoofCellsinAoI              256
#define maxnoofCellsinUEHistoryInfo    16
#define maxnoofCellsinNG_RANnode       16384
#define maxnoofCellsinRNA              32
#define maxnoofCellsUEMovingTrajectory 16
#define maxnoofDRBs                    32
#define maxnoofEUTRABands              16
#define maxnoofEUTRABPLMNs             6
#define maxnoofEPLMNs                  15
#define maxnoofForbiddenTACs           4096
#define maxnoofMBSFNEUTRA              8
#define maxnoofMultiConnectivityMinusOne 3
#define maxnoofNeighbours              1024
#define maxnoofNRCellBands             32
#define maxnoofPLMNs                   16
#define maxnoofPDUSessions             256
#define maxnoofProtectedResourcePatterns 16
#define maxnoofQoSFlows                64
#define maxnoofRANAreaCodes            32
#define maxnoofRANAreasinRNA           16
#define maxnoofRANNodesinAoI           64
#define maxnoofSCellGroups             3
#define maxnoofSCellGroupsplus1        4
#define maxnoofSliceItems              1024
#define maxnoofsupportedPLMNs          12
#define maxnoofsupportedTACs           256
#define maxnoofTAI                     16
#define maxnoofTAIsinAoI               16
#define maxnooftimeperiods             2
#define maxnoofTNLAssociations         32
#define maxnoofUEContexts              8192
#define maxNRARFCN                     3279165
#define maxNrOfErrors                  256

typedef enum _ProcedureCode_enum {
  id_handoverPreparation =   0,
  id_sNStatusTransfer =   1,
  id_handoverCancel =   2,
  id_retrieveUEContext =   3,
  id_rANPaging =   4,
  id_xnUAddressIndication =   5,
  id_uEContextRelease =   6,
  id_sNGRANnodeAdditionPreparation =   7,
  id_sNGRANnodeReconfigurationCompletion =   8,
  id_mNGRANnodeinitiatedSNGRANnodeModificationPreparation =   9,
  id_sNGRANnodeinitiatedSNGRANnodeModificationPreparation =  10,
  id_mNGRANnodeinitiatedSNGRANnodeRelease =  11,
  id_sNGRANnodeinitiatedSNGRANnodeRelease =  12,
  id_sNGRANnodeCounterCheck =  13,
  id_sNGRANnodeChange =  14,
  id_rRCTransfer =  15,
  id_xnRemoval =  16,
  id_xnSetup   =  17,
  id_nGRANnodeConfigurationUpdate =  18,
  id_cellActivation =  19,
  id_reset     =  20,
  id_errorIndication =  21,
  id_privateMessage =  22,
  id_notificationControl =  23,
  id_activityNotification =  24,
  id_e_UTRA_NR_CellResourceCoordination =  25,
  id_secondaryRATDataUsageReport =  26
} ProcedureCode_enum;

typedef enum _ProtocolIE_ID_enum {
  id_ActivatedServedCells =   0,
  id_ActivationIDforCellActivation =   1,
  id_admittedSplitSRB =   2,
  id_admittedSplitSRBrelease =   3,
  id_AMF_Region_Information =   4,
  id_AssistanceDataForRANPaging =   5,
  id_BearersSubjectToCounterCheck =   6,
  id_Cause     =   7,
  id_cellAssistanceInfo_NR =   8,
  id_ConfigurationUpdateInitiatingNodeChoice =   9,
  id_CriticalityDiagnostics =  10,
  id_XnUAddressInfoperPDUSession_List =  11,
  id_DRBsSubjectToStatusTransfer_List =  12,
  id_ExpectedUEBehaviour =  13,
  id_GlobalNG_RAN_node_ID =  14,
  id_GUAMI     =  15,
  id_indexToRatFrequSelectionPriority =  16,
  id_initiatingNodeType_ResourceCoordRequest =  17,
  id_List_of_served_cells_E_UTRA =  18,
  id_List_of_served_cells_NR =  19,
  id_LocationReportingInformation =  20,
  id_MAC_I     =  21,
  id_MaskedIMEISV =  22,
  id_M_NG_RANnodeUEXnAPID =  23,
  id_MN_to_SN_Container =  24,
  id_MobilityRestrictionList =  25,
  id_new_NG_RAN_Cell_Identity =  26,
  id_newNG_RANnodeUEXnAPID =  27,
  id_UEReportRRCTransfer =  28,
  id_oldNG_RANnodeUEXnAPID =  29,
  id_OldtoNewNG_RANnodeResumeContainer =  30,
  id_PagingDRX =  31,
  id_PCellID   =  32,
  id_PDCPChangeIndication =  33,
  id_PDUSessionAdmittedAddedAddReqAck =  34,
  id_PDUSessionAdmittedModSNModConfirm =  35,
  id_PDUSessionAdmitted_SNModResponse =  36,
  id_PDUSessionNotAdmittedAddReqAck =  37,
  id_PDUSessionNotAdmitted_SNModResponse =  38,
  id_PDUSessionReleasedList_RelConf =  39,
  id_PDUSessionReleasedSNModConfirm =  40,
  id_PDUSessionResourcesActivityNotifyList =  41,
  id_PDUSessionResourcesAdmitted_List =  42,
  id_PDUSessionResourcesNotAdmitted_List =  43,
  id_PDUSessionResourcesNotifyList =  44,
  id_PDUSession_SNChangeConfirm_List =  45,
  id_PDUSession_SNChangeRequired_List =  46,
  id_PDUSessionToBeAddedAddReq =  47,
  id_PDUSessionToBeModifiedSNModRequired =  48,
  id_PDUSessionToBeReleasedList_RelRqd =  49,
  id_PDUSessionToBeReleased_RelReq =  50,
  id_PDUSessionToBeReleasedSNModRequired =  51,
  id_RANPagingArea =  52,
  id_PagingPriority =  53,
  id_requestedSplitSRB =  54,
  id_requestedSplitSRBrelease =  55,
  id_ResetRequestTypeInfo =  56,
  id_ResetResponseTypeInfo =  57,
  id_RespondingNodeTypeConfigUpdateAck =  58,
  id_respondingNodeType_ResourceCoordResponse =  59,
  id_ResponseInfo_ReconfCompl =  60,
  id_RRCConfigIndication =  61,
  id_RRCResumeCause =  62,
  id_SCGConfigurationQuery =  63,
  id_selectedPLMN =  64,
  id_ServedCellsToActivate =  65,
  id_servedCellsToUpdate_E_UTRA =  66,
  id_ServedCellsToUpdateInitiatingNodeChoice =  67,
  id_servedCellsToUpdate_NR =  68,
  id_s_ng_RANnode_SecurityKey =  69,
  id_S_NG_RANnodeUE_AMBR =  70,
  id_S_NG_RANnodeUEXnAPID =  71,
  id_SN_to_MN_Container =  72,
  id_sourceNG_RANnodeUEXnAPID =  73,
  id_SplitSRB_RRCTransfer =  74,
  id_TAISupport_list =  75,
  id_TimeToWait =  76,
  id_Target2SourceNG_RANnodeTranspContainer =  77,
  id_targetCellGlobalID =  78,
  id_targetNG_RANnodeUEXnAPID =  79,
  id_target_S_NG_RANnodeID =  80,
  id_TraceActivation =  81,
  id_UEContextID =  82,
  id_UEContextInfoHORequest =  83,
  id_UEContextInfoRetrUECtxtResp =  84,
  id_UEContextInfo_SNModRequest =  85,
  id_UEContextKeptIndicator =  86,
  id_UEContextRefAtSN_HORequest =  87,
  id_UEHistoryInformation =  88,
  id_UEIdentityIndexValue =  89,
  id_UERANPagingIdentity =  90,
  id_UESecurityCapabilities =  91,
  id_UserPlaneTrafficActivityReport =  92,
  id_XnRemovalThreshold =  93,
  id_DesiredActNotificationLevel =  94,
  id_AvailableDRBIDs =  95,
  id_AdditionalDRBIDs =  96,
  id_SpareDRBIDs =  97,
  id_RequiredNumberOfDRBIDs =  98,
  id_TNLA_To_Add_List =  99,
  id_TNLA_To_Update_List = 100,
  id_TNLA_To_Remove_List = 101,
  id_TNLA_Setup_List = 102,
  id_TNLA_Failed_To_Setup_List = 103,
  id_PDUSessionToBeReleased_RelReqAck = 104,
  id_S_NG_RANnodeMaxIPDataRate_UL = 105,
  id_Unknown_106 = 106,
  id_PDUSessionResourceSecondaryRATUsageList = 107,
  id_Additional_UL_NG_U_TNLatUPF_List = 108,
  id_SecondarydataForwardingInfoFromTarget_List = 109,
  id_LocationInformationSNReporting = 110,
  id_LocationInformationSN = 111,
  id_LastE_UTRANPLMNIdentity = 112,
  id_S_NG_RANnodeMaxIPDataRate_DL = 113,
  id_MaxIPrate_DL = 114,
  id_SecurityResult = 115,
  id_S_NSSAI   = 116,
  id_MR_DC_ResourceCoordinationInfo = 117,
  id_AMF_Region_Information_To_Add = 118,
  id_AMF_Region_Information_To_Delete = 119,
  id_OldQoSFlowMap_ULendmarkerexpected = 120,
  id_RANPagingFailure = 121,
  id_UERadioCapabilityForPaging = 122,
  id_PDUSessionDataForwarding_SNModResponse = 123,
  id_DRBsNotAdmittedSetupModifyList = 124,
  id_Secondary_MN_Xn_U_TNLInfoatM = 125,
  id_NE_DC_TDM_Pattern = 126,
  id_PDUSessionCommonNetworkInstance = 127,
  id_BPLMN_ID_Info_EUTRA = 128,
  id_BPLMN_ID_Info_NR = 129,
  id_InterfaceInstanceIndication = 130,
  id_S_NG_RANnode_Addition_Trigger_Ind = 131,
  id_DefaultDRB_Allowed = 132,
  id_DRB_IDs_takenintouse = 133,
  id_SplitSessionIndicator = 134,
  id_CNTypeRestrictionsForEquivalent = 135,
  id_CNTypeRestrictionsForServing = 136,
  id_DRBs_transferred_to_MN = 137,
  id_ULForwardingProposal = 138,
  id_EndpointIPAddressAndPort = 139,
  id_Unknown_140 = 140,
  id_Unknown_141 = 141,
  id_Unknown_142 = 142,
  id_Unknown_143 = 143,
  id_Unknown_144 = 144,
  id_Unknown_145 = 145,
  id_Unknown_146 = 146,
  id_Unknown_147 = 147,
  id_Unknown_148 = 148,
  id_Unknown_149 = 149,
  id_Unknown_150 = 150,
  id_Unknown_151 = 151,
  id_Unknown_152 = 152,
  id_Unknown_153 = 153,
  id_Unknown_154 = 154,
  id_FiveGCMobilityRestrictionListContainer = 155
} ProtocolIE_ID_enum;

typedef enum _GlobalNG_RANNode_ID_enum {
  GlobalNG_RANNode_ID_gNB =   0,
  GlobalNG_RANNode_ID_ng_eNB =   1,
  GlobalNG_RANNode_ID_choice_extension =   2
} GlobalNG_RANNode_ID_enum;

/*--- End of included file: packet-xnap-val.h ---*/
#line 47 "./asn1/xnap/packet-xnap-template.c"

/* Initialize the protocol and registered fields */
static int proto_xnap = -1;
static int hf_xnap_transportLayerAddressIPv4 = -1;
static int hf_xnap_transportLayerAddressIPv6 = -1;
static int hf_xnap_ng_ran_TraceID_TraceID = -1;
static int hf_xnap_ng_ran_TraceID_TraceRecordingSessionReference = -1;

/*--- Included file: packet-xnap-hf.c ---*/
#line 1 "./asn1/xnap/packet-xnap-hf.c"
static int hf_xnap_Additional_UL_NG_U_TNLatUPF_List_PDU = -1;  /* Additional_UL_NG_U_TNLatUPF_List */
static int hf_xnap_ActivationIDforCellActivation_PDU = -1;  /* ActivationIDforCellActivation */
static int hf_xnap_AMF_Region_Information_PDU = -1;  /* AMF_Region_Information */
static int hf_xnap_AssistanceDataForRANPaging_PDU = -1;  /* AssistanceDataForRANPaging */
static int hf_xnap_BPLMN_ID_Info_EUTRA_PDU = -1;  /* BPLMN_ID_Info_EUTRA */
static int hf_xnap_BPLMN_ID_Info_NR_PDU = -1;     /* BPLMN_ID_Info_NR */
static int hf_xnap_BitRate_PDU = -1;              /* BitRate */
static int hf_xnap_Cause_PDU = -1;                /* Cause */
static int hf_xnap_CellAssistanceInfo_NR_PDU = -1;  /* CellAssistanceInfo_NR */
static int hf_xnap_CriticalityDiagnostics_PDU = -1;  /* CriticalityDiagnostics */
static int hf_xnap_XnUAddressInfoperPDUSession_List_PDU = -1;  /* XnUAddressInfoperPDUSession_List */
static int hf_xnap_DesiredActNotificationLevel_PDU = -1;  /* DesiredActNotificationLevel */
static int hf_xnap_DefaultDRB_Allowed_PDU = -1;   /* DefaultDRB_Allowed */
static int hf_xnap_DRB_List_PDU = -1;             /* DRB_List */
static int hf_xnap_DRB_List_withCause_PDU = -1;   /* DRB_List_withCause */
static int hf_xnap_DRB_Number_PDU = -1;           /* DRB_Number */
static int hf_xnap_DRBsSubjectToStatusTransfer_List_PDU = -1;  /* DRBsSubjectToStatusTransfer_List */
static int hf_xnap_EndpointIPAddressAndPort_PDU = -1;  /* EndpointIPAddressAndPort */
static int hf_xnap_ExpectedUEBehaviour_PDU = -1;  /* ExpectedUEBehaviour */
static int hf_xnap_FiveGCMobilityRestrictionListContainer_PDU = -1;  /* FiveGCMobilityRestrictionListContainer */
static int hf_xnap_GlobalNG_RANCell_ID_PDU = -1;  /* GlobalNG_RANCell_ID */
static int hf_xnap_GlobalNG_RANNode_ID_PDU = -1;  /* GlobalNG_RANNode_ID */
static int hf_xnap_GUAMI_PDU = -1;                /* GUAMI */
static int hf_xnap_InterfaceInstanceIndication_PDU = -1;  /* InterfaceInstanceIndication */
static int hf_xnap_LocationInformationSNReporting_PDU = -1;  /* LocationInformationSNReporting */
static int hf_xnap_LocationReportingInformation_PDU = -1;  /* LocationReportingInformation */
static int hf_xnap_MAC_I_PDU = -1;                /* MAC_I */
static int hf_xnap_MaskedIMEISV_PDU = -1;         /* MaskedIMEISV */
static int hf_xnap_MaxIPrate_PDU = -1;            /* MaxIPrate */
static int hf_xnap_MobilityRestrictionList_PDU = -1;  /* MobilityRestrictionList */
static int hf_xnap_CNTypeRestrictionsForEquivalent_PDU = -1;  /* CNTypeRestrictionsForEquivalent */
static int hf_xnap_CNTypeRestrictionsForServing_PDU = -1;  /* CNTypeRestrictionsForServing */
static int hf_xnap_MR_DC_ResourceCoordinationInfo_PDU = -1;  /* MR_DC_ResourceCoordinationInfo */
static int hf_xnap_NE_DC_TDM_Pattern_PDU = -1;    /* NE_DC_TDM_Pattern */
static int hf_xnap_NG_RAN_Cell_Identity_PDU = -1;  /* NG_RAN_Cell_Identity */
static int hf_xnap_NG_RANnodeUEXnAPID_PDU = -1;   /* NG_RANnodeUEXnAPID */
static int hf_xnap_PagingDRX_PDU = -1;            /* PagingDRX */
static int hf_xnap_PagingPriority_PDU = -1;       /* PagingPriority */
static int hf_xnap_PDCPChangeIndication_PDU = -1;  /* PDCPChangeIndication */
static int hf_xnap_PDUSession_List_withCause_PDU = -1;  /* PDUSession_List_withCause */
static int hf_xnap_PDUSessionResourcesAdmitted_List_PDU = -1;  /* PDUSessionResourcesAdmitted_List */
static int hf_xnap_PDUSessionResourcesNotAdmitted_List_PDU = -1;  /* PDUSessionResourcesNotAdmitted_List */
static int hf_xnap_PDUSessionResourceSecondaryRATUsageList_PDU = -1;  /* PDUSessionResourceSecondaryRATUsageList */
static int hf_xnap_PDUSessionCommonNetworkInstance_PDU = -1;  /* PDUSessionCommonNetworkInstance */
static int hf_xnap_PLMN_Identity_PDU = -1;        /* PLMN_Identity */
static int hf_xnap_QoSFlows_List_PDU = -1;        /* QoSFlows_List */
static int hf_xnap_RANPagingArea_PDU = -1;        /* RANPagingArea */
static int hf_xnap_RANPagingFailure_PDU = -1;     /* RANPagingFailure */
static int hf_xnap_ResetRequestTypeInfo_PDU = -1;  /* ResetRequestTypeInfo */
static int hf_xnap_ResetResponseTypeInfo_PDU = -1;  /* ResetResponseTypeInfo */
static int hf_xnap_RFSP_Index_PDU = -1;           /* RFSP_Index */
static int hf_xnap_RRCConfigIndication_PDU = -1;  /* RRCConfigIndication */
static int hf_xnap_RRCResumeCause_PDU = -1;       /* RRCResumeCause */
static int hf_xnap_SecondarydataForwardingInfoFromTarget_List_PDU = -1;  /* SecondarydataForwardingInfoFromTarget_List */
static int hf_xnap_SCGConfigurationQuery_PDU = -1;  /* SCGConfigurationQuery */
static int hf_xnap_SecurityResult_PDU = -1;       /* SecurityResult */
static int hf_xnap_ServedCells_E_UTRA_PDU = -1;   /* ServedCells_E_UTRA */
static int hf_xnap_ServedCellsToUpdate_E_UTRA_PDU = -1;  /* ServedCellsToUpdate_E_UTRA */
static int hf_xnap_ServedCells_NR_PDU = -1;       /* ServedCells_NR */
static int hf_xnap_ServedCellsToUpdate_NR_PDU = -1;  /* ServedCellsToUpdate_NR */
static int hf_xnap_S_NG_RANnode_SecurityKey_PDU = -1;  /* S_NG_RANnode_SecurityKey */
static int hf_xnap_S_NG_RANnode_Addition_Trigger_Ind_PDU = -1;  /* S_NG_RANnode_Addition_Trigger_Ind */
static int hf_xnap_S_NSSAI_PDU = -1;              /* S_NSSAI */
static int hf_xnap_SplitSessionIndicator_PDU = -1;  /* SplitSessionIndicator */
static int hf_xnap_SplitSRBsTypes_PDU = -1;       /* SplitSRBsTypes */
static int hf_xnap_TAISupport_List_PDU = -1;      /* TAISupport_List */
static int hf_xnap_Target_CGI_PDU = -1;           /* Target_CGI */
static int hf_xnap_TimeToWait_PDU = -1;           /* TimeToWait */
static int hf_xnap_TNLA_To_Add_List_PDU = -1;     /* TNLA_To_Add_List */
static int hf_xnap_TNLA_To_Update_List_PDU = -1;  /* TNLA_To_Update_List */
static int hf_xnap_TNLA_To_Remove_List_PDU = -1;  /* TNLA_To_Remove_List */
static int hf_xnap_TNLA_Setup_List_PDU = -1;      /* TNLA_Setup_List */
static int hf_xnap_TNLA_Failed_To_Setup_List_PDU = -1;  /* TNLA_Failed_To_Setup_List */
static int hf_xnap_TraceActivation_PDU = -1;      /* TraceActivation */
static int hf_xnap_UEAggregateMaximumBitRate_PDU = -1;  /* UEAggregateMaximumBitRate */
static int hf_xnap_UEContextKeptIndicator_PDU = -1;  /* UEContextKeptIndicator */
static int hf_xnap_UEContextID_PDU = -1;          /* UEContextID */
static int hf_xnap_UEContextInfoRetrUECtxtResp_PDU = -1;  /* UEContextInfoRetrUECtxtResp */
static int hf_xnap_UEHistoryInformation_PDU = -1;  /* UEHistoryInformation */
static int hf_xnap_UEIdentityIndexValue_PDU = -1;  /* UEIdentityIndexValue */
static int hf_xnap_UERadioCapabilityForPaging_PDU = -1;  /* UERadioCapabilityForPaging */
static int hf_xnap_UERANPagingIdentity_PDU = -1;  /* UERANPagingIdentity */
static int hf_xnap_UESecurityCapabilities_PDU = -1;  /* UESecurityCapabilities */
static int hf_xnap_ULForwardingProposal_PDU = -1;  /* ULForwardingProposal */
static int hf_xnap_UPTransportLayerInformation_PDU = -1;  /* UPTransportLayerInformation */
static int hf_xnap_UserPlaneTrafficActivityReport_PDU = -1;  /* UserPlaneTrafficActivityReport */
static int hf_xnap_XnBenefitValue_PDU = -1;       /* XnBenefitValue */
static int hf_xnap_HandoverRequest_PDU = -1;      /* HandoverRequest */
static int hf_xnap_UEContextInfoHORequest_PDU = -1;  /* UEContextInfoHORequest */
static int hf_xnap_UEContextRefAtSN_HORequest_PDU = -1;  /* UEContextRefAtSN_HORequest */
static int hf_xnap_HandoverRequestAcknowledge_PDU = -1;  /* HandoverRequestAcknowledge */
static int hf_xnap_Target2SourceNG_RANnodeTranspContainer_PDU = -1;  /* Target2SourceNG_RANnodeTranspContainer */
static int hf_xnap_HandoverPreparationFailure_PDU = -1;  /* HandoverPreparationFailure */
static int hf_xnap_SNStatusTransfer_PDU = -1;     /* SNStatusTransfer */
static int hf_xnap_UEContextRelease_PDU = -1;     /* UEContextRelease */
static int hf_xnap_HandoverCancel_PDU = -1;       /* HandoverCancel */
static int hf_xnap_RANPaging_PDU = -1;            /* RANPaging */
static int hf_xnap_RetrieveUEContextRequest_PDU = -1;  /* RetrieveUEContextRequest */
static int hf_xnap_RetrieveUEContextResponse_PDU = -1;  /* RetrieveUEContextResponse */
static int hf_xnap_RetrieveUEContextFailure_PDU = -1;  /* RetrieveUEContextFailure */
static int hf_xnap_OldtoNewNG_RANnodeResumeContainer_PDU = -1;  /* OldtoNewNG_RANnodeResumeContainer */
static int hf_xnap_XnUAddressIndication_PDU = -1;  /* XnUAddressIndication */
static int hf_xnap_SNodeAdditionRequest_PDU = -1;  /* SNodeAdditionRequest */
static int hf_xnap_MN_to_SN_Container_PDU = -1;   /* MN_to_SN_Container */
static int hf_xnap_PDUSessionToBeAddedAddReq_PDU = -1;  /* PDUSessionToBeAddedAddReq */
static int hf_xnap_SNodeAdditionRequestAcknowledge_PDU = -1;  /* SNodeAdditionRequestAcknowledge */
static int hf_xnap_SN_to_MN_Container_PDU = -1;   /* SN_to_MN_Container */
static int hf_xnap_PDUSessionAdmittedAddedAddReqAck_PDU = -1;  /* PDUSessionAdmittedAddedAddReqAck */
static int hf_xnap_PDUSessionNotAdmittedAddReqAck_PDU = -1;  /* PDUSessionNotAdmittedAddReqAck */
static int hf_xnap_SNodeAdditionRequestReject_PDU = -1;  /* SNodeAdditionRequestReject */
static int hf_xnap_SNodeReconfigurationComplete_PDU = -1;  /* SNodeReconfigurationComplete */
static int hf_xnap_ResponseInfo_ReconfCompl_PDU = -1;  /* ResponseInfo_ReconfCompl */
static int hf_xnap_SNodeModificationRequest_PDU = -1;  /* SNodeModificationRequest */
static int hf_xnap_UEContextInfo_SNModRequest_PDU = -1;  /* UEContextInfo_SNModRequest */
static int hf_xnap_SNodeModificationRequestAcknowledge_PDU = -1;  /* SNodeModificationRequestAcknowledge */
static int hf_xnap_PDUSessionAdmitted_SNModResponse_PDU = -1;  /* PDUSessionAdmitted_SNModResponse */
static int hf_xnap_PDUSessionNotAdmitted_SNModResponse_PDU = -1;  /* PDUSessionNotAdmitted_SNModResponse */
static int hf_xnap_PDUSessionDataForwarding_SNModResponse_PDU = -1;  /* PDUSessionDataForwarding_SNModResponse */
static int hf_xnap_SNodeModificationRequestReject_PDU = -1;  /* SNodeModificationRequestReject */
static int hf_xnap_SNodeModificationRequired_PDU = -1;  /* SNodeModificationRequired */
static int hf_xnap_PDUSessionToBeModifiedSNModRequired_PDU = -1;  /* PDUSessionToBeModifiedSNModRequired */
static int hf_xnap_PDUSessionToBeReleasedSNModRequired_PDU = -1;  /* PDUSessionToBeReleasedSNModRequired */
static int hf_xnap_SNodeModificationConfirm_PDU = -1;  /* SNodeModificationConfirm */
static int hf_xnap_PDUSessionAdmittedModSNModConfirm_PDU = -1;  /* PDUSessionAdmittedModSNModConfirm */
static int hf_xnap_PDUSessionReleasedSNModConfirm_PDU = -1;  /* PDUSessionReleasedSNModConfirm */
static int hf_xnap_SNodeModificationRefuse_PDU = -1;  /* SNodeModificationRefuse */
static int hf_xnap_SNodeReleaseRequest_PDU = -1;  /* SNodeReleaseRequest */
static int hf_xnap_SNodeReleaseRequestAcknowledge_PDU = -1;  /* SNodeReleaseRequestAcknowledge */
static int hf_xnap_PDUSessionToBeReleasedList_RelReqAck_PDU = -1;  /* PDUSessionToBeReleasedList_RelReqAck */
static int hf_xnap_SNodeReleaseReject_PDU = -1;   /* SNodeReleaseReject */
static int hf_xnap_SNodeReleaseRequired_PDU = -1;  /* SNodeReleaseRequired */
static int hf_xnap_PDUSessionToBeReleasedList_RelRqd_PDU = -1;  /* PDUSessionToBeReleasedList_RelRqd */
static int hf_xnap_SNodeReleaseConfirm_PDU = -1;  /* SNodeReleaseConfirm */
static int hf_xnap_PDUSessionReleasedList_RelConf_PDU = -1;  /* PDUSessionReleasedList_RelConf */
static int hf_xnap_SNodeCounterCheckRequest_PDU = -1;  /* SNodeCounterCheckRequest */
static int hf_xnap_BearersSubjectToCounterCheck_List_PDU = -1;  /* BearersSubjectToCounterCheck_List */
static int hf_xnap_SNodeChangeRequired_PDU = -1;  /* SNodeChangeRequired */
static int hf_xnap_PDUSession_SNChangeRequired_List_PDU = -1;  /* PDUSession_SNChangeRequired_List */
static int hf_xnap_SNodeChangeConfirm_PDU = -1;   /* SNodeChangeConfirm */
static int hf_xnap_PDUSession_SNChangeConfirm_List_PDU = -1;  /* PDUSession_SNChangeConfirm_List */
static int hf_xnap_SNodeChangeRefuse_PDU = -1;    /* SNodeChangeRefuse */
static int hf_xnap_RRCTransfer_PDU = -1;          /* RRCTransfer */
static int hf_xnap_SplitSRB_RRCTransfer_PDU = -1;  /* SplitSRB_RRCTransfer */
static int hf_xnap_UEReportRRCTransfer_PDU = -1;  /* UEReportRRCTransfer */
static int hf_xnap_NotificationControlIndication_PDU = -1;  /* NotificationControlIndication */
static int hf_xnap_PDUSessionResourcesNotifyList_PDU = -1;  /* PDUSessionResourcesNotifyList */
static int hf_xnap_ActivityNotification_PDU = -1;  /* ActivityNotification */
static int hf_xnap_PDUSessionResourcesActivityNotifyList_PDU = -1;  /* PDUSessionResourcesActivityNotifyList */
static int hf_xnap_XnSetupRequest_PDU = -1;       /* XnSetupRequest */
static int hf_xnap_XnSetupResponse_PDU = -1;      /* XnSetupResponse */
static int hf_xnap_XnSetupFailure_PDU = -1;       /* XnSetupFailure */
static int hf_xnap_NGRANNodeConfigurationUpdate_PDU = -1;  /* NGRANNodeConfigurationUpdate */
static int hf_xnap_ConfigurationUpdateInitiatingNodeChoice_PDU = -1;  /* ConfigurationUpdateInitiatingNodeChoice */
static int hf_xnap_NGRANNodeConfigurationUpdateAcknowledge_PDU = -1;  /* NGRANNodeConfigurationUpdateAcknowledge */
static int hf_xnap_RespondingNodeTypeConfigUpdateAck_PDU = -1;  /* RespondingNodeTypeConfigUpdateAck */
static int hf_xnap_NGRANNodeConfigurationUpdateFailure_PDU = -1;  /* NGRANNodeConfigurationUpdateFailure */
static int hf_xnap_E_UTRA_NR_CellResourceCoordinationRequest_PDU = -1;  /* E_UTRA_NR_CellResourceCoordinationRequest */
static int hf_xnap_InitiatingNodeType_ResourceCoordRequest_PDU = -1;  /* InitiatingNodeType_ResourceCoordRequest */
static int hf_xnap_E_UTRA_NR_CellResourceCoordinationResponse_PDU = -1;  /* E_UTRA_NR_CellResourceCoordinationResponse */
static int hf_xnap_RespondingNodeType_ResourceCoordResponse_PDU = -1;  /* RespondingNodeType_ResourceCoordResponse */
static int hf_xnap_SecondaryRATDataUsageReport_PDU = -1;  /* SecondaryRATDataUsageReport */
static int hf_xnap_XnRemovalRequest_PDU = -1;     /* XnRemovalRequest */
static int hf_xnap_XnRemovalResponse_PDU = -1;    /* XnRemovalResponse */
static int hf_xnap_XnRemovalFailure_PDU = -1;     /* XnRemovalFailure */
static int hf_xnap_CellActivationRequest_PDU = -1;  /* CellActivationRequest */
static int hf_xnap_ServedCellsToActivate_PDU = -1;  /* ServedCellsToActivate */
static int hf_xnap_CellActivationResponse_PDU = -1;  /* CellActivationResponse */
static int hf_xnap_ActivatedServedCells_PDU = -1;  /* ActivatedServedCells */
static int hf_xnap_CellActivationFailure_PDU = -1;  /* CellActivationFailure */
static int hf_xnap_ResetRequest_PDU = -1;         /* ResetRequest */
static int hf_xnap_ResetResponse_PDU = -1;        /* ResetResponse */
static int hf_xnap_ErrorIndication_PDU = -1;      /* ErrorIndication */
static int hf_xnap_PrivateMessage_PDU = -1;       /* PrivateMessage */
static int hf_xnap_XnAP_PDU_PDU = -1;             /* XnAP_PDU */
static int hf_xnap_local = -1;                    /* INTEGER_0_maxPrivateIEs */
static int hf_xnap_global = -1;                   /* OBJECT_IDENTIFIER */
static int hf_xnap_ProtocolIE_Container_item = -1;  /* ProtocolIE_Field */
static int hf_xnap_id = -1;                       /* ProtocolIE_ID */
static int hf_xnap_criticality = -1;              /* Criticality */
static int hf_xnap_protocolIE_Field_value = -1;   /* ProtocolIE_Field_value */
static int hf_xnap_ProtocolExtensionContainer_item = -1;  /* ProtocolExtensionField */
static int hf_xnap_extension_id = -1;             /* ProtocolIE_ID */
static int hf_xnap_extensionValue = -1;           /* T_extensionValue */
static int hf_xnap_PrivateIE_Container_item = -1;  /* PrivateIE_Field */
static int hf_xnap_private_id = -1;               /* PrivateIE_ID */
static int hf_xnap_privateIE_Field_value = -1;    /* PrivateIE_Field_value */
static int hf_xnap_additional_UL_NG_U_TNLatUPF = -1;  /* UPTransportLayerInformation */
static int hf_xnap_iE_Extensions = -1;            /* ProtocolExtensionContainer */
static int hf_xnap_Additional_UL_NG_U_TNLatUPF_List_item = -1;  /* Additional_UL_NG_U_TNLatUPF_Item */
static int hf_xnap_priorityLevel = -1;            /* INTEGER_0_15_ */
static int hf_xnap_pre_emption_capability = -1;   /* T_pre_emption_capability */
static int hf_xnap_pre_emption_vulnerability = -1;  /* T_pre_emption_vulnerability */
static int hf_xnap_AMF_Region_Information_item = -1;  /* GlobalAMF_Region_Information */
static int hf_xnap_plmn_ID = -1;                  /* PLMN_Identity */
static int hf_xnap_amf_region_id = -1;            /* BIT_STRING_SIZE_8 */
static int hf_xnap_AreaOfInterestInformation_item = -1;  /* AreaOfInterest_Item */
static int hf_xnap_listOfTAIsinAoI = -1;          /* ListOfTAIsinAoI */
static int hf_xnap_listOfCellsinAoI = -1;         /* ListOfCells */
static int hf_xnap_listOfRANNodesinAoI = -1;      /* ListOfRANNodesinAoI */
static int hf_xnap_requestReferenceID = -1;       /* RequestReferenceID */
static int hf_xnap_key_NG_RAN_Star = -1;          /* BIT_STRING_SIZE_256 */
static int hf_xnap_ncc = -1;                      /* INTEGER_0_7 */
static int hf_xnap_ran_paging_attempt_info = -1;  /* RANPagingAttemptInfo */
static int hf_xnap_BPLMN_ID_Info_EUTRA_item = -1;  /* BPLMN_ID_Info_EUTRA_Item */
static int hf_xnap_broadcastPLMNs = -1;           /* BroadcastEUTRAPLMNs */
static int hf_xnap_tac = -1;                      /* TAC */
static int hf_xnap_e_utraCI = -1;                 /* E_UTRA_Cell_Identity */
static int hf_xnap_ranac = -1;                    /* RANAC */
static int hf_xnap_iE_Extension = -1;             /* ProtocolExtensionContainer */
static int hf_xnap_BPLMN_ID_Info_NR_item = -1;    /* BPLMN_ID_Info_NR_Item */
static int hf_xnap_broadcastPLMNs_01 = -1;        /* BroadcastPLMNs */
static int hf_xnap_nr_CI = -1;                    /* NR_Cell_Identity */
static int hf_xnap_BroadcastPLMNs_item = -1;      /* PLMN_Identity */
static int hf_xnap_BroadcastEUTRAPLMNs_item = -1;  /* PLMN_Identity */
static int hf_xnap_plmn_id = -1;                  /* PLMN_Identity */
static int hf_xnap_tAISliceSupport_List = -1;     /* SliceSupport_List */
static int hf_xnap_radioNetwork = -1;             /* CauseRadioNetworkLayer */
static int hf_xnap_transport = -1;                /* CauseTransportLayer */
static int hf_xnap_protocol = -1;                 /* CauseProtocol */
static int hf_xnap_misc = -1;                     /* CauseMisc */
static int hf_xnap_choice_extension = -1;         /* ProtocolIE_Single_Container */
static int hf_xnap_limitedNR_List = -1;           /* SEQUENCE_SIZE_1_maxnoofCellsinNG_RANnode_OF_NR_CGI */
static int hf_xnap_limitedNR_List_item = -1;      /* NR_CGI */
static int hf_xnap_full_List = -1;                /* T_full_List */
static int hf_xnap_eNDC_Support = -1;             /* T_eNDC_Support */
static int hf_xnap_pdcp_SN12 = -1;                /* INTEGER_0_4095 */
static int hf_xnap_hfn_PDCP_SN12 = -1;            /* INTEGER_0_1048575 */
static int hf_xnap_pdcp_SN18 = -1;                /* INTEGER_0_262143 */
static int hf_xnap_hfn_PDCP_SN18 = -1;            /* INTEGER_0_16383 */
static int hf_xnap_endpointIPAddress = -1;        /* TransportLayerAddress */
static int hf_xnap_procedureCode = -1;            /* ProcedureCode */
static int hf_xnap_triggeringMessage = -1;        /* TriggeringMessage */
static int hf_xnap_procedureCriticality = -1;     /* Criticality */
static int hf_xnap_iEsCriticalityDiagnostics = -1;  /* CriticalityDiagnostics_IE_List */
static int hf_xnap_CriticalityDiagnostics_IE_List_item = -1;  /* CriticalityDiagnostics_IE_List_item */
static int hf_xnap_iECriticality = -1;            /* Criticality */
static int hf_xnap_iE_ID = -1;                    /* ProtocolIE_ID */
static int hf_xnap_typeOfError = -1;              /* TypeOfError */
static int hf_xnap_XnUAddressInfoperPDUSession_List_item = -1;  /* XnUAddressInfoperPDUSession_Item */
static int hf_xnap_pduSession_ID = -1;            /* PDUSession_ID */
static int hf_xnap_dataForwardingInfoFromTargetNGRANnode = -1;  /* DataForwardingInfoFromTargetNGRANnode */
static int hf_xnap_pduSessionResourceSetupCompleteInfo_SNterm = -1;  /* PDUSessionResourceBearerSetupCompleteInfo_SNterminated */
static int hf_xnap_qosFlowsAcceptedForDataForwarding_List = -1;  /* QoSFLowsAcceptedToBeForwarded_List */
static int hf_xnap_pduSessionLevelDLDataForwardingInfo = -1;  /* UPTransportLayerInformation */
static int hf_xnap_pduSessionLevelULDataForwardingInfo = -1;  /* UPTransportLayerInformation */
static int hf_xnap_dataForwardingResponseDRBItemList = -1;  /* DataForwardingResponseDRBItemList */
static int hf_xnap_QoSFLowsAcceptedToBeForwarded_List_item = -1;  /* QoSFLowsAcceptedToBeForwarded_Item */
static int hf_xnap_qosFlowIdentifier = -1;        /* QoSFlowIdentifier */
static int hf_xnap_qosFlowsToBeForwarded = -1;    /* QoSFLowsToBeForwarded_List */
static int hf_xnap_sourceDRBtoQoSFlowMapping = -1;  /* DRBToQoSFlowMapping_List */
static int hf_xnap_QoSFLowsToBeForwarded_List_item = -1;  /* QoSFLowsToBeForwarded_Item */
static int hf_xnap_dl_dataforwarding = -1;        /* DLForwarding */
static int hf_xnap_ul_dataforwarding = -1;        /* ULForwarding */
static int hf_xnap_DataForwardingResponseDRBItemList_item = -1;  /* DataForwardingResponseDRBItem */
static int hf_xnap_drb_ID = -1;                   /* DRB_ID */
static int hf_xnap_dlForwardingUPTNL = -1;        /* UPTransportLayerInformation */
static int hf_xnap_ulForwardingUPTNL = -1;        /* UPTransportLayerInformation */
static int hf_xnap_activationSFN = -1;            /* ActivationSFN */
static int hf_xnap_sharedResourceType = -1;       /* SharedResourceType */
static int hf_xnap_reservedSubframePattern = -1;  /* ReservedSubframePattern */
static int hf_xnap_DRB_List_item = -1;            /* DRB_ID */
static int hf_xnap_DRB_List_withCause_item = -1;  /* DRB_List_withCause_Item */
static int hf_xnap_drb_id = -1;                   /* DRB_ID */
static int hf_xnap_cause = -1;                    /* Cause */
static int hf_xnap_rLC_Mode = -1;                 /* RLCMode */
static int hf_xnap_DRBsSubjectToStatusTransfer_List_item = -1;  /* DRBsSubjectToStatusTransfer_Item */
static int hf_xnap_drbID = -1;                    /* DRB_ID */
static int hf_xnap_pdcpStatusTransfer_UL = -1;    /* DRBBStatusTransferChoice */
static int hf_xnap_pdcpStatusTransfer_DL = -1;    /* DRBBStatusTransferChoice */
static int hf_xnap_pdcp_sn_12bits = -1;           /* DRBBStatusTransfer12bitsSN */
static int hf_xnap_pdcp_sn_18bits = -1;           /* DRBBStatusTransfer18bitsSN */
static int hf_xnap_receiveStatusofPDCPSDU = -1;   /* BIT_STRING_SIZE_1_2048 */
static int hf_xnap_cOUNTValue = -1;               /* COUNT_PDCP_SN12 */
static int hf_xnap_receiveStatusofPDCPSDU_01 = -1;  /* BIT_STRING_SIZE_1_131072 */
static int hf_xnap_cOUNTValue_01 = -1;            /* COUNT_PDCP_SN18 */
static int hf_xnap_DRBToQoSFlowMapping_List_item = -1;  /* DRBToQoSFlowMapping_Item */
static int hf_xnap_qosFlows_List = -1;            /* QoSFlows_List */
static int hf_xnap_priorityLevelQoS = -1;         /* PriorityLevelQoS */
static int hf_xnap_packetDelayBudget = -1;        /* PacketDelayBudget */
static int hf_xnap_packetErrorRate = -1;          /* PacketErrorRate */
static int hf_xnap_fiveQI = -1;                   /* FiveQI */
static int hf_xnap_delayCritical = -1;            /* T_delayCritical */
static int hf_xnap_averagingWindow = -1;          /* AveragingWindow */
static int hf_xnap_maximumDataBurstVolume = -1;   /* MaximumDataBurstVolume */
static int hf_xnap_e_utra_CI = -1;                /* E_UTRA_Cell_Identity */
static int hf_xnap_E_UTRAMultibandInfoList_item = -1;  /* E_UTRAFrequencyBandIndicator */
static int hf_xnap_rootSequenceIndex = -1;        /* INTEGER_0_837 */
static int hf_xnap_zeroCorrelationIndex = -1;     /* INTEGER_0_15 */
static int hf_xnap_highSpeedFlag = -1;            /* T_highSpeedFlag */
static int hf_xnap_prach_FreqOffset = -1;         /* INTEGER_0_94 */
static int hf_xnap_prach_ConfigIndex = -1;        /* INTEGER_0_63 */
static int hf_xnap_portNumber = -1;               /* PortNumber */
static int hf_xnap_expectedActivityPeriod = -1;   /* ExpectedActivityPeriod */
static int hf_xnap_expectedIdlePeriod = -1;       /* ExpectedIdlePeriod */
static int hf_xnap_sourceOfUEActivityBehaviourInformation = -1;  /* SourceOfUEActivityBehaviourInformation */
static int hf_xnap_expectedUEActivityBehaviour = -1;  /* ExpectedUEActivityBehaviour */
static int hf_xnap_expectedHOInterval = -1;       /* ExpectedHOInterval */
static int hf_xnap_expectedUEMobility = -1;       /* ExpectedUEMobility */
static int hf_xnap_expectedUEMovingTrajectory = -1;  /* ExpectedUEMovingTrajectory */
static int hf_xnap_ExpectedUEMovingTrajectory_item = -1;  /* ExpectedUEMovingTrajectoryItem */
static int hf_xnap_nGRAN_CGI = -1;                /* GlobalNG_RANCell_ID */
static int hf_xnap_timeStayedInCell = -1;         /* INTEGER_0_4095 */
static int hf_xnap_maxFlowBitRateDL = -1;         /* BitRate */
static int hf_xnap_maxFlowBitRateUL = -1;         /* BitRate */
static int hf_xnap_guaranteedFlowBitRateDL = -1;  /* BitRate */
static int hf_xnap_guaranteedFlowBitRateUL = -1;  /* BitRate */
static int hf_xnap_notificationControl = -1;      /* T_notificationControl */
static int hf_xnap_maxPacketLossRateDL = -1;      /* PacketLossRate */
static int hf_xnap_maxPacketLossRateUL = -1;      /* PacketLossRate */
static int hf_xnap_gnb_id = -1;                   /* GNB_ID_Choice */
static int hf_xnap_gnb_ID = -1;                   /* BIT_STRING_SIZE_22_32 */
static int hf_xnap_enb_id = -1;                   /* ENB_ID_Choice */
static int hf_xnap_enb_ID_macro = -1;             /* BIT_STRING_SIZE_20 */
static int hf_xnap_enb_ID_shortmacro = -1;        /* BIT_STRING_SIZE_18 */
static int hf_xnap_enb_ID_longmacro = -1;         /* BIT_STRING_SIZE_21 */
static int hf_xnap_ng_RAN_Cell_id = -1;           /* NG_RAN_Cell_Identity */
static int hf_xnap_gNB = -1;                      /* GlobalgNB_ID */
static int hf_xnap_ng_eNB = -1;                   /* GlobalngeNB_ID */
static int hf_xnap_tnl_address = -1;              /* TransportLayerAddress */
static int hf_xnap_gtp_teid = -1;                 /* GTP_TEID */
static int hf_xnap_amf_set_id = -1;               /* BIT_STRING_SIZE_10 */
static int hf_xnap_amf_pointer = -1;              /* BIT_STRING_SIZE_6 */
static int hf_xnap_i_RNTI_full = -1;              /* BIT_STRING_SIZE_40 */
static int hf_xnap_i_RNTI_short = -1;             /* BIT_STRING_SIZE_24 */
static int hf_xnap_nG_RAN_Cell = -1;              /* LastVisitedNGRANCellInformation */
static int hf_xnap_e_UTRAN_Cell = -1;             /* LastVisitedEUTRANCellInformation */
static int hf_xnap_uTRAN_Cell = -1;               /* LastVisitedUTRANCellInformation */
static int hf_xnap_gERAN_Cell = -1;               /* LastVisitedGERANCellInformation */
static int hf_xnap_ListOfCells_item = -1;         /* CellsinAoI_Item */
static int hf_xnap_pLMN_Identity = -1;            /* PLMN_Identity */
static int hf_xnap_ng_ran_cell_id = -1;           /* NG_RAN_Cell_Identity */
static int hf_xnap_ListOfRANNodesinAoI_item = -1;  /* GlobalNG_RANNodesinAoI_Item */
static int hf_xnap_global_NG_RAN_Node_ID = -1;    /* GlobalNG_RANNode_ID */
static int hf_xnap_ListOfTAIsinAoI_item = -1;     /* TAIsinAoI_Item */
static int hf_xnap_tAC = -1;                      /* TAC */
static int hf_xnap_eventType = -1;                /* EventType */
static int hf_xnap_reportArea = -1;               /* ReportArea */
static int hf_xnap_areaOfInterest = -1;           /* AreaOfInterestInformation */
static int hf_xnap_maxIPrate_UL = -1;             /* MaxIPrate */
static int hf_xnap_oneframe = -1;                 /* BIT_STRING_SIZE_6 */
static int hf_xnap_fourframes = -1;               /* BIT_STRING_SIZE_24 */
static int hf_xnap_MBSFNSubframeInfo_E_UTRA_item = -1;  /* MBSFNSubframeInfo_E_UTRA_Item */
static int hf_xnap_radioframeAllocationPeriod = -1;  /* T_radioframeAllocationPeriod */
static int hf_xnap_radioframeAllocationOffset = -1;  /* INTEGER_0_7_ */
static int hf_xnap_subframeAllocation = -1;       /* MBSFNSubframeAllocation_E_UTRA */
static int hf_xnap_serving_PLMN = -1;             /* PLMN_Identity */
static int hf_xnap_equivalent_PLMNs = -1;         /* SEQUENCE_SIZE_1_maxnoofEPLMNs_OF_PLMN_Identity */
static int hf_xnap_equivalent_PLMNs_item = -1;    /* PLMN_Identity */
static int hf_xnap_rat_Restrictions = -1;         /* RAT_RestrictionsList */
static int hf_xnap_forbiddenAreaInformation = -1;  /* ForbiddenAreaList */
static int hf_xnap_serviceAreaInformation = -1;   /* ServiceAreaList */
static int hf_xnap_CNTypeRestrictionsForEquivalent_item = -1;  /* CNTypeRestrictionsForEquivalentItem */
static int hf_xnap_plmn_Identity = -1;            /* PLMN_Identity */
static int hf_xnap_cn_Type = -1;                  /* T_cn_Type */
static int hf_xnap_RAT_RestrictionsList_item = -1;  /* RAT_RestrictionsItem */
static int hf_xnap_rat_RestrictionInformation = -1;  /* RAT_RestrictionInformation */
static int hf_xnap_ForbiddenAreaList_item = -1;   /* ForbiddenAreaItem */
static int hf_xnap_forbidden_TACs = -1;           /* SEQUENCE_SIZE_1_maxnoofForbiddenTACs_OF_TAC */
static int hf_xnap_forbidden_TACs_item = -1;      /* TAC */
static int hf_xnap_ServiceAreaList_item = -1;     /* ServiceAreaItem */
static int hf_xnap_allowed_TACs_ServiceArea = -1;  /* SEQUENCE_SIZE_1_maxnoofAllowedAreas_OF_TAC */
static int hf_xnap_allowed_TACs_ServiceArea_item = -1;  /* TAC */
static int hf_xnap_not_allowed_TACs_ServiceArea = -1;  /* SEQUENCE_SIZE_1_maxnoofAllowedAreas_OF_TAC */
static int hf_xnap_not_allowed_TACs_ServiceArea_item = -1;  /* TAC */
static int hf_xnap_ng_RAN_Node_ResourceCoordinationInfo = -1;  /* NG_RAN_Node_ResourceCoordinationInfo */
static int hf_xnap_eutra_resource_coordination_info = -1;  /* E_UTRA_ResourceCoordinationInfo */
static int hf_xnap_nr_resource_coordination_info = -1;  /* NR_ResourceCoordinationInfo */
static int hf_xnap_e_utra_cell = -1;              /* E_UTRA_CGI */
static int hf_xnap_ul_coordination_info = -1;     /* BIT_STRING_SIZE_6_4400 */
static int hf_xnap_dl_coordination_info = -1;     /* BIT_STRING_SIZE_6_4400 */
static int hf_xnap_nr_cell = -1;                  /* NR_CGI */
static int hf_xnap_e_utra_coordination_assistance_info = -1;  /* E_UTRA_CoordinationAssistanceInfo */
static int hf_xnap_nr_coordination_assistance_info = -1;  /* NR_CoordinationAssistanceInfo */
static int hf_xnap_subframeAssignment = -1;       /* T_subframeAssignment */
static int hf_xnap_harqOffset = -1;               /* INTEGER_0_9 */
static int hf_xnap_NeighbourInformation_E_UTRA_item = -1;  /* NeighbourInformation_E_UTRA_Item */
static int hf_xnap_e_utra_PCI = -1;               /* E_UTRAPCI */
static int hf_xnap_e_utra_cgi = -1;               /* E_UTRA_CGI */
static int hf_xnap_earfcn = -1;                   /* E_UTRAARFCN */
static int hf_xnap_NeighbourInformation_NR_item = -1;  /* NeighbourInformation_NR_Item */
static int hf_xnap_nr_PCI = -1;                   /* NRPCI */
static int hf_xnap_nr_cgi = -1;                   /* NR_CGI */
static int hf_xnap_nr_mode_info = -1;             /* NeighbourInformation_NR_ModeInfo */
static int hf_xnap_connectivitySupport = -1;      /* Connectivity_Support */
static int hf_xnap_measurementTimingConfiguration = -1;  /* T_measurementTimingConfiguration */
static int hf_xnap_fdd_info = -1;                 /* NeighbourInformation_NR_ModeFDDInfo */
static int hf_xnap_tdd_info = -1;                 /* NeighbourInformation_NR_ModeTDDInfo */
static int hf_xnap_ul_NR_FreqInfo = -1;           /* NRFrequencyInfo */
static int hf_xnap_dl_NR_FequInfo = -1;           /* NRFrequencyInfo */
static int hf_xnap_ie_Extensions = -1;            /* ProtocolExtensionContainer */
static int hf_xnap_nr_FreqInfo = -1;              /* NRFrequencyInfo */
static int hf_xnap_nr = -1;                       /* NR_Cell_Identity */
static int hf_xnap_e_utra = -1;                   /* E_UTRA_Cell_Identity */
static int hf_xnap_nr_01 = -1;                    /* NRPCI */
static int hf_xnap_e_utra_01 = -1;                /* E_UTRAPCI */
static int hf_xnap_NG_RAN_Cell_Identity_ListinRANPagingArea_item = -1;  /* NG_RAN_Cell_Identity */
static int hf_xnap_nr_CI_01 = -1;                 /* NR_Cell_Identity */
static int hf_xnap_NRFrequencyBand_List_item = -1;  /* NRFrequencyBandItem */
static int hf_xnap_nr_frequency_band = -1;        /* NRFrequencyBand */
static int hf_xnap_supported_SUL_Band_List = -1;  /* SupportedSULBandList */
static int hf_xnap_nrARFCN = -1;                  /* NRARFCN */
static int hf_xnap_sul_information = -1;          /* SUL_Information */
static int hf_xnap_frequencyBand_List = -1;       /* NRFrequencyBand_List */
static int hf_xnap_fdd = -1;                      /* NRModeInfoFDD */
static int hf_xnap_tdd = -1;                      /* NRModeInfoTDD */
static int hf_xnap_ulNRFrequencyInfo = -1;        /* NRFrequencyInfo */
static int hf_xnap_dlNRFrequencyInfo = -1;        /* NRFrequencyInfo */
static int hf_xnap_ulNRTransmissonBandwidth = -1;  /* NRTransmissionBandwidth */
static int hf_xnap_dlNRTransmissonBandwidth = -1;  /* NRTransmissionBandwidth */
static int hf_xnap_nrFrequencyInfo = -1;          /* NRFrequencyInfo */
static int hf_xnap_nrTransmissonBandwidth = -1;   /* NRTransmissionBandwidth */
static int hf_xnap_nRSCS = -1;                    /* NRSCS */
static int hf_xnap_nRNRB = -1;                    /* NRNRB */
static int hf_xnap_pER_Scalar = -1;               /* PER_Scalar */
static int hf_xnap_pER_Exponent = -1;             /* PER_Exponent */
static int hf_xnap_from_S_NG_RAN_node = -1;       /* T_from_S_NG_RAN_node */
static int hf_xnap_from_M_NG_RAN_node = -1;       /* T_from_M_NG_RAN_node */
static int hf_xnap_ulPDCPSNLength = -1;           /* T_ulPDCPSNLength */
static int hf_xnap_dlPDCPSNLength = -1;           /* T_dlPDCPSNLength */
static int hf_xnap_downlink_session_AMBR = -1;    /* BitRate */
static int hf_xnap_uplink_session_AMBR = -1;      /* BitRate */
static int hf_xnap_PDUSession_List_item = -1;     /* PDUSession_ID */
static int hf_xnap_PDUSession_List_withCause_item = -1;  /* PDUSession_List_withCause_Item */
static int hf_xnap_pduSessionId = -1;             /* PDUSession_ID */
static int hf_xnap_PDUSession_List_withDataForwardingFromTarget_item = -1;  /* PDUSession_List_withDataForwardingFromTarget_Item */
static int hf_xnap_dataforwardinginfoTarget = -1;  /* DataForwardingInfoFromTargetNGRANnode */
static int hf_xnap_PDUSession_List_withDataForwardingRequest_item = -1;  /* PDUSession_List_withDataForwardingRequest_Item */
static int hf_xnap_dataforwardingInfofromSource = -1;  /* DataforwardingandOffloadingInfofromSource */
static int hf_xnap_dRBtoBeReleasedList = -1;      /* DRBToQoSFlowMapping_List */
static int hf_xnap_PDUSessionResourcesAdmitted_List_item = -1;  /* PDUSessionResourcesAdmitted_Item */
static int hf_xnap_pduSessionResourceAdmittedInfo = -1;  /* PDUSessionResourceAdmittedInfo */
static int hf_xnap_dL_NG_U_TNL_Information_Unchanged = -1;  /* T_dL_NG_U_TNL_Information_Unchanged */
static int hf_xnap_qosFlowsAdmitted_List = -1;    /* QoSFlowsAdmitted_List */
static int hf_xnap_qosFlowsNotAdmitted_List = -1;  /* QoSFlows_List_withCause */
static int hf_xnap_dataForwardingInfoFromTarget = -1;  /* DataForwardingInfoFromTargetNGRANnode */
static int hf_xnap_PDUSessionResourcesNotAdmitted_List_item = -1;  /* PDUSessionResourcesNotAdmitted_Item */
static int hf_xnap_PDUSessionResourcesToBeSetup_List_item = -1;  /* PDUSessionResourcesToBeSetup_Item */
static int hf_xnap_s_NSSAI = -1;                  /* S_NSSAI */
static int hf_xnap_pduSessionAMBR = -1;           /* PDUSessionAggregateMaximumBitRate */
static int hf_xnap_uL_NG_U_TNLatUPF = -1;         /* UPTransportLayerInformation */
static int hf_xnap_source_DL_NG_U_TNL_Information = -1;  /* UPTransportLayerInformation */
static int hf_xnap_securityIndication = -1;       /* SecurityIndication */
static int hf_xnap_pduSessionType = -1;           /* PDUSessionType */
static int hf_xnap_pduSessionNetworkInstance = -1;  /* PDUSessionNetworkInstance */
static int hf_xnap_qosFlowsToBeSetup_List = -1;   /* QoSFlowsToBeSetup_List */
static int hf_xnap_dataforwardinginfofromSource = -1;  /* DataforwardingandOffloadingInfofromSource */
static int hf_xnap_qosFlowsToBeSetup_List_01 = -1;  /* QoSFlowsToBeSetup_List_Setup_SNterminated */
static int hf_xnap_QoSFlowsToBeSetup_List_Setup_SNterminated_item = -1;  /* QoSFlowsToBeSetup_List_Setup_SNterminated_Item */
static int hf_xnap_qfi = -1;                      /* QoSFlowIdentifier */
static int hf_xnap_qosFlowLevelQoSParameters = -1;  /* QoSFlowLevelQoSParameters */
static int hf_xnap_offeredGBRQoSFlowInfo = -1;    /* GBRQoSFlowInfo */
static int hf_xnap_dL_NG_U_TNLatNG_RAN = -1;      /* UPTransportLayerInformation */
static int hf_xnap_dRBsToBeSetup = -1;            /* DRBsToBeSetupList_SetupResponse_SNterminated */
static int hf_xnap_qosFlowsNotAdmittedList = -1;  /* QoSFlows_List_withCause */
static int hf_xnap_securityResult = -1;           /* SecurityResult */
static int hf_xnap_DRBsToBeSetupList_SetupResponse_SNterminated_item = -1;  /* DRBsToBeSetupList_SetupResponse_SNterminated_Item */
static int hf_xnap_sN_UL_PDCP_UP_TNLInfo = -1;    /* UPTransportParameters */
static int hf_xnap_dRB_QoS = -1;                  /* QoSFlowLevelQoSParameters */
static int hf_xnap_pDCP_SNLength = -1;            /* PDCPSNLength */
static int hf_xnap_uL_Configuration = -1;         /* ULConfiguration */
static int hf_xnap_secondary_SN_UL_PDCP_UP_TNLInfo = -1;  /* UPTransportParameters */
static int hf_xnap_duplicationActivation = -1;    /* DuplicationActivation */
static int hf_xnap_qoSFlowsMappedtoDRB_SetupResponse_SNterminated = -1;  /* QoSFlowsMappedtoDRB_SetupResponse_SNterminated */
static int hf_xnap_QoSFlowsMappedtoDRB_SetupResponse_SNterminated_item = -1;  /* QoSFlowsMappedtoDRB_SetupResponse_SNterminated_Item */
static int hf_xnap_qoSFlowIdentifier = -1;        /* QoSFlowIdentifier */
static int hf_xnap_mCGRequestedGBRQoSFlowInfo = -1;  /* GBRQoSFlowInfo */
static int hf_xnap_qosFlowMappingIndication = -1;  /* QoSFlowMappingIndication */
static int hf_xnap_dRBsToBeSetup_01 = -1;         /* DRBsToBeSetupList_Setup_MNterminated */
static int hf_xnap_DRBsToBeSetupList_Setup_MNterminated_item = -1;  /* DRBsToBeSetupList_Setup_MNterminated_Item */
static int hf_xnap_mN_UL_PDCP_UP_TNLInfo = -1;    /* UPTransportParameters */
static int hf_xnap_secondary_MN_UL_PDCP_UP_TNLInfo = -1;  /* UPTransportParameters */
static int hf_xnap_qoSFlowsMappedtoDRB_Setup_MNterminated = -1;  /* QoSFlowsMappedtoDRB_Setup_MNterminated */
static int hf_xnap_QoSFlowsMappedtoDRB_Setup_MNterminated_item = -1;  /* QoSFlowsMappedtoDRB_Setup_MNterminated_Item */
static int hf_xnap_qoSFlowLevelQoSParameters = -1;  /* QoSFlowLevelQoSParameters */
static int hf_xnap_dRBsAdmittedList = -1;         /* DRBsAdmittedList_SetupResponse_MNterminated */
static int hf_xnap_DRBsAdmittedList_SetupResponse_MNterminated_item = -1;  /* DRBsAdmittedList_SetupResponse_MNterminated_Item */
static int hf_xnap_sN_DL_SCG_UP_TNLInfo = -1;     /* UPTransportParameters */
static int hf_xnap_secondary_SN_DL_SCG_UP_TNLInfo = -1;  /* UPTransportParameters */
static int hf_xnap_lCID = -1;                     /* LCID */
static int hf_xnap_qosFlowsToBeModified_List = -1;  /* QoSFlowsToBeSetup_List_Modified_SNterminated */
static int hf_xnap_qoSFlowsToBeReleased_List = -1;  /* QoSFlows_List_withCause */
static int hf_xnap_drbsToBeModifiedList = -1;     /* DRBsToBeModified_List_Modified_SNterminated */
static int hf_xnap_dRBsToBeReleased = -1;         /* DRB_List_withCause */
static int hf_xnap_QoSFlowsToBeSetup_List_Modified_SNterminated_item = -1;  /* QoSFlowsToBeSetup_List_Modified_SNterminated_Item */
static int hf_xnap_DRBsToBeModified_List_Modified_SNterminated_item = -1;  /* DRBsToBeModified_List_Modified_SNterminated_Item */
static int hf_xnap_mN_DL_SCG_UP_TNLInfo = -1;     /* UPTransportParameters */
static int hf_xnap_secondary_MN_DL_SCG_UP_TNLInfo = -1;  /* UPTransportParameters */
static int hf_xnap_rlc_status = -1;               /* RLC_Status */
static int hf_xnap_dRBsToBeModified = -1;         /* DRBsToBeModifiedList_ModificationResponse_SNterminated */
static int hf_xnap_qosFlowsNotAdmittedTBAdded = -1;  /* QoSFlows_List_withCause */
static int hf_xnap_qosFlowsReleased = -1;         /* QoSFlows_List_withCause */
static int hf_xnap_DRBsToBeModifiedList_ModificationResponse_SNterminated_item = -1;  /* DRBsToBeModifiedList_ModificationResponse_SNterminated_Item */
static int hf_xnap_dRBsToBeModified_01 = -1;      /* DRBsToBeModifiedList_Modification_MNterminated */
static int hf_xnap_DRBsToBeModifiedList_Modification_MNterminated_item = -1;  /* DRBsToBeModifiedList_Modification_MNterminated_Item */
static int hf_xnap_pdcpDuplicationConfiguration = -1;  /* PDCPDuplicationConfiguration */
static int hf_xnap_dRBsAdmittedList_01 = -1;      /* DRBsAdmittedList_ModificationResponse_MNterminated */
static int hf_xnap_dRBsReleasedList = -1;         /* DRB_List */
static int hf_xnap_dRBsNotAdmittedSetupModifyList = -1;  /* DRB_List_withCause */
static int hf_xnap_DRBsAdmittedList_ModificationResponse_MNterminated_item = -1;  /* DRBsAdmittedList_ModificationResponse_MNterminated_Item */
static int hf_xnap_drbsToBeSetupList = -1;        /* DRBsToBeSetup_List_ModRqd_SNterminated */
static int hf_xnap_drbsToBeModifiedList_01 = -1;  /* DRBsToBeModified_List_ModRqd_SNterminated */
static int hf_xnap_DRBsToBeSetup_List_ModRqd_SNterminated_item = -1;  /* DRBsToBeSetup_List_ModRqd_SNterminated_Item */
static int hf_xnap_sn_UL_PDCP_UPTNLinfo = -1;     /* UPTransportParameters */
static int hf_xnap_qoSFlowsMappedtoDRB_ModRqd_SNterminated = -1;  /* QoSFlowsSetupMappedtoDRB_ModRqd_SNterminated */
static int hf_xnap_QoSFlowsSetupMappedtoDRB_ModRqd_SNterminated_item = -1;  /* QoSFlowsSetupMappedtoDRB_ModRqd_SNterminated_Item */
static int hf_xnap_DRBsToBeModified_List_ModRqd_SNterminated_item = -1;  /* DRBsToBeModified_List_ModRqd_SNterminated_Item */
static int hf_xnap_qoSFlowsMappedtoDRB_ModRqd_SNterminated_01 = -1;  /* QoSFlowsModifiedMappedtoDRB_ModRqd_SNterminated */
static int hf_xnap_QoSFlowsModifiedMappedtoDRB_ModRqd_SNterminated_item = -1;  /* QoSFlowsModifiedMappedtoDRB_ModRqd_SNterminated_Item */
static int hf_xnap_dRBsAdmittedList_02 = -1;      /* DRBsAdmittedList_ModConfirm_SNterminated */
static int hf_xnap_DRBsAdmittedList_ModConfirm_SNterminated_item = -1;  /* DRBsAdmittedList_ModConfirm_SNterminated_Item */
static int hf_xnap_mN_DL_CG_UP_TNLInfo = -1;      /* UPTransportParameters */
static int hf_xnap_secondary_MN_DL_CG_UP_TNLInfo = -1;  /* UPTransportParameters */
static int hf_xnap_dRBsToBeModified_02 = -1;      /* DRBsToBeModified_List_ModRqd_MNterminated */
static int hf_xnap_DRBsToBeModified_List_ModRqd_MNterminated_item = -1;  /* DRBsToBeModified_List_ModRqd_MNterminated_Item */
static int hf_xnap_sN_DL_SCG_UP_TNLInfo_01 = -1;  /* UPTransportLayerInformation */
static int hf_xnap_secondary_SN_DL_SCG_UP_TNLInfo_01 = -1;  /* UPTransportLayerInformation */
static int hf_xnap_dRBsToBeSetupList = -1;        /* SEQUENCE_SIZE_1_maxnoofDRBs_OF_DRBsToBeSetupList_BearerSetupComplete_SNterminated_Item */
static int hf_xnap_dRBsToBeSetupList_item = -1;   /* DRBsToBeSetupList_BearerSetupComplete_SNterminated_Item */
static int hf_xnap_dRB_ID = -1;                   /* DRB_ID */
static int hf_xnap_mN_Xn_U_TNLInfoatM = -1;       /* UPTransportLayerInformation */
static int hf_xnap_PDUSessionResourceSecondaryRATUsageList_item = -1;  /* PDUSessionResourceSecondaryRATUsageItem */
static int hf_xnap_pDUSessionID = -1;             /* PDUSession_ID */
static int hf_xnap_secondaryRATUsageInformation = -1;  /* SecondaryRATUsageInformation */
static int hf_xnap_rATType = -1;                  /* T_rATType */
static int hf_xnap_pDUSessionTimedReportList = -1;  /* VolumeTimedReportList */
static int hf_xnap_protectedResourceList = -1;    /* ProtectedE_UTRAResourceList */
static int hf_xnap_mbsfnControlRegionLength = -1;  /* MBSFNControlRegionLength */
static int hf_xnap_pDCCHRegionLength = -1;        /* INTEGER_1_3 */
static int hf_xnap_ProtectedE_UTRAResourceList_item = -1;  /* ProtectedE_UTRAResource_Item */
static int hf_xnap_resourceType = -1;             /* T_resourceType */
static int hf_xnap_intra_PRBProtectedResourceFootprint = -1;  /* BIT_STRING_SIZE_84_ */
static int hf_xnap_protectedFootprintFrequencyPattern = -1;  /* BIT_STRING_SIZE_6_110_ */
static int hf_xnap_protectedFootprintTimePattern = -1;  /* ProtectedE_UTRAFootprintTimePattern */
static int hf_xnap_protectedFootprintTimeperiodicity = -1;  /* INTEGER_1_320_ */
static int hf_xnap_protectedFootrpintStartTime = -1;  /* INTEGER_1_20_ */
static int hf_xnap_non_dynamic = -1;              /* NonDynamic5QIDescriptor */
static int hf_xnap_dynamic = -1;                  /* Dynamic5QIDescriptor */
static int hf_xnap_qos_characteristics = -1;      /* QoSCharacteristics */
static int hf_xnap_allocationAndRetentionPrio = -1;  /* AllocationandRetentionPriority */
static int hf_xnap_gBRQoSFlowInfo = -1;           /* GBRQoSFlowInfo */
static int hf_xnap_relectiveQoS = -1;             /* ReflectiveQoSAttribute */
static int hf_xnap_additionalQoSflowInfo = -1;    /* T_additionalQoSflowInfo */
static int hf_xnap_QoSFlowNotificationControlIndicationInfo_item = -1;  /* QoSFlowNotify_Item */
static int hf_xnap_notificationInformation = -1;  /* T_notificationInformation */
static int hf_xnap_QoSFlows_List_item = -1;       /* QoSFlow_Item */
static int hf_xnap_QoSFlows_List_withCause_item = -1;  /* QoSFlowwithCause_Item */
static int hf_xnap_QoSFlowsAdmitted_List_item = -1;  /* QoSFlowsAdmitted_Item */
static int hf_xnap_QoSFlowsToBeSetup_List_item = -1;  /* QoSFlowsToBeSetup_Item */
static int hf_xnap_e_RAB_ID = -1;                 /* E_RAB_ID */
static int hf_xnap_QoSFlowsUsageReportList_item = -1;  /* QoSFlowsUsageReport_Item */
static int hf_xnap_rATType_01 = -1;               /* T_rATType_01 */
static int hf_xnap_qoSFlowsTimedReportList = -1;  /* VolumeTimedReportList */
static int hf_xnap_rANAC = -1;                    /* RANAC */
static int hf_xnap_RANAreaID_List_item = -1;      /* RANAreaID */
static int hf_xnap_rANPagingAreaChoice = -1;      /* RANPagingAreaChoice */
static int hf_xnap_cell_List = -1;                /* NG_RAN_Cell_Identity_ListinRANPagingArea */
static int hf_xnap_rANAreaID_List = -1;           /* RANAreaID_List */
static int hf_xnap_pagingAttemptCount = -1;       /* INTEGER_1_16_ */
static int hf_xnap_intendedNumberOfPagingAttempts = -1;  /* INTEGER_1_16_ */
static int hf_xnap_nextPagingAreaScope = -1;      /* T_nextPagingAreaScope */
static int hf_xnap_subframeType = -1;             /* T_subframeType */
static int hf_xnap_reservedSubframePattern_01 = -1;  /* BIT_STRING_SIZE_10_160 */
static int hf_xnap_fullReset = -1;                /* ResetRequestTypeInfo_Full */
static int hf_xnap_partialReset = -1;             /* ResetRequestTypeInfo_Partial */
static int hf_xnap_ue_contexts_ToBeReleasedList = -1;  /* ResetRequestPartialReleaseList */
static int hf_xnap_ResetRequestPartialReleaseList_item = -1;  /* ResetRequestPartialReleaseItem */
static int hf_xnap_ng_ran_node1UEXnAPID = -1;     /* NG_RANnodeUEXnAPID */
static int hf_xnap_ng_ran_node2UEXnAPID = -1;     /* NG_RANnodeUEXnAPID */
static int hf_xnap_fullReset_01 = -1;             /* ResetResponseTypeInfo_Full */
static int hf_xnap_partialReset_01 = -1;          /* ResetResponseTypeInfo_Partial */
static int hf_xnap_ue_contexts_AdmittedToBeReleasedList = -1;  /* ResetResponsePartialReleaseList */
static int hf_xnap_ResetResponsePartialReleaseList_item = -1;  /* ResetResponsePartialReleaseItem */
static int hf_xnap_reestablishment_Indication = -1;  /* Reestablishment_Indication */
static int hf_xnap_secondarydataForwardingInfoFromTarget = -1;  /* DataForwardingInfoFromTargetNGRANnode */
static int hf_xnap_SecondarydataForwardingInfoFromTarget_List_item = -1;  /* SecondarydataForwardingInfoFromTarget_Item */
static int hf_xnap_pDUSessionUsageReport = -1;    /* PDUSessionUsageReport */
static int hf_xnap_qosFlowsUsageReportList = -1;  /* QoSFlowsUsageReportList */
static int hf_xnap_integrityProtectionIndication = -1;  /* T_integrityProtectionIndication */
static int hf_xnap_confidentialityProtectionIndication = -1;  /* T_confidentialityProtectionIndication */
static int hf_xnap_maximumIPdatarate = -1;        /* MaximumIPdatarate */
static int hf_xnap_integrityProtectionResult = -1;  /* T_integrityProtectionResult */
static int hf_xnap_confidentialityProtectionResult = -1;  /* T_confidentialityProtectionResult */
static int hf_xnap_e_utra_pci = -1;               /* E_UTRAPCI */
static int hf_xnap_broadcastPLMNs_02 = -1;        /* SEQUENCE_SIZE_1_maxnoofBPLMNs_OF_ServedCellInformation_E_UTRA_perBPLMN */
static int hf_xnap_broadcastPLMNs_item = -1;      /* ServedCellInformation_E_UTRA_perBPLMN */
static int hf_xnap_e_utra_mode_info = -1;         /* ServedCellInformation_E_UTRA_ModeInfo */
static int hf_xnap_numberofAntennaPorts = -1;     /* NumberOfAntennaPorts_E_UTRA */
static int hf_xnap_prach_configuration = -1;      /* E_UTRAPRACHConfiguration */
static int hf_xnap_mBSFNsubframeInfo = -1;        /* MBSFNSubframeInfo_E_UTRA */
static int hf_xnap_multibandInfo = -1;            /* E_UTRAMultibandInfoList */
static int hf_xnap_freqBandIndicatorPriority = -1;  /* T_freqBandIndicatorPriority */
static int hf_xnap_bandwidthReducedSI = -1;       /* T_bandwidthReducedSI */
static int hf_xnap_protectedE_UTRAResourceIndication = -1;  /* ProtectedE_UTRAResourceIndication */
static int hf_xnap_fdd_01 = -1;                   /* ServedCellInformation_E_UTRA_FDDInfo */
static int hf_xnap_tdd_01 = -1;                   /* ServedCellInformation_E_UTRA_TDDInfo */
static int hf_xnap_ul_earfcn = -1;                /* E_UTRAARFCN */
static int hf_xnap_dl_earfcn = -1;                /* E_UTRAARFCN */
static int hf_xnap_ul_e_utraTxBW = -1;            /* E_UTRATransmissionBandwidth */
static int hf_xnap_dl_e_utraTxBW = -1;            /* E_UTRATransmissionBandwidth */
static int hf_xnap_e_utraTxBW = -1;               /* E_UTRATransmissionBandwidth */
static int hf_xnap_subframeAssignmnet = -1;       /* T_subframeAssignmnet */
static int hf_xnap_specialSubframeInfo = -1;      /* SpecialSubframeInfo_E_UTRA */
static int hf_xnap_ServedCells_E_UTRA_item = -1;  /* ServedCells_E_UTRA_Item */
static int hf_xnap_served_cell_info_E_UTRA = -1;  /* ServedCellInformation_E_UTRA */
static int hf_xnap_neighbour_info_NR = -1;        /* NeighbourInformation_NR */
static int hf_xnap_neighbour_info_E_UTRA = -1;    /* NeighbourInformation_E_UTRA */
static int hf_xnap_served_Cells_ToAdd_E_UTRA = -1;  /* ServedCells_E_UTRA */
static int hf_xnap_served_Cells_ToModify_E_UTRA = -1;  /* ServedCells_ToModify_E_UTRA */
static int hf_xnap_served_Cells_ToDelete_E_UTRA = -1;  /* SEQUENCE_SIZE_1_maxnoofCellsinNG_RANnode_OF_E_UTRA_CGI */
static int hf_xnap_served_Cells_ToDelete_E_UTRA_item = -1;  /* E_UTRA_CGI */
static int hf_xnap_ServedCells_ToModify_E_UTRA_item = -1;  /* ServedCells_ToModify_E_UTRA_Item */
static int hf_xnap_old_ECGI = -1;                 /* E_UTRA_CGI */
static int hf_xnap_deactivation_indication = -1;  /* T_deactivation_indication */
static int hf_xnap_nrPCI = -1;                    /* NRPCI */
static int hf_xnap_cellID = -1;                   /* NR_CGI */
static int hf_xnap_broadcastPLMN = -1;            /* BroadcastPLMNs */
static int hf_xnap_nrModeInfo = -1;               /* NRModeInfo */
static int hf_xnap_measurementTimingConfiguration_01 = -1;  /* T_measurementTimingConfiguration_01 */
static int hf_xnap_ServedCells_NR_item = -1;      /* ServedCells_NR_Item */
static int hf_xnap_served_cell_info_NR = -1;      /* ServedCellInformation_NR */
static int hf_xnap_ServedCells_ToModify_NR_item = -1;  /* ServedCells_ToModify_NR_Item */
static int hf_xnap_old_NR_CGI = -1;               /* NR_CGI */
static int hf_xnap_deactivation_indication_01 = -1;  /* T_deactivation_indication_01 */
static int hf_xnap_served_Cells_ToAdd_NR = -1;    /* ServedCells_NR */
static int hf_xnap_served_Cells_ToModify_NR = -1;  /* ServedCells_ToModify_NR */
static int hf_xnap_served_Cells_ToDelete_NR = -1;  /* SEQUENCE_SIZE_1_maxnoofCellsinNG_RANnode_OF_NR_CGI */
static int hf_xnap_served_Cells_ToDelete_NR_item = -1;  /* NR_CGI */
static int hf_xnap_ul_onlySharing = -1;           /* SharedResourceType_UL_OnlySharing */
static int hf_xnap_ul_and_dl_Sharing = -1;        /* SharedResourceType_ULDL_Sharing */
static int hf_xnap_ul_resourceBitmap = -1;        /* DataTrafficResources */
static int hf_xnap_ul_resources = -1;             /* SharedResourceType_ULDL_Sharing_UL_Resources */
static int hf_xnap_dl_resources = -1;             /* SharedResourceType_ULDL_Sharing_DL_Resources */
static int hf_xnap_unchanged = -1;                /* NULL */
static int hf_xnap_changed = -1;                  /* SharedResourceType_ULDL_Sharing_UL_ResourcesChanged */
static int hf_xnap_changed_01 = -1;               /* SharedResourceType_ULDL_Sharing_DL_ResourcesChanged */
static int hf_xnap_dl_resourceBitmap = -1;        /* DataTrafficResources */
static int hf_xnap_SliceSupport_List_item = -1;   /* S_NSSAI */
static int hf_xnap_sst = -1;                      /* OCTET_STRING_SIZE_1 */
static int hf_xnap_sd = -1;                       /* OCTET_STRING_SIZE_3 */
static int hf_xnap_specialSubframePattern = -1;   /* SpecialSubframePatterns_E_UTRA */
static int hf_xnap_cyclicPrefixDL = -1;           /* CyclicPrefix_E_UTRA_DL */
static int hf_xnap_cyclicPrefixUL = -1;           /* CyclicPrefix_E_UTRA_UL */
static int hf_xnap_sulFrequencyInfo = -1;         /* NRARFCN */
static int hf_xnap_sulTransmissionBandwidth = -1;  /* NRTransmissionBandwidth */
static int hf_xnap_SupportedSULBandList_item = -1;  /* SupportedSULBandItem */
static int hf_xnap_sulBandItem = -1;              /* SUL_FrequencyBand */
static int hf_xnap_TAISupport_List_item = -1;     /* TAISupport_Item */
static int hf_xnap_broadcastPLMNs_03 = -1;        /* SEQUENCE_SIZE_1_maxnoofsupportedPLMNs_OF_BroadcastPLMNinTAISupport_Item */
static int hf_xnap_broadcastPLMNs_item_01 = -1;   /* BroadcastPLMNinTAISupport_Item */
static int hf_xnap_nr_02 = -1;                    /* NR_CGI */
static int hf_xnap_e_utra_02 = -1;                /* E_UTRA_CGI */
static int hf_xnap_TNLA_To_Add_List_item = -1;    /* TNLA_To_Add_Item */
static int hf_xnap_tNLAssociationTransportLayerAddress = -1;  /* CPTransportLayerInformation */
static int hf_xnap_tNLAssociationUsage = -1;      /* TNLAssociationUsage */
static int hf_xnap_TNLA_To_Update_List_item = -1;  /* TNLA_To_Update_Item */
static int hf_xnap_TNLA_To_Remove_List_item = -1;  /* TNLA_To_Remove_Item */
static int hf_xnap_TNLA_Setup_List_item = -1;     /* TNLA_Setup_Item */
static int hf_xnap_TNLA_Failed_To_Setup_List_item = -1;  /* TNLA_Failed_To_Setup_Item */
static int hf_xnap_ng_ran_TraceID = -1;           /* T_ng_ran_TraceID */
static int hf_xnap_interfaces_to_trace = -1;      /* T_interfaces_to_trace */
static int hf_xnap_trace_depth = -1;              /* Trace_Depth */
static int hf_xnap_trace_coll_address = -1;       /* TransportLayerAddress */
static int hf_xnap_ie_Extension = -1;             /* ProtocolExtensionContainer */
static int hf_xnap_dl_UE_AMBR = -1;               /* BitRate */
static int hf_xnap_ul_UE_AMBR = -1;               /* BitRate */
static int hf_xnap_rRCResume = -1;                /* UEContextIDforRRCResume */
static int hf_xnap_rRRCReestablishment = -1;      /* UEContextIDforRRCReestablishment */
static int hf_xnap_i_rnti = -1;                   /* I_RNTI */
static int hf_xnap_allocated_c_rnti = -1;         /* C_RNTI */
static int hf_xnap_accessPCI = -1;                /* NG_RAN_CellPCI */
static int hf_xnap_c_rnti = -1;                   /* C_RNTI */
static int hf_xnap_failureCellPCI = -1;           /* NG_RAN_CellPCI */
static int hf_xnap_ng_c_UE_signalling_ref = -1;   /* AMF_UE_NGAP_ID */
static int hf_xnap_signalling_TNL_at_source = -1;  /* CPTransportLayerInformation */
static int hf_xnap_ueSecurityCapabilities = -1;   /* UESecurityCapabilities */
static int hf_xnap_securityInformation = -1;      /* AS_SecurityInformation */
static int hf_xnap_ue_AMBR = -1;                  /* UEAggregateMaximumBitRate */
static int hf_xnap_pduSessionResourcesToBeSetup_List = -1;  /* PDUSessionResourcesToBeSetup_List */
static int hf_xnap_rrc_Context = -1;              /* T_rrc_Context */
static int hf_xnap_mobilityRestrictionList = -1;  /* MobilityRestrictionList */
static int hf_xnap_indexToRatFrequencySelectionPriority = -1;  /* RFSP_Index */
static int hf_xnap_UEHistoryInformation_item = -1;  /* LastVisitedCell_Item */
static int hf_xnap_indexLength10 = -1;            /* BIT_STRING_SIZE_10 */
static int hf_xnap_uERadioCapabilityForPagingOfNR = -1;  /* UERadioCapabilityForPagingOfNR */
static int hf_xnap_uERadioCapabilityForPagingOfEUTRA = -1;  /* UERadioCapabilityForPagingOfEUTRA */
static int hf_xnap_nr_EncyptionAlgorithms = -1;   /* T_nr_EncyptionAlgorithms */
static int hf_xnap_nr_IntegrityProtectionAlgorithms = -1;  /* T_nr_IntegrityProtectionAlgorithms */
static int hf_xnap_e_utra_EncyptionAlgorithms = -1;  /* T_e_utra_EncyptionAlgorithms */
static int hf_xnap_e_utra_IntegrityProtectionAlgorithms = -1;  /* T_e_utra_IntegrityProtectionAlgorithms */
static int hf_xnap_uL_PDCP = -1;                  /* UL_UE_Configuration */
static int hf_xnap_gtpTunnel = -1;                /* GTPtunnelTransportLayerInformation */
static int hf_xnap_UPTransportParameters_item = -1;  /* UPTransportParametersItem */
static int hf_xnap_upTNLInfo = -1;                /* UPTransportLayerInformation */
static int hf_xnap_cellGroupID = -1;              /* CellGroupID */
static int hf_xnap_VolumeTimedReportList_item = -1;  /* VolumeTimedReport_Item */
static int hf_xnap_startTimeStamp = -1;           /* T_startTimeStamp */
static int hf_xnap_endTimeStamp = -1;             /* T_endTimeStamp */
static int hf_xnap_usageCountUL = -1;             /* INTEGER_0_18446744073709551615 */
static int hf_xnap_usageCountDL = -1;             /* INTEGER_0_18446744073709551615 */
static int hf_xnap_protocolIEs = -1;              /* ProtocolIE_Container */
static int hf_xnap_ng_c_UE_reference = -1;        /* AMF_UE_NGAP_ID */
static int hf_xnap_cp_TNL_info_source = -1;       /* CPTransportLayerInformation */
static int hf_xnap_rrc_Context_01 = -1;           /* T_rrc_Context_01 */
static int hf_xnap_locationReportingInformation = -1;  /* LocationReportingInformation */
static int hf_xnap_mrl = -1;                      /* MobilityRestrictionList */
static int hf_xnap_globalNG_RANNode_ID = -1;      /* GlobalNG_RANNode_ID */
static int hf_xnap_sN_NG_RANnodeUEXnAPID = -1;    /* NG_RANnodeUEXnAPID */
static int hf_xnap_PDUSessionToBeAddedAddReq_item = -1;  /* PDUSessionToBeAddedAddReq_Item */
static int hf_xnap_sN_PDUSessionAMBR = -1;        /* PDUSessionAggregateMaximumBitRate */
static int hf_xnap_sn_terminated = -1;            /* PDUSessionResourceSetupInfo_SNterminated */
static int hf_xnap_mn_terminated = -1;            /* PDUSessionResourceSetupInfo_MNterminated */
static int hf_xnap_PDUSessionAdmittedAddedAddReqAck_item = -1;  /* PDUSessionAdmittedAddedAddReqAck_Item */
static int hf_xnap_sn_terminated_01 = -1;         /* PDUSessionResourceSetupResponseInfo_SNterminated */
static int hf_xnap_mn_terminated_01 = -1;         /* PDUSessionResourceSetupResponseInfo_MNterminated */
static int hf_xnap_pduSessionResourcesNotAdmitted_SNterminated = -1;  /* PDUSessionResourcesNotAdmitted_List */
static int hf_xnap_pduSessionResourcesNotAdmitted_MNterminated = -1;  /* PDUSessionResourcesNotAdmitted_List */
static int hf_xnap_responseType_ReconfComplete = -1;  /* ResponseType_ReconfComplete */
static int hf_xnap_configuration_successfully_applied = -1;  /* Configuration_successfully_applied */
static int hf_xnap_configuration_rejected_by_M_NG_RANNode = -1;  /* Configuration_rejected_by_M_NG_RANNode */
static int hf_xnap_m_NG_RANNode_to_S_NG_RANNode_Container = -1;  /* T_m_NG_RANNode_to_S_NG_RANNode_Container */
static int hf_xnap_m_NG_RANNode_to_S_NG_RANNode_Container_01 = -1;  /* T_m_NG_RANNode_to_S_NG_RANNode_Container_01 */
static int hf_xnap_s_ng_RANnode_SecurityKey = -1;  /* S_NG_RANnode_SecurityKey */
static int hf_xnap_s_ng_RANnodeUE_AMBR = -1;      /* UEAggregateMaximumBitRate */
static int hf_xnap_lowerLayerPresenceStatusChange = -1;  /* LowerLayerPresenceStatusChange */
static int hf_xnap_pduSessionResourceToBeAdded = -1;  /* PDUSessionsToBeAdded_SNModRequest_List */
static int hf_xnap_pduSessionResourceToBeModified = -1;  /* PDUSessionsToBeModified_SNModRequest_List */
static int hf_xnap_pduSessionResourceToBeReleased = -1;  /* PDUSessionsToBeReleased_SNModRequest_List */
static int hf_xnap_PDUSessionsToBeAdded_SNModRequest_List_item = -1;  /* PDUSessionsToBeAdded_SNModRequest_Item */
static int hf_xnap_PDUSessionsToBeModified_SNModRequest_List_item = -1;  /* PDUSessionsToBeModified_SNModRequest_Item */
static int hf_xnap_sn_terminated_02 = -1;         /* PDUSessionResourceModificationInfo_SNterminated */
static int hf_xnap_mn_terminated_02 = -1;         /* PDUSessionResourceModificationInfo_MNterminated */
static int hf_xnap_pdu_session_list = -1;         /* PDUSession_List_withCause */
static int hf_xnap_pduSessionResourcesAdmittedToBeAdded = -1;  /* PDUSessionAdmittedToBeAddedSNModResponse */
static int hf_xnap_pduSessionResourcesAdmittedToBeModified = -1;  /* PDUSessionAdmittedToBeModifiedSNModResponse */
static int hf_xnap_pduSessionResourcesAdmittedToBeReleased = -1;  /* PDUSessionAdmittedToBeReleasedSNModResponse */
static int hf_xnap_PDUSessionAdmittedToBeAddedSNModResponse_item = -1;  /* PDUSessionAdmittedToBeAddedSNModResponse_Item */
static int hf_xnap_PDUSessionAdmittedToBeModifiedSNModResponse_item = -1;  /* PDUSessionAdmittedToBeModifiedSNModResponse_Item */
static int hf_xnap_sn_terminated_03 = -1;         /* PDUSessionResourceModificationResponseInfo_SNterminated */
static int hf_xnap_mn_terminated_03 = -1;         /* PDUSessionResourceModificationResponseInfo_MNterminated */
static int hf_xnap_sn_terminated_04 = -1;         /* PDUSession_List_withDataForwardingRequest */
static int hf_xnap_mn_terminated_04 = -1;         /* PDUSession_List_withCause */
static int hf_xnap_pdu_Session_List = -1;         /* PDUSession_List */
static int hf_xnap_PDUSessionToBeModifiedSNModRequired_item = -1;  /* PDUSessionToBeModifiedSNModRequired_Item */
static int hf_xnap_sn_terminated_05 = -1;         /* PDUSessionResourceModRqdInfo_SNterminated */
static int hf_xnap_mn_terminated_05 = -1;         /* PDUSessionResourceModRqdInfo_MNterminated */
static int hf_xnap_PDUSessionAdmittedModSNModConfirm_item = -1;  /* PDUSessionAdmittedModSNModConfirm_Item */
static int hf_xnap_sn_terminated_06 = -1;         /* PDUSessionResourceModConfirmInfo_SNterminated */
static int hf_xnap_mn_terminated_06 = -1;         /* PDUSessionResourceModConfirmInfo_MNterminated */
static int hf_xnap_sn_terminated_07 = -1;         /* PDUSession_List_withDataForwardingFromTarget */
static int hf_xnap_mn_terminated_07 = -1;         /* PDUSession_List */
static int hf_xnap_pduSessionsToBeReleasedList_SNterminated = -1;  /* PDUSession_List_withDataForwardingRequest */
static int hf_xnap_pduSessionsReleasedList_SNterminated = -1;  /* PDUSession_List_withDataForwardingFromTarget */
static int hf_xnap_BearersSubjectToCounterCheck_List_item = -1;  /* BearersSubjectToCounterCheck_Item */
static int hf_xnap_ul_count = -1;                 /* INTEGER_0_4294967295 */
static int hf_xnap_dl_count = -1;                 /* INTEGER_0_4294967295 */
static int hf_xnap_PDUSession_SNChangeRequired_List_item = -1;  /* PDUSession_SNChangeRequired_Item */
static int hf_xnap_sn_terminated_08 = -1;         /* PDUSessionResourceChangeRequiredInfo_SNterminated */
static int hf_xnap_mn_terminated_08 = -1;         /* PDUSessionResourceChangeRequiredInfo_MNterminated */
static int hf_xnap_PDUSession_SNChangeConfirm_List_item = -1;  /* PDUSession_SNChangeConfirm_Item */
static int hf_xnap_sn_terminated_09 = -1;         /* PDUSessionResourceChangeConfirmInfo_SNterminated */
static int hf_xnap_mn_terminated_09 = -1;         /* PDUSessionResourceChangeConfirmInfo_MNterminated */
static int hf_xnap_rrcContainer = -1;             /* OCTET_STRING */
static int hf_xnap_srbType = -1;                  /* T_srbType */
static int hf_xnap_deliveryStatus = -1;           /* DeliveryStatus */
static int hf_xnap_PDUSessionResourcesNotifyList_item = -1;  /* PDUSessionResourcesNotify_Item */
static int hf_xnap_qosFlowsNotificationContrIndInfo = -1;  /* QoSFlowNotificationControlIndicationInfo */
static int hf_xnap_PDUSessionResourcesActivityNotifyList_item = -1;  /* PDUSessionResourcesActivityNotify_Item */
static int hf_xnap_pduSessionLevelUPactivityreport = -1;  /* UserPlaneTrafficActivityReport */
static int hf_xnap_qosFlowsActivityNotifyList = -1;  /* QoSFlowsActivityNotifyList */
static int hf_xnap_QoSFlowsActivityNotifyList_item = -1;  /* QoSFlowsActivityNotifyItem */
static int hf_xnap_gNB_01 = -1;                   /* ProtocolIE_Container */
static int hf_xnap_ng_eNB_01 = -1;                /* ProtocolIE_Container */
static int hf_xnap_ng_eNB_02 = -1;                /* RespondingNodeTypeConfigUpdateAck_ng_eNB */
static int hf_xnap_gNB_02 = -1;                   /* RespondingNodeTypeConfigUpdateAck_gNB */
static int hf_xnap_served_NR_Cells = -1;          /* ServedCells_NR */
static int hf_xnap_ng_eNB_03 = -1;                /* ResourceCoordRequest_ng_eNB_initiated */
static int hf_xnap_gNB_03 = -1;                   /* ResourceCoordRequest_gNB_initiated */
static int hf_xnap_dataTrafficResourceIndication = -1;  /* DataTrafficResourceIndication */
static int hf_xnap_spectrumSharingGroupID = -1;   /* SpectrumSharingGroupID */
static int hf_xnap_listofE_UTRACells = -1;        /* SEQUENCE_SIZE_1_maxnoofCellsinNG_RANnode_OF_E_UTRA_CGI */
static int hf_xnap_listofE_UTRACells_item = -1;   /* E_UTRA_CGI */
static int hf_xnap_listofNRCells = -1;            /* SEQUENCE_SIZE_1_maxnoofCellsinNG_RANnode_OF_NR_CGI */
static int hf_xnap_listofNRCells_item = -1;       /* NR_CGI */
static int hf_xnap_ng_eNB_04 = -1;                /* ResourceCoordResponse_ng_eNB_initiated */
static int hf_xnap_gNB_04 = -1;                   /* ResourceCoordResponse_gNB_initiated */
static int hf_xnap_nr_cells = -1;                 /* SEQUENCE_SIZE_1_maxnoofCellsinNG_RANnode_OF_NR_CGI */
static int hf_xnap_nr_cells_item = -1;            /* NR_CGI */
static int hf_xnap_e_utra_cells = -1;             /* SEQUENCE_SIZE_1_maxnoofCellsinNG_RANnode_OF_E_UTRA_CGI */
static int hf_xnap_e_utra_cells_item = -1;        /* E_UTRA_CGI */
static int hf_xnap_privateIEs = -1;               /* PrivateIE_Container */
static int hf_xnap_initiatingMessage = -1;        /* InitiatingMessage */
static int hf_xnap_successfulOutcome = -1;        /* SuccessfulOutcome */
static int hf_xnap_unsuccessfulOutcome = -1;      /* UnsuccessfulOutcome */
static int hf_xnap_initiatingMessage_value = -1;  /* InitiatingMessage_value */
static int hf_xnap_successfulOutcome_value = -1;  /* SuccessfulOutcome_value */
static int hf_xnap_value = -1;                    /* UnsuccessfulOutcome_value */
/* named bits */
static int hf_xnap_RAT_RestrictionInformation_e_UTRA = -1;
static int hf_xnap_RAT_RestrictionInformation_nR = -1;
static int hf_xnap_T_interfaces_to_trace_ng_c = -1;
static int hf_xnap_T_interfaces_to_trace_x_nc = -1;
static int hf_xnap_T_interfaces_to_trace_uu = -1;
static int hf_xnap_T_interfaces_to_trace_f1_c = -1;
static int hf_xnap_T_interfaces_to_trace_e1 = -1;
static int hf_xnap_T_nr_EncyptionAlgorithms_spare_bit0 = -1;
static int hf_xnap_T_nr_EncyptionAlgorithms_nea1_128 = -1;
static int hf_xnap_T_nr_EncyptionAlgorithms_nea2_128 = -1;
static int hf_xnap_T_nr_EncyptionAlgorithms_nea3_128 = -1;
static int hf_xnap_T_nr_IntegrityProtectionAlgorithms_spare_bit0 = -1;
static int hf_xnap_T_nr_IntegrityProtectionAlgorithms_nia1_128 = -1;
static int hf_xnap_T_nr_IntegrityProtectionAlgorithms_nia2_128 = -1;
static int hf_xnap_T_nr_IntegrityProtectionAlgorithms_nia3_128 = -1;
static int hf_xnap_T_e_utra_EncyptionAlgorithms_spare_bit0 = -1;
static int hf_xnap_T_e_utra_EncyptionAlgorithms_eea1_128 = -1;
static int hf_xnap_T_e_utra_EncyptionAlgorithms_eea2_128 = -1;
static int hf_xnap_T_e_utra_EncyptionAlgorithms_eea3_128 = -1;
static int hf_xnap_T_e_utra_IntegrityProtectionAlgorithms_spare_bit0 = -1;
static int hf_xnap_T_e_utra_IntegrityProtectionAlgorithms_eia1_128 = -1;
static int hf_xnap_T_e_utra_IntegrityProtectionAlgorithms_eia2_128 = -1;
static int hf_xnap_T_e_utra_IntegrityProtectionAlgorithms_eia3_128 = -1;

/*--- End of included file: packet-xnap-hf.c ---*/
#line 55 "./asn1/xnap/packet-xnap-template.c"

/* Initialize the subtree pointers */
static gint ett_xnap = -1;
static gint ett_xnap_RRC_Context = -1;
static gint ett_nxap_container = -1;
static gint ett_xnap_PLMN_Identity = -1;
static gint ett_xnap_measurementTimingConfiguration = -1;
static gint ett_xnap_TransportLayerAddress = -1;
static gint ett_xnap_ng_ran_TraceID = -1;
static gint ett_xnap_LastVisitedEUTRANCellInformation = -1;
static gint ett_xnap_LastVisitedNGRANCellInformation = -1;
static gint ett_xnap_LastVisitedUTRANCellInformation = -1;
static gint ett_xnap_LastVisitedGERANCellInformation = -1;
static gint ett_xnap_UERadioCapabilityForPagingOfNR = -1;
static gint ett_xnap_UERadioCapabilityForPagingOfEUTRA = -1;
static gint ett_xnap_FiveGCMobilityRestrictionListContainer = -1;

/*--- Included file: packet-xnap-ett.c ---*/
#line 1 "./asn1/xnap/packet-xnap-ett.c"
static gint ett_xnap_PrivateIE_ID = -1;
static gint ett_xnap_ProtocolIE_Container = -1;
static gint ett_xnap_ProtocolIE_Field = -1;
static gint ett_xnap_ProtocolExtensionContainer = -1;
static gint ett_xnap_ProtocolExtensionField = -1;
static gint ett_xnap_PrivateIE_Container = -1;
static gint ett_xnap_PrivateIE_Field = -1;
static gint ett_xnap_Additional_UL_NG_U_TNLatUPF_Item = -1;
static gint ett_xnap_Additional_UL_NG_U_TNLatUPF_List = -1;
static gint ett_xnap_AllocationandRetentionPriority = -1;
static gint ett_xnap_AMF_Region_Information = -1;
static gint ett_xnap_GlobalAMF_Region_Information = -1;
static gint ett_xnap_AreaOfInterestInformation = -1;
static gint ett_xnap_AreaOfInterest_Item = -1;
static gint ett_xnap_AS_SecurityInformation = -1;
static gint ett_xnap_AssistanceDataForRANPaging = -1;
static gint ett_xnap_BPLMN_ID_Info_EUTRA = -1;
static gint ett_xnap_BPLMN_ID_Info_EUTRA_Item = -1;
static gint ett_xnap_BPLMN_ID_Info_NR = -1;
static gint ett_xnap_BPLMN_ID_Info_NR_Item = -1;
static gint ett_xnap_BroadcastPLMNs = -1;
static gint ett_xnap_BroadcastEUTRAPLMNs = -1;
static gint ett_xnap_BroadcastPLMNinTAISupport_Item = -1;
static gint ett_xnap_Cause = -1;
static gint ett_xnap_CellAssistanceInfo_NR = -1;
static gint ett_xnap_SEQUENCE_SIZE_1_maxnoofCellsinNG_RANnode_OF_NR_CGI = -1;
static gint ett_xnap_Connectivity_Support = -1;
static gint ett_xnap_COUNT_PDCP_SN12 = -1;
static gint ett_xnap_COUNT_PDCP_SN18 = -1;
static gint ett_xnap_CPTransportLayerInformation = -1;
static gint ett_xnap_CriticalityDiagnostics = -1;
static gint ett_xnap_CriticalityDiagnostics_IE_List = -1;
static gint ett_xnap_CriticalityDiagnostics_IE_List_item = -1;
static gint ett_xnap_XnUAddressInfoperPDUSession_List = -1;
static gint ett_xnap_XnUAddressInfoperPDUSession_Item = -1;
static gint ett_xnap_DataForwardingInfoFromTargetNGRANnode = -1;
static gint ett_xnap_QoSFLowsAcceptedToBeForwarded_List = -1;
static gint ett_xnap_QoSFLowsAcceptedToBeForwarded_Item = -1;
static gint ett_xnap_DataforwardingandOffloadingInfofromSource = -1;
static gint ett_xnap_QoSFLowsToBeForwarded_List = -1;
static gint ett_xnap_QoSFLowsToBeForwarded_Item = -1;
static gint ett_xnap_DataForwardingResponseDRBItemList = -1;
static gint ett_xnap_DataForwardingResponseDRBItem = -1;
static gint ett_xnap_DataTrafficResourceIndication = -1;
static gint ett_xnap_DRB_List = -1;
static gint ett_xnap_DRB_List_withCause = -1;
static gint ett_xnap_DRB_List_withCause_Item = -1;
static gint ett_xnap_DRBsSubjectToStatusTransfer_List = -1;
static gint ett_xnap_DRBsSubjectToStatusTransfer_Item = -1;
static gint ett_xnap_DRBBStatusTransferChoice = -1;
static gint ett_xnap_DRBBStatusTransfer12bitsSN = -1;
static gint ett_xnap_DRBBStatusTransfer18bitsSN = -1;
static gint ett_xnap_DRBToQoSFlowMapping_List = -1;
static gint ett_xnap_DRBToQoSFlowMapping_Item = -1;
static gint ett_xnap_Dynamic5QIDescriptor = -1;
static gint ett_xnap_E_UTRA_CGI = -1;
static gint ett_xnap_E_UTRAMultibandInfoList = -1;
static gint ett_xnap_E_UTRAPRACHConfiguration = -1;
static gint ett_xnap_EndpointIPAddressAndPort = -1;
static gint ett_xnap_ExpectedUEActivityBehaviour = -1;
static gint ett_xnap_ExpectedUEBehaviour = -1;
static gint ett_xnap_ExpectedUEMovingTrajectory = -1;
static gint ett_xnap_ExpectedUEMovingTrajectoryItem = -1;
static gint ett_xnap_GBRQoSFlowInfo = -1;
static gint ett_xnap_GlobalgNB_ID = -1;
static gint ett_xnap_GNB_ID_Choice = -1;
static gint ett_xnap_GlobalngeNB_ID = -1;
static gint ett_xnap_ENB_ID_Choice = -1;
static gint ett_xnap_GlobalNG_RANCell_ID = -1;
static gint ett_xnap_GlobalNG_RANNode_ID = -1;
static gint ett_xnap_GTPtunnelTransportLayerInformation = -1;
static gint ett_xnap_GUAMI = -1;
static gint ett_xnap_I_RNTI = -1;
static gint ett_xnap_LastVisitedCell_Item = -1;
static gint ett_xnap_ListOfCells = -1;
static gint ett_xnap_CellsinAoI_Item = -1;
static gint ett_xnap_ListOfRANNodesinAoI = -1;
static gint ett_xnap_GlobalNG_RANNodesinAoI_Item = -1;
static gint ett_xnap_ListOfTAIsinAoI = -1;
static gint ett_xnap_TAIsinAoI_Item = -1;
static gint ett_xnap_LocationReportingInformation = -1;
static gint ett_xnap_MaximumIPdatarate = -1;
static gint ett_xnap_MBSFNSubframeAllocation_E_UTRA = -1;
static gint ett_xnap_MBSFNSubframeInfo_E_UTRA = -1;
static gint ett_xnap_MBSFNSubframeInfo_E_UTRA_Item = -1;
static gint ett_xnap_MobilityRestrictionList = -1;
static gint ett_xnap_SEQUENCE_SIZE_1_maxnoofEPLMNs_OF_PLMN_Identity = -1;
static gint ett_xnap_CNTypeRestrictionsForEquivalent = -1;
static gint ett_xnap_CNTypeRestrictionsForEquivalentItem = -1;
static gint ett_xnap_RAT_RestrictionsList = -1;
static gint ett_xnap_RAT_RestrictionsItem = -1;
static gint ett_xnap_RAT_RestrictionInformation = -1;
static gint ett_xnap_ForbiddenAreaList = -1;
static gint ett_xnap_ForbiddenAreaItem = -1;
static gint ett_xnap_SEQUENCE_SIZE_1_maxnoofForbiddenTACs_OF_TAC = -1;
static gint ett_xnap_ServiceAreaList = -1;
static gint ett_xnap_ServiceAreaItem = -1;
static gint ett_xnap_SEQUENCE_SIZE_1_maxnoofAllowedAreas_OF_TAC = -1;
static gint ett_xnap_MR_DC_ResourceCoordinationInfo = -1;
static gint ett_xnap_NG_RAN_Node_ResourceCoordinationInfo = -1;
static gint ett_xnap_E_UTRA_ResourceCoordinationInfo = -1;
static gint ett_xnap_NR_ResourceCoordinationInfo = -1;
static gint ett_xnap_NE_DC_TDM_Pattern = -1;
static gint ett_xnap_NeighbourInformation_E_UTRA = -1;
static gint ett_xnap_NeighbourInformation_E_UTRA_Item = -1;
static gint ett_xnap_NeighbourInformation_NR = -1;
static gint ett_xnap_NeighbourInformation_NR_Item = -1;
static gint ett_xnap_NeighbourInformation_NR_ModeInfo = -1;
static gint ett_xnap_NeighbourInformation_NR_ModeFDDInfo = -1;
static gint ett_xnap_NeighbourInformation_NR_ModeTDDInfo = -1;
static gint ett_xnap_NG_RAN_Cell_Identity = -1;
static gint ett_xnap_NG_RAN_CellPCI = -1;
static gint ett_xnap_NonDynamic5QIDescriptor = -1;
static gint ett_xnap_NG_RAN_Cell_Identity_ListinRANPagingArea = -1;
static gint ett_xnap_NR_CGI = -1;
static gint ett_xnap_NRFrequencyBand_List = -1;
static gint ett_xnap_NRFrequencyBandItem = -1;
static gint ett_xnap_NRFrequencyInfo = -1;
static gint ett_xnap_NRModeInfo = -1;
static gint ett_xnap_NRModeInfoFDD = -1;
static gint ett_xnap_NRModeInfoTDD = -1;
static gint ett_xnap_NRTransmissionBandwidth = -1;
static gint ett_xnap_PacketErrorRate = -1;
static gint ett_xnap_PDCPChangeIndication = -1;
static gint ett_xnap_PDCPSNLength = -1;
static gint ett_xnap_PDUSessionAggregateMaximumBitRate = -1;
static gint ett_xnap_PDUSession_List = -1;
static gint ett_xnap_PDUSession_List_withCause = -1;
static gint ett_xnap_PDUSession_List_withCause_Item = -1;
static gint ett_xnap_PDUSession_List_withDataForwardingFromTarget = -1;
static gint ett_xnap_PDUSession_List_withDataForwardingFromTarget_Item = -1;
static gint ett_xnap_PDUSession_List_withDataForwardingRequest = -1;
static gint ett_xnap_PDUSession_List_withDataForwardingRequest_Item = -1;
static gint ett_xnap_PDUSessionResourcesAdmitted_List = -1;
static gint ett_xnap_PDUSessionResourcesAdmitted_Item = -1;
static gint ett_xnap_PDUSessionResourceAdmittedInfo = -1;
static gint ett_xnap_PDUSessionResourcesNotAdmitted_List = -1;
static gint ett_xnap_PDUSessionResourcesNotAdmitted_Item = -1;
static gint ett_xnap_PDUSessionResourcesToBeSetup_List = -1;
static gint ett_xnap_PDUSessionResourcesToBeSetup_Item = -1;
static gint ett_xnap_PDUSessionResourceSetupInfo_SNterminated = -1;
static gint ett_xnap_QoSFlowsToBeSetup_List_Setup_SNterminated = -1;
static gint ett_xnap_QoSFlowsToBeSetup_List_Setup_SNterminated_Item = -1;
static gint ett_xnap_PDUSessionResourceSetupResponseInfo_SNterminated = -1;
static gint ett_xnap_DRBsToBeSetupList_SetupResponse_SNterminated = -1;
static gint ett_xnap_DRBsToBeSetupList_SetupResponse_SNterminated_Item = -1;
static gint ett_xnap_QoSFlowsMappedtoDRB_SetupResponse_SNterminated = -1;
static gint ett_xnap_QoSFlowsMappedtoDRB_SetupResponse_SNterminated_Item = -1;
static gint ett_xnap_PDUSessionResourceSetupInfo_MNterminated = -1;
static gint ett_xnap_DRBsToBeSetupList_Setup_MNterminated = -1;
static gint ett_xnap_DRBsToBeSetupList_Setup_MNterminated_Item = -1;
static gint ett_xnap_QoSFlowsMappedtoDRB_Setup_MNterminated = -1;
static gint ett_xnap_QoSFlowsMappedtoDRB_Setup_MNterminated_Item = -1;
static gint ett_xnap_PDUSessionResourceSetupResponseInfo_MNterminated = -1;
static gint ett_xnap_DRBsAdmittedList_SetupResponse_MNterminated = -1;
static gint ett_xnap_DRBsAdmittedList_SetupResponse_MNterminated_Item = -1;
static gint ett_xnap_PDUSessionResourceModificationInfo_SNterminated = -1;
static gint ett_xnap_QoSFlowsToBeSetup_List_Modified_SNterminated = -1;
static gint ett_xnap_QoSFlowsToBeSetup_List_Modified_SNterminated_Item = -1;
static gint ett_xnap_DRBsToBeModified_List_Modified_SNterminated = -1;
static gint ett_xnap_DRBsToBeModified_List_Modified_SNterminated_Item = -1;
static gint ett_xnap_PDUSessionResourceModificationResponseInfo_SNterminated = -1;
static gint ett_xnap_DRBsToBeModifiedList_ModificationResponse_SNterminated = -1;
static gint ett_xnap_DRBsToBeModifiedList_ModificationResponse_SNterminated_Item = -1;
static gint ett_xnap_PDUSessionResourceModificationInfo_MNterminated = -1;
static gint ett_xnap_DRBsToBeModifiedList_Modification_MNterminated = -1;
static gint ett_xnap_DRBsToBeModifiedList_Modification_MNterminated_Item = -1;
static gint ett_xnap_PDUSessionResourceModificationResponseInfo_MNterminated = -1;
static gint ett_xnap_DRBsAdmittedList_ModificationResponse_MNterminated = -1;
static gint ett_xnap_DRBsAdmittedList_ModificationResponse_MNterminated_Item = -1;
static gint ett_xnap_PDUSessionResourceChangeRequiredInfo_SNterminated = -1;
static gint ett_xnap_PDUSessionResourceChangeConfirmInfo_SNterminated = -1;
static gint ett_xnap_PDUSessionResourceChangeRequiredInfo_MNterminated = -1;
static gint ett_xnap_PDUSessionResourceChangeConfirmInfo_MNterminated = -1;
static gint ett_xnap_PDUSessionResourceModRqdInfo_SNterminated = -1;
static gint ett_xnap_DRBsToBeSetup_List_ModRqd_SNterminated = -1;
static gint ett_xnap_DRBsToBeSetup_List_ModRqd_SNterminated_Item = -1;
static gint ett_xnap_QoSFlowsSetupMappedtoDRB_ModRqd_SNterminated = -1;
static gint ett_xnap_QoSFlowsSetupMappedtoDRB_ModRqd_SNterminated_Item = -1;
static gint ett_xnap_DRBsToBeModified_List_ModRqd_SNterminated = -1;
static gint ett_xnap_DRBsToBeModified_List_ModRqd_SNterminated_Item = -1;
static gint ett_xnap_QoSFlowsModifiedMappedtoDRB_ModRqd_SNterminated = -1;
static gint ett_xnap_QoSFlowsModifiedMappedtoDRB_ModRqd_SNterminated_Item = -1;
static gint ett_xnap_PDUSessionResourceModConfirmInfo_SNterminated = -1;
static gint ett_xnap_DRBsAdmittedList_ModConfirm_SNterminated = -1;
static gint ett_xnap_DRBsAdmittedList_ModConfirm_SNterminated_Item = -1;
static gint ett_xnap_PDUSessionResourceModRqdInfo_MNterminated = -1;
static gint ett_xnap_DRBsToBeModified_List_ModRqd_MNterminated = -1;
static gint ett_xnap_DRBsToBeModified_List_ModRqd_MNterminated_Item = -1;
static gint ett_xnap_PDUSessionResourceModConfirmInfo_MNterminated = -1;
static gint ett_xnap_PDUSessionResourceBearerSetupCompleteInfo_SNterminated = -1;
static gint ett_xnap_SEQUENCE_SIZE_1_maxnoofDRBs_OF_DRBsToBeSetupList_BearerSetupComplete_SNterminated_Item = -1;
static gint ett_xnap_DRBsToBeSetupList_BearerSetupComplete_SNterminated_Item = -1;
static gint ett_xnap_PDUSessionResourceSecondaryRATUsageList = -1;
static gint ett_xnap_PDUSessionResourceSecondaryRATUsageItem = -1;
static gint ett_xnap_PDUSessionUsageReport = -1;
static gint ett_xnap_ProtectedE_UTRAResourceIndication = -1;
static gint ett_xnap_ProtectedE_UTRAResourceList = -1;
static gint ett_xnap_ProtectedE_UTRAResource_Item = -1;
static gint ett_xnap_ProtectedE_UTRAFootprintTimePattern = -1;
static gint ett_xnap_QoSCharacteristics = -1;
static gint ett_xnap_QoSFlowLevelQoSParameters = -1;
static gint ett_xnap_QoSFlowNotificationControlIndicationInfo = -1;
static gint ett_xnap_QoSFlowNotify_Item = -1;
static gint ett_xnap_QoSFlows_List = -1;
static gint ett_xnap_QoSFlow_Item = -1;
static gint ett_xnap_QoSFlows_List_withCause = -1;
static gint ett_xnap_QoSFlowwithCause_Item = -1;
static gint ett_xnap_QoSFlowsAdmitted_List = -1;
static gint ett_xnap_QoSFlowsAdmitted_Item = -1;
static gint ett_xnap_QoSFlowsToBeSetup_List = -1;
static gint ett_xnap_QoSFlowsToBeSetup_Item = -1;
static gint ett_xnap_QoSFlowsUsageReportList = -1;
static gint ett_xnap_QoSFlowsUsageReport_Item = -1;
static gint ett_xnap_RANAreaID = -1;
static gint ett_xnap_RANAreaID_List = -1;
static gint ett_xnap_RANPagingArea = -1;
static gint ett_xnap_RANPagingAreaChoice = -1;
static gint ett_xnap_RANPagingAttemptInfo = -1;
static gint ett_xnap_ReservedSubframePattern = -1;
static gint ett_xnap_ResetRequestTypeInfo = -1;
static gint ett_xnap_ResetRequestTypeInfo_Full = -1;
static gint ett_xnap_ResetRequestTypeInfo_Partial = -1;
static gint ett_xnap_ResetRequestPartialReleaseList = -1;
static gint ett_xnap_ResetRequestPartialReleaseItem = -1;
static gint ett_xnap_ResetResponseTypeInfo = -1;
static gint ett_xnap_ResetResponseTypeInfo_Full = -1;
static gint ett_xnap_ResetResponseTypeInfo_Partial = -1;
static gint ett_xnap_ResetResponsePartialReleaseList = -1;
static gint ett_xnap_ResetResponsePartialReleaseItem = -1;
static gint ett_xnap_RLC_Status = -1;
static gint ett_xnap_SecondarydataForwardingInfoFromTarget_Item = -1;
static gint ett_xnap_SecondarydataForwardingInfoFromTarget_List = -1;
static gint ett_xnap_SecondaryRATUsageInformation = -1;
static gint ett_xnap_SecurityIndication = -1;
static gint ett_xnap_SecurityResult = -1;
static gint ett_xnap_ServedCellInformation_E_UTRA = -1;
static gint ett_xnap_SEQUENCE_SIZE_1_maxnoofBPLMNs_OF_ServedCellInformation_E_UTRA_perBPLMN = -1;
static gint ett_xnap_ServedCellInformation_E_UTRA_perBPLMN = -1;
static gint ett_xnap_ServedCellInformation_E_UTRA_ModeInfo = -1;
static gint ett_xnap_ServedCellInformation_E_UTRA_FDDInfo = -1;
static gint ett_xnap_ServedCellInformation_E_UTRA_TDDInfo = -1;
static gint ett_xnap_ServedCells_E_UTRA = -1;
static gint ett_xnap_ServedCells_E_UTRA_Item = -1;
static gint ett_xnap_ServedCellsToUpdate_E_UTRA = -1;
static gint ett_xnap_SEQUENCE_SIZE_1_maxnoofCellsinNG_RANnode_OF_E_UTRA_CGI = -1;
static gint ett_xnap_ServedCells_ToModify_E_UTRA = -1;
static gint ett_xnap_ServedCells_ToModify_E_UTRA_Item = -1;
static gint ett_xnap_ServedCellInformation_NR = -1;
static gint ett_xnap_ServedCells_NR = -1;
static gint ett_xnap_ServedCells_NR_Item = -1;
static gint ett_xnap_ServedCells_ToModify_NR = -1;
static gint ett_xnap_ServedCells_ToModify_NR_Item = -1;
static gint ett_xnap_ServedCellsToUpdate_NR = -1;
static gint ett_xnap_SharedResourceType = -1;
static gint ett_xnap_SharedResourceType_UL_OnlySharing = -1;
static gint ett_xnap_SharedResourceType_ULDL_Sharing = -1;
static gint ett_xnap_SharedResourceType_ULDL_Sharing_UL_Resources = -1;
static gint ett_xnap_SharedResourceType_ULDL_Sharing_UL_ResourcesChanged = -1;
static gint ett_xnap_SharedResourceType_ULDL_Sharing_DL_Resources = -1;
static gint ett_xnap_SharedResourceType_ULDL_Sharing_DL_ResourcesChanged = -1;
static gint ett_xnap_SliceSupport_List = -1;
static gint ett_xnap_S_NSSAI = -1;
static gint ett_xnap_SpecialSubframeInfo_E_UTRA = -1;
static gint ett_xnap_SUL_Information = -1;
static gint ett_xnap_SupportedSULBandList = -1;
static gint ett_xnap_SupportedSULBandItem = -1;
static gint ett_xnap_TAISupport_List = -1;
static gint ett_xnap_TAISupport_Item = -1;
static gint ett_xnap_SEQUENCE_SIZE_1_maxnoofsupportedPLMNs_OF_BroadcastPLMNinTAISupport_Item = -1;
static gint ett_xnap_Target_CGI = -1;
static gint ett_xnap_TNLA_To_Add_List = -1;
static gint ett_xnap_TNLA_To_Add_Item = -1;
static gint ett_xnap_TNLA_To_Update_List = -1;
static gint ett_xnap_TNLA_To_Update_Item = -1;
static gint ett_xnap_TNLA_To_Remove_List = -1;
static gint ett_xnap_TNLA_To_Remove_Item = -1;
static gint ett_xnap_TNLA_Setup_List = -1;
static gint ett_xnap_TNLA_Setup_Item = -1;
static gint ett_xnap_TNLA_Failed_To_Setup_List = -1;
static gint ett_xnap_TNLA_Failed_To_Setup_Item = -1;
static gint ett_xnap_TraceActivation = -1;
static gint ett_xnap_T_interfaces_to_trace = -1;
static gint ett_xnap_UEAggregateMaximumBitRate = -1;
static gint ett_xnap_UEContextID = -1;
static gint ett_xnap_UEContextIDforRRCResume = -1;
static gint ett_xnap_UEContextIDforRRCReestablishment = -1;
static gint ett_xnap_UEContextInfoRetrUECtxtResp = -1;
static gint ett_xnap_UEHistoryInformation = -1;
static gint ett_xnap_UEIdentityIndexValue = -1;
static gint ett_xnap_UERadioCapabilityForPaging = -1;
static gint ett_xnap_UERANPagingIdentity = -1;
static gint ett_xnap_UESecurityCapabilities = -1;
static gint ett_xnap_T_nr_EncyptionAlgorithms = -1;
static gint ett_xnap_T_nr_IntegrityProtectionAlgorithms = -1;
static gint ett_xnap_T_e_utra_EncyptionAlgorithms = -1;
static gint ett_xnap_T_e_utra_IntegrityProtectionAlgorithms = -1;
static gint ett_xnap_ULConfiguration = -1;
static gint ett_xnap_UPTransportLayerInformation = -1;
static gint ett_xnap_UPTransportParameters = -1;
static gint ett_xnap_UPTransportParametersItem = -1;
static gint ett_xnap_VolumeTimedReportList = -1;
static gint ett_xnap_VolumeTimedReport_Item = -1;
static gint ett_xnap_HandoverRequest = -1;
static gint ett_xnap_UEContextInfoHORequest = -1;
static gint ett_xnap_UEContextRefAtSN_HORequest = -1;
static gint ett_xnap_HandoverRequestAcknowledge = -1;
static gint ett_xnap_HandoverPreparationFailure = -1;
static gint ett_xnap_SNStatusTransfer = -1;
static gint ett_xnap_UEContextRelease = -1;
static gint ett_xnap_HandoverCancel = -1;
static gint ett_xnap_RANPaging = -1;
static gint ett_xnap_RetrieveUEContextRequest = -1;
static gint ett_xnap_RetrieveUEContextResponse = -1;
static gint ett_xnap_RetrieveUEContextFailure = -1;
static gint ett_xnap_XnUAddressIndication = -1;
static gint ett_xnap_SNodeAdditionRequest = -1;
static gint ett_xnap_PDUSessionToBeAddedAddReq = -1;
static gint ett_xnap_PDUSessionToBeAddedAddReq_Item = -1;
static gint ett_xnap_SNodeAdditionRequestAcknowledge = -1;
static gint ett_xnap_PDUSessionAdmittedAddedAddReqAck = -1;
static gint ett_xnap_PDUSessionAdmittedAddedAddReqAck_Item = -1;
static gint ett_xnap_PDUSessionNotAdmittedAddReqAck = -1;
static gint ett_xnap_SNodeAdditionRequestReject = -1;
static gint ett_xnap_SNodeReconfigurationComplete = -1;
static gint ett_xnap_ResponseInfo_ReconfCompl = -1;
static gint ett_xnap_ResponseType_ReconfComplete = -1;
static gint ett_xnap_Configuration_successfully_applied = -1;
static gint ett_xnap_Configuration_rejected_by_M_NG_RANNode = -1;
static gint ett_xnap_SNodeModificationRequest = -1;
static gint ett_xnap_UEContextInfo_SNModRequest = -1;
static gint ett_xnap_PDUSessionsToBeAdded_SNModRequest_List = -1;
static gint ett_xnap_PDUSessionsToBeAdded_SNModRequest_Item = -1;
static gint ett_xnap_PDUSessionsToBeModified_SNModRequest_List = -1;
static gint ett_xnap_PDUSessionsToBeModified_SNModRequest_Item = -1;
static gint ett_xnap_PDUSessionsToBeReleased_SNModRequest_List = -1;
static gint ett_xnap_SNodeModificationRequestAcknowledge = -1;
static gint ett_xnap_PDUSessionAdmitted_SNModResponse = -1;
static gint ett_xnap_PDUSessionAdmittedToBeAddedSNModResponse = -1;
static gint ett_xnap_PDUSessionAdmittedToBeAddedSNModResponse_Item = -1;
static gint ett_xnap_PDUSessionAdmittedToBeModifiedSNModResponse = -1;
static gint ett_xnap_PDUSessionAdmittedToBeModifiedSNModResponse_Item = -1;
static gint ett_xnap_PDUSessionAdmittedToBeReleasedSNModResponse = -1;
static gint ett_xnap_PDUSessionNotAdmitted_SNModResponse = -1;
static gint ett_xnap_PDUSessionDataForwarding_SNModResponse = -1;
static gint ett_xnap_SNodeModificationRequestReject = -1;
static gint ett_xnap_SNodeModificationRequired = -1;
static gint ett_xnap_PDUSessionToBeModifiedSNModRequired = -1;
static gint ett_xnap_PDUSessionToBeModifiedSNModRequired_Item = -1;
static gint ett_xnap_PDUSessionToBeReleasedSNModRequired = -1;
static gint ett_xnap_SNodeModificationConfirm = -1;
static gint ett_xnap_PDUSessionAdmittedModSNModConfirm = -1;
static gint ett_xnap_PDUSessionAdmittedModSNModConfirm_Item = -1;
static gint ett_xnap_PDUSessionReleasedSNModConfirm = -1;
static gint ett_xnap_SNodeModificationRefuse = -1;
static gint ett_xnap_SNodeReleaseRequest = -1;
static gint ett_xnap_SNodeReleaseRequestAcknowledge = -1;
static gint ett_xnap_PDUSessionToBeReleasedList_RelReqAck = -1;
static gint ett_xnap_SNodeReleaseReject = -1;
static gint ett_xnap_SNodeReleaseRequired = -1;
static gint ett_xnap_PDUSessionToBeReleasedList_RelRqd = -1;
static gint ett_xnap_SNodeReleaseConfirm = -1;
static gint ett_xnap_PDUSessionReleasedList_RelConf = -1;
static gint ett_xnap_SNodeCounterCheckRequest = -1;
static gint ett_xnap_BearersSubjectToCounterCheck_List = -1;
static gint ett_xnap_BearersSubjectToCounterCheck_Item = -1;
static gint ett_xnap_SNodeChangeRequired = -1;
static gint ett_xnap_PDUSession_SNChangeRequired_List = -1;
static gint ett_xnap_PDUSession_SNChangeRequired_Item = -1;
static gint ett_xnap_SNodeChangeConfirm = -1;
static gint ett_xnap_PDUSession_SNChangeConfirm_List = -1;
static gint ett_xnap_PDUSession_SNChangeConfirm_Item = -1;
static gint ett_xnap_SNodeChangeRefuse = -1;
static gint ett_xnap_RRCTransfer = -1;
static gint ett_xnap_SplitSRB_RRCTransfer = -1;
static gint ett_xnap_UEReportRRCTransfer = -1;
static gint ett_xnap_NotificationControlIndication = -1;
static gint ett_xnap_PDUSessionResourcesNotifyList = -1;
static gint ett_xnap_PDUSessionResourcesNotify_Item = -1;
static gint ett_xnap_ActivityNotification = -1;
static gint ett_xnap_PDUSessionResourcesActivityNotifyList = -1;
static gint ett_xnap_PDUSessionResourcesActivityNotify_Item = -1;
static gint ett_xnap_QoSFlowsActivityNotifyList = -1;
static gint ett_xnap_QoSFlowsActivityNotifyItem = -1;
static gint ett_xnap_XnSetupRequest = -1;
static gint ett_xnap_XnSetupResponse = -1;
static gint ett_xnap_XnSetupFailure = -1;
static gint ett_xnap_NGRANNodeConfigurationUpdate = -1;
static gint ett_xnap_ConfigurationUpdateInitiatingNodeChoice = -1;
static gint ett_xnap_NGRANNodeConfigurationUpdateAcknowledge = -1;
static gint ett_xnap_RespondingNodeTypeConfigUpdateAck = -1;
static gint ett_xnap_RespondingNodeTypeConfigUpdateAck_ng_eNB = -1;
static gint ett_xnap_RespondingNodeTypeConfigUpdateAck_gNB = -1;
static gint ett_xnap_NGRANNodeConfigurationUpdateFailure = -1;
static gint ett_xnap_E_UTRA_NR_CellResourceCoordinationRequest = -1;
static gint ett_xnap_InitiatingNodeType_ResourceCoordRequest = -1;
static gint ett_xnap_ResourceCoordRequest_ng_eNB_initiated = -1;
static gint ett_xnap_ResourceCoordRequest_gNB_initiated = -1;
static gint ett_xnap_E_UTRA_NR_CellResourceCoordinationResponse = -1;
static gint ett_xnap_RespondingNodeType_ResourceCoordResponse = -1;
static gint ett_xnap_ResourceCoordResponse_ng_eNB_initiated = -1;
static gint ett_xnap_ResourceCoordResponse_gNB_initiated = -1;
static gint ett_xnap_SecondaryRATDataUsageReport = -1;
static gint ett_xnap_XnRemovalRequest = -1;
static gint ett_xnap_XnRemovalResponse = -1;
static gint ett_xnap_XnRemovalFailure = -1;
static gint ett_xnap_CellActivationRequest = -1;
static gint ett_xnap_ServedCellsToActivate = -1;
static gint ett_xnap_CellActivationResponse = -1;
static gint ett_xnap_ActivatedServedCells = -1;
static gint ett_xnap_CellActivationFailure = -1;
static gint ett_xnap_ResetRequest = -1;
static gint ett_xnap_ResetResponse = -1;
static gint ett_xnap_ErrorIndication = -1;
static gint ett_xnap_PrivateMessage = -1;
static gint ett_xnap_XnAP_PDU = -1;
static gint ett_xnap_InitiatingMessage = -1;
static gint ett_xnap_SuccessfulOutcome = -1;
static gint ett_xnap_UnsuccessfulOutcome = -1;

/*--- End of included file: packet-xnap-ett.c ---*/
#line 72 "./asn1/xnap/packet-xnap-template.c"

enum {
  XNAP_NG_RAN_CONTAINER_AUTOMATIC,
  XNAP_NG_RAN_CONTAINER_GNB,
  XNAP_NG_RAN_CONTAINER_NG_ENB
};

static const enum_val_t xnap_target_ng_ran_container_vals[] = {
  {"automatic", "automatic", XNAP_NG_RAN_CONTAINER_AUTOMATIC},
  {"gnb", "gNB", XNAP_NG_RAN_CONTAINER_GNB},
  {"ng-enb","ng-eNB", XNAP_NG_RAN_CONTAINER_NG_ENB},
  {NULL, NULL, -1}
};

/* Global variables */
static guint xnap_sctp_port = SCTP_PORT_XnAP;
static gint xnap_dissect_target_ng_ran_container_as = XNAP_NG_RAN_CONTAINER_AUTOMATIC;

/* Dissector tables */
static dissector_table_t xnap_ies_dissector_table;
static dissector_table_t xnap_extension_dissector_table;
static dissector_table_t xnap_proc_imsg_dissector_table;
static dissector_table_t xnap_proc_sout_dissector_table;
static dissector_table_t xnap_proc_uout_dissector_table;

void proto_register_xnap(void);
void proto_reg_handoff_xnap(void);
static int dissect_ProtocolIEFieldValue(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *);
static int dissect_ProtocolExtensionFieldExtensionValue(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *);
static int dissect_InitiatingMessageValue(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *);
static int dissect_SuccessfulOutcomeValue(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *);
static int dissect_UnsuccessfulOutcomeValue(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *);
static int dissect_XnAP_PDU_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_);

static dissector_handle_t xnap_handle;

static void
xnap_PacketLossRate_fmt(gchar *s, guint32 v)
{
  g_snprintf(s, ITEM_LABEL_LENGTH, "%.1f%% (%u)", (float)v/10, v);
}

static void
xnap_PacketDelayBudget_fmt(gchar *s, guint32 v)
{
  g_snprintf(s, ITEM_LABEL_LENGTH, "%.1fms (%u)", (float)v/2, v);
}

typedef enum {
  INITIATING_MESSAGE,
  SUCCESSFUL_OUTCOME,
  UNSUCCESSFUL_OUTCOME
} xnap_message_type;

struct xnap_conv_info {
  address addr_a;
  guint32 port_a;
  GlobalNG_RANNode_ID_enum ranmode_id_a;
  address addr_b;
  guint32 port_b;
  GlobalNG_RANNode_ID_enum ranmode_id_b;
};

struct xnap_private_data {
  struct xnap_conv_info *xnap_conv;
  xnap_message_type message_type;
  guint32 procedure_code;
  guint32 protocol_ie_id;
};

static struct xnap_private_data*
xnap_get_private_data(packet_info *pinfo)
{
  struct xnap_private_data *xnap_data = (struct xnap_private_data*)p_get_proto_data(pinfo->pool, pinfo, proto_xnap, 0);
  if (!xnap_data) {
    xnap_data = wmem_new0(pinfo->pool, struct xnap_private_data);
    p_add_proto_data(pinfo->pool, pinfo, proto_xnap, 0, xnap_data);
  }
  return xnap_data;
}

static GlobalNG_RANNode_ID_enum
xnap_get_ranmode_id(address *addr, guint32 port, packet_info *pinfo)
{
  struct xnap_private_data *xnap_data = xnap_get_private_data(pinfo);
  GlobalNG_RANNode_ID_enum ranmode_id = (GlobalNG_RANNode_ID_enum)-1;

  if (xnap_data->xnap_conv) {
    if (addresses_equal(addr, &xnap_data->xnap_conv->addr_a) && port == xnap_data->xnap_conv->port_a) {
      ranmode_id = xnap_data->xnap_conv->ranmode_id_a;
    } else if (addresses_equal(addr, &xnap_data->xnap_conv->addr_b) && port == xnap_data->xnap_conv->port_b) {
      ranmode_id = xnap_data->xnap_conv->ranmode_id_b;
    }
  }
  return ranmode_id;
}


/*--- Included file: packet-xnap-fn.c ---*/
#line 1 "./asn1/xnap/packet-xnap-fn.c"

static const value_string xnap_Criticality_vals[] = {
  {   0, "reject" },
  {   1, "ignore" },
  {   2, "notify" },
  { 0, NULL }
};


static int
dissect_xnap_Criticality(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     3, NULL, FALSE, 0, NULL);

  return offset;
}



static int
dissect_xnap_INTEGER_0_maxPrivateIEs(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, maxPrivateIEs, NULL, FALSE);

  return offset;
}



static int
dissect_xnap_OBJECT_IDENTIFIER(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_object_identifier(tvb, offset, actx, tree, hf_index, NULL);

  return offset;
}


static const value_string xnap_PrivateIE_ID_vals[] = {
  {   0, "local" },
  {   1, "global" },
  { 0, NULL }
};

static const per_choice_t PrivateIE_ID_choice[] = {
  {   0, &hf_xnap_local          , ASN1_NO_EXTENSIONS     , dissect_xnap_INTEGER_0_maxPrivateIEs },
  {   1, &hf_xnap_global         , ASN1_NO_EXTENSIONS     , dissect_xnap_OBJECT_IDENTIFIER },
  { 0, NULL, 0, NULL }
};

static int
dissect_xnap_PrivateIE_ID(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_xnap_PrivateIE_ID, PrivateIE_ID_choice,
                                 NULL);

  return offset;
}


static const value_string xnap_ProcedureCode_vals[] = {
  { id_handoverPreparation, "id-handoverPreparation" },
  { id_sNStatusTransfer, "id-sNStatusTransfer" },
  { id_handoverCancel, "id-handoverCancel" },
  { id_retrieveUEContext, "id-retrieveUEContext" },
  { id_rANPaging, "id-rANPaging" },
  { id_xnUAddressIndication, "id-xnUAddressIndication" },
  { id_uEContextRelease, "id-uEContextRelease" },
  { id_sNGRANnodeAdditionPreparation, "id-sNGRANnodeAdditionPreparation" },
  { id_sNGRANnodeReconfigurationCompletion, "id-sNGRANnodeReconfigurationCompletion" },
  { id_mNGRANnodeinitiatedSNGRANnodeModificationPreparation, "id-mNGRANnodeinitiatedSNGRANnodeModificationPreparation" },
  { id_sNGRANnodeinitiatedSNGRANnodeModificationPreparation, "id-sNGRANnodeinitiatedSNGRANnodeModificationPreparation" },
  { id_mNGRANnodeinitiatedSNGRANnodeRelease, "id-mNGRANnodeinitiatedSNGRANnodeRelease" },
  { id_sNGRANnodeinitiatedSNGRANnodeRelease, "id-sNGRANnodeinitiatedSNGRANnodeRelease" },
  { id_sNGRANnodeCounterCheck, "id-sNGRANnodeCounterCheck" },
  { id_sNGRANnodeChange, "id-sNGRANnodeChange" },
  { id_rRCTransfer, "id-rRCTransfer" },
  { id_xnRemoval, "id-xnRemoval" },
  { id_xnSetup, "id-xnSetup" },
  { id_nGRANnodeConfigurationUpdate, "id-nGRANnodeConfigurationUpdate" },
  { id_cellActivation, "id-cellActivation" },
  { id_reset, "id-reset" },
  { id_errorIndication, "id-errorIndication" },
  { id_privateMessage, "id-privateMessage" },
  { id_notificationControl, "id-notificationControl" },
  { id_activityNotification, "id-activityNotification" },
  { id_e_UTRA_NR_CellResourceCoordination, "id-e-UTRA-NR-CellResourceCoordination" },
  { id_secondaryRATDataUsageReport, "id-secondaryRATDataUsageReport" },
  { 0, NULL }
};

static value_string_ext xnap_ProcedureCode_vals_ext = VALUE_STRING_EXT_INIT(xnap_ProcedureCode_vals);


static int
dissect_xnap_ProcedureCode(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 66 "./asn1/xnap/xnap.cnf"
  struct xnap_private_data *xnap_data = xnap_get_private_data(actx->pinfo);
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 255U, &xnap_data->procedure_code, FALSE);




  return offset;
}


static const value_string xnap_ProtocolIE_ID_vals[] = {
  { id_ActivatedServedCells, "id-ActivatedServedCells" },
  { id_ActivationIDforCellActivation, "id-ActivationIDforCellActivation" },
  { id_admittedSplitSRB, "id-admittedSplitSRB" },
  { id_admittedSplitSRBrelease, "id-admittedSplitSRBrelease" },
  { id_AMF_Region_Information, "id-AMF-Region-Information" },
  { id_AssistanceDataForRANPaging, "id-AssistanceDataForRANPaging" },
  { id_BearersSubjectToCounterCheck, "id-BearersSubjectToCounterCheck" },
  { id_Cause, "id-Cause" },
  { id_cellAssistanceInfo_NR, "id-cellAssistanceInfo-NR" },
  { id_ConfigurationUpdateInitiatingNodeChoice, "id-ConfigurationUpdateInitiatingNodeChoice" },
  { id_CriticalityDiagnostics, "id-CriticalityDiagnostics" },
  { id_XnUAddressInfoperPDUSession_List, "id-XnUAddressInfoperPDUSession-List" },
  { id_DRBsSubjectToStatusTransfer_List, "id-DRBsSubjectToStatusTransfer-List" },
  { id_ExpectedUEBehaviour, "id-ExpectedUEBehaviour" },
  { id_GlobalNG_RAN_node_ID, "id-GlobalNG-RAN-node-ID" },
  { id_GUAMI, "id-GUAMI" },
  { id_indexToRatFrequSelectionPriority, "id-indexToRatFrequSelectionPriority" },
  { id_initiatingNodeType_ResourceCoordRequest, "id-initiatingNodeType-ResourceCoordRequest" },
  { id_List_of_served_cells_E_UTRA, "id-List-of-served-cells-E-UTRA" },
  { id_List_of_served_cells_NR, "id-List-of-served-cells-NR" },
  { id_LocationReportingInformation, "id-LocationReportingInformation" },
  { id_MAC_I, "id-MAC-I" },
  { id_MaskedIMEISV, "id-MaskedIMEISV" },
  { id_M_NG_RANnodeUEXnAPID, "id-M-NG-RANnodeUEXnAPID" },
  { id_MN_to_SN_Container, "id-MN-to-SN-Container" },
  { id_MobilityRestrictionList, "id-MobilityRestrictionList" },
  { id_new_NG_RAN_Cell_Identity, "id-new-NG-RAN-Cell-Identity" },
  { id_newNG_RANnodeUEXnAPID, "id-newNG-RANnodeUEXnAPID" },
  { id_UEReportRRCTransfer, "id-UEReportRRCTransfer" },
  { id_oldNG_RANnodeUEXnAPID, "id-oldNG-RANnodeUEXnAPID" },
  { id_OldtoNewNG_RANnodeResumeContainer, "id-OldtoNewNG-RANnodeResumeContainer" },
  { id_PagingDRX, "id-PagingDRX" },
  { id_PCellID, "id-PCellID" },
  { id_PDCPChangeIndication, "id-PDCPChangeIndication" },
  { id_PDUSessionAdmittedAddedAddReqAck, "id-PDUSessionAdmittedAddedAddReqAck" },
  { id_PDUSessionAdmittedModSNModConfirm, "id-PDUSessionAdmittedModSNModConfirm" },
  { id_PDUSessionAdmitted_SNModResponse, "id-PDUSessionAdmitted-SNModResponse" },
  { id_PDUSessionNotAdmittedAddReqAck, "id-PDUSessionNotAdmittedAddReqAck" },
  { id_PDUSessionNotAdmitted_SNModResponse, "id-PDUSessionNotAdmitted-SNModResponse" },
  { id_PDUSessionReleasedList_RelConf, "id-PDUSessionReleasedList-RelConf" },
  { id_PDUSessionReleasedSNModConfirm, "id-PDUSessionReleasedSNModConfirm" },
  { id_PDUSessionResourcesActivityNotifyList, "id-PDUSessionResourcesActivityNotifyList" },
  { id_PDUSessionResourcesAdmitted_List, "id-PDUSessionResourcesAdmitted-List" },
  { id_PDUSessionResourcesNotAdmitted_List, "id-PDUSessionResourcesNotAdmitted-List" },
  { id_PDUSessionResourcesNotifyList, "id-PDUSessionResourcesNotifyList" },
  { id_PDUSession_SNChangeConfirm_List, "id-PDUSession-SNChangeConfirm-List" },
  { id_PDUSession_SNChangeRequired_List, "id-PDUSession-SNChangeRequired-List" },
  { id_PDUSessionToBeAddedAddReq, "id-PDUSessionToBeAddedAddReq" },
  { id_PDUSessionToBeModifiedSNModRequired, "id-PDUSessionToBeModifiedSNModRequired" },
  { id_PDUSessionToBeReleasedList_RelRqd, "id-PDUSessionToBeReleasedList-RelRqd" },
  { id_PDUSessionToBeReleased_RelReq, "id-PDUSessionToBeReleased-RelReq" },
  { id_PDUSessionToBeReleasedSNModRequired, "id-PDUSessionToBeReleasedSNModRequired" },
  { id_RANPagingArea, "id-RANPagingArea" },
  { id_PagingPriority, "id-PagingPriority" },
  { id_requestedSplitSRB, "id-requestedSplitSRB" },
  { id_requestedSplitSRBrelease, "id-requestedSplitSRBrelease" },
  { id_ResetRequestTypeInfo, "id-ResetRequestTypeInfo" },
  { id_ResetResponseTypeInfo, "id-ResetResponseTypeInfo" },
  { id_RespondingNodeTypeConfigUpdateAck, "id-RespondingNodeTypeConfigUpdateAck" },
  { id_respondingNodeType_ResourceCoordResponse, "id-respondingNodeType-ResourceCoordResponse" },
  { id_ResponseInfo_ReconfCompl, "id-ResponseInfo-ReconfCompl" },
  { id_RRCConfigIndication, "id-RRCConfigIndication" },
  { id_RRCResumeCause, "id-RRCResumeCause" },
  { id_SCGConfigurationQuery, "id-SCGConfigurationQuery" },
  { id_selectedPLMN, "id-selectedPLMN" },
  { id_ServedCellsToActivate, "id-ServedCellsToActivate" },
  { id_servedCellsToUpdate_E_UTRA, "id-servedCellsToUpdate-E-UTRA" },
  { id_ServedCellsToUpdateInitiatingNodeChoice, "id-ServedCellsToUpdateInitiatingNodeChoice" },
  { id_servedCellsToUpdate_NR, "id-servedCellsToUpdate-NR" },
  { id_s_ng_RANnode_SecurityKey, "id-s-ng-RANnode-SecurityKey" },
  { id_S_NG_RANnodeUE_AMBR, "id-S-NG-RANnodeUE-AMBR" },
  { id_S_NG_RANnodeUEXnAPID, "id-S-NG-RANnodeUEXnAPID" },
  { id_SN_to_MN_Container, "id-SN-to-MN-Container" },
  { id_sourceNG_RANnodeUEXnAPID, "id-sourceNG-RANnodeUEXnAPID" },
  { id_SplitSRB_RRCTransfer, "id-SplitSRB-RRCTransfer" },
  { id_TAISupport_list, "id-TAISupport-list" },
  { id_TimeToWait, "id-TimeToWait" },
  { id_Target2SourceNG_RANnodeTranspContainer, "id-Target2SourceNG-RANnodeTranspContainer" },
  { id_targetCellGlobalID, "id-targetCellGlobalID" },
  { id_targetNG_RANnodeUEXnAPID, "id-targetNG-RANnodeUEXnAPID" },
  { id_target_S_NG_RANnodeID, "id-target-S-NG-RANnodeID" },
  { id_TraceActivation, "id-TraceActivation" },
  { id_UEContextID, "id-UEContextID" },
  { id_UEContextInfoHORequest, "id-UEContextInfoHORequest" },
  { id_UEContextInfoRetrUECtxtResp, "id-UEContextInfoRetrUECtxtResp" },
  { id_UEContextInfo_SNModRequest, "id-UEContextInfo-SNModRequest" },
  { id_UEContextKeptIndicator, "id-UEContextKeptIndicator" },
  { id_UEContextRefAtSN_HORequest, "id-UEContextRefAtSN-HORequest" },
  { id_UEHistoryInformation, "id-UEHistoryInformation" },
  { id_UEIdentityIndexValue, "id-UEIdentityIndexValue" },
  { id_UERANPagingIdentity, "id-UERANPagingIdentity" },
  { id_UESecurityCapabilities, "id-UESecurityCapabilities" },
  { id_UserPlaneTrafficActivityReport, "id-UserPlaneTrafficActivityReport" },
  { id_XnRemovalThreshold, "id-XnRemovalThreshold" },
  { id_DesiredActNotificationLevel, "id-DesiredActNotificationLevel" },
  { id_AvailableDRBIDs, "id-AvailableDRBIDs" },
  { id_AdditionalDRBIDs, "id-AdditionalDRBIDs" },
  { id_SpareDRBIDs, "id-SpareDRBIDs" },
  { id_RequiredNumberOfDRBIDs, "id-RequiredNumberOfDRBIDs" },
  { id_TNLA_To_Add_List, "id-TNLA-To-Add-List" },
  { id_TNLA_To_Update_List, "id-TNLA-To-Update-List" },
  { id_TNLA_To_Remove_List, "id-TNLA-To-Remove-List" },
  { id_TNLA_Setup_List, "id-TNLA-Setup-List" },
  { id_TNLA_Failed_To_Setup_List, "id-TNLA-Failed-To-Setup-List" },
  { id_PDUSessionToBeReleased_RelReqAck, "id-PDUSessionToBeReleased-RelReqAck" },
  { id_S_NG_RANnodeMaxIPDataRate_UL, "id-S-NG-RANnodeMaxIPDataRate-UL" },
  { id_Unknown_106, "id-Unknown-106" },
  { id_PDUSessionResourceSecondaryRATUsageList, "id-PDUSessionResourceSecondaryRATUsageList" },
  { id_Additional_UL_NG_U_TNLatUPF_List, "id-Additional-UL-NG-U-TNLatUPF-List" },
  { id_SecondarydataForwardingInfoFromTarget_List, "id-SecondarydataForwardingInfoFromTarget-List" },
  { id_LocationInformationSNReporting, "id-LocationInformationSNReporting" },
  { id_LocationInformationSN, "id-LocationInformationSN" },
  { id_LastE_UTRANPLMNIdentity, "id-LastE-UTRANPLMNIdentity" },
  { id_S_NG_RANnodeMaxIPDataRate_DL, "id-S-NG-RANnodeMaxIPDataRate-DL" },
  { id_MaxIPrate_DL, "id-MaxIPrate-DL" },
  { id_SecurityResult, "id-SecurityResult" },
  { id_S_NSSAI, "id-S-NSSAI" },
  { id_MR_DC_ResourceCoordinationInfo, "id-MR-DC-ResourceCoordinationInfo" },
  { id_AMF_Region_Information_To_Add, "id-AMF-Region-Information-To-Add" },
  { id_AMF_Region_Information_To_Delete, "id-AMF-Region-Information-To-Delete" },
  { id_OldQoSFlowMap_ULendmarkerexpected, "id-OldQoSFlowMap-ULendmarkerexpected" },
  { id_RANPagingFailure, "id-RANPagingFailure" },
  { id_UERadioCapabilityForPaging, "id-UERadioCapabilityForPaging" },
  { id_PDUSessionDataForwarding_SNModResponse, "id-PDUSessionDataForwarding-SNModResponse" },
  { id_DRBsNotAdmittedSetupModifyList, "id-DRBsNotAdmittedSetupModifyList" },
  { id_Secondary_MN_Xn_U_TNLInfoatM, "id-Secondary-MN-Xn-U-TNLInfoatM" },
  { id_NE_DC_TDM_Pattern, "id-NE-DC-TDM-Pattern" },
  { id_PDUSessionCommonNetworkInstance, "id-PDUSessionCommonNetworkInstance" },
  { id_BPLMN_ID_Info_EUTRA, "id-BPLMN-ID-Info-EUTRA" },
  { id_BPLMN_ID_Info_NR, "id-BPLMN-ID-Info-NR" },
  { id_InterfaceInstanceIndication, "id-InterfaceInstanceIndication" },
  { id_S_NG_RANnode_Addition_Trigger_Ind, "id-S-NG-RANnode-Addition-Trigger-Ind" },
  { id_DefaultDRB_Allowed, "id-DefaultDRB-Allowed" },
  { id_DRB_IDs_takenintouse, "id-DRB-IDs-takenintouse" },
  { id_SplitSessionIndicator, "id-SplitSessionIndicator" },
  { id_CNTypeRestrictionsForEquivalent, "id-CNTypeRestrictionsForEquivalent" },
  { id_CNTypeRestrictionsForServing, "id-CNTypeRestrictionsForServing" },
  { id_DRBs_transferred_to_MN, "id-DRBs-transferred-to-MN" },
  { id_ULForwardingProposal, "id-ULForwardingProposal" },
  { id_EndpointIPAddressAndPort, "id-EndpointIPAddressAndPort" },
  { id_Unknown_140, "id-Unknown-140" },
  { id_Unknown_141, "id-Unknown-141" },
  { id_Unknown_142, "id-Unknown-142" },
  { id_Unknown_143, "id-Unknown-143" },
  { id_Unknown_144, "id-Unknown-144" },
  { id_Unknown_145, "id-Unknown-145" },
  { id_Unknown_146, "id-Unknown-146" },
  { id_Unknown_147, "id-Unknown-147" },
  { id_Unknown_148, "id-Unknown-148" },
  { id_Unknown_149, "id-Unknown-149" },
  { id_Unknown_150, "id-Unknown-150" },
  { id_Unknown_151, "id-Unknown-151" },
  { id_Unknown_152, "id-Unknown-152" },
  { id_Unknown_153, "id-Unknown-153" },
  { id_Unknown_154, "id-Unknown-154" },
  { id_FiveGCMobilityRestrictionListContainer, "id-FiveGCMobilityRestrictionListContainer" },
  { 0, NULL }
};

static value_string_ext xnap_ProtocolIE_ID_vals_ext = VALUE_STRING_EXT_INIT(xnap_ProtocolIE_ID_vals);


static int
dissect_xnap_ProtocolIE_ID(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 53 "./asn1/xnap/xnap.cnf"
  struct xnap_private_data *xnap_data = xnap_get_private_data(actx->pinfo);
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, maxProtocolIEs, &xnap_data->protocol_ie_id, FALSE);



#line 56 "./asn1/xnap/xnap.cnf"
  if (tree) {
    proto_item_append_text(proto_item_get_parent_nth(actx->created_item, 2), ": %s", val_to_str_ext(xnap_data->protocol_ie_id, &xnap_ProtocolIE_ID_vals_ext, "unknown (%d)"));
  }

  return offset;
}


static const value_string xnap_TriggeringMessage_vals[] = {
  {   0, "initiating-message" },
  {   1, "successful-outcome" },
  {   2, "unsuccessful-outcome" },
  { 0, NULL }
};


static int
dissect_xnap_TriggeringMessage(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     3, NULL, FALSE, 0, NULL);

  return offset;
}



static int
dissect_xnap_ProtocolIE_Field_value(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_open_type_pdu_new(tvb, offset, actx, tree, hf_index, dissect_ProtocolIEFieldValue);

  return offset;
}


static const per_sequence_t ProtocolIE_Field_sequence[] = {
  { &hf_xnap_id             , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_xnap_ProtocolIE_ID },
  { &hf_xnap_criticality    , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_xnap_Criticality },
  { &hf_xnap_protocolIE_Field_value, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_xnap_ProtocolIE_Field_value },
  { NULL, 0, 0, NULL }
};

static int
dissect_xnap_ProtocolIE_Field(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_xnap_ProtocolIE_Field, ProtocolIE_Field_sequence);

  return offset;
}


static const per_sequence_t ProtocolIE_Container_sequence_of[1] = {
  { &hf_xnap_ProtocolIE_Container_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_xnap_ProtocolIE_Field },
};

static int
dissect_xnap_ProtocolIE_Container(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_xnap_ProtocolIE_Container, ProtocolIE_Container_sequence_of,
                                                  0, maxProtocolIEs, FALSE);

  return offset;
}



static int
dissect_xnap_ProtocolIE_Single_Container(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_xnap_ProtocolIE_Field(tvb, offset, actx, tree, hf_index);

  return offset;
}



static int
dissect_xnap_T_extensionValue(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_open_type_pdu_new(tvb, offset, actx, tree, hf_index, dissect_ProtocolExtensionFieldExtensionValue);

  return offset;
}


static const per_sequence_t ProtocolExtensionField_sequence[] = {
  { &hf_xnap_extension_id   , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_xnap_ProtocolIE_ID },
  { &hf_xnap_criticality    , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_xnap_Criticality },
  { &hf_xnap_extensionValue , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_xnap_T_extensionValue },
  { NULL, 0, 0, NULL }
};

static int
dissect_xnap_ProtocolExtensionField(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_xnap_ProtocolExtensionField, ProtocolExtensionField_sequence);

  return offset;
}


static const per_sequence_t ProtocolExtensionContainer_sequence_of[1] = {
  { &hf_xnap_ProtocolExtensionContainer_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_xnap_ProtocolExtensionField },
};

static int
dissect_xnap_ProtocolExtensionContainer(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_xnap_ProtocolExtensionContainer, ProtocolExtensionContainer_sequence_of,
                                                  1, maxProtocolExtensions, FALSE);

  return offset;
}



static int
dissect_xnap_PrivateIE_Field_value(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_open_type(tvb, offset, actx, tree, hf_index, NULL);

  return offset;
}


static const per_sequence_t PrivateIE_Field_sequence[] = {
  { &hf_xnap_private_id     , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_xnap_PrivateIE_ID },
  { &hf_xnap_criticality    , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_xnap_Criticality },
  { &hf_xnap_privateIE_Field_value, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_xnap_PrivateIE_Field_value },
  { NULL, 0, 0, NULL }
};

static int
dissect_xnap_PrivateIE_Field(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_xnap_PrivateIE_Field, PrivateIE_Field_sequence);

  return offset;
}


static const per_sequence_t PrivateIE_Container_sequence_of[1] = {
  { &hf_xnap_PrivateIE_Container_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_xnap_PrivateIE_Field },
};

static int
dissect_xnap_PrivateIE_Container(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_xnap_PrivateIE_Container, PrivateIE_Container_sequence_of,
                                                  1, maxPrivateIEs, FALSE);

  return offset;
}



static int
dissect_xnap_TransportLayerAddress(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 331 "./asn1/xnap/xnap.cnf"
  tvbuff_t *parameter_tvb = NULL;
  proto_tree *subtree;
  int len;

  offset = dissect_per_bit_string(tvb, offset, actx, tree, hf_index,
                                     1, 160, TRUE, NULL, 0, &parameter_tvb, &len);

  if (!parameter_tvb)
    return offset;

  subtree = proto_item_add_subtree(actx->created_item, ett_xnap_TransportLayerAddress);
  if (len == 32) {
    /* IPv4 */
     proto_tree_add_item(subtree, hf_xnap_transportLayerAddressIPv4, parameter_tvb, 0, 4, ENC_BIG_ENDIAN);
  } else if (len == 128) {
    /* IPv6 */
     proto_tree_add_item(subtree, hf_xnap_transportLayerAddressIPv6, parameter_tvb, 0, 16, ENC_NA);
  } else if (len == 160) {
    /* IPv4 */
     proto_tree_add_item(subtree, hf_xnap_transportLayerAddressIPv4, parameter_tvb, 0, 4, ENC_BIG_ENDIAN);
    /* IPv6 */
     proto_tree_add_item(subtree, hf_xnap_transportLayerAddressIPv6, parameter_tvb, 4, 16, ENC_NA);
  }



  return offset;
}



static int
dissect_xnap_GTP_TEID(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_octet_string(tvb, offset, actx, tree, hf_index,
                                       4, 4, FALSE, NULL);

  return offset;
}


static const per_sequence_t GTPtunnelTransportLayerInformation_sequence[] = {
  { &hf_xnap_tnl_address    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_xnap_TransportLayerAddress },
  { &hf_xnap_gtp_teid       , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_xnap_GTP_TEID },
  { &hf_xnap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_xnap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_xnap_GTPtunnelTransportLayerInformation(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_xnap_GTPtunnelTransportLayerInformation, GTPtunnelTransportLayerInformation_sequence);

  return offset;
}


static const value_string xnap_UPTransportLayerInformation_vals[] = {
  {   0, "gtpTunnel" },
  {   1, "choice-extension" },
  { 0, NULL }
};

static const per_choice_t UPTransportLayerInformation_choice[] = {
  {   0, &hf_xnap_gtpTunnel      , ASN1_NO_EXTENSIONS     , dissect_xnap_GTPtunnelTransportLayerInformation },
  {   1, &hf_xnap_choice_extension, ASN1_NO_EXTENSIONS     , dissect_xnap_ProtocolIE_Single_Container },
  { 0, NULL, 0, NULL }
};

static int
dissect_xnap_UPTransportLayerInformation(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_xnap_UPTransportLayerInformation, UPTransportLayerInformation_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t Additional_UL_NG_U_TNLatUPF_Item_sequence[] = {
  { &hf_xnap_additional_UL_NG_U_TNLatUPF, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_xnap_UPTransportLayerInformation },
  { &hf_xnap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_xnap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_xnap_Additional_UL_NG_U_TNLatUPF_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_xnap_Additional_UL_NG_U_TNLatUPF_Item, Additional_UL_NG_U_TNLatUPF_Item_sequence);

  return offset;
}


static const per_sequence_t Additional_UL_NG_U_TNLatUPF_List_sequence_of[1] = {
  { &hf_xnap_Additional_UL_NG_U_TNLatUPF_List_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_xnap_Additional_UL_NG_U_TNLatUPF_Item },
};

static int
dissect_xnap_Additional_UL_NG_U_TNLatUPF_List(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_xnap_Additional_UL_NG_U_TNLatUPF_List, Additional_UL_NG_U_TNLatUPF_List_sequence_of,
                                                  1, maxnoofMultiConnectivityMinusOne, FALSE);

  return offset;
}



static int
dissect_xnap_ActivationIDforCellActivation(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 255U, NULL, FALSE);

  return offset;
}



static int
dissect_xnap_INTEGER_0_15_(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 15U, NULL, TRUE);

  return offset;
}


static const value_string xnap_T_pre_emption_capability_vals[] = {
  {   0, "shall-not-trigger-preemptdatDion" },
  {   1, "may-trigger-preemption" },
  { 0, NULL }
};


static int
dissect_xnap_T_pre_emption_capability(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     2, NULL, TRUE, 0, NULL);

  return offset;
}


static const value_string xnap_T_pre_emption_vulnerability_vals[] = {
  {   0, "not-preemptable" },
  {   1, "preemptable" },
  { 0, NULL }
};


static int
dissect_xnap_T_pre_emption_vulnerability(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     2, NULL, TRUE, 0, NULL);

  return offset;
}


static const per_sequence_t AllocationandRetentionPriority_sequence[] = {
  { &hf_xnap_priorityLevel  , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_xnap_INTEGER_0_15_ },
  { &hf_xnap_pre_emption_capability, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_xnap_T_pre_emption_capability },
  { &hf_xnap_pre_emption_vulnerability, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_xnap_T_pre_emption_vulnerability },
  { &hf_xnap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_xnap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_xnap_AllocationandRetentionPriority(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_xnap_AllocationandRetentionPriority, AllocationandRetentionPriority_sequence);

  return offset;
}



static int
dissect_xnap_ActivationSFN(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 1023U, NULL, FALSE);

  return offset;
}



static int
dissect_xnap_PLMN_Identity(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 244 "./asn1/xnap/xnap.cnf"
  tvbuff_t *parameter_tvb = NULL;
  proto_tree *subtree;
  offset = dissect_per_octet_string(tvb, offset, actx, tree, hf_index,
                                       3, 3, FALSE, &parameter_tvb);

  if (!parameter_tvb)
    return offset;

  subtree = proto_item_add_subtree(actx->created_item, ett_xnap_PLMN_Identity);
  dissect_e212_mcc_mnc(parameter_tvb, actx->pinfo, subtree, 0, E212_NONE, FALSE);



  return offset;
}



static int
dissect_xnap_BIT_STRING_SIZE_8(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_bit_string(tvb, offset, actx, tree, hf_index,
                                     8, 8, FALSE, NULL, 0, NULL, NULL);

  return offset;
}


static const per_sequence_t GlobalAMF_Region_Information_sequence[] = {
  { &hf_xnap_plmn_ID        , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_xnap_PLMN_Identity },
  { &hf_xnap_amf_region_id  , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_xnap_BIT_STRING_SIZE_8 },
  { &hf_xnap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_xnap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_xnap_GlobalAMF_Region_Information(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_xnap_GlobalAMF_Region_Information, GlobalAMF_Region_Information_sequence);

  return offset;
}


static const per_sequence_t AMF_Region_Information_sequence_of[1] = {
  { &hf_xnap_AMF_Region_Information_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_xnap_GlobalAMF_Region_Information },
};

static int
dissect_xnap_AMF_Region_Information(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_xnap_AMF_Region_Information, AMF_Region_Information_sequence_of,
                                                  1, maxnoofAMFRegions, FALSE);

  return offset;
}



static int
dissect_xnap_AMF_UE_NGAP_ID(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer_64b(tvb, offset, actx, tree, hf_index,
                                                            0U, G_GUINT64_CONSTANT(1099511627775), NULL, FALSE);

  return offset;
}



static int
dissect_xnap_TAC(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 265 "./asn1/xnap/xnap.cnf"
  tvbuff_t *parameter_tvb = NULL;
  offset = dissect_per_octet_string(tvb, offset, actx, tree, -1,
                                       3, 3, FALSE, &parameter_tvb);

  if (parameter_tvb) {
    actx->created_item = proto_tree_add_item(tree, hf_index, parameter_tvb, 0, 3, ENC_BIG_ENDIAN);
  }



  return offset;
}


static const per_sequence_t TAIsinAoI_Item_sequence[] = {
  { &hf_xnap_pLMN_Identity  , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_xnap_PLMN_Identity },
  { &hf_xnap_tAC            , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_xnap_TAC },
  { &hf_xnap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_xnap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_xnap_TAIsinAoI_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_xnap_TAIsinAoI_Item, TAIsinAoI_Item_sequence);

  return offset;
}


static const per_sequence_t ListOfTAIsinAoI_sequence_of[1] = {
  { &hf_xnap_ListOfTAIsinAoI_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_xnap_TAIsinAoI_Item },
};

static int
dissect_xnap_ListOfTAIsinAoI(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_xnap_ListOfTAIsinAoI, ListOfTAIsinAoI_sequence_of,
                                                  1, maxnoofTAIsinAoI, FALSE);

  return offset;
}



static int
dissect_xnap_NR_Cell_Identity(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 278 "./asn1/xnap/xnap.cnf"
  tvbuff_t *cell_id_tvb = NULL;
  offset = dissect_per_bit_string(tvb, offset, actx, tree, -1,
                                     36, 36, FALSE, NULL, 0, &cell_id_tvb, NULL);

  if (cell_id_tvb) {
    guint64 cell_id = tvb_get_bits64(cell_id_tvb, 0, 36, ENC_BIG_ENDIAN);
    actx->created_item = proto_tree_add_uint64(tree, hf_index, cell_id_tvb, 0, 5, cell_id);
  }



  return offset;
}



static int
dissect_xnap_E_UTRA_Cell_Identity(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 292 "./asn1/xnap/xnap.cnf"
  tvbuff_t *cell_id_tvb = NULL;
  offset = dissect_per_bit_string(tvb, offset, actx, tree, -1,
                                     28, 28, FALSE, NULL, 0, &cell_id_tvb, NULL);

  if (cell_id_tvb) {
    guint32 cell_id = tvb_get_bits32(cell_id_tvb, 0, 28, ENC_BIG_ENDIAN);
    actx->created_item = proto_tree_add_uint(tree, hf_index, cell_id_tvb, 0, 4, cell_id);
  }



  return offset;
}


static const value_string xnap_NG_RAN_Cell_Identity_vals[] = {
  {   0, "nr" },
  {   1, "e-utra" },
  {   2, "choice-extension" },
  { 0, NULL }
};

static const per_choice_t NG_RAN_Cell_Identity_choice[] = {
  {   0, &hf_xnap_nr             , ASN1_NO_EXTENSIONS     , dissect_xnap_NR_Cell_Identity },
  {   1, &hf_xnap_e_utra         , ASN1_NO_EXTENSIONS     , dissect_xnap_E_UTRA_Cell_Identity },
  {   2, &hf_xnap_choice_extension, ASN1_NO_EXTENSIONS     , dissect_xnap_ProtocolIE_Single_Container },
  { 0, NULL, 0, NULL }
};

static int
dissect_xnap_NG_RAN_Cell_Identity(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_xnap_NG_RAN_Cell_Identity, NG_RAN_Cell_Identity_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t CellsinAoI_Item_sequence[] = {
  { &hf_xnap_pLMN_Identity  , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_xnap_PLMN_Identity },
  { &hf_xnap_ng_ran_cell_id , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_xnap_NG_RAN_Cell_Identity },
  { &hf_xnap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_xnap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_xnap_CellsinAoI_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_xnap_CellsinAoI_Item, CellsinAoI_Item_sequence);

  return offset;
}


static const per_sequence_t ListOfCells_sequence_of[1] = {
  { &hf_xnap_ListOfCells_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_xnap_CellsinAoI_Item },
};

static int
dissect_xnap_ListOfCells(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_xnap_ListOfCells, ListOfCells_sequence_of,
                                                  1, maxnoofCellsinAoI, FALSE);

  return offset;
}



static int
dissect_xnap_BIT_STRING_SIZE_22_32(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_bit_string(tvb, offset, actx, tree, hf_index,
                                     22, 32, FALSE, NULL, 0, NULL, NULL);

  return offset;
}


static const value_string xnap_GNB_ID_Choice_vals[] = {
  {   0, "gnb-ID" },
  {   1, "choice-extension" },
  { 0, NULL }
};

static const per_choice_t GNB_ID_Choice_choice[] = {
  {   0, &hf_xnap_gnb_ID         , ASN1_NO_EXTENSIONS     , dissect_xnap_BIT_STRING_SIZE_22_32 },
  {   1, &hf_xnap_choice_extension, ASN1_NO_EXTENSIONS     , dissect_xnap_ProtocolIE_Single_Container },
  { 0, NULL, 0, NULL }
};

static int
dissect_xnap_GNB_ID_Choice(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_xnap_GNB_ID_Choice, GNB_ID_Choice_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t GlobalgNB_ID_sequence[] = {
  { &hf_xnap_plmn_id        , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_xnap_PLMN_Identity },
  { &hf_xnap_gnb_id         , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_xnap_GNB_ID_Choice },
  { &hf_xnap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_xnap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_xnap_GlobalgNB_ID(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_xnap_GlobalgNB_ID, GlobalgNB_ID_sequence);

  return offset;
}



static int
dissect_xnap_BIT_STRING_SIZE_20(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_bit_string(tvb, offset, actx, tree, hf_index,
                                     20, 20, FALSE, NULL, 0, NULL, NULL);

  return offset;
}



static int
dissect_xnap_BIT_STRING_SIZE_18(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_bit_string(tvb, offset, actx, tree, hf_index,
                                     18, 18, FALSE, NULL, 0, NULL, NULL);

  return offset;
}



static int
dissect_xnap_BIT_STRING_SIZE_21(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_bit_string(tvb, offset, actx, tree, hf_index,
                                     21, 21, FALSE, NULL, 0, NULL, NULL);

  return offset;
}


static const value_string xnap_ENB_ID_Choice_vals[] = {
  {   0, "enb-ID-macro" },
  {   1, "enb-ID-shortmacro" },
  {   2, "enb-ID-longmacro" },
  {   3, "choice-extension" },
  { 0, NULL }
};

static const per_choice_t ENB_ID_Choice_choice[] = {
  {   0, &hf_xnap_enb_ID_macro   , ASN1_NO_EXTENSIONS     , dissect_xnap_BIT_STRING_SIZE_20 },
  {   1, &hf_xnap_enb_ID_shortmacro, ASN1_NO_EXTENSIONS     , dissect_xnap_BIT_STRING_SIZE_18 },
  {   2, &hf_xnap_enb_ID_longmacro, ASN1_NO_EXTENSIONS     , dissect_xnap_BIT_STRING_SIZE_21 },
  {   3, &hf_xnap_choice_extension, ASN1_NO_EXTENSIONS     , dissect_xnap_ProtocolIE_Single_Container },
  { 0, NULL, 0, NULL }
};

static int
dissect_xnap_ENB_ID_Choice(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_xnap_ENB_ID_Choice, ENB_ID_Choice_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t GlobalngeNB_ID_sequence[] = {
  { &hf_xnap_plmn_id        , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_xnap_PLMN_Identity },
  { &hf_xnap_enb_id         , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_xnap_ENB_ID_Choice },
  { &hf_xnap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_xnap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_xnap_GlobalngeNB_ID(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_xnap_GlobalngeNB_ID, GlobalngeNB_ID_sequence);

  return offset;
}


static const value_string xnap_GlobalNG_RANNode_ID_vals[] = {
  { GlobalNG_RANNode_ID_gNB, "gNB" },
  { GlobalNG_RANNode_ID_ng_eNB, "ng-eNB" },
  { GlobalNG_RANNode_ID_choice_extension, "choice-extension" },
  { 0, NULL }
};

static const per_choice_t GlobalNG_RANNode_ID_choice[] = {
  { GlobalNG_RANNode_ID_gNB, &hf_xnap_gNB            , ASN1_NO_EXTENSIONS     , dissect_xnap_GlobalgNB_ID },
  { GlobalNG_RANNode_ID_ng_eNB, &hf_xnap_ng_eNB         , ASN1_NO_EXTENSIONS     , dissect_xnap_GlobalngeNB_ID },
  { GlobalNG_RANNode_ID_choice_extension, &hf_xnap_choice_extension, ASN1_NO_EXTENSIONS     , dissect_xnap_ProtocolIE_Single_Container },
  { 0, NULL, 0, NULL }
};

static int
dissect_xnap_GlobalNG_RANNode_ID(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 89 "./asn1/xnap/xnap.cnf"
  gint value;
  struct xnap_private_data *xnap_data = xnap_get_private_data(actx->pinfo);

  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_xnap_GlobalNG_RANNode_ID, GlobalNG_RANNode_ID_choice,
                                 &value);

  if (xnap_data->xnap_conv && xnap_data->procedure_code == id_xnSetup) {
    if (addresses_equal(&actx->pinfo->src, &xnap_data->xnap_conv->addr_a) &&
        actx->pinfo->srcport == xnap_data->xnap_conv->port_a) {
      xnap_data->xnap_conv->ranmode_id_a = (GlobalNG_RANNode_ID_enum)value;
    } else if (addresses_equal(&actx->pinfo->src, &xnap_data->xnap_conv->addr_b) &&
               actx->pinfo->srcport == xnap_data->xnap_conv->port_b) {
      xnap_data->xnap_conv->ranmode_id_b = (GlobalNG_RANNode_ID_enum)value;
    }
  }



  return offset;
}


static const per_sequence_t GlobalNG_RANNodesinAoI_Item_sequence[] = {
  { &hf_xnap_global_NG_RAN_Node_ID, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_xnap_GlobalNG_RANNode_ID },
  { &hf_xnap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_xnap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_xnap_GlobalNG_RANNodesinAoI_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_xnap_GlobalNG_RANNodesinAoI_Item, GlobalNG_RANNodesinAoI_Item_sequence);

  return offset;
}


static const per_sequence_t ListOfRANNodesinAoI_sequence_of[1] = {
  { &hf_xnap_ListOfRANNodesinAoI_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_xnap_GlobalNG_RANNodesinAoI_Item },
};

static int
dissect_xnap_ListOfRANNodesinAoI(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_xnap_ListOfRANNodesinAoI, ListOfRANNodesinAoI_sequence_of,
                                                  1, maxnoofRANNodesinAoI, FALSE);

  return offset;
}



static int
dissect_xnap_RequestReferenceID(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            1U, 64U, NULL, TRUE);

  return offset;
}


static const per_sequence_t AreaOfInterest_Item_sequence[] = {
  { &hf_xnap_listOfTAIsinAoI, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_xnap_ListOfTAIsinAoI },
  { &hf_xnap_listOfCellsinAoI, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_xnap_ListOfCells },
  { &hf_xnap_listOfRANNodesinAoI, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_xnap_ListOfRANNodesinAoI },
  { &hf_xnap_requestReferenceID, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_xnap_RequestReferenceID },
  { &hf_xnap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_xnap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_xnap_AreaOfInterest_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_xnap_AreaOfInterest_Item, AreaOfInterest_Item_sequence);

  return offset;
}


static const per_sequence_t AreaOfInterestInformation_sequence_of[1] = {
  { &hf_xnap_AreaOfInterestInformation_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_xnap_AreaOfInterest_Item },
};

static int
dissect_xnap_AreaOfInterestInformation(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_xnap_AreaOfInterestInformation, AreaOfInterestInformation_sequence_of,
                                                  1, maxnoofAoIs, FALSE);

  return offset;
}



static int
dissect_xnap_BIT_STRING_SIZE_256(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_bit_string(tvb, offset, actx, tree, hf_index,
                                     256, 256, FALSE, NULL, 0, NULL, NULL);

  return offset;
}



static int
dissect_xnap_INTEGER_0_7(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 7U, NULL, FALSE);

  return offset;
}


static const per_sequence_t AS_SecurityInformation_sequence[] = {
  { &hf_xnap_key_NG_RAN_Star, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_xnap_BIT_STRING_SIZE_256 },
  { &hf_xnap_ncc            , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_xnap_INTEGER_0_7 },
  { &hf_xnap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_xnap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_xnap_AS_SecurityInformation(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_xnap_AS_SecurityInformation, AS_SecurityInformation_sequence);

  return offset;
}



static int
dissect_xnap_INTEGER_1_16_(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            1U, 16U, NULL, TRUE);

  return offset;
}


static const value_string xnap_T_nextPagingAreaScope_vals[] = {
  {   0, "same" },
  {   1, "changed" },
  { 0, NULL }
};


static int
dissect_xnap_T_nextPagingAreaScope(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     2, NULL, TRUE, 0, NULL);

  return offset;
}


static const per_sequence_t RANPagingAttemptInfo_sequence[] = {
  { &hf_xnap_pagingAttemptCount, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_xnap_INTEGER_1_16_ },
  { &hf_xnap_intendedNumberOfPagingAttempts, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_xnap_INTEGER_1_16_ },
  { &hf_xnap_nextPagingAreaScope, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_xnap_T_nextPagingAreaScope },
  { &hf_xnap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_xnap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_xnap_RANPagingAttemptInfo(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_xnap_RANPagingAttemptInfo, RANPagingAttemptInfo_sequence);

  return offset;
}


static const per_sequence_t AssistanceDataForRANPaging_sequence[] = {
  { &hf_xnap_ran_paging_attempt_info, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_xnap_RANPagingAttemptInfo },
  { &hf_xnap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_xnap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_xnap_AssistanceDataForRANPaging(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_xnap_AssistanceDataForRANPaging, AssistanceDataForRANPaging_sequence);

  return offset;
}



static int
dissect_xnap_AveragingWindow(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 4095U, NULL, TRUE);

  return offset;
}


static const per_sequence_t BroadcastEUTRAPLMNs_sequence_of[1] = {
  { &hf_xnap_BroadcastEUTRAPLMNs_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_xnap_PLMN_Identity },
};

static int
dissect_xnap_BroadcastEUTRAPLMNs(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_xnap_BroadcastEUTRAPLMNs, BroadcastEUTRAPLMNs_sequence_of,
                                                  1, maxnoofEUTRABPLMNs, FALSE);

  return offset;
}



static int
dissect_xnap_RANAC(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 255U, NULL, FALSE);

  return offset;
}


static const per_sequence_t BPLMN_ID_Info_EUTRA_Item_sequence[] = {
  { &hf_xnap_broadcastPLMNs , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_xnap_BroadcastEUTRAPLMNs },
  { &hf_xnap_tac            , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_xnap_TAC },
  { &hf_xnap_e_utraCI       , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_xnap_E_UTRA_Cell_Identity },
  { &hf_xnap_ranac          , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_xnap_RANAC },
  { &hf_xnap_iE_Extension   , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_xnap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_xnap_BPLMN_ID_Info_EUTRA_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_xnap_BPLMN_ID_Info_EUTRA_Item, BPLMN_ID_Info_EUTRA_Item_sequence);

  return offset;
}


static const per_sequence_t BPLMN_ID_Info_EUTRA_sequence_of[1] = {
  { &hf_xnap_BPLMN_ID_Info_EUTRA_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_xnap_BPLMN_ID_Info_EUTRA_Item },
};

static int
dissect_xnap_BPLMN_ID_Info_EUTRA(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_xnap_BPLMN_ID_Info_EUTRA, BPLMN_ID_Info_EUTRA_sequence_of,
                                                  1, maxnoofEUTRABPLMNs, FALSE);

  return offset;
}


static const per_sequence_t BroadcastPLMNs_sequence_of[1] = {
  { &hf_xnap_BroadcastPLMNs_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_xnap_PLMN_Identity },
};

static int
dissect_xnap_BroadcastPLMNs(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_xnap_BroadcastPLMNs, BroadcastPLMNs_sequence_of,
                                                  1, maxnoofBPLMNs, FALSE);

  return offset;
}


static const per_sequence_t BPLMN_ID_Info_NR_Item_sequence[] = {
  { &hf_xnap_broadcastPLMNs_01, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_xnap_BroadcastPLMNs },
  { &hf_xnap_tac            , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_xnap_TAC },
  { &hf_xnap_nr_CI          , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_xnap_NR_Cell_Identity },
  { &hf_xnap_ranac          , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_xnap_RANAC },
  { &hf_xnap_iE_Extension   , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_xnap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_xnap_BPLMN_ID_Info_NR_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_xnap_BPLMN_ID_Info_NR_Item, BPLMN_ID_Info_NR_Item_sequence);

  return offset;
}


static const per_sequence_t BPLMN_ID_Info_NR_sequence_of[1] = {
  { &hf_xnap_BPLMN_ID_Info_NR_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_xnap_BPLMN_ID_Info_NR_Item },
};

static int
dissect_xnap_BPLMN_ID_Info_NR(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_xnap_BPLMN_ID_Info_NR, BPLMN_ID_Info_NR_sequence_of,
                                                  1, maxnoofBPLMNs, FALSE);

  return offset;
}



static int
dissect_xnap_BitRate(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer_64b(tvb, offset, actx, tree, hf_index,
                                                            0U, G_GUINT64_CONSTANT(4000000000000), NULL, TRUE);

  return offset;
}



static int
dissect_xnap_OCTET_STRING_SIZE_1(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_octet_string(tvb, offset, actx, tree, hf_index,
                                       1, 1, FALSE, NULL);

  return offset;
}



static int
dissect_xnap_OCTET_STRING_SIZE_3(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_octet_string(tvb, offset, actx, tree, hf_index,
                                       3, 3, FALSE, NULL);

  return offset;
}


static const per_sequence_t S_NSSAI_sequence[] = {
  { &hf_xnap_sst            , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_xnap_OCTET_STRING_SIZE_1 },
  { &hf_xnap_sd             , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_xnap_OCTET_STRING_SIZE_3 },
  { &hf_xnap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_xnap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_xnap_S_NSSAI(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_xnap_S_NSSAI, S_NSSAI_sequence);

  return offset;
}


static const per_sequence_t SliceSupport_List_sequence_of[1] = {
  { &hf_xnap_SliceSupport_List_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_xnap_S_NSSAI },
};

static int
dissect_xnap_SliceSupport_List(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_xnap_SliceSupport_List, SliceSupport_List_sequence_of,
                                                  1, maxnoofSliceItems, FALSE);

  return offset;
}


static const per_sequence_t BroadcastPLMNinTAISupport_Item_sequence[] = {
  { &hf_xnap_plmn_id        , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_xnap_PLMN_Identity },
  { &hf_xnap_tAISliceSupport_List, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_xnap_SliceSupport_List },
  { &hf_xnap_iE_Extension   , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_xnap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_xnap_BroadcastPLMNinTAISupport_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_xnap_BroadcastPLMNinTAISupport_Item, BroadcastPLMNinTAISupport_Item_sequence);

  return offset;
}


static const value_string xnap_CauseRadioNetworkLayer_vals[] = {
  {   0, "cell-not-available" },
  {   1, "handover-desirable-for-radio-reasons" },
  {   2, "handover-target-not-allowed" },
  {   3, "invalid-AMF-Set-ID" },
  {   4, "no-radio-resources-available-in-target-cell" },
  {   5, "partial-handover" },
  {   6, "reduce-load-in-serving-cell" },
  {   7, "resource-optimisation-handover" },
  {   8, "time-critical-handover" },
  {   9, "tXnRELOCoverall-expiry" },
  {  10, "tTXnRELOCprep-expiry" },
  {  11, "unknown-GUAMI-ID" },
  {  12, "unknown-local-NG-RAN-node-UE-XnAP-ID" },
  {  13, "inconsistent-remote-NG-RAN-node-UE-XnAP-ID" },
  {  14, "encryption-and-or-integrity-protection-algorithms-not-supported" },
  {  15, "protection-algorithms-not-supported" },
  {  16, "multiple-PDU-session-ID-instances" },
  {  17, "unknown-PDU-session-ID" },
  {  18, "unknown-QoS-Flow-ID" },
  {  19, "multiple-QoS-Flow-ID-instances" },
  {  20, "switch-off-ongoing" },
  {  21, "not-supported-5QI-value" },
  {  22, "tXnDCoverall-expiry" },
  {  23, "tXnDCprep-expiry" },
  {  24, "action-desirable-for-radio-reasons" },
  {  25, "reduce-load" },
  {  26, "resource-optimisation" },
  {  27, "time-critical-action" },
  {  28, "target-not-allowed" },
  {  29, "no-radio-resources-available" },
  {  30, "invalid-QoS-combination" },
  {  31, "encryption-algorithms-not-supported" },
  {  32, "procedure-cancelled" },
  {  33, "rRM-purpose" },
  {  34, "improve-user-bit-rate" },
  {  35, "user-inactivity" },
  {  36, "radio-connection-with-UE-lost" },
  {  37, "failure-in-the-radio-interface-procedure" },
  {  38, "bearer-option-not-supported" },
  {  39, "up-integrity-protection-not-possible" },
  {  40, "up-confidentiality-protection-not-possible" },
  {  41, "resources-not-available-for-the-slice-s" },
  {  42, "ue-max-IP-data-rate-reason" },
  {  43, "cP-integrity-protection-failure" },
  {  44, "uP-integrity-protection-failure" },
  {  45, "slice-not-supported-by-NG-RAN" },
  {  46, "mN-Mobility" },
  {  47, "sN-Mobility" },
  {  48, "count-reaches-max-value" },
  {  49, "unknown-old-en-gNB-UE-X2AP-ID" },
  {  50, "pDCP-Overload" },
  {  51, "drb-id-not-available" },
  {  52, "unspecified" },
  {  53, "ue-context-id-not-known" },
  {  54, "non-relocation-of-context" },
  { 0, NULL }
};

static value_string_ext xnap_CauseRadioNetworkLayer_vals_ext = VALUE_STRING_EXT_INIT(xnap_CauseRadioNetworkLayer_vals);


static int
dissect_xnap_CauseRadioNetworkLayer(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     53, NULL, TRUE, 2, NULL);

  return offset;
}


static const value_string xnap_CauseTransportLayer_vals[] = {
  {   0, "transport-resource-unavailable" },
  {   1, "unspecified" },
  { 0, NULL }
};


static int
dissect_xnap_CauseTransportLayer(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     2, NULL, TRUE, 0, NULL);

  return offset;
}


static const value_string xnap_CauseProtocol_vals[] = {
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
dissect_xnap_CauseProtocol(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     7, NULL, TRUE, 0, NULL);

  return offset;
}


static const value_string xnap_CauseMisc_vals[] = {
  {   0, "control-processing-overload" },
  {   1, "hardware-failure" },
  {   2, "o-and-M-intervention" },
  {   3, "not-enough-user-plane-processing-resources" },
  {   4, "unspecified" },
  { 0, NULL }
};


static int
dissect_xnap_CauseMisc(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     5, NULL, TRUE, 0, NULL);

  return offset;
}


static const value_string xnap_Cause_vals[] = {
  {   0, "radioNetwork" },
  {   1, "transport" },
  {   2, "protocol" },
  {   3, "misc" },
  {   4, "choice-extension" },
  { 0, NULL }
};

static const per_choice_t Cause_choice[] = {
  {   0, &hf_xnap_radioNetwork   , ASN1_NO_EXTENSIONS     , dissect_xnap_CauseRadioNetworkLayer },
  {   1, &hf_xnap_transport      , ASN1_NO_EXTENSIONS     , dissect_xnap_CauseTransportLayer },
  {   2, &hf_xnap_protocol       , ASN1_NO_EXTENSIONS     , dissect_xnap_CauseProtocol },
  {   3, &hf_xnap_misc           , ASN1_NO_EXTENSIONS     , dissect_xnap_CauseMisc },
  {   4, &hf_xnap_choice_extension, ASN1_NO_EXTENSIONS     , dissect_xnap_ProtocolIE_Single_Container },
  { 0, NULL, 0, NULL }
};

static int
dissect_xnap_Cause(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_xnap_Cause, Cause_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t NR_CGI_sequence[] = {
  { &hf_xnap_plmn_id        , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_xnap_PLMN_Identity },
  { &hf_xnap_nr_CI_01       , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_xnap_NR_Cell_Identity },
  { &hf_xnap_iE_Extension   , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_xnap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_xnap_NR_CGI(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_xnap_NR_CGI, NR_CGI_sequence);

  return offset;
}


static const per_sequence_t SEQUENCE_SIZE_1_maxnoofCellsinNG_RANnode_OF_NR_CGI_sequence_of[1] = {
  { &hf_xnap_limitedNR_List_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_xnap_NR_CGI },
};

static int
dissect_xnap_SEQUENCE_SIZE_1_maxnoofCellsinNG_RANnode_OF_NR_CGI(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_xnap_SEQUENCE_SIZE_1_maxnoofCellsinNG_RANnode_OF_NR_CGI, SEQUENCE_SIZE_1_maxnoofCellsinNG_RANnode_OF_NR_CGI_sequence_of,
                                                  1, maxnoofCellsinNG_RANnode, FALSE);

  return offset;
}


static const value_string xnap_T_full_List_vals[] = {
  {   0, "all-served-cells-NR" },
  { 0, NULL }
};


static int
dissect_xnap_T_full_List(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     1, NULL, TRUE, 0, NULL);

  return offset;
}


static const value_string xnap_CellAssistanceInfo_NR_vals[] = {
  {   0, "limitedNR-List" },
  {   1, "full-List" },
  {   2, "choice-extension" },
  { 0, NULL }
};

static const per_choice_t CellAssistanceInfo_NR_choice[] = {
  {   0, &hf_xnap_limitedNR_List , ASN1_NO_EXTENSIONS     , dissect_xnap_SEQUENCE_SIZE_1_maxnoofCellsinNG_RANnode_OF_NR_CGI },
  {   1, &hf_xnap_full_List      , ASN1_NO_EXTENSIONS     , dissect_xnap_T_full_List },
  {   2, &hf_xnap_choice_extension, ASN1_NO_EXTENSIONS     , dissect_xnap_ProtocolIE_Single_Container },
  { 0, NULL, 0, NULL }
};

static int
dissect_xnap_CellAssistanceInfo_NR(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_xnap_CellAssistanceInfo_NR, CellAssistanceInfo_NR_choice,
                                 NULL);

  return offset;
}



static int
dissect_xnap_CellGroupID(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, maxnoofSCellGroups, NULL, FALSE);

  return offset;
}


static const value_string xnap_T_eNDC_Support_vals[] = {
  {   0, "supported" },
  {   1, "not-supported" },
  { 0, NULL }
};


static int
dissect_xnap_T_eNDC_Support(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     2, NULL, TRUE, 0, NULL);

  return offset;
}


static const per_sequence_t Connectivity_Support_sequence[] = {
  { &hf_xnap_eNDC_Support   , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_xnap_T_eNDC_Support },
  { &hf_xnap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_xnap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_xnap_Connectivity_Support(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_xnap_Connectivity_Support, Connectivity_Support_sequence);

  return offset;
}



static int
dissect_xnap_INTEGER_0_4095(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 4095U, NULL, FALSE);

  return offset;
}



static int
dissect_xnap_INTEGER_0_1048575(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 1048575U, NULL, FALSE);

  return offset;
}


static const per_sequence_t COUNT_PDCP_SN12_sequence[] = {
  { &hf_xnap_pdcp_SN12      , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_xnap_INTEGER_0_4095 },
  { &hf_xnap_hfn_PDCP_SN12  , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_xnap_INTEGER_0_1048575 },
  { &hf_xnap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_xnap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_xnap_COUNT_PDCP_SN12(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_xnap_COUNT_PDCP_SN12, COUNT_PDCP_SN12_sequence);

  return offset;
}



static int
dissect_xnap_INTEGER_0_262143(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 262143U, NULL, FALSE);

  return offset;
}



static int
dissect_xnap_INTEGER_0_16383(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 16383U, NULL, FALSE);

  return offset;
}


static const per_sequence_t COUNT_PDCP_SN18_sequence[] = {
  { &hf_xnap_pdcp_SN18      , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_xnap_INTEGER_0_262143 },
  { &hf_xnap_hfn_PDCP_SN18  , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_xnap_INTEGER_0_16383 },
  { &hf_xnap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_xnap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_xnap_COUNT_PDCP_SN18(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_xnap_COUNT_PDCP_SN18, COUNT_PDCP_SN18_sequence);

  return offset;
}


static const value_string xnap_CPTransportLayerInformation_vals[] = {
  {   0, "endpointIPAddress" },
  {   1, "choice-extension" },
  { 0, NULL }
};

static const per_choice_t CPTransportLayerInformation_choice[] = {
  {   0, &hf_xnap_endpointIPAddress, ASN1_NO_EXTENSIONS     , dissect_xnap_TransportLayerAddress },
  {   1, &hf_xnap_choice_extension, ASN1_NO_EXTENSIONS     , dissect_xnap_ProtocolIE_Single_Container },
  { 0, NULL, 0, NULL }
};

static int
dissect_xnap_CPTransportLayerInformation(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_xnap_CPTransportLayerInformation, CPTransportLayerInformation_choice,
                                 NULL);

  return offset;
}


static const value_string xnap_TypeOfError_vals[] = {
  {   0, "not-understood" },
  {   1, "missing" },
  { 0, NULL }
};


static int
dissect_xnap_TypeOfError(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     2, NULL, TRUE, 0, NULL);

  return offset;
}


static const per_sequence_t CriticalityDiagnostics_IE_List_item_sequence[] = {
  { &hf_xnap_iECriticality  , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_xnap_Criticality },
  { &hf_xnap_iE_ID          , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_xnap_ProtocolIE_ID },
  { &hf_xnap_typeOfError    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_xnap_TypeOfError },
  { &hf_xnap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_xnap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_xnap_CriticalityDiagnostics_IE_List_item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_xnap_CriticalityDiagnostics_IE_List_item, CriticalityDiagnostics_IE_List_item_sequence);

  return offset;
}


static const per_sequence_t CriticalityDiagnostics_IE_List_sequence_of[1] = {
  { &hf_xnap_CriticalityDiagnostics_IE_List_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_xnap_CriticalityDiagnostics_IE_List_item },
};

static int
dissect_xnap_CriticalityDiagnostics_IE_List(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_xnap_CriticalityDiagnostics_IE_List, CriticalityDiagnostics_IE_List_sequence_of,
                                                  1, maxNrOfErrors, FALSE);

  return offset;
}


static const per_sequence_t CriticalityDiagnostics_sequence[] = {
  { &hf_xnap_procedureCode  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_xnap_ProcedureCode },
  { &hf_xnap_triggeringMessage, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_xnap_TriggeringMessage },
  { &hf_xnap_procedureCriticality, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_xnap_Criticality },
  { &hf_xnap_iEsCriticalityDiagnostics, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_xnap_CriticalityDiagnostics_IE_List },
  { &hf_xnap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_xnap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_xnap_CriticalityDiagnostics(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_xnap_CriticalityDiagnostics, CriticalityDiagnostics_sequence);

  return offset;
}



static int
dissect_xnap_C_RNTI(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_bit_string(tvb, offset, actx, tree, hf_index,
                                     16, 16, FALSE, NULL, 0, NULL, NULL);

  return offset;
}


static const value_string xnap_CyclicPrefix_E_UTRA_DL_vals[] = {
  {   0, "normal" },
  {   1, "extended" },
  { 0, NULL }
};


static int
dissect_xnap_CyclicPrefix_E_UTRA_DL(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     2, NULL, TRUE, 0, NULL);

  return offset;
}


static const value_string xnap_CyclicPrefix_E_UTRA_UL_vals[] = {
  {   0, "normal" },
  {   1, "extended" },
  { 0, NULL }
};


static int
dissect_xnap_CyclicPrefix_E_UTRA_UL(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     2, NULL, TRUE, 0, NULL);

  return offset;
}



static int
dissect_xnap_PDUSession_ID(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 255U, NULL, FALSE);

  return offset;
}



static int
dissect_xnap_QoSFlowIdentifier(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 63U, NULL, TRUE);

  return offset;
}


static const per_sequence_t QoSFLowsAcceptedToBeForwarded_Item_sequence[] = {
  { &hf_xnap_qosFlowIdentifier, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_xnap_QoSFlowIdentifier },
  { &hf_xnap_iE_Extension   , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_xnap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_xnap_QoSFLowsAcceptedToBeForwarded_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_xnap_QoSFLowsAcceptedToBeForwarded_Item, QoSFLowsAcceptedToBeForwarded_Item_sequence);

  return offset;
}


static const per_sequence_t QoSFLowsAcceptedToBeForwarded_List_sequence_of[1] = {
  { &hf_xnap_QoSFLowsAcceptedToBeForwarded_List_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_xnap_QoSFLowsAcceptedToBeForwarded_Item },
};

static int
dissect_xnap_QoSFLowsAcceptedToBeForwarded_List(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_xnap_QoSFLowsAcceptedToBeForwarded_List, QoSFLowsAcceptedToBeForwarded_List_sequence_of,
                                                  1, maxnoofQoSFlows, FALSE);

  return offset;
}



static int
dissect_xnap_DRB_ID(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            1U, 32U, NULL, TRUE);

  return offset;
}


static const per_sequence_t DataForwardingResponseDRBItem_sequence[] = {
  { &hf_xnap_drb_ID         , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_xnap_DRB_ID },
  { &hf_xnap_dlForwardingUPTNL, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_xnap_UPTransportLayerInformation },
  { &hf_xnap_ulForwardingUPTNL, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_xnap_UPTransportLayerInformation },
  { &hf_xnap_iE_Extension   , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_xnap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_xnap_DataForwardingResponseDRBItem(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_xnap_DataForwardingResponseDRBItem, DataForwardingResponseDRBItem_sequence);

  return offset;
}


static const per_sequence_t DataForwardingResponseDRBItemList_sequence_of[1] = {
  { &hf_xnap_DataForwardingResponseDRBItemList_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_xnap_DataForwardingResponseDRBItem },
};

static int
dissect_xnap_DataForwardingResponseDRBItemList(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_xnap_DataForwardingResponseDRBItemList, DataForwardingResponseDRBItemList_sequence_of,
                                                  1, maxnoofDRBs, FALSE);

  return offset;
}


static const per_sequence_t DataForwardingInfoFromTargetNGRANnode_sequence[] = {
  { &hf_xnap_qosFlowsAcceptedForDataForwarding_List, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_xnap_QoSFLowsAcceptedToBeForwarded_List },
  { &hf_xnap_pduSessionLevelDLDataForwardingInfo, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_xnap_UPTransportLayerInformation },
  { &hf_xnap_pduSessionLevelULDataForwardingInfo, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_xnap_UPTransportLayerInformation },
  { &hf_xnap_dataForwardingResponseDRBItemList, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_xnap_DataForwardingResponseDRBItemList },
  { &hf_xnap_iE_Extension   , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_xnap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_xnap_DataForwardingInfoFromTargetNGRANnode(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_xnap_DataForwardingInfoFromTargetNGRANnode, DataForwardingInfoFromTargetNGRANnode_sequence);

  return offset;
}


static const per_sequence_t DRBsToBeSetupList_BearerSetupComplete_SNterminated_Item_sequence[] = {
  { &hf_xnap_dRB_ID         , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_xnap_DRB_ID },
  { &hf_xnap_mN_Xn_U_TNLInfoatM, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_xnap_UPTransportLayerInformation },
  { &hf_xnap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_xnap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_xnap_DRBsToBeSetupList_BearerSetupComplete_SNterminated_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_xnap_DRBsToBeSetupList_BearerSetupComplete_SNterminated_Item, DRBsToBeSetupList_BearerSetupComplete_SNterminated_Item_sequence);

  return offset;
}


static const per_sequence_t SEQUENCE_SIZE_1_maxnoofDRBs_OF_DRBsToBeSetupList_BearerSetupComplete_SNterminated_Item_sequence_of[1] = {
  { &hf_xnap_dRBsToBeSetupList_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_xnap_DRBsToBeSetupList_BearerSetupComplete_SNterminated_Item },
};

static int
dissect_xnap_SEQUENCE_SIZE_1_maxnoofDRBs_OF_DRBsToBeSetupList_BearerSetupComplete_SNterminated_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_xnap_SEQUENCE_SIZE_1_maxnoofDRBs_OF_DRBsToBeSetupList_BearerSetupComplete_SNterminated_Item, SEQUENCE_SIZE_1_maxnoofDRBs_OF_DRBsToBeSetupList_BearerSetupComplete_SNterminated_Item_sequence_of,
                                                  1, maxnoofDRBs, FALSE);

  return offset;
}


static const per_sequence_t PDUSessionResourceBearerSetupCompleteInfo_SNterminated_sequence[] = {
  { &hf_xnap_dRBsToBeSetupList, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_xnap_SEQUENCE_SIZE_1_maxnoofDRBs_OF_DRBsToBeSetupList_BearerSetupComplete_SNterminated_Item },
  { &hf_xnap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_xnap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_xnap_PDUSessionResourceBearerSetupCompleteInfo_SNterminated(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_xnap_PDUSessionResourceBearerSetupCompleteInfo_SNterminated, PDUSessionResourceBearerSetupCompleteInfo_SNterminated_sequence);

  return offset;
}


static const per_sequence_t XnUAddressInfoperPDUSession_Item_sequence[] = {
  { &hf_xnap_pduSession_ID  , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_xnap_PDUSession_ID },
  { &hf_xnap_dataForwardingInfoFromTargetNGRANnode, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_xnap_DataForwardingInfoFromTargetNGRANnode },
  { &hf_xnap_pduSessionResourceSetupCompleteInfo_SNterm, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_xnap_PDUSessionResourceBearerSetupCompleteInfo_SNterminated },
  { &hf_xnap_iE_Extension   , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_xnap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_xnap_XnUAddressInfoperPDUSession_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_xnap_XnUAddressInfoperPDUSession_Item, XnUAddressInfoperPDUSession_Item_sequence);

  return offset;
}


static const per_sequence_t XnUAddressInfoperPDUSession_List_sequence_of[1] = {
  { &hf_xnap_XnUAddressInfoperPDUSession_List_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_xnap_XnUAddressInfoperPDUSession_Item },
};

static int
dissect_xnap_XnUAddressInfoperPDUSession_List(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_xnap_XnUAddressInfoperPDUSession_List, XnUAddressInfoperPDUSession_List_sequence_of,
                                                  1, maxnoofPDUSessions, FALSE);

  return offset;
}


static const value_string xnap_DLForwarding_vals[] = {
  {   0, "dl-forwarding-proposed" },
  { 0, NULL }
};


static int
dissect_xnap_DLForwarding(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     1, NULL, TRUE, 0, NULL);

  return offset;
}


static const value_string xnap_ULForwarding_vals[] = {
  {   0, "ul-forwarding-proposed" },
  { 0, NULL }
};


static int
dissect_xnap_ULForwarding(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     1, NULL, TRUE, 0, NULL);

  return offset;
}


static const per_sequence_t QoSFLowsToBeForwarded_Item_sequence[] = {
  { &hf_xnap_qosFlowIdentifier, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_xnap_QoSFlowIdentifier },
  { &hf_xnap_dl_dataforwarding, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_xnap_DLForwarding },
  { &hf_xnap_ul_dataforwarding, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_xnap_ULForwarding },
  { &hf_xnap_iE_Extension   , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_xnap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_xnap_QoSFLowsToBeForwarded_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_xnap_QoSFLowsToBeForwarded_Item, QoSFLowsToBeForwarded_Item_sequence);

  return offset;
}


static const per_sequence_t QoSFLowsToBeForwarded_List_sequence_of[1] = {
  { &hf_xnap_QoSFLowsToBeForwarded_List_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_xnap_QoSFLowsToBeForwarded_Item },
};

static int
dissect_xnap_QoSFLowsToBeForwarded_List(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_xnap_QoSFLowsToBeForwarded_List, QoSFLowsToBeForwarded_List_sequence_of,
                                                  1, maxnoofQoSFlows, FALSE);

  return offset;
}


static const value_string xnap_QoSFlowMappingIndication_vals[] = {
  {   0, "ul" },
  {   1, "dl" },
  { 0, NULL }
};


static int
dissect_xnap_QoSFlowMappingIndication(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     2, NULL, TRUE, 0, NULL);

  return offset;
}


static const per_sequence_t QoSFlow_Item_sequence[] = {
  { &hf_xnap_qfi            , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_xnap_QoSFlowIdentifier },
  { &hf_xnap_qosFlowMappingIndication, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_xnap_QoSFlowMappingIndication },
  { &hf_xnap_iE_Extension   , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_xnap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_xnap_QoSFlow_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_xnap_QoSFlow_Item, QoSFlow_Item_sequence);

  return offset;
}


static const per_sequence_t QoSFlows_List_sequence_of[1] = {
  { &hf_xnap_QoSFlows_List_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_xnap_QoSFlow_Item },
};

static int
dissect_xnap_QoSFlows_List(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_xnap_QoSFlows_List, QoSFlows_List_sequence_of,
                                                  1, maxnoofQoSFlows, FALSE);

  return offset;
}


static const value_string xnap_RLCMode_vals[] = {
  {   0, "rlc-am" },
  {   1, "rlc-um-bidirectional" },
  {   2, "rlc-um-unidirectional-ul" },
  {   3, "rlc-um-unidirectional-dl" },
  { 0, NULL }
};


static int
dissect_xnap_RLCMode(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     4, NULL, TRUE, 0, NULL);

  return offset;
}


static const per_sequence_t DRBToQoSFlowMapping_Item_sequence[] = {
  { &hf_xnap_drb_ID         , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_xnap_DRB_ID },
  { &hf_xnap_qosFlows_List  , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_xnap_QoSFlows_List },
  { &hf_xnap_rLC_Mode       , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_xnap_RLCMode },
  { &hf_xnap_iE_Extension   , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_xnap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_xnap_DRBToQoSFlowMapping_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_xnap_DRBToQoSFlowMapping_Item, DRBToQoSFlowMapping_Item_sequence);

  return offset;
}


static const per_sequence_t DRBToQoSFlowMapping_List_sequence_of[1] = {
  { &hf_xnap_DRBToQoSFlowMapping_List_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_xnap_DRBToQoSFlowMapping_Item },
};

static int
dissect_xnap_DRBToQoSFlowMapping_List(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_xnap_DRBToQoSFlowMapping_List, DRBToQoSFlowMapping_List_sequence_of,
                                                  1, maxnoofDRBs, FALSE);

  return offset;
}


static const per_sequence_t DataforwardingandOffloadingInfofromSource_sequence[] = {
  { &hf_xnap_qosFlowsToBeForwarded, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_xnap_QoSFLowsToBeForwarded_List },
  { &hf_xnap_sourceDRBtoQoSFlowMapping, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_xnap_DRBToQoSFlowMapping_List },
  { &hf_xnap_iE_Extension   , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_xnap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_xnap_DataforwardingandOffloadingInfofromSource(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_xnap_DataforwardingandOffloadingInfofromSource, DataforwardingandOffloadingInfofromSource_sequence);

  return offset;
}



static int
dissect_xnap_DataTrafficResources(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_bit_string(tvb, offset, actx, tree, hf_index,
                                     6, 17600, FALSE, NULL, 0, NULL, NULL);

  return offset;
}


static const per_sequence_t SharedResourceType_UL_OnlySharing_sequence[] = {
  { &hf_xnap_ul_resourceBitmap, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_xnap_DataTrafficResources },
  { &hf_xnap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_xnap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_xnap_SharedResourceType_UL_OnlySharing(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_xnap_SharedResourceType_UL_OnlySharing, SharedResourceType_UL_OnlySharing_sequence);

  return offset;
}



static int
dissect_xnap_NULL(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_null(tvb, offset, actx, tree, hf_index);

  return offset;
}


static const per_sequence_t SharedResourceType_ULDL_Sharing_UL_ResourcesChanged_sequence[] = {
  { &hf_xnap_ul_resourceBitmap, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_xnap_DataTrafficResources },
  { &hf_xnap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_xnap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_xnap_SharedResourceType_ULDL_Sharing_UL_ResourcesChanged(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_xnap_SharedResourceType_ULDL_Sharing_UL_ResourcesChanged, SharedResourceType_ULDL_Sharing_UL_ResourcesChanged_sequence);

  return offset;
}


static const value_string xnap_SharedResourceType_ULDL_Sharing_UL_Resources_vals[] = {
  {   0, "unchanged" },
  {   1, "changed" },
  {   2, "choice-extension" },
  { 0, NULL }
};

static const per_choice_t SharedResourceType_ULDL_Sharing_UL_Resources_choice[] = {
  {   0, &hf_xnap_unchanged      , ASN1_NO_EXTENSIONS     , dissect_xnap_NULL },
  {   1, &hf_xnap_changed        , ASN1_NO_EXTENSIONS     , dissect_xnap_SharedResourceType_ULDL_Sharing_UL_ResourcesChanged },
  {   2, &hf_xnap_choice_extension, ASN1_NO_EXTENSIONS     , dissect_xnap_ProtocolIE_Single_Container },
  { 0, NULL, 0, NULL }
};

static int
dissect_xnap_SharedResourceType_ULDL_Sharing_UL_Resources(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_xnap_SharedResourceType_ULDL_Sharing_UL_Resources, SharedResourceType_ULDL_Sharing_UL_Resources_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t SharedResourceType_ULDL_Sharing_DL_ResourcesChanged_sequence[] = {
  { &hf_xnap_dl_resourceBitmap, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_xnap_DataTrafficResources },
  { &hf_xnap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_xnap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_xnap_SharedResourceType_ULDL_Sharing_DL_ResourcesChanged(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_xnap_SharedResourceType_ULDL_Sharing_DL_ResourcesChanged, SharedResourceType_ULDL_Sharing_DL_ResourcesChanged_sequence);

  return offset;
}


static const value_string xnap_SharedResourceType_ULDL_Sharing_DL_Resources_vals[] = {
  {   0, "unchanged" },
  {   1, "changed" },
  {   2, "choice-extension" },
  { 0, NULL }
};

static const per_choice_t SharedResourceType_ULDL_Sharing_DL_Resources_choice[] = {
  {   0, &hf_xnap_unchanged      , ASN1_NO_EXTENSIONS     , dissect_xnap_NULL },
  {   1, &hf_xnap_changed_01     , ASN1_NO_EXTENSIONS     , dissect_xnap_SharedResourceType_ULDL_Sharing_DL_ResourcesChanged },
  {   2, &hf_xnap_choice_extension, ASN1_NO_EXTENSIONS     , dissect_xnap_ProtocolIE_Single_Container },
  { 0, NULL, 0, NULL }
};

static int
dissect_xnap_SharedResourceType_ULDL_Sharing_DL_Resources(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_xnap_SharedResourceType_ULDL_Sharing_DL_Resources, SharedResourceType_ULDL_Sharing_DL_Resources_choice,
                                 NULL);

  return offset;
}


static const value_string xnap_SharedResourceType_ULDL_Sharing_vals[] = {
  {   0, "ul-resources" },
  {   1, "dl-resources" },
  {   2, "choice-extension" },
  { 0, NULL }
};

static const per_choice_t SharedResourceType_ULDL_Sharing_choice[] = {
  {   0, &hf_xnap_ul_resources   , ASN1_NO_EXTENSIONS     , dissect_xnap_SharedResourceType_ULDL_Sharing_UL_Resources },
  {   1, &hf_xnap_dl_resources   , ASN1_NO_EXTENSIONS     , dissect_xnap_SharedResourceType_ULDL_Sharing_DL_Resources },
  {   2, &hf_xnap_choice_extension, ASN1_NO_EXTENSIONS     , dissect_xnap_ProtocolIE_Single_Container },
  { 0, NULL, 0, NULL }
};

static int
dissect_xnap_SharedResourceType_ULDL_Sharing(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_xnap_SharedResourceType_ULDL_Sharing, SharedResourceType_ULDL_Sharing_choice,
                                 NULL);

  return offset;
}


static const value_string xnap_SharedResourceType_vals[] = {
  {   0, "ul-onlySharing" },
  {   1, "ul-and-dl-Sharing" },
  {   2, "choice-extension" },
  { 0, NULL }
};

static const per_choice_t SharedResourceType_choice[] = {
  {   0, &hf_xnap_ul_onlySharing , ASN1_NO_EXTENSIONS     , dissect_xnap_SharedResourceType_UL_OnlySharing },
  {   1, &hf_xnap_ul_and_dl_Sharing, ASN1_NO_EXTENSIONS     , dissect_xnap_SharedResourceType_ULDL_Sharing },
  {   2, &hf_xnap_choice_extension, ASN1_NO_EXTENSIONS     , dissect_xnap_ProtocolIE_Single_Container },
  { 0, NULL, 0, NULL }
};

static int
dissect_xnap_SharedResourceType(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_xnap_SharedResourceType, SharedResourceType_choice,
                                 NULL);

  return offset;
}


static const value_string xnap_T_subframeType_vals[] = {
  {   0, "mbsfn" },
  {   1, "non-mbsfn" },
  { 0, NULL }
};


static int
dissect_xnap_T_subframeType(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     2, NULL, TRUE, 0, NULL);

  return offset;
}



static int
dissect_xnap_BIT_STRING_SIZE_10_160(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_bit_string(tvb, offset, actx, tree, hf_index,
                                     10, 160, FALSE, NULL, 0, NULL, NULL);

  return offset;
}



static int
dissect_xnap_MBSFNControlRegionLength(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 3U, NULL, FALSE);

  return offset;
}


static const per_sequence_t ReservedSubframePattern_sequence[] = {
  { &hf_xnap_subframeType   , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_xnap_T_subframeType },
  { &hf_xnap_reservedSubframePattern_01, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_xnap_BIT_STRING_SIZE_10_160 },
  { &hf_xnap_mbsfnControlRegionLength, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_xnap_MBSFNControlRegionLength },
  { &hf_xnap_iE_Extension   , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_xnap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_xnap_ReservedSubframePattern(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_xnap_ReservedSubframePattern, ReservedSubframePattern_sequence);

  return offset;
}


static const per_sequence_t DataTrafficResourceIndication_sequence[] = {
  { &hf_xnap_activationSFN  , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_xnap_ActivationSFN },
  { &hf_xnap_sharedResourceType, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_xnap_SharedResourceType },
  { &hf_xnap_reservedSubframePattern, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_xnap_ReservedSubframePattern },
  { &hf_xnap_iE_Extension   , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_xnap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_xnap_DataTrafficResourceIndication(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_xnap_DataTrafficResourceIndication, DataTrafficResourceIndication_sequence);

  return offset;
}



static int
dissect_xnap_DeliveryStatus(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 4095U, NULL, TRUE);

  return offset;
}


static const value_string xnap_DesiredActNotificationLevel_vals[] = {
  {   0, "none" },
  {   1, "qos-flow" },
  {   2, "pdu-session" },
  {   3, "ue-level" },
  { 0, NULL }
};


static int
dissect_xnap_DesiredActNotificationLevel(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     4, NULL, TRUE, 0, NULL);

  return offset;
}


static const value_string xnap_DefaultDRB_Allowed_vals[] = {
  {   0, "true" },
  {   1, "false" },
  { 0, NULL }
};


static int
dissect_xnap_DefaultDRB_Allowed(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     2, NULL, TRUE, 0, NULL);

  return offset;
}


static const per_sequence_t DRB_List_sequence_of[1] = {
  { &hf_xnap_DRB_List_item  , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_xnap_DRB_ID },
};

static int
dissect_xnap_DRB_List(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_xnap_DRB_List, DRB_List_sequence_of,
                                                  1, maxnoofDRBs, FALSE);

  return offset;
}


static const per_sequence_t DRB_List_withCause_Item_sequence[] = {
  { &hf_xnap_drb_id         , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_xnap_DRB_ID },
  { &hf_xnap_cause          , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_xnap_Cause },
  { &hf_xnap_rLC_Mode       , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_xnap_RLCMode },
  { &hf_xnap_iE_Extension   , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_xnap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_xnap_DRB_List_withCause_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_xnap_DRB_List_withCause_Item, DRB_List_withCause_Item_sequence);

  return offset;
}


static const per_sequence_t DRB_List_withCause_sequence_of[1] = {
  { &hf_xnap_DRB_List_withCause_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_xnap_DRB_List_withCause_Item },
};

static int
dissect_xnap_DRB_List_withCause(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_xnap_DRB_List_withCause, DRB_List_withCause_sequence_of,
                                                  1, maxnoofDRBs, FALSE);

  return offset;
}



static int
dissect_xnap_DRB_Number(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            1U, 32U, NULL, TRUE);

  return offset;
}



static int
dissect_xnap_BIT_STRING_SIZE_1_2048(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_bit_string(tvb, offset, actx, tree, hf_index,
                                     1, 2048, FALSE, NULL, 0, NULL, NULL);

  return offset;
}


static const per_sequence_t DRBBStatusTransfer12bitsSN_sequence[] = {
  { &hf_xnap_receiveStatusofPDCPSDU, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_xnap_BIT_STRING_SIZE_1_2048 },
  { &hf_xnap_cOUNTValue     , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_xnap_COUNT_PDCP_SN12 },
  { &hf_xnap_iE_Extension   , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_xnap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_xnap_DRBBStatusTransfer12bitsSN(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_xnap_DRBBStatusTransfer12bitsSN, DRBBStatusTransfer12bitsSN_sequence);

  return offset;
}



static int
dissect_xnap_BIT_STRING_SIZE_1_131072(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_bit_string(tvb, offset, actx, tree, hf_index,
                                     1, 131072, FALSE, NULL, 0, NULL, NULL);

  return offset;
}


static const per_sequence_t DRBBStatusTransfer18bitsSN_sequence[] = {
  { &hf_xnap_receiveStatusofPDCPSDU_01, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_xnap_BIT_STRING_SIZE_1_131072 },
  { &hf_xnap_cOUNTValue_01  , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_xnap_COUNT_PDCP_SN18 },
  { &hf_xnap_iE_Extension   , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_xnap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_xnap_DRBBStatusTransfer18bitsSN(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_xnap_DRBBStatusTransfer18bitsSN, DRBBStatusTransfer18bitsSN_sequence);

  return offset;
}


static const value_string xnap_DRBBStatusTransferChoice_vals[] = {
  {   0, "pdcp-sn-12bits" },
  {   1, "pdcp-sn-18bits" },
  {   2, "choice-extension" },
  { 0, NULL }
};

static const per_choice_t DRBBStatusTransferChoice_choice[] = {
  {   0, &hf_xnap_pdcp_sn_12bits , ASN1_NO_EXTENSIONS     , dissect_xnap_DRBBStatusTransfer12bitsSN },
  {   1, &hf_xnap_pdcp_sn_18bits , ASN1_NO_EXTENSIONS     , dissect_xnap_DRBBStatusTransfer18bitsSN },
  {   2, &hf_xnap_choice_extension, ASN1_NO_EXTENSIONS     , dissect_xnap_ProtocolIE_Single_Container },
  { 0, NULL, 0, NULL }
};

static int
dissect_xnap_DRBBStatusTransferChoice(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_xnap_DRBBStatusTransferChoice, DRBBStatusTransferChoice_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t DRBsSubjectToStatusTransfer_Item_sequence[] = {
  { &hf_xnap_drbID          , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_xnap_DRB_ID },
  { &hf_xnap_pdcpStatusTransfer_UL, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_xnap_DRBBStatusTransferChoice },
  { &hf_xnap_pdcpStatusTransfer_DL, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_xnap_DRBBStatusTransferChoice },
  { &hf_xnap_iE_Extension   , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_xnap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_xnap_DRBsSubjectToStatusTransfer_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_xnap_DRBsSubjectToStatusTransfer_Item, DRBsSubjectToStatusTransfer_Item_sequence);

  return offset;
}


static const per_sequence_t DRBsSubjectToStatusTransfer_List_sequence_of[1] = {
  { &hf_xnap_DRBsSubjectToStatusTransfer_List_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_xnap_DRBsSubjectToStatusTransfer_Item },
};

static int
dissect_xnap_DRBsSubjectToStatusTransfer_List(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_xnap_DRBsSubjectToStatusTransfer_List, DRBsSubjectToStatusTransfer_List_sequence_of,
                                                  1, maxnoofDRBs, FALSE);

  return offset;
}


static const value_string xnap_DuplicationActivation_vals[] = {
  {   0, "active" },
  {   1, "inactive" },
  { 0, NULL }
};


static int
dissect_xnap_DuplicationActivation(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     2, NULL, TRUE, 0, NULL);

  return offset;
}



static int
dissect_xnap_PriorityLevelQoS(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            1U, 127U, NULL, TRUE);

  return offset;
}



static int
dissect_xnap_PacketDelayBudget(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 1023U, NULL, TRUE);

  return offset;
}



static int
dissect_xnap_PER_Scalar(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 9U, NULL, TRUE);

  return offset;
}



static int
dissect_xnap_PER_Exponent(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 9U, NULL, TRUE);

  return offset;
}


static const per_sequence_t PacketErrorRate_sequence[] = {
  { &hf_xnap_pER_Scalar     , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_xnap_PER_Scalar },
  { &hf_xnap_pER_Exponent   , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_xnap_PER_Exponent },
  { &hf_xnap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_xnap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_xnap_PacketErrorRate(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_xnap_PacketErrorRate, PacketErrorRate_sequence);

  return offset;
}



static int
dissect_xnap_FiveQI(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 255U, NULL, TRUE);

  return offset;
}


static const value_string xnap_T_delayCritical_vals[] = {
  {   0, "delay-critical" },
  {   1, "non-delay-critical" },
  { 0, NULL }
};


static int
dissect_xnap_T_delayCritical(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     2, NULL, TRUE, 0, NULL);

  return offset;
}



static int
dissect_xnap_MaximumDataBurstVolume(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 4095U, NULL, TRUE);

  return offset;
}


static const per_sequence_t Dynamic5QIDescriptor_sequence[] = {
  { &hf_xnap_priorityLevelQoS, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_xnap_PriorityLevelQoS },
  { &hf_xnap_packetDelayBudget, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_xnap_PacketDelayBudget },
  { &hf_xnap_packetErrorRate, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_xnap_PacketErrorRate },
  { &hf_xnap_fiveQI         , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_xnap_FiveQI },
  { &hf_xnap_delayCritical  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_xnap_T_delayCritical },
  { &hf_xnap_averagingWindow, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_xnap_AveragingWindow },
  { &hf_xnap_maximumDataBurstVolume, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_xnap_MaximumDataBurstVolume },
  { &hf_xnap_iE_Extension   , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_xnap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_xnap_Dynamic5QIDescriptor(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_xnap_Dynamic5QIDescriptor, Dynamic5QIDescriptor_sequence);

  return offset;
}



static int
dissect_xnap_E_RAB_ID(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 15U, NULL, TRUE);

  return offset;
}



static int
dissect_xnap_E_UTRAARFCN(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, maxEARFCN, NULL, FALSE);

  return offset;
}


static const per_sequence_t E_UTRA_CGI_sequence[] = {
  { &hf_xnap_plmn_id        , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_xnap_PLMN_Identity },
  { &hf_xnap_e_utra_CI      , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_xnap_E_UTRA_Cell_Identity },
  { &hf_xnap_iE_Extension   , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_xnap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_xnap_E_UTRA_CGI(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_xnap_E_UTRA_CGI, E_UTRA_CGI_sequence);

  return offset;
}



static int
dissect_xnap_E_UTRAFrequencyBandIndicator(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            1U, 256U, NULL, TRUE);

  return offset;
}


static const per_sequence_t E_UTRAMultibandInfoList_sequence_of[1] = {
  { &hf_xnap_E_UTRAMultibandInfoList_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_xnap_E_UTRAFrequencyBandIndicator },
};

static int
dissect_xnap_E_UTRAMultibandInfoList(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_xnap_E_UTRAMultibandInfoList, E_UTRAMultibandInfoList_sequence_of,
                                                  1, maxnoofEUTRABands, FALSE);

  return offset;
}



static int
dissect_xnap_E_UTRAPCI(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 503U, NULL, TRUE);

  return offset;
}



static int
dissect_xnap_INTEGER_0_837(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 837U, NULL, FALSE);

  return offset;
}



static int
dissect_xnap_INTEGER_0_15(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 15U, NULL, FALSE);

  return offset;
}


static const value_string xnap_T_highSpeedFlag_vals[] = {
  {   0, "true" },
  {   1, "false" },
  { 0, NULL }
};


static int
dissect_xnap_T_highSpeedFlag(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     2, NULL, TRUE, 0, NULL);

  return offset;
}



static int
dissect_xnap_INTEGER_0_94(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 94U, NULL, FALSE);

  return offset;
}



static int
dissect_xnap_INTEGER_0_63(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 63U, NULL, FALSE);

  return offset;
}


static const per_sequence_t E_UTRAPRACHConfiguration_sequence[] = {
  { &hf_xnap_rootSequenceIndex, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_xnap_INTEGER_0_837 },
  { &hf_xnap_zeroCorrelationIndex, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_xnap_INTEGER_0_15 },
  { &hf_xnap_highSpeedFlag  , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_xnap_T_highSpeedFlag },
  { &hf_xnap_prach_FreqOffset, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_xnap_INTEGER_0_94 },
  { &hf_xnap_prach_ConfigIndex, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_xnap_INTEGER_0_63 },
  { &hf_xnap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_xnap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_xnap_E_UTRAPRACHConfiguration(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_xnap_E_UTRAPRACHConfiguration, E_UTRAPRACHConfiguration_sequence);

  return offset;
}


static const value_string xnap_E_UTRATransmissionBandwidth_vals[] = {
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
dissect_xnap_E_UTRATransmissionBandwidth(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     6, NULL, TRUE, 1, NULL);

  return offset;
}



static int
dissect_xnap_PortNumber(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 256 "./asn1/xnap/xnap.cnf"
  tvbuff_t *parameter_tvb = NULL;
  offset = dissect_per_bit_string(tvb, offset, actx, tree, -1,
                                     16, 16, FALSE, NULL, 0, &parameter_tvb, NULL);

  if (parameter_tvb) {
    actx->created_item = proto_tree_add_item(tree, hf_index, parameter_tvb, 0, 2, ENC_BIG_ENDIAN);
  }



  return offset;
}


static const per_sequence_t EndpointIPAddressAndPort_sequence[] = {
  { &hf_xnap_endpointIPAddress, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_xnap_TransportLayerAddress },
  { &hf_xnap_portNumber     , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_xnap_PortNumber },
  { &hf_xnap_iE_Extensions  , ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_xnap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_xnap_EndpointIPAddressAndPort(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_xnap_EndpointIPAddressAndPort, EndpointIPAddressAndPort_sequence);

  return offset;
}


static const value_string xnap_EventType_vals[] = {
  {   0, "report-upon-change-of-serving-cell" },
  {   1, "report-UE-moving-presence-into-or-out-of-the-Area-of-Interest" },
  { 0, NULL }
};


static int
dissect_xnap_EventType(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     2, NULL, TRUE, 0, NULL);

  return offset;
}



static int
dissect_xnap_ExpectedActivityPeriod(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            1U, 181U, NULL, TRUE);

  return offset;
}


static const value_string xnap_ExpectedHOInterval_vals[] = {
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
dissect_xnap_ExpectedHOInterval(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     7, NULL, TRUE, 0, NULL);

  return offset;
}



static int
dissect_xnap_ExpectedIdlePeriod(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            1U, 181U, NULL, TRUE);

  return offset;
}


static const value_string xnap_SourceOfUEActivityBehaviourInformation_vals[] = {
  {   0, "subscription-information" },
  {   1, "statistics" },
  { 0, NULL }
};


static int
dissect_xnap_SourceOfUEActivityBehaviourInformation(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     2, NULL, TRUE, 0, NULL);

  return offset;
}


static const per_sequence_t ExpectedUEActivityBehaviour_sequence[] = {
  { &hf_xnap_expectedActivityPeriod, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_xnap_ExpectedActivityPeriod },
  { &hf_xnap_expectedIdlePeriod, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_xnap_ExpectedIdlePeriod },
  { &hf_xnap_sourceOfUEActivityBehaviourInformation, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_xnap_SourceOfUEActivityBehaviourInformation },
  { &hf_xnap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_xnap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_xnap_ExpectedUEActivityBehaviour(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_xnap_ExpectedUEActivityBehaviour, ExpectedUEActivityBehaviour_sequence);

  return offset;
}


static const value_string xnap_ExpectedUEMobility_vals[] = {
  {   0, "stationary" },
  {   1, "mobile" },
  { 0, NULL }
};


static int
dissect_xnap_ExpectedUEMobility(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     2, NULL, TRUE, 0, NULL);

  return offset;
}


static const per_sequence_t GlobalNG_RANCell_ID_sequence[] = {
  { &hf_xnap_plmn_id        , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_xnap_PLMN_Identity },
  { &hf_xnap_ng_RAN_Cell_id , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_xnap_NG_RAN_Cell_Identity },
  { &hf_xnap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_xnap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_xnap_GlobalNG_RANCell_ID(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_xnap_GlobalNG_RANCell_ID, GlobalNG_RANCell_ID_sequence);

  return offset;
}


static const per_sequence_t ExpectedUEMovingTrajectoryItem_sequence[] = {
  { &hf_xnap_nGRAN_CGI      , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_xnap_GlobalNG_RANCell_ID },
  { &hf_xnap_timeStayedInCell, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_xnap_INTEGER_0_4095 },
  { &hf_xnap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_xnap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_xnap_ExpectedUEMovingTrajectoryItem(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_xnap_ExpectedUEMovingTrajectoryItem, ExpectedUEMovingTrajectoryItem_sequence);

  return offset;
}


static const per_sequence_t ExpectedUEMovingTrajectory_sequence_of[1] = {
  { &hf_xnap_ExpectedUEMovingTrajectory_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_xnap_ExpectedUEMovingTrajectoryItem },
};

static int
dissect_xnap_ExpectedUEMovingTrajectory(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_xnap_ExpectedUEMovingTrajectory, ExpectedUEMovingTrajectory_sequence_of,
                                                  1, maxnoofCellsUEMovingTrajectory, FALSE);

  return offset;
}


static const per_sequence_t ExpectedUEBehaviour_sequence[] = {
  { &hf_xnap_expectedUEActivityBehaviour, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_xnap_ExpectedUEActivityBehaviour },
  { &hf_xnap_expectedHOInterval, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_xnap_ExpectedHOInterval },
  { &hf_xnap_expectedUEMobility, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_xnap_ExpectedUEMobility },
  { &hf_xnap_expectedUEMovingTrajectory, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_xnap_ExpectedUEMovingTrajectory },
  { &hf_xnap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_xnap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_xnap_ExpectedUEBehaviour(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_xnap_ExpectedUEBehaviour, ExpectedUEBehaviour_sequence);

  return offset;
}



static int
dissect_xnap_FiveGCMobilityRestrictionListContainer(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 452 "./asn1/xnap/xnap.cnf"
  tvbuff_t *parameter_tvb = NULL;

  offset = dissect_per_octet_string(tvb, offset, actx, tree, hf_index,
                                       NO_BOUND, NO_BOUND, FALSE, &parameter_tvb);

  if (parameter_tvb) {
    proto_tree *subtree = proto_item_add_subtree(actx->created_item, ett_xnap_FiveGCMobilityRestrictionListContainer);
    dissect_ngap_MobilityRestrictionList_PDU(parameter_tvb, actx->pinfo, subtree, NULL);
  }



  return offset;
}


static const value_string xnap_T_notificationControl_vals[] = {
  {   0, "notification-requested" },
  { 0, NULL }
};


static int
dissect_xnap_T_notificationControl(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     1, NULL, TRUE, 0, NULL);

  return offset;
}



static int
dissect_xnap_PacketLossRate(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 1000U, NULL, TRUE);

  return offset;
}


static const per_sequence_t GBRQoSFlowInfo_sequence[] = {
  { &hf_xnap_maxFlowBitRateDL, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_xnap_BitRate },
  { &hf_xnap_maxFlowBitRateUL, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_xnap_BitRate },
  { &hf_xnap_guaranteedFlowBitRateDL, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_xnap_BitRate },
  { &hf_xnap_guaranteedFlowBitRateUL, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_xnap_BitRate },
  { &hf_xnap_notificationControl, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_xnap_T_notificationControl },
  { &hf_xnap_maxPacketLossRateDL, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_xnap_PacketLossRate },
  { &hf_xnap_maxPacketLossRateUL, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_xnap_PacketLossRate },
  { &hf_xnap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_xnap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_xnap_GBRQoSFlowInfo(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_xnap_GBRQoSFlowInfo, GBRQoSFlowInfo_sequence);

  return offset;
}



static int
dissect_xnap_BIT_STRING_SIZE_10(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_bit_string(tvb, offset, actx, tree, hf_index,
                                     10, 10, FALSE, NULL, 0, NULL, NULL);

  return offset;
}



static int
dissect_xnap_BIT_STRING_SIZE_6(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_bit_string(tvb, offset, actx, tree, hf_index,
                                     6, 6, FALSE, NULL, 0, NULL, NULL);

  return offset;
}


static const per_sequence_t GUAMI_sequence[] = {
  { &hf_xnap_plmn_ID        , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_xnap_PLMN_Identity },
  { &hf_xnap_amf_region_id  , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_xnap_BIT_STRING_SIZE_8 },
  { &hf_xnap_amf_set_id     , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_xnap_BIT_STRING_SIZE_10 },
  { &hf_xnap_amf_pointer    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_xnap_BIT_STRING_SIZE_6 },
  { &hf_xnap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_xnap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_xnap_GUAMI(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_xnap_GUAMI, GUAMI_sequence);

  return offset;
}



static int
dissect_xnap_InterfaceInstanceIndication(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 255U, NULL, TRUE);

  return offset;
}



static int
dissect_xnap_BIT_STRING_SIZE_40(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_bit_string(tvb, offset, actx, tree, hf_index,
                                     40, 40, FALSE, NULL, 0, NULL, NULL);

  return offset;
}



static int
dissect_xnap_BIT_STRING_SIZE_24(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_bit_string(tvb, offset, actx, tree, hf_index,
                                     24, 24, FALSE, NULL, 0, NULL, NULL);

  return offset;
}


static const value_string xnap_I_RNTI_vals[] = {
  {   0, "i-RNTI-full" },
  {   1, "i-RNTI-short" },
  {   2, "choice-extension" },
  { 0, NULL }
};

static const per_choice_t I_RNTI_choice[] = {
  {   0, &hf_xnap_i_RNTI_full    , ASN1_NO_EXTENSIONS     , dissect_xnap_BIT_STRING_SIZE_40 },
  {   1, &hf_xnap_i_RNTI_short   , ASN1_NO_EXTENSIONS     , dissect_xnap_BIT_STRING_SIZE_24 },
  {   2, &hf_xnap_choice_extension, ASN1_NO_EXTENSIONS     , dissect_xnap_ProtocolIE_Single_Container },
  { 0, NULL, 0, NULL }
};

static int
dissect_xnap_I_RNTI(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_xnap_I_RNTI, I_RNTI_choice,
                                 NULL);

  return offset;
}



static int
dissect_xnap_LastVisitedNGRANCellInformation(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 365 "./asn1/xnap/xnap.cnf"
  tvbuff_t *parameter_tvb = NULL;
  proto_tree *subtree;
  offset = dissect_per_octet_string(tvb, offset, actx, tree, hf_index,
                                       NO_BOUND, NO_BOUND, FALSE, &parameter_tvb);

  if (parameter_tvb) {
    subtree = proto_item_add_subtree(actx->created_item, ett_xnap_LastVisitedNGRANCellInformation);
    dissect_ngap_LastVisitedNGRANCellInformation_PDU(parameter_tvb, actx->pinfo, subtree, NULL);
  }



  return offset;
}



static int
dissect_xnap_LastVisitedEUTRANCellInformation(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 374 "./asn1/xnap/xnap.cnf"
  tvbuff_t *parameter_tvb = NULL;
  proto_tree *subtree;
  offset = dissect_per_octet_string(tvb, offset, actx, tree, hf_index,
                                       NO_BOUND, NO_BOUND, FALSE, &parameter_tvb);

  if (parameter_tvb) {
    subtree = proto_item_add_subtree(actx->created_item, ett_xnap_LastVisitedEUTRANCellInformation);
    dissect_s1ap_LastVisitedEUTRANCellInformation_PDU(parameter_tvb, actx->pinfo, subtree, NULL);
  }



  return offset;
}



static int
dissect_xnap_LastVisitedUTRANCellInformation(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 383 "./asn1/xnap/xnap.cnf"
  tvbuff_t *parameter_tvb;
  proto_tree *subtree;
  offset = dissect_per_octet_string(tvb, offset, actx, tree, hf_index,
                                       NO_BOUND, NO_BOUND, FALSE, &parameter_tvb);

  if (parameter_tvb) {
    subtree = proto_item_add_subtree(actx->created_item, ett_xnap_LastVisitedUTRANCellInformation);
    dissect_ranap_LastVisitedUTRANCell_Item_PDU(parameter_tvb, actx->pinfo, subtree, NULL);
  }



  return offset;
}



static int
dissect_xnap_LastVisitedGERANCellInformation(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 392 "./asn1/xnap/xnap.cnf"
  tvbuff_t *parameter_tvb = NULL;
  proto_tree *subtree;
  offset = dissect_per_octet_string(tvb, offset, actx, tree, hf_index,
                                       NO_BOUND, NO_BOUND, FALSE, &parameter_tvb);

  if (parameter_tvb) {
    subtree = proto_item_add_subtree(actx->created_item, ett_xnap_LastVisitedGERANCellInformation);
    dissect_s1ap_LastVisitedGERANCellInformation_PDU(parameter_tvb, actx->pinfo, subtree, NULL);
  }



  return offset;
}


static const value_string xnap_LastVisitedCell_Item_vals[] = {
  {   0, "nG-RAN-Cell" },
  {   1, "e-UTRAN-Cell" },
  {   2, "uTRAN-Cell" },
  {   3, "gERAN-Cell" },
  {   4, "choice-extension" },
  { 0, NULL }
};

static const per_choice_t LastVisitedCell_Item_choice[] = {
  {   0, &hf_xnap_nG_RAN_Cell    , ASN1_NO_EXTENSIONS     , dissect_xnap_LastVisitedNGRANCellInformation },
  {   1, &hf_xnap_e_UTRAN_Cell   , ASN1_NO_EXTENSIONS     , dissect_xnap_LastVisitedEUTRANCellInformation },
  {   2, &hf_xnap_uTRAN_Cell     , ASN1_NO_EXTENSIONS     , dissect_xnap_LastVisitedUTRANCellInformation },
  {   3, &hf_xnap_gERAN_Cell     , ASN1_NO_EXTENSIONS     , dissect_xnap_LastVisitedGERANCellInformation },
  {   4, &hf_xnap_choice_extension, ASN1_NO_EXTENSIONS     , dissect_xnap_ProtocolIE_Single_Container },
  { 0, NULL, 0, NULL }
};

static int
dissect_xnap_LastVisitedCell_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_xnap_LastVisitedCell_Item, LastVisitedCell_Item_choice,
                                 NULL);

  return offset;
}



static int
dissect_xnap_LCID(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            1U, 32U, NULL, TRUE);

  return offset;
}


static const value_string xnap_LocationInformationSNReporting_vals[] = {
  {   0, "pSCell" },
  { 0, NULL }
};


static int
dissect_xnap_LocationInformationSNReporting(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     1, NULL, TRUE, 0, NULL);

  return offset;
}


static const value_string xnap_ReportArea_vals[] = {
  {   0, "cell" },
  { 0, NULL }
};


static int
dissect_xnap_ReportArea(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     1, NULL, TRUE, 0, NULL);

  return offset;
}


static const per_sequence_t LocationReportingInformation_sequence[] = {
  { &hf_xnap_eventType      , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_xnap_EventType },
  { &hf_xnap_reportArea     , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_xnap_ReportArea },
  { &hf_xnap_areaOfInterest , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_xnap_AreaOfInterestInformation },
  { &hf_xnap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_xnap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_xnap_LocationReportingInformation(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_xnap_LocationReportingInformation, LocationReportingInformation_sequence);

  return offset;
}


static const value_string xnap_LowerLayerPresenceStatusChange_vals[] = {
  {   0, "release-lower-layers" },
  {   1, "re-establish-lower-layers" },
  { 0, NULL }
};


static int
dissect_xnap_LowerLayerPresenceStatusChange(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     2, NULL, TRUE, 0, NULL);

  return offset;
}



static int
dissect_xnap_MAC_I(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_bit_string(tvb, offset, actx, tree, hf_index,
                                     16, 16, FALSE, NULL, 0, NULL, NULL);

  return offset;
}



static int
dissect_xnap_MaskedIMEISV(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_bit_string(tvb, offset, actx, tree, hf_index,
                                     64, 64, FALSE, NULL, 0, NULL, NULL);

  return offset;
}


static const value_string xnap_MaxIPrate_vals[] = {
  {   0, "bitrate64kbs" },
  {   1, "max-UErate" },
  { 0, NULL }
};


static int
dissect_xnap_MaxIPrate(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     2, NULL, TRUE, 0, NULL);

  return offset;
}


static const per_sequence_t MaximumIPdatarate_sequence[] = {
  { &hf_xnap_maxIPrate_UL   , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_xnap_MaxIPrate },
  { &hf_xnap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_xnap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_xnap_MaximumIPdatarate(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_xnap_MaximumIPdatarate, MaximumIPdatarate_sequence);

  return offset;
}


static const value_string xnap_MBSFNSubframeAllocation_E_UTRA_vals[] = {
  {   0, "oneframe" },
  {   1, "fourframes" },
  {   2, "choice-extension" },
  { 0, NULL }
};

static const per_choice_t MBSFNSubframeAllocation_E_UTRA_choice[] = {
  {   0, &hf_xnap_oneframe       , ASN1_NO_EXTENSIONS     , dissect_xnap_BIT_STRING_SIZE_6 },
  {   1, &hf_xnap_fourframes     , ASN1_NO_EXTENSIONS     , dissect_xnap_BIT_STRING_SIZE_24 },
  {   2, &hf_xnap_choice_extension, ASN1_NO_EXTENSIONS     , dissect_xnap_ProtocolIE_Single_Container },
  { 0, NULL, 0, NULL }
};

static int
dissect_xnap_MBSFNSubframeAllocation_E_UTRA(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_xnap_MBSFNSubframeAllocation_E_UTRA, MBSFNSubframeAllocation_E_UTRA_choice,
                                 NULL);

  return offset;
}


static const value_string xnap_T_radioframeAllocationPeriod_vals[] = {
  {   0, "n1" },
  {   1, "n2" },
  {   2, "n4" },
  {   3, "n8" },
  {   4, "n16" },
  {   5, "n32" },
  { 0, NULL }
};


static int
dissect_xnap_T_radioframeAllocationPeriod(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     6, NULL, TRUE, 0, NULL);

  return offset;
}



static int
dissect_xnap_INTEGER_0_7_(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 7U, NULL, TRUE);

  return offset;
}


static const per_sequence_t MBSFNSubframeInfo_E_UTRA_Item_sequence[] = {
  { &hf_xnap_radioframeAllocationPeriod, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_xnap_T_radioframeAllocationPeriod },
  { &hf_xnap_radioframeAllocationOffset, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_xnap_INTEGER_0_7_ },
  { &hf_xnap_subframeAllocation, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_xnap_MBSFNSubframeAllocation_E_UTRA },
  { &hf_xnap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_xnap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_xnap_MBSFNSubframeInfo_E_UTRA_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_xnap_MBSFNSubframeInfo_E_UTRA_Item, MBSFNSubframeInfo_E_UTRA_Item_sequence);

  return offset;
}


static const per_sequence_t MBSFNSubframeInfo_E_UTRA_sequence_of[1] = {
  { &hf_xnap_MBSFNSubframeInfo_E_UTRA_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_xnap_MBSFNSubframeInfo_E_UTRA_Item },
};

static int
dissect_xnap_MBSFNSubframeInfo_E_UTRA(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_xnap_MBSFNSubframeInfo_E_UTRA, MBSFNSubframeInfo_E_UTRA_sequence_of,
                                                  1, maxnoofMBSFNEUTRA, FALSE);

  return offset;
}


static const per_sequence_t SEQUENCE_SIZE_1_maxnoofEPLMNs_OF_PLMN_Identity_sequence_of[1] = {
  { &hf_xnap_equivalent_PLMNs_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_xnap_PLMN_Identity },
};

static int
dissect_xnap_SEQUENCE_SIZE_1_maxnoofEPLMNs_OF_PLMN_Identity(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_xnap_SEQUENCE_SIZE_1_maxnoofEPLMNs_OF_PLMN_Identity, SEQUENCE_SIZE_1_maxnoofEPLMNs_OF_PLMN_Identity_sequence_of,
                                                  1, maxnoofEPLMNs, FALSE);

  return offset;
}


static int * const RAT_RestrictionInformation_bits[] = {
  &hf_xnap_RAT_RestrictionInformation_e_UTRA,
  &hf_xnap_RAT_RestrictionInformation_nR,
  NULL
};

static int
dissect_xnap_RAT_RestrictionInformation(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_bit_string(tvb, offset, actx, tree, hf_index,
                                     8, 8, TRUE, RAT_RestrictionInformation_bits, 2, NULL, NULL);

  return offset;
}


static const per_sequence_t RAT_RestrictionsItem_sequence[] = {
  { &hf_xnap_plmn_Identity  , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_xnap_PLMN_Identity },
  { &hf_xnap_rat_RestrictionInformation, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_xnap_RAT_RestrictionInformation },
  { &hf_xnap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_xnap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_xnap_RAT_RestrictionsItem(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_xnap_RAT_RestrictionsItem, RAT_RestrictionsItem_sequence);

  return offset;
}


static const per_sequence_t RAT_RestrictionsList_sequence_of[1] = {
  { &hf_xnap_RAT_RestrictionsList_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_xnap_RAT_RestrictionsItem },
};

static int
dissect_xnap_RAT_RestrictionsList(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_xnap_RAT_RestrictionsList, RAT_RestrictionsList_sequence_of,
                                                  1, maxnoofPLMNs, FALSE);

  return offset;
}


static const per_sequence_t SEQUENCE_SIZE_1_maxnoofForbiddenTACs_OF_TAC_sequence_of[1] = {
  { &hf_xnap_forbidden_TACs_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_xnap_TAC },
};

static int
dissect_xnap_SEQUENCE_SIZE_1_maxnoofForbiddenTACs_OF_TAC(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_xnap_SEQUENCE_SIZE_1_maxnoofForbiddenTACs_OF_TAC, SEQUENCE_SIZE_1_maxnoofForbiddenTACs_OF_TAC_sequence_of,
                                                  1, maxnoofForbiddenTACs, FALSE);

  return offset;
}


static const per_sequence_t ForbiddenAreaItem_sequence[] = {
  { &hf_xnap_plmn_Identity  , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_xnap_PLMN_Identity },
  { &hf_xnap_forbidden_TACs , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_xnap_SEQUENCE_SIZE_1_maxnoofForbiddenTACs_OF_TAC },
  { &hf_xnap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_xnap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_xnap_ForbiddenAreaItem(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_xnap_ForbiddenAreaItem, ForbiddenAreaItem_sequence);

  return offset;
}


static const per_sequence_t ForbiddenAreaList_sequence_of[1] = {
  { &hf_xnap_ForbiddenAreaList_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_xnap_ForbiddenAreaItem },
};

static int
dissect_xnap_ForbiddenAreaList(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_xnap_ForbiddenAreaList, ForbiddenAreaList_sequence_of,
                                                  1, maxnoofPLMNs, FALSE);

  return offset;
}


static const per_sequence_t SEQUENCE_SIZE_1_maxnoofAllowedAreas_OF_TAC_sequence_of[1] = {
  { &hf_xnap_allowed_TACs_ServiceArea_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_xnap_TAC },
};

static int
dissect_xnap_SEQUENCE_SIZE_1_maxnoofAllowedAreas_OF_TAC(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_xnap_SEQUENCE_SIZE_1_maxnoofAllowedAreas_OF_TAC, SEQUENCE_SIZE_1_maxnoofAllowedAreas_OF_TAC_sequence_of,
                                                  1, maxnoofAllowedAreas, FALSE);

  return offset;
}


static const per_sequence_t ServiceAreaItem_sequence[] = {
  { &hf_xnap_plmn_Identity  , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_xnap_PLMN_Identity },
  { &hf_xnap_allowed_TACs_ServiceArea, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_xnap_SEQUENCE_SIZE_1_maxnoofAllowedAreas_OF_TAC },
  { &hf_xnap_not_allowed_TACs_ServiceArea, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_xnap_SEQUENCE_SIZE_1_maxnoofAllowedAreas_OF_TAC },
  { &hf_xnap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_xnap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_xnap_ServiceAreaItem(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_xnap_ServiceAreaItem, ServiceAreaItem_sequence);

  return offset;
}


static const per_sequence_t ServiceAreaList_sequence_of[1] = {
  { &hf_xnap_ServiceAreaList_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_xnap_ServiceAreaItem },
};

static int
dissect_xnap_ServiceAreaList(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_xnap_ServiceAreaList, ServiceAreaList_sequence_of,
                                                  1, maxnoofPLMNs, FALSE);

  return offset;
}


static const per_sequence_t MobilityRestrictionList_sequence[] = {
  { &hf_xnap_serving_PLMN   , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_xnap_PLMN_Identity },
  { &hf_xnap_equivalent_PLMNs, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_xnap_SEQUENCE_SIZE_1_maxnoofEPLMNs_OF_PLMN_Identity },
  { &hf_xnap_rat_Restrictions, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_xnap_RAT_RestrictionsList },
  { &hf_xnap_forbiddenAreaInformation, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_xnap_ForbiddenAreaList },
  { &hf_xnap_serviceAreaInformation, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_xnap_ServiceAreaList },
  { &hf_xnap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_xnap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_xnap_MobilityRestrictionList(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_xnap_MobilityRestrictionList, MobilityRestrictionList_sequence);

  return offset;
}


static const value_string xnap_T_cn_Type_vals[] = {
  {   0, "epc-forbidden" },
  {   1, "fiveGC-forbidden" },
  { 0, NULL }
};


static int
dissect_xnap_T_cn_Type(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     2, NULL, TRUE, 0, NULL);

  return offset;
}


static const per_sequence_t CNTypeRestrictionsForEquivalentItem_sequence[] = {
  { &hf_xnap_plmn_Identity  , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_xnap_PLMN_Identity },
  { &hf_xnap_cn_Type        , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_xnap_T_cn_Type },
  { &hf_xnap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_xnap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_xnap_CNTypeRestrictionsForEquivalentItem(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_xnap_CNTypeRestrictionsForEquivalentItem, CNTypeRestrictionsForEquivalentItem_sequence);

  return offset;
}


static const per_sequence_t CNTypeRestrictionsForEquivalent_sequence_of[1] = {
  { &hf_xnap_CNTypeRestrictionsForEquivalent_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_xnap_CNTypeRestrictionsForEquivalentItem },
};

static int
dissect_xnap_CNTypeRestrictionsForEquivalent(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_xnap_CNTypeRestrictionsForEquivalent, CNTypeRestrictionsForEquivalent_sequence_of,
                                                  1, maxnoofEPLMNs, FALSE);

  return offset;
}


static const value_string xnap_CNTypeRestrictionsForServing_vals[] = {
  {   0, "epc-forbidden" },
  { 0, NULL }
};


static int
dissect_xnap_CNTypeRestrictionsForServing(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     1, NULL, TRUE, 0, NULL);

  return offset;
}



static int
dissect_xnap_BIT_STRING_SIZE_6_4400(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_bit_string(tvb, offset, actx, tree, hf_index,
                                     6, 4400, FALSE, NULL, 0, NULL, NULL);

  return offset;
}


static const value_string xnap_E_UTRA_CoordinationAssistanceInfo_vals[] = {
  {   0, "coordination-not-required" },
  { 0, NULL }
};


static int
dissect_xnap_E_UTRA_CoordinationAssistanceInfo(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     1, NULL, TRUE, 0, NULL);

  return offset;
}


static const per_sequence_t E_UTRA_ResourceCoordinationInfo_sequence[] = {
  { &hf_xnap_e_utra_cell    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_xnap_E_UTRA_CGI },
  { &hf_xnap_ul_coordination_info, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_xnap_BIT_STRING_SIZE_6_4400 },
  { &hf_xnap_dl_coordination_info, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_xnap_BIT_STRING_SIZE_6_4400 },
  { &hf_xnap_nr_cell        , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_xnap_NR_CGI },
  { &hf_xnap_e_utra_coordination_assistance_info, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_xnap_E_UTRA_CoordinationAssistanceInfo },
  { &hf_xnap_iE_Extension   , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_xnap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_xnap_E_UTRA_ResourceCoordinationInfo(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_xnap_E_UTRA_ResourceCoordinationInfo, E_UTRA_ResourceCoordinationInfo_sequence);

  return offset;
}


static const value_string xnap_NR_CoordinationAssistanceInfo_vals[] = {
  {   0, "coordination-not-required" },
  { 0, NULL }
};


static int
dissect_xnap_NR_CoordinationAssistanceInfo(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     1, NULL, TRUE, 0, NULL);

  return offset;
}


static const per_sequence_t NR_ResourceCoordinationInfo_sequence[] = {
  { &hf_xnap_nr_cell        , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_xnap_NR_CGI },
  { &hf_xnap_ul_coordination_info, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_xnap_BIT_STRING_SIZE_6_4400 },
  { &hf_xnap_dl_coordination_info, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_xnap_BIT_STRING_SIZE_6_4400 },
  { &hf_xnap_e_utra_cell    , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_xnap_E_UTRA_CGI },
  { &hf_xnap_nr_coordination_assistance_info, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_xnap_NR_CoordinationAssistanceInfo },
  { &hf_xnap_iE_Extension   , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_xnap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_xnap_NR_ResourceCoordinationInfo(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_xnap_NR_ResourceCoordinationInfo, NR_ResourceCoordinationInfo_sequence);

  return offset;
}


static const value_string xnap_NG_RAN_Node_ResourceCoordinationInfo_vals[] = {
  {   0, "eutra-resource-coordination-info" },
  {   1, "nr-resource-coordination-info" },
  { 0, NULL }
};

static const per_choice_t NG_RAN_Node_ResourceCoordinationInfo_choice[] = {
  {   0, &hf_xnap_eutra_resource_coordination_info, ASN1_NO_EXTENSIONS     , dissect_xnap_E_UTRA_ResourceCoordinationInfo },
  {   1, &hf_xnap_nr_resource_coordination_info, ASN1_NO_EXTENSIONS     , dissect_xnap_NR_ResourceCoordinationInfo },
  { 0, NULL, 0, NULL }
};

static int
dissect_xnap_NG_RAN_Node_ResourceCoordinationInfo(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_xnap_NG_RAN_Node_ResourceCoordinationInfo, NG_RAN_Node_ResourceCoordinationInfo_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t MR_DC_ResourceCoordinationInfo_sequence[] = {
  { &hf_xnap_ng_RAN_Node_ResourceCoordinationInfo, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_xnap_NG_RAN_Node_ResourceCoordinationInfo },
  { &hf_xnap_iE_Extension   , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_xnap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_xnap_MR_DC_ResourceCoordinationInfo(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_xnap_MR_DC_ResourceCoordinationInfo, MR_DC_ResourceCoordinationInfo_sequence);

  return offset;
}


static const value_string xnap_T_subframeAssignment_vals[] = {
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
dissect_xnap_T_subframeAssignment(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     7, NULL, FALSE, 0, NULL);

  return offset;
}



static int
dissect_xnap_INTEGER_0_9(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 9U, NULL, FALSE);

  return offset;
}


static const per_sequence_t NE_DC_TDM_Pattern_sequence[] = {
  { &hf_xnap_subframeAssignment, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_xnap_T_subframeAssignment },
  { &hf_xnap_harqOffset     , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_xnap_INTEGER_0_9 },
  { &hf_xnap_iE_Extension   , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_xnap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_xnap_NE_DC_TDM_Pattern(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_xnap_NE_DC_TDM_Pattern, NE_DC_TDM_Pattern_sequence);

  return offset;
}


static const per_sequence_t NeighbourInformation_E_UTRA_Item_sequence[] = {
  { &hf_xnap_e_utra_PCI     , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_xnap_E_UTRAPCI },
  { &hf_xnap_e_utra_cgi     , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_xnap_E_UTRA_CGI },
  { &hf_xnap_earfcn         , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_xnap_E_UTRAARFCN },
  { &hf_xnap_tac            , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_xnap_TAC },
  { &hf_xnap_ranac          , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_xnap_RANAC },
  { &hf_xnap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_xnap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_xnap_NeighbourInformation_E_UTRA_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_xnap_NeighbourInformation_E_UTRA_Item, NeighbourInformation_E_UTRA_Item_sequence);

  return offset;
}


static const per_sequence_t NeighbourInformation_E_UTRA_sequence_of[1] = {
  { &hf_xnap_NeighbourInformation_E_UTRA_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_xnap_NeighbourInformation_E_UTRA_Item },
};

static int
dissect_xnap_NeighbourInformation_E_UTRA(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_xnap_NeighbourInformation_E_UTRA, NeighbourInformation_E_UTRA_sequence_of,
                                                  1, maxnoofNeighbours, FALSE);

  return offset;
}



static int
dissect_xnap_NRPCI(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 1007U, NULL, TRUE);

  return offset;
}



static int
dissect_xnap_NRARFCN(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, maxNRARFCN, NULL, FALSE);

  return offset;
}


static const value_string xnap_NRSCS_vals[] = {
  {   0, "scs15" },
  {   1, "scs30" },
  {   2, "scs60" },
  {   3, "scs120" },
  { 0, NULL }
};


static int
dissect_xnap_NRSCS(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     4, NULL, TRUE, 0, NULL);

  return offset;
}


static const value_string xnap_NRNRB_vals[] = {
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

static value_string_ext xnap_NRNRB_vals_ext = VALUE_STRING_EXT_INIT(xnap_NRNRB_vals);


static int
dissect_xnap_NRNRB(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     29, NULL, TRUE, 0, NULL);

  return offset;
}


static const per_sequence_t NRTransmissionBandwidth_sequence[] = {
  { &hf_xnap_nRSCS          , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_xnap_NRSCS },
  { &hf_xnap_nRNRB          , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_xnap_NRNRB },
  { &hf_xnap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_xnap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_xnap_NRTransmissionBandwidth(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_xnap_NRTransmissionBandwidth, NRTransmissionBandwidth_sequence);

  return offset;
}


static const per_sequence_t SUL_Information_sequence[] = {
  { &hf_xnap_sulFrequencyInfo, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_xnap_NRARFCN },
  { &hf_xnap_sulTransmissionBandwidth, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_xnap_NRTransmissionBandwidth },
  { &hf_xnap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_xnap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_xnap_SUL_Information(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_xnap_SUL_Information, SUL_Information_sequence);

  return offset;
}



static int
dissect_xnap_NRFrequencyBand(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            1U, 1024U, NULL, TRUE);

  return offset;
}



static int
dissect_xnap_SUL_FrequencyBand(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            1U, 1024U, NULL, FALSE);

  return offset;
}


static const per_sequence_t SupportedSULBandItem_sequence[] = {
  { &hf_xnap_sulBandItem    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_xnap_SUL_FrequencyBand },
  { &hf_xnap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_xnap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_xnap_SupportedSULBandItem(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_xnap_SupportedSULBandItem, SupportedSULBandItem_sequence);

  return offset;
}


static const per_sequence_t SupportedSULBandList_sequence_of[1] = {
  { &hf_xnap_SupportedSULBandList_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_xnap_SupportedSULBandItem },
};

static int
dissect_xnap_SupportedSULBandList(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_xnap_SupportedSULBandList, SupportedSULBandList_sequence_of,
                                                  1, maxnoofNRCellBands, FALSE);

  return offset;
}


static const per_sequence_t NRFrequencyBandItem_sequence[] = {
  { &hf_xnap_nr_frequency_band, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_xnap_NRFrequencyBand },
  { &hf_xnap_supported_SUL_Band_List, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_xnap_SupportedSULBandList },
  { &hf_xnap_iE_Extension   , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_xnap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_xnap_NRFrequencyBandItem(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_xnap_NRFrequencyBandItem, NRFrequencyBandItem_sequence);

  return offset;
}


static const per_sequence_t NRFrequencyBand_List_sequence_of[1] = {
  { &hf_xnap_NRFrequencyBand_List_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_xnap_NRFrequencyBandItem },
};

static int
dissect_xnap_NRFrequencyBand_List(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_xnap_NRFrequencyBand_List, NRFrequencyBand_List_sequence_of,
                                                  1, maxnoofNRCellBands, FALSE);

  return offset;
}


static const per_sequence_t NRFrequencyInfo_sequence[] = {
  { &hf_xnap_nrARFCN        , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_xnap_NRARFCN },
  { &hf_xnap_sul_information, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_xnap_SUL_Information },
  { &hf_xnap_frequencyBand_List, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_xnap_NRFrequencyBand_List },
  { &hf_xnap_iE_Extension   , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_xnap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_xnap_NRFrequencyInfo(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_xnap_NRFrequencyInfo, NRFrequencyInfo_sequence);

  return offset;
}


static const per_sequence_t NeighbourInformation_NR_ModeFDDInfo_sequence[] = {
  { &hf_xnap_ul_NR_FreqInfo , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_xnap_NRFrequencyInfo },
  { &hf_xnap_dl_NR_FequInfo , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_xnap_NRFrequencyInfo },
  { &hf_xnap_ie_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_xnap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_xnap_NeighbourInformation_NR_ModeFDDInfo(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_xnap_NeighbourInformation_NR_ModeFDDInfo, NeighbourInformation_NR_ModeFDDInfo_sequence);

  return offset;
}


static const per_sequence_t NeighbourInformation_NR_ModeTDDInfo_sequence[] = {
  { &hf_xnap_nr_FreqInfo    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_xnap_NRFrequencyInfo },
  { &hf_xnap_ie_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_xnap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_xnap_NeighbourInformation_NR_ModeTDDInfo(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_xnap_NeighbourInformation_NR_ModeTDDInfo, NeighbourInformation_NR_ModeTDDInfo_sequence);

  return offset;
}


static const value_string xnap_NeighbourInformation_NR_ModeInfo_vals[] = {
  {   0, "fdd-info" },
  {   1, "tdd-info" },
  {   2, "choice-extension" },
  { 0, NULL }
};

static const per_choice_t NeighbourInformation_NR_ModeInfo_choice[] = {
  {   0, &hf_xnap_fdd_info       , ASN1_NO_EXTENSIONS     , dissect_xnap_NeighbourInformation_NR_ModeFDDInfo },
  {   1, &hf_xnap_tdd_info       , ASN1_NO_EXTENSIONS     , dissect_xnap_NeighbourInformation_NR_ModeTDDInfo },
  {   2, &hf_xnap_choice_extension, ASN1_NO_EXTENSIONS     , dissect_xnap_ProtocolIE_Single_Container },
  { 0, NULL, 0, NULL }
};

static int
dissect_xnap_NeighbourInformation_NR_ModeInfo(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_xnap_NeighbourInformation_NR_ModeInfo, NeighbourInformation_NR_ModeInfo_choice,
                                 NULL);

  return offset;
}



static int
dissect_xnap_T_measurementTimingConfiguration(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 308 "./asn1/xnap/xnap.cnf"
  tvbuff_t *param_tvb = NULL;
  offset = dissect_per_octet_string(tvb, offset, actx, tree, hf_index,
                                       NO_BOUND, NO_BOUND, FALSE, &param_tvb);

  if (param_tvb) {
    proto_tree *subtree = proto_item_add_subtree(actx->created_item, ett_xnap_measurementTimingConfiguration);
    dissect_nr_rrc_MeasurementTimingConfiguration_PDU(param_tvb, actx->pinfo, subtree, NULL);
  }



  return offset;
}


static const per_sequence_t NeighbourInformation_NR_Item_sequence[] = {
  { &hf_xnap_nr_PCI         , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_xnap_NRPCI },
  { &hf_xnap_nr_cgi         , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_xnap_NR_CGI },
  { &hf_xnap_tac            , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_xnap_TAC },
  { &hf_xnap_ranac          , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_xnap_RANAC },
  { &hf_xnap_nr_mode_info   , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_xnap_NeighbourInformation_NR_ModeInfo },
  { &hf_xnap_connectivitySupport, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_xnap_Connectivity_Support },
  { &hf_xnap_measurementTimingConfiguration, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_xnap_T_measurementTimingConfiguration },
  { &hf_xnap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_xnap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_xnap_NeighbourInformation_NR_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_xnap_NeighbourInformation_NR_Item, NeighbourInformation_NR_Item_sequence);

  return offset;
}


static const per_sequence_t NeighbourInformation_NR_sequence_of[1] = {
  { &hf_xnap_NeighbourInformation_NR_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_xnap_NeighbourInformation_NR_Item },
};

static int
dissect_xnap_NeighbourInformation_NR(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_xnap_NeighbourInformation_NR, NeighbourInformation_NR_sequence_of,
                                                  1, maxnoofNeighbours, FALSE);

  return offset;
}


static const value_string xnap_NG_RAN_CellPCI_vals[] = {
  {   0, "nr" },
  {   1, "e-utra" },
  {   2, "choice-extension" },
  { 0, NULL }
};

static const per_choice_t NG_RAN_CellPCI_choice[] = {
  {   0, &hf_xnap_nr_01          , ASN1_NO_EXTENSIONS     , dissect_xnap_NRPCI },
  {   1, &hf_xnap_e_utra_01      , ASN1_NO_EXTENSIONS     , dissect_xnap_E_UTRAPCI },
  {   2, &hf_xnap_choice_extension, ASN1_NO_EXTENSIONS     , dissect_xnap_ProtocolIE_Single_Container },
  { 0, NULL, 0, NULL }
};

static int
dissect_xnap_NG_RAN_CellPCI(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_xnap_NG_RAN_CellPCI, NG_RAN_CellPCI_choice,
                                 NULL);

  return offset;
}



static int
dissect_xnap_NG_RANnodeUEXnAPID(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 4294967295U, NULL, FALSE);

  return offset;
}


static const per_sequence_t NonDynamic5QIDescriptor_sequence[] = {
  { &hf_xnap_fiveQI         , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_xnap_FiveQI },
  { &hf_xnap_priorityLevelQoS, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_xnap_PriorityLevelQoS },
  { &hf_xnap_averagingWindow, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_xnap_AveragingWindow },
  { &hf_xnap_maximumDataBurstVolume, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_xnap_MaximumDataBurstVolume },
  { &hf_xnap_iE_Extension   , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_xnap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_xnap_NonDynamic5QIDescriptor(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_xnap_NonDynamic5QIDescriptor, NonDynamic5QIDescriptor_sequence);

  return offset;
}


static const per_sequence_t NG_RAN_Cell_Identity_ListinRANPagingArea_sequence_of[1] = {
  { &hf_xnap_NG_RAN_Cell_Identity_ListinRANPagingArea_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_xnap_NG_RAN_Cell_Identity },
};

static int
dissect_xnap_NG_RAN_Cell_Identity_ListinRANPagingArea(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_xnap_NG_RAN_Cell_Identity_ListinRANPagingArea, NG_RAN_Cell_Identity_ListinRANPagingArea_sequence_of,
                                                  1, maxnoofCellsinRNA, FALSE);

  return offset;
}


static const per_sequence_t NRModeInfoFDD_sequence[] = {
  { &hf_xnap_ulNRFrequencyInfo, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_xnap_NRFrequencyInfo },
  { &hf_xnap_dlNRFrequencyInfo, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_xnap_NRFrequencyInfo },
  { &hf_xnap_ulNRTransmissonBandwidth, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_xnap_NRTransmissionBandwidth },
  { &hf_xnap_dlNRTransmissonBandwidth, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_xnap_NRTransmissionBandwidth },
  { &hf_xnap_iE_Extension   , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_xnap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_xnap_NRModeInfoFDD(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_xnap_NRModeInfoFDD, NRModeInfoFDD_sequence);

  return offset;
}


static const per_sequence_t NRModeInfoTDD_sequence[] = {
  { &hf_xnap_nrFrequencyInfo, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_xnap_NRFrequencyInfo },
  { &hf_xnap_nrTransmissonBandwidth, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_xnap_NRTransmissionBandwidth },
  { &hf_xnap_iE_Extension   , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_xnap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_xnap_NRModeInfoTDD(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_xnap_NRModeInfoTDD, NRModeInfoTDD_sequence);

  return offset;
}


static const value_string xnap_NRModeInfo_vals[] = {
  {   0, "fdd" },
  {   1, "tdd" },
  {   2, "choice-extension" },
  { 0, NULL }
};

static const per_choice_t NRModeInfo_choice[] = {
  {   0, &hf_xnap_fdd            , ASN1_NO_EXTENSIONS     , dissect_xnap_NRModeInfoFDD },
  {   1, &hf_xnap_tdd            , ASN1_NO_EXTENSIONS     , dissect_xnap_NRModeInfoTDD },
  {   2, &hf_xnap_choice_extension, ASN1_NO_EXTENSIONS     , dissect_xnap_ProtocolIE_Single_Container },
  { 0, NULL, 0, NULL }
};

static int
dissect_xnap_NRModeInfo(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_xnap_NRModeInfo, NRModeInfo_choice,
                                 NULL);

  return offset;
}


static const value_string xnap_NumberOfAntennaPorts_E_UTRA_vals[] = {
  {   0, "an1" },
  {   1, "an2" },
  {   2, "an4" },
  { 0, NULL }
};


static int
dissect_xnap_NumberOfAntennaPorts_E_UTRA(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     3, NULL, TRUE, 0, NULL);

  return offset;
}


static const value_string xnap_PagingDRX_vals[] = {
  {   0, "v32" },
  {   1, "v64" },
  {   2, "v128" },
  {   3, "v256" },
  { 0, NULL }
};


static int
dissect_xnap_PagingDRX(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     4, NULL, TRUE, 0, NULL);

  return offset;
}


static const value_string xnap_PagingPriority_vals[] = {
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
dissect_xnap_PagingPriority(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     8, NULL, TRUE, 0, NULL);

  return offset;
}


static const value_string xnap_T_from_S_NG_RAN_node_vals[] = {
  {   0, "s-ng-ran-node-key-update-required" },
  {   1, "pdcp-data-recovery-required" },
  { 0, NULL }
};


static int
dissect_xnap_T_from_S_NG_RAN_node(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     2, NULL, TRUE, 0, NULL);

  return offset;
}


static const value_string xnap_T_from_M_NG_RAN_node_vals[] = {
  {   0, "pdcp-data-recovery-required" },
  { 0, NULL }
};


static int
dissect_xnap_T_from_M_NG_RAN_node(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     1, NULL, TRUE, 0, NULL);

  return offset;
}


static const value_string xnap_PDCPChangeIndication_vals[] = {
  {   0, "from-S-NG-RAN-node" },
  {   1, "from-M-NG-RAN-node" },
  {   2, "choice-extension" },
  { 0, NULL }
};

static const per_choice_t PDCPChangeIndication_choice[] = {
  {   0, &hf_xnap_from_S_NG_RAN_node, ASN1_NO_EXTENSIONS     , dissect_xnap_T_from_S_NG_RAN_node },
  {   1, &hf_xnap_from_M_NG_RAN_node, ASN1_NO_EXTENSIONS     , dissect_xnap_T_from_M_NG_RAN_node },
  {   2, &hf_xnap_choice_extension, ASN1_NO_EXTENSIONS     , dissect_xnap_ProtocolIE_Single_Container },
  { 0, NULL, 0, NULL }
};

static int
dissect_xnap_PDCPChangeIndication(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_xnap_PDCPChangeIndication, PDCPChangeIndication_choice,
                                 NULL);

  return offset;
}


static const value_string xnap_PDCPDuplicationConfiguration_vals[] = {
  {   0, "configured" },
  {   1, "de-configured" },
  { 0, NULL }
};


static int
dissect_xnap_PDCPDuplicationConfiguration(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     2, NULL, TRUE, 0, NULL);

  return offset;
}


static const value_string xnap_T_ulPDCPSNLength_vals[] = {
  {   0, "v12bits" },
  {   1, "v18bits" },
  { 0, NULL }
};


static int
dissect_xnap_T_ulPDCPSNLength(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     2, NULL, TRUE, 0, NULL);

  return offset;
}


static const value_string xnap_T_dlPDCPSNLength_vals[] = {
  {   0, "v12bits" },
  {   1, "v18bits" },
  { 0, NULL }
};


static int
dissect_xnap_T_dlPDCPSNLength(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     2, NULL, TRUE, 0, NULL);

  return offset;
}


static const per_sequence_t PDCPSNLength_sequence[] = {
  { &hf_xnap_ulPDCPSNLength , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_xnap_T_ulPDCPSNLength },
  { &hf_xnap_dlPDCPSNLength , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_xnap_T_dlPDCPSNLength },
  { &hf_xnap_iE_Extension   , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_xnap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_xnap_PDCPSNLength(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_xnap_PDCPSNLength, PDCPSNLength_sequence);

  return offset;
}


static const per_sequence_t PDUSessionAggregateMaximumBitRate_sequence[] = {
  { &hf_xnap_downlink_session_AMBR, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_xnap_BitRate },
  { &hf_xnap_uplink_session_AMBR, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_xnap_BitRate },
  { &hf_xnap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_xnap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_xnap_PDUSessionAggregateMaximumBitRate(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_xnap_PDUSessionAggregateMaximumBitRate, PDUSessionAggregateMaximumBitRate_sequence);

  return offset;
}


static const per_sequence_t PDUSession_List_sequence_of[1] = {
  { &hf_xnap_PDUSession_List_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_xnap_PDUSession_ID },
};

static int
dissect_xnap_PDUSession_List(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_xnap_PDUSession_List, PDUSession_List_sequence_of,
                                                  1, maxnoofPDUSessions, FALSE);

  return offset;
}


static const per_sequence_t PDUSession_List_withCause_Item_sequence[] = {
  { &hf_xnap_pduSessionId   , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_xnap_PDUSession_ID },
  { &hf_xnap_cause          , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_xnap_Cause },
  { &hf_xnap_iE_Extension   , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_xnap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_xnap_PDUSession_List_withCause_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_xnap_PDUSession_List_withCause_Item, PDUSession_List_withCause_Item_sequence);

  return offset;
}


static const per_sequence_t PDUSession_List_withCause_sequence_of[1] = {
  { &hf_xnap_PDUSession_List_withCause_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_xnap_PDUSession_List_withCause_Item },
};

static int
dissect_xnap_PDUSession_List_withCause(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_xnap_PDUSession_List_withCause, PDUSession_List_withCause_sequence_of,
                                                  1, maxnoofPDUSessions, FALSE);

  return offset;
}


static const per_sequence_t PDUSession_List_withDataForwardingFromTarget_Item_sequence[] = {
  { &hf_xnap_pduSessionId   , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_xnap_PDUSession_ID },
  { &hf_xnap_dataforwardinginfoTarget, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_xnap_DataForwardingInfoFromTargetNGRANnode },
  { &hf_xnap_iE_Extension   , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_xnap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_xnap_PDUSession_List_withDataForwardingFromTarget_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_xnap_PDUSession_List_withDataForwardingFromTarget_Item, PDUSession_List_withDataForwardingFromTarget_Item_sequence);

  return offset;
}


static const per_sequence_t PDUSession_List_withDataForwardingFromTarget_sequence_of[1] = {
  { &hf_xnap_PDUSession_List_withDataForwardingFromTarget_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_xnap_PDUSession_List_withDataForwardingFromTarget_Item },
};

static int
dissect_xnap_PDUSession_List_withDataForwardingFromTarget(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_xnap_PDUSession_List_withDataForwardingFromTarget, PDUSession_List_withDataForwardingFromTarget_sequence_of,
                                                  1, maxnoofPDUSessions, FALSE);

  return offset;
}


static const per_sequence_t PDUSession_List_withDataForwardingRequest_Item_sequence[] = {
  { &hf_xnap_pduSessionId   , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_xnap_PDUSession_ID },
  { &hf_xnap_dataforwardingInfofromSource, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_xnap_DataforwardingandOffloadingInfofromSource },
  { &hf_xnap_dRBtoBeReleasedList, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_xnap_DRBToQoSFlowMapping_List },
  { &hf_xnap_iE_Extension   , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_xnap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_xnap_PDUSession_List_withDataForwardingRequest_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_xnap_PDUSession_List_withDataForwardingRequest_Item, PDUSession_List_withDataForwardingRequest_Item_sequence);

  return offset;
}


static const per_sequence_t PDUSession_List_withDataForwardingRequest_sequence_of[1] = {
  { &hf_xnap_PDUSession_List_withDataForwardingRequest_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_xnap_PDUSession_List_withDataForwardingRequest_Item },
};

static int
dissect_xnap_PDUSession_List_withDataForwardingRequest(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_xnap_PDUSession_List_withDataForwardingRequest, PDUSession_List_withDataForwardingRequest_sequence_of,
                                                  1, maxnoofPDUSessions, FALSE);

  return offset;
}


static const value_string xnap_T_dL_NG_U_TNL_Information_Unchanged_vals[] = {
  {   0, "true" },
  { 0, NULL }
};


static int
dissect_xnap_T_dL_NG_U_TNL_Information_Unchanged(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     1, NULL, TRUE, 0, NULL);

  return offset;
}


static const per_sequence_t QoSFlowsAdmitted_Item_sequence[] = {
  { &hf_xnap_qfi            , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_xnap_QoSFlowIdentifier },
  { &hf_xnap_iE_Extension   , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_xnap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_xnap_QoSFlowsAdmitted_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_xnap_QoSFlowsAdmitted_Item, QoSFlowsAdmitted_Item_sequence);

  return offset;
}


static const per_sequence_t QoSFlowsAdmitted_List_sequence_of[1] = {
  { &hf_xnap_QoSFlowsAdmitted_List_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_xnap_QoSFlowsAdmitted_Item },
};

static int
dissect_xnap_QoSFlowsAdmitted_List(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_xnap_QoSFlowsAdmitted_List, QoSFlowsAdmitted_List_sequence_of,
                                                  1, maxnoofQoSFlows, FALSE);

  return offset;
}


static const per_sequence_t QoSFlowwithCause_Item_sequence[] = {
  { &hf_xnap_qfi            , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_xnap_QoSFlowIdentifier },
  { &hf_xnap_cause          , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_xnap_Cause },
  { &hf_xnap_iE_Extension   , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_xnap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_xnap_QoSFlowwithCause_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_xnap_QoSFlowwithCause_Item, QoSFlowwithCause_Item_sequence);

  return offset;
}


static const per_sequence_t QoSFlows_List_withCause_sequence_of[1] = {
  { &hf_xnap_QoSFlows_List_withCause_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_xnap_QoSFlowwithCause_Item },
};

static int
dissect_xnap_QoSFlows_List_withCause(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_xnap_QoSFlows_List_withCause, QoSFlows_List_withCause_sequence_of,
                                                  1, maxnoofQoSFlows, FALSE);

  return offset;
}


static const per_sequence_t PDUSessionResourceAdmittedInfo_sequence[] = {
  { &hf_xnap_dL_NG_U_TNL_Information_Unchanged, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_xnap_T_dL_NG_U_TNL_Information_Unchanged },
  { &hf_xnap_qosFlowsAdmitted_List, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_xnap_QoSFlowsAdmitted_List },
  { &hf_xnap_qosFlowsNotAdmitted_List, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_xnap_QoSFlows_List_withCause },
  { &hf_xnap_dataForwardingInfoFromTarget, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_xnap_DataForwardingInfoFromTargetNGRANnode },
  { &hf_xnap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_xnap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_xnap_PDUSessionResourceAdmittedInfo(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_xnap_PDUSessionResourceAdmittedInfo, PDUSessionResourceAdmittedInfo_sequence);

  return offset;
}


static const per_sequence_t PDUSessionResourcesAdmitted_Item_sequence[] = {
  { &hf_xnap_pduSessionId   , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_xnap_PDUSession_ID },
  { &hf_xnap_pduSessionResourceAdmittedInfo, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_xnap_PDUSessionResourceAdmittedInfo },
  { &hf_xnap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_xnap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_xnap_PDUSessionResourcesAdmitted_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_xnap_PDUSessionResourcesAdmitted_Item, PDUSessionResourcesAdmitted_Item_sequence);

  return offset;
}


static const per_sequence_t PDUSessionResourcesAdmitted_List_sequence_of[1] = {
  { &hf_xnap_PDUSessionResourcesAdmitted_List_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_xnap_PDUSessionResourcesAdmitted_Item },
};

static int
dissect_xnap_PDUSessionResourcesAdmitted_List(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_xnap_PDUSessionResourcesAdmitted_List, PDUSessionResourcesAdmitted_List_sequence_of,
                                                  1, maxnoofPDUSessions, FALSE);

  return offset;
}


static const per_sequence_t PDUSessionResourcesNotAdmitted_Item_sequence[] = {
  { &hf_xnap_pduSessionId   , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_xnap_PDUSession_ID },
  { &hf_xnap_cause          , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_xnap_Cause },
  { &hf_xnap_iE_Extension   , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_xnap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_xnap_PDUSessionResourcesNotAdmitted_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_xnap_PDUSessionResourcesNotAdmitted_Item, PDUSessionResourcesNotAdmitted_Item_sequence);

  return offset;
}


static const per_sequence_t PDUSessionResourcesNotAdmitted_List_sequence_of[1] = {
  { &hf_xnap_PDUSessionResourcesNotAdmitted_List_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_xnap_PDUSessionResourcesNotAdmitted_Item },
};

static int
dissect_xnap_PDUSessionResourcesNotAdmitted_List(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_xnap_PDUSessionResourcesNotAdmitted_List, PDUSessionResourcesNotAdmitted_List_sequence_of,
                                                  1, maxnoofPDUSessions, FALSE);

  return offset;
}


static const value_string xnap_T_integrityProtectionIndication_vals[] = {
  {   0, "required" },
  {   1, "preferred" },
  {   2, "not-needed" },
  { 0, NULL }
};


static int
dissect_xnap_T_integrityProtectionIndication(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     3, NULL, TRUE, 0, NULL);

  return offset;
}


static const value_string xnap_T_confidentialityProtectionIndication_vals[] = {
  {   0, "required" },
  {   1, "preferred" },
  {   2, "not-needed" },
  { 0, NULL }
};


static int
dissect_xnap_T_confidentialityProtectionIndication(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     3, NULL, TRUE, 0, NULL);

  return offset;
}


static const per_sequence_t SecurityIndication_sequence[] = {
  { &hf_xnap_integrityProtectionIndication, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_xnap_T_integrityProtectionIndication },
  { &hf_xnap_confidentialityProtectionIndication, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_xnap_T_confidentialityProtectionIndication },
  { &hf_xnap_maximumIPdatarate, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_xnap_MaximumIPdatarate },
  { &hf_xnap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_xnap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_xnap_SecurityIndication(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_xnap_SecurityIndication, SecurityIndication_sequence);

  return offset;
}


static const value_string xnap_PDUSessionType_vals[] = {
  {   0, "ipv4" },
  {   1, "ipv6" },
  {   2, "ipv4v6" },
  {   3, "ethernet" },
  {   4, "unstructured" },
  { 0, NULL }
};


static int
dissect_xnap_PDUSessionType(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     5, NULL, TRUE, 0, NULL);

  return offset;
}



static int
dissect_xnap_PDUSessionNetworkInstance(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            1U, 256U, NULL, TRUE);

  return offset;
}


static const value_string xnap_QoSCharacteristics_vals[] = {
  {   0, "non-dynamic" },
  {   1, "dynamic" },
  {   2, "choice-extension" },
  { 0, NULL }
};

static const per_choice_t QoSCharacteristics_choice[] = {
  {   0, &hf_xnap_non_dynamic    , ASN1_NO_EXTENSIONS     , dissect_xnap_NonDynamic5QIDescriptor },
  {   1, &hf_xnap_dynamic        , ASN1_NO_EXTENSIONS     , dissect_xnap_Dynamic5QIDescriptor },
  {   2, &hf_xnap_choice_extension, ASN1_NO_EXTENSIONS     , dissect_xnap_ProtocolIE_Single_Container },
  { 0, NULL, 0, NULL }
};

static int
dissect_xnap_QoSCharacteristics(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_xnap_QoSCharacteristics, QoSCharacteristics_choice,
                                 NULL);

  return offset;
}


static const value_string xnap_ReflectiveQoSAttribute_vals[] = {
  {   0, "subject-to-reflective-QoS" },
  { 0, NULL }
};


static int
dissect_xnap_ReflectiveQoSAttribute(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     1, NULL, TRUE, 0, NULL);

  return offset;
}


static const value_string xnap_T_additionalQoSflowInfo_vals[] = {
  {   0, "more-likely" },
  { 0, NULL }
};


static int
dissect_xnap_T_additionalQoSflowInfo(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     1, NULL, TRUE, 0, NULL);

  return offset;
}


static const per_sequence_t QoSFlowLevelQoSParameters_sequence[] = {
  { &hf_xnap_qos_characteristics, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_xnap_QoSCharacteristics },
  { &hf_xnap_allocationAndRetentionPrio, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_xnap_AllocationandRetentionPriority },
  { &hf_xnap_gBRQoSFlowInfo , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_xnap_GBRQoSFlowInfo },
  { &hf_xnap_relectiveQoS   , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_xnap_ReflectiveQoSAttribute },
  { &hf_xnap_additionalQoSflowInfo, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_xnap_T_additionalQoSflowInfo },
  { &hf_xnap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_xnap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_xnap_QoSFlowLevelQoSParameters(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_xnap_QoSFlowLevelQoSParameters, QoSFlowLevelQoSParameters_sequence);

  return offset;
}


static const per_sequence_t QoSFlowsToBeSetup_Item_sequence[] = {
  { &hf_xnap_qfi            , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_xnap_QoSFlowIdentifier },
  { &hf_xnap_qosFlowLevelQoSParameters, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_xnap_QoSFlowLevelQoSParameters },
  { &hf_xnap_e_RAB_ID       , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_xnap_E_RAB_ID },
  { &hf_xnap_iE_Extension   , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_xnap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_xnap_QoSFlowsToBeSetup_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_xnap_QoSFlowsToBeSetup_Item, QoSFlowsToBeSetup_Item_sequence);

  return offset;
}


static const per_sequence_t QoSFlowsToBeSetup_List_sequence_of[1] = {
  { &hf_xnap_QoSFlowsToBeSetup_List_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_xnap_QoSFlowsToBeSetup_Item },
};

static int
dissect_xnap_QoSFlowsToBeSetup_List(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_xnap_QoSFlowsToBeSetup_List, QoSFlowsToBeSetup_List_sequence_of,
                                                  1, maxnoofQoSFlows, FALSE);

  return offset;
}


static const per_sequence_t PDUSessionResourcesToBeSetup_Item_sequence[] = {
  { &hf_xnap_pduSessionId   , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_xnap_PDUSession_ID },
  { &hf_xnap_s_NSSAI        , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_xnap_S_NSSAI },
  { &hf_xnap_pduSessionAMBR , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_xnap_PDUSessionAggregateMaximumBitRate },
  { &hf_xnap_uL_NG_U_TNLatUPF, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_xnap_UPTransportLayerInformation },
  { &hf_xnap_source_DL_NG_U_TNL_Information, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_xnap_UPTransportLayerInformation },
  { &hf_xnap_securityIndication, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_xnap_SecurityIndication },
  { &hf_xnap_pduSessionType , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_xnap_PDUSessionType },
  { &hf_xnap_pduSessionNetworkInstance, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_xnap_PDUSessionNetworkInstance },
  { &hf_xnap_qosFlowsToBeSetup_List, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_xnap_QoSFlowsToBeSetup_List },
  { &hf_xnap_dataforwardinginfofromSource, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_xnap_DataforwardingandOffloadingInfofromSource },
  { &hf_xnap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_xnap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_xnap_PDUSessionResourcesToBeSetup_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_xnap_PDUSessionResourcesToBeSetup_Item, PDUSessionResourcesToBeSetup_Item_sequence);

  return offset;
}


static const per_sequence_t PDUSessionResourcesToBeSetup_List_sequence_of[1] = {
  { &hf_xnap_PDUSessionResourcesToBeSetup_List_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_xnap_PDUSessionResourcesToBeSetup_Item },
};

static int
dissect_xnap_PDUSessionResourcesToBeSetup_List(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_xnap_PDUSessionResourcesToBeSetup_List, PDUSessionResourcesToBeSetup_List_sequence_of,
                                                  1, maxnoofPDUSessions, FALSE);

  return offset;
}


static const per_sequence_t QoSFlowsToBeSetup_List_Setup_SNterminated_Item_sequence[] = {
  { &hf_xnap_qfi            , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_xnap_QoSFlowIdentifier },
  { &hf_xnap_qosFlowLevelQoSParameters, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_xnap_QoSFlowLevelQoSParameters },
  { &hf_xnap_offeredGBRQoSFlowInfo, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_xnap_GBRQoSFlowInfo },
  { &hf_xnap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_xnap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_xnap_QoSFlowsToBeSetup_List_Setup_SNterminated_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_xnap_QoSFlowsToBeSetup_List_Setup_SNterminated_Item, QoSFlowsToBeSetup_List_Setup_SNterminated_Item_sequence);

  return offset;
}


static const per_sequence_t QoSFlowsToBeSetup_List_Setup_SNterminated_sequence_of[1] = {
  { &hf_xnap_QoSFlowsToBeSetup_List_Setup_SNterminated_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_xnap_QoSFlowsToBeSetup_List_Setup_SNterminated_Item },
};

static int
dissect_xnap_QoSFlowsToBeSetup_List_Setup_SNterminated(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_xnap_QoSFlowsToBeSetup_List_Setup_SNterminated, QoSFlowsToBeSetup_List_Setup_SNterminated_sequence_of,
                                                  1, maxnoofQoSFlows, FALSE);

  return offset;
}


static const per_sequence_t PDUSessionResourceSetupInfo_SNterminated_sequence[] = {
  { &hf_xnap_uL_NG_U_TNLatUPF, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_xnap_UPTransportLayerInformation },
  { &hf_xnap_pduSessionType , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_xnap_PDUSessionType },
  { &hf_xnap_pduSessionNetworkInstance, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_xnap_PDUSessionNetworkInstance },
  { &hf_xnap_qosFlowsToBeSetup_List_01, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_xnap_QoSFlowsToBeSetup_List_Setup_SNterminated },
  { &hf_xnap_dataforwardinginfofromSource, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_xnap_DataforwardingandOffloadingInfofromSource },
  { &hf_xnap_securityIndication, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_xnap_SecurityIndication },
  { &hf_xnap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_xnap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_xnap_PDUSessionResourceSetupInfo_SNterminated(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_xnap_PDUSessionResourceSetupInfo_SNterminated, PDUSessionResourceSetupInfo_SNterminated_sequence);

  return offset;
}


static const per_sequence_t UPTransportParametersItem_sequence[] = {
  { &hf_xnap_upTNLInfo      , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_xnap_UPTransportLayerInformation },
  { &hf_xnap_cellGroupID    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_xnap_CellGroupID },
  { &hf_xnap_iE_Extension   , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_xnap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_xnap_UPTransportParametersItem(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_xnap_UPTransportParametersItem, UPTransportParametersItem_sequence);

  return offset;
}


static const per_sequence_t UPTransportParameters_sequence_of[1] = {
  { &hf_xnap_UPTransportParameters_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_xnap_UPTransportParametersItem },
};

static int
dissect_xnap_UPTransportParameters(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_xnap_UPTransportParameters, UPTransportParameters_sequence_of,
                                                  1, maxnoofSCellGroupsplus1, FALSE);

  return offset;
}


static const value_string xnap_UL_UE_Configuration_vals[] = {
  {   0, "no-data" },
  {   1, "shared" },
  {   2, "only" },
  { 0, NULL }
};


static int
dissect_xnap_UL_UE_Configuration(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     3, NULL, TRUE, 0, NULL);

  return offset;
}


static const per_sequence_t ULConfiguration_sequence[] = {
  { &hf_xnap_uL_PDCP        , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_xnap_UL_UE_Configuration },
  { &hf_xnap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_xnap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_xnap_ULConfiguration(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_xnap_ULConfiguration, ULConfiguration_sequence);

  return offset;
}


static const per_sequence_t QoSFlowsMappedtoDRB_SetupResponse_SNterminated_Item_sequence[] = {
  { &hf_xnap_qoSFlowIdentifier, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_xnap_QoSFlowIdentifier },
  { &hf_xnap_mCGRequestedGBRQoSFlowInfo, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_xnap_GBRQoSFlowInfo },
  { &hf_xnap_qosFlowMappingIndication, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_xnap_QoSFlowMappingIndication },
  { &hf_xnap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_xnap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_xnap_QoSFlowsMappedtoDRB_SetupResponse_SNterminated_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_xnap_QoSFlowsMappedtoDRB_SetupResponse_SNterminated_Item, QoSFlowsMappedtoDRB_SetupResponse_SNterminated_Item_sequence);

  return offset;
}


static const per_sequence_t QoSFlowsMappedtoDRB_SetupResponse_SNterminated_sequence_of[1] = {
  { &hf_xnap_QoSFlowsMappedtoDRB_SetupResponse_SNterminated_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_xnap_QoSFlowsMappedtoDRB_SetupResponse_SNterminated_Item },
};

static int
dissect_xnap_QoSFlowsMappedtoDRB_SetupResponse_SNterminated(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_xnap_QoSFlowsMappedtoDRB_SetupResponse_SNterminated, QoSFlowsMappedtoDRB_SetupResponse_SNterminated_sequence_of,
                                                  1, maxnoofQoSFlows, FALSE);

  return offset;
}


static const per_sequence_t DRBsToBeSetupList_SetupResponse_SNterminated_Item_sequence[] = {
  { &hf_xnap_drb_ID         , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_xnap_DRB_ID },
  { &hf_xnap_sN_UL_PDCP_UP_TNLInfo, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_xnap_UPTransportParameters },
  { &hf_xnap_dRB_QoS        , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_xnap_QoSFlowLevelQoSParameters },
  { &hf_xnap_pDCP_SNLength  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_xnap_PDCPSNLength },
  { &hf_xnap_rLC_Mode       , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_xnap_RLCMode },
  { &hf_xnap_uL_Configuration, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_xnap_ULConfiguration },
  { &hf_xnap_secondary_SN_UL_PDCP_UP_TNLInfo, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_xnap_UPTransportParameters },
  { &hf_xnap_duplicationActivation, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_xnap_DuplicationActivation },
  { &hf_xnap_qoSFlowsMappedtoDRB_SetupResponse_SNterminated, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_xnap_QoSFlowsMappedtoDRB_SetupResponse_SNterminated },
  { &hf_xnap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_xnap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_xnap_DRBsToBeSetupList_SetupResponse_SNterminated_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_xnap_DRBsToBeSetupList_SetupResponse_SNterminated_Item, DRBsToBeSetupList_SetupResponse_SNterminated_Item_sequence);

  return offset;
}


static const per_sequence_t DRBsToBeSetupList_SetupResponse_SNterminated_sequence_of[1] = {
  { &hf_xnap_DRBsToBeSetupList_SetupResponse_SNterminated_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_xnap_DRBsToBeSetupList_SetupResponse_SNterminated_Item },
};

static int
dissect_xnap_DRBsToBeSetupList_SetupResponse_SNterminated(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_xnap_DRBsToBeSetupList_SetupResponse_SNterminated, DRBsToBeSetupList_SetupResponse_SNterminated_sequence_of,
                                                  1, maxnoofDRBs, FALSE);

  return offset;
}


static const value_string xnap_T_integrityProtectionResult_vals[] = {
  {   0, "performed" },
  {   1, "not-performed" },
  { 0, NULL }
};


static int
dissect_xnap_T_integrityProtectionResult(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     2, NULL, TRUE, 0, NULL);

  return offset;
}


static const value_string xnap_T_confidentialityProtectionResult_vals[] = {
  {   0, "performed" },
  {   1, "not-performed" },
  { 0, NULL }
};


static int
dissect_xnap_T_confidentialityProtectionResult(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     2, NULL, TRUE, 0, NULL);

  return offset;
}


static const per_sequence_t SecurityResult_sequence[] = {
  { &hf_xnap_integrityProtectionResult, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_xnap_T_integrityProtectionResult },
  { &hf_xnap_confidentialityProtectionResult, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_xnap_T_confidentialityProtectionResult },
  { &hf_xnap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_xnap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_xnap_SecurityResult(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_xnap_SecurityResult, SecurityResult_sequence);

  return offset;
}


static const per_sequence_t PDUSessionResourceSetupResponseInfo_SNterminated_sequence[] = {
  { &hf_xnap_dL_NG_U_TNLatNG_RAN, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_xnap_UPTransportLayerInformation },
  { &hf_xnap_dRBsToBeSetup  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_xnap_DRBsToBeSetupList_SetupResponse_SNterminated },
  { &hf_xnap_dataforwardinginfoTarget, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_xnap_DataForwardingInfoFromTargetNGRANnode },
  { &hf_xnap_qosFlowsNotAdmittedList, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_xnap_QoSFlows_List_withCause },
  { &hf_xnap_securityResult , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_xnap_SecurityResult },
  { &hf_xnap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_xnap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_xnap_PDUSessionResourceSetupResponseInfo_SNterminated(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_xnap_PDUSessionResourceSetupResponseInfo_SNterminated, PDUSessionResourceSetupResponseInfo_SNterminated_sequence);

  return offset;
}


static const per_sequence_t QoSFlowsMappedtoDRB_Setup_MNterminated_Item_sequence[] = {
  { &hf_xnap_qoSFlowIdentifier, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_xnap_QoSFlowIdentifier },
  { &hf_xnap_qoSFlowLevelQoSParameters, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_xnap_QoSFlowLevelQoSParameters },
  { &hf_xnap_qosFlowMappingIndication, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_xnap_QoSFlowMappingIndication },
  { &hf_xnap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_xnap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_xnap_QoSFlowsMappedtoDRB_Setup_MNterminated_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_xnap_QoSFlowsMappedtoDRB_Setup_MNterminated_Item, QoSFlowsMappedtoDRB_Setup_MNterminated_Item_sequence);

  return offset;
}


static const per_sequence_t QoSFlowsMappedtoDRB_Setup_MNterminated_sequence_of[1] = {
  { &hf_xnap_QoSFlowsMappedtoDRB_Setup_MNterminated_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_xnap_QoSFlowsMappedtoDRB_Setup_MNterminated_Item },
};

static int
dissect_xnap_QoSFlowsMappedtoDRB_Setup_MNterminated(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_xnap_QoSFlowsMappedtoDRB_Setup_MNterminated, QoSFlowsMappedtoDRB_Setup_MNterminated_sequence_of,
                                                  1, maxnoofQoSFlows, FALSE);

  return offset;
}


static const per_sequence_t DRBsToBeSetupList_Setup_MNterminated_Item_sequence[] = {
  { &hf_xnap_drb_ID         , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_xnap_DRB_ID },
  { &hf_xnap_mN_UL_PDCP_UP_TNLInfo, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_xnap_UPTransportParameters },
  { &hf_xnap_rLC_Mode       , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_xnap_RLCMode },
  { &hf_xnap_uL_Configuration, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_xnap_ULConfiguration },
  { &hf_xnap_dRB_QoS        , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_xnap_QoSFlowLevelQoSParameters },
  { &hf_xnap_pDCP_SNLength  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_xnap_PDCPSNLength },
  { &hf_xnap_secondary_MN_UL_PDCP_UP_TNLInfo, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_xnap_UPTransportParameters },
  { &hf_xnap_duplicationActivation, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_xnap_DuplicationActivation },
  { &hf_xnap_qoSFlowsMappedtoDRB_Setup_MNterminated, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_xnap_QoSFlowsMappedtoDRB_Setup_MNterminated },
  { &hf_xnap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_xnap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_xnap_DRBsToBeSetupList_Setup_MNterminated_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_xnap_DRBsToBeSetupList_Setup_MNterminated_Item, DRBsToBeSetupList_Setup_MNterminated_Item_sequence);

  return offset;
}


static const per_sequence_t DRBsToBeSetupList_Setup_MNterminated_sequence_of[1] = {
  { &hf_xnap_DRBsToBeSetupList_Setup_MNterminated_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_xnap_DRBsToBeSetupList_Setup_MNterminated_Item },
};

static int
dissect_xnap_DRBsToBeSetupList_Setup_MNterminated(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_xnap_DRBsToBeSetupList_Setup_MNterminated, DRBsToBeSetupList_Setup_MNterminated_sequence_of,
                                                  1, maxnoofDRBs, FALSE);

  return offset;
}


static const per_sequence_t PDUSessionResourceSetupInfo_MNterminated_sequence[] = {
  { &hf_xnap_pduSessionType , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_xnap_PDUSessionType },
  { &hf_xnap_dRBsToBeSetup_01, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_xnap_DRBsToBeSetupList_Setup_MNterminated },
  { &hf_xnap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_xnap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_xnap_PDUSessionResourceSetupInfo_MNterminated(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_xnap_PDUSessionResourceSetupInfo_MNterminated, PDUSessionResourceSetupInfo_MNterminated_sequence);

  return offset;
}


static const per_sequence_t DRBsAdmittedList_SetupResponse_MNterminated_Item_sequence[] = {
  { &hf_xnap_drb_ID         , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_xnap_DRB_ID },
  { &hf_xnap_sN_DL_SCG_UP_TNLInfo, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_xnap_UPTransportParameters },
  { &hf_xnap_secondary_SN_DL_SCG_UP_TNLInfo, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_xnap_UPTransportParameters },
  { &hf_xnap_lCID           , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_xnap_LCID },
  { &hf_xnap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_xnap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_xnap_DRBsAdmittedList_SetupResponse_MNterminated_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_xnap_DRBsAdmittedList_SetupResponse_MNterminated_Item, DRBsAdmittedList_SetupResponse_MNterminated_Item_sequence);

  return offset;
}


static const per_sequence_t DRBsAdmittedList_SetupResponse_MNterminated_sequence_of[1] = {
  { &hf_xnap_DRBsAdmittedList_SetupResponse_MNterminated_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_xnap_DRBsAdmittedList_SetupResponse_MNterminated_Item },
};

static int
dissect_xnap_DRBsAdmittedList_SetupResponse_MNterminated(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_xnap_DRBsAdmittedList_SetupResponse_MNterminated, DRBsAdmittedList_SetupResponse_MNterminated_sequence_of,
                                                  1, maxnoofDRBs, FALSE);

  return offset;
}


static const per_sequence_t PDUSessionResourceSetupResponseInfo_MNterminated_sequence[] = {
  { &hf_xnap_dRBsAdmittedList, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_xnap_DRBsAdmittedList_SetupResponse_MNterminated },
  { &hf_xnap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_xnap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_xnap_PDUSessionResourceSetupResponseInfo_MNterminated(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_xnap_PDUSessionResourceSetupResponseInfo_MNterminated, PDUSessionResourceSetupResponseInfo_MNterminated_sequence);

  return offset;
}


static const per_sequence_t QoSFlowsToBeSetup_List_Modified_SNterminated_Item_sequence[] = {
  { &hf_xnap_qfi            , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_xnap_QoSFlowIdentifier },
  { &hf_xnap_qosFlowLevelQoSParameters, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_xnap_QoSFlowLevelQoSParameters },
  { &hf_xnap_offeredGBRQoSFlowInfo, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_xnap_GBRQoSFlowInfo },
  { &hf_xnap_qosFlowMappingIndication, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_xnap_QoSFlowMappingIndication },
  { &hf_xnap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_xnap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_xnap_QoSFlowsToBeSetup_List_Modified_SNterminated_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_xnap_QoSFlowsToBeSetup_List_Modified_SNterminated_Item, QoSFlowsToBeSetup_List_Modified_SNterminated_Item_sequence);

  return offset;
}


static const per_sequence_t QoSFlowsToBeSetup_List_Modified_SNterminated_sequence_of[1] = {
  { &hf_xnap_QoSFlowsToBeSetup_List_Modified_SNterminated_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_xnap_QoSFlowsToBeSetup_List_Modified_SNterminated_Item },
};

static int
dissect_xnap_QoSFlowsToBeSetup_List_Modified_SNterminated(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_xnap_QoSFlowsToBeSetup_List_Modified_SNterminated, QoSFlowsToBeSetup_List_Modified_SNterminated_sequence_of,
                                                  1, maxnoofQoSFlows, FALSE);

  return offset;
}


static const value_string xnap_Reestablishment_Indication_vals[] = {
  {   0, "reestablished" },
  { 0, NULL }
};


static int
dissect_xnap_Reestablishment_Indication(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     1, NULL, TRUE, 0, NULL);

  return offset;
}


static const per_sequence_t RLC_Status_sequence[] = {
  { &hf_xnap_reestablishment_Indication, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_xnap_Reestablishment_Indication },
  { &hf_xnap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_xnap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_xnap_RLC_Status(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_xnap_RLC_Status, RLC_Status_sequence);

  return offset;
}


static const per_sequence_t DRBsToBeModified_List_Modified_SNterminated_Item_sequence[] = {
  { &hf_xnap_drb_ID         , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_xnap_DRB_ID },
  { &hf_xnap_mN_DL_SCG_UP_TNLInfo, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_xnap_UPTransportParameters },
  { &hf_xnap_secondary_MN_DL_SCG_UP_TNLInfo, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_xnap_UPTransportParameters },
  { &hf_xnap_lCID           , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_xnap_LCID },
  { &hf_xnap_rlc_status     , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_xnap_RLC_Status },
  { &hf_xnap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_xnap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_xnap_DRBsToBeModified_List_Modified_SNterminated_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_xnap_DRBsToBeModified_List_Modified_SNterminated_Item, DRBsToBeModified_List_Modified_SNterminated_Item_sequence);

  return offset;
}


static const per_sequence_t DRBsToBeModified_List_Modified_SNterminated_sequence_of[1] = {
  { &hf_xnap_DRBsToBeModified_List_Modified_SNterminated_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_xnap_DRBsToBeModified_List_Modified_SNterminated_Item },
};

static int
dissect_xnap_DRBsToBeModified_List_Modified_SNterminated(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_xnap_DRBsToBeModified_List_Modified_SNterminated, DRBsToBeModified_List_Modified_SNterminated_sequence_of,
                                                  1, maxnoofDRBs, FALSE);

  return offset;
}


static const per_sequence_t PDUSessionResourceModificationInfo_SNterminated_sequence[] = {
  { &hf_xnap_uL_NG_U_TNLatUPF, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_xnap_UPTransportLayerInformation },
  { &hf_xnap_pduSessionNetworkInstance, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_xnap_PDUSessionNetworkInstance },
  { &hf_xnap_qosFlowsToBeSetup_List_01, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_xnap_QoSFlowsToBeSetup_List_Setup_SNterminated },
  { &hf_xnap_dataforwardinginfofromSource, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_xnap_DataforwardingandOffloadingInfofromSource },
  { &hf_xnap_qosFlowsToBeModified_List, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_xnap_QoSFlowsToBeSetup_List_Modified_SNterminated },
  { &hf_xnap_qoSFlowsToBeReleased_List, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_xnap_QoSFlows_List_withCause },
  { &hf_xnap_drbsToBeModifiedList, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_xnap_DRBsToBeModified_List_Modified_SNterminated },
  { &hf_xnap_dRBsToBeReleased, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_xnap_DRB_List_withCause },
  { &hf_xnap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_xnap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_xnap_PDUSessionResourceModificationInfo_SNterminated(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_xnap_PDUSessionResourceModificationInfo_SNterminated, PDUSessionResourceModificationInfo_SNterminated_sequence);

  return offset;
}


static const per_sequence_t DRBsToBeModifiedList_ModificationResponse_SNterminated_Item_sequence[] = {
  { &hf_xnap_drb_ID         , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_xnap_DRB_ID },
  { &hf_xnap_sN_UL_PDCP_UP_TNLInfo, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_xnap_UPTransportParameters },
  { &hf_xnap_dRB_QoS        , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_xnap_QoSFlowLevelQoSParameters },
  { &hf_xnap_qoSFlowsMappedtoDRB_SetupResponse_SNterminated, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_xnap_QoSFlowsMappedtoDRB_SetupResponse_SNterminated },
  { &hf_xnap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_xnap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_xnap_DRBsToBeModifiedList_ModificationResponse_SNterminated_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_xnap_DRBsToBeModifiedList_ModificationResponse_SNterminated_Item, DRBsToBeModifiedList_ModificationResponse_SNterminated_Item_sequence);

  return offset;
}


static const per_sequence_t DRBsToBeModifiedList_ModificationResponse_SNterminated_sequence_of[1] = {
  { &hf_xnap_DRBsToBeModifiedList_ModificationResponse_SNterminated_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_xnap_DRBsToBeModifiedList_ModificationResponse_SNterminated_Item },
};

static int
dissect_xnap_DRBsToBeModifiedList_ModificationResponse_SNterminated(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_xnap_DRBsToBeModifiedList_ModificationResponse_SNterminated, DRBsToBeModifiedList_ModificationResponse_SNterminated_sequence_of,
                                                  1, maxnoofDRBs, FALSE);

  return offset;
}


static const per_sequence_t PDUSessionResourceModificationResponseInfo_SNterminated_sequence[] = {
  { &hf_xnap_dL_NG_U_TNLatNG_RAN, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_xnap_UPTransportLayerInformation },
  { &hf_xnap_dRBsToBeSetup  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_xnap_DRBsToBeSetupList_SetupResponse_SNterminated },
  { &hf_xnap_dataforwardinginfoTarget, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_xnap_DataForwardingInfoFromTargetNGRANnode },
  { &hf_xnap_dRBsToBeModified, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_xnap_DRBsToBeModifiedList_ModificationResponse_SNterminated },
  { &hf_xnap_dRBsToBeReleased, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_xnap_DRB_List_withCause },
  { &hf_xnap_dataforwardinginfofromSource, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_xnap_DataforwardingandOffloadingInfofromSource },
  { &hf_xnap_qosFlowsNotAdmittedTBAdded, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_xnap_QoSFlows_List_withCause },
  { &hf_xnap_qosFlowsReleased, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_xnap_QoSFlows_List_withCause },
  { &hf_xnap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_xnap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_xnap_PDUSessionResourceModificationResponseInfo_SNterminated(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_xnap_PDUSessionResourceModificationResponseInfo_SNterminated, PDUSessionResourceModificationResponseInfo_SNterminated_sequence);

  return offset;
}


static const per_sequence_t DRBsToBeModifiedList_Modification_MNterminated_Item_sequence[] = {
  { &hf_xnap_drb_ID         , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_xnap_DRB_ID },
  { &hf_xnap_mN_UL_PDCP_UP_TNLInfo, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_xnap_UPTransportParameters },
  { &hf_xnap_dRB_QoS        , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_xnap_QoSFlowLevelQoSParameters },
  { &hf_xnap_secondary_MN_UL_PDCP_UP_TNLInfo, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_xnap_UPTransportParameters },
  { &hf_xnap_uL_Configuration, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_xnap_ULConfiguration },
  { &hf_xnap_pdcpDuplicationConfiguration, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_xnap_PDCPDuplicationConfiguration },
  { &hf_xnap_duplicationActivation, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_xnap_DuplicationActivation },
  { &hf_xnap_qoSFlowsMappedtoDRB_Setup_MNterminated, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_xnap_QoSFlowsMappedtoDRB_Setup_MNterminated },
  { &hf_xnap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_xnap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_xnap_DRBsToBeModifiedList_Modification_MNterminated_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_xnap_DRBsToBeModifiedList_Modification_MNterminated_Item, DRBsToBeModifiedList_Modification_MNterminated_Item_sequence);

  return offset;
}


static const per_sequence_t DRBsToBeModifiedList_Modification_MNterminated_sequence_of[1] = {
  { &hf_xnap_DRBsToBeModifiedList_Modification_MNterminated_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_xnap_DRBsToBeModifiedList_Modification_MNterminated_Item },
};

static int
dissect_xnap_DRBsToBeModifiedList_Modification_MNterminated(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_xnap_DRBsToBeModifiedList_Modification_MNterminated, DRBsToBeModifiedList_Modification_MNterminated_sequence_of,
                                                  1, maxnoofDRBs, FALSE);

  return offset;
}


static const per_sequence_t PDUSessionResourceModificationInfo_MNterminated_sequence[] = {
  { &hf_xnap_pduSessionType , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_xnap_PDUSessionType },
  { &hf_xnap_dRBsToBeSetup_01, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_xnap_DRBsToBeSetupList_Setup_MNterminated },
  { &hf_xnap_dRBsToBeModified_01, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_xnap_DRBsToBeModifiedList_Modification_MNterminated },
  { &hf_xnap_dRBsToBeReleased, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_xnap_DRB_List_withCause },
  { &hf_xnap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_xnap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_xnap_PDUSessionResourceModificationInfo_MNterminated(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_xnap_PDUSessionResourceModificationInfo_MNterminated, PDUSessionResourceModificationInfo_MNterminated_sequence);

  return offset;
}


static const per_sequence_t DRBsAdmittedList_ModificationResponse_MNterminated_Item_sequence[] = {
  { &hf_xnap_drb_ID         , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_xnap_DRB_ID },
  { &hf_xnap_sN_DL_SCG_UP_TNLInfo, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_xnap_UPTransportParameters },
  { &hf_xnap_secondary_SN_DL_SCG_UP_TNLInfo, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_xnap_UPTransportParameters },
  { &hf_xnap_lCID           , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_xnap_LCID },
  { &hf_xnap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_xnap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_xnap_DRBsAdmittedList_ModificationResponse_MNterminated_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_xnap_DRBsAdmittedList_ModificationResponse_MNterminated_Item, DRBsAdmittedList_ModificationResponse_MNterminated_Item_sequence);

  return offset;
}


static const per_sequence_t DRBsAdmittedList_ModificationResponse_MNterminated_sequence_of[1] = {
  { &hf_xnap_DRBsAdmittedList_ModificationResponse_MNterminated_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_xnap_DRBsAdmittedList_ModificationResponse_MNterminated_Item },
};

static int
dissect_xnap_DRBsAdmittedList_ModificationResponse_MNterminated(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_xnap_DRBsAdmittedList_ModificationResponse_MNterminated, DRBsAdmittedList_ModificationResponse_MNterminated_sequence_of,
                                                  1, maxnoofDRBs, FALSE);

  return offset;
}


static const per_sequence_t PDUSessionResourceModificationResponseInfo_MNterminated_sequence[] = {
  { &hf_xnap_dRBsAdmittedList_01, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_xnap_DRBsAdmittedList_ModificationResponse_MNterminated },
  { &hf_xnap_dRBsReleasedList, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_xnap_DRB_List },
  { &hf_xnap_dRBsNotAdmittedSetupModifyList, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_xnap_DRB_List_withCause },
  { &hf_xnap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_xnap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_xnap_PDUSessionResourceModificationResponseInfo_MNterminated(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_xnap_PDUSessionResourceModificationResponseInfo_MNterminated, PDUSessionResourceModificationResponseInfo_MNterminated_sequence);

  return offset;
}


static const per_sequence_t PDUSessionResourceChangeRequiredInfo_SNterminated_sequence[] = {
  { &hf_xnap_dataforwardinginfofromSource, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_xnap_DataforwardingandOffloadingInfofromSource },
  { &hf_xnap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_xnap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_xnap_PDUSessionResourceChangeRequiredInfo_SNterminated(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_xnap_PDUSessionResourceChangeRequiredInfo_SNterminated, PDUSessionResourceChangeRequiredInfo_SNterminated_sequence);

  return offset;
}


static const per_sequence_t PDUSessionResourceChangeConfirmInfo_SNterminated_sequence[] = {
  { &hf_xnap_dataforwardinginfoTarget, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_xnap_DataForwardingInfoFromTargetNGRANnode },
  { &hf_xnap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_xnap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_xnap_PDUSessionResourceChangeConfirmInfo_SNterminated(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_xnap_PDUSessionResourceChangeConfirmInfo_SNterminated, PDUSessionResourceChangeConfirmInfo_SNterminated_sequence);

  return offset;
}


static const per_sequence_t PDUSessionResourceChangeRequiredInfo_MNterminated_sequence[] = {
  { &hf_xnap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_xnap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_xnap_PDUSessionResourceChangeRequiredInfo_MNterminated(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_xnap_PDUSessionResourceChangeRequiredInfo_MNterminated, PDUSessionResourceChangeRequiredInfo_MNterminated_sequence);

  return offset;
}


static const per_sequence_t PDUSessionResourceChangeConfirmInfo_MNterminated_sequence[] = {
  { &hf_xnap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_xnap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_xnap_PDUSessionResourceChangeConfirmInfo_MNterminated(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_xnap_PDUSessionResourceChangeConfirmInfo_MNterminated, PDUSessionResourceChangeConfirmInfo_MNterminated_sequence);

  return offset;
}


static const per_sequence_t QoSFlowsSetupMappedtoDRB_ModRqd_SNterminated_Item_sequence[] = {
  { &hf_xnap_qoSFlowIdentifier, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_xnap_QoSFlowIdentifier },
  { &hf_xnap_mCGRequestedGBRQoSFlowInfo, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_xnap_GBRQoSFlowInfo },
  { &hf_xnap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_xnap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_xnap_QoSFlowsSetupMappedtoDRB_ModRqd_SNterminated_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_xnap_QoSFlowsSetupMappedtoDRB_ModRqd_SNterminated_Item, QoSFlowsSetupMappedtoDRB_ModRqd_SNterminated_Item_sequence);

  return offset;
}


static const per_sequence_t QoSFlowsSetupMappedtoDRB_ModRqd_SNterminated_sequence_of[1] = {
  { &hf_xnap_QoSFlowsSetupMappedtoDRB_ModRqd_SNterminated_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_xnap_QoSFlowsSetupMappedtoDRB_ModRqd_SNterminated_Item },
};

static int
dissect_xnap_QoSFlowsSetupMappedtoDRB_ModRqd_SNterminated(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_xnap_QoSFlowsSetupMappedtoDRB_ModRqd_SNterminated, QoSFlowsSetupMappedtoDRB_ModRqd_SNterminated_sequence_of,
                                                  1, maxnoofQoSFlows, FALSE);

  return offset;
}


static const per_sequence_t DRBsToBeSetup_List_ModRqd_SNterminated_Item_sequence[] = {
  { &hf_xnap_drb_ID         , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_xnap_DRB_ID },
  { &hf_xnap_pDCP_SNLength  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_xnap_PDCPSNLength },
  { &hf_xnap_sn_UL_PDCP_UPTNLinfo, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_xnap_UPTransportParameters },
  { &hf_xnap_dRB_QoS        , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_xnap_QoSFlowLevelQoSParameters },
  { &hf_xnap_secondary_SN_UL_PDCP_UP_TNLInfo, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_xnap_UPTransportParameters },
  { &hf_xnap_duplicationActivation, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_xnap_DuplicationActivation },
  { &hf_xnap_uL_Configuration, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_xnap_ULConfiguration },
  { &hf_xnap_qoSFlowsMappedtoDRB_ModRqd_SNterminated, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_xnap_QoSFlowsSetupMappedtoDRB_ModRqd_SNterminated },
  { &hf_xnap_rLC_Mode       , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_xnap_RLCMode },
  { &hf_xnap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_xnap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_xnap_DRBsToBeSetup_List_ModRqd_SNterminated_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_xnap_DRBsToBeSetup_List_ModRqd_SNterminated_Item, DRBsToBeSetup_List_ModRqd_SNterminated_Item_sequence);

  return offset;
}


static const per_sequence_t DRBsToBeSetup_List_ModRqd_SNterminated_sequence_of[1] = {
  { &hf_xnap_DRBsToBeSetup_List_ModRqd_SNterminated_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_xnap_DRBsToBeSetup_List_ModRqd_SNterminated_Item },
};

static int
dissect_xnap_DRBsToBeSetup_List_ModRqd_SNterminated(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_xnap_DRBsToBeSetup_List_ModRqd_SNterminated, DRBsToBeSetup_List_ModRqd_SNterminated_sequence_of,
                                                  1, maxnoofDRBs, FALSE);

  return offset;
}


static const per_sequence_t QoSFlowsModifiedMappedtoDRB_ModRqd_SNterminated_Item_sequence[] = {
  { &hf_xnap_qoSFlowIdentifier, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_xnap_QoSFlowIdentifier },
  { &hf_xnap_mCGRequestedGBRQoSFlowInfo, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_xnap_GBRQoSFlowInfo },
  { &hf_xnap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_xnap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_xnap_QoSFlowsModifiedMappedtoDRB_ModRqd_SNterminated_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_xnap_QoSFlowsModifiedMappedtoDRB_ModRqd_SNterminated_Item, QoSFlowsModifiedMappedtoDRB_ModRqd_SNterminated_Item_sequence);

  return offset;
}


static const per_sequence_t QoSFlowsModifiedMappedtoDRB_ModRqd_SNterminated_sequence_of[1] = {
  { &hf_xnap_QoSFlowsModifiedMappedtoDRB_ModRqd_SNterminated_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_xnap_QoSFlowsModifiedMappedtoDRB_ModRqd_SNterminated_Item },
};

static int
dissect_xnap_QoSFlowsModifiedMappedtoDRB_ModRqd_SNterminated(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_xnap_QoSFlowsModifiedMappedtoDRB_ModRqd_SNterminated, QoSFlowsModifiedMappedtoDRB_ModRqd_SNterminated_sequence_of,
                                                  1, maxnoofQoSFlows, FALSE);

  return offset;
}


static const per_sequence_t DRBsToBeModified_List_ModRqd_SNterminated_Item_sequence[] = {
  { &hf_xnap_drb_ID         , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_xnap_DRB_ID },
  { &hf_xnap_sN_UL_PDCP_UP_TNLInfo, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_xnap_UPTransportParameters },
  { &hf_xnap_dRB_QoS        , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_xnap_QoSFlowLevelQoSParameters },
  { &hf_xnap_secondary_SN_UL_PDCP_UP_TNLInfo, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_xnap_UPTransportParameters },
  { &hf_xnap_uL_Configuration, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_xnap_ULConfiguration },
  { &hf_xnap_pdcpDuplicationConfiguration, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_xnap_PDCPDuplicationConfiguration },
  { &hf_xnap_duplicationActivation, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_xnap_DuplicationActivation },
  { &hf_xnap_qoSFlowsMappedtoDRB_ModRqd_SNterminated_01, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_xnap_QoSFlowsModifiedMappedtoDRB_ModRqd_SNterminated },
  { &hf_xnap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_xnap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_xnap_DRBsToBeModified_List_ModRqd_SNterminated_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_xnap_DRBsToBeModified_List_ModRqd_SNterminated_Item, DRBsToBeModified_List_ModRqd_SNterminated_Item_sequence);

  return offset;
}


static const per_sequence_t DRBsToBeModified_List_ModRqd_SNterminated_sequence_of[1] = {
  { &hf_xnap_DRBsToBeModified_List_ModRqd_SNterminated_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_xnap_DRBsToBeModified_List_ModRqd_SNterminated_Item },
};

static int
dissect_xnap_DRBsToBeModified_List_ModRqd_SNterminated(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_xnap_DRBsToBeModified_List_ModRqd_SNterminated, DRBsToBeModified_List_ModRqd_SNterminated_sequence_of,
                                                  1, maxnoofDRBs, FALSE);

  return offset;
}


static const per_sequence_t PDUSessionResourceModRqdInfo_SNterminated_sequence[] = {
  { &hf_xnap_dL_NG_U_TNLatNG_RAN, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_xnap_UPTransportLayerInformation },
  { &hf_xnap_qoSFlowsToBeReleased_List, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_xnap_QoSFlows_List_withCause },
  { &hf_xnap_dataforwardinginfofromSource, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_xnap_DataforwardingandOffloadingInfofromSource },
  { &hf_xnap_drbsToBeSetupList, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_xnap_DRBsToBeSetup_List_ModRqd_SNterminated },
  { &hf_xnap_drbsToBeModifiedList_01, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_xnap_DRBsToBeModified_List_ModRqd_SNterminated },
  { &hf_xnap_dRBsToBeReleased, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_xnap_DRB_List_withCause },
  { &hf_xnap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_xnap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_xnap_PDUSessionResourceModRqdInfo_SNterminated(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_xnap_PDUSessionResourceModRqdInfo_SNterminated, PDUSessionResourceModRqdInfo_SNterminated_sequence);

  return offset;
}


static const per_sequence_t DRBsAdmittedList_ModConfirm_SNterminated_Item_sequence[] = {
  { &hf_xnap_drb_ID         , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_xnap_DRB_ID },
  { &hf_xnap_mN_DL_CG_UP_TNLInfo, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_xnap_UPTransportParameters },
  { &hf_xnap_secondary_MN_DL_CG_UP_TNLInfo, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_xnap_UPTransportParameters },
  { &hf_xnap_lCID           , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_xnap_LCID },
  { &hf_xnap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_xnap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_xnap_DRBsAdmittedList_ModConfirm_SNterminated_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_xnap_DRBsAdmittedList_ModConfirm_SNterminated_Item, DRBsAdmittedList_ModConfirm_SNterminated_Item_sequence);

  return offset;
}


static const per_sequence_t DRBsAdmittedList_ModConfirm_SNterminated_sequence_of[1] = {
  { &hf_xnap_DRBsAdmittedList_ModConfirm_SNterminated_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_xnap_DRBsAdmittedList_ModConfirm_SNterminated_Item },
};

static int
dissect_xnap_DRBsAdmittedList_ModConfirm_SNterminated(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_xnap_DRBsAdmittedList_ModConfirm_SNterminated, DRBsAdmittedList_ModConfirm_SNterminated_sequence_of,
                                                  1, maxnoofDRBs, FALSE);

  return offset;
}


static const per_sequence_t PDUSessionResourceModConfirmInfo_SNterminated_sequence[] = {
  { &hf_xnap_uL_NG_U_TNLatUPF, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_xnap_UPTransportLayerInformation },
  { &hf_xnap_dRBsAdmittedList_02, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_xnap_DRBsAdmittedList_ModConfirm_SNterminated },
  { &hf_xnap_dRBsNotAdmittedSetupModifyList, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_xnap_DRB_List_withCause },
  { &hf_xnap_dataforwardinginfoTarget, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_xnap_DataForwardingInfoFromTargetNGRANnode },
  { &hf_xnap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_xnap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_xnap_PDUSessionResourceModConfirmInfo_SNterminated(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_xnap_PDUSessionResourceModConfirmInfo_SNterminated, PDUSessionResourceModConfirmInfo_SNterminated_sequence);

  return offset;
}


static const per_sequence_t DRBsToBeModified_List_ModRqd_MNterminated_Item_sequence[] = {
  { &hf_xnap_drb_ID         , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_xnap_DRB_ID },
  { &hf_xnap_sN_DL_SCG_UP_TNLInfo_01, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_xnap_UPTransportLayerInformation },
  { &hf_xnap_secondary_SN_DL_SCG_UP_TNLInfo_01, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_xnap_UPTransportLayerInformation },
  { &hf_xnap_lCID           , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_xnap_LCID },
  { &hf_xnap_rlc_status     , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_xnap_RLC_Status },
  { &hf_xnap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_xnap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_xnap_DRBsToBeModified_List_ModRqd_MNterminated_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_xnap_DRBsToBeModified_List_ModRqd_MNterminated_Item, DRBsToBeModified_List_ModRqd_MNterminated_Item_sequence);

  return offset;
}


static const per_sequence_t DRBsToBeModified_List_ModRqd_MNterminated_sequence_of[1] = {
  { &hf_xnap_DRBsToBeModified_List_ModRqd_MNterminated_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_xnap_DRBsToBeModified_List_ModRqd_MNterminated_Item },
};

static int
dissect_xnap_DRBsToBeModified_List_ModRqd_MNterminated(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_xnap_DRBsToBeModified_List_ModRqd_MNterminated, DRBsToBeModified_List_ModRqd_MNterminated_sequence_of,
                                                  1, maxnoofDRBs, FALSE);

  return offset;
}


static const per_sequence_t PDUSessionResourceModRqdInfo_MNterminated_sequence[] = {
  { &hf_xnap_dRBsToBeModified_02, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_xnap_DRBsToBeModified_List_ModRqd_MNterminated },
  { &hf_xnap_dRBsToBeReleased, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_xnap_DRB_List_withCause },
  { &hf_xnap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_xnap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_xnap_PDUSessionResourceModRqdInfo_MNterminated(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_xnap_PDUSessionResourceModRqdInfo_MNterminated, PDUSessionResourceModRqdInfo_MNterminated_sequence);

  return offset;
}


static const per_sequence_t PDUSessionResourceModConfirmInfo_MNterminated_sequence[] = {
  { &hf_xnap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_xnap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_xnap_PDUSessionResourceModConfirmInfo_MNterminated(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_xnap_PDUSessionResourceModConfirmInfo_MNterminated, PDUSessionResourceModConfirmInfo_MNterminated_sequence);

  return offset;
}


static const value_string xnap_T_rATType_vals[] = {
  {   0, "nr" },
  {   1, "eutra" },
  { 0, NULL }
};


static int
dissect_xnap_T_rATType(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     2, NULL, TRUE, 0, NULL);

  return offset;
}



static int
dissect_xnap_T_startTimeStamp(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 410 "./asn1/xnap/xnap.cnf"
  tvbuff_t *timestamp_tvb = NULL;
  offset = dissect_per_octet_string(tvb, offset, actx, tree, hf_index,
                                       4, 4, FALSE, &timestamp_tvb);




#line 414 "./asn1/xnap/xnap.cnf"
  if (timestamp_tvb) {
    proto_item_append_text(actx->created_item, " (%s)", tvb_ntp_fmt_ts_sec(timestamp_tvb, 0));
  }


  return offset;
}



static int
dissect_xnap_T_endTimeStamp(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 419 "./asn1/xnap/xnap.cnf"
  tvbuff_t *timestamp_tvb = NULL;
  offset = dissect_per_octet_string(tvb, offset, actx, tree, hf_index,
                                       4, 4, FALSE, &timestamp_tvb);




#line 423 "./asn1/xnap/xnap.cnf"
  if (timestamp_tvb) {
    proto_item_append_text(actx->created_item, " (%s)", tvb_ntp_fmt_ts_sec(timestamp_tvb, 0));
  }


  return offset;
}



static int
dissect_xnap_INTEGER_0_18446744073709551615(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer_64b(tvb, offset, actx, tree, hf_index,
                                                            0U, G_GUINT64_CONSTANT(18446744073709551615), NULL, FALSE);

  return offset;
}


static const per_sequence_t VolumeTimedReport_Item_sequence[] = {
  { &hf_xnap_startTimeStamp , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_xnap_T_startTimeStamp },
  { &hf_xnap_endTimeStamp   , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_xnap_T_endTimeStamp },
  { &hf_xnap_usageCountUL   , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_xnap_INTEGER_0_18446744073709551615 },
  { &hf_xnap_usageCountDL   , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_xnap_INTEGER_0_18446744073709551615 },
  { &hf_xnap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_xnap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_xnap_VolumeTimedReport_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_xnap_VolumeTimedReport_Item, VolumeTimedReport_Item_sequence);

  return offset;
}


static const per_sequence_t VolumeTimedReportList_sequence_of[1] = {
  { &hf_xnap_VolumeTimedReportList_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_xnap_VolumeTimedReport_Item },
};

static int
dissect_xnap_VolumeTimedReportList(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_xnap_VolumeTimedReportList, VolumeTimedReportList_sequence_of,
                                                  1, maxnooftimeperiods, FALSE);

  return offset;
}


static const per_sequence_t PDUSessionUsageReport_sequence[] = {
  { &hf_xnap_rATType        , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_xnap_T_rATType },
  { &hf_xnap_pDUSessionTimedReportList, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_xnap_VolumeTimedReportList },
  { &hf_xnap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_xnap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_xnap_PDUSessionUsageReport(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_xnap_PDUSessionUsageReport, PDUSessionUsageReport_sequence);

  return offset;
}


static const value_string xnap_T_rATType_01_vals[] = {
  {   0, "nr" },
  {   1, "eutra" },
  { 0, NULL }
};


static int
dissect_xnap_T_rATType_01(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     2, NULL, TRUE, 0, NULL);

  return offset;
}


static const per_sequence_t QoSFlowsUsageReport_Item_sequence[] = {
  { &hf_xnap_qosFlowIdentifier, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_xnap_QoSFlowIdentifier },
  { &hf_xnap_rATType_01     , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_xnap_T_rATType_01 },
  { &hf_xnap_qoSFlowsTimedReportList, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_xnap_VolumeTimedReportList },
  { &hf_xnap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_xnap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_xnap_QoSFlowsUsageReport_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_xnap_QoSFlowsUsageReport_Item, QoSFlowsUsageReport_Item_sequence);

  return offset;
}


static const per_sequence_t QoSFlowsUsageReportList_sequence_of[1] = {
  { &hf_xnap_QoSFlowsUsageReportList_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_xnap_QoSFlowsUsageReport_Item },
};

static int
dissect_xnap_QoSFlowsUsageReportList(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_xnap_QoSFlowsUsageReportList, QoSFlowsUsageReportList_sequence_of,
                                                  1, maxnoofQoSFlows, FALSE);

  return offset;
}


static const per_sequence_t SecondaryRATUsageInformation_sequence[] = {
  { &hf_xnap_pDUSessionUsageReport, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_xnap_PDUSessionUsageReport },
  { &hf_xnap_qosFlowsUsageReportList, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_xnap_QoSFlowsUsageReportList },
  { &hf_xnap_iE_Extension   , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_xnap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_xnap_SecondaryRATUsageInformation(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_xnap_SecondaryRATUsageInformation, SecondaryRATUsageInformation_sequence);

  return offset;
}


static const per_sequence_t PDUSessionResourceSecondaryRATUsageItem_sequence[] = {
  { &hf_xnap_pDUSessionID   , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_xnap_PDUSession_ID },
  { &hf_xnap_secondaryRATUsageInformation, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_xnap_SecondaryRATUsageInformation },
  { &hf_xnap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_xnap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_xnap_PDUSessionResourceSecondaryRATUsageItem(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_xnap_PDUSessionResourceSecondaryRATUsageItem, PDUSessionResourceSecondaryRATUsageItem_sequence);

  return offset;
}


static const per_sequence_t PDUSessionResourceSecondaryRATUsageList_sequence_of[1] = {
  { &hf_xnap_PDUSessionResourceSecondaryRATUsageList_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_xnap_PDUSessionResourceSecondaryRATUsageItem },
};

static int
dissect_xnap_PDUSessionResourceSecondaryRATUsageList(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_xnap_PDUSessionResourceSecondaryRATUsageList, PDUSessionResourceSecondaryRATUsageList_sequence_of,
                                                  1, maxnoofPDUSessions, FALSE);

  return offset;
}



static int
dissect_xnap_PDUSessionCommonNetworkInstance(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_octet_string(tvb, offset, actx, tree, hf_index,
                                       NO_BOUND, NO_BOUND, FALSE, NULL);

  return offset;
}


static const value_string xnap_T_resourceType_vals[] = {
  {   0, "downlinknonCRS" },
  {   1, "cRS" },
  {   2, "uplink" },
  { 0, NULL }
};


static int
dissect_xnap_T_resourceType(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     3, NULL, TRUE, 0, NULL);

  return offset;
}



static int
dissect_xnap_BIT_STRING_SIZE_84_(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_bit_string(tvb, offset, actx, tree, hf_index,
                                     84, 84, TRUE, NULL, 0, NULL, NULL);

  return offset;
}



static int
dissect_xnap_BIT_STRING_SIZE_6_110_(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_bit_string(tvb, offset, actx, tree, hf_index,
                                     6, 110, TRUE, NULL, 0, NULL, NULL);

  return offset;
}



static int
dissect_xnap_INTEGER_1_320_(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            1U, 320U, NULL, TRUE);

  return offset;
}



static int
dissect_xnap_INTEGER_1_20_(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            1U, 20U, NULL, TRUE);

  return offset;
}


static const per_sequence_t ProtectedE_UTRAFootprintTimePattern_sequence[] = {
  { &hf_xnap_protectedFootprintTimeperiodicity, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_xnap_INTEGER_1_320_ },
  { &hf_xnap_protectedFootrpintStartTime, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_xnap_INTEGER_1_20_ },
  { &hf_xnap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_xnap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_xnap_ProtectedE_UTRAFootprintTimePattern(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_xnap_ProtectedE_UTRAFootprintTimePattern, ProtectedE_UTRAFootprintTimePattern_sequence);

  return offset;
}


static const per_sequence_t ProtectedE_UTRAResource_Item_sequence[] = {
  { &hf_xnap_resourceType   , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_xnap_T_resourceType },
  { &hf_xnap_intra_PRBProtectedResourceFootprint, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_xnap_BIT_STRING_SIZE_84_ },
  { &hf_xnap_protectedFootprintFrequencyPattern, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_xnap_BIT_STRING_SIZE_6_110_ },
  { &hf_xnap_protectedFootprintTimePattern, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_xnap_ProtectedE_UTRAFootprintTimePattern },
  { &hf_xnap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_xnap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_xnap_ProtectedE_UTRAResource_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_xnap_ProtectedE_UTRAResource_Item, ProtectedE_UTRAResource_Item_sequence);

  return offset;
}


static const per_sequence_t ProtectedE_UTRAResourceList_sequence_of[1] = {
  { &hf_xnap_ProtectedE_UTRAResourceList_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_xnap_ProtectedE_UTRAResource_Item },
};

static int
dissect_xnap_ProtectedE_UTRAResourceList(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_xnap_ProtectedE_UTRAResourceList, ProtectedE_UTRAResourceList_sequence_of,
                                                  1, maxnoofProtectedResourcePatterns, FALSE);

  return offset;
}



static int
dissect_xnap_INTEGER_1_3(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            1U, 3U, NULL, FALSE);

  return offset;
}


static const per_sequence_t ProtectedE_UTRAResourceIndication_sequence[] = {
  { &hf_xnap_activationSFN  , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_xnap_ActivationSFN },
  { &hf_xnap_protectedResourceList, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_xnap_ProtectedE_UTRAResourceList },
  { &hf_xnap_mbsfnControlRegionLength, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_xnap_MBSFNControlRegionLength },
  { &hf_xnap_pDCCHRegionLength, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_xnap_INTEGER_1_3 },
  { &hf_xnap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_xnap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_xnap_ProtectedE_UTRAResourceIndication(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_xnap_ProtectedE_UTRAResourceIndication, ProtectedE_UTRAResourceIndication_sequence);

  return offset;
}


static const value_string xnap_T_notificationInformation_vals[] = {
  {   0, "fulfilled" },
  {   1, "not-fulfilled" },
  { 0, NULL }
};


static int
dissect_xnap_T_notificationInformation(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     2, NULL, TRUE, 0, NULL);

  return offset;
}


static const per_sequence_t QoSFlowNotify_Item_sequence[] = {
  { &hf_xnap_qosFlowIdentifier, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_xnap_QoSFlowIdentifier },
  { &hf_xnap_notificationInformation, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_xnap_T_notificationInformation },
  { &hf_xnap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_xnap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_xnap_QoSFlowNotify_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_xnap_QoSFlowNotify_Item, QoSFlowNotify_Item_sequence);

  return offset;
}


static const per_sequence_t QoSFlowNotificationControlIndicationInfo_sequence_of[1] = {
  { &hf_xnap_QoSFlowNotificationControlIndicationInfo_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_xnap_QoSFlowNotify_Item },
};

static int
dissect_xnap_QoSFlowNotificationControlIndicationInfo(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_xnap_QoSFlowNotificationControlIndicationInfo, QoSFlowNotificationControlIndicationInfo_sequence_of,
                                                  1, maxnoofQoSFlows, FALSE);

  return offset;
}


static const per_sequence_t RANAreaID_sequence[] = {
  { &hf_xnap_tAC            , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_xnap_TAC },
  { &hf_xnap_rANAC          , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_xnap_RANAC },
  { &hf_xnap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_xnap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_xnap_RANAreaID(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_xnap_RANAreaID, RANAreaID_sequence);

  return offset;
}


static const per_sequence_t RANAreaID_List_sequence_of[1] = {
  { &hf_xnap_RANAreaID_List_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_xnap_RANAreaID },
};

static int
dissect_xnap_RANAreaID_List(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_xnap_RANAreaID_List, RANAreaID_List_sequence_of,
                                                  1, maxnoofRANAreasinRNA, FALSE);

  return offset;
}


static const value_string xnap_RANPagingAreaChoice_vals[] = {
  {   0, "cell-List" },
  {   1, "rANAreaID-List" },
  {   2, "choice-extension" },
  { 0, NULL }
};

static const per_choice_t RANPagingAreaChoice_choice[] = {
  {   0, &hf_xnap_cell_List      , ASN1_NO_EXTENSIONS     , dissect_xnap_NG_RAN_Cell_Identity_ListinRANPagingArea },
  {   1, &hf_xnap_rANAreaID_List , ASN1_NO_EXTENSIONS     , dissect_xnap_RANAreaID_List },
  {   2, &hf_xnap_choice_extension, ASN1_NO_EXTENSIONS     , dissect_xnap_ProtocolIE_Single_Container },
  { 0, NULL, 0, NULL }
};

static int
dissect_xnap_RANPagingAreaChoice(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_xnap_RANPagingAreaChoice, RANPagingAreaChoice_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t RANPagingArea_sequence[] = {
  { &hf_xnap_pLMN_Identity  , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_xnap_PLMN_Identity },
  { &hf_xnap_rANPagingAreaChoice, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_xnap_RANPagingAreaChoice },
  { &hf_xnap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_xnap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_xnap_RANPagingArea(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_xnap_RANPagingArea, RANPagingArea_sequence);

  return offset;
}


static const value_string xnap_RANPagingFailure_vals[] = {
  {   0, "true" },
  { 0, NULL }
};


static int
dissect_xnap_RANPagingFailure(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     1, NULL, TRUE, 0, NULL);

  return offset;
}


static const per_sequence_t ResetRequestTypeInfo_Full_sequence[] = {
  { &hf_xnap_iE_Extension   , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_xnap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_xnap_ResetRequestTypeInfo_Full(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_xnap_ResetRequestTypeInfo_Full, ResetRequestTypeInfo_Full_sequence);

  return offset;
}


static const per_sequence_t ResetRequestPartialReleaseItem_sequence[] = {
  { &hf_xnap_ng_ran_node1UEXnAPID, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_xnap_NG_RANnodeUEXnAPID },
  { &hf_xnap_ng_ran_node2UEXnAPID, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_xnap_NG_RANnodeUEXnAPID },
  { &hf_xnap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_xnap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_xnap_ResetRequestPartialReleaseItem(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_xnap_ResetRequestPartialReleaseItem, ResetRequestPartialReleaseItem_sequence);

  return offset;
}


static const per_sequence_t ResetRequestPartialReleaseList_sequence_of[1] = {
  { &hf_xnap_ResetRequestPartialReleaseList_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_xnap_ResetRequestPartialReleaseItem },
};

static int
dissect_xnap_ResetRequestPartialReleaseList(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_xnap_ResetRequestPartialReleaseList, ResetRequestPartialReleaseList_sequence_of,
                                                  1, maxnoofUEContexts, FALSE);

  return offset;
}


static const per_sequence_t ResetRequestTypeInfo_Partial_sequence[] = {
  { &hf_xnap_ue_contexts_ToBeReleasedList, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_xnap_ResetRequestPartialReleaseList },
  { &hf_xnap_iE_Extension   , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_xnap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_xnap_ResetRequestTypeInfo_Partial(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_xnap_ResetRequestTypeInfo_Partial, ResetRequestTypeInfo_Partial_sequence);

  return offset;
}


static const value_string xnap_ResetRequestTypeInfo_vals[] = {
  {   0, "fullReset" },
  {   1, "partialReset" },
  {   2, "choice-extension" },
  { 0, NULL }
};

static const per_choice_t ResetRequestTypeInfo_choice[] = {
  {   0, &hf_xnap_fullReset      , ASN1_NO_EXTENSIONS     , dissect_xnap_ResetRequestTypeInfo_Full },
  {   1, &hf_xnap_partialReset   , ASN1_NO_EXTENSIONS     , dissect_xnap_ResetRequestTypeInfo_Partial },
  {   2, &hf_xnap_choice_extension, ASN1_NO_EXTENSIONS     , dissect_xnap_ProtocolIE_Single_Container },
  { 0, NULL, 0, NULL }
};

static int
dissect_xnap_ResetRequestTypeInfo(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_xnap_ResetRequestTypeInfo, ResetRequestTypeInfo_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t ResetResponseTypeInfo_Full_sequence[] = {
  { &hf_xnap_iE_Extension   , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_xnap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_xnap_ResetResponseTypeInfo_Full(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_xnap_ResetResponseTypeInfo_Full, ResetResponseTypeInfo_Full_sequence);

  return offset;
}


static const per_sequence_t ResetResponsePartialReleaseItem_sequence[] = {
  { &hf_xnap_ng_ran_node1UEXnAPID, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_xnap_NG_RANnodeUEXnAPID },
  { &hf_xnap_ng_ran_node2UEXnAPID, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_xnap_NG_RANnodeUEXnAPID },
  { &hf_xnap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_xnap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_xnap_ResetResponsePartialReleaseItem(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_xnap_ResetResponsePartialReleaseItem, ResetResponsePartialReleaseItem_sequence);

  return offset;
}


static const per_sequence_t ResetResponsePartialReleaseList_sequence_of[1] = {
  { &hf_xnap_ResetResponsePartialReleaseList_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_xnap_ResetResponsePartialReleaseItem },
};

static int
dissect_xnap_ResetResponsePartialReleaseList(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_xnap_ResetResponsePartialReleaseList, ResetResponsePartialReleaseList_sequence_of,
                                                  1, maxnoofUEContexts, FALSE);

  return offset;
}


static const per_sequence_t ResetResponseTypeInfo_Partial_sequence[] = {
  { &hf_xnap_ue_contexts_AdmittedToBeReleasedList, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_xnap_ResetResponsePartialReleaseList },
  { &hf_xnap_iE_Extension   , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_xnap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_xnap_ResetResponseTypeInfo_Partial(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_xnap_ResetResponseTypeInfo_Partial, ResetResponseTypeInfo_Partial_sequence);

  return offset;
}


static const value_string xnap_ResetResponseTypeInfo_vals[] = {
  {   0, "fullReset" },
  {   1, "partialReset" },
  {   2, "choice-extension" },
  { 0, NULL }
};

static const per_choice_t ResetResponseTypeInfo_choice[] = {
  {   0, &hf_xnap_fullReset_01   , ASN1_NO_EXTENSIONS     , dissect_xnap_ResetResponseTypeInfo_Full },
  {   1, &hf_xnap_partialReset_01, ASN1_NO_EXTENSIONS     , dissect_xnap_ResetResponseTypeInfo_Partial },
  {   2, &hf_xnap_choice_extension, ASN1_NO_EXTENSIONS     , dissect_xnap_ProtocolIE_Single_Container },
  { 0, NULL, 0, NULL }
};

static int
dissect_xnap_ResetResponseTypeInfo(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_xnap_ResetResponseTypeInfo, ResetResponseTypeInfo_choice,
                                 NULL);

  return offset;
}



static int
dissect_xnap_RFSP_Index(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            1U, 256U, NULL, FALSE);

  return offset;
}


static const value_string xnap_RRCConfigIndication_vals[] = {
  {   0, "full-config" },
  {   1, "delta-config" },
  { 0, NULL }
};


static int
dissect_xnap_RRCConfigIndication(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     2, NULL, TRUE, 0, NULL);

  return offset;
}


static const value_string xnap_RRCResumeCause_vals[] = {
  {   0, "rna-Update" },
  { 0, NULL }
};


static int
dissect_xnap_RRCResumeCause(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     1, NULL, TRUE, 0, NULL);

  return offset;
}


static const per_sequence_t SecondarydataForwardingInfoFromTarget_Item_sequence[] = {
  { &hf_xnap_secondarydataForwardingInfoFromTarget, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_xnap_DataForwardingInfoFromTargetNGRANnode },
  { &hf_xnap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_xnap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_xnap_SecondarydataForwardingInfoFromTarget_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_xnap_SecondarydataForwardingInfoFromTarget_Item, SecondarydataForwardingInfoFromTarget_Item_sequence);

  return offset;
}


static const per_sequence_t SecondarydataForwardingInfoFromTarget_List_sequence_of[1] = {
  { &hf_xnap_SecondarydataForwardingInfoFromTarget_List_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_xnap_SecondarydataForwardingInfoFromTarget_Item },
};

static int
dissect_xnap_SecondarydataForwardingInfoFromTarget_List(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_xnap_SecondarydataForwardingInfoFromTarget_List, SecondarydataForwardingInfoFromTarget_List_sequence_of,
                                                  1, maxnoofMultiConnectivityMinusOne, FALSE);

  return offset;
}


static const value_string xnap_SCGConfigurationQuery_vals[] = {
  {   0, "true" },
  { 0, NULL }
};


static int
dissect_xnap_SCGConfigurationQuery(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     1, NULL, TRUE, 0, NULL);

  return offset;
}


static const per_sequence_t ServedCellInformation_E_UTRA_perBPLMN_sequence[] = {
  { &hf_xnap_plmn_id        , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_xnap_PLMN_Identity },
  { &hf_xnap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_xnap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_xnap_ServedCellInformation_E_UTRA_perBPLMN(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_xnap_ServedCellInformation_E_UTRA_perBPLMN, ServedCellInformation_E_UTRA_perBPLMN_sequence);

  return offset;
}


static const per_sequence_t SEQUENCE_SIZE_1_maxnoofBPLMNs_OF_ServedCellInformation_E_UTRA_perBPLMN_sequence_of[1] = {
  { &hf_xnap_broadcastPLMNs_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_xnap_ServedCellInformation_E_UTRA_perBPLMN },
};

static int
dissect_xnap_SEQUENCE_SIZE_1_maxnoofBPLMNs_OF_ServedCellInformation_E_UTRA_perBPLMN(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_xnap_SEQUENCE_SIZE_1_maxnoofBPLMNs_OF_ServedCellInformation_E_UTRA_perBPLMN, SEQUENCE_SIZE_1_maxnoofBPLMNs_OF_ServedCellInformation_E_UTRA_perBPLMN_sequence_of,
                                                  1, maxnoofBPLMNs, FALSE);

  return offset;
}


static const per_sequence_t ServedCellInformation_E_UTRA_FDDInfo_sequence[] = {
  { &hf_xnap_ul_earfcn      , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_xnap_E_UTRAARFCN },
  { &hf_xnap_dl_earfcn      , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_xnap_E_UTRAARFCN },
  { &hf_xnap_ul_e_utraTxBW  , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_xnap_E_UTRATransmissionBandwidth },
  { &hf_xnap_dl_e_utraTxBW  , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_xnap_E_UTRATransmissionBandwidth },
  { &hf_xnap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_xnap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_xnap_ServedCellInformation_E_UTRA_FDDInfo(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_xnap_ServedCellInformation_E_UTRA_FDDInfo, ServedCellInformation_E_UTRA_FDDInfo_sequence);

  return offset;
}


static const value_string xnap_T_subframeAssignmnet_vals[] = {
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
dissect_xnap_T_subframeAssignmnet(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     7, NULL, TRUE, 0, NULL);

  return offset;
}


static const value_string xnap_SpecialSubframePatterns_E_UTRA_vals[] = {
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
dissect_xnap_SpecialSubframePatterns_E_UTRA(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     11, NULL, TRUE, 0, NULL);

  return offset;
}


static const per_sequence_t SpecialSubframeInfo_E_UTRA_sequence[] = {
  { &hf_xnap_specialSubframePattern, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_xnap_SpecialSubframePatterns_E_UTRA },
  { &hf_xnap_cyclicPrefixDL , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_xnap_CyclicPrefix_E_UTRA_DL },
  { &hf_xnap_cyclicPrefixUL , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_xnap_CyclicPrefix_E_UTRA_UL },
  { &hf_xnap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_xnap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_xnap_SpecialSubframeInfo_E_UTRA(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_xnap_SpecialSubframeInfo_E_UTRA, SpecialSubframeInfo_E_UTRA_sequence);

  return offset;
}


static const per_sequence_t ServedCellInformation_E_UTRA_TDDInfo_sequence[] = {
  { &hf_xnap_earfcn         , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_xnap_E_UTRAARFCN },
  { &hf_xnap_e_utraTxBW     , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_xnap_E_UTRATransmissionBandwidth },
  { &hf_xnap_subframeAssignmnet, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_xnap_T_subframeAssignmnet },
  { &hf_xnap_specialSubframeInfo, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_xnap_SpecialSubframeInfo_E_UTRA },
  { &hf_xnap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_xnap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_xnap_ServedCellInformation_E_UTRA_TDDInfo(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_xnap_ServedCellInformation_E_UTRA_TDDInfo, ServedCellInformation_E_UTRA_TDDInfo_sequence);

  return offset;
}


static const value_string xnap_ServedCellInformation_E_UTRA_ModeInfo_vals[] = {
  {   0, "fdd" },
  {   1, "tdd" },
  {   2, "choice-extension" },
  { 0, NULL }
};

static const per_choice_t ServedCellInformation_E_UTRA_ModeInfo_choice[] = {
  {   0, &hf_xnap_fdd_01         , ASN1_NO_EXTENSIONS     , dissect_xnap_ServedCellInformation_E_UTRA_FDDInfo },
  {   1, &hf_xnap_tdd_01         , ASN1_NO_EXTENSIONS     , dissect_xnap_ServedCellInformation_E_UTRA_TDDInfo },
  {   2, &hf_xnap_choice_extension, ASN1_NO_EXTENSIONS     , dissect_xnap_ProtocolIE_Single_Container },
  { 0, NULL, 0, NULL }
};

static int
dissect_xnap_ServedCellInformation_E_UTRA_ModeInfo(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_xnap_ServedCellInformation_E_UTRA_ModeInfo, ServedCellInformation_E_UTRA_ModeInfo_choice,
                                 NULL);

  return offset;
}


static const value_string xnap_T_freqBandIndicatorPriority_vals[] = {
  {   0, "not-broadcast" },
  {   1, "broadcast" },
  { 0, NULL }
};


static int
dissect_xnap_T_freqBandIndicatorPriority(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     2, NULL, TRUE, 0, NULL);

  return offset;
}


static const value_string xnap_T_bandwidthReducedSI_vals[] = {
  {   0, "scheduled" },
  { 0, NULL }
};


static int
dissect_xnap_T_bandwidthReducedSI(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     1, NULL, TRUE, 0, NULL);

  return offset;
}


static const per_sequence_t ServedCellInformation_E_UTRA_sequence[] = {
  { &hf_xnap_e_utra_pci     , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_xnap_E_UTRAPCI },
  { &hf_xnap_e_utra_cgi     , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_xnap_E_UTRA_CGI },
  { &hf_xnap_tac            , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_xnap_TAC },
  { &hf_xnap_ranac          , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_xnap_RANAC },
  { &hf_xnap_broadcastPLMNs_02, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_xnap_SEQUENCE_SIZE_1_maxnoofBPLMNs_OF_ServedCellInformation_E_UTRA_perBPLMN },
  { &hf_xnap_e_utra_mode_info, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_xnap_ServedCellInformation_E_UTRA_ModeInfo },
  { &hf_xnap_numberofAntennaPorts, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_xnap_NumberOfAntennaPorts_E_UTRA },
  { &hf_xnap_prach_configuration, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_xnap_E_UTRAPRACHConfiguration },
  { &hf_xnap_mBSFNsubframeInfo, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_xnap_MBSFNSubframeInfo_E_UTRA },
  { &hf_xnap_multibandInfo  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_xnap_E_UTRAMultibandInfoList },
  { &hf_xnap_freqBandIndicatorPriority, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_xnap_T_freqBandIndicatorPriority },
  { &hf_xnap_bandwidthReducedSI, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_xnap_T_bandwidthReducedSI },
  { &hf_xnap_protectedE_UTRAResourceIndication, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_xnap_ProtectedE_UTRAResourceIndication },
  { &hf_xnap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_xnap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_xnap_ServedCellInformation_E_UTRA(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_xnap_ServedCellInformation_E_UTRA, ServedCellInformation_E_UTRA_sequence);

  return offset;
}


static const per_sequence_t ServedCells_E_UTRA_Item_sequence[] = {
  { &hf_xnap_served_cell_info_E_UTRA, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_xnap_ServedCellInformation_E_UTRA },
  { &hf_xnap_neighbour_info_NR, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_xnap_NeighbourInformation_NR },
  { &hf_xnap_neighbour_info_E_UTRA, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_xnap_NeighbourInformation_E_UTRA },
  { &hf_xnap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_xnap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_xnap_ServedCells_E_UTRA_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_xnap_ServedCells_E_UTRA_Item, ServedCells_E_UTRA_Item_sequence);

  return offset;
}


static const per_sequence_t ServedCells_E_UTRA_sequence_of[1] = {
  { &hf_xnap_ServedCells_E_UTRA_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_xnap_ServedCells_E_UTRA_Item },
};

static int
dissect_xnap_ServedCells_E_UTRA(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_xnap_ServedCells_E_UTRA, ServedCells_E_UTRA_sequence_of,
                                                  1, maxnoofCellsinNG_RANnode, FALSE);

  return offset;
}


static const value_string xnap_T_deactivation_indication_vals[] = {
  {   0, "deactivated" },
  { 0, NULL }
};


static int
dissect_xnap_T_deactivation_indication(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     1, NULL, TRUE, 0, NULL);

  return offset;
}


static const per_sequence_t ServedCells_ToModify_E_UTRA_Item_sequence[] = {
  { &hf_xnap_old_ECGI       , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_xnap_E_UTRA_CGI },
  { &hf_xnap_served_cell_info_E_UTRA, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_xnap_ServedCellInformation_E_UTRA },
  { &hf_xnap_neighbour_info_NR, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_xnap_NeighbourInformation_NR },
  { &hf_xnap_neighbour_info_E_UTRA, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_xnap_NeighbourInformation_E_UTRA },
  { &hf_xnap_deactivation_indication, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_xnap_T_deactivation_indication },
  { &hf_xnap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_xnap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_xnap_ServedCells_ToModify_E_UTRA_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_xnap_ServedCells_ToModify_E_UTRA_Item, ServedCells_ToModify_E_UTRA_Item_sequence);

  return offset;
}


static const per_sequence_t ServedCells_ToModify_E_UTRA_sequence_of[1] = {
  { &hf_xnap_ServedCells_ToModify_E_UTRA_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_xnap_ServedCells_ToModify_E_UTRA_Item },
};

static int
dissect_xnap_ServedCells_ToModify_E_UTRA(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_xnap_ServedCells_ToModify_E_UTRA, ServedCells_ToModify_E_UTRA_sequence_of,
                                                  1, maxnoofCellsinNG_RANnode, FALSE);

  return offset;
}


static const per_sequence_t SEQUENCE_SIZE_1_maxnoofCellsinNG_RANnode_OF_E_UTRA_CGI_sequence_of[1] = {
  { &hf_xnap_served_Cells_ToDelete_E_UTRA_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_xnap_E_UTRA_CGI },
};

static int
dissect_xnap_SEQUENCE_SIZE_1_maxnoofCellsinNG_RANnode_OF_E_UTRA_CGI(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_xnap_SEQUENCE_SIZE_1_maxnoofCellsinNG_RANnode_OF_E_UTRA_CGI, SEQUENCE_SIZE_1_maxnoofCellsinNG_RANnode_OF_E_UTRA_CGI_sequence_of,
                                                  1, maxnoofCellsinNG_RANnode, FALSE);

  return offset;
}


static const per_sequence_t ServedCellsToUpdate_E_UTRA_sequence[] = {
  { &hf_xnap_served_Cells_ToAdd_E_UTRA, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_xnap_ServedCells_E_UTRA },
  { &hf_xnap_served_Cells_ToModify_E_UTRA, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_xnap_ServedCells_ToModify_E_UTRA },
  { &hf_xnap_served_Cells_ToDelete_E_UTRA, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_xnap_SEQUENCE_SIZE_1_maxnoofCellsinNG_RANnode_OF_E_UTRA_CGI },
  { &hf_xnap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_xnap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_xnap_ServedCellsToUpdate_E_UTRA(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_xnap_ServedCellsToUpdate_E_UTRA, ServedCellsToUpdate_E_UTRA_sequence);

  return offset;
}



static int
dissect_xnap_T_measurementTimingConfiguration_01(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 300 "./asn1/xnap/xnap.cnf"
  tvbuff_t *param_tvb = NULL;
  offset = dissect_per_octet_string(tvb, offset, actx, tree, hf_index,
                                       NO_BOUND, NO_BOUND, FALSE, &param_tvb);

  if (param_tvb) {
    proto_tree *subtree = proto_item_add_subtree(actx->created_item, ett_xnap_measurementTimingConfiguration);
    dissect_nr_rrc_MeasurementTimingConfiguration_PDU(param_tvb, actx->pinfo, subtree, NULL);
  }



  return offset;
}


static const per_sequence_t ServedCellInformation_NR_sequence[] = {
  { &hf_xnap_nrPCI          , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_xnap_NRPCI },
  { &hf_xnap_cellID         , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_xnap_NR_CGI },
  { &hf_xnap_tac            , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_xnap_TAC },
  { &hf_xnap_ranac          , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_xnap_RANAC },
  { &hf_xnap_broadcastPLMN  , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_xnap_BroadcastPLMNs },
  { &hf_xnap_nrModeInfo     , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_xnap_NRModeInfo },
  { &hf_xnap_measurementTimingConfiguration_01, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_xnap_T_measurementTimingConfiguration_01 },
  { &hf_xnap_connectivitySupport, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_xnap_Connectivity_Support },
  { &hf_xnap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_xnap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_xnap_ServedCellInformation_NR(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_xnap_ServedCellInformation_NR, ServedCellInformation_NR_sequence);

  return offset;
}


static const per_sequence_t ServedCells_NR_Item_sequence[] = {
  { &hf_xnap_served_cell_info_NR, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_xnap_ServedCellInformation_NR },
  { &hf_xnap_neighbour_info_NR, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_xnap_NeighbourInformation_NR },
  { &hf_xnap_neighbour_info_E_UTRA, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_xnap_NeighbourInformation_E_UTRA },
  { &hf_xnap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_xnap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_xnap_ServedCells_NR_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_xnap_ServedCells_NR_Item, ServedCells_NR_Item_sequence);

  return offset;
}


static const per_sequence_t ServedCells_NR_sequence_of[1] = {
  { &hf_xnap_ServedCells_NR_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_xnap_ServedCells_NR_Item },
};

static int
dissect_xnap_ServedCells_NR(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_xnap_ServedCells_NR, ServedCells_NR_sequence_of,
                                                  1, maxnoofCellsinNG_RANnode, FALSE);

  return offset;
}


static const value_string xnap_T_deactivation_indication_01_vals[] = {
  {   0, "deactivated" },
  { 0, NULL }
};


static int
dissect_xnap_T_deactivation_indication_01(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     1, NULL, TRUE, 0, NULL);

  return offset;
}


static const per_sequence_t ServedCells_ToModify_NR_Item_sequence[] = {
  { &hf_xnap_old_NR_CGI     , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_xnap_NR_CGI },
  { &hf_xnap_served_cell_info_NR, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_xnap_ServedCellInformation_NR },
  { &hf_xnap_neighbour_info_NR, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_xnap_NeighbourInformation_NR },
  { &hf_xnap_neighbour_info_E_UTRA, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_xnap_NeighbourInformation_E_UTRA },
  { &hf_xnap_deactivation_indication_01, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_xnap_T_deactivation_indication_01 },
  { &hf_xnap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_xnap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_xnap_ServedCells_ToModify_NR_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_xnap_ServedCells_ToModify_NR_Item, ServedCells_ToModify_NR_Item_sequence);

  return offset;
}


static const per_sequence_t ServedCells_ToModify_NR_sequence_of[1] = {
  { &hf_xnap_ServedCells_ToModify_NR_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_xnap_ServedCells_ToModify_NR_Item },
};

static int
dissect_xnap_ServedCells_ToModify_NR(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_xnap_ServedCells_ToModify_NR, ServedCells_ToModify_NR_sequence_of,
                                                  1, maxnoofCellsinNG_RANnode, FALSE);

  return offset;
}


static const per_sequence_t ServedCellsToUpdate_NR_sequence[] = {
  { &hf_xnap_served_Cells_ToAdd_NR, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_xnap_ServedCells_NR },
  { &hf_xnap_served_Cells_ToModify_NR, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_xnap_ServedCells_ToModify_NR },
  { &hf_xnap_served_Cells_ToDelete_NR, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_xnap_SEQUENCE_SIZE_1_maxnoofCellsinNG_RANnode_OF_NR_CGI },
  { &hf_xnap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_xnap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_xnap_ServedCellsToUpdate_NR(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_xnap_ServedCellsToUpdate_NR, ServedCellsToUpdate_NR_sequence);

  return offset;
}



static int
dissect_xnap_S_NG_RANnode_SecurityKey(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_bit_string(tvb, offset, actx, tree, hf_index,
                                     256, 256, FALSE, NULL, 0, NULL, NULL);

  return offset;
}


static const value_string xnap_S_NG_RANnode_Addition_Trigger_Ind_vals[] = {
  {   0, "sn-change" },
  {   1, "inter-MN-HO" },
  {   2, "intra-MN-HO" },
  { 0, NULL }
};


static int
dissect_xnap_S_NG_RANnode_Addition_Trigger_Ind(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     3, NULL, TRUE, 0, NULL);

  return offset;
}



static int
dissect_xnap_SpectrumSharingGroupID(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            1U, maxnoofCellsinNG_RANnode, NULL, FALSE);

  return offset;
}


static const value_string xnap_SplitSessionIndicator_vals[] = {
  {   0, "split" },
  { 0, NULL }
};


static int
dissect_xnap_SplitSessionIndicator(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     1, NULL, TRUE, 0, NULL);

  return offset;
}


static const value_string xnap_SplitSRBsTypes_vals[] = {
  {   0, "srb1" },
  {   1, "srb2" },
  {   2, "srb1and2" },
  { 0, NULL }
};


static int
dissect_xnap_SplitSRBsTypes(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     3, NULL, TRUE, 0, NULL);

  return offset;
}


static const per_sequence_t SEQUENCE_SIZE_1_maxnoofsupportedPLMNs_OF_BroadcastPLMNinTAISupport_Item_sequence_of[1] = {
  { &hf_xnap_broadcastPLMNs_item_01, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_xnap_BroadcastPLMNinTAISupport_Item },
};

static int
dissect_xnap_SEQUENCE_SIZE_1_maxnoofsupportedPLMNs_OF_BroadcastPLMNinTAISupport_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_xnap_SEQUENCE_SIZE_1_maxnoofsupportedPLMNs_OF_BroadcastPLMNinTAISupport_Item, SEQUENCE_SIZE_1_maxnoofsupportedPLMNs_OF_BroadcastPLMNinTAISupport_Item_sequence_of,
                                                  1, maxnoofsupportedPLMNs, FALSE);

  return offset;
}


static const per_sequence_t TAISupport_Item_sequence[] = {
  { &hf_xnap_tac            , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_xnap_TAC },
  { &hf_xnap_broadcastPLMNs_03, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_xnap_SEQUENCE_SIZE_1_maxnoofsupportedPLMNs_OF_BroadcastPLMNinTAISupport_Item },
  { &hf_xnap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_xnap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_xnap_TAISupport_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_xnap_TAISupport_Item, TAISupport_Item_sequence);

  return offset;
}


static const per_sequence_t TAISupport_List_sequence_of[1] = {
  { &hf_xnap_TAISupport_List_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_xnap_TAISupport_Item },
};

static int
dissect_xnap_TAISupport_List(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_xnap_TAISupport_List, TAISupport_List_sequence_of,
                                                  1, maxnoofsupportedTACs, FALSE);

  return offset;
}


static const value_string xnap_Target_CGI_vals[] = {
  {   0, "nr" },
  {   1, "e-utra" },
  {   2, "choice-extension" },
  { 0, NULL }
};

static const per_choice_t Target_CGI_choice[] = {
  {   0, &hf_xnap_nr_02          , ASN1_NO_EXTENSIONS     , dissect_xnap_NR_CGI },
  {   1, &hf_xnap_e_utra_02      , ASN1_NO_EXTENSIONS     , dissect_xnap_E_UTRA_CGI },
  {   2, &hf_xnap_choice_extension, ASN1_NO_EXTENSIONS     , dissect_xnap_ProtocolIE_Single_Container },
  { 0, NULL, 0, NULL }
};

static int
dissect_xnap_Target_CGI(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_xnap_Target_CGI, Target_CGI_choice,
                                 NULL);

  return offset;
}


static const value_string xnap_TimeToWait_vals[] = {
  {   0, "v1s" },
  {   1, "v2s" },
  {   2, "v5s" },
  {   3, "v10s" },
  {   4, "v20s" },
  {   5, "v60s" },
  { 0, NULL }
};


static int
dissect_xnap_TimeToWait(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     6, NULL, TRUE, 0, NULL);

  return offset;
}


static const value_string xnap_TNLAssociationUsage_vals[] = {
  {   0, "ue" },
  {   1, "non-ue" },
  {   2, "both" },
  { 0, NULL }
};


static int
dissect_xnap_TNLAssociationUsage(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     3, NULL, TRUE, 0, NULL);

  return offset;
}


static const per_sequence_t TNLA_To_Add_Item_sequence[] = {
  { &hf_xnap_tNLAssociationTransportLayerAddress, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_xnap_CPTransportLayerInformation },
  { &hf_xnap_tNLAssociationUsage, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_xnap_TNLAssociationUsage },
  { &hf_xnap_iE_Extensions  , ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_xnap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_xnap_TNLA_To_Add_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_xnap_TNLA_To_Add_Item, TNLA_To_Add_Item_sequence);

  return offset;
}


static const per_sequence_t TNLA_To_Add_List_sequence_of[1] = {
  { &hf_xnap_TNLA_To_Add_List_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_xnap_TNLA_To_Add_Item },
};

static int
dissect_xnap_TNLA_To_Add_List(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_xnap_TNLA_To_Add_List, TNLA_To_Add_List_sequence_of,
                                                  1, maxnoofTNLAssociations, FALSE);

  return offset;
}


static const per_sequence_t TNLA_To_Update_Item_sequence[] = {
  { &hf_xnap_tNLAssociationTransportLayerAddress, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_xnap_CPTransportLayerInformation },
  { &hf_xnap_tNLAssociationUsage, ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_xnap_TNLAssociationUsage },
  { &hf_xnap_iE_Extensions  , ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_xnap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_xnap_TNLA_To_Update_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_xnap_TNLA_To_Update_Item, TNLA_To_Update_Item_sequence);

  return offset;
}


static const per_sequence_t TNLA_To_Update_List_sequence_of[1] = {
  { &hf_xnap_TNLA_To_Update_List_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_xnap_TNLA_To_Update_Item },
};

static int
dissect_xnap_TNLA_To_Update_List(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_xnap_TNLA_To_Update_List, TNLA_To_Update_List_sequence_of,
                                                  1, maxnoofTNLAssociations, FALSE);

  return offset;
}


static const per_sequence_t TNLA_To_Remove_Item_sequence[] = {
  { &hf_xnap_tNLAssociationTransportLayerAddress, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_xnap_CPTransportLayerInformation },
  { &hf_xnap_iE_Extensions  , ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_xnap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_xnap_TNLA_To_Remove_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_xnap_TNLA_To_Remove_Item, TNLA_To_Remove_Item_sequence);

  return offset;
}


static const per_sequence_t TNLA_To_Remove_List_sequence_of[1] = {
  { &hf_xnap_TNLA_To_Remove_List_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_xnap_TNLA_To_Remove_Item },
};

static int
dissect_xnap_TNLA_To_Remove_List(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_xnap_TNLA_To_Remove_List, TNLA_To_Remove_List_sequence_of,
                                                  1, maxnoofTNLAssociations, FALSE);

  return offset;
}


static const per_sequence_t TNLA_Setup_Item_sequence[] = {
  { &hf_xnap_tNLAssociationTransportLayerAddress, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_xnap_CPTransportLayerInformation },
  { &hf_xnap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_xnap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_xnap_TNLA_Setup_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_xnap_TNLA_Setup_Item, TNLA_Setup_Item_sequence);

  return offset;
}


static const per_sequence_t TNLA_Setup_List_sequence_of[1] = {
  { &hf_xnap_TNLA_Setup_List_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_xnap_TNLA_Setup_Item },
};

static int
dissect_xnap_TNLA_Setup_List(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_xnap_TNLA_Setup_List, TNLA_Setup_List_sequence_of,
                                                  1, maxnoofTNLAssociations, FALSE);

  return offset;
}


static const per_sequence_t TNLA_Failed_To_Setup_Item_sequence[] = {
  { &hf_xnap_tNLAssociationTransportLayerAddress, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_xnap_CPTransportLayerInformation },
  { &hf_xnap_cause          , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_xnap_Cause },
  { &hf_xnap_iE_Extensions  , ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_xnap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_xnap_TNLA_Failed_To_Setup_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_xnap_TNLA_Failed_To_Setup_Item, TNLA_Failed_To_Setup_Item_sequence);

  return offset;
}


static const per_sequence_t TNLA_Failed_To_Setup_List_sequence_of[1] = {
  { &hf_xnap_TNLA_Failed_To_Setup_List_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_xnap_TNLA_Failed_To_Setup_Item },
};

static int
dissect_xnap_TNLA_Failed_To_Setup_List(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_xnap_TNLA_Failed_To_Setup_List, TNLA_Failed_To_Setup_List_sequence_of,
                                                  1, maxnoofTNLAssociations, FALSE);

  return offset;
}



static int
dissect_xnap_T_ng_ran_TraceID(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 354 "./asn1/xnap/xnap.cnf"
  tvbuff_t *parameter_tvb;
  proto_tree *subtree = NULL;
  offset = dissect_per_octet_string(tvb, offset, actx, tree, hf_index,
                                       8, 8, FALSE, &parameter_tvb);

  if (!parameter_tvb)
    return offset;
  subtree = proto_item_add_subtree(actx->created_item, ett_xnap_ng_ran_TraceID);
  dissect_e212_mcc_mnc(parameter_tvb, actx->pinfo, subtree, 0, E212_NONE, FALSE);
  proto_tree_add_item(subtree, hf_xnap_ng_ran_TraceID_TraceID, parameter_tvb, 3, 3, ENC_BIG_ENDIAN);
  proto_tree_add_item(subtree, hf_xnap_ng_ran_TraceID_TraceRecordingSessionReference, parameter_tvb, 6, 2, ENC_BIG_ENDIAN);



  return offset;
}


static int * const T_interfaces_to_trace_bits[] = {
  &hf_xnap_T_interfaces_to_trace_ng_c,
  &hf_xnap_T_interfaces_to_trace_x_nc,
  &hf_xnap_T_interfaces_to_trace_uu,
  &hf_xnap_T_interfaces_to_trace_f1_c,
  &hf_xnap_T_interfaces_to_trace_e1,
  NULL
};

static int
dissect_xnap_T_interfaces_to_trace(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_bit_string(tvb, offset, actx, tree, hf_index,
                                     8, 8, FALSE, T_interfaces_to_trace_bits, 5, NULL, NULL);

  return offset;
}


static const value_string xnap_Trace_Depth_vals[] = {
  {   0, "minimum" },
  {   1, "medium" },
  {   2, "maximum" },
  {   3, "minimumWithoutVendorSpecificExtension" },
  {   4, "mediumWithoutVendorSpecificExtension" },
  {   5, "maximumWithoutVendorSpecificExtension" },
  { 0, NULL }
};


static int
dissect_xnap_Trace_Depth(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     6, NULL, TRUE, 0, NULL);

  return offset;
}


static const per_sequence_t TraceActivation_sequence[] = {
  { &hf_xnap_ng_ran_TraceID , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_xnap_T_ng_ran_TraceID },
  { &hf_xnap_interfaces_to_trace, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_xnap_T_interfaces_to_trace },
  { &hf_xnap_trace_depth    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_xnap_Trace_Depth },
  { &hf_xnap_trace_coll_address, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_xnap_TransportLayerAddress },
  { &hf_xnap_ie_Extension   , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_xnap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_xnap_TraceActivation(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_xnap_TraceActivation, TraceActivation_sequence);

  return offset;
}


static const per_sequence_t UEAggregateMaximumBitRate_sequence[] = {
  { &hf_xnap_dl_UE_AMBR     , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_xnap_BitRate },
  { &hf_xnap_ul_UE_AMBR     , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_xnap_BitRate },
  { &hf_xnap_iE_Extension   , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_xnap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_xnap_UEAggregateMaximumBitRate(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_xnap_UEAggregateMaximumBitRate, UEAggregateMaximumBitRate_sequence);

  return offset;
}


static const value_string xnap_UEContextKeptIndicator_vals[] = {
  {   0, "true" },
  { 0, NULL }
};


static int
dissect_xnap_UEContextKeptIndicator(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     1, NULL, TRUE, 0, NULL);

  return offset;
}


static const per_sequence_t UEContextIDforRRCResume_sequence[] = {
  { &hf_xnap_i_rnti         , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_xnap_I_RNTI },
  { &hf_xnap_allocated_c_rnti, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_xnap_C_RNTI },
  { &hf_xnap_accessPCI      , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_xnap_NG_RAN_CellPCI },
  { &hf_xnap_iE_Extension   , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_xnap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_xnap_UEContextIDforRRCResume(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_xnap_UEContextIDforRRCResume, UEContextIDforRRCResume_sequence);

  return offset;
}


static const per_sequence_t UEContextIDforRRCReestablishment_sequence[] = {
  { &hf_xnap_c_rnti         , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_xnap_C_RNTI },
  { &hf_xnap_failureCellPCI , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_xnap_NG_RAN_CellPCI },
  { &hf_xnap_iE_Extension   , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_xnap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_xnap_UEContextIDforRRCReestablishment(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_xnap_UEContextIDforRRCReestablishment, UEContextIDforRRCReestablishment_sequence);

  return offset;
}


static const value_string xnap_UEContextID_vals[] = {
  {   0, "rRCResume" },
  {   1, "rRRCReestablishment" },
  {   2, "choice-extension" },
  { 0, NULL }
};

static const per_choice_t UEContextID_choice[] = {
  {   0, &hf_xnap_rRCResume      , ASN1_NO_EXTENSIONS     , dissect_xnap_UEContextIDforRRCResume },
  {   1, &hf_xnap_rRRCReestablishment, ASN1_NO_EXTENSIONS     , dissect_xnap_UEContextIDforRRCReestablishment },
  {   2, &hf_xnap_choice_extension, ASN1_NO_EXTENSIONS     , dissect_xnap_ProtocolIE_Single_Container },
  { 0, NULL, 0, NULL }
};

static int
dissect_xnap_UEContextID(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_xnap_UEContextID, UEContextID_choice,
                                 NULL);

  return offset;
}


static int * const T_nr_EncyptionAlgorithms_bits[] = {
  &hf_xnap_T_nr_EncyptionAlgorithms_spare_bit0,
  &hf_xnap_T_nr_EncyptionAlgorithms_nea1_128,
  &hf_xnap_T_nr_EncyptionAlgorithms_nea2_128,
  &hf_xnap_T_nr_EncyptionAlgorithms_nea3_128,
  NULL
};

static int
dissect_xnap_T_nr_EncyptionAlgorithms(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_bit_string(tvb, offset, actx, tree, hf_index,
                                     16, 16, TRUE, T_nr_EncyptionAlgorithms_bits, 4, NULL, NULL);

  return offset;
}


static int * const T_nr_IntegrityProtectionAlgorithms_bits[] = {
  &hf_xnap_T_nr_IntegrityProtectionAlgorithms_spare_bit0,
  &hf_xnap_T_nr_IntegrityProtectionAlgorithms_nia1_128,
  &hf_xnap_T_nr_IntegrityProtectionAlgorithms_nia2_128,
  &hf_xnap_T_nr_IntegrityProtectionAlgorithms_nia3_128,
  NULL
};

static int
dissect_xnap_T_nr_IntegrityProtectionAlgorithms(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_bit_string(tvb, offset, actx, tree, hf_index,
                                     16, 16, TRUE, T_nr_IntegrityProtectionAlgorithms_bits, 4, NULL, NULL);

  return offset;
}


static int * const T_e_utra_EncyptionAlgorithms_bits[] = {
  &hf_xnap_T_e_utra_EncyptionAlgorithms_spare_bit0,
  &hf_xnap_T_e_utra_EncyptionAlgorithms_eea1_128,
  &hf_xnap_T_e_utra_EncyptionAlgorithms_eea2_128,
  &hf_xnap_T_e_utra_EncyptionAlgorithms_eea3_128,
  NULL
};

static int
dissect_xnap_T_e_utra_EncyptionAlgorithms(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_bit_string(tvb, offset, actx, tree, hf_index,
                                     16, 16, TRUE, T_e_utra_EncyptionAlgorithms_bits, 4, NULL, NULL);

  return offset;
}


static int * const T_e_utra_IntegrityProtectionAlgorithms_bits[] = {
  &hf_xnap_T_e_utra_IntegrityProtectionAlgorithms_spare_bit0,
  &hf_xnap_T_e_utra_IntegrityProtectionAlgorithms_eia1_128,
  &hf_xnap_T_e_utra_IntegrityProtectionAlgorithms_eia2_128,
  &hf_xnap_T_e_utra_IntegrityProtectionAlgorithms_eia3_128,
  NULL
};

static int
dissect_xnap_T_e_utra_IntegrityProtectionAlgorithms(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_bit_string(tvb, offset, actx, tree, hf_index,
                                     16, 16, TRUE, T_e_utra_IntegrityProtectionAlgorithms_bits, 4, NULL, NULL);

  return offset;
}


static const per_sequence_t UESecurityCapabilities_sequence[] = {
  { &hf_xnap_nr_EncyptionAlgorithms, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_xnap_T_nr_EncyptionAlgorithms },
  { &hf_xnap_nr_IntegrityProtectionAlgorithms, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_xnap_T_nr_IntegrityProtectionAlgorithms },
  { &hf_xnap_e_utra_EncyptionAlgorithms, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_xnap_T_e_utra_EncyptionAlgorithms },
  { &hf_xnap_e_utra_IntegrityProtectionAlgorithms, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_xnap_T_e_utra_IntegrityProtectionAlgorithms },
  { &hf_xnap_iE_Extension   , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_xnap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_xnap_UESecurityCapabilities(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_xnap_UESecurityCapabilities, UESecurityCapabilities_sequence);

  return offset;
}



static int
dissect_xnap_T_rrc_Context(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 224 "./asn1/xnap/xnap.cnf"
  tvbuff_t *parameter_tvb = NULL;

  offset = dissect_per_octet_string(tvb, offset, actx, tree, hf_index,
                                       NO_BOUND, NO_BOUND, FALSE, &parameter_tvb);

  if (parameter_tvb) {
    proto_tree *subtree;
    GlobalNG_RANNode_ID_enum target_ranmode_id = xnap_get_ranmode_id(&actx->pinfo->dst, actx->pinfo->destport, actx->pinfo);

    subtree = proto_item_add_subtree(actx->created_item, ett_xnap_RRC_Context);
    if ((xnap_dissect_target_ng_ran_container_as == XNAP_NG_RAN_CONTAINER_AUTOMATIC &&
         target_ranmode_id == GlobalNG_RANNode_ID_gNB) &&
        (xnap_dissect_target_ng_ran_container_as == XNAP_NG_RAN_CONTAINER_GNB)) {
      dissect_nr_rrc_HandoverPreparationInformation_PDU(parameter_tvb, actx->pinfo, subtree, NULL);
    } else if ((xnap_dissect_target_ng_ran_container_as == XNAP_NG_RAN_CONTAINER_AUTOMATIC &&
                target_ranmode_id == GlobalNG_RANNode_ID_ng_eNB) &&
               (xnap_dissect_target_ng_ran_container_as == XNAP_NG_RAN_CONTAINER_NG_ENB)) {
      dissect_lte_rrc_HandoverPreparationInformation_PDU(parameter_tvb, actx->pinfo, subtree, NULL);
    }
  }



  return offset;
}


static const per_sequence_t UEContextInfoRetrUECtxtResp_sequence[] = {
  { &hf_xnap_ng_c_UE_signalling_ref, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_xnap_AMF_UE_NGAP_ID },
  { &hf_xnap_signalling_TNL_at_source, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_xnap_CPTransportLayerInformation },
  { &hf_xnap_ueSecurityCapabilities, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_xnap_UESecurityCapabilities },
  { &hf_xnap_securityInformation, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_xnap_AS_SecurityInformation },
  { &hf_xnap_ue_AMBR        , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_xnap_UEAggregateMaximumBitRate },
  { &hf_xnap_pduSessionResourcesToBeSetup_List, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_xnap_PDUSessionResourcesToBeSetup_List },
  { &hf_xnap_rrc_Context    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_xnap_T_rrc_Context },
  { &hf_xnap_mobilityRestrictionList, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_xnap_MobilityRestrictionList },
  { &hf_xnap_indexToRatFrequencySelectionPriority, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_xnap_RFSP_Index },
  { &hf_xnap_iE_Extension   , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_xnap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_xnap_UEContextInfoRetrUECtxtResp(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_xnap_UEContextInfoRetrUECtxtResp, UEContextInfoRetrUECtxtResp_sequence);

  return offset;
}


static const per_sequence_t UEHistoryInformation_sequence_of[1] = {
  { &hf_xnap_UEHistoryInformation_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_xnap_LastVisitedCell_Item },
};

static int
dissect_xnap_UEHistoryInformation(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_xnap_UEHistoryInformation, UEHistoryInformation_sequence_of,
                                                  1, maxnoofCellsinUEHistoryInfo, FALSE);

  return offset;
}


static const value_string xnap_UEIdentityIndexValue_vals[] = {
  {   0, "indexLength10" },
  {   1, "choice-extension" },
  { 0, NULL }
};

static const per_choice_t UEIdentityIndexValue_choice[] = {
  {   0, &hf_xnap_indexLength10  , ASN1_NO_EXTENSIONS     , dissect_xnap_BIT_STRING_SIZE_10 },
  {   1, &hf_xnap_choice_extension, ASN1_NO_EXTENSIONS     , dissect_xnap_ProtocolIE_Single_Container },
  { 0, NULL, 0, NULL }
};

static int
dissect_xnap_UEIdentityIndexValue(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_xnap_UEIdentityIndexValue, UEIdentityIndexValue_choice,
                                 NULL);

  return offset;
}



static int
dissect_xnap_UERadioCapabilityForPagingOfNR(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 434 "./asn1/xnap/xnap.cnf"
  tvbuff_t *parameter_tvb = NULL;

  offset = dissect_per_octet_string(tvb, offset, actx, tree, hf_index,
                                       NO_BOUND, NO_BOUND, FALSE, &parameter_tvb);

  if (parameter_tvb) {
    proto_tree *subtree = proto_item_add_subtree(actx->created_item, ett_xnap_UERadioCapabilityForPagingOfNR);
    dissect_nr_rrc_UERadioPagingInformation_PDU(parameter_tvb, actx->pinfo, subtree, NULL);
  }



  return offset;
}



static int
dissect_xnap_UERadioCapabilityForPagingOfEUTRA(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 443 "./asn1/xnap/xnap.cnf"
  tvbuff_t *parameter_tvb = NULL;

  offset = dissect_per_octet_string(tvb, offset, actx, tree, hf_index,
                                       NO_BOUND, NO_BOUND, FALSE, &parameter_tvb);

  if (parameter_tvb) {
    proto_tree *subtree = proto_item_add_subtree(actx->created_item, ett_xnap_UERadioCapabilityForPagingOfEUTRA);
    dissect_lte_rrc_UERadioPagingInformation_PDU(parameter_tvb, actx->pinfo, subtree, NULL);
  }



  return offset;
}


static const per_sequence_t UERadioCapabilityForPaging_sequence[] = {
  { &hf_xnap_uERadioCapabilityForPagingOfNR, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_xnap_UERadioCapabilityForPagingOfNR },
  { &hf_xnap_uERadioCapabilityForPagingOfEUTRA, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_xnap_UERadioCapabilityForPagingOfEUTRA },
  { &hf_xnap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_xnap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_xnap_UERadioCapabilityForPaging(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_xnap_UERadioCapabilityForPaging, UERadioCapabilityForPaging_sequence);

  return offset;
}


static const value_string xnap_UERANPagingIdentity_vals[] = {
  {   0, "i-RNTI-full" },
  {   1, "choice-extension" },
  { 0, NULL }
};

static const per_choice_t UERANPagingIdentity_choice[] = {
  {   0, &hf_xnap_i_RNTI_full    , ASN1_NO_EXTENSIONS     , dissect_xnap_BIT_STRING_SIZE_40 },
  {   1, &hf_xnap_choice_extension, ASN1_NO_EXTENSIONS     , dissect_xnap_ProtocolIE_Single_Container },
  { 0, NULL, 0, NULL }
};

static int
dissect_xnap_UERANPagingIdentity(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_xnap_UERANPagingIdentity, UERANPagingIdentity_choice,
                                 NULL);

  return offset;
}


static const value_string xnap_ULForwardingProposal_vals[] = {
  {   0, "ul-forwarding-proposed" },
  { 0, NULL }
};


static int
dissect_xnap_ULForwardingProposal(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     1, NULL, TRUE, 0, NULL);

  return offset;
}


static const value_string xnap_UserPlaneTrafficActivityReport_vals[] = {
  {   0, "inactive" },
  {   1, "re-activated" },
  { 0, NULL }
};


static int
dissect_xnap_UserPlaneTrafficActivityReport(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     2, NULL, TRUE, 0, NULL);

  return offset;
}



static int
dissect_xnap_XnBenefitValue(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            1U, 8U, NULL, TRUE);

  return offset;
}


static const per_sequence_t HandoverRequest_sequence[] = {
  { &hf_xnap_protocolIEs    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_xnap_ProtocolIE_Container },
  { NULL, 0, 0, NULL }
};

static int
dissect_xnap_HandoverRequest(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 463 "./asn1/xnap/xnap.cnf"
  col_append_sep_str(actx->pinfo->cinfo, COL_INFO, NULL, "HandoverRequest");

  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_xnap_HandoverRequest, HandoverRequest_sequence);

  return offset;
}



static int
dissect_xnap_T_rrc_Context_01(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 104 "./asn1/xnap/xnap.cnf"
  tvbuff_t *parameter_tvb = NULL;

  offset = dissect_per_octet_string(tvb, offset, actx, tree, hf_index,
                                       NO_BOUND, NO_BOUND, FALSE, &parameter_tvb);

  if (parameter_tvb) {
    proto_tree *subtree;
    GlobalNG_RANNode_ID_enum target_ranmode_id = xnap_get_ranmode_id(&actx->pinfo->dst, actx->pinfo->destport, actx->pinfo);

    subtree = proto_item_add_subtree(actx->created_item, ett_xnap_RRC_Context);
    if ((xnap_dissect_target_ng_ran_container_as == XNAP_NG_RAN_CONTAINER_AUTOMATIC &&
         target_ranmode_id == GlobalNG_RANNode_ID_gNB) ||
        (xnap_dissect_target_ng_ran_container_as == XNAP_NG_RAN_CONTAINER_GNB)) {
      dissect_nr_rrc_HandoverPreparationInformation_PDU(parameter_tvb, actx->pinfo, subtree, NULL);
    } else if ((xnap_dissect_target_ng_ran_container_as == XNAP_NG_RAN_CONTAINER_AUTOMATIC &&
                target_ranmode_id == GlobalNG_RANNode_ID_ng_eNB) ||
               (xnap_dissect_target_ng_ran_container_as == XNAP_NG_RAN_CONTAINER_NG_ENB)) {
      dissect_lte_rrc_HandoverPreparationInformation_PDU(parameter_tvb, actx->pinfo, subtree, NULL);
    }
  }



  return offset;
}


static const per_sequence_t UEContextInfoHORequest_sequence[] = {
  { &hf_xnap_ng_c_UE_reference, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_xnap_AMF_UE_NGAP_ID },
  { &hf_xnap_cp_TNL_info_source, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_xnap_CPTransportLayerInformation },
  { &hf_xnap_ueSecurityCapabilities, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_xnap_UESecurityCapabilities },
  { &hf_xnap_securityInformation, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_xnap_AS_SecurityInformation },
  { &hf_xnap_indexToRatFrequencySelectionPriority, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_xnap_RFSP_Index },
  { &hf_xnap_ue_AMBR        , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_xnap_UEAggregateMaximumBitRate },
  { &hf_xnap_pduSessionResourcesToBeSetup_List, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_xnap_PDUSessionResourcesToBeSetup_List },
  { &hf_xnap_rrc_Context_01 , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_xnap_T_rrc_Context_01 },
  { &hf_xnap_locationReportingInformation, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_xnap_LocationReportingInformation },
  { &hf_xnap_mrl            , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_xnap_MobilityRestrictionList },
  { &hf_xnap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_xnap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_xnap_UEContextInfoHORequest(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_xnap_UEContextInfoHORequest, UEContextInfoHORequest_sequence);

  return offset;
}


static const per_sequence_t UEContextRefAtSN_HORequest_sequence[] = {
  { &hf_xnap_globalNG_RANNode_ID, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_xnap_GlobalNG_RANNode_ID },
  { &hf_xnap_sN_NG_RANnodeUEXnAPID, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_xnap_NG_RANnodeUEXnAPID },
  { &hf_xnap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_xnap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_xnap_UEContextRefAtSN_HORequest(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_xnap_UEContextRefAtSN_HORequest, UEContextRefAtSN_HORequest_sequence);

  return offset;
}


static const per_sequence_t HandoverRequestAcknowledge_sequence[] = {
  { &hf_xnap_protocolIEs    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_xnap_ProtocolIE_Container },
  { NULL, 0, 0, NULL }
};

static int
dissect_xnap_HandoverRequestAcknowledge(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 465 "./asn1/xnap/xnap.cnf"
  col_append_sep_str(actx->pinfo->cinfo, COL_INFO, NULL, "HandoverRequestAcknowledge");

  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_xnap_HandoverRequestAcknowledge, HandoverRequestAcknowledge_sequence);

  return offset;
}



static int
dissect_xnap_Target2SourceNG_RANnodeTranspContainer(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 124 "./asn1/xnap/xnap.cnf"
  tvbuff_t *parameter_tvb = NULL;

  offset = dissect_per_octet_string(tvb, offset, actx, tree, hf_index,
                                       NO_BOUND, NO_BOUND, FALSE, &parameter_tvb);

  if (parameter_tvb) {
    proto_tree *subtree;
    GlobalNG_RANNode_ID_enum source_ranmode_id = xnap_get_ranmode_id(&actx->pinfo->src, actx->pinfo->srcport, actx->pinfo);

    subtree = proto_item_add_subtree(actx->created_item, ett_nxap_container);
    if ((xnap_dissect_target_ng_ran_container_as == XNAP_NG_RAN_CONTAINER_AUTOMATIC &&
         source_ranmode_id == GlobalNG_RANNode_ID_gNB) ||
        (xnap_dissect_target_ng_ran_container_as == XNAP_NG_RAN_CONTAINER_GNB)) {
      dissect_nr_rrc_HandoverCommand_PDU(parameter_tvb, actx->pinfo, subtree, NULL);
    } else if ((xnap_dissect_target_ng_ran_container_as == XNAP_NG_RAN_CONTAINER_AUTOMATIC &&
                source_ranmode_id == GlobalNG_RANNode_ID_ng_eNB) ||
               (xnap_dissect_target_ng_ran_container_as == XNAP_NG_RAN_CONTAINER_NG_ENB)) {
      dissect_lte_rrc_HandoverCommand_PDU(parameter_tvb, actx->pinfo, subtree, NULL);
    }
  }



  return offset;
}


static const per_sequence_t HandoverPreparationFailure_sequence[] = {
  { &hf_xnap_protocolIEs    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_xnap_ProtocolIE_Container },
  { NULL, 0, 0, NULL }
};

static int
dissect_xnap_HandoverPreparationFailure(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 467 "./asn1/xnap/xnap.cnf"
  col_append_sep_str(actx->pinfo->cinfo, COL_INFO, NULL, "HandoverPreparationFailure");

  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_xnap_HandoverPreparationFailure, HandoverPreparationFailure_sequence);

  return offset;
}


static const per_sequence_t SNStatusTransfer_sequence[] = {
  { &hf_xnap_protocolIEs    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_xnap_ProtocolIE_Container },
  { NULL, 0, 0, NULL }
};

static int
dissect_xnap_SNStatusTransfer(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 469 "./asn1/xnap/xnap.cnf"
  col_append_sep_str(actx->pinfo->cinfo, COL_INFO, NULL, "SNStatusTransfer");

  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_xnap_SNStatusTransfer, SNStatusTransfer_sequence);

  return offset;
}


static const per_sequence_t UEContextRelease_sequence[] = {
  { &hf_xnap_protocolIEs    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_xnap_ProtocolIE_Container },
  { NULL, 0, 0, NULL }
};

static int
dissect_xnap_UEContextRelease(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 483 "./asn1/xnap/xnap.cnf"
  col_append_sep_str(actx->pinfo->cinfo, COL_INFO, NULL, "UEContextRelease");

  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_xnap_UEContextRelease, UEContextRelease_sequence);

  return offset;
}


static const per_sequence_t HandoverCancel_sequence[] = {
  { &hf_xnap_protocolIEs    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_xnap_ProtocolIE_Container },
  { NULL, 0, 0, NULL }
};

static int
dissect_xnap_HandoverCancel(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 471 "./asn1/xnap/xnap.cnf"
  col_append_sep_str(actx->pinfo->cinfo, COL_INFO, NULL, "HandoverCancel");

  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_xnap_HandoverCancel, HandoverCancel_sequence);

  return offset;
}


static const per_sequence_t RANPaging_sequence[] = {
  { &hf_xnap_protocolIEs    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_xnap_ProtocolIE_Container },
  { NULL, 0, 0, NULL }
};

static int
dissect_xnap_RANPaging(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 479 "./asn1/xnap/xnap.cnf"
  col_append_sep_str(actx->pinfo->cinfo, COL_INFO, NULL, "RANPaging");

  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_xnap_RANPaging, RANPaging_sequence);

  return offset;
}


static const per_sequence_t RetrieveUEContextRequest_sequence[] = {
  { &hf_xnap_protocolIEs    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_xnap_ProtocolIE_Container },
  { NULL, 0, 0, NULL }
};

static int
dissect_xnap_RetrieveUEContextRequest(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 473 "./asn1/xnap/xnap.cnf"
  col_append_sep_str(actx->pinfo->cinfo, COL_INFO, NULL, "RetrieveUEContextRequest");

  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_xnap_RetrieveUEContextRequest, RetrieveUEContextRequest_sequence);

  return offset;
}


static const per_sequence_t RetrieveUEContextResponse_sequence[] = {
  { &hf_xnap_protocolIEs    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_xnap_ProtocolIE_Container },
  { NULL, 0, 0, NULL }
};

static int
dissect_xnap_RetrieveUEContextResponse(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 475 "./asn1/xnap/xnap.cnf"
  col_append_sep_str(actx->pinfo->cinfo, COL_INFO, NULL, "RetrieveUEContextResponse");

  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_xnap_RetrieveUEContextResponse, RetrieveUEContextResponse_sequence);

  return offset;
}


static const per_sequence_t RetrieveUEContextFailure_sequence[] = {
  { &hf_xnap_protocolIEs    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_xnap_ProtocolIE_Container },
  { NULL, 0, 0, NULL }
};

static int
dissect_xnap_RetrieveUEContextFailure(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 477 "./asn1/xnap/xnap.cnf"
  col_append_sep_str(actx->pinfo->cinfo, COL_INFO, NULL, "RetrieveUEContextFailure");

  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_xnap_RetrieveUEContextFailure, RetrieveUEContextFailure_sequence);

  return offset;
}



static int
dissect_xnap_OldtoNewNG_RANnodeResumeContainer(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_octet_string(tvb, offset, actx, tree, hf_index,
                                       NO_BOUND, NO_BOUND, FALSE, NULL);

  return offset;
}


static const per_sequence_t XnUAddressIndication_sequence[] = {
  { &hf_xnap_protocolIEs    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_xnap_ProtocolIE_Container },
  { NULL, 0, 0, NULL }
};

static int
dissect_xnap_XnUAddressIndication(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 481 "./asn1/xnap/xnap.cnf"
  col_append_sep_str(actx->pinfo->cinfo, COL_INFO, NULL, "XnUAddressIndication");

  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_xnap_XnUAddressIndication, XnUAddressIndication_sequence);

  return offset;
}


static const per_sequence_t SNodeAdditionRequest_sequence[] = {
  { &hf_xnap_protocolIEs    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_xnap_ProtocolIE_Container },
  { NULL, 0, 0, NULL }
};

static int
dissect_xnap_SNodeAdditionRequest(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 485 "./asn1/xnap/xnap.cnf"
  col_append_sep_str(actx->pinfo->cinfo, COL_INFO, NULL, "SNodeAdditionRequest");

  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_xnap_SNodeAdditionRequest, SNodeAdditionRequest_sequence);

  return offset;
}



static int
dissect_xnap_MN_to_SN_Container(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 144 "./asn1/xnap/xnap.cnf"
  tvbuff_t *parameter_tvb = NULL;

  offset = dissect_per_octet_string(tvb, offset, actx, tree, hf_index,
                                       NO_BOUND, NO_BOUND, FALSE, &parameter_tvb);

  if (parameter_tvb) {
    proto_tree *subtree;
    GlobalNG_RANNode_ID_enum target_ranmode_id = xnap_get_ranmode_id(&actx->pinfo->dst, actx->pinfo->destport, actx->pinfo);

    subtree = proto_item_add_subtree(actx->created_item, ett_nxap_container);
    if ((xnap_dissect_target_ng_ran_container_as == XNAP_NG_RAN_CONTAINER_AUTOMATIC &&
         target_ranmode_id == GlobalNG_RANNode_ID_gNB) ||
        (xnap_dissect_target_ng_ran_container_as == XNAP_NG_RAN_CONTAINER_GNB)) {
      dissect_nr_rrc_CG_ConfigInfo_PDU(parameter_tvb, actx->pinfo, subtree, NULL);
    } else if ((xnap_dissect_target_ng_ran_container_as == XNAP_NG_RAN_CONTAINER_AUTOMATIC &&
                target_ranmode_id == GlobalNG_RANNode_ID_ng_eNB) ||
               (xnap_dissect_target_ng_ran_container_as == XNAP_NG_RAN_CONTAINER_NG_ENB)) {
      dissect_lte_rrc_SCG_ConfigInfo_r12_PDU(parameter_tvb, actx->pinfo, subtree, NULL);
    }
  }



  return offset;
}


static const per_sequence_t PDUSessionToBeAddedAddReq_Item_sequence[] = {
  { &hf_xnap_pduSessionId   , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_xnap_PDUSession_ID },
  { &hf_xnap_s_NSSAI        , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_xnap_S_NSSAI },
  { &hf_xnap_sN_PDUSessionAMBR, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_xnap_PDUSessionAggregateMaximumBitRate },
  { &hf_xnap_sn_terminated  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_xnap_PDUSessionResourceSetupInfo_SNterminated },
  { &hf_xnap_mn_terminated  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_xnap_PDUSessionResourceSetupInfo_MNterminated },
  { &hf_xnap_iE_Extension   , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_xnap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_xnap_PDUSessionToBeAddedAddReq_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_xnap_PDUSessionToBeAddedAddReq_Item, PDUSessionToBeAddedAddReq_Item_sequence);

  return offset;
}


static const per_sequence_t PDUSessionToBeAddedAddReq_sequence_of[1] = {
  { &hf_xnap_PDUSessionToBeAddedAddReq_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_xnap_PDUSessionToBeAddedAddReq_Item },
};

static int
dissect_xnap_PDUSessionToBeAddedAddReq(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_xnap_PDUSessionToBeAddedAddReq, PDUSessionToBeAddedAddReq_sequence_of,
                                                  1, maxnoofPDUSessions, FALSE);

  return offset;
}


static const per_sequence_t SNodeAdditionRequestAcknowledge_sequence[] = {
  { &hf_xnap_protocolIEs    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_xnap_ProtocolIE_Container },
  { NULL, 0, 0, NULL }
};

static int
dissect_xnap_SNodeAdditionRequestAcknowledge(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 487 "./asn1/xnap/xnap.cnf"
  col_append_sep_str(actx->pinfo->cinfo, COL_INFO, NULL, "SNodeAdditionRequestAcknowledge");

  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_xnap_SNodeAdditionRequestAcknowledge, SNodeAdditionRequestAcknowledge_sequence);

  return offset;
}



static int
dissect_xnap_SN_to_MN_Container(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 164 "./asn1/xnap/xnap.cnf"
  tvbuff_t *parameter_tvb = NULL;

  offset = dissect_per_octet_string(tvb, offset, actx, tree, hf_index,
                                       NO_BOUND, NO_BOUND, FALSE, &parameter_tvb);

  if (parameter_tvb) {
    proto_tree *subtree;
    GlobalNG_RANNode_ID_enum source_ranmode_id = xnap_get_ranmode_id(&actx->pinfo->src, actx->pinfo->srcport, actx->pinfo);

    subtree = proto_item_add_subtree(actx->created_item, ett_nxap_container);
    if ((xnap_dissect_target_ng_ran_container_as == XNAP_NG_RAN_CONTAINER_AUTOMATIC &&
         source_ranmode_id == GlobalNG_RANNode_ID_gNB) ||
        (xnap_dissect_target_ng_ran_container_as == XNAP_NG_RAN_CONTAINER_GNB)) {
      dissect_nr_rrc_CG_Config_PDU(parameter_tvb, actx->pinfo, subtree, NULL);
    } else if ((xnap_dissect_target_ng_ran_container_as == XNAP_NG_RAN_CONTAINER_AUTOMATIC &&
                source_ranmode_id == GlobalNG_RANNode_ID_ng_eNB) ||
               (xnap_dissect_target_ng_ran_container_as == XNAP_NG_RAN_CONTAINER_NG_ENB)) {
      dissect_lte_rrc_SCG_Config_r12_PDU(parameter_tvb, actx->pinfo, subtree, NULL);
    }
  }



  return offset;
}


static const per_sequence_t PDUSessionAdmittedAddedAddReqAck_Item_sequence[] = {
  { &hf_xnap_pduSessionId   , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_xnap_PDUSession_ID },
  { &hf_xnap_sn_terminated_01, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_xnap_PDUSessionResourceSetupResponseInfo_SNterminated },
  { &hf_xnap_mn_terminated_01, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_xnap_PDUSessionResourceSetupResponseInfo_MNterminated },
  { &hf_xnap_iE_Extension   , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_xnap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_xnap_PDUSessionAdmittedAddedAddReqAck_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_xnap_PDUSessionAdmittedAddedAddReqAck_Item, PDUSessionAdmittedAddedAddReqAck_Item_sequence);

  return offset;
}


static const per_sequence_t PDUSessionAdmittedAddedAddReqAck_sequence_of[1] = {
  { &hf_xnap_PDUSessionAdmittedAddedAddReqAck_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_xnap_PDUSessionAdmittedAddedAddReqAck_Item },
};

static int
dissect_xnap_PDUSessionAdmittedAddedAddReqAck(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_xnap_PDUSessionAdmittedAddedAddReqAck, PDUSessionAdmittedAddedAddReqAck_sequence_of,
                                                  1, maxnoofPDUSessions, FALSE);

  return offset;
}


static const per_sequence_t PDUSessionNotAdmittedAddReqAck_sequence[] = {
  { &hf_xnap_pduSessionResourcesNotAdmitted_SNterminated, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_xnap_PDUSessionResourcesNotAdmitted_List },
  { &hf_xnap_pduSessionResourcesNotAdmitted_MNterminated, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_xnap_PDUSessionResourcesNotAdmitted_List },
  { &hf_xnap_iE_Extension   , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_xnap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_xnap_PDUSessionNotAdmittedAddReqAck(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_xnap_PDUSessionNotAdmittedAddReqAck, PDUSessionNotAdmittedAddReqAck_sequence);

  return offset;
}


static const per_sequence_t SNodeAdditionRequestReject_sequence[] = {
  { &hf_xnap_protocolIEs    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_xnap_ProtocolIE_Container },
  { NULL, 0, 0, NULL }
};

static int
dissect_xnap_SNodeAdditionRequestReject(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 489 "./asn1/xnap/xnap.cnf"
  col_append_sep_str(actx->pinfo->cinfo, COL_INFO, NULL, "SNodeAdditionRequestReject");

  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_xnap_SNodeAdditionRequestReject, SNodeAdditionRequestReject_sequence);

  return offset;
}


static const per_sequence_t SNodeReconfigurationComplete_sequence[] = {
  { &hf_xnap_protocolIEs    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_xnap_ProtocolIE_Container },
  { NULL, 0, 0, NULL }
};

static int
dissect_xnap_SNodeReconfigurationComplete(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 491 "./asn1/xnap/xnap.cnf"
  col_append_sep_str(actx->pinfo->cinfo, COL_INFO, NULL, "SNodeReconfigurationComplete");

  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_xnap_SNodeReconfigurationComplete, SNodeReconfigurationComplete_sequence);

  return offset;
}



static int
dissect_xnap_T_m_NG_RANNode_to_S_NG_RANNode_Container(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 184 "./asn1/xnap/xnap.cnf"
  tvbuff_t *parameter_tvb = NULL;

  offset = dissect_per_octet_string(tvb, offset, actx, tree, hf_index,
                                       NO_BOUND, NO_BOUND, FALSE, &parameter_tvb);

  if (parameter_tvb) {
    proto_tree *subtree;
    GlobalNG_RANNode_ID_enum target_ranmode_id = xnap_get_ranmode_id(&actx->pinfo->dst, actx->pinfo->destport, actx->pinfo);

    subtree = proto_item_add_subtree(actx->created_item, ett_nxap_container);
    if ((xnap_dissect_target_ng_ran_container_as == XNAP_NG_RAN_CONTAINER_AUTOMATIC &&
         target_ranmode_id == GlobalNG_RANNode_ID_gNB) ||
        (xnap_dissect_target_ng_ran_container_as == XNAP_NG_RAN_CONTAINER_GNB)) {
      dissect_nr_rrc_RRCReconfigurationComplete_PDU(parameter_tvb, actx->pinfo, subtree, NULL);
    } else if ((xnap_dissect_target_ng_ran_container_as == XNAP_NG_RAN_CONTAINER_AUTOMATIC &&
                target_ranmode_id == GlobalNG_RANNode_ID_ng_eNB) ||
               (xnap_dissect_target_ng_ran_container_as == XNAP_NG_RAN_CONTAINER_NG_ENB)) {
      dissect_lte_rrc_RRCConnectionReconfigurationComplete_PDU(parameter_tvb, actx->pinfo, subtree, NULL);
    }
  }



  return offset;
}


static const per_sequence_t Configuration_successfully_applied_sequence[] = {
  { &hf_xnap_m_NG_RANNode_to_S_NG_RANNode_Container, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_xnap_T_m_NG_RANNode_to_S_NG_RANNode_Container },
  { &hf_xnap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_xnap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_xnap_Configuration_successfully_applied(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_xnap_Configuration_successfully_applied, Configuration_successfully_applied_sequence);

  return offset;
}



static int
dissect_xnap_T_m_NG_RANNode_to_S_NG_RANNode_Container_01(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 204 "./asn1/xnap/xnap.cnf"
  tvbuff_t *parameter_tvb = NULL;

  offset = dissect_per_octet_string(tvb, offset, actx, tree, hf_index,
                                       NO_BOUND, NO_BOUND, FALSE, &parameter_tvb);

  if (parameter_tvb) {
    proto_tree *subtree;
    GlobalNG_RANNode_ID_enum target_ranmode_id = xnap_get_ranmode_id(&actx->pinfo->dst, actx->pinfo->destport, actx->pinfo);

    subtree = proto_item_add_subtree(actx->created_item, ett_nxap_container);
    if ((xnap_dissect_target_ng_ran_container_as == XNAP_NG_RAN_CONTAINER_AUTOMATIC &&
         target_ranmode_id == GlobalNG_RANNode_ID_gNB) ||
        (xnap_dissect_target_ng_ran_container_as == XNAP_NG_RAN_CONTAINER_GNB)) {
      dissect_nr_rrc_CG_ConfigInfo_PDU(parameter_tvb, actx->pinfo, subtree, NULL);
    } else if ((xnap_dissect_target_ng_ran_container_as == XNAP_NG_RAN_CONTAINER_AUTOMATIC &&
                target_ranmode_id == GlobalNG_RANNode_ID_ng_eNB) ||
               (xnap_dissect_target_ng_ran_container_as == XNAP_NG_RAN_CONTAINER_NG_ENB)) {
      dissect_lte_rrc_SCG_ConfigInfo_r12_PDU(parameter_tvb, actx->pinfo, subtree, NULL);
    }
  }



  return offset;
}


static const per_sequence_t Configuration_rejected_by_M_NG_RANNode_sequence[] = {
  { &hf_xnap_cause          , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_xnap_Cause },
  { &hf_xnap_m_NG_RANNode_to_S_NG_RANNode_Container_01, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_xnap_T_m_NG_RANNode_to_S_NG_RANNode_Container_01 },
  { &hf_xnap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_xnap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_xnap_Configuration_rejected_by_M_NG_RANNode(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_xnap_Configuration_rejected_by_M_NG_RANNode, Configuration_rejected_by_M_NG_RANNode_sequence);

  return offset;
}


static const value_string xnap_ResponseType_ReconfComplete_vals[] = {
  {   0, "configuration-successfully-applied" },
  {   1, "configuration-rejected-by-M-NG-RANNode" },
  {   2, "choice-extension" },
  { 0, NULL }
};

static const per_choice_t ResponseType_ReconfComplete_choice[] = {
  {   0, &hf_xnap_configuration_successfully_applied, ASN1_NO_EXTENSIONS     , dissect_xnap_Configuration_successfully_applied },
  {   1, &hf_xnap_configuration_rejected_by_M_NG_RANNode, ASN1_NO_EXTENSIONS     , dissect_xnap_Configuration_rejected_by_M_NG_RANNode },
  {   2, &hf_xnap_choice_extension, ASN1_NO_EXTENSIONS     , dissect_xnap_ProtocolIE_Single_Container },
  { 0, NULL, 0, NULL }
};

static int
dissect_xnap_ResponseType_ReconfComplete(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_xnap_ResponseType_ReconfComplete, ResponseType_ReconfComplete_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t ResponseInfo_ReconfCompl_sequence[] = {
  { &hf_xnap_responseType_ReconfComplete, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_xnap_ResponseType_ReconfComplete },
  { &hf_xnap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_xnap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_xnap_ResponseInfo_ReconfCompl(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_xnap_ResponseInfo_ReconfCompl, ResponseInfo_ReconfCompl_sequence);

  return offset;
}


static const per_sequence_t SNodeModificationRequest_sequence[] = {
  { &hf_xnap_protocolIEs    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_xnap_ProtocolIE_Container },
  { NULL, 0, 0, NULL }
};

static int
dissect_xnap_SNodeModificationRequest(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 493 "./asn1/xnap/xnap.cnf"
  col_append_sep_str(actx->pinfo->cinfo, COL_INFO, NULL, "SNodeModificationRequest");

  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_xnap_SNodeModificationRequest, SNodeModificationRequest_sequence);

  return offset;
}


static const per_sequence_t PDUSessionsToBeAdded_SNModRequest_Item_sequence[] = {
  { &hf_xnap_pduSessionId   , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_xnap_PDUSession_ID },
  { &hf_xnap_s_NSSAI        , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_xnap_S_NSSAI },
  { &hf_xnap_sN_PDUSessionAMBR, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_xnap_PDUSessionAggregateMaximumBitRate },
  { &hf_xnap_sn_terminated  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_xnap_PDUSessionResourceSetupInfo_SNterminated },
  { &hf_xnap_mn_terminated  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_xnap_PDUSessionResourceSetupInfo_MNterminated },
  { &hf_xnap_iE_Extension   , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_xnap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_xnap_PDUSessionsToBeAdded_SNModRequest_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_xnap_PDUSessionsToBeAdded_SNModRequest_Item, PDUSessionsToBeAdded_SNModRequest_Item_sequence);

  return offset;
}


static const per_sequence_t PDUSessionsToBeAdded_SNModRequest_List_sequence_of[1] = {
  { &hf_xnap_PDUSessionsToBeAdded_SNModRequest_List_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_xnap_PDUSessionsToBeAdded_SNModRequest_Item },
};

static int
dissect_xnap_PDUSessionsToBeAdded_SNModRequest_List(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_xnap_PDUSessionsToBeAdded_SNModRequest_List, PDUSessionsToBeAdded_SNModRequest_List_sequence_of,
                                                  1, maxnoofPDUSessions, FALSE);

  return offset;
}


static const per_sequence_t PDUSessionsToBeModified_SNModRequest_Item_sequence[] = {
  { &hf_xnap_pduSessionId   , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_xnap_PDUSession_ID },
  { &hf_xnap_sN_PDUSessionAMBR, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_xnap_PDUSessionAggregateMaximumBitRate },
  { &hf_xnap_sn_terminated_02, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_xnap_PDUSessionResourceModificationInfo_SNterminated },
  { &hf_xnap_mn_terminated_02, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_xnap_PDUSessionResourceModificationInfo_MNterminated },
  { &hf_xnap_iE_Extension   , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_xnap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_xnap_PDUSessionsToBeModified_SNModRequest_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_xnap_PDUSessionsToBeModified_SNModRequest_Item, PDUSessionsToBeModified_SNModRequest_Item_sequence);

  return offset;
}


static const per_sequence_t PDUSessionsToBeModified_SNModRequest_List_sequence_of[1] = {
  { &hf_xnap_PDUSessionsToBeModified_SNModRequest_List_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_xnap_PDUSessionsToBeModified_SNModRequest_Item },
};

static int
dissect_xnap_PDUSessionsToBeModified_SNModRequest_List(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_xnap_PDUSessionsToBeModified_SNModRequest_List, PDUSessionsToBeModified_SNModRequest_List_sequence_of,
                                                  1, maxnoofPDUSessions, FALSE);

  return offset;
}


static const per_sequence_t PDUSessionsToBeReleased_SNModRequest_List_sequence[] = {
  { &hf_xnap_pdu_session_list, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_xnap_PDUSession_List_withCause },
  { &hf_xnap_iE_Extension   , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_xnap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_xnap_PDUSessionsToBeReleased_SNModRequest_List(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_xnap_PDUSessionsToBeReleased_SNModRequest_List, PDUSessionsToBeReleased_SNModRequest_List_sequence);

  return offset;
}


static const per_sequence_t UEContextInfo_SNModRequest_sequence[] = {
  { &hf_xnap_ueSecurityCapabilities, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_xnap_UESecurityCapabilities },
  { &hf_xnap_s_ng_RANnode_SecurityKey, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_xnap_S_NG_RANnode_SecurityKey },
  { &hf_xnap_s_ng_RANnodeUE_AMBR, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_xnap_UEAggregateMaximumBitRate },
  { &hf_xnap_indexToRatFrequencySelectionPriority, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_xnap_RFSP_Index },
  { &hf_xnap_lowerLayerPresenceStatusChange, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_xnap_LowerLayerPresenceStatusChange },
  { &hf_xnap_pduSessionResourceToBeAdded, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_xnap_PDUSessionsToBeAdded_SNModRequest_List },
  { &hf_xnap_pduSessionResourceToBeModified, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_xnap_PDUSessionsToBeModified_SNModRequest_List },
  { &hf_xnap_pduSessionResourceToBeReleased, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_xnap_PDUSessionsToBeReleased_SNModRequest_List },
  { &hf_xnap_iE_Extension   , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_xnap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_xnap_UEContextInfo_SNModRequest(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_xnap_UEContextInfo_SNModRequest, UEContextInfo_SNModRequest_sequence);

  return offset;
}


static const per_sequence_t SNodeModificationRequestAcknowledge_sequence[] = {
  { &hf_xnap_protocolIEs    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_xnap_ProtocolIE_Container },
  { NULL, 0, 0, NULL }
};

static int
dissect_xnap_SNodeModificationRequestAcknowledge(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 495 "./asn1/xnap/xnap.cnf"
  col_append_sep_str(actx->pinfo->cinfo, COL_INFO, NULL, "SNodeModificationRequestAcknowledge");

  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_xnap_SNodeModificationRequestAcknowledge, SNodeModificationRequestAcknowledge_sequence);

  return offset;
}


static const per_sequence_t PDUSessionAdmittedToBeAddedSNModResponse_Item_sequence[] = {
  { &hf_xnap_pduSessionId   , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_xnap_PDUSession_ID },
  { &hf_xnap_sn_terminated_01, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_xnap_PDUSessionResourceSetupResponseInfo_SNterminated },
  { &hf_xnap_mn_terminated_01, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_xnap_PDUSessionResourceSetupResponseInfo_MNterminated },
  { &hf_xnap_iE_Extension   , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_xnap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_xnap_PDUSessionAdmittedToBeAddedSNModResponse_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_xnap_PDUSessionAdmittedToBeAddedSNModResponse_Item, PDUSessionAdmittedToBeAddedSNModResponse_Item_sequence);

  return offset;
}


static const per_sequence_t PDUSessionAdmittedToBeAddedSNModResponse_sequence_of[1] = {
  { &hf_xnap_PDUSessionAdmittedToBeAddedSNModResponse_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_xnap_PDUSessionAdmittedToBeAddedSNModResponse_Item },
};

static int
dissect_xnap_PDUSessionAdmittedToBeAddedSNModResponse(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_xnap_PDUSessionAdmittedToBeAddedSNModResponse, PDUSessionAdmittedToBeAddedSNModResponse_sequence_of,
                                                  1, maxnoofPDUSessions, FALSE);

  return offset;
}


static const per_sequence_t PDUSessionAdmittedToBeModifiedSNModResponse_Item_sequence[] = {
  { &hf_xnap_pduSessionId   , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_xnap_PDUSession_ID },
  { &hf_xnap_sn_terminated_03, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_xnap_PDUSessionResourceModificationResponseInfo_SNterminated },
  { &hf_xnap_mn_terminated_03, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_xnap_PDUSessionResourceModificationResponseInfo_MNterminated },
  { &hf_xnap_iE_Extension   , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_xnap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_xnap_PDUSessionAdmittedToBeModifiedSNModResponse_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_xnap_PDUSessionAdmittedToBeModifiedSNModResponse_Item, PDUSessionAdmittedToBeModifiedSNModResponse_Item_sequence);

  return offset;
}


static const per_sequence_t PDUSessionAdmittedToBeModifiedSNModResponse_sequence_of[1] = {
  { &hf_xnap_PDUSessionAdmittedToBeModifiedSNModResponse_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_xnap_PDUSessionAdmittedToBeModifiedSNModResponse_Item },
};

static int
dissect_xnap_PDUSessionAdmittedToBeModifiedSNModResponse(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_xnap_PDUSessionAdmittedToBeModifiedSNModResponse, PDUSessionAdmittedToBeModifiedSNModResponse_sequence_of,
                                                  1, maxnoofPDUSessions, FALSE);

  return offset;
}


static const per_sequence_t PDUSessionAdmittedToBeReleasedSNModResponse_sequence[] = {
  { &hf_xnap_sn_terminated_04, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_xnap_PDUSession_List_withDataForwardingRequest },
  { &hf_xnap_mn_terminated_04, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_xnap_PDUSession_List_withCause },
  { &hf_xnap_iE_Extension   , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_xnap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_xnap_PDUSessionAdmittedToBeReleasedSNModResponse(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_xnap_PDUSessionAdmittedToBeReleasedSNModResponse, PDUSessionAdmittedToBeReleasedSNModResponse_sequence);

  return offset;
}


static const per_sequence_t PDUSessionAdmitted_SNModResponse_sequence[] = {
  { &hf_xnap_pduSessionResourcesAdmittedToBeAdded, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_xnap_PDUSessionAdmittedToBeAddedSNModResponse },
  { &hf_xnap_pduSessionResourcesAdmittedToBeModified, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_xnap_PDUSessionAdmittedToBeModifiedSNModResponse },
  { &hf_xnap_pduSessionResourcesAdmittedToBeReleased, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_xnap_PDUSessionAdmittedToBeReleasedSNModResponse },
  { &hf_xnap_iE_Extension   , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_xnap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_xnap_PDUSessionAdmitted_SNModResponse(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_xnap_PDUSessionAdmitted_SNModResponse, PDUSessionAdmitted_SNModResponse_sequence);

  return offset;
}


static const per_sequence_t PDUSessionNotAdmitted_SNModResponse_sequence[] = {
  { &hf_xnap_pdu_Session_List, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_xnap_PDUSession_List },
  { &hf_xnap_iE_Extension   , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_xnap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_xnap_PDUSessionNotAdmitted_SNModResponse(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_xnap_PDUSessionNotAdmitted_SNModResponse, PDUSessionNotAdmitted_SNModResponse_sequence);

  return offset;
}


static const per_sequence_t PDUSessionDataForwarding_SNModResponse_sequence[] = {
  { &hf_xnap_sn_terminated_04, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_xnap_PDUSession_List_withDataForwardingRequest },
  { &hf_xnap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_xnap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_xnap_PDUSessionDataForwarding_SNModResponse(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_xnap_PDUSessionDataForwarding_SNModResponse, PDUSessionDataForwarding_SNModResponse_sequence);

  return offset;
}


static const per_sequence_t SNodeModificationRequestReject_sequence[] = {
  { &hf_xnap_protocolIEs    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_xnap_ProtocolIE_Container },
  { NULL, 0, 0, NULL }
};

static int
dissect_xnap_SNodeModificationRequestReject(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 497 "./asn1/xnap/xnap.cnf"
  col_append_sep_str(actx->pinfo->cinfo, COL_INFO, NULL, "SNodeModificationRequestReject");

  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_xnap_SNodeModificationRequestReject, SNodeModificationRequestReject_sequence);

  return offset;
}


static const per_sequence_t SNodeModificationRequired_sequence[] = {
  { &hf_xnap_protocolIEs    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_xnap_ProtocolIE_Container },
  { NULL, 0, 0, NULL }
};

static int
dissect_xnap_SNodeModificationRequired(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 499 "./asn1/xnap/xnap.cnf"
  col_append_sep_str(actx->pinfo->cinfo, COL_INFO, NULL, "SNodeModificationRequired");

  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_xnap_SNodeModificationRequired, SNodeModificationRequired_sequence);

  return offset;
}


static const per_sequence_t PDUSessionToBeModifiedSNModRequired_Item_sequence[] = {
  { &hf_xnap_pduSessionId   , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_xnap_PDUSession_ID },
  { &hf_xnap_sn_terminated_05, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_xnap_PDUSessionResourceModRqdInfo_SNterminated },
  { &hf_xnap_mn_terminated_05, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_xnap_PDUSessionResourceModRqdInfo_MNterminated },
  { &hf_xnap_iE_Extension   , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_xnap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_xnap_PDUSessionToBeModifiedSNModRequired_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_xnap_PDUSessionToBeModifiedSNModRequired_Item, PDUSessionToBeModifiedSNModRequired_Item_sequence);

  return offset;
}


static const per_sequence_t PDUSessionToBeModifiedSNModRequired_sequence_of[1] = {
  { &hf_xnap_PDUSessionToBeModifiedSNModRequired_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_xnap_PDUSessionToBeModifiedSNModRequired_Item },
};

static int
dissect_xnap_PDUSessionToBeModifiedSNModRequired(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_xnap_PDUSessionToBeModifiedSNModRequired, PDUSessionToBeModifiedSNModRequired_sequence_of,
                                                  1, maxnoofPDUSessions, FALSE);

  return offset;
}


static const per_sequence_t PDUSessionToBeReleasedSNModRequired_sequence[] = {
  { &hf_xnap_sn_terminated_04, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_xnap_PDUSession_List_withDataForwardingRequest },
  { &hf_xnap_mn_terminated_04, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_xnap_PDUSession_List_withCause },
  { &hf_xnap_iE_Extension   , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_xnap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_xnap_PDUSessionToBeReleasedSNModRequired(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_xnap_PDUSessionToBeReleasedSNModRequired, PDUSessionToBeReleasedSNModRequired_sequence);

  return offset;
}


static const per_sequence_t SNodeModificationConfirm_sequence[] = {
  { &hf_xnap_protocolIEs    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_xnap_ProtocolIE_Container },
  { NULL, 0, 0, NULL }
};

static int
dissect_xnap_SNodeModificationConfirm(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 501 "./asn1/xnap/xnap.cnf"
  col_append_sep_str(actx->pinfo->cinfo, COL_INFO, NULL, "SNodeModificationConfirm");

  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_xnap_SNodeModificationConfirm, SNodeModificationConfirm_sequence);

  return offset;
}


static const per_sequence_t PDUSessionAdmittedModSNModConfirm_Item_sequence[] = {
  { &hf_xnap_pduSessionId   , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_xnap_PDUSession_ID },
  { &hf_xnap_sn_terminated_06, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_xnap_PDUSessionResourceModConfirmInfo_SNterminated },
  { &hf_xnap_mn_terminated_06, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_xnap_PDUSessionResourceModConfirmInfo_MNterminated },
  { &hf_xnap_iE_Extension   , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_xnap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_xnap_PDUSessionAdmittedModSNModConfirm_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_xnap_PDUSessionAdmittedModSNModConfirm_Item, PDUSessionAdmittedModSNModConfirm_Item_sequence);

  return offset;
}


static const per_sequence_t PDUSessionAdmittedModSNModConfirm_sequence_of[1] = {
  { &hf_xnap_PDUSessionAdmittedModSNModConfirm_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_xnap_PDUSessionAdmittedModSNModConfirm_Item },
};

static int
dissect_xnap_PDUSessionAdmittedModSNModConfirm(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_xnap_PDUSessionAdmittedModSNModConfirm, PDUSessionAdmittedModSNModConfirm_sequence_of,
                                                  1, maxnoofPDUSessions, FALSE);

  return offset;
}


static const per_sequence_t PDUSessionReleasedSNModConfirm_sequence[] = {
  { &hf_xnap_sn_terminated_07, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_xnap_PDUSession_List_withDataForwardingFromTarget },
  { &hf_xnap_mn_terminated_07, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_xnap_PDUSession_List },
  { &hf_xnap_iE_Extension   , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_xnap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_xnap_PDUSessionReleasedSNModConfirm(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_xnap_PDUSessionReleasedSNModConfirm, PDUSessionReleasedSNModConfirm_sequence);

  return offset;
}


static const per_sequence_t SNodeModificationRefuse_sequence[] = {
  { &hf_xnap_protocolIEs    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_xnap_ProtocolIE_Container },
  { NULL, 0, 0, NULL }
};

static int
dissect_xnap_SNodeModificationRefuse(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 503 "./asn1/xnap/xnap.cnf"
  col_append_sep_str(actx->pinfo->cinfo, COL_INFO, NULL, "SNodeModificationRefuse");

  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_xnap_SNodeModificationRefuse, SNodeModificationRefuse_sequence);

  return offset;
}


static const per_sequence_t SNodeReleaseRequest_sequence[] = {
  { &hf_xnap_protocolIEs    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_xnap_ProtocolIE_Container },
  { NULL, 0, 0, NULL }
};

static int
dissect_xnap_SNodeReleaseRequest(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 505 "./asn1/xnap/xnap.cnf"
  col_append_sep_str(actx->pinfo->cinfo, COL_INFO, NULL, "SNodeReleaseRequest");

  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_xnap_SNodeReleaseRequest, SNodeReleaseRequest_sequence);

  return offset;
}


static const per_sequence_t SNodeReleaseRequestAcknowledge_sequence[] = {
  { &hf_xnap_protocolIEs    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_xnap_ProtocolIE_Container },
  { NULL, 0, 0, NULL }
};

static int
dissect_xnap_SNodeReleaseRequestAcknowledge(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 507 "./asn1/xnap/xnap.cnf"
  col_append_sep_str(actx->pinfo->cinfo, COL_INFO, NULL, "SNodeReleaseRequestAcknowledge");

  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_xnap_SNodeReleaseRequestAcknowledge, SNodeReleaseRequestAcknowledge_sequence);

  return offset;
}


static const per_sequence_t PDUSessionToBeReleasedList_RelReqAck_sequence[] = {
  { &hf_xnap_pduSessionsToBeReleasedList_SNterminated, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_xnap_PDUSession_List_withDataForwardingRequest },
  { &hf_xnap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_xnap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_xnap_PDUSessionToBeReleasedList_RelReqAck(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_xnap_PDUSessionToBeReleasedList_RelReqAck, PDUSessionToBeReleasedList_RelReqAck_sequence);

  return offset;
}


static const per_sequence_t SNodeReleaseReject_sequence[] = {
  { &hf_xnap_protocolIEs    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_xnap_ProtocolIE_Container },
  { NULL, 0, 0, NULL }
};

static int
dissect_xnap_SNodeReleaseReject(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 509 "./asn1/xnap/xnap.cnf"
  col_append_sep_str(actx->pinfo->cinfo, COL_INFO, NULL, "SNodeReleaseReject");

  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_xnap_SNodeReleaseReject, SNodeReleaseReject_sequence);

  return offset;
}


static const per_sequence_t SNodeReleaseRequired_sequence[] = {
  { &hf_xnap_protocolIEs    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_xnap_ProtocolIE_Container },
  { NULL, 0, 0, NULL }
};

static int
dissect_xnap_SNodeReleaseRequired(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 511 "./asn1/xnap/xnap.cnf"
  col_append_sep_str(actx->pinfo->cinfo, COL_INFO, NULL, "SNodeReleaseRequired");

  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_xnap_SNodeReleaseRequired, SNodeReleaseRequired_sequence);

  return offset;
}


static const per_sequence_t PDUSessionToBeReleasedList_RelRqd_sequence[] = {
  { &hf_xnap_pduSessionsToBeReleasedList_SNterminated, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_xnap_PDUSession_List_withDataForwardingRequest },
  { &hf_xnap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_xnap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_xnap_PDUSessionToBeReleasedList_RelRqd(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_xnap_PDUSessionToBeReleasedList_RelRqd, PDUSessionToBeReleasedList_RelRqd_sequence);

  return offset;
}


static const per_sequence_t SNodeReleaseConfirm_sequence[] = {
  { &hf_xnap_protocolIEs    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_xnap_ProtocolIE_Container },
  { NULL, 0, 0, NULL }
};

static int
dissect_xnap_SNodeReleaseConfirm(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 513 "./asn1/xnap/xnap.cnf"
  col_append_sep_str(actx->pinfo->cinfo, COL_INFO, NULL, "SNodeReleaseConfirm");

  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_xnap_SNodeReleaseConfirm, SNodeReleaseConfirm_sequence);

  return offset;
}


static const per_sequence_t PDUSessionReleasedList_RelConf_sequence[] = {
  { &hf_xnap_pduSessionsReleasedList_SNterminated, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_xnap_PDUSession_List_withDataForwardingFromTarget },
  { &hf_xnap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_xnap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_xnap_PDUSessionReleasedList_RelConf(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_xnap_PDUSessionReleasedList_RelConf, PDUSessionReleasedList_RelConf_sequence);

  return offset;
}


static const per_sequence_t SNodeCounterCheckRequest_sequence[] = {
  { &hf_xnap_protocolIEs    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_xnap_ProtocolIE_Container },
  { NULL, 0, 0, NULL }
};

static int
dissect_xnap_SNodeCounterCheckRequest(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 515 "./asn1/xnap/xnap.cnf"
  col_append_sep_str(actx->pinfo->cinfo, COL_INFO, NULL, "SNodeCounterCheckRequest");

  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_xnap_SNodeCounterCheckRequest, SNodeCounterCheckRequest_sequence);

  return offset;
}



static int
dissect_xnap_INTEGER_0_4294967295(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 4294967295U, NULL, FALSE);

  return offset;
}


static const per_sequence_t BearersSubjectToCounterCheck_Item_sequence[] = {
  { &hf_xnap_drb_ID         , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_xnap_DRB_ID },
  { &hf_xnap_ul_count       , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_xnap_INTEGER_0_4294967295 },
  { &hf_xnap_dl_count       , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_xnap_INTEGER_0_4294967295 },
  { &hf_xnap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_xnap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_xnap_BearersSubjectToCounterCheck_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_xnap_BearersSubjectToCounterCheck_Item, BearersSubjectToCounterCheck_Item_sequence);

  return offset;
}


static const per_sequence_t BearersSubjectToCounterCheck_List_sequence_of[1] = {
  { &hf_xnap_BearersSubjectToCounterCheck_List_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_xnap_BearersSubjectToCounterCheck_Item },
};

static int
dissect_xnap_BearersSubjectToCounterCheck_List(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_xnap_BearersSubjectToCounterCheck_List, BearersSubjectToCounterCheck_List_sequence_of,
                                                  1, maxnoofDRBs, FALSE);

  return offset;
}


static const per_sequence_t SNodeChangeRequired_sequence[] = {
  { &hf_xnap_protocolIEs    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_xnap_ProtocolIE_Container },
  { NULL, 0, 0, NULL }
};

static int
dissect_xnap_SNodeChangeRequired(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 517 "./asn1/xnap/xnap.cnf"
  col_append_sep_str(actx->pinfo->cinfo, COL_INFO, NULL, "SNodeChangeRequired");

  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_xnap_SNodeChangeRequired, SNodeChangeRequired_sequence);

  return offset;
}


static const per_sequence_t PDUSession_SNChangeRequired_Item_sequence[] = {
  { &hf_xnap_pduSessionId   , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_xnap_PDUSession_ID },
  { &hf_xnap_sn_terminated_08, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_xnap_PDUSessionResourceChangeRequiredInfo_SNterminated },
  { &hf_xnap_mn_terminated_08, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_xnap_PDUSessionResourceChangeRequiredInfo_MNterminated },
  { &hf_xnap_iE_Extension   , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_xnap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_xnap_PDUSession_SNChangeRequired_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_xnap_PDUSession_SNChangeRequired_Item, PDUSession_SNChangeRequired_Item_sequence);

  return offset;
}


static const per_sequence_t PDUSession_SNChangeRequired_List_sequence_of[1] = {
  { &hf_xnap_PDUSession_SNChangeRequired_List_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_xnap_PDUSession_SNChangeRequired_Item },
};

static int
dissect_xnap_PDUSession_SNChangeRequired_List(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_xnap_PDUSession_SNChangeRequired_List, PDUSession_SNChangeRequired_List_sequence_of,
                                                  1, maxnoofPDUSessions, FALSE);

  return offset;
}


static const per_sequence_t SNodeChangeConfirm_sequence[] = {
  { &hf_xnap_protocolIEs    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_xnap_ProtocolIE_Container },
  { NULL, 0, 0, NULL }
};

static int
dissect_xnap_SNodeChangeConfirm(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 519 "./asn1/xnap/xnap.cnf"
  col_append_sep_str(actx->pinfo->cinfo, COL_INFO, NULL, "SNodeChangeConfirm");

  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_xnap_SNodeChangeConfirm, SNodeChangeConfirm_sequence);

  return offset;
}


static const per_sequence_t PDUSession_SNChangeConfirm_Item_sequence[] = {
  { &hf_xnap_pduSessionId   , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_xnap_PDUSession_ID },
  { &hf_xnap_sn_terminated_09, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_xnap_PDUSessionResourceChangeConfirmInfo_SNterminated },
  { &hf_xnap_mn_terminated_09, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_xnap_PDUSessionResourceChangeConfirmInfo_MNterminated },
  { &hf_xnap_iE_Extension   , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_xnap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_xnap_PDUSession_SNChangeConfirm_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_xnap_PDUSession_SNChangeConfirm_Item, PDUSession_SNChangeConfirm_Item_sequence);

  return offset;
}


static const per_sequence_t PDUSession_SNChangeConfirm_List_sequence_of[1] = {
  { &hf_xnap_PDUSession_SNChangeConfirm_List_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_xnap_PDUSession_SNChangeConfirm_Item },
};

static int
dissect_xnap_PDUSession_SNChangeConfirm_List(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_xnap_PDUSession_SNChangeConfirm_List, PDUSession_SNChangeConfirm_List_sequence_of,
                                                  1, maxnoofPDUSessions, FALSE);

  return offset;
}


static const per_sequence_t SNodeChangeRefuse_sequence[] = {
  { &hf_xnap_protocolIEs    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_xnap_ProtocolIE_Container },
  { NULL, 0, 0, NULL }
};

static int
dissect_xnap_SNodeChangeRefuse(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 521 "./asn1/xnap/xnap.cnf"
  col_append_sep_str(actx->pinfo->cinfo, COL_INFO, NULL, "SNodeChangeRefuse");

  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_xnap_SNodeChangeRefuse, SNodeChangeRefuse_sequence);

  return offset;
}


static const per_sequence_t RRCTransfer_sequence[] = {
  { &hf_xnap_protocolIEs    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_xnap_ProtocolIE_Container },
  { NULL, 0, 0, NULL }
};

static int
dissect_xnap_RRCTransfer(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 523 "./asn1/xnap/xnap.cnf"
  col_append_sep_str(actx->pinfo->cinfo, COL_INFO, NULL, "RRCTransfer");

  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_xnap_RRCTransfer, RRCTransfer_sequence);

  return offset;
}



static int
dissect_xnap_OCTET_STRING(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_octet_string(tvb, offset, actx, tree, hf_index,
                                       NO_BOUND, NO_BOUND, FALSE, NULL);

  return offset;
}


static const value_string xnap_T_srbType_vals[] = {
  {   0, "srb1" },
  {   1, "srb2" },
  { 0, NULL }
};


static int
dissect_xnap_T_srbType(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     2, NULL, TRUE, 0, NULL);

  return offset;
}


static const per_sequence_t SplitSRB_RRCTransfer_sequence[] = {
  { &hf_xnap_rrcContainer   , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_xnap_OCTET_STRING },
  { &hf_xnap_srbType        , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_xnap_T_srbType },
  { &hf_xnap_deliveryStatus , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_xnap_DeliveryStatus },
  { &hf_xnap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_xnap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_xnap_SplitSRB_RRCTransfer(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_xnap_SplitSRB_RRCTransfer, SplitSRB_RRCTransfer_sequence);

  return offset;
}


static const per_sequence_t UEReportRRCTransfer_sequence[] = {
  { &hf_xnap_rrcContainer   , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_xnap_OCTET_STRING },
  { &hf_xnap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_xnap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_xnap_UEReportRRCTransfer(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_xnap_UEReportRRCTransfer, UEReportRRCTransfer_sequence);

  return offset;
}


static const per_sequence_t NotificationControlIndication_sequence[] = {
  { &hf_xnap_protocolIEs    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_xnap_ProtocolIE_Container },
  { NULL, 0, 0, NULL }
};

static int
dissect_xnap_NotificationControlIndication(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 559 "./asn1/xnap/xnap.cnf"
  col_append_sep_str(actx->pinfo->cinfo, COL_INFO, NULL, "NotificationControlIndication");

  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_xnap_NotificationControlIndication, NotificationControlIndication_sequence);

  return offset;
}


static const per_sequence_t PDUSessionResourcesNotify_Item_sequence[] = {
  { &hf_xnap_pduSessionId   , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_xnap_PDUSession_ID },
  { &hf_xnap_qosFlowsNotificationContrIndInfo, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_xnap_QoSFlowNotificationControlIndicationInfo },
  { &hf_xnap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_xnap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_xnap_PDUSessionResourcesNotify_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_xnap_PDUSessionResourcesNotify_Item, PDUSessionResourcesNotify_Item_sequence);

  return offset;
}


static const per_sequence_t PDUSessionResourcesNotifyList_sequence_of[1] = {
  { &hf_xnap_PDUSessionResourcesNotifyList_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_xnap_PDUSessionResourcesNotify_Item },
};

static int
dissect_xnap_PDUSessionResourcesNotifyList(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_xnap_PDUSessionResourcesNotifyList, PDUSessionResourcesNotifyList_sequence_of,
                                                  1, maxnoofPDUSessions, FALSE);

  return offset;
}


static const per_sequence_t ActivityNotification_sequence[] = {
  { &hf_xnap_protocolIEs    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_xnap_ProtocolIE_Container },
  { NULL, 0, 0, NULL }
};

static int
dissect_xnap_ActivityNotification(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 561 "./asn1/xnap/xnap.cnf"
  col_append_sep_str(actx->pinfo->cinfo, COL_INFO, NULL, "ActivityNotification");

  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_xnap_ActivityNotification, ActivityNotification_sequence);

  return offset;
}


static const per_sequence_t QoSFlowsActivityNotifyItem_sequence[] = {
  { &hf_xnap_qosFlowIdentifier, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_xnap_QoSFlowIdentifier },
  { &hf_xnap_pduSessionLevelUPactivityreport, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_xnap_UserPlaneTrafficActivityReport },
  { &hf_xnap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_xnap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_xnap_QoSFlowsActivityNotifyItem(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_xnap_QoSFlowsActivityNotifyItem, QoSFlowsActivityNotifyItem_sequence);

  return offset;
}


static const per_sequence_t QoSFlowsActivityNotifyList_sequence_of[1] = {
  { &hf_xnap_QoSFlowsActivityNotifyList_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_xnap_QoSFlowsActivityNotifyItem },
};

static int
dissect_xnap_QoSFlowsActivityNotifyList(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_xnap_QoSFlowsActivityNotifyList, QoSFlowsActivityNotifyList_sequence_of,
                                                  1, maxnoofQoSFlows, FALSE);

  return offset;
}


static const per_sequence_t PDUSessionResourcesActivityNotify_Item_sequence[] = {
  { &hf_xnap_pduSessionId   , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_xnap_PDUSession_ID },
  { &hf_xnap_pduSessionLevelUPactivityreport, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_xnap_UserPlaneTrafficActivityReport },
  { &hf_xnap_qosFlowsActivityNotifyList, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_xnap_QoSFlowsActivityNotifyList },
  { &hf_xnap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_xnap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_xnap_PDUSessionResourcesActivityNotify_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_xnap_PDUSessionResourcesActivityNotify_Item, PDUSessionResourcesActivityNotify_Item_sequence);

  return offset;
}


static const per_sequence_t PDUSessionResourcesActivityNotifyList_sequence_of[1] = {
  { &hf_xnap_PDUSessionResourcesActivityNotifyList_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_xnap_PDUSessionResourcesActivityNotify_Item },
};

static int
dissect_xnap_PDUSessionResourcesActivityNotifyList(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_xnap_PDUSessionResourcesActivityNotifyList, PDUSessionResourcesActivityNotifyList_sequence_of,
                                                  1, maxnoofPDUSessions, FALSE);

  return offset;
}


static const per_sequence_t XnSetupRequest_sequence[] = {
  { &hf_xnap_protocolIEs    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_xnap_ProtocolIE_Container },
  { NULL, 0, 0, NULL }
};

static int
dissect_xnap_XnSetupRequest(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 531 "./asn1/xnap/xnap.cnf"
  col_append_sep_str(actx->pinfo->cinfo, COL_INFO, NULL, "XnSetupRequest");

  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_xnap_XnSetupRequest, XnSetupRequest_sequence);

  return offset;
}


static const per_sequence_t XnSetupResponse_sequence[] = {
  { &hf_xnap_protocolIEs    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_xnap_ProtocolIE_Container },
  { NULL, 0, 0, NULL }
};

static int
dissect_xnap_XnSetupResponse(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 533 "./asn1/xnap/xnap.cnf"
  col_append_sep_str(actx->pinfo->cinfo, COL_INFO, NULL, "XnSetupResponse");

  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_xnap_XnSetupResponse, XnSetupResponse_sequence);

  return offset;
}


static const per_sequence_t XnSetupFailure_sequence[] = {
  { &hf_xnap_protocolIEs    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_xnap_ProtocolIE_Container },
  { NULL, 0, 0, NULL }
};

static int
dissect_xnap_XnSetupFailure(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 535 "./asn1/xnap/xnap.cnf"
  col_append_sep_str(actx->pinfo->cinfo, COL_INFO, NULL, "XnSetupFailure");

  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_xnap_XnSetupFailure, XnSetupFailure_sequence);

  return offset;
}


static const per_sequence_t NGRANNodeConfigurationUpdate_sequence[] = {
  { &hf_xnap_protocolIEs    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_xnap_ProtocolIE_Container },
  { NULL, 0, 0, NULL }
};

static int
dissect_xnap_NGRANNodeConfigurationUpdate(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 537 "./asn1/xnap/xnap.cnf"
  col_append_sep_str(actx->pinfo->cinfo, COL_INFO, NULL, "NGRANNodeConfigurationUpdate");

  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_xnap_NGRANNodeConfigurationUpdate, NGRANNodeConfigurationUpdate_sequence);

  return offset;
}


static const value_string xnap_ConfigurationUpdateInitiatingNodeChoice_vals[] = {
  {   0, "gNB" },
  {   1, "ng-eNB" },
  {   2, "choice-extension" },
  { 0, NULL }
};

static const per_choice_t ConfigurationUpdateInitiatingNodeChoice_choice[] = {
  {   0, &hf_xnap_gNB_01         , ASN1_NO_EXTENSIONS     , dissect_xnap_ProtocolIE_Container },
  {   1, &hf_xnap_ng_eNB_01      , ASN1_NO_EXTENSIONS     , dissect_xnap_ProtocolIE_Container },
  {   2, &hf_xnap_choice_extension, ASN1_NO_EXTENSIONS     , dissect_xnap_ProtocolIE_Single_Container },
  { 0, NULL, 0, NULL }
};

static int
dissect_xnap_ConfigurationUpdateInitiatingNodeChoice(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_xnap_ConfigurationUpdateInitiatingNodeChoice, ConfigurationUpdateInitiatingNodeChoice_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t NGRANNodeConfigurationUpdateAcknowledge_sequence[] = {
  { &hf_xnap_protocolIEs    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_xnap_ProtocolIE_Container },
  { NULL, 0, 0, NULL }
};

static int
dissect_xnap_NGRANNodeConfigurationUpdateAcknowledge(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 539 "./asn1/xnap/xnap.cnf"
  col_append_sep_str(actx->pinfo->cinfo, COL_INFO, NULL, "NGRANNodeConfigurationUpdateAcknowledge");

  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_xnap_NGRANNodeConfigurationUpdateAcknowledge, NGRANNodeConfigurationUpdateAcknowledge_sequence);

  return offset;
}


static const per_sequence_t RespondingNodeTypeConfigUpdateAck_ng_eNB_sequence[] = {
  { &hf_xnap_iE_Extension   , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_xnap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_xnap_RespondingNodeTypeConfigUpdateAck_ng_eNB(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_xnap_RespondingNodeTypeConfigUpdateAck_ng_eNB, RespondingNodeTypeConfigUpdateAck_ng_eNB_sequence);

  return offset;
}


static const per_sequence_t RespondingNodeTypeConfigUpdateAck_gNB_sequence[] = {
  { &hf_xnap_served_NR_Cells, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_xnap_ServedCells_NR },
  { &hf_xnap_iE_Extension   , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_xnap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_xnap_RespondingNodeTypeConfigUpdateAck_gNB(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_xnap_RespondingNodeTypeConfigUpdateAck_gNB, RespondingNodeTypeConfigUpdateAck_gNB_sequence);

  return offset;
}


static const value_string xnap_RespondingNodeTypeConfigUpdateAck_vals[] = {
  {   0, "ng-eNB" },
  {   1, "gNB" },
  {   2, "choice-extension" },
  { 0, NULL }
};

static const per_choice_t RespondingNodeTypeConfigUpdateAck_choice[] = {
  {   0, &hf_xnap_ng_eNB_02      , ASN1_NO_EXTENSIONS     , dissect_xnap_RespondingNodeTypeConfigUpdateAck_ng_eNB },
  {   1, &hf_xnap_gNB_02         , ASN1_NO_EXTENSIONS     , dissect_xnap_RespondingNodeTypeConfigUpdateAck_gNB },
  {   2, &hf_xnap_choice_extension, ASN1_NO_EXTENSIONS     , dissect_xnap_ProtocolIE_Single_Container },
  { 0, NULL, 0, NULL }
};

static int
dissect_xnap_RespondingNodeTypeConfigUpdateAck(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_xnap_RespondingNodeTypeConfigUpdateAck, RespondingNodeTypeConfigUpdateAck_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t NGRANNodeConfigurationUpdateFailure_sequence[] = {
  { &hf_xnap_protocolIEs    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_xnap_ProtocolIE_Container },
  { NULL, 0, 0, NULL }
};

static int
dissect_xnap_NGRANNodeConfigurationUpdateFailure(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 541 "./asn1/xnap/xnap.cnf"
  col_append_sep_str(actx->pinfo->cinfo, COL_INFO, NULL, "NGRANNodeConfigurationUpdateFailure");

  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_xnap_NGRANNodeConfigurationUpdateFailure, NGRANNodeConfigurationUpdateFailure_sequence);

  return offset;
}


static const per_sequence_t E_UTRA_NR_CellResourceCoordinationRequest_sequence[] = {
  { &hf_xnap_protocolIEs    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_xnap_ProtocolIE_Container },
  { NULL, 0, 0, NULL }
};

static int
dissect_xnap_E_UTRA_NR_CellResourceCoordinationRequest(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 543 "./asn1/xnap/xnap.cnf"
  col_append_sep_str(actx->pinfo->cinfo, COL_INFO, NULL, "E-UTRA-NR-CellResourceCoordinationRequest");

  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_xnap_E_UTRA_NR_CellResourceCoordinationRequest, E_UTRA_NR_CellResourceCoordinationRequest_sequence);

  return offset;
}


static const per_sequence_t ResourceCoordRequest_ng_eNB_initiated_sequence[] = {
  { &hf_xnap_dataTrafficResourceIndication, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_xnap_DataTrafficResourceIndication },
  { &hf_xnap_spectrumSharingGroupID, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_xnap_SpectrumSharingGroupID },
  { &hf_xnap_listofE_UTRACells, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_xnap_SEQUENCE_SIZE_1_maxnoofCellsinNG_RANnode_OF_E_UTRA_CGI },
  { &hf_xnap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_xnap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_xnap_ResourceCoordRequest_ng_eNB_initiated(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_xnap_ResourceCoordRequest_ng_eNB_initiated, ResourceCoordRequest_ng_eNB_initiated_sequence);

  return offset;
}


static const per_sequence_t ResourceCoordRequest_gNB_initiated_sequence[] = {
  { &hf_xnap_dataTrafficResourceIndication, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_xnap_DataTrafficResourceIndication },
  { &hf_xnap_listofE_UTRACells, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_xnap_SEQUENCE_SIZE_1_maxnoofCellsinNG_RANnode_OF_E_UTRA_CGI },
  { &hf_xnap_spectrumSharingGroupID, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_xnap_SpectrumSharingGroupID },
  { &hf_xnap_listofNRCells  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_xnap_SEQUENCE_SIZE_1_maxnoofCellsinNG_RANnode_OF_NR_CGI },
  { &hf_xnap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_xnap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_xnap_ResourceCoordRequest_gNB_initiated(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_xnap_ResourceCoordRequest_gNB_initiated, ResourceCoordRequest_gNB_initiated_sequence);

  return offset;
}


static const value_string xnap_InitiatingNodeType_ResourceCoordRequest_vals[] = {
  {   0, "ng-eNB" },
  {   1, "gNB" },
  {   2, "choice-extension" },
  { 0, NULL }
};

static const per_choice_t InitiatingNodeType_ResourceCoordRequest_choice[] = {
  {   0, &hf_xnap_ng_eNB_03      , ASN1_NO_EXTENSIONS     , dissect_xnap_ResourceCoordRequest_ng_eNB_initiated },
  {   1, &hf_xnap_gNB_03         , ASN1_NO_EXTENSIONS     , dissect_xnap_ResourceCoordRequest_gNB_initiated },
  {   2, &hf_xnap_choice_extension, ASN1_NO_EXTENSIONS     , dissect_xnap_ProtocolIE_Single_Container },
  { 0, NULL, 0, NULL }
};

static int
dissect_xnap_InitiatingNodeType_ResourceCoordRequest(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_xnap_InitiatingNodeType_ResourceCoordRequest, InitiatingNodeType_ResourceCoordRequest_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t E_UTRA_NR_CellResourceCoordinationResponse_sequence[] = {
  { &hf_xnap_protocolIEs    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_xnap_ProtocolIE_Container },
  { NULL, 0, 0, NULL }
};

static int
dissect_xnap_E_UTRA_NR_CellResourceCoordinationResponse(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 545 "./asn1/xnap/xnap.cnf"
  col_append_sep_str(actx->pinfo->cinfo, COL_INFO, NULL, "E-UTRA-NR-CellResourceCoordinationResponse");

  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_xnap_E_UTRA_NR_CellResourceCoordinationResponse, E_UTRA_NR_CellResourceCoordinationResponse_sequence);

  return offset;
}


static const per_sequence_t ResourceCoordResponse_ng_eNB_initiated_sequence[] = {
  { &hf_xnap_dataTrafficResourceIndication, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_xnap_DataTrafficResourceIndication },
  { &hf_xnap_spectrumSharingGroupID, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_xnap_SpectrumSharingGroupID },
  { &hf_xnap_listofE_UTRACells, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_xnap_SEQUENCE_SIZE_1_maxnoofCellsinNG_RANnode_OF_E_UTRA_CGI },
  { &hf_xnap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_xnap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_xnap_ResourceCoordResponse_ng_eNB_initiated(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_xnap_ResourceCoordResponse_ng_eNB_initiated, ResourceCoordResponse_ng_eNB_initiated_sequence);

  return offset;
}


static const per_sequence_t ResourceCoordResponse_gNB_initiated_sequence[] = {
  { &hf_xnap_dataTrafficResourceIndication, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_xnap_DataTrafficResourceIndication },
  { &hf_xnap_spectrumSharingGroupID, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_xnap_SpectrumSharingGroupID },
  { &hf_xnap_listofNRCells  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_xnap_SEQUENCE_SIZE_1_maxnoofCellsinNG_RANnode_OF_NR_CGI },
  { &hf_xnap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_xnap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_xnap_ResourceCoordResponse_gNB_initiated(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_xnap_ResourceCoordResponse_gNB_initiated, ResourceCoordResponse_gNB_initiated_sequence);

  return offset;
}


static const value_string xnap_RespondingNodeType_ResourceCoordResponse_vals[] = {
  {   0, "ng-eNB" },
  {   1, "gNB" },
  {   2, "choice-extension" },
  { 0, NULL }
};

static const per_choice_t RespondingNodeType_ResourceCoordResponse_choice[] = {
  {   0, &hf_xnap_ng_eNB_04      , ASN1_NO_EXTENSIONS     , dissect_xnap_ResourceCoordResponse_ng_eNB_initiated },
  {   1, &hf_xnap_gNB_04         , ASN1_NO_EXTENSIONS     , dissect_xnap_ResourceCoordResponse_gNB_initiated },
  {   2, &hf_xnap_choice_extension, ASN1_NO_EXTENSIONS     , dissect_xnap_ProtocolIE_Single_Container },
  { 0, NULL, 0, NULL }
};

static int
dissect_xnap_RespondingNodeType_ResourceCoordResponse(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_xnap_RespondingNodeType_ResourceCoordResponse, RespondingNodeType_ResourceCoordResponse_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t SecondaryRATDataUsageReport_sequence[] = {
  { &hf_xnap_protocolIEs    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_xnap_ProtocolIE_Container },
  { NULL, 0, 0, NULL }
};

static int
dissect_xnap_SecondaryRATDataUsageReport(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 565 "./asn1/xnap/xnap.cnf"
  col_append_sep_str(actx->pinfo->cinfo, COL_INFO, NULL, "SecondaryRATDataUsageReport");


  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_xnap_SecondaryRATDataUsageReport, SecondaryRATDataUsageReport_sequence);

  return offset;
}


static const per_sequence_t XnRemovalRequest_sequence[] = {
  { &hf_xnap_protocolIEs    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_xnap_ProtocolIE_Container },
  { NULL, 0, 0, NULL }
};

static int
dissect_xnap_XnRemovalRequest(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 525 "./asn1/xnap/xnap.cnf"
  col_append_sep_str(actx->pinfo->cinfo, COL_INFO, NULL, "XnRemovalRequest");

  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_xnap_XnRemovalRequest, XnRemovalRequest_sequence);

  return offset;
}


static const per_sequence_t XnRemovalResponse_sequence[] = {
  { &hf_xnap_protocolIEs    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_xnap_ProtocolIE_Container },
  { NULL, 0, 0, NULL }
};

static int
dissect_xnap_XnRemovalResponse(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 527 "./asn1/xnap/xnap.cnf"
  col_append_sep_str(actx->pinfo->cinfo, COL_INFO, NULL, "XnRemovalResponse");

  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_xnap_XnRemovalResponse, XnRemovalResponse_sequence);

  return offset;
}


static const per_sequence_t XnRemovalFailure_sequence[] = {
  { &hf_xnap_protocolIEs    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_xnap_ProtocolIE_Container },
  { NULL, 0, 0, NULL }
};

static int
dissect_xnap_XnRemovalFailure(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 529 "./asn1/xnap/xnap.cnf"
  col_append_sep_str(actx->pinfo->cinfo, COL_INFO, NULL, "XnRemovalFailure");

  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_xnap_XnRemovalFailure, XnRemovalFailure_sequence);

  return offset;
}


static const per_sequence_t CellActivationRequest_sequence[] = {
  { &hf_xnap_protocolIEs    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_xnap_ProtocolIE_Container },
  { NULL, 0, 0, NULL }
};

static int
dissect_xnap_CellActivationRequest(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 547 "./asn1/xnap/xnap.cnf"
  col_append_sep_str(actx->pinfo->cinfo, COL_INFO, NULL, "CellActivationRequest");

  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_xnap_CellActivationRequest, CellActivationRequest_sequence);

  return offset;
}


static const value_string xnap_ServedCellsToActivate_vals[] = {
  {   0, "nr-cells" },
  {   1, "e-utra-cells" },
  {   2, "choice-extension" },
  { 0, NULL }
};

static const per_choice_t ServedCellsToActivate_choice[] = {
  {   0, &hf_xnap_nr_cells       , ASN1_NO_EXTENSIONS     , dissect_xnap_SEQUENCE_SIZE_1_maxnoofCellsinNG_RANnode_OF_NR_CGI },
  {   1, &hf_xnap_e_utra_cells   , ASN1_NO_EXTENSIONS     , dissect_xnap_SEQUENCE_SIZE_1_maxnoofCellsinNG_RANnode_OF_E_UTRA_CGI },
  {   2, &hf_xnap_choice_extension, ASN1_NO_EXTENSIONS     , dissect_xnap_ProtocolIE_Single_Container },
  { 0, NULL, 0, NULL }
};

static int
dissect_xnap_ServedCellsToActivate(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_xnap_ServedCellsToActivate, ServedCellsToActivate_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t CellActivationResponse_sequence[] = {
  { &hf_xnap_protocolIEs    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_xnap_ProtocolIE_Container },
  { NULL, 0, 0, NULL }
};

static int
dissect_xnap_CellActivationResponse(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 549 "./asn1/xnap/xnap.cnf"
  col_append_sep_str(actx->pinfo->cinfo, COL_INFO, NULL, "CellActivationResponse");

  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_xnap_CellActivationResponse, CellActivationResponse_sequence);

  return offset;
}


static const value_string xnap_ActivatedServedCells_vals[] = {
  {   0, "nr-cells" },
  {   1, "e-utra-cells" },
  {   2, "choice-extension" },
  { 0, NULL }
};

static const per_choice_t ActivatedServedCells_choice[] = {
  {   0, &hf_xnap_nr_cells       , ASN1_NO_EXTENSIONS     , dissect_xnap_SEQUENCE_SIZE_1_maxnoofCellsinNG_RANnode_OF_NR_CGI },
  {   1, &hf_xnap_e_utra_cells   , ASN1_NO_EXTENSIONS     , dissect_xnap_SEQUENCE_SIZE_1_maxnoofCellsinNG_RANnode_OF_E_UTRA_CGI },
  {   2, &hf_xnap_choice_extension, ASN1_NO_EXTENSIONS     , dissect_xnap_ProtocolIE_Single_Container },
  { 0, NULL, 0, NULL }
};

static int
dissect_xnap_ActivatedServedCells(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_xnap_ActivatedServedCells, ActivatedServedCells_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t CellActivationFailure_sequence[] = {
  { &hf_xnap_protocolIEs    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_xnap_ProtocolIE_Container },
  { NULL, 0, 0, NULL }
};

static int
dissect_xnap_CellActivationFailure(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 551 "./asn1/xnap/xnap.cnf"
  col_append_sep_str(actx->pinfo->cinfo, COL_INFO, NULL, "CellActivationFailure");

  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_xnap_CellActivationFailure, CellActivationFailure_sequence);

  return offset;
}


static const per_sequence_t ResetRequest_sequence[] = {
  { &hf_xnap_protocolIEs    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_xnap_ProtocolIE_Container },
  { NULL, 0, 0, NULL }
};

static int
dissect_xnap_ResetRequest(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 553 "./asn1/xnap/xnap.cnf"
  col_append_sep_str(actx->pinfo->cinfo, COL_INFO, NULL, "ResetRequest");

  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_xnap_ResetRequest, ResetRequest_sequence);

  return offset;
}


static const per_sequence_t ResetResponse_sequence[] = {
  { &hf_xnap_protocolIEs    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_xnap_ProtocolIE_Container },
  { NULL, 0, 0, NULL }
};

static int
dissect_xnap_ResetResponse(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 555 "./asn1/xnap/xnap.cnf"
  col_append_sep_str(actx->pinfo->cinfo, COL_INFO, NULL, "ResetResponse");

  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_xnap_ResetResponse, ResetResponse_sequence);

  return offset;
}


static const per_sequence_t ErrorIndication_sequence[] = {
  { &hf_xnap_protocolIEs    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_xnap_ProtocolIE_Container },
  { NULL, 0, 0, NULL }
};

static int
dissect_xnap_ErrorIndication(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 557 "./asn1/xnap/xnap.cnf"
  col_append_sep_str(actx->pinfo->cinfo, COL_INFO, NULL, "ErrorIndication");

  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_xnap_ErrorIndication, ErrorIndication_sequence);

  return offset;
}


static const per_sequence_t PrivateMessage_sequence[] = {
  { &hf_xnap_privateIEs     , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_xnap_PrivateIE_Container },
  { NULL, 0, 0, NULL }
};

static int
dissect_xnap_PrivateMessage(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 563 "./asn1/xnap/xnap.cnf"
  col_append_sep_str(actx->pinfo->cinfo, COL_INFO, NULL, "PrivateMessage");

  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_xnap_PrivateMessage, PrivateMessage_sequence);

  return offset;
}



static int
dissect_xnap_InitiatingMessage_value(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 71 "./asn1/xnap/xnap.cnf"
  struct xnap_private_data *xnap_data = xnap_get_private_data(actx->pinfo);
  xnap_data->message_type = INITIATING_MESSAGE;


  offset = dissect_per_open_type_pdu_new(tvb, offset, actx, tree, hf_index, dissect_InitiatingMessageValue);

  return offset;
}


static const per_sequence_t InitiatingMessage_sequence[] = {
  { &hf_xnap_procedureCode  , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_xnap_ProcedureCode },
  { &hf_xnap_criticality    , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_xnap_Criticality },
  { &hf_xnap_initiatingMessage_value, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_xnap_InitiatingMessage_value },
  { NULL, 0, 0, NULL }
};

static int
dissect_xnap_InitiatingMessage(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_xnap_InitiatingMessage, InitiatingMessage_sequence);

  return offset;
}



static int
dissect_xnap_SuccessfulOutcome_value(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 76 "./asn1/xnap/xnap.cnf"
  struct xnap_private_data *xnap_data = xnap_get_private_data(actx->pinfo);
  xnap_data->message_type = SUCCESSFUL_OUTCOME;


  offset = dissect_per_open_type_pdu_new(tvb, offset, actx, tree, hf_index, dissect_SuccessfulOutcomeValue);

  return offset;
}


static const per_sequence_t SuccessfulOutcome_sequence[] = {
  { &hf_xnap_procedureCode  , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_xnap_ProcedureCode },
  { &hf_xnap_criticality    , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_xnap_Criticality },
  { &hf_xnap_successfulOutcome_value, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_xnap_SuccessfulOutcome_value },
  { NULL, 0, 0, NULL }
};

static int
dissect_xnap_SuccessfulOutcome(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_xnap_SuccessfulOutcome, SuccessfulOutcome_sequence);

  return offset;
}



static int
dissect_xnap_UnsuccessfulOutcome_value(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 81 "./asn1/xnap/xnap.cnf"
  struct xnap_private_data *xnap_data = xnap_get_private_data(actx->pinfo);
  xnap_data->message_type = UNSUCCESSFUL_OUTCOME;


  offset = dissect_per_open_type_pdu_new(tvb, offset, actx, tree, hf_index, dissect_UnsuccessfulOutcomeValue);

  return offset;
}


static const per_sequence_t UnsuccessfulOutcome_sequence[] = {
  { &hf_xnap_procedureCode  , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_xnap_ProcedureCode },
  { &hf_xnap_criticality    , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_xnap_Criticality },
  { &hf_xnap_value          , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_xnap_UnsuccessfulOutcome_value },
  { NULL, 0, 0, NULL }
};

static int
dissect_xnap_UnsuccessfulOutcome(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_xnap_UnsuccessfulOutcome, UnsuccessfulOutcome_sequence);

  return offset;
}


static const value_string xnap_XnAP_PDU_vals[] = {
  {   0, "initiatingMessage" },
  {   1, "successfulOutcome" },
  {   2, "unsuccessfulOutcome" },
  { 0, NULL }
};

static const per_choice_t XnAP_PDU_choice[] = {
  {   0, &hf_xnap_initiatingMessage, ASN1_EXTENSION_ROOT    , dissect_xnap_InitiatingMessage },
  {   1, &hf_xnap_successfulOutcome, ASN1_EXTENSION_ROOT    , dissect_xnap_SuccessfulOutcome },
  {   2, &hf_xnap_unsuccessfulOutcome, ASN1_EXTENSION_ROOT    , dissect_xnap_UnsuccessfulOutcome },
  { 0, NULL, 0, NULL }
};

static int
dissect_xnap_XnAP_PDU(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_xnap_XnAP_PDU, XnAP_PDU_choice,
                                 NULL);

  return offset;
}

/*--- PDUs ---*/

static int dissect_Additional_UL_NG_U_TNLatUPF_List_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_xnap_Additional_UL_NG_U_TNLatUPF_List(tvb, offset, &asn1_ctx, tree, hf_xnap_Additional_UL_NG_U_TNLatUPF_List_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_ActivationIDforCellActivation_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_xnap_ActivationIDforCellActivation(tvb, offset, &asn1_ctx, tree, hf_xnap_ActivationIDforCellActivation_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_AMF_Region_Information_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_xnap_AMF_Region_Information(tvb, offset, &asn1_ctx, tree, hf_xnap_AMF_Region_Information_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_AssistanceDataForRANPaging_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_xnap_AssistanceDataForRANPaging(tvb, offset, &asn1_ctx, tree, hf_xnap_AssistanceDataForRANPaging_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_BPLMN_ID_Info_EUTRA_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_xnap_BPLMN_ID_Info_EUTRA(tvb, offset, &asn1_ctx, tree, hf_xnap_BPLMN_ID_Info_EUTRA_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_BPLMN_ID_Info_NR_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_xnap_BPLMN_ID_Info_NR(tvb, offset, &asn1_ctx, tree, hf_xnap_BPLMN_ID_Info_NR_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_BitRate_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_xnap_BitRate(tvb, offset, &asn1_ctx, tree, hf_xnap_BitRate_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_Cause_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_xnap_Cause(tvb, offset, &asn1_ctx, tree, hf_xnap_Cause_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_CellAssistanceInfo_NR_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_xnap_CellAssistanceInfo_NR(tvb, offset, &asn1_ctx, tree, hf_xnap_CellAssistanceInfo_NR_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_CriticalityDiagnostics_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_xnap_CriticalityDiagnostics(tvb, offset, &asn1_ctx, tree, hf_xnap_CriticalityDiagnostics_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_XnUAddressInfoperPDUSession_List_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_xnap_XnUAddressInfoperPDUSession_List(tvb, offset, &asn1_ctx, tree, hf_xnap_XnUAddressInfoperPDUSession_List_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_DesiredActNotificationLevel_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_xnap_DesiredActNotificationLevel(tvb, offset, &asn1_ctx, tree, hf_xnap_DesiredActNotificationLevel_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_DefaultDRB_Allowed_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_xnap_DefaultDRB_Allowed(tvb, offset, &asn1_ctx, tree, hf_xnap_DefaultDRB_Allowed_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_DRB_List_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_xnap_DRB_List(tvb, offset, &asn1_ctx, tree, hf_xnap_DRB_List_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_DRB_List_withCause_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_xnap_DRB_List_withCause(tvb, offset, &asn1_ctx, tree, hf_xnap_DRB_List_withCause_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_DRB_Number_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_xnap_DRB_Number(tvb, offset, &asn1_ctx, tree, hf_xnap_DRB_Number_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_DRBsSubjectToStatusTransfer_List_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_xnap_DRBsSubjectToStatusTransfer_List(tvb, offset, &asn1_ctx, tree, hf_xnap_DRBsSubjectToStatusTransfer_List_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_EndpointIPAddressAndPort_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_xnap_EndpointIPAddressAndPort(tvb, offset, &asn1_ctx, tree, hf_xnap_EndpointIPAddressAndPort_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_ExpectedUEBehaviour_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_xnap_ExpectedUEBehaviour(tvb, offset, &asn1_ctx, tree, hf_xnap_ExpectedUEBehaviour_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_FiveGCMobilityRestrictionListContainer_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_xnap_FiveGCMobilityRestrictionListContainer(tvb, offset, &asn1_ctx, tree, hf_xnap_FiveGCMobilityRestrictionListContainer_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_GlobalNG_RANCell_ID_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_xnap_GlobalNG_RANCell_ID(tvb, offset, &asn1_ctx, tree, hf_xnap_GlobalNG_RANCell_ID_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_GlobalNG_RANNode_ID_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_xnap_GlobalNG_RANNode_ID(tvb, offset, &asn1_ctx, tree, hf_xnap_GlobalNG_RANNode_ID_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_GUAMI_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_xnap_GUAMI(tvb, offset, &asn1_ctx, tree, hf_xnap_GUAMI_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_InterfaceInstanceIndication_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_xnap_InterfaceInstanceIndication(tvb, offset, &asn1_ctx, tree, hf_xnap_InterfaceInstanceIndication_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_LocationInformationSNReporting_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_xnap_LocationInformationSNReporting(tvb, offset, &asn1_ctx, tree, hf_xnap_LocationInformationSNReporting_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_LocationReportingInformation_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_xnap_LocationReportingInformation(tvb, offset, &asn1_ctx, tree, hf_xnap_LocationReportingInformation_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_MAC_I_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_xnap_MAC_I(tvb, offset, &asn1_ctx, tree, hf_xnap_MAC_I_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_MaskedIMEISV_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_xnap_MaskedIMEISV(tvb, offset, &asn1_ctx, tree, hf_xnap_MaskedIMEISV_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_MaxIPrate_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_xnap_MaxIPrate(tvb, offset, &asn1_ctx, tree, hf_xnap_MaxIPrate_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_MobilityRestrictionList_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_xnap_MobilityRestrictionList(tvb, offset, &asn1_ctx, tree, hf_xnap_MobilityRestrictionList_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_CNTypeRestrictionsForEquivalent_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_xnap_CNTypeRestrictionsForEquivalent(tvb, offset, &asn1_ctx, tree, hf_xnap_CNTypeRestrictionsForEquivalent_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_CNTypeRestrictionsForServing_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_xnap_CNTypeRestrictionsForServing(tvb, offset, &asn1_ctx, tree, hf_xnap_CNTypeRestrictionsForServing_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_MR_DC_ResourceCoordinationInfo_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_xnap_MR_DC_ResourceCoordinationInfo(tvb, offset, &asn1_ctx, tree, hf_xnap_MR_DC_ResourceCoordinationInfo_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_NE_DC_TDM_Pattern_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_xnap_NE_DC_TDM_Pattern(tvb, offset, &asn1_ctx, tree, hf_xnap_NE_DC_TDM_Pattern_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_NG_RAN_Cell_Identity_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_xnap_NG_RAN_Cell_Identity(tvb, offset, &asn1_ctx, tree, hf_xnap_NG_RAN_Cell_Identity_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_NG_RANnodeUEXnAPID_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_xnap_NG_RANnodeUEXnAPID(tvb, offset, &asn1_ctx, tree, hf_xnap_NG_RANnodeUEXnAPID_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_PagingDRX_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_xnap_PagingDRX(tvb, offset, &asn1_ctx, tree, hf_xnap_PagingDRX_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_PagingPriority_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_xnap_PagingPriority(tvb, offset, &asn1_ctx, tree, hf_xnap_PagingPriority_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_PDCPChangeIndication_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_xnap_PDCPChangeIndication(tvb, offset, &asn1_ctx, tree, hf_xnap_PDCPChangeIndication_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_PDUSession_List_withCause_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_xnap_PDUSession_List_withCause(tvb, offset, &asn1_ctx, tree, hf_xnap_PDUSession_List_withCause_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_PDUSessionResourcesAdmitted_List_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_xnap_PDUSessionResourcesAdmitted_List(tvb, offset, &asn1_ctx, tree, hf_xnap_PDUSessionResourcesAdmitted_List_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_PDUSessionResourcesNotAdmitted_List_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_xnap_PDUSessionResourcesNotAdmitted_List(tvb, offset, &asn1_ctx, tree, hf_xnap_PDUSessionResourcesNotAdmitted_List_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_PDUSessionResourceSecondaryRATUsageList_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_xnap_PDUSessionResourceSecondaryRATUsageList(tvb, offset, &asn1_ctx, tree, hf_xnap_PDUSessionResourceSecondaryRATUsageList_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_PDUSessionCommonNetworkInstance_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_xnap_PDUSessionCommonNetworkInstance(tvb, offset, &asn1_ctx, tree, hf_xnap_PDUSessionCommonNetworkInstance_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_PLMN_Identity_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_xnap_PLMN_Identity(tvb, offset, &asn1_ctx, tree, hf_xnap_PLMN_Identity_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_QoSFlows_List_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_xnap_QoSFlows_List(tvb, offset, &asn1_ctx, tree, hf_xnap_QoSFlows_List_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_RANPagingArea_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_xnap_RANPagingArea(tvb, offset, &asn1_ctx, tree, hf_xnap_RANPagingArea_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_RANPagingFailure_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_xnap_RANPagingFailure(tvb, offset, &asn1_ctx, tree, hf_xnap_RANPagingFailure_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_ResetRequestTypeInfo_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_xnap_ResetRequestTypeInfo(tvb, offset, &asn1_ctx, tree, hf_xnap_ResetRequestTypeInfo_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_ResetResponseTypeInfo_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_xnap_ResetResponseTypeInfo(tvb, offset, &asn1_ctx, tree, hf_xnap_ResetResponseTypeInfo_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_RFSP_Index_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_xnap_RFSP_Index(tvb, offset, &asn1_ctx, tree, hf_xnap_RFSP_Index_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_RRCConfigIndication_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_xnap_RRCConfigIndication(tvb, offset, &asn1_ctx, tree, hf_xnap_RRCConfigIndication_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_RRCResumeCause_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_xnap_RRCResumeCause(tvb, offset, &asn1_ctx, tree, hf_xnap_RRCResumeCause_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_SecondarydataForwardingInfoFromTarget_List_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_xnap_SecondarydataForwardingInfoFromTarget_List(tvb, offset, &asn1_ctx, tree, hf_xnap_SecondarydataForwardingInfoFromTarget_List_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_SCGConfigurationQuery_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_xnap_SCGConfigurationQuery(tvb, offset, &asn1_ctx, tree, hf_xnap_SCGConfigurationQuery_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_SecurityResult_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_xnap_SecurityResult(tvb, offset, &asn1_ctx, tree, hf_xnap_SecurityResult_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_ServedCells_E_UTRA_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_xnap_ServedCells_E_UTRA(tvb, offset, &asn1_ctx, tree, hf_xnap_ServedCells_E_UTRA_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_ServedCellsToUpdate_E_UTRA_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_xnap_ServedCellsToUpdate_E_UTRA(tvb, offset, &asn1_ctx, tree, hf_xnap_ServedCellsToUpdate_E_UTRA_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_ServedCells_NR_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_xnap_ServedCells_NR(tvb, offset, &asn1_ctx, tree, hf_xnap_ServedCells_NR_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_ServedCellsToUpdate_NR_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_xnap_ServedCellsToUpdate_NR(tvb, offset, &asn1_ctx, tree, hf_xnap_ServedCellsToUpdate_NR_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_S_NG_RANnode_SecurityKey_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_xnap_S_NG_RANnode_SecurityKey(tvb, offset, &asn1_ctx, tree, hf_xnap_S_NG_RANnode_SecurityKey_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_S_NG_RANnode_Addition_Trigger_Ind_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_xnap_S_NG_RANnode_Addition_Trigger_Ind(tvb, offset, &asn1_ctx, tree, hf_xnap_S_NG_RANnode_Addition_Trigger_Ind_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_S_NSSAI_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_xnap_S_NSSAI(tvb, offset, &asn1_ctx, tree, hf_xnap_S_NSSAI_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_SplitSessionIndicator_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_xnap_SplitSessionIndicator(tvb, offset, &asn1_ctx, tree, hf_xnap_SplitSessionIndicator_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_SplitSRBsTypes_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_xnap_SplitSRBsTypes(tvb, offset, &asn1_ctx, tree, hf_xnap_SplitSRBsTypes_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_TAISupport_List_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_xnap_TAISupport_List(tvb, offset, &asn1_ctx, tree, hf_xnap_TAISupport_List_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_Target_CGI_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_xnap_Target_CGI(tvb, offset, &asn1_ctx, tree, hf_xnap_Target_CGI_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_TimeToWait_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_xnap_TimeToWait(tvb, offset, &asn1_ctx, tree, hf_xnap_TimeToWait_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_TNLA_To_Add_List_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_xnap_TNLA_To_Add_List(tvb, offset, &asn1_ctx, tree, hf_xnap_TNLA_To_Add_List_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_TNLA_To_Update_List_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_xnap_TNLA_To_Update_List(tvb, offset, &asn1_ctx, tree, hf_xnap_TNLA_To_Update_List_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_TNLA_To_Remove_List_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_xnap_TNLA_To_Remove_List(tvb, offset, &asn1_ctx, tree, hf_xnap_TNLA_To_Remove_List_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_TNLA_Setup_List_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_xnap_TNLA_Setup_List(tvb, offset, &asn1_ctx, tree, hf_xnap_TNLA_Setup_List_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_TNLA_Failed_To_Setup_List_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_xnap_TNLA_Failed_To_Setup_List(tvb, offset, &asn1_ctx, tree, hf_xnap_TNLA_Failed_To_Setup_List_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_TraceActivation_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_xnap_TraceActivation(tvb, offset, &asn1_ctx, tree, hf_xnap_TraceActivation_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_UEAggregateMaximumBitRate_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_xnap_UEAggregateMaximumBitRate(tvb, offset, &asn1_ctx, tree, hf_xnap_UEAggregateMaximumBitRate_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_UEContextKeptIndicator_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_xnap_UEContextKeptIndicator(tvb, offset, &asn1_ctx, tree, hf_xnap_UEContextKeptIndicator_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_UEContextID_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_xnap_UEContextID(tvb, offset, &asn1_ctx, tree, hf_xnap_UEContextID_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_UEContextInfoRetrUECtxtResp_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_xnap_UEContextInfoRetrUECtxtResp(tvb, offset, &asn1_ctx, tree, hf_xnap_UEContextInfoRetrUECtxtResp_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_UEHistoryInformation_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_xnap_UEHistoryInformation(tvb, offset, &asn1_ctx, tree, hf_xnap_UEHistoryInformation_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_UEIdentityIndexValue_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_xnap_UEIdentityIndexValue(tvb, offset, &asn1_ctx, tree, hf_xnap_UEIdentityIndexValue_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_UERadioCapabilityForPaging_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_xnap_UERadioCapabilityForPaging(tvb, offset, &asn1_ctx, tree, hf_xnap_UERadioCapabilityForPaging_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_UERANPagingIdentity_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_xnap_UERANPagingIdentity(tvb, offset, &asn1_ctx, tree, hf_xnap_UERANPagingIdentity_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_UESecurityCapabilities_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_xnap_UESecurityCapabilities(tvb, offset, &asn1_ctx, tree, hf_xnap_UESecurityCapabilities_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_ULForwardingProposal_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_xnap_ULForwardingProposal(tvb, offset, &asn1_ctx, tree, hf_xnap_ULForwardingProposal_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_UPTransportLayerInformation_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_xnap_UPTransportLayerInformation(tvb, offset, &asn1_ctx, tree, hf_xnap_UPTransportLayerInformation_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_UserPlaneTrafficActivityReport_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_xnap_UserPlaneTrafficActivityReport(tvb, offset, &asn1_ctx, tree, hf_xnap_UserPlaneTrafficActivityReport_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_XnBenefitValue_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_xnap_XnBenefitValue(tvb, offset, &asn1_ctx, tree, hf_xnap_XnBenefitValue_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_HandoverRequest_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_xnap_HandoverRequest(tvb, offset, &asn1_ctx, tree, hf_xnap_HandoverRequest_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_UEContextInfoHORequest_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_xnap_UEContextInfoHORequest(tvb, offset, &asn1_ctx, tree, hf_xnap_UEContextInfoHORequest_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_UEContextRefAtSN_HORequest_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_xnap_UEContextRefAtSN_HORequest(tvb, offset, &asn1_ctx, tree, hf_xnap_UEContextRefAtSN_HORequest_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_HandoverRequestAcknowledge_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_xnap_HandoverRequestAcknowledge(tvb, offset, &asn1_ctx, tree, hf_xnap_HandoverRequestAcknowledge_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_Target2SourceNG_RANnodeTranspContainer_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_xnap_Target2SourceNG_RANnodeTranspContainer(tvb, offset, &asn1_ctx, tree, hf_xnap_Target2SourceNG_RANnodeTranspContainer_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_HandoverPreparationFailure_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_xnap_HandoverPreparationFailure(tvb, offset, &asn1_ctx, tree, hf_xnap_HandoverPreparationFailure_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_SNStatusTransfer_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_xnap_SNStatusTransfer(tvb, offset, &asn1_ctx, tree, hf_xnap_SNStatusTransfer_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_UEContextRelease_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_xnap_UEContextRelease(tvb, offset, &asn1_ctx, tree, hf_xnap_UEContextRelease_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_HandoverCancel_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_xnap_HandoverCancel(tvb, offset, &asn1_ctx, tree, hf_xnap_HandoverCancel_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_RANPaging_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_xnap_RANPaging(tvb, offset, &asn1_ctx, tree, hf_xnap_RANPaging_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_RetrieveUEContextRequest_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_xnap_RetrieveUEContextRequest(tvb, offset, &asn1_ctx, tree, hf_xnap_RetrieveUEContextRequest_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_RetrieveUEContextResponse_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_xnap_RetrieveUEContextResponse(tvb, offset, &asn1_ctx, tree, hf_xnap_RetrieveUEContextResponse_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_RetrieveUEContextFailure_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_xnap_RetrieveUEContextFailure(tvb, offset, &asn1_ctx, tree, hf_xnap_RetrieveUEContextFailure_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_OldtoNewNG_RANnodeResumeContainer_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_xnap_OldtoNewNG_RANnodeResumeContainer(tvb, offset, &asn1_ctx, tree, hf_xnap_OldtoNewNG_RANnodeResumeContainer_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_XnUAddressIndication_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_xnap_XnUAddressIndication(tvb, offset, &asn1_ctx, tree, hf_xnap_XnUAddressIndication_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_SNodeAdditionRequest_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_xnap_SNodeAdditionRequest(tvb, offset, &asn1_ctx, tree, hf_xnap_SNodeAdditionRequest_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_MN_to_SN_Container_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_xnap_MN_to_SN_Container(tvb, offset, &asn1_ctx, tree, hf_xnap_MN_to_SN_Container_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_PDUSessionToBeAddedAddReq_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_xnap_PDUSessionToBeAddedAddReq(tvb, offset, &asn1_ctx, tree, hf_xnap_PDUSessionToBeAddedAddReq_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_SNodeAdditionRequestAcknowledge_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_xnap_SNodeAdditionRequestAcknowledge(tvb, offset, &asn1_ctx, tree, hf_xnap_SNodeAdditionRequestAcknowledge_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_SN_to_MN_Container_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_xnap_SN_to_MN_Container(tvb, offset, &asn1_ctx, tree, hf_xnap_SN_to_MN_Container_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_PDUSessionAdmittedAddedAddReqAck_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_xnap_PDUSessionAdmittedAddedAddReqAck(tvb, offset, &asn1_ctx, tree, hf_xnap_PDUSessionAdmittedAddedAddReqAck_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_PDUSessionNotAdmittedAddReqAck_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_xnap_PDUSessionNotAdmittedAddReqAck(tvb, offset, &asn1_ctx, tree, hf_xnap_PDUSessionNotAdmittedAddReqAck_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_SNodeAdditionRequestReject_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_xnap_SNodeAdditionRequestReject(tvb, offset, &asn1_ctx, tree, hf_xnap_SNodeAdditionRequestReject_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_SNodeReconfigurationComplete_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_xnap_SNodeReconfigurationComplete(tvb, offset, &asn1_ctx, tree, hf_xnap_SNodeReconfigurationComplete_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_ResponseInfo_ReconfCompl_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_xnap_ResponseInfo_ReconfCompl(tvb, offset, &asn1_ctx, tree, hf_xnap_ResponseInfo_ReconfCompl_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_SNodeModificationRequest_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_xnap_SNodeModificationRequest(tvb, offset, &asn1_ctx, tree, hf_xnap_SNodeModificationRequest_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_UEContextInfo_SNModRequest_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_xnap_UEContextInfo_SNModRequest(tvb, offset, &asn1_ctx, tree, hf_xnap_UEContextInfo_SNModRequest_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_SNodeModificationRequestAcknowledge_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_xnap_SNodeModificationRequestAcknowledge(tvb, offset, &asn1_ctx, tree, hf_xnap_SNodeModificationRequestAcknowledge_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_PDUSessionAdmitted_SNModResponse_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_xnap_PDUSessionAdmitted_SNModResponse(tvb, offset, &asn1_ctx, tree, hf_xnap_PDUSessionAdmitted_SNModResponse_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_PDUSessionNotAdmitted_SNModResponse_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_xnap_PDUSessionNotAdmitted_SNModResponse(tvb, offset, &asn1_ctx, tree, hf_xnap_PDUSessionNotAdmitted_SNModResponse_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_PDUSessionDataForwarding_SNModResponse_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_xnap_PDUSessionDataForwarding_SNModResponse(tvb, offset, &asn1_ctx, tree, hf_xnap_PDUSessionDataForwarding_SNModResponse_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_SNodeModificationRequestReject_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_xnap_SNodeModificationRequestReject(tvb, offset, &asn1_ctx, tree, hf_xnap_SNodeModificationRequestReject_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_SNodeModificationRequired_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_xnap_SNodeModificationRequired(tvb, offset, &asn1_ctx, tree, hf_xnap_SNodeModificationRequired_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_PDUSessionToBeModifiedSNModRequired_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_xnap_PDUSessionToBeModifiedSNModRequired(tvb, offset, &asn1_ctx, tree, hf_xnap_PDUSessionToBeModifiedSNModRequired_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_PDUSessionToBeReleasedSNModRequired_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_xnap_PDUSessionToBeReleasedSNModRequired(tvb, offset, &asn1_ctx, tree, hf_xnap_PDUSessionToBeReleasedSNModRequired_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_SNodeModificationConfirm_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_xnap_SNodeModificationConfirm(tvb, offset, &asn1_ctx, tree, hf_xnap_SNodeModificationConfirm_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_PDUSessionAdmittedModSNModConfirm_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_xnap_PDUSessionAdmittedModSNModConfirm(tvb, offset, &asn1_ctx, tree, hf_xnap_PDUSessionAdmittedModSNModConfirm_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_PDUSessionReleasedSNModConfirm_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_xnap_PDUSessionReleasedSNModConfirm(tvb, offset, &asn1_ctx, tree, hf_xnap_PDUSessionReleasedSNModConfirm_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_SNodeModificationRefuse_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_xnap_SNodeModificationRefuse(tvb, offset, &asn1_ctx, tree, hf_xnap_SNodeModificationRefuse_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_SNodeReleaseRequest_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_xnap_SNodeReleaseRequest(tvb, offset, &asn1_ctx, tree, hf_xnap_SNodeReleaseRequest_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_SNodeReleaseRequestAcknowledge_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_xnap_SNodeReleaseRequestAcknowledge(tvb, offset, &asn1_ctx, tree, hf_xnap_SNodeReleaseRequestAcknowledge_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_PDUSessionToBeReleasedList_RelReqAck_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_xnap_PDUSessionToBeReleasedList_RelReqAck(tvb, offset, &asn1_ctx, tree, hf_xnap_PDUSessionToBeReleasedList_RelReqAck_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_SNodeReleaseReject_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_xnap_SNodeReleaseReject(tvb, offset, &asn1_ctx, tree, hf_xnap_SNodeReleaseReject_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_SNodeReleaseRequired_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_xnap_SNodeReleaseRequired(tvb, offset, &asn1_ctx, tree, hf_xnap_SNodeReleaseRequired_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_PDUSessionToBeReleasedList_RelRqd_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_xnap_PDUSessionToBeReleasedList_RelRqd(tvb, offset, &asn1_ctx, tree, hf_xnap_PDUSessionToBeReleasedList_RelRqd_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_SNodeReleaseConfirm_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_xnap_SNodeReleaseConfirm(tvb, offset, &asn1_ctx, tree, hf_xnap_SNodeReleaseConfirm_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_PDUSessionReleasedList_RelConf_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_xnap_PDUSessionReleasedList_RelConf(tvb, offset, &asn1_ctx, tree, hf_xnap_PDUSessionReleasedList_RelConf_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_SNodeCounterCheckRequest_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_xnap_SNodeCounterCheckRequest(tvb, offset, &asn1_ctx, tree, hf_xnap_SNodeCounterCheckRequest_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_BearersSubjectToCounterCheck_List_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_xnap_BearersSubjectToCounterCheck_List(tvb, offset, &asn1_ctx, tree, hf_xnap_BearersSubjectToCounterCheck_List_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_SNodeChangeRequired_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_xnap_SNodeChangeRequired(tvb, offset, &asn1_ctx, tree, hf_xnap_SNodeChangeRequired_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_PDUSession_SNChangeRequired_List_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_xnap_PDUSession_SNChangeRequired_List(tvb, offset, &asn1_ctx, tree, hf_xnap_PDUSession_SNChangeRequired_List_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_SNodeChangeConfirm_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_xnap_SNodeChangeConfirm(tvb, offset, &asn1_ctx, tree, hf_xnap_SNodeChangeConfirm_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_PDUSession_SNChangeConfirm_List_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_xnap_PDUSession_SNChangeConfirm_List(tvb, offset, &asn1_ctx, tree, hf_xnap_PDUSession_SNChangeConfirm_List_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_SNodeChangeRefuse_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_xnap_SNodeChangeRefuse(tvb, offset, &asn1_ctx, tree, hf_xnap_SNodeChangeRefuse_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_RRCTransfer_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_xnap_RRCTransfer(tvb, offset, &asn1_ctx, tree, hf_xnap_RRCTransfer_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_SplitSRB_RRCTransfer_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_xnap_SplitSRB_RRCTransfer(tvb, offset, &asn1_ctx, tree, hf_xnap_SplitSRB_RRCTransfer_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_UEReportRRCTransfer_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_xnap_UEReportRRCTransfer(tvb, offset, &asn1_ctx, tree, hf_xnap_UEReportRRCTransfer_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_NotificationControlIndication_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_xnap_NotificationControlIndication(tvb, offset, &asn1_ctx, tree, hf_xnap_NotificationControlIndication_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_PDUSessionResourcesNotifyList_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_xnap_PDUSessionResourcesNotifyList(tvb, offset, &asn1_ctx, tree, hf_xnap_PDUSessionResourcesNotifyList_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_ActivityNotification_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_xnap_ActivityNotification(tvb, offset, &asn1_ctx, tree, hf_xnap_ActivityNotification_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_PDUSessionResourcesActivityNotifyList_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_xnap_PDUSessionResourcesActivityNotifyList(tvb, offset, &asn1_ctx, tree, hf_xnap_PDUSessionResourcesActivityNotifyList_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_XnSetupRequest_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_xnap_XnSetupRequest(tvb, offset, &asn1_ctx, tree, hf_xnap_XnSetupRequest_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_XnSetupResponse_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_xnap_XnSetupResponse(tvb, offset, &asn1_ctx, tree, hf_xnap_XnSetupResponse_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_XnSetupFailure_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_xnap_XnSetupFailure(tvb, offset, &asn1_ctx, tree, hf_xnap_XnSetupFailure_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_NGRANNodeConfigurationUpdate_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_xnap_NGRANNodeConfigurationUpdate(tvb, offset, &asn1_ctx, tree, hf_xnap_NGRANNodeConfigurationUpdate_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_ConfigurationUpdateInitiatingNodeChoice_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_xnap_ConfigurationUpdateInitiatingNodeChoice(tvb, offset, &asn1_ctx, tree, hf_xnap_ConfigurationUpdateInitiatingNodeChoice_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_NGRANNodeConfigurationUpdateAcknowledge_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_xnap_NGRANNodeConfigurationUpdateAcknowledge(tvb, offset, &asn1_ctx, tree, hf_xnap_NGRANNodeConfigurationUpdateAcknowledge_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_RespondingNodeTypeConfigUpdateAck_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_xnap_RespondingNodeTypeConfigUpdateAck(tvb, offset, &asn1_ctx, tree, hf_xnap_RespondingNodeTypeConfigUpdateAck_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_NGRANNodeConfigurationUpdateFailure_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_xnap_NGRANNodeConfigurationUpdateFailure(tvb, offset, &asn1_ctx, tree, hf_xnap_NGRANNodeConfigurationUpdateFailure_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_E_UTRA_NR_CellResourceCoordinationRequest_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_xnap_E_UTRA_NR_CellResourceCoordinationRequest(tvb, offset, &asn1_ctx, tree, hf_xnap_E_UTRA_NR_CellResourceCoordinationRequest_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_InitiatingNodeType_ResourceCoordRequest_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_xnap_InitiatingNodeType_ResourceCoordRequest(tvb, offset, &asn1_ctx, tree, hf_xnap_InitiatingNodeType_ResourceCoordRequest_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_E_UTRA_NR_CellResourceCoordinationResponse_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_xnap_E_UTRA_NR_CellResourceCoordinationResponse(tvb, offset, &asn1_ctx, tree, hf_xnap_E_UTRA_NR_CellResourceCoordinationResponse_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_RespondingNodeType_ResourceCoordResponse_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_xnap_RespondingNodeType_ResourceCoordResponse(tvb, offset, &asn1_ctx, tree, hf_xnap_RespondingNodeType_ResourceCoordResponse_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_SecondaryRATDataUsageReport_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_xnap_SecondaryRATDataUsageReport(tvb, offset, &asn1_ctx, tree, hf_xnap_SecondaryRATDataUsageReport_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_XnRemovalRequest_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_xnap_XnRemovalRequest(tvb, offset, &asn1_ctx, tree, hf_xnap_XnRemovalRequest_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_XnRemovalResponse_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_xnap_XnRemovalResponse(tvb, offset, &asn1_ctx, tree, hf_xnap_XnRemovalResponse_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_XnRemovalFailure_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_xnap_XnRemovalFailure(tvb, offset, &asn1_ctx, tree, hf_xnap_XnRemovalFailure_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_CellActivationRequest_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_xnap_CellActivationRequest(tvb, offset, &asn1_ctx, tree, hf_xnap_CellActivationRequest_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_ServedCellsToActivate_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_xnap_ServedCellsToActivate(tvb, offset, &asn1_ctx, tree, hf_xnap_ServedCellsToActivate_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_CellActivationResponse_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_xnap_CellActivationResponse(tvb, offset, &asn1_ctx, tree, hf_xnap_CellActivationResponse_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_ActivatedServedCells_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_xnap_ActivatedServedCells(tvb, offset, &asn1_ctx, tree, hf_xnap_ActivatedServedCells_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_CellActivationFailure_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_xnap_CellActivationFailure(tvb, offset, &asn1_ctx, tree, hf_xnap_CellActivationFailure_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_ResetRequest_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_xnap_ResetRequest(tvb, offset, &asn1_ctx, tree, hf_xnap_ResetRequest_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_ResetResponse_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_xnap_ResetResponse(tvb, offset, &asn1_ctx, tree, hf_xnap_ResetResponse_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_ErrorIndication_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_xnap_ErrorIndication(tvb, offset, &asn1_ctx, tree, hf_xnap_ErrorIndication_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_PrivateMessage_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_xnap_PrivateMessage(tvb, offset, &asn1_ctx, tree, hf_xnap_PrivateMessage_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_XnAP_PDU_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_xnap_XnAP_PDU(tvb, offset, &asn1_ctx, tree, hf_xnap_XnAP_PDU_PDU);
  offset += 7; offset >>= 3;
  return offset;
}


/*--- End of included file: packet-xnap-fn.c ---*/
#line 170 "./asn1/xnap/packet-xnap-template.c"

static int dissect_ProtocolIEFieldValue(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
  struct xnap_private_data *xnap_data = xnap_get_private_data(pinfo);

  return (dissector_try_uint_new(xnap_ies_dissector_table, xnap_data->protocol_ie_id, tvb, pinfo, tree, FALSE, NULL)) ? tvb_captured_length(tvb) : 0;
}

static int dissect_ProtocolExtensionFieldExtensionValue(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
  struct xnap_private_data *xnap_data = xnap_get_private_data(pinfo);

  return (dissector_try_uint_new(xnap_extension_dissector_table, xnap_data->protocol_ie_id, tvb, pinfo, tree, FALSE, NULL)) ? tvb_captured_length(tvb) : 0;
}

static int dissect_InitiatingMessageValue(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
  struct xnap_private_data *xnap_data = xnap_get_private_data(pinfo);

  return (dissector_try_uint_new(xnap_proc_imsg_dissector_table, xnap_data->procedure_code, tvb, pinfo, tree, FALSE, NULL)) ? tvb_captured_length(tvb) : 0;
}

static int dissect_SuccessfulOutcomeValue(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
  struct xnap_private_data *xnap_data = xnap_get_private_data(pinfo);

  return (dissector_try_uint_new(xnap_proc_sout_dissector_table, xnap_data->procedure_code, tvb, pinfo, tree, FALSE, NULL)) ? tvb_captured_length(tvb) : 0;
}

static int dissect_UnsuccessfulOutcomeValue(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
  struct xnap_private_data *xnap_data = xnap_get_private_data(pinfo);

  return (dissector_try_uint_new(xnap_proc_uout_dissector_table, xnap_data->procedure_code, tvb, pinfo, tree, FALSE, NULL)) ? tvb_captured_length(tvb) : 0;
}

static int
dissect_xnap(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data)
{
  proto_item *xnap_item;
  proto_tree *xnap_tree;
  conversation_t *conversation;
  struct xnap_private_data* xnap_data;

  col_set_str(pinfo->cinfo, COL_PROTOCOL, "XnAP");
  col_clear_fence(pinfo->cinfo, COL_INFO);
  col_clear(pinfo->cinfo, COL_INFO);

  xnap_item = proto_tree_add_item(tree, proto_xnap, tvb, 0, -1, ENC_NA);
  xnap_tree = proto_item_add_subtree(xnap_item, ett_xnap);

  xnap_data = xnap_get_private_data(pinfo);
  conversation = find_or_create_conversation(pinfo);
  xnap_data->xnap_conv = (struct xnap_conv_info *)conversation_get_proto_data(conversation, proto_xnap);
  if (!xnap_data->xnap_conv) {
    xnap_data->xnap_conv = wmem_new0(wmem_file_scope(), struct xnap_conv_info);
    copy_address_wmem(wmem_file_scope(), &xnap_data->xnap_conv->addr_a, &pinfo->src);
    xnap_data->xnap_conv->port_a = pinfo->srcport;
    xnap_data->xnap_conv->ranmode_id_a = (GlobalNG_RANNode_ID_enum)-1;
    copy_address_wmem(wmem_file_scope(), &xnap_data->xnap_conv->addr_b, &pinfo->dst);
    xnap_data->xnap_conv->port_b = pinfo->destport;
    xnap_data->xnap_conv->ranmode_id_b = (GlobalNG_RANNode_ID_enum)-1;
    conversation_add_proto_data(conversation, proto_xnap, xnap_data->xnap_conv);
  }

  return dissect_XnAP_PDU_PDU(tvb, pinfo, xnap_tree, data);
}

void proto_register_xnap(void) {

  /* List of fields */

  static hf_register_info hf[] = {
    { &hf_xnap_transportLayerAddressIPv4,
      { "TransportLayerAddress (IPv4)", "xnap.TransportLayerAddressIPv4",
        FT_IPv4, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_xnap_transportLayerAddressIPv6,
      { "TransportLayerAddress (IPv6)", "xnap.TransportLayerAddressIPv6",
        FT_IPv6, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_xnap_ng_ran_TraceID_TraceID,
      { "TraceID", "xnap.ng_ran_TraceID.TraceID",
        FT_UINT24, BASE_HEX, NULL, 0,
        NULL, HFILL }},
    { &hf_xnap_ng_ran_TraceID_TraceRecordingSessionReference,
      { "TraceRecordingSessionReference", "xnap.ng_ran_TraceID.TraceRecordingSessionReference",
        FT_UINT16, BASE_HEX, NULL, 0,
        NULL, HFILL }},

/*--- Included file: packet-xnap-hfarr.c ---*/
#line 1 "./asn1/xnap/packet-xnap-hfarr.c"
    { &hf_xnap_Additional_UL_NG_U_TNLatUPF_List_PDU,
      { "Additional-UL-NG-U-TNLatUPF-List", "xnap.Additional_UL_NG_U_TNLatUPF_List",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_xnap_ActivationIDforCellActivation_PDU,
      { "ActivationIDforCellActivation", "xnap.ActivationIDforCellActivation",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_xnap_AMF_Region_Information_PDU,
      { "AMF-Region-Information", "xnap.AMF_Region_Information",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_xnap_AssistanceDataForRANPaging_PDU,
      { "AssistanceDataForRANPaging", "xnap.AssistanceDataForRANPaging_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_xnap_BPLMN_ID_Info_EUTRA_PDU,
      { "BPLMN-ID-Info-EUTRA", "xnap.BPLMN_ID_Info_EUTRA",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_xnap_BPLMN_ID_Info_NR_PDU,
      { "BPLMN-ID-Info-NR", "xnap.BPLMN_ID_Info_NR",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_xnap_BitRate_PDU,
      { "BitRate", "xnap.BitRate",
        FT_UINT64, BASE_DEC|BASE_UNIT_STRING, &units_bit_sec, 0,
        NULL, HFILL }},
    { &hf_xnap_Cause_PDU,
      { "Cause", "xnap.Cause",
        FT_UINT32, BASE_DEC, VALS(xnap_Cause_vals), 0,
        NULL, HFILL }},
    { &hf_xnap_CellAssistanceInfo_NR_PDU,
      { "CellAssistanceInfo-NR", "xnap.CellAssistanceInfo_NR",
        FT_UINT32, BASE_DEC, VALS(xnap_CellAssistanceInfo_NR_vals), 0,
        NULL, HFILL }},
    { &hf_xnap_CriticalityDiagnostics_PDU,
      { "CriticalityDiagnostics", "xnap.CriticalityDiagnostics_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_xnap_XnUAddressInfoperPDUSession_List_PDU,
      { "XnUAddressInfoperPDUSession-List", "xnap.XnUAddressInfoperPDUSession_List",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_xnap_DesiredActNotificationLevel_PDU,
      { "DesiredActNotificationLevel", "xnap.DesiredActNotificationLevel",
        FT_UINT32, BASE_DEC, VALS(xnap_DesiredActNotificationLevel_vals), 0,
        NULL, HFILL }},
    { &hf_xnap_DefaultDRB_Allowed_PDU,
      { "DefaultDRB-Allowed", "xnap.DefaultDRB_Allowed",
        FT_UINT32, BASE_DEC, VALS(xnap_DefaultDRB_Allowed_vals), 0,
        NULL, HFILL }},
    { &hf_xnap_DRB_List_PDU,
      { "DRB-List", "xnap.DRB_List",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_xnap_DRB_List_withCause_PDU,
      { "DRB-List-withCause", "xnap.DRB_List_withCause",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_xnap_DRB_Number_PDU,
      { "DRB-Number", "xnap.DRB_Number",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_xnap_DRBsSubjectToStatusTransfer_List_PDU,
      { "DRBsSubjectToStatusTransfer-List", "xnap.DRBsSubjectToStatusTransfer_List",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_xnap_EndpointIPAddressAndPort_PDU,
      { "EndpointIPAddressAndPort", "xnap.EndpointIPAddressAndPort_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_xnap_ExpectedUEBehaviour_PDU,
      { "ExpectedUEBehaviour", "xnap.ExpectedUEBehaviour_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_xnap_FiveGCMobilityRestrictionListContainer_PDU,
      { "FiveGCMobilityRestrictionListContainer", "xnap.FiveGCMobilityRestrictionListContainer",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_xnap_GlobalNG_RANCell_ID_PDU,
      { "GlobalNG-RANCell-ID", "xnap.GlobalNG_RANCell_ID_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_xnap_GlobalNG_RANNode_ID_PDU,
      { "GlobalNG-RANNode-ID", "xnap.GlobalNG_RANNode_ID",
        FT_UINT32, BASE_DEC, VALS(xnap_GlobalNG_RANNode_ID_vals), 0,
        NULL, HFILL }},
    { &hf_xnap_GUAMI_PDU,
      { "GUAMI", "xnap.GUAMI_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_xnap_InterfaceInstanceIndication_PDU,
      { "InterfaceInstanceIndication", "xnap.InterfaceInstanceIndication",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_xnap_LocationInformationSNReporting_PDU,
      { "LocationInformationSNReporting", "xnap.LocationInformationSNReporting",
        FT_UINT32, BASE_DEC, VALS(xnap_LocationInformationSNReporting_vals), 0,
        NULL, HFILL }},
    { &hf_xnap_LocationReportingInformation_PDU,
      { "LocationReportingInformation", "xnap.LocationReportingInformation_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_xnap_MAC_I_PDU,
      { "MAC-I", "xnap.MAC_I",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_xnap_MaskedIMEISV_PDU,
      { "MaskedIMEISV", "xnap.MaskedIMEISV",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_xnap_MaxIPrate_PDU,
      { "MaxIPrate", "xnap.MaxIPrate",
        FT_UINT32, BASE_DEC, VALS(xnap_MaxIPrate_vals), 0,
        NULL, HFILL }},
    { &hf_xnap_MobilityRestrictionList_PDU,
      { "MobilityRestrictionList", "xnap.MobilityRestrictionList_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_xnap_CNTypeRestrictionsForEquivalent_PDU,
      { "CNTypeRestrictionsForEquivalent", "xnap.CNTypeRestrictionsForEquivalent",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_xnap_CNTypeRestrictionsForServing_PDU,
      { "CNTypeRestrictionsForServing", "xnap.CNTypeRestrictionsForServing",
        FT_UINT32, BASE_DEC, VALS(xnap_CNTypeRestrictionsForServing_vals), 0,
        NULL, HFILL }},
    { &hf_xnap_MR_DC_ResourceCoordinationInfo_PDU,
      { "MR-DC-ResourceCoordinationInfo", "xnap.MR_DC_ResourceCoordinationInfo_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_xnap_NE_DC_TDM_Pattern_PDU,
      { "NE-DC-TDM-Pattern", "xnap.NE_DC_TDM_Pattern_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_xnap_NG_RAN_Cell_Identity_PDU,
      { "NG-RAN-Cell-Identity", "xnap.NG_RAN_Cell_Identity",
        FT_UINT32, BASE_DEC, VALS(xnap_NG_RAN_Cell_Identity_vals), 0,
        NULL, HFILL }},
    { &hf_xnap_NG_RANnodeUEXnAPID_PDU,
      { "NG-RANnodeUEXnAPID", "xnap.NG_RANnodeUEXnAPID",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_xnap_PagingDRX_PDU,
      { "PagingDRX", "xnap.PagingDRX",
        FT_UINT32, BASE_DEC, VALS(xnap_PagingDRX_vals), 0,
        NULL, HFILL }},
    { &hf_xnap_PagingPriority_PDU,
      { "PagingPriority", "xnap.PagingPriority",
        FT_UINT32, BASE_DEC, VALS(xnap_PagingPriority_vals), 0,
        NULL, HFILL }},
    { &hf_xnap_PDCPChangeIndication_PDU,
      { "PDCPChangeIndication", "xnap.PDCPChangeIndication",
        FT_UINT32, BASE_DEC, VALS(xnap_PDCPChangeIndication_vals), 0,
        NULL, HFILL }},
    { &hf_xnap_PDUSession_List_withCause_PDU,
      { "PDUSession-List-withCause", "xnap.PDUSession_List_withCause",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_xnap_PDUSessionResourcesAdmitted_List_PDU,
      { "PDUSessionResourcesAdmitted-List", "xnap.PDUSessionResourcesAdmitted_List",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_xnap_PDUSessionResourcesNotAdmitted_List_PDU,
      { "PDUSessionResourcesNotAdmitted-List", "xnap.PDUSessionResourcesNotAdmitted_List",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_xnap_PDUSessionResourceSecondaryRATUsageList_PDU,
      { "PDUSessionResourceSecondaryRATUsageList", "xnap.PDUSessionResourceSecondaryRATUsageList",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_xnap_PDUSessionCommonNetworkInstance_PDU,
      { "PDUSessionCommonNetworkInstance", "xnap.PDUSessionCommonNetworkInstance",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_xnap_PLMN_Identity_PDU,
      { "PLMN-Identity", "xnap.PLMN_Identity",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_xnap_QoSFlows_List_PDU,
      { "QoSFlows-List", "xnap.QoSFlows_List",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_xnap_RANPagingArea_PDU,
      { "RANPagingArea", "xnap.RANPagingArea_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_xnap_RANPagingFailure_PDU,
      { "RANPagingFailure", "xnap.RANPagingFailure",
        FT_UINT32, BASE_DEC, VALS(xnap_RANPagingFailure_vals), 0,
        NULL, HFILL }},
    { &hf_xnap_ResetRequestTypeInfo_PDU,
      { "ResetRequestTypeInfo", "xnap.ResetRequestTypeInfo",
        FT_UINT32, BASE_DEC, VALS(xnap_ResetRequestTypeInfo_vals), 0,
        NULL, HFILL }},
    { &hf_xnap_ResetResponseTypeInfo_PDU,
      { "ResetResponseTypeInfo", "xnap.ResetResponseTypeInfo",
        FT_UINT32, BASE_DEC, VALS(xnap_ResetResponseTypeInfo_vals), 0,
        NULL, HFILL }},
    { &hf_xnap_RFSP_Index_PDU,
      { "RFSP-Index", "xnap.RFSP_Index",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_xnap_RRCConfigIndication_PDU,
      { "RRCConfigIndication", "xnap.RRCConfigIndication",
        FT_UINT32, BASE_DEC, VALS(xnap_RRCConfigIndication_vals), 0,
        NULL, HFILL }},
    { &hf_xnap_RRCResumeCause_PDU,
      { "RRCResumeCause", "xnap.RRCResumeCause",
        FT_UINT32, BASE_DEC, VALS(xnap_RRCResumeCause_vals), 0,
        NULL, HFILL }},
    { &hf_xnap_SecondarydataForwardingInfoFromTarget_List_PDU,
      { "SecondarydataForwardingInfoFromTarget-List", "xnap.SecondarydataForwardingInfoFromTarget_List",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_xnap_SCGConfigurationQuery_PDU,
      { "SCGConfigurationQuery", "xnap.SCGConfigurationQuery",
        FT_UINT32, BASE_DEC, VALS(xnap_SCGConfigurationQuery_vals), 0,
        NULL, HFILL }},
    { &hf_xnap_SecurityResult_PDU,
      { "SecurityResult", "xnap.SecurityResult_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_xnap_ServedCells_E_UTRA_PDU,
      { "ServedCells-E-UTRA", "xnap.ServedCells_E_UTRA",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_xnap_ServedCellsToUpdate_E_UTRA_PDU,
      { "ServedCellsToUpdate-E-UTRA", "xnap.ServedCellsToUpdate_E_UTRA_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_xnap_ServedCells_NR_PDU,
      { "ServedCells-NR", "xnap.ServedCells_NR",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_xnap_ServedCellsToUpdate_NR_PDU,
      { "ServedCellsToUpdate-NR", "xnap.ServedCellsToUpdate_NR_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_xnap_S_NG_RANnode_SecurityKey_PDU,
      { "S-NG-RANnode-SecurityKey", "xnap.S_NG_RANnode_SecurityKey",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_xnap_S_NG_RANnode_Addition_Trigger_Ind_PDU,
      { "S-NG-RANnode-Addition-Trigger-Ind", "xnap.S_NG_RANnode_Addition_Trigger_Ind",
        FT_UINT32, BASE_DEC, VALS(xnap_S_NG_RANnode_Addition_Trigger_Ind_vals), 0,
        NULL, HFILL }},
    { &hf_xnap_S_NSSAI_PDU,
      { "S-NSSAI", "xnap.S_NSSAI_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_xnap_SplitSessionIndicator_PDU,
      { "SplitSessionIndicator", "xnap.SplitSessionIndicator",
        FT_UINT32, BASE_DEC, VALS(xnap_SplitSessionIndicator_vals), 0,
        NULL, HFILL }},
    { &hf_xnap_SplitSRBsTypes_PDU,
      { "SplitSRBsTypes", "xnap.SplitSRBsTypes",
        FT_UINT32, BASE_DEC, VALS(xnap_SplitSRBsTypes_vals), 0,
        NULL, HFILL }},
    { &hf_xnap_TAISupport_List_PDU,
      { "TAISupport-List", "xnap.TAISupport_List",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_xnap_Target_CGI_PDU,
      { "Target-CGI", "xnap.Target_CGI",
        FT_UINT32, BASE_DEC, VALS(xnap_Target_CGI_vals), 0,
        NULL, HFILL }},
    { &hf_xnap_TimeToWait_PDU,
      { "TimeToWait", "xnap.TimeToWait",
        FT_UINT32, BASE_DEC, VALS(xnap_TimeToWait_vals), 0,
        NULL, HFILL }},
    { &hf_xnap_TNLA_To_Add_List_PDU,
      { "TNLA-To-Add-List", "xnap.TNLA_To_Add_List",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_xnap_TNLA_To_Update_List_PDU,
      { "TNLA-To-Update-List", "xnap.TNLA_To_Update_List",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_xnap_TNLA_To_Remove_List_PDU,
      { "TNLA-To-Remove-List", "xnap.TNLA_To_Remove_List",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_xnap_TNLA_Setup_List_PDU,
      { "TNLA-Setup-List", "xnap.TNLA_Setup_List",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_xnap_TNLA_Failed_To_Setup_List_PDU,
      { "TNLA-Failed-To-Setup-List", "xnap.TNLA_Failed_To_Setup_List",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_xnap_TraceActivation_PDU,
      { "TraceActivation", "xnap.TraceActivation_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_xnap_UEAggregateMaximumBitRate_PDU,
      { "UEAggregateMaximumBitRate", "xnap.UEAggregateMaximumBitRate_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_xnap_UEContextKeptIndicator_PDU,
      { "UEContextKeptIndicator", "xnap.UEContextKeptIndicator",
        FT_UINT32, BASE_DEC, VALS(xnap_UEContextKeptIndicator_vals), 0,
        NULL, HFILL }},
    { &hf_xnap_UEContextID_PDU,
      { "UEContextID", "xnap.UEContextID",
        FT_UINT32, BASE_DEC, VALS(xnap_UEContextID_vals), 0,
        NULL, HFILL }},
    { &hf_xnap_UEContextInfoRetrUECtxtResp_PDU,
      { "UEContextInfoRetrUECtxtResp", "xnap.UEContextInfoRetrUECtxtResp_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_xnap_UEHistoryInformation_PDU,
      { "UEHistoryInformation", "xnap.UEHistoryInformation",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_xnap_UEIdentityIndexValue_PDU,
      { "UEIdentityIndexValue", "xnap.UEIdentityIndexValue",
        FT_UINT32, BASE_DEC, VALS(xnap_UEIdentityIndexValue_vals), 0,
        NULL, HFILL }},
    { &hf_xnap_UERadioCapabilityForPaging_PDU,
      { "UERadioCapabilityForPaging", "xnap.UERadioCapabilityForPaging_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_xnap_UERANPagingIdentity_PDU,
      { "UERANPagingIdentity", "xnap.UERANPagingIdentity",
        FT_UINT32, BASE_DEC, VALS(xnap_UERANPagingIdentity_vals), 0,
        NULL, HFILL }},
    { &hf_xnap_UESecurityCapabilities_PDU,
      { "UESecurityCapabilities", "xnap.UESecurityCapabilities_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_xnap_ULForwardingProposal_PDU,
      { "ULForwardingProposal", "xnap.ULForwardingProposal",
        FT_UINT32, BASE_DEC, VALS(xnap_ULForwardingProposal_vals), 0,
        NULL, HFILL }},
    { &hf_xnap_UPTransportLayerInformation_PDU,
      { "UPTransportLayerInformation", "xnap.UPTransportLayerInformation",
        FT_UINT32, BASE_DEC, VALS(xnap_UPTransportLayerInformation_vals), 0,
        NULL, HFILL }},
    { &hf_xnap_UserPlaneTrafficActivityReport_PDU,
      { "UserPlaneTrafficActivityReport", "xnap.UserPlaneTrafficActivityReport",
        FT_UINT32, BASE_DEC, VALS(xnap_UserPlaneTrafficActivityReport_vals), 0,
        NULL, HFILL }},
    { &hf_xnap_XnBenefitValue_PDU,
      { "XnBenefitValue", "xnap.XnBenefitValue",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_xnap_HandoverRequest_PDU,
      { "HandoverRequest", "xnap.HandoverRequest_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_xnap_UEContextInfoHORequest_PDU,
      { "UEContextInfoHORequest", "xnap.UEContextInfoHORequest_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_xnap_UEContextRefAtSN_HORequest_PDU,
      { "UEContextRefAtSN-HORequest", "xnap.UEContextRefAtSN_HORequest_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_xnap_HandoverRequestAcknowledge_PDU,
      { "HandoverRequestAcknowledge", "xnap.HandoverRequestAcknowledge_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_xnap_Target2SourceNG_RANnodeTranspContainer_PDU,
      { "Target2SourceNG-RANnodeTranspContainer", "xnap.Target2SourceNG_RANnodeTranspContainer",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_xnap_HandoverPreparationFailure_PDU,
      { "HandoverPreparationFailure", "xnap.HandoverPreparationFailure_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_xnap_SNStatusTransfer_PDU,
      { "SNStatusTransfer", "xnap.SNStatusTransfer_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_xnap_UEContextRelease_PDU,
      { "UEContextRelease", "xnap.UEContextRelease_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_xnap_HandoverCancel_PDU,
      { "HandoverCancel", "xnap.HandoverCancel_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_xnap_RANPaging_PDU,
      { "RANPaging", "xnap.RANPaging_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_xnap_RetrieveUEContextRequest_PDU,
      { "RetrieveUEContextRequest", "xnap.RetrieveUEContextRequest_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_xnap_RetrieveUEContextResponse_PDU,
      { "RetrieveUEContextResponse", "xnap.RetrieveUEContextResponse_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_xnap_RetrieveUEContextFailure_PDU,
      { "RetrieveUEContextFailure", "xnap.RetrieveUEContextFailure_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_xnap_OldtoNewNG_RANnodeResumeContainer_PDU,
      { "OldtoNewNG-RANnodeResumeContainer", "xnap.OldtoNewNG_RANnodeResumeContainer",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_xnap_XnUAddressIndication_PDU,
      { "XnUAddressIndication", "xnap.XnUAddressIndication_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_xnap_SNodeAdditionRequest_PDU,
      { "SNodeAdditionRequest", "xnap.SNodeAdditionRequest_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_xnap_MN_to_SN_Container_PDU,
      { "MN-to-SN-Container", "xnap.MN_to_SN_Container",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_xnap_PDUSessionToBeAddedAddReq_PDU,
      { "PDUSessionToBeAddedAddReq", "xnap.PDUSessionToBeAddedAddReq",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_xnap_SNodeAdditionRequestAcknowledge_PDU,
      { "SNodeAdditionRequestAcknowledge", "xnap.SNodeAdditionRequestAcknowledge_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_xnap_SN_to_MN_Container_PDU,
      { "SN-to-MN-Container", "xnap.SN_to_MN_Container",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_xnap_PDUSessionAdmittedAddedAddReqAck_PDU,
      { "PDUSessionAdmittedAddedAddReqAck", "xnap.PDUSessionAdmittedAddedAddReqAck",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_xnap_PDUSessionNotAdmittedAddReqAck_PDU,
      { "PDUSessionNotAdmittedAddReqAck", "xnap.PDUSessionNotAdmittedAddReqAck_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_xnap_SNodeAdditionRequestReject_PDU,
      { "SNodeAdditionRequestReject", "xnap.SNodeAdditionRequestReject_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_xnap_SNodeReconfigurationComplete_PDU,
      { "SNodeReconfigurationComplete", "xnap.SNodeReconfigurationComplete_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_xnap_ResponseInfo_ReconfCompl_PDU,
      { "ResponseInfo-ReconfCompl", "xnap.ResponseInfo_ReconfCompl_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_xnap_SNodeModificationRequest_PDU,
      { "SNodeModificationRequest", "xnap.SNodeModificationRequest_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_xnap_UEContextInfo_SNModRequest_PDU,
      { "UEContextInfo-SNModRequest", "xnap.UEContextInfo_SNModRequest_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_xnap_SNodeModificationRequestAcknowledge_PDU,
      { "SNodeModificationRequestAcknowledge", "xnap.SNodeModificationRequestAcknowledge_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_xnap_PDUSessionAdmitted_SNModResponse_PDU,
      { "PDUSessionAdmitted-SNModResponse", "xnap.PDUSessionAdmitted_SNModResponse_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_xnap_PDUSessionNotAdmitted_SNModResponse_PDU,
      { "PDUSessionNotAdmitted-SNModResponse", "xnap.PDUSessionNotAdmitted_SNModResponse_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_xnap_PDUSessionDataForwarding_SNModResponse_PDU,
      { "PDUSessionDataForwarding-SNModResponse", "xnap.PDUSessionDataForwarding_SNModResponse_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_xnap_SNodeModificationRequestReject_PDU,
      { "SNodeModificationRequestReject", "xnap.SNodeModificationRequestReject_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_xnap_SNodeModificationRequired_PDU,
      { "SNodeModificationRequired", "xnap.SNodeModificationRequired_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_xnap_PDUSessionToBeModifiedSNModRequired_PDU,
      { "PDUSessionToBeModifiedSNModRequired", "xnap.PDUSessionToBeModifiedSNModRequired",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_xnap_PDUSessionToBeReleasedSNModRequired_PDU,
      { "PDUSessionToBeReleasedSNModRequired", "xnap.PDUSessionToBeReleasedSNModRequired_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_xnap_SNodeModificationConfirm_PDU,
      { "SNodeModificationConfirm", "xnap.SNodeModificationConfirm_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_xnap_PDUSessionAdmittedModSNModConfirm_PDU,
      { "PDUSessionAdmittedModSNModConfirm", "xnap.PDUSessionAdmittedModSNModConfirm",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_xnap_PDUSessionReleasedSNModConfirm_PDU,
      { "PDUSessionReleasedSNModConfirm", "xnap.PDUSessionReleasedSNModConfirm_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_xnap_SNodeModificationRefuse_PDU,
      { "SNodeModificationRefuse", "xnap.SNodeModificationRefuse_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_xnap_SNodeReleaseRequest_PDU,
      { "SNodeReleaseRequest", "xnap.SNodeReleaseRequest_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_xnap_SNodeReleaseRequestAcknowledge_PDU,
      { "SNodeReleaseRequestAcknowledge", "xnap.SNodeReleaseRequestAcknowledge_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_xnap_PDUSessionToBeReleasedList_RelReqAck_PDU,
      { "PDUSessionToBeReleasedList-RelReqAck", "xnap.PDUSessionToBeReleasedList_RelReqAck_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_xnap_SNodeReleaseReject_PDU,
      { "SNodeReleaseReject", "xnap.SNodeReleaseReject_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_xnap_SNodeReleaseRequired_PDU,
      { "SNodeReleaseRequired", "xnap.SNodeReleaseRequired_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_xnap_PDUSessionToBeReleasedList_RelRqd_PDU,
      { "PDUSessionToBeReleasedList-RelRqd", "xnap.PDUSessionToBeReleasedList_RelRqd_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_xnap_SNodeReleaseConfirm_PDU,
      { "SNodeReleaseConfirm", "xnap.SNodeReleaseConfirm_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_xnap_PDUSessionReleasedList_RelConf_PDU,
      { "PDUSessionReleasedList-RelConf", "xnap.PDUSessionReleasedList_RelConf_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_xnap_SNodeCounterCheckRequest_PDU,
      { "SNodeCounterCheckRequest", "xnap.SNodeCounterCheckRequest_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_xnap_BearersSubjectToCounterCheck_List_PDU,
      { "BearersSubjectToCounterCheck-List", "xnap.BearersSubjectToCounterCheck_List",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_xnap_SNodeChangeRequired_PDU,
      { "SNodeChangeRequired", "xnap.SNodeChangeRequired_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_xnap_PDUSession_SNChangeRequired_List_PDU,
      { "PDUSession-SNChangeRequired-List", "xnap.PDUSession_SNChangeRequired_List",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_xnap_SNodeChangeConfirm_PDU,
      { "SNodeChangeConfirm", "xnap.SNodeChangeConfirm_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_xnap_PDUSession_SNChangeConfirm_List_PDU,
      { "PDUSession-SNChangeConfirm-List", "xnap.PDUSession_SNChangeConfirm_List",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_xnap_SNodeChangeRefuse_PDU,
      { "SNodeChangeRefuse", "xnap.SNodeChangeRefuse_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_xnap_RRCTransfer_PDU,
      { "RRCTransfer", "xnap.RRCTransfer_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_xnap_SplitSRB_RRCTransfer_PDU,
      { "SplitSRB-RRCTransfer", "xnap.SplitSRB_RRCTransfer_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_xnap_UEReportRRCTransfer_PDU,
      { "UEReportRRCTransfer", "xnap.UEReportRRCTransfer_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_xnap_NotificationControlIndication_PDU,
      { "NotificationControlIndication", "xnap.NotificationControlIndication_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_xnap_PDUSessionResourcesNotifyList_PDU,
      { "PDUSessionResourcesNotifyList", "xnap.PDUSessionResourcesNotifyList",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_xnap_ActivityNotification_PDU,
      { "ActivityNotification", "xnap.ActivityNotification_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_xnap_PDUSessionResourcesActivityNotifyList_PDU,
      { "PDUSessionResourcesActivityNotifyList", "xnap.PDUSessionResourcesActivityNotifyList",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_xnap_XnSetupRequest_PDU,
      { "XnSetupRequest", "xnap.XnSetupRequest_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_xnap_XnSetupResponse_PDU,
      { "XnSetupResponse", "xnap.XnSetupResponse_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_xnap_XnSetupFailure_PDU,
      { "XnSetupFailure", "xnap.XnSetupFailure_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_xnap_NGRANNodeConfigurationUpdate_PDU,
      { "NGRANNodeConfigurationUpdate", "xnap.NGRANNodeConfigurationUpdate_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_xnap_ConfigurationUpdateInitiatingNodeChoice_PDU,
      { "ConfigurationUpdateInitiatingNodeChoice", "xnap.ConfigurationUpdateInitiatingNodeChoice",
        FT_UINT32, BASE_DEC, VALS(xnap_ConfigurationUpdateInitiatingNodeChoice_vals), 0,
        NULL, HFILL }},
    { &hf_xnap_NGRANNodeConfigurationUpdateAcknowledge_PDU,
      { "NGRANNodeConfigurationUpdateAcknowledge", "xnap.NGRANNodeConfigurationUpdateAcknowledge_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_xnap_RespondingNodeTypeConfigUpdateAck_PDU,
      { "RespondingNodeTypeConfigUpdateAck", "xnap.RespondingNodeTypeConfigUpdateAck",
        FT_UINT32, BASE_DEC, VALS(xnap_RespondingNodeTypeConfigUpdateAck_vals), 0,
        NULL, HFILL }},
    { &hf_xnap_NGRANNodeConfigurationUpdateFailure_PDU,
      { "NGRANNodeConfigurationUpdateFailure", "xnap.NGRANNodeConfigurationUpdateFailure_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_xnap_E_UTRA_NR_CellResourceCoordinationRequest_PDU,
      { "E-UTRA-NR-CellResourceCoordinationRequest", "xnap.E_UTRA_NR_CellResourceCoordinationRequest_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_xnap_InitiatingNodeType_ResourceCoordRequest_PDU,
      { "InitiatingNodeType-ResourceCoordRequest", "xnap.InitiatingNodeType_ResourceCoordRequest",
        FT_UINT32, BASE_DEC, VALS(xnap_InitiatingNodeType_ResourceCoordRequest_vals), 0,
        NULL, HFILL }},
    { &hf_xnap_E_UTRA_NR_CellResourceCoordinationResponse_PDU,
      { "E-UTRA-NR-CellResourceCoordinationResponse", "xnap.E_UTRA_NR_CellResourceCoordinationResponse_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_xnap_RespondingNodeType_ResourceCoordResponse_PDU,
      { "RespondingNodeType-ResourceCoordResponse", "xnap.RespondingNodeType_ResourceCoordResponse",
        FT_UINT32, BASE_DEC, VALS(xnap_RespondingNodeType_ResourceCoordResponse_vals), 0,
        NULL, HFILL }},
    { &hf_xnap_SecondaryRATDataUsageReport_PDU,
      { "SecondaryRATDataUsageReport", "xnap.SecondaryRATDataUsageReport_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_xnap_XnRemovalRequest_PDU,
      { "XnRemovalRequest", "xnap.XnRemovalRequest_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_xnap_XnRemovalResponse_PDU,
      { "XnRemovalResponse", "xnap.XnRemovalResponse_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_xnap_XnRemovalFailure_PDU,
      { "XnRemovalFailure", "xnap.XnRemovalFailure_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_xnap_CellActivationRequest_PDU,
      { "CellActivationRequest", "xnap.CellActivationRequest_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_xnap_ServedCellsToActivate_PDU,
      { "ServedCellsToActivate", "xnap.ServedCellsToActivate",
        FT_UINT32, BASE_DEC, VALS(xnap_ServedCellsToActivate_vals), 0,
        NULL, HFILL }},
    { &hf_xnap_CellActivationResponse_PDU,
      { "CellActivationResponse", "xnap.CellActivationResponse_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_xnap_ActivatedServedCells_PDU,
      { "ActivatedServedCells", "xnap.ActivatedServedCells",
        FT_UINT32, BASE_DEC, VALS(xnap_ActivatedServedCells_vals), 0,
        NULL, HFILL }},
    { &hf_xnap_CellActivationFailure_PDU,
      { "CellActivationFailure", "xnap.CellActivationFailure_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_xnap_ResetRequest_PDU,
      { "ResetRequest", "xnap.ResetRequest_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_xnap_ResetResponse_PDU,
      { "ResetResponse", "xnap.ResetResponse_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_xnap_ErrorIndication_PDU,
      { "ErrorIndication", "xnap.ErrorIndication_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_xnap_PrivateMessage_PDU,
      { "PrivateMessage", "xnap.PrivateMessage_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_xnap_XnAP_PDU_PDU,
      { "XnAP-PDU", "xnap.XnAP_PDU",
        FT_UINT32, BASE_DEC, VALS(xnap_XnAP_PDU_vals), 0,
        NULL, HFILL }},
    { &hf_xnap_local,
      { "local", "xnap.local",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_maxPrivateIEs", HFILL }},
    { &hf_xnap_global,
      { "global", "xnap.global",
        FT_OID, BASE_NONE, NULL, 0,
        "OBJECT_IDENTIFIER", HFILL }},
    { &hf_xnap_ProtocolIE_Container_item,
      { "ProtocolIE-Field", "xnap.ProtocolIE_Field_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_xnap_id,
      { "id", "xnap.id",
        FT_UINT32, BASE_DEC|BASE_EXT_STRING, &xnap_ProtocolIE_ID_vals_ext, 0,
        "ProtocolIE_ID", HFILL }},
    { &hf_xnap_criticality,
      { "criticality", "xnap.criticality",
        FT_UINT32, BASE_DEC, VALS(xnap_Criticality_vals), 0,
        NULL, HFILL }},
    { &hf_xnap_protocolIE_Field_value,
      { "value", "xnap.value_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "ProtocolIE_Field_value", HFILL }},
    { &hf_xnap_ProtocolExtensionContainer_item,
      { "ProtocolExtensionField", "xnap.ProtocolExtensionField_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_xnap_extension_id,
      { "id", "xnap.id",
        FT_UINT32, BASE_DEC|BASE_EXT_STRING, &xnap_ProtocolIE_ID_vals_ext, 0,
        "ProtocolIE_ID", HFILL }},
    { &hf_xnap_extensionValue,
      { "extensionValue", "xnap.extensionValue_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_xnap_PrivateIE_Container_item,
      { "PrivateIE-Field", "xnap.PrivateIE_Field_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_xnap_private_id,
      { "id", "xnap.id",
        FT_UINT32, BASE_DEC, VALS(xnap_PrivateIE_ID_vals), 0,
        "PrivateIE_ID", HFILL }},
    { &hf_xnap_privateIE_Field_value,
      { "value", "xnap.value_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "PrivateIE_Field_value", HFILL }},
    { &hf_xnap_additional_UL_NG_U_TNLatUPF,
      { "additional-UL-NG-U-TNLatUPF", "xnap.additional_UL_NG_U_TNLatUPF",
        FT_UINT32, BASE_DEC, VALS(xnap_UPTransportLayerInformation_vals), 0,
        "UPTransportLayerInformation", HFILL }},
    { &hf_xnap_iE_Extensions,
      { "iE-Extensions", "xnap.iE_Extensions",
        FT_UINT32, BASE_DEC, NULL, 0,
        "ProtocolExtensionContainer", HFILL }},
    { &hf_xnap_Additional_UL_NG_U_TNLatUPF_List_item,
      { "Additional-UL-NG-U-TNLatUPF-Item", "xnap.Additional_UL_NG_U_TNLatUPF_Item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_xnap_priorityLevel,
      { "priorityLevel", "xnap.priorityLevel",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_15_", HFILL }},
    { &hf_xnap_pre_emption_capability,
      { "pre-emption-capability", "xnap.pre_emption_capability",
        FT_UINT32, BASE_DEC, VALS(xnap_T_pre_emption_capability_vals), 0,
        NULL, HFILL }},
    { &hf_xnap_pre_emption_vulnerability,
      { "pre-emption-vulnerability", "xnap.pre_emption_vulnerability",
        FT_UINT32, BASE_DEC, VALS(xnap_T_pre_emption_vulnerability_vals), 0,
        NULL, HFILL }},
    { &hf_xnap_AMF_Region_Information_item,
      { "GlobalAMF-Region-Information", "xnap.GlobalAMF_Region_Information_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_xnap_plmn_ID,
      { "plmn-ID", "xnap.plmn_ID",
        FT_BYTES, BASE_NONE, NULL, 0,
        "PLMN_Identity", HFILL }},
    { &hf_xnap_amf_region_id,
      { "amf-region-id", "xnap.amf_region_id",
        FT_BYTES, BASE_NONE, NULL, 0,
        "BIT_STRING_SIZE_8", HFILL }},
    { &hf_xnap_AreaOfInterestInformation_item,
      { "AreaOfInterest-Item", "xnap.AreaOfInterest_Item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_xnap_listOfTAIsinAoI,
      { "listOfTAIsinAoI", "xnap.listOfTAIsinAoI",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_xnap_listOfCellsinAoI,
      { "listOfCellsinAoI", "xnap.listOfCellsinAoI",
        FT_UINT32, BASE_DEC, NULL, 0,
        "ListOfCells", HFILL }},
    { &hf_xnap_listOfRANNodesinAoI,
      { "listOfRANNodesinAoI", "xnap.listOfRANNodesinAoI",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_xnap_requestReferenceID,
      { "requestReferenceID", "xnap.requestReferenceID",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_xnap_key_NG_RAN_Star,
      { "key-NG-RAN-Star", "xnap.key_NG_RAN_Star",
        FT_BYTES, BASE_NONE, NULL, 0,
        "BIT_STRING_SIZE_256", HFILL }},
    { &hf_xnap_ncc,
      { "ncc", "xnap.ncc",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_7", HFILL }},
    { &hf_xnap_ran_paging_attempt_info,
      { "ran-paging-attempt-info", "xnap.ran_paging_attempt_info_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "RANPagingAttemptInfo", HFILL }},
    { &hf_xnap_BPLMN_ID_Info_EUTRA_item,
      { "BPLMN-ID-Info-EUTRA-Item", "xnap.BPLMN_ID_Info_EUTRA_Item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_xnap_broadcastPLMNs,
      { "broadcastPLMNs", "xnap.broadcastPLMNs",
        FT_UINT32, BASE_DEC, NULL, 0,
        "BroadcastEUTRAPLMNs", HFILL }},
    { &hf_xnap_tac,
      { "tac", "xnap.tac",
        FT_UINT24, BASE_DEC_HEX, NULL, 0,
        NULL, HFILL }},
    { &hf_xnap_e_utraCI,
      { "e-utraCI", "xnap.e_utraCI",
        FT_BYTES, BASE_NONE, NULL, 0,
        "E_UTRA_Cell_Identity", HFILL }},
    { &hf_xnap_ranac,
      { "ranac", "xnap.ranac",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_xnap_iE_Extension,
      { "iE-Extension", "xnap.iE_Extension",
        FT_UINT32, BASE_DEC, NULL, 0,
        "ProtocolExtensionContainer", HFILL }},
    { &hf_xnap_BPLMN_ID_Info_NR_item,
      { "BPLMN-ID-Info-NR-Item", "xnap.BPLMN_ID_Info_NR_Item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_xnap_broadcastPLMNs_01,
      { "broadcastPLMNs", "xnap.broadcastPLMNs",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_xnap_nr_CI,
      { "nr-CI", "xnap.nr_CI",
        FT_BYTES, BASE_NONE, NULL, 0,
        "NR_Cell_Identity", HFILL }},
    { &hf_xnap_BroadcastPLMNs_item,
      { "PLMN-Identity", "xnap.PLMN_Identity",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_xnap_BroadcastEUTRAPLMNs_item,
      { "PLMN-Identity", "xnap.PLMN_Identity",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_xnap_plmn_id,
      { "plmn-id", "xnap.plmn_id",
        FT_BYTES, BASE_NONE, NULL, 0,
        "PLMN_Identity", HFILL }},
    { &hf_xnap_tAISliceSupport_List,
      { "tAISliceSupport-List", "xnap.tAISliceSupport_List",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SliceSupport_List", HFILL }},
    { &hf_xnap_radioNetwork,
      { "radioNetwork", "xnap.radioNetwork",
        FT_UINT32, BASE_DEC|BASE_EXT_STRING, &xnap_CauseRadioNetworkLayer_vals_ext, 0,
        "CauseRadioNetworkLayer", HFILL }},
    { &hf_xnap_transport,
      { "transport", "xnap.transport",
        FT_UINT32, BASE_DEC, VALS(xnap_CauseTransportLayer_vals), 0,
        "CauseTransportLayer", HFILL }},
    { &hf_xnap_protocol,
      { "protocol", "xnap.protocol",
        FT_UINT32, BASE_DEC, VALS(xnap_CauseProtocol_vals), 0,
        "CauseProtocol", HFILL }},
    { &hf_xnap_misc,
      { "misc", "xnap.misc",
        FT_UINT32, BASE_DEC, VALS(xnap_CauseMisc_vals), 0,
        "CauseMisc", HFILL }},
    { &hf_xnap_choice_extension,
      { "choice-extension", "xnap.choice_extension_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "ProtocolIE_Single_Container", HFILL }},
    { &hf_xnap_limitedNR_List,
      { "limitedNR-List", "xnap.limitedNR_List",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_SIZE_1_maxnoofCellsinNG_RANnode_OF_NR_CGI", HFILL }},
    { &hf_xnap_limitedNR_List_item,
      { "NR-CGI", "xnap.NR_CGI_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_xnap_full_List,
      { "full-List", "xnap.full_List",
        FT_UINT32, BASE_DEC, VALS(xnap_T_full_List_vals), 0,
        NULL, HFILL }},
    { &hf_xnap_eNDC_Support,
      { "eNDC-Support", "xnap.eNDC_Support",
        FT_UINT32, BASE_DEC, VALS(xnap_T_eNDC_Support_vals), 0,
        NULL, HFILL }},
    { &hf_xnap_pdcp_SN12,
      { "pdcp-SN12", "xnap.pdcp_SN12",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_4095", HFILL }},
    { &hf_xnap_hfn_PDCP_SN12,
      { "hfn-PDCP-SN12", "xnap.hfn_PDCP_SN12",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_1048575", HFILL }},
    { &hf_xnap_pdcp_SN18,
      { "pdcp-SN18", "xnap.pdcp_SN18",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_262143", HFILL }},
    { &hf_xnap_hfn_PDCP_SN18,
      { "hfn-PDCP-SN18", "xnap.hfn_PDCP_SN18",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_16383", HFILL }},
    { &hf_xnap_endpointIPAddress,
      { "endpointIPAddress", "xnap.endpointIPAddress",
        FT_BYTES, BASE_NONE, NULL, 0,
        "TransportLayerAddress", HFILL }},
    { &hf_xnap_procedureCode,
      { "procedureCode", "xnap.procedureCode",
        FT_UINT32, BASE_DEC|BASE_EXT_STRING, &xnap_ProcedureCode_vals_ext, 0,
        NULL, HFILL }},
    { &hf_xnap_triggeringMessage,
      { "triggeringMessage", "xnap.triggeringMessage",
        FT_UINT32, BASE_DEC, VALS(xnap_TriggeringMessage_vals), 0,
        NULL, HFILL }},
    { &hf_xnap_procedureCriticality,
      { "procedureCriticality", "xnap.procedureCriticality",
        FT_UINT32, BASE_DEC, VALS(xnap_Criticality_vals), 0,
        "Criticality", HFILL }},
    { &hf_xnap_iEsCriticalityDiagnostics,
      { "iEsCriticalityDiagnostics", "xnap.iEsCriticalityDiagnostics",
        FT_UINT32, BASE_DEC, NULL, 0,
        "CriticalityDiagnostics_IE_List", HFILL }},
    { &hf_xnap_CriticalityDiagnostics_IE_List_item,
      { "CriticalityDiagnostics-IE-List item", "xnap.CriticalityDiagnostics_IE_List_item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_xnap_iECriticality,
      { "iECriticality", "xnap.iECriticality",
        FT_UINT32, BASE_DEC, VALS(xnap_Criticality_vals), 0,
        "Criticality", HFILL }},
    { &hf_xnap_iE_ID,
      { "iE-ID", "xnap.iE_ID",
        FT_UINT32, BASE_DEC|BASE_EXT_STRING, &xnap_ProtocolIE_ID_vals_ext, 0,
        "ProtocolIE_ID", HFILL }},
    { &hf_xnap_typeOfError,
      { "typeOfError", "xnap.typeOfError",
        FT_UINT32, BASE_DEC, VALS(xnap_TypeOfError_vals), 0,
        NULL, HFILL }},
    { &hf_xnap_XnUAddressInfoperPDUSession_List_item,
      { "XnUAddressInfoperPDUSession-Item", "xnap.XnUAddressInfoperPDUSession_Item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_xnap_pduSession_ID,
      { "pduSession-ID", "xnap.pduSession_ID",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_xnap_dataForwardingInfoFromTargetNGRANnode,
      { "dataForwardingInfoFromTargetNGRANnode", "xnap.dataForwardingInfoFromTargetNGRANnode_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_xnap_pduSessionResourceSetupCompleteInfo_SNterm,
      { "pduSessionResourceSetupCompleteInfo-SNterm", "xnap.pduSessionResourceSetupCompleteInfo_SNterm_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "PDUSessionResourceBearerSetupCompleteInfo_SNterminated", HFILL }},
    { &hf_xnap_qosFlowsAcceptedForDataForwarding_List,
      { "qosFlowsAcceptedForDataForwarding-List", "xnap.qosFlowsAcceptedForDataForwarding_List",
        FT_UINT32, BASE_DEC, NULL, 0,
        "QoSFLowsAcceptedToBeForwarded_List", HFILL }},
    { &hf_xnap_pduSessionLevelDLDataForwardingInfo,
      { "pduSessionLevelDLDataForwardingInfo", "xnap.pduSessionLevelDLDataForwardingInfo",
        FT_UINT32, BASE_DEC, VALS(xnap_UPTransportLayerInformation_vals), 0,
        "UPTransportLayerInformation", HFILL }},
    { &hf_xnap_pduSessionLevelULDataForwardingInfo,
      { "pduSessionLevelULDataForwardingInfo", "xnap.pduSessionLevelULDataForwardingInfo",
        FT_UINT32, BASE_DEC, VALS(xnap_UPTransportLayerInformation_vals), 0,
        "UPTransportLayerInformation", HFILL }},
    { &hf_xnap_dataForwardingResponseDRBItemList,
      { "dataForwardingResponseDRBItemList", "xnap.dataForwardingResponseDRBItemList",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_xnap_QoSFLowsAcceptedToBeForwarded_List_item,
      { "QoSFLowsAcceptedToBeForwarded-Item", "xnap.QoSFLowsAcceptedToBeForwarded_Item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_xnap_qosFlowIdentifier,
      { "qosFlowIdentifier", "xnap.qosFlowIdentifier",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_xnap_qosFlowsToBeForwarded,
      { "qosFlowsToBeForwarded", "xnap.qosFlowsToBeForwarded",
        FT_UINT32, BASE_DEC, NULL, 0,
        "QoSFLowsToBeForwarded_List", HFILL }},
    { &hf_xnap_sourceDRBtoQoSFlowMapping,
      { "sourceDRBtoQoSFlowMapping", "xnap.sourceDRBtoQoSFlowMapping",
        FT_UINT32, BASE_DEC, NULL, 0,
        "DRBToQoSFlowMapping_List", HFILL }},
    { &hf_xnap_QoSFLowsToBeForwarded_List_item,
      { "QoSFLowsToBeForwarded-Item", "xnap.QoSFLowsToBeForwarded_Item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_xnap_dl_dataforwarding,
      { "dl-dataforwarding", "xnap.dl_dataforwarding",
        FT_UINT32, BASE_DEC, VALS(xnap_DLForwarding_vals), 0,
        "DLForwarding", HFILL }},
    { &hf_xnap_ul_dataforwarding,
      { "ul-dataforwarding", "xnap.ul_dataforwarding",
        FT_UINT32, BASE_DEC, VALS(xnap_ULForwarding_vals), 0,
        "ULForwarding", HFILL }},
    { &hf_xnap_DataForwardingResponseDRBItemList_item,
      { "DataForwardingResponseDRBItem", "xnap.DataForwardingResponseDRBItem_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_xnap_drb_ID,
      { "drb-ID", "xnap.drb_ID",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_xnap_dlForwardingUPTNL,
      { "dlForwardingUPTNL", "xnap.dlForwardingUPTNL",
        FT_UINT32, BASE_DEC, VALS(xnap_UPTransportLayerInformation_vals), 0,
        "UPTransportLayerInformation", HFILL }},
    { &hf_xnap_ulForwardingUPTNL,
      { "ulForwardingUPTNL", "xnap.ulForwardingUPTNL",
        FT_UINT32, BASE_DEC, VALS(xnap_UPTransportLayerInformation_vals), 0,
        "UPTransportLayerInformation", HFILL }},
    { &hf_xnap_activationSFN,
      { "activationSFN", "xnap.activationSFN",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_xnap_sharedResourceType,
      { "sharedResourceType", "xnap.sharedResourceType",
        FT_UINT32, BASE_DEC, VALS(xnap_SharedResourceType_vals), 0,
        NULL, HFILL }},
    { &hf_xnap_reservedSubframePattern,
      { "reservedSubframePattern", "xnap.reservedSubframePattern_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_xnap_DRB_List_item,
      { "DRB-ID", "xnap.DRB_ID",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_xnap_DRB_List_withCause_item,
      { "DRB-List-withCause-Item", "xnap.DRB_List_withCause_Item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_xnap_drb_id,
      { "drb-id", "xnap.drb_id",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_xnap_cause,
      { "cause", "xnap.cause",
        FT_UINT32, BASE_DEC, VALS(xnap_Cause_vals), 0,
        NULL, HFILL }},
    { &hf_xnap_rLC_Mode,
      { "rLC-Mode", "xnap.rLC_Mode",
        FT_UINT32, BASE_DEC, VALS(xnap_RLCMode_vals), 0,
        "RLCMode", HFILL }},
    { &hf_xnap_DRBsSubjectToStatusTransfer_List_item,
      { "DRBsSubjectToStatusTransfer-Item", "xnap.DRBsSubjectToStatusTransfer_Item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_xnap_drbID,
      { "drbID", "xnap.drbID",
        FT_UINT32, BASE_DEC, NULL, 0,
        "DRB_ID", HFILL }},
    { &hf_xnap_pdcpStatusTransfer_UL,
      { "pdcpStatusTransfer-UL", "xnap.pdcpStatusTransfer_UL",
        FT_UINT32, BASE_DEC, VALS(xnap_DRBBStatusTransferChoice_vals), 0,
        "DRBBStatusTransferChoice", HFILL }},
    { &hf_xnap_pdcpStatusTransfer_DL,
      { "pdcpStatusTransfer-DL", "xnap.pdcpStatusTransfer_DL",
        FT_UINT32, BASE_DEC, VALS(xnap_DRBBStatusTransferChoice_vals), 0,
        "DRBBStatusTransferChoice", HFILL }},
    { &hf_xnap_pdcp_sn_12bits,
      { "pdcp-sn-12bits", "xnap.pdcp_sn_12bits_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "DRBBStatusTransfer12bitsSN", HFILL }},
    { &hf_xnap_pdcp_sn_18bits,
      { "pdcp-sn-18bits", "xnap.pdcp_sn_18bits_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "DRBBStatusTransfer18bitsSN", HFILL }},
    { &hf_xnap_receiveStatusofPDCPSDU,
      { "receiveStatusofPDCPSDU", "xnap.receiveStatusofPDCPSDU",
        FT_BYTES, BASE_NONE, NULL, 0,
        "BIT_STRING_SIZE_1_2048", HFILL }},
    { &hf_xnap_cOUNTValue,
      { "cOUNTValue", "xnap.cOUNTValue_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "COUNT_PDCP_SN12", HFILL }},
    { &hf_xnap_receiveStatusofPDCPSDU_01,
      { "receiveStatusofPDCPSDU", "xnap.receiveStatusofPDCPSDU",
        FT_BYTES, BASE_NONE, NULL, 0,
        "BIT_STRING_SIZE_1_131072", HFILL }},
    { &hf_xnap_cOUNTValue_01,
      { "cOUNTValue", "xnap.cOUNTValue_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "COUNT_PDCP_SN18", HFILL }},
    { &hf_xnap_DRBToQoSFlowMapping_List_item,
      { "DRBToQoSFlowMapping-Item", "xnap.DRBToQoSFlowMapping_Item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_xnap_qosFlows_List,
      { "qosFlows-List", "xnap.qosFlows_List",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_xnap_priorityLevelQoS,
      { "priorityLevelQoS", "xnap.priorityLevelQoS",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_xnap_packetDelayBudget,
      { "packetDelayBudget", "xnap.packetDelayBudget",
        FT_UINT32, BASE_CUSTOM, CF_FUNC(xnap_PacketDelayBudget_fmt), 0,
        NULL, HFILL }},
    { &hf_xnap_packetErrorRate,
      { "packetErrorRate", "xnap.packetErrorRate_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_xnap_fiveQI,
      { "fiveQI", "xnap.fiveQI",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_xnap_delayCritical,
      { "delayCritical", "xnap.delayCritical",
        FT_UINT32, BASE_DEC, VALS(xnap_T_delayCritical_vals), 0,
        NULL, HFILL }},
    { &hf_xnap_averagingWindow,
      { "averagingWindow", "xnap.averagingWindow",
        FT_UINT32, BASE_DEC|BASE_UNIT_STRING, &units_milliseconds, 0,
        NULL, HFILL }},
    { &hf_xnap_maximumDataBurstVolume,
      { "maximumDataBurstVolume", "xnap.maximumDataBurstVolume",
        FT_UINT32, BASE_DEC|BASE_UNIT_STRING, &units_byte_bytes, 0,
        NULL, HFILL }},
    { &hf_xnap_e_utra_CI,
      { "e-utra-CI", "xnap.E-UTRA-Cell-Identity",
        FT_UINT32, BASE_HEX, NULL, 0,
        "E_UTRA_Cell_Identity", HFILL }},
    { &hf_xnap_E_UTRAMultibandInfoList_item,
      { "E-UTRAFrequencyBandIndicator", "xnap.E_UTRAFrequencyBandIndicator",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_xnap_rootSequenceIndex,
      { "rootSequenceIndex", "xnap.rootSequenceIndex",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_837", HFILL }},
    { &hf_xnap_zeroCorrelationIndex,
      { "zeroCorrelationIndex", "xnap.zeroCorrelationIndex",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_15", HFILL }},
    { &hf_xnap_highSpeedFlag,
      { "highSpeedFlag", "xnap.highSpeedFlag",
        FT_UINT32, BASE_DEC, VALS(xnap_T_highSpeedFlag_vals), 0,
        NULL, HFILL }},
    { &hf_xnap_prach_FreqOffset,
      { "prach-FreqOffset", "xnap.prach_FreqOffset",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_94", HFILL }},
    { &hf_xnap_prach_ConfigIndex,
      { "prach-ConfigIndex", "xnap.prach_ConfigIndex",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_63", HFILL }},
    { &hf_xnap_portNumber,
      { "portNumber", "xnap.portNumber",
        FT_UINT16, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_xnap_expectedActivityPeriod,
      { "expectedActivityPeriod", "xnap.expectedActivityPeriod",
        FT_UINT32, BASE_DEC|BASE_UNIT_STRING, &units_seconds, 0,
        NULL, HFILL }},
    { &hf_xnap_expectedIdlePeriod,
      { "expectedIdlePeriod", "xnap.expectedIdlePeriod",
        FT_UINT32, BASE_DEC|BASE_UNIT_STRING, &units_seconds, 0,
        NULL, HFILL }},
    { &hf_xnap_sourceOfUEActivityBehaviourInformation,
      { "sourceOfUEActivityBehaviourInformation", "xnap.sourceOfUEActivityBehaviourInformation",
        FT_UINT32, BASE_DEC, VALS(xnap_SourceOfUEActivityBehaviourInformation_vals), 0,
        NULL, HFILL }},
    { &hf_xnap_expectedUEActivityBehaviour,
      { "expectedUEActivityBehaviour", "xnap.expectedUEActivityBehaviour_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_xnap_expectedHOInterval,
      { "expectedHOInterval", "xnap.expectedHOInterval",
        FT_UINT32, BASE_DEC, VALS(xnap_ExpectedHOInterval_vals), 0,
        NULL, HFILL }},
    { &hf_xnap_expectedUEMobility,
      { "expectedUEMobility", "xnap.expectedUEMobility",
        FT_UINT32, BASE_DEC, VALS(xnap_ExpectedUEMobility_vals), 0,
        NULL, HFILL }},
    { &hf_xnap_expectedUEMovingTrajectory,
      { "expectedUEMovingTrajectory", "xnap.expectedUEMovingTrajectory",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_xnap_ExpectedUEMovingTrajectory_item,
      { "ExpectedUEMovingTrajectoryItem", "xnap.ExpectedUEMovingTrajectoryItem_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_xnap_nGRAN_CGI,
      { "nGRAN-CGI", "xnap.nGRAN_CGI_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "GlobalNG_RANCell_ID", HFILL }},
    { &hf_xnap_timeStayedInCell,
      { "timeStayedInCell", "xnap.timeStayedInCell",
        FT_UINT32, BASE_DEC|BASE_UNIT_STRING, &units_seconds, 0,
        "INTEGER_0_4095", HFILL }},
    { &hf_xnap_maxFlowBitRateDL,
      { "maxFlowBitRateDL", "xnap.maxFlowBitRateDL",
        FT_UINT64, BASE_DEC|BASE_UNIT_STRING, &units_bit_sec, 0,
        "BitRate", HFILL }},
    { &hf_xnap_maxFlowBitRateUL,
      { "maxFlowBitRateUL", "xnap.maxFlowBitRateUL",
        FT_UINT64, BASE_DEC|BASE_UNIT_STRING, &units_bit_sec, 0,
        "BitRate", HFILL }},
    { &hf_xnap_guaranteedFlowBitRateDL,
      { "guaranteedFlowBitRateDL", "xnap.guaranteedFlowBitRateDL",
        FT_UINT64, BASE_DEC|BASE_UNIT_STRING, &units_bit_sec, 0,
        "BitRate", HFILL }},
    { &hf_xnap_guaranteedFlowBitRateUL,
      { "guaranteedFlowBitRateUL", "xnap.guaranteedFlowBitRateUL",
        FT_UINT64, BASE_DEC|BASE_UNIT_STRING, &units_bit_sec, 0,
        "BitRate", HFILL }},
    { &hf_xnap_notificationControl,
      { "notificationControl", "xnap.notificationControl",
        FT_UINT32, BASE_DEC, VALS(xnap_T_notificationControl_vals), 0,
        NULL, HFILL }},
    { &hf_xnap_maxPacketLossRateDL,
      { "maxPacketLossRateDL", "xnap.maxPacketLossRateDL",
        FT_UINT32, BASE_CUSTOM, CF_FUNC(xnap_PacketLossRate_fmt), 0,
        "PacketLossRate", HFILL }},
    { &hf_xnap_maxPacketLossRateUL,
      { "maxPacketLossRateUL", "xnap.maxPacketLossRateUL",
        FT_UINT32, BASE_CUSTOM, CF_FUNC(xnap_PacketLossRate_fmt), 0,
        "PacketLossRate", HFILL }},
    { &hf_xnap_gnb_id,
      { "gnb-id", "xnap.gnb_id",
        FT_UINT32, BASE_DEC, VALS(xnap_GNB_ID_Choice_vals), 0,
        "GNB_ID_Choice", HFILL }},
    { &hf_xnap_gnb_ID,
      { "gnb-ID", "xnap.gnb_ID",
        FT_BYTES, BASE_NONE, NULL, 0,
        "BIT_STRING_SIZE_22_32", HFILL }},
    { &hf_xnap_enb_id,
      { "enb-id", "xnap.enb_id",
        FT_UINT32, BASE_DEC, VALS(xnap_ENB_ID_Choice_vals), 0,
        "ENB_ID_Choice", HFILL }},
    { &hf_xnap_enb_ID_macro,
      { "enb-ID-macro", "xnap.enb_ID_macro",
        FT_BYTES, BASE_NONE, NULL, 0,
        "BIT_STRING_SIZE_20", HFILL }},
    { &hf_xnap_enb_ID_shortmacro,
      { "enb-ID-shortmacro", "xnap.enb_ID_shortmacro",
        FT_BYTES, BASE_NONE, NULL, 0,
        "BIT_STRING_SIZE_18", HFILL }},
    { &hf_xnap_enb_ID_longmacro,
      { "enb-ID-longmacro", "xnap.enb_ID_longmacro",
        FT_BYTES, BASE_NONE, NULL, 0,
        "BIT_STRING_SIZE_21", HFILL }},
    { &hf_xnap_ng_RAN_Cell_id,
      { "ng-RAN-Cell-id", "xnap.ng_RAN_Cell_id",
        FT_UINT32, BASE_DEC, VALS(xnap_NG_RAN_Cell_Identity_vals), 0,
        "NG_RAN_Cell_Identity", HFILL }},
    { &hf_xnap_gNB,
      { "gNB", "xnap.gNB_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "GlobalgNB_ID", HFILL }},
    { &hf_xnap_ng_eNB,
      { "ng-eNB", "xnap.ng_eNB_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "GlobalngeNB_ID", HFILL }},
    { &hf_xnap_tnl_address,
      { "tnl-address", "xnap.tnl_address",
        FT_BYTES, BASE_NONE, NULL, 0,
        "TransportLayerAddress", HFILL }},
    { &hf_xnap_gtp_teid,
      { "gtp-teid", "xnap.gtp_teid",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_xnap_amf_set_id,
      { "amf-set-id", "xnap.amf_set_id",
        FT_BYTES, BASE_NONE, NULL, 0,
        "BIT_STRING_SIZE_10", HFILL }},
    { &hf_xnap_amf_pointer,
      { "amf-pointer", "xnap.amf_pointer",
        FT_BYTES, BASE_NONE, NULL, 0,
        "BIT_STRING_SIZE_6", HFILL }},
    { &hf_xnap_i_RNTI_full,
      { "i-RNTI-full", "xnap.i_RNTI_full",
        FT_BYTES, BASE_NONE, NULL, 0,
        "BIT_STRING_SIZE_40", HFILL }},
    { &hf_xnap_i_RNTI_short,
      { "i-RNTI-short", "xnap.i_RNTI_short",
        FT_BYTES, BASE_NONE, NULL, 0,
        "BIT_STRING_SIZE_24", HFILL }},
    { &hf_xnap_nG_RAN_Cell,
      { "nG-RAN-Cell", "xnap.nG_RAN_Cell",
        FT_BYTES, BASE_NONE, NULL, 0,
        "LastVisitedNGRANCellInformation", HFILL }},
    { &hf_xnap_e_UTRAN_Cell,
      { "e-UTRAN-Cell", "xnap.e_UTRAN_Cell",
        FT_BYTES, BASE_NONE, NULL, 0,
        "LastVisitedEUTRANCellInformation", HFILL }},
    { &hf_xnap_uTRAN_Cell,
      { "uTRAN-Cell", "xnap.uTRAN_Cell",
        FT_BYTES, BASE_NONE, NULL, 0,
        "LastVisitedUTRANCellInformation", HFILL }},
    { &hf_xnap_gERAN_Cell,
      { "gERAN-Cell", "xnap.gERAN_Cell",
        FT_BYTES, BASE_NONE, NULL, 0,
        "LastVisitedGERANCellInformation", HFILL }},
    { &hf_xnap_ListOfCells_item,
      { "CellsinAoI-Item", "xnap.CellsinAoI_Item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_xnap_pLMN_Identity,
      { "pLMN-Identity", "xnap.pLMN_Identity",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_xnap_ng_ran_cell_id,
      { "ng-ran-cell-id", "xnap.ng_ran_cell_id",
        FT_UINT32, BASE_DEC, VALS(xnap_NG_RAN_Cell_Identity_vals), 0,
        "NG_RAN_Cell_Identity", HFILL }},
    { &hf_xnap_ListOfRANNodesinAoI_item,
      { "GlobalNG-RANNodesinAoI-Item", "xnap.GlobalNG_RANNodesinAoI_Item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_xnap_global_NG_RAN_Node_ID,
      { "global-NG-RAN-Node-ID", "xnap.global_NG_RAN_Node_ID",
        FT_UINT32, BASE_DEC, VALS(xnap_GlobalNG_RANNode_ID_vals), 0,
        "GlobalNG_RANNode_ID", HFILL }},
    { &hf_xnap_ListOfTAIsinAoI_item,
      { "TAIsinAoI-Item", "xnap.TAIsinAoI_Item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_xnap_tAC,
      { "tAC", "xnap.tAC",
        FT_UINT24, BASE_DEC_HEX, NULL, 0,
        NULL, HFILL }},
    { &hf_xnap_eventType,
      { "eventType", "xnap.eventType",
        FT_UINT32, BASE_DEC, VALS(xnap_EventType_vals), 0,
        NULL, HFILL }},
    { &hf_xnap_reportArea,
      { "reportArea", "xnap.reportArea",
        FT_UINT32, BASE_DEC, VALS(xnap_ReportArea_vals), 0,
        NULL, HFILL }},
    { &hf_xnap_areaOfInterest,
      { "areaOfInterest", "xnap.areaOfInterest",
        FT_UINT32, BASE_DEC, NULL, 0,
        "AreaOfInterestInformation", HFILL }},
    { &hf_xnap_maxIPrate_UL,
      { "maxIPrate-UL", "xnap.maxIPrate_UL",
        FT_UINT32, BASE_DEC, VALS(xnap_MaxIPrate_vals), 0,
        "MaxIPrate", HFILL }},
    { &hf_xnap_oneframe,
      { "oneframe", "xnap.oneframe",
        FT_BYTES, BASE_NONE, NULL, 0,
        "BIT_STRING_SIZE_6", HFILL }},
    { &hf_xnap_fourframes,
      { "fourframes", "xnap.fourframes",
        FT_BYTES, BASE_NONE, NULL, 0,
        "BIT_STRING_SIZE_24", HFILL }},
    { &hf_xnap_MBSFNSubframeInfo_E_UTRA_item,
      { "MBSFNSubframeInfo-E-UTRA-Item", "xnap.MBSFNSubframeInfo_E_UTRA_Item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_xnap_radioframeAllocationPeriod,
      { "radioframeAllocationPeriod", "xnap.radioframeAllocationPeriod",
        FT_UINT32, BASE_DEC, VALS(xnap_T_radioframeAllocationPeriod_vals), 0,
        NULL, HFILL }},
    { &hf_xnap_radioframeAllocationOffset,
      { "radioframeAllocationOffset", "xnap.radioframeAllocationOffset",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_7_", HFILL }},
    { &hf_xnap_subframeAllocation,
      { "subframeAllocation", "xnap.subframeAllocation",
        FT_UINT32, BASE_DEC, VALS(xnap_MBSFNSubframeAllocation_E_UTRA_vals), 0,
        "MBSFNSubframeAllocation_E_UTRA", HFILL }},
    { &hf_xnap_serving_PLMN,
      { "serving-PLMN", "xnap.serving_PLMN",
        FT_BYTES, BASE_NONE, NULL, 0,
        "PLMN_Identity", HFILL }},
    { &hf_xnap_equivalent_PLMNs,
      { "equivalent-PLMNs", "xnap.equivalent_PLMNs",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_SIZE_1_maxnoofEPLMNs_OF_PLMN_Identity", HFILL }},
    { &hf_xnap_equivalent_PLMNs_item,
      { "PLMN-Identity", "xnap.PLMN_Identity",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_xnap_rat_Restrictions,
      { "rat-Restrictions", "xnap.rat_Restrictions",
        FT_UINT32, BASE_DEC, NULL, 0,
        "RAT_RestrictionsList", HFILL }},
    { &hf_xnap_forbiddenAreaInformation,
      { "forbiddenAreaInformation", "xnap.forbiddenAreaInformation",
        FT_UINT32, BASE_DEC, NULL, 0,
        "ForbiddenAreaList", HFILL }},
    { &hf_xnap_serviceAreaInformation,
      { "serviceAreaInformation", "xnap.serviceAreaInformation",
        FT_UINT32, BASE_DEC, NULL, 0,
        "ServiceAreaList", HFILL }},
    { &hf_xnap_CNTypeRestrictionsForEquivalent_item,
      { "CNTypeRestrictionsForEquivalentItem", "xnap.CNTypeRestrictionsForEquivalentItem_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_xnap_plmn_Identity,
      { "plmn-Identity", "xnap.plmn_Identity",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_xnap_cn_Type,
      { "cn-Type", "xnap.cn_Type",
        FT_UINT32, BASE_DEC, VALS(xnap_T_cn_Type_vals), 0,
        NULL, HFILL }},
    { &hf_xnap_RAT_RestrictionsList_item,
      { "RAT-RestrictionsItem", "xnap.RAT_RestrictionsItem_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_xnap_rat_RestrictionInformation,
      { "rat-RestrictionInformation", "xnap.rat_RestrictionInformation",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_xnap_ForbiddenAreaList_item,
      { "ForbiddenAreaItem", "xnap.ForbiddenAreaItem_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_xnap_forbidden_TACs,
      { "forbidden-TACs", "xnap.forbidden_TACs",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_SIZE_1_maxnoofForbiddenTACs_OF_TAC", HFILL }},
    { &hf_xnap_forbidden_TACs_item,
      { "TAC", "xnap.TAC",
        FT_UINT24, BASE_DEC_HEX, NULL, 0,
        NULL, HFILL }},
    { &hf_xnap_ServiceAreaList_item,
      { "ServiceAreaItem", "xnap.ServiceAreaItem_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_xnap_allowed_TACs_ServiceArea,
      { "allowed-TACs-ServiceArea", "xnap.allowed_TACs_ServiceArea",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_SIZE_1_maxnoofAllowedAreas_OF_TAC", HFILL }},
    { &hf_xnap_allowed_TACs_ServiceArea_item,
      { "TAC", "xnap.TAC",
        FT_UINT24, BASE_DEC_HEX, NULL, 0,
        NULL, HFILL }},
    { &hf_xnap_not_allowed_TACs_ServiceArea,
      { "not-allowed-TACs-ServiceArea", "xnap.not_allowed_TACs_ServiceArea",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_SIZE_1_maxnoofAllowedAreas_OF_TAC", HFILL }},
    { &hf_xnap_not_allowed_TACs_ServiceArea_item,
      { "TAC", "xnap.TAC",
        FT_UINT24, BASE_DEC_HEX, NULL, 0,
        NULL, HFILL }},
    { &hf_xnap_ng_RAN_Node_ResourceCoordinationInfo,
      { "ng-RAN-Node-ResourceCoordinationInfo", "xnap.ng_RAN_Node_ResourceCoordinationInfo",
        FT_UINT32, BASE_DEC, VALS(xnap_NG_RAN_Node_ResourceCoordinationInfo_vals), 0,
        NULL, HFILL }},
    { &hf_xnap_eutra_resource_coordination_info,
      { "eutra-resource-coordination-info", "xnap.eutra_resource_coordination_info_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "E_UTRA_ResourceCoordinationInfo", HFILL }},
    { &hf_xnap_nr_resource_coordination_info,
      { "nr-resource-coordination-info", "xnap.nr_resource_coordination_info_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "NR_ResourceCoordinationInfo", HFILL }},
    { &hf_xnap_e_utra_cell,
      { "e-utra-cell", "xnap.e_utra_cell_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "E_UTRA_CGI", HFILL }},
    { &hf_xnap_ul_coordination_info,
      { "ul-coordination-info", "xnap.ul_coordination_info",
        FT_BYTES, BASE_NONE, NULL, 0,
        "BIT_STRING_SIZE_6_4400", HFILL }},
    { &hf_xnap_dl_coordination_info,
      { "dl-coordination-info", "xnap.dl_coordination_info",
        FT_BYTES, BASE_NONE, NULL, 0,
        "BIT_STRING_SIZE_6_4400", HFILL }},
    { &hf_xnap_nr_cell,
      { "nr-cell", "xnap.nr_cell_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "NR_CGI", HFILL }},
    { &hf_xnap_e_utra_coordination_assistance_info,
      { "e-utra-coordination-assistance-info", "xnap.e_utra_coordination_assistance_info",
        FT_UINT32, BASE_DEC, VALS(xnap_E_UTRA_CoordinationAssistanceInfo_vals), 0,
        "E_UTRA_CoordinationAssistanceInfo", HFILL }},
    { &hf_xnap_nr_coordination_assistance_info,
      { "nr-coordination-assistance-info", "xnap.nr_coordination_assistance_info",
        FT_UINT32, BASE_DEC, VALS(xnap_NR_CoordinationAssistanceInfo_vals), 0,
        "NR_CoordinationAssistanceInfo", HFILL }},
    { &hf_xnap_subframeAssignment,
      { "subframeAssignment", "xnap.subframeAssignment",
        FT_UINT32, BASE_DEC, VALS(xnap_T_subframeAssignment_vals), 0,
        NULL, HFILL }},
    { &hf_xnap_harqOffset,
      { "harqOffset", "xnap.harqOffset",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_9", HFILL }},
    { &hf_xnap_NeighbourInformation_E_UTRA_item,
      { "NeighbourInformation-E-UTRA-Item", "xnap.NeighbourInformation_E_UTRA_Item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_xnap_e_utra_PCI,
      { "e-utra-PCI", "xnap.e_utra_PCI",
        FT_UINT32, BASE_DEC, NULL, 0,
        "E_UTRAPCI", HFILL }},
    { &hf_xnap_e_utra_cgi,
      { "e-utra-cgi", "xnap.e_utra_cgi_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_xnap_earfcn,
      { "earfcn", "xnap.earfcn",
        FT_UINT32, BASE_DEC, NULL, 0,
        "E_UTRAARFCN", HFILL }},
    { &hf_xnap_NeighbourInformation_NR_item,
      { "NeighbourInformation-NR-Item", "xnap.NeighbourInformation_NR_Item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_xnap_nr_PCI,
      { "nr-PCI", "xnap.nr_PCI",
        FT_UINT32, BASE_DEC, NULL, 0,
        "NRPCI", HFILL }},
    { &hf_xnap_nr_cgi,
      { "nr-cgi", "xnap.nr_cgi_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_xnap_nr_mode_info,
      { "nr-mode-info", "xnap.nr_mode_info",
        FT_UINT32, BASE_DEC, VALS(xnap_NeighbourInformation_NR_ModeInfo_vals), 0,
        "NeighbourInformation_NR_ModeInfo", HFILL }},
    { &hf_xnap_connectivitySupport,
      { "connectivitySupport", "xnap.connectivitySupport_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "Connectivity_Support", HFILL }},
    { &hf_xnap_measurementTimingConfiguration,
      { "measurementTimingConfiguration", "xnap.measurementTimingConfiguration",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_xnap_fdd_info,
      { "fdd-info", "xnap.fdd_info_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "NeighbourInformation_NR_ModeFDDInfo", HFILL }},
    { &hf_xnap_tdd_info,
      { "tdd-info", "xnap.tdd_info_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "NeighbourInformation_NR_ModeTDDInfo", HFILL }},
    { &hf_xnap_ul_NR_FreqInfo,
      { "ul-NR-FreqInfo", "xnap.ul_NR_FreqInfo_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "NRFrequencyInfo", HFILL }},
    { &hf_xnap_dl_NR_FequInfo,
      { "dl-NR-FequInfo", "xnap.dl_NR_FequInfo_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "NRFrequencyInfo", HFILL }},
    { &hf_xnap_ie_Extensions,
      { "ie-Extensions", "xnap.ie_Extensions",
        FT_UINT32, BASE_DEC, NULL, 0,
        "ProtocolExtensionContainer", HFILL }},
    { &hf_xnap_nr_FreqInfo,
      { "nr-FreqInfo", "xnap.nr_FreqInfo_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "NRFrequencyInfo", HFILL }},
    { &hf_xnap_nr,
      { "nr", "xnap.NR-Cell-Identity",
        FT_UINT40, BASE_HEX, NULL, 0,
        "NR_Cell_Identity", HFILL }},
    { &hf_xnap_e_utra,
      { "e-utra", "xnap.E-UTRA-Cell-Identity",
        FT_UINT32, BASE_HEX, NULL, 0,
        "E_UTRA_Cell_Identity", HFILL }},
    { &hf_xnap_nr_01,
      { "nr", "xnap.nr",
        FT_UINT32, BASE_DEC, NULL, 0,
        "NRPCI", HFILL }},
    { &hf_xnap_e_utra_01,
      { "e-utra", "xnap.e_utra",
        FT_UINT32, BASE_DEC, NULL, 0,
        "E_UTRAPCI", HFILL }},
    { &hf_xnap_NG_RAN_Cell_Identity_ListinRANPagingArea_item,
      { "NG-RAN-Cell-Identity", "xnap.NG_RAN_Cell_Identity",
        FT_UINT32, BASE_DEC, VALS(xnap_NG_RAN_Cell_Identity_vals), 0,
        NULL, HFILL }},
    { &hf_xnap_nr_CI_01,
      { "nr-CI", "xnap.NR-Cell-Identity",
        FT_UINT40, BASE_HEX, NULL, 0,
        "NR_Cell_Identity", HFILL }},
    { &hf_xnap_NRFrequencyBand_List_item,
      { "NRFrequencyBandItem", "xnap.NRFrequencyBandItem_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_xnap_nr_frequency_band,
      { "nr-frequency-band", "xnap.nr_frequency_band",
        FT_UINT32, BASE_DEC, NULL, 0,
        "NRFrequencyBand", HFILL }},
    { &hf_xnap_supported_SUL_Band_List,
      { "supported-SUL-Band-List", "xnap.supported_SUL_Band_List",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SupportedSULBandList", HFILL }},
    { &hf_xnap_nrARFCN,
      { "nrARFCN", "xnap.nrARFCN",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_xnap_sul_information,
      { "sul-information", "xnap.sul_information_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_xnap_frequencyBand_List,
      { "frequencyBand-List", "xnap.frequencyBand_List",
        FT_UINT32, BASE_DEC, NULL, 0,
        "NRFrequencyBand_List", HFILL }},
    { &hf_xnap_fdd,
      { "fdd", "xnap.fdd_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "NRModeInfoFDD", HFILL }},
    { &hf_xnap_tdd,
      { "tdd", "xnap.tdd_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "NRModeInfoTDD", HFILL }},
    { &hf_xnap_ulNRFrequencyInfo,
      { "ulNRFrequencyInfo", "xnap.ulNRFrequencyInfo_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "NRFrequencyInfo", HFILL }},
    { &hf_xnap_dlNRFrequencyInfo,
      { "dlNRFrequencyInfo", "xnap.dlNRFrequencyInfo_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "NRFrequencyInfo", HFILL }},
    { &hf_xnap_ulNRTransmissonBandwidth,
      { "ulNRTransmissonBandwidth", "xnap.ulNRTransmissonBandwidth_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "NRTransmissionBandwidth", HFILL }},
    { &hf_xnap_dlNRTransmissonBandwidth,
      { "dlNRTransmissonBandwidth", "xnap.dlNRTransmissonBandwidth_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "NRTransmissionBandwidth", HFILL }},
    { &hf_xnap_nrFrequencyInfo,
      { "nrFrequencyInfo", "xnap.nrFrequencyInfo_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_xnap_nrTransmissonBandwidth,
      { "nrTransmissonBandwidth", "xnap.nrTransmissonBandwidth_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "NRTransmissionBandwidth", HFILL }},
    { &hf_xnap_nRSCS,
      { "nRSCS", "xnap.nRSCS",
        FT_UINT32, BASE_DEC, VALS(xnap_NRSCS_vals), 0,
        NULL, HFILL }},
    { &hf_xnap_nRNRB,
      { "nRNRB", "xnap.nRNRB",
        FT_UINT32, BASE_DEC|BASE_EXT_STRING, &xnap_NRNRB_vals_ext, 0,
        NULL, HFILL }},
    { &hf_xnap_pER_Scalar,
      { "pER-Scalar", "xnap.pER_Scalar",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_xnap_pER_Exponent,
      { "pER-Exponent", "xnap.pER_Exponent",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_xnap_from_S_NG_RAN_node,
      { "from-S-NG-RAN-node", "xnap.from_S_NG_RAN_node",
        FT_UINT32, BASE_DEC, VALS(xnap_T_from_S_NG_RAN_node_vals), 0,
        NULL, HFILL }},
    { &hf_xnap_from_M_NG_RAN_node,
      { "from-M-NG-RAN-node", "xnap.from_M_NG_RAN_node",
        FT_UINT32, BASE_DEC, VALS(xnap_T_from_M_NG_RAN_node_vals), 0,
        NULL, HFILL }},
    { &hf_xnap_ulPDCPSNLength,
      { "ulPDCPSNLength", "xnap.ulPDCPSNLength",
        FT_UINT32, BASE_DEC, VALS(xnap_T_ulPDCPSNLength_vals), 0,
        NULL, HFILL }},
    { &hf_xnap_dlPDCPSNLength,
      { "dlPDCPSNLength", "xnap.dlPDCPSNLength",
        FT_UINT32, BASE_DEC, VALS(xnap_T_dlPDCPSNLength_vals), 0,
        NULL, HFILL }},
    { &hf_xnap_downlink_session_AMBR,
      { "downlink-session-AMBR", "xnap.downlink_session_AMBR",
        FT_UINT64, BASE_DEC|BASE_UNIT_STRING, &units_bit_sec, 0,
        "BitRate", HFILL }},
    { &hf_xnap_uplink_session_AMBR,
      { "uplink-session-AMBR", "xnap.uplink_session_AMBR",
        FT_UINT64, BASE_DEC|BASE_UNIT_STRING, &units_bit_sec, 0,
        "BitRate", HFILL }},
    { &hf_xnap_PDUSession_List_item,
      { "PDUSession-ID", "xnap.PDUSession_ID",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_xnap_PDUSession_List_withCause_item,
      { "PDUSession-List-withCause-Item", "xnap.PDUSession_List_withCause_Item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_xnap_pduSessionId,
      { "pduSessionId", "xnap.pduSessionId",
        FT_UINT32, BASE_DEC, NULL, 0,
        "PDUSession_ID", HFILL }},
    { &hf_xnap_PDUSession_List_withDataForwardingFromTarget_item,
      { "PDUSession-List-withDataForwardingFromTarget-Item", "xnap.PDUSession_List_withDataForwardingFromTarget_Item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_xnap_dataforwardinginfoTarget,
      { "dataforwardinginfoTarget", "xnap.dataforwardinginfoTarget_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "DataForwardingInfoFromTargetNGRANnode", HFILL }},
    { &hf_xnap_PDUSession_List_withDataForwardingRequest_item,
      { "PDUSession-List-withDataForwardingRequest-Item", "xnap.PDUSession_List_withDataForwardingRequest_Item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_xnap_dataforwardingInfofromSource,
      { "dataforwardingInfofromSource", "xnap.dataforwardingInfofromSource_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "DataforwardingandOffloadingInfofromSource", HFILL }},
    { &hf_xnap_dRBtoBeReleasedList,
      { "dRBtoBeReleasedList", "xnap.dRBtoBeReleasedList",
        FT_UINT32, BASE_DEC, NULL, 0,
        "DRBToQoSFlowMapping_List", HFILL }},
    { &hf_xnap_PDUSessionResourcesAdmitted_List_item,
      { "PDUSessionResourcesAdmitted-Item", "xnap.PDUSessionResourcesAdmitted_Item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_xnap_pduSessionResourceAdmittedInfo,
      { "pduSessionResourceAdmittedInfo", "xnap.pduSessionResourceAdmittedInfo_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_xnap_dL_NG_U_TNL_Information_Unchanged,
      { "dL-NG-U-TNL-Information-Unchanged", "xnap.dL_NG_U_TNL_Information_Unchanged",
        FT_UINT32, BASE_DEC, VALS(xnap_T_dL_NG_U_TNL_Information_Unchanged_vals), 0,
        NULL, HFILL }},
    { &hf_xnap_qosFlowsAdmitted_List,
      { "qosFlowsAdmitted-List", "xnap.qosFlowsAdmitted_List",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_xnap_qosFlowsNotAdmitted_List,
      { "qosFlowsNotAdmitted-List", "xnap.qosFlowsNotAdmitted_List",
        FT_UINT32, BASE_DEC, NULL, 0,
        "QoSFlows_List_withCause", HFILL }},
    { &hf_xnap_dataForwardingInfoFromTarget,
      { "dataForwardingInfoFromTarget", "xnap.dataForwardingInfoFromTarget_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "DataForwardingInfoFromTargetNGRANnode", HFILL }},
    { &hf_xnap_PDUSessionResourcesNotAdmitted_List_item,
      { "PDUSessionResourcesNotAdmitted-Item", "xnap.PDUSessionResourcesNotAdmitted_Item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_xnap_PDUSessionResourcesToBeSetup_List_item,
      { "PDUSessionResourcesToBeSetup-Item", "xnap.PDUSessionResourcesToBeSetup_Item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_xnap_s_NSSAI,
      { "s-NSSAI", "xnap.s_NSSAI_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_xnap_pduSessionAMBR,
      { "pduSessionAMBR", "xnap.pduSessionAMBR_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "PDUSessionAggregateMaximumBitRate", HFILL }},
    { &hf_xnap_uL_NG_U_TNLatUPF,
      { "uL-NG-U-TNLatUPF", "xnap.uL_NG_U_TNLatUPF",
        FT_UINT32, BASE_DEC, VALS(xnap_UPTransportLayerInformation_vals), 0,
        "UPTransportLayerInformation", HFILL }},
    { &hf_xnap_source_DL_NG_U_TNL_Information,
      { "source-DL-NG-U-TNL-Information", "xnap.source_DL_NG_U_TNL_Information",
        FT_UINT32, BASE_DEC, VALS(xnap_UPTransportLayerInformation_vals), 0,
        "UPTransportLayerInformation", HFILL }},
    { &hf_xnap_securityIndication,
      { "securityIndication", "xnap.securityIndication_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_xnap_pduSessionType,
      { "pduSessionType", "xnap.pduSessionType",
        FT_UINT32, BASE_DEC, VALS(xnap_PDUSessionType_vals), 0,
        NULL, HFILL }},
    { &hf_xnap_pduSessionNetworkInstance,
      { "pduSessionNetworkInstance", "xnap.pduSessionNetworkInstance",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_xnap_qosFlowsToBeSetup_List,
      { "qosFlowsToBeSetup-List", "xnap.qosFlowsToBeSetup_List",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_xnap_dataforwardinginfofromSource,
      { "dataforwardinginfofromSource", "xnap.dataforwardinginfofromSource_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "DataforwardingandOffloadingInfofromSource", HFILL }},
    { &hf_xnap_qosFlowsToBeSetup_List_01,
      { "qosFlowsToBeSetup-List", "xnap.qosFlowsToBeSetup_List",
        FT_UINT32, BASE_DEC, NULL, 0,
        "QoSFlowsToBeSetup_List_Setup_SNterminated", HFILL }},
    { &hf_xnap_QoSFlowsToBeSetup_List_Setup_SNterminated_item,
      { "QoSFlowsToBeSetup-List-Setup-SNterminated-Item", "xnap.QoSFlowsToBeSetup_List_Setup_SNterminated_Item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_xnap_qfi,
      { "qfi", "xnap.qfi",
        FT_UINT32, BASE_DEC, NULL, 0,
        "QoSFlowIdentifier", HFILL }},
    { &hf_xnap_qosFlowLevelQoSParameters,
      { "qosFlowLevelQoSParameters", "xnap.qosFlowLevelQoSParameters_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_xnap_offeredGBRQoSFlowInfo,
      { "offeredGBRQoSFlowInfo", "xnap.offeredGBRQoSFlowInfo_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "GBRQoSFlowInfo", HFILL }},
    { &hf_xnap_dL_NG_U_TNLatNG_RAN,
      { "dL-NG-U-TNLatNG-RAN", "xnap.dL_NG_U_TNLatNG_RAN",
        FT_UINT32, BASE_DEC, VALS(xnap_UPTransportLayerInformation_vals), 0,
        "UPTransportLayerInformation", HFILL }},
    { &hf_xnap_dRBsToBeSetup,
      { "dRBsToBeSetup", "xnap.dRBsToBeSetup",
        FT_UINT32, BASE_DEC, NULL, 0,
        "DRBsToBeSetupList_SetupResponse_SNterminated", HFILL }},
    { &hf_xnap_qosFlowsNotAdmittedList,
      { "qosFlowsNotAdmittedList", "xnap.qosFlowsNotAdmittedList",
        FT_UINT32, BASE_DEC, NULL, 0,
        "QoSFlows_List_withCause", HFILL }},
    { &hf_xnap_securityResult,
      { "securityResult", "xnap.securityResult_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_xnap_DRBsToBeSetupList_SetupResponse_SNterminated_item,
      { "DRBsToBeSetupList-SetupResponse-SNterminated-Item", "xnap.DRBsToBeSetupList_SetupResponse_SNterminated_Item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_xnap_sN_UL_PDCP_UP_TNLInfo,
      { "sN-UL-PDCP-UP-TNLInfo", "xnap.sN_UL_PDCP_UP_TNLInfo",
        FT_UINT32, BASE_DEC, NULL, 0,
        "UPTransportParameters", HFILL }},
    { &hf_xnap_dRB_QoS,
      { "dRB-QoS", "xnap.dRB_QoS_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "QoSFlowLevelQoSParameters", HFILL }},
    { &hf_xnap_pDCP_SNLength,
      { "pDCP-SNLength", "xnap.pDCP_SNLength_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "PDCPSNLength", HFILL }},
    { &hf_xnap_uL_Configuration,
      { "uL-Configuration", "xnap.uL_Configuration_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "ULConfiguration", HFILL }},
    { &hf_xnap_secondary_SN_UL_PDCP_UP_TNLInfo,
      { "secondary-SN-UL-PDCP-UP-TNLInfo", "xnap.secondary_SN_UL_PDCP_UP_TNLInfo",
        FT_UINT32, BASE_DEC, NULL, 0,
        "UPTransportParameters", HFILL }},
    { &hf_xnap_duplicationActivation,
      { "duplicationActivation", "xnap.duplicationActivation",
        FT_UINT32, BASE_DEC, VALS(xnap_DuplicationActivation_vals), 0,
        NULL, HFILL }},
    { &hf_xnap_qoSFlowsMappedtoDRB_SetupResponse_SNterminated,
      { "qoSFlowsMappedtoDRB-SetupResponse-SNterminated", "xnap.qoSFlowsMappedtoDRB_SetupResponse_SNterminated",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_xnap_QoSFlowsMappedtoDRB_SetupResponse_SNterminated_item,
      { "QoSFlowsMappedtoDRB-SetupResponse-SNterminated-Item", "xnap.QoSFlowsMappedtoDRB_SetupResponse_SNterminated_Item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_xnap_qoSFlowIdentifier,
      { "qoSFlowIdentifier", "xnap.qoSFlowIdentifier",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_xnap_mCGRequestedGBRQoSFlowInfo,
      { "mCGRequestedGBRQoSFlowInfo", "xnap.mCGRequestedGBRQoSFlowInfo_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "GBRQoSFlowInfo", HFILL }},
    { &hf_xnap_qosFlowMappingIndication,
      { "qosFlowMappingIndication", "xnap.qosFlowMappingIndication",
        FT_UINT32, BASE_DEC, VALS(xnap_QoSFlowMappingIndication_vals), 0,
        NULL, HFILL }},
    { &hf_xnap_dRBsToBeSetup_01,
      { "dRBsToBeSetup", "xnap.dRBsToBeSetup",
        FT_UINT32, BASE_DEC, NULL, 0,
        "DRBsToBeSetupList_Setup_MNterminated", HFILL }},
    { &hf_xnap_DRBsToBeSetupList_Setup_MNterminated_item,
      { "DRBsToBeSetupList-Setup-MNterminated-Item", "xnap.DRBsToBeSetupList_Setup_MNterminated_Item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_xnap_mN_UL_PDCP_UP_TNLInfo,
      { "mN-UL-PDCP-UP-TNLInfo", "xnap.mN_UL_PDCP_UP_TNLInfo",
        FT_UINT32, BASE_DEC, NULL, 0,
        "UPTransportParameters", HFILL }},
    { &hf_xnap_secondary_MN_UL_PDCP_UP_TNLInfo,
      { "secondary-MN-UL-PDCP-UP-TNLInfo", "xnap.secondary_MN_UL_PDCP_UP_TNLInfo",
        FT_UINT32, BASE_DEC, NULL, 0,
        "UPTransportParameters", HFILL }},
    { &hf_xnap_qoSFlowsMappedtoDRB_Setup_MNterminated,
      { "qoSFlowsMappedtoDRB-Setup-MNterminated", "xnap.qoSFlowsMappedtoDRB_Setup_MNterminated",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_xnap_QoSFlowsMappedtoDRB_Setup_MNterminated_item,
      { "QoSFlowsMappedtoDRB-Setup-MNterminated-Item", "xnap.QoSFlowsMappedtoDRB_Setup_MNterminated_Item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_xnap_qoSFlowLevelQoSParameters,
      { "qoSFlowLevelQoSParameters", "xnap.qoSFlowLevelQoSParameters_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_xnap_dRBsAdmittedList,
      { "dRBsAdmittedList", "xnap.dRBsAdmittedList",
        FT_UINT32, BASE_DEC, NULL, 0,
        "DRBsAdmittedList_SetupResponse_MNterminated", HFILL }},
    { &hf_xnap_DRBsAdmittedList_SetupResponse_MNterminated_item,
      { "DRBsAdmittedList-SetupResponse-MNterminated-Item", "xnap.DRBsAdmittedList_SetupResponse_MNterminated_Item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_xnap_sN_DL_SCG_UP_TNLInfo,
      { "sN-DL-SCG-UP-TNLInfo", "xnap.sN_DL_SCG_UP_TNLInfo",
        FT_UINT32, BASE_DEC, NULL, 0,
        "UPTransportParameters", HFILL }},
    { &hf_xnap_secondary_SN_DL_SCG_UP_TNLInfo,
      { "secondary-SN-DL-SCG-UP-TNLInfo", "xnap.secondary_SN_DL_SCG_UP_TNLInfo",
        FT_UINT32, BASE_DEC, NULL, 0,
        "UPTransportParameters", HFILL }},
    { &hf_xnap_lCID,
      { "lCID", "xnap.lCID",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_xnap_qosFlowsToBeModified_List,
      { "qosFlowsToBeModified-List", "xnap.qosFlowsToBeModified_List",
        FT_UINT32, BASE_DEC, NULL, 0,
        "QoSFlowsToBeSetup_List_Modified_SNterminated", HFILL }},
    { &hf_xnap_qoSFlowsToBeReleased_List,
      { "qoSFlowsToBeReleased-List", "xnap.qoSFlowsToBeReleased_List",
        FT_UINT32, BASE_DEC, NULL, 0,
        "QoSFlows_List_withCause", HFILL }},
    { &hf_xnap_drbsToBeModifiedList,
      { "drbsToBeModifiedList", "xnap.drbsToBeModifiedList",
        FT_UINT32, BASE_DEC, NULL, 0,
        "DRBsToBeModified_List_Modified_SNterminated", HFILL }},
    { &hf_xnap_dRBsToBeReleased,
      { "dRBsToBeReleased", "xnap.dRBsToBeReleased",
        FT_UINT32, BASE_DEC, NULL, 0,
        "DRB_List_withCause", HFILL }},
    { &hf_xnap_QoSFlowsToBeSetup_List_Modified_SNterminated_item,
      { "QoSFlowsToBeSetup-List-Modified-SNterminated-Item", "xnap.QoSFlowsToBeSetup_List_Modified_SNterminated_Item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_xnap_DRBsToBeModified_List_Modified_SNterminated_item,
      { "DRBsToBeModified-List-Modified-SNterminated-Item", "xnap.DRBsToBeModified_List_Modified_SNterminated_Item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_xnap_mN_DL_SCG_UP_TNLInfo,
      { "mN-DL-SCG-UP-TNLInfo", "xnap.mN_DL_SCG_UP_TNLInfo",
        FT_UINT32, BASE_DEC, NULL, 0,
        "UPTransportParameters", HFILL }},
    { &hf_xnap_secondary_MN_DL_SCG_UP_TNLInfo,
      { "secondary-MN-DL-SCG-UP-TNLInfo", "xnap.secondary_MN_DL_SCG_UP_TNLInfo",
        FT_UINT32, BASE_DEC, NULL, 0,
        "UPTransportParameters", HFILL }},
    { &hf_xnap_rlc_status,
      { "rlc-status", "xnap.rlc_status_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_xnap_dRBsToBeModified,
      { "dRBsToBeModified", "xnap.dRBsToBeModified",
        FT_UINT32, BASE_DEC, NULL, 0,
        "DRBsToBeModifiedList_ModificationResponse_SNterminated", HFILL }},
    { &hf_xnap_qosFlowsNotAdmittedTBAdded,
      { "qosFlowsNotAdmittedTBAdded", "xnap.qosFlowsNotAdmittedTBAdded",
        FT_UINT32, BASE_DEC, NULL, 0,
        "QoSFlows_List_withCause", HFILL }},
    { &hf_xnap_qosFlowsReleased,
      { "qosFlowsReleased", "xnap.qosFlowsReleased",
        FT_UINT32, BASE_DEC, NULL, 0,
        "QoSFlows_List_withCause", HFILL }},
    { &hf_xnap_DRBsToBeModifiedList_ModificationResponse_SNterminated_item,
      { "DRBsToBeModifiedList-ModificationResponse-SNterminated-Item", "xnap.DRBsToBeModifiedList_ModificationResponse_SNterminated_Item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_xnap_dRBsToBeModified_01,
      { "dRBsToBeModified", "xnap.dRBsToBeModified",
        FT_UINT32, BASE_DEC, NULL, 0,
        "DRBsToBeModifiedList_Modification_MNterminated", HFILL }},
    { &hf_xnap_DRBsToBeModifiedList_Modification_MNterminated_item,
      { "DRBsToBeModifiedList-Modification-MNterminated-Item", "xnap.DRBsToBeModifiedList_Modification_MNterminated_Item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_xnap_pdcpDuplicationConfiguration,
      { "pdcpDuplicationConfiguration", "xnap.pdcpDuplicationConfiguration",
        FT_UINT32, BASE_DEC, VALS(xnap_PDCPDuplicationConfiguration_vals), 0,
        NULL, HFILL }},
    { &hf_xnap_dRBsAdmittedList_01,
      { "dRBsAdmittedList", "xnap.dRBsAdmittedList",
        FT_UINT32, BASE_DEC, NULL, 0,
        "DRBsAdmittedList_ModificationResponse_MNterminated", HFILL }},
    { &hf_xnap_dRBsReleasedList,
      { "dRBsReleasedList", "xnap.dRBsReleasedList",
        FT_UINT32, BASE_DEC, NULL, 0,
        "DRB_List", HFILL }},
    { &hf_xnap_dRBsNotAdmittedSetupModifyList,
      { "dRBsNotAdmittedSetupModifyList", "xnap.dRBsNotAdmittedSetupModifyList",
        FT_UINT32, BASE_DEC, NULL, 0,
        "DRB_List_withCause", HFILL }},
    { &hf_xnap_DRBsAdmittedList_ModificationResponse_MNterminated_item,
      { "DRBsAdmittedList-ModificationResponse-MNterminated-Item", "xnap.DRBsAdmittedList_ModificationResponse_MNterminated_Item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_xnap_drbsToBeSetupList,
      { "drbsToBeSetupList", "xnap.drbsToBeSetupList",
        FT_UINT32, BASE_DEC, NULL, 0,
        "DRBsToBeSetup_List_ModRqd_SNterminated", HFILL }},
    { &hf_xnap_drbsToBeModifiedList_01,
      { "drbsToBeModifiedList", "xnap.drbsToBeModifiedList",
        FT_UINT32, BASE_DEC, NULL, 0,
        "DRBsToBeModified_List_ModRqd_SNterminated", HFILL }},
    { &hf_xnap_DRBsToBeSetup_List_ModRqd_SNterminated_item,
      { "DRBsToBeSetup-List-ModRqd-SNterminated-Item", "xnap.DRBsToBeSetup_List_ModRqd_SNterminated_Item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_xnap_sn_UL_PDCP_UPTNLinfo,
      { "sn-UL-PDCP-UPTNLinfo", "xnap.sn_UL_PDCP_UPTNLinfo",
        FT_UINT32, BASE_DEC, NULL, 0,
        "UPTransportParameters", HFILL }},
    { &hf_xnap_qoSFlowsMappedtoDRB_ModRqd_SNterminated,
      { "qoSFlowsMappedtoDRB-ModRqd-SNterminated", "xnap.qoSFlowsMappedtoDRB_ModRqd_SNterminated",
        FT_UINT32, BASE_DEC, NULL, 0,
        "QoSFlowsSetupMappedtoDRB_ModRqd_SNterminated", HFILL }},
    { &hf_xnap_QoSFlowsSetupMappedtoDRB_ModRqd_SNterminated_item,
      { "QoSFlowsSetupMappedtoDRB-ModRqd-SNterminated-Item", "xnap.QoSFlowsSetupMappedtoDRB_ModRqd_SNterminated_Item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_xnap_DRBsToBeModified_List_ModRqd_SNterminated_item,
      { "DRBsToBeModified-List-ModRqd-SNterminated-Item", "xnap.DRBsToBeModified_List_ModRqd_SNterminated_Item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_xnap_qoSFlowsMappedtoDRB_ModRqd_SNterminated_01,
      { "qoSFlowsMappedtoDRB-ModRqd-SNterminated", "xnap.qoSFlowsMappedtoDRB_ModRqd_SNterminated",
        FT_UINT32, BASE_DEC, NULL, 0,
        "QoSFlowsModifiedMappedtoDRB_ModRqd_SNterminated", HFILL }},
    { &hf_xnap_QoSFlowsModifiedMappedtoDRB_ModRqd_SNterminated_item,
      { "QoSFlowsModifiedMappedtoDRB-ModRqd-SNterminated-Item", "xnap.QoSFlowsModifiedMappedtoDRB_ModRqd_SNterminated_Item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_xnap_dRBsAdmittedList_02,
      { "dRBsAdmittedList", "xnap.dRBsAdmittedList",
        FT_UINT32, BASE_DEC, NULL, 0,
        "DRBsAdmittedList_ModConfirm_SNterminated", HFILL }},
    { &hf_xnap_DRBsAdmittedList_ModConfirm_SNterminated_item,
      { "DRBsAdmittedList-ModConfirm-SNterminated-Item", "xnap.DRBsAdmittedList_ModConfirm_SNterminated_Item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_xnap_mN_DL_CG_UP_TNLInfo,
      { "mN-DL-CG-UP-TNLInfo", "xnap.mN_DL_CG_UP_TNLInfo",
        FT_UINT32, BASE_DEC, NULL, 0,
        "UPTransportParameters", HFILL }},
    { &hf_xnap_secondary_MN_DL_CG_UP_TNLInfo,
      { "secondary-MN-DL-CG-UP-TNLInfo", "xnap.secondary_MN_DL_CG_UP_TNLInfo",
        FT_UINT32, BASE_DEC, NULL, 0,
        "UPTransportParameters", HFILL }},
    { &hf_xnap_dRBsToBeModified_02,
      { "dRBsToBeModified", "xnap.dRBsToBeModified",
        FT_UINT32, BASE_DEC, NULL, 0,
        "DRBsToBeModified_List_ModRqd_MNterminated", HFILL }},
    { &hf_xnap_DRBsToBeModified_List_ModRqd_MNterminated_item,
      { "DRBsToBeModified-List-ModRqd-MNterminated-Item", "xnap.DRBsToBeModified_List_ModRqd_MNterminated_Item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_xnap_sN_DL_SCG_UP_TNLInfo_01,
      { "sN-DL-SCG-UP-TNLInfo", "xnap.sN_DL_SCG_UP_TNLInfo",
        FT_UINT32, BASE_DEC, VALS(xnap_UPTransportLayerInformation_vals), 0,
        "UPTransportLayerInformation", HFILL }},
    { &hf_xnap_secondary_SN_DL_SCG_UP_TNLInfo_01,
      { "secondary-SN-DL-SCG-UP-TNLInfo", "xnap.secondary_SN_DL_SCG_UP_TNLInfo",
        FT_UINT32, BASE_DEC, VALS(xnap_UPTransportLayerInformation_vals), 0,
        "UPTransportLayerInformation", HFILL }},
    { &hf_xnap_dRBsToBeSetupList,
      { "dRBsToBeSetupList", "xnap.dRBsToBeSetupList",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_SIZE_1_maxnoofDRBs_OF_DRBsToBeSetupList_BearerSetupComplete_SNterminated_Item", HFILL }},
    { &hf_xnap_dRBsToBeSetupList_item,
      { "DRBsToBeSetupList-BearerSetupComplete-SNterminated-Item", "xnap.DRBsToBeSetupList_BearerSetupComplete_SNterminated_Item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_xnap_dRB_ID,
      { "dRB-ID", "xnap.dRB_ID",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_xnap_mN_Xn_U_TNLInfoatM,
      { "mN-Xn-U-TNLInfoatM", "xnap.mN_Xn_U_TNLInfoatM",
        FT_UINT32, BASE_DEC, VALS(xnap_UPTransportLayerInformation_vals), 0,
        "UPTransportLayerInformation", HFILL }},
    { &hf_xnap_PDUSessionResourceSecondaryRATUsageList_item,
      { "PDUSessionResourceSecondaryRATUsageItem", "xnap.PDUSessionResourceSecondaryRATUsageItem_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_xnap_pDUSessionID,
      { "pDUSessionID", "xnap.pDUSessionID",
        FT_UINT32, BASE_DEC, NULL, 0,
        "PDUSession_ID", HFILL }},
    { &hf_xnap_secondaryRATUsageInformation,
      { "secondaryRATUsageInformation", "xnap.secondaryRATUsageInformation_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_xnap_rATType,
      { "rATType", "xnap.rATType",
        FT_UINT32, BASE_DEC, VALS(xnap_T_rATType_vals), 0,
        NULL, HFILL }},
    { &hf_xnap_pDUSessionTimedReportList,
      { "pDUSessionTimedReportList", "xnap.pDUSessionTimedReportList",
        FT_UINT32, BASE_DEC, NULL, 0,
        "VolumeTimedReportList", HFILL }},
    { &hf_xnap_protectedResourceList,
      { "protectedResourceList", "xnap.protectedResourceList",
        FT_UINT32, BASE_DEC, NULL, 0,
        "ProtectedE_UTRAResourceList", HFILL }},
    { &hf_xnap_mbsfnControlRegionLength,
      { "mbsfnControlRegionLength", "xnap.mbsfnControlRegionLength",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_xnap_pDCCHRegionLength,
      { "pDCCHRegionLength", "xnap.pDCCHRegionLength",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_1_3", HFILL }},
    { &hf_xnap_ProtectedE_UTRAResourceList_item,
      { "ProtectedE-UTRAResource-Item", "xnap.ProtectedE_UTRAResource_Item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_xnap_resourceType,
      { "resourceType", "xnap.resourceType",
        FT_UINT32, BASE_DEC, VALS(xnap_T_resourceType_vals), 0,
        NULL, HFILL }},
    { &hf_xnap_intra_PRBProtectedResourceFootprint,
      { "intra-PRBProtectedResourceFootprint", "xnap.intra_PRBProtectedResourceFootprint",
        FT_BYTES, BASE_NONE, NULL, 0,
        "BIT_STRING_SIZE_84_", HFILL }},
    { &hf_xnap_protectedFootprintFrequencyPattern,
      { "protectedFootprintFrequencyPattern", "xnap.protectedFootprintFrequencyPattern",
        FT_BYTES, BASE_NONE, NULL, 0,
        "BIT_STRING_SIZE_6_110_", HFILL }},
    { &hf_xnap_protectedFootprintTimePattern,
      { "protectedFootprintTimePattern", "xnap.protectedFootprintTimePattern_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "ProtectedE_UTRAFootprintTimePattern", HFILL }},
    { &hf_xnap_protectedFootprintTimeperiodicity,
      { "protectedFootprintTimeperiodicity", "xnap.protectedFootprintTimeperiodicity",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_1_320_", HFILL }},
    { &hf_xnap_protectedFootrpintStartTime,
      { "protectedFootrpintStartTime", "xnap.protectedFootrpintStartTime",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_1_20_", HFILL }},
    { &hf_xnap_non_dynamic,
      { "non-dynamic", "xnap.non_dynamic_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "NonDynamic5QIDescriptor", HFILL }},
    { &hf_xnap_dynamic,
      { "dynamic", "xnap.dynamic_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "Dynamic5QIDescriptor", HFILL }},
    { &hf_xnap_qos_characteristics,
      { "qos-characteristics", "xnap.qos_characteristics",
        FT_UINT32, BASE_DEC, VALS(xnap_QoSCharacteristics_vals), 0,
        "QoSCharacteristics", HFILL }},
    { &hf_xnap_allocationAndRetentionPrio,
      { "allocationAndRetentionPrio", "xnap.allocationAndRetentionPrio_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "AllocationandRetentionPriority", HFILL }},
    { &hf_xnap_gBRQoSFlowInfo,
      { "gBRQoSFlowInfo", "xnap.gBRQoSFlowInfo_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_xnap_relectiveQoS,
      { "relectiveQoS", "xnap.relectiveQoS",
        FT_UINT32, BASE_DEC, VALS(xnap_ReflectiveQoSAttribute_vals), 0,
        "ReflectiveQoSAttribute", HFILL }},
    { &hf_xnap_additionalQoSflowInfo,
      { "additionalQoSflowInfo", "xnap.additionalQoSflowInfo",
        FT_UINT32, BASE_DEC, VALS(xnap_T_additionalQoSflowInfo_vals), 0,
        NULL, HFILL }},
    { &hf_xnap_QoSFlowNotificationControlIndicationInfo_item,
      { "QoSFlowNotify-Item", "xnap.QoSFlowNotify_Item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_xnap_notificationInformation,
      { "notificationInformation", "xnap.notificationInformation",
        FT_UINT32, BASE_DEC, VALS(xnap_T_notificationInformation_vals), 0,
        NULL, HFILL }},
    { &hf_xnap_QoSFlows_List_item,
      { "QoSFlow-Item", "xnap.QoSFlow_Item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_xnap_QoSFlows_List_withCause_item,
      { "QoSFlowwithCause-Item", "xnap.QoSFlowwithCause_Item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_xnap_QoSFlowsAdmitted_List_item,
      { "QoSFlowsAdmitted-Item", "xnap.QoSFlowsAdmitted_Item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_xnap_QoSFlowsToBeSetup_List_item,
      { "QoSFlowsToBeSetup-Item", "xnap.QoSFlowsToBeSetup_Item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_xnap_e_RAB_ID,
      { "e-RAB-ID", "xnap.e_RAB_ID",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_xnap_QoSFlowsUsageReportList_item,
      { "QoSFlowsUsageReport-Item", "xnap.QoSFlowsUsageReport_Item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_xnap_rATType_01,
      { "rATType", "xnap.rATType",
        FT_UINT32, BASE_DEC, VALS(xnap_T_rATType_01_vals), 0,
        "T_rATType_01", HFILL }},
    { &hf_xnap_qoSFlowsTimedReportList,
      { "qoSFlowsTimedReportList", "xnap.qoSFlowsTimedReportList",
        FT_UINT32, BASE_DEC, NULL, 0,
        "VolumeTimedReportList", HFILL }},
    { &hf_xnap_rANAC,
      { "rANAC", "xnap.rANAC",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_xnap_RANAreaID_List_item,
      { "RANAreaID", "xnap.RANAreaID_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_xnap_rANPagingAreaChoice,
      { "rANPagingAreaChoice", "xnap.rANPagingAreaChoice",
        FT_UINT32, BASE_DEC, VALS(xnap_RANPagingAreaChoice_vals), 0,
        NULL, HFILL }},
    { &hf_xnap_cell_List,
      { "cell-List", "xnap.cell_List",
        FT_UINT32, BASE_DEC, NULL, 0,
        "NG_RAN_Cell_Identity_ListinRANPagingArea", HFILL }},
    { &hf_xnap_rANAreaID_List,
      { "rANAreaID-List", "xnap.rANAreaID_List",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_xnap_pagingAttemptCount,
      { "pagingAttemptCount", "xnap.pagingAttemptCount",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_1_16_", HFILL }},
    { &hf_xnap_intendedNumberOfPagingAttempts,
      { "intendedNumberOfPagingAttempts", "xnap.intendedNumberOfPagingAttempts",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_1_16_", HFILL }},
    { &hf_xnap_nextPagingAreaScope,
      { "nextPagingAreaScope", "xnap.nextPagingAreaScope",
        FT_UINT32, BASE_DEC, VALS(xnap_T_nextPagingAreaScope_vals), 0,
        NULL, HFILL }},
    { &hf_xnap_subframeType,
      { "subframeType", "xnap.subframeType",
        FT_UINT32, BASE_DEC, VALS(xnap_T_subframeType_vals), 0,
        NULL, HFILL }},
    { &hf_xnap_reservedSubframePattern_01,
      { "reservedSubframePattern", "xnap.reservedSubframePattern",
        FT_BYTES, BASE_NONE, NULL, 0,
        "BIT_STRING_SIZE_10_160", HFILL }},
    { &hf_xnap_fullReset,
      { "fullReset", "xnap.fullReset_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "ResetRequestTypeInfo_Full", HFILL }},
    { &hf_xnap_partialReset,
      { "partialReset", "xnap.partialReset_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "ResetRequestTypeInfo_Partial", HFILL }},
    { &hf_xnap_ue_contexts_ToBeReleasedList,
      { "ue-contexts-ToBeReleasedList", "xnap.ue_contexts_ToBeReleasedList",
        FT_UINT32, BASE_DEC, NULL, 0,
        "ResetRequestPartialReleaseList", HFILL }},
    { &hf_xnap_ResetRequestPartialReleaseList_item,
      { "ResetRequestPartialReleaseItem", "xnap.ResetRequestPartialReleaseItem_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_xnap_ng_ran_node1UEXnAPID,
      { "ng-ran-node1UEXnAPID", "xnap.ng_ran_node1UEXnAPID",
        FT_UINT32, BASE_DEC, NULL, 0,
        "NG_RANnodeUEXnAPID", HFILL }},
    { &hf_xnap_ng_ran_node2UEXnAPID,
      { "ng-ran-node2UEXnAPID", "xnap.ng_ran_node2UEXnAPID",
        FT_UINT32, BASE_DEC, NULL, 0,
        "NG_RANnodeUEXnAPID", HFILL }},
    { &hf_xnap_fullReset_01,
      { "fullReset", "xnap.fullReset_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "ResetResponseTypeInfo_Full", HFILL }},
    { &hf_xnap_partialReset_01,
      { "partialReset", "xnap.partialReset_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "ResetResponseTypeInfo_Partial", HFILL }},
    { &hf_xnap_ue_contexts_AdmittedToBeReleasedList,
      { "ue-contexts-AdmittedToBeReleasedList", "xnap.ue_contexts_AdmittedToBeReleasedList",
        FT_UINT32, BASE_DEC, NULL, 0,
        "ResetResponsePartialReleaseList", HFILL }},
    { &hf_xnap_ResetResponsePartialReleaseList_item,
      { "ResetResponsePartialReleaseItem", "xnap.ResetResponsePartialReleaseItem_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_xnap_reestablishment_Indication,
      { "reestablishment-Indication", "xnap.reestablishment_Indication",
        FT_UINT32, BASE_DEC, VALS(xnap_Reestablishment_Indication_vals), 0,
        NULL, HFILL }},
    { &hf_xnap_secondarydataForwardingInfoFromTarget,
      { "secondarydataForwardingInfoFromTarget", "xnap.secondarydataForwardingInfoFromTarget_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "DataForwardingInfoFromTargetNGRANnode", HFILL }},
    { &hf_xnap_SecondarydataForwardingInfoFromTarget_List_item,
      { "SecondarydataForwardingInfoFromTarget-Item", "xnap.SecondarydataForwardingInfoFromTarget_Item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_xnap_pDUSessionUsageReport,
      { "pDUSessionUsageReport", "xnap.pDUSessionUsageReport_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_xnap_qosFlowsUsageReportList,
      { "qosFlowsUsageReportList", "xnap.qosFlowsUsageReportList",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_xnap_integrityProtectionIndication,
      { "integrityProtectionIndication", "xnap.integrityProtectionIndication",
        FT_UINT32, BASE_DEC, VALS(xnap_T_integrityProtectionIndication_vals), 0,
        NULL, HFILL }},
    { &hf_xnap_confidentialityProtectionIndication,
      { "confidentialityProtectionIndication", "xnap.confidentialityProtectionIndication",
        FT_UINT32, BASE_DEC, VALS(xnap_T_confidentialityProtectionIndication_vals), 0,
        NULL, HFILL }},
    { &hf_xnap_maximumIPdatarate,
      { "maximumIPdatarate", "xnap.maximumIPdatarate_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_xnap_integrityProtectionResult,
      { "integrityProtectionResult", "xnap.integrityProtectionResult",
        FT_UINT32, BASE_DEC, VALS(xnap_T_integrityProtectionResult_vals), 0,
        NULL, HFILL }},
    { &hf_xnap_confidentialityProtectionResult,
      { "confidentialityProtectionResult", "xnap.confidentialityProtectionResult",
        FT_UINT32, BASE_DEC, VALS(xnap_T_confidentialityProtectionResult_vals), 0,
        NULL, HFILL }},
    { &hf_xnap_e_utra_pci,
      { "e-utra-pci", "xnap.e_utra_pci",
        FT_UINT32, BASE_DEC, NULL, 0,
        "E_UTRAPCI", HFILL }},
    { &hf_xnap_broadcastPLMNs_02,
      { "broadcastPLMNs", "xnap.broadcastPLMNs",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_SIZE_1_maxnoofBPLMNs_OF_ServedCellInformation_E_UTRA_perBPLMN", HFILL }},
    { &hf_xnap_broadcastPLMNs_item,
      { "ServedCellInformation-E-UTRA-perBPLMN", "xnap.ServedCellInformation_E_UTRA_perBPLMN_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_xnap_e_utra_mode_info,
      { "e-utra-mode-info", "xnap.e_utra_mode_info",
        FT_UINT32, BASE_DEC, VALS(xnap_ServedCellInformation_E_UTRA_ModeInfo_vals), 0,
        "ServedCellInformation_E_UTRA_ModeInfo", HFILL }},
    { &hf_xnap_numberofAntennaPorts,
      { "numberofAntennaPorts", "xnap.numberofAntennaPorts",
        FT_UINT32, BASE_DEC, VALS(xnap_NumberOfAntennaPorts_E_UTRA_vals), 0,
        "NumberOfAntennaPorts_E_UTRA", HFILL }},
    { &hf_xnap_prach_configuration,
      { "prach-configuration", "xnap.prach_configuration_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "E_UTRAPRACHConfiguration", HFILL }},
    { &hf_xnap_mBSFNsubframeInfo,
      { "mBSFNsubframeInfo", "xnap.mBSFNsubframeInfo",
        FT_UINT32, BASE_DEC, NULL, 0,
        "MBSFNSubframeInfo_E_UTRA", HFILL }},
    { &hf_xnap_multibandInfo,
      { "multibandInfo", "xnap.multibandInfo",
        FT_UINT32, BASE_DEC, NULL, 0,
        "E_UTRAMultibandInfoList", HFILL }},
    { &hf_xnap_freqBandIndicatorPriority,
      { "freqBandIndicatorPriority", "xnap.freqBandIndicatorPriority",
        FT_UINT32, BASE_DEC, VALS(xnap_T_freqBandIndicatorPriority_vals), 0,
        NULL, HFILL }},
    { &hf_xnap_bandwidthReducedSI,
      { "bandwidthReducedSI", "xnap.bandwidthReducedSI",
        FT_UINT32, BASE_DEC, VALS(xnap_T_bandwidthReducedSI_vals), 0,
        NULL, HFILL }},
    { &hf_xnap_protectedE_UTRAResourceIndication,
      { "protectedE-UTRAResourceIndication", "xnap.protectedE_UTRAResourceIndication_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_xnap_fdd_01,
      { "fdd", "xnap.fdd_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "ServedCellInformation_E_UTRA_FDDInfo", HFILL }},
    { &hf_xnap_tdd_01,
      { "tdd", "xnap.tdd_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "ServedCellInformation_E_UTRA_TDDInfo", HFILL }},
    { &hf_xnap_ul_earfcn,
      { "ul-earfcn", "xnap.ul_earfcn",
        FT_UINT32, BASE_DEC, NULL, 0,
        "E_UTRAARFCN", HFILL }},
    { &hf_xnap_dl_earfcn,
      { "dl-earfcn", "xnap.dl_earfcn",
        FT_UINT32, BASE_DEC, NULL, 0,
        "E_UTRAARFCN", HFILL }},
    { &hf_xnap_ul_e_utraTxBW,
      { "ul-e-utraTxBW", "xnap.ul_e_utraTxBW",
        FT_UINT32, BASE_DEC, VALS(xnap_E_UTRATransmissionBandwidth_vals), 0,
        "E_UTRATransmissionBandwidth", HFILL }},
    { &hf_xnap_dl_e_utraTxBW,
      { "dl-e-utraTxBW", "xnap.dl_e_utraTxBW",
        FT_UINT32, BASE_DEC, VALS(xnap_E_UTRATransmissionBandwidth_vals), 0,
        "E_UTRATransmissionBandwidth", HFILL }},
    { &hf_xnap_e_utraTxBW,
      { "e-utraTxBW", "xnap.e_utraTxBW",
        FT_UINT32, BASE_DEC, VALS(xnap_E_UTRATransmissionBandwidth_vals), 0,
        "E_UTRATransmissionBandwidth", HFILL }},
    { &hf_xnap_subframeAssignmnet,
      { "subframeAssignmnet", "xnap.subframeAssignmnet",
        FT_UINT32, BASE_DEC, VALS(xnap_T_subframeAssignmnet_vals), 0,
        NULL, HFILL }},
    { &hf_xnap_specialSubframeInfo,
      { "specialSubframeInfo", "xnap.specialSubframeInfo_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "SpecialSubframeInfo_E_UTRA", HFILL }},
    { &hf_xnap_ServedCells_E_UTRA_item,
      { "ServedCells-E-UTRA-Item", "xnap.ServedCells_E_UTRA_Item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_xnap_served_cell_info_E_UTRA,
      { "served-cell-info-E-UTRA", "xnap.served_cell_info_E_UTRA_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "ServedCellInformation_E_UTRA", HFILL }},
    { &hf_xnap_neighbour_info_NR,
      { "neighbour-info-NR", "xnap.neighbour_info_NR",
        FT_UINT32, BASE_DEC, NULL, 0,
        "NeighbourInformation_NR", HFILL }},
    { &hf_xnap_neighbour_info_E_UTRA,
      { "neighbour-info-E-UTRA", "xnap.neighbour_info_E_UTRA",
        FT_UINT32, BASE_DEC, NULL, 0,
        "NeighbourInformation_E_UTRA", HFILL }},
    { &hf_xnap_served_Cells_ToAdd_E_UTRA,
      { "served-Cells-ToAdd-E-UTRA", "xnap.served_Cells_ToAdd_E_UTRA",
        FT_UINT32, BASE_DEC, NULL, 0,
        "ServedCells_E_UTRA", HFILL }},
    { &hf_xnap_served_Cells_ToModify_E_UTRA,
      { "served-Cells-ToModify-E-UTRA", "xnap.served_Cells_ToModify_E_UTRA",
        FT_UINT32, BASE_DEC, NULL, 0,
        "ServedCells_ToModify_E_UTRA", HFILL }},
    { &hf_xnap_served_Cells_ToDelete_E_UTRA,
      { "served-Cells-ToDelete-E-UTRA", "xnap.served_Cells_ToDelete_E_UTRA",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_SIZE_1_maxnoofCellsinNG_RANnode_OF_E_UTRA_CGI", HFILL }},
    { &hf_xnap_served_Cells_ToDelete_E_UTRA_item,
      { "E-UTRA-CGI", "xnap.E_UTRA_CGI_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_xnap_ServedCells_ToModify_E_UTRA_item,
      { "ServedCells-ToModify-E-UTRA-Item", "xnap.ServedCells_ToModify_E_UTRA_Item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_xnap_old_ECGI,
      { "old-ECGI", "xnap.old_ECGI_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "E_UTRA_CGI", HFILL }},
    { &hf_xnap_deactivation_indication,
      { "deactivation-indication", "xnap.deactivation_indication",
        FT_UINT32, BASE_DEC, VALS(xnap_T_deactivation_indication_vals), 0,
        NULL, HFILL }},
    { &hf_xnap_nrPCI,
      { "nrPCI", "xnap.nrPCI",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_xnap_cellID,
      { "cellID", "xnap.cellID_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "NR_CGI", HFILL }},
    { &hf_xnap_broadcastPLMN,
      { "broadcastPLMN", "xnap.broadcastPLMN",
        FT_UINT32, BASE_DEC, NULL, 0,
        "BroadcastPLMNs", HFILL }},
    { &hf_xnap_nrModeInfo,
      { "nrModeInfo", "xnap.nrModeInfo",
        FT_UINT32, BASE_DEC, VALS(xnap_NRModeInfo_vals), 0,
        NULL, HFILL }},
    { &hf_xnap_measurementTimingConfiguration_01,
      { "measurementTimingConfiguration", "xnap.measurementTimingConfiguration",
        FT_BYTES, BASE_NONE, NULL, 0,
        "T_measurementTimingConfiguration_01", HFILL }},
    { &hf_xnap_ServedCells_NR_item,
      { "ServedCells-NR-Item", "xnap.ServedCells_NR_Item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_xnap_served_cell_info_NR,
      { "served-cell-info-NR", "xnap.served_cell_info_NR_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "ServedCellInformation_NR", HFILL }},
    { &hf_xnap_ServedCells_ToModify_NR_item,
      { "ServedCells-ToModify-NR-Item", "xnap.ServedCells_ToModify_NR_Item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_xnap_old_NR_CGI,
      { "old-NR-CGI", "xnap.old_NR_CGI_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "NR_CGI", HFILL }},
    { &hf_xnap_deactivation_indication_01,
      { "deactivation-indication", "xnap.deactivation_indication",
        FT_UINT32, BASE_DEC, VALS(xnap_T_deactivation_indication_01_vals), 0,
        "T_deactivation_indication_01", HFILL }},
    { &hf_xnap_served_Cells_ToAdd_NR,
      { "served-Cells-ToAdd-NR", "xnap.served_Cells_ToAdd_NR",
        FT_UINT32, BASE_DEC, NULL, 0,
        "ServedCells_NR", HFILL }},
    { &hf_xnap_served_Cells_ToModify_NR,
      { "served-Cells-ToModify-NR", "xnap.served_Cells_ToModify_NR",
        FT_UINT32, BASE_DEC, NULL, 0,
        "ServedCells_ToModify_NR", HFILL }},
    { &hf_xnap_served_Cells_ToDelete_NR,
      { "served-Cells-ToDelete-NR", "xnap.served_Cells_ToDelete_NR",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_SIZE_1_maxnoofCellsinNG_RANnode_OF_NR_CGI", HFILL }},
    { &hf_xnap_served_Cells_ToDelete_NR_item,
      { "NR-CGI", "xnap.NR_CGI_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_xnap_ul_onlySharing,
      { "ul-onlySharing", "xnap.ul_onlySharing_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "SharedResourceType_UL_OnlySharing", HFILL }},
    { &hf_xnap_ul_and_dl_Sharing,
      { "ul-and-dl-Sharing", "xnap.ul_and_dl_Sharing",
        FT_UINT32, BASE_DEC, VALS(xnap_SharedResourceType_ULDL_Sharing_vals), 0,
        "SharedResourceType_ULDL_Sharing", HFILL }},
    { &hf_xnap_ul_resourceBitmap,
      { "ul-resourceBitmap", "xnap.ul_resourceBitmap",
        FT_BYTES, BASE_NONE, NULL, 0,
        "DataTrafficResources", HFILL }},
    { &hf_xnap_ul_resources,
      { "ul-resources", "xnap.ul_resources",
        FT_UINT32, BASE_DEC, VALS(xnap_SharedResourceType_ULDL_Sharing_UL_Resources_vals), 0,
        "SharedResourceType_ULDL_Sharing_UL_Resources", HFILL }},
    { &hf_xnap_dl_resources,
      { "dl-resources", "xnap.dl_resources",
        FT_UINT32, BASE_DEC, VALS(xnap_SharedResourceType_ULDL_Sharing_DL_Resources_vals), 0,
        "SharedResourceType_ULDL_Sharing_DL_Resources", HFILL }},
    { &hf_xnap_unchanged,
      { "unchanged", "xnap.unchanged_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_xnap_changed,
      { "changed", "xnap.changed_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "SharedResourceType_ULDL_Sharing_UL_ResourcesChanged", HFILL }},
    { &hf_xnap_changed_01,
      { "changed", "xnap.changed_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "SharedResourceType_ULDL_Sharing_DL_ResourcesChanged", HFILL }},
    { &hf_xnap_dl_resourceBitmap,
      { "dl-resourceBitmap", "xnap.dl_resourceBitmap",
        FT_BYTES, BASE_NONE, NULL, 0,
        "DataTrafficResources", HFILL }},
    { &hf_xnap_SliceSupport_List_item,
      { "S-NSSAI", "xnap.S_NSSAI_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_xnap_sst,
      { "sst", "xnap.sst",
        FT_BYTES, BASE_NONE, NULL, 0,
        "OCTET_STRING_SIZE_1", HFILL }},
    { &hf_xnap_sd,
      { "sd", "xnap.sd",
        FT_BYTES, BASE_NONE, NULL, 0,
        "OCTET_STRING_SIZE_3", HFILL }},
    { &hf_xnap_specialSubframePattern,
      { "specialSubframePattern", "xnap.specialSubframePattern",
        FT_UINT32, BASE_DEC, VALS(xnap_SpecialSubframePatterns_E_UTRA_vals), 0,
        "SpecialSubframePatterns_E_UTRA", HFILL }},
    { &hf_xnap_cyclicPrefixDL,
      { "cyclicPrefixDL", "xnap.cyclicPrefixDL",
        FT_UINT32, BASE_DEC, VALS(xnap_CyclicPrefix_E_UTRA_DL_vals), 0,
        "CyclicPrefix_E_UTRA_DL", HFILL }},
    { &hf_xnap_cyclicPrefixUL,
      { "cyclicPrefixUL", "xnap.cyclicPrefixUL",
        FT_UINT32, BASE_DEC, VALS(xnap_CyclicPrefix_E_UTRA_UL_vals), 0,
        "CyclicPrefix_E_UTRA_UL", HFILL }},
    { &hf_xnap_sulFrequencyInfo,
      { "sulFrequencyInfo", "xnap.sulFrequencyInfo",
        FT_UINT32, BASE_DEC, NULL, 0,
        "NRARFCN", HFILL }},
    { &hf_xnap_sulTransmissionBandwidth,
      { "sulTransmissionBandwidth", "xnap.sulTransmissionBandwidth_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "NRTransmissionBandwidth", HFILL }},
    { &hf_xnap_SupportedSULBandList_item,
      { "SupportedSULBandItem", "xnap.SupportedSULBandItem_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_xnap_sulBandItem,
      { "sulBandItem", "xnap.sulBandItem",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SUL_FrequencyBand", HFILL }},
    { &hf_xnap_TAISupport_List_item,
      { "TAISupport-Item", "xnap.TAISupport_Item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_xnap_broadcastPLMNs_03,
      { "broadcastPLMNs", "xnap.broadcastPLMNs",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_SIZE_1_maxnoofsupportedPLMNs_OF_BroadcastPLMNinTAISupport_Item", HFILL }},
    { &hf_xnap_broadcastPLMNs_item_01,
      { "BroadcastPLMNinTAISupport-Item", "xnap.BroadcastPLMNinTAISupport_Item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_xnap_nr_02,
      { "nr", "xnap.nr_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "NR_CGI", HFILL }},
    { &hf_xnap_e_utra_02,
      { "e-utra", "xnap.e_utra_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "E_UTRA_CGI", HFILL }},
    { &hf_xnap_TNLA_To_Add_List_item,
      { "TNLA-To-Add-Item", "xnap.TNLA_To_Add_Item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_xnap_tNLAssociationTransportLayerAddress,
      { "tNLAssociationTransportLayerAddress", "xnap.tNLAssociationTransportLayerAddress",
        FT_UINT32, BASE_DEC, VALS(xnap_CPTransportLayerInformation_vals), 0,
        "CPTransportLayerInformation", HFILL }},
    { &hf_xnap_tNLAssociationUsage,
      { "tNLAssociationUsage", "xnap.tNLAssociationUsage",
        FT_UINT32, BASE_DEC, VALS(xnap_TNLAssociationUsage_vals), 0,
        NULL, HFILL }},
    { &hf_xnap_TNLA_To_Update_List_item,
      { "TNLA-To-Update-Item", "xnap.TNLA_To_Update_Item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_xnap_TNLA_To_Remove_List_item,
      { "TNLA-To-Remove-Item", "xnap.TNLA_To_Remove_Item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_xnap_TNLA_Setup_List_item,
      { "TNLA-Setup-Item", "xnap.TNLA_Setup_Item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_xnap_TNLA_Failed_To_Setup_List_item,
      { "TNLA-Failed-To-Setup-Item", "xnap.TNLA_Failed_To_Setup_Item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_xnap_ng_ran_TraceID,
      { "ng-ran-TraceID", "xnap.ng_ran_TraceID",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_xnap_interfaces_to_trace,
      { "interfaces-to-trace", "xnap.interfaces_to_trace",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_xnap_trace_depth,
      { "trace-depth", "xnap.trace_depth",
        FT_UINT32, BASE_DEC, VALS(xnap_Trace_Depth_vals), 0,
        NULL, HFILL }},
    { &hf_xnap_trace_coll_address,
      { "trace-coll-address", "xnap.trace_coll_address",
        FT_BYTES, BASE_NONE, NULL, 0,
        "TransportLayerAddress", HFILL }},
    { &hf_xnap_ie_Extension,
      { "ie-Extension", "xnap.ie_Extension",
        FT_UINT32, BASE_DEC, NULL, 0,
        "ProtocolExtensionContainer", HFILL }},
    { &hf_xnap_dl_UE_AMBR,
      { "dl-UE-AMBR", "xnap.dl_UE_AMBR",
        FT_UINT64, BASE_DEC|BASE_UNIT_STRING, &units_bit_sec, 0,
        "BitRate", HFILL }},
    { &hf_xnap_ul_UE_AMBR,
      { "ul-UE-AMBR", "xnap.ul_UE_AMBR",
        FT_UINT64, BASE_DEC|BASE_UNIT_STRING, &units_bit_sec, 0,
        "BitRate", HFILL }},
    { &hf_xnap_rRCResume,
      { "rRCResume", "xnap.rRCResume_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "UEContextIDforRRCResume", HFILL }},
    { &hf_xnap_rRRCReestablishment,
      { "rRRCReestablishment", "xnap.rRRCReestablishment_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "UEContextIDforRRCReestablishment", HFILL }},
    { &hf_xnap_i_rnti,
      { "i-rnti", "xnap.i_rnti",
        FT_UINT32, BASE_DEC, VALS(xnap_I_RNTI_vals), 0,
        NULL, HFILL }},
    { &hf_xnap_allocated_c_rnti,
      { "allocated-c-rnti", "xnap.allocated_c_rnti",
        FT_BYTES, BASE_NONE, NULL, 0,
        "C_RNTI", HFILL }},
    { &hf_xnap_accessPCI,
      { "accessPCI", "xnap.accessPCI",
        FT_UINT32, BASE_DEC, VALS(xnap_NG_RAN_CellPCI_vals), 0,
        "NG_RAN_CellPCI", HFILL }},
    { &hf_xnap_c_rnti,
      { "c-rnti", "xnap.c_rnti",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_xnap_failureCellPCI,
      { "failureCellPCI", "xnap.failureCellPCI",
        FT_UINT32, BASE_DEC, VALS(xnap_NG_RAN_CellPCI_vals), 0,
        "NG_RAN_CellPCI", HFILL }},
    { &hf_xnap_ng_c_UE_signalling_ref,
      { "ng-c-UE-signalling-ref", "xnap.ng_c_UE_signalling_ref",
        FT_UINT64, BASE_DEC, NULL, 0,
        "AMF_UE_NGAP_ID", HFILL }},
    { &hf_xnap_signalling_TNL_at_source,
      { "signalling-TNL-at-source", "xnap.signalling_TNL_at_source",
        FT_UINT32, BASE_DEC, VALS(xnap_CPTransportLayerInformation_vals), 0,
        "CPTransportLayerInformation", HFILL }},
    { &hf_xnap_ueSecurityCapabilities,
      { "ueSecurityCapabilities", "xnap.ueSecurityCapabilities_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_xnap_securityInformation,
      { "securityInformation", "xnap.securityInformation_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "AS_SecurityInformation", HFILL }},
    { &hf_xnap_ue_AMBR,
      { "ue-AMBR", "xnap.ue_AMBR_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "UEAggregateMaximumBitRate", HFILL }},
    { &hf_xnap_pduSessionResourcesToBeSetup_List,
      { "pduSessionResourcesToBeSetup-List", "xnap.pduSessionResourcesToBeSetup_List",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_xnap_rrc_Context,
      { "rrc-Context", "xnap.rrc_Context",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_xnap_mobilityRestrictionList,
      { "mobilityRestrictionList", "xnap.mobilityRestrictionList_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_xnap_indexToRatFrequencySelectionPriority,
      { "indexToRatFrequencySelectionPriority", "xnap.indexToRatFrequencySelectionPriority",
        FT_UINT32, BASE_DEC, NULL, 0,
        "RFSP_Index", HFILL }},
    { &hf_xnap_UEHistoryInformation_item,
      { "LastVisitedCell-Item", "xnap.LastVisitedCell_Item",
        FT_UINT32, BASE_DEC, VALS(xnap_LastVisitedCell_Item_vals), 0,
        NULL, HFILL }},
    { &hf_xnap_indexLength10,
      { "indexLength10", "xnap.indexLength10",
        FT_BYTES, BASE_NONE, NULL, 0,
        "BIT_STRING_SIZE_10", HFILL }},
    { &hf_xnap_uERadioCapabilityForPagingOfNR,
      { "uERadioCapabilityForPagingOfNR", "xnap.uERadioCapabilityForPagingOfNR",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_xnap_uERadioCapabilityForPagingOfEUTRA,
      { "uERadioCapabilityForPagingOfEUTRA", "xnap.uERadioCapabilityForPagingOfEUTRA",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_xnap_nr_EncyptionAlgorithms,
      { "nr-EncyptionAlgorithms", "xnap.nr_EncyptionAlgorithms",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_xnap_nr_IntegrityProtectionAlgorithms,
      { "nr-IntegrityProtectionAlgorithms", "xnap.nr_IntegrityProtectionAlgorithms",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_xnap_e_utra_EncyptionAlgorithms,
      { "e-utra-EncyptionAlgorithms", "xnap.e_utra_EncyptionAlgorithms",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_xnap_e_utra_IntegrityProtectionAlgorithms,
      { "e-utra-IntegrityProtectionAlgorithms", "xnap.e_utra_IntegrityProtectionAlgorithms",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_xnap_uL_PDCP,
      { "uL-PDCP", "xnap.uL_PDCP",
        FT_UINT32, BASE_DEC, VALS(xnap_UL_UE_Configuration_vals), 0,
        "UL_UE_Configuration", HFILL }},
    { &hf_xnap_gtpTunnel,
      { "gtpTunnel", "xnap.gtpTunnel_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "GTPtunnelTransportLayerInformation", HFILL }},
    { &hf_xnap_UPTransportParameters_item,
      { "UPTransportParametersItem", "xnap.UPTransportParametersItem_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_xnap_upTNLInfo,
      { "upTNLInfo", "xnap.upTNLInfo",
        FT_UINT32, BASE_DEC, VALS(xnap_UPTransportLayerInformation_vals), 0,
        "UPTransportLayerInformation", HFILL }},
    { &hf_xnap_cellGroupID,
      { "cellGroupID", "xnap.cellGroupID",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_xnap_VolumeTimedReportList_item,
      { "VolumeTimedReport-Item", "xnap.VolumeTimedReport_Item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_xnap_startTimeStamp,
      { "startTimeStamp", "xnap.startTimeStamp",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_xnap_endTimeStamp,
      { "endTimeStamp", "xnap.endTimeStamp",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_xnap_usageCountUL,
      { "usageCountUL", "xnap.usageCountUL",
        FT_UINT64, BASE_DEC|BASE_UNIT_STRING, &units_octet_octets, 0,
        "INTEGER_0_18446744073709551615", HFILL }},
    { &hf_xnap_usageCountDL,
      { "usageCountDL", "xnap.usageCountDL",
        FT_UINT64, BASE_DEC|BASE_UNIT_STRING, &units_octet_octets, 0,
        "INTEGER_0_18446744073709551615", HFILL }},
    { &hf_xnap_protocolIEs,
      { "protocolIEs", "xnap.protocolIEs",
        FT_UINT32, BASE_DEC, NULL, 0,
        "ProtocolIE_Container", HFILL }},
    { &hf_xnap_ng_c_UE_reference,
      { "ng-c-UE-reference", "xnap.ng_c_UE_reference",
        FT_UINT64, BASE_DEC, NULL, 0,
        "AMF_UE_NGAP_ID", HFILL }},
    { &hf_xnap_cp_TNL_info_source,
      { "cp-TNL-info-source", "xnap.cp_TNL_info_source",
        FT_UINT32, BASE_DEC, VALS(xnap_CPTransportLayerInformation_vals), 0,
        "CPTransportLayerInformation", HFILL }},
    { &hf_xnap_rrc_Context_01,
      { "rrc-Context", "xnap.rrc_Context",
        FT_BYTES, BASE_NONE, NULL, 0,
        "T_rrc_Context_01", HFILL }},
    { &hf_xnap_locationReportingInformation,
      { "locationReportingInformation", "xnap.locationReportingInformation_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_xnap_mrl,
      { "mrl", "xnap.mrl_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "MobilityRestrictionList", HFILL }},
    { &hf_xnap_globalNG_RANNode_ID,
      { "globalNG-RANNode-ID", "xnap.globalNG_RANNode_ID",
        FT_UINT32, BASE_DEC, VALS(xnap_GlobalNG_RANNode_ID_vals), 0,
        NULL, HFILL }},
    { &hf_xnap_sN_NG_RANnodeUEXnAPID,
      { "sN-NG-RANnodeUEXnAPID", "xnap.sN_NG_RANnodeUEXnAPID",
        FT_UINT32, BASE_DEC, NULL, 0,
        "NG_RANnodeUEXnAPID", HFILL }},
    { &hf_xnap_PDUSessionToBeAddedAddReq_item,
      { "PDUSessionToBeAddedAddReq-Item", "xnap.PDUSessionToBeAddedAddReq_Item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_xnap_sN_PDUSessionAMBR,
      { "sN-PDUSessionAMBR", "xnap.sN_PDUSessionAMBR_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "PDUSessionAggregateMaximumBitRate", HFILL }},
    { &hf_xnap_sn_terminated,
      { "sn-terminated", "xnap.sn_terminated_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "PDUSessionResourceSetupInfo_SNterminated", HFILL }},
    { &hf_xnap_mn_terminated,
      { "mn-terminated", "xnap.mn_terminated_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "PDUSessionResourceSetupInfo_MNterminated", HFILL }},
    { &hf_xnap_PDUSessionAdmittedAddedAddReqAck_item,
      { "PDUSessionAdmittedAddedAddReqAck-Item", "xnap.PDUSessionAdmittedAddedAddReqAck_Item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_xnap_sn_terminated_01,
      { "sn-terminated", "xnap.sn_terminated_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "PDUSessionResourceSetupResponseInfo_SNterminated", HFILL }},
    { &hf_xnap_mn_terminated_01,
      { "mn-terminated", "xnap.mn_terminated_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "PDUSessionResourceSetupResponseInfo_MNterminated", HFILL }},
    { &hf_xnap_pduSessionResourcesNotAdmitted_SNterminated,
      { "pduSessionResourcesNotAdmitted-SNterminated", "xnap.pduSessionResourcesNotAdmitted_SNterminated",
        FT_UINT32, BASE_DEC, NULL, 0,
        "PDUSessionResourcesNotAdmitted_List", HFILL }},
    { &hf_xnap_pduSessionResourcesNotAdmitted_MNterminated,
      { "pduSessionResourcesNotAdmitted-MNterminated", "xnap.pduSessionResourcesNotAdmitted_MNterminated",
        FT_UINT32, BASE_DEC, NULL, 0,
        "PDUSessionResourcesNotAdmitted_List", HFILL }},
    { &hf_xnap_responseType_ReconfComplete,
      { "responseType-ReconfComplete", "xnap.responseType_ReconfComplete",
        FT_UINT32, BASE_DEC, VALS(xnap_ResponseType_ReconfComplete_vals), 0,
        NULL, HFILL }},
    { &hf_xnap_configuration_successfully_applied,
      { "configuration-successfully-applied", "xnap.configuration_successfully_applied_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_xnap_configuration_rejected_by_M_NG_RANNode,
      { "configuration-rejected-by-M-NG-RANNode", "xnap.configuration_rejected_by_M_NG_RANNode_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_xnap_m_NG_RANNode_to_S_NG_RANNode_Container,
      { "m-NG-RANNode-to-S-NG-RANNode-Container", "xnap.m_NG_RANNode_to_S_NG_RANNode_Container",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_xnap_m_NG_RANNode_to_S_NG_RANNode_Container_01,
      { "m-NG-RANNode-to-S-NG-RANNode-Container", "xnap.m_NG_RANNode_to_S_NG_RANNode_Container",
        FT_BYTES, BASE_NONE, NULL, 0,
        "T_m_NG_RANNode_to_S_NG_RANNode_Container_01", HFILL }},
    { &hf_xnap_s_ng_RANnode_SecurityKey,
      { "s-ng-RANnode-SecurityKey", "xnap.s_ng_RANnode_SecurityKey",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_xnap_s_ng_RANnodeUE_AMBR,
      { "s-ng-RANnodeUE-AMBR", "xnap.s_ng_RANnodeUE_AMBR_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "UEAggregateMaximumBitRate", HFILL }},
    { &hf_xnap_lowerLayerPresenceStatusChange,
      { "lowerLayerPresenceStatusChange", "xnap.lowerLayerPresenceStatusChange",
        FT_UINT32, BASE_DEC, VALS(xnap_LowerLayerPresenceStatusChange_vals), 0,
        NULL, HFILL }},
    { &hf_xnap_pduSessionResourceToBeAdded,
      { "pduSessionResourceToBeAdded", "xnap.pduSessionResourceToBeAdded",
        FT_UINT32, BASE_DEC, NULL, 0,
        "PDUSessionsToBeAdded_SNModRequest_List", HFILL }},
    { &hf_xnap_pduSessionResourceToBeModified,
      { "pduSessionResourceToBeModified", "xnap.pduSessionResourceToBeModified",
        FT_UINT32, BASE_DEC, NULL, 0,
        "PDUSessionsToBeModified_SNModRequest_List", HFILL }},
    { &hf_xnap_pduSessionResourceToBeReleased,
      { "pduSessionResourceToBeReleased", "xnap.pduSessionResourceToBeReleased_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "PDUSessionsToBeReleased_SNModRequest_List", HFILL }},
    { &hf_xnap_PDUSessionsToBeAdded_SNModRequest_List_item,
      { "PDUSessionsToBeAdded-SNModRequest-Item", "xnap.PDUSessionsToBeAdded_SNModRequest_Item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_xnap_PDUSessionsToBeModified_SNModRequest_List_item,
      { "PDUSessionsToBeModified-SNModRequest-Item", "xnap.PDUSessionsToBeModified_SNModRequest_Item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_xnap_sn_terminated_02,
      { "sn-terminated", "xnap.sn_terminated_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "PDUSessionResourceModificationInfo_SNterminated", HFILL }},
    { &hf_xnap_mn_terminated_02,
      { "mn-terminated", "xnap.mn_terminated_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "PDUSessionResourceModificationInfo_MNterminated", HFILL }},
    { &hf_xnap_pdu_session_list,
      { "pdu-session-list", "xnap.pdu_session_list",
        FT_UINT32, BASE_DEC, NULL, 0,
        "PDUSession_List_withCause", HFILL }},
    { &hf_xnap_pduSessionResourcesAdmittedToBeAdded,
      { "pduSessionResourcesAdmittedToBeAdded", "xnap.pduSessionResourcesAdmittedToBeAdded",
        FT_UINT32, BASE_DEC, NULL, 0,
        "PDUSessionAdmittedToBeAddedSNModResponse", HFILL }},
    { &hf_xnap_pduSessionResourcesAdmittedToBeModified,
      { "pduSessionResourcesAdmittedToBeModified", "xnap.pduSessionResourcesAdmittedToBeModified",
        FT_UINT32, BASE_DEC, NULL, 0,
        "PDUSessionAdmittedToBeModifiedSNModResponse", HFILL }},
    { &hf_xnap_pduSessionResourcesAdmittedToBeReleased,
      { "pduSessionResourcesAdmittedToBeReleased", "xnap.pduSessionResourcesAdmittedToBeReleased_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "PDUSessionAdmittedToBeReleasedSNModResponse", HFILL }},
    { &hf_xnap_PDUSessionAdmittedToBeAddedSNModResponse_item,
      { "PDUSessionAdmittedToBeAddedSNModResponse-Item", "xnap.PDUSessionAdmittedToBeAddedSNModResponse_Item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_xnap_PDUSessionAdmittedToBeModifiedSNModResponse_item,
      { "PDUSessionAdmittedToBeModifiedSNModResponse-Item", "xnap.PDUSessionAdmittedToBeModifiedSNModResponse_Item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_xnap_sn_terminated_03,
      { "sn-terminated", "xnap.sn_terminated_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "PDUSessionResourceModificationResponseInfo_SNterminated", HFILL }},
    { &hf_xnap_mn_terminated_03,
      { "mn-terminated", "xnap.mn_terminated_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "PDUSessionResourceModificationResponseInfo_MNterminated", HFILL }},
    { &hf_xnap_sn_terminated_04,
      { "sn-terminated", "xnap.sn_terminated",
        FT_UINT32, BASE_DEC, NULL, 0,
        "PDUSession_List_withDataForwardingRequest", HFILL }},
    { &hf_xnap_mn_terminated_04,
      { "mn-terminated", "xnap.mn_terminated",
        FT_UINT32, BASE_DEC, NULL, 0,
        "PDUSession_List_withCause", HFILL }},
    { &hf_xnap_pdu_Session_List,
      { "pdu-Session-List", "xnap.pdu_Session_List",
        FT_UINT32, BASE_DEC, NULL, 0,
        "PDUSession_List", HFILL }},
    { &hf_xnap_PDUSessionToBeModifiedSNModRequired_item,
      { "PDUSessionToBeModifiedSNModRequired-Item", "xnap.PDUSessionToBeModifiedSNModRequired_Item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_xnap_sn_terminated_05,
      { "sn-terminated", "xnap.sn_terminated_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "PDUSessionResourceModRqdInfo_SNterminated", HFILL }},
    { &hf_xnap_mn_terminated_05,
      { "mn-terminated", "xnap.mn_terminated_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "PDUSessionResourceModRqdInfo_MNterminated", HFILL }},
    { &hf_xnap_PDUSessionAdmittedModSNModConfirm_item,
      { "PDUSessionAdmittedModSNModConfirm-Item", "xnap.PDUSessionAdmittedModSNModConfirm_Item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_xnap_sn_terminated_06,
      { "sn-terminated", "xnap.sn_terminated_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "PDUSessionResourceModConfirmInfo_SNterminated", HFILL }},
    { &hf_xnap_mn_terminated_06,
      { "mn-terminated", "xnap.mn_terminated_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "PDUSessionResourceModConfirmInfo_MNterminated", HFILL }},
    { &hf_xnap_sn_terminated_07,
      { "sn-terminated", "xnap.sn_terminated",
        FT_UINT32, BASE_DEC, NULL, 0,
        "PDUSession_List_withDataForwardingFromTarget", HFILL }},
    { &hf_xnap_mn_terminated_07,
      { "mn-terminated", "xnap.mn_terminated",
        FT_UINT32, BASE_DEC, NULL, 0,
        "PDUSession_List", HFILL }},
    { &hf_xnap_pduSessionsToBeReleasedList_SNterminated,
      { "pduSessionsToBeReleasedList-SNterminated", "xnap.pduSessionsToBeReleasedList_SNterminated",
        FT_UINT32, BASE_DEC, NULL, 0,
        "PDUSession_List_withDataForwardingRequest", HFILL }},
    { &hf_xnap_pduSessionsReleasedList_SNterminated,
      { "pduSessionsReleasedList-SNterminated", "xnap.pduSessionsReleasedList_SNterminated",
        FT_UINT32, BASE_DEC, NULL, 0,
        "PDUSession_List_withDataForwardingFromTarget", HFILL }},
    { &hf_xnap_BearersSubjectToCounterCheck_List_item,
      { "BearersSubjectToCounterCheck-Item", "xnap.BearersSubjectToCounterCheck_Item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_xnap_ul_count,
      { "ul-count", "xnap.ul_count",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_4294967295", HFILL }},
    { &hf_xnap_dl_count,
      { "dl-count", "xnap.dl_count",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_4294967295", HFILL }},
    { &hf_xnap_PDUSession_SNChangeRequired_List_item,
      { "PDUSession-SNChangeRequired-Item", "xnap.PDUSession_SNChangeRequired_Item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_xnap_sn_terminated_08,
      { "sn-terminated", "xnap.sn_terminated_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "PDUSessionResourceChangeRequiredInfo_SNterminated", HFILL }},
    { &hf_xnap_mn_terminated_08,
      { "mn-terminated", "xnap.mn_terminated_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "PDUSessionResourceChangeRequiredInfo_MNterminated", HFILL }},
    { &hf_xnap_PDUSession_SNChangeConfirm_List_item,
      { "PDUSession-SNChangeConfirm-Item", "xnap.PDUSession_SNChangeConfirm_Item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_xnap_sn_terminated_09,
      { "sn-terminated", "xnap.sn_terminated_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "PDUSessionResourceChangeConfirmInfo_SNterminated", HFILL }},
    { &hf_xnap_mn_terminated_09,
      { "mn-terminated", "xnap.mn_terminated_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "PDUSessionResourceChangeConfirmInfo_MNterminated", HFILL }},
    { &hf_xnap_rrcContainer,
      { "rrcContainer", "xnap.rrcContainer",
        FT_BYTES, BASE_NONE, NULL, 0,
        "OCTET_STRING", HFILL }},
    { &hf_xnap_srbType,
      { "srbType", "xnap.srbType",
        FT_UINT32, BASE_DEC, VALS(xnap_T_srbType_vals), 0,
        NULL, HFILL }},
    { &hf_xnap_deliveryStatus,
      { "deliveryStatus", "xnap.deliveryStatus",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_xnap_PDUSessionResourcesNotifyList_item,
      { "PDUSessionResourcesNotify-Item", "xnap.PDUSessionResourcesNotify_Item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_xnap_qosFlowsNotificationContrIndInfo,
      { "qosFlowsNotificationContrIndInfo", "xnap.qosFlowsNotificationContrIndInfo",
        FT_UINT32, BASE_DEC, NULL, 0,
        "QoSFlowNotificationControlIndicationInfo", HFILL }},
    { &hf_xnap_PDUSessionResourcesActivityNotifyList_item,
      { "PDUSessionResourcesActivityNotify-Item", "xnap.PDUSessionResourcesActivityNotify_Item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_xnap_pduSessionLevelUPactivityreport,
      { "pduSessionLevelUPactivityreport", "xnap.pduSessionLevelUPactivityreport",
        FT_UINT32, BASE_DEC, VALS(xnap_UserPlaneTrafficActivityReport_vals), 0,
        "UserPlaneTrafficActivityReport", HFILL }},
    { &hf_xnap_qosFlowsActivityNotifyList,
      { "qosFlowsActivityNotifyList", "xnap.qosFlowsActivityNotifyList",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_xnap_QoSFlowsActivityNotifyList_item,
      { "QoSFlowsActivityNotifyItem", "xnap.QoSFlowsActivityNotifyItem_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_xnap_gNB_01,
      { "gNB", "xnap.gNB",
        FT_UINT32, BASE_DEC, NULL, 0,
        "ProtocolIE_Container", HFILL }},
    { &hf_xnap_ng_eNB_01,
      { "ng-eNB", "xnap.ng_eNB",
        FT_UINT32, BASE_DEC, NULL, 0,
        "ProtocolIE_Container", HFILL }},
    { &hf_xnap_ng_eNB_02,
      { "ng-eNB", "xnap.ng_eNB_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "RespondingNodeTypeConfigUpdateAck_ng_eNB", HFILL }},
    { &hf_xnap_gNB_02,
      { "gNB", "xnap.gNB_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "RespondingNodeTypeConfigUpdateAck_gNB", HFILL }},
    { &hf_xnap_served_NR_Cells,
      { "served-NR-Cells", "xnap.served_NR_Cells",
        FT_UINT32, BASE_DEC, NULL, 0,
        "ServedCells_NR", HFILL }},
    { &hf_xnap_ng_eNB_03,
      { "ng-eNB", "xnap.ng_eNB_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "ResourceCoordRequest_ng_eNB_initiated", HFILL }},
    { &hf_xnap_gNB_03,
      { "gNB", "xnap.gNB_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "ResourceCoordRequest_gNB_initiated", HFILL }},
    { &hf_xnap_dataTrafficResourceIndication,
      { "dataTrafficResourceIndication", "xnap.dataTrafficResourceIndication_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_xnap_spectrumSharingGroupID,
      { "spectrumSharingGroupID", "xnap.spectrumSharingGroupID",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_xnap_listofE_UTRACells,
      { "listofE-UTRACells", "xnap.listofE_UTRACells",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_SIZE_1_maxnoofCellsinNG_RANnode_OF_E_UTRA_CGI", HFILL }},
    { &hf_xnap_listofE_UTRACells_item,
      { "E-UTRA-CGI", "xnap.E_UTRA_CGI_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_xnap_listofNRCells,
      { "listofNRCells", "xnap.listofNRCells",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_SIZE_1_maxnoofCellsinNG_RANnode_OF_NR_CGI", HFILL }},
    { &hf_xnap_listofNRCells_item,
      { "NR-CGI", "xnap.NR_CGI_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_xnap_ng_eNB_04,
      { "ng-eNB", "xnap.ng_eNB_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "ResourceCoordResponse_ng_eNB_initiated", HFILL }},
    { &hf_xnap_gNB_04,
      { "gNB", "xnap.gNB_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "ResourceCoordResponse_gNB_initiated", HFILL }},
    { &hf_xnap_nr_cells,
      { "nr-cells", "xnap.nr_cells",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_SIZE_1_maxnoofCellsinNG_RANnode_OF_NR_CGI", HFILL }},
    { &hf_xnap_nr_cells_item,
      { "NR-CGI", "xnap.NR_CGI_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_xnap_e_utra_cells,
      { "e-utra-cells", "xnap.e_utra_cells",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_SIZE_1_maxnoofCellsinNG_RANnode_OF_E_UTRA_CGI", HFILL }},
    { &hf_xnap_e_utra_cells_item,
      { "E-UTRA-CGI", "xnap.E_UTRA_CGI_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_xnap_privateIEs,
      { "privateIEs", "xnap.privateIEs",
        FT_UINT32, BASE_DEC, NULL, 0,
        "PrivateIE_Container", HFILL }},
    { &hf_xnap_initiatingMessage,
      { "initiatingMessage", "xnap.initiatingMessage_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_xnap_successfulOutcome,
      { "successfulOutcome", "xnap.successfulOutcome_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_xnap_unsuccessfulOutcome,
      { "unsuccessfulOutcome", "xnap.unsuccessfulOutcome_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_xnap_initiatingMessage_value,
      { "value", "xnap.value_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "InitiatingMessage_value", HFILL }},
    { &hf_xnap_successfulOutcome_value,
      { "value", "xnap.value_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "SuccessfulOutcome_value", HFILL }},
    { &hf_xnap_value,
      { "value", "xnap.value_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "UnsuccessfulOutcome_value", HFILL }},
    { &hf_xnap_RAT_RestrictionInformation_e_UTRA,
      { "e-UTRA", "xnap.RAT.RestrictionInformation.e.UTRA",
        FT_BOOLEAN, 8, NULL, 0x80,
        NULL, HFILL }},
    { &hf_xnap_RAT_RestrictionInformation_nR,
      { "nR", "xnap.RAT.RestrictionInformation.nR",
        FT_BOOLEAN, 8, NULL, 0x40,
        NULL, HFILL }},
    { &hf_xnap_T_interfaces_to_trace_ng_c,
      { "ng-c", "xnap.T.interfaces.to.trace.ng.c",
        FT_BOOLEAN, 8, NULL, 0x80,
        NULL, HFILL }},
    { &hf_xnap_T_interfaces_to_trace_x_nc,
      { "x-nc", "xnap.T.interfaces.to.trace.x.nc",
        FT_BOOLEAN, 8, NULL, 0x40,
        NULL, HFILL }},
    { &hf_xnap_T_interfaces_to_trace_uu,
      { "uu", "xnap.T.interfaces.to.trace.uu",
        FT_BOOLEAN, 8, NULL, 0x20,
        NULL, HFILL }},
    { &hf_xnap_T_interfaces_to_trace_f1_c,
      { "f1-c", "xnap.T.interfaces.to.trace.f1.c",
        FT_BOOLEAN, 8, NULL, 0x10,
        NULL, HFILL }},
    { &hf_xnap_T_interfaces_to_trace_e1,
      { "e1", "xnap.T.interfaces.to.trace.e1",
        FT_BOOLEAN, 8, NULL, 0x08,
        NULL, HFILL }},
    { &hf_xnap_T_nr_EncyptionAlgorithms_spare_bit0,
      { "spare_bit0", "xnap.T.nr.EncyptionAlgorithms.spare.bit0",
        FT_BOOLEAN, 8, NULL, 0x80,
        NULL, HFILL }},
    { &hf_xnap_T_nr_EncyptionAlgorithms_nea1_128,
      { "nea1-128", "xnap.T.nr.EncyptionAlgorithms.nea1.128",
        FT_BOOLEAN, 8, NULL, 0x40,
        NULL, HFILL }},
    { &hf_xnap_T_nr_EncyptionAlgorithms_nea2_128,
      { "nea2-128", "xnap.T.nr.EncyptionAlgorithms.nea2.128",
        FT_BOOLEAN, 8, NULL, 0x20,
        NULL, HFILL }},
    { &hf_xnap_T_nr_EncyptionAlgorithms_nea3_128,
      { "nea3-128", "xnap.T.nr.EncyptionAlgorithms.nea3.128",
        FT_BOOLEAN, 8, NULL, 0x10,
        NULL, HFILL }},
    { &hf_xnap_T_nr_IntegrityProtectionAlgorithms_spare_bit0,
      { "spare_bit0", "xnap.T.nr.IntegrityProtectionAlgorithms.spare.bit0",
        FT_BOOLEAN, 8, NULL, 0x80,
        NULL, HFILL }},
    { &hf_xnap_T_nr_IntegrityProtectionAlgorithms_nia1_128,
      { "nia1-128", "xnap.T.nr.IntegrityProtectionAlgorithms.nia1.128",
        FT_BOOLEAN, 8, NULL, 0x40,
        NULL, HFILL }},
    { &hf_xnap_T_nr_IntegrityProtectionAlgorithms_nia2_128,
      { "nia2-128", "xnap.T.nr.IntegrityProtectionAlgorithms.nia2.128",
        FT_BOOLEAN, 8, NULL, 0x20,
        NULL, HFILL }},
    { &hf_xnap_T_nr_IntegrityProtectionAlgorithms_nia3_128,
      { "nia3-128", "xnap.T.nr.IntegrityProtectionAlgorithms.nia3.128",
        FT_BOOLEAN, 8, NULL, 0x10,
        NULL, HFILL }},
    { &hf_xnap_T_e_utra_EncyptionAlgorithms_spare_bit0,
      { "spare_bit0", "xnap.T.e.utra.EncyptionAlgorithms.spare.bit0",
        FT_BOOLEAN, 8, NULL, 0x80,
        NULL, HFILL }},
    { &hf_xnap_T_e_utra_EncyptionAlgorithms_eea1_128,
      { "eea1-128", "xnap.T.e.utra.EncyptionAlgorithms.eea1.128",
        FT_BOOLEAN, 8, NULL, 0x40,
        NULL, HFILL }},
    { &hf_xnap_T_e_utra_EncyptionAlgorithms_eea2_128,
      { "eea2-128", "xnap.T.e.utra.EncyptionAlgorithms.eea2.128",
        FT_BOOLEAN, 8, NULL, 0x20,
        NULL, HFILL }},
    { &hf_xnap_T_e_utra_EncyptionAlgorithms_eea3_128,
      { "eea3-128", "xnap.T.e.utra.EncyptionAlgorithms.eea3.128",
        FT_BOOLEAN, 8, NULL, 0x10,
        NULL, HFILL }},
    { &hf_xnap_T_e_utra_IntegrityProtectionAlgorithms_spare_bit0,
      { "spare_bit0", "xnap.T.e.utra.IntegrityProtectionAlgorithms.spare.bit0",
        FT_BOOLEAN, 8, NULL, 0x80,
        NULL, HFILL }},
    { &hf_xnap_T_e_utra_IntegrityProtectionAlgorithms_eia1_128,
      { "eia1-128", "xnap.T.e.utra.IntegrityProtectionAlgorithms.eia1.128",
        FT_BOOLEAN, 8, NULL, 0x40,
        NULL, HFILL }},
    { &hf_xnap_T_e_utra_IntegrityProtectionAlgorithms_eia2_128,
      { "eia2-128", "xnap.T.e.utra.IntegrityProtectionAlgorithms.eia2.128",
        FT_BOOLEAN, 8, NULL, 0x20,
        NULL, HFILL }},
    { &hf_xnap_T_e_utra_IntegrityProtectionAlgorithms_eia3_128,
      { "eia3-128", "xnap.T.e.utra.IntegrityProtectionAlgorithms.eia3.128",
        FT_BOOLEAN, 8, NULL, 0x10,
        NULL, HFILL }},

/*--- End of included file: packet-xnap-hfarr.c ---*/
#line 260 "./asn1/xnap/packet-xnap-template.c"
  };

  /* List of subtrees */
  static gint *ett[] = {
    &ett_xnap,
    &ett_xnap_RRC_Context,
    &ett_nxap_container,
    &ett_xnap_PLMN_Identity,
    &ett_xnap_measurementTimingConfiguration,
    &ett_xnap_TransportLayerAddress,
    &ett_xnap_ng_ran_TraceID,
    &ett_xnap_LastVisitedEUTRANCellInformation,
    &ett_xnap_LastVisitedNGRANCellInformation,
    &ett_xnap_LastVisitedUTRANCellInformation,
    &ett_xnap_LastVisitedGERANCellInformation,
    &ett_xnap_UERadioCapabilityForPagingOfNR,
    &ett_xnap_UERadioCapabilityForPagingOfEUTRA,
    &ett_xnap_FiveGCMobilityRestrictionListContainer,

/*--- Included file: packet-xnap-ettarr.c ---*/
#line 1 "./asn1/xnap/packet-xnap-ettarr.c"
    &ett_xnap_PrivateIE_ID,
    &ett_xnap_ProtocolIE_Container,
    &ett_xnap_ProtocolIE_Field,
    &ett_xnap_ProtocolExtensionContainer,
    &ett_xnap_ProtocolExtensionField,
    &ett_xnap_PrivateIE_Container,
    &ett_xnap_PrivateIE_Field,
    &ett_xnap_Additional_UL_NG_U_TNLatUPF_Item,
    &ett_xnap_Additional_UL_NG_U_TNLatUPF_List,
    &ett_xnap_AllocationandRetentionPriority,
    &ett_xnap_AMF_Region_Information,
    &ett_xnap_GlobalAMF_Region_Information,
    &ett_xnap_AreaOfInterestInformation,
    &ett_xnap_AreaOfInterest_Item,
    &ett_xnap_AS_SecurityInformation,
    &ett_xnap_AssistanceDataForRANPaging,
    &ett_xnap_BPLMN_ID_Info_EUTRA,
    &ett_xnap_BPLMN_ID_Info_EUTRA_Item,
    &ett_xnap_BPLMN_ID_Info_NR,
    &ett_xnap_BPLMN_ID_Info_NR_Item,
    &ett_xnap_BroadcastPLMNs,
    &ett_xnap_BroadcastEUTRAPLMNs,
    &ett_xnap_BroadcastPLMNinTAISupport_Item,
    &ett_xnap_Cause,
    &ett_xnap_CellAssistanceInfo_NR,
    &ett_xnap_SEQUENCE_SIZE_1_maxnoofCellsinNG_RANnode_OF_NR_CGI,
    &ett_xnap_Connectivity_Support,
    &ett_xnap_COUNT_PDCP_SN12,
    &ett_xnap_COUNT_PDCP_SN18,
    &ett_xnap_CPTransportLayerInformation,
    &ett_xnap_CriticalityDiagnostics,
    &ett_xnap_CriticalityDiagnostics_IE_List,
    &ett_xnap_CriticalityDiagnostics_IE_List_item,
    &ett_xnap_XnUAddressInfoperPDUSession_List,
    &ett_xnap_XnUAddressInfoperPDUSession_Item,
    &ett_xnap_DataForwardingInfoFromTargetNGRANnode,
    &ett_xnap_QoSFLowsAcceptedToBeForwarded_List,
    &ett_xnap_QoSFLowsAcceptedToBeForwarded_Item,
    &ett_xnap_DataforwardingandOffloadingInfofromSource,
    &ett_xnap_QoSFLowsToBeForwarded_List,
    &ett_xnap_QoSFLowsToBeForwarded_Item,
    &ett_xnap_DataForwardingResponseDRBItemList,
    &ett_xnap_DataForwardingResponseDRBItem,
    &ett_xnap_DataTrafficResourceIndication,
    &ett_xnap_DRB_List,
    &ett_xnap_DRB_List_withCause,
    &ett_xnap_DRB_List_withCause_Item,
    &ett_xnap_DRBsSubjectToStatusTransfer_List,
    &ett_xnap_DRBsSubjectToStatusTransfer_Item,
    &ett_xnap_DRBBStatusTransferChoice,
    &ett_xnap_DRBBStatusTransfer12bitsSN,
    &ett_xnap_DRBBStatusTransfer18bitsSN,
    &ett_xnap_DRBToQoSFlowMapping_List,
    &ett_xnap_DRBToQoSFlowMapping_Item,
    &ett_xnap_Dynamic5QIDescriptor,
    &ett_xnap_E_UTRA_CGI,
    &ett_xnap_E_UTRAMultibandInfoList,
    &ett_xnap_E_UTRAPRACHConfiguration,
    &ett_xnap_EndpointIPAddressAndPort,
    &ett_xnap_ExpectedUEActivityBehaviour,
    &ett_xnap_ExpectedUEBehaviour,
    &ett_xnap_ExpectedUEMovingTrajectory,
    &ett_xnap_ExpectedUEMovingTrajectoryItem,
    &ett_xnap_GBRQoSFlowInfo,
    &ett_xnap_GlobalgNB_ID,
    &ett_xnap_GNB_ID_Choice,
    &ett_xnap_GlobalngeNB_ID,
    &ett_xnap_ENB_ID_Choice,
    &ett_xnap_GlobalNG_RANCell_ID,
    &ett_xnap_GlobalNG_RANNode_ID,
    &ett_xnap_GTPtunnelTransportLayerInformation,
    &ett_xnap_GUAMI,
    &ett_xnap_I_RNTI,
    &ett_xnap_LastVisitedCell_Item,
    &ett_xnap_ListOfCells,
    &ett_xnap_CellsinAoI_Item,
    &ett_xnap_ListOfRANNodesinAoI,
    &ett_xnap_GlobalNG_RANNodesinAoI_Item,
    &ett_xnap_ListOfTAIsinAoI,
    &ett_xnap_TAIsinAoI_Item,
    &ett_xnap_LocationReportingInformation,
    &ett_xnap_MaximumIPdatarate,
    &ett_xnap_MBSFNSubframeAllocation_E_UTRA,
    &ett_xnap_MBSFNSubframeInfo_E_UTRA,
    &ett_xnap_MBSFNSubframeInfo_E_UTRA_Item,
    &ett_xnap_MobilityRestrictionList,
    &ett_xnap_SEQUENCE_SIZE_1_maxnoofEPLMNs_OF_PLMN_Identity,
    &ett_xnap_CNTypeRestrictionsForEquivalent,
    &ett_xnap_CNTypeRestrictionsForEquivalentItem,
    &ett_xnap_RAT_RestrictionsList,
    &ett_xnap_RAT_RestrictionsItem,
    &ett_xnap_RAT_RestrictionInformation,
    &ett_xnap_ForbiddenAreaList,
    &ett_xnap_ForbiddenAreaItem,
    &ett_xnap_SEQUENCE_SIZE_1_maxnoofForbiddenTACs_OF_TAC,
    &ett_xnap_ServiceAreaList,
    &ett_xnap_ServiceAreaItem,
    &ett_xnap_SEQUENCE_SIZE_1_maxnoofAllowedAreas_OF_TAC,
    &ett_xnap_MR_DC_ResourceCoordinationInfo,
    &ett_xnap_NG_RAN_Node_ResourceCoordinationInfo,
    &ett_xnap_E_UTRA_ResourceCoordinationInfo,
    &ett_xnap_NR_ResourceCoordinationInfo,
    &ett_xnap_NE_DC_TDM_Pattern,
    &ett_xnap_NeighbourInformation_E_UTRA,
    &ett_xnap_NeighbourInformation_E_UTRA_Item,
    &ett_xnap_NeighbourInformation_NR,
    &ett_xnap_NeighbourInformation_NR_Item,
    &ett_xnap_NeighbourInformation_NR_ModeInfo,
    &ett_xnap_NeighbourInformation_NR_ModeFDDInfo,
    &ett_xnap_NeighbourInformation_NR_ModeTDDInfo,
    &ett_xnap_NG_RAN_Cell_Identity,
    &ett_xnap_NG_RAN_CellPCI,
    &ett_xnap_NonDynamic5QIDescriptor,
    &ett_xnap_NG_RAN_Cell_Identity_ListinRANPagingArea,
    &ett_xnap_NR_CGI,
    &ett_xnap_NRFrequencyBand_List,
    &ett_xnap_NRFrequencyBandItem,
    &ett_xnap_NRFrequencyInfo,
    &ett_xnap_NRModeInfo,
    &ett_xnap_NRModeInfoFDD,
    &ett_xnap_NRModeInfoTDD,
    &ett_xnap_NRTransmissionBandwidth,
    &ett_xnap_PacketErrorRate,
    &ett_xnap_PDCPChangeIndication,
    &ett_xnap_PDCPSNLength,
    &ett_xnap_PDUSessionAggregateMaximumBitRate,
    &ett_xnap_PDUSession_List,
    &ett_xnap_PDUSession_List_withCause,
    &ett_xnap_PDUSession_List_withCause_Item,
    &ett_xnap_PDUSession_List_withDataForwardingFromTarget,
    &ett_xnap_PDUSession_List_withDataForwardingFromTarget_Item,
    &ett_xnap_PDUSession_List_withDataForwardingRequest,
    &ett_xnap_PDUSession_List_withDataForwardingRequest_Item,
    &ett_xnap_PDUSessionResourcesAdmitted_List,
    &ett_xnap_PDUSessionResourcesAdmitted_Item,
    &ett_xnap_PDUSessionResourceAdmittedInfo,
    &ett_xnap_PDUSessionResourcesNotAdmitted_List,
    &ett_xnap_PDUSessionResourcesNotAdmitted_Item,
    &ett_xnap_PDUSessionResourcesToBeSetup_List,
    &ett_xnap_PDUSessionResourcesToBeSetup_Item,
    &ett_xnap_PDUSessionResourceSetupInfo_SNterminated,
    &ett_xnap_QoSFlowsToBeSetup_List_Setup_SNterminated,
    &ett_xnap_QoSFlowsToBeSetup_List_Setup_SNterminated_Item,
    &ett_xnap_PDUSessionResourceSetupResponseInfo_SNterminated,
    &ett_xnap_DRBsToBeSetupList_SetupResponse_SNterminated,
    &ett_xnap_DRBsToBeSetupList_SetupResponse_SNterminated_Item,
    &ett_xnap_QoSFlowsMappedtoDRB_SetupResponse_SNterminated,
    &ett_xnap_QoSFlowsMappedtoDRB_SetupResponse_SNterminated_Item,
    &ett_xnap_PDUSessionResourceSetupInfo_MNterminated,
    &ett_xnap_DRBsToBeSetupList_Setup_MNterminated,
    &ett_xnap_DRBsToBeSetupList_Setup_MNterminated_Item,
    &ett_xnap_QoSFlowsMappedtoDRB_Setup_MNterminated,
    &ett_xnap_QoSFlowsMappedtoDRB_Setup_MNterminated_Item,
    &ett_xnap_PDUSessionResourceSetupResponseInfo_MNterminated,
    &ett_xnap_DRBsAdmittedList_SetupResponse_MNterminated,
    &ett_xnap_DRBsAdmittedList_SetupResponse_MNterminated_Item,
    &ett_xnap_PDUSessionResourceModificationInfo_SNterminated,
    &ett_xnap_QoSFlowsToBeSetup_List_Modified_SNterminated,
    &ett_xnap_QoSFlowsToBeSetup_List_Modified_SNterminated_Item,
    &ett_xnap_DRBsToBeModified_List_Modified_SNterminated,
    &ett_xnap_DRBsToBeModified_List_Modified_SNterminated_Item,
    &ett_xnap_PDUSessionResourceModificationResponseInfo_SNterminated,
    &ett_xnap_DRBsToBeModifiedList_ModificationResponse_SNterminated,
    &ett_xnap_DRBsToBeModifiedList_ModificationResponse_SNterminated_Item,
    &ett_xnap_PDUSessionResourceModificationInfo_MNterminated,
    &ett_xnap_DRBsToBeModifiedList_Modification_MNterminated,
    &ett_xnap_DRBsToBeModifiedList_Modification_MNterminated_Item,
    &ett_xnap_PDUSessionResourceModificationResponseInfo_MNterminated,
    &ett_xnap_DRBsAdmittedList_ModificationResponse_MNterminated,
    &ett_xnap_DRBsAdmittedList_ModificationResponse_MNterminated_Item,
    &ett_xnap_PDUSessionResourceChangeRequiredInfo_SNterminated,
    &ett_xnap_PDUSessionResourceChangeConfirmInfo_SNterminated,
    &ett_xnap_PDUSessionResourceChangeRequiredInfo_MNterminated,
    &ett_xnap_PDUSessionResourceChangeConfirmInfo_MNterminated,
    &ett_xnap_PDUSessionResourceModRqdInfo_SNterminated,
    &ett_xnap_DRBsToBeSetup_List_ModRqd_SNterminated,
    &ett_xnap_DRBsToBeSetup_List_ModRqd_SNterminated_Item,
    &ett_xnap_QoSFlowsSetupMappedtoDRB_ModRqd_SNterminated,
    &ett_xnap_QoSFlowsSetupMappedtoDRB_ModRqd_SNterminated_Item,
    &ett_xnap_DRBsToBeModified_List_ModRqd_SNterminated,
    &ett_xnap_DRBsToBeModified_List_ModRqd_SNterminated_Item,
    &ett_xnap_QoSFlowsModifiedMappedtoDRB_ModRqd_SNterminated,
    &ett_xnap_QoSFlowsModifiedMappedtoDRB_ModRqd_SNterminated_Item,
    &ett_xnap_PDUSessionResourceModConfirmInfo_SNterminated,
    &ett_xnap_DRBsAdmittedList_ModConfirm_SNterminated,
    &ett_xnap_DRBsAdmittedList_ModConfirm_SNterminated_Item,
    &ett_xnap_PDUSessionResourceModRqdInfo_MNterminated,
    &ett_xnap_DRBsToBeModified_List_ModRqd_MNterminated,
    &ett_xnap_DRBsToBeModified_List_ModRqd_MNterminated_Item,
    &ett_xnap_PDUSessionResourceModConfirmInfo_MNterminated,
    &ett_xnap_PDUSessionResourceBearerSetupCompleteInfo_SNterminated,
    &ett_xnap_SEQUENCE_SIZE_1_maxnoofDRBs_OF_DRBsToBeSetupList_BearerSetupComplete_SNterminated_Item,
    &ett_xnap_DRBsToBeSetupList_BearerSetupComplete_SNterminated_Item,
    &ett_xnap_PDUSessionResourceSecondaryRATUsageList,
    &ett_xnap_PDUSessionResourceSecondaryRATUsageItem,
    &ett_xnap_PDUSessionUsageReport,
    &ett_xnap_ProtectedE_UTRAResourceIndication,
    &ett_xnap_ProtectedE_UTRAResourceList,
    &ett_xnap_ProtectedE_UTRAResource_Item,
    &ett_xnap_ProtectedE_UTRAFootprintTimePattern,
    &ett_xnap_QoSCharacteristics,
    &ett_xnap_QoSFlowLevelQoSParameters,
    &ett_xnap_QoSFlowNotificationControlIndicationInfo,
    &ett_xnap_QoSFlowNotify_Item,
    &ett_xnap_QoSFlows_List,
    &ett_xnap_QoSFlow_Item,
    &ett_xnap_QoSFlows_List_withCause,
    &ett_xnap_QoSFlowwithCause_Item,
    &ett_xnap_QoSFlowsAdmitted_List,
    &ett_xnap_QoSFlowsAdmitted_Item,
    &ett_xnap_QoSFlowsToBeSetup_List,
    &ett_xnap_QoSFlowsToBeSetup_Item,
    &ett_xnap_QoSFlowsUsageReportList,
    &ett_xnap_QoSFlowsUsageReport_Item,
    &ett_xnap_RANAreaID,
    &ett_xnap_RANAreaID_List,
    &ett_xnap_RANPagingArea,
    &ett_xnap_RANPagingAreaChoice,
    &ett_xnap_RANPagingAttemptInfo,
    &ett_xnap_ReservedSubframePattern,
    &ett_xnap_ResetRequestTypeInfo,
    &ett_xnap_ResetRequestTypeInfo_Full,
    &ett_xnap_ResetRequestTypeInfo_Partial,
    &ett_xnap_ResetRequestPartialReleaseList,
    &ett_xnap_ResetRequestPartialReleaseItem,
    &ett_xnap_ResetResponseTypeInfo,
    &ett_xnap_ResetResponseTypeInfo_Full,
    &ett_xnap_ResetResponseTypeInfo_Partial,
    &ett_xnap_ResetResponsePartialReleaseList,
    &ett_xnap_ResetResponsePartialReleaseItem,
    &ett_xnap_RLC_Status,
    &ett_xnap_SecondarydataForwardingInfoFromTarget_Item,
    &ett_xnap_SecondarydataForwardingInfoFromTarget_List,
    &ett_xnap_SecondaryRATUsageInformation,
    &ett_xnap_SecurityIndication,
    &ett_xnap_SecurityResult,
    &ett_xnap_ServedCellInformation_E_UTRA,
    &ett_xnap_SEQUENCE_SIZE_1_maxnoofBPLMNs_OF_ServedCellInformation_E_UTRA_perBPLMN,
    &ett_xnap_ServedCellInformation_E_UTRA_perBPLMN,
    &ett_xnap_ServedCellInformation_E_UTRA_ModeInfo,
    &ett_xnap_ServedCellInformation_E_UTRA_FDDInfo,
    &ett_xnap_ServedCellInformation_E_UTRA_TDDInfo,
    &ett_xnap_ServedCells_E_UTRA,
    &ett_xnap_ServedCells_E_UTRA_Item,
    &ett_xnap_ServedCellsToUpdate_E_UTRA,
    &ett_xnap_SEQUENCE_SIZE_1_maxnoofCellsinNG_RANnode_OF_E_UTRA_CGI,
    &ett_xnap_ServedCells_ToModify_E_UTRA,
    &ett_xnap_ServedCells_ToModify_E_UTRA_Item,
    &ett_xnap_ServedCellInformation_NR,
    &ett_xnap_ServedCells_NR,
    &ett_xnap_ServedCells_NR_Item,
    &ett_xnap_ServedCells_ToModify_NR,
    &ett_xnap_ServedCells_ToModify_NR_Item,
    &ett_xnap_ServedCellsToUpdate_NR,
    &ett_xnap_SharedResourceType,
    &ett_xnap_SharedResourceType_UL_OnlySharing,
    &ett_xnap_SharedResourceType_ULDL_Sharing,
    &ett_xnap_SharedResourceType_ULDL_Sharing_UL_Resources,
    &ett_xnap_SharedResourceType_ULDL_Sharing_UL_ResourcesChanged,
    &ett_xnap_SharedResourceType_ULDL_Sharing_DL_Resources,
    &ett_xnap_SharedResourceType_ULDL_Sharing_DL_ResourcesChanged,
    &ett_xnap_SliceSupport_List,
    &ett_xnap_S_NSSAI,
    &ett_xnap_SpecialSubframeInfo_E_UTRA,
    &ett_xnap_SUL_Information,
    &ett_xnap_SupportedSULBandList,
    &ett_xnap_SupportedSULBandItem,
    &ett_xnap_TAISupport_List,
    &ett_xnap_TAISupport_Item,
    &ett_xnap_SEQUENCE_SIZE_1_maxnoofsupportedPLMNs_OF_BroadcastPLMNinTAISupport_Item,
    &ett_xnap_Target_CGI,
    &ett_xnap_TNLA_To_Add_List,
    &ett_xnap_TNLA_To_Add_Item,
    &ett_xnap_TNLA_To_Update_List,
    &ett_xnap_TNLA_To_Update_Item,
    &ett_xnap_TNLA_To_Remove_List,
    &ett_xnap_TNLA_To_Remove_Item,
    &ett_xnap_TNLA_Setup_List,
    &ett_xnap_TNLA_Setup_Item,
    &ett_xnap_TNLA_Failed_To_Setup_List,
    &ett_xnap_TNLA_Failed_To_Setup_Item,
    &ett_xnap_TraceActivation,
    &ett_xnap_T_interfaces_to_trace,
    &ett_xnap_UEAggregateMaximumBitRate,
    &ett_xnap_UEContextID,
    &ett_xnap_UEContextIDforRRCResume,
    &ett_xnap_UEContextIDforRRCReestablishment,
    &ett_xnap_UEContextInfoRetrUECtxtResp,
    &ett_xnap_UEHistoryInformation,
    &ett_xnap_UEIdentityIndexValue,
    &ett_xnap_UERadioCapabilityForPaging,
    &ett_xnap_UERANPagingIdentity,
    &ett_xnap_UESecurityCapabilities,
    &ett_xnap_T_nr_EncyptionAlgorithms,
    &ett_xnap_T_nr_IntegrityProtectionAlgorithms,
    &ett_xnap_T_e_utra_EncyptionAlgorithms,
    &ett_xnap_T_e_utra_IntegrityProtectionAlgorithms,
    &ett_xnap_ULConfiguration,
    &ett_xnap_UPTransportLayerInformation,
    &ett_xnap_UPTransportParameters,
    &ett_xnap_UPTransportParametersItem,
    &ett_xnap_VolumeTimedReportList,
    &ett_xnap_VolumeTimedReport_Item,
    &ett_xnap_HandoverRequest,
    &ett_xnap_UEContextInfoHORequest,
    &ett_xnap_UEContextRefAtSN_HORequest,
    &ett_xnap_HandoverRequestAcknowledge,
    &ett_xnap_HandoverPreparationFailure,
    &ett_xnap_SNStatusTransfer,
    &ett_xnap_UEContextRelease,
    &ett_xnap_HandoverCancel,
    &ett_xnap_RANPaging,
    &ett_xnap_RetrieveUEContextRequest,
    &ett_xnap_RetrieveUEContextResponse,
    &ett_xnap_RetrieveUEContextFailure,
    &ett_xnap_XnUAddressIndication,
    &ett_xnap_SNodeAdditionRequest,
    &ett_xnap_PDUSessionToBeAddedAddReq,
    &ett_xnap_PDUSessionToBeAddedAddReq_Item,
    &ett_xnap_SNodeAdditionRequestAcknowledge,
    &ett_xnap_PDUSessionAdmittedAddedAddReqAck,
    &ett_xnap_PDUSessionAdmittedAddedAddReqAck_Item,
    &ett_xnap_PDUSessionNotAdmittedAddReqAck,
    &ett_xnap_SNodeAdditionRequestReject,
    &ett_xnap_SNodeReconfigurationComplete,
    &ett_xnap_ResponseInfo_ReconfCompl,
    &ett_xnap_ResponseType_ReconfComplete,
    &ett_xnap_Configuration_successfully_applied,
    &ett_xnap_Configuration_rejected_by_M_NG_RANNode,
    &ett_xnap_SNodeModificationRequest,
    &ett_xnap_UEContextInfo_SNModRequest,
    &ett_xnap_PDUSessionsToBeAdded_SNModRequest_List,
    &ett_xnap_PDUSessionsToBeAdded_SNModRequest_Item,
    &ett_xnap_PDUSessionsToBeModified_SNModRequest_List,
    &ett_xnap_PDUSessionsToBeModified_SNModRequest_Item,
    &ett_xnap_PDUSessionsToBeReleased_SNModRequest_List,
    &ett_xnap_SNodeModificationRequestAcknowledge,
    &ett_xnap_PDUSessionAdmitted_SNModResponse,
    &ett_xnap_PDUSessionAdmittedToBeAddedSNModResponse,
    &ett_xnap_PDUSessionAdmittedToBeAddedSNModResponse_Item,
    &ett_xnap_PDUSessionAdmittedToBeModifiedSNModResponse,
    &ett_xnap_PDUSessionAdmittedToBeModifiedSNModResponse_Item,
    &ett_xnap_PDUSessionAdmittedToBeReleasedSNModResponse,
    &ett_xnap_PDUSessionNotAdmitted_SNModResponse,
    &ett_xnap_PDUSessionDataForwarding_SNModResponse,
    &ett_xnap_SNodeModificationRequestReject,
    &ett_xnap_SNodeModificationRequired,
    &ett_xnap_PDUSessionToBeModifiedSNModRequired,
    &ett_xnap_PDUSessionToBeModifiedSNModRequired_Item,
    &ett_xnap_PDUSessionToBeReleasedSNModRequired,
    &ett_xnap_SNodeModificationConfirm,
    &ett_xnap_PDUSessionAdmittedModSNModConfirm,
    &ett_xnap_PDUSessionAdmittedModSNModConfirm_Item,
    &ett_xnap_PDUSessionReleasedSNModConfirm,
    &ett_xnap_SNodeModificationRefuse,
    &ett_xnap_SNodeReleaseRequest,
    &ett_xnap_SNodeReleaseRequestAcknowledge,
    &ett_xnap_PDUSessionToBeReleasedList_RelReqAck,
    &ett_xnap_SNodeReleaseReject,
    &ett_xnap_SNodeReleaseRequired,
    &ett_xnap_PDUSessionToBeReleasedList_RelRqd,
    &ett_xnap_SNodeReleaseConfirm,
    &ett_xnap_PDUSessionReleasedList_RelConf,
    &ett_xnap_SNodeCounterCheckRequest,
    &ett_xnap_BearersSubjectToCounterCheck_List,
    &ett_xnap_BearersSubjectToCounterCheck_Item,
    &ett_xnap_SNodeChangeRequired,
    &ett_xnap_PDUSession_SNChangeRequired_List,
    &ett_xnap_PDUSession_SNChangeRequired_Item,
    &ett_xnap_SNodeChangeConfirm,
    &ett_xnap_PDUSession_SNChangeConfirm_List,
    &ett_xnap_PDUSession_SNChangeConfirm_Item,
    &ett_xnap_SNodeChangeRefuse,
    &ett_xnap_RRCTransfer,
    &ett_xnap_SplitSRB_RRCTransfer,
    &ett_xnap_UEReportRRCTransfer,
    &ett_xnap_NotificationControlIndication,
    &ett_xnap_PDUSessionResourcesNotifyList,
    &ett_xnap_PDUSessionResourcesNotify_Item,
    &ett_xnap_ActivityNotification,
    &ett_xnap_PDUSessionResourcesActivityNotifyList,
    &ett_xnap_PDUSessionResourcesActivityNotify_Item,
    &ett_xnap_QoSFlowsActivityNotifyList,
    &ett_xnap_QoSFlowsActivityNotifyItem,
    &ett_xnap_XnSetupRequest,
    &ett_xnap_XnSetupResponse,
    &ett_xnap_XnSetupFailure,
    &ett_xnap_NGRANNodeConfigurationUpdate,
    &ett_xnap_ConfigurationUpdateInitiatingNodeChoice,
    &ett_xnap_NGRANNodeConfigurationUpdateAcknowledge,
    &ett_xnap_RespondingNodeTypeConfigUpdateAck,
    &ett_xnap_RespondingNodeTypeConfigUpdateAck_ng_eNB,
    &ett_xnap_RespondingNodeTypeConfigUpdateAck_gNB,
    &ett_xnap_NGRANNodeConfigurationUpdateFailure,
    &ett_xnap_E_UTRA_NR_CellResourceCoordinationRequest,
    &ett_xnap_InitiatingNodeType_ResourceCoordRequest,
    &ett_xnap_ResourceCoordRequest_ng_eNB_initiated,
    &ett_xnap_ResourceCoordRequest_gNB_initiated,
    &ett_xnap_E_UTRA_NR_CellResourceCoordinationResponse,
    &ett_xnap_RespondingNodeType_ResourceCoordResponse,
    &ett_xnap_ResourceCoordResponse_ng_eNB_initiated,
    &ett_xnap_ResourceCoordResponse_gNB_initiated,
    &ett_xnap_SecondaryRATDataUsageReport,
    &ett_xnap_XnRemovalRequest,
    &ett_xnap_XnRemovalResponse,
    &ett_xnap_XnRemovalFailure,
    &ett_xnap_CellActivationRequest,
    &ett_xnap_ServedCellsToActivate,
    &ett_xnap_CellActivationResponse,
    &ett_xnap_ActivatedServedCells,
    &ett_xnap_CellActivationFailure,
    &ett_xnap_ResetRequest,
    &ett_xnap_ResetResponse,
    &ett_xnap_ErrorIndication,
    &ett_xnap_PrivateMessage,
    &ett_xnap_XnAP_PDU,
    &ett_xnap_InitiatingMessage,
    &ett_xnap_SuccessfulOutcome,
    &ett_xnap_UnsuccessfulOutcome,

/*--- End of included file: packet-xnap-ettarr.c ---*/
#line 279 "./asn1/xnap/packet-xnap-template.c"
  };

  module_t *xnap_module;

  proto_xnap = proto_register_protocol(PNAME, PSNAME, PFNAME);
  proto_register_field_array(proto_xnap, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));

  xnap_handle = register_dissector("xnap", dissect_xnap, proto_xnap);

  xnap_ies_dissector_table = register_dissector_table("xnap.ies", "XNAP-PROTOCOL-IES", proto_xnap, FT_UINT32, BASE_DEC);
  xnap_extension_dissector_table = register_dissector_table("xnap.extension", "XNAP-PROTOCOL-EXTENSION", proto_xnap, FT_UINT32, BASE_DEC);
  xnap_proc_imsg_dissector_table = register_dissector_table("xnap.proc.imsg", "XNAP-ELEMENTARY-PROCEDURE InitiatingMessage", proto_xnap, FT_UINT32, BASE_DEC);
  xnap_proc_sout_dissector_table = register_dissector_table("xnap.proc.sout", "XNAP-ELEMENTARY-PROCEDURE SuccessfulOutcome", proto_xnap, FT_UINT32, BASE_DEC);
  xnap_proc_uout_dissector_table = register_dissector_table("xnap.proc.uout", "XNAP-ELEMENTARY-PROCEDURE UnsuccessfulOutcome", proto_xnap, FT_UINT32, BASE_DEC);

  xnap_module = prefs_register_protocol(proto_xnap, proto_reg_handoff_xnap);

  prefs_register_uint_preference(xnap_module, "sctp.port",
                                 "XnAP SCTP Port",
                                 "Set the SCTP port for XnAP messages",
                                 10,
                                 &xnap_sctp_port);
  prefs_register_enum_preference(xnap_module, "dissect_target_ng_ran_container_as", "Dissect target NG-RAN container as",
                                 "Select whether target NG-RAN container should be decoded automatically"
                                 " (based on Xn Setup procedure) or manually",
                                 &xnap_dissect_target_ng_ran_container_as, xnap_target_ng_ran_container_vals, FALSE);
}


void
proto_reg_handoff_xnap(void)
{
  static gboolean initialized = FALSE;
  static guint sctp_port;

  if (!initialized) {
    dissector_add_for_decode_as("sctp.port", xnap_handle);
    dissector_add_uint("sctp.ppi", XNAP_PROTOCOL_ID, xnap_handle);
    initialized = TRUE;

/*--- Included file: packet-xnap-dis-tab.c ---*/
#line 1 "./asn1/xnap/packet-xnap-dis-tab.c"
  dissector_add_uint("xnap.ies", id_ActivatedServedCells, create_dissector_handle(dissect_ActivatedServedCells_PDU, proto_xnap));
  dissector_add_uint("xnap.ies", id_ActivationIDforCellActivation, create_dissector_handle(dissect_ActivationIDforCellActivation_PDU, proto_xnap));
  dissector_add_uint("xnap.ies", id_admittedSplitSRB, create_dissector_handle(dissect_SplitSRBsTypes_PDU, proto_xnap));
  dissector_add_uint("xnap.ies", id_admittedSplitSRBrelease, create_dissector_handle(dissect_SplitSRBsTypes_PDU, proto_xnap));
  dissector_add_uint("xnap.ies", id_AMF_Region_Information, create_dissector_handle(dissect_AMF_Region_Information_PDU, proto_xnap));
  dissector_add_uint("xnap.ies", id_AssistanceDataForRANPaging, create_dissector_handle(dissect_AssistanceDataForRANPaging_PDU, proto_xnap));
  dissector_add_uint("xnap.ies", id_BearersSubjectToCounterCheck, create_dissector_handle(dissect_BearersSubjectToCounterCheck_List_PDU, proto_xnap));
  dissector_add_uint("xnap.ies", id_Cause, create_dissector_handle(dissect_Cause_PDU, proto_xnap));
  dissector_add_uint("xnap.ies", id_cellAssistanceInfo_NR, create_dissector_handle(dissect_CellAssistanceInfo_NR_PDU, proto_xnap));
  dissector_add_uint("xnap.ies", id_ConfigurationUpdateInitiatingNodeChoice, create_dissector_handle(dissect_ConfigurationUpdateInitiatingNodeChoice_PDU, proto_xnap));
  dissector_add_uint("xnap.ies", id_CriticalityDiagnostics, create_dissector_handle(dissect_CriticalityDiagnostics_PDU, proto_xnap));
  dissector_add_uint("xnap.ies", id_XnUAddressInfoperPDUSession_List, create_dissector_handle(dissect_XnUAddressInfoperPDUSession_List_PDU, proto_xnap));
  dissector_add_uint("xnap.ies", id_DRBsSubjectToStatusTransfer_List, create_dissector_handle(dissect_DRBsSubjectToStatusTransfer_List_PDU, proto_xnap));
  dissector_add_uint("xnap.ies", id_ExpectedUEBehaviour, create_dissector_handle(dissect_ExpectedUEBehaviour_PDU, proto_xnap));
  dissector_add_uint("xnap.ies", id_GlobalNG_RAN_node_ID, create_dissector_handle(dissect_GlobalNG_RANNode_ID_PDU, proto_xnap));
  dissector_add_uint("xnap.ies", id_GUAMI, create_dissector_handle(dissect_GUAMI_PDU, proto_xnap));
  dissector_add_uint("xnap.ies", id_indexToRatFrequSelectionPriority, create_dissector_handle(dissect_RFSP_Index_PDU, proto_xnap));
  dissector_add_uint("xnap.ies", id_initiatingNodeType_ResourceCoordRequest, create_dissector_handle(dissect_InitiatingNodeType_ResourceCoordRequest_PDU, proto_xnap));
  dissector_add_uint("xnap.ies", id_List_of_served_cells_E_UTRA, create_dissector_handle(dissect_ServedCells_E_UTRA_PDU, proto_xnap));
  dissector_add_uint("xnap.ies", id_List_of_served_cells_NR, create_dissector_handle(dissect_ServedCells_NR_PDU, proto_xnap));
  dissector_add_uint("xnap.ies", id_LocationReportingInformation, create_dissector_handle(dissect_LocationReportingInformation_PDU, proto_xnap));
  dissector_add_uint("xnap.ies", id_MAC_I, create_dissector_handle(dissect_MAC_I_PDU, proto_xnap));
  dissector_add_uint("xnap.ies", id_MaskedIMEISV, create_dissector_handle(dissect_MaskedIMEISV_PDU, proto_xnap));
  dissector_add_uint("xnap.ies", id_M_NG_RANnodeUEXnAPID, create_dissector_handle(dissect_NG_RANnodeUEXnAPID_PDU, proto_xnap));
  dissector_add_uint("xnap.ies", id_MN_to_SN_Container, create_dissector_handle(dissect_MN_to_SN_Container_PDU, proto_xnap));
  dissector_add_uint("xnap.ies", id_MobilityRestrictionList, create_dissector_handle(dissect_MobilityRestrictionList_PDU, proto_xnap));
  dissector_add_uint("xnap.ies", id_new_NG_RAN_Cell_Identity, create_dissector_handle(dissect_NG_RAN_Cell_Identity_PDU, proto_xnap));
  dissector_add_uint("xnap.ies", id_newNG_RANnodeUEXnAPID, create_dissector_handle(dissect_NG_RANnodeUEXnAPID_PDU, proto_xnap));
  dissector_add_uint("xnap.ies", id_UEReportRRCTransfer, create_dissector_handle(dissect_UEReportRRCTransfer_PDU, proto_xnap));
  dissector_add_uint("xnap.ies", id_oldNG_RANnodeUEXnAPID, create_dissector_handle(dissect_NG_RANnodeUEXnAPID_PDU, proto_xnap));
  dissector_add_uint("xnap.ies", id_OldtoNewNG_RANnodeResumeContainer, create_dissector_handle(dissect_OldtoNewNG_RANnodeResumeContainer_PDU, proto_xnap));
  dissector_add_uint("xnap.ies", id_PagingDRX, create_dissector_handle(dissect_PagingDRX_PDU, proto_xnap));
  dissector_add_uint("xnap.ies", id_PCellID, create_dissector_handle(dissect_GlobalNG_RANCell_ID_PDU, proto_xnap));
  dissector_add_uint("xnap.ies", id_PDCPChangeIndication, create_dissector_handle(dissect_PDCPChangeIndication_PDU, proto_xnap));
  dissector_add_uint("xnap.ies", id_PDUSessionAdmittedAddedAddReqAck, create_dissector_handle(dissect_PDUSessionAdmittedAddedAddReqAck_PDU, proto_xnap));
  dissector_add_uint("xnap.ies", id_PDUSessionAdmittedModSNModConfirm, create_dissector_handle(dissect_PDUSessionAdmittedModSNModConfirm_PDU, proto_xnap));
  dissector_add_uint("xnap.ies", id_PDUSessionAdmitted_SNModResponse, create_dissector_handle(dissect_PDUSessionAdmitted_SNModResponse_PDU, proto_xnap));
  dissector_add_uint("xnap.ies", id_PDUSessionNotAdmittedAddReqAck, create_dissector_handle(dissect_PDUSessionNotAdmittedAddReqAck_PDU, proto_xnap));
  dissector_add_uint("xnap.ies", id_PDUSessionNotAdmitted_SNModResponse, create_dissector_handle(dissect_PDUSessionNotAdmitted_SNModResponse_PDU, proto_xnap));
  dissector_add_uint("xnap.ies", id_PDUSessionReleasedList_RelConf, create_dissector_handle(dissect_PDUSessionReleasedList_RelConf_PDU, proto_xnap));
  dissector_add_uint("xnap.ies", id_PDUSessionReleasedSNModConfirm, create_dissector_handle(dissect_PDUSessionReleasedSNModConfirm_PDU, proto_xnap));
  dissector_add_uint("xnap.ies", id_PDUSessionResourcesActivityNotifyList, create_dissector_handle(dissect_PDUSessionResourcesActivityNotifyList_PDU, proto_xnap));
  dissector_add_uint("xnap.ies", id_PDUSessionResourcesAdmitted_List, create_dissector_handle(dissect_PDUSessionResourcesAdmitted_List_PDU, proto_xnap));
  dissector_add_uint("xnap.ies", id_PDUSessionResourcesNotAdmitted_List, create_dissector_handle(dissect_PDUSessionResourcesNotAdmitted_List_PDU, proto_xnap));
  dissector_add_uint("xnap.ies", id_PDUSessionResourcesNotifyList, create_dissector_handle(dissect_PDUSessionResourcesNotifyList_PDU, proto_xnap));
  dissector_add_uint("xnap.ies", id_PDUSession_SNChangeConfirm_List, create_dissector_handle(dissect_PDUSession_SNChangeConfirm_List_PDU, proto_xnap));
  dissector_add_uint("xnap.ies", id_PDUSession_SNChangeRequired_List, create_dissector_handle(dissect_PDUSession_SNChangeRequired_List_PDU, proto_xnap));
  dissector_add_uint("xnap.ies", id_PDUSessionToBeAddedAddReq, create_dissector_handle(dissect_PDUSessionToBeAddedAddReq_PDU, proto_xnap));
  dissector_add_uint("xnap.ies", id_PDUSessionToBeModifiedSNModRequired, create_dissector_handle(dissect_PDUSessionToBeModifiedSNModRequired_PDU, proto_xnap));
  dissector_add_uint("xnap.ies", id_PDUSessionToBeReleasedList_RelRqd, create_dissector_handle(dissect_PDUSessionToBeReleasedList_RelRqd_PDU, proto_xnap));
  dissector_add_uint("xnap.ies", id_PDUSessionToBeReleased_RelReq, create_dissector_handle(dissect_PDUSession_List_withCause_PDU, proto_xnap));
  dissector_add_uint("xnap.ies", id_PDUSessionToBeReleasedSNModRequired, create_dissector_handle(dissect_PDUSessionToBeReleasedSNModRequired_PDU, proto_xnap));
  dissector_add_uint("xnap.ies", id_RANPagingArea, create_dissector_handle(dissect_RANPagingArea_PDU, proto_xnap));
  dissector_add_uint("xnap.ies", id_PagingPriority, create_dissector_handle(dissect_PagingPriority_PDU, proto_xnap));
  dissector_add_uint("xnap.ies", id_requestedSplitSRB, create_dissector_handle(dissect_SplitSRBsTypes_PDU, proto_xnap));
  dissector_add_uint("xnap.ies", id_requestedSplitSRBrelease, create_dissector_handle(dissect_SplitSRBsTypes_PDU, proto_xnap));
  dissector_add_uint("xnap.ies", id_ResetRequestTypeInfo, create_dissector_handle(dissect_ResetRequestTypeInfo_PDU, proto_xnap));
  dissector_add_uint("xnap.ies", id_ResetResponseTypeInfo, create_dissector_handle(dissect_ResetResponseTypeInfo_PDU, proto_xnap));
  dissector_add_uint("xnap.ies", id_RespondingNodeTypeConfigUpdateAck, create_dissector_handle(dissect_RespondingNodeTypeConfigUpdateAck_PDU, proto_xnap));
  dissector_add_uint("xnap.ies", id_respondingNodeType_ResourceCoordResponse, create_dissector_handle(dissect_RespondingNodeType_ResourceCoordResponse_PDU, proto_xnap));
  dissector_add_uint("xnap.ies", id_ResponseInfo_ReconfCompl, create_dissector_handle(dissect_ResponseInfo_ReconfCompl_PDU, proto_xnap));
  dissector_add_uint("xnap.ies", id_RRCConfigIndication, create_dissector_handle(dissect_RRCConfigIndication_PDU, proto_xnap));
  dissector_add_uint("xnap.ies", id_RRCResumeCause, create_dissector_handle(dissect_RRCResumeCause_PDU, proto_xnap));
  dissector_add_uint("xnap.ies", id_SCGConfigurationQuery, create_dissector_handle(dissect_SCGConfigurationQuery_PDU, proto_xnap));
  dissector_add_uint("xnap.ies", id_selectedPLMN, create_dissector_handle(dissect_PLMN_Identity_PDU, proto_xnap));
  dissector_add_uint("xnap.ies", id_ServedCellsToActivate, create_dissector_handle(dissect_ServedCellsToActivate_PDU, proto_xnap));
  dissector_add_uint("xnap.ies", id_servedCellsToUpdate_E_UTRA, create_dissector_handle(dissect_ServedCellsToUpdate_E_UTRA_PDU, proto_xnap));
  dissector_add_uint("xnap.ies", id_servedCellsToUpdate_NR, create_dissector_handle(dissect_ServedCellsToUpdate_NR_PDU, proto_xnap));
  dissector_add_uint("xnap.ies", id_s_ng_RANnode_SecurityKey, create_dissector_handle(dissect_S_NG_RANnode_SecurityKey_PDU, proto_xnap));
  dissector_add_uint("xnap.ies", id_S_NG_RANnodeUE_AMBR, create_dissector_handle(dissect_UEAggregateMaximumBitRate_PDU, proto_xnap));
  dissector_add_uint("xnap.ies", id_S_NG_RANnodeUEXnAPID, create_dissector_handle(dissect_NG_RANnodeUEXnAPID_PDU, proto_xnap));
  dissector_add_uint("xnap.ies", id_SN_to_MN_Container, create_dissector_handle(dissect_SN_to_MN_Container_PDU, proto_xnap));
  dissector_add_uint("xnap.ies", id_sourceNG_RANnodeUEXnAPID, create_dissector_handle(dissect_NG_RANnodeUEXnAPID_PDU, proto_xnap));
  dissector_add_uint("xnap.ies", id_SplitSRB_RRCTransfer, create_dissector_handle(dissect_SplitSRB_RRCTransfer_PDU, proto_xnap));
  dissector_add_uint("xnap.ies", id_TAISupport_list, create_dissector_handle(dissect_TAISupport_List_PDU, proto_xnap));
  dissector_add_uint("xnap.ies", id_TimeToWait, create_dissector_handle(dissect_TimeToWait_PDU, proto_xnap));
  dissector_add_uint("xnap.ies", id_Target2SourceNG_RANnodeTranspContainer, create_dissector_handle(dissect_Target2SourceNG_RANnodeTranspContainer_PDU, proto_xnap));
  dissector_add_uint("xnap.ies", id_targetCellGlobalID, create_dissector_handle(dissect_Target_CGI_PDU, proto_xnap));
  dissector_add_uint("xnap.ies", id_targetNG_RANnodeUEXnAPID, create_dissector_handle(dissect_NG_RANnodeUEXnAPID_PDU, proto_xnap));
  dissector_add_uint("xnap.ies", id_target_S_NG_RANnodeID, create_dissector_handle(dissect_GlobalNG_RANNode_ID_PDU, proto_xnap));
  dissector_add_uint("xnap.ies", id_TraceActivation, create_dissector_handle(dissect_TraceActivation_PDU, proto_xnap));
  dissector_add_uint("xnap.ies", id_UEContextID, create_dissector_handle(dissect_UEContextID_PDU, proto_xnap));
  dissector_add_uint("xnap.ies", id_UEContextInfoHORequest, create_dissector_handle(dissect_UEContextInfoHORequest_PDU, proto_xnap));
  dissector_add_uint("xnap.ies", id_UEContextInfoRetrUECtxtResp, create_dissector_handle(dissect_UEContextInfoRetrUECtxtResp_PDU, proto_xnap));
  dissector_add_uint("xnap.ies", id_UEContextInfo_SNModRequest, create_dissector_handle(dissect_UEContextInfo_SNModRequest_PDU, proto_xnap));
  dissector_add_uint("xnap.ies", id_UEContextKeptIndicator, create_dissector_handle(dissect_UEContextKeptIndicator_PDU, proto_xnap));
  dissector_add_uint("xnap.ies", id_UEContextRefAtSN_HORequest, create_dissector_handle(dissect_UEContextRefAtSN_HORequest_PDU, proto_xnap));
  dissector_add_uint("xnap.ies", id_UEHistoryInformation, create_dissector_handle(dissect_UEHistoryInformation_PDU, proto_xnap));
  dissector_add_uint("xnap.ies", id_UEIdentityIndexValue, create_dissector_handle(dissect_UEIdentityIndexValue_PDU, proto_xnap));
  dissector_add_uint("xnap.ies", id_UERANPagingIdentity, create_dissector_handle(dissect_UERANPagingIdentity_PDU, proto_xnap));
  dissector_add_uint("xnap.ies", id_UESecurityCapabilities, create_dissector_handle(dissect_UESecurityCapabilities_PDU, proto_xnap));
  dissector_add_uint("xnap.ies", id_UserPlaneTrafficActivityReport, create_dissector_handle(dissect_UserPlaneTrafficActivityReport_PDU, proto_xnap));
  dissector_add_uint("xnap.ies", id_XnRemovalThreshold, create_dissector_handle(dissect_XnBenefitValue_PDU, proto_xnap));
  dissector_add_uint("xnap.ies", id_DesiredActNotificationLevel, create_dissector_handle(dissect_DesiredActNotificationLevel_PDU, proto_xnap));
  dissector_add_uint("xnap.ies", id_AvailableDRBIDs, create_dissector_handle(dissect_DRB_List_PDU, proto_xnap));
  dissector_add_uint("xnap.ies", id_AdditionalDRBIDs, create_dissector_handle(dissect_DRB_List_PDU, proto_xnap));
  dissector_add_uint("xnap.ies", id_SpareDRBIDs, create_dissector_handle(dissect_DRB_List_PDU, proto_xnap));
  dissector_add_uint("xnap.ies", id_RequiredNumberOfDRBIDs, create_dissector_handle(dissect_DRB_Number_PDU, proto_xnap));
  dissector_add_uint("xnap.ies", id_TNLA_To_Add_List, create_dissector_handle(dissect_TNLA_To_Add_List_PDU, proto_xnap));
  dissector_add_uint("xnap.ies", id_TNLA_To_Update_List, create_dissector_handle(dissect_TNLA_To_Update_List_PDU, proto_xnap));
  dissector_add_uint("xnap.ies", id_TNLA_To_Remove_List, create_dissector_handle(dissect_TNLA_To_Remove_List_PDU, proto_xnap));
  dissector_add_uint("xnap.ies", id_TNLA_Setup_List, create_dissector_handle(dissect_TNLA_Setup_List_PDU, proto_xnap));
  dissector_add_uint("xnap.ies", id_TNLA_Failed_To_Setup_List, create_dissector_handle(dissect_TNLA_Failed_To_Setup_List_PDU, proto_xnap));
  dissector_add_uint("xnap.ies", id_PDUSessionToBeReleased_RelReqAck, create_dissector_handle(dissect_PDUSessionToBeReleasedList_RelReqAck_PDU, proto_xnap));
  dissector_add_uint("xnap.ies", id_S_NG_RANnodeMaxIPDataRate_UL, create_dissector_handle(dissect_BitRate_PDU, proto_xnap));
  dissector_add_uint("xnap.ies", id_PDUSessionResourceSecondaryRATUsageList, create_dissector_handle(dissect_PDUSessionResourceSecondaryRATUsageList_PDU, proto_xnap));
  dissector_add_uint("xnap.ies", id_LocationInformationSNReporting, create_dissector_handle(dissect_LocationInformationSNReporting_PDU, proto_xnap));
  dissector_add_uint("xnap.ies", id_LocationInformationSN, create_dissector_handle(dissect_Target_CGI_PDU, proto_xnap));
  dissector_add_uint("xnap.ies", id_S_NG_RANnodeMaxIPDataRate_DL, create_dissector_handle(dissect_BitRate_PDU, proto_xnap));
  dissector_add_uint("xnap.ies", id_MR_DC_ResourceCoordinationInfo, create_dissector_handle(dissect_MR_DC_ResourceCoordinationInfo_PDU, proto_xnap));
  dissector_add_uint("xnap.ies", id_AMF_Region_Information_To_Add, create_dissector_handle(dissect_AMF_Region_Information_PDU, proto_xnap));
  dissector_add_uint("xnap.ies", id_AMF_Region_Information_To_Delete, create_dissector_handle(dissect_AMF_Region_Information_PDU, proto_xnap));
  dissector_add_uint("xnap.ies", id_RANPagingFailure, create_dissector_handle(dissect_RANPagingFailure_PDU, proto_xnap));
  dissector_add_uint("xnap.ies", id_UERadioCapabilityForPaging, create_dissector_handle(dissect_UERadioCapabilityForPaging_PDU, proto_xnap));
  dissector_add_uint("xnap.ies", id_PDUSessionDataForwarding_SNModResponse, create_dissector_handle(dissect_PDUSessionDataForwarding_SNModResponse_PDU, proto_xnap));
  dissector_add_uint("xnap.ies", id_NE_DC_TDM_Pattern, create_dissector_handle(dissect_NE_DC_TDM_Pattern_PDU, proto_xnap));
  dissector_add_uint("xnap.ies", id_InterfaceInstanceIndication, create_dissector_handle(dissect_InterfaceInstanceIndication_PDU, proto_xnap));
  dissector_add_uint("xnap.ies", id_S_NG_RANnode_Addition_Trigger_Ind, create_dissector_handle(dissect_S_NG_RANnode_Addition_Trigger_Ind_PDU, proto_xnap));
  dissector_add_uint("xnap.ies", id_DRBs_transferred_to_MN, create_dissector_handle(dissect_DRB_List_PDU, proto_xnap));
  dissector_add_uint("xnap.ies", id_EndpointIPAddressAndPort, create_dissector_handle(dissect_EndpointIPAddressAndPort_PDU, proto_xnap));
  dissector_add_uint("xnap.extension", id_Additional_UL_NG_U_TNLatUPF_List, create_dissector_handle(dissect_Additional_UL_NG_U_TNLatUPF_List_PDU, proto_xnap));
  dissector_add_uint("xnap.extension", id_SecondarydataForwardingInfoFromTarget_List, create_dissector_handle(dissect_SecondarydataForwardingInfoFromTarget_List_PDU, proto_xnap));
  dissector_add_uint("xnap.extension", id_LastE_UTRANPLMNIdentity, create_dissector_handle(dissect_PLMN_Identity_PDU, proto_xnap));
  dissector_add_uint("xnap.extension", id_MaxIPrate_DL, create_dissector_handle(dissect_MaxIPrate_PDU, proto_xnap));
  dissector_add_uint("xnap.extension", id_SecurityResult, create_dissector_handle(dissect_SecurityResult_PDU, proto_xnap));
  dissector_add_uint("xnap.extension", id_S_NSSAI, create_dissector_handle(dissect_S_NSSAI_PDU, proto_xnap));
  dissector_add_uint("xnap.extension", id_OldQoSFlowMap_ULendmarkerexpected, create_dissector_handle(dissect_QoSFlows_List_PDU, proto_xnap));
  dissector_add_uint("xnap.extension", id_DRBsNotAdmittedSetupModifyList, create_dissector_handle(dissect_DRB_List_withCause_PDU, proto_xnap));
  dissector_add_uint("xnap.extension", id_Secondary_MN_Xn_U_TNLInfoatM, create_dissector_handle(dissect_UPTransportLayerInformation_PDU, proto_xnap));
  dissector_add_uint("xnap.extension", id_PDUSessionCommonNetworkInstance, create_dissector_handle(dissect_PDUSessionCommonNetworkInstance_PDU, proto_xnap));
  dissector_add_uint("xnap.extension", id_BPLMN_ID_Info_EUTRA, create_dissector_handle(dissect_BPLMN_ID_Info_EUTRA_PDU, proto_xnap));
  dissector_add_uint("xnap.extension", id_BPLMN_ID_Info_NR, create_dissector_handle(dissect_BPLMN_ID_Info_NR_PDU, proto_xnap));
  dissector_add_uint("xnap.extension", id_DefaultDRB_Allowed, create_dissector_handle(dissect_DefaultDRB_Allowed_PDU, proto_xnap));
  dissector_add_uint("xnap.extension", id_DRB_IDs_takenintouse, create_dissector_handle(dissect_DRB_List_PDU, proto_xnap));
  dissector_add_uint("xnap.extension", id_SplitSessionIndicator, create_dissector_handle(dissect_SplitSessionIndicator_PDU, proto_xnap));
  dissector_add_uint("xnap.extension", id_CNTypeRestrictionsForEquivalent, create_dissector_handle(dissect_CNTypeRestrictionsForEquivalent_PDU, proto_xnap));
  dissector_add_uint("xnap.extension", id_CNTypeRestrictionsForServing, create_dissector_handle(dissect_CNTypeRestrictionsForServing_PDU, proto_xnap));
  dissector_add_uint("xnap.extension", id_ULForwardingProposal, create_dissector_handle(dissect_ULForwardingProposal_PDU, proto_xnap));
  dissector_add_uint("xnap.extension", id_FiveGCMobilityRestrictionListContainer, create_dissector_handle(dissect_FiveGCMobilityRestrictionListContainer_PDU, proto_xnap));
  dissector_add_uint("xnap.proc.imsg", id_handoverPreparation, create_dissector_handle(dissect_HandoverRequest_PDU, proto_xnap));
  dissector_add_uint("xnap.proc.sout", id_handoverPreparation, create_dissector_handle(dissect_HandoverRequestAcknowledge_PDU, proto_xnap));
  dissector_add_uint("xnap.proc.uout", id_handoverPreparation, create_dissector_handle(dissect_HandoverPreparationFailure_PDU, proto_xnap));
  dissector_add_uint("xnap.proc.imsg", id_sNStatusTransfer, create_dissector_handle(dissect_SNStatusTransfer_PDU, proto_xnap));
  dissector_add_uint("xnap.proc.imsg", id_handoverCancel, create_dissector_handle(dissect_HandoverCancel_PDU, proto_xnap));
  dissector_add_uint("xnap.proc.imsg", id_retrieveUEContext, create_dissector_handle(dissect_RetrieveUEContextRequest_PDU, proto_xnap));
  dissector_add_uint("xnap.proc.sout", id_retrieveUEContext, create_dissector_handle(dissect_RetrieveUEContextResponse_PDU, proto_xnap));
  dissector_add_uint("xnap.proc.uout", id_retrieveUEContext, create_dissector_handle(dissect_RetrieveUEContextFailure_PDU, proto_xnap));
  dissector_add_uint("xnap.proc.imsg", id_rANPaging, create_dissector_handle(dissect_RANPaging_PDU, proto_xnap));
  dissector_add_uint("xnap.proc.imsg", id_xnUAddressIndication, create_dissector_handle(dissect_XnUAddressIndication_PDU, proto_xnap));
  dissector_add_uint("xnap.proc.imsg", id_uEContextRelease, create_dissector_handle(dissect_UEContextRelease_PDU, proto_xnap));
  dissector_add_uint("xnap.proc.imsg", id_sNGRANnodeAdditionPreparation, create_dissector_handle(dissect_SNodeAdditionRequest_PDU, proto_xnap));
  dissector_add_uint("xnap.proc.sout", id_sNGRANnodeAdditionPreparation, create_dissector_handle(dissect_SNodeAdditionRequestAcknowledge_PDU, proto_xnap));
  dissector_add_uint("xnap.proc.uout", id_sNGRANnodeAdditionPreparation, create_dissector_handle(dissect_SNodeAdditionRequestReject_PDU, proto_xnap));
  dissector_add_uint("xnap.proc.imsg", id_sNGRANnodeReconfigurationCompletion, create_dissector_handle(dissect_SNodeReconfigurationComplete_PDU, proto_xnap));
  dissector_add_uint("xnap.proc.imsg", id_mNGRANnodeinitiatedSNGRANnodeModificationPreparation, create_dissector_handle(dissect_SNodeModificationRequest_PDU, proto_xnap));
  dissector_add_uint("xnap.proc.sout", id_mNGRANnodeinitiatedSNGRANnodeModificationPreparation, create_dissector_handle(dissect_SNodeModificationRequestAcknowledge_PDU, proto_xnap));
  dissector_add_uint("xnap.proc.uout", id_mNGRANnodeinitiatedSNGRANnodeModificationPreparation, create_dissector_handle(dissect_SNodeModificationRequestReject_PDU, proto_xnap));
  dissector_add_uint("xnap.proc.imsg", id_sNGRANnodeinitiatedSNGRANnodeModificationPreparation, create_dissector_handle(dissect_SNodeModificationRequired_PDU, proto_xnap));
  dissector_add_uint("xnap.proc.sout", id_sNGRANnodeinitiatedSNGRANnodeModificationPreparation, create_dissector_handle(dissect_SNodeModificationConfirm_PDU, proto_xnap));
  dissector_add_uint("xnap.proc.uout", id_sNGRANnodeinitiatedSNGRANnodeModificationPreparation, create_dissector_handle(dissect_SNodeModificationRefuse_PDU, proto_xnap));
  dissector_add_uint("xnap.proc.imsg", id_mNGRANnodeinitiatedSNGRANnodeRelease, create_dissector_handle(dissect_SNodeReleaseRequest_PDU, proto_xnap));
  dissector_add_uint("xnap.proc.sout", id_mNGRANnodeinitiatedSNGRANnodeRelease, create_dissector_handle(dissect_SNodeReleaseRequestAcknowledge_PDU, proto_xnap));
  dissector_add_uint("xnap.proc.uout", id_mNGRANnodeinitiatedSNGRANnodeRelease, create_dissector_handle(dissect_SNodeReleaseReject_PDU, proto_xnap));
  dissector_add_uint("xnap.proc.imsg", id_sNGRANnodeinitiatedSNGRANnodeRelease, create_dissector_handle(dissect_SNodeReleaseRequired_PDU, proto_xnap));
  dissector_add_uint("xnap.proc.sout", id_sNGRANnodeinitiatedSNGRANnodeRelease, create_dissector_handle(dissect_SNodeReleaseConfirm_PDU, proto_xnap));
  dissector_add_uint("xnap.proc.imsg", id_sNGRANnodeCounterCheck, create_dissector_handle(dissect_SNodeCounterCheckRequest_PDU, proto_xnap));
  dissector_add_uint("xnap.proc.imsg", id_sNGRANnodeChange, create_dissector_handle(dissect_SNodeChangeRequired_PDU, proto_xnap));
  dissector_add_uint("xnap.proc.sout", id_sNGRANnodeChange, create_dissector_handle(dissect_SNodeChangeConfirm_PDU, proto_xnap));
  dissector_add_uint("xnap.proc.uout", id_sNGRANnodeChange, create_dissector_handle(dissect_SNodeChangeRefuse_PDU, proto_xnap));
  dissector_add_uint("xnap.proc.imsg", id_rRCTransfer, create_dissector_handle(dissect_RRCTransfer_PDU, proto_xnap));
  dissector_add_uint("xnap.proc.imsg", id_xnRemoval, create_dissector_handle(dissect_XnRemovalRequest_PDU, proto_xnap));
  dissector_add_uint("xnap.proc.sout", id_xnRemoval, create_dissector_handle(dissect_XnRemovalResponse_PDU, proto_xnap));
  dissector_add_uint("xnap.proc.uout", id_xnRemoval, create_dissector_handle(dissect_XnRemovalFailure_PDU, proto_xnap));
  dissector_add_uint("xnap.proc.imsg", id_xnSetup, create_dissector_handle(dissect_XnSetupRequest_PDU, proto_xnap));
  dissector_add_uint("xnap.proc.sout", id_xnSetup, create_dissector_handle(dissect_XnSetupResponse_PDU, proto_xnap));
  dissector_add_uint("xnap.proc.uout", id_xnSetup, create_dissector_handle(dissect_XnSetupFailure_PDU, proto_xnap));
  dissector_add_uint("xnap.proc.imsg", id_nGRANnodeConfigurationUpdate, create_dissector_handle(dissect_NGRANNodeConfigurationUpdate_PDU, proto_xnap));
  dissector_add_uint("xnap.proc.sout", id_nGRANnodeConfigurationUpdate, create_dissector_handle(dissect_NGRANNodeConfigurationUpdateAcknowledge_PDU, proto_xnap));
  dissector_add_uint("xnap.proc.uout", id_nGRANnodeConfigurationUpdate, create_dissector_handle(dissect_NGRANNodeConfigurationUpdateFailure_PDU, proto_xnap));
  dissector_add_uint("xnap.proc.imsg", id_e_UTRA_NR_CellResourceCoordination, create_dissector_handle(dissect_E_UTRA_NR_CellResourceCoordinationRequest_PDU, proto_xnap));
  dissector_add_uint("xnap.proc.sout", id_e_UTRA_NR_CellResourceCoordination, create_dissector_handle(dissect_E_UTRA_NR_CellResourceCoordinationResponse_PDU, proto_xnap));
  dissector_add_uint("xnap.proc.imsg", id_cellActivation, create_dissector_handle(dissect_CellActivationRequest_PDU, proto_xnap));
  dissector_add_uint("xnap.proc.sout", id_cellActivation, create_dissector_handle(dissect_CellActivationResponse_PDU, proto_xnap));
  dissector_add_uint("xnap.proc.uout", id_cellActivation, create_dissector_handle(dissect_CellActivationFailure_PDU, proto_xnap));
  dissector_add_uint("xnap.proc.imsg", id_reset, create_dissector_handle(dissect_ResetRequest_PDU, proto_xnap));
  dissector_add_uint("xnap.proc.sout", id_reset, create_dissector_handle(dissect_ResetResponse_PDU, proto_xnap));
  dissector_add_uint("xnap.proc.imsg", id_errorIndication, create_dissector_handle(dissect_ErrorIndication_PDU, proto_xnap));
  dissector_add_uint("xnap.proc.imsg", id_notificationControl, create_dissector_handle(dissect_NotificationControlIndication_PDU, proto_xnap));
  dissector_add_uint("xnap.proc.imsg", id_activityNotification, create_dissector_handle(dissect_ActivityNotification_PDU, proto_xnap));
  dissector_add_uint("xnap.proc.imsg", id_privateMessage, create_dissector_handle(dissect_PrivateMessage_PDU, proto_xnap));
  dissector_add_uint("xnap.proc.imsg", id_secondaryRATDataUsageReport, create_dissector_handle(dissect_SecondaryRATDataUsageReport_PDU, proto_xnap));


/*--- End of included file: packet-xnap-dis-tab.c ---*/
#line 320 "./asn1/xnap/packet-xnap-template.c"
  } else {
    if (sctp_port != 0) {
      dissector_delete_uint("sctp.port", sctp_port, xnap_handle);
    }
  }
  sctp_port = xnap_sctp_port;
  if (sctp_port != 0) {
    dissector_add_uint("sctp.port", sctp_port, xnap_handle);
  }
}
