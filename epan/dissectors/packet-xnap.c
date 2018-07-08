/* Do not modify this file. Changes will be overwritten.                      */
/* Generated automatically by the ASN.1 to Wireshark dissector compiler       */
/* packet-xnap.c                                                              */
/* asn2wrs.py -p xnap -c ./xnap.cnf -s ./packet-xnap-template -D . -O ../.. XnAP-CommonDataTypes.asn XnAP-Constants.asn XnAP-Containers.asn XnAP-IEs.asn XnAP-PDU-Contents.asn XnAP-PDU-Descriptions.asn */

/* Input file: packet-xnap-template.c */

#line 1 "./asn1/xnap/packet-xnap-template.c"
/* packet-xnap.c
 * Routines for dissecting NG-RAN Xn application protocol (XnAP)
 * 3GPP TS 38.423 packet dissection
 * Copyright 2018, Pascal Quantin <pascal.quantin@gmail.com>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * Ref:
 * 3GPP TS 38.423 V15.0.0 (2018-06)
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
#define maxnoofAoIs                    64
#define maxnoofBPLMNs                  6
#define maxnoofCellsinAoI              256
#define maxnoofCellsinNGRANnode        16384
#define maxnoofCellsinRNA              32
#define maxnoofDRBs                    32
#define maxnoofEUTRABands              16
#define maxnoofEPLMNs                  15
#define maxnoofForbiddenTACs           4096
#define maxnoofMBSFNEUTRA              8
#define maxnoofNeighbours              1024
#define maxnoofNRCellBands             32
#define maxnoofPLMNs                   16
#define maxnoofPDUSessions             256
#define maxnoofQoSFlows                64
#define maxnoofRANAreaCodes            32
#define maxnoofRANAreasinRNA           16
#define maxnoofSliceItems              1024
#define maxnoofsupportedPLMNs          16
#define maxnoofsupportedTACs           1024
#define maxnoofTAI                     16
#define maxnoofTAIsinAoI               16
#define maxnoofUEContexts              8292
#define maxNRARFCN                     3279165
#define maxNrOfErrors                  256

typedef enum _ProcedureCode_enum {
  id_handoverPreparation =   0,
  id_sNStatusTransfer =   1,
  id_handoverCancel =   2,
  id_retrieveUEContext =   3,
  id_rANPaging =   4,
  id_dataForwardingAddressIndication =   5,
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
  id_privateMessage =  22
} ProcedureCode_enum;

typedef enum _ProtocolIE_ID_enum {
  id_ActivatedServedCells =   0,
  id_ActivationIDforCellActivation =   1,
  id_AMF_Pool_Information =   2,
  id_AreaOfInterest_Item =   3,
  id_AssistanceDataForRANPaging =   4,
  id_Cause     =   5,
  id_cellAssistanceInfo_NR =   6,
  id_ConfigurationUpdateInitiatingNodeChoice =   7,
  id_CriticalityDiagnostics =   8,
  id_dataforwardingInfoperPDUSession =   9,
  id_dataforwardingInfoperPDUSession_Item =  10,
  id_DataForwardingResponseDRBItem =  11,
  id_DRBsSubjectToStatusTransfer_Item =  12,
  id_DRBsSubjectToStatusTransfer_List =  13,
  id_DRBToQoSFlowMapping_Item =  14,
  id_GlobalNG_RAN_node_ID =  15,
  id_GUAMI     =  16,
  id_List_of_served_cells_E_UTRA =  17,
  id_List_of_served_cells_NR =  18,
  id_LocationReportingInformation =  19,
  id_MAC_I     =  20,
  id_MaskedIMEISV =  21,
  id_new_NG_RAN_Cell_Identity =  22,
  id_newNG_RANnodeUEXnAPID =  23,
  id_oldNG_RANnodeUEXnAPID =  24,
  id_PagingDRX =  25,
  id_PDUSessionResourceAdmittedResponseTransferItem =  26,
  id_PDUSessionResourcesAdmitted_Item =  27,
  id_PDUSessionResourcesAdmitted_List =  28,
  id_PDUSessionResourcesNotAdmitted_Item =  29,
  id_PDUSessionResourcesNotAdmitted_List =  30,
  id_PDUSessionResourcesToBeSetup_Item =  31,
  id_QoSFlowAdmitted_Item =  32,
  id_QoSFlow_Item =  33,
  id_QoSFlowNotAdmitted_Item =  34,
  id_QoSFlowsToBeSetup_Item =  35,
  id_RANPagingArea =  36,
  id_RANPagingPriority =  37,
  id_ResetRequestPartialReleaseItem =  38,
  id_ResetRequestTypeInfo =  39,
  id_ResetResponsePartialReleaseItem =  40,
  id_ResetResponseTypeInfo =  41,
  id_RespondingNodeTypeConfigUpdateAck =  42,
  id_ServedCellsToActivate =  43,
  id_servedCellsToUpdate_E_UTRA =  44,
  id_ServedCellsToUpdateInitiatingNodeChoice =  45,
  id_servedCellsToUpdate_NR =  46,
  id_sourceNG_RANnodeUEXnAPID =  47,
  id_TAISupport_Item =  48,
  id_TAISupport_list =  49,
  id_Target2SourceNG_RANnodeTranspContainer =  50,
  id_targetCellGlobalID =  51,
  id_targetNG_RANnodeUEXnAPID =  52,
  id_TraceActivation =  53,
  id_UEContextID =  54,
  id_UEContextInfoHORequest =  55,
  id_UEContextInfoRetrUECtxtResp =  56,
  id_UEIdentityIndexValue =  57,
  id_UERANPagingIdentity =  58,
  id_XnRemovalThreshold =  59
} ProtocolIE_ID_enum;

typedef enum _TriggeringMessage_enum {
  initiating_message =   0,
  successful_outcome =   1,
  unsuccessful_outcome =   2
} TriggeringMessage_enum;

typedef enum _GlobalNG_RANNode_ID_enum {
  GlobalNG_RANNode_ID_gNB =   0,
  GlobalNG_RANNode_ID_ng_eNB =   1,
  GlobalNG_RANNode_ID_choice_extension =   2
} GlobalNG_RANNode_ID_enum;

/*--- End of included file: packet-xnap-val.h ---*/
#line 43 "./asn1/xnap/packet-xnap-template.c"

/* Initialize the protocol and registered fields */
static int proto_xnap = -1;
static int hf_xnap_transportLayerAddressIPv4 = -1;
static int hf_xnap_transportLayerAddressIPv6 = -1;
static int hf_xnap_ng_ran_TraceID_TraceID = -1;
static int hf_xnap_ng_ran_TraceID_TraceRecordingSessionReference = -1;

/*--- Included file: packet-xnap-hf.c ---*/
#line 1 "./asn1/xnap/packet-xnap-hf.c"
static int hf_xnap_ActivationIDforCellActivation_PDU = -1;  /* ActivationIDforCellActivation */
static int hf_xnap_AMF_Pool_Information_PDU = -1;  /* AMF_Pool_Information */
static int hf_xnap_AreaOfInterest_Item_PDU = -1;  /* AreaOfInterest_Item */
static int hf_xnap_AssistanceDataForRANPaging_PDU = -1;  /* AssistanceDataForRANPaging */
static int hf_xnap_Cause_PDU = -1;                /* Cause */
static int hf_xnap_CellAssistanceInfo_NR_PDU = -1;  /* CellAssistanceInfo_NR */
static int hf_xnap_CriticalityDiagnostics_PDU = -1;  /* CriticalityDiagnostics */
static int hf_xnap_DataforwardingInfoperPDUSession_PDU = -1;  /* DataforwardingInfoperPDUSession */
static int hf_xnap_DataforwardingInfoperPDUSession_Item_PDU = -1;  /* DataforwardingInfoperPDUSession_Item */
static int hf_xnap_DataForwardingResponseDRBItem_PDU = -1;  /* DataForwardingResponseDRBItem */
static int hf_xnap_DRBsSubjectToStatusTransfer_List_PDU = -1;  /* DRBsSubjectToStatusTransfer_List */
static int hf_xnap_DRBsSubjectToStatusTransfer_Item_PDU = -1;  /* DRBsSubjectToStatusTransfer_Item */
static int hf_xnap_DRBToQoSFlowMapping_Item_PDU = -1;  /* DRBToQoSFlowMapping_Item */
static int hf_xnap_GlobalNG_RANNode_ID_PDU = -1;  /* GlobalNG_RANNode_ID */
static int hf_xnap_GUAMI_PDU = -1;                /* GUAMI */
static int hf_xnap_LocationReportingInformation_PDU = -1;  /* LocationReportingInformation */
static int hf_xnap_MAC_I_PDU = -1;                /* MAC_I */
static int hf_xnap_MaskedIMEISV_PDU = -1;         /* MaskedIMEISV */
static int hf_xnap_NG_RAN_Cell_Identity_PDU = -1;  /* NG_RAN_Cell_Identity */
static int hf_xnap_NG_RANnodeUEXnAPID_PDU = -1;   /* NG_RANnodeUEXnAPID */
static int hf_xnap_PagingDRX_PDU = -1;            /* PagingDRX */
static int hf_xnap_PDUSessionResourcesAdmitted_List_PDU = -1;  /* PDUSessionResourcesAdmitted_List */
static int hf_xnap_PDUSessionResourcesAdmitted_Item_PDU = -1;  /* PDUSessionResourcesAdmitted_Item */
static int hf_xnap_PDUSessionResourcesNotAdmitted_List_PDU = -1;  /* PDUSessionResourcesNotAdmitted_List */
static int hf_xnap_PDUSessionResourcesNotAdmitted_Item_PDU = -1;  /* PDUSessionResourcesNotAdmitted_Item */
static int hf_xnap_PDUSessionResourcesToBeSetup_Item_PDU = -1;  /* PDUSessionResourcesToBeSetup_Item */
static int hf_xnap_QoSFlow_Item_PDU = -1;         /* QoSFlow_Item */
static int hf_xnap_QoSFlowAdmitted_Item_PDU = -1;  /* QoSFlowAdmitted_Item */
static int hf_xnap_QoSFlowNotAdmitted_Item_PDU = -1;  /* QoSFlowNotAdmitted_Item */
static int hf_xnap_QoSFlowsToBeSetup_Item_PDU = -1;  /* QoSFlowsToBeSetup_Item */
static int hf_xnap_RANPagingArea_PDU = -1;        /* RANPagingArea */
static int hf_xnap_RANPagingPriority_PDU = -1;    /* RANPagingPriority */
static int hf_xnap_ResetRequestTypeInfo_PDU = -1;  /* ResetRequestTypeInfo */
static int hf_xnap_ResetRequestPartialReleaseItem_PDU = -1;  /* ResetRequestPartialReleaseItem */
static int hf_xnap_ResetResponseTypeInfo_PDU = -1;  /* ResetResponseTypeInfo */
static int hf_xnap_ResetResponsePartialReleaseItem_PDU = -1;  /* ResetResponsePartialReleaseItem */
static int hf_xnap_ServedCells_E_UTRA_PDU = -1;   /* ServedCells_E_UTRA */
static int hf_xnap_ServedCellsToUpdate_E_UTRA_PDU = -1;  /* ServedCellsToUpdate_E_UTRA */
static int hf_xnap_ServedCells_NR_PDU = -1;       /* ServedCells_NR */
static int hf_xnap_ServedCellsToUpdate_NR_PDU = -1;  /* ServedCellsToUpdate_NR */
static int hf_xnap_TAISupport_List_PDU = -1;      /* TAISupport_List */
static int hf_xnap_TAISupport_Item_PDU = -1;      /* TAISupport_Item */
static int hf_xnap_Target_CGI_PDU = -1;           /* Target_CGI */
static int hf_xnap_TraceActivation_PDU = -1;      /* TraceActivation */
static int hf_xnap_UEContextID_PDU = -1;          /* UEContextID */
static int hf_xnap_UEContextInfoRetrUECtxtResp_PDU = -1;  /* UEContextInfoRetrUECtxtResp */
static int hf_xnap_UEIdentityIndexValue_PDU = -1;  /* UEIdentityIndexValue */
static int hf_xnap_UERANPagingIdentity_PDU = -1;  /* UERANPagingIdentity */
static int hf_xnap_XnBenefitValue_PDU = -1;       /* XnBenefitValue */
static int hf_xnap_HandoverRequest_PDU = -1;      /* HandoverRequest */
static int hf_xnap_UEContextInfoHORequest_PDU = -1;  /* UEContextInfoHORequest */
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
static int hf_xnap_DataForwardingAddressIndication_PDU = -1;  /* DataForwardingAddressIndication */
static int hf_xnap_SNodeAdditionRequest_PDU = -1;  /* SNodeAdditionRequest */
static int hf_xnap_SNodeAdditionRequestAcknowledge_PDU = -1;  /* SNodeAdditionRequestAcknowledge */
static int hf_xnap_SNodeAdditionRequestReject_PDU = -1;  /* SNodeAdditionRequestReject */
static int hf_xnap_SNodeReconfigurationComplete_PDU = -1;  /* SNodeReconfigurationComplete */
static int hf_xnap_SNodeModificationRequest_PDU = -1;  /* SNodeModificationRequest */
static int hf_xnap_SNodeModificationRequestAcknowledge_PDU = -1;  /* SNodeModificationRequestAcknowledge */
static int hf_xnap_SNodeModificationRequestReject_PDU = -1;  /* SNodeModificationRequestReject */
static int hf_xnap_SNodeModificationRequired_PDU = -1;  /* SNodeModificationRequired */
static int hf_xnap_SNodeModificationConfirm_PDU = -1;  /* SNodeModificationConfirm */
static int hf_xnap_SNodeModificationRefuse_PDU = -1;  /* SNodeModificationRefuse */
static int hf_xnap_SNodeReleaseRequest_PDU = -1;  /* SNodeReleaseRequest */
static int hf_xnap_SNodeReleaseRequestAcknowledge_PDU = -1;  /* SNodeReleaseRequestAcknowledge */
static int hf_xnap_SNodeReleaseReject_PDU = -1;   /* SNodeReleaseReject */
static int hf_xnap_SNodeReleaseRequired_PDU = -1;  /* SNodeReleaseRequired */
static int hf_xnap_SNodeReleaseConfirm_PDU = -1;  /* SNodeReleaseConfirm */
static int hf_xnap_SNodeCounterCheckRequest_PDU = -1;  /* SNodeCounterCheckRequest */
static int hf_xnap_SNodeChangeRequired_PDU = -1;  /* SNodeChangeRequired */
static int hf_xnap_SNodeChangeConfirm_PDU = -1;   /* SNodeChangeConfirm */
static int hf_xnap_SNodeChangeRefuse_PDU = -1;    /* SNodeChangeRefuse */
static int hf_xnap_RRCTransfer_PDU = -1;          /* RRCTransfer */
static int hf_xnap_XnSetupRequest_PDU = -1;       /* XnSetupRequest */
static int hf_xnap_XnSetupResponse_PDU = -1;      /* XnSetupResponse */
static int hf_xnap_XnSetupFailure_PDU = -1;       /* XnSetupFailure */
static int hf_xnap_NGRANNodeConfigurationUpdate_PDU = -1;  /* NGRANNodeConfigurationUpdate */
static int hf_xnap_ConfigurationUpdateInitiatingNodeChoice_PDU = -1;  /* ConfigurationUpdateInitiatingNodeChoice */
static int hf_xnap_NGRANNodeConfigurationUpdateAcknowledge_PDU = -1;  /* NGRANNodeConfigurationUpdateAcknowledge */
static int hf_xnap_RespondingNodeTypeConfigUpdateAck_PDU = -1;  /* RespondingNodeTypeConfigUpdateAck */
static int hf_xnap_NGRANNodeConfigurationUpdateFailure_PDU = -1;  /* NGRANNodeConfigurationUpdateFailure */
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
static int hf_xnap_priorityLevel = -1;            /* INTEGER_0_15_ */
static int hf_xnap_pre_emption_capability = -1;   /* T_pre_emption_capability */
static int hf_xnap_pre_emption_vulnerability = -1;  /* T_pre_emption_vulnerability */
static int hf_xnap_iE_Extensions = -1;            /* ProtocolExtensionContainer */
static int hf_xnap_AreaOfInterest_item = -1;      /* ProtocolIE_Single_Container */
static int hf_xnap_listOfTAIs = -1;               /* ListOfTAIsinAoI */
static int hf_xnap_listOfCells = -1;              /* ListOfCells */
static int hf_xnap_key_NG_RAN_Star = -1;          /* BIT_STRING_SIZE_256 */
static int hf_xnap_ncc = -1;                      /* INTEGER_0_7 */
static int hf_xnap_ran_paging_attempt_info = -1;  /* RANPagingAttemptInfo */
static int hf_xnap_BroadcastPLMNs_item = -1;      /* PLMN_Identity */
static int hf_xnap_plmn_id = -1;                  /* PLMN_Identity */
static int hf_xnap_tAISliceSupport_List = -1;     /* SliceSupport_List */
static int hf_xnap_iE_Extension = -1;             /* ProtocolExtensionContainer */
static int hf_xnap_radioNetwork = -1;             /* CauseRadioNetworkLayer */
static int hf_xnap_transport = -1;                /* CauseTransportLayer */
static int hf_xnap_protocol = -1;                 /* CauseProtocol */
static int hf_xnap_misc = -1;                     /* CauseMisc */
static int hf_xnap_choice_extension = -1;         /* ProtocolExtensionContainer */
static int hf_xnap_limitedNR_List = -1;           /* SEQUENCE_SIZE_1_maxnoofCellsinNGRANnode_OF_NR_CGI */
static int hf_xnap_limitedNR_List_item = -1;      /* NR_CGI */
static int hf_xnap_full_List = -1;                /* T_full_List */
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
static int hf_xnap_DataforwardingInfoperPDUSession_item = -1;  /* ProtocolIE_Single_Container */
static int hf_xnap_pduSession_ID = -1;            /* PDUSession_ID */
static int hf_xnap_dlForwardingUPTNL = -1;        /* UPTransportLayerInformation */
static int hf_xnap_pduSessionLevelDLDataForwardingInfo = -1;  /* UPTransportLayerInformation */
static int hf_xnap_dataForwardingResponseDRBItemList = -1;  /* DataForwardingResponseDRBItemList */
static int hf_xnap_DataForwardingResponseDRBItemList_item = -1;  /* ProtocolIE_Single_Container */
static int hf_xnap_drb_ID = -1;                   /* DRB_ID */
static int hf_xnap_ulForwardingUPTNL = -1;        /* UPTransportLayerInformation */
static int hf_xnap_DRBsSubjectToStatusTransfer_List_item = -1;  /* ProtocolIE_Single_Container */
static int hf_xnap_drbID = -1;                    /* DRB_ID */
static int hf_xnap_statusTransfer = -1;           /* DRBBStatusTransferChoice */
static int hf_xnap_pdcp_sn_12bits = -1;           /* DRBBStatusTransfer12bitsSN */
static int hf_xnap_pdcp_sn_18bits = -1;           /* DRBBStatusTransfer18bitsSN */
static int hf_xnap_receiveStatusofPDCPSDU = -1;   /* BIT_STRING_SIZE_1_2048 */
static int hf_xnap_ulCOUNTValue = -1;             /* COUNT_PDCP_SN12 */
static int hf_xnap_dlCOUNTValue = -1;             /* COUNT_PDCP_SN12 */
static int hf_xnap_receiveStatusofPDCPSDU_01 = -1;  /* BIT_STRING_SIZE_1_131072 */
static int hf_xnap_ulCOUNTValue_01 = -1;          /* COUNT_PDCP_SN18 */
static int hf_xnap_dlCOUNTValue_01 = -1;          /* COUNT_PDCP_SN18 */
static int hf_xnap_DRBToQoSFlowMapping_List_item = -1;  /* ProtocolIE_Single_Container */
static int hf_xnap_qosFlows_List = -1;            /* QoSFlows_List */
static int hf_xnap_priorityLevel_01 = -1;         /* INTEGER_1_128 */
static int hf_xnap_packetDelayBudget = -1;        /* PacketDelayBudget */
static int hf_xnap_packetErrorRate = -1;          /* PacketErrorRate */
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
static int hf_xnap_gNB = -1;                      /* GlobalgNB_ID */
static int hf_xnap_ng_eNB = -1;                   /* GlobalngeNB_ID */
static int hf_xnap_tnl_address = -1;              /* TransportLayerAddress */
static int hf_xnap_gtp_teid = -1;                 /* GTP_TEID */
static int hf_xnap_plmn_ID = -1;                  /* PLMN_Identity */
static int hf_xnap_amf_region_if = -1;            /* OCTET_STRING_SIZE_2 */
static int hf_xnap_amf_set_id = -1;               /* BIT_STRING_SIZE_4 */
static int hf_xnap_amf_pointer = -1;              /* BIT_STRING_SIZE_4 */
static int hf_xnap_ListOfCells_item = -1;         /* CellsinAoI_Item */
static int hf_xnap_pLMN_Identity = -1;            /* PLMN_Identity */
static int hf_xnap_ng_ran_cell_id = -1;           /* NG_RAN_Cell_Identity */
static int hf_xnap_ListOfTAIsinAoI_item = -1;     /* TAIsinAoI_Item */
static int hf_xnap_tAC = -1;                      /* TAC */
static int hf_xnap_eventType = -1;                /* EventType */
static int hf_xnap_reportArea = -1;               /* ReportArea */
static int hf_xnap_areaOfInterest = -1;           /* AreaOfInterest */
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
static int hf_xnap_RAT_RestrictionsList_item = -1;  /* RAT_RestrictionsItem */
static int hf_xnap_plmn_Identity = -1;            /* PLMN_Identity */
static int hf_xnap_rat_RestrictionInformation = -1;  /* RAT_RestrictionInformation */
static int hf_xnap_ForbiddenAreaList_item = -1;   /* ForbiddenAreaItem */
static int hf_xnap_forbidden_TACs = -1;           /* SEQUENCE_SIZE_1_maxnoofForbiddenTACs_OF_TAC */
static int hf_xnap_forbidden_TACs_item = -1;      /* TAC */
static int hf_xnap_ServiceAreaList_item = -1;     /* ServiceAreaItem */
static int hf_xnap_allowed_TACs_ServiceArea = -1;  /* SEQUENCE_SIZE_1_maxnoofAllowedAreas_OF_TAC */
static int hf_xnap_allowed_TACs_ServiceArea_item = -1;  /* TAC */
static int hf_xnap_not_allowed_TACs_ServiceArea = -1;  /* SEQUENCE_SIZE_1_maxnoofAllowedAreas_OF_TAC */
static int hf_xnap_not_allowed_TACs_ServiceArea_item = -1;  /* TAC */
static int hf_xnap_NeighbourInformation_E_UTRA_item = -1;  /* NeighbourInformation_E_UTRA_Item */
static int hf_xnap_e_utra_PCI = -1;               /* E_UTRAPCI */
static int hf_xnap_e_utra_cgi = -1;               /* E_UTRA_CGI */
static int hf_xnap_earfcn = -1;                   /* E_UTRAARFCN */
static int hf_xnap_tac = -1;                      /* TAC */
static int hf_xnap_NeighbourInformation_NR_item = -1;  /* NeighbourInformation_NR_Item */
static int hf_xnap_nr_mode_info = -1;             /* NeighbourInformation_NR_ModeInfo */
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
static int hf_xnap_fiveQI = -1;                   /* INTEGER_0_255 */
static int hf_xnap_NG_RAN_Cell_Identity_ListinRANPagingArea_item = -1;  /* NG_RAN_Cell_Identity */
static int hf_xnap_nr_CI = -1;                    /* NR_Cell_Identity */
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
static int hf_xnap_PDUSessionResourcesAdmitted_List_item = -1;  /* ProtocolIE_Single_Container */
static int hf_xnap_pduSessionId = -1;             /* PDUSession_ID */
static int hf_xnap_pduSessionResourceAdmittedInfo = -1;  /* PDUSessionResourceAdmittedInfo */
static int hf_xnap_qosFlowsAdmitted_List = -1;    /* QoSFlowsAdmitted_List */
static int hf_xnap_qosFlowsNotAdmitted_List = -1;  /* QoSFlowsNotAdmitted_List */
static int hf_xnap_dataForwardingInfoFromTarget = -1;  /* DataForwardingInfoFromTargetNGRANnode */
static int hf_xnap_PDUSessionResourcesNotAdmitted_List_item = -1;  /* ProtocolIE_Single_Container */
static int hf_xnap_cause = -1;                    /* Cause */
static int hf_xnap_PDUSessionResourcesToBeSetup_List_item = -1;  /* ProtocolIE_Single_Container */
static int hf_xnap_s_NSSAI = -1;                  /* S_NSSAI */
static int hf_xnap_pduSessionAMBR = -1;           /* OCTET_STRING */
static int hf_xnap_uL_NG_U_TNLatUPF = -1;         /* UPTransportLayerInformation */
static int hf_xnap_securityIndication = -1;       /* SecurityIndication */
static int hf_xnap_pduSessionType = -1;           /* PDUSessionType */
static int hf_xnap_qosFlowsToBeSetup_List = -1;   /* QoSFlowsToBeSetup_List */
static int hf_xnap_sourceDRBtoQoSFlowMapping = -1;  /* DRBToQoSFlowMapping_List */
static int hf_xnap_non_dynamic = -1;              /* NonDynamic5QIDescriptor */
static int hf_xnap_dynamic = -1;                  /* Dynamic5QIDescriptor */
static int hf_xnap_qos_characteristics = -1;      /* QoSCharacteristics */
static int hf_xnap_allocationAndRetentionPrio = -1;  /* AllocationandRetentionPriority */
static int hf_xnap_gBRQoSFlowInfo = -1;           /* GBRQoSFlowInfo */
static int hf_xnap_relectiveQoS = -1;             /* ReflectiveQoSAttribute */
static int hf_xnap_additionalQoSflowInfo = -1;    /* T_additionalQoSflowInfo */
static int hf_xnap_pPI = -1;                      /* INTEGER_1_8_ */
static int hf_xnap_QoSFlows_List_item = -1;       /* ProtocolIE_Single_Container */
static int hf_xnap_qfi = -1;                      /* QoSFlowIndicator */
static int hf_xnap_QoSFlowsAdmitted_List_item = -1;  /* ProtocolIE_Single_Container */
static int hf_xnap_dataForwardingAccepted = -1;   /* DataForwardingAccepted */
static int hf_xnap_QoSFlowsNotAdmitted_List_item = -1;  /* ProtocolIE_Single_Container */
static int hf_xnap_QoSFlowsToBeSetup_List_item = -1;  /* ProtocolIE_Single_Container */
static int hf_xnap_dlDataForwarding = -1;         /* DLForwarding */
static int hf_xnap_qosFlowLevelQoSParameters = -1;  /* QoSFlowLevelQoSParameters */
static int hf_xnap_e_RAB_ID = -1;                 /* E_RAB_ID */
static int hf_xnap_rANAC = -1;                    /* RANAC */
static int hf_xnap_RANAreaID_List_item = -1;      /* RANAreaID */
static int hf_xnap_rANPagingAreaChoice = -1;      /* RANPagingAreaChoice */
static int hf_xnap_cell_List = -1;                /* NG_RAN_Cell_Identity_ListinRANPagingArea */
static int hf_xnap_rANAreaID_List = -1;           /* RANAreaID_List */
static int hf_xnap_pagingAttemptCount = -1;       /* INTEGER_1_16_ */
static int hf_xnap_intendedNumberOfPagingAttempts = -1;  /* INTEGER_1_16_ */
static int hf_xnap_nextPagingAreaScope = -1;      /* T_nextPagingAreaScope */
static int hf_xnap_fullReset = -1;                /* ResetRequestTypeInfo_Full */
static int hf_xnap_partialReset = -1;             /* ResetRequestTypeInfo_Partial */
static int hf_xnap_ue_contexts_ToBeReleasedList = -1;  /* ResetRequestPartialReleaseList */
static int hf_xnap_ResetRequestPartialReleaseList_item = -1;  /* ProtocolIE_Single_Container */
static int hf_xnap_ng_ran_node1UEXnAPID = -1;     /* NG_RANnodeUEXnAPID */
static int hf_xnap_ng_ran_node2UEXnAPID = -1;     /* NG_RANnodeUEXnAPID */
static int hf_xnap_fullReset_01 = -1;             /* ResetResponseTypeInfo_Full */
static int hf_xnap_partialReset_01 = -1;          /* ResetResponseTypeInfo_Partial */
static int hf_xnap_ue_contexts_AdmittedToBeReleasedList = -1;  /* ResetResponsePartialReleaseList */
static int hf_xnap_ResetResponsePartialReleaseList_item = -1;  /* ProtocolIE_Single_Container */
static int hf_xnap_integrityProtectionIndication = -1;  /* T_integrityProtectionIndication */
static int hf_xnap_confidentialityProtectionIndication = -1;  /* T_confidentialityProtectionIndication */
static int hf_xnap_e_utra_pci = -1;               /* E_UTRAPCI */
static int hf_xnap_broadcastPLMNs = -1;           /* SEQUENCE_SIZE_1_maxnoofBPLMNs_OF_ServedCellInformation_E_UTRA_perBPLMN */
static int hf_xnap_broadcastPLMNs_item = -1;      /* ServedCellInformation_E_UTRA_perBPLMN */
static int hf_xnap_numberofAntennaPorts = -1;     /* NumberOfAntennaPorts_E_UTRA */
static int hf_xnap_prach_configuration = -1;      /* E_UTRAPRACHConfiguration */
static int hf_xnap_mBSFNsubframeInfo = -1;        /* MBSFNSubframeInfo_E_UTRA */
static int hf_xnap_multibandInfo = -1;            /* E_UTRAMultibandInfoList */
static int hf_xnap_freqBandIndicatorPriority = -1;  /* T_freqBandIndicatorPriority */
static int hf_xnap_bandwidthReducedSI = -1;       /* T_bandwidthReducedSI */
static int hf_xnap_e_utra_mode_info = -1;         /* ServedCellInformation_E_UTRA_perBPLMN_ModeInfo */
static int hf_xnap_fdd_01 = -1;                   /* ServedCellInformation_E_UTRA_perBPLMN_FDDInfo */
static int hf_xnap_tdd_01 = -1;                   /* ServedCellInformation_E_UTRA_perBPLMN_TDDInfo */
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
static int hf_xnap_served_Cells_ToDelete_E_UTRA = -1;  /* SEQUENCE_SIZE_1_maxnoofCellsinNGRANnode_OF_E_UTRA_CGI */
static int hf_xnap_served_Cells_ToDelete_E_UTRA_item = -1;  /* E_UTRA_CGI */
static int hf_xnap_ServedCells_ToModify_E_UTRA_item = -1;  /* ServedCells_ToModify_E_UTRA_Item */
static int hf_xnap_old_ECGI = -1;                 /* E_UTRA_CGI */
static int hf_xnap_nrPCI = -1;                    /* NRPCI */
static int hf_xnap_cellID = -1;                   /* NR_CGI */
static int hf_xnap_ranac = -1;                    /* RANAC */
static int hf_xnap_broadcastPLMN = -1;            /* BroadcastPLMNs */
static int hf_xnap_nrModeInfo = -1;               /* NRModeInfo */
static int hf_xnap_measurementTimingConfiguration = -1;  /* T_measurementTimingConfiguration */
static int hf_xnap_ServedCells_NR_item = -1;      /* ServedCells_NR_Item */
static int hf_xnap_served_cell_info_NR = -1;      /* ServedCellInformation_NR */
static int hf_xnap_ServedCells_ToModify_NR_item = -1;  /* ServedCells_ToModify_NR_Item */
static int hf_xnap_old_NR_CGI = -1;               /* NR_CGI */
static int hf_xnap_served_Cells_ToAdd_NR = -1;    /* ServedCells_NR */
static int hf_xnap_served_Cells_ToModify_NR = -1;  /* ServedCells_ToModify_NR */
static int hf_xnap_served_Cells_ToDelete_NR = -1;  /* SEQUENCE_SIZE_1_maxnoofCellsinNGRANnode_OF_NR_CGI */
static int hf_xnap_served_Cells_ToDelete_NR_item = -1;  /* NR_CGI */
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
static int hf_xnap_TAISupport_List_item = -1;     /* ProtocolIE_Single_Container */
static int hf_xnap_broadcastPLMNs_01 = -1;        /* SEQUENCE_SIZE_1_maxnoofsupportedPLMNs_OF_BroadcastPLMNinTAISupport_Item */
static int hf_xnap_broadcastPLMNs_item_01 = -1;   /* BroadcastPLMNinTAISupport_Item */
static int hf_xnap_nr_02 = -1;                    /* NR_CGI */
static int hf_xnap_e_utra_02 = -1;                /* E_UTRA_CGI */
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
static int hf_xnap_c_rnti = -1;                   /* C_RNTI */
static int hf_xnap_failureCellPCI = -1;           /* NG_RAN_CellPCI */
static int hf_xnap_ng_c_UE_signalling_ref = -1;   /* AMF_UE_NGAP_ID */
static int hf_xnap_signalling_TNL_at_source = -1;  /* CPTransportLayerInformation */
static int hf_xnap_ueSecurityCapabilities = -1;   /* UESecurityCapabilities */
static int hf_xnap_securityInformation = -1;      /* AS_SecurityInformation */
static int hf_xnap_ue_AMBR = -1;                  /* UEAggregateMaximumBitRate */
static int hf_xnap_pduSessionResourcesToBeSet_List = -1;  /* PDUSessionResourcesToBeSetup_List */
static int hf_xnap_rrc_Context = -1;              /* T_rrc_Context */
static int hf_xnap_mobilityRestrictionList = -1;  /* MobilityRestrictionList */
static int hf_xnap_indexToRatFrequencySelectionPriority = -1;  /* RFSP_Index */
static int hf_xnap_i_RNTI = -1;                   /* I_RNTI */
static int hf_xnap_nr_EncyptionAlgorithms = -1;   /* T_nr_EncyptionAlgorithms */
static int hf_xnap_nr_IntegrityProtectionAlgorithms = -1;  /* T_nr_IntegrityProtectionAlgorithms */
static int hf_xnap_e_utra_EncyptionAlgorithms = -1;  /* T_e_utra_EncyptionAlgorithms */
static int hf_xnap_e_utra_IntegrityProtectionAlgorithms = -1;  /* T_e_utra_IntegrityProtectionAlgorithms */
static int hf_xnap_gtpTunnel = -1;                /* GTPtunnelTransportLayerInformation */
static int hf_xnap_protocolIEs = -1;              /* ProtocolIE_Container */
static int hf_xnap_ng_c_UE_reference = -1;        /* AMF_UE_NGAP_ID */
static int hf_xnap_cp_TNL_info_source = -1;       /* CPTransportLayerInformation */
static int hf_xnap_pduSessionResourcesToBeSetup_List = -1;  /* PDUSessionResourcesToBeSetup_List */
static int hf_xnap_rrc_Context_01 = -1;           /* T_rrc_Context_01 */
static int hf_xnap_locationReportingInformation = -1;  /* LocationReportingInformation */
static int hf_xnap_hlr = -1;                      /* MobilityRestrictionList */
static int hf_xnap_gNB_01 = -1;                   /* ProtocolIE_Container */
static int hf_xnap_ng_eNB_01 = -1;                /* ProtocolIE_Container */
static int hf_xnap_ng_eNB_02 = -1;                /* RespondingNodeTypeConfigUpdateAck_ng_eNB */
static int hf_xnap_gNB_02 = -1;                   /* RespondingNodeTypeConfigUpdateAck_gNB */
static int hf_xnap_served_NR_Cells = -1;          /* ServedCells_NR */
static int hf_xnap_nr_cells = -1;                 /* SEQUENCE_SIZE_1_maxnoofCellsinNGRANnode_OF_NR_CGI */
static int hf_xnap_nr_cells_item = -1;            /* NR_CGI */
static int hf_xnap_e_utra_cells = -1;             /* SEQUENCE_SIZE_1_maxnoofCellsinNGRANnode_OF_E_UTRA_CGI */
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
static int hf_xnap_T_nr_EncyptionAlgorithms_nea1_128 = -1;
static int hf_xnap_T_nr_EncyptionAlgorithms_nea2_128 = -1;
static int hf_xnap_T_nr_EncyptionAlgorithms_nea3_128 = -1;
static int hf_xnap_T_nr_IntegrityProtectionAlgorithms_nia1_128 = -1;
static int hf_xnap_T_nr_IntegrityProtectionAlgorithms_nia2_128 = -1;
static int hf_xnap_T_nr_IntegrityProtectionAlgorithms_nia3_128 = -1;
static int hf_xnap_T_e_utra_EncyptionAlgorithms_eea1_128 = -1;
static int hf_xnap_T_e_utra_EncyptionAlgorithms_eea2_128 = -1;
static int hf_xnap_T_e_utra_EncyptionAlgorithms_eea3_128 = -1;
static int hf_xnap_T_e_utra_IntegrityProtectionAlgorithms_eia1_128 = -1;
static int hf_xnap_T_e_utra_IntegrityProtectionAlgorithms_eia2_128 = -1;
static int hf_xnap_T_e_utra_IntegrityProtectionAlgorithms_eia3_128 = -1;

/*--- End of included file: packet-xnap-hf.c ---*/
#line 51 "./asn1/xnap/packet-xnap-template.c"

/* Initialize the subtree pointers */
static gint ett_xnap = -1;
static gint ett_xnap_RRC_Context = -1;
static gint ett_nxap_container = -1;
static gint ett_xnap_PLMN_Identity = -1;
static gint ett_xnap_measurementTimingConfiguration = -1;
static gint ett_xnap_TransportLayerAddress = -1;
static gint ett_xnap_nr_EncyptionAlgorithms = -1;
static gint ett_xnap_nr_IntegrityProtectionAlgorithms = -1;
static gint ett_xnap_e_utra_EncyptionAlgorithms = -1;
static gint ett_xnap_e_utra_IntegrityProtectionAlgorithms = -1;
static gint ett_xnap_ng_ran_TraceID = -1;
static gint ett_xnap_interfaces_to_trace = -1;

/*--- Included file: packet-xnap-ett.c ---*/
#line 1 "./asn1/xnap/packet-xnap-ett.c"
static gint ett_xnap_PrivateIE_ID = -1;
static gint ett_xnap_ProtocolIE_Container = -1;
static gint ett_xnap_ProtocolIE_Field = -1;
static gint ett_xnap_ProtocolExtensionContainer = -1;
static gint ett_xnap_ProtocolExtensionField = -1;
static gint ett_xnap_PrivateIE_Container = -1;
static gint ett_xnap_PrivateIE_Field = -1;
static gint ett_xnap_AllocationandRetentionPriority = -1;
static gint ett_xnap_AreaOfInterest = -1;
static gint ett_xnap_AreaOfInterest_Item = -1;
static gint ett_xnap_AS_SecurityInformation = -1;
static gint ett_xnap_AssistanceDataForRANPaging = -1;
static gint ett_xnap_BroadcastPLMNs = -1;
static gint ett_xnap_BroadcastPLMNinTAISupport_Item = -1;
static gint ett_xnap_Cause = -1;
static gint ett_xnap_CellAssistanceInfo_NR = -1;
static gint ett_xnap_SEQUENCE_SIZE_1_maxnoofCellsinNGRANnode_OF_NR_CGI = -1;
static gint ett_xnap_COUNT_PDCP_SN12 = -1;
static gint ett_xnap_COUNT_PDCP_SN18 = -1;
static gint ett_xnap_CPTransportLayerInformation = -1;
static gint ett_xnap_CriticalityDiagnostics = -1;
static gint ett_xnap_CriticalityDiagnostics_IE_List = -1;
static gint ett_xnap_CriticalityDiagnostics_IE_List_item = -1;
static gint ett_xnap_DataforwardingInfoperPDUSession = -1;
static gint ett_xnap_DataforwardingInfoperPDUSession_Item = -1;
static gint ett_xnap_DataForwardingInfoFromTargetNGRANnode = -1;
static gint ett_xnap_DataForwardingResponseDRBItemList = -1;
static gint ett_xnap_DataForwardingResponseDRBItem = -1;
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
static gint ett_xnap_GBRQoSFlowInfo = -1;
static gint ett_xnap_GlobalgNB_ID = -1;
static gint ett_xnap_GNB_ID_Choice = -1;
static gint ett_xnap_GlobalngeNB_ID = -1;
static gint ett_xnap_ENB_ID_Choice = -1;
static gint ett_xnap_GlobalNG_RANNode_ID = -1;
static gint ett_xnap_GTPtunnelTransportLayerInformation = -1;
static gint ett_xnap_GUAMI = -1;
static gint ett_xnap_ListOfCells = -1;
static gint ett_xnap_CellsinAoI_Item = -1;
static gint ett_xnap_ListOfTAIsinAoI = -1;
static gint ett_xnap_TAIsinAoI_Item = -1;
static gint ett_xnap_LocationReportingInformation = -1;
static gint ett_xnap_MBSFNSubframeAllocation_E_UTRA = -1;
static gint ett_xnap_MBSFNSubframeInfo_E_UTRA = -1;
static gint ett_xnap_MBSFNSubframeInfo_E_UTRA_Item = -1;
static gint ett_xnap_MobilityRestrictionList = -1;
static gint ett_xnap_SEQUENCE_SIZE_1_maxnoofEPLMNs_OF_PLMN_Identity = -1;
static gint ett_xnap_RAT_RestrictionsList = -1;
static gint ett_xnap_RAT_RestrictionsItem = -1;
static gint ett_xnap_RAT_RestrictionInformation = -1;
static gint ett_xnap_ForbiddenAreaList = -1;
static gint ett_xnap_ForbiddenAreaItem = -1;
static gint ett_xnap_SEQUENCE_SIZE_1_maxnoofForbiddenTACs_OF_TAC = -1;
static gint ett_xnap_ServiceAreaList = -1;
static gint ett_xnap_ServiceAreaItem = -1;
static gint ett_xnap_SEQUENCE_SIZE_1_maxnoofAllowedAreas_OF_TAC = -1;
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
static gint ett_xnap_PDUSessionResourcesAdmitted_List = -1;
static gint ett_xnap_PDUSessionResourcesAdmitted_Item = -1;
static gint ett_xnap_PDUSessionResourceAdmittedInfo = -1;
static gint ett_xnap_PDUSessionResourcesNotAdmitted_List = -1;
static gint ett_xnap_PDUSessionResourcesNotAdmitted_Item = -1;
static gint ett_xnap_PDUSessionResourcesToBeSetup_List = -1;
static gint ett_xnap_PDUSessionResourcesToBeSetup_Item = -1;
static gint ett_xnap_QoSCharacteristics = -1;
static gint ett_xnap_QoSFlowLevelQoSParameters = -1;
static gint ett_xnap_QoSFlows_List = -1;
static gint ett_xnap_QoSFlow_Item = -1;
static gint ett_xnap_QoSFlowsAdmitted_List = -1;
static gint ett_xnap_QoSFlowAdmitted_Item = -1;
static gint ett_xnap_QoSFlowsNotAdmitted_List = -1;
static gint ett_xnap_QoSFlowNotAdmitted_Item = -1;
static gint ett_xnap_QoSFlowsToBeSetup_List = -1;
static gint ett_xnap_QoSFlowsToBeSetup_Item = -1;
static gint ett_xnap_RANAreaID = -1;
static gint ett_xnap_RANAreaID_List = -1;
static gint ett_xnap_RANPagingArea = -1;
static gint ett_xnap_RANPagingAreaChoice = -1;
static gint ett_xnap_RANPagingAttemptInfo = -1;
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
static gint ett_xnap_SecurityIndication = -1;
static gint ett_xnap_ServedCellInformation_E_UTRA = -1;
static gint ett_xnap_SEQUENCE_SIZE_1_maxnoofBPLMNs_OF_ServedCellInformation_E_UTRA_perBPLMN = -1;
static gint ett_xnap_ServedCellInformation_E_UTRA_perBPLMN = -1;
static gint ett_xnap_ServedCellInformation_E_UTRA_perBPLMN_ModeInfo = -1;
static gint ett_xnap_ServedCellInformation_E_UTRA_perBPLMN_FDDInfo = -1;
static gint ett_xnap_ServedCellInformation_E_UTRA_perBPLMN_TDDInfo = -1;
static gint ett_xnap_ServedCells_E_UTRA = -1;
static gint ett_xnap_ServedCells_E_UTRA_Item = -1;
static gint ett_xnap_ServedCellsToUpdate_E_UTRA = -1;
static gint ett_xnap_SEQUENCE_SIZE_1_maxnoofCellsinNGRANnode_OF_E_UTRA_CGI = -1;
static gint ett_xnap_ServedCells_ToModify_E_UTRA = -1;
static gint ett_xnap_ServedCells_ToModify_E_UTRA_Item = -1;
static gint ett_xnap_ServedCellInformation_NR = -1;
static gint ett_xnap_ServedCells_NR = -1;
static gint ett_xnap_ServedCells_NR_Item = -1;
static gint ett_xnap_ServedCells_ToModify_NR = -1;
static gint ett_xnap_ServedCells_ToModify_NR_Item = -1;
static gint ett_xnap_ServedCellsToUpdate_NR = -1;
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
static gint ett_xnap_TraceActivation = -1;
static gint ett_xnap_T_interfaces_to_trace = -1;
static gint ett_xnap_UEAggregateMaximumBitRate = -1;
static gint ett_xnap_UEContextID = -1;
static gint ett_xnap_UEContextIDforRRCResume = -1;
static gint ett_xnap_UEContextIDforRRCReestablishment = -1;
static gint ett_xnap_UEContextInfoRetrUECtxtResp = -1;
static gint ett_xnap_UERANPagingIdentity = -1;
static gint ett_xnap_UESecurityCapabilities = -1;
static gint ett_xnap_T_nr_EncyptionAlgorithms = -1;
static gint ett_xnap_T_nr_IntegrityProtectionAlgorithms = -1;
static gint ett_xnap_T_e_utra_EncyptionAlgorithms = -1;
static gint ett_xnap_T_e_utra_IntegrityProtectionAlgorithms = -1;
static gint ett_xnap_UPTransportLayerInformation = -1;
static gint ett_xnap_HandoverRequest = -1;
static gint ett_xnap_UEContextInfoHORequest = -1;
static gint ett_xnap_HandoverRequestAcknowledge = -1;
static gint ett_xnap_HandoverPreparationFailure = -1;
static gint ett_xnap_SNStatusTransfer = -1;
static gint ett_xnap_UEContextRelease = -1;
static gint ett_xnap_HandoverCancel = -1;
static gint ett_xnap_RANPaging = -1;
static gint ett_xnap_RetrieveUEContextRequest = -1;
static gint ett_xnap_RetrieveUEContextResponse = -1;
static gint ett_xnap_RetrieveUEContextFailure = -1;
static gint ett_xnap_DataForwardingAddressIndication = -1;
static gint ett_xnap_SNodeAdditionRequest = -1;
static gint ett_xnap_SNodeAdditionRequestAcknowledge = -1;
static gint ett_xnap_SNodeAdditionRequestReject = -1;
static gint ett_xnap_SNodeReconfigurationComplete = -1;
static gint ett_xnap_SNodeModificationRequest = -1;
static gint ett_xnap_SNodeModificationRequestAcknowledge = -1;
static gint ett_xnap_SNodeModificationRequestReject = -1;
static gint ett_xnap_SNodeModificationRequired = -1;
static gint ett_xnap_SNodeModificationConfirm = -1;
static gint ett_xnap_SNodeModificationRefuse = -1;
static gint ett_xnap_SNodeReleaseRequest = -1;
static gint ett_xnap_SNodeReleaseRequestAcknowledge = -1;
static gint ett_xnap_SNodeReleaseReject = -1;
static gint ett_xnap_SNodeReleaseRequired = -1;
static gint ett_xnap_SNodeReleaseConfirm = -1;
static gint ett_xnap_SNodeCounterCheckRequest = -1;
static gint ett_xnap_SNodeChangeRequired = -1;
static gint ett_xnap_SNodeChangeConfirm = -1;
static gint ett_xnap_SNodeChangeRefuse = -1;
static gint ett_xnap_RRCTransfer = -1;
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
#line 66 "./asn1/xnap/packet-xnap-template.c"

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
  g_snprintf(s, ITEM_LABEL_LENGTH, "%.1f %% (%u)", (float)v/10, v);
}

typedef enum {
  INITIATING_MESSAGE,
  SUCCESSFUL_OUTCOME,
  UNSUCCESSFUL_OUTCOME
} xnap_message_type;

struct xnap_conv_info {
  address addr_a;
  GlobalNG_RANNode_ID_enum ranmode_id_a;
  address addr_b;
  GlobalNG_RANNode_ID_enum ranmode_id_b;
};

struct xnap_private_data {
  struct xnap_conv_info *xnap_conv;
  xnap_message_type message_type;
  guint32 procedure_code;
  guint32 protocol_ie_id;
  guint32 triggering_message;
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
  { id_dataForwardingAddressIndication, "id-dataForwardingAddressIndication" },
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
  { 0, NULL }
};

static value_string_ext xnap_ProcedureCode_vals_ext = VALUE_STRING_EXT_INIT(xnap_ProcedureCode_vals);


static int
dissect_xnap_ProcedureCode(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 75 "./asn1/xnap/xnap.cnf"
  struct xnap_private_data *xnap_data = xnap_get_private_data(actx->pinfo);
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 255U, &xnap_data->procedure_code, FALSE);




  return offset;
}


static const value_string xnap_ProtocolIE_ID_vals[] = {
  { id_ActivatedServedCells, "id-ActivatedServedCells" },
  { id_ActivationIDforCellActivation, "id-ActivationIDforCellActivation" },
  { id_AMF_Pool_Information, "id-AMF-Pool-Information" },
  { id_AreaOfInterest_Item, "id-AreaOfInterest-Item" },
  { id_AssistanceDataForRANPaging, "id-AssistanceDataForRANPaging" },
  { id_Cause, "id-Cause" },
  { id_cellAssistanceInfo_NR, "id-cellAssistanceInfo-NR" },
  { id_ConfigurationUpdateInitiatingNodeChoice, "id-ConfigurationUpdateInitiatingNodeChoice" },
  { id_CriticalityDiagnostics, "id-CriticalityDiagnostics" },
  { id_dataforwardingInfoperPDUSession, "id-dataforwardingInfoperPDUSession" },
  { id_dataforwardingInfoperPDUSession_Item, "id-dataforwardingInfoperPDUSession-Item" },
  { id_DataForwardingResponseDRBItem, "id-DataForwardingResponseDRBItem" },
  { id_DRBsSubjectToStatusTransfer_Item, "id-DRBsSubjectToStatusTransfer-Item" },
  { id_DRBsSubjectToStatusTransfer_List, "id-DRBsSubjectToStatusTransfer-List" },
  { id_DRBToQoSFlowMapping_Item, "id-DRBToQoSFlowMapping-Item" },
  { id_GlobalNG_RAN_node_ID, "id-GlobalNG-RAN-node-ID" },
  { id_GUAMI, "id-GUAMI" },
  { id_List_of_served_cells_E_UTRA, "id-List-of-served-cells-E-UTRA" },
  { id_List_of_served_cells_NR, "id-List-of-served-cells-NR" },
  { id_LocationReportingInformation, "id-LocationReportingInformation" },
  { id_MAC_I, "id-MAC-I" },
  { id_MaskedIMEISV, "id-MaskedIMEISV" },
  { id_new_NG_RAN_Cell_Identity, "id-new-NG-RAN-Cell-Identity" },
  { id_newNG_RANnodeUEXnAPID, "id-newNG-RANnodeUEXnAPID" },
  { id_oldNG_RANnodeUEXnAPID, "id-oldNG-RANnodeUEXnAPID" },
  { id_PagingDRX, "id-PagingDRX" },
  { id_PDUSessionResourceAdmittedResponseTransferItem, "id-PDUSessionResourceAdmittedResponseTransferItem" },
  { id_PDUSessionResourcesAdmitted_Item, "id-PDUSessionResourcesAdmitted-Item" },
  { id_PDUSessionResourcesAdmitted_List, "id-PDUSessionResourcesAdmitted-List" },
  { id_PDUSessionResourcesNotAdmitted_Item, "id-PDUSessionResourcesNotAdmitted-Item" },
  { id_PDUSessionResourcesNotAdmitted_List, "id-PDUSessionResourcesNotAdmitted-List" },
  { id_PDUSessionResourcesToBeSetup_Item, "id-PDUSessionResourcesToBeSetup-Item" },
  { id_QoSFlowAdmitted_Item, "id-QoSFlowAdmitted-Item" },
  { id_QoSFlow_Item, "id-QoSFlow-Item" },
  { id_QoSFlowNotAdmitted_Item, "id-QoSFlowNotAdmitted-Item" },
  { id_QoSFlowsToBeSetup_Item, "id-QoSFlowsToBeSetup-Item" },
  { id_RANPagingArea, "id-RANPagingArea" },
  { id_RANPagingPriority, "id-RANPagingPriority" },
  { id_ResetRequestPartialReleaseItem, "id-ResetRequestPartialReleaseItem" },
  { id_ResetRequestTypeInfo, "id-ResetRequestTypeInfo" },
  { id_ResetResponsePartialReleaseItem, "id-ResetResponsePartialReleaseItem" },
  { id_ResetResponseTypeInfo, "id-ResetResponseTypeInfo" },
  { id_RespondingNodeTypeConfigUpdateAck, "id-RespondingNodeTypeConfigUpdateAck" },
  { id_ServedCellsToActivate, "id-ServedCellsToActivate" },
  { id_servedCellsToUpdate_E_UTRA, "id-servedCellsToUpdate-E-UTRA" },
  { id_ServedCellsToUpdateInitiatingNodeChoice, "id-ServedCellsToUpdateInitiatingNodeChoice" },
  { id_servedCellsToUpdate_NR, "id-servedCellsToUpdate-NR" },
  { id_sourceNG_RANnodeUEXnAPID, "id-sourceNG-RANnodeUEXnAPID" },
  { id_TAISupport_Item, "id-TAISupport-Item" },
  { id_TAISupport_list, "id-TAISupport-list" },
  { id_Target2SourceNG_RANnodeTranspContainer, "id-Target2SourceNG-RANnodeTranspContainer" },
  { id_targetCellGlobalID, "id-targetCellGlobalID" },
  { id_targetNG_RANnodeUEXnAPID, "id-targetNG-RANnodeUEXnAPID" },
  { id_TraceActivation, "id-TraceActivation" },
  { id_UEContextID, "id-UEContextID" },
  { id_UEContextInfoHORequest, "id-UEContextInfoHORequest" },
  { id_UEContextInfoRetrUECtxtResp, "id-UEContextInfoRetrUECtxtResp" },
  { id_UEIdentityIndexValue, "id-UEIdentityIndexValue" },
  { id_UERANPagingIdentity, "id-UERANPagingIdentity" },
  { id_XnRemovalThreshold, "id-XnRemovalThreshold" },
  { 0, NULL }
};

static value_string_ext xnap_ProtocolIE_ID_vals_ext = VALUE_STRING_EXT_INIT(xnap_ProtocolIE_ID_vals);


static int
dissect_xnap_ProtocolIE_ID(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 62 "./asn1/xnap/xnap.cnf"
  struct xnap_private_data *xnap_data = xnap_get_private_data(actx->pinfo);
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, maxProtocolIEs, &xnap_data->protocol_ie_id, FALSE);



#line 65 "./asn1/xnap/xnap.cnf"
  if (tree) {
    proto_item_append_text(proto_item_get_parent_nth(actx->created_item, 2), ": %s", val_to_str_ext(xnap_data->protocol_ie_id, &xnap_ProtocolIE_ID_vals_ext, "unknown (%d)"));
  }

  return offset;
}


static const value_string xnap_TriggeringMessage_vals[] = {
  { initiating_message, "initiating-message" },
  { successful_outcome, "successful-outcome" },
  { unsuccessful_outcome, "unsuccessful-outcome" },
  { 0, NULL }
};


static int
dissect_xnap_TriggeringMessage(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 79 "./asn1/xnap/xnap.cnf"
  struct xnap_private_data *xnap_data = xnap_get_private_data(actx->pinfo);
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     3, &xnap_data->triggering_message, FALSE, 0, NULL);



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
dissect_xnap_AMF_Pool_Information(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_octet_string(tvb, offset, actx, tree, hf_index,
                                       NO_BOUND, NO_BOUND, FALSE, NULL);

  return offset;
}



static int
dissect_xnap_AMF_UE_NGAP_ID(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 4294967295U, NULL, FALSE);

  return offset;
}


static const per_sequence_t AreaOfInterest_sequence_of[1] = {
  { &hf_xnap_AreaOfInterest_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_xnap_ProtocolIE_Single_Container },
};

static int
dissect_xnap_AreaOfInterest(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_xnap_AreaOfInterest, AreaOfInterest_sequence_of,
                                                  1, maxnoofAoIs, FALSE);

  return offset;
}



static int
dissect_xnap_PLMN_Identity(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 200 "./asn1/xnap/xnap.cnf"
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
dissect_xnap_TAC(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 212 "./asn1/xnap/xnap.cnf"
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
#line 225 "./asn1/xnap/xnap.cnf"
  tvbuff_t *cell_id_tvb = NULL;
  offset = dissect_per_bit_string(tvb, offset, actx, tree, -1,
                                     36, 36, FALSE, &cell_id_tvb, NULL);

  if (cell_id_tvb) {
    guint64 cell_id = tvb_get_bits64(cell_id_tvb, 0, 36, ENC_BIG_ENDIAN);
    actx->created_item = proto_tree_add_uint64(tree, hf_index, cell_id_tvb, 0, 5, cell_id);
  }



  return offset;
}



static int
dissect_xnap_E_UTRA_Cell_Identity(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 239 "./asn1/xnap/xnap.cnf"
  tvbuff_t *cell_id_tvb = NULL;
  offset = dissect_per_bit_string(tvb, offset, actx, tree, -1,
                                     28, 28, FALSE, &cell_id_tvb, NULL);

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
  {   0, &hf_xnap_nr             , ASN1_EXTENSION_ROOT    , dissect_xnap_NR_Cell_Identity },
  {   1, &hf_xnap_e_utra         , ASN1_EXTENSION_ROOT    , dissect_xnap_E_UTRA_Cell_Identity },
  {   2, &hf_xnap_choice_extension, ASN1_EXTENSION_ROOT    , dissect_xnap_ProtocolExtensionContainer },
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


static const per_sequence_t AreaOfInterest_Item_sequence[] = {
  { &hf_xnap_listOfTAIs     , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_xnap_ListOfTAIsinAoI },
  { &hf_xnap_listOfCells    , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_xnap_ListOfCells },
  { &hf_xnap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_xnap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_xnap_AreaOfInterest_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_xnap_AreaOfInterest_Item, AreaOfInterest_Item_sequence);

  return offset;
}



static int
dissect_xnap_BIT_STRING_SIZE_256(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_bit_string(tvb, offset, actx, tree, hf_index,
                                     256, 256, FALSE, NULL, NULL);

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
                                                            0U, 63U, NULL, FALSE);

  return offset;
}



static int
dissect_xnap_BitRate(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer_64b(tvb, offset, actx, tree, hf_index,
                                                            0U, G_GUINT64_CONSTANT(4000000000000), NULL, TRUE);

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
  { &hf_xnap_sd             , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_xnap_OCTET_STRING_SIZE_3 },
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
  { &hf_xnap_tAISliceSupport_List, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_xnap_SliceSupport_List },
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
  {   3, "invalid-AMF-Region-ID" },
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
  {  41, "unspecified" },
  { 0, NULL }
};


static int
dissect_xnap_CauseRadioNetworkLayer(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     42, NULL, TRUE, 0, NULL);

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
  {   0, &hf_xnap_radioNetwork   , ASN1_EXTENSION_ROOT    , dissect_xnap_CauseRadioNetworkLayer },
  {   1, &hf_xnap_transport      , ASN1_EXTENSION_ROOT    , dissect_xnap_CauseTransportLayer },
  {   2, &hf_xnap_protocol       , ASN1_EXTENSION_ROOT    , dissect_xnap_CauseProtocol },
  {   3, &hf_xnap_misc           , ASN1_EXTENSION_ROOT    , dissect_xnap_CauseMisc },
  {   4, &hf_xnap_choice_extension, ASN1_EXTENSION_ROOT    , dissect_xnap_ProtocolExtensionContainer },
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
  { &hf_xnap_nr_CI          , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_xnap_NR_Cell_Identity },
  { &hf_xnap_iE_Extension   , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_xnap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_xnap_NR_CGI(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_xnap_NR_CGI, NR_CGI_sequence);

  return offset;
}


static const per_sequence_t SEQUENCE_SIZE_1_maxnoofCellsinNGRANnode_OF_NR_CGI_sequence_of[1] = {
  { &hf_xnap_limitedNR_List_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_xnap_NR_CGI },
};

static int
dissect_xnap_SEQUENCE_SIZE_1_maxnoofCellsinNGRANnode_OF_NR_CGI(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_xnap_SEQUENCE_SIZE_1_maxnoofCellsinNGRANnode_OF_NR_CGI, SEQUENCE_SIZE_1_maxnoofCellsinNGRANnode_OF_NR_CGI_sequence_of,
                                                  1, maxnoofCellsinNGRANnode, FALSE);

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
  {   0, &hf_xnap_limitedNR_List , ASN1_EXTENSION_ROOT    , dissect_xnap_SEQUENCE_SIZE_1_maxnoofCellsinNGRANnode_OF_NR_CGI },
  {   1, &hf_xnap_full_List      , ASN1_EXTENSION_ROOT    , dissect_xnap_T_full_List },
  {   2, &hf_xnap_choice_extension, ASN1_EXTENSION_ROOT    , dissect_xnap_ProtocolExtensionContainer },
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



static int
dissect_xnap_TransportLayerAddress(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 261 "./asn1/xnap/xnap.cnf"
  tvbuff_t *parameter_tvb = NULL;
  proto_tree *subtree;
  int len;

  offset = dissect_per_bit_string(tvb, offset, actx, tree, hf_index,
                                     1, 160, TRUE, &parameter_tvb, &len);

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


static const value_string xnap_CPTransportLayerInformation_vals[] = {
  {   0, "endpointIPAddress" },
  {   1, "choice-extension" },
  { 0, NULL }
};

static const per_choice_t CPTransportLayerInformation_choice[] = {
  {   0, &hf_xnap_endpointIPAddress, ASN1_EXTENSION_ROOT    , dissect_xnap_TransportLayerAddress },
  {   1, &hf_xnap_choice_extension, ASN1_EXTENSION_ROOT    , dissect_xnap_ProtocolExtensionContainer },
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
                                     16, 16, FALSE, NULL, NULL);

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


static const per_sequence_t DataforwardingInfoperPDUSession_sequence_of[1] = {
  { &hf_xnap_DataforwardingInfoperPDUSession_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_xnap_ProtocolIE_Single_Container },
};

static int
dissect_xnap_DataforwardingInfoperPDUSession(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_xnap_DataforwardingInfoperPDUSession, DataforwardingInfoperPDUSession_sequence_of,
                                                  1, maxnoofPDUSessions, FALSE);

  return offset;
}



static int
dissect_xnap_PDUSession_ID(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 255U, NULL, FALSE);

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
  {   0, &hf_xnap_gtpTunnel      , ASN1_EXTENSION_ROOT    , dissect_xnap_GTPtunnelTransportLayerInformation },
  {   1, &hf_xnap_choice_extension, ASN1_EXTENSION_ROOT    , dissect_xnap_ProtocolExtensionContainer },
  { 0, NULL, 0, NULL }
};

static int
dissect_xnap_UPTransportLayerInformation(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_xnap_UPTransportLayerInformation, UPTransportLayerInformation_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t DataforwardingInfoperPDUSession_Item_sequence[] = {
  { &hf_xnap_pduSession_ID  , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_xnap_PDUSession_ID },
  { &hf_xnap_dlForwardingUPTNL, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_xnap_UPTransportLayerInformation },
  { &hf_xnap_iE_Extension   , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_xnap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_xnap_DataforwardingInfoperPDUSession_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_xnap_DataforwardingInfoperPDUSession_Item, DataforwardingInfoperPDUSession_Item_sequence);

  return offset;
}


static const value_string xnap_DataForwardingAccepted_vals[] = {
  {   0, "data-forwarding-accepted" },
  { 0, NULL }
};


static int
dissect_xnap_DataForwardingAccepted(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     1, NULL, TRUE, 0, NULL);

  return offset;
}


static const per_sequence_t DataForwardingResponseDRBItemList_sequence_of[1] = {
  { &hf_xnap_DataForwardingResponseDRBItemList_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_xnap_ProtocolIE_Single_Container },
};

static int
dissect_xnap_DataForwardingResponseDRBItemList(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_xnap_DataForwardingResponseDRBItemList, DataForwardingResponseDRBItemList_sequence_of,
                                                  1, maxnoofDRBs, FALSE);

  return offset;
}


static const per_sequence_t DataForwardingInfoFromTargetNGRANnode_sequence[] = {
  { &hf_xnap_pduSessionLevelDLDataForwardingInfo, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_xnap_UPTransportLayerInformation },
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


static const per_sequence_t DRBsSubjectToStatusTransfer_List_sequence_of[1] = {
  { &hf_xnap_DRBsSubjectToStatusTransfer_List_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_xnap_ProtocolIE_Single_Container },
};

static int
dissect_xnap_DRBsSubjectToStatusTransfer_List(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_xnap_DRBsSubjectToStatusTransfer_List, DRBsSubjectToStatusTransfer_List_sequence_of,
                                                  1, maxnoofDRBs, FALSE);

  return offset;
}



static int
dissect_xnap_BIT_STRING_SIZE_1_2048(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_bit_string(tvb, offset, actx, tree, hf_index,
                                     1, 2048, FALSE, NULL, NULL);

  return offset;
}


static const per_sequence_t DRBBStatusTransfer12bitsSN_sequence[] = {
  { &hf_xnap_receiveStatusofPDCPSDU, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_xnap_BIT_STRING_SIZE_1_2048 },
  { &hf_xnap_ulCOUNTValue   , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_xnap_COUNT_PDCP_SN12 },
  { &hf_xnap_dlCOUNTValue   , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_xnap_COUNT_PDCP_SN12 },
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
                                     1, 131072, FALSE, NULL, NULL);

  return offset;
}


static const per_sequence_t DRBBStatusTransfer18bitsSN_sequence[] = {
  { &hf_xnap_receiveStatusofPDCPSDU_01, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_xnap_BIT_STRING_SIZE_1_131072 },
  { &hf_xnap_ulCOUNTValue_01, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_xnap_COUNT_PDCP_SN18 },
  { &hf_xnap_dlCOUNTValue_01, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_xnap_COUNT_PDCP_SN18 },
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
  {   0, &hf_xnap_pdcp_sn_12bits , ASN1_EXTENSION_ROOT    , dissect_xnap_DRBBStatusTransfer12bitsSN },
  {   1, &hf_xnap_pdcp_sn_18bits , ASN1_EXTENSION_ROOT    , dissect_xnap_DRBBStatusTransfer18bitsSN },
  {   2, &hf_xnap_choice_extension, ASN1_EXTENSION_ROOT    , dissect_xnap_ProtocolExtensionContainer },
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
  { &hf_xnap_statusTransfer , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_xnap_DRBBStatusTransferChoice },
  { &hf_xnap_iE_Extension   , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_xnap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_xnap_DRBsSubjectToStatusTransfer_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_xnap_DRBsSubjectToStatusTransfer_Item, DRBsSubjectToStatusTransfer_Item_sequence);

  return offset;
}


static const per_sequence_t DRBToQoSFlowMapping_List_sequence_of[1] = {
  { &hf_xnap_DRBToQoSFlowMapping_List_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_xnap_ProtocolIE_Single_Container },
};

static int
dissect_xnap_DRBToQoSFlowMapping_List(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_xnap_DRBToQoSFlowMapping_List, DRBToQoSFlowMapping_List_sequence_of,
                                                  1, maxnoofDRBs, FALSE);

  return offset;
}


static const per_sequence_t QoSFlows_List_sequence_of[1] = {
  { &hf_xnap_QoSFlows_List_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_xnap_ProtocolIE_Single_Container },
};

static int
dissect_xnap_QoSFlows_List(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_xnap_QoSFlows_List, QoSFlows_List_sequence_of,
                                                  1, maxnoofQoSFlows, FALSE);

  return offset;
}


static const per_sequence_t DRBToQoSFlowMapping_Item_sequence[] = {
  { &hf_xnap_drb_ID         , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_xnap_DRB_ID },
  { &hf_xnap_qosFlows_List  , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_xnap_QoSFlows_List },
  { &hf_xnap_iE_Extension   , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_xnap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_xnap_DRBToQoSFlowMapping_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_xnap_DRBToQoSFlowMapping_Item, DRBToQoSFlowMapping_Item_sequence);

  return offset;
}



static int
dissect_xnap_INTEGER_1_128(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            1U, 128U, NULL, FALSE);

  return offset;
}



static int
dissect_xnap_PacketDelayBudget(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 63U, NULL, FALSE);

  return offset;
}



static int
dissect_xnap_PacketErrorRate(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 63U, NULL, FALSE);

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
                                                            0U, 63U, NULL, FALSE);

  return offset;
}


static const per_sequence_t Dynamic5QIDescriptor_sequence[] = {
  { &hf_xnap_priorityLevel_01, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_xnap_INTEGER_1_128 },
  { &hf_xnap_packetDelayBudget, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_xnap_PacketDelayBudget },
  { &hf_xnap_packetErrorRate, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_xnap_PacketErrorRate },
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
                                                            0U, 1000U, NULL, FALSE);

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
dissect_xnap_BIT_STRING_SIZE_22_32(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_bit_string(tvb, offset, actx, tree, hf_index,
                                     22, 32, FALSE, NULL, NULL);

  return offset;
}


static const value_string xnap_GNB_ID_Choice_vals[] = {
  {   0, "gnb-ID" },
  {   1, "choice-extension" },
  { 0, NULL }
};

static const per_choice_t GNB_ID_Choice_choice[] = {
  {   0, &hf_xnap_gnb_ID         , ASN1_EXTENSION_ROOT    , dissect_xnap_BIT_STRING_SIZE_22_32 },
  {   1, &hf_xnap_choice_extension, ASN1_EXTENSION_ROOT    , dissect_xnap_ProtocolExtensionContainer },
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
                                     20, 20, FALSE, NULL, NULL);

  return offset;
}



static int
dissect_xnap_BIT_STRING_SIZE_18(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_bit_string(tvb, offset, actx, tree, hf_index,
                                     18, 18, FALSE, NULL, NULL);

  return offset;
}



static int
dissect_xnap_BIT_STRING_SIZE_21(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_bit_string(tvb, offset, actx, tree, hf_index,
                                     21, 21, FALSE, NULL, NULL);

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
  {   0, &hf_xnap_enb_ID_macro   , ASN1_EXTENSION_ROOT    , dissect_xnap_BIT_STRING_SIZE_20 },
  {   1, &hf_xnap_enb_ID_shortmacro, ASN1_EXTENSION_ROOT    , dissect_xnap_BIT_STRING_SIZE_18 },
  {   2, &hf_xnap_enb_ID_longmacro, ASN1_EXTENSION_ROOT    , dissect_xnap_BIT_STRING_SIZE_21 },
  {   3, &hf_xnap_choice_extension, ASN1_EXTENSION_ROOT    , dissect_xnap_ProtocolExtensionContainer },
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
  { GlobalNG_RANNode_ID_gNB, &hf_xnap_gNB            , ASN1_EXTENSION_ROOT    , dissect_xnap_GlobalgNB_ID },
  { GlobalNG_RANNode_ID_ng_eNB, &hf_xnap_ng_eNB         , ASN1_EXTENSION_ROOT    , dissect_xnap_GlobalngeNB_ID },
  { GlobalNG_RANNode_ID_choice_extension, &hf_xnap_choice_extension, ASN1_EXTENSION_ROOT    , dissect_xnap_ProtocolExtensionContainer },
  { 0, NULL, 0, NULL }
};

static int
dissect_xnap_GlobalNG_RANNode_ID(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 103 "./asn1/xnap/xnap.cnf"
  gint value;
  struct xnap_private_data *xnap_data = xnap_get_private_data(actx->pinfo);

  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_xnap_GlobalNG_RANNode_ID, GlobalNG_RANNode_ID_choice,
                                 &value);

  if (xnap_data->xnap_conv && xnap_data->procedure_code == id_xnSetup) {
    if (addresses_equal(&actx->pinfo->src, &xnap_data->xnap_conv->addr_a)) {
      xnap_data->xnap_conv->ranmode_id_a = (GlobalNG_RANNode_ID_enum)value;
    } else if (addresses_equal(&actx->pinfo->src, &xnap_data->xnap_conv->addr_b)) {
      xnap_data->xnap_conv->ranmode_id_b = (GlobalNG_RANNode_ID_enum)value;
    }
  }



  return offset;
}



static int
dissect_xnap_OCTET_STRING_SIZE_2(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_octet_string(tvb, offset, actx, tree, hf_index,
                                       2, 2, FALSE, NULL);

  return offset;
}



static int
dissect_xnap_BIT_STRING_SIZE_4(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_bit_string(tvb, offset, actx, tree, hf_index,
                                     4, 4, FALSE, NULL, NULL);

  return offset;
}


static const per_sequence_t GUAMI_sequence[] = {
  { &hf_xnap_plmn_ID        , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_xnap_PLMN_Identity },
  { &hf_xnap_amf_region_if  , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_xnap_OCTET_STRING_SIZE_2 },
  { &hf_xnap_amf_set_id     , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_xnap_BIT_STRING_SIZE_4 },
  { &hf_xnap_amf_pointer    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_xnap_BIT_STRING_SIZE_4 },
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
dissect_xnap_I_RNTI(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_bit_string(tvb, offset, actx, tree, hf_index,
                                     40, 40, FALSE, NULL, NULL);

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
  { &hf_xnap_areaOfInterest , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_xnap_AreaOfInterest },
  { &hf_xnap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_xnap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_xnap_LocationReportingInformation(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_xnap_LocationReportingInformation, LocationReportingInformation_sequence);

  return offset;
}



static int
dissect_xnap_MAC_I(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_bit_string(tvb, offset, actx, tree, hf_index,
                                     16, 16, FALSE, NULL, NULL);

  return offset;
}



static int
dissect_xnap_MaskedIMEISV(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_bit_string(tvb, offset, actx, tree, hf_index,
                                     64, 64, FALSE, NULL, NULL);

  return offset;
}



static int
dissect_xnap_BIT_STRING_SIZE_6(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_bit_string(tvb, offset, actx, tree, hf_index,
                                     6, 6, FALSE, NULL, NULL);

  return offset;
}



static int
dissect_xnap_BIT_STRING_SIZE_24(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_bit_string(tvb, offset, actx, tree, hf_index,
                                     24, 24, FALSE, NULL, NULL);

  return offset;
}


static const value_string xnap_MBSFNSubframeAllocation_E_UTRA_vals[] = {
  {   0, "oneframe" },
  {   1, "fourframes" },
  {   2, "choice-extension" },
  { 0, NULL }
};

static const per_choice_t MBSFNSubframeAllocation_E_UTRA_choice[] = {
  {   0, &hf_xnap_oneframe       , ASN1_EXTENSION_ROOT    , dissect_xnap_BIT_STRING_SIZE_6 },
  {   1, &hf_xnap_fourframes     , ASN1_EXTENSION_ROOT    , dissect_xnap_BIT_STRING_SIZE_24 },
  {   2, &hf_xnap_choice_extension, ASN1_EXTENSION_ROOT    , dissect_xnap_ProtocolExtensionContainer },
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



static int
dissect_xnap_RAT_RestrictionInformation(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 340 "./asn1/xnap/xnap.cnf"
  tvbuff_t *parameter_tvb = NULL;
  offset = dissect_per_bit_string(tvb, offset, actx, tree, hf_index,
                                     8, 8, TRUE, &parameter_tvb, NULL);

  if (parameter_tvb) {
    const gint *fields[] = {
      &hf_xnap_RAT_RestrictionInformation_e_UTRA,
      &hf_xnap_RAT_RestrictionInformation_nR,
      NULL
    };
    proto_tree *subtree = proto_item_add_subtree(actx->created_item, ett_xnap_RAT_RestrictionInformation);
    proto_tree_add_bitmask_list(subtree, parameter_tvb, 0, 1, fields, ENC_BIG_ENDIAN);
  }



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
  { &hf_xnap_allowed_TACs_ServiceArea, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_xnap_SEQUENCE_SIZE_1_maxnoofAllowedAreas_OF_TAC },
  { &hf_xnap_not_allowed_TACs_ServiceArea, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_xnap_SEQUENCE_SIZE_1_maxnoofAllowedAreas_OF_TAC },
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


static const per_sequence_t NeighbourInformation_E_UTRA_Item_sequence[] = {
  { &hf_xnap_e_utra_PCI     , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_xnap_E_UTRAPCI },
  { &hf_xnap_e_utra_cgi     , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_xnap_E_UTRA_CGI },
  { &hf_xnap_earfcn         , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_xnap_E_UTRAARFCN },
  { &hf_xnap_tac            , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_xnap_TAC },
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
dissect_xnap_NRARFCN(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, maxNRARFCN, NULL, FALSE);

  return offset;
}



static int
dissect_xnap_NRTransmissionBandwidth(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 65535U, NULL, TRUE);

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
  {   0, &hf_xnap_fdd_info       , ASN1_EXTENSION_ROOT    , dissect_xnap_NeighbourInformation_NR_ModeFDDInfo },
  {   1, &hf_xnap_tdd_info       , ASN1_EXTENSION_ROOT    , dissect_xnap_NeighbourInformation_NR_ModeTDDInfo },
  {   2, &hf_xnap_choice_extension, ASN1_EXTENSION_ROOT    , dissect_xnap_ProtocolExtensionContainer },
  { 0, NULL, 0, NULL }
};

static int
dissect_xnap_NeighbourInformation_NR_ModeInfo(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_xnap_NeighbourInformation_NR_ModeInfo, NeighbourInformation_NR_ModeInfo_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t NeighbourInformation_NR_Item_sequence[] = {
  { &hf_xnap_e_utra_cgi     , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_xnap_E_UTRA_CGI },
  { &hf_xnap_e_utra_PCI     , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_xnap_E_UTRAPCI },
  { &hf_xnap_earfcn         , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_xnap_E_UTRAARFCN },
  { &hf_xnap_tac            , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_xnap_TAC },
  { &hf_xnap_nr_mode_info   , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_xnap_NeighbourInformation_NR_ModeInfo },
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



static int
dissect_xnap_NRPCI(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 1007U, NULL, TRUE);

  return offset;
}


static const value_string xnap_NG_RAN_CellPCI_vals[] = {
  {   0, "nr" },
  {   1, "e-utra" },
  {   2, "choice-extension" },
  { 0, NULL }
};

static const per_choice_t NG_RAN_CellPCI_choice[] = {
  {   0, &hf_xnap_nr_01          , ASN1_EXTENSION_ROOT    , dissect_xnap_NRPCI },
  {   1, &hf_xnap_e_utra_01      , ASN1_EXTENSION_ROOT    , dissect_xnap_E_UTRAPCI },
  {   2, &hf_xnap_choice_extension, ASN1_EXTENSION_ROOT    , dissect_xnap_ProtocolExtensionContainer },
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



static int
dissect_xnap_INTEGER_0_255(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 255U, NULL, FALSE);

  return offset;
}


static const per_sequence_t NonDynamic5QIDescriptor_sequence[] = {
  { &hf_xnap_fiveQI         , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_xnap_INTEGER_0_255 },
  { &hf_xnap_priorityLevel_01, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_xnap_INTEGER_1_128 },
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
  {   0, &hf_xnap_fdd            , ASN1_EXTENSION_ROOT    , dissect_xnap_NRModeInfoFDD },
  {   1, &hf_xnap_tdd            , ASN1_EXTENSION_ROOT    , dissect_xnap_NRModeInfoTDD },
  {   2, &hf_xnap_choice_extension, ASN1_EXTENSION_ROOT    , dissect_xnap_ProtocolExtensionContainer },
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
  {   2, "an3" },
  { 0, NULL }
};


static int
dissect_xnap_NumberOfAntennaPorts_E_UTRA(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     3, NULL, TRUE, 0, NULL);

  return offset;
}



static int
dissect_xnap_PagingDRX(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 63U, NULL, FALSE);

  return offset;
}


static const per_sequence_t PDUSessionResourcesAdmitted_List_sequence_of[1] = {
  { &hf_xnap_PDUSessionResourcesAdmitted_List_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_xnap_ProtocolIE_Single_Container },
};

static int
dissect_xnap_PDUSessionResourcesAdmitted_List(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_xnap_PDUSessionResourcesAdmitted_List, PDUSessionResourcesAdmitted_List_sequence_of,
                                                  1, maxnoofPDUSessions, FALSE);

  return offset;
}


static const per_sequence_t QoSFlowsAdmitted_List_sequence_of[1] = {
  { &hf_xnap_QoSFlowsAdmitted_List_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_xnap_ProtocolIE_Single_Container },
};

static int
dissect_xnap_QoSFlowsAdmitted_List(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_xnap_QoSFlowsAdmitted_List, QoSFlowsAdmitted_List_sequence_of,
                                                  1, maxnoofQoSFlows, FALSE);

  return offset;
}


static const per_sequence_t QoSFlowsNotAdmitted_List_sequence_of[1] = {
  { &hf_xnap_QoSFlowsNotAdmitted_List_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_xnap_ProtocolIE_Single_Container },
};

static int
dissect_xnap_QoSFlowsNotAdmitted_List(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_xnap_QoSFlowsNotAdmitted_List, QoSFlowsNotAdmitted_List_sequence_of,
                                                  1, maxnoofQoSFlows, FALSE);

  return offset;
}


static const per_sequence_t PDUSessionResourceAdmittedInfo_sequence[] = {
  { &hf_xnap_qosFlowsAdmitted_List, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_xnap_QoSFlowsAdmitted_List },
  { &hf_xnap_qosFlowsNotAdmitted_List, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_xnap_QoSFlowsNotAdmitted_List },
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
  { &hf_xnap_pduSessionResourceAdmittedInfo, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_xnap_PDUSessionResourceAdmittedInfo },
  { &hf_xnap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_xnap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_xnap_PDUSessionResourcesAdmitted_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_xnap_PDUSessionResourcesAdmitted_Item, PDUSessionResourcesAdmitted_Item_sequence);

  return offset;
}


static const per_sequence_t PDUSessionResourcesNotAdmitted_List_sequence_of[1] = {
  { &hf_xnap_PDUSessionResourcesNotAdmitted_List_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_xnap_ProtocolIE_Single_Container },
};

static int
dissect_xnap_PDUSessionResourcesNotAdmitted_List(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_xnap_PDUSessionResourcesNotAdmitted_List, PDUSessionResourcesNotAdmitted_List_sequence_of,
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


static const per_sequence_t PDUSessionResourcesToBeSetup_List_sequence_of[1] = {
  { &hf_xnap_PDUSessionResourcesToBeSetup_List_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_xnap_ProtocolIE_Single_Container },
};

static int
dissect_xnap_PDUSessionResourcesToBeSetup_List(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_xnap_PDUSessionResourcesToBeSetup_List, PDUSessionResourcesToBeSetup_List_sequence_of,
                                                  1, maxnoofPDUSessions, FALSE);

  return offset;
}



static int
dissect_xnap_OCTET_STRING(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_octet_string(tvb, offset, actx, tree, hf_index,
                                       NO_BOUND, NO_BOUND, FALSE, NULL);

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


static const per_sequence_t QoSFlowsToBeSetup_List_sequence_of[1] = {
  { &hf_xnap_QoSFlowsToBeSetup_List_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_xnap_ProtocolIE_Single_Container },
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
  { &hf_xnap_pduSessionAMBR , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_xnap_OCTET_STRING },
  { &hf_xnap_uL_NG_U_TNLatUPF, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_xnap_UPTransportLayerInformation },
  { &hf_xnap_securityIndication, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_xnap_SecurityIndication },
  { &hf_xnap_pduSessionType , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_xnap_PDUSessionType },
  { &hf_xnap_qosFlowsToBeSetup_List, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_xnap_QoSFlowsToBeSetup_List },
  { &hf_xnap_sourceDRBtoQoSFlowMapping, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_xnap_DRBToQoSFlowMapping_List },
  { &hf_xnap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_xnap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_xnap_PDUSessionResourcesToBeSetup_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_xnap_PDUSessionResourcesToBeSetup_Item, PDUSessionResourcesToBeSetup_Item_sequence);

  return offset;
}


static const value_string xnap_QoSCharacteristics_vals[] = {
  {   0, "non-dynamic" },
  {   1, "dynamic" },
  {   2, "choice-extension" },
  { 0, NULL }
};

static const per_choice_t QoSCharacteristics_choice[] = {
  {   0, &hf_xnap_non_dynamic    , ASN1_EXTENSION_ROOT    , dissect_xnap_NonDynamic5QIDescriptor },
  {   1, &hf_xnap_dynamic        , ASN1_EXTENSION_ROOT    , dissect_xnap_Dynamic5QIDescriptor },
  {   2, &hf_xnap_choice_extension, ASN1_EXTENSION_ROOT    , dissect_xnap_ProtocolExtensionContainer },
  { 0, NULL, 0, NULL }
};

static int
dissect_xnap_QoSCharacteristics(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_xnap_QoSCharacteristics, QoSCharacteristics_choice,
                                 NULL);

  return offset;
}



static int
dissect_xnap_QoSFlowIndicator(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 63U, NULL, TRUE);

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



static int
dissect_xnap_INTEGER_1_8_(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            1U, 8U, NULL, TRUE);

  return offset;
}


static const per_sequence_t QoSFlowLevelQoSParameters_sequence[] = {
  { &hf_xnap_qos_characteristics, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_xnap_QoSCharacteristics },
  { &hf_xnap_allocationAndRetentionPrio, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_xnap_AllocationandRetentionPriority },
  { &hf_xnap_gBRQoSFlowInfo , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_xnap_GBRQoSFlowInfo },
  { &hf_xnap_relectiveQoS   , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_xnap_ReflectiveQoSAttribute },
  { &hf_xnap_additionalQoSflowInfo, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_xnap_T_additionalQoSflowInfo },
  { &hf_xnap_pPI            , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_xnap_INTEGER_1_8_ },
  { &hf_xnap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_xnap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_xnap_QoSFlowLevelQoSParameters(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_xnap_QoSFlowLevelQoSParameters, QoSFlowLevelQoSParameters_sequence);

  return offset;
}


static const per_sequence_t QoSFlow_Item_sequence[] = {
  { &hf_xnap_qfi            , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_xnap_QoSFlowIndicator },
  { &hf_xnap_iE_Extension   , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_xnap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_xnap_QoSFlow_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_xnap_QoSFlow_Item, QoSFlow_Item_sequence);

  return offset;
}


static const per_sequence_t QoSFlowAdmitted_Item_sequence[] = {
  { &hf_xnap_qfi            , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_xnap_QoSFlowIndicator },
  { &hf_xnap_dataForwardingAccepted, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_xnap_DataForwardingAccepted },
  { &hf_xnap_iE_Extension   , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_xnap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_xnap_QoSFlowAdmitted_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_xnap_QoSFlowAdmitted_Item, QoSFlowAdmitted_Item_sequence);

  return offset;
}


static const per_sequence_t QoSFlowNotAdmitted_Item_sequence[] = {
  { &hf_xnap_qfi            , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_xnap_QoSFlowIndicator },
  { &hf_xnap_cause          , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_xnap_Cause },
  { &hf_xnap_iE_Extension   , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_xnap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_xnap_QoSFlowNotAdmitted_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_xnap_QoSFlowNotAdmitted_Item, QoSFlowNotAdmitted_Item_sequence);

  return offset;
}


static const per_sequence_t QoSFlowsToBeSetup_Item_sequence[] = {
  { &hf_xnap_qfi            , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_xnap_QoSFlowIndicator },
  { &hf_xnap_dlDataForwarding, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_xnap_DLForwarding },
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



static int
dissect_xnap_RANAC(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_bit_string(tvb, offset, actx, tree, hf_index,
                                     6, 6, FALSE, NULL, NULL);

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
  {   0, &hf_xnap_cell_List      , ASN1_EXTENSION_ROOT    , dissect_xnap_NG_RAN_Cell_Identity_ListinRANPagingArea },
  {   1, &hf_xnap_rANAreaID_List , ASN1_EXTENSION_ROOT    , dissect_xnap_RANAreaID_List },
  {   2, &hf_xnap_choice_extension, ASN1_EXTENSION_ROOT    , dissect_xnap_ProtocolExtensionContainer },
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



static int
dissect_xnap_RANPagingPriority(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            1U, 256U, NULL, FALSE);

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


static const per_sequence_t ResetRequestPartialReleaseList_sequence_of[1] = {
  { &hf_xnap_ResetRequestPartialReleaseList_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_xnap_ProtocolIE_Single_Container },
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
  {   0, &hf_xnap_fullReset      , ASN1_EXTENSION_ROOT    , dissect_xnap_ResetRequestTypeInfo_Full },
  {   1, &hf_xnap_partialReset   , ASN1_EXTENSION_ROOT    , dissect_xnap_ResetRequestTypeInfo_Partial },
  {   2, &hf_xnap_choice_extension, ASN1_EXTENSION_ROOT    , dissect_xnap_ProtocolExtensionContainer },
  { 0, NULL, 0, NULL }
};

static int
dissect_xnap_ResetRequestTypeInfo(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_xnap_ResetRequestTypeInfo, ResetRequestTypeInfo_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t ResetRequestPartialReleaseItem_sequence[] = {
  { &hf_xnap_ng_ran_node1UEXnAPID, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_xnap_NG_RANnodeUEXnAPID },
  { &hf_xnap_ng_ran_node2UEXnAPID, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_xnap_NG_RANnodeUEXnAPID },
  { &hf_xnap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_xnap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_xnap_ResetRequestPartialReleaseItem(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_xnap_ResetRequestPartialReleaseItem, ResetRequestPartialReleaseItem_sequence);

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


static const per_sequence_t ResetResponsePartialReleaseList_sequence_of[1] = {
  { &hf_xnap_ResetResponsePartialReleaseList_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_xnap_ProtocolIE_Single_Container },
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
  {   0, &hf_xnap_fullReset_01   , ASN1_EXTENSION_ROOT    , dissect_xnap_ResetResponseTypeInfo_Full },
  {   1, &hf_xnap_partialReset_01, ASN1_EXTENSION_ROOT    , dissect_xnap_ResetResponseTypeInfo_Partial },
  {   2, &hf_xnap_choice_extension, ASN1_EXTENSION_ROOT    , dissect_xnap_ProtocolExtensionContainer },
  { 0, NULL, 0, NULL }
};

static int
dissect_xnap_ResetResponseTypeInfo(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_xnap_ResetResponseTypeInfo, ResetResponseTypeInfo_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t ResetResponsePartialReleaseItem_sequence[] = {
  { &hf_xnap_ng_ran_node1UEXnAPID, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_xnap_NG_RANnodeUEXnAPID },
  { &hf_xnap_ng_ran_node2UEXnAPID, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_xnap_NG_RANnodeUEXnAPID },
  { &hf_xnap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_xnap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_xnap_ResetResponsePartialReleaseItem(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_xnap_ResetResponsePartialReleaseItem, ResetResponsePartialReleaseItem_sequence);

  return offset;
}



static int
dissect_xnap_RFSP_Index(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            1U, 256U, NULL, FALSE);

  return offset;
}


static const per_sequence_t ServedCellInformation_E_UTRA_perBPLMN_FDDInfo_sequence[] = {
  { &hf_xnap_ul_earfcn      , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_xnap_E_UTRAARFCN },
  { &hf_xnap_dl_earfcn      , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_xnap_E_UTRAARFCN },
  { &hf_xnap_ul_e_utraTxBW  , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_xnap_E_UTRATransmissionBandwidth },
  { &hf_xnap_dl_e_utraTxBW  , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_xnap_E_UTRATransmissionBandwidth },
  { &hf_xnap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_xnap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_xnap_ServedCellInformation_E_UTRA_perBPLMN_FDDInfo(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_xnap_ServedCellInformation_E_UTRA_perBPLMN_FDDInfo, ServedCellInformation_E_UTRA_perBPLMN_FDDInfo_sequence);

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


static const per_sequence_t ServedCellInformation_E_UTRA_perBPLMN_TDDInfo_sequence[] = {
  { &hf_xnap_earfcn         , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_xnap_E_UTRAARFCN },
  { &hf_xnap_e_utraTxBW     , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_xnap_E_UTRATransmissionBandwidth },
  { &hf_xnap_subframeAssignmnet, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_xnap_T_subframeAssignmnet },
  { &hf_xnap_specialSubframeInfo, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_xnap_SpecialSubframeInfo_E_UTRA },
  { &hf_xnap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_xnap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_xnap_ServedCellInformation_E_UTRA_perBPLMN_TDDInfo(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_xnap_ServedCellInformation_E_UTRA_perBPLMN_TDDInfo, ServedCellInformation_E_UTRA_perBPLMN_TDDInfo_sequence);

  return offset;
}


static const value_string xnap_ServedCellInformation_E_UTRA_perBPLMN_ModeInfo_vals[] = {
  {   0, "fdd" },
  {   1, "tdd" },
  {   2, "choice-extension" },
  { 0, NULL }
};

static const per_choice_t ServedCellInformation_E_UTRA_perBPLMN_ModeInfo_choice[] = {
  {   0, &hf_xnap_fdd_01         , ASN1_EXTENSION_ROOT    , dissect_xnap_ServedCellInformation_E_UTRA_perBPLMN_FDDInfo },
  {   1, &hf_xnap_tdd_01         , ASN1_EXTENSION_ROOT    , dissect_xnap_ServedCellInformation_E_UTRA_perBPLMN_TDDInfo },
  {   2, &hf_xnap_choice_extension, ASN1_EXTENSION_ROOT    , dissect_xnap_ProtocolExtensionContainer },
  { 0, NULL, 0, NULL }
};

static int
dissect_xnap_ServedCellInformation_E_UTRA_perBPLMN_ModeInfo(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_xnap_ServedCellInformation_E_UTRA_perBPLMN_ModeInfo, ServedCellInformation_E_UTRA_perBPLMN_ModeInfo_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t ServedCellInformation_E_UTRA_perBPLMN_sequence[] = {
  { &hf_xnap_plmn_id        , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_xnap_PLMN_Identity },
  { &hf_xnap_e_utra_mode_info, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_xnap_ServedCellInformation_E_UTRA_perBPLMN_ModeInfo },
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
  { &hf_xnap_broadcastPLMNs , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_xnap_SEQUENCE_SIZE_1_maxnoofBPLMNs_OF_ServedCellInformation_E_UTRA_perBPLMN },
  { &hf_xnap_numberofAntennaPorts, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_xnap_NumberOfAntennaPorts_E_UTRA },
  { &hf_xnap_prach_configuration, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_xnap_E_UTRAPRACHConfiguration },
  { &hf_xnap_mBSFNsubframeInfo, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_xnap_MBSFNSubframeInfo_E_UTRA },
  { &hf_xnap_multibandInfo  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_xnap_E_UTRAMultibandInfoList },
  { &hf_xnap_freqBandIndicatorPriority, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_xnap_T_freqBandIndicatorPriority },
  { &hf_xnap_bandwidthReducedSI, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_xnap_T_bandwidthReducedSI },
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
                                                  1, maxnoofCellsinNGRANnode, FALSE);

  return offset;
}


static const per_sequence_t ServedCells_ToModify_E_UTRA_Item_sequence[] = {
  { &hf_xnap_old_ECGI       , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_xnap_E_UTRA_CGI },
  { &hf_xnap_served_cell_info_E_UTRA, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_xnap_ServedCellInformation_E_UTRA },
  { &hf_xnap_neighbour_info_NR, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_xnap_NeighbourInformation_NR },
  { &hf_xnap_neighbour_info_E_UTRA, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_xnap_NeighbourInformation_E_UTRA },
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
                                                  1, maxnoofCellsinNGRANnode, FALSE);

  return offset;
}


static const per_sequence_t SEQUENCE_SIZE_1_maxnoofCellsinNGRANnode_OF_E_UTRA_CGI_sequence_of[1] = {
  { &hf_xnap_served_Cells_ToDelete_E_UTRA_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_xnap_E_UTRA_CGI },
};

static int
dissect_xnap_SEQUENCE_SIZE_1_maxnoofCellsinNGRANnode_OF_E_UTRA_CGI(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_xnap_SEQUENCE_SIZE_1_maxnoofCellsinNGRANnode_OF_E_UTRA_CGI, SEQUENCE_SIZE_1_maxnoofCellsinNGRANnode_OF_E_UTRA_CGI_sequence_of,
                                                  1, maxnoofCellsinNGRANnode, FALSE);

  return offset;
}


static const per_sequence_t ServedCellsToUpdate_E_UTRA_sequence[] = {
  { &hf_xnap_served_Cells_ToAdd_E_UTRA, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_xnap_ServedCells_E_UTRA },
  { &hf_xnap_served_Cells_ToModify_E_UTRA, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_xnap_ServedCells_ToModify_E_UTRA },
  { &hf_xnap_served_Cells_ToDelete_E_UTRA, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_xnap_SEQUENCE_SIZE_1_maxnoofCellsinNGRANnode_OF_E_UTRA_CGI },
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
dissect_xnap_T_measurementTimingConfiguration(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 247 "./asn1/xnap/xnap.cnf"
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
  { &hf_xnap_measurementTimingConfiguration, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_xnap_T_measurementTimingConfiguration },
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
                                                  1, maxnoofCellsinNGRANnode, FALSE);

  return offset;
}


static const per_sequence_t ServedCells_ToModify_NR_Item_sequence[] = {
  { &hf_xnap_old_NR_CGI     , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_xnap_NR_CGI },
  { &hf_xnap_served_cell_info_NR, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_xnap_ServedCellInformation_NR },
  { &hf_xnap_neighbour_info_NR, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_xnap_NeighbourInformation_NR },
  { &hf_xnap_neighbour_info_E_UTRA, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_xnap_NeighbourInformation_E_UTRA },
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
                                                  1, maxnoofCellsinNGRANnode, FALSE);

  return offset;
}


static const per_sequence_t ServedCellsToUpdate_NR_sequence[] = {
  { &hf_xnap_served_Cells_ToAdd_NR, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_xnap_ServedCells_NR },
  { &hf_xnap_served_Cells_ToModify_NR, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_xnap_ServedCells_ToModify_NR },
  { &hf_xnap_served_Cells_ToDelete_NR, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_xnap_SEQUENCE_SIZE_1_maxnoofCellsinNGRANnode_OF_NR_CGI },
  { &hf_xnap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_xnap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_xnap_ServedCellsToUpdate_NR(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_xnap_ServedCellsToUpdate_NR, ServedCellsToUpdate_NR_sequence);

  return offset;
}


static const per_sequence_t TAISupport_List_sequence_of[1] = {
  { &hf_xnap_TAISupport_List_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_xnap_ProtocolIE_Single_Container },
};

static int
dissect_xnap_TAISupport_List(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_xnap_TAISupport_List, TAISupport_List_sequence_of,
                                                  1, maxnoofsupportedTACs, FALSE);

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
  { &hf_xnap_broadcastPLMNs_01, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_xnap_SEQUENCE_SIZE_1_maxnoofsupportedPLMNs_OF_BroadcastPLMNinTAISupport_Item },
  { &hf_xnap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_xnap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_xnap_TAISupport_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_xnap_TAISupport_Item, TAISupport_Item_sequence);

  return offset;
}


static const value_string xnap_Target_CGI_vals[] = {
  {   0, "nr" },
  {   1, "e-utra" },
  {   2, "choice-extension" },
  { 0, NULL }
};

static const per_choice_t Target_CGI_choice[] = {
  {   0, &hf_xnap_nr_02          , ASN1_EXTENSION_ROOT    , dissect_xnap_NR_CGI },
  {   1, &hf_xnap_e_utra_02      , ASN1_EXTENSION_ROOT    , dissect_xnap_E_UTRA_CGI },
  {   2, &hf_xnap_choice_extension, ASN1_EXTENSION_ROOT    , dissect_xnap_ProtocolExtensionContainer },
  { 0, NULL, 0, NULL }
};

static int
dissect_xnap_Target_CGI(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_xnap_Target_CGI, Target_CGI_choice,
                                 NULL);

  return offset;
}



static int
dissect_xnap_T_ng_ran_TraceID(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 353 "./asn1/xnap/xnap.cnf"
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



static int
dissect_xnap_T_interfaces_to_trace(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 364 "./asn1/xnap/xnap.cnf"
  tvbuff_t *parameter_tvb = NULL;
  offset = dissect_per_bit_string(tvb, offset, actx, tree, hf_index,
                                     8, 8, FALSE, &parameter_tvb, NULL);

  if (parameter_tvb) {
    const gint *fields[] = {
      &hf_xnap_T_interfaces_to_trace_ng_c,
      &hf_xnap_T_interfaces_to_trace_x_nc,
      &hf_xnap_T_interfaces_to_trace_uu,
      &hf_xnap_T_interfaces_to_trace_f1_c,
      &hf_xnap_T_interfaces_to_trace_e1,
      NULL
    };
    proto_tree *subtree = proto_item_add_subtree(actx->created_item, ett_xnap_interfaces_to_trace);
    proto_tree_add_bitmask_list(subtree, parameter_tvb, 0, 1, fields, ENC_BIG_ENDIAN);
  }



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


static const per_sequence_t UEContextIDforRRCResume_sequence[] = {
  { &hf_xnap_i_rnti         , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_xnap_I_RNTI },
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
  {   0, &hf_xnap_rRCResume      , ASN1_EXTENSION_ROOT    , dissect_xnap_UEContextIDforRRCResume },
  {   1, &hf_xnap_rRRCReestablishment, ASN1_EXTENSION_ROOT    , dissect_xnap_UEContextIDforRRCReestablishment },
  {   2, &hf_xnap_choice_extension, ASN1_EXTENSION_ROOT    , dissect_xnap_ProtocolExtensionContainer },
  { 0, NULL, 0, NULL }
};

static int
dissect_xnap_UEContextID(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_xnap_UEContextID, UEContextID_choice,
                                 NULL);

  return offset;
}



static int
dissect_xnap_T_nr_EncyptionAlgorithms(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 284 "./asn1/xnap/xnap.cnf"
  tvbuff_t *parameter_tvb = NULL;
  offset = dissect_per_bit_string(tvb, offset, actx, tree, hf_index,
                                     16, 16, TRUE, &parameter_tvb, NULL);

  if (parameter_tvb) {
    const gint *fields[] = {
      &hf_xnap_T_nr_EncyptionAlgorithms_nea1_128,
      &hf_xnap_T_nr_EncyptionAlgorithms_nea2_128,
      &hf_xnap_T_nr_EncyptionAlgorithms_nea3_128,
      NULL
    };
    proto_tree *subtree = proto_item_add_subtree(actx->created_item, ett_xnap_nr_EncyptionAlgorithms);
    proto_tree_add_bitmask_list(subtree, parameter_tvb, 0, 2, fields, ENC_BIG_ENDIAN);
  }



  return offset;
}



static int
dissect_xnap_T_nr_IntegrityProtectionAlgorithms(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 298 "./asn1/xnap/xnap.cnf"
  tvbuff_t *parameter_tvb = NULL;
  offset = dissect_per_bit_string(tvb, offset, actx, tree, hf_index,
                                     16, 16, TRUE, &parameter_tvb, NULL);

  if (parameter_tvb) {
    const gint *fields[] = {
      &hf_xnap_T_nr_IntegrityProtectionAlgorithms_nia1_128,
      &hf_xnap_T_nr_IntegrityProtectionAlgorithms_nia2_128,
      &hf_xnap_T_nr_IntegrityProtectionAlgorithms_nia3_128,
      NULL
    };
    proto_tree *subtree = proto_item_add_subtree(actx->created_item, ett_xnap_nr_IntegrityProtectionAlgorithms);
    proto_tree_add_bitmask_list(subtree, parameter_tvb, 0, 2, fields, ENC_BIG_ENDIAN);
  }



  return offset;
}



static int
dissect_xnap_T_e_utra_EncyptionAlgorithms(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 312 "./asn1/xnap/xnap.cnf"
  tvbuff_t *parameter_tvb = NULL;
  offset = dissect_per_bit_string(tvb, offset, actx, tree, hf_index,
                                     16, 16, TRUE, &parameter_tvb, NULL);

  if (parameter_tvb) {
    const gint *fields[] = {
      &hf_xnap_T_e_utra_EncyptionAlgorithms_eea1_128,
      &hf_xnap_T_e_utra_EncyptionAlgorithms_eea2_128,
      &hf_xnap_T_e_utra_EncyptionAlgorithms_eea3_128,
      NULL
    };
    proto_tree *subtree = proto_item_add_subtree(actx->created_item, ett_xnap_e_utra_EncyptionAlgorithms);
    proto_tree_add_bitmask_list(subtree, parameter_tvb, 0, 2, fields, ENC_BIG_ENDIAN);
  }



  return offset;
}



static int
dissect_xnap_T_e_utra_IntegrityProtectionAlgorithms(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 326 "./asn1/xnap/xnap.cnf"
  tvbuff_t *parameter_tvb = NULL;
  offset = dissect_per_bit_string(tvb, offset, actx, tree, hf_index,
                                     16, 16, TRUE, &parameter_tvb, NULL);

  if (parameter_tvb) {
    const gint *fields[] = {
      &hf_xnap_T_e_utra_IntegrityProtectionAlgorithms_eia1_128,
      &hf_xnap_T_e_utra_IntegrityProtectionAlgorithms_eia2_128,
      &hf_xnap_T_e_utra_IntegrityProtectionAlgorithms_eia3_128,
      NULL
    };
    proto_tree *subtree = proto_item_add_subtree(actx->created_item, ett_xnap_e_utra_IntegrityProtectionAlgorithms);
    proto_tree_add_bitmask_list(subtree, parameter_tvb, 0, 2, fields, ENC_BIG_ENDIAN);
  }



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
#line 172 "./asn1/xnap/xnap.cnf"
  tvbuff_t *parameter_tvb = NULL;

  offset = dissect_per_octet_string(tvb, offset, actx, tree, hf_index,
                                       NO_BOUND, NO_BOUND, FALSE, &parameter_tvb);

  if (parameter_tvb) {
    struct xnap_private_data *xnap_data = xnap_get_private_data(actx->pinfo);
    proto_tree *subtree;
    GlobalNG_RANNode_ID_enum target_ranmode_id = (GlobalNG_RANNode_ID_enum)-1;

    if (xnap_data->xnap_conv) {
      if (addresses_equal(&actx->pinfo->dst, &xnap_data->xnap_conv->addr_a)) {
        target_ranmode_id = xnap_data->xnap_conv->ranmode_id_a;
      } else if (addresses_equal(&actx->pinfo->dst, &xnap_data->xnap_conv->addr_b)) {
        target_ranmode_id = xnap_data->xnap_conv->ranmode_id_b;
      }
    }
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
  { &hf_xnap_pduSessionResourcesToBeSet_List, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_xnap_PDUSessionResourcesToBeSetup_List },
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



static int
dissect_xnap_UEIdentityIndexValue(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 63U, NULL, FALSE);

  return offset;
}


static const value_string xnap_UERANPagingIdentity_vals[] = {
  {   0, "i-RNTI" },
  {   1, "choice-extension" },
  { 0, NULL }
};

static const per_choice_t UERANPagingIdentity_choice[] = {
  {   0, &hf_xnap_i_RNTI         , ASN1_EXTENSION_ROOT    , dissect_xnap_I_RNTI },
  {   1, &hf_xnap_choice_extension, ASN1_EXTENSION_ROOT    , dissect_xnap_ProtocolExtensionContainer },
  { 0, NULL, 0, NULL }
};

static int
dissect_xnap_UERANPagingIdentity(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_xnap_UERANPagingIdentity, UERANPagingIdentity_choice,
                                 NULL);

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
#line 382 "./asn1/xnap/xnap.cnf"
  col_append_sep_str(actx->pinfo->cinfo, COL_INFO, NULL, "HandoverRequest");

  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_xnap_HandoverRequest, HandoverRequest_sequence);

  return offset;
}



static int
dissect_xnap_T_rrc_Context_01(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 116 "./asn1/xnap/xnap.cnf"
  tvbuff_t *parameter_tvb = NULL;

  offset = dissect_per_octet_string(tvb, offset, actx, tree, hf_index,
                                       NO_BOUND, NO_BOUND, FALSE, &parameter_tvb);

  if (parameter_tvb) {
    struct xnap_private_data *xnap_data = xnap_get_private_data(actx->pinfo);
    proto_tree *subtree;
    GlobalNG_RANNode_ID_enum target_ranmode_id = (GlobalNG_RANNode_ID_enum)-1;

    if (xnap_data->xnap_conv) {
      if (addresses_equal(&actx->pinfo->dst, &xnap_data->xnap_conv->addr_a)) {
        target_ranmode_id = xnap_data->xnap_conv->ranmode_id_a;
      } else if (addresses_equal(&actx->pinfo->dst, &xnap_data->xnap_conv->addr_b)) {
        target_ranmode_id = xnap_data->xnap_conv->ranmode_id_b;
      }
    }
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
  { &hf_xnap_hlr            , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_xnap_MobilityRestrictionList },
  { &hf_xnap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_xnap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_xnap_UEContextInfoHORequest(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_xnap_UEContextInfoHORequest, UEContextInfoHORequest_sequence);

  return offset;
}


static const per_sequence_t HandoverRequestAcknowledge_sequence[] = {
  { &hf_xnap_protocolIEs    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_xnap_ProtocolIE_Container },
  { NULL, 0, 0, NULL }
};

static int
dissect_xnap_HandoverRequestAcknowledge(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 384 "./asn1/xnap/xnap.cnf"
  col_append_sep_str(actx->pinfo->cinfo, COL_INFO, NULL, "HandoverRequestAcknowledge");

  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_xnap_HandoverRequestAcknowledge, HandoverRequestAcknowledge_sequence);

  return offset;
}



static int
dissect_xnap_Target2SourceNG_RANnodeTranspContainer(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 144 "./asn1/xnap/xnap.cnf"
  tvbuff_t *parameter_tvb = NULL;

  offset = dissect_per_octet_string(tvb, offset, actx, tree, hf_index,
                                       NO_BOUND, NO_BOUND, FALSE, &parameter_tvb);

  if (parameter_tvb) {
    struct xnap_private_data *xnap_data = xnap_get_private_data(actx->pinfo);
    proto_tree *subtree;
    GlobalNG_RANNode_ID_enum target_ranmode_id = (GlobalNG_RANNode_ID_enum)-1;

    if (xnap_data->xnap_conv) {
      if (addresses_equal(&actx->pinfo->dst, &xnap_data->xnap_conv->addr_a)) {
        target_ranmode_id = xnap_data->xnap_conv->ranmode_id_a;
      } else if (addresses_equal(&actx->pinfo->dst, &xnap_data->xnap_conv->addr_b)) {
        target_ranmode_id = xnap_data->xnap_conv->ranmode_id_b;
      }
    }
    subtree = proto_item_add_subtree(actx->created_item, ett_nxap_container);
    if ((xnap_dissect_target_ng_ran_container_as == XNAP_NG_RAN_CONTAINER_AUTOMATIC &&
         target_ranmode_id == GlobalNG_RANNode_ID_gNB) ||
        (xnap_dissect_target_ng_ran_container_as == XNAP_NG_RAN_CONTAINER_GNB)) {
      dissect_nr_rrc_HandoverCommand_PDU(parameter_tvb, actx->pinfo, subtree, NULL);
    } else if ((xnap_dissect_target_ng_ran_container_as == XNAP_NG_RAN_CONTAINER_AUTOMATIC &&
                target_ranmode_id == GlobalNG_RANNode_ID_ng_eNB) ||
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
#line 386 "./asn1/xnap/xnap.cnf"
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
#line 388 "./asn1/xnap/xnap.cnf"
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
#line 402 "./asn1/xnap/xnap.cnf"
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
#line 390 "./asn1/xnap/xnap.cnf"
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
#line 398 "./asn1/xnap/xnap.cnf"
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
#line 392 "./asn1/xnap/xnap.cnf"
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
#line 394 "./asn1/xnap/xnap.cnf"
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
#line 396 "./asn1/xnap/xnap.cnf"
  col_append_sep_str(actx->pinfo->cinfo, COL_INFO, NULL, "RetrieveUEContextFailure");

  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_xnap_RetrieveUEContextFailure, RetrieveUEContextFailure_sequence);

  return offset;
}


static const per_sequence_t DataForwardingAddressIndication_sequence[] = {
  { &hf_xnap_protocolIEs    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_xnap_ProtocolIE_Container },
  { NULL, 0, 0, NULL }
};

static int
dissect_xnap_DataForwardingAddressIndication(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 400 "./asn1/xnap/xnap.cnf"
  col_append_sep_str(actx->pinfo->cinfo, COL_INFO, NULL, "DataForwardingAddressIndication");

  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_xnap_DataForwardingAddressIndication, DataForwardingAddressIndication_sequence);

  return offset;
}


static const per_sequence_t SNodeAdditionRequest_sequence[] = {
  { &hf_xnap_protocolIEs    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_xnap_ProtocolIE_Container },
  { NULL, 0, 0, NULL }
};

static int
dissect_xnap_SNodeAdditionRequest(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 404 "./asn1/xnap/xnap.cnf"
  col_append_sep_str(actx->pinfo->cinfo, COL_INFO, NULL, "SNodeAdditionRequest");

  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_xnap_SNodeAdditionRequest, SNodeAdditionRequest_sequence);

  return offset;
}


static const per_sequence_t SNodeAdditionRequestAcknowledge_sequence[] = {
  { &hf_xnap_protocolIEs    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_xnap_ProtocolIE_Container },
  { NULL, 0, 0, NULL }
};

static int
dissect_xnap_SNodeAdditionRequestAcknowledge(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 406 "./asn1/xnap/xnap.cnf"
  col_append_sep_str(actx->pinfo->cinfo, COL_INFO, NULL, "SNodeAdditionRequestAcknowledge");

  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_xnap_SNodeAdditionRequestAcknowledge, SNodeAdditionRequestAcknowledge_sequence);

  return offset;
}


static const per_sequence_t SNodeAdditionRequestReject_sequence[] = {
  { &hf_xnap_protocolIEs    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_xnap_ProtocolIE_Container },
  { NULL, 0, 0, NULL }
};

static int
dissect_xnap_SNodeAdditionRequestReject(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 408 "./asn1/xnap/xnap.cnf"
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
#line 410 "./asn1/xnap/xnap.cnf"
  col_append_sep_str(actx->pinfo->cinfo, COL_INFO, NULL, "SNodeReconfigurationComplete");

  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_xnap_SNodeReconfigurationComplete, SNodeReconfigurationComplete_sequence);

  return offset;
}


static const per_sequence_t SNodeModificationRequest_sequence[] = {
  { &hf_xnap_protocolIEs    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_xnap_ProtocolIE_Container },
  { NULL, 0, 0, NULL }
};

static int
dissect_xnap_SNodeModificationRequest(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 412 "./asn1/xnap/xnap.cnf"
  col_append_sep_str(actx->pinfo->cinfo, COL_INFO, NULL, "SNodeModificationRequest");

  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_xnap_SNodeModificationRequest, SNodeModificationRequest_sequence);

  return offset;
}


static const per_sequence_t SNodeModificationRequestAcknowledge_sequence[] = {
  { &hf_xnap_protocolIEs    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_xnap_ProtocolIE_Container },
  { NULL, 0, 0, NULL }
};

static int
dissect_xnap_SNodeModificationRequestAcknowledge(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 414 "./asn1/xnap/xnap.cnf"
  col_append_sep_str(actx->pinfo->cinfo, COL_INFO, NULL, "SNodeModificationRequestAcknowledge");

  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_xnap_SNodeModificationRequestAcknowledge, SNodeModificationRequestAcknowledge_sequence);

  return offset;
}


static const per_sequence_t SNodeModificationRequestReject_sequence[] = {
  { &hf_xnap_protocolIEs    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_xnap_ProtocolIE_Container },
  { NULL, 0, 0, NULL }
};

static int
dissect_xnap_SNodeModificationRequestReject(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 416 "./asn1/xnap/xnap.cnf"
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
#line 418 "./asn1/xnap/xnap.cnf"
  col_append_sep_str(actx->pinfo->cinfo, COL_INFO, NULL, "SNodeModificationRequired");

  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_xnap_SNodeModificationRequired, SNodeModificationRequired_sequence);

  return offset;
}


static const per_sequence_t SNodeModificationConfirm_sequence[] = {
  { &hf_xnap_protocolIEs    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_xnap_ProtocolIE_Container },
  { NULL, 0, 0, NULL }
};

static int
dissect_xnap_SNodeModificationConfirm(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 420 "./asn1/xnap/xnap.cnf"
  col_append_sep_str(actx->pinfo->cinfo, COL_INFO, NULL, "SNodeModificationConfirm");

  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_xnap_SNodeModificationConfirm, SNodeModificationConfirm_sequence);

  return offset;
}


static const per_sequence_t SNodeModificationRefuse_sequence[] = {
  { &hf_xnap_protocolIEs    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_xnap_ProtocolIE_Container },
  { NULL, 0, 0, NULL }
};

static int
dissect_xnap_SNodeModificationRefuse(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 422 "./asn1/xnap/xnap.cnf"
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
#line 424 "./asn1/xnap/xnap.cnf"
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
#line 426 "./asn1/xnap/xnap.cnf"
  col_append_sep_str(actx->pinfo->cinfo, COL_INFO, NULL, "SNodeReleaseRequestAcknowledge");

  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_xnap_SNodeReleaseRequestAcknowledge, SNodeReleaseRequestAcknowledge_sequence);

  return offset;
}


static const per_sequence_t SNodeReleaseReject_sequence[] = {
  { &hf_xnap_protocolIEs    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_xnap_ProtocolIE_Container },
  { NULL, 0, 0, NULL }
};

static int
dissect_xnap_SNodeReleaseReject(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 428 "./asn1/xnap/xnap.cnf"
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
#line 430 "./asn1/xnap/xnap.cnf"
  col_append_sep_str(actx->pinfo->cinfo, COL_INFO, NULL, "SNodeReleaseRequired");

  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_xnap_SNodeReleaseRequired, SNodeReleaseRequired_sequence);

  return offset;
}


static const per_sequence_t SNodeReleaseConfirm_sequence[] = {
  { &hf_xnap_protocolIEs    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_xnap_ProtocolIE_Container },
  { NULL, 0, 0, NULL }
};

static int
dissect_xnap_SNodeReleaseConfirm(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 432 "./asn1/xnap/xnap.cnf"
  col_append_sep_str(actx->pinfo->cinfo, COL_INFO, NULL, "SNodeReleaseConfirm");

  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_xnap_SNodeReleaseConfirm, SNodeReleaseConfirm_sequence);

  return offset;
}


static const per_sequence_t SNodeCounterCheckRequest_sequence[] = {
  { &hf_xnap_protocolIEs    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_xnap_ProtocolIE_Container },
  { NULL, 0, 0, NULL }
};

static int
dissect_xnap_SNodeCounterCheckRequest(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 434 "./asn1/xnap/xnap.cnf"
  col_append_sep_str(actx->pinfo->cinfo, COL_INFO, NULL, "SNodeCounterCheckRequest");

  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_xnap_SNodeCounterCheckRequest, SNodeCounterCheckRequest_sequence);

  return offset;
}


static const per_sequence_t SNodeChangeRequired_sequence[] = {
  { &hf_xnap_protocolIEs    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_xnap_ProtocolIE_Container },
  { NULL, 0, 0, NULL }
};

static int
dissect_xnap_SNodeChangeRequired(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 436 "./asn1/xnap/xnap.cnf"
  col_append_sep_str(actx->pinfo->cinfo, COL_INFO, NULL, "SNodeChangeRequired");

  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_xnap_SNodeChangeRequired, SNodeChangeRequired_sequence);

  return offset;
}


static const per_sequence_t SNodeChangeConfirm_sequence[] = {
  { &hf_xnap_protocolIEs    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_xnap_ProtocolIE_Container },
  { NULL, 0, 0, NULL }
};

static int
dissect_xnap_SNodeChangeConfirm(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 438 "./asn1/xnap/xnap.cnf"
  col_append_sep_str(actx->pinfo->cinfo, COL_INFO, NULL, "SNodeChangeConfirm");

  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_xnap_SNodeChangeConfirm, SNodeChangeConfirm_sequence);

  return offset;
}


static const per_sequence_t SNodeChangeRefuse_sequence[] = {
  { &hf_xnap_protocolIEs    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_xnap_ProtocolIE_Container },
  { NULL, 0, 0, NULL }
};

static int
dissect_xnap_SNodeChangeRefuse(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 440 "./asn1/xnap/xnap.cnf"
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
#line 442 "./asn1/xnap/xnap.cnf"
  col_append_sep_str(actx->pinfo->cinfo, COL_INFO, NULL, "RRCTransfer");

  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_xnap_RRCTransfer, RRCTransfer_sequence);

  return offset;
}


static const per_sequence_t XnSetupRequest_sequence[] = {
  { &hf_xnap_protocolIEs    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_xnap_ProtocolIE_Container },
  { NULL, 0, 0, NULL }
};

static int
dissect_xnap_XnSetupRequest(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 450 "./asn1/xnap/xnap.cnf"
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
#line 452 "./asn1/xnap/xnap.cnf"
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
#line 454 "./asn1/xnap/xnap.cnf"
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
#line 456 "./asn1/xnap/xnap.cnf"
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
  {   0, &hf_xnap_gNB_01         , ASN1_EXTENSION_ROOT    , dissect_xnap_ProtocolIE_Container },
  {   1, &hf_xnap_ng_eNB_01      , ASN1_EXTENSION_ROOT    , dissect_xnap_ProtocolIE_Container },
  {   2, &hf_xnap_choice_extension, ASN1_EXTENSION_ROOT    , dissect_xnap_ProtocolExtensionContainer },
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
#line 458 "./asn1/xnap/xnap.cnf"
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
  {   0, &hf_xnap_ng_eNB_02      , ASN1_EXTENSION_ROOT    , dissect_xnap_RespondingNodeTypeConfigUpdateAck_ng_eNB },
  {   1, &hf_xnap_gNB_02         , ASN1_EXTENSION_ROOT    , dissect_xnap_RespondingNodeTypeConfigUpdateAck_gNB },
  {   2, &hf_xnap_choice_extension, ASN1_EXTENSION_ROOT    , dissect_xnap_ProtocolExtensionContainer },
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
#line 460 "./asn1/xnap/xnap.cnf"
  col_append_sep_str(actx->pinfo->cinfo, COL_INFO, NULL, "NGRANNodeConfigurationUpdateFailure");

  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_xnap_NGRANNodeConfigurationUpdateFailure, NGRANNodeConfigurationUpdateFailure_sequence);

  return offset;
}


static const per_sequence_t XnRemovalRequest_sequence[] = {
  { &hf_xnap_protocolIEs    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_xnap_ProtocolIE_Container },
  { NULL, 0, 0, NULL }
};

static int
dissect_xnap_XnRemovalRequest(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 444 "./asn1/xnap/xnap.cnf"
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
#line 446 "./asn1/xnap/xnap.cnf"
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
#line 448 "./asn1/xnap/xnap.cnf"
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
#line 462 "./asn1/xnap/xnap.cnf"
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
  {   0, &hf_xnap_nr_cells       , ASN1_EXTENSION_ROOT    , dissect_xnap_SEQUENCE_SIZE_1_maxnoofCellsinNGRANnode_OF_NR_CGI },
  {   1, &hf_xnap_e_utra_cells   , ASN1_EXTENSION_ROOT    , dissect_xnap_SEQUENCE_SIZE_1_maxnoofCellsinNGRANnode_OF_E_UTRA_CGI },
  {   2, &hf_xnap_choice_extension, ASN1_EXTENSION_ROOT    , dissect_xnap_ProtocolExtensionContainer },
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
#line 464 "./asn1/xnap/xnap.cnf"
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
  {   0, &hf_xnap_nr_cells       , ASN1_EXTENSION_ROOT    , dissect_xnap_SEQUENCE_SIZE_1_maxnoofCellsinNGRANnode_OF_NR_CGI },
  {   1, &hf_xnap_e_utra_cells   , ASN1_EXTENSION_ROOT    , dissect_xnap_SEQUENCE_SIZE_1_maxnoofCellsinNGRANnode_OF_E_UTRA_CGI },
  {   2, &hf_xnap_choice_extension, ASN1_EXTENSION_ROOT    , dissect_xnap_ProtocolExtensionContainer },
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
#line 466 "./asn1/xnap/xnap.cnf"
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
#line 468 "./asn1/xnap/xnap.cnf"
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
#line 470 "./asn1/xnap/xnap.cnf"
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
#line 472 "./asn1/xnap/xnap.cnf"
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
#line 474 "./asn1/xnap/xnap.cnf"
  col_append_sep_str(actx->pinfo->cinfo, COL_INFO, NULL, "PrivateMessage");


  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_xnap_PrivateMessage, PrivateMessage_sequence);

  return offset;
}



static int
dissect_xnap_InitiatingMessage_value(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 85 "./asn1/xnap/xnap.cnf"
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
#line 90 "./asn1/xnap/xnap.cnf"
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
#line 95 "./asn1/xnap/xnap.cnf"
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

static int dissect_ActivationIDforCellActivation_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_xnap_ActivationIDforCellActivation(tvb, offset, &asn1_ctx, tree, hf_xnap_ActivationIDforCellActivation_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_AMF_Pool_Information_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_xnap_AMF_Pool_Information(tvb, offset, &asn1_ctx, tree, hf_xnap_AMF_Pool_Information_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_AreaOfInterest_Item_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_xnap_AreaOfInterest_Item(tvb, offset, &asn1_ctx, tree, hf_xnap_AreaOfInterest_Item_PDU);
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
static int dissect_DataforwardingInfoperPDUSession_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_xnap_DataforwardingInfoperPDUSession(tvb, offset, &asn1_ctx, tree, hf_xnap_DataforwardingInfoperPDUSession_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_DataforwardingInfoperPDUSession_Item_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_xnap_DataforwardingInfoperPDUSession_Item(tvb, offset, &asn1_ctx, tree, hf_xnap_DataforwardingInfoperPDUSession_Item_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_DataForwardingResponseDRBItem_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_xnap_DataForwardingResponseDRBItem(tvb, offset, &asn1_ctx, tree, hf_xnap_DataForwardingResponseDRBItem_PDU);
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
static int dissect_DRBsSubjectToStatusTransfer_Item_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_xnap_DRBsSubjectToStatusTransfer_Item(tvb, offset, &asn1_ctx, tree, hf_xnap_DRBsSubjectToStatusTransfer_Item_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_DRBToQoSFlowMapping_Item_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_xnap_DRBToQoSFlowMapping_Item(tvb, offset, &asn1_ctx, tree, hf_xnap_DRBToQoSFlowMapping_Item_PDU);
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
static int dissect_PDUSessionResourcesAdmitted_List_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_xnap_PDUSessionResourcesAdmitted_List(tvb, offset, &asn1_ctx, tree, hf_xnap_PDUSessionResourcesAdmitted_List_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_PDUSessionResourcesAdmitted_Item_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_xnap_PDUSessionResourcesAdmitted_Item(tvb, offset, &asn1_ctx, tree, hf_xnap_PDUSessionResourcesAdmitted_Item_PDU);
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
static int dissect_PDUSessionResourcesNotAdmitted_Item_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_xnap_PDUSessionResourcesNotAdmitted_Item(tvb, offset, &asn1_ctx, tree, hf_xnap_PDUSessionResourcesNotAdmitted_Item_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_PDUSessionResourcesToBeSetup_Item_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_xnap_PDUSessionResourcesToBeSetup_Item(tvb, offset, &asn1_ctx, tree, hf_xnap_PDUSessionResourcesToBeSetup_Item_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_QoSFlow_Item_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_xnap_QoSFlow_Item(tvb, offset, &asn1_ctx, tree, hf_xnap_QoSFlow_Item_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_QoSFlowAdmitted_Item_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_xnap_QoSFlowAdmitted_Item(tvb, offset, &asn1_ctx, tree, hf_xnap_QoSFlowAdmitted_Item_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_QoSFlowNotAdmitted_Item_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_xnap_QoSFlowNotAdmitted_Item(tvb, offset, &asn1_ctx, tree, hf_xnap_QoSFlowNotAdmitted_Item_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_QoSFlowsToBeSetup_Item_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_xnap_QoSFlowsToBeSetup_Item(tvb, offset, &asn1_ctx, tree, hf_xnap_QoSFlowsToBeSetup_Item_PDU);
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
static int dissect_RANPagingPriority_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_xnap_RANPagingPriority(tvb, offset, &asn1_ctx, tree, hf_xnap_RANPagingPriority_PDU);
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
static int dissect_ResetRequestPartialReleaseItem_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_xnap_ResetRequestPartialReleaseItem(tvb, offset, &asn1_ctx, tree, hf_xnap_ResetRequestPartialReleaseItem_PDU);
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
static int dissect_ResetResponsePartialReleaseItem_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_xnap_ResetResponsePartialReleaseItem(tvb, offset, &asn1_ctx, tree, hf_xnap_ResetResponsePartialReleaseItem_PDU);
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
static int dissect_TAISupport_List_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_xnap_TAISupport_List(tvb, offset, &asn1_ctx, tree, hf_xnap_TAISupport_List_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_TAISupport_Item_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_xnap_TAISupport_Item(tvb, offset, &asn1_ctx, tree, hf_xnap_TAISupport_Item_PDU);
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
static int dissect_TraceActivation_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_xnap_TraceActivation(tvb, offset, &asn1_ctx, tree, hf_xnap_TraceActivation_PDU);
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
static int dissect_UEIdentityIndexValue_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_xnap_UEIdentityIndexValue(tvb, offset, &asn1_ctx, tree, hf_xnap_UEIdentityIndexValue_PDU);
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
static int dissect_DataForwardingAddressIndication_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_xnap_DataForwardingAddressIndication(tvb, offset, &asn1_ctx, tree, hf_xnap_DataForwardingAddressIndication_PDU);
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
static int dissect_SNodeAdditionRequestAcknowledge_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_xnap_SNodeAdditionRequestAcknowledge(tvb, offset, &asn1_ctx, tree, hf_xnap_SNodeAdditionRequestAcknowledge_PDU);
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
static int dissect_SNodeModificationRequest_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_xnap_SNodeModificationRequest(tvb, offset, &asn1_ctx, tree, hf_xnap_SNodeModificationRequest_PDU);
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
static int dissect_SNodeModificationConfirm_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_xnap_SNodeModificationConfirm(tvb, offset, &asn1_ctx, tree, hf_xnap_SNodeModificationConfirm_PDU);
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
static int dissect_SNodeReleaseConfirm_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_xnap_SNodeReleaseConfirm(tvb, offset, &asn1_ctx, tree, hf_xnap_SNodeReleaseConfirm_PDU);
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
static int dissect_SNodeChangeRequired_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_xnap_SNodeChangeRequired(tvb, offset, &asn1_ctx, tree, hf_xnap_SNodeChangeRequired_PDU);
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
#line 141 "./asn1/xnap/packet-xnap-template.c"

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
    xnap_data->xnap_conv->ranmode_id_a = (GlobalNG_RANNode_ID_enum)-1;
    copy_address_wmem(wmem_file_scope(), &xnap_data->xnap_conv->addr_b, &pinfo->dst);
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
    { &hf_xnap_ActivationIDforCellActivation_PDU,
      { "ActivationIDforCellActivation", "xnap.ActivationIDforCellActivation",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_xnap_AMF_Pool_Information_PDU,
      { "AMF-Pool-Information", "xnap.AMF_Pool_Information",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_xnap_AreaOfInterest_Item_PDU,
      { "AreaOfInterest-Item", "xnap.AreaOfInterest_Item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_xnap_AssistanceDataForRANPaging_PDU,
      { "AssistanceDataForRANPaging", "xnap.AssistanceDataForRANPaging_element",
        FT_NONE, BASE_NONE, NULL, 0,
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
    { &hf_xnap_DataforwardingInfoperPDUSession_PDU,
      { "DataforwardingInfoperPDUSession", "xnap.DataforwardingInfoperPDUSession",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_xnap_DataforwardingInfoperPDUSession_Item_PDU,
      { "DataforwardingInfoperPDUSession-Item", "xnap.DataforwardingInfoperPDUSession_Item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_xnap_DataForwardingResponseDRBItem_PDU,
      { "DataForwardingResponseDRBItem", "xnap.DataForwardingResponseDRBItem_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_xnap_DRBsSubjectToStatusTransfer_List_PDU,
      { "DRBsSubjectToStatusTransfer-List", "xnap.DRBsSubjectToStatusTransfer_List",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_xnap_DRBsSubjectToStatusTransfer_Item_PDU,
      { "DRBsSubjectToStatusTransfer-Item", "xnap.DRBsSubjectToStatusTransfer_Item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_xnap_DRBToQoSFlowMapping_Item_PDU,
      { "DRBToQoSFlowMapping-Item", "xnap.DRBToQoSFlowMapping_Item_element",
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
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_xnap_PDUSessionResourcesAdmitted_List_PDU,
      { "PDUSessionResourcesAdmitted-List", "xnap.PDUSessionResourcesAdmitted_List",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_xnap_PDUSessionResourcesAdmitted_Item_PDU,
      { "PDUSessionResourcesAdmitted-Item", "xnap.PDUSessionResourcesAdmitted_Item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_xnap_PDUSessionResourcesNotAdmitted_List_PDU,
      { "PDUSessionResourcesNotAdmitted-List", "xnap.PDUSessionResourcesNotAdmitted_List",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_xnap_PDUSessionResourcesNotAdmitted_Item_PDU,
      { "PDUSessionResourcesNotAdmitted-Item", "xnap.PDUSessionResourcesNotAdmitted_Item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_xnap_PDUSessionResourcesToBeSetup_Item_PDU,
      { "PDUSessionResourcesToBeSetup-Item", "xnap.PDUSessionResourcesToBeSetup_Item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_xnap_QoSFlow_Item_PDU,
      { "QoSFlow-Item", "xnap.QoSFlow_Item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_xnap_QoSFlowAdmitted_Item_PDU,
      { "QoSFlowAdmitted-Item", "xnap.QoSFlowAdmitted_Item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_xnap_QoSFlowNotAdmitted_Item_PDU,
      { "QoSFlowNotAdmitted-Item", "xnap.QoSFlowNotAdmitted_Item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_xnap_QoSFlowsToBeSetup_Item_PDU,
      { "QoSFlowsToBeSetup-Item", "xnap.QoSFlowsToBeSetup_Item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_xnap_RANPagingArea_PDU,
      { "RANPagingArea", "xnap.RANPagingArea_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_xnap_RANPagingPriority_PDU,
      { "RANPagingPriority", "xnap.RANPagingPriority",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_xnap_ResetRequestTypeInfo_PDU,
      { "ResetRequestTypeInfo", "xnap.ResetRequestTypeInfo",
        FT_UINT32, BASE_DEC, VALS(xnap_ResetRequestTypeInfo_vals), 0,
        NULL, HFILL }},
    { &hf_xnap_ResetRequestPartialReleaseItem_PDU,
      { "ResetRequestPartialReleaseItem", "xnap.ResetRequestPartialReleaseItem_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_xnap_ResetResponseTypeInfo_PDU,
      { "ResetResponseTypeInfo", "xnap.ResetResponseTypeInfo",
        FT_UINT32, BASE_DEC, VALS(xnap_ResetResponseTypeInfo_vals), 0,
        NULL, HFILL }},
    { &hf_xnap_ResetResponsePartialReleaseItem_PDU,
      { "ResetResponsePartialReleaseItem", "xnap.ResetResponsePartialReleaseItem_element",
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
    { &hf_xnap_TAISupport_List_PDU,
      { "TAISupport-List", "xnap.TAISupport_List",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_xnap_TAISupport_Item_PDU,
      { "TAISupport-Item", "xnap.TAISupport_Item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_xnap_Target_CGI_PDU,
      { "Target-CGI", "xnap.Target_CGI",
        FT_UINT32, BASE_DEC, VALS(xnap_Target_CGI_vals), 0,
        NULL, HFILL }},
    { &hf_xnap_TraceActivation_PDU,
      { "TraceActivation", "xnap.TraceActivation_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_xnap_UEContextID_PDU,
      { "UEContextID", "xnap.UEContextID",
        FT_UINT32, BASE_DEC, VALS(xnap_UEContextID_vals), 0,
        NULL, HFILL }},
    { &hf_xnap_UEContextInfoRetrUECtxtResp_PDU,
      { "UEContextInfoRetrUECtxtResp", "xnap.UEContextInfoRetrUECtxtResp_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_xnap_UEIdentityIndexValue_PDU,
      { "UEIdentityIndexValue", "xnap.UEIdentityIndexValue",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_xnap_UERANPagingIdentity_PDU,
      { "UERANPagingIdentity", "xnap.UERANPagingIdentity",
        FT_UINT32, BASE_DEC, VALS(xnap_UERANPagingIdentity_vals), 0,
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
    { &hf_xnap_DataForwardingAddressIndication_PDU,
      { "DataForwardingAddressIndication", "xnap.DataForwardingAddressIndication_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_xnap_SNodeAdditionRequest_PDU,
      { "SNodeAdditionRequest", "xnap.SNodeAdditionRequest_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_xnap_SNodeAdditionRequestAcknowledge_PDU,
      { "SNodeAdditionRequestAcknowledge", "xnap.SNodeAdditionRequestAcknowledge_element",
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
    { &hf_xnap_SNodeModificationRequest_PDU,
      { "SNodeModificationRequest", "xnap.SNodeModificationRequest_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_xnap_SNodeModificationRequestAcknowledge_PDU,
      { "SNodeModificationRequestAcknowledge", "xnap.SNodeModificationRequestAcknowledge_element",
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
    { &hf_xnap_SNodeModificationConfirm_PDU,
      { "SNodeModificationConfirm", "xnap.SNodeModificationConfirm_element",
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
    { &hf_xnap_SNodeReleaseReject_PDU,
      { "SNodeReleaseReject", "xnap.SNodeReleaseReject_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_xnap_SNodeReleaseRequired_PDU,
      { "SNodeReleaseRequired", "xnap.SNodeReleaseRequired_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_xnap_SNodeReleaseConfirm_PDU,
      { "SNodeReleaseConfirm", "xnap.SNodeReleaseConfirm_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_xnap_SNodeCounterCheckRequest_PDU,
      { "SNodeCounterCheckRequest", "xnap.SNodeCounterCheckRequest_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_xnap_SNodeChangeRequired_PDU,
      { "SNodeChangeRequired", "xnap.SNodeChangeRequired_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_xnap_SNodeChangeConfirm_PDU,
      { "SNodeChangeConfirm", "xnap.SNodeChangeConfirm_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_xnap_SNodeChangeRefuse_PDU,
      { "SNodeChangeRefuse", "xnap.SNodeChangeRefuse_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_xnap_RRCTransfer_PDU,
      { "RRCTransfer", "xnap.RRCTransfer_element",
        FT_NONE, BASE_NONE, NULL, 0,
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
    { &hf_xnap_iE_Extensions,
      { "iE-Extensions", "xnap.iE_Extensions",
        FT_UINT32, BASE_DEC, NULL, 0,
        "ProtocolExtensionContainer", HFILL }},
    { &hf_xnap_AreaOfInterest_item,
      { "ProtocolIE-Single-Container", "xnap.ProtocolIE_Single_Container_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_xnap_listOfTAIs,
      { "listOfTAIs", "xnap.listOfTAIs",
        FT_UINT32, BASE_DEC, NULL, 0,
        "ListOfTAIsinAoI", HFILL }},
    { &hf_xnap_listOfCells,
      { "listOfCells", "xnap.listOfCells",
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
    { &hf_xnap_BroadcastPLMNs_item,
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
    { &hf_xnap_iE_Extension,
      { "iE-Extension", "xnap.iE_Extension",
        FT_UINT32, BASE_DEC, NULL, 0,
        "ProtocolExtensionContainer", HFILL }},
    { &hf_xnap_radioNetwork,
      { "radioNetwork", "xnap.radioNetwork",
        FT_UINT32, BASE_DEC, VALS(xnap_CauseRadioNetworkLayer_vals), 0,
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
      { "choice-extension", "xnap.choice_extension",
        FT_UINT32, BASE_DEC, NULL, 0,
        "ProtocolExtensionContainer", HFILL }},
    { &hf_xnap_limitedNR_List,
      { "limitedNR-List", "xnap.limitedNR_List",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_SIZE_1_maxnoofCellsinNGRANnode_OF_NR_CGI", HFILL }},
    { &hf_xnap_limitedNR_List_item,
      { "NR-CGI", "xnap.NR_CGI_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_xnap_full_List,
      { "full-List", "xnap.full_List",
        FT_UINT32, BASE_DEC, VALS(xnap_T_full_List_vals), 0,
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
    { &hf_xnap_DataforwardingInfoperPDUSession_item,
      { "ProtocolIE-Single-Container", "xnap.ProtocolIE_Single_Container_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_xnap_pduSession_ID,
      { "pduSession-ID", "xnap.pduSession_ID",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_xnap_dlForwardingUPTNL,
      { "dlForwardingUPTNL", "xnap.dlForwardingUPTNL",
        FT_UINT32, BASE_DEC, VALS(xnap_UPTransportLayerInformation_vals), 0,
        "UPTransportLayerInformation", HFILL }},
    { &hf_xnap_pduSessionLevelDLDataForwardingInfo,
      { "pduSessionLevelDLDataForwardingInfo", "xnap.pduSessionLevelDLDataForwardingInfo",
        FT_UINT32, BASE_DEC, VALS(xnap_UPTransportLayerInformation_vals), 0,
        "UPTransportLayerInformation", HFILL }},
    { &hf_xnap_dataForwardingResponseDRBItemList,
      { "dataForwardingResponseDRBItemList", "xnap.dataForwardingResponseDRBItemList",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_xnap_DataForwardingResponseDRBItemList_item,
      { "ProtocolIE-Single-Container", "xnap.ProtocolIE_Single_Container_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_xnap_drb_ID,
      { "drb-ID", "xnap.drb_ID",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_xnap_ulForwardingUPTNL,
      { "ulForwardingUPTNL", "xnap.ulForwardingUPTNL",
        FT_UINT32, BASE_DEC, VALS(xnap_UPTransportLayerInformation_vals), 0,
        "UPTransportLayerInformation", HFILL }},
    { &hf_xnap_DRBsSubjectToStatusTransfer_List_item,
      { "ProtocolIE-Single-Container", "xnap.ProtocolIE_Single_Container_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_xnap_drbID,
      { "drbID", "xnap.drbID",
        FT_UINT32, BASE_DEC, NULL, 0,
        "DRB_ID", HFILL }},
    { &hf_xnap_statusTransfer,
      { "statusTransfer", "xnap.statusTransfer",
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
    { &hf_xnap_ulCOUNTValue,
      { "ulCOUNTValue", "xnap.ulCOUNTValue_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "COUNT_PDCP_SN12", HFILL }},
    { &hf_xnap_dlCOUNTValue,
      { "dlCOUNTValue", "xnap.dlCOUNTValue_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "COUNT_PDCP_SN12", HFILL }},
    { &hf_xnap_receiveStatusofPDCPSDU_01,
      { "receiveStatusofPDCPSDU", "xnap.receiveStatusofPDCPSDU",
        FT_BYTES, BASE_NONE, NULL, 0,
        "BIT_STRING_SIZE_1_131072", HFILL }},
    { &hf_xnap_ulCOUNTValue_01,
      { "ulCOUNTValue", "xnap.ulCOUNTValue_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "COUNT_PDCP_SN18", HFILL }},
    { &hf_xnap_dlCOUNTValue_01,
      { "dlCOUNTValue", "xnap.dlCOUNTValue_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "COUNT_PDCP_SN18", HFILL }},
    { &hf_xnap_DRBToQoSFlowMapping_List_item,
      { "ProtocolIE-Single-Container", "xnap.ProtocolIE_Single_Container_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_xnap_qosFlows_List,
      { "qosFlows-List", "xnap.qosFlows_List",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_xnap_priorityLevel_01,
      { "priorityLevel", "xnap.priorityLevel",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_1_128", HFILL }},
    { &hf_xnap_packetDelayBudget,
      { "packetDelayBudget", "xnap.packetDelayBudget",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_xnap_packetErrorRate,
      { "packetErrorRate", "xnap.packetErrorRate",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_xnap_delayCritical,
      { "delayCritical", "xnap.delayCritical",
        FT_UINT32, BASE_DEC, VALS(xnap_T_delayCritical_vals), 0,
        NULL, HFILL }},
    { &hf_xnap_averagingWindow,
      { "averagingWindow", "xnap.averagingWindow",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_xnap_maximumDataBurstVolume,
      { "maximumDataBurstVolume", "xnap.maximumDataBurstVolume",
        FT_UINT32, BASE_DEC, NULL, 0,
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
    { &hf_xnap_plmn_ID,
      { "plmn-ID", "xnap.plmn_ID",
        FT_BYTES, BASE_NONE, NULL, 0,
        "PLMN_Identity", HFILL }},
    { &hf_xnap_amf_region_if,
      { "amf-region-if", "xnap.amf_region_if",
        FT_BYTES, BASE_NONE, NULL, 0,
        "OCTET_STRING_SIZE_2", HFILL }},
    { &hf_xnap_amf_set_id,
      { "amf-set-id", "xnap.amf_set_id",
        FT_BYTES, BASE_NONE, NULL, 0,
        "BIT_STRING_SIZE_4", HFILL }},
    { &hf_xnap_amf_pointer,
      { "amf-pointer", "xnap.amf_pointer",
        FT_BYTES, BASE_NONE, NULL, 0,
        "BIT_STRING_SIZE_4", HFILL }},
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
        NULL, HFILL }},
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
    { &hf_xnap_RAT_RestrictionsList_item,
      { "RAT-RestrictionsItem", "xnap.RAT_RestrictionsItem_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_xnap_plmn_Identity,
      { "plmn-Identity", "xnap.plmn_Identity",
        FT_BYTES, BASE_NONE, NULL, 0,
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
    { &hf_xnap_tac,
      { "tac", "xnap.tac",
        FT_UINT24, BASE_DEC_HEX, NULL, 0,
        NULL, HFILL }},
    { &hf_xnap_NeighbourInformation_NR_item,
      { "NeighbourInformation-NR-Item", "xnap.NeighbourInformation_NR_Item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_xnap_nr_mode_info,
      { "nr-mode-info", "xnap.nr_mode_info",
        FT_UINT32, BASE_DEC, VALS(xnap_NeighbourInformation_NR_ModeInfo_vals), 0,
        "NeighbourInformation_NR_ModeInfo", HFILL }},
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
    { &hf_xnap_fiveQI,
      { "fiveQI", "xnap.fiveQI",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_255", HFILL }},
    { &hf_xnap_NG_RAN_Cell_Identity_ListinRANPagingArea_item,
      { "NG-RAN-Cell-Identity", "xnap.NG_RAN_Cell_Identity",
        FT_UINT32, BASE_DEC, VALS(xnap_NG_RAN_Cell_Identity_vals), 0,
        NULL, HFILL }},
    { &hf_xnap_nr_CI,
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
      { "ulNRTransmissonBandwidth", "xnap.ulNRTransmissonBandwidth",
        FT_UINT32, BASE_DEC, NULL, 0,
        "NRTransmissionBandwidth", HFILL }},
    { &hf_xnap_dlNRTransmissonBandwidth,
      { "dlNRTransmissonBandwidth", "xnap.dlNRTransmissonBandwidth",
        FT_UINT32, BASE_DEC, NULL, 0,
        "NRTransmissionBandwidth", HFILL }},
    { &hf_xnap_nrFrequencyInfo,
      { "nrFrequencyInfo", "xnap.nrFrequencyInfo_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_xnap_nrTransmissonBandwidth,
      { "nrTransmissonBandwidth", "xnap.nrTransmissonBandwidth",
        FT_UINT32, BASE_DEC, NULL, 0,
        "NRTransmissionBandwidth", HFILL }},
    { &hf_xnap_PDUSessionResourcesAdmitted_List_item,
      { "ProtocolIE-Single-Container", "xnap.ProtocolIE_Single_Container_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_xnap_pduSessionId,
      { "pduSessionId", "xnap.pduSessionId",
        FT_UINT32, BASE_DEC, NULL, 0,
        "PDUSession_ID", HFILL }},
    { &hf_xnap_pduSessionResourceAdmittedInfo,
      { "pduSessionResourceAdmittedInfo", "xnap.pduSessionResourceAdmittedInfo_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_xnap_qosFlowsAdmitted_List,
      { "qosFlowsAdmitted-List", "xnap.qosFlowsAdmitted_List",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_xnap_qosFlowsNotAdmitted_List,
      { "qosFlowsNotAdmitted-List", "xnap.qosFlowsNotAdmitted_List",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_xnap_dataForwardingInfoFromTarget,
      { "dataForwardingInfoFromTarget", "xnap.dataForwardingInfoFromTarget_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "DataForwardingInfoFromTargetNGRANnode", HFILL }},
    { &hf_xnap_PDUSessionResourcesNotAdmitted_List_item,
      { "ProtocolIE-Single-Container", "xnap.ProtocolIE_Single_Container_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_xnap_cause,
      { "cause", "xnap.cause",
        FT_UINT32, BASE_DEC, VALS(xnap_Cause_vals), 0,
        NULL, HFILL }},
    { &hf_xnap_PDUSessionResourcesToBeSetup_List_item,
      { "ProtocolIE-Single-Container", "xnap.ProtocolIE_Single_Container_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_xnap_s_NSSAI,
      { "s-NSSAI", "xnap.s_NSSAI_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_xnap_pduSessionAMBR,
      { "pduSessionAMBR", "xnap.pduSessionAMBR",
        FT_BYTES, BASE_NONE, NULL, 0,
        "OCTET_STRING", HFILL }},
    { &hf_xnap_uL_NG_U_TNLatUPF,
      { "uL-NG-U-TNLatUPF", "xnap.uL_NG_U_TNLatUPF",
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
    { &hf_xnap_qosFlowsToBeSetup_List,
      { "qosFlowsToBeSetup-List", "xnap.qosFlowsToBeSetup_List",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_xnap_sourceDRBtoQoSFlowMapping,
      { "sourceDRBtoQoSFlowMapping", "xnap.sourceDRBtoQoSFlowMapping",
        FT_UINT32, BASE_DEC, NULL, 0,
        "DRBToQoSFlowMapping_List", HFILL }},
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
    { &hf_xnap_pPI,
      { "pPI", "xnap.pPI",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_1_8_", HFILL }},
    { &hf_xnap_QoSFlows_List_item,
      { "ProtocolIE-Single-Container", "xnap.ProtocolIE_Single_Container_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_xnap_qfi,
      { "qfi", "xnap.qfi",
        FT_UINT32, BASE_DEC, NULL, 0,
        "QoSFlowIndicator", HFILL }},
    { &hf_xnap_QoSFlowsAdmitted_List_item,
      { "ProtocolIE-Single-Container", "xnap.ProtocolIE_Single_Container_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_xnap_dataForwardingAccepted,
      { "dataForwardingAccepted", "xnap.dataForwardingAccepted",
        FT_UINT32, BASE_DEC, VALS(xnap_DataForwardingAccepted_vals), 0,
        NULL, HFILL }},
    { &hf_xnap_QoSFlowsNotAdmitted_List_item,
      { "ProtocolIE-Single-Container", "xnap.ProtocolIE_Single_Container_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_xnap_QoSFlowsToBeSetup_List_item,
      { "ProtocolIE-Single-Container", "xnap.ProtocolIE_Single_Container_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_xnap_dlDataForwarding,
      { "dlDataForwarding", "xnap.dlDataForwarding",
        FT_UINT32, BASE_DEC, VALS(xnap_DLForwarding_vals), 0,
        "DLForwarding", HFILL }},
    { &hf_xnap_qosFlowLevelQoSParameters,
      { "qosFlowLevelQoSParameters", "xnap.qosFlowLevelQoSParameters_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_xnap_e_RAB_ID,
      { "e-RAB-ID", "xnap.e_RAB_ID",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_xnap_rANAC,
      { "rANAC", "xnap.rANAC",
        FT_BYTES, BASE_NONE, NULL, 0,
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
      { "ProtocolIE-Single-Container", "xnap.ProtocolIE_Single_Container_element",
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
      { "ProtocolIE-Single-Container", "xnap.ProtocolIE_Single_Container_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_xnap_integrityProtectionIndication,
      { "integrityProtectionIndication", "xnap.integrityProtectionIndication",
        FT_UINT32, BASE_DEC, VALS(xnap_T_integrityProtectionIndication_vals), 0,
        NULL, HFILL }},
    { &hf_xnap_confidentialityProtectionIndication,
      { "confidentialityProtectionIndication", "xnap.confidentialityProtectionIndication",
        FT_UINT32, BASE_DEC, VALS(xnap_T_confidentialityProtectionIndication_vals), 0,
        NULL, HFILL }},
    { &hf_xnap_e_utra_pci,
      { "e-utra-pci", "xnap.e_utra_pci",
        FT_UINT32, BASE_DEC, NULL, 0,
        "E_UTRAPCI", HFILL }},
    { &hf_xnap_broadcastPLMNs,
      { "broadcastPLMNs", "xnap.broadcastPLMNs",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_SIZE_1_maxnoofBPLMNs_OF_ServedCellInformation_E_UTRA_perBPLMN", HFILL }},
    { &hf_xnap_broadcastPLMNs_item,
      { "ServedCellInformation-E-UTRA-perBPLMN", "xnap.ServedCellInformation_E_UTRA_perBPLMN_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
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
    { &hf_xnap_e_utra_mode_info,
      { "e-utra-mode-info", "xnap.e_utra_mode_info",
        FT_UINT32, BASE_DEC, VALS(xnap_ServedCellInformation_E_UTRA_perBPLMN_ModeInfo_vals), 0,
        "ServedCellInformation_E_UTRA_perBPLMN_ModeInfo", HFILL }},
    { &hf_xnap_fdd_01,
      { "fdd", "xnap.fdd_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "ServedCellInformation_E_UTRA_perBPLMN_FDDInfo", HFILL }},
    { &hf_xnap_tdd_01,
      { "tdd", "xnap.tdd_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "ServedCellInformation_E_UTRA_perBPLMN_TDDInfo", HFILL }},
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
        "SEQUENCE_SIZE_1_maxnoofCellsinNGRANnode_OF_E_UTRA_CGI", HFILL }},
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
    { &hf_xnap_nrPCI,
      { "nrPCI", "xnap.nrPCI",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_xnap_cellID,
      { "cellID", "xnap.cellID_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "NR_CGI", HFILL }},
    { &hf_xnap_ranac,
      { "ranac", "xnap.ranac",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_xnap_broadcastPLMN,
      { "broadcastPLMN", "xnap.broadcastPLMN",
        FT_UINT32, BASE_DEC, NULL, 0,
        "BroadcastPLMNs", HFILL }},
    { &hf_xnap_nrModeInfo,
      { "nrModeInfo", "xnap.nrModeInfo",
        FT_UINT32, BASE_DEC, VALS(xnap_NRModeInfo_vals), 0,
        NULL, HFILL }},
    { &hf_xnap_measurementTimingConfiguration,
      { "measurementTimingConfiguration", "xnap.measurementTimingConfiguration",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
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
        "SEQUENCE_SIZE_1_maxnoofCellsinNGRANnode_OF_NR_CGI", HFILL }},
    { &hf_xnap_served_Cells_ToDelete_NR_item,
      { "NR-CGI", "xnap.NR_CGI_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
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
      { "sulTransmissionBandwidth", "xnap.sulTransmissionBandwidth",
        FT_UINT32, BASE_DEC, NULL, 0,
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
      { "ProtocolIE-Single-Container", "xnap.ProtocolIE_Single_Container_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_xnap_broadcastPLMNs_01,
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
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
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
        FT_UINT32, BASE_DEC, NULL, 0,
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
    { &hf_xnap_pduSessionResourcesToBeSet_List,
      { "pduSessionResourcesToBeSet-List", "xnap.pduSessionResourcesToBeSet_List",
        FT_UINT32, BASE_DEC, NULL, 0,
        "PDUSessionResourcesToBeSetup_List", HFILL }},
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
    { &hf_xnap_i_RNTI,
      { "i-RNTI", "xnap.i_RNTI",
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
    { &hf_xnap_gtpTunnel,
      { "gtpTunnel", "xnap.gtpTunnel_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "GTPtunnelTransportLayerInformation", HFILL }},
    { &hf_xnap_protocolIEs,
      { "protocolIEs", "xnap.protocolIEs",
        FT_UINT32, BASE_DEC, NULL, 0,
        "ProtocolIE_Container", HFILL }},
    { &hf_xnap_ng_c_UE_reference,
      { "ng-c-UE-reference", "xnap.ng_c_UE_reference",
        FT_UINT32, BASE_DEC, NULL, 0,
        "AMF_UE_NGAP_ID", HFILL }},
    { &hf_xnap_cp_TNL_info_source,
      { "cp-TNL-info-source", "xnap.cp_TNL_info_source",
        FT_UINT32, BASE_DEC, VALS(xnap_CPTransportLayerInformation_vals), 0,
        "CPTransportLayerInformation", HFILL }},
    { &hf_xnap_pduSessionResourcesToBeSetup_List,
      { "pduSessionResourcesToBeSetup-List", "xnap.pduSessionResourcesToBeSetup_List",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_xnap_rrc_Context_01,
      { "rrc-Context", "xnap.rrc_Context",
        FT_BYTES, BASE_NONE, NULL, 0,
        "T_rrc_Context_01", HFILL }},
    { &hf_xnap_locationReportingInformation,
      { "locationReportingInformation", "xnap.locationReportingInformation_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_xnap_hlr,
      { "hlr", "xnap.hlr_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "MobilityRestrictionList", HFILL }},
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
    { &hf_xnap_nr_cells,
      { "nr-cells", "xnap.nr_cells",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_SIZE_1_maxnoofCellsinNGRANnode_OF_NR_CGI", HFILL }},
    { &hf_xnap_nr_cells_item,
      { "NR-CGI", "xnap.NR_CGI_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_xnap_e_utra_cells,
      { "e-utra-cells", "xnap.e_utra_cells",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_SIZE_1_maxnoofCellsinNGRANnode_OF_E_UTRA_CGI", HFILL }},
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
      { "e-UTRA", "xnap.e-UTRA",
        FT_BOOLEAN, 8, NULL, 0x80,
        NULL, HFILL }},
    { &hf_xnap_RAT_RestrictionInformation_nR,
      { "nR", "xnap.nR",
        FT_BOOLEAN, 8, NULL, 0x40,
        NULL, HFILL }},
    { &hf_xnap_T_interfaces_to_trace_ng_c,
      { "ng-c", "xnap.ng-c",
        FT_BOOLEAN, 8, NULL, 0x80,
        NULL, HFILL }},
    { &hf_xnap_T_interfaces_to_trace_x_nc,
      { "x-nc", "xnap.x-nc",
        FT_BOOLEAN, 8, NULL, 0x40,
        NULL, HFILL }},
    { &hf_xnap_T_interfaces_to_trace_uu,
      { "uu", "xnap.uu",
        FT_BOOLEAN, 8, NULL, 0x20,
        NULL, HFILL }},
    { &hf_xnap_T_interfaces_to_trace_f1_c,
      { "f1-c", "xnap.f1-c",
        FT_BOOLEAN, 8, NULL, 0x10,
        NULL, HFILL }},
    { &hf_xnap_T_interfaces_to_trace_e1,
      { "e1", "xnap.e1",
        FT_BOOLEAN, 8, NULL, 0x08,
        NULL, HFILL }},
    { &hf_xnap_T_nr_EncyptionAlgorithms_nea1_128,
      { "nea1-128", "xnap.nea1-128",
        FT_BOOLEAN, 8, NULL, 0x40,
        NULL, HFILL }},
    { &hf_xnap_T_nr_EncyptionAlgorithms_nea2_128,
      { "nea2-128", "xnap.nea2-128",
        FT_BOOLEAN, 8, NULL, 0x20,
        NULL, HFILL }},
    { &hf_xnap_T_nr_EncyptionAlgorithms_nea3_128,
      { "nea3-128", "xnap.nea3-128",
        FT_BOOLEAN, 8, NULL, 0x10,
        NULL, HFILL }},
    { &hf_xnap_T_nr_IntegrityProtectionAlgorithms_nia1_128,
      { "nia1-128", "xnap.nia1-128",
        FT_BOOLEAN, 8, NULL, 0x40,
        NULL, HFILL }},
    { &hf_xnap_T_nr_IntegrityProtectionAlgorithms_nia2_128,
      { "nia2-128", "xnap.nia2-128",
        FT_BOOLEAN, 8, NULL, 0x20,
        NULL, HFILL }},
    { &hf_xnap_T_nr_IntegrityProtectionAlgorithms_nia3_128,
      { "nia3-128", "xnap.nia3-128",
        FT_BOOLEAN, 8, NULL, 0x10,
        NULL, HFILL }},
    { &hf_xnap_T_e_utra_EncyptionAlgorithms_eea1_128,
      { "eea1-128", "xnap.eea1-128",
        FT_BOOLEAN, 8, NULL, 0x40,
        NULL, HFILL }},
    { &hf_xnap_T_e_utra_EncyptionAlgorithms_eea2_128,
      { "eea2-128", "xnap.eea2-128",
        FT_BOOLEAN, 8, NULL, 0x20,
        NULL, HFILL }},
    { &hf_xnap_T_e_utra_EncyptionAlgorithms_eea3_128,
      { "eea3-128", "xnap.eea3-128",
        FT_BOOLEAN, 8, NULL, 0x10,
        NULL, HFILL }},
    { &hf_xnap_T_e_utra_IntegrityProtectionAlgorithms_eia1_128,
      { "eia1-128", "xnap.eia1-128",
        FT_BOOLEAN, 8, NULL, 0x40,
        NULL, HFILL }},
    { &hf_xnap_T_e_utra_IntegrityProtectionAlgorithms_eia2_128,
      { "eia2-128", "xnap.eia2-128",
        FT_BOOLEAN, 8, NULL, 0x20,
        NULL, HFILL }},
    { &hf_xnap_T_e_utra_IntegrityProtectionAlgorithms_eia3_128,
      { "eia3-128", "xnap.eia3-128",
        FT_BOOLEAN, 8, NULL, 0x10,
        NULL, HFILL }},

/*--- End of included file: packet-xnap-hfarr.c ---*/
#line 229 "./asn1/xnap/packet-xnap-template.c"
  };

  /* List of subtrees */
  static gint *ett[] = {
    &ett_xnap,
    &ett_xnap_RRC_Context,
    &ett_nxap_container,
    &ett_xnap_PLMN_Identity,
    &ett_xnap_measurementTimingConfiguration,
    &ett_xnap_TransportLayerAddress,
    &ett_xnap_nr_EncyptionAlgorithms,
    &ett_xnap_nr_IntegrityProtectionAlgorithms,
    &ett_xnap_e_utra_EncyptionAlgorithms,
    &ett_xnap_e_utra_IntegrityProtectionAlgorithms,
    &ett_xnap_ng_ran_TraceID,
    &ett_xnap_interfaces_to_trace,

/*--- Included file: packet-xnap-ettarr.c ---*/
#line 1 "./asn1/xnap/packet-xnap-ettarr.c"
    &ett_xnap_PrivateIE_ID,
    &ett_xnap_ProtocolIE_Container,
    &ett_xnap_ProtocolIE_Field,
    &ett_xnap_ProtocolExtensionContainer,
    &ett_xnap_ProtocolExtensionField,
    &ett_xnap_PrivateIE_Container,
    &ett_xnap_PrivateIE_Field,
    &ett_xnap_AllocationandRetentionPriority,
    &ett_xnap_AreaOfInterest,
    &ett_xnap_AreaOfInterest_Item,
    &ett_xnap_AS_SecurityInformation,
    &ett_xnap_AssistanceDataForRANPaging,
    &ett_xnap_BroadcastPLMNs,
    &ett_xnap_BroadcastPLMNinTAISupport_Item,
    &ett_xnap_Cause,
    &ett_xnap_CellAssistanceInfo_NR,
    &ett_xnap_SEQUENCE_SIZE_1_maxnoofCellsinNGRANnode_OF_NR_CGI,
    &ett_xnap_COUNT_PDCP_SN12,
    &ett_xnap_COUNT_PDCP_SN18,
    &ett_xnap_CPTransportLayerInformation,
    &ett_xnap_CriticalityDiagnostics,
    &ett_xnap_CriticalityDiagnostics_IE_List,
    &ett_xnap_CriticalityDiagnostics_IE_List_item,
    &ett_xnap_DataforwardingInfoperPDUSession,
    &ett_xnap_DataforwardingInfoperPDUSession_Item,
    &ett_xnap_DataForwardingInfoFromTargetNGRANnode,
    &ett_xnap_DataForwardingResponseDRBItemList,
    &ett_xnap_DataForwardingResponseDRBItem,
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
    &ett_xnap_GBRQoSFlowInfo,
    &ett_xnap_GlobalgNB_ID,
    &ett_xnap_GNB_ID_Choice,
    &ett_xnap_GlobalngeNB_ID,
    &ett_xnap_ENB_ID_Choice,
    &ett_xnap_GlobalNG_RANNode_ID,
    &ett_xnap_GTPtunnelTransportLayerInformation,
    &ett_xnap_GUAMI,
    &ett_xnap_ListOfCells,
    &ett_xnap_CellsinAoI_Item,
    &ett_xnap_ListOfTAIsinAoI,
    &ett_xnap_TAIsinAoI_Item,
    &ett_xnap_LocationReportingInformation,
    &ett_xnap_MBSFNSubframeAllocation_E_UTRA,
    &ett_xnap_MBSFNSubframeInfo_E_UTRA,
    &ett_xnap_MBSFNSubframeInfo_E_UTRA_Item,
    &ett_xnap_MobilityRestrictionList,
    &ett_xnap_SEQUENCE_SIZE_1_maxnoofEPLMNs_OF_PLMN_Identity,
    &ett_xnap_RAT_RestrictionsList,
    &ett_xnap_RAT_RestrictionsItem,
    &ett_xnap_RAT_RestrictionInformation,
    &ett_xnap_ForbiddenAreaList,
    &ett_xnap_ForbiddenAreaItem,
    &ett_xnap_SEQUENCE_SIZE_1_maxnoofForbiddenTACs_OF_TAC,
    &ett_xnap_ServiceAreaList,
    &ett_xnap_ServiceAreaItem,
    &ett_xnap_SEQUENCE_SIZE_1_maxnoofAllowedAreas_OF_TAC,
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
    &ett_xnap_PDUSessionResourcesAdmitted_List,
    &ett_xnap_PDUSessionResourcesAdmitted_Item,
    &ett_xnap_PDUSessionResourceAdmittedInfo,
    &ett_xnap_PDUSessionResourcesNotAdmitted_List,
    &ett_xnap_PDUSessionResourcesNotAdmitted_Item,
    &ett_xnap_PDUSessionResourcesToBeSetup_List,
    &ett_xnap_PDUSessionResourcesToBeSetup_Item,
    &ett_xnap_QoSCharacteristics,
    &ett_xnap_QoSFlowLevelQoSParameters,
    &ett_xnap_QoSFlows_List,
    &ett_xnap_QoSFlow_Item,
    &ett_xnap_QoSFlowsAdmitted_List,
    &ett_xnap_QoSFlowAdmitted_Item,
    &ett_xnap_QoSFlowsNotAdmitted_List,
    &ett_xnap_QoSFlowNotAdmitted_Item,
    &ett_xnap_QoSFlowsToBeSetup_List,
    &ett_xnap_QoSFlowsToBeSetup_Item,
    &ett_xnap_RANAreaID,
    &ett_xnap_RANAreaID_List,
    &ett_xnap_RANPagingArea,
    &ett_xnap_RANPagingAreaChoice,
    &ett_xnap_RANPagingAttemptInfo,
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
    &ett_xnap_SecurityIndication,
    &ett_xnap_ServedCellInformation_E_UTRA,
    &ett_xnap_SEQUENCE_SIZE_1_maxnoofBPLMNs_OF_ServedCellInformation_E_UTRA_perBPLMN,
    &ett_xnap_ServedCellInformation_E_UTRA_perBPLMN,
    &ett_xnap_ServedCellInformation_E_UTRA_perBPLMN_ModeInfo,
    &ett_xnap_ServedCellInformation_E_UTRA_perBPLMN_FDDInfo,
    &ett_xnap_ServedCellInformation_E_UTRA_perBPLMN_TDDInfo,
    &ett_xnap_ServedCells_E_UTRA,
    &ett_xnap_ServedCells_E_UTRA_Item,
    &ett_xnap_ServedCellsToUpdate_E_UTRA,
    &ett_xnap_SEQUENCE_SIZE_1_maxnoofCellsinNGRANnode_OF_E_UTRA_CGI,
    &ett_xnap_ServedCells_ToModify_E_UTRA,
    &ett_xnap_ServedCells_ToModify_E_UTRA_Item,
    &ett_xnap_ServedCellInformation_NR,
    &ett_xnap_ServedCells_NR,
    &ett_xnap_ServedCells_NR_Item,
    &ett_xnap_ServedCells_ToModify_NR,
    &ett_xnap_ServedCells_ToModify_NR_Item,
    &ett_xnap_ServedCellsToUpdate_NR,
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
    &ett_xnap_TraceActivation,
    &ett_xnap_T_interfaces_to_trace,
    &ett_xnap_UEAggregateMaximumBitRate,
    &ett_xnap_UEContextID,
    &ett_xnap_UEContextIDforRRCResume,
    &ett_xnap_UEContextIDforRRCReestablishment,
    &ett_xnap_UEContextInfoRetrUECtxtResp,
    &ett_xnap_UERANPagingIdentity,
    &ett_xnap_UESecurityCapabilities,
    &ett_xnap_T_nr_EncyptionAlgorithms,
    &ett_xnap_T_nr_IntegrityProtectionAlgorithms,
    &ett_xnap_T_e_utra_EncyptionAlgorithms,
    &ett_xnap_T_e_utra_IntegrityProtectionAlgorithms,
    &ett_xnap_UPTransportLayerInformation,
    &ett_xnap_HandoverRequest,
    &ett_xnap_UEContextInfoHORequest,
    &ett_xnap_HandoverRequestAcknowledge,
    &ett_xnap_HandoverPreparationFailure,
    &ett_xnap_SNStatusTransfer,
    &ett_xnap_UEContextRelease,
    &ett_xnap_HandoverCancel,
    &ett_xnap_RANPaging,
    &ett_xnap_RetrieveUEContextRequest,
    &ett_xnap_RetrieveUEContextResponse,
    &ett_xnap_RetrieveUEContextFailure,
    &ett_xnap_DataForwardingAddressIndication,
    &ett_xnap_SNodeAdditionRequest,
    &ett_xnap_SNodeAdditionRequestAcknowledge,
    &ett_xnap_SNodeAdditionRequestReject,
    &ett_xnap_SNodeReconfigurationComplete,
    &ett_xnap_SNodeModificationRequest,
    &ett_xnap_SNodeModificationRequestAcknowledge,
    &ett_xnap_SNodeModificationRequestReject,
    &ett_xnap_SNodeModificationRequired,
    &ett_xnap_SNodeModificationConfirm,
    &ett_xnap_SNodeModificationRefuse,
    &ett_xnap_SNodeReleaseRequest,
    &ett_xnap_SNodeReleaseRequestAcknowledge,
    &ett_xnap_SNodeReleaseReject,
    &ett_xnap_SNodeReleaseRequired,
    &ett_xnap_SNodeReleaseConfirm,
    &ett_xnap_SNodeCounterCheckRequest,
    &ett_xnap_SNodeChangeRequired,
    &ett_xnap_SNodeChangeConfirm,
    &ett_xnap_SNodeChangeRefuse,
    &ett_xnap_RRCTransfer,
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
#line 246 "./asn1/xnap/packet-xnap-template.c"
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
  dissector_add_uint("xnap.ies", id_AMF_Pool_Information, create_dissector_handle(dissect_AMF_Pool_Information_PDU, proto_xnap));
  dissector_add_uint("xnap.ies", id_AreaOfInterest_Item, create_dissector_handle(dissect_AreaOfInterest_Item_PDU, proto_xnap));
  dissector_add_uint("xnap.ies", id_AssistanceDataForRANPaging, create_dissector_handle(dissect_AssistanceDataForRANPaging_PDU, proto_xnap));
  dissector_add_uint("xnap.ies", id_Cause, create_dissector_handle(dissect_Cause_PDU, proto_xnap));
  dissector_add_uint("xnap.ies", id_cellAssistanceInfo_NR, create_dissector_handle(dissect_CellAssistanceInfo_NR_PDU, proto_xnap));
  dissector_add_uint("xnap.ies", id_ConfigurationUpdateInitiatingNodeChoice, create_dissector_handle(dissect_ConfigurationUpdateInitiatingNodeChoice_PDU, proto_xnap));
  dissector_add_uint("xnap.ies", id_CriticalityDiagnostics, create_dissector_handle(dissect_CriticalityDiagnostics_PDU, proto_xnap));
  dissector_add_uint("xnap.ies", id_dataforwardingInfoperPDUSession, create_dissector_handle(dissect_DataforwardingInfoperPDUSession_PDU, proto_xnap));
  dissector_add_uint("xnap.ies", id_dataforwardingInfoperPDUSession_Item, create_dissector_handle(dissect_DataforwardingInfoperPDUSession_Item_PDU, proto_xnap));
  dissector_add_uint("xnap.ies", id_DataForwardingResponseDRBItem, create_dissector_handle(dissect_DataForwardingResponseDRBItem_PDU, proto_xnap));
  dissector_add_uint("xnap.ies", id_DRBsSubjectToStatusTransfer_Item, create_dissector_handle(dissect_DRBsSubjectToStatusTransfer_Item_PDU, proto_xnap));
  dissector_add_uint("xnap.ies", id_DRBsSubjectToStatusTransfer_List, create_dissector_handle(dissect_DRBsSubjectToStatusTransfer_List_PDU, proto_xnap));
  dissector_add_uint("xnap.ies", id_DRBToQoSFlowMapping_Item, create_dissector_handle(dissect_DRBToQoSFlowMapping_Item_PDU, proto_xnap));
  dissector_add_uint("xnap.ies", id_GlobalNG_RAN_node_ID, create_dissector_handle(dissect_GlobalNG_RANNode_ID_PDU, proto_xnap));
  dissector_add_uint("xnap.ies", id_GUAMI, create_dissector_handle(dissect_GUAMI_PDU, proto_xnap));
  dissector_add_uint("xnap.ies", id_List_of_served_cells_E_UTRA, create_dissector_handle(dissect_ServedCells_E_UTRA_PDU, proto_xnap));
  dissector_add_uint("xnap.ies", id_List_of_served_cells_NR, create_dissector_handle(dissect_ServedCells_NR_PDU, proto_xnap));
  dissector_add_uint("xnap.ies", id_LocationReportingInformation, create_dissector_handle(dissect_LocationReportingInformation_PDU, proto_xnap));
  dissector_add_uint("xnap.ies", id_MAC_I, create_dissector_handle(dissect_MAC_I_PDU, proto_xnap));
  dissector_add_uint("xnap.ies", id_MaskedIMEISV, create_dissector_handle(dissect_MaskedIMEISV_PDU, proto_xnap));
  dissector_add_uint("xnap.ies", id_new_NG_RAN_Cell_Identity, create_dissector_handle(dissect_NG_RAN_Cell_Identity_PDU, proto_xnap));
  dissector_add_uint("xnap.ies", id_newNG_RANnodeUEXnAPID, create_dissector_handle(dissect_NG_RANnodeUEXnAPID_PDU, proto_xnap));
  dissector_add_uint("xnap.ies", id_oldNG_RANnodeUEXnAPID, create_dissector_handle(dissect_NG_RANnodeUEXnAPID_PDU, proto_xnap));
  dissector_add_uint("xnap.ies", id_PagingDRX, create_dissector_handle(dissect_PagingDRX_PDU, proto_xnap));
  dissector_add_uint("xnap.ies", id_PDUSessionResourcesAdmitted_Item, create_dissector_handle(dissect_PDUSessionResourcesAdmitted_Item_PDU, proto_xnap));
  dissector_add_uint("xnap.ies", id_PDUSessionResourcesAdmitted_List, create_dissector_handle(dissect_PDUSessionResourcesAdmitted_List_PDU, proto_xnap));
  dissector_add_uint("xnap.ies", id_PDUSessionResourcesNotAdmitted_Item, create_dissector_handle(dissect_PDUSessionResourcesNotAdmitted_Item_PDU, proto_xnap));
  dissector_add_uint("xnap.ies", id_PDUSessionResourcesNotAdmitted_List, create_dissector_handle(dissect_PDUSessionResourcesNotAdmitted_List_PDU, proto_xnap));
  dissector_add_uint("xnap.ies", id_PDUSessionResourcesToBeSetup_Item, create_dissector_handle(dissect_PDUSessionResourcesToBeSetup_Item_PDU, proto_xnap));
  dissector_add_uint("xnap.ies", id_QoSFlowAdmitted_Item, create_dissector_handle(dissect_QoSFlowAdmitted_Item_PDU, proto_xnap));
  dissector_add_uint("xnap.ies", id_QoSFlow_Item, create_dissector_handle(dissect_QoSFlow_Item_PDU, proto_xnap));
  dissector_add_uint("xnap.ies", id_QoSFlowNotAdmitted_Item, create_dissector_handle(dissect_QoSFlowNotAdmitted_Item_PDU, proto_xnap));
  dissector_add_uint("xnap.ies", id_QoSFlowsToBeSetup_Item, create_dissector_handle(dissect_QoSFlowsToBeSetup_Item_PDU, proto_xnap));
  dissector_add_uint("xnap.ies", id_RANPagingArea, create_dissector_handle(dissect_RANPagingArea_PDU, proto_xnap));
  dissector_add_uint("xnap.ies", id_RANPagingPriority, create_dissector_handle(dissect_RANPagingPriority_PDU, proto_xnap));
  dissector_add_uint("xnap.ies", id_ResetRequestPartialReleaseItem, create_dissector_handle(dissect_ResetRequestPartialReleaseItem_PDU, proto_xnap));
  dissector_add_uint("xnap.ies", id_ResetRequestTypeInfo, create_dissector_handle(dissect_ResetRequestTypeInfo_PDU, proto_xnap));
  dissector_add_uint("xnap.ies", id_ResetResponsePartialReleaseItem, create_dissector_handle(dissect_ResetResponsePartialReleaseItem_PDU, proto_xnap));
  dissector_add_uint("xnap.ies", id_ResetResponseTypeInfo, create_dissector_handle(dissect_ResetResponseTypeInfo_PDU, proto_xnap));
  dissector_add_uint("xnap.ies", id_RespondingNodeTypeConfigUpdateAck, create_dissector_handle(dissect_RespondingNodeTypeConfigUpdateAck_PDU, proto_xnap));
  dissector_add_uint("xnap.ies", id_ServedCellsToActivate, create_dissector_handle(dissect_ServedCellsToActivate_PDU, proto_xnap));
  dissector_add_uint("xnap.ies", id_servedCellsToUpdate_E_UTRA, create_dissector_handle(dissect_ServedCellsToUpdate_E_UTRA_PDU, proto_xnap));
  dissector_add_uint("xnap.ies", id_servedCellsToUpdate_NR, create_dissector_handle(dissect_ServedCellsToUpdate_NR_PDU, proto_xnap));
  dissector_add_uint("xnap.ies", id_sourceNG_RANnodeUEXnAPID, create_dissector_handle(dissect_NG_RANnodeUEXnAPID_PDU, proto_xnap));
  dissector_add_uint("xnap.ies", id_TAISupport_Item, create_dissector_handle(dissect_TAISupport_Item_PDU, proto_xnap));
  dissector_add_uint("xnap.ies", id_TAISupport_list, create_dissector_handle(dissect_TAISupport_List_PDU, proto_xnap));
  dissector_add_uint("xnap.ies", id_Target2SourceNG_RANnodeTranspContainer, create_dissector_handle(dissect_Target2SourceNG_RANnodeTranspContainer_PDU, proto_xnap));
  dissector_add_uint("xnap.ies", id_targetCellGlobalID, create_dissector_handle(dissect_Target_CGI_PDU, proto_xnap));
  dissector_add_uint("xnap.ies", id_targetNG_RANnodeUEXnAPID, create_dissector_handle(dissect_NG_RANnodeUEXnAPID_PDU, proto_xnap));
  dissector_add_uint("xnap.ies", id_TraceActivation, create_dissector_handle(dissect_TraceActivation_PDU, proto_xnap));
  dissector_add_uint("xnap.ies", id_UEContextID, create_dissector_handle(dissect_UEContextID_PDU, proto_xnap));
  dissector_add_uint("xnap.ies", id_UEContextInfoHORequest, create_dissector_handle(dissect_UEContextInfoHORequest_PDU, proto_xnap));
  dissector_add_uint("xnap.ies", id_UEContextInfoRetrUECtxtResp, create_dissector_handle(dissect_UEContextInfoRetrUECtxtResp_PDU, proto_xnap));
  dissector_add_uint("xnap.ies", id_UEIdentityIndexValue, create_dissector_handle(dissect_UEIdentityIndexValue_PDU, proto_xnap));
  dissector_add_uint("xnap.ies", id_UERANPagingIdentity, create_dissector_handle(dissect_UERANPagingIdentity_PDU, proto_xnap));
  dissector_add_uint("xnap.ies", id_XnRemovalThreshold, create_dissector_handle(dissect_XnBenefitValue_PDU, proto_xnap));
  dissector_add_uint("xnap.proc.imsg", id_handoverPreparation, create_dissector_handle(dissect_HandoverRequest_PDU, proto_xnap));
  dissector_add_uint("xnap.proc.sout", id_handoverPreparation, create_dissector_handle(dissect_HandoverRequestAcknowledge_PDU, proto_xnap));
  dissector_add_uint("xnap.proc.uout", id_handoverPreparation, create_dissector_handle(dissect_HandoverPreparationFailure_PDU, proto_xnap));
  dissector_add_uint("xnap.proc.imsg", id_sNStatusTransfer, create_dissector_handle(dissect_SNStatusTransfer_PDU, proto_xnap));
  dissector_add_uint("xnap.proc.imsg", id_handoverCancel, create_dissector_handle(dissect_HandoverCancel_PDU, proto_xnap));
  dissector_add_uint("xnap.proc.imsg", id_retrieveUEContext, create_dissector_handle(dissect_RetrieveUEContextRequest_PDU, proto_xnap));
  dissector_add_uint("xnap.proc.sout", id_retrieveUEContext, create_dissector_handle(dissect_RetrieveUEContextResponse_PDU, proto_xnap));
  dissector_add_uint("xnap.proc.uout", id_retrieveUEContext, create_dissector_handle(dissect_RetrieveUEContextFailure_PDU, proto_xnap));
  dissector_add_uint("xnap.proc.imsg", id_rANPaging, create_dissector_handle(dissect_RANPaging_PDU, proto_xnap));
  dissector_add_uint("xnap.proc.imsg", id_dataForwardingAddressIndication, create_dissector_handle(dissect_DataForwardingAddressIndication_PDU, proto_xnap));
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
  dissector_add_uint("xnap.proc.imsg", id_cellActivation, create_dissector_handle(dissect_CellActivationRequest_PDU, proto_xnap));
  dissector_add_uint("xnap.proc.sout", id_cellActivation, create_dissector_handle(dissect_CellActivationResponse_PDU, proto_xnap));
  dissector_add_uint("xnap.proc.uout", id_cellActivation, create_dissector_handle(dissect_CellActivationFailure_PDU, proto_xnap));
  dissector_add_uint("xnap.proc.imsg", id_reset, create_dissector_handle(dissect_ResetRequest_PDU, proto_xnap));
  dissector_add_uint("xnap.proc.sout", id_reset, create_dissector_handle(dissect_ResetResponse_PDU, proto_xnap));
  dissector_add_uint("xnap.proc.imsg", id_errorIndication, create_dissector_handle(dissect_ErrorIndication_PDU, proto_xnap));
  dissector_add_uint("xnap.proc.imsg", id_privateMessage, create_dissector_handle(dissect_PrivateMessage_PDU, proto_xnap));


/*--- End of included file: packet-xnap-dis-tab.c ---*/
#line 287 "./asn1/xnap/packet-xnap-template.c"
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
