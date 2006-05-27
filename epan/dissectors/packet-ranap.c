/* Do not modify this file.                                                   */
/* It is created automatically by the ASN.1 to Wireshark dissector compiler   */
/* .\packet-ranap.c                                                           */
/* ../../tools/asn2wrs.py -e -p ranap -c ranap.cnf -s packet-ranap-template ranap.asn */

/* Input file: packet-ranap-template.c */

#line 1 "packet-ranap-template.c"
/* packet-ranap-template.c
 * Routines for Radio Access Network Application Part Protocol dissection
 * Copyright 2005 - 2006, Anders Broman <anders.broman@ericsson.com>
 * Based on the dissector by Martin Held <Martin.Held@icn.siemens.de>
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
 * References: 3GPP TS 25.413 version 6.6.0 Release
 */

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <glib.h>
#include <epan/packet.h>
#include <epan/prefs.h>
#include <epan/conversation.h>
#include <epan/tap.h>

#include <stdio.h>
#include <string.h>

#include "packet-ber.h"
#include "packet-per.h"
#include "packet-ranap.h"
#include "packet-e212.h"

#define SCCP_SSN_RANAP 0x8E


#define PNAME  "Radio Access Network Application Part"
#define PSNAME "RANAP"
#define PFNAME "ranap"

#define BYTE_ALIGN_OFFSET(offset)		\
	if(offset&0x07){			\
		offset=(offset&0xfffffff8)+8;	\
	}

/* Higest Ranap_ProcedureCode_value, use in heuristics */
#define RANAP_MAX_PC  42

/* Initialize the protocol and registered fields */
int proto_ranap = -1;
static dissector_table_t nas_pdu_dissector_table;

static int hf_ranap_pdu_length = -1;
static int hf_ranap_IE_length = -1;


/*--- Included file: packet-ranap-hf.c ---*/
#line 1 "packet-ranap-hf.c"
static int hf_ranap_RANAP_PDU_PDU = -1;           /* RANAP_PDU */
static int hf_ranap_initiatingMessage = -1;       /* InitiatingMessage */
static int hf_ranap_successfulOutcome = -1;       /* SuccessfulOutcome */
static int hf_ranap_unsuccessfulOutcome = -1;     /* UnsuccessfulOutcome */
static int hf_ranap_outcome = -1;                 /* Outcome */
static int hf_ranap_procedureCode = -1;           /* ProcedureCode */
static int hf_ranap_criticality = -1;             /* Criticality */
static int hf_ranap_value = -1;                   /* Value */
static int hf_ranap_iu_ReleaseCommand = -1;       /* Iu_ReleaseCommand */
static int hf_ranap_relocationRequired = -1;      /* RelocationRequired */
static int hf_ranap_relocationRequest = -1;       /* RelocationRequest */
static int hf_ranap_relocationCancel = -1;        /* RelocationCancel */
static int hf_ranap_sRNS_ContextRequest = -1;     /* SRNS_ContextRequest */
static int hf_ranap_securityModeCommand = -1;     /* SecurityModeCommand */
static int hf_ranap_dataVolumeReportRequest = -1;  /* DataVolumeReportRequest */
static int hf_ranap_reset = -1;                   /* Reset */
static int hf_ranap_rAB_ReleaseRequest = -1;      /* RAB_ReleaseRequest */
static int hf_ranap_iu_ReleaseRequest = -1;       /* Iu_ReleaseRequest */
static int hf_ranap_relocationDetect = -1;        /* RelocationDetect */
static int hf_ranap_relocationComplete = -1;      /* RelocationComplete */
static int hf_ranap_paging = -1;                  /* Paging */
static int hf_ranap_commonID = -1;                /* CommonID */
static int hf_ranap_cN_InvokeTrace = -1;          /* CN_InvokeTrace */
static int hf_ranap_cN_DeactivateTrace = -1;      /* CN_DeactivateTrace */
static int hf_ranap_locationReportingControl = -1;  /* LocationReportingControl */
static int hf_ranap_locationReport = -1;          /* LocationReport */
static int hf_ranap_initialUE_Message = -1;       /* InitialUE_Message */
static int hf_ranap_directTransfer = -1;          /* DirectTransfer */
static int hf_ranap_overload = -1;                /* Overload */
static int hf_ranap_errorIndication = -1;         /* ErrorIndication */
static int hf_ranap_sRNS_DataForwardCommand = -1;  /* SRNS_DataForwardCommand */
static int hf_ranap_forwardSRNS_Context = -1;     /* ForwardSRNS_Context */
static int hf_ranap_rAB_AssignmentRequest = -1;   /* RAB_AssignmentRequest */
static int hf_ranap_privateMessage = -1;          /* PrivateMessage */
static int hf_ranap_resetResource = -1;           /* ResetResource */
static int hf_ranap_rANAP_RelocationInformation = -1;  /* RANAP_RelocationInformation */
static int hf_ranap_rAB_ModifyRequest = -1;       /* RAB_ModifyRequest */
static int hf_ranap_locationRelatedDataRequest = -1;  /* LocationRelatedDataRequest */
static int hf_ranap_informationTransferIndication = -1;  /* InformationTransferIndication */
static int hf_ranap_uESpecificInformationIndication = -1;  /* UESpecificInformationIndication */
static int hf_ranap_directInformationTransfer = -1;  /* DirectInformationTransfer */
static int hf_ranap_uplinkInformationExchangeRequest = -1;  /* UplinkInformationExchangeRequest */
static int hf_ranap_mBMSSessionStart = -1;        /* MBMSSessionStart */
static int hf_ranap_mBMSSessionUpdate = -1;       /* MBMSSessionUpdate */
static int hf_ranap_mMBMSSessionStop = -1;        /* MBMSSessionStop */
static int hf_ranap_mBMSUELinkingRequest = -1;    /* MBMSUELinkingRequest */
static int hf_ranap_mBMSRegistrationRequest = -1;  /* MBMSRegistrationRequest */
static int hf_ranap_mBMSCNDe_RegistrationRequest = -1;  /* MBMSCNDe_RegistrationRequest */
static int hf_ranap_mBMSRABEstablishmentIndication = -1;  /* MBMSRABEstablishmentIndication */
static int hf_ranap_mBMSRABReleaseRequest = -1;   /* MBMSRABReleaseRequest */
static int hf_ranap_iu_ReleaseComplete = -1;      /* Iu_ReleaseComplete */
static int hf_ranap_relocationCommand = -1;       /* RelocationCommand */
static int hf_ranap_relocationRequestAcknowledge = -1;  /* RelocationRequestAcknowledge */
static int hf_ranap_relocationCancelAcknowledge = -1;  /* RelocationCancelAcknowledge */
static int hf_ranap_sRNS_ContextResponse = -1;    /* SRNS_ContextResponse */
static int hf_ranap_securityModeComplete = -1;    /* SecurityModeComplete */
static int hf_ranap_dataVolumeReport = -1;        /* DataVolumeReport */
static int hf_ranap_resetAcknowledge = -1;        /* ResetAcknowledge */
static int hf_ranap_resetResourceAcknowledge = -1;  /* ResetResourceAcknowledge */
static int hf_ranap_locationRelatedDataResponse = -1;  /* LocationRelatedDataResponse */
static int hf_ranap_informationTransferConfirmation = -1;  /* InformationTransferConfirmation */
static int hf_ranap_uplinkInformationExchangeResponse = -1;  /* UplinkInformationExchangeResponse */
static int hf_ranap_mBMSSessionStartResponse = -1;  /* MBMSSessionStartResponse */
static int hf_ranap_mBMSSessionUpdateResponse = -1;  /* MBMSSessionUpdateResponse */
static int hf_ranap_mBMSSessionStopResponse = -1;  /* MBMSSessionStopResponse */
static int hf_ranap_mBMSRegistrationResponse = -1;  /* MBMSRegistrationResponse */
static int hf_ranap_mBMSCNDeRegistrationResponse = -1;  /* MBMSCNDe_RegistrationResponse */
static int hf_ranap_mBMSRABRelease = -1;          /* MBMSRABRelease */
static int hf_ranap_relocationPreparationFailure = -1;  /* RelocationPreparationFailure */
static int hf_ranap_relocationFailure = -1;       /* RelocationFailure */
static int hf_ranap_securityModeReject = -1;      /* SecurityModeReject */
static int hf_ranap_locationRelatedDataFailure = -1;  /* LocationRelatedDataFailure */
static int hf_ranap_informationTransferFailure = -1;  /* InformationTransferFailure */
static int hf_ranap_uplinkInformationExchangeFailure = -1;  /* UplinkInformationExchangeFailure */
static int hf_ranap_mBMSSessionStartFailure = -1;  /* MBMSSessionStartFailure */
static int hf_ranap_mBMSSessionUpdateFailure = -1;  /* MBMSSessionUpdateFailure */
static int hf_ranap_mBMSRegistrationFailure = -1;  /* MBMSRegistrationFailure */
static int hf_ranap_mBMSRABReleaseFailure = -1;   /* MBMSRABReleaseFailure */
static int hf_ranap_rAB_AssignmentResponse = -1;  /* RAB_AssignmentResponse */
static int hf_ranap_mBMSUELinkingResponse = -1;   /* MBMSUELinkingResponse */
static int hf_ranap_id_AccuracyFulfilmentIndicator = -1;  /* AccuracyFulfilmentIndicator */
static int hf_ranap_id_APN = -1;                  /* APN */
static int hf_ranap_id_AreaIdentity = -1;         /* AreaIdentity */
static int hf_ranap_id_Alt_RAB_Parameters = -1;   /* Alt_RAB_Parameters */
static int hf_ranap_id_Ass_RAB_Parameters = -1;   /* Ass_RAB_Parameters */
static int hf_ranap_id_BroadcastAssistanceDataDecipheringKeys = -1;  /* BroadcastAssistanceDataDecipheringKeys */
static int hf_ranap_id_LocationRelatedDataRequestType = -1;  /* LocationRelatedDataRequestType */
static int hf_ranap_id_CN_DomainIndicator = -1;   /* CN_DomainIndicator */
static int hf_ranap_id_Cause = -1;                /* Cause */
static int hf_ranap_id_ChosenEncryptionAlgorithm = -1;  /* ChosenEncryptionAlgorithm */
static int hf_ranap_id_ChosenIntegrityProtectionAlgorithm = -1;  /* ChosenIntegrityProtectionAlgorithm */
static int hf_ranap_id_ClassmarkInformation2 = -1;  /* ClassmarkInformation2 */
static int hf_ranap_id_ClassmarkInformation3 = -1;  /* ClassmarkInformation3 */
static int hf_ranap_id_ClientType = -1;           /* ClientType */
static int hf_ranap_id_CNMBMSLinkingInformation = -1;  /* CNMBMSLinkingInformation */
static int hf_ranap_id_CriticalityDiagnostics = -1;  /* CriticalityDiagnostics */
static int hf_ranap_id_DeltaRAListofIdleModeUEs = -1;  /* DeltaRAListofIdleModeUEs */
static int hf_ranap_id_DRX_CycleLengthCoefficient = -1;  /* DRX_CycleLengthCoefficient */
static int hf_ranap_id_DirectTransferInformationItem_RANAP_RelocInf = -1;  /* DirectTransferInformationItem_RANAP_RelocInf */
static int hf_ranap_id_DirectTransferInformationList_RANAP_RelocInf = -1;  /* DirectTransferInformationList_RANAP_RelocInf */
static int hf_ranap_id_DL_GTP_PDU_SequenceNumber = -1;  /* DL_GTP_PDU_SequenceNumber */
static int hf_ranap_id_EncryptionInformation = -1;  /* EncryptionInformation */
static int hf_ranap_id_FrequenceLayerConvergenceFlag = -1;  /* FrequenceLayerConvergenceFlag */
static int hf_ranap_id_GERAN_BSC_Container = -1;  /* GERAN_BSC_Container */
static int hf_ranap_id_GERAN_Classmark = -1;      /* GERAN_Classmark */
static int hf_ranap_id_GERAN_Iumode_RAB_Failed_RABAssgntResponse_Item = -1;  /* GERAN_Iumode_RAB_Failed_RABAssgntResponse_Item */
static int hf_ranap_id_GERAN_Iumode_RAB_FailedList_RABAssgntResponse = -1;  /* GERAN_Iumode_RAB_FailedList_RABAssgntResponse */
static int hf_ranap_id_GlobalCN_ID = -1;          /* GlobalCN_ID */
static int hf_ranap_id_GlobalRNC_ID = -1;         /* GlobalRNC_ID */
static int hf_ranap_id_InformationExchangeID = -1;  /* InformationExchangeID */
static int hf_ranap_id_InformationExchangeType = -1;  /* InformationExchangeType */
static int hf_ranap_id_InformationRequested = -1;  /* InformationRequested */
static int hf_ranap_id_InformationRequestType = -1;  /* InformationRequestType */
static int hf_ranap_id_InformationTransferID = -1;  /* InformationTransferID */
static int hf_ranap_id_InformationTransferType = -1;  /* InformationTransferType */
static int hf_ranap_id_TraceRecordingSessionInformation = -1;  /* TraceRecordingSessionInformation */
static int hf_ranap_id_IntegrityProtectionInformation = -1;  /* IntegrityProtectionInformation */
static int hf_ranap_id_InterSystemInformationTransferType = -1;  /* InterSystemInformationTransferType */
static int hf_ranap_id_InterSystemInformation_TransparentContainer = -1;  /* InterSystemInformation_TransparentContainer */
static int hf_ranap_id_IPMulticastAddress = -1;   /* IPMulticastAddress */
static int hf_ranap_id_IuSigConId = -1;           /* IuSignallingConnectionIdentifier */
static int hf_ranap_id_IuSigConIdItem = -1;       /* ResetResourceAckItem */
static int hf_ranap_id_IuSigConIdList = -1;       /* ResetResourceAckList */
static int hf_ranap_id_IuTransportAssociation = -1;  /* IuTransportAssociation */
static int hf_ranap_id_JoinedMBMSBearerServicesList = -1;  /* JoinedMBMSBearerService_IEs */
static int hf_ranap_id_KeyStatus = -1;            /* KeyStatus */
static int hf_ranap_id_L3_Information = -1;       /* L3_Information */
static int hf_ranap_id_LAI = -1;                  /* LAI */
static int hf_ranap_id_LastKnownServiceArea = -1;  /* LastKnownServiceArea */
static int hf_ranap_id_SRB_TrCH_Mapping = -1;     /* SRB_TrCH_Mapping */
static int hf_ranap_id_LeftMBMSBearerServicesList = -1;  /* LeftMBMSBearerService_IEs */
static int hf_ranap_id_LocationRelatedDataRequestTypeSpecificToGERANIuMode = -1;  /* LocationRelatedDataRequestTypeSpecificToGERANIuMode */
static int hf_ranap_id_SignallingIndication = -1;  /* SignallingIndication */
static int hf_ranap_id_hS_DSCH_MAC_d_Flow_ID = -1;  /* HS_DSCH_MAC_d_Flow_ID */
static int hf_ranap_id_CellLoadInformationGroup = -1;  /* CellLoadInformationGroup */
static int hf_ranap_id_MBMSBearerServiceType = -1;  /* MBMSBearerServiceType */
static int hf_ranap_id_MBMSCNDe_Registration = -1;  /* MBMSCNDe_Registration */
static int hf_ranap_id_MBMSRegistrationRequestType = -1;  /* MBMSRegistrationRequestType */
static int hf_ranap_id_MBMSServiceArea = -1;      /* MBMSServiceArea */
static int hf_ranap_id_MBMSSessionDuration = -1;  /* MBMSSessionDuration */
static int hf_ranap_id_MBMSSessionIdentity = -1;  /* MBMSSessionIdentity */
static int hf_ranap_id_MBMSSessionRepetitionNumber = -1;  /* MBMSSessionRepetitionNumber */
static int hf_ranap_id_NAS_PDU = -1;              /* NAS_PDU */
static int hf_ranap_id_NAS_SequenceNumber = -1;   /* NAS_SequenceNumber */
static int hf_ranap_id_NewBSS_To_OldBSS_Information = -1;  /* NewBSS_To_OldBSS_Information */
static int hf_ranap_id_NonSearchingIndication = -1;  /* NonSearchingIndication */
static int hf_ranap_id_NumberOfSteps = -1;        /* NumberOfSteps */
static int hf_ranap_id_OMC_ID = -1;               /* OMC_ID */
static int hf_ranap_id_OldBSS_ToNewBSS_Information = -1;  /* OldBSS_ToNewBSS_Information */
static int hf_ranap_id_PagingAreaID = -1;         /* PagingAreaID */
static int hf_ranap_id_PagingCause = -1;          /* PagingCause */
static int hf_ranap_id_PDP_TypeInformation = -1;  /* PDP_TypeInformation */
static int hf_ranap_id_PermanentNAS_UE_ID = -1;   /* PermanentNAS_UE_ID */
static int hf_ranap_id_PositionData = -1;         /* PositionData */
static int hf_ranap_id_PositionDataSpecificToGERANIuMode = -1;  /* PositionDataSpecificToGERANIuMode */
static int hf_ranap_id_PositioningPriority = -1;  /* PositioningPriority */
static int hf_ranap_id_ProvidedData = -1;         /* ProvidedData */
static int hf_ranap_id_RAB_ContextItem = -1;      /* RAB_ContextItem */
static int hf_ranap_id_RAB_ContextList = -1;      /* RAB_ContextList */
static int hf_ranap_id_RAB_ContextFailedtoTransferItem = -1;  /* RABs_ContextFailedtoTransferItem */
static int hf_ranap_id_RAB_ContextFailedtoTransferList = -1;  /* RAB_ContextFailedtoTransferList */
static int hf_ranap_id_RAB_ContextItem_RANAP_RelocInf = -1;  /* RAB_ContextItem_RANAP_RelocInf */
static int hf_ranap_id_RAB_ContextList_RANAP_RelocInf = -1;  /* RAB_ContextList_RANAP_RelocInf */
static int hf_ranap_id_RAB_DataForwardingItem = -1;  /* RAB_DataForwardingItem */
static int hf_ranap_id_RAB_DataForwardingItem_SRNS_CtxReq = -1;  /* RAB_DataForwardingItem_SRNS_CtxReq */
static int hf_ranap_id_RAB_DataForwardingList = -1;  /* RAB_DataForwardingList */
static int hf_ranap_id_RAB_DataForwardingList_SRNS_CtxReq = -1;  /* RAB_DataForwardingList_SRNS_CtxReq */
static int hf_ranap_id_RAB_DataVolumeReportItem = -1;  /* RAB_DataVolumeReportItem */
static int hf_ranap_id_RAB_DataVolumeReportList = -1;  /* RAB_DataVolumeReportList */
static int hf_ranap_id_RAB_DataVolumeReportRequestItem = -1;  /* RAB_DataVolumeReportRequestItem */
static int hf_ranap_id_RAB_DataVolumeReportRequestList = -1;  /* RAB_DataVolumeReportRequestList */
static int hf_ranap_id_RAB_FailedItem = -1;       /* RAB_FailedItem */
static int hf_ranap_id_RAB_FailedList = -1;       /* RAB_FailedList */
static int hf_ranap_id_RAB_FailedtoReportItem = -1;  /* RABs_failed_to_reportItem */
static int hf_ranap_id_RAB_FailedtoReportList = -1;  /* RAB_FailedtoReportList */
static int hf_ranap_id_RAB_ID = -1;               /* RAB_ID */
static int hf_ranap_id_RAB_ModifyList = -1;       /* RAB_ModifyList */
static int hf_ranap_id_RAB_ModifyItem = -1;       /* RAB_ModifyItem */
static int hf_ranap_id_TypeOfError = -1;          /* TypeOfError */
static int hf_ranap_id_RAB_Parameters = -1;       /* RAB_Parameters */
static int hf_ranap_id_RAB_QueuedItem = -1;       /* RAB_QueuedItem */
static int hf_ranap_id_RAB_QueuedList = -1;       /* RAB_QueuedList */
static int hf_ranap_id_RAB_ReleaseFailedList = -1;  /* RAB_ReleaseFailedList */
static int hf_ranap_id_RAB_ReleaseItem = -1;      /* RAB_ReleaseItem */
static int hf_ranap_id_RAB_ReleasedItem_IuRelComp = -1;  /* RAB_ReleasedItem_IuRelComp */
static int hf_ranap_id_MessageStructure = -1;     /* MessageStructure */
static int hf_ranap_id_RAB_ReleaseList = -1;      /* RAB_ReleaseList */
static int hf_ranap_id_RAB_ReleasedItem = -1;     /* RAB_ReleasedItem */
static int hf_ranap_id_RAB_ReleasedList = -1;     /* RAB_ReleasedList */
static int hf_ranap_id_RAB_ReleasedList_IuRelComp = -1;  /* RAB_ReleasedList_IuRelComp */
static int hf_ranap_id_RAB_RelocationReleaseItem = -1;  /* RAB_RelocationReleaseItem */
static int hf_ranap_id_RAB_RelocationReleaseList = -1;  /* RAB_RelocationReleaseList */
static int hf_ranap_id_RAB_SetupItem_RelocReq = -1;  /* RAB_SetupItem_RelocReq */
static int hf_ranap_id_RAB_SetupItem_RelocReqAck = -1;  /* RAB_SetupItem_RelocReqAck */
static int hf_ranap_id_RAB_SetupList_RelocReq = -1;  /* RAB_SetupList_RelocReq */
static int hf_ranap_id_RAB_SetupList_RelocReqAck = -1;  /* RAB_SetupList_RelocReqAck */
static int hf_ranap_id_RAB_SetupOrModifiedItem = -1;  /* RAB_SetupOrModifiedItem */
static int hf_ranap_id_RAB_SetupOrModifiedList = -1;  /* RAB_SetupOrModifiedList */
static int hf_ranap_id_RAB_SetupOrModifyList = -1;  /* RAB_SetupOrModifyList */
static int hf_ranap_id_RAC = -1;                  /* RAC */
static int hf_ranap_id_RAListofIdleModeUEs = -1;  /* RAListofIdleModeUEs */
static int hf_ranap_id_RedirectionCompleted = -1;  /* RedirectionCompleted */
static int hf_ranap_id_RedirectionIndication = -1;  /* RedirectionIndication */
static int hf_ranap_id_RejectCauseValue = -1;     /* RejectCauseValue */
static int hf_ranap_id_RelocationType = -1;       /* RelocationType */
static int hf_ranap_id_RequestType = -1;          /* RequestType */
static int hf_ranap_id_ResponseTime = -1;         /* ResponseTime */
static int hf_ranap_id_SAI = -1;                  /* SAI */
static int hf_ranap_id_SAPI = -1;                 /* SAPI */
static int hf_ranap_id_SelectedPLMN_ID = -1;      /* PLMNidentity */
static int hf_ranap_id_SessionUpdateID = -1;      /* SessionUpdateID */
static int hf_ranap_id_SNA_Access_Information = -1;  /* SNA_Access_Information */
static int hf_ranap_id_SourceID = -1;             /* SourceID */
static int hf_ranap_id_SourceRNC_ToTargetRNC_TransparentContainer = -1;  /* SourceRNC_ToTargetRNC_TransparentContainer */
static int hf_ranap_id_SourceRNC_PDCP_context_info = -1;  /* RRC_Container */
static int hf_ranap_id_TargetID = -1;             /* TargetID */
static int hf_ranap_id_TargetRNC_ToSourceRNC_TransparentContainer = -1;  /* TargetRNC_ToSourceRNC_TransparentContainer */
static int hf_ranap_id_TemporaryUE_ID = -1;       /* TemporaryUE_ID */
static int hf_ranap_id_TMGI = -1;                 /* TMGI */
static int hf_ranap_id_TracePropagationParameters = -1;  /* TracePropagationParameters */
static int hf_ranap_id_TraceReference = -1;       /* TraceReference */
static int hf_ranap_id_TraceType = -1;            /* TraceType */
static int hf_ranap_id_TransportLayerAddress = -1;  /* TransportLayerAddress */
static int hf_ranap_id_TransportLayerInformation = -1;  /* TransportLayerInformation */
static int hf_ranap_id_TriggerID = -1;            /* TriggerID */
static int hf_ranap_id_UE_ID = -1;                /* UE_ID */
static int hf_ranap_id_UESBI_Iu = -1;             /* UESBI_Iu */
static int hf_ranap_id_UL_GTP_PDU_SequenceNumber = -1;  /* UL_GTP_PDU_SequenceNumber */
static int hf_ranap_id_UnsuccessfulLinkingList = -1;  /* UnsuccessfulLinking_IEs */
static int hf_ranap_id_VerticalAccuracyCode = -1;  /* VerticalAccuracyCode */
static int hf_ranap_id_MBMSLinkingInformation = -1;  /* MBMSLinkingInformation */
static int hf_ranap_id_AlternativeRABConfiguration = -1;  /* RAB_Parameters */
static int hf_ranap_id_AlternativeRABConfigurationRequest = -1;  /* AlternativeRABConfigurationRequest */
static int hf_ranap_id_E_DCH_MAC_d_Flow_ID = -1;  /* E_DCH_MAC_d_Flow_ID */
static int hf_ranap_id_RAB_SetupOrModifyItem1 = -1;  /* RAB_SetupOrModifyItemFirst */
static int hf_ranap_id_RAB_SetupOrModifyItem2 = -1;  /* RAB_SetupOrModifyItemSecond */
static int hf_ranap_protocolIEs = -1;             /* ProtocolIE_Container */
static int hf_ranap_protocolExtensions = -1;      /* ProtocolExtensionContainer */
static int hf_ranap_rAB_ID = -1;                  /* RAB_ID */
static int hf_ranap_rab_dl_UnsuccessfullyTransmittedDataVolume = -1;  /* DataVolumeList */
static int hf_ranap_iE_Extensions = -1;           /* ProtocolExtensionContainer */
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
static int hf_ranap_tMGI = -1;                    /* TMGI */
static int hf_ranap_mBMS_PTP_RAB_ID = -1;         /* MBMS_PTP_RAB_ID */
static int hf_ranap_cause = -1;                   /* Cause */
static int hf_ranap_dl_GTP_PDU_SequenceNumber = -1;  /* DL_GTP_PDU_SequenceNumber */
static int hf_ranap_ul_GTP_PDU_SequenceNumber = -1;  /* UL_GTP_PDU_SequenceNumber */
static int hf_ranap_dl_N_PDU_SequenceNumber = -1;  /* DL_N_PDU_SequenceNumber */
static int hf_ranap_ul_N_PDU_SequenceNumber = -1;  /* UL_N_PDU_SequenceNumber */
static int hf_ranap_iuSigConId = -1;              /* IuSignallingConnectionIdentifier */
static int hf_ranap_transportLayerInformation = -1;  /* TransportLayerInformation */
static int hf_ranap_dl_dataVolumes = -1;          /* DataVolumeList */
static int hf_ranap_DataVolumeList_item = -1;     /* DataVolumeList_item */
static int hf_ranap_dl_UnsuccessfullyTransmittedDataVolume = -1;  /* UnsuccessfullyTransmittedDataVolume */
static int hf_ranap_dataVolumeReference = -1;     /* DataVolumeReference */
static int hf_ranap_gERAN_Classmark = -1;         /* GERAN_Classmark */
static int hf_ranap_privateIEs = -1;              /* PrivateIE_Container */
static int hf_ranap_nAS_PDU = -1;                 /* NAS_PDU */
static int hf_ranap_sAPI = -1;                    /* SAPI */
static int hf_ranap_cN_DomainIndicator = -1;      /* CN_DomainIndicator */
static int hf_ranap_requested_RAB_Parameter_Values = -1;  /* Requested_RAB_Parameter_Values */
static int hf_ranap_LeftMBMSBearerService_IEs_item = -1;  /* LeftMBMSBearerService_IEs_item */
static int hf_ranap_UnsuccessfulLinking_IEs_item = -1;  /* UnsuccessfulLinking_IEs_item */
static int hf_ranap_priorityLevel = -1;           /* PriorityLevel */
static int hf_ranap_pre_emptionCapability = -1;   /* Pre_emptionCapability */
static int hf_ranap_pre_emptionVulnerability = -1;  /* Pre_emptionVulnerability */
static int hf_ranap_queuingAllowed = -1;          /* QueuingAllowed */
static int hf_ranap_altMaxBitrateInf = -1;        /* Alt_RAB_Parameter_MaxBitrateInf */
static int hf_ranap_altGuaranteedBitRateInf = -1;  /* Alt_RAB_Parameter_GuaranteedBitrateInf */
static int hf_ranap_altGuaranteedBitrateType = -1;  /* Alt_RAB_Parameter_GuaranteedBitrateType */
static int hf_ranap_altGuaranteedBitrates = -1;   /* Alt_RAB_Parameter_GuaranteedBitrates */
static int hf_ranap_Alt_RAB_Parameter_GuaranteedBitrates_item = -1;  /* Alt_RAB_Parameter_GuaranteedBitrateList */
static int hf_ranap_Alt_RAB_Parameter_GuaranteedBitrateList_item = -1;  /* GuaranteedBitrate */
static int hf_ranap_altMaxBitrateType = -1;       /* Alt_RAB_Parameter_MaxBitrateType */
static int hf_ranap_altMaxBitrates = -1;          /* Alt_RAB_Parameter_MaxBitrates */
static int hf_ranap_Alt_RAB_Parameter_MaxBitrates_item = -1;  /* Alt_RAB_Parameter_MaxBitrateList */
static int hf_ranap_Alt_RAB_Parameter_MaxBitrateList_item = -1;  /* MaxBitrate */
static int hf_ranap_sAI = -1;                     /* SAI */
static int hf_ranap_geographicalArea = -1;        /* GeographicalArea */
static int hf_ranap_assMaxBitrateInf = -1;        /* Ass_RAB_Parameter_MaxBitrateList */
static int hf_ranap_assGuaranteedBitRateInf = -1;  /* Ass_RAB_Parameter_GuaranteedBitrateList */
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
static int hf_ranap_cell_Capacity_Class_Value = -1;  /* Cell_Capacity_Class_Value */
static int hf_ranap_loadValue = -1;               /* LoadValue */
static int hf_ranap_rTLoadValue = -1;             /* RTLoadValue */
static int hf_ranap_nRTLoadInformationValue = -1;  /* NRTLoadInformationValue */
static int hf_ranap_sourceCellID = -1;            /* SourceCellID */
static int hf_ranap_uplinkCellLoadInformation = -1;  /* CellLoadInformation */
static int hf_ranap_downlinkCellLoadInformation = -1;  /* CellLoadInformation */
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
static int hf_ranap_newRAListofIdleModeUEs = -1;  /* NewRAListofIdleModeUEs */
static int hf_ranap_rAListwithNoIdleModeUEsAnyMore = -1;  /* RAListwithNoIdleModeUEsAnyMore */
static int hf_ranap_NewRAListofIdleModeUEs_item = -1;  /* RAC */
static int hf_ranap_RAListwithNoIdleModeUEsAnyMore_item = -1;  /* RAC */
static int hf_ranap_encryptionpermittedAlgorithms = -1;  /* PermittedEncryptionAlgorithms */
static int hf_ranap_encryptionkey = -1;           /* EncryptionKey */
static int hf_ranap_iMEIlist = -1;                /* IMEIList */
static int hf_ranap_iMEISVlist = -1;              /* IMEISVList */
static int hf_ranap_iMEIgroup = -1;               /* IMEIGroup */
static int hf_ranap_iMEISVgroup = -1;             /* IMEISVGroup */
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
static int hf_ranap_requestedMBMSIPMulticastAddressandAPNRequest = -1;  /* RequestedMBMSIPMulticastAddressandAPNRequest */
static int hf_ranap_requestedMulticastServiceList = -1;  /* RequestedMulticastServiceList */
static int hf_ranap_mBMSIPMulticastAddressandAPNRequest = -1;  /* MBMSIPMulticastAddressandAPNRequest */
static int hf_ranap_permanentNAS_UE_ID = -1;      /* PermanentNAS_UE_ID */
static int hf_ranap_rNCTraceInformation = -1;     /* RNCTraceInformation */
static int hf_ranap_permittedAlgorithms = -1;     /* PermittedIntegrityProtectionAlgorithms */
static int hf_ranap_key = -1;                     /* IntegrityProtectionKey */
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
static int hf_ranap_MBMSIPMulticastAddressandAPNRequest_item = -1;  /* TMGI */
static int hf_ranap_mBMSServiceAreaList = -1;     /* MBMSServiceAreaList */
static int hf_ranap_MBMSServiceAreaList_item = -1;  /* MBMSServiceAreaCode */
static int hf_ranap_rAI = -1;                     /* RAI */
static int hf_ranap_PDP_TypeInformation_item = -1;  /* PDP_Type */
static int hf_ranap_iMSI = -1;                    /* IMSI */
static int hf_ranap_PermittedEncryptionAlgorithms_item = -1;  /* EncryptionAlgorithm */
static int hf_ranap_PermittedIntegrityProtectionAlgorithms_item = -1;  /* IntegrityProtectionAlgorithm */
static int hf_ranap_PLMNs_in_shared_network_item = -1;  /* PLMNs_in_shared_network_item */
static int hf_ranap_lA_LIST = -1;                 /* LA_LIST */
static int hf_ranap_PositioningDataSet_item = -1;  /* PositioningMethodAndUsage */
static int hf_ranap_positioningDataDiscriminator = -1;  /* PositioningDataDiscriminator */
static int hf_ranap_positioningDataSet = -1;      /* PositioningDataSet */
static int hf_ranap_shared_network_information = -1;  /* Shared_Network_Information */
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
static int hf_ranap_RAB_TrCH_Mapping_item = -1;   /* RAB_TrCH_MappingItem */
static int hf_ranap_trCH_ID_List = -1;            /* TrCH_ID_List */
static int hf_ranap_notEmptyRAListofIdleModeUEs = -1;  /* NotEmptyRAListofIdleModeUEs */
static int hf_ranap_emptyFullRAListofIdleModeUEs = -1;  /* T_emptyFullRAListofIdleModeUEs */
static int hf_ranap_rAofIdleModeUEs = -1;         /* RAofIdleModeUEs */
static int hf_ranap_RAofIdleModeUEs_item = -1;    /* RAC */
static int hf_ranap_RequestedMBMSIPMulticastAddressandAPNRequest_item = -1;  /* MBMSIPMulticastAddressandAPNlist */
static int hf_ranap_iPMulticastAddress = -1;      /* IPMulticastAddress */
static int hf_ranap_aPN = -1;                     /* APN */
static int hf_ranap_RequestedMulticastServiceList_item = -1;  /* TMGI */
static int hf_ranap_requestedMaxBitrates = -1;    /* Requested_RAB_Parameter_MaxBitrateList */
static int hf_ranap_requestedGuaranteedBitrates = -1;  /* Requested_RAB_Parameter_GuaranteedBitrateList */
static int hf_ranap_Requested_RAB_Parameter_MaxBitrateList_item = -1;  /* MaxBitrate */
static int hf_ranap_Requested_RAB_Parameter_GuaranteedBitrateList_item = -1;  /* GuaranteedBitrate */
static int hf_ranap_event = -1;                   /* Event */
static int hf_ranap_reportArea = -1;              /* ReportArea */
static int hf_ranap_accuracyCode = -1;            /* INTEGER_0_127 */
static int hf_ranap_mantissa = -1;                /* INTEGER_1_9 */
static int hf_ranap_exponent = -1;                /* INTEGER_1_8 */
static int hf_ranap_rIMInformation = -1;          /* RIMInformation */
static int hf_ranap_rIMRoutingAddress = -1;       /* RIMRoutingAddress */
static int hf_ranap_globalRNC_ID = -1;            /* GlobalRNC_ID */
static int hf_ranap_gERAN_Cell_ID = -1;           /* GERAN_Cell_ID */
static int hf_ranap_traceReference = -1;          /* TraceReference */
static int hf_ranap_traceActivationIndicator = -1;  /* T_traceActivationIndicator */
static int hf_ranap_equipmentsToBeTraced = -1;    /* EquipmentsToBeTraced */
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
static int hf_ranap_uTRANcellID = -1;             /* TargetCellId */
static int hf_ranap_SRB_TrCH_Mapping_item = -1;   /* SRB_TrCH_MappingItem */
static int hf_ranap_sRB_ID = -1;                  /* SRB_ID */
static int hf_ranap_trCH_ID = -1;                 /* TrCH_ID */
static int hf_ranap_targetRNC_ID = -1;            /* TargetRNC_ID */
static int hf_ranap_cGI = -1;                     /* CGI */
static int hf_ranap_tMSI = -1;                    /* TMSI */
static int hf_ranap_p_TMSI = -1;                  /* P_TMSI */
static int hf_ranap_serviceID = -1;               /* OCTET_STRING_SIZE_3 */
static int hf_ranap_traceRecordingSessionReference = -1;  /* TraceRecordingSessionReference */
static int hf_ranap_traceDepth = -1;              /* TraceDepth */
static int hf_ranap_listOfInterfacesToTrace = -1;  /* ListOfInterfacesToTrace */
static int hf_ranap_dCH_ID = -1;                  /* DCH_ID */
static int hf_ranap_dSCH_ID = -1;                 /* DSCH_ID */
static int hf_ranap_uSCH_ID = -1;                 /* USCH_ID */
static int hf_ranap_TrCH_ID_List_item = -1;       /* TrCH_ID */
static int hf_ranap_imsi = -1;                    /* IMSI */
static int hf_ranap_imei = -1;                    /* IMEI */
static int hf_ranap_imeisv = -1;                  /* IMEISV */
static int hf_ranap_uESBI_IuA = -1;               /* UESBI_IuA */
static int hf_ranap_uESBI_IuB = -1;               /* UESBI_IuB */
static int hf_ranap_local = -1;                   /* INTEGER_0_65535 */
static int hf_ranap_global = -1;                  /* OBJECT_IDENTIFIER */
static int hf_ranap_ProtocolIE_Container_item = -1;  /* ProtocolIE_Field */
static int hf_ranap_id = -1;                      /* ProtocolIE_ID */
static int hf_ranap_ie_field_value = -1;          /* RANAP_PROTOCOL_IES_Value */
static int hf_ranap_ProtocolIE_ContainerPair_item = -1;  /* ProtocolIE_FieldPair */
static int hf_ranap_firstCriticality = -1;        /* Criticality */
static int hf_ranap_firstValue = -1;              /* FirstValue */
static int hf_ranap_secondCriticality = -1;       /* Criticality */
static int hf_ranap_secondValue = -1;             /* SecondValue */
static int hf_ranap_ProtocolIE_ContainerList_item = -1;  /* ProtocolIE_Container */
static int hf_ranap_ProtocolIE_ContainerList15_item = -1;  /* ProtocolIE_Container */
static int hf_ranap_ProtocolIE_ContainerList256_item = -1;  /* ProtocolIE_Container */
static int hf_ranap_ProtocolIE_ContainerList250_item = -1;  /* ProtocolIE_Container */
static int hf_ranap_ProtocolIE_ContainerPairList_item = -1;  /* ProtocolIE_ContainerPair */
static int hf_ranap_ProtocolIE_ContainerPairList256_item = -1;  /* ProtocolIE_ContainerPair */
static int hf_ranap_ProtocolExtensionContainer_item = -1;  /* ProtocolExtensionField */
static int hf_ranap_ext_id = -1;                  /* ProtocolExtensionID */
static int hf_ranap_extensionValue = -1;          /* Extension */
static int hf_ranap_PrivateIE_Container_item = -1;  /* PrivateIE_Field */
static int hf_ranap_private_id = -1;              /* PrivateIE_ID */
static int hf_ranap_private_value = -1;           /* RANAP_PRIVATE_IES_Value */

/*--- End of included file: packet-ranap-hf.c ---*/
#line 67 "packet-ranap-template.c"

/* Initialize the subtree pointers */
static int ett_ranap = -1;
static int ett_ranap_plnmidentity = -1;

/*--- Included file: packet-ranap-ett.c ---*/
#line 1 "packet-ranap-ett.c"
static gint ett_ranap_RANAP_PDU = -1;
static gint ett_ranap_InitiatingMessage = -1;
static gint ett_ranap_SuccessfulOutcome = -1;
static gint ett_ranap_UnsuccessfulOutcome = -1;
static gint ett_ranap_Outcome = -1;
static gint ett_ranap_Dummy_initiating_messages = -1;
static gint ett_ranap_Dummy_SuccessfulOutcome_messages = -1;
static gint ett_ranap_Dummy_UnsuccessfulOutcome_messages = -1;
static gint ett_ranap_Dummy_Outcome_messages = -1;
static gint ett_ranap_Dymmy_ie_ids = -1;
static gint ett_ranap_Dymmy_firstvalue_ie_ids = -1;
static gint ett_ranap_Dymmy_secondvalue_ie_ids = -1;
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
static gint ett_ranap_AllocationOrRetentionPriority = -1;
static gint ett_ranap_Alt_RAB_Parameters = -1;
static gint ett_ranap_Alt_RAB_Parameter_GuaranteedBitrateInf = -1;
static gint ett_ranap_Alt_RAB_Parameter_GuaranteedBitrates = -1;
static gint ett_ranap_Alt_RAB_Parameter_GuaranteedBitrateList = -1;
static gint ett_ranap_Alt_RAB_Parameter_MaxBitrateInf = -1;
static gint ett_ranap_Alt_RAB_Parameter_MaxBitrates = -1;
static gint ett_ranap_Alt_RAB_Parameter_MaxBitrateList = -1;
static gint ett_ranap_AreaIdentity = -1;
static gint ett_ranap_Ass_RAB_Parameters = -1;
static gint ett_ranap_Ass_RAB_Parameter_GuaranteedBitrateList = -1;
static gint ett_ranap_Ass_RAB_Parameter_MaxBitrateList = -1;
static gint ett_ranap_AuthorisedPLMNs = -1;
static gint ett_ranap_AuthorisedPLMNs_item = -1;
static gint ett_ranap_AuthorisedSNAs = -1;
static gint ett_ranap_BroadcastAssistanceDataDecipheringKeys = -1;
static gint ett_ranap_Cause = -1;
static gint ett_ranap_CellLoadInformation = -1;
static gint ett_ranap_CellLoadInformationGroup = -1;
static gint ett_ranap_CriticalityDiagnostics = -1;
static gint ett_ranap_CriticalityDiagnostics_IE_List = -1;
static gint ett_ranap_CriticalityDiagnostics_IE_List_item = -1;
static gint ett_ranap_MessageStructure = -1;
static gint ett_ranap_MessageStructure_item = -1;
static gint ett_ranap_CGI = -1;
static gint ett_ranap_DeltaRAListofIdleModeUEs = -1;
static gint ett_ranap_NewRAListofIdleModeUEs = -1;
static gint ett_ranap_RAListwithNoIdleModeUEsAnyMore = -1;
static gint ett_ranap_EncryptionInformation = -1;
static gint ett_ranap_EquipmentsToBeTraced = -1;
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
static gint ett_ranap_MBMSIPMulticastAddressandAPNRequest = -1;
static gint ett_ranap_MBMSServiceArea = -1;
static gint ett_ranap_MBMSServiceAreaList = -1;
static gint ett_ranap_PagingAreaID = -1;
static gint ett_ranap_PDP_TypeInformation = -1;
static gint ett_ranap_PermanentNAS_UE_ID = -1;
static gint ett_ranap_PermittedEncryptionAlgorithms = -1;
static gint ett_ranap_PermittedIntegrityProtectionAlgorithms = -1;
static gint ett_ranap_PLMNs_in_shared_network = -1;
static gint ett_ranap_PLMNs_in_shared_network_item = -1;
static gint ett_ranap_PositioningDataSet = -1;
static gint ett_ranap_PositionData = -1;
static gint ett_ranap_ProvidedData = -1;
static gint ett_ranap_RAB_Parameter_GuaranteedBitrateList = -1;
static gint ett_ranap_RAB_Parameter_MaxBitrateList = -1;
static gint ett_ranap_RAB_Parameters = -1;
static gint ett_ranap_RAB_TrCH_Mapping = -1;
static gint ett_ranap_RAB_TrCH_MappingItem = -1;
static gint ett_ranap_RAI = -1;
static gint ett_ranap_RAListofIdleModeUEs = -1;
static gint ett_ranap_NotEmptyRAListofIdleModeUEs = -1;
static gint ett_ranap_RAofIdleModeUEs = -1;
static gint ett_ranap_RequestedMBMSIPMulticastAddressandAPNRequest = -1;
static gint ett_ranap_MBMSIPMulticastAddressandAPNlist = -1;
static gint ett_ranap_RequestedMulticastServiceList = -1;
static gint ett_ranap_Requested_RAB_Parameter_Values = -1;
static gint ett_ranap_Requested_RAB_Parameter_MaxBitrateList = -1;
static gint ett_ranap_Requested_RAB_Parameter_GuaranteedBitrateList = -1;
static gint ett_ranap_RequestType = -1;
static gint ett_ranap_ResidualBitErrorRatio = -1;
static gint ett_ranap_RIM_Transfer = -1;
static gint ett_ranap_RIMRoutingAddress = -1;
static gint ett_ranap_RNCTraceInformation = -1;
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
static gint ett_ranap_SourceUTRANCellID = -1;
static gint ett_ranap_SRB_TrCH_Mapping = -1;
static gint ett_ranap_SRB_TrCH_MappingItem = -1;
static gint ett_ranap_TargetID = -1;
static gint ett_ranap_TargetRNC_ID = -1;
static gint ett_ranap_TargetRNC_ToSourceRNC_TransparentContainer = -1;
static gint ett_ranap_TemporaryUE_ID = -1;
static gint ett_ranap_TMGI = -1;
static gint ett_ranap_TracePropagationParameters = -1;
static gint ett_ranap_TraceRecordingSessionInformation = -1;
static gint ett_ranap_TrCH_ID = -1;
static gint ett_ranap_TrCH_ID_List = -1;
static gint ett_ranap_UE_ID = -1;
static gint ett_ranap_UESBI_Iu = -1;
static gint ett_ranap_PrivateIE_ID = -1;
static gint ett_ranap_ProtocolIE_Container = -1;
static gint ett_ranap_ProtocolIE_Field = -1;
static gint ett_ranap_ProtocolIE_ContainerPair = -1;
static gint ett_ranap_ProtocolIE_FieldPair = -1;
static gint ett_ranap_ProtocolIE_ContainerList = -1;
static gint ett_ranap_ProtocolIE_ContainerList15 = -1;
static gint ett_ranap_ProtocolIE_ContainerList256 = -1;
static gint ett_ranap_ProtocolIE_ContainerList250 = -1;
static gint ett_ranap_ProtocolIE_ContainerPairList = -1;
static gint ett_ranap_ProtocolIE_ContainerPairList256 = -1;
static gint ett_ranap_ProtocolExtensionContainer = -1;
static gint ett_ranap_ProtocolExtensionField = -1;
static gint ett_ranap_PrivateIE_Container = -1;
static gint ett_ranap_PrivateIE_Field = -1;

/*--- End of included file: packet-ranap-ett.c ---*/
#line 72 "packet-ranap-template.c"


/* Global variables */
static proto_tree *top_tree;
static guint type_of_message;
static guint32 ProcedureCode;
static guint32 ProtocolIE_ID;

static int dissect_ranap_ies(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree);
static int dissect_ranap_FirstValue_ies(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree);
static int dissect_ranap_SecondValue_ies(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree);
static int dissect_ranap_messages(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree);

/*--- Included file: packet-ranap-fn.c ---*/
#line 1 "packet-ranap-fn.c"
/*--- Fields for imported types ---*/



static const value_string ranap_ProcedureCode_vals[] = {
  {   0, "id-RAB-Assignment" },
  {   1, "id-Iu-Release" },
  {   2, "id-RelocationPreparation" },
  {   3, "id-RelocationResourceAllocation" },
  {   4, "id-RelocationCancel" },
  {   5, "id-SRNS-ContextTransfer" },
  {   6, "id-SecurityModeControl" },
  {   7, "id-DataVolumeReport" },
  {   9, "id-Reset" },
  {  10, "id-RAB-ReleaseRequest" },
  {  11, "id-Iu-ReleaseRequest" },
  {  12, "id-RelocationDetect" },
  {  13, "id-RelocationComplete" },
  {  14, "id-Paging" },
  {  15, "id-CommonID" },
  {  16, "id-CN-InvokeTrace" },
  {  17, "id-LocationReportingControl" },
  {  18, "id-LocationReport" },
  {  19, "id-InitialUE-Message" },
  {  20, "id-DirectTransfer" },
  {  21, "id-OverloadControl" },
  {  22, "id-ErrorIndication" },
  {  23, "id-SRNS-DataForward" },
  {  24, "id-ForwardSRNS-Context" },
  {  25, "id-privateMessage" },
  {  26, "id-CN-DeactivateTrace" },
  {  27, "id-ResetResource" },
  {  28, "id-RANAP-Relocation" },
  {  29, "id-RAB-ModifyRequest" },
  {  30, "id-LocationRelatedData" },
  {  31, "id-InformationTransfer" },
  {  32, "id-UESpecificInformation" },
  {  33, "id-UplinkInformationExchange" },
  {  34, "id-DirectInformationTransfer" },
  {  35, "id-MBMSSessionStart" },
  {  36, "id-MBMSSessionUpdate" },
  {  37, "id-MBMSSessionStop" },
  {  38, "id-MBMSUELinking" },
  {  39, "id-MBMSRegistration" },
  {  40, "id-MBMSCNDe-Registration-Procedure" },
  {  41, "id-MBMSRABEstablishmentIndication" },
  {  42, "id-MBMSRABRelease" },
  { 0, NULL }
};


static int
dissect_ranap_ProcedureCode(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                              0U, 255U, &ProcedureCode, FALSE);

#line 36 "ranap.cnf"
	if (check_col(actx->pinfo->cinfo, COL_INFO))
       col_add_fstr(actx->pinfo->cinfo, COL_INFO, "%s ",
                   val_to_str(ProcedureCode, ranap_ProcedureCode_vals,
                              "unknown message"));

  return offset;
}
static int dissect_procedureCode(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_ranap_ProcedureCode(tvb, offset, actx, tree, hf_ranap_procedureCode);
}


static const value_string ranap_Criticality_vals[] = {
  {   0, "reject" },
  {   1, "ignore" },
  {   2, "notify" },
  { 0, NULL }
};


static int
dissect_ranap_Criticality(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     3, NULL, FALSE, 0, NULL);

  return offset;
}
static int dissect_criticality(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_ranap_Criticality(tvb, offset, actx, tree, hf_ranap_criticality);
}
static int dissect_procedureCriticality(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_ranap_Criticality(tvb, offset, actx, tree, hf_ranap_procedureCriticality);
}
static int dissect_iECriticality(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_ranap_Criticality(tvb, offset, actx, tree, hf_ranap_iECriticality);
}
static int dissect_firstCriticality(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_ranap_Criticality(tvb, offset, actx, tree, hf_ranap_firstCriticality);
}
static int dissect_secondCriticality(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_ranap_Criticality(tvb, offset, actx, tree, hf_ranap_secondCriticality);
}



static int
dissect_ranap_Value(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
#line 49 "ranap.cnf"
	
	offset = dissect_ranap_messages(tvb, offset, actx, tree);



  return offset;
}
static int dissect_value(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_ranap_Value(tvb, offset, actx, tree, hf_ranap_value);
}


static const per_sequence_t InitiatingMessage_sequence[] = {
  { "procedureCode"               , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_procedureCode },
  { "criticality"                 , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_criticality },
  { "value"                       , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_value },
  { NULL, 0, 0, NULL }
};

static int
dissect_ranap_InitiatingMessage(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ranap_InitiatingMessage, InitiatingMessage_sequence);

  return offset;
}
static int dissect_initiatingMessage(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_ranap_InitiatingMessage(tvb, offset, actx, tree, hf_ranap_initiatingMessage);
}


static const per_sequence_t SuccessfulOutcome_sequence[] = {
  { "procedureCode"               , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_procedureCode },
  { "criticality"                 , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_criticality },
  { "value"                       , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_value },
  { NULL, 0, 0, NULL }
};

static int
dissect_ranap_SuccessfulOutcome(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ranap_SuccessfulOutcome, SuccessfulOutcome_sequence);

  return offset;
}
static int dissect_successfulOutcome(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_ranap_SuccessfulOutcome(tvb, offset, actx, tree, hf_ranap_successfulOutcome);
}


static const per_sequence_t UnsuccessfulOutcome_sequence[] = {
  { "procedureCode"               , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_procedureCode },
  { "criticality"                 , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_criticality },
  { "value"                       , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_value },
  { NULL, 0, 0, NULL }
};

static int
dissect_ranap_UnsuccessfulOutcome(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ranap_UnsuccessfulOutcome, UnsuccessfulOutcome_sequence);

  return offset;
}
static int dissect_unsuccessfulOutcome(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_ranap_UnsuccessfulOutcome(tvb, offset, actx, tree, hf_ranap_unsuccessfulOutcome);
}


static const per_sequence_t Outcome_sequence[] = {
  { "procedureCode"               , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_procedureCode },
  { "criticality"                 , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_criticality },
  { "value"                       , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_value },
  { NULL, 0, 0, NULL }
};

static int
dissect_ranap_Outcome(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ranap_Outcome, Outcome_sequence);

  return offset;
}
static int dissect_outcome(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_ranap_Outcome(tvb, offset, actx, tree, hf_ranap_outcome);
}


static const value_string ranap_RANAP_PDU_vals[] = {
  {   0, "initiatingMessage" },
  {   1, "successfulOutcome" },
  {   2, "unsuccessfulOutcome" },
  {   3, "outcome" },
  { 0, NULL }
};

static const per_choice_t RANAP_PDU_choice[] = {
  {   0, "initiatingMessage"           , ASN1_EXTENSION_ROOT    , dissect_initiatingMessage },
  {   1, "successfulOutcome"           , ASN1_EXTENSION_ROOT    , dissect_successfulOutcome },
  {   2, "unsuccessfulOutcome"         , ASN1_EXTENSION_ROOT    , dissect_unsuccessfulOutcome },
  {   3, "outcome"                     , ASN1_EXTENSION_ROOT    , dissect_outcome },
  { 0, NULL, 0, NULL }
};

static int
dissect_ranap_RANAP_PDU(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_ranap_RANAP_PDU, RANAP_PDU_choice,
                                 &type_of_message);

  return offset;
}


static const value_string ranap_ProtocolIE_ID_vals[] = {
  {   0, "id-AreaIdentity" },
  {   3, "id-CN-DomainIndicator" },
  {   4, "id-Cause" },
  {   5, "id-ChosenEncryptionAlgorithm" },
  {   6, "id-ChosenIntegrityProtectionAlgorithm" },
  {   7, "id-ClassmarkInformation2" },
  {   8, "id-ClassmarkInformation3" },
  {   9, "id-CriticalityDiagnostics" },
  {  10, "id-DL-GTP-PDU-SequenceNumber" },
  {  11, "id-EncryptionInformation" },
  {  12, "id-IntegrityProtectionInformation" },
  {  13, "id-IuTransportAssociation" },
  {  14, "id-L3-Information" },
  {  15, "id-LAI" },
  {  16, "id-NAS-PDU" },
  {  17, "id-NonSearchingIndication" },
  {  18, "id-NumberOfSteps" },
  {  19, "id-OMC-ID" },
  {  20, "id-OldBSS-ToNewBSS-Information" },
  {  21, "id-PagingAreaID" },
  {  22, "id-PagingCause" },
  {  23, "id-PermanentNAS-UE-ID" },
  {  24, "id-RAB-ContextItem" },
  {  25, "id-RAB-ContextList" },
  {  26, "id-RAB-DataForwardingItem" },
  {  27, "id-RAB-DataForwardingItem-SRNS-CtxReq" },
  {  28, "id-RAB-DataForwardingList" },
  {  29, "id-RAB-DataForwardingList-SRNS-CtxReq" },
  {  30, "id-RAB-DataVolumeReportItem" },
  {  31, "id-RAB-DataVolumeReportList" },
  {  32, "id-RAB-DataVolumeReportRequestItem" },
  {  33, "id-RAB-DataVolumeReportRequestList" },
  {  34, "id-RAB-FailedItem" },
  {  35, "id-RAB-FailedList" },
  {  36, "id-RAB-ID" },
  {  37, "id-RAB-QueuedItem" },
  {  38, "id-RAB-QueuedList" },
  {  39, "id-RAB-ReleaseFailedList" },
  {  40, "id-RAB-ReleaseItem" },
  {  41, "id-RAB-ReleaseList" },
  {  42, "id-RAB-ReleasedItem" },
  {  43, "id-RAB-ReleasedList" },
  {  44, "id-RAB-ReleasedList-IuRelComp" },
  {  45, "id-RAB-RelocationReleaseItem" },
  {  46, "id-RAB-RelocationReleaseList" },
  {  47, "id-RAB-SetupItem-RelocReq" },
  {  48, "id-RAB-SetupItem-RelocReqAck" },
  {  49, "id-RAB-SetupList-RelocReq" },
  {  50, "id-RAB-SetupList-RelocReqAck" },
  {  51, "id-RAB-SetupOrModifiedItem" },
  {  52, "id-RAB-SetupOrModifiedList" },
  {  53, "id-RAB-SetupOrModifyItem" },
  {  54, "id-RAB-SetupOrModifyList" },
  {  55, "id-RAC" },
  {  56, "id-RelocationType" },
  {  57, "id-RequestType" },
  {  58, "id-SAI" },
  {  59, "id-SAPI" },
  {  60, "id-SourceID" },
  {  61, "id-SourceRNC-ToTargetRNC-TransparentContainer" },
  {  62, "id-TargetID" },
  {  63, "id-TargetRNC-ToSourceRNC-TransparentContainer" },
  {  64, "id-TemporaryUE-ID" },
  {  65, "id-TraceReference" },
  {  66, "id-TraceType" },
  {  67, "id-TransportLayerAddress" },
  {  68, "id-TriggerID" },
  {  69, "id-UE-ID" },
  {  70, "id-UL-GTP-PDU-SequenceNumber" },
  {  71, "id-RAB-FailedtoReportItem" },
  {  72, "id-RAB-FailedtoReportList" },
  {  75, "id-KeyStatus" },
  {  76, "id-DRX-CycleLengthCoefficient" },
  {  77, "id-IuSigConIdList" },
  {  78, "id-IuSigConIdItem" },
  {  79, "id-IuSigConId" },
  {  81, "id-DirectTransferInformationList-RANAP-RelocInf" },
  {  82, "id-RAB-ContextItem-RANAP-RelocInf" },
  {  83, "id-RAB-ContextList-RANAP-RelocInf" },
  {  84, "id-RAB-ContextFailedtoTransferItem" },
  {  85, "id-RAB-ContextFailedtoTransferList" },
  {  86, "id-GlobalRNC-ID" },
  {  87, "id-RAB-ReleasedItem-IuRelComp" },
  {  88, "id-MessageStructure" },
  {  89, "id-Alt-RAB-Parameters" },
  {  90, "id-Ass-RAB-Parameters" },
  {  91, "id-RAB-ModifyList" },
  {  92, "id-RAB-ModifyItem" },
  {  93, "id-TypeOfError" },
  {  94, "id-BroadcastAssistanceDataDecipheringKeys" },
  {  95, "id-LocationRelatedDataRequestType" },
  {  96, "id-GlobalCN-ID" },
  {  97, "id-LastKnownServiceArea" },
  {  98, "id-SRB-TrCH-Mapping" },
  {  99, "id-InterSystemInformation-TransparentContainer" },
  { 100, "id-NewBSS-To-OldBSS-Information" },
  { 103, "id-SourceRNC-PDCP-context-info" },
  { 104, "id-InformationTransferID" },
  { 105, "id-SNA-Access-Information" },
  { 106, "id-ProvidedData" },
  { 107, "id-GERAN-BSC-Container" },
  { 108, "id-GERAN-Classmark" },
  { 109, "id-GERAN-Iumode-RAB-Failed-RABAssgntResponse-Item" },
  { 110, "id-GERAN-Iumode-RAB-FailedList-RABAssgntResponse" },
  { 111, "id-VerticalAccuracyCode" },
  { 112, "id-ResponseTime" },
  { 113, "id-PositioningPriority" },
  { 114, "id-ClientType" },
  { 115, "id-LocationRelatedDataRequestTypeSpecificToGERANIuMode" },
  { 116, "id-SignallingIndication" },
  { 117, "id-hS-DSCH-MAC-d-Flow-ID" },
  { 118, "id-UESBI-Iu" },
  { 119, "id-PositionData" },
  { 120, "id-PositionDataSpecificToGERANIuMode" },
  { 121, "id-CellLoadInformationGroup" },
  { 122, "id-AccuracyFulfilmentIndicator" },
  { 123, "id-InformationTransferType" },
  { 124, "id-TraceRecordingSessionInformation" },
  { 125, "id-TracePropagationParameters" },
  { 126, "id-InterSystemInformationTransferType" },
  { 127, "id-SelectedPLMN-ID" },
  { 128, "id-RedirectionCompleted" },
  { 129, "id-RedirectionIndication" },
  { 130, "id-NAS-SequenceNumber" },
  { 131, "id-RejectCauseValue" },
  { 132, "id-APN" },
  { 133, "id-CNMBMSLinkingInformation" },
  { 134, "id-DeltaRAListofIdleModeUEs" },
  { 135, "id-FrequenceLayerConvergenceFlag" },
  { 136, "id-InformationExchangeID" },
  { 137, "id-InformationExchangeType" },
  { 138, "id-InformationRequested" },
  { 139, "id-InformationRequestType" },
  { 140, "id-IPMulticastAddress" },
  { 141, "id-JoinedMBMSBearerServicesList" },
  { 142, "id-LeftMBMSBearerServicesList" },
  { 143, "id-MBMSBearerServiceType" },
  { 144, "id-MBMSCNDe-Registration" },
  { 145, "id-MBMSServiceArea" },
  { 146, "id-MBMSSessionDuration" },
  { 147, "id-MBMSSessionIdentity" },
  { 148, "id-PDP-TypeInformation" },
  { 149, "id-RAB-Parameters" },
  { 150, "id-RAListofIdleModeUEs" },
  { 151, "id-MBMSRegistrationRequestType" },
  { 152, "id-SessionUpdateID" },
  { 153, "id-TMGI" },
  { 154, "id-TransportLayerInformation" },
  { 155, "id-UnsuccessfulLinkingList" },
  { 156, "id-MBMSLinkingInformation" },
  { 157, "id-MBMSSessionRepetitionNumber" },
  { 158, "id-AlternativeRABConfiguration" },
  { 159, "id-AlternativeRABConfigurationRequest" },
  { 160, "id-E-DCH-MAC-d-Flow-ID" },
  { 0, NULL }
};


static int
dissect_ranap_ProtocolIE_ID(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                              0U, 65535U, &ProtocolIE_ID, FALSE);

  return offset;
}
static int dissect_iE_ID(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_ranap_ProtocolIE_ID(tvb, offset, actx, tree, hf_ranap_iE_ID);
}
static int dissect_id(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_ranap_ProtocolIE_ID(tvb, offset, actx, tree, hf_ranap_id);
}



static int
dissect_ranap_RANAP_PROTOCOL_IES_Value(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
#line 53 "ranap.cnf"

	offset = dissect_ranap_ies(tvb, offset, actx, tree);



  return offset;
}
static int dissect_ie_field_value(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_ranap_RANAP_PROTOCOL_IES_Value(tvb, offset, actx, tree, hf_ranap_ie_field_value);
}


static const per_sequence_t ProtocolIE_Field_sequence[] = {
  { "id"                          , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_id },
  { "criticality"                 , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_criticality },
  { "value"                       , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ie_field_value },
  { NULL, 0, 0, NULL }
};

static int
dissect_ranap_ProtocolIE_Field(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ranap_ProtocolIE_Field, ProtocolIE_Field_sequence);

  return offset;
}
static int dissect_ProtocolIE_Container_item(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_ranap_ProtocolIE_Field(tvb, offset, actx, tree, hf_ranap_ProtocolIE_Container_item);
}


static const per_sequence_t ProtocolIE_Container_sequence_of[1] = {
  { ""                            , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ProtocolIE_Container_item },
};

static int
dissect_ranap_ProtocolIE_Container(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_ranap_ProtocolIE_Container, ProtocolIE_Container_sequence_of,
                                                  0, 65535);

  return offset;
}
static int dissect_protocolIEs(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_ranap_ProtocolIE_Container(tvb, offset, actx, tree, hf_ranap_protocolIEs);
}
static int dissect_ProtocolIE_ContainerList_item(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_ranap_ProtocolIE_Container(tvb, offset, actx, tree, hf_ranap_ProtocolIE_ContainerList_item);
}
static int dissect_ProtocolIE_ContainerList15_item(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_ranap_ProtocolIE_Container(tvb, offset, actx, tree, hf_ranap_ProtocolIE_ContainerList15_item);
}
static int dissect_ProtocolIE_ContainerList256_item(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_ranap_ProtocolIE_Container(tvb, offset, actx, tree, hf_ranap_ProtocolIE_ContainerList256_item);
}
static int dissect_ProtocolIE_ContainerList250_item(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_ranap_ProtocolIE_Container(tvb, offset, actx, tree, hf_ranap_ProtocolIE_ContainerList250_item);
}



static int
dissect_ranap_ProtocolExtensionID(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                              0U, 65535U, &ProtocolIE_ID, FALSE);

  return offset;
}
static int dissect_ext_id(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_ranap_ProtocolExtensionID(tvb, offset, actx, tree, hf_ranap_ext_id);
}



static int
dissect_ranap_Extension(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
#line 72 "ranap.cnf"

	offset = dissect_ranap_ies(tvb, offset, actx, tree);



  return offset;
}
static int dissect_extensionValue(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_ranap_Extension(tvb, offset, actx, tree, hf_ranap_extensionValue);
}


static const per_sequence_t ProtocolExtensionField_sequence[] = {
  { "id"                          , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ext_id },
  { "criticality"                 , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_criticality },
  { "extensionValue"              , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_extensionValue },
  { NULL, 0, 0, NULL }
};

static int
dissect_ranap_ProtocolExtensionField(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ranap_ProtocolExtensionField, ProtocolExtensionField_sequence);

  return offset;
}
static int dissect_ProtocolExtensionContainer_item(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_ranap_ProtocolExtensionField(tvb, offset, actx, tree, hf_ranap_ProtocolExtensionContainer_item);
}


static const per_sequence_t ProtocolExtensionContainer_sequence_of[1] = {
  { ""                            , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ProtocolExtensionContainer_item },
};

static int
dissect_ranap_ProtocolExtensionContainer(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_ranap_ProtocolExtensionContainer, ProtocolExtensionContainer_sequence_of,
                                                  1, 65535);

  return offset;
}
static int dissect_protocolExtensions(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_ranap_ProtocolExtensionContainer(tvb, offset, actx, tree, hf_ranap_protocolExtensions);
}
static int dissect_iE_Extensions(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_ranap_ProtocolExtensionContainer(tvb, offset, actx, tree, hf_ranap_iE_Extensions);
}


static const per_sequence_t Iu_ReleaseCommand_sequence[] = {
  { "protocolIEs"                 , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_protocolIEs },
  { "protocolExtensions"          , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_protocolExtensions },
  { NULL, 0, 0, NULL }
};

static int
dissect_ranap_Iu_ReleaseCommand(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ranap_Iu_ReleaseCommand, Iu_ReleaseCommand_sequence);

  return offset;
}
static int dissect_iu_ReleaseCommand(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_ranap_Iu_ReleaseCommand(tvb, offset, actx, tree, hf_ranap_iu_ReleaseCommand);
}


static const per_sequence_t RelocationRequired_sequence[] = {
  { "protocolIEs"                 , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_protocolIEs },
  { "protocolExtensions"          , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_protocolExtensions },
  { NULL, 0, 0, NULL }
};

static int
dissect_ranap_RelocationRequired(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ranap_RelocationRequired, RelocationRequired_sequence);

  return offset;
}
static int dissect_relocationRequired(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_ranap_RelocationRequired(tvb, offset, actx, tree, hf_ranap_relocationRequired);
}


static const per_sequence_t RelocationRequest_sequence[] = {
  { "protocolIEs"                 , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_protocolIEs },
  { "protocolExtensions"          , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_protocolExtensions },
  { NULL, 0, 0, NULL }
};

static int
dissect_ranap_RelocationRequest(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ranap_RelocationRequest, RelocationRequest_sequence);

  return offset;
}
static int dissect_relocationRequest(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_ranap_RelocationRequest(tvb, offset, actx, tree, hf_ranap_relocationRequest);
}


static const per_sequence_t RelocationCancel_sequence[] = {
  { "protocolIEs"                 , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_protocolIEs },
  { "protocolExtensions"          , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_protocolExtensions },
  { NULL, 0, 0, NULL }
};

static int
dissect_ranap_RelocationCancel(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ranap_RelocationCancel, RelocationCancel_sequence);

  return offset;
}
static int dissect_relocationCancel(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_ranap_RelocationCancel(tvb, offset, actx, tree, hf_ranap_relocationCancel);
}


static const per_sequence_t SRNS_ContextRequest_sequence[] = {
  { "protocolIEs"                 , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_protocolIEs },
  { "protocolExtensions"          , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_protocolExtensions },
  { NULL, 0, 0, NULL }
};

static int
dissect_ranap_SRNS_ContextRequest(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ranap_SRNS_ContextRequest, SRNS_ContextRequest_sequence);

  return offset;
}
static int dissect_sRNS_ContextRequest(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_ranap_SRNS_ContextRequest(tvb, offset, actx, tree, hf_ranap_sRNS_ContextRequest);
}


static const per_sequence_t SecurityModeCommand_sequence[] = {
  { "protocolIEs"                 , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_protocolIEs },
  { "protocolExtensions"          , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_protocolExtensions },
  { NULL, 0, 0, NULL }
};

static int
dissect_ranap_SecurityModeCommand(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ranap_SecurityModeCommand, SecurityModeCommand_sequence);

  return offset;
}
static int dissect_securityModeCommand(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_ranap_SecurityModeCommand(tvb, offset, actx, tree, hf_ranap_securityModeCommand);
}


static const per_sequence_t DataVolumeReportRequest_sequence[] = {
  { "protocolIEs"                 , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_protocolIEs },
  { "protocolExtensions"          , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_protocolExtensions },
  { NULL, 0, 0, NULL }
};

static int
dissect_ranap_DataVolumeReportRequest(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ranap_DataVolumeReportRequest, DataVolumeReportRequest_sequence);

  return offset;
}
static int dissect_dataVolumeReportRequest(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_ranap_DataVolumeReportRequest(tvb, offset, actx, tree, hf_ranap_dataVolumeReportRequest);
}


static const per_sequence_t Reset_sequence[] = {
  { "protocolIEs"                 , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_protocolIEs },
  { "protocolExtensions"          , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_protocolExtensions },
  { NULL, 0, 0, NULL }
};

static int
dissect_ranap_Reset(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ranap_Reset, Reset_sequence);

  return offset;
}
static int dissect_reset(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_ranap_Reset(tvb, offset, actx, tree, hf_ranap_reset);
}


static const per_sequence_t RAB_ReleaseRequest_sequence[] = {
  { "protocolIEs"                 , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_protocolIEs },
  { "protocolExtensions"          , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_protocolExtensions },
  { NULL, 0, 0, NULL }
};

static int
dissect_ranap_RAB_ReleaseRequest(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ranap_RAB_ReleaseRequest, RAB_ReleaseRequest_sequence);

  return offset;
}
static int dissect_rAB_ReleaseRequest(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_ranap_RAB_ReleaseRequest(tvb, offset, actx, tree, hf_ranap_rAB_ReleaseRequest);
}


static const per_sequence_t Iu_ReleaseRequest_sequence[] = {
  { "protocolIEs"                 , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_protocolIEs },
  { "protocolExtensions"          , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_protocolExtensions },
  { NULL, 0, 0, NULL }
};

static int
dissect_ranap_Iu_ReleaseRequest(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ranap_Iu_ReleaseRequest, Iu_ReleaseRequest_sequence);

  return offset;
}
static int dissect_iu_ReleaseRequest(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_ranap_Iu_ReleaseRequest(tvb, offset, actx, tree, hf_ranap_iu_ReleaseRequest);
}


static const per_sequence_t RelocationDetect_sequence[] = {
  { "protocolIEs"                 , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_protocolIEs },
  { "protocolExtensions"          , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_protocolExtensions },
  { NULL, 0, 0, NULL }
};

static int
dissect_ranap_RelocationDetect(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ranap_RelocationDetect, RelocationDetect_sequence);

  return offset;
}
static int dissect_relocationDetect(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_ranap_RelocationDetect(tvb, offset, actx, tree, hf_ranap_relocationDetect);
}


static const per_sequence_t RelocationComplete_sequence[] = {
  { "protocolIEs"                 , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_protocolIEs },
  { "protocolExtensions"          , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_protocolExtensions },
  { NULL, 0, 0, NULL }
};

static int
dissect_ranap_RelocationComplete(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ranap_RelocationComplete, RelocationComplete_sequence);

  return offset;
}
static int dissect_relocationComplete(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_ranap_RelocationComplete(tvb, offset, actx, tree, hf_ranap_relocationComplete);
}


static const per_sequence_t Paging_sequence[] = {
  { "protocolIEs"                 , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_protocolIEs },
  { "protocolExtensions"          , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_protocolExtensions },
  { NULL, 0, 0, NULL }
};

static int
dissect_ranap_Paging(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ranap_Paging, Paging_sequence);

  return offset;
}
static int dissect_paging(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_ranap_Paging(tvb, offset, actx, tree, hf_ranap_paging);
}


static const per_sequence_t CommonID_sequence[] = {
  { "protocolIEs"                 , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_protocolIEs },
  { "protocolExtensions"          , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_protocolExtensions },
  { NULL, 0, 0, NULL }
};

static int
dissect_ranap_CommonID(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ranap_CommonID, CommonID_sequence);

  return offset;
}
static int dissect_commonID(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_ranap_CommonID(tvb, offset, actx, tree, hf_ranap_commonID);
}


static const per_sequence_t CN_InvokeTrace_sequence[] = {
  { "protocolIEs"                 , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_protocolIEs },
  { "protocolExtensions"          , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_protocolExtensions },
  { NULL, 0, 0, NULL }
};

static int
dissect_ranap_CN_InvokeTrace(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ranap_CN_InvokeTrace, CN_InvokeTrace_sequence);

  return offset;
}
static int dissect_cN_InvokeTrace(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_ranap_CN_InvokeTrace(tvb, offset, actx, tree, hf_ranap_cN_InvokeTrace);
}


static const per_sequence_t CN_DeactivateTrace_sequence[] = {
  { "protocolIEs"                 , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_protocolIEs },
  { "protocolExtensions"          , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_protocolExtensions },
  { NULL, 0, 0, NULL }
};

static int
dissect_ranap_CN_DeactivateTrace(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ranap_CN_DeactivateTrace, CN_DeactivateTrace_sequence);

  return offset;
}
static int dissect_cN_DeactivateTrace(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_ranap_CN_DeactivateTrace(tvb, offset, actx, tree, hf_ranap_cN_DeactivateTrace);
}


static const per_sequence_t LocationReportingControl_sequence[] = {
  { "protocolIEs"                 , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_protocolIEs },
  { "protocolExtensions"          , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_protocolExtensions },
  { NULL, 0, 0, NULL }
};

static int
dissect_ranap_LocationReportingControl(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ranap_LocationReportingControl, LocationReportingControl_sequence);

  return offset;
}
static int dissect_locationReportingControl(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_ranap_LocationReportingControl(tvb, offset, actx, tree, hf_ranap_locationReportingControl);
}


static const per_sequence_t LocationReport_sequence[] = {
  { "protocolIEs"                 , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_protocolIEs },
  { "protocolExtensions"          , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_protocolExtensions },
  { NULL, 0, 0, NULL }
};

static int
dissect_ranap_LocationReport(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ranap_LocationReport, LocationReport_sequence);

  return offset;
}
static int dissect_locationReport(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_ranap_LocationReport(tvb, offset, actx, tree, hf_ranap_locationReport);
}


static const per_sequence_t InitialUE_Message_sequence[] = {
  { "protocolIEs"                 , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_protocolIEs },
  { "protocolExtensions"          , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_protocolExtensions },
  { NULL, 0, 0, NULL }
};

static int
dissect_ranap_InitialUE_Message(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ranap_InitialUE_Message, InitialUE_Message_sequence);

  return offset;
}
static int dissect_initialUE_Message(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_ranap_InitialUE_Message(tvb, offset, actx, tree, hf_ranap_initialUE_Message);
}


static const per_sequence_t DirectTransfer_sequence[] = {
  { "protocolIEs"                 , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_protocolIEs },
  { "protocolExtensions"          , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_protocolExtensions },
  { NULL, 0, 0, NULL }
};

static int
dissect_ranap_DirectTransfer(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ranap_DirectTransfer, DirectTransfer_sequence);

  return offset;
}
static int dissect_directTransfer(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_ranap_DirectTransfer(tvb, offset, actx, tree, hf_ranap_directTransfer);
}


static const per_sequence_t Overload_sequence[] = {
  { "protocolIEs"                 , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_protocolIEs },
  { "protocolExtensions"          , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_protocolExtensions },
  { NULL, 0, 0, NULL }
};

static int
dissect_ranap_Overload(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ranap_Overload, Overload_sequence);

  return offset;
}
static int dissect_overload(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_ranap_Overload(tvb, offset, actx, tree, hf_ranap_overload);
}


static const per_sequence_t ErrorIndication_sequence[] = {
  { "protocolIEs"                 , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_protocolIEs },
  { "protocolExtensions"          , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_protocolExtensions },
  { NULL, 0, 0, NULL }
};

static int
dissect_ranap_ErrorIndication(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ranap_ErrorIndication, ErrorIndication_sequence);

  return offset;
}
static int dissect_errorIndication(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_ranap_ErrorIndication(tvb, offset, actx, tree, hf_ranap_errorIndication);
}


static const per_sequence_t SRNS_DataForwardCommand_sequence[] = {
  { "protocolIEs"                 , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_protocolIEs },
  { "protocolExtensions"          , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_protocolExtensions },
  { NULL, 0, 0, NULL }
};

static int
dissect_ranap_SRNS_DataForwardCommand(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ranap_SRNS_DataForwardCommand, SRNS_DataForwardCommand_sequence);

  return offset;
}
static int dissect_sRNS_DataForwardCommand(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_ranap_SRNS_DataForwardCommand(tvb, offset, actx, tree, hf_ranap_sRNS_DataForwardCommand);
}


static const per_sequence_t ForwardSRNS_Context_sequence[] = {
  { "protocolIEs"                 , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_protocolIEs },
  { "protocolExtensions"          , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_protocolExtensions },
  { NULL, 0, 0, NULL }
};

static int
dissect_ranap_ForwardSRNS_Context(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ranap_ForwardSRNS_Context, ForwardSRNS_Context_sequence);

  return offset;
}
static int dissect_forwardSRNS_Context(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_ranap_ForwardSRNS_Context(tvb, offset, actx, tree, hf_ranap_forwardSRNS_Context);
}


static const per_sequence_t RAB_AssignmentRequest_sequence[] = {
  { "protocolIEs"                 , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_protocolIEs },
  { "protocolExtensions"          , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_protocolExtensions },
  { NULL, 0, 0, NULL }
};

static int
dissect_ranap_RAB_AssignmentRequest(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ranap_RAB_AssignmentRequest, RAB_AssignmentRequest_sequence);

  return offset;
}
static int dissect_rAB_AssignmentRequest(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_ranap_RAB_AssignmentRequest(tvb, offset, actx, tree, hf_ranap_rAB_AssignmentRequest);
}



static int
dissect_ranap_INTEGER_0_65535(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                              0U, 65535U, NULL, FALSE);

  return offset;
}
static int dissect_innerRadius(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_ranap_INTEGER_0_65535(tvb, offset, actx, tree, hf_ranap_innerRadius);
}
static int dissect_local(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_ranap_INTEGER_0_65535(tvb, offset, actx, tree, hf_ranap_local);
}



static int
dissect_ranap_OBJECT_IDENTIFIER(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_object_identifier(tvb, offset, actx, tree, hf_index, NULL);

  return offset;
}
static int dissect_global(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_ranap_OBJECT_IDENTIFIER(tvb, offset, actx, tree, hf_ranap_global);
}


static const value_string ranap_PrivateIE_ID_vals[] = {
  {   0, "local" },
  {   1, "global" },
  { 0, NULL }
};

static const per_choice_t PrivateIE_ID_choice[] = {
  {   0, "local"                       , ASN1_NO_EXTENSIONS     , dissect_local },
  {   1, "global"                      , ASN1_NO_EXTENSIONS     , dissect_global },
  { 0, NULL, 0, NULL }
};

static int
dissect_ranap_PrivateIE_ID(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_ranap_PrivateIE_ID, PrivateIE_ID_choice,
                                 NULL);

  return offset;
}
static int dissect_private_id(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_ranap_PrivateIE_ID(tvb, offset, actx, tree, hf_ranap_private_id);
}



static int
dissect_ranap_RANAP_PRIVATE_IES_Value(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
#line 76 "ranap.cnf"
/* FIX ME */



  return offset;
}
static int dissect_private_value(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_ranap_RANAP_PRIVATE_IES_Value(tvb, offset, actx, tree, hf_ranap_private_value);
}


static const per_sequence_t PrivateIE_Field_sequence[] = {
  { "id"                          , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_private_id },
  { "criticality"                 , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_criticality },
  { "value"                       , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_private_value },
  { NULL, 0, 0, NULL }
};

static int
dissect_ranap_PrivateIE_Field(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ranap_PrivateIE_Field, PrivateIE_Field_sequence);

  return offset;
}
static int dissect_PrivateIE_Container_item(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_ranap_PrivateIE_Field(tvb, offset, actx, tree, hf_ranap_PrivateIE_Container_item);
}


static const per_sequence_t PrivateIE_Container_sequence_of[1] = {
  { ""                            , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_PrivateIE_Container_item },
};

static int
dissect_ranap_PrivateIE_Container(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_ranap_PrivateIE_Container, PrivateIE_Container_sequence_of,
                                                  1, 65535);

  return offset;
}
static int dissect_privateIEs(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_ranap_PrivateIE_Container(tvb, offset, actx, tree, hf_ranap_privateIEs);
}


static const per_sequence_t PrivateMessage_sequence[] = {
  { "privateIEs"                  , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_privateIEs },
  { NULL, 0, 0, NULL }
};

static int
dissect_ranap_PrivateMessage(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ranap_PrivateMessage, PrivateMessage_sequence);

  return offset;
}
static int dissect_privateMessage(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_ranap_PrivateMessage(tvb, offset, actx, tree, hf_ranap_privateMessage);
}


static const per_sequence_t ResetResource_sequence[] = {
  { "protocolIEs"                 , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_protocolIEs },
  { "protocolExtensions"          , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_protocolExtensions },
  { NULL, 0, 0, NULL }
};

static int
dissect_ranap_ResetResource(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ranap_ResetResource, ResetResource_sequence);

  return offset;
}
static int dissect_resetResource(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_ranap_ResetResource(tvb, offset, actx, tree, hf_ranap_resetResource);
}


static const per_sequence_t RANAP_RelocationInformation_sequence[] = {
  { "protocolIEs"                 , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_protocolIEs },
  { "protocolExtensions"          , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_protocolExtensions },
  { NULL, 0, 0, NULL }
};

static int
dissect_ranap_RANAP_RelocationInformation(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ranap_RANAP_RelocationInformation, RANAP_RelocationInformation_sequence);

  return offset;
}
static int dissect_rANAP_RelocationInformation(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_ranap_RANAP_RelocationInformation(tvb, offset, actx, tree, hf_ranap_rANAP_RelocationInformation);
}


static const per_sequence_t RAB_ModifyRequest_sequence[] = {
  { "protocolIEs"                 , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_protocolIEs },
  { "protocolExtensions"          , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_protocolExtensions },
  { NULL, 0, 0, NULL }
};

static int
dissect_ranap_RAB_ModifyRequest(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ranap_RAB_ModifyRequest, RAB_ModifyRequest_sequence);

  return offset;
}
static int dissect_rAB_ModifyRequest(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_ranap_RAB_ModifyRequest(tvb, offset, actx, tree, hf_ranap_rAB_ModifyRequest);
}


static const per_sequence_t LocationRelatedDataRequest_sequence[] = {
  { "protocolIEs"                 , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_protocolIEs },
  { "protocolExtensions"          , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_protocolExtensions },
  { NULL, 0, 0, NULL }
};

static int
dissect_ranap_LocationRelatedDataRequest(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ranap_LocationRelatedDataRequest, LocationRelatedDataRequest_sequence);

  return offset;
}
static int dissect_locationRelatedDataRequest(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_ranap_LocationRelatedDataRequest(tvb, offset, actx, tree, hf_ranap_locationRelatedDataRequest);
}


static const per_sequence_t InformationTransferIndication_sequence[] = {
  { "protocolIEs"                 , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_protocolIEs },
  { "protocolExtensions"          , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_protocolExtensions },
  { NULL, 0, 0, NULL }
};

static int
dissect_ranap_InformationTransferIndication(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ranap_InformationTransferIndication, InformationTransferIndication_sequence);

  return offset;
}
static int dissect_informationTransferIndication(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_ranap_InformationTransferIndication(tvb, offset, actx, tree, hf_ranap_informationTransferIndication);
}


static const per_sequence_t UESpecificInformationIndication_sequence[] = {
  { "protocolIEs"                 , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_protocolIEs },
  { "protocolExtensions"          , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_protocolExtensions },
  { NULL, 0, 0, NULL }
};

static int
dissect_ranap_UESpecificInformationIndication(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ranap_UESpecificInformationIndication, UESpecificInformationIndication_sequence);

  return offset;
}
static int dissect_uESpecificInformationIndication(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_ranap_UESpecificInformationIndication(tvb, offset, actx, tree, hf_ranap_uESpecificInformationIndication);
}


static const per_sequence_t DirectInformationTransfer_sequence[] = {
  { "protocolIEs"                 , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_protocolIEs },
  { "protocolExtensions"          , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_protocolExtensions },
  { NULL, 0, 0, NULL }
};

static int
dissect_ranap_DirectInformationTransfer(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ranap_DirectInformationTransfer, DirectInformationTransfer_sequence);

  return offset;
}
static int dissect_directInformationTransfer(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_ranap_DirectInformationTransfer(tvb, offset, actx, tree, hf_ranap_directInformationTransfer);
}


static const per_sequence_t UplinkInformationExchangeRequest_sequence[] = {
  { "protocolIEs"                 , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_protocolIEs },
  { "protocolExtensions"          , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_protocolExtensions },
  { NULL, 0, 0, NULL }
};

static int
dissect_ranap_UplinkInformationExchangeRequest(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ranap_UplinkInformationExchangeRequest, UplinkInformationExchangeRequest_sequence);

  return offset;
}
static int dissect_uplinkInformationExchangeRequest(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_ranap_UplinkInformationExchangeRequest(tvb, offset, actx, tree, hf_ranap_uplinkInformationExchangeRequest);
}


static const per_sequence_t MBMSSessionStart_sequence[] = {
  { "protocolIEs"                 , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_protocolIEs },
  { "protocolExtensions"          , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_protocolExtensions },
  { NULL, 0, 0, NULL }
};

static int
dissect_ranap_MBMSSessionStart(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ranap_MBMSSessionStart, MBMSSessionStart_sequence);

  return offset;
}
static int dissect_mBMSSessionStart(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_ranap_MBMSSessionStart(tvb, offset, actx, tree, hf_ranap_mBMSSessionStart);
}


static const per_sequence_t MBMSSessionUpdate_sequence[] = {
  { "protocolIEs"                 , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_protocolIEs },
  { "protocolExtensions"          , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_protocolExtensions },
  { NULL, 0, 0, NULL }
};

static int
dissect_ranap_MBMSSessionUpdate(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ranap_MBMSSessionUpdate, MBMSSessionUpdate_sequence);

  return offset;
}
static int dissect_mBMSSessionUpdate(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_ranap_MBMSSessionUpdate(tvb, offset, actx, tree, hf_ranap_mBMSSessionUpdate);
}


static const per_sequence_t MBMSSessionStop_sequence[] = {
  { "protocolIEs"                 , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_protocolIEs },
  { "protocolExtensions"          , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_protocolExtensions },
  { NULL, 0, 0, NULL }
};

static int
dissect_ranap_MBMSSessionStop(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ranap_MBMSSessionStop, MBMSSessionStop_sequence);

  return offset;
}
static int dissect_mMBMSSessionStop(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_ranap_MBMSSessionStop(tvb, offset, actx, tree, hf_ranap_mMBMSSessionStop);
}


static const per_sequence_t MBMSUELinkingRequest_sequence[] = {
  { "protocolIEs"                 , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_protocolIEs },
  { "protocolExtensions"          , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_protocolExtensions },
  { NULL, 0, 0, NULL }
};

static int
dissect_ranap_MBMSUELinkingRequest(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ranap_MBMSUELinkingRequest, MBMSUELinkingRequest_sequence);

  return offset;
}
static int dissect_mBMSUELinkingRequest(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_ranap_MBMSUELinkingRequest(tvb, offset, actx, tree, hf_ranap_mBMSUELinkingRequest);
}


static const per_sequence_t MBMSRegistrationRequest_sequence[] = {
  { "protocolIEs"                 , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_protocolIEs },
  { "protocolExtensions"          , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_protocolExtensions },
  { NULL, 0, 0, NULL }
};

static int
dissect_ranap_MBMSRegistrationRequest(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ranap_MBMSRegistrationRequest, MBMSRegistrationRequest_sequence);

  return offset;
}
static int dissect_mBMSRegistrationRequest(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_ranap_MBMSRegistrationRequest(tvb, offset, actx, tree, hf_ranap_mBMSRegistrationRequest);
}


static const per_sequence_t MBMSCNDe_RegistrationRequest_sequence[] = {
  { "protocolIEs"                 , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_protocolIEs },
  { "protocolExtensions"          , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_protocolExtensions },
  { NULL, 0, 0, NULL }
};

static int
dissect_ranap_MBMSCNDe_RegistrationRequest(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ranap_MBMSCNDe_RegistrationRequest, MBMSCNDe_RegistrationRequest_sequence);

  return offset;
}
static int dissect_mBMSCNDe_RegistrationRequest(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_ranap_MBMSCNDe_RegistrationRequest(tvb, offset, actx, tree, hf_ranap_mBMSCNDe_RegistrationRequest);
}


static const per_sequence_t MBMSRABEstablishmentIndication_sequence[] = {
  { "protocolIEs"                 , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_protocolIEs },
  { "protocolExtensions"          , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_protocolExtensions },
  { NULL, 0, 0, NULL }
};

static int
dissect_ranap_MBMSRABEstablishmentIndication(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ranap_MBMSRABEstablishmentIndication, MBMSRABEstablishmentIndication_sequence);

  return offset;
}
static int dissect_mBMSRABEstablishmentIndication(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_ranap_MBMSRABEstablishmentIndication(tvb, offset, actx, tree, hf_ranap_mBMSRABEstablishmentIndication);
}


static const per_sequence_t MBMSRABReleaseRequest_sequence[] = {
  { "protocolIEs"                 , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_protocolIEs },
  { "protocolExtensions"          , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_protocolExtensions },
  { NULL, 0, 0, NULL }
};

static int
dissect_ranap_MBMSRABReleaseRequest(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ranap_MBMSRABReleaseRequest, MBMSRABReleaseRequest_sequence);

  return offset;
}
static int dissect_mBMSRABReleaseRequest(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_ranap_MBMSRABReleaseRequest(tvb, offset, actx, tree, hf_ranap_mBMSRABReleaseRequest);
}


static const value_string ranap_Dummy_initiating_messages_vals[] = {
  {   0, "iu-ReleaseCommand" },
  {   1, "relocationRequired" },
  {   2, "relocationRequest" },
  {   3, "relocationCancel" },
  {   4, "sRNS-ContextRequest" },
  {   5, "securityModeCommand" },
  {   6, "dataVolumeReportRequest" },
  {   7, "reset" },
  {   8, "rAB-ReleaseRequest" },
  {   9, "iu-ReleaseRequest" },
  {  10, "relocationDetect" },
  {  11, "relocationComplete" },
  {  12, "paging" },
  {  13, "commonID" },
  {  14, "cN-InvokeTrace" },
  {  15, "cN-DeactivateTrace" },
  {  16, "locationReportingControl" },
  {  17, "locationReport" },
  {  18, "initialUE-Message" },
  {  19, "directTransfer" },
  {  20, "overload" },
  {  21, "errorIndication" },
  {  22, "sRNS-DataForwardCommand" },
  {  23, "forwardSRNS-Context" },
  {  24, "rAB-AssignmentRequest" },
  {  25, "privateMessage" },
  {  26, "resetResource" },
  {  27, "rANAP-RelocationInformation" },
  {  28, "rAB-ModifyRequest" },
  {  29, "locationRelatedDataRequest" },
  {  30, "informationTransferIndication" },
  {  31, "uESpecificInformationIndication" },
  {  32, "directInformationTransfer" },
  {  33, "uplinkInformationExchangeRequest" },
  {  34, "mBMSSessionStart" },
  {  35, "mBMSSessionUpdate" },
  {  36, "mMBMSSessionStop" },
  {  37, "mBMSUELinkingRequest" },
  {  38, "mBMSRegistrationRequest" },
  {  39, "mBMSCNDe-RegistrationRequest" },
  {  40, "mBMSRABEstablishmentIndication" },
  {  41, "mBMSRABReleaseRequest" },
  { 0, NULL }
};

static const per_choice_t Dummy_initiating_messages_choice[] = {
  {   0, "iu-ReleaseCommand"           , ASN1_EXTENSION_ROOT    , dissect_iu_ReleaseCommand },
  {   1, "relocationRequired"          , ASN1_EXTENSION_ROOT    , dissect_relocationRequired },
  {   2, "relocationRequest"           , ASN1_EXTENSION_ROOT    , dissect_relocationRequest },
  {   3, "relocationCancel"            , ASN1_EXTENSION_ROOT    , dissect_relocationCancel },
  {   4, "sRNS-ContextRequest"         , ASN1_EXTENSION_ROOT    , dissect_sRNS_ContextRequest },
  {   5, "securityModeCommand"         , ASN1_EXTENSION_ROOT    , dissect_securityModeCommand },
  {   6, "dataVolumeReportRequest"     , ASN1_EXTENSION_ROOT    , dissect_dataVolumeReportRequest },
  {   7, "reset"                       , ASN1_EXTENSION_ROOT    , dissect_reset },
  {   8, "rAB-ReleaseRequest"          , ASN1_EXTENSION_ROOT    , dissect_rAB_ReleaseRequest },
  {   9, "iu-ReleaseRequest"           , ASN1_EXTENSION_ROOT    , dissect_iu_ReleaseRequest },
  {  10, "relocationDetect"            , ASN1_EXTENSION_ROOT    , dissect_relocationDetect },
  {  11, "relocationComplete"          , ASN1_EXTENSION_ROOT    , dissect_relocationComplete },
  {  12, "paging"                      , ASN1_EXTENSION_ROOT    , dissect_paging },
  {  13, "commonID"                    , ASN1_EXTENSION_ROOT    , dissect_commonID },
  {  14, "cN-InvokeTrace"              , ASN1_EXTENSION_ROOT    , dissect_cN_InvokeTrace },
  {  15, "cN-DeactivateTrace"          , ASN1_EXTENSION_ROOT    , dissect_cN_DeactivateTrace },
  {  16, "locationReportingControl"    , ASN1_EXTENSION_ROOT    , dissect_locationReportingControl },
  {  17, "locationReport"              , ASN1_EXTENSION_ROOT    , dissect_locationReport },
  {  18, "initialUE-Message"           , ASN1_EXTENSION_ROOT    , dissect_initialUE_Message },
  {  19, "directTransfer"              , ASN1_EXTENSION_ROOT    , dissect_directTransfer },
  {  20, "overload"                    , ASN1_EXTENSION_ROOT    , dissect_overload },
  {  21, "errorIndication"             , ASN1_EXTENSION_ROOT    , dissect_errorIndication },
  {  22, "sRNS-DataForwardCommand"     , ASN1_EXTENSION_ROOT    , dissect_sRNS_DataForwardCommand },
  {  23, "forwardSRNS-Context"         , ASN1_EXTENSION_ROOT    , dissect_forwardSRNS_Context },
  {  24, "rAB-AssignmentRequest"       , ASN1_EXTENSION_ROOT    , dissect_rAB_AssignmentRequest },
  {  25, "privateMessage"              , ASN1_EXTENSION_ROOT    , dissect_privateMessage },
  {  26, "resetResource"               , ASN1_EXTENSION_ROOT    , dissect_resetResource },
  {  27, "rANAP-RelocationInformation" , ASN1_EXTENSION_ROOT    , dissect_rANAP_RelocationInformation },
  {  28, "rAB-ModifyRequest"           , ASN1_EXTENSION_ROOT    , dissect_rAB_ModifyRequest },
  {  29, "locationRelatedDataRequest"  , ASN1_EXTENSION_ROOT    , dissect_locationRelatedDataRequest },
  {  30, "informationTransferIndication", ASN1_EXTENSION_ROOT    , dissect_informationTransferIndication },
  {  31, "uESpecificInformationIndication", ASN1_EXTENSION_ROOT    , dissect_uESpecificInformationIndication },
  {  32, "directInformationTransfer"   , ASN1_EXTENSION_ROOT    , dissect_directInformationTransfer },
  {  33, "uplinkInformationExchangeRequest", ASN1_EXTENSION_ROOT    , dissect_uplinkInformationExchangeRequest },
  {  34, "mBMSSessionStart"            , ASN1_EXTENSION_ROOT    , dissect_mBMSSessionStart },
  {  35, "mBMSSessionUpdate"           , ASN1_EXTENSION_ROOT    , dissect_mBMSSessionUpdate },
  {  36, "mMBMSSessionStop"            , ASN1_EXTENSION_ROOT    , dissect_mMBMSSessionStop },
  {  37, "mBMSUELinkingRequest"        , ASN1_EXTENSION_ROOT    , dissect_mBMSUELinkingRequest },
  {  38, "mBMSRegistrationRequest"     , ASN1_EXTENSION_ROOT    , dissect_mBMSRegistrationRequest },
  {  39, "mBMSCNDe-RegistrationRequest", ASN1_EXTENSION_ROOT    , dissect_mBMSCNDe_RegistrationRequest },
  {  40, "mBMSRABEstablishmentIndication", ASN1_EXTENSION_ROOT    , dissect_mBMSRABEstablishmentIndication },
  {  41, "mBMSRABReleaseRequest"       , ASN1_EXTENSION_ROOT    , dissect_mBMSRABReleaseRequest },
  { 0, NULL, 0, NULL }
};

static int
dissect_ranap_Dummy_initiating_messages(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_ranap_Dummy_initiating_messages, Dummy_initiating_messages_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t Iu_ReleaseComplete_sequence[] = {
  { "protocolIEs"                 , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_protocolIEs },
  { "protocolExtensions"          , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_protocolExtensions },
  { NULL, 0, 0, NULL }
};

static int
dissect_ranap_Iu_ReleaseComplete(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ranap_Iu_ReleaseComplete, Iu_ReleaseComplete_sequence);

  return offset;
}
static int dissect_iu_ReleaseComplete(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_ranap_Iu_ReleaseComplete(tvb, offset, actx, tree, hf_ranap_iu_ReleaseComplete);
}


static const per_sequence_t RelocationCommand_sequence[] = {
  { "protocolIEs"                 , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_protocolIEs },
  { "protocolExtensions"          , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_protocolExtensions },
  { NULL, 0, 0, NULL }
};

static int
dissect_ranap_RelocationCommand(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ranap_RelocationCommand, RelocationCommand_sequence);

  return offset;
}
static int dissect_relocationCommand(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_ranap_RelocationCommand(tvb, offset, actx, tree, hf_ranap_relocationCommand);
}


static const per_sequence_t RelocationRequestAcknowledge_sequence[] = {
  { "protocolIEs"                 , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_protocolIEs },
  { "protocolExtensions"          , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_protocolExtensions },
  { NULL, 0, 0, NULL }
};

static int
dissect_ranap_RelocationRequestAcknowledge(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ranap_RelocationRequestAcknowledge, RelocationRequestAcknowledge_sequence);

  return offset;
}
static int dissect_relocationRequestAcknowledge(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_ranap_RelocationRequestAcknowledge(tvb, offset, actx, tree, hf_ranap_relocationRequestAcknowledge);
}


static const per_sequence_t RelocationCancelAcknowledge_sequence[] = {
  { "protocolIEs"                 , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_protocolIEs },
  { "protocolExtensions"          , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_protocolExtensions },
  { NULL, 0, 0, NULL }
};

static int
dissect_ranap_RelocationCancelAcknowledge(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ranap_RelocationCancelAcknowledge, RelocationCancelAcknowledge_sequence);

  return offset;
}
static int dissect_relocationCancelAcknowledge(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_ranap_RelocationCancelAcknowledge(tvb, offset, actx, tree, hf_ranap_relocationCancelAcknowledge);
}


static const per_sequence_t SRNS_ContextResponse_sequence[] = {
  { "protocolIEs"                 , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_protocolIEs },
  { "protocolExtensions"          , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_protocolExtensions },
  { NULL, 0, 0, NULL }
};

static int
dissect_ranap_SRNS_ContextResponse(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ranap_SRNS_ContextResponse, SRNS_ContextResponse_sequence);

  return offset;
}
static int dissect_sRNS_ContextResponse(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_ranap_SRNS_ContextResponse(tvb, offset, actx, tree, hf_ranap_sRNS_ContextResponse);
}


static const per_sequence_t SecurityModeComplete_sequence[] = {
  { "protocolIEs"                 , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_protocolIEs },
  { "protocolExtensions"          , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_protocolExtensions },
  { NULL, 0, 0, NULL }
};

static int
dissect_ranap_SecurityModeComplete(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ranap_SecurityModeComplete, SecurityModeComplete_sequence);

  return offset;
}
static int dissect_securityModeComplete(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_ranap_SecurityModeComplete(tvb, offset, actx, tree, hf_ranap_securityModeComplete);
}


static const per_sequence_t DataVolumeReport_sequence[] = {
  { "protocolIEs"                 , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_protocolIEs },
  { "protocolExtensions"          , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_protocolExtensions },
  { NULL, 0, 0, NULL }
};

static int
dissect_ranap_DataVolumeReport(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ranap_DataVolumeReport, DataVolumeReport_sequence);

  return offset;
}
static int dissect_dataVolumeReport(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_ranap_DataVolumeReport(tvb, offset, actx, tree, hf_ranap_dataVolumeReport);
}


static const per_sequence_t ResetAcknowledge_sequence[] = {
  { "protocolIEs"                 , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_protocolIEs },
  { "protocolExtensions"          , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_protocolExtensions },
  { NULL, 0, 0, NULL }
};

static int
dissect_ranap_ResetAcknowledge(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ranap_ResetAcknowledge, ResetAcknowledge_sequence);

  return offset;
}
static int dissect_resetAcknowledge(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_ranap_ResetAcknowledge(tvb, offset, actx, tree, hf_ranap_resetAcknowledge);
}


static const per_sequence_t ResetResourceAcknowledge_sequence[] = {
  { "protocolIEs"                 , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_protocolIEs },
  { "protocolExtensions"          , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_protocolExtensions },
  { NULL, 0, 0, NULL }
};

static int
dissect_ranap_ResetResourceAcknowledge(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ranap_ResetResourceAcknowledge, ResetResourceAcknowledge_sequence);

  return offset;
}
static int dissect_resetResourceAcknowledge(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_ranap_ResetResourceAcknowledge(tvb, offset, actx, tree, hf_ranap_resetResourceAcknowledge);
}


static const per_sequence_t LocationRelatedDataResponse_sequence[] = {
  { "protocolIEs"                 , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_protocolIEs },
  { "protocolExtensions"          , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_protocolExtensions },
  { NULL, 0, 0, NULL }
};

static int
dissect_ranap_LocationRelatedDataResponse(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ranap_LocationRelatedDataResponse, LocationRelatedDataResponse_sequence);

  return offset;
}
static int dissect_locationRelatedDataResponse(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_ranap_LocationRelatedDataResponse(tvb, offset, actx, tree, hf_ranap_locationRelatedDataResponse);
}


static const per_sequence_t InformationTransferConfirmation_sequence[] = {
  { "protocolIEs"                 , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_protocolIEs },
  { "protocolExtensions"          , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_protocolExtensions },
  { NULL, 0, 0, NULL }
};

static int
dissect_ranap_InformationTransferConfirmation(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ranap_InformationTransferConfirmation, InformationTransferConfirmation_sequence);

  return offset;
}
static int dissect_informationTransferConfirmation(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_ranap_InformationTransferConfirmation(tvb, offset, actx, tree, hf_ranap_informationTransferConfirmation);
}


static const per_sequence_t UplinkInformationExchangeResponse_sequence[] = {
  { "protocolIEs"                 , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_protocolIEs },
  { "protocolExtensions"          , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_protocolExtensions },
  { NULL, 0, 0, NULL }
};

static int
dissect_ranap_UplinkInformationExchangeResponse(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ranap_UplinkInformationExchangeResponse, UplinkInformationExchangeResponse_sequence);

  return offset;
}
static int dissect_uplinkInformationExchangeResponse(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_ranap_UplinkInformationExchangeResponse(tvb, offset, actx, tree, hf_ranap_uplinkInformationExchangeResponse);
}


static const per_sequence_t MBMSSessionStartResponse_sequence[] = {
  { "protocolIEs"                 , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_protocolIEs },
  { "protocolExtensions"          , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_protocolExtensions },
  { NULL, 0, 0, NULL }
};

static int
dissect_ranap_MBMSSessionStartResponse(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ranap_MBMSSessionStartResponse, MBMSSessionStartResponse_sequence);

  return offset;
}
static int dissect_mBMSSessionStartResponse(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_ranap_MBMSSessionStartResponse(tvb, offset, actx, tree, hf_ranap_mBMSSessionStartResponse);
}


static const per_sequence_t MBMSSessionUpdateResponse_sequence[] = {
  { "protocolIEs"                 , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_protocolIEs },
  { "protocolExtensions"          , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_protocolExtensions },
  { NULL, 0, 0, NULL }
};

static int
dissect_ranap_MBMSSessionUpdateResponse(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ranap_MBMSSessionUpdateResponse, MBMSSessionUpdateResponse_sequence);

  return offset;
}
static int dissect_mBMSSessionUpdateResponse(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_ranap_MBMSSessionUpdateResponse(tvb, offset, actx, tree, hf_ranap_mBMSSessionUpdateResponse);
}


static const per_sequence_t MBMSSessionStopResponse_sequence[] = {
  { "protocolIEs"                 , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_protocolIEs },
  { "protocolExtensions"          , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_protocolExtensions },
  { NULL, 0, 0, NULL }
};

static int
dissect_ranap_MBMSSessionStopResponse(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ranap_MBMSSessionStopResponse, MBMSSessionStopResponse_sequence);

  return offset;
}
static int dissect_mBMSSessionStopResponse(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_ranap_MBMSSessionStopResponse(tvb, offset, actx, tree, hf_ranap_mBMSSessionStopResponse);
}


static const per_sequence_t MBMSRegistrationResponse_sequence[] = {
  { "protocolIEs"                 , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_protocolIEs },
  { "protocolExtensions"          , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_protocolExtensions },
  { NULL, 0, 0, NULL }
};

static int
dissect_ranap_MBMSRegistrationResponse(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ranap_MBMSRegistrationResponse, MBMSRegistrationResponse_sequence);

  return offset;
}
static int dissect_mBMSRegistrationResponse(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_ranap_MBMSRegistrationResponse(tvb, offset, actx, tree, hf_ranap_mBMSRegistrationResponse);
}


static const per_sequence_t MBMSCNDe_RegistrationResponse_sequence[] = {
  { "protocolIEs"                 , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_protocolIEs },
  { "protocolExtensions"          , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_protocolExtensions },
  { NULL, 0, 0, NULL }
};

static int
dissect_ranap_MBMSCNDe_RegistrationResponse(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ranap_MBMSCNDe_RegistrationResponse, MBMSCNDe_RegistrationResponse_sequence);

  return offset;
}
static int dissect_mBMSCNDeRegistrationResponse(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_ranap_MBMSCNDe_RegistrationResponse(tvb, offset, actx, tree, hf_ranap_mBMSCNDeRegistrationResponse);
}


static const per_sequence_t MBMSRABRelease_sequence[] = {
  { "protocolIEs"                 , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_protocolIEs },
  { "protocolExtensions"          , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_protocolExtensions },
  { NULL, 0, 0, NULL }
};

static int
dissect_ranap_MBMSRABRelease(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ranap_MBMSRABRelease, MBMSRABRelease_sequence);

  return offset;
}
static int dissect_mBMSRABRelease(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_ranap_MBMSRABRelease(tvb, offset, actx, tree, hf_ranap_mBMSRABRelease);
}


static const value_string ranap_Dummy_SuccessfulOutcome_messages_vals[] = {
  {   0, "iu-ReleaseComplete" },
  {   1, "relocationCommand" },
  {   2, "relocationRequestAcknowledge" },
  {   3, "relocationCancelAcknowledge" },
  {   4, "sRNS-ContextResponse" },
  {   5, "securityModeComplete" },
  {   6, "dataVolumeReport" },
  {   7, "resetAcknowledge" },
  {   8, "resetResourceAcknowledge" },
  {   9, "locationRelatedDataResponse" },
  {  10, "informationTransferConfirmation" },
  {  11, "uplinkInformationExchangeResponse" },
  {  12, "mBMSSessionStartResponse" },
  {  13, "mBMSSessionUpdateResponse" },
  {  14, "mBMSSessionStopResponse" },
  {  15, "mBMSRegistrationResponse" },
  {  16, "mBMSCNDeRegistrationResponse" },
  {  17, "mBMSRABRelease" },
  { 0, NULL }
};

static const per_choice_t Dummy_SuccessfulOutcome_messages_choice[] = {
  {   0, "iu-ReleaseComplete"          , ASN1_EXTENSION_ROOT    , dissect_iu_ReleaseComplete },
  {   1, "relocationCommand"           , ASN1_EXTENSION_ROOT    , dissect_relocationCommand },
  {   2, "relocationRequestAcknowledge", ASN1_EXTENSION_ROOT    , dissect_relocationRequestAcknowledge },
  {   3, "relocationCancelAcknowledge" , ASN1_EXTENSION_ROOT    , dissect_relocationCancelAcknowledge },
  {   4, "sRNS-ContextResponse"        , ASN1_EXTENSION_ROOT    , dissect_sRNS_ContextResponse },
  {   5, "securityModeComplete"        , ASN1_EXTENSION_ROOT    , dissect_securityModeComplete },
  {   6, "dataVolumeReport"            , ASN1_EXTENSION_ROOT    , dissect_dataVolumeReport },
  {   7, "resetAcknowledge"            , ASN1_EXTENSION_ROOT    , dissect_resetAcknowledge },
  {   8, "resetResourceAcknowledge"    , ASN1_EXTENSION_ROOT    , dissect_resetResourceAcknowledge },
  {   9, "locationRelatedDataResponse" , ASN1_EXTENSION_ROOT    , dissect_locationRelatedDataResponse },
  {  10, "informationTransferConfirmation", ASN1_EXTENSION_ROOT    , dissect_informationTransferConfirmation },
  {  11, "uplinkInformationExchangeResponse", ASN1_EXTENSION_ROOT    , dissect_uplinkInformationExchangeResponse },
  {  12, "mBMSSessionStartResponse"    , ASN1_EXTENSION_ROOT    , dissect_mBMSSessionStartResponse },
  {  13, "mBMSSessionUpdateResponse"   , ASN1_EXTENSION_ROOT    , dissect_mBMSSessionUpdateResponse },
  {  14, "mBMSSessionStopResponse"     , ASN1_EXTENSION_ROOT    , dissect_mBMSSessionStopResponse },
  {  15, "mBMSRegistrationResponse"    , ASN1_EXTENSION_ROOT    , dissect_mBMSRegistrationResponse },
  {  16, "mBMSCNDeRegistrationResponse", ASN1_EXTENSION_ROOT    , dissect_mBMSCNDeRegistrationResponse },
  {  17, "mBMSRABRelease"              , ASN1_EXTENSION_ROOT    , dissect_mBMSRABRelease },
  { 0, NULL, 0, NULL }
};

static int
dissect_ranap_Dummy_SuccessfulOutcome_messages(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_ranap_Dummy_SuccessfulOutcome_messages, Dummy_SuccessfulOutcome_messages_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t RelocationPreparationFailure_sequence[] = {
  { "protocolIEs"                 , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_protocolIEs },
  { "protocolExtensions"          , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_protocolExtensions },
  { NULL, 0, 0, NULL }
};

static int
dissect_ranap_RelocationPreparationFailure(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ranap_RelocationPreparationFailure, RelocationPreparationFailure_sequence);

  return offset;
}
static int dissect_relocationPreparationFailure(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_ranap_RelocationPreparationFailure(tvb, offset, actx, tree, hf_ranap_relocationPreparationFailure);
}


static const per_sequence_t RelocationFailure_sequence[] = {
  { "protocolIEs"                 , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_protocolIEs },
  { "protocolExtensions"          , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_protocolExtensions },
  { NULL, 0, 0, NULL }
};

static int
dissect_ranap_RelocationFailure(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ranap_RelocationFailure, RelocationFailure_sequence);

  return offset;
}
static int dissect_relocationFailure(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_ranap_RelocationFailure(tvb, offset, actx, tree, hf_ranap_relocationFailure);
}


static const per_sequence_t SecurityModeReject_sequence[] = {
  { "protocolIEs"                 , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_protocolIEs },
  { "protocolExtensions"          , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_protocolExtensions },
  { NULL, 0, 0, NULL }
};

static int
dissect_ranap_SecurityModeReject(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ranap_SecurityModeReject, SecurityModeReject_sequence);

  return offset;
}
static int dissect_securityModeReject(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_ranap_SecurityModeReject(tvb, offset, actx, tree, hf_ranap_securityModeReject);
}


static const per_sequence_t LocationRelatedDataFailure_sequence[] = {
  { "protocolIEs"                 , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_protocolIEs },
  { "protocolExtensions"          , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_protocolExtensions },
  { NULL, 0, 0, NULL }
};

static int
dissect_ranap_LocationRelatedDataFailure(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ranap_LocationRelatedDataFailure, LocationRelatedDataFailure_sequence);

  return offset;
}
static int dissect_locationRelatedDataFailure(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_ranap_LocationRelatedDataFailure(tvb, offset, actx, tree, hf_ranap_locationRelatedDataFailure);
}


static const per_sequence_t InformationTransferFailure_sequence[] = {
  { "protocolIEs"                 , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_protocolIEs },
  { "protocolExtensions"          , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_protocolExtensions },
  { NULL, 0, 0, NULL }
};

static int
dissect_ranap_InformationTransferFailure(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ranap_InformationTransferFailure, InformationTransferFailure_sequence);

  return offset;
}
static int dissect_informationTransferFailure(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_ranap_InformationTransferFailure(tvb, offset, actx, tree, hf_ranap_informationTransferFailure);
}


static const per_sequence_t UplinkInformationExchangeFailure_sequence[] = {
  { "protocolIEs"                 , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_protocolIEs },
  { "protocolExtensions"          , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_protocolExtensions },
  { NULL, 0, 0, NULL }
};

static int
dissect_ranap_UplinkInformationExchangeFailure(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ranap_UplinkInformationExchangeFailure, UplinkInformationExchangeFailure_sequence);

  return offset;
}
static int dissect_uplinkInformationExchangeFailure(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_ranap_UplinkInformationExchangeFailure(tvb, offset, actx, tree, hf_ranap_uplinkInformationExchangeFailure);
}


static const per_sequence_t MBMSSessionStartFailure_sequence[] = {
  { "protocolIEs"                 , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_protocolIEs },
  { "protocolExtensions"          , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_protocolExtensions },
  { NULL, 0, 0, NULL }
};

static int
dissect_ranap_MBMSSessionStartFailure(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ranap_MBMSSessionStartFailure, MBMSSessionStartFailure_sequence);

  return offset;
}
static int dissect_mBMSSessionStartFailure(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_ranap_MBMSSessionStartFailure(tvb, offset, actx, tree, hf_ranap_mBMSSessionStartFailure);
}


static const per_sequence_t MBMSSessionUpdateFailure_sequence[] = {
  { "protocolIEs"                 , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_protocolIEs },
  { "protocolExtensions"          , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_protocolExtensions },
  { NULL, 0, 0, NULL }
};

static int
dissect_ranap_MBMSSessionUpdateFailure(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ranap_MBMSSessionUpdateFailure, MBMSSessionUpdateFailure_sequence);

  return offset;
}
static int dissect_mBMSSessionUpdateFailure(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_ranap_MBMSSessionUpdateFailure(tvb, offset, actx, tree, hf_ranap_mBMSSessionUpdateFailure);
}


static const per_sequence_t MBMSRegistrationFailure_sequence[] = {
  { "protocolIEs"                 , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_protocolIEs },
  { "protocolExtensions"          , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_protocolExtensions },
  { NULL, 0, 0, NULL }
};

static int
dissect_ranap_MBMSRegistrationFailure(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ranap_MBMSRegistrationFailure, MBMSRegistrationFailure_sequence);

  return offset;
}
static int dissect_mBMSRegistrationFailure(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_ranap_MBMSRegistrationFailure(tvb, offset, actx, tree, hf_ranap_mBMSRegistrationFailure);
}


static const per_sequence_t MBMSRABReleaseFailure_sequence[] = {
  { "protocolIEs"                 , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_protocolIEs },
  { "protocolExtensions"          , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_protocolExtensions },
  { NULL, 0, 0, NULL }
};

static int
dissect_ranap_MBMSRABReleaseFailure(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ranap_MBMSRABReleaseFailure, MBMSRABReleaseFailure_sequence);

  return offset;
}
static int dissect_mBMSRABReleaseFailure(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_ranap_MBMSRABReleaseFailure(tvb, offset, actx, tree, hf_ranap_mBMSRABReleaseFailure);
}


static const value_string ranap_Dummy_UnsuccessfulOutcome_messages_vals[] = {
  {   0, "relocationPreparationFailure" },
  {   1, "relocationFailure" },
  {   2, "securityModeReject" },
  {   3, "locationRelatedDataFailure" },
  {   4, "informationTransferFailure" },
  {   5, "uplinkInformationExchangeFailure" },
  {   6, "mBMSSessionStartFailure" },
  {   7, "mBMSSessionUpdateFailure" },
  {   8, "mBMSRegistrationFailure" },
  {   9, "mBMSRABReleaseFailure" },
  { 0, NULL }
};

static const per_choice_t Dummy_UnsuccessfulOutcome_messages_choice[] = {
  {   0, "relocationPreparationFailure", ASN1_EXTENSION_ROOT    , dissect_relocationPreparationFailure },
  {   1, "relocationFailure"           , ASN1_EXTENSION_ROOT    , dissect_relocationFailure },
  {   2, "securityModeReject"          , ASN1_EXTENSION_ROOT    , dissect_securityModeReject },
  {   3, "locationRelatedDataFailure"  , ASN1_EXTENSION_ROOT    , dissect_locationRelatedDataFailure },
  {   4, "informationTransferFailure"  , ASN1_EXTENSION_ROOT    , dissect_informationTransferFailure },
  {   5, "uplinkInformationExchangeFailure", ASN1_EXTENSION_ROOT    , dissect_uplinkInformationExchangeFailure },
  {   6, "mBMSSessionStartFailure"     , ASN1_EXTENSION_ROOT    , dissect_mBMSSessionStartFailure },
  {   7, "mBMSSessionUpdateFailure"    , ASN1_EXTENSION_ROOT    , dissect_mBMSSessionUpdateFailure },
  {   8, "mBMSRegistrationFailure"     , ASN1_EXTENSION_ROOT    , dissect_mBMSRegistrationFailure },
  {   9, "mBMSRABReleaseFailure"       , ASN1_EXTENSION_ROOT    , dissect_mBMSRABReleaseFailure },
  { 0, NULL, 0, NULL }
};

static int
dissect_ranap_Dummy_UnsuccessfulOutcome_messages(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_ranap_Dummy_UnsuccessfulOutcome_messages, Dummy_UnsuccessfulOutcome_messages_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t RAB_AssignmentResponse_sequence[] = {
  { "protocolIEs"                 , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_protocolIEs },
  { "protocolExtensions"          , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_protocolExtensions },
  { NULL, 0, 0, NULL }
};

static int
dissect_ranap_RAB_AssignmentResponse(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ranap_RAB_AssignmentResponse, RAB_AssignmentResponse_sequence);

  return offset;
}
static int dissect_rAB_AssignmentResponse(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_ranap_RAB_AssignmentResponse(tvb, offset, actx, tree, hf_ranap_rAB_AssignmentResponse);
}


static const per_sequence_t MBMSUELinkingResponse_sequence[] = {
  { "protocolIEs"                 , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_protocolIEs },
  { "protocolExtensions"          , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_protocolExtensions },
  { NULL, 0, 0, NULL }
};

static int
dissect_ranap_MBMSUELinkingResponse(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ranap_MBMSUELinkingResponse, MBMSUELinkingResponse_sequence);

  return offset;
}
static int dissect_mBMSUELinkingResponse(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_ranap_MBMSUELinkingResponse(tvb, offset, actx, tree, hf_ranap_mBMSUELinkingResponse);
}


static const value_string ranap_Dummy_Outcome_messages_vals[] = {
  {   0, "iu-ReleaseCommand" },
  {   1, "rAB-AssignmentResponse" },
  {   2, "mBMSUELinkingResponse" },
  { 0, NULL }
};

static const per_choice_t Dummy_Outcome_messages_choice[] = {
  {   0, "iu-ReleaseCommand"           , ASN1_EXTENSION_ROOT    , dissect_iu_ReleaseCommand },
  {   1, "rAB-AssignmentResponse"      , ASN1_EXTENSION_ROOT    , dissect_rAB_AssignmentResponse },
  {   2, "mBMSUELinkingResponse"       , ASN1_EXTENSION_ROOT    , dissect_mBMSUELinkingResponse },
  { 0, NULL, 0, NULL }
};

static int
dissect_ranap_Dummy_Outcome_messages(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_ranap_Dummy_Outcome_messages, Dummy_Outcome_messages_choice,
                                 NULL);

  return offset;
}


static const value_string ranap_AccuracyFulfilmentIndicator_vals[] = {
  {   0, "requested-Accuracy-Fulfilled" },
  {   1, "requested-Accuracy-Not-Fulfilled" },
  { 0, NULL }
};


static int
dissect_ranap_AccuracyFulfilmentIndicator(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     2, NULL, TRUE, 0, NULL);

  return offset;
}
static int dissect_id_AccuracyFulfilmentIndicator(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_ranap_AccuracyFulfilmentIndicator(tvb, offset, actx, tree, hf_ranap_id_AccuracyFulfilmentIndicator);
}



static int
dissect_ranap_APN(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_octet_string(tvb, offset, actx, tree, hf_index,
                                       1, 255, NULL);

  return offset;
}
static int dissect_id_APN(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_ranap_APN(tvb, offset, actx, tree, hf_ranap_id_APN);
}
static int dissect_aPN(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_ranap_APN(tvb, offset, actx, tree, hf_ranap_aPN);
}



static int
dissect_ranap_PLMNidentity(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
#line 79 "ranap.cnf"

	tvbuff_t *parameter_tvb=NULL;

  offset = dissect_per_octet_string(tvb, offset, actx, tree, hf_index,
                                       3, 3, &parameter_tvb);


	 if (!parameter_tvb)
		return offset;
	dissect_e212_mcc_mnc(parameter_tvb, tree, 0);



  return offset;
}
static int dissect_id_SelectedPLMN_ID(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_ranap_PLMNidentity(tvb, offset, actx, tree, hf_ranap_id_SelectedPLMN_ID);
}
static int dissect_pLMNidentity(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_ranap_PLMNidentity(tvb, offset, actx, tree, hf_ranap_pLMNidentity);
}



static int
dissect_ranap_LAC(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_octet_string(tvb, offset, actx, tree, hf_index,
                                       2, 2, NULL);

  return offset;
}
static int dissect_lAC(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_ranap_LAC(tvb, offset, actx, tree, hf_ranap_lAC);
}



static int
dissect_ranap_SAC(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_octet_string(tvb, offset, actx, tree, hf_index,
                                       2, 2, NULL);

  return offset;
}
static int dissect_sAC(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_ranap_SAC(tvb, offset, actx, tree, hf_ranap_sAC);
}


static const per_sequence_t SAI_sequence[] = {
  { "pLMNidentity"                , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_pLMNidentity },
  { "lAC"                         , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_lAC },
  { "sAC"                         , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_sAC },
  { "iE-Extensions"               , ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_iE_Extensions },
  { NULL, 0, 0, NULL }
};

static int
dissect_ranap_SAI(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ranap_SAI, SAI_sequence);

  return offset;
}
static int dissect_id_SAI(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_ranap_SAI(tvb, offset, actx, tree, hf_ranap_id_SAI);
}
static int dissect_sAI(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_ranap_SAI(tvb, offset, actx, tree, hf_ranap_sAI);
}


static const value_string ranap_T_latitudeSign_vals[] = {
  {   0, "north" },
  {   1, "south" },
  { 0, NULL }
};


static int
dissect_ranap_T_latitudeSign(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     2, NULL, FALSE, 0, NULL);

  return offset;
}
static int dissect_latitudeSign(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_ranap_T_latitudeSign(tvb, offset, actx, tree, hf_ranap_latitudeSign);
}



static int
dissect_ranap_INTEGER_0_8388607(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                              0U, 8388607U, NULL, FALSE);

  return offset;
}
static int dissect_latitude(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_ranap_INTEGER_0_8388607(tvb, offset, actx, tree, hf_ranap_latitude);
}



static int
dissect_ranap_INTEGER_M8388608_8388607(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                              -8388608, 8388607U, NULL, FALSE);

  return offset;
}
static int dissect_longitude(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_ranap_INTEGER_M8388608_8388607(tvb, offset, actx, tree, hf_ranap_longitude);
}


static const per_sequence_t GeographicalCoordinates_sequence[] = {
  { "latitudeSign"                , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_latitudeSign },
  { "latitude"                    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_latitude },
  { "longitude"                   , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_longitude },
  { "iE-Extensions"               , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_iE_Extensions },
  { NULL, 0, 0, NULL }
};

static int
dissect_ranap_GeographicalCoordinates(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ranap_GeographicalCoordinates, GeographicalCoordinates_sequence);

  return offset;
}
static int dissect_geographicalCoordinates(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_ranap_GeographicalCoordinates(tvb, offset, actx, tree, hf_ranap_geographicalCoordinates);
}


static const per_sequence_t GA_Point_sequence[] = {
  { "geographicalCoordinates"     , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_geographicalCoordinates },
  { "iE-Extensions"               , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_iE_Extensions },
  { NULL, 0, 0, NULL }
};

static int
dissect_ranap_GA_Point(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ranap_GA_Point, GA_Point_sequence);

  return offset;
}
static int dissect_point(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_ranap_GA_Point(tvb, offset, actx, tree, hf_ranap_point);
}



static int
dissect_ranap_INTEGER_0_127(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                              0U, 127U, NULL, FALSE);

  return offset;
}
static int dissect_uncertaintyRadius(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_ranap_INTEGER_0_127(tvb, offset, actx, tree, hf_ranap_uncertaintyRadius);
}
static int dissect_confidence(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_ranap_INTEGER_0_127(tvb, offset, actx, tree, hf_ranap_confidence);
}
static int dissect_uncertaintyAltitude(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_ranap_INTEGER_0_127(tvb, offset, actx, tree, hf_ranap_uncertaintyAltitude);
}
static int dissect_uncertaintyCode(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_ranap_INTEGER_0_127(tvb, offset, actx, tree, hf_ranap_uncertaintyCode);
}
static int dissect_uncertaintySemi_major(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_ranap_INTEGER_0_127(tvb, offset, actx, tree, hf_ranap_uncertaintySemi_major);
}
static int dissect_uncertaintySemi_minor(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_ranap_INTEGER_0_127(tvb, offset, actx, tree, hf_ranap_uncertaintySemi_minor);
}
static int dissect_accuracyCode(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_ranap_INTEGER_0_127(tvb, offset, actx, tree, hf_ranap_accuracyCode);
}


static const per_sequence_t GA_PointWithUnCertainty_sequence[] = {
  { "geographicalCoordinates"     , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_geographicalCoordinates },
  { "iE-Extensions"               , ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_iE_Extensions },
  { "uncertaintyCode"             , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_uncertaintyCode },
  { NULL, 0, 0, NULL }
};

static int
dissect_ranap_GA_PointWithUnCertainty(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ranap_GA_PointWithUnCertainty, GA_PointWithUnCertainty_sequence);

  return offset;
}
static int dissect_pointWithUnCertainty(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_ranap_GA_PointWithUnCertainty(tvb, offset, actx, tree, hf_ranap_pointWithUnCertainty);
}


static const per_sequence_t GA_Polygon_item_sequence[] = {
  { "geographicalCoordinates"     , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_geographicalCoordinates },
  { "iE-Extensions"               , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_iE_Extensions },
  { NULL, 0, 0, NULL }
};

static int
dissect_ranap_GA_Polygon_item(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ranap_GA_Polygon_item, GA_Polygon_item_sequence);

  return offset;
}
static int dissect_GA_Polygon_item(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_ranap_GA_Polygon_item(tvb, offset, actx, tree, hf_ranap_GA_Polygon_item);
}


static const per_sequence_t GA_Polygon_sequence_of[1] = {
  { ""                            , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_GA_Polygon_item },
};

static int
dissect_ranap_GA_Polygon(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_ranap_GA_Polygon, GA_Polygon_sequence_of,
                                                  1, 15);

  return offset;
}
static int dissect_polygon(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_ranap_GA_Polygon(tvb, offset, actx, tree, hf_ranap_polygon);
}



static int
dissect_ranap_INTEGER_0_179(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                              0U, 179U, NULL, FALSE);

  return offset;
}
static int dissect_offsetAngle(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_ranap_INTEGER_0_179(tvb, offset, actx, tree, hf_ranap_offsetAngle);
}
static int dissect_includedAngle(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_ranap_INTEGER_0_179(tvb, offset, actx, tree, hf_ranap_includedAngle);
}
static int dissect_orientationOfMajorAxis(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_ranap_INTEGER_0_179(tvb, offset, actx, tree, hf_ranap_orientationOfMajorAxis);
}


static const per_sequence_t GA_UncertaintyEllipse_sequence[] = {
  { "uncertaintySemi-major"       , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_uncertaintySemi_major },
  { "uncertaintySemi-minor"       , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_uncertaintySemi_minor },
  { "orientationOfMajorAxis"      , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_orientationOfMajorAxis },
  { NULL, 0, 0, NULL }
};

static int
dissect_ranap_GA_UncertaintyEllipse(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ranap_GA_UncertaintyEllipse, GA_UncertaintyEllipse_sequence);

  return offset;
}
static int dissect_uncertaintyEllipse(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_ranap_GA_UncertaintyEllipse(tvb, offset, actx, tree, hf_ranap_uncertaintyEllipse);
}


static const per_sequence_t GA_PointWithUnCertaintyEllipse_sequence[] = {
  { "geographicalCoordinates"     , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_geographicalCoordinates },
  { "uncertaintyEllipse"          , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_uncertaintyEllipse },
  { "confidence"                  , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_confidence },
  { "iE-Extensions"               , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_iE_Extensions },
  { NULL, 0, 0, NULL }
};

static int
dissect_ranap_GA_PointWithUnCertaintyEllipse(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ranap_GA_PointWithUnCertaintyEllipse, GA_PointWithUnCertaintyEllipse_sequence);

  return offset;
}
static int dissect_pointWithUncertaintyEllipse(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_ranap_GA_PointWithUnCertaintyEllipse(tvb, offset, actx, tree, hf_ranap_pointWithUncertaintyEllipse);
}


static const value_string ranap_T_directionOfAltitude_vals[] = {
  {   0, "height" },
  {   1, "depth" },
  { 0, NULL }
};


static int
dissect_ranap_T_directionOfAltitude(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     2, NULL, FALSE, 0, NULL);

  return offset;
}
static int dissect_directionOfAltitude(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_ranap_T_directionOfAltitude(tvb, offset, actx, tree, hf_ranap_directionOfAltitude);
}



static int
dissect_ranap_INTEGER_0_32767(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                              0U, 32767U, NULL, FALSE);

  return offset;
}
static int dissect_altitude(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_ranap_INTEGER_0_32767(tvb, offset, actx, tree, hf_ranap_altitude);
}
static int dissect_ageOfSAI(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_ranap_INTEGER_0_32767(tvb, offset, actx, tree, hf_ranap_ageOfSAI);
}


static const per_sequence_t GA_AltitudeAndDirection_sequence[] = {
  { "directionOfAltitude"         , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_directionOfAltitude },
  { "altitude"                    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_altitude },
  { NULL, 0, 0, NULL }
};

static int
dissect_ranap_GA_AltitudeAndDirection(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ranap_GA_AltitudeAndDirection, GA_AltitudeAndDirection_sequence);

  return offset;
}
static int dissect_altitudeAndDirection(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_ranap_GA_AltitudeAndDirection(tvb, offset, actx, tree, hf_ranap_altitudeAndDirection);
}


static const per_sequence_t GA_PointWithAltitude_sequence[] = {
  { "geographicalCoordinates"     , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_geographicalCoordinates },
  { "altitudeAndDirection"        , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_altitudeAndDirection },
  { "iE-Extensions"               , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_iE_Extensions },
  { NULL, 0, 0, NULL }
};

static int
dissect_ranap_GA_PointWithAltitude(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ranap_GA_PointWithAltitude, GA_PointWithAltitude_sequence);

  return offset;
}
static int dissect_pointWithAltitude(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_ranap_GA_PointWithAltitude(tvb, offset, actx, tree, hf_ranap_pointWithAltitude);
}


static const per_sequence_t GA_PointWithAltitudeAndUncertaintyEllipsoid_sequence[] = {
  { "geographicalCoordinates"     , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_geographicalCoordinates },
  { "altitudeAndDirection"        , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_altitudeAndDirection },
  { "uncertaintyEllipse"          , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_uncertaintyEllipse },
  { "uncertaintyAltitude"         , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_uncertaintyAltitude },
  { "confidence"                  , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_confidence },
  { "iE-Extensions"               , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_iE_Extensions },
  { NULL, 0, 0, NULL }
};

static int
dissect_ranap_GA_PointWithAltitudeAndUncertaintyEllipsoid(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ranap_GA_PointWithAltitudeAndUncertaintyEllipsoid, GA_PointWithAltitudeAndUncertaintyEllipsoid_sequence);

  return offset;
}
static int dissect_pointWithAltitudeAndUncertaintyEllipsoid(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_ranap_GA_PointWithAltitudeAndUncertaintyEllipsoid(tvb, offset, actx, tree, hf_ranap_pointWithAltitudeAndUncertaintyEllipsoid);
}


static const per_sequence_t GA_EllipsoidArc_sequence[] = {
  { "geographicalCoordinates"     , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_geographicalCoordinates },
  { "innerRadius"                 , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_innerRadius },
  { "uncertaintyRadius"           , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_uncertaintyRadius },
  { "offsetAngle"                 , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_offsetAngle },
  { "includedAngle"               , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_includedAngle },
  { "confidence"                  , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_confidence },
  { "iE-Extensions"               , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_iE_Extensions },
  { NULL, 0, 0, NULL }
};

static int
dissect_ranap_GA_EllipsoidArc(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ranap_GA_EllipsoidArc, GA_EllipsoidArc_sequence);

  return offset;
}
static int dissect_ellipsoidArc(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_ranap_GA_EllipsoidArc(tvb, offset, actx, tree, hf_ranap_ellipsoidArc);
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
  {   0, "point"                       , ASN1_EXTENSION_ROOT    , dissect_point },
  {   1, "pointWithUnCertainty"        , ASN1_EXTENSION_ROOT    , dissect_pointWithUnCertainty },
  {   2, "polygon"                     , ASN1_EXTENSION_ROOT    , dissect_polygon },
  {   3, "pointWithUncertaintyEllipse" , ASN1_NOT_EXTENSION_ROOT, dissect_pointWithUncertaintyEllipse },
  {   4, "pointWithAltitude"           , ASN1_NOT_EXTENSION_ROOT, dissect_pointWithAltitude },
  {   5, "pointWithAltitudeAndUncertaintyEllipsoid", ASN1_NOT_EXTENSION_ROOT, dissect_pointWithAltitudeAndUncertaintyEllipsoid },
  {   6, "ellipsoidArc"                , ASN1_NOT_EXTENSION_ROOT, dissect_ellipsoidArc },
  { 0, NULL, 0, NULL }
};

static int
dissect_ranap_GeographicalArea(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_ranap_GeographicalArea, GeographicalArea_choice,
                                 NULL);

  return offset;
}
static int dissect_geographicalArea(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_ranap_GeographicalArea(tvb, offset, actx, tree, hf_ranap_geographicalArea);
}


static const value_string ranap_AreaIdentity_vals[] = {
  {   0, "sAI" },
  {   1, "geographicalArea" },
  { 0, NULL }
};

static const per_choice_t AreaIdentity_choice[] = {
  {   0, "sAI"                         , ASN1_EXTENSION_ROOT    , dissect_sAI },
  {   1, "geographicalArea"            , ASN1_EXTENSION_ROOT    , dissect_geographicalArea },
  { 0, NULL, 0, NULL }
};

static int
dissect_ranap_AreaIdentity(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_ranap_AreaIdentity, AreaIdentity_choice,
                                 NULL);

  return offset;
}
static int dissect_id_AreaIdentity(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_ranap_AreaIdentity(tvb, offset, actx, tree, hf_ranap_id_AreaIdentity);
}


static const value_string ranap_Alt_RAB_Parameter_MaxBitrateType_vals[] = {
  {   0, "unspecified" },
  {   1, "value-range" },
  {   2, "discrete-values" },
  { 0, NULL }
};


static int
dissect_ranap_Alt_RAB_Parameter_MaxBitrateType(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     3, NULL, TRUE, 0, NULL);

  return offset;
}
static int dissect_altMaxBitrateType(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_ranap_Alt_RAB_Parameter_MaxBitrateType(tvb, offset, actx, tree, hf_ranap_altMaxBitrateType);
}



static int
dissect_ranap_MaxBitrate(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                              1U, 16000000U, NULL, FALSE);

  return offset;
}
static int dissect_Alt_RAB_Parameter_MaxBitrateList_item(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_ranap_MaxBitrate(tvb, offset, actx, tree, hf_ranap_Alt_RAB_Parameter_MaxBitrateList_item);
}
static int dissect_Ass_RAB_Parameter_MaxBitrateList_item(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_ranap_MaxBitrate(tvb, offset, actx, tree, hf_ranap_Ass_RAB_Parameter_MaxBitrateList_item);
}
static int dissect_RAB_Parameter_MaxBitrateList_item(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_ranap_MaxBitrate(tvb, offset, actx, tree, hf_ranap_RAB_Parameter_MaxBitrateList_item);
}
static int dissect_Requested_RAB_Parameter_MaxBitrateList_item(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_ranap_MaxBitrate(tvb, offset, actx, tree, hf_ranap_Requested_RAB_Parameter_MaxBitrateList_item);
}


static const per_sequence_t Alt_RAB_Parameter_MaxBitrateList_sequence_of[1] = {
  { ""                            , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_Alt_RAB_Parameter_MaxBitrateList_item },
};

static int
dissect_ranap_Alt_RAB_Parameter_MaxBitrateList(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_ranap_Alt_RAB_Parameter_MaxBitrateList, Alt_RAB_Parameter_MaxBitrateList_sequence_of,
                                                  1, 2);

  return offset;
}
static int dissect_Alt_RAB_Parameter_MaxBitrates_item(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_ranap_Alt_RAB_Parameter_MaxBitrateList(tvb, offset, actx, tree, hf_ranap_Alt_RAB_Parameter_MaxBitrates_item);
}


static const per_sequence_t Alt_RAB_Parameter_MaxBitrates_sequence_of[1] = {
  { ""                            , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_Alt_RAB_Parameter_MaxBitrates_item },
};

static int
dissect_ranap_Alt_RAB_Parameter_MaxBitrates(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_ranap_Alt_RAB_Parameter_MaxBitrates, Alt_RAB_Parameter_MaxBitrates_sequence_of,
                                                  1, 16);

  return offset;
}
static int dissect_altMaxBitrates(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_ranap_Alt_RAB_Parameter_MaxBitrates(tvb, offset, actx, tree, hf_ranap_altMaxBitrates);
}


static const per_sequence_t Alt_RAB_Parameter_MaxBitrateInf_sequence[] = {
  { "altMaxBitrateType"           , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_altMaxBitrateType },
  { "altMaxBitrates"              , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_altMaxBitrates },
  { NULL, 0, 0, NULL }
};

static int
dissect_ranap_Alt_RAB_Parameter_MaxBitrateInf(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ranap_Alt_RAB_Parameter_MaxBitrateInf, Alt_RAB_Parameter_MaxBitrateInf_sequence);

  return offset;
}
static int dissect_altMaxBitrateInf(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_ranap_Alt_RAB_Parameter_MaxBitrateInf(tvb, offset, actx, tree, hf_ranap_altMaxBitrateInf);
}


static const value_string ranap_Alt_RAB_Parameter_GuaranteedBitrateType_vals[] = {
  {   0, "unspecified" },
  {   1, "value-range" },
  {   2, "discrete-values" },
  { 0, NULL }
};


static int
dissect_ranap_Alt_RAB_Parameter_GuaranteedBitrateType(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     3, NULL, TRUE, 0, NULL);

  return offset;
}
static int dissect_altGuaranteedBitrateType(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_ranap_Alt_RAB_Parameter_GuaranteedBitrateType(tvb, offset, actx, tree, hf_ranap_altGuaranteedBitrateType);
}



static int
dissect_ranap_GuaranteedBitrate(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                              0U, 16000000U, NULL, FALSE);

  return offset;
}
static int dissect_Alt_RAB_Parameter_GuaranteedBitrateList_item(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_ranap_GuaranteedBitrate(tvb, offset, actx, tree, hf_ranap_Alt_RAB_Parameter_GuaranteedBitrateList_item);
}
static int dissect_Ass_RAB_Parameter_GuaranteedBitrateList_item(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_ranap_GuaranteedBitrate(tvb, offset, actx, tree, hf_ranap_Ass_RAB_Parameter_GuaranteedBitrateList_item);
}
static int dissect_RAB_Parameter_GuaranteedBitrateList_item(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_ranap_GuaranteedBitrate(tvb, offset, actx, tree, hf_ranap_RAB_Parameter_GuaranteedBitrateList_item);
}
static int dissect_Requested_RAB_Parameter_GuaranteedBitrateList_item(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_ranap_GuaranteedBitrate(tvb, offset, actx, tree, hf_ranap_Requested_RAB_Parameter_GuaranteedBitrateList_item);
}


static const per_sequence_t Alt_RAB_Parameter_GuaranteedBitrateList_sequence_of[1] = {
  { ""                            , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_Alt_RAB_Parameter_GuaranteedBitrateList_item },
};

static int
dissect_ranap_Alt_RAB_Parameter_GuaranteedBitrateList(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_ranap_Alt_RAB_Parameter_GuaranteedBitrateList, Alt_RAB_Parameter_GuaranteedBitrateList_sequence_of,
                                                  1, 2);

  return offset;
}
static int dissect_Alt_RAB_Parameter_GuaranteedBitrates_item(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_ranap_Alt_RAB_Parameter_GuaranteedBitrateList(tvb, offset, actx, tree, hf_ranap_Alt_RAB_Parameter_GuaranteedBitrates_item);
}


static const per_sequence_t Alt_RAB_Parameter_GuaranteedBitrates_sequence_of[1] = {
  { ""                            , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_Alt_RAB_Parameter_GuaranteedBitrates_item },
};

static int
dissect_ranap_Alt_RAB_Parameter_GuaranteedBitrates(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_ranap_Alt_RAB_Parameter_GuaranteedBitrates, Alt_RAB_Parameter_GuaranteedBitrates_sequence_of,
                                                  1, 16);

  return offset;
}
static int dissect_altGuaranteedBitrates(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_ranap_Alt_RAB_Parameter_GuaranteedBitrates(tvb, offset, actx, tree, hf_ranap_altGuaranteedBitrates);
}


static const per_sequence_t Alt_RAB_Parameter_GuaranteedBitrateInf_sequence[] = {
  { "altGuaranteedBitrateType"    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_altGuaranteedBitrateType },
  { "altGuaranteedBitrates"       , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_altGuaranteedBitrates },
  { NULL, 0, 0, NULL }
};

static int
dissect_ranap_Alt_RAB_Parameter_GuaranteedBitrateInf(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ranap_Alt_RAB_Parameter_GuaranteedBitrateInf, Alt_RAB_Parameter_GuaranteedBitrateInf_sequence);

  return offset;
}
static int dissect_altGuaranteedBitRateInf(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_ranap_Alt_RAB_Parameter_GuaranteedBitrateInf(tvb, offset, actx, tree, hf_ranap_altGuaranteedBitRateInf);
}


static const per_sequence_t Alt_RAB_Parameters_sequence[] = {
  { "altMaxBitrateInf"            , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_altMaxBitrateInf },
  { "altGuaranteedBitRateInf"     , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_altGuaranteedBitRateInf },
  { "iE-Extensions"               , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_iE_Extensions },
  { NULL, 0, 0, NULL }
};

static int
dissect_ranap_Alt_RAB_Parameters(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ranap_Alt_RAB_Parameters, Alt_RAB_Parameters_sequence);

  return offset;
}
static int dissect_id_Alt_RAB_Parameters(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_ranap_Alt_RAB_Parameters(tvb, offset, actx, tree, hf_ranap_id_Alt_RAB_Parameters);
}


static const per_sequence_t Ass_RAB_Parameter_MaxBitrateList_sequence_of[1] = {
  { ""                            , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_Ass_RAB_Parameter_MaxBitrateList_item },
};

static int
dissect_ranap_Ass_RAB_Parameter_MaxBitrateList(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_ranap_Ass_RAB_Parameter_MaxBitrateList, Ass_RAB_Parameter_MaxBitrateList_sequence_of,
                                                  1, 2);

  return offset;
}
static int dissect_assMaxBitrateInf(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_ranap_Ass_RAB_Parameter_MaxBitrateList(tvb, offset, actx, tree, hf_ranap_assMaxBitrateInf);
}


static const per_sequence_t Ass_RAB_Parameter_GuaranteedBitrateList_sequence_of[1] = {
  { ""                            , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_Ass_RAB_Parameter_GuaranteedBitrateList_item },
};

static int
dissect_ranap_Ass_RAB_Parameter_GuaranteedBitrateList(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_ranap_Ass_RAB_Parameter_GuaranteedBitrateList, Ass_RAB_Parameter_GuaranteedBitrateList_sequence_of,
                                                  1, 2);

  return offset;
}
static int dissect_assGuaranteedBitRateInf(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_ranap_Ass_RAB_Parameter_GuaranteedBitrateList(tvb, offset, actx, tree, hf_ranap_assGuaranteedBitRateInf);
}


static const per_sequence_t Ass_RAB_Parameters_sequence[] = {
  { "assMaxBitrateInf"            , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_assMaxBitrateInf },
  { "assGuaranteedBitRateInf"     , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_assGuaranteedBitRateInf },
  { "iE-Extensions"               , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_iE_Extensions },
  { NULL, 0, 0, NULL }
};

static int
dissect_ranap_Ass_RAB_Parameters(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ranap_Ass_RAB_Parameters, Ass_RAB_Parameters_sequence);

  return offset;
}
static int dissect_id_Ass_RAB_Parameters(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_ranap_Ass_RAB_Parameters(tvb, offset, actx, tree, hf_ranap_id_Ass_RAB_Parameters);
}



static int
dissect_ranap_BIT_STRING_SIZE_1(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_bit_string(tvb, offset, actx, tree, hf_index,
                                     1, 1, FALSE);

  return offset;
}
static int dissect_cipheringKeyFlag(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_ranap_BIT_STRING_SIZE_1(tvb, offset, actx, tree, hf_ranap_cipheringKeyFlag);
}



static int
dissect_ranap_BIT_STRING_SIZE_56(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_bit_string(tvb, offset, actx, tree, hf_index,
                                     56, 56, FALSE);

  return offset;
}
static int dissect_currentDecipheringKey(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_ranap_BIT_STRING_SIZE_56(tvb, offset, actx, tree, hf_ranap_currentDecipheringKey);
}
static int dissect_nextDecipheringKey(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_ranap_BIT_STRING_SIZE_56(tvb, offset, actx, tree, hf_ranap_nextDecipheringKey);
}


static const per_sequence_t BroadcastAssistanceDataDecipheringKeys_sequence[] = {
  { "cipheringKeyFlag"            , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_cipheringKeyFlag },
  { "currentDecipheringKey"       , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_currentDecipheringKey },
  { "nextDecipheringKey"          , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_nextDecipheringKey },
  { NULL, 0, 0, NULL }
};

static int
dissect_ranap_BroadcastAssistanceDataDecipheringKeys(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ranap_BroadcastAssistanceDataDecipheringKeys, BroadcastAssistanceDataDecipheringKeys_sequence);

  return offset;
}
static int dissect_id_BroadcastAssistanceDataDecipheringKeys(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_ranap_BroadcastAssistanceDataDecipheringKeys(tvb, offset, actx, tree, hf_ranap_id_BroadcastAssistanceDataDecipheringKeys);
}


static const value_string ranap_RequestedLocationRelatedDataType_vals[] = {
  {   0, "decipheringKeysUEBasedOTDOA" },
  {   1, "decipheringKeysAssistedGPS" },
  {   2, "dedicatedAssistanceDataUEBasedOTDOA" },
  {   3, "dedicatedAssistanceDataAssistedGPS" },
  { 0, NULL }
};


static int
dissect_ranap_RequestedLocationRelatedDataType(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     4, NULL, TRUE, 0, NULL);

  return offset;
}
static int dissect_requestedLocationRelatedDataType(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_ranap_RequestedLocationRelatedDataType(tvb, offset, actx, tree, hf_ranap_requestedLocationRelatedDataType);
}



static int
dissect_ranap_RequestedGPSAssistanceData(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_octet_string(tvb, offset, actx, tree, hf_index,
                                       1, 38, NULL);

  return offset;
}
static int dissect_requestedGPSAssistanceData(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_ranap_RequestedGPSAssistanceData(tvb, offset, actx, tree, hf_ranap_requestedGPSAssistanceData);
}


static const per_sequence_t LocationRelatedDataRequestType_sequence[] = {
  { "requestedLocationRelatedDataType", ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_requestedLocationRelatedDataType },
  { "requestedGPSAssistanceData"  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_requestedGPSAssistanceData },
  { NULL, 0, 0, NULL }
};

static int
dissect_ranap_LocationRelatedDataRequestType(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ranap_LocationRelatedDataRequestType, LocationRelatedDataRequestType_sequence);

  return offset;
}
static int dissect_id_LocationRelatedDataRequestType(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_ranap_LocationRelatedDataRequestType(tvb, offset, actx, tree, hf_ranap_id_LocationRelatedDataRequestType);
}


static const value_string ranap_CN_DomainIndicator_vals[] = {
  {   0, "cs-domain" },
  {   1, "ps-domain" },
  { 0, NULL }
};


static int
dissect_ranap_CN_DomainIndicator(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     2, NULL, FALSE, 0, NULL);

  return offset;
}
static int dissect_id_CN_DomainIndicator(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_ranap_CN_DomainIndicator(tvb, offset, actx, tree, hf_ranap_id_CN_DomainIndicator);
}
static int dissect_cN_DomainIndicator(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_ranap_CN_DomainIndicator(tvb, offset, actx, tree, hf_ranap_cN_DomainIndicator);
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


static int
dissect_ranap_CauseRadioNetwork(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                              1U, 64U, NULL, FALSE);

  return offset;
}
static int dissect_radioNetwork(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_ranap_CauseRadioNetwork(tvb, offset, actx, tree, hf_ranap_radioNetwork);
}


static const value_string ranap_CauseTransmissionNetwork_vals[] = {
  {  65, "signalling-transport-resource-failure" },
  {  66, "iu-transport-connection-failed-to-establish" },
  { 0, NULL }
};


static int
dissect_ranap_CauseTransmissionNetwork(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                              65U, 80U, NULL, FALSE);

  return offset;
}
static int dissect_transmissionNetwork(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_ranap_CauseTransmissionNetwork(tvb, offset, actx, tree, hf_ranap_transmissionNetwork);
}


static const value_string ranap_CauseNAS_vals[] = {
  {  81, "user-restriction-start-indication" },
  {  82, "user-restriction-end-indication" },
  {  83, "normal-release" },
  { 0, NULL }
};


static int
dissect_ranap_CauseNAS(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                              81U, 96U, NULL, FALSE);

  return offset;
}
static int dissect_nAS(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_ranap_CauseNAS(tvb, offset, actx, tree, hf_ranap_nAS);
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
dissect_ranap_CauseProtocol(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                              97U, 112U, NULL, FALSE);

  return offset;
}
static int dissect_protocol(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_ranap_CauseProtocol(tvb, offset, actx, tree, hf_ranap_protocol);
}


static const value_string ranap_CauseMisc_vals[] = {
  { 113, "om-intervention" },
  { 114, "no-resource-available" },
  { 115, "unspecified-failure" },
  { 116, "network-optimisation" },
  { 0, NULL }
};


static int
dissect_ranap_CauseMisc(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                              113U, 128U, NULL, FALSE);

  return offset;
}
static int dissect_misc(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_ranap_CauseMisc(tvb, offset, actx, tree, hf_ranap_misc);
}



static int
dissect_ranap_CauseNon_Standard(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                              129U, 256U, NULL, FALSE);

  return offset;
}
static int dissect_non_Standard(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_ranap_CauseNon_Standard(tvb, offset, actx, tree, hf_ranap_non_Standard);
}


static const value_string ranap_CauseRadioNetworkExtension_vals[] = {
  { 257, "iP-multicast-address-and-APN-not-valid" },
  { 258, "mBMS-de-registration-rejected-due-to-implicit-registration" },
  { 259, "mBMS-request-superseded" },
  { 260, "mBMS-de-registration-during-session-not-allowed" },
  { 261, "mBMS-no-data-bearer-necessary" },
  { 0, NULL }
};


static int
dissect_ranap_CauseRadioNetworkExtension(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                              257U, 512U, NULL, FALSE);

  return offset;
}
static int dissect_radioNetworkExtension(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_ranap_CauseRadioNetworkExtension(tvb, offset, actx, tree, hf_ranap_radioNetworkExtension);
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
  {   0, "radioNetwork"                , ASN1_EXTENSION_ROOT    , dissect_radioNetwork },
  {   1, "transmissionNetwork"         , ASN1_EXTENSION_ROOT    , dissect_transmissionNetwork },
  {   2, "nAS"                         , ASN1_EXTENSION_ROOT    , dissect_nAS },
  {   3, "protocol"                    , ASN1_EXTENSION_ROOT    , dissect_protocol },
  {   4, "misc"                        , ASN1_EXTENSION_ROOT    , dissect_misc },
  {   5, "non-Standard"                , ASN1_EXTENSION_ROOT    , dissect_non_Standard },
  {   6, "radioNetworkExtension"       , ASN1_NOT_EXTENSION_ROOT, dissect_radioNetworkExtension },
  { 0, NULL, 0, NULL }
};

static int
dissect_ranap_Cause(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_ranap_Cause, Cause_choice,
                                 NULL);

  return offset;
}
static int dissect_id_Cause(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_ranap_Cause(tvb, offset, actx, tree, hf_ranap_id_Cause);
}
static int dissect_cause(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_ranap_Cause(tvb, offset, actx, tree, hf_ranap_cause);
}


static const value_string ranap_EncryptionAlgorithm_vals[] = {
  {   0, "no-encryption" },
  {   1, "standard-UMTS-encryption-algorith-UEA1" },
  { 0, NULL }
};


static int
dissect_ranap_EncryptionAlgorithm(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                              0U, 15U, NULL, FALSE);

  return offset;
}
static int dissect_PermittedEncryptionAlgorithms_item(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_ranap_EncryptionAlgorithm(tvb, offset, actx, tree, hf_ranap_PermittedEncryptionAlgorithms_item);
}



static int
dissect_ranap_ChosenEncryptionAlgorithm(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_ranap_EncryptionAlgorithm(tvb, offset, actx, tree, hf_index);

  return offset;
}
static int dissect_id_ChosenEncryptionAlgorithm(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_ranap_ChosenEncryptionAlgorithm(tvb, offset, actx, tree, hf_ranap_id_ChosenEncryptionAlgorithm);
}
static int dissect_chosenEncryptionAlgorithForSignalling(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_ranap_ChosenEncryptionAlgorithm(tvb, offset, actx, tree, hf_ranap_chosenEncryptionAlgorithForSignalling);
}
static int dissect_chosenEncryptionAlgorithForCS(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_ranap_ChosenEncryptionAlgorithm(tvb, offset, actx, tree, hf_ranap_chosenEncryptionAlgorithForCS);
}
static int dissect_chosenEncryptionAlgorithForPS(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_ranap_ChosenEncryptionAlgorithm(tvb, offset, actx, tree, hf_ranap_chosenEncryptionAlgorithForPS);
}


static const value_string ranap_IntegrityProtectionAlgorithm_vals[] = {
  {   0, "standard-UMTS-integrity-algorithm-UIA1" },
  {  15, "no-value" },
  { 0, NULL }
};


static int
dissect_ranap_IntegrityProtectionAlgorithm(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                              0U, 15U, NULL, FALSE);

  return offset;
}
static int dissect_PermittedIntegrityProtectionAlgorithms_item(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_ranap_IntegrityProtectionAlgorithm(tvb, offset, actx, tree, hf_ranap_PermittedIntegrityProtectionAlgorithms_item);
}



static int
dissect_ranap_ChosenIntegrityProtectionAlgorithm(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_ranap_IntegrityProtectionAlgorithm(tvb, offset, actx, tree, hf_index);

  return offset;
}
static int dissect_id_ChosenIntegrityProtectionAlgorithm(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_ranap_ChosenIntegrityProtectionAlgorithm(tvb, offset, actx, tree, hf_ranap_id_ChosenIntegrityProtectionAlgorithm);
}
static int dissect_chosenIntegrityProtectionAlgorithm(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_ranap_ChosenIntegrityProtectionAlgorithm(tvb, offset, actx, tree, hf_ranap_chosenIntegrityProtectionAlgorithm);
}



static int
dissect_ranap_ClassmarkInformation2(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_octet_string(tvb, offset, actx, tree, hf_index,
                                       NO_BOUND, NO_BOUND, NULL);

  return offset;
}
static int dissect_id_ClassmarkInformation2(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_ranap_ClassmarkInformation2(tvb, offset, actx, tree, hf_ranap_id_ClassmarkInformation2);
}



static int
dissect_ranap_ClassmarkInformation3(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_octet_string(tvb, offset, actx, tree, hf_index,
                                       NO_BOUND, NO_BOUND, NULL);

  return offset;
}
static int dissect_id_ClassmarkInformation3(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_ranap_ClassmarkInformation3(tvb, offset, actx, tree, hf_ranap_id_ClassmarkInformation3);
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
dissect_ranap_ClientType(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     8, NULL, TRUE, 0, NULL);

  return offset;
}
static int dissect_id_ClientType(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_ranap_ClientType(tvb, offset, actx, tree, hf_ranap_id_ClientType);
}



static int
dissect_ranap_OCTET_STRING_SIZE_3(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_octet_string(tvb, offset, actx, tree, hf_index,
                                       3, 3, NULL);

  return offset;
}
static int dissect_serviceID(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_ranap_OCTET_STRING_SIZE_3(tvb, offset, actx, tree, hf_ranap_serviceID);
}


static const per_sequence_t TMGI_sequence[] = {
  { "pLMNidentity"                , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_pLMNidentity },
  { "serviceID"                   , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_serviceID },
  { "iE-Extensions"               , ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_iE_Extensions },
  { NULL, 0, 0, NULL }
};

static int
dissect_ranap_TMGI(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ranap_TMGI, TMGI_sequence);

  return offset;
}
static int dissect_id_TMGI(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_ranap_TMGI(tvb, offset, actx, tree, hf_ranap_id_TMGI);
}
static int dissect_tMGI(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_ranap_TMGI(tvb, offset, actx, tree, hf_ranap_tMGI);
}
static int dissect_MBMSIPMulticastAddressandAPNRequest_item(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_ranap_TMGI(tvb, offset, actx, tree, hf_ranap_MBMSIPMulticastAddressandAPNRequest_item);
}
static int dissect_RequestedMulticastServiceList_item(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_ranap_TMGI(tvb, offset, actx, tree, hf_ranap_RequestedMulticastServiceList_item);
}



static int
dissect_ranap_MBMS_PTP_RAB_ID(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_bit_string(tvb, offset, actx, tree, hf_index,
                                     8, 8, FALSE);

  return offset;
}
static int dissect_mBMS_PTP_RAB_ID(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_ranap_MBMS_PTP_RAB_ID(tvb, offset, actx, tree, hf_ranap_mBMS_PTP_RAB_ID);
}


static const per_sequence_t JoinedMBMSBearerService_IEs_item_sequence[] = {
  { "tMGI"                        , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_tMGI },
  { "mBMS-PTP-RAB-ID"             , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_mBMS_PTP_RAB_ID },
  { "iE-Extensions"               , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_iE_Extensions },
  { NULL, 0, 0, NULL }
};

static int
dissect_ranap_JoinedMBMSBearerService_IEs_item(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ranap_JoinedMBMSBearerService_IEs_item, JoinedMBMSBearerService_IEs_item_sequence);

  return offset;
}
static int dissect_JoinedMBMSBearerService_IEs_item(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_ranap_JoinedMBMSBearerService_IEs_item(tvb, offset, actx, tree, hf_ranap_JoinedMBMSBearerService_IEs_item);
}


static const per_sequence_t JoinedMBMSBearerService_IEs_sequence_of[1] = {
  { ""                            , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_JoinedMBMSBearerService_IEs_item },
};

static int
dissect_ranap_JoinedMBMSBearerService_IEs(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_ranap_JoinedMBMSBearerService_IEs, JoinedMBMSBearerService_IEs_sequence_of,
                                                  1, 128);

  return offset;
}
static int dissect_id_JoinedMBMSBearerServicesList(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_ranap_JoinedMBMSBearerService_IEs(tvb, offset, actx, tree, hf_ranap_id_JoinedMBMSBearerServicesList);
}
static int dissect_joinedMBMSBearerService_IEs(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_ranap_JoinedMBMSBearerService_IEs(tvb, offset, actx, tree, hf_ranap_joinedMBMSBearerService_IEs);
}


static const per_sequence_t CNMBMSLinkingInformation_sequence[] = {
  { "joinedMBMSBearerService-IEs" , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_joinedMBMSBearerService_IEs },
  { "iE-Extensions"               , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_iE_Extensions },
  { NULL, 0, 0, NULL }
};

static int
dissect_ranap_CNMBMSLinkingInformation(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ranap_CNMBMSLinkingInformation, CNMBMSLinkingInformation_sequence);

  return offset;
}
static int dissect_id_CNMBMSLinkingInformation(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_ranap_CNMBMSLinkingInformation(tvb, offset, actx, tree, hf_ranap_id_CNMBMSLinkingInformation);
}


static const value_string ranap_TriggeringMessage_vals[] = {
  {   0, "initiating-message" },
  {   1, "successful-outcome" },
  {   2, "unsuccessfull-outcome" },
  {   3, "outcome" },
  { 0, NULL }
};


static int
dissect_ranap_TriggeringMessage(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     4, NULL, FALSE, 0, NULL);

  return offset;
}
static int dissect_triggeringMessage(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_ranap_TriggeringMessage(tvb, offset, actx, tree, hf_ranap_triggeringMessage);
}



static int
dissect_ranap_RepetitionNumber0(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                              0U, 255U, NULL, FALSE);

  return offset;
}
static int dissect_repetitionNumber(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_ranap_RepetitionNumber0(tvb, offset, actx, tree, hf_ranap_repetitionNumber);
}


static const per_sequence_t CriticalityDiagnostics_IE_List_item_sequence[] = {
  { "iECriticality"               , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_iECriticality },
  { "iE-ID"                       , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_iE_ID },
  { "repetitionNumber"            , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_repetitionNumber },
  { "iE-Extensions"               , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_iE_Extensions },
  { NULL, 0, 0, NULL }
};

static int
dissect_ranap_CriticalityDiagnostics_IE_List_item(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ranap_CriticalityDiagnostics_IE_List_item, CriticalityDiagnostics_IE_List_item_sequence);

  return offset;
}
static int dissect_CriticalityDiagnostics_IE_List_item(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_ranap_CriticalityDiagnostics_IE_List_item(tvb, offset, actx, tree, hf_ranap_CriticalityDiagnostics_IE_List_item);
}


static const per_sequence_t CriticalityDiagnostics_IE_List_sequence_of[1] = {
  { ""                            , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_CriticalityDiagnostics_IE_List_item },
};

static int
dissect_ranap_CriticalityDiagnostics_IE_List(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_ranap_CriticalityDiagnostics_IE_List, CriticalityDiagnostics_IE_List_sequence_of,
                                                  1, 256);

  return offset;
}
static int dissect_iEsCriticalityDiagnostics(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_ranap_CriticalityDiagnostics_IE_List(tvb, offset, actx, tree, hf_ranap_iEsCriticalityDiagnostics);
}


static const per_sequence_t CriticalityDiagnostics_sequence[] = {
  { "procedureCode"               , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_procedureCode },
  { "triggeringMessage"           , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_triggeringMessage },
  { "procedureCriticality"        , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_procedureCriticality },
  { "iEsCriticalityDiagnostics"   , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_iEsCriticalityDiagnostics },
  { "iE-Extensions"               , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_iE_Extensions },
  { NULL, 0, 0, NULL }
};

static int
dissect_ranap_CriticalityDiagnostics(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ranap_CriticalityDiagnostics, CriticalityDiagnostics_sequence);

  return offset;
}
static int dissect_id_CriticalityDiagnostics(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_ranap_CriticalityDiagnostics(tvb, offset, actx, tree, hf_ranap_id_CriticalityDiagnostics);
}



static int
dissect_ranap_RAC(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_octet_string(tvb, offset, actx, tree, hf_index,
                                       1, 1, NULL);

  return offset;
}
static int dissect_id_RAC(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_ranap_RAC(tvb, offset, actx, tree, hf_ranap_id_RAC);
}
static int dissect_NewRAListofIdleModeUEs_item(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_ranap_RAC(tvb, offset, actx, tree, hf_ranap_NewRAListofIdleModeUEs_item);
}
static int dissect_RAListwithNoIdleModeUEsAnyMore_item(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_ranap_RAC(tvb, offset, actx, tree, hf_ranap_RAListwithNoIdleModeUEsAnyMore_item);
}
static int dissect_rAC(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_ranap_RAC(tvb, offset, actx, tree, hf_ranap_rAC);
}
static int dissect_RAofIdleModeUEs_item(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_ranap_RAC(tvb, offset, actx, tree, hf_ranap_RAofIdleModeUEs_item);
}


static const per_sequence_t NewRAListofIdleModeUEs_sequence_of[1] = {
  { ""                            , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_NewRAListofIdleModeUEs_item },
};

static int
dissect_ranap_NewRAListofIdleModeUEs(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_ranap_NewRAListofIdleModeUEs, NewRAListofIdleModeUEs_sequence_of,
                                                  1, 65536);

  return offset;
}
static int dissect_newRAListofIdleModeUEs(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_ranap_NewRAListofIdleModeUEs(tvb, offset, actx, tree, hf_ranap_newRAListofIdleModeUEs);
}


static const per_sequence_t RAListwithNoIdleModeUEsAnyMore_sequence_of[1] = {
  { ""                            , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_RAListwithNoIdleModeUEsAnyMore_item },
};

static int
dissect_ranap_RAListwithNoIdleModeUEsAnyMore(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_ranap_RAListwithNoIdleModeUEsAnyMore, RAListwithNoIdleModeUEsAnyMore_sequence_of,
                                                  1, 65536);

  return offset;
}
static int dissect_rAListwithNoIdleModeUEsAnyMore(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_ranap_RAListwithNoIdleModeUEsAnyMore(tvb, offset, actx, tree, hf_ranap_rAListwithNoIdleModeUEsAnyMore);
}


static const per_sequence_t DeltaRAListofIdleModeUEs_sequence[] = {
  { "newRAListofIdleModeUEs"      , ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_newRAListofIdleModeUEs },
  { "rAListwithNoIdleModeUEsAnyMore", ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_rAListwithNoIdleModeUEsAnyMore },
  { "iE-Extensions"               , ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_iE_Extensions },
  { NULL, 0, 0, NULL }
};

static int
dissect_ranap_DeltaRAListofIdleModeUEs(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ranap_DeltaRAListofIdleModeUEs, DeltaRAListofIdleModeUEs_sequence);

  return offset;
}
static int dissect_id_DeltaRAListofIdleModeUEs(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_ranap_DeltaRAListofIdleModeUEs(tvb, offset, actx, tree, hf_ranap_id_DeltaRAListofIdleModeUEs);
}



static int
dissect_ranap_DRX_CycleLengthCoefficient(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                              6U, 9U, NULL, FALSE);

  return offset;
}
static int dissect_id_DRX_CycleLengthCoefficient(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_ranap_DRX_CycleLengthCoefficient(tvb, offset, actx, tree, hf_ranap_id_DRX_CycleLengthCoefficient);
}



static int
dissect_ranap_NAS_PDU(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
#line 57 "ranap.cnf"

tvbuff_t *nas_pdu_tvb=NULL;

  offset = dissect_per_octet_string(tvb, offset, actx, tree, hf_index,
                                       NO_BOUND, NO_BOUND, &nas_pdu_tvb);


	if (nas_pdu_tvb)
		dissector_try_port(nas_pdu_dissector_table, 0x1, nas_pdu_tvb, actx->pinfo, top_tree);



  return offset;
}
static int dissect_id_NAS_PDU(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_ranap_NAS_PDU(tvb, offset, actx, tree, hf_ranap_id_NAS_PDU);
}
static int dissect_nAS_PDU(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_ranap_NAS_PDU(tvb, offset, actx, tree, hf_ranap_nAS_PDU);
}


static const value_string ranap_SAPI_vals[] = {
  {   0, "sapi-0" },
  {   1, "sapi-3" },
  { 0, NULL }
};


static int
dissect_ranap_SAPI(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     2, NULL, TRUE, 0, NULL);

  return offset;
}
static int dissect_id_SAPI(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_ranap_SAPI(tvb, offset, actx, tree, hf_ranap_id_SAPI);
}
static int dissect_sAPI(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_ranap_SAPI(tvb, offset, actx, tree, hf_ranap_sAPI);
}


static const per_sequence_t DirectTransferInformationItem_RANAP_RelocInf_sequence[] = {
  { "nAS-PDU"                     , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_nAS_PDU },
  { "sAPI"                        , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_sAPI },
  { "cN-DomainIndicator"          , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_cN_DomainIndicator },
  { "iE-Extensions"               , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_iE_Extensions },
  { NULL, 0, 0, NULL }
};

static int
dissect_ranap_DirectTransferInformationItem_RANAP_RelocInf(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ranap_DirectTransferInformationItem_RANAP_RelocInf, DirectTransferInformationItem_RANAP_RelocInf_sequence);

  return offset;
}
static int dissect_id_DirectTransferInformationItem_RANAP_RelocInf(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_ranap_DirectTransferInformationItem_RANAP_RelocInf(tvb, offset, actx, tree, hf_ranap_id_DirectTransferInformationItem_RANAP_RelocInf);
}


static const per_sequence_t ProtocolIE_ContainerList15_sequence_of[1] = {
  { ""                            , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ProtocolIE_ContainerList15_item },
};

static int
dissect_ranap_ProtocolIE_ContainerList15(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_ranap_ProtocolIE_ContainerList15, ProtocolIE_ContainerList15_sequence_of,
                                                  1, 15);

  return offset;
}



static int
dissect_ranap_DirectTransfer_IE_ContainerList(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_ranap_ProtocolIE_ContainerList15(tvb, offset, actx, tree, hf_index);

  return offset;
}



static int
dissect_ranap_DirectTransferInformationList_RANAP_RelocInf(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_ranap_DirectTransfer_IE_ContainerList(tvb, offset, actx, tree, hf_index);

  return offset;
}
static int dissect_id_DirectTransferInformationList_RANAP_RelocInf(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_ranap_DirectTransferInformationList_RANAP_RelocInf(tvb, offset, actx, tree, hf_ranap_id_DirectTransferInformationList_RANAP_RelocInf);
}



static int
dissect_ranap_DL_GTP_PDU_SequenceNumber(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                              0U, 65535U, NULL, FALSE);

  return offset;
}
static int dissect_id_DL_GTP_PDU_SequenceNumber(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_ranap_DL_GTP_PDU_SequenceNumber(tvb, offset, actx, tree, hf_ranap_id_DL_GTP_PDU_SequenceNumber);
}
static int dissect_dL_GTP_PDU_SequenceNumber(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_ranap_DL_GTP_PDU_SequenceNumber(tvb, offset, actx, tree, hf_ranap_dL_GTP_PDU_SequenceNumber);
}
static int dissect_dl_GTP_PDU_SequenceNumber(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_ranap_DL_GTP_PDU_SequenceNumber(tvb, offset, actx, tree, hf_ranap_dl_GTP_PDU_SequenceNumber);
}


static const per_sequence_t PermittedEncryptionAlgorithms_sequence_of[1] = {
  { ""                            , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_PermittedEncryptionAlgorithms_item },
};

static int
dissect_ranap_PermittedEncryptionAlgorithms(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_ranap_PermittedEncryptionAlgorithms, PermittedEncryptionAlgorithms_sequence_of,
                                                  1, 16);

  return offset;
}
static int dissect_encryptionpermittedAlgorithms(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_ranap_PermittedEncryptionAlgorithms(tvb, offset, actx, tree, hf_ranap_encryptionpermittedAlgorithms);
}



static int
dissect_ranap_EncryptionKey(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_bit_string(tvb, offset, actx, tree, hf_index,
                                     128, 128, FALSE);

  return offset;
}
static int dissect_encryptionkey(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_ranap_EncryptionKey(tvb, offset, actx, tree, hf_ranap_encryptionkey);
}
static int dissect_cipheringKey(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_ranap_EncryptionKey(tvb, offset, actx, tree, hf_ranap_cipheringKey);
}


static const per_sequence_t EncryptionInformation_sequence[] = {
  { "encryptionpermittedAlgorithms", ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_encryptionpermittedAlgorithms },
  { "encryptionkey"               , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_encryptionkey },
  { "iE-Extensions"               , ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_iE_Extensions },
  { NULL, 0, 0, NULL }
};

static int
dissect_ranap_EncryptionInformation(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ranap_EncryptionInformation, EncryptionInformation_sequence);

  return offset;
}
static int dissect_id_EncryptionInformation(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_ranap_EncryptionInformation(tvb, offset, actx, tree, hf_ranap_id_EncryptionInformation);
}


static const value_string ranap_FrequenceLayerConvergenceFlag_vals[] = {
  {   0, "no-FLC-flag" },
  { 0, NULL }
};


static int
dissect_ranap_FrequenceLayerConvergenceFlag(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     1, NULL, TRUE, 0, NULL);

  return offset;
}
static int dissect_id_FrequenceLayerConvergenceFlag(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_ranap_FrequenceLayerConvergenceFlag(tvb, offset, actx, tree, hf_ranap_id_FrequenceLayerConvergenceFlag);
}



static int
dissect_ranap_GERAN_BSC_Container(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_octet_string(tvb, offset, actx, tree, hf_index,
                                       NO_BOUND, NO_BOUND, NULL);

  return offset;
}
static int dissect_id_GERAN_BSC_Container(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_ranap_GERAN_BSC_Container(tvb, offset, actx, tree, hf_ranap_id_GERAN_BSC_Container);
}



static int
dissect_ranap_GERAN_Classmark(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_octet_string(tvb, offset, actx, tree, hf_index,
                                       NO_BOUND, NO_BOUND, NULL);

  return offset;
}
static int dissect_id_GERAN_Classmark(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_ranap_GERAN_Classmark(tvb, offset, actx, tree, hf_ranap_id_GERAN_Classmark);
}
static int dissect_gERAN_Classmark(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_ranap_GERAN_Classmark(tvb, offset, actx, tree, hf_ranap_gERAN_Classmark);
}



static int
dissect_ranap_RAB_ID(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_bit_string(tvb, offset, actx, tree, hf_index,
                                     8, 8, FALSE);

  return offset;
}
static int dissect_id_RAB_ID(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_ranap_RAB_ID(tvb, offset, actx, tree, hf_ranap_id_RAB_ID);
}
static int dissect_rAB_ID(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_ranap_RAB_ID(tvb, offset, actx, tree, hf_ranap_rAB_ID);
}


static const per_sequence_t GERAN_Iumode_RAB_Failed_RABAssgntResponse_Item_sequence[] = {
  { "rAB-ID"                      , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_rAB_ID },
  { "cause"                       , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_cause },
  { "gERAN-Classmark"             , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_gERAN_Classmark },
  { "iE-Extensions"               , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_iE_Extensions },
  { NULL, 0, 0, NULL }
};

static int
dissect_ranap_GERAN_Iumode_RAB_Failed_RABAssgntResponse_Item(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ranap_GERAN_Iumode_RAB_Failed_RABAssgntResponse_Item, GERAN_Iumode_RAB_Failed_RABAssgntResponse_Item_sequence);

  return offset;
}
static int dissect_id_GERAN_Iumode_RAB_Failed_RABAssgntResponse_Item(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_ranap_GERAN_Iumode_RAB_Failed_RABAssgntResponse_Item(tvb, offset, actx, tree, hf_ranap_id_GERAN_Iumode_RAB_Failed_RABAssgntResponse_Item);
}


static const per_sequence_t ProtocolIE_ContainerList256_sequence_of[1] = {
  { ""                            , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ProtocolIE_ContainerList256_item },
};

static int
dissect_ranap_ProtocolIE_ContainerList256(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_ranap_ProtocolIE_ContainerList256, ProtocolIE_ContainerList256_sequence_of,
                                                  1, 256);

  return offset;
}



static int
dissect_ranap_RAB_IE_ContainerList(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_ranap_ProtocolIE_ContainerList256(tvb, offset, actx, tree, hf_index);

  return offset;
}



static int
dissect_ranap_GERAN_Iumode_RAB_FailedList_RABAssgntResponse(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_ranap_RAB_IE_ContainerList(tvb, offset, actx, tree, hf_index);

  return offset;
}
static int dissect_id_GERAN_Iumode_RAB_FailedList_RABAssgntResponse(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_ranap_GERAN_Iumode_RAB_FailedList_RABAssgntResponse(tvb, offset, actx, tree, hf_ranap_id_GERAN_Iumode_RAB_FailedList_RABAssgntResponse);
}



static int
dissect_ranap_CN_ID(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                              0U, 4095U, NULL, FALSE);

  return offset;
}
static int dissect_cN_ID(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_ranap_CN_ID(tvb, offset, actx, tree, hf_ranap_cN_ID);
}


static const per_sequence_t GlobalCN_ID_sequence[] = {
  { "pLMNidentity"                , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_pLMNidentity },
  { "cN-ID"                       , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_cN_ID },
  { NULL, 0, 0, NULL }
};

static int
dissect_ranap_GlobalCN_ID(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ranap_GlobalCN_ID, GlobalCN_ID_sequence);

  return offset;
}
static int dissect_id_GlobalCN_ID(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_ranap_GlobalCN_ID(tvb, offset, actx, tree, hf_ranap_id_GlobalCN_ID);
}



static int
dissect_ranap_RNC_ID(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                              0U, 4095U, NULL, FALSE);

  return offset;
}
static int dissect_rNC_ID(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_ranap_RNC_ID(tvb, offset, actx, tree, hf_ranap_rNC_ID);
}


static const per_sequence_t GlobalRNC_ID_sequence[] = {
  { "pLMNidentity"                , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_pLMNidentity },
  { "rNC-ID"                      , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_rNC_ID },
  { NULL, 0, 0, NULL }
};

static int
dissect_ranap_GlobalRNC_ID(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ranap_GlobalRNC_ID, GlobalRNC_ID_sequence);

  return offset;
}
static int dissect_id_GlobalRNC_ID(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_ranap_GlobalRNC_ID(tvb, offset, actx, tree, hf_ranap_id_GlobalRNC_ID);
}
static int dissect_globalRNC_ID(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_ranap_GlobalRNC_ID(tvb, offset, actx, tree, hf_ranap_globalRNC_ID);
}



static int
dissect_ranap_InformationExchangeID(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                              0U, 1048575U, NULL, FALSE);

  return offset;
}
static int dissect_id_InformationExchangeID(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_ranap_InformationExchangeID(tvb, offset, actx, tree, hf_ranap_id_InformationExchangeID);
}


static const value_string ranap_InformationExchangeType_vals[] = {
  {   0, "transfer" },
  {   1, "request" },
  { 0, NULL }
};


static int
dissect_ranap_InformationExchangeType(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     2, NULL, TRUE, 0, NULL);

  return offset;
}
static int dissect_id_InformationExchangeType(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_ranap_InformationExchangeType(tvb, offset, actx, tree, hf_ranap_id_InformationExchangeType);
}



static int
dissect_ranap_IPMulticastAddress(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_octet_string(tvb, offset, actx, tree, hf_index,
                                       4, 16, NULL);

  return offset;
}
static int dissect_id_IPMulticastAddress(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_ranap_IPMulticastAddress(tvb, offset, actx, tree, hf_ranap_id_IPMulticastAddress);
}
static int dissect_iPMulticastAddress(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_ranap_IPMulticastAddress(tvb, offset, actx, tree, hf_ranap_iPMulticastAddress);
}


static const per_sequence_t MBMSIPMulticastAddressandAPNlist_sequence[] = {
  { "tMGI"                        , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_tMGI },
  { "iPMulticastAddress"          , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_iPMulticastAddress },
  { "aPN"                         , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_aPN },
  { "iE-Extensions"               , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_iE_Extensions },
  { NULL, 0, 0, NULL }
};

static int
dissect_ranap_MBMSIPMulticastAddressandAPNlist(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ranap_MBMSIPMulticastAddressandAPNlist, MBMSIPMulticastAddressandAPNlist_sequence);

  return offset;
}
static int dissect_RequestedMBMSIPMulticastAddressandAPNRequest_item(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_ranap_MBMSIPMulticastAddressandAPNlist(tvb, offset, actx, tree, hf_ranap_RequestedMBMSIPMulticastAddressandAPNRequest_item);
}


static const per_sequence_t RequestedMBMSIPMulticastAddressandAPNRequest_sequence_of[1] = {
  { ""                            , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_RequestedMBMSIPMulticastAddressandAPNRequest_item },
};

static int
dissect_ranap_RequestedMBMSIPMulticastAddressandAPNRequest(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_ranap_RequestedMBMSIPMulticastAddressandAPNRequest, RequestedMBMSIPMulticastAddressandAPNRequest_sequence_of,
                                                  1, 512);

  return offset;
}
static int dissect_requestedMBMSIPMulticastAddressandAPNRequest(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_ranap_RequestedMBMSIPMulticastAddressandAPNRequest(tvb, offset, actx, tree, hf_ranap_requestedMBMSIPMulticastAddressandAPNRequest);
}


static const per_sequence_t RequestedMulticastServiceList_sequence_of[1] = {
  { ""                            , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_RequestedMulticastServiceList_item },
};

static int
dissect_ranap_RequestedMulticastServiceList(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_ranap_RequestedMulticastServiceList, RequestedMulticastServiceList_sequence_of,
                                                  1, 128);

  return offset;
}
static int dissect_requestedMulticastServiceList(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_ranap_RequestedMulticastServiceList(tvb, offset, actx, tree, hf_ranap_requestedMulticastServiceList);
}


static const value_string ranap_InformationRequested_vals[] = {
  {   0, "requestedMBMSIPMulticastAddressandAPNRequest" },
  {   1, "requestedMulticastServiceList" },
  { 0, NULL }
};

static const per_choice_t InformationRequested_choice[] = {
  {   0, "requestedMBMSIPMulticastAddressandAPNRequest", ASN1_EXTENSION_ROOT    , dissect_requestedMBMSIPMulticastAddressandAPNRequest },
  {   1, "requestedMulticastServiceList", ASN1_EXTENSION_ROOT    , dissect_requestedMulticastServiceList },
  { 0, NULL, 0, NULL }
};

static int
dissect_ranap_InformationRequested(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_ranap_InformationRequested, InformationRequested_choice,
                                 NULL);

  return offset;
}
static int dissect_id_InformationRequested(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_ranap_InformationRequested(tvb, offset, actx, tree, hf_ranap_id_InformationRequested);
}


static const per_sequence_t MBMSIPMulticastAddressandAPNRequest_sequence_of[1] = {
  { ""                            , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_MBMSIPMulticastAddressandAPNRequest_item },
};

static int
dissect_ranap_MBMSIPMulticastAddressandAPNRequest(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_ranap_MBMSIPMulticastAddressandAPNRequest, MBMSIPMulticastAddressandAPNRequest_sequence_of,
                                                  1, 512);

  return offset;
}
static int dissect_mBMSIPMulticastAddressandAPNRequest(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_ranap_MBMSIPMulticastAddressandAPNRequest(tvb, offset, actx, tree, hf_ranap_mBMSIPMulticastAddressandAPNRequest);
}



static int
dissect_ranap_IMSI(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_octet_string(tvb, offset, actx, tree, hf_index,
                                       3, 8, NULL);

  return offset;
}
static int dissect_iMSI(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_ranap_IMSI(tvb, offset, actx, tree, hf_ranap_iMSI);
}
static int dissect_imsi(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_ranap_IMSI(tvb, offset, actx, tree, hf_ranap_imsi);
}


static const value_string ranap_PermanentNAS_UE_ID_vals[] = {
  {   0, "iMSI" },
  { 0, NULL }
};

static const per_choice_t PermanentNAS_UE_ID_choice[] = {
  {   0, "iMSI"                        , ASN1_EXTENSION_ROOT    , dissect_iMSI },
  { 0, NULL, 0, NULL }
};

static int
dissect_ranap_PermanentNAS_UE_ID(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_ranap_PermanentNAS_UE_ID, PermanentNAS_UE_ID_choice,
                                 NULL);

  return offset;
}
static int dissect_id_PermanentNAS_UE_ID(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_ranap_PermanentNAS_UE_ID(tvb, offset, actx, tree, hf_ranap_id_PermanentNAS_UE_ID);
}
static int dissect_permanentNAS_UE_ID(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_ranap_PermanentNAS_UE_ID(tvb, offset, actx, tree, hf_ranap_permanentNAS_UE_ID);
}


static const value_string ranap_InformationRequestType_vals[] = {
  {   0, "mBMSIPMulticastAddressandAPNRequest" },
  {   1, "permanentNAS-UE-ID" },
  { 0, NULL }
};

static const per_choice_t InformationRequestType_choice[] = {
  {   0, "mBMSIPMulticastAddressandAPNRequest", ASN1_EXTENSION_ROOT    , dissect_mBMSIPMulticastAddressandAPNRequest },
  {   1, "permanentNAS-UE-ID"          , ASN1_EXTENSION_ROOT    , dissect_permanentNAS_UE_ID },
  { 0, NULL, 0, NULL }
};

static int
dissect_ranap_InformationRequestType(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_ranap_InformationRequestType, InformationRequestType_choice,
                                 NULL);

  return offset;
}
static int dissect_id_InformationRequestType(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_ranap_InformationRequestType(tvb, offset, actx, tree, hf_ranap_id_InformationRequestType);
}



static int
dissect_ranap_InformationTransferID(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                              0U, 1048575U, NULL, FALSE);

  return offset;
}
static int dissect_id_InformationTransferID(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_ranap_InformationTransferID(tvb, offset, actx, tree, hf_ranap_id_InformationTransferID);
}



static int
dissect_ranap_TraceReference(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_octet_string(tvb, offset, actx, tree, hf_index,
                                       2, 3, NULL);

  return offset;
}
static int dissect_id_TraceReference(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_ranap_TraceReference(tvb, offset, actx, tree, hf_ranap_id_TraceReference);
}
static int dissect_traceReference(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_ranap_TraceReference(tvb, offset, actx, tree, hf_ranap_traceReference);
}


static const value_string ranap_T_traceActivationIndicator_vals[] = {
  {   0, "activated" },
  {   1, "deactivated" },
  { 0, NULL }
};


static int
dissect_ranap_T_traceActivationIndicator(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     2, NULL, FALSE, 0, NULL);

  return offset;
}
static int dissect_traceActivationIndicator(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_ranap_T_traceActivationIndicator(tvb, offset, actx, tree, hf_ranap_traceActivationIndicator);
}



static int
dissect_ranap_IMEI(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_octet_string(tvb, offset, actx, tree, hf_index,
                                       8, 8, NULL);

  return offset;
}
static int dissect_iMEI(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_ranap_IMEI(tvb, offset, actx, tree, hf_ranap_iMEI);
}
static int dissect_IMEIList_item(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_ranap_IMEI(tvb, offset, actx, tree, hf_ranap_IMEIList_item);
}
static int dissect_imei(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_ranap_IMEI(tvb, offset, actx, tree, hf_ranap_imei);
}


static const per_sequence_t IMEIList_sequence_of[1] = {
  { ""                            , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_IMEIList_item },
};

static int
dissect_ranap_IMEIList(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_ranap_IMEIList, IMEIList_sequence_of,
                                                  1, 64);

  return offset;
}
static int dissect_iMEIlist(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_ranap_IMEIList(tvb, offset, actx, tree, hf_ranap_iMEIlist);
}



static int
dissect_ranap_IMEISV(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_octet_string(tvb, offset, actx, tree, hf_index,
                                       8, 8, NULL);

  return offset;
}
static int dissect_iMEISV(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_ranap_IMEISV(tvb, offset, actx, tree, hf_ranap_iMEISV);
}
static int dissect_IMEISVList_item(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_ranap_IMEISV(tvb, offset, actx, tree, hf_ranap_IMEISVList_item);
}
static int dissect_imeisv(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_ranap_IMEISV(tvb, offset, actx, tree, hf_ranap_imeisv);
}


static const per_sequence_t IMEISVList_sequence_of[1] = {
  { ""                            , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_IMEISVList_item },
};

static int
dissect_ranap_IMEISVList(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_ranap_IMEISVList, IMEISVList_sequence_of,
                                                  1, 64);

  return offset;
}
static int dissect_iMEISVlist(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_ranap_IMEISVList(tvb, offset, actx, tree, hf_ranap_iMEISVlist);
}



static int
dissect_ranap_BIT_STRING_SIZE_7(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_bit_string(tvb, offset, actx, tree, hf_index,
                                     7, 7, FALSE);

  return offset;
}
static int dissect_iMEIMask(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_ranap_BIT_STRING_SIZE_7(tvb, offset, actx, tree, hf_ranap_iMEIMask);
}
static int dissect_iMEISVMask(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_ranap_BIT_STRING_SIZE_7(tvb, offset, actx, tree, hf_ranap_iMEISVMask);
}


static const per_sequence_t IMEIGroup_sequence[] = {
  { "iMEI"                        , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_iMEI },
  { "iMEIMask"                    , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_iMEIMask },
  { "iE-Extensions"               , ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_iE_Extensions },
  { NULL, 0, 0, NULL }
};

static int
dissect_ranap_IMEIGroup(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ranap_IMEIGroup, IMEIGroup_sequence);

  return offset;
}
static int dissect_iMEIgroup(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_ranap_IMEIGroup(tvb, offset, actx, tree, hf_ranap_iMEIgroup);
}


static const per_sequence_t IMEISVGroup_sequence[] = {
  { "iMEISV"                      , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_iMEISV },
  { "iMEISVMask"                  , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_iMEISVMask },
  { "iE-Extensions"               , ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_iE_Extensions },
  { NULL, 0, 0, NULL }
};

static int
dissect_ranap_IMEISVGroup(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ranap_IMEISVGroup, IMEISVGroup_sequence);

  return offset;
}
static int dissect_iMEISVgroup(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_ranap_IMEISVGroup(tvb, offset, actx, tree, hf_ranap_iMEISVgroup);
}


static const value_string ranap_EquipmentsToBeTraced_vals[] = {
  {   0, "iMEIlist" },
  {   1, "iMEISVlist" },
  {   2, "iMEIgroup" },
  {   3, "iMEISVgroup" },
  { 0, NULL }
};

static const per_choice_t EquipmentsToBeTraced_choice[] = {
  {   0, "iMEIlist"                    , ASN1_EXTENSION_ROOT    , dissect_iMEIlist },
  {   1, "iMEISVlist"                  , ASN1_EXTENSION_ROOT    , dissect_iMEISVlist },
  {   2, "iMEIgroup"                   , ASN1_EXTENSION_ROOT    , dissect_iMEIgroup },
  {   3, "iMEISVgroup"                 , ASN1_EXTENSION_ROOT    , dissect_iMEISVgroup },
  { 0, NULL, 0, NULL }
};

static int
dissect_ranap_EquipmentsToBeTraced(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_ranap_EquipmentsToBeTraced, EquipmentsToBeTraced_choice,
                                 NULL);

  return offset;
}
static int dissect_equipmentsToBeTraced(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_ranap_EquipmentsToBeTraced(tvb, offset, actx, tree, hf_ranap_equipmentsToBeTraced);
}


static const per_sequence_t RNCTraceInformation_sequence[] = {
  { "traceReference"              , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_traceReference },
  { "traceActivationIndicator"    , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_traceActivationIndicator },
  { "equipmentsToBeTraced"        , ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_equipmentsToBeTraced },
  { "iE-Extensions"               , ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_iE_Extensions },
  { NULL, 0, 0, NULL }
};

static int
dissect_ranap_RNCTraceInformation(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ranap_RNCTraceInformation, RNCTraceInformation_sequence);

  return offset;
}
static int dissect_rNCTraceInformation(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_ranap_RNCTraceInformation(tvb, offset, actx, tree, hf_ranap_rNCTraceInformation);
}


static const value_string ranap_InformationTransferType_vals[] = {
  {   0, "rNCTraceInformation" },
  { 0, NULL }
};

static const per_choice_t InformationTransferType_choice[] = {
  {   0, "rNCTraceInformation"         , ASN1_EXTENSION_ROOT    , dissect_rNCTraceInformation },
  { 0, NULL, 0, NULL }
};

static int
dissect_ranap_InformationTransferType(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_ranap_InformationTransferType, InformationTransferType_choice,
                                 NULL);

  return offset;
}
static int dissect_id_InformationTransferType(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_ranap_InformationTransferType(tvb, offset, actx, tree, hf_ranap_id_InformationTransferType);
}



static int
dissect_ranap_TraceRecordingSessionReference(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                              0U, 65535U, NULL, FALSE);

  return offset;
}
static int dissect_traceRecordingSessionReference(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_ranap_TraceRecordingSessionReference(tvb, offset, actx, tree, hf_ranap_traceRecordingSessionReference);
}


static const per_sequence_t TraceRecordingSessionInformation_sequence[] = {
  { "traceReference"              , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_traceReference },
  { "traceRecordingSessionReference", ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_traceRecordingSessionReference },
  { "iE-Extensions"               , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_iE_Extensions },
  { NULL, 0, 0, NULL }
};

static int
dissect_ranap_TraceRecordingSessionInformation(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ranap_TraceRecordingSessionInformation, TraceRecordingSessionInformation_sequence);

  return offset;
}
static int dissect_id_TraceRecordingSessionInformation(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_ranap_TraceRecordingSessionInformation(tvb, offset, actx, tree, hf_ranap_id_TraceRecordingSessionInformation);
}


static const per_sequence_t PermittedIntegrityProtectionAlgorithms_sequence_of[1] = {
  { ""                            , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_PermittedIntegrityProtectionAlgorithms_item },
};

static int
dissect_ranap_PermittedIntegrityProtectionAlgorithms(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_ranap_PermittedIntegrityProtectionAlgorithms, PermittedIntegrityProtectionAlgorithms_sequence_of,
                                                  1, 16);

  return offset;
}
static int dissect_permittedAlgorithms(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_ranap_PermittedIntegrityProtectionAlgorithms(tvb, offset, actx, tree, hf_ranap_permittedAlgorithms);
}



static int
dissect_ranap_IntegrityProtectionKey(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_bit_string(tvb, offset, actx, tree, hf_index,
                                     128, 128, FALSE);

  return offset;
}
static int dissect_key(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_ranap_IntegrityProtectionKey(tvb, offset, actx, tree, hf_ranap_key);
}
static int dissect_integrityProtectionKey(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_ranap_IntegrityProtectionKey(tvb, offset, actx, tree, hf_ranap_integrityProtectionKey);
}


static const per_sequence_t IntegrityProtectionInformation_sequence[] = {
  { "permittedAlgorithms"         , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_permittedAlgorithms },
  { "key"                         , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_key },
  { "iE-Extensions"               , ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_iE_Extensions },
  { NULL, 0, 0, NULL }
};

static int
dissect_ranap_IntegrityProtectionInformation(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ranap_IntegrityProtectionInformation, IntegrityProtectionInformation_sequence);

  return offset;
}
static int dissect_id_IntegrityProtectionInformation(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_ranap_IntegrityProtectionInformation(tvb, offset, actx, tree, hf_ranap_id_IntegrityProtectionInformation);
}



static int
dissect_ranap_RIMInformation(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_octet_string(tvb, offset, actx, tree, hf_index,
                                       NO_BOUND, NO_BOUND, NULL);

  return offset;
}
static int dissect_rIMInformation(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_ranap_RIMInformation(tvb, offset, actx, tree, hf_ranap_rIMInformation);
}


static const per_sequence_t LAI_sequence[] = {
  { "pLMNidentity"                , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_pLMNidentity },
  { "lAC"                         , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_lAC },
  { "iE-Extensions"               , ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_iE_Extensions },
  { NULL, 0, 0, NULL }
};

static int
dissect_ranap_LAI(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ranap_LAI, LAI_sequence);

  return offset;
}
static int dissect_id_LAI(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_ranap_LAI(tvb, offset, actx, tree, hf_ranap_id_LAI);
}
static int dissect_lAI(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_ranap_LAI(tvb, offset, actx, tree, hf_ranap_lAI);
}



static int
dissect_ranap_CI(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_octet_string(tvb, offset, actx, tree, hf_index,
                                       2, 2, NULL);

  return offset;
}
static int dissect_cI(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_ranap_CI(tvb, offset, actx, tree, hf_ranap_cI);
}


static const per_sequence_t GERAN_Cell_ID_sequence[] = {
  { "lAI"                         , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_lAI },
  { "rAC"                         , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_rAC },
  { "cI"                          , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_cI },
  { "iE-Extensions"               , ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_iE_Extensions },
  { NULL, 0, 0, NULL }
};

static int
dissect_ranap_GERAN_Cell_ID(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ranap_GERAN_Cell_ID, GERAN_Cell_ID_sequence);

  return offset;
}
static int dissect_gERAN_Cell_ID(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_ranap_GERAN_Cell_ID(tvb, offset, actx, tree, hf_ranap_gERAN_Cell_ID);
}


static const value_string ranap_RIMRoutingAddress_vals[] = {
  {   0, "globalRNC-ID" },
  {   1, "gERAN-Cell-ID" },
  { 0, NULL }
};

static const per_choice_t RIMRoutingAddress_choice[] = {
  {   0, "globalRNC-ID"                , ASN1_EXTENSION_ROOT    , dissect_globalRNC_ID },
  {   1, "gERAN-Cell-ID"               , ASN1_EXTENSION_ROOT    , dissect_gERAN_Cell_ID },
  { 0, NULL, 0, NULL }
};

static int
dissect_ranap_RIMRoutingAddress(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_ranap_RIMRoutingAddress, RIMRoutingAddress_choice,
                                 NULL);

  return offset;
}
static int dissect_rIMRoutingAddress(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_ranap_RIMRoutingAddress(tvb, offset, actx, tree, hf_ranap_rIMRoutingAddress);
}


static const per_sequence_t RIM_Transfer_sequence[] = {
  { "rIMInformation"              , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_rIMInformation },
  { "rIMRoutingAddress"           , ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_rIMRoutingAddress },
  { "iE-Extensions"               , ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_iE_Extensions },
  { NULL, 0, 0, NULL }
};

static int
dissect_ranap_RIM_Transfer(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ranap_RIM_Transfer, RIM_Transfer_sequence);

  return offset;
}
static int dissect_rIM_Transfer(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_ranap_RIM_Transfer(tvb, offset, actx, tree, hf_ranap_rIM_Transfer);
}


static const value_string ranap_InterSystemInformationTransferType_vals[] = {
  {   0, "rIM-Transfer" },
  { 0, NULL }
};

static const per_choice_t InterSystemInformationTransferType_choice[] = {
  {   0, "rIM-Transfer"                , ASN1_EXTENSION_ROOT    , dissect_rIM_Transfer },
  { 0, NULL, 0, NULL }
};

static int
dissect_ranap_InterSystemInformationTransferType(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_ranap_InterSystemInformationTransferType, InterSystemInformationTransferType_choice,
                                 NULL);

  return offset;
}
static int dissect_id_InterSystemInformationTransferType(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_ranap_InterSystemInformationTransferType(tvb, offset, actx, tree, hf_ranap_id_InterSystemInformationTransferType);
}



static int
dissect_ranap_Cell_Capacity_Class_Value(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                              1U, 100U, NULL, TRUE);

  return offset;
}
static int dissect_cell_Capacity_Class_Value(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_ranap_Cell_Capacity_Class_Value(tvb, offset, actx, tree, hf_ranap_cell_Capacity_Class_Value);
}



static int
dissect_ranap_LoadValue(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                              0U, 100U, NULL, FALSE);

  return offset;
}
static int dissect_loadValue(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_ranap_LoadValue(tvb, offset, actx, tree, hf_ranap_loadValue);
}



static int
dissect_ranap_RTLoadValue(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                              0U, 100U, NULL, FALSE);

  return offset;
}
static int dissect_rTLoadValue(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_ranap_RTLoadValue(tvb, offset, actx, tree, hf_ranap_rTLoadValue);
}



static int
dissect_ranap_NRTLoadInformationValue(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                              0U, 3U, NULL, FALSE);

  return offset;
}
static int dissect_nRTLoadInformationValue(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_ranap_NRTLoadInformationValue(tvb, offset, actx, tree, hf_ranap_nRTLoadInformationValue);
}


static const per_sequence_t CellLoadInformation_sequence[] = {
  { "cell-Capacity-Class-Value"   , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_cell_Capacity_Class_Value },
  { "loadValue"                   , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_loadValue },
  { "rTLoadValue"                 , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_rTLoadValue },
  { "nRTLoadInformationValue"     , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_nRTLoadInformationValue },
  { "iE-Extensions"               , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_iE_Extensions },
  { NULL, 0, 0, NULL }
};

static int
dissect_ranap_CellLoadInformation(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ranap_CellLoadInformation, CellLoadInformation_sequence);

  return offset;
}
static int dissect_uplinkCellLoadInformation(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_ranap_CellLoadInformation(tvb, offset, actx, tree, hf_ranap_uplinkCellLoadInformation);
}
static int dissect_downlinkCellLoadInformation(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_ranap_CellLoadInformation(tvb, offset, actx, tree, hf_ranap_downlinkCellLoadInformation);
}


static const per_sequence_t InterSystemInformation_TransparentContainer_sequence[] = {
  { "downlinkCellLoadInformation" , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_downlinkCellLoadInformation },
  { "uplinkCellLoadInformation"   , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_uplinkCellLoadInformation },
  { "iE-Extensions"               , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_iE_Extensions },
  { NULL, 0, 0, NULL }
};

static int
dissect_ranap_InterSystemInformation_TransparentContainer(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ranap_InterSystemInformation_TransparentContainer, InterSystemInformation_TransparentContainer_sequence);

  return offset;
}
static int dissect_id_InterSystemInformation_TransparentContainer(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_ranap_InterSystemInformation_TransparentContainer(tvb, offset, actx, tree, hf_ranap_id_InterSystemInformation_TransparentContainer);
}



static int
dissect_ranap_IuSignallingConnectionIdentifier(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_bit_string(tvb, offset, actx, tree, hf_index,
                                     24, 24, FALSE);

  return offset;
}
static int dissect_id_IuSigConId(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_ranap_IuSignallingConnectionIdentifier(tvb, offset, actx, tree, hf_ranap_id_IuSigConId);
}
static int dissect_iuSigConId(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_ranap_IuSignallingConnectionIdentifier(tvb, offset, actx, tree, hf_ranap_iuSigConId);
}


static const per_sequence_t ResetResourceAckItem_sequence[] = {
  { "iuSigConId"                  , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_iuSigConId },
  { "iE-Extensions"               , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_iE_Extensions },
  { NULL, 0, 0, NULL }
};

static int
dissect_ranap_ResetResourceAckItem(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ranap_ResetResourceAckItem, ResetResourceAckItem_sequence);

  return offset;
}
static int dissect_id_IuSigConIdItem(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_ranap_ResetResourceAckItem(tvb, offset, actx, tree, hf_ranap_id_IuSigConIdItem);
}


static const per_sequence_t ProtocolIE_ContainerList250_sequence_of[1] = {
  { ""                            , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ProtocolIE_ContainerList250_item },
};

static int
dissect_ranap_ProtocolIE_ContainerList250(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_ranap_ProtocolIE_ContainerList250, ProtocolIE_ContainerList250_sequence_of,
                                                  1, 250);

  return offset;
}



static int
dissect_ranap_IuSigConId_IE_ContainerList(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_ranap_ProtocolIE_ContainerList250(tvb, offset, actx, tree, hf_index);

  return offset;
}



static int
dissect_ranap_ResetResourceAckList(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_ranap_IuSigConId_IE_ContainerList(tvb, offset, actx, tree, hf_index);

  return offset;
}
static int dissect_id_IuSigConIdList(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_ranap_ResetResourceAckList(tvb, offset, actx, tree, hf_ranap_id_IuSigConIdList);
}



static int
dissect_ranap_GTP_TEI(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_octet_string(tvb, offset, actx, tree, hf_index,
                                       4, 4, NULL);

  return offset;
}
static int dissect_gTP_TEI(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_ranap_GTP_TEI(tvb, offset, actx, tree, hf_ranap_gTP_TEI);
}



static int
dissect_ranap_BindingID(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_octet_string(tvb, offset, actx, tree, hf_index,
                                       4, 4, NULL);

  return offset;
}
static int dissect_bindingID(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_ranap_BindingID(tvb, offset, actx, tree, hf_ranap_bindingID);
}


static const value_string ranap_IuTransportAssociation_vals[] = {
  {   0, "gTP-TEI" },
  {   1, "bindingID" },
  { 0, NULL }
};

static const per_choice_t IuTransportAssociation_choice[] = {
  {   0, "gTP-TEI"                     , ASN1_EXTENSION_ROOT    , dissect_gTP_TEI },
  {   1, "bindingID"                   , ASN1_EXTENSION_ROOT    , dissect_bindingID },
  { 0, NULL, 0, NULL }
};

static int
dissect_ranap_IuTransportAssociation(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_ranap_IuTransportAssociation, IuTransportAssociation_choice,
                                 NULL);

  return offset;
}
static int dissect_id_IuTransportAssociation(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_ranap_IuTransportAssociation(tvb, offset, actx, tree, hf_ranap_id_IuTransportAssociation);
}
static int dissect_iuTransportAssociation(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_ranap_IuTransportAssociation(tvb, offset, actx, tree, hf_ranap_iuTransportAssociation);
}


static const value_string ranap_KeyStatus_vals[] = {
  {   0, "old" },
  {   1, "new" },
  { 0, NULL }
};


static int
dissect_ranap_KeyStatus(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     2, NULL, TRUE, 0, NULL);

  return offset;
}
static int dissect_id_KeyStatus(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_ranap_KeyStatus(tvb, offset, actx, tree, hf_ranap_id_KeyStatus);
}



static int
dissect_ranap_L3_Information(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_octet_string(tvb, offset, actx, tree, hf_index,
                                       NO_BOUND, NO_BOUND, NULL);

  return offset;
}
static int dissect_id_L3_Information(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_ranap_L3_Information(tvb, offset, actx, tree, hf_ranap_id_L3_Information);
}


static const per_sequence_t LastKnownServiceArea_sequence[] = {
  { "sAI"                         , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_sAI },
  { "ageOfSAI"                    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ageOfSAI },
  { "iE-Extensions"               , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_iE_Extensions },
  { NULL, 0, 0, NULL }
};

static int
dissect_ranap_LastKnownServiceArea(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ranap_LastKnownServiceArea, LastKnownServiceArea_sequence);

  return offset;
}
static int dissect_id_LastKnownServiceArea(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_ranap_LastKnownServiceArea(tvb, offset, actx, tree, hf_ranap_id_LastKnownServiceArea);
}



static int
dissect_ranap_SRB_ID(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                              1U, 32U, NULL, FALSE);

  return offset;
}
static int dissect_sRB_ID(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_ranap_SRB_ID(tvb, offset, actx, tree, hf_ranap_sRB_ID);
}



static int
dissect_ranap_DCH_ID(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                              0U, 255U, NULL, FALSE);

  return offset;
}
static int dissect_dCH_ID(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_ranap_DCH_ID(tvb, offset, actx, tree, hf_ranap_dCH_ID);
}



static int
dissect_ranap_DSCH_ID(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                              0U, 255U, NULL, FALSE);

  return offset;
}
static int dissect_dSCH_ID(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_ranap_DSCH_ID(tvb, offset, actx, tree, hf_ranap_dSCH_ID);
}



static int
dissect_ranap_USCH_ID(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                              0U, 255U, NULL, FALSE);

  return offset;
}
static int dissect_uSCH_ID(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_ranap_USCH_ID(tvb, offset, actx, tree, hf_ranap_uSCH_ID);
}


static const per_sequence_t TrCH_ID_sequence[] = {
  { "dCH-ID"                      , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_dCH_ID },
  { "dSCH-ID"                     , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_dSCH_ID },
  { "uSCH-ID"                     , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_uSCH_ID },
  { "iE-Extensions"               , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_iE_Extensions },
  { NULL, 0, 0, NULL }
};

static int
dissect_ranap_TrCH_ID(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ranap_TrCH_ID, TrCH_ID_sequence);

  return offset;
}
static int dissect_trCH_ID(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_ranap_TrCH_ID(tvb, offset, actx, tree, hf_ranap_trCH_ID);
}
static int dissect_TrCH_ID_List_item(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_ranap_TrCH_ID(tvb, offset, actx, tree, hf_ranap_TrCH_ID_List_item);
}


static const per_sequence_t SRB_TrCH_MappingItem_sequence[] = {
  { "sRB-ID"                      , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_sRB_ID },
  { "trCH-ID"                     , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_trCH_ID },
  { "iE-Extensions"               , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_iE_Extensions },
  { NULL, 0, 0, NULL }
};

static int
dissect_ranap_SRB_TrCH_MappingItem(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ranap_SRB_TrCH_MappingItem, SRB_TrCH_MappingItem_sequence);

  return offset;
}
static int dissect_SRB_TrCH_Mapping_item(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_ranap_SRB_TrCH_MappingItem(tvb, offset, actx, tree, hf_ranap_SRB_TrCH_Mapping_item);
}


static const per_sequence_t SRB_TrCH_Mapping_sequence_of[1] = {
  { ""                            , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_SRB_TrCH_Mapping_item },
};

static int
dissect_ranap_SRB_TrCH_Mapping(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_ranap_SRB_TrCH_Mapping, SRB_TrCH_Mapping_sequence_of,
                                                  1, 8);

  return offset;
}
static int dissect_id_SRB_TrCH_Mapping(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_ranap_SRB_TrCH_Mapping(tvb, offset, actx, tree, hf_ranap_id_SRB_TrCH_Mapping);
}


static const per_sequence_t LeftMBMSBearerService_IEs_item_sequence[] = {
  { "tMGI"                        , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_tMGI },
  { NULL, 0, 0, NULL }
};

static int
dissect_ranap_LeftMBMSBearerService_IEs_item(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ranap_LeftMBMSBearerService_IEs_item, LeftMBMSBearerService_IEs_item_sequence);

  return offset;
}
static int dissect_LeftMBMSBearerService_IEs_item(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_ranap_LeftMBMSBearerService_IEs_item(tvb, offset, actx, tree, hf_ranap_LeftMBMSBearerService_IEs_item);
}


static const per_sequence_t LeftMBMSBearerService_IEs_sequence_of[1] = {
  { ""                            , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_LeftMBMSBearerService_IEs_item },
};

static int
dissect_ranap_LeftMBMSBearerService_IEs(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_ranap_LeftMBMSBearerService_IEs, LeftMBMSBearerService_IEs_sequence_of,
                                                  1, 128);

  return offset;
}
static int dissect_id_LeftMBMSBearerServicesList(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_ranap_LeftMBMSBearerService_IEs(tvb, offset, actx, tree, hf_ranap_id_LeftMBMSBearerServicesList);
}


static const value_string ranap_LocationRelatedDataRequestTypeSpecificToGERANIuMode_vals[] = {
  {   0, "decipheringKeysEOTD" },
  {   1, "dedicatedMobileAssistedEOTDAssistanceData" },
  {   2, "dedicatedMobileBasedEOTDAssistanceData" },
  { 0, NULL }
};


static int
dissect_ranap_LocationRelatedDataRequestTypeSpecificToGERANIuMode(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     3, NULL, TRUE, 0, NULL);

  return offset;
}
static int dissect_id_LocationRelatedDataRequestTypeSpecificToGERANIuMode(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_ranap_LocationRelatedDataRequestTypeSpecificToGERANIuMode(tvb, offset, actx, tree, hf_ranap_id_LocationRelatedDataRequestTypeSpecificToGERANIuMode);
}


static const value_string ranap_SignallingIndication_vals[] = {
  {   0, "signalling" },
  { 0, NULL }
};


static int
dissect_ranap_SignallingIndication(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     1, NULL, TRUE, 0, NULL);

  return offset;
}
static int dissect_id_SignallingIndication(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_ranap_SignallingIndication(tvb, offset, actx, tree, hf_ranap_id_SignallingIndication);
}



static int
dissect_ranap_HS_DSCH_MAC_d_Flow_ID(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                              0U, 7U, NULL, FALSE);

  return offset;
}
static int dissect_id_hS_DSCH_MAC_d_Flow_ID(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_ranap_HS_DSCH_MAC_d_Flow_ID(tvb, offset, actx, tree, hf_ranap_id_hS_DSCH_MAC_d_Flow_ID);
}



static int
dissect_ranap_TargetCellId(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                              0U, 268435455U, NULL, FALSE);

  return offset;
}
static int dissect_targetCellId(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_ranap_TargetCellId(tvb, offset, actx, tree, hf_ranap_targetCellId);
}
static int dissect_uTRANcellID(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_ranap_TargetCellId(tvb, offset, actx, tree, hf_ranap_uTRANcellID);
}


static const per_sequence_t SourceUTRANCellID_sequence[] = {
  { "pLMNidentity"                , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_pLMNidentity },
  { "uTRANcellID"                 , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_uTRANcellID },
  { "iE-Extensions"               , ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_iE_Extensions },
  { NULL, 0, 0, NULL }
};

static int
dissect_ranap_SourceUTRANCellID(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ranap_SourceUTRANCellID, SourceUTRANCellID_sequence);

  return offset;
}
static int dissect_sourceUTRANCellID(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_ranap_SourceUTRANCellID(tvb, offset, actx, tree, hf_ranap_sourceUTRANCellID);
}


static const per_sequence_t CGI_sequence[] = {
  { "pLMNidentity"                , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_pLMNidentity },
  { "lAC"                         , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_lAC },
  { "cI"                          , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_cI },
  { "iE-Extensions"               , ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_iE_Extensions },
  { NULL, 0, 0, NULL }
};

static int
dissect_ranap_CGI(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ranap_CGI, CGI_sequence);

  return offset;
}
static int dissect_sourceGERANCellID(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_ranap_CGI(tvb, offset, actx, tree, hf_ranap_sourceGERANCellID);
}
static int dissect_cGI(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_ranap_CGI(tvb, offset, actx, tree, hf_ranap_cGI);
}


static const value_string ranap_SourceCellID_vals[] = {
  {   0, "sourceUTRANCellID" },
  {   1, "sourceGERANCellID" },
  { 0, NULL }
};

static const per_choice_t SourceCellID_choice[] = {
  {   0, "sourceUTRANCellID"           , ASN1_EXTENSION_ROOT    , dissect_sourceUTRANCellID },
  {   1, "sourceGERANCellID"           , ASN1_EXTENSION_ROOT    , dissect_sourceGERANCellID },
  { 0, NULL, 0, NULL }
};

static int
dissect_ranap_SourceCellID(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_ranap_SourceCellID, SourceCellID_choice,
                                 NULL);

  return offset;
}
static int dissect_sourceCellID(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_ranap_SourceCellID(tvb, offset, actx, tree, hf_ranap_sourceCellID);
}


static const per_sequence_t CellLoadInformationGroup_sequence[] = {
  { "sourceCellID"                , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_sourceCellID },
  { "uplinkCellLoadInformation"   , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_uplinkCellLoadInformation },
  { "downlinkCellLoadInformation" , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_downlinkCellLoadInformation },
  { "iE-Extensions"               , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_iE_Extensions },
  { NULL, 0, 0, NULL }
};

static int
dissect_ranap_CellLoadInformationGroup(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ranap_CellLoadInformationGroup, CellLoadInformationGroup_sequence);

  return offset;
}
static int dissect_id_CellLoadInformationGroup(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_ranap_CellLoadInformationGroup(tvb, offset, actx, tree, hf_ranap_id_CellLoadInformationGroup);
}


static const value_string ranap_MBMSBearerServiceType_vals[] = {
  {   0, "multicast" },
  {   1, "broadcast" },
  { 0, NULL }
};


static int
dissect_ranap_MBMSBearerServiceType(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     2, NULL, TRUE, 0, NULL);

  return offset;
}
static int dissect_id_MBMSBearerServiceType(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_ranap_MBMSBearerServiceType(tvb, offset, actx, tree, hf_ranap_id_MBMSBearerServiceType);
}


static const value_string ranap_MBMSCNDe_Registration_vals[] = {
  {   0, "normalsessionstop" },
  {   1, "deregister" },
  { 0, NULL }
};


static int
dissect_ranap_MBMSCNDe_Registration(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     2, NULL, TRUE, 0, NULL);

  return offset;
}
static int dissect_id_MBMSCNDe_Registration(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_ranap_MBMSCNDe_Registration(tvb, offset, actx, tree, hf_ranap_id_MBMSCNDe_Registration);
}


static const value_string ranap_MBMSRegistrationRequestType_vals[] = {
  {   0, "register" },
  {   1, "deregister" },
  { 0, NULL }
};


static int
dissect_ranap_MBMSRegistrationRequestType(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     2, NULL, TRUE, 0, NULL);

  return offset;
}
static int dissect_id_MBMSRegistrationRequestType(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_ranap_MBMSRegistrationRequestType(tvb, offset, actx, tree, hf_ranap_id_MBMSRegistrationRequestType);
}



static int
dissect_ranap_MBMSServiceAreaCode(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                              0U, 65535U, NULL, FALSE);

  return offset;
}
static int dissect_MBMSServiceAreaList_item(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_ranap_MBMSServiceAreaCode(tvb, offset, actx, tree, hf_ranap_MBMSServiceAreaList_item);
}


static const per_sequence_t MBMSServiceAreaList_sequence_of[1] = {
  { ""                            , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_MBMSServiceAreaList_item },
};

static int
dissect_ranap_MBMSServiceAreaList(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_ranap_MBMSServiceAreaList, MBMSServiceAreaList_sequence_of,
                                                  1, 256);

  return offset;
}
static int dissect_mBMSServiceAreaList(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_ranap_MBMSServiceAreaList(tvb, offset, actx, tree, hf_ranap_mBMSServiceAreaList);
}


static const per_sequence_t MBMSServiceArea_sequence[] = {
  { "mBMSServiceAreaList"         , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_mBMSServiceAreaList },
  { "iE-Extensions"               , ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_iE_Extensions },
  { NULL, 0, 0, NULL }
};

static int
dissect_ranap_MBMSServiceArea(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ranap_MBMSServiceArea, MBMSServiceArea_sequence);

  return offset;
}
static int dissect_id_MBMSServiceArea(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_ranap_MBMSServiceArea(tvb, offset, actx, tree, hf_ranap_id_MBMSServiceArea);
}



static int
dissect_ranap_MBMSSessionDuration(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_octet_string(tvb, offset, actx, tree, hf_index,
                                       3, 3, NULL);

  return offset;
}
static int dissect_id_MBMSSessionDuration(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_ranap_MBMSSessionDuration(tvb, offset, actx, tree, hf_ranap_id_MBMSSessionDuration);
}



static int
dissect_ranap_MBMSSessionIdentity(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_octet_string(tvb, offset, actx, tree, hf_index,
                                       1, 1, NULL);

  return offset;
}
static int dissect_id_MBMSSessionIdentity(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_ranap_MBMSSessionIdentity(tvb, offset, actx, tree, hf_ranap_id_MBMSSessionIdentity);
}



static int
dissect_ranap_MBMSSessionRepetitionNumber(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                              0U, 255U, NULL, FALSE);

  return offset;
}
static int dissect_id_MBMSSessionRepetitionNumber(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_ranap_MBMSSessionRepetitionNumber(tvb, offset, actx, tree, hf_ranap_id_MBMSSessionRepetitionNumber);
}



static int
dissect_ranap_NAS_SequenceNumber(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_bit_string(tvb, offset, actx, tree, hf_index,
                                     2, 2, FALSE);

  return offset;
}
static int dissect_id_NAS_SequenceNumber(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_ranap_NAS_SequenceNumber(tvb, offset, actx, tree, hf_ranap_id_NAS_SequenceNumber);
}



static int
dissect_ranap_NewBSS_To_OldBSS_Information(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_octet_string(tvb, offset, actx, tree, hf_index,
                                       NO_BOUND, NO_BOUND, NULL);

  return offset;
}
static int dissect_id_NewBSS_To_OldBSS_Information(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_ranap_NewBSS_To_OldBSS_Information(tvb, offset, actx, tree, hf_ranap_id_NewBSS_To_OldBSS_Information);
}


static const value_string ranap_NonSearchingIndication_vals[] = {
  {   0, "non-searching" },
  {   1, "searching" },
  { 0, NULL }
};


static int
dissect_ranap_NonSearchingIndication(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     2, NULL, FALSE, 0, NULL);

  return offset;
}
static int dissect_id_NonSearchingIndication(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_ranap_NonSearchingIndication(tvb, offset, actx, tree, hf_ranap_id_NonSearchingIndication);
}



static int
dissect_ranap_NumberOfSteps(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                              1U, 16U, NULL, FALSE);

  return offset;
}
static int dissect_id_NumberOfSteps(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_ranap_NumberOfSteps(tvb, offset, actx, tree, hf_ranap_id_NumberOfSteps);
}



static int
dissect_ranap_OMC_ID(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_octet_string(tvb, offset, actx, tree, hf_index,
                                       3, 22, NULL);

  return offset;
}
static int dissect_id_OMC_ID(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_ranap_OMC_ID(tvb, offset, actx, tree, hf_ranap_id_OMC_ID);
}



static int
dissect_ranap_OldBSS_ToNewBSS_Information(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_octet_string(tvb, offset, actx, tree, hf_index,
                                       NO_BOUND, NO_BOUND, NULL);

  return offset;
}
static int dissect_id_OldBSS_ToNewBSS_Information(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_ranap_OldBSS_ToNewBSS_Information(tvb, offset, actx, tree, hf_ranap_id_OldBSS_ToNewBSS_Information);
}


static const per_sequence_t RAI_sequence[] = {
  { "lAI"                         , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_lAI },
  { "rAC"                         , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_rAC },
  { "iE-Extensions"               , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_iE_Extensions },
  { NULL, 0, 0, NULL }
};

static int
dissect_ranap_RAI(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ranap_RAI, RAI_sequence);

  return offset;
}
static int dissect_rAI(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_ranap_RAI(tvb, offset, actx, tree, hf_ranap_rAI);
}


static const value_string ranap_PagingAreaID_vals[] = {
  {   0, "lAI" },
  {   1, "rAI" },
  { 0, NULL }
};

static const per_choice_t PagingAreaID_choice[] = {
  {   0, "lAI"                         , ASN1_EXTENSION_ROOT    , dissect_lAI },
  {   1, "rAI"                         , ASN1_EXTENSION_ROOT    , dissect_rAI },
  { 0, NULL, 0, NULL }
};

static int
dissect_ranap_PagingAreaID(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_ranap_PagingAreaID, PagingAreaID_choice,
                                 NULL);

  return offset;
}
static int dissect_id_PagingAreaID(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_ranap_PagingAreaID(tvb, offset, actx, tree, hf_ranap_id_PagingAreaID);
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
dissect_ranap_PagingCause(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     5, NULL, TRUE, 1, NULL);

  return offset;
}
static int dissect_id_PagingCause(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_ranap_PagingCause(tvb, offset, actx, tree, hf_ranap_id_PagingCause);
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
dissect_ranap_PDP_Type(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     5, NULL, TRUE, 0, NULL);

  return offset;
}
static int dissect_PDP_TypeInformation_item(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_ranap_PDP_Type(tvb, offset, actx, tree, hf_ranap_PDP_TypeInformation_item);
}


static const per_sequence_t PDP_TypeInformation_sequence_of[1] = {
  { ""                            , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_PDP_TypeInformation_item },
};

static int
dissect_ranap_PDP_TypeInformation(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_ranap_PDP_TypeInformation, PDP_TypeInformation_sequence_of,
                                                  1, 2);

  return offset;
}
static int dissect_id_PDP_TypeInformation(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_ranap_PDP_TypeInformation(tvb, offset, actx, tree, hf_ranap_id_PDP_TypeInformation);
}
static int dissect_pDP_TypeInformation(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_ranap_PDP_TypeInformation(tvb, offset, actx, tree, hf_ranap_pDP_TypeInformation);
}



static int
dissect_ranap_PositioningDataDiscriminator(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_bit_string(tvb, offset, actx, tree, hf_index,
                                     4, 4, FALSE);

  return offset;
}
static int dissect_positioningDataDiscriminator(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_ranap_PositioningDataDiscriminator(tvb, offset, actx, tree, hf_ranap_positioningDataDiscriminator);
}



static int
dissect_ranap_PositioningMethodAndUsage(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_octet_string(tvb, offset, actx, tree, hf_index,
                                       1, 1, NULL);

  return offset;
}
static int dissect_PositioningDataSet_item(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_ranap_PositioningMethodAndUsage(tvb, offset, actx, tree, hf_ranap_PositioningDataSet_item);
}


static const per_sequence_t PositioningDataSet_sequence_of[1] = {
  { ""                            , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_PositioningDataSet_item },
};

static int
dissect_ranap_PositioningDataSet(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_ranap_PositioningDataSet, PositioningDataSet_sequence_of,
                                                  1, 9);

  return offset;
}
static int dissect_positioningDataSet(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_ranap_PositioningDataSet(tvb, offset, actx, tree, hf_ranap_positioningDataSet);
}


static const per_sequence_t PositionData_sequence[] = {
  { "positioningDataDiscriminator", ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_positioningDataDiscriminator },
  { "positioningDataSet"          , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_positioningDataSet },
  { "iE-Extensions"               , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_iE_Extensions },
  { NULL, 0, 0, NULL }
};

static int
dissect_ranap_PositionData(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ranap_PositionData, PositionData_sequence);

  return offset;
}
static int dissect_id_PositionData(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_ranap_PositionData(tvb, offset, actx, tree, hf_ranap_id_PositionData);
}



static int
dissect_ranap_PositionDataSpecificToGERANIuMode(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_octet_string(tvb, offset, actx, tree, hf_index,
                                       NO_BOUND, NO_BOUND, NULL);

  return offset;
}
static int dissect_id_PositionDataSpecificToGERANIuMode(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_ranap_PositionDataSpecificToGERANIuMode(tvb, offset, actx, tree, hf_ranap_id_PositionDataSpecificToGERANIuMode);
}


static const value_string ranap_PositioningPriority_vals[] = {
  {   0, "high-Priority" },
  {   1, "normal-Priority" },
  { 0, NULL }
};


static int
dissect_ranap_PositioningPriority(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     2, NULL, TRUE, 0, NULL);

  return offset;
}
static int dissect_id_PositioningPriority(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_ranap_PositioningPriority(tvb, offset, actx, tree, hf_ranap_id_PositioningPriority);
}



static int
dissect_ranap_SNAC(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                              0U, 65535U, NULL, FALSE);

  return offset;
}
static int dissect_AuthorisedSNAs_item(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_ranap_SNAC(tvb, offset, actx, tree, hf_ranap_AuthorisedSNAs_item);
}
static int dissect_ListOF_SNAs_item(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_ranap_SNAC(tvb, offset, actx, tree, hf_ranap_ListOF_SNAs_item);
}


static const per_sequence_t ListOF_SNAs_sequence_of[1] = {
  { ""                            , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ListOF_SNAs_item },
};

static int
dissect_ranap_ListOF_SNAs(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_ranap_ListOF_SNAs, ListOF_SNAs_sequence_of,
                                                  1, 65536);

  return offset;
}
static int dissect_listOF_SNAs(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_ranap_ListOF_SNAs(tvb, offset, actx, tree, hf_ranap_listOF_SNAs);
}


static const per_sequence_t LA_LIST_item_sequence[] = {
  { "lAC"                         , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_lAC },
  { "listOF-SNAs"                 , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_listOF_SNAs },
  { "iE-Extensions"               , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_iE_Extensions },
  { NULL, 0, 0, NULL }
};

static int
dissect_ranap_LA_LIST_item(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ranap_LA_LIST_item, LA_LIST_item_sequence);

  return offset;
}
static int dissect_LA_LIST_item(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_ranap_LA_LIST_item(tvb, offset, actx, tree, hf_ranap_LA_LIST_item);
}


static const per_sequence_t LA_LIST_sequence_of[1] = {
  { ""                            , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_LA_LIST_item },
};

static int
dissect_ranap_LA_LIST(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_ranap_LA_LIST, LA_LIST_sequence_of,
                                                  1, 65536);

  return offset;
}
static int dissect_lA_LIST(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_ranap_LA_LIST(tvb, offset, actx, tree, hf_ranap_lA_LIST);
}


static const per_sequence_t PLMNs_in_shared_network_item_sequence[] = {
  { "pLMNidentity"                , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pLMNidentity },
  { "lA-LIST"                     , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_lA_LIST },
  { NULL, 0, 0, NULL }
};

static int
dissect_ranap_PLMNs_in_shared_network_item(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ranap_PLMNs_in_shared_network_item, PLMNs_in_shared_network_item_sequence);

  return offset;
}
static int dissect_PLMNs_in_shared_network_item(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_ranap_PLMNs_in_shared_network_item(tvb, offset, actx, tree, hf_ranap_PLMNs_in_shared_network_item);
}


static const per_sequence_t PLMNs_in_shared_network_sequence_of[1] = {
  { ""                            , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_PLMNs_in_shared_network_item },
};

static int
dissect_ranap_PLMNs_in_shared_network(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_ranap_PLMNs_in_shared_network, PLMNs_in_shared_network_sequence_of,
                                                  1, 32);

  return offset;
}
static int dissect_pLMNs_in_shared_network(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_ranap_PLMNs_in_shared_network(tvb, offset, actx, tree, hf_ranap_pLMNs_in_shared_network);
}


static const per_sequence_t Shared_Network_Information_sequence[] = {
  { "pLMNs-in-shared-network"     , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pLMNs_in_shared_network },
  { "iE-Extensions"               , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_iE_Extensions },
  { NULL, 0, 0, NULL }
};

static int
dissect_ranap_Shared_Network_Information(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ranap_Shared_Network_Information, Shared_Network_Information_sequence);

  return offset;
}
static int dissect_shared_network_information(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_ranap_Shared_Network_Information(tvb, offset, actx, tree, hf_ranap_shared_network_information);
}


static const value_string ranap_ProvidedData_vals[] = {
  {   0, "shared-network-information" },
  { 0, NULL }
};

static const per_choice_t ProvidedData_choice[] = {
  {   0, "shared-network-information"  , ASN1_EXTENSION_ROOT    , dissect_shared_network_information },
  { 0, NULL, 0, NULL }
};

static int
dissect_ranap_ProvidedData(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_ranap_ProvidedData, ProvidedData_choice,
                                 NULL);

  return offset;
}
static int dissect_id_ProvidedData(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_ranap_ProvidedData(tvb, offset, actx, tree, hf_ranap_id_ProvidedData);
}



static int
dissect_ranap_UL_GTP_PDU_SequenceNumber(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                              0U, 65535U, NULL, FALSE);

  return offset;
}
static int dissect_id_UL_GTP_PDU_SequenceNumber(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_ranap_UL_GTP_PDU_SequenceNumber(tvb, offset, actx, tree, hf_ranap_id_UL_GTP_PDU_SequenceNumber);
}
static int dissect_uL_GTP_PDU_SequenceNumber(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_ranap_UL_GTP_PDU_SequenceNumber(tvb, offset, actx, tree, hf_ranap_uL_GTP_PDU_SequenceNumber);
}
static int dissect_ul_GTP_PDU_SequenceNumber(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_ranap_UL_GTP_PDU_SequenceNumber(tvb, offset, actx, tree, hf_ranap_ul_GTP_PDU_SequenceNumber);
}



static int
dissect_ranap_DL_N_PDU_SequenceNumber(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                              0U, 65535U, NULL, FALSE);

  return offset;
}
static int dissect_dl_N_PDU_SequenceNumber(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_ranap_DL_N_PDU_SequenceNumber(tvb, offset, actx, tree, hf_ranap_dl_N_PDU_SequenceNumber);
}



static int
dissect_ranap_UL_N_PDU_SequenceNumber(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                              0U, 65535U, NULL, FALSE);

  return offset;
}
static int dissect_ul_N_PDU_SequenceNumber(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_ranap_UL_N_PDU_SequenceNumber(tvb, offset, actx, tree, hf_ranap_ul_N_PDU_SequenceNumber);
}


static const per_sequence_t RAB_ContextItem_sequence[] = {
  { "rAB-ID"                      , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_rAB_ID },
  { "dl-GTP-PDU-SequenceNumber"   , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_dl_GTP_PDU_SequenceNumber },
  { "ul-GTP-PDU-SequenceNumber"   , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ul_GTP_PDU_SequenceNumber },
  { "dl-N-PDU-SequenceNumber"     , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_dl_N_PDU_SequenceNumber },
  { "ul-N-PDU-SequenceNumber"     , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ul_N_PDU_SequenceNumber },
  { "iE-Extensions"               , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_iE_Extensions },
  { NULL, 0, 0, NULL }
};

static int
dissect_ranap_RAB_ContextItem(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ranap_RAB_ContextItem, RAB_ContextItem_sequence);

  return offset;
}
static int dissect_id_RAB_ContextItem(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_ranap_RAB_ContextItem(tvb, offset, actx, tree, hf_ranap_id_RAB_ContextItem);
}



static int
dissect_ranap_RAB_ContextList(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_ranap_RAB_IE_ContainerList(tvb, offset, actx, tree, hf_index);

  return offset;
}
static int dissect_id_RAB_ContextList(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_ranap_RAB_ContextList(tvb, offset, actx, tree, hf_ranap_id_RAB_ContextList);
}


static const per_sequence_t RABs_ContextFailedtoTransferItem_sequence[] = {
  { "rAB-ID"                      , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_rAB_ID },
  { "cause"                       , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_cause },
  { "iE-Extensions"               , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_iE_Extensions },
  { NULL, 0, 0, NULL }
};

static int
dissect_ranap_RABs_ContextFailedtoTransferItem(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ranap_RABs_ContextFailedtoTransferItem, RABs_ContextFailedtoTransferItem_sequence);

  return offset;
}
static int dissect_id_RAB_ContextFailedtoTransferItem(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_ranap_RABs_ContextFailedtoTransferItem(tvb, offset, actx, tree, hf_ranap_id_RAB_ContextFailedtoTransferItem);
}



static int
dissect_ranap_RAB_ContextFailedtoTransferList(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_ranap_RAB_IE_ContainerList(tvb, offset, actx, tree, hf_index);

  return offset;
}
static int dissect_id_RAB_ContextFailedtoTransferList(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_ranap_RAB_ContextFailedtoTransferList(tvb, offset, actx, tree, hf_ranap_id_RAB_ContextFailedtoTransferList);
}


static const per_sequence_t RAB_ContextItem_RANAP_RelocInf_sequence[] = {
  { "rAB-ID"                      , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_rAB_ID },
  { "dl-GTP-PDU-SequenceNumber"   , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_dl_GTP_PDU_SequenceNumber },
  { "ul-GTP-PDU-SequenceNumber"   , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ul_GTP_PDU_SequenceNumber },
  { "dl-N-PDU-SequenceNumber"     , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_dl_N_PDU_SequenceNumber },
  { "ul-N-PDU-SequenceNumber"     , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ul_N_PDU_SequenceNumber },
  { "iE-Extensions"               , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_iE_Extensions },
  { NULL, 0, 0, NULL }
};

static int
dissect_ranap_RAB_ContextItem_RANAP_RelocInf(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ranap_RAB_ContextItem_RANAP_RelocInf, RAB_ContextItem_RANAP_RelocInf_sequence);

  return offset;
}
static int dissect_id_RAB_ContextItem_RANAP_RelocInf(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_ranap_RAB_ContextItem_RANAP_RelocInf(tvb, offset, actx, tree, hf_ranap_id_RAB_ContextItem_RANAP_RelocInf);
}



static int
dissect_ranap_RAB_ContextList_RANAP_RelocInf(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_ranap_RAB_IE_ContainerList(tvb, offset, actx, tree, hf_index);

  return offset;
}
static int dissect_id_RAB_ContextList_RANAP_RelocInf(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_ranap_RAB_ContextList_RANAP_RelocInf(tvb, offset, actx, tree, hf_ranap_id_RAB_ContextList_RANAP_RelocInf);
}



static int
dissect_ranap_TransportLayerAddress(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_bit_string(tvb, offset, actx, tree, hf_index,
                                     1, 160, TRUE);

  return offset;
}
static int dissect_id_TransportLayerAddress(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_ranap_TransportLayerAddress(tvb, offset, actx, tree, hf_ranap_id_TransportLayerAddress);
}
static int dissect_transportLayerAddress(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_ranap_TransportLayerAddress(tvb, offset, actx, tree, hf_ranap_transportLayerAddress);
}


static const per_sequence_t RAB_DataForwardingItem_sequence[] = {
  { "rAB-ID"                      , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_rAB_ID },
  { "transportLayerAddress"       , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_transportLayerAddress },
  { "iuTransportAssociation"      , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_iuTransportAssociation },
  { "iE-Extensions"               , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_iE_Extensions },
  { NULL, 0, 0, NULL }
};

static int
dissect_ranap_RAB_DataForwardingItem(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ranap_RAB_DataForwardingItem, RAB_DataForwardingItem_sequence);

  return offset;
}
static int dissect_id_RAB_DataForwardingItem(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_ranap_RAB_DataForwardingItem(tvb, offset, actx, tree, hf_ranap_id_RAB_DataForwardingItem);
}


static const per_sequence_t RAB_DataForwardingItem_SRNS_CtxReq_sequence[] = {
  { "rAB-ID"                      , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_rAB_ID },
  { "iE-Extensions"               , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_iE_Extensions },
  { NULL, 0, 0, NULL }
};

static int
dissect_ranap_RAB_DataForwardingItem_SRNS_CtxReq(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ranap_RAB_DataForwardingItem_SRNS_CtxReq, RAB_DataForwardingItem_SRNS_CtxReq_sequence);

  return offset;
}
static int dissect_id_RAB_DataForwardingItem_SRNS_CtxReq(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_ranap_RAB_DataForwardingItem_SRNS_CtxReq(tvb, offset, actx, tree, hf_ranap_id_RAB_DataForwardingItem_SRNS_CtxReq);
}



static int
dissect_ranap_RAB_DataForwardingList(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_ranap_RAB_IE_ContainerList(tvb, offset, actx, tree, hf_index);

  return offset;
}
static int dissect_id_RAB_DataForwardingList(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_ranap_RAB_DataForwardingList(tvb, offset, actx, tree, hf_ranap_id_RAB_DataForwardingList);
}



static int
dissect_ranap_RAB_DataForwardingList_SRNS_CtxReq(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_ranap_RAB_IE_ContainerList(tvb, offset, actx, tree, hf_index);

  return offset;
}
static int dissect_id_RAB_DataForwardingList_SRNS_CtxReq(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_ranap_RAB_DataForwardingList_SRNS_CtxReq(tvb, offset, actx, tree, hf_ranap_id_RAB_DataForwardingList_SRNS_CtxReq);
}



static int
dissect_ranap_UnsuccessfullyTransmittedDataVolume(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                              0U, 4294967295U, NULL, FALSE);

  return offset;
}
static int dissect_dl_UnsuccessfullyTransmittedDataVolume(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_ranap_UnsuccessfullyTransmittedDataVolume(tvb, offset, actx, tree, hf_ranap_dl_UnsuccessfullyTransmittedDataVolume);
}



static int
dissect_ranap_DataVolumeReference(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                              0U, 255U, NULL, FALSE);

  return offset;
}
static int dissect_dataVolumeReference(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_ranap_DataVolumeReference(tvb, offset, actx, tree, hf_ranap_dataVolumeReference);
}


static const per_sequence_t DataVolumeList_item_sequence[] = {
  { "dl-UnsuccessfullyTransmittedDataVolume", ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_dl_UnsuccessfullyTransmittedDataVolume },
  { "dataVolumeReference"         , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_dataVolumeReference },
  { "iE-Extensions"               , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_iE_Extensions },
  { NULL, 0, 0, NULL }
};

static int
dissect_ranap_DataVolumeList_item(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ranap_DataVolumeList_item, DataVolumeList_item_sequence);

  return offset;
}
static int dissect_DataVolumeList_item(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_ranap_DataVolumeList_item(tvb, offset, actx, tree, hf_ranap_DataVolumeList_item);
}


static const per_sequence_t DataVolumeList_sequence_of[1] = {
  { ""                            , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_DataVolumeList_item },
};

static int
dissect_ranap_DataVolumeList(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_ranap_DataVolumeList, DataVolumeList_sequence_of,
                                                  1, 2);

  return offset;
}
static int dissect_rab_dl_UnsuccessfullyTransmittedDataVolume(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_ranap_DataVolumeList(tvb, offset, actx, tree, hf_ranap_rab_dl_UnsuccessfullyTransmittedDataVolume);
}
static int dissect_dl_dataVolumes(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_ranap_DataVolumeList(tvb, offset, actx, tree, hf_ranap_dl_dataVolumes);
}


static const per_sequence_t RAB_DataVolumeReportItem_sequence[] = {
  { "rAB-ID"                      , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_rAB_ID },
  { "dl-UnsuccessfullyTransmittedDataVolume", ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_rab_dl_UnsuccessfullyTransmittedDataVolume },
  { "iE-Extensions"               , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_iE_Extensions },
  { NULL, 0, 0, NULL }
};

static int
dissect_ranap_RAB_DataVolumeReportItem(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ranap_RAB_DataVolumeReportItem, RAB_DataVolumeReportItem_sequence);

  return offset;
}
static int dissect_id_RAB_DataVolumeReportItem(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_ranap_RAB_DataVolumeReportItem(tvb, offset, actx, tree, hf_ranap_id_RAB_DataVolumeReportItem);
}



static int
dissect_ranap_RAB_DataVolumeReportList(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_ranap_RAB_IE_ContainerList(tvb, offset, actx, tree, hf_index);

  return offset;
}
static int dissect_id_RAB_DataVolumeReportList(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_ranap_RAB_DataVolumeReportList(tvb, offset, actx, tree, hf_ranap_id_RAB_DataVolumeReportList);
}


static const per_sequence_t RAB_DataVolumeReportRequestItem_sequence[] = {
  { "rAB-ID"                      , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_rAB_ID },
  { "iE-Extensions"               , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_iE_Extensions },
  { NULL, 0, 0, NULL }
};

static int
dissect_ranap_RAB_DataVolumeReportRequestItem(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ranap_RAB_DataVolumeReportRequestItem, RAB_DataVolumeReportRequestItem_sequence);

  return offset;
}
static int dissect_id_RAB_DataVolumeReportRequestItem(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_ranap_RAB_DataVolumeReportRequestItem(tvb, offset, actx, tree, hf_ranap_id_RAB_DataVolumeReportRequestItem);
}



static int
dissect_ranap_RAB_DataVolumeReportRequestList(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_ranap_RAB_IE_ContainerList(tvb, offset, actx, tree, hf_index);

  return offset;
}
static int dissect_id_RAB_DataVolumeReportRequestList(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_ranap_RAB_DataVolumeReportRequestList(tvb, offset, actx, tree, hf_ranap_id_RAB_DataVolumeReportRequestList);
}


static const per_sequence_t RAB_FailedItem_sequence[] = {
  { "rAB-ID"                      , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_rAB_ID },
  { "cause"                       , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_cause },
  { "iE-Extensions"               , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_iE_Extensions },
  { NULL, 0, 0, NULL }
};

static int
dissect_ranap_RAB_FailedItem(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ranap_RAB_FailedItem, RAB_FailedItem_sequence);

  return offset;
}
static int dissect_id_RAB_FailedItem(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_ranap_RAB_FailedItem(tvb, offset, actx, tree, hf_ranap_id_RAB_FailedItem);
}



static int
dissect_ranap_RAB_FailedList(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_ranap_RAB_IE_ContainerList(tvb, offset, actx, tree, hf_index);

  return offset;
}
static int dissect_id_RAB_FailedList(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_ranap_RAB_FailedList(tvb, offset, actx, tree, hf_ranap_id_RAB_FailedList);
}


static const per_sequence_t RABs_failed_to_reportItem_sequence[] = {
  { "rAB-ID"                      , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_rAB_ID },
  { "cause"                       , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_cause },
  { "iE-Extensions"               , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_iE_Extensions },
  { NULL, 0, 0, NULL }
};

static int
dissect_ranap_RABs_failed_to_reportItem(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ranap_RABs_failed_to_reportItem, RABs_failed_to_reportItem_sequence);

  return offset;
}
static int dissect_id_RAB_FailedtoReportItem(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_ranap_RABs_failed_to_reportItem(tvb, offset, actx, tree, hf_ranap_id_RAB_FailedtoReportItem);
}



static int
dissect_ranap_RAB_FailedtoReportList(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_ranap_RAB_IE_ContainerList(tvb, offset, actx, tree, hf_index);

  return offset;
}
static int dissect_id_RAB_FailedtoReportList(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_ranap_RAB_FailedtoReportList(tvb, offset, actx, tree, hf_ranap_id_RAB_FailedtoReportList);
}



static int
dissect_ranap_RAB_ModifyList(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_ranap_RAB_IE_ContainerList(tvb, offset, actx, tree, hf_index);

  return offset;
}
static int dissect_id_RAB_ModifyList(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_ranap_RAB_ModifyList(tvb, offset, actx, tree, hf_ranap_id_RAB_ModifyList);
}


static const per_sequence_t Requested_RAB_Parameter_MaxBitrateList_sequence_of[1] = {
  { ""                            , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_Requested_RAB_Parameter_MaxBitrateList_item },
};

static int
dissect_ranap_Requested_RAB_Parameter_MaxBitrateList(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_ranap_Requested_RAB_Parameter_MaxBitrateList, Requested_RAB_Parameter_MaxBitrateList_sequence_of,
                                                  1, 2);

  return offset;
}
static int dissect_requestedMaxBitrates(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_ranap_Requested_RAB_Parameter_MaxBitrateList(tvb, offset, actx, tree, hf_ranap_requestedMaxBitrates);
}


static const per_sequence_t Requested_RAB_Parameter_GuaranteedBitrateList_sequence_of[1] = {
  { ""                            , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_Requested_RAB_Parameter_GuaranteedBitrateList_item },
};

static int
dissect_ranap_Requested_RAB_Parameter_GuaranteedBitrateList(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_ranap_Requested_RAB_Parameter_GuaranteedBitrateList, Requested_RAB_Parameter_GuaranteedBitrateList_sequence_of,
                                                  1, 2);

  return offset;
}
static int dissect_requestedGuaranteedBitrates(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_ranap_Requested_RAB_Parameter_GuaranteedBitrateList(tvb, offset, actx, tree, hf_ranap_requestedGuaranteedBitrates);
}


static const per_sequence_t Requested_RAB_Parameter_Values_sequence[] = {
  { "requestedMaxBitrates"        , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_requestedMaxBitrates },
  { "requestedGuaranteedBitrates" , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_requestedGuaranteedBitrates },
  { "iE-Extensions"               , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_iE_Extensions },
  { NULL, 0, 0, NULL }
};

static int
dissect_ranap_Requested_RAB_Parameter_Values(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ranap_Requested_RAB_Parameter_Values, Requested_RAB_Parameter_Values_sequence);

  return offset;
}
static int dissect_requested_RAB_Parameter_Values(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_ranap_Requested_RAB_Parameter_Values(tvb, offset, actx, tree, hf_ranap_requested_RAB_Parameter_Values);
}


static const per_sequence_t RAB_ModifyItem_sequence[] = {
  { "rAB-ID"                      , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_rAB_ID },
  { "requested-RAB-Parameter-Values", ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_requested_RAB_Parameter_Values },
  { "iE-Extensions"               , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_iE_Extensions },
  { NULL, 0, 0, NULL }
};

static int
dissect_ranap_RAB_ModifyItem(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ranap_RAB_ModifyItem, RAB_ModifyItem_sequence);

  return offset;
}
static int dissect_id_RAB_ModifyItem(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_ranap_RAB_ModifyItem(tvb, offset, actx, tree, hf_ranap_id_RAB_ModifyItem);
}


static const value_string ranap_TypeOfError_vals[] = {
  {   0, "not-understood" },
  {   1, "missing" },
  { 0, NULL }
};


static int
dissect_ranap_TypeOfError(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     2, NULL, TRUE, 0, NULL);

  return offset;
}
static int dissect_id_TypeOfError(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_ranap_TypeOfError(tvb, offset, actx, tree, hf_ranap_id_TypeOfError);
}


static const value_string ranap_TrafficClass_vals[] = {
  {   0, "conversational" },
  {   1, "streaming" },
  {   2, "interactive" },
  {   3, "background" },
  { 0, NULL }
};


static int
dissect_ranap_TrafficClass(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     4, NULL, TRUE, 0, NULL);

  return offset;
}
static int dissect_trafficClass(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_ranap_TrafficClass(tvb, offset, actx, tree, hf_ranap_trafficClass);
}


static const value_string ranap_RAB_AsymmetryIndicator_vals[] = {
  {   0, "symmetric-bidirectional" },
  {   1, "asymmetric-unidirectional-downlink" },
  {   2, "asymmetric-unidirectional-uplink" },
  {   3, "asymmetric-bidirectional" },
  { 0, NULL }
};


static int
dissect_ranap_RAB_AsymmetryIndicator(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     4, NULL, TRUE, 0, NULL);

  return offset;
}
static int dissect_rAB_AsymmetryIndicator(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_ranap_RAB_AsymmetryIndicator(tvb, offset, actx, tree, hf_ranap_rAB_AsymmetryIndicator);
}


static const per_sequence_t RAB_Parameter_MaxBitrateList_sequence_of[1] = {
  { ""                            , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_RAB_Parameter_MaxBitrateList_item },
};

static int
dissect_ranap_RAB_Parameter_MaxBitrateList(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_ranap_RAB_Parameter_MaxBitrateList, RAB_Parameter_MaxBitrateList_sequence_of,
                                                  1, 2);

  return offset;
}
static int dissect_maxBitrate(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_ranap_RAB_Parameter_MaxBitrateList(tvb, offset, actx, tree, hf_ranap_maxBitrate);
}


static const per_sequence_t RAB_Parameter_GuaranteedBitrateList_sequence_of[1] = {
  { ""                            , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_RAB_Parameter_GuaranteedBitrateList_item },
};

static int
dissect_ranap_RAB_Parameter_GuaranteedBitrateList(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_ranap_RAB_Parameter_GuaranteedBitrateList, RAB_Parameter_GuaranteedBitrateList_sequence_of,
                                                  1, 2);

  return offset;
}
static int dissect_guaranteedBitRate(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_ranap_RAB_Parameter_GuaranteedBitrateList(tvb, offset, actx, tree, hf_ranap_guaranteedBitRate);
}


static const value_string ranap_DeliveryOrder_vals[] = {
  {   0, "delivery-order-requested" },
  {   1, "delivery-order-not-requested" },
  { 0, NULL }
};


static int
dissect_ranap_DeliveryOrder(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     2, NULL, FALSE, 0, NULL);

  return offset;
}
static int dissect_deliveryOrder(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_ranap_DeliveryOrder(tvb, offset, actx, tree, hf_ranap_deliveryOrder);
}



static int
dissect_ranap_MaxSDU_Size(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                              0U, 32768U, NULL, FALSE);

  return offset;
}
static int dissect_maxSDU_Size(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_ranap_MaxSDU_Size(tvb, offset, actx, tree, hf_ranap_maxSDU_Size);
}



static int
dissect_ranap_INTEGER_1_9(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                              1U, 9U, NULL, FALSE);

  return offset;
}
static int dissect_mantissa(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_ranap_INTEGER_1_9(tvb, offset, actx, tree, hf_ranap_mantissa);
}



static int
dissect_ranap_INTEGER_1_6(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                              1U, 6U, NULL, FALSE);

  return offset;
}
static int dissect_exponent_1_8(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_ranap_INTEGER_1_6(tvb, offset, actx, tree, hf_ranap_exponent_1_8);
}


static const per_sequence_t SDU_ErrorRatio_sequence[] = {
  { "mantissa"                    , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_mantissa },
  { "exponent"                    , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_exponent_1_8 },
  { "iE-Extensions"               , ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_iE_Extensions },
  { NULL, 0, 0, NULL }
};

static int
dissect_ranap_SDU_ErrorRatio(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ranap_SDU_ErrorRatio, SDU_ErrorRatio_sequence);

  return offset;
}
static int dissect_sDU_ErrorRatio(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_ranap_SDU_ErrorRatio(tvb, offset, actx, tree, hf_ranap_sDU_ErrorRatio);
}



static int
dissect_ranap_INTEGER_1_8(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                              1U, 8U, NULL, FALSE);

  return offset;
}
static int dissect_exponent(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_ranap_INTEGER_1_8(tvb, offset, actx, tree, hf_ranap_exponent);
}


static const per_sequence_t ResidualBitErrorRatio_sequence[] = {
  { "mantissa"                    , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_mantissa },
  { "exponent"                    , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_exponent },
  { "iE-Extensions"               , ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_iE_Extensions },
  { NULL, 0, 0, NULL }
};

static int
dissect_ranap_ResidualBitErrorRatio(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ranap_ResidualBitErrorRatio, ResidualBitErrorRatio_sequence);

  return offset;
}
static int dissect_residualBitErrorRatio(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_ranap_ResidualBitErrorRatio(tvb, offset, actx, tree, hf_ranap_residualBitErrorRatio);
}


static const value_string ranap_DeliveryOfErroneousSDU_vals[] = {
  {   0, "yes" },
  {   1, "no" },
  {   2, "no-error-detection-consideration" },
  { 0, NULL }
};


static int
dissect_ranap_DeliveryOfErroneousSDU(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     3, NULL, FALSE, 0, NULL);

  return offset;
}
static int dissect_deliveryOfErroneousSDU(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_ranap_DeliveryOfErroneousSDU(tvb, offset, actx, tree, hf_ranap_deliveryOfErroneousSDU);
}



static int
dissect_ranap_SubflowSDU_Size(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                              0U, 4095U, NULL, FALSE);

  return offset;
}
static int dissect_subflowSDU_Size(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_ranap_SubflowSDU_Size(tvb, offset, actx, tree, hf_ranap_subflowSDU_Size);
}



static int
dissect_ranap_RAB_SubflowCombinationBitRate(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                              0U, 16000000U, NULL, FALSE);

  return offset;
}
static int dissect_rAB_SubflowCombinationBitRate(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_ranap_RAB_SubflowCombinationBitRate(tvb, offset, actx, tree, hf_ranap_rAB_SubflowCombinationBitRate);
}


static const per_sequence_t SDU_FormatInformationParameters_item_sequence[] = {
  { "subflowSDU-Size"             , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_subflowSDU_Size },
  { "rAB-SubflowCombinationBitRate", ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_rAB_SubflowCombinationBitRate },
  { "iE-Extensions"               , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_iE_Extensions },
  { NULL, 0, 0, NULL }
};

static int
dissect_ranap_SDU_FormatInformationParameters_item(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ranap_SDU_FormatInformationParameters_item, SDU_FormatInformationParameters_item_sequence);

  return offset;
}
static int dissect_SDU_FormatInformationParameters_item(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_ranap_SDU_FormatInformationParameters_item(tvb, offset, actx, tree, hf_ranap_SDU_FormatInformationParameters_item);
}


static const per_sequence_t SDU_FormatInformationParameters_sequence_of[1] = {
  { ""                            , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_SDU_FormatInformationParameters_item },
};

static int
dissect_ranap_SDU_FormatInformationParameters(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_ranap_SDU_FormatInformationParameters, SDU_FormatInformationParameters_sequence_of,
                                                  1, 64);

  return offset;
}
static int dissect_sDU_FormatInformationParameters(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_ranap_SDU_FormatInformationParameters(tvb, offset, actx, tree, hf_ranap_sDU_FormatInformationParameters);
}


static const per_sequence_t SDU_Parameters_item_sequence[] = {
  { "sDU-ErrorRatio"              , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_sDU_ErrorRatio },
  { "residualBitErrorRatio"       , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_residualBitErrorRatio },
  { "deliveryOfErroneousSDU"      , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_deliveryOfErroneousSDU },
  { "sDU-FormatInformationParameters", ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_sDU_FormatInformationParameters },
  { "iE-Extensions"               , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_iE_Extensions },
  { NULL, 0, 0, NULL }
};

static int
dissect_ranap_SDU_Parameters_item(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ranap_SDU_Parameters_item, SDU_Parameters_item_sequence);

  return offset;
}
static int dissect_SDU_Parameters_item(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_ranap_SDU_Parameters_item(tvb, offset, actx, tree, hf_ranap_SDU_Parameters_item);
}


static const per_sequence_t SDU_Parameters_sequence_of[1] = {
  { ""                            , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_SDU_Parameters_item },
};

static int
dissect_ranap_SDU_Parameters(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_ranap_SDU_Parameters, SDU_Parameters_sequence_of,
                                                  1, 7);

  return offset;
}
static int dissect_sDU_Parameters(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_ranap_SDU_Parameters(tvb, offset, actx, tree, hf_ranap_sDU_Parameters);
}



static int
dissect_ranap_TransferDelay(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                              0U, 65535U, NULL, FALSE);

  return offset;
}
static int dissect_transferDelay(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_ranap_TransferDelay(tvb, offset, actx, tree, hf_ranap_transferDelay);
}


static const value_string ranap_TrafficHandlingPriority_vals[] = {
  {   0, "spare" },
  {   1, "highest" },
  {  14, "lowest" },
  {  15, "no-priority-used" },
  { 0, NULL }
};


static int
dissect_ranap_TrafficHandlingPriority(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                              0U, 15U, NULL, FALSE);

  return offset;
}
static int dissect_trafficHandlingPriority(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_ranap_TrafficHandlingPriority(tvb, offset, actx, tree, hf_ranap_trafficHandlingPriority);
}


static const value_string ranap_PriorityLevel_vals[] = {
  {   0, "spare" },
  {   1, "highest" },
  {  14, "lowest" },
  {  15, "no-priority" },
  { 0, NULL }
};


static int
dissect_ranap_PriorityLevel(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                              0U, 15U, NULL, FALSE);

  return offset;
}
static int dissect_priorityLevel(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_ranap_PriorityLevel(tvb, offset, actx, tree, hf_ranap_priorityLevel);
}


static const value_string ranap_Pre_emptionCapability_vals[] = {
  {   0, "shall-not-trigger-pre-emption" },
  {   1, "may-trigger-pre-emption" },
  { 0, NULL }
};


static int
dissect_ranap_Pre_emptionCapability(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     2, NULL, FALSE, 0, NULL);

  return offset;
}
static int dissect_pre_emptionCapability(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_ranap_Pre_emptionCapability(tvb, offset, actx, tree, hf_ranap_pre_emptionCapability);
}


static const value_string ranap_Pre_emptionVulnerability_vals[] = {
  {   0, "not-pre-emptable" },
  {   1, "pre-emptable" },
  { 0, NULL }
};


static int
dissect_ranap_Pre_emptionVulnerability(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     2, NULL, FALSE, 0, NULL);

  return offset;
}
static int dissect_pre_emptionVulnerability(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_ranap_Pre_emptionVulnerability(tvb, offset, actx, tree, hf_ranap_pre_emptionVulnerability);
}


static const value_string ranap_QueuingAllowed_vals[] = {
  {   0, "queueing-not-allowed" },
  {   1, "queueing-allowed" },
  { 0, NULL }
};


static int
dissect_ranap_QueuingAllowed(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     2, NULL, FALSE, 0, NULL);

  return offset;
}
static int dissect_queuingAllowed(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_ranap_QueuingAllowed(tvb, offset, actx, tree, hf_ranap_queuingAllowed);
}


static const per_sequence_t AllocationOrRetentionPriority_sequence[] = {
  { "priorityLevel"               , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_priorityLevel },
  { "pre-emptionCapability"       , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pre_emptionCapability },
  { "pre-emptionVulnerability"    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pre_emptionVulnerability },
  { "queuingAllowed"              , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_queuingAllowed },
  { "iE-Extensions"               , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_iE_Extensions },
  { NULL, 0, 0, NULL }
};

static int
dissect_ranap_AllocationOrRetentionPriority(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ranap_AllocationOrRetentionPriority, AllocationOrRetentionPriority_sequence);

  return offset;
}
static int dissect_allocationOrRetentionPriority(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_ranap_AllocationOrRetentionPriority(tvb, offset, actx, tree, hf_ranap_allocationOrRetentionPriority);
}


static const value_string ranap_SourceStatisticsDescriptor_vals[] = {
  {   0, "speech" },
  {   1, "unknown" },
  { 0, NULL }
};


static int
dissect_ranap_SourceStatisticsDescriptor(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     2, NULL, TRUE, 0, NULL);

  return offset;
}
static int dissect_sourceStatisticsDescriptor(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_ranap_SourceStatisticsDescriptor(tvb, offset, actx, tree, hf_ranap_sourceStatisticsDescriptor);
}


static const value_string ranap_RelocationRequirement_vals[] = {
  {   0, "lossless" },
  {   1, "none" },
  { 0, NULL }
};


static int
dissect_ranap_RelocationRequirement(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     2, NULL, TRUE, 0, NULL);

  return offset;
}
static int dissect_relocationRequirement(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_ranap_RelocationRequirement(tvb, offset, actx, tree, hf_ranap_relocationRequirement);
}


static const per_sequence_t RAB_Parameters_sequence[] = {
  { "trafficClass"                , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_trafficClass },
  { "rAB-AsymmetryIndicator"      , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_rAB_AsymmetryIndicator },
  { "maxBitrate"                  , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_maxBitrate },
  { "guaranteedBitRate"           , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_guaranteedBitRate },
  { "deliveryOrder"               , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_deliveryOrder },
  { "maxSDU-Size"                 , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_maxSDU_Size },
  { "sDU-Parameters"              , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_sDU_Parameters },
  { "transferDelay"               , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_transferDelay },
  { "trafficHandlingPriority"     , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_trafficHandlingPriority },
  { "allocationOrRetentionPriority", ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_allocationOrRetentionPriority },
  { "sourceStatisticsDescriptor"  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_sourceStatisticsDescriptor },
  { "relocationRequirement"       , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_relocationRequirement },
  { "iE-Extensions"               , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_iE_Extensions },
  { NULL, 0, 0, NULL }
};

static int
dissect_ranap_RAB_Parameters(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ranap_RAB_Parameters, RAB_Parameters_sequence);

  return offset;
}
static int dissect_id_RAB_Parameters(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_ranap_RAB_Parameters(tvb, offset, actx, tree, hf_ranap_id_RAB_Parameters);
}
static int dissect_id_AlternativeRABConfiguration(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_ranap_RAB_Parameters(tvb, offset, actx, tree, hf_ranap_id_AlternativeRABConfiguration);
}
static int dissect_rAB_Parameters(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_ranap_RAB_Parameters(tvb, offset, actx, tree, hf_ranap_rAB_Parameters);
}


static const per_sequence_t RAB_QueuedItem_sequence[] = {
  { "rAB-ID"                      , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_rAB_ID },
  { "iE-Extensions"               , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_iE_Extensions },
  { NULL, 0, 0, NULL }
};

static int
dissect_ranap_RAB_QueuedItem(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ranap_RAB_QueuedItem, RAB_QueuedItem_sequence);

  return offset;
}
static int dissect_id_RAB_QueuedItem(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_ranap_RAB_QueuedItem(tvb, offset, actx, tree, hf_ranap_id_RAB_QueuedItem);
}



static int
dissect_ranap_RAB_QueuedList(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_ranap_RAB_IE_ContainerList(tvb, offset, actx, tree, hf_index);

  return offset;
}
static int dissect_id_RAB_QueuedList(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_ranap_RAB_QueuedList(tvb, offset, actx, tree, hf_ranap_id_RAB_QueuedList);
}



static int
dissect_ranap_RAB_ReleaseFailedList(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_ranap_RAB_FailedList(tvb, offset, actx, tree, hf_index);

  return offset;
}
static int dissect_id_RAB_ReleaseFailedList(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_ranap_RAB_ReleaseFailedList(tvb, offset, actx, tree, hf_ranap_id_RAB_ReleaseFailedList);
}


static const per_sequence_t RAB_ReleaseItem_sequence[] = {
  { "rAB-ID"                      , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_rAB_ID },
  { "cause"                       , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_cause },
  { "iE-Extensions"               , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_iE_Extensions },
  { NULL, 0, 0, NULL }
};

static int
dissect_ranap_RAB_ReleaseItem(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ranap_RAB_ReleaseItem, RAB_ReleaseItem_sequence);

  return offset;
}
static int dissect_id_RAB_ReleaseItem(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_ranap_RAB_ReleaseItem(tvb, offset, actx, tree, hf_ranap_id_RAB_ReleaseItem);
}


static const per_sequence_t RAB_ReleasedItem_IuRelComp_sequence[] = {
  { "rAB-ID"                      , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_rAB_ID },
  { "dL-GTP-PDU-SequenceNumber"   , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_dL_GTP_PDU_SequenceNumber },
  { "uL-GTP-PDU-SequenceNumber"   , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_uL_GTP_PDU_SequenceNumber },
  { "iE-Extensions"               , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_iE_Extensions },
  { NULL, 0, 0, NULL }
};

static int
dissect_ranap_RAB_ReleasedItem_IuRelComp(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ranap_RAB_ReleasedItem_IuRelComp, RAB_ReleasedItem_IuRelComp_sequence);

  return offset;
}
static int dissect_id_RAB_ReleasedItem_IuRelComp(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_ranap_RAB_ReleasedItem_IuRelComp(tvb, offset, actx, tree, hf_ranap_id_RAB_ReleasedItem_IuRelComp);
}



static int
dissect_ranap_RepetitionNumber1(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                              1U, 256U, NULL, FALSE);

  return offset;
}
static int dissect_item_repetitionNumber(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_ranap_RepetitionNumber1(tvb, offset, actx, tree, hf_ranap_item_repetitionNumber);
}


static const per_sequence_t MessageStructure_item_sequence[] = {
  { "iE-ID"                       , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_iE_ID },
  { "repetitionNumber"            , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_item_repetitionNumber },
  { "iE-Extensions"               , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_iE_Extensions },
  { NULL, 0, 0, NULL }
};

static int
dissect_ranap_MessageStructure_item(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ranap_MessageStructure_item, MessageStructure_item_sequence);

  return offset;
}
static int dissect_MessageStructure_item(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_ranap_MessageStructure_item(tvb, offset, actx, tree, hf_ranap_MessageStructure_item);
}


static const per_sequence_t MessageStructure_sequence_of[1] = {
  { ""                            , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_MessageStructure_item },
};

static int
dissect_ranap_MessageStructure(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_ranap_MessageStructure, MessageStructure_sequence_of,
                                                  1, 256);

  return offset;
}
static int dissect_id_MessageStructure(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_ranap_MessageStructure(tvb, offset, actx, tree, hf_ranap_id_MessageStructure);
}



static int
dissect_ranap_RAB_ReleaseList(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_ranap_RAB_IE_ContainerList(tvb, offset, actx, tree, hf_index);

  return offset;
}
static int dissect_id_RAB_ReleaseList(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_ranap_RAB_ReleaseList(tvb, offset, actx, tree, hf_ranap_id_RAB_ReleaseList);
}


static const per_sequence_t RAB_ReleasedItem_sequence[] = {
  { "rAB-ID"                      , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_rAB_ID },
  { "dl-dataVolumes"              , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_dl_dataVolumes },
  { "dL-GTP-PDU-SequenceNumber"   , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_dL_GTP_PDU_SequenceNumber },
  { "uL-GTP-PDU-SequenceNumber"   , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_uL_GTP_PDU_SequenceNumber },
  { "iE-Extensions"               , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_iE_Extensions },
  { NULL, 0, 0, NULL }
};

static int
dissect_ranap_RAB_ReleasedItem(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ranap_RAB_ReleasedItem, RAB_ReleasedItem_sequence);

  return offset;
}
static int dissect_id_RAB_ReleasedItem(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_ranap_RAB_ReleasedItem(tvb, offset, actx, tree, hf_ranap_id_RAB_ReleasedItem);
}



static int
dissect_ranap_RAB_ReleasedList(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_ranap_RAB_IE_ContainerList(tvb, offset, actx, tree, hf_index);

  return offset;
}
static int dissect_id_RAB_ReleasedList(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_ranap_RAB_ReleasedList(tvb, offset, actx, tree, hf_ranap_id_RAB_ReleasedList);
}



static int
dissect_ranap_RAB_ReleasedList_IuRelComp(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_ranap_RAB_IE_ContainerList(tvb, offset, actx, tree, hf_index);

  return offset;
}
static int dissect_id_RAB_ReleasedList_IuRelComp(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_ranap_RAB_ReleasedList_IuRelComp(tvb, offset, actx, tree, hf_ranap_id_RAB_ReleasedList_IuRelComp);
}


static const per_sequence_t RAB_RelocationReleaseItem_sequence[] = {
  { "rAB-ID"                      , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_rAB_ID },
  { "iE-Extensions"               , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_iE_Extensions },
  { NULL, 0, 0, NULL }
};

static int
dissect_ranap_RAB_RelocationReleaseItem(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ranap_RAB_RelocationReleaseItem, RAB_RelocationReleaseItem_sequence);

  return offset;
}
static int dissect_id_RAB_RelocationReleaseItem(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_ranap_RAB_RelocationReleaseItem(tvb, offset, actx, tree, hf_ranap_id_RAB_RelocationReleaseItem);
}



static int
dissect_ranap_RAB_RelocationReleaseList(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_ranap_RAB_IE_ContainerList(tvb, offset, actx, tree, hf_index);

  return offset;
}
static int dissect_id_RAB_RelocationReleaseList(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_ranap_RAB_RelocationReleaseList(tvb, offset, actx, tree, hf_ranap_id_RAB_RelocationReleaseList);
}



static int
dissect_ranap_NAS_SynchronisationIndicator(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_bit_string(tvb, offset, actx, tree, hf_index,
                                     4, 4, FALSE);

  return offset;
}
static int dissect_nAS_SynchronisationIndicator(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_ranap_NAS_SynchronisationIndicator(tvb, offset, actx, tree, hf_ranap_nAS_SynchronisationIndicator);
}


static const value_string ranap_DataVolumeReportingIndication_vals[] = {
  {   0, "do-report" },
  {   1, "do-not-report" },
  { 0, NULL }
};


static int
dissect_ranap_DataVolumeReportingIndication(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     2, NULL, FALSE, 0, NULL);

  return offset;
}
static int dissect_dataVolumeReportingIndication(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_ranap_DataVolumeReportingIndication(tvb, offset, actx, tree, hf_ranap_dataVolumeReportingIndication);
}


static const value_string ranap_UserPlaneMode_vals[] = {
  {   0, "transparent-mode" },
  {   1, "support-mode-for-predefined-SDU-sizes" },
  { 0, NULL }
};


static int
dissect_ranap_UserPlaneMode(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     2, NULL, TRUE, 0, NULL);

  return offset;
}
static int dissect_userPlaneMode(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_ranap_UserPlaneMode(tvb, offset, actx, tree, hf_ranap_userPlaneMode);
}



static int
dissect_ranap_UP_ModeVersions(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_bit_string(tvb, offset, actx, tree, hf_index,
                                     16, 16, FALSE);

  return offset;
}
static int dissect_uP_ModeVersions(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_ranap_UP_ModeVersions(tvb, offset, actx, tree, hf_ranap_uP_ModeVersions);
}


static const per_sequence_t UserPlaneInformation_sequence[] = {
  { "userPlaneMode"               , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_userPlaneMode },
  { "uP-ModeVersions"             , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_uP_ModeVersions },
  { "iE-Extensions"               , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_iE_Extensions },
  { NULL, 0, 0, NULL }
};

static int
dissect_ranap_UserPlaneInformation(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ranap_UserPlaneInformation, UserPlaneInformation_sequence);

  return offset;
}
static int dissect_userPlaneInformation(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_ranap_UserPlaneInformation(tvb, offset, actx, tree, hf_ranap_userPlaneInformation);
}


static const value_string ranap_Service_Handover_vals[] = {
  {   0, "handover-to-GSM-should-be-performed" },
  {   1, "handover-to-GSM-should-not-be-performed" },
  {   2, "handover-to-GSM-shall-not-be-performed" },
  { 0, NULL }
};


static int
dissect_ranap_Service_Handover(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     3, NULL, TRUE, 0, NULL);

  return offset;
}
static int dissect_service_Handover(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_ranap_Service_Handover(tvb, offset, actx, tree, hf_ranap_service_Handover);
}


static const per_sequence_t RAB_SetupItem_RelocReq_sequence[] = {
  { "rAB-ID"                      , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_rAB_ID },
  { "nAS-SynchronisationIndicator", ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_nAS_SynchronisationIndicator },
  { "rAB-Parameters"              , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_rAB_Parameters },
  { "dataVolumeReportingIndication", ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_dataVolumeReportingIndication },
  { "pDP-TypeInformation"         , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_pDP_TypeInformation },
  { "userPlaneInformation"        , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_userPlaneInformation },
  { "transportLayerAddress"       , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_transportLayerAddress },
  { "iuTransportAssociation"      , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_iuTransportAssociation },
  { "service-Handover"            , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_service_Handover },
  { "iE-Extensions"               , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_iE_Extensions },
  { NULL, 0, 0, NULL }
};

static int
dissect_ranap_RAB_SetupItem_RelocReq(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ranap_RAB_SetupItem_RelocReq, RAB_SetupItem_RelocReq_sequence);

  return offset;
}
static int dissect_id_RAB_SetupItem_RelocReq(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_ranap_RAB_SetupItem_RelocReq(tvb, offset, actx, tree, hf_ranap_id_RAB_SetupItem_RelocReq);
}


static const per_sequence_t RAB_SetupItem_RelocReqAck_sequence[] = {
  { "rAB-ID"                      , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_rAB_ID },
  { "transportLayerAddress"       , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_transportLayerAddress },
  { "iuTransportAssociation"      , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_iuTransportAssociation },
  { "iE-Extensions"               , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_iE_Extensions },
  { NULL, 0, 0, NULL }
};

static int
dissect_ranap_RAB_SetupItem_RelocReqAck(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ranap_RAB_SetupItem_RelocReqAck, RAB_SetupItem_RelocReqAck_sequence);

  return offset;
}
static int dissect_id_RAB_SetupItem_RelocReqAck(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_ranap_RAB_SetupItem_RelocReqAck(tvb, offset, actx, tree, hf_ranap_id_RAB_SetupItem_RelocReqAck);
}



static int
dissect_ranap_RAB_SetupList_RelocReq(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_ranap_RAB_IE_ContainerList(tvb, offset, actx, tree, hf_index);

  return offset;
}
static int dissect_id_RAB_SetupList_RelocReq(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_ranap_RAB_SetupList_RelocReq(tvb, offset, actx, tree, hf_ranap_id_RAB_SetupList_RelocReq);
}



static int
dissect_ranap_RAB_SetupList_RelocReqAck(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_ranap_RAB_IE_ContainerList(tvb, offset, actx, tree, hf_index);

  return offset;
}
static int dissect_id_RAB_SetupList_RelocReqAck(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_ranap_RAB_SetupList_RelocReqAck(tvb, offset, actx, tree, hf_ranap_id_RAB_SetupList_RelocReqAck);
}


static const per_sequence_t RAB_SetupOrModifiedItem_sequence[] = {
  { "rAB-ID"                      , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_rAB_ID },
  { "transportLayerAddress"       , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_transportLayerAddress },
  { "iuTransportAssociation"      , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_iuTransportAssociation },
  { "dl-dataVolumes"              , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_dl_dataVolumes },
  { "iE-Extensions"               , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_iE_Extensions },
  { NULL, 0, 0, NULL }
};

static int
dissect_ranap_RAB_SetupOrModifiedItem(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ranap_RAB_SetupOrModifiedItem, RAB_SetupOrModifiedItem_sequence);

  return offset;
}
static int dissect_id_RAB_SetupOrModifiedItem(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_ranap_RAB_SetupOrModifiedItem(tvb, offset, actx, tree, hf_ranap_id_RAB_SetupOrModifiedItem);
}



static int
dissect_ranap_RAB_SetupOrModifiedList(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_ranap_RAB_IE_ContainerList(tvb, offset, actx, tree, hf_index);

  return offset;
}
static int dissect_id_RAB_SetupOrModifiedList(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_ranap_RAB_SetupOrModifiedList(tvb, offset, actx, tree, hf_ranap_id_RAB_SetupOrModifiedList);
}



static int
dissect_ranap_FirstValue(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
#line 69 "ranap.cnf"
	offset = dissect_ranap_FirstValue_ies(tvb, offset, actx, tree);



  return offset;
}
static int dissect_firstValue(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_ranap_FirstValue(tvb, offset, actx, tree, hf_ranap_firstValue);
}



static int
dissect_ranap_SecondValue(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
#line 66 "ranap.cnf"
	offset = dissect_ranap_SecondValue_ies(tvb, offset, actx, tree);



  return offset;
}
static int dissect_secondValue(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_ranap_SecondValue(tvb, offset, actx, tree, hf_ranap_secondValue);
}


static const per_sequence_t ProtocolIE_FieldPair_sequence[] = {
  { "id"                          , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_id },
  { "firstCriticality"            , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_firstCriticality },
  { "firstValue"                  , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_firstValue },
  { "secondCriticality"           , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_secondCriticality },
  { "secondValue"                 , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_secondValue },
  { NULL, 0, 0, NULL }
};

static int
dissect_ranap_ProtocolIE_FieldPair(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ranap_ProtocolIE_FieldPair, ProtocolIE_FieldPair_sequence);

  return offset;
}
static int dissect_ProtocolIE_ContainerPair_item(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_ranap_ProtocolIE_FieldPair(tvb, offset, actx, tree, hf_ranap_ProtocolIE_ContainerPair_item);
}


static const per_sequence_t ProtocolIE_ContainerPair_sequence_of[1] = {
  { ""                            , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ProtocolIE_ContainerPair_item },
};

static int
dissect_ranap_ProtocolIE_ContainerPair(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_ranap_ProtocolIE_ContainerPair, ProtocolIE_ContainerPair_sequence_of,
                                                  0, 65535);

  return offset;
}
static int dissect_ProtocolIE_ContainerPairList_item(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_ranap_ProtocolIE_ContainerPair(tvb, offset, actx, tree, hf_ranap_ProtocolIE_ContainerPairList_item);
}
static int dissect_ProtocolIE_ContainerPairList256_item(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_ranap_ProtocolIE_ContainerPair(tvb, offset, actx, tree, hf_ranap_ProtocolIE_ContainerPairList256_item);
}


static const per_sequence_t ProtocolIE_ContainerPairList256_sequence_of[1] = {
  { ""                            , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ProtocolIE_ContainerPairList256_item },
};

static int
dissect_ranap_ProtocolIE_ContainerPairList256(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_ranap_ProtocolIE_ContainerPairList256, ProtocolIE_ContainerPairList256_sequence_of,
                                                  1, 256);

  return offset;
}



static int
dissect_ranap_RAB_IE_ContainerPairList(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_ranap_ProtocolIE_ContainerPairList256(tvb, offset, actx, tree, hf_index);

  return offset;
}



static int
dissect_ranap_RAB_SetupOrModifyList(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_ranap_RAB_IE_ContainerPairList(tvb, offset, actx, tree, hf_index);

  return offset;
}
static int dissect_id_RAB_SetupOrModifyList(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_ranap_RAB_SetupOrModifyList(tvb, offset, actx, tree, hf_ranap_id_RAB_SetupOrModifyList);
}


static const per_sequence_t RAofIdleModeUEs_sequence_of[1] = {
  { ""                            , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_RAofIdleModeUEs_item },
};

static int
dissect_ranap_RAofIdleModeUEs(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_ranap_RAofIdleModeUEs, RAofIdleModeUEs_sequence_of,
                                                  1, 65536);

  return offset;
}
static int dissect_rAofIdleModeUEs(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_ranap_RAofIdleModeUEs(tvb, offset, actx, tree, hf_ranap_rAofIdleModeUEs);
}


static const per_sequence_t NotEmptyRAListofIdleModeUEs_sequence[] = {
  { "rAofIdleModeUEs"             , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_rAofIdleModeUEs },
  { "iE-Extensions"               , ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_iE_Extensions },
  { NULL, 0, 0, NULL }
};

static int
dissect_ranap_NotEmptyRAListofIdleModeUEs(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ranap_NotEmptyRAListofIdleModeUEs, NotEmptyRAListofIdleModeUEs_sequence);

  return offset;
}
static int dissect_notEmptyRAListofIdleModeUEs(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_ranap_NotEmptyRAListofIdleModeUEs(tvb, offset, actx, tree, hf_ranap_notEmptyRAListofIdleModeUEs);
}


static const value_string ranap_T_emptyFullRAListofIdleModeUEs_vals[] = {
  {   0, "emptylist" },
  {   1, "fulllist" },
  { 0, NULL }
};


static int
dissect_ranap_T_emptyFullRAListofIdleModeUEs(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     2, NULL, TRUE, 0, NULL);

  return offset;
}
static int dissect_emptyFullRAListofIdleModeUEs(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_ranap_T_emptyFullRAListofIdleModeUEs(tvb, offset, actx, tree, hf_ranap_emptyFullRAListofIdleModeUEs);
}


static const value_string ranap_RAListofIdleModeUEs_vals[] = {
  {   0, "notEmptyRAListofIdleModeUEs" },
  {   1, "emptyFullRAListofIdleModeUEs" },
  { 0, NULL }
};

static const per_choice_t RAListofIdleModeUEs_choice[] = {
  {   0, "notEmptyRAListofIdleModeUEs" , ASN1_EXTENSION_ROOT    , dissect_notEmptyRAListofIdleModeUEs },
  {   1, "emptyFullRAListofIdleModeUEs", ASN1_EXTENSION_ROOT    , dissect_emptyFullRAListofIdleModeUEs },
  { 0, NULL, 0, NULL }
};

static int
dissect_ranap_RAListofIdleModeUEs(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_ranap_RAListofIdleModeUEs, RAListofIdleModeUEs_choice,
                                 NULL);

  return offset;
}
static int dissect_id_RAListofIdleModeUEs(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_ranap_RAListofIdleModeUEs(tvb, offset, actx, tree, hf_ranap_id_RAListofIdleModeUEs);
}


static const value_string ranap_RedirectionCompleted_vals[] = {
  {   0, "redirection-completed" },
  { 0, NULL }
};


static int
dissect_ranap_RedirectionCompleted(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     1, NULL, TRUE, 0, NULL);

  return offset;
}
static int dissect_id_RedirectionCompleted(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_ranap_RedirectionCompleted(tvb, offset, actx, tree, hf_ranap_id_RedirectionCompleted);
}



static int
dissect_ranap_RedirectionIndication(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_ranap_ProtocolIE_Container(tvb, offset, actx, tree, hf_index);

  return offset;
}
static int dissect_id_RedirectionIndication(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_ranap_RedirectionIndication(tvb, offset, actx, tree, hf_ranap_id_RedirectionIndication);
}


static const value_string ranap_RejectCauseValue_vals[] = {
  {   0, "pLMN-Not-Allowed" },
  {   1, "location-Area-Not-Allowed" },
  {   2, "roaming-Not-Allowed-In-This-Location-Area" },
  {   3, "no-Suitable-Cell-In-Location-Area" },
  {   4, "gPRS-Services-Not-Allowed-In-This-PLMN" },
  { 0, NULL }
};


static int
dissect_ranap_RejectCauseValue(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     5, NULL, TRUE, 0, NULL);

  return offset;
}
static int dissect_id_RejectCauseValue(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_ranap_RejectCauseValue(tvb, offset, actx, tree, hf_ranap_id_RejectCauseValue);
}


static const value_string ranap_RelocationType_vals[] = {
  {   0, "ue-not-involved" },
  {   1, "ue-involved" },
  { 0, NULL }
};


static int
dissect_ranap_RelocationType(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     2, NULL, TRUE, 0, NULL);

  return offset;
}
static int dissect_id_RelocationType(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_ranap_RelocationType(tvb, offset, actx, tree, hf_ranap_id_RelocationType);
}
static int dissect_relocationType(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_ranap_RelocationType(tvb, offset, actx, tree, hf_ranap_relocationType);
}


static const value_string ranap_Event_vals[] = {
  {   0, "stop-change-of-service-area" },
  {   1, "direct" },
  {   2, "change-of-servicearea" },
  {   3, "stop-direct" },
  { 0, NULL }
};


static int
dissect_ranap_Event(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     3, NULL, TRUE, 1, NULL);

  return offset;
}
static int dissect_event(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_ranap_Event(tvb, offset, actx, tree, hf_ranap_event);
}


static const value_string ranap_ReportArea_vals[] = {
  {   0, "service-area" },
  {   1, "geographical-area" },
  { 0, NULL }
};


static int
dissect_ranap_ReportArea(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     2, NULL, TRUE, 0, NULL);

  return offset;
}
static int dissect_reportArea(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_ranap_ReportArea(tvb, offset, actx, tree, hf_ranap_reportArea);
}


static const per_sequence_t RequestType_sequence[] = {
  { "event"                       , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_event },
  { "reportArea"                  , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_reportArea },
  { "accuracyCode"                , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_accuracyCode },
  { NULL, 0, 0, NULL }
};

static int
dissect_ranap_RequestType(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ranap_RequestType, RequestType_sequence);

  return offset;
}
static int dissect_id_RequestType(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_ranap_RequestType(tvb, offset, actx, tree, hf_ranap_id_RequestType);
}


static const value_string ranap_ResponseTime_vals[] = {
  {   0, "lowdelay" },
  {   1, "delaytolerant" },
  { 0, NULL }
};


static int
dissect_ranap_ResponseTime(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     2, NULL, TRUE, 0, NULL);

  return offset;
}
static int dissect_id_ResponseTime(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_ranap_ResponseTime(tvb, offset, actx, tree, hf_ranap_id_ResponseTime);
}



static int
dissect_ranap_SessionUpdateID(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                              0U, 1048575U, NULL, FALSE);

  return offset;
}
static int dissect_id_SessionUpdateID(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_ranap_SessionUpdateID(tvb, offset, actx, tree, hf_ranap_id_SessionUpdateID);
}


static const per_sequence_t AuthorisedSNAs_sequence_of[1] = {
  { ""                            , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_AuthorisedSNAs_item },
};

static int
dissect_ranap_AuthorisedSNAs(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_ranap_AuthorisedSNAs, AuthorisedSNAs_sequence_of,
                                                  1, 65536);

  return offset;
}
static int dissect_authorisedSNAsList(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_ranap_AuthorisedSNAs(tvb, offset, actx, tree, hf_ranap_authorisedSNAsList);
}


static const per_sequence_t AuthorisedPLMNs_item_sequence[] = {
  { "pLMNidentity"                , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pLMNidentity },
  { "authorisedSNAsList"          , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_authorisedSNAsList },
  { "iE-Extensions"               , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_iE_Extensions },
  { NULL, 0, 0, NULL }
};

static int
dissect_ranap_AuthorisedPLMNs_item(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ranap_AuthorisedPLMNs_item, AuthorisedPLMNs_item_sequence);

  return offset;
}
static int dissect_AuthorisedPLMNs_item(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_ranap_AuthorisedPLMNs_item(tvb, offset, actx, tree, hf_ranap_AuthorisedPLMNs_item);
}


static const per_sequence_t AuthorisedPLMNs_sequence_of[1] = {
  { ""                            , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_AuthorisedPLMNs_item },
};

static int
dissect_ranap_AuthorisedPLMNs(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_ranap_AuthorisedPLMNs, AuthorisedPLMNs_sequence_of,
                                                  1, 32);

  return offset;
}
static int dissect_authorisedPLMNs(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_ranap_AuthorisedPLMNs(tvb, offset, actx, tree, hf_ranap_authorisedPLMNs);
}


static const per_sequence_t SNA_Access_Information_sequence[] = {
  { "authorisedPLMNs"             , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_authorisedPLMNs },
  { "iE-Extensions"               , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_iE_Extensions },
  { NULL, 0, 0, NULL }
};

static int
dissect_ranap_SNA_Access_Information(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ranap_SNA_Access_Information, SNA_Access_Information_sequence);

  return offset;
}
static int dissect_id_SNA_Access_Information(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_ranap_SNA_Access_Information(tvb, offset, actx, tree, hf_ranap_id_SNA_Access_Information);
}


static const per_sequence_t SourceRNC_ID_sequence[] = {
  { "pLMNidentity"                , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_pLMNidentity },
  { "rNC-ID"                      , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_rNC_ID },
  { "iE-Extensions"               , ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_iE_Extensions },
  { NULL, 0, 0, NULL }
};

static int
dissect_ranap_SourceRNC_ID(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ranap_SourceRNC_ID, SourceRNC_ID_sequence);

  return offset;
}
static int dissect_sourceRNC_ID(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_ranap_SourceRNC_ID(tvb, offset, actx, tree, hf_ranap_sourceRNC_ID);
}


static const value_string ranap_SourceID_vals[] = {
  {   0, "sourceRNC-ID" },
  {   1, "sAI" },
  { 0, NULL }
};

static const per_choice_t SourceID_choice[] = {
  {   0, "sourceRNC-ID"                , ASN1_EXTENSION_ROOT    , dissect_sourceRNC_ID },
  {   1, "sAI"                         , ASN1_EXTENSION_ROOT    , dissect_sAI },
  { 0, NULL, 0, NULL }
};

static int
dissect_ranap_SourceID(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_ranap_SourceID, SourceID_choice,
                                 NULL);

  return offset;
}
static int dissect_id_SourceID(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_ranap_SourceID(tvb, offset, actx, tree, hf_ranap_id_SourceID);
}



static int
dissect_ranap_RRC_Container(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_octet_string(tvb, offset, actx, tree, hf_index,
                                       NO_BOUND, NO_BOUND, NULL);

  return offset;
}
static int dissect_id_SourceRNC_PDCP_context_info(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_ranap_RRC_Container(tvb, offset, actx, tree, hf_ranap_id_SourceRNC_PDCP_context_info);
}
static int dissect_rRC_Container(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_ranap_RRC_Container(tvb, offset, actx, tree, hf_ranap_rRC_Container);
}



static int
dissect_ranap_NumberOfIuInstances(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                              1U, 2U, NULL, FALSE);

  return offset;
}
static int dissect_numberOfIuInstances(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_ranap_NumberOfIuInstances(tvb, offset, actx, tree, hf_ranap_numberOfIuInstances);
}



static int
dissect_ranap_D_RNTI(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                              0U, 1048575U, NULL, FALSE);

  return offset;
}
static int dissect_d_RNTI(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_ranap_D_RNTI(tvb, offset, actx, tree, hf_ranap_d_RNTI);
}


static const per_sequence_t TrCH_ID_List_sequence_of[1] = {
  { ""                            , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_TrCH_ID_List_item },
};

static int
dissect_ranap_TrCH_ID_List(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_ranap_TrCH_ID_List, TrCH_ID_List_sequence_of,
                                                  1, 7);

  return offset;
}
static int dissect_trCH_ID_List(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_ranap_TrCH_ID_List(tvb, offset, actx, tree, hf_ranap_trCH_ID_List);
}


static const per_sequence_t RAB_TrCH_MappingItem_sequence[] = {
  { "rAB-ID"                      , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_rAB_ID },
  { "trCH-ID-List"                , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_trCH_ID_List },
  { "iE-Extensions"               , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_iE_Extensions },
  { NULL, 0, 0, NULL }
};

static int
dissect_ranap_RAB_TrCH_MappingItem(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ranap_RAB_TrCH_MappingItem, RAB_TrCH_MappingItem_sequence);

  return offset;
}
static int dissect_RAB_TrCH_Mapping_item(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_ranap_RAB_TrCH_MappingItem(tvb, offset, actx, tree, hf_ranap_RAB_TrCH_Mapping_item);
}


static const per_sequence_t RAB_TrCH_Mapping_sequence_of[1] = {
  { ""                            , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_RAB_TrCH_Mapping_item },
};

static int
dissect_ranap_RAB_TrCH_Mapping(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_ranap_RAB_TrCH_Mapping, RAB_TrCH_Mapping_sequence_of,
                                                  1, 256);

  return offset;
}
static int dissect_rAB_TrCH_Mapping(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_ranap_RAB_TrCH_Mapping(tvb, offset, actx, tree, hf_ranap_rAB_TrCH_Mapping);
}


static const per_sequence_t SourceRNC_ToTargetRNC_TransparentContainer_sequence[] = {
  { "rRC-Container"               , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_rRC_Container },
  { "numberOfIuInstances"         , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_numberOfIuInstances },
  { "relocationType"              , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_relocationType },
  { "chosenIntegrityProtectionAlgorithm", ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_chosenIntegrityProtectionAlgorithm },
  { "integrityProtectionKey"      , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_integrityProtectionKey },
  { "chosenEncryptionAlgorithForSignalling", ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_chosenEncryptionAlgorithForSignalling },
  { "cipheringKey"                , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_cipheringKey },
  { "chosenEncryptionAlgorithForCS", ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_chosenEncryptionAlgorithForCS },
  { "chosenEncryptionAlgorithForPS", ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_chosenEncryptionAlgorithForPS },
  { "d-RNTI"                      , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_d_RNTI },
  { "targetCellId"                , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_targetCellId },
  { "rAB-TrCH-Mapping"            , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_rAB_TrCH_Mapping },
  { "iE-Extensions"               , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_iE_Extensions },
  { NULL, 0, 0, NULL }
};

static int
dissect_ranap_SourceRNC_ToTargetRNC_TransparentContainer(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ranap_SourceRNC_ToTargetRNC_TransparentContainer, SourceRNC_ToTargetRNC_TransparentContainer_sequence);

  return offset;
}
static int dissect_id_SourceRNC_ToTargetRNC_TransparentContainer(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_ranap_SourceRNC_ToTargetRNC_TransparentContainer(tvb, offset, actx, tree, hf_ranap_id_SourceRNC_ToTargetRNC_TransparentContainer);
}


static const per_sequence_t TargetRNC_ID_sequence[] = {
  { "lAI"                         , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_lAI },
  { "rAC"                         , ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_rAC },
  { "rNC-ID"                      , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_rNC_ID },
  { "iE-Extensions"               , ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_iE_Extensions },
  { NULL, 0, 0, NULL }
};

static int
dissect_ranap_TargetRNC_ID(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ranap_TargetRNC_ID, TargetRNC_ID_sequence);

  return offset;
}
static int dissect_targetRNC_ID(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_ranap_TargetRNC_ID(tvb, offset, actx, tree, hf_ranap_targetRNC_ID);
}


const value_string ranap_TargetID_vals[] = {
  {   0, "targetRNC-ID" },
  {   1, "cGI" },
  { 0, NULL }
};

static const per_choice_t TargetID_choice[] = {
  {   0, "targetRNC-ID"                , ASN1_EXTENSION_ROOT    , dissect_targetRNC_ID },
  {   1, "cGI"                         , ASN1_EXTENSION_ROOT    , dissect_cGI },
  { 0, NULL, 0, NULL }
};

int
dissect_ranap_TargetID(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_ranap_TargetID, TargetID_choice,
                                 NULL);

  return offset;
}
static int dissect_id_TargetID(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_ranap_TargetID(tvb, offset, actx, tree, hf_ranap_id_TargetID);
}


static const per_sequence_t TargetRNC_ToSourceRNC_TransparentContainer_sequence[] = {
  { "rRC-Container"               , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_rRC_Container },
  { "d-RNTI"                      , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_d_RNTI },
  { "iE-Extensions"               , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_iE_Extensions },
  { NULL, 0, 0, NULL }
};

static int
dissect_ranap_TargetRNC_ToSourceRNC_TransparentContainer(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ranap_TargetRNC_ToSourceRNC_TransparentContainer, TargetRNC_ToSourceRNC_TransparentContainer_sequence);

  return offset;
}
static int dissect_id_TargetRNC_ToSourceRNC_TransparentContainer(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_ranap_TargetRNC_ToSourceRNC_TransparentContainer(tvb, offset, actx, tree, hf_ranap_id_TargetRNC_ToSourceRNC_TransparentContainer);
}



static int
dissect_ranap_TMSI(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_octet_string(tvb, offset, actx, tree, hf_index,
                                       4, 4, NULL);

  return offset;
}
static int dissect_tMSI(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_ranap_TMSI(tvb, offset, actx, tree, hf_ranap_tMSI);
}



static int
dissect_ranap_P_TMSI(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_octet_string(tvb, offset, actx, tree, hf_index,
                                       4, 4, NULL);

  return offset;
}
static int dissect_p_TMSI(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_ranap_P_TMSI(tvb, offset, actx, tree, hf_ranap_p_TMSI);
}


static const value_string ranap_TemporaryUE_ID_vals[] = {
  {   0, "tMSI" },
  {   1, "p-TMSI" },
  { 0, NULL }
};

static const per_choice_t TemporaryUE_ID_choice[] = {
  {   0, "tMSI"                        , ASN1_EXTENSION_ROOT    , dissect_tMSI },
  {   1, "p-TMSI"                      , ASN1_EXTENSION_ROOT    , dissect_p_TMSI },
  { 0, NULL, 0, NULL }
};

static int
dissect_ranap_TemporaryUE_ID(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_ranap_TemporaryUE_ID, TemporaryUE_ID_choice,
                                 NULL);

  return offset;
}
static int dissect_id_TemporaryUE_ID(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_ranap_TemporaryUE_ID(tvb, offset, actx, tree, hf_ranap_id_TemporaryUE_ID);
}


static const value_string ranap_TraceDepth_vals[] = {
  {   0, "minimum" },
  {   1, "medium" },
  {   2, "maximum" },
  { 0, NULL }
};


static int
dissect_ranap_TraceDepth(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     3, NULL, TRUE, 0, NULL);

  return offset;
}
static int dissect_traceDepth(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_ranap_TraceDepth(tvb, offset, actx, tree, hf_ranap_traceDepth);
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
dissect_ranap_T_interface(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     5, NULL, TRUE, 0, NULL);

  return offset;
}
static int dissect_interface(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_ranap_T_interface(tvb, offset, actx, tree, hf_ranap_interface);
}


static const per_sequence_t InterfacesToTraceItem_sequence[] = {
  { "interface"                   , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_interface },
  { "iE-Extensions"               , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_iE_Extensions },
  { NULL, 0, 0, NULL }
};

static int
dissect_ranap_InterfacesToTraceItem(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ranap_InterfacesToTraceItem, InterfacesToTraceItem_sequence);

  return offset;
}
static int dissect_ListOfInterfacesToTrace_item(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_ranap_InterfacesToTraceItem(tvb, offset, actx, tree, hf_ranap_ListOfInterfacesToTrace_item);
}


static const per_sequence_t ListOfInterfacesToTrace_sequence_of[1] = {
  { ""                            , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ListOfInterfacesToTrace_item },
};

static int
dissect_ranap_ListOfInterfacesToTrace(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_ranap_ListOfInterfacesToTrace, ListOfInterfacesToTrace_sequence_of,
                                                  1, 16);

  return offset;
}
static int dissect_listOfInterfacesToTrace(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_ranap_ListOfInterfacesToTrace(tvb, offset, actx, tree, hf_ranap_listOfInterfacesToTrace);
}


static const per_sequence_t TracePropagationParameters_sequence[] = {
  { "traceRecordingSessionReference", ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_traceRecordingSessionReference },
  { "traceDepth"                  , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_traceDepth },
  { "listOfInterfacesToTrace"     , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_listOfInterfacesToTrace },
  { "iE-Extensions"               , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_iE_Extensions },
  { NULL, 0, 0, NULL }
};

static int
dissect_ranap_TracePropagationParameters(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ranap_TracePropagationParameters, TracePropagationParameters_sequence);

  return offset;
}
static int dissect_id_TracePropagationParameters(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_ranap_TracePropagationParameters(tvb, offset, actx, tree, hf_ranap_id_TracePropagationParameters);
}



static int
dissect_ranap_TraceType(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_octet_string(tvb, offset, actx, tree, hf_index,
                                       1, 1, NULL);

  return offset;
}
static int dissect_id_TraceType(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_ranap_TraceType(tvb, offset, actx, tree, hf_ranap_id_TraceType);
}


static const per_sequence_t TransportLayerInformation_sequence[] = {
  { "transportLayerAddress"       , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_transportLayerAddress },
  { "iuTransportAssociation"      , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_iuTransportAssociation },
  { "iE-Extensions"               , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_iE_Extensions },
  { NULL, 0, 0, NULL }
};

static int
dissect_ranap_TransportLayerInformation(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ranap_TransportLayerInformation, TransportLayerInformation_sequence);

  return offset;
}
static int dissect_id_TransportLayerInformation(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_ranap_TransportLayerInformation(tvb, offset, actx, tree, hf_ranap_id_TransportLayerInformation);
}
static int dissect_transportLayerInformation(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_ranap_TransportLayerInformation(tvb, offset, actx, tree, hf_ranap_transportLayerInformation);
}



static int
dissect_ranap_TriggerID(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_octet_string(tvb, offset, actx, tree, hf_index,
                                       3, 22, NULL);

  return offset;
}
static int dissect_id_TriggerID(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_ranap_TriggerID(tvb, offset, actx, tree, hf_ranap_id_TriggerID);
}


static const value_string ranap_UE_ID_vals[] = {
  {   0, "imsi" },
  {   1, "imei" },
  {   2, "imeisv" },
  { 0, NULL }
};

static const per_choice_t UE_ID_choice[] = {
  {   0, "imsi"                        , ASN1_EXTENSION_ROOT    , dissect_imsi },
  {   1, "imei"                        , ASN1_EXTENSION_ROOT    , dissect_imei },
  {   2, "imeisv"                      , ASN1_NOT_EXTENSION_ROOT, dissect_imeisv },
  { 0, NULL, 0, NULL }
};

static int
dissect_ranap_UE_ID(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_ranap_UE_ID, UE_ID_choice,
                                 NULL);

  return offset;
}
static int dissect_id_UE_ID(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_ranap_UE_ID(tvb, offset, actx, tree, hf_ranap_id_UE_ID);
}



static int
dissect_ranap_UESBI_IuA(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_bit_string(tvb, offset, actx, tree, hf_index,
                                     1, 128, FALSE);

  return offset;
}
static int dissect_uESBI_IuA(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_ranap_UESBI_IuA(tvb, offset, actx, tree, hf_ranap_uESBI_IuA);
}



static int
dissect_ranap_UESBI_IuB(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_bit_string(tvb, offset, actx, tree, hf_index,
                                     1, 128, FALSE);

  return offset;
}
static int dissect_uESBI_IuB(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_ranap_UESBI_IuB(tvb, offset, actx, tree, hf_ranap_uESBI_IuB);
}


static const per_sequence_t UESBI_Iu_sequence[] = {
  { "uESBI-IuA"                   , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_uESBI_IuA },
  { "uESBI-IuB"                   , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_uESBI_IuB },
  { "iE-Extensions"               , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_iE_Extensions },
  { NULL, 0, 0, NULL }
};

static int
dissect_ranap_UESBI_Iu(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ranap_UESBI_Iu, UESBI_Iu_sequence);

  return offset;
}
static int dissect_id_UESBI_Iu(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_ranap_UESBI_Iu(tvb, offset, actx, tree, hf_ranap_id_UESBI_Iu);
}


static const per_sequence_t UnsuccessfulLinking_IEs_item_sequence[] = {
  { "tMGI"                        , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_tMGI },
  { "cause"                       , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_cause },
  { "iE-Extensions"               , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_iE_Extensions },
  { NULL, 0, 0, NULL }
};

static int
dissect_ranap_UnsuccessfulLinking_IEs_item(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ranap_UnsuccessfulLinking_IEs_item, UnsuccessfulLinking_IEs_item_sequence);

  return offset;
}
static int dissect_UnsuccessfulLinking_IEs_item(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_ranap_UnsuccessfulLinking_IEs_item(tvb, offset, actx, tree, hf_ranap_UnsuccessfulLinking_IEs_item);
}


static const per_sequence_t UnsuccessfulLinking_IEs_sequence_of[1] = {
  { ""                            , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_UnsuccessfulLinking_IEs_item },
};

static int
dissect_ranap_UnsuccessfulLinking_IEs(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_ranap_UnsuccessfulLinking_IEs, UnsuccessfulLinking_IEs_sequence_of,
                                                  1, 128);

  return offset;
}
static int dissect_id_UnsuccessfulLinkingList(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_ranap_UnsuccessfulLinking_IEs(tvb, offset, actx, tree, hf_ranap_id_UnsuccessfulLinkingList);
}



static int
dissect_ranap_VerticalAccuracyCode(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                              0U, 127U, NULL, FALSE);

  return offset;
}
static int dissect_id_VerticalAccuracyCode(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_ranap_VerticalAccuracyCode(tvb, offset, actx, tree, hf_ranap_id_VerticalAccuracyCode);
}


static const value_string ranap_MBMSLinkingInformation_vals[] = {
  {   0, "uE-has-joined-multicast-services" },
  { 0, NULL }
};


static int
dissect_ranap_MBMSLinkingInformation(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     1, NULL, TRUE, 0, NULL);

  return offset;
}
static int dissect_id_MBMSLinkingInformation(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_ranap_MBMSLinkingInformation(tvb, offset, actx, tree, hf_ranap_id_MBMSLinkingInformation);
}


static const value_string ranap_AlternativeRABConfigurationRequest_vals[] = {
  {   0, "alternative-RAB-configuration-Requested" },
  { 0, NULL }
};


static int
dissect_ranap_AlternativeRABConfigurationRequest(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     1, NULL, TRUE, 0, NULL);

  return offset;
}
static int dissect_id_AlternativeRABConfigurationRequest(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_ranap_AlternativeRABConfigurationRequest(tvb, offset, actx, tree, hf_ranap_id_AlternativeRABConfigurationRequest);
}



static int
dissect_ranap_E_DCH_MAC_d_Flow_ID(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                              0U, 7U, NULL, FALSE);

  return offset;
}
static int dissect_id_E_DCH_MAC_d_Flow_ID(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_ranap_E_DCH_MAC_d_Flow_ID(tvb, offset, actx, tree, hf_ranap_id_E_DCH_MAC_d_Flow_ID);
}


static const value_string ranap_Dymmy_ie_ids_vals[] = {
  {   0, "id-AccuracyFulfilmentIndicator" },
  {   1, "id-APN" },
  {   2, "id-AreaIdentity" },
  {   3, "id-Alt-RAB-Parameters" },
  {   4, "id-Ass-RAB-Parameters" },
  {   5, "id-BroadcastAssistanceDataDecipheringKeys" },
  {   6, "id-LocationRelatedDataRequestType" },
  {   7, "id-CN-DomainIndicator" },
  {   8, "id-Cause" },
  {   9, "id-ChosenEncryptionAlgorithm" },
  {  10, "id-ChosenIntegrityProtectionAlgorithm" },
  {  11, "id-ClassmarkInformation2" },
  {  12, "id-ClassmarkInformation3" },
  {  13, "id-ClientType" },
  {  14, "id-CNMBMSLinkingInformation" },
  {  15, "id-CriticalityDiagnostics" },
  {  16, "id-DeltaRAListofIdleModeUEs" },
  {  17, "id-DRX-CycleLengthCoefficient" },
  {  18, "id-DirectTransferInformationItem-RANAP-RelocInf" },
  {  19, "id-DirectTransferInformationList-RANAP-RelocInf" },
  {  20, "id-DL-GTP-PDU-SequenceNumber" },
  {  21, "id-EncryptionInformation" },
  {  22, "id-FrequenceLayerConvergenceFlag" },
  {  23, "id-GERAN-BSC-Container" },
  {  24, "id-GERAN-Classmark" },
  {  25, "id-GERAN-Iumode-RAB-Failed-RABAssgntResponse-Item" },
  {  26, "id-GERAN-Iumode-RAB-FailedList-RABAssgntResponse" },
  {  27, "id-GlobalCN-ID" },
  {  28, "id-GlobalRNC-ID" },
  {  29, "id-InformationExchangeID" },
  {  30, "id-InformationExchangeType" },
  {  31, "id-InformationRequested" },
  {  32, "id-InformationRequestType" },
  {  33, "id-InformationTransferID" },
  {  34, "id-InformationTransferType" },
  {  35, "id-TraceRecordingSessionInformation" },
  {  36, "id-IntegrityProtectionInformation" },
  {  37, "id-InterSystemInformationTransferType" },
  {  38, "id-InterSystemInformation-TransparentContainer" },
  {  39, "id-IPMulticastAddress" },
  {  40, "id-IuSigConId" },
  {  41, "id-IuSigConIdItem" },
  {  42, "id-IuSigConIdList" },
  {  43, "id-IuTransportAssociation" },
  {  44, "id-JoinedMBMSBearerServicesList" },
  {  45, "id-KeyStatus" },
  {  46, "id-L3-Information" },
  {  47, "id-LAI" },
  {  48, "id-LastKnownServiceArea" },
  {  49, "id-SRB-TrCH-Mapping" },
  {  50, "id-LeftMBMSBearerServicesList" },
  {  51, "id-LocationRelatedDataRequestTypeSpecificToGERANIuMode" },
  {  52, "id-SignallingIndication" },
  {  53, "id-hS-DSCH-MAC-d-Flow-ID" },
  {  54, "id-CellLoadInformationGroup" },
  {  55, "id-MBMSBearerServiceType" },
  {  56, "id-MBMSCNDe-Registration" },
  {  57, "id-MBMSRegistrationRequestType" },
  {  58, "id-MBMSServiceArea" },
  {  59, "id-MBMSSessionDuration" },
  {  60, "id-MBMSSessionIdentity" },
  {  61, "id-MBMSSessionRepetitionNumber" },
  {  62, "id-NAS-PDU" },
  {  63, "id-NAS-SequenceNumber" },
  {  64, "id-NewBSS-To-OldBSS-Information" },
  {  65, "id-NonSearchingIndication" },
  {  66, "id-NumberOfSteps" },
  {  67, "id-OMC-ID" },
  {  68, "id-OldBSS-ToNewBSS-Information" },
  {  69, "id-PagingAreaID" },
  {  70, "id-PagingCause" },
  {  71, "id-PDP-TypeInformation" },
  {  72, "id-PermanentNAS-UE-ID" },
  {  73, "id-PositionData" },
  {  74, "id-PositionDataSpecificToGERANIuMode" },
  {  75, "id-PositioningPriority" },
  {  76, "id-ProvidedData" },
  {  77, "id-RAB-ContextItem" },
  {  78, "id-RAB-ContextList" },
  {  79, "id-RAB-ContextFailedtoTransferItem" },
  {  80, "id-RAB-ContextFailedtoTransferList" },
  {  81, "id-RAB-ContextItem-RANAP-RelocInf" },
  {  82, "id-RAB-ContextList-RANAP-RelocInf" },
  {  83, "id-RAB-DataForwardingItem" },
  {  84, "id-RAB-DataForwardingItem-SRNS-CtxReq" },
  {  85, "id-RAB-DataForwardingList" },
  {  86, "id-RAB-DataForwardingList-SRNS-CtxReq" },
  {  87, "id-RAB-DataVolumeReportItem" },
  {  88, "id-RAB-DataVolumeReportList" },
  {  89, "id-RAB-DataVolumeReportRequestItem" },
  {  90, "id-RAB-DataVolumeReportRequestList" },
  {  91, "id-RAB-FailedItem" },
  {  92, "id-RAB-FailedList" },
  {  93, "id-RAB-FailedtoReportItem" },
  {  94, "id-RAB-FailedtoReportList" },
  {  95, "id-RAB-ID" },
  {  96, "id-RAB-ModifyList" },
  {  97, "id-RAB-ModifyItem" },
  {  98, "id-TypeOfError" },
  {  99, "id-RAB-Parameters" },
  { 100, "id-RAB-QueuedItem" },
  { 101, "id-RAB-QueuedList" },
  { 102, "id-RAB-ReleaseFailedList" },
  { 103, "id-RAB-ReleaseItem" },
  { 104, "id-RAB-ReleasedItem-IuRelComp" },
  { 105, "id-MessageStructure" },
  { 106, "id-RAB-ReleaseList" },
  { 107, "id-RAB-ReleasedItem" },
  { 108, "id-RAB-ReleasedList" },
  { 109, "id-RAB-ReleasedList-IuRelComp" },
  { 110, "id-RAB-RelocationReleaseItem" },
  { 111, "id-RAB-RelocationReleaseList" },
  { 112, "id-RAB-SetupItem-RelocReq" },
  { 113, "id-RAB-SetupItem-RelocReqAck" },
  { 114, "id-RAB-SetupList-RelocReq" },
  { 115, "id-RAB-SetupList-RelocReqAck" },
  { 116, "id-RAB-SetupOrModifiedItem" },
  { 117, "id-RAB-SetupOrModifiedList" },
  { 118, "id-RAB-SetupOrModifyList" },
  { 119, "id-RAC" },
  { 120, "id-RAListofIdleModeUEs" },
  { 121, "id-RedirectionCompleted" },
  { 122, "id-RedirectionIndication" },
  { 123, "id-RejectCauseValue" },
  { 124, "id-RelocationType" },
  { 125, "id-RequestType" },
  { 126, "id-ResponseTime" },
  { 127, "id-SAI" },
  { 128, "id-SAPI" },
  { 129, "id-SelectedPLMN-ID" },
  { 130, "id-SessionUpdateID" },
  { 131, "id-SNA-Access-Information" },
  { 132, "id-SourceID" },
  { 133, "id-SourceRNC-ToTargetRNC-TransparentContainer" },
  { 134, "id-SourceRNC-PDCP-context-info" },
  { 135, "id-TargetID" },
  { 136, "id-TargetRNC-ToSourceRNC-TransparentContainer" },
  { 137, "id-TemporaryUE-ID" },
  { 138, "id-TMGI" },
  { 139, "id-TracePropagationParameters" },
  { 140, "id-TraceReference" },
  { 141, "id-TraceType" },
  { 142, "id-TransportLayerAddress" },
  { 143, "id-TransportLayerInformation" },
  { 144, "id-TriggerID" },
  { 145, "id-UE-ID" },
  { 146, "id-UESBI-Iu" },
  { 147, "id-UL-GTP-PDU-SequenceNumber" },
  { 148, "id-UnsuccessfulLinkingList" },
  { 149, "id-VerticalAccuracyCode" },
  { 150, "id-MBMSLinkingInformation" },
  { 151, "id-AlternativeRABConfiguration" },
  { 152, "id-AlternativeRABConfigurationRequest" },
  { 153, "id-E-DCH-MAC-d-Flow-ID" },
  { 0, NULL }
};

static const per_choice_t Dymmy_ie_ids_choice[] = {
  {   0, "id-AccuracyFulfilmentIndicator", ASN1_NO_EXTENSIONS     , dissect_id_AccuracyFulfilmentIndicator },
  {   1, "id-APN"                      , ASN1_NO_EXTENSIONS     , dissect_id_APN },
  {   2, "id-AreaIdentity"             , ASN1_NO_EXTENSIONS     , dissect_id_AreaIdentity },
  {   3, "id-Alt-RAB-Parameters"       , ASN1_NO_EXTENSIONS     , dissect_id_Alt_RAB_Parameters },
  {   4, "id-Ass-RAB-Parameters"       , ASN1_NO_EXTENSIONS     , dissect_id_Ass_RAB_Parameters },
  {   5, "id-BroadcastAssistanceDataDecipheringKeys", ASN1_NO_EXTENSIONS     , dissect_id_BroadcastAssistanceDataDecipheringKeys },
  {   6, "id-LocationRelatedDataRequestType", ASN1_NO_EXTENSIONS     , dissect_id_LocationRelatedDataRequestType },
  {   7, "id-CN-DomainIndicator"       , ASN1_NO_EXTENSIONS     , dissect_id_CN_DomainIndicator },
  {   8, "id-Cause"                    , ASN1_NO_EXTENSIONS     , dissect_id_Cause },
  {   9, "id-ChosenEncryptionAlgorithm", ASN1_NO_EXTENSIONS     , dissect_id_ChosenEncryptionAlgorithm },
  {  10, "id-ChosenIntegrityProtectionAlgorithm", ASN1_NO_EXTENSIONS     , dissect_id_ChosenIntegrityProtectionAlgorithm },
  {  11, "id-ClassmarkInformation2"    , ASN1_NO_EXTENSIONS     , dissect_id_ClassmarkInformation2 },
  {  12, "id-ClassmarkInformation3"    , ASN1_NO_EXTENSIONS     , dissect_id_ClassmarkInformation3 },
  {  13, "id-ClientType"               , ASN1_NO_EXTENSIONS     , dissect_id_ClientType },
  {  14, "id-CNMBMSLinkingInformation" , ASN1_NO_EXTENSIONS     , dissect_id_CNMBMSLinkingInformation },
  {  15, "id-CriticalityDiagnostics"   , ASN1_NO_EXTENSIONS     , dissect_id_CriticalityDiagnostics },
  {  16, "id-DeltaRAListofIdleModeUEs" , ASN1_NO_EXTENSIONS     , dissect_id_DeltaRAListofIdleModeUEs },
  {  17, "id-DRX-CycleLengthCoefficient", ASN1_NO_EXTENSIONS     , dissect_id_DRX_CycleLengthCoefficient },
  {  18, "id-DirectTransferInformationItem-RANAP-RelocInf", ASN1_NO_EXTENSIONS     , dissect_id_DirectTransferInformationItem_RANAP_RelocInf },
  {  19, "id-DirectTransferInformationList-RANAP-RelocInf", ASN1_NO_EXTENSIONS     , dissect_id_DirectTransferInformationList_RANAP_RelocInf },
  {  20, "id-DL-GTP-PDU-SequenceNumber", ASN1_NO_EXTENSIONS     , dissect_id_DL_GTP_PDU_SequenceNumber },
  {  21, "id-EncryptionInformation"    , ASN1_NO_EXTENSIONS     , dissect_id_EncryptionInformation },
  {  22, "id-FrequenceLayerConvergenceFlag", ASN1_NO_EXTENSIONS     , dissect_id_FrequenceLayerConvergenceFlag },
  {  23, "id-GERAN-BSC-Container"      , ASN1_NO_EXTENSIONS     , dissect_id_GERAN_BSC_Container },
  {  24, "id-GERAN-Classmark"          , ASN1_NO_EXTENSIONS     , dissect_id_GERAN_Classmark },
  {  25, "id-GERAN-Iumode-RAB-Failed-RABAssgntResponse-Item", ASN1_NO_EXTENSIONS     , dissect_id_GERAN_Iumode_RAB_Failed_RABAssgntResponse_Item },
  {  26, "id-GERAN-Iumode-RAB-FailedList-RABAssgntResponse", ASN1_NO_EXTENSIONS     , dissect_id_GERAN_Iumode_RAB_FailedList_RABAssgntResponse },
  {  27, "id-GlobalCN-ID"              , ASN1_NO_EXTENSIONS     , dissect_id_GlobalCN_ID },
  {  28, "id-GlobalRNC-ID"             , ASN1_NO_EXTENSIONS     , dissect_id_GlobalRNC_ID },
  {  29, "id-InformationExchangeID"    , ASN1_NO_EXTENSIONS     , dissect_id_InformationExchangeID },
  {  30, "id-InformationExchangeType"  , ASN1_NO_EXTENSIONS     , dissect_id_InformationExchangeType },
  {  31, "id-InformationRequested"     , ASN1_NO_EXTENSIONS     , dissect_id_InformationRequested },
  {  32, "id-InformationRequestType"   , ASN1_NO_EXTENSIONS     , dissect_id_InformationRequestType },
  {  33, "id-InformationTransferID"    , ASN1_NO_EXTENSIONS     , dissect_id_InformationTransferID },
  {  34, "id-InformationTransferType"  , ASN1_NO_EXTENSIONS     , dissect_id_InformationTransferType },
  {  35, "id-TraceRecordingSessionInformation", ASN1_NO_EXTENSIONS     , dissect_id_TraceRecordingSessionInformation },
  {  36, "id-IntegrityProtectionInformation", ASN1_NO_EXTENSIONS     , dissect_id_IntegrityProtectionInformation },
  {  37, "id-InterSystemInformationTransferType", ASN1_NO_EXTENSIONS     , dissect_id_InterSystemInformationTransferType },
  {  38, "id-InterSystemInformation-TransparentContainer", ASN1_NO_EXTENSIONS     , dissect_id_InterSystemInformation_TransparentContainer },
  {  39, "id-IPMulticastAddress"       , ASN1_NO_EXTENSIONS     , dissect_id_IPMulticastAddress },
  {  40, "id-IuSigConId"               , ASN1_NO_EXTENSIONS     , dissect_id_IuSigConId },
  {  41, "id-IuSigConIdItem"           , ASN1_NO_EXTENSIONS     , dissect_id_IuSigConIdItem },
  {  42, "id-IuSigConIdList"           , ASN1_NO_EXTENSIONS     , dissect_id_IuSigConIdList },
  {  43, "id-IuTransportAssociation"   , ASN1_NO_EXTENSIONS     , dissect_id_IuTransportAssociation },
  {  44, "id-JoinedMBMSBearerServicesList", ASN1_NO_EXTENSIONS     , dissect_id_JoinedMBMSBearerServicesList },
  {  45, "id-KeyStatus"                , ASN1_NO_EXTENSIONS     , dissect_id_KeyStatus },
  {  46, "id-L3-Information"           , ASN1_NO_EXTENSIONS     , dissect_id_L3_Information },
  {  47, "id-LAI"                      , ASN1_NO_EXTENSIONS     , dissect_id_LAI },
  {  48, "id-LastKnownServiceArea"     , ASN1_NO_EXTENSIONS     , dissect_id_LastKnownServiceArea },
  {  49, "id-SRB-TrCH-Mapping"         , ASN1_NO_EXTENSIONS     , dissect_id_SRB_TrCH_Mapping },
  {  50, "id-LeftMBMSBearerServicesList", ASN1_NO_EXTENSIONS     , dissect_id_LeftMBMSBearerServicesList },
  {  51, "id-LocationRelatedDataRequestTypeSpecificToGERANIuMode", ASN1_NO_EXTENSIONS     , dissect_id_LocationRelatedDataRequestTypeSpecificToGERANIuMode },
  {  52, "id-SignallingIndication"     , ASN1_NO_EXTENSIONS     , dissect_id_SignallingIndication },
  {  53, "id-hS-DSCH-MAC-d-Flow-ID"    , ASN1_NO_EXTENSIONS     , dissect_id_hS_DSCH_MAC_d_Flow_ID },
  {  54, "id-CellLoadInformationGroup" , ASN1_NO_EXTENSIONS     , dissect_id_CellLoadInformationGroup },
  {  55, "id-MBMSBearerServiceType"    , ASN1_NO_EXTENSIONS     , dissect_id_MBMSBearerServiceType },
  {  56, "id-MBMSCNDe-Registration"    , ASN1_NO_EXTENSIONS     , dissect_id_MBMSCNDe_Registration },
  {  57, "id-MBMSRegistrationRequestType", ASN1_NO_EXTENSIONS     , dissect_id_MBMSRegistrationRequestType },
  {  58, "id-MBMSServiceArea"          , ASN1_NO_EXTENSIONS     , dissect_id_MBMSServiceArea },
  {  59, "id-MBMSSessionDuration"      , ASN1_NO_EXTENSIONS     , dissect_id_MBMSSessionDuration },
  {  60, "id-MBMSSessionIdentity"      , ASN1_NO_EXTENSIONS     , dissect_id_MBMSSessionIdentity },
  {  61, "id-MBMSSessionRepetitionNumber", ASN1_NO_EXTENSIONS     , dissect_id_MBMSSessionRepetitionNumber },
  {  62, "id-NAS-PDU"                  , ASN1_NO_EXTENSIONS     , dissect_id_NAS_PDU },
  {  63, "id-NAS-SequenceNumber"       , ASN1_NO_EXTENSIONS     , dissect_id_NAS_SequenceNumber },
  {  64, "id-NewBSS-To-OldBSS-Information", ASN1_NO_EXTENSIONS     , dissect_id_NewBSS_To_OldBSS_Information },
  {  65, "id-NonSearchingIndication"   , ASN1_NO_EXTENSIONS     , dissect_id_NonSearchingIndication },
  {  66, "id-NumberOfSteps"            , ASN1_NO_EXTENSIONS     , dissect_id_NumberOfSteps },
  {  67, "id-OMC-ID"                   , ASN1_NO_EXTENSIONS     , dissect_id_OMC_ID },
  {  68, "id-OldBSS-ToNewBSS-Information", ASN1_NO_EXTENSIONS     , dissect_id_OldBSS_ToNewBSS_Information },
  {  69, "id-PagingAreaID"             , ASN1_NO_EXTENSIONS     , dissect_id_PagingAreaID },
  {  70, "id-PagingCause"              , ASN1_NO_EXTENSIONS     , dissect_id_PagingCause },
  {  71, "id-PDP-TypeInformation"      , ASN1_NO_EXTENSIONS     , dissect_id_PDP_TypeInformation },
  {  72, "id-PermanentNAS-UE-ID"       , ASN1_NO_EXTENSIONS     , dissect_id_PermanentNAS_UE_ID },
  {  73, "id-PositionData"             , ASN1_NO_EXTENSIONS     , dissect_id_PositionData },
  {  74, "id-PositionDataSpecificToGERANIuMode", ASN1_NO_EXTENSIONS     , dissect_id_PositionDataSpecificToGERANIuMode },
  {  75, "id-PositioningPriority"      , ASN1_NO_EXTENSIONS     , dissect_id_PositioningPriority },
  {  76, "id-ProvidedData"             , ASN1_NO_EXTENSIONS     , dissect_id_ProvidedData },
  {  77, "id-RAB-ContextItem"          , ASN1_NO_EXTENSIONS     , dissect_id_RAB_ContextItem },
  {  78, "id-RAB-ContextList"          , ASN1_NO_EXTENSIONS     , dissect_id_RAB_ContextList },
  {  79, "id-RAB-ContextFailedtoTransferItem", ASN1_NO_EXTENSIONS     , dissect_id_RAB_ContextFailedtoTransferItem },
  {  80, "id-RAB-ContextFailedtoTransferList", ASN1_NO_EXTENSIONS     , dissect_id_RAB_ContextFailedtoTransferList },
  {  81, "id-RAB-ContextItem-RANAP-RelocInf", ASN1_NO_EXTENSIONS     , dissect_id_RAB_ContextItem_RANAP_RelocInf },
  {  82, "id-RAB-ContextList-RANAP-RelocInf", ASN1_NO_EXTENSIONS     , dissect_id_RAB_ContextList_RANAP_RelocInf },
  {  83, "id-RAB-DataForwardingItem"   , ASN1_NO_EXTENSIONS     , dissect_id_RAB_DataForwardingItem },
  {  84, "id-RAB-DataForwardingItem-SRNS-CtxReq", ASN1_NO_EXTENSIONS     , dissect_id_RAB_DataForwardingItem_SRNS_CtxReq },
  {  85, "id-RAB-DataForwardingList"   , ASN1_NO_EXTENSIONS     , dissect_id_RAB_DataForwardingList },
  {  86, "id-RAB-DataForwardingList-SRNS-CtxReq", ASN1_NO_EXTENSIONS     , dissect_id_RAB_DataForwardingList_SRNS_CtxReq },
  {  87, "id-RAB-DataVolumeReportItem" , ASN1_NO_EXTENSIONS     , dissect_id_RAB_DataVolumeReportItem },
  {  88, "id-RAB-DataVolumeReportList" , ASN1_NO_EXTENSIONS     , dissect_id_RAB_DataVolumeReportList },
  {  89, "id-RAB-DataVolumeReportRequestItem", ASN1_NO_EXTENSIONS     , dissect_id_RAB_DataVolumeReportRequestItem },
  {  90, "id-RAB-DataVolumeReportRequestList", ASN1_NO_EXTENSIONS     , dissect_id_RAB_DataVolumeReportRequestList },
  {  91, "id-RAB-FailedItem"           , ASN1_NO_EXTENSIONS     , dissect_id_RAB_FailedItem },
  {  92, "id-RAB-FailedList"           , ASN1_NO_EXTENSIONS     , dissect_id_RAB_FailedList },
  {  93, "id-RAB-FailedtoReportItem"   , ASN1_NO_EXTENSIONS     , dissect_id_RAB_FailedtoReportItem },
  {  94, "id-RAB-FailedtoReportList"   , ASN1_NO_EXTENSIONS     , dissect_id_RAB_FailedtoReportList },
  {  95, "id-RAB-ID"                   , ASN1_NO_EXTENSIONS     , dissect_id_RAB_ID },
  {  96, "id-RAB-ModifyList"           , ASN1_NO_EXTENSIONS     , dissect_id_RAB_ModifyList },
  {  97, "id-RAB-ModifyItem"           , ASN1_NO_EXTENSIONS     , dissect_id_RAB_ModifyItem },
  {  98, "id-TypeOfError"              , ASN1_NO_EXTENSIONS     , dissect_id_TypeOfError },
  {  99, "id-RAB-Parameters"           , ASN1_NO_EXTENSIONS     , dissect_id_RAB_Parameters },
  { 100, "id-RAB-QueuedItem"           , ASN1_NO_EXTENSIONS     , dissect_id_RAB_QueuedItem },
  { 101, "id-RAB-QueuedList"           , ASN1_NO_EXTENSIONS     , dissect_id_RAB_QueuedList },
  { 102, "id-RAB-ReleaseFailedList"    , ASN1_NO_EXTENSIONS     , dissect_id_RAB_ReleaseFailedList },
  { 103, "id-RAB-ReleaseItem"          , ASN1_NO_EXTENSIONS     , dissect_id_RAB_ReleaseItem },
  { 104, "id-RAB-ReleasedItem-IuRelComp", ASN1_NO_EXTENSIONS     , dissect_id_RAB_ReleasedItem_IuRelComp },
  { 105, "id-MessageStructure"         , ASN1_NO_EXTENSIONS     , dissect_id_MessageStructure },
  { 106, "id-RAB-ReleaseList"          , ASN1_NO_EXTENSIONS     , dissect_id_RAB_ReleaseList },
  { 107, "id-RAB-ReleasedItem"         , ASN1_NO_EXTENSIONS     , dissect_id_RAB_ReleasedItem },
  { 108, "id-RAB-ReleasedList"         , ASN1_NO_EXTENSIONS     , dissect_id_RAB_ReleasedList },
  { 109, "id-RAB-ReleasedList-IuRelComp", ASN1_NO_EXTENSIONS     , dissect_id_RAB_ReleasedList_IuRelComp },
  { 110, "id-RAB-RelocationReleaseItem", ASN1_NO_EXTENSIONS     , dissect_id_RAB_RelocationReleaseItem },
  { 111, "id-RAB-RelocationReleaseList", ASN1_NO_EXTENSIONS     , dissect_id_RAB_RelocationReleaseList },
  { 112, "id-RAB-SetupItem-RelocReq"   , ASN1_NO_EXTENSIONS     , dissect_id_RAB_SetupItem_RelocReq },
  { 113, "id-RAB-SetupItem-RelocReqAck", ASN1_NO_EXTENSIONS     , dissect_id_RAB_SetupItem_RelocReqAck },
  { 114, "id-RAB-SetupList-RelocReq"   , ASN1_NO_EXTENSIONS     , dissect_id_RAB_SetupList_RelocReq },
  { 115, "id-RAB-SetupList-RelocReqAck", ASN1_NO_EXTENSIONS     , dissect_id_RAB_SetupList_RelocReqAck },
  { 116, "id-RAB-SetupOrModifiedItem"  , ASN1_NO_EXTENSIONS     , dissect_id_RAB_SetupOrModifiedItem },
  { 117, "id-RAB-SetupOrModifiedList"  , ASN1_NO_EXTENSIONS     , dissect_id_RAB_SetupOrModifiedList },
  { 118, "id-RAB-SetupOrModifyList"    , ASN1_NO_EXTENSIONS     , dissect_id_RAB_SetupOrModifyList },
  { 119, "id-RAC"                      , ASN1_NO_EXTENSIONS     , dissect_id_RAC },
  { 120, "id-RAListofIdleModeUEs"      , ASN1_NO_EXTENSIONS     , dissect_id_RAListofIdleModeUEs },
  { 121, "id-RedirectionCompleted"     , ASN1_NO_EXTENSIONS     , dissect_id_RedirectionCompleted },
  { 122, "id-RedirectionIndication"    , ASN1_NO_EXTENSIONS     , dissect_id_RedirectionIndication },
  { 123, "id-RejectCauseValue"         , ASN1_NO_EXTENSIONS     , dissect_id_RejectCauseValue },
  { 124, "id-RelocationType"           , ASN1_NO_EXTENSIONS     , dissect_id_RelocationType },
  { 125, "id-RequestType"              , ASN1_NO_EXTENSIONS     , dissect_id_RequestType },
  { 126, "id-ResponseTime"             , ASN1_NO_EXTENSIONS     , dissect_id_ResponseTime },
  { 127, "id-SAI"                      , ASN1_NO_EXTENSIONS     , dissect_id_SAI },
  { 128, "id-SAPI"                     , ASN1_NO_EXTENSIONS     , dissect_id_SAPI },
  { 129, "id-SelectedPLMN-ID"          , ASN1_NO_EXTENSIONS     , dissect_id_SelectedPLMN_ID },
  { 130, "id-SessionUpdateID"          , ASN1_NO_EXTENSIONS     , dissect_id_SessionUpdateID },
  { 131, "id-SNA-Access-Information"   , ASN1_NO_EXTENSIONS     , dissect_id_SNA_Access_Information },
  { 132, "id-SourceID"                 , ASN1_NO_EXTENSIONS     , dissect_id_SourceID },
  { 133, "id-SourceRNC-ToTargetRNC-TransparentContainer", ASN1_NO_EXTENSIONS     , dissect_id_SourceRNC_ToTargetRNC_TransparentContainer },
  { 134, "id-SourceRNC-PDCP-context-info", ASN1_NO_EXTENSIONS     , dissect_id_SourceRNC_PDCP_context_info },
  { 135, "id-TargetID"                 , ASN1_NO_EXTENSIONS     , dissect_id_TargetID },
  { 136, "id-TargetRNC-ToSourceRNC-TransparentContainer", ASN1_NO_EXTENSIONS     , dissect_id_TargetRNC_ToSourceRNC_TransparentContainer },
  { 137, "id-TemporaryUE-ID"           , ASN1_NO_EXTENSIONS     , dissect_id_TemporaryUE_ID },
  { 138, "id-TMGI"                     , ASN1_NO_EXTENSIONS     , dissect_id_TMGI },
  { 139, "id-TracePropagationParameters", ASN1_NO_EXTENSIONS     , dissect_id_TracePropagationParameters },
  { 140, "id-TraceReference"           , ASN1_NO_EXTENSIONS     , dissect_id_TraceReference },
  { 141, "id-TraceType"                , ASN1_NO_EXTENSIONS     , dissect_id_TraceType },
  { 142, "id-TransportLayerAddress"    , ASN1_NO_EXTENSIONS     , dissect_id_TransportLayerAddress },
  { 143, "id-TransportLayerInformation", ASN1_NO_EXTENSIONS     , dissect_id_TransportLayerInformation },
  { 144, "id-TriggerID"                , ASN1_NO_EXTENSIONS     , dissect_id_TriggerID },
  { 145, "id-UE-ID"                    , ASN1_NO_EXTENSIONS     , dissect_id_UE_ID },
  { 146, "id-UESBI-Iu"                 , ASN1_NO_EXTENSIONS     , dissect_id_UESBI_Iu },
  { 147, "id-UL-GTP-PDU-SequenceNumber", ASN1_NO_EXTENSIONS     , dissect_id_UL_GTP_PDU_SequenceNumber },
  { 148, "id-UnsuccessfulLinkingList"  , ASN1_NO_EXTENSIONS     , dissect_id_UnsuccessfulLinkingList },
  { 149, "id-VerticalAccuracyCode"     , ASN1_NO_EXTENSIONS     , dissect_id_VerticalAccuracyCode },
  { 150, "id-MBMSLinkingInformation"   , ASN1_NO_EXTENSIONS     , dissect_id_MBMSLinkingInformation },
  { 151, "id-AlternativeRABConfiguration", ASN1_NO_EXTENSIONS     , dissect_id_AlternativeRABConfiguration },
  { 152, "id-AlternativeRABConfigurationRequest", ASN1_NO_EXTENSIONS     , dissect_id_AlternativeRABConfigurationRequest },
  { 153, "id-E-DCH-MAC-d-Flow-ID"      , ASN1_NO_EXTENSIONS     , dissect_id_E_DCH_MAC_d_Flow_ID },
  { 0, NULL, 0, NULL }
};

static int
dissect_ranap_Dymmy_ie_ids(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_ranap_Dymmy_ie_ids, Dymmy_ie_ids_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t RAB_SetupOrModifyItemFirst_sequence[] = {
  { "rAB-ID"                      , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_rAB_ID },
  { "nAS-SynchronisationIndicator", ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_nAS_SynchronisationIndicator },
  { "rAB-Parameters"              , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_rAB_Parameters },
  { "userPlaneInformation"        , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_userPlaneInformation },
  { "transportLayerInformation"   , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_transportLayerInformation },
  { "service-Handover"            , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_service_Handover },
  { "iE-Extensions"               , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_iE_Extensions },
  { NULL, 0, 0, NULL }
};

static int
dissect_ranap_RAB_SetupOrModifyItemFirst(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ranap_RAB_SetupOrModifyItemFirst, RAB_SetupOrModifyItemFirst_sequence);

  return offset;
}
static int dissect_id_RAB_SetupOrModifyItem1(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_ranap_RAB_SetupOrModifyItemFirst(tvb, offset, actx, tree, hf_ranap_id_RAB_SetupOrModifyItem1);
}


static const value_string ranap_Dymmy_firstvalue_ie_ids_vals[] = {
  {   0, "id-RAB-SetupOrModifyItem1" },
  { 0, NULL }
};

static const per_choice_t Dymmy_firstvalue_ie_ids_choice[] = {
  {   0, "id-RAB-SetupOrModifyItem1"   , ASN1_EXTENSION_ROOT    , dissect_id_RAB_SetupOrModifyItem1 },
  { 0, NULL, 0, NULL }
};

static int
dissect_ranap_Dymmy_firstvalue_ie_ids(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_ranap_Dymmy_firstvalue_ie_ids, Dymmy_firstvalue_ie_ids_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t RAB_SetupOrModifyItemSecond_sequence[] = {
  { "pDP-TypeInformation"         , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_pDP_TypeInformation },
  { "dataVolumeReportingIndication", ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_dataVolumeReportingIndication },
  { "dl-GTP-PDU-SequenceNumber"   , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_dl_GTP_PDU_SequenceNumber },
  { "ul-GTP-PDU-SequenceNumber"   , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ul_GTP_PDU_SequenceNumber },
  { "dl-N-PDU-SequenceNumber"     , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_dl_N_PDU_SequenceNumber },
  { "ul-N-PDU-SequenceNumber"     , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ul_N_PDU_SequenceNumber },
  { "iE-Extensions"               , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_iE_Extensions },
  { NULL, 0, 0, NULL }
};

static int
dissect_ranap_RAB_SetupOrModifyItemSecond(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ranap_RAB_SetupOrModifyItemSecond, RAB_SetupOrModifyItemSecond_sequence);

  return offset;
}
static int dissect_id_RAB_SetupOrModifyItem2(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_ranap_RAB_SetupOrModifyItemSecond(tvb, offset, actx, tree, hf_ranap_id_RAB_SetupOrModifyItem2);
}


static const value_string ranap_Dymmy_secondvalue_ie_ids_vals[] = {
  {   0, "id-RAB-SetupOrModifyItem2" },
  { 0, NULL }
};

static const per_choice_t Dymmy_secondvalue_ie_ids_choice[] = {
  {   0, "id-RAB-SetupOrModifyItem2"   , ASN1_EXTENSION_ROOT    , dissect_id_RAB_SetupOrModifyItem2 },
  { 0, NULL, 0, NULL }
};

static int
dissect_ranap_Dymmy_secondvalue_ie_ids(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_ranap_Dymmy_secondvalue_ie_ids, Dymmy_secondvalue_ie_ids_choice,
                                 NULL);

  return offset;
}



static int
dissect_ranap_ProtocolError_IE_ContainerList(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_ranap_ProtocolIE_ContainerList256(tvb, offset, actx, tree, hf_index);

  return offset;
}



static int
dissect_ranap_ResetResourceList(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_ranap_IuSigConId_IE_ContainerList(tvb, offset, actx, tree, hf_index);

  return offset;
}


static const per_sequence_t ResetResourceItem_sequence[] = {
  { "iuSigConId"                  , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_iuSigConId },
  { "iE-Extensions"               , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_iE_Extensions },
  { NULL, 0, 0, NULL }
};

static int
dissect_ranap_ResetResourceItem(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ranap_ResetResourceItem, ResetResourceItem_sequence);

  return offset;
}


static const value_string ranap_RateControlAllowed_vals[] = {
  {   0, "not-allowed" },
  {   1, "allowed" },
  { 0, NULL }
};


static int
dissect_ranap_RateControlAllowed(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     2, NULL, FALSE, 0, NULL);

  return offset;
}


static const value_string ranap_Presence_vals[] = {
  {   0, "optional" },
  {   1, "conditional" },
  {   2, "mandatory" },
  { 0, NULL }
};


static int
dissect_ranap_Presence(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     3, NULL, FALSE, 0, NULL);

  return offset;
}



static int
dissect_ranap_ProcedureCodeSuccessfulOutcome(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                              0U, 255U, NULL, FALSE);

  return offset;
}



static int
dissect_ranap_ProcedureCodeUnsuccessfulOutcome(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                              0U, 255U, NULL, FALSE);

  return offset;
}



static int
dissect_ranap_ProcedureCodeOutcome(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                              0U, 255U, NULL, FALSE);

  return offset;
}


static const per_sequence_t ProtocolIE_ContainerList_sequence_of[1] = {
  { ""                            , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ProtocolIE_ContainerList_item },
};

static int
dissect_ranap_ProtocolIE_ContainerList(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_sequence_of(tvb, offset, actx, tree, hf_index,
                                      ett_ranap_ProtocolIE_ContainerList, ProtocolIE_ContainerList_sequence_of);

  return offset;
}


static const per_sequence_t ProtocolIE_ContainerPairList_sequence_of[1] = {
  { ""                            , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ProtocolIE_ContainerPairList_item },
};

static int
dissect_ranap_ProtocolIE_ContainerPairList(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_sequence_of(tvb, offset, actx, tree, hf_index,
                                      ett_ranap_ProtocolIE_ContainerPairList, ProtocolIE_ContainerPairList_sequence_of);

  return offset;
}

/*--- PDUs ---*/

static int dissect_RANAP_PDU_PDU(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree) {
  asn_ctx_t asn_ctx;
  asn_ctx_init(&asn_ctx, ASN_ENC_PER, TRUE, pinfo);
  return dissect_ranap_RANAP_PDU(tvb, 0, &asn_ctx, tree, hf_ranap_RANAP_PDU_PDU);
}


/*--- End of included file: packet-ranap-fn.c ---*/
#line 85 "packet-ranap-template.c"



static int dissect_ranap_ies(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree){

	guint length;
	
	offset = dissect_per_length_determinant(tvb, offset, actx, tree, hf_ranap_IE_length, &length);
	switch(ProtocolIE_ID){
		case 0: /*id-AreaIdentity */
			offset = dissect_id_AreaIdentity(tvb, offset, actx, tree);
			break;
		case 3: /*id-CN-DomainIndicator */
			offset = dissect_id_CN_DomainIndicator(tvb, offset, actx, tree);
			break;
		case 4: /* Cause */
			offset = dissect_id_Cause(tvb, offset, actx, tree);
			break;
		case 5: /*id-ChosenEncryptionAlgorithm */
			offset = dissect_id_ChosenEncryptionAlgorithm(tvb, offset, actx, tree);
			break;
		case 6: /*id-ChosenIntegrityProtectionAlgorithm */
			offset = dissect_id_ChosenIntegrityProtectionAlgorithm(tvb, offset, actx, tree);
			break;
		case 7: /*id-ClassmarkInformation2 */
			offset = dissect_id_ClassmarkInformation2(tvb, offset, actx, tree);
			break;
		case 8: /*id-ClassmarkInformation3 */
			offset = dissect_id_ClassmarkInformation3(tvb, offset, actx, tree);
			break;
		case 9: /*id-CriticalityDiagnostics */
			offset = dissect_id_CriticalityDiagnostics(tvb, offset, actx, tree);
			break;
		case 10: /*id-DL-GTP-PDU-SequenceNumber */
			offset = dissect_id_DL_GTP_PDU_SequenceNumber(tvb, offset, actx, tree);
			break;
		case 11: /*id-EncryptionInformation */
			offset = dissect_id_EncryptionInformation(tvb, offset, actx, tree);
			break;
		case 12: /*id-IntegrityProtectionInformation */
			offset = dissect_id_IntegrityProtectionInformation(tvb, offset, actx, tree);
			break;
		case 13: /*id-IuTransportAssociation */
			offset = dissect_id_IuTransportAssociation(tvb, offset, actx, tree);
			break;
		case 14: /*id-L3-Information */
			offset = dissect_id_L3_Information(tvb, offset, actx, tree);
			break;
		case 15: /*id-LAI */
			offset = dissect_id_LAI(tvb, offset, actx, tree);
			break;
		case 16: /*id-NAS-PDU */
			offset = dissect_id_NAS_PDU(tvb, offset, actx, tree);
			break;
		case 17: /*id-NonSearchingIndication */
			offset = dissect_id_NonSearchingIndication(tvb, offset, actx, tree);
			break;
		case 18: /*id-NumberOfSteps */
			offset = dissect_id_NumberOfSteps(tvb, offset, actx, tree);
			break;
		case 19: /*id-OMC-ID */
			offset = dissect_id_OMC_ID(tvb, offset, actx, tree);
			break;
		case 20: /*id-OldBSS-ToNewBSS-Information */
			offset = dissect_id_OldBSS_ToNewBSS_Information(tvb, offset, actx, tree);
			break;
		case 21: /*id-PagingAreaID */
			offset = dissect_id_PagingAreaID(tvb, offset, actx, tree);
			break;
		case 22: /*id-PagingCause */
			offset = dissect_id_PagingCause(tvb, offset, actx, tree);
			break;
		case 23: /*id-PermanentNAS-UE-ID */
			offset = dissect_id_PermanentNAS_UE_ID(tvb, offset, actx, tree);
			break;
		case 24: /*id-RAB-ContextItem */
			offset = dissect_id_RAB_ContextItem(tvb, offset, actx, tree);
			break;
		case 25: /*id-RAB-ContextList */
			offset = dissect_id_RAB_ContextList(tvb, offset, actx, tree);
			break;
		case 26: /*id-RAB-DataForwardingItem */
			offset = dissect_id_RAB_DataForwardingItem(tvb, offset, actx, tree);
			break;
		case 27: /*id-RAB-DataForwardingItem-SRNS-CtxReq */
			break;
		case 28: /*id-RAB-DataForwardingList */
			offset = dissect_id_RAB_DataForwardingList(tvb, offset, actx, tree);
			break;
		case 29: /*id-RAB-DataForwardingList-SRNS-CtxReq */
			offset = dissect_id_RAB_DataForwardingList_SRNS_CtxReq(tvb, offset, actx, tree);
			break;
		case 30: /*id-RAB-DataVolumeReportItem */
			offset = dissect_id_RAB_DataVolumeReportItem(tvb, offset, actx, tree);
			break;
		case 31: /*id-RAB-DataVolumeReportList */
			offset = dissect_id_RAB_DataVolumeReportList(tvb, offset, actx, tree);
			break;
		case 32: /*id-RAB-DataVolumeReportRequestItem */
			offset = dissect_id_RAB_DataVolumeReportRequestItem(tvb, offset, actx, tree);
			break;
		case 33: /*id-RAB-DataVolumeReportRequestList */
			offset = dissect_id_RAB_DataVolumeReportRequestList(tvb, offset, actx, tree);
			break;
		case 34: /*id-RAB-FailedItem */
			offset = dissect_id_RAB_FailedItem(tvb, offset, actx, tree);
			break;
		case 35: /*id-RAB-FailedList */
			offset = dissect_id_RAB_FailedList(tvb, offset, actx, tree);
			break;
		case 36: /*id-RAB-ID */
			offset = dissect_id_RAB_ID(tvb, offset, actx, tree);
			break;
		case 37: /*id-RAB-QueuedItem */
			offset = dissect_id_RAB_QueuedItem(tvb, offset, actx, tree);
			break;
		case 38: /*id-RAB-QueuedList */
			offset = dissect_id_RAB_QueuedList(tvb, offset, actx, tree);
			break;
		case 39: /*id-RAB-ReleaseFailedList */
			offset = dissect_id_RAB_ReleaseFailedList(tvb, offset, actx, tree);
			break;
		case 40: /*id-RAB-ReleaseItem */
			offset = dissect_id_RAB_ReleaseItem(tvb, offset, actx, tree);
			break;
		case 41: /*id-RAB-ReleaseList */
			offset = dissect_id_RAB_ReleaseList(tvb, offset, actx, tree);
			break;
		case 42: /*id-RAB-ReleasedItem */
			offset = dissect_id_RAB_ReleasedItem(tvb, offset, actx, tree);
			break;
		case 43: /*id-RAB-ReleasedList */
			offset = dissect_id_RAB_ReleasedList(tvb, offset, actx, tree);
			break;
		case 44: /* id-RAB-ReleasedList-IuRelComp */
			offset = dissect_id_RAB_ReleasedList_IuRelComp(tvb, offset, actx, tree);
			break;
		case 45: /*id-RAB-RelocationReleaseItem */
			offset = dissect_id_RAB_RelocationReleaseItem(tvb, offset, actx, tree);
			break;
		case 46: /*id-RAB-RelocationReleaseList */
			offset = dissect_id_RAB_RelocationReleaseList(tvb, offset, actx, tree);
			break;
		case 47: /*id-RAB-SetupItem-RelocReq */
			offset = dissect_id_RAB_SetupItem_RelocReq(tvb, offset, actx, tree);
			break;
		case 48: /*id-RAB-SetupItem-RelocReqAck */
			offset = dissect_id_RAB_SetupItem_RelocReqAck(tvb, offset, actx, tree);
			break;
		case 49: /*id-RAB-SetupList-RelocReq */
			offset = dissect_id_RAB_SetupList_RelocReq(tvb, offset, actx, tree);
			break;
		case 50: /*id-RAB-SetupList-RelocReqAck */
			offset = dissect_id_RAB_SetupList_RelocReqAck(tvb, offset, actx, tree);
			break;
		case 51: /*id-RAB-SetupOrModifiedItem */
			offset = dissect_id_RAB_SetupOrModifiedItem(tvb, offset, actx, tree);
			break;
		case 52: /*id-RAB-SetupOrModifiedList */
			offset = dissect_id_RAB_SetupOrModifiedList(tvb, offset, actx, tree);
			break;
		case 53: /*id-RAB-SetupOrModifyItem */
			/* Special handling */ 
			break;
		case 54: /*id-RAB-SetupOrModifyList */
			offset = dissect_id_RAB_SetupOrModifyList(tvb, offset, actx, tree);
			break;
		case 55: /*id-RAC */
			offset = dissect_id_RAC(tvb, offset, actx, tree);
			break;
		case 56: /*id-RelocationType */
			offset =  dissect_id_RelocationType(tvb, offset, actx, tree);
			break;
		case 57: /*id-RequestType */
			offset =  dissect_id_RequestType(tvb, offset, actx, tree);
			break;
		case 58: /*id-SAI */
			offset = dissect_id_SAI(tvb, offset, actx, tree);
			break;
		case 59: /*id-SAPI */
			offset = dissect_id_SAPI(tvb, offset, actx, tree);
			break;
		case 60: /*id-SourceID */
			offset = dissect_id_SourceID(tvb, offset, actx, tree);
			break;
		case 61: /*id-SourceRNC-ToTargetRNC-TransparentContainer */
			offset = dissect_id_SourceRNC_ToTargetRNC_TransparentContainer(tvb, offset, actx, tree);
			break;
		case 62: /*id-TargetID */
			offset = dissect_id_TargetID(tvb, offset, actx, tree);
			break;
		case 63: /*id-TargetRNC-ToSourceRNC-TransparentContainer */
			offset = dissect_id_TargetRNC_ToSourceRNC_TransparentContainer(tvb, offset, actx, tree);
			break;
		case 64: /*id-TemporaryUE-ID */
			offset = dissect_id_TemporaryUE_ID(tvb, offset, actx, tree);
			break;
		case 65: /*id-TraceReference */
			offset = dissect_id_TraceReference(tvb, offset, actx, tree);
			break;
		case 66: /*id-TraceType */
			offset = dissect_id_TraceType(tvb, offset, actx, tree);
			break;
		case 67: /*id-TransportLayerAddress */
			offset = dissect_id_TransportLayerAddress(tvb, offset, actx, tree);
			break;
		case 68: /*id-TriggerID */
			offset = dissect_id_TriggerID(tvb, offset, actx, tree);
			break;
		case 69: /*id-UE-ID */
			offset = dissect_id_UE_ID(tvb, offset, actx, tree);
			break;
		case 70: /*id-UL-GTP-PDU-SequenceNumber */
			offset = dissect_id_UL_GTP_PDU_SequenceNumber(tvb, offset, actx, tree);
			break;
		case 71: /*id-RAB-FailedtoReportItem */
			offset = dissect_id_RAB_FailedtoReportItem(tvb, offset, actx, tree);
			break;
		case 72: /*id-RAB-FailedtoReportList */
			offset = dissect_id_RAB_FailedtoReportList(tvb, offset, actx, tree);
			break;
		case 75: /*id-KeyStatus */
			offset = dissect_id_KeyStatus(tvb, offset, actx, tree);
			break;
		case 76: /*id-DRX-CycleLengthCoefficient */
			offset = dissect_id_DRX_CycleLengthCoefficient(tvb, offset, actx, tree);
			break;
		case 77: /*id-IuSigConIdList */
			offset = dissect_id_IuSigConIdList(tvb, offset, actx, tree);
			break;
		case 78: /*id-IuSigConIdItem */
			offset = dissect_id_IuSigConIdItem(tvb, offset, actx, tree);
			break;
		case 79: /*id-IuSigConId */
			offset = dissect_id_IuSigConId(tvb, offset, actx, tree);
			break;
		case 81: /*id-DirectTransferInformationList-RANAP-RelocInf */
			offset = dissect_id_DirectTransferInformationItem_RANAP_RelocInf(tvb, offset, actx, tree);
			break;
		case 82: /*id-RAB-ContextItem-RANAP-RelocInf */
			offset = dissect_id_RAB_ContextItem_RANAP_RelocInf(tvb, offset, actx, tree);
			break;
		case 83: /*id-RAB-ContextList-RANAP-RelocInf */
			offset = dissect_id_RAB_ContextList_RANAP_RelocInf(tvb, offset, actx, tree);
			break;
		case 84: /*id-RAB-ContextFailedtoTransferItem */
			offset = dissect_id_RAB_ContextFailedtoTransferItem(tvb, offset, actx, tree);
			break;
		case 85: /*id-RAB-ContextFailedtoTransferList */
			offset = dissect_id_RAB_ContextFailedtoTransferList(tvb, offset, actx, tree);
			break;
		case 86: /*id-GlobalRNC-ID */
			offset = dissect_id_GlobalRNC_ID(tvb, offset, actx, tree);
			break;
		case 87: /* id-RAB-ReleasedItem-IuRelComp */
			offset = dissect_id_RAB_ReleasedItem_IuRelComp(tvb, offset, actx, tree);
			break;
		case 88: /*id-MessageStructure */
			offset = dissect_id_MessageStructure(tvb, offset, actx, tree);
			break;
		case 89: /*id-Alt-RAB-Parameters */
			offset = dissect_id_Alt_RAB_Parameters(tvb, offset, actx, tree);
			break;
		case 90: /*id-Ass-RAB-Parameters */
			offset = dissect_id_Ass_RAB_Parameters(tvb, offset, actx, tree);
			break;
		case 91: /*id-RAB-ModifyList */
			offset = dissect_id_RAB_ModifyList(tvb, offset, actx, tree);
			break;
		case 92: /*id-RAB-ModifyItem */
			offset = dissect_id_RAB_ModifyItem(tvb, offset, actx, tree);
			break;
		case 93: /*id-TypeOfError */
			offset = dissect_id_TypeOfError(tvb, offset, actx, tree);
			break;
		case 94: /*id-BroadcastAssistanceDataDecipheringKeys */
			offset = dissect_id_BroadcastAssistanceDataDecipheringKeys(tvb, offset, actx, tree);
			break;
		case 95: /*id-LocationRelatedDataRequestType */
			offset = dissect_id_LocationRelatedDataRequestType(tvb, offset, actx, tree);
			break;
		case 96: /*id-GlobalCN-ID */
			offset = dissect_id_GlobalCN_ID(tvb, offset, actx, tree);
			break;
		case 97: /*id-LastKnownServiceArea */
			offset = dissect_id_LastKnownServiceArea(tvb, offset, actx, tree);
			break;
		case 98: /*id-SRB-TrCH-Mapping */
			offset = dissect_id_SRB_TrCH_Mapping(tvb, offset, actx, tree);
			break;
		case 99: /*id-InterSystemInformation-TransparentContainer */
			offset = dissect_id_InterSystemInformation_TransparentContainer(tvb, offset, actx, tree);
			break;
		case 100: /*id-NewBSS-To-OldBSS-Information */
			offset = dissect_id_OldBSS_ToNewBSS_Information(tvb, offset, actx, tree);
			break;
		case 103: /*id-SourceRNC-PDCP-context-info */
			offset = dissect_id_SourceRNC_PDCP_context_info(tvb, offset, actx, tree);
			break;
		case 104: /*id-InformationTransferID */
			offset = dissect_id_InformationTransferID(tvb, offset, actx, tree);
			break;
		case 105: /*id-SNA-Access-Information */
			offset = dissect_id_SNA_Access_Information(tvb, offset, actx, tree);
			break;
		case 106: /*id-ProvidedData */
			offset = dissect_id_ProvidedData(tvb, offset, actx, tree);
			break;
		case 107: /*id-GERAN-BSC-Container */
			offset = dissect_id_GERAN_BSC_Container(tvb, offset, actx, tree);
			break;
		case 108: /*id-GERAN-Classmark */
			offset = dissect_id_GERAN_Classmark(tvb, offset, actx, tree);
			break;
		case 109: /*id-GERAN-Iumode-RAB-Failed-RABAssgntResponse-Item */
			offset = dissect_id_GERAN_Iumode_RAB_Failed_RABAssgntResponse_Item(tvb, offset, actx, tree);
			break;
		case 110: /*id-GERAN-Iumode-RAB-FailedList-RABAssgntResponse */
			offset = dissect_id_GERAN_Iumode_RAB_FailedList_RABAssgntResponse(tvb, offset, actx, tree);
			break;
		case 111: /*id-VerticalAccuracyCode */
			offset = dissect_id_VerticalAccuracyCode(tvb, offset, actx, tree);
			break;
		case 112: /*id-ResponseTime */
			offset = dissect_id_ResponseTime(tvb, offset, actx, tree);
			break;
		case 113: /*id-PositioningPriority */
			offset = dissect_id_PositioningPriority(tvb, offset, actx, tree);
			break;
		case 114: /*id-ClientType */
			offset = dissect_id_ClientType(tvb, offset, actx, tree);
			break;
		case 115: /*id-LocationRelatedDataRequestTypeSpecificToGERANIuMode */
			offset = dissect_id_LocationRelatedDataRequestTypeSpecificToGERANIuMode(tvb, offset, actx, tree);
			break;
		case 116: /*id-SignallingIndication */
			offset = dissect_id_SignallingIndication(tvb, offset, actx, tree);
			break;
		case 117: /*id-hS-DSCH-MAC-d-Flow-ID */
			offset = dissect_id_hS_DSCH_MAC_d_Flow_ID(tvb, offset, actx, tree);
			break;
		case 118: /*id-UESBI-Iu */
			offset = dissect_id_UESBI_Iu(tvb, offset, actx, tree);
			break;
		case 119: /*id-PositionData */
			offset = dissect_id_PositionData(tvb, offset, actx, tree);
			break;
		case 120: /*id-PositionDataSpecificToGERANIuMode */
			offset = dissect_id_PositionDataSpecificToGERANIuMode(tvb, offset, actx, tree);
			break;
		case 121: /*id-CellLoadInformationGroup */
			offset = dissect_id_CellLoadInformationGroup(tvb, offset, actx, tree);
			break;
		case 122: /*id-AccuracyFulfilmentIndicator */
			offset = dissect_id_AccuracyFulfilmentIndicator(tvb, offset, actx, tree);
			break;
		case 123: /*id-InformationTransferType */
			offset = dissect_id_InformationTransferType(tvb, offset, actx, tree);
			break;
		case 124: /*id-TraceRecordingSessionInformation */
			offset = dissect_id_TraceRecordingSessionInformation(tvb, offset, actx, tree);
			break;
		case 125: /*id-TracePropagationParameters */
			offset = dissect_id_TracePropagationParameters(tvb, offset, actx, tree);
			break;
		case 126: /*id-InterSystemInformationTransferType */
			offset = dissect_id_InterSystemInformationTransferType(tvb, offset, actx, tree);
			break;
		case 127: /*id-SelectedPLMN-ID */
			offset = dissect_id_SelectedPLMN_ID(tvb, offset, actx, tree);
			break;
		case 128: /*id-RedirectionCompleted */
			offset = dissect_id_RedirectionCompleted(tvb, offset, actx, tree);
			break;
		case 129: /*id-RedirectionIndication */
			offset = dissect_id_RedirectionIndication(tvb, offset, actx, tree);
			break;
		case 130: /*id-NAS-SequenceNumber */
			offset = dissect_id_NAS_SequenceNumber(tvb, offset, actx, tree);
			break;
		case 131: /*id-RejectCauseValue */
			offset = dissect_id_RejectCauseValue(tvb, offset, actx, tree);
			break;
		case 132: /*id-APN */
			offset = dissect_id_APN(tvb, offset, actx, tree);
		case 133: /*id-CNMBMSLinkingInformation */
			offset = dissect_id_CNMBMSLinkingInformation(tvb, offset, actx, tree);
			break;
		case 134: /*id-DeltaRAListofIdleModeUEs */
			offset = dissect_id_DeltaRAListofIdleModeUEs(tvb, offset, actx, tree);
			break;
		case 135: /*id-FrequenceLayerConvergenceFlag */
			offset = dissect_id_FrequenceLayerConvergenceFlag(tvb, offset, actx, tree);
			break;
		case 136: /*id-InformationExchangeID */
			offset = dissect_id_InformationExchangeID(tvb, offset, actx, tree);
			break;
		case 137: /*id-InformationExchangeType */
			offset = dissect_id_InformationExchangeType(tvb, offset, actx, tree);
			break;
		case 138: /*id-InformationRequested */
			offset = dissect_id_InformationRequested(tvb, offset, actx, tree);
			break;
		case 139: /*id-InformationRequestType */
			offset = dissect_id_InformationRequestType(tvb, offset, actx, tree);
			break;
		case 140: /*id-IPMulticastAddress */
			offset = dissect_id_IPMulticastAddress(tvb, offset, actx, tree);
			break;
		case 141: /*id-JoinedMBMSBearerServicesList */
			offset = dissect_id_JoinedMBMSBearerServicesList(tvb, offset, actx, tree);
			break;
		case 142: /*id-LeftMBMSBearerServicesList */
			offset = dissect_id_LeftMBMSBearerServicesList(tvb, offset, actx, tree);
			break;
		case 143: /*id-MBMSBearerServiceType */
			offset = dissect_id_MBMSBearerServiceType(tvb, offset, actx, tree);
			break;
		case 144: /*id-MBMSCNDe-Registration */
			offset = dissect_id_MBMSCNDe_Registration(tvb, offset, actx, tree);
			break;
		case 145: /*id-MBMSServiceArea */
			offset = dissect_id_MBMSServiceArea(tvb, offset, actx, tree);
			break;
		case 146: /*id-MBMSSessionDuration */
			offset = dissect_id_MBMSSessionDuration(tvb, offset, actx, tree);
			break;
		case 147: /*id-MBMSSessionIdentity */
			offset = dissect_id_MBMSSessionIdentity(tvb, offset, actx, tree);
			break;
		case 148: /*id-PDP-TypeInformation */
			offset = dissect_id_PDP_TypeInformation(tvb, offset, actx, tree);
			break;
		case 149: /*id-RAB-Parameters */
			offset = dissect_id_RAB_Parameters(tvb, offset, actx, tree);
			break;
		case 150: /*id-RAListofIdleModeUEs */
			offset = dissect_id_RAListofIdleModeUEs(tvb, offset, actx, tree);
			break;
		case 151: /*id-MBMSRegistrationRequestType */
			offset = dissect_id_MBMSRegistrationRequestType(tvb, offset, actx, tree);
			break;
		case 152: /*id-SessionUpdateID */
			offset = dissect_id_SessionUpdateID(tvb, offset, actx, tree);
			break;
		case 153: /*id-TMGI */
			offset = dissect_id_TMGI(tvb, offset, actx, tree);
			break;
		case 154: /*id-TransportLayerInformation */
			offset = dissect_id_TransportLayerInformation(tvb, offset, actx, tree);
			break;
		case 155: /*id-UnsuccessfulLinkingList */
			offset = dissect_id_UnsuccessfulLinkingList(tvb, offset, actx, tree);
			break;
		case 156: /*id-MBMSLinkingInformation */
			offset = dissect_id_MBMSLinkingInformation(tvb, offset, actx, tree);
			break;
		case 157: /*id-MBMSSessionRepetitionNumber */
			offset = dissect_id_MBMSSessionRepetitionNumber(tvb, offset, actx, tree);
			break;
		case 158: /*id-AlternativeRABConfiguration */
			offset = dissect_id_AlternativeRABConfiguration(tvb, offset, actx, tree);
			break;
		case 159: /*id-AlternativeRABConfigurationRequest */
			offset = dissect_id_AlternativeRABConfigurationRequest(tvb, offset, actx, tree);
			break;
		case 160: /*id-E-DCH-MAC-d-Flow-ID */
			offset = dissect_id_E_DCH_MAC_d_Flow_ID(tvb, offset, actx, tree);
			break;
		default:
			offset = offset + (length<<3);
			break;
			
	}
	return offset;
}

static int dissect_ranap_FirstValue_ies(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree){

	guint length;
	int start_offset;
	
	offset = dissect_per_length_determinant(tvb, offset, actx, tree, hf_ranap_IE_length, &length);
	start_offset = offset;
	switch(ProtocolIE_ID){
		case 53: /*id-RAB-SetupOrModifyItem */
			offset = dissect_id_RAB_SetupOrModifyItem1(tvb, offset, actx, tree);
			break;
		default:
			offset = offset + (length<<3);
			break;
	}
	/* We might not stop on a byte boundary */
	BYTE_ALIGN_OFFSET(offset);
	return offset;
}

static int dissect_ranap_SecondValue_ies(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree){

	guint length;
	
	offset = dissect_per_length_determinant(tvb, offset, actx, tree, hf_ranap_IE_length, &length);

	switch(ProtocolIE_ID){
		case 53: /*id-RAB-SetupOrModifyItem */
			offset = dissect_id_RAB_SetupOrModifyItem2(tvb, offset, actx, tree);
			break;
		default:
			offset = offset + (length<<3);
			break;
	}
	/* We might not stop on a byte boundary */
	BYTE_ALIGN_OFFSET(offset);
	return offset;
}


static int dissect_ranap_messages(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree){
	guint length;

	offset = dissect_per_length_determinant(tvb, offset, actx, tree, hf_ranap_pdu_length, &length);
	switch(type_of_message){
		case 0: /* Initating message */ 
			switch(ProcedureCode){
				case 0: /* id-RAB-Assignment*/
					offset = dissect_rAB_AssignmentRequest(tvb, offset, actx, tree);
					break;
				case 1: /* id-Iu-Release */
					offset = dissect_iu_ReleaseCommand(tvb, offset, actx, tree);
					break;
				case 2: /* id-RelocationPreparation*/
					offset = dissect_relocationRequired(tvb, offset, actx, tree);
					break;
				case 3: /* id-RelocationResourceAllocation*/
					offset = dissect_relocationRequest(tvb, offset, actx, tree);
					break;
				case 4: /* id-RelocationCancel*/
					offset = dissect_relocationCancel(tvb, offset, actx, tree);
					break;
				case 5: /* id-SRNS-ContextTransfer*/
					offset = dissect_sRNS_ContextRequest(tvb, offset, actx, tree);
					break;
				case 6: /* id-SecurityModeControl*/
					offset = dissect_securityModeCommand(tvb, offset, actx, tree);
					break;
				case 7: /* id-DataVolumeReport*/
					offset = dissect_dataVolumeReportRequest(tvb, offset, actx, tree);
					break;
				case 9: /* id-Reset*/
					offset = dissect_reset(tvb, offset, actx, tree);
					break;
				case 10: /* id-RAB-ReleaseRequest*/
					offset = dissect_rAB_ReleaseRequest(tvb, offset, actx, tree);
					break;
				case 11: /* id-Iu-ReleaseRequest*/
					offset = dissect_iu_ReleaseRequest(tvb, offset, actx, tree);
					break;
				case 12: /* id-RelocationDetect*/
					offset = dissect_relocationDetect(tvb, offset, actx, tree);
					break;
				case 13: /* id-RelocationComplete*/
					offset = dissect_relocationComplete(tvb, offset, actx, tree);
					break;
				case 14: /* id-Paging*/
					offset = dissect_paging(tvb, offset, actx, tree);
					break;
				case 15: /* id-CommonID*/
					offset = dissect_commonID(tvb, offset, actx, tree);
					break;
				case 16: /* id-CN-InvokeTrace*/
					offset = dissect_cN_InvokeTrace(tvb, offset, actx, tree);
					break;
				case 17: /* id-LocationReportingControl*/
					offset = dissect_locationReportingControl(tvb, offset, actx, tree);
					break;
				case 18: /* id-LocationReport*/
					offset = dissect_locationReport(tvb, offset, actx, tree);
					break;
				case 19: /* id-InitialUE-Message*/
					offset = dissect_initialUE_Message(tvb, offset, actx, tree);
					break;
				case 20: /* id-DirectTransfer*/
					offset = dissect_directTransfer(tvb, offset, actx, tree);
					break;
				case 21: /* id-OverloadControl*/
					offset = dissect_overload(tvb, offset, actx, tree);
					break;
				case 22: /* id-ErrorIndication*/
					offset = dissect_errorIndication(tvb, offset, actx, tree);
					break;
				case 23: /* id-SRNS-DataForward*/
					offset = dissect_sRNS_DataForwardCommand(tvb, offset, actx, tree);
					break;
				case 24: /* id-ForwardSRNS-Context*/
					offset = dissect_forwardSRNS_Context(tvb, offset, actx, tree);
					break;
				case 25: /* id-privateMessage*/
					offset = dissect_privateMessage(tvb, offset, actx, tree);
					break;
				case 26: /* id-CN-DeactivateTrace*/
					break;
				case 27: /* id-ResetResource*/
					offset = dissect_resetResource(tvb, offset, actx, tree);
					break;
				case 28: /* id-RANAP-Relocation*/
					offset = dissect_rANAP_RelocationInformation(tvb, offset, actx, tree);
					break;
				case 29: /* id-RAB-ModifyRequest*/
					offset = dissect_rAB_ModifyRequest(tvb, offset, actx, tree);
					break;
				case 30: /* id-LocationRelatedData*/
					offset = dissect_locationRelatedDataRequest(tvb, offset, actx, tree);
					break;
				case 31: /* id-InformationTransfer*/
					offset = dissect_informationTransferIndication(tvb, offset, actx, tree);
					break;
				case 32: /* id-UESpecificInformation*/
					offset = dissect_uESpecificInformationIndication(tvb, offset, actx, tree);
					break;
				case 33: /* id-UplinkInformationExchange*/
					offset = dissect_uplinkInformationExchangeRequest(tvb, offset, actx, tree);
					break;
				case 34: /* id-DirectInformationTransfer*/
					offset = dissect_directInformationTransfer(tvb, offset, actx, tree);
					break;
				case 35: /* id-MBMSSessionStart*/
					offset = dissect_mBMSSessionStart(tvb, offset, actx, tree);
 					break;
				case 36: /* id-MBMSSessionUpdate*/
					offset = dissect_mBMSSessionUpdate(tvb, offset, actx, tree);
					break;
				case 37: /* id-MBMSSessionStop*/
					offset = dissect_mMBMSSessionStop(tvb, offset, actx, tree);
					break;
				case 38: /* id-MBMSUELinking*/
					offset = dissect_mBMSUELinkingRequest(tvb, offset, actx, tree);
					break;
				case 39: /* id-MBMSRegistration*/
					offset = dissect_mBMSRegistrationRequest(tvb, offset, actx, tree);
					break;
				case 40: /* id-MBMSCNDe-Registration-Procedure*/
					offset = dissect_mBMSCNDe_RegistrationRequest(tvb, offset, actx, tree);
					break;
				case 41: /* id-MBMSRABEstablishmentIndication*/
					offset = dissect_mBMSRABEstablishmentIndication(tvb, offset, actx, tree);
					break;
				case 42: /* id-MBMSRABRelease*/
					offset = dissect_mBMSRABReleaseRequest(tvb, offset, actx, tree);
					break;
				default:
					offset = offset + (length<<3);
					break;
			}	
			break;
		case 1:
			/* successfulOutcome */
			switch(ProcedureCode){
				case 0: /* id-RAB-Assignment*/
					break;
				case 1: /* id-Iu-Release */
					offset = dissect_iu_ReleaseComplete(tvb, offset, actx, tree);
					break;
				case 2: /* id-RelocationPreparation*/
					offset = dissect_relocationCommand(tvb, offset, actx, tree);
					break;
				case 3: /* id-RelocationResourceAllocation*/
					offset = dissect_relocationRequestAcknowledge(tvb, offset, actx, tree);
					break;
				case 4: /* id-RelocationCancel*/
					offset = dissect_relocationCancelAcknowledge(tvb, offset, actx, tree);
					break;
				case 5: /* id-SRNS-ContextTransfer*/
					offset = dissect_sRNS_ContextResponse(tvb, offset, actx, tree);
					break;
				case 6: /* id-SecurityModeControl*/
					offset = dissect_securityModeComplete(tvb, offset, actx, tree);
					break;
				case 7: /* id-DataVolumeReport*/
					offset = dissect_dataVolumeReport(tvb, offset, actx, tree);
					break;
				case 9: /* id-Reset*/
					offset = dissect_resetAcknowledge(tvb, offset, actx, tree);
					break;
				case 10: /* id-RAB-ReleaseRequest*/
					offset = dissect_rAB_ReleaseRequest(tvb, offset, actx, tree);
					break;
				case 11: /* id-Iu-ReleaseRequest*/
					offset = dissect_iu_ReleaseRequest(tvb, offset, actx, tree);
					break;
				case 12: /* id-RelocationDetect*/
					offset = dissect_relocationDetect(tvb, offset, actx, tree);
					break;
				case 13: /* id-RelocationComplete*/
					offset = dissect_relocationComplete(tvb, offset, actx, tree);
					break;
				case 14: /* id-Paging*/
					offset = dissect_paging(tvb, offset, actx, tree);
					break;
				case 15: /* id-CommonID*/
					offset = dissect_commonID(tvb, offset, actx, tree);
					break;
				case 16: /* id-CN-InvokeTrace*/
					break;
				case 17: /* id-LocationReportingControl*/
					break;
				case 18: /* id-LocationReport*/
					break;
				case 19: /* id-InitialUE-Message*/
					break;
				case 20: /* id-DirectTransfer*/
					break;
				case 21: /* id-OverloadControl*/
					break;
				case 22: /* id-ErrorIndication*/
					break;
				case 23: /* id-SRNS-DataForward*/
					break;
				case 24: /* id-ForwardSRNS-Context*/
					break;
				case 25: /* id-privateMessage*/
					break;
				case 26: /* id-CN-DeactivateTrace*/
					break;
				case 27: /* id-ResetResource*/
					offset = dissect_resetResourceAcknowledge(tvb, offset, actx, tree);
					break;
				case 28: /* id-RANAP-Relocation*/
					break;
				case 29: /* id-RAB-ModifyRequest*/
					break;
				case 30: /* id-LocationRelatedData*/
					offset = dissect_locationRelatedDataResponse(tvb, offset, actx, tree);
					break;
				case 31: /* id-InformationTransfer*/
					offset = dissect_informationTransferConfirmation(tvb, offset, actx, tree);
					break;
				case 32: /* id-UESpecificInformation*/
					break;
				case 33: /* id-UplinkInformationExchange*/
					offset = dissect_uplinkInformationExchangeResponse(tvb, offset, actx, tree);
					break;
				case 34: /* id-DirectInformationTransfer*/
					break;
				case 35: /* id-MBMSSessionStart*/
					offset = dissect_mBMSSessionStartResponse(tvb, offset, actx, tree);
					break;
				case 36: /* id-MBMSSessionUpdate*/
					offset = dissect_mBMSSessionUpdateResponse(tvb, offset, actx, tree);
					break;
				case 37: /* id-MBMSSessionStop*/
					offset = dissect_mBMSSessionStopResponse(tvb, offset, actx, tree);
					break;
				case 38: /* id-MBMSUELinking*/
					break;
				case 39: /* id-MBMSRegistration*/
					offset = dissect_mBMSRegistrationResponse(tvb, offset, actx, tree);
					break;
				case 40: /* id-MBMSCNDe-Registration-Procedure*/
					offset = dissect_mBMSCNDeRegistrationResponse(tvb, offset, actx, tree);
					break;
				case 41: /* id-MBMSRABEstablishmentIndication*/
					break;
				case 42: /* id-MBMSRABRelease*/
					offset = dissect_mBMSRABRelease(tvb, offset, actx, tree);
					break;
				default:
					offset = offset + (length<<3);
					break;
			}
			break;
		case 2:
			/* unsuccessfulOutcome */
			switch(ProcedureCode){
				case 0: /* id-RAB-Assignment*/
					break;
				case 1: /* id-Iu-Release */
					break;
				case 2: /* id-RelocationPreparation*/
					offset = dissect_relocationPreparationFailure(tvb, offset, actx, tree);
					break;
				case 3: /* id-RelocationResourceAllocation*/
					offset = dissect_relocationFailure(tvb, offset, actx, tree);
					break;
				case 4: /* id-RelocationCancel*/
					break;
				case 5: /* id-SRNS-ContextTransfer*/
					break;
				case 6: /* id-SecurityModeControl*/
					offset = dissect_securityModeReject(tvb, offset, actx, tree);
					break;
				case 7: /* id-DataVolumeReport*/
					break;
				case 9: /* id-Reset*/
					break;
				case 10: /* id-RAB-ReleaseRequest*/
					break;
				case 11: /* id-Iu-ReleaseRequest*/
					break;
				case 12: /* id-RelocationDetect*/
					break;
				case 13: /* id-RelocationComplete*/
					break;
				case 14: /* id-Paging*/
					break;
				case 15: /* id-CommonID*/
					break;
				case 16: /* id-CN-InvokeTrace*/
					break;
				case 17: /* id-LocationReportingControl*/
					break;
				case 18: /* id-LocationReport*/
					break;
				case 19: /* id-InitialUE-Message*/
					break;
				case 20: /* id-DirectTransfer*/
					break;
				case 21: /* id-OverloadControl*/
					break;
				case 22: /* id-ErrorIndication*/
					break;
				case 23: /* id-SRNS-DataForward*/
					break;
				case 24: /* id-ForwardSRNS-Context*/
					break;
				case 25: /* id-privateMessage*/
					break;
				case 26: /* id-CN-DeactivateTrace*/
					break;
				case 27: /* id-ResetResource*/
					break;
				case 28: /* id-RANAP-Relocation*/
					break;
				case 29: /* id-RAB-ModifyRequest*/
					break;
				case 30: /* id-LocationRelatedData*/
					offset = dissect_locationRelatedDataFailure(tvb, offset, actx, tree);
					break;
				case 31: /* id-InformationTransfer*/
					offset = dissect_informationTransferFailure(tvb, offset, actx, tree);
					break;
				case 32: /* id-UESpecificInformation*/
					break;
				case 33: /* id-UplinkInformationExchange*/
					offset = dissect_uplinkInformationExchangeFailure(tvb, offset, actx, tree);
					break;
				case 34: /* id-DirectInformationTransfer*/
					break;
				case 35: /* id-MBMSSessionStart*/
					offset = dissect_mBMSSessionStartFailure(tvb, offset, actx, tree);
					break;
				case 36: /* id-MBMSSessionUpdate*/
					offset = dissect_mBMSSessionUpdateFailure(tvb, offset, actx, tree);
					break;
				case 37: /* id-MBMSSessionStop*/
					break;
				case 38: /* id-MBMSUELinking*/
					break;
				case 39: /* id-MBMSRegistration*/
					offset = dissect_mBMSRegistrationFailure(tvb, offset, actx, tree);
					break;
				case 40: /* id-MBMSCNDe-Registration-Procedure*/
					break;
				case 41: /* id-MBMSRABEstablishmentIndication*/
					break;
				case 42: /* id-MBMSRABRelease*/
					offset = dissect_mBMSRABReleaseFailure(tvb, offset, actx, tree);
					break;
				default:
					offset = offset + (length<<3);
					break;
			}
			break;
		case 3:
			/* outcome */
			switch(ProcedureCode){
				case 0: /* id-RAB-Assignment*/
					offset = dissect_rAB_AssignmentResponse(tvb, offset, actx, tree);
					break;
				case 1: /* id-Iu-Release */
					offset = dissect_iu_ReleaseCommand(tvb, offset, actx, tree);
					break;
				case 2: /* id-RelocationPreparation*/
					break;
				case 3: /* id-RelocationResourceAllocation*/
					break;
				case 4: /* id-RelocationCancel*/
					break;
				case 5: /* id-SRNS-ContextTransfer*/
					break;
				case 6: /* id-SecurityModeControl*/
					break;
				case 7: /* id-DataVolumeReport*/
					break;
				case 9: /* id-Reset*/
					break;
				case 10: /* id-RAB-ReleaseRequest*/
					break;
				case 11: /* id-Iu-ReleaseRequest*/
					break;
				case 12: /* id-RelocationDetect*/
					break;
				case 13: /* id-RelocationComplete*/
					break;
				case 14: /* id-Paging*/
					break;
				case 15: /* id-CommonID*/
					break;
				case 16: /* id-CN-InvokeTrace*/
					break;
				case 17: /* id-LocationReportingControl*/
					break;
				case 18: /* id-LocationReport*/
					break;
				case 19: /* id-InitialUE-Message*/
					break;
				case 20: /* id-DirectTransfer*/
					break;
				case 21: /* id-OverloadControl*/
					break;
				case 22: /* id-ErrorIndication*/
					break;
				case 23: /* id-SRNS-DataForward*/
					break;
				case 24: /* id-ForwardSRNS-Context*/
					break;
				case 25: /* id-privateMessage*/
					break;
				case 26: /* id-CN-DeactivateTrace*/
					break;
				case 27: /* id-ResetResource*/
					break;
				case 28: /* id-RANAP-Relocation*/
					break;
				case 29: /* id-RAB-ModifyRequest*/
					break;
				case 30: /* id-LocationRelatedData*/
					break;
				case 31: /* id-InformationTransfer*/
					break;
				case 32: /* id-UESpecificInformation*/
					break;
				case 33: /* id-UplinkInformationExchange*/
					break;
				case 34: /* id-DirectInformationTransfer*/
					break;
				case 35: /* id-MBMSSessionStart*/
					break;
				case 36: /* id-MBMSSessionUpdate*/
					break;
				case 37: /* id-MBMSSessionStop*/
					break;
				case 38: /* id-MBMSUELinking*/
					offset = dissect_mBMSUELinkingResponse(tvb, offset, actx, tree);
					break;
				case 39: /* id-MBMSRegistration*/
					break;
				case 40: /* id-MBMSCNDe-Registration-Procedure*/
					break;
				case 41: /* id-MBMSRABEstablishmentIndication*/
					break;
				case 42: /* id-MBMSRABRelease*/
					break;
				default:
					offset = offset + (length<<3);
					break;
			}
			break;
		default:
			break;
	}
	return offset;
}



static void
dissect_ranap(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	proto_item	*ranap_item = NULL;
	proto_tree	*ranap_tree = NULL;
	int			offset = 0;

	top_tree = tree;

	/* make entry in the Protocol column on summary display */
	if (check_col(pinfo->cinfo, COL_PROTOCOL))
		col_set_str(pinfo->cinfo, COL_PROTOCOL, "RANAP");

    /* create the ranap protocol tree */
    ranap_item = proto_tree_add_item(tree, proto_ranap, tvb, 0, -1, FALSE);
    ranap_tree = proto_item_add_subtree(ranap_item, ett_ranap);

	offset = dissect_RANAP_PDU_PDU(tvb, pinfo, ranap_tree);

}

static gboolean
dissect_sccp_ranap_heur(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    guint8 temp;

    /* Is it a ranap packet?
     *
     * 4th octet should be the length of the rest of the message.
     *    note: I believe the length octet may actually be represented
     *          by more than one octet.  Something like...
     *          bit 01234567          octets
     *              0xxxxxxx             1
     *              10xxxxxx xxxxxxxx    2
     *          For now, we have ignored this.  I hope that's safe.
     *
     * 2nd octet is the message-type e Z[0, 28]
     * (obviously there must be at least four octets)
     *
     * If both hold true we'll assume its RANAP
     */

    #define LENGTH_OFFSET 3
    #define MSG_TYPE_OFFSET 1
    if (tvb_length(tvb) < 4) { return FALSE; }
    if (tvb_get_guint8(tvb, LENGTH_OFFSET) != (tvb_length(tvb) - 4)) { return FALSE; }
    temp = tvb_get_guint8(tvb, MSG_TYPE_OFFSET);
    if (temp > RANAP_MAX_PC) { return FALSE; }

    dissect_ranap(tvb, pinfo, tree);

    return TRUE;
}

/*--- proto_reg_handoff_ranap ---------------------------------------
This proto is called directly from packet-gsm_a and needs to know component type */
void proto_reg_handoff_ranap(void) {
    dissector_handle_t	ranap_handle;

    ranap_handle = create_dissector_handle(dissect_ranap, proto_ranap);
	dissector_add("sccp.ssn", SCCP_SSN_RANAP, ranap_handle);

	/* Add heuristic dissector
	* Perhaps we want a preference whether the heuristic dissector
	* is or isn't enabled
	*/
	heur_dissector_add("sccp", dissect_sccp_ranap_heur, proto_ranap); 


}

/*--- proto_register_ranap -------------------------------------------*/
void proto_register_ranap(void) {

  /* List of fields */
  static hf_register_info hf[] = {
	{ &hf_ranap_pdu_length,
		{ "PDU Length", "ranap.pdu_length", FT_UINT32, BASE_DEC,
		NULL, 0, "Number of octets in the PDU", HFILL }},
	{ &hf_ranap_IE_length,
		{ "IE Length", "ranap.ie_length", FT_UINT32, BASE_DEC,
		NULL, 0, "Number of octets in the IE", HFILL }},


/*--- Included file: packet-ranap-hfarr.c ---*/
#line 1 "packet-ranap-hfarr.c"
    { &hf_ranap_RANAP_PDU_PDU,
      { "RANAP-PDU", "ranap.RANAP_PDU",
        FT_UINT32, BASE_DEC, VALS(ranap_RANAP_PDU_vals), 0,
        "RANAP-PDU", HFILL }},
    { &hf_ranap_initiatingMessage,
      { "initiatingMessage", "ranap.initiatingMessage",
        FT_NONE, BASE_NONE, NULL, 0,
        "RANAP-PDU/initiatingMessage", HFILL }},
    { &hf_ranap_successfulOutcome,
      { "successfulOutcome", "ranap.successfulOutcome",
        FT_NONE, BASE_NONE, NULL, 0,
        "RANAP-PDU/successfulOutcome", HFILL }},
    { &hf_ranap_unsuccessfulOutcome,
      { "unsuccessfulOutcome", "ranap.unsuccessfulOutcome",
        FT_NONE, BASE_NONE, NULL, 0,
        "RANAP-PDU/unsuccessfulOutcome", HFILL }},
    { &hf_ranap_outcome,
      { "outcome", "ranap.outcome",
        FT_NONE, BASE_NONE, NULL, 0,
        "RANAP-PDU/outcome", HFILL }},
    { &hf_ranap_procedureCode,
      { "procedureCode", "ranap.procedureCode",
        FT_UINT32, BASE_DEC, VALS(ranap_ProcedureCode_vals), 0,
        "", HFILL }},
    { &hf_ranap_criticality,
      { "criticality", "ranap.criticality",
        FT_UINT32, BASE_DEC, VALS(ranap_Criticality_vals), 0,
        "", HFILL }},
    { &hf_ranap_value,
      { "value", "ranap.value",
        FT_NONE, BASE_NONE, NULL, 0,
        "", HFILL }},
    { &hf_ranap_iu_ReleaseCommand,
      { "iu-ReleaseCommand", "ranap.iu_ReleaseCommand",
        FT_NONE, BASE_NONE, NULL, 0,
        "", HFILL }},
    { &hf_ranap_relocationRequired,
      { "relocationRequired", "ranap.relocationRequired",
        FT_NONE, BASE_NONE, NULL, 0,
        "Dummy-initiating-messages/relocationRequired", HFILL }},
    { &hf_ranap_relocationRequest,
      { "relocationRequest", "ranap.relocationRequest",
        FT_NONE, BASE_NONE, NULL, 0,
        "Dummy-initiating-messages/relocationRequest", HFILL }},
    { &hf_ranap_relocationCancel,
      { "relocationCancel", "ranap.relocationCancel",
        FT_NONE, BASE_NONE, NULL, 0,
        "Dummy-initiating-messages/relocationCancel", HFILL }},
    { &hf_ranap_sRNS_ContextRequest,
      { "sRNS-ContextRequest", "ranap.sRNS_ContextRequest",
        FT_NONE, BASE_NONE, NULL, 0,
        "Dummy-initiating-messages/sRNS-ContextRequest", HFILL }},
    { &hf_ranap_securityModeCommand,
      { "securityModeCommand", "ranap.securityModeCommand",
        FT_NONE, BASE_NONE, NULL, 0,
        "Dummy-initiating-messages/securityModeCommand", HFILL }},
    { &hf_ranap_dataVolumeReportRequest,
      { "dataVolumeReportRequest", "ranap.dataVolumeReportRequest",
        FT_NONE, BASE_NONE, NULL, 0,
        "Dummy-initiating-messages/dataVolumeReportRequest", HFILL }},
    { &hf_ranap_reset,
      { "reset", "ranap.reset",
        FT_NONE, BASE_NONE, NULL, 0,
        "Dummy-initiating-messages/reset", HFILL }},
    { &hf_ranap_rAB_ReleaseRequest,
      { "rAB-ReleaseRequest", "ranap.rAB_ReleaseRequest",
        FT_NONE, BASE_NONE, NULL, 0,
        "Dummy-initiating-messages/rAB-ReleaseRequest", HFILL }},
    { &hf_ranap_iu_ReleaseRequest,
      { "iu-ReleaseRequest", "ranap.iu_ReleaseRequest",
        FT_NONE, BASE_NONE, NULL, 0,
        "Dummy-initiating-messages/iu-ReleaseRequest", HFILL }},
    { &hf_ranap_relocationDetect,
      { "relocationDetect", "ranap.relocationDetect",
        FT_NONE, BASE_NONE, NULL, 0,
        "Dummy-initiating-messages/relocationDetect", HFILL }},
    { &hf_ranap_relocationComplete,
      { "relocationComplete", "ranap.relocationComplete",
        FT_NONE, BASE_NONE, NULL, 0,
        "Dummy-initiating-messages/relocationComplete", HFILL }},
    { &hf_ranap_paging,
      { "paging", "ranap.paging",
        FT_NONE, BASE_NONE, NULL, 0,
        "Dummy-initiating-messages/paging", HFILL }},
    { &hf_ranap_commonID,
      { "commonID", "ranap.commonID",
        FT_NONE, BASE_NONE, NULL, 0,
        "Dummy-initiating-messages/commonID", HFILL }},
    { &hf_ranap_cN_InvokeTrace,
      { "cN-InvokeTrace", "ranap.cN_InvokeTrace",
        FT_NONE, BASE_NONE, NULL, 0,
        "Dummy-initiating-messages/cN-InvokeTrace", HFILL }},
    { &hf_ranap_cN_DeactivateTrace,
      { "cN-DeactivateTrace", "ranap.cN_DeactivateTrace",
        FT_NONE, BASE_NONE, NULL, 0,
        "Dummy-initiating-messages/cN-DeactivateTrace", HFILL }},
    { &hf_ranap_locationReportingControl,
      { "locationReportingControl", "ranap.locationReportingControl",
        FT_NONE, BASE_NONE, NULL, 0,
        "Dummy-initiating-messages/locationReportingControl", HFILL }},
    { &hf_ranap_locationReport,
      { "locationReport", "ranap.locationReport",
        FT_NONE, BASE_NONE, NULL, 0,
        "Dummy-initiating-messages/locationReport", HFILL }},
    { &hf_ranap_initialUE_Message,
      { "initialUE-Message", "ranap.initialUE_Message",
        FT_NONE, BASE_NONE, NULL, 0,
        "Dummy-initiating-messages/initialUE-Message", HFILL }},
    { &hf_ranap_directTransfer,
      { "directTransfer", "ranap.directTransfer",
        FT_NONE, BASE_NONE, NULL, 0,
        "Dummy-initiating-messages/directTransfer", HFILL }},
    { &hf_ranap_overload,
      { "overload", "ranap.overload",
        FT_NONE, BASE_NONE, NULL, 0,
        "Dummy-initiating-messages/overload", HFILL }},
    { &hf_ranap_errorIndication,
      { "errorIndication", "ranap.errorIndication",
        FT_NONE, BASE_NONE, NULL, 0,
        "Dummy-initiating-messages/errorIndication", HFILL }},
    { &hf_ranap_sRNS_DataForwardCommand,
      { "sRNS-DataForwardCommand", "ranap.sRNS_DataForwardCommand",
        FT_NONE, BASE_NONE, NULL, 0,
        "Dummy-initiating-messages/sRNS-DataForwardCommand", HFILL }},
    { &hf_ranap_forwardSRNS_Context,
      { "forwardSRNS-Context", "ranap.forwardSRNS_Context",
        FT_NONE, BASE_NONE, NULL, 0,
        "Dummy-initiating-messages/forwardSRNS-Context", HFILL }},
    { &hf_ranap_rAB_AssignmentRequest,
      { "rAB-AssignmentRequest", "ranap.rAB_AssignmentRequest",
        FT_NONE, BASE_NONE, NULL, 0,
        "Dummy-initiating-messages/rAB-AssignmentRequest", HFILL }},
    { &hf_ranap_privateMessage,
      { "privateMessage", "ranap.privateMessage",
        FT_NONE, BASE_NONE, NULL, 0,
        "Dummy-initiating-messages/privateMessage", HFILL }},
    { &hf_ranap_resetResource,
      { "resetResource", "ranap.resetResource",
        FT_NONE, BASE_NONE, NULL, 0,
        "Dummy-initiating-messages/resetResource", HFILL }},
    { &hf_ranap_rANAP_RelocationInformation,
      { "rANAP-RelocationInformation", "ranap.rANAP_RelocationInformation",
        FT_NONE, BASE_NONE, NULL, 0,
        "Dummy-initiating-messages/rANAP-RelocationInformation", HFILL }},
    { &hf_ranap_rAB_ModifyRequest,
      { "rAB-ModifyRequest", "ranap.rAB_ModifyRequest",
        FT_NONE, BASE_NONE, NULL, 0,
        "Dummy-initiating-messages/rAB-ModifyRequest", HFILL }},
    { &hf_ranap_locationRelatedDataRequest,
      { "locationRelatedDataRequest", "ranap.locationRelatedDataRequest",
        FT_NONE, BASE_NONE, NULL, 0,
        "Dummy-initiating-messages/locationRelatedDataRequest", HFILL }},
    { &hf_ranap_informationTransferIndication,
      { "informationTransferIndication", "ranap.informationTransferIndication",
        FT_NONE, BASE_NONE, NULL, 0,
        "Dummy-initiating-messages/informationTransferIndication", HFILL }},
    { &hf_ranap_uESpecificInformationIndication,
      { "uESpecificInformationIndication", "ranap.uESpecificInformationIndication",
        FT_NONE, BASE_NONE, NULL, 0,
        "Dummy-initiating-messages/uESpecificInformationIndication", HFILL }},
    { &hf_ranap_directInformationTransfer,
      { "directInformationTransfer", "ranap.directInformationTransfer",
        FT_NONE, BASE_NONE, NULL, 0,
        "Dummy-initiating-messages/directInformationTransfer", HFILL }},
    { &hf_ranap_uplinkInformationExchangeRequest,
      { "uplinkInformationExchangeRequest", "ranap.uplinkInformationExchangeRequest",
        FT_NONE, BASE_NONE, NULL, 0,
        "Dummy-initiating-messages/uplinkInformationExchangeRequest", HFILL }},
    { &hf_ranap_mBMSSessionStart,
      { "mBMSSessionStart", "ranap.mBMSSessionStart",
        FT_NONE, BASE_NONE, NULL, 0,
        "Dummy-initiating-messages/mBMSSessionStart", HFILL }},
    { &hf_ranap_mBMSSessionUpdate,
      { "mBMSSessionUpdate", "ranap.mBMSSessionUpdate",
        FT_NONE, BASE_NONE, NULL, 0,
        "Dummy-initiating-messages/mBMSSessionUpdate", HFILL }},
    { &hf_ranap_mMBMSSessionStop,
      { "mMBMSSessionStop", "ranap.mMBMSSessionStop",
        FT_NONE, BASE_NONE, NULL, 0,
        "Dummy-initiating-messages/mMBMSSessionStop", HFILL }},
    { &hf_ranap_mBMSUELinkingRequest,
      { "mBMSUELinkingRequest", "ranap.mBMSUELinkingRequest",
        FT_NONE, BASE_NONE, NULL, 0,
        "Dummy-initiating-messages/mBMSUELinkingRequest", HFILL }},
    { &hf_ranap_mBMSRegistrationRequest,
      { "mBMSRegistrationRequest", "ranap.mBMSRegistrationRequest",
        FT_NONE, BASE_NONE, NULL, 0,
        "Dummy-initiating-messages/mBMSRegistrationRequest", HFILL }},
    { &hf_ranap_mBMSCNDe_RegistrationRequest,
      { "mBMSCNDe-RegistrationRequest", "ranap.mBMSCNDe_RegistrationRequest",
        FT_NONE, BASE_NONE, NULL, 0,
        "Dummy-initiating-messages/mBMSCNDe-RegistrationRequest", HFILL }},
    { &hf_ranap_mBMSRABEstablishmentIndication,
      { "mBMSRABEstablishmentIndication", "ranap.mBMSRABEstablishmentIndication",
        FT_NONE, BASE_NONE, NULL, 0,
        "Dummy-initiating-messages/mBMSRABEstablishmentIndication", HFILL }},
    { &hf_ranap_mBMSRABReleaseRequest,
      { "mBMSRABReleaseRequest", "ranap.mBMSRABReleaseRequest",
        FT_NONE, BASE_NONE, NULL, 0,
        "Dummy-initiating-messages/mBMSRABReleaseRequest", HFILL }},
    { &hf_ranap_iu_ReleaseComplete,
      { "iu-ReleaseComplete", "ranap.iu_ReleaseComplete",
        FT_NONE, BASE_NONE, NULL, 0,
        "Dummy-SuccessfulOutcome-messages/iu-ReleaseComplete", HFILL }},
    { &hf_ranap_relocationCommand,
      { "relocationCommand", "ranap.relocationCommand",
        FT_NONE, BASE_NONE, NULL, 0,
        "Dummy-SuccessfulOutcome-messages/relocationCommand", HFILL }},
    { &hf_ranap_relocationRequestAcknowledge,
      { "relocationRequestAcknowledge", "ranap.relocationRequestAcknowledge",
        FT_NONE, BASE_NONE, NULL, 0,
        "Dummy-SuccessfulOutcome-messages/relocationRequestAcknowledge", HFILL }},
    { &hf_ranap_relocationCancelAcknowledge,
      { "relocationCancelAcknowledge", "ranap.relocationCancelAcknowledge",
        FT_NONE, BASE_NONE, NULL, 0,
        "Dummy-SuccessfulOutcome-messages/relocationCancelAcknowledge", HFILL }},
    { &hf_ranap_sRNS_ContextResponse,
      { "sRNS-ContextResponse", "ranap.sRNS_ContextResponse",
        FT_NONE, BASE_NONE, NULL, 0,
        "Dummy-SuccessfulOutcome-messages/sRNS-ContextResponse", HFILL }},
    { &hf_ranap_securityModeComplete,
      { "securityModeComplete", "ranap.securityModeComplete",
        FT_NONE, BASE_NONE, NULL, 0,
        "Dummy-SuccessfulOutcome-messages/securityModeComplete", HFILL }},
    { &hf_ranap_dataVolumeReport,
      { "dataVolumeReport", "ranap.dataVolumeReport",
        FT_NONE, BASE_NONE, NULL, 0,
        "Dummy-SuccessfulOutcome-messages/dataVolumeReport", HFILL }},
    { &hf_ranap_resetAcknowledge,
      { "resetAcknowledge", "ranap.resetAcknowledge",
        FT_NONE, BASE_NONE, NULL, 0,
        "Dummy-SuccessfulOutcome-messages/resetAcknowledge", HFILL }},
    { &hf_ranap_resetResourceAcknowledge,
      { "resetResourceAcknowledge", "ranap.resetResourceAcknowledge",
        FT_NONE, BASE_NONE, NULL, 0,
        "Dummy-SuccessfulOutcome-messages/resetResourceAcknowledge", HFILL }},
    { &hf_ranap_locationRelatedDataResponse,
      { "locationRelatedDataResponse", "ranap.locationRelatedDataResponse",
        FT_NONE, BASE_NONE, NULL, 0,
        "Dummy-SuccessfulOutcome-messages/locationRelatedDataResponse", HFILL }},
    { &hf_ranap_informationTransferConfirmation,
      { "informationTransferConfirmation", "ranap.informationTransferConfirmation",
        FT_NONE, BASE_NONE, NULL, 0,
        "Dummy-SuccessfulOutcome-messages/informationTransferConfirmation", HFILL }},
    { &hf_ranap_uplinkInformationExchangeResponse,
      { "uplinkInformationExchangeResponse", "ranap.uplinkInformationExchangeResponse",
        FT_NONE, BASE_NONE, NULL, 0,
        "Dummy-SuccessfulOutcome-messages/uplinkInformationExchangeResponse", HFILL }},
    { &hf_ranap_mBMSSessionStartResponse,
      { "mBMSSessionStartResponse", "ranap.mBMSSessionStartResponse",
        FT_NONE, BASE_NONE, NULL, 0,
        "Dummy-SuccessfulOutcome-messages/mBMSSessionStartResponse", HFILL }},
    { &hf_ranap_mBMSSessionUpdateResponse,
      { "mBMSSessionUpdateResponse", "ranap.mBMSSessionUpdateResponse",
        FT_NONE, BASE_NONE, NULL, 0,
        "Dummy-SuccessfulOutcome-messages/mBMSSessionUpdateResponse", HFILL }},
    { &hf_ranap_mBMSSessionStopResponse,
      { "mBMSSessionStopResponse", "ranap.mBMSSessionStopResponse",
        FT_NONE, BASE_NONE, NULL, 0,
        "Dummy-SuccessfulOutcome-messages/mBMSSessionStopResponse", HFILL }},
    { &hf_ranap_mBMSRegistrationResponse,
      { "mBMSRegistrationResponse", "ranap.mBMSRegistrationResponse",
        FT_NONE, BASE_NONE, NULL, 0,
        "Dummy-SuccessfulOutcome-messages/mBMSRegistrationResponse", HFILL }},
    { &hf_ranap_mBMSCNDeRegistrationResponse,
      { "mBMSCNDeRegistrationResponse", "ranap.mBMSCNDeRegistrationResponse",
        FT_NONE, BASE_NONE, NULL, 0,
        "Dummy-SuccessfulOutcome-messages/mBMSCNDeRegistrationResponse", HFILL }},
    { &hf_ranap_mBMSRABRelease,
      { "mBMSRABRelease", "ranap.mBMSRABRelease",
        FT_NONE, BASE_NONE, NULL, 0,
        "Dummy-SuccessfulOutcome-messages/mBMSRABRelease", HFILL }},
    { &hf_ranap_relocationPreparationFailure,
      { "relocationPreparationFailure", "ranap.relocationPreparationFailure",
        FT_NONE, BASE_NONE, NULL, 0,
        "Dummy-UnsuccessfulOutcome-messages/relocationPreparationFailure", HFILL }},
    { &hf_ranap_relocationFailure,
      { "relocationFailure", "ranap.relocationFailure",
        FT_NONE, BASE_NONE, NULL, 0,
        "Dummy-UnsuccessfulOutcome-messages/relocationFailure", HFILL }},
    { &hf_ranap_securityModeReject,
      { "securityModeReject", "ranap.securityModeReject",
        FT_NONE, BASE_NONE, NULL, 0,
        "Dummy-UnsuccessfulOutcome-messages/securityModeReject", HFILL }},
    { &hf_ranap_locationRelatedDataFailure,
      { "locationRelatedDataFailure", "ranap.locationRelatedDataFailure",
        FT_NONE, BASE_NONE, NULL, 0,
        "Dummy-UnsuccessfulOutcome-messages/locationRelatedDataFailure", HFILL }},
    { &hf_ranap_informationTransferFailure,
      { "informationTransferFailure", "ranap.informationTransferFailure",
        FT_NONE, BASE_NONE, NULL, 0,
        "Dummy-UnsuccessfulOutcome-messages/informationTransferFailure", HFILL }},
    { &hf_ranap_uplinkInformationExchangeFailure,
      { "uplinkInformationExchangeFailure", "ranap.uplinkInformationExchangeFailure",
        FT_NONE, BASE_NONE, NULL, 0,
        "Dummy-UnsuccessfulOutcome-messages/uplinkInformationExchangeFailure", HFILL }},
    { &hf_ranap_mBMSSessionStartFailure,
      { "mBMSSessionStartFailure", "ranap.mBMSSessionStartFailure",
        FT_NONE, BASE_NONE, NULL, 0,
        "Dummy-UnsuccessfulOutcome-messages/mBMSSessionStartFailure", HFILL }},
    { &hf_ranap_mBMSSessionUpdateFailure,
      { "mBMSSessionUpdateFailure", "ranap.mBMSSessionUpdateFailure",
        FT_NONE, BASE_NONE, NULL, 0,
        "Dummy-UnsuccessfulOutcome-messages/mBMSSessionUpdateFailure", HFILL }},
    { &hf_ranap_mBMSRegistrationFailure,
      { "mBMSRegistrationFailure", "ranap.mBMSRegistrationFailure",
        FT_NONE, BASE_NONE, NULL, 0,
        "Dummy-UnsuccessfulOutcome-messages/mBMSRegistrationFailure", HFILL }},
    { &hf_ranap_mBMSRABReleaseFailure,
      { "mBMSRABReleaseFailure", "ranap.mBMSRABReleaseFailure",
        FT_NONE, BASE_NONE, NULL, 0,
        "Dummy-UnsuccessfulOutcome-messages/mBMSRABReleaseFailure", HFILL }},
    { &hf_ranap_rAB_AssignmentResponse,
      { "rAB-AssignmentResponse", "ranap.rAB_AssignmentResponse",
        FT_NONE, BASE_NONE, NULL, 0,
        "Dummy-Outcome-messages/rAB-AssignmentResponse", HFILL }},
    { &hf_ranap_mBMSUELinkingResponse,
      { "mBMSUELinkingResponse", "ranap.mBMSUELinkingResponse",
        FT_NONE, BASE_NONE, NULL, 0,
        "Dummy-Outcome-messages/mBMSUELinkingResponse", HFILL }},
    { &hf_ranap_id_AccuracyFulfilmentIndicator,
      { "id-AccuracyFulfilmentIndicator", "ranap.id_AccuracyFulfilmentIndicator",
        FT_UINT32, BASE_DEC, VALS(ranap_AccuracyFulfilmentIndicator_vals), 0,
        "Dymmy-ie-ids/id-AccuracyFulfilmentIndicator", HFILL }},
    { &hf_ranap_id_APN,
      { "id-APN", "ranap.id_APN",
        FT_BYTES, BASE_HEX, NULL, 0,
        "Dymmy-ie-ids/id-APN", HFILL }},
    { &hf_ranap_id_AreaIdentity,
      { "id-AreaIdentity", "ranap.id_AreaIdentity",
        FT_UINT32, BASE_DEC, VALS(ranap_AreaIdentity_vals), 0,
        "Dymmy-ie-ids/id-AreaIdentity", HFILL }},
    { &hf_ranap_id_Alt_RAB_Parameters,
      { "id-Alt-RAB-Parameters", "ranap.id_Alt_RAB_Parameters",
        FT_NONE, BASE_NONE, NULL, 0,
        "Dymmy-ie-ids/id-Alt-RAB-Parameters", HFILL }},
    { &hf_ranap_id_Ass_RAB_Parameters,
      { "id-Ass-RAB-Parameters", "ranap.id_Ass_RAB_Parameters",
        FT_NONE, BASE_NONE, NULL, 0,
        "Dymmy-ie-ids/id-Ass-RAB-Parameters", HFILL }},
    { &hf_ranap_id_BroadcastAssistanceDataDecipheringKeys,
      { "id-BroadcastAssistanceDataDecipheringKeys", "ranap.id_BroadcastAssistanceDataDecipheringKeys",
        FT_NONE, BASE_NONE, NULL, 0,
        "Dymmy-ie-ids/id-BroadcastAssistanceDataDecipheringKeys", HFILL }},
    { &hf_ranap_id_LocationRelatedDataRequestType,
      { "id-LocationRelatedDataRequestType", "ranap.id_LocationRelatedDataRequestType",
        FT_NONE, BASE_NONE, NULL, 0,
        "Dymmy-ie-ids/id-LocationRelatedDataRequestType", HFILL }},
    { &hf_ranap_id_CN_DomainIndicator,
      { "id-CN-DomainIndicator", "ranap.id_CN_DomainIndicator",
        FT_UINT32, BASE_DEC, VALS(ranap_CN_DomainIndicator_vals), 0,
        "Dymmy-ie-ids/id-CN-DomainIndicator", HFILL }},
    { &hf_ranap_id_Cause,
      { "id-Cause", "ranap.id_Cause",
        FT_UINT32, BASE_DEC, VALS(ranap_Cause_vals), 0,
        "Dymmy-ie-ids/id-Cause", HFILL }},
    { &hf_ranap_id_ChosenEncryptionAlgorithm,
      { "id-ChosenEncryptionAlgorithm", "ranap.id_ChosenEncryptionAlgorithm",
        FT_UINT32, BASE_DEC, VALS(ranap_EncryptionAlgorithm_vals), 0,
        "Dymmy-ie-ids/id-ChosenEncryptionAlgorithm", HFILL }},
    { &hf_ranap_id_ChosenIntegrityProtectionAlgorithm,
      { "id-ChosenIntegrityProtectionAlgorithm", "ranap.id_ChosenIntegrityProtectionAlgorithm",
        FT_UINT32, BASE_DEC, VALS(ranap_IntegrityProtectionAlgorithm_vals), 0,
        "Dymmy-ie-ids/id-ChosenIntegrityProtectionAlgorithm", HFILL }},
    { &hf_ranap_id_ClassmarkInformation2,
      { "id-ClassmarkInformation2", "ranap.id_ClassmarkInformation2",
        FT_BYTES, BASE_HEX, NULL, 0,
        "Dymmy-ie-ids/id-ClassmarkInformation2", HFILL }},
    { &hf_ranap_id_ClassmarkInformation3,
      { "id-ClassmarkInformation3", "ranap.id_ClassmarkInformation3",
        FT_BYTES, BASE_HEX, NULL, 0,
        "Dymmy-ie-ids/id-ClassmarkInformation3", HFILL }},
    { &hf_ranap_id_ClientType,
      { "id-ClientType", "ranap.id_ClientType",
        FT_UINT32, BASE_DEC, VALS(ranap_ClientType_vals), 0,
        "Dymmy-ie-ids/id-ClientType", HFILL }},
    { &hf_ranap_id_CNMBMSLinkingInformation,
      { "id-CNMBMSLinkingInformation", "ranap.id_CNMBMSLinkingInformation",
        FT_NONE, BASE_NONE, NULL, 0,
        "Dymmy-ie-ids/id-CNMBMSLinkingInformation", HFILL }},
    { &hf_ranap_id_CriticalityDiagnostics,
      { "id-CriticalityDiagnostics", "ranap.id_CriticalityDiagnostics",
        FT_NONE, BASE_NONE, NULL, 0,
        "Dymmy-ie-ids/id-CriticalityDiagnostics", HFILL }},
    { &hf_ranap_id_DeltaRAListofIdleModeUEs,
      { "id-DeltaRAListofIdleModeUEs", "ranap.id_DeltaRAListofIdleModeUEs",
        FT_NONE, BASE_NONE, NULL, 0,
        "Dymmy-ie-ids/id-DeltaRAListofIdleModeUEs", HFILL }},
    { &hf_ranap_id_DRX_CycleLengthCoefficient,
      { "id-DRX-CycleLengthCoefficient", "ranap.id_DRX_CycleLengthCoefficient",
        FT_UINT32, BASE_DEC, NULL, 0,
        "Dymmy-ie-ids/id-DRX-CycleLengthCoefficient", HFILL }},
    { &hf_ranap_id_DirectTransferInformationItem_RANAP_RelocInf,
      { "id-DirectTransferInformationItem-RANAP-RelocInf", "ranap.id_DirectTransferInformationItem_RANAP_RelocInf",
        FT_NONE, BASE_NONE, NULL, 0,
        "Dymmy-ie-ids/id-DirectTransferInformationItem-RANAP-RelocInf", HFILL }},
    { &hf_ranap_id_DirectTransferInformationList_RANAP_RelocInf,
      { "id-DirectTransferInformationList-RANAP-RelocInf", "ranap.id_DirectTransferInformationList_RANAP_RelocInf",
        FT_UINT32, BASE_DEC, NULL, 0,
        "Dymmy-ie-ids/id-DirectTransferInformationList-RANAP-RelocInf", HFILL }},
    { &hf_ranap_id_DL_GTP_PDU_SequenceNumber,
      { "id-DL-GTP-PDU-SequenceNumber", "ranap.id_DL_GTP_PDU_SequenceNumber",
        FT_UINT32, BASE_DEC, NULL, 0,
        "Dymmy-ie-ids/id-DL-GTP-PDU-SequenceNumber", HFILL }},
    { &hf_ranap_id_EncryptionInformation,
      { "id-EncryptionInformation", "ranap.id_EncryptionInformation",
        FT_NONE, BASE_NONE, NULL, 0,
        "Dymmy-ie-ids/id-EncryptionInformation", HFILL }},
    { &hf_ranap_id_FrequenceLayerConvergenceFlag,
      { "id-FrequenceLayerConvergenceFlag", "ranap.id_FrequenceLayerConvergenceFlag",
        FT_UINT32, BASE_DEC, VALS(ranap_FrequenceLayerConvergenceFlag_vals), 0,
        "Dymmy-ie-ids/id-FrequenceLayerConvergenceFlag", HFILL }},
    { &hf_ranap_id_GERAN_BSC_Container,
      { "id-GERAN-BSC-Container", "ranap.id_GERAN_BSC_Container",
        FT_BYTES, BASE_HEX, NULL, 0,
        "Dymmy-ie-ids/id-GERAN-BSC-Container", HFILL }},
    { &hf_ranap_id_GERAN_Classmark,
      { "id-GERAN-Classmark", "ranap.id_GERAN_Classmark",
        FT_BYTES, BASE_HEX, NULL, 0,
        "Dymmy-ie-ids/id-GERAN-Classmark", HFILL }},
    { &hf_ranap_id_GERAN_Iumode_RAB_Failed_RABAssgntResponse_Item,
      { "id-GERAN-Iumode-RAB-Failed-RABAssgntResponse-Item", "ranap.id_GERAN_Iumode_RAB_Failed_RABAssgntResponse_Item",
        FT_NONE, BASE_NONE, NULL, 0,
        "Dymmy-ie-ids/id-GERAN-Iumode-RAB-Failed-RABAssgntResponse-Item", HFILL }},
    { &hf_ranap_id_GERAN_Iumode_RAB_FailedList_RABAssgntResponse,
      { "id-GERAN-Iumode-RAB-FailedList-RABAssgntResponse", "ranap.id_GERAN_Iumode_RAB_FailedList_RABAssgntResponse",
        FT_UINT32, BASE_DEC, NULL, 0,
        "Dymmy-ie-ids/id-GERAN-Iumode-RAB-FailedList-RABAssgntResponse", HFILL }},
    { &hf_ranap_id_GlobalCN_ID,
      { "id-GlobalCN-ID", "ranap.id_GlobalCN_ID",
        FT_NONE, BASE_NONE, NULL, 0,
        "Dymmy-ie-ids/id-GlobalCN-ID", HFILL }},
    { &hf_ranap_id_GlobalRNC_ID,
      { "id-GlobalRNC-ID", "ranap.id_GlobalRNC_ID",
        FT_NONE, BASE_NONE, NULL, 0,
        "Dymmy-ie-ids/id-GlobalRNC-ID", HFILL }},
    { &hf_ranap_id_InformationExchangeID,
      { "id-InformationExchangeID", "ranap.id_InformationExchangeID",
        FT_UINT32, BASE_DEC, NULL, 0,
        "Dymmy-ie-ids/id-InformationExchangeID", HFILL }},
    { &hf_ranap_id_InformationExchangeType,
      { "id-InformationExchangeType", "ranap.id_InformationExchangeType",
        FT_UINT32, BASE_DEC, VALS(ranap_InformationExchangeType_vals), 0,
        "Dymmy-ie-ids/id-InformationExchangeType", HFILL }},
    { &hf_ranap_id_InformationRequested,
      { "id-InformationRequested", "ranap.id_InformationRequested",
        FT_UINT32, BASE_DEC, VALS(ranap_InformationRequested_vals), 0,
        "Dymmy-ie-ids/id-InformationRequested", HFILL }},
    { &hf_ranap_id_InformationRequestType,
      { "id-InformationRequestType", "ranap.id_InformationRequestType",
        FT_UINT32, BASE_DEC, VALS(ranap_InformationRequestType_vals), 0,
        "Dymmy-ie-ids/id-InformationRequestType", HFILL }},
    { &hf_ranap_id_InformationTransferID,
      { "id-InformationTransferID", "ranap.id_InformationTransferID",
        FT_UINT32, BASE_DEC, NULL, 0,
        "Dymmy-ie-ids/id-InformationTransferID", HFILL }},
    { &hf_ranap_id_InformationTransferType,
      { "id-InformationTransferType", "ranap.id_InformationTransferType",
        FT_UINT32, BASE_DEC, VALS(ranap_InformationTransferType_vals), 0,
        "Dymmy-ie-ids/id-InformationTransferType", HFILL }},
    { &hf_ranap_id_TraceRecordingSessionInformation,
      { "id-TraceRecordingSessionInformation", "ranap.id_TraceRecordingSessionInformation",
        FT_NONE, BASE_NONE, NULL, 0,
        "Dymmy-ie-ids/id-TraceRecordingSessionInformation", HFILL }},
    { &hf_ranap_id_IntegrityProtectionInformation,
      { "id-IntegrityProtectionInformation", "ranap.id_IntegrityProtectionInformation",
        FT_NONE, BASE_NONE, NULL, 0,
        "Dymmy-ie-ids/id-IntegrityProtectionInformation", HFILL }},
    { &hf_ranap_id_InterSystemInformationTransferType,
      { "id-InterSystemInformationTransferType", "ranap.id_InterSystemInformationTransferType",
        FT_UINT32, BASE_DEC, VALS(ranap_InterSystemInformationTransferType_vals), 0,
        "Dymmy-ie-ids/id-InterSystemInformationTransferType", HFILL }},
    { &hf_ranap_id_InterSystemInformation_TransparentContainer,
      { "id-InterSystemInformation-TransparentContainer", "ranap.id_InterSystemInformation_TransparentContainer",
        FT_NONE, BASE_NONE, NULL, 0,
        "Dymmy-ie-ids/id-InterSystemInformation-TransparentContainer", HFILL }},
    { &hf_ranap_id_IPMulticastAddress,
      { "id-IPMulticastAddress", "ranap.id_IPMulticastAddress",
        FT_BYTES, BASE_HEX, NULL, 0,
        "Dymmy-ie-ids/id-IPMulticastAddress", HFILL }},
    { &hf_ranap_id_IuSigConId,
      { "id-IuSigConId", "ranap.id_IuSigConId",
        FT_BYTES, BASE_HEX, NULL, 0,
        "Dymmy-ie-ids/id-IuSigConId", HFILL }},
    { &hf_ranap_id_IuSigConIdItem,
      { "id-IuSigConIdItem", "ranap.id_IuSigConIdItem",
        FT_NONE, BASE_NONE, NULL, 0,
        "Dymmy-ie-ids/id-IuSigConIdItem", HFILL }},
    { &hf_ranap_id_IuSigConIdList,
      { "id-IuSigConIdList", "ranap.id_IuSigConIdList",
        FT_UINT32, BASE_DEC, NULL, 0,
        "Dymmy-ie-ids/id-IuSigConIdList", HFILL }},
    { &hf_ranap_id_IuTransportAssociation,
      { "id-IuTransportAssociation", "ranap.id_IuTransportAssociation",
        FT_UINT32, BASE_DEC, VALS(ranap_IuTransportAssociation_vals), 0,
        "Dymmy-ie-ids/id-IuTransportAssociation", HFILL }},
    { &hf_ranap_id_JoinedMBMSBearerServicesList,
      { "id-JoinedMBMSBearerServicesList", "ranap.id_JoinedMBMSBearerServicesList",
        FT_UINT32, BASE_DEC, NULL, 0,
        "Dymmy-ie-ids/id-JoinedMBMSBearerServicesList", HFILL }},
    { &hf_ranap_id_KeyStatus,
      { "id-KeyStatus", "ranap.id_KeyStatus",
        FT_UINT32, BASE_DEC, VALS(ranap_KeyStatus_vals), 0,
        "Dymmy-ie-ids/id-KeyStatus", HFILL }},
    { &hf_ranap_id_L3_Information,
      { "id-L3-Information", "ranap.id_L3_Information",
        FT_BYTES, BASE_HEX, NULL, 0,
        "Dymmy-ie-ids/id-L3-Information", HFILL }},
    { &hf_ranap_id_LAI,
      { "id-LAI", "ranap.id_LAI",
        FT_NONE, BASE_NONE, NULL, 0,
        "Dymmy-ie-ids/id-LAI", HFILL }},
    { &hf_ranap_id_LastKnownServiceArea,
      { "id-LastKnownServiceArea", "ranap.id_LastKnownServiceArea",
        FT_NONE, BASE_NONE, NULL, 0,
        "Dymmy-ie-ids/id-LastKnownServiceArea", HFILL }},
    { &hf_ranap_id_SRB_TrCH_Mapping,
      { "id-SRB-TrCH-Mapping", "ranap.id_SRB_TrCH_Mapping",
        FT_UINT32, BASE_DEC, NULL, 0,
        "Dymmy-ie-ids/id-SRB-TrCH-Mapping", HFILL }},
    { &hf_ranap_id_LeftMBMSBearerServicesList,
      { "id-LeftMBMSBearerServicesList", "ranap.id_LeftMBMSBearerServicesList",
        FT_UINT32, BASE_DEC, NULL, 0,
        "Dymmy-ie-ids/id-LeftMBMSBearerServicesList", HFILL }},
    { &hf_ranap_id_LocationRelatedDataRequestTypeSpecificToGERANIuMode,
      { "id-LocationRelatedDataRequestTypeSpecificToGERANIuMode", "ranap.id_LocationRelatedDataRequestTypeSpecificToGERANIuMode",
        FT_UINT32, BASE_DEC, VALS(ranap_LocationRelatedDataRequestTypeSpecificToGERANIuMode_vals), 0,
        "Dymmy-ie-ids/id-LocationRelatedDataRequestTypeSpecificToGERANIuMode", HFILL }},
    { &hf_ranap_id_SignallingIndication,
      { "id-SignallingIndication", "ranap.id_SignallingIndication",
        FT_UINT32, BASE_DEC, VALS(ranap_SignallingIndication_vals), 0,
        "Dymmy-ie-ids/id-SignallingIndication", HFILL }},
    { &hf_ranap_id_hS_DSCH_MAC_d_Flow_ID,
      { "id-hS-DSCH-MAC-d-Flow-ID", "ranap.id_hS_DSCH_MAC_d_Flow_ID",
        FT_UINT32, BASE_DEC, NULL, 0,
        "Dymmy-ie-ids/id-hS-DSCH-MAC-d-Flow-ID", HFILL }},
    { &hf_ranap_id_CellLoadInformationGroup,
      { "id-CellLoadInformationGroup", "ranap.id_CellLoadInformationGroup",
        FT_NONE, BASE_NONE, NULL, 0,
        "Dymmy-ie-ids/id-CellLoadInformationGroup", HFILL }},
    { &hf_ranap_id_MBMSBearerServiceType,
      { "id-MBMSBearerServiceType", "ranap.id_MBMSBearerServiceType",
        FT_UINT32, BASE_DEC, VALS(ranap_MBMSBearerServiceType_vals), 0,
        "Dymmy-ie-ids/id-MBMSBearerServiceType", HFILL }},
    { &hf_ranap_id_MBMSCNDe_Registration,
      { "id-MBMSCNDe-Registration", "ranap.id_MBMSCNDe_Registration",
        FT_UINT32, BASE_DEC, VALS(ranap_MBMSCNDe_Registration_vals), 0,
        "Dymmy-ie-ids/id-MBMSCNDe-Registration", HFILL }},
    { &hf_ranap_id_MBMSRegistrationRequestType,
      { "id-MBMSRegistrationRequestType", "ranap.id_MBMSRegistrationRequestType",
        FT_UINT32, BASE_DEC, VALS(ranap_MBMSRegistrationRequestType_vals), 0,
        "Dymmy-ie-ids/id-MBMSRegistrationRequestType", HFILL }},
    { &hf_ranap_id_MBMSServiceArea,
      { "id-MBMSServiceArea", "ranap.id_MBMSServiceArea",
        FT_NONE, BASE_NONE, NULL, 0,
        "Dymmy-ie-ids/id-MBMSServiceArea", HFILL }},
    { &hf_ranap_id_MBMSSessionDuration,
      { "id-MBMSSessionDuration", "ranap.id_MBMSSessionDuration",
        FT_BYTES, BASE_HEX, NULL, 0,
        "Dymmy-ie-ids/id-MBMSSessionDuration", HFILL }},
    { &hf_ranap_id_MBMSSessionIdentity,
      { "id-MBMSSessionIdentity", "ranap.id_MBMSSessionIdentity",
        FT_BYTES, BASE_HEX, NULL, 0,
        "Dymmy-ie-ids/id-MBMSSessionIdentity", HFILL }},
    { &hf_ranap_id_MBMSSessionRepetitionNumber,
      { "id-MBMSSessionRepetitionNumber", "ranap.id_MBMSSessionRepetitionNumber",
        FT_UINT32, BASE_DEC, NULL, 0,
        "Dymmy-ie-ids/id-MBMSSessionRepetitionNumber", HFILL }},
    { &hf_ranap_id_NAS_PDU,
      { "id-NAS-PDU", "ranap.id_NAS_PDU",
        FT_BYTES, BASE_HEX, NULL, 0,
        "Dymmy-ie-ids/id-NAS-PDU", HFILL }},
    { &hf_ranap_id_NAS_SequenceNumber,
      { "id-NAS-SequenceNumber", "ranap.id_NAS_SequenceNumber",
        FT_BYTES, BASE_HEX, NULL, 0,
        "Dymmy-ie-ids/id-NAS-SequenceNumber", HFILL }},
    { &hf_ranap_id_NewBSS_To_OldBSS_Information,
      { "id-NewBSS-To-OldBSS-Information", "ranap.id_NewBSS_To_OldBSS_Information",
        FT_BYTES, BASE_HEX, NULL, 0,
        "Dymmy-ie-ids/id-NewBSS-To-OldBSS-Information", HFILL }},
    { &hf_ranap_id_NonSearchingIndication,
      { "id-NonSearchingIndication", "ranap.id_NonSearchingIndication",
        FT_UINT32, BASE_DEC, VALS(ranap_NonSearchingIndication_vals), 0,
        "Dymmy-ie-ids/id-NonSearchingIndication", HFILL }},
    { &hf_ranap_id_NumberOfSteps,
      { "id-NumberOfSteps", "ranap.id_NumberOfSteps",
        FT_UINT32, BASE_DEC, NULL, 0,
        "Dymmy-ie-ids/id-NumberOfSteps", HFILL }},
    { &hf_ranap_id_OMC_ID,
      { "id-OMC-ID", "ranap.id_OMC_ID",
        FT_BYTES, BASE_HEX, NULL, 0,
        "Dymmy-ie-ids/id-OMC-ID", HFILL }},
    { &hf_ranap_id_OldBSS_ToNewBSS_Information,
      { "id-OldBSS-ToNewBSS-Information", "ranap.id_OldBSS_ToNewBSS_Information",
        FT_BYTES, BASE_HEX, NULL, 0,
        "Dymmy-ie-ids/id-OldBSS-ToNewBSS-Information", HFILL }},
    { &hf_ranap_id_PagingAreaID,
      { "id-PagingAreaID", "ranap.id_PagingAreaID",
        FT_UINT32, BASE_DEC, VALS(ranap_PagingAreaID_vals), 0,
        "Dymmy-ie-ids/id-PagingAreaID", HFILL }},
    { &hf_ranap_id_PagingCause,
      { "id-PagingCause", "ranap.id_PagingCause",
        FT_UINT32, BASE_DEC, VALS(ranap_PagingCause_vals), 0,
        "Dymmy-ie-ids/id-PagingCause", HFILL }},
    { &hf_ranap_id_PDP_TypeInformation,
      { "id-PDP-TypeInformation", "ranap.id_PDP_TypeInformation",
        FT_UINT32, BASE_DEC, NULL, 0,
        "Dymmy-ie-ids/id-PDP-TypeInformation", HFILL }},
    { &hf_ranap_id_PermanentNAS_UE_ID,
      { "id-PermanentNAS-UE-ID", "ranap.id_PermanentNAS_UE_ID",
        FT_UINT32, BASE_DEC, VALS(ranap_PermanentNAS_UE_ID_vals), 0,
        "Dymmy-ie-ids/id-PermanentNAS-UE-ID", HFILL }},
    { &hf_ranap_id_PositionData,
      { "id-PositionData", "ranap.id_PositionData",
        FT_NONE, BASE_NONE, NULL, 0,
        "Dymmy-ie-ids/id-PositionData", HFILL }},
    { &hf_ranap_id_PositionDataSpecificToGERANIuMode,
      { "id-PositionDataSpecificToGERANIuMode", "ranap.id_PositionDataSpecificToGERANIuMode",
        FT_BYTES, BASE_HEX, NULL, 0,
        "Dymmy-ie-ids/id-PositionDataSpecificToGERANIuMode", HFILL }},
    { &hf_ranap_id_PositioningPriority,
      { "id-PositioningPriority", "ranap.id_PositioningPriority",
        FT_UINT32, BASE_DEC, VALS(ranap_PositioningPriority_vals), 0,
        "Dymmy-ie-ids/id-PositioningPriority", HFILL }},
    { &hf_ranap_id_ProvidedData,
      { "id-ProvidedData", "ranap.id_ProvidedData",
        FT_UINT32, BASE_DEC, VALS(ranap_ProvidedData_vals), 0,
        "Dymmy-ie-ids/id-ProvidedData", HFILL }},
    { &hf_ranap_id_RAB_ContextItem,
      { "id-RAB-ContextItem", "ranap.id_RAB_ContextItem",
        FT_NONE, BASE_NONE, NULL, 0,
        "Dymmy-ie-ids/id-RAB-ContextItem", HFILL }},
    { &hf_ranap_id_RAB_ContextList,
      { "id-RAB-ContextList", "ranap.id_RAB_ContextList",
        FT_UINT32, BASE_DEC, NULL, 0,
        "Dymmy-ie-ids/id-RAB-ContextList", HFILL }},
    { &hf_ranap_id_RAB_ContextFailedtoTransferItem,
      { "id-RAB-ContextFailedtoTransferItem", "ranap.id_RAB_ContextFailedtoTransferItem",
        FT_NONE, BASE_NONE, NULL, 0,
        "Dymmy-ie-ids/id-RAB-ContextFailedtoTransferItem", HFILL }},
    { &hf_ranap_id_RAB_ContextFailedtoTransferList,
      { "id-RAB-ContextFailedtoTransferList", "ranap.id_RAB_ContextFailedtoTransferList",
        FT_UINT32, BASE_DEC, NULL, 0,
        "Dymmy-ie-ids/id-RAB-ContextFailedtoTransferList", HFILL }},
    { &hf_ranap_id_RAB_ContextItem_RANAP_RelocInf,
      { "id-RAB-ContextItem-RANAP-RelocInf", "ranap.id_RAB_ContextItem_RANAP_RelocInf",
        FT_NONE, BASE_NONE, NULL, 0,
        "Dymmy-ie-ids/id-RAB-ContextItem-RANAP-RelocInf", HFILL }},
    { &hf_ranap_id_RAB_ContextList_RANAP_RelocInf,
      { "id-RAB-ContextList-RANAP-RelocInf", "ranap.id_RAB_ContextList_RANAP_RelocInf",
        FT_UINT32, BASE_DEC, NULL, 0,
        "Dymmy-ie-ids/id-RAB-ContextList-RANAP-RelocInf", HFILL }},
    { &hf_ranap_id_RAB_DataForwardingItem,
      { "id-RAB-DataForwardingItem", "ranap.id_RAB_DataForwardingItem",
        FT_NONE, BASE_NONE, NULL, 0,
        "Dymmy-ie-ids/id-RAB-DataForwardingItem", HFILL }},
    { &hf_ranap_id_RAB_DataForwardingItem_SRNS_CtxReq,
      { "id-RAB-DataForwardingItem-SRNS-CtxReq", "ranap.id_RAB_DataForwardingItem_SRNS_CtxReq",
        FT_NONE, BASE_NONE, NULL, 0,
        "Dymmy-ie-ids/id-RAB-DataForwardingItem-SRNS-CtxReq", HFILL }},
    { &hf_ranap_id_RAB_DataForwardingList,
      { "id-RAB-DataForwardingList", "ranap.id_RAB_DataForwardingList",
        FT_UINT32, BASE_DEC, NULL, 0,
        "Dymmy-ie-ids/id-RAB-DataForwardingList", HFILL }},
    { &hf_ranap_id_RAB_DataForwardingList_SRNS_CtxReq,
      { "id-RAB-DataForwardingList-SRNS-CtxReq", "ranap.id_RAB_DataForwardingList_SRNS_CtxReq",
        FT_UINT32, BASE_DEC, NULL, 0,
        "Dymmy-ie-ids/id-RAB-DataForwardingList-SRNS-CtxReq", HFILL }},
    { &hf_ranap_id_RAB_DataVolumeReportItem,
      { "id-RAB-DataVolumeReportItem", "ranap.id_RAB_DataVolumeReportItem",
        FT_NONE, BASE_NONE, NULL, 0,
        "Dymmy-ie-ids/id-RAB-DataVolumeReportItem", HFILL }},
    { &hf_ranap_id_RAB_DataVolumeReportList,
      { "id-RAB-DataVolumeReportList", "ranap.id_RAB_DataVolumeReportList",
        FT_UINT32, BASE_DEC, NULL, 0,
        "Dymmy-ie-ids/id-RAB-DataVolumeReportList", HFILL }},
    { &hf_ranap_id_RAB_DataVolumeReportRequestItem,
      { "id-RAB-DataVolumeReportRequestItem", "ranap.id_RAB_DataVolumeReportRequestItem",
        FT_NONE, BASE_NONE, NULL, 0,
        "Dymmy-ie-ids/id-RAB-DataVolumeReportRequestItem", HFILL }},
    { &hf_ranap_id_RAB_DataVolumeReportRequestList,
      { "id-RAB-DataVolumeReportRequestList", "ranap.id_RAB_DataVolumeReportRequestList",
        FT_UINT32, BASE_DEC, NULL, 0,
        "Dymmy-ie-ids/id-RAB-DataVolumeReportRequestList", HFILL }},
    { &hf_ranap_id_RAB_FailedItem,
      { "id-RAB-FailedItem", "ranap.id_RAB_FailedItem",
        FT_NONE, BASE_NONE, NULL, 0,
        "Dymmy-ie-ids/id-RAB-FailedItem", HFILL }},
    { &hf_ranap_id_RAB_FailedList,
      { "id-RAB-FailedList", "ranap.id_RAB_FailedList",
        FT_UINT32, BASE_DEC, NULL, 0,
        "Dymmy-ie-ids/id-RAB-FailedList", HFILL }},
    { &hf_ranap_id_RAB_FailedtoReportItem,
      { "id-RAB-FailedtoReportItem", "ranap.id_RAB_FailedtoReportItem",
        FT_NONE, BASE_NONE, NULL, 0,
        "Dymmy-ie-ids/id-RAB-FailedtoReportItem", HFILL }},
    { &hf_ranap_id_RAB_FailedtoReportList,
      { "id-RAB-FailedtoReportList", "ranap.id_RAB_FailedtoReportList",
        FT_UINT32, BASE_DEC, NULL, 0,
        "Dymmy-ie-ids/id-RAB-FailedtoReportList", HFILL }},
    { &hf_ranap_id_RAB_ID,
      { "id-RAB-ID", "ranap.id_RAB_ID",
        FT_BYTES, BASE_HEX, NULL, 0,
        "Dymmy-ie-ids/id-RAB-ID", HFILL }},
    { &hf_ranap_id_RAB_ModifyList,
      { "id-RAB-ModifyList", "ranap.id_RAB_ModifyList",
        FT_UINT32, BASE_DEC, NULL, 0,
        "Dymmy-ie-ids/id-RAB-ModifyList", HFILL }},
    { &hf_ranap_id_RAB_ModifyItem,
      { "id-RAB-ModifyItem", "ranap.id_RAB_ModifyItem",
        FT_NONE, BASE_NONE, NULL, 0,
        "Dymmy-ie-ids/id-RAB-ModifyItem", HFILL }},
    { &hf_ranap_id_TypeOfError,
      { "id-TypeOfError", "ranap.id_TypeOfError",
        FT_UINT32, BASE_DEC, VALS(ranap_TypeOfError_vals), 0,
        "Dymmy-ie-ids/id-TypeOfError", HFILL }},
    { &hf_ranap_id_RAB_Parameters,
      { "id-RAB-Parameters", "ranap.id_RAB_Parameters",
        FT_NONE, BASE_NONE, NULL, 0,
        "Dymmy-ie-ids/id-RAB-Parameters", HFILL }},
    { &hf_ranap_id_RAB_QueuedItem,
      { "id-RAB-QueuedItem", "ranap.id_RAB_QueuedItem",
        FT_NONE, BASE_NONE, NULL, 0,
        "Dymmy-ie-ids/id-RAB-QueuedItem", HFILL }},
    { &hf_ranap_id_RAB_QueuedList,
      { "id-RAB-QueuedList", "ranap.id_RAB_QueuedList",
        FT_UINT32, BASE_DEC, NULL, 0,
        "Dymmy-ie-ids/id-RAB-QueuedList", HFILL }},
    { &hf_ranap_id_RAB_ReleaseFailedList,
      { "id-RAB-ReleaseFailedList", "ranap.id_RAB_ReleaseFailedList",
        FT_UINT32, BASE_DEC, NULL, 0,
        "Dymmy-ie-ids/id-RAB-ReleaseFailedList", HFILL }},
    { &hf_ranap_id_RAB_ReleaseItem,
      { "id-RAB-ReleaseItem", "ranap.id_RAB_ReleaseItem",
        FT_NONE, BASE_NONE, NULL, 0,
        "Dymmy-ie-ids/id-RAB-ReleaseItem", HFILL }},
    { &hf_ranap_id_RAB_ReleasedItem_IuRelComp,
      { "id-RAB-ReleasedItem-IuRelComp", "ranap.id_RAB_ReleasedItem_IuRelComp",
        FT_NONE, BASE_NONE, NULL, 0,
        "Dymmy-ie-ids/id-RAB-ReleasedItem-IuRelComp", HFILL }},
    { &hf_ranap_id_MessageStructure,
      { "id-MessageStructure", "ranap.id_MessageStructure",
        FT_UINT32, BASE_DEC, NULL, 0,
        "Dymmy-ie-ids/id-MessageStructure", HFILL }},
    { &hf_ranap_id_RAB_ReleaseList,
      { "id-RAB-ReleaseList", "ranap.id_RAB_ReleaseList",
        FT_UINT32, BASE_DEC, NULL, 0,
        "Dymmy-ie-ids/id-RAB-ReleaseList", HFILL }},
    { &hf_ranap_id_RAB_ReleasedItem,
      { "id-RAB-ReleasedItem", "ranap.id_RAB_ReleasedItem",
        FT_NONE, BASE_NONE, NULL, 0,
        "Dymmy-ie-ids/id-RAB-ReleasedItem", HFILL }},
    { &hf_ranap_id_RAB_ReleasedList,
      { "id-RAB-ReleasedList", "ranap.id_RAB_ReleasedList",
        FT_UINT32, BASE_DEC, NULL, 0,
        "Dymmy-ie-ids/id-RAB-ReleasedList", HFILL }},
    { &hf_ranap_id_RAB_ReleasedList_IuRelComp,
      { "id-RAB-ReleasedList-IuRelComp", "ranap.id_RAB_ReleasedList_IuRelComp",
        FT_UINT32, BASE_DEC, NULL, 0,
        "Dymmy-ie-ids/id-RAB-ReleasedList-IuRelComp", HFILL }},
    { &hf_ranap_id_RAB_RelocationReleaseItem,
      { "id-RAB-RelocationReleaseItem", "ranap.id_RAB_RelocationReleaseItem",
        FT_NONE, BASE_NONE, NULL, 0,
        "Dymmy-ie-ids/id-RAB-RelocationReleaseItem", HFILL }},
    { &hf_ranap_id_RAB_RelocationReleaseList,
      { "id-RAB-RelocationReleaseList", "ranap.id_RAB_RelocationReleaseList",
        FT_UINT32, BASE_DEC, NULL, 0,
        "Dymmy-ie-ids/id-RAB-RelocationReleaseList", HFILL }},
    { &hf_ranap_id_RAB_SetupItem_RelocReq,
      { "id-RAB-SetupItem-RelocReq", "ranap.id_RAB_SetupItem_RelocReq",
        FT_NONE, BASE_NONE, NULL, 0,
        "Dymmy-ie-ids/id-RAB-SetupItem-RelocReq", HFILL }},
    { &hf_ranap_id_RAB_SetupItem_RelocReqAck,
      { "id-RAB-SetupItem-RelocReqAck", "ranap.id_RAB_SetupItem_RelocReqAck",
        FT_NONE, BASE_NONE, NULL, 0,
        "Dymmy-ie-ids/id-RAB-SetupItem-RelocReqAck", HFILL }},
    { &hf_ranap_id_RAB_SetupList_RelocReq,
      { "id-RAB-SetupList-RelocReq", "ranap.id_RAB_SetupList_RelocReq",
        FT_UINT32, BASE_DEC, NULL, 0,
        "Dymmy-ie-ids/id-RAB-SetupList-RelocReq", HFILL }},
    { &hf_ranap_id_RAB_SetupList_RelocReqAck,
      { "id-RAB-SetupList-RelocReqAck", "ranap.id_RAB_SetupList_RelocReqAck",
        FT_UINT32, BASE_DEC, NULL, 0,
        "Dymmy-ie-ids/id-RAB-SetupList-RelocReqAck", HFILL }},
    { &hf_ranap_id_RAB_SetupOrModifiedItem,
      { "id-RAB-SetupOrModifiedItem", "ranap.id_RAB_SetupOrModifiedItem",
        FT_NONE, BASE_NONE, NULL, 0,
        "Dymmy-ie-ids/id-RAB-SetupOrModifiedItem", HFILL }},
    { &hf_ranap_id_RAB_SetupOrModifiedList,
      { "id-RAB-SetupOrModifiedList", "ranap.id_RAB_SetupOrModifiedList",
        FT_UINT32, BASE_DEC, NULL, 0,
        "Dymmy-ie-ids/id-RAB-SetupOrModifiedList", HFILL }},
    { &hf_ranap_id_RAB_SetupOrModifyList,
      { "id-RAB-SetupOrModifyList", "ranap.id_RAB_SetupOrModifyList",
        FT_UINT32, BASE_DEC, NULL, 0,
        "Dymmy-ie-ids/id-RAB-SetupOrModifyList", HFILL }},
    { &hf_ranap_id_RAC,
      { "id-RAC", "ranap.id_RAC",
        FT_BYTES, BASE_HEX, NULL, 0,
        "Dymmy-ie-ids/id-RAC", HFILL }},
    { &hf_ranap_id_RAListofIdleModeUEs,
      { "id-RAListofIdleModeUEs", "ranap.id_RAListofIdleModeUEs",
        FT_UINT32, BASE_DEC, VALS(ranap_RAListofIdleModeUEs_vals), 0,
        "Dymmy-ie-ids/id-RAListofIdleModeUEs", HFILL }},
    { &hf_ranap_id_RedirectionCompleted,
      { "id-RedirectionCompleted", "ranap.id_RedirectionCompleted",
        FT_UINT32, BASE_DEC, VALS(ranap_RedirectionCompleted_vals), 0,
        "Dymmy-ie-ids/id-RedirectionCompleted", HFILL }},
    { &hf_ranap_id_RedirectionIndication,
      { "id-RedirectionIndication", "ranap.id_RedirectionIndication",
        FT_UINT32, BASE_DEC, NULL, 0,
        "Dymmy-ie-ids/id-RedirectionIndication", HFILL }},
    { &hf_ranap_id_RejectCauseValue,
      { "id-RejectCauseValue", "ranap.id_RejectCauseValue",
        FT_UINT32, BASE_DEC, VALS(ranap_RejectCauseValue_vals), 0,
        "Dymmy-ie-ids/id-RejectCauseValue", HFILL }},
    { &hf_ranap_id_RelocationType,
      { "id-RelocationType", "ranap.id_RelocationType",
        FT_UINT32, BASE_DEC, VALS(ranap_RelocationType_vals), 0,
        "Dymmy-ie-ids/id-RelocationType", HFILL }},
    { &hf_ranap_id_RequestType,
      { "id-RequestType", "ranap.id_RequestType",
        FT_NONE, BASE_NONE, NULL, 0,
        "Dymmy-ie-ids/id-RequestType", HFILL }},
    { &hf_ranap_id_ResponseTime,
      { "id-ResponseTime", "ranap.id_ResponseTime",
        FT_UINT32, BASE_DEC, VALS(ranap_ResponseTime_vals), 0,
        "Dymmy-ie-ids/id-ResponseTime", HFILL }},
    { &hf_ranap_id_SAI,
      { "id-SAI", "ranap.id_SAI",
        FT_NONE, BASE_NONE, NULL, 0,
        "Dymmy-ie-ids/id-SAI", HFILL }},
    { &hf_ranap_id_SAPI,
      { "id-SAPI", "ranap.id_SAPI",
        FT_UINT32, BASE_DEC, VALS(ranap_SAPI_vals), 0,
        "Dymmy-ie-ids/id-SAPI", HFILL }},
    { &hf_ranap_id_SelectedPLMN_ID,
      { "id-SelectedPLMN-ID", "ranap.id_SelectedPLMN_ID",
        FT_BYTES, BASE_HEX, NULL, 0,
        "Dymmy-ie-ids/id-SelectedPLMN-ID", HFILL }},
    { &hf_ranap_id_SessionUpdateID,
      { "id-SessionUpdateID", "ranap.id_SessionUpdateID",
        FT_UINT32, BASE_DEC, NULL, 0,
        "Dymmy-ie-ids/id-SessionUpdateID", HFILL }},
    { &hf_ranap_id_SNA_Access_Information,
      { "id-SNA-Access-Information", "ranap.id_SNA_Access_Information",
        FT_NONE, BASE_NONE, NULL, 0,
        "Dymmy-ie-ids/id-SNA-Access-Information", HFILL }},
    { &hf_ranap_id_SourceID,
      { "id-SourceID", "ranap.id_SourceID",
        FT_UINT32, BASE_DEC, VALS(ranap_SourceID_vals), 0,
        "Dymmy-ie-ids/id-SourceID", HFILL }},
    { &hf_ranap_id_SourceRNC_ToTargetRNC_TransparentContainer,
      { "id-SourceRNC-ToTargetRNC-TransparentContainer", "ranap.id_SourceRNC_ToTargetRNC_TransparentContainer",
        FT_NONE, BASE_NONE, NULL, 0,
        "Dymmy-ie-ids/id-SourceRNC-ToTargetRNC-TransparentContainer", HFILL }},
    { &hf_ranap_id_SourceRNC_PDCP_context_info,
      { "id-SourceRNC-PDCP-context-info", "ranap.id_SourceRNC_PDCP_context_info",
        FT_BYTES, BASE_HEX, NULL, 0,
        "Dymmy-ie-ids/id-SourceRNC-PDCP-context-info", HFILL }},
    { &hf_ranap_id_TargetID,
      { "id-TargetID", "ranap.id_TargetID",
        FT_UINT32, BASE_DEC, VALS(ranap_TargetID_vals), 0,
        "Dymmy-ie-ids/id-TargetID", HFILL }},
    { &hf_ranap_id_TargetRNC_ToSourceRNC_TransparentContainer,
      { "id-TargetRNC-ToSourceRNC-TransparentContainer", "ranap.id_TargetRNC_ToSourceRNC_TransparentContainer",
        FT_NONE, BASE_NONE, NULL, 0,
        "Dymmy-ie-ids/id-TargetRNC-ToSourceRNC-TransparentContainer", HFILL }},
    { &hf_ranap_id_TemporaryUE_ID,
      { "id-TemporaryUE-ID", "ranap.id_TemporaryUE_ID",
        FT_UINT32, BASE_DEC, VALS(ranap_TemporaryUE_ID_vals), 0,
        "Dymmy-ie-ids/id-TemporaryUE-ID", HFILL }},
    { &hf_ranap_id_TMGI,
      { "id-TMGI", "ranap.id_TMGI",
        FT_NONE, BASE_NONE, NULL, 0,
        "Dymmy-ie-ids/id-TMGI", HFILL }},
    { &hf_ranap_id_TracePropagationParameters,
      { "id-TracePropagationParameters", "ranap.id_TracePropagationParameters",
        FT_NONE, BASE_NONE, NULL, 0,
        "Dymmy-ie-ids/id-TracePropagationParameters", HFILL }},
    { &hf_ranap_id_TraceReference,
      { "id-TraceReference", "ranap.id_TraceReference",
        FT_BYTES, BASE_HEX, NULL, 0,
        "Dymmy-ie-ids/id-TraceReference", HFILL }},
    { &hf_ranap_id_TraceType,
      { "id-TraceType", "ranap.id_TraceType",
        FT_BYTES, BASE_HEX, NULL, 0,
        "Dymmy-ie-ids/id-TraceType", HFILL }},
    { &hf_ranap_id_TransportLayerAddress,
      { "id-TransportLayerAddress", "ranap.id_TransportLayerAddress",
        FT_BYTES, BASE_HEX, NULL, 0,
        "Dymmy-ie-ids/id-TransportLayerAddress", HFILL }},
    { &hf_ranap_id_TransportLayerInformation,
      { "id-TransportLayerInformation", "ranap.id_TransportLayerInformation",
        FT_NONE, BASE_NONE, NULL, 0,
        "Dymmy-ie-ids/id-TransportLayerInformation", HFILL }},
    { &hf_ranap_id_TriggerID,
      { "id-TriggerID", "ranap.id_TriggerID",
        FT_BYTES, BASE_HEX, NULL, 0,
        "Dymmy-ie-ids/id-TriggerID", HFILL }},
    { &hf_ranap_id_UE_ID,
      { "id-UE-ID", "ranap.id_UE_ID",
        FT_UINT32, BASE_DEC, VALS(ranap_UE_ID_vals), 0,
        "Dymmy-ie-ids/id-UE-ID", HFILL }},
    { &hf_ranap_id_UESBI_Iu,
      { "id-UESBI-Iu", "ranap.id_UESBI_Iu",
        FT_NONE, BASE_NONE, NULL, 0,
        "Dymmy-ie-ids/id-UESBI-Iu", HFILL }},
    { &hf_ranap_id_UL_GTP_PDU_SequenceNumber,
      { "id-UL-GTP-PDU-SequenceNumber", "ranap.id_UL_GTP_PDU_SequenceNumber",
        FT_UINT32, BASE_DEC, NULL, 0,
        "Dymmy-ie-ids/id-UL-GTP-PDU-SequenceNumber", HFILL }},
    { &hf_ranap_id_UnsuccessfulLinkingList,
      { "id-UnsuccessfulLinkingList", "ranap.id_UnsuccessfulLinkingList",
        FT_UINT32, BASE_DEC, NULL, 0,
        "Dymmy-ie-ids/id-UnsuccessfulLinkingList", HFILL }},
    { &hf_ranap_id_VerticalAccuracyCode,
      { "id-VerticalAccuracyCode", "ranap.id_VerticalAccuracyCode",
        FT_UINT32, BASE_DEC, NULL, 0,
        "Dymmy-ie-ids/id-VerticalAccuracyCode", HFILL }},
    { &hf_ranap_id_MBMSLinkingInformation,
      { "id-MBMSLinkingInformation", "ranap.id_MBMSLinkingInformation",
        FT_UINT32, BASE_DEC, VALS(ranap_MBMSLinkingInformation_vals), 0,
        "Dymmy-ie-ids/id-MBMSLinkingInformation", HFILL }},
    { &hf_ranap_id_AlternativeRABConfiguration,
      { "id-AlternativeRABConfiguration", "ranap.id_AlternativeRABConfiguration",
        FT_NONE, BASE_NONE, NULL, 0,
        "Dymmy-ie-ids/id-AlternativeRABConfiguration", HFILL }},
    { &hf_ranap_id_AlternativeRABConfigurationRequest,
      { "id-AlternativeRABConfigurationRequest", "ranap.id_AlternativeRABConfigurationRequest",
        FT_UINT32, BASE_DEC, VALS(ranap_AlternativeRABConfigurationRequest_vals), 0,
        "Dymmy-ie-ids/id-AlternativeRABConfigurationRequest", HFILL }},
    { &hf_ranap_id_E_DCH_MAC_d_Flow_ID,
      { "id-E-DCH-MAC-d-Flow-ID", "ranap.id_E_DCH_MAC_d_Flow_ID",
        FT_UINT32, BASE_DEC, NULL, 0,
        "Dymmy-ie-ids/id-E-DCH-MAC-d-Flow-ID", HFILL }},
    { &hf_ranap_id_RAB_SetupOrModifyItem1,
      { "id-RAB-SetupOrModifyItem1", "ranap.id_RAB_SetupOrModifyItem1",
        FT_NONE, BASE_NONE, NULL, 0,
        "Dymmy-firstvalue-ie-ids/id-RAB-SetupOrModifyItem1", HFILL }},
    { &hf_ranap_id_RAB_SetupOrModifyItem2,
      { "id-RAB-SetupOrModifyItem2", "ranap.id_RAB_SetupOrModifyItem2",
        FT_NONE, BASE_NONE, NULL, 0,
        "Dymmy-secondvalue-ie-ids/id-RAB-SetupOrModifyItem2", HFILL }},
    { &hf_ranap_protocolIEs,
      { "protocolIEs", "ranap.protocolIEs",
        FT_UINT32, BASE_DEC, NULL, 0,
        "", HFILL }},
    { &hf_ranap_protocolExtensions,
      { "protocolExtensions", "ranap.protocolExtensions",
        FT_UINT32, BASE_DEC, NULL, 0,
        "", HFILL }},
    { &hf_ranap_rAB_ID,
      { "rAB-ID", "ranap.rAB_ID",
        FT_BYTES, BASE_HEX, NULL, 0,
        "", HFILL }},
    { &hf_ranap_rab_dl_UnsuccessfullyTransmittedDataVolume,
      { "dl-UnsuccessfullyTransmittedDataVolume", "ranap.dl_UnsuccessfullyTransmittedDataVolume",
        FT_UINT32, BASE_DEC, NULL, 0,
        "RAB-DataVolumeReportItem/dl-UnsuccessfullyTransmittedDataVolume", HFILL }},
    { &hf_ranap_iE_Extensions,
      { "iE-Extensions", "ranap.iE_Extensions",
        FT_UINT32, BASE_DEC, NULL, 0,
        "", HFILL }},
    { &hf_ranap_dL_GTP_PDU_SequenceNumber,
      { "dL-GTP-PDU-SequenceNumber", "ranap.dL_GTP_PDU_SequenceNumber",
        FT_UINT32, BASE_DEC, NULL, 0,
        "", HFILL }},
    { &hf_ranap_uL_GTP_PDU_SequenceNumber,
      { "uL-GTP-PDU-SequenceNumber", "ranap.uL_GTP_PDU_SequenceNumber",
        FT_UINT32, BASE_DEC, NULL, 0,
        "", HFILL }},
    { &hf_ranap_transportLayerAddress,
      { "transportLayerAddress", "ranap.transportLayerAddress",
        FT_BYTES, BASE_HEX, NULL, 0,
        "", HFILL }},
    { &hf_ranap_iuTransportAssociation,
      { "iuTransportAssociation", "ranap.iuTransportAssociation",
        FT_UINT32, BASE_DEC, VALS(ranap_IuTransportAssociation_vals), 0,
        "", HFILL }},
    { &hf_ranap_nAS_SynchronisationIndicator,
      { "nAS-SynchronisationIndicator", "ranap.nAS_SynchronisationIndicator",
        FT_BYTES, BASE_HEX, NULL, 0,
        "", HFILL }},
    { &hf_ranap_rAB_Parameters,
      { "rAB-Parameters", "ranap.rAB_Parameters",
        FT_NONE, BASE_NONE, NULL, 0,
        "", HFILL }},
    { &hf_ranap_dataVolumeReportingIndication,
      { "dataVolumeReportingIndication", "ranap.dataVolumeReportingIndication",
        FT_UINT32, BASE_DEC, VALS(ranap_DataVolumeReportingIndication_vals), 0,
        "", HFILL }},
    { &hf_ranap_pDP_TypeInformation,
      { "pDP-TypeInformation", "ranap.pDP_TypeInformation",
        FT_UINT32, BASE_DEC, NULL, 0,
        "", HFILL }},
    { &hf_ranap_userPlaneInformation,
      { "userPlaneInformation", "ranap.userPlaneInformation",
        FT_NONE, BASE_NONE, NULL, 0,
        "", HFILL }},
    { &hf_ranap_service_Handover,
      { "service-Handover", "ranap.service_Handover",
        FT_UINT32, BASE_DEC, VALS(ranap_Service_Handover_vals), 0,
        "", HFILL }},
    { &hf_ranap_userPlaneMode,
      { "userPlaneMode", "ranap.userPlaneMode",
        FT_UINT32, BASE_DEC, VALS(ranap_UserPlaneMode_vals), 0,
        "UserPlaneInformation/userPlaneMode", HFILL }},
    { &hf_ranap_uP_ModeVersions,
      { "uP-ModeVersions", "ranap.uP_ModeVersions",
        FT_BYTES, BASE_HEX, NULL, 0,
        "UserPlaneInformation/uP-ModeVersions", HFILL }},
    { &hf_ranap_joinedMBMSBearerService_IEs,
      { "joinedMBMSBearerService-IEs", "ranap.joinedMBMSBearerService_IEs",
        FT_UINT32, BASE_DEC, NULL, 0,
        "CNMBMSLinkingInformation/joinedMBMSBearerService-IEs", HFILL }},
    { &hf_ranap_JoinedMBMSBearerService_IEs_item,
      { "Item", "ranap.JoinedMBMSBearerService_IEs_item",
        FT_NONE, BASE_NONE, NULL, 0,
        "JoinedMBMSBearerService-IEs/_item", HFILL }},
    { &hf_ranap_tMGI,
      { "tMGI", "ranap.tMGI",
        FT_NONE, BASE_NONE, NULL, 0,
        "", HFILL }},
    { &hf_ranap_mBMS_PTP_RAB_ID,
      { "mBMS-PTP-RAB-ID", "ranap.mBMS_PTP_RAB_ID",
        FT_BYTES, BASE_HEX, NULL, 0,
        "JoinedMBMSBearerService-IEs/_item/mBMS-PTP-RAB-ID", HFILL }},
    { &hf_ranap_cause,
      { "cause", "ranap.cause",
        FT_UINT32, BASE_DEC, VALS(ranap_Cause_vals), 0,
        "", HFILL }},
    { &hf_ranap_dl_GTP_PDU_SequenceNumber,
      { "dl-GTP-PDU-SequenceNumber", "ranap.dl_GTP_PDU_SequenceNumber",
        FT_UINT32, BASE_DEC, NULL, 0,
        "", HFILL }},
    { &hf_ranap_ul_GTP_PDU_SequenceNumber,
      { "ul-GTP-PDU-SequenceNumber", "ranap.ul_GTP_PDU_SequenceNumber",
        FT_UINT32, BASE_DEC, NULL, 0,
        "", HFILL }},
    { &hf_ranap_dl_N_PDU_SequenceNumber,
      { "dl-N-PDU-SequenceNumber", "ranap.dl_N_PDU_SequenceNumber",
        FT_UINT32, BASE_DEC, NULL, 0,
        "", HFILL }},
    { &hf_ranap_ul_N_PDU_SequenceNumber,
      { "ul-N-PDU-SequenceNumber", "ranap.ul_N_PDU_SequenceNumber",
        FT_UINT32, BASE_DEC, NULL, 0,
        "", HFILL }},
    { &hf_ranap_iuSigConId,
      { "iuSigConId", "ranap.iuSigConId",
        FT_BYTES, BASE_HEX, NULL, 0,
        "", HFILL }},
    { &hf_ranap_transportLayerInformation,
      { "transportLayerInformation", "ranap.transportLayerInformation",
        FT_NONE, BASE_NONE, NULL, 0,
        "RAB-SetupOrModifyItemFirst/transportLayerInformation", HFILL }},
    { &hf_ranap_dl_dataVolumes,
      { "dl-dataVolumes", "ranap.dl_dataVolumes",
        FT_UINT32, BASE_DEC, NULL, 0,
        "", HFILL }},
    { &hf_ranap_DataVolumeList_item,
      { "Item", "ranap.DataVolumeList_item",
        FT_NONE, BASE_NONE, NULL, 0,
        "DataVolumeList/_item", HFILL }},
    { &hf_ranap_dl_UnsuccessfullyTransmittedDataVolume,
      { "dl-UnsuccessfullyTransmittedDataVolume", "ranap.dl_UnsuccessfullyTransmittedDataVolume",
        FT_UINT32, BASE_DEC, NULL, 0,
        "DataVolumeList/_item/dl-UnsuccessfullyTransmittedDataVolume", HFILL }},
    { &hf_ranap_dataVolumeReference,
      { "dataVolumeReference", "ranap.dataVolumeReference",
        FT_UINT32, BASE_DEC, NULL, 0,
        "DataVolumeList/_item/dataVolumeReference", HFILL }},
    { &hf_ranap_gERAN_Classmark,
      { "gERAN-Classmark", "ranap.gERAN_Classmark",
        FT_BYTES, BASE_HEX, NULL, 0,
        "GERAN-Iumode-RAB-Failed-RABAssgntResponse-Item/gERAN-Classmark", HFILL }},
    { &hf_ranap_privateIEs,
      { "privateIEs", "ranap.privateIEs",
        FT_UINT32, BASE_DEC, NULL, 0,
        "PrivateMessage/privateIEs", HFILL }},
    { &hf_ranap_nAS_PDU,
      { "nAS-PDU", "ranap.nAS_PDU",
        FT_BYTES, BASE_HEX, NULL, 0,
        "DirectTransferInformationItem-RANAP-RelocInf/nAS-PDU", HFILL }},
    { &hf_ranap_sAPI,
      { "sAPI", "ranap.sAPI",
        FT_UINT32, BASE_DEC, VALS(ranap_SAPI_vals), 0,
        "DirectTransferInformationItem-RANAP-RelocInf/sAPI", HFILL }},
    { &hf_ranap_cN_DomainIndicator,
      { "cN-DomainIndicator", "ranap.cN_DomainIndicator",
        FT_UINT32, BASE_DEC, VALS(ranap_CN_DomainIndicator_vals), 0,
        "DirectTransferInformationItem-RANAP-RelocInf/cN-DomainIndicator", HFILL }},
    { &hf_ranap_requested_RAB_Parameter_Values,
      { "requested-RAB-Parameter-Values", "ranap.requested_RAB_Parameter_Values",
        FT_NONE, BASE_NONE, NULL, 0,
        "RAB-ModifyItem/requested-RAB-Parameter-Values", HFILL }},
    { &hf_ranap_LeftMBMSBearerService_IEs_item,
      { "Item", "ranap.LeftMBMSBearerService_IEs_item",
        FT_NONE, BASE_NONE, NULL, 0,
        "LeftMBMSBearerService-IEs/_item", HFILL }},
    { &hf_ranap_UnsuccessfulLinking_IEs_item,
      { "Item", "ranap.UnsuccessfulLinking_IEs_item",
        FT_NONE, BASE_NONE, NULL, 0,
        "UnsuccessfulLinking-IEs/_item", HFILL }},
    { &hf_ranap_priorityLevel,
      { "priorityLevel", "ranap.priorityLevel",
        FT_UINT32, BASE_DEC, VALS(ranap_PriorityLevel_vals), 0,
        "AllocationOrRetentionPriority/priorityLevel", HFILL }},
    { &hf_ranap_pre_emptionCapability,
      { "pre-emptionCapability", "ranap.pre_emptionCapability",
        FT_UINT32, BASE_DEC, VALS(ranap_Pre_emptionCapability_vals), 0,
        "AllocationOrRetentionPriority/pre-emptionCapability", HFILL }},
    { &hf_ranap_pre_emptionVulnerability,
      { "pre-emptionVulnerability", "ranap.pre_emptionVulnerability",
        FT_UINT32, BASE_DEC, VALS(ranap_Pre_emptionVulnerability_vals), 0,
        "AllocationOrRetentionPriority/pre-emptionVulnerability", HFILL }},
    { &hf_ranap_queuingAllowed,
      { "queuingAllowed", "ranap.queuingAllowed",
        FT_UINT32, BASE_DEC, VALS(ranap_QueuingAllowed_vals), 0,
        "AllocationOrRetentionPriority/queuingAllowed", HFILL }},
    { &hf_ranap_altMaxBitrateInf,
      { "altMaxBitrateInf", "ranap.altMaxBitrateInf",
        FT_NONE, BASE_NONE, NULL, 0,
        "Alt-RAB-Parameters/altMaxBitrateInf", HFILL }},
    { &hf_ranap_altGuaranteedBitRateInf,
      { "altGuaranteedBitRateInf", "ranap.altGuaranteedBitRateInf",
        FT_NONE, BASE_NONE, NULL, 0,
        "Alt-RAB-Parameters/altGuaranteedBitRateInf", HFILL }},
    { &hf_ranap_altGuaranteedBitrateType,
      { "altGuaranteedBitrateType", "ranap.altGuaranteedBitrateType",
        FT_UINT32, BASE_DEC, VALS(ranap_Alt_RAB_Parameter_GuaranteedBitrateType_vals), 0,
        "Alt-RAB-Parameter-GuaranteedBitrateInf/altGuaranteedBitrateType", HFILL }},
    { &hf_ranap_altGuaranteedBitrates,
      { "altGuaranteedBitrates", "ranap.altGuaranteedBitrates",
        FT_UINT32, BASE_DEC, NULL, 0,
        "Alt-RAB-Parameter-GuaranteedBitrateInf/altGuaranteedBitrates", HFILL }},
    { &hf_ranap_Alt_RAB_Parameter_GuaranteedBitrates_item,
      { "Item", "ranap.Alt_RAB_Parameter_GuaranteedBitrates_item",
        FT_UINT32, BASE_DEC, NULL, 0,
        "Alt-RAB-Parameter-GuaranteedBitrates/_item", HFILL }},
    { &hf_ranap_Alt_RAB_Parameter_GuaranteedBitrateList_item,
      { "Item", "ranap.Alt_RAB_Parameter_GuaranteedBitrateList_item",
        FT_UINT32, BASE_DEC, NULL, 0,
        "Alt-RAB-Parameter-GuaranteedBitrateList/_item", HFILL }},
    { &hf_ranap_altMaxBitrateType,
      { "altMaxBitrateType", "ranap.altMaxBitrateType",
        FT_UINT32, BASE_DEC, VALS(ranap_Alt_RAB_Parameter_MaxBitrateType_vals), 0,
        "Alt-RAB-Parameter-MaxBitrateInf/altMaxBitrateType", HFILL }},
    { &hf_ranap_altMaxBitrates,
      { "altMaxBitrates", "ranap.altMaxBitrates",
        FT_UINT32, BASE_DEC, NULL, 0,
        "Alt-RAB-Parameter-MaxBitrateInf/altMaxBitrates", HFILL }},
    { &hf_ranap_Alt_RAB_Parameter_MaxBitrates_item,
      { "Item", "ranap.Alt_RAB_Parameter_MaxBitrates_item",
        FT_UINT32, BASE_DEC, NULL, 0,
        "Alt-RAB-Parameter-MaxBitrates/_item", HFILL }},
    { &hf_ranap_Alt_RAB_Parameter_MaxBitrateList_item,
      { "Item", "ranap.Alt_RAB_Parameter_MaxBitrateList_item",
        FT_UINT32, BASE_DEC, NULL, 0,
        "Alt-RAB-Parameter-MaxBitrateList/_item", HFILL }},
    { &hf_ranap_sAI,
      { "sAI", "ranap.sAI",
        FT_NONE, BASE_NONE, NULL, 0,
        "", HFILL }},
    { &hf_ranap_geographicalArea,
      { "geographicalArea", "ranap.geographicalArea",
        FT_UINT32, BASE_DEC, VALS(ranap_GeographicalArea_vals), 0,
        "AreaIdentity/geographicalArea", HFILL }},
    { &hf_ranap_assMaxBitrateInf,
      { "assMaxBitrateInf", "ranap.assMaxBitrateInf",
        FT_UINT32, BASE_DEC, NULL, 0,
        "Ass-RAB-Parameters/assMaxBitrateInf", HFILL }},
    { &hf_ranap_assGuaranteedBitRateInf,
      { "assGuaranteedBitRateInf", "ranap.assGuaranteedBitRateInf",
        FT_UINT32, BASE_DEC, NULL, 0,
        "Ass-RAB-Parameters/assGuaranteedBitRateInf", HFILL }},
    { &hf_ranap_Ass_RAB_Parameter_GuaranteedBitrateList_item,
      { "Item", "ranap.Ass_RAB_Parameter_GuaranteedBitrateList_item",
        FT_UINT32, BASE_DEC, NULL, 0,
        "Ass-RAB-Parameter-GuaranteedBitrateList/_item", HFILL }},
    { &hf_ranap_Ass_RAB_Parameter_MaxBitrateList_item,
      { "Item", "ranap.Ass_RAB_Parameter_MaxBitrateList_item",
        FT_UINT32, BASE_DEC, NULL, 0,
        "Ass-RAB-Parameter-MaxBitrateList/_item", HFILL }},
    { &hf_ranap_AuthorisedPLMNs_item,
      { "Item", "ranap.AuthorisedPLMNs_item",
        FT_NONE, BASE_NONE, NULL, 0,
        "AuthorisedPLMNs/_item", HFILL }},
    { &hf_ranap_pLMNidentity,
      { "pLMNidentity", "ranap.pLMNidentity",
        FT_BYTES, BASE_HEX, NULL, 0,
        "", HFILL }},
    { &hf_ranap_authorisedSNAsList,
      { "authorisedSNAsList", "ranap.authorisedSNAsList",
        FT_UINT32, BASE_DEC, NULL, 0,
        "AuthorisedPLMNs/_item/authorisedSNAsList", HFILL }},
    { &hf_ranap_AuthorisedSNAs_item,
      { "Item", "ranap.AuthorisedSNAs_item",
        FT_UINT32, BASE_DEC, NULL, 0,
        "AuthorisedSNAs/_item", HFILL }},
    { &hf_ranap_cipheringKeyFlag,
      { "cipheringKeyFlag", "ranap.cipheringKeyFlag",
        FT_BYTES, BASE_HEX, NULL, 0,
        "BroadcastAssistanceDataDecipheringKeys/cipheringKeyFlag", HFILL }},
    { &hf_ranap_currentDecipheringKey,
      { "currentDecipheringKey", "ranap.currentDecipheringKey",
        FT_BYTES, BASE_HEX, NULL, 0,
        "BroadcastAssistanceDataDecipheringKeys/currentDecipheringKey", HFILL }},
    { &hf_ranap_nextDecipheringKey,
      { "nextDecipheringKey", "ranap.nextDecipheringKey",
        FT_BYTES, BASE_HEX, NULL, 0,
        "BroadcastAssistanceDataDecipheringKeys/nextDecipheringKey", HFILL }},
    { &hf_ranap_radioNetwork,
      { "radioNetwork", "ranap.radioNetwork",
        FT_UINT32, BASE_DEC, VALS(ranap_CauseRadioNetwork_vals), 0,
        "Cause/radioNetwork", HFILL }},
    { &hf_ranap_transmissionNetwork,
      { "transmissionNetwork", "ranap.transmissionNetwork",
        FT_UINT32, BASE_DEC, VALS(ranap_CauseTransmissionNetwork_vals), 0,
        "Cause/transmissionNetwork", HFILL }},
    { &hf_ranap_nAS,
      { "nAS", "ranap.nAS",
        FT_UINT32, BASE_DEC, VALS(ranap_CauseNAS_vals), 0,
        "Cause/nAS", HFILL }},
    { &hf_ranap_protocol,
      { "protocol", "ranap.protocol",
        FT_UINT32, BASE_DEC, VALS(ranap_CauseProtocol_vals), 0,
        "Cause/protocol", HFILL }},
    { &hf_ranap_misc,
      { "misc", "ranap.misc",
        FT_UINT32, BASE_DEC, VALS(ranap_CauseMisc_vals), 0,
        "Cause/misc", HFILL }},
    { &hf_ranap_non_Standard,
      { "non-Standard", "ranap.non_Standard",
        FT_UINT32, BASE_DEC, NULL, 0,
        "Cause/non-Standard", HFILL }},
    { &hf_ranap_radioNetworkExtension,
      { "radioNetworkExtension", "ranap.radioNetworkExtension",
        FT_UINT32, BASE_DEC, VALS(ranap_CauseRadioNetworkExtension_vals), 0,
        "Cause/radioNetworkExtension", HFILL }},
    { &hf_ranap_cell_Capacity_Class_Value,
      { "cell-Capacity-Class-Value", "ranap.cell_Capacity_Class_Value",
        FT_UINT32, BASE_DEC, NULL, 0,
        "CellLoadInformation/cell-Capacity-Class-Value", HFILL }},
    { &hf_ranap_loadValue,
      { "loadValue", "ranap.loadValue",
        FT_UINT32, BASE_DEC, NULL, 0,
        "CellLoadInformation/loadValue", HFILL }},
    { &hf_ranap_rTLoadValue,
      { "rTLoadValue", "ranap.rTLoadValue",
        FT_UINT32, BASE_DEC, NULL, 0,
        "CellLoadInformation/rTLoadValue", HFILL }},
    { &hf_ranap_nRTLoadInformationValue,
      { "nRTLoadInformationValue", "ranap.nRTLoadInformationValue",
        FT_UINT32, BASE_DEC, NULL, 0,
        "CellLoadInformation/nRTLoadInformationValue", HFILL }},
    { &hf_ranap_sourceCellID,
      { "sourceCellID", "ranap.sourceCellID",
        FT_UINT32, BASE_DEC, VALS(ranap_SourceCellID_vals), 0,
        "CellLoadInformationGroup/sourceCellID", HFILL }},
    { &hf_ranap_uplinkCellLoadInformation,
      { "uplinkCellLoadInformation", "ranap.uplinkCellLoadInformation",
        FT_NONE, BASE_NONE, NULL, 0,
        "", HFILL }},
    { &hf_ranap_downlinkCellLoadInformation,
      { "downlinkCellLoadInformation", "ranap.downlinkCellLoadInformation",
        FT_NONE, BASE_NONE, NULL, 0,
        "", HFILL }},
    { &hf_ranap_triggeringMessage,
      { "triggeringMessage", "ranap.triggeringMessage",
        FT_UINT32, BASE_DEC, VALS(ranap_TriggeringMessage_vals), 0,
        "CriticalityDiagnostics/triggeringMessage", HFILL }},
    { &hf_ranap_procedureCriticality,
      { "procedureCriticality", "ranap.procedureCriticality",
        FT_UINT32, BASE_DEC, VALS(ranap_Criticality_vals), 0,
        "CriticalityDiagnostics/procedureCriticality", HFILL }},
    { &hf_ranap_iEsCriticalityDiagnostics,
      { "iEsCriticalityDiagnostics", "ranap.iEsCriticalityDiagnostics",
        FT_UINT32, BASE_DEC, NULL, 0,
        "CriticalityDiagnostics/iEsCriticalityDiagnostics", HFILL }},
    { &hf_ranap_CriticalityDiagnostics_IE_List_item,
      { "Item", "ranap.CriticalityDiagnostics_IE_List_item",
        FT_NONE, BASE_NONE, NULL, 0,
        "CriticalityDiagnostics-IE-List/_item", HFILL }},
    { &hf_ranap_iECriticality,
      { "iECriticality", "ranap.iECriticality",
        FT_UINT32, BASE_DEC, VALS(ranap_Criticality_vals), 0,
        "CriticalityDiagnostics-IE-List/_item/iECriticality", HFILL }},
    { &hf_ranap_iE_ID,
      { "iE-ID", "ranap.iE_ID",
        FT_UINT32, BASE_DEC, VALS(ranap_ProtocolIE_ID_vals), 0,
        "", HFILL }},
    { &hf_ranap_repetitionNumber,
      { "repetitionNumber", "ranap.repetitionNumber",
        FT_UINT32, BASE_DEC, NULL, 0,
        "CriticalityDiagnostics-IE-List/_item/repetitionNumber", HFILL }},
    { &hf_ranap_MessageStructure_item,
      { "Item", "ranap.MessageStructure_item",
        FT_NONE, BASE_NONE, NULL, 0,
        "MessageStructure/_item", HFILL }},
    { &hf_ranap_item_repetitionNumber,
      { "repetitionNumber", "ranap.repetitionNumber",
        FT_UINT32, BASE_DEC, NULL, 0,
        "MessageStructure/_item/repetitionNumber", HFILL }},
    { &hf_ranap_lAC,
      { "lAC", "ranap.lAC",
        FT_BYTES, BASE_HEX, NULL, 0,
        "", HFILL }},
    { &hf_ranap_cI,
      { "cI", "ranap.cI",
        FT_BYTES, BASE_HEX, NULL, 0,
        "", HFILL }},
    { &hf_ranap_newRAListofIdleModeUEs,
      { "newRAListofIdleModeUEs", "ranap.newRAListofIdleModeUEs",
        FT_UINT32, BASE_DEC, NULL, 0,
        "DeltaRAListofIdleModeUEs/newRAListofIdleModeUEs", HFILL }},
    { &hf_ranap_rAListwithNoIdleModeUEsAnyMore,
      { "rAListwithNoIdleModeUEsAnyMore", "ranap.rAListwithNoIdleModeUEsAnyMore",
        FT_UINT32, BASE_DEC, NULL, 0,
        "DeltaRAListofIdleModeUEs/rAListwithNoIdleModeUEsAnyMore", HFILL }},
    { &hf_ranap_NewRAListofIdleModeUEs_item,
      { "Item", "ranap.NewRAListofIdleModeUEs_item",
        FT_BYTES, BASE_HEX, NULL, 0,
        "NewRAListofIdleModeUEs/_item", HFILL }},
    { &hf_ranap_RAListwithNoIdleModeUEsAnyMore_item,
      { "Item", "ranap.RAListwithNoIdleModeUEsAnyMore_item",
        FT_BYTES, BASE_HEX, NULL, 0,
        "RAListwithNoIdleModeUEsAnyMore/_item", HFILL }},
    { &hf_ranap_encryptionpermittedAlgorithms,
      { "encryptionpermittedAlgorithms", "ranap.encryptionpermittedAlgorithms",
        FT_UINT32, BASE_DEC, NULL, 0,
        "EncryptionInformation/encryptionpermittedAlgorithms", HFILL }},
    { &hf_ranap_encryptionkey,
      { "encryptionkey", "ranap.encryptionkey",
        FT_BYTES, BASE_HEX, NULL, 0,
        "EncryptionInformation/encryptionkey", HFILL }},
    { &hf_ranap_iMEIlist,
      { "iMEIlist", "ranap.iMEIlist",
        FT_UINT32, BASE_DEC, NULL, 0,
        "EquipmentsToBeTraced/iMEIlist", HFILL }},
    { &hf_ranap_iMEISVlist,
      { "iMEISVlist", "ranap.iMEISVlist",
        FT_UINT32, BASE_DEC, NULL, 0,
        "EquipmentsToBeTraced/iMEISVlist", HFILL }},
    { &hf_ranap_iMEIgroup,
      { "iMEIgroup", "ranap.iMEIgroup",
        FT_NONE, BASE_NONE, NULL, 0,
        "EquipmentsToBeTraced/iMEIgroup", HFILL }},
    { &hf_ranap_iMEISVgroup,
      { "iMEISVgroup", "ranap.iMEISVgroup",
        FT_NONE, BASE_NONE, NULL, 0,
        "EquipmentsToBeTraced/iMEISVgroup", HFILL }},
    { &hf_ranap_point,
      { "point", "ranap.point",
        FT_NONE, BASE_NONE, NULL, 0,
        "GeographicalArea/point", HFILL }},
    { &hf_ranap_pointWithUnCertainty,
      { "pointWithUnCertainty", "ranap.pointWithUnCertainty",
        FT_NONE, BASE_NONE, NULL, 0,
        "GeographicalArea/pointWithUnCertainty", HFILL }},
    { &hf_ranap_polygon,
      { "polygon", "ranap.polygon",
        FT_UINT32, BASE_DEC, NULL, 0,
        "GeographicalArea/polygon", HFILL }},
    { &hf_ranap_pointWithUncertaintyEllipse,
      { "pointWithUncertaintyEllipse", "ranap.pointWithUncertaintyEllipse",
        FT_NONE, BASE_NONE, NULL, 0,
        "GeographicalArea/pointWithUncertaintyEllipse", HFILL }},
    { &hf_ranap_pointWithAltitude,
      { "pointWithAltitude", "ranap.pointWithAltitude",
        FT_NONE, BASE_NONE, NULL, 0,
        "GeographicalArea/pointWithAltitude", HFILL }},
    { &hf_ranap_pointWithAltitudeAndUncertaintyEllipsoid,
      { "pointWithAltitudeAndUncertaintyEllipsoid", "ranap.pointWithAltitudeAndUncertaintyEllipsoid",
        FT_NONE, BASE_NONE, NULL, 0,
        "GeographicalArea/pointWithAltitudeAndUncertaintyEllipsoid", HFILL }},
    { &hf_ranap_ellipsoidArc,
      { "ellipsoidArc", "ranap.ellipsoidArc",
        FT_NONE, BASE_NONE, NULL, 0,
        "GeographicalArea/ellipsoidArc", HFILL }},
    { &hf_ranap_latitudeSign,
      { "latitudeSign", "ranap.latitudeSign",
        FT_UINT32, BASE_DEC, VALS(ranap_T_latitudeSign_vals), 0,
        "GeographicalCoordinates/latitudeSign", HFILL }},
    { &hf_ranap_latitude,
      { "latitude", "ranap.latitude",
        FT_UINT32, BASE_DEC, NULL, 0,
        "GeographicalCoordinates/latitude", HFILL }},
    { &hf_ranap_longitude,
      { "longitude", "ranap.longitude",
        FT_INT32, BASE_DEC, NULL, 0,
        "GeographicalCoordinates/longitude", HFILL }},
    { &hf_ranap_directionOfAltitude,
      { "directionOfAltitude", "ranap.directionOfAltitude",
        FT_UINT32, BASE_DEC, VALS(ranap_T_directionOfAltitude_vals), 0,
        "GA-AltitudeAndDirection/directionOfAltitude", HFILL }},
    { &hf_ranap_altitude,
      { "altitude", "ranap.altitude",
        FT_UINT32, BASE_DEC, NULL, 0,
        "GA-AltitudeAndDirection/altitude", HFILL }},
    { &hf_ranap_geographicalCoordinates,
      { "geographicalCoordinates", "ranap.geographicalCoordinates",
        FT_NONE, BASE_NONE, NULL, 0,
        "", HFILL }},
    { &hf_ranap_innerRadius,
      { "innerRadius", "ranap.innerRadius",
        FT_UINT32, BASE_DEC, NULL, 0,
        "GA-EllipsoidArc/innerRadius", HFILL }},
    { &hf_ranap_uncertaintyRadius,
      { "uncertaintyRadius", "ranap.uncertaintyRadius",
        FT_UINT32, BASE_DEC, NULL, 0,
        "GA-EllipsoidArc/uncertaintyRadius", HFILL }},
    { &hf_ranap_offsetAngle,
      { "offsetAngle", "ranap.offsetAngle",
        FT_UINT32, BASE_DEC, NULL, 0,
        "GA-EllipsoidArc/offsetAngle", HFILL }},
    { &hf_ranap_includedAngle,
      { "includedAngle", "ranap.includedAngle",
        FT_UINT32, BASE_DEC, NULL, 0,
        "GA-EllipsoidArc/includedAngle", HFILL }},
    { &hf_ranap_confidence,
      { "confidence", "ranap.confidence",
        FT_UINT32, BASE_DEC, NULL, 0,
        "", HFILL }},
    { &hf_ranap_altitudeAndDirection,
      { "altitudeAndDirection", "ranap.altitudeAndDirection",
        FT_NONE, BASE_NONE, NULL, 0,
        "", HFILL }},
    { &hf_ranap_uncertaintyEllipse,
      { "uncertaintyEllipse", "ranap.uncertaintyEllipse",
        FT_NONE, BASE_NONE, NULL, 0,
        "", HFILL }},
    { &hf_ranap_uncertaintyAltitude,
      { "uncertaintyAltitude", "ranap.uncertaintyAltitude",
        FT_UINT32, BASE_DEC, NULL, 0,
        "GA-PointWithAltitudeAndUncertaintyEllipsoid/uncertaintyAltitude", HFILL }},
    { &hf_ranap_uncertaintyCode,
      { "uncertaintyCode", "ranap.uncertaintyCode",
        FT_UINT32, BASE_DEC, NULL, 0,
        "GA-PointWithUnCertainty/uncertaintyCode", HFILL }},
    { &hf_ranap_GA_Polygon_item,
      { "Item", "ranap.GA_Polygon_item",
        FT_NONE, BASE_NONE, NULL, 0,
        "GA-Polygon/_item", HFILL }},
    { &hf_ranap_uncertaintySemi_major,
      { "uncertaintySemi-major", "ranap.uncertaintySemi_major",
        FT_UINT32, BASE_DEC, NULL, 0,
        "GA-UncertaintyEllipse/uncertaintySemi-major", HFILL }},
    { &hf_ranap_uncertaintySemi_minor,
      { "uncertaintySemi-minor", "ranap.uncertaintySemi_minor",
        FT_UINT32, BASE_DEC, NULL, 0,
        "GA-UncertaintyEllipse/uncertaintySemi-minor", HFILL }},
    { &hf_ranap_orientationOfMajorAxis,
      { "orientationOfMajorAxis", "ranap.orientationOfMajorAxis",
        FT_UINT32, BASE_DEC, NULL, 0,
        "GA-UncertaintyEllipse/orientationOfMajorAxis", HFILL }},
    { &hf_ranap_lAI,
      { "lAI", "ranap.lAI",
        FT_NONE, BASE_NONE, NULL, 0,
        "", HFILL }},
    { &hf_ranap_rAC,
      { "rAC", "ranap.rAC",
        FT_BYTES, BASE_HEX, NULL, 0,
        "", HFILL }},
    { &hf_ranap_cN_ID,
      { "cN-ID", "ranap.cN_ID",
        FT_UINT32, BASE_DEC, NULL, 0,
        "GlobalCN-ID/cN-ID", HFILL }},
    { &hf_ranap_rNC_ID,
      { "rNC-ID", "ranap.rNC_ID",
        FT_UINT32, BASE_DEC, NULL, 0,
        "", HFILL }},
    { &hf_ranap_iMEI,
      { "iMEI", "ranap.iMEI",
        FT_BYTES, BASE_HEX, NULL, 0,
        "IMEIGroup/iMEI", HFILL }},
    { &hf_ranap_iMEIMask,
      { "iMEIMask", "ranap.iMEIMask",
        FT_BYTES, BASE_HEX, NULL, 0,
        "IMEIGroup/iMEIMask", HFILL }},
    { &hf_ranap_IMEIList_item,
      { "Item", "ranap.IMEIList_item",
        FT_BYTES, BASE_HEX, NULL, 0,
        "IMEIList/_item", HFILL }},
    { &hf_ranap_iMEISV,
      { "iMEISV", "ranap.iMEISV",
        FT_BYTES, BASE_HEX, NULL, 0,
        "IMEISVGroup/iMEISV", HFILL }},
    { &hf_ranap_iMEISVMask,
      { "iMEISVMask", "ranap.iMEISVMask",
        FT_BYTES, BASE_HEX, NULL, 0,
        "IMEISVGroup/iMEISVMask", HFILL }},
    { &hf_ranap_IMEISVList_item,
      { "Item", "ranap.IMEISVList_item",
        FT_BYTES, BASE_HEX, NULL, 0,
        "IMEISVList/_item", HFILL }},
    { &hf_ranap_requestedMBMSIPMulticastAddressandAPNRequest,
      { "requestedMBMSIPMulticastAddressandAPNRequest", "ranap.requestedMBMSIPMulticastAddressandAPNRequest",
        FT_UINT32, BASE_DEC, NULL, 0,
        "InformationRequested/requestedMBMSIPMulticastAddressandAPNRequest", HFILL }},
    { &hf_ranap_requestedMulticastServiceList,
      { "requestedMulticastServiceList", "ranap.requestedMulticastServiceList",
        FT_UINT32, BASE_DEC, NULL, 0,
        "InformationRequested/requestedMulticastServiceList", HFILL }},
    { &hf_ranap_mBMSIPMulticastAddressandAPNRequest,
      { "mBMSIPMulticastAddressandAPNRequest", "ranap.mBMSIPMulticastAddressandAPNRequest",
        FT_UINT32, BASE_DEC, NULL, 0,
        "InformationRequestType/mBMSIPMulticastAddressandAPNRequest", HFILL }},
    { &hf_ranap_permanentNAS_UE_ID,
      { "permanentNAS-UE-ID", "ranap.permanentNAS_UE_ID",
        FT_UINT32, BASE_DEC, VALS(ranap_PermanentNAS_UE_ID_vals), 0,
        "InformationRequestType/permanentNAS-UE-ID", HFILL }},
    { &hf_ranap_rNCTraceInformation,
      { "rNCTraceInformation", "ranap.rNCTraceInformation",
        FT_NONE, BASE_NONE, NULL, 0,
        "InformationTransferType/rNCTraceInformation", HFILL }},
    { &hf_ranap_permittedAlgorithms,
      { "permittedAlgorithms", "ranap.permittedAlgorithms",
        FT_UINT32, BASE_DEC, NULL, 0,
        "IntegrityProtectionInformation/permittedAlgorithms", HFILL }},
    { &hf_ranap_key,
      { "key", "ranap.key",
        FT_BYTES, BASE_HEX, NULL, 0,
        "IntegrityProtectionInformation/key", HFILL }},
    { &hf_ranap_rIM_Transfer,
      { "rIM-Transfer", "ranap.rIM_Transfer",
        FT_NONE, BASE_NONE, NULL, 0,
        "InterSystemInformationTransferType/rIM-Transfer", HFILL }},
    { &hf_ranap_gTP_TEI,
      { "gTP-TEI", "ranap.gTP_TEI",
        FT_BYTES, BASE_HEX, NULL, 0,
        "IuTransportAssociation/gTP-TEI", HFILL }},
    { &hf_ranap_bindingID,
      { "bindingID", "ranap.bindingID",
        FT_BYTES, BASE_HEX, NULL, 0,
        "IuTransportAssociation/bindingID", HFILL }},
    { &hf_ranap_LA_LIST_item,
      { "Item", "ranap.LA_LIST_item",
        FT_NONE, BASE_NONE, NULL, 0,
        "LA-LIST/_item", HFILL }},
    { &hf_ranap_listOF_SNAs,
      { "listOF-SNAs", "ranap.listOF_SNAs",
        FT_UINT32, BASE_DEC, NULL, 0,
        "LA-LIST/_item/listOF-SNAs", HFILL }},
    { &hf_ranap_ageOfSAI,
      { "ageOfSAI", "ranap.ageOfSAI",
        FT_UINT32, BASE_DEC, NULL, 0,
        "LastKnownServiceArea/ageOfSAI", HFILL }},
    { &hf_ranap_ListOF_SNAs_item,
      { "Item", "ranap.ListOF_SNAs_item",
        FT_UINT32, BASE_DEC, NULL, 0,
        "ListOF-SNAs/_item", HFILL }},
    { &hf_ranap_ListOfInterfacesToTrace_item,
      { "Item", "ranap.ListOfInterfacesToTrace_item",
        FT_NONE, BASE_NONE, NULL, 0,
        "ListOfInterfacesToTrace/_item", HFILL }},
    { &hf_ranap_interface,
      { "interface", "ranap.interface",
        FT_UINT32, BASE_DEC, VALS(ranap_T_interface_vals), 0,
        "InterfacesToTraceItem/interface", HFILL }},
    { &hf_ranap_requestedLocationRelatedDataType,
      { "requestedLocationRelatedDataType", "ranap.requestedLocationRelatedDataType",
        FT_UINT32, BASE_DEC, VALS(ranap_RequestedLocationRelatedDataType_vals), 0,
        "LocationRelatedDataRequestType/requestedLocationRelatedDataType", HFILL }},
    { &hf_ranap_requestedGPSAssistanceData,
      { "requestedGPSAssistanceData", "ranap.requestedGPSAssistanceData",
        FT_BYTES, BASE_HEX, NULL, 0,
        "LocationRelatedDataRequestType/requestedGPSAssistanceData", HFILL }},
    { &hf_ranap_MBMSIPMulticastAddressandAPNRequest_item,
      { "Item", "ranap.MBMSIPMulticastAddressandAPNRequest_item",
        FT_NONE, BASE_NONE, NULL, 0,
        "MBMSIPMulticastAddressandAPNRequest/_item", HFILL }},
    { &hf_ranap_mBMSServiceAreaList,
      { "mBMSServiceAreaList", "ranap.mBMSServiceAreaList",
        FT_UINT32, BASE_DEC, NULL, 0,
        "MBMSServiceArea/mBMSServiceAreaList", HFILL }},
    { &hf_ranap_MBMSServiceAreaList_item,
      { "Item", "ranap.MBMSServiceAreaList_item",
        FT_UINT32, BASE_DEC, NULL, 0,
        "MBMSServiceAreaList/_item", HFILL }},
    { &hf_ranap_rAI,
      { "rAI", "ranap.rAI",
        FT_NONE, BASE_NONE, NULL, 0,
        "PagingAreaID/rAI", HFILL }},
    { &hf_ranap_PDP_TypeInformation_item,
      { "Item", "ranap.PDP_TypeInformation_item",
        FT_UINT32, BASE_DEC, VALS(ranap_PDP_Type_vals), 0,
        "PDP-TypeInformation/_item", HFILL }},
    { &hf_ranap_iMSI,
      { "iMSI", "ranap.iMSI",
        FT_BYTES, BASE_HEX, NULL, 0,
        "PermanentNAS-UE-ID/iMSI", HFILL }},
    { &hf_ranap_PermittedEncryptionAlgorithms_item,
      { "Item", "ranap.PermittedEncryptionAlgorithms_item",
        FT_UINT32, BASE_DEC, VALS(ranap_EncryptionAlgorithm_vals), 0,
        "PermittedEncryptionAlgorithms/_item", HFILL }},
    { &hf_ranap_PermittedIntegrityProtectionAlgorithms_item,
      { "Item", "ranap.PermittedIntegrityProtectionAlgorithms_item",
        FT_UINT32, BASE_DEC, VALS(ranap_IntegrityProtectionAlgorithm_vals), 0,
        "PermittedIntegrityProtectionAlgorithms/_item", HFILL }},
    { &hf_ranap_PLMNs_in_shared_network_item,
      { "Item", "ranap.PLMNs_in_shared_network_item",
        FT_NONE, BASE_NONE, NULL, 0,
        "PLMNs-in-shared-network/_item", HFILL }},
    { &hf_ranap_lA_LIST,
      { "lA-LIST", "ranap.lA_LIST",
        FT_UINT32, BASE_DEC, NULL, 0,
        "PLMNs-in-shared-network/_item/lA-LIST", HFILL }},
    { &hf_ranap_PositioningDataSet_item,
      { "Item", "ranap.PositioningDataSet_item",
        FT_BYTES, BASE_HEX, NULL, 0,
        "PositioningDataSet/_item", HFILL }},
    { &hf_ranap_positioningDataDiscriminator,
      { "positioningDataDiscriminator", "ranap.positioningDataDiscriminator",
        FT_BYTES, BASE_HEX, NULL, 0,
        "PositionData/positioningDataDiscriminator", HFILL }},
    { &hf_ranap_positioningDataSet,
      { "positioningDataSet", "ranap.positioningDataSet",
        FT_UINT32, BASE_DEC, NULL, 0,
        "PositionData/positioningDataSet", HFILL }},
    { &hf_ranap_shared_network_information,
      { "shared-network-information", "ranap.shared_network_information",
        FT_NONE, BASE_NONE, NULL, 0,
        "ProvidedData/shared-network-information", HFILL }},
    { &hf_ranap_RAB_Parameter_GuaranteedBitrateList_item,
      { "Item", "ranap.RAB_Parameter_GuaranteedBitrateList_item",
        FT_UINT32, BASE_DEC, NULL, 0,
        "RAB-Parameter-GuaranteedBitrateList/_item", HFILL }},
    { &hf_ranap_RAB_Parameter_MaxBitrateList_item,
      { "Item", "ranap.RAB_Parameter_MaxBitrateList_item",
        FT_UINT32, BASE_DEC, NULL, 0,
        "RAB-Parameter-MaxBitrateList/_item", HFILL }},
    { &hf_ranap_trafficClass,
      { "trafficClass", "ranap.trafficClass",
        FT_UINT32, BASE_DEC, VALS(ranap_TrafficClass_vals), 0,
        "RAB-Parameters/trafficClass", HFILL }},
    { &hf_ranap_rAB_AsymmetryIndicator,
      { "rAB-AsymmetryIndicator", "ranap.rAB_AsymmetryIndicator",
        FT_UINT32, BASE_DEC, VALS(ranap_RAB_AsymmetryIndicator_vals), 0,
        "RAB-Parameters/rAB-AsymmetryIndicator", HFILL }},
    { &hf_ranap_maxBitrate,
      { "maxBitrate", "ranap.maxBitrate",
        FT_UINT32, BASE_DEC, NULL, 0,
        "RAB-Parameters/maxBitrate", HFILL }},
    { &hf_ranap_guaranteedBitRate,
      { "guaranteedBitRate", "ranap.guaranteedBitRate",
        FT_UINT32, BASE_DEC, NULL, 0,
        "RAB-Parameters/guaranteedBitRate", HFILL }},
    { &hf_ranap_deliveryOrder,
      { "deliveryOrder", "ranap.deliveryOrder",
        FT_UINT32, BASE_DEC, VALS(ranap_DeliveryOrder_vals), 0,
        "RAB-Parameters/deliveryOrder", HFILL }},
    { &hf_ranap_maxSDU_Size,
      { "maxSDU-Size", "ranap.maxSDU_Size",
        FT_UINT32, BASE_DEC, NULL, 0,
        "RAB-Parameters/maxSDU-Size", HFILL }},
    { &hf_ranap_sDU_Parameters,
      { "sDU-Parameters", "ranap.sDU_Parameters",
        FT_UINT32, BASE_DEC, NULL, 0,
        "RAB-Parameters/sDU-Parameters", HFILL }},
    { &hf_ranap_transferDelay,
      { "transferDelay", "ranap.transferDelay",
        FT_UINT32, BASE_DEC, NULL, 0,
        "RAB-Parameters/transferDelay", HFILL }},
    { &hf_ranap_trafficHandlingPriority,
      { "trafficHandlingPriority", "ranap.trafficHandlingPriority",
        FT_UINT32, BASE_DEC, VALS(ranap_TrafficHandlingPriority_vals), 0,
        "RAB-Parameters/trafficHandlingPriority", HFILL }},
    { &hf_ranap_allocationOrRetentionPriority,
      { "allocationOrRetentionPriority", "ranap.allocationOrRetentionPriority",
        FT_NONE, BASE_NONE, NULL, 0,
        "RAB-Parameters/allocationOrRetentionPriority", HFILL }},
    { &hf_ranap_sourceStatisticsDescriptor,
      { "sourceStatisticsDescriptor", "ranap.sourceStatisticsDescriptor",
        FT_UINT32, BASE_DEC, VALS(ranap_SourceStatisticsDescriptor_vals), 0,
        "RAB-Parameters/sourceStatisticsDescriptor", HFILL }},
    { &hf_ranap_relocationRequirement,
      { "relocationRequirement", "ranap.relocationRequirement",
        FT_UINT32, BASE_DEC, VALS(ranap_RelocationRequirement_vals), 0,
        "RAB-Parameters/relocationRequirement", HFILL }},
    { &hf_ranap_RAB_TrCH_Mapping_item,
      { "Item", "ranap.RAB_TrCH_Mapping_item",
        FT_NONE, BASE_NONE, NULL, 0,
        "RAB-TrCH-Mapping/_item", HFILL }},
    { &hf_ranap_trCH_ID_List,
      { "trCH-ID-List", "ranap.trCH_ID_List",
        FT_UINT32, BASE_DEC, NULL, 0,
        "RAB-TrCH-MappingItem/trCH-ID-List", HFILL }},
    { &hf_ranap_notEmptyRAListofIdleModeUEs,
      { "notEmptyRAListofIdleModeUEs", "ranap.notEmptyRAListofIdleModeUEs",
        FT_NONE, BASE_NONE, NULL, 0,
        "RAListofIdleModeUEs/notEmptyRAListofIdleModeUEs", HFILL }},
    { &hf_ranap_emptyFullRAListofIdleModeUEs,
      { "emptyFullRAListofIdleModeUEs", "ranap.emptyFullRAListofIdleModeUEs",
        FT_UINT32, BASE_DEC, VALS(ranap_T_emptyFullRAListofIdleModeUEs_vals), 0,
        "RAListofIdleModeUEs/emptyFullRAListofIdleModeUEs", HFILL }},
    { &hf_ranap_rAofIdleModeUEs,
      { "rAofIdleModeUEs", "ranap.rAofIdleModeUEs",
        FT_UINT32, BASE_DEC, NULL, 0,
        "NotEmptyRAListofIdleModeUEs/rAofIdleModeUEs", HFILL }},
    { &hf_ranap_RAofIdleModeUEs_item,
      { "Item", "ranap.RAofIdleModeUEs_item",
        FT_BYTES, BASE_HEX, NULL, 0,
        "RAofIdleModeUEs/_item", HFILL }},
    { &hf_ranap_RequestedMBMSIPMulticastAddressandAPNRequest_item,
      { "Item", "ranap.RequestedMBMSIPMulticastAddressandAPNRequest_item",
        FT_NONE, BASE_NONE, NULL, 0,
        "RequestedMBMSIPMulticastAddressandAPNRequest/_item", HFILL }},
    { &hf_ranap_iPMulticastAddress,
      { "iPMulticastAddress", "ranap.iPMulticastAddress",
        FT_BYTES, BASE_HEX, NULL, 0,
        "MBMSIPMulticastAddressandAPNlist/iPMulticastAddress", HFILL }},
    { &hf_ranap_aPN,
      { "aPN", "ranap.aPN",
        FT_BYTES, BASE_HEX, NULL, 0,
        "MBMSIPMulticastAddressandAPNlist/aPN", HFILL }},
    { &hf_ranap_RequestedMulticastServiceList_item,
      { "Item", "ranap.RequestedMulticastServiceList_item",
        FT_NONE, BASE_NONE, NULL, 0,
        "RequestedMulticastServiceList/_item", HFILL }},
    { &hf_ranap_requestedMaxBitrates,
      { "requestedMaxBitrates", "ranap.requestedMaxBitrates",
        FT_UINT32, BASE_DEC, NULL, 0,
        "Requested-RAB-Parameter-Values/requestedMaxBitrates", HFILL }},
    { &hf_ranap_requestedGuaranteedBitrates,
      { "requestedGuaranteedBitrates", "ranap.requestedGuaranteedBitrates",
        FT_UINT32, BASE_DEC, NULL, 0,
        "Requested-RAB-Parameter-Values/requestedGuaranteedBitrates", HFILL }},
    { &hf_ranap_Requested_RAB_Parameter_MaxBitrateList_item,
      { "Item", "ranap.Requested_RAB_Parameter_MaxBitrateList_item",
        FT_UINT32, BASE_DEC, NULL, 0,
        "Requested-RAB-Parameter-MaxBitrateList/_item", HFILL }},
    { &hf_ranap_Requested_RAB_Parameter_GuaranteedBitrateList_item,
      { "Item", "ranap.Requested_RAB_Parameter_GuaranteedBitrateList_item",
        FT_UINT32, BASE_DEC, NULL, 0,
        "Requested-RAB-Parameter-GuaranteedBitrateList/_item", HFILL }},
    { &hf_ranap_event,
      { "event", "ranap.event",
        FT_UINT32, BASE_DEC, VALS(ranap_Event_vals), 0,
        "RequestType/event", HFILL }},
    { &hf_ranap_reportArea,
      { "reportArea", "ranap.reportArea",
        FT_UINT32, BASE_DEC, VALS(ranap_ReportArea_vals), 0,
        "RequestType/reportArea", HFILL }},
    { &hf_ranap_accuracyCode,
      { "accuracyCode", "ranap.accuracyCode",
        FT_UINT32, BASE_DEC, NULL, 0,
        "RequestType/accuracyCode", HFILL }},
    { &hf_ranap_mantissa,
      { "mantissa", "ranap.mantissa",
        FT_UINT32, BASE_DEC, NULL, 0,
        "", HFILL }},
    { &hf_ranap_exponent,
      { "exponent", "ranap.exponent",
        FT_UINT32, BASE_DEC, NULL, 0,
        "ResidualBitErrorRatio/exponent", HFILL }},
    { &hf_ranap_rIMInformation,
      { "rIMInformation", "ranap.rIMInformation",
        FT_BYTES, BASE_HEX, NULL, 0,
        "RIM-Transfer/rIMInformation", HFILL }},
    { &hf_ranap_rIMRoutingAddress,
      { "rIMRoutingAddress", "ranap.rIMRoutingAddress",
        FT_UINT32, BASE_DEC, VALS(ranap_RIMRoutingAddress_vals), 0,
        "RIM-Transfer/rIMRoutingAddress", HFILL }},
    { &hf_ranap_globalRNC_ID,
      { "globalRNC-ID", "ranap.globalRNC_ID",
        FT_NONE, BASE_NONE, NULL, 0,
        "RIMRoutingAddress/globalRNC-ID", HFILL }},
    { &hf_ranap_gERAN_Cell_ID,
      { "gERAN-Cell-ID", "ranap.gERAN_Cell_ID",
        FT_NONE, BASE_NONE, NULL, 0,
        "RIMRoutingAddress/gERAN-Cell-ID", HFILL }},
    { &hf_ranap_traceReference,
      { "traceReference", "ranap.traceReference",
        FT_BYTES, BASE_HEX, NULL, 0,
        "", HFILL }},
    { &hf_ranap_traceActivationIndicator,
      { "traceActivationIndicator", "ranap.traceActivationIndicator",
        FT_UINT32, BASE_DEC, VALS(ranap_T_traceActivationIndicator_vals), 0,
        "RNCTraceInformation/traceActivationIndicator", HFILL }},
    { &hf_ranap_equipmentsToBeTraced,
      { "equipmentsToBeTraced", "ranap.equipmentsToBeTraced",
        FT_UINT32, BASE_DEC, VALS(ranap_EquipmentsToBeTraced_vals), 0,
        "RNCTraceInformation/equipmentsToBeTraced", HFILL }},
    { &hf_ranap_sAC,
      { "sAC", "ranap.sAC",
        FT_BYTES, BASE_HEX, NULL, 0,
        "SAI/sAC", HFILL }},
    { &hf_ranap_pLMNs_in_shared_network,
      { "pLMNs-in-shared-network", "ranap.pLMNs_in_shared_network",
        FT_UINT32, BASE_DEC, NULL, 0,
        "Shared-Network-Information/pLMNs-in-shared-network", HFILL }},
    { &hf_ranap_exponent_1_8,
      { "exponent", "ranap.exponent",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SDU-ErrorRatio/exponent", HFILL }},
    { &hf_ranap_SDU_FormatInformationParameters_item,
      { "Item", "ranap.SDU_FormatInformationParameters_item",
        FT_NONE, BASE_NONE, NULL, 0,
        "SDU-FormatInformationParameters/_item", HFILL }},
    { &hf_ranap_subflowSDU_Size,
      { "subflowSDU-Size", "ranap.subflowSDU_Size",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SDU-FormatInformationParameters/_item/subflowSDU-Size", HFILL }},
    { &hf_ranap_rAB_SubflowCombinationBitRate,
      { "rAB-SubflowCombinationBitRate", "ranap.rAB_SubflowCombinationBitRate",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SDU-FormatInformationParameters/_item/rAB-SubflowCombinationBitRate", HFILL }},
    { &hf_ranap_SDU_Parameters_item,
      { "Item", "ranap.SDU_Parameters_item",
        FT_NONE, BASE_NONE, NULL, 0,
        "SDU-Parameters/_item", HFILL }},
    { &hf_ranap_sDU_ErrorRatio,
      { "sDU-ErrorRatio", "ranap.sDU_ErrorRatio",
        FT_NONE, BASE_NONE, NULL, 0,
        "SDU-Parameters/_item/sDU-ErrorRatio", HFILL }},
    { &hf_ranap_residualBitErrorRatio,
      { "residualBitErrorRatio", "ranap.residualBitErrorRatio",
        FT_NONE, BASE_NONE, NULL, 0,
        "SDU-Parameters/_item/residualBitErrorRatio", HFILL }},
    { &hf_ranap_deliveryOfErroneousSDU,
      { "deliveryOfErroneousSDU", "ranap.deliveryOfErroneousSDU",
        FT_UINT32, BASE_DEC, VALS(ranap_DeliveryOfErroneousSDU_vals), 0,
        "SDU-Parameters/_item/deliveryOfErroneousSDU", HFILL }},
    { &hf_ranap_sDU_FormatInformationParameters,
      { "sDU-FormatInformationParameters", "ranap.sDU_FormatInformationParameters",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SDU-Parameters/_item/sDU-FormatInformationParameters", HFILL }},
    { &hf_ranap_authorisedPLMNs,
      { "authorisedPLMNs", "ranap.authorisedPLMNs",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SNA-Access-Information/authorisedPLMNs", HFILL }},
    { &hf_ranap_sourceUTRANCellID,
      { "sourceUTRANCellID", "ranap.sourceUTRANCellID",
        FT_NONE, BASE_NONE, NULL, 0,
        "SourceCellID/sourceUTRANCellID", HFILL }},
    { &hf_ranap_sourceGERANCellID,
      { "sourceGERANCellID", "ranap.sourceGERANCellID",
        FT_NONE, BASE_NONE, NULL, 0,
        "SourceCellID/sourceGERANCellID", HFILL }},
    { &hf_ranap_sourceRNC_ID,
      { "sourceRNC-ID", "ranap.sourceRNC_ID",
        FT_NONE, BASE_NONE, NULL, 0,
        "SourceID/sourceRNC-ID", HFILL }},
    { &hf_ranap_rRC_Container,
      { "rRC-Container", "ranap.rRC_Container",
        FT_BYTES, BASE_HEX, NULL, 0,
        "", HFILL }},
    { &hf_ranap_numberOfIuInstances,
      { "numberOfIuInstances", "ranap.numberOfIuInstances",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SourceRNC-ToTargetRNC-TransparentContainer/numberOfIuInstances", HFILL }},
    { &hf_ranap_relocationType,
      { "relocationType", "ranap.relocationType",
        FT_UINT32, BASE_DEC, VALS(ranap_RelocationType_vals), 0,
        "SourceRNC-ToTargetRNC-TransparentContainer/relocationType", HFILL }},
    { &hf_ranap_chosenIntegrityProtectionAlgorithm,
      { "chosenIntegrityProtectionAlgorithm", "ranap.chosenIntegrityProtectionAlgorithm",
        FT_UINT32, BASE_DEC, VALS(ranap_IntegrityProtectionAlgorithm_vals), 0,
        "SourceRNC-ToTargetRNC-TransparentContainer/chosenIntegrityProtectionAlgorithm", HFILL }},
    { &hf_ranap_integrityProtectionKey,
      { "integrityProtectionKey", "ranap.integrityProtectionKey",
        FT_BYTES, BASE_HEX, NULL, 0,
        "SourceRNC-ToTargetRNC-TransparentContainer/integrityProtectionKey", HFILL }},
    { &hf_ranap_chosenEncryptionAlgorithForSignalling,
      { "chosenEncryptionAlgorithForSignalling", "ranap.chosenEncryptionAlgorithForSignalling",
        FT_UINT32, BASE_DEC, VALS(ranap_EncryptionAlgorithm_vals), 0,
        "SourceRNC-ToTargetRNC-TransparentContainer/chosenEncryptionAlgorithForSignalling", HFILL }},
    { &hf_ranap_cipheringKey,
      { "cipheringKey", "ranap.cipheringKey",
        FT_BYTES, BASE_HEX, NULL, 0,
        "SourceRNC-ToTargetRNC-TransparentContainer/cipheringKey", HFILL }},
    { &hf_ranap_chosenEncryptionAlgorithForCS,
      { "chosenEncryptionAlgorithForCS", "ranap.chosenEncryptionAlgorithForCS",
        FT_UINT32, BASE_DEC, VALS(ranap_EncryptionAlgorithm_vals), 0,
        "SourceRNC-ToTargetRNC-TransparentContainer/chosenEncryptionAlgorithForCS", HFILL }},
    { &hf_ranap_chosenEncryptionAlgorithForPS,
      { "chosenEncryptionAlgorithForPS", "ranap.chosenEncryptionAlgorithForPS",
        FT_UINT32, BASE_DEC, VALS(ranap_EncryptionAlgorithm_vals), 0,
        "SourceRNC-ToTargetRNC-TransparentContainer/chosenEncryptionAlgorithForPS", HFILL }},
    { &hf_ranap_d_RNTI,
      { "d-RNTI", "ranap.d_RNTI",
        FT_UINT32, BASE_DEC, NULL, 0,
        "", HFILL }},
    { &hf_ranap_targetCellId,
      { "targetCellId", "ranap.targetCellId",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SourceRNC-ToTargetRNC-TransparentContainer/targetCellId", HFILL }},
    { &hf_ranap_rAB_TrCH_Mapping,
      { "rAB-TrCH-Mapping", "ranap.rAB_TrCH_Mapping",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SourceRNC-ToTargetRNC-TransparentContainer/rAB-TrCH-Mapping", HFILL }},
    { &hf_ranap_uTRANcellID,
      { "uTRANcellID", "ranap.uTRANcellID",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SourceUTRANCellID/uTRANcellID", HFILL }},
    { &hf_ranap_SRB_TrCH_Mapping_item,
      { "Item", "ranap.SRB_TrCH_Mapping_item",
        FT_NONE, BASE_NONE, NULL, 0,
        "SRB-TrCH-Mapping/_item", HFILL }},
    { &hf_ranap_sRB_ID,
      { "sRB-ID", "ranap.sRB_ID",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SRB-TrCH-MappingItem/sRB-ID", HFILL }},
    { &hf_ranap_trCH_ID,
      { "trCH-ID", "ranap.trCH_ID",
        FT_NONE, BASE_NONE, NULL, 0,
        "SRB-TrCH-MappingItem/trCH-ID", HFILL }},
    { &hf_ranap_targetRNC_ID,
      { "targetRNC-ID", "ranap.targetRNC_ID",
        FT_NONE, BASE_NONE, NULL, 0,
        "TargetID/targetRNC-ID", HFILL }},
    { &hf_ranap_cGI,
      { "cGI", "ranap.cGI",
        FT_NONE, BASE_NONE, NULL, 0,
        "TargetID/cGI", HFILL }},
    { &hf_ranap_tMSI,
      { "tMSI", "ranap.tMSI",
        FT_BYTES, BASE_HEX, NULL, 0,
        "TemporaryUE-ID/tMSI", HFILL }},
    { &hf_ranap_p_TMSI,
      { "p-TMSI", "ranap.p_TMSI",
        FT_BYTES, BASE_HEX, NULL, 0,
        "TemporaryUE-ID/p-TMSI", HFILL }},
    { &hf_ranap_serviceID,
      { "serviceID", "ranap.serviceID",
        FT_BYTES, BASE_HEX, NULL, 0,
        "TMGI/serviceID", HFILL }},
    { &hf_ranap_traceRecordingSessionReference,
      { "traceRecordingSessionReference", "ranap.traceRecordingSessionReference",
        FT_UINT32, BASE_DEC, NULL, 0,
        "", HFILL }},
    { &hf_ranap_traceDepth,
      { "traceDepth", "ranap.traceDepth",
        FT_UINT32, BASE_DEC, VALS(ranap_TraceDepth_vals), 0,
        "TracePropagationParameters/traceDepth", HFILL }},
    { &hf_ranap_listOfInterfacesToTrace,
      { "listOfInterfacesToTrace", "ranap.listOfInterfacesToTrace",
        FT_UINT32, BASE_DEC, NULL, 0,
        "TracePropagationParameters/listOfInterfacesToTrace", HFILL }},
    { &hf_ranap_dCH_ID,
      { "dCH-ID", "ranap.dCH_ID",
        FT_UINT32, BASE_DEC, NULL, 0,
        "TrCH-ID/dCH-ID", HFILL }},
    { &hf_ranap_dSCH_ID,
      { "dSCH-ID", "ranap.dSCH_ID",
        FT_UINT32, BASE_DEC, NULL, 0,
        "TrCH-ID/dSCH-ID", HFILL }},
    { &hf_ranap_uSCH_ID,
      { "uSCH-ID", "ranap.uSCH_ID",
        FT_UINT32, BASE_DEC, NULL, 0,
        "TrCH-ID/uSCH-ID", HFILL }},
    { &hf_ranap_TrCH_ID_List_item,
      { "Item", "ranap.TrCH_ID_List_item",
        FT_NONE, BASE_NONE, NULL, 0,
        "TrCH-ID-List/_item", HFILL }},
    { &hf_ranap_imsi,
      { "imsi", "ranap.imsi",
        FT_BYTES, BASE_HEX, NULL, 0,
        "UE-ID/imsi", HFILL }},
    { &hf_ranap_imei,
      { "imei", "ranap.imei",
        FT_BYTES, BASE_HEX, NULL, 0,
        "UE-ID/imei", HFILL }},
    { &hf_ranap_imeisv,
      { "imeisv", "ranap.imeisv",
        FT_BYTES, BASE_HEX, NULL, 0,
        "UE-ID/imeisv", HFILL }},
    { &hf_ranap_uESBI_IuA,
      { "uESBI-IuA", "ranap.uESBI_IuA",
        FT_BYTES, BASE_HEX, NULL, 0,
        "UESBI-Iu/uESBI-IuA", HFILL }},
    { &hf_ranap_uESBI_IuB,
      { "uESBI-IuB", "ranap.uESBI_IuB",
        FT_BYTES, BASE_HEX, NULL, 0,
        "UESBI-Iu/uESBI-IuB", HFILL }},
    { &hf_ranap_local,
      { "local", "ranap.local",
        FT_UINT32, BASE_DEC, NULL, 0,
        "PrivateIE-ID/local", HFILL }},
    { &hf_ranap_global,
      { "global", "ranap.global",
        FT_OID, BASE_NONE, NULL, 0,
        "PrivateIE-ID/global", HFILL }},
    { &hf_ranap_ProtocolIE_Container_item,
      { "Item", "ranap.ProtocolIE_Container_item",
        FT_NONE, BASE_NONE, NULL, 0,
        "ProtocolIE-Container/_item", HFILL }},
    { &hf_ranap_id,
      { "id", "ranap.id",
        FT_UINT32, BASE_DEC, VALS(ranap_ProtocolIE_ID_vals), 0,
        "", HFILL }},
    { &hf_ranap_ie_field_value,
      { "value", "ranap.value",
        FT_NONE, BASE_NONE, NULL, 0,
        "ProtocolIE-Field/value", HFILL }},
    { &hf_ranap_ProtocolIE_ContainerPair_item,
      { "Item", "ranap.ProtocolIE_ContainerPair_item",
        FT_NONE, BASE_NONE, NULL, 0,
        "ProtocolIE-ContainerPair/_item", HFILL }},
    { &hf_ranap_firstCriticality,
      { "firstCriticality", "ranap.firstCriticality",
        FT_UINT32, BASE_DEC, VALS(ranap_Criticality_vals), 0,
        "ProtocolIE-FieldPair/firstCriticality", HFILL }},
    { &hf_ranap_firstValue,
      { "firstValue", "ranap.firstValue",
        FT_NONE, BASE_NONE, NULL, 0,
        "ProtocolIE-FieldPair/firstValue", HFILL }},
    { &hf_ranap_secondCriticality,
      { "secondCriticality", "ranap.secondCriticality",
        FT_UINT32, BASE_DEC, VALS(ranap_Criticality_vals), 0,
        "ProtocolIE-FieldPair/secondCriticality", HFILL }},
    { &hf_ranap_secondValue,
      { "secondValue", "ranap.secondValue",
        FT_NONE, BASE_NONE, NULL, 0,
        "ProtocolIE-FieldPair/secondValue", HFILL }},
    { &hf_ranap_ProtocolIE_ContainerList_item,
      { "Item", "ranap.ProtocolIE_ContainerList_item",
        FT_UINT32, BASE_DEC, NULL, 0,
        "ProtocolIE-ContainerList/_item", HFILL }},
    { &hf_ranap_ProtocolIE_ContainerList15_item,
      { "Item", "ranap.ProtocolIE_ContainerList15_item",
        FT_UINT32, BASE_DEC, NULL, 0,
        "ProtocolIE-ContainerList15/_item", HFILL }},
    { &hf_ranap_ProtocolIE_ContainerList256_item,
      { "Item", "ranap.ProtocolIE_ContainerList256_item",
        FT_UINT32, BASE_DEC, NULL, 0,
        "ProtocolIE-ContainerList256/_item", HFILL }},
    { &hf_ranap_ProtocolIE_ContainerList250_item,
      { "Item", "ranap.ProtocolIE_ContainerList250_item",
        FT_UINT32, BASE_DEC, NULL, 0,
        "ProtocolIE-ContainerList250/_item", HFILL }},
    { &hf_ranap_ProtocolIE_ContainerPairList_item,
      { "Item", "ranap.ProtocolIE_ContainerPairList_item",
        FT_UINT32, BASE_DEC, NULL, 0,
        "ProtocolIE-ContainerPairList/_item", HFILL }},
    { &hf_ranap_ProtocolIE_ContainerPairList256_item,
      { "Item", "ranap.ProtocolIE_ContainerPairList256_item",
        FT_UINT32, BASE_DEC, NULL, 0,
        "ProtocolIE-ContainerPairList256/_item", HFILL }},
    { &hf_ranap_ProtocolExtensionContainer_item,
      { "Item", "ranap.ProtocolExtensionContainer_item",
        FT_NONE, BASE_NONE, NULL, 0,
        "ProtocolExtensionContainer/_item", HFILL }},
    { &hf_ranap_ext_id,
      { "id", "ranap.id",
        FT_UINT8, BASE_DEC, VALS(ranap_ProtocolIE_ID_vals), 0,
        "ProtocolExtensionField/id", HFILL }},
    { &hf_ranap_extensionValue,
      { "extensionValue", "ranap.extensionValue",
        FT_NONE, BASE_NONE, NULL, 0,
        "ProtocolExtensionField/extensionValue", HFILL }},
    { &hf_ranap_PrivateIE_Container_item,
      { "Item", "ranap.PrivateIE_Container_item",
        FT_NONE, BASE_NONE, NULL, 0,
        "PrivateIE-Container/_item", HFILL }},
    { &hf_ranap_private_id,
      { "id", "ranap.id",
        FT_UINT32, BASE_DEC, VALS(ranap_PrivateIE_ID_vals), 0,
        "PrivateIE-Field/id", HFILL }},
    { &hf_ranap_private_value,
      { "value", "ranap.value",
        FT_NONE, BASE_NONE, NULL, 0,
        "PrivateIE-Field/value", HFILL }},

/*--- End of included file: packet-ranap-hfarr.c ---*/
#line 1144 "packet-ranap-template.c"
  };

  /* List of subtrees */
  static gint *ett[] = {
	  &ett_ranap,
	  &ett_ranap_plnmidentity,

/*--- Included file: packet-ranap-ettarr.c ---*/
#line 1 "packet-ranap-ettarr.c"
    &ett_ranap_RANAP_PDU,
    &ett_ranap_InitiatingMessage,
    &ett_ranap_SuccessfulOutcome,
    &ett_ranap_UnsuccessfulOutcome,
    &ett_ranap_Outcome,
    &ett_ranap_Dummy_initiating_messages,
    &ett_ranap_Dummy_SuccessfulOutcome_messages,
    &ett_ranap_Dummy_UnsuccessfulOutcome_messages,
    &ett_ranap_Dummy_Outcome_messages,
    &ett_ranap_Dymmy_ie_ids,
    &ett_ranap_Dymmy_firstvalue_ie_ids,
    &ett_ranap_Dymmy_secondvalue_ie_ids,
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
    &ett_ranap_AllocationOrRetentionPriority,
    &ett_ranap_Alt_RAB_Parameters,
    &ett_ranap_Alt_RAB_Parameter_GuaranteedBitrateInf,
    &ett_ranap_Alt_RAB_Parameter_GuaranteedBitrates,
    &ett_ranap_Alt_RAB_Parameter_GuaranteedBitrateList,
    &ett_ranap_Alt_RAB_Parameter_MaxBitrateInf,
    &ett_ranap_Alt_RAB_Parameter_MaxBitrates,
    &ett_ranap_Alt_RAB_Parameter_MaxBitrateList,
    &ett_ranap_AreaIdentity,
    &ett_ranap_Ass_RAB_Parameters,
    &ett_ranap_Ass_RAB_Parameter_GuaranteedBitrateList,
    &ett_ranap_Ass_RAB_Parameter_MaxBitrateList,
    &ett_ranap_AuthorisedPLMNs,
    &ett_ranap_AuthorisedPLMNs_item,
    &ett_ranap_AuthorisedSNAs,
    &ett_ranap_BroadcastAssistanceDataDecipheringKeys,
    &ett_ranap_Cause,
    &ett_ranap_CellLoadInformation,
    &ett_ranap_CellLoadInformationGroup,
    &ett_ranap_CriticalityDiagnostics,
    &ett_ranap_CriticalityDiagnostics_IE_List,
    &ett_ranap_CriticalityDiagnostics_IE_List_item,
    &ett_ranap_MessageStructure,
    &ett_ranap_MessageStructure_item,
    &ett_ranap_CGI,
    &ett_ranap_DeltaRAListofIdleModeUEs,
    &ett_ranap_NewRAListofIdleModeUEs,
    &ett_ranap_RAListwithNoIdleModeUEsAnyMore,
    &ett_ranap_EncryptionInformation,
    &ett_ranap_EquipmentsToBeTraced,
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
    &ett_ranap_MBMSIPMulticastAddressandAPNRequest,
    &ett_ranap_MBMSServiceArea,
    &ett_ranap_MBMSServiceAreaList,
    &ett_ranap_PagingAreaID,
    &ett_ranap_PDP_TypeInformation,
    &ett_ranap_PermanentNAS_UE_ID,
    &ett_ranap_PermittedEncryptionAlgorithms,
    &ett_ranap_PermittedIntegrityProtectionAlgorithms,
    &ett_ranap_PLMNs_in_shared_network,
    &ett_ranap_PLMNs_in_shared_network_item,
    &ett_ranap_PositioningDataSet,
    &ett_ranap_PositionData,
    &ett_ranap_ProvidedData,
    &ett_ranap_RAB_Parameter_GuaranteedBitrateList,
    &ett_ranap_RAB_Parameter_MaxBitrateList,
    &ett_ranap_RAB_Parameters,
    &ett_ranap_RAB_TrCH_Mapping,
    &ett_ranap_RAB_TrCH_MappingItem,
    &ett_ranap_RAI,
    &ett_ranap_RAListofIdleModeUEs,
    &ett_ranap_NotEmptyRAListofIdleModeUEs,
    &ett_ranap_RAofIdleModeUEs,
    &ett_ranap_RequestedMBMSIPMulticastAddressandAPNRequest,
    &ett_ranap_MBMSIPMulticastAddressandAPNlist,
    &ett_ranap_RequestedMulticastServiceList,
    &ett_ranap_Requested_RAB_Parameter_Values,
    &ett_ranap_Requested_RAB_Parameter_MaxBitrateList,
    &ett_ranap_Requested_RAB_Parameter_GuaranteedBitrateList,
    &ett_ranap_RequestType,
    &ett_ranap_ResidualBitErrorRatio,
    &ett_ranap_RIM_Transfer,
    &ett_ranap_RIMRoutingAddress,
    &ett_ranap_RNCTraceInformation,
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
    &ett_ranap_SourceUTRANCellID,
    &ett_ranap_SRB_TrCH_Mapping,
    &ett_ranap_SRB_TrCH_MappingItem,
    &ett_ranap_TargetID,
    &ett_ranap_TargetRNC_ID,
    &ett_ranap_TargetRNC_ToSourceRNC_TransparentContainer,
    &ett_ranap_TemporaryUE_ID,
    &ett_ranap_TMGI,
    &ett_ranap_TracePropagationParameters,
    &ett_ranap_TraceRecordingSessionInformation,
    &ett_ranap_TrCH_ID,
    &ett_ranap_TrCH_ID_List,
    &ett_ranap_UE_ID,
    &ett_ranap_UESBI_Iu,
    &ett_ranap_PrivateIE_ID,
    &ett_ranap_ProtocolIE_Container,
    &ett_ranap_ProtocolIE_Field,
    &ett_ranap_ProtocolIE_ContainerPair,
    &ett_ranap_ProtocolIE_FieldPair,
    &ett_ranap_ProtocolIE_ContainerList,
    &ett_ranap_ProtocolIE_ContainerList15,
    &ett_ranap_ProtocolIE_ContainerList256,
    &ett_ranap_ProtocolIE_ContainerList250,
    &ett_ranap_ProtocolIE_ContainerPairList,
    &ett_ranap_ProtocolIE_ContainerPairList256,
    &ett_ranap_ProtocolExtensionContainer,
    &ett_ranap_ProtocolExtensionField,
    &ett_ranap_PrivateIE_Container,
    &ett_ranap_PrivateIE_Field,

/*--- End of included file: packet-ranap-ettarr.c ---*/
#line 1151 "packet-ranap-template.c"
  };

  /* Register protocol */
  proto_ranap = proto_register_protocol(PNAME, PSNAME, PFNAME); 
/*XXX  register_dissector("ranap", dissect_ranap, proto_ranap);*/
  /* Register fields and subtrees */
  proto_register_field_array(proto_ranap, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));
  register_dissector("ranap", dissect_ranap, proto_ranap);
  nas_pdu_dissector_table = register_dissector_table("ranap.nas_pdu", "RANAP NAS PDU", FT_UINT8, BASE_DEC);


}


