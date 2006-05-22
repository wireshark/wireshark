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

#include "packet-ranap-hf.c"

/* Initialize the subtree pointers */
static int ett_ranap = -1;
static int ett_ranap_plnmidentity = -1;
#include "packet-ranap-ett.c"


/* Global variables */
static proto_tree *top_tree;
static guint type_of_message;
static guint32 ProcedureCode;
static guint32 ProtocolIE_ID;

static int dissect_ranap_ies(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree);
static int dissect_ranap_FirstValue_ies(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree);
static int dissect_ranap_SecondValue_ies(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree);
static int dissect_ranap_messages(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree);
#include "packet-ranap-fn.c"



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

#include "packet-ranap-hfarr.c"
  };

  /* List of subtrees */
  static gint *ett[] = {
	  &ett_ranap,
	  &ett_ranap_plnmidentity,
#include "packet-ranap-ettarr.c"
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


