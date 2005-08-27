/* packet-ranap.c
 * Routines for Radio Access Network Application Part Protocol dissection
 * Based on 3GPP TS 25.413 V3.4.0
 * Copyright 2001, Martin Held <Martin.Held@icn.siemens.de>
 *
 * $Id$
 *
 * Ethereal - Network traffic analyzer
 * By Gerald Combs <gerald@ethereal.com>
 * Copyright 1998 Gerald Combs
 *
 * Copied from README.developer
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
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 */

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <stdio.h>
#include <stdlib.h>


#include <string.h>
#include <glib.h>

#include <epan/packet.h>
#include <epan/emem.h>


#define SCCP_SSN_RANAP 0x8E

/* description of PDU header */
#define PDU_NUMBER_OF_OCTETS_OFFSET 3

/* PDU Index Values */
#define InitiatingMessage 0
#define SuccessfulOutcome 1
#define	UnsuccessfulOutcome 2
#define	Outcome 3

static const value_string   ranap_pdu_index_values[] = {
  {InitiatingMessage, 		"InitiatingMessage"},
  {SuccessfulOutcome, 		"SuccessfulOutcome"},
  {UnsuccessfulOutcome,  	"UnsuccessfulOutcome"},
  {Outcome,  			"Outcome"},
  { 0,				NULL}
};


/* Procedure Code Values */
#define PC_RAB_Assignment 0
#define PC_Iu_Release 1
#define PC_RelocationPreparation 2
#define PC_RelocationResourceAllocation 3
#define PC_RelocationCancel 4
#define PC_SRNS_ContextTransfer 5
#define PC_SecurityModeControl 6
#define PC_DataVolumeReport 7
#define PC_CN_InformationBroadcast 8
#define PC_Reset 9
#define PC_RAB_ReleaseRequest 10
#define PC_Iu_ReleaseRequest 11
#define PC_RelocationDetect 12
#define PC_RelocationComplete 13
#define PC_Paging 14
#define PC_CommonID 15
#define PC_CN_InvokeTrace 16
#define PC_LocationReportingControl 17
#define PC_LocationReport 18
#define PC_InitialUE_Message 19
#define PC_DirectTransfer 20
#define PC_OverloadControl 21
#define PC_ErrorIndication 22
#define PC_SRNS_DataForward 23
#define PC_ForwardSRNS_Context 24
#define PC_privateMessage 25
#define PC_CN_DeactivateTrace 26
#define PC_ResetResource 27
#define PC_RANAP_Relocation 28
#define PC_max 28

static const value_string   ranap_procedure_code_values[] = {
  {PC_RAB_Assignment,			"RAB-Assignment"},
  {PC_Iu_Release,			"IU-Release"},
  {PC_RelocationPreparation, 		"RelocationPreparation"},
  {PC_RelocationResourceAllocation, 	"RelocationResourceAllocation"},
  {PC_RelocationCancel, 		"RelocationCancel"},
  {PC_SRNS_ContextTransfer, 		"SRNS-ContextTransfer"},
  {PC_SecurityModeControl, 		"SecurityModeControl"},
  {PC_DataVolumeReport, 		"DataVolumeReport"},
  {PC_CN_InformationBroadcast, 		"CN-InformationBroadcast"},
  {PC_Reset, 				"Reset"},
  {PC_RAB_ReleaseRequest, 		"RAB-ReleaseRequest"},
  {PC_Iu_ReleaseRequest, 		"Iu-ReleaseRequest"},
  {PC_RelocationDetect, 		"RelocationDetect"},
  {PC_RelocationComplete, 		"RelocationComplete"},
  {PC_Paging,				"Paging"},
  {PC_CommonID, 			"CommonID"},
  {PC_CN_InvokeTrace,			"CN-InvokeTrace"},
  {PC_LocationReportingControl, 	"LocationReportingControl"},
  {PC_LocationReport, 			"LocationReport"},
  {PC_InitialUE_Message, 		"InitialUE_Message"},
  {PC_DirectTransfer,			"DirectTransfer"},
  {PC_OverloadControl, 			"OverloadControl"},
  {PC_ErrorIndication, 			"ErrorIndication"},
  {PC_SRNS_DataForward, 		"SRNS-DataForward"},
  {PC_ForwardSRNS_Context, 		"ForwardSRNS-Context"},
  {PC_privateMessage,			"privateMessage"},
  {PC_CN_DeactivateTrace, 		"CN-DeactivateTrace"},
  {PC_ResetResource, 			"ResetResource"},
  {PC_RANAP_Relocation, 		"RANAP-Relocation"},
  {0,                          		NULL}
};


static const value_string  ranap_message_names[][5] = {
  {/* PC_RAB_Assignment */
     { InitiatingMessage,		"RAB-AssignmentRequest"},
     { SuccessfulOutcome,		"undefined message"},
     { UnsuccessfulOutcome,		"undefined message"},
     { Outcome,				"RAB-AssignmentResponse"},
     { 0,				NULL}, },
  { /* PC_Iu_Release */
     { InitiatingMessage,		"Iu-ReleaseCommand"},
     { SuccessfulOutcome,	  	"Iu-ReleaseComplete"},
     { UnsuccessfulOutcome,	  	NULL},
     { Outcome,			  	NULL},
     { 0,				NULL}, },
  { /* PC_RelocationPreparation */
     { InitiatingMessage,		"RelocationRequired"},
     { SuccessfulOutcome,	  	"RelocationCommand"},
     { UnsuccessfulOutcome,	  	"RelocationPreparationFailure"},
     { Outcome,			  	NULL},
     { 0,				NULL}, },
  { /* PC_RelocationResourceAllocation */
     { InitiatingMessage,		"RelocationRequest"},
     { SuccessfulOutcome,	  	"RelocationRequestAcknowledge"},
     { UnsuccessfulOutcome,	  	"RelocationFailure"},
     { Outcome,			  	NULL},
     { 0,				NULL}, },
  { /* PC_RelocationCancel */
     { InitiatingMessage,		"RelocationCancel"},
     { SuccessfulOutcome,	  	"RelocationCancelAcknowledge"},
     { UnsuccessfulOutcome,	  	NULL},
     { Outcome,			  	NULL},
     { 0,				NULL}, },
  { /* PC_SRNS_ContextTransfer */
     { InitiatingMessage,		"SRNS-ContextRequest"},
     { SuccessfulOutcome,	  	"SRNS-ContextResponse"},
     { UnsuccessfulOutcome,	  	NULL},
     { Outcome,			  	NULL},
     { 0,				NULL}, },
  { /* PC_SecurityModeControl */
     { InitiatingMessage,		"SecurityModeCommand"},
     { SuccessfulOutcome,	  	"SecurityModeComplete"},
     { UnsuccessfulOutcome,	  	"SecurityModeReject"},
     { Outcome,			  	NULL},
     { 0,				NULL}, },
  { /* PC_DataVolumeReport */
     { InitiatingMessage,		"DataVolumeReportRequest"},
     { SuccessfulOutcome,	  	"DataVolumeReport"},
     { UnsuccessfulOutcome,	  	NULL},
     { Outcome,			  	NULL},
     { 0,				NULL}, },
  { /* PC_CN_InformationBroadcast */
     { InitiatingMessage,		"CN-InformationBroadcastRequest"},
     { SuccessfulOutcome,	  	"CN-InformationBroadcastConfirm"},
     { UnsuccessfulOutcome,	  	"CN-InformationBroadcastReject"},
     { Outcome,			  	NULL},
     { 0,				NULL}, },
 { /* PC_Reset */
     { InitiatingMessage,		"Reset"},
     { SuccessfulOutcome,	  	"ResetAcknowledge"},
     { UnsuccessfulOutcome,	  	NULL},
     { Outcome,			  	NULL},
     { 0,				NULL}, },
  { /* PC_RAB_ReleaseRequest */
     { InitiatingMessage,		"RAB-ReleaseRequest"},
     { SuccessfulOutcome,	  	NULL},
     { UnsuccessfulOutcome,	  	NULL},
     { Outcome,			  	NULL},
     { 0,				NULL}, },
  { /* PC_Iu_ReleaseRequest */
     { InitiatingMessage,		"Iu-ReleaseRequest"},
     { SuccessfulOutcome,	  	NULL},
     { UnsuccessfulOutcome,	  	NULL},
     { Outcome,			  	NULL},
     { 0,				NULL}, },
  { /* PC_RelocationDetect */
     { InitiatingMessage,		"RelocationDetect"},
     { SuccessfulOutcome,	  	NULL},
     { UnsuccessfulOutcome,	  	NULL},
     { Outcome,			  	NULL},
     { 0,				NULL}, },
  { /* PC_RelocationComplete */
     { InitiatingMessage,		"RelocationComplete"},
     { SuccessfulOutcome,	  	NULL},
     { UnsuccessfulOutcome,	  	NULL},
     { Outcome,			  	NULL},
     { 0,				NULL}, },
  { /* PC_Paging */
     { InitiatingMessage,		"Paging"},
     { SuccessfulOutcome,	  	NULL},
     { UnsuccessfulOutcome,	  	NULL},
     { Outcome,			  	NULL},
     { 0,				NULL}, },
  { /* PC_CommonID */
     { InitiatingMessage,		"CommonID"},
     { SuccessfulOutcome,	  	NULL},
     { UnsuccessfulOutcome,	  	NULL},
     { Outcome,			  	NULL},
     { 0,				NULL}, },
  { /* PC_CN_InvokeTrace */
     { InitiatingMessage,		"CN-InvokeTrace"},
     { SuccessfulOutcome,	  	NULL},
     { UnsuccessfulOutcome,	  	NULL},
     { Outcome,			  	NULL},
     { 0,				NULL}, },
  {/* PC_LocationReportingControl */
     { InitiatingMessage,		"LocationReportingControl"},
     { SuccessfulOutcome,	  	NULL},
     { UnsuccessfulOutcome,	  	NULL},
     { Outcome,			  	NULL},
     { 0,				NULL}, },
  { /* PC_LocationReport */
     { InitiatingMessage,		"LocationReport"},
     { SuccessfulOutcome,	  	NULL},
     { UnsuccessfulOutcome,	  	NULL},
     { Outcome,			  	NULL},
     { 0,				NULL}, },
  { /* PC_InitialUE_Message */
     { InitiatingMessage,		"InitialUE-Message"},
     { SuccessfulOutcome,	  	NULL},
     { UnsuccessfulOutcome,	  	NULL},
     { Outcome,			  	NULL},
     { 0,				NULL}, },
  { /* PC_DirectTransfer */
     { InitiatingMessage,		"DirectTransfer"},
     { SuccessfulOutcome,	  	NULL},
     { UnsuccessfulOutcome,	  	NULL},
     { Outcome,			  	NULL},
     { 0,				NULL}, },
  { /* PC_OverloadControl */
     { InitiatingMessage,		"Overload"},
     { SuccessfulOutcome,	  	NULL},
     { UnsuccessfulOutcome,	  	NULL},
     { Outcome,			  	NULL},
     { 0,				NULL}, },
  { /* PC_ErrorIndication */
     { InitiatingMessage,		"ErrorIndication"},
     { SuccessfulOutcome,	  	NULL},
     { UnsuccessfulOutcome,	  	NULL},
     { Outcome,			  	NULL},
     { 0,				NULL}, },
  { /* PC_SRNS_DataForward */
     { InitiatingMessage,		"SRNS-DataForwardCommand"},
     { SuccessfulOutcome,	  	NULL},
     { UnsuccessfulOutcome,	  	NULL},
     { Outcome,			  	NULL},
     { 0,				NULL}, },
  { /* PC_ForwardSRNS_Context */
     { InitiatingMessage,		"ForwardSRNS-Context"},
     { SuccessfulOutcome,	  	NULL},
     { UnsuccessfulOutcome,	  	NULL},
     { Outcome,			  	NULL},
     { 0,				NULL}, },
  { /* PC_privateMessage */
     { InitiatingMessage,		"PrivateMessage"},
     { SuccessfulOutcome,	  	NULL},
     { UnsuccessfulOutcome,	  	NULL},
     { Outcome,			  	NULL},
     { 0,				NULL}, },
  { /* PC_CN_DeactivateTrace */
     { InitiatingMessage,		"CN-DeactivateTrace"},
     { SuccessfulOutcome,	  	NULL},
     { UnsuccessfulOutcome,	  	NULL},
     { Outcome,			  	NULL},
     { 0,				NULL}, },
  { /* PC_ResetResource */
     { InitiatingMessage,		"ResetResource"},
     { SuccessfulOutcome,	  	"ResetResourceAcknowledge"},
     { UnsuccessfulOutcome,	  	NULL},
     { Outcome,			  	NULL},
     { 0,				NULL}, },
  { /* PC_RANAP_Relocation */
     { InitiatingMessage,		"RANAP-RelocationInformation"},
     { SuccessfulOutcome,	  	NULL},
     { UnsuccessfulOutcome,	  	NULL},
     { Outcome,			  	NULL},
     { 0,				NULL}, }
};


/* Criticality Values */
#define CR_reject 0
#define CR_ignore 1
#define CR_notify 2

static const value_string   ranap_criticality_values[] = {
  {CR_reject,			"reject"},
  {CR_ignore,			"ignore"},
  {CR_notify,			"notify"},
  {0,                         NULL}};


/* presence values for optional components */
#define PR_not_present 0
#define PR_present 1

static const value_string ranap_presence_values[] = {
   {PR_not_present,		"not present"},
   {PR_present,			"present"},
   {0,                         	NULL}};


/* description of IE Header */
#define IE_ID_LENGTH 2
#define IE_CRITICALITY_LENGTH 1


/* description of IE-ID values */
#define IE_AreaIdentity 0
#define IE_CN_BroadcastInformationPiece 1
#define IE_CN_BroadcastInformationPieceList 2
#define IE_CN_DomainIndicator 3
#define IE_Cause 4
#define IE_ChosenEncryptionAlgorithm 5
#define IE_ChosenIntegrityProtectionAlgorithm 6
#define IE_ClassmarkInformation2 7
#define IE_ClassmarkInformation3 8
#define IE_CriticalityDiagnostics 9
#define IE_DL_GTP_PDU_SequenceNumber 10
#define IE_EncryptionInformation 11
#define IE_IntegrityProtectionInformation 12
#define IE_IuTransportAssociation 13
#define IE_L3_Information 14
#define IE_LAI 15
#define IE_NAS_PDU 16
#define IE_NonSearchingIndication 17
#define IE_NumberOfSteps 18
#define IE_OMC_ID 19
#define IE_OldBSS_ToNewBSS_Information 20
#define IE_PagingAreaID 21
#define IE_PagingCause 22
#define IE_PermanentNAS_UE_ID 23
#define IE_RAB_ContextItem 24
#define IE_RAB_ContextList 25
#define IE_RAB_DataForwardingItem 26
#define IE_RAB_DataForwardingItem_SRNS_CtxReq 27
#define IE_RAB_DataForwardingList 28
#define IE_RAB_DataForwardingList_SRNS_CtxReq 29
#define IE_RAB_DataVolumeReportItem 30
#define IE_RAB_DataVolumeReportList 31
#define IE_RAB_DataVolumeReportRequestItem 32
#define IE_RAB_DataVolumeReportRequestList 33
#define IE_RAB_FailedItem 34
#define IE_RAB_FailedList 35
#define IE_RAB_ID 36
#define IE_RAB_QueuedItem 37
#define IE_RAB_QueuedList 38
#define IE_RAB_ReleaseFailedList 39
#define IE_RAB_ReleaseItem 40
#define IE_RAB_ReleaseList 41
#define IE_RAB_ReleasedItem 42
#define IE_RAB_ReleasedList 43
#define IE_RAB_ReleasedList_IuRelComp 44
#define IE_RAB_RelocationReleaseItem 45
#define IE_RAB_RelocationReleaseList 46
#define IE_RAB_SetupItem_RelocReq 47
#define IE_RAB_SetupItem_RelocReqAck 48
#define IE_RAB_SetupList_RelocReq 49
#define IE_RAB_SetupList_RelocReqAck 50
#define IE_RAB_SetupOrModifiedItem 51
#define IE_RAB_SetupOrModifiedList 52
#define IE_RAB_SetupOrModifyItem 53
#define IE_RAB_SetupOrModifyList 54
#define IE_RAC 55
#define IE_RelocationType 56
#define IE_RequestType 57
#define IE_SAI 58
#define IE_SAPI 59
#define IE_SourceID 60
#define IE_SourceRNC_ToTargetRNC_TransparentContainer 61
#define IE_TargetID 62
#define IE_TargetRNC_ToSourceRNC_TransparentContainer 63
#define IE_TemporaryUE_ID 64
#define IE_TraceReference 65
#define IE_TraceType 66
#define IE_TransportLayerAddress 67
#define IE_TriggerID 68
#define IE_UE_ID 69
#define IE_UL_GTP_PDU_SequenceNumber 70
#define IE_RAB_FailedtoReportItem 71
#define IE_RAB_FailedtoReportList 72
#define IE_KeyStatus 75
#define IE_DRX_CycleLengthCoefficient 76
#define IE_IuSigConIdList 77
#define IE_IuSigConIdItem 78
#define IE_IuSigConId 79
#define IE_DirectTransferInformationItem_RANAP_RelocInf 80
#define IE_DirectTransferInformationList_RANAP_RelocInf 81
#define IE_RAB_ContextItem_RANAP_RelocInf 82
#define IE_RAB_ContextList_RANAP_RelocInf 83
#define IE_RAB_ContextFailedtoTransferItem 84
#define IE_RAB_ContextFailedtoTransferList 85
#define IE_GlobalRNC_ID 86
#define IE_RAB_ReleasedItem_IuRelComp 87

static const value_string   ranap_ie_id_values[] = {
  {IE_AreaIdentity,				"AreaIdentity"},
  {IE_CN_BroadcastInformationPiece,		"CN_BroadcastInformationPiece"},
  {IE_CN_BroadcastInformationPieceList,		"CN_BroadcastInformationPieceList"},
  {IE_CN_DomainIndicator,			"CN_DomainIndicator"},
  {IE_Cause,					"Cause"},
  {IE_ChosenEncryptionAlgorithm,		"ChosenEncryptionAlgorithm"},
  {IE_ChosenIntegrityProtectionAlgorithm,	"ChosenIntegrityProtectionAlgorithm"},
  {IE_ClassmarkInformation2,			"ClassmarkInformation2"},
  {IE_ClassmarkInformation3,			"ClassmarkInformation3"},
  {IE_CriticalityDiagnostics,			"CriticalityDiagnostics"},
  {IE_DL_GTP_PDU_SequenceNumber,		"DL_GTP_PDU_SequenceNumber"},
  {IE_EncryptionInformation,			"EncryptionInformation"},
  {IE_IntegrityProtectionInformation,		"IntegrityProtectionInformation"},
  {IE_IuTransportAssociation,			"IuTransportAssociation"},
  {IE_L3_Information,				"L3_Information"},
  {IE_LAI,					"LAI"},
  {IE_NAS_PDU,					"NAS_PDU"},
  {IE_NonSearchingIndication,			"NonSearchingIndication"},
  {IE_NumberOfSteps,				"NumberOfSteps"},
  {IE_OMC_ID,					"OMC_ID"},
  {IE_OldBSS_ToNewBSS_Information,		"OldBSS_ToNewBSS_Information"},
  {IE_PagingAreaID,				"PagingAreaID"},
  {IE_PagingCause,				"PagingCause"},
  {IE_PermanentNAS_UE_ID,			"PermanentNAS_UE_ID"},
  {IE_RAB_ContextItem,				"RAB_ContextItem"},
  {IE_RAB_ContextList,				"RAB_ContextList"},
  {IE_RAB_DataForwardingItem,			"RAB_DataForwardingItem"},
  {IE_RAB_DataForwardingItem_SRNS_CtxReq,	"RAB_DataForwardingItem_SRNS_CtxReq"},
  {IE_RAB_DataForwardingList,			"RAB_DataForwardingList"},
  {IE_RAB_DataForwardingList_SRNS_CtxReq,	"RAB_DataForwardingList_SRNS_CtxReq"},
  {IE_RAB_DataVolumeReportItem,			"RAB_DataVolumeReportItem"},
  {IE_RAB_DataVolumeReportList,			"RAB_DataVolumeReportList"},
  {IE_RAB_DataVolumeReportRequestItem,		"RAB_DataVolumeReportRequestItem"},
  {IE_RAB_DataVolumeReportRequestList,		"RAB_DataVolumeReportRequestList"},
  {IE_RAB_FailedItem,				"RAB_FailedItem"},
  {IE_RAB_FailedList,				"RAB_FailedList"},
  {IE_RAB_ID,					"RAB_ID"},
  {IE_RAB_QueuedItem,				"RAB_QueuedItem"},
  {IE_RAB_QueuedList,				"RAB_QueuedList"},
  {IE_RAB_ReleaseFailedList,			"RAB_ReleaseFailedList"},
  {IE_RAB_ReleaseItem,				"RAB_ReleaseItem"},
  {IE_RAB_ReleaseList,				"RAB_ReleaseList"},
  {IE_RAB_ReleasedItem,				"RAB_ReleasedItem"},
  {IE_RAB_ReleasedList,				"RAB_ReleasedList"},
  {IE_RAB_ReleasedList_IuRelComp,		"RAB_ReleasedList_IuRelComp"},
  {IE_RAB_RelocationReleaseItem,		"RAB_RelocationReleaseItem"},
  {IE_RAB_RelocationReleaseList,		"RAB_RelocationReleaseList"},
  {IE_RAB_SetupItem_RelocReq,			"RAB_SetupItem_RelocReq"},
  {IE_RAB_SetupItem_RelocReqAck,		"RAB_SetupItem_RelocReqAck"},
  {IE_RAB_SetupList_RelocReq,			"RAB_SetupList_RelocReq"},
  {IE_RAB_SetupList_RelocReqAck,		"RAB_SetupList_RelocReqAck"},
  {IE_RAB_SetupOrModifiedItem,			"RAB_SetupOrModifiedItem"},
  {IE_RAB_SetupOrModifiedList,			"RAB_SetupOrModifiedList"},
  {IE_RAB_SetupOrModifyItem,			"RAB_SetupOrModifyItem"},
  {IE_RAB_SetupOrModifyList,			"RAB_SetupOrModifyList"},
  {IE_RAC,					"RAC"},
  {IE_RelocationType,				"RelocationType"},
  {IE_RequestType,				"RequestType"},
  {IE_SAI,					"SAI"},
  {IE_SAPI,					"SAPI"},
  {IE_SourceID,					"SourceID"},
  {IE_SourceRNC_ToTargetRNC_TransparentContainer,
  						"SourceRNC_ToTargetRNC_TransparentContainer"},
  {IE_TargetID,					"TargetID"},
  {IE_TargetRNC_ToSourceRNC_TransparentContainer,
  						"TargetRNC_ToSourceRNC_TransparentContainer"},
  {IE_TemporaryUE_ID,				"TemporaryUE_ID"},
  {IE_TraceReference,				"TraceReference"},
  {IE_TraceType,				"TraceType"},
  {IE_TransportLayerAddress,			"TransportLayerAddress"},
  {IE_TriggerID,				"TriggerID"},
  {IE_UE_ID,					"UE_ID"},
  {IE_UL_GTP_PDU_SequenceNumber,		"UL_GTP_PDU_SequenceNumber"},
  {IE_RAB_FailedtoReportItem,			"RAB_FailedtoReportItem"},
  {IE_RAB_FailedtoReportList,			"RAB_FailedtoReportList"},
  {IE_KeyStatus,				"KeyStatus"},
  {IE_DRX_CycleLengthCoefficient,		"DRX_CycleLengthCoefficient"},
  {IE_IuSigConIdList,				"IuSigConIdList"},
  {IE_IuSigConIdItem,				"IuSigConIdItem"},
  {IE_IuSigConId,				"IuSigConId"},
  {IE_DirectTransferInformationItem_RANAP_RelocInf,
  						"DirectTransferInformationItem_RANAP_RelocInf"},
  {IE_DirectTransferInformationList_RANAP_RelocInf,
  						"DirectTransferInformationList_RANAP_RelocInf"},
  {IE_RAB_ContextItem_RANAP_RelocInf,		"RAB_ContextItem_RANAP_RelocInf"},
  {IE_RAB_ContextList_RANAP_RelocInf,		"RAB_ContextList_RANAP_RelocInf"},
  {IE_RAB_ContextFailedtoTransferItem,		"RAB_ContextFailedtoTransferItem"},
  {IE_RAB_ContextFailedtoTransferList,		"RAB_ContextFailedtoTransferList"},
  {IE_GlobalRNC_ID,				"GlobalRNC_ID"},
  {IE_RAB_ReleasedItem_IuRelComp,		"RAB_ReleasedItem_IuRelComp"},
  {0,                    		      	NULL}
};


/* Description of IE-Contents */

/* Length of fields within IEs */
#define RAB_ID_LENGTH 1
#define PLMN_ID_LENGTH 3
#define LAC_LENGTH 2
#define IE_PROTOCOL_EXTENSION_LENGTH 1
#define RAC_LENGTH 1
#define SAC_LENGTH 2
#define NUM_RABS_LENGTH 1


/* Traffic Class values */
#define	TC_conversational 0
#define TC_streaming 1
#define TC_interactive 2
#define TC_background 3

static const value_string ranap_trafficClass_values[] = {
  {TC_conversational,		"conversational"},
  {TC_streaming,		"streaming"},
  {TC_interactive,		"interactive"},
  {TC_background,		"background"},
  {0,                         	NULL}};


/* rAB-AsymmetryIndicator values */
#define AI_symmetric_bidirectional 0
#define AI_asymmetric_unidirectional_downlink 1
#define AI_asymmetric_unidirectional_uplink 2
#define AI_asymmetric_bidirectional 3

static const value_string ranap_rAB_AsymmetryIndicator_values[] = {
   {AI_symmetric_bidirectional,			"symmetric-bidirectional"},
   {AI_asymmetric_unidirectional_downlink,	"asymmetric-unidirectional-downlink"},
   {AI_asymmetric_unidirectional_uplink,	"asymmetric-unidirectional-uplink"},
   {AI_asymmetric_bidirectional,		"asymmetric-bidirectional"},
   {0,                         			NULL}};


/* DeliveryOrder values */
#define DO_delivery_order_requested 0
#define DO_delivery_order_not_requested 1

static const value_string ranap_DeliveryOrder_values[] = {
   {DO_delivery_order_requested,		"delivery-order-requested"},
   {DO_delivery_order_not_requested,		"delivery-order-not-requested"},
   {0,                         			NULL}};

#define maxSDU_Size_LENGTH 2

/* deliveryOfErroneousSDU values */
#define DOES_yes 0
#define DOES_no 1
#define DOES_no_error_detection_consideration 2

static const value_string ranap_deliveryOfErroneousSDU_values[] = {
   {DOES_yes,					"yes"},
   {DOES_no,					"no"},
   {DOES_no_error_detection_consideration,	"no-error-detection-consideration"},
   {0,                         			NULL}};


#define subflowSDU_Size_LENGTH 2
#define transferDelay_LENGTH 2


/* trafficHandlingPriority values */
static const value_string ranap_priority_values[] = {
   {  0,	"spare"},
   {  1,	"highest"},
   {  2,	""},
   {  3,	""},
   {  4,	""},
   {  5,	""},
   {  6,	""},
   {  7,	""},
   {  8,	""},
   {  9,	""},
   { 10,	""},
   { 11,	""},
   { 12,	""},
   { 13,	""},
   { 14,	"lowest"},
   { 15,	"no-priority-used"},
   {  0,	NULL}};


/* pre-emptionCapability values */
static const value_string ranap_pre_emptionCapability_values[] = {
   {  0,	"shall-not-trigger-pre-emption"},
   {  1,	"may-trigger-pre-emption"},
   {  0,	NULL}};

/* pre-emptionVulnerability values */
static const value_string ranap_pre_emptionVulnerability_values[] = {
   {  0,	"not-pre-emptable"},
   {  1,	"pre-emptable"},
   {  0,	NULL}};


/* queuingAllowed values	 */
static const value_string ranap_queuingAllowed_values[] = {
   {  0,	"queueing-not-allowed"},
   {  1,	"queueing-allowed"},
   {  0,	NULL}};


/* sourceStatisticsDescriptor values */
static const value_string ranap_sourceStatisticsDescriptor_values[] = {
   {  0,	"speech"},
   {  1,	"unknown"},
   {  0,	NULL}};

/* relocationRequirement values */
static const value_string ranap_relocationRequirement_values[] = {
   {  0,	"lossless"},
   {  1,	"none"},
   {  0,	NULL}};

/* userPlaneMode values */
static const value_string ranap_userPlaneMode_values[] = {
   {  0,	"transparent-mode"},
   {  1,	"support-mode-for-predefined-SDU-sizes"},
   {  0,	NULL}};

/* PDP_Type values */
static const value_string ranap_PDP_Type_values[] = {
   {  0,	"empty"},
   {  1,	"ppp"},
   {  2,	"osp-ihoss"},
   {  3,	"ipv4"},
   {  4,	"ipv6"},
   {  0,	NULL}};

/* dataVolumeReportingIndication values */
static const value_string ranap_dataVolumeReportingIndication_values[] = {
   {  0,	"do-report"},
   {  1,	"do-not-report"},
   {  0,	NULL}};


/* cause_choice values */
#define CC_CauseRadioNetwork		0
#define CC_CauseTransmissionNetwork	1
#define CC_CauseNAS			2
#define CC_CauseProtocol		3
#define CC_CauseMisc			4
#define CC_CauseNon_Standard		5

static const value_string ranap_cause_choice_values[] = {
   {  CC_CauseRadioNetwork,		"CauseRadioNetwork"},
   {  CC_CauseTransmissionNetwork,	"CauseTransmissionNetwork"},
   {  CC_CauseNAS,			"CauseNAS"},
   {  CC_CauseProtocol,			"CauseProtocol"},
   {  CC_CauseMisc,			"CauseMisc"},
   {  CC_CauseNon_Standard,		"CauseNon-Standard"},
   {  0,				NULL}};


/* cause values */
static const value_string ranap_cause_value_str[] = {
/* CauseRadioNetwork (1..64) */
   {  1,	"rab-pre-empted"},
   {  2,	"trelocoverall-expiry"},
   {  3,	"trelocprep-expiry"},
   {  4,	"treloccomplete-expiry"},
   {  5,	"tqueing-expiry"},
   {  6,	"relocation-triggered"},
   {  7,	"trellocalloc-expiry"},
   {  8,	"unable-to-establish-during-relocation"},
   {  9,	"unknown-target-rnc"},
   { 10,	"relocation-cancelled"},
   { 11,	"successful-relocation"},
   { 12,	"requested-ciphering-and-or-integrity-protection-algorithms-not-supported"},
   { 13,	"change-of-ciphering-and-or-integrity-protection-is-not-supported"},
   { 14,	"failure-in-the-radio-interface-procedure"},
   { 15,	"release-due-to-utran-generated-reason"},
   { 16,	"user-inactivity"},
   { 17,	"time-critical-relocation"},
   { 18,	"requested-traffic-class-not-available"},
   { 19,	"invalid-rab-parameters-value"},
   { 20,	"requested-maximum-bit-rate-not-available"},
   { 21,	"requested-guaranteed-bit-rate-not-available"},
   { 22,	"requested-transfer-delay-not-achievable"},
   { 23,	"invalid-rab-parameters-combination"},
   { 24,	"condition-violation-for-sdu-parameters"},
   { 25,	"condition-violation-for-traffic-handling-priority"},
   { 26,	"condition-violation-for-guaranteed-bit-rate"},
   { 27,	"user-plane-versions-not-supported"},
   { 28,	"iu-up-failure"},
   { 29,	"relocation-failure-in-target-CN-RNC-or-target-system"},
   { 30,	"invalid-RAB-ID"},
   { 31,	"no-remaining-rab"},
   { 32,	"interaction-with-other-procedure"},
   { 33,	"requested-maximum-bit-rate-for-dl-not-available"},
   { 34,	"requested-maximum-bit-rate-for-ul-not-available"},
   { 35,	"requested-guaranteed-bit-rate-for-dl-not-available"},
   { 36,	"requested-guaranteed-bit-rate-for-ul-not-available"},
   { 37,	"repeated-integrity-checking-failure"},
   { 38,	"requested-report-type-not-supported"},
   { 39,	"request-superseded"},
   { 40, 	"release-due-to-UE-generated-signalling-connection-release"},
   { 41,	"resource-optimisation-relocation"},
   { 42,	"requested-information-not-available"},
   { 43,	"relocation-desirable-for-radio-reasons"},
   { 44,	"relocation-not-supported-in-target-RNC-or-target-system"},
   { 45,	"directed-retry"},
   { 46,        "radio-connection-with-UE-Lost"},

/* CauseTransmissionNetwork (65..80) */
   { 65,	"logical-error-unknown-iu-transport-association"},
   { 66,        "iu-transport-connection-failed-to-establish"},

/* CauseNAS (81..96) */
   { 81,	"user-restriction-start-indication"},
   { 82,	"user-restriction-end-indication"},
   { 83,	"normal-release"},

/* CauseProtocol (97..112) */
   { 97,	"transfer-syntax-error"},
   { 98,	"semantic-error"},
   { 99,	"message-not-compatible-with-receiver-state"},
   {100,	"abstract-syntax-error-reject"},
   {101,	"abstract-syntax-error-ignore-and-notify"},
   {102,	"abstract-syntax-error-falsely-constructed-message"},

/* CauseMisc (113..128) */
   {113,	"om-intervention"},
   {114,	"no-resource-available"},
   {115,	"unspecified-failure"},
   {116,	"network-optimisation"},
   {  0,	NULL}};


/* CN_DomainIndicator_values */
static const value_string ranap_CN_DomainIndicator_values[] = {
   {  0,	"cs-domain"},
   {  1,	"ps-domain"},
   {  0,	NULL}};


/* SAPI_values */
static const value_string ranap_SAPI_values[] = {
   {  0,	"sapi-0"},
   {  1,	"sapi-3"},
   {  0,	NULL}};

/* service_Handover_values */
static const value_string ranap_service_Handover_values[] = {
   {  0,	"handover-to-GSM-should-be-performed"},
   {  1,	"handover-to-GSM-should-not-be-performed"},
   {  2,	"handover-to-GSM-shall-not-be-performed"},
   {  0,	NULL}};

/* Initialize the protocol and registered fields */
/* protocol */
static int proto_ranap = -1;

static dissector_table_t nas_pdu_dissector_table;

packet_info *g_pinfo = NULL;
proto_tree *g_tree = NULL;

/* pdu header fields */
static int hf_ranap_pdu_number_of_octets = -1;
static int hf_ranap_pdu_index = -1;
static int hf_ranap_procedure_code = -1;
static int hf_ranap_pdu_criticality = -1;
static int hf_ranap_number_of_ies = -1;

/* ie header fields */
static int hf_ranap_ie_ie_id = -1;
static int hf_ranap_ie_criticality = -1;
static int hf_ranap_ie_number_of_octets = -1;
static int hf_ranap_ie_protocol_extension = -1;

/*ie contents fields */
static int hf_ranap_number_of_ies_in_list = -1;
static int hf_ranap_ie_pair_first_criticality = -1;
static int hf_ranap_ie_pair_second_criticality = -1;
static int hf_ranap_first_value_number_of_octets = -1;
static int hf_ranap_second_value_number_of_octets = -1;
static int hf_ranap_rab_id = -1;
static int hf_ranap_nas_pdu = -1;
static int hf_ranap_plmn_id = -1;
static int hf_ranap_lac = -1;
static int hf_ranap_sac = -1;
static int hf_ranap_rac = -1;
static int hf_ranap_nAS_SynchronisationIndicator = -1;
static int hf_ranap_trafficClass = -1;
static int hf_ranap_deliveryOrder = -1;
static int hf_ranap_iE_Extensions_present = -1;
static int hf_ranap_num_rabs = -1;
static int hf_ranap_nAS_SynchronisationIndicator_present = -1;
static int hf_ranap_rAB_Parameters_present = -1;
static int hf_ranap_userPlaneInformation_present = -1;
static int hf_ranap_transportLayerInformation_present = -1;
static int hf_ranap_service_Handover_present = -1;
static int hf_ranap_guaranteedBitRate_present = -1;
static int hf_ranap_transferDelay_present = -1;
static int hf_ranap_trafficHandlingPriority_present = -1;
static int hf_ranap_allocationOrRetentionPriority_present = -1;
static int hf_ranap_sourceStatisticsDescriptor_present = -1;
static int hf_ranap_relocationRequirement_present = -1;
static int hf_ranap_rAB_AsymmetryIndicator = -1;
static int hf_ranap_maxBitrate = -1;
static int hf_ranap_guaranteedBitrate = -1;
static int hf_ranap_maxSDU_Size = -1;
static int hf_ranap_sDU_ErrorRatio_mantissa = -1;
static int hf_ranap_sDU_ErrorRatio_exponent = -1;
static int hf_ranap_residualBitErrorRatio_mantissa = -1;
static int hf_ranap_residualBitErrorRatio_exponent = -1;
static int hf_ranap_deliveryOfErroneousSDU = -1;
static int hf_ranap_subflowSDU_Size = -1;
static int hf_ranap_rAB_SubflowCombinationBitRate = -1;
static int hf_ranap_sDU_ErrorRatio_present = -1;
static int hf_ranap_sDU_FormatInformationParameters_present = -1;
static int hf_ranap_subflowSDU_Size_present = -1;
static int hf_ranap_rAB_SubflowCombinationBitRate_present = -1;
static int hf_ranap_transferDelay = -1;
static int hf_ranap_trafficHandlingPriority = -1;
static int hf_ranap_priorityLevel = -1;
static int hf_ranap_pre_emptionCapability = -1;
static int hf_ranap_pre_emptionVulnerability = -1;
static int hf_ranap_queuingAllowed = -1;
static int hf_ranap_sourceStatisticsDescriptor = -1;
static int hf_ranap_userPlaneMode = -1;
static int hf_ranap_uP_ModeVersions = -1;
static int hf_ranap_number_of_ProtocolExtensionFields = -1;
static int hf_ranap_ext_field_id = -1;
static int hf_ranap_ext_field_criticality = -1;
static int hf_ranap_ext_field_number_of_octets = -1;
static int hf_ranap_transportLayerAddress = -1;
static int hf_ranap_transportLayerAddress_length = -1;
static int hf_ranap_gTP_TEI = -1;
static int hf_ranap_bindingID = -1;
static int hf_ranap_pDP_TypeInformation_present = -1;
static int hf_ranap_dataVolumeReportingIndication_present = -1;
static int hf_ranap_dl_GTP_PDU_SequenceNumber_present = -1;
static int hf_ranap_ul_GTP_PDU_SequenceNumber_present = -1;
static int hf_ranap_dl_N_PDU_SequenceNumber_present = -1;
static int hf_ranap_ul_N_PDU_SequenceNumber_present = -1;
static int hf_ranap_PDP_Type = -1;
static int hf_ranap_dataVolumeReportingIndication = -1;
static int hf_ranap_dl_GTP_PDU_SequenceNumber = -1;
static int hf_ranap_ul_GTP_PDU_SequenceNumber = -1;
static int hf_ranap_dl_N_PDU_SequenceNumber = -1;
static int hf_ranap_ul_N_PDU_SequenceNumber = -1;
static int hf_ranap_cause_choice = -1;
static int hf_ranap_cause_value = -1;
static int hf_ranap_transportLayerAddress_present = -1;
static int hf_ranap_iuTransportAssociation_present = -1;
static int hf_ranap_dl_dataVolumes_present = -1;
static int hf_ranap_dataVolumeReference_present = -1;
static int hf_ranap_dl_UnsuccessfullyTransmittedDataVolume = -1;
static int hf_ranap_dataVolumeReference = -1;
static int hf_ranap_procedureCode_present = -1;
static int hf_ranap_triggeringMessage_present = -1;
static int hf_ranap_procedureCriticality_present = -1;
static int hf_ranap_iEsCriticalityDiagnostics_present = -1;
static int hf_ranap_triggeringMessage = -1;
static int hf_ranap_iECriticality = -1;
static int hf_ranap_procedureCriticality = -1;
static int hf_ranap_repetitionNumber = -1;
static int hf_ranap_num_of_CriticalityDiagnostics_IEs = -1;
static int hf_ranap_repetitionNumber_present = -1;
static int hf_ranap_dl_UnsuccessfullyTransmittedDataVolume_present = -1;
static int hf_ranap_CN_DomainIndicator = -1;
static int hf_ranap_IuSigConId = -1;
static int hf_ranap_SAPI = -1;
static int hf_ranap_msg_extension_present = -1;
static int hf_ranap_ProtocolExtensionContainer_present = -1;
static int hf_ranap_nas_pdu_length = -1;
static int hf_ranap_relocationRequirement = -1;
static int hf_ranap_service_Handover = -1;
static int hf_ranap_extension_field = -1;
static int hf_ranap_RNC_ID = -1;


/* subtrees */
static gint ett_ranap = -1;
static gint ett_ranap_optionals = -1;
static gint ett_ranap_iE_Extension = -1;
static gint ett_ranap_ie = -1;
static gint ett_ranap_ie_pair = -1;
static gint ett_ranap_rab = -1;
static gint ett_ranap_ie_pair_first_value = -1;
static gint ett_ranap_ie_pair_second_value = -1;
static gint ett_ranap_rAB_Parameters = -1;
static gint ett_ranap_sDU = -1;
static gint ett_ranap_allocationOrRetentionPriority = -1;
static gint ett_ranap_CriticalityDiagnostics_IE = -1;



/*****************************************************************************/
/*                                                                           */
/*  Utility Functions                                                        */
/*                                                                           */
/*****************************************************************************/

/* sets *offset and *bitoffset n bits further */
static void
proceed_nbits(gint *offset, gint *bitoffset, gint n)
{
   *bitoffset += n;
   *offset += *bitoffset / 8;
   *bitoffset %= 8;
}

/* sets *offset and *bitoffset to the next byte boundary */
static void allign(gint *offset, gint *bitoffset)
{
  if ( *bitoffset != 0 )
  {
     (*offset)++;
     *bitoffset=0;
  }
}

/* sets *offset and *bitoffset behind the following integer */
static void
proceed_perint32(gint *offset, gint *bitoffset, gint length)
{
   proceed_nbits(offset, bitoffset, 2);
   allign(offset, bitoffset);
   *offset += length;
}


/* extract length field found at offset */
/* if length field spans more than two bytes -1 is returned and the field is not decoded */
static guint8
extract_length(tvbuff_t *tvb, gint offset, gint *length, gint *length_size)
{
   guint8	tmp_length8;
   guint16	tmp_length16;

   tmp_length8 = tvb_get_guint8(tvb, offset);
   if ((tmp_length8 & 0x80) == 0)
   {
   	/* length coded in one byte */
   	*length = tmp_length8;
   	*length_size = 1;
    }
    else
    {
    	tmp_length16 = tvb_get_ntohs(tvb, offset);
    	if ( ((tmp_length16 & 0x8000) == 0x8000) &&  ((tmp_length16 & 0x4000) == 0) )
        {
    	    /* length coded in two bytes */
    	    *length = tmp_length16 & 0x3FFF;
       	    *length_size = 2;
        }
        else
        {   /* length is coded in more than 2 bytes */
           return (-1);
        }
    }
    return(0);
}

/* extract the next n bits and return them alligned to the LSB */
static guint8
extract_nbits(tvbuff_t *tvb, gint offset, gint bitoffset, gint n)
{
   guint8	uint_bits;
   guint16	tmp_2bytes;

   /* extract value */
   if (bitoffset + n <= 8)
   {
      /* all bits contained in one byte */
      uint_bits = tvb_get_guint8(tvb, offset);
      uint_bits <<= bitoffset; 				/* remove bitoffset */
      uint_bits >>= 8-n;				/* allign to LSB */
   }
   else
   {
      /* bits contained within 2 bytes */
      tmp_2bytes = tvb_get_ntohs(tvb, offset);
      tmp_2bytes <<=  bitoffset;			/* remove bitoffset */
      uint_bits = tmp_2bytes >> ( 8 + (8-n));		/* allign to LSB */
   }

   return(uint_bits);
}


/* extract an integer with 2bit length field and return the int value*/
static guint32
extract_int32(tvbuff_t *tvb, gint offset, gint bitoffset, gint *length)
{
   guint16	tmp_2byte;
   guint32	result = 0;

   tmp_2byte = tvb_get_ntohs(tvb, offset);

   tmp_2byte <<= bitoffset;		/* remove bitoffset */
   *length = tmp_2byte >> (6 + 8);	/* allign 2bit length field to LSB */
   (*length)++;				/* now we have the length of the int value */

   proceed_nbits(&offset, &bitoffset, 2);
   allign(&offset, &bitoffset);

   switch (*length)
   {
      case 1:
         result = tvb_get_guint8(tvb, offset);
         break;
      case 2:
         result = tvb_get_ntohs(tvb, offset);
         break;
      case 3:
         result = tvb_get_ntoh24(tvb, offset);
         break;
      case 4:
         result = tvb_get_ntohl(tvb, offset);
         break;
    }

    return(result);
}


/* return bitmask string looking like "..01 0..."  */
static char *
bitmaskstr(guint bitoffset, guint bitlength, guint16 value, guint *length)
{
   static char		maskstr[20];
   guint		i;


   strcpy(maskstr, "                   ");

   for (i=0; i<16; i++)
   {
      if ( i < bitoffset  ||  i > bitoffset+bitlength-1 )
      {
      	 /* i is outside extracted bitfield */
      	 maskstr[i + i/4] = '.';
      }
      else
      {  /* i is inside extracted bitfield */
         if ( ((0x8000 >> i) & value) != 0x0000 )
         {
            /* bit is set */
            maskstr[i + i/4] = '1';
         }
         else
         {
            /* bit is not set */
            maskstr[i + i/4] = '0';
         }
      }
   }
   if (bitoffset + bitlength <= 8)
   {
      /* bitfield is located within first byte only */
      maskstr[9] = '\0';
      *length = 1;
   }
   else
   {
      /* bitfield is located within first & second byte */
      maskstr[19] = '\0';
      *length = 2;
   }

   return(maskstr);
}

/* add bitstring */
static proto_item *
proto_tree_add_bitstring(proto_tree *tree, int hfindex, tvbuff_t *tvb, gint offset,
                         gint bitoffset, gint bitlength)
{
   guint16		read_2bytes;
   guint16		alligned_2bytes;
   guint8		one_byte;
   char			*maskstr;
   char			*maskstr_buf;
   guint		length;
   int			i;
   guint8		bitstr[128];
   char			*buf;
   header_field_info	*hf_info_p;
   gint			byte_span;
   gint			initial_offset = offset;

   memset(bitstr, 0, 128);

   maskstr_buf=ep_alloc(56);
   maskstr_buf[0]=0;

   buf=ep_alloc(256);
   buf[0]=0;

   /* create bitmask string for first byte */
   read_2bytes = tvb_get_ntohs(tvb, offset);
   maskstr = bitmaskstr(bitoffset, (bitoffset+bitlength >8) ? 8-bitoffset : bitlength, read_2bytes, &length);
   if (bitoffset+bitlength > 8)
   {
      g_snprintf(maskstr_buf, 56, "%s + %d Bits = ", maskstr, bitlength - (8-bitoffset));
   }
   else
   {
      g_snprintf(maskstr_buf, 56, "%s = ", maskstr);
   }


   /* print all but the last byte to buf */
   byte_span = (bitoffset + bitlength + 7) / 8;
   for (i=0; i < byte_span - 1; i++, offset++)
   {
      read_2bytes = tvb_get_ntohs(tvb, offset);
      alligned_2bytes = read_2bytes << bitoffset;	/* remove bitoffset */
      one_byte = alligned_2bytes >> 8;			/* move to low byte */

      bitstr[i]=one_byte;
      g_snprintf(buf+2*i, 256-2*i, "%02X", one_byte);
   }

   /* add last byte if it contains bits which have not yet been shifted in */
   if ( ((bitlength + 7) / 8 ) == byte_span )
   {
      read_2bytes = tvb_get_ntohs(tvb, offset);
      alligned_2bytes = read_2bytes << bitoffset;	/* remove bitoffset */
      one_byte = alligned_2bytes >> 8;			/* move to low byte */
      one_byte >>= (8 - (bitlength%8));			/*cut off surplus bits */
      one_byte <<= (8 - (bitlength%8));			/* allign to MSB in low byte*/

      bitstr[i]=one_byte;
      g_snprintf(buf+2*i, 256-2*i, "%02X", one_byte);
   }

   /* get header field info */
   hf_info_p = proto_registrar_get_nth(hfindex);


  return ( proto_tree_add_bytes_format(tree, hfindex, tvb, initial_offset,
	   byte_span , bitstr, "%s %s: %s", maskstr_buf, hf_info_p->name, buf) );

}


/* add unsigned int, 1-8 bits long */
static proto_item *
proto_tree_add_uint_bits(proto_tree *tree, int hfindex, tvbuff_t *tvb, gint offset,
                         gint bitoffset, gint bitlength, gint min)
{
   guint8		uint_bits;
   guint16		read_2bytes, alligned_2bytes;
   char			*maskstr;
   guint		length;
   header_field_info	*hf_info_p;


   /* extract value */
   if (bitoffset + bitlength <= 8)
   {
      /* all bits contained in one byte */
      uint_bits = tvb_get_guint8(tvb, offset);
      read_2bytes = uint_bits;
      read_2bytes <<= 8;
   }
   else
   {
      /* bits contained within 2 bytes */
      read_2bytes = tvb_get_ntohs(tvb, offset);
   }
   alligned_2bytes = read_2bytes << bitoffset;			/* remove bitoffset */
   uint_bits = alligned_2bytes >> ( 8 + (8-bitlength));		/* allign to LSB */

   uint_bits += min;

   /* create bitmask string */
   maskstr = bitmaskstr(bitoffset, bitlength, read_2bytes, &length);

   /* get header field info */
   hf_info_p = proto_registrar_get_nth(hfindex);

   if (hf_info_p->strings != NULL)
   {
      /* string representation for decoded header field present */
      return ( proto_tree_add_uint_format(tree, hfindex, tvb, offset,
	      length, uint_bits, "%s = %s: %s (%d)", maskstr, hf_info_p->name,
	      val_to_str(uint_bits, hf_info_p->strings, "%d"), uint_bits) );
   }
   else
   {
      /* no string representation */
      return ( proto_tree_add_uint_format(tree, hfindex, tvb, offset,
	      length, uint_bits, "%s = %s: %d", maskstr, hf_info_p->name, uint_bits) );
   }
}

/* add PER encoded integer (maximum length of value: 4 bytes) */
static proto_item *
proto_tree_add_PERint32(proto_tree *tree, int hfindex, tvbuff_t *tvb, gint offset,
                         gint bitoffset, gint *length, gint min)
{
    guint32		value;
    guint16		tmp_2bytes;
    char		*maskstr;
    guint		length_size;
    header_field_info	*hf_info_p;

    /* get value */
    value = extract_int32(tvb, offset, bitoffset, length);
    value += min;

    /* create bitmask string for 2 bit length field */
    tmp_2bytes = tvb_get_ntohs(tvb, offset);
    maskstr = bitmaskstr(bitoffset, 2, tmp_2bytes, &length_size);

    /* get header field info */
    hf_info_p = proto_registrar_get_nth(hfindex);

    return ( proto_tree_add_uint_format(tree, hfindex, tvb, offset,
	     (*length) + length_size, value,
	     "%s + %d Bytes = %s: %d", maskstr, *length, hf_info_p->name, value) );
}



/*****************************************************************************/
/*                                                                           */
/*  Dissecting Functions for single parameters                               */
/*                                                                           */
/*****************************************************************************/
static int
dissect_iE_Extension(tvbuff_t *tvb, proto_tree *tree, gint *offset, gint *bitoffset, const char *description)
{
  proto_item	*ext_item = NULL;
  proto_tree	*ext_tree = NULL;
  guint16	number_of_extFields;
  gint		number_of_octets = 0;
  gint		number_of_octets_size = 0;
  int		i;

  allign(offset, bitoffset);

  /* create subtree for iE_Extension */
  if (tree)
  {
     ext_item = proto_tree_add_text(tree, tvb, *offset, 0, "%s iE-Extensions", description);
     ext_tree = proto_item_add_subtree(ext_item, ett_ranap_iE_Extension);
  }

  /* number of extension fields */
  number_of_extFields = tvb_get_ntohs(tvb, *offset) + 1;
  if (ext_tree)
  {
     proto_tree_add_uint(ext_tree, hf_ranap_number_of_ProtocolExtensionFields,
	           	         tvb, *offset, 2, number_of_extFields);
  }

  *offset += 2;

  /*  for each extension field */
  for (i=1; i <= number_of_extFields; i++)
  {
     /* add fields to ie subtee */
     /* Extension Field ID */
     if (ext_tree)
     {
        proto_tree_add_item(ext_tree, hf_ranap_ext_field_id, tvb,
                            *offset, IE_ID_LENGTH, FALSE);
     }
     *offset += IE_ID_LENGTH;

     /* criticality */
     if (ext_tree)
     {
        proto_tree_add_uint_bits(ext_tree, hf_ranap_ext_field_criticality, tvb,
                                 *offset, *bitoffset, 2, 0);
     }
     proceed_nbits(offset, bitoffset, 2);

     /* number of octets in the IE */
     allign(offset, bitoffset);
     if (0 == extract_length(tvb, *offset, &number_of_octets, &number_of_octets_size))
     {
       if (ext_tree)
       {
          proto_tree_add_uint(ext_tree, hf_ranap_ext_field_number_of_octets, tvb,
                              *offset, number_of_octets_size, number_of_octets);
       }
     }
     else
     {
       /* decoding is not supported */
       if (ext_tree)
       {
          proto_tree_add_text(ext_tree, tvb, *offset, 0,
                              "Number of Octets greater than 0x3FFF, dissection not supported");
       }
       return(-1);
     }

     *offset += number_of_octets_size;
     if (ext_tree)
     {
     	proto_tree_add_item(ext_tree, hf_ranap_extension_field, tvb,
                            *offset, number_of_octets, FALSE);

     }

     *offset +=  number_of_octets;
  }

  return(0);
}


static int
dissect_userPlaneInformation(tvbuff_t *tvb, proto_tree *tree, gint *offset, gint *bitoffset)
{
   int		extension_present;
   int		iE_Extensions_present;
   int		tmp_extension_present;

   /* protocol_extension present ? */
   extension_present = extract_nbits(tvb, *offset, *bitoffset, 1);
   proceed_nbits(offset, bitoffset, 1);

   /* iE_Extensions present ? */
   iE_Extensions_present = extract_nbits(tvb, *offset, *bitoffset, 1);
   proceed_nbits(offset, bitoffset, 1);

   /* userPlaneMode */
   tmp_extension_present = extract_nbits(tvb, *offset, *bitoffset, 1);
   proceed_nbits(offset, bitoffset, 1);

   proto_tree_add_uint_bits(tree, hf_ranap_userPlaneMode, tvb, *offset,
                            *bitoffset, 1, 0);
   proceed_nbits(offset, bitoffset, 1);

   /* uP-ModeVersions */
   proto_tree_add_bitstring(tree, hf_ranap_uP_ModeVersions, tvb, *offset,
                            *bitoffset, 16);
   proceed_nbits(offset, bitoffset, 16);

   /* iE-Extensions */
   if (iE_Extensions_present)
   {
      return(dissect_iE_Extension(tvb, tree, offset, bitoffset, "UserPlaneInformation"));
   }
   return(0);
}



static int
dissect_sDU_Parameters(tvbuff_t *tvb, proto_tree *ie_tree, gint *offset, gint *bitoffset)
{
   proto_item	*sDU_item = NULL;
   proto_tree	*sDU_tree = NULL;
   proto_item	*optionals_item = NULL;
   proto_tree	*optionals_tree = NULL;
   int		ret;
   int		extension_present;
   int		sDU_ErrorRatio_present;
   int		sDU_FormatInformationParameters_present;
   int 		iE_Extensions_present;
   int		sDU_ErrorRatio_iE_Extensions_present;
   int		residualBitErrorRatio_iE_Extensions_present;
   gint		length;
   gint		number_of_sDU_FormatInformationParameters;
   int		sDU_FormatInformationParameters_extension_present;
   int		subflowSDU_Size_present;
   int		rAB_SubflowCombinationBitRate_present;
   int		sDU_FormatInformationParameters_iE_Extensions_present;
   gint		i;

   /* create subtree for sDU_Parameters */
   sDU_item = proto_tree_add_text(ie_tree, tvb, *offset, 0,
                                      "sDU Parameters");
   sDU_tree = proto_item_add_subtree(sDU_item, ett_ranap_sDU);

   /* create subtree for extension/optional/default bitmap */
   optionals_item = proto_tree_add_text(sDU_tree, tvb, *offset, 1,
                                      "sDU_Parameters Extension/Optional/Default bitmap");
   optionals_tree = proto_item_add_subtree(optionals_item, ett_ranap_optionals);

   /* protocol_extension present ? */
   extension_present = extract_nbits(tvb, *offset, *bitoffset, 1);
   proto_tree_add_uint_bits(optionals_tree, hf_ranap_ie_protocol_extension, tvb,
                            *offset, *bitoffset, 1, 0);
   proceed_nbits(offset, bitoffset, 1);

   /*  sDU_ErrorRatio present ? */
   sDU_ErrorRatio_present = extract_nbits(tvb, *offset, *bitoffset, 1);
   proto_tree_add_uint_bits(optionals_tree, hf_ranap_sDU_ErrorRatio_present, tvb,
                            *offset, *bitoffset, 1, 0);
   proceed_nbits(offset, bitoffset, 1);

   /*  sDU_FormatInformationParameters present ? */
   sDU_FormatInformationParameters_present = extract_nbits(tvb, *offset, *bitoffset, 1);
   proto_tree_add_uint_bits(optionals_tree, hf_ranap_sDU_FormatInformationParameters_present, tvb,
                            *offset, *bitoffset, 1, 0);
   proceed_nbits(offset, bitoffset, 1);

   /* iE_Extensions present ? */
   iE_Extensions_present = extract_nbits(tvb, *offset, *bitoffset, 1);
   proto_tree_add_uint_bits(optionals_tree, hf_ranap_iE_Extensions_present, tvb,
                            *offset, *bitoffset, 1, 0);
   proceed_nbits(offset, bitoffset, 1);


   /* sDU_ErrorRatio */
   if (sDU_ErrorRatio_present)
   {
      sDU_ErrorRatio_iE_Extensions_present = extract_nbits(tvb, *offset, *bitoffset, 1);
      proceed_nbits(offset, bitoffset, 1);

      proto_tree_add_uint_bits(sDU_tree, hf_ranap_sDU_ErrorRatio_mantissa, tvb, *offset,
                               *bitoffset, 4, 1);
      proceed_nbits(offset, bitoffset, 4);

      proto_tree_add_uint_bits(sDU_tree, hf_ranap_sDU_ErrorRatio_exponent, tvb, *offset,
                               *bitoffset, 3, 1);
      proceed_nbits(offset, bitoffset, 3);

      if (sDU_ErrorRatio_iE_Extensions_present)
      {
      	 if ((ret=dissect_iE_Extension(tvb, sDU_tree, offset, bitoffset, "sDU_ErrorRatio")) != 0)
      	     return (ret);
      }
   }

   /* residualBitErrorRatio */
   residualBitErrorRatio_iE_Extensions_present = extract_nbits(tvb, *offset, *bitoffset, 1);
   proceed_nbits(offset, bitoffset, 1);

   proto_tree_add_uint_bits(sDU_tree, hf_ranap_residualBitErrorRatio_mantissa, tvb, *offset,
                            *bitoffset, 4, 1);
   proceed_nbits(offset, bitoffset, 4);

   proto_tree_add_uint_bits(sDU_tree, hf_ranap_sDU_ErrorRatio_exponent, tvb, *offset,
                            *bitoffset, 3, 1);
   proceed_nbits(offset, bitoffset, 3);


   if (residualBitErrorRatio_iE_Extensions_present)
   {
      if ((ret=dissect_iE_Extension(tvb, sDU_tree, offset, bitoffset, "residualBitErrorRatio")) != 0)
           return(ret);
   }


   /* deliveryOfErroneousSDU */
   proto_tree_add_uint_bits(sDU_tree, hf_ranap_deliveryOfErroneousSDU, tvb, *offset,
                            *bitoffset, 2, 0);
   proceed_nbits(offset, bitoffset, 2);


   /* sDU_FormatInformationParameters */
   if (sDU_FormatInformationParameters_present)
   {
      number_of_sDU_FormatInformationParameters = extract_nbits(tvb, *offset, *bitoffset, 6) + 1;
      proceed_nbits(offset, bitoffset, 6);

      for (i=1; i<= number_of_sDU_FormatInformationParameters; i++)
      {
      	  /* create subtree for extension/optional/default bitmap */
         optionals_item = proto_tree_add_text(sDU_tree, tvb, *offset, 1,
                                      "sDU_FormatInformationParameters Extension/Optional/Default bitmap");
         optionals_tree = proto_item_add_subtree(optionals_item, ett_ranap_optionals);

         /* protocol extension present ? */
         sDU_FormatInformationParameters_extension_present =
             extract_nbits(tvb, *offset, *bitoffset, 1);
         proto_tree_add_uint_bits(optionals_tree, hf_ranap_ie_protocol_extension, tvb,
                            *offset, *bitoffset, 1, 0);
         proceed_nbits(offset, bitoffset, 1);

         /* subflowSDU_Size present ? */
         subflowSDU_Size_present = extract_nbits(tvb, *offset, *bitoffset, 1);
         proto_tree_add_uint_bits(optionals_tree, hf_ranap_subflowSDU_Size_present, tvb,
                            *offset, *bitoffset, 1, 0);
         proceed_nbits(offset, bitoffset, 1);

         /* rAB_SubflowCombinationBitRate present ? */
         rAB_SubflowCombinationBitRate_present = extract_nbits(tvb, *offset, *bitoffset, 1);
         proto_tree_add_uint_bits(optionals_tree, hf_ranap_rAB_SubflowCombinationBitRate_present, tvb,
                            *offset, *bitoffset, 1, 0);
         proceed_nbits(offset, bitoffset, 1);

         /* ie_Extension present ? */
         sDU_FormatInformationParameters_iE_Extensions_present =
             extract_nbits(tvb, *offset, *bitoffset, 1);
         proto_tree_add_uint_bits(optionals_tree, hf_ranap_iE_Extensions_present, tvb,
                            *offset, *bitoffset, 1, 0);
         proceed_nbits(offset, bitoffset, 1);

         if (subflowSDU_Size_present)
         {
            allign(offset, bitoffset);
            proto_tree_add_item(sDU_tree, hf_ranap_subflowSDU_Size,
			tvb, *offset, subflowSDU_Size_LENGTH, FALSE);
            offset += subflowSDU_Size_LENGTH;
         }

         if (rAB_SubflowCombinationBitRate_present)
         {
             proto_tree_add_PERint32(sDU_tree, hf_ranap_rAB_SubflowCombinationBitRate,
                                     tvb, *offset, *bitoffset, &length, 0);
             proceed_perint32(offset, bitoffset, length);
	 }

         if (sDU_FormatInformationParameters_iE_Extensions_present)
         {
      	    if ((ret=dissect_iE_Extension(tvb, sDU_tree, offset, bitoffset,
      	                                   "sDU_FormatInformationParameters" )) != 0)
      	        return (ret);
         }
      }
    }

    if (extension_present)
    {
        /* extended sequence */
        /* decoding is not supported */
        proto_tree_add_text(ie_tree, tvb, *offset, IE_PROTOCOL_EXTENSION_LENGTH,
      	                  "Protocol extension for sDU_FormatInformationParameters present, dissection not supported");
        return(-1);
    }

  return (0);

}


static int
dissect_rAB_Parameters(tvbuff_t *tvb, proto_tree *ie_tree, gint *offset, gint *bitoffset)
{
   guint8	tmp_byte;
   proto_item	*rab_item = NULL;
   proto_tree	*rab_tree = NULL;
   proto_item	*optionals_item = NULL;
   proto_tree	*optionals_tree = NULL;
   proto_item	*prio_item = NULL;
   proto_tree	*prio_tree = NULL;
   int		ret;
   int		extension_present;
   int		tmp_extension_present;
   int		guaranteedBitRate_present;
   int		transferDelay_present;
   int		trafficHandlingPriority_present;
   int		allocationOrRetentionPriority_present;
   int		sourceStatisticsDescriptor_present;
   int		relocationRequirement_present;
   int		iE_Extensions_present;
   int		tmp_iE_Extensions_present;
   int		i;
   gint		length;

   /* create subtree for rAB_Parameters */
   rab_item = proto_tree_add_text(ie_tree, tvb, *offset, 0,
                                      "rAB_Parameters");
   rab_tree = proto_item_add_subtree(rab_item, ett_ranap_rAB_Parameters);

   /* create subtree for extension/optional/default bitmap */
   optionals_item = proto_tree_add_text(rab_tree, tvb, *offset, IE_PROTOCOL_EXTENSION_LENGTH,
                                      "rAB_Parameters Extension/Optional/Default bitmap");
   optionals_tree = proto_item_add_subtree(optionals_item, ett_ranap_optionals);

   /* protocol extension present ? */
   extension_present = extract_nbits(tvb, *offset, *bitoffset, 1);
   proto_tree_add_uint_bits(optionals_tree, hf_ranap_ie_protocol_extension, tvb,
                            *offset, *bitoffset, 1, 0);
   proceed_nbits(offset, bitoffset, 1);

   /* guaranteedBitRate present ? */
   guaranteedBitRate_present = extract_nbits(tvb, *offset, *bitoffset, 1);
   proto_tree_add_uint_bits(optionals_tree, hf_ranap_guaranteedBitRate_present,
                            tvb, *offset, *bitoffset, 1, 0);
   proceed_nbits(offset, bitoffset, 1);

   /* transferDelay present ? */
   transferDelay_present = extract_nbits(tvb, *offset, *bitoffset, 1);
   proto_tree_add_uint_bits(optionals_tree, hf_ranap_transferDelay_present,
                            tvb, *offset, *bitoffset, 1, 0);
   proceed_nbits(offset, bitoffset, 1);

   /* trafficHandlingPriority present ? */
   trafficHandlingPriority_present = extract_nbits(tvb, *offset, *bitoffset, 1);
   proto_tree_add_uint_bits(optionals_tree, hf_ranap_trafficHandlingPriority_present,
                            tvb, *offset, *bitoffset, 1, 0);
   proceed_nbits(offset, bitoffset, 1);

   /* allocationOrRetentionPriority present ? */
   allocationOrRetentionPriority_present = extract_nbits(tvb, *offset, *bitoffset, 1);
   proto_tree_add_uint_bits(optionals_tree, hf_ranap_allocationOrRetentionPriority_present,
                            tvb, *offset, *bitoffset, 1, 0);
   proceed_nbits(offset, bitoffset, 1);

   /* sourceStatisticsDescriptor present ? */
   sourceStatisticsDescriptor_present = extract_nbits(tvb, *offset, *bitoffset, 1);
   proto_tree_add_uint_bits(optionals_tree, hf_ranap_sourceStatisticsDescriptor_present,
                            tvb, *offset, *bitoffset, 1, 0);
   proceed_nbits(offset, bitoffset, 1);

   /* relocationRequirement present ? */
   relocationRequirement_present = extract_nbits(tvb, *offset, *bitoffset, 1);
   proto_tree_add_uint_bits(optionals_tree, hf_ranap_relocationRequirement_present,
                            tvb, *offset, *bitoffset, 1, 0);
   proceed_nbits(offset, bitoffset, 1);

   /* iE-Extensions present ? */
   iE_Extensions_present = extract_nbits(tvb, *offset, *bitoffset, 1);
   proto_tree_add_uint_bits(optionals_tree, hf_ranap_iE_Extensions_present,
                            tvb, *offset, *bitoffset, 1, 0);
   proceed_nbits(offset, bitoffset, 1);


   /* trafficClass */
   tmp_extension_present = extract_nbits(tvb, *offset, *bitoffset, 1);
   proceed_nbits(offset, bitoffset, 1);

   proto_tree_add_uint_bits(rab_tree, hf_ranap_trafficClass,
                            tvb, *offset, *bitoffset, 2, 0);
   proceed_nbits(offset, bitoffset, 2);

   if (tmp_extension_present)
   {
      /* decoding is not supported */
      proto_tree_add_text(rab_tree, tvb, *offset, IE_PROTOCOL_EXTENSION_LENGTH,
    	                  "Protocol extension for trafficClass present, dissection not supported");
      return(-1);
   }


   /* rAB-AsymmetryIndicator */
   tmp_extension_present = extract_nbits(tvb, *offset, *bitoffset, 1);
   proceed_nbits(offset, bitoffset, 1);

   proto_tree_add_uint_bits(rab_tree, hf_ranap_rAB_AsymmetryIndicator,
                            tvb, *offset, *bitoffset, 2, 0);
   proceed_nbits(offset, bitoffset, 2);

   if (tmp_extension_present)
   {
      /* decoding is not supported */
      proto_tree_add_text(rab_tree, tvb, *offset, IE_PROTOCOL_EXTENSION_LENGTH,
    	                  "Protocol extension for rAB-AsymmetryIndicator present, dissection not supported");
      return(-1);
   }


   /* maxBitrate */
   tmp_byte = extract_nbits(tvb, *offset, *bitoffset, 1) +1 ;  /*sequence 1..2 */
   proceed_nbits(offset, bitoffset, 1);

   for (i=1; i<= tmp_byte; i++)
   {
      proto_tree_add_PERint32(rab_tree, hf_ranap_maxBitrate,
                              tvb, *offset, *bitoffset, &length, 1);
      proceed_perint32(offset, bitoffset, length);
   }


   /* guaranteedBitRate */
   if (guaranteedBitRate_present)
   {
      tmp_byte = extract_nbits(tvb, *offset, *bitoffset, 1) +1 ;  /*sequence 1..2 */
      proceed_nbits(offset, bitoffset, 1);

      for (i=1; i<= tmp_byte; i++)
      {
        proto_tree_add_PERint32(rab_tree, hf_ranap_guaranteedBitrate,
                                tvb, *offset, *bitoffset, &length, 0);
        proceed_perint32(offset, bitoffset, length);
      }
   }

   /* deliveryOrder */
   proto_tree_add_uint_bits(rab_tree, hf_ranap_deliveryOrder, tvb, *offset,
                            *bitoffset, 1, 0);
   proceed_nbits(offset, bitoffset, 1);


   /* maxSDU-Size */
   allign(offset, bitoffset);
   proto_tree_add_item(rab_tree, hf_ranap_maxSDU_Size,
			tvb, *offset, maxSDU_Size_LENGTH, FALSE);
   *offset += maxSDU_Size_LENGTH;

   /* sDU-Parameters */
   tmp_byte = extract_nbits(tvb, *offset, *bitoffset, 3) + 1; /*sequence 1..7 */
   proceed_nbits(offset, bitoffset, 3);
   for (i=1; i<= tmp_byte; i++)
   {
      if ((ret=dissect_sDU_Parameters(tvb, rab_tree, offset, bitoffset))!=0) return(ret);
   }

   /* transferDelay  */
   if (transferDelay_present)
   {
      allign(offset, bitoffset);
      proto_tree_add_item(rab_tree, hf_ranap_transferDelay,
			  tvb, *offset, transferDelay_LENGTH, FALSE);
      *offset += transferDelay_LENGTH;
   }


   /* trafficHandlingPriority */
   if (trafficHandlingPriority_present)
   {
      proto_tree_add_uint_bits(rab_tree, hf_ranap_trafficHandlingPriority, tvb, *offset,
                               *bitoffset, 4, 0);
      proceed_nbits(offset, bitoffset, 4);
   }

   /* allocationOrRetentionPriority */
   if (allocationOrRetentionPriority_present)
   {
      /* create subtree for */
      prio_item = proto_tree_add_text(rab_tree, tvb, *offset, 0,
                                      "allocationOrRetentionPriority");
      prio_tree = proto_item_add_subtree(prio_item, ett_ranap_allocationOrRetentionPriority);

      /* protocol extension  present ? */
      tmp_extension_present = extract_nbits(tvb, *offset, *bitoffset, 1);
      proceed_nbits(offset, bitoffset, 1);

      /* iE Extension present ? */
      tmp_iE_Extensions_present = extract_nbits(tvb, *offset, *bitoffset, 1);
      proceed_nbits(offset, bitoffset, 1);

      /* allocationOrRetentionPriority */
      proto_tree_add_uint_bits(prio_tree, hf_ranap_priorityLevel, tvb, *offset,
                               *bitoffset, 4, 0);
      proceed_nbits(offset, bitoffset, 4);

      /* pre-emptionCapability */
      proto_tree_add_uint_bits(prio_tree, hf_ranap_pre_emptionCapability, tvb, *offset,
                               *bitoffset, 1, 0);
      proceed_nbits(offset, bitoffset, 1);

      /* pre-emptionVulnerability */
      proto_tree_add_uint_bits(prio_tree, hf_ranap_pre_emptionVulnerability, tvb, *offset,
                               *bitoffset, 1, 0);
      proceed_nbits(offset, bitoffset, 1);

      /* queuingAllowed */
      proto_tree_add_uint_bits(prio_tree, hf_ranap_queuingAllowed, tvb, *offset,
                               *bitoffset, 1, 0);
      proceed_nbits(offset, bitoffset, 1);

      if (tmp_iE_Extensions_present)
      {
      	 if ((ret=dissect_iE_Extension(tvb, prio_tree, offset, bitoffset,
      	                                   "AllocationOrRetentionPriority")) != 0)
      	        return (ret);
      }

      if (tmp_extension_present)
      {
         /* decoding is not supported */
         proto_tree_add_text(prio_tree, tvb, *offset, IE_PROTOCOL_EXTENSION_LENGTH,
    	                  "Protocol extension for rAB-allocationOrRetentionPriority present, dissection not supported");
         return(-1);
      }
   }

   /* sourceStatisticsDescriptor */
   if (sourceStatisticsDescriptor_present)
   {
      /* protocol extension */
      tmp_extension_present = extract_nbits(tvb, *offset, *bitoffset, 1);
      proceed_nbits(offset, bitoffset, 1);

      if (tmp_extension_present)
      {
         /* decoding is not supported */
         proto_tree_add_text(prio_tree, tvb, *offset, IE_PROTOCOL_EXTENSION_LENGTH,
    	                  "Protocol extension for sourceStatisticsDescriptor present, dissection not supported");
         return(-1);
      }

      proto_tree_add_uint_bits(rab_tree, hf_ranap_sourceStatisticsDescriptor, tvb, *offset,
                               *bitoffset, 1, 0);
      proceed_nbits(offset, bitoffset, 1);
    }

    /* relocationRequirement */
    if (relocationRequirement_present)
    {
      /* protocol extension */
      tmp_extension_present = extract_nbits(tvb, *offset, *bitoffset, 1);
      proceed_nbits(offset, bitoffset, 1);

      if (tmp_extension_present)
      {
         /* decoding is not supported */
         proto_tree_add_text(prio_tree, tvb, *offset, IE_PROTOCOL_EXTENSION_LENGTH,
    	                  "Protocol extension for relocationRequirement present, dissection not supported");
         return(-1);
      }

      proto_tree_add_uint_bits(rab_tree, hf_ranap_relocationRequirement, tvb, *offset,
                               *bitoffset, 1, 0);
      proceed_nbits(offset, bitoffset, 1);
    }


   /* iE-Extensions */
   if (iE_Extensions_present)
   {
     if ((ret=dissect_iE_Extension(tvb, rab_tree, offset, bitoffset, "rAB_Parameters" )) != 0 )
      	        return (ret);
   }

   /* extended */
   if (extension_present)
   {
      /* decoding is not supported */
      proto_tree_add_text(rab_tree, tvb, *offset, IE_PROTOCOL_EXTENSION_LENGTH,
    	                  "Protocol extension for rAB_Parameters present, dissection not supported");
      return(-1);
   }

   return(0);
}



static int
dissect_TransportLayerAddress(tvbuff_t *tvb, proto_tree *ie_tree, gint *offset, gint *bitoffset)
{
   gint		extension_present;
   gint		str_length;

   extension_present = extract_nbits(tvb, *offset, *bitoffset, 1);
   proceed_nbits(offset, bitoffset, 1);
   if (extension_present)
   {
      /* extended integer */
      proto_tree_add_text(ie_tree, tvb, *offset, 0,
                          "extension present for TransportLayerAddress, dissection not supported");
      return (-1);
   }

   /* extract and add length of transportLayerAddress bitstring */
   str_length = extract_nbits(tvb, *offset, *bitoffset, 8) + 1;
   proto_tree_add_uint_bits(ie_tree, hf_ranap_transportLayerAddress_length,
                             tvb, *offset, *bitoffset, 8, 1);
   proceed_nbits(offset, bitoffset, 8);
   allign(offset, bitoffset);

   /* add transportLayerAddress */
   proto_tree_add_bitstring(ie_tree, hf_ranap_transportLayerAddress, tvb, *offset,
                            *bitoffset, str_length);
   proceed_nbits(offset, bitoffset, str_length);

   return (0);
}



static int
dissect_iuTransportAssociation(tvbuff_t *tvb, proto_tree *ie_tree, gint *offset, gint *bitoffset)
{
   guint	extension_present;
   guint	choice_value;

   /* extension present ? */
   extension_present = extract_nbits(tvb, *offset, *bitoffset, 1);
   if (extension_present)
   {
      /* extended choice */
      proto_tree_add_text(ie_tree, tvb, *offset, 0,
                          "extension present for IuTransportAssociation, dissection not supported");
      return (-1);
   }
   proceed_nbits(offset, bitoffset, 1);

   /* choice */
   choice_value = extract_nbits(tvb, *offset, *bitoffset, 1);
   proceed_nbits(offset, bitoffset, 1);
   allign(offset, bitoffset);
   if (choice_value == 0)
   {
      /*  gTP-TEI */
      proto_tree_add_item(ie_tree, hf_ranap_gTP_TEI, tvb, *offset, 4, FALSE);
      *offset += 4;
   }
   else
   {
      /* bindingID */
      proto_tree_add_item(ie_tree, hf_ranap_bindingID, tvb, *offset, 4, FALSE);
      *offset += 4;
   }

   return (0);
}


static int
dissect_transportLayerInformation(tvbuff_t *tvb, proto_tree *ie_tree, gint *offset, gint *bitoffset)
{
   proto_item	*optionals_item = NULL;
   proto_tree	*optionals_tree = NULL;
   int		extension_present;
   int		iE_Extensions_present;
   int		ret;

   /* create subtree for extension/optional/default bitmap */
   optionals_item = proto_tree_add_text(ie_tree, tvb, *offset, IE_PROTOCOL_EXTENSION_LENGTH,
                                      "TransportLayerInformation Extension/Optional/Default bitmap");
   optionals_tree = proto_item_add_subtree(optionals_item, ett_ranap_optionals);


   /* protocol extension present ? */
   extension_present = extract_nbits(tvb, *offset, *bitoffset, 1);
   proto_tree_add_uint_bits(optionals_tree, hf_ranap_ie_protocol_extension, tvb,
                            *offset, *bitoffset, 1, 0);
   proceed_nbits(offset, bitoffset, 1);

   /* iE-Extensions present ? */
   iE_Extensions_present = extract_nbits(tvb, *offset, *bitoffset, 1);
   proto_tree_add_uint_bits(optionals_tree, hf_ranap_iE_Extensions_present,
                            tvb, *offset, *bitoffset, 1, 0);
   proceed_nbits(offset, bitoffset, 1);


   /* transportLayerAddress */
   if ((ret=dissect_TransportLayerAddress(tvb, ie_tree, offset, bitoffset)) != 0)
       return (ret);

   /* iuTransportAssociation */
   if ((ret=dissect_iuTransportAssociation(tvb, ie_tree, offset, bitoffset)) != 0)
      return (ret);

   /* iE-Extensions */
   if (iE_Extensions_present)
   {
     if ((ret=dissect_iE_Extension(tvb, ie_tree, offset, bitoffset, "TransportLayerInformation" )) != 0 )
      	        return (ret);
   }

   /* protocol extension */
   if (extension_present)
   {
      /* extended sequence */
      proto_tree_add_text(ie_tree, tvb, *offset, 0,
                          "extension present for TransportLayerInformation, dissection not supported");
      return (-1);
   }

   return(0);
}


static int
dissect_dataVolumeList (tvbuff_t *tvb, proto_tree *ie_tree, gint *offset, gint *bitoffset, const char *parname)
{
   proto_item	*optionals_item = NULL;
   proto_tree	*optionals_tree = NULL;
   gint		extension_present;
   gint		dataVolumeReference_present;
   gint		iE_Extensions_present;
   gint		number_vol;
   gint		length;
   gint		i;
   int		ret;

   /* number of volumes */
   number_vol = extract_nbits(tvb, *offset, *bitoffset, 1) + 1;
   proceed_nbits(offset, bitoffset, 1);

   for (i=1; i<=number_vol; i++)
   {
      /* create subtree for extension/optional/default bitmap */
      optionals_item = proto_tree_add_text(ie_tree, tvb, *offset, 1,
                                           "%d. %s Extension/Optional/Default bitmap",
                                            i, parname);
      optionals_tree = proto_item_add_subtree(optionals_item, ett_ranap_optionals);

      /* protocol_extension present ? */
      extension_present = extract_nbits(tvb, *offset, *bitoffset, 1);
      proto_tree_add_uint_bits(optionals_tree, hf_ranap_ie_protocol_extension, tvb,
                               *offset, *bitoffset, 1, 0);
      proceed_nbits(offset, bitoffset, 1);

      /* dataVolumeReference present ? */
      dataVolumeReference_present = extract_nbits(tvb, *offset, *bitoffset, 1);
      proto_tree_add_uint_bits(optionals_tree, hf_ranap_dataVolumeReference_present, tvb,
                               *offset, *bitoffset, 1, 0);
      proceed_nbits(offset, bitoffset, 1);

      /* iE_Extensions present ? */
      iE_Extensions_present = extract_nbits(tvb, *offset, *bitoffset, 1);
      proto_tree_add_uint_bits(optionals_tree, hf_ranap_iE_Extensions_present, tvb,
                               *offset, *bitoffset, 1, 0);
      proceed_nbits(offset, bitoffset, 1);


      /* UnsuccessfullyTransmittedDataVolume */
      proto_tree_add_PERint32(ie_tree, hf_ranap_dl_UnsuccessfullyTransmittedDataVolume,
                              tvb, *offset, *bitoffset, &length, 0);
      proceed_perint32(offset, bitoffset, length);

      /* DataVolumeReference */
      if (dataVolumeReference_present)
      {
         proto_tree_add_uint_bits(ie_tree, hf_ranap_dataVolumeReference, tvb,
                                  *offset, *bitoffset, 8, 0);
         proceed_nbits(offset, bitoffset, 8);
      }

     /* iE-Extensions */
     if (iE_Extensions_present)
     {
      	if ((ret=dissect_iE_Extension(tvb, ie_tree, offset, bitoffset, "dl-dataVolumes" )) != 0)
      	     return(ret);
     }

     /* protocol extended */
     if (extension_present)
     {
        /* extended sequence */
        /* decoding is not supported */
        proto_tree_add_text(ie_tree, tvb, *offset, IE_PROTOCOL_EXTENSION_LENGTH,
      	                  "Protocol extension for dl-dataVolumes present, dissection not supported");
        return(-1);
     }
  }

  return (0);

}

static int
dissect_cause(tvbuff_t *tvb, proto_tree *ie_tree, gint *offset, gint *bitoffset)
{
   gint		extension_present;
   int		cause_choice;

  /* protocol extension present ? */
  extension_present = extract_nbits(tvb, *offset, *bitoffset, 1);
  proceed_nbits(offset, bitoffset, 1);
  if (extension_present)
  {
     /* choice extension present */
     proto_tree_add_text(ie_tree, tvb, *offset, 0,
                          "extension present for cause, dissection not supported");
     return (-1);
  }
  cause_choice = extract_nbits(tvb, *offset, *bitoffset, 3);
  proto_tree_add_uint_bits(ie_tree, hf_ranap_cause_choice,
                           tvb, *offset, *bitoffset, 3, 0);
  proceed_nbits(offset, bitoffset, 3);

  switch (cause_choice)
  {
     case CC_CauseRadioNetwork:
        proto_tree_add_uint_bits(ie_tree, hf_ranap_cause_value,
                                 tvb, *offset, *bitoffset, 6, 1);
        proceed_nbits(offset, bitoffset, 6);
        break;
     case CC_CauseTransmissionNetwork:
        proto_tree_add_uint_bits(ie_tree, hf_ranap_cause_value,
                                 tvb, *offset, *bitoffset, 4, 65);
        proceed_nbits(offset, bitoffset, 4);
        break;
     case CC_CauseNAS:
        proto_tree_add_uint_bits(ie_tree, hf_ranap_cause_value,
                                 tvb, *offset, *bitoffset, 4, 81);
        proceed_nbits(offset, bitoffset, 4);
        break;
     case CC_CauseProtocol:
        proto_tree_add_uint_bits(ie_tree, hf_ranap_cause_value,
                                 tvb, *offset, *bitoffset, 4, 97);
        proceed_nbits(offset, bitoffset, 4);
     case CC_CauseMisc:
        proto_tree_add_uint_bits(ie_tree, hf_ranap_cause_value,
                                 tvb, *offset, *bitoffset, 4, 113);
        proceed_nbits(offset, bitoffset, 4);
        break;
     case CC_CauseNon_Standard:
        proto_tree_add_uint_bits(ie_tree, hf_ranap_cause_value,
                                 tvb, *offset, *bitoffset, 7, 129);
        proceed_nbits(offset, bitoffset, 7);
        break;
     default:
       proto_tree_add_text(ie_tree, tvb, *offset, 0,
                            "unexpected cause choice value, dissection not supported");
       return(-1);
  }
  return(0);
}


static int
dissect_iEsCriticalityDiagnostics(tvbuff_t *tvb, proto_tree *ie_tree, gint *offset, gint *bitoffset)
{
   proto_item		*diag_item = NULL;
   proto_tree		*diag_tree = NULL;
   proto_item		*optionals_item = NULL;
   proto_tree		*optionals_tree = NULL;
   int			extension_present;
   int			repetitionNumber_present;
   int			iE_Extensions_present;
   int			num_of_errors;
   int			i;

   allign(offset, bitoffset);
   num_of_errors = extract_nbits(tvb, *offset, *bitoffset, 8) + 1;
   proto_tree_add_uint_bits(ie_tree, hf_ranap_num_of_CriticalityDiagnostics_IEs, tvb,
                            *offset, *bitoffset, 8, 1);
   proceed_nbits(offset, bitoffset, 8);

   for ( i= 1; i <= num_of_errors; i++)
   {
      /* add subtree for CriticalityDiagnostics-IE */
      diag_item = proto_tree_add_text(ie_tree, tvb, *offset, 0,
                                      "%d. CriticalityDiagnostics-IE", i);
      diag_tree = proto_item_add_subtree(diag_item, ett_ranap_CriticalityDiagnostics_IE);

      /* create subtree for extension/optional/default bitmap */
      optionals_item = proto_tree_add_text(diag_tree, tvb, *offset, 1,
                                         "CriticalityDiagnostics-IE Extension/Optional/Default bitmap");
      optionals_tree = proto_item_add_subtree(optionals_item, ett_ranap_optionals);

      /* protocol_extension present ? */
      extension_present = extract_nbits(tvb, *offset, *bitoffset, 1);
      proto_tree_add_uint_bits(optionals_tree, hf_ranap_ie_protocol_extension, tvb,
                               *offset, *bitoffset, 1, 0);
      proceed_nbits(offset, bitoffset, 1);

      /* repetitionNumber present ? */
      repetitionNumber_present = extract_nbits(tvb, *offset, *bitoffset, 1);
      proto_tree_add_uint_bits(optionals_tree, hf_ranap_repetitionNumber_present, tvb,
                               *offset, *bitoffset, 1, 0);
      proceed_nbits(offset, bitoffset, 1);

      /* iE_Extensions present ? */
      iE_Extensions_present = extract_nbits(tvb, *offset, *bitoffset, 1);
      proto_tree_add_uint_bits(optionals_tree, hf_ranap_iE_Extensions_present,
                               tvb, *offset, *bitoffset, 1, 0);
      proceed_nbits(offset, bitoffset, 1);

      /* iECriticality */
      proto_tree_add_uint_bits(diag_tree, hf_ranap_iECriticality,
                               tvb, *offset, *bitoffset, 2, 0);
      proceed_nbits(offset, bitoffset, 2);

      /* iE-ID */
      allign(offset, bitoffset);
      proto_tree_add_item(diag_tree, hf_ranap_ie_ie_id, tvb,
                          *offset, IE_ID_LENGTH, FALSE);
      *offset += IE_ID_LENGTH;

      /* repetitionNumber */
      if (repetitionNumber_present)
      {
      	 allign(offset, bitoffset);
         proto_tree_add_uint_bits(diag_tree, hf_ranap_repetitionNumber,
                                  tvb, *offset, *bitoffset, 8, 1);
         proceed_nbits(offset, bitoffset, 8);
      }

      /* iE-Extensions */
      if (iE_Extensions_present)
      {
        return(dissect_iE_Extension(tvb, diag_tree, offset, bitoffset, "CriticalityDiagnostics-IE"));
      }


      /* protocol extended */
      if (extension_present)
      {
         /* extended sequence */
         /* decoding is not supported */
         proto_tree_add_text(diag_tree, tvb, *offset, IE_PROTOCOL_EXTENSION_LENGTH,
       	                  "Protocol extension for CriticalityDiagnostics-IE present, dissection not supported");
         return(-1);
      }
   }

   return(0);
}



/*****************************************************************************/
/*                                                                           */
/*  Dissecting Functions for IEs                                             */
/*                                                                           */
/*****************************************************************************/

static int
dissect_IE_RAB_ID(tvbuff_t *tvb, proto_tree *ie_tree)
{
  if (ie_tree)
  {
       proto_tree_add_item(ie_tree, hf_ranap_rab_id, tvb,
                           0, RAB_ID_LENGTH, FALSE);
  }
  return(0);
}


static int
dissect_IE_RAC(tvbuff_t *tvb, proto_tree *ie_tree)
{
  if (ie_tree)
  {
       proto_tree_add_item(ie_tree, hf_ranap_rac, tvb,
                           0, RAC_LENGTH, FALSE);
  }
  return(0);
}


static int
dissect_IE_LAI(tvbuff_t *tvb, proto_tree *ie_tree)
{
  proto_item	*optionals_item = NULL;
  proto_tree	*optionals_tree = NULL;
  int		iE_Extensions_present;
  gint		offset = 0;
  gint		bitoffset = 0;
  int		ret;

  if (ie_tree)
  {
      /* create subtree for extension/optional/default bitmap */
     optionals_item = proto_tree_add_text(ie_tree, tvb, offset, 1,
                                      "LAI Extension/Optional/Default bitmap");
     optionals_tree = proto_item_add_subtree(optionals_item, ett_ranap_optionals);

     /* iE_Extensions_present present ? */
     iE_Extensions_present = extract_nbits(tvb, offset, bitoffset, 1);
     proto_tree_add_uint_bits(optionals_tree, hf_ranap_iE_Extensions_present, tvb,
                              offset, bitoffset, 1, 0);
     proceed_nbits(&offset, &bitoffset, 1);

     /* plmn_id */
     allign(&offset, &bitoffset);
     proto_tree_add_item(ie_tree, hf_ranap_plmn_id, tvb,
                         offset, PLMN_ID_LENGTH, FALSE);
     offset += PLMN_ID_LENGTH;

     /* lac */
     proto_tree_add_item(ie_tree, hf_ranap_lac, tvb,
                         offset, LAC_LENGTH, FALSE);
     offset += LAC_LENGTH;

     /* iE_Extensions */
     if (iE_Extensions_present)
     {
      	if ((ret=dissect_iE_Extension(tvb, ie_tree, &offset, &bitoffset, "LAI")) != 0)
      	     return (ret);
     }
  }
  return(0);
}


static int
dissect_IE_GlobalRNC_ID(tvbuff_t *tvb, proto_tree *ie_tree)
{
  gint		offset = 0;

  if (ie_tree)
  {
     /*  plmn_id */
     proto_tree_add_item(ie_tree, hf_ranap_plmn_id, tvb,
                           offset, PLMN_ID_LENGTH, FALSE);
     offset += PLMN_ID_LENGTH;

     /* RNC ID */
     proto_tree_add_item(ie_tree, hf_ranap_RNC_ID, tvb, offset, 2, FALSE);
     offset += 2;
  }

  return(0);
}


static int
dissect_IE_SAI(tvbuff_t *tvb, proto_tree *ie_tree)
{
  proto_item	*optionals_item = NULL;
  proto_tree	*optionals_tree = NULL;
  int		iE_Extensions_present;
  gint		offset = 0;
  gint		bitoffset = 0;
  int		ret;

  if (ie_tree)
  {
      /* create subtree for extension/optional/default bitmap */
     optionals_item = proto_tree_add_text(ie_tree, tvb, offset, 1,
                                      "SAI Extension/Optional/Default bitmap");
     optionals_tree = proto_item_add_subtree(optionals_item, ett_ranap_optionals);

     /* iE_Extensions_present present ? */
     iE_Extensions_present = extract_nbits(tvb, offset, bitoffset, 1);
     proto_tree_add_uint_bits(optionals_tree, hf_ranap_iE_Extensions_present, tvb,
                              offset, bitoffset, 1, 0);
     proceed_nbits(&offset, &bitoffset, 1);

     /*  plmn_id */
     allign(&offset, &bitoffset);
     proto_tree_add_item(ie_tree, hf_ranap_plmn_id, tvb,
                           offset, PLMN_ID_LENGTH, FALSE);
     offset += PLMN_ID_LENGTH;

     /* lac */
     proto_tree_add_item(ie_tree, hf_ranap_lac, tvb,
                           offset, LAC_LENGTH, FALSE);
     offset += LAC_LENGTH;

     /* sac */
     proto_tree_add_item(ie_tree, hf_ranap_sac, tvb,
                           offset, SAC_LENGTH, FALSE);
     offset += SAC_LENGTH;

     /* iE_Extensions */
     if (iE_Extensions_present)
     {
      	if ((ret=dissect_iE_Extension(tvb, ie_tree, &offset, &bitoffset, "SAI")) != 0)
      	     return (ret);
     }
  }
  return(0);
}


static int
dissect_IE_NAS_PDU(tvbuff_t *tvb, proto_tree *ie_tree)
{
   tvbuff_t		*next_tvb;
   gint			length;
   gint			length_size;

   if (extract_length(tvb, 0, &length, &length_size) != 0)
   {
      if (ie_tree)
      {
    	   /* decoding is not supported */
    	   proto_tree_add_text(ie_tree, tvb, 0,
    	                       2, "Number of Octets greater than 0x3FFF, dissection not supported");
      }
      return(-1);
   }

   if (ie_tree)
   {
       /* NAS - PDU length */
       proto_tree_add_item(ie_tree, hf_ranap_nas_pdu_length, tvb,
                           0, length_size, FALSE);
   }

   if (ie_tree)
   {
       /* NAS - PDU */
       proto_tree_add_item(ie_tree, hf_ranap_nas_pdu, tvb,
                           length_size, length, FALSE);
   }

   /* call NAS dissector */
   next_tvb = tvb_new_subset(tvb, length_size, length, length);

   if (dissector_try_port(nas_pdu_dissector_table, 0x1, next_tvb, g_pinfo, g_tree)) return(0);
   return(0);
}


static int
dissect_IE_CN_DomainIndicator(tvbuff_t *tvb, proto_tree *ie_tree)
{
  gint		offset = 0;
  gint		bitoffset = 0;

  if (ie_tree)
  {
     proto_tree_add_uint_bits(ie_tree, hf_ranap_CN_DomainIndicator, tvb,
                              offset, bitoffset, 1, 0);
  }
  return(0);
}


static int
dissect_IE_IuSigConId(tvbuff_t *tvb, proto_tree *ie_tree)
{
  guint32	value;

  if (ie_tree)
  {
     value = tvb_get_ntoh24(tvb, 0);
     proto_tree_add_uint(ie_tree, hf_ranap_IuSigConId,
	tvb, 0, 3, value);

  }
  return(0);
}


static int
dissect_IE_SAPI(tvbuff_t *tvb, proto_tree *ie_tree)
{
  gint		offset = 0;
  gint		bitoffset = 0;
  int		extension_present;

  if (ie_tree)
  {
     /* protocol_extension present ? */
     extension_present = extract_nbits(tvb, offset, bitoffset, 1);
     proceed_nbits(&offset, &bitoffset, 1);

     if (extension_present)
     {
        /* extended enum */
        /* decoding is not supported */
        proto_tree_add_text(ie_tree, tvb, offset, IE_PROTOCOL_EXTENSION_LENGTH,
      	                  "Protocol extension for IE_SAPI present, dissection not supported");
        return(-1);
     }

     /* SAPI */
     proto_tree_add_uint_bits(ie_tree, hf_ranap_SAPI, tvb,
                              offset, bitoffset, 1, 0);
  }
  return(0);
}


static int
dissect_IE_TransportLayerAddress(tvbuff_t *tvb, proto_tree *ie_tree)
{
  gint		offset = 0;
  gint		bitoffset = 0;

  if (ie_tree)
  {
     return(dissect_TransportLayerAddress(tvb, ie_tree, &offset, &bitoffset));
  }
  return(0);
}


static int
dissect_IE_IuTransportAssociation(tvbuff_t *tvb, proto_tree *ie_tree)
{
  gint		offset = 0;
  gint		bitoffset = 0;

  if (ie_tree)
  {
     return(dissect_iuTransportAssociation(tvb, ie_tree, &offset, &bitoffset));
  }
  return(0);
}


static int
dissect_IE_Cause(tvbuff_t *tvb, proto_tree *ie_tree)
{
  gint		offset = 0;
  gint		bitoffset = 0;

  if (ie_tree)
  {
     return(dissect_cause(tvb, ie_tree, &offset, &bitoffset));
  }
  return(0);
}


static int
dissect_IE_RAB_ReleasedItem_IuRelComp(tvbuff_t *tvb, proto_tree *ie_tree)
{
   proto_item	*optionals_item = NULL;
   proto_tree	*optionals_tree = NULL;
   int		extension_present;
   int		dl_GTP_PDU_SequenceNumber_present;
   int		ul_GTP_PDU_SequenceNumber_present;
   int		iE_Extensions_present;
   gint		offset = 0;
   gint		bitoffset = 0;
   int		ret;

  if (ie_tree)
  {
     /* create subtree for extension/optional/default bitmap */
     optionals_item = proto_tree_add_text(ie_tree, tvb, offset, 1,
                                      "RAB_ReleasedItem_IuRelComp Extension/Optional/Default bitmap");
     optionals_tree = proto_item_add_subtree(optionals_item, ett_ranap_optionals);

     /* protocol_extension present ? */
     extension_present = extract_nbits(tvb, offset, bitoffset, 1);
     proto_tree_add_uint_bits(optionals_tree, hf_ranap_ie_protocol_extension, tvb,
                              offset, bitoffset, 1, 0);
     proceed_nbits(&offset, &bitoffset, 1);

     /* dl_GTP_PDU_SequenceNumber present ? */
     dl_GTP_PDU_SequenceNumber_present = extract_nbits(tvb, offset, bitoffset, 1);
     proto_tree_add_uint_bits(optionals_tree, hf_ranap_dl_GTP_PDU_SequenceNumber_present, tvb,
                              offset, bitoffset, 1, 0);
     proceed_nbits(&offset, &bitoffset, 1);

     /* ul_GTP_PDU_SequenceNumber present ? */
     ul_GTP_PDU_SequenceNumber_present = extract_nbits(tvb, offset, bitoffset, 1);
     proto_tree_add_uint_bits(optionals_tree, hf_ranap_ul_GTP_PDU_SequenceNumber_present, tvb,
                              offset, bitoffset, 1, 0);
     proceed_nbits(&offset, &bitoffset, 1);

     /* iE_Extensions_present present ? */
     iE_Extensions_present = extract_nbits(tvb, offset, bitoffset, 1);
     proto_tree_add_uint_bits(optionals_tree, hf_ranap_iE_Extensions_present, tvb,
                              offset, bitoffset, 1, 0);
     proceed_nbits(&offset, &bitoffset, 1);


     /* rAB-ID */
     proto_tree_add_uint_bits(ie_tree, hf_ranap_rab_id,
                             tvb, offset, bitoffset, 8, 0);
     proceed_nbits(&offset, &bitoffset, 8);

     /* dl-GTP-PDU-SequenceNumber */
     if (dl_GTP_PDU_SequenceNumber_present)
     {
     	allign(&offset, &bitoffset);
     	proto_tree_add_item(ie_tree, hf_ranap_dl_GTP_PDU_SequenceNumber, tvb, offset, 2, FALSE);
        offset += 2;
     }

     /* ul-GTP-PDU-SequenceNumber */
     if (ul_GTP_PDU_SequenceNumber_present)
     {
     	allign(&offset, &bitoffset);
     	proto_tree_add_item(ie_tree, hf_ranap_ul_GTP_PDU_SequenceNumber, tvb, offset, 2, FALSE);
        offset += 2;
     }

     /* iE-Extensions */
     if (iE_Extensions_present)
     {
      	if ((ret=dissect_iE_Extension(tvb, ie_tree, &offset, &bitoffset, "RAB_ReleasedItem_IuRelComp")) != 0)
      	     return (ret);
     }

     /* protocol extended */
     if (extension_present)
     {
        /* extended sequence */
        /* decoding is not supported */
        proto_tree_add_text(ie_tree, tvb, offset, IE_PROTOCOL_EXTENSION_LENGTH,
      	                  "Protocol extension for RAB_ReleasedItem_IuRelComp present, dissection not supported");
        return(-1);
     }
  }
  return(0);
}


static int
dissect_IE_RAB_DataVolumeReportItem(tvbuff_t *tvb, proto_tree *ie_tree)
{
   proto_item	*optionals_item = NULL;
   proto_tree	*optionals_tree = NULL;
   int		extension_present;
   int		dl_UnsuccessfullyTransmittedDataVolume_present;
   int		iE_Extensions_present;
   gint		offset = 0;
   gint		bitoffset = 0;
   int		ret;

  if (ie_tree)
  {
     /* create subtree for extension/optional/default bitmap */
     optionals_item = proto_tree_add_text(ie_tree, tvb, offset, 1,
                                      "RAB_DataVolumeReportItem Extension/Optional/Default bitmap");
     optionals_tree = proto_item_add_subtree(optionals_item, ett_ranap_optionals);

     /* protocol_extension present ? */
     extension_present = extract_nbits(tvb, offset, bitoffset, 1);
     proto_tree_add_uint_bits(optionals_tree, hf_ranap_ie_protocol_extension, tvb,
                              offset, bitoffset, 1, 0);
     proceed_nbits(&offset, &bitoffset, 1);

     /* dl_UnsuccessfullyTransmittedDataVolume present ? */
     dl_UnsuccessfullyTransmittedDataVolume_present = extract_nbits(tvb, offset, bitoffset, 1);
     proto_tree_add_uint_bits(optionals_tree, hf_ranap_dl_UnsuccessfullyTransmittedDataVolume_present, tvb,
                              offset, bitoffset, 1, 0);
     proceed_nbits(&offset, &bitoffset, 1);

     /* iE_Extensions_present present ? */
     iE_Extensions_present = extract_nbits(tvb, offset, bitoffset, 1);
     proto_tree_add_uint_bits(optionals_tree, hf_ranap_iE_Extensions_present, tvb,
                              offset, bitoffset, 1, 0);
     proceed_nbits(&offset, &bitoffset, 1);


     /* rAB-ID */
     proto_tree_add_uint_bits(ie_tree, hf_ranap_rab_id,
                             tvb, offset, bitoffset, 8, 0);
     proceed_nbits(&offset, &bitoffset, 8);

     /* dl_UnsuccessfullyTransmittedDataVolume */
     if (dl_UnsuccessfullyTransmittedDataVolume_present)
     {

        if ((ret = dissect_dataVolumeList(tvb, ie_tree, &offset, &bitoffset,
             "dl_UnsuccessfullyTransmittedDataVolume")) != 0)
            return (ret);
     }

     /* iE-Extensions */
     if (iE_Extensions_present)
     {
      	if ((ret=dissect_iE_Extension(tvb, ie_tree, &offset, &bitoffset, "IE_RAB_DataVolumeReportItem")) != 0)
      	     return (ret);
     }

     /* protocol extended */
     if (extension_present)
     {
        /* extended enum */
        /* decoding is not supported */
        proto_tree_add_text(ie_tree, tvb, offset, IE_PROTOCOL_EXTENSION_LENGTH,
      	                  "Protocol extension for IE_RAB_DataVolumeReportItem present, dissection not supported");
        return(-1);
     }
  }
  return(0);
}


static int
dissect_IE_RAB_SetupOrModifyItemSecond(tvbuff_t *tvb, proto_tree *ie_tree)
{
   proto_item	*optionals_item = NULL;
   proto_tree	*optionals_tree = NULL;
   int		extension_present;
   int		tmp_extension;
   int		pDP_TypeInformation_present;
   int		dataVolumeReportingIndication_present;
   int		dl_GTP_PDU_SequenceNumber_present;
   int		ul_GTP_PDU_SequenceNumber_present;
   int		dl_N_PDU_SequenceNumber_present;
   int		ul_N_PDU_SequenceNumber_present;
   int		iE_Extensions_present;
   gint		offset = 0;
   gint		bitoffset = 0;
   gint8	tmp_byte;
   gint		i;
   int		ret;

  if (ie_tree)
  {
     /* create subtree for extension/optional/default bitmap */
     optionals_item = proto_tree_add_text(ie_tree, tvb, offset, 1,
                                      "SetupOrModifyItemSecond Extension/Optional/Default bitmap");
     optionals_tree = proto_item_add_subtree(optionals_item, ett_ranap_optionals);

     /* protocol_extension present ? */
     extension_present = extract_nbits(tvb, offset, bitoffset, 1);
     proto_tree_add_uint_bits(optionals_tree, hf_ranap_ie_protocol_extension, tvb,
                              offset, bitoffset, 1, 0);
     proceed_nbits(&offset, &bitoffset, 1);

     /* pDP_TypeInformation present ? */
     pDP_TypeInformation_present = extract_nbits(tvb, offset, bitoffset, 1);
     proto_tree_add_uint_bits(optionals_tree, hf_ranap_pDP_TypeInformation_present, tvb,
                              offset, bitoffset, 1, 0);
     proceed_nbits(&offset, &bitoffset, 1);

     /* dataVolumeReportingIndication present ? */
     dataVolumeReportingIndication_present = extract_nbits(tvb, offset, bitoffset, 1);
     proto_tree_add_uint_bits(optionals_tree, hf_ranap_dataVolumeReportingIndication_present, tvb,
                              offset, bitoffset, 1, 0);
     proceed_nbits(&offset, &bitoffset, 1);

     /* dl_GTP_PDU_SequenceNumber present present ? */
     dl_GTP_PDU_SequenceNumber_present = extract_nbits(tvb, offset, bitoffset, 1);
     proto_tree_add_uint_bits(optionals_tree, hf_ranap_dl_GTP_PDU_SequenceNumber_present, tvb,
                              offset, bitoffset, 1, 0);
     proceed_nbits(&offset, &bitoffset, 1);


     /* ul_GTP_PDU_SequenceNumber present ? */
     ul_GTP_PDU_SequenceNumber_present = extract_nbits(tvb, offset, bitoffset, 1);
     proto_tree_add_uint_bits(optionals_tree, hf_ranap_ul_GTP_PDU_SequenceNumber_present, tvb,
                              offset, bitoffset, 1, 0);
     proceed_nbits(&offset, &bitoffset, 1);

     /* dl_N_PDU_SequenceNumber present ? */
     dl_N_PDU_SequenceNumber_present = extract_nbits(tvb, offset, bitoffset, 1);
     proto_tree_add_uint_bits(optionals_tree, hf_ranap_dl_N_PDU_SequenceNumber_present, tvb,
                              offset, bitoffset, 1, 0);
     proceed_nbits(&offset, &bitoffset, 1);

     /* ul_N_PDU_SequenceNumber present ? */
     ul_N_PDU_SequenceNumber_present = extract_nbits(tvb, offset, bitoffset, 1);
     proto_tree_add_uint_bits(optionals_tree, hf_ranap_ul_N_PDU_SequenceNumber_present, tvb,
                              offset, bitoffset, 1, 0);
     proceed_nbits(&offset, &bitoffset, 1);

     /* iE_Extensions present ? */
     iE_Extensions_present = extract_nbits(tvb, offset, bitoffset, 1);
     proto_tree_add_uint_bits(optionals_tree, hf_ranap_iE_Extensions_present, tvb,
                              offset, bitoffset, 1, 0);
     proceed_nbits(&offset, &bitoffset, 1);

     /* pDP-TypeInformation */
     if (pDP_TypeInformation_present)
     {
     	tmp_byte = extract_nbits(tvb, offset, bitoffset, 1) + 1;    /* Sequence 1..2 */
        proceed_nbits(&offset, &bitoffset, 1);
     	for (i=1; i<=tmp_byte; i++)
     	{
     	   tmp_extension = extract_nbits(tvb, offset, bitoffset, 1);
           proceed_nbits(&offset, &bitoffset, 1);
           if (tmp_extension != 0)
           {
              /* extended enum */
              /* decoding is not supported */
              proto_tree_add_text(ie_tree, tvb, offset, IE_PROTOCOL_EXTENSION_LENGTH,
            	                  "Protocol extension for PDP-Type present, dissection not supported");
              return(-1);
           }

           proto_tree_add_uint_bits(ie_tree, hf_ranap_PDP_Type, tvb,
                                    offset, bitoffset, 3, 0);
           proceed_nbits(&offset, &bitoffset, 3);
        }
     }

     /* dataVolumeReportingIndication */
     if (dataVolumeReportingIndication_present)
     {
       proto_tree_add_uint_bits(ie_tree, hf_ranap_dataVolumeReportingIndication, tvb,
                                offset, bitoffset, 1, 0);
       proceed_nbits(&offset, &bitoffset, 1);
     }

     /* dl-GTP-PDU-SequenceNumber */
     if (dl_GTP_PDU_SequenceNumber_present)
     {
     	allign(&offset, &bitoffset);
     	proto_tree_add_item(ie_tree, hf_ranap_dl_GTP_PDU_SequenceNumber, tvb, offset, 2, FALSE);
        offset += 2;
     }

     /* ul-GTP-PDU-SequenceNumber */
     if (ul_GTP_PDU_SequenceNumber_present)
     {
     	allign(&offset, &bitoffset);
     	proto_tree_add_item(ie_tree, hf_ranap_ul_GTP_PDU_SequenceNumber, tvb, offset, 2, FALSE);
        offset += 2;
     }

     /* dl-N-PDU-SequenceNumber	*/
     if (dl_N_PDU_SequenceNumber_present)
     {
     	allign(&offset, &bitoffset);
     	proto_tree_add_item(ie_tree, hf_ranap_dl_N_PDU_SequenceNumber, tvb, offset, 2, FALSE);
        offset += 2;
     }

     /* ul-N-PDU-SequenceNumber */
     if (ul_N_PDU_SequenceNumber_present)
     {
     	allign(&offset, &bitoffset);
     	proto_tree_add_item(ie_tree, hf_ranap_ul_N_PDU_SequenceNumber, tvb, offset, 2, FALSE);
        offset += 2;
     }

     /* iE-Extensions */
     if (iE_Extensions_present)
     {
      	if ((ret=dissect_iE_Extension(tvb, ie_tree, &offset, &bitoffset, "SetupOrModifyItemSecond")) != 0)
      	     return (ret);
     }

     /* protocol extended */
     if (extension_present)
     {
        /* extended enum */
        /* decoding is not supported */
        proto_tree_add_text(ie_tree, tvb, offset, IE_PROTOCOL_EXTENSION_LENGTH,
      	                  "Protocol extension for SetupOrModifyItemSecond present, dissection not supported");
        return(-1);
     }
  }
  return(0);
}


static int
dissect_IE_RAB_SetupOrModifiedItem (tvbuff_t *tvb, proto_tree *ie_tree)
{
   proto_item	*optionals_item = NULL;
   proto_tree	*optionals_tree = NULL;
   int		ret;
   int		extension_present;
   int		transportLayerAddress_present;
   int		iuTransportAssociation_present;
   int		dl_dataVolumes_present;
   int		iE_Extensions_present;
   gint		offset = 0;
   gint		bitoffset = 0;


  if (ie_tree)
  {
     /* create subtree for extension/optional/default bitmap */
     optionals_item = proto_tree_add_text(ie_tree, tvb, offset, 1,
                                        "RAB-SetupOrModifiedItem Extension/Optional/Default bitmap");
     optionals_tree = proto_item_add_subtree(optionals_item, ett_ranap_optionals);

     /* protocol_extension present ? */
     extension_present = extract_nbits(tvb, offset, bitoffset, 1);
     proto_tree_add_uint_bits(optionals_tree, hf_ranap_ie_protocol_extension, tvb,
                              offset, bitoffset, 1, 0);
     proceed_nbits(&offset, &bitoffset, 1);

     /* transportLayerAddress present ? */
     transportLayerAddress_present = extract_nbits(tvb, offset, bitoffset, 1);
     proto_tree_add_uint_bits(optionals_tree, hf_ranap_transportLayerAddress_present, tvb,
                              offset, bitoffset, 1, 0);
     proceed_nbits(&offset, &bitoffset, 1);

     /* iuTransportAssociation present ? */
     iuTransportAssociation_present = extract_nbits(tvb, offset, bitoffset, 1);
     proto_tree_add_uint_bits(optionals_tree, hf_ranap_iuTransportAssociation_present, tvb,
                              offset, bitoffset, 1, 0);
     proceed_nbits(&offset, &bitoffset, 1);

     /* dl_dataVolumes present ? */
     dl_dataVolumes_present = extract_nbits(tvb, offset, bitoffset, 1);
     proto_tree_add_uint_bits(optionals_tree, hf_ranap_dl_dataVolumes_present, tvb,
                              offset, bitoffset, 1, 0);
     proceed_nbits(&offset, &bitoffset, 1);

     /* iE_Extensions present ? */
     iE_Extensions_present = extract_nbits(tvb, offset, bitoffset, 1);
     proto_tree_add_uint_bits(optionals_tree, hf_ranap_iE_Extensions_present, tvb,
                              offset, bitoffset, 1, 0);
     proceed_nbits(&offset, &bitoffset, 1);


     /* rAB-ID */
     proto_tree_add_uint_bits(ie_tree, hf_ranap_rab_id,
                             tvb, offset, bitoffset, 8, 0);
     proceed_nbits(&offset, &bitoffset, 8);

     /* transportLayerAddress */
     if (transportLayerAddress_present)
     {
        if ((ret=dissect_TransportLayerAddress(tvb, ie_tree, &offset, &bitoffset)) != 0)
            return (ret);
     }

     /* iuTransportAssociation	*/
     if (iuTransportAssociation_present)
     {
        if ((ret=dissect_iuTransportAssociation(tvb, ie_tree, &offset, &bitoffset)) != 0)
            return (ret);
     }

     /* dl-dataVolumes	*/
     if (dl_dataVolumes_present)
     {
        if ((ret = dissect_dataVolumeList(tvb, ie_tree, &offset, &bitoffset,
                                          "dl-dataVolumes")) != 0)
            return (ret);
     }

     /* iE-Extensions	*/
     if (iE_Extensions_present)
     {
       if ((ret=dissect_iE_Extension(tvb, ie_tree, &offset, &bitoffset, "RAB_SetupOrModifiedItem")) != 0)
       	   return (ret);
     }

     /* protocol extended */
     if (extension_present)
     {
        /* extended sequence */
        /* decoding is not supported */
        proto_tree_add_text(ie_tree, tvb, offset, IE_PROTOCOL_EXTENSION_LENGTH,
     	                  "Protocol extension for RAB_SetupOrModifiedItem present, dissection not supported");
        return(-1);
     }
  }

  return (0);
}


static int
dissect_IE_RAB_SetupOrModifyItemFirst (tvbuff_t *tvb, proto_tree *ie_tree)
{
  gint		offset;
  gint		bitoffset;
  proto_item	*optionals_item = NULL;
  proto_tree	*optionals_tree = NULL;
  int		extension_present;
  int 		nAS_SynchronisationIndicator_present;
  int		rAB_Parameters_present;
  int		userPlaneInformation_present;
  int		transportLayerInformation_present;
  int		service_Handover_present;
  int		iE_Extensions_present;
  int		tmp_extension_present;
  int		ret;

  if (ie_tree)
  {
    offset = 0; bitoffset = 0;

    /* create subtree for extension/optional/default bitmap */
    optionals_item = proto_tree_add_text(ie_tree, tvb, offset,IE_PROTOCOL_EXTENSION_LENGTH,
                                      "RAB_SetupOrModifyItemFirst Extension/Optional/Default bitmap");
    optionals_tree = proto_item_add_subtree(optionals_item, ett_ranap_optionals);

    /* protocol extension present ? */
    extension_present = extract_nbits(tvb, offset, bitoffset, 1);
    proto_tree_add_uint_bits(optionals_tree, hf_ranap_ie_protocol_extension,
                             tvb, offset, bitoffset, 1, 0);
    proceed_nbits(&offset, &bitoffset, 1);

    /* nAS_SynchronisationIndicator present ? */
    nAS_SynchronisationIndicator_present = extract_nbits(tvb, offset, bitoffset, 1);
    proto_tree_add_uint_bits(optionals_tree, hf_ranap_nAS_SynchronisationIndicator_present,
                             tvb, offset, bitoffset, 1, 0);
    proceed_nbits(&offset, &bitoffset, 1);

    /* rAB_Parameters present ? */
    rAB_Parameters_present = extract_nbits(tvb, offset, bitoffset, 1);
    proto_tree_add_uint_bits(optionals_tree, hf_ranap_rAB_Parameters_present,
                             tvb, offset, bitoffset, 1, 0);
    proceed_nbits(&offset, &bitoffset, 1);

    /* userPlaneInformation present ? */
    userPlaneInformation_present = extract_nbits(tvb, offset, bitoffset, 1);
    proto_tree_add_uint_bits(optionals_tree, hf_ranap_userPlaneInformation_present,
                             tvb, offset, bitoffset, 1, 0);
    proceed_nbits(&offset, &bitoffset, 1);

    /* transportLayerInformation present ? */
    transportLayerInformation_present = extract_nbits(tvb, offset, bitoffset, 1);
    proto_tree_add_uint_bits(optionals_tree, hf_ranap_transportLayerInformation_present,
                             tvb, offset, bitoffset, 1, 0);
    proceed_nbits(&offset, &bitoffset, 1);

    /* service_Handover present ? */
    service_Handover_present = extract_nbits(tvb, offset, bitoffset, 1);
    proto_tree_add_uint_bits(optionals_tree, hf_ranap_service_Handover_present,
                             tvb, offset, bitoffset, 1, 0);
    proceed_nbits(&offset, &bitoffset, 1);

    /* iE_Extensions present ? */
    iE_Extensions_present = extract_nbits(tvb, offset, bitoffset, 1);
    proto_tree_add_uint_bits(optionals_tree, hf_ranap_iE_Extensions_present,
                             tvb, offset, bitoffset, 1, 0);
    proceed_nbits(&offset, &bitoffset, 1);


    /* add RAB-ID */
    proto_tree_add_uint_bits(ie_tree, hf_ranap_rab_id,
                             tvb, offset, bitoffset, 8, 0);
    proceed_nbits(&offset, &bitoffset, 8);

    /* nAS-SynchronisationIndicator */
    if (nAS_SynchronisationIndicator_present)
    {
       proto_tree_add_uint_bits(ie_tree, hf_ranap_nAS_SynchronisationIndicator,
                             tvb, offset, bitoffset, 4, 0);
       proceed_nbits(&offset, &bitoffset, 4);
    }

    /* rAB-Parameters */
    if (rAB_Parameters_present)
    {
       if ((ret=dissect_rAB_Parameters(tvb, ie_tree, &offset, &bitoffset)) != 0)
           return(ret);
    }

    /* userPlaneInformation */
    if (userPlaneInformation_present)
    {
       if ((ret=dissect_userPlaneInformation(tvb, ie_tree, &offset, &bitoffset)) != 0)
           return(ret);
    }

   /* transportLayerInformation */
    if (transportLayerInformation_present)
    {
       if ((ret=dissect_transportLayerInformation(tvb, ie_tree, &offset, &bitoffset)) != 0)
           return(ret);
    }

    /* service_Handover */
    if (service_Handover_present)
    {
       tmp_extension_present = extract_nbits(tvb, offset, bitoffset, 1);
       proceed_nbits(&offset, &bitoffset, 1);

       if (tmp_extension_present)
       {
       	  /* extended enum */
          /* decoding is not supported */
          proto_tree_add_text(ie_tree, tvb, offset, IE_PROTOCOL_EXTENSION_LENGTH,
        	                  "Protocol extension for service_Handover present, dissection not supported");
          return(-1);
       }

       proto_tree_add_uint_bits(ie_tree, hf_ranap_service_Handover,
                            tvb, offset, bitoffset, 2, 0);
       proceed_nbits(&offset, &bitoffset, 2);
    }

   /* iE-Extensions */
   if (iE_Extensions_present)
   {
     if ((ret=dissect_iE_Extension(tvb, ie_tree, &offset, &bitoffset, "SetupOrModifyItemFirst" )) != 0)
      	        return(ret);
   }

  }
  return(0);
}


static int
dissect_IE_RAB_ReleaseItem(tvbuff_t *tvb, proto_tree *ie_tree)
{
  proto_item	*optionals_item = NULL;
  proto_tree	*optionals_tree = NULL;
  gint		offset = 0;
  gint		bitoffset = 0;
  int		extension_present;
  int		iE_Extensions_present;
  int		ret;


  /* create subtree for extension/optional/default bitmap */
  optionals_item = proto_tree_add_text(ie_tree, tvb, offset,IE_PROTOCOL_EXTENSION_LENGTH,
                                    "RAB_ReleaseItem Extension/Optional/Default bitmap");
  optionals_tree = proto_item_add_subtree(optionals_item, ett_ranap_optionals);

  /* protocol extension present ? */
  extension_present = extract_nbits(tvb, offset, bitoffset, 1);
  proto_tree_add_uint_bits(optionals_tree, hf_ranap_ie_protocol_extension,
                           tvb, offset, bitoffset, 1, 0);
  proceed_nbits(&offset, &bitoffset, 1);


  /* iE_Extensions present ? */
  iE_Extensions_present = extract_nbits(tvb, offset, bitoffset, 1);
  proto_tree_add_uint_bits(optionals_tree, hf_ranap_iE_Extensions_present,
                           tvb, offset, bitoffset, 1, 0);
  proceed_nbits(&offset, &bitoffset, 1);


  /* add RAB-ID */
  proto_tree_add_uint_bits(ie_tree, hf_ranap_rab_id,
                           tvb, offset, bitoffset, 8, 0);
  proceed_nbits(&offset, &bitoffset, 8);


  /* add cause */
  if ((ret=dissect_cause(tvb, ie_tree, &offset, &bitoffset)) != 0)
   	     return (ret);

  /* iE Extensions */
  if (iE_Extensions_present)
  {
   	if ((ret=dissect_iE_Extension(tvb, ie_tree, &offset, &bitoffset, "RAB_ReleasedItem")) != 0)
   	     return (ret);
  }

  /* protocol extended */
  if (extension_present)
  {
     /* extended sequence */
     /* decoding is not supported */
     proto_tree_add_text(ie_tree, tvb, offset, IE_PROTOCOL_EXTENSION_LENGTH,
   	                  "Protocol extension for RAB_ReleasedItem present, dissection not supported");
     return(-1);
  }

  return(0);
}


static int
dissect_IE_RAB_ReleasedItem (tvbuff_t *tvb, proto_tree *ie_tree)
{
   proto_item	*optionals_item = NULL;
   proto_tree	*optionals_tree = NULL;
   int		ret;
   int		extension_present;
   int		dl_dataVolumes_present;
   int		dl_GTP_PDU_SequenceNumber_present;
   int		ul_GTP_PDU_SequenceNumber_present;
   int		iE_Extensions_present;
   gint		offset = 0;
   gint		bitoffset = 0;

  if (ie_tree)
  {
     /* create subtree for extension/optional/default bitmap */
     optionals_item = proto_tree_add_text(ie_tree, tvb, offset, 1,
                                        "RAB-ReleasedItem Extension/Optional/Default bitmap");
     optionals_tree = proto_item_add_subtree(optionals_item, ett_ranap_optionals);

     /* protocol_extension present ? */
     extension_present = extract_nbits(tvb, offset, bitoffset, 1);
     proto_tree_add_uint_bits(optionals_tree, hf_ranap_ie_protocol_extension, tvb,
                              offset, bitoffset, 1, 0);
     proceed_nbits(&offset, &bitoffset, 1);

     /* dl_dataVolumes present ? */
     dl_dataVolumes_present = extract_nbits(tvb, offset, bitoffset, 1);
     proto_tree_add_uint_bits(optionals_tree, hf_ranap_dl_dataVolumes_present, tvb,
                              offset, bitoffset, 1, 0);
     proceed_nbits(&offset, &bitoffset, 1);

     /* dL_GTP_PDU_SequenceNumber present ? */
     dl_GTP_PDU_SequenceNumber_present = extract_nbits(tvb, offset, bitoffset, 1);
     proto_tree_add_uint_bits(optionals_tree, hf_ranap_dl_GTP_PDU_SequenceNumber_present,
                              tvb, offset, bitoffset, 1, 0);
     proceed_nbits(&offset, &bitoffset, 1);

     /* uL_GTP_PDU_SequenceNumber present ? */
     ul_GTP_PDU_SequenceNumber_present = extract_nbits(tvb, offset, bitoffset, 1);
     proto_tree_add_uint_bits(optionals_tree, hf_ranap_ul_GTP_PDU_SequenceNumber_present,
                              tvb, offset, bitoffset, 1, 0);
     proceed_nbits(&offset, &bitoffset, 1);

     /* iE_Extensions present ? */
     iE_Extensions_present = extract_nbits(tvb, offset, bitoffset, 1);
     proto_tree_add_uint_bits(optionals_tree, hf_ranap_iE_Extensions_present,
                              tvb, offset, bitoffset, 1, 0);
     proceed_nbits(&offset, &bitoffset, 1);

     /* rAB-ID */
     proto_tree_add_uint_bits(ie_tree, hf_ranap_rab_id,
                              tvb, offset, bitoffset, 8, 0);
     proceed_nbits(&offset, &bitoffset, 8);

     /* dl-dataVolumes */
     if (dl_dataVolumes_present)
     {
        if ((ret=dissect_dataVolumeList(tvb, ie_tree, &offset, &bitoffset,
                                        "dl-dataVolumes")) != 0)
            return (ret);
     }

     /* dL-GTP-PDU-SequenceNumber */
     if (dl_GTP_PDU_SequenceNumber_present)
     {
     	allign(&offset, &bitoffset);
     	proto_tree_add_item(ie_tree, hf_ranap_dl_GTP_PDU_SequenceNumber, tvb, offset, 2, FALSE);
        offset += 2;
     }

     /* uL-GTP-PDU-SequenceNumber */
     if (ul_GTP_PDU_SequenceNumber_present)
     {
     	allign(&offset, &bitoffset);
     	proto_tree_add_item(ie_tree, hf_ranap_ul_GTP_PDU_SequenceNumber, tvb, offset, 2, FALSE);
        offset += 2;
     }

     /* iE-Extensions */
     if (iE_Extensions_present)
     {
        if ((ret=dissect_iE_Extension(tvb, ie_tree, &offset, &bitoffset, "UserPlaneInformation")) != 0)
           return(ret);
     }

     /* protocol extended */
     if (extension_present)
     {
        /* extended sequence */
        /* decoding is not supported */
        proto_tree_add_text(ie_tree, tvb, offset, IE_PROTOCOL_EXTENSION_LENGTH,
      	                  "Protocol extension for RAB_ReleasedItem present, dissection not supported");
        return(-1);
     }
  }

  return(0);
}


static int
dissect_IE_RAB_QueuedItem (tvbuff_t *tvb, proto_tree *ie_tree)
{
   proto_item	*optionals_item = NULL;
   proto_tree	*optionals_tree = NULL;
   int		ret;
   int		extension_present;
   int		iE_Extensions_present;
   gint		offset = 0;
   gint		bitoffset = 0;


  if (ie_tree)
  {
     /* create subtree for extension/optional/default bitmap */
     optionals_item = proto_tree_add_text(ie_tree, tvb, offset, 1,
                                        "RAB-QueuedItem Extension/Optional/Default bitmap");
     optionals_tree = proto_item_add_subtree(optionals_item, ett_ranap_optionals);

     /* protocol_extension present ? */
     extension_present = extract_nbits(tvb, offset, bitoffset, 1);
     proto_tree_add_uint_bits(optionals_tree, hf_ranap_ie_protocol_extension, tvb,
                              offset, bitoffset, 1, 0);
     proceed_nbits(&offset, &bitoffset, 1);

     /* iE_Extensions present ? */
     iE_Extensions_present = extract_nbits(tvb, offset, bitoffset, 1);
     proto_tree_add_uint_bits(optionals_tree, hf_ranap_iE_Extensions_present,
                              tvb, offset, bitoffset, 1, 0);
     proceed_nbits(&offset, &bitoffset, 1);

     /* rAB-ID */
     proto_tree_add_uint_bits(ie_tree, hf_ranap_rab_id,
                             tvb, offset, bitoffset, 8, 0);
     proceed_nbits(&offset, &bitoffset, 8);

     /* iE-Extensions */
     if (iE_Extensions_present)
     {
       if ((ret=dissect_iE_Extension(tvb, ie_tree, &offset, &bitoffset, "RAB_QueuedItem" )) != 0 )
        	        return (ret);
     }

     /* protocol extended */
     if (extension_present)
     {
        /* extended sequence */
        /* decoding is not supported */
        proto_tree_add_text(ie_tree, tvb, offset, IE_PROTOCOL_EXTENSION_LENGTH,
      	                  "Protocol extension for RAB_QueuedItem present, dissection not supported");
        return(-1);
     }
  }

  return(0);
}


static int
dissect_IE_RAB_FailedItem(tvbuff_t *tvb, proto_tree *ie_tree)
{
   proto_item	*optionals_item = NULL;
   proto_tree	*optionals_tree = NULL;
   int		ret;
   int		extension_present;
   int		iE_Extensions_present;
   gint		offset = 0;
   gint		bitoffset = 0;

  if (ie_tree)
  {
     /* create subtree for extension/optional/default bitmap */
     optionals_item = proto_tree_add_text(ie_tree, tvb, offset, 1,
                                        "RAB-FailedItem Extension/Optional/Default bitmap");
     optionals_tree = proto_item_add_subtree(optionals_item, ett_ranap_optionals);

     /* protocol_extension present ? */
     extension_present = extract_nbits(tvb, offset, bitoffset, 1);
     proto_tree_add_uint_bits(optionals_tree, hf_ranap_ie_protocol_extension, tvb,
                              offset, bitoffset, 1, 0);
     proceed_nbits(&offset, &bitoffset, 1);

     /* iE_Extensions present ? */
     iE_Extensions_present = extract_nbits(tvb, offset, bitoffset, 1);
     proto_tree_add_uint_bits(optionals_tree, hf_ranap_iE_Extensions_present,
                              tvb, offset, bitoffset, 1, 0);
     proceed_nbits(&offset, &bitoffset, 1);

     /* rAB-ID */
     proto_tree_add_uint_bits(ie_tree, hf_ranap_rab_id,
                             tvb, offset, bitoffset, 8, 0);
     proceed_nbits(&offset, &bitoffset, 8);

     /* cause */
     if ((ret=dissect_cause(tvb, ie_tree, &offset, &bitoffset)) != 0)
   	        return (ret);

     /* iE-Extensions */
     if (iE_Extensions_present)
     {
       if ((ret=dissect_iE_Extension(tvb, ie_tree, &offset, &bitoffset, "RAB-FailedItem")) != 0)
      	     return (ret);
     }


     /* protocol extended */
     if (extension_present)
     {
        /* extended sequence */
        /* decoding is not supported */
        proto_tree_add_text(ie_tree, tvb, offset, IE_PROTOCOL_EXTENSION_LENGTH,
      	                  "Protocol extension for RAB-FailedItem present, dissection not supported");
        return(-1);
     }
  }
  return(0);
}


static int
dissect_IE_CriticalityDiagnostics(tvbuff_t *tvb, proto_tree *ie_tree)

{
   proto_item	*optionals_item = NULL;
   proto_tree	*optionals_tree = NULL;
   int		ret;
   int		extension_present;
   int		procedureCode_present;
   int		triggeringMessage_present;
   int		procedureCriticality_present;
   int		iEsCriticalityDiagnostics_present;
   int 		iE_Extensions_present;
   gint		offset = 0;
   gint		bitoffset = 0;


  if (ie_tree)
  {
     /* create subtree for extension/optional/default bitmap */
     optionals_item = proto_tree_add_text(ie_tree, tvb, offset, 1,
                                        "IE-CriticalityDiagnostics Extension/Optional/Default bitmap");
     optionals_tree = proto_item_add_subtree(optionals_item, ett_ranap_optionals);

     /* protocol_extension present ? */
     extension_present = extract_nbits(tvb, offset, bitoffset, 1);
     proto_tree_add_uint_bits(optionals_tree, hf_ranap_ie_protocol_extension, tvb,
                              offset, bitoffset, 1, 0);
     proceed_nbits(&offset, &bitoffset, 1);

     /* procedureCode present ? */
     procedureCode_present = extract_nbits(tvb, offset, bitoffset, 1);
     proto_tree_add_uint_bits(optionals_tree, hf_ranap_procedureCode_present,
                              tvb, offset, bitoffset, 1, 0);
     proceed_nbits(&offset, &bitoffset, 1);

     /* triggeringMessage present ? */
     triggeringMessage_present = extract_nbits(tvb, offset, bitoffset, 1);
     proto_tree_add_uint_bits(optionals_tree, hf_ranap_triggeringMessage_present,
                              tvb, offset, bitoffset, 1, 0);
     proceed_nbits(&offset, &bitoffset, 1);

     /* procedureCriticality present ? */
     procedureCriticality_present = extract_nbits(tvb, offset, bitoffset, 1);
     proto_tree_add_uint_bits(optionals_tree, hf_ranap_procedureCriticality_present,
                              tvb, offset, bitoffset, 1, 0);
     proceed_nbits(&offset, &bitoffset, 1);

     /* iEsCriticalityDiagnostics present ? */
     iEsCriticalityDiagnostics_present = extract_nbits(tvb, offset, bitoffset, 1);
     proto_tree_add_uint_bits(optionals_tree, hf_ranap_iEsCriticalityDiagnostics_present,
                              tvb, offset, bitoffset, 1, 0);
     proceed_nbits(&offset, &bitoffset, 1);

     /* iE_Extensions present ? */
     iE_Extensions_present = extract_nbits(tvb, offset, bitoffset, 1);
     proto_tree_add_uint_bits(optionals_tree, hf_ranap_iE_Extensions_present,
                              tvb, offset, bitoffset, 1, 0);
     proceed_nbits(&offset, &bitoffset, 1);


     /* procedureCode */
     if (procedureCode_present)
     {
     	allign (&offset, &bitoffset);
        proto_tree_add_item(ie_tree, hf_ranap_procedure_code, tvb, offset, 1, FALSE);
        offset += 1;
     }

     /* triggeringMessage */
     if (triggeringMessage_present)
     {
        proto_tree_add_uint_bits(ie_tree, hf_ranap_triggeringMessage,
                                 tvb, offset, bitoffset, 2, 0);
        proceed_nbits(&offset, &bitoffset, 2);
     }

     /* procedureCriticality */
     if (procedureCriticality_present)
     {
        proto_tree_add_uint_bits(ie_tree, hf_ranap_procedureCriticality,
                                 tvb, offset, bitoffset, 2, 0);
        proceed_nbits(&offset, &bitoffset, 2);
     }

     /* iEsCriticalityDiagnostics */
     if (iEsCriticalityDiagnostics_present)
     {
     	if ((ret=dissect_iEsCriticalityDiagnostics(tvb, ie_tree, &offset, &bitoffset)) != 0)
           return(ret);
     }

     /* iE-Extensions */
     if (iE_Extensions_present)
     {
     	if ((ret=dissect_iE_Extension(tvb, ie_tree, &offset, &bitoffset, "IE_CriticalityDiagnostics")) != 0)
           return(ret);
     }


     /* protocol extended */
     if (extension_present)
     {
        /* extended sequence */
        /* decoding is not supported */
        proto_tree_add_text(ie_tree, tvb, offset, IE_PROTOCOL_EXTENSION_LENGTH,
      	                  "Protocol extension for IE CriticalityDiagnostics present, dissection not supported");
        return(-1);
     }
  }
  return(0);
}


static int
dissect_unknown_IE(tvbuff_t *tvb, proto_tree *ie_tree)
{
  if (ie_tree)
  {
     proto_tree_add_text(ie_tree, tvb, 0, -1,
	   		   "IE Contents (dissection not implemented)");
  }
  return(0);
}



/*****************************************************************************/
/*                                                                           */
/*  Dissecting Functions for IE Lists / Containers                           */
/*                                                                           */
/*****************************************************************************/

static int
dissect_RAB_IE_ContainerPairList(tvbuff_t *tvb, proto_tree *ie_tree)
{
  proto_item	*rab_item = NULL;
  proto_tree	*rab_tree = NULL;
  proto_item	*ie_pair_item = NULL;
  proto_tree	*ie_pair_tree = NULL;
  proto_item	*first_value_item = NULL;
  proto_tree	*first_value_tree = NULL;
  proto_item	*second_value_item = NULL;
  proto_tree	*second_value_tree = NULL;
  guint 	number_of_RABs, currentRAB;
  guint		number_of_IEs, currentIE;
  gint		number_of_octets_first, number_of_octets_second;
  gint		number_of_octets_first_size, number_of_octets_second_size ;
  gint		offset = 0;
  gint		bitoffset = 0;
  gint		tmp_offset;
  guint16	ie_id;
  tvbuff_t	*first_value_tvb;
  tvbuff_t	*second_value_tvb;

  if (ie_tree)
  {
     /* number of RABs in the list */
     number_of_RABs = 1 + tvb_get_guint8(tvb, offset);
     proto_tree_add_uint(ie_tree, hf_ranap_num_rabs,
	                 tvb, offset,
		         NUM_RABS_LENGTH, number_of_RABs);

     offset += NUM_RABS_LENGTH;

     /* do for each RAB */
     for (currentRAB=1; currentRAB<=number_of_RABs; currentRAB++)
     {
     	/* create subtree for RAB */
        rab_item = proto_tree_add_text(ie_tree, tvb, offset, 0, "%d. RAB", currentRAB);
        rab_tree = proto_item_add_subtree(rab_item, ett_ranap_rab);

     	/* number of IE pairs for this RAB */
        number_of_IEs = tvb_get_ntohs(tvb, offset);
        proto_tree_add_uint(rab_tree, hf_ranap_number_of_ies_in_list,
		            tvb, offset, 2, number_of_IEs);

        offset += 2; /*points now to beginning of first IE pair */

        /* do for each IE pair */
        for (currentIE=1; currentIE<=number_of_IEs; currentIE++)
        {
           /*  use tmp_offset to point to current field */
           tmp_offset = offset;
           /* IE pair ID */
           ie_id = tvb_get_ntohs(tvb, tmp_offset);
           tmp_offset += IE_ID_LENGTH;

           tmp_offset += 1; /* skip first criticality byte */
           /* number of octets in first value */
           extract_length(tvb, tmp_offset, &number_of_octets_first, &number_of_octets_first_size);
           tmp_offset += number_of_octets_first_size + number_of_octets_first;

           tmp_offset += 1; /* skip second criticality byte */
           /* number of octets in second value */
           extract_length(tvb, tmp_offset, &number_of_octets_second, &number_of_octets_second_size);
           tmp_offset += number_of_octets_second_size + number_of_octets_second;

           /* create subtree for ie_pair */
           ie_pair_item = proto_tree_add_text(rab_tree, tvb, offset,
           			     tmp_offset - offset,
                                     "%s IE Pair (%u)",
                                     val_to_str(ie_id, ranap_ie_id_values, "Unknown"),
                                     ie_id);
           ie_pair_tree = proto_item_add_subtree(ie_pair_item, ett_ranap_ie_pair);

           /* add fields to ie pair subtee */
           /* use offset to point to current field */
            /* IE ID */
           proto_tree_add_item(ie_pair_tree, hf_ranap_ie_ie_id, tvb, offset, IE_ID_LENGTH, FALSE);
           offset += IE_ID_LENGTH;

           /* first criticality */
           proto_tree_add_uint_bits(ie_pair_tree, hf_ranap_ie_pair_first_criticality, tvb,
                                    offset, bitoffset, 2, 0);
           proceed_nbits(&offset, &bitoffset, 2);

           /* number of octets in first value */
           allign(&offset, &bitoffset);
           if (number_of_octets_first != 0)
           {
              proto_tree_add_uint(ie_pair_tree, hf_ranap_first_value_number_of_octets,
	                          tvb, offset,
	                          number_of_octets_first_size,
	                          number_of_octets_first);
           }
           else
           {
    	      /* decoding is not supported */
    	      proto_tree_add_text(ie_pair_tree, tvb, offset,
    	                    2, "Number of Octets greater than 0x3FFF, dissection not supported");
    	      return(-1);
           }
           offset += number_of_octets_first_size;

           /* add subtree for first value */
           first_value_item = proto_tree_add_text(ie_pair_tree, tvb, offset,
                                     number_of_octets_first,
                                     "%sFirst",
                                     val_to_str(ie_id, ranap_ie_id_values, "Unknown"));
           first_value_tree = proto_item_add_subtree(first_value_item, ett_ranap_ie_pair_first_value);

           /* create tvb containing first value */
           first_value_tvb = tvb_new_subset(tvb, offset, number_of_octets_first, number_of_octets_first);

           /* add fields of first value */
           switch (ie_id)
           {
              case  IE_RAB_SetupOrModifyItem:
                 dissect_IE_RAB_SetupOrModifyItemFirst (first_value_tvb, first_value_tree);
                 break;

              default:
                 dissect_unknown_IE(first_value_tvb, first_value_tree);
                 break;
           }

           offset += number_of_octets_first;


           /* second criticality */
           proto_tree_add_uint_bits(ie_pair_tree, hf_ranap_ie_pair_second_criticality, tvb,
                                    offset, bitoffset, 2, 0);
           proceed_nbits(&offset, &bitoffset, 2);

           /* number of octets of second value */
           allign(&offset, &bitoffset);
           if (number_of_octets_second != 0)
           {
              proto_tree_add_uint(ie_pair_tree, hf_ranap_second_value_number_of_octets,
	                          tvb, offset,
	                          number_of_octets_second_size,
	                          number_of_octets_second);
           }
           else
           {
    	      /* decoding is not supported */
    	      proto_tree_add_text(ie_pair_tree, tvb, offset,
    	                    2, "Number of Octets greater than 0x3FFF, dissection not supported");
    	      return(-1);
           }
           offset += number_of_octets_second_size;

           /* add subtree for second value */
           second_value_item = proto_tree_add_text(ie_pair_tree, tvb, offset,
                                     number_of_octets_second,
                                     "%sSecond",
                                     val_to_str(ie_id, ranap_ie_id_values, "Unknown"));
           second_value_tree = proto_item_add_subtree(second_value_item, ett_ranap_ie_pair_second_value);

           /* create tvb containing first value */
           second_value_tvb = tvb_new_subset(tvb, offset, number_of_octets_second, number_of_octets_second);

           /* add fields of second value */
           switch (ie_id)
           {
              case  IE_RAB_SetupOrModifyItem:
                 dissect_IE_RAB_SetupOrModifyItemSecond (second_value_tvb, second_value_tree);
                 break;

              default:
                 dissect_unknown_IE(second_value_tvb, second_value_tree);
                 break;
           }

           offset += number_of_octets_second;

        }/* for each IE ... */
     }/* for each RAB ... */
   }
   return(0);
}


static int
dissect_RAB_IE_ContainerList(tvbuff_t *tvb, proto_tree *list_tree)
{
  proto_item	*rab_item = NULL;
  proto_tree	*rab_tree = NULL;
  proto_item	*ie_item = NULL;
  proto_tree	*ie_tree = NULL;

  guint		number_of_RABs, currentRAB;
  guint		number_of_IEs, currentIE;
  gint		ie_number_of_octets = 0;
  gint		ie_number_of_octets_size = 0;
  gint		offset = 0;
  gint		bitoffset = 0;
  gint		ie_offset = 0;
  gint		ie_header_length;
  guint16	ie_id;
  tvbuff_t	*ie_tvb;


  if (list_tree)
  {
     /* number of RABs in the list */
     number_of_RABs = 1 + tvb_get_guint8(tvb, offset);
     proto_tree_add_uint(list_tree, hf_ranap_num_rabs,
	                 tvb, offset,
		         NUM_RABS_LENGTH, number_of_RABs);

     offset +=  NUM_RABS_LENGTH;

     /* do for each RAB */
     for (currentRAB=1; currentRAB<=number_of_RABs; currentRAB++)
     {
     	/* create subtree for RAB */
        rab_item = proto_tree_add_text(list_tree, tvb, offset, 0, "%d. RAB", currentRAB);
        rab_tree = proto_item_add_subtree(rab_item, ett_ranap_rab);

     	/* number of IEs for this RAB */
        number_of_IEs = tvb_get_ntohs(tvb, offset);
        proto_tree_add_uint(rab_tree, hf_ranap_number_of_ies_in_list,
		            tvb, offset, 2, number_of_IEs);

        offset += 2; /*points now to beginning of first IE in list */
        ie_offset = offset;

        /* do for each IE */
        for (currentIE=1; currentIE<=number_of_IEs; currentIE++)
        {
           /* extract IE ID */
           ie_id = tvb_get_ntohs(tvb, offset);
           offset += IE_ID_LENGTH;

           offset += IE_CRITICALITY_LENGTH; /* skip criticality byte */

           /* number of octets */
           extract_length(tvb, offset, &ie_number_of_octets, &ie_number_of_octets_size);
           ie_header_length = IE_ID_LENGTH + IE_CRITICALITY_LENGTH + ie_number_of_octets_size;

           /* reset offset to beginning of ie */
           offset = ie_offset;

           /* create subtree for ie */
           ie_item = proto_tree_add_text(rab_tree, tvb, offset,
                             ie_header_length + ie_number_of_octets,
                             "%s IE (%u)",
                             val_to_str(ie_id, ranap_ie_id_values, "Unknown"),
                             ie_id);
           ie_tree = proto_item_add_subtree(ie_item, ett_ranap_ie);

           /* IE ID */
           proto_tree_add_item(ie_tree, hf_ranap_ie_ie_id, tvb,
                               offset, IE_ID_LENGTH, FALSE);
           offset += IE_ID_LENGTH;

           /* criticality */
           proto_tree_add_uint_bits(ie_tree, hf_ranap_ie_criticality, tvb,
                                    offset, bitoffset, 2, 0);
           proceed_nbits(&offset, &bitoffset, 2);

           allign(&offset, &bitoffset);
           if (ie_number_of_octets != 0)
           {
              proto_tree_add_uint(ie_tree, hf_ranap_ie_number_of_octets, tvb,
                                  offset, ie_number_of_octets_size, ie_number_of_octets);
           }
           else
           {
          	  /* decoding is not supported */
        	  proto_tree_add_text(ie_tree, tvb, offset,
        	                    0, "Number of Octets greater than 0x3FFF, dissection not supported");
        	  return(-1);
           }
           offset += ie_number_of_octets_size;


           /* create tvb containing ie */
           ie_tvb = tvb_new_subset(tvb, offset, ie_number_of_octets, ie_number_of_octets);

           /* add fields of ie */
           switch (ie_id)
           {
              case  IE_RAB_SetupOrModifiedItem:
                 dissect_IE_RAB_SetupOrModifiedItem(ie_tvb, ie_tree);
                 break;
              case  IE_RAB_ReleaseItem:
                 dissect_IE_RAB_ReleaseItem(ie_tvb, ie_tree);
                 break;
              case  IE_RAB_ReleasedItem:
                 dissect_IE_RAB_ReleasedItem(ie_tvb, ie_tree);
                 break;
              case  IE_RAB_ReleasedItem_IuRelComp:
                 dissect_IE_RAB_ReleasedItem_IuRelComp(ie_tvb, ie_tree);
                 break;
              case  IE_RAB_QueuedItem:
                 dissect_IE_RAB_QueuedItem(ie_tvb, ie_tree);
                 break;
              case  IE_RAB_FailedItem:
                 dissect_IE_RAB_FailedItem(ie_tvb, ie_tree);
                 break;
              case  IE_RAB_DataVolumeReportItem:
                 dissect_IE_RAB_DataVolumeReportItem(ie_tvb, ie_tree);
                 break;
              default:
                 dissect_unknown_IE(ie_tvb, ie_tree);
                 break;
           }

           ie_offset += (ie_header_length + ie_number_of_octets);
           offset = ie_offset;
        } /* for each IE */
     } /* for each RAB */
   }
   return (0);
}


static int
dissect_ranap_ie(guint16 ie_id, tvbuff_t *ie_contents_tvb, proto_tree *ie_tree)
{
     /* call specific dissection function for ie contents */
     switch(ie_id)
     {
        case IE_RAB_ID:
           return(dissect_IE_RAB_ID(ie_contents_tvb, ie_tree));
           break;
        case IE_NAS_PDU:
           return(dissect_IE_NAS_PDU(ie_contents_tvb, ie_tree));
           break;
        case IE_LAI:
           return(dissect_IE_LAI(ie_contents_tvb, ie_tree));
           break;
        case IE_RAC:
           return(dissect_IE_RAC(ie_contents_tvb, ie_tree));
           break;
        case IE_SAI:
           return(dissect_IE_SAI(ie_contents_tvb, ie_tree));
           break;
        case IE_GlobalRNC_ID:
	   return(dissect_IE_GlobalRNC_ID(ie_contents_tvb, ie_tree));
           break;
        case IE_CN_DomainIndicator:
           return(dissect_IE_CN_DomainIndicator(ie_contents_tvb, ie_tree));
           break;
        case IE_IuSigConId:
           return(dissect_IE_IuSigConId(ie_contents_tvb, ie_tree));
           break;
        case IE_SAPI:
           return(dissect_IE_SAPI(ie_contents_tvb, ie_tree));
           break;
        case IE_TransportLayerAddress:
           return(dissect_IE_TransportLayerAddress(ie_contents_tvb, ie_tree));
           break;
        case IE_IuTransportAssociation:
           return(dissect_IE_IuTransportAssociation(ie_contents_tvb, ie_tree));
           break;
        case IE_RAB_SetupOrModifyList:
           return(dissect_RAB_IE_ContainerPairList(ie_contents_tvb, ie_tree));
           break;
        case IE_RAB_SetupOrModifiedList:
        case IE_RAB_ReleaseList:
        case IE_RAB_ReleasedList:
        case IE_RAB_QueuedList:
        case IE_RAB_FailedList:
        case IE_RAB_ReleaseFailedList:
        case IE_RAB_DataVolumeReportList:
        case IE_RAB_ReleasedList_IuRelComp:
        case IE_RAB_RelocationReleaseList:
        case IE_RAB_DataForwardingList:
        case IE_RAB_SetupList_RelocReq:
        case IE_RAB_SetupList_RelocReqAck:
        case IE_RAB_DataForwardingList_SRNS_CtxReq:
        case IE_RAB_ContextList:
        case IE_RAB_ContextFailedtoTransferList:
        case IE_RAB_DataVolumeReportRequestList:
        case IE_RAB_FailedtoReportList:
        case IE_RAB_ContextList_RANAP_RelocInf:
           return(dissect_RAB_IE_ContainerList(ie_contents_tvb, ie_tree));
           break;
        case IE_CriticalityDiagnostics:
           return(dissect_IE_CriticalityDiagnostics(ie_contents_tvb, ie_tree));
           break;
        case IE_Cause:
           return(dissect_IE_Cause(ie_contents_tvb, ie_tree));
           break;
        default:
           return(dissect_unknown_IE(ie_contents_tvb, ie_tree));
           break;
     }
}


static int
dissect_ranap_ie_container(tvbuff_t *tvb, proto_tree *ranap_tree)
{
  proto_item	*ie_item = NULL;
  proto_tree	*ie_tree = NULL;
  proto_item	*optionals_item = NULL;
  proto_tree	*optionals_tree = NULL;

  int		msg_extension_present;
  int		ProtocolExtensionContainer_present;

  guint16	number_of_ies;
  guint16	ie_id;
  gint		ie_number_of_octets = 0;
  gint		ie_number_of_octets_size = 0;
  guint16	ie_header_length;
  gint		offset = 0;
  gint		bitoffset = 0;
  gint		i, ie_offset;
  tvbuff_t	*ie_contents_tvb;

  if (ranap_tree)
  {
     /* create subtree for extension/optional bitmap of message */
     optionals_item = proto_tree_add_text(ranap_tree, tvb, offset, 1,
                                        "Message Extension/Optional/Default bitmap");
     optionals_tree = proto_item_add_subtree(optionals_item, ett_ranap_optionals);
  }

  /* msg_extension present ? */
  msg_extension_present = extract_nbits(tvb, offset, bitoffset, 1);

  if (ranap_tree)
  {
     proto_tree_add_uint_bits(optionals_tree, hf_ranap_msg_extension_present, tvb,
                              offset, bitoffset, 1, 0);
  }
  proceed_nbits(&offset, &bitoffset, 1);

  /* ProtocolExtensionContainer present ? */
  ProtocolExtensionContainer_present = extract_nbits(tvb, offset, bitoffset, 1);
  if (ranap_tree)
  {
      proto_tree_add_uint_bits(optionals_tree, hf_ranap_ProtocolExtensionContainer_present,
                              tvb, offset, bitoffset, 1, 0);
  }
  proceed_nbits(&offset, &bitoffset, 1);


  /* extract ie container data */
  /* number of ies */
  allign(&offset, &bitoffset);
  number_of_ies = tvb_get_ntohs(tvb, offset);
  if (ranap_tree)
  {
     proto_tree_add_uint(ranap_tree, hf_ranap_number_of_ies,
		         tvb, offset, 2, number_of_ies);
  }
  offset += 2;

  ie_offset = offset; /* ie_offset marks beginning of IE-Header */

  /* do the following for each IE in the PDU */
  for (i=1; i <= number_of_ies; i++)
  {
     /* extract IE header fields which are needed even if no ranap tree exists*/
     /* IE-ID */
     ie_id = tvb_get_ntohs(tvb, offset);
     offset += IE_ID_LENGTH;

    /* number of octets in the IE */
    offset += IE_CRITICALITY_LENGTH; /* skip criticality byte */
    ie_number_of_octets = 0;
    extract_length(tvb, offset, &ie_number_of_octets, &ie_number_of_octets_size);
    ie_header_length = IE_ID_LENGTH + IE_CRITICALITY_LENGTH + ie_number_of_octets_size;

    if (ranap_tree)
    {
       offset = ie_offset; /* start from beginning of IE */
       /* create subtree for ie */
       ie_item = proto_tree_add_text(ranap_tree, tvb, offset,
                                     ie_header_length + ie_number_of_octets,
                                     "%s IE (%u)",
                                     val_to_str(ie_id, ranap_ie_id_values, "Unknown"),
                                     ie_id);
       ie_tree = proto_item_add_subtree(ie_item, ett_ranap_ie);

       /* add fields to ie subtee */
       /* IE ID */
       proto_tree_add_item(ie_tree, hf_ranap_ie_ie_id, tvb,
                           offset, IE_ID_LENGTH, FALSE);
       offset += IE_ID_LENGTH;

       /* criticality */
       proto_tree_add_uint_bits(ie_tree, hf_ranap_ie_criticality, tvb,
                                offset, bitoffset, 2, 0);
       proceed_nbits(&offset, &bitoffset, 2);

       /* number of octets */
       allign(&offset, &bitoffset);
       if (ie_number_of_octets != 0)
       {
          proto_tree_add_uint(ie_tree, hf_ranap_ie_number_of_octets, tvb,
                              offset, ie_number_of_octets_size, ie_number_of_octets);
          offset += ie_number_of_octets_size;
       }
       else
       {
      	  /* decoding is not supported */
    	  proto_tree_add_text(ranap_tree, tvb, offset,
    	                      2, "Number of Octets greater than 0x3FFF, dissection not supported");
    	  return(-1);
       }
     }

     /* check if number_of_octets could be decoded */
     /* in case we skipped if (ranap_tree) {....} */
     if (ie_number_of_octets == 0) return (-1);

     /* create tvb containing the ie contents */
     ie_contents_tvb = tvb_new_subset(tvb, ie_offset + ie_header_length,
                                      ie_number_of_octets, ie_number_of_octets);

     /* call specific dissection function for ie contents */
     dissect_ranap_ie(ie_id, ie_contents_tvb, ie_tree);

     /* set ie_offset to beginning of next ie */
     ie_offset += (ie_header_length + ie_number_of_octets);
     offset = ie_offset;
  }

  /* protocol Extensions */
  if (ProtocolExtensionContainer_present)
  {
     return(dissect_iE_Extension(tvb, ranap_tree, &offset, &bitoffset, "PDU"));
  }

  return(0);

}


static void
dissect_ranap(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
  proto_item	*ranap_item = NULL;
  proto_tree	*ranap_tree = NULL;

  guint		procedure_code;
  guint		pdu_index;
  gint		number_of_octets = 0;
  gint		number_of_octets_size = 0;
  gint		offset = 0;
  gint		tmp_offset = 0;
  gint		bitoffset = 0;
  gint		tmp_bitoffset = 0;
  guint		extension_present;

  tvbuff_t	*ie_tvb;


  g_pinfo = pinfo;

  /* make entry in the Protocol column on summary display */
  if (check_col(pinfo->cinfo, COL_PROTOCOL))
    col_set_str(pinfo->cinfo, COL_PROTOCOL, "RANAP");

  /* extract header fields which are needed even if no tree exists */

  /* protocol_extension present ? */
  extension_present = extract_nbits(tvb, tmp_offset, tmp_bitoffset, 1);
  proceed_nbits(&tmp_offset, &tmp_bitoffset, 1);
  if (extension_present)
  {
      /* extended choice */
      /* decoding is not supported */
      if (check_col(pinfo->cinfo, COL_INFO))
      {
	  col_append_str(pinfo->cinfo, COL_INFO, "RANAP-PDU Protocol extension present, dissection not supported");
      }

      if (tree)
      {
	  proto_tree_add_text(tree, tvb, 0, -1, "RANAP Message");
      }
      return;
  }

  /* pdu_index choice 0..3 */
  pdu_index = extract_nbits(tvb, tmp_offset, tmp_bitoffset, 2);
  proceed_nbits(&tmp_offset, &tmp_bitoffset, 2);

  /* procedure code */
  allign(&tmp_offset, &tmp_bitoffset);
  procedure_code = tvb_get_guint8(tvb, tmp_offset);
  tmp_offset += 1;

  /* add Procedure Code to Info Column */
  if (check_col(pinfo->cinfo, COL_INFO))
  {
    if (procedure_code <= PC_max)
    {
       col_add_fstr(pinfo->cinfo, COL_INFO, "%s ",
                   val_to_str(pdu_index, ranap_message_names[procedure_code],
                              "unknown message"));
    }
  }

  /* extract number of octets */
  tmp_offset += 1; /* leave out criticality byte */
  extract_length(tvb, tmp_offset, &number_of_octets, &number_of_octets_size);

  /* In the interest of speed, if "tree" is NULL, don't do any work not
     necessary to generate protocol tree items. */
  if (tree)
  {
    g_tree = tree;

    /* create the ranap protocol tree */
    ranap_item = proto_tree_add_item(tree, proto_ranap, tvb, 0, -1, FALSE);
    ranap_tree = proto_item_add_subtree(ranap_item, ett_ranap);

    /* Add fields to ranap protocol tree */
    /* PDU Index */
    proceed_nbits(&offset, &bitoffset, 1);  /* leave out extension bit, checked above */
    proto_tree_add_uint_bits(ranap_tree, hf_ranap_pdu_index, tvb,
                             offset, bitoffset, 2, 0);
    proceed_nbits(&offset, &bitoffset, 2);


    /* Procedure Code */
    allign(&offset, &bitoffset);
    proto_tree_add_item(ranap_tree, hf_ranap_procedure_code, tvb, offset, 1, FALSE);
    offset += 1;

    /* PDU Criticality */
    proto_tree_add_uint_bits(ranap_tree, hf_ranap_pdu_criticality, tvb,
                             offset, bitoffset, 2, 0);
    proceed_nbits(&offset, &bitoffset, 2);

    /* number of octets */
    allign(&offset, &bitoffset);
    if (number_of_octets != 0)
    {
       proto_tree_add_uint(ranap_tree, hf_ranap_pdu_number_of_octets,
	                   tvb, offset,
	                   number_of_octets_size, number_of_octets);
       offset += number_of_octets_size;
    }
    else
    {
    	/* decoding is not supported */
    	proto_tree_add_text(ranap_tree, tvb, offset,
    	                    2, "Number of Octets greater than 0x3FFF, dissection not supported");
    	return;
    }
  }

  /* set offset to the beginning of ProtocolIE-Container */
  /* in case we skipped "if(tree){...}" above */
  offset = PDU_NUMBER_OF_OCTETS_OFFSET + number_of_octets_size;

  /* create a tvb containing the remainder of the PDU */
  ie_tvb = tvb_new_subset(tvb, offset, -1, -1);

  /* dissect the ies */
  dissect_ranap_ie_container(ie_tvb, ranap_tree);
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
    if (temp > 28) { return FALSE; }

    dissect_ranap(tvb, pinfo, tree);

    return TRUE;
}


/*****************************************************************************/
/*                                                                           */
/*  Protocol Registration Functions                                          */
/*                                                                           */
/*****************************************************************************/

void
proto_register_ranap(void)
{
  /* Setup list of header fields */
  static hf_register_info hf[] = {
    { &hf_ranap_pdu_index,
      { "RANAP-PDU Index",
        "ranap.ranap_pdu_index",
	FT_UINT8, BASE_HEX, VALS(&ranap_pdu_index_values), 0x0,
	"", HFILL }
    },
    { &hf_ranap_procedure_code,
      { "Procedure Code",
        "ranap.procedure_code",
	FT_UINT8, BASE_DEC, VALS(&ranap_procedure_code_values), 0x0,
	"", HFILL }
    },
    { &hf_ranap_pdu_criticality,
      { "Criticality of PDU",
        "ranap.pdu.criticality",
	FT_UINT8, BASE_HEX, VALS(&ranap_criticality_values), 0x0,
	"", HFILL }
    },
    { &hf_ranap_pdu_number_of_octets,
      { "Number of Octets in PDU",
        "ranap.pdu.num_of_octets",
	FT_UINT16, BASE_DEC, NULL, 0x0,
	"", HFILL }
    },
    { &hf_ranap_ie_protocol_extension,
      { "Protocol Extension",
        "ranap.ie.protocol_extension_present",
	FT_UINT8, BASE_HEX, VALS(&ranap_presence_values), 0x0,
	"", HFILL }
    },
    { &hf_ranap_number_of_ies,
      { "Number of IEs in PDU",
        "ranap.pdu.number_of_ies",
	FT_UINT16, BASE_DEC, NULL, 0x0,
	"", HFILL }
    },
    { &hf_ranap_number_of_ies_in_list,
      { "Number of IEs in list",
        "ranap.number_of_ies",
	FT_UINT16, BASE_DEC, NULL, 0x0,
	"", HFILL }
    },
    { &hf_ranap_ie_ie_id,
      { "IE-ID",
        "ranap.ie.ie_id",
	FT_UINT16, BASE_DEC, VALS(&ranap_ie_id_values), 0x0,
	"", HFILL }
    },
    { &hf_ranap_ext_field_id,
      { "ProtocolExtensionField ID",
        "ranap.ie.ProtocolExtensionFields.Id",
	FT_UINT16, BASE_DEC, NULL, 0x0,
	"", HFILL }
    },
    { &hf_ranap_ie_criticality,
      { "Criticality of IE",
        "ranap.ie.criticality",
	FT_UINT8, BASE_HEX, VALS(&ranap_criticality_values), 0x0,
	"", HFILL }
    },
    { &hf_ranap_ext_field_criticality,
      { "Criticality of ProtocolExtensionField",
        "ranap.ie.ProtocolExtensionFields.criticality",
	FT_UINT8, BASE_HEX, VALS(&ranap_criticality_values), 0x0,
	"", HFILL }
    },
    { &hf_ranap_ie_pair_first_criticality,
      { "First Criticality",
        "ranap.ie_pair.first_criticality",
	FT_UINT8, BASE_HEX, VALS(&ranap_criticality_values), 0x0,
	"", HFILL }
    },
    { &hf_ranap_ie_pair_second_criticality,
      { "Second Criticality",
        "ranap.ie_pair.second_criticality",
	FT_UINT8, BASE_HEX, VALS(&ranap_criticality_values), 0x0,
	"", HFILL }
    },
    { &hf_ranap_ie_number_of_octets,
      { "Number of Octets in IE",
        "ranap.ie.number_of_octets",
	FT_UINT16, BASE_DEC, NULL, 0x0,
	"", HFILL }
    },
    { &hf_ranap_first_value_number_of_octets,
      { "Number of Octets in first value",
        "ranap.ie_pair.first_value.number_of_octets",
	FT_UINT16, BASE_DEC, NULL, 0x0,
	"", HFILL }
    },
    { &hf_ranap_second_value_number_of_octets,
      { "Number of Octets in second value",
        "ranap.ie_pair.second_value.number_of_octets",
	FT_UINT16, BASE_DEC, NULL, 0x0,
	"", HFILL }
    },
    { &hf_ranap_rab_id,
      { "RAB-ID",
        "ranap.RAB_ID",
	FT_UINT8, BASE_HEX, NULL, 0x0,
	"", HFILL }
    },
    { &hf_ranap_nas_pdu,
      { "NAS-PDU",
        "ranap.NAS_PDU",
	FT_BYTES, BASE_NONE, NULL, 0x0,
	"", HFILL }
    },
    { &hf_ranap_extension_field,
      { "Extension Field Value",
        "ranap.Extension_Field_Value",
	FT_BYTES, BASE_NONE, NULL, 0x0,
	"", HFILL }
    },
    { &hf_ranap_plmn_id,
      { "PLMN-ID",
        "ranap.PLMN_ID",
	FT_BYTES, BASE_NONE, NULL, 0x0,
	"", HFILL }
    },
    { &hf_ranap_lac,
      { "LAC",
        "ranap.LAC",
	FT_BYTES, BASE_NONE, NULL, 0x0,
	"", HFILL }
    },
    { &hf_ranap_sac,
      { "SAC",
        "ranap.SAC",
	FT_BYTES, BASE_NONE, NULL, 0x0,
	"", HFILL }
    },
    { &hf_ranap_rac,
      { "RAC",
        "ranap.RAC",
	FT_BYTES, BASE_NONE, NULL, 0x0,
	"", HFILL }
    },
    { &hf_ranap_num_rabs,
      { "Number of RABs",
        "ranap.number_of_RABs",
	FT_UINT8, BASE_DEC, NULL, 0x0,
	"", HFILL }
    },
    { &hf_ranap_nAS_SynchronisationIndicator_present,
      { "nAS-SynchronisationIndicator",
        "ranap.nAS-SynchronisationIndicator_present",
	FT_UINT8, BASE_HEX, VALS(&ranap_presence_values), 0x0,
	"", HFILL }
    },
    { &hf_ranap_rAB_Parameters_present,
      { "rAB-Parameters",
        "ranap.rAB_Parameters_present",
	FT_UINT8, BASE_HEX, VALS(&ranap_presence_values), 0x0,
	"", HFILL }
    },
    { &hf_ranap_userPlaneInformation_present,
      { "userPlaneInformation",
        "ranap.userPlaneInformation_present",
	FT_UINT8, BASE_HEX, VALS(&ranap_presence_values), 0x0,
	"", HFILL }
    },
    { &hf_ranap_transportLayerInformation_present,
      { "transportLayerInformation",
        "ranap.transportLayerInformation_present",
	FT_UINT8, BASE_HEX, VALS(&ranap_presence_values), 0x0,
	"", HFILL }
    },
    { &hf_ranap_service_Handover_present,
      { "service-Handover",
        "ranap.service_Handover_present",
	FT_UINT8, BASE_HEX, VALS(&ranap_presence_values), 0x0,
	"", HFILL }
    },
    { &hf_ranap_iE_Extensions_present,
      { "iE-Extensions",
        "ranap.ie.iE-Extensions_present",
	FT_UINT8, BASE_HEX, VALS(&ranap_presence_values), 0x0,
	"", HFILL }
    },
    { &hf_ranap_nAS_SynchronisationIndicator,
      { "nAS-SynchronisationIndicator",
        "ranap.nAS-SynchronisationIndicator",
	FT_UINT8, BASE_HEX, NULL, 0x0,
	"", HFILL }
    },
    { &hf_ranap_guaranteedBitRate_present,
      { "guaranteedBitRate",
        "ranap.guaranteedBitRate_present",
	FT_UINT8, BASE_HEX, VALS(&ranap_presence_values), 0x0,
	"", HFILL }
    },
    { &hf_ranap_transferDelay_present,
      { "transferDelay",
        "ranap.transferDelay_present",
	FT_UINT8, BASE_HEX, VALS(&ranap_presence_values), 0x0,
	"", HFILL }
    },
    { &hf_ranap_trafficHandlingPriority_present,
      { "trafficHandlingPriority",
        "ranap.trafficHandlingPriority_present",
	FT_UINT8, BASE_HEX, VALS(&ranap_presence_values), 0x0,
	"", HFILL }
    },
    { &hf_ranap_allocationOrRetentionPriority_present,
      { "allocationOrRetentionPriority",
        "ranap.allocationOrRetentionPriority_present",
	FT_UINT8, BASE_HEX, VALS(&ranap_presence_values), 0x0,
	"", HFILL }
    },
    { &hf_ranap_sourceStatisticsDescriptor_present,
      { "sourceStatisticsDescriptor",
        "ranap.sourceStatisticsDescriptor_present",
	FT_UINT8, BASE_HEX, VALS(&ranap_presence_values), 0x0,
	"", HFILL }
    },
    { &hf_ranap_relocationRequirement_present,
      { "relocationRequirement",
        "ranap.relocationRequirement_present",
	FT_UINT8, BASE_HEX, VALS(&ranap_presence_values), 0x0,
	"", HFILL }
    },
    { &hf_ranap_trafficClass,
      { "Traffic Class",
        "ranap.rab_Parameters.trafficClass",
	FT_UINT8, BASE_DEC, VALS(&ranap_trafficClass_values), 0x0,
	"", HFILL }
    },
    { &hf_ranap_rAB_AsymmetryIndicator,
      { "rAB_AsymmetryIndicator",
        "ranap.rab_Parameters.rAB_AsymmetryIndicator",
	FT_UINT8, BASE_DEC, VALS(&ranap_rAB_AsymmetryIndicator_values), 0x0,
	"", HFILL }
    },
    { &hf_ranap_maxBitrate,
      { "maxBitrate",
        "ranap.rab_Parameters.maxBitrate",
	FT_UINT32, BASE_DEC, NULL, 0x0,
	"", HFILL }
    },
    { &hf_ranap_guaranteedBitrate,
      { "guaranteedBitrate",
        "ranap.rab_Parameters.guaranteedBitrate",
	FT_UINT32, BASE_DEC, NULL, 0x0,
	"", HFILL }
    },
    { &hf_ranap_deliveryOrder,
      { "deliveryOrder",
        "ranap.rab_Parameters.deliveryOrder",
	FT_UINT8, BASE_DEC, VALS(&ranap_DeliveryOrder_values), 0x0,
	"", HFILL }
    },
    { &hf_ranap_maxSDU_Size,
      { "maxSDU_Size",
        "ranap.rab_Parameters.maxSDU_Size",
	FT_UINT16, BASE_DEC, NULL, 0x0,
	"", HFILL }
    },
    { &hf_ranap_sDU_ErrorRatio_mantissa,
      { "sDU_ErrorRatio: mantissa",
        "ranap.rab_Parameters.sDU_ErrorRatio.mantissa",
	FT_UINT8, BASE_DEC, NULL, 0x0,
	"", HFILL }
    },
    { &hf_ranap_sDU_ErrorRatio_exponent,
      { "sDU_ErrorRatio: exponent",
        "ranap.rab_Parameters.sDU_ErrorRatio.exponent",
	FT_UINT8, BASE_DEC, NULL, 0x0,
	"", HFILL }
    },
    { &hf_ranap_residualBitErrorRatio_mantissa,
      { "residualBitErrorRatio: mantissa",
        "ranap.rab_Parameters.residualBitErrorRatio.mantissa",
	FT_UINT8, BASE_DEC, NULL, 0x0,
	"", HFILL }
    },
    { &hf_ranap_residualBitErrorRatio_exponent,
      { "residualBitErrorRatio: exponent",
        "ranap.rab_Parameters.residualBitErrorRatio.exponent",
	FT_UINT8, BASE_DEC, NULL, 0x0,
	"", HFILL }
    },
    { &hf_ranap_deliveryOfErroneousSDU,
      { "deliveryOfErroneousSDU",
        "ranap.rab_Parameters.ranap_deliveryOfErroneousSDU",
	FT_UINT8, BASE_DEC, VALS(&ranap_deliveryOfErroneousSDU_values), 0x0,
	"", HFILL }
    },
    { &hf_ranap_subflowSDU_Size,
      { "subflowSDU_Size",
        "ranap.rab_Parameters.subflowSDU_Size",
	FT_UINT8, BASE_DEC, NULL, 0x0,
	"", HFILL }
    },
    { &hf_ranap_rAB_SubflowCombinationBitRate,
      { "rAB_SubflowCombinationBitRate",
        "ranap.rab_Parameters.rAB_SubflowCombinationBitRate",
	FT_UINT32, BASE_DEC, NULL, 0x0,
	"", HFILL }
    },
    { &hf_ranap_sDU_ErrorRatio_present,
      { "sDU_ErrorRatio",
        "ranap.sDU_ErrorRatio_present",
	FT_UINT8, BASE_HEX, VALS(&ranap_presence_values), 0x0,
	"", HFILL }
    },
    { &hf_ranap_sDU_FormatInformationParameters_present,
      { "sDU_FormatInformationParameters",
        "ranap.sDU_FormatInformationParameters_present",
	FT_UINT8, BASE_HEX, VALS(&ranap_presence_values), 0x0,
	"", HFILL }
    },
    { &hf_ranap_subflowSDU_Size_present,
      { "subflowSDU_Size",
        "ranap.subflowSDU_Size_present",
	FT_UINT8, BASE_HEX, VALS(&ranap_presence_values), 0x0,
	"", HFILL }
    },
    { &hf_ranap_rAB_SubflowCombinationBitRate_present,
      { "subflowSDU_Size",
        "ranap.rAB_SubflowCombinationBitRate_present",
	FT_UINT8, BASE_HEX, VALS(&ranap_presence_values), 0x0,
	"", HFILL }
    },
    { &hf_ranap_transferDelay,
      { "transferDelay",
        "ranap.rab_Parameters.transferDelay",
	FT_UINT16, BASE_DEC, NULL, 0x0,
	"", HFILL }
    },
    { &hf_ranap_trafficHandlingPriority,
      { "trafficHandlingPriority",
        "ranap.rab_Parameters.trafficHandlingPriority",
	FT_UINT8, BASE_DEC, VALS(&ranap_priority_values), 0x0,
	"", HFILL }
    },
    { &hf_ranap_priorityLevel,
      { "priorityLevel",
        "ranap.rab_Parameters.allocationOrRetentionPriority.priorityLevel",
	FT_UINT8, BASE_DEC, VALS(&ranap_priority_values), 0x0,
	"", HFILL }
    },
    { &hf_ranap_pre_emptionCapability,
      { "pre-emptionCapability",
        "ranap.rab_Parameters.allocationOrRetentionPriority.pre_emptionCapability",
	FT_UINT8, BASE_DEC, VALS(&ranap_pre_emptionCapability_values), 0x0,
	"", HFILL }
    },
    { &hf_ranap_pre_emptionVulnerability,
      { "pre-emptionVulnerability",
        "ranap.rab_Parameters.allocationOrRetentionPriority.pre_emptionVulnerability",
	FT_UINT8, BASE_DEC, VALS(&ranap_pre_emptionVulnerability_values), 0x0,
	"", HFILL }
    },
    { &hf_ranap_queuingAllowed,
      { "queuingAllowed",
        "ranap.rab_Parameters.allocationOrRetentionPriority.queuingAllowed",
	FT_UINT8, BASE_DEC, VALS(&ranap_queuingAllowed_values), 0x0,
	"", HFILL }
    },
    { &hf_ranap_sourceStatisticsDescriptor,
      { "sourceStatisticsDescriptor",
        "ranap.rab_Parameters.sourceStatisticsDescriptor",
	FT_UINT8, BASE_DEC, VALS(&ranap_sourceStatisticsDescriptor_values), 0x0,
	"", HFILL }
    },
    { &hf_ranap_relocationRequirement,
      { "relocationRequirement",
        "ranap.rab_Parameters.relocationRequirement",
	FT_UINT8, BASE_DEC, VALS(&ranap_relocationRequirement_values), 0x0,
	"", HFILL }
    },
    { &hf_ranap_userPlaneMode,
      { "userPlaneMode",
        "ranap.userPlaneMode",
	FT_UINT8, BASE_DEC, VALS(&ranap_userPlaneMode_values), 0x0,
	"", HFILL }
    },
    { &hf_ranap_uP_ModeVersions,
      { "uP_ModeVersions",
        "ranap.uP_ModeVersions",
	FT_BYTES, BASE_NONE, NULL, 0x0,
	"", HFILL }
    },
    { &hf_ranap_number_of_ProtocolExtensionFields,
      { "Number of ProtocolExtensionFields",
        "ranap.number_of_ProtocolExtensionFields",
	FT_UINT16, BASE_DEC, NULL, 0x0,
	"", HFILL }
    },
    { &hf_ranap_ext_field_number_of_octets,
      { "Number of octets",
        "ranap.ProtocolExtensionFields.octets",
	FT_UINT16, BASE_DEC, NULL, 0x0,
	"", HFILL }
    },
    { &hf_ranap_transportLayerAddress_length,
      { "bit length of transportLayerAddress",
        "ranap.transportLayerAddress_length",
	FT_UINT8, BASE_DEC, NULL, 0x0,
	"", HFILL }
    },
    { &hf_ranap_transportLayerAddress,
      { "transportLayerAddress",
        "ranap.transportLayerAddress",
	FT_BYTES, BASE_NONE, NULL, 0x0,
	"", HFILL }
    },
    { &hf_ranap_gTP_TEI,
      { "gTP_TEI",
        "ranap.gTP_TEI",
	FT_BYTES, BASE_NONE, NULL, 0x0,
	"", HFILL }
    },
    { &hf_ranap_bindingID,
      { "bindingID",
        "ranap.bindingID",
	FT_BYTES, BASE_NONE, NULL, 0x0,
	"", HFILL }
    },
    { &hf_ranap_pDP_TypeInformation_present,
      { "pDP_TypeInformation",
        "ranap.pDP_TypeInformation_present",
	FT_UINT8, BASE_HEX, VALS(&ranap_presence_values), 0x0,
	"", HFILL }
    },
    { &hf_ranap_dataVolumeReportingIndication_present,
      { "dataVolumeReportingIndication",
        "ranap.dataVolumeReportingIndication_present",
	FT_UINT8, BASE_HEX, VALS(&ranap_presence_values), 0x0,
	"", HFILL }
    },
    { &hf_ranap_dl_GTP_PDU_SequenceNumber_present,
      { "dl_GTP_PDU_SequenceNumber",
        "ranap.dl_GTP_PDU_SequenceNumber_present",
	FT_UINT8, BASE_HEX, VALS(&ranap_presence_values), 0x0,
	"", HFILL }
    },
    { &hf_ranap_ul_GTP_PDU_SequenceNumber_present,
      { "ul_GTP_PDU_SequenceNumber",
        "ranap.ul_GTP_PDU_SequenceNumber_present",
	FT_UINT8, BASE_HEX, VALS(&ranap_presence_values), 0x0,
	"", HFILL }
    },
    { &hf_ranap_dl_N_PDU_SequenceNumber_present,
      { "dl_N_PDU_SequenceNumber",
        "ranap.dl_N_PDU_SequenceNumber_present",
	FT_UINT8, BASE_HEX, VALS(&ranap_presence_values), 0x0,
	"", HFILL }
    },
    { &hf_ranap_ul_N_PDU_SequenceNumber_present,
      { "ul_N_PDU_SequenceNumber",
        "ranap.ul_N_PDU_SequenceNumber_present",
	FT_UINT8, BASE_HEX, VALS(&ranap_presence_values), 0x0,
	"", HFILL }
    },
    { &hf_ranap_PDP_Type,
      { "PDP-Type",
        "ranap.RAB_SetupOrModifyItemSecond.PDP_Type",
	FT_UINT8, BASE_HEX, VALS(&ranap_PDP_Type_values), 0x0,
	"", HFILL }
    },
    { &hf_ranap_dataVolumeReportingIndication,
      { "dataVolumeReportingIndication",
        "ranap.RAB_SetupOrModifyItemSecond.dataVolumeReportingIndication",
	FT_UINT8, BASE_HEX, VALS(&ranap_dataVolumeReportingIndication_values), 0x0,
	"", HFILL }
    },
    { &hf_ranap_dl_GTP_PDU_SequenceNumber,
      { "dl_GTP_PDU_SequenceNumber",
        "ranap.RAB_SetupOrModifyItemSecond.dl_GTP_PDU_SequenceNumber",
	FT_UINT16, BASE_DEC, NULL, 0x0,
	"", HFILL }
    },
    { &hf_ranap_ul_GTP_PDU_SequenceNumber,
      { "ul_GTP_PDU_SequenceNumber",
        "ranap.RAB_SetupOrModifyItemSecond.ul_GTP_PDU_SequenceNumber",
	FT_UINT16, BASE_DEC, NULL, 0x0,
	"", HFILL }
    },
    { &hf_ranap_dl_N_PDU_SequenceNumber,
      { "ul_GTP_PDU_SequenceNumber",
        "ranap.RAB_SetupOrModifyItemSecond.ul_GTP_PDU_SequenceNumber",
	FT_UINT16, BASE_DEC, NULL, 0x0,
	"", HFILL }
    },
    { &hf_ranap_ul_N_PDU_SequenceNumber,
      { "ul_GTP_PDU_SequenceNumber",
        "ranap.RAB_SetupOrModifyItemSecond.ul_GTP_PDU_SequenceNumber",
	FT_UINT16, BASE_DEC, NULL, 0x0,
	"", HFILL }
    },
    { &hf_ranap_cause_choice,
      { "cause choice",
        "ranap.cause_choice",
	FT_UINT8, BASE_HEX, VALS(&ranap_cause_choice_values), 0x0,
	"", HFILL }
    },
    { &hf_ranap_cause_value,
      { "cause value",
        "ranap.cause_value",
	FT_UINT8, BASE_DEC,VALS(&ranap_cause_value_str), 0x0,
	"", HFILL }
    },
    { &hf_ranap_transportLayerAddress_present,
      { "transportLayerAddress",
        "ranap.transportLayerAddress_present",
	FT_UINT8, BASE_HEX, VALS(&ranap_presence_values), 0x0,
	"", HFILL }
    },
    { &hf_ranap_iuTransportAssociation_present,
      { "iuTransportAssociation",
        "ranap.iuTransportAssociation_present",
	FT_UINT8, BASE_HEX, VALS(&ranap_presence_values), 0x0,
	"", HFILL }
    },
    { &hf_ranap_dl_dataVolumes_present,
      { "dl_dataVolumes",
        "ranap.dl_dataVolumes_present",
	FT_UINT8, BASE_HEX, VALS(&ranap_presence_values), 0x0,
	"", HFILL }
    },
    { &hf_ranap_dataVolumeReference_present,
      { "dataVolumeReference",
        "ranap.dataVolumeReference_present",
	FT_UINT8, BASE_HEX, VALS(&ranap_presence_values), 0x0,
	"", HFILL }
    },
    { &hf_ranap_dl_UnsuccessfullyTransmittedDataVolume,
      { "dl-UnsuccessfullyTransmittedDataVolume",
        "ranap.dl-UnsuccessfullyTransmittedDataVolume",
	FT_UINT32, BASE_DEC, NULL, 0x0,
	"", HFILL }
    },
    { &hf_ranap_dataVolumeReference,
      { "dataVolumeReference",
        "ranap.dataVolumeReference",
	FT_UINT8, BASE_DEC, NULL, 0x0,
	"", HFILL }
    },
    { &hf_ranap_procedureCode_present,
      { "procedureCode",
        "ranap.procedureCode_present",
	FT_UINT8, BASE_HEX, VALS(&ranap_presence_values), 0x0,
	"", HFILL }
    },
    { &hf_ranap_triggeringMessage_present,
      { "triggeringMessage",
        "ranap.triggeringMessage_present",
	FT_UINT8, BASE_HEX, VALS(&ranap_presence_values), 0x0,
	"", HFILL }
    },
    { &hf_ranap_procedureCriticality_present,
      { "procedureCriticality",
        "ranap.procedureCriticality_present",
	FT_UINT8, BASE_HEX, VALS(&ranap_presence_values), 0x0,
	"", HFILL }
    },
    { &hf_ranap_iEsCriticalityDiagnostics_present,
      { "iEsCriticalityDiagnostics",
        "ranap.iEsCriticalityDiagnostics_present",
	FT_UINT8, BASE_HEX, VALS(&ranap_presence_values), 0x0,
	"", HFILL }
    },
    { &hf_ranap_triggeringMessage,
      { "triggeringMessage",
        "ranap.triggeringMessage",
	FT_UINT8, BASE_HEX, VALS(&ranap_pdu_index_values), 0x0,
	"", HFILL }
    },
    { &hf_ranap_procedureCriticality,
      { "procedureCriticality",
        "ranap.procedureCriticality",
	FT_UINT8, BASE_HEX, VALS(&ranap_criticality_values), 0x0,
	"", HFILL }
    },
    { &hf_ranap_iECriticality,
      { "iECriticality",
        "ranap.iECriticality",
	FT_UINT8, BASE_HEX, VALS(&ranap_criticality_values), 0x0,
	"", HFILL }
    },
    { &hf_ranap_repetitionNumber,
      { "repetitionNumber",
        "ranap.repetitionNumber",
	FT_UINT16, BASE_DEC, NULL, 0x0,
	"", HFILL }
    },
    { &hf_ranap_num_of_CriticalityDiagnostics_IEs,
      { "Number of CriticalityDiagnostics-IEs",
        "ranap.num_of_CriticalityDiagnostics_IEs",
	FT_UINT16, BASE_DEC, NULL, 0x0,
	"", HFILL }
    },
    { &hf_ranap_repetitionNumber_present,
      { "repetitionNumber",
        "ranap.repetitionNumber_present",
	FT_UINT8, BASE_HEX, VALS(&ranap_presence_values), 0x0,
	"", HFILL }
    },
    { &hf_ranap_dl_UnsuccessfullyTransmittedDataVolume_present,
      { "dl-UnsuccessfullyTransmittedDataVolume",
        "ranap.dl_UnsuccessfullyTransmittedDataVolume_present",
	FT_UINT8, BASE_HEX, VALS(&ranap_presence_values), 0x0,
	"", HFILL }
    },
    { &hf_ranap_CN_DomainIndicator,
      { "CN-DomainIndicator",
        "ranap.CN_DomainIndicator",
	FT_UINT8, BASE_HEX, VALS(&ranap_CN_DomainIndicator_values), 0x0,
	"", HFILL }
    },
    { &hf_ranap_service_Handover,
      { "service-Handover",
        "ranap.service_Handover",
	FT_UINT8, BASE_HEX, VALS(&ranap_service_Handover_values), 0x0,
	"", HFILL }
    },
    { &hf_ranap_IuSigConId,
      { "IuSigConId",
        "ranap.IuSigConId",
	FT_UINT24, BASE_DEC, NULL, 0x0,
	"", HFILL }
    },
    { &hf_ranap_SAPI,
      { "SAPI",
        "ranap.sapi",
	FT_UINT8, BASE_HEX, VALS(&ranap_SAPI_values), 0x0,
	"", HFILL }
    },
    { &hf_ranap_msg_extension_present,
      { "Message Extension",
        "ranap.msg_extension_present",
	FT_UINT8, BASE_HEX, VALS(&ranap_presence_values), 0x0,
	"", HFILL }
    },
    { &hf_ranap_ProtocolExtensionContainer_present,
      { "ProtocolExtensionContainer",
        "ranap.ProtocolExtensionContainer_present",
	FT_UINT8, BASE_HEX, VALS(&ranap_presence_values), 0x0,
	"", HFILL }
    },
    { &hf_ranap_nas_pdu_length,
      { "length of NAS-PDU",
        "ranap.nas_pdu_length",
	FT_UINT16, BASE_DEC, NULL, 0x0,
	"", HFILL }
    },
    { &hf_ranap_RNC_ID,
      { "RNC ID",
        "ranap.RNC_ID",
	FT_UINT16, BASE_DEC, NULL, 0x0fff,
	"", HFILL }
    }
  };

  /* Setup protocol subtree array */
  static gint *ett[] = {
    &ett_ranap,
    &ett_ranap_optionals,
    &ett_ranap_iE_Extension,
    &ett_ranap_ie,
    &ett_ranap_ie_pair,
    &ett_ranap_rab,
    &ett_ranap_ie_pair_first_value,
    &ett_ranap_ie_pair_second_value,
    &ett_ranap_sDU,
    &ett_ranap_rAB_Parameters,
    &ett_ranap_allocationOrRetentionPriority  ,
    &ett_ranap_CriticalityDiagnostics_IE
  };


  /* Register the protocol name and description */
  proto_ranap = proto_register_protocol("Radio Access Network Application Part",
				       "RANAP", "ranap");

  /* Register the header fields and subtrees */
  proto_register_field_array(proto_ranap, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));

  nas_pdu_dissector_table = register_dissector_table("ranap.nas_pdu", "RANAP NAS PDU", FT_UINT8, BASE_DEC);
  register_dissector("ranap", dissect_ranap, proto_ranap);

}


void
proto_reg_handoff_ranap(void)
{
  dissector_handle_t ranap_handle;

  ranap_handle = find_dissector("ranap");;
  /*
  dissector_add("sua.ssn",  SCCP_SSN_RANAP, ranap_handle);
  */
  dissector_add("sccp.ssn", SCCP_SSN_RANAP, ranap_handle);

  /* Add heuristic dissector
   * Perhaps we want a preference whether the heuristic dissector
   * is or isn't enabled
   */
  heur_dissector_add("sccp", dissect_sccp_ranap_heur, proto_ranap);
}
